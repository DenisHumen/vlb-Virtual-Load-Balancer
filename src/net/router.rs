use anyhow::{Context, Result, bail};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::process::Command;
use tracing::{debug, info};

/// Metric used for the provisional default route installed at startup when
/// the main table has none. High enough to always lose to the metric-0 route
/// the balancer installs, and shared with `system::ensure_bootstrap_default`
/// so the installer and the cleanup cannot drift apart.
pub const BOOTSTRAP_METRIC: u32 = 4096;

/// Owns writes to the kernel main routing table. Forwarding stays in
/// the kernel; this just picks which next-hop becomes the default.
pub struct Router {
    dry_run: bool,
    /// Whether startup installed a provisional default route that we are
    /// responsible for removing once a real one is chosen.
    ///
    /// Tracked rather than inferred, so cleanup only ever removes a route
    /// this process created. Deleting by shape alone would mean that an
    /// operator's own `default … metric 4096 proto static` — unusual, but
    /// theirs — would silently disappear the first time a provider came up.
    owns_bootstrap: AtomicBool,
}

impl Router {
    pub fn new(dry_run: bool, installed_bootstrap: bool) -> Self {
        Self {
            dry_run,
            owns_bootstrap: AtomicBool::new(installed_bootstrap),
        }
    }

    /// Put our default route at metric 0 in the main table.
    ///
    /// `metric 0` is required: the kernel's lookup key includes the
    /// metric, so without it `ip route replace default` ends up adding a
    /// second default next to whatever DHCP/netplan installed at metric
    /// 100, instead of replacing it. Lowest metric wins, so 0 is ours.
    ///
    /// `proto static` is also required for the same reason: the
    /// route-replace key includes the protocol. If we omit it our route
    /// becomes `proto boot` and a netplan-written `proto static` default
    /// won't be replaced — you'd end up with two defaults, the kernel
    /// non-deterministically picks one, and failback to the primary
    /// silently breaks. With `proto static` a single `replace` swaps in
    /// our route cleanly, including over a netplan-managed entry.
    pub async fn set_default_route(&self, gateway: Ipv4Addr, interface: &str) -> Result<()> {
        if self.dry_run {
            info!(%gateway, interface, "dry-run: would install default route");
            return Ok(());
        }

        let gw = gateway.to_string();
        let status = Command::new("ip")
            .args([
                "route", "replace", "default", "via", &gw, "dev", interface, "metric", "0",
                "proto", "static",
            ])
            .status()
            .await
            .context("failed to invoke `ip route replace`")?;

        if !status.success() {
            bail!(
                "`ip route replace default via {gw} dev {interface} metric 0 proto static` failed"
            );
        }
        debug!(%gateway, interface, "default route installed at metric 0 proto static");

        self.drop_bootstrap_default().await;
        Ok(())
    }

    /// Remove the provisional default route installed at startup, if it is
    /// still there.
    ///
    /// `system::ensure_bootstrap_default` may install a default at
    /// [`BOOTSTRAP_METRIC`] on a box that had none, purely so reverse-path
    /// filtering does not drop probe replies before any provider is known to
    /// be healthy. Once a real choice is installed at metric 0 that route has
    /// done its job, and leaving it behind would mean two coexisting defaults
    /// — the exact situation the metric-0 / proto-static scheme exists to
    /// avoid, and something that makes `ip route show default` misleading to
    /// whoever is debugging at the time.
    async fn drop_bootstrap_default(&self) {
        // `swap` so the deletion is attempted exactly once even if several
        // reconciles land at the same moment.
        if !self.owns_bootstrap.swap(false, Ordering::SeqCst) {
            return;
        }
        let _ = Command::new("ip")
            .args([
                "route",
                "del",
                "default",
                "metric",
                &BOOTSTRAP_METRIC.to_string(),
                "proto",
                "static",
            ])
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }

    /// Read back the default route the kernel is actually using.
    ///
    /// This is the ground truth the route watchdog compares against. Our own
    /// idea of "the active provider" is only a belief; a DHCP renew or a
    /// `netplan apply` can replace the route without telling us, and then
    /// everything looks healthy while traffic leaves the wrong way.
    ///
    /// Returns `None` when no default route exists at all. In dry-run we
    /// still read (reading mutates nothing), so `--dry-run` reports honestly.
    pub async fn current_default(&self) -> Result<Option<InstalledRoute>> {
        let out = Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .kill_on_drop(true)
            .output()
            .await
            .context("failed to invoke `ip route show default`")?;
        if !out.status.success() {
            bail!(
                "`ip route show default` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(parse_default_route(&String::from_utf8_lossy(&out.stdout)))
    }

    /// Drop conntrack state after a failover so existing flows reset
    /// immediately and reconnect through the new provider instead of
    /// black-holing until TCP timeout.
    ///
    /// We use a single-armed NAT topology where every provider's egress
    /// shares the gateway machine's own source IP, so there's no
    /// `-s <old>` filter to scope the flush — a full flush is right.
    pub async fn flush_conntrack(&self) {
        if self.dry_run {
            return;
        }
        // `conntrack` may be missing on minimal systems — ignore errors.
        let _ = Command::new("conntrack")
            .args(["-F"])
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }
}

/// The default route as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRoute {
    pub gateway: Ipv4Addr,
    pub interface: String,
    pub metric: Option<u32>,
    pub proto: Option<String>,
}

/// Parse `ip -4 route show default` output.
///
/// Lines look like:
///   `default via 10.0.0.2 dev ens18 proto static metric 0`
///   `default via 10.0.0.1 dev ens18 proto dhcp src 10.0.0.50 metric 100`
///
/// When several defaults coexist (the exact situation `metric 0 proto
/// static` exists to avoid) the kernel prefers the lowest metric, so that is
/// what we report — a missing metric counts as 0, matching kernel behaviour.
fn parse_default_route(stdout: &str) -> Option<InstalledRoute> {
    let mut best: Option<InstalledRoute> = None;
    for line in stdout.lines() {
        let line = line.trim();
        if !line.starts_with("default ") {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut gateway = None;
        let mut interface = None;
        let mut metric = None;
        let mut proto = None;
        let mut i = 0;
        while i < tokens.len() {
            match tokens[i] {
                "via" => {
                    gateway = tokens.get(i + 1).and_then(|s| s.parse::<Ipv4Addr>().ok());
                    i += 2;
                }
                "dev" => {
                    interface = tokens.get(i + 1).map(|s| s.to_string());
                    i += 2;
                }
                "metric" => {
                    metric = tokens.get(i + 1).and_then(|s| s.parse::<u32>().ok());
                    i += 2;
                }
                "proto" => {
                    proto = tokens.get(i + 1).map(|s| s.to_string());
                    i += 2;
                }
                _ => i += 1,
            }
        }
        // A default route with no `via` is a directly-connected default
        // (point-to-point links). We cannot compare it to a provider gateway,
        // so it is not a candidate.
        let (Some(gateway), Some(interface)) = (gateway, interface) else {
            continue;
        };
        let candidate = InstalledRoute {
            gateway,
            interface,
            metric,
            proto,
        };
        let better = match &best {
            None => true,
            Some(b) => candidate.metric.unwrap_or(0) < b.metric.unwrap_or(0),
        };
        if better {
            best = Some(candidate);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_our_own_route() {
        let r = parse_default_route("default via 10.0.0.2 dev ens18 proto static metric 0\n")
            .expect("parsed");
        assert_eq!(r.gateway, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(r.interface, "ens18");
        assert_eq!(r.metric, Some(0));
        assert_eq!(r.proto.as_deref(), Some("static"));
    }

    #[test]
    fn parses_a_dhcp_written_route_with_src() {
        let r = parse_default_route(
            "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 100\n",
        )
        .expect("parsed");
        assert_eq!(r.gateway, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(r.metric, Some(100));
        assert_eq!(r.proto.as_deref(), Some("dhcp"));
    }

    /// The scenario the watchdog exists for: something else added its own
    /// default alongside ours. The kernel uses the lowest metric, so that is
    /// the one we must compare against — reporting the other would make the
    /// watchdog "fix" a route that was never actually in use.
    #[test]
    fn prefers_the_lowest_metric_when_several_defaults_coexist() {
        let out = "default via 10.0.0.9 dev ens18 proto dhcp metric 100\n\
                   default via 10.0.0.2 dev ens18 proto static metric 0\n";
        let r = parse_default_route(out).expect("parsed");
        assert_eq!(r.gateway, Ipv4Addr::new(10, 0, 0, 2));

        // Order in the output must not matter.
        let reversed = "default via 10.0.0.2 dev ens18 proto static metric 0\n\
                        default via 10.0.0.9 dev ens18 proto dhcp metric 100\n";
        assert_eq!(
            parse_default_route(reversed).unwrap().gateway,
            Ipv4Addr::new(10, 0, 0, 2)
        );
    }

    #[test]
    fn missing_metric_counts_as_zero() {
        let out = "default via 10.0.0.5 dev eth0\n\
                   default via 10.0.0.6 dev eth0 metric 50\n";
        assert_eq!(
            parse_default_route(out).unwrap().gateway,
            Ipv4Addr::new(10, 0, 0, 5)
        );
    }

    #[test]
    fn no_default_route_is_none() {
        assert_eq!(parse_default_route(""), None);
        assert_eq!(
            parse_default_route("10.0.0.0/24 dev eth0 scope link\n"),
            None
        );
    }

    #[test]
    fn directly_connected_default_is_not_a_candidate() {
        // No `via` means no comparable next-hop address.
        assert_eq!(parse_default_route("default dev ppp0 scope link\n"), None);
    }

    #[test]
    fn garbage_lines_do_not_panic() {
        for junk in [
            "default via\n",
            "default via not-an-ip dev eth0\n",
            "default dev\n",
            "default via 1.2.3.4 dev\n",
            "\n\n   \n",
        ] {
            let _ = parse_default_route(junk);
        }
    }
}
