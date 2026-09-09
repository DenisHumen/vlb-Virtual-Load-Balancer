use anyhow::{Context, Result, bail};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::process::Command;
use tracing::{debug, info, warn};

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

        self.remove_competing_defaults(gateway, interface).await;
        self.drop_bootstrap_default().await;
        Ok(())
    }

    /// Delete any other default route that ties with ours for the kernel's
    /// preference.
    ///
    /// `ip route replace` keys on (destination, **metric**, **proto**), so it
    /// only displaces a route matching all three. A default installed by
    /// something else at the same metric 0 but a different proto — which is
    /// what netplan, systemd-networkd or a DHCP client can produce — is a
    /// *different* route as far as the kernel is concerned. Both then sit in
    /// the table at equal cost and the kernel picks between them by insertion
    /// order, which is to say arbitrarily.
    ///
    /// Found by the lab: a competitor at `metric 0 proto kernel` won the
    /// lookup outright while vlb believed its own route was installed and
    /// active. Everything reported healthy; traffic left through the wrong
    /// uplink.
    ///
    /// Routes at a *higher* metric are left alone: the kernel already
    /// prefers ours, and if ours ever disappears one of those taking over is
    /// better than no route at all — the watchdog notices and reclaims.
    async fn remove_competing_defaults(&self, gateway: Ipv4Addr, interface: &str) {
        let out = Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .kill_on_drop(true)
            .output()
            .await;
        let Ok(out) = out else { return };
        if !out.status.success() {
            return;
        }

        for route in parse_all_defaults(&String::from_utf8_lossy(&out.stdout)) {
            // A missing metric means 0, which is what we install at.
            if route.metric.unwrap_or(0) != 0 {
                continue;
            }
            let is_ours = route.gateway == gateway
                && route.interface == interface
                && route.proto.as_deref() == Some("static");
            if is_ours {
                continue;
            }

            warn!(
                found_gw = %route.gateway,
                found_dev = %route.interface,
                found_proto = route.proto.as_deref().unwrap_or("(none)"),
                "another default route sits at metric 0 alongside ours — the kernel \
                 would choose between them arbitrarily, so removing it"
            );

            let mut args = vec![
                "route".to_string(),
                "del".to_string(),
                "default".to_string(),
                "via".to_string(),
                route.gateway.to_string(),
                "dev".to_string(),
                route.interface.clone(),
                "metric".to_string(),
                route.metric.unwrap_or(0).to_string(),
            ];
            if let Some(proto) = &route.proto {
                args.push("proto".to_string());
                args.push(proto.clone());
            }
            let _ = Command::new("ip")
                .args(&args)
                .kill_on_drop(true)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await;
        }
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
        Ok(parse_default_route_from(&self.read_defaults().await?))
    }

    /// Every default route currently in the main table.
    ///
    /// The watchdog needs all of them, not just the preferred one: a rival at
    /// the same metric 0 does not change which route "wins" in a way we can
    /// observe reliably — the kernel breaks that tie by insertion order — so
    /// the only safe check is whether a rival exists at all.
    pub async fn current_defaults(&self) -> Result<Vec<InstalledRoute>> {
        self.read_defaults().await
    }

    async fn read_defaults(&self) -> Result<Vec<InstalledRoute>> {
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
        Ok(parse_all_defaults(&String::from_utf8_lossy(&out.stdout)))
    }

    /// Forget every connection the kernel is tracking.
    ///
    /// After the default route moves, the flows that were using the old
    /// uplink are bound to a path that no longer carries them. Dropping their
    /// state does not reset them — deleting a conntrack entry emits neither
    /// an RST nor an ICMP error — but it stops the kernel treating their
    /// packets as an established flow, so the next one is either NATed afresh
    /// down the new path or refused outright, instead of being sent somewhere
    /// that will silently discard it until the application's own timeout.
    ///
    /// This is a blunt instrument: single-armed NAT means every provider's
    /// egress leaves with the gateway's own address, so there is no `-s` to
    /// scope it by, and every connection on the box goes — including ones
    /// that were not using the provider being left. [`Self::flush_mark`]
    /// scopes it properly once connections carry a per-provider mark.
    pub async fn flush_conntrack(&self) {
        if self.dry_run {
            return;
        }
        self.run_conntrack(&["-F"], "flush all connection tracking")
            .await;
    }

    /// Forget only the connections carrying one provider's mark.
    ///
    /// `conntrack -D -m <mark>/<mask>` filters on the connection mark rather
    /// than on addresses, which is exactly the scope a full flush lacks: the
    /// flows of the provider that just died go, and everyone else's stay.
    pub async fn flush_mark(&self, mark: u32, mask: u32) {
        if self.dry_run {
            return;
        }
        let filter = format!("{mark:#x}/{mask:#x}");
        self.run_conntrack(
            &["-D", "-m", &filter],
            "drop the connections pinned to one provider",
        )
        .await;
    }

    /// How many tracked connections carry each provider mark.
    ///
    /// One dump of the table, tallied in a single pass, rather than one
    /// `conntrack -L -m …` per provider: the table is dumped in full either
    /// way, and a gateway with tens of thousands of flows should not pay for
    /// that three times to answer one question.
    ///
    /// `None` when conntrack is absent or unreadable — the caller shows
    /// nothing rather than claiming zero.
    pub async fn pinned_counts(&self, mask: u32) -> Option<HashMap<u32, u64>> {
        if self.dry_run {
            return None;
        }
        let out = Command::new("conntrack")
            .args(["-L", "-o", "extended"])
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output()
            .await
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let mut counts: HashMap<u32, u64> = HashMap::new();
        for line in text.lines() {
            // `mark=512` sits among the flags at the end of each entry.
            let Some(at) = line.find("mark=") else {
                continue;
            };
            let rest = &line[at + 5..];
            let end = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            let Ok(mark) = rest[..end].parse::<u32>() else {
                continue;
            };
            let masked = mark & mask;
            if masked != 0 {
                *counts.entry(masked).or_default() += 1;
            }
        }
        Some(counts)
    }

    /// `conntrack` is an optional dependency, and until now its absence and
    /// its failures were both discarded. Neither is fatal — but an operator
    /// whose flows are not being dropped should be able to find out why.
    async fn run_conntrack(&self, args: &[&str], what: &str) {
        match Command::new("conntrack")
            .args(args)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
        {
            Ok(out) if out.status.success() => {}
            // `-D` with nothing to delete exits 1. That is the normal case on
            // a quiet link, not a failure.
            Ok(out) if out.status.code() == Some(1) => {
                debug!(what, "conntrack matched nothing");
            }
            Ok(out) => {
                debug!(
                    what,
                    status = ?out.status.code(),
                    stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                    "conntrack did not succeed"
                );
            }
            Err(e) => {
                warn!(
                    what,
                    error = %e,
                    "could not run conntrack — connections on a provider that has \
                     gone away will hang until they time out rather than failing fast"
                );
            }
        }
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

impl std::fmt::Display for InstalledRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "via {} dev {} metric {} proto {}",
            self.gateway,
            self.interface,
            self.metric.unwrap_or(0),
            self.proto.as_deref().unwrap_or("-")
        )
    }
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
/// The route the kernel prefers: lowest metric, a missing metric meaning 0.
fn parse_default_route_from(routes: &[InstalledRoute]) -> Option<InstalledRoute> {
    routes.iter().min_by_key(|r| r.metric.unwrap_or(0)).cloned()
}

/// Every default route in the output, in the order the kernel listed them.
pub(crate) fn parse_all_defaults(stdout: &str) -> Vec<InstalledRoute> {
    let mut found = Vec::new();
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
        found.push(InstalledRoute {
            gateway,
            interface,
            metric,
            proto,
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test shorthand: parse the output, then pick what the kernel would.
    fn preferred_default(stdout: &str) -> Option<InstalledRoute> {
        parse_default_route_from(&parse_all_defaults(stdout))
    }

    #[test]
    fn parses_our_own_route() {
        let r = preferred_default("default via 10.0.0.2 dev ens18 proto static metric 0\n")
            .expect("parsed");
        assert_eq!(r.gateway, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(r.interface, "ens18");
        assert_eq!(r.metric, Some(0));
        assert_eq!(r.proto.as_deref(), Some("static"));
    }

    #[test]
    fn parses_a_dhcp_written_route_with_src() {
        let r = preferred_default(
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
        let r = preferred_default(out).expect("parsed");
        assert_eq!(r.gateway, Ipv4Addr::new(10, 0, 0, 2));

        // Order in the output must not matter.
        let reversed = "default via 10.0.0.2 dev ens18 proto static metric 0\n\
                        default via 10.0.0.9 dev ens18 proto dhcp metric 100\n";
        assert_eq!(
            preferred_default(reversed).unwrap().gateway,
            Ipv4Addr::new(10, 0, 0, 2)
        );
    }

    /// A competitor at the *same* metric but a different proto is the case
    /// `ip route replace` cannot handle: proto is part of the route key, so
    /// the two coexist at equal cost and the kernel picks between them by
    /// insertion order. Found by the lab, where a `proto kernel metric 0`
    /// route took the traffic while vlb believed its own was active.
    ///
    /// Both have to be visible to the caller so the competitor can be
    /// deleted rather than merely out-ranked.
    #[test]
    fn all_defaults_are_enumerated_including_same_metric_rivals() {
        let out = "default via 10.77.0.3 dev eth0 proto kernel metric 0\n\
                   default via 10.77.0.2 dev eth0 proto static metric 0\n\
                   default via 10.77.0.9 dev eth0 proto dhcp metric 100\n";
        let all = parse_all_defaults(out);
        assert_eq!(all.len(), 3, "every default must be listed: {all:?}");

        let rivals: Vec<_> = all
            .iter()
            .filter(|r| r.metric.unwrap_or(0) == 0 && r.proto.as_deref() != Some("static"))
            .collect();
        assert_eq!(rivals.len(), 1);
        assert_eq!(rivals[0].gateway, Ipv4Addr::new(10, 77, 0, 3));
        assert_eq!(rivals[0].proto.as_deref(), Some("kernel"));

        // The higher-metric one is not a rival: the kernel already prefers
        // ours, and leaving it is better than having no fallback at all.
        assert!(
            all.iter()
                .any(|r| r.metric == Some(100) && r.gateway == Ipv4Addr::new(10, 77, 0, 9))
        );
    }

    /// A DHCP client writing its default at metric 0 is the realistic shape
    /// of this on Ubuntu, and the one most likely to be hit in production.
    #[test]
    fn a_dhcp_route_at_metric_zero_is_recognised_as_a_rival() {
        let out = "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.50 metric 0\n\
                   default via 10.0.0.2 dev eth0 proto static metric 0\n";
        let all = parse_all_defaults(out);
        assert_eq!(all.len(), 2);
        let rival = all
            .iter()
            .find(|r| r.proto.as_deref() == Some("dhcp"))
            .expect("dhcp route parsed");
        assert_eq!(rival.metric, Some(0));
        assert_eq!(rival.gateway, Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn missing_metric_counts_as_zero() {
        let out = "default via 10.0.0.5 dev eth0\n\
                   default via 10.0.0.6 dev eth0 metric 50\n";
        assert_eq!(
            preferred_default(out).unwrap().gateway,
            Ipv4Addr::new(10, 0, 0, 5)
        );
    }

    #[test]
    fn no_default_route_is_none() {
        assert_eq!(preferred_default(""), None);
        assert_eq!(preferred_default("10.0.0.0/24 dev eth0 scope link\n"), None);
    }

    #[test]
    fn directly_connected_default_is_not_a_candidate() {
        // No `via` means no comparable next-hop address.
        assert_eq!(preferred_default("default dev ppp0 scope link\n"), None);
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
            let _ = preferred_default(junk);
        }
    }
}
