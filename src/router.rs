use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use tokio::process::Command;
use tracing::{debug, info};

/// Manages the kernel's main routing table. The hot-path forwarding is done
/// entirely by the kernel — this service only decides *which* next-hop is
/// installed as the default route.
pub struct Router {
    dry_run: bool,
}

impl Router {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    /// Install our default route at metric 0 in the main table.
    ///
    /// The explicit `metric 0` matters: route lookup keys `(to, tos, table,
    /// metric)` mean `ip route replace default via X dev Y` without a metric
    /// won't overwrite a DHCP/netplan default at metric 100 — it adds a
    /// second default. With metric 0 ours is always chosen (lowest wins) and
    /// replaces cleanly on subsequent calls.
    pub async fn set_default_route(&self, gateway: Ipv4Addr, interface: &str) -> Result<()> {
        if self.dry_run {
            info!(%gateway, interface, "dry-run: would install default route");
            return Ok(());
        }

        let gw = gateway.to_string();
        let status = Command::new("ip")
            .args([
                "route", "replace", "default",
                "via", &gw,
                "dev", interface,
                "metric", "0",
            ])
            .status()
            .await
            .context("failed to invoke `ip route replace`")?;

        if !status.success() {
            bail!("`ip route replace default via {gw} dev {interface} metric 0` failed");
        }
        debug!(%gateway, interface, "default route installed at metric 0");
        Ok(())
    }

    /// Drop conntrack state so that, after a failover, existing flows see an
    /// immediate reset and reconnect through the new provider.
    ///
    /// In our single-armed NAT topology, every provider's egress uses the
    /// same local source IP (the gateway machine's own address), so there is
    /// no `-s <old-ip>` filter to apply — a full flush is the right call.
    /// The alternative is letting flows black-hole until TCP timeout.
    pub async fn flush_conntrack(&self) {
        if self.dry_run {
            return;
        }
        // `conntrack` may not be installed on minimal systems — ignore errors.
        let _ = Command::new("conntrack")
            .args(["-F"])
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }
}
