use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use tokio::process::Command;
use tracing::{debug, info};

/// Owns writes to the kernel main routing table. Forwarding stays in
/// the kernel; this just picks which next-hop becomes the default.
pub struct Router {
    dry_run: bool,
}

impl Router {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
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
        Ok(())
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
