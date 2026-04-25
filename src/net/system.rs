use anyhow::{Context, Result, bail};
use std::process::Command as StdCommand;
use tokio::process::Command;
use tracing::{info, warn};

use crate::config::Config;

/// Ensure the process is running as uid 0. Routing-table mutation, iptables
/// rules, and sysctl writes all require CAP_NET_ADMIN + write access to
/// /proc/sys, which in practice means root.
pub fn check_root() -> Result<()> {
    let out = StdCommand::new("id")
        .arg("-u")
        .output()
        .context("failed to invoke `id -u` to determine current uid")?;
    let uid: u32 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .context("could not parse uid returned by `id -u`")?;
    if uid != 0 {
        bail!("vlb must be run as root (current uid = {uid})");
    }
    Ok(())
}

/// Bring the host into a state where it can NAT-forward client traffic:
///   - IP forwarding on
///   - sysctl knobs that trip up single-armed NAT gateways turned off
///   - MASQUERADE rule on each provider interface
///   - FORWARD policy set to ACCEPT
///   - per-provider routing tables and fwmark-based ip rules, used by
///     health probes to verify each provider's internet path independently
///   - optionally stop ufw/firewalld (opt-in via config)
pub async fn prepare(cfg: &Config) -> Result<()> {
    info!("preparing host: sysctl, forwarding, NAT, policy routing");
    tune_sysctl().await?;

    if cfg.firewall.manage {
        if cfg.firewall.disable_host_firewall {
            disable_host_firewall().await;
        }
        configure_nat(cfg).await?;
        allow_forward().await?;
    } else {
        warn!("firewall.manage = false — NAT/forward rules NOT installed (manual setup required)");
    }

    setup_policy_routing(cfg).await?;
    Ok(())
}

async fn tune_sysctl() -> Result<()> {
    // (key, value). rp_filter = 2 (loose) is the safe choice for a single-
    // armed gateway where packets may arrive and leave on the same iface.
    let knobs = [
        ("net.ipv4.ip_forward", "1"),
        ("net.ipv4.conf.all.forwarding", "1"),
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.all.rp_filter", "2"),
        ("net.ipv4.conf.default.rp_filter", "2"),
    ];

    for (k, v) in knobs {
        let arg = format!("{k}={v}");
        let status = Command::new("sysctl")
            .args(["-w", &arg])
            .status()
            .await
            .with_context(|| format!("failed to run `sysctl -w {arg}`"))?;
        if !status.success() {
            bail!("`sysctl -w {arg}` failed");
        }
    }

    // Persist knobs across reboots.
    let persisted: String = knobs.iter().map(|(k, v)| format!("{k} = {v}\n")).collect();
    if let Err(e) = tokio::fs::write("/etc/sysctl.d/99-vlb.conf", persisted).await {
        warn!(error = %e, "failed to persist sysctl settings (non-fatal)");
    }

    info!("sysctl tuned (ip_forward=1, redirects off, rp_filter=loose)");
    Ok(())
}

async fn which(bin: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {bin} >/dev/null 2>&1")])
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn disable_host_firewall() {
    if which("ufw").await {
        let _ = Command::new("ufw")
            .arg("--force")
            .arg("disable")
            .status()
            .await;
        warn!("ufw disabled (disable_host_firewall=true)");
    }
    if which("firewall-cmd").await {
        let _ = Command::new("systemctl")
            .args(["stop", "firewalld"])
            .status()
            .await;
        let _ = Command::new("systemctl")
            .args(["disable", "firewalld"])
            .status()
            .await;
        warn!("firewalld stopped & disabled (disable_host_firewall=true)");
    }
}

async fn configure_nat(cfg: &Config) -> Result<()> {
    let mut seen: Vec<String> = Vec::new();

    // Collect every interface that should have a MASQUERADE rule.
    let interfaces: Vec<String> = if let Some(wan) = &cfg.firewall.wan_interface {
        vec![wan.clone()]
    } else {
        cfg.providers.iter().map(|p| p.interface.clone()).collect()
    };

    for iface in interfaces {
        if seen.iter().any(|i| i == &iface) {
            continue;
        }
        seen.push(iface.clone());

        // Idempotency: `-C` checks whether the rule already exists.
        let check = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-C",
                "POSTROUTING",
                "-o",
                &iface,
                "-j",
                "MASQUERADE",
            ])
            .status()
            .await;
        if matches!(check, Ok(s) if s.success()) {
            info!(iface, "NAT masquerade rule already present");
            continue;
        }

        let add = Command::new("iptables")
            .args([
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-o",
                &iface,
                "-j",
                "MASQUERADE",
            ])
            .status()
            .await
            .context("failed to invoke iptables for MASQUERADE rule")?;
        if !add.success() {
            bail!("failed to install MASQUERADE rule on {iface}");
        }
        info!(iface, "NAT masquerade rule installed");
    }
    Ok(())
}

async fn allow_forward() -> Result<()> {
    let status = Command::new("iptables")
        .args(["-P", "FORWARD", "ACCEPT"])
        .status()
        .await
        .context("failed to invoke iptables for FORWARD policy")?;
    if !status.success() {
        bail!("failed to set iptables FORWARD policy to ACCEPT");
    }
    info!("iptables FORWARD policy = ACCEPT");
    Ok(())
}

/// Install one routing table and one `ip rule` per provider.
///
/// The result: packets tagged with `fwmark = base + prio` are routed through
/// table `base + prio`, which contains `default via <provider_gw>`. We use
/// this path only from health probes (`ping -m <mark>`), so client traffic
/// continues to follow the regular main-table default route that the
/// balancer actively manages.
///
/// Idempotent: repeated runs overwrite existing state, and stale rules at
/// our pref values are removed in a delete-until-ENOENT loop.
async fn setup_policy_routing(cfg: &Config) -> Result<()> {
    for p in &cfg.providers {
        let table = cfg.table_for(p);
        let mark = cfg.mark_for(p);
        let pref = cfg.rule_pref_for(p);

        let gw = p.gateway.to_string();
        let table_str = table.to_string();
        let mark_str = mark.to_string();
        let pref_str = pref.to_string();

        // (1) Default route inside the per-provider table. `ip route replace`
        //     handles both "no route yet" and "route from a prior run".
        let route = Command::new("ip")
            .args([
                "route",
                "replace",
                "default",
                "via",
                &gw,
                "dev",
                &p.interface,
                "table",
                &table_str,
            ])
            .status()
            .await
            .context("failed to invoke `ip route replace` for per-provider table")?;
        if !route.success() {
            bail!(
                "failed to install default route in table {table} via {gw} dev {}",
                p.interface
            );
        }

        // (2) Remove any stale rule(s) sitting at our pref. `ip rule del`
        //     removes a SINGLE matching rule per call, so we loop until
        //     deletion fails (ENOENT) to drain prior-run leftovers or
        //     duplicates added by other tooling.
        loop {
            let del = Command::new("ip")
                .args(["rule", "del", "pref", &pref_str])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .await
                .context("failed to invoke `ip rule del`")?;
            if !del.success() {
                break;
            }
        }

        // (3) Install a fresh rule: fwmark M lookup T at pref P.
        let add = Command::new("ip")
            .args([
                "rule", "add", "pref", &pref_str, "fwmark", &mark_str, "lookup", &table_str,
            ])
            .status()
            .await
            .context("failed to invoke `ip rule add`")?;
        if !add.success() {
            bail!("failed to add ip rule: fwmark {mark_str} lookup {table_str} pref {pref_str}");
        }

        let mark_hex = format!("0x{mark:x}");
        info!(
            provider = %p.name,
            table,
            mark = %mark_hex,
            pref,
            "policy route installed"
        );
    }
    Ok(())
}
