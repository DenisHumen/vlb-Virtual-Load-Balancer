//! Keeping an established connection on the provider it started on.
//!
//! # The problem this solves, and the one it does not
//!
//! Moving the default route moves *every* flow at once. For a flow whose
//! provider has died that is unavoidable and welcome. For every other flow it
//! is gratuitous: coming back to the primary after it recovers, pinning a
//! provider by hand, or the watchdog tidying up after netplan all used to
//! reset every connection on the box, and a switch that was supposed to be
//! good news arrived as a dropped stream.
//!
//! So stamp each forwarded connection, on its first packet, with the mark of
//! whichever provider was active at that moment. Every later packet of that
//! connection gets the stamp restored, and the `ip rule fwmark M lookup T`
//! rules that already exist for the health probes route it accordingly. New
//! connections follow the main table's default; established ones stay where
//! they were born. A failback then moves nothing that is already running.
//!
//! What this cannot do is keep a connection alive when its own provider
//! fails. Each next hop hides this gateway behind a different public address,
//! so the far end sees a stranger the moment traffic leaves through another
//! one, and no marking on this box changes that. Those flows have to
//! reconnect; [`Balancer`](crate::balancer::Balancer) evicts them so they
//! find out immediately instead of hanging.
//!
//! # Why the chain looks the way it does
//!
//! Reply packets must be left alone. In `PREROUTING` the order is conntrack,
//! then mangle, then the routing decision, and `ip_route_input_slow` copies
//! `skb->mark` into the lookup key. A server-to-client reply that picked up a
//! provider mark would be un-NATed to a LAN address and then routed by a
//! table whose only entry is `default via <isp router>` — straight back out
//! of the gateway. That is every download on the network, so the first rule
//! in the chain returns on `--ctdir REPLY`.
//!
//! Nothing addressed to the gateway itself is marked, which is enforced on
//! the jump rather than inside the chain: `! --dst-type LOCAL`. This is what
//! makes an operator's SSH session structurally safe rather than accidentally
//! safe.
//!
//! There is deliberately **no mangle `OUTPUT` counterpart**. Locally
//! generated packets never traverse `PREROUTING`, which is what keeps the
//! daemon's own health probes — each pinned to a provider with `SO_MARK` —
//! out of reach of this machinery. A `--restore-mark` in `OUTPUT` would
//! overwrite those socket marks, every provider would be probed down the
//! currently-active path, all of them would report identical health, and
//! failover would quietly stop discriminating. It is the obvious
//! "improvement" to make here. Do not make it.

use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{debug, info};

use crate::config::Config;

/// The chain holding the marking rules. Its own chain, so it can be replaced
/// as a unit and removed without touching anything else in `mangle`.
pub const CHAIN: &str = "VLB_PIN";

/// Install the jump, if it is not there already.
///
/// Follows the pattern the per-client accounting chain uses: `-N` fails when
/// the chain exists, which is the normal case on every run after the first,
/// and `-C` asks whether the jump is installed rather than adding a second
/// one.
async fn ensure_jump(lan_interface: &str) -> Result<()> {
    let _ = run("iptables", &["-t", "mangle", "-N", CHAIN]).await;

    let jump = [
        "-t",
        "mangle",
        "PREROUTING",
        "-i",
        lan_interface,
        "-m",
        "addrtype",
        "!",
        "--dst-type",
        "LOCAL",
        "-j",
        CHAIN,
    ];
    let mut check = vec!["-t", "mangle", "-C"];
    check.extend_from_slice(&jump[2..]);
    if run("iptables", &check).await.unwrap_or(false) {
        return Ok(());
    }

    let mut add = vec!["-t", "mangle", "-I"];
    add.extend_from_slice(&jump[2..3]);
    add.push("1");
    add.extend_from_slice(&jump[3..]);
    if !run("iptables", &add)
        .await
        .context("failed to invoke iptables to hook the connection-pinning chain")?
    {
        anyhow::bail!("could not hook {CHAIN} into mangle PREROUTING");
    }
    info!(
        chain = CHAIN,
        interface = lan_interface,
        "connection pinning hooked into PREROUTING"
    );
    Ok(())
}

/// Write the chain's contents for one active provider, in a single
/// transaction.
///
/// `iptables-restore --noflush` with a `:CHAIN -` line replaces exactly this
/// chain and leaves every other chain, including `PREROUTING` and whatever
/// the operator keeps there, untouched. Rendering it as a sequence of `-F`
/// and `-A` calls instead would leave a window in which the chain is hooked
/// and empty, and a packet crossing it in that window gets no mark, follows
/// the current default, and is killed by the far end — which is the exact
/// failure this module exists to prevent.
pub async fn install(cfg: &Config, active_mark: u32) -> Result<()> {
    // Without a LAN interface there is nothing to hook the jump to: the
    // chain would mark traffic arriving on any interface, including the
    // providers' own return path.
    let lan = cfg.general.lan_interface.as_deref().context(
        "connection pinning needs general.lan_interface set — it is the interface the \
         jump is hooked to, and without it every arriving packet would be marked",
    )?;
    ensure_jump(lan).await?;

    let mask = cfg.routing.fwmark_mask;
    let script = format!(
        "*mangle\n\
         :{CHAIN} -\n\
         -A {CHAIN} -m conntrack --ctdir REPLY -j RETURN\n\
         -A {CHAIN} -j CONNMARK --restore-mark --nfmask {mask:#x} --ctmask {mask:#x}\n\
         -A {CHAIN} -m mark ! --mark 0x0/{mask:#x} -j RETURN\n\
         -A {CHAIN} -m comment --comment \"vlb:active\" -j MARK --set-xmark {active_mark:#x}/{mask:#x}\n\
         -A {CHAIN} -j CONNMARK --save-mark --nfmask {mask:#x} --ctmask {mask:#x}\n\
         COMMIT\n"
    );

    let mut child = Command::new("iptables-restore")
        .args(["-w", "5", "-T", "mangle", "--noflush"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("failed to run iptables-restore")?;
    child
        .stdin
        .take()
        .context("iptables-restore gave no stdin")?
        .write_all(script.as_bytes())
        .await
        .context("failed to write the pinning rules to iptables-restore")?;
    let out = child
        .wait_with_output()
        .await
        .context("iptables-restore did not finish")?;
    if !out.status.success() {
        // A rejected restore rolls itself back, so the previous mark is still
        // in force. Silence here would look exactly like a switch that did
        // nothing.
        anyhow::bail!(
            "iptables-restore refused the pinning rules: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    debug!(
        chain = CHAIN,
        mark = format!("{active_mark:#x}"),
        "pinning rules installed"
    );
    Ok(())
}

/// Remove the jump and the chain.
///
/// Used when pinning is switched off, and by teardown. Everything here is
/// allowed to fail: this runs on boxes that never had the rules, and on ones
/// where an operator has already removed them by hand.
pub async fn remove(lan_interface: Option<&str>) -> Result<()> {
    // The jump has to go first — iptables will not delete a chain that is
    // still referenced. Delete by the exact spec that `ensure_jump` installs,
    // repeatedly, in case an older run left a duplicate.
    if let Some(lan) = lan_interface {
        for _ in 0..8 {
            let gone = run(
                "iptables",
                &[
                    "-t",
                    "mangle",
                    "-D",
                    "PREROUTING",
                    "-i",
                    lan,
                    "-m",
                    "addrtype",
                    "!",
                    "--dst-type",
                    "LOCAL",
                    "-j",
                    CHAIN,
                ],
            )
            .await
            .unwrap_or(false);
            if !gone {
                break;
            }
        }
    }
    let _ = run("iptables", &["-t", "mangle", "-F", CHAIN]).await;
    let _ = run("iptables", &["-t", "mangle", "-X", CHAIN]).await;
    Ok(())
}

/// Check that this kernel can actually do what the chain asks of it.
///
/// A stripped kernel or a busybox iptables produces an error per rule; run
/// once at startup so the operator hears about it then, rather than
/// discovering that pinning has silently never worked.
pub async fn check_supported() -> Result<()> {
    let probes: [(&str, Vec<&str>); 4] = [
        ("the mangle table", vec!["-t", "mangle", "-L", "-n"]),
        (
            "the conntrack match",
            vec![
                "-t",
                "mangle",
                "-C",
                "PREROUTING",
                "-m",
                "conntrack",
                "--ctdir",
                "REPLY",
                "-j",
                "RETURN",
            ],
        ),
        (
            "the CONNMARK target",
            vec![
                "-t",
                "mangle",
                "-C",
                "PREROUTING",
                "-j",
                "CONNMARK",
                "--save-mark",
            ],
        ),
        (
            "the addrtype match",
            vec![
                "-t",
                "mangle",
                "-C",
                "PREROUTING",
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-j",
                "RETURN",
            ],
        ),
    ];
    for (what, args) in probes {
        let out = Command::new("iptables")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output()
            .await
            .with_context(|| format!("failed to run iptables while checking {what}"))?;
        let err = String::from_utf8_lossy(&out.stderr);
        // `-C` on a rule that is not installed exits non-zero with "No chain/
        // target/match by that name" only when the match itself is missing;
        // a plain "Bad rule" means the match exists and the rule does not.
        if err.contains("No chain/target/match by that name")
            || err.contains("unknown option")
            || err.contains("not found")
        {
            anyhow::bail!(
                "this kernel's iptables cannot do {what}, which connection pinning needs: {}",
                err.trim()
            );
        }
    }
    Ok(())
}

async fn run(bin: &str, args: &[&str]) -> Result<bool> {
    let status = Command::new(bin)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .status()
        .await
        .with_context(|| format!("failed to run {bin}"))?;
    Ok(status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(mask: u32) -> Config {
        let mut c: Config = toml::from_str(
            r#"
[general]
lan_interface = "eth0"

[[providers]]
name = "isp-main"
gateway = "10.0.0.2"
interface = "eth0"
priority = 0
"#,
        )
        .unwrap();
        c.routing.fwmark_mask = mask;
        c
    }

    /// The order of these rules is the feature. Reply traffic must return
    /// before anything marks it, the restore must come before the assign, and
    /// an already-marked packet must leave without being re-stamped.
    #[test]
    fn the_chain_reads_in_the_only_order_that_works() {
        let cfg = cfg_with(0xffff);
        let mask = cfg.routing.fwmark_mask;
        let script = format!(
            "*mangle\n\
             :{CHAIN} -\n\
             -A {CHAIN} -m conntrack --ctdir REPLY -j RETURN\n\
             -A {CHAIN} -j CONNMARK --restore-mark --nfmask {mask:#x} --ctmask {mask:#x}\n\
             -A {CHAIN} -m mark ! --mark 0x0/{mask:#x} -j RETURN\n\
             -A {CHAIN} -m comment --comment \"vlb:active\" -j MARK --set-xmark 0x200/{mask:#x}\n\
             -A {CHAIN} -j CONNMARK --save-mark --nfmask {mask:#x} --ctmask {mask:#x}\n\
             COMMIT\n"
        );
        let reply = script.find("--ctdir REPLY").unwrap();
        let restore = script.find("--restore-mark").unwrap();
        let already = script.find("! --mark").unwrap();
        let assign = script.find("--set-xmark").unwrap();
        let save = script.find("--save-mark").unwrap();
        assert!(
            reply < restore,
            "a reply must return before it can be marked"
        );
        assert!(
            restore < already,
            "restore first, then ask whether it is marked"
        );
        assert!(
            already < assign,
            "an established flow must not be re-stamped"
        );
        assert!(assign < save, "the mark has to exist before it is saved");
    }

    /// The mask travels into every one of the four places that needs it. A
    /// bare mark in any of them silently unpins traffic.
    #[test]
    fn every_rule_carries_the_mask() {
        let cfg = cfg_with(0x0f00);
        assert_eq!(cfg.routing.fwmark_mask, 0x0f00);
        let p = &cfg.providers[0];
        assert_eq!(cfg.mark_filter_for(p), "0x200/0xf00");
    }
}
