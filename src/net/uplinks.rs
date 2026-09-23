//! Traffic per uplink, counted where it is forwarded.
//!
//! `/proc/net/dev` counts an interface, not an uplink. With one interface per
//! provider that is the same thing; with several providers behind one
//! interface — the single-armed layout vlb is often deployed in — every
//! provider would be credited with the whole interface, and the per-provider
//! numbers were identical to the byte while their sum was the real total
//! times the number of providers.
//!
//! So count forwarded packets instead, in a chain of our own hooked into
//! `FORWARD`, split by the provider a connection belongs to:
//!
//! ```text
//! -A VLB_UPLINKS -m connmark --mark 0x200/0xffff -m conntrack --ctdir ORIGINAL -m comment --comment vlb:up:0x200 -j RETURN
//! -A VLB_UPLINKS -m connmark --mark 0x200/0xffff -m conntrack --ctdir REPLY    -m comment --comment vlb:down:0x200 -j RETURN
//! …one pair per provider…
//! -A VLB_UPLINKS -m conntrack --ctdir ORIGINAL -m comment --comment vlb:up:unmarked -j RETURN
//! -A VLB_UPLINKS -m conntrack --ctdir REPLY    -m comment --comment vlb:down:unmarked -j RETURN
//! ```
//!
//! A connection carries its provider's mark when connection pinning stamped
//! it. One that carries none follows the main table's default route — the
//! active provider's — so the unmarked pair is credited to whichever
//! provider was active during the interval. Without pinning, that is every
//! forwarded connection, and the attribution is exact: there is no other
//! path a forwarded packet can take.
//!
//! The comments carry the mark rather than the provider's name, so no name
//! ever has to survive iptables' quoting.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::debug;

use crate::traffic::IfCounters;

/// The chain holding the counting rules.
pub const CHAIN: &str = "VLB_UPLINKS";

const UNMARKED: &str = "unmarked";

/// The rules, as `iptables-restore --noflush` input. Declaring the chain
/// replaces its contents in one step, so there is never a moment in which
/// it is hooked but empty.
pub fn rules(marks: &[u32], mask: u32) -> String {
    let mut s = format!("*filter\n:{CHAIN} -\n");
    for m in marks {
        for (dir, tag) in [("ORIGINAL", "up"), ("REPLY", "down")] {
            s.push_str(&format!(
                "-A {CHAIN} -m connmark --mark {m:#x}/{mask:#x} -m conntrack --ctdir {dir} \
                 -m comment --comment vlb:{tag}:{m:#x} -j RETURN\n"
            ));
        }
    }
    for (dir, tag) in [("ORIGINAL", "up"), ("REPLY", "down")] {
        s.push_str(&format!(
            "-A {CHAIN} -m conntrack --ctdir {dir} -m comment --comment vlb:{tag}:{UNMARKED} \
             -j RETURN\n"
        ));
    }
    s.push_str("COMMIT\n");
    s
}

/// Install (or refresh) the chain and hook it into `FORWARD`.
pub async fn install(marks: &[u32], mask: u32) -> Result<()> {
    // `-N` fails when the chain exists, which is the normal case on every
    // start after the first.
    let _ = run("iptables", &["-t", "filter", "-N", CHAIN]).await;
    restore(&rules(marks, mask)).await?;
    let jump = ["FORWARD", "-j", CHAIN];
    let mut check = vec!["-t", "filter", "-C"];
    check.extend_from_slice(&jump);
    if !run("iptables", &check).await.unwrap_or(false) {
        let ok = run(
            "iptables",
            &["-t", "filter", "-I", "FORWARD", "1", "-j", CHAIN],
        )
        .await
        .context("failed to invoke iptables to hook the uplink accounting chain")?;
        if !ok {
            anyhow::bail!("iptables refused to hook {CHAIN} into FORWARD");
        }
    }
    debug!(chain = CHAIN, "uplink accounting rules installed");
    Ok(())
}

/// Remove the jump and the chain. Everything is allowed to fail: most boxes
/// this runs on never had them.
pub async fn remove() {
    for _ in 0..8 {
        if !run("iptables", &["-t", "filter", "-D", "FORWARD", "-j", CHAIN])
            .await
            .unwrap_or(false)
        {
            break;
        }
    }
    let _ = run("iptables", &["-t", "filter", "-F", CHAIN]).await;
    let _ = run("iptables", &["-t", "filter", "-X", CHAIN]).await;
}

/// The counters as they stand, keyed by mark (`None` for unmarked).
pub async fn read() -> Result<HashMap<Option<u32>, IfCounters>> {
    let out = Command::new("iptables-save")
        .args(["-c", "-t", "filter"])
        .kill_on_drop(true)
        .output()
        .await
        .context("failed to run iptables-save")?;
    if !out.status.success() {
        anyhow::bail!(
            "iptables-save failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let parsed = parse(&String::from_utf8_lossy(&out.stdout));
    if parsed.is_empty() {
        anyhow::bail!("the {CHAIN} chain is gone");
    }
    Ok(parsed)
}

/// Pull our counters out of `iptables-save -c`. Download (reply direction)
/// is `rx`, upload is `tx`, as for an uplink's own interface.
pub fn parse(save: &str) -> HashMap<Option<u32>, IfCounters> {
    let mut out: HashMap<Option<u32>, IfCounters> = HashMap::new();
    for line in save.lines() {
        let Some(rest) = line.trim().strip_prefix('[') else {
            continue;
        };
        let Some((counts, rule)) = rest.split_once(']') else {
            continue;
        };
        if !rule.contains(&format!("-A {CHAIN} ")) {
            continue;
        }
        let Some((pkts, bytes)) = counts.split_once(':') else {
            continue;
        };
        let (Ok(pkts), Ok(bytes)) = (pkts.trim().parse::<u64>(), bytes.trim().parse::<u64>())
        else {
            continue;
        };
        let Some(tag) = rule
            .split_whitespace()
            .map(|w| w.trim_matches('"'))
            .find_map(|w| w.strip_prefix("vlb:"))
        else {
            continue;
        };
        let Some((dir, key)) = tag.split_once(':') else {
            continue;
        };
        let key = if key == UNMARKED {
            None
        } else {
            match u32::from_str_radix(key.trim_start_matches("0x"), 16) {
                Ok(m) => Some(m),
                Err(_) => continue,
            }
        };
        let entry = out.entry(key).or_default();
        match dir {
            "down" => {
                entry.rx_bytes = bytes;
                entry.rx_packets = pkts;
            }
            "up" => {
                entry.tx_bytes = bytes;
                entry.tx_packets = pkts;
            }
            _ => {}
        }
    }
    out
}

/// Turn two readings into one interval's traffic per provider mark.
///
/// Unmarked traffic went out through the default route, so it belongs to
/// `active_mark`; with nothing active it is not credited to anyone rather
/// than guessed. A counter that went backwards (the chain was rebuilt) is
/// skipped for this interval, like a reset interface counter.
pub fn attribute(
    prev: &HashMap<Option<u32>, IfCounters>,
    curr: &HashMap<Option<u32>, IfCounters>,
    active_mark: Option<u32>,
) -> HashMap<u32, IfCounters> {
    let mut out: HashMap<u32, IfCounters> = HashMap::new();
    for (key, now) in curr {
        let Some(before) = prev.get(key) else {
            continue;
        };
        let Some(d) = crate::traffic::delta(*before, *now) else {
            continue;
        };
        let Some(mark) = key.or(active_mark) else {
            continue;
        };
        let e = out.entry(mark).or_default();
        e.rx_bytes += d.rx_bytes;
        e.rx_packets += d.rx_packets;
        e.tx_bytes += d.tx_bytes;
        e.tx_packets += d.tx_packets;
    }
    out
}

async fn restore(script: &str) -> Result<()> {
    let mut child = Command::new("iptables-restore")
        .args(["-w", "5", "-T", "filter", "--noflush"])
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
        .context("failed to write the accounting rules to iptables-restore")?;
    let out = child
        .wait_with_output()
        .await
        .context("iptables-restore did not finish")?;
    if !out.status.success() {
        anyhow::bail!(
            "iptables-restore refused the uplink accounting rules: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

async fn run(bin: &str, args: &[&str]) -> Result<bool> {
    let status = Command::new(bin)
        .args(args)
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .with_context(|| format!("failed to invoke `{bin}`"))?;
    Ok(status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(rx: u64, tx: u64) -> IfCounters {
        IfCounters {
            rx_bytes: rx,
            rx_packets: rx / 100,
            tx_bytes: tx,
            tx_packets: tx / 100,
        }
    }

    /// Provider rules come first and return, so a marked connection is
    /// counted once, by its own provider — never again as "unmarked".
    #[test]
    fn provider_rules_precede_the_catch_all_and_return() {
        let r = rules(&[0x200, 0x201], 0xffff);
        let lines: Vec<&str> = r.lines().filter(|l| l.starts_with("-A ")).collect();
        assert_eq!(lines.len(), 6);
        assert!(lines[0].contains("--mark 0x200/0xffff") && lines[0].contains("ORIGINAL"));
        assert!(lines[3].contains("--mark 0x201/0xffff") && lines[3].contains("REPLY"));
        assert!(lines[4].contains("vlb:up:unmarked") && !lines[4].contains("connmark"));
        assert!(lines.iter().all(|l| l.ends_with("-j RETURN")));
        assert!(r.starts_with("*filter\n:VLB_UPLINKS -\n") && r.ends_with("COMMIT\n"));
    }

    #[test]
    fn counters_are_read_from_iptables_save() {
        let save = "\
*filter
:FORWARD ACCEPT [0:0]
:VLB_UPLINKS - [0:0]
[10:1500] -A FORWARD -j VLB_UPLINKS
[7:700] -A VLB_UPLINKS -m connmark --mark 0x200/0xffff -m conntrack --ctdir ORIGINAL -m comment --comment vlb:up:0x200 -j RETURN
[9:9000] -A VLB_UPLINKS -m connmark --mark 0x200/0xffff -m conntrack --ctdir REPLY -m comment --comment vlb:down:0x200 -j RETURN
[3:300] -A VLB_UPLINKS -m conntrack --ctdir ORIGINAL -m comment --comment \"vlb:up:unmarked\" -j RETURN
[4:4000] -A VLB_UPLINKS -m conntrack --ctdir REPLY -m comment --comment vlb:down:unmarked -j RETURN
[5:500] -A VLB_CLIENTS -d 10.0.0.50/32 -m comment --comment vlb:dl:10.0.0.50
COMMIT
";
        let p = parse(save);
        assert_eq!(p.len(), 2);
        let marked = p[&Some(0x200)];
        assert_eq!((marked.rx_bytes, marked.tx_bytes), (9000, 700));
        assert_eq!((marked.rx_packets, marked.tx_packets), (9, 7));
        let unmarked = p[&None];
        assert_eq!((unmarked.rx_bytes, unmarked.tx_bytes), (4000, 300));
    }

    /// The point of the whole module: two providers behind one interface
    /// each get their own traffic, unmarked traffic goes to the active one
    /// only, and the parts add up to the whole — nothing is counted twice.
    #[test]
    fn traffic_is_split_between_uplinks_not_copied_to_each() {
        let prev = HashMap::from([
            (Some(0x200), c(1_000, 100)),
            (Some(0x201), c(2_000, 200)),
            (None, c(10_000, 1_000)),
        ]);
        let curr = HashMap::from([
            (Some(0x200), c(1_500, 150)),
            (Some(0x201), c(2_000, 200)),
            (None, c(30_000, 3_000)),
        ]);
        let per = attribute(&prev, &curr, Some(0x201));
        assert_eq!(per[&0x200].rx_bytes, 500);
        assert_eq!(
            per[&0x201].rx_bytes, 20_000,
            "unmarked goes to the active one"
        );
        assert_eq!(per[&0x201].tx_bytes, 2_000);
        let total: u64 = per.values().map(|c| c.rx_bytes).sum();
        assert_eq!(total, 500 + 20_000);

        // Nothing active: unmarked traffic is credited to no one.
        let per = attribute(&prev, &curr, None);
        assert_eq!(per[&0x200].rx_bytes, 500);
        assert_eq!(per.values().map(|c| c.rx_bytes).sum::<u64>(), 500);
    }

    /// A rebuilt chain starts from zero; that interval is skipped rather
    /// than turned into a huge negative-wrapped spike.
    #[test]
    fn a_counter_reset_skips_one_interval() {
        let prev = HashMap::from([(None, c(50_000, 5_000))]);
        let curr = HashMap::from([(None, c(100, 10))]);
        assert!(attribute(&prev, &curr, Some(0x200)).is_empty());
        // And a key seen for the first time has nothing to diff against.
        let curr = HashMap::from([(None, c(60_000, 6_000)), (Some(0x202), c(10, 10))]);
        let per = attribute(&prev, &curr, Some(0x200));
        assert_eq!(per.keys().copied().collect::<Vec<_>>(), vec![0x200]);
    }
}
