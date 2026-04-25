//! Per-interface traffic counter sampler.
//!
//! The kernel exposes cumulative rx/tx byte and packet counters in
//! `/proc/net/dev`. We poll it on a fixed cadence, compute the delta since
//! our previous sample for each interface we care about, and persist the
//! result into `traffic_samples` so the TUI and `vlb stats` can build rate
//! graphs without having to keep a separate log.
//!
//! Deltas — not raw counters — are stored. That makes aggregation
//! (`SUM` over a time window) trivial and also makes the storage survive
//! kernel counter wraps/resets (on reset we skip one cycle rather than
//! emitting a huge spike).

use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, Default)]
pub struct IfCounters {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

/// Read `/proc/net/dev` and return a map `iface -> counters`.
///
/// On non-Linux targets this returns an empty map so the rest of the
/// codebase compiles unchanged (the service is Linux-only at runtime, but
/// the unit tests must still build on Windows/macOS dev boxes).
#[cfg(target_os = "linux")]
pub async fn snapshot() -> Result<HashMap<String, IfCounters>> {
    let raw = tokio::fs::read_to_string("/proc/net/dev")
        .await
        .map_err(|e| anyhow::anyhow!("failed to read /proc/net/dev: {e}"))?;
    Ok(parse_proc_net_dev(&raw))
}

#[cfg(not(target_os = "linux"))]
pub async fn snapshot() -> Result<HashMap<String, IfCounters>> {
    Ok(HashMap::new())
}

/// Parse the textual `/proc/net/dev` format. Pulled out for unit testing.
///
/// Layout (two header lines, then one row per interface):
///
/// ```text
/// Inter-|   Receive                                                |  Transmit
///  face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop ...
///   eth0: 12345   67      0    0    0    0     0          0        98765   43       0    0    ...
/// ```
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_proc_net_dev(raw: &str) -> HashMap<String, IfCounters> {
    let mut out = HashMap::new();
    for line in raw.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_string();
        if name.is_empty() {
            continue;
        }
        let cols: Vec<&str> = rest.split_whitespace().collect();
        // 8 receive + 8 transmit = 16 columns.
        if cols.len() < 16 {
            continue;
        }
        let parse = |idx: usize| cols[idx].parse::<u64>().unwrap_or(0);
        out.insert(
            name,
            IfCounters {
                rx_bytes: parse(0),
                rx_packets: parse(1),
                tx_bytes: parse(8),
                tx_packets: parse(9),
            },
        );
    }
    out
}

/// Subtract previous counters from current. If the current value is smaller
/// (counter reset / overflow on 32-bit kernels), return None so the caller
/// can skip the sample instead of emitting a negative delta.
pub fn delta(prev: IfCounters, curr: IfCounters) -> Option<IfCounters> {
    Some(IfCounters {
        rx_bytes: curr.rx_bytes.checked_sub(prev.rx_bytes)?,
        rx_packets: curr.rx_packets.checked_sub(prev.rx_packets)?,
        tx_bytes: curr.tx_bytes.checked_sub(prev.tx_bytes)?,
        tx_packets: curr.tx_packets.checked_sub(prev.tx_packets)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let raw = "Inter-|   Receive                                                |  Transmit\n\
                   face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n\
                      lo:  100    2    0    0    0     0          0         0       100    2    0    0    0     0       0          0\n\
                    eth0: 5000   50    0    0    0     0          0         0      8000   40    0    0    0     0       0          0\n";
        let got = parse_proc_net_dev(raw);
        assert_eq!(got.len(), 2);
        let eth0 = got.get("eth0").unwrap();
        assert_eq!(eth0.rx_bytes, 5000);
        assert_eq!(eth0.rx_packets, 50);
        assert_eq!(eth0.tx_bytes, 8000);
        assert_eq!(eth0.tx_packets, 40);
    }

    #[test]
    fn delta_detects_reset() {
        let prev = IfCounters {
            rx_bytes: 100,
            ..Default::default()
        };
        let curr = IfCounters {
            rx_bytes: 50,
            ..Default::default()
        };
        assert!(delta(prev, curr).is_none());
    }

    #[test]
    fn delta_subtracts() {
        let prev = IfCounters {
            rx_bytes: 100,
            tx_bytes: 200,
            ..Default::default()
        };
        let curr = IfCounters {
            rx_bytes: 150,
            tx_bytes: 260,
            ..Default::default()
        };
        let d = delta(prev, curr).unwrap();
        assert_eq!(d.rx_bytes, 50);
        assert_eq!(d.tx_bytes, 60);
    }
}
