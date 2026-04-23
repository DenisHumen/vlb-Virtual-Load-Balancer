use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout as tokio_timeout;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProbeOutcome {
    Success { latency: Duration },
    Failed,
}

impl ProbeOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self, ProbeOutcome::Success { .. })
    }

    pub fn latency_ms(&self) -> Option<f64> {
        match self {
            ProbeOutcome::Success { latency } => Some(latency.as_secs_f64() * 1000.0),
            ProbeOutcome::Failed => None,
        }
    }
}

/// Single ICMP echo via the system `ping` binary.
///
/// `mark`, if set, becomes the socket's `SO_MARK` via `ping -m <mark>`. The
/// kernel then consults `ip rule fwmark <mark> lookup <table>` to select a
/// per-provider routing table — this is how we probe each upstream's
/// *internet* reachability independently, even for providers that are not
/// currently the owner of the main default route.
///
/// The ping binary is additionally wrapped in a `tokio::time::timeout` as a
/// safety net: `-W` already bounds the ICMP wait, but a stuck ping process
/// (e.g. DNS lookup on a hostile resolver in some distributions, or a
/// blocked syscall) would otherwise hang the probe task indefinitely.
async fn ping_once(target: Ipv4Addr, timeout: Duration, mark: Option<u32>) -> ProbeOutcome {
    // iputils ping accepts a float for `-W`; 0.2 s is the minimum we allow
    // so probes cannot accidentally degenerate into instant-fail spinning.
    let timeout_str = format!("{:.2}", timeout.as_secs_f64().max(0.2));
    let target_str = target.to_string();
    let mark_str = mark.map(|m| m.to_string());

    let mut cmd = Command::new("ping");
    cmd.args(["-c", "1", "-W", &timeout_str, "-n", "-q"]);
    if let Some(ref m) = mark_str {
        cmd.args(["-m", m.as_str()]);
    }
    cmd.arg(&target_str);
    cmd.stdin(std::process::Stdio::null());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());

    // Hard wall-clock cap: ping's own -W + a generous slack. If we ever hit
    // this branch it means ping itself is misbehaving, not just that the
    // target is unreachable — we treat it as a failed probe either way.
    let hard_deadline = timeout
        .saturating_mul(2)
        .saturating_add(Duration::from_millis(500));

    let started = Instant::now();
    let result = tokio_timeout(hard_deadline, cmd.kill_on_drop(true).output()).await;

    match result {
        Ok(Ok(out)) if out.status.success() => {
            ProbeOutcome::Success { latency: started.elapsed() }
        }
        _ => ProbeOutcome::Failed,
    }
}

/// Ping the provider's next-hop gateway. No fwmark: the gateway lives on a
/// directly-connected subnet and is resolved via the main table's interface
/// route, so we always reach it the same way regardless of which provider
/// currently owns the default.
pub async fn check_gateway(gateway: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
    ping_once(gateway, timeout, None).await
}

/// Ping external targets via a specific provider, forced by fwmark. Returns
/// success on the first reachable target. Fails only if *all* targets are
/// unreachable — single-target hiccups don't flap the state machine.
pub async fn check_internet_via(
    targets: &[Ipv4Addr],
    timeout: Duration,
    mark: u32,
) -> ProbeOutcome {
    for &t in targets {
        let outcome = ping_once(t, timeout, Some(mark)).await;
        if outcome.is_success() {
            return outcome;
        }
    }
    ProbeOutcome::Failed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_helpers() {
        let ok = ProbeOutcome::Success { latency: Duration::from_millis(5) };
        assert!(ok.is_success());
        assert_eq!(ok.latency_ms(), Some(5.0));

        let fail = ProbeOutcome::Failed;
        assert!(!fail.is_success());
        assert_eq!(fail.latency_ms(), None);
    }
}
