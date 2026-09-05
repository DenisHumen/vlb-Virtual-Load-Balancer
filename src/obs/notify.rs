//! `sd_notify(3)` without libsystemd.
//!
//! Best-effort and silent by design. When `NOTIFY_SOCKET` is not set — a
//! terminal, a container, the test lab — every call here is a no-op. Under
//! systemd, `STATUS=` puts a one-line summary of what the gateway is doing
//! into `systemctl status vlb`, which is the first place an operator looks,
//! and `READY=1` / `STOPPING=1` mark the lifecycle for units that opt into
//! `Type=notify`.
//!
//! The shipped unit uses `Type=exec` with `NotifyAccess=main`: the status
//! line is shown, but startup does not *depend* on the notification. That
//! keeps an older binary — say, one rolled back to after a bad update —
//! startable under the newer unit, which `Type=notify` would not allow.

/// Tell systemd the daemon is operational.
pub fn ready() {
    send("READY=1");
}

/// Tell systemd a shutdown is in progress.
pub fn stopping() {
    send("STOPPING=1");
}

/// One-line status, shown by `systemctl status`.
pub fn status(msg: &str) {
    send(&format!("STATUS={}", one_line(msg)));
}

/// systemd requires a single line; keep it short enough to read.
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .take(240)
        .collect()
}

#[cfg(target_os = "linux")]
fn send(payload: &str) {
    use std::os::unix::net::UnixDatagram;
    use std::sync::OnceLock;

    static SOCKET: OnceLock<Option<(UnixDatagram, String)>> = OnceLock::new();
    let entry = SOCKET.get_or_init(|| {
        let path = std::env::var("NOTIFY_SOCKET").ok()?;
        if path.is_empty() {
            return None;
        }
        let sock = UnixDatagram::unbound().ok()?;
        Some((sock, path))
    });
    let Some((sock, path)) = entry else { return };

    // A datagram send never blocks meaningfully, so this is safe from an
    // async context. Failures are deliberately ignored: a lost status line
    // is not worth a log message, let alone an error.
    if let Some(name) = path.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        if let Ok(addr) = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()) {
            let _ = sock.send_to_addr(payload.as_bytes(), &addr);
        }
    } else {
        let _ = sock.send_to(payload.as_bytes(), path);
    }
}

#[cfg(not(target_os = "linux"))]
fn send(_payload: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_flattened_to_one_line() {
        assert_eq!(one_line("a\nb\r\nc"), "a b  c");
        assert!(one_line(&"x".repeat(1000)).chars().count() <= 240);
    }

    /// With no NOTIFY_SOCKET in the environment every call must be a silent
    /// no-op — this is the path the lab, `--dry-run` and plain terminals take.
    #[test]
    fn calls_are_noops_without_a_socket() {
        ready();
        status("anything");
        stopping();
    }
}
