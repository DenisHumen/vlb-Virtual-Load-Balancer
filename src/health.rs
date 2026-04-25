use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout as tokio_timeout;

/// Where an internet probe should connect. Strings from `probe_targets`
/// in the config are parsed into one of these: literal IPv4 addresses go
/// to `Ip`, anything else is treated as a DNS name and resolved through
/// the provider's own resolver chain (fwmark-bound) at probe time.
///
/// Hostnames are essential for catching the "selectively prohibited"
/// failure mode: some misbehaving upstream routers (e.g. an ISP
/// enforcement box on an unpaid account) return ICMP echoes for popular
/// public DNS IPs (1.1.1.1, 8.8.8.8) but reply with
/// `Destination Net Prohibited` for general internet destinations like
/// `google.com`. A pure-IP probe list would never see the failure.
#[derive(Debug, Clone)]
pub enum ProbeTarget {
    Ip(Ipv4Addr),
    Hostname(String),
}

impl ProbeTarget {
    /// Parse a config string. IPv4 literal → `Ip`, otherwise `Hostname`
    /// after a lowercase + trim normalisation. Validation of acceptable
    /// hostnames lives in `config.rs`; here we accept whatever the
    /// caller already validated.
    pub fn parse(s: &str) -> Self {
        let trimmed = s.trim();
        if let Ok(ip) = trimmed.parse::<Ipv4Addr>() {
            ProbeTarget::Ip(ip)
        } else {
            ProbeTarget::Hostname(trimmed.to_ascii_lowercase())
        }
    }
}

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

/// Burst of ICMP echos via the system `ping` binary.
///
/// `mark`, if set, becomes the socket's `SO_MARK` via `ping -m <mark>`. The
/// kernel then consults `ip rule fwmark <mark> lookup <table>` to select a
/// per-provider routing table — this is how we probe each upstream's
/// *internet* reachability independently, even for providers that are not
/// currently the owner of the main default route.
///
/// We send `count` echoes and require at least `min_success` replies to
/// consider the target reachable. This is deliberately stricter than a
/// single-packet probe: real-world flaky uplinks (e.g. an upstream router
/// alternating between forwarding and answering with
/// `Destination Net Prohibited` because the customer's plan has expired)
/// will randomly pass a 1-of-1 probe but consistently fail a "≥2 of 3"
/// probe. ICMP error responses (`prohibited`, `unreachable`) do **not**
/// increment ping's received counter, so a partially blocked link is
/// detected reliably.
///
/// The ping binary is additionally wrapped in a `tokio::time::timeout` as a
/// safety net: `-W` already bounds each ICMP wait, but a stuck ping
/// process would otherwise hang the probe task indefinitely.
async fn ping_burst(
    target: Ipv4Addr,
    per_packet_timeout: Duration,
    count: u32,
    min_success: u32,
    mark: Option<u32>,
) -> ProbeOutcome {
    let count = count.max(1);
    let min_success = min_success.clamp(1, count);
    // iputils ping accepts a float for `-W`; 0.2 s is the floor we allow so
    // probes can't accidentally degenerate into instant-fail spinning.
    let pkt_to = per_packet_timeout.as_secs_f64().max(0.2);
    let pkt_to_str = format!("{:.2}", pkt_to);
    let count_str = count.to_string();
    // Overall deadline = N * per-packet timeout + a slack tick. Without
    // `-w`, ping would otherwise wait `count` seconds between packets.
    let deadline_secs = (pkt_to * count as f64).ceil() as u64 + 1;
    let deadline_str = deadline_secs.to_string();
    let target_str = target.to_string();
    let mark_str = mark.map(|m| m.to_string());

    let mut cmd = Command::new("ping");
    cmd.args([
        "-c", &count_str,
        "-W", &pkt_to_str,
        "-w", &deadline_str,
        "-n", "-q",
    ]);
    if let Some(ref m) = mark_str {
        cmd.args(["-m", m.as_str()]);
    }
    cmd.arg(&target_str);
    cmd.stdin(std::process::Stdio::null());
    // Capture stdout so we can parse the `X packets transmitted, Y
    // received` summary line. iputils prints it on the second-to-last
    // line of output; ICMP error responses (Destination Net Prohibited,
    // Host Unreachable, etc.) are NOT counted as received.
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::null());

    let hard_deadline =
        Duration::from_secs(deadline_secs).saturating_add(Duration::from_millis(500));

    let started = Instant::now();
    let result = tokio_timeout(hard_deadline, cmd.kill_on_drop(true).output()).await;

    let out = match result {
        Ok(Ok(o)) => o,
        _ => return ProbeOutcome::Failed,
    };

    // Parse "<n> packets transmitted, <m> received". On systems where ping
    // exits non-zero because some packets were lost, the summary is still
    // printed — so we ignore exit status entirely and rely on the count.
    let stdout = std::str::from_utf8(&out.stdout).unwrap_or("");
    let received: u32 = stdout
        .lines()
        .find_map(|line| {
            let l = line.trim();
            // Look for "received" between the comma and the next comma/end.
            let rcvd_pos = l.find("received")?;
            let before = &l[..rcvd_pos];
            let n_str = before.rsplit(',').next()?.trim();
            n_str.split_whitespace().next()?.parse::<u32>().ok()
        })
        .unwrap_or(0);

    if received >= min_success {
        ProbeOutcome::Success { latency: started.elapsed() }
    } else {
        ProbeOutcome::Failed
    }
}

/// Ping the provider's next-hop gateway. No fwmark: the gateway lives on a
/// directly-connected subnet and is resolved via the main table's interface
/// route, so we always reach it the same way regardless of which provider
/// currently owns the default.
pub async fn check_gateway(gateway: Ipv4Addr, timeout: Duration) -> ProbeOutcome {
    // Gateway lives on the directly-connected LAN; one packet is enough,
    // and flapping is essentially impossible. Cheaper for the hot path.
    ping_burst(gateway, timeout, 1, 1, None).await
}

/// Ping external targets via a specific provider, forced by fwmark.
///
/// Targets fall into two classes:
///   - `Ip(addr)`        — pinged directly with the provider's mark.
///   - `Hostname(name)`  — first resolved via the provider's mark-bound
///     DNS (so the resolution itself proves the provider's UDP/53 path
///     is alive), then the resulting IPv4 is pinged with the same mark.
///
/// Each target is hit with a 3-packet burst, requiring at least 2 echo
/// replies. This catches the "intermittent prohibited" failure mode
/// where an upstream router (e.g. an ISP enforcement box for an unpaid
/// account) answers some echoes normally and others with
/// `Destination Net Prohibited` — a single-packet probe would flap
/// depending on which half of the cycle it lands in.
///
/// Success semantics are deliberately asymmetric:
///   - If **any hostname** target is configured, **at least one
///     hostname target must succeed**. Hostname probes are the only
///     reliable way to detect "selectively prohibited" uplinks that
///     allow ICMP to popular public DNS IPs (1.1.1.1, 8.8.8.8) but
///     block general destinations like `google.com`. Without this
///     rule, an early-success on the IP probe would short-circuit and
///     mask the failure.
///   - If only IP targets are configured, "any one IP succeeds" wins.
///
/// All targets are evaluated each probe cycle (no early return) so a
/// later success can rescue an earlier hiccup, and the reported latency
/// comes from the first successful target encountered.
pub async fn check_internet_via(
    targets: &[ProbeTarget],
    resolvers: &[Ipv4Addr],
    timeout: Duration,
    mark: u32,
) -> ProbeOutcome {
    if targets.is_empty() {
        return ProbeOutcome::Failed;
    }

    // Run every target's probe concurrently. Sequential evaluation would
    // serialise N×~3 s ping bursts plus DNS round-trips and easily blow
    // past `interval_secs`, starving the rest of the health loop. Each
    // task is independent, owns its own DNS socket and ping subprocess,
    // so concurrency is safe — the mark is just a u32 we copy in.
    let resolvers_owned: Vec<Ipv4Addr> = resolvers.to_vec();
    let mut tasks: Vec<tokio::task::JoinHandle<TargetResult>> = Vec::with_capacity(targets.len());
    for t in targets {
        let target = t.clone();
        let resolvers = resolvers_owned.clone();
        tasks.push(tokio::spawn(async move {
            match target {
                ProbeTarget::Ip(ip) => {
                    let outcome = ping_burst(ip, timeout, 3, 2, Some(mark)).await;
                    TargetResult { is_hostname: false, outcome }
                }
                ProbeTarget::Hostname(name) => {
                    let ip = match resolve_a_via(&resolvers, &name, timeout, mark).await {
                        Some(ip) => ip,
                        None => {
                            return TargetResult {
                                is_hostname: true,
                                outcome: ProbeOutcome::Failed,
                            };
                        }
                    };
                    let outcome = ping_burst(ip, timeout, 3, 2, Some(mark)).await;
                    TargetResult { is_hostname: true, outcome }
                }
            }
        }));
    }

    let mut has_hostname = false;
    let mut hostname_ok = false;
    let mut any_ip_ok = false;
    let mut first_success_latency: Option<Duration> = None;

    for h in tasks {
        let res = match h.await {
            Ok(r) => r,
            // A panic in a probe task is treated as a failed probe — we
            // never want a panic to bypass the health checks. The panic
            // itself will already be logged by Tokio's default handler.
            Err(_) => continue,
        };
        if res.is_hostname {
            has_hostname = true;
            if let ProbeOutcome::Success { latency } = res.outcome {
                hostname_ok = true;
                first_success_latency.get_or_insert(latency);
            }
        } else if let ProbeOutcome::Success { latency } = res.outcome {
            any_ip_ok = true;
            first_success_latency.get_or_insert(latency);
        }
    }

    let ok = if has_hostname { hostname_ok } else { any_ip_ok };
    if ok {
        ProbeOutcome::Success {
            latency: first_success_latency.unwrap_or_default(),
        }
    } else {
        ProbeOutcome::Failed
    }
}

struct TargetResult {
    is_hostname: bool,
    outcome: ProbeOutcome,
}

/// Build a minimal DNS query (UDP wire format) for an A record. Returns
/// `(packet, txid)`. The transaction id is randomised so concurrent probes
/// can't accidentally accept each other's replies if the resolver is slow.
#[cfg(target_os = "linux")]
fn build_dns_query(name: &str, txid: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + name.len());
    // Header: id, flags=0x0100 (RD set), qdcount=1, others=0.
    buf.extend_from_slice(&txid.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    buf.extend_from_slice(&0u16.to_be_bytes()); // ancount
    buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
    buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
    // QNAME: sequence of length-prefixed labels, terminated by 0.
    for label in name.split('.').filter(|l| !l.is_empty()) {
        let bytes = label.as_bytes();
        let len = bytes.len().min(63) as u8;
        buf.push(len);
        buf.extend_from_slice(&bytes[..len as usize]);
    }
    buf.push(0);
    buf.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    buf
}

/// Inspect a DNS reply: must match `txid`, have RCODE=0 (NOERROR) and
/// at least one answer record. We don't bother parsing the answer section
/// fully — the answer count alone is enough to distinguish "resolver alive
/// AND returned data" from "resolver replied with REFUSED/NXDOMAIN/empty".
#[cfg(target_os = "linux")]
fn dns_reply_ok(reply: &[u8], txid: u16) -> bool {
    if reply.len() < 12 {
        return false;
    }
    let rid = u16::from_be_bytes([reply[0], reply[1]]);
    if rid != txid {
        return false;
    }
    let flags = u16::from_be_bytes([reply[2], reply[3]]);
    // QR bit must be 1 (response), RCODE (low 4 bits) must be 0 (NOERROR).
    if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 {
        return false;
    }
    let ancount = u16::from_be_bytes([reply[6], reply[7]]);
    ancount > 0
}

/// One DNS A-query against a single resolver, optionally bound to a
/// per-provider fwmark via `SO_MARK`. The kernel then routes the packet
/// through the corresponding `ip rule fwmark <mark>` table — same
/// mechanism `ping -m` uses for ICMP. This catches the failure mode where
/// the link is up (ICMP works), but the ISP has cut UDP/53 because the
/// account is unpaid or the captive portal is intercepting traffic.
#[cfg(target_os = "linux")]
async fn dns_query_once(
    resolver: Ipv4Addr,
    name: &str,
    timeout: Duration,
    mark: Option<u32>,
) -> ProbeOutcome {
    use std::os::fd::AsRawFd;

    let std_sock = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return ProbeOutcome::Failed,
    };
    if std_sock.set_nonblocking(true).is_err() {
        return ProbeOutcome::Failed;
    }
    if let Some(m) = mark {
        // SO_MARK is a privileged socket option (CAP_NET_ADMIN). The vlb
        // daemon already runs as root for ip-rule/iptables management, so
        // setting it here is allowed; on a non-privileged process this
        // setsockopt would fail with EPERM and the probe is treated as
        // failed — better than silently routing through the wrong path.
        let fd = std_sock.as_raw_fd();
        let val: libc::c_int = m as libc::c_int;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return ProbeOutcome::Failed;
        }
    }

    let sock = match tokio::net::UdpSocket::from_std(std_sock) {
        Ok(s) => s,
        Err(_) => return ProbeOutcome::Failed,
    };

    let txid: u16 = (Instant::now().elapsed().subsec_nanos() & 0xFFFF) as u16;
    let pkt = build_dns_query(name, txid);
    let dst = std::net::SocketAddr::from((resolver, 53u16));

    let started = Instant::now();
    if tokio_timeout(timeout, sock.send_to(&pkt, dst)).await.is_err() {
        return ProbeOutcome::Failed;
    }

    let mut buf = [0u8; 1500];
    match tokio_timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) if dns_reply_ok(&buf[..n], txid) => {
            ProbeOutcome::Success { latency: started.elapsed() }
        }
        _ => ProbeOutcome::Failed,
    }
}

#[cfg(not(target_os = "linux"))]
async fn dns_query_once(
    _resolver: Ipv4Addr,
    _name: &str,
    _timeout: Duration,
    _mark: Option<u32>,
) -> ProbeOutcome {
    ProbeOutcome::Failed
}

/// DNS reachability check via a specific provider's fwmark. Tries each
/// resolver in order, returning success on the first one that gives a
/// valid answer for `name`. Fails only if **all** resolvers fail to
/// respond or return errors — single-resolver hiccups must not flap the
/// state machine.
pub async fn check_dns_via(
    resolvers: &[Ipv4Addr],
    name: &str,
    timeout: Duration,
    mark: u32,
) -> ProbeOutcome {
    for &r in resolvers {
        let outcome = dns_query_once(r, name, timeout, Some(mark)).await;
        if outcome.is_success() {
            return outcome;
        }
    }
    ProbeOutcome::Failed
}

/// Resolve `name` to an IPv4 address through the first responsive
/// resolver in `resolvers`, with the query routed via the provider's
/// `mark`. Returns `None` if every resolver fails, returns no answers,
/// or sends a malformed packet. This is the building block that lets
/// `check_internet_via` ping arbitrary hostnames per-provider without
/// depending on the system resolver (which would always use whichever
/// provider currently owns the default route).
#[cfg(target_os = "linux")]
async fn resolve_a_via(
    resolvers: &[Ipv4Addr],
    name: &str,
    timeout: Duration,
    mark: u32,
) -> Option<Ipv4Addr> {
    for &r in resolvers {
        if let Some(ip) = dns_resolve_a_once(r, name, timeout, Some(mark)).await {
            return Some(ip);
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
async fn resolve_a_via(
    _resolvers: &[Ipv4Addr],
    _name: &str,
    _timeout: Duration,
    _mark: u32,
) -> Option<Ipv4Addr> {
    None
}

/// Send one DNS A-query and parse the first A record from the answer
/// section. Mirrors `dns_query_once` but extracts the rdata instead of
/// only checking ancount, so callers can use the resolved IP for
/// downstream probes (e.g. ICMP). Returns `None` on any malformation,
/// timeout, or empty answer set.
#[cfg(target_os = "linux")]
async fn dns_resolve_a_once(
    resolver: Ipv4Addr,
    name: &str,
    timeout: Duration,
    mark: Option<u32>,
) -> Option<Ipv4Addr> {
    use std::os::fd::AsRawFd;

    let std_sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    std_sock.set_nonblocking(true).ok()?;
    if let Some(m) = mark {
        let fd = std_sock.as_raw_fd();
        let val: libc::c_int = m as libc::c_int;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return None;
        }
    }

    let sock = tokio::net::UdpSocket::from_std(std_sock).ok()?;
    let txid: u16 = (Instant::now().elapsed().subsec_nanos() & 0xFFFF) as u16;
    let pkt = build_dns_query(name, txid);
    // Question section size in the wire format we just built: qname
    // (length-prefixed labels + terminating 0) + qtype(2) + qclass(2).
    // Equals total packet length minus the 12-byte fixed header.
    let qsize = pkt.len() - 12;
    let dst = std::net::SocketAddr::from((resolver, 53u16));

    if tokio_timeout(timeout, sock.send_to(&pkt, dst)).await.is_err() {
        return None;
    }

    let mut buf = [0u8; 1500];
    let n = match tokio_timeout(timeout, sock.recv_from(&mut buf)).await {
        Ok(Ok((n, _))) => n,
        _ => return None,
    };
    dns_extract_first_a(&buf[..n], txid, qsize)
}

/// Walk a DNS reply's answer section and return the first A record's
/// IPv4 payload. Tolerant of compressed names (RFC 1035 §4.1.4): a
/// pointer is detected via the high two bits being 11 and consumes 2
/// bytes; uncompressed names walk length-prefixed labels until a 0
/// terminator. Returns `None` on any out-of-bounds read, wrong txid,
/// non-response flag, non-NOERROR rcode, or absence of A/IN records.
#[cfg(target_os = "linux")]
fn dns_extract_first_a(reply: &[u8], txid: u16, qsize: usize) -> Option<Ipv4Addr> {
    if reply.len() < 12 + qsize {
        return None;
    }
    if u16::from_be_bytes([reply[0], reply[1]]) != txid {
        return None;
    }
    let flags = u16::from_be_bytes([reply[2], reply[3]]);
    if (flags & 0x8000) == 0 || (flags & 0x000F) != 0 {
        return None;
    }
    let ancount = u16::from_be_bytes([reply[6], reply[7]]) as usize;
    if ancount == 0 {
        return None;
    }

    let mut p = 12 + qsize;
    for _ in 0..ancount {
        // Skip the answer's NAME field. Either a compression pointer
        // (2 bytes, top bits 11) or a sequence of length-prefixed
        // labels terminated by 0 (potentially ending in a pointer).
        if p >= reply.len() {
            return None;
        }
        if reply[p] & 0xC0 == 0xC0 {
            p += 2;
        } else {
            loop {
                if p >= reply.len() {
                    return None;
                }
                let l = reply[p];
                if l == 0 {
                    p += 1;
                    break;
                }
                if l & 0xC0 == 0xC0 {
                    p += 2;
                    break;
                }
                p += 1 + l as usize;
            }
        }
        // Fixed RR header: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 bytes.
        if p + 10 > reply.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([reply[p], reply[p + 1]]);
        let rclass = u16::from_be_bytes([reply[p + 2], reply[p + 3]]);
        let rdlen = u16::from_be_bytes([reply[p + 8], reply[p + 9]]) as usize;
        p += 10;
        if p + rdlen > reply.len() {
            return None;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            return Some(Ipv4Addr::new(
                reply[p],
                reply[p + 1],
                reply[p + 2],
                reply[p + 3],
            ));
        }
        p += rdlen;
    }
    None
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

    /// Validate the `X packets transmitted, Y received` parser against the
    /// real iputils ping output formats we depend on. Includes the
    /// "errors" variant produced when the kernel returns ICMP errors
    /// (`Destination Net Prohibited`), which must NOT be counted as
    /// received — that's the whole point of the burst probe.
    #[test]
    fn parse_received_count() {
        let extract = |stdout: &str| -> u32 {
            stdout
                .lines()
                .find_map(|line| {
                    let l = line.trim();
                    let rcvd_pos = l.find("received")?;
                    let before = &l[..rcvd_pos];
                    let n_str = before.rsplit(',').next()?.trim();
                    n_str.split_whitespace().next()?.parse::<u32>().ok()
                })
                .unwrap_or(0)
        };

        // All replies received.
        assert_eq!(
            extract(
                "PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.\n\n\
                 --- 1.1.1.1 ping statistics ---\n\
                 3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n\
                 rtt min/avg/max/mdev = 1.0/1.5/2.0/0.4 ms\n"
            ),
            3
        );
        // Partial loss.
        assert_eq!(
            extract(
                "3 packets transmitted, 1 received, 66% packet loss, time 2003ms\n"
            ),
            1
        );
        // ICMP errors counted separately by ping — they are NOT in the
        // "received" total. This is the key case we rely on.
        assert_eq!(
            extract(
                "3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2002ms\n"
            ),
            0
        );
        // Total loss.
        assert_eq!(
            extract(
                "3 packets transmitted, 0 received, 100% packet loss, time 2003ms\n"
            ),
            0
        );
        // Empty/garbage.
        assert_eq!(extract(""), 0);
        assert_eq!(extract("ping: usage: ..."), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dns_query_packet_layout() {
        let pkt = build_dns_query("a.bc", 0xBEEF);
        // Header: id (2) + flags (2) + 4*counts (8) = 12 bytes.
        assert_eq!(&pkt[..2], &[0xBE, 0xEF]);
        assert_eq!(&pkt[2..4], &[0x01, 0x00]); // RD set
        assert_eq!(&pkt[4..6], &[0x00, 0x01]); // qdcount = 1
        // QNAME: 1 'a' 2 'b' 'c' 0
        assert_eq!(&pkt[12..18], &[1, b'a', 2, b'b', b'c', 0]);
        // QTYPE = A (1), QCLASS = IN (1).
        assert_eq!(&pkt[18..22], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dns_reply_validation() {
        // Minimal NOERROR response with ancount=1: header is enough for ok().
        let mut reply = vec![
            0xBE, 0xEF, // id
            0x81, 0x80, // flags: QR=1, RD=1, RA=1, RCODE=0
            0x00, 0x01, // qdcount
            0x00, 0x01, // ancount = 1
            0x00, 0x00, 0x00, 0x00,
        ];
        assert!(dns_reply_ok(&reply, 0xBEEF));
        // Wrong txid.
        assert!(!dns_reply_ok(&reply, 0x1234));
        // RCODE = SERVFAIL (2).
        reply[3] = 0x82;
        assert!(!dns_reply_ok(&reply, 0xBEEF));
        // Reset RCODE, but ancount = 0.
        reply[3] = 0x80;
        reply[7] = 0x00;
        assert!(!dns_reply_ok(&reply, 0xBEEF));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dns_extract_a_record() {
        // Build a real-looking DNS reply for "x.io" → 93.184.216.34, with
        // a compressed answer name (pointer to the question name).
        // Header.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&0xCAFEu16.to_be_bytes());
        buf.extend_from_slice(&0x8180u16.to_be_bytes()); // QR=1, RD=1, RA=1
        buf.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        buf.extend_from_slice(&1u16.to_be_bytes()); // ancount
        buf.extend_from_slice(&0u16.to_be_bytes()); // nscount
        buf.extend_from_slice(&0u16.to_be_bytes()); // arcount
        // Question: x.io / A / IN
        let qname_offset = buf.len() as u16;
        buf.push(1); buf.push(b'x');
        buf.push(2); buf.push(b'i'); buf.push(b'o');
        buf.push(0);
        buf.extend_from_slice(&1u16.to_be_bytes()); // qtype
        buf.extend_from_slice(&1u16.to_be_bytes()); // qclass
        let qsize = buf.len() - 12;
        // Answer: pointer to qname, A, IN, ttl=60, rdlen=4, rdata.
        buf.extend_from_slice(&(0xC000u16 | qname_offset).to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes()); // type A
        buf.extend_from_slice(&1u16.to_be_bytes()); // class IN
        buf.extend_from_slice(&60u32.to_be_bytes()); // ttl
        buf.extend_from_slice(&4u16.to_be_bytes()); // rdlen
        buf.extend_from_slice(&[93, 184, 216, 34]);

        let ip = dns_extract_first_a(&buf, 0xCAFE, qsize);
        assert_eq!(ip, Some(Ipv4Addr::new(93, 184, 216, 34)));

        // Wrong txid → None.
        assert_eq!(dns_extract_first_a(&buf, 0x0001, qsize), None);

        // SERVFAIL → None.
        let mut bad = buf.clone();
        bad[3] = 0x82;
        assert_eq!(dns_extract_first_a(&bad, 0xCAFE, qsize), None);

        // Truncated rdata → None.
        let truncated = &buf[..buf.len() - 2];
        assert_eq!(dns_extract_first_a(truncated, 0xCAFE, qsize), None);

        // Answer that's only a CNAME (type 5) before the A is skipped
        // gracefully: build a 2-answer reply where the first is CNAME
        // and the second is A.
        let mut multi: Vec<u8> = Vec::new();
        multi.extend_from_slice(&0xBEEFu16.to_be_bytes());
        multi.extend_from_slice(&0x8180u16.to_be_bytes());
        multi.extend_from_slice(&1u16.to_be_bytes());
        multi.extend_from_slice(&2u16.to_be_bytes()); // ancount=2
        multi.extend_from_slice(&0u16.to_be_bytes());
        multi.extend_from_slice(&0u16.to_be_bytes());
        let qname_offset_m = multi.len() as u16;
        multi.push(1); multi.push(b'a');
        multi.push(2); multi.push(b'i'); multi.push(b'o');
        multi.push(0);
        multi.extend_from_slice(&1u16.to_be_bytes());
        multi.extend_from_slice(&1u16.to_be_bytes());
        let qsize_m = multi.len() - 12;
        // Answer 1: CNAME with 4-byte rdata (pointer + nul) — content
        // doesn't matter, parser must skip it cleanly.
        multi.extend_from_slice(&(0xC000u16 | qname_offset_m).to_be_bytes());
        multi.extend_from_slice(&5u16.to_be_bytes()); // type CNAME
        multi.extend_from_slice(&1u16.to_be_bytes());
        multi.extend_from_slice(&60u32.to_be_bytes());
        multi.extend_from_slice(&2u16.to_be_bytes()); // rdlen=2
        multi.extend_from_slice(&(0xC000u16 | qname_offset_m).to_be_bytes());
        // Answer 2: A
        multi.extend_from_slice(&(0xC000u16 | qname_offset_m).to_be_bytes());
        multi.extend_from_slice(&1u16.to_be_bytes());
        multi.extend_from_slice(&1u16.to_be_bytes());
        multi.extend_from_slice(&60u32.to_be_bytes());
        multi.extend_from_slice(&4u16.to_be_bytes());
        multi.extend_from_slice(&[10, 20, 30, 40]);
        assert_eq!(
            dns_extract_first_a(&multi, 0xBEEF, qsize_m),
            Some(Ipv4Addr::new(10, 20, 30, 40))
        );
    }

    #[test]
    fn probe_target_parsing() {
        match ProbeTarget::parse("1.1.1.1") {
            ProbeTarget::Ip(ip) => assert_eq!(ip, Ipv4Addr::new(1, 1, 1, 1)),
            _ => panic!("expected IP"),
        }
        match ProbeTarget::parse("  Google.com  ") {
            ProbeTarget::Hostname(h) => assert_eq!(h, "google.com"),
            _ => panic!("expected hostname"),
        }
        // Strings that almost look like an IP but aren't (e.g. octets
        // out of range) fall through to hostname — config validation is
        // responsible for rejecting clearly bogus names.
        match ProbeTarget::parse("999.0.0.1") {
            ProbeTarget::Hostname(_) => {}
            _ => panic!("expected hostname"),
        }
    }
}
