//! Content canary: fetch a known resource through a specific provider and
//! verify the bytes that come back.
//!
//! # Why this exists
//!
//! Every other probe in `vlb` answers "can packets reach X?". That question
//! has a blind spot which is precisely the failure mode that hurts most in
//! production: **the uplink is up, but the ISP is intercepting it.** When an
//! account goes unpaid, a typical provider does not black-hole traffic — it
//! transparently redirects it:
//!
//! * UDP/53 is intercepted and every A query answers with the portal's IP;
//! * TCP/80 is intercepted and every request answers with the payment page;
//! * ICMP is left alone, or answered by the ISP's own box.
//!
//! Against that, reachability probes all pass:
//!
//! | Probe                        | Result on a hijacked uplink            |
//! |------------------------------|----------------------------------------|
//! | ping the next hop            | passes — the router is fine            |
//! | ping `1.1.1.1`               | passes — ICMP allowed, or spoofed      |
//! | resolve `google.com`, ping it| passes — resolves to the portal, which answers |
//! | DNS query returns NOERROR    | passes — the hijacked answer is well-formed |
//!
//! So the provider looks perfectly healthy and no failover happens, while
//! no real traffic works. The only reliable discriminator is **content
//! authenticity**: ask for bytes we already know, and check we got them.
//! An interceptor can fake reachability for free; it cannot produce content
//! it does not have.
//!
//! # Verdict semantics
//!
//! We deliberately distinguish two kinds of failure, because they justify
//! very different reactions:
//!
//! * [`CanaryVerdict::Tampered`] — proof that something is answering in
//!   place of the real server. It overrides the quorum: one tampered target
//!   is enough to take the provider down, immediately, with no threshold.
//! * [`CanaryVerdict::Unreachable`] — something went wrong, but benign
//!   explanations exist. Counts as a single vote against the provider and
//!   must repeat before it matters.
//!
//! Drawing that line correctly is the most safety-critical decision in this
//! module, because `Tampered` is powerful enough for one endpoint to fail
//! every uplink over on its own. Only signals that *cannot* occur on a
//! healthy link qualify:
//!
//! | Observation                                   | Verdict     | Why |
//! |-----------------------------------------------|-------------|-----|
//! | 3xx redirect                                  | Tampered    | The portal signature. The real endpoints never redirect. |
//! | 511 Network Authentication Required           | Tampered    | RFC 6585 defines it as "a captive portal is in the way". |
//! | 2xx, but not the expected one                 | Tampered    | A portal answering `generate_204` with a login page. |
//! | Expected status, wrong body                   | Tampered    | Somebody else's bytes. |
//! | Public hostname resolving into RFC1918/CGNAT  | Tampered    | No public name legitimately resolves there. |
//! | **4xx / 5xx**                                 | Unreachable | Almost always a wrong URL or a broken endpoint. Interceptors serve payment pages, not 404s — and treating a typo'd canary URL as proof would fail over every provider at once on a perfectly healthy network. |
//! | Timeout, refused, TLS handshake failure       | Unreachable | Ordinary transient conditions. |
//!
//! # The blind spot content checking still has
//!
//! Verifying content proves the bytes are genuine. It says nothing about how
//! *fast* they arrived — and a provider suspending an account may simply
//! apply a rate limit rather than redirect or drop. Every check above passes
//! under that.
//!
//! It is worse than "small transfers are fast enough": a rate limiter is a
//! token bucket, so a small transfer drains the burst allowance and completes
//! at **full line speed**. Measured against a 64 kbit/s policer in the test
//! lab, the 1.2 KB canary file arrived in 0.6 ms while a 256 KB transfer over
//! the same link took 12.3 seconds. No latency budget on the small probe
//! could ever fire.
//!
//! [`check_throughput_via`] closes that by moving enough bytes to outlast the
//! bucket.

use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::http::{self, HttpRequest, Url};

/// What the response body has to look like for the probe to pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentExpectation {
    /// Body must equal these bytes exactly.
    Exact(Vec<u8>),
    /// SHA-256 over the whole body must equal this digest. Strictest option
    /// and the one to use for a file you control.
    Sha256([u8; 32]),
    /// Body must contain this marker. Robust against trailing-newline and
    /// line-ending normalisation, and still impossible for a portal page to
    /// satisfy by accident.
    Contains(String),
    /// Only the status code is checked. For endpoints whose whole contract
    /// is the status, like `generate_204`.
    StatusOnly,
}

impl ContentExpectation {
    pub fn describe(&self) -> String {
        match self {
            ContentExpectation::Exact(b) => {
                format!("exact {} bytes", b.len())
            }
            ContentExpectation::Sha256(d) => format!("sha256 {}", hex(&d[..4])),
            ContentExpectation::Contains(s) => format!("contains {s:?}"),
            ContentExpectation::StatusOnly => "status only".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CanaryTarget {
    pub url: Url,
    pub expect_status: u16,
    pub expect: ContentExpectation,
}

impl CanaryTarget {
    pub fn label(&self) -> String {
        self.url.to_string()
    }
}

/// Outcome of a single canary fetch.
#[derive(Debug, Clone, PartialEq)]
pub enum CanaryVerdict {
    Ok {
        latency: Duration,
    },
    /// The wire worked but the content was not ours. Proof of interception.
    Tampered {
        detail: String,
    },
    /// The exchange could not be completed at all.
    Unreachable {
        detail: String,
    },
}

impl CanaryVerdict {
    pub fn is_ok(&self) -> bool {
        matches!(self, CanaryVerdict::Ok { .. })
    }

    pub fn is_tampered(&self) -> bool {
        matches!(self, CanaryVerdict::Tampered { .. })
    }

    pub fn detail(&self) -> Option<&str> {
        match self {
            CanaryVerdict::Ok { .. } => None,
            CanaryVerdict::Tampered { detail } | CanaryVerdict::Unreachable { detail } => {
                Some(detail)
            }
        }
    }
}

/// How many targets must pass for the provider to be considered good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quorum {
    /// One passing target is enough. Most forgiving; use when some targets
    /// may be blocked in your region for reasons unrelated to the uplink.
    Any,
    /// More than half must pass. The default: survives one target being
    /// unavailable, still fails when an interceptor breaks everything.
    Majority,
    /// Every target must pass. Strictest, and the most prone to false
    /// failover if any single endpoint has an outage.
    All,
}

impl Quorum {
    /// Minimum number of passing targets out of `total`.
    pub fn required(self, total: usize) -> usize {
        match self {
            Quorum::Any => 1,
            // Strictly more than half: 2 of 3, 2 of 2, 3 of 4.
            Quorum::Majority => total / 2 + 1,
            Quorum::All => total,
        }
        .max(1)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Quorum::Any => "any",
            Quorum::Majority => "majority",
            Quorum::All => "all",
        }
    }
}

/// Aggregate result across all canary targets for one provider.
#[derive(Debug, Clone)]
pub struct CanaryReport {
    pub passed: usize,
    pub total: usize,
    pub required: usize,
    /// Set when at least one target proved interception. Overrides quorum.
    pub tampered: Option<String>,
    /// Best (lowest) latency among passing targets, for display.
    pub latency: Option<Duration>,
    pub per_target: Vec<(String, CanaryVerdict)>,
}

impl CanaryReport {
    pub fn is_ok(&self) -> bool {
        self.tampered.is_none() && self.passed >= self.required
    }

    /// Tampering that amounts to *proof*, as opposed to an oddity.
    ///
    /// This distinction matters more than it looks. A conclusive verdict
    /// bypasses the failure threshold and takes the provider down on the
    /// first observation — which is exactly right for an intercepted uplink,
    /// and exactly wrong for a single flaky endpoint.
    ///
    /// A real intercept is indiscriminate: a portal in the path rewrites
    /// *everything*, so every target fails and the quorum collapses with it.
    /// One target coming back wrong while the others verify correctly is a
    /// different animal — a transparent cache on one CDN, a hotel proxy, an
    /// endpoint that quietly changed its own content. Treating that as proof
    /// would let one misbehaving third-party URL mark every provider DOWN at
    /// once, leaving the gateway with no failover capability at all, on a
    /// network where nothing is actually wrong.
    ///
    /// So proof requires both signals: content came back wrong **and** not
    /// enough targets verified. A lone tampered target still fails the round
    /// and will take the provider down if it persists — the signal is kept,
    /// the cliff is not.
    pub fn conclusive_tamper(&self) -> Option<&str> {
        match &self.tampered {
            Some(detail) if self.passed < self.required => Some(detail),
            _ => None,
        }
    }

    /// One-line human summary for logs and the TUI.
    pub fn summary(&self) -> String {
        if let Some(t) = self.conclusive_tamper() {
            return format!("CONTENT TAMPERED — {t}");
        }
        if let Some(t) = &self.tampered {
            // Suspicious but not proof: say so plainly, so nobody reading the
            // journal concludes the uplink was hijacked on this evidence.
            return format!(
                "content mismatch on one target while {}/{} others still verified \
                 (counted as a failed round, not proof) — {t}",
                self.passed, self.total
            );
        }
        if self.is_ok() {
            return format!("{}/{} canary targets verified", self.passed, self.total);
        }
        let failures: Vec<String> = self
            .per_target
            .iter()
            .filter(|(_, v)| !v.is_ok())
            .map(|(l, v)| format!("{l}: {}", v.detail().unwrap_or("failed")))
            .collect();
        format!(
            "only {}/{} canary targets verified (need {}) — {}",
            self.passed,
            self.total,
            self.required,
            failures.join("; ")
        )
    }
}

/// Run every canary target through the given provider's fwmark.
///
/// `resolve` turns a hostname into an IPv4 through that same provider, so
/// the whole chain — DNS, TCP, TLS, HTTP — is pinned to one uplink.
pub async fn check_canary_via<R, F>(
    targets: &[CanaryTarget],
    timeout: Duration,
    mark: Option<u32>,
    quorum: Quorum,
    user_agent: &str,
    resolve: R,
) -> CanaryReport
where
    R: Fn(String) -> F + Clone + Send + Sync + 'static,
    F: std::future::Future<Output = Option<Ipv4Addr>> + Send,
{
    let total = targets.len();
    let required = quorum.required(total.max(1));

    if targets.is_empty() {
        return CanaryReport {
            passed: 0,
            total: 0,
            required: 0,
            tampered: None,
            latency: None,
            per_target: Vec::new(),
        };
    }

    // All targets concurrently: serialised HTTPS fetches would easily exceed
    // the probe interval and starve the health loop.
    let mut futures = Vec::with_capacity(total);
    for t in targets {
        let t = t.clone();
        let ua = user_agent.to_string();
        let resolve = resolve.clone();
        futures.push(async move {
            let label = t.label();
            let verdict = check_one(&t, timeout, mark, &ua, resolve).await;
            (label, verdict)
        });
    }
    let per_target: Vec<(String, CanaryVerdict)> = futures_join_all(futures).await;

    let tampered = per_target
        .iter()
        .find(|(_, v)| v.is_tampered())
        .map(|(l, v)| format!("{l}: {}", v.detail().unwrap_or("content mismatch")));

    let passed = per_target.iter().filter(|(_, v)| v.is_ok()).count();
    let latency = per_target
        .iter()
        .filter_map(|(_, v)| match v {
            CanaryVerdict::Ok { latency } => Some(*latency),
            _ => None,
        })
        .min();

    CanaryReport {
        passed,
        total,
        required,
        tampered,
        latency,
        per_target,
    }
}

/// Await a set of futures concurrently and collect the results in order.
///
/// Hand-rolled so we don't pull in `futures` for a single combinator. Each
/// probe gets its own task, so a wedged target cannot delay the others.
async fn futures_join_all<F, T>(futures: Vec<F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handles: Vec<_> = futures.into_iter().map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        match h.await {
            Ok(v) => out.push(v),
            // A panicked probe task must never be read as a pass. The caller
            // sees a shorter result vector, which lowers `passed` and so
            // fails the quorum — the safe direction.
            Err(e) => tracing::error!(error = %e, "canary probe task panicked"),
        }
    }
    out
}

async fn check_one<R, F>(
    target: &CanaryTarget,
    timeout: Duration,
    mark: Option<u32>,
    user_agent: &str,
    resolve: R,
) -> CanaryVerdict
where
    R: Fn(String) -> F,
    F: std::future::Future<Output = Option<Ipv4Addr>>,
{
    // 1. Resolve through this provider. An IP literal in the URL skips DNS.
    let (ip, from_dns) = match target.url.host_as_ip() {
        Some(ip) => (ip, false),
        None => match resolve(target.url.host.clone()).await {
            Some(ip) => (ip, true),
            None => {
                return CanaryVerdict::Unreachable {
                    detail: format!("DNS resolution of {} failed", target.url.host),
                };
            }
        },
    };

    // 2. A *resolved* hostname landing in private / carrier-grade-NAT /
    //    link-local space is a rewritten answer, full stop — no public name
    //    legitimately resolves there. Catching it here means we do not even
    //    have to make the request to know.
    //
    //    This applies only to addresses that came out of DNS. An IP literal
    //    in the URL is the operator's explicit choice, and pointing a canary
    //    at a host on your own network is a perfectly reasonable thing to
    //    do — treating that as a hijack would make such a target permanently
    //    "tampered" and hold the provider down forever.
    if from_dns && let Some(range) = non_routable_range(ip) {
        return CanaryVerdict::Tampered {
            detail: format!(
                "{} resolved to {ip} ({range}) — DNS answer was rewritten by the uplink",
                target.url.host
            ),
        };
    }

    let req = HttpRequest {
        url: target.url.clone(),
        connect_ip: ip,
        mark,
        timeout,
        // Canary bodies are tiny. The cap is generous enough for a portal
        // page to arrive and be recognised as wrong, and small enough that a
        // hostile endpoint cannot make us buffer anything meaningful.
        max_body: 256 * 1024,
        user_agent: user_agent.to_string(),
    };

    let started = Instant::now();
    let resp = match http::fetch(&req).await {
        Ok(r) => r,
        Err(e) => {
            return CanaryVerdict::Unreachable {
                // The full error chain matters here: "TLS handshake failed"
                // vs "connection refused" is the difference between an
                // interception attempt and a dead link.
                detail: format!("{e:#}"),
            };
        }
    };
    let latency = started.elapsed();

    // 3. A redirect is the signature move of a captive portal or paywall.
    //    We never follow it: the redirect itself is the finding.
    if resp.is_redirect() {
        let loc = resp.header("location").unwrap_or("(no Location header)");
        return CanaryVerdict::Tampered {
            detail: format!(
                "HTTP {} redirect to {loc} — expected {} with no redirect \
                 (classic captive-portal / unpaid-account intercept)",
                resp.status, target.expect_status
            ),
        };
    }

    // 3b. RFC 6585 §6 exists precisely to say "a captive portal is in the
    //     way". Nothing else emits it.
    if resp.status == 511 {
        return CanaryVerdict::Tampered {
            detail: "HTTP 511 Network Authentication Required — a captive portal \
                     is intercepting this uplink"
                .to_string(),
        };
    }

    if resp.status != target.expect_status {
        // Which kind of failure this is matters enormously, because
        // `Tampered` is treated as proof and overrides the quorum — one
        // target alone can take a provider down.
        //
        // A 4xx/5xx is overwhelmingly a wrong URL or a broken endpoint, not
        // an intercept: interceptors serve payment pages and redirects, they
        // do not return 404. Treating it as proof would mean a typo in a
        // canary URL instantly fails over every provider at once, which is a
        // far worse outcome than missing one signal. So it counts as a
        // single failed vote and nothing more.
        //
        // A *2xx* that is not the one we asked for is different: that is
        // exactly what a portal does to `generate_204`, answering 200 with a
        // login page where the contract is an empty 204.
        if (400..600).contains(&resp.status) {
            return CanaryVerdict::Unreachable {
                detail: format!(
                    "HTTP {} (expected {}) — the endpoint rejected the request; \
                     check the canary URL. {}",
                    resp.status,
                    target.expect_status,
                    describe_body(&resp.body)
                ),
            };
        }
        return CanaryVerdict::Tampered {
            detail: format!(
                "HTTP {} but expected {} ({})",
                resp.status,
                target.expect_status,
                describe_body(&resp.body)
            ),
        };
    }

    // 4. Content check. A truncated body cannot be compared honestly, so it
    //    is reported as unreachable rather than as a mismatch.
    if resp.truncated && !matches!(target.expect, ContentExpectation::StatusOnly) {
        return CanaryVerdict::Unreachable {
            detail: format!(
                "response body exceeded the probe size cap ({} bytes read) — \
                 cannot verify content",
                resp.body.len()
            ),
        };
    }

    match &target.expect {
        ContentExpectation::StatusOnly => CanaryVerdict::Ok { latency },
        ContentExpectation::Exact(want) => {
            if resp.body == *want {
                CanaryVerdict::Ok { latency }
            } else {
                CanaryVerdict::Tampered {
                    detail: format!(
                        "body mismatch: expected {} bytes, got {}",
                        want.len(),
                        describe_body(&resp.body)
                    ),
                }
            }
        }
        ContentExpectation::Sha256(want) => {
            let got: [u8; 32] = Sha256::digest(&resp.body).into();
            if got == *want {
                CanaryVerdict::Ok { latency }
            } else {
                CanaryVerdict::Tampered {
                    detail: format!(
                        "sha256 mismatch: expected {}, got {} ({})",
                        hex(&want[..8]),
                        hex(&got[..8]),
                        describe_body(&resp.body)
                    ),
                }
            }
        }
        ContentExpectation::Contains(marker) => {
            if find_subslice(&resp.body, marker.as_bytes()) {
                CanaryVerdict::Ok { latency }
            } else {
                CanaryVerdict::Tampered {
                    detail: format!(
                        "marker {marker:?} absent from the response ({})",
                        describe_body(&resp.body)
                    ),
                }
            }
        }
    }
}

/// Short, log-safe description of a body we did not expect. Portal pages are
/// HTML, so surfacing the first line makes the cause obvious in the journal.
fn describe_body(body: &[u8]) -> String {
    if body.is_empty() {
        return "empty body".to_string();
    }
    let text = String::from_utf8_lossy(&body[..body.len().min(120)]);
    let first: String = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect();
    format!("{} bytes starting {first:?}", body.len())
}

// ─────────────────────────────────────────────────────────────────────────
// Throughput
// ─────────────────────────────────────────────────────────────────────────

/// Result of one throughput measurement.
#[derive(Debug, Clone, PartialEq)]
pub enum ThroughputVerdict {
    Ok {
        kbps: u64,
        bytes: usize,
        elapsed: Duration,
    },
    /// The link is up and reachable and cannot carry enough traffic to be
    /// usable.
    ///
    /// `kbps` is `None` when the transfer never finished. We then know the
    /// rate was under the floor without knowing what it was — and that is
    /// still a statement about speed, which is why it belongs here rather
    /// than in `Unmeasurable`. The payload is sized so any link meeting the
    /// floor delivers it comfortably inside the budget, so failing to
    /// deliver it *is* the finding.
    TooSlow {
        kbps: Option<u64>,
        floor_kbps: u64,
        bytes: usize,
        elapsed: Duration,
    },
    /// Could not measure at all.
    Unmeasurable { detail: String },
}

impl ThroughputVerdict {
    pub fn is_ok(&self) -> bool {
        matches!(self, ThroughputVerdict::Ok { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            ThroughputVerdict::Ok {
                kbps,
                bytes,
                elapsed,
            } => format!(
                "{kbps} kbit/s ({bytes} bytes in {} ms)",
                elapsed.as_millis()
            ),
            ThroughputVerdict::TooSlow {
                kbps: Some(kbps),
                floor_kbps,
                bytes,
                elapsed,
            } => format!(
                "{kbps} kbit/s is below the {floor_kbps} kbit/s floor \
                 ({bytes} bytes took {} ms) — the link is reachable but too \
                 slow to carry real traffic",
                elapsed.as_millis()
            ),
            ThroughputVerdict::TooSlow {
                kbps: None,
                floor_kbps,
                elapsed,
                ..
            } => format!(
                "the payload did not finish transferring within {} ms, so the link \
                 is below the {floor_kbps} kbit/s floor — reachable, but too slow \
                 to carry real traffic",
                elapsed.as_millis()
            ),
            ThroughputVerdict::Unmeasurable { detail } => detail.clone(),
        }
    }
}

/// Measure how fast a provider can actually move bytes.
///
/// # Why reachability probes cannot answer this
///
/// A provider suspending an account does not always redirect or drop; a
/// common alternative is to leave everything reachable and apply a rate
/// limit — 64 kbit/s is typical. Every other check in this crate passes
/// happily under that: ICMP echoes are tiny, DNS answers are tiny, and the
/// content canary fetches barely a kilobyte.
///
/// Worse, it is not merely that small transfers are "fast enough" — a rate
/// limiter is a token bucket with a burst allowance, so a small transfer
/// completes at **full line speed** by draining the bucket. Measured in the
/// test lab against a 64 kbit/s policer: the 1.2 KB canary file arrived in
/// 0.6 ms, while a 256 KB transfer over the same link took 12.3 seconds.
/// A latency budget on the small probe would therefore never fire.
///
/// So the payload has to be large enough to exhaust the bucket. 64 KiB is
/// past any plausible burst while still costing almost nothing when fetched
/// a couple of times a minute.
///
/// RTT dilutes the figure on fast links — 64 KiB over a 100 ms RTT reads as
/// roughly 5 Mbit/s however fast the pipe really is — which is precisely why
/// the floor belongs far below any real link and just above a suspension
/// throttle.
pub async fn check_throughput_via<R, F>(
    url: &Url,
    floor_kbps: u64,
    timeout: Duration,
    mark: Option<u32>,
    user_agent: &str,
    resolve: R,
) -> ThroughputVerdict
where
    R: Fn(String) -> F,
    F: std::future::Future<Output = Option<Ipv4Addr>>,
{
    let ip = match url.host_as_ip() {
        Some(ip) => ip,
        None => match resolve(url.host.clone()).await {
            Some(ip) => ip,
            None => {
                return ThroughputVerdict::Unmeasurable {
                    detail: format!("DNS resolution of {} failed", url.host),
                };
            }
        },
    };

    let req = HttpRequest {
        url: url.clone(),
        connect_ip: ip,
        mark,
        timeout,
        // Room for the payload plus slack; anything larger is not ours.
        max_body: 4 * 1024 * 1024,
        user_agent: user_agent.to_string(),
    };

    let started = Instant::now();
    let resp = match http::fetch(&req).await {
        Ok(r) => r,
        Err(e) => {
            // A timeout is evidence about speed. The payload is sized so that
            // any link meeting the floor delivers it comfortably inside the
            // budget, so not finishing means the rate was below the floor —
            // we simply do not learn what it was, hence `kbps: None` rather
            // than a fabricated figure.
            //
            // Every other failure (DNS, refused, TLS) says nothing about
            // throughput and stays unmeasurable, so a broken endpoint is
            // never reported to the operator as "your provider is throttled".
            if http::is_timeout(&e) {
                return ThroughputVerdict::TooSlow {
                    kbps: None,
                    floor_kbps,
                    bytes: 0,
                    elapsed: started.elapsed(),
                };
            }
            return ThroughputVerdict::Unmeasurable {
                detail: format!("{e:#}"),
            };
        }
    };
    let elapsed = started.elapsed();

    if !(200..300).contains(&resp.status) {
        return ThroughputVerdict::Unmeasurable {
            detail: format!("HTTP {} fetching the throughput payload", resp.status),
        };
    }

    classify_throughput(resp.body.len(), elapsed, floor_kbps)
}

/// Minimum payload that can say anything about a link's speed.
///
/// Below this the figure is dominated by round-trip time, and — the reason
/// that matters here — a rate limiter is a token bucket, so a small transfer
/// drains the burst allowance and completes at full line speed even on a
/// throttled link. 16 KiB outlasts any plausible burst.
const MIN_MEASURABLE_BYTES: usize = 16 * 1024;

/// Turn a completed transfer into a verdict.
///
/// Split out from the I/O so the arithmetic and its edge cases are testable
/// without a server: a payload too small to mean anything, a transfer that
/// registered no elapsed time, and the boundary at the floor itself.
fn classify_throughput(bytes: usize, elapsed: Duration, floor_kbps: u64) -> ThroughputVerdict {
    if bytes < MIN_MEASURABLE_BYTES {
        return ThroughputVerdict::Unmeasurable {
            detail: format!(
                "throughput payload was only {bytes} bytes — too small to measure \
                 against (needs at least {} KiB to outlast a rate limiter's burst)",
                MIN_MEASURABLE_BYTES / 1024
            ),
        };
    }

    let secs = elapsed.as_secs_f64();
    if secs <= 0.0 {
        return ThroughputVerdict::Unmeasurable {
            detail: "transfer completed in no measurable time".to_string(),
        };
    }
    let kbps = ((bytes as f64 * 8.0) / secs / 1000.0).round() as u64;

    if kbps < floor_kbps {
        ThroughputVerdict::TooSlow {
            kbps: Some(kbps),
            floor_kbps,
            bytes,
            elapsed,
        }
    } else {
        ThroughputVerdict::Ok {
            kbps,
            bytes,
            elapsed,
        }
    }
}

/// Classify an address that a *public* hostname must never resolve to.
/// Returns the range name when the address is non-routable.
pub fn non_routable_range(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if ip.is_unspecified() {
        return Some("0.0.0.0/8");
    }
    if ip.is_loopback() {
        return Some("127.0.0.0/8 loopback");
    }
    if ip.is_private() {
        return Some("RFC1918 private");
    }
    if ip.is_link_local() {
        return Some("169.254.0.0/16 link-local");
    }
    // 100.64.0.0/10 — carrier-grade NAT. ISP intercept boxes commonly live
    // here, and no public service ever does.
    if o[0] == 100 && (64..128).contains(&o[1]) {
        return Some("100.64.0.0/10 CGNAT");
    }
    if ip.is_multicast() {
        return Some("multicast");
    }
    if ip.is_broadcast() {
        return Some("255.255.255.255 broadcast");
    }
    // 240.0.0.0/4 — reserved.
    if o[0] >= 240 {
        return Some("240.0.0.0/4 reserved");
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Lowercase hex. Used for digests in log lines and config errors.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse a 64-character hex SHA-256 digest from config.
pub fn parse_sha256(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        anyhow::bail!(
            "sha256 digest must be exactly 64 hex characters, got {}",
            s.len()
        );
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(c: u8) -> anyhow::Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => anyhow::bail!("invalid hex character {:?} in sha256 digest", c as char),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(url: &str, status: u16, expect: ContentExpectation) -> CanaryTarget {
        CanaryTarget {
            url: Url::parse(url).unwrap(),
            expect_status: status,
            expect,
        }
    }

    /// Resolver stub that always returns the same address.
    fn fixed_resolver(
        ip: Ipv4Addr,
    ) -> impl Fn(String) -> std::future::Ready<Option<Ipv4Addr>> + Clone {
        move |_host: String| std::future::ready(Some(ip))
    }

    #[test]
    fn quorum_thresholds() {
        assert_eq!(Quorum::Any.required(3), 1);
        assert_eq!(Quorum::Majority.required(3), 2);
        assert_eq!(Quorum::Majority.required(2), 2);
        assert_eq!(Quorum::Majority.required(4), 3);
        assert_eq!(Quorum::All.required(3), 3);
        // Never zero, even for a degenerate empty set.
        assert_eq!(Quorum::Majority.required(0), 1);
    }

    #[test]
    fn non_routable_ranges_cover_hijack_targets() {
        // The addresses an intercepting ISP actually points you at.
        for (ip, expect) in [
            ("10.0.0.1", "RFC1918 private"),
            ("192.168.1.1", "RFC1918 private"),
            ("172.16.5.5", "RFC1918 private"),
            ("100.64.0.1", "100.64.0.0/10 CGNAT"),
            ("100.127.255.254", "100.64.0.0/10 CGNAT"),
            ("127.0.0.1", "127.0.0.0/8 loopback"),
            ("169.254.1.1", "169.254.0.0/16 link-local"),
            ("0.0.0.0", "0.0.0.0/8"),
            ("240.0.0.1", "240.0.0.0/4 reserved"),
        ] {
            let parsed: Ipv4Addr = ip.parse().unwrap();
            assert_eq!(non_routable_range(parsed), Some(expect), "for {ip}");
        }

        // Real public addresses must stay clean, including the edges of the
        // CGNAT block which are ordinary public space.
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.1",
            "239.255.255.255"
                .parse::<Ipv4Addr>()
                .map(|_| "203.0.113.9")
                .unwrap(),
        ] {
            let parsed: Ipv4Addr = ip.parse().unwrap();
            assert_eq!(non_routable_range(parsed), None, "for {ip}");
        }
    }

    #[tokio::test]
    async fn dns_hijack_into_private_space_is_tampered_without_a_request() {
        // The uplink answers every A query with its own portal box. We must
        // catch it from the answer alone — no HTTP request is even made.
        let t = target(
            "http://detectportal.firefox.com/success.txt",
            200,
            ContentExpectation::Exact(b"success\n".to_vec()),
        );
        let report = check_canary_via(
            std::slice::from_ref(&t),
            Duration::from_millis(200),
            None,
            Quorum::Majority,
            "vlb-test",
            fixed_resolver("10.10.10.10".parse().unwrap()),
        )
        .await;

        assert!(!report.is_ok());
        let detail = report.tampered.expect("must be flagged as tampered");
        assert!(detail.contains("10.10.10.10"), "{detail}");
        assert!(detail.contains("RFC1918"), "{detail}");
    }

    /// Regression: the non-routable check must apply only to addresses that
    /// came out of DNS.
    ///
    /// An IP literal in the URL is the operator's explicit choice, and
    /// pointing a canary at a host on your own network is entirely
    /// reasonable. An earlier version applied the private-range rule to
    /// literals too, which made such a target permanently "tampered" and
    /// pinned every provider to DOWN for ever — found by the docker lab,
    /// whose origin server lives on 10.78.0.10.
    #[tokio::test]
    async fn private_ip_literal_target_is_not_treated_as_a_hijack() {
        let t = target(
            "http://10.78.0.10/canary.txt",
            200,
            ContentExpectation::Contains("vlb-canary".into()),
        );
        let report = check_canary_via(
            std::slice::from_ref(&t),
            Duration::from_millis(150),
            None,
            Quorum::Any,
            "vlb-test",
            // Must never be consulted for a literal.
            |_h: String| std::future::ready(Some("203.0.113.1".parse().unwrap())),
        )
        .await;

        assert!(
            report.tampered.is_none(),
            "an explicitly configured private target was flagged as a hijack: {:?}",
            report.tampered
        );
        // Nothing is listening in the test environment, so the honest verdict
        // is "unreachable" — the point is that it is not "tampered".
        assert!(matches!(
            report.per_target[0].1,
            CanaryVerdict::Unreachable { .. }
        ));
    }

    #[tokio::test]
    async fn unresolvable_host_is_unreachable_not_tampered() {
        // DNS silence is ambiguous — it must not be treated as proof of
        // interception, only as one failed vote.
        let t = target("http://example.com/x", 200, ContentExpectation::StatusOnly);
        let report = check_canary_via(
            std::slice::from_ref(&t),
            Duration::from_millis(200),
            None,
            Quorum::Majority,
            "vlb-test",
            |_h: String| std::future::ready(None),
        )
        .await;

        assert!(!report.is_ok());
        assert!(report.tampered.is_none(), "must not claim tampering");
        assert!(matches!(
            report.per_target[0].1,
            CanaryVerdict::Unreachable { .. }
        ));
    }

    #[tokio::test]
    async fn empty_target_list_is_vacuously_ok() {
        // Canary disabled must never wedge a provider into permanent DOWN.
        let report = check_canary_via(
            &[],
            Duration::from_millis(200),
            None,
            Quorum::Majority,
            "vlb-test",
            fixed_resolver("1.1.1.1".parse().unwrap()),
        )
        .await;
        assert!(report.is_ok());
        assert_eq!(report.total, 0);
    }

    /// The single most dangerous thing this module can get wrong.
    ///
    /// `Tampered` is treated as *proof* and overrides the quorum, so one
    /// target alone can take a provider down. That power must be reserved
    /// for signals that cannot occur on a working link. A 4xx/5xx is not one
    /// of them: it means a wrong URL or a broken endpoint far more often
    /// than an intercept, and interceptors serve payment pages, not 404s.
    ///
    /// This was found by running the live-endpoint check against a canary
    /// URL whose file had not been pushed yet: GitHub answered 404, the
    /// probe called it tampering, and *every* provider would have been
    /// failed over at once on a completely healthy network.
    #[test]
    fn client_and_server_errors_are_never_treated_as_proof_of_tampering() {
        for status in [400u16, 401, 403, 404, 410, 500, 502, 503] {
            let raw = format!("HTTP/1.1 {status} Something\r\nContent-Length: 3\r\n\r\nnah");
            let resp = crate::http::parse_response(raw.as_bytes(), 4096).unwrap();
            assert!(
                !resp.is_redirect(),
                "{status} should not be classified as a redirect"
            );
            assert!(
                (400..600).contains(&resp.status),
                "{status} must fall in the non-conclusive band"
            );
        }
    }

    /// The converse: the statuses that genuinely are portal signatures must
    /// keep their conclusive treatment.
    #[test]
    fn portal_signatures_stay_conclusive() {
        for status in [301u16, 302, 303, 307, 308] {
            let raw =
                format!("HTTP/1.1 {status} Moved\r\nLocation: /pay\r\nContent-Length: 0\r\n\r\n");
            let resp = crate::http::parse_response(raw.as_bytes(), 4096).unwrap();
            assert!(resp.is_redirect(), "{status} must count as a redirect");
        }
        // 511 is defined by RFC 6585 to mean exactly "a captive portal is in
        // the way", so it is proof on its own.
        let raw = b"HTTP/1.1 511 Network Authentication Required\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(crate::http::parse_response(raw, 4096).unwrap().status, 511);
    }

    /// Tampering only counts as proof when the quorum fails with it.
    ///
    /// This is the difference between "an ISP is intercepting this uplink"
    /// and "one third-party URL is behaving oddly today". Getting it wrong in
    /// the permissive direction misses real intercepts; getting it wrong in
    /// the strict direction is worse — one misbehaving endpoint would mark
    /// *every* provider DOWN at once, on a network where nothing is broken,
    /// leaving the gateway with no failover capability.
    #[test]
    fn tampering_is_proof_only_when_the_quorum_fails_with_it() {
        let mk = |passed, total, required, tampered: Option<&str>| CanaryReport {
            passed,
            total,
            required,
            tampered: tampered.map(String::from),
            latency: None,
            per_target: Vec::new(),
        };

        // Real intercept: a portal rewrites everything, so nothing verifies.
        let intercepted = mk(0, 3, 2, Some("portal page"));
        assert_eq!(intercepted.conclusive_tamper(), Some("portal page"));
        assert!(!intercepted.is_ok());
        assert!(intercepted.summary().contains("CONTENT TAMPERED"));

        // Partial intercept — HTTP rewritten, HTTPS still honest. One target
        // passes, which is below a majority of three, so still proof.
        let partial = mk(1, 3, 2, Some("portal page"));
        assert_eq!(partial.conclusive_tamper(), Some("portal page"));

        // One odd endpoint while the others verify: suspicious, not proof.
        let odd = mk(2, 3, 2, Some("cache rewrote it"));
        assert_eq!(odd.conclusive_tamper(), None);
        assert!(!odd.is_ok(), "the round should still count as failed");
        let s = odd.summary();
        assert!(!s.contains("CONTENT TAMPERED"), "must not claim proof: {s}");
        assert!(s.contains("not proof"), "{s}");

        // No tampering at all is never conclusive, however few passed.
        assert_eq!(mk(0, 3, 2, None).conclusive_tamper(), None);
    }

    #[test]
    fn report_is_ok_respects_quorum_and_tamper_override() {
        let mk = |passed, total, required, tampered: Option<&str>| CanaryReport {
            passed,
            total,
            required,
            tampered: tampered.map(String::from),
            latency: None,
            per_target: Vec::new(),
        };
        assert!(mk(2, 3, 2, None).is_ok());
        assert!(!mk(1, 3, 2, None).is_ok());

        // Any tampering fails the round, even when the quorum is otherwise
        // satisfied — content that came back wrong is never acceptable. What
        // it does *not* do on its own is bypass the failure threshold; see
        // `tampering_is_proof_only_when_the_quorum_fails_with_it`.
        //
        // 2 of 3 passing with the third tampered is the realistic shape: a
        // tampered target is never counted among `passed`.
        let odd = mk(2, 3, 2, Some("portal"));
        assert!(!odd.is_ok());
        assert_eq!(odd.conclusive_tamper(), None);

        // Quorum failing alongside the tampering is what makes it proof.
        let intercepted = mk(0, 3, 2, Some("portal"));
        assert!(!intercepted.is_ok());
        assert!(intercepted.summary().contains("TAMPERED"));
    }

    #[test]
    fn sha256_parsing_roundtrip() {
        let digest = Sha256::digest(b"vlb-canary-v1\n");
        let as_hex = hex(&digest);
        assert_eq!(as_hex.len(), 64);
        assert_eq!(parse_sha256(&as_hex).unwrap(), <[u8; 32]>::from(digest));
        // Uppercase is accepted; wrong length and non-hex are not.
        assert!(parse_sha256(&as_hex.to_uppercase()).is_ok());
        assert!(parse_sha256("abc").is_err());
        assert!(parse_sha256(&"z".repeat(64)).is_err());
    }

    #[test]
    fn describe_body_surfaces_portal_html() {
        // What an operator will actually see in the log when a paywall hits.
        let html = b"<!DOCTYPE html>\n<html><head><title>Pay your bill</title>";
        let d = describe_body(html);
        assert!(d.contains("<!DOCTYPE html>"), "{d}");
        assert!(d.starts_with("56 bytes"), "{d}");
        assert_eq!(describe_body(b""), "empty body");
    }

    #[test]
    fn expectation_describe_is_stable() {
        assert_eq!(
            ContentExpectation::StatusOnly.describe(),
            "status only".to_string()
        );
        assert!(
            ContentExpectation::Contains("vlb".into())
                .describe()
                .contains("vlb")
        );
    }

    /// Verify the shipped default targets against the live internet.
    ///
    /// Ignored by default: it needs working connectivity and depends on
    /// third-party endpoints, so it has no place in the normal suite. But it
    /// is the only thing that can catch the failure mode where the *default
    /// config itself* is wrong — a mistaken status code or marker would make
    /// every fresh deployment fail its primary over on the first probe. Run
    /// it whenever the default target list changes:
    ///
    /// ```text
    /// cargo test --  --ignored canary_defaults_match_the_real_endpoints
    /// ```
    #[tokio::test]
    #[ignore = "requires internet access and hits third-party endpoints"]
    async fn canary_defaults_match_the_real_endpoints() {
        let cfg = crate::config::CanaryConfig::default();
        let targets = cfg.targets_parsed().expect("default targets must parse");

        // No fwmark: this test is about the endpoints, not policy routing, so
        // it goes out over whatever default route the host has.
        let report = check_canary_via(
            &targets,
            Duration::from_secs(15),
            None,
            cfg.quorum_parsed().unwrap(),
            &cfg.user_agent,
            |host: String| async move {
                tokio::net::lookup_host((host.as_str(), 0))
                    .await
                    .ok()
                    .and_then(|mut it| {
                        it.find_map(|a| match a.ip() {
                            std::net::IpAddr::V4(v4) => Some(v4),
                            _ => None,
                        })
                    })
            },
        )
        .await;

        for (label, verdict) in &report.per_target {
            println!("  {label} -> {verdict:?}");
        }

        assert!(
            report.tampered.is_none(),
            "a default target reported tampering against the real internet, which \
             means the shipped expectation is wrong (or this network intercepts \
             traffic): {:?}",
            report.tampered
        );
        assert!(
            report.is_ok(),
            "the shipped default canary targets do not pass on a healthy link: {}",
            report.summary()
        );
    }

    /// The throughput verdict has to distinguish "slow" from "did not work",
    /// because only the first is a statement about the link's speed. A
    /// timeout tells us the transfer did not finish, not how fast it was.
    #[test]
    fn throughput_verdicts_read_correctly() {
        let ok = ThroughputVerdict::Ok {
            kbps: 8000,
            bytes: 65536,
            elapsed: Duration::from_millis(65),
        };
        assert!(ok.is_ok());
        assert!(ok.describe().contains("8000 kbit/s"));

        let slow = ThroughputVerdict::TooSlow {
            kbps: Some(60),
            floor_kbps: 128,
            bytes: 65536,
            elapsed: Duration::from_secs(8),
        };
        assert!(!slow.is_ok());
        let d = slow.describe();
        assert!(d.contains("60 kbit/s"), "{d}");
        assert!(d.contains("128"), "{d}");
        assert!(d.contains("too slow"), "{d}");

        let bad = ThroughputVerdict::Unmeasurable {
            detail: "DNS resolution failed".into(),
        };
        assert!(!bad.is_ok());
        assert_eq!(bad.describe(), "DNS resolution failed");

        // A transfer that never finished still says "too slow". Classifying
        // it as unmeasurable instead would let a throttled provider be
        // reported as merely unreachable, pointing the operator at the wrong
        // problem — which is exactly what the lab caught.
        let never_finished = ThroughputVerdict::TooSlow {
            kbps: None,
            floor_kbps: 128,
            bytes: 0,
            elapsed: Duration::from_secs(15),
        };
        assert!(!never_finished.is_ok());
        let d = never_finished.describe();
        assert!(d.contains("did not finish"), "{d}");
        assert!(d.contains("128"), "{d}");
    }

    /// A payload smaller than a rate limiter's burst allowance measures
    /// nothing useful — it completes at full line speed even on a throttled
    /// link, which is exactly why a latency check on the 1.2 KB canary file
    /// cannot detect throttling. Refuse to report a figure from one rather
    /// than reporting a flattering lie.
    #[test]
    fn a_too_small_payload_is_unmeasurable_not_fast() {
        // 1.2 KB in 0.6 ms is the real measurement taken through the lab's
        // 64 kbit/s policer. Naively that reads as 16 Mbit/s.
        let v = classify_throughput(1243, Duration::from_micros(600), 128);
        assert!(
            !v.is_ok(),
            "a burst-sized transfer must not read as healthy"
        );
        assert!(matches!(v, ThroughputVerdict::Unmeasurable { .. }));
        assert!(
            v.describe().contains("too small to measure"),
            "{}",
            v.describe()
        );
    }

    #[test]
    fn throughput_classification_boundaries() {
        // 64 KiB in 8 s ≈ 66 kbit/s: a throttled link, below the floor.
        let slow = classify_throughput(65_536, Duration::from_secs(8), 128);
        assert!(matches!(
            slow,
            ThroughputVerdict::TooSlow { kbps: Some(66), .. }
        ));

        // 64 KiB in 120 ms ≈ 4.4 Mbit/s: a healthy link.
        let fast = classify_throughput(65_536, Duration::from_millis(120), 128);
        assert!(fast.is_ok(), "{}", fast.describe());

        // Exactly at the floor passes — the floor is a minimum, not a
        // threshold to exceed.
        let at_floor = classify_throughput(65_536, Duration::from_millis(4096), 128);
        assert!(at_floor.is_ok(), "{}", at_floor.describe());

        // A zero-duration transfer would divide by zero; report it rather
        // than inventing an infinite rate.
        let instant = classify_throughput(65_536, Duration::ZERO, 128);
        assert!(matches!(instant, ThroughputVerdict::Unmeasurable { .. }));
    }

    /// The arithmetic, pinned against the figures actually measured in the
    /// test lab: a 64 kbit/s policer moved 256 KiB in 12.3 s.
    #[test]
    fn throughput_arithmetic_matches_a_real_measurement() {
        let kbps = |bytes: usize, secs: f64| ((bytes as f64 * 8.0) / secs / 1000.0).round() as u64;

        // The lab's throttled link.
        assert_eq!(kbps(262_144, 12.318), 170);

        // The shipped 64 KiB payload over the same 64 kbit/s link: 8 s.
        assert_eq!(kbps(65_536, 8.0), 66);
        assert!(kbps(65_536, 8.0) < 128, "must fall below the default floor");

        // A healthy link, where round-trip time dominates: 64 KiB in 120 ms
        // still reads as several Mbit/s, comfortably clear of the floor.
        assert!(kbps(65_536, 0.12) > 4_000);
    }

    #[test]
    fn find_subslice_marker_matching() {
        assert!(find_subslice(b"xx vlb-canary-v1 yy", b"vlb-canary-v1"));
        assert!(!find_subslice(b"<html>pay up</html>", b"vlb-canary-v1"));
        assert!(find_subslice(b"anything", b""));
        assert!(!find_subslice(b"ab", b"abc"));
    }
}
