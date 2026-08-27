use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::canary::{CanaryTarget, Quorum, check_canary_via};
use crate::config::{Config, Provider};
use crate::control;
use crate::health::{
    ProbeTarget, check_dns_integrity_via, check_dns_via, check_gateway, check_internet_via,
};
use crate::router::Router;
use crate::selection::{Decision, FlapTracker, ProviderView, SelectionInput, decide};
use crate::stats::{FailoverRecord, HealthRecord, Stats, SystemPoint, TrafficPoint};
use crate::sysmon::SysMonitor;
use crate::traffic;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Up,
    Down,
    Unknown,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            State::Up => "up",
            State::Down => "down",
            State::Unknown => "unknown",
        }
    }

    pub fn as_label(self) -> &'static str {
        self.as_str()
    }

    fn colored(self) -> String {
        match self {
            State::Up => format!(
                "{} {}",
                "●".bright_green().bold(),
                "UP".bright_green().bold()
            ),
            State::Down => format!("{} {}", "●".bright_red().bold(), "DOWN".bright_red().bold()),
            State::Unknown => format!(
                "{} {}",
                "●".bright_yellow().bold(),
                "UNKNOWN".bright_yellow().bold()
            ),
        }
    }
}

/// Which layer of checking caused a provider to be considered unhealthy.
/// Surfaced in logs, the control snapshot and the TUI, because "down" alone
/// does not tell an operator whether to call the ISP or check a cable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureLayer {
    /// Next-hop unreachable: dead cable, dead ISP router, power loss.
    Gateway,
    /// Gateway answers but the wider internet does not.
    Internet,
    /// ICMP works, UDP/53 does not.
    Dns,
    /// The resolver answered — with a fabricated address.
    DnsHijack,
    /// Content came back wrong. Proof of interception.
    ContentTampered,
    /// Canary endpoints could not be reached often enough.
    ContentUnreachable,
}

impl FailureLayer {
    pub fn as_str(self) -> &'static str {
        match self {
            FailureLayer::Gateway => "gateway",
            FailureLayer::Internet => "internet",
            FailureLayer::Dns => "dns",
            FailureLayer::DnsHijack => "dns-hijack",
            FailureLayer::ContentTampered => "content-tampered",
            FailureLayer::ContentUnreachable => "content-unreachable",
        }
    }

    /// Whether this is *proof* of a broken uplink rather than a symptom.
    ///
    /// Fabricated DNS answers and wrong content cannot happen on a working
    /// link — no amount of packet loss makes a server return someone else's
    /// bytes. So these bypass the consecutive-failure threshold entirely and
    /// take the provider down on first observation, which is what makes
    /// detection fast for the case this whole feature exists for.
    pub fn is_conclusive(self) -> bool {
        matches!(
            self,
            FailureLayer::DnsHijack | FailureLayer::ContentTampered
        )
    }
}

#[derive(Debug)]
struct ProviderState {
    cfg: Provider,
    state: State,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_latency_ms: Option<f64>,
    last_check: Option<DateTime<Utc>>,
    /// When this provider last transitioned into `Up`. Drives the failback
    /// stability window; reset to `None` on every drop out of `Up`.
    up_since: Option<DateTime<Utc>>,
    /// Which layer failed, and the human-readable detail behind it.
    failure_layer: Option<FailureLayer>,
    failure_detail: Option<String>,
    /// Consecutive failing canary rounds. Tracked separately from the ICMP
    /// counters because the canary runs on its own, slower cadence.
    canary_failures: u32,
    last_canary_at: Option<DateTime<Utc>>,
    last_canary_summary: Option<String>,
    canary_ok: bool,
    /// The canary's own "this content was tampered with" verdict, kept
    /// separately from `failure_layer`.
    ///
    /// `failure_layer` records whichever layer failed *most recently*, so a
    /// gateway blip after a proven intercept would overwrite it and the next
    /// tick would then mislabel the same intercept as a mere unreachable
    /// endpoint. The canary owns this field exclusively, so its verdict
    /// survives until the canary itself clears it.
    canary_tampered: Option<String>,
}

pub struct Balancer {
    cfg: Config,
    /// Pre-parsed probe targets (IP literals vs hostnames). Computed
    /// once at construction so the hot health loop doesn't re-parse on
    /// every probe interval.
    probe_targets: Vec<ProbeTarget>,
    /// Pre-parsed canary endpoints and the quorum rule over them.
    canary_targets: Vec<CanaryTarget>,
    canary_quorum: Quorum,
    router: Router,
    stats: Arc<Stats>,
    providers: RwLock<HashMap<String, ProviderState>>,
    active: RwLock<Option<String>>,
    /// Operator pin: when set, the balancer tries to keep this provider
    /// active regardless of priority. It still respects health — a forced
    /// provider that's DOWN falls back to the best available until it
    /// recovers.
    force_override: RwLock<Option<String>>,
    /// Recent switch history, used to stretch the failback window when a
    /// link keeps bouncing.
    flap: StdMutex<FlapTracker>,
    handles: StdMutex<Vec<JoinHandle<()>>>,
}

/// Read-only snapshot of the balancer state, serialized over the control
/// protocol and consumed by the TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlSnapshot {
    pub active: Option<String>,
    pub forced: Option<String>,
    pub providers: Vec<ProviderSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSnapshot {
    pub name: String,
    pub gateway: String,
    pub interface: String,
    pub priority: u32,
    pub role: String,
    pub state: State,
    pub last_latency_ms: Option<f64>,
    pub last_check: Option<DateTime<Utc>>,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    /// Older clients simply omit these; `#[serde(default)]` keeps a new TUI
    /// talking to an old daemon (and the reverse) from failing to parse.
    #[serde(default)]
    pub up_since: Option<DateTime<Utc>>,
    #[serde(default)]
    pub failure_layer: Option<FailureLayer>,
    #[serde(default)]
    pub failure_detail: Option<String>,
    #[serde(default)]
    pub canary_ok: bool,
    #[serde(default)]
    pub last_canary_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_canary_summary: Option<String>,
}

impl Balancer {
    pub async fn new(cfg: Config, dry_run: bool, installed_bootstrap: bool) -> Result<Arc<Self>> {
        let stats = Arc::new(Stats::open(&cfg.database.path, &cfg.providers)?);
        let router = Router::new(dry_run, installed_bootstrap);

        let probe_targets: Vec<ProbeTarget> = cfg
            .health
            .probe_targets
            .iter()
            .map(|s| ProbeTarget::parse(s))
            .collect();

        // Parsed once here rather than per probe. `validate()` already
        // proved these are well-formed, so a failure now is a programming
        // error, not operator input — but we still surface it instead of
        // unwrapping.
        let (canary_targets, canary_quorum) = if cfg.canary.enabled {
            (cfg.canary.targets_parsed()?, cfg.canary.quorum_parsed()?)
        } else {
            warn!(
                "canary disabled — vlb cannot detect an uplink that is reachable but \
                 intercepted (unpaid account, captive portal). Reachability probes \
                 alone will report such a provider as healthy."
            );
            (Vec::new(), Quorum::Any)
        };

        let mut providers = HashMap::with_capacity(cfg.providers.len());
        for p in &cfg.providers {
            providers.insert(
                p.name.clone(),
                ProviderState {
                    cfg: p.clone(),
                    state: State::Unknown,
                    consecutive_failures: 0,
                    consecutive_successes: 0,
                    last_latency_ms: None,
                    last_check: None,
                    up_since: None,
                    failure_layer: None,
                    failure_detail: None,
                    canary_failures: 0,
                    last_canary_at: None,
                    last_canary_summary: None,
                    canary_tampered: None,
                    // Optimistic until the first round completes, so a
                    // provider is not held DOWN for the first canary
                    // interval purely because we have not looked yet.
                    canary_ok: true,
                },
            );
        }

        info!(
            providers = cfg.providers.len(),
            canary_targets = canary_targets.len(),
            canary_quorum = canary_quorum.as_str(),
            db = %cfg.database.path.display(),
            "balancer initialized"
        );

        Ok(Arc::new(Self {
            cfg,
            probe_targets,
            canary_targets,
            canary_quorum,
            router,
            stats,
            providers: RwLock::new(providers),
            active: RwLock::new(None),
            force_override: RwLock::new(None),
            flap: StdMutex::new(FlapTracker::new()),
            handles: StdMutex::new(Vec::new()),
        }))
    }

    pub fn spawn_tasks(self: &Arc<Self>, shutdown: watch::Receiver<bool>) {
        let provider_names: Vec<String> =
            self.cfg.providers.iter().map(|p| p.name.clone()).collect();
        for name in provider_names {
            let me = Arc::clone(self);
            let rx = shutdown.clone();
            let handle = tokio::spawn(async move { me.health_loop(name, rx).await });
            self.handles.lock().unwrap().push(handle);
        }

        let me = Arc::clone(self);
        let rx = shutdown.clone();
        let handle = tokio::spawn(async move { me.status_loop(rx).await });
        self.handles.lock().unwrap().push(handle);

        if self.cfg.traffic.enabled {
            let me = Arc::clone(self);
            let rx = shutdown.clone();
            let handle = tokio::spawn(async move { me.traffic_loop(rx).await });
            self.handles.lock().unwrap().push(handle);
        }

        if self.cfg.system.enabled {
            let me = Arc::clone(self);
            let rx = shutdown.clone();
            let handle = tokio::spawn(async move { me.system_loop(rx).await });
            self.handles.lock().unwrap().push(handle);
        }

        if self.cfg.failover.route_watchdog_secs > 0 {
            let me = Arc::clone(self);
            let rx = shutdown.clone();
            let handle = tokio::spawn(async move { me.route_watchdog(rx).await });
            self.handles.lock().unwrap().push(handle);
        }

        if self.cfg.health.retention_hours > 0 {
            let me = Arc::clone(self);
            let rx = shutdown.clone();
            let handle = tokio::spawn(async move { me.retention_loop(rx).await });
            self.handles.lock().unwrap().push(handle);
        }

        let listen = self.cfg.control.listen.clone();
        let me = Arc::clone(self);
        let rx = shutdown.clone();
        let handle = tokio::spawn(async move { control::serve(listen, me, rx).await });
        self.handles.lock().unwrap().push(handle);
    }

    async fn health_loop(self: Arc<Self>, name: String, mut shutdown: watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.cfg.health.interval_secs);
        let timeout = Duration::from_millis(self.cfg.health.timeout_ms);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        // Snapshot config-only fields once — they don't change at runtime
        // and we don't want to take the lock on every probe tick.
        let (provider_cfg, mark) = {
            let ps = self.providers.read().await;
            let Some(entry) = ps.get(&name) else { return };
            (entry.cfg.clone(), self.cfg.mark_for(&entry.cfg))
        };

        // The canary runs on its own, slower schedule inside this same loop
        // rather than in a task of its own: that keeps a single writer per
        // provider, so probe results and canary results can never interleave
        // into an inconsistent state.
        let canary_interval = Duration::from_secs(self.cfg.canary.interval_secs.max(1));
        let canary_timeout = Duration::from_millis(self.cfg.canary.timeout_ms.max(200));
        let mut last_canary: Option<std::time::Instant> = None;

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::debug!(provider = %name, "health loop stopping");
                        return;
                    }
                }
            }

            // 1. Next-hop check. Catches dead ISP router / dead cable
            //    /power outage upstream of us. No fwmark needed: the
            //    gateway is on the LAN, main table reaches it directly.
            let gw_probe = check_gateway(provider_cfg.gateway, timeout).await;
            let _ = self.stats.record_health(&HealthRecord {
                provider: name.clone(),
                timestamp: Utc::now(),
                success: gw_probe.is_success(),
                latency_ms: gw_probe.latency_ms(),
                kind: "gateway",
            });

            // 2. Internet check via this provider's fwmark, no matter
            //    who owns the default route right now. Skipped when the
            //    gateway is already down — there's nothing further to
            //    learn.
            let net_probe_opt = if gw_probe.is_success() {
                let probe = check_internet_via(
                    &self.probe_targets,
                    &self.cfg.health.dns_resolvers,
                    timeout,
                    mark,
                )
                .await;
                let _ = self.stats.record_health(&HealthRecord {
                    provider: name.clone(),
                    timestamp: Utc::now(),
                    success: probe.is_success(),
                    latency_ms: probe.latency_ms(),
                    kind: "internet",
                });
                Some(probe)
            } else {
                None
            };

            // 3. DNS check (ICMP works but UDP/53 is dropped — unpaid
            //    accounts, captive portals). Skipped if the link is
            //    already known to be broken at a lower layer.
            let dns_probe_opt = if self.cfg.health.dns_check_enabled
                && gw_probe.is_success()
                && net_probe_opt
                    .as_ref()
                    .map(|p| p.is_success())
                    .unwrap_or(false)
            {
                let probe = check_dns_via(
                    &self.cfg.health.dns_resolvers,
                    &self.cfg.health.dns_check_name,
                    timeout,
                    mark,
                )
                .await;
                let _ = self.stats.record_health(&HealthRecord {
                    provider: name.clone(),
                    timestamp: Utc::now(),
                    success: probe.is_success(),
                    latency_ms: probe.latency_ms(),
                    kind: "dns",
                });
                Some(probe)
            } else {
                None
            };

            // 4. DNS integrity. The resolver answered — but is it telling
            //    the truth? A random name under `.invalid` must come back
            //    NXDOMAIN; an address means a middlebox is answering for it.
            //    Only runs when DNS itself worked, since a dead resolver has
            //    already failed at step 3.
            let dns_integrity_bad = if self.cfg.health.dns_integrity_check
                && dns_probe_opt
                    .as_ref()
                    .map(|p| p.is_success())
                    .unwrap_or(false)
            {
                let verdict =
                    check_dns_integrity_via(&self.cfg.health.dns_resolvers, timeout, mark).await;
                let _ = self.stats.record_health(&HealthRecord {
                    provider: name.clone(),
                    timestamp: Utc::now(),
                    success: !verdict.is_hijacked(),
                    latency_ms: None,
                    kind: "dns_integrity",
                });
                match verdict {
                    crate::health::DnsIntegrity::Hijacked { detail } => Some(detail),
                    _ => None,
                }
            } else {
                None
            };

            // 5. Content canary, on its own slower cadence. This is the
            //    layer that sees an uplink which answers everything above
            //    perfectly while serving somebody else's bytes.
            //    Skipped when the gateway is already down, for the same
            //    reason the layers above are: there is nothing further to
            //    learn from a link whose next hop is gone, and a canary round
            //    against a dead uplink burns a full timeout on every tick,
            //    stretching this provider's loop well past its interval.
            let canary_due = self.cfg.canary.enabled
                && !self.canary_targets.is_empty()
                && gw_probe.is_success()
                && last_canary
                    .map(|t: std::time::Instant| t.elapsed() >= canary_interval)
                    .unwrap_or(true);
            if canary_due {
                last_canary = Some(std::time::Instant::now());
                self.run_canary(&name, mark, canary_timeout).await;
            }

            let (canary_ok, canary_tamper, canary_summary) = {
                let ps = self.providers.read().await;
                match ps.get(&name) {
                    Some(e) => (
                        e.canary_ok,
                        e.canary_tampered.clone(),
                        e.last_canary_summary.clone(),
                    ),
                    None => (true, None, None),
                }
            };

            // Roll the layers up into one verdict, keeping the *first*
            // failing layer as the cause so the log points at the real
            // problem rather than a downstream symptom.
            let mut failure: Option<(FailureLayer, String)> = None;
            if !gw_probe.is_success() {
                failure = Some((
                    FailureLayer::Gateway,
                    format!("next hop {} did not answer ICMP", provider_cfg.gateway),
                ));
            } else if !net_probe_opt
                .as_ref()
                .map(|p| p.is_success())
                .unwrap_or(false)
            {
                failure = Some((
                    FailureLayer::Internet,
                    "gateway is reachable but no external probe target answered".to_string(),
                ));
            } else if !dns_probe_opt
                .as_ref()
                .map(|p| p.is_success())
                .unwrap_or(true)
            {
                failure = Some((
                    FailureLayer::Dns,
                    "ICMP reaches the internet but UDP/53 got no valid answer \
                     (typical of an unpaid account or a captive portal)"
                        .to_string(),
                ));
            } else if let Some(detail) = dns_integrity_bad {
                failure = Some((FailureLayer::DnsHijack, detail));
            } else if let Some(detail) = canary_tamper {
                failure = Some((FailureLayer::ContentTampered, detail));
            } else if !canary_ok {
                failure = Some((
                    FailureLayer::ContentUnreachable,
                    canary_summary.unwrap_or_else(|| "canary quorum not met".to_string()),
                ));
            }

            let overall_ok = failure.is_none();

            // Prefer the internet-probe latency for display — it reflects
            // the real user-facing latency through the provider, not just
            // the last LAN hop.
            let latency = net_probe_opt
                .as_ref()
                .and_then(|p| p.latency_ms())
                .or_else(|| gw_probe.latency_ms());

            if let Some((layer, detail)) = &failure {
                if layer.is_conclusive() {
                    // Loud, because this is the case that used to go
                    // completely unnoticed and leave clients offline.
                    error!(
                        provider = %name,
                        layer = layer.as_str(),
                        "{} {} — {detail}",
                        "UPLINK COMPROMISED".bright_red().bold(),
                        name.bright_white().bold(),
                    );
                } else {
                    warn!(provider = %name, layer = layer.as_str(), "unhealthy: {detail}");
                }
            }

            self.apply_probe_result(&name, overall_ok, latency, failure)
                .await;

            if let Err(e) = self.reconcile_active().await {
                error!(error = %e, "failed to reconcile active provider");
            }
        }
    }

    /// One canary round for a provider: fetch every configured target
    /// through this uplink's mark and fold the result into its state.
    async fn run_canary(self: &Arc<Self>, name: &str, mark: u32, timeout: Duration) {
        let resolvers = self.cfg.health.dns_resolvers.clone();
        let resolve_timeout = Duration::from_millis(self.cfg.health.timeout_ms);
        // Hostnames are resolved through this provider's own marked DNS, so
        // the whole chain — DNS, TCP, TLS, HTTP — is pinned to one uplink.
        let resolver = move |host: String| {
            let resolvers = resolvers.clone();
            async move { crate::health::resolve_a_via(&resolvers, &host, resolve_timeout, mark).await }
        };

        let report = check_canary_via(
            &self.canary_targets,
            timeout,
            Some(mark),
            self.canary_quorum,
            &self.cfg.canary.user_agent,
            resolver,
        )
        .await;

        let now = Utc::now();
        let _ = self.stats.record_health(&HealthRecord {
            provider: name.to_string(),
            timestamp: now,
            success: report.is_ok(),
            latency_ms: report.latency.map(|d| d.as_secs_f64() * 1000.0),
            kind: "canary",
        });

        let summary = report.summary();
        let mut ps = self.providers.write().await;
        let Some(entry) = ps.get_mut(name) else {
            return;
        };
        entry.last_canary_at = Some(now);
        entry.last_canary_summary = Some(summary.clone());

        if let Some(detail) = report.conclusive_tamper().map(str::to_string) {
            // Proof: content came back wrong *and* too few targets verified.
            // No threshold, no grace — an indiscriminate rewrite of every
            // endpoint is not something a working link does.
            entry.canary_failures = entry.canary_failures.saturating_add(1);
            entry.canary_ok = false;
            entry.canary_tampered = Some(detail);
        } else if report.is_ok() {
            if entry.canary_failures > 0 {
                info!(provider = %name, "canary recovered: {summary}");
            }
            entry.canary_failures = 0;
            entry.canary_ok = true;
            entry.canary_tampered = None;
        } else {
            // Either the endpoints were unreachable, or one came back wrong
            // while the rest verified. Both have benign explanations, so both
            // require repetition before they cost the provider its health.
            entry.canary_failures = entry.canary_failures.saturating_add(1);
            let threshold = self.cfg.canary.failure_threshold;
            entry.canary_tampered = None;
            if entry.canary_failures >= threshold {
                entry.canary_ok = false;
            }
            if report.tampered.is_some() {
                // Worth a warning rather than a debug line: something really
                // is rewriting content, even if it is not enough to convict
                // the uplink on its own.
                warn!(
                    provider = %name,
                    failures = entry.canary_failures,
                    threshold,
                    "{summary}"
                );
            } else {
                debug!(
                    provider = %name,
                    failures = entry.canary_failures,
                    threshold,
                    "canary round failed: {summary}"
                );
            }
        }
    }

    async fn apply_probe_result(
        &self,
        name: &str,
        success: bool,
        latency_ms: Option<f64>,
        failure: Option<(FailureLayer, String)>,
    ) {
        let fthr = self.cfg.health.failure_threshold;
        let sthr = self.cfg.health.success_threshold;

        let (prev, new, cause) = {
            let mut ps = self.providers.write().await;
            let Some(entry) = ps.get_mut(name) else {
                return;
            };
            let now = Utc::now();
            entry.last_check = Some(now);
            entry.last_latency_ms = latency_ms;
            let prev = entry.state;

            if success {
                entry.consecutive_failures = 0;
                entry.consecutive_successes = entry.consecutive_successes.saturating_add(1);
                entry.failure_layer = None;
                entry.failure_detail = None;
                if entry.state != State::Up && entry.consecutive_successes >= sthr {
                    entry.state = State::Up;
                    // The failback stability window is measured from here.
                    entry.up_since = Some(now);
                }
            } else {
                let conclusive = failure
                    .as_ref()
                    .map(|(l, _)| l.is_conclusive())
                    .unwrap_or(false);
                entry.consecutive_successes = 0;
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                if let Some((layer, detail)) = &failure {
                    entry.failure_layer = Some(*layer);
                    entry.failure_detail = Some(detail.clone());
                }
                // Proof of interception skips the threshold entirely: there
                // is nothing to confirm, and every extra tick spent
                // confirming is a tick of clients sitting on a dead uplink.
                if entry.state != State::Down && (conclusive || entry.consecutive_failures >= fthr)
                {
                    entry.state = State::Down;
                    entry.up_since = None;
                }
            }
            (prev, entry.state, entry.failure_detail.clone())
        };

        if prev != new {
            match new {
                State::Down => warn!(
                    "provider {} is now {}{}",
                    name.bright_white().bold(),
                    new.colored(),
                    cause
                        .as_deref()
                        .map(|c| format!("  ·  {c}"))
                        .unwrap_or_default()
                ),
                _ => info!(
                    "provider {} is now {}",
                    name.bright_white().bold(),
                    new.colored()
                ),
            }
            let _ = self.stats.record_state_change(name, new.as_str());
        }
    }

    /// Pick the best provider (forced if set and healthy; else highest-
    /// priority UP) and ensure the kernel default route points at it. No-op
    /// when the best candidate is already active.
    async fn reconcile_active(self: &Arc<Self>) -> Result<()> {
        self.reconcile_inner(false).await
    }

    /// Same as `reconcile_active`, but forces `ip route replace` even when
    /// the target provider is already the current active. Used by operator
    /// commands (`force`/`auto`) so that a stale kernel default route from
    /// a competing tool (NetworkManager, netplan, DHCP) gets rewritten back
    /// to our choice without requiring the operator to switch twice.
    async fn reconcile_active_forced(self: &Arc<Self>) -> Result<()> {
        self.reconcile_inner(true).await
    }

    async fn reconcile_inner(self: &Arc<Self>, always_install: bool) -> Result<()> {
        let forced = self.force_override.read().await.clone();
        let now = Utc::now();

        // Stretch the failback window if this gateway has been switching a
        // lot lately — see `FlapTracker` for why.
        let failback_stable = {
            let flap = self.flap.lock().unwrap();
            flap.effective_failback(
                now,
                Duration::from_secs(self.cfg.failover.failback_stable_secs),
                self.cfg.failover.flap_threshold,
                Duration::from_secs(self.cfg.failover.flap_window_secs),
                Duration::from_secs(self.cfg.failover.max_failback_stable_secs),
            )
        };

        let (views, by_name): (Vec<ProviderView>, HashMap<String, Provider>) = {
            let ps = self.providers.read().await;
            let views = ps
                .values()
                .map(|p| ProviderView {
                    name: p.cfg.name.clone(),
                    priority: p.cfg.priority,
                    state: p.state,
                    up_since: p.up_since,
                })
                .collect();
            let by_name = ps
                .values()
                .map(|p| (p.cfg.name.clone(), p.cfg.clone()))
                .collect();
            (views, by_name)
        };

        let mut active_guard = self.active.write().await;
        let current: Option<String> = (*active_guard).clone();

        let decision = decide(&SelectionInput {
            now,
            current: current.clone(),
            forced,
            providers: views,
            failback_stable,
        });

        match decision {
            Decision::Keep => {
                if always_install {
                    // Operator-initiated: re-assert the route in case an
                    // external tool (NetworkManager, netplan apply, a DHCP
                    // renew) overwrote it behind our back.
                    if let Some(cur) = current.as_ref().and_then(|c| by_name.get(c)) {
                        self.router
                            .set_default_route(cur.gateway, &cur.interface)
                            .await?;
                        self.router.flush_conntrack().await;
                        info!(
                            provider = %cur.name,
                            "{}: re-asserted default route (operator request)",
                            "FORCE".bright_magenta().bold()
                        );
                    }
                }
                Ok(())
            }

            Decision::WaitingForFailback {
                candidate,
                stable_for,
                required,
            } => {
                // Debug, not info: this fires on every tick while waiting,
                // and the interesting event is the switch that follows.
                debug!(
                    candidate = %candidate,
                    stable_for_s = stable_for.as_secs(),
                    required_s = required.as_secs(),
                    "failback pending — waiting for the higher-priority provider to prove itself"
                );
                Ok(())
            }

            Decision::Switch { to, reason } => {
                let Some(target) = by_name.get(&to) else {
                    // The decision only ever names a provider it was given.
                    bail!("selection chose unknown provider '{to}'");
                };

                // Is this actually a change, or are we re-asserting a route
                // the kernel already has? It matters because the flush below
                // resets every live connection on the box.
                //
                // The common case is a daemon restart: state starts empty, so
                // the first reconcile is a "switch" to whichever provider is
                // healthy — usually the one already installed. Flushing there
                // would drop every established connection for no reason, and
                // an update is exactly when that would be noticed.
                let route_unchanged = matches!(
                    self.router.current_default().await,
                    Ok(Some(ref r)) if r.gateway == target.gateway && r.interface == target.interface
                );

                self.router
                    .set_default_route(target.gateway, &target.interface)
                    .await?;

                if route_unchanged {
                    debug!(
                        provider = %to,
                        "selected provider already owns the default route — \
                         skipping the conntrack flush"
                    );
                } else {
                    // A real path change: existing flows are bound to the old
                    // uplink's NAT state and would black-hole until they time
                    // out. Reset them so they reconnect immediately.
                    self.router.flush_conntrack().await;
                }

                let _ = self.stats.record_failover(&FailoverRecord {
                    timestamp: now,
                    from_provider: current.clone(),
                    to_provider: to.clone(),
                    reason: reason.clone(),
                });

                *active_guard = Some(to.clone());
                drop(active_guard);

                // Only count real switches — not the initial installation,
                // which is not a flap by any definition.
                if current.is_some() {
                    self.flap.lock().unwrap().record_switch(now);
                }

                let from_label = current.as_deref().unwrap_or("(none)");
                info!(
                    "{} {} {} {}  ·  {}",
                    "FAILOVER".bright_magenta().bold(),
                    from_label.bright_yellow(),
                    "→".bright_cyan().bold(),
                    to.bright_green().bold(),
                    reason.dimmed()
                );
                Ok(())
            }

            Decision::NoHealthyProvider => {
                if let Some(cur) = current {
                    error!(
                        provider = %cur,
                        "no healthy providers — keeping the installed route (traffic may black-hole)"
                    );
                } else {
                    warn!("no healthy providers yet — waiting for first successful probes");
                }
                Ok(())
            }
        }
    }

    /// Periodically confirm that the kernel default route is still the one
    /// we installed, and put it back if it is not.
    ///
    /// A DHCP renew, `netplan apply` or NetworkManager can silently replace
    /// the default route underneath a running daemon. Everything then looks
    /// healthy from our side — our own state says "provider X is active" —
    /// while traffic actually leaves through whatever the other tool chose.
    /// The watchdog closes that gap.
    async fn route_watchdog(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let period = Duration::from_secs(self.cfg.failover.route_watchdog_secs.max(1));
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        debug!("route watchdog stopping");
                        return;
                    }
                }
            }

            let Some(active) = self.active.read().await.clone() else {
                continue;
            };
            let expected = {
                let ps = self.providers.read().await;
                ps.get(&active).map(|p| p.cfg.clone())
            };
            let Some(expected) = expected else { continue };

            // Both the next hop *and* the egress interface have to match.
            // A route with the right gateway on the wrong interface sends
            // traffic somewhere we did not choose just as effectively as a
            // wrong gateway does.
            let matches = |r: &crate::router::InstalledRoute| {
                r.gateway == expected.gateway && r.interface == expected.interface
            };

            match self.router.current_default().await {
                Ok(Some(installed)) if matches(&installed) => {}
                Ok(other) => {
                    warn!(
                        provider = %expected.name,
                        expected_gw = %expected.gateway,
                        expected_dev = %expected.interface,
                        found = ?other,
                        "default route was changed by something else — re-installing ours"
                    );
                    if let Err(e) = self
                        .router
                        .set_default_route(expected.gateway, &expected.interface)
                        .await
                    {
                        error!(error = %e, "route watchdog failed to re-install the default route");
                    } else {
                        // Traffic has been leaving through somebody else's
                        // choice of uplink for up to one watchdog period, so
                        // conntrack now holds entries bound to the wrong
                        // path. Without a flush those flows stay broken until
                        // they time out — the same reason a normal switchover
                        // flushes.
                        self.router.flush_conntrack().await;
                        let _ = self.stats.record_failover(&FailoverRecord {
                            timestamp: Utc::now(),
                            from_provider: Some(expected.name.clone()),
                            to_provider: expected.name.clone(),
                            reason: "route watchdog: external tool replaced our default route"
                                .to_string(),
                        });
                    }
                }
                Err(e) => debug!(error = %e, "route watchdog could not read the default route"),
            }
        }
    }

    /// Hourly prune of `health_checks`. Without this the table grows without
    /// bound — several rows per provider every few seconds adds up to tens
    /// of millions of rows a year on a box that is never restarted.
    async fn retention_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let retention = self.cfg.health.retention_hours;
        if retention == 0 {
            return;
        }
        let mut ticker = tokio::time::interval(Duration::from_secs(3600));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick fires immediately; that is deliberate, so a daemon
        // restarted after a long outage cleans up straight away.
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                }
            }
            match self.stats.prune_health(retention) {
                Ok(n) if n > 0 => info!(deleted = n, "health: pruned old check rows"),
                Ok(_) => {}
                Err(e) => warn!(error = %e, "health: prune failed"),
            }
        }
    }

    async fn status_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        // Short warm-up so the first snapshot shows real probe results.
        let warmup = Duration::from_secs(
            self.cfg.health.interval_secs + self.cfg.health.success_threshold as u64,
        );
        tokio::select! {
            _ = tokio::time::sleep(warmup) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { return; }
            }
        }

        let interval = Duration::from_secs(self.cfg.health.status_print_secs.max(5));
        loop {
            self.print_status().await;
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() { return; }
                }
            }
        }
    }

    async fn print_status(&self) {
        let ps = self.providers.read().await;
        let active_guard = self.active.read().await;
        let active: Option<String> = (*active_guard).clone();
        drop(active_guard);

        let mut rows: Vec<&ProviderState> = ps.values().collect();
        rows.sort_by_key(|p| p.cfg.priority);

        let divider = "─".repeat(78);
        println!();
        println!("{}", format!("┌{divider}┐").bright_blue());
        println!(
            "{} {}",
            "│".bright_blue(),
            " vlb status snapshot".bright_white().bold()
        );
        println!("{}", format!("├{divider}┤").bright_blue());

        for p in rows {
            let marker = if Some(&p.cfg.name) == active.as_ref() {
                "★".bright_yellow().bold().to_string()
            } else {
                " ".to_string()
            };
            // Pad plain text first, then apply colors — width specifiers
            // applied directly to colored strings count ANSI escape bytes as
            // characters and break column alignment.
            let name_cell = format!("{:<14}", p.cfg.name);
            let gw_cell = format!("{:<15}", p.cfg.gateway);
            let (dot, state_label) = match p.state {
                State::Up => ("●".bright_green().bold(), "UP     ".bright_green().bold()),
                State::Down => ("●".bright_red().bold(), "DOWN   ".bright_red().bold()),
                State::Unknown => ("●".bright_yellow().bold(), "UNKNOWN".bright_yellow().bold()),
            };
            let latency = p
                .last_latency_ms
                .map(|l| format!("{l:8.2} ms"))
                .unwrap_or_else(|| "      --  ".to_string());
            let last = p
                .last_check
                .map(|t| t.format("%H:%M:%S").to_string())
                .unwrap_or_else(|| "--:--:--".to_string());

            println!(
                "{} {} {} prio={:<2} {} {} {}  lat={}  last={}",
                "│".bright_blue(),
                marker,
                name_cell.bright_white().bold(),
                p.cfg.priority,
                gw_cell.bright_white(),
                dot,
                state_label,
                latency.bright_cyan(),
                last.dimmed(),
            );
        }
        println!("{}", format!("└{divider}┘").bright_blue());
        println!();
    }

    pub async fn shutdown(&self) {
        let handles = std::mem::take(&mut *self.handles.lock().unwrap());
        for h in &handles {
            h.abort();
        }
        for h in handles {
            let _ = h.await;
        }
        info!("{}", "balancer stopped".bright_white().bold());
    }

    // ────────────────────────────────────────────────────────────────────
    // Public control-plane API, consumed by `src/control.rs` and the TUI.
    // ────────────────────────────────────────────────────────────────────

    pub async fn snapshot(&self) -> ControlSnapshot {
        let ps = self.providers.read().await;
        let active = self.active.read().await.clone();
        let forced = self.force_override.read().await.clone();

        let mut providers: Vec<ProviderSnapshot> = ps
            .values()
            .map(|p| ProviderSnapshot {
                name: p.cfg.name.clone(),
                gateway: p.cfg.gateway.to_string(),
                interface: p.cfg.interface.clone(),
                priority: p.cfg.priority,
                role: p.cfg.role.as_str().to_string(),
                state: p.state,
                last_latency_ms: p.last_latency_ms,
                last_check: p.last_check,
                consecutive_failures: p.consecutive_failures,
                consecutive_successes: p.consecutive_successes,
                up_since: p.up_since,
                failure_layer: p.failure_layer,
                failure_detail: p.failure_detail.clone(),
                canary_ok: p.canary_ok,
                last_canary_at: p.last_canary_at,
                last_canary_summary: p.last_canary_summary.clone(),
            })
            .collect();
        providers.sort_by_key(|p| p.priority);

        ControlSnapshot {
            active,
            forced,
            providers,
        }
    }

    pub async fn force_provider(self: &Arc<Self>, name: &str) -> Result<()> {
        // We accept a force pin even if the provider is currently Down or
        // Unknown. Operator intent wins over our health view: probes can
        // lag for a few ticks after start, and `force` is the documented
        // escape hatch when our probes and reality disagree (e.g. the
        // probe target is blocked but real traffic works).
        //
        // If the pinned provider happens to be Down, `reconcile_inner`
        // falls back to the best healthy one until the pin recovers and
        // then puts the pinned route back.
        let (exists, state) = {
            let ps = self.providers.read().await;
            match ps.get(name) {
                Some(p) => (true, p.state),
                None => (false, State::Unknown),
            }
        };
        if !exists {
            return Err(anyhow!("unknown provider '{name}'"));
        }
        {
            let mut f = self.force_override.write().await;
            *f = Some(name.to_string());
        }
        match state {
            State::Up => info!(provider = %name, "operator override installed"),
            State::Down => warn!(
                provider = %name,
                "operator override installed for provider currently DOWN — \
                 route will switch as soon as it recovers; using healthy \
                 fallback in the meantime"
            ),
            State::Unknown => info!(
                provider = %name,
                "operator override installed for provider in UNKNOWN state \
                 (no probes yet) — route will switch as soon as it comes up"
            ),
        }
        // Always reconcile AND force a route re-install even if the target
        // is already the current active — this lets operators use `force`
        // to recover from a situation where an external actor (NetworkManager,
        // netplan apply, DHCP renew) has overwritten our default route.
        if let Err(e) = self.reconcile_active_forced().await {
            warn!(error = %e, "failed to reconcile after force");
            return Err(e);
        }
        Ok(())
    }

    pub async fn clear_force(self: &Arc<Self>) {
        {
            let mut f = self.force_override.write().await;
            *f = None;
        }
        info!("operator override cleared");
        if let Err(e) = self.reconcile_active_forced().await {
            warn!(error = %e, "failed to reconcile after clearing force");
        }
    }

    pub fn recent_system(&self, limit: u32) -> Result<Vec<SystemPoint>> {
        let limit = limit.min(10_000);
        self.stats.recent_system(limit)
    }

    pub fn recent_traffic(&self, provider: &str, limit: u32) -> Result<Vec<TrafficPoint>> {
        // Clamp to a sane maximum so a buggy TUI can't DoS the DB.
        let limit = limit.min(10_000);
        self.stats.recent_traffic(provider, limit)
    }

    // ────────────────────────────────────────────────────────────────────
    // Background loops.
    // ────────────────────────────────────────────────────────────────────

    async fn traffic_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.cfg.traffic.interval_secs.max(1));
        let retention = self.cfg.traffic.retention_hours;
        let mut prev: HashMap<String, traffic::IfCounters> = HashMap::new();
        let mut last_prune = Utc::now();
        let mut first_sample_logged = false;
        let mut missing_warned: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        // Distinct interfaces we actually need to sample (multiple providers
        // may share one LAN NIC — sampling it 3× per tick was wasteful and
        // caused stale-prev bugs).
        let watched: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            self.cfg
                .providers
                .iter()
                .filter(|p| seen.insert(p.interface.clone()))
                .map(|p| p.interface.clone())
                .collect()
        };
        info!(
            interval_s = interval.as_secs(),
            interfaces = ?watched,
            "traffic: sampling started"
        );

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        debug!("traffic loop stopping");
                        return;
                    }
                }
            }

            let snap = match traffic::snapshot().await {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, "traffic: failed to read counters");
                    continue;
                }
            };

            // 1. Compute per-interface deltas once (fixes the bug where
            //    providers sharing an interface got 0 deltas because `prev`
            //    had already been overwritten by the previous iteration).
            let now = Utc::now();
            let mut iface_delta: HashMap<String, traffic::IfCounters> = HashMap::new();
            for iface in &watched {
                let Some(curr) = snap.get(iface).copied() else {
                    if missing_warned.insert(iface.clone()) {
                        warn!(
                            iface = %iface,
                            "traffic: interface not found in /proc/net/dev — \
                             check `ip link` and the config `interface = ...` values"
                        );
                    }
                    continue;
                };
                if let Some(prev_c) = prev.get(iface).copied() {
                    if let Some(d) = traffic::delta(prev_c, curr) {
                        iface_delta.insert(iface.clone(), d);
                    } else {
                        debug!(iface = %iface, "traffic: counter reset, skipping");
                    }
                }
                prev.insert(iface.clone(), curr);
            }

            // 2. Persist one row per provider using the cached delta.
            for p in &self.cfg.providers {
                let Some(d) = iface_delta.get(&p.interface).copied() else {
                    continue;
                };
                if let Err(e) = self.stats.record_traffic(
                    &p.name,
                    &p.interface,
                    now,
                    interval.as_secs_f64(),
                    &d,
                ) {
                    warn!(error = %e, provider = %p.name, "traffic: persist failed");
                } else if !first_sample_logged {
                    info!(
                        provider = %p.name,
                        iface = %p.interface,
                        rx_bytes = d.rx_bytes,
                        tx_bytes = d.tx_bytes,
                        "traffic: first sample recorded"
                    );
                    first_sample_logged = true;
                }
            }

            // Prune at most once per hour.
            if retention > 0 && (now - last_prune).num_seconds() > 3600 {
                match self.stats.prune_traffic(retention) {
                    Ok(n) if n > 0 => info!(deleted = n, "traffic: pruned old samples"),
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "traffic: prune failed"),
                }
                last_prune = now;
            }
        }
    }

    /// Host-wide btop-style metrics: CPU (per-core + total), RAM, swap,
    /// load average, aggregate network, disk totals, process count. Sampled
    /// on `system.interval_secs`, written to `system_samples`, pruned hourly.
    async fn system_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.cfg.system.interval_secs.max(1));
        let retention = self.cfg.system.retention_hours;
        let per_core = self.cfg.system.per_core;

        let mut monitor = SysMonitor::new();
        // sysinfo needs two refreshes to produce accurate CPU %; warm it up
        // so the first DB row is already meaningful.
        let _ = monitor.sample();

        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_prune = Utc::now();

        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        debug!("system loop stopping");
                        return;
                    }
                }
            }

            let sample = monitor.sample();
            let now = Utc::now();
            if let Err(e) = self.stats.record_system(now, &sample, per_core) {
                warn!(error = %e, "system: failed to persist sample");
            }

            if retention > 0 && (now - last_prune).num_seconds() > 3600 {
                match self.stats.prune_system(retention) {
                    Ok(n) if n > 0 => info!(deleted = n, "system: pruned old samples"),
                    Ok(_) => {}
                    Err(e) => warn!(error = %e, "system: prune failed"),
                }
                last_prune = now;
            }
        }
    }
}
