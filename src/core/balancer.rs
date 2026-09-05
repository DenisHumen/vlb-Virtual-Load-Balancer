use anyhow::{Result, anyhow, bail};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::notify;
use crate::router::Router;
use crate::selection::{Decision, FlapTracker, ProviderView, SelectionInput, decide};
use crate::stats::{FailoverEvent, FailoverRecord, HealthRecord, Stats, SystemPoint, TrafficPoint};
use crate::sysmon::SysMonitor;
use crate::system::Prepared;
use crate::traffic;

/// Key under which the operator pin is persisted in the stats database.
const KV_FORCED_PROVIDER: &str = "forced_provider";

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
    /// Reachable, authentic, and far too slow to carry traffic.
    Throttled,
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
            FailureLayer::Throttled => "throttled",
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
    /// Consecutive failing throughput measurements, and the latest reading.
    /// Kept apart from the canary counters because this check runs on its own
    /// much slower cadence and is the noisiest of the three.
    throughput_failures: u32,
    throughput_ok: bool,
    last_throughput_at: Option<DateTime<Utc>>,
    last_throughput_summary: Option<String>,
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
    /// Pre-parsed throughput payload URL; `None` when the check is off.
    throughput_url: Option<crate::http::Url>,
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
    dry_run: bool,
    /// Providers whose routing table could not be set up at startup. The
    /// health loop retries them until they work.
    policy_pending: Vec<String>,
    /// True while `active` names a provider adopted from the kernel routing
    /// table at startup that this process has not yet verified itself.
    active_adopted: AtomicBool,
    started_at: DateTime<Utc>,
    /// The failback countdown, if one is running — surfaced to the TUI.
    failback_pending: StdMutex<Option<FailbackPending>>,
    /// Last line handed to systemd, so an unchanged status is not re-sent on
    /// every tick.
    last_status_line: StdMutex<String>,
}

/// A better provider is healthy and the daemon is waiting for it to prove
/// stable before failing back to it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailbackPending {
    pub candidate: String,
    pub stable_for_secs: u64,
    pub required_secs: u64,
}

/// Read-only snapshot of the balancer state, serialized over the control
/// protocol and consumed by the TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlSnapshot {
    pub active: Option<String>,
    pub forced: Option<String>,
    pub providers: Vec<ProviderSnapshot>,
    /// Fields below were added later; `#[serde(default)]` keeps a newer TUI
    /// talking to an older daemon (and the reverse) during an update.
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    /// `active` was taken over from the routing table at startup and has not
    /// been confirmed healthy by this process yet.
    #[serde(default)]
    pub active_adopted: bool,
    /// The default route as the kernel actually has it — the ground truth,
    /// independent of what the daemon believes.
    #[serde(default)]
    pub kernel_route: Option<String>,
    #[serde(default)]
    pub failback_pending: Option<FailbackPending>,
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
    #[serde(default)]
    pub throughput_ok: bool,
    #[serde(default)]
    pub last_throughput_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_throughput_summary: Option<String>,
}

impl Balancer {
    pub async fn new(cfg: Config, dry_run: bool, prepared: Prepared) -> Result<Arc<Self>> {
        let stats = Arc::new(Stats::open(&cfg.database.path, &cfg.providers)?);
        let router = Router::new(dry_run, prepared.installed_bootstrap);
        let now = Utc::now();

        // ── continuity across a restart ─────────────────────────────────
        //
        // Nothing is torn down on shutdown, so after an update the kernel
        // still routes through whichever provider the previous instance
        // chose. Rather than start from "nothing selected" — where the first
        // provider to pass its checks wins, which on links of unequal speed
        // is often the *backup*, complete with a conntrack flush and a
        // thirty-second detour before failing back — take the installed
        // route as the incumbent. It keeps carrying traffic, untouched, until
        // this process has probed its provider to a verdict of its own.
        //
        // Only a route at metric 0 qualifies: that is what this daemon
        // installs. The provisional bootstrap route and a netplan default at
        // metric 100 are not choices anyone made.
        let (active, adopted) = match router.current_default().await {
            Ok(Some(route)) if route.metric.unwrap_or(0) == 0 => {
                match cfg
                    .providers
                    .iter()
                    .find(|p| p.gateway == route.gateway && p.interface == route.interface)
                {
                    Some(p) => {
                        info!(
                            provider = %p.name,
                            route = %route,
                            "adopted the installed default route as the incumbent — traffic \
                             keeps flowing through it while the health checks confirm it"
                        );
                        (Some(p.name.clone()), true)
                    }
                    None => {
                        info!(
                            route = %route,
                            "the installed default route matches no configured provider; \
                             the first provider to pass its checks will replace it"
                        );
                        (None, false)
                    }
                }
            }
            Ok(_) => (None, false),
            Err(e) => {
                debug!(error = %e, "could not read the default route at startup");
                (None, false)
            }
        };

        // The operator's pin outlives the process: an update must not
        // silently undo a `vlb force` from an hour ago.
        let forced = match stats.get_kv(KV_FORCED_PROVIDER) {
            Ok(Some(name)) if cfg.providers.iter().any(|p| p.name == name) => {
                info!(
                    provider = %name,
                    "operator pin restored from the previous run (release it with `vlb auto`)"
                );
                Some(name)
            }
            Ok(Some(name)) => {
                warn!(
                    provider = %name,
                    "a persisted operator pin names a provider that is no longer configured — \
                     discarding it"
                );
                let _ = stats.del_kv(KV_FORCED_PROVIDER);
                None
            }
            Ok(None) => None,
            Err(e) => {
                warn!(error = %e, "could not read the persisted operator pin");
                None
            }
        };

        // Flap history survives too, so a bouncing uplink cannot reset its
        // own backoff by having the daemon restarted.
        let flap = {
            let window = chrono::Duration::seconds(cfg.failover.flap_window_secs as i64);
            match stats.failover_times_since(now - window, 256) {
                Ok(times) if !times.is_empty() => {
                    info!(
                        switches = times.len(),
                        window_secs = cfg.failover.flap_window_secs,
                        "flap history restored from the previous run"
                    );
                    FlapTracker::with_history(times)
                }
                Ok(_) => FlapTracker::new(),
                Err(e) => {
                    warn!(error = %e, "could not restore flap history");
                    FlapTracker::new()
                }
            }
        };

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

        // Parsed once. `validate()` already proved it well-formed.
        let throughput_url = if cfg.canary.enabled && cfg.canary.throughput.enabled {
            Some(crate::http::Url::parse(&cfg.canary.throughput.url)?)
        } else {
            None
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
                    throughput_failures: 0,
                    // Optimistic until measured, so a provider is not held
                    // down for a whole interval just because we have not
                    // looked yet.
                    throughput_ok: true,
                    last_throughput_at: None,
                    last_throughput_summary: None,
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
            incumbent = active.as_deref().unwrap_or("(none)"),
            "balancer initialized"
        );

        let me = Arc::new(Self {
            cfg,
            probe_targets,
            canary_targets,
            canary_quorum,
            throughput_url,
            router,
            stats,
            providers: RwLock::new(providers),
            active: RwLock::new(active),
            force_override: RwLock::new(forced),
            flap: StdMutex::new(flap),
            handles: StdMutex::new(Vec::new()),
            dry_run,
            policy_pending: prepared.policy_pending,
            active_adopted: AtomicBool::new(adopted),
            started_at: now,
            failback_pending: StdMutex::new(None),
            last_status_line: StdMutex::new(String::new()),
        });
        me.publish_status().await;
        Ok(me)
    }

    /// Hand systemd a one-line summary for `systemctl status vlb`.
    ///
    /// Sent only when the line changes, which is rarely: the interesting
    /// transitions are a provider changing state or the route moving.
    async fn publish_status(&self) {
        let line = {
            let ps = self.providers.read().await;
            let active = self.active.read().await.clone();
            let forced = self.force_override.read().await.clone();
            let mut rows: Vec<&ProviderState> = ps.values().collect();
            rows.sort_by_key(|p| p.cfg.priority);
            let mut parts = Vec::with_capacity(rows.len() + 2);
            parts.push(match &active {
                Some(a) if self.active_adopted.load(Ordering::Relaxed) => {
                    format!("active: {a} (adopted, verifying)")
                }
                Some(a) => format!("active: {a}"),
                None => "active: none yet".to_string(),
            });
            for p in rows {
                let mut s = format!("{} {}", p.cfg.name, p.state.as_str().to_uppercase());
                if let Some(l) = p.failure_layer
                    && p.state != State::Up
                {
                    s.push_str(&format!(" [{}]", l.as_str()));
                }
                if let Some(ms) = p.last_latency_ms
                    && p.state == State::Up
                {
                    s.push_str(&format!(" {ms:.0}ms"));
                }
                parts.push(s);
            }
            if let Some(f) = forced {
                parts.push(format!("pinned: {f}"));
            }
            parts.join(" · ")
        };
        let changed = {
            let mut last = self.last_status_line.lock().unwrap();
            if *last == line {
                false
            } else {
                *last = line.clone();
                true
            }
        };
        if changed {
            notify::status(&line);
        }
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

        // The throughput probe moves real bytes, so it runs far less often
        // than everything else — a couple of times a minute rather than a
        // couple of times a second.
        let throughput_interval = Duration::from_secs(cfg_throughput_interval(&self.cfg));
        let throughput_timeout =
            Duration::from_millis(self.cfg.canary.throughput.timeout_ms.max(1000));
        let mut last_throughput: Option<std::time::Instant> = None;

        // Startup could not install this provider's routing table (its
        // interface was not up yet, typically). Keep trying from here: the
        // probes below cannot pass without it, so until it succeeds this
        // provider is simply — and truthfully — down.
        let mut policy_ready = self.dry_run || !self.policy_pending.contains(&name);
        let mut policy_attempts: u32 = 0;

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

            if !policy_ready {
                policy_attempts = policy_attempts.saturating_add(1);
                match crate::system::setup_provider_policy_route(&self.cfg, &provider_cfg).await {
                    Ok(()) => {
                        policy_ready = true;
                        info!(
                            provider = %name,
                            attempts = policy_attempts,
                            "routing table set up — the interface is usable now"
                        );
                    }
                    Err(e) => {
                        // Loud the first time and every so often after that,
                        // quiet in between: a permanently absent interface
                        // should not fill the journal.
                        if policy_attempts == 1 || policy_attempts % 20 == 0 {
                            warn!(provider = %name, attempts = policy_attempts, error = %e,
                                  "routing table still cannot be set up; retrying");
                        } else {
                            debug!(provider = %name, error = %e, "routing table retry failed");
                        }
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
            }

            // 6. Throughput.
            //
            //    When to *run* it and how to *label* its result are separate
            //    questions, and conflating them gets one of the two wrong.
            //
            //    Running: only when the *reachability* layers pass — gateway,
            //    internet, DNS, and no proof of interception. Those failing
            //    means the link is dead, and firing a 64 KiB transfer at a
            //    dead link teaches us nothing while stretching the health loop
            //    by the whole timeout, delaying the failover they just called
            //    for. Measured in the lab: the blackhole scenario went from
            //    8 s to 26 s when this ran unconditionally.
            //
            //    Note what is deliberately *not* in that gate: the canary. A
            //    throttled link starves the canary, so gating on it would let
            //    the condition being detected switch off its own detector —
            //    the probe would never run precisely when it was needed, and
            //    the throttle would be misreported as unreachable endpoints.
            //
            //    Labelling: a known-bad throughput reading outranks a canary
            //    timeout. On a rate-limited link the canary times out *because
            //    of* the throttle, so reporting the timeout would name the
            //    symptom and hide the cause — telling the operator to go
            //    looking at endpoints when the provider has capped them.
            if failure.is_none() {
                let since_last = last_throughput.map(|t: std::time::Instant| t.elapsed());
                let on_schedule = since_last
                    .map(|elapsed| elapsed >= throughput_interval)
                    .unwrap_or(true);

                // Measure early when the canary has just failed while every
                // reachability layer still passes. That combination has few
                // explanations and a rate limit is the leading one: the
                // throttle starves the canary, which is *why* it failed.
                //
                // Without this the answer waits for the next scheduled round
                // — up to two minutes at the shipped interval — and for that
                // whole window the provider is reported as having unreachable
                // endpoints. The operator is sent to check third-party URLs
                // when the actual finding is that their ISP has capped the
                // link. The floor on spacing keeps a persistently broken
                // provider from re-measuring on every tick.
                let min_spacing = Duration::from_secs(15).min(throughput_interval);
                let expedited = !canary_ok
                    && since_last
                        .map(|elapsed| elapsed >= min_spacing)
                        .unwrap_or(true);

                if self.throughput_url.is_some() && (on_schedule || expedited) {
                    if expedited && !on_schedule {
                        debug!(
                            provider = %name,
                            "canary failed while reachability passed — measuring throughput \
                             now rather than waiting for the next scheduled round"
                        );
                    }
                    last_throughput = Some(std::time::Instant::now());
                    self.run_throughput(&name, mark, throughput_timeout).await;
                }
            }

            if failure.is_none() {
                let (tp_ok, tp_summary) = {
                    let ps = self.providers.read().await;
                    match ps.get(&name) {
                        Some(e) => (e.throughput_ok, e.last_throughput_summary.clone()),
                        None => (true, None),
                    }
                };
                if !tp_ok {
                    failure = Some((
                        FailureLayer::Throttled,
                        tp_summary.unwrap_or_else(|| "throughput below the floor".into()),
                    ));
                } else if !canary_ok {
                    failure = Some((
                        FailureLayer::ContentUnreachable,
                        canary_summary.unwrap_or_else(|| "canary quorum not met".to_string()),
                    ));
                }
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
            self.publish_status().await;
        }
    }

    /// One throughput measurement for a provider.
    ///
    /// Deliberately separate from the content canary: that one asks "are
    /// these bytes ours", this one asks "can this link actually move bytes".
    /// A throttled provider passes the first and fails the second.
    async fn run_throughput(self: &Arc<Self>, name: &str, mark: u32, timeout: Duration) {
        let Some(url) = self.throughput_url.clone() else {
            return;
        };
        let floor = self.cfg.canary.throughput.min_kbps;
        let resolvers = self.cfg.health.dns_resolvers.clone();
        let resolve_timeout = Duration::from_millis(self.cfg.health.timeout_ms);
        let resolver = move |host: String| {
            let resolvers = resolvers.clone();
            async move { crate::health::resolve_a_via(&resolvers, &host, resolve_timeout, mark).await }
        };

        let verdict = crate::canary::check_throughput_via(
            &url,
            floor,
            timeout,
            Some(mark),
            &self.cfg.canary.user_agent,
            resolver,
        )
        .await;

        let now = Utc::now();
        let _ = self.stats.record_health(&HealthRecord {
            provider: name.to_string(),
            timestamp: now,
            success: verdict.is_ok(),
            latency_ms: None,
            kind: "throughput",
        });

        let summary = verdict.describe();
        let threshold = self.cfg.canary.throughput.failure_threshold;

        let mut ps = self.providers.write().await;
        let Some(entry) = ps.get_mut(name) else {
            return;
        };
        entry.last_throughput_at = Some(now);
        entry.last_throughput_summary = Some(summary.clone());

        if verdict.is_ok() {
            if entry.throughput_failures > 0 {
                info!(provider = %name, "throughput recovered: {summary}");
            }
            entry.throughput_failures = 0;
            entry.throughput_ok = true;
        } else {
            entry.throughput_failures = entry.throughput_failures.saturating_add(1);
            if entry.throughput_failures >= threshold {
                entry.throughput_ok = false;
            }
            warn!(
                provider = %name,
                failures = entry.throughput_failures,
                threshold,
                "throughput check failed: {summary}"
            );
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
                if entry.state != State::Up && entry.consecutive_successes >= sthr {
                    entry.state = State::Up;
                    // The failback stability window is measured from here.
                    entry.up_since = Some(now);
                    // Only now is the reason stale. Clearing it on the first
                    // successful tick — before the provider has actually
                    // recovered — leaves a window where the snapshot says
                    // DOWN with no explanation, which is the one moment an
                    // operator is most likely to be looking at it. A flapping
                    // link spends most of its time in exactly that window.
                    entry.failure_layer = None;
                    entry.failure_detail = None;
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

        // The countdown is only meaningful while a failback is pending;
        // every other outcome clears it.
        {
            let pending = match &decision {
                Decision::WaitingForFailback {
                    candidate,
                    stable_for,
                    required,
                } => Some(FailbackPending {
                    candidate: candidate.clone(),
                    stable_for_secs: stable_for.as_secs(),
                    required_secs: required.as_secs(),
                }),
                _ => None,
            };
            *self.failback_pending.lock().unwrap() = pending;
        }

        match decision {
            Decision::Keep => {
                // An adopted incumbent that has now passed its checks is,
                // from here on, simply ours. Assert the route once so it
                // carries our metric/proto and any rival at metric 0 is
                // removed — `replace` on an identical route changes nothing
                // the kernel forwards on, so no flush is needed or done.
                let verifying = self.active_adopted.swap(false, Ordering::SeqCst);
                if verifying && let Some(cur) = current.as_ref().and_then(|c| by_name.get(c)) {
                    self.router
                        .set_default_route(cur.gateway, &cur.interface)
                        .await?;
                    info!(
                        provider = %cur.name,
                        "{} the adopted route's provider passed its health checks — \
                         the route is now verified and owned by this process",
                        "VERIFIED".bright_green().bold()
                    );
                }
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

            Decision::WaitingForVerdict {
                incumbent,
                candidate,
            } => {
                debug!(
                    incumbent = %incumbent,
                    candidate = %candidate,
                    "keeping the adopted route while its provider is still being probed \
                     — a healthy alternative exists but 'unknown' is not 'broken'"
                );
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
                // Whatever was adopted at startup, this is now our own
                // choice, made on our own evidence.
                self.active_adopted.store(false, Ordering::SeqCst);
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

            // Hold the read side of `active` across the whole check-and-fix.
            // `reconcile` installs a new route and *then* updates `active`
            // under the write lock; a watchdog tick landing between those two
            // steps would read the old name, see the new route as foreign,
            // and put the old — possibly dead — provider's route back for a
            // full watchdog period. Holding the lock serialises the two.
            let active_guard = self.active.read().await;
            let Some(active) = active_guard.clone() else {
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

            // Look at *every* default, not just the preferred one. A rival at
            // the same metric 0 with a different proto sits alongside ours at
            // equal cost, and the kernel breaks that tie by insertion order —
            // so "the best route looks right" is not a safe check. The only
            // reliable question is whether a rival exists at all.
            let verdict = self.router.current_defaults().await.map(|routes| {
                let ours_present = routes.iter().any(&matches);
                let rival = routes
                    .iter()
                    .find(|r| r.metric.unwrap_or(0) == 0 && !matches(r))
                    .cloned();
                (ours_present, rival)
            });

            match verdict {
                Ok((true, None)) => {}
                Ok((ours_present, rival)) => {
                    if let Some(r) = &rival {
                        warn!(
                            rival_gw = %r.gateway,
                            rival_proto = r.proto.as_deref().unwrap_or("(none)"),
                            ours_present,
                            "a competing default route is installed at metric 0 —                              the kernel would choose between it and ours arbitrarily"
                        );
                    }
                    let other = rival;
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
            drop(active_guard);
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
        notify::stopping();
        let handles = std::mem::take(&mut *self.handles.lock().unwrap());
        for h in &handles {
            h.abort();
        }
        for h in handles {
            let _ = h.await;
        }
        // Deliberately no teardown: the default route, the per-provider
        // tables, the NAT rules and the sysctls all stay exactly as they are,
        // so clients keep flowing through the restart and the next instance
        // adopts the route rather than choosing afresh.
        info!(
            "{} — routes, rules and NAT left in place so traffic keeps flowing",
            "balancer stopped".bright_white().bold()
        );
    }

    // ────────────────────────────────────────────────────────────────────
    // Public control-plane API, consumed by `src/control.rs` and the TUI.
    // ────────────────────────────────────────────────────────────────────

    pub async fn snapshot(&self) -> ControlSnapshot {
        // Read the kernel first, outside every lock: it is a subprocess.
        let kernel_route = match self.router.current_default().await {
            Ok(Some(r)) => Some(r.to_string()),
            _ => None,
        };
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
                throughput_ok: p.throughput_ok,
                last_throughput_at: p.last_throughput_at,
                last_throughput_summary: p.last_throughput_summary.clone(),
            })
            .collect();
        providers.sort_by_key(|p| p.priority);

        ControlSnapshot {
            active,
            forced,
            providers,
            version: env!("CARGO_PKG_VERSION").to_string(),
            started_at: Some(self.started_at),
            active_adopted: self.active_adopted.load(Ordering::Relaxed),
            kernel_route,
            failback_pending: self.failback_pending.lock().unwrap().clone(),
        }
    }

    /// Most recent failover events, newest first.
    pub fn recent_failovers(&self, limit: u32) -> Result<Vec<FailoverEvent>> {
        self.stats.recent_failovers(limit.clamp(1, 1_000))
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
        // Persist so the pin outlives a restart (an update, say).
        if let Err(e) = self.stats.set_kv(KV_FORCED_PROVIDER, name) {
            warn!(error = %e, "could not persist the operator pin; it will not survive a restart");
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
        self.publish_status().await;
        Ok(())
    }

    pub async fn clear_force(self: &Arc<Self>) {
        {
            let mut f = self.force_override.write().await;
            *f = None;
        }
        if let Err(e) = self.stats.del_kv(KV_FORCED_PROVIDER) {
            warn!(error = %e, "could not clear the persisted operator pin");
        }
        info!("operator override cleared");
        if let Err(e) = self.reconcile_active_forced().await {
            warn!(error = %e, "failed to reconcile after clearing force");
        }
        self.publish_status().await;
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

/// Effective throughput interval, floored at one second.
fn cfg_throughput_interval(cfg: &Config) -> u64 {
    cfg.canary.throughput.interval_secs.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which layers are treated as *proof* rather than as symptoms.
    ///
    /// Only these two bypass the consecutive-failure threshold and take a
    /// provider down on first observation, so the membership of this set is
    /// the difference between "fails over in a second" and "fails over on a
    /// twitch". A fabricated DNS answer and wrong content cannot occur on a
    /// working link; everything else can.
    #[test]
    fn only_fabricated_answers_count_as_proof() {
        assert!(FailureLayer::DnsHijack.is_conclusive());
        assert!(FailureLayer::ContentTampered.is_conclusive());

        for layer in [
            FailureLayer::Gateway,
            FailureLayer::Internet,
            FailureLayer::Dns,
            FailureLayer::ContentUnreachable,
            FailureLayer::Throttled,
        ] {
            assert!(
                !layer.is_conclusive(),
                "{} can happen on a working link and must not bypass the threshold",
                layer.as_str()
            );
        }
    }

    /// The labels end up in logs, in `vlb status` and in the TUI, and the
    /// lab greps for them. A rename that slipped through would quietly break
    /// every one of those at once.
    #[test]
    fn failure_layer_labels_are_stable_and_distinct() {
        let all = [
            (FailureLayer::Gateway, "gateway"),
            (FailureLayer::Internet, "internet"),
            (FailureLayer::Dns, "dns"),
            (FailureLayer::DnsHijack, "dns-hijack"),
            (FailureLayer::ContentTampered, "content-tampered"),
            (FailureLayer::ContentUnreachable, "content-unreachable"),
            (FailureLayer::Throttled, "throttled"),
        ];
        for (layer, expected) in all {
            assert_eq!(layer.as_str(), expected);
        }
        let labels: std::collections::HashSet<&str> = all.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(labels.len(), all.len(), "labels must be distinct");
    }

    /// The wire form is what the TUI and `vlb status` parse. `snake_case`
    /// serialisation is why the lab asserts on `content_tampered` rather
    /// than the hyphenated display label — the two differ on purpose and
    /// both are load-bearing.
    #[test]
    fn failure_layer_serialises_as_snake_case() {
        let json = serde_json::to_string(&FailureLayer::ContentTampered).unwrap();
        assert_eq!(json, "\"content_tampered\"");
        assert_eq!(
            serde_json::to_string(&FailureLayer::DnsHijack).unwrap(),
            "\"dns_hijack\""
        );
        let back: FailureLayer = serde_json::from_str("\"throttled\"").unwrap();
        assert_eq!(back, FailureLayer::Throttled);
    }
}
