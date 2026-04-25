use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{RwLock, watch};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::{Config, Provider};
use crate::control;
use crate::health::{ProbeTarget, check_dns_via, check_gateway, check_internet_via};
use crate::router::Router;
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

#[derive(Debug)]
struct ProviderState {
    cfg: Provider,
    state: State,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_latency_ms: Option<f64>,
    last_check: Option<DateTime<Utc>>,
}

pub struct Balancer {
    cfg: Config,
    /// Pre-parsed probe targets (IP literals vs hostnames). Computed
    /// once at construction so the hot health loop doesn't re-parse on
    /// every probe interval.
    probe_targets: Vec<ProbeTarget>,
    router: Router,
    stats: Arc<Stats>,
    providers: RwLock<HashMap<String, ProviderState>>,
    active: RwLock<Option<String>>,
    /// Operator pin: when set, the balancer tries to keep this provider
    /// active regardless of priority. It still respects health — a forced
    /// provider that's DOWN falls back to the best available until it
    /// recovers.
    force_override: RwLock<Option<String>>,
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
}

impl Balancer {
    pub async fn new(cfg: Config, dry_run: bool) -> Result<Arc<Self>> {
        let stats = Arc::new(Stats::open(&cfg.database.path, &cfg.providers)?);
        let router = Router::new(dry_run);

        let probe_targets: Vec<ProbeTarget> = cfg
            .health
            .probe_targets
            .iter()
            .map(|s| ProbeTarget::parse(s))
            .collect();

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
                },
            );
        }

        info!(
            providers = cfg.providers.len(),
            db = %cfg.database.path.display(),
            "balancer initialized"
        );

        Ok(Arc::new(Self {
            cfg,
            probe_targets,
            router,
            stats,
            providers: RwLock::new(providers),
            active: RwLock::new(None),
            force_override: RwLock::new(None),
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

            let overall_ok = gw_probe.is_success()
                && net_probe_opt
                    .as_ref()
                    .map(|p| p.is_success())
                    .unwrap_or(false)
                && dns_probe_opt
                    .as_ref()
                    .map(|p| p.is_success())
                    .unwrap_or(true);

            // Prefer the internet-probe latency for display — it reflects
            // the real user-facing latency through the provider, not just
            // the last LAN hop.
            let latency = net_probe_opt
                .as_ref()
                .and_then(|p| p.latency_ms())
                .or_else(|| gw_probe.latency_ms());

            if !overall_ok && gw_probe.is_success() {
                if net_probe_opt
                    .as_ref()
                    .map(|p| p.is_success())
                    .unwrap_or(false)
                    && dns_probe_opt
                        .as_ref()
                        .map(|p| !p.is_success())
                        .unwrap_or(false)
                {
                    warn!(
                        provider = %name,
                        "ICMP reaches the internet but DNS resolution failed — \
                         provider marked as unhealthy (likely unpaid account / captive portal)"
                    );
                } else {
                    warn!(
                        provider = %name,
                        "gateway reachable but internet probe failed — provider marked as unhealthy"
                    );
                }
            }

            self.apply_probe_result(&name, overall_ok, latency).await;

            if let Err(e) = self.reconcile_active().await {
                error!(error = %e, "failed to reconcile active provider");
            }
        }
    }

    async fn apply_probe_result(&self, name: &str, success: bool, latency_ms: Option<f64>) {
        let fthr = self.cfg.health.failure_threshold;
        let sthr = self.cfg.health.success_threshold;

        let (prev, new) = {
            let mut ps = self.providers.write().await;
            let Some(entry) = ps.get_mut(name) else {
                return;
            };
            entry.last_check = Some(Utc::now());
            entry.last_latency_ms = latency_ms;
            let prev = entry.state;

            if success {
                entry.consecutive_failures = 0;
                entry.consecutive_successes = entry.consecutive_successes.saturating_add(1);
                if entry.state != State::Up && entry.consecutive_successes >= sthr {
                    entry.state = State::Up;
                }
            } else {
                entry.consecutive_successes = 0;
                entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
                if entry.state != State::Down && entry.consecutive_failures >= fthr {
                    entry.state = State::Down;
                }
            }
            (prev, entry.state)
        };

        if prev != new {
            info!(
                "provider {} is now {}",
                name.bright_white().bold(),
                new.colored()
            );
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

        let (best, reason_prefix): (Option<Provider>, &'static str) = {
            let ps = self.providers.read().await;
            if let Some(ref forced_name) = forced {
                match ps.get(forced_name) {
                    Some(entry) if entry.state == State::Up => {
                        (Some(entry.cfg.clone()), "operator override")
                    }
                    Some(entry) if always_install => {
                        // Operator-initiated action (force / auto-then-force).
                        // Install the override *regardless* of our health
                        // view so manual switching is never blocked by a
                        // stale/lagging probe. Health-driven reconciles
                        // (the ticker path, `always_install = false`) still
                        // fall back to a healthy provider below, so the
                        // operator can recover automatically.
                        (Some(entry.cfg.clone()), "operator override (forced)")
                    }
                    Some(_) => {
                        // Forced provider exists but is not UP — fall back
                        // automatically and log once.
                        let fallback = ps
                            .values()
                            .filter(|p| p.state == State::Up)
                            .min_by_key(|p| p.cfg.priority)
                            .map(|p| p.cfg.clone());
                        (fallback, "forced provider unavailable, auto fallback")
                    }
                    None => {
                        // Shouldn't happen — force_provider validates.
                        let fallback = ps
                            .values()
                            .filter(|p| p.state == State::Up)
                            .min_by_key(|p| p.cfg.priority)
                            .map(|p| p.cfg.clone());
                        (fallback, "forced provider not found")
                    }
                }
            } else {
                let best = ps
                    .values()
                    .filter(|p| p.state == State::Up)
                    .min_by_key(|p| p.cfg.priority)
                    .map(|p| p.cfg.clone());
                (best, "priority selection")
            }
        };

        let mut active_guard = self.active.write().await;
        let current: Option<String> = (*active_guard).clone();
        match (current, best) {
            (Some(cur), Some(best)) if cur == best.name => {
                if always_install {
                    // Operator-initiated: re-assert the route in case an
                    // external tool overwrote it.
                    self.router
                        .set_default_route(best.gateway, &best.interface)
                        .await?;
                    self.router.flush_conntrack().await;
                    info!(
                        provider = %best.name,
                        "{}: re-asserted default route (operator request)",
                        "FORCE".bright_magenta().bold()
                    );
                }
                Ok(())
            }

            (prev, Some(best)) => {
                let reason = match &prev {
                    None => format!("{reason_prefix}: initial selection"),
                    Some(p) => format!("{reason_prefix}: replacing '{p}'"),
                };

                self.router
                    .set_default_route(best.gateway, &best.interface)
                    .await?;
                self.router.flush_conntrack().await;

                let _ = self.stats.record_failover(&FailoverRecord {
                    timestamp: Utc::now(),
                    from_provider: prev.clone(),
                    to_provider: best.name.clone(),
                    reason: reason.clone(),
                });

                *active_guard = Some(best.name.clone());
                drop(active_guard);

                let arrow = "→".bright_cyan().bold();
                let from_label = prev.as_deref().unwrap_or("(none)");
                info!(
                    "{} {} {} {}  ·  {}",
                    "FAILOVER".bright_magenta().bold(),
                    from_label.bright_yellow(),
                    arrow,
                    best.name.bright_green().bold(),
                    reason.dimmed()
                );
                Ok(())
            }

            (Some(cur), None) => {
                error!(
                    provider = %cur,
                    "no healthy providers — keeping previously installed route (traffic may black-hole)"
                );
                Ok(())
            }

            (None, None) => {
                warn!("no healthy providers yet — waiting for first successful probes");
                Ok(())
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
