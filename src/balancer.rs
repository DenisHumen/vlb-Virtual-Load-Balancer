use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::config::{Config, Provider};
use crate::control;
use crate::health::{check_gateway, check_internet_via};
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

    pub fn as_label(self) -> &'static str { self.as_str() }

    fn colored(self) -> String {
        match self {
            State::Up => format!("{} {}", "●".bright_green().bold(), "UP".bright_green().bold()),
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

        // Snapshot the provider's immutable runtime parameters — they come
        // from config and never change after startup, so we can cache them
        // outside the lock.
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

            // (1) Next-hop reachability — a dead ISP router, a dead cable,
            //     or a power outage upstream of us all show up here first.
            //     No fwmark: gateway is directly connected, main-table's
            //     interface route resolves it regardless of active default.
            let gw_probe = check_gateway(provider_cfg.gateway, timeout).await;
            let _ = self.stats.record_health(&HealthRecord {
                provider: name.clone(),
                timestamp: Utc::now(),
                success: gw_probe.is_success(),
                latency_ms: gw_probe.latency_ms(),
                kind: "gateway",
            });

            // (2) End-to-end internet check for THIS provider, regardless of
            //     whether it's currently active. The fwmark forces the ping
            //     through the provider's dedicated routing table, so we
            //     catch "gateway answers but uplink is dead" for every
            //     provider independently — that's the key requirement.
            //
            //     Skipped when the gateway probe already failed, since the
            //     internet path cannot possibly be better than the next hop.
            let net_probe_opt = if gw_probe.is_success() {
                let probe = check_internet_via(
                    &self.cfg.health.probe_targets,
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

            let overall_ok = gw_probe.is_success()
                && net_probe_opt.as_ref().map(|p| p.is_success()).unwrap_or(false);

            // Prefer the internet-probe latency for display — it reflects
            // the real user-facing latency through the provider, not just
            // the last LAN hop.
            let latency = net_probe_opt
                .and_then(|p| p.latency_ms())
                .or_else(|| gw_probe.latency_ms());

            if !overall_ok && gw_probe.is_success() {
                warn!(
                    provider = %name,
                    "gateway reachable but internet probe failed — provider marked as unhealthy"
                );
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
            info!("provider {} is now {}", name.bright_white().bold(), new.colored());
            let _ = self.stats.record_state_change(name, new.as_str());
        }
    }

    /// Pick the best provider (forced if set and healthy; else highest-
    /// priority UP) and ensure the kernel default route points at it. No-op
    /// when the best candidate is already active.
    async fn reconcile_active(self: &Arc<Self>) -> Result<()> {
        let forced = self.force_override.read().await.clone();

        let (best, reason_prefix): (Option<Provider>, &'static str) = {
            let ps = self.providers.read().await;
            if let Some(ref forced_name) = forced {
                match ps.get(forced_name) {
                    Some(entry) if entry.state == State::Up => {
                        (Some(entry.cfg.clone()), "operator override")
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
            (Some(cur), Some(best)) if cur == best.name => Ok(()),

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
                State::Unknown => (
                    "●".bright_yellow().bold(),
                    "UNKNOWN".bright_yellow().bold(),
                ),
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

        ControlSnapshot { active, forced, providers }
    }

    pub async fn force_provider(self: &Arc<Self>, name: &str) -> Result<()> {
        {
            let ps = self.providers.read().await;
            if !ps.contains_key(name) {
                return Err(anyhow!("unknown provider '{name}'"));
            }
        }
        {
            let mut f = self.force_override.write().await;
            *f = Some(name.to_string());
        }
        info!(provider = %name, "operator override installed");
        if let Err(e) = self.reconcile_active().await {
            warn!(error = %e, "failed to reconcile after force");
        }
        Ok(())
    }

    pub async fn clear_force(self: &Arc<Self>) {
        {
            let mut f = self.force_override.write().await;
            *f = None;
        }
        info!("operator override cleared");
        if let Err(e) = self.reconcile_active().await {
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

        // Seed `prev` on the first tick; we emit deltas only after that.
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

            let now = Utc::now();
            for p in &self.cfg.providers {
                let Some(curr) = snap.get(&p.interface).copied() else {
                    continue;
                };
                if let Some(prev_c) = prev.get(&p.interface).copied() {
                    if let Some(d) = traffic::delta(prev_c, curr) {
                        let secs = interval.as_secs_f64();
                        if let Err(e) = self.stats.record_traffic(
                            &p.name,
                            &p.interface,
                            now,
                            secs,
                            &d,
                        ) {
                            warn!(error = %e, "traffic: failed to persist sample");
                        }
                    } else {
                        debug!(
                            iface = %p.interface,
                            "traffic: counter reset detected, skipping sample"
                        );
                    }
                }
                prev.insert(p.interface.clone(), curr);
            }

            // Prune at most once per hour.
            if retention > 0
                && (now - last_prune).num_seconds() > 3600
            {
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
