use anyhow::Result;
use chrono::{DateTime, Utc};
use colored::Colorize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::config::{Config, Provider};
use crate::health::{check_gateway, check_internet_via};
use crate::router::Router;
use crate::stats::{FailoverRecord, HealthRecord, Stats};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    handles: StdMutex<Vec<JoinHandle<()>>>,
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
            handles: StdMutex::new(Vec::new()),
        }))
    }

    pub fn spawn_tasks(self: &Arc<Self>) {
        let provider_names: Vec<String> =
            self.cfg.providers.iter().map(|p| p.name.clone()).collect();
        for name in provider_names {
            let me = Arc::clone(self);
            let handle = tokio::spawn(async move { me.health_loop(name).await });
            self.handles.lock().unwrap().push(handle);
        }

        let me = Arc::clone(self);
        let handle = tokio::spawn(async move { me.status_loop().await });
        self.handles.lock().unwrap().push(handle);
    }

    async fn health_loop(self: Arc<Self>, name: String) {
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
            ticker.tick().await;

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

    /// Pick the highest-priority UP provider and ensure the kernel default
    /// route points at it. No-op when the best candidate is already active.
    async fn reconcile_active(self: &Arc<Self>) -> Result<()> {
        let best: Option<Provider> = {
            let ps = self.providers.read().await;
            ps.values()
                .filter(|p| p.state == State::Up)
                .min_by_key(|p| p.cfg.priority)
                .map(|p| p.cfg.clone())
        };

        let mut active_guard = self.active.write().await;
        let current: Option<String> = (*active_guard).clone();
        match (current, best) {
            (Some(cur), Some(best)) if cur == best.name => Ok(()),

            (prev, Some(best)) => {
                let reason = match &prev {
                    None => "initial selection".to_string(),
                    Some(p) => format!("'{p}' down or outranked by higher-priority provider"),
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

    async fn status_loop(self: Arc<Self>) {
        // Short warm-up so the first snapshot shows real probe results.
        tokio::time::sleep(Duration::from_secs(
            self.cfg.health.interval_secs + self.cfg.health.success_threshold as u64,
        ))
        .await;

        let interval = Duration::from_secs(self.cfg.health.status_print_secs.max(5));
        loop {
            self.print_status().await;
            tokio::time::sleep(interval).await;
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
        for h in handles {
            h.abort();
        }
        info!("{}", "balancer stopped".bright_white().bold());
    }
}
