use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::sync::watch;

// Source layout (kept flat at the crate root via `#[path]` so every
// `use crate::xxx::Item` keeps working without churn):
//
//   core/  — orchestration core (balancer state machine, config schema)
//   net/   — kernel-facing networking (router, system bring-up, probes,
//            /proc/net/dev sampling)
//   obs/   — observability (tracing init, SQLite stats, host metrics)
//   ui/    — operator-facing surfaces (TUI, control protocol)
#[path = "core/balancer.rs"]
mod balancer;
#[path = "core/config.rs"]
mod config;
#[path = "core/selection.rs"]
mod selection;
#[path = "core/update.rs"]
mod update;

#[path = "net/canary.rs"]
mod canary;
#[path = "net/health.rs"]
mod health;
#[path = "net/http.rs"]
mod http;
#[path = "net/router.rs"]
mod router;
#[path = "net/system.rs"]
mod system;
#[path = "net/traffic.rs"]
mod traffic;

#[path = "obs/logger.rs"]
mod logger;
#[path = "obs/stats.rs"]
mod stats;
#[path = "obs/sysmon.rs"]
mod sysmon;

#[path = "ui/control.rs"]
mod control;
#[path = "ui/tui.rs"]
mod tui;

use crate::balancer::Balancer;
use crate::config::Config;
use crate::control::{Request, Response};

#[derive(Parser, Debug)]
#[command(
    name = "vlb",
    version,
    about = "Virtual Load Balancer — multi-provider failover gateway",
    long_about = None,
)]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "vlb.toml", global = true)]
    config: PathBuf,

    /// Do not modify system state (sysctl, iptables, ip route). Useful for dry-runs.
    #[arg(long, global = true)]
    dry_run: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Run the balancer (default).
    Run,
    /// Parse and validate the config file, then exit.
    Check,
    /// Print aggregated statistics from the SQLite database and exit.
    Stats {
        /// Window size in hours for the rolling summary.
        #[arg(long, default_value_t = 24)]
        hours: u32,
        /// Maximum number of recent failover events to show.
        #[arg(long, default_value_t = 10)]
        recent: u32,
    },
    /// Interactive terminal dashboard. Connects to the running daemon's
    /// control port (taken from the config file) to display live status,
    /// rx/tx graphs per provider, and to force-select a provider.
    Tui,
    /// Query the running daemon for a JSON status snapshot.
    Status,
    /// Pin the active provider (override). The daemon will keep this
    /// provider active for as long as it stays healthy.
    Force {
        /// Provider name to force.
        provider: String,
    },
    /// Release an operator pin and return to automatic selection.
    Auto,
    /// Query the running daemon for recent host metrics (CPU/RAM/load/etc).
    System {
        /// How many recent samples to fetch (clamped to 10_000).
        #[arg(long, default_value_t = 60)]
        limit: u32,
    },
    /// Diagnostic dump: configured interfaces vs /proc/net/dev, DB row
    /// counts per provider. Use this when the TUI shows "samples: 0" to
    /// tell whether the daemon is sampling, whether counters are moving,
    /// and whether the DB contains anything.
    Diag,
    /// Run every health layer once against each provider and print a timed
    /// report, without touching the routing table.
    ///
    /// Use this to size the timeouts for your links: it shows how long the
    /// gateway ping, the internet probe, DNS and each canary fetch actually
    /// take through each uplink, so `canary.timeout_ms` can be set from
    /// measurements rather than guesswork. Safe to run against a live
    /// daemon — it only reads.
    Probe {
        /// Probe a single provider instead of all of them.
        #[arg(long)]
        provider: Option<String>,
        /// Repeat this many times and report the slowest run, which is the
        /// number a timeout has to accommodate.
        #[arg(long, default_value_t = 1)]
        repeat: u32,
    },
    /// Check for a newer release on GitHub and install it.
    Update {
        /// Only report what is available; change nothing.
        #[arg(long)]
        check: bool,
        /// Consider pre-releases (alpha / beta / rc).
        #[arg(long)]
        pre: bool,
        /// Do not ask for confirmation.
        #[arg(short, long)]
        yes: bool,
        /// Install even when the published release is not newer than the
        /// running binary. Needed to roll back.
        #[arg(long)]
        force: bool,
    },
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    logger::init();

    let command = cli.command.as_ref().cloned().unwrap_or(Command::Run);
    match command {
        Command::Check => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            println!("{}", config.summary());
            println!("configuration OK");
            Ok(())
        }
        Command::Stats { hours, recent } => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            let stats = stats::Stats::open(&config.database.path, &config.providers)?;
            let report = stats.report(hours, recent)?;
            println!("{report}");
            Ok(())
        }
        Command::Tui => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            tui::run(config).await
        }
        Command::Status => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            let resp = control::send(&config.control.listen, &Request::Status).await?;
            print_response(&resp);
            Ok(())
        }
        Command::Force { provider } => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            let resp = control::send(&config.control.listen, &Request::Force { provider }).await?;
            print_response(&resp);
            Ok(())
        }
        Command::Auto => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            let resp = control::send(&config.control.listen, &Request::Auto).await?;
            print_response(&resp);
            Ok(())
        }
        Command::System { limit } => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            let resp = control::send(&config.control.listen, &Request::System { limit }).await?;
            print_response(&resp);
            Ok(())
        }
        Command::Diag => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            diag(&config).await
        }
        Command::Probe { provider, repeat } => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            probe_report(&config, provider.as_deref(), repeat.max(1)).await
        }
        Command::Update {
            check,
            pre,
            yes,
            force,
        } => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            do_update(&config, check, pre, yes, force).await
        }
        Command::Run => run(cli).await,
    }
}

fn print_response(resp: &Response) {
    match serde_json::to_string_pretty(resp) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("{resp:?}"),
    }
}

async fn run(cli: Cli) -> Result<()> {
    logger::print_banner();

    let config = Config::load(&cli.config)?;
    config.validate()?;
    tracing::info!(
        path = %cli.config.display(),
        providers = config.providers.len(),
        "configuration loaded"
    );

    // `prepare` reports whether it had to install a provisional default
    // route, so the router knows whether the cleanup afterwards is removing
    // something we created or something the operator did.
    let installed_bootstrap = if !cli.dry_run {
        system::check_root()?;
        system::prepare(&config).await?
    } else {
        tracing::warn!("dry-run mode: system state will not be modified");
        false
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let balancer = Balancer::new(config, cli.dry_run, installed_bootstrap).await?;
    balancer.spawn_tasks(shutdown_rx);

    wait_for_shutdown().await;
    tracing::warn!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    balancer.shutdown().await;
    Ok(())
}

/// Wait for SIGINT or, on Unix, SIGTERM. Either triggers a graceful shutdown.
async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler; falling back to SIGINT only");
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// `vlb probe` — run every health layer once per provider and time it.
///
/// This exists to answer "what should my timeouts be?" with measurements
/// instead of guesses, and to let an operator see *why* a provider is
/// considered unhealthy without reading the journal. It mutates nothing:
/// no routes, no iptables, no database writes.
async fn probe_report(config: &Config, only: Option<&str>, repeat: u32) -> Result<()> {
    use std::time::Instant;

    let providers: Vec<&config::Provider> = match only {
        Some(name) => {
            let found: Vec<_> = config.providers.iter().filter(|p| p.name == name).collect();
            if found.is_empty() {
                anyhow::bail!(
                    "unknown provider {name:?}. Configured: {}",
                    config
                        .providers
                        .iter()
                        .map(|p| p.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            found
        }
        None => config.providers.iter().collect(),
    };

    let timeout = std::time::Duration::from_millis(config.health.timeout_ms);
    let canary_timeout = std::time::Duration::from_millis(config.canary.timeout_ms);
    let probe_targets: Vec<health::ProbeTarget> = config
        .health
        .probe_targets
        .iter()
        .map(|s| health::ProbeTarget::parse(s))
        .collect();
    let canary_targets = config.canary.targets_parsed()?;
    let quorum = config.canary.quorum_parsed()?;

    println!("== vlb probe ==");
    println!(
        "repeat={repeat}  health_timeout={}ms  canary_timeout={}ms  quorum={}",
        config.health.timeout_ms,
        config.canary.timeout_ms,
        quorum.as_str()
    );
    println!(
        "note: probes are fwmark-bound, so each provider is tested independently\n      \
         of which one currently owns the default route."
    );

    for p in providers {
        let mark = config.mark_for(p);
        println!(
            "\n── {} (priority {}, gw {}, dev {}, mark 0x{:x}) ──",
            p.name, p.priority, p.gateway, p.interface, mark
        );

        // Track the worst observed duration per layer: a timeout has to
        // cover the slow case, not the median.
        let mut worst: Vec<(String, u128, bool)> = Vec::new();
        let mut record = |label: String, ms: u128, ok: bool| match worst
            .iter_mut()
            .find(|(l, _, _)| *l == label)
        {
            Some(slot) => {
                slot.1 = slot.1.max(ms);
                slot.2 &= ok;
            }
            None => worst.push((label, ms, ok)),
        };

        for round in 1..=repeat {
            if repeat > 1 {
                println!("  · run {round}/{repeat}");
            }

            let t = Instant::now();
            let gw = health::check_gateway(p.gateway, timeout).await;
            record("gateway".into(), t.elapsed().as_millis(), gw.is_success());

            let t = Instant::now();
            let net = health::check_internet_via(
                &probe_targets,
                &config.health.dns_resolvers,
                timeout,
                mark,
            )
            .await;
            record("internet".into(), t.elapsed().as_millis(), net.is_success());

            if config.health.dns_check_enabled {
                let t = Instant::now();
                let dns = health::check_dns_via(
                    &config.health.dns_resolvers,
                    &config.health.dns_check_name,
                    timeout,
                    mark,
                )
                .await;
                record("dns".into(), t.elapsed().as_millis(), dns.is_success());
            }

            if config.health.dns_integrity_check {
                let t = Instant::now();
                let integ =
                    health::check_dns_integrity_via(&config.health.dns_resolvers, timeout, mark)
                        .await;
                record(
                    "dns-integrity".into(),
                    t.elapsed().as_millis(),
                    !integ.is_hijacked(),
                );
                if let health::DnsIntegrity::Hijacked { detail } = &integ {
                    println!("    DNS HIJACK: {detail}");
                }
            }

            if config.canary.enabled && !canary_targets.is_empty() {
                let resolvers = config.health.dns_resolvers.clone();
                let resolver = move |host: String| {
                    let resolvers = resolvers.clone();
                    async move { health::resolve_a_via(&resolvers, &host, timeout, mark).await }
                };
                let t = Instant::now();
                let report = canary::check_canary_via(
                    &canary_targets,
                    canary_timeout,
                    Some(mark),
                    quorum,
                    &config.canary.user_agent,
                    resolver,
                )
                .await;
                record("canary".into(), t.elapsed().as_millis(), report.is_ok());
                for (label, verdict) in &report.per_target {
                    let mark_char = match verdict {
                        canary::CanaryVerdict::Ok { .. } => "ok  ",
                        canary::CanaryVerdict::Tampered { .. } => "TAMPERED",
                        canary::CanaryVerdict::Unreachable { .. } => "unreach",
                    };
                    let extra = verdict
                        .detail()
                        .map(|d| format!("  — {d}"))
                        .unwrap_or_default();
                    let lat = match verdict {
                        canary::CanaryVerdict::Ok { latency } => {
                            format!("{:>7.0} ms", latency.as_secs_f64() * 1000.0)
                        }
                        _ => "      -- ".to_string(),
                    };
                    println!("    {mark_char:>8}  {lat}  {label}{extra}");
                }
                println!("    canary verdict: {}", report.summary());
            }
        }

        println!("  slowest observed per layer:");
        for (label, ms, ok) in &worst {
            println!(
                "    {:<14} {:>7} ms   {}",
                label,
                ms,
                if *ok { "pass" } else { "FAIL" }
            );
        }
        if let Some((_, slowest, _)) = worst.iter().find(|(l, _, _)| l == "canary") {
            // Round up to the next 500 ms and add ~60% headroom, then clamp
            // to something that still fits inside a 10 s interval.
            let suggested =
                (((*slowest as f64 * 1.6) / 500.0).ceil() as u64 * 500).clamp(1000, 8000);
            println!(
                "  suggested canary.timeout_ms >= {suggested} (slowest run {slowest} ms + headroom)"
            );
        }
    }
    Ok(())
}

/// `vlb update` — check GitHub Releases and optionally install.
async fn do_update(
    config: &Config,
    check_only: bool,
    pre: bool,
    assume_yes: bool,
    force: bool,
) -> Result<()> {
    let allow_pre = pre || config.update.allow_prerelease;
    let current = update::current_version();
    println!("current version : {current}");
    println!("repository      : {}", config.update.repo);

    let release = update::check(&config.update.repo, allow_pre).await?;
    println!(
        "latest release  : {}{}",
        release.tag,
        if release.prerelease {
            " (pre-release)"
        } else {
            ""
        }
    );

    let newer = update::is_newer(&release.tag, current);
    if !newer {
        println!("\nAlready up to date.");
        if !force {
            return Ok(());
        }
        println!("--force given: installing {} anyway.", release.tag);
    }

    if check_only {
        if newer {
            println!("\nAn update is available. Install it with:\n    sudo vlb update");
        }
        return Ok(());
    }

    let dest =
        std::env::current_exe().context("cannot determine the path of the running binary")?;
    println!("install target  : {}", dest.display());

    if !assume_yes {
        // Replacing the binary of a live gateway briefly drops the daemon,
        // so never do it without an explicit yes.
        println!(
            "\nThis replaces the vlb binary{}.",
            if config.update.restart_service {
                format!(" and restarts the `{}` service", config.update.service_name)
            } else {
                String::new()
            }
        );
        print!("Proceed? [y/N] ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Aborted; nothing was changed.");
            return Ok(());
        }
    }

    update::install(&release, &dest).await?;

    if config.update.restart_service {
        let unit = &config.update.service_name;
        if update::service_is_active(unit).await {
            println!("restarting {unit} …");
            update::restart_service(unit).await?;
            println!("done — {unit} is running {}", release.tag);
        } else {
            println!(
                "note: the `{unit}` service is not active, so nothing was restarted. \
                 The new binary is installed and will be used on next start."
            );
        }
    } else {
        println!(
            "note: update.restart_service = false — restart vlb yourself to use the new binary."
        );
    }

    Ok(())
}

/// `vlb diag` — inspect the live sampling chain without touching the daemon.
///
/// Prints:
///   1. Configured provider interfaces and whether each appears in
///      `/proc/net/dev` (with current rx/tx byte counters).
///   2. Whether the daemon is reachable on the control port.
///   3. Row counts per provider in `traffic_samples` and `system_samples`
///      along with the most recent timestamp.
///
/// This is the first thing to run when the TUI shows `samples: 0`.
async fn diag(config: &Config) -> Result<()> {
    println!("== vlb diag ==");
    println!("config path used      : (loaded and validated)");
    println!("database path         : {}", config.database.path.display());
    println!("traffic enabled       : {}", config.traffic.enabled);
    println!("traffic interval_secs : {}", config.traffic.interval_secs);
    println!("control listen        : {}", config.control.listen);
    println!();

    // 1. /proc/net/dev snapshot for every interface we care about.
    println!("-- interfaces (/proc/net/dev) --");
    let snap = traffic::snapshot().await.unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    for p in &config.providers {
        if !seen.insert(p.interface.clone()) {
            continue;
        }
        match snap.get(&p.interface) {
            Some(c) => println!(
                "  {:<12} OK  rx_bytes={:>15}  tx_bytes={:>15}  rx_pkts={:>10}  tx_pkts={:>10}",
                p.interface, c.rx_bytes, c.tx_bytes, c.rx_packets, c.tx_packets
            ),
            None => println!(
                "  {:<12} MISSING — not found in /proc/net/dev (check `ip link`)",
                p.interface
            ),
        }
    }
    println!();

    // 2. control port reachability.
    println!("-- control port --");
    match control::send(&config.control.listen, &control::Request::Status).await {
        Ok(control::Response::Status { snapshot }) => {
            println!("  {} reachable — daemon is up", config.control.listen);
            println!(
                "  active provider     : {}",
                snapshot.active.as_deref().unwrap_or("(none)")
            );
            println!(
                "  operator override   : {}",
                snapshot.forced.as_deref().unwrap_or("(none)")
            );
            println!("  providers:");
            for p in &snapshot.providers {
                println!(
                    "    {:<16} state={:<8} latency={}",
                    p.name,
                    p.state.as_label(),
                    p.last_latency_ms
                        .map(|ms| format!("{ms:.1}ms"))
                        .unwrap_or_else(|| "—".into())
                );
            }
        }
        Ok(other) => println!("  unexpected response: {other:?}"),
        Err(e) => println!("  {} UNREACHABLE: {e}", config.control.listen),
    }
    println!();

    // 2b. Actual kernel default route(s). This is the ground truth for
    //     "did the force switch actually happen?".
    println!("-- kernel default route (ip route show default) --");
    #[cfg(unix)]
    {
        match tokio::process::Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .await
        {
            Ok(out) if out.status.success() => {
                let s = String::from_utf8_lossy(&out.stdout);
                if s.trim().is_empty() {
                    println!("  (no default route installed)");
                } else {
                    for line in s.lines() {
                        println!("  {line}");
                    }
                }
            }
            Ok(out) => println!(
                "  `ip route` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => println!("  `ip route` not runnable: {e}"),
        }
    }
    #[cfg(not(unix))]
    {
        println!("  (not a Unix host — skipping)");
    }
    println!();

    // 3. DB row counts. Opened read-only to avoid any accidental writes
    //    stepping on a running daemon.
    println!("-- database row counts --");
    match rusqlite::Connection::open_with_flags(
        &config.database.path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_URI
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Err(e) => println!("  cannot open DB: {e}"),
        Ok(conn) => {
            for p in &config.providers {
                let row: rusqlite::Result<(i64, Option<String>)> = conn.query_row(
                    "SELECT COUNT(*), MAX(ts) FROM traffic_samples WHERE provider = ?1",
                    rusqlite::params![p.name],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                );
                match row {
                    Ok((n, ts)) => println!(
                        "  traffic {:<14} rows={:>6}  last={}",
                        p.name,
                        n,
                        ts.unwrap_or_else(|| "—".into())
                    ),
                    Err(e) => println!("  traffic {:<14} query error: {e}", p.name),
                }
            }
            let sys_row: rusqlite::Result<(i64, Option<String>)> =
                conn.query_row("SELECT COUNT(*), MAX(ts) FROM system_samples", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                });
            match sys_row {
                Ok((n, ts)) => println!(
                    "  system                rows={:>6}  last={}",
                    n,
                    ts.unwrap_or_else(|| "—".into())
                ),
                Err(e) => println!("  system query error: {e}"),
            }
        }
    }
    Ok(())
}
