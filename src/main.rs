use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::sync::watch;

mod balancer;
mod config;
mod control;
mod health;
mod logger;
mod router;
mod stats;
mod system;
mod sysmon;
mod traffic;
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
            tui::run(config.control.listen).await
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
            let resp = control::send(
                &config.control.listen,
                &Request::Force { provider },
            )
            .await?;
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
            let resp =
                control::send(&config.control.listen, &Request::System { limit }).await?;
            print_response(&resp);
            Ok(())
        }
        Command::Diag => {
            let config = Config::load(&cli.config)?;
            config.validate()?;
            diag(&config).await
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

    if !cli.dry_run {
        system::check_root()?;
        system::prepare(&config).await?;
    } else {
        tracing::warn!("dry-run mode: system state will not be modified");
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let balancer = Balancer::new(config, cli.dry_run).await?;
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
        use tokio::signal::unix::{signal, SignalKind};
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
        Ok(_) => println!("  {} reachable — daemon is up", config.control.listen),
        Err(e) => println!("  {} UNREACHABLE: {e}", config.control.listen),
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
            let sys_row: rusqlite::Result<(i64, Option<String>)> = conn.query_row(
                "SELECT COUNT(*), MAX(ts) FROM system_samples",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            );
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
