use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::sync::watch;

mod balancer;
mod config;
mod health;
mod logger;
mod router;
mod stats;
mod system;

use crate::balancer::Balancer;
use crate::config::Config;

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
        Command::Run => run(cli).await,
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
