use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tokio::signal;

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
    #[arg(short, long, default_value = "vlb.toml")]
    config: PathBuf,

    /// Do not modify system state (sysctl, iptables, ip route). Useful for dry-runs.
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    logger::init();
    logger::print_banner();

    let config = Config::load(&cli.config)?;
    config.validate()?;
    tracing::info!(path = %cli.config.display(), providers = config.providers.len(), "configuration loaded");

    if !cli.dry_run {
        system::check_root()?;
        system::prepare(&config).await?;
    } else {
        tracing::warn!("dry-run mode: system state will not be modified");
    }

    let balancer = Balancer::new(config, cli.dry_run).await?;
    balancer.spawn_tasks();

    match signal::ctrl_c().await {
        Ok(_) => tracing::warn!("shutdown signal received"),
        Err(e) => tracing::error!(error = %e, "failed to listen for shutdown signal"),
    }

    balancer.shutdown().await;
    Ok(())
}
