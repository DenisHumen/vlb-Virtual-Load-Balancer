use colored::Colorize;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::EnvFilter;

pub fn init() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,vlb=debug,virtual_load_balancer=debug"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_ansi(true)
        .with_timer(ChronoLocal::new("%H:%M:%S%.3f".to_string()))
        .compact()
        .init();
}

pub fn print_banner() {
    let line = "═".repeat(58);
    println!("{}", format!("╔{line}╗").bright_cyan().bold());
    println!(
        "{}",
        "║           VIRTUAL LOAD BALANCER  ·  v0.1.0               ║"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "║       multi-provider failover gateway  ·  rust          ║"
            .bright_cyan()
            .bold()
    );
    println!("{}", format!("╚{line}╝").bright_cyan().bold());
    println!();
}
