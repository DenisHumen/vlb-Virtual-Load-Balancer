use colored::Colorize;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::time::ChronoLocal;

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
    let version = env!("CARGO_PKG_VERSION");
    let width = 58usize;
    let line = "═".repeat(width);
    let line1 = center_line(width, &format!("VIRTUAL LOAD BALANCER  ·  v{version}"));
    let line2 = center_line(width, "multi-provider failover gateway  ·  rust");

    println!("{}", format!("╔{line}╗").bright_cyan().bold());
    println!("{}", format!("║{line1}║").bright_cyan().bold());
    println!("{}", format!("║{line2}║").bright_cyan().bold());
    println!("{}", format!("╚{line}╝").bright_cyan().bold());
    println!();
}

fn center_line(width: usize, text: &str) -> String {
    let text_len = text.chars().count();
    if text_len >= width {
        return text.chars().take(width).collect();
    }
    let total_pad = width - text_len;
    let left = total_pad / 2;
    let right = total_pad - left;
    format!("{}{}{}", " ".repeat(left), text, " ".repeat(right))
}
