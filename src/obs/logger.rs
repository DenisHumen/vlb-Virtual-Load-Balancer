use colored::Colorize;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::time::ChronoLocal;

/// Initialise tracing. `RUST_LOG` wins when set; `default` applies otherwise.
///
/// The daemon and the one-shot subcommands want different defaults: `vlb
/// run` in a terminal is a debugging session and should be chatty, while
/// `vlb update` or `vlb probe` are read by an operator who wants the
/// command's own output, not the tracing stream interleaved with it.
pub fn init(default: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));

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
