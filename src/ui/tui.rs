//! Interactive terminal dashboard — vlb's "btop on steroids".
//!
//! Layout (top → bottom):
//!   1. system panel: CPU/RAM/SWAP/DISK gauges, load averages, per-core
//!      grid, CPU history sparkline (btop-style)
//!   2. providers table
//!   3. traffic chart for selected provider (rx/tx bits per second)
//!   4. footer with keybind hints and ephemeral status messages
//!
//! Keys:
//!   ↑/↓ or j/k    — select provider
//!   f / Enter     — force-pin selected provider
//!   a             — release pin (auto)
//!   r             — refresh immediately
//!   q / Esc / ^C  — quit

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Axis, Block, Borders, Cell, Chart, Dataset, Gauge, GraphType, Paragraph, Row, Sparkline, Table,
};
use ratatui::Terminal;
use std::collections::HashMap;
use std::io::{self, Stdout};
use std::time::{Duration, Instant};

use crate::balancer::{ControlSnapshot, ProviderSnapshot, State};
use crate::control::{self, Request, Response, SystemPointWire, TrafficPointWire};

pub async fn run(listen: String) -> Result<()> {
    let initial = match control::send(&listen, &Request::Status).await {
        Ok(Response::Status { snapshot }) => snapshot,
        Ok(Response::Error { error }) => {
            return Err(anyhow::anyhow!("control error: {error}"));
        }
        Ok(_) => return Err(anyhow::anyhow!("unexpected response to status")),
        Err(e) => {
            return Err(e).context(format!(
                "could not connect to vlb at {listen} — is it running?"
            ));
        }
    };

    let mut terminal = setup_terminal()?;
    let result = run_app(&mut terminal, listen, initial).await;
    restore_terminal(&mut terminal)?;
    result
}

struct App {
    listen: String,
    snapshot: ControlSnapshot,
    selected: usize,
    traffic: HashMap<String, Vec<TrafficPointWire>>,
    system: Vec<SystemPointWire>,
    last_message: Option<(String, Instant)>,
    last_refresh: Instant,
    should_quit: bool,
}

impl App {
    fn new(listen: String, snapshot: ControlSnapshot) -> Self {
        Self {
            listen,
            snapshot,
            selected: 0,
            traffic: HashMap::new(),
            system: Vec::new(),
            last_message: None,
            last_refresh: Instant::now(),
            should_quit: false,
        }
    }

    fn selected_provider(&self) -> Option<&ProviderSnapshot> {
        self.snapshot.providers.get(self.selected)
    }

    fn set_message(&mut self, msg: impl Into<String>) {
        self.last_message = Some((msg.into(), Instant::now()));
    }

    async fn refresh(&mut self) {
        match control::send(&self.listen, &Request::Status).await {
            Ok(Response::Status { snapshot }) => {
                self.snapshot = snapshot;
                if self.selected >= self.snapshot.providers.len() {
                    self.selected = self.snapshot.providers.len().saturating_sub(1);
                }
            }
            Ok(Response::Error { error }) => self.set_message(format!("status error: {error}")),
            Ok(_) => self.set_message("unexpected response to status"),
            Err(e) => self.set_message(format!("refresh failed: {e}")),
        }

        for p in self.snapshot.providers.clone() {
            match control::send(
                &self.listen,
                &Request::Traffic {
                    provider: p.name.clone(),
                    limit: 180,
                },
            )
            .await
            {
                Ok(Response::Traffic { points }) => {
                    self.traffic.insert(p.name.clone(), points);
                }
                Ok(_) => {}
                Err(_) => {}
            }
        }

        match control::send(&self.listen, &Request::System { limit: 240 }).await {
            Ok(Response::System { points }) => self.system = points,
            Ok(_) => {}
            Err(_) => {}
        }
        self.last_refresh = Instant::now();
    }

    async fn force_selected(&mut self) {
        let Some(p) = self.selected_provider().cloned() else {
            return;
        };
        match control::send(
            &self.listen,
            &Request::Force {
                provider: p.name.clone(),
            },
        )
        .await
        {
            Ok(Response::Ok { message }) => self.set_message(message),
            Ok(Response::Error { error }) => self.set_message(format!("error: {error}")),
            Ok(_) => self.set_message("unexpected response"),
            Err(e) => self.set_message(format!("force failed: {e}")),
        }
    }

    async fn clear_force(&mut self) {
        match control::send(&self.listen, &Request::Auto).await {
            Ok(Response::Ok { message }) => self.set_message(message),
            Ok(Response::Error { error }) => self.set_message(format!("error: {error}")),
            Ok(_) => self.set_message("unexpected response"),
            Err(e) => self.set_message(format!("clear failed: {e}")),
        }
    }
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    listen: String,
    initial: ControlSnapshot,
) -> Result<()> {
    let mut app = App::new(listen, initial);
    app.refresh().await;

    let tick = Duration::from_millis(1500);

    loop {
        terminal.draw(|f| draw(f, &app))?;

        let remaining = tick.saturating_sub(app.last_refresh.elapsed());
        if event::poll(remaining.max(Duration::from_millis(50)))? {
            if let Event::Key(k) = event::read()? {
                handle_key(&mut app, k).await;
            }
        }

        if app.last_refresh.elapsed() >= tick {
            app.refresh().await;
        }

        if app.should_quit {
            break;
        }
    }
    Ok(())
}

async fn handle_key(app: &mut App, key: KeyEvent) {
    if key.kind == KeyEventKind::Release {
        return;
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }
        KeyCode::Char('j') | KeyCode::Down => {
            if !app.snapshot.providers.is_empty() {
                app.selected = (app.selected + 1) % app.snapshot.providers.len();
            }
        }
        KeyCode::Char('k') | KeyCode::Up => {
            if !app.snapshot.providers.is_empty() {
                if app.selected == 0 {
                    app.selected = app.snapshot.providers.len() - 1;
                } else {
                    app.selected -= 1;
                }
            }
        }
        KeyCode::Char('f') | KeyCode::Enter => {
            app.force_selected().await;
            app.refresh().await;
        }
        KeyCode::Char('a') => {
            app.clear_force().await;
            app.refresh().await;
        }
        KeyCode::Char('r') => {
            app.refresh().await;
            app.set_message("refreshed");
        }
        _ => {}
    }
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(9),
            Constraint::Length(3 + app.snapshot.providers.len() as u16),
            Constraint::Min(6),
            Constraint::Length(3),
        ])
        .split(f.area());

    draw_system(f, chunks[0], app);
    draw_providers(f, chunks[1], app);
    draw_traffic(f, chunks[2], app);
    draw_footer(f, chunks[3], app);
}

fn state_style(state: State) -> Style {
    match state {
        State::Up => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        State::Down => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        State::Unknown => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    }
}

/// Map a percent value (0..100) to btop's green → yellow → red palette.
fn level_color(pct: f64) -> Color {
    if pct < 50.0 {
        Color::Green
    } else if pct < 80.0 {
        Color::Yellow
    } else {
        Color::Red
    }
}

fn draw_system(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" system (btop-style) ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let latest = app.system.last().map(|p| &p.sample);

    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner);

    let gauges_area = halves[0];
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(gauges_area);

    let default_sample;
    let s = match latest {
        Some(s) => s,
        None => {
            default_sample = crate::sysmon::SysSample::default();
            &default_sample
        }
    };
    let cpu_pct = s.cpu_total.clamp(0.0, 100.0);
    let mem_pct = s.mem_pct();
    let swap_pct = s.swap_pct();
    let disk_pct = s.disk_pct();

    f.render_widget(
        Gauge::default()
            .gauge_style(
                Style::default()
                    .fg(level_color(cpu_pct as f64))
                    .bg(Color::Black),
            )
            .percent(cpu_pct as u16)
            .label(format!("CPU  {cpu_pct:5.1}%")),
        rows[0],
    );
    f.render_widget(
        Gauge::default()
            .gauge_style(
                Style::default()
                    .fg(level_color(mem_pct as f64))
                    .bg(Color::Black),
            )
            .percent(mem_pct as u16)
            .label(format!(
                "RAM  {:>9} / {:>9}  ({mem_pct:5.1}%)",
                fmt_bytes(s.mem_used),
                fmt_bytes(s.mem_total)
            )),
        rows[1],
    );
    f.render_widget(
        Gauge::default()
            .gauge_style(
                Style::default()
                    .fg(level_color(swap_pct as f64))
                    .bg(Color::Black),
            )
            .percent(swap_pct as u16)
            .label(format!(
                "SWAP {:>9} / {:>9}  ({swap_pct:5.1}%)",
                fmt_bytes(s.swap_used),
                fmt_bytes(s.swap_total)
            )),
        rows[2],
    );
    f.render_widget(
        Gauge::default()
            .gauge_style(
                Style::default()
                    .fg(level_color(disk_pct as f64))
                    .bg(Color::Black),
            )
            .percent(disk_pct as u16)
            .label(format!(
                "DISK {:>9} / {:>9}  ({disk_pct:5.1}%)",
                fmt_bytes(s.disk_used),
                fmt_bytes(s.disk_total)
            )),
        rows[3],
    );

    let footer_line = Paragraph::new(Line::from(vec![
        Span::styled("load ", Style::default().fg(Color::Gray)),
        Span::styled(
            format!("{:.2}", s.load1),
            Style::default()
                .fg(level_color(s.load1 * 25.0))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(format!("{:.2}", s.load5), Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        Span::styled(format!("{:.2}", s.load15), Style::default().fg(Color::Cyan)),
        Span::raw("   "),
        Span::styled(
            format!("up {}", fmt_duration(s.uptime_s)),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("   "),
        Span::styled(
            format!("procs {}", s.procs),
            Style::default().fg(Color::DarkGray),
        ),
        Span::raw("   "),
        Span::styled(
            format!(
                "net ↓{} ↑{}",
                fmt_bytes(s.net_rx_bytes),
                fmt_bytes(s.net_tx_bytes)
            ),
            Style::default().fg(Color::Magenta),
        ),
    ]));
    f.render_widget(footer_line, rows[4]);

    let right = halves[1];
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(right);

    draw_per_core_grid(f, split[0], &s.cpu_per_core);
    draw_cpu_history(f, split[1], app);
}

fn draw_per_core_grid(f: &mut ratatui::Frame, area: Rect, cores: &[f32]) {
    if cores.is_empty() || area.height == 0 || area.width < 8 {
        let p = Paragraph::new(Line::from(Span::styled(
            "(no per-core data)",
            Style::default().fg(Color::DarkGray),
        )));
        f.render_widget(p, area);
        return;
    }

    let cell_w: u16 = 14;
    let cols = (area.width / cell_w).max(1) as usize;
    let rows_needed = cores.len().div_ceil(cols);
    let rows_n = rows_needed.min(area.height as usize).max(1);

    let row_constraints: Vec<Constraint> = (0..rows_n).map(|_| Constraint::Length(1)).collect();
    let row_rects = Layout::default()
        .direction(Direction::Vertical)
        .constraints(row_constraints)
        .split(area);

    for (row_idx, row_rect) in row_rects.iter().enumerate() {
        let col_constraints: Vec<Constraint> =
            (0..cols).map(|_| Constraint::Length(cell_w)).collect();
        let cells = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(col_constraints)
            .split(*row_rect);
        for (col_idx, cell_rect) in cells.iter().enumerate() {
            let idx = row_idx * cols + col_idx;
            if idx >= cores.len() {
                break;
            }
            let pct = cores[idx].clamp(0.0, 100.0);
            let g = Gauge::default()
                .percent(pct as u16)
                .gauge_style(
                    Style::default()
                        .fg(level_color(pct as f64))
                        .bg(Color::Black),
                )
                .label(format!("c{idx:<2}{pct:>4.0}%"));
            f.render_widget(g, *cell_rect);
        }
    }
}

fn draw_cpu_history(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let data: Vec<u64> = app
        .system
        .iter()
        .map(|p| p.sample.cpu_total.clamp(0.0, 100.0) as u64)
        .collect();
    let spark = Sparkline::default()
        .block(
            Block::default()
                .borders(Borders::TOP)
                .title(" cpu history "),
        )
        .max(100)
        .style(Style::default().fg(Color::Cyan))
        .data(&data);
    f.render_widget(spark, area);
}

fn draw_providers(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let header = Row::new(vec![
        Cell::from(""),
        Cell::from("name"),
        Cell::from("prio"),
        Cell::from("state"),
        Cell::from("gateway"),
        Cell::from("iface"),
        Cell::from("latency"),
        Cell::from("last check"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let active = app.snapshot.active.clone();
    let forced = app.snapshot.forced.clone();

    let rows: Vec<Row> = app
        .snapshot
        .providers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut marker = String::new();
            if Some(&p.name) == active.as_ref() {
                marker.push('★');
            }
            if Some(&p.name) == forced.as_ref() {
                marker.push('📌');
            }
            let state_cell =
                Cell::from(p.state.as_label().to_uppercase()).style(state_style(p.state));
            let latency = p
                .last_latency_ms
                .map(|l| format!("{l:.2} ms"))
                .unwrap_or_else(|| "--".into());
            let last = p
                .last_check
                .map(|t| t.format("%H:%M:%S").to_string())
                .unwrap_or_else(|| "--:--:--".into());
            let mut row = Row::new(vec![
                Cell::from(marker),
                Cell::from(p.name.clone()),
                Cell::from(p.priority.to_string()),
                state_cell,
                Cell::from(p.gateway.clone()),
                Cell::from(p.interface.clone()),
                Cell::from(latency),
                Cell::from(last),
            ]);
            if i == app.selected {
                row = row.style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                );
            }
            row
        })
        .collect();

    let widths = [
        Constraint::Length(3),
        Constraint::Length(16),
        Constraint::Length(5),
        Constraint::Length(8),
        Constraint::Length(16),
        Constraint::Length(10),
        Constraint::Length(12),
        Constraint::Length(10),
    ];
    let title = match &app.snapshot.active {
        Some(a) => format!(" vlb — active: {a} "),
        None => " vlb — no active provider ".into(),
    };
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(table, area);
}

fn draw_traffic(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let Some(selected) = app.selected_provider() else {
        return;
    };
    let points = app.traffic.get(&selected.name).cloned().unwrap_or_default();

    let rx: Vec<(f64, f64)> = points
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let bps = if p.interval_s > 0.0 {
                (p.rx_bytes as f64 * 8.0) / p.interval_s
            } else {
                0.0
            };
            (i as f64, bps)
        })
        .collect();
    let tx: Vec<(f64, f64)> = points
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let bps = if p.interval_s > 0.0 {
                (p.tx_bytes as f64 * 8.0) / p.interval_s
            } else {
                0.0
            };
            (i as f64, bps)
        })
        .collect();

    let max_y = rx
        .iter()
        .chain(tx.iter())
        .map(|&(_, y)| y)
        .fold(1.0_f64, f64::max);
    let x_len = points.len().max(1) as f64 - 1.0;

    let rx_total: u64 = points.iter().map(|p| p.rx_bytes).sum();
    let tx_total: u64 = points.iter().map(|p| p.tx_bytes).sum();
    let rx_pkts: u64 = points.iter().map(|p| p.rx_packets).sum();
    let tx_pkts: u64 = points.iter().map(|p| p.tx_packets).sum();

    let datasets = vec![
        Dataset::default()
            .name("rx")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Cyan))
            .data(&rx),
        Dataset::default()
            .name("tx")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Magenta))
            .data(&tx),
    ];

    let title = format!(
        " {} — rx {} ({} pkts)  ·  tx {} ({} pkts)  ·  samples: {} ",
        selected.name,
        fmt_bytes(rx_total),
        fmt_count(rx_pkts),
        fmt_bytes(tx_total),
        fmt_count(tx_pkts),
        points.len()
    );

    let chart = Chart::new(datasets)
        .block(Block::default().borders(Borders::ALL).title(title))
        .x_axis(
            Axis::default()
                .bounds([0.0, x_len.max(1.0)])
                .style(Style::default().fg(Color::DarkGray)),
        )
        .y_axis(
            Axis::default()
                .bounds([0.0, max_y * 1.15])
                .labels(vec![
                    Span::from("0".to_string()),
                    Span::from(fmt_rate(max_y * 0.5)),
                    Span::from(fmt_rate(max_y * 1.15)),
                ])
                .style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(chart, area);
}

fn draw_footer(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let keys = Line::from(vec![
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(" select  "),
        Span::styled("f", Style::default().fg(Color::Yellow)),
        Span::raw(" force  "),
        Span::styled("a", Style::default().fg(Color::Yellow)),
        Span::raw(" auto  "),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw(" refresh  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);
    let msg = app
        .last_message
        .as_ref()
        .filter(|(_, t)| t.elapsed() < Duration::from_secs(5))
        .map(|(m, _)| m.clone())
        .unwrap_or_default();
    let text = vec![keys, Line::from(msg)];
    let p = Paragraph::new(text).block(Block::default().borders(Borders::ALL));
    f.render_widget(p, area);
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}

fn fmt_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0usize;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} {}", UNITS[u])
    } else {
        format!("{v:.2} {}", UNITS[u])
    }
}

fn fmt_rate(bps: f64) -> String {
    const UNITS: &[&str] = &["bit/s", "Kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"];
    let mut v = bps;
    let mut u = 0usize;
    while v >= 1000.0 && u < UNITS.len() - 1 {
        v /= 1000.0;
        u += 1;
    }
    format!("{v:.1} {}", UNITS[u])
}

fn fmt_count(n: u64) -> String {
    if n < 1_000 {
        format!("{n}")
    } else if n < 1_000_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else if n < 1_000_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else {
        format!("{:.2}G", n as f64 / 1_000_000_000.0)
    }
}

fn fmt_duration(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h{minutes:02}m")
    } else if hours > 0 {
        format!("{hours}h{minutes:02}m")
    } else {
        format!("{minutes}m")
    }
}
