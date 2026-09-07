//! Interactive terminal dashboard — vlb's "btop on steroids".
//!
//! Layout (top → bottom):
//!   1. gateway panel: active provider (and whether it is verified or merely
//!      adopted from the routing table), pin, failback countdown, the
//!      kernel's own default route, daemon version and uptime
//!   2. system panel: CPU/RAM/SWAP/DISK gauges, load averages, per-core
//!      grid, CPU history sparkline (btop-style)
//!   3. providers table
//!   4. recent failover events — what happened, when, and why
//!   5. traffic chart for selected provider (rx/tx bits per second)
//!   6. footer with keybind hints and ephemeral status messages
//!
//! Keys:
//!   ↑/↓ or j/k    — select provider
//!   f / Enter     — force-pin selected provider
//!   a             — release pin (auto)
//!   c             — LAN clients: who is connected, traffic, drops
//!   r             — refresh immediately
//!   u             — check for a new release and install it
//!   q / Esc / ^C  — quit
//!
//! On the client screens ↑/↓ moves between hosts, Enter opens one host's
//! full history, `w` cycles the reporting window and Esc goes back.

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Axis, Block, Borders, Cell, Chart, Dataset, Gauge, GraphType, Paragraph, Row, Sparkline, Table,
};
use std::collections::HashMap;
use std::io::{self, Stdout};
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

use crate::balancer::{ClientDetail, ClientInfo, ControlSnapshot, ProviderSnapshot, State};
use crate::config::Config;
use crate::control::{
    self, FailoverEventWire, Request, Response, SystemPointWire, TrafficPointWire,
};
// Formatting lives in one module so the dashboard, the CLI reports and the
// stats summary cannot drift apart on what a megabyte is.
use crate::format::{
    ago as fmt_ago, bytes as fmt_bytes, count as fmt_count, duration as fmt_duration,
    rate as fmt_rate, rate_from_bytes as fmt_rate_bytes,
};
use crate::update;

/// Which screen the dashboard is showing.
///
/// The client views are screens rather than overlays: they are tables the
/// operator navigates and reads, and squeezing them into a corner of the
/// provider dashboard would make both unreadable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Dashboard,
    Clients,
    ClientDetail,
}

/// Reporting windows the client views cycle through with `w`.
const WINDOWS: [(u32, &str); 4] = [(1, "1h"), (24, "24h"), (168, "7d"), (720, "30d")];

pub async fn run(config: Config, config_path: PathBuf) -> Result<()> {
    let listen = config.control.listen.clone();
    let initial = first_snapshot(&listen).await?;

    let mut terminal = setup_terminal()?;
    let result = run_app(&mut terminal, config, config_path, initial).await;
    restore_terminal(&mut terminal)?;
    result
}

/// Fetch the first snapshot, giving the daemon a moment if it is busy.
///
/// A daemon that has just started is doing a burst of work — bringing up
/// policy routing, meeting every host on the LAN — and a single attempt that
/// lands inside that window fails for a reason that is nobody's problem.
/// So retry, and separate the two outcomes that mean genuinely different
/// things: nothing listening (it is not running) versus listening but slow
/// to answer (it is running and busy). Reporting the second as the first is
/// what sends an operator looking in the wrong place.
async fn first_snapshot(listen: &str) -> Result<ControlSnapshot> {
    const ATTEMPTS: usize = 4;
    let mut last = String::new();

    for attempt in 1..=ATTEMPTS {
        match control::send(listen, &Request::Status).await {
            Ok(Response::Status { snapshot }) => return Ok(snapshot),
            Ok(Response::Error { error }) => {
                anyhow::bail!("the daemon at {listen} refused the request: {error}")
            }
            Ok(other) => anyhow::bail!("unexpected response to status: {other:?}"),
            Err(e) => {
                last = format!("{e}");
                if last.contains("refused") {
                    anyhow::bail!(
                        "nothing is listening on {listen} — the daemon is not running.\n\
                         Start it with:  sudo bash scripts/vlb.sh start"
                    );
                }
                if attempt < ATTEMPTS {
                    eprintln!(
                        "vlb has not answered yet ({attempt}/{ATTEMPTS}) — it may still be \
                         starting up; retrying…"
                    );
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    }

    anyhow::bail!(
        "vlb is listening on {listen} but did not answer after {ATTEMPTS} attempts \
         ({last}).\nIt is running, so look at what it is doing:\n    \
         sudo journalctl -u vlb -n 50\n    sudo tail -50 /var/log/vlb.log"
    )
}

/// Modal state for the self-update flow. The dashboard keeps running
/// underneath; the modal only gates the keys that would apply the update.
#[derive(Debug, Clone, PartialEq)]
enum UpdateState {
    Idle,
    /// Querying the GitHub API.
    Checking,
    /// A newer release exists and is waiting for a yes/no.
    Available {
        tag: String,
        prerelease: bool,
    },
    /// Already current — shown briefly, then dismissed.
    UpToDate {
        tag: String,
    },
    Installing {
        tag: String,
    },
    Done {
        message: String,
    },
    Failed {
        error: String,
    },
}

struct App {
    /// The clock the screen is drawn against.
    ///
    /// `None` means the real one. The fixtures that render the README
    /// pictures set it, because "up for 1d 1h16m" and "37m00s ago" are
    /// computed at draw time: without a seam here the same fixture produced
    /// slightly different bytes on every run, every asset was rewritten by
    /// every regeneration, and no diff could show whether a change had
    /// altered a picture.
    clock: Option<chrono::DateTime<chrono::Utc>>,
    /// The zone wall-clock times are shown in. `None` means this machine's.
    ///
    /// Fixed for the README pictures: the provider table prints the time of
    /// the last check in local time, so without this the same fixture
    /// rendered a different picture on a laptop in Kyiv and in a UTC
    /// container, and the committed asset could never match both.
    zone: Option<chrono::FixedOffset>,
    listen: String,
    config: Config,
    config_path: PathBuf,
    snapshot: ControlSnapshot,
    selected: usize,
    traffic: HashMap<String, Vec<TrafficPointWire>>,
    system: Vec<SystemPointWire>,
    events: Vec<FailoverEventWire>,
    view: View,
    clients: Vec<ClientInfo>,
    client_selected: usize,
    client_detail: Option<Box<ClientDetail>>,
    /// Index into [`WINDOWS`].
    window: usize,
    client_error: Option<String>,
    last_message: Option<(String, Instant)>,
    last_refresh: Instant,
    /// Consecutive refreshes that could not reach the daemon — during an
    /// update restart this is expected for a few seconds.
    unreachable_for: u32,
    update: UpdateState,
    /// The update runs in its own task so the dashboard keeps drawing and
    /// the progress lines below are visible while it works.
    update_task: Option<JoinHandle<Result<update::Outcome>>>,
    update_log: Arc<StdMutex<Vec<String>>>,
    should_quit: bool,
}

impl App {
    /// The clock this screen is drawn against.
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.clock.unwrap_or_else(chrono::Utc::now)
    }

    /// A date and time, in the zone this screen shows times in.
    fn stamp(&self, t: chrono::DateTime<chrono::Utc>) -> String {
        self.local(t).format("%m-%d %H:%M").to_string()
    }

    /// The same, to the second.
    fn stamp_secs(&self, t: chrono::DateTime<chrono::Utc>) -> String {
        self.local(t).format("%Y-%m-%d %H:%M:%S").to_string()
    }

    /// One instant, in the zone this screen shows times in.
    fn local<Tz: chrono::TimeZone>(
        &self,
        t: chrono::DateTime<Tz>,
    ) -> chrono::DateTime<chrono::FixedOffset> {
        match self.zone {
            Some(off) => t.with_timezone(&off),
            None => t.with_timezone(&chrono::Local).fixed_offset(),
        }
    }

    fn new(config: Config, config_path: PathBuf, snapshot: ControlSnapshot) -> Self {
        Self {
            clock: None,
            zone: None,
            listen: config.control.listen.clone(),
            config,
            config_path,
            snapshot,
            selected: 0,
            traffic: HashMap::new(),
            system: Vec::new(),
            events: Vec::new(),
            view: View::Dashboard,
            clients: Vec::new(),
            client_selected: 0,
            client_detail: None,
            window: 1, // 24h
            client_error: None,
            last_message: None,
            last_refresh: Instant::now(),
            unreachable_for: 0,
            update: UpdateState::Idle,
            update_task: None,
            update_log: Arc::new(StdMutex::new(Vec::new())),
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
                if self.unreachable_for > 0 {
                    self.set_message(format!(
                        "daemon is back (v{})",
                        if snapshot.version.is_empty() {
                            "?".to_string()
                        } else {
                            snapshot.version.clone()
                        }
                    ));
                }
                self.unreachable_for = 0;
                self.snapshot = snapshot;
                if self.selected >= self.snapshot.providers.len() {
                    self.selected = self.snapshot.providers.len().saturating_sub(1);
                }
            }
            Ok(Response::Error { error }) => self.set_message(format!("status error: {error}")),
            Ok(_) => self.set_message("unexpected response to status"),
            Err(e) => {
                self.unreachable_for = self.unreachable_for.saturating_add(1);
                self.set_message(format!(
                    "daemon unreachable ({}×): {e}",
                    self.unreachable_for
                ));
            }
        }

        // Only fetch what the current screen shows. The client views ask for
        // an aggregate the daemon computes from the database, and pulling
        // per-provider traffic graphs at the same time would double the work
        // for something nobody is looking at.
        if self.view != View::Dashboard {
            self.refresh_clients().await;
            self.last_refresh = Instant::now();
            return;
        }

        match control::send(&self.listen, &Request::Events { limit: 8 }).await {
            Ok(Response::Events { events }) => self.events = events,
            Ok(_) => {}
            Err(_) => {}
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

    /// The reporting window the client views are showing.
    fn window_hours(&self) -> u32 {
        WINDOWS[self.window.min(WINDOWS.len() - 1)].0
    }

    fn window_label(&self) -> &'static str {
        WINDOWS[self.window.min(WINDOWS.len() - 1)].1
    }

    fn selected_client(&self) -> Option<&ClientInfo> {
        self.clients.get(self.client_selected)
    }

    async fn refresh_clients(&mut self) {
        let hours = self.window_hours();
        match control::send(&self.listen, &Request::Clients { hours }).await {
            Ok(Response::Clients { clients }) => {
                self.client_error = None;
                self.clients = clients;
                if self.client_selected >= self.clients.len() {
                    self.client_selected = self.clients.len().saturating_sub(1);
                }
            }
            Ok(Response::Error { error }) => self.client_error = Some(error),
            Ok(_) => self.client_error = Some("unexpected response to `clients`".into()),
            Err(e) => self.client_error = Some(format!("{e}")),
        }

        if self.view == View::ClientDetail
            && let Some(ip) = self.selected_client().map(|c| c.ip.clone())
        {
            match control::send(
                &self.listen,
                &Request::ClientDetail {
                    ip,
                    hours,
                    limit: 600,
                },
            )
            .await
            {
                Ok(Response::ClientDetail { detail }) => {
                    self.client_detail = Some(detail);
                    self.client_error = None;
                }
                Ok(Response::Error { error }) => self.client_error = Some(error),
                Ok(_) => {}
                Err(e) => self.client_error = Some(format!("{e}")),
            }
        }
    }

    /// Is the daemon we are talking to older than this dashboard?
    ///
    /// Worth surfacing rather than leaving as an empty screen: updating from
    /// a git checkout rebuilds the binary but leaves the running daemon on
    /// the old one until it is restarted, and "the client list is empty" is a
    /// confusing way to find that out.
    fn daemon_is_older(&self) -> bool {
        let theirs = &self.snapshot.version;
        !theirs.is_empty() && update::is_newer(update::current_version(), theirs)
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

    /// Ask GitHub what the newest release is.
    async fn check_for_update(&mut self) {
        self.update = UpdateState::Checking;
        let allow_pre = self.config.update.allow_prerelease;
        match update::check(&self.config.update.repo, allow_pre).await {
            Ok(release) => {
                if update::is_newer(&release.tag, update::current_version()) {
                    self.update = UpdateState::Available {
                        tag: release.tag,
                        prerelease: release.prerelease,
                    };
                } else {
                    self.update = UpdateState::UpToDate { tag: release.tag };
                }
            }
            Err(e) => {
                self.update = UpdateState::Failed {
                    error: format!("{e:#}"),
                }
            }
        }
    }

    /// Download, verify and install the release the operator just confirmed.
    ///
    /// Deliberately re-queries the API rather than caching the asset URLs
    /// from the check: those URLs are what we are about to execute as root,
    /// and the gap between checking and confirming can be arbitrarily long.
    ///
    /// Runs as a background task: the whole flow — download, pre-flight
    /// probe, restart, waiting for the daemon to come back — takes a while,
    /// and the dashboard should show its progress rather than freeze.
    fn apply_update(&mut self) {
        let UpdateState::Available { tag, .. } = self.update.clone() else {
            return;
        };
        self.update = UpdateState::Installing { tag: tag.clone() };
        self.update_log.lock().unwrap().clear();

        let repo = self.config.update.repo.clone();
        let allow_pre = self.config.update.allow_prerelease;
        let plan = update::Plan {
            config_path: self.config_path.clone(),
            control_listen: self.listen.clone(),
            service: self.config.update.service_name.clone(),
            restart_service: self.config.update.restart_service,
            skip_preflight: false,
        };
        let log = Arc::clone(&self.update_log);

        self.update_task = Some(tokio::spawn(async move {
            let release = update::check(&repo, allow_pre).await?;
            let dest = std::env::current_exe().context("cannot locate the running binary")?;
            let mut progress = |line: String| {
                log.lock().unwrap().push(line);
            };
            update::perform(&release, &dest, &plan, &mut progress).await
        }));
    }

    /// Collect the result of a finished update task, if any.
    async fn poll_update_task(&mut self) {
        let finished = matches!(&self.update_task, Some(h) if h.is_finished());
        if !finished {
            return;
        }
        let Some(handle) = self.update_task.take() else {
            return;
        };
        self.update = match handle.await {
            Ok(Ok(outcome)) => UpdateState::Done {
                message: outcome.summary(),
            },
            Ok(Err(e)) => UpdateState::Failed {
                error: format!("{e:#}"),
            },
            Err(e) => UpdateState::Failed {
                error: format!("the update task panicked: {e}"),
            },
        };
    }

    fn dismiss_update(&mut self) {
        if self.update_task.is_some() {
            // Never abandon a half-done install by dismissing its modal.
            return;
        }
        self.update = UpdateState::Idle;
    }

    /// Is a modal currently capturing y/n?
    fn update_modal_open(&self) -> bool {
        !matches!(self.update, UpdateState::Idle)
    }
}

async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    config: Config,
    config_path: PathBuf,
    initial: ControlSnapshot,
) -> Result<()> {
    let mut app = App::new(config, config_path, initial);
    app.refresh().await;

    let tick = Duration::from_millis(1500);

    loop {
        terminal.draw(|f| draw(f, &app))?;

        // Poll more often while an update is running so its progress lines
        // appear as they happen.
        let poll_for = if app.update_task.is_some() {
            Duration::from_millis(250)
        } else {
            tick.saturating_sub(app.last_refresh.elapsed())
        };
        if event::poll(poll_for.max(Duration::from_millis(50)))?
            && let Event::Key(k) = event::read()?
        {
            handle_key(&mut app, k).await;
        }

        app.poll_update_task().await;

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

    // While the update modal is open it owns the keyboard, so a stray `f`
    // cannot force a provider over while the operator is reading a prompt
    // about replacing the binary. Ctrl-C still quits.
    if app.update_modal_open() {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            app.should_quit = true;
            return;
        }
        match app.update.clone() {
            UpdateState::Available { .. } => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    app.apply_update();
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Char('q') => {
                    app.dismiss_update();
                }
                _ => {}
            },
            // Checking runs inline; Installing runs in its own task and
            // must not be dismissed halfway through.
            UpdateState::Checking | UpdateState::Installing { .. } => {}
            UpdateState::UpToDate { .. }
            | UpdateState::Done { .. }
            | UpdateState::Failed { .. } => {
                // Any key dismisses an informational result.
                app.dismiss_update();
            }
            UpdateState::Idle => {}
        }
        return;
    }

    // The client screens own the keyboard while they are up: there is
    // nothing on them that a provider hotkey would mean.
    if app.view != View::Dashboard {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.should_quit = true;
            }
            KeyCode::Char('q') => app.should_quit = true,
            KeyCode::Esc | KeyCode::Backspace | KeyCode::Left | KeyCode::Char('h') => {
                if app.view == View::ClientDetail {
                    app.view = View::Clients;
                    app.client_detail = None;
                } else {
                    app.view = View::Dashboard;
                }
            }
            KeyCode::Char('c') => {
                app.view = View::Dashboard;
                app.client_detail = None;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if !app.clients.is_empty() {
                    app.client_selected = (app.client_selected + 1) % app.clients.len();
                    if app.view == View::ClientDetail {
                        app.refresh_clients().await;
                    }
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if !app.clients.is_empty() {
                    app.client_selected = if app.client_selected == 0 {
                        app.clients.len() - 1
                    } else {
                        app.client_selected - 1
                    };
                    if app.view == View::ClientDetail {
                        app.refresh_clients().await;
                    }
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if app.view == View::Clients && !app.clients.is_empty() {
                    app.view = View::ClientDetail;
                    app.refresh_clients().await;
                }
            }
            KeyCode::Char('w') => {
                app.window = (app.window + 1) % WINDOWS.len();
                app.refresh_clients().await;
            }
            KeyCode::Char('r') => app.refresh_clients().await,
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }
        KeyCode::Char('c') => {
            app.view = View::Clients;
            app.refresh_clients().await;
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
        KeyCode::Char('u') => {
            app.check_for_update().await;
        }
        _ => {}
    }
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    match app.view {
        View::Dashboard => draw_dashboard(f, app),
        View::Clients => draw_clients(f, f.area(), app),
        View::ClientDetail => draw_client_detail(f, f.area(), app),
    }
    if app.update_modal_open() {
        draw_update_modal(f, f.area(), app);
    }
}

fn draw_dashboard(f: &mut ratatui::Frame, app: &App) {
    let events_h = 2 + (app.events.len().clamp(1, 5) as u16);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(9),
            Constraint::Length(3 + app.snapshot.providers.len() as u16),
            Constraint::Length(events_h),
            Constraint::Min(6),
            // Four rows, not three. The footer draws two lines — the keys
            // and, under them, whatever went wrong — and a bordered block
            // three rows tall has exactly one row inside it, so the second
            // line was never drawn at all. A fixed height rather than one
            // that follows the message: a footer that grows and shrinks
            // every few seconds drags the chart above it up and down.
            Constraint::Length(4),
        ])
        .split(f.area());

    draw_gateway(f, chunks[0], app);
    draw_system(f, chunks[1], app);
    draw_providers(f, chunks[2], app);
    draw_events(f, chunks[3], app);
    draw_traffic(f, chunks[4], app);
    draw_footer(f, chunks[5], app);
}

/// The one-glance panel: what is carrying traffic right now, whether that
/// is a verified choice or one inherited from the routing table at startup,
/// the pin, the failback countdown, and what the kernel itself says.
fn draw_gateway(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let s = &app.snapshot;
    let daemon_version = if s.version.is_empty() {
        "?".to_string()
    } else {
        s.version.clone()
    };
    let uptime = s
        .started_at
        .map(|t| {
            let secs = (app.now() - t).num_seconds().max(0) as u64;
            fmt_duration(secs)
        })
        .unwrap_or_else(|| "?".into());
    let title = format!(
        " gateway · daemon v{daemon_version} up {uptime} · tui v{} ",
        update::current_version()
    );

    let mut line1: Vec<Span> = vec![Span::styled("active ", Style::default().fg(Color::Gray))];
    match &s.active {
        Some(a) => {
            line1.push(Span::styled(
                a.clone(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ));
            if s.active_adopted {
                line1.push(Span::styled(
                    "  (adopted from the routing table — verifying)",
                    Style::default().fg(Color::Yellow),
                ));
            }
        }
        None => line1.push(Span::styled(
            "none yet",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
    }
    line1.push(Span::raw("   "));
    line1.push(Span::styled("pin ", Style::default().fg(Color::Gray)));
    match &s.forced {
        Some(p) => line1.push(Span::styled(
            format!("📌 {p}"),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )),
        None => line1.push(Span::styled("auto", Style::default().fg(Color::DarkGray))),
    }
    if let Some(fb) = &s.failback_pending {
        let left = fb.required_secs.saturating_sub(fb.stable_for_secs);
        line1.push(Span::raw("   "));
        line1.push(Span::styled(
            format!(
                "failback → {} in {}s ({}/{}s stable)",
                fb.candidate, left, fb.stable_for_secs, fb.required_secs
            ),
            Style::default().fg(Color::Cyan),
        ));
    }

    let line2 = Line::from(vec![
        Span::styled("kernel ", Style::default().fg(Color::Gray)),
        Span::styled(
            s.kernel_route
                .clone()
                .unwrap_or_else(|| "(no default route)".into()),
            Style::default().fg(Color::White),
        ),
    ]);

    let block = Block::default().borders(Borders::ALL).title(title);
    f.render_widget(
        Paragraph::new(vec![Line::from(line1), line2]).block(block),
        area,
    );
}

/// Recent failovers, newest first: the answer to "what happened last night".
fn draw_events(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" recent events ");
    let inner_w = area.width.saturating_sub(2) as usize;
    let lines: Vec<Line> = if app.events.is_empty() {
        vec![Line::from(Span::styled(
            "(no failover events recorded)",
            Style::default().fg(Color::DarkGray),
        ))]
    } else {
        app.events
            .iter()
            .take(5)
            .map(|e| {
                let when = chrono::DateTime::parse_from_rfc3339(&e.ts)
                    .map(|t| app.local(t).format("%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|_| e.ts.clone());
                let from = e.from.as_deref().unwrap_or("—");
                let head = format!("{when}  {from} → {}  ", e.to);
                let room = inner_w.saturating_sub(head.chars().count());
                Line::from(vec![
                    Span::styled(when.clone(), Style::default().fg(Color::DarkGray)),
                    Span::raw("  "),
                    Span::styled(from.to_string(), Style::default().fg(Color::Yellow)),
                    Span::raw(" → "),
                    Span::styled(
                        e.to.clone(),
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  "),
                    Span::styled(
                        truncate(&e.reason, room.max(8)),
                        Style::default().fg(Color::Gray),
                    ),
                ])
            })
            .collect()
    };
    f.render_widget(Paragraph::new(lines).block(block), area);
}

/// Cut a string to `max` characters, adding an ellipsis. Operates on chars,
/// not bytes, so a multi-byte character is never split.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// Centre a box of the given size inside `area`.
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

fn draw_update_modal(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let current = update::current_version();
    let (title, body, colour) = match &app.update {
        UpdateState::Idle => return,
        UpdateState::Checking => (
            " update ",
            vec![
                Line::from(format!("current: {current}")),
                Line::from(format!("repo:    {}", app.config.update.repo)),
                Line::from(""),
                Line::from("Querying GitHub for the latest release..."),
            ],
            Color::Cyan,
        ),
        UpdateState::Available { tag, prerelease } => (
            " update available ",
            vec![
                Line::from(format!("current: {current}")),
                Line::from(format!(
                    "latest:  {tag}{}",
                    if *prerelease { "  (pre-release)" } else { "" }
                )),
                Line::from(""),
                Line::from("The binary will be downloaded, its SHA-256 verified against the"),
                Line::from("published checksum, and checked as runnable before it replaces"),
                Line::from("the current one. The previous binary is kept as vlb.bak."),
                Line::from(if app.config.update.restart_service {
                    format!(
                        "The `{}` service will then be restarted - expect a brief blip.",
                        app.config.update.service_name
                    )
                } else {
                    "The service will NOT be restarted automatically.".to_string()
                }),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  y  ", Style::default().fg(Color::Black).bg(Color::Green)),
                    Span::raw(" install    "),
                    Span::styled("  n  ", Style::default().fg(Color::Black).bg(Color::Gray)),
                    Span::raw(" cancel"),
                ]),
            ],
            Color::Yellow,
        ),
        UpdateState::UpToDate { tag } => (
            " up to date ",
            vec![
                Line::from(format!("current: {current}")),
                Line::from(format!("latest:  {tag}")),
                Line::from(""),
                Line::from("Nothing to do. Press any key."),
            ],
            Color::Green,
        ),
        UpdateState::Installing { tag } => {
            let mut body = vec![Line::from(format!("Installing {tag}... do not interrupt."))];
            body.push(Line::from(""));
            let log = app.update_log.lock().unwrap();
            let start = log.len().saturating_sub(8);
            for line in log.iter().skip(start) {
                body.push(Line::from(vec![
                    Span::styled("  · ", Style::default().fg(Color::Cyan)),
                    Span::raw(truncate(line, 76)),
                ]));
            }
            if log.is_empty() {
                body.push(Line::from("  · querying GitHub..."));
            }
            (" installing ", body, Color::Cyan)
        }
        UpdateState::Done { message } => {
            let mut body: Vec<Line> = message
                .lines()
                .map(|l| Line::from(truncate(l, 78)))
                .collect();
            body.push(Line::from(""));
            body.push(Line::from("Press any key."));
            (" update complete ", body, Color::Green)
        }
        UpdateState::Failed { error } => {
            // The message says whether anything changed and whether a
            // rollback happened; do not assert either here.
            let mut body: Vec<Line> = Vec::new();
            for para in error.split('\n') {
                let mut rest = para;
                while !rest.is_empty() {
                    let take: String = rest.chars().take(78).collect();
                    body.push(Line::from(take.clone()));
                    rest = &rest[take.len()..];
                }
            }
            body.truncate(12);
            body.push(Line::from(""));
            body.push(Line::from("Press any key."));
            (" update failed ", body, Color::Red)
        }
    };

    let height = (body.len() as u16 + 4).min(area.height);
    let rect = centered_rect(84, height, area);
    // Clear what is underneath so the dashboard does not bleed through.
    f.render_widget(ratatui::widgets::Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .border_style(Style::default().fg(colour).add_modifier(Modifier::BOLD));
    f.render_widget(Paragraph::new(body).block(block), rect);
}

// ─────────────────────────────────────────────────────────────────────────
// Client screens
// ─────────────────────────────────────────────────────────────────────────

/// A dot that reads as "connected" at a glance, and a word for anyone whose
/// terminal or eyes do not do colour.
fn online_cell(online: bool) -> Cell<'static> {
    if online {
        Cell::from("●").style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Cell::from("·").style(Style::default().fg(Color::DarkGray))
    }
}

/// Trouble reaching the daemon, or the daemon not understanding the request.
///
/// The second case is the one worth explaining: updating from a git checkout
/// rebuilds the binary but leaves the *running* daemon on the previous one,
/// and an unexplained empty screen is a poor way to discover that.
fn client_error_lines(app: &App) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    if let Some(err) = &app.client_error {
        out.push(Line::from(vec![
            Span::styled(
                "cannot read clients: ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(truncate(err, 96)),
        ]));
        if err.contains("unknown variant") || err.contains("invalid request") {
            out.push(Line::from(Span::styled(
                "the running daemon is older than this dashboard — restart it to pick up \
                 the new build:  sudo systemctl restart vlb",
                Style::default().fg(Color::Yellow),
            )));
        }
    } else if app.daemon_is_older() {
        out.push(Line::from(Span::styled(
            format!(
                "the running daemon is v{} while this dashboard is v{} — restart it to pick \
                 up the new build",
                app.snapshot.version,
                update::current_version()
            ),
            Style::default().fg(Color::Yellow),
        )));
    }
    out
}

fn draw_clients(f: &mut ratatui::Frame, area: Rect, app: &App) {
    // ── summary ────────────────────────────────────────────────────────
    let online = app.clients.iter().filter(|c| c.online).count();
    let rx: i64 = app.clients.iter().map(|c| c.rx_bytes).sum();
    let tx: i64 = app.clients.iter().map(|c| c.tx_bytes).sum();
    let rx_now: f64 = app.clients.iter().map(|c| c.rx_bps).sum();
    let tx_now: f64 = app.clients.iter().map(|c| c.tx_bps).sum();
    let drops: i64 = app.clients.iter().map(|c| c.disconnects).sum();

    let mut header = vec![Line::from(vec![
        Span::styled(
            format!("{online}"),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" of {} hosts connected", app.clients.len()),
            Style::default().fg(Color::Gray),
        ),
        Span::raw("   "),
        Span::styled("now ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("↓ {}", fmt_rate_bytes(rx_now)),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("  "),
        Span::styled(
            format!("↑ {}", fmt_rate_bytes(tx_now)),
            Style::default().fg(Color::Magenta),
        ),
        Span::raw("   "),
        Span::styled(
            format!("total {} ", app.window_label()),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("↓ {}", fmt_bytes(rx.max(0) as u64)),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("  "),
        Span::styled(
            format!("↑ {}", fmt_bytes(tx.max(0) as u64)),
            Style::default().fg(Color::Magenta),
        ),
        Span::raw("   "),
        Span::styled(
            format!("{drops} drops"),
            Style::default().fg(if drops > 0 {
                Color::Yellow
            } else {
                Color::DarkGray
            }),
        ),
    ])];
    header.extend(client_error_lines(app));
    if header.len() == 1 && app.clients.is_empty() {
        header.push(Line::from(Span::styled(
            "no hosts seen yet — traffic has to cross the gateway before a client appears",
            Style::default().fg(Color::DarkGray),
        )));
    }

    // Size the header to what it actually has to say. A fixed height would
    // silently swallow the very line that explains an empty screen.
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(header.len() as u16 + 2),
            Constraint::Min(4),
            Constraint::Length(4),
        ])
        .split(area);

    f.render_widget(
        Paragraph::new(header).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" clients · window {} ", app.window_label())),
        ),
        chunks[0],
    );

    // ── the table ──────────────────────────────────────────────────────
    // Shed columns as the terminal narrows rather than letting every column
    // be squeezed: a truncated MAC address and a truncated byte count are
    // both useless, but only one of them is worth the width. Identity,
    // totals, drops and last-seen are what survive to the end.
    let width = chunks[1].width;
    let show_mac = width >= 126;
    // 106 was two short: at 106 and 107 the table asks for more columns
    // than it has and ratatui takes the difference out of whichever column
    // it likes. Both thresholds are the sum of the widths below plus the
    // spacing between them.
    let show_rates = width >= 108;
    let now = app.now();

    let mut head = vec!["", "name", "address"];
    if show_mac {
        head.push("mac");
    }
    if show_rates {
        head.extend(["↓ now", "↑ now"]);
    }
    head.extend(["↓ total", "↑ total", "online", "drops", "last seen"]);
    let header_row = Row::new(head.into_iter().map(Cell::from).collect::<Vec<_>>())
        .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = app
        .clients
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let named = c.label.is_some() || c.hostname.is_some();
            let name_cell = Cell::from(if named {
                truncate(c.display_name(), 16)
            } else {
                "—".to_string()
            })
            .style(if c.label.is_some() {
                // An operator-assigned name is a fact about the machine, not
                // a guess; it is worth distinguishing from a DHCP hostname.
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            });

            // De-emphasis has to survive the selection bar.
            //
            // The bar is drawn with a DarkGray background, and three cells in
            // the row set DarkGray as their foreground — so on the selected
            // row the MAC address, the drop count and the last-seen time were
            // painted in the background colour. Contrast 1.00: three columns
            // simply gone, for the one host the operator was looking at.
            let dim = if i == app.client_selected {
                Color::Gray
            } else {
                Color::DarkGray
            };

            let mut cells = vec![online_cell(c.online), name_cell, Cell::from(c.ip.clone())];
            if show_mac {
                cells.push(
                    Cell::from(c.mac.clone().unwrap_or_else(|| "—".into()))
                        .style(Style::default().fg(dim)),
                );
            }
            if show_rates {
                cells.push(
                    Cell::from(fmt_rate_bytes(c.rx_bps)).style(Style::default().fg(Color::Cyan)),
                );
                cells.push(
                    Cell::from(fmt_rate_bytes(c.tx_bps)).style(Style::default().fg(Color::Magenta)),
                );
            }
            cells.extend([
                Cell::from(fmt_bytes(c.rx_bytes.max(0) as u64)),
                Cell::from(fmt_bytes(c.tx_bytes.max(0) as u64)),
                Cell::from(fmt_duration(c.online_secs.max(0) as u64))
                    .style(Style::default().fg(Color::Gray)),
                Cell::from(c.disconnects.to_string()).style(if c.disconnects > 0 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(dim)
                }),
                Cell::from(
                    c.last_seen
                        .map(|t| fmt_ago(t, now))
                        .unwrap_or_else(|| "—".into()),
                )
                .style(Style::default().fg(dim)),
            ]);

            let row = Row::new(cells);
            if i == app.client_selected {
                row.style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            }
        })
        .collect();

    let mut widths = vec![
        Constraint::Length(2),
        Constraint::Length(16),
        Constraint::Length(15), // an IPv4 address is at most 15 characters
    ];
    if show_mac {
        widths.push(Constraint::Length(17)); // and a MAC is exactly 17
    }
    if show_rates {
        widths.push(Constraint::Length(11));
        widths.push(Constraint::Length(11));
    }
    widths.extend([
        Constraint::Length(10),
        Constraint::Length(10),
        // fmt_duration reaches "365d 23h59m"; ago() reaches "37m00s ago" and
        // longer. Both columns used to be narrower than their own output.
        Constraint::Length(10),
        Constraint::Length(5),
        Constraint::Min(12),
    ]);

    f.render_widget(
        Table::new(rows, widths).header(header_row).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" hosts (↑/↓ select · Enter for details) "),
        ),
        chunks[1],
    );

    let keys = Line::from(vec![
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(" select  "),
        Span::styled("Enter", Style::default().fg(Color::Yellow)),
        Span::raw(" details  "),
        Span::styled("w", Style::default().fg(Color::Yellow)),
        Span::raw(format!(" window ({})  ", app.window_label())),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw(" refresh  "),
        Span::styled("c/Esc", Style::default().fg(Color::Yellow)),
        Span::raw(" back to providers  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);
    let hint = Line::from(Span::styled(
        "traffic is counted in the kernel per host; \"online\" comes from the ARP table, \
         refreshed by an occasional ping",
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(
        Paragraph::new(vec![keys, hint]).block(Block::default().borders(Borders::ALL)),
        chunks[2],
    );
}

fn draw_client_detail(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let Some(detail) = app.client_detail.as_deref() else {
        let body = if let Some(err) = &app.client_error {
            vec![
                Line::from(Span::styled(
                    "could not load this client",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
                Line::from(truncate(err, 100)),
            ]
        } else {
            vec![Line::from("loading…")]
        };
        f.render_widget(
            Paragraph::new(body).block(Block::default().borders(Borders::ALL).title(" client ")),
            area,
        );
        return;
    };

    let sessions_h = 3 + detail.sessions.len().clamp(1, 8) as u16;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Min(7),
            Constraint::Length(sessions_h),
            Constraint::Length(4),
        ])
        .split(area);

    let c = &detail.client;
    let now = app.now();

    // ── who, and how it is doing ───────────────────────────────────────
    let state_line = match (c.online, c.session_secs) {
        (true, Some(s)) => Line::from(vec![
            Span::styled(
                "● online",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  connected for {}", fmt_duration(s.max(0) as u64)),
                Style::default().fg(Color::Gray),
            ),
        ]),
        (true, None) => Line::from(Span::styled(
            "● online",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )),
        (false, _) => Line::from(vec![
            Span::styled(
                "· offline",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                c.last_seen
                    .map(|t| format!("  last seen {}", fmt_ago(t, now)))
                    .unwrap_or_default(),
                Style::default().fg(Color::Gray),
            ),
        ]),
    };

    let info = vec![
        Line::from(vec![
            Span::styled(
                c.display_name().to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("   {}", c.ip), Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("   {}", c.mac.as_deref().unwrap_or("—")),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        state_line,
        Line::from(vec![
            Span::styled("traffic   ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("↓ {}", fmt_bytes(c.rx_bytes.max(0) as u64)),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("   "),
            Span::styled(
                format!("↑ {}", fmt_bytes(c.tx_bytes.max(0) as u64)),
                Style::default().fg(Color::Magenta),
            ),
            Span::styled(
                format!("   over the last {}", app.window_label()),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
        Line::from(vec![
            Span::styled("average   ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("↓ {}", fmt_rate_bytes(detail.avg_rx_bps)),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("   "),
            Span::styled(
                format!("↑ {}", fmt_rate_bytes(detail.avg_tx_bps)),
                Style::default().fg(Color::Magenta),
            ),
            Span::styled("   while connected", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("peak      ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("↓ {}", fmt_rate_bytes(detail.peak_rx_bps)),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw("   "),
            Span::styled(
                format!("↑ {}", fmt_rate_bytes(detail.peak_tx_bps)),
                Style::default().fg(Color::Magenta),
            ),
        ]),
        Line::from(vec![
            Span::styled("connected ", Style::default().fg(Color::Gray)),
            // The time and the percentage have to be the same measurement.
            // This printed the *current session* next to the share of the
            // whole window, so a host connected for four hours out of nine
            // read "4h12m of 24h (36.7%)" — two true numbers that cannot both
            // describe one thing.
            Span::raw(format!(
                "{} of {}  ({:.1}%)",
                fmt_duration(
                    detail
                        .sessions
                        .iter()
                        .map(|s| s.duration_secs.max(0) as u64)
                        .sum::<u64>()
                ),
                app.window_label(),
                detail.availability_pct
            )),
            Span::raw("   "),
            Span::styled(
                format!("drops {}", c.disconnects),
                Style::default().fg(if c.disconnects > 0 {
                    Color::Yellow
                } else {
                    Color::DarkGray
                }),
            ),
            Span::raw("   "),
            Span::styled(
                format!(
                    "longest {}",
                    fmt_duration(detail.longest_session_secs.max(0) as u64)
                ),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                c.first_seen
                    .map(|t| format!("   first seen {}", app.stamp(t)))
                    .unwrap_or_default(),
                Style::default().fg(Color::DarkGray),
            ),
        ]),
    ];
    f.render_widget(
        Paragraph::new(info).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" client {} ", c.ip)),
        ),
        chunks[0],
    );

    // ── traffic over time ──────────────────────────────────────────────
    let rx: Vec<(f64, f64)> = detail
        .samples
        .iter()
        .enumerate()
        .map(|(i, s)| (i as f64, s.rx_bps * 8.0))
        .collect();
    let tx: Vec<(f64, f64)> = detail
        .samples
        .iter()
        .enumerate()
        .map(|(i, s)| (i as f64, s.tx_bps * 8.0))
        .collect();
    let max_y = rx
        .iter()
        .chain(tx.iter())
        .map(|&(_, y)| y)
        .fold(1.0_f64, f64::max);
    let x_len = detail.samples.len().max(1) as f64 - 1.0;
    let span = match (detail.samples.first(), detail.samples.last()) {
        (Some(a), Some(b)) => format!("{} → {}", app.stamp(a.ts), app.stamp(b.ts)),
        _ => "no traffic recorded in this window".to_string(),
    };
    let datasets = vec![
        Dataset::default()
            .name("↓ rx")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Cyan))
            .data(&rx),
        Dataset::default()
            .name("↑ tx")
            .marker(symbols::Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(Color::Magenta))
            .data(&tx),
    ];
    f.render_widget(
        Chart::new(datasets)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" traffic · {span} ")),
            )
            .x_axis(
                Axis::default()
                    .bounds([0.0, x_len.max(1.0)])
                    .style(Style::default().fg(Color::DarkGray)),
            )
            .y_axis(
                Axis::default()
                    .bounds([0.0, max_y * 1.15])
                    .labels(vec![
                        Span::from("0"),
                        Span::from(fmt_rate(max_y * 1.15 * 0.5)),
                        Span::from(fmt_rate(max_y * 1.15)),
                    ])
                    .style(Style::default().fg(Color::DarkGray)),
            ),
        chunks[1],
    );

    // ── every connection, and every gap between them ───────────────────
    let header_row = Row::new(vec![
        Cell::from("started"),
        Cell::from("ended"),
        Cell::from("duration"),
        Cell::from("away before"),
        Cell::from("↓"),
        Cell::from("↑"),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = detail
        .sessions
        .iter()
        .take(8)
        .map(|s| {
            Row::new(vec![
                Cell::from(app.stamp_secs(s.started_at)),
                Cell::from(match s.ended_at {
                    Some(t) => app.stamp_secs(t),
                    None => "— still connected".to_string(),
                })
                .style(if s.ended_at.is_none() {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default()
                }),
                Cell::from(fmt_duration(s.duration_secs.max(0) as u64)),
                Cell::from(
                    s.gap_before_secs
                        .map(|g| fmt_duration(g.max(0) as u64))
                        .unwrap_or_else(|| "—".into()),
                )
                .style(Style::default().fg(Color::Yellow)),
                Cell::from(fmt_bytes(s.rx_bytes.max(0) as u64))
                    .style(Style::default().fg(Color::Cyan)),
                Cell::from(fmt_bytes(s.tx_bytes.max(0) as u64))
                    .style(Style::default().fg(Color::Magenta)),
            ])
        })
        .collect();
    let rows = if rows.is_empty() {
        vec![Row::new(vec![
            Cell::from("(no connections recorded yet)").style(Style::default().fg(Color::DarkGray)),
        ])]
    } else {
        rows
    };

    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(21),
                Constraint::Length(21),
                Constraint::Length(11),
                Constraint::Length(13),
                Constraint::Length(12),
                Constraint::Min(10),
            ],
        )
        .header(header_row)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" connections (newest first · \"away before\" is the gap) "),
        ),
        chunks[2],
    );

    let keys = Line::from(vec![
        Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
        Span::raw(" next host  "),
        Span::styled("Esc", Style::default().fg(Color::Yellow)),
        Span::raw(" back to the list  "),
        Span::styled("w", Style::default().fg(Color::Yellow)),
        Span::raw(format!(" window ({})  ", app.window_label())),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw(" refresh  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);
    let mut lines = vec![keys];
    lines.extend(client_error_lines(app));
    f.render_widget(
        Paragraph::new(lines).block(Block::default().borders(Borders::ALL)),
        chunks[3],
    );
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

    // The load line runs the width of the panel, not the width of the left
    // column. Inside the left half it is cut at 59 columns, which lands in
    // the middle of the network counters: "net down 4.4" and nothing after
    // it, which reads as a number rather than a truncation.
    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(1)])
        .split(inner);

    let halves = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(body[0]);

    let gauges_area = halves[0];
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            // Slack, so a gauge given the remainder does not stretch into a
            // three-row slab.
            Constraint::Min(0),
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
    f.render_widget(footer_line, body[1]);

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

    // Fit the cores that exist rather than the cores that happen to fit.
    // With a fixed cell width, a machine with more cores than rows_n * cols
    // simply lost the rest — no ellipsis, no count, nothing to notice. Narrow
    // the cells until they all fit, and only then give up and say how many
    // are not shown.
    let cols_max = (area.width / 8).max(1) as usize;
    let rows_avail = (area.height as usize).max(1);
    let mut cols = (area.width / 14).max(1) as usize;
    while cols < cols_max && cores.len().div_ceil(cols) > rows_avail {
        cols += 1;
    }
    let cell_w: u16 = (area.width / cols as u16).max(6);
    let rows_n = cores.len().div_ceil(cols).min(rows_avail).max(1);
    let shown = (rows_n * cols).min(cores.len());

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
            // If some cores still will not fit, say so in the last cell
            // rather than ending the list without comment.
            if idx == shown - 1 && shown < cores.len() {
                let p = Paragraph::new(Line::from(Span::styled(
                    format!("+{} more", cores.len() - shown + 1),
                    Style::default().fg(Color::DarkGray),
                )));
                f.render_widget(p, *cell_rect);
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
    // What the table asks for has to fit what it is given.
    //
    // Every column here is a fixed Length, and when they add up to more than
    // the panel has, ratatui shrinks them — silently, and not evenly. At the
    // 120 columns this dashboard is drawn at, the old widths came to 128 and
    // the whole 10-column deficit landed on one column: provider names were
    // served back as "isp-ma". The two least load-bearing columns now drop
    // out on a narrow terminal instead, and the rest are sized to what their
    // own values actually need.
    let wide = area.width >= 120;

    let mut header_cells = vec![
        Cell::from(""),
        Cell::from("name"),
        Cell::from("prio"),
        Cell::from("state"),
        Cell::from("gateway"),
    ];
    if wide {
        header_cells.push(Cell::from("iface"));
    }
    header_cells.extend([
        Cell::from("latency"),
        Cell::from("canary"),
        Cell::from("speed"),
        Cell::from("up for"),
    ]);
    if wide {
        header_cells.push(Cell::from("checked"));
    }
    header_cells.push(Cell::from("why"));
    let header = Row::new(header_cells).style(Style::default().add_modifier(Modifier::BOLD));

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
            // Local time. Every other clock on this screen is local, and a
            // column of timestamps in a second timezone is worse than no
            // column at all.
            let last = p
                .last_check
                .map(|t| app.local(t).format("%H:%M:%S").to_string())
                .unwrap_or_else(|| "--:--:--".into());
            // The canary column is what answers "is this uplink actually
            // carrying my traffic", as opposed to merely answering pings —
            // so it gets its own cell instead of being buried in UP/DOWN.
            let canary_cell = match (p.last_canary_at.is_some(), p.canary_ok) {
                (false, _) => Cell::from("-").style(Style::default().fg(Color::DarkGray)),
                (true, true) => Cell::from("ok").style(Style::default().fg(Color::Green)),
                (true, false) => Cell::from("FAIL")
                    .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            };
            // The throughput floor: the layer that sees a link which is
            // reachable, authentic and useless.
            let speed_cell = match (p.last_throughput_at.is_some(), p.throughput_ok) {
                (false, _) => Cell::from("-").style(Style::default().fg(Color::DarkGray)),
                (true, true) => {
                    let short = p
                        .last_throughput_summary
                        .as_deref()
                        .and_then(|s| s.split(" (").next())
                        .map(|s| s.replace(" kbit/s", "k"))
                        .unwrap_or_else(|| "ok".into());
                    Cell::from(truncate(&short, 9)).style(Style::default().fg(Color::Green))
                }
                (true, false) => Cell::from("SLOW")
                    .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            };
            let up_for = match (p.state, p.up_since) {
                (State::Up, Some(t)) => fmt_duration((app.now() - t).num_seconds().max(0) as u64),
                _ => "-".into(),
            };
            let why = p
                .failure_layer
                .map(|l| l.as_str().to_string())
                .unwrap_or_default();
            let why_cell = Cell::from(why).style(match p.failure_layer {
                Some(l) if l.is_conclusive() => {
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                }
                Some(_) => Style::default().fg(Color::Yellow),
                None => Style::default(),
            });

            let mut cells = vec![
                Cell::from(marker),
                Cell::from(truncate(&p.name, 14)),
                Cell::from(p.priority.to_string()),
                state_cell,
                Cell::from(p.gateway.clone()),
            ];
            if wide {
                cells.push(Cell::from(truncate(&p.interface, 8)));
            }
            cells.extend([
                Cell::from(latency),
                canary_cell,
                speed_cell,
                Cell::from(up_for),
            ]);
            if wide {
                cells.push(Cell::from(last));
            }
            cells.push(why_cell);
            let mut row = Row::new(cells);
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

    // Sized to the longest value each column can hold: an IPv4 address is
    // 15 characters, "content-unreachable" — the longest failure layer — is
    // 19, and a timestamp is 8. With one column of spacing between them this
    // comes to 116 of the 118 the panel has at 120 columns, so nothing is
    // squeezed and the slack goes to "why".
    let mut widths = vec![
        Constraint::Length(2),
        Constraint::Length(14),
        Constraint::Length(4),
        Constraint::Length(6),
        Constraint::Length(15),
    ];
    if wide {
        widths.push(Constraint::Length(8));
    }
    widths.extend([
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(6),
        // fmt_duration reaches "16d 12h00m" — ten characters.
        Constraint::Length(10),
    ]);
    if wide {
        widths.push(Constraint::Length(8));
    }
    widths.push(Constraint::Min(19));
    let title = match &app.snapshot.active {
        Some(a) if app.snapshot.active_adopted => format!(" providers — active: {a} (verifying) "),
        Some(a) => format!(" providers — active: {a} "),
        None => " providers — no active provider ".into(),
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
                    Span::from(fmt_rate(max_y * 1.15 * 0.5)),
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
        Span::styled("c", Style::default().fg(Color::Yellow)),
        Span::raw(" clients  "),
        Span::styled("r", Style::default().fg(Color::Yellow)),
        Span::raw(" refresh  "),
        Span::styled("u", Style::default().fg(Color::Yellow)),
        Span::raw(" update  "),
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit"),
    ]);
    // Prefer the selected provider's failure reason over a stale action
    // message: when something is wrong, that is what the operator needs.
    let detail = app.selected_provider().and_then(|p| {
        p.failure_detail
            .as_ref()
            .map(|d| (p.name.clone(), p.failure_layer, d.clone()))
    });
    let msg_line = match detail {
        Some((name, layer, detail)) => Line::from(vec![
            Span::styled(
                format!("{name} [{}] ", layer.map(|l| l.as_str()).unwrap_or("down")),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(truncate(&detail, 140)),
        ]),
        None => Line::from(
            app.last_message
                .as_ref()
                .filter(|(_, t)| t.elapsed() < Duration::from_secs(5))
                .map(|(m, _)| m.clone())
                .unwrap_or_default(),
        ),
    };
    let text = vec![keys, msg_line];
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::balancer::{ClientSessionInfo, ClientTrafficPoint, FailbackPending};
    use chrono::{Duration as ChronoDuration, Utc};
    use ratatui::backend::TestBackend;

    /// Render a screen into an off-screen buffer and return it as plain text.
    ///
    /// This is what makes the screens testable at all: the assertions below
    /// check what an operator actually sees, not what the code meant to
    /// draw. Set `VLB_SHOTS=1` to print the frames — that is how the
    /// screenshots in the README are produced, so they cannot drift from the
    /// real thing.
    fn render(app: &App, w: u16, h: u16, which: View) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal
            .draw(|f| match which {
                View::Clients => draw_clients(f, f.area(), app),
                View::ClientDetail => draw_client_detail(f, f.area(), app),
                View::Dashboard => draw_dashboard(f, app),
            })
            .unwrap();

        let buf = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                let idx = y as usize * buf.area.width as usize + x as usize;
                out.push_str(buf.content[idx].symbol());
            }
            out = out.trim_end_matches(' ').to_string();
            out.push('\n');
        }
        if std::env::var("VLB_SHOTS").is_ok() {
            println!("\n=== {which:?} {w}x{h} ===\n{out}");
        }
        out
    }

    // ── documentation assets ───────────────────────────────────────────
    //
    // The pictures in the README are rendered here, from the same widgets
    // the program draws with. A hand-drawn mock-up of a terminal is a
    // promise nobody checks; this one cannot drift, because it *is* the
    // output. `VLB_SHOTS=1 cargo test --bin vlb tui::` writes them.

    /// Character cell size, in the SVG's coordinate space.
    const CW: f64 = 8.0;
    const CH: f64 = 17.0;

    /// The colours a terminal would use. `default` is what an unset colour
    /// becomes, which differs by role and again when a cell is reversed —
    /// gauges and selected rows are drawn that way, and ignoring it turns
    /// every progress bar into a grey slab.
    /// A background needs its own table.
    ///
    /// The terminal's two structural backgrounds are ANSI black (a gauge
    /// trough) and ANSI bright black (a selection bar). Rendered with the
    /// foreground palette they come out at 1.09:1 and 1.00:1 against the
    /// page — an invisible trough, and a selection bar that swallows any
    /// text the row happened to dim. Both get a panel grey here instead,
    /// which is what a terminal theme actually shows and what leaves the
    /// text on top of it readable.
    fn svg_bg(c: Color, default: &'static str) -> &'static str {
        match c {
            Color::Reset => default,
            Color::Black => "#21262d",
            Color::DarkGray => "#30363d",
            other => svg_colour(other, default),
        }
    }

    fn svg_colour(c: Color, default: &'static str) -> &'static str {
        match c {
            Color::Reset => default,
            Color::Black => "#161b22",
            Color::Red | Color::LightRed => "#ff7b72",
            Color::Green | Color::LightGreen => "#3fb950",
            Color::Yellow | Color::LightYellow => "#d29922",
            Color::Blue | Color::LightBlue => "#58a6ff",
            Color::Magenta | Color::LightMagenta => "#bc8cff",
            Color::Cyan | Color::LightCyan => "#39c5cf",
            Color::Gray => "#8b949e",
            Color::DarkGray => "#6e7681",
            Color::White => "#f0f6fc",
            _ => "#c9d1d9",
        }
    }

    fn xml_escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn xml_unescape(s: &str) -> String {
        s.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")
    }

    /// Pull one attribute out of a line this module wrote itself.
    fn svg_attr(line: &str, name: &str) -> Option<String> {
        let key = format!("{name}=\"");
        let start = line.find(&key)? + key.len();
        let rest = &line[start..];
        let end = rest.find('"')?;
        Some(rest[..end].to_string())
    }

    /// Read a rendered group back and check it against the buffer it came
    /// from.
    ///
    /// This renderer fails silently. A run that drops characters, or lands a
    /// column to the left of where it belongs, still produces a well-formed
    /// SVG that no XML check will complain about — the only place it showed
    /// up was in the published README, as words run together and rows
    /// letter-spaced. So put the picture back together from what was written
    /// and compare it with what the terminal drew.
    fn verify_group(svg: &str, buf: &ratatui::buffer::Buffer, w: u16, h: u16) {
        // Spaces inside a run are content, and XML only knows that if the
        // element says so. Without this the parser strips the ones at each
        // end of a run and collapses the rest, and `textLength` then
        // stretches whatever survived across the whole span.
        for line in svg.lines().filter(|l| l.starts_with("<text")) {
            assert!(
                line.contains("xml:space=\"preserve\""),
                "a text run may not leave its spaces to the parser's discretion: {line}"
            );
        }

        // (start column, cells, what is drawn there)
        let mut items: Vec<(usize, usize, String)> = Vec::new();
        for line in svg.lines() {
            let (x, row) = match (svg_attr(line, "x"), svg_attr(line, "y")) {
                (Some(x), Some(y)) => (
                    x.parse::<f64>().unwrap(),
                    (y.parse::<f64>().unwrap() / CH).floor() as usize,
                ),
                _ => continue,
            };
            let col = (x / CW).round() as usize;
            if line.starts_with("<text") {
                let body = line
                    .split_once('>')
                    .and_then(|(_, rest)| rest.strip_suffix("</text>"))
                    .unwrap_or_default();
                let cells = (svg_attr(line, "textLength")
                    .unwrap()
                    .parse::<f64>()
                    .unwrap()
                    / CW)
                    .round() as usize;
                items.push((row * 1000 + col, cells, xml_unescape(body)));
            } else if line.contains("shape-rendering") {
                // A solid bar: the same cells, drawn as one rectangle.
                let cells = (svg_attr(line, "width").unwrap().parse::<f64>().unwrap() / CW).round()
                    as usize;
                items.push((row * 1000 + col, cells, "\u{2588}".repeat(cells)));
            }
        }
        items.sort_by_key(|i| i.0);

        for y in 0..h as usize {
            let mut got = String::new();
            let mut col = 0usize;
            for (key, cells, text) in items.iter().filter(|i| i.0 / 1000 == y) {
                let start = key % 1000;
                assert!(start >= col, "row {y}: runs overlap at column {start}");
                got.push_str(&" ".repeat(start - col));
                got.push_str(text);
                col = start + cells;
            }
            let want: String = (0..w)
                .map(|x| buf.content[y * w as usize + x as usize].symbol())
                .collect();
            assert_eq!(
                got.trim_end(),
                want.trim_end(),
                "row {y} of the picture does not say what the terminal drew"
            );
        }
    }

    /// Render one screen and return it as an SVG group.
    ///
    /// Runs of identically-styled cells become one `<text>` with an explicit
    /// `textLength`, so the columns line up whatever monospace font the
    /// reader's browser happens to pick.
    fn svg_group(app: &App, w: u16, h: u16, which: View, class: &str) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal
            .draw(|f| match which {
                View::Clients => draw_clients(f, f.area(), app),
                View::ClientDetail => draw_client_detail(f, f.area(), app),
                View::Dashboard => draw_dashboard(f, app),
            })
            .unwrap();
        let buf = terminal.backend().buffer().clone();

        // Resolve one cell to the pair of colours it is actually painted
        // with. Reverse video swaps them, the way a terminal does; nothing
        // in the dashboard sets it today, but a cell that arrived reversed
        // and was drawn un-reversed would be silently unreadable, and that
        // is not a thing to find out from a screenshot.
        let paint = |c: &ratatui::buffer::Cell| -> (&'static str, &'static str, bool) {
            let bold = c.modifier.contains(Modifier::BOLD);
            if c.modifier.contains(Modifier::REVERSED) {
                (svg_bg(c.bg, "#0d1117"), svg_colour(c.fg, "#c9d1d9"), bold)
            } else {
                (svg_colour(c.fg, "#c9d1d9"), svg_bg(c.bg, "none"), bold)
            }
        };

        let mut out = format!("<g class=\"{class}\">\n");
        for y in 0..h {
            let mut x = 0u16;
            while x < w {
                let key = paint(&buf.content[y as usize * w as usize + x as usize]);
                let start = x;
                // Cell symbols, not characters. One cell can hold a
                // multi-character grapheme, and the second half of a
                // double-width glyph is an empty symbol that still owns a
                // column — so widths have to be counted in cells.
                let mut cells: Vec<&str> = Vec::new();
                while x < w {
                    let c = &buf.content[y as usize * w as usize + x as usize];
                    if paint(c) != key {
                        break;
                    }
                    cells.push(c.symbol());
                    x += 1;
                }
                let (fg, bg, bold) = key;
                let blank = cells.iter().all(|s| s.trim().is_empty());
                if blank && bg == "none" {
                    continue;
                }
                if bg != "none" {
                    out.push_str(&format!(
                        "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"{bg}\"/>\n",
                        start as f64 * CW,
                        y as f64 * CH,
                        cells.len() as f64 * CW,
                        CH,
                    ));
                }
                if !blank {
                    // Leading and trailing blanks carry no ink, and a run
                    // that ends a line is mostly them. Dropping them shrinks
                    // the file, and it is what keeps `textLength` honest: the
                    // attribute pins the drawn glyphs to the columns they
                    // actually occupy, so it can only nudge, never stretch.
                    let lead = cells.iter().take_while(|s| s.trim().is_empty()).count();
                    let trail = cells
                        .iter()
                        .rev()
                        .take_while(|s| s.trim().is_empty())
                        .count();
                    let inked = &cells[lead..cells.len() - trail];
                    // A run of full blocks is a bar, not writing. Drawn as
                    // glyphs it comes out with a hairline seam between every
                    // pair of cells; one rectangle is what the eye expects.
                    if inked.iter().all(|s| *s == "\u{2588}") {
                        out.push_str(&format!(
                            "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" \
                             fill=\"{fg}\" shape-rendering=\"crispEdges\"/>\n",
                            (start as usize + lead) as f64 * CW,
                            y as f64 * CH,
                            inked.len() as f64 * CW,
                            CH,
                        ));
                        continue;
                    }
                    // `xml:space="preserve"` is not optional. Without it the
                    // parser strips the spaces at each end of a run and
                    // collapses the ones inside, and `textLength` then
                    // stretches the survivors across the whole span: words
                    // ran into each other, rows came out letter-spaced, and a
                    // lone border character became a grey slab the width of a
                    // panel.
                    out.push_str(&format!(
                        "<text xml:space=\"preserve\" x=\"{:.1}\" y=\"{:.1}\" textLength=\"{:.1}\" \
                         lengthAdjust=\"spacingAndGlyphs\" fill=\"{fg}\"{}>{}</text>\n",
                        (start as usize + lead) as f64 * CW,
                        y as f64 * CH + CH * 0.74,
                        inked.len() as f64 * CW,
                        if bold { " font-weight=\"bold\"" } else { "" },
                        xml_escape(&inked.concat())
                    ));
                }
            }
        }
        out.push_str("</g>\n");
        verify_group(&out, &buf, w, h);
        out
    }

    /// Wrap groups into a finished SVG. More than one group turns into an
    /// animation: each is shown in turn, on a loop.
    fn svg_document(groups: &[String], w: u16, h: u16, hold_secs: f64, caption: &str) -> String {
        let width = w as f64 * CW;
        let height = h as f64 * CH;
        let mut s = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {width:.0} {height:.0}\" \
             width=\"{width:.0}\" height=\"{height:.0}\" role=\"img\" \
             aria-labelledby=\"vlb-title\" font-family=\"ui-monospace, \
             SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace\" font-size=\"14\">\n"
        );
        // The description travels with the file. These are linked as
        // documents as well as embedded, and an `alt` attribute in the
        // README does not follow a saved copy anywhere.
        s.push_str(&format!(
            "<title id=\"vlb-title\">{}</title>\n",
            xml_escape(caption)
        ));
        s.push_str("<rect width=\"100%\" height=\"100%\" rx=\"8\" fill=\"#0d1117\"/>\n");

        if groups.len() > 1 {
            let total = hold_secs * groups.len() as f64;
            s.push_str("<style type=\"text/css\">\n");
            for i in 0..groups.len() {
                let from = 100.0 * i as f64 / groups.len() as f64;
                let to = 100.0 * (i + 1) as f64 / groups.len() as f64;
                s.push_str(&format!(
                    ".f{i} {{ animation: k{i} {total:.1}s step-end infinite }}\n\
                     @keyframes k{i} {{ {from:.3}% {{ visibility: visible }} \
                     {to:.3}% {{ visibility: hidden }} }}\n"
                ));
            }
            s.push_str("</style>\n");
        }
        for (i, g) in groups.iter().enumerate() {
            // Fail to a still, not to nothing.
            //
            // Hiding every frame in CSS and revealing one from a keyframe
            // means a renderer that parses CSS but does not implement
            // animation — most SVG rasterizers — draws an empty box. Hiding
            // the later frames with a presentation attribute instead leaves
            // frame 0 the default state, and a CSS animation still wins over
            // a presentation attribute wherever animation works at all.
            if i == 0 {
                s.push_str(g);
            } else {
                s.push_str(&g.replacen("\">\n", "\" visibility=\"hidden\">\n", 1));
            }
        }
        s.push_str("</svg>\n");
        s
    }

    /// Build one asset, and publish it only when asked to.
    ///
    /// The document is always produced, so the generator is exercised on
    /// every `cargo test` run and the assertions below have something to
    /// check. It used to be built only under `VLB_SHOTS`, which made the
    /// whole renderer dead code in CI: the pictures in the README were the
    /// one place its bugs could show up, and by then they were published.
    fn write_asset(
        name: &str,
        caption: &str,
        groups: &[String],
        w: u16,
        h: u16,
        hold_secs: f64,
    ) -> String {
        let svg = svg_document(groups, w, h, hold_secs, caption);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("docs/assets")
            .join(name);
        if std::env::var("VLB_SHOTS").is_ok() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &svg).unwrap();
            println!("wrote {}", path.display());
        } else if let Ok(published) = std::fs::read_to_string(&path) {
            // The README says these pictures cannot drift from what the
            // program draws. That was a claim, not a fact: the 0.5.0 release
            // shipped a dashboard labelled v0.4.0. The output is
            // reproducible now, so the claim can simply be checked.
            assert_eq!(
                published, svg,
                "docs/assets/{name} is not what the generator produces any more.\n\
                 Regenerate it:  VLB_SHOTS=1 cargo test --bin vlb tui::tests::render_readme_assets"
            );
        }
        svg
    }

    /// A triangle wave, in whole numbers.
    ///
    /// The fixtures used to shape their traffic with `sin` and `cos`. Two
    /// libms do not have to agree on the last bit of a sine, and they do
    /// not: the same fixture produced a peak of 31.6 Mbit/s on one machine
    /// and a hair less on another, so the committed picture could not match
    /// both. Integer arithmetic has no such freedom.
    fn wave(i: i64, period: i64, amplitude: i64) -> i64 {
        let x = i.rem_euclid(period);
        let up = if x * 2 <= period { x } else { period - x };
        up * 2 * amplitude / period
    }

    /// A fixed instant for everything the pictures print as a wall clock.
    ///
    /// The fixtures used to build every timestamp from `Utc::now()`, so
    /// regenerating the README assets rewrote all five files whether or not
    /// anything had changed, and no diff could tell you whether a layout
    /// change had altered a picture. Durations stay relative to the real
    /// clock, because "up for" and "last seen" are durations; only the
    /// absolute strings come from here.
    fn fixture_clock() -> chrono::DateTime<Utc> {
        "2026-01-15T09:41:07Z".parse().unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn provider(
        name: &str,
        gw: &str,
        priority: u32,
        state: State,
        latency: f64,
        up_for_secs: i64,
        layer: Option<crate::balancer::FailureLayer>,
        detail: Option<&str>,
    ) -> ProviderSnapshot {
        let now = fixture_clock();
        let stamp = now;
        ProviderSnapshot {
            name: name.into(),
            gateway: gw.into(),
            interface: "ens18".into(),
            priority,
            role: if priority == 0 { "primary" } else { "backup" }.into(),
            state,
            last_latency_ms: (state != State::Down).then_some(latency),
            last_check: Some(stamp),
            consecutive_failures: if state == State::Down { 3 } else { 0 },
            consecutive_successes: if state == State::Up { 240 } else { 0 },
            up_since: (state == State::Up).then(|| now - ChronoDuration::seconds(up_for_secs)),
            failure_layer: layer,
            failure_detail: detail.map(String::from),
            canary_ok: state == State::Up,
            last_canary_at: Some(stamp),
            last_canary_summary: Some("3/3 canary targets verified".into()),
            throughput_ok: state == State::Up,
            last_throughput_at: Some(stamp),
            // Three uplinks that all measure exactly the same speed is the
            // one detail that gives a mocked screenshot away.
            last_throughput_summary: Some(format!("{} kbit/s", 94_210 - (priority as u64 * 8_650))),
        }
    }

    /// One host for the pictures.
    ///
    /// `seed` separates them. Every host used to carry the same MAC address,
    /// the same download rate, the same upload rate and the same time online,
    /// which is not what a real network looks like and is the detail that
    /// gives a mocked screenshot away.
    fn client(
        ip: &str,
        name: Option<&str>,
        online: bool,
        rx: i64,
        drops: i64,
        seed: u8,
    ) -> ClientInfo {
        let now = fixture_clock();
        let k = seed as f64;
        ClientInfo {
            ip: ip.into(),
            mac: Some(format!(
                "a4:5e:60:{:02x}:{:02x}:{:02x}",
                0x11 + seed,
                0x2c,
                0x9e - seed * 7
            )),
            hostname: name.map(String::from),
            label: None,
            online,
            // A wall-clock date, so it belongs to the same day as every
            // other absolute time in the picture.
            first_seen: Some(fixture_clock() - ChronoDuration::days(3 + seed as i64)),
            last_seen: Some(if online {
                now
            } else {
                now - ChronoDuration::minutes(37)
            }),
            rx_bps: if online {
                2_950_000.0 / (1.0 + k * 0.9)
            } else {
                0.0
            },
            tx_bps: if online {
                288_000.0 / (1.0 + k * 0.55)
            } else {
                0.0
            },
            rx_bytes: rx,
            tx_bytes: rx / (7 + seed as i64),
            disconnects: drops,
            online_secs: if online {
                15_120 - seed as i64 * 2_640
            } else {
                3_600
            },
            session_secs: online.then_some(15_120 - seed as i64 * 2_640),
        }
    }

    fn sample_app() -> App {
        let cfg: Config = toml::from_str(
            r#"
[[providers]]
name = "isp-main"
gateway = "10.0.0.2"
interface = "eth0"
priority = 0
"#,
        )
        .unwrap();
        let snapshot = ControlSnapshot {
            active: Some("isp-main".into()),
            forced: None,
            providers: Vec::new(),
            version: update::current_version().to_string(),
            started_at: Some(fixture_clock() - ChronoDuration::hours(30)),
            active_adopted: false,
            kernel_route: Some("via 10.0.0.2 dev eth0 metric 0 proto static".into()),
            failback_pending: None,
        };
        let mut app = App::new(cfg, std::path::PathBuf::from("/etc/vlb/vlb.toml"), snapshot);
        // Every duration on screen is measured from here, so the pictures
        // come out byte-identical however long the test takes to run.
        app.clock = Some(fixture_clock());
        app.zone = chrono::FixedOffset::east_opt(0);
        app.clients = vec![
            client("192.168.8.24", Some("denis-pc"), true, 3_650_722_201, 0, 0),
            client("192.168.8.31", Some("kitchen-tv"), true, 812_000_000, 2, 1),
            client("192.168.8.12", None, true, 41_000_000, 0, 2),
            client(
                "192.168.8.57",
                Some("iphone-anna"),
                false,
                220_500_000,
                5,
                3,
            ),
            client("192.168.8.9", Some("nas"), true, 1_284_000_000, 0, 4),
            client("192.168.8.44", Some("work-laptop"), true, 96_400_000, 1, 5),
            client("192.168.8.71", Some("printer"), false, 2_100_000, 3, 6),
        ];
        app.clients[2].mac = None;
        app.clients[1].label = Some("TV (living room)".into());
        app
    }

    /// One client's detail, as a picture that does not contradict itself.
    ///
    /// It used to: a header that said "over the last 24h" above a chart
    /// spanning 39 minutes, a stated peak the chart could not reach, an
    /// availability figure that did not match the sessions listed under it,
    /// and a gap of 12m18s between two timestamps 12m00s apart. Everything
    /// below is derived from three durations and one byte total, so the
    /// numbers cannot drift apart again.
    fn sample_detail() -> ClientDetail {
        const CURRENT: i64 = 15_120; // 4h12m, still running
        const GAP: i64 = 738; // 12m18s away
        const PREVIOUS: i64 = 16_560; // 4h36m
        const WINDOW: i64 = 24 * 3600;
        let connected = CURRENT + PREVIOUS;

        let end = fixture_clock();
        let mut c = client("192.168.8.24", Some("denis-pc"), true, 3_650_722_201, 2, 0);
        c.online_secs = CURRENT;
        c.session_secs = Some(CURRENT);
        let rx_total = c.rx_bytes;
        let tx_total = c.tx_bytes;

        // 15-minute buckets across the whole window, carrying traffic only
        // while the host was actually connected.
        let samples: Vec<ClientTrafficPoint> = (0..96)
            .map(|i| {
                let ago = (95 - i) as f64 * 900.0;
                let live = ago <= CURRENT as f64
                    || (ago >= (CURRENT + GAP) as f64 && ago <= (CURRENT + GAP + PREVIOUS) as f64);
                ClientTrafficPoint {
                    ts: end - ChronoDuration::seconds(ago as i64),
                    rx_bps: if live {
                        (760_000 + wave(i, 17, 3_900_000) + wave(i, 6, 540_000)) as f64
                    } else {
                        0.0
                    },
                    tx_bps: if live {
                        (74_000 + wave(i + 3, 23, 430_000) + wave(i, 9, 60_000)) as f64
                    } else {
                        0.0
                    },
                }
            })
            .collect();

        let peak_rx_bps = samples.iter().map(|s| s.rx_bps).fold(0.0, f64::max);
        let peak_tx_bps = samples.iter().map(|s| s.tx_bps).fold(0.0, f64::max);

        // The sessions account for every byte the header claims.
        let prev_rx = rx_total * PREVIOUS / connected;
        let prev_tx = tx_total * PREVIOUS / connected;
        ClientDetail {
            client: c,
            window_hours: 24,
            samples,
            sessions: vec![
                ClientSessionInfo {
                    started_at: end - ChronoDuration::seconds(CURRENT),
                    ended_at: None,
                    duration_secs: CURRENT,
                    gap_before_secs: Some(GAP),
                    rx_bytes: rx_total - prev_rx,
                    tx_bytes: tx_total - prev_tx,
                },
                ClientSessionInfo {
                    started_at: end - ChronoDuration::seconds(CURRENT + GAP + PREVIOUS),
                    ended_at: Some(end - ChronoDuration::seconds(CURRENT + GAP)),
                    duration_secs: PREVIOUS,
                    gap_before_secs: Some(120),
                    rx_bytes: prev_rx,
                    tx_bytes: prev_tx,
                },
            ],
            peak_rx_bps,
            peak_tx_bps,
            avg_rx_bps: rx_total as f64 / connected as f64,
            avg_tx_bps: tx_total as f64 / connected as f64,
            longest_session_secs: PREVIOUS,
            availability_pct: 100.0 * connected as f64 / WINDOW as f64,
        }
    }
    fn dashboard_app(
        providers: Vec<ProviderSnapshot>,
        active: &str,
        events: Vec<FailoverEventWire>,
        failback: Option<FailbackPending>,
    ) -> App {
        let mut app = sample_app();
        app.snapshot.active = Some(active.into());
        app.snapshot.providers = providers;
        app.snapshot.failback_pending = failback;
        app.snapshot.kernel_route = Some(format!(
            "via {} dev ens18 metric 0 proto static",
            if active == "isp-main" {
                "10.0.0.2"
            } else {
                "10.0.1.1"
            }
        ));
        app.events = events;
        app.selected = 0;

        let now = fixture_clock();
        app.system = (0..60)
            .map(|i| {
                // The headline figure is the mean of the cores, because that
                // is what it is. It used to be an unrelated sawtooth, so the
                // picture showed "CPU 28.0%" above four cores averaging 19.
                let cores: Vec<f32> = (0..4)
                    .map(|c| 4.0 + ((i * 3 + c * 11) % 31) as f32)
                    .collect();
                let total = cores.iter().sum::<f32>() / cores.len() as f32;
                SystemPointWire {
                    ts: (now - ChronoDuration::seconds(60 - i)).to_rfc3339(),
                    sample: crate::sysmon::SysSample {
                        cpu_total: total,
                        cpu_per_core: cores,
                        mem_total: 2 * 1024 * 1024 * 1024,
                        mem_used: 412 * 1024 * 1024,
                        mem_available: 1_600 * 1024 * 1024,
                        swap_total: 1024 * 1024 * 1024,
                        swap_used: 0,
                        load1: 0.18,
                        load5: 0.22,
                        load15: 0.20,
                        net_rx_bytes: 4_812_000_000,
                        net_tx_bytes: 812_000_000,
                        disk_total: 40 * 1024 * 1024 * 1024,
                        disk_used: 9 * 1024 * 1024 * 1024,
                        uptime_s: 1_209_600,
                        procs: 128,
                    },
                }
            })
            .collect();

        for p in app.snapshot.providers.clone() {
            let carrying = Some(&p.name) == app.snapshot.active.as_ref();
            let points = (0..90)
                .map(|i| TrafficPointWire {
                    ts: (now - ChronoDuration::seconds(90 - i)).to_rfc3339(),
                    interval_s: 2.0,
                    // The moduli here never wrapped — i tops out at 90, so
                    // `(i * 137) % 700_000` was just `i * 137` and the chart
                    // in the README's headline picture came out a flat line.
                    // Two triangles of different period give it the shape
                    // real traffic has, without leaving the integers.
                    rx_bytes: if carrying {
                        (620_000 + wave(i, 29, 900_000) + wave(i, 13, 240_000)) as u64
                    } else {
                        (1_400 + wave(i, 7, 900)) as u64
                    },
                    rx_packets: 900,
                    tx_bytes: if carrying {
                        (96_000 + wave(i + 5, 37, 130_000) + wave(i, 11, 34_000)) as u64
                    } else {
                        400
                    },
                    tx_packets: 300,
                })
                .collect();
            app.traffic.insert(p.name.clone(), points);
        }
        app
    }

    /// Render the pictures the README uses.
    ///
    /// Normally a no-op: it only writes when asked, so an ordinary test run
    /// never touches the working tree. Run it with
    /// `VLB_SHOTS=1 cargo test --bin vlb tui::tests::render_readme_assets`.
    #[test]
    fn render_readme_assets() {
        use crate::balancer::FailureLayer;
        // One timeline, told over five frames.
        //
        // Each event is stamped once, at the moment it happens, and every
        // frame is drawn at its own instant on the same clock. Ageing the
        // events instead — the same switchover written as "1s ago", then
        // "22s ago", then "52s ago" — printed a past event at three
        // different wall-clock times while nothing else on the screen moved.
        let now = fixture_clock();
        let at = |app: App, secs: i64| -> App {
            let mut a = app;
            a.clock = Some(now + ChronoDuration::seconds(secs));
            a
        };
        let ev = |secs: i64, from: Option<&str>, to: &str, reason: &str| FailoverEventWire {
            ts: (now + ChronoDuration::seconds(secs)).to_rfc3339(),
            from: from.map(String::from),
            to: to.into(),
            reason: reason.into(),
        };

        // ── the failover, as it happens ────────────────────────────────
        let healthy = || {
            vec![
                provider(
                    "isp-main",
                    "10.0.0.2",
                    0,
                    State::Up,
                    10.7,
                    91_000,
                    None,
                    None,
                ),
                provider(
                    "isp-second",
                    "10.0.1.1",
                    1,
                    State::Up,
                    14.2,
                    412_800,
                    None,
                    None,
                ),
                provider(
                    "isp-backup",
                    "10.0.0.1",
                    2,
                    State::Up,
                    21.9,
                    1_425_600,
                    None,
                    None,
                ),
            ]
        };
        let intercepted = {
            let mut v = healthy();
            v[0] = provider(
                "isp-main",
                "10.0.0.2",
                0,
                State::Down,
                10.7,
                0,
                Some(FailureLayer::ContentTampered),
                Some("canary.txt came back as a payment page (302 to portal.isp.example)"),
            );
            v
        };
        let recovering = {
            let mut v = healthy();
            v[0] = provider("isp-main", "10.0.0.2", 0, State::Up, 11.1, 8, None, None);
            v
        };

        let settled = ev(
            -3_600,
            Some("isp-backup"),
            "isp-main",
            "failback to higher-priority 'isp-main'",
        );
        let switched = ev(
            31,
            Some("isp-main"),
            "isp-second",
            "'isp-main' is down — switching to healthy 'isp-second' (priority 1)",
        );
        let failed_back = ev(
            82,
            Some("isp-second"),
            "isp-main",
            "failback to higher-priority 'isp-main' (priority 0 < 1), healthy for 30s",
        );
        let frames = vec![
            svg_group(
                &at(
                    dashboard_app(healthy(), "isp-main", vec![settled.clone()], None),
                    0,
                ),
                120,
                34,
                View::Dashboard,
                "f0",
            ),
            svg_group(
                &at(
                    dashboard_app(intercepted.clone(), "isp-main", vec![settled.clone()], None),
                    30,
                ),
                120,
                34,
                View::Dashboard,
                "f1",
            ),
            svg_group(
                &at(
                    dashboard_app(
                        intercepted,
                        "isp-second",
                        vec![switched.clone(), settled.clone()],
                        None,
                    ),
                    31,
                ),
                120,
                34,
                View::Dashboard,
                "f2",
            ),
            svg_group(
                &at(
                    dashboard_app(
                        recovering,
                        "isp-second",
                        vec![switched.clone(), settled.clone()],
                        Some(FailbackPending {
                            candidate: "isp-main".into(),
                            stable_for_secs: 22,
                            required_secs: 30,
                        }),
                    ),
                    53,
                ),
                120,
                34,
                View::Dashboard,
                "f3",
            ),
            svg_group(
                &at(
                    dashboard_app(
                        healthy(),
                        "isp-main",
                        vec![failed_back, switched, settled],
                        None,
                    ),
                    82,
                ),
                120,
                34,
                View::Dashboard,
                "f4",
            ),
        ];
        write_asset(
            "failover.svg",
            "The vlb dashboard through a failover: the primary uplink is caught \
serving somebody else's bytes, traffic moves to the second uplink, the primary \
recovers, and the route returns only once it has proven itself.",
            &frames,
            120,
            34,
            2.2,
        );
        write_asset(
            "tui-dashboard.svg",
            "The vlb dashboard: the gateway panel, host metrics, the provider \
table with per-layer health, recent switchovers and the traffic chart.",
            &frames[0..1],
            120,
            34,
            1.0,
        );

        // ── the client screens ─────────────────────────────────────────
        let app = sample_app();
        write_asset(
            "tui-clients.svg",
            "The vlb client list: every host behind the gateway with its live \
rates, totals, time online and drop count.",
            &[svg_group(&app, 132, 19, View::Clients, "f0")],
            132,
            19,
            1.0,
        );

        let mut detail_app = sample_app();
        detail_app.client_detail = Some(Box::new(sample_detail()));
        write_asset(
            "tui-client-detail.svg",
            "One client in detail: its connections, the gaps between them, and \
its average and peak rates.",
            &[svg_group(&detail_app, 132, 26, View::ClientDetail, "f0")],
            132,
            26,
            1.0,
        );
        write_asset(
            "clients.svg",
            "The vlb client list, then one client in detail: its connections, \
the gaps between them, and its average and peak rates.",
            &[
                svg_group(&app, 132, 26, View::Clients, "f0"),
                svg_group(&detail_app, 132, 26, View::ClientDetail, "f1"),
            ],
            132,
            26,
            3.5,
        );
    }

    /// The dashboard is the screen an operator watches during an outage, and
    /// the picture at the top of the README. Nothing rendered it as text
    /// until this test, so every column width in it was unverified — and one
    /// of them was wrong: the table asked for 128 columns inside a panel 118
    /// wide, and the deficit came out of the provider names.
    #[test]
    fn dashboard_prints_provider_names_and_reasons_in_full() {
        use crate::balancer::FailureLayer;
        let providers = vec![
            provider(
                "isp-main",
                "203.0.113.254",
                0,
                State::Down,
                10.7,
                91_000,
                // The longest label the "why" column can be asked to hold.
                Some(FailureLayer::ContentUnreachable),
                Some("no canary target answered"),
            ),
            provider(
                "isp-second",
                "198.51.100.1",
                1,
                State::Up,
                14.2,
                412_800,
                None,
                None,
            ),
            provider(
                "isp-backup",
                "192.0.2.1",
                2,
                State::Up,
                21.9,
                1_425_600,
                None,
                None,
            ),
        ];
        let app = dashboard_app(providers, "isp-second", vec![], None);
        let out = render(&app, 120, 34, View::Dashboard);

        for name in ["isp-main", "isp-second", "isp-backup"] {
            assert!(out.contains(name), "provider name {name} was cut:\n{out}");
        }
        assert!(
            out.contains("content-unreachable"),
            "the failure layer was cut, which is the one thing the column is for:\n{out}"
        );
        assert!(
            out.contains("203.0.113.254"),
            "a gateway address was cut:\n{out}"
        );
        // The footer draws two lines; a three-row bordered block only ever
        // showed the first, which is where the keys are and where the
        // failure explanation is not.
        assert!(out.contains("q quit"), "the key hints went missing:\n{out}");
        assert!(
            out.contains("no canary target answered"),
            "the failure detail never reached the footer:\n{out}"
        );
    }

    /// The list has to answer "who is here, how much are they using, and did
    /// they drop" without the operator reading a manual first.
    #[test]
    fn client_list_shows_identity_traffic_and_drops() {
        let app = sample_app();
        let out = render(&app, 132, 18, View::Clients);

        assert!(out.contains("denis-pc"), "{out}");
        assert!(out.contains("192.168.8.24"), "{out}");
        assert!(
            out.contains("a4:5e:60:11:2c:9e"),
            "mac on a wide terminal\n{out}"
        );
        // The operator's own label wins over the DHCP hostname.
        assert!(out.contains("TV (living room)"), "{out}");
        // A host that never announced a name is not blank, it is "—".
        assert!(out.contains('—'), "{out}");
        assert!(out.contains("5 of 7 hosts connected"), "{out}");
        assert!(out.contains("3.40 GiB"), "totals in binary units\n{out}");
        assert!(out.contains("Mbit/s"), "live rates in bits\n{out}");
        assert!(out.contains("window 24h"), "{out}");
        assert!(out.contains("Enter"), "the keys are on screen\n{out}");
    }

    /// A narrow terminal must shed whole columns rather than squeeze every
    /// one of them: half a MAC address and half a byte count are both
    /// useless, and identity is what has to survive to the end.
    #[test]
    fn client_list_sheds_columns_as_the_terminal_narrows() {
        let app = sample_app();

        let medium = render(&app, 110, 16, View::Clients);
        assert!(
            !medium.contains("a4:5e:60:11:2c:9e"),
            "no room for MACs\n{medium}"
        );
        assert!(medium.contains("Mbit/s"), "live rates still fit\n{medium}");
        assert!(medium.contains("denis-pc"), "{medium}");
        assert!(medium.contains("3.40 GiB"), "{medium}");

        let narrow = render(&app, 90, 16, View::Clients);
        // The per-host rate columns are gone (the summary still has a
        // gateway-wide figure, which costs no table width).
        assert!(
            !narrow.contains("12.3 Mbit/s"),
            "per-host rates go before totals do\n{narrow}"
        );
        assert!(narrow.contains("denis-pc"), "{narrow}");
        assert!(narrow.contains("192.168.8.24"), "{narrow}");
        assert!(narrow.contains("3.40 GiB"), "totals survive\n{narrow}");
        assert!(narrow.contains("drops"), "and so do drops\n{narrow}");
    }

    /// Every column must be wide enough for its widest possible value: a
    /// MAC is always 17 characters and an IPv4 address up to 15, and a
    /// truncated one of either is worse than no column at all.
    #[test]
    fn wide_terminals_show_addresses_in_full() {
        let app = sample_app();
        let out = render(&app, 132, 19, View::Clients);
        assert!(out.contains("a4:5e:60:11:2c:9e"), "{out}");
        assert!(out.contains("192.168.8.24"), "{out}");
        assert!(out.contains("3.40 GiB"), "{out}");
    }

    #[test]
    fn client_detail_shows_sessions_gaps_and_averages() {
        let mut app = sample_app();
        app.client_detail = Some(Box::new(sample_detail()));
        let out = render(&app, 132, 26, View::ClientDetail);

        assert!(out.contains("denis-pc"), "{out}");
        assert!(out.contains("connected for"), "{out}");
        assert!(out.contains("average"), "{out}");
        assert!(out.contains("peak"), "{out}");
        assert!(out.contains("drops 2"), "{out}");
        assert!(out.contains("36.7%"), "availability\n{out}");
        // The gap between connections is the point of the table.
        assert!(out.contains("away before"), "{out}");
        assert!(out.contains("12m18s"), "a 738-second gap\n{out}");
        assert!(out.contains("still connected"), "the open session\n{out}");
    }

    /// An empty LAN should explain itself rather than showing a blank frame.
    #[test]
    fn an_empty_client_list_says_why() {
        let mut app = sample_app();
        app.clients.clear();
        let out = render(&app, 110, 12, View::Clients);
        assert!(out.contains("no hosts seen yet"), "{out}");
    }

    /// Updating from a git checkout rebuilds the binary but leaves the
    /// running daemon on the old one. An operator who then presses `c` and
    /// sees nothing deserves to be told why.
    #[test]
    fn an_older_daemon_is_named_as_the_reason() {
        let mut app = sample_app();
        app.snapshot.version = "0.0.1".into();
        assert!(app.daemon_is_older());
        let out = render(&app, 124, 14, View::Clients);
        assert!(
            out.contains("v0.0.1"),
            "the version it is actually running\n{out}"
        );
        assert!(out.contains("restart it"), "{out}");

        // And when the daemon simply rejects the request, the same advice.
        let mut app = sample_app();
        app.client_error = Some("invalid request: unknown variant `clients`".into());
        let out = render(&app, 124, 14, View::Clients);
        assert!(out.contains("older than this dashboard"), "{out}");
    }

    /// Same build on both ends is the normal case and must stay quiet.
    #[test]
    fn a_matching_daemon_says_nothing() {
        let app = sample_app();
        assert!(!app.daemon_is_older());
        let out = render(&app, 124, 14, View::Clients);
        assert!(!out.contains("restart it"), "{out}");
    }
}
