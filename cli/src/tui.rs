//! `goodbyedpi tui`: живая панель управления демоном.
//!
//! Обновляется раз в секунду из state.json, /metrics и `tc`. Действия
//! (start/stop/reload/doctor) вызывают те же функции, что и CLI-команды.

use anyhow::Result;
use goodbyedpi_daemon::config::DpiConfig;
use goodbyedpi_daemon::control::{self, DaemonState, RunDir};
use goodbyedpi_daemon::profile::{self as lint_profile, Severity};
use goodbyedpi_proto::Stats;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Cell, Paragraph, RenderDirection, Row, Sparkline, Table, Tabs, Wrap,
};
use ratatui::{DefaultTerminal, Frame};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::doctor::{self, Check, DoctorOptions, Status};
use crate::service::{self, StartOptions};
use crate::system;

// С запасом на самые широкие терминалы: на экран берётся хвост под ширину панели
const HISTORY: usize = 600;
const TABS: [&str; 3] = ["Overview", "Doctor", "Profile"];
/// Сколько живёт flash-сообщение: потом оно уже не про текущее состояние
const FLASH_TTL: Duration = Duration::from_secs(8);
/// Окно подтверждения stop повторным `s`
const STOP_CONFIRM: Duration = Duration::from_secs(3);

struct Flash {
    status: Status,
    text: String,
    at: Instant,
}

pub struct TuiOptions {
    pub run_dir: RunDir,
    /// С чем запускать демон по `s`, если он остановлен
    pub start: Option<StartOptions>,
    pub metrics_bind: String,
}

struct IfaceRow {
    name: String,
    operstate: String,
    egress: bool,
    ingress: bool,
}

struct App {
    opts: TuiOptions,
    tab: usize,
    pid: Option<u32>,
    state: Option<DaemonState>,
    stats: Option<Stats>,
    prev_stats: Option<(Instant, Stats)>,
    rates: Stats,
    pps: VecDeque<u64>,
    mpps: VecDeque<u64>,
    ifaces: Vec<IfaceRow>,
    profile: Option<Result<DpiConfig, String>>,
    doctor: Vec<Check>,
    /// Выделенная строка в развёрнутом списке doctor (заголовки групп + проверки)
    doctor_sel: usize,
    /// Раскрытые группы doctor; по умолчанию раскрыты только группы с WARN/FAIL
    doctor_open: Vec<&'static str>,
    message: Option<Flash>,
    stop_armed: Option<Instant>,
    last_refresh: Option<Instant>,
}

impl App {
    fn new(opts: TuiOptions) -> Self {
        Self {
            opts,
            tab: 0,
            pid: None,
            state: None,
            stats: None,
            prev_stats: None,
            rates: Stats::default(),
            pps: VecDeque::with_capacity(HISTORY),
            mpps: VecDeque::with_capacity(HISTORY),
            ifaces: Vec::new(),
            profile: None,
            doctor: Vec::new(),
            doctor_sel: 0,
            doctor_open: Vec::new(),
            message: None,
            stop_armed: None,
            last_refresh: None,
        }
    }

    fn interfaces(&self) -> Vec<String> {
        if let Some(st) = &self.state {
            return st.interfaces.clone();
        }
        if let Some(start) = &self.opts.start {
            return start.interfaces.clone();
        }
        system::guess_interface().into_iter().collect()
    }

    fn refresh(&mut self) {
        self.last_refresh = Some(Instant::now());
        self.pid = self.opts.run_dir.running_pid();
        let new_state = if self.pid.is_some() {
            self.opts.run_dir.read_state().ok().flatten()
        } else {
            None
        };
        // Профиль переразбираем только когда поменялся сам state
        if new_state != self.state || self.profile.is_none() {
            self.profile = new_state.as_ref().map(|st| {
                let v = crate::profile::validate(&service::running_profile(st));
                v.config.ok_or_else(|| v.error.unwrap_or_default())
            });
        }
        self.state = new_state;

        let bind = self
            .state
            .as_ref()
            .and_then(|s| s.metrics_bind.clone())
            .unwrap_or_else(|| self.opts.metrics_bind.clone());
        self.stats = if self.pid.is_some() {
            service::scrape_metrics(&bind).ok()
        } else {
            None
        };

        let now = Instant::now();
        if let Some(cur) = self.stats {
            if let Some((t, prev)) = self.prev_stats {
                let dt = now.duration_since(t).as_secs_f64().max(0.001);
                let rate = |a: u64, b: u64| (a.saturating_sub(b) as f64 / dt).round() as u64;
                self.rates = Stats {
                    packets_total: rate(cur.packets_total, prev.packets_total),
                    packets_tcp: rate(cur.packets_tcp, prev.packets_tcp),
                    packets_udp: rate(cur.packets_udp, prev.packets_udp),
                    packets_ipv6: rate(cur.packets_ipv6, prev.packets_ipv6),
                    packets_http: rate(cur.packets_http, prev.packets_http),
                    packets_tls: rate(cur.packets_tls, prev.packets_tls),
                    packets_quic: rate(cur.packets_quic, prev.packets_quic),
                    packets_modified: rate(cur.packets_modified, prev.packets_modified),
                    events_sent: rate(cur.events_sent, prev.events_sent),
                    errors: rate(cur.errors, prev.errors),
                };
                push_bounded(&mut self.pps, self.rates.packets_total);
                push_bounded(&mut self.mpps, self.rates.packets_modified);
            }
            self.prev_stats = Some((now, cur));
        } else {
            self.prev_stats = None;
            self.rates = Stats::default();
        }

        self.ifaces = self
            .interfaces()
            .into_iter()
            .map(|name| {
                let info = system::interface_info(&name);
                let tc = system::tc_state(&name);
                IfaceRow {
                    operstate: if info.exists {
                        info.operstate
                    } else {
                        "missing".into()
                    },
                    egress: tc.ours_attached("egress"),
                    ingress: tc.ours_attached("ingress"),
                    name,
                }
            })
            .collect();
    }

    fn run_doctor(&mut self) {
        let profile = self
            .state
            .as_ref()
            .map(service::running_profile)
            .or_else(|| self.opts.start.as_ref().map(|s| s.profile.clone()));
        self.doctor = doctor::run(&DoctorOptions {
            interfaces: self.interfaces(),
            profile,
            run_dir: self.opts.run_dir.clone(),
            load_bpf: true,
            metrics_bind: self.opts.metrics_bind.clone(),
        });
        self.doctor_open = Vec::new();
        for c in &self.doctor {
            if c.status >= Status::Warn && !self.doctor_open.contains(&c.group) {
                self.doctor_open.push(c.group);
            }
        }
        // Курсор сразу на первую проблему (FAIL важнее WARN)
        let rows = doctor_rows(self);
        let first = |want: Status| {
            rows.iter()
                .position(|r| matches!(r, DocRow::Check(i) if self.doctor[*i].status == want))
        };
        self.doctor_sel = first(Status::Fail)
            .or_else(|| first(Status::Warn))
            .unwrap_or(0);
        let fails = self
            .doctor
            .iter()
            .filter(|c| c.status == Status::Fail)
            .count();
        let warns = self
            .doctor
            .iter()
            .filter(|c| c.status == Status::Warn)
            .count();
        let (status, text) = if fails > 0 {
            (
                Status::Fail,
                format!("doctor: {} failed, {} warnings", fails, warns),
            )
        } else if warns > 0 {
            (Status::Warn, format!("doctor: {} warnings", warns))
        } else {
            (Status::Pass, "doctor: all checks passed".into())
        };
        self.flash(status, text);
    }

    fn flash(&mut self, status: Status, text: impl Into<String>) {
        self.message = Some(Flash {
            status,
            text: text.into(),
            at: Instant::now(),
        });
    }

    fn stop_armed(&self) -> bool {
        self.pid.is_some() && self.stop_armed.is_some_and(|t| t.elapsed() < STOP_CONFIRM)
    }

    /// Enter: раскрыть/свернуть группу под курсором (на проверке — её группу)
    fn toggle_doctor_group(&mut self) {
        let rows = doctor_rows(self);
        let group = match rows.get(self.doctor_sel) {
            Some(DocRow::Group { group, .. }) => *group,
            Some(DocRow::Check(i)) => self.doctor[*i].group,
            None => return,
        };
        if let Some(pos) = self.doctor_open.iter().position(|g| *g == group) {
            self.doctor_open.remove(pos);
        } else {
            self.doctor_open.push(group);
        }
        // Курсор остаётся на заголовке группы, а не прыгает на чужую строку
        self.doctor_sel = doctor_rows(self)
            .iter()
            .position(|r| matches!(r, DocRow::Group { group: g, .. } if *g == group))
            .unwrap_or(0);
    }

    fn reload(&mut self) {
        let (status, text) = match service::reload(&self.opts.run_dir) {
            Ok(o) if o.ok => (Status::Pass, format!("reload applied: {}", o.message)),
            Ok(o) => (Status::Fail, format!("reload rejected: {}", o.message)),
            Err(e) => (Status::Fail, format!("reload: {:#}", e)),
        };
        self.flash(status, text);
        self.profile = None;
    }

    fn toggle_service(&mut self) {
        if self.pid.is_some() {
            if !self.stop_armed() {
                self.stop_armed = Some(Instant::now());
                self.flash(Status::Warn, "press s again within 3s to stop the daemon");
                return;
            }
            self.stop_armed = None;
            let (status, text) = match service::stop(&self.opts.run_dir) {
                Ok(m) => (Status::Pass, m),
                Err(e) => (Status::Fail, format!("{:#}", e)),
            };
            self.flash(status, text);
        } else if let Some(start) = &self.opts.start {
            let (status, text) = match service::start(start, &self.opts.run_dir) {
                Ok(m) => (Status::Pass, m),
                Err(e) => (Status::Fail, first_line(&format!("{:#}", e))),
            };
            self.flash(status, text);
        } else {
            self.flash(
                Status::Warn,
                "no profile to start with: relaunch as `sudo goodbyedpi tui -i <iface> -f <profile>`",
            );
        }
        self.prev_stats = None;
    }
}

fn first_line(s: &str) -> String {
    s.lines().next().unwrap_or_default().to_string()
}

fn push_bounded(buf: &mut VecDeque<u64>, v: u64) {
    if buf.len() == HISTORY {
        buf.pop_front();
    }
    buf.push_back(v);
}

pub fn run(opts: TuiOptions) -> Result<()> {
    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, App::new(opts));
    ratatui::restore();
    result
}

fn event_loop(terminal: &mut DefaultTerminal, mut app: App) -> Result<()> {
    loop {
        if app
            .last_refresh
            .is_none_or(|t| t.elapsed() >= Duration::from_secs(1))
        {
            app.refresh();
        }
        terminal.draw(|f| draw(f, &app))?;

        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(()),
            KeyCode::Tab | KeyCode::Right => app.tab = (app.tab + 1) % TABS.len(),
            KeyCode::BackTab | KeyCode::Left => app.tab = (app.tab + TABS.len() - 1) % TABS.len(),
            KeyCode::Char('1') => app.tab = 0,
            KeyCode::Char('2') => app.tab = 1,
            KeyCode::Char('3') => app.tab = 2,
            KeyCode::Char('r') => {
                app.reload();
                app.refresh();
            }
            KeyCode::Char('s') => {
                app.toggle_service();
                app.refresh();
            }
            KeyCode::Char('d') => {
                app.tab = 1;
                app.flash(Status::Skip, "running doctor...");
                terminal.draw(|f| draw(f, &app))?;
                app.run_doctor();
            }
            KeyCode::Down | KeyCode::Char('j') if !app.doctor.is_empty() => {
                let last = doctor_rows(&app).len().saturating_sub(1);
                app.doctor_sel = (app.doctor_sel + 1).min(last);
            }
            KeyCode::Enter | KeyCode::Char(' ') if app.tab == 1 => app.toggle_doctor_group(),
            KeyCode::Up | KeyCode::Char('k') => app.doctor_sel = app.doctor_sel.saturating_sub(1),
            _ => {}
        }
    }
}

fn status_color(s: Status) -> Color {
    match s {
        Status::Pass => Color::Green,
        Status::Skip => Color::DarkGray,
        Status::Warn => Color::Yellow,
        Status::Fail => Color::Red,
    }
}

fn panel(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(Color::DarkGray))
        .title(Span::styled(format!(" {} ", title), Style::new().bold()))
}

fn draw(f: &mut Frame, app: &App) {
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .areas(f.area());

    draw_header(f, header, app);
    f.render_widget(
        Tabs::new(TABS)
            .select(app.tab)
            .style(Style::new().fg(Color::DarkGray))
            .highlight_style(Style::new().fg(Color::White).bold().underlined())
            .divider(" "),
        tabs,
    );
    match app.tab {
        0 => draw_overview(f, body, app),
        1 => draw_doctor(f, body, app),
        _ => draw_profile(f, body, app),
    }
    draw_footer(f, footer, app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let mut spans = vec![Span::styled(
        " GoodByeDPI eBPF ",
        Style::new().bold().reversed(),
    )];
    match (app.pid, &app.state) {
        (Some(pid), Some(st)) => {
            let uptime = control::now_secs().saturating_sub(st.started_at);
            spans.push(Span::styled(
                "  ● running",
                Style::new().fg(Color::Green).bold(),
            ));
            spans.push(Span::raw(format!(
                "  pid {} · up {} · v{} · {}",
                pid,
                service::format_duration(uptime),
                st.version,
                st.interfaces.join(", ")
            )));
        }
        (Some(pid), None) => {
            spans.push(Span::styled(
                "  ● starting",
                Style::new().fg(Color::Yellow).bold(),
            ));
            spans.push(Span::raw(format!("  pid {}", pid)));
        }
        _ => spans.push(Span::styled(
            "  ○ stopped",
            Style::new().fg(Color::Red).bold(),
        )),
    }
    f.render_widget(Line::from(spans), area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let [msg, keys] = Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    if let Some(flash) = app.message.as_ref().filter(|m| m.at.elapsed() < FLASH_TTL) {
        f.render_widget(
            Line::from(Span::styled(
                format!(" {}", flash.text),
                Style::new().fg(status_color(flash.status)),
            )),
            msg,
        );
    }

    // Клавиши — без цвета: cyan зарезервирован под живые данные
    let key = |k: &'static str| Span::styled(k, Style::new().fg(Color::White).bold());
    let mut spans = vec![Span::raw(" ")];
    if app.stop_armed() {
        let alarm = Style::new().fg(Color::Red).bold();
        spans.push(Span::styled("s", alarm));
        spans.push(Span::styled(" confirm stop  ", alarm));
    } else {
        spans.push(key("s"));
        spans.push(Span::raw(if app.pid.is_some() {
            " stop  "
        } else {
            " start  "
        }));
    }
    spans.extend([
        key("r"),
        Span::raw(" reload  "),
        key("d"),
        Span::raw(" doctor  "),
    ]);
    if app.tab == 1 && !app.doctor.is_empty() {
        spans.extend([
            key("↑↓"),
            Span::raw(" select  "),
            key("enter"),
            Span::raw(" expand  "),
        ]);
    }
    spans.extend([
        key("tab"),
        Span::raw(" next tab  "),
        key("q"),
        Span::raw(" quit"),
    ]);
    f.render_widget(Line::from(spans).style(Style::new().fg(Color::Gray)), keys);
}

fn fmt_count(v: u64) -> String {
    match v {
        0..=9_999 => v.to_string(),
        10_000..=9_999_999 => format!("{:.1}k", v as f64 / 1e3),
        _ => format!("{:.1}M", v as f64 / 1e6),
    }
}

/// Доля `part/whole` в процентах; None, если знаменатель пуст.
fn share(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| part as f64 * 100.0 / whole as f64)
}

/// Горизонтальный бар из блоков с дробной последней ячейкой.
fn bar(pct: f64, width: u16) -> String {
    const PARTS: [char; 8] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
    let cells = pct.clamp(0.0, 100.0) / 100.0 * f64::from(width);
    let full = cells.floor() as usize;
    let frac = ((cells - cells.floor()) * 8.0).floor() as usize;
    let mut s = "█".repeat(full);
    if frac > 0 && full < usize::from(width) {
        s.push(PARTS[frac - 1]);
    }
    s
}

/// Активные техники профиля одной строкой: "split 1 · oob [1] · auto rst=on…".
fn active_techniques(cfg: &DpiConfig) -> Vec<(&'static str, String)> {
    lint_profile::summarize(cfg)
        .into_iter()
        .filter(|(_, v)| v != "off" && v != "any")
        .filter_map(|(k, v)| {
            if k != "auto" {
                return Some((k, v));
            }
            // "rst=on redirect=off ssl=off" -> "rst"
            let on: Vec<&str> = v
                .split_whitespace()
                .filter_map(|kv| kv.strip_suffix("=on"))
                .collect();
            (!on.is_empty()).then(|| (k, on.join("+")))
        })
        .collect()
}

/// Ответ на главный вопрос экрана: работает ли обход прямо сейчас.
fn verdict(app: &App) -> (Status, &'static str, String) {
    let Some(s) = app.stats else {
        return match (app.pid, &app.opts.start) {
            (Some(_), _) => (
                Status::Warn,
                "no metrics",
                "daemon runs without the metrics endpoint (--no-metrics?)".into(),
            ),
            (None, Some(start)) => (
                Status::Skip,
                "stopped",
                format!(
                    "press s to start on {} · d to diagnose",
                    start.interfaces.join(", ")
                ),
            ),
            (None, None) => (
                Status::Skip,
                "stopped",
                "start: sudo goodbyedpi tui -i <iface> -f <profile> · d to diagnose".into(),
            ),
        };
    };

    let r = app.rates;
    let cfg = match &app.profile {
        Some(Ok(cfg)) => Some(cfg),
        _ => None,
    };
    // QUIC без -g идёт мимо обхода: частая причина «YouTube не грузит»
    let quic_hint = if s.packets_quic > 0 && cfg.is_some_and(|c| !c.ip_fragment) {
        " · QUIC passes through untouched (add -g8)"
    } else {
        ""
    };
    let l7 = s.packets_http + s.packets_tls;

    if r.errors > 0 {
        return (
            Status::Fail,
            "errors",
            format!(
                "{}/s internal eBPF errors · see /run/goodbyedpi/daemon.log",
                fmt_count(r.errors)
            ),
        );
    }
    if l7 == 0 {
        return (
            Status::Skip,
            "waiting",
            format!("no HTTP/TLS traffic seen yet{}", quic_hint),
        );
    }
    if s.packets_modified == 0 {
        return (
            Status::Warn,
            "idle",
            format!(
                "HTTP/TLS seen, nothing modified · port/hostlist filters may not match{}",
                quic_hint
            ),
        );
    }
    let handled = share(s.packets_modified, l7).unwrap_or(0.0).min(100.0);
    (
        Status::Pass,
        "bypass active",
        format!(
            "{:.0}% of HTTP/TLS handled · {} error{}{}",
            handled,
            fmt_count(s.errors),
            if s.errors == 1 { "" } else { "s" },
            quic_hint
        ),
    )
}

fn draw_verdict(f: &mut Frame, area: Rect, app: &App) {
    let (status, label, detail) = verdict(app);
    let color = status_color(status);
    f.render_widget(
        Line::from(vec![
            Span::styled(" ● ", Style::new().fg(color)),
            Span::styled(label, Style::new().fg(color).bold()),
            Span::raw("  "),
            Span::styled(detail, Style::new().fg(Color::Gray)),
        ]),
        area,
    );
}

fn draw_overview(f: &mut Frame, area: Rect, app: &App) {
    // Вердикт сверху; ряд таблиц по высоте счётчиков (10 строк + шапка + рамка); графики — остаток
    let [verdict_area, top, bottom] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(13),
        Constraint::Min(5),
    ])
    .areas(area);
    draw_verdict(f, verdict_area, app);
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(top);

    draw_interfaces(f, left, app);
    draw_traffic(f, right, app);

    let [pps_area, mod_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(bottom);
    draw_history(f, pps_area, "packets/s", &app.pps, Color::Cyan);
    draw_history(f, mod_area, "modified/s", &app.mpps, Color::Magenta);
}

fn draw_interfaces(f: &mut Frame, area: Rect, app: &App) {
    let hook = |on: bool| {
        if on {
            Cell::from("attached").style(Style::new().fg(Color::Green))
        } else {
            Cell::from("—").style(Style::new().fg(Color::DarkGray))
        }
    };
    let rows: Vec<Row> = app
        .ifaces
        .iter()
        .map(|i| {
            let state_style = match i.operstate.as_str() {
                "up" | "unknown" => Style::new().fg(Color::Green),
                "missing" => Style::new().fg(Color::Red),
                _ => Style::new().fg(Color::Yellow),
            };
            Row::new(vec![
                Cell::from(i.name.clone()).style(Style::new().bold()),
                Cell::from(i.operstate.clone()).style(state_style),
                hook(i.egress),
                hook(i.ingress),
            ])
        })
        .collect();

    let table_height = (rows.len() as u16).max(1) + 3;
    let [ifaces_area, info_area] =
        Layout::vertical([Constraint::Length(table_height), Constraint::Min(0)]).areas(area);
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(12),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(9),
            ],
        )
        .header(
            Row::new(["iface", "link", "egress", "ingress"])
                .style(Style::new().fg(Color::DarkGray)),
        )
        .block(panel("Interfaces")),
        ifaces_area,
    );

    // Под интерфейсами: активный профиль, метрики, итог reload
    let label =
        |s: &'static str| Span::styled(format!("{:<9}", s), Style::new().fg(Color::DarkGray));
    let mut lines = Vec::new();
    match (&app.state, &app.profile) {
        (Some(st), profile) => {
            let source = st
                .config_file
                .clone()
                .unwrap_or_else(|| format!("-c \"{}\"", st.config));
            lines.push(Line::from(vec![label("source"), Span::raw(source)]));
            if let Some(Ok(cfg)) = profile {
                let active: Vec<Span> = active_techniques(cfg)
                    .into_iter()
                    .enumerate()
                    .flat_map(|(i, (k, v))| {
                        let sep = if i == 0 { "" } else { " · " };
                        [
                            Span::styled(sep, Style::new().fg(Color::DarkGray)),
                            Span::styled(format!("{} ", k), Style::new().fg(Color::Gray)),
                            Span::styled(v, Style::new().fg(Color::White)),
                        ]
                    })
                    .collect();
                let mut line = vec![label("active")];
                line.extend(active);
                lines.push(Line::from(line));
            }
            if let Some(bind) = &st.metrics_bind {
                lines.push(Line::from(vec![
                    label("metrics"),
                    Span::raw(format!("http://{}/metrics", bind)),
                ]));
            }
            if st.reload.generation > 0 {
                let (color, verdict) = if st.reload.ok {
                    (Color::Green, "applied")
                } else {
                    (Color::Red, "rejected")
                };
                let ago = (st.reload.at > 0)
                    .then(|| control::now_secs().saturating_sub(st.reload.at))
                    .map(|secs| format!(" · {} ago", service::format_duration(secs)))
                    .unwrap_or_default();
                lines.push(Line::from(vec![
                    label("reload"),
                    Span::raw(format!("#{} ", st.reload.generation)),
                    Span::styled(verdict, Style::new().fg(color).bold()),
                    Span::styled(ago, Style::new().fg(Color::DarkGray)),
                ]));
                lines.push(Line::from(vec![
                    label(""),
                    Span::styled(st.reload.message.clone(), Style::new().fg(Color::Gray)),
                ]));
            } else {
                lines.push(Line::from(vec![
                    label("reload"),
                    Span::styled("none yet", Style::new().fg(Color::DarkGray)),
                ]));
            }
        }
        (None, _) => {
            let dim = Style::new().fg(Color::DarkGray);
            match &app.opts.start {
                Some(start) => {
                    let source = start
                        .profile
                        .file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| format!("-c \"{}\"", start.profile.inline));
                    lines.push(Line::from(vec![label("ready"), Span::raw(source)]));
                    lines.push(Line::from(vec![
                        label(""),
                        Span::styled("press s to start, d to check the system first", dim),
                    ]));
                }
                None => {
                    lines.push(Line::from(Span::styled("daemon is not running", dim)));
                    lines.push(Line::from(Span::styled(
                        "to start it from here: sudo goodbyedpi tui -i <iface> -f <profile>",
                        dim,
                    )));
                    lines.push(Line::from(Span::styled(
                        "press d to see why it may not start",
                        dim,
                    )));
                }
            }
        }
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(panel("Session")),
        info_area,
    );
}

fn draw_traffic(f: &mut Frame, area: Rect, app: &App) {
    let block = panel("Traffic");
    let Some(s) = app.stats else {
        let text = if app.pid.is_some() {
            "metrics endpoint unreachable (daemon started with --no-metrics?)"
        } else {
            "no data while the daemon is stopped"
        };
        f.render_widget(
            Paragraph::new(text)
                .style(Style::new().fg(Color::DarkGray))
                .block(block),
            area,
        );
        return;
    };

    let r = app.rates;
    // Ширина бара = всё, что осталось после фиксированных колонок
    let fixed = 10 + 9 + 9 + 7 + 4 + 2;
    let bar_width = area.width.saturating_sub(fixed).max(1);
    // Один знаменатель на всю колонку; доля обхода от HTTP/TLS — в строке-вердикте
    let row = |name: &'static str, total: u64, rate: u64, pct: Option<f64>, color: Color| {
        let (pct_cell, bar_cell) = match pct {
            Some(p) => (
                Cell::from(format!("{:>5.1}%", p)),
                Cell::from(bar(p, bar_width)).style(Style::new().fg(color)),
            ),
            None => (
                Cell::from("    —").style(Style::new().fg(Color::DarkGray)),
                Cell::from(""),
            ),
        };
        Row::new(vec![
            Cell::from(name),
            Cell::from(fmt_count(total)),
            Cell::from(format!("{}/s", fmt_count(rate))).style(Style::new().fg(Color::Cyan)),
            pct_cell,
            bar_cell,
        ])
    };
    let p = s.packets_total;
    let proto = Color::Blue;
    let mut rows = vec![
        row("packets", p, r.packets_total, None, proto),
        row(
            "tcp",
            s.packets_tcp,
            r.packets_tcp,
            share(s.packets_tcp, p),
            proto,
        ),
        row(
            "udp",
            s.packets_udp,
            r.packets_udp,
            share(s.packets_udp, p),
            proto,
        ),
        row(
            "ipv6",
            s.packets_ipv6,
            r.packets_ipv6,
            share(s.packets_ipv6, p),
            proto,
        ),
        row(
            "http",
            s.packets_http,
            r.packets_http,
            share(s.packets_http, p),
            proto,
        ),
        row(
            "tls",
            s.packets_tls,
            r.packets_tls,
            share(s.packets_tls, p),
            proto,
        ),
        row(
            "quic",
            s.packets_quic,
            r.packets_quic,
            share(s.packets_quic, p),
            proto,
        ),
        row(
            "modified",
            s.packets_modified,
            r.packets_modified,
            share(s.packets_modified, p),
            Color::Magenta,
        ),
        row(
            "events",
            s.events_sent,
            r.events_sent,
            share(s.events_sent, p),
            Color::Magenta,
        ),
    ];
    let err_style = if s.errors > 0 {
        Style::new().fg(Color::Red)
    } else {
        Style::new()
    };
    rows.push(row("errors", s.errors, r.errors, None, Color::Red).style(err_style));

    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(7),
                Constraint::Min(1),
            ],
        )
        .header(
            Row::new(["counter", "total", "rate", "share", "of all packets"])
                .style(Style::new().fg(Color::DarkGray)),
        )
        .block(block),
        area,
    );
}

/// Спарклайн, растущий справа: новое значение всегда у правой границы,
/// история подрезается под ширину панели.
fn draw_history(f: &mut Frame, area: Rect, title: &str, history: &VecDeque<u64>, color: Color) {
    let width = usize::from(area.width.saturating_sub(2));
    let data: Vec<u64> = history.iter().rev().take(width).copied().collect();
    let now = data.first().copied().unwrap_or(0);
    let peak = data.iter().copied().max().unwrap_or(0);
    let title = format!(
        "{} · now {} · peak {}",
        title,
        fmt_count(now),
        fmt_count(peak)
    );
    f.render_widget(
        Sparkline::default()
            .data(&data)
            .direction(RenderDirection::RightToLeft)
            .style(Style::new().fg(color))
            .block(panel(&title)),
        area,
    );
}

/// Строка списка doctor: заголовок группы или проверка (индекс в `app.doctor`).
enum DocRow {
    Group {
        group: &'static str,
        total: usize,
        worst: Status,
        problems: usize,
        open: bool,
    },
    Check(usize),
}

/// Группы в порядке doctor; PASS-группы свёрнуты, проблемные раскрыты.
fn doctor_rows(app: &App) -> Vec<DocRow> {
    let mut groups: Vec<&'static str> = Vec::new();
    for c in &app.doctor {
        if !groups.contains(&c.group) {
            groups.push(c.group);
        }
    }
    let mut rows = Vec::new();
    for group in groups {
        let members: Vec<usize> = (0..app.doctor.len())
            .filter(|&i| app.doctor[i].group == group)
            .collect();
        let worst = members
            .iter()
            .map(|&i| app.doctor[i].status)
            .max()
            .unwrap_or(Status::Pass);
        let problems = members
            .iter()
            .filter(|&&i| app.doctor[i].status >= Status::Warn)
            .count();
        let open = app.doctor_open.contains(&group);
        rows.push(DocRow::Group {
            group,
            total: members.len(),
            worst,
            problems,
            open,
        });
        if open {
            rows.extend(members.into_iter().map(DocRow::Check));
        }
    }
    rows
}

fn draw_doctor(f: &mut Frame, area: Rect, app: &App) {
    if app.doctor.is_empty() {
        f.render_widget(
            Paragraph::new(vec![
                Line::from("Press d to run diagnostics."),
                Line::from(""),
                Line::from(Span::styled(
                    "Checks kernel version, BTF, kernel config, capabilities, TC conflicts, \
                     verifier acceptance and live BPF maps.",
                    Style::new().fg(Color::Gray),
                )),
                Line::from(Span::styled(
                    if system::is_root() {
                        "Running as root: verifier trial load enabled."
                    } else {
                        "Not root: verifier and live map checks will be skipped."
                    },
                    Style::new().fg(Color::DarkGray),
                )),
            ])
            .wrap(Wrap { trim: true })
            .block(panel("Doctor")),
            area,
        );
        return;
    }

    let count = |want: Status| app.doctor.iter().filter(|c| c.status == want).count();
    let (pass, warn, fail) = (
        count(Status::Pass),
        count(Status::Warn),
        count(Status::Fail),
    );
    let skipped = match count(Status::Skip) {
        0 => String::new(),
        n => format!(" · {} skipped", n),
    };
    let title = format!(
        "Checks · {} passed · {} warn · {} fail{}",
        pass, warn, fail, skipped
    );

    let [list, detail] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area);
    let rows = doctor_rows(app);
    let table_rows: Vec<Row> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut row = match r {
                DocRow::Group {
                    group,
                    total,
                    worst,
                    problems,
                    open,
                } => {
                    let arrow = if *open { "▾" } else { "▸" };
                    let summary = if *problems == 0 {
                        format!("{}/{} ok", total, total)
                    } else {
                        format!("{} of {} need attention", problems, total)
                    };
                    Row::new(vec![
                        Cell::from(format!("{} {}", arrow, group)).style(Style::new().bold()),
                        Cell::from(summary).style(Style::new().fg(status_color(*worst))),
                    ])
                }
                DocRow::Check(idx) => {
                    let c = &app.doctor[*idx];
                    Row::new(vec![
                        Cell::from(Line::from(vec![
                            Span::raw("  "),
                            Span::styled(
                                c.status.label(),
                                Style::new().fg(status_color(c.status)).bold(),
                            ),
                            Span::raw(format!(" {}", c.title)),
                        ])),
                        Cell::from(c.detail.lines().next().unwrap_or_default().to_string())
                            .style(Style::new().fg(Color::DarkGray)),
                    ])
                }
            };
            if i == app.doctor_sel {
                // Только фон: REVERSED перекрашивал цветные ячейки статуса в плашки
                row = row.style(
                    Style::new()
                        .bg(Color::Indexed(237))
                        .add_modifier(Modifier::BOLD),
                );
            }
            row
        })
        .collect();
    // Прокрутка: держим выделенную строку в окне
    let visible = list.height.saturating_sub(2) as usize;
    let offset = app.doctor_sel.saturating_sub(visible.saturating_sub(1));
    f.render_widget(
        Table::new(
            table_rows.into_iter().skip(offset),
            [Constraint::Length(30), Constraint::Min(10)],
        )
        .block(panel(&title)),
        list,
    );

    let mut lines = Vec::new();
    match rows.get(app.doctor_sel) {
        Some(DocRow::Group { group, open, .. }) => {
            lines.push(Line::from(Span::styled(*group, Style::new().bold())));
            lines.push(Line::from(""));
            for c in app.doctor.iter().filter(|c| c.group == *group) {
                lines.push(Line::from(vec![
                    Span::styled(
                        format!("{} ", c.status.label()),
                        Style::new().fg(status_color(c.status)).bold(),
                    ),
                    Span::raw(format!("{:<20} ", c.title)),
                    Span::styled(
                        c.detail.lines().next().unwrap_or_default().to_string(),
                        Style::new().fg(Color::Gray),
                    ),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                if *open {
                    "enter to collapse"
                } else {
                    "enter to expand"
                },
                Style::new().fg(Color::DarkGray),
            )));
        }
        Some(DocRow::Check(idx)) => {
            let c = &app.doctor[*idx];
            lines.push(Line::from(vec![
                Span::styled(
                    c.status.label(),
                    Style::new().fg(status_color(c.status)).bold(),
                ),
                Span::raw("  "),
                Span::styled(c.title.clone(), Style::new().bold()),
                Span::styled(format!("  · {}", c.group), Style::new().fg(Color::DarkGray)),
            ]));
            lines.push(Line::from(""));
            lines.extend(c.detail.lines().map(|l| Line::from(l.to_string())));
            if let Some(hint) = c.hint.as_ref().filter(|_| c.status >= Status::Warn) {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "fix",
                    Style::new().fg(Color::White).bold().underlined(),
                )));
                lines.extend(hint.lines().map(|l| Line::from(l.to_string())));
            }
        }
        None => {}
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(panel("Details")),
        detail,
    );
}

fn draw_profile(f: &mut Frame, area: Rect, app: &App) {
    let Some(st) = &app.state else {
        f.render_widget(
            Paragraph::new("daemon is not running")
                .style(Style::new().fg(Color::DarkGray))
                .block(panel("Active profile")),
            area,
        );
        return;
    };

    let [left, right] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area);

    // Слева: все параметры профиля
    let mut techniques = Vec::new();
    match &app.profile {
        Some(Ok(cfg)) => {
            // Включённое — сверху и ярко; выключенные техники — одной тусклой строкой
            let (off, rest): (Vec<_>, Vec<_>) = lint_profile::summarize(cfg)
                .into_iter()
                .partition(|(_, v)| v == "off");
            for (k, v) in rest {
                let value_style = if v == "any" {
                    Style::new().fg(Color::DarkGray)
                } else {
                    Style::new().fg(Color::White).bold()
                };
                techniques.push(Line::from(vec![
                    Span::styled(format!("{:<11} ", k), Style::new().fg(Color::Gray)),
                    Span::styled(v, value_style),
                ]));
            }
            if !off.is_empty() {
                let names: Vec<&str> = off.iter().map(|(k, _)| *k).collect();
                techniques.push(Line::from(Span::styled(
                    format!("{:<11} {}", "off", names.join(", ")),
                    Style::new().fg(Color::DarkGray),
                )));
            }
        }
        Some(Err(e)) => techniques.push(Line::from(Span::styled(
            format!("profile on disk no longer parses: {}", e),
            Style::new().fg(Color::Red),
        ))),
        None => {}
    }
    let [tech_area, text_area] = Layout::vertical([
        Constraint::Length(techniques.len() as u16 + 2),
        Constraint::Min(3),
    ])
    .areas(left);
    f.render_widget(
        Paragraph::new(techniques)
            .wrap(Wrap { trim: false })
            .block(panel("Techniques")),
        tech_area,
    );

    // Сам текст профиля с номерами строк: номера совпадают с `goodbyedpi validate`
    let (title, text) = match &st.config_file {
        Some(file) => (
            "Profile file",
            std::fs::read_to_string(file)
                .unwrap_or_else(|e| format!("cannot read {}: {}", file, e)),
        ),
        None => ("Inline profile", st.config.clone()),
    };
    let text_lines: Vec<Line> = text
        .lines()
        .enumerate()
        .map(|(i, l)| {
            let style = if l.trim_start().starts_with('#') {
                Style::new().fg(Color::DarkGray)
            } else {
                Style::new()
            };
            Line::from(vec![
                Span::styled(format!("{:>3} ", i + 1), Style::new().fg(Color::DarkGray)),
                Span::styled(l.to_string(), style),
            ])
        })
        .collect();
    f.render_widget(Paragraph::new(text_lines).block(panel(title)), text_area);

    // Справа: откуда профиль, lint, как применить изменения
    let [source_area, lint_area] =
        Layout::vertical([Constraint::Length(7), Constraint::Min(3)]).areas(right);
    let label =
        |s: &'static str| Span::styled(format!("{:<8}", s), Style::new().fg(Color::DarkGray));
    let mut source = Vec::new();
    if let Some(file) = &st.config_file {
        source.push(Line::from(vec![label("file"), Span::raw(file.clone())]));
    }
    if !st.config.is_empty() {
        source.push(Line::from(vec![
            label("inline"),
            Span::raw(st.config.clone()),
        ]));
    }
    source.push(Line::from(vec![
        label("ifaces"),
        Span::raw(st.interfaces.join(", ")),
    ]));
    // Подсказка про reload имеет смысл только для профиля из файла: inline `-c` не перечитать
    let hint = if st.config_file.is_some() {
        "edit the file, then press r to validate and hot-reload"
    } else {
        "inline -c is fixed for this run; start with -f <file> to hot-reload"
    };
    source.push(Line::from(""));
    source.push(Line::from(Span::styled(
        hint,
        Style::new().fg(Color::DarkGray),
    )));
    f.render_widget(
        Paragraph::new(source)
            .wrap(Wrap { trim: false })
            .block(panel("Source")),
        source_area,
    );

    let mut lint_lines = Vec::new();
    if let Some(Ok(cfg)) = &app.profile {
        let lints = lint_profile::lint(cfg);
        if lints.is_empty() {
            lint_lines.push(Line::from(Span::styled(
                "✓ no issues",
                Style::new().fg(Color::Green),
            )));
        }
        for l in lints {
            let (label, color) = match l.severity {
                Severity::Warning => ("warn ", Color::Yellow),
                Severity::Info => ("info ", Color::Blue),
            };
            lint_lines.push(Line::from(vec![
                Span::styled(label, Style::new().fg(color).bold()),
                Span::raw(l.message),
            ]));
        }
    }
    f.render_widget(
        Paragraph::new(lint_lines)
            .wrap(Wrap { trim: false })
            .block(panel("Lint")),
        lint_area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn sample_app() -> App {
        let mut app = App::new(TuiOptions {
            run_dir: RunDir::new("/nonexistent"),
            start: None,
            metrics_bind: "127.0.0.1:1".into(),
        });
        app.pid = Some(42);
        app.state = Some(DaemonState {
            pid: 42,
            version: "0.1.0".into(),
            started_at: control::now_secs() - 3700,
            interfaces: vec!["eth0".into(), "wlan0".into()],
            config: "s1 -o1 -Ar".into(),
            config_file: None,
            metrics_bind: None,
            reload: control::ReloadStatus {
                generation: 2,
                ok: false,
                message: "changing auto flags requires a restart".into(),
                at: 0,
            },
        });
        app.profile = Some(Ok(DpiConfig::parse("s1 -o1 -Ar -g1400").unwrap()));
        app.stats = Some(Stats {
            packets_total: 123_456,
            packets_tcp: 110_000,
            packets_udp: 13_000,
            packets_ipv6: 2_100,
            packets_http: 700,
            packets_tls: 1_600,
            packets_quic: 900,
            packets_modified: 1_150,
            events_sent: 1_200,
            errors: 1,
        });
        app.pps = (0..HISTORY as u64).map(|i| (i * 37) % 23 + i % 7).collect();
        app.mpps = (0..HISTORY as u64).map(|i| (i * 13) % 5).collect();
        app.ifaces = vec![IfaceRow {
            name: "eth0".into(),
            operstate: "up".into(),
            egress: true,
            ingress: false,
        }];
        let groups = ["kernel", "privileges", "tools", "interfaces", "ebpf"];
        app.doctor = (0..30)
            .map(|i| Check {
                group: groups[i / 6],
                title: format!("check {}", i),
                status: match i {
                    14 => Status::Fail,
                    20 => Status::Warn,
                    _ => Status::Pass,
                },
                detail: "line one\nline two".into(),
                hint: Some("do something".into()),
            })
            .collect();
        app.doctor_open = vec!["interfaces", "ebpf"];
        app.doctor_sel = 3;
        app
    }

    #[test]
    fn renders_all_tabs_at_any_size() {
        let mut app = sample_app();
        for (w, h) in [(140, 40), (80, 24), (30, 8), (10, 3)] {
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            for tab in 0..TABS.len() {
                app.tab = tab;
                terminal.draw(|f| draw(f, &app)).unwrap();
            }
        }
    }

    #[test]
    fn overview_shows_running_state() {
        let app = sample_app();
        let mut terminal = Terminal::new(TestBackend::new(120, 30)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(text.contains("running"));
        assert!(text.contains("123.5k"));
        assert!(text.contains("rejected"));
    }

    /// Текстовый снимок всех вкладок для ручной проверки вёрстки:
    /// `cargo test -p goodbyedpi-cli print_snapshot -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_snapshot() {
        let mut app = sample_app();
        let (w, h) = std::env::var("TUI_SIZE")
            .ok()
            .and_then(|s| {
                let (w, h) = s.split_once('x')?;
                Some((w.parse().ok()?, h.parse().ok()?))
            })
            .unwrap_or((140, 36));
        for (tab, name) in TABS.iter().enumerate() {
            app.tab = tab;
            let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
            terminal.draw(|f| draw(f, &app)).unwrap();
            let buf = terminal.backend().buffer();
            println!("--- {} ---", name);
            for y in 0..h {
                let line: String = (0..w).map(|x| buf[(x, y)].symbol().to_string()).collect();
                println!("{}", line.trim_end());
            }
        }
    }

    #[test]
    fn verdict_reflects_bypass_state() {
        let mut app = sample_app();
        app.rates = Stats::default();
        let (status, label, detail) = verdict(&app);
        assert_eq!((status, label), (Status::Pass, "bypass active"));
        assert!(detail.contains("50% of HTTP/TLS"), "{}", detail);

        app.stats.as_mut().unwrap().packets_modified = 0;
        assert_eq!(verdict(&app).1, "idle");

        app.rates.errors = 3;
        assert_eq!(verdict(&app).0, Status::Fail);

        app.stats = None;
        app.pid = None;
        assert_eq!(verdict(&app).1, "stopped");
    }

    #[test]
    fn doctor_collapses_passing_groups() {
        let app = sample_app();
        let rows = doctor_rows(&app);
        // 5 заголовков + 12 проверок в двух раскрытых группах
        assert_eq!(rows.len(), 5 + 12);
        assert!(matches!(rows[0], DocRow::Group { open: false, .. }));
    }

    #[test]
    fn flash_expires() {
        let mut app = sample_app();
        app.flash(Status::Pass, "done");
        app.message.as_mut().unwrap().at = Instant::now() - FLASH_TTL - Duration::from_secs(1);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(!text.contains("done"));
    }
}
