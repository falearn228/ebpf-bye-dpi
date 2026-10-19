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
use ratatui::widgets::{Block, BorderType, Cell, Paragraph, Row, Sparkline, Table, Tabs, Wrap};
use ratatui::{DefaultTerminal, Frame};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::doctor::{self, Check, DoctorOptions, Status};
use crate::service::{self, StartOptions};
use crate::system;

const HISTORY: usize = 120;
const TABS: [&str; 3] = ["Overview", "Doctor", "Profile"];

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
    doctor_sel: usize,
    message: Option<(Status, String)>,
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
        self.doctor_sel = self
            .doctor
            .iter()
            .position(|c| c.status == Status::Fail)
            .or_else(|| self.doctor.iter().position(|c| c.status == Status::Warn))
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
        self.message = Some(if fails > 0 {
            (
                Status::Fail,
                format!("doctor: {} failed, {} warnings", fails, warns),
            )
        } else if warns > 0 {
            (Status::Warn, format!("doctor: {} warnings", warns))
        } else {
            (Status::Pass, "doctor: all checks passed".into())
        });
    }

    fn reload(&mut self) {
        self.message = Some(match service::reload(&self.opts.run_dir) {
            Ok(o) if o.ok => (Status::Pass, format!("reload applied: {}", o.message)),
            Ok(o) => (Status::Fail, format!("reload rejected: {}", o.message)),
            Err(e) => (Status::Fail, format!("reload: {:#}", e)),
        });
        self.profile = None;
    }

    fn toggle_service(&mut self) {
        if self.pid.is_some() {
            let armed = self
                .stop_armed
                .is_some_and(|t| t.elapsed() < Duration::from_secs(3));
            if !armed {
                self.stop_armed = Some(Instant::now());
                self.message = Some((Status::Warn, "press s again to stop the daemon".into()));
                return;
            }
            self.stop_armed = None;
            self.message = Some(match service::stop(&self.opts.run_dir) {
                Ok(m) => (Status::Pass, m),
                Err(e) => (Status::Fail, format!("{:#}", e)),
            });
        } else if let Some(start) = &self.opts.start {
            self.message = Some(match service::start(start, &self.opts.run_dir) {
                Ok(m) => (Status::Pass, m),
                Err(e) => (Status::Fail, first_line(&format!("{:#}", e))),
            });
        } else {
            self.message = Some((
                Status::Warn,
                "daemon stopped; launch `goodbyedpi tui -i <iface> -c <profile>` to start it from here"
                    .into(),
            ));
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
                app.message = Some((Status::Skip, "running doctor...".into()));
                terminal.draw(|f| draw(f, &app))?;
                app.run_doctor();
            }
            KeyCode::Down | KeyCode::Char('j') if !app.doctor.is_empty() => {
                app.doctor_sel = (app.doctor_sel + 1).min(app.doctor.len() - 1);
            }
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
            .highlight_style(Style::new().fg(Color::Cyan).bold())
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
    if let Some((status, text)) = &app.message {
        f.render_widget(
            Line::from(Span::styled(
                format!(" {}", text),
                Style::new().fg(status_color(*status)),
            )),
            msg,
        );
    }
    let action = if app.pid.is_some() { "stop" } else { "start" };
    let key = |k: &'static str| Span::styled(k, Style::new().fg(Color::Cyan).bold());
    f.render_widget(
        Line::from(vec![
            Span::raw(" "),
            key("s"),
            Span::raw(format!(" {}  ", action)),
            key("r"),
            Span::raw(" reload  "),
            key("d"),
            Span::raw(" doctor  "),
            key("tab"),
            Span::raw(" switch  "),
            key("↑↓"),
            Span::raw(" select  "),
            key("q"),
            Span::raw(" quit"),
        ])
        .style(Style::new().fg(Color::Gray)),
        keys,
    );
}

fn fmt_count(v: u64) -> String {
    match v {
        0..=9_999 => v.to_string(),
        10_000..=9_999_999 => format!("{:.1}k", v as f64 / 1e3),
        _ => format!("{:.1}M", v as f64 / 1e6),
    }
}

fn draw_overview(f: &mut Frame, area: Rect, app: &App) {
    let [top, bottom] = Layout::vertical([Constraint::Min(8), Constraint::Length(9)]).areas(area);
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(top);

    // Интерфейсы и состояние хуков
    let hook = |on: bool| {
        if on {
            Cell::from("attached").style(Style::new().fg(Color::Green))
        } else {
            Cell::from("—").style(Style::new().fg(Color::DarkGray))
        }
    };
    let rows = app.ifaces.iter().map(|i| {
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
    });
    let mut lines_below = Vec::new();
    if let Some(st) = &app.state {
        if st.reload.generation > 0 {
            let (color, verdict) = if st.reload.ok {
                (Color::Green, "applied")
            } else {
                (Color::Red, "rejected")
            };
            lines_below.push(Line::from(vec![
                Span::raw(format!("last reload #{}: ", st.reload.generation)),
                Span::styled(verdict, Style::new().fg(color)),
            ]));
            lines_below.push(Line::from(Span::styled(
                st.reload.message.clone(),
                Style::new().fg(Color::Gray),
            )));
        }
    }
    let [ifaces_area, reload_area] = Layout::vertical([
        Constraint::Min(4),
        Constraint::Length(lines_below.len() as u16 + 2),
    ])
    .areas(left);
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
    if !lines_below.is_empty() {
        f.render_widget(
            Paragraph::new(lines_below)
                .wrap(Wrap { trim: true })
                .block(panel("Reload")),
            reload_area,
        );
    }

    // Счётчики
    let stats_block = panel("Traffic");
    match app.stats {
        Some(s) => {
            let r = app.rates;
            let row = |name: &'static str, total: u64, rate: u64| {
                Row::new(vec![
                    Cell::from(name),
                    Cell::from(fmt_count(total)),
                    Cell::from(format!("{}/s", fmt_count(rate)))
                        .style(Style::new().fg(Color::Cyan)),
                ])
            };
            let mut rows = vec![
                row("packets", s.packets_total, r.packets_total),
                row("tcp", s.packets_tcp, r.packets_tcp),
                row("udp", s.packets_udp, r.packets_udp),
                row("ipv6", s.packets_ipv6, r.packets_ipv6),
                row("http", s.packets_http, r.packets_http),
                row("tls", s.packets_tls, r.packets_tls),
                row("quic", s.packets_quic, r.packets_quic),
                row("modified", s.packets_modified, r.packets_modified),
                row("events", s.events_sent, r.events_sent),
            ];
            let err_style = if s.errors > 0 {
                Style::new().fg(Color::Red)
            } else {
                Style::new()
            };
            rows.push(row("errors", s.errors, r.errors).style(err_style));
            f.render_widget(
                Table::new(
                    rows,
                    [
                        Constraint::Length(10),
                        Constraint::Length(10),
                        Constraint::Length(10),
                    ],
                )
                .header(
                    Row::new(["counter", "total", "rate"]).style(Style::new().fg(Color::DarkGray)),
                )
                .block(stats_block),
                right,
            );
        }
        None => {
            let text = if app.pid.is_some() {
                "metrics endpoint unreachable (daemon started with --no-metrics?)"
            } else {
                "daemon is not running"
            };
            f.render_widget(
                Paragraph::new(text)
                    .style(Style::new().fg(Color::DarkGray))
                    .block(stats_block),
                right,
            );
        }
    }

    // История pps
    let [pps_area, mod_area] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(bottom);
    let pps: Vec<u64> = app.pps.iter().copied().collect();
    let mpps: Vec<u64> = app.mpps.iter().copied().collect();
    f.render_widget(
        Sparkline::default()
            .data(&pps)
            .style(Style::new().fg(Color::Cyan))
            .block(panel(&format!(
                "packets/s · {}",
                fmt_count(app.rates.packets_total)
            ))),
        pps_area,
    );
    f.render_widget(
        Sparkline::default()
            .data(&mpps)
            .style(Style::new().fg(Color::Magenta))
            .block(panel(&format!(
                "modified/s · {}",
                fmt_count(app.rates.packets_modified)
            ))),
        mod_area,
    );
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

    let [list, detail] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
    let rows: Vec<Row> = app
        .doctor
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let mut row = Row::new(vec![
                Cell::from(c.status.label()).style(Style::new().fg(status_color(c.status)).bold()),
                Cell::from(c.group).style(Style::new().fg(Color::DarkGray)),
                Cell::from(c.title.clone()),
            ]);
            if i == app.doctor_sel {
                row = row.style(Style::new().add_modifier(Modifier::REVERSED));
            }
            row
        })
        .collect();
    // Прокрутка: держим выделенную строку в окне
    let visible = list.height.saturating_sub(2) as usize;
    let offset = app.doctor_sel.saturating_sub(visible.saturating_sub(1));
    f.render_widget(
        Table::new(
            rows.into_iter().skip(offset),
            [
                Constraint::Length(4),
                Constraint::Length(10),
                Constraint::Min(10),
            ],
        )
        .block(panel("Checks")),
        list,
    );

    if let Some(c) = app.doctor.get(app.doctor_sel) {
        let mut lines = vec![
            Line::from(vec![
                Span::styled(
                    c.status.label(),
                    Style::new().fg(status_color(c.status)).bold(),
                ),
                Span::raw("  "),
                Span::styled(c.title.clone(), Style::new().bold()),
            ]),
            Line::from(""),
        ];
        lines.extend(c.detail.lines().map(|l| Line::from(l.to_string())));
        if let Some(hint) = &c.hint {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "fix:",
                Style::new().fg(Color::Cyan).bold(),
            )));
            lines
                .extend(hint.lines().map(|l| {
                    Line::from(Span::styled(l.to_string(), Style::new().fg(Color::Cyan)))
                }));
        }
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(panel("Details")),
            detail,
        );
    }
}

fn draw_profile(f: &mut Frame, area: Rect, app: &App) {
    let block = panel("Active profile");
    let Some(st) = &app.state else {
        f.render_widget(
            Paragraph::new("daemon is not running")
                .style(Style::new().fg(Color::DarkGray))
                .block(block),
            area,
        );
        return;
    };

    let mut lines = vec![];
    if let Some(file) = &st.config_file {
        lines.push(Line::from(vec![
            Span::styled("file    ", Style::new().fg(Color::DarkGray)),
            Span::raw(file.clone()),
        ]));
    }
    if !st.config.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("inline  ", Style::new().fg(Color::DarkGray)),
            Span::raw(st.config.clone()),
        ]));
    }
    lines.push(Line::from(""));
    match &app.profile {
        Some(Ok(cfg)) => {
            for (k, v) in lint_profile::summarize(cfg) {
                let style = if v == "off" || v == "any" {
                    Style::new().fg(Color::DarkGray)
                } else {
                    Style::new()
                };
                lines.push(Line::from(vec![
                    Span::styled(format!("{:<11} ", k), Style::new().fg(Color::Gray)),
                    Span::styled(v, style),
                ]));
            }
            let lints = lint_profile::lint(cfg);
            if !lints.is_empty() {
                lines.push(Line::from(""));
            }
            for l in lints {
                let (label, color) = match l.severity {
                    Severity::Warning => ("warn ", Color::Yellow),
                    Severity::Info => ("info ", Color::Blue),
                };
                lines.push(Line::from(vec![
                    Span::styled(label, Style::new().fg(color).bold()),
                    Span::raw(l.message),
                ]));
            }
        }
        Some(Err(e)) => lines.push(Line::from(Span::styled(
            format!("profile on disk no longer parses: {}", e),
            Style::new().fg(Color::Red),
        ))),
        None => {}
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "The view reflects the profile file on disk; press r to validate it and hot-reload the daemon.",
        Style::new().fg(Color::DarkGray),
    )));
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block),
        area,
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
            errors: 1,
            ..Stats::default()
        });
        app.pps = (0..HISTORY as u64).collect();
        app.ifaces = vec![IfaceRow {
            name: "eth0".into(),
            operstate: "up".into(),
            egress: true,
            ingress: false,
        }];
        app.doctor = (0..30)
            .map(|i| Check {
                group: "kernel",
                title: format!("check {}", i),
                status: if i % 3 == 0 {
                    Status::Fail
                } else {
                    Status::Pass
                },
                detail: "line one\nline two".into(),
                hint: Some("do something".into()),
            })
            .collect();
        app.doctor_sel = 25;
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
}
