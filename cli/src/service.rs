//! Управление процессом демона: start/stop/reload через pid/state файлы
//! и сигналы, плюс чтение live-метрик с Prometheus endpoint.

use anyhow::{anyhow, Context, Result};
use goodbyedpi_daemon::control::{DaemonState, RunDir};
use goodbyedpi_proto::Stats;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::profile::{self, ProfileSource};

pub const LOG_FILE: &str = "daemon.log";

/// Путь к бинарнику демона: $GOODBYEDPI_DAEMON, соседний файл, затем PATH.
pub fn daemon_binary() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("GOODBYEDPI_DAEMON") {
        return Ok(PathBuf::from(path));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(sibling) = exe.parent().map(|d| d.join("goodbyedpi-daemon")) {
            if sibling.is_file() {
                return Ok(sibling);
            }
        }
    }
    if let Some(paths) = std::env::var_os("PATH") {
        if let Some(found) = std::env::split_paths(&paths)
            .map(|d| d.join("goodbyedpi-daemon"))
            .find(|p| p.is_file())
        {
            return Ok(found);
        }
    }
    Err(anyhow!(
        "goodbyedpi-daemon binary not found (set GOODBYEDPI_DAEMON or install it into PATH)"
    ))
}

#[derive(Debug, Clone)]
pub struct StartOptions {
    pub interfaces: Vec<String>,
    pub profile: ProfileSource,
    pub foreground: bool,
    pub debug: bool,
    /// Дополнительные аргументы демона после `--`
    pub extra: Vec<String>,
}

fn daemon_args(opts: &StartOptions, run_dir: &RunDir) -> Vec<String> {
    let mut args = vec!["-i".to_string(), opts.interfaces.join(",")];
    if !opts.profile.inline.trim().is_empty() {
        args.push("-c".into());
        args.push(opts.profile.inline.clone());
    }
    if let Some(file) = &opts.profile.file {
        args.push("--config-file".into());
        args.push(file.display().to_string());
    }
    args.push("--run-dir".into());
    args.push(run_dir.path().display().to_string());
    if opts.debug {
        args.push("--debug".into());
    }
    args.extend(opts.extra.iter().cloned());
    args
}

pub fn start(opts: &StartOptions, run_dir: &RunDir) -> Result<String> {
    if let Some(pid) = run_dir.running_pid() {
        return Err(anyhow!(
            "daemon already running (pid {}); use `goodbyedpi reload` to apply a new profile",
            pid
        ));
    }

    let validation = profile::validate(&opts.profile);
    if let Some(err) = &validation.error {
        return Err(anyhow!(
            "profile is invalid, not starting: {} (run `goodbyedpi validate`)",
            err
        ));
    }

    if !crate::system::is_root() {
        return Err(anyhow!(
            "starting the daemon needs root or CAP_BPF+CAP_NET_ADMIN+CAP_NET_RAW: \
             re-run with sudo, or use `systemctl start goodbyedpi`"
        ));
    }

    let bin = daemon_binary()?;
    let args = daemon_args(opts, run_dir);

    if opts.foreground {
        let err = Command::new(&bin).args(&args).exec();
        return Err(anyhow!("failed to exec {}: {}", bin.display(), err));
    }

    std::fs::create_dir_all(run_dir.path())
        .with_context(|| format!("Failed to create {}", run_dir.path().display()))?;
    let log_path = run_dir.path().join(LOG_FILE);
    let log = std::fs::File::create(&log_path)
        .with_context(|| format!("Failed to create {}", log_path.display()))?;

    let mut child = Command::new(&bin)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        // Отдельная группа процессов: Ctrl+C в терминале не убьёт демон
        .process_group(0)
        .spawn()
        .with_context(|| format!("Failed to spawn {}", bin.display()))?;

    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            let tail = log_tail(&log_path, 15);
            return Err(anyhow!(
                "daemon exited during startup ({})\n--- {} ---\n{}\n---\n\
                 Run `sudo goodbyedpi doctor -i {}` to find out why.",
                status,
                log_path.display(),
                tail,
                opts.interfaces.join(",")
            ));
        }
        if run_dir
            .read_state()
            .ok()
            .flatten()
            .is_some_and(|s| s.pid == pid)
        {
            return Ok(format!(
                "goodbyedpi-daemon started (pid {}) on {}; log: {}",
                pid,
                opts.interfaces.join(", "),
                log_path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(anyhow!(
        "daemon (pid {}) did not become ready in 15s, see {}",
        pid,
        log_path.display()
    ))
}

pub fn log_tail(path: &std::path::Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn send_signal(pid: u32, signal: libc::c_int) -> Result<()> {
    // SAFETY: kill без побочных эффектов на память процесса
    let rc = unsafe { libc::kill(pid as libc::pid_t, signal) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        let hint = if err.raw_os_error() == Some(libc::EPERM) {
            " (permission denied: use sudo)"
        } else {
            ""
        };
        return Err(anyhow!("failed to signal pid {}: {}{}", pid, err, hint));
    }
    Ok(())
}

pub fn stop(run_dir: &RunDir) -> Result<String> {
    let Some(pid) = run_dir.running_pid() else {
        return Ok("daemon is not running".to_string());
    };
    send_signal(pid, libc::SIGTERM)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if !goodbyedpi_daemon::control::daemon_alive(pid) {
            return Ok(format!("daemon (pid {}) stopped, TC hooks removed", pid));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(anyhow!(
        "daemon (pid {}) still alive after 10s; TC hooks may remain, check `goodbyedpi doctor`",
        pid
    ))
}

/// Профиль, с которым работает демон, читается из его state.json.
pub fn running_profile(state: &DaemonState) -> ProfileSource {
    ProfileSource {
        inline: state.config.clone(),
        file: state.config_file.as_ref().map(PathBuf::from),
    }
}

/// Пути к hostlist/ipset в профиле относительные к cwd демона — валидируем оттуда же.
fn enter_daemon_cwd(pid: u32) {
    if let Ok(cwd) = std::fs::read_link(format!("/proc/{}/cwd", pid)) {
        let _ = std::env::set_current_dir(cwd);
    }
}

#[derive(Debug, Clone)]
pub struct ReloadOutcome {
    pub ok: bool,
    pub message: String,
}

/// Безопасный reload: профиль проверяется локально до отправки SIGHUP,
/// затем ждём, пока демон сам отчитается о результате в state.json.
pub fn reload(run_dir: &RunDir) -> Result<ReloadOutcome> {
    let pid = run_dir
        .running_pid()
        .ok_or_else(|| anyhow!("daemon is not running"))?;
    let state = run_dir.read_state()?.ok_or_else(|| {
        anyhow!(
            "daemon state file missing: {}",
            run_dir.state_path().display()
        )
    })?;

    let previous_cwd = std::env::current_dir().ok();
    enter_daemon_cwd(pid);
    let validation = profile::validate(&running_profile(&state));
    if let Some(cwd) = previous_cwd {
        let _ = std::env::set_current_dir(cwd);
    }
    if let Some(err) = validation.error {
        return Ok(ReloadOutcome {
            ok: false,
            message: format!("profile invalid, daemon NOT signalled: {}", err),
        });
    }

    let generation = state.reload.generation;
    send_signal(pid, libc::SIGHUP)?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Some(st) = run_dir.read_state().ok().flatten() {
            if st.reload.generation > generation {
                return Ok(ReloadOutcome {
                    ok: st.reload.ok,
                    message: st.reload.message,
                });
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(anyhow!("daemon did not report reload result within 5s"))
}

/// Снимает /metrics и раскладывает в Stats. Таймауты короткие: TUI не должен залипать.
pub fn scrape_metrics(bind: &str) -> Result<Stats> {
    let addr = bind
        .to_socket_addrs()
        .context("bad metrics address")?
        .next()
        .ok_or_else(|| anyhow!("bad metrics address"))?;
    let timeout = Duration::from_millis(300);
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    stream.write_all(b"GET /metrics HTTP/1.0\r\n\r\n")?;
    let mut body = String::new();
    stream.read_to_string(&mut body)?;
    Ok(parse_metrics(&body))
}

pub fn parse_metrics(text: &str) -> Stats {
    let mut s = Stats::default();
    for line in text.lines().filter(|l| l.starts_with("goodbyedpi_")) {
        let mut it = line.split_whitespace();
        let (Some(name), Some(value)) = (it.next(), it.next()) else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        let slot = match name {
            "goodbyedpi_packets_total" => &mut s.packets_total,
            "goodbyedpi_packets_tcp" => &mut s.packets_tcp,
            "goodbyedpi_packets_udp" => &mut s.packets_udp,
            "goodbyedpi_packets_ipv6" => &mut s.packets_ipv6,
            "goodbyedpi_packets_http" => &mut s.packets_http,
            "goodbyedpi_packets_tls" => &mut s.packets_tls,
            "goodbyedpi_packets_quic" => &mut s.packets_quic,
            "goodbyedpi_packets_modified" => &mut s.packets_modified,
            "goodbyedpi_events_sent" => &mut s.events_sent,
            "goodbyedpi_errors" => &mut s.errors,
            _ => continue,
        };
        *slot = value;
    }
    s
}

pub fn format_duration(secs: u64) -> String {
    let (d, h, m, s) = (
        secs / 86400,
        secs % 86400 / 3600,
        secs % 3600 / 60,
        secs % 60,
    );
    if d > 0 {
        format!("{}d{:02}h{:02}m", d, h, m)
    } else if h > 0 {
        format!("{}h{:02}m", h, m)
    } else {
        format!("{}m{:02}s", m, s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_prometheus_text() {
        let text = "HTTP/1.1 200 OK\r\n\r\n# HELP x\ngoodbyedpi_packets_total 42\ngoodbyedpi_errors 3\nother 9\n";
        let s = parse_metrics(text);
        assert_eq!(s.packets_total, 42);
        assert_eq!(s.errors, 3);
    }

    #[test]
    fn formats_uptime() {
        assert_eq!(format_duration(59), "0m59s");
        assert_eq!(format_duration(3700), "1h01m");
        assert_eq!(format_duration(90000), "1d01h00m");
    }
}
