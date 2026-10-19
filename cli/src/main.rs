use anyhow::{anyhow, Context, Result};
use clap::{Args as ClapArgs, CommandFactory, Parser, Subcommand};
use goodbyedpi_daemon::control::{self, RunDir};
use goodbyedpi_daemon::profile::{summarize, Severity};
use serde::Serialize;
use std::path::PathBuf;

mod doctor;
mod profile;
mod service;
mod system;
mod tui;

use doctor::{DoctorOptions, Status};
use profile::ProfileSource;
use service::StartOptions;

const DEFAULT_METRICS_BIND: &str = "127.0.0.1:9877";

#[derive(Parser, Debug)]
#[command(name = "goodbyedpi")]
#[command(about = "GoodByeDPI eBPF: control, validate and diagnose the daemon")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Cmd>,

    /// Daemon run directory (pid/state files)
    #[arg(long, global = true, default_value = control::DEFAULT_RUN_DIR)]
    run_dir: PathBuf,

    // Старые флаги до появления подкоманд: `goodbyedpi -i eth0 -c ... --daemon|--status|--stop`
    #[arg(short, long, hide = true)]
    interface: Vec<String>,
    #[arg(short, long, hide = true, allow_hyphen_values = true)]
    config: Option<String>,
    #[arg(long, hide = true)]
    daemon: bool,
    #[arg(long, hide = true)]
    status: bool,
    #[arg(long, hide = true)]
    stop: bool,
    #[arg(short, long, hide = true)]
    debug: bool,
}

#[derive(ClapArgs, Debug, Clone, Default)]
struct ProfileArgs {
    /// Inline profile (e.g. "s1 -o1 -Ar")
    #[arg(short, long, allow_hyphen_values = true)]
    config: Option<String>,

    /// Profile file (multiline zapret/winws-like syntax)
    #[arg(short = 'f', long)]
    config_file: Option<PathBuf>,
}

impl ProfileArgs {
    fn source(&self) -> ProfileSource {
        ProfileSource {
            inline: self.config.clone().unwrap_or_default(),
            // Абсолютный путь: демон и `reload` могут работать из другого cwd
            file: self
                .config_file
                .as_ref()
                .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())),
        }
    }
}

#[derive(ClapArgs, Debug, Clone, Default)]
struct IfaceArgs {
    /// Interface(s): repeat -i or comma-separate (default: default-route interface)
    #[arg(short, long, value_delimiter = ',')]
    interface: Vec<String>,
}

impl IfaceArgs {
    fn resolve(&self) -> Result<Vec<String>> {
        if !self.interface.is_empty() {
            return Ok(self.interface.clone());
        }
        system::guess_interface().map(|i| vec![i]).ok_or_else(|| {
            anyhow!("cannot guess the interface (no default route); pass -i <iface>")
        })
    }
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Start the daemon in the background (or --foreground)
    Start {
        #[command(flatten)]
        iface: IfaceArgs,
        #[command(flatten)]
        profile: ProfileArgs,
        /// Replace this process with the daemon (for terminals/containers)
        #[arg(long)]
        foreground: bool,
        /// Validate profile and eBPF object, attach nothing
        #[arg(long)]
        dry_run: bool,
        #[arg(short, long)]
        debug: bool,
        /// Extra daemon arguments, e.g. -- --no-metrics --bpf-printk
        #[arg(last = true)]
        extra: Vec<String>,
    },
    /// Stop the daemon (SIGTERM, waits for TC cleanup)
    Stop,
    /// Validate the daemon's profile, then hot-reload it (SIGHUP)
    Reload,
    /// Show daemon state, hooks and live counters
    Status {
        /// Machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Check a profile without touching the system
    Validate {
        #[command(flatten)]
        profile: ProfileArgs,
        /// Also trial-load the eBPF object into the verifier (root)
        #[arg(long)]
        dry_run: bool,
        /// Treat warnings as errors
        #[arg(long)]
        strict: bool,
    },
    /// Explain why the daemon cannot start or does not work
    Doctor {
        #[command(flatten)]
        iface: IfaceArgs,
        #[command(flatten)]
        profile: ProfileArgs,
        /// Skip the verifier trial load
        #[arg(long)]
        no_load: bool,
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = DEFAULT_METRICS_BIND)]
        metrics_bind: String,
    },
    /// Interactive dashboard
    Tui {
        #[command(flatten)]
        iface: IfaceArgs,
        #[command(flatten)]
        profile: ProfileArgs,
        #[arg(long, default_value = DEFAULT_METRICS_BIND)]
        metrics_bind: String,
    },
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {:#}", e);
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let run_dir = RunDir::new(&cli.run_dir);

    let Some(command) = cli.command else {
        return legacy(&cli, &run_dir);
    };

    match command {
        Cmd::Start {
            iface,
            profile,
            foreground,
            dry_run,
            debug,
            extra,
        } => {
            let opts = StartOptions {
                interfaces: iface.resolve()?,
                profile: profile.source(),
                foreground,
                debug,
                extra,
            };
            if dry_run {
                return start_dry_run(&opts);
            }
            println!("{}", service::start(&opts, &run_dir)?);
            Ok(())
        }
        Cmd::Stop => {
            println!("{}", service::stop(&run_dir)?);
            Ok(())
        }
        Cmd::Reload => {
            let outcome = service::reload(&run_dir)?;
            if outcome.ok {
                println!("reload applied: {}", outcome.message);
                Ok(())
            } else {
                Err(anyhow!("reload rejected: {}", outcome.message))
            }
        }
        Cmd::Status { json } => status(&run_dir, json),
        Cmd::Validate {
            profile,
            dry_run,
            strict,
        } => validate(&profile.source(), dry_run, strict),
        Cmd::Doctor {
            iface,
            profile,
            no_load,
            json,
            metrics_bind,
        } => {
            let src = profile.source();
            let state = run_dir.read_state().ok().flatten();
            // Без явных аргументов диагностируем то, с чем работает демон
            let interfaces = match (&state, iface.interface.is_empty()) {
                (Some(st), true) => st.interfaces.clone(),
                _ => iface.resolve()?,
            };
            let profile = if src.is_empty() {
                state.as_ref().map(service::running_profile)
            } else {
                Some(src)
            };
            let checks = doctor::run(&DoctorOptions {
                interfaces,
                profile,
                run_dir,
                load_bpf: !no_load,
                metrics_bind,
            });
            print_doctor(&checks, json)
        }
        Cmd::Tui {
            iface,
            profile,
            metrics_bind,
        } => {
            let src = profile.source();
            let start = (!iface.interface.is_empty() || !src.is_empty())
                .then(|| -> Result<StartOptions> {
                    Ok(StartOptions {
                        interfaces: iface.resolve()?,
                        profile: src,
                        foreground: false,
                        debug: false,
                        extra: Vec::new(),
                    })
                })
                .transpose()?;
            tui::run(tui::TuiOptions {
                run_dir,
                start,
                metrics_bind,
            })
        }
    }
}

fn legacy(cli: &Cli, run_dir: &RunDir) -> Result<()> {
    if cli.status {
        return status(run_dir, false);
    }
    if cli.stop {
        println!("{}", service::stop(run_dir)?);
        return Ok(());
    }
    if cli.daemon || !cli.interface.is_empty() || cli.config.is_some() {
        let opts = StartOptions {
            interfaces: IfaceArgs {
                interface: cli.interface.clone(),
            }
            .resolve()?,
            profile: ProfileSource {
                inline: cli.config.clone().unwrap_or_else(|| "s1 -o1 -Ar".into()),
                file: None,
            },
            foreground: !cli.daemon,
            debug: cli.debug,
            extra: Vec::new(),
        };
        println!("{}", service::start(&opts, run_dir)?);
        return Ok(());
    }
    Cli::command().print_help()?;
    Ok(())
}

fn print_validation(v: &profile::Validation) {
    if let Some(err) = &v.error {
        println!("✗ profile invalid: {}", err);
        if let Some(loc) = &v.location {
            println!("  --> {}:{}:{}", loc.origin, loc.line, loc.column);
            println!("   | {}", loc.text);
            println!("   | {}^", " ".repeat(loc.column.saturating_sub(1)));
        }
        return;
    }
    if let Some(cfg) = &v.config {
        println!("✓ profile parsed");
        for (k, val) in summarize(cfg) {
            println!("  {:<11} {}", k, val);
        }
    }
    for lint in &v.lints {
        let label = match lint.severity {
            Severity::Warning => "warning",
            Severity::Info => "info",
        };
        println!("  {}: {}", label, lint.message);
    }
}

fn validate(src: &ProfileSource, dry_run: bool, strict: bool) -> Result<()> {
    if src.is_empty() {
        return Err(anyhow!("nothing to validate: pass -c \"...\" or -f <file>"));
    }
    let v = profile::validate(src);
    print_validation(&v);
    if !v.ok() {
        return Err(anyhow!("validation failed"));
    }
    if strict && v.lints.iter().any(|l| l.severity == Severity::Warning) {
        return Err(anyhow!("warnings present (--strict)"));
    }
    if dry_run {
        verify_object()?;
    }
    Ok(())
}

fn verify_object() -> Result<()> {
    let report =
        goodbyedpi_daemon::bpf::inspect_object(goodbyedpi_daemon::bpf::has_bpf_privileges())?;
    println!("✓ eBPF object opened ({} bytes)", report.object_size);
    let abi_ok = report.missing_programs.is_empty() && report.maps.iter().all(|m| m.ok());
    if !abi_ok {
        return Err(anyhow!(
            "eBPF object/userspace ABI mismatch, run `goodbyedpi doctor`"
        ));
    }
    if !report.load_attempted {
        println!("- verifier trial load skipped (needs CAP_BPF or CAP_SYS_ADMIN)");
        return Ok(());
    }
    match &report.load_error {
        None => {
            println!("✓ verifier accepted the programs (nothing attached)");
            Ok(())
        }
        Some(err) => {
            let (why, fix) = doctor::explain_load_failure(err, &report.libbpf_log);
            Err(anyhow!(
                "verifier rejected programs: {}\n  fix: {}",
                why,
                fix
            ))
        }
    }
}

fn start_dry_run(opts: &StartOptions) -> Result<()> {
    println!("interfaces: {}", opts.interfaces.join(", "));
    for iface in &opts.interfaces {
        let info = system::interface_info(iface);
        if !info.exists {
            return Err(anyhow!("interface '{}' does not exist", iface));
        }
        let tc = system::tc_state(iface);
        let plan = if tc.has_clsact {
            "reuse existing clsact qdisc"
        } else {
            "create clsact qdisc"
        };
        println!(
            "  {}: {}, attach dpi_egress + dpi_ingress ({} other bpf filters present)",
            iface,
            plan,
            tc.filters.iter().filter(|f| !f.ours).count()
        );
    }
    let v = profile::validate(&opts.profile);
    print_validation(&v);
    if !v.ok() {
        return Err(anyhow!("validation failed"));
    }
    verify_object()?;
    println!("dry run OK: nothing was changed");
    Ok(())
}

#[derive(Serialize)]
struct IfaceStatus {
    name: String,
    operstate: String,
    egress_attached: bool,
    ingress_attached: bool,
}

#[derive(Serialize)]
struct StatusReport {
    running: bool,
    pid: Option<u32>,
    uptime_secs: Option<u64>,
    state: Option<control::DaemonState>,
    interfaces: Vec<IfaceStatus>,
    stats: Option<std::collections::BTreeMap<&'static str, u64>>,
}

fn stats_map(s: &goodbyedpi_proto::Stats) -> std::collections::BTreeMap<&'static str, u64> {
    [
        ("packets_total", s.packets_total),
        ("packets_tcp", s.packets_tcp),
        ("packets_udp", s.packets_udp),
        ("packets_ipv6", s.packets_ipv6),
        ("packets_http", s.packets_http),
        ("packets_tls", s.packets_tls),
        ("packets_quic", s.packets_quic),
        ("packets_modified", s.packets_modified),
        ("events_sent", s.events_sent),
        ("errors", s.errors),
    ]
    .into_iter()
    .collect()
}

fn status(run_dir: &RunDir, json: bool) -> Result<()> {
    let pid = run_dir.running_pid();
    let state = if pid.is_some() {
        run_dir.read_state().context("reading daemon state")?
    } else {
        None
    };
    let stats = state
        .as_ref()
        .and_then(|s| s.metrics_bind.as_deref())
        .and_then(|bind| service::scrape_metrics(bind).ok());
    let ifaces: Vec<IfaceStatus> = state
        .as_ref()
        .map(|s| s.interfaces.clone())
        .unwrap_or_default()
        .into_iter()
        .map(|name| {
            let tc = system::tc_state(&name);
            IfaceStatus {
                operstate: system::interface_info(&name).operstate,
                egress_attached: tc.ours_attached("egress"),
                ingress_attached: tc.ours_attached("ingress"),
                name,
            }
        })
        .collect();

    let report = StatusReport {
        running: pid.is_some(),
        pid,
        uptime_secs: state
            .as_ref()
            .map(|s| control::now_secs().saturating_sub(s.started_at)),
        stats: stats.as_ref().map(stats_map),
        state,
        interfaces: ifaces,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let Some(pid) = report.pid else {
        println!("○ goodbyedpi-daemon is not running");
        if run_dir.read_pid().is_some() {
            println!("  stale pid file found: previous run crashed, see `goodbyedpi doctor`");
        }
        return Ok(());
    };
    println!(
        "● goodbyedpi-daemon running (pid {}, up {})",
        pid,
        service::format_duration(report.uptime_secs.unwrap_or(0))
    );
    if let Some(st) = &report.state {
        if let Some(file) = &st.config_file {
            println!("  profile file: {}", file);
        }
        if !st.config.is_empty() {
            println!("  profile:      {}", st.config);
        }
        if st.reload.generation > 0 {
            println!(
                "  last reload:  #{} {}: {}",
                st.reload.generation,
                if st.reload.ok { "applied" } else { "REJECTED" },
                st.reload.message
            );
        }
    }
    for i in &report.interfaces {
        let hook = |b: bool| if b { "attached" } else { "MISSING" };
        println!(
            "  {:<10} link {:<8} egress {:<9} ingress {}",
            i.name,
            i.operstate,
            hook(i.egress_attached),
            hook(i.ingress_attached)
        );
    }
    match &report.stats {
        Some(s) => println!(
            "  packets {}  tls {}  quic {}  modified {}  events {}  errors {}",
            s["packets_total"],
            s["packets_tls"],
            s["packets_quic"],
            s["packets_modified"],
            s["events_sent"],
            s["errors"]
        ),
        None => println!("  metrics: unavailable"),
    }
    Ok(())
}

fn print_doctor(checks: &[doctor::Check], json: bool) -> Result<()> {
    let failed = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warned = checks.iter().filter(|c| c.status == Status::Warn).count();

    if json {
        println!("{}", serde_json::to_string_pretty(checks)?);
    } else {
        let color = std::io::IsTerminal::is_terminal(&std::io::stdout());
        let paint = |s: Status| -> String {
            let label = s.label();
            if !color {
                return label.to_string();
            }
            let code = match s {
                Status::Pass => "32",
                Status::Skip => "90",
                Status::Warn => "33",
                Status::Fail => "31;1",
            };
            format!("\x1b[{}m{}\x1b[0m", code, label)
        };
        let mut group = "";
        for c in checks {
            if c.group != group {
                group = c.group;
                println!("\n{}", group);
            }
            let mut lines = c.detail.lines();
            println!(
                "  [{}] {:<22} {}",
                paint(c.status),
                c.title,
                lines.next().unwrap_or("")
            );
            for line in lines {
                println!("  {:>29}{}", "", line);
            }
            if let Some(hint) = &c.hint {
                if c.status >= Status::Warn {
                    for (i, line) in hint.lines().enumerate() {
                        let prefix = if i == 0 { "fix: " } else { "     " };
                        println!("  {:>29}{}{}", "", prefix, line);
                    }
                }
            }
        }
        println!(
            "\n{} checks: {} failed, {} warnings",
            checks.len(),
            failed,
            warned
        );
    }

    if failed > 0 {
        return Err(anyhow!("{} check(s) failed", failed));
    }
    Ok(())
}
