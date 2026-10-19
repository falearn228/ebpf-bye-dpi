use anyhow::{anyhow, Context, Result};
use clap::Parser;
use goodbyedpi_proto::Stats;
use log::{error, info, warn};
use std::sync::Arc;
use tokio::sync::{mpsc, watch, RwLock};

use goodbyedpi_daemon::auto_logic::AutoLogic;
use goodbyedpi_daemon::bpf::{self, BpfManager};
use goodbyedpi_daemon::config::DpiConfig;
use goodbyedpi_daemon::control::{self, DaemonState, ReloadStatus, RunDir};
use goodbyedpi_daemon::metrics;
use goodbyedpi_daemon::profile;
use goodbyedpi_daemon::ringbuf::EventProcessor;

#[derive(Parser, Debug)]
#[command(name = "goodbyedpi-daemon")]
#[command(about = "eBPF-based GoodByeDPI implementation")]
#[command(version)]
struct Args {
    /// Interface(s) to attach to: repeat -i or use a comma list (eth0,wlan0)
    #[arg(short, long, value_delimiter = ',', default_value = "eth0")]
    interface: Vec<String>,

    /// Config string (e.g., "s1 -o1 -Ar -f-1 -r1+s -At -As")
    #[arg(short, long, default_value = "", allow_hyphen_values = true)]
    config: String,

    /// Path to a config/profile file with multiline zapret/winws-like arguments
    #[arg(long)]
    config_file: Option<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    /// Prometheus metrics bind address (e.g. 127.0.0.1:9877)
    #[arg(long, default_value = "127.0.0.1:9877")]
    metrics_bind: String,

    /// Disable Prometheus metrics endpoint
    #[arg(long)]
    no_metrics: bool,

    /// Enable bpf_printk logs in eBPF (writes into trace_pipe)
    #[arg(long)]
    bpf_printk: bool,

    /// Directory for pid/state files used by `goodbyedpi status|reload|stop`
    #[arg(long, default_value = control::DEFAULT_RUN_DIR)]
    run_dir: String,

    /// Parse profile and verify the eBPF object, but attach nothing
    #[arg(long)]
    dry_run: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_default_env()
        .filter_level(if args.debug {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Info
        })
        .init();

    let interfaces = normalize_interfaces(&args.interface)?;

    // Parse configuration
    let parsed_config = load_config(&args)?;

    if args.dry_run {
        return dry_run(&interfaces, &parsed_config);
    }

    info!("Starting GoodByeDPI eBPF daemon");
    info!("Interfaces: {}", interfaces.join(", "));
    info!("Config: {}", args.config);
    if let Some(path) = &args.config_file {
        info!("Config file: {}", path);
    }
    info!(
        "Metrics endpoint: {}",
        if args.no_metrics {
            "disabled"
        } else {
            &args.metrics_bind
        }
    );
    info!(
        "eBPF bpf_printk: {}",
        if args.bpf_printk {
            "enabled"
        } else {
            "disabled"
        }
    );

    let run_dir = RunDir::new(&args.run_dir);
    let _run_guard = run_dir.acquire()?;

    // Check if any auto-logic is enabled
    let auto_flags = (
        parsed_config.auto_rst,
        parsed_config.auto_redirect,
        parsed_config.auto_ssl,
    );
    let (auto_rst, auto_redirect, auto_ssl) = auto_flags;

    let config = Arc::new(RwLock::new(parsed_config));
    info!("Parsed config: {:?}", config.read().await);

    // Create auto-logic state machine if any auto mode is enabled
    let auto_logic: Option<Arc<AutoLogic>> = if auto_rst || auto_redirect || auto_ssl {
        let al = AutoLogic::new(auto_rst, auto_redirect, auto_ssl);
        info!(
            "Auto-logic enabled: RST={}, Redirect={}, SSL={}",
            auto_rst, auto_redirect, auto_ssl
        );
        Some(Arc::new(al))
    } else {
        info!("Auto-logic disabled (use -Ar, -At, -As to enable)");
        None
    };

    // Load and attach eBPF programs: отдельный экземпляр объекта на интерфейс
    let mut managers: Vec<BpfManager> = Vec::with_capacity(interfaces.len());
    for iface in &interfaces {
        match BpfManager::load_and_attach(iface, config.clone()).await {
            Ok(manager) => {
                info!(
                    "eBPF programs loaded and attached successfully on {}",
                    iface
                );
                managers.push(manager);
            }
            Err(e) => {
                // Откатываем уже подключённые интерфейсы, чтобы не оставить TC-хуки
                for manager in managers {
                    manager.shutdown();
                }
                return Err(e.context(format!(
                    "Failed to load and attach eBPF programs to interface '{}' \
                     (run `goodbyedpi doctor -i {}` for a diagnosis)",
                    iface, iface
                )));
            }
        }
    }

    // Один канал обновлений конфига на все интерфейсы (auto-logic и hot reload)
    let config_update_tx = spawn_config_fanout(
        managers
            .iter_mut()
            .filter_map(BpfManager::take_config_sender)
            .collect(),
    )?;

    // Create event processor with auto-logic if enabled
    let event_processor = if let Some(ref al) = auto_logic {
        EventProcessor::with_auto_logic_and_channel(al.clone(), config_update_tx.clone())
            .context("Failed to create event processor with auto-logic and config channel")?
    } else {
        EventProcessor::new().context("Failed to create event processor")?
    };

    info!("Event processor started");

    let event_rx = merge_event_receivers(&mut managers)?;

    let stats_snapshot = Arc::new(RwLock::new(Stats::default()));
    let stats_receivers: Vec<watch::Receiver<Stats>> = managers
        .iter_mut()
        .filter_map(BpfManager::take_stats_receiver)
        .collect();
    if stats_receivers.is_empty() {
        warn!("Stats receiver not available, metrics will stay at zero");
    } else {
        spawn_stats_aggregator(stats_receivers, stats_snapshot.clone());
    }

    if !args.no_metrics {
        let bind_addr = args.metrics_bind.clone();
        let stats_for_metrics = stats_snapshot.clone();
        tokio::spawn(async move {
            if let Err(e) = metrics::run_prometheus_server(bind_addr, stats_for_metrics).await {
                log::error!("Metrics server failed: {}", e);
            }
        });
    }

    let mut daemon_state = DaemonState {
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        started_at: control::now_secs(),
        interfaces: interfaces.clone(),
        config: args.config.clone(),
        config_file: args.config_file.clone(),
        metrics_bind: (!args.no_metrics).then(|| args.metrics_bind.clone()),
        reload: ReloadStatus::default(),
    };
    if let Err(e) = run_dir.write_state(&daemon_state) {
        warn!("Failed to write daemon state: {:#}", e);
    }

    // Spawn event processing task
    let config_clone = config.clone();
    let mut event_handle = tokio::spawn(async move {
        event_processor.run(event_rx, config_clone).await;
    });

    // Main loop
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

    // Handle Ctrl+C, SIGTERM and SIGHUP (hot reload)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("Failed to set up SIGTERM signal handler")?;
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .context("Failed to set up SIGHUP signal handler")?;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Cleanup expired connections
                for manager in managers.iter_mut() {
                    if let Err(e) = manager.cleanup_connections().await {
                        log::warn!("Connection cleanup error: {}", e);
                    }
                }

                // Cleanup auto-logic states if enabled
                if let Some(ref al) = auto_logic {
                    let cleaned = al.cleanup().await;
                    if cleaned > 0 {
                        log::debug!("Auto-logic cleaned up {} expired states", cleaned);
                    }

                    // Log stats periodically
                    let stats = al.get_stats().await;
                    if stats.total_connections > 0 {
                        log::debug!("Auto-logic stats: {}", stats);
                    }
                }
            }
            _ = sighup.recv() => {
                info!("Received SIGHUP, reloading configuration...");
                let generation = daemon_state.reload.generation + 1;
                daemon_state.reload = match reload_config(&args, &config, &config_update_tx, auto_flags).await {
                    Ok(message) => {
                        info!("Reload #{} applied: {}", generation, message);
                        ReloadStatus { generation, ok: true, message, at: control::now_secs() }
                    }
                    Err(e) => {
                        let message = format!("{:#}", e);
                        error!("Reload #{} rejected, keeping previous config: {}", generation, message);
                        ReloadStatus { generation, ok: false, message, at: control::now_secs() }
                    }
                };
                if let Err(e) = run_dir.write_state(&daemon_state) {
                    warn!("Failed to write daemon state: {:#}", e);
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                break;
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
                break;
            }
            _ = &mut event_handle => {
                log::error!("Event processing task exited unexpectedly");
                break;
            }
        }
    }

    // Cleanup
    info!("Cleaning up...");

    // Gracefully shutdown BPF managers (waits for threads to finish)
    for manager in managers {
        manager.shutdown();
    }

    info!("Goodbye!");
    Ok(())
}

fn normalize_interfaces(raw: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for iface in raw.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if !out.iter().any(|known| known == iface) {
            out.push(iface.to_string());
        }
    }
    if out.is_empty() {
        return Err(anyhow!("No network interface given (-i eth0)"));
    }
    Ok(out)
}

fn load_config(args: &Args) -> Result<DpiConfig> {
    let merged_config = load_merged_config(args)
        .with_context(|| "Failed to load CLI/profile configuration".to_string())?;
    let mut parsed_config = DpiConfig::parse(&merged_config)
        .with_context(|| format!("Failed to parse DPI configuration: '{}'", merged_config))?;
    parsed_config.bpf_printk = args.bpf_printk;
    Ok(parsed_config)
}

/// Безопасный hot reload: новый профиль сначала полностью разбирается и
/// сериализуется, и только потом подменяет текущий. Любая ошибка — старый
/// конфиг остаётся в силе и в BPF-картах, и в userspace.
async fn reload_config(
    args: &Args,
    config: &Arc<RwLock<DpiConfig>>,
    config_update_tx: &std::sync::mpsc::Sender<Vec<u8>>,
    startup_auto_flags: (bool, bool, bool),
) -> Result<String> {
    let new_config = load_config(args)?;

    // AutoLogic создаётся один раз при старте, его нельзя пересоздать на лету
    let new_auto_flags = (
        new_config.auto_rst,
        new_config.auto_redirect,
        new_config.auto_ssl,
    );
    if new_auto_flags != startup_auto_flags {
        return Err(anyhow!(
            "changing auto flags (-Ar/-At/-As) requires a restart: running {:?}, new {:?}",
            startup_auto_flags,
            new_auto_flags
        ));
    }

    let config_bytes = new_config
        .to_bytes()
        .context("Failed to serialize reloaded config")?;

    let mut current = config.write().await;
    if *current == new_config {
        return Ok("config unchanged".to_string());
    }
    config_update_tx
        .send(config_bytes)
        .map_err(|_| anyhow!("BPF threads are gone, cannot push config"))?;
    *current = new_config;

    let summary = profile::summarize(&current)
        .into_iter()
        .filter(|(_, v)| v != "off" && v != "any")
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(summary)
}

/// Рассылает сериализованный конфиг во все BPF-потоки (по одному на интерфейс).
fn spawn_config_fanout(
    senders: Vec<std::sync::mpsc::Sender<Vec<u8>>>,
) -> Result<std::sync::mpsc::Sender<Vec<u8>>> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::Builder::new()
        .name("config-fanout".into())
        .spawn(move || {
            for bytes in rx {
                for sender in &senders {
                    let _ = sender.send(bytes.clone());
                }
            }
        })
        .context("Failed to spawn config fan-out thread")?;
    Ok(tx)
}

/// Сводит ring buffer события всех интерфейсов в один поток для EventProcessor.
fn merge_event_receivers(
    managers: &mut [BpfManager],
) -> Result<mpsc::Receiver<goodbyedpi_proto::Event>> {
    if managers.len() == 1 {
        return managers[0]
            .take_event_receiver()
            .context("Event receiver not available");
    }

    let (merged_tx, merged_rx) = mpsc::channel(1024);
    for manager in managers.iter_mut() {
        let mut rx = manager
            .take_event_receiver()
            .context("Event receiver not available")?;
        let tx = merged_tx.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if tx.send(event).await.is_err() {
                    break;
                }
            }
        });
    }
    Ok(merged_rx)
}

fn spawn_stats_aggregator(receivers: Vec<watch::Receiver<Stats>>, snapshot: Arc<RwLock<Stats>>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loop {
            tick.tick().await;
            let mut total = Stats::default();
            for rx in &receivers {
                total.accumulate(&rx.borrow());
            }
            *snapshot.write().await = total;
        }
    });
}

/// `--dry-run`: печатает разобранный профиль и проверяет eBPF-объект.
/// С правами root объект загружается в ядро (verifier), но не attach'ится.
fn dry_run(interfaces: &[String], config: &DpiConfig) -> Result<()> {
    println!("Interfaces: {}", interfaces.join(", "));
    for iface in interfaces {
        if nix::net::if_::if_nametoindex(iface.as_str()).is_err() {
            println!("  ! interface '{}' does not exist", iface);
        }
    }

    println!("Profile:");
    for (key, value) in profile::summarize(config) {
        println!("  {:<11} {}", key, value);
    }
    for lint in profile::lint(config) {
        println!("  {:?}: {}", lint.severity, lint.message);
    }

    let report = bpf::inspect_object(bpf::has_bpf_privileges())?;
    println!("eBPF object: {} bytes", report.object_size);
    let mut failed = !report.missing_programs.is_empty();
    for prog in &report.missing_programs {
        println!("  ! program '{}' missing", prog);
    }
    for map in &report.maps {
        if !map.ok() {
            failed = true;
            println!(
                "  ! map '{}' found={} value_size={:?} expected={:?}",
                map.name, map.found, map.value_size, map.expected_value_size
            );
        }
    }
    if !report.load_attempted {
        println!("  verifier: skipped (needs CAP_BPF or CAP_SYS_ADMIN)");
    } else if let Some(err) = &report.load_error {
        failed = true;
        println!("  verifier: REJECTED: {}", err);
        for line in report.libbpf_log.iter().rev().take(20).rev() {
            println!("    {}", line);
        }
    } else {
        println!("  verifier: accepted");
    }

    if failed {
        return Err(anyhow!(
            "dry run failed, see `goodbyedpi doctor` for details"
        ));
    }
    println!("Dry run OK: nothing was attached");
    Ok(())
}

fn load_merged_config(args: &Args) -> Result<String> {
    let mut chunks = Vec::new();

    if let Some(path) = &args.config_file {
        let from_file = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file '{}'", path))?;
        if !from_file.trim().is_empty() {
            chunks.push(from_file);
        }
    }

    if !args.config.trim().is_empty() {
        chunks.push(args.config.clone());
    }

    Ok(chunks.join("\n"))
}
