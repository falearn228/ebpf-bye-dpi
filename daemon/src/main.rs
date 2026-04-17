use anyhow::{Context, Result};
use clap::Parser;
use goodbyedpi_proto::Stats;
use log::info;
use std::sync::Arc;
use tokio::sync::RwLock;

mod auto_logic;
mod bpf;
mod config;
mod injector;
mod l7;
mod metrics;
mod ringbuf;
mod rules;
mod state;
mod tc;

use auto_logic::AutoLogic;
use bpf::BpfManager;
use config::DpiConfig;
use ringbuf::EventProcessor;

#[derive(Parser, Debug)]
#[command(name = "goodbyedpi-daemon")]
#[command(about = "eBPF-based GoodByeDPI implementation")]
struct Args {
    /// Interface to attach to
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// Config string (e.g., "s1 -o1 -Ar -f-1 -r1+s -At -As")
    #[arg(short, long, default_value = "")]
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

    info!("Starting GoodByeDPI eBPF daemon");
    info!("Interface: {}", args.interface);
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

    // Parse configuration
    let merged_config = load_merged_config(&args)
        .with_context(|| "Failed to load CLI/profile configuration".to_string())?;
    let mut parsed_config = DpiConfig::parse(&merged_config)
        .with_context(|| format!("Failed to parse DPI configuration: '{}'", merged_config))?;
    parsed_config.bpf_printk = args.bpf_printk;

    // Check if any auto-logic is enabled
    let auto_rst = parsed_config.auto_rst;
    let auto_redirect = parsed_config.auto_redirect;
    let auto_ssl = parsed_config.auto_ssl;

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

    // Load and attach eBPF programs
    let mut bpf_manager = BpfManager::load_and_attach(&args.interface, config.clone())
        .await
        .with_context(|| {
            format!(
                "Failed to load and attach eBPF programs to interface '{}'",
                args.interface
            )
        })?;

    info!(
        "eBPF programs loaded and attached successfully on {}",
        args.interface
    );

    // Get config update channel from bpf_manager (for auto-logic to update BPF config)
    let config_update_tx = bpf_manager.take_config_sender();

    // Create event processor with auto-logic if enabled
    let event_processor = if let Some(ref al) = auto_logic {
        if let Some(tx) = config_update_tx {
            EventProcessor::with_auto_logic_and_channel(al.clone(), tx)
                .context("Failed to create event processor with auto-logic and config channel")?
        } else {
            EventProcessor::with_auto_logic(al.clone())
                .context("Failed to create event processor with auto-logic")?
        }
    } else {
        EventProcessor::new().context("Failed to create event processor")?
    };

    info!("Event processor started");

    // Get event receiver from bpf_manager
    let event_rx = bpf_manager
        .take_event_receiver()
        .context("Event receiver not available")?;

    let stats_snapshot = Arc::new(RwLock::new(Stats::default()));

    if let Some(mut stats_rx) = bpf_manager.take_stats_receiver() {
        let stats_snapshot_clone = stats_snapshot.clone();
        tokio::spawn(async move {
            loop {
                if stats_rx.changed().await.is_err() {
                    break;
                }
                let new_stats = *stats_rx.borrow_and_update();
                *stats_snapshot_clone.write().await = new_stats;
            }
        });
    } else {
        log::warn!("Stats receiver not available, metrics will stay at zero");
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

    // Spawn event processing task
    let config_clone = config.clone();
    let mut event_handle = tokio::spawn(async move {
        event_processor.run(event_rx, config_clone).await;
    });

    // Main loop
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));

    // Handle Ctrl+C and SIGTERM
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("Failed to set up SIGTERM signal handler")?;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Cleanup expired connections
                if let Err(e) = bpf_manager.cleanup_connections().await {
                    log::warn!("Connection cleanup error: {}", e);
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

    // Gracefully shutdown BPF manager (waits for thread to finish)
    bpf_manager.shutdown();

    info!("Goodbye!");
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
