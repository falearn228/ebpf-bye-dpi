use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use std::sync::Arc;
use tokio::sync::RwLock;

mod auto_logic;
mod bpf;
mod config;
mod injector;
mod ringbuf;
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

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::from_default_env()
        .filter_level(if args.debug { log::LevelFilter::Debug } else { log::LevelFilter::Info })
        .init();

    info!("Starting GoodByeDPI eBPF daemon");
    info!("Interface: {}", args.interface);
    info!("Config: {}", args.config);

    // Parse configuration
    let parsed_config = DpiConfig::parse(&args.config)
        .with_context(|| format!(
            "Failed to parse DPI configuration: '{}'",
            args.config
        ))?;
    
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
    let mut bpf_manager = BpfManager::load_and_attach(&args.interface, config.clone()).await
        .with_context(|| format!(
            "Failed to load and attach eBPF programs to interface '{}'",
            args.interface
        ))?;
    
    info!("eBPF programs loaded and attached successfully on {}", args.interface);

    // Create event processor with auto-logic if enabled
    let event_processor = if let Some(ref al) = auto_logic {
        EventProcessor::with_auto_logic(al.clone())
            .context("Failed to create event processor with auto-logic")?
    } else {
        EventProcessor::new()
            .context("Failed to create event processor")?
    };
    
    info!("Event processor started");

    // Get event receiver from bpf_manager
    let event_rx = bpf_manager.take_event_receiver()
        .context("Event receiver not available")?;

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
    drop(bpf_manager);
    
    // Additional cleanup to ensure TC filters are removed
    if let Err(e) = tc::full_cleanup(&args.interface) {
        log::warn!(
            "Cleanup error for interface '{}': {}. \
             You may need to manually remove TC filters with: tc qdisc del dev {} clsact",
            args.interface, e, args.interface
        );
    }
    
    info!("Goodbye!");
    Ok(())
}
