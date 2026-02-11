use anyhow::{Context, Result};
use clap::Parser;
use log::info;
use std::sync::Arc;
use tokio::sync::RwLock;

mod bpf;
mod config;
mod injector;
mod state;
mod tc;

use config::DpiConfig;

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
    let config = Arc::new(RwLock::new(parsed_config));
    info!("Parsed config: {:?}", config.read().await);

    // Load and attach eBPF programs
    let mut skel = bpf::load_and_attach(&args.interface, config.clone()).await
        .with_context(|| format!(
            "Failed to load and attach eBPF programs to interface '{}'",
            args.interface
        ))?;
    
    info!("eBPF programs loaded and attached successfully on {}", args.interface);

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    
    // Handle Ctrl+C and SIGTERM
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("Failed to set up SIGTERM signal handler")?;

    loop {
        tokio::select! {
            _ = interval.tick() => {
                // Cleanup expired connections
                skel.cleanup_connections().await?;
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                break;
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down...");
                break;
            }
        }
    }

    // Explicit cleanup before exit
    info!("Cleaning up...");
    drop(skel);
    
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
