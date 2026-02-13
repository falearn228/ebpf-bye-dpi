use anyhow::Result;
use clap::Parser;
use log::info;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "goodbyedpi")]
#[command(about = "GoodByeDPI eBPF CLI")]
struct Args {
    /// Interface to use
    #[arg(short, long, default_value = "eth0")]
    interface: String,

    /// DPI bypass config
    #[arg(short, long, default_value = "s1 -o1 -Ar")]
    config: String,

    /// Run in daemon mode
    #[arg(short, long)]
    daemon: bool,

    /// Show status
    #[arg(long)]
    status: bool,

    /// Stop daemon
    #[arg(long)]
    stop: bool,

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

    if args.status {
        show_status().await?;
        return Ok(());
    }

    if args.stop {
        stop_daemon().await?;
        return Ok(());
    }

    if args.daemon {
        info!("Starting daemon with config: {}", args.config);
        // Execute daemon binary
        let output = Command::new("goodbyedpi-daemon")
            .args(["-i", &args.interface, "-c", &args.config])
            .spawn()?;
        info!("Daemon started with PID: {:?}", output.id());
    } else {
        // One-shot mode
        run_single(&args.interface, &args.config).await?;
    }

    Ok(())
}

async fn run_single(interface: &str, config: &str) -> Result<()> {
    info!("Running single-shot mode on {}", interface);
    info!("Config: {}", config);
    
    // Parse and validate config
    let _cfg = goodbyedpi_proto::Config::default();
    
    info!("This would start the daemon in foreground mode");
    
    Ok(())
}

async fn show_status() -> Result<()> {
    info!("Checking daemon status...");
    // Check if daemon is running
    // Read stats from BPF maps
    Ok(())
}

async fn stop_daemon() -> Result<()> {
    info!("Stopping daemon...");
    // Signal daemon to stop
    Ok(())
}
