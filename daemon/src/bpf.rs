use anyhow::{Context, Result};
use goodbyedpi_proto::Stats;
use log::{debug, error, info, warn};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, RwLock};

use crate::config::DpiConfig;
use crate::state::ConnectionState;
use goodbyedpi_proto::Event;

/// Buffer size for event channel
const EVENT_CHANNEL_SIZE: usize = 1024;
/// Ring buffer poll timeout (milliseconds)
const RING_BUFFER_TIMEOUT_MS: i32 = 100;

/// BPF Manager - handles eBPF lifecycle and ring buffer
pub struct BpfManager {
    _state: ConnectionState,
    interface: String,
    /// Event receiver channel (taken by main for event processing)
    event_rx: Option<mpsc::Receiver<Event>>,
    /// Handle to the BPF thread
    bpf_thread: Option<JoinHandle<()>>,
    /// Shutdown sender for BPF thread
    shutdown_tx: watch::Sender<bool>,
    /// Config update sender for BPF thread (sync channel for cross-thread communication)
    config_tx: std::sync::mpsc::Sender<Vec<u8>>,
    /// Stats receiver channel (latest BPF stats snapshot)
    stats_rx: Option<watch::Receiver<Stats>>,
}

impl BpfManager {
    /// Load BPF programs and start ring buffer monitoring
    pub async fn load_and_attach(interface: &str, config: Arc<RwLock<DpiConfig>>) -> Result<Self> {
        info!("Loading eBPF programs for interface: {}", interface);

        // Get config bytes for BPF map
        let config_guard = config.read().await;
        let config_bytes = config_guard
            .to_bytes()
            .context("Failed to serialize configuration for eBPF map")?;
        drop(config_guard);

        // Create async channel for events
        let (event_tx, event_rx) = mpsc::channel::<Event>(EVENT_CHANNEL_SIZE);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (stats_tx, stats_rx) = watch::channel(Stats::default());

        // Create sync channel for config updates (used from async context to sync BPF thread)
        let (config_tx, config_rx) = std::sync::mpsc::channel::<Vec<u8>>();

        // Clone for the BPF thread
        let interface_clone = interface.to_string();

        // Spawn dedicated thread for BPF lifecycle
        let bpf_thread = thread::spawn(move || {
            if let Err(e) = bpf_thread_main(
                &interface_clone,
                config_bytes,
                event_tx,
                shutdown_rx,
                config_rx,
                stats_tx,
            ) {
                error!("BPF thread error: {}", e);
            }
        });

        // Give BPF thread time to initialize
        tokio::time::sleep(Duration::from_millis(200)).await;

        let state = ConnectionState::new();

        info!("BPF manager initialized successfully");

        Ok(Self {
            _state: state,
            interface: interface.to_string(),
            event_rx: Some(event_rx),
            bpf_thread: Some(bpf_thread),
            shutdown_tx,
            config_tx,
            stats_rx: Some(stats_rx),
        })
    }

    /// Take event receiver (can only be called once)
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<Event>> {
        self.event_rx.take()
    }

    /// Take config update sender (can only be called once)
    ///
    /// This allows other components to send config updates to the BPF thread.
    pub fn take_config_sender(&mut self) -> Option<std::sync::mpsc::Sender<Vec<u8>>> {
        // Since we can't easily move the sender out of Arc,
        // we create a new sender from the same channel
        // Note: This requires the channel to be clonable, which std::sync::mpsc::Sender is
        Some(self.config_tx.clone())
    }

    /// Take stats receiver (can only be called once)
    pub fn take_stats_receiver(&mut self) -> Option<watch::Receiver<Stats>> {
        self.stats_rx.take()
    }

    /// Cleanup connections periodically
    pub async fn cleanup_connections(&mut self) -> Result<()> {
        debug!("Connection cleanup called (handled in BPF thread)");
        Ok(())
    }

    /// Shutdown BPF manager gracefully
    ///
    /// This method sends a shutdown signal and waits for the BPF thread to complete.
    /// It also performs TC cleanup. This is the preferred way to shut down the manager.
    pub fn shutdown(mut self) {
        info!("Shutting down BPF manager...");

        // Signal BPF thread to stop
        let _ = self.shutdown_tx.send(true);
        info!("Shutdown signal sent to BPF thread");

        // Wait for BPF thread to finish
        if let Some(handle) = self.bpf_thread.take() {
            info!("Waiting for BPF thread to finish...");
            match handle.join() {
                Ok(()) => info!("BPF thread finished successfully"),
                Err(e) => error!("BPF thread panicked: {:?}", e),
            }
        }

        // Additional TC cleanup (in case BPF thread didn't complete it)
        if let Err(e) = crate::tc::full_cleanup(&self.interface) {
            warn!("TC cleanup error for interface '{}': {}", self.interface, e);
        }

        info!("BPF manager shutdown complete");
    }
}

impl Drop for BpfManager {
    fn drop(&mut self) {
        // Signal BPF thread to stop
        let _ = self.shutdown_tx.send(true);
        info!("BPF manager dropped, signaling shutdown...");

        // Note: We cannot wait for the thread here because Drop cannot be async
        // and join() might block. Use shutdown() for graceful shutdown.
        // The thread will clean up TC on its own when it receives the signal.
        if self.bpf_thread.is_some() {
            warn!("BPF manager dropped without calling shutdown() - thread may not finish cleanly");
        }
    }
}

/// Main function for the BPF thread (runs in separate OS thread)
fn bpf_thread_main(
    interface: &str,
    config_bytes: Vec<u8>,
    event_tx: mpsc::Sender<Event>,
    mut shutdown_rx: watch::Receiver<bool>,
    config_rx: std::sync::mpsc::Receiver<Vec<u8>>,
    stats_tx: watch::Sender<Stats>,
) -> Result<()> {
    info!("BPF thread started");

    // Load BPF object
    let mut skel_builder = libbpf_rs::ObjectBuilder::default();
    let bpf_obj_path = concat!(env!("OUT_DIR"), "/goodbyedpi.bpf.o");

    let obj = skel_builder
        .open_file(bpf_obj_path)
        .context("Failed to open BPF object file")?;

    // Load the BPF object
    let mut obj = obj.load().context("Failed to load BPF object")?;

    // Set config map after loading
    if let Some(config_map) = obj.map_mut("config_map") {
        let key: u32 = 0;
        let key_bytes = unsafe { std::slice::from_raw_parts(&key as *const _ as *const u8, 4) };
        config_map
            .update(key_bytes, &config_bytes, libbpf_rs::MapFlags::ANY)
            .context("Failed to set config map")?;
        info!("Config map updated ({} bytes)", config_bytes.len());

        // Log all config values for debugging
        log_config_bytes(&config_bytes);
    } else {
        warn!("Config map not found in BPF object!");
    }
    info!("BPF object loaded in thread");

    // Get interface index
    let ifidx =
        nix::net::if_::if_nametoindex(interface).context("Failed to get interface index")?;

    // Attach egress program using TcHook
    if let Some(prog) = obj.prog_mut("dpi_egress") {
        let fd = prog.as_fd();
        let mut hook = libbpf_rs::TcHook::new(fd);

        hook.attach_point(libbpf_rs::TC_EGRESS)
            .ifindex(ifidx as i32);

        // Create the qdisc first
        let mut create_hook = hook;
        if let Err(e) = create_hook.create() {
            warn!("TC qdisc create warning (may already exist): {}", e);
        }

        // Attach the program
        hook.attach()
            .context("Failed to attach TC egress program")?;

        info!("TC egress program attached to {}", interface);
    } else {
        return Err(anyhow::anyhow!("dpi_egress program not found"));
    }

    // Attach ingress program
    if let Some(prog) = obj.prog_mut("dpi_ingress") {
        let fd = prog.as_fd();
        let mut hook = libbpf_rs::TcHook::new(fd);

        hook.attach_point(libbpf_rs::TC_INGRESS)
            .ifindex(ifidx as i32);

        hook.attach()
            .context("Failed to attach TC ingress program")?;

        info!("TC ingress program attached to {}", interface);
    } else {
        return Err(anyhow::anyhow!("dpi_ingress program not found"));
    }

    // Get config_map reference for runtime updates
    let config_map = obj.map("config_map");
    let stats_map = obj.map("stats_map");

    if let Err(e) = publish_stats(stats_map, &stats_tx) {
        warn!("Failed to publish initial stats: {}", e);
    }

    // Setup ring buffer
    if let Some(events_map) = obj.map("events") {
        info!("Setting up ring buffer polling");

        if let Err(e) = run_ring_buffer_poll(
            events_map,
            event_tx,
            &mut shutdown_rx,
            config_map,
            config_rx,
            stats_map,
            stats_tx,
        ) {
            error!("Ring buffer error: {}", e);
        }
    } else {
        warn!("No events map found");

        // Just wait for shutdown, also process config updates
        let mut last_stats_read = Instant::now();
        while !*shutdown_rx.borrow() {
            thread::sleep(Duration::from_millis(100));

            // Check for config updates
            while let Ok(new_config) = config_rx.try_recv() {
                if let Some(map) = config_map {
                    if let Err(e) = update_config_map(map, &new_config) {
                        error!("Failed to update config map: {}", e);
                    }
                }
            }

            if last_stats_read.elapsed() >= Duration::from_secs(1) {
                if let Err(e) = publish_stats(stats_map, &stats_tx) {
                    warn!("Failed to publish stats: {}", e);
                }
                last_stats_read = Instant::now();
            }

            if shutdown_rx.has_changed().unwrap_or(false) && *shutdown_rx.borrow() {
                break;
            }
        }
    }

    // Cleanup TC
    info!("BPF thread cleaning up TC...");
    let _ = crate::tc::full_cleanup(interface);

    info!("BPF thread exiting");
    Ok(())
}

/// Log configuration bytes for debugging
fn log_config_bytes(config_bytes: &[u8]) {
    if config_bytes.len() >= 24 {
        let split_pos = i32::from_ne_bytes([
            config_bytes[0],
            config_bytes[1],
            config_bytes[2],
            config_bytes[3],
        ]);
        let oob_pos = i32::from_ne_bytes([
            config_bytes[4],
            config_bytes[5],
            config_bytes[6],
            config_bytes[7],
        ]);
        let fake_offset = i32::from_ne_bytes([
            config_bytes[8],
            config_bytes[9],
            config_bytes[10],
            config_bytes[11],
        ]);
        let tlsrec_pos = i32::from_ne_bytes([
            config_bytes[12],
            config_bytes[13],
            config_bytes[14],
            config_bytes[15],
        ]);
        let auto_rst = config_bytes[16] != 0;
        let auto_redirect = config_bytes[17] != 0;
        let auto_ssl = config_bytes[18] != 0;
        let ip_fragment = config_bytes[19];
        let frag_size = u16::from_ne_bytes([config_bytes[20], config_bytes[21]]);
        let disorder = config_bytes[22] != 0;
        let bpf_printk = config_bytes[23] != 0;

        info!(
            "  BPF Config: split_pos={}, oob_pos={}, fake_offset={}, tlsrec_pos={}",
            split_pos, oob_pos, fake_offset, tlsrec_pos
        );
        info!(
            "  BPF Config: auto_rst={}, auto_redirect={}, auto_ssl={}",
            auto_rst, auto_redirect, auto_ssl
        );
        info!(
            "  BPF Config: ip_fragment={}, frag_size={}, disorder={}",
            ip_fragment, frag_size, disorder
        );
        info!("  BPF Config: bpf_printk={}", bpf_printk);
    }
}

/// Update config map with new configuration bytes
fn update_config_map(config_map: &libbpf_rs::Map, config_bytes: &[u8]) -> Result<()> {
    let key: u32 = 0;
    let key_bytes = unsafe { std::slice::from_raw_parts(&key as *const _ as *const u8, 4) };

    config_map
        .update(key_bytes, config_bytes, libbpf_rs::MapFlags::ANY)
        .context("Failed to update config map")?;

    info!(
        "Config map updated at runtime ({} bytes)",
        config_bytes.len()
    );
    log_config_bytes(config_bytes);

    Ok(())
}

/// Run ring buffer polling
fn run_ring_buffer_poll(
    events_map: &libbpf_rs::Map,
    event_tx: mpsc::Sender<Event>,
    shutdown_rx: &mut watch::Receiver<bool>,
    config_map: Option<&libbpf_rs::Map>,
    config_rx: std::sync::mpsc::Receiver<Vec<u8>>,
    stats_map: Option<&libbpf_rs::Map>,
    stats_tx: watch::Sender<Stats>,
) -> Result<()> {
    use libbpf_rs::RingBufferBuilder;
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut builder = RingBufferBuilder::new();

    // Event counter for diagnostics
    static EVENT_COUNT: AtomicU64 = AtomicU64::new(0);

    // Callback for ring buffer events
    let callback = move |data: &[u8]| -> i32 {
        let count = EVENT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;

        info!(
            "[BPF CALLBACK] Called with {} bytes, event count={}",
            data.len(),
            count
        );

        if data.len() < std::mem::size_of::<Event>() {
            warn!(
                "Event data too small: {} bytes (expected {})",
                data.len(),
                std::mem::size_of::<Event>()
            );
            return 0;
        }

        // Parse event from raw bytes
        let event = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const Event) };

        // Log received event
        let (src_ip, dst_ip) = event.format_ips();
        info!(
            "[BPF] Received event type={} from {}:{} -> {}:{}",
            event.event_type, src_ip, event.src_port, dst_ip, event.dst_port
        );

        // Send to async context via channel
        match event_tx.try_send(event) {
            Ok(_) => {
                info!("[BPF] Event sent to channel successfully");
            }
            Err(e) => {
                warn!("[BPF] Failed to send event to channel: {:?}", e);
                // Channel full or closed
                if event_tx.is_closed() {
                    return -1; // Signal to stop polling
                }
            }
        }

        0
    };

    info!("[RINGBUF] Adding events map to ring buffer builder...");
    builder
        .add(events_map, callback)
        .context("Failed to add ring buffer callback")?;
    info!("[RINGBUF] Events map added successfully");

    let ringbuf = builder.build().context("Failed to build ring buffer")?;
    info!("[RINGBUF] Ring buffer built successfully");

    info!("Ring buffer polling started");

    // Poll loop
    let mut poll_count = 0u64;
    let mut last_stats_read = Instant::now();
    loop {
        // Check shutdown
        if *shutdown_rx.borrow() {
            break;
        }

        // Process any pending config updates
        while let Ok(new_config) = config_rx.try_recv() {
            if let Some(map) = config_map {
                if let Err(e) = update_config_map(map, &new_config) {
                    error!("Failed to update config map: {}", e);
                }
            } else {
                warn!("Config map not available for update");
            }
        }

        // Poll with timeout
        match ringbuf.poll(Duration::from_millis(RING_BUFFER_TIMEOUT_MS as u64)) {
            Ok(_) => {
                poll_count += 1;
                if poll_count % 100 == 0 {
                    info!("[RINGBUF] Poll #{} completed", poll_count);
                }
            }
            Err(e) => {
                error!("Ring buffer poll error: {}", e);
                break;
            }
        }

        if last_stats_read.elapsed() >= Duration::from_secs(1) {
            if let Err(e) = publish_stats(stats_map, &stats_tx) {
                warn!("Failed to publish stats: {}", e);
            }
            last_stats_read = Instant::now();
        }

        // Check shutdown again
        if shutdown_rx.has_changed().unwrap_or(false) && *shutdown_rx.borrow() {
            break;
        }
    }

    info!("Ring buffer polling stopped, total polls: {}", poll_count);
    Ok(())
}

fn publish_stats(
    stats_map: Option<&libbpf_rs::Map>,
    stats_tx: &watch::Sender<Stats>,
) -> Result<()> {
    let Some(stats_map) = stats_map else {
        return Ok(());
    };

    let stats = read_stats_map(stats_map)?;
    let _ = stats_tx.send(stats);
    Ok(())
}

fn read_stats_map(stats_map: &libbpf_rs::Map) -> Result<Stats> {
    let key: u32 = 0;
    let key_bytes = key.to_ne_bytes();

    let value = stats_map
        .lookup(&key_bytes, libbpf_rs::MapFlags::ANY)
        .context("Failed to lookup stats_map")?
        .unwrap_or_else(|| vec![0u8; std::mem::size_of::<Stats>()]);

    if value.len() < std::mem::size_of::<Stats>() {
        return Err(anyhow::anyhow!(
            "Invalid stats_map value size: got {}, expected at least {}",
            value.len(),
            std::mem::size_of::<Stats>()
        ));
    }

    let stats = unsafe { std::ptr::read_unaligned(value.as_ptr() as *const Stats) };
    Ok(stats)
}
