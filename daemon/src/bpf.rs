use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::os::fd::AsFd;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::{mpsc, watch, RwLock};

use crate::config::DpiConfig;
use crate::injector::RawInjector;
use crate::state::ConnectionState;
use goodbyedpi_proto::Event;

/// Buffer size for event channel
const EVENT_CHANNEL_SIZE: usize = 1024;
/// Ring buffer poll timeout (milliseconds)
const RING_BUFFER_TIMEOUT_MS: i32 = 100;

/// BPF Manager - handles eBPF lifecycle and ring buffer
pub struct BpfManager {
    _state: ConnectionState,
    _interface: String,
    /// Event receiver channel (taken by main for event processing)
    event_rx: Option<mpsc::Receiver<Event>>,
    /// Handle to the BPF thread
    _bpf_thread: thread::JoinHandle<()>,
    /// Shutdown sender for BPF thread
    shutdown_tx: watch::Sender<bool>,
}

impl BpfManager {
    /// Load BPF programs and start ring buffer monitoring
    pub async fn load_and_attach(
        interface: &str,
        config: Arc<RwLock<DpiConfig>>,
    ) -> Result<Self> {
        info!("Loading eBPF programs for interface: {}", interface);

        // Get config bytes for BPF map
        let config_guard = config.read().await;
        let config_bytes = config_guard.to_bytes()
            .context("Failed to serialize configuration for eBPF map")?;
        drop(config_guard);

        // Create async channel for events
        let (event_tx, event_rx) = mpsc::channel::<Event>(EVENT_CHANNEL_SIZE);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        // Clone for the BPF thread
        let interface_clone = interface.to_string();
        
        // Spawn dedicated thread for BPF lifecycle
        let bpf_thread = thread::spawn(move || {
            if let Err(e) = bpf_thread_main(
                &interface_clone,
                config_bytes,
                event_tx,
                shutdown_rx,
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
            _interface: interface.to_string(),
            event_rx: Some(event_rx),
            _bpf_thread: bpf_thread,
            shutdown_tx,
        })
    }

    /// Take event receiver (can only be called once)
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<Event>> {
        self.event_rx.take()
    }

    /// Cleanup connections periodically
    pub async fn cleanup_connections(&mut self) -> Result<()> {
        debug!("Connection cleanup called (handled in BPF thread)");
        Ok(())
    }
}

impl Drop for BpfManager {
    fn drop(&mut self) {
        // Signal BPF thread to stop
        let _ = self.shutdown_tx.send(true);
        info!("BPF manager dropped, signaling shutdown...");
    }
}

/// Main function for the BPF thread (runs in separate OS thread)
fn bpf_thread_main(
    interface: &str,
    config_bytes: Vec<u8>,
    event_tx: mpsc::Sender<Event>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<()> {
    info!("BPF thread started");

    // Load BPF object
    let mut skel_builder = libbpf_rs::ObjectBuilder::default();
    let bpf_obj_path = concat!(env!("OUT_DIR"), "/goodbyedpi.bpf.o");
    
    let mut obj = skel_builder
        .open_file(bpf_obj_path)
        .context("Failed to open BPF object file")?;

    // Load the BPF object
    let mut obj = obj.load().context("Failed to load BPF object")?;
    
    // Set config map after loading
    if let Some(config_map) = obj.map_mut("config_map") {
        let key: u32 = 0;
        let key_bytes = unsafe {
            std::slice::from_raw_parts(&key as *const _ as *const u8, 4)
        };
        config_map
            .update(key_bytes, &config_bytes, libbpf_rs::MapFlags::ANY)
            .context("Failed to set config map")?;
        debug!("Config map updated ({} bytes)", config_bytes.len());
    }
    info!("BPF object loaded in thread");

    // Get interface index
    let ifidx = nix::net::if_::if_nametoindex(interface)
        .context("Failed to get interface index")?;

    // Attach egress program using TcHook
    if let Some(prog) = obj.prog_mut("dpi_egress") {
        let fd = prog.as_fd();
        let mut hook = libbpf_rs::TcHook::new(fd);
        
        hook.attach_point(libbpf_rs::TC_EGRESS)
            .ifindex(ifidx as i32);
        
        // Create the qdisc first
        let mut create_hook = hook.clone();
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

    // Create injector for packet injection
    let injector = RawInjector::new().ok();
    if injector.is_some() {
        info!("Raw injector created in BPF thread");
    }

    // Setup ring buffer
    if let Some(events_map) = obj.map("events") {
        info!("Setting up ring buffer polling");
        
        if let Err(e) = run_ring_buffer_poll(
            events_map,
            event_tx,
            &mut shutdown_rx,
        ) {
            error!("Ring buffer error: {}", e);
        }
    } else {
        warn!("No events map found");
        
        // Just wait for shutdown
        while !*shutdown_rx.borrow() {
            thread::sleep(Duration::from_millis(100));
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

/// Run ring buffer polling
fn run_ring_buffer_poll(
    events_map: &libbpf_rs::Map,
    event_tx: mpsc::Sender<Event>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<()> {
    use libbpf_rs::RingBufferBuilder;

    let mut builder = RingBufferBuilder::new();
    
    // Callback for ring buffer events
    let callback = move |data: &[u8]| -> i32 {
        if data.len() < std::mem::size_of::<Event>() {
            warn!("Event data too small: {} bytes", data.len());
            return 0;
        }

        // Parse event from raw bytes
        let event = unsafe {
            std::ptr::read_unaligned(data.as_ptr() as *const Event)
        };

        // Send to async context via channel
        match event_tx.try_send(event) {
            Ok(_) => {}
            Err(_) => {
                // Channel full or closed
                if event_tx.is_closed() {
                    return -1; // Signal to stop polling
                }
            }
        }

        0
    };

    builder.add(events_map, callback)
        .context("Failed to add ring buffer callback")?;
    
    let ringbuf = builder.build()
        .context("Failed to build ring buffer")?;

    info!("Ring buffer polling started");

    // Poll loop
    loop {
        // Check shutdown
        if *shutdown_rx.borrow() {
            break;
        }

        // Poll with timeout
        match ringbuf.poll(Duration::from_millis(RING_BUFFER_TIMEOUT_MS as u64)) {
            Ok(_) => {}
            Err(e) => {
                error!("Ring buffer poll error: {}", e);
                break;
            }
        }

        // Check shutdown again
        if shutdown_rx.has_changed().unwrap_or(false) && *shutdown_rx.borrow() {
            break;
        }
    }

    info!("Ring buffer polling stopped");
    Ok(())
}

/// Legacy BpfSkel for compatibility
pub struct BpfSkel {
    #[allow(dead_code)]
    manager: BpfManager,
}

impl BpfSkel {
    pub async fn cleanup_connections(&mut self) -> Result<()> {
        self.manager.cleanup_connections().await
    }
}

/// Legacy load function
pub async fn load_and_attach(
    interface: &str,
    config: Arc<RwLock<DpiConfig>>,
) -> Result<BpfSkel> {
    let manager = BpfManager::load_and_attach(interface, config).await?;
    Ok(BpfSkel { manager })
}
