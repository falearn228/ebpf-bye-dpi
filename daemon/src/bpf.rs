use anyhow::{anyhow, Context, Result};
use goodbyedpi_proto::Stats;
use libbpf_rs::AsRawLibbpf;
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

/// eBPF-объект, собранный build.rs и встроенный в бинарник.
/// Встраивание нужно для пакетов: установленный бинарник не должен ссылаться на OUT_DIR сборки.
pub static BPF_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/goodbyedpi.bpf.o"));

/// TC-программы, которые демон обязан найти в объекте.
pub const REQUIRED_PROGRAMS: &[&str] = &["dpi_egress", "dpi_ingress"];

/// BPF-карты, от которых зависит userspace.
pub const REQUIRED_MAPS: &[&str] = &["config_map", "conn_map", "events", "sni_cache", "stats_map"];

/// Открывает встроенный eBPF-объект (без загрузки в ядро).
pub fn open_embedded_object() -> Result<libbpf_rs::OpenObject> {
    if BPF_OBJECT.is_empty() {
        return Err(anyhow!(
            "Embedded eBPF object is empty: binary was built without clang/make. \
             Install clang + libbpf headers and rebuild"
        ));
    }
    libbpf_rs::ObjectBuilder::default()
        .open_memory(BPF_OBJECT)
        .context("Failed to open embedded BPF object")
}

/// Может ли процесс загружать BPF: CAP_BPF или CAP_SYS_ADMIN в CapEff.
/// Именно капы, а не euid: root в контейнере обычно без CAP_BPF.
pub fn has_bpf_privileges() -> bool {
    const CAP_SYS_ADMIN: u32 = 21;
    const CAP_BPF: u32 = 39;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            let line = status.lines().find(|l| l.starts_with("CapEff:"))?;
            u64::from_str_radix(line.trim_start_matches("CapEff:").trim(), 16).ok()
        })
        .is_some_and(|caps| caps & (1 << CAP_BPF | 1 << CAP_SYS_ADMIN) != 0)
}

/// Результат проверки одной BPF-карты на соответствие ABI userspace.
#[derive(Debug, Clone)]
pub struct MapCheck {
    pub name: &'static str,
    pub found: bool,
    pub value_size: Option<u32>,
    pub expected_value_size: Option<u32>,
}

impl MapCheck {
    pub fn ok(&self) -> bool {
        self.found
            && match (self.value_size, self.expected_value_size) {
                (Some(actual), Some(expected)) => actual == expected,
                _ => true,
            }
    }
}

/// Отчёт preflight-проверки eBPF-объекта для `doctor` и `--dry-run`.
#[derive(Debug, Clone, Default)]
pub struct ObjectReport {
    pub object_size: usize,
    pub missing_programs: Vec<&'static str>,
    pub maps: Vec<MapCheck>,
    /// Была ли попытка загрузки в ядро (требует CAP_BPF/CAP_SYS_ADMIN)
    pub load_attempted: bool,
    pub load_error: Option<String>,
    /// Вывод libbpf во время загрузки, включая лог verifier'а при отказе
    pub libbpf_log: Vec<String>,
}

impl ObjectReport {
    pub fn loaded(&self) -> bool {
        self.load_attempted && self.load_error.is_none()
    }
}

static LIBBPF_LOG: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn capture_libbpf_print(_level: libbpf_rs::PrintLevel, msg: String) {
    if let Ok(mut log) = LIBBPF_LOG.lock() {
        log.extend(msg.lines().map(str::to_string));
    }
}

/// Проверяет встроенный объект: наличие программ, размеры значений карт
/// против `repr(C)` структур proto и (при `load = true`) прохождение verifier'а.
/// Программы никуда не attach'атся: объект выгружается сразу после проверки.
pub fn inspect_object(load: bool) -> Result<ObjectReport> {
    let open = open_embedded_object()?;
    let mut report = ObjectReport {
        object_size: BPF_OBJECT.len(),
        ..ObjectReport::default()
    };

    let prog_names: Vec<String> = open
        .progs_iter()
        .filter_map(|p| p.name().ok().map(str::to_string))
        .collect();
    report.missing_programs = REQUIRED_PROGRAMS
        .iter()
        .copied()
        .filter(|name| !prog_names.iter().any(|p| p == name))
        .collect();

    for name in REQUIRED_MAPS.iter().copied() {
        let map = open.maps_iter().find(|m| m.name().ok() == Some(name));
        // SAFETY: указатель валиден, пока жив OpenObject.
        let value_size =
            map.map(|m| unsafe { libbpf_sys::bpf_map__value_size(m.as_libbpf_object().as_ptr()) });
        let expected_value_size = match name {
            "config_map" => Some(std::mem::size_of::<goodbyedpi_proto::Config>() as u32),
            "stats_map" => Some(std::mem::size_of::<Stats>() as u32),
            _ => None,
        };
        report.maps.push(MapCheck {
            name,
            found: map.is_some(),
            value_size,
            expected_value_size,
        });
    }

    if load {
        report.load_attempted = true;
        if let Ok(mut log) = LIBBPF_LOG.lock() {
            log.clear();
        }
        let prev = libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Info, capture_libbpf_print)));
        let result = open.load();
        libbpf_rs::set_print(prev);
        if let Err(e) = result {
            report.load_error = Some(format!("{:#}", e));
        }
        if let Ok(mut log) = LIBBPF_LOG.lock() {
            report.libbpf_log = std::mem::take(&mut *log);
        }
    }

    Ok(report)
}

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
        let (init_tx, init_rx) = std::sync::mpsc::channel::<Result<(), String>>();

        // Clone for the BPF thread
        let interface_clone = interface.to_string();

        // Spawn dedicated thread for BPF lifecycle
        let error_init_tx = init_tx.clone();
        let bpf_thread = thread::spawn(move || {
            if let Err(e) = bpf_thread_main(
                &interface_clone,
                config_bytes,
                event_tx,
                shutdown_rx,
                config_rx,
                stats_tx,
                init_tx,
            ) {
                let error_msg = format!("{:#}", e);
                let _ = error_init_tx.send(Err(error_msg.clone()));
                error!("BPF thread error: {}", error_msg);
            }
        });

        let init_result =
            tokio::task::spawn_blocking(move || init_rx.recv_timeout(Duration::from_secs(10)))
                .await
                .context("Failed to wait for BPF thread initialization")?;

        match init_result {
            Ok(Ok(())) => {}
            Ok(Err(error_msg)) => return Err(anyhow::anyhow!(error_msg)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err(anyhow::anyhow!(
                    "Timed out waiting for BPF thread initialization"
                ));
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(anyhow::anyhow!(
                    "BPF thread exited before initialization completed"
                ));
            }
        }

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
    init_tx: std::sync::mpsc::Sender<Result<(), String>>,
) -> Result<()> {
    info!("BPF thread started");

    // Load BPF object
    let obj = open_embedded_object()?;

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

    let _ = init_tx.send(Ok(()));

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
                if poll_count.is_multiple_of(100) {
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
