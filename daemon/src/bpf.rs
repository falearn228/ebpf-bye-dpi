use anyhow::{Context, Result};
use log::{debug, info, warn};
use std::sync::Arc;
use tokio::sync::RwLock;
use nix::net::if_::if_nametoindex;

use crate::config::DpiConfig;
use crate::injector::RawInjector;
use crate::state::ConnectionState;
use crate::tc;
use goodbyedpi_proto::Event;

// TODO: Вот эти флаги не используются! Разобраться
// Event types from eBPF
const EVENT_FAKE_TRIGGERED: u32 = 1;
const EVENT_RST_DETECTED: u32 = 2;
const EVENT_REDIRECT_DETECTED: u32 = 3;
const EVENT_SSL_ERROR_DETECTED: u32 = 4;
const EVENT_DISORDER_TRIGGERED: u32 = 5;

// Special flags in event.flags
const FLAG_DISORDER: u8 = 0xFE;      /* Special flag for DISORDER */
const FLAG_QUIC_FRAG: u8 = 0xFD;     /* Special flag for QUIC fragmentation */
const FLAG_TLS_SPLIT: u8 = 0xFF;     /* Special flag for TLS split */


// TODO: не использутся поля config и injector
pub struct BpfSkel {
    config: Arc<RwLock<DpiConfig>>,
    state: ConnectionState,
    injector: RawInjector,
    interface: String,
}


// TODO: associated items `log_stats`, `handle_event`, and `spawn_ringbuf_monitor` are never use
impl BpfSkel {
    pub async fn cleanup_connections(&mut self) -> Result<()> {
        let count = self.state.cleanup().await;
        if count > 0 {
            debug!("Cleaned up {} expired connections", count);
        }
        Ok(())
    }

    pub fn log_stats(&self) {
        // Stats can be read from BPF map if needed
        // For now, just log that we're active
        info!("[GoodByeDPI] BPF programs active on {}", self.interface);
    }

    fn handle_event(data: &[u8]) -> i32 {
        if data.len() < std::mem::size_of::<Event>() {
            debug!("Event data too small: {} bytes", data.len());
            return 0;
        }

        let event = unsafe {
            &*(data.as_ptr() as *const Event)
        };

        let (src_ip, dst_ip) = event.format_ips();

        match event.event_type {
            EVENT_FAKE_TRIGGERED => {
                // Check for special flags
                if event.flags == FLAG_DISORDER {
                    info!(
                        "[DISORDER] {}:{} -> {}:{}, seq={}, ipv6={}",
                        src_ip, event.src_port, dst_ip, event.dst_port,
                        u32::from_be(event.seq), event.is_ipv6
                    );
                } else if event.flags == FLAG_QUIC_FRAG {
                    info!(
                        "[QUIC FRAG] {}:{} -> {}:{}, frag_size={}, ipv6={}",
                        src_ip, event.src_port, dst_ip, event.dst_port,
                        event.payload_len, event.is_ipv6
                    );
                } else if event.flags == FLAG_TLS_SPLIT {
                    info!(
                        "[TLS SPLIT] {}:{} -> {}:{}, ipv6={}",
                        src_ip, event.src_port, dst_ip, event.dst_port, event.is_ipv6
                    );
                } else {
                    info!(
                        "[FAKE] {}:{} -> {}:{}, seq={}, flags={:02x}, ipv6={}",
                        src_ip, event.src_port, dst_ip, event.dst_port,
                        u32::from_be(event.seq), event.flags, event.is_ipv6
                    );
                }
            }
            EVENT_RST_DETECTED => {
                warn!(
                    "RST detected: {}:{} -> {}:{}, ipv6={}",
                    src_ip, event.src_port, dst_ip, event.dst_port, event.is_ipv6
                );
            }
            EVENT_REDIRECT_DETECTED => {
                warn!(
                    "HTTP Redirect detected: {}:{} -> {}:{}, ipv6={}",
                    src_ip, event.src_port, dst_ip, event.dst_port, event.is_ipv6
                );
            }
            EVENT_SSL_ERROR_DETECTED => {
                warn!(
                    "SSL Error detected: {}:{} -> {}:{}, ipv6={}",
                    src_ip, event.src_port, dst_ip, event.dst_port, event.is_ipv6
                );
            }
            EVENT_DISORDER_TRIGGERED => {
                info!(
                    "Disorder triggered: {}:{} -> {}:{}, seq={}, ipv6={}",
                    src_ip, event.src_port, dst_ip, event.dst_port,
                    u32::from_be(event.seq), event.is_ipv6
                );
            }
            _ => debug!("Unknown event type: {}", event.event_type),
        }

        0
    }

    pub fn spawn_ringbuf_monitor(&self, _skel: Arc<dyn RingBufferOps>) {
        // Spawn a blocking task for ring buffer polling
        tokio::task::spawn_blocking(move || {
            // This would use the actual ring buffer from libbpf-rs
            // For now, it's a placeholder
            loop {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        });
    }
}


// TODO: trait `RingBufferOps` is never used
// Trait for ring buffer operations (to be implemented with actual libbpf)
/// Trait for ring buffer operations (to be implemented with actual libbpf)
pub trait RingBufferOps: Send + Sync {
    /// Poll the ring buffer for events
    /// 
    /// # Arguments
    /// * `timeout` - Timeout in milliseconds (-1 for infinite)
    /// 
    /// # Returns
    /// Number of events consumed, or negative value on error
    fn poll(&self, timeout: i32) -> i32;
}

pub async fn load_and_attach(
    interface: &str,
    config: Arc<RwLock<DpiConfig>>,
) -> Result<BpfSkel> {
    info!("Loading eBPF programs for interface: {}", interface);

    // Setup TC qdisc
    tc::setup_qdisc(interface)?;

    // Get interface index
    let ifidx = if_nametoindex(interface)
        .with_context(|| format!(
            "Failed to get interface index for '{}'. Please ensure the interface exists and you have sufficient permissions.",
            interface
        ))?;

    info!("Interface {} has index {}", interface, ifidx);

    // Get config bytes
    let config_guard = config.read().await;
    let config_bytes = config_guard.to_bytes()
        .context("Failed to serialize configuration for eBPF map. This is likely a bug in the config parser.")?;
    drop(config_guard);

    // For now, use tc directly to load BPF object
    let bpf_obj = concat!(env!("OUT_DIR"), "/goodbyedpi.bpf.o");
    
    // Attach TC programs with config (egress loads both, ingress just attaches)
    tc::attach_egress(interface, bpf_obj, &config_bytes)?;
    tc::attach_ingress(interface, bpf_obj)?;

    info!("eBPF programs loaded and attached to {}", interface);

    // Initialize connection state and injector
    let state = ConnectionState::new();
    let injector = RawInjector::new()
        .context("Failed to initialize raw socket injector. Ensure you have CAP_NET_RAW capability or run as root.")?;

    Ok(BpfSkel {
        config,
        state,
        injector,
        interface: interface.to_string(),
    })
}

impl Drop for BpfSkel {
    fn drop(&mut self) {
        // Cleanup TC filters and pinned maps
        let _ = tc::full_cleanup(&self.interface);
    }
}
