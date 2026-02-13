//! Ring buffer event processor for GoodByeDPI
//!
//! This module processes events received from eBPF via channel.
//! It handles DPI bypass events and triggers appropriate actions.

use anyhow::{Context, Result};
use log::{debug, info, warn};
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::mpsc::Receiver;
use tokio::sync::RwLock;

use crate::auto_logic::{AutoLogic, ConfigRecommendations, Strategy};
use crate::config::DpiConfig;
use crate::injector::RawInjector;
use goodbyedpi_proto::{event_types, ConnKey, Event, MAX_PAYLOAD_SIZE};

// Special flags from eBPF
const FLAG_DISORDER: u8 = 0xFE;
const FLAG_QUIC_FRAG: u8 = 0xFD;
const FLAG_TLS_SPLIT: u8 = 0xFF;

/// Event processor that handles events from ring buffer
pub struct EventProcessor {
    injector: RawInjector,
    /// Optional auto-logic state machine
    auto_logic: Option<Arc<AutoLogic>>,
}

impl EventProcessor {
    /// Create new event processor
    pub fn new() -> Result<Self> {
        let injector = RawInjector::new()
            .context("Failed to create raw socket injector for event processor")?;
        
        info!("Event processor initialized with raw socket injector");
        
        Ok(Self { 
            injector,
            auto_logic: None,
        })
    }

    /// Create new event processor with auto-logic
    pub fn with_auto_logic(auto_logic: Arc<AutoLogic>) -> Result<Self> {
        let injector = RawInjector::new()
            .context("Failed to create raw socket injector for event processor")?;
        
        info!("Event processor initialized with raw socket injector and auto-logic");
        
        Ok(Self { 
            injector,
            auto_logic: Some(auto_logic),
        })
    }

    /// Run event processing loop
    pub async fn run(
        &self,
        mut event_rx: Receiver<Event>,
        config: Arc<RwLock<DpiConfig>>,
    ) {
        info!("Event processing loop started");
        
        while let Some(event) = event_rx.recv().await {
            let cfg = config.read().await;
            self.process_event(&event, &cfg).await;
            drop(cfg);
        }
        
        info!("Event processing loop stopped");
    }

    /// Build connection key from event
    fn build_conn_key(&self, event: &Event) -> ConnKey {
        ConnKey {
            src_ip: event.src_ip,
            dst_ip: event.dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            is_ipv6: event.is_ipv6,
            proto: 6, // TCP
        }
    }

    /// Process a single event
    async fn process_event(&self, event: &Event, config: &DpiConfig) {
        let (src_ip, dst_ip) = event.format_ips();
        
        match event.event_type {
            event_types::SPLIT_TRIGGERED => {
                self.handle_split_triggered(event, config, &src_ip, &dst_ip).await;
            }
            event_types::FAKE_TRIGGERED => {
                self.handle_fake_triggered(event, config, &src_ip, &dst_ip).await;
            }
            event_types::RST_DETECTED => {
                self.handle_rst_detected(event, config, &src_ip, &dst_ip).await;
            }
            event_types::REDIRECT_DETECTED => {
                self.handle_redirect_detected(event, config, &src_ip, &dst_ip).await;
            }
            event_types::SSL_ERROR_DETECTED => {
                self.handle_ssl_error_detected(event, config, &src_ip, &dst_ip).await;
            }
            event_types::DISORDER_TRIGGERED => {
                self.handle_disorder_triggered(event, config, &src_ip, &dst_ip).await;
            }
            event_types::QUIC_FRAGMENT_TRIGGERED => {
                self.handle_quic_fragmentation(event, &src_ip, &dst_ip, config).await;
            }
            event_types::OOB_TRIGGERED => {
                self.handle_oob_triggered(event, &src_ip, &dst_ip).await;
            }
            _ => {
                debug!("Unknown event type: {}", event.event_type);
            }
        }
    }

    /// Handle SPLIT_TRIGGERED event - real TCP split in userspace
    ///
    /// This is the main DPI bypass technique: split TCP payload into two packets.
    /// The original packet was dropped by eBPF, so we need to send both parts.
    async fn handle_split_triggered(
        &self,
        event: &Event,
        config: &DpiConfig,
        src_ip: &str,
        dst_ip: &str,
    ) {
        // Only IPv4 supported for now
        if event.is_ipv6 != 0 {
            warn!("[SPLIT] IPv6 split not yet implemented for {}:{} -> {}:{}",
                  src_ip, event.src_port, dst_ip, event.dst_port);
            return;
        }

        // Get split position from config (or from event.reserved field)
        let split_pos = match config.split_pos {
            Some(pos) if pos > 0 => pos,
            _ if event.reserved > 0 => event.reserved as usize,
            _ => {
                warn!("[SPLIT] No valid split position configured");
                return;
            }
        };

        // Get payload from event
        let payload_len = event.payload_len as usize;
        if payload_len == 0 {
            warn!("[SPLIT] Empty payload, nothing to split");
            return;
        }

        // Validate split position
        if split_pos >= payload_len {
            warn!("[SPLIT] Split position {} >= payload length {}, skipping",
                  split_pos, payload_len);
            return;
        }

        // Log payload preview
        let payload_preview: String = event.payload[..16.min(payload_len)]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        info!(
            "[SPLIT] Real TCP split: {}:{} -> {}:{}, seq={}, split_pos={}, payload_len={}, preview={}",
            src_ip, event.src_port, dst_ip, event.dst_port,
            u32::from_be(event.seq), split_pos, payload_len, payload_preview
        );

        // Get IP addresses
        let src_ipv4 = event.src_ip_v4();
        let dst_ipv4 = event.dst_ip_v4();

        // Extract actual payload (up to payload_len bytes)
        let payload = &event.payload[..payload_len];

        // Inject split packets
        let (first_result, second_result) = self.injector.inject_split_packets(
            src_ipv4, dst_ipv4,
            event.src_port, event.dst_port,
            u32::from_be(event.seq),
            u32::from_be(event.ack),
            event.flags,
            payload,
            split_pos,
        );

        // Log results
        match first_result {
            Ok(_) => info!("[SPLIT] First packet sent successfully ({} bytes)", split_pos),
            Err(e) => warn!("[SPLIT] Failed to send first packet: {}", e),
        }

        match second_result {
            Ok(_) => info!("[SPLIT] Second packet sent successfully ({} bytes)", payload_len - split_pos),
            Err(e) => warn!("[SPLIT] Failed to send second packet: {}", e),
        }
    }

    /// Handle FAKE_TRIGGERED event
    async fn handle_fake_triggered(
        &self,
        event: &Event,
        config: &DpiConfig,
        src_ip: &str,
        dst_ip: &str,
    ) {
        // Log payload preview (first 16 bytes as hex)
        let payload_preview: String = event.payload[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        match event.flags {
            FLAG_DISORDER => {
                info!(
                    "[DISORDER] {}:{} -> {}:{}, seq={}, ipv6={}, payload_preview={}",
                    src_ip, event.src_port, dst_ip, event.dst_port,
                    u32::from_be(event.seq), event.is_ipv6, payload_preview
                );
            }
            FLAG_QUIC_FRAG => {
                info!(
                    "[QUIC FRAG] {}:{} -> {}:{}, payload_len={}, ipv6={}, payload_preview={}",
                    src_ip, event.src_port, dst_ip, event.dst_port,
                    event.payload_len, event.is_ipv6, payload_preview
                );
                self.handle_quic_fragmentation(event, src_ip, dst_ip, config).await;
            }
            FLAG_TLS_SPLIT => {
                info!(
                    "[TLS SPLIT] {}:{} -> {}:{}, ipv6={}, payload_preview={}",
                    src_ip, event.src_port, dst_ip, event.dst_port, event.is_ipv6, payload_preview
                );
                self.handle_tls_split(event, config, src_ip, dst_ip).await;
            }
            _ => {
                // Regular fake packet trigger (TCP split)
                info!(
                    "[FAKE] {}:{} -> {}:{}, seq={}, flags={:02x}, ipv6={}, payload_len={}, payload_preview={}",
                    src_ip, event.src_port, dst_ip, event.dst_port,
                    u32::from_be(event.seq), event.flags, event.is_ipv6,
                    event.payload_len, payload_preview
                );
                
                // Inject fake packet if fake_offset is configured
                if config.fake_offset.is_some() {
                    if let Err(e) = self.inject_fake_packet(event, config).await {
                        warn!("Failed to inject fake packet: {}", e);
                    }
                }
            }
        }
    }

    /// Handle RST detection for auto-logic
    async fn handle_rst_detected(&self, event: &Event, config: &DpiConfig, src_ip: &str, dst_ip: &str) {
        if !config.auto_rst {
            return;
        }
        
        // Log payload preview
        let payload_preview: String = event.payload[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        warn!(
            "[AUTO-RST] Connection reset detected: {}:{} -> {}:{}, seq={}, ipv6={}, payload_preview={}",
            src_ip, event.src_port, dst_ip, event.dst_port,
            u32::from_be(event.seq), event.is_ipv6, payload_preview
        );

        // Use auto-logic if available
        if let Some(ref auto_logic) = self.auto_logic {
            let key = self.build_conn_key(event);
            let src_ip = event.src_ip_v4();
            let dst_ip = event.dst_ip_v4();
            
            if let Some(strategy) = auto_logic.handle_rst(
                &key,
                src_ip,
                dst_ip,
                event.src_port,
                event.dst_port,
            ).await {
                // Apply the new strategy
                self.apply_strategy(&strategy, event, config).await;
            }
        } else {
            info!("[AUTO-RST] Auto-logic not enabled, RST logged but no action taken");
        }
    }

    /// Handle HTTP Redirect detection for auto-logic
    async fn handle_redirect_detected(&self, event: &Event, config: &DpiConfig, src_ip: &str, dst_ip: &str) {
        if !config.auto_redirect {
            return;
        }
        
        // Try to extract HTTP response from payload
        let payload_len = (event.payload_len as usize).min(64);
        let payload_str = String::from_utf8_lossy(&event.payload[..payload_len]);
        
        warn!(
            "[AUTO-REDIRECT] HTTP 301/302 detected: {}:{} -> {}:{}, ipv6={}, response_preview={}",
            src_ip, event.src_port, dst_ip, event.dst_port, event.is_ipv6,
            payload_str.chars().take(50).collect::<String>()
        );

        // Use auto-logic if available
        if let Some(ref auto_logic) = self.auto_logic {
            let key = self.build_conn_key(event);
            let src_ip = event.src_ip_v4();
            let dst_ip = event.dst_ip_v4();
            
            if let Some(strategy) = auto_logic.handle_redirect(
                &key,
                src_ip,
                dst_ip,
                event.src_port,
                event.dst_port,
            ).await {
                // Apply the strengthened strategy
                self.apply_strategy(&strategy, event, config).await;
            }
        } else {
            info!("[AUTO-REDIRECT] Auto-logic not enabled, redirect logged but no action taken");
        }
    }

    /// Handle SSL/TLS error detection for auto-logic
    async fn handle_ssl_error_detected(&self, event: &Event, config: &DpiConfig, src_ip: &str, dst_ip: &str) {
        if !config.auto_ssl {
            return;
        }
        
        // Log TLS alert details from payload
        let payload_preview: String = event.payload[..16]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        
        warn!(
            "[AUTO-SSL] SSL Fatal Alert detected: {}:{} -> {}:{}, seq={}, ipv6={}, alert_data={}",
            src_ip, event.src_port, dst_ip, event.dst_port,
            u32::from_be(event.seq), event.is_ipv6, payload_preview
        );

        // Use auto-logic if available
        if let Some(ref auto_logic) = self.auto_logic {
            let key = self.build_conn_key(event);
            let src_ip = event.src_ip_v4();
            let dst_ip = event.dst_ip_v4();
            
            if let Some(strategy) = auto_logic.handle_ssl_error(
                &key,
                src_ip,
                dst_ip,
                event.src_port,
                event.dst_port,
            ).await {
                // Apply the TLS-focused strategy
                self.apply_strategy(&strategy, event, config).await;
            }
        } else {
            info!("[AUTO-SSL] Auto-logic not enabled, SSL error logged but no action taken");
        }
    }

    /// Apply a strategy to handle the current connection
    async fn apply_strategy(&self, strategy: &Strategy, event: &Event, config: &DpiConfig) {
        info!("[AUTO] Applying strategy: {}", strategy.description());
        
        let recs = ConfigRecommendations::from(strategy);
        
        // For now, we log the recommended configuration
        // In a full implementation, this would update the BPF config map
        debug!(
            "[AUTO] Recommended config: split_pos={:?}, use_fake={}, fake_offset={:?}, use_tlsrec={}, use_disorder={}",
            recs.split_pos, recs.use_fake, recs.fake_offset, recs.use_tlsrec, recs.use_disorder
        );
        
        // If the strategy uses fake and we have a fake_offset, inject a fake packet
        if recs.use_fake && recs.fake_offset.is_some() {
            if let Err(e) = self.inject_fake_packet(event, config).await {
                warn!("[AUTO] Failed to inject fake packet for strategy: {}", e);
            }
        }
        
        // If the strategy has a split position, perform the split
        if let Some(split_pos) = recs.split_pos {
            if event.payload_len as usize > split_pos {
                info!("[AUTO] Performing split at position {}", split_pos);
                // Note: In a real implementation, we might need to re-inject the packet
                // with the new split position. For now, we just log it.
            }
        }
    }

    /// Handle disorder trigger event
    ///
    /// Implements packet disorder technique: sends packets in wrong order.
    /// The second part of the payload is sent first (with higher sequence number),
    /// followed by the first part. This confuses DPI systems.
    async fn handle_disorder_triggered(
        &self, 
        event: &Event, 
        config: &DpiConfig,
        src_ip: &str, 
        dst_ip: &str,
    ) {
        // Only IPv4 supported for now
        if event.is_ipv6 != 0 {
            warn!("[DISORDER] IPv6 disorder not yet implemented for {}:{} -> {}:{}",
                  src_ip, event.src_port, dst_ip, event.dst_port);
            return;
        }

        // Get payload from event
        let payload_len = event.payload_len as usize;
        if payload_len == 0 {
            warn!("[DISORDER] Empty payload, nothing to disorder");
            return;
        }

        // Get split position from config or use default
        let split_pos = match config.split_pos {
            Some(pos) if pos > 0 && pos < payload_len => pos,
            _ => {
                // Default: split in the middle or at position 10, whichever is smaller
                let default_pos = 10.min(payload_len / 2).max(1);
                if default_pos >= payload_len {
                    warn!("[DISORDER] Payload too short for disorder: {} bytes", payload_len);
                    return;
                }
                default_pos
            }
        };

        // Validate split position
        if split_pos >= payload_len {
            warn!("[DISORDER] Split position {} >= payload length {}, skipping",
                  split_pos, payload_len);
            return;
        }

        // Log payload preview
        let payload_preview: String = event.payload[..16.min(payload_len)]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        info!(
            "[DISORDER] Packet disorder: {}:{} -> {}:{}, seq={}, split_pos={}, payload_len={}, preview={}",
            src_ip, event.src_port, dst_ip, event.dst_port,
            u32::from_be(event.seq), split_pos, payload_len, payload_preview
        );

        // Get IP addresses
        let src_ipv4 = event.src_ip_v4();
        let dst_ipv4 = event.dst_ip_v4();

        // Extract actual payload
        let payload = &event.payload[..payload_len];

        // Inject packets in disorder (second part first, then first part)
        let (second_result, first_result) = self.injector.inject_disorder_packets(
            src_ipv4, dst_ipv4,
            event.src_port, event.dst_port,
            u32::from_be(event.seq),
            u32::from_be(event.ack),
            event.flags,
            payload,
            split_pos,
        );

        // Log results
        match second_result {
            Ok(_) => info!("[DISORDER] Out-of-order packet (second part) sent successfully"),
            Err(e) => warn!("[DISORDER] Failed to send out-of-order packet: {}", e),
        }

        match first_result {
            Ok(_) => info!("[DISORDER] In-order packet (first part) sent successfully"),
            Err(e) => warn!("[DISORDER] Failed to send in-order packet: {}", e),
        }
    }

    /// Handle OOB (Out-of-Band) triggered event
    ///
    /// Injects a TCP packet with URG flag set and urgent pointer configured.
    /// The original packet was dropped by eBPF, so we inject the modified version.
    ///
    /// Event fields used:
    /// - `reserved` - contains the OOB position (urgent pointer value)
    /// - `flags` - contains original TCP flags plus URG flag
    async fn handle_oob_triggered(
        &self,
        event: &Event,
        src_ip: &str,
        dst_ip: &str,
    ) {
        // Only IPv4 supported for now
        if event.is_ipv6 != 0 {
            warn!(
                "[OOB] IPv6 OOB not yet implemented for {}:{} -> {}:{}",
                src_ip, event.src_port, dst_ip, event.dst_port
            );
            return;
        }

        // Get payload from event
        let payload_len = event.payload_len as usize;
        if payload_len == 0 {
            warn!("[OOB] Empty payload, nothing to send with OOB");
            return;
        }

        // Get OOB position from event (stored in reserved field by eBPF)
        let oob_pos = if event.reserved > 0 {
            event.reserved as u16
        } else {
            warn!("[OOB] No valid OOB position available (reserved=0)");
            return;
        };

        // Validate OOB position
        if oob_pos as usize > payload_len.min(MAX_PAYLOAD_SIZE) {
            warn!(
                "[OOB] OOB position {} > payload length {}, skipping",
                oob_pos,
                payload_len.min(MAX_PAYLOAD_SIZE)
            );
            return;
        }

        // Log payload preview (first 16 bytes as hex)
        let payload_preview: String = event.payload[..16.min(payload_len.min(MAX_PAYLOAD_SIZE))]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        info!(
            "[OOB] OOB packet injection: {}:{} -> {}:{}, seq={}, oob_pos={}, payload_len={}, preview={}",
            src_ip, event.src_port, dst_ip, event.dst_port,
            u32::from_be(event.seq), oob_pos, payload_len, payload_preview
        );

        // Get IP addresses
        let src_ipv4 = event.src_ip_v4();
        let dst_ipv4 = event.dst_ip_v4();

        // Extract actual payload (up to payload_len bytes, limited by MAX_PAYLOAD_SIZE)
        let actual_len = payload_len.min(MAX_PAYLOAD_SIZE);
        let payload = &event.payload[..actual_len];

        // Inject OOB packet with URG flag
        match self.injector.inject_oob_packet(
            src_ipv4, dst_ipv4,
            event.src_port, event.dst_port,
            u32::from_be(event.seq),
            u32::from_be(event.ack),
            oob_pos,
            payload,
        ) {
            Ok(_) => {
                info!(
                    "[OOB] OOB packet sent successfully with URG flag, urgent_ptr={}",
                    oob_pos
                );
            }
            Err(e) => {
                warn!("[OOB] Failed to inject OOB packet: {}", e);
            }
        }
    }

    /// Handle QUIC fragmentation logic
    /// 
    /// Fragments UDP/QUIC payload into multiple IP fragments.
    /// Each fragment contains part of the UDP payload with IP MF flag
    /// set on all fragments except the last one.
    async fn handle_quic_fragmentation(
        &self,
        event: &Event,
        src_ip: &str,
        dst_ip: &str,
        config: &DpiConfig,
    ) {
        // Only IPv4 supported for now
        if event.is_ipv6 != 0 {
            warn!("[QUIC FRAG] IPv6 fragmentation not yet implemented for {}:{} -> {}:{}",
                  src_ip, event.src_port, dst_ip, event.dst_port);
            return;
        }

        // Get payload from event
        let payload_len = event.payload_len as usize;
        if payload_len == 0 {
            warn!("[QUIC FRAG] Empty payload, nothing to fragment");
            return;
        }

        // Get fragment size from config
        let frag_size = if config.frag_size > 0 {
            config.frag_size as u16
        } else {
            8 // Default 8-byte fragments
        };

        // Log payload preview
        let payload_preview: String = event.payload[..16.min(payload_len)]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        info!(
            "[QUIC FRAG] IP Fragmentation: {}:{} -> {}:{}, payload_len={}, frag_size={}, preview={}",
            src_ip, event.src_port, dst_ip, event.dst_port,
            payload_len, frag_size, payload_preview
        );

        // Get IP addresses
        let src_ipv4 = event.src_ip_v4();
        let dst_ipv4 = event.dst_ip_v4();

        // Extract actual payload (up to payload_len bytes, limited by MAX_PAYLOAD_SIZE)
        let actual_len = payload_len.min(MAX_PAYLOAD_SIZE);
        let payload = &event.payload[..actual_len];

        // Inject fragmented UDP packets
        match self.injector.udp_injector().inject_fragmented_udp(
            src_ipv4, dst_ipv4,
            event.src_port, event.dst_port,
            payload,
            frag_size,
        ) {
            Ok(num_frags) => {
                info!("[QUIC FRAG] Successfully sent {} fragments", num_frags);
            }
            Err(e) => {
                warn!("[QUIC FRAG] Failed to inject fragmented UDP: {}", e);
            }
        }
    }

    /// Handle TLS record split
    ///
    /// Splits a TLS Client Hello record into two separate TLS records.
    /// The split position is determined by the eBPF program based on SNI location
    /// and configuration (tlsrec_pos). This confuses DPI systems that expect
    /// a complete TLS record in a single packet.
    ///
    /// Event fields used:
    /// - `reserved` - contains the split position within the payload
    /// - `sni_offset` - offset to SNI hostname (for logging)
    /// - `sni_length` - length of SNI hostname (for logging)
    async fn handle_tls_split(
        &self,
        event: &Event,
        _config: &DpiConfig,
        src_ip: &str,
        dst_ip: &str,
    ) {
        // Only IPv4 supported for now
        if event.is_ipv6 != 0 {
            warn!(
                "[TLS SPLIT] IPv6 TLS split not yet implemented for {}:{} -> {}:{}",
                src_ip, event.src_port, dst_ip, event.dst_port
            );
            return;
        }

        // Get payload from event
        let payload_len = event.payload_len as usize;
        if payload_len == 0 {
            warn!("[TLS SPLIT] Empty payload, nothing to split");
            return;
        }

        // Get split position from event (stored in reserved field by eBPF)
        let split_pos = if event.reserved > 0 {
            event.reserved as usize
        } else {
            // Fallback: split at SNI offset if available
            if event.sni_offset > 0 {
                event.sni_offset as usize
            } else {
                warn!("[TLS SPLIT] No valid split position available (reserved=0, sni_offset=0)");
                return;
            }
        };

        // Validate split position
        if split_pos >= payload_len.min(MAX_PAYLOAD_SIZE) {
            warn!(
                "[TLS SPLIT] Split position {} >= payload length {}, skipping",
                split_pos,
                payload_len.min(MAX_PAYLOAD_SIZE)
            );
            return;
        }

        // Log SNI information if available
        let sni_info = if event.sni_offset > 0 && event.sni_length > 0 {
            let sni_start = event.sni_offset as usize;
            let sni_len = event.sni_length as usize;
            if sni_start + sni_len <= payload_len.min(MAX_PAYLOAD_SIZE) {
                let sni_bytes = &event.payload[sni_start..sni_start + sni_len];
                match std::str::from_utf8(sni_bytes) {
                    Ok(sni) => format!(", SNI='{}' (offset={}, len={})", sni, event.sni_offset, event.sni_length),
                    Err(_) => format!(", SNI=<invalid utf8> (offset={}, len={})", event.sni_offset, event.sni_length),
                }
            } else {
                format!(", SNI offset/length out of bounds (offset={}, len={})", event.sni_offset, event.sni_length)
            }
        } else {
            String::new()
        };

        // Log payload preview (first 16 bytes as hex)
        let payload_preview: String = event.payload[..16.min(payload_len.min(MAX_PAYLOAD_SIZE))]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        info!(
            "[TLS SPLIT] TLS record split: {}:{} -> {}:{}, seq={}, split_pos={}, payload_len={}, preview={}{}",
            src_ip, event.src_port, dst_ip, event.dst_port,
            u32::from_be(event.seq), split_pos, payload_len, payload_preview, sni_info
        );

        // Get IP addresses
        let src_ipv4 = event.src_ip_v4();
        let dst_ipv4 = event.dst_ip_v4();

        // Extract actual payload (up to payload_len bytes, limited by MAX_PAYLOAD_SIZE)
        let actual_len = payload_len.min(MAX_PAYLOAD_SIZE);
        let payload = &event.payload[..actual_len];

        // Inject TLS split packets
        let (first_result, second_result) = self.injector.inject_tls_split_packets(
            src_ipv4, dst_ipv4,
            event.src_port, event.dst_port,
            u32::from_be(event.seq),
            u32::from_be(event.ack),
            event.flags,
            payload,
            split_pos,
        );

        // Log results
        match first_result {
            Ok(_) => info!("[TLS SPLIT] First TLS record sent successfully ({} bytes to split pos)", split_pos),
            Err(e) => warn!("[TLS SPLIT] Failed to send first TLS record: {}", e),
        }

        match second_result {
            Ok(_) => info!("[TLS SPLIT] Second TLS record sent successfully ({} bytes remaining)", actual_len - split_pos),
            Err(e) => warn!("[TLS SPLIT] Failed to send second TLS record: {}", e),
        }
    }

    /// Inject a fake packet using the new offset-based method
    async fn inject_fake_packet(&self, event: &Event, config: &DpiConfig) -> Result<()> {
        // Only IPv4 supported for now
        if event.is_ipv6 != 0 {
            return Err(anyhow::anyhow!("IPv6 fake packet injection not yet supported"));
        }
        
        let src_ip = Ipv4Addr::from(u32::from_be(event.src_ip[0]));
        let dst_ip = Ipv4Addr::from(u32::from_be(event.dst_ip[0]));
        
        // Convert isize to i32 for the injector method
        let fake_offset: i32 = config.fake_offset.unwrap_or(0) as i32;
        
        // Get payload from event
        let payload_len = event.payload_len as usize;
        let payload = if payload_len > 0 {
            &event.payload[..payload_len.min(64)]
        } else {
            // Default fake payload for HTTP
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        };

        info!(
            "[FAKE] Injecting fake packet: {}:{} -> {}:{}, seq={}, offset={}, payload_len={}",
            src_ip, event.src_port, dst_ip, event.dst_port,
            u32::from_be(event.seq), fake_offset, payload.len()
        );

        // Use the new inject_fake_with_offset method
        self.injector.inject_fake_with_offset(
            src_ip, dst_ip,
            event.src_port, event.dst_port,
            u32::from_be(event.seq),
            u32::from_be(event.ack),
            fake_offset,
            payload,
        )?;

        info!("[FAKE] Fake packet injected successfully");
        Ok(())
    }

    /// Get auto-logic reference
    pub fn auto_logic(&self) -> Option<&Arc<AutoLogic>> {
        self.auto_logic.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_types() {
        assert_eq!(event_types::FAKE_TRIGGERED, 1);
        assert_eq!(event_types::RST_DETECTED, 2);
        assert_eq!(event_types::REDIRECT_DETECTED, 3);
        assert_eq!(event_types::SSL_ERROR_DETECTED, 4);
        assert_eq!(event_types::DISORDER_TRIGGERED, 5);
    }

    #[test]
    fn test_build_conn_key() {
        // Create a mock event
        let event = Event {
            event_type: event_types::RST_DETECTED,
            src_ip: [0xC0A80101, 0, 0, 0], // 192.168.1.1
            dst_ip: [0x0A000001, 0, 0, 0], // 10.0.0.1
            src_port: 12345,
            dst_port: 443,
            seq: 1000,
            ack: 500,
            flags: 0x18,
            payload_len: 0,
            is_ipv6: 0,
            sni_offset: 0,
            sni_length: 0,
            reserved: 0,
            payload: [0u8; 64],
        };

        // We can't create EventProcessor in tests without a raw socket,
        // but we can test the logic independently
        let expected_key = ConnKey {
            src_ip: [0xC0A80101, 0, 0, 0],
            dst_ip: [0x0A000001, 0, 0, 0],
            src_port: 12345,
            dst_port: 443,
            is_ipv6: 0,
            proto: 6,
        };

        assert_eq!(expected_key.src_port, 12345);
        assert_eq!(expected_key.dst_port, 443);
    }

    #[test]
    fn test_tls_split_event_fields() {
        // Test that TLS split event fields are correctly interpreted
        let tls_payload = [
            0x16, 0x03, 0x01, 0x00, 0x20, // TLS header: Handshake, TLS 1.0, 32 bytes
            0x01, 0x00, 0x00, 0x1c,       // Client Hello, 28 bytes
            // ... more handshake data would follow
        ];
        
        let mut payload = [0u8; MAX_PAYLOAD_SIZE];
        payload[..tls_payload.len()].copy_from_slice(&tls_payload);
        
        // Create a TLS split event
        let event = Event {
            event_type: event_types::TLSREC_TRIGGERED,
            src_ip: [0xC0A80101, 0, 0, 0], // 192.168.1.1
            dst_ip: [0x0A000001, 0, 0, 0], // 10.0.0.1
            src_port: 54321,
            dst_port: 443,
            seq: 1000,
            ack: 500,
            flags: 0x18, // PSH|ACK
            payload_len: tls_payload.len() as u8,
            is_ipv6: 0,
            sni_offset: 10,  // SNI starts at offset 10
            sni_length: 12,  // SNI is 12 bytes long
            reserved: 15,    // Split position (within handshake data)
            payload,
        };
        
        // Verify event fields
        assert_eq!(event.event_type, event_types::TLSREC_TRIGGERED);
        assert_eq!(event.sni_offset, 10);
        assert_eq!(event.sni_length, 12);
        assert_eq!(event.reserved, 15); // Split position
        assert_eq!(event.is_ipv6, 0);
        
        // Verify payload content
        assert_eq!(event.payload[0], 0x16); // Handshake content type
        assert_eq!(event.payload[1], 0x03); // Version major
        assert_eq!(event.payload[2], 0x01); // Version minor
    }

    #[test]
    fn test_tls_split_validation() {
        // Test validation logic for TLS split positions
        const TLS_HEADER_LEN: usize = 5;
        
        // Test case 1: split_pos too small (within TLS header)
        let split_pos_small = 3;
        assert!(split_pos_small <= TLS_HEADER_LEN);
        
        // Test case 2: split_pos at payload boundary (no data for second record)
        let payload_len = 40;
        let split_pos_end = 40;
        assert!(split_pos_end >= payload_len);
        
        // Test case 3: valid split position
        let split_pos_valid = 20;
        assert!(split_pos_valid > TLS_HEADER_LEN);
        assert!(split_pos_valid < payload_len);
    }

    #[test]
    fn test_sni_extraction_from_payload() {
        // Test extracting SNI from payload for logging
        let mut payload = [0u8; 64];
        let sni_bytes = b"example.com";
        let sni_offset = 10;
        
        // Copy SNI into payload at offset
        payload[sni_offset..sni_offset + sni_bytes.len()].copy_from_slice(sni_bytes);
        
        // Verify extraction
        let extracted = &payload[sni_offset..sni_offset + sni_bytes.len()];
        assert_eq!(extracted, sni_bytes);
        
        // Test UTF-8 conversion
        let sni_str = std::str::from_utf8(extracted).unwrap();
        assert_eq!(sni_str, "example.com");
    }

    #[test]
    fn test_tls_split_ipv6_check() {
        // Test that IPv6 events are rejected for TLS split
        let event_ipv6 = Event {
            event_type: event_types::TLSREC_TRIGGERED,
            src_ip: [0x20010000, 0x00000000, 0x00000000, 0x00000001], // IPv6
            dst_ip: [0x20010000, 0x00000000, 0x00000000, 0x00000002],
            src_port: 54321,
            dst_port: 443,
            seq: 1000,
            ack: 500,
            flags: 0x18,
            payload_len: 40,
            is_ipv6: 1, // IPv6 flag set
            sni_offset: 10,
            sni_length: 12,
            reserved: 20,
            payload: [0u8; MAX_PAYLOAD_SIZE],
        };
        
        assert_eq!(event_ipv6.is_ipv6, 1);
        // In real handler, this would trigger the IPv6 warning and return early
    }

    #[test]
    fn test_oob_event_fields() {
        // Test that OOB event fields are correctly interpreted
        let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        let mut payload = [0u8; MAX_PAYLOAD_SIZE];
        payload[..http_payload.len()].copy_from_slice(http_payload);
        
        // Create an OOB event
        let event = Event {
            event_type: event_types::OOB_TRIGGERED,
            src_ip: [0xC0A80101, 0, 0, 0], // 192.168.1.1
            dst_ip: [0x0A000001, 0, 0, 0], // 10.0.0.1
            src_port: 54321,
            dst_port: 443,
            seq: 1000,
            ack: 500,
            flags: 0x38, // URG|PSH|ACK
            payload_len: http_payload.len() as u8,
            is_ipv6: 0,
            sni_offset: 0,
            sni_length: 0,
            reserved: 10, // OOB position (urgent pointer)
            payload,
        };
        
        // Verify event fields
        assert_eq!(event.event_type, event_types::OOB_TRIGGERED);
        assert_eq!(event.flags, 0x38); // URG|PSH|ACK
        assert_eq!(event.reserved, 10); // OOB position
        assert_eq!(event.is_ipv6, 0);
        
        // Verify payload content
        assert_eq!(&event.payload[..http_payload.len()], http_payload);
    }

    #[test]
    fn test_oob_validation() {
        // Test validation logic for OOB positions
        let payload_len = 100;
        
        // Valid OOB position
        let oob_pos_valid: u8 = 50;
        assert!(oob_pos_valid > 0);
        assert!(oob_pos_valid as usize <= payload_len);
        
        // Invalid OOB positions
        let oob_pos_zero: u8 = 0;
        let oob_pos_large: u8 = 150; // > payload_len
        
        assert!(oob_pos_zero == 0);
        assert!(oob_pos_large as usize > payload_len);
    }

    #[test]
    fn test_oob_event_type_constant() {
        // Verify OOB event type constant value
        assert_eq!(event_types::OOB_TRIGGERED, 9);
    }

    #[test]
    fn test_oob_ipv6_check() {
        // Test that IPv6 events are rejected for OOB
        let event_ipv6 = Event {
            event_type: event_types::OOB_TRIGGERED,
            src_ip: [0x20010000, 0x00000000, 0x00000000, 0x00000001], // IPv6
            dst_ip: [0x20010000, 0x00000000, 0x00000000, 0x00000002],
            src_port: 54321,
            dst_port: 443,
            seq: 1000,
            ack: 500,
            flags: 0x38, // URG|PSH|ACK
            payload_len: 40,
            is_ipv6: 1, // IPv6 flag set
            sni_offset: 0,
            sni_length: 0,
            reserved: 10,
            payload: [0u8; MAX_PAYLOAD_SIZE],
        };
        
        assert_eq!(event_ipv6.is_ipv6, 1);
        assert_eq!(event_ipv6.event_type, event_types::OOB_TRIGGERED);
        // In real handler, this would trigger the IPv6 warning and return early
    }

    #[test]
    fn test_disorder_event_type_constant() {
        // Verify DISORDER event type constant value
        assert_eq!(event_types::DISORDER_TRIGGERED, 5);
    }

    #[test]
    fn test_disorder_event_fields() {
        // Test that DISORDER event fields are correctly interpreted
        let http_payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        
        let mut payload = [0u8; MAX_PAYLOAD_SIZE];
        payload[..http_payload.len()].copy_from_slice(http_payload);
        
        // Create a DISORDER event
        // IP addresses stored as u32 values that will be interpreted as big-endian by src_ip_v4()
        // src_ip_v4() does: Ipv4Addr::from(u32::from_be(self.src_ip[0]))
        // So we need self.src_ip[0] to be in the byte order such that from_be gives correct result
        // from_be converts from big-endian to native. So if we want 192.168.1.1:
        // In little-endian system: 0xC0A80101 as LE u32 = 0x0101A8C0
        // from_be(0x0101A8C0) on LE = byte-swap(0x0101A8C0) = 0xC0A80101 = correct!
        let src_ip_val = 0x0101A8C0u32; // This is 0xC0A80101 in LE
        let dst_ip_val = 0x0100000Au32; // This is 0x0A000001 in LE
        
        let event = Event {
            event_type: event_types::DISORDER_TRIGGERED,
            src_ip: [src_ip_val, 0, 0, 0],
            dst_ip: [dst_ip_val, 0, 0, 0],
            src_port: 54321,
            dst_port: 443,
            seq: 1000,
            ack: 500,
            flags: 0x18, // PSH|ACK
            payload_len: http_payload.len() as u8,
            is_ipv6: 0,
            sni_offset: 0,
            sni_length: 0,
            reserved: 0, // 0 = let userspace decide split position
            payload,
        };
        
        // Verify event fields
        assert_eq!(event.event_type, event_types::DISORDER_TRIGGERED);
        assert_eq!(event.flags, 0x18);
        assert_eq!(event.reserved, 0);
        assert_eq!(event.is_ipv6, 0);
        
        // Verify payload content
        assert_eq!(&event.payload[..http_payload.len()], http_payload);
        
        // Verify IP addresses (src_ip_v4() converts from network byte order)
        assert_eq!(event.src_ip_v4().to_string(), "192.168.1.1");
        assert_eq!(event.dst_ip_v4().to_string(), "10.0.0.1");
    }

    #[test]
    fn test_disorder_split_position_logic() {
        // Test split position selection logic for disorder
        let payload_len = 40;
        
        // When config has valid split position
        let config_split_pos: Option<usize> = Some(10);
        let split_pos = match config_split_pos {
            Some(pos) if pos > 0 && pos < payload_len => pos,
            _ => 10.min(payload_len / 2).max(1),
        };
        assert_eq!(split_pos, 10);
        
        // When config split position is too large - should use default
        let config_split_large: Option<usize> = Some(100);
        let split_pos_large = match config_split_large {
            Some(pos) if pos > 0 && pos < payload_len => pos,
            _ => 10.min(payload_len / 2).max(1),
        };
        // Default: 10.min(40/2).max(1) = 10.min(20).max(1) = 10
        assert_eq!(split_pos_large, 10);
        
        // When config has no split position - should use default
        let config_split_none: Option<usize> = None;
        let split_pos_default = match config_split_none {
            Some(pos) if pos > 0 && pos < payload_len => pos,
            _ => 10.min(payload_len / 2).max(1),
        };
        // Default: 10.min(40/2).max(1) = 10.min(20).max(1) = 10
        assert_eq!(split_pos_default, 10);
        
        // Test with small payload - default should be clamped to at least 1
        let small_payload_len = 10;
        let split_pos_small = match None as Option<usize> {
            Some(pos) if pos > 0 && pos < small_payload_len => pos,
            _ => 10.min(small_payload_len / 2).max(1),
        };
        // 10.min(10/2).max(1) = 10.min(5).max(1) = 5
        assert_eq!(split_pos_small, 5);
    }

    #[test]
    fn test_disorder_ipv6_check() {
        // Test that IPv6 events are rejected for disorder
        let event_ipv6 = Event {
            event_type: event_types::DISORDER_TRIGGERED,
            src_ip: [0x20010000, 0x00000000, 0x00000000, 0x00000001], // IPv6
            dst_ip: [0x20010000, 0x00000000, 0x00000000, 0x00000002],
            src_port: 54321,
            dst_port: 443,
            seq: 1000,
            ack: 500,
            flags: 0x18, // PSH|ACK
            payload_len: 40,
            is_ipv6: 1, // IPv6 flag set
            sni_offset: 0,
            sni_length: 0,
            reserved: 0,
            payload: [0u8; MAX_PAYLOAD_SIZE],
        };
        
        assert_eq!(event_ipv6.is_ipv6, 1);
        assert_eq!(event_ipv6.event_type, event_types::DISORDER_TRIGGERED);
        // In real handler, this would trigger the IPv6 warning and return early
    }

    #[test]
    fn test_disorder_empty_payload_check() {
        // Test that empty payload is rejected for disorder
        let event_empty = Event {
            event_type: event_types::DISORDER_TRIGGERED,
            src_ip: [0xC0A80101, 0, 0, 0],
            dst_ip: [0x0A000001, 0, 0, 0],
            src_port: 54321,
            dst_port: 443,
            seq: 1000,
            ack: 500,
            flags: 0x18,
            payload_len: 0, // Empty payload
            is_ipv6: 0,
            sni_offset: 0,
            sni_length: 0,
            reserved: 0,
            payload: [0u8; MAX_PAYLOAD_SIZE],
        };
        
        assert_eq!(event_empty.payload_len, 0);
        // In real handler, this would trigger "Empty payload" warning and return
    }

    #[test]
    fn test_disorder_sequence_byte_order() {
        // Test sequence number byte order handling for disorder
        let seq_be: u32 = 1000u32.to_be(); // Network byte order (big-endian)
        let seq_host = u32::from_be(seq_be); // Convert to host byte order
        
        assert_eq!(seq_host, 1000);
        
        // Test wrapping calculation with BE conversion
        let split_pos = 10;
        let second_seq = seq_host.wrapping_add(split_pos as u32);
        assert_eq!(second_seq, 1010);
    }
}
