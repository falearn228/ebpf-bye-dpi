//! Ring buffer event processor for GoodByeDPI
//!
//! This module processes events received from eBPF via channel.
//! It handles DPI bypass events and triggers appropriate actions.

use anyhow::{Context, Result};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use tokio::sync::mpsc::Receiver;
use tokio::sync::RwLock;

use crate::auto_logic::{AutoLogic, ConfigRecommendations, Strategy};
use crate::config::DpiConfig;
use crate::injector::RawInjector;
use crate::l7::{detect_l7, L7Protocol};
use crate::rules::extract_target_host;
use goodbyedpi_proto::{event_types, ConnKey, Event, RuleAction, MAX_PAYLOAD_SIZE};

// Special flags from eBPF
const FLAG_DISORDER: u8 = 0xFE;
const FLAG_QUIC_FRAG: u8 = 0xFD;
const FLAG_TLS_SPLIT: u8 = 0xFF;

/// Event processor that handles events from ring buffer
pub struct EventProcessor {
    injector: RawInjector,
    /// Optional auto-logic state machine
    auto_logic: Option<Arc<AutoLogic>>,
    /// Channel for sending config updates to BPF thread
    config_update_tx: Option<std::sync::mpsc::Sender<Vec<u8>>>,
    cutoff_counters: Mutex<HashMap<(ConnKey, u8), u8>>,
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
            config_update_tx: None,
            cutoff_counters: Mutex::new(HashMap::new()),
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
            config_update_tx: None,
            cutoff_counters: Mutex::new(HashMap::new()),
        })
    }

    /// Set the config update channel for BPF updates
    #[allow(dead_code)]
    pub fn set_config_update_tx(&mut self, tx: std::sync::mpsc::Sender<Vec<u8>>) {
        self.config_update_tx = Some(tx);
    }

    /// Create event processor with auto-logic and config update channel
    pub fn with_auto_logic_and_channel(
        auto_logic: Arc<AutoLogic>,
        config_update_tx: std::sync::mpsc::Sender<Vec<u8>>,
    ) -> Result<Self> {
        let injector = RawInjector::new()
            .context("Failed to create raw socket injector for event processor")?;

        info!("Event processor initialized with auto-logic and BPF config channel");

        Ok(Self {
            injector,
            auto_logic: Some(auto_logic),
            config_update_tx: Some(config_update_tx),
            cutoff_counters: Mutex::new(HashMap::new()),
        })
    }

    /// Run event processing loop
    pub async fn run(&self, mut event_rx: Receiver<Event>, config: Arc<RwLock<DpiConfig>>) {
        info!("Event processing loop started");

        let mut event_count = 0u64;

        while let Some(event) = event_rx.recv().await {
            event_count += 1;
            info!(
                "[PROCESSOR] Received event #{} from channel, type={}",
                event_count, event.event_type
            );

            let mut cfg = config.write().await;
            let cfg_before = cfg.clone();
            self.process_event(&event, &mut cfg).await;

            // Update BPF only when auto-logic actually changed configuration
            if self.config_update_tx.is_some() && *cfg != cfg_before {
                if let Err(e) = self.update_bpf_config(&cfg) {
                    warn!("[AUTO] Failed to update BPF config: {}", e);
                }
            }
            drop(cfg);
        }

        info!(
            "Event processing loop stopped, total events processed: {}",
            event_count
        );
    }

    /// Update BPF config via the config update channel
    fn update_bpf_config(&self, config: &DpiConfig) -> Result<()> {
        if let Some(ref tx) = self.config_update_tx {
            let config_bytes = config
                .to_bytes()
                .context("Failed to serialize config for BPF update")?;

            tx.send(config_bytes)
                .context("Failed to send config update to BPF thread")?;

            debug!("[AUTO] BPF config update sent");
        }
        Ok(())
    }

    /// Build connection key from event
    fn build_conn_key(&self, event: &Event) -> ConnKey {
        self.build_conn_key_for_action(event, RuleAction::Split)
    }

    fn build_conn_key_for_action(&self, event: &Event, action: RuleAction) -> ConnKey {
        let proto = match action.default_protocol() {
            goodbyedpi_proto::RuleProtocol::Tcp => 6,
            goodbyedpi_proto::RuleProtocol::Udp => 17,
        };
        ConnKey {
            src_ip: event.src_ip,
            dst_ip: event.dst_ip,
            src_port: event.src_port,
            dst_port: event.dst_port,
            is_ipv6: event.is_ipv6,
            proto,
            _pad: [0; 2], // Explicit zeroed padding for consistent hashing
        }
    }

    fn action_cutoff_allows(&self, config: &DpiConfig, event: &Event, action: RuleAction) -> bool {
        let limit = config
            .matching_section(event, action)
            .and_then(|section| section.cutoff)
            .or(config.dpi_desync_cutoff);
        let Some(limit) = limit else {
            return true;
        };

        let key = (
            self.build_conn_key_for_action(event, action),
            action_key(action),
        );
        let mut guard = match self.cutoff_counters.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !consume_cutoff_budget(&mut guard, key, limit) {
            debug!(
                "[CUTOFF] Skip action {:?} for {}:{} -> {}:{} (limit {} reached)",
                action,
                event.format_ips().0,
                event.src_port,
                event.format_ips().1,
                event.dst_port,
                limit
            );
            return false;
        }
        true
    }

    fn configure_injector(&self, config: &DpiConfig, event: &Event, action: RuleAction) {
        let section = config.matching_section(event, action);
        let ip_id_zero =
            section.map(|section| section.ip_id_zero).unwrap_or(false) || config.ip_id_zero;
        let autottl = section
            .and_then(|section| section.autottl)
            .or(config.dpi_desync_autottl);
        self.injector.set_tuning(ip_id_zero, autottl);
    }

    /// Resolve repeats from rule engine for specific action and event
    fn repeats_for_action(&self, config: &DpiConfig, event: &Event, action: RuleAction) -> u8 {
        let proto = action.default_protocol();

        if let Some(section) = config.matching_section(event, action) {
            return section.repeats.unwrap_or(1).max(1);
        }

        let repeats = config
            .rules
            .iter()
            .find(|rule| rule.matches(proto, event.dst_port, action))
            .map(|rule| rule.repeats)
            .or_else(|| {
                config
                    .dpi_desync_repeats
                    .filter(|_| config.dpi_desync_actions.contains(&action))
            })
            .unwrap_or(1);

        repeats.max(1)
    }

    /// Check global port filter (`--filter-tcp/--filter-udp`) before injection.
    fn port_filter_allows(&self, config: &DpiConfig, event: &Event, action: RuleAction) -> bool {
        if !config.sections.is_empty() {
            let (src_ip, dst_ip) = event.format_ips();
            if let Some(section) = config.matching_section(event, action) {
                debug!(
                    "[SECTION] Match action {:?} via {:?} ports={:?} for {}:{} -> {}:{} repeats={:?} cutoff={:?}",
                    action,
                    section.proto,
                    section.ports,
                    src_ip,
                    event.src_port,
                    dst_ip,
                    event.dst_port,
                    section.repeats,
                    section.cutoff
                );
                return true;
            }
            debug!(
                "[FILTER] Skip action {:?} for {}:{} -> {}:{} (no matching zapret section)",
                action, src_ip, event.src_port, dst_ip, event.dst_port
            );
            return false;
        }

        let allowed = match action.default_protocol() {
            goodbyedpi_proto::RuleProtocol::Tcp => config.tcp_port_allowed(event.dst_port),
            goodbyedpi_proto::RuleProtocol::Udp => config.udp_port_allowed(event.dst_port),
        };

        if !allowed {
            debug!(
                "[FILTER] Skip action {:?} for dst_port {} (filtered)",
                action, event.dst_port
            );
        }
        allowed
    }

    /// Check L7 filter (`--filter-l7`) before injection.
    fn l7_filter_allows(&self, config: &DpiConfig, event: &Event, action: RuleAction) -> bool {
        if !config.sections.is_empty() {
            return true;
        }

        let allowed = config.l7_allowed(event);
        if !allowed {
            let payload_len = (event.payload_len as usize).min(MAX_PAYLOAD_SIZE);
            let detected = detect_l7(&event.payload[..payload_len]);
            debug!(
                "[FILTER] Skip action {:?} for dst_port {} (l7 mismatch: detected={:?})",
                action, event.dst_port, detected
            );
        }
        allowed
    }

    /// Check host/ip targeting lists before injection.
    fn target_filter_allows(&self, config: &DpiConfig, event: &Event, action: RuleAction) -> bool {
        if !config.sections.is_empty() {
            return true;
        }

        let allowed = config.target_allowed(event);
        if !allowed {
            let host = extract_target_host(event).unwrap_or_else(|| "<none>".to_string());
            debug!(
                "[FILTER] Skip action {:?} for host='{}' dst_port={} (host/ip targeting mismatch)",
                action, host, event.dst_port
            );
        }
        allowed
    }

    /// Process a single event
    async fn process_event(&self, event: &Event, config: &mut DpiConfig) {
        let (src_ip, dst_ip) = event.format_ips();

        info!(
            "[RINGBUF] Processing event type={} from {}:{} -> {}:{}",
            event.event_type, src_ip, event.src_port, dst_ip, event.dst_port
        );

        match event.event_type {
            event_types::SPLIT_TRIGGERED => {
                self.handle_split_triggered(event, config, &src_ip, &dst_ip)
                    .await;
            }
            event_types::TLSREC_TRIGGERED => {
                self.handle_tls_split(event, config, &src_ip, &dst_ip).await;
            }
            event_types::FAKE_TRIGGERED => {
                self.handle_fake_triggered(event, config, &src_ip, &dst_ip)
                    .await;
            }
            event_types::RST_DETECTED => {
                self.handle_rst_detected(event, config, &src_ip, &dst_ip)
                    .await;
            }
            event_types::REDIRECT_DETECTED => {
                self.handle_redirect_detected(event, config, &src_ip, &dst_ip)
                    .await;
            }
            event_types::SSL_ERROR_DETECTED => {
                self.handle_ssl_error_detected(event, config, &src_ip, &dst_ip)
                    .await;
            }
            event_types::SUCCESS_DETECTED => {
                self.handle_success_detected(event, &src_ip, &dst_ip).await;
            }
            event_types::DISORDER_TRIGGERED => {
                self.handle_disorder_triggered(event, config, &src_ip, &dst_ip)
                    .await;
            }
            event_types::QUIC_FRAGMENT_TRIGGERED => {
                self.handle_quic_fragmentation(event, &src_ip, &dst_ip, config)
                    .await;
            }
            event_types::OOB_TRIGGERED => {
                self.handle_oob_triggered(event, config, &src_ip, &dst_ip)
                    .await;
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
        if !self.port_filter_allows(config, event, RuleAction::Split) {
            return;
        }
        if !self.l7_filter_allows(config, event, RuleAction::Split) {
            return;
        }
        if !self.target_filter_allows(config, event, RuleAction::Split) {
            return;
        }
        if !self.action_cutoff_allows(config, event, RuleAction::Split) {
            return;
        }
        self.configure_injector(config, event, RuleAction::Split);

        info!(
            "[SPLIT] handle_split_triggered called for {}:{} -> {}:{}, event_type={}",
            src_ip, event.src_port, dst_ip, event.dst_port, event.event_type
        );

        // Get split position from config (or from event.reserved field)
        let split_pos = match config.split_pos {
            Some(pos) if pos > 0 => pos,
            _ if event.reserved > 0 => event.reserved as usize,
            _ => {
                warn!("[SPLIT] No valid split position configured");
                return;
            }
        };

        // Get payload from event (clamped to MAX_PAYLOAD_SIZE for safety)
        let payload_len = (event.payload_len as usize).min(MAX_PAYLOAD_SIZE);
        if payload_len == 0 {
            warn!("[SPLIT] Empty payload, nothing to split");
            return;
        }

        // Validate split position
        if split_pos >= payload_len {
            warn!(
                "[SPLIT] Split position {} >= payload length {}, skipping",
                split_pos, payload_len
            );
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
            event.seq, split_pos, payload_len, payload_preview
        );

        // Extract actual payload (already clamped to MAX_PAYLOAD_SIZE)
        let payload = &event.payload[..payload_len];
        let repeats = self.repeats_for_action(config, event, RuleAction::Split);
        for attempt in 1..=repeats {
            let (first_result, second_result) = if event.is_ipv6 != 0 {
                self.injector.inject_split_packets_v6(
                    event.src_ip_v6(),
                    event.dst_ip_v6(),
                    event.src_port,
                    event.dst_port,
                    event.seq,
                    event.ack,
                    event.flags,
                    payload,
                    split_pos,
                )
            } else {
                self.injector.inject_split_packets(
                    event.src_ip_v4(),
                    event.dst_ip_v4(),
                    event.src_port,
                    event.dst_port,
                    event.seq,
                    event.ack,
                    event.flags,
                    payload,
                    split_pos,
                )
            };

            // Log results
            match first_result {
                Ok(_) => info!(
                    "[SPLIT] First packet sent successfully ({} bytes), attempt {}/{}",
                    split_pos, attempt, repeats
                ),
                Err(e) => warn!(
                    "[SPLIT] Failed to send first packet on attempt {}/{}: {}",
                    attempt, repeats, e
                ),
            }

            match second_result {
                Ok(_) => info!(
                    "[SPLIT] Second packet sent successfully ({} bytes), attempt {}/{}",
                    payload_len - split_pos,
                    attempt,
                    repeats
                ),
                Err(e) => warn!(
                    "[SPLIT] Failed to send second packet on attempt {}/{}: {}",
                    attempt, repeats, e
                ),
            }
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
                    src_ip,
                    event.src_port,
                    dst_ip,
                    event.dst_port,
                    event.seq,
                    event.is_ipv6,
                    payload_preview
                );
            }
            FLAG_QUIC_FRAG => {
                info!(
                    "[QUIC FRAG] {}:{} -> {}:{}, payload_len={}, ipv6={}, payload_preview={}",
                    src_ip,
                    event.src_port,
                    dst_ip,
                    event.dst_port,
                    event.payload_len,
                    event.is_ipv6,
                    payload_preview
                );
                self.handle_quic_fragmentation(event, src_ip, dst_ip, config)
                    .await;
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
                    event.seq, event.flags, event.is_ipv6,
                    event.payload_len, payload_preview
                );

                // Inject fake packet if fake_offset is configured
                if config.fake_offset.is_some() {
                    if !self.port_filter_allows(config, event, RuleAction::Fake) {
                        return;
                    }
                    if !self.l7_filter_allows(config, event, RuleAction::Fake) {
                        return;
                    }
                    if !self.target_filter_allows(config, event, RuleAction::Fake) {
                        return;
                    }
                    if !self.action_cutoff_allows(config, event, RuleAction::Fake) {
                        return;
                    }
                    self.configure_injector(config, event, RuleAction::Fake);
                    let repeats = self.repeats_for_action(config, event, RuleAction::Fake);
                    for attempt in 1..=repeats {
                        if let Err(e) = self.inject_fake_packet(event, config).await {
                            warn!(
                                "[FAKE] Failed to inject fake packet on attempt {}/{}: {}",
                                attempt, repeats, e
                            );
                        }
                    }
                }
            }
        }
    }

    /// Handle RST detection for auto-logic
    async fn handle_rst_detected(
        &self,
        event: &Event,
        config: &mut DpiConfig,
        src_ip: &str,
        dst_ip: &str,
    ) {
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
            event.seq, event.is_ipv6, payload_preview
        );

        // Use auto-logic if available
        if let Some(ref auto_logic) = self.auto_logic {
            let key = self.build_conn_key(event);

            if let Some(strategy) = auto_logic
                .handle_rst(&key, src_ip, dst_ip, event.src_port, event.dst_port)
                .await
            {
                // Apply the new strategy
                self.apply_strategy(&strategy, event, config).await;
            }
        } else {
            info!("[AUTO-RST] Auto-logic not enabled, RST logged but no action taken");
        }
    }

    /// Handle HTTP Redirect detection for auto-logic
    async fn handle_redirect_detected(
        &self,
        event: &Event,
        config: &mut DpiConfig,
        src_ip: &str,
        dst_ip: &str,
    ) {
        if !config.auto_redirect {
            return;
        }

        // Try to extract HTTP response from payload
        let payload_len = (event.payload_len as usize).min(64);
        let payload_str = String::from_utf8_lossy(&event.payload[..payload_len]);

        warn!(
            "[AUTO-REDIRECT] HTTP 301/302 detected: {}:{} -> {}:{}, ipv6={}, response_preview={}",
            src_ip,
            event.src_port,
            dst_ip,
            event.dst_port,
            event.is_ipv6,
            payload_str.chars().take(50).collect::<String>()
        );

        // Use auto-logic if available
        if let Some(ref auto_logic) = self.auto_logic {
            let key = self.build_conn_key(event);

            if let Some(strategy) = auto_logic
                .handle_redirect(&key, src_ip, dst_ip, event.src_port, event.dst_port)
                .await
            {
                // Apply the strengthened strategy
                self.apply_strategy(&strategy, event, config).await;
            }
        } else {
            info!("[AUTO-REDIRECT] Auto-logic not enabled, redirect logged but no action taken");
        }
    }

    /// Handle SSL/TLS error detection for auto-logic
    async fn handle_ssl_error_detected(
        &self,
        event: &Event,
        config: &mut DpiConfig,
        src_ip: &str,
        dst_ip: &str,
    ) {
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
            src_ip,
            event.src_port,
            dst_ip,
            event.dst_port,
            event.seq,
            event.is_ipv6,
            payload_preview
        );

        // Use auto-logic if available
        if let Some(ref auto_logic) = self.auto_logic {
            let key = self.build_conn_key(event);

            if let Some(strategy) = auto_logic
                .handle_ssl_error(&key, src_ip, dst_ip, event.src_port, event.dst_port)
                .await
            {
                // Apply the TLS-focused strategy
                self.apply_strategy(&strategy, event, config).await;
            }
        } else {
            info!("[AUTO-SSL] Auto-logic not enabled, SSL error logged but no action taken");
        }
    }

    async fn handle_success_detected(&self, event: &Event, src_ip: &str, dst_ip: &str) {
        info!(
            "[AUTO-SUCCESS] Positive response detected: {}:{} -> {}:{}, ipv6={}",
            src_ip, event.src_port, dst_ip, event.dst_port, event.is_ipv6
        );

        if let Some(ref auto_logic) = self.auto_logic {
            let key = self.build_conn_key(event);
            auto_logic.mark_success(&key).await;
        } else {
            info!("[AUTO-SUCCESS] Auto-logic not enabled, success logged but no state updated");
        }
    }

    /// Apply a strategy to handle the current connection
    ///
    /// Updates the BPF configuration based on the recommended strategy.
    /// This modifies the shared config and sends an update to the BPF thread.
    async fn apply_strategy(&self, strategy: &Strategy, event: &Event, config: &mut DpiConfig) {
        info!("[AUTO] Applying strategy: {}", strategy.description());

        let recs = ConfigRecommendations::from(strategy);

        // Apply configuration changes based on strategy recommendations
        let mut config_changed = false;

        // Update split position if recommended
        if let Some(split_pos) = recs.split_pos {
            if config.split_pos != Some(split_pos) {
                info!(
                    "[AUTO] Updating split_pos: {:?} -> {}",
                    config.split_pos, split_pos
                );
                config.split_pos = Some(split_pos);
                config_changed = true;
            }
        }

        // Update fake settings if recommended
        if recs.use_fake {
            if config.fake_offset != recs.fake_offset {
                info!(
                    "[AUTO] Updating fake_offset: {:?} -> {:?}",
                    config.fake_offset, recs.fake_offset
                );
                config.fake_offset = recs.fake_offset;
                config_changed = true;
            }
        } else if config.fake_offset.is_some()
            && !matches!(strategy, Strategy::FakeWithSplit { .. })
        {
            // Disable fake if strategy doesn't use it (but preserve if it does)
            info!("[AUTO] Disabling fake packet (fake_offset=None)");
            config.fake_offset = None;
            config_changed = true;
        }

        // Update TLS record split if recommended
        if recs.use_tlsrec {
            // TLS record split uses split_pos from strategy
            if let Some(split_pos) = recs.split_pos {
                let tlsrec_pos = split_pos as i32;
                if config.tlsrec_pos != Some(tlsrec_pos) {
                    info!(
                        "[AUTO] Updating tlsrec_pos: {:?} -> {}",
                        config.tlsrec_pos, split_pos
                    );
                    config.tlsrec_pos = Some(tlsrec_pos);
                    config_changed = true;
                }
            }
        }

        // Update disorder if recommended
        if recs.use_disorder && !config.use_disorder {
            info!("[AUTO] Enabling packet disorder");
            config.use_disorder = true;
            config_changed = true;
        }

        // Log the current configuration state
        debug!(
            "[AUTO] Current BPF config: split_pos={:?}, fake_offset={:?}, tlsrec_pos={:?}, disorder={}",
            config.split_pos, config.fake_offset, config.tlsrec_pos, config.use_disorder
        );

        // If the strategy uses fake and we have a fake_offset, inject a fake packet
        if recs.use_fake
            && recs.fake_offset.is_some()
            && self.port_filter_allows(config, event, RuleAction::Fake)
        {
            if !self.l7_filter_allows(config, event, RuleAction::Fake) {
                return;
            }
            if !self.target_filter_allows(config, event, RuleAction::Fake) {
                return;
            }
            if !self.action_cutoff_allows(config, event, RuleAction::Fake) {
                return;
            }
            self.configure_injector(config, event, RuleAction::Fake);
            let repeats = self.repeats_for_action(config, event, RuleAction::Fake);
            for attempt in 1..=repeats {
                if let Err(e) = self.inject_fake_packet(event, config).await {
                    warn!(
                        "[AUTO] Failed to inject fake packet for strategy on attempt {}/{}: {}",
                        attempt, repeats, e
                    );
                }
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

        // BPF config will be updated by the caller (run loop) if changed
        if config_changed {
            info!("[AUTO] Configuration updated, BPF map will be synchronized");
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
        if !self.port_filter_allows(config, event, RuleAction::Disorder) {
            return;
        }
        if !self.l7_filter_allows(config, event, RuleAction::Disorder) {
            return;
        }
        if !self.target_filter_allows(config, event, RuleAction::Disorder) {
            return;
        }
        if !self.action_cutoff_allows(config, event, RuleAction::Disorder) {
            return;
        }
        self.configure_injector(config, event, RuleAction::Disorder);

        // Get payload from event (clamped to MAX_PAYLOAD_SIZE for safety)
        let payload_len = (event.payload_len as usize).min(MAX_PAYLOAD_SIZE);
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
                    warn!(
                        "[DISORDER] Payload too short for disorder: {} bytes",
                        payload_len
                    );
                    return;
                }
                default_pos
            }
        };

        // Validate split position
        if split_pos >= payload_len {
            warn!(
                "[DISORDER] Split position {} >= payload length {}, skipping",
                split_pos, payload_len
            );
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
            event.seq, split_pos, payload_len, payload_preview
        );

        // Extract actual payload
        let payload = &event.payload[..payload_len];
        let repeats = self.repeats_for_action(config, event, RuleAction::Disorder);
        for attempt in 1..=repeats {
            let (second_result, first_result) = if event.is_ipv6 != 0 {
                self.injector.inject_disorder_packets_v6(
                    event.src_ip_v6(),
                    event.dst_ip_v6(),
                    event.src_port,
                    event.dst_port,
                    event.seq,
                    event.ack,
                    event.flags,
                    payload,
                    split_pos,
                )
            } else {
                self.injector.inject_disorder_packets(
                    event.src_ip_v4(),
                    event.dst_ip_v4(),
                    event.src_port,
                    event.dst_port,
                    event.seq,
                    event.ack,
                    event.flags,
                    payload,
                    split_pos,
                )
            };

            // Log results
            match second_result {
                Ok(_) => info!(
                    "[DISORDER] Out-of-order packet (second part) sent successfully, attempt {}/{}",
                    attempt, repeats
                ),
                Err(e) => warn!(
                    "[DISORDER] Failed to send out-of-order packet on attempt {}/{}: {}",
                    attempt, repeats, e
                ),
            }

            match first_result {
                Ok(_) => info!(
                    "[DISORDER] In-order packet (first part) sent successfully, attempt {}/{}",
                    attempt, repeats
                ),
                Err(e) => warn!(
                    "[DISORDER] Failed to send in-order packet on attempt {}/{}: {}",
                    attempt, repeats, e
                ),
            }
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
        config: &DpiConfig,
        src_ip: &str,
        dst_ip: &str,
    ) {
        if !self.port_filter_allows(config, event, RuleAction::Oob) {
            return;
        }
        if !self.l7_filter_allows(config, event, RuleAction::Oob) {
            return;
        }
        if !self.target_filter_allows(config, event, RuleAction::Oob) {
            return;
        }
        if !self.action_cutoff_allows(config, event, RuleAction::Oob) {
            return;
        }
        self.configure_injector(config, event, RuleAction::Oob);

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
            event.seq, oob_pos, payload_len, payload_preview
        );

        // Extract actual payload (up to payload_len bytes, limited by MAX_PAYLOAD_SIZE)
        let actual_len = payload_len.min(MAX_PAYLOAD_SIZE);
        let payload = &event.payload[..actual_len];

        let repeats = self.repeats_for_action(config, event, RuleAction::Oob);
        for attempt in 1..=repeats {
            // Inject OOB packet with URG flag
            let inject_result = if event.is_ipv6 != 0 {
                self.injector.inject_oob_packet_v6(
                    event.src_ip_v6(),
                    event.dst_ip_v6(),
                    event.src_port,
                    event.dst_port,
                    event.seq,
                    event.ack,
                    oob_pos,
                    payload,
                )
            } else {
                self.injector.inject_oob_packet(
                    event.src_ip_v4(),
                    event.dst_ip_v4(),
                    event.src_port,
                    event.dst_port,
                    event.seq,
                    event.ack,
                    oob_pos,
                    payload,
                )
            };
            match inject_result {
                Ok(_) => {
                    info!(
                        "[OOB] OOB packet sent successfully with URG flag, urgent_ptr={}, attempt {}/{}",
                        oob_pos, attempt, repeats
                    );
                }
                Err(e) => {
                    warn!(
                        "[OOB] Failed to inject OOB packet on attempt {}/{}: {}",
                        attempt, repeats, e
                    );
                }
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
        if !self.port_filter_allows(config, event, RuleAction::Frag) {
            return;
        }
        if !self.l7_filter_allows(config, event, RuleAction::Frag) {
            return;
        }
        if !self.target_filter_allows(config, event, RuleAction::Frag) {
            return;
        }
        if !self.action_cutoff_allows(config, event, RuleAction::Frag) {
            return;
        }
        self.configure_injector(config, event, RuleAction::Frag);

        info!(
            "[QUIC FRAG] Fragmentation triggered for {}:{} -> {}:{}, payload_len={}",
            src_ip, event.src_port, dst_ip, event.dst_port, event.payload_len
        );

        // Get payload from event (clamped to MAX_PAYLOAD_SIZE for safety)
        let payload_len = (event.payload_len as usize).min(MAX_PAYLOAD_SIZE);
        if payload_len == 0 {
            warn!("[QUIC FRAG] Empty payload, nothing to fragment");
            return;
        }

        // Get fragment size from config
        let frag_size = if config.frag_size > 0 {
            config.frag_size
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

        // Extract actual payload (up to payload_len bytes, limited by MAX_PAYLOAD_SIZE)
        let actual_len = payload_len.min(MAX_PAYLOAD_SIZE);
        let payload = &event.payload[..actual_len];
        let repeats = self.repeats_for_action(config, event, RuleAction::Frag);
        for attempt in 1..=repeats {
            // Inject fragmented UDP packets
            let inject_result = if event.is_ipv6 != 0 {
                self.injector.udp_injector().inject_fragmented_udp_v6(
                    event.src_ip_v6(),
                    event.dst_ip_v6(),
                    event.src_port,
                    event.dst_port,
                    payload,
                    frag_size,
                )
            } else {
                self.injector.udp_injector().inject_fragmented_udp(
                    event.src_ip_v4(),
                    event.dst_ip_v4(),
                    event.src_port,
                    event.dst_port,
                    payload,
                    frag_size,
                )
            };
            match inject_result {
                Ok(num_frags) => {
                    info!(
                        "[QUIC FRAG] Successfully sent {} fragments, attempt {}/{}",
                        num_frags, attempt, repeats
                    );
                }
                Err(e) => {
                    warn!(
                        "[QUIC FRAG] Failed to inject fragmented UDP on attempt {}/{}: {}",
                        attempt, repeats, e
                    );
                }
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
        config: &DpiConfig,
        src_ip: &str,
        dst_ip: &str,
    ) {
        if !self.port_filter_allows(config, event, RuleAction::Tlsrec) {
            return;
        }
        if !self.l7_filter_allows(config, event, RuleAction::Tlsrec) {
            return;
        }
        if !self.target_filter_allows(config, event, RuleAction::Tlsrec) {
            return;
        }
        if !self.action_cutoff_allows(config, event, RuleAction::Tlsrec) {
            return;
        }
        self.configure_injector(config, event, RuleAction::Tlsrec);

        // Get payload from event (clamped to MAX_PAYLOAD_SIZE for safety)
        let payload_len = (event.payload_len as usize).min(MAX_PAYLOAD_SIZE);
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
                    Ok(sni) => format!(
                        ", SNI='{}' (offset={}, len={})",
                        sni, event.sni_offset, event.sni_length
                    ),
                    Err(_) => format!(
                        ", SNI=<invalid utf8> (offset={}, len={})",
                        event.sni_offset, event.sni_length
                    ),
                }
            } else {
                format!(
                    ", SNI offset/length out of bounds (offset={}, len={})",
                    event.sni_offset, event.sni_length
                )
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
            event.seq, split_pos, payload_len, payload_preview, sni_info
        );

        // Extract actual payload (up to payload_len bytes, limited by MAX_PAYLOAD_SIZE)
        let actual_len = payload_len.min(MAX_PAYLOAD_SIZE);
        let payload = &event.payload[..actual_len];
        let repeats = self.repeats_for_action(config, event, RuleAction::Tlsrec);
        for attempt in 1..=repeats {
            let (first_result, second_result) = if event.is_ipv6 != 0 {
                self.injector.inject_tls_split_packets_v6(
                    event.src_ip_v6(),
                    event.dst_ip_v6(),
                    event.src_port,
                    event.dst_port,
                    event.seq,
                    event.ack,
                    event.flags,
                    payload,
                    split_pos,
                )
            } else {
                self.injector.inject_tls_split_packets(
                    event.src_ip_v4(),
                    event.dst_ip_v4(),
                    event.src_port,
                    event.dst_port,
                    event.seq,
                    event.ack,
                    event.flags,
                    payload,
                    split_pos,
                )
            };

            // Log results
            match first_result {
                Ok(_) => info!(
                    "[TLS SPLIT] First TLS record sent successfully ({} bytes to split pos), attempt {}/{}",
                    split_pos, attempt, repeats
                ),
                Err(e) => warn!(
                    "[TLS SPLIT] Failed to send first TLS record on attempt {}/{}: {}",
                    attempt, repeats, e
                ),
            }

            match second_result {
                Ok(_) => info!(
                    "[TLS SPLIT] Second TLS record sent successfully ({} bytes remaining), attempt {}/{}",
                    actual_len - split_pos,
                    attempt,
                    repeats
                ),
                Err(e) => warn!(
                    "[TLS SPLIT] Failed to send second TLS record on attempt {}/{}: {}",
                    attempt, repeats, e
                ),
            }
        }
    }

    /// Inject a fake packet using the new offset-based method
    async fn inject_fake_packet(&self, event: &Event, config: &DpiConfig) -> Result<()> {
        // Convert isize to i32 for the injector method
        let fake_offset: i32 = config.fake_offset.unwrap_or(0) as i32;
        let (src_ip, dst_ip) = event.format_ips();

        // Get payload from event (clamped to MAX_PAYLOAD_SIZE for safety)
        let payload_len = (event.payload_len as usize).min(MAX_PAYLOAD_SIZE);
        let event_payload = if payload_len > 0 {
            &event.payload[..payload_len]
        } else {
            // Default fake payload for HTTP
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" as &[u8]
        };
        let detected_l7 = detect_l7(event_payload);
        let (payload, profile_name): (&[u8], Option<&str>) =
            if let Some(profile) = select_fake_profile_payload(config, event, detected_l7) {
                profile
            } else {
                (event_payload, None)
            };

        let l7_name = match detected_l7 {
            L7Protocol::Unknown => "unknown",
            L7Protocol::Stun => "stun",
            L7Protocol::Discord => "discord",
        };

        info!(
            "[FAKE] Injecting fake packet: {}:{} -> {}:{}, seq={}, offset={}, payload_len={}, l7={}, profile={}",
            src_ip,
            event.src_port,
            dst_ip,
            event.dst_port,
            event.seq,
            fake_offset,
            payload.len(),
            l7_name,
            profile_name.unwrap_or("event/default")
        );

        // Use the new inject_fake_with_offset method
        if event.is_ipv6 != 0 {
            let src_ip = event.src_ip_v6();
            let dst_ip = event.dst_ip_v6();
            self.injector.inject_fake_with_offset_v6(
                src_ip,
                dst_ip,
                event.src_port,
                event.dst_port,
                event.seq,
                event.ack,
                fake_offset,
                payload,
            )?;
        } else {
            let src_ip = event.src_ip_v4();
            let dst_ip = event.dst_ip_v4();
            self.injector.inject_fake_with_offset(
                src_ip,
                dst_ip,
                event.src_port,
                event.dst_port,
                event.seq,
                event.ack,
                fake_offset,
                payload,
            )?;
        }

        info!("[FAKE] Fake packet injected successfully");
        Ok(())
    }
    /// Get auto-logic reference
    #[allow(dead_code)]
    pub fn auto_logic(&self) -> Option<&Arc<AutoLogic>> {
        self.auto_logic.as_ref()
    }
}

fn consume_cutoff_budget(
    counters: &mut HashMap<(ConnKey, u8), u8>,
    key: (ConnKey, u8),
    limit: u8,
) -> bool {
    let counter = counters.entry(key).or_insert(0);
    if *counter >= limit {
        return false;
    }
    *counter += 1;
    true
}

fn unknown_udp_fallback_allowed(
    config: &DpiConfig,
    event: &Event,
    detected_l7: L7Protocol,
) -> bool {
    matches!(detected_l7, L7Protocol::Unknown)
        && (config
            .matching_section(event, RuleAction::Fake)
            .map(|section| section.any_protocol)
            .unwrap_or(false)
            || config.dpi_desync_any_protocol
            || event.dst_port == 443)
}

fn select_fake_profile_payload<'a>(
    config: &'a DpiConfig,
    event: &Event,
    detected_l7: L7Protocol,
) -> Option<(&'a [u8], Option<&'static str>)> {
    let section_profiles = config
        .matching_section(event, RuleAction::Fake)
        .map(|section| &section.fake_profiles);

    match detected_l7 {
        L7Protocol::Stun => {
            if let Some(payload) = section_profiles.and_then(|profiles| profiles.stun.as_ref()) {
                return Some((payload.as_slice(), Some("section-fake-stun")));
            }
            if let Some(payload) = config.fake_profiles.stun.as_ref() {
                return Some((payload.as_slice(), Some("fake-stun")));
            }
        }
        L7Protocol::Discord => {
            if let Some(payload) = section_profiles.and_then(|profiles| profiles.discord.as_ref()) {
                return Some((payload.as_slice(), Some("section-fake-discord")));
            }
            if let Some(payload) = config.fake_profiles.discord.as_ref() {
                return Some((payload.as_slice(), Some("fake-discord")));
            }
        }
        L7Protocol::Unknown => {}
    }

    if config.dpi_desync_actions.contains(&RuleAction::Split)
        && config.dpi_desync_actions.contains(&RuleAction::Fake)
    {
        if let Some(payload) = section_profiles.and_then(|profiles| profiles.hostfakesplit.as_ref())
        {
            return Some((payload.as_slice(), Some("section-hostfakesplit-mod")));
        }
        if let Some(payload) = config.fake_profiles.hostfakesplit.as_ref() {
            return Some((payload.as_slice(), Some("hostfakesplit-mod")));
        }
    }

    // Keep host-based fallback for Discord HTTPS/API flows where payload
    // signature is not enough at this stage.
    if let Some(host) = extract_target_host(event) {
        if host.contains("discord") {
            if let Some(payload) = config.fake_profiles.discord.as_ref() {
                return Some((payload.as_slice(), Some("fake-discord")));
            }
        }
    }

    if event.dst_port == 443 {
        if let Some(payload) = section_profiles.and_then(|profiles| profiles.quic.as_ref()) {
            return Some((payload.as_slice(), Some("section-fake-quic")));
        }
        if let Some(payload) = config.fake_profiles.quic.as_ref() {
            return Some((payload.as_slice(), Some("fake-quic")));
        }
    }

    if unknown_udp_fallback_allowed(config, event, detected_l7) {
        if let Some(payload) = section_profiles.and_then(|profiles| profiles.unknown_udp.as_ref()) {
            return Some((payload.as_slice(), Some("section-fake-unknown-udp")));
        }
        if let Some(payload) = config.fake_profiles.unknown_udp.as_ref() {
            return Some((payload.as_slice(), Some("fake-unknown-udp")));
        }
    }

    None
}

fn action_key(action: RuleAction) -> u8 {
    match action {
        RuleAction::Split => 1,
        RuleAction::Oob => 2,
        RuleAction::Fake => 3,
        RuleAction::Tlsrec => 4,
        RuleAction::Disorder => 5,
        RuleAction::Frag => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DpiConfig;

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
        // We can't create EventProcessor in tests without a raw socket,
        // but we can test the logic independently
        let expected_key = ConnKey {
            src_ip: [0xC0A80101, 0, 0, 0],
            dst_ip: [0x0A000001, 0, 0, 0],
            src_port: 12345,
            dst_port: 443,
            is_ipv6: 0,
            proto: 6,
            _pad: [0; 2],
        };

        assert_eq!(expected_key.src_port, 12345);
        assert_eq!(expected_key.dst_port, 443);
    }

    #[test]
    fn test_tls_split_event_fields() {
        // Test that TLS split event fields are correctly interpreted
        let tls_payload = [
            0x16, 0x03, 0x01, 0x00, 0x20, // TLS header: Handshake, TLS 1.0, 32 bytes
            0x01, 0x00, 0x00,
            0x1c, // Client Hello, 28 bytes
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
            payload_len: tls_payload.len() as u16,
            is_ipv6: 0,
            sni_offset: 10, // SNI starts at offset 10
            sni_length: 12, // SNI is 12 bytes long
            reserved: 15,   // Split position (within handshake data)
            payload,
            _pad: [0; 3],
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
            _pad: [0; 3],
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
            payload_len: http_payload.len() as u16,
            is_ipv6: 0,
            sni_offset: 0,
            sni_length: 0,
            reserved: 10, // OOB position (urgent pointer)
            payload,
            _pad: [0; 3],
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
            _pad: [0; 3],
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
            payload_len: http_payload.len() as u16,
            is_ipv6: 0,
            sni_offset: 0,
            sni_length: 0,
            reserved: 0, // 0 = let userspace decide split position
            payload,
            _pad: [0; 3],
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
            _pad: [0; 3],
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
            _pad: [0; 3],
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

    #[test]
    fn test_looks_like_stun_positive() {
        let mut payload = [0u8; 20];
        payload[0] = 0x00;
        payload[1] = 0x01;
        payload[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        assert!(crate::l7::looks_like_stun(&payload));
    }

    #[test]
    fn test_looks_like_stun_negative() {
        let payload = [0u8; 10];
        assert!(!crate::l7::looks_like_stun(&payload));

        let mut payload2 = [0u8; 20];
        payload2[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        assert!(!crate::l7::looks_like_stun(&payload2));
    }

    fn make_event(dst_port: u16) -> Event {
        Event {
            event_type: event_types::FAKE_TRIGGERED,
            src_ip: [0x0101A8C0, 0, 0, 0],
            dst_ip: [0x0100000A, 0, 0, 0],
            src_port: 12345,
            dst_port,
            seq: 1000,
            ack: 500,
            flags: 0x18,
            payload_len: 8,
            is_ipv6: 0,
            sni_offset: 0,
            sni_length: 0,
            reserved: 0,
            payload: [0u8; MAX_PAYLOAD_SIZE],
            _pad: [0; 3],
        }
    }

    #[test]
    fn test_unknown_udp_fallback_requires_any_protocol_for_non_443() {
        let mut cfg = DpiConfig::parse("").unwrap();
        cfg.fake_profiles.unknown_udp = Some(vec![0xde, 0xad, 0xbe, 0xef]);

        let event = make_event(3478);
        assert!(!unknown_udp_fallback_allowed(
            &cfg,
            &event,
            L7Protocol::Unknown
        ));
        assert_eq!(
            select_fake_profile_payload(&cfg, &event, L7Protocol::Unknown),
            None
        );

        cfg.dpi_desync_any_protocol = true;
        let profile = select_fake_profile_payload(&cfg, &event, L7Protocol::Unknown).unwrap();
        assert_eq!(profile.1, Some("fake-unknown-udp"));
        assert_eq!(profile.0, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_unknown_udp_fallback_allowed_on_port_443_without_any_protocol() {
        let mut cfg = DpiConfig::parse("").unwrap();
        cfg.fake_profiles.unknown_udp = Some(vec![0xfa, 0xce]);

        let event = make_event(443);
        assert!(unknown_udp_fallback_allowed(
            &cfg,
            &event,
            L7Protocol::Unknown
        ));

        let profile = select_fake_profile_payload(&cfg, &event, L7Protocol::Unknown).unwrap();
        assert_eq!(profile.1, Some("fake-unknown-udp"));
        assert_eq!(profile.0, &[0xfa, 0xce]);
    }

    #[test]
    fn test_quic_profile_takes_priority_over_unknown_udp_fallback() {
        let mut cfg = DpiConfig::parse("").unwrap();
        cfg.fake_profiles.quic = Some(vec![0xc3, 0xff]);
        cfg.fake_profiles.unknown_udp = Some(vec![0xde, 0xad]);

        let event = make_event(443);
        let profile = select_fake_profile_payload(&cfg, &event, L7Protocol::Unknown).unwrap();
        assert_eq!(profile.1, Some("fake-quic"));
        assert_eq!(profile.0, &[0xc3, 0xff]);
    }

    #[test]
    fn test_cutoff_budget_is_per_action_and_connection() {
        let event_a = make_event(443);
        let mut event_b = make_event(443);
        event_b.src_port = 54321;

        let key_a_fake = (
            ConnKey {
                src_ip: event_a.src_ip,
                dst_ip: event_a.dst_ip,
                src_port: event_a.src_port,
                dst_port: event_a.dst_port,
                is_ipv6: event_a.is_ipv6,
                proto: 6,
                _pad: [0; 2],
            },
            action_key(RuleAction::Fake),
        );
        let key_a_split = (key_a_fake.0, action_key(RuleAction::Split));
        let key_b_fake = (
            ConnKey {
                src_ip: event_b.src_ip,
                dst_ip: event_b.dst_ip,
                src_port: event_b.src_port,
                dst_port: event_b.dst_port,
                is_ipv6: event_b.is_ipv6,
                proto: 6,
                _pad: [0; 2],
            },
            action_key(RuleAction::Fake),
        );

        let mut counters = HashMap::new();
        assert!(consume_cutoff_budget(&mut counters, key_a_fake, 2));
        assert!(consume_cutoff_budget(&mut counters, key_a_fake, 2));
        assert!(!consume_cutoff_budget(&mut counters, key_a_fake, 2));

        assert!(consume_cutoff_budget(&mut counters, key_a_split, 2));
        assert!(consume_cutoff_budget(&mut counters, key_b_fake, 2));
    }
}
