//! Auto-Logic State Machine for DPI Bypass
//!
//! This module implements a state machine that automatically adjusts
//! DPI bypass strategies based on network feedback (RST, Redirect, SSL errors).
//!
//! # Strategy Flow
//!
//! ```text
//! TCP Split (pos=1) -> TCP Split (pos=2) -> TLS Record Split -> Disorder
//!        ^                                              |
//!        |______________________________________________|
//!                    (after 3 failed attempts each)
//!
//! On Redirect: Add fake packet to current strategy
//! On SSL Error: Switch to TLS-focused strategies
//! ```

use dashmap::DashMap;
use goodbyedpi_proto::{strategy_types, AutoLogicState, ConnKey};
use log::{debug, info};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Strategy configuration for a connection
#[derive(Debug, Clone)]
pub enum Strategy {
    /// TCP split at specific position
    TcpSplit(usize),
    /// TLS record split at SNI boundary
    TlsRecordSplit,
    /// Out-of-order packet delivery
    Disorder,
    /// Fake packet combined with split
    FakeWithSplit {
        split_pos: usize,
        fake_offset: isize,
    },
}

impl Strategy {
    /// Convert strategy to human-readable description
    pub fn description(&self) -> String {
        match self {
            Strategy::TcpSplit(pos) => format!("TCP split at position {}", pos),
            Strategy::TlsRecordSplit => "TLS record split".to_string(),
            Strategy::Disorder => "Out-of-order delivery".to_string(),
            Strategy::FakeWithSplit {
                split_pos,
                fake_offset,
            } => {
                format!(
                    "Fake packet (offset={}) + split at {}",
                    fake_offset, split_pos
                )
            }
        }
    }

    /// Get the split position if applicable
    #[allow(dead_code)]
    pub fn split_position(&self) -> Option<usize> {
        match self {
            Strategy::TcpSplit(pos) => Some(*pos),
            Strategy::FakeWithSplit { split_pos, .. } => Some(*split_pos),
            _ => None,
        }
    }

    /// Check if this strategy uses fake packets
    #[allow(dead_code)]
    pub fn uses_fake(&self) -> bool {
        matches!(self, Strategy::FakeWithSplit { .. })
    }

    /// Check if this strategy uses disorder
    #[allow(dead_code)]
    pub fn uses_disorder(&self) -> bool {
        matches!(self, Strategy::Disorder)
    }
}

impl From<&AutoLogicState> for Strategy {
    fn from(state: &AutoLogicState) -> Self {
        let split_pos = state.get_split_position();

        match state.strategy {
            strategy_types::TCP_SPLIT => Strategy::TcpSplit(split_pos),
            strategy_types::TLS_RECORD_SPLIT => Strategy::TlsRecordSplit,
            strategy_types::DISORDER => Strategy::Disorder,
            strategy_types::FAKE_WITH_SPLIT => Strategy::FakeWithSplit {
                split_pos,
                fake_offset: -1, // Default offset
            },
            _ => Strategy::TcpSplit(split_pos),
        }
    }
}

/// Connection state with auto-logic tracking
#[derive(Debug, Clone)]
pub struct AutoConnectionState {
    /// Current auto-logic state
    pub auto_state: AutoLogicState,
    /// Current strategy
    pub strategy: Strategy,
    /// When this state was created
    #[allow(dead_code)]
    pub created_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Number of RST events received
    pub rst_count: u32,
    /// Number of redirect events received
    pub redirect_count: u32,
    /// Number of SSL errors received
    pub ssl_error_count: u32,
    /// Whether this connection has been successfully established
    pub success: bool,
}

impl AutoConnectionState {
    /// Create new auto-logic state for a connection
    pub fn new() -> Self {
        let auto_state = AutoLogicState::new();
        let strategy = Strategy::from(&auto_state);

        Self {
            auto_state,
            strategy,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            rst_count: 0,
            redirect_count: 0,
            ssl_error_count: 0,
            success: false,
        }
    }

    /// Update strategy from current auto_state
    fn update_strategy(&mut self) {
        self.strategy = Strategy::from(&self.auto_state);
    }

    /// Handle RST event - move to next strategy
    pub fn handle_rst(&mut self) -> &Strategy {
        self.rst_count += 1;
        self.last_activity = Instant::now();

        let old_strategy = self.strategy.description();
        self.auto_state.next_strategy_on_rst();
        self.update_strategy();

        info!(
            "[AUTO] RST #{}: switching strategy '{}' -> '{}'",
            self.rst_count,
            old_strategy,
            self.strategy.description()
        );

        &self.strategy
    }

    /// Handle Redirect event - strengthen bypass
    pub fn handle_redirect(&mut self) -> &Strategy {
        self.redirect_count += 1;
        self.last_activity = Instant::now();

        let old_strategy = self.strategy.description();
        self.auto_state.strengthen_on_redirect();
        self.update_strategy();

        info!(
            "[AUTO] Redirect #{}: strengthening '{}' -> '{}'",
            self.redirect_count,
            old_strategy,
            self.strategy.description()
        );

        &self.strategy
    }

    /// Handle SSL error event - prefer TLS strategies
    pub fn handle_ssl_error(&mut self) -> &Strategy {
        self.ssl_error_count += 1;
        self.last_activity = Instant::now();

        // For SSL errors, prefer TLS record split
        if !matches!(self.strategy, Strategy::TlsRecordSplit) {
            let old_strategy = self.strategy.description();
            self.auto_state.strategy = strategy_types::TLS_RECORD_SPLIT;
            self.auto_state.attempts = 0;
            self.update_strategy();

            info!(
                "[AUTO] SSL error #{}: switching to TLS strategy '{}' -> '{}'",
                self.ssl_error_count,
                old_strategy,
                self.strategy.description()
            );
        }

        &self.strategy
    }

    /// Mark connection as successful
    #[allow(dead_code)]
    pub fn mark_success(&mut self) {
        self.success = true;
        self.last_activity = Instant::now();
    }

    /// Check if state is expired
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.last_activity.elapsed() > ttl
    }

    /// Get configuration recommendations based on current strategy
    #[allow(dead_code)]
    pub fn get_config_recommendations(&self) -> ConfigRecommendations {
        ConfigRecommendations::from(&self.strategy)
    }
}

impl Default for AutoConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration recommendations for the current strategy
#[derive(Debug, Clone)]
pub struct ConfigRecommendations {
    /// Recommended split position
    pub split_pos: Option<usize>,
    /// Whether to enable fake packets
    pub use_fake: bool,
    /// Fake offset if enabled
    pub fake_offset: Option<isize>,
    /// Whether to use TLS record split
    pub use_tlsrec: bool,
    /// Whether to use disorder
    pub use_disorder: bool,
}

impl From<&Strategy> for ConfigRecommendations {
    fn from(strategy: &Strategy) -> Self {
        match strategy {
            Strategy::TcpSplit(pos) => Self {
                split_pos: Some(*pos),
                use_fake: false,
                fake_offset: None,
                use_tlsrec: false,
                use_disorder: false,
            },
            Strategy::TlsRecordSplit => Self {
                split_pos: None,
                use_fake: false,
                fake_offset: None,
                use_tlsrec: true,
                use_disorder: false,
            },
            Strategy::Disorder => Self {
                split_pos: Some(1),
                use_fake: false,
                fake_offset: None,
                use_tlsrec: false,
                use_disorder: true,
            },
            Strategy::FakeWithSplit {
                split_pos,
                fake_offset,
            } => Self {
                split_pos: Some(*split_pos),
                use_fake: true,
                fake_offset: Some(*fake_offset),
                use_tlsrec: false,
                use_disorder: false,
            },
        }
    }
}

/// Auto-logic state machine manager
pub struct AutoLogic {
    /// Per-connection states
    states: Arc<DashMap<ConnKey, AutoConnectionState>>,
    /// Time-to-live for connection states
    ttl: Duration,
    /// Whether auto-logic is enabled for RST
    enabled_rst: bool,
    /// Whether auto-logic is enabled for Redirect
    enabled_redirect: bool,
    /// Whether auto-logic is enabled for SSL errors
    enabled_ssl: bool,
}

impl AutoLogic {
    /// Create new auto-logic manager
    pub fn new(enabled_rst: bool, enabled_redirect: bool, enabled_ssl: bool) -> Self {
        Self {
            states: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(60),
            enabled_rst,
            enabled_redirect,
            enabled_ssl,
        }
    }

    /// Get or create connection state
    #[allow(dead_code)]
    pub async fn get_or_create(&self, key: &ConnKey) -> AutoConnectionState {
        self.states.entry(*key).or_default().clone()
    }

    /// Get connection state if exists
    #[allow(dead_code)]
    pub async fn get(&self, key: &ConnKey) -> Option<AutoConnectionState> {
        self.states.get(key).map(|state| state.clone())
    }

    /// Handle RST event for a connection
    pub async fn handle_rst(
        &self,
        key: &ConnKey,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) -> Option<Strategy> {
        if !self.enabled_rst {
            return None;
        }

        let entry = self.states.entry(*key);
        let mut state = entry.or_default();

        debug!(
            "[AUTO-RST] {}:{} -> {}:{}",
            src_ip, src_port, dst_ip, dst_port
        );

        let strategy = state.handle_rst().clone();
        Some(strategy)
    }

    /// Handle Redirect event for a connection
    pub async fn handle_redirect(
        &self,
        key: &ConnKey,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) -> Option<Strategy> {
        if !self.enabled_redirect {
            return None;
        }

        let entry = self.states.entry(*key);
        let mut state = entry.or_default();

        debug!(
            "[AUTO-REDIRECT] {}:{} -> {}:{}",
            src_ip, src_port, dst_ip, dst_port
        );

        let strategy = state.handle_redirect().clone();
        Some(strategy)
    }

    /// Handle SSL error event for a connection
    pub async fn handle_ssl_error(
        &self,
        key: &ConnKey,
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
    ) -> Option<Strategy> {
        if !self.enabled_ssl {
            return None;
        }

        let entry = self.states.entry(*key);
        let mut state = entry.or_default();

        debug!(
            "[AUTO-SSL] {}:{} -> {}:{}",
            src_ip, src_port, dst_ip, dst_port
        );

        let strategy = state.handle_ssl_error().clone();
        Some(strategy)
    }

    /// Mark connection as successful
    #[allow(dead_code)]
    pub async fn mark_success(&self, key: &ConnKey) {
        if let Some(mut state) = self.states.get_mut(key) {
            state.mark_success();
            debug!("[AUTO] Connection {:?} marked as successful", key);
        }
    }

    /// Remove connection state
    #[allow(dead_code)]
    pub async fn remove(&self, key: &ConnKey) {
        self.states.remove(key);
    }

    /// Cleanup expired connections
    pub async fn cleanup(&self) -> usize {
        let before = self.states.len();
        self.states.retain(|_, state| !state.is_expired(self.ttl));
        let removed = before - self.states.len();

        if removed > 0 {
            debug!("[AUTO] Cleaned up {} expired connection states", removed);
        }

        removed
    }

    /// Get statistics
    pub async fn get_stats(&self) -> AutoLogicStats {
        let total = self.states.len() as u32;

        let (rst_total, redirect_total, ssl_total, success_total) = self.states.iter().fold(
            (0u32, 0u32, 0u32, 0u32),
            |(rst, redirect, ssl, success), entry| {
                let state = entry.value();
                (
                    rst + state.rst_count,
                    redirect + state.redirect_count,
                    ssl + state.ssl_error_count,
                    success + if state.success { 1 } else { 0 },
                )
            },
        );

        AutoLogicStats {
            total_connections: total,
            total_rst_events: rst_total,
            total_redirect_events: redirect_total,
            total_ssl_errors: ssl_total,
            successful_connections: success_total,
        }
    }

    /// Check if auto-logic is enabled for RST
    #[allow(dead_code)]
    pub fn is_rst_enabled(&self) -> bool {
        self.enabled_rst
    }

    /// Check if auto-logic is enabled for Redirect
    #[allow(dead_code)]
    pub fn is_redirect_enabled(&self) -> bool {
        self.enabled_redirect
    }

    /// Check if auto-logic is enabled for SSL
    #[allow(dead_code)]
    pub fn is_ssl_enabled(&self) -> bool {
        self.enabled_ssl
    }
}

/// Statistics for auto-logic
#[derive(Debug, Clone)]
pub struct AutoLogicStats {
    pub total_connections: u32,
    pub total_rst_events: u32,
    pub total_redirect_events: u32,
    pub total_ssl_errors: u32,
    pub successful_connections: u32,
}

impl std::fmt::Display for AutoLogicStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "AutoLogicStats {{ connections: {}, RST: {}, Redirect: {}, SSL: {}, Success: {} }}",
            self.total_connections,
            self.total_rst_events,
            self.total_redirect_events,
            self.total_ssl_errors,
            self.successful_connections
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_state_machine_rst() {
        let mut state = AutoConnectionState::new();

        // Initial state should be TCP split
        assert!(matches!(state.strategy, Strategy::TcpSplit(_)));

        // After 3 RSTs, should move to TLS
        state.handle_rst();
        state.handle_rst();
        state.handle_rst();

        assert!(matches!(state.strategy, Strategy::TlsRecordSplit));

        // After 1 more RST, should move to Disorder
        state.handle_rst();
        assert!(matches!(state.strategy, Strategy::Disorder));

        // After 1 more RST, should cycle back to TCP split with new param
        state.handle_rst();
        assert!(matches!(state.strategy, Strategy::TcpSplit(_)));
    }

    #[test]
    fn test_strategy_strengthen_on_redirect() {
        let mut state = AutoConnectionState::new();

        // Initial state
        assert!(!state.strategy.uses_fake());

        // After redirect, should enable fake
        state.handle_redirect();
        assert!(state.strategy.uses_fake());
        assert!(matches!(state.strategy, Strategy::FakeWithSplit { .. }));
    }

    #[test]
    fn test_ssl_error_switch_to_tls() {
        let mut state = AutoConnectionState::new();

        // Start with TCP split
        state.auto_state.strategy = strategy_types::TCP_SPLIT;
        state.update_strategy();

        // After SSL error, should switch to TLS
        state.handle_ssl_error();
        assert!(matches!(state.strategy, Strategy::TlsRecordSplit));
    }

    #[test]
    fn test_config_recommendations() {
        let strategy = Strategy::TcpSplit(5);
        let recs = ConfigRecommendations::from(&strategy);

        assert_eq!(recs.split_pos, Some(5));
        assert!(!recs.use_fake);

        let strategy = Strategy::FakeWithSplit {
            split_pos: 2,
            fake_offset: -1,
        };
        let recs = ConfigRecommendations::from(&strategy);

        assert_eq!(recs.split_pos, Some(2));
        assert!(recs.use_fake);
        assert_eq!(recs.fake_offset, Some(-1));
    }

    #[tokio::test]
    async fn test_auto_logic_manager() {
        let auto = AutoLogic::new(true, true, true);

        let key = ConnKey {
            src_ip: [192, 168, 1, 1].map(u32::from_be),
            dst_ip: [10, 0, 0, 1].map(u32::from_be),
            src_port: 12345,
            dst_port: 443,
            is_ipv6: 0,
            proto: 6,
            _pad: [0; 2],
        };

        // Test RST handling
        let strategy = auto
            .handle_rst(&key, "192.168.1.1", "10.0.0.1", 12345, 443)
            .await;

        assert!(strategy.is_some());

        // Test stats
        let stats = auto.get_stats().await;
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.total_rst_events, 1);
    }

    #[tokio::test]
    async fn test_mark_success_updates_stats() {
        let auto = AutoLogic::new(true, true, true);
        let key = ConnKey {
            src_ip: [0xC0A80101, 0, 0, 0],
            dst_ip: [0x0A000001, 0, 0, 0],
            src_port: 12345,
            dst_port: 443,
            is_ipv6: 0,
            proto: 6,
            _pad: [0; 2],
        };

        auto.handle_rst(&key, "192.168.1.1", "10.0.0.1", 12345, 443)
            .await;
        auto.mark_success(&key).await;

        let stats = auto.get_stats().await;
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.successful_connections, 1);
    }

    #[tokio::test]
    async fn test_ipv6_flow_uses_same_auto_logic() {
        let auto = AutoLogic::new(true, true, true);
        let key = ConnKey {
            src_ip: [
                u32::from_ne_bytes([0xfd, 0x00, 0, 1]),
                0,
                0,
                u32::from_ne_bytes([0, 0, 0, 1]),
            ],
            dst_ip: [
                u32::from_ne_bytes([0xfd, 0x00, 0, 1]),
                0,
                0,
                u32::from_ne_bytes([0, 0, 0, 2]),
            ],
            src_port: 12345,
            dst_port: 443,
            is_ipv6: 1,
            proto: 6,
            _pad: [0; 2],
        };

        let strategy = auto
            .handle_rst(&key, "[fd00:1::1]", "[fd00:1::2]", 12345, 443)
            .await;

        assert!(strategy.is_some());
        let stats = auto.get_stats().await;
        assert_eq!(stats.total_connections, 1);
        assert_eq!(stats.total_rst_events, 1);
    }
}
