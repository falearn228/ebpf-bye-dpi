use goodbyedpi_proto::{ConnKey, ConnState};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::auto_logic::AutoLogic;

/// Connection state manager with optional auto-logic
pub struct ConnectionState {
    states: Arc<RwLock<HashMap<ConnKey, (ConnState, Instant)>>>,
    ttl: Duration,
    /// Auto-logic state machine (optional)
    auto_logic: Option<AutoLogic>,
}

impl ConnectionState {
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(60),
            auto_logic: None,
        }
    }

    /// Create with auto-logic enabled
    pub fn with_auto_logic(auto_logic: AutoLogic) -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(60),
            auto_logic: Some(auto_logic),
        }
    }

    /// Get auto-logic reference
    pub fn auto_logic(&self) -> Option<&AutoLogic> {
        self.auto_logic.as_ref()
    }

    #[allow(dead_code)]
    pub async fn get(&self, key: &ConnKey) -> Option<ConnState> {
        let states = self.states.read().await;
        states.get(key).map(|(s, _)| *s)
    }

    #[allow(dead_code)]
    pub async fn insert(&self, key: ConnKey, state: ConnState) {
        let mut states = self.states.write().await;
        states.insert(key, (state, Instant::now()));
    }

    #[allow(dead_code)]
    pub async fn update(&self, key: &ConnKey, f: impl FnOnce(&mut ConnState)) -> bool {
        let mut states = self.states.write().await;
        if let Some((state, ts)) = states.get_mut(key) {
            f(state);
            *ts = Instant::now();
            true
        } else {
            false
        }
    }

    /// Cleanup expired connections and auto-logic states
    pub async fn cleanup(&self) -> usize {
        // Cleanup basic states
        let mut states = self.states.write().await;
        let now = Instant::now();
        let before = states.len();
        states.retain(|_, (_, ts)| now.duration_since(*ts) < self.ttl);
        let removed = before - states.len();
        drop(states);

        // Cleanup auto-logic states if enabled
        if let Some(ref auto_logic) = self.auto_logic {
            let auto_removed = auto_logic.cleanup().await;
            return removed + auto_removed as usize;
        }

        removed
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

// Re-export auto_logic types for convenience
pub use crate::auto_logic::{Strategy, ConfigRecommendations, AutoLogicStats};
