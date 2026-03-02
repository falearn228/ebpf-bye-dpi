use goodbyedpi_proto::{ConnKey, ConnState};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::auto_logic::AutoLogic;

/// Connection state manager with optional auto-logic
pub struct ConnectionState {
    states: Arc<DashMap<ConnKey, (ConnState, Instant)>>,
    ttl: Duration,
    /// Auto-logic state machine (optional)
    auto_logic: Option<AutoLogic>,
}

impl ConnectionState {
    pub fn new() -> Self {
        Self {
            states: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(60),
            auto_logic: None,
        }
    }

    /// Create with auto-logic enabled
    pub fn with_auto_logic(auto_logic: AutoLogic) -> Self {
        Self {
            states: Arc::new(DashMap::new()),
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
        self.states.get(key).map(|entry| entry.value().0)
    }

    #[allow(dead_code)]
    pub async fn insert(&self, key: ConnKey, state: ConnState) {
        self.states.insert(key, (state, Instant::now()));
    }

    #[allow(dead_code)]
    pub async fn update(&self, key: &ConnKey, f: impl FnOnce(&mut ConnState)) -> bool {
        if let Some(mut entry) = self.states.get_mut(key) {
            let (state, ts) = entry.value_mut();
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
        let before = self.states.len();
        self.states.retain(|_, (_, ts)| ts.elapsed() < self.ttl);
        let removed = before - self.states.len();

        // Cleanup auto-logic states if enabled
        if let Some(ref auto_logic) = self.auto_logic {
            let auto_removed = auto_logic.cleanup().await;
            return removed + auto_removed;
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
