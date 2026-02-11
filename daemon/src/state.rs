use goodbyedpi_proto::{ConnKey, ConnState};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct ConnectionState {
    states: Arc<RwLock<HashMap<ConnKey, (ConnState, Instant)>>>,
    ttl: Duration,
}

impl ConnectionState {
    pub fn new() -> Self {
        Self {
            states: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(60),
        }
    }

    //TODO: methods `get`, `insert`, and `update` are never used
    pub async fn get(&self, key: &ConnKey) -> Option<ConnState> {
        let states = self.states.read().await;
        states.get(key).map(|(s, _)| *s)
    }

    pub async fn insert(&self, key: ConnKey, state: ConnState) {
        let mut states = self.states.write().await;
        states.insert(key, (state, Instant::now()));
    }

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

    pub async fn cleanup(&self) -> usize {
        let mut states = self.states.write().await;
        let now = Instant::now();
        let before = states.len();
        states.retain(|_, (_, ts)| now.duration_since(*ts) < self.ttl);
        before - states.len()
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}
