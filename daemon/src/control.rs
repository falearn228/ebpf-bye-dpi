//! Runtime-файлы демона в run-директории (по умолчанию `/run/goodbyedpi`).
//!
//! - `daemon.pid` — PID процесса, защищает от второго экземпляра;
//! - `state.json` — снимок состояния для `goodbyedpi status`/`tui`/`reload`.
//!
//! Запись атомарная (tmp + rename), чтобы CLI никогда не читал половину файла.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_RUN_DIR: &str = "/run/goodbyedpi";
pub const PID_FILE: &str = "daemon.pid";
pub const STATE_FILE: &str = "state.json";

/// Итог последнего hot reload (SIGHUP).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadStatus {
    /// Номер попытки; 0 = reload ещё не выполнялся
    pub generation: u64,
    pub ok: bool,
    pub message: String,
    /// Unix-время попытки
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonState {
    pub pid: u32,
    pub version: String,
    pub started_at: u64,
    pub interfaces: Vec<String>,
    /// Inline-конфиг из `-c`
    pub config: String,
    pub config_file: Option<String>,
    pub metrics_bind: Option<String>,
    pub reload: ReloadStatus,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Жив ли процесс демона с данным PID (а не случайный процесс с переиспользованным PID).
pub fn daemon_alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        // "goodbyedpi" без суффикса — это CLI, не демон
        .map(|comm| {
            let comm = comm.trim();
            comm.starts_with("goodbyedpi") && comm != "goodbyedpi"
        })
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct RunDir {
    path: PathBuf,
}

impl RunDir {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn pid_path(&self) -> PathBuf {
        self.path.join(PID_FILE)
    }

    pub fn state_path(&self) -> PathBuf {
        self.path.join(STATE_FILE)
    }

    pub fn read_pid(&self) -> Option<u32> {
        std::fs::read_to_string(self.pid_path())
            .ok()
            .and_then(|s| s.trim().parse().ok())
    }

    /// PID работающего демона, если pid-файл не устарел.
    pub fn running_pid(&self) -> Option<u32> {
        self.read_pid().filter(|pid| daemon_alive(*pid))
    }

    pub fn read_state(&self) -> Result<Option<DaemonState>> {
        let path = self.state_path();
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("Failed to read {}", path.display())),
        };
        let state = serde_json::from_str(&raw)
            .with_context(|| format!("Failed to parse {}", path.display()))?;
        Ok(Some(state))
    }

    pub fn write_state(&self, state: &DaemonState) -> Result<()> {
        let json = serde_json::to_string_pretty(state).context("Failed to serialize state")?;
        write_atomic(&self.state_path(), json.as_bytes())
    }

    /// Занимает run-директорию: падает, если демон уже работает.
    /// Возвращённый guard удаляет pid/state файлы при drop.
    pub fn acquire(&self) -> Result<RunDirGuard> {
        std::fs::create_dir_all(&self.path)
            .with_context(|| format!("Failed to create run dir {}", self.path.display()))?;

        if let Some(pid) = self.running_pid() {
            if pid != std::process::id() {
                return Err(anyhow!(
                    "Another goodbyedpi-daemon is already running (pid {}, run dir {}). \
                     Stop it first: `goodbyedpi stop`",
                    pid,
                    self.path.display()
                ));
            }
        }

        write_atomic(&self.pid_path(), std::process::id().to_string().as_bytes())?;
        Ok(RunDirGuard { dir: self.clone() })
    }
}

pub struct RunDirGuard {
    dir: RunDir,
}

impl Drop for RunDirGuard {
    fn drop(&mut self) {
        // Чужой pid-файл не трогаем
        if self.dir.read_pid() == Some(std::process::id()) {
            let _ = std::fs::remove_file(self.dir.pid_path());
            let _ = std::fs::remove_file(self.dir.state_path());
        }
    }
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("Failed to rename {} -> {}", tmp.display(), path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_run_dir(tag: &str) -> RunDir {
        let dir = std::env::temp_dir().join(format!(
            "goodbyedpi-control-test-{}-{}",
            tag,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        RunDir::new(dir)
    }

    fn sample_state() -> DaemonState {
        DaemonState {
            pid: std::process::id(),
            version: "0.1.0".into(),
            started_at: 1,
            interfaces: vec!["eth0".into(), "wlan0".into()],
            config: "s1 -o1".into(),
            config_file: None,
            metrics_bind: Some("127.0.0.1:9877".into()),
            reload: ReloadStatus::default(),
        }
    }

    #[test]
    fn state_roundtrip_and_cleanup() {
        let dir = temp_run_dir("roundtrip");
        {
            let _guard = dir.acquire().unwrap();
            assert_eq!(dir.read_pid(), Some(std::process::id()));
            dir.write_state(&sample_state()).unwrap();
            assert_eq!(dir.read_state().unwrap(), Some(sample_state()));
        }
        assert!(dir.read_pid().is_none());
        assert!(dir.read_state().unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir.path());
    }

    #[test]
    fn stale_pid_does_not_block_acquire() {
        let dir = temp_run_dir("stale");
        std::fs::create_dir_all(dir.path()).unwrap();
        // PID ядра (2 = kthreadd) никогда не является демоном
        std::fs::write(dir.pid_path(), "2").unwrap();
        assert!(dir.running_pid().is_none());
        let guard = dir.acquire().unwrap();
        drop(guard);
        let _ = std::fs::remove_dir_all(dir.path());
    }
}
