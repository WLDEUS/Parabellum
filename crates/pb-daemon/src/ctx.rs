//! Shared daemon state, passed around as `Arc<Ctx>`.

use crate::backends::{Backends, NullEngine, ScanEngine};
use crate::bus::EventBus;
use crate::jobs::JobManager;
use crate::store::{StatField, Store};
use crate::system::BatteryState;
use pb_core::config::Config;
use pb_core::model::{RealtimeStatus, StatusInfo};
use pb_core::paths::Paths;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Instant;
use tokio::sync::{watch, Notify, Semaphore};

/// Concurrent real-time scans (exec + file activity).
pub const REALTIME_SLOTS: usize = 2;

/// Mutable runtime state (small, guarded by a std mutex, never held across `.await`).
#[derive(Debug, Default)]
pub struct RuntimeState {
    /// Protection paused until this Unix time.
    pub paused_until: Option<i64>,
    /// Watcher health as reported by `MonitorHealth` events (`full_disk_access` filled by the status task).
    pub health: RealtimeStatus,
    pub battery: BatteryState,
    /// `config.toml` was invalid and a fallback is in use.
    pub config_error: Option<String>,
    /// The engine could not be loaded.
    pub engine_error: Option<String>,
    /// Cached Full Disk Access check.
    pub fda: Option<(bool, Instant)>,
    /// First-run baseline windows: until when persistence / device events are recorded silently.
    pub persistence_baseline_until: Option<Instant>,
    pub devices_baseline_until: Option<Instant>,
    /// Last status pushed to subscribers.
    pub last_status: Option<StatusInfo>,
    /// Last DB update error message (for the 3-day alert).
    pub last_update_error: Option<String>,
}

/// Everything the daemon tasks share.
pub struct Ctx {
    pub paths: Paths,
    /// `PARABELLUM_ROOT` set: unprivileged development instance (relaxed peer checks, no chown).
    pub dev_mode: bool,
    /// Who may run protection-weakening commands.
    pub access: crate::ipc::AccessPolicy,
    pub store: Store,
    pub bus: EventBus,
    pub backends: Backends,
    pub jobs: JobManager,
    pub started: Instant,
    config_tx: watch::Sender<Arc<Config>>,
    engine: RwLock<Arc<dyn ScanEngine>>,
    engine_generation: AtomicU64,
    state: Mutex<RuntimeState>,
    pub shutdown: watch::Sender<bool>,
    /// Wakes the status task (recompute + push if changed).
    pub status_dirty: Notify,
    /// A DB/components/app update is running.
    pub update_running: AtomicBool,
    /// Files restored by the user without allowing them: `path -> (sha256, ts)`; real-time skips them.
    pub restored: Mutex<HashMap<String, (String, i64)>>,
    /// Hashes restored by the user in the last minute (the destination may differ from the original path).
    pub restored_hashes: Mutex<HashMap<String, std::time::Instant>>,
    pub realtime_slots: Arc<Semaphore>,
}

impl Ctx {
    /// Build the context (engine starts as [`NullEngine`] until loaded).
    pub fn new(
        paths: Paths,
        dev_mode: bool,
        store: Store,
        backends: Backends,
        config: Config,
    ) -> Self {
        let (config_tx, _) = watch::channel(Arc::new(config));
        let (shutdown, _) = watch::channel(false);
        Self {
            paths,
            dev_mode,
            access: crate::ipc::AccessPolicy::for_mode(dev_mode),
            store,
            bus: EventBus::new(),
            backends,
            jobs: JobManager::new(),
            started: Instant::now(),
            config_tx,
            engine: RwLock::new(Arc::new(NullEngine)),
            engine_generation: AtomicU64::new(0),
            state: Mutex::new(RuntimeState::default()),
            shutdown,
            status_dirty: Notify::new(),
            update_running: AtomicBool::new(false),
            restored: Mutex::new(HashMap::new()),
            restored_hashes: Mutex::new(HashMap::new()),
            realtime_slots: Arc::new(Semaphore::new(REALTIME_SLOTS)),
        }
    }

    /// Current configuration snapshot.
    pub fn config(&self) -> Arc<Config> {
        self.config_tx.borrow().clone()
    }

    /// Receiver notified on every configuration change (monitors, DNS supervisor).
    pub fn config_rx(&self) -> watch::Receiver<Arc<Config>> {
        self.config_tx.subscribe()
    }

    /// Publish a new configuration (already validated and saved).
    pub fn publish_config(&self, cfg: Config) {
        self.config_tx.send_replace(Arc::new(cfg));
        self.status_dirty.notify_one();
    }

    /// Current engine.
    pub fn engine(&self) -> Arc<dyn ScanEngine> {
        self.engine
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Atomically replace the engine (after a DB update); in-flight scans keep the old one.
    pub fn swap_engine(&self, engine: Arc<dyn ScanEngine>) {
        *self.engine.write().unwrap_or_else(|e| e.into_inner()) = engine;
        self.engine_generation.fetch_add(1, Ordering::SeqCst);
        self.status_dirty.notify_one();
    }

    /// Incremented on each engine swap (caches keyed on verdicts must be invalidated).
    pub fn engine_generation(&self) -> u64 {
        self.engine_generation.load(Ordering::SeqCst)
    }

    /// Lock the runtime state (never hold across an await).
    pub fn state(&self) -> MutexGuard<'_, RuntimeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn shutdown_rx(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }

    /// Real-time protection paused by the user at `now`.
    pub fn is_paused(&self, now: i64) -> bool {
        matches!(self.state().paused_until, Some(t) if t > now)
    }

    /// On battery below `energy.pause_on_battery_below`: defer deferrable heavy work.
    pub fn should_defer_heavy_work(&self) -> bool {
        let threshold = self.config().energy.pause_on_battery_below;
        let b = self.state().battery;
        threshold > 0 && b.on_battery && b.percent.map(|p| p < threshold).unwrap_or(false)
    }

    /// Home of the console user (for `~` expansion).
    pub fn console_home(&self) -> Option<PathBuf> {
        crate::system::console_user().map(|u| u.home)
    }

    /// Paths the real-time pipeline never scans: our own tree, our logs, configured excludes.
    pub fn is_excluded(&self, path: &Path, cfg: &Config) -> bool {
        if path.starts_with(&self.paths.root) || path.starts_with(&self.paths.log_dir) {
            return true;
        }
        if cfg.scan.exclude_paths.is_empty() {
            return false;
        }
        let home = self
            .console_home()
            .unwrap_or_else(|| PathBuf::from("/var/empty"));
        cfg.scan
            .exclude_paths
            .iter()
            .filter(|e| !e.trim().is_empty())
            .any(|e| path.starts_with(pb_core::expand_user_path(e.trim(), &home)))
    }

    /// Add to a daily counter (today, local time). Errors are logged.
    pub async fn bump_stat(&self, field: StatField, n: u64) {
        if n == 0 {
            return;
        }
        let date = crate::system::local_date(pb_core::now_ts());
        if let Err(e) = self.store.run(move |s| s.bump_daily(&date, field, n)).await {
            tracing::warn!(error = %e, "daily stats update failed");
        }
    }

    /// Remember a user restore so real-time does not re-quarantine the file (24 h).
    pub fn remember_restored(&self, path: &str, sha256: &str) {
        let now = pb_core::now_ts();
        let mut g = self.restored.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, (_, ts)| now - *ts < 86_400);
        if g.len() < 10_000 {
            g.insert(path.to_string(), (sha256.to_ascii_lowercase(), now));
        }
    }

    /// Remember a hash being restored (valid 60 s, any path).
    pub fn remember_restored_hash(&self, sha256: &str) {
        let mut g = self
            .restored_hashes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        g.retain(|_, at| at.elapsed() < std::time::Duration::from_secs(60));
        g.insert(sha256.to_ascii_lowercase(), std::time::Instant::now());
    }

    /// Was this file restored by the user: same path + hash in the last 24 h, or same hash in the last minute?
    pub fn was_restored(&self, path: &str, sha256: &str) -> bool {
        let recent = self
            .restored_hashes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&sha256.to_ascii_lowercase())
            .is_some_and(|at| at.elapsed() < std::time::Duration::from_secs(60));
        if recent {
            return true;
        }
        let now = pb_core::now_ts();
        let g = self.restored.lock().unwrap_or_else(|e| e.into_inner());
        matches!(g.get(path), Some((s, ts)) if s.eq_ignore_ascii_case(sha256) && now - *ts < 86_400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Ctx {
        Ctx::new(
            Paths::with_root("/tmp/pbx"),
            true,
            Store::open_in_memory().unwrap(),
            Backends::unavailable(),
            Config::default(),
        )
    }

    #[test]
    fn exclusions() {
        let c = ctx();
        let mut cfg = Config::default();
        assert!(c.is_excluded(Path::new("/tmp/pbx/quarantine/x"), &cfg));
        assert!(!c.is_excluded(Path::new("/tmp/other"), &cfg));
        cfg.scan.exclude_paths = vec!["/tmp/other".into(), "".into()];
        assert!(c.is_excluded(Path::new("/tmp/other/f"), &cfg));
        assert!(!c.is_excluded(Path::new("/tmp/otherx"), &cfg));
    }

    #[test]
    fn pause_and_battery() {
        let c = ctx();
        assert!(!c.is_paused(100));
        c.state().paused_until = Some(200);
        assert!(c.is_paused(100));
        assert!(!c.is_paused(200));
        assert!(!c.should_defer_heavy_work());
        c.state().battery = BatteryState {
            on_battery: true,
            percent: Some(10),
        };
        assert!(c.should_defer_heavy_work());
        c.state().battery = BatteryState {
            on_battery: true,
            percent: Some(50),
        };
        assert!(!c.should_defer_heavy_work());
    }

    #[test]
    fn restored_files() {
        let c = ctx();
        c.remember_restored("/a", "ABC");
        assert!(c.was_restored("/a", "abc"));
        assert!(!c.was_restored("/a", "def"));
        assert!(!c.was_restored("/b", "abc"));
        c.remember_restored_hash("FFF");
        assert!(c.was_restored("/anywhere.restored-1", "fff"));
    }

    #[test]
    fn config_and_engine_swap() {
        let c = ctx();
        let rx = c.config_rx();
        let mut cfg = Config::default();
        cfg.dns.enabled = true;
        c.publish_config(cfg);
        assert!(rx.has_changed().unwrap());
        assert!(c.config().dns.enabled);
        let g = c.engine_generation();
        c.swap_engine(Arc::new(NullEngine));
        assert_eq!(c.engine_generation(), g + 1);
    }
}
