//! Parabellum monitors: everything that *observes* the Mac and turns it into
//! [`pb_core::events::MonitorEvent`]s for the daemon.
//!
//! The crate is deliberately **pure**: no SQLite, no scanning, no alert policy. Each watcher is a
//! small struct with an `async fn run(self, ctx: MonitorContext)` that:
//! - sends events on `ctx.tx` (bounded tokio channel owned by the daemon),
//! - reports its own state with [`MonitorEvent::MonitorHealth`] (`monitor` is one of the
//!   `MONITOR_*` constants below),
//! - restarts its internal work with exponential backoff on failure (never panics, never exits the
//!   process),
//! - returns once `ctx.shutdown` flips to `true` (or its sender is dropped).
//!
//! Watchers:
//! - [`FileWatcher`]: FSEvents (inotify on Linux) on `scan.watch_paths`,
//! - [`EsLoggerWatcher`]: Apple's `/usr/bin/eslogger` (Endpoint Security, observe-only),
//! - [`PersistenceWatcher`]: launchd plists, BTM, cron, periodic, shell profiles, configuration
//!   profiles, system/kernel extensions, authorization plugins, browser extensions,
//! - [`DeviceWatcher`]: volumes, USB/HID/Thunderbolt (IOKit), Bluetooth, network interfaces, Wi-Fi.
//!
//! Cross-watcher signals: [`persistence_trigger`] (eslogger `btm_launch_item_add` -> persistence
//! rescan) and [`volume_trigger`] (eslogger `mount`/`unmount` -> volume refresh).
//!
//! Typical daemon wiring:
//! ```no_run
//! # async fn demo(paths: pb_core::paths::Paths, config: pb_core::config::Config,
//! #               known: Vec<pb_core::model::PersistenceItem>) {
//! use pb_monitor::*;
//! let (tx, mut rx) = tokio::sync::mpsc::channel(4096);
//! let (_cfg_tx, cfg_rx) = tokio::sync::watch::channel(config);
//! let (_stop_tx, stop_rx) = tokio::sync::watch::channel(false);
//! let ctx = MonitorContext { paths, config: cfg_rx, user: console_user(), tx, shutdown: stop_rx };
//! tokio::spawn(FileWatcher.run(ctx.clone()));
//! tokio::spawn(EsLoggerWatcher.run(ctx.clone()));
//! tokio::spawn(PersistenceWatcher { known }.run(ctx.clone()));
//! tokio::spawn(DeviceWatcher.run(ctx));
//! while let Some(_event) = rx.recv().await { /* daemon logic */ }
//! # }
//! ```

#![deny(unsafe_op_in_unsafe_fn)]

pub mod devices;
pub mod eslogger;
pub mod fs_watcher;
pub mod osquery;
pub mod persistence;
pub mod sensitive;
mod user;
mod util;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use pb_core::config::Config;
use pb_core::events::MonitorEvent;
use pb_core::paths::Paths;
use tokio::sync::{mpsc, watch, Notify};

pub use devices::{diff_devices, DeviceWatcher, HidBlocker};
pub use eslogger::{EsLoggerOptions, EsLoggerWatcher};
pub use fs_watcher::FileWatcher;
pub use persistence::PersistenceWatcher;
pub use user::{console_user, has_full_disk_access, ConsoleUser};

/// `MonitorHealth.monitor` value of [`FileWatcher`] (maps to `RealtimeStatus::fsevents`).
pub const MONITOR_FSEVENTS: &str = "fsevents";
/// `MonitorHealth.monitor` value of [`EsLoggerWatcher`] (maps to `RealtimeStatus::eslogger`).
pub const MONITOR_ESLOGGER: &str = "eslogger";
/// `MonitorHealth.monitor` value of [`PersistenceWatcher`] (maps to `RealtimeStatus::persistence_monitor`).
pub const MONITOR_PERSISTENCE: &str = "persistence";
/// `MonitorHealth.monitor` value of [`DeviceWatcher`] (maps to `RealtimeStatus::device_monitor`).
pub const MONITOR_DEVICES: &str = "devices";

/// Everything a watcher needs. Cheap to clone (one clone per watcher).
#[derive(Debug, Clone)]
pub struct MonitorContext {
    /// Filesystem layout; anything under `paths.root` is never reported (our own files).
    pub paths: Paths,
    /// Live configuration; watchers re-read it when it changes.
    pub config: watch::Receiver<Config>,
    /// Console user at start. Watchers also refresh it periodically (login / fast user switching).
    pub user: Option<ConsoleUser>,
    /// Event sink (bounded). High-volume events (file activity, exec) are dropped and counted when
    /// the channel is full; rare events (persistence, devices, health) wait for capacity.
    pub tx: mpsc::Sender<MonitorEvent>,
    /// Flips to `true` when the daemon shuts down.
    pub shutdown: watch::Receiver<bool>,
}

/// Errors of this crate (most are logged and turned into `MonitorHealth` events).
#[derive(Debug, thiserror::Error)]
pub enum MonitorError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("command `{0}` timed out")]
    Timeout(String),
    #[error("command `{program}` failed: {message}")]
    Command { program: String, message: String },
    #[error("parse error: {0}")]
    Parse(String),
    #[error("file watcher error: {0}")]
    Notify(String),
    #[error("IOKit error: {0}")]
    IoKit(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("unsupported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("refused: {0}")]
    Refused(String),
}

impl From<notify::Error> for MonitorError {
    fn from(e: notify::Error) -> Self {
        MonitorError::Notify(e.to_string())
    }
}

/// Shared signal: "persistence may have changed, rescan soon" (eslogger `btm_launch_item_add`).
/// The [`PersistenceWatcher`] waits on it; a notification sent while nobody waits is kept (one
/// permit), so it is never lost.
pub fn persistence_trigger() -> Arc<Notify> {
    static T: OnceLock<Arc<Notify>> = OnceLock::new();
    T.get_or_init(|| Arc::new(Notify::new())).clone()
}

/// Shared signal: "a filesystem was mounted / unmounted" (eslogger `mount` / `unmount`).
/// The [`DeviceWatcher`] waits on it to refresh volumes immediately.
pub fn volume_trigger() -> Arc<Notify> {
    static T: OnceLock<Arc<Notify>> = OnceLock::new();
    T.get_or_init(|| Arc::new(Notify::new())).clone()
}

/// Home directories whose per-user persistence locations are scanned: every directory in `/Users`
/// (except `Shared` and hidden entries), the console user's home and `/var/root`. Bounded to 32.
pub fn user_homes(console: Option<&ConsoleUser>) -> Vec<PathBuf> {
    let mut homes: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/Users") {
        for entry in rd.flatten().take(64) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || name == "Shared" {
                continue;
            }
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                homes.push(entry.path());
            }
        }
    }
    if let Some(u) = console {
        if !homes.contains(&u.home) {
            homes.push(u.home.clone());
        }
    }
    #[cfg(target_os = "macos")]
    homes.push(PathBuf::from("/var/root"));
    homes.sort();
    homes.dedup();
    homes.truncate(32);
    homes
}
