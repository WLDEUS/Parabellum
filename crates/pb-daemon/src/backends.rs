//! Integration points with the other Parabellum crates (pb-engine, pb-monitor, pb-updater, pb-dns).
//!
//! The daemon only talks to these small traits. `Backends::unavailable()` provides stubs answering
//! [`ErrorCode::Unavailable`] (used until the real crates are wired in, and for degraded startup);
//! [`crate::adapters`] maps them onto the real crates; tests use in-process fakes.

use async_trait::async_trait;
use pb_core::config::Config;
use pb_core::events::MonitorEvent;
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::*;
use pb_core::paths::Paths;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

/// Error returned by a backend.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BackendError {
    /// The component is missing / not wired / not supported on this platform.
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Failed(String),
}

impl BackendError {
    /// Stub error used by the placeholders.
    pub fn not_wired(what: &str) -> Self {
        BackendError::Unavailable(format!("{what} indisponible"))
    }
}

impl From<BackendError> for IpcError {
    fn from(e: BackendError) -> Self {
        match e {
            BackendError::Unavailable(m) => IpcError::new(ErrorCode::Unavailable, m),
            BackendError::NotFound(m) => IpcError::new(ErrorCode::NotFound, m),
            BackendError::Invalid(m) => IpcError::new(ErrorCode::BadRequest, m),
            BackendError::Failed(m) => IpcError::new(ErrorCode::Internal, m),
        }
    }
}

/// Daemon-side scan options (mapped to the engine's options by the adapter, together with `Config`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOpts {
    pub origin: ScanOrigin,
    pub use_clamav: bool,
    pub recursive: bool,
    /// Volume scans: only executables, scripts, installers, archives, documents with macros…
    pub only_risky_types: bool,
}

impl ScanOpts {
    /// Options for a real-time single-file scan.
    pub fn realtime(cfg: &Config) -> Self {
        Self {
            origin: ScanOrigin::Realtime,
            use_clamav: cfg.scan.clamav_realtime,
            recursive: false,
            only_risky_types: false,
        }
    }
}

/// Per-report callback of a tree scan. Return `false` to stop early.
pub type ReportSink<'a> = &'a mut (dyn FnMut(ScanReport) -> bool + Send);

/// A loaded scanning engine (hash DB + YARA-X + ClamAV wrapper + ML + signing checks).
/// All methods are blocking and are called from `spawn_blocking` threads.
pub trait ScanEngine: Send + Sync + 'static {
    /// Scan one file (or bundle / container) and return its report. Never panics; errors go into `report.error`.
    fn scan_file(&self, path: &Path, cfg: &Config, opts: &ScanOpts) -> ScanReport;

    /// Scan files and directory trees. Must call `sink` for every scanned file (clean ones included, so the
    /// daemon can count them) and stop as soon as `cancel` is set or `sink` returns `false`.
    fn scan_tree(
        &self,
        roots: &[PathBuf],
        cfg: &Config,
        opts: &ScanOpts,
        cancel: &AtomicBool,
        sink: ReportSink<'_>,
    );

    /// Code-signing facts of an executable / bundle (`codesign`), `None` if not determinable.
    fn signing_info(&self, path: &Path) -> Option<SigningInfo>;

    /// Is this Apple Developer Team ID in the trusted list of the DB bundle?
    fn is_trusted_team(&self, team_id: &str) -> bool;

    /// Pure hash-DB lookup (cheap, no file I/O) used for nightly retro-checks of `file_history`.
    fn lookup_hash(&self, sha256: &str) -> Option<Detection>;

    /// [`ScanEngine::lookup_hash`] is implemented (otherwise DB changes trigger a re-scan retro-hunt).
    fn supports_hash_lookup(&self) -> bool {
        false
    }

    /// Version / counters of the loaded DB (`version`, `built_at`, `malware_hashes`, `yara_rules`…).
    fn db_status(&self) -> DbStatus;

    /// `clamscan` found and usable.
    fn clamav_available(&self) -> bool;

    /// ML model loaded.
    fn ml_loaded(&self) -> bool;

    /// Strong enough for automatic action (auto-quarantine, kill): hash DB, ClamAV (non-PUA), YARA /
    /// heuristic high+ when the signer is not trusted. ML alone never is.
    fn is_signature_grade(&self, d: &Detection, signing: Option<&SigningInfo>) -> bool {
        let _ = signing;
        match d.engine {
            DetectionEngine::HashDb | DetectionEngine::ClamAv => true,
            DetectionEngine::Yara | DetectionEngine::Heuristic => d.severity >= Severity::High,
            DetectionEngine::Ml | DetectionEngine::VirusTotal => false,
        }
    }

    /// Hashes the user allowed (restored with "allow", reported false positives): they win over every engine.
    fn set_local_allowlist(&self, sha256_hex: &[String]) {
        let _ = sha256_hex;
    }
}

/// Builds (and rebuilds after DB updates) the scanning engine.
pub trait EngineLoader: Send + Sync + 'static {
    /// Load the engine from `paths.db_current()` with the given configuration. Blocking.
    fn load(&self, paths: &Paths, cfg: &Config) -> Result<Arc<dyn ScanEngine>, BackendError>;
}

/// Reversible quarantine (pb-engine `Quarantine`). Blocking.
pub trait QuarantineStore: Send + Sync + 'static {
    fn quarantine(
        &self,
        path: &Path,
        sha256: Option<&str>,
        detections: &[Detection],
        reason: &str,
    ) -> Result<QuarantineEntry, BackendError>;
    fn list(&self) -> Result<Vec<QuarantineEntry>, BackendError>;
    fn get(&self, id: &str) -> Result<QuarantineEntry, BackendError>;
    /// Put the file back; returns the restored path.
    fn restore(&self, id: &str) -> Result<PathBuf, BackendError>;
    fn delete(&self, id: &str) -> Result<(), BackendError>;
}

/// What the monitors need to start.
pub struct MonitorContext {
    pub paths: Paths,
    pub events: mpsc::Sender<MonitorEvent>,
    pub config: watch::Receiver<Arc<Config>>,
    pub shutdown: watch::Receiver<bool>,
    /// Persistence items known from previous runs (the watcher diffs against it).
    pub persistence_snapshot: Vec<PersistenceItem>,
    /// Devices known from previous runs.
    pub known_devices: Vec<DeviceInfo>,
    /// Home directory of the console user (for `~` expansion), if any.
    pub console_home: Option<PathBuf>,
}

/// One osquery result row of the hunting pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsqueryRow {
    pub query: String,
    /// The pack flags this query as alerting.
    pub alert: bool,
    pub description: Option<String>,
    pub columns: BTreeMap<String, String>,
}

/// pb-monitor: watchers + device helpers + osquery.
#[async_trait]
pub trait Monitors: Send + Sync + 'static {
    /// Start every watcher; they push [`MonitorEvent`]s and stop when `shutdown` turns `true`.
    fn start(&self, ctx: MonitorContext) -> Vec<JoinHandle<()>>;
    /// TCC Full Disk Access granted to the daemon.
    fn has_full_disk_access(&self) -> bool;
    /// Best-effort: seize an HID device so it cannot type.
    fn block_hid(&self, device: &DeviceInfo) -> Result<(), BackendError>;
    fn unblock_hid(&self, device_id: &str) -> Result<(), BackendError>;
    /// Run the hunting pack (`pack` = path of `osquery/hunting.json`, `None` = built-in default pack).
    async fn run_osquery_pack(
        &self,
        pack: Option<PathBuf>,
    ) -> Result<Vec<OsqueryRow>, BackendError>;
}

/// Outcome of a threat-DB update.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DbUpdateOutcome {
    /// A new bundle was installed (engine must be reloaded).
    pub updated: bool,
    pub version: Option<String>,
    pub messages: Vec<String>,
}

/// pb-updater: signed DB, freshclam, third-party components, app updates, browser extension state.
#[async_trait]
pub trait Updater: Send + Sync + 'static {
    async fn update_db(&self, cfg: &Config) -> Result<DbUpdateOutcome, BackendError>;
    async fn freshclam(&self, cfg: &Config) -> Result<String, BackendError>;
    /// Update components with `auto_update` set. Returns one message per component.
    async fn update_components(&self, cfg: &Config) -> Result<Vec<String>, BackendError>;
    /// Check (and, if `updates.auto_update_app`, install) a new Parabellum release. Returns a message.
    async fn check_app_update(&self, cfg: &Config) -> Result<String, BackendError>;
    async fn list_components(&self, cfg: &Config) -> Vec<ComponentStatus>;
    async fn install_component(
        &self,
        name: &str,
        cfg: &Config,
    ) -> Result<ComponentStatus, BackendError>;
    async fn set_component_auto_update(
        &self,
        name: &str,
        auto_update: bool,
        cfg: &Config,
    ) -> Result<Vec<ComponentStatus>, BackendError>;
    /// uBlock Origin Lite state in (Chrome, Safari) for the console user.
    async fn extension_states(
        &self,
        console_home: Option<PathBuf>,
    ) -> (ExtensionState, ExtensionState);
    /// Update bookkeeping (`last_check`, `last_success`, `last_error`, `previous_version`) + manifest facts.
    fn db_update_status(&self, cfg: &Config) -> DbStatus;
}

/// pb-dns: dnscrypt-proxy + system DNS switching (fail-open).
#[async_trait]
pub trait Dns: Send + Sync + 'static {
    /// Undo a half-applied state left by a crash (restores system DNS if the proxy is dead).
    async fn recover_on_startup(&self);
    /// Start the proxy with the merged lists and point the system DNS at it.
    async fn enable(&self, cfg: &Config) -> Result<DnsStatus, BackendError>;
    /// Restore the original system DNS and stop the proxy (user toggle).
    async fn disable(&self) -> Result<DnsStatus, BackendError>;
    /// Restore the original system DNS before the daemon exits (fail-open), without changing the config.
    async fn restore_system_dns(&self) -> Result<(), BackendError>;
    async fn status(&self, cfg: &Config) -> DnsStatus;
    /// Rebuild the merged blocklist from the current DB bundle and reload the proxy. Returns the domain count.
    async fn rebuild_lists(&self, cfg: &Config) -> Result<u64, BackendError>;
    /// Watchdog keeping the proxy alive (fail-open when it dies).
    fn start_supervisor(
        &self,
        config: watch::Receiver<Arc<Config>>,
        shutdown: watch::Receiver<bool>,
    ) -> Option<JoinHandle<()>>;
}

/// Hash reputation lookups (VirusTotal API v3).
#[async_trait]
pub trait HashReputation: Send + Sync + 'static {
    /// Number of engines flagging the hash as malicious, `None` if VirusTotal does not know it.
    async fn malicious_engines(
        &self,
        sha256: &str,
        api_key: &str,
    ) -> Result<Option<u32>, BackendError>;
}

/// The set of integrations the daemon runs with.
#[derive(Clone)]
pub struct Backends {
    pub engine_loader: Arc<dyn EngineLoader>,
    pub quarantine: Arc<dyn QuarantineStore>,
    pub monitors: Arc<dyn Monitors>,
    pub updater: Arc<dyn Updater>,
    pub dns: Arc<dyn Dns>,
    pub reputation: Arc<dyn HashReputation>,
}

impl Backends {
    /// Every integration answers "unavailable" (no detection at all).
    pub fn unavailable() -> Self {
        Self {
            engine_loader: Arc::new(NullEngineLoader),
            quarantine: Arc::new(NullQuarantine),
            monitors: Arc::new(NullMonitors),
            updater: Arc::new(NullUpdater),
            dns: Arc::new(NullDns),
            reputation: Arc::new(crate::virustotal::VirusTotal::new()),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Placeholders
// ---------------------------------------------------------------------------------------------

/// Engine stub: every scan reports an error, nothing is detected.
#[derive(Debug, Default)]
pub struct NullEngine;

impl ScanEngine for NullEngine {
    fn scan_file(&self, path: &Path, _cfg: &Config, _opts: &ScanOpts) -> ScanReport {
        ScanReport {
            path: path.to_string_lossy().into_owned(),
            error: Some("moteur d'analyse indisponible".into()),
            ..Default::default()
        }
    }
    fn scan_tree(
        &self,
        roots: &[PathBuf],
        cfg: &Config,
        opts: &ScanOpts,
        cancel: &AtomicBool,
        sink: ReportSink<'_>,
    ) {
        for r in roots {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            if !sink(self.scan_file(r, cfg, opts)) {
                return;
            }
        }
    }
    fn signing_info(&self, _path: &Path) -> Option<SigningInfo> {
        None
    }
    fn is_trusted_team(&self, _team_id: &str) -> bool {
        false
    }
    fn lookup_hash(&self, _sha256: &str) -> Option<Detection> {
        None
    }
    fn db_status(&self) -> DbStatus {
        DbStatus::default()
    }
    fn clamav_available(&self) -> bool {
        false
    }
    fn ml_loaded(&self) -> bool {
        false
    }
}

/// Loader stub.
#[derive(Debug, Default)]
pub struct NullEngineLoader;

impl EngineLoader for NullEngineLoader {
    fn load(&self, _paths: &Paths, _cfg: &Config) -> Result<Arc<dyn ScanEngine>, BackendError> {
        Err(BackendError::not_wired("moteur d'analyse"))
    }
}

/// Quarantine stub.
#[derive(Debug, Default)]
pub struct NullQuarantine;

impl QuarantineStore for NullQuarantine {
    fn quarantine(
        &self,
        _p: &Path,
        _s: Option<&str>,
        _d: &[Detection],
        _r: &str,
    ) -> Result<QuarantineEntry, BackendError> {
        Err(BackendError::not_wired("quarantaine"))
    }
    fn list(&self) -> Result<Vec<QuarantineEntry>, BackendError> {
        Ok(vec![])
    }
    fn get(&self, id: &str) -> Result<QuarantineEntry, BackendError> {
        Err(BackendError::NotFound(format!(
            "entrée de quarantaine inconnue : {id}"
        )))
    }
    fn restore(&self, _id: &str) -> Result<PathBuf, BackendError> {
        Err(BackendError::not_wired("quarantaine"))
    }
    fn delete(&self, _id: &str) -> Result<(), BackendError> {
        Err(BackendError::not_wired("quarantaine"))
    }
}

/// Monitors stub (no watcher started).
#[derive(Debug, Default)]
pub struct NullMonitors;

#[async_trait]
impl Monitors for NullMonitors {
    fn start(&self, _ctx: MonitorContext) -> Vec<JoinHandle<()>> {
        vec![]
    }
    fn has_full_disk_access(&self) -> bool {
        false
    }
    fn block_hid(&self, _device: &DeviceInfo) -> Result<(), BackendError> {
        Err(BackendError::not_wired("blocage HID"))
    }
    fn unblock_hid(&self, _device_id: &str) -> Result<(), BackendError> {
        Ok(())
    }
    async fn run_osquery_pack(
        &self,
        _pack: Option<PathBuf>,
    ) -> Result<Vec<OsqueryRow>, BackendError> {
        Err(BackendError::not_wired("osquery"))
    }
}

/// Updater stub.
#[derive(Debug, Default)]
pub struct NullUpdater;

#[async_trait]
impl Updater for NullUpdater {
    async fn update_db(&self, _cfg: &Config) -> Result<DbUpdateOutcome, BackendError> {
        Err(BackendError::not_wired("mise à jour de la base"))
    }
    async fn freshclam(&self, _cfg: &Config) -> Result<String, BackendError> {
        Err(BackendError::not_wired("freshclam"))
    }
    async fn update_components(&self, _cfg: &Config) -> Result<Vec<String>, BackendError> {
        Err(BackendError::not_wired("gestionnaire de composants"))
    }
    async fn check_app_update(&self, _cfg: &Config) -> Result<String, BackendError> {
        Err(BackendError::not_wired("mise à jour de l'app"))
    }
    async fn list_components(&self, _cfg: &Config) -> Vec<ComponentStatus> {
        vec![]
    }
    async fn install_component(
        &self,
        _name: &str,
        _cfg: &Config,
    ) -> Result<ComponentStatus, BackendError> {
        Err(BackendError::not_wired("gestionnaire de composants"))
    }
    async fn set_component_auto_update(
        &self,
        _n: &str,
        _a: bool,
        _c: &Config,
    ) -> Result<Vec<ComponentStatus>, BackendError> {
        Err(BackendError::not_wired("gestionnaire de composants"))
    }
    async fn extension_states(&self, _home: Option<PathBuf>) -> (ExtensionState, ExtensionState) {
        (ExtensionState::Unknown, ExtensionState::Unknown)
    }
    fn db_update_status(&self, _cfg: &Config) -> DbStatus {
        DbStatus::default()
    }
}

/// DNS stub.
#[derive(Debug, Default)]
pub struct NullDns;

#[async_trait]
impl Dns for NullDns {
    async fn recover_on_startup(&self) {}
    async fn enable(&self, _cfg: &Config) -> Result<DnsStatus, BackendError> {
        Err(BackendError::not_wired("blocage DNS"))
    }
    async fn disable(&self) -> Result<DnsStatus, BackendError> {
        Ok(DnsStatus::default())
    }
    async fn restore_system_dns(&self) -> Result<(), BackendError> {
        Ok(())
    }
    async fn status(&self, cfg: &Config) -> DnsStatus {
        DnsStatus {
            enabled: cfg.dns.enabled,
            listen: cfg.dns.listen.clone(),
            message: Some("blocage DNS indisponible".into()),
            ..Default::default()
        }
    }
    async fn rebuild_lists(&self, _cfg: &Config) -> Result<u64, BackendError> {
        Err(BackendError::not_wired("blocage DNS"))
    }
    fn start_supervisor(
        &self,
        _c: watch::Receiver<Arc<Config>>,
        _s: watch::Receiver<bool>,
    ) -> Option<JoinHandle<()>> {
        None
    }
}
