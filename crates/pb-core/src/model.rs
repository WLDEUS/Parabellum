//! Shared data model. Serialized as JSON over IPC and stored (as JSON columns) in SQLite.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------------------------
// Verdicts & detections
// ---------------------------------------------------------------------------------------------

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    #[default]
    Clean,
    Suspicious,
    Malicious,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionEngine {
    /// SHA-256 match in the Parabellum hash database (MalwareBazaar etc.).
    HashDb,
    /// ClamAV (`clamscan`) signature.
    #[serde(rename = "clamav")]
    ClamAv,
    /// YARA-X rule.
    Yara,
    /// Mach-O static classifier.
    Ml,
    /// Built-in heuristic (e.g. unsigned binary in a LaunchAgent, script dropper patterns).
    Heuristic,
    /// VirusTotal hash lookup (opt-in).
    VirusTotal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    pub engine: DetectionEngine,
    /// Signature / rule / family name, e.g. `MacOS.Stealer.AMOS`.
    pub name: String,
    pub severity: Severity,
    /// 0.0 – 1.0
    pub confidence: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    #[serde(rename = "macho")]
    MachO,
    /// Universal (fat) Mach-O.
    #[serde(rename = "fat_macho")]
    FatMachO,
    Dmg,
    Pkg,
    Zip,
    /// Shell / Python / AppleScript / JXA / Perl / Ruby… (shebang or extension).
    Script,
    /// Mach-O dylib / bundle are reported as MachO; this is for `.app` directories.
    AppBundle,
    Document,
    Archive,
    #[default]
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SigningInfo {
    pub signed: bool,
    /// Signature verifies (not tampered).
    pub valid: bool,
    pub adhoc: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identifier: Option<String>,
    /// Leaf authority, e.g. `Developer ID Application: Foo (TEAMID)` or `Software Signing`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// Gatekeeper / notarization assessment (`spctl`), when it was computed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notarized: Option<bool>,
    /// Signed by Apple itself (platform binary / `Software Signing`).
    pub apple: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ScanReport {
    /// File path. For archive / DMG / PKG members: `<container path>!/<inner path>`.
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub size: u64,
    pub kind: FileKind,
    pub verdict: Verdict,
    /// Combined score 0.0 – 1.0 (see pb-engine scoring).
    pub score: f32,
    #[serde(default)]
    pub detections: Vec<Detection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningInfo>,
    /// Scan error (unreadable file, timeout, limit hit…). A report with an error is never `malicious`
    /// unless a detection was made before the error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
    /// Result came from the scan cache.
    #[serde(default)]
    pub cached: bool,
}

// ---------------------------------------------------------------------------------------------
// Scan jobs
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanOrigin {
    Manual,
    Downloads,
    Volume,
    Realtime,
    Scheduled,
    RetroHunt,
    /// Mercenary-spyware trace check (Zero Breach Toolkit, run as the console user).
    Spyware,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Finished,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanJobSummary {
    pub job_id: String,
    pub origin: ScanOrigin,
    pub paths: Vec<String>,
    pub state: JobState,
    pub started_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<i64>,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    /// Files with verdict != clean.
    pub threats: u64,
    pub errors: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanJobDetail {
    pub summary: ScanJobSummary,
    /// Non-clean reports and reports with errors only.
    pub findings: Vec<ScanReport>,
}

// ---------------------------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// UUID v4.
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub detections: Vec<Detection>,
    pub quarantined_at: i64,
    pub owner_uid: u32,
    pub owner_gid: u32,
    /// Original permission bits (st_mode & 0o7777).
    pub mode: u32,
    /// Why it was quarantined: "auto", "user", "persistence"…
    pub reason: String,
}

// ---------------------------------------------------------------------------------------------
// Alerts
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    Malware,
    Suspicious,
    Persistence,
    Device,
    Network,
    Update,
    System,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    #[default]
    Open,
    Acknowledged,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertAction {
    Acknowledge,
    Quarantine,
    /// Allow this file hash from now on (local allowlist) and restore it if quarantined.
    Allow,
    Restore,
    TrustDevice,
    BlockDevice,
    ApprovePersistence,
    /// Unload the launch item and quarantine its plist + program.
    RemovePersistence,
    ReportFalsePositive,
    Dismiss,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    /// SQLite row id (0 before insertion).
    pub id: i64,
    pub ts: i64,
    pub kind: AlertKind,
    pub severity: Severity,
    pub title: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistence_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine_id: Option<String>,
    pub status: AlertStatus,
    /// Actions the UI should offer for this alert.
    pub actions: Vec<AlertAction>,
}

// ---------------------------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceKind {
    /// Mounted filesystem (USB key, external disk, SD card, network share, DMG).
    Volume,
    /// USB / SPI keyboard, mouse, or any HID interface.
    Hid,
    /// Other USB device (hub, storage controller, serial, ethernet adapter…).
    Usb,
    Bluetooth,
    NetworkInterface,
    Thunderbolt,
    WifiNetwork,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DeviceTrust {
    #[default]
    Unknown,
    Trusted,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// Stable identifier, e.g. `hid:05ac:0281:<serial-or-location>`, `vol:<volume uuid>`,
    /// `bt:<address>`, `net:<bsd name>:<mac>`, `wifi:<ssid>`.
    pub id: String,
    pub kind: DeviceKind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vendor_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,
    /// "USB", "SPI", "Bluetooth", "Thunderbolt", "Virtual", "Network"…
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// Free-form extra properties (mount point, filesystem, BSD name, MAC, RSSI…).
    #[serde(default)]
    pub details: BTreeMap<String, String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub connected: bool,
    pub trust: DeviceTrust,
    /// Present when Parabellum first ran (never alerted on).
    pub baseline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceChange {
    /// Never seen before.
    New,
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceEvent {
    pub device: DeviceInfo,
    pub change: DeviceChange,
}

// ---------------------------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceKind {
    LaunchAgent,
    LaunchDaemon,
    LoginItem,
    /// Background Task Management item (`sfltool dumpbtm`, eslogger `btm_launch_item_add`).
    BackgroundItem,
    Cron,
    Periodic,
    ShellProfile,
    ConfigurationProfile,
    BrowserExtension,
    SystemExtension,
    KernelExtension,
    AuthorizationPlugin,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceStatus {
    /// Existed at first run.
    Baseline,
    #[default]
    New,
    Approved,
    Removed,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PersistenceItem {
    /// Stable id: hex SHA-256 of `kind|path|label` truncated to 16 hex chars.
    pub id: String,
    pub kind: PersistenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Plist / config / profile path that creates the persistence.
    pub path: String,
    /// Program that will be executed, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(default)]
    pub arguments: Vec<String>,
    /// User owning it (for per-user items).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing: Option<SigningInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_sha256: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub status: PersistenceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceChangeKind {
    Added,
    Modified,
    Removed,
}

// ---------------------------------------------------------------------------------------------
// Components (third-party tools managed by the updater) & DB
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    NotInstalled,
    Installed,
    UpdateAvailable,
    Updating,
    Error,
    Disabled,
    /// Installed but needs a user action (approve system extension, enable browser extension…).
    NeedsUserAction,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComponentStatus {
    /// Machine name: `clamav`, `osquery`, `dnscrypt-proxy`, `lulu`, `blockblock`, `oversight`,
    /// `parabellum`, `threat-db`, `ml-model`, `ublock-chrome`, `ublock-safari`, `zero-breach-toolkit`.
    pub name: String,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_version: Option<String>,
    pub state: ComponentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check: Option<i64>,
    pub auto_update: bool,
    /// Required for full protection (shown prominently when missing).
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Where the user can act (store page, System Settings deep link, release page).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_url: Option<String>,
}

/// One macOS security setting checked by the daemon (`posture` command).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureCheck {
    /// Stable machine id: `sip`, `gatekeeper`, `filevault`, `firewall`, `security_updates`,
    /// `macos_updates`, `xprotect`, `guest_account`, `remote_login`, `screen_sharing`.
    pub id: String,
    pub title: String,
    /// The setting is in its safe state (false also when the check could not run: see `severity` info).
    pub ok: bool,
    /// Severity of the alert raised while `ok` is false (`info` = could not be checked).
    pub severity: Severity,
    /// What was observed (French).
    pub detail: String,
    /// How to fix it (French, "Réglages Système > …"); empty when `ok`.
    #[serde(default)]
    pub fix: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DbStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub built_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub malware_hashes: u64,
    pub yara_rules: u64,
    pub blocked_domains: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clamav_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_model_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateTarget {
    Db,
    Components,
    App,
    All,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateResult {
    pub target: UpdateTarget,
    pub ok: bool,
    pub started_at: i64,
    pub finished_at: i64,
    /// Human-readable lines (one per component / step).
    pub messages: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_db_version: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// DNS & ad blocking
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DnsStatus {
    pub enabled: bool,
    /// dnscrypt-proxy process alive and answering.
    pub running: bool,
    pub listen: String,
    pub blocked_domains: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub list_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queries_blocked_24h: Option<u64>,
    /// Network services whose DNS servers we changed (restored when disabled).
    #[serde(default)]
    pub managed_services: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionState {
    NotInstalled,
    InstalledDisabled,
    Enabled,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AdblockStatus {
    pub chrome_ublock: ExtensionState,
    pub safari_ublock: ExtensionState,
    pub dns: DnsStatus,
    pub chrome_store_url: String,
    pub safari_store_url: String,
}

// ---------------------------------------------------------------------------------------------
// Daemon status & reports
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    #[default]
    Active,
    /// Paused by the user (until `paused_until`).
    Paused,
    /// Running but something important is missing (no DB, no Full Disk Access, monitor down…).
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RealtimeStatus {
    pub fsevents: bool,
    pub eslogger: bool,
    pub full_disk_access: bool,
    pub persistence_monitor: bool,
    pub device_monitor: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct StatusInfo {
    pub version: String,
    pub protection: ProtectionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paused_until: Option<i64>,
    /// Why protection is degraded (empty when active).
    #[serde(default)]
    pub issues: Vec<String>,
    pub realtime: RealtimeStatus,
    pub db: DbStatus,
    pub open_alerts: u32,
    pub quarantined: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_scan: Option<i64>,
    pub dns_enabled: bool,
    pub on_battery: bool,
    pub components_needing_attention: u32,
    pub ml_enabled: bool,
    pub uptime_secs: u64,
    /// Resident memory of the daemon, bytes.
    pub rss_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NamedCount {
    pub name: String,
    pub count: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WeeklyReport {
    pub week_start: i64,
    pub week_end: i64,
    pub files_scanned: u64,
    pub threats_detected: u64,
    pub quarantined: u64,
    pub false_positives_reported: u64,
    pub persistence_new: u64,
    pub devices_new: u64,
    pub db_updates: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub db_version: Option<String>,
    #[serde(default)]
    pub component_updates: Vec<String>,
    #[serde(default)]
    pub top_detections: Vec<NamedCount>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_blocked_queries: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enums_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&FileKind::FatMachO).unwrap(),
            "\"fat_macho\""
        );
        assert_eq!(
            serde_json::to_string(&FileKind::MachO).unwrap(),
            "\"macho\""
        );
        assert_eq!(
            serde_json::to_string(&DetectionEngine::ClamAv).unwrap(),
            "\"clamav\""
        );
        assert_eq!(
            serde_json::to_string(&AlertAction::RemovePersistence).unwrap(),
            "\"remove_persistence\""
        );
        assert_eq!(
            serde_json::to_string(&ExtensionState::InstalledDisabled).unwrap(),
            "\"installed_disabled\""
        );
    }

    #[test]
    fn severity_orders() {
        assert!(Severity::Critical > Severity::High && Severity::Low > Severity::Info);
        assert!(Verdict::Malicious > Verdict::Suspicious && Verdict::Suspicious > Verdict::Clean);
    }

    #[test]
    fn optional_fields_omitted() {
        let r = ScanReport {
            path: "/x".into(),
            ..Default::default()
        };
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("sha256").is_none());
        assert_eq!(v["verdict"], "clean");
    }
}
