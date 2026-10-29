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
    /// Behaviour detection: info-stealer, ransomware (decoy files, mass encryption).
    Behavior,
    /// Privacy: data breaches, GDPR request follow-up.
    Privacy,
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
    /// Kill the process named in the alert (`process_pid` + `process_path`, re-checked before signalling).
    KillProcess,
    /// Resume a process Parabellum suspended (SIGCONT).
    ResumeProcess,
    /// Mark the network named in the alert (`network_id`) as trusted.
    TrustNetwork,
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
    /// Process involved (behaviour alerts): pid at detection time and executable path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_path: Option<String>,
    /// Network involved (network / VPN alerts), `gw:<router MAC>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
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

// ---------------------------------------------------------------------------------------------
// VPN & networks
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VpnState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    /// The last attempt failed (see `VpnStatus::message`); retried with backoff while the VPN is wanted.
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchState {
    /// Not enabled in the configuration, or the VPN is not wanted right now.
    #[default]
    Off,
    /// Rules loaded, the tunnel is up: only tunnel / LAN / VPN-server traffic leaves the Mac.
    Armed,
    /// Rules loaded, the tunnel is down: Internet traffic is blocked until it comes back.
    Blocking,
    /// pf could not be configured (see `VpnStatus::message`).
    Error,
}

/// Imported VPN profile, without its secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnProfileInfo {
    /// Display name (link fragment / `[Interface]` comment / server).
    pub name: String,
    /// `shadowsocks`, `vless`, `vmess`, `trojan`, `hysteria2`, `tuic`, `wireguard`.
    pub protocol: String,
    pub server: String,
    pub port: u16,
    /// Transport / security summary, e.g. `tls+ws`, `reality`, `udp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    pub imported_at: i64,
}

/// A network the Mac joined, identified by its router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInfo {
    /// `gw:<router MAC>` (stable for a given router; also works on Ethernet, no location permission).
    pub id: String,
    /// Wi-Fi name when macOS reveals it, else `Ethernet` / interface name.
    pub name: String,
    /// BSD interface (`en0`).
    pub interface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_mac: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    /// Wi-Fi security as reported by macOS (`WPA2 Personal`, `None`…), when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    pub trusted: bool,
    pub first_seen: i64,
    pub last_seen: i64,
    /// The Mac is on this network right now.
    pub current: bool,
}

/// One check of a leak test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakCheck {
    /// `tunnel`, `ipv4`, `ipv6`, `dns`, `kill_switch`.
    pub id: String,
    pub ok: bool,
    /// What was observed (French).
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeakTestResult {
    pub ts: i64,
    /// Every check passed.
    pub ok: bool,
    pub vpn_connected: bool,
    /// Public IPv4 seen by the Internet now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ipv4: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_ipv6: Option<String>,
    /// Public IPv4 of this network without the VPN (remembered per network).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub home_ipv4: Option<String>,
    /// System DNS servers in use (`scutil --dns`).
    #[serde(default)]
    pub dns_servers: Vec<String>,
    pub checks: Vec<LeakCheck>,
}

/// A VPN configured in macOS (Network settings), as listed by `scutil --nc list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalVpnService {
    pub name: String,
    /// Provider bundle id (`com.liguangming.Shadowrocket`, `com.wireguard.macos`…), when shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub state: VpnState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VpnStatus {
    pub mode: crate::config::VpnMode,
    pub backend: crate::config::VpnBackend,
    pub state: VpnState,
    /// The daemon wants the tunnel up right now (mode + network + manual override).
    pub wanted: bool,
    /// `Some(true)`: connected by hand; `Some(false)`: disconnected by hand until the next network change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manual_override: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<VpnProfileInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_since: Option<i64>,
    /// Tunnel interface (`utun5`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    pub kill_switch: KillSwitchState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_leak_test: Option<LeakTestResult>,
    /// sing-box binary installed (backend `sing_box`).
    pub engine_installed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// ---------------------------------------------------------------------------------------------
// Behaviour guard (stealers, ransomware) & snapshots
// ---------------------------------------------------------------------------------------------

/// APFS local snapshot (`tmutil listlocalsnapshots /`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Full name, e.g. `com.apple.TimeMachine.2026-10-29-120000.local`.
    pub name: String,
    /// Creation time parsed from the name (local time), when possible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
    /// Created by Parabellum (vs. Time Machine / the system).
    pub ours: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct GuardStatus {
    pub stealer_detection: bool,
    pub ransomware_detection: bool,
    /// Decoy files in place.
    #[serde(default)]
    pub canaries: Vec<String>,
    pub snapshots_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_snapshot: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_error: Option<String>,
    /// Processes suspended by Parabellum, waiting for a decision.
    #[serde(default)]
    pub suspended: Vec<SuspendedProcess>,
    /// Detections in the last 7 days.
    pub detections_7d: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuspendedProcess {
    pub pid: i32,
    pub path: String,
    pub since: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_id: Option<i64>,
}

// ---------------------------------------------------------------------------------------------
// Privacy: identity, data brokers, GDPR requests, breaches, aliases
// ---------------------------------------------------------------------------------------------

/// The person data brokers must erase. Stored by the daemon (root-only); masked over IPC unless revealed
/// with administrator approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct IdentityProfile {
    pub full_name: String,
    /// Every address brokers may know (the first one is used as the contact address).
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    /// Current postal address (multi-line).
    pub postal_address: String,
    pub previous_addresses: Vec<String>,
    /// `YYYY-MM-DD`, optional (some brokers need it to find you).
    pub birth_date: String,
    /// ISO country code of residence (`FR`): selects the supervisory authority (CNIL).
    pub country: String,
}

/// One organisation from the signed broker list (`privacy/brokers.json` in the threat DB).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerInfo {
    /// Stable slug.
    pub id: String,
    pub name: String,
    /// Privacy / DPO contact address; brokers without one need the web form (`opt_out_url`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opt_out_url: Option<String>,
    /// `eu`, `global`, `us`.
    pub region: String,
    /// `ads`, `addresses`, `credit`, `people-search`, `marketing`, `background-check`…
    pub category: String,
    /// `datenanfragen` (CC0) or `eraser` (MIT).
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RemovalStatus {
    /// Waiting for the daily sending quota.
    #[default]
    Queued,
    /// Draft written, waiting for you to send it (drafts mode).
    DraftReady,
    /// Sent (or marked sent); the one-month deadline runs.
    Sent,
    /// Deadline passed: reminder sent / drafted.
    Reminded,
    /// Reminder unanswered: CNIL complaint suggested.
    Escalated,
    /// The broker confirmed the erasure (or said it holds nothing).
    Completed,
    /// The broker refused or asked for something you do not want to give.
    Refused,
    /// The broker only accepts its web form: do it by hand, then mark it completed.
    NeedsForm,
    /// Sending failed (see `last_error`).
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovalRequest {
    /// UUID v4.
    pub id: String,
    pub broker_id: String,
    pub broker_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broker_email: Option<String>,
    pub status: RemovalStatus,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<i64>,
    /// Legal answer deadline (sent + one month).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reminded_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opt_out_url: Option<String>,
    /// Draft file (drafts mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Counters of the removal campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RemovalSummary {
    pub total: u64,
    pub queued: u64,
    pub waiting_answer: u64,
    pub overdue: u64,
    pub completed: u64,
    pub needs_action: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_send_at: Option<i64>,
}

/// A ready-to-send email (drafts mode, reminders): the app / CLI writes it as an `.eml` or opens a
/// `mailto:` link, as the user — the daemon never writes into the home folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailDraft {
    pub request_id: String,
    pub to: String,
    pub subject: String,
    /// Plain-text body (UTF-8, `\n` line breaks).
    pub body: String,
}

/// GDPR complaint draft for the supervisory authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplaintDraft {
    pub authority: String,
    /// Where to file it (CNIL online form).
    pub url: String,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreachFinding {
    pub email: String,
    /// Breach name as given by the provider.
    pub breach: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breach_date: Option<String>,
    /// Exposed data classes (`Passwords`, `Email addresses`…), when the provider says.
    #[serde(default)]
    pub data_classes: Vec<String>,
    pub first_seen: i64,
    /// Seen for the first time by the last check.
    pub new: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailAlias {
    /// Provider id of the alias.
    pub id: String,
    pub email: String,
    /// What it is for (site name).
    pub label: String,
    pub provider: crate::config::AliasProvider,
    pub created_at: i64,
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_models_wire_format() {
        assert_eq!(
            serde_json::to_string(&KillSwitchState::Blocking).unwrap(),
            "\"blocking\""
        );
        assert_eq!(
            serde_json::to_string(&RemovalStatus::NeedsForm).unwrap(),
            "\"needs_form\""
        );
        assert_eq!(
            serde_json::to_string(&AlertAction::KillProcess).unwrap(),
            "\"kill_process\""
        );
        let s = VpnStatus::default();
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["mode"], "off");
        assert_eq!(v["backend"], "sing_box");
        assert!(v.get("profile").is_none());
    }

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
