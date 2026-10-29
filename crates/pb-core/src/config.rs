//! User configuration (`config.toml`). Every section and field has a default so that a partial or
//! older file always loads (`#[serde(default)]` everywhere). The daemon is the only writer; the app
//! edits it through the `get_config` / `set_config` IPC commands.

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("cannot serialize config: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("invalid value: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub scan: ScanConfig,
    pub realtime: RealtimeConfig,
    pub ml: MlConfig,
    pub dns: DnsConfig,
    pub devices: DevicesConfig,
    pub persistence: PersistenceConfig,
    pub updates: UpdatesConfig,
    pub energy: EnergyConfig,
    pub privacy: PrivacyConfig,
    pub notifications: NotificationsConfig,
    pub security: SecurityConfig,
    pub vpn: VpnConfig,
    pub guard: GuardConfig,
    pub network: NetworkGuardConfig,
    pub data_removal: DataRemovalConfig,
    pub breach: BreachConfig,
    pub aliases: AliasConfig,
}

impl Config {
    /// Load from disk; a missing file yields defaults.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_toml(&s),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn from_toml(s: &str) -> Result<Self, ConfigError> {
        let c: Config = toml::from_str(s)?;
        c.validate()?;
        Ok(c)
    }

    pub fn to_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(self)?)
    }

    /// Atomic write (tmp file + rename).
    pub fn save(&self, path: &Path) -> Result<(), ConfigError> {
        self.validate()?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, self.to_toml()?)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Reject values that would make the daemon misbehave.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.scan.max_file_size_mb == 0 {
            return Err(ConfigError::Invalid(
                "scan.max_file_size_mb must be > 0".into(),
            ));
        }
        if self.scan.archive_max_depth > 10 {
            return Err(ConfigError::Invalid(
                "scan.archive_max_depth must be <= 10".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.ml.suspicious_threshold) {
            return Err(ConfigError::Invalid(
                "ml.suspicious_threshold must be within 0..1".into(),
            ));
        }
        if self.updates.daily_hour > 23 {
            return Err(ConfigError::Invalid(
                "updates.daily_hour must be 0..23".into(),
            ));
        }
        match self.dns.listen.parse::<std::net::SocketAddr>() {
            Ok(a) if a.ip().is_loopback() => {}
            _ => {
                return Err(ConfigError::Invalid(
                    "dns.listen must be a loopback socket address (127.0.0.1:53 or [::1]:53)"
                        .into(),
                ))
            }
        }
        for url in [&self.updates.db_base_url, &self.updates.app_releases_api] {
            if !url.starts_with("https://") {
                return Err(ConfigError::Invalid(format!(
                    "update URL must use https: {url}"
                )));
            }
        }
        if !(1..=7).contains(&self.security.spyware_scan_weekday) {
            return Err(ConfigError::Invalid(
                "security.spyware_scan_weekday must be 1 (Monday)..7 (Sunday)".into(),
            ));
        }
        if self.security.spyware_scan_hour > 23 {
            return Err(ConfigError::Invalid(
                "security.spyware_scan_hour must be 0..23".into(),
            ));
        }
        if self.energy.pause_on_battery_below > 100 {
            return Err(ConfigError::Invalid(
                "energy.pause_on_battery_below must be 0..100".into(),
            ));
        }
        self.validate_protection()
    }

    /// Validation of the VPN / guard / network / privacy sections.
    fn validate_protection(&self) -> Result<(), ConfigError> {
        let invalid = |m: &str| Err(ConfigError::Invalid(m.into()));
        if self.vpn.leak_test_interval_minutes > 7 * 24 * 60 {
            return invalid("vpn.leak_test_interval_minutes must be <= 10080");
        }
        if let Some(s) = &self.vpn.external_service {
            if s.trim().is_empty() || s.len() > 128 || s.chars().any(char::is_control) {
                return invalid("vpn.external_service must be a non-empty name (<= 128 chars)");
            }
        }
        for a in &self.vpn.external_server_addresses {
            if !is_host_or_ip(a) {
                return Err(ConfigError::Invalid(format!(
                    "vpn.external_server_addresses: invalid host or IP: {a}"
                )));
            }
        }
        for n in &self.vpn.trusted_networks {
            if !is_network_id(n) {
                return Err(ConfigError::Invalid(format!(
                    "vpn.trusted_networks: invalid network id: {n}"
                )));
            }
        }
        if !(15..=24 * 60).contains(&self.guard.snapshot_interval_minutes) {
            return invalid("guard.snapshot_interval_minutes must be 15..1440");
        }
        for t in &self.guard.trusted_team_ids {
            if !is_team_id(t) {
                return Err(ConfigError::Invalid(format!(
                    "guard.trusted_team_ids: invalid Team ID: {t}"
                )));
            }
        }
        if !(5..=600).contains(&self.network.poll_seconds) {
            return invalid("network.poll_seconds must be 5..600");
        }
        let d = &self.data_removal;
        if !(1..=200).contains(&d.max_emails_per_day) {
            return invalid("data_removal.max_emails_per_day must be 1..200");
        }
        if !(7..=90).contains(&d.reminder_after_days) {
            return invalid("data_removal.reminder_after_days must be 7..90");
        }
        if !(7..=90).contains(&d.escalate_after_days) {
            return invalid("data_removal.escalate_after_days must be 7..90");
        }
        if d.repeat_every_days != 0 && !(30..=730).contains(&d.repeat_every_days) {
            return invalid("data_removal.repeat_every_days must be 0 or 30..730");
        }
        for r in &d.regions {
            if !matches!(r.as_str(), "eu" | "global" | "us") {
                return Err(ConfigError::Invalid(format!(
                    "data_removal.regions: unknown region {r} (eu, global, us)"
                )));
            }
        }
        if !matches!(d.language.as_str(), "fr" | "en") {
            return invalid("data_removal.language must be fr or en");
        }
        if d.send_mode == SendMode::Smtp {
            if d.smtp_host.trim().is_empty() || !is_host_or_ip(d.smtp_host.trim()) {
                return invalid("data_removal.smtp_host is required in smtp mode");
            }
            if d.smtp_port == 0 {
                return invalid("data_removal.smtp_port must be > 0");
            }
            if !is_email(&d.from_address) {
                return invalid("data_removal.from_address must be an email address in smtp mode");
            }
        }
        if !d.from_address.is_empty() && !is_email(&d.from_address) {
            return invalid("data_removal.from_address must be an email address");
        }
        for e in &self.breach.emails {
            if !is_email(e) {
                return Err(ConfigError::Invalid(format!(
                    "breach.emails: invalid address: {e}"
                )));
            }
        }
        if !(1..=24 * 30).contains(&self.breach.check_interval_hours) {
            return invalid("breach.check_interval_hours must be 1..720");
        }
        if !self.aliases.base_url.is_empty() && !self.aliases.base_url.starts_with("https://") {
            return invalid("aliases.base_url must use https");
        }
        Ok(())
    }
}

/// `host`, `host.domain`, IPv4 or IPv6 literal (no scheme, port or path).
pub fn is_host_or_ip(s: &str) -> bool {
    if s.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// Network fingerprint id: `gw:<router MAC, lowercase aa:bb:cc:dd:ee:ff>`.
pub fn is_network_id(s: &str) -> bool {
    let Some(mac) = s.strip_prefix("gw:") else {
        return false;
    };
    let parts: Vec<&str> = mac.split(':').collect();
    parts.len() == 6
        && parts.iter().all(|p| {
            p.len() == 2
                && p.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
}

/// Apple Developer Team ID: 10 uppercase letters / digits.
pub fn is_team_id(s: &str) -> bool {
    s.len() == 10
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Minimal email syntax check (`local@domain.tld`, no spaces / control characters / angle brackets).
pub fn is_email(s: &str) -> bool {
    let Some((local, domain)) = s.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && s.len() <= 254
        && domain.contains('.')
        && is_host_or_ip(domain)
        && !s.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ',' | ';' | '"')
        })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Files larger than this are hashed but not content-scanned.
    pub max_file_size_mb: u64,
    /// Nested archive depth (zip in dmg in zip…).
    pub archive_max_depth: u32,
    /// Max total uncompressed bytes extracted from one archive (zip-bomb guard).
    pub archive_max_total_mb: u64,
    /// Max number of entries inspected per archive.
    pub archive_max_entries: u32,
    /// Folders watched for new files (`~` = console user's home).
    pub watch_paths: Vec<String>,
    /// Never scanned (prefix match after `~` expansion).
    pub exclude_paths: Vec<String>,
    /// Run ClamAV (clamscan) for manual / volume / scheduled scans.
    pub clamav_on_demand: bool,
    /// Also run ClamAV on real-time events (batched). Costly in RAM, off by default.
    pub clamav_realtime: bool,
    /// Scan DMG contents by mounting them read-only (`hdiutil attach -readonly -nobrowse`).
    pub mount_dmg: bool,
    /// Expand PKG (`pkgutil --expand-full`) and scan scripts + payload.
    pub expand_pkg: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size_mb: 200,
            archive_max_depth: 3,
            archive_max_total_mb: 1024,
            archive_max_entries: 20_000,
            watch_paths: vec![
                "~/Downloads".into(),
                "~/Desktop".into(),
                "~/Documents".into(),
                "/Applications".into(),
                "~/Applications".into(),
            ],
            exclude_paths: vec![],
            clamav_on_demand: true,
            clamav_realtime: false,
            mount_dmg: true,
            expand_pkg: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RealtimeConfig {
    pub enabled: bool,
    /// Use Apple's `eslogger` (Endpoint Security, observe-only) for exec/create/rename/btm events.
    pub eslogger: bool,
    /// Use FSEvents on `scan.watch_paths` (works without Full Disk Access for most user folders).
    pub fsevents: bool,
    /// Automatically quarantine files whose verdict is `malicious` from a signature engine
    /// (hash DB, ClamAV, YARA rule with severity >= high). ML alone never quarantines.
    pub auto_quarantine: bool,
    /// Scan executables when they are launched (eslogger `exec`), with an in-memory cache by cdhash/sha256.
    pub scan_on_exec: bool,
    /// Without the Endpoint Security entitlement we cannot block an exec beforehand; this kills (SIGKILL)
    /// a process right after launch when its executable is `malicious` per a signature engine
    /// (never for ML-only or `suspicious` verdicts, never for Apple platform binaries).
    pub kill_malicious_processes: bool,
}

impl Default for RealtimeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            eslogger: true,
            fsevents: true,
            auto_quarantine: true,
            scan_on_exec: true,
            kill_malicious_processes: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MlConfig {
    pub enabled: bool,
    /// Score above which a Mach-O is reported as `suspicious`.
    pub suspicious_threshold: f32,
    /// Only score binaries that are unsigned, ad-hoc signed or not notarized.
    pub only_untrusted: bool,
}

impl Default for MlConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suspicious_threshold: 0.85,
            only_untrusted: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    /// Route system DNS through the local dnscrypt-proxy with the merged blocklist.
    pub enabled: bool,
    pub listen: String,
    /// dnscrypt-proxy `server_names` (public resolvers list names).
    pub upstream_servers: Vec<String>,
    pub block_malware: bool,
    pub block_ads: bool,
    pub block_trackers: bool,
    /// Extra user rules (exact domain or `*.domain`).
    pub custom_allow: Vec<String>,
    pub custom_block: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: "127.0.0.1:53".into(),
            upstream_servers: vec![
                "cloudflare".into(),
                "quad9-doh-ip4-port443-filter-pri".into(),
            ],
            block_malware: true,
            block_ads: true,
            block_trackers: true,
            custom_allow: vec![],
            custom_block: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DevicesConfig {
    /// Scan newly mounted external volumes (USB keys, disks, SD cards, DMGs).
    pub scan_volumes: bool,
    /// Alert when a new keyboard / HID device appears (BadUSB).
    pub alert_new_hid: bool,
    /// Best-effort: seize (block input of) unknown keyboards until approved in the app. Off by default.
    pub block_new_hid: bool,
    pub alert_bluetooth: bool,
    pub alert_network_interfaces: bool,
    pub alert_thunderbolt: bool,
    pub alert_wifi_networks: bool,
    /// Also alert for every *new* USB device that is not HID / storage.
    pub alert_other_usb: bool,
}

impl Default for DevicesConfig {
    fn default() -> Self {
        Self {
            scan_volumes: true,
            alert_new_hid: true,
            block_new_hid: false,
            alert_bluetooth: true,
            alert_network_interfaces: true,
            alert_thunderbolt: true,
            alert_wifi_networks: true,
            alert_other_usb: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PersistenceConfig {
    pub enabled: bool,
    /// Full re-enumeration interval (events catch most changes in between).
    pub full_scan_interval_minutes: u32,
    /// Run the osquery hunting pack (if osquery is installed) once a day.
    pub osquery_hunting: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            full_scan_interval_minutes: 360,
            osquery_hunting: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdatesConfig {
    /// Base URL of the threat-DB channel. `{latest}/manifest.json`, `{latest}/parabellum-db.tar.gz`,
    /// `{latest}/parabellum-db.tar.gz.minisig` are fetched from it.
    pub db_base_url: String,
    /// GitHub API URL used to discover app releases (`.pkg`).
    pub app_releases_api: String,
    /// Optional GitHub token (fine-grained, read-only, contents) when the repository is private.
    pub github_token: Option<String>,
    /// Hour (local time, 0-23) of the daily update run.
    pub daily_hour: u8,
    /// Automatically install updates of third-party components (ClamAV, osquery, dnscrypt-proxy, LuLu…).
    pub auto_update_components: bool,
    /// Automatically install new Parabellum releases (otherwise: notify only).
    pub auto_update_app: bool,
    /// Run `freshclam` as part of the daily update.
    pub freshclam: bool,
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self {
            db_base_url: "https://github.com/WLDEUS/Parabellum/releases/download/db-latest".into(),
            app_releases_api: "https://api.github.com/repos/WLDEUS/Parabellum/releases".into(),
            github_token: None,
            daily_hour: 3,
            auto_update_components: true,
            auto_update_app: false,
            freshclam: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnergyConfig {
    /// Defer scheduled / batch scans when on battery below this percentage (0 = never defer).
    pub pause_on_battery_below: u8,
    /// Run scans with background QoS (efficiency cores).
    pub background_qos: bool,
}

impl Default for EnergyConfig {
    fn default() -> Self {
        Self {
            pause_on_battery_below: 20,
            background_qos: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PrivacyConfig {
    /// Opt-in: look up the SHA-256 of suspicious files on VirusTotal (hash only, never the file).
    pub virustotal_lookup: bool,
    pub virustotal_api_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationsConfig {
    pub enabled: bool,
    /// Minimum severity that triggers a macOS notification.
    pub min_severity: crate::model::Severity,
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_severity: crate::model::Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Weekly mercenary-spyware check (Zero Breach Toolkit shipped in the threat DB), also run after a DB
    /// update that changes its indicators (at most daily). Deferred on low battery.
    pub spyware_scan_weekly: bool,
    /// Day of the weekly check: 1 = Monday … 7 = Sunday.
    pub spyware_scan_weekday: u8,
    /// Hour (local time, 0-23) of the weekly check.
    pub spyware_scan_hour: u8,
    /// Daily check of the macOS security settings (SIP, Gatekeeper, FileVault, firewall…), with alerts.
    pub posture_checks: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            spyware_scan_weekly: true,
            spyware_scan_weekday: 3,
            spyware_scan_hour: 13,
            posture_checks: true,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// VPN, behaviour guard, network guard, privacy (data removal, breaches, aliases)
// ---------------------------------------------------------------------------------------------

/// When the VPN must be up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VpnMode {
    /// Never connected automatically (manual `vpn_connect` still works).
    #[default]
    Off,
    /// Always connected.
    Always,
    /// Connected on every network that is not in `vpn.trusted_networks`.
    UntrustedNetworks,
}

/// Which VPN engine Parabellum drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum VpnBackend {
    /// sing-box (open source, GPL-3.0) run by the daemon with a TUN interface, from the imported profile.
    #[default]
    SingBox,
    /// A VPN already configured in macOS (Shadowrocket, WireGuard, sing-box for Apple…), driven with
    /// `scutil --nc start|stop <vpn.external_service>`.
    External,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnConfig {
    pub mode: VpnMode,
    pub backend: VpnBackend,
    /// External backend: name of the macOS VPN service (`scutil --nc list`), e.g. `Shadowrocket`.
    pub external_service: Option<String>,
    /// External backend: VPN server hosts / IPs the kill switch lets through (the sing-box backend takes
    /// them from the imported profile).
    pub external_server_addresses: Vec<String>,
    /// Network fingerprints (`gw:<router MAC>`) considered safe for `untrusted_networks` mode.
    pub trusted_networks: Vec<String>,
    /// While the VPN should be up, block every packet that does not go through the tunnel (pf anchor).
    pub kill_switch: bool,
    /// Keep the local network (printers, NAS, AirDrop, DHCP) reachable outside the tunnel.
    pub allow_lan: bool,
    /// sing-box: route IPv6 into the tunnel too (otherwise IPv6 is blocked while connected).
    pub tunnel_ipv6: bool,
    /// Automatic leak test while connected, in minutes (0 = only on demand).
    pub leak_test_interval_minutes: u32,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            mode: VpnMode::Off,
            backend: VpnBackend::SingBox,
            external_service: None,
            external_server_addresses: vec![],
            trusted_networks: vec![],
            kill_switch: false,
            allow_lan: true,
            tunnel_ipv6: true,
            leak_test_interval_minutes: 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardConfig {
    /// Info-stealer behaviour: fake password dialogs, browser / keychain / wallet credential theft,
    /// staging + exfiltration of the loot (eslogger exec / create / rename events).
    pub stealer_detection: bool,
    /// Kill the offending process on a high-confidence match (never Apple system services).
    pub kill_on_detection: bool,
    /// Team IDs allowed to read browser / keychain data on top of the DB allowlist (password managers…).
    pub trusted_team_ids: Vec<String>,
    /// Ransomware: decoy files in the watched user folders + mass "encrypt-and-rename" detection.
    pub ransomware_detection: bool,
    /// Suspend (SIGSTOP) suspected ransomware until you decide (kill or resume) instead of only alerting.
    pub suspend_ransomware: bool,
    /// Periodic APFS local snapshots of the data volume (Time Machine local snapshots, purged by macOS
    /// after about 24 h): restore points if files get encrypted.
    pub snapshots: bool,
    pub snapshot_interval_minutes: u32,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            stealer_detection: true,
            kill_on_detection: true,
            trusted_team_ids: vec![],
            ransomware_detection: true,
            suspend_ransomware: true,
            snapshots: true,
            snapshot_interval_minutes: 60,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkGuardConfig {
    /// Watch the current network: router identity change (ARP spoofing), another host claiming the
    /// router's MAC, a known Wi-Fi name now open (evil twin). Also feeds the VPN auto-connect.
    pub enabled: bool,
    /// Polling period of the routing table / ARP cache, seconds.
    pub poll_seconds: u32,
}

impl Default for NetworkGuardConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_seconds: 20,
        }
    }
}

/// How GDPR erasure requests leave the Mac.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SendMode {
    /// `.eml` drafts written to `~/Downloads/Parabellum-RGPD/`, sent by you from your mail app.
    #[default]
    Drafts,
    /// Sent by the daemon through your SMTP account (rate-limited).
    Smtp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DataRemovalConfig {
    pub enabled: bool,
    /// Broker lists: `eu` (Datenanfragen: ad-tech, address and credit brokers relevant in France / EU),
    /// `global` (international marketing data brokers), `us` (US people-search sites).
    pub regions: Vec<String>,
    pub send_mode: SendMode,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_username: String,
    /// Secret (app password); redacted over IPC.
    pub smtp_password: Option<String>,
    /// Sender address (also where brokers answer).
    pub from_address: String,
    pub max_emails_per_day: u32,
    /// Unanswered requests get a formal reminder after this many days (GDPR art. 12(3): one month).
    pub reminder_after_days: u32,
    /// Days after the reminder before a CNIL complaint is suggested.
    pub escalate_after_days: u32,
    /// Letter language: `fr` or `en` (non-French recipients always get English).
    pub language: String,
    /// Brokers re-collect data: send a new request every N days (0 = never).
    pub repeat_every_days: u32,
}

impl Default for DataRemovalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            regions: vec!["eu".into(), "global".into()],
            send_mode: SendMode::Drafts,
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: None,
            from_address: String::new(),
            max_emails_per_day: 20,
            reminder_after_days: 30,
            escalate_after_days: 15,
            language: "fr".into(),
            repeat_every_days: 180,
        }
    }
}

/// Data-breach lookup service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BreachProvider {
    /// XposedOrNot (free, no key).
    #[default]
    XposedOrNot,
    /// Have I Been Pwned (paid API key).
    Hibp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BreachConfig {
    pub enabled: bool,
    /// Addresses checked against known breaches (only the address is sent to the provider).
    pub emails: Vec<String>,
    pub provider: BreachProvider,
    /// Secret; redacted over IPC.
    pub hibp_api_key: Option<String>,
    pub check_interval_hours: u32,
}

impl Default for BreachConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            emails: vec![],
            provider: BreachProvider::XposedOrNot,
            hibp_api_key: None,
            check_interval_hours: 24 * 7,
        }
    }
}

/// Email alias service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AliasProvider {
    #[default]
    None,
    /// addy.io (open source, self-hostable).
    Addy,
    /// SimpleLogin (open source, Proton).
    SimpleLogin,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AliasConfig {
    pub provider: AliasProvider,
    /// Secret; redacted over IPC.
    pub api_key: Option<String>,
    /// Empty = the provider's public instance (`https://app.addy.io`, `https://app.simplelogin.io`);
    /// set it for a self-hosted instance.
    pub base_url: String,
    /// addy.io: alias domain (empty = account default).
    pub domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_sections_validate() {
        let c = Config::default();
        assert!(c.validate().is_ok());
        assert!(
            Config::from_toml("[vpn]\nmode = \"untrusted_networks\"\nkill_switch = true\n").is_ok()
        );
        assert!(
            Config::from_toml("[vpn]\ntrusted_networks = [\"gw:aa:bb:cc:dd:ee:ff\"]\n").is_ok()
        );
        assert!(
            Config::from_toml("[vpn]\ntrusted_networks = [\"gw:AA:bb:cc:dd:ee:ff\"]\n").is_err()
        );
        assert!(Config::from_toml("[vpn]\nexternal_server_addresses = [\"vpn.example.com\", \"203.0.113.7\", \"2001:db8::1\"]\n").is_ok());
        assert!(Config::from_toml("[vpn]\nexternal_server_addresses = [\"https://x\"]\n").is_err());
        assert!(Config::from_toml("[guard]\nsnapshot_interval_minutes = 5\n").is_err());
        assert!(Config::from_toml("[guard]\ntrusted_team_ids = [\"2BUA8C4S2C\"]\n").is_ok());
        assert!(Config::from_toml("[guard]\ntrusted_team_ids = [\"nope\"]\n").is_err());
        assert!(Config::from_toml("[network]\npoll_seconds = 1\n").is_err());
        assert!(Config::from_toml("[data_removal]\nregions = [\"eu\", \"mars\"]\n").is_err());
        assert!(Config::from_toml("[data_removal]\nsend_mode = \"smtp\"\n").is_err());
        assert!(Config::from_toml(
            "[data_removal]\nsend_mode = \"smtp\"\nsmtp_host = \"smtp.gmail.com\"\nfrom_address = \"q@example.com\"\n"
        )
        .is_ok());
        assert!(Config::from_toml("[breach]\nemails = [\"not an email\"]\n").is_err());
        assert!(Config::from_toml("[aliases]\nbase_url = \"http://addy.local\"\n").is_err());
    }

    #[test]
    fn syntax_helpers() {
        assert!(is_email("q.m+tag@sub.example.fr"));
        assert!(!is_email("q@localhost"));
        assert!(!is_email("a b@example.com"));
        assert!(!is_email("<x@example.com>"));
        assert!(is_host_or_ip("smtp.gmail.com") && is_host_or_ip("::1") && !is_host_or_ip("a..b"));
        assert!(is_team_id("EQHXZ8M8AV") && !is_team_id("eqhxz8m8av"));
        assert!(is_network_id("gw:00:11:22:aa:bb:cc") && !is_network_id("gw:00:11:22:aa:bb"));
    }

    #[test]
    fn default_roundtrip() {
        let c = Config::default();
        let s = c.to_toml().unwrap();
        assert_eq!(Config::from_toml(&s).unwrap(), c);
    }

    #[test]
    fn partial_file_uses_defaults() {
        let c = Config::from_toml("[dns]\nenabled = true\n").unwrap();
        assert!(c.dns.enabled);
        assert_eq!(c.scan, ScanConfig::default());
    }

    #[test]
    fn rejects_bad_values() {
        assert!(Config::from_toml("[ml]\nsuspicious_threshold = 3.0\n").is_err());
        assert!(Config::from_toml("[dns]\nlisten = \"203.0.113.5:53\"\n").is_err());
        assert!(Config::from_toml("[dns]\nlisten = \"0.0.0.0:53\"\n").is_err());
        assert!(Config::from_toml("[dns]\nlisten = \"[::1]:53\"\n").is_ok());
        assert!(Config::from_toml("[updates]\ndb_base_url = \"http://evil\"\n").is_err());
        assert!(Config::from_toml("[security]\nspyware_scan_weekday = 0\n").is_err());
        assert!(Config::from_toml("[security]\nspyware_scan_hour = 24\n").is_err());
        let c = Config::from_toml("[security]\nspyware_scan_weekly = false\n").unwrap();
        assert!(!c.security.spyware_scan_weekly && c.security.posture_checks);
    }

    #[test]
    fn missing_file_is_default() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(
            Config::load(&d.path().join("nope.toml")).unwrap(),
            Config::default()
        );
    }
}
