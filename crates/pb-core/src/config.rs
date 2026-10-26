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
        if self.energy.pause_on_battery_below > 100 {
            return Err(ConfigError::Invalid(
                "energy.pause_on_battery_below must be 0..100".into(),
            ));
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
