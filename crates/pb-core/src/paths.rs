//! On-disk layout.
//!
//! Production layout (root-owned, created by the installer):
//! ```text
//! /Library/Application Support/Parabellum/      (root:wheel 0755)
//!   bin/parabellumd, bin/parabellum             daemon + CLI (CLI symlinked to /usr/local/bin/parabellum)
//!   config.toml                                 (root:wheel 0600 — may hold tokens; written by the daemon only)
//!   db/current -> db/versions/<version>/        active threat-DB bundle (atomic symlink swap)
//!   db/previous -> db/versions/<version>/       kept for rollback
//!   db/versions/<version>/                      unpacked bundles (see docs/db-bundle.md)
//!   db/downloads/                               partial downloads
//!   clamav/db/                                  freshclam-managed official ClamAV signatures
//!   clamav/freshclam.conf
//!   components/                                 downloaded installers, dnscrypt-proxy binary, versions.json
//!   dns/                                        dnscrypt-proxy.toml, merged blocklist, allowlist, query log stats
//!   quarantine/                                 (root:wheel 0700) neutralised files + metadata
//!   state/parabellum.sqlite                     alerts, scan history, devices, persistence baseline, reports
//!   cache/                                      scan cache, compiled YARA rules cache
//!   tmp/                                        scratch (DMG mounts, PKG expansion), wiped at start
//! /Library/Logs/Parabellum/parabellumd.log
//! /var/run/parabellum.sock                      (root:admin 0660) IPC socket
//! ```
//! Setting `PARABELLUM_ROOT=/some/dir` relocates **everything** (logs and socket included) under that dir,
//! which is how tests and Linux development builds run unprivileged.

use std::path::{Path, PathBuf};

pub const DEFAULT_ROOT: &str = "/Library/Application Support/Parabellum";
pub const DEFAULT_LOG_DIR: &str = "/Library/Logs/Parabellum";
pub const DEFAULT_SOCKET: &str = "/var/run/parabellum.sock";
pub const APP_PATH: &str = "/Applications/Parabellum.app";
pub const CLI_LINK: &str = "/usr/local/bin/parabellum";
pub const LAUNCH_DAEMON_PLIST: &str = "/Library/LaunchDaemons/com.wldeus.parabellum.daemon.plist";
pub const LAUNCH_AGENT_PLIST: &str = "/Library/LaunchAgents/com.wldeus.parabellum.ui.plist";
/// Env var overriding the root directory (tests / dev).
pub const ROOT_ENV: &str = "PARABELLUM_ROOT";
/// Env var overriding only the socket path (lets the app/CLI talk to a dev daemon).
pub const SOCKET_ENV: &str = "PARABELLUM_SOCKET";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub root: PathBuf,
    pub log_dir: PathBuf,
    pub socket: PathBuf,
}

impl Paths {
    /// Production paths, unless `PARABELLUM_ROOT` / `PARABELLUM_SOCKET` are set.
    pub fn system() -> Self {
        let mut p = match std::env::var_os(ROOT_ENV) {
            Some(r) if !r.is_empty() => Self::with_root(PathBuf::from(r)),
            _ => Self {
                root: PathBuf::from(DEFAULT_ROOT),
                log_dir: PathBuf::from(DEFAULT_LOG_DIR),
                socket: PathBuf::from(DEFAULT_SOCKET),
            },
        };
        if let Some(s) = std::env::var_os(SOCKET_ENV) {
            if !s.is_empty() {
                p.socket = PathBuf::from(s);
            }
        }
        p
    }

    /// Everything relocated under `root` (logs in `root/logs`, socket at `root/run/parabellum.sock`).
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            log_dir: root.join("logs"),
            socket: root.join("run").join("parabellum.sock"),
            root,
        }
    }

    pub fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }
    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.toml")
    }
    pub fn db_dir(&self) -> PathBuf {
        self.root.join("db")
    }
    /// Symlink to the active bundle directory.
    pub fn db_current(&self) -> PathBuf {
        self.db_dir().join("current")
    }
    /// Symlink to the previous bundle directory (rollback target).
    pub fn db_previous(&self) -> PathBuf {
        self.db_dir().join("previous")
    }
    pub fn db_versions_dir(&self) -> PathBuf {
        self.db_dir().join("versions")
    }
    pub fn db_downloads_dir(&self) -> PathBuf {
        self.db_dir().join("downloads")
    }
    pub fn clamav_dir(&self) -> PathBuf {
        self.root.join("clamav")
    }
    pub fn clamav_db_dir(&self) -> PathBuf {
        self.clamav_dir().join("db")
    }
    pub fn components_dir(&self) -> PathBuf {
        self.root.join("components")
    }
    pub fn dns_dir(&self) -> PathBuf {
        self.root.join("dns")
    }
    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }
    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }
    pub fn state_db(&self) -> PathBuf {
        self.state_dir().join("parabellum.sqlite")
    }
    pub fn cache_dir(&self) -> PathBuf {
        self.root.join("cache")
    }
    pub fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }
    pub fn log_file(&self) -> PathBuf {
        self.log_dir.join("parabellumd.log")
    }

    /// All directories the daemon must create at startup (permissions are the daemon's job).
    pub fn all_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.root.clone(),
            self.bin_dir(),
            self.db_dir(),
            self.db_versions_dir(),
            self.db_downloads_dir(),
            self.clamav_dir(),
            self.clamav_db_dir(),
            self.components_dir(),
            self.dns_dir(),
            self.quarantine_dir(),
            self.state_dir(),
            self.cache_dir(),
            self.tmp_dir(),
            self.log_dir.clone(),
            self.socket
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| self.root.clone()),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_root_relocates_everything() {
        let p = Paths::with_root("/tmp/pb");
        assert_eq!(p.db_current(), Path::new("/tmp/pb/db/current"));
        assert_eq!(p.socket, Path::new("/tmp/pb/run/parabellum.sock"));
        assert_eq!(p.log_file(), Path::new("/tmp/pb/logs/parabellumd.log"));
        assert!(p.all_dirs().iter().all(|d| d.starts_with("/tmp/pb")));
    }
}
