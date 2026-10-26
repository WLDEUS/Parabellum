//! System-wide DNS blocking for Parabellum.
//!
//! - [`DnsManager`]: merges the threat-DB lists (`dns/{malware,ads,trackers}.txt`, `dns/allowlist.txt`) with
//!   the user's custom rules into dnscrypt-proxy name files, writes `dns/dnscrypt-proxy.toml`, switches the
//!   macOS system DNS to the local proxy (originals saved first in `dns/saved-dns.json`) and restores it.
//! - [`DnsSupervisor`]: runs and health-checks dnscrypt-proxy, **fails open** (restores the original DNS)
//!   when it stops answering, re-applies when healthy, follows network-service changes.
//!
//! Daemon integration:
//! ```text
//! let dns = Arc::new(DnsManager::new(paths.clone()));
//! dns.recover_on_startup(&config.dns).await?;              // crash safety (also done by the supervisor)
//! tokio::spawn(DnsSupervisor::new(dns.clone()).run(config_rx, shutdown_rx));
//! // IPC SetDns{enabled}: save config.dns.enabled, push it on config_tx, then
//! //   enabled  → dns.enable(&cfg.dns).await   (prepares files; switches now if the proxy already answers)
//! //   disabled → dns.disable().await          (restores the system DNS)
//! // After a threat-DB update: spawn_blocking(|| dns.rebuild_lists(&cfg.dns, Some(&paths.db_current())))
//! //   (the supervisor restarts dnscrypt-proxy to load the new lists).
//! // SIGTERM: dns.restore_system_dns().await (keeps dns.enabled, the next start re-applies), then shutdown_tx.
//! ```
//! On non-macOS platforms the system-DNS backend is a no-op (state files are still maintained).

mod fsutil;
pub mod lists;
mod manager;
pub mod packet;
mod pidfile;
mod process;
pub mod proxy_config;
pub mod querylog;
mod supervisor;
pub mod system;
pub mod trust;

pub use manager::{our_servers, DnsManager, ListsState, PROXY_USER};
pub use supervisor::DnsSupervisor;
pub use system::{SavedDns, SAVED_DNS_VERSION};

use pb_core::paths::Paths;
use std::path::PathBuf;

/// `dns/blocked-names.txt`
pub const BLOCKED_NAMES_FILE: &str = "blocked-names.txt";
/// `dns/allowed-names.txt`
pub const ALLOWED_NAMES_FILE: &str = "allowed-names.txt";
/// `dns/dnscrypt-proxy.toml`
pub const PROXY_CONFIG_FILE: &str = "dnscrypt-proxy.toml";
/// `dns/saved-dns.json` (original DNS servers; read by the uninstall script too).
pub const SAVED_DNS_FILE: &str = "saved-dns.json";
/// `dns/lists-state.json`
pub const LISTS_STATE_FILE: &str = "lists-state.json";
/// `dns/runtime/`: owned by the proxy's unprivileged user (logs, resolver-list cache).
pub const RUNTIME_DIR: &str = "runtime";
/// `dns/dnscrypt-proxy.pid`: pid of the supervised proxy (root-owned dir, used to kill a stale proxy).
pub const PIDFILE: &str = "dnscrypt-proxy.pid";
/// Blocked-queries log (LTSV) inside [`RUNTIME_DIR`], rotated by dnscrypt-proxy.
pub const BLOCKED_LOG_FILE: &str = "blocked.log";

/// The managed dnscrypt-proxy binary (installed by pb-updater): `components/dnscrypt-proxy/dnscrypt-proxy`.
pub fn proxy_binary(paths: &Paths) -> PathBuf {
    paths
        .components_dir()
        .join("dnscrypt-proxy")
        .join("dnscrypt-proxy")
}

/// Errors of DNS operations (messages are user-facing, in French).
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("configuration DNS invalide : {0}")]
    Config(String),
    #[error("dnscrypt-proxy n'est pas installé (composant « dnscrypt-proxy »)")]
    ProxyMissing,
    #[error("binaire non fiable pour root (modifiable par un utilisateur) : {0}")]
    Untrusted(String),
    #[error("commande échouée : {0}")]
    Command(String),
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),
}
