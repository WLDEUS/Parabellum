//! VPN, kill switch, leak tests and network guard for Parabellum.
//!
//! - Backends ([`pb_core::config::VpnBackend`]):
//!   - `sing_box`: the daemon runs the pinned sing-box binary (TUN inbound, `auto_route`) with a config generated
//!     from the imported profile (share link or WireGuard `.conf`), server hostnames pre-resolved to IPs;
//!   - `external`: a VPN already configured in macOS (Shadowrocket, WireGuard app…) driven with
//!     `scutil --nc start|stop|status <name>`.
//! - Kill switch: pf rules in the `com.apple/250.Parabellum` anchor (evaluated by the stock `/etc/pf.conf`),
//!   pf enabled with a reference token (`pfctl -E` / `pfctl -X`), never touching `/etc/pf.conf`.
//! - Leak test: public IPv4/IPv6 through the default route vs. the network's "home" IP, system DNS servers,
//!   kill-switch state.
//! - Network guard: network fingerprint `gw:<router MAC>` (no Location permission needed), router MAC change
//!   while on the same network (ARP spoofing), another IP claiming the router's MAC, a known Wi-Fi name that is
//!   now open (evil twin); drives the `untrusted_networks` VPN mode.
//!
//! Daemon integration (`pb-daemon/src/vpn.rs`):
//! ```text
//! let vpn = VpnService::new(paths.clone(), hooks);      // hooks: status push, alerts, sing-box install, config save
//! vpn.recover_on_startup().await;
//! tokio::spawn(vpn.clone().run(config_rx, shutdown_rx));
//! // IPC: vpn.status() / connect() / disconnect() / import_profile() / remove_profile() / leak_test() /
//! //      list_services() / networks() / set_network_trust()
//! // SIGTERM: vpn.shutdown().await  (stops sing-box, removes the kill switch: fail open)
//! ```
//! Pure parsers / generators are unit-tested on Linux; system calls are macOS-only (no-ops or
//! `VpnError::Unavailable` elsewhere).

pub mod fsutil;
pub mod killswitch;
pub mod leak;
pub mod netguard;
pub mod netprobe;
pub mod profile;
pub mod runner;
pub mod scutil;
mod service;
pub mod singbox;
pub mod store;
pub mod sys;
#[cfg(test)]
pub(crate) mod testutil;

use async_trait::async_trait;
use pb_core::config::Config;
use pb_core::model::{
    ExternalVpnService, LeakTestResult, NetworkInfo, Severity, VpnProfileInfo, VpnStatus,
};
use pb_core::paths::Paths;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;

use service::Runtime;

/// Errors returned to the daemon (mapped onto IPC error codes).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VpnError {
    /// Bad input (unparsable profile, unknown network…).
    #[error("{0}")]
    Invalid(String),
    /// Missing piece (no profile, sing-box not installed, not macOS…).
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Failed(String),
}

/// Alert raised by the VPN service / network guard. The daemon stores it (kind `network`) and
/// deduplicates on `key` for 24 h.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetAlert {
    pub severity: Severity,
    pub title: String,
    pub message: String,
    /// Network involved (`gw:<router MAC>`).
    pub network_id: Option<String>,
    /// Dedupe key, e.g. `arp-spoof:gw:aa:…`.
    pub key: String,
    /// Offer the "trust this network" action.
    pub offer_trust: bool,
}

/// What the service needs from the daemon.
#[async_trait]
pub trait VpnHooks: Send + Sync + 'static {
    /// Status changed: push it to subscribed clients.
    fn status_changed(&self, status: &VpnStatus);
    /// Raise an alert.
    fn alert(&self, alert: NetAlert);
    /// Install (if needed) the pinned sing-box component and return the binary path.
    async fn ensure_singbox(&self) -> Result<PathBuf, VpnError>;
    /// Persist `vpn.trusted_networks` (the daemon validates, saves and republishes the config).
    async fn save_trusted_networks(&self, ids: Vec<String>) -> Result<(), VpnError>;
}

/// Remove a kill switch left by a previous run (crash, SIGKILL, power loss). Call it first thing at daemon
/// startup, once the single-instance lock is held, so no later startup step can leave the Mac offline.
pub async fn recover_kill_switch(paths: &Paths) {
    let sys: Arc<dyn sys::System> = Arc::new(sys::RealSystem::new());
    killswitch::KillSwitch::new(sys, &paths.vpn_dir())
        .recover()
        .await;
}

/// Last-resort synchronous flush of the kill-switch anchor, for startup failures before the async runtime
/// exists (best effort; the pf reference token, if any, is released by the next successful start).
pub fn flush_kill_switch_blocking() {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new(sys::PFCTL)
            .args(["-a", killswitch::ANCHOR, "-F", "all"])
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Conventional location of the managed sing-box binary (`components/sing-box/sing-box`), shared with the
/// component manager.
pub fn singbox_binary(paths: &Paths) -> PathBuf {
    paths.components_dir().join("sing-box").join("sing-box")
}

/// The VPN / kill switch / network guard service. Cheap to share (`Arc`).
pub struct VpnService {
    paths: Paths,
    hooks: Arc<dyn VpnHooks>,
    sys: Arc<dyn sys::System>,
    dir: PathBuf,
    cfg: std::sync::Mutex<Arc<Config>>,
    status: std::sync::Mutex<VpnStatus>,
    rt: tokio::sync::Mutex<Runtime>,
    wake: tokio::sync::Notify,
    killswitch: killswitch::KillSwitch,
}

impl VpnService {
    /// State lives in `paths.vpn_dir()` (root-only): `profile.json` (secrets), `sing-box.json`,
    /// `networks.json` (fingerprints, home IPs), `killswitch.json` (pf token).
    pub fn new(paths: Paths, hooks: Arc<dyn VpnHooks>) -> Arc<Self> {
        Self::with_system(paths, hooks, Arc::new(sys::RealSystem::new()))
    }

    /// Same with an injected [`sys::System`] (tests).
    pub fn with_system(
        paths: Paths,
        hooks: Arc<dyn VpnHooks>,
        sys: Arc<dyn sys::System>,
    ) -> Arc<Self> {
        let dir = paths.vpn_dir();
        Arc::new(Self {
            killswitch: killswitch::KillSwitch::new(sys.clone(), &dir),
            rt: tokio::sync::Mutex::new(Runtime::new(sys.clone(), &dir)),
            paths,
            hooks,
            sys,
            dir,
            cfg: std::sync::Mutex::new(Arc::new(Config::default())),
            status: std::sync::Mutex::new(VpnStatus::default()),
            wake: tokio::sync::Notify::new(),
        })
    }

    /// Crash recovery: a kill switch or sing-box left by a previous run is removed / stopped (the main loop
    /// re-applies what the configuration wants).
    pub async fn recover_on_startup(&self) {
        self.recover().await
    }

    /// Main loop until shutdown: follows the configuration, network changes (polling every
    /// `network.poll_seconds`), tunnel health (restart with backoff), periodic leak tests, kill switch, network
    /// guard alerts. Takes the tunnel down and removes the kill switch before returning.
    pub async fn run(
        self: Arc<Self>,
        config: watch::Receiver<Arc<Config>>,
        shutdown: watch::Receiver<bool>,
    ) {
        self.run_loop(config, shutdown).await
    }

    pub async fn status(&self) -> VpnStatus {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Manual connect (override until `disconnect`).
    pub async fn connect(&self) -> Result<VpnStatus, VpnError> {
        self.do_connect().await
    }

    /// Manual disconnect (override until the next network change).
    pub async fn disconnect(&self) -> Result<VpnStatus, VpnError> {
        self.do_disconnect().await
    }

    /// Parse and store a profile (share link or WireGuard `.conf`), replacing the previous one.
    pub async fn import_profile(&self, text: &str) -> Result<VpnProfileInfo, VpnError> {
        self.do_import(text).await
    }

    pub async fn remove_profile(&self) -> Result<(), VpnError> {
        self.do_remove_profile().await
    }

    /// Leak test now (rate-limited to one every 15 s; returns the last result inside that window).
    pub async fn leak_test(&self) -> Result<LeakTestResult, VpnError> {
        self.do_leak_test(false).await
    }

    /// `scutil --nc list`.
    pub async fn list_services(&self) -> Vec<ExternalVpnService> {
        scutil::list(self.sys.as_ref()).await
    }

    /// Networks seen, current first.
    pub async fn networks(&self) -> Vec<NetworkInfo> {
        let cfg = self.cfg();
        let rt = self.rt.lock().await;
        rt.networks
            .list(&cfg.vpn.trusted_networks, rt.current_network.as_deref())
    }

    /// Trust / untrust a network (saved through [`VpnHooks::save_trusted_networks`]).
    pub async fn set_network_trust(
        &self,
        id: &str,
        trusted: bool,
    ) -> Result<NetworkInfo, VpnError> {
        self.do_set_trust(id, trusted).await
    }

    /// Daemon stop: stop sing-box, remove the kill switch (fail open), restore anything changed.
    pub async fn shutdown(&self) {
        self.do_shutdown().await
    }

    fn cfg(&self) -> Arc<Config> {
        self.cfg.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}
