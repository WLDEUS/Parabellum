//! [`VpnService`] orchestration: one reconciliation step ([`VpnService::tick`]) run by the main loop and by
//! the IPC operations, serialized by the runtime mutex.
//!
//! Desired state: `wanted` = manual override (connect → on until disconnect; disconnect → off until the network
//! changes) else the mode (`off`, `always`, `untrusted_networks` → on unless the current network is trusted;
//! an unknown / missing network counts as untrusted so a kill switch never opens while classifying).

use crate::killswitch::{render_rules, KillSwitchRules};
use crate::leak::{self, LeakInputs};
use crate::netprobe::{self, NetworkSnapshot};
use crate::profile::{self, VpnProfile};
use crate::runner::{RunnerState, SingBoxRunner};
use crate::singbox::{build_config, SingBoxOptions};
use crate::store::NetworksFile;
use crate::sys::System;
use crate::{fsutil, netguard, scutil, NetAlert, VpnError, VpnService};
use pb_core::config::{Config, VpnBackend, VpnMode};
use pb_core::model::{
    KillSwitchState, LeakTestResult, NetworkInfo, Severity, VpnProfileInfo, VpnState, VpnStatus,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;

pub const PROFILE_FILE: &str = "profile.json";
/// First arming of the kill switch: the tunnel must come up within this delay, else the rules are removed.
pub const FIRST_ARM_TIMEOUT: Duration = Duration::from_secs(45);
/// An external VPN that is not connected after this long is reported as failing.
pub const EXTERNAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Leak tests requested more often than this return the previous result.
pub const LEAK_MIN_INTERVAL: Duration = Duration::from_secs(15);
/// Public IP of a network without VPN is refreshed at most this often.
pub const HOME_IP_INTERVAL: i64 = 6 * 3600;
/// `networks.json` is rewritten for a mere `last_seen` refresh at most this often.
const NETWORKS_SAVE_INTERVAL: Duration = Duration::from_secs(600);
const BACKOFF_MIN: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(120);
/// Cached `utun*` list lifetime.
const UTUN_CACHE: Duration = Duration::from_secs(30);
/// End-to-end checks through the tunnel: the daemon's own HTTPS requests are routed into the TUN by
/// sing-box (`auto_route` + `strict_route`), so a success proves the server carries traffic. A captive
/// portal fails the TLS handshake.
pub const TUNNEL_CHECK_URLS: [&str; 2] = [
    "https://cp.cloudflare.com/generate_204",
    "https://captive.apple.com/hotspot-detect.html",
];
const TUNNEL_CHECK_TIMEOUT: Duration = Duration::from_secs(4);
/// Spacing of the checks while the tunnel is being verified.
const TUNNEL_VERIFY_EVERY: Duration = Duration::from_secs(3);
/// sing-box up (TUN created) but no traffic through it after this long: wrong credentials, server down or
/// unreachable network. The attempt fails (backoff) and the kill switch first-arm timeout applies.
pub const TUNNEL_VERIFY_TIMEOUT: Duration = Duration::from_secs(30);
/// Health check of an established tunnel.
const HEALTH_INTERVAL: Duration = Duration::from_secs(60);
/// Consecutive failed health checks before the tunnel is restarted.
const HEALTH_MAX_FAILURES: u32 = 3;
/// sing-box exiting this many times in a row (never carrying traffic in between) is a local problem — a
/// configuration rejected after an update, a broken binary — not a hostile network: the kill switch is
/// released so the Mac (and the daemon's own updater) keep Internet access.
pub const ENGINE_FAILURE_LIMIT: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Latch {
    /// The tunnel did not come up after the first arming: retried once it connects.
    FirstArmTimeout,
    /// pf refused the rules: retried after a configuration change or a manual connect.
    PfFailed,
    /// sing-box keeps exiting: released until the tunnel works again or a manual connect.
    EngineFailing,
}

/// Mutable state of the service (guarded by a tokio mutex).
pub struct Runtime {
    state: VpnState,
    message: Option<String>,
    connected_since: Option<i64>,
    interface: Option<String>,
    manual_override: Option<bool>,
    override_network: Option<String>,
    wanted: bool,
    running_backend: Option<VpnBackend>,
    runner: SingBoxRunner,
    profile: Option<VpnProfile>,
    profile_loaded: bool,
    server_ips: Vec<IpAddr>,
    resolve_cache: HashMap<String, Vec<IpAddr>>,
    engine_path: Option<PathBuf>,
    backoff: Duration,
    next_attempt: Option<Instant>,
    external_started: Option<Instant>,
    ks_state: KillSwitchState,
    ks_first_deadline: Option<Instant>,
    ks_ever_armed: bool,
    ks_latch: Option<Latch>,
    ks_blocking_alerted: bool,
    /// Last end-to-end check while the tunnel is being verified.
    verify_probe: Option<Instant>,
    /// Last health check of the established tunnel and consecutive failures.
    health_checked: Option<Instant>,
    health_failures: u32,
    /// Consecutive sing-box exits / start failures since the tunnel last carried traffic.
    engine_failures: u32,
    utuns: Option<(Instant, Vec<String>)>,
    pub(crate) networks: NetworksFile,
    networks_saved: Option<Instant>,
    last_snapshot: Option<NetworkSnapshot>,
    pub(crate) current_network: Option<String>,
    last_probe: Option<Instant>,
    last_leak: Option<LeakTestResult>,
    last_leak_at: Option<Instant>,
    last_auto_leak: Option<Instant>,
    loaded: bool,
}

impl Runtime {
    pub(crate) fn new(sys: Arc<dyn System>, dir: &Path) -> Self {
        Self {
            state: VpnState::Disconnected,
            message: None,
            connected_since: None,
            interface: None,
            manual_override: None,
            override_network: None,
            wanted: false,
            running_backend: None,
            runner: SingBoxRunner::new(sys, dir),
            profile: None,
            profile_loaded: false,
            server_ips: vec![],
            resolve_cache: HashMap::new(),
            engine_path: None,
            backoff: BACKOFF_MIN,
            next_attempt: None,
            external_started: None,
            ks_state: KillSwitchState::Off,
            ks_first_deadline: None,
            ks_ever_armed: false,
            ks_latch: None,
            ks_blocking_alerted: false,
            verify_probe: None,
            health_checked: None,
            health_failures: 0,
            engine_failures: 0,
            utuns: None,
            networks: NetworksFile::default(),
            networks_saved: None,
            last_snapshot: None,
            current_network: None,
            last_probe: None,
            last_leak: None,
            last_leak_at: None,
            last_auto_leak: None,
            loaded: false,
        }
    }
}

fn now_ts() -> i64 {
    pb_core::now_ts()
}

impl VpnService {
    fn set_cfg(&self, cfg: Arc<Config>) {
        *self.cfg.lock().unwrap_or_else(|e| e.into_inner()) = cfg;
    }

    fn profile_path(&self) -> PathBuf {
        self.dir.join(PROFILE_FILE)
    }

    fn ensure_loaded(&self, rt: &mut Runtime) {
        if rt.loaded {
            return;
        }
        rt.loaded = true;
        rt.networks = NetworksFile::load(&self.dir);
        self.load_profile(rt);
    }

    fn load_profile(&self, rt: &mut Runtime) {
        if rt.profile_loaded {
            return;
        }
        rt.profile_loaded = true;
        rt.profile = match fsutil::read_json::<VpnProfile>(&self.profile_path()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "VPN profile unreadable");
                None
            }
        };
    }

    pub(crate) async fn recover(&self) {
        let mut rt = self.rt.lock().await;
        self.ensure_loaded(&mut rt);
        self.killswitch.recover().await;
        rt.runner.recover_stale().await;
    }

    pub(crate) async fn run_loop(
        self: Arc<Self>,
        mut config: watch::Receiver<Arc<Config>>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let first = config.borrow_and_update().clone();
        self.set_cfg(first);
        self.tick().await;
        loop {
            let delay = self.next_delay().await;
            tokio::select! {
                r = shutdown.changed() => {
                    if r.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
                r = config.changed() => {
                    if r.is_err() {
                        break;
                    }
                    let new = config.borrow_and_update().clone();
                    let old = self.cfg();
                    self.set_cfg(new.clone());
                    self.on_config_change(&old, &new).await;
                }
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(delay) => {}
            }
            self.tick().await;
        }
        self.do_shutdown().await;
    }

    async fn next_delay(&self) -> Duration {
        let cfg = self.cfg();
        let rt = self.rt.lock().await;
        let poll = Duration::from_secs(u64::from(cfg.network.poll_seconds.clamp(5, 600)));
        if matches!(rt.state, VpnState::Connecting | VpnState::Disconnecting) {
            return Duration::from_secs(1);
        }
        if rt.running_backend.is_some() || self.killswitch.is_applied() {
            return Duration::from_secs(5).min(poll);
        }
        if let Some(t) = rt.next_attempt {
            let d = t.saturating_duration_since(Instant::now());
            return d.clamp(Duration::from_secs(1), poll);
        }
        poll
    }

    async fn on_config_change(&self, old: &Config, new: &Config) {
        let mut rt = self.rt.lock().await;
        if old.vpn != new.vpn {
            rt.ks_latch = None;
            rt.next_attempt = None;
            rt.backoff = BACKOFF_MIN;
            if old.vpn.mode != new.vpn.mode {
                rt.manual_override = None;
                rt.override_network = None;
            }
        }
        let singbox_inputs_changed = old.vpn.allow_lan != new.vpn.allow_lan
            || old.vpn.tunnel_ipv6 != new.vpn.tunnel_ipv6
            || old.dns.enabled != new.dns.enabled
            || old.dns.listen != new.dns.listen;
        if rt.running_backend == Some(VpnBackend::SingBox) && singbox_inputs_changed {
            tracing::info!("sing-box settings changed: restarting the tunnel");
            rt.runner.stop().await;
            rt.running_backend = None;
            rt.state = VpnState::Disconnected;
            rt.interface = None;
        }
        if old.vpn.external_server_addresses != new.vpn.external_server_addresses
            && rt.running_backend == Some(VpnBackend::External)
        {
            rt.server_ips = self
                .resolve_all(&mut rt, &new.vpn.external_server_addresses)
                .await;
        }
    }

    /// One reconciliation step.
    pub(crate) async fn tick(&self) {
        let cfg = self.cfg();
        let mut rt = self.rt.lock().await;
        self.ensure_loaded(&mut rt);
        self.maybe_probe_network(&mut rt, &cfg).await;
        self.reconcile_tunnel(&mut rt, &cfg).await;
        self.reconcile_killswitch(&mut rt, &cfg).await;
        self.maybe_auto_leak_test(&mut rt, &cfg).await;
        self.maybe_refresh_home_ip(&mut rt, &cfg).await;
        self.publish(&rt, &cfg);
    }

    // -----------------------------------------------------------------------------------------
    // Network
    // -----------------------------------------------------------------------------------------

    async fn maybe_probe_network(&self, rt: &mut Runtime, cfg: &Config) {
        let needed = cfg.network.enabled
            || cfg.vpn.mode != VpnMode::Off
            || rt.manual_override.is_some()
            || cfg.vpn.kill_switch;
        if !needed || !self.sys.is_macos() {
            return;
        }
        let poll = Duration::from_secs(u64::from(cfg.network.poll_seconds.clamp(5, 600)));
        if rt.last_probe.map(|t| t.elapsed() < poll).unwrap_or(false) {
            return;
        }
        rt.last_probe = Some(Instant::now());
        let snap = netprobe::probe(self.sys.as_ref()).await;
        self.apply_snapshot(rt, cfg, snap);
    }

    /// Record a probe result: guard alerts, networks store, network change handling.
    pub(crate) fn apply_snapshot(
        &self,
        rt: &mut Runtime,
        cfg: &Config,
        snap: Option<NetworkSnapshot>,
    ) {
        let now = now_ts();
        let Some(s) = snap else {
            rt.last_snapshot = None;
            if rt.current_network.take().is_some() {
                tracing::info!("network lost");
            }
            return;
        };
        if cfg.network.enabled {
            for a in netguard::detect(rt.last_snapshot.as_ref(), &s, &rt.networks.networks) {
                tracing::warn!(key = %a.key, "network guard alert");
                self.hooks.alert(a);
            }
        }
        let before = rt.networks.clone();
        let id = rt.networks.record(&s, now);
        let structural_change = {
            let strip = |f: &NetworksFile| {
                f.networks
                    .iter()
                    .map(|n| {
                        (
                            n.id.clone(),
                            n.name.clone(),
                            n.security.clone(),
                            n.ssid.clone(),
                        )
                    })
                    .collect::<Vec<_>>()
            };
            strip(&before) != strip(&rt.networks)
        };
        let save_due = rt
            .networks_saved
            .map(|t| t.elapsed() >= NETWORKS_SAVE_INTERVAL)
            .unwrap_or(true);
        if structural_change || save_due {
            match rt.networks.save(&self.dir) {
                Ok(()) => rt.networks_saved = Some(Instant::now()),
                Err(e) => tracing::warn!(error = %e, "cannot save networks.json"),
            }
        }
        rt.last_snapshot = Some(s);
        if id != rt.current_network {
            tracing::info!(network = ?id, "network changed");
            if rt.manual_override == Some(false) && rt.override_network != id {
                rt.manual_override = None;
                rt.override_network = None;
            }
            rt.current_network = id;
            rt.next_attempt = None;
            rt.backoff = BACKOFF_MIN;
        }
    }

    fn compute_wanted(rt: &Runtime, cfg: &Config) -> bool {
        if let Some(o) = rt.manual_override {
            return o;
        }
        match cfg.vpn.mode {
            VpnMode::Off => false,
            VpnMode::Always => true,
            VpnMode::UntrustedNetworks => match &rt.current_network {
                Some(id) => !cfg.vpn.trusted_networks.iter().any(|t| t == id),
                None => true,
            },
        }
    }

    // -----------------------------------------------------------------------------------------
    // Tunnel
    // -----------------------------------------------------------------------------------------

    async fn resolve_all(&self, rt: &mut Runtime, hosts: &[String]) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for h in hosts {
            let ips = match self.sys.resolve(h).await {
                Ok(ips) => {
                    rt.resolve_cache.insert(h.clone(), ips.clone());
                    ips
                }
                Err(e) => {
                    tracing::warn!(host = %h, error = %e, "cannot resolve VPN server");
                    rt.resolve_cache.get(h).cloned().unwrap_or_default()
                }
            };
            for ip in ips {
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
        out
    }

    fn fail(&self, rt: &mut Runtime, msg: String) {
        let was = rt.state;
        tracing::warn!(error = %msg, "VPN connection failed");
        if was != VpnState::Error {
            self.hooks.alert(NetAlert {
                severity: Severity::Medium,
                title: "Connexion VPN impossible".into(),
                message: msg.clone(),
                network_id: rt.current_network.clone(),
                key: "vpn-error".into(),
                offer_trust: false,
            });
        }
        rt.state = VpnState::Error;
        rt.message = Some(msg);
        rt.connected_since = None;
        rt.interface = None;
        rt.next_attempt = Some(Instant::now() + rt.backoff);
        rt.backoff = (rt.backoff * 2).min(BACKOFF_MAX);
    }

    fn connected(&self, rt: &mut Runtime, interface: Option<String>) {
        if rt.state != VpnState::Connected {
            tracing::info!(interface = ?interface, "VPN connected");
            rt.connected_since = Some(now_ts());
        }
        rt.state = VpnState::Connected;
        rt.interface = interface;
        rt.message = None;
        rt.backoff = BACKOFF_MIN;
        rt.next_attempt = None;
        rt.engine_failures = 0;
        if matches!(
            rt.ks_latch,
            Some(Latch::FirstArmTimeout) | Some(Latch::EngineFailing)
        ) {
            rt.ks_latch = None;
        }
    }

    async fn tunnel_works(&self) -> bool {
        for url in TUNNEL_CHECK_URLS {
            if self.sys.http_get(url, TUNNEL_CHECK_TIMEOUT).await.is_ok() {
                return true;
            }
        }
        false
    }

    /// sing-box runs and its TUN exists: declare the tunnel connected only once traffic actually goes
    /// through it, then keep checking it.
    async fn on_singbox_running(&self, rt: &mut Runtime, interface: String) {
        if !self.sys.is_macos() {
            self.connected(rt, Some(interface));
            return;
        }
        if rt.state == VpnState::Connected {
            rt.interface = Some(interface);
            let due = rt
                .health_checked
                .map(|t| t.elapsed() >= HEALTH_INTERVAL)
                .unwrap_or(true);
            if !due {
                return;
            }
            rt.health_checked = Some(Instant::now());
            if self.tunnel_works().await {
                rt.health_failures = 0;
                return;
            }
            rt.health_failures += 1;
            tracing::warn!(failures = rt.health_failures, "VPN health check failed");
            if rt.health_failures >= HEALTH_MAX_FAILURES {
                rt.health_failures = 0;
                rt.runner.stop().await;
                self.dropped(rt, "le tunnel ne laisse plus passer de trafic".into());
            }
            return;
        }
        rt.state = VpnState::Connecting;
        rt.interface = Some(interface);
        let due = rt
            .verify_probe
            .map(|t| t.elapsed() >= TUNNEL_VERIFY_EVERY)
            .unwrap_or(true);
        if due {
            rt.verify_probe = Some(Instant::now());
            if self.tunnel_works().await {
                rt.verify_probe = None;
                rt.health_checked = Some(Instant::now());
                rt.health_failures = 0;
                let iface = rt.interface.clone();
                self.connected(rt, iface);
                return;
            }
        }
        if rt
            .runner
            .running_for()
            .map(|d| d > TUNNEL_VERIFY_TIMEOUT)
            .unwrap_or(false)
        {
            let tail = crate::runner::log_tail(&self.dir, 3);
            rt.runner.stop().await;
            rt.verify_probe = None;
            rt.running_backend = None;
            let detail = if tail.is_empty() {
                String::new()
            } else {
                format!(" : {tail}")
            };
            self.fail(
                rt,
                format!(
                    "le serveur VPN ne répond pas (aucun trafic à travers le tunnel en {} s){detail}",
                    TUNNEL_VERIFY_TIMEOUT.as_secs()
                ),
            );
        }
    }

    fn dropped(&self, rt: &mut Runtime, msg: String) {
        let was_connected = rt.state == VpnState::Connected;
        rt.running_backend = None;
        if was_connected {
            self.hooks.alert(NetAlert {
                severity: Severity::Medium,
                title: "Tunnel VPN interrompu".into(),
                message: format!("{msg}. Reconnexion automatique en cours."),
                network_id: rt.current_network.clone(),
                key: "vpn-drop".into(),
                offer_trust: false,
            });
            rt.state = VpnState::Connecting;
            rt.message = Some(msg);
            rt.connected_since = None;
            rt.interface = None;
            rt.next_attempt = Some(Instant::now() + BACKOFF_MIN);
        } else {
            self.fail(rt, msg);
        }
    }

    async fn reconcile_tunnel(&self, rt: &mut Runtime, cfg: &Config) {
        let wanted = Self::compute_wanted(rt, cfg);
        rt.wanted = wanted;
        let backend = cfg.vpn.backend;
        if let Some(rb) = rt.running_backend {
            if rb != backend || !wanted {
                self.stop_tunnel(rt).await;
            }
        }
        if !wanted {
            if rt.running_backend.is_none() {
                rt.state = VpnState::Disconnected;
                rt.message = None;
                rt.connected_since = None;
                rt.interface = None;
                rt.next_attempt = None;
                rt.backoff = BACKOFF_MIN;
            }
            return;
        }
        if rt.running_backend.is_none() {
            if rt.next_attempt.map(|t| Instant::now() < t).unwrap_or(false) {
                return;
            }
            match self.start_tunnel(rt, cfg).await {
                Ok(()) => {}
                Err(e) => self.fail(rt, e.to_string()),
            }
            if rt.running_backend.is_none() {
                return;
            }
        }
        match rt.running_backend {
            Some(VpnBackend::SingBox) => match rt.runner.poll().await {
                RunnerState::Running { interface } => self.on_singbox_running(rt, interface).await,
                RunnerState::Starting => {
                    if rt.state != VpnState::Connected {
                        rt.state = VpnState::Connecting;
                    }
                }
                RunnerState::Failed(msg) => {
                    rt.engine_failures += 1;
                    rt.verify_probe = None;
                    self.dropped(rt, msg)
                }
                RunnerState::NotRunning => {
                    rt.engine_failures += 1;
                    rt.verify_probe = None;
                    self.dropped(rt, "sing-box arrêté".into())
                }
            },
            Some(VpnBackend::External) => {
                let name = cfg.vpn.external_service.clone().unwrap_or_default();
                match scutil::status(self.sys.as_ref(), &name).await {
                    Ok(st) => match st.state {
                        VpnState::Connected => self.connected(rt, st.interface),
                        VpnState::Connecting => rt.state = VpnState::Connecting,
                        _ => {
                            let waited = rt
                                .external_started
                                .map(|t| t.elapsed() > EXTERNAL_CONNECT_TIMEOUT)
                                .unwrap_or(true);
                            if rt.state == VpnState::Connected {
                                self.dropped(rt, format!("le VPN « {name} » s'est déconnecté"));
                            } else if waited {
                                rt.running_backend = None;
                                self.fail(rt, format!("le VPN « {name} » ne se connecte pas"));
                            } else {
                                rt.state = VpnState::Connecting;
                            }
                        }
                    },
                    Err(e) => {
                        rt.running_backend = None;
                        self.fail(rt, e.to_string());
                    }
                }
            }
            None => {}
        }
    }

    async fn start_tunnel(&self, rt: &mut Runtime, cfg: &Config) -> Result<(), VpnError> {
        match cfg.vpn.backend {
            VpnBackend::SingBox => {
                self.load_profile(rt);
                let profile = rt.profile.clone().ok_or_else(|| {
                    VpnError::Unavailable(
                        "aucun profil VPN : importez un lien (vless://, ss://, trojan://…) ou un fichier WireGuard"
                            .into(),
                    )
                })?;
                let binary = self.hooks.ensure_singbox().await?;
                rt.engine_path = Some(binary.clone());
                let ips = self
                    .resolve_all(rt, std::slice::from_ref(&profile.server))
                    .await;
                let server_ip = ips
                    .iter()
                    .find(|i| i.is_ipv4())
                    .or_else(|| ips.first())
                    .copied()
                    .ok_or_else(|| {
                        VpnError::Failed(format!(
                            "impossible de résoudre le serveur VPN {}",
                            profile.server
                        ))
                    })?;
                let local_dns = if cfg.dns.enabled {
                    cfg.dns.listen.parse::<SocketAddr>().ok()
                } else {
                    None
                };
                let opts = SingBoxOptions {
                    server_ip,
                    tunnel_ipv6: cfg.vpn.tunnel_ipv6,
                    allow_lan: cfg.vpn.allow_lan,
                    local_dns,
                };
                let config = build_config(&profile, &opts);
                rt.server_ips = ips;
                // Kill switch first (the server must stay reachable while traffic is blocked).
                rt.state = VpnState::Connecting;
                self.reconcile_killswitch(rt, cfg).await;
                rt.runner.start(&binary, &config).await?;
                rt.running_backend = Some(VpnBackend::SingBox);
                rt.state = VpnState::Connecting;
                Ok(())
            }
            VpnBackend::External => {
                let name = cfg.vpn.external_service.clone().ok_or_else(|| {
                    VpnError::Unavailable(
                        "choisissez le VPN macOS à piloter (réglage vpn.external_service)".into(),
                    )
                })?;
                rt.server_ips = self
                    .resolve_all(rt, &cfg.vpn.external_server_addresses)
                    .await;
                let st = scutil::status(self.sys.as_ref(), &name).await?;
                rt.running_backend = Some(VpnBackend::External);
                rt.external_started = Some(Instant::now());
                if st.state == VpnState::Connected {
                    self.connected(rt, st.interface);
                    return Ok(());
                }
                rt.state = VpnState::Connecting;
                self.reconcile_killswitch(rt, cfg).await;
                if let Err(e) = scutil::control(self.sys.as_ref(), &name, true).await {
                    rt.running_backend = None;
                    return Err(e);
                }
                Ok(())
            }
        }
    }

    async fn stop_tunnel(&self, rt: &mut Runtime) {
        match rt.running_backend.take() {
            Some(VpnBackend::SingBox) => rt.runner.stop().await,
            Some(VpnBackend::External) => {
                let name = self.cfg().vpn.external_service.clone().unwrap_or_default();
                if let Err(e) = scutil::control(self.sys.as_ref(), &name, false).await {
                    tracing::warn!(error = %e, "cannot stop the external VPN");
                }
            }
            None => {}
        }
        tracing::info!("VPN disconnected");
        rt.state = VpnState::Disconnected;
        rt.message = None;
        rt.connected_since = None;
        rt.interface = None;
    }

    // -----------------------------------------------------------------------------------------
    // Kill switch
    // -----------------------------------------------------------------------------------------

    async fn utuns(&self, rt: &mut Runtime) -> Vec<String> {
        if let Some((t, v)) = &rt.utuns {
            let has_tunnel = rt.interface.as_ref().map(|i| v.contains(i)).unwrap_or(true);
            if t.elapsed() < UTUN_CACHE && has_tunnel {
                return v.clone();
            }
        }
        let v = netprobe::utun_interfaces(self.sys.as_ref()).await;
        rt.utuns = Some((Instant::now(), v.clone()));
        v
    }

    async fn reconcile_killswitch(&self, rt: &mut Runtime, cfg: &Config) {
        let enabled = cfg.vpn.kill_switch && self.sys.is_macos();
        if enabled && rt.ks_latch.is_none() && rt.engine_failures >= ENGINE_FAILURE_LIMIT {
            rt.ks_latch = Some(Latch::EngineFailing);
            rt.ks_first_deadline = None;
            self.hooks.alert(NetAlert {
                severity: Severity::High,
                title: "Coupe-circuit retiré : sing-box ne démarre plus".into(),
                message: format!(
                    "sing-box s'est arrêté {} fois de suite{}. Ce n'est pas un problème de réseau : les règles ont \
                     été retirées pour ne pas couper Internet (ni les mises à jour de Parabellum). Elles reviendront \
                     dès que le tunnel fonctionnera ; vérifiez le profil VPN.",
                    rt.engine_failures,
                    rt.message
                        .as_deref()
                        .map(|m| format!(" ({m})"))
                        .unwrap_or_default()
                ),
                network_id: rt.current_network.clone(),
                key: "killswitch-engine".into(),
                offer_trust: false,
            });
        }
        if !enabled || !rt.wanted || rt.ks_latch.is_some() {
            if self.killswitch.is_applied() {
                if let Err(e) = self.killswitch.remove().await {
                    tracing::warn!(error = %e, "kill switch removal");
                }
            }
            rt.ks_state = if enabled && rt.ks_latch.is_some() {
                KillSwitchState::Error
            } else {
                KillSwitchState::Off
            };
            if !enabled || !rt.wanted {
                rt.ks_first_deadline = None;
                rt.ks_blocking_alerted = false;
            }
            if !enabled {
                rt.ks_ever_armed = false;
            }
            return;
        }
        let mut ifs = self.utuns(rt).await;
        if let Some(i) = &rt.interface {
            if !ifs.contains(i) {
                ifs.push(i.clone());
            }
        }
        let rules = render_rules(&KillSwitchRules {
            tunnel_interfaces: ifs,
            server_ips: rt.server_ips.clone(),
            allow_lan: cfg.vpn.allow_lan,
        });
        if let Err(e) = self.killswitch.apply(&rules, now_ts()).await {
            let _ = self.killswitch.remove().await;
            rt.ks_state = KillSwitchState::Error;
            rt.ks_latch = Some(Latch::PfFailed);
            self.hooks.alert(NetAlert {
                severity: Severity::High,
                title: "Coupe-circuit VPN impossible à activer".into(),
                message: format!("{e}. Le trafic n'est pas bloqué si le tunnel tombe."),
                network_id: rt.current_network.clone(),
                key: "killswitch-pf".into(),
                offer_trust: false,
            });
            return;
        }
        if rt.state == VpnState::Connected {
            rt.ks_state = KillSwitchState::Armed;
            rt.ks_ever_armed = true;
            rt.ks_first_deadline = None;
            rt.ks_blocking_alerted = false;
            return;
        }
        rt.ks_state = KillSwitchState::Blocking;
        if !rt.ks_ever_armed {
            let deadline = *rt
                .ks_first_deadline
                .get_or_insert_with(|| Instant::now() + FIRST_ARM_TIMEOUT);
            if Instant::now() >= deadline {
                let _ = self.killswitch.remove().await;
                rt.ks_state = KillSwitchState::Error;
                rt.ks_latch = Some(Latch::FirstArmTimeout);
                rt.ks_first_deadline = None;
                self.hooks.alert(NetAlert {
                    severity: Severity::High,
                    title: "Coupe-circuit retiré : tunnel injoignable".into(),
                    message: format!(
                        "Le VPN ne s'est pas connecté dans les {} s suivant l'activation du coupe-circuit : les \
                         règles ont été retirées pour ne pas couper Internet. Vérifiez le profil VPN ; le \
                         coupe-circuit se réactivera dès que le tunnel sera établi.",
                        FIRST_ARM_TIMEOUT.as_secs()
                    ),
                    network_id: rt.current_network.clone(),
                    key: "killswitch-first-arm".into(),
                    offer_trust: false,
                });
            }
        } else if !rt.ks_blocking_alerted {
            rt.ks_blocking_alerted = true;
            self.hooks.alert(NetAlert {
                severity: Severity::Medium,
                title: "VPN coupé : Internet bloqué par le coupe-circuit".into(),
                message: "Le tunnel est tombé ; le coupe-circuit bloque le trafic jusqu'à la reconnexion. Sur un \
                          Wi-Fi à portail captif (hôtel, gare), connectez-vous d'abord : désactivez temporairement le \
                          coupe-circuit (Parabellum > VPN, ou `sudo parabellum vpn disconnect`), puis réactivez-le."
                    .into(),
                network_id: rt.current_network.clone(),
                key: "killswitch-blocking".into(),
                offer_trust: rt.current_network.is_some(),
            });
        }
    }

    // -----------------------------------------------------------------------------------------
    // Leak tests & home IP
    // -----------------------------------------------------------------------------------------

    async fn leak_inputs(&self, rt: &mut Runtime, cfg: &Config) -> LeakInputs {
        let (v4, v6) = leak::probe_public(self.sys.as_ref()).await;
        let dns = netprobe::dns_servers(self.sys.as_ref()).await;
        let (physical_ipv6, gateway_ip) = match &rt.last_snapshot {
            Some(s) => (
                netprobe::interface_ipv6(self.sys.as_ref(), &s.interface).await,
                s.gateway_ip,
            ),
            None => (vec![], None),
        };
        let home_ipv4 = rt
            .current_network
            .as_deref()
            .and_then(|id| rt.networks.get(id))
            .and_then(|n| n.home_ipv4.as_deref())
            .and_then(|h| h.parse().ok());
        LeakInputs {
            ts: now_ts(),
            vpn_connected: rt.state == VpnState::Connected,
            tunnel_interface: rt.interface.clone(),
            public_ipv4: v4,
            public_ipv6: v6,
            home_ipv4,
            physical_ipv6,
            dns_servers: dns,
            gateway_ip,
            allow_lan: cfg.vpn.allow_lan,
            kill_switch_enabled: cfg.vpn.kill_switch,
            kill_switch: rt.ks_state,
        }
    }

    pub(crate) async fn do_leak_test(&self, auto: bool) -> Result<LeakTestResult, VpnError> {
        let cfg = self.cfg();
        let mut rt = self.rt.lock().await;
        self.ensure_loaded(&mut rt);
        if !auto {
            if let (Some(at), Some(last)) = (rt.last_leak_at, rt.last_leak.clone()) {
                if at.elapsed() < LEAK_MIN_INTERVAL {
                    return Ok(last);
                }
            }
        }
        let result = self.run_leak_test(&mut rt, &cfg).await;
        self.publish(&rt, &cfg);
        Ok(result)
    }

    async fn run_leak_test(&self, rt: &mut Runtime, cfg: &Config) -> LeakTestResult {
        let inputs = self.leak_inputs(rt, cfg).await;
        let result = leak::evaluate(&inputs);
        rt.last_leak = Some(result.clone());
        rt.last_leak_at = Some(Instant::now());
        result
    }

    async fn maybe_auto_leak_test(&self, rt: &mut Runtime, cfg: &Config) {
        let interval = u64::from(cfg.vpn.leak_test_interval_minutes) * 60;
        if interval == 0 || rt.state != VpnState::Connected {
            return;
        }
        let settled = rt
            .connected_since
            .map(|t| now_ts() - t >= 10)
            .unwrap_or(false);
        let due = rt
            .last_auto_leak
            .map(|t| t.elapsed() >= Duration::from_secs(interval))
            .unwrap_or(true);
        if !settled || !due {
            return;
        }
        rt.last_auto_leak = Some(Instant::now());
        let r = self.run_leak_test(rt, cfg).await;
        if !r.ok && r.vpn_connected {
            let failing: Vec<&str> = r
                .checks
                .iter()
                .filter(|c| !c.ok)
                .map(|c| c.id.as_str())
                .collect();
            let details: Vec<String> = r
                .checks
                .iter()
                .filter(|c| !c.ok)
                .map(|c| c.detail.clone())
                .collect();
            self.hooks.alert(NetAlert {
                severity: Severity::High,
                title: "Fuite détectée malgré le VPN".into(),
                message: details.join(" ; "),
                network_id: rt.current_network.clone(),
                key: format!("leak:{}", failing.join(",")),
                offer_trust: false,
            });
        }
    }

    async fn maybe_refresh_home_ip(&self, rt: &mut Runtime, cfg: &Config) {
        if rt.running_backend.is_some() || rt.state == VpnState::Connected {
            return;
        }
        let Some(id) = rt.current_network.clone() else {
            return;
        };
        if rt.last_snapshot.as_ref().map(|s| s.default_via_tunnel) != Some(false) {
            return;
        }
        let now = now_ts();
        let due = rt
            .networks
            .get(&id)
            .map(|n| {
                n.home_checked_at
                    .map(|t| now - t >= HOME_IP_INTERVAL)
                    .unwrap_or(true)
            })
            .unwrap_or(false);
        if !due {
            return;
        }
        // Another macOS VPN may be up without owning the default route.
        if scutil::list(self.sys.as_ref())
            .await
            .iter()
            .any(|s| s.state == VpnState::Connected)
        {
            return;
        }
        let _ = cfg;
        let (v4, _) = leak::probe_public(self.sys.as_ref()).await;
        if let Some(n) = rt.networks.get_mut(&id) {
            n.home_checked_at = Some(now);
            if let Some(ip) = v4 {
                n.home_ipv4 = Some(ip.to_string());
            }
        }
        if let Err(e) = rt.networks.save(&self.dir) {
            tracing::warn!(error = %e, "cannot save networks.json");
        } else {
            rt.networks_saved = Some(Instant::now());
        }
    }

    // -----------------------------------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------------------------------

    fn build_status(&self, rt: &Runtime, cfg: &Config) -> VpnStatus {
        let network = rt.current_network.as_deref().and_then(|id| {
            rt.networks.get(id).map(|n| {
                NetworksFile::info(n, cfg.vpn.trusted_networks.iter().any(|t| t == id), true)
            })
        });
        let engine_installed = rt
            .engine_path
            .as_ref()
            .map(|p| p.is_file())
            .unwrap_or(false)
            || crate::singbox_binary(&self.paths).is_file();
        let mut message = rt.message.clone();
        if rt.ks_state == KillSwitchState::Error && message.is_none() {
            message = Some("coupe-circuit inactif (erreur)".into());
        }
        VpnStatus {
            mode: cfg.vpn.mode,
            backend: cfg.vpn.backend,
            state: rt.state,
            wanted: rt.wanted,
            manual_override: rt.manual_override,
            profile: rt.profile.as_ref().map(VpnProfile::info),
            external_service: cfg.vpn.external_service.clone(),
            connected_since: rt.connected_since,
            interface: rt.interface.clone(),
            kill_switch: rt.ks_state,
            network,
            last_leak_test: rt.last_leak.clone(),
            engine_installed,
            message,
        }
    }

    fn publish(&self, rt: &Runtime, cfg: &Config) {
        let s = self.build_status(rt, cfg);
        let changed = {
            let mut g = self.status.lock().unwrap_or_else(|e| e.into_inner());
            if *g != s {
                *g = s.clone();
                true
            } else {
                false
            }
        };
        if changed {
            self.hooks.status_changed(&s);
        }
    }

    // -----------------------------------------------------------------------------------------
    // IPC operations
    // -----------------------------------------------------------------------------------------

    pub(crate) async fn do_connect(&self) -> Result<VpnStatus, VpnError> {
        let cfg = self.cfg();
        {
            let mut rt = self.rt.lock().await;
            self.ensure_loaded(&mut rt);
            match cfg.vpn.backend {
                VpnBackend::SingBox if rt.profile.is_none() => {
                    return Err(VpnError::Unavailable(
                        "aucun profil VPN : importez d'abord un lien ou un fichier WireGuard"
                            .into(),
                    ))
                }
                VpnBackend::External if cfg.vpn.external_service.is_none() => {
                    return Err(VpnError::Unavailable(
                        "choisissez d'abord le VPN macOS à piloter (vpn.external_service)".into(),
                    ))
                }
                _ => {}
            }
            rt.manual_override = Some(true);
            rt.override_network = None;
            if rt.ks_latch.is_some() {
                rt.ks_latch = None;
                rt.ks_first_deadline = None;
            }
            rt.engine_failures = 0;
            rt.next_attempt = None;
            rt.backoff = BACKOFF_MIN;
        }
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            self.tick().await;
            let s = self.status().await;
            match s.state {
                VpnState::Connected => return Ok(s),
                VpnState::Error => {
                    return Err(VpnError::Failed(
                        s.message
                            .unwrap_or_else(|| "connexion VPN impossible".into()),
                    ))
                }
                _ if Instant::now() >= deadline => return Ok(s),
                _ => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }

    pub(crate) async fn do_disconnect(&self) -> Result<VpnStatus, VpnError> {
        {
            let mut rt = self.rt.lock().await;
            rt.manual_override = Some(false);
            rt.override_network = rt.current_network.clone();
        }
        self.tick().await;
        Ok(self.status().await)
    }

    pub(crate) async fn do_import(&self, text: &str) -> Result<VpnProfileInfo, VpnError> {
        let profile = profile::parse(text, now_ts())?;
        fsutil::write_json(&self.profile_path(), &profile)
            .map_err(|e| VpnError::Failed(format!("enregistrement du profil : {e}")))?;
        let info = profile.info();
        tracing::info!(protocol = %info.protocol, server = %info.server, "VPN profile imported");
        {
            let mut rt = self.rt.lock().await;
            self.ensure_loaded(&mut rt);
            rt.profile = Some(profile);
            rt.profile_loaded = true;
            rt.resolve_cache.clear();
            rt.next_attempt = None;
            rt.backoff = BACKOFF_MIN;
            if rt.running_backend == Some(VpnBackend::SingBox) {
                rt.runner.stop().await;
                rt.running_backend = None;
                rt.state = VpnState::Disconnected;
                rt.interface = None;
            }
        }
        self.wake.notify_one();
        self.tick().await;
        Ok(info)
    }

    pub(crate) async fn do_remove_profile(&self) -> Result<(), VpnError> {
        fsutil::remove(&self.profile_path())
            .map_err(|e| VpnError::Failed(format!("suppression du profil : {e}")))?;
        let _ = fsutil::remove(&self.dir.join(crate::runner::CONFIG_FILE));
        {
            let mut rt = self.rt.lock().await;
            rt.profile = None;
            rt.profile_loaded = true;
            if rt.running_backend == Some(VpnBackend::SingBox) {
                rt.runner.stop().await;
                rt.running_backend = None;
                rt.state = VpnState::Disconnected;
                rt.interface = None;
            }
        }
        self.tick().await;
        Ok(())
    }

    pub(crate) async fn do_set_trust(
        &self,
        id: &str,
        trusted: bool,
    ) -> Result<NetworkInfo, VpnError> {
        if !pb_core::config::is_network_id(id) {
            return Err(VpnError::Invalid(format!(
                "identifiant de réseau invalide : {id}"
            )));
        }
        let cfg = self.cfg();
        let stored = {
            let rt = self.rt.lock().await;
            rt.networks.get(id).cloned()
        };
        let stored = stored.ok_or_else(|| VpnError::NotFound(format!("réseau {id} inconnu")))?;
        let mut list = cfg.vpn.trusted_networks.clone();
        list.retain(|t| t != id);
        if trusted {
            list.push(id.to_string());
        }
        self.hooks.save_trusted_networks(list.clone()).await?;
        let mut new_cfg = (*cfg).clone();
        new_cfg.vpn.trusted_networks = list;
        self.set_cfg(Arc::new(new_cfg));
        let current = {
            let rt = self.rt.lock().await;
            rt.current_network.as_deref() == Some(id)
        };
        self.wake.notify_one();
        Ok(NetworksFile::info(&stored, trusted, current))
    }

    pub(crate) async fn do_shutdown(&self) {
        let mut rt = self.rt.lock().await;
        // Rules first: launchd may SIGKILL us while sing-box takes its grace period to stop, and a kill
        // switch outliving the daemon would leave the Mac offline.
        if let Err(e) = self.killswitch.remove().await {
            tracing::warn!(error = %e, "kill switch removal at shutdown");
        }
        rt.ks_state = KillSwitchState::Off;
        if rt.running_backend == Some(VpnBackend::SingBox) {
            rt.runner.stop().await;
            rt.running_backend = None;
        }
        // An external VPN keeps running: it is the user's own app.
        if rt.running_backend.is_none() {
            rt.state = VpnState::Disconnected;
            rt.interface = None;
            rt.connected_since = None;
        }
    }
}

#[cfg(test)]
mod tests;
