use super::*;
use crate::killswitch::ANCHOR;
use crate::netprobe::fixtures;
use crate::sys::{ARP, IFCONFIG, IPCONFIG, PFCTL, ROUTE, SCUTIL};
use crate::testutil::FakeSystem;
use crate::VpnHooks;
use async_trait::async_trait;
use pb_core::paths::Paths;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

#[derive(Default)]
struct Hooks {
    statuses: Mutex<Vec<VpnStatus>>,
    alerts: Mutex<Vec<NetAlert>>,
    trusted: Mutex<Option<Vec<String>>>,
    no_engine: bool,
}

#[async_trait]
impl VpnHooks for Hooks {
    fn status_changed(&self, s: &VpnStatus) {
        self.statuses.lock().unwrap().push(s.clone());
    }
    fn alert(&self, a: NetAlert) {
        self.alerts.lock().unwrap().push(a);
    }
    async fn ensure_singbox(&self) -> Result<PathBuf, VpnError> {
        if self.no_engine {
            return Err(VpnError::Unavailable("sing-box non installé".into()));
        }
        Ok(PathBuf::from("/pb/components/sing-box/sing-box"))
    }
    async fn save_trusted_networks(&self, ids: Vec<String>) -> Result<(), VpnError> {
        *self.trusted.lock().unwrap() = Some(ids);
        Ok(())
    }
}

impl Hooks {
    fn alert_keys(&self) -> Vec<String> {
        self.alerts
            .lock()
            .unwrap()
            .iter()
            .map(|a| a.key.clone())
            .collect()
    }
}

const HOME_ID: &str = "gw:00:24:d4:a1:b2:c3";

fn macos_sys() -> Arc<FakeSystem> {
    let sys = FakeSystem::macos();
    sys.respond(ROUTE, &["-n", "get", "default"], 0, fixtures::ROUTE_GET, "");
    sys.respond(ARP, &["-an"], 0, fixtures::ARP_OUT, "");
    sys.respond(IPCONFIG, &["getsummary"], 0, fixtures::IPCONFIG_WIFI, "");
    sys.respond(IFCONFIG, &["-l"], 0, "lo0 en0 utun0 utun1\n", "");
    sys.respond(PFCTL, &["-a", ANCHOR, "-f"], 0, "", "");
    sys.respond(PFCTL, &["-E"], 0, "", "Token : 77\n");
    sys.respond(
        PFCTL,
        &["-s", "rules"],
        0,
        "anchor \"com.apple/*\" all\n",
        "",
    );
    sys.respond(PFCTL, &["-a", ANCHOR, "-F", "all"], 0, "", "");
    sys.respond(PFCTL, &["-X"], 0, "", "");
    sys.respond(SCUTIL, &["--nc", "list"], 0, "", "");
    sys
}

fn setup(sys: Arc<FakeSystem>, hooks: Arc<Hooks>) -> (tempfile::TempDir, Arc<VpnService>) {
    let d = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(d.path());
    std::fs::create_dir_all(paths.vpn_dir()).unwrap();
    let svc = VpnService::with_system(paths, hooks, sys);
    (d, svc)
}

fn cfg(f: impl FnOnce(&mut Config)) -> Arc<Config> {
    let mut c = Config::default();
    f(&mut c);
    Arc::new(c)
}

/// Force the next probe (bypass the poll interval).
async fn reprobe(svc: &VpnService) {
    svc.rt.lock().await.last_probe = None;
}

#[tokio::test]
async fn singbox_always_with_kill_switch() {
    let sys = macos_sys();
    let hooks = Arc::new(Hooks::default());
    let (_d, svc) = setup(sys.clone(), hooks.clone());
    svc.import_profile("trojan://pw@203.0.113.9:443?sni=vpn.example.com#Paris")
        .await
        .unwrap();
    svc.set_cfg(cfg(|c| {
        c.vpn.mode = VpnMode::Always;
        c.vpn.kill_switch = true;
    }));
    svc.tick().await;
    let p = sys.last_process().expect("sing-box spawned");
    assert_eq!(p.program, Path::new("/pb/components/sing-box/sing-box"));
    let s = svc.status().await;
    assert_eq!(s.state, VpnState::Connecting);
    assert!(s.wanted);
    assert_eq!(s.kill_switch, KillSwitchState::Blocking);
    assert_eq!(s.network.as_ref().map(|n| n.id.as_str()), Some(HOME_ID));
    assert_eq!(s.profile.as_ref().unwrap().name, "Paris");
    let rules = std::fs::read_to_string(svc.dir.join("killswitch.pf")).unwrap();
    assert!(rules.contains("pass out quick inet from any to 203.0.113.9"));
    // The TUN appears.
    sys.respond(IFCONFIG, &["-l"], 0, "lo0 en0 utun0 utun1 utun7\n", "");
    svc.tick().await;
    let s = svc.status().await;
    assert_eq!(s.state, VpnState::Connected);
    assert_eq!(s.interface.as_deref(), Some("utun7"));
    assert_eq!(s.kill_switch, KillSwitchState::Armed);
    let rules = std::fs::read_to_string(svc.dir.join("killswitch.pf")).unwrap();
    assert!(rules.contains("pass quick on utun7 all"));
    // sing-box dies: Blocking + alert mentioning captive portals, restart scheduled.
    p.exited.store(true, Ordering::SeqCst);
    svc.tick().await;
    let s = svc.status().await;
    assert_eq!(s.kill_switch, KillSwitchState::Blocking);
    let keys = hooks.alert_keys();
    assert!(keys.contains(&"vpn-drop".to_string()), "{keys:?}");
    assert!(keys.contains(&"killswitch-blocking".to_string()));
    let a = hooks
        .alerts
        .lock()
        .unwrap()
        .iter()
        .find(|a| a.key == "killswitch-blocking")
        .cloned()
        .unwrap();
    assert!(a.message.contains("portail captif"));
    // Shutdown: sing-box stopped, rules removed (fail open).
    svc.shutdown().await;
    assert!(!svc.killswitch.is_applied());
    assert!(sys.count(PFCTL, &["-X", "77"]) >= 1);
    assert!(!hooks.statuses.lock().unwrap().is_empty());
}

#[tokio::test]
async fn kill_switch_first_arm_timeout_fails_open() {
    let sys = macos_sys();
    let hooks = Arc::new(Hooks::default());
    let (_d, svc) = setup(sys.clone(), hooks.clone());
    svc.import_profile("trojan://pw@203.0.113.9:443")
        .await
        .unwrap();
    svc.set_cfg(cfg(|c| {
        c.vpn.mode = VpnMode::Always;
        c.vpn.kill_switch = true;
    }));
    svc.tick().await;
    assert!(svc.killswitch.is_applied());
    svc.rt.lock().await.ks_first_deadline = Some(Instant::now() - Duration::from_secs(1));
    svc.tick().await;
    assert!(!svc.killswitch.is_applied());
    assert_eq!(svc.status().await.kill_switch, KillSwitchState::Error);
    assert!(hooks
        .alert_keys()
        .contains(&"killswitch-first-arm".to_string()));
    // Latched: not re-applied while still connecting.
    svc.tick().await;
    assert!(!svc.killswitch.is_applied());
    // Once the tunnel is up, the kill switch arms again.
    sys.respond(IFCONFIG, &["-l"], 0, "lo0 en0 utun0 utun1 utun3\n", "");
    svc.tick().await;
    svc.tick().await;
    assert_eq!(svc.status().await.kill_switch, KillSwitchState::Armed);
    assert!(svc.killswitch.is_applied());
}

#[tokio::test]
async fn untrusted_networks_mode_and_override() {
    let sys = macos_sys();
    let hooks = Arc::new(Hooks::default());
    let (_d, svc) = setup(sys.clone(), hooks.clone());
    svc.import_profile("trojan://pw@203.0.113.9:443")
        .await
        .unwrap();
    svc.set_cfg(cfg(|c| {
        c.vpn.mode = VpnMode::UntrustedNetworks;
        c.vpn.trusted_networks = vec![HOME_ID.into()];
    }));
    svc.tick().await;
    let s = svc.status().await;
    assert!(!s.wanted);
    assert_eq!(s.state, VpnState::Disconnected);
    assert!(s.network.as_ref().unwrap().trusted);
    assert!(sys.last_process().is_none());
    // Manual connect on a trusted network.
    sys.respond_after_spawn(IFCONFIG, &["-l"], 0, "lo0 en0 utun0 utun1 utun9\n", "");
    let s = svc.connect().await.unwrap();
    assert_eq!(s.state, VpnState::Connected);
    assert_eq!(s.manual_override, Some(true));
    // Manual disconnect holds until the network changes.
    let s = svc.disconnect().await.unwrap();
    assert_eq!(s.state, VpnState::Disconnected);
    assert_eq!(s.manual_override, Some(false));
    // Move to another (untrusted) network: override cleared, tunnel wanted.
    sys.respond(
        ARP,
        &["-an"],
        0,
        "? (192.168.1.254) at 12:34:56:78:9a:bc on en0 ifscope [ethernet]\n",
        "",
    );
    sys.respond(
        IPCONFIG,
        &["getsummary"],
        0,
        "<dictionary> {\n  InterfaceType : WiFi\n  SSID : Gare-WiFi\n  Security : None\n}\n",
        "",
    );
    reprobe(&svc).await;
    svc.rt.lock().await.last_snapshot = None; // disconnection in between
    svc.tick().await;
    let s = svc.status().await;
    assert_eq!(s.manual_override, None);
    assert!(s.wanted);
    assert_eq!(s.network.as_ref().unwrap().name, "Gare-WiFi");
    assert!(!s.network.as_ref().unwrap().trusted);
    // Trusting it (through the daemon hook) turns the tunnel off.
    let info = svc
        .set_network_trust("gw:12:34:56:78:9a:bc", true)
        .await
        .unwrap();
    assert!(info.trusted && info.current);
    assert_eq!(
        hooks.trusted.lock().unwrap().clone().unwrap(),
        vec![HOME_ID.to_string(), "gw:12:34:56:78:9a:bc".to_string()]
    );
    svc.tick().await;
    assert!(!svc.status().await.wanted);
    assert!(matches!(
        svc.set_network_trust("gw:99:99:99:99:99:99", true).await,
        Err(VpnError::NotFound(_))
    ));
    assert!(matches!(
        svc.set_network_trust("nope", true).await,
        Err(VpnError::Invalid(_))
    ));
    assert_eq!(svc.networks().await.len(), 2);
}

#[tokio::test]
async fn arp_spoofing_alert_and_auto_vpn() {
    let sys = macos_sys();
    let hooks = Arc::new(Hooks::default());
    let (_d, svc) = setup(sys.clone(), hooks.clone());
    svc.set_cfg(cfg(|c| {
        c.vpn.mode = VpnMode::UntrustedNetworks;
        c.vpn.trusted_networks = vec![HOME_ID.into()];
    }));
    svc.tick().await;
    assert!(!svc.status().await.wanted);
    // Same router IP and Wi-Fi, new MAC, no disconnection: spoofing.
    sys.respond(
        ARP,
        &["-an"],
        0,
        "? (192.168.1.254) at de:ad:be:ef:0:1 on en0 ifscope [ethernet]\n",
        "",
    );
    reprobe(&svc).await;
    svc.tick().await;
    assert!(hooks
        .alert_keys()
        .contains(&"arp-spoof:192.168.1.254:de:ad:be:ef:00:01".to_string()));
    // The impostor's network is untrusted: the VPN is wanted (no profile -> error state, reported).
    let s = svc.status().await;
    assert!(s.wanted);
    assert_eq!(s.state, VpnState::Error);
    assert!(s.message.unwrap().contains("profil"));
}

#[tokio::test]
async fn external_backend() {
    let sys = macos_sys();
    sys.respond(
        SCUTIL,
        &["--nc", "status", "Shadowrocket"],
        0,
        "Disconnected\n",
        "",
    );
    sys.respond(SCUTIL, &["--nc", "start", "Shadowrocket"], 0, "", "");
    sys.respond(SCUTIL, &["--nc", "stop", "Shadowrocket"], 0, "", "");
    sys.dns("sr.example.com", &["198.51.100.20"]);
    let hooks = Arc::new(Hooks::default());
    let (_d, svc) = setup(sys.clone(), hooks.clone());
    svc.set_cfg(cfg(|c| {
        c.vpn.mode = VpnMode::Always;
        c.vpn.backend = VpnBackend::External;
        c.vpn.external_service = Some("Shadowrocket".into());
        c.vpn.external_server_addresses = vec!["sr.example.com".into()];
        c.vpn.kill_switch = true;
    }));
    svc.tick().await;
    assert_eq!(sys.count(SCUTIL, &["--nc", "start", "Shadowrocket"]), 1);
    assert_eq!(svc.status().await.state, VpnState::Connecting);
    let rules = std::fs::read_to_string(svc.dir.join("killswitch.pf")).unwrap();
    assert!(rules.contains("198.51.100.20"));
    sys.respond(
        SCUTIL,
        &["--nc", "status", "Shadowrocket"],
        0,
        "Connected\nExtended Status <dictionary> {\n  InterfaceName : utun4\n}\n",
        "",
    );
    svc.tick().await;
    let s = svc.status().await;
    assert_eq!(s.state, VpnState::Connected);
    assert_eq!(s.interface.as_deref(), Some("utun4"));
    assert_eq!(s.kill_switch, KillSwitchState::Armed);
    svc.disconnect().await.unwrap();
    assert_eq!(sys.count(SCUTIL, &["--nc", "stop", "Shadowrocket"]), 1);
    assert_eq!(svc.status().await.kill_switch, KillSwitchState::Off);
    assert!(!svc.killswitch.is_applied());
}

#[tokio::test]
async fn leak_test_and_home_ip() {
    let sys = macos_sys();
    sys.respond(SCUTIL, &["--dns"], 0, fixtures::SCUTIL_DNS, "");
    sys.respond(IFCONFIG, &["en0"], 0, fixtures::IFCONFIG_EN0, "");
    sys.http(crate::leak::IPV4_URL, Ok("{\"ip\":\"90.12.34.56\"}"));
    let hooks = Arc::new(Hooks::default());
    let (_d, svc) = setup(sys.clone(), hooks.clone());
    svc.set_cfg(cfg(|c| c.network.enabled = true));
    // VPN down on a known network: home IP recorded.
    svc.tick().await;
    {
        let rt = svc.rt.lock().await;
        assert_eq!(
            rt.networks.get(HOME_ID).unwrap().home_ipv4.as_deref(),
            Some("90.12.34.56")
        );
    }
    let r = svc.leak_test().await.unwrap();
    assert!(!r.ok);
    assert!(!r.vpn_connected);
    let ipv4 = r.checks.iter().find(|c| c.id == "ipv4").unwrap();
    assert!(!ipv4.ok, "same IP as without VPN");
    // Rate limit: same result within 15 s.
    sys.http(crate::leak::IPV4_URL, Ok("{\"ip\":\"203.0.113.9\"}"));
    assert_eq!(svc.leak_test().await.unwrap(), r);
    assert_eq!(svc.status().await.last_leak_test, Some(r));
}

#[tokio::test]
async fn errors_and_linux() {
    let hooks = Arc::new(Hooks {
        no_engine: true,
        ..Default::default()
    });
    let sys = FakeSystem::linux();
    let (d, svc) = setup(sys.clone(), hooks.clone());
    assert!(matches!(svc.connect().await, Err(VpnError::Unavailable(_))));
    assert!(matches!(
        svc.import_profile("garbage").await,
        Err(VpnError::Invalid(_))
    ));
    svc.import_profile("trojan://pw@203.0.113.9:443")
        .await
        .unwrap();
    let mode = std::fs::metadata(Paths::with_root(d.path()).vpn_dir().join(PROFILE_FILE)).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(mode.permissions().mode() & 0o777, 0o600);
    // sing-box missing: error reported, no panic.
    let err = svc.connect().await.unwrap_err();
    assert!(err.to_string().contains("sing-box"));
    // Engine available on Linux: runs without system tools, kill switch stays off.
    let hooks = Arc::new(Hooks::default());
    let (_d2, svc) = setup(sys.clone(), hooks.clone());
    svc.import_profile("trojan://pw@203.0.113.9:443")
        .await
        .unwrap();
    svc.set_cfg(cfg(|c| c.vpn.kill_switch = true));
    let s = svc.connect().await.unwrap();
    assert_eq!(s.state, VpnState::Connected);
    assert_eq!(s.kill_switch, KillSwitchState::Off);
    svc.remove_profile().await.unwrap();
    let s = svc.status().await;
    assert!(s.profile.is_none());
    assert!(sys
        .last_process()
        .unwrap()
        .terminated
        .load(Ordering::SeqCst));
    assert!(svc.list_services().await.is_empty());
}

#[tokio::test]
async fn config_change_restarts_singbox() {
    let sys = FakeSystem::linux();
    let hooks = Arc::new(Hooks::default());
    let (_d, svc) = setup(sys.clone(), hooks.clone());
    svc.import_profile("trojan://pw@203.0.113.9:443")
        .await
        .unwrap();
    let c1 = cfg(|c| c.vpn.mode = VpnMode::Always);
    svc.set_cfg(c1.clone());
    svc.tick().await;
    svc.tick().await;
    assert_eq!(svc.status().await.state, VpnState::Connected);
    let first = sys.last_process().unwrap();
    let c2 = cfg(|c| {
        c.vpn.mode = VpnMode::Always;
        c.dns.enabled = true;
    });
    svc.set_cfg(c2.clone());
    svc.on_config_change(&c1, &c2).await;
    assert!(first.terminated.load(Ordering::SeqCst));
    svc.tick().await;
    let second = sys.last_process().unwrap();
    assert_ne!(first.pid, second.pid);
    let conf: serde_json::Value =
        serde_json::from_slice(&std::fs::read(svc.dir.join(crate::runner::CONFIG_FILE)).unwrap())
            .unwrap();
    assert_eq!(conf["dns"]["final"], "dns-local");
    // Mode off: tunnel stopped.
    let c3 = cfg(|c| c.vpn.mode = VpnMode::Off);
    svc.set_cfg(c3.clone());
    svc.on_config_change(&c2, &c3).await;
    svc.tick().await;
    assert!(second.terminated.load(Ordering::SeqCst));
    assert_eq!(svc.status().await.state, VpnState::Disconnected);
}

#[tokio::test]
async fn run_loop_stops_on_shutdown() {
    let sys = FakeSystem::linux();
    let hooks = Arc::new(Hooks::default());
    let (_d, svc) = setup(sys, hooks);
    let (_ctx, crx) = watch::channel(Arc::new(Config::default()));
    let (stx, srx) = watch::channel(false);
    let h = tokio::spawn(svc.clone().run(crx, srx));
    tokio::time::sleep(Duration::from_millis(50)).await;
    stx.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), h)
        .await
        .unwrap()
        .unwrap();
}
