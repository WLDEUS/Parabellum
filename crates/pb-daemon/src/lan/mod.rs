//! "Réseau local": inventory of the devices of the current network, alerts when an unknown device joins a
//! trusted network.
//!
//! Policy (documented in `LanConfig`):
//! - periodic scan every `lan.scan_interval_minutes` (skipped on low battery and offline);
//! - **active** (rate-limited sweep of the /24, IPv6 all-nodes ping, Bonjour) only on networks the user
//!   trusts (`vpn.trusted_networks`), that are not behind a captive portal, when `lan.active_on_trusted`;
//! - **passive** (ARP / NDP caches, no packet sent) everywhere else: sweeping a public Wi-Fi can look
//!   hostile. A scan the user starts from the app may be active anywhere (the app asks first on an
//!   untrusted network);
//! - the first scan of a network is its baseline (no alert); afterwards a device never seen before on a
//!   trusted network raises one `network` alert ("Je connais cet appareil" / "Ignorer").
//!
//! State: `state/lan.json` (root-only). Network identity: `gw:<router MAC>`, shared with the VPN.

pub mod classify;
pub mod oui;
pub mod parse;
pub mod probe;
pub mod store;

use crate::actions;
use crate::ctx::Ctx;
use pb_core::config::{is_network_id, Config};
use pb_core::ipc::{DaemonEvent, ErrorCode, IpcError};
use pb_core::model::*;
use pb_vpn::netprobe::{normalize_mac, NetworkSnapshot};
use probe::{LanSystem, RealLanSystem};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use store::LanFile;

/// `Alert::device_id` of LAN alerts: `lan:<mac>` (the network is in `network_id`).
pub const ALERT_DEVICE_PREFIX: &str = "lan:";
/// Period of the scheduling loop (the scan itself follows `lan.scan_interval_minutes`).
pub const TICK: Duration = Duration::from_secs(300);
pub const STARTUP_DELAY: Duration = Duration::from_secs(120);
const SNAPSHOT_TTL: Duration = Duration::from_secs(60);
const CAPTIVE_TTL: Duration = Duration::from_secs(3600);
/// Individual alerts per scan (beyond: one summary alert).
pub const MAX_ALERTS_PER_SCAN: usize = 5;
pub const MAX_NAME: usize = 64;

#[derive(Default)]
struct Live {
    scanning: bool,
    progress: f32,
    phase: Option<String>,
    message: Option<String>,
    snap: Option<(Instant, Option<NetworkSnapshot>)>,
    captive: HashMap<String, (Instant, bool)>,
}

/// Result of a scan, for alerting.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub network_id: String,
    pub network_name: String,
    pub trusted: bool,
    pub mode: LanScanMode,
    pub new_devices: Vec<LanDevice>,
}

fn bad(m: impl Into<String>) -> IpcError {
    IpcError::new(ErrorCode::BadRequest, m)
}

/// Scan mode for a request (`None` = policy) and the note shown to the user when it is passive.
pub fn decide_mode(
    request: Option<bool>,
    trusted: bool,
    active_on_trusted: bool,
    captive: Option<bool>,
) -> (LanScanMode, Option<String>) {
    match request {
        Some(true) => (LanScanMode::Active, None),
        Some(false) => (
            LanScanMode::Passive,
            Some("Analyse passive demandée : caches système uniquement.".into()),
        ),
        None if !trusted => (
            LanScanMode::Passive,
            Some(
                "Réseau non marqué de confiance : seuls les caches système sont lus (aucun paquet envoyé). \
                 Lance une analyse complète si tu le souhaites."
                    .into(),
            ),
        ),
        None if !active_on_trusted => (
            LanScanMode::Passive,
            Some("Analyse active désactivée dans les réglages : caches système uniquement.".into()),
        ),
        None if captive == Some(true) => (
            LanScanMode::Passive,
            Some("Portail captif ou Internet indisponible : analyse passive.".into()),
        ),
        None => (LanScanMode::Active, None),
    }
}

/// The LAN inventory service (shared as `Arc`).
pub struct LanService {
    dir: PathBuf,
    oui: PathBuf,
    sys: Arc<dyn LanSystem>,
    file: tokio::sync::Mutex<LanFile>,
    scan_lock: tokio::sync::Mutex<()>,
    live: Mutex<Live>,
}

impl LanService {
    /// State in `dir/lan.json`, vendors from `oui` (`db/current/lan/oui.tsv`).
    pub fn new(dir: PathBuf, oui: PathBuf, sys: Arc<dyn LanSystem>) -> Arc<Self> {
        let file = LanFile::load(&dir);
        Arc::new(Self {
            dir,
            oui,
            sys,
            file: tokio::sync::Mutex::new(file),
            scan_lock: tokio::sync::Mutex::new(()),
            live: Mutex::new(Live::default()),
        })
    }

    fn live(&self) -> std::sync::MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_scanning(&self) -> bool {
        self.live().scanning
    }

    /// Current network (cached for a minute unless `fresh`).
    pub async fn snapshot(&self, fresh: bool) -> Option<NetworkSnapshot> {
        if !fresh {
            if let Some((at, s)) = &self.live().snap {
                if at.elapsed() < SNAPSHOT_TTL {
                    return s.clone();
                }
            }
        }
        let s = if self.sys.is_macos() {
            self.sys.snapshot().await
        } else {
            None
        };
        self.live().snap = Some((Instant::now(), s.clone()));
        s
    }

    async fn captive(&self, id: &str) -> bool {
        if let Some((at, v)) = self.live().captive.get(id) {
            if at.elapsed() < CAPTIVE_TTL {
                return *v;
            }
        }
        let v = self.sys.captive().await;
        self.live()
            .captive
            .insert(id.to_string(), (Instant::now(), v));
        v
    }

    /// Last scan of a network.
    pub async fn last_scan(&self, id: &str) -> Option<i64> {
        self.file.lock().await.get(id).and_then(|n| n.last_scan)
    }

    /// `lan_status`.
    pub async fn status(&self, cfg: &Config, network_id: Option<&str>) -> LanStatus {
        let snap = if self.is_scanning() {
            self.live().snap.as_ref().and_then(|(_, s)| s.clone())
        } else {
            self.snapshot(false).await
        };
        let current = snap.as_ref().and_then(|s| s.network_id());
        let wanted = network_id.map(str::to_string).or_else(|| current.clone());
        let trusted = &cfg.vpn.trusted_networks;
        let file = self.file.lock().await;
        let network = wanted.as_deref().map(|id| match file.get(id) {
            Some(n) => store::view(
                n,
                trusted.iter().any(|t| t == id),
                current.as_deref() == Some(id),
            ),
            None => LanNetwork {
                id: id.to_string(),
                name: snap.as_ref().map(|s| s.display_name()).unwrap_or_default(),
                interface: snap
                    .as_ref()
                    .map(|s| s.interface.clone())
                    .unwrap_or_default(),
                subnet: None,
                trusted: trusted.iter().any(|t| t == id),
                current: current.as_deref() == Some(id),
                last_scan: None,
                last_scan_mode: None,
                devices: vec![],
            },
        });
        let live = self.live();
        let message = live.message.clone().or_else(|| match (&snap, &current) {
            (None, _) if self.sys.is_macos() => Some("Hors ligne : aucun réseau local.".into()),
            (None, _) => Some("Inventaire du réseau local disponible sur macOS uniquement.".into()),
            (Some(_), None) => {
                Some("Adresse matérielle du routeur inconnue : réseau non identifiable.".into())
            }
            _ => None,
        });
        LanStatus {
            enabled: cfg.lan.enabled,
            scanning: live.scanning,
            progress: live.progress,
            phase: live.phase.clone(),
            network,
            networks: file.summaries(trusted, current.as_deref()),
            message,
            interval_minutes: cfg.lan.scan_interval_minutes,
        }
    }

    fn set_progress(&self, p: f32, phase: Option<&str>) {
        let mut l = self.live();
        l.progress = p.clamp(0.0, 1.0);
        l.phase = phase.map(str::to_string);
    }

    /// Scan the current network. `publish` receives the status at each step. `Busy` while another scan runs.
    pub async fn scan(
        &self,
        cfg: &Config,
        request: Option<bool>,
        publish: &(dyn Fn(LanStatus) + Send + Sync),
    ) -> Result<ScanOutcome, IpcError> {
        let _guard = self.scan_lock.try_lock().map_err(|_| {
            IpcError::new(
                ErrorCode::Busy,
                "une analyse du réseau local est déjà en cours",
            )
        })?;
        let snap = self.snapshot(true).await.ok_or_else(|| {
            IpcError::new(
                ErrorCode::Unavailable,
                "hors ligne : aucun réseau local à analyser",
            )
        })?;
        let id = snap.network_id().ok_or_else(|| {
            IpcError::new(
                ErrorCode::Unavailable,
                "adresse matérielle du routeur inconnue",
            )
        })?;
        let trusted = cfg.vpn.trusted_networks.contains(&id);
        let captive = if request.is_none() && trusted && cfg.lan.active_on_trusted {
            Some(self.captive(&id).await)
        } else {
            None
        };
        let (mode, note) = decide_mode(request, trusted, cfg.lan.active_on_trusted, captive);
        {
            let mut l = self.live();
            l.scanning = true;
            l.message = note.clone();
        }
        self.set_progress(0.0, Some("Préparation"));
        publish(self.status(cfg, Some(&id)).await);
        let step = |p: f32, phase: &str| self.set_progress(p, Some(phase));
        let result =
            probe::collect(self.sys.as_ref(), &snap, mode == LanScanMode::Active, &step).await;
        let macs: Vec<String> = result.observations.iter().map(|o| o.mac.clone()).collect();
        let oui = self.oui.clone();
        let vendors = tokio::task::spawn_blocking(move || oui::lookup(&oui, &macs))
            .await
            .unwrap_or_default();
        let now = pb_core::now_ts();
        let name = snap.display_name();
        let new_devices = {
            let mut file = self.file.lock().await;
            let net = file.network_mut(&id, &name, &snap.interface, now);
            if result.subnet.is_some() {
                net.subnet = result.subnet.clone();
            }
            let new = store::merge(net, result.observations, &vendors, mode, now);
            if let Err(e) = file.save(&self.dir) {
                tracing::warn!(error = %e, "lan.json not saved");
            }
            new
        };
        {
            let mut l = self.live();
            l.scanning = false;
            l.progress = 1.0;
            l.phase = None;
        }
        publish(self.status(cfg, Some(&id)).await);
        tracing::info!(network = %id, ?mode, new = new_devices.len(), "LAN scan done");
        Ok(ScanOutcome {
            network_id: id,
            network_name: name,
            trusted,
            mode,
            new_devices,
        })
    }

    /// Rename / mark known.
    pub async fn set_device(
        &self,
        network_id: &str,
        mac: &str,
        name: Option<String>,
        trusted: Option<bool>,
    ) -> Result<LanDevice, IpcError> {
        let (network_id, mac) = validate_ids(network_id, mac)?;
        let name = match name {
            Some(n) => Some(validate_name(&n)?),
            None => None,
        };
        let mut file = self.file.lock().await;
        let net = file
            .get_mut(&network_id)
            .ok_or_else(|| IpcError::new(ErrorCode::NotFound, "réseau inconnu"))?;
        let d = net
            .devices
            .iter_mut()
            .find(|d| d.mac == mac)
            .ok_or_else(|| IpcError::new(ErrorCode::NotFound, "appareil inconnu sur ce réseau"))?;
        if let Some(n) = name {
            d.name = (!n.is_empty()).then_some(n);
        }
        if let Some(t) = trusted {
            d.trusted = t;
        }
        let out = d.clone();
        file.save(&self.dir)
            .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?;
        Ok(out)
    }

    pub async fn forget(&self, network_id: &str, mac: &str) -> Result<(), IpcError> {
        let (network_id, mac) = validate_ids(network_id, mac)?;
        let mut file = self.file.lock().await;
        let net = file
            .get_mut(&network_id)
            .ok_or_else(|| IpcError::new(ErrorCode::NotFound, "réseau inconnu"))?;
        let before = net.devices.len();
        net.devices.retain(|d| d.mac != mac);
        if net.devices.len() == before {
            return Err(IpcError::new(
                ErrorCode::NotFound,
                "appareil inconnu sur ce réseau",
            ));
        }
        file.save(&self.dir)
            .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))
    }

    /// On-demand TCP check of the [`probe::TOP_PORTS`] of an online device of the current network.
    pub async fn ports(&self, mac: &str) -> Result<LanDevice, IpcError> {
        let mac = normalize_mac(mac).ok_or_else(|| bad("adresse matérielle invalide"))?;
        let _guard = self.scan_lock.try_lock().map_err(|_| {
            IpcError::new(ErrorCode::Busy, "une analyse du réseau local est en cours")
        })?;
        let id = self
            .snapshot(true)
            .await
            .and_then(|s| s.network_id())
            .ok_or_else(|| IpcError::new(ErrorCode::Unavailable, "hors ligne"))?;
        let ip = {
            let file = self.file.lock().await;
            let d = file
                .get(&id)
                .and_then(|n| n.devices.iter().find(|d| d.mac == mac))
                .ok_or_else(|| {
                    IpcError::new(ErrorCode::NotFound, "appareil absent du réseau actuel")
                })?;
            if !d.online || d.is_self {
                return Err(bad("appareil hors ligne (ou ce Mac)"));
            }
            d.ipv4
                .as_deref()
                .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                .ok_or_else(|| bad("appareil sans adresse IPv4"))?
        };
        let open = self
            .sys
            .tcp_open(ip, &probe::TOP_PORTS, probe::PORT_TIMEOUT)
            .await;
        let mut file = self.file.lock().await;
        let d = file
            .get_mut(&id)
            .and_then(|n| n.devices.iter_mut().find(|d| d.mac == mac))
            .ok_or_else(|| IpcError::new(ErrorCode::NotFound, "appareil oublié entre-temps"))?;
        d.open_ports = open;
        d.ports_checked_at = Some(pb_core::now_ts());
        if d.device_type == LanDeviceType::Unknown {
            d.device_type = classify::guess(&classify::Evidence {
                vendor: d.vendor.as_deref(),
                model: d.model.as_deref(),
                services: &d.services,
                open_ports: &d.open_ports,
                ..Default::default()
            });
        }
        let out = d.clone();
        file.save(&self.dir)
            .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?;
        Ok(out)
    }
}

fn validate_ids(network_id: &str, mac: &str) -> Result<(String, String), IpcError> {
    if !is_network_id(network_id) {
        return Err(bad(format!(
            "identifiant de réseau invalide : {network_id}"
        )));
    }
    let m = normalize_mac(mac).ok_or_else(|| bad("adresse matérielle invalide"))?;
    Ok((network_id.to_string(), m))
}

fn validate_name(n: &str) -> Result<String, IpcError> {
    let n = n.trim();
    if n.chars().count() > MAX_NAME || n.chars().any(char::is_control) {
        return Err(bad(format!("nom invalide (au plus {MAX_NAME} caractères)")));
    }
    Ok(n.to_string())
}

/// Label of a device in alerts.
pub fn device_label(d: &LanDevice) -> String {
    d.name
        .clone()
        .or_else(|| d.mdns_name.clone())
        .or_else(|| d.hostname.clone())
        .or_else(|| d.vendor.as_ref().map(|v| format!("Appareil {v}")))
        .unwrap_or_else(|| format!("Appareil {}", d.mac))
}

/// Alerts for the new devices of a scan (trusted networks only, see the module docs).
pub fn alerts_for(o: &ScanOutcome) -> Vec<(Alert, String)> {
    if !o.trusted {
        return vec![];
    }
    let devices: Vec<&LanDevice> = o
        .new_devices
        .iter()
        .filter(|d| !d.is_self && !d.is_gateway && !d.trusted)
        .collect();
    let mut out = Vec::new();
    for d in devices.iter().take(MAX_ALERTS_PER_SCAN) {
        let who = match (&d.vendor, d.private_mac) {
            (_, true) => {
                "adresse privée : un téléphone, une tablette ou un ordinateur récent, peut-être un \
                          appareil connu qui a changé d'adresse"
                    .to_string()
            }
            (Some(v), false) => format!("fabricant : {v}"),
            (None, false) => "fabricant inconnu".to_string(),
        };
        let ip = d.ipv4.clone().unwrap_or_else(|| "sans IPv4".into());
        let mut a = actions::alert(
            AlertKind::Network,
            Severity::Medium,
            "Nouvel appareil sur le réseau local",
            format!(
                "« {} » ({ip}, {}, {who}) vient d'apparaître sur {}. Si tu ne le reconnais pas, change le mot \
                 de passe du Wi-Fi et vérifie la liste des appareils dans l'interface de ta box.",
                device_label(d),
                d.mac,
                o.network_name
            ),
        );
        a.device_id = Some(format!("{ALERT_DEVICE_PREFIX}{}", d.mac));
        a.network_id = Some(o.network_id.clone());
        a.actions = vec![AlertAction::TrustLanDevice, AlertAction::Dismiss];
        out.push((a, format!("lan-new:{}:{}", o.network_id, d.mac)));
    }
    if devices.len() > MAX_ALERTS_PER_SCAN {
        let mut a = actions::alert(
            AlertKind::Network,
            Severity::Medium,
            "Plusieurs nouveaux appareils sur le réseau local",
            format!(
                "{} autres appareils inconnus sont apparus sur {}. Ouvre « Réseau local » pour les passer en revue.",
                devices.len() - MAX_ALERTS_PER_SCAN,
                o.network_name
            ),
        );
        a.network_id = Some(o.network_id.clone());
        out.push((a, format!("lan-many:{}", o.network_id)));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Daemon glue
// ---------------------------------------------------------------------------------------------

static SERVICE: OnceLock<Arc<LanService>> = OnceLock::new();

/// The service (created on first use).
pub fn service(ctx: &Ctx) -> Arc<LanService> {
    SERVICE
        .get_or_init(|| {
            LanService::new(
                ctx.paths.state_dir(),
                ctx.paths.db_current().join(pb_core::db::LAN_OUI),
                Arc::new(RealLanSystem::default()),
            )
        })
        .clone()
}

fn publisher(ctx: &Arc<Ctx>) -> impl Fn(LanStatus) + Send + Sync {
    let ctx = ctx.clone();
    move |s| ctx.bus.publish(DaemonEvent::Lan(s))
}

/// Scan, then raise the alerts the configuration asks for.
pub async fn scan_and_alert(
    ctx: &Arc<Ctx>,
    request: Option<bool>,
) -> Result<ScanOutcome, IpcError> {
    let cfg = ctx.config();
    let svc = service(ctx);
    let outcome = svc.scan(&cfg, request, &publisher(ctx)).await?;
    if cfg.lan.alert_new_devices {
        for (alert, key) in alerts_for(&outcome) {
            actions::raise_alert(ctx, alert, Some(key)).await;
        }
    }
    Ok(outcome)
}

pub async fn status(ctx: &Arc<Ctx>, network_id: Option<&str>) -> Result<LanStatus, IpcError> {
    if let Some(id) = network_id {
        if !is_network_id(id) {
            return Err(bad(format!("identifiant de réseau invalide : {id}")));
        }
    }
    Ok(service(ctx).status(&ctx.config(), network_id).await)
}

/// `lan_scan`: starts the scan in the background and answers with the status (progress follows as events).
pub async fn scan_now(ctx: &Arc<Ctx>, active: Option<bool>) -> Result<LanStatus, IpcError> {
    let svc = service(ctx);
    if svc.is_scanning() {
        return Ok(svc.status(&ctx.config(), None).await);
    }
    if !svc.sys.is_macos() {
        return Err(IpcError::new(
            ErrorCode::Unavailable,
            "inventaire du réseau local : macOS uniquement",
        ));
    }
    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        if let Err(e) = scan_and_alert(&ctx2, active).await {
            tracing::info!(error = %e.message, "LAN scan not run");
            service(&ctx2).live().message = Some(e.message);
            ctx2.bus.publish(DaemonEvent::Lan(
                service(&ctx2).status(&ctx2.config(), None).await,
            ));
        }
    });
    // Let the task flag the scan before answering.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut st = svc.status(&ctx.config(), None).await;
    st.scanning = true;
    Ok(st)
}

pub async fn set_device(
    ctx: &Arc<Ctx>,
    network_id: &str,
    mac: &str,
    name: Option<String>,
    trusted: Option<bool>,
) -> Result<LanDevice, IpcError> {
    let d = service(ctx)
        .set_device(network_id, mac, name, trusted)
        .await?;
    ctx.bus.publish(DaemonEvent::Lan(
        service(ctx).status(&ctx.config(), None).await,
    ));
    Ok(d)
}

pub async fn forget_device(ctx: &Arc<Ctx>, network_id: &str, mac: &str) -> Result<(), IpcError> {
    service(ctx).forget(network_id, mac).await
}

pub async fn check_ports(ctx: &Arc<Ctx>, mac: &str) -> Result<LanDevice, IpcError> {
    service(ctx).ports(mac).await
}

/// Periodic scans (see the module docs).
pub async fn run_loop(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    tokio::select! {
        _ = tokio::time::sleep(STARTUP_DELAY) => {}
        _ = shutdown.changed() => return,
    }
    loop {
        let cfg = ctx.config();
        let svc = service(&ctx);
        if cfg.lan.enabled
            && svc.sys.is_macos()
            && !ctx.should_defer_heavy_work()
            && !svc.is_scanning()
        {
            if let Some(id) = svc.snapshot(true).await.and_then(|s| s.network_id()) {
                let interval = i64::from(cfg.lan.scan_interval_minutes) * 60;
                let due = svc
                    .last_scan(&id)
                    .await
                    .is_none_or(|t| pb_core::now_ts() - t >= interval - 30);
                if due {
                    if let Err(e) = scan_and_alert(&ctx, None).await {
                        tracing::debug!(error = %e.message, "periodic LAN scan skipped");
                    }
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(TICK) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::probe::fake::FakeLan;
    use super::probe::tests::home_system;
    use super::*;

    fn svc(sys: FakeLan) -> (tempfile::TempDir, Arc<LanService>) {
        let d = tempfile::tempdir().unwrap();
        let oui = d.path().join("oui.tsv");
        std::fs::write(
            &oui,
            "0024D4\tFreebox SAS\n90DD5D\tApple, Inc.\n305A3A\tHewlett Packard\n",
        )
        .unwrap();
        let s = LanService::new(d.path().to_path_buf(), oui, Arc::new(sys));
        (d, s)
    }

    fn trusted_cfg() -> Config {
        let mut c = Config::default();
        c.vpn.trusted_networks = vec!["gw:00:24:d4:a1:b2:c3".into()];
        c
    }

    #[test]
    fn mode_policy() {
        assert_eq!(
            decide_mode(None, true, true, Some(false)).0,
            LanScanMode::Active
        );
        assert_eq!(decide_mode(None, false, true, None).0, LanScanMode::Passive);
        assert!(decide_mode(None, false, true, None)
            .1
            .unwrap()
            .contains("non marqué"));
        assert_eq!(
            decide_mode(None, true, true, Some(true)).0,
            LanScanMode::Passive
        );
        assert_eq!(decide_mode(None, true, false, None).0, LanScanMode::Passive);
        assert_eq!(
            decide_mode(Some(true), false, false, None).0,
            LanScanMode::Active
        );
        assert_eq!(
            decide_mode(Some(false), true, true, None).0,
            LanScanMode::Passive
        );
    }

    #[tokio::test]
    async fn untrusted_network_is_scanned_passively_without_alerts() {
        let (_d, s) = svc(home_system());
        let o = s.scan(&Config::default(), None, &|_| {}).await.unwrap();
        assert_eq!(o.mode, LanScanMode::Passive);
        assert!(!o.trusted && o.new_devices.is_empty());
        let st = s.status(&Config::default(), None).await;
        let net = st.network.unwrap();
        assert_eq!(net.devices.len(), 6);
        assert!(st.message.unwrap().contains("non marqué"));
        assert_eq!(net.last_scan_mode, Some(LanScanMode::Passive));
        let gw = net.devices.iter().find(|d| d.is_gateway).unwrap();
        assert_eq!(gw.vendor.as_deref(), Some("Freebox SAS"));
    }

    #[tokio::test]
    async fn trusted_network_active_scan_then_new_device_alert() {
        let sys = home_system();
        let (_d, s) = svc(sys);
        let cfg = trusted_cfg();
        let events = Mutex::new(0usize);
        let o = s
            .scan(&cfg, None, &|_| *events.lock().unwrap() += 1)
            .await
            .unwrap();
        assert_eq!(o.mode, LanScanMode::Active);
        assert!(o.new_devices.is_empty(), "first scan is the baseline");
        assert!(*events.lock().unwrap() >= 2);
        let st = s.status(&cfg, None).await;
        let net = st.network.unwrap();
        let printer = net
            .devices
            .iter()
            .find(|d| d.mac == "30:5a:3a:44:55:66")
            .unwrap();
        assert_eq!(printer.device_type, LanDeviceType::Printer);
        let tv = net
            .devices
            .iter()
            .find(|d| d.mac == "90:dd:5d:11:22:33")
            .unwrap();
        assert_eq!(tv.device_type, LanDeviceType::Tv);
        // A new device appears: forget one and rescan.
        s.forget("gw:00:24:d4:a1:b2:c3", "3A:5F:12:9C:7E:01")
            .await
            .unwrap();
        let o = s.scan(&cfg, None, &|_| {}).await.unwrap();
        assert_eq!(o.new_devices.len(), 1);
        let alerts = alerts_for(&o);
        assert_eq!(alerts.len(), 1);
        let (a, key) = &alerts[0];
        assert_eq!(a.device_id.as_deref(), Some("lan:3a:5f:12:9c:7e:01"));
        assert_eq!(
            a.actions,
            vec![AlertAction::TrustLanDevice, AlertAction::Dismiss]
        );
        assert!(a.message.contains("adresse privée"));
        assert_eq!(key, "lan-new:gw:00:24:d4:a1:b2:c3:3a:5f:12:9c:7e:01");
        // Mark it known, rename it.
        let d = s
            .set_device(
                "gw:00:24:d4:a1:b2:c3",
                "3a:5f:12:9c:7e:01",
                Some(" iPhone de Camille ".into()),
                Some(true),
            )
            .await
            .unwrap();
        assert!(d.trusted && d.name.as_deref() == Some("iPhone de Camille"));
        assert!(s
            .set_device("gw:00:24:d4:a1:b2:c3", "zz", None, None)
            .await
            .is_err());
        assert!(s
            .set_device("gw:bad", "3a:5f:12:9c:7e:01", None, None)
            .await
            .is_err());
        assert!(s
            .set_device(
                "gw:00:24:d4:a1:b2:c3",
                "3a:5f:12:9c:7e:01",
                Some("x\u{7}".into()),
                None
            )
            .await
            .is_err());
        // Persisted.
        let again = LanService::new(s.dir.clone(), s.oui.clone(), Arc::new(home_system()));
        let st = again.status(&cfg, Some("gw:00:24:d4:a1:b2:c3")).await;
        assert!(st
            .network
            .unwrap()
            .devices
            .iter()
            .any(|d| d.name.as_deref() == Some("iPhone de Camille")));
    }

    #[tokio::test]
    async fn captive_portal_keeps_trusted_scan_passive_and_ports_on_demand() {
        let mut sys = home_system();
        sys.captive = true;
        sys.open_ports = vec![80, 9100, 631];
        let (_d, s) = svc(sys);
        let o = s.scan(&trusted_cfg(), None, &|_| {}).await.unwrap();
        assert_eq!(o.mode, LanScanMode::Passive);
        let d = s.ports("30:5a:3a:44:55:66").await.unwrap();
        assert_eq!(d.open_ports, vec![80, 631, 9100]);
        assert!(d.ports_checked_at.is_some());
        assert!(s.ports("3c:22:fb:01:02:03").await.is_err(), "not this Mac");
        assert!(s.ports("aa:aa:aa:aa:aa:aa").await.is_err());
    }

    #[test]
    fn many_new_devices_are_summarised() {
        let dev = |i: u8| LanDevice {
            mac: format!("00:11:22:33:44:{i:02x}"),
            ipv4: None,
            ipv6: vec![],
            hostname: None,
            mdns_name: None,
            name: None,
            vendor: None,
            private_mac: false,
            device_type: LanDeviceType::Unknown,
            model: None,
            services: vec![],
            open_ports: vec![],
            ports_checked_at: None,
            first_seen: 0,
            last_seen: 0,
            online: true,
            trusted: false,
            baseline: false,
            is_gateway: false,
            is_self: false,
        };
        let mut o = ScanOutcome {
            network_id: "gw:00:24:d4:a1:b2:c3".into(),
            network_name: "Maison".into(),
            trusted: true,
            mode: LanScanMode::Active,
            new_devices: (0..8).map(dev).collect(),
        };
        let a = alerts_for(&o);
        assert_eq!(a.len(), MAX_ALERTS_PER_SCAN + 1);
        assert!(a.last().unwrap().0.message.starts_with("3 autres"));
        o.trusted = false;
        assert!(alerts_for(&o).is_empty());
    }
}
