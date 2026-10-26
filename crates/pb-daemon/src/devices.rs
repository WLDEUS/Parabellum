//! Devices: first-run baseline, alerts on new devices (BadUSB keyboards first), opt-in HID blocking,
//! volume auto-scan, trust decisions (trust / block / forget).

use crate::actions;
use crate::backends::ScanOpts;
use crate::baseline;
use crate::ctx::Ctx;
use crate::jobs::{self, JobSpec};
use crate::store::{AlertKey, StatField};
use pb_core::config::Config;
use pb_core::ipc::{DaemonEvent, ErrorCode, IpcError};
use pb_core::model::*;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Ordered worker for device events.
pub async fn run_worker(ctx: Arc<Ctx>, mut rx: mpsc::Receiver<DeviceEvent>) {
    while let Some(ev) = rx.recv().await {
        handle_event(&ctx, ev).await;
    }
}

fn detail<'a>(d: &'a DeviceInfo, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|k| d.details.get(*k))
        .map(String::as_str)
        .filter(|v| !v.is_empty())
}

fn truthy(v: Option<&str>) -> bool {
    matches!(
        v.map(|s| s.to_ascii_lowercase()).as_deref(),
        Some("true" | "yes" | "1")
    )
}

/// Mount point of a volume device.
pub fn mount_point(d: &DeviceInfo) -> Option<String> {
    detail(d, &["mount_point", "mountpoint", "mount", "path"])
        .filter(|m| m.starts_with('/'))
        .map(str::to_string)
}

/// HID device exposing a keyboard interface (pb-monitor sets `details["is_keyboard"]`; name heuristics
/// only when the key is absent).
pub fn is_keyboard(d: &DeviceInfo) -> bool {
    if d.kind != DeviceKind::Hid {
        return false;
    }
    if let Some(v) = detail(d, &["is_keyboard", "keyboard"]) {
        return truthy(Some(v));
    }
    let name = d.name.to_ascii_lowercase();
    name.contains("keyboard") || name.contains("clavier")
}

/// Built-in device (internal keyboard / trackpad): `details["built_in"]`, else SPI transport.
pub fn is_builtin(d: &DeviceInfo) -> bool {
    if let Some(v) = detail(d, &["built_in", "builtin"]) {
        return truthy(Some(v));
    }
    matches!(
        d.transport
            .as_deref()
            .map(str::to_ascii_uppercase)
            .as_deref(),
        Some("SPI" | "BUILT-IN")
    )
}

/// Alert severity for a new device, `None` when alerts are off for its kind.
pub fn new_device_severity(cfg: &Config, d: &DeviceInfo) -> Option<Severity> {
    let c = &cfg.devices;
    match d.kind {
        DeviceKind::Hid if c.alert_new_hid => Some(if is_keyboard(d) {
            Severity::High
        } else {
            Severity::Medium
        }),
        // HID and storage functions get their own (HID / volume) events.
        DeviceKind::Usb
            if c.alert_other_usb
                && !truthy(detail(d, &["has_hid"]))
                && !truthy(detail(d, &["has_storage"])) =>
        {
            Some(Severity::Medium)
        }
        DeviceKind::Thunderbolt if c.alert_thunderbolt => Some(Severity::Medium),
        DeviceKind::NetworkInterface if c.alert_network_interfaces => Some(Severity::Medium),
        DeviceKind::Bluetooth if c.alert_bluetooth => Some(Severity::Medium),
        DeviceKind::WifiNetwork if c.alert_wifi_networks => Some(Severity::Low),
        DeviceKind::Volume => Some(Severity::Info),
        _ => None,
    }
}

fn kind_label(k: DeviceKind) -> &'static str {
    match k {
        DeviceKind::Volume => "Volume",
        DeviceKind::Hid => "Périphérique HID",
        DeviceKind::Usb => "Périphérique USB",
        DeviceKind::Bluetooth => "Appareil Bluetooth",
        DeviceKind::NetworkInterface => "Interface réseau",
        DeviceKind::Thunderbolt => "Périphérique Thunderbolt",
        DeviceKind::WifiNetwork => "Réseau Wi-Fi",
    }
}

fn describe(d: &DeviceInfo) -> String {
    let mut s = format!(
        "{} « {} »",
        if is_keyboard(d) {
            "Clavier"
        } else {
            kind_label(d.kind)
        },
        d.name
    );
    if let Some(v) = &d.vendor {
        s.push_str(&format!(" ({v})"));
    }
    if let (Some(v), Some(p)) = (d.vendor_id, d.product_id) {
        s.push_str(&format!(" [{v:04x}:{p:04x}]"));
    }
    if let Some(t) = &d.transport {
        s.push_str(&format!(" via {t}"));
    }
    s
}

fn publish(ctx: &Ctx, device: &DeviceInfo, change: DeviceChange) {
    ctx.bus.publish(DaemonEvent::Device(DeviceEvent {
        device: device.clone(),
        change,
    }));
}

async fn save(ctx: &Arc<Ctx>, d: &DeviceInfo) {
    let d2 = d.clone();
    if let Err(e) = ctx.store.run(move |s| s.upsert_device(&d2)).await {
        tracing::error!(error = %e, "cannot store device");
    }
}

/// Handle a device event from the watcher.
pub async fn handle_event(ctx: &Arc<Ctx>, ev: DeviceEvent) {
    let now = pb_core::now_ts();
    let mut dev = ev.device;
    // DMGs mounted by the engine itself under tmp/ are not user devices.
    if dev.kind == DeviceKind::Volume
        && mount_point(&dev)
            .map(|m| std::path::Path::new(&m).starts_with(ctx.paths.tmp_dir()))
            .unwrap_or(false)
    {
        return;
    }
    let id = dev.id.clone();
    let existing = match ctx.store.run(move |s| s.get_device(&id)).await {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "device lookup failed");
            return;
        }
    };
    if ev.change == DeviceChange::Disconnected {
        if let Some(mut e) = existing {
            e.connected = false;
            e.last_seen = now;
            save(ctx, &e).await;
            publish(ctx, &e, DeviceChange::Disconnected);
        }
        return;
    }
    let cfg = ctx.config();
    match existing {
        Some(prev) => {
            dev.first_seen = prev.first_seen;
            dev.trust = prev.trust;
            dev.baseline = prev.baseline;
            dev.connected = true;
            dev.last_seen = now;
            save(ctx, &dev).await;
            publish(ctx, &dev, DeviceChange::Connected);
            match dev.trust {
                DeviceTrust::Blocked => {
                    if let Err(e) = enforce_block(ctx, &dev).await {
                        tracing::warn!(device = %dev.id, error = %e.message, "cannot re-apply block");
                    }
                    let since = now - 3600;
                    let did = dev.id.clone();
                    let recent = ctx
                        .store
                        .run(move |s| {
                            s.find_recent_alert_by(AlertKind::Device, AlertKey::Device(&did), since)
                        })
                        .await
                        .ok()
                        .flatten();
                    if recent.is_none() {
                        let mut a = actions::alert(
                            AlertKind::Device,
                            Severity::Medium,
                            "Périphérique bloqué reconnecté",
                            format!("{} a été reconnecté ; il reste bloqué.", describe(&dev)),
                        );
                        a.device_id = Some(dev.id.clone());
                        a.actions = vec![AlertAction::TrustDevice, AlertAction::Acknowledge];
                        actions::raise_alert(ctx, a, None).await;
                    }
                }
                DeviceTrust::Unknown => {
                    if cfg.devices.block_new_hid
                        && is_keyboard(&dev)
                        && !is_builtin(&dev)
                        && !dev.baseline
                    {
                        if let Err(e) = block_hid(ctx, &dev).await {
                            tracing::warn!(device = %dev.id, error = %e.message, "cannot block keyboard");
                        }
                    }
                    maybe_scan_volume(ctx, &cfg, &dev).await;
                }
                DeviceTrust::Trusted => maybe_scan_volume(ctx, &cfg, &dev).await,
            }
        }
        None => {
            dev.first_seen = now;
            dev.last_seen = now;
            dev.connected = true;
            dev.trust = DeviceTrust::Unknown;
            if baseline::in_window(ctx, baseline::Kind::Devices) {
                dev.baseline = true;
                save(ctx, &dev).await;
                publish(ctx, &dev, DeviceChange::New);
                return;
            }
            dev.baseline = false;
            save(ctx, &dev).await;
            ctx.bump_stat(StatField::DevicesNew, 1).await;
            publish(ctx, &dev, DeviceChange::New);
            let blocked = cfg.devices.block_new_hid && is_keyboard(&dev) && !is_builtin(&dev);
            let mut block_note = String::new();
            if blocked {
                match block_hid(ctx, &dev).await {
                    Ok(()) => block_note = " Saisie bloquée jusqu'à votre accord.".into(),
                    Err(e) => block_note = format!(" Blocage impossible : {}.", e.message),
                }
            }
            if let Some(severity) = new_device_severity(&cfg, &dev) {
                let (title, msg) = if dev.kind == DeviceKind::Hid && is_keyboard(&dev) {
                    (
                        "Nouveau clavier connecté",
                        format!(
                            "{} vient d'apparaître. Si vous n'avez pas branché de clavier, il peut s'agir d'une attaque BadUSB.{block_note}",
                            describe(&dev)
                        ),
                    )
                } else if dev.kind == DeviceKind::Volume {
                    let mp = mount_point(&dev)
                        .map(|m| format!(" monté sur {m}"))
                        .unwrap_or_default();
                    ("Nouveau volume", format!("{}{mp}.", describe(&dev)))
                } else {
                    (
                        "Nouveau périphérique",
                        format!("{} détecté pour la première fois.", describe(&dev)),
                    )
                };
                let mut a = actions::alert(AlertKind::Device, severity, title, msg);
                a.device_id = Some(dev.id.clone());
                a.actions = vec![
                    AlertAction::TrustDevice,
                    AlertAction::BlockDevice,
                    AlertAction::Acknowledge,
                ];
                actions::raise_alert(ctx, a, None).await;
            }
            maybe_scan_volume(ctx, &cfg, &dev).await;
        }
    }
}

async fn maybe_scan_volume(ctx: &Arc<Ctx>, cfg: &Config, dev: &DeviceInfo) {
    if dev.kind != DeviceKind::Volume
        || !cfg.devices.scan_volumes
        || dev.trust == DeviceTrust::Blocked
    {
        return;
    }
    let Some(mp) = mount_point(dev) else {
        tracing::debug!(device = %dev.id, "volume without mount point");
        return;
    };
    if ctx
        .jobs
        .active()
        .iter()
        .any(|j| j.origin() == ScanOrigin::Volume && j.spec.paths.contains(&mp))
    {
        return;
    }
    let spec = JobSpec {
        paths: vec![mp.clone()],
        roots: vec![PathBuf::from(&mp)],
        opts: ScanOpts {
            origin: ScanOrigin::Volume,
            use_clamav: cfg.scan.clamav_on_demand,
            recursive: true,
            only_risky_types: true,
        },
    };
    match jobs::submit(ctx, spec).await {
        Ok(id) => tracing::info!(job = %id, mount = %mp, "volume scan queued"),
        Err(e) => tracing::warn!(mount = %mp, error = %e.message, "cannot queue volume scan"),
    }
}

async fn block_hid(ctx: &Arc<Ctx>, dev: &DeviceInfo) -> Result<(), IpcError> {
    let m = ctx.backends.monitors.clone();
    let d = dev.clone();
    tokio::task::spawn_blocking(move || m.block_hid(&d))
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?
        .map_err(IpcError::from)
}

async fn enforce_block(ctx: &Arc<Ctx>, dev: &DeviceInfo) -> Result<(), IpcError> {
    match dev.kind {
        DeviceKind::Hid => block_hid(ctx, dev).await,
        DeviceKind::Volume => match mount_point(dev) {
            Some(mp) if dev.connected => crate::system::diskutil_unmount_force(&mp)
                .await
                .map_err(|e| IpcError::new(ErrorCode::Unavailable, e)),
            _ => Ok(()),
        },
        // Others: remembered; reconnections raise an alert.
        _ => Ok(()),
    }
}

/// Trust / block / forget (`unknown`) a device.
pub async fn set_device_trust(
    ctx: &Arc<Ctx>,
    id: &str,
    trust: DeviceTrust,
) -> Result<DeviceInfo, IpcError> {
    let id2 = id.to_string();
    let mut dev = ctx
        .store
        .run(move |s| s.get_device(&id2))
        .await?
        .ok_or_else(|| {
            IpcError::new(
                ErrorCode::NotFound,
                format!("périphérique {id} introuvable"),
            )
        })?;
    let previous = dev.trust;
    dev.trust = trust;
    save(ctx, &dev).await;
    let did = dev.id.clone();
    let open = ctx
        .store
        .run(move |s| s.open_alerts_by(AlertKey::Device(&did)))
        .await
        .unwrap_or_default();
    for mut a in open {
        a.status = AlertStatus::Resolved;
        a.actions.clear();
        let _ = actions::save_alert(ctx, &a).await;
    }
    publish(
        ctx,
        &dev,
        if dev.connected {
            DeviceChange::Connected
        } else {
            DeviceChange::Disconnected
        },
    );
    match trust {
        DeviceTrust::Blocked => enforce_block(ctx, &dev).await?,
        DeviceTrust::Trusted | DeviceTrust::Unknown => {
            if dev.kind == DeviceKind::Hid
                && (previous == DeviceTrust::Blocked || ctx.config().devices.block_new_hid)
            {
                let m = ctx.backends.monitors.clone();
                let did = dev.id.clone();
                let res = tokio::task::spawn_blocking(move || m.unblock_hid(&did)).await;
                if let Ok(Err(e)) = res {
                    tracing::warn!(device = %dev.id, error = %e, "cannot unblock HID device");
                }
            }
        }
    }
    tracing::info!(device = %dev.id, ?trust, "device trust changed");
    Ok(dev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn dev(kind: DeviceKind, name: &str, details: &[(&str, &str)]) -> DeviceInfo {
        DeviceInfo {
            id: format!("x:{name}"),
            kind,
            name: name.into(),
            vendor: None,
            vendor_id: Some(0x05ac),
            product_id: Some(0x0281),
            serial: None,
            transport: Some("USB".into()),
            details: details
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
            first_seen: 0,
            last_seen: 0,
            connected: true,
            trust: DeviceTrust::Unknown,
            baseline: false,
        }
    }

    #[test]
    fn classification() {
        assert!(is_keyboard(&dev(DeviceKind::Hid, "Magic Keyboard", &[])));
        assert!(is_keyboard(&dev(
            DeviceKind::Hid,
            "Gadget",
            &[("is_keyboard", "true")]
        )));
        assert!(!is_keyboard(&dev(
            DeviceKind::Hid,
            "Keyboard-ish mouse",
            &[("is_keyboard", "false")]
        )));
        assert!(!is_builtin(&dev(
            DeviceKind::Hid,
            "K",
            &[("built_in", "false")]
        )));
        assert!(is_builtin(&dev(
            DeviceKind::Hid,
            "K",
            &[("built_in", "true")]
        )));
        let cfg = Config::default();
        assert_eq!(
            new_device_severity(&cfg, &dev(DeviceKind::Usb, "Hub", &[("has_hid", "true")])),
            None
        );
        assert_eq!(
            new_device_severity(
                &cfg,
                &dev(DeviceKind::Usb, "Serial", &[("has_hid", "false")])
            ),
            Some(Severity::Medium)
        );
        assert!(!is_keyboard(&dev(DeviceKind::Hid, "Mouse", &[])));
        assert!(!is_keyboard(&dev(DeviceKind::Usb, "Keyboard hub", &[])));
        let mut internal = dev(DeviceKind::Hid, "Apple Internal Keyboard", &[]);
        internal.transport = Some("SPI".into());
        assert!(is_builtin(&internal));
        assert_eq!(
            mount_point(&dev(
                DeviceKind::Volume,
                "KEY",
                &[("mount_point", "/Volumes/KEY")]
            ))
            .as_deref(),
            Some("/Volumes/KEY")
        );
        assert_eq!(
            mount_point(&dev(DeviceKind::Volume, "KEY", &[("mount_point", "rel")])),
            None
        );
    }

    #[test]
    fn severities() {
        let mut cfg = Config::default();
        assert_eq!(
            new_device_severity(&cfg, &dev(DeviceKind::Hid, "Keyboard", &[])),
            Some(Severity::High)
        );
        assert_eq!(
            new_device_severity(&cfg, &dev(DeviceKind::Hid, "Mouse", &[])),
            Some(Severity::Medium)
        );
        assert_eq!(
            new_device_severity(&cfg, &dev(DeviceKind::WifiNetwork, "Cafe", &[])),
            Some(Severity::Low)
        );
        assert_eq!(
            new_device_severity(&cfg, &dev(DeviceKind::Volume, "KEY", &[])),
            Some(Severity::Info)
        );
        cfg.devices.alert_wifi_networks = false;
        assert_eq!(
            new_device_severity(&cfg, &dev(DeviceKind::WifiNetwork, "Cafe", &[])),
            None
        );
        assert!(describe(&dev(DeviceKind::Hid, "Keyboard", &[])).contains("[05ac:0281]"));
    }
}
