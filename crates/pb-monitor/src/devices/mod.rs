//! [`DeviceWatcher`]: volumes, USB / HID / Thunderbolt (IOKit), Bluetooth, network interfaces and
//! known Wi-Fi networks, reported as `MonitorEvent::Device(DeviceEvent { change: Connected |
//! Disconnected })`. At startup every present device is reported `Connected`; the daemon turns
//! unknown devices into `New` and owns trust / baseline / alerts.
//!
//! Device ids (stable across reboots): `vol:<volume uuid>`, `usb:<vid>:<pid>:<serial|loc-…>`,
//! `hid:<vid>:<pid>:<serial|loc-…>`, `tb:<switch uid>`, `bt:<address>`, `net:<bsd name>:<mac>`,
//! `wifi:<ssid>`. Useful `details` keys: volumes `mount_point`, `protocol`, `filesystem`,
//! `internal`, `disk_image`; HID `is_keyboard`, `built_in`, `usage_page`, `usage`; USB
//! `interface_classes`, `has_hid`, `has_storage`, `built_in`; Thunderbolt `depth`, `built_in`.
//!
//! Resource use: IOKit notifications and FSEvents are event-driven; the only polls are
//! `getifaddrs` every 15 s, `getfsstat` every 30 s (both cheap syscalls) and `system_profiler
//! SPBluetoothDataType` every 15 min. `diskutil` runs once per new mount, `networksetup` only when
//! the interface list changes.

pub mod parse;
pub mod sys;

mod hid_block;
#[cfg(target_os = "macos")]
mod iokit;

pub use hid_block::HidBlocker;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pb_core::events::MonitorEvent;
use pb_core::model::{DeviceChange, DeviceEvent, DeviceInfo, DeviceKind};
use plist::Dictionary;
use tokio::sync::mpsc;

use crate::util::{
    is_shutdown, read_file_bounded, run_command_ok, send_health, sleep_or_shutdown, wait_shutdown,
    Backoff,
};
use crate::{volume_trigger, MonitorContext, MONITOR_DEVICES};
use parse::{
    hid_from_props, is_reportable_mount, new_device, parse_bluetooth_prefs, parse_diskutil_info,
    parse_ioreg_archive, parse_known_networks, parse_mobile_bluetooth_devices,
    parse_networksetup_ports, parse_system_profiler_bluetooth, parse_system_profiler_thunderbolt,
    thunderbolt_from_props, usb_from_props, volume_from_diskutil, volume_from_mount,
};
use sys::{LinkInterface, MountEntry, VOLUME_ROOTS};

const DISKUTIL: &str = "/usr/sbin/diskutil";
const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const SYSTEM_PROFILER: &str = "/usr/sbin/system_profiler";
const IOREG: &str = "/usr/sbin/ioreg";
const PREFS_DIR: &str = "/Library/Preferences";
const BT_PREFS_DIR: &str = "/Library/Bluetooth/Library/Preferences";
const LEGACY_BT_PLIST: &str = "/Library/Preferences/com.apple.Bluetooth.plist";
const MOBILE_BT_PLIST: &str =
    "/Library/Bluetooth/Library/Preferences/com.apple.MobileBluetooth.devices.plist";
const KNOWN_NETWORKS_PLIST: &str = "/Library/Preferences/com.apple.wifi.known-networks.plist";
const MAX_PREF_PLIST: u64 = 8 * 1024 * 1024;

const NET_POLL: Duration = Duration::from_secs(15);
const VOLUME_POLL: Duration = Duration::from_secs(30);
const BT_PROFILER_POLL: Duration = Duration::from_secs(15 * 60);
const IOREG_POLL: Duration = Duration::from_secs(15);
const NETWORKSETUP_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// Interface name prefixes that are virtual / system (ignored unless `networksetup` lists them as
/// a hardware port).
pub const IGNORED_INTERFACE_PREFIXES: &[&str] = &[
    "lo", "utun", "awdl", "llw", "anpi", "ap", "bridge", "gif", "stf", "XHC", "ipsec", "pktap",
    "vmenet", "docker", "veth", "br-",
];

/// IORegistry classes followed for USB / HID / Thunderbolt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IoClass {
    Usb,
    Hid,
    Thunderbolt,
}

impl IoClass {
    pub(crate) const ALL: [IoClass; 3] = [IoClass::Usb, IoClass::Hid, IoClass::Thunderbolt];

    /// IOKit class name (matches subclasses too).
    pub(crate) fn class_name(self) -> &'static CStr {
        match self {
            IoClass::Usb => c"IOUSBHostDevice",
            IoClass::Hid => c"IOHIDDevice",
            IoClass::Thunderbolt => c"IOThunderboltSwitch",
        }
    }

    pub(crate) fn parse(self, d: &Dictionary) -> Option<DeviceInfo> {
        match self {
            IoClass::Usb => usb_from_props(d),
            IoClass::Hid => hid_from_props(d),
            IoClass::Thunderbolt => thunderbolt_from_props(d),
        }
    }
}

/// Compares two snapshots keyed by device id: ids only in `new` -> `Connected` (device from
/// `new`); ids only in `old` -> `Disconnected` (device from `old`, `connected = false`).
pub fn diff_devices(
    old: &BTreeMap<String, DeviceInfo>,
    new: &BTreeMap<String, DeviceInfo>,
) -> Vec<DeviceEvent> {
    let now = pb_core::now_ts();
    let mut out = Vec::new();
    for (id, d) in new {
        if !old.contains_key(id) {
            let mut device = d.clone();
            device.connected = true;
            out.push(DeviceEvent {
                device,
                change: DeviceChange::Connected,
            });
        }
    }
    for (id, d) in old {
        if !new.contains_key(id) {
            let mut device = d.clone();
            device.connected = false;
            device.last_seen = now;
            out.push(DeviceEvent {
                device,
                change: DeviceChange::Disconnected,
            });
        }
    }
    out
}

/// Reference counting for event-based sources: several registry entries (HID interfaces) can map
/// to the same device id; `Connected` on 0 -> 1, `Disconnected` on 1 -> 0.
#[derive(Debug, Default)]
pub(crate) struct RefTracker {
    entries: HashMap<u64, String>,
    refs: HashMap<String, (usize, DeviceInfo)>,
}

impl RefTracker {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn arrive(&mut self, entry_id: u64, dev: DeviceInfo) -> Option<DeviceEvent> {
        if let Some(prev) = self.entries.get(&entry_id) {
            if *prev == dev.id {
                return None; // duplicate notification
            }
            // Same registry entry re-described with a different id: treat as departure first.
            let _ = self.depart(entry_id);
        }
        self.entries.insert(entry_id, dev.id.clone());
        let slot = self
            .refs
            .entry(dev.id.clone())
            .or_insert_with(|| (0, dev.clone()));
        slot.0 += 1;
        (slot.0 == 1).then_some(DeviceEvent {
            device: dev,
            change: DeviceChange::Connected,
        })
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn depart(&mut self, entry_id: u64) -> Option<DeviceEvent> {
        let id = self.entries.remove(&entry_id)?;
        let slot = self.refs.get_mut(&id)?;
        slot.0 = slot.0.saturating_sub(1);
        if slot.0 > 0 {
            return None;
        }
        let (_, mut device) = self.refs.remove(&id)?;
        device.connected = false;
        device.last_seen = pb_core::now_ts();
        Some(DeviceEvent {
            device,
            change: DeviceChange::Disconnected,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.refs.len()
    }
}

/// Builds the network-interface snapshot from `getifaddrs` + `networksetup` hardware ports.
/// The permanent MAC from `networksetup` is preferred (macOS rotates private Wi-Fi addresses).
pub(crate) fn build_net_snapshot(
    ifs: &[LinkInterface],
    ports: &BTreeMap<String, (String, Option<String>)>,
) -> BTreeMap<String, DeviceInfo> {
    let mut out = BTreeMap::new();
    for i in ifs {
        let port = ports.get(&i.name);
        if port.is_none()
            && IGNORED_INTERFACE_PREFIXES
                .iter()
                .any(|p| i.name.starts_with(p))
        {
            continue;
        }
        let Some(mac) = port.and_then(|p| p.1.clone()).or_else(|| i.mac.clone()) else {
            continue;
        };
        let name = port.map(|p| p.0.clone()).unwrap_or_else(|| i.name.clone());
        let mut d = new_device(
            format!("net:{}:{}", parse::id_part(&i.name), mac),
            DeviceKind::NetworkInterface,
            name,
        );
        d.transport = Some("Network".into());
        d.details.insert("bsd_name".into(), i.name.clone());
        d.details.insert("mac".into(), mac);
        if let Some(cur) = &i.mac {
            d.details.insert("current_mac".into(), cur.clone());
        }
        if let Some((p, _)) = port {
            d.details.insert("hardware_port".into(), p.clone());
        }
        out.insert(d.id.clone(), d);
    }
    out
}

fn describe_volume(m: &MountEntry) -> Option<DeviceInfo> {
    let network = matches!(
        m.fstype.as_str(),
        "smbfs" | "afpfs" | "nfs" | "webdav" | "ftp"
    );
    if !network && Path::new(DISKUTIL).is_file() {
        let mp = m.mount_point.to_string_lossy();
        match run_command_ok(
            DISKUTIL,
            &["info", "-plist", &mp],
            Duration::from_secs(15),
            1024 * 1024,
        ) {
            Ok(bytes) => match parse_diskutil_info(&bytes) {
                Ok(d) => return volume_from_diskutil(&d, m),
                Err(e) => tracing::debug!(mount = %mp, error = %e, "diskutil output unparsable"),
            },
            Err(e) => tracing::debug!(mount = %mp, error = %e, "diskutil failed"),
        }
    }
    Some(volume_from_mount(m))
}

/// Mounted volumes; `diskutil` runs once per (mount point, source).
fn snapshot_volumes(
    own_root: &Path,
    cache: &mut HashMap<(PathBuf, String), Option<DeviceInfo>>,
) -> BTreeMap<String, DeviceInfo> {
    let mut out = BTreeMap::new();
    let mut live = HashSet::new();
    for m in sys::list_mounts()
        .into_iter()
        .filter(|m| is_reportable_mount(m, VOLUME_ROOTS, own_root))
        .take(256)
    {
        let key = (m.mount_point.clone(), m.mount_from.clone());
        live.insert(key.clone());
        if let Some(d) = cache
            .entry(key)
            .or_insert_with(|| describe_volume(&m))
            .clone()
        {
            out.insert(d.id.clone(), d);
        }
    }
    cache.retain(|k, _| live.contains(k));
    out
}

fn read_plist_file<T>(path: &str, parse: fn(&[u8]) -> Result<T, crate::MonitorError>) -> Option<T> {
    match read_file_bounded(Path::new(path), MAX_PREF_PLIST) {
        Ok(b) => parse(&b)
            .map_err(|e| tracing::debug!(path, error = %e, "unparsable preferences"))
            .ok(),
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::debug!(path, error = %e, "preferences unreadable");
            }
            None
        }
    }
}

/// Paired Bluetooth devices from the preference plists (modern + legacy).
fn snapshot_bt_plists() -> BTreeMap<String, DeviceInfo> {
    let mut out = BTreeMap::new();
    for list in [
        read_plist_file(MOBILE_BT_PLIST, parse_mobile_bluetooth_devices),
        read_plist_file(LEGACY_BT_PLIST, parse_bluetooth_prefs),
    ]
    .into_iter()
    .flatten()
    {
        for d in list {
            out.entry(d.id.clone()).or_insert(d);
        }
    }
    out
}

fn snapshot_bt_profiler() -> Option<BTreeMap<String, DeviceInfo>> {
    if !Path::new(SYSTEM_PROFILER).is_file() {
        return None;
    }
    let out = run_command_ok(
        SYSTEM_PROFILER,
        &["SPBluetoothDataType", "-json"],
        Duration::from_secs(60),
        4 * 1024 * 1024,
    )
    .map_err(|e| tracing::debug!(error = %e, "system_profiler bluetooth failed"))
    .ok()?;
    let list = parse_system_profiler_bluetooth(&out).ok()?;
    Some(list.into_iter().map(|d| (d.id.clone(), d)).collect())
}

fn merge_bt(
    plists: &BTreeMap<String, DeviceInfo>,
    profiler: &BTreeMap<String, DeviceInfo>,
) -> BTreeMap<String, DeviceInfo> {
    let mut out = plists.clone();
    for (id, d) in profiler {
        match out.get_mut(id) {
            Some(existing) => {
                if let Some(c) = d.details.get("connected_now") {
                    existing.details.insert("connected_now".into(), c.clone());
                }
                if let Some(t) = d.details.get("minor_type") {
                    existing.details.insert("minor_type".into(), t.clone());
                }
            }
            None => {
                out.insert(id.clone(), d.clone());
            }
        }
    }
    out
}

fn snapshot_wifi() -> BTreeMap<String, DeviceInfo> {
    read_plist_file(KNOWN_NETWORKS_PLIST, parse_known_networks)
        .unwrap_or_default()
        .into_iter()
        .map(|d| (d.id.clone(), d))
        .collect()
}

/// `ioreg -a -l -r -d <n> -c <class>` fallback when IOKit notifications are unavailable.
fn snapshot_ioreg(class: IoClass) -> Option<BTreeMap<String, DeviceInfo>> {
    let name = class.class_name().to_str().ok()?;
    let depth = if class == IoClass::Usb { "2" } else { "1" };
    let out = run_command_ok(
        IOREG,
        &["-a", "-l", "-r", "-d", depth, "-c", name],
        Duration::from_secs(15),
        16 * 1024 * 1024,
    )
    .map_err(|e| tracing::debug!(class = name, error = %e, "ioreg failed"))
    .ok()?;
    let entries = parse_ioreg_archive(&out).ok()?;
    Some(
        entries
            .iter()
            .filter_map(|d| class.parse(d))
            .map(|d| (d.id.clone(), d))
            .collect(),
    )
}

/// Fills a generic Thunderbolt name / vendor from `system_profiler SPThunderboltDataType -json`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn enrich_thunderbolt(dev: &mut DeviceInfo) {
    let Some(uid) = dev
        .details
        .get("uid")
        .and_then(|u| parse::parse_int_text(u))
        .map(|u| u as u64)
    else {
        return;
    };
    let Ok(out) = run_command_ok(
        SYSTEM_PROFILER,
        &["SPThunderboltDataType", "-json"],
        Duration::from_secs(30),
        4 * 1024 * 1024,
    ) else {
        return;
    };
    if let Some((_, name, vendor)) = parse_system_profiler_thunderbolt(&out)
        .into_iter()
        .find(|(u, _, _)| *u == uid)
    {
        if let Some(n) = name {
            dev.name = n;
        }
        if dev.vendor.is_none() {
            dev.vendor = vendor;
        }
    }
}

/// Watches devices (see module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct DeviceWatcher;

#[derive(Default)]
struct State {
    volumes: BTreeMap<String, DeviceInfo>,
    volume_cache: HashMap<(PathBuf, String), Option<DeviceInfo>>,
    net: BTreeMap<String, DeviceInfo>,
    net_ifs: Vec<LinkInterface>,
    net_ports: BTreeMap<String, (String, Option<String>)>,
    net_ports_at: Option<Instant>,
    bt_plists: BTreeMap<String, DeviceInfo>,
    bt_profiler: BTreeMap<String, DeviceInfo>,
    bt: BTreeMap<String, DeviceInfo>,
    wifi: BTreeMap<String, DeviceInfo>,
    io: RefTracker,
    ioreg: HashMap<IoClass, BTreeMap<String, DeviceInfo>>,
}

impl State {
    fn refresh_net(&mut self) -> Vec<DeviceEvent> {
        let ifs = sys::list_link_interfaces();
        let stale = self
            .net_ports_at
            .map(|t| t.elapsed() >= NETWORKSETUP_MIN_INTERVAL)
            .unwrap_or(true);
        if (ifs != self.net_ifs || self.net_ports_at.is_none())
            && stale
            && Path::new(NETWORKSETUP).is_file()
        {
            match run_command_ok(
                NETWORKSETUP,
                &["-listallhardwareports"],
                Duration::from_secs(10),
                256 * 1024,
            ) {
                Ok(out) => {
                    self.net_ports = parse_networksetup_ports(&String::from_utf8_lossy(&out))
                }
                Err(e) => tracing::debug!(error = %e, "networksetup failed"),
            }
            self.net_ports_at = Some(Instant::now());
        }
        self.net_ifs = ifs;
        let new = build_net_snapshot(&self.net_ifs, &self.net_ports);
        let ev = diff_devices(&self.net, &new);
        self.net = new;
        ev
    }

    fn refresh_volumes(&mut self, own_root: &Path) -> Vec<DeviceEvent> {
        let new = snapshot_volumes(own_root, &mut self.volume_cache);
        let ev = diff_devices(&self.volumes, &new);
        self.volumes = new;
        ev
    }

    fn refresh_bt(&mut self, with_profiler: bool) -> Vec<DeviceEvent> {
        self.bt_plists = snapshot_bt_plists();
        if with_profiler {
            if let Some(p) = snapshot_bt_profiler() {
                self.bt_profiler = p;
            }
        }
        let new = merge_bt(&self.bt_plists, &self.bt_profiler);
        let ev = diff_devices(&self.bt, &new);
        self.bt = new;
        ev
    }

    fn refresh_wifi(&mut self) -> Vec<DeviceEvent> {
        let new = snapshot_wifi();
        let ev = diff_devices(&self.wifi, &new);
        self.wifi = new;
        ev
    }

    fn refresh_ioreg(&mut self) -> Vec<DeviceEvent> {
        let mut ev = Vec::new();
        for class in IoClass::ALL {
            if let Some(new) = snapshot_ioreg(class) {
                let old = self.ioreg.entry(class).or_default();
                ev.extend(diff_devices(old, &new));
                *old = new;
            }
        }
        ev
    }

    fn count(&self) -> usize {
        self.volumes.len()
            + self.net.len()
            + self.bt.len()
            + self.wifi.len()
            + self.io.len()
            + self.ioreg.values().map(|m| m.len()).sum::<usize>()
    }
}

/// What the watcher should refresh, decided from a filesystem event path.
fn classify_fs_path(p: &Path) -> Option<&'static str> {
    if p.starts_with("/Volumes") {
        return Some("volumes");
    }
    let name = p.file_name()?.to_string_lossy();
    if name.starts_with("com.apple.Bluetooth")
        || name.starts_with("com.apple.MobileBluetooth.devices")
    {
        Some("bluetooth")
    } else if name.starts_with("com.apple.wifi.known-networks") {
        Some("wifi")
    } else {
        None
    }
}

/// Runs a blocking closure on the blocking pool, moving the state in and out.
async fn blocking<F>(state: &mut Option<State>, f: F) -> Result<Vec<DeviceEvent>, String>
where
    F: FnOnce(&mut State) -> Vec<DeviceEvent> + Send + 'static,
{
    let mut s = state.take().unwrap_or_default();
    let (s, ev) = tokio::task::spawn_blocking(move || {
        let ev = f(&mut s);
        (s, ev)
    })
    .await
    .map_err(|e| format!("tâche périphériques interrompue : {e}"))?;
    *state = Some(s);
    Ok(ev)
}

async fn emit(tx: &mpsc::Sender<MonitorEvent>, events: Vec<DeviceEvent>) -> bool {
    for e in events {
        if tx.send(MonitorEvent::Device(e)).await.is_err() {
            return false;
        }
    }
    true
}

#[cfg(target_os = "macos")]
type IoEvent = iokit::IoKitEvent;
#[cfg(not(target_os = "macos"))]
type IoEvent = std::convert::Infallible;

impl DeviceWatcher {
    /// Runs until shutdown.
    pub async fn run(self, mut ctx: MonitorContext) {
        let mut backoff = Backoff::new(Duration::from_secs(5), Duration::from_secs(600));
        let mut state = Some(State::default());
        loop {
            if is_shutdown(&ctx.shutdown) {
                return;
            }
            match run_loop(&mut ctx, &mut state).await {
                Ok(()) => return,
                Err(msg) => {
                    send_health(&ctx.tx, MONITOR_DEVICES, false, msg).await;
                    if sleep_or_shutdown(backoff.next_delay(), &mut ctx.shutdown).await {
                        return;
                    }
                }
            }
        }
    }
}

async fn run_loop(ctx: &mut MonitorContext, state: &mut Option<State>) -> Result<(), String> {
    let own_root = ctx.paths.root.clone();
    let tx = ctx.tx.clone();

    // Initial snapshots: everything present is reported Connected (diff against what we already
    // reported if this is a restart).
    let root = own_root.clone();
    let ev = blocking(state, move |s| {
        let mut ev = s.refresh_volumes(&root);
        ev.extend(s.refresh_net());
        ev.extend(s.refresh_bt(true));
        ev.extend(s.refresh_wifi());
        ev
    })
    .await?;
    if !emit(&tx, ev).await {
        return Ok(());
    }

    // IOKit notifications (macOS), ioreg polling as fallback.
    let (io_tx, mut io_rx) = mpsc::channel::<IoEvent>(4096);
    #[cfg(target_os = "macos")]
    let (_iokit, ioreg_fallback) = match tokio::task::spawn_blocking(move || {
        iokit::IoKitMonitor::start(io_tx)
    })
    .await
    {
        Ok(Ok(m)) => (Some(m), false),
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "IOKit notifications unavailable, falling back to ioreg polling");
            (None, true)
        }
        Err(e) => {
            tracing::warn!(error = %e, "IOKit start task failed, falling back to ioreg polling");
            (None, true)
        }
    };
    #[cfg(not(target_os = "macos"))]
    let ioreg_fallback = {
        drop(io_tx);
        false
    };
    if ioreg_fallback {
        let ev = blocking(state, |s| s.refresh_ioreg()).await?;
        if !emit(&tx, ev).await {
            return Ok(());
        }
    }

    // FSEvents on /Volumes and the preference folders.
    let (fs_tx, mut fs_rx) = mpsc::channel::<PathBuf>(256);
    let _fs_watcher = {
        use notify::Watcher;
        match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(ev) = res {
                for p in ev.paths.into_iter().take(4) {
                    let _ = fs_tx.try_send(p);
                }
            }
        }) {
            Ok(mut w) => {
                for d in ["/Volumes", PREFS_DIR, BT_PREFS_DIR] {
                    if Path::new(d).is_dir() {
                        if let Err(e) = w.watch(Path::new(d), notify::RecursiveMode::NonRecursive) {
                            tracing::debug!(dir = d, error = %e, "cannot watch device folder");
                        }
                    }
                }
                Some(w)
            }
            Err(e) => {
                tracing::warn!(error = %e, "device FSEvents unavailable, polling only");
                None
            }
        }
    };

    let count = state.as_ref().map(State::count).unwrap_or(0);
    let mut msg = format!("{count} périphérique(s) suivi(s)");
    if ioreg_fallback {
        msg.push_str(" ; IOKit indisponible, sondage ioreg toutes les 15 s");
    }
    send_health(&tx, MONITOR_DEVICES, true, msg).await;

    let trigger = volume_trigger();
    let start = tokio::time::Instant::now();
    let mut net_tick = tokio::time::interval_at(start + NET_POLL, NET_POLL);
    let mut vol_tick = tokio::time::interval_at(start + VOLUME_POLL, VOLUME_POLL);
    let mut bt_tick = tokio::time::interval_at(start + BT_PROFILER_POLL, BT_PROFILER_POLL);
    let mut ioreg_tick = tokio::time::interval_at(start + IOREG_POLL, IOREG_POLL);
    for t in [&mut net_tick, &mut vol_tick, &mut bt_tick, &mut ioreg_tick] {
        t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    }
    let mut pending_vol: Option<tokio::time::Instant> = None;
    let mut pending_bt: Option<tokio::time::Instant> = None;
    let mut pending_wifi: Option<tokio::time::Instant> = None;

    loop {
        let deadline = [pending_vol, pending_bt, pending_wifi]
            .into_iter()
            .flatten()
            .min();
        let events: Vec<DeviceEvent> = tokio::select! {
            _ = wait_shutdown(&mut ctx.shutdown) => return Ok(()),
            _ = trigger.notified() => {
                pending_vol.get_or_insert(tokio::time::Instant::now() + Duration::from_secs(1));
                Vec::new()
            }
            Some(p) = fs_rx.recv() => {
                let soon = tokio::time::Instant::now() + Duration::from_secs(2);
                match classify_fs_path(&p) {
                    Some("volumes") => { pending_vol.get_or_insert(tokio::time::Instant::now() + Duration::from_secs(1)); }
                    Some("bluetooth") => { pending_bt.get_or_insert(soon); }
                    Some("wifi") => { pending_wifi.get_or_insert(soon); }
                    _ => {}
                }
                Vec::new()
            }
            Some(io) = io_rx.recv() => handle_io(state, io).await?,
            _ = net_tick.tick() => blocking(state, |s| s.refresh_net()).await?,
            _ = vol_tick.tick() => {
                pending_vol.get_or_insert(tokio::time::Instant::now());
                Vec::new()
            }
            _ = bt_tick.tick() => blocking(state, |s| s.refresh_bt(true)).await?,
            _ = ioreg_tick.tick(), if ioreg_fallback => blocking(state, |s| s.refresh_ioreg()).await?,
            _ = sleep_until_opt(deadline) => {
                let now = tokio::time::Instant::now();
                let do_vol = pending_vol.map(|d| d <= now).unwrap_or(false);
                let do_bt = pending_bt.map(|d| d <= now).unwrap_or(false);
                let do_wifi = pending_wifi.map(|d| d <= now).unwrap_or(false);
                if do_vol { pending_vol = None; }
                if do_bt { pending_bt = None; }
                if do_wifi { pending_wifi = None; }
                let root = own_root.clone();
                blocking(state, move |s| {
                    let mut ev = Vec::new();
                    if do_vol { ev.extend(s.refresh_volumes(&root)); }
                    if do_bt { ev.extend(s.refresh_bt(false)); }
                    if do_wifi { ev.extend(s.refresh_wifi()); }
                    ev
                }).await?
            }
        };
        if !emit(&tx, events).await {
            return Ok(());
        }
    }
}

async fn sleep_until_opt(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(d).await,
        None => std::future::pending::<()>().await,
    }
}

#[cfg(target_os = "macos")]
async fn handle_io(state: &mut Option<State>, io: IoEvent) -> Result<Vec<DeviceEvent>, String> {
    let Some(s) = state.as_mut() else {
        return Ok(Vec::new());
    };
    if !io.arrived {
        return Ok(s.io.depart(io.entry_id).into_iter().collect());
    }
    let Some(dev) = io.props.as_ref().and_then(|p| io.class.parse(p)) else {
        return Ok(Vec::new());
    };
    let Some(ev) = s.io.arrive(io.entry_id, dev) else {
        return Ok(Vec::new());
    };
    let generic = ev.device.kind == DeviceKind::Thunderbolt
        && ev
            .device
            .details
            .get("built_in")
            .map(|b| b == "false")
            .unwrap_or(false)
        && (ev.device.vendor.is_none()
            || ev.device.name == "Thunderbolt"
            || ev.device.name.starts_with("IOThunderbolt"));
    if generic {
        let DeviceEvent { device, change } = ev;
        let fallback = device.clone();
        let device = tokio::task::spawn_blocking(move || {
            let mut d = device;
            enrich_thunderbolt(&mut d);
            d
        })
        .await
        .unwrap_or(fallback);
        return Ok(vec![DeviceEvent { device, change }]);
    }
    Ok(vec![ev])
}

#[cfg(not(target_os = "macos"))]
async fn handle_io(_state: &mut Option<State>, io: IoEvent) -> Result<Vec<DeviceEvent>, String> {
    match io {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_core::config::Config;
    use pb_core::paths::Paths;
    use tokio::sync::watch;

    fn dev(id: &str, kind: DeviceKind) -> DeviceInfo {
        new_device(id.into(), kind, id.into())
    }

    #[test]
    fn diff_reports_connections_and_disconnections() {
        let mut old = BTreeMap::new();
        old.insert("a".to_string(), dev("a", DeviceKind::Volume));
        old.insert("b".to_string(), dev("b", DeviceKind::Volume));
        let mut new = BTreeMap::new();
        new.insert("b".to_string(), dev("b", DeviceKind::Volume));
        new.insert("c".to_string(), dev("c", DeviceKind::Volume));
        let ev = diff_devices(&old, &new);
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].change, DeviceChange::Connected);
        assert_eq!(ev[0].device.id, "c");
        assert!(ev[0].device.connected);
        assert_eq!(ev[1].change, DeviceChange::Disconnected);
        assert_eq!(ev[1].device.id, "a");
        assert!(!ev[1].device.connected);
        // startup: everything is Connected
        assert_eq!(
            diff_devices(&BTreeMap::new(), &new)
                .iter()
                .filter(|e| e.change == DeviceChange::Connected)
                .count(),
            2
        );
        assert!(diff_devices(&new, &new).is_empty());
    }

    #[test]
    fn ref_tracker_counts_interfaces() {
        let mut t = RefTracker::default();
        let kb = dev("hid:05ac:0221:loc-1", DeviceKind::Hid);
        assert_eq!(
            t.arrive(1, kb.clone()).map(|e| e.change),
            Some(DeviceChange::Connected)
        );
        assert!(
            t.arrive(2, kb.clone()).is_none(),
            "second interface of the same device"
        );
        assert!(t.arrive(2, kb.clone()).is_none(), "duplicate notification");
        assert!(t.depart(1).is_none());
        let ev = t.depart(2).expect("last interface gone");
        assert_eq!(ev.change, DeviceChange::Disconnected);
        assert!(!ev.device.connected);
        assert!(t.depart(99).is_none());
        assert_eq!(t.len(), 0);
    }

    #[test]
    fn net_snapshot_prefers_hardware_mac_and_ignores_virtual() {
        let ifs = vec![
            LinkInterface {
                name: "en0".into(),
                mac: Some("aa:aa:aa:aa:aa:01".into()),
            },
            LinkInterface {
                name: "en5".into(),
                mac: Some("00:e0:4c:68:01:02".into()),
            },
            LinkInterface {
                name: "utun3".into(),
                mac: None,
            },
            LinkInterface {
                name: "awdl0".into(),
                mac: Some("12:34:56:78:9a:bc".into()),
            },
            LinkInterface {
                name: "bridge0".into(),
                mac: Some("36:7d:da:00:11:22".into()),
            },
        ];
        let mut ports = BTreeMap::new();
        ports.insert(
            "en0".to_string(),
            ("Wi-Fi".to_string(), Some("3c:22:fb:01:02:03".to_string())),
        );
        ports.insert(
            "bridge0".to_string(),
            ("Thunderbolt Bridge".to_string(), None),
        );
        let snap = build_net_snapshot(&ifs, &ports);
        let ids: Vec<&str> = snap.keys().map(String::as_str).collect();
        assert_eq!(
            ids,
            vec![
                "net:bridge0:36:7d:da:00:11:22",
                "net:en0:3c:22:fb:01:02:03",
                "net:en5:00:e0:4c:68:01:02"
            ]
        );
        let wifi = &snap["net:en0:3c:22:fb:01:02:03"];
        assert_eq!(wifi.name, "Wi-Fi");
        assert_eq!(wifi.details["current_mac"], "aa:aa:aa:aa:aa:01");
        // a rotated private address does not change the id
        let ifs2 = vec![LinkInterface {
            name: "en0".into(),
            mac: Some("aa:aa:aa:aa:aa:02".into()),
        }];
        assert!(build_net_snapshot(&ifs2, &ports).contains_key("net:en0:3c:22:fb:01:02:03"));
    }

    #[test]
    fn bluetooth_merge_and_fs_classification() {
        let mut plists = BTreeMap::new();
        plists.insert("bt:aa".to_string(), dev("bt:aa", DeviceKind::Bluetooth));
        let mut prof = BTreeMap::new();
        let mut p = dev("bt:aa", DeviceKind::Bluetooth);
        p.details.insert("connected_now".into(), "true".into());
        prof.insert("bt:aa".to_string(), p);
        prof.insert("bt:bb".to_string(), dev("bt:bb", DeviceKind::Bluetooth));
        let m = merge_bt(&plists, &prof);
        assert_eq!(m.len(), 2);
        assert_eq!(m["bt:aa"].details["connected_now"], "true");
        assert_eq!(classify_fs_path(Path::new("/Volumes/USB")), Some("volumes"));
        assert_eq!(
            classify_fs_path(Path::new(
                "/Library/Preferences/com.apple.wifi.known-networks.plist"
            )),
            Some("wifi")
        );
        assert_eq!(
            classify_fs_path(Path::new(
                "/Library/Preferences/com.apple.Bluetooth.plist.aBcD"
            )),
            Some("bluetooth")
        );
        assert_eq!(
            classify_fs_path(Path::new("/Library/Preferences/com.apple.other.plist")),
            None
        );
    }

    #[tokio::test]
    async fn watcher_reports_startup_devices_then_health_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let (_c, cfg_rx) = watch::channel(Config::default());
        let (stop_tx, stop_rx) = watch::channel(false);
        let (tx, mut rx) = mpsc::channel(1024);
        let ctx = MonitorContext {
            paths: Paths::with_root(dir.path()),
            config: cfg_rx,
            user: None,
            tx,
            shutdown: stop_rx,
        };
        let task = tokio::spawn(DeviceWatcher.run(ctx));
        loop {
            match tokio::time::timeout(Duration::from_secs(30), rx.recv())
                .await
                .unwrap()
                .unwrap()
            {
                MonitorEvent::Device(e) => assert_eq!(e.change, DeviceChange::Connected),
                MonitorEvent::MonitorHealth { ok, monitor, .. } => {
                    assert!(ok);
                    assert_eq!(monitor, MONITOR_DEVICES);
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        // trigger path works without panicking
        volume_trigger().notify_one();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        stop_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
    }
}
