//! Pure device parsers: IORegistry property dictionaries (from IOKit or `ioreg -a`), `diskutil
//! info -plist`, Bluetooth preference plists, `system_profiler -json`, Wi-Fi known networks,
//! `networksetup -listallhardwareports`.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use pb_core::model::{DeviceInfo, DeviceKind, DeviceTrust};
use plist::{Dictionary, Value};

use super::sys::MountEntry;
use crate::util::clip;
use crate::MonitorError;

/// New `DeviceInfo` (connected, unknown trust, timestamps = now; the daemon merges with its DB).
pub fn new_device(id: String, kind: DeviceKind, name: String) -> DeviceInfo {
    let now = pb_core::now_ts();
    DeviceInfo {
        id,
        kind,
        name,
        vendor: None,
        vendor_id: None,
        product_id: None,
        serial: None,
        transport: None,
        details: BTreeMap::new(),
        first_seen: now,
        last_seen: now,
        connected: true,
        trust: DeviceTrust::Unknown,
        baseline: false,
    }
}

fn get_i64(d: &Dictionary, key: &str) -> Option<i64> {
    match d.get(key)? {
        Value::Integer(i) => i.as_signed().or_else(|| i.as_unsigned().map(|u| u as i64)),
        Value::Real(r) if r.is_finite() => Some(*r as i64),
        Value::String(s) => parse_int_text(s),
        _ => None,
    }
}

fn get_u64(d: &Dictionary, key: &str) -> Option<u64> {
    match d.get(key)? {
        Value::Integer(i) => i.as_unsigned().or_else(|| i.as_signed().map(|s| s as u64)),
        Value::String(s) => parse_int_text(s).map(|v| v as u64),
        _ => None,
    }
}

fn get_str(d: &Dictionary, key: &str) -> Option<String> {
    d.get(key)
        .and_then(Value::as_string)
        .map(|s| clip(s.trim(), 256))
        .filter(|s| !s.is_empty())
}

fn get_bool(d: &Dictionary, key: &str) -> Option<bool> {
    match d.get(key)? {
        Value::Boolean(b) => Some(*b),
        Value::Integer(i) => i.as_signed().map(|v| v != 0),
        Value::String(s) => match s.to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" => Some(true),
            "no" | "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// `0x004C`, `0x004C (Apple)`, `76` -> 76.
pub(crate) fn parse_int_text(s: &str) -> Option<i64> {
    let t = s.trim();
    let t = t.split_whitespace().next().unwrap_or(t);
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(h, 16)
            .ok()
            .or_else(|| u64::from_str_radix(h, 16).ok().map(|u| u as i64))
    } else {
        t.parse().ok()
    }
}

/// Id component: keeps `[A-Za-z0-9._-]`, replaces the rest with `_`, max 64 chars.
pub(crate) fn id_part(s: &str) -> String {
    s.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn bool_str(b: bool) -> String {
    if b { "true" } else { "false" }.to_string()
}

/// `IORegistryEntryID` of an archived registry entry.
pub fn registry_entry_id(d: &Dictionary) -> Option<u64> {
    get_u64(d, "IORegistryEntryID")
}

/// Parses `ioreg -a …` output: an array of registry entries (dictionaries).
pub fn parse_ioreg_archive(bytes: &[u8]) -> Result<Vec<Dictionary>, MonitorError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let v = Value::from_reader(Cursor::new(bytes))
        .map_err(|e| MonitorError::Parse(format!("ioreg: {e}")))?;
    Ok(match v {
        Value::Array(a) => a
            .into_iter()
            .filter_map(Value::into_dictionary)
            .take(4096)
            .collect(),
        Value::Dictionary(d) => vec![d],
        _ => Vec::new(),
    })
}

/// `bInterfaceClass` values of child entries (`IORegistryEntryChildren`, recursive, bounded).
pub fn usb_interface_classes(d: &Dictionary) -> Vec<u8> {
    fn walk(d: &Dictionary, depth: usize, out: &mut Vec<u8>) {
        if depth > 4 || out.len() > 32 {
            return;
        }
        if let Some(children) = d.get("IORegistryEntryChildren").and_then(Value::as_array) {
            for c in children.iter().take(64) {
                if let Some(cd) = c.as_dictionary() {
                    if let Some(cls) = get_i64(cd, "bInterfaceClass") {
                        out.push(cls as u8);
                    }
                    walk(cd, depth + 1, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(d, 0, &mut out);
    out.sort_unstable();
    out.dedup();
    out
}

fn serial_or_location(serial: Option<&str>, location: Option<u64>) -> String {
    match (serial, location) {
        (Some(s), _) => id_part(s),
        (None, Some(l)) => format!("loc-{l:x}"),
        (None, None) => "0".into(),
    }
}

/// USB device (`IOUSBHostDevice`). `None` without a vendor id.
pub fn usb_from_props(d: &Dictionary) -> Option<DeviceInfo> {
    let vid = get_u64(d, "idVendor")?;
    let pid = get_u64(d, "idProduct").unwrap_or(0);
    let serial = get_str(d, "USB Serial Number").or_else(|| get_str(d, "kUSBSerialNumberString"));
    let location = get_u64(d, "locationID");
    let name = get_str(d, "USB Product Name")
        .or_else(|| get_str(d, "kUSBProductString"))
        .or_else(|| get_str(d, "IORegistryEntryName"))
        .unwrap_or_else(|| "Périphérique USB".into());
    let id = format!(
        "usb:{vid:04x}:{pid:04x}:{}",
        serial_or_location(serial.as_deref(), location)
    );
    let mut dev = new_device(id, DeviceKind::Usb, name);
    dev.vendor = get_str(d, "USB Vendor Name").or_else(|| get_str(d, "kUSBVendorString"));
    dev.vendor_id = u32::try_from(vid).ok();
    dev.product_id = u32::try_from(pid).ok();
    dev.serial = serial;
    dev.transport = Some("USB".into());
    if let Some(l) = location {
        dev.details
            .insert("location_id".into(), format!("0x{l:08x}"));
    }
    if let Some(c) = get_i64(d, "bDeviceClass") {
        dev.details.insert("device_class".into(), c.to_string());
    }
    if let Some(s) = get_i64(d, "Device Speed").or_else(|| get_i64(d, "USBSpeed")) {
        dev.details.insert("speed".into(), s.to_string());
    }
    let classes = usb_interface_classes(d);
    if !classes.is_empty() {
        dev.details.insert(
            "interface_classes".into(),
            classes
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
        dev.details
            .insert("has_hid".into(), bool_str(classes.contains(&3)));
        dev.details
            .insert("has_storage".into(), bool_str(classes.contains(&8)));
    }
    let built_in = get_bool(d, "Built-In").unwrap_or(false);
    dev.details.insert("built_in".into(), bool_str(built_in));
    if let Some(r) = registry_entry_id(d) {
        dev.details.insert("registry_id".into(), r.to_string());
    }
    Some(dev)
}

/// HID transports that are always built into the Mac.
pub const BUILT_IN_HID_TRANSPORTS: &[&str] = &["SPI", "FIFO"];

fn usage_pairs(d: &Dictionary) -> Vec<(i64, i64)> {
    let mut v = Vec::new();
    if let (Some(p), Some(u)) = (get_i64(d, "PrimaryUsagePage"), get_i64(d, "PrimaryUsage")) {
        v.push((p, u));
    }
    if let Some(arr) = d.get("DeviceUsagePairs").and_then(Value::as_array) {
        for e in arr.iter().take(32) {
            if let Some(ed) = e.as_dictionary() {
                if let (Some(p), Some(u)) =
                    (get_i64(ed, "DeviceUsagePage"), get_i64(ed, "DeviceUsage"))
                {
                    v.push((p, u));
                }
            }
        }
    }
    v
}

/// HID device (`IOHIDDevice`). `details.is_keyboard` = generic desktop page (1) usage keyboard (6)
/// or keypad (7) in the primary usage or `DeviceUsagePairs`; `details.built_in` = `Built-In` flag
/// or SPI / FIFO transport.
pub fn hid_from_props(d: &Dictionary) -> Option<DeviceInfo> {
    let vid = get_u64(d, "VendorID").unwrap_or(0);
    let pid = get_u64(d, "ProductID").unwrap_or(0);
    let transport = get_str(d, "Transport");
    let serial = get_str(d, "SerialNumber");
    let location = get_u64(d, "LocationID");
    let name = get_str(d, "Product")
        .or_else(|| get_str(d, "IORegistryEntryName"))
        .unwrap_or_else(|| "Périphérique HID".into());
    if vid == 0
        && pid == 0
        && location.is_none()
        && serial.is_none()
        && registry_entry_id(d).is_none()
    {
        return None;
    }
    let id = format!(
        "hid:{vid:04x}:{pid:04x}:{}",
        serial_or_location(serial.as_deref(), location)
    );
    let mut dev = new_device(id, DeviceKind::Hid, name);
    dev.vendor = get_str(d, "Manufacturer");
    dev.vendor_id = u32::try_from(vid).ok().filter(|v| *v != 0);
    dev.product_id = u32::try_from(pid).ok().filter(|v| *v != 0);
    dev.serial = serial;
    let pairs = usage_pairs(d);
    let is_keyboard = pairs.iter().any(|(p, u)| *p == 1 && (*u == 6 || *u == 7));
    let built_in = get_bool(d, "Built-In").unwrap_or(false)
        || transport
            .as_deref()
            .map(|t| {
                BUILT_IN_HID_TRANSPORTS
                    .iter()
                    .any(|b| b.eq_ignore_ascii_case(t))
            })
            .unwrap_or(false);
    if let Some((p, u)) = pairs.first() {
        dev.details.insert("usage_page".into(), p.to_string());
        dev.details.insert("usage".into(), u.to_string());
    }
    dev.details
        .insert("is_keyboard".into(), bool_str(is_keyboard));
    dev.details.insert("built_in".into(), bool_str(built_in));
    if let Some(l) = location {
        dev.details
            .insert("location_id".into(), format!("0x{l:08x}"));
    }
    if let Some(r) = registry_entry_id(d) {
        dev.details.insert("registry_id".into(), r.to_string());
    }
    dev.transport = transport;
    Some(dev)
}

/// Thunderbolt switch (`IOThunderboltSwitch` and subclasses). Depth 0 = the Mac's own controller
/// (`details.built_in = true`).
pub fn thunderbolt_from_props(d: &Dictionary) -> Option<DeviceInfo> {
    let uid = get_u64(d, "UID");
    let vid = get_u64(d, "Vendor ID");
    let pid = get_u64(d, "Device ID");
    let route = get_u64(d, "Route String");
    let id = match (uid, vid, pid) {
        (Some(u), _, _) => format!("tb:{u:016x}"),
        (None, Some(v), Some(p)) => format!("tb:{v:04x}:{p:04x}:{:x}", route.unwrap_or(0)),
        _ => return None,
    };
    let name = get_str(d, "Device Model Name")
        .or_else(|| get_str(d, "IORegistryEntryName"))
        .unwrap_or_else(|| "Thunderbolt".into());
    let mut dev = new_device(id, DeviceKind::Thunderbolt, name);
    dev.vendor = get_str(d, "Device Vendor Name");
    dev.vendor_id = vid.and_then(|v| u32::try_from(v).ok());
    dev.product_id = pid.and_then(|v| u32::try_from(v).ok());
    dev.transport = Some("Thunderbolt".into());
    let depth = get_i64(d, "Depth");
    if let Some(dp) = depth {
        dev.details.insert("depth".into(), dp.to_string());
    }
    if let Some(r) = route {
        dev.details
            .insert("route_string".into(), format!("0x{r:x}"));
    }
    if let Some(u) = uid {
        dev.details.insert("uid".into(), format!("0x{u:016x}"));
    }
    dev.details
        .insert("built_in".into(), bool_str(depth == Some(0)));
    if let Some(r) = registry_entry_id(d) {
        dev.details.insert("registry_id".into(), r.to_string());
    }
    Some(dev)
}

/// `(switch uid, device name, vendor name)` from `system_profiler SPThunderboltDataType -json`.
pub fn parse_system_profiler_thunderbolt(
    json: &[u8],
) -> Vec<(u64, Option<String>, Option<String>)> {
    fn walk(
        v: &serde_json::Value,
        depth: usize,
        out: &mut Vec<(u64, Option<String>, Option<String>)>,
    ) {
        if depth > 8 || out.len() > 128 {
            return;
        }
        match v {
            serde_json::Value::Object(o) => {
                if let Some(uid) = o
                    .get("switch_uid_key")
                    .and_then(|u| u.as_str())
                    .and_then(parse_int_text)
                {
                    let s = |k: &str| o.get(k).and_then(|x| x.as_str()).map(|x| clip(x, 256));
                    out.push((uid as u64, s("device_name_key"), s("vendor_name_key")));
                }
                for c in o.values() {
                    walk(c, depth + 1, out);
                }
            }
            serde_json::Value::Array(a) => {
                for c in a.iter().take(128) {
                    walk(c, depth + 1, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(json) {
        walk(&v, 0, &mut out);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Volumes
// ---------------------------------------------------------------------------------------------

/// `mount(2)` flag: not shown in Finder (`-nobrowse` DMG mounts, system mounts).
pub const MNT_DONTBROWSE: u32 = 0x0010_0000;
const NETWORK_FS: &[&str] = &[
    "smbfs",
    "afpfs",
    "nfs",
    "webdav",
    "ftp",
    "cifs",
    "nfs4",
    "fuse.sshfs",
];
const SYSTEM_VOLUME_NAMES: &[&str] = &[
    "Recovery",
    "Preboot",
    "VM",
    "Update",
    "xART",
    "Hardware",
    "iSCPreboot",
];

/// Mounts that may be reported: under one of `roots` (`/Volumes` on macOS), not hidden, not a
/// Time Machine snapshot, not `-nobrowse`, not under our own root.
pub fn is_reportable_mount(m: &MountEntry, roots: &[&str], own_root: &Path) -> bool {
    if !roots
        .iter()
        .any(|r| m.mount_point.starts_with(r) && m.mount_point != Path::new(r))
    {
        return false;
    }
    if m.mount_point.starts_with(own_root) || m.flags & MNT_DONTBROWSE != 0 {
        return false;
    }
    let name = m
        .mount_point
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    !(name.is_empty() || name.starts_with('.') || name.starts_with("com.apple."))
}

/// Parses `diskutil info -plist <mountpoint>`.
pub fn parse_diskutil_info(bytes: &[u8]) -> Result<Dictionary, MonitorError> {
    Value::from_reader(Cursor::new(bytes))
        .map_err(|e| MonitorError::Parse(format!("diskutil: {e}")))?
        .into_dictionary()
        .ok_or_else(|| MonitorError::Parse("diskutil output is not a dictionary".into()))
}

/// Volume from the mount table only (network shares, or when diskutil fails).
pub fn volume_from_mount(m: &MountEntry) -> DeviceInfo {
    let name = m
        .mount_point
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| m.mount_from.clone());
    let network = NETWORK_FS.contains(&m.fstype.as_str());
    let id = if network {
        format!("vol:net:{}", id_part(&m.mount_from))
    } else {
        format!("vol:{}:{}", id_part(&m.mount_from), id_part(&name))
    };
    let mut dev = new_device(id, DeviceKind::Volume, name);
    dev.transport = network.then(|| "Network".to_string());
    dev.details.insert(
        "mount_point".into(),
        m.mount_point.to_string_lossy().into_owned(),
    );
    dev.details
        .insert("mount_from".into(), m.mount_from.clone());
    dev.details.insert("filesystem".into(), m.fstype.clone());
    dev.details.insert("disk_image".into(), "false".into());
    dev
}

/// Volume from `diskutil info -plist` + the mount entry. `None` for internal system volumes.
pub fn volume_from_diskutil(d: &Dictionary, m: &MountEntry) -> Option<DeviceInfo> {
    let internal = get_bool(d, "Internal").unwrap_or(false);
    let protocol = get_str(d, "BusProtocol");
    let media = get_str(d, "MediaName");
    let disk_image = protocol.as_deref() == Some("Disk Image")
        || get_bool(d, "DiskImage").unwrap_or(false)
        || media
            .as_deref()
            .map(|n| n.contains("Disk Image"))
            .unwrap_or(false);
    let fs = get_str(d, "FilesystemType")
        .or_else(|| get_str(d, "FilesystemName"))
        .unwrap_or_else(|| m.fstype.clone());
    let vol_name = get_str(d, "VolumeName");
    if internal
        && !disk_image
        && fs == "apfs"
        && vol_name
            .as_deref()
            .map(|n| SYSTEM_VOLUME_NAMES.contains(&n))
            .unwrap_or(false)
    {
        return None;
    }
    let name = vol_name
        .clone()
        .or_else(|| {
            m.mount_point
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        })
        .unwrap_or_default();
    let ident = get_str(d, "DeviceIdentifier");
    let id = match get_str(d, "VolumeUUID").or_else(|| get_str(d, "DiskUUID")) {
        Some(u) => format!("vol:{}", id_part(&u)),
        None => format!(
            "vol:{}:{}",
            id_part(ident.as_deref().unwrap_or(&m.mount_from)),
            id_part(&name)
        ),
    };
    let mut dev = new_device(id, DeviceKind::Volume, name);
    dev.transport = if disk_image {
        Some("Virtual".into())
    } else if NETWORK_FS.contains(&m.fstype.as_str()) {
        Some("Network".into())
    } else {
        protocol.clone()
    };
    let det = &mut dev.details;
    det.insert(
        "mount_point".into(),
        m.mount_point.to_string_lossy().into_owned(),
    );
    det.insert("mount_from".into(), m.mount_from.clone());
    det.insert("filesystem".into(), fs);
    det.insert("internal".into(), bool_str(internal));
    det.insert("disk_image".into(), bool_str(disk_image));
    if let Some(p) = protocol {
        det.insert("protocol".into(), p);
    }
    if let Some(i) = ident {
        det.insert("device_identifier".into(), i);
    }
    if let Some(n) = media {
        det.insert("media_name".into(), n);
    }
    let removable = get_bool(d, "RemovableMedia").or_else(|| get_bool(d, "Removable"));
    if let Some(r) = removable {
        det.insert("removable".into(), bool_str(r));
    }
    if let Some(e) = get_bool(d, "Ejectable") {
        det.insert("ejectable".into(), bool_str(e));
    }
    if let Some(w) = get_bool(d, "WritableVolume") {
        det.insert("writable".into(), bool_str(w));
    }
    if let Some(s) = get_u64(d, "TotalSize").or_else(|| get_u64(d, "Size")) {
        det.insert("size".into(), s.to_string());
    }
    Some(dev)
}

// ---------------------------------------------------------------------------------------------
// Bluetooth
// ---------------------------------------------------------------------------------------------

/// `aa-bb-cc-dd-ee-ff` / `AA:BB:…` -> `aa:bb:cc:dd:ee:ff` (6 hex octets) or `None`.
pub fn normalize_bt_address(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split(['-', ':']).collect();
    if parts.len() != 6
        || !parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    Some(parts.join(":").to_ascii_lowercase())
}

fn bt_device(addr: &str, name: Option<String>) -> DeviceInfo {
    let mut d = new_device(
        format!("bt:{addr}"),
        DeviceKind::Bluetooth,
        name.unwrap_or_else(|| addr.to_string()),
    );
    d.transport = Some("Bluetooth".into());
    d.details.insert("address".into(), addr.to_string());
    d
}

/// Legacy `/Library/Preferences/com.apple.Bluetooth.plist`: `PairedDevices` (addresses) enriched with
/// `DeviceCache` (`Name`, `VendorID`, `ProductID`).
pub fn parse_bluetooth_prefs(bytes: &[u8]) -> Result<Vec<DeviceInfo>, MonitorError> {
    let v = Value::from_reader(Cursor::new(bytes))
        .map_err(|e| MonitorError::Parse(format!("bluetooth plist: {e}")))?;
    let Some(root) = v.as_dictionary() else {
        return Ok(Vec::new());
    };
    let cache = root.get("DeviceCache").and_then(Value::as_dictionary);
    let mut out = Vec::new();
    for a in root
        .get("PairedDevices")
        .and_then(Value::as_array)
        .map(|a| a.as_slice())
        .unwrap_or(&[])
        .iter()
        .take(256)
    {
        let Some(raw) = a.as_string() else { continue };
        let Some(addr) = normalize_bt_address(raw) else {
            continue;
        };
        let entry = cache
            .and_then(|c| c.get(raw).or_else(|| c.get(&addr)))
            .and_then(Value::as_dictionary);
        let mut d = bt_device(
            &addr,
            entry.and_then(|e| get_str(e, "Name").or_else(|| get_str(e, "displayName"))),
        );
        if let Some(e) = entry {
            d.vendor_id = get_u64(e, "VendorID").and_then(|v| u32::try_from(v).ok());
            d.product_id = get_u64(e, "ProductID").and_then(|v| u32::try_from(v).ok());
        }
        out.push(d);
    }
    Ok(out)
}

/// `/Library/Bluetooth/Library/Preferences/com.apple.MobileBluetooth.devices.plist`: dictionary
/// address -> {`Name`, `DefaultName`, `DeviceIdVendor`, `DeviceIdProduct`, `LastSeenTime`…}.
pub fn parse_mobile_bluetooth_devices(bytes: &[u8]) -> Result<Vec<DeviceInfo>, MonitorError> {
    let v = Value::from_reader(Cursor::new(bytes))
        .map_err(|e| MonitorError::Parse(format!("bluetooth plist: {e}")))?;
    let Some(root) = v.as_dictionary() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (k, val) in root.iter().take(512) {
        let Some(addr) = normalize_bt_address(k) else {
            continue;
        };
        let entry = val.as_dictionary();
        let name = entry.and_then(|e| get_str(e, "Name").or_else(|| get_str(e, "DefaultName")));
        let mut d = bt_device(&addr, name);
        if let Some(e) = entry {
            d.vendor_id = get_u64(e, "DeviceIdVendor").and_then(|v| u32::try_from(v).ok());
            d.product_id = get_u64(e, "DeviceIdProduct").and_then(|v| u32::try_from(v).ok());
            if let Some(t) = get_i64(e, "LastSeenTime") {
                d.details.insert("last_seen_time".into(), t.to_string());
            }
        }
        out.push(d);
    }
    Ok(out)
}

/// `system_profiler SPBluetoothDataType -json`: arrays `device_connected` / `device_not_connected`
/// (also any other `device_*` array) of `{ "<name>": { "device_address": …, "device_minorType": …,
/// "device_vendorID": "0x004C", "device_productID": "0x0267" } }`.
pub fn parse_system_profiler_bluetooth(json: &[u8]) -> Result<Vec<DeviceInfo>, MonitorError> {
    let v: serde_json::Value = serde_json::from_slice(json)
        .map_err(|e| MonitorError::Parse(format!("system_profiler: {e}")))?;
    let mut out = Vec::new();
    let controllers = v
        .get("SPBluetoothDataType")
        .and_then(|x| x.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[]);
    for c in controllers.iter().take(8) {
        let Some(obj) = c.as_object() else { continue };
        for (group, list) in obj {
            if !group.starts_with("device_") {
                continue;
            }
            let Some(arr) = list.as_array() else { continue };
            for entry in arr.iter().take(256) {
                let Some(eo) = entry.as_object() else {
                    continue;
                };
                for (name, props) in eo {
                    let Some(addr) = props
                        .get("device_address")
                        .and_then(|a| a.as_str())
                        .and_then(normalize_bt_address)
                    else {
                        continue;
                    };
                    let mut d = bt_device(&addr, Some(clip(name, 256)));
                    let s = |k: &str| props.get(k).and_then(|x| x.as_str());
                    d.vendor_id = s("device_vendorID")
                        .and_then(parse_int_text)
                        .and_then(|v| u32::try_from(v).ok());
                    d.product_id = s("device_productID")
                        .and_then(parse_int_text)
                        .and_then(|v| u32::try_from(v).ok());
                    if let Some(t) = s("device_minorType") {
                        d.details.insert("minor_type".into(), clip(t, 64));
                    }
                    d.details.insert(
                        "connected_now".into(),
                        bool_str(group == "device_connected"),
                    );
                    out.push(d);
                }
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Wi-Fi, network interfaces
// ---------------------------------------------------------------------------------------------

/// `/Library/Preferences/com.apple.wifi.known-networks.plist`: keys `wifi.network.ssid.<SSID>` ->
/// {`SSID` (data), `AddedAt`, `SupportedSecurityTypes`, `Hidden`…}. Device id `wifi:<ssid>`.
pub fn parse_known_networks(bytes: &[u8]) -> Result<Vec<DeviceInfo>, MonitorError> {
    let v = Value::from_reader(Cursor::new(bytes))
        .map_err(|e| MonitorError::Parse(format!("known networks: {e}")))?;
    let Some(root) = v.as_dictionary() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (k, val) in root.iter().take(2048) {
        let Some(suffix) = k.strip_prefix("wifi.network.ssid.") else {
            continue;
        };
        let entry = val.as_dictionary();
        let ssid = entry
            .and_then(|e| e.get("SSID"))
            .and_then(|s| match s {
                Value::Data(d) => Some(String::from_utf8_lossy(d).into_owned()),
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| suffix.to_string());
        let ssid = clip(&ssid, 64);
        let mut d = new_device(
            format!("wifi:{ssid}"),
            DeviceKind::WifiNetwork,
            ssid.clone(),
        );
        d.transport = Some("Wi-Fi".into());
        if let Some(e) = entry {
            if let Some(t) = e.get("AddedAt").and_then(Value::as_date) {
                d.details.insert(
                    "added_at".into(),
                    crate::util::unix_secs(t.into()).to_string(),
                );
            }
            if let Some(s) = get_str(e, "SupportedSecurityTypes") {
                d.details.insert("security".into(), s);
            }
            if let Some(h) = get_bool(e, "Hidden") {
                d.details.insert("hidden".into(), bool_str(h));
            }
        }
        out.push(d);
    }
    Ok(out)
}

/// `networksetup -listallhardwareports`: BSD name -> (hardware port, permanent MAC).
pub fn parse_networksetup_ports(text: &str) -> BTreeMap<String, (String, Option<String>)> {
    let mut out = BTreeMap::new();
    let mut port: Option<String> = None;
    let mut dev: Option<String> = None;
    let flush = |port: &mut Option<String>,
                 dev: &mut Option<String>,
                 mac: Option<String>,
                 out: &mut BTreeMap<_, _>| {
        if let (Some(p), Some(d)) = (port.take(), dev.take()) {
            out.insert(d, (p, mac));
        }
    };
    for line in text.lines() {
        let t = line.trim();
        if let Some(p) = t.strip_prefix("Hardware Port:") {
            flush(&mut port, &mut dev, None, &mut out);
            port = Some(clip(p.trim(), 128));
        } else if let Some(d) = t.strip_prefix("Device:") {
            dev = Some(clip(d.trim(), 32));
        } else if let Some(m) = t.strip_prefix("Ethernet Address:") {
            let mac = normalize_mac(m.trim());
            flush(&mut port, &mut dev, mac, &mut out);
        }
    }
    flush(&mut port, &mut dev, None, &mut out);
    out
}

/// `AA:BB:cc:…` (6 octets, not all zero) -> lowercase, else `None`.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6
        || !parts
            .iter()
            .all(|p| (1..=2).contains(&p.len()) && p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return None;
    }
    let norm: Vec<String> = parts
        .iter()
        .map(|p| format!("{:0>2}", p.to_ascii_lowercase()))
        .collect();
    if norm.iter().all(|p| p == "00") {
        return None;
    }
    Some(norm.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fx(name: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn ioreg_usb_hid_thunderbolt() {
        let usb = parse_ioreg_archive(&fx("ioreg_usb.plist")).unwrap();
        assert_eq!(usb.len(), 2);
        let key = usb_from_props(&usb[0]).unwrap();
        assert_eq!(key.id, "usb:0781:5581:4C530001230712112440");
        assert_eq!(key.name, "Ultra");
        assert_eq!(key.vendor.as_deref(), Some("SanDisk"));
        assert_eq!(key.vendor_id, Some(0x0781));
        assert_eq!(key.details["interface_classes"], "8");
        assert_eq!(key.details["has_storage"], "true");
        assert_eq!(key.details["registry_id"], "4294971234");
        let rubber = usb_from_props(&usb[1]).unwrap();
        assert_eq!(rubber.id, "usb:05ac:0221:loc-1100000");
        assert_eq!(rubber.details["has_hid"], "true");

        let hid = parse_ioreg_archive(&fx("ioreg_hid.plist")).unwrap();
        let devs: Vec<DeviceInfo> = hid.iter().filter_map(hid_from_props).collect();
        assert_eq!(devs.len(), 3);
        assert_eq!(devs[0].transport.as_deref(), Some("FIFO"));
        assert_eq!(devs[0].details["built_in"], "true");
        assert_eq!(devs[0].details["is_keyboard"], "true");
        assert_eq!(devs[1].id, "hid:05ac:0221:loc-1100000");
        assert_eq!(devs[1].details["is_keyboard"], "true");
        assert_eq!(devs[1].details["built_in"], "false");
        assert_eq!(
            devs[2].details["is_keyboard"], "true",
            "keyboard found in DeviceUsagePairs"
        );
        assert_eq!(devs[2].details["usage"], "2");
        assert_eq!(devs[2].transport.as_deref(), Some("Bluetooth Low Energy"));

        let tb = parse_ioreg_archive(&fx("ioreg_thunderbolt.plist")).unwrap();
        let t: Vec<DeviceInfo> = tb.iter().filter_map(thunderbolt_from_props).collect();
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].details["built_in"], "true");
        assert_eq!(t[1].id, "tb:00d4a2bd8a7c3f00");
        assert_eq!(t[1].vendor.as_deref(), Some("CalDigit, Inc."));
        assert_eq!(t[1].details["built_in"], "false");
        let sp = parse_system_profiler_thunderbolt(&fx("system_profiler_thunderbolt.json"));
        assert!(sp.contains(&(
            0x00d4_a2bd_8a7c_3f00,
            Some("TS4".into()),
            Some("CalDigit, Inc.".into())
        )));
        assert!(parse_ioreg_archive(b"").unwrap().is_empty());
    }

    #[test]
    fn volumes() {
        let m = MountEntry {
            mount_point: PathBuf::from("/Volumes/USBKEY"),
            mount_from: "/dev/disk4s1".into(),
            fstype: "msdos".into(),
            flags: 0,
        };
        let d = parse_diskutil_info(&fx("diskutil_usb.plist")).unwrap();
        let v = volume_from_diskutil(&d, &m).unwrap();
        assert_eq!(v.id, "vol:6A7F2B1C-3D4E-3F5A-9B8C-7D6E5F4A3B2C");
        assert_eq!(v.name, "USBKEY");
        assert_eq!(v.transport.as_deref(), Some("USB"));
        assert_eq!(v.details["internal"], "false");
        assert_eq!(v.details["disk_image"], "false");
        assert_eq!(v.details["filesystem"], "msdos");
        assert_eq!(v.details["mount_point"], "/Volumes/USBKEY");
        assert_eq!(v.details["protocol"], "USB");
        let dmg = parse_diskutil_info(&fx("diskutil_dmg.plist")).unwrap();
        let m2 = MountEntry {
            mount_point: PathBuf::from("/Volumes/Installer"),
            mount_from: "/dev/disk5s1".into(),
            fstype: "apfs".into(),
            flags: 0,
        };
        let v2 = volume_from_diskutil(&dmg, &m2).unwrap();
        assert_eq!(v2.transport.as_deref(), Some("Virtual"));
        assert_eq!(v2.details["disk_image"], "true");

        let own = Path::new("/Library/Application Support/Parabellum");
        assert!(is_reportable_mount(&m, &["/Volumes"], own));
        let hidden = MountEntry {
            mount_point: PathBuf::from("/Volumes/.timemachine"),
            ..m.clone()
        };
        assert!(!is_reportable_mount(&hidden, &["/Volumes"], own));
        let snap = MountEntry {
            mount_point: PathBuf::from("/Volumes/com.apple.TimeMachine.localsnapshots"),
            ..m.clone()
        };
        assert!(!is_reportable_mount(&snap, &["/Volumes"], own));
        let nobrowse = MountEntry {
            flags: MNT_DONTBROWSE,
            ..m.clone()
        };
        assert!(!is_reportable_mount(&nobrowse, &["/Volumes"], own));
        let root = MountEntry {
            mount_point: PathBuf::from("/"),
            ..m.clone()
        };
        assert!(!is_reportable_mount(&root, &["/Volumes"], own));
        let smb = MountEntry {
            mount_point: PathBuf::from("/Volumes/share"),
            mount_from: "//q@nas/share".into(),
            fstype: "smbfs".into(),
            flags: 0,
        };
        let s = volume_from_mount(&smb);
        assert_eq!(s.transport.as_deref(), Some("Network"));
        assert_eq!(s.id, "vol:net:__q_nas_share");
    }

    #[test]
    fn bluetooth_sources() {
        let legacy = parse_bluetooth_prefs(&fx("bluetooth_prefs.plist")).unwrap();
        assert_eq!(legacy.len(), 2);
        assert_eq!(legacy[0].id, "bt:a4:83:e7:11:22:33");
        assert_eq!(legacy[0].name, "Magic Keyboard");
        assert_eq!(legacy[0].vendor_id, Some(76));
        let mobile = parse_mobile_bluetooth_devices(&fx("mobile_bluetooth_devices.plist")).unwrap();
        assert_eq!(mobile.len(), 2);
        assert!(mobile
            .iter()
            .any(|d| d.id == "bt:f4:34:f0:aa:bb:cc" && d.name == "AirPods Pro"));
        let sp = parse_system_profiler_bluetooth(&fx("system_profiler_bluetooth.json")).unwrap();
        assert_eq!(sp.len(), 2);
        assert_eq!(sp[0].id, "bt:a4:83:e7:11:22:33");
        assert_eq!(sp[0].details["connected_now"], "true");
        assert_eq!(sp[0].vendor_id, Some(0x4c));
        assert_eq!(sp[1].details["connected_now"], "false");
        assert_eq!(
            normalize_bt_address("A4-83-E7-11-22-33").as_deref(),
            Some("a4:83:e7:11:22:33")
        );
        assert_eq!(normalize_bt_address("nope"), None);
    }

    #[test]
    fn wifi_and_network() {
        let nets = parse_known_networks(&fx("known_networks.plist")).unwrap();
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].id, "wifi:Café Wi-Fi");
        assert!(nets[0].details.contains_key("added_at"));
        assert_eq!(nets[1].id, "wifi:HomeNet");
        let text = String::from_utf8(fx("networksetup_ports.txt")).unwrap();
        let ports = parse_networksetup_ports(&text);
        assert_eq!(
            ports["en0"],
            ("Wi-Fi".to_string(), Some("3c:22:fb:01:02:03".to_string()))
        );
        assert_eq!(ports["en5"].0, "USB 10/100/1000 LAN");
        assert_eq!(ports["bridge0"], ("Thunderbolt Bridge".to_string(), None));
        assert_eq!(
            normalize_mac("0:1:2:a:b:c").as_deref(),
            Some("00:01:02:0a:0b:0c")
        );
        assert_eq!(normalize_mac("00:00:00:00:00:00"), None);
        assert_eq!(parse_int_text("0x004C (Apple)"), Some(76));
        assert_eq!(id_part("a b:c/d"), "a_b_c_d");
    }
}
