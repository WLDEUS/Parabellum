//! `state/lan.json`: devices seen per network (root-only state directory), and the merge of a scan into it.

use super::classify::{self, Evidence};
use super::oui::is_private_mac;
use pb_core::model::{LanDevice, LanDeviceType, LanNetwork, LanNetworkSummary, LanScanMode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub const LAN_FILE: &str = "lan.json";
/// Networks kept (least recently scanned dropped first).
pub const MAX_NETWORKS: usize = 50;
/// Devices kept per network (least recently seen dropped first).
pub const MAX_DEVICES: usize = 512;
/// IPv6 addresses kept per device.
const MAX_V6: usize = 8;
/// Bonjour services kept per device.
const MAX_SERVICES: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StoredLanNetwork {
    pub id: String,
    pub name: String,
    pub interface: String,
    pub subnet: Option<String>,
    pub first_seen: i64,
    pub last_scan: Option<i64>,
    pub last_scan_mode: Option<LanScanMode>,
    pub devices: Vec<LanDevice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LanFile {
    pub version: u32,
    pub networks: Vec<StoredLanNetwork>,
}

/// What one scan saw of one device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    pub mac: String,
    pub ipv4: Option<String>,
    pub ipv6: Vec<String>,
    pub hostname: Option<String>,
    pub mdns_name: Option<String>,
    pub model: Option<String>,
    pub services: Vec<String>,
    pub is_gateway: bool,
    pub is_self: bool,
}

impl LanFile {
    pub fn load(dir: &Path) -> Self {
        match pb_vpn::fsutil::read_json::<LanFile>(&dir.join(LAN_FILE)) {
            Ok(Some(f)) => f,
            Ok(None) => Self::default(),
            Err(e) => {
                tracing::warn!(error = %e, "lan.json unreadable, starting empty");
                Self::default()
            }
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        pb_vpn::fsutil::write_json(&dir.join(LAN_FILE), self)
    }

    pub fn get(&self, id: &str) -> Option<&StoredLanNetwork> {
        self.networks.iter().find(|n| n.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut StoredLanNetwork> {
        self.networks.iter_mut().find(|n| n.id == id)
    }

    /// The network `id`, created when new.
    pub fn network_mut(
        &mut self,
        id: &str,
        name: &str,
        interface: &str,
        now: i64,
    ) -> &mut StoredLanNetwork {
        if let Some(i) = self.networks.iter().position(|n| n.id == id) {
            let n = &mut self.networks[i];
            if !name.is_empty() && (n.name.is_empty() || !name.starts_with("Wi-Fi (")) {
                n.name = name.to_string();
            }
            n.interface = interface.to_string();
            return &mut self.networks[i];
        }
        if self.networks.len() >= MAX_NETWORKS {
            self.networks
                .sort_by_key(|n| std::cmp::Reverse(n.last_scan.unwrap_or(n.first_seen)));
            self.networks.truncate(MAX_NETWORKS - 1);
        }
        self.networks.push(StoredLanNetwork {
            id: id.to_string(),
            name: name.to_string(),
            interface: interface.to_string(),
            first_seen: now,
            ..Default::default()
        });
        self.networks.last_mut().expect("just pushed")
    }

    /// Summaries, current first then most recently scanned.
    pub fn summaries(&self, trusted: &[String], current: Option<&str>) -> Vec<LanNetworkSummary> {
        let mut v: Vec<LanNetworkSummary> = self
            .networks
            .iter()
            .map(|n| LanNetworkSummary {
                id: n.id.clone(),
                name: n.name.clone(),
                trusted: trusted.contains(&n.id),
                current: current == Some(n.id.as_str()),
                devices: n.devices.len() as u32,
                unknown: n.devices.iter().filter(|d| is_unknown(d)).count() as u32,
                last_scan: n.last_scan,
            })
            .collect();
        v.sort_by_key(|s| (!s.current, std::cmp::Reverse(s.last_scan.unwrap_or(0))));
        v
    }
}

/// Neither known by the user, nor this Mac / the router.
pub fn is_unknown(d: &LanDevice) -> bool {
    !d.trusted && !d.is_self && !d.is_gateway
}

/// Public view of a stored network (devices: online first, then by IP).
pub fn view(n: &StoredLanNetwork, trusted: bool, current: bool) -> LanNetwork {
    let mut devices = n.devices.clone();
    devices.sort_by(|a, b| {
        (!a.online, ip_key(a.ipv4.as_deref()), &a.mac).cmp(&(
            !b.online,
            ip_key(b.ipv4.as_deref()),
            &b.mac,
        ))
    });
    LanNetwork {
        id: n.id.clone(),
        name: n.name.clone(),
        interface: n.interface.clone(),
        subnet: n.subnet.clone(),
        trusted,
        current,
        last_scan: n.last_scan,
        last_scan_mode: n.last_scan_mode,
        devices,
    }
}

fn ip_key(ip: Option<&str>) -> u32 {
    ip.and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .map(u32::from)
        .unwrap_or(u32::MAX)
}

fn push_unique(list: &mut Vec<String>, v: &str, cap: usize) {
    if !list.iter().any(|x| x == v) && list.len() < cap {
        list.push(v.to_string());
    }
}

/// Merge one scan into `net`. Devices not observed go offline. Returns the devices seen for the first
/// time (none on the network's first scan: they become the baseline).
pub fn merge(
    net: &mut StoredLanNetwork,
    observations: Vec<Observation>,
    vendors: &HashMap<String, String>,
    mode: LanScanMode,
    now: i64,
) -> Vec<LanDevice> {
    let first_scan = net.last_scan.is_none();
    let mut index: BTreeMap<String, usize> = net
        .devices
        .iter()
        .enumerate()
        .map(|(i, d)| (d.mac.clone(), i))
        .collect();
    for d in &mut net.devices {
        d.online = false;
    }
    let mut new_macs = Vec::new();
    for o in observations {
        let i = match index.get(&o.mac) {
            Some(i) => *i,
            None => {
                net.devices.push(LanDevice {
                    mac: o.mac.clone(),
                    ipv4: None,
                    ipv6: vec![],
                    hostname: None,
                    mdns_name: None,
                    name: None,
                    vendor: None,
                    private_mac: is_private_mac(&o.mac),
                    device_type: LanDeviceType::Unknown,
                    model: None,
                    services: vec![],
                    open_ports: vec![],
                    ports_checked_at: None,
                    first_seen: now,
                    last_seen: now,
                    online: true,
                    trusted: false,
                    baseline: first_scan,
                    is_gateway: false,
                    is_self: false,
                });
                let i = net.devices.len() - 1;
                index.insert(o.mac.clone(), i);
                if !first_scan {
                    new_macs.push(o.mac.clone());
                }
                i
            }
        };
        let d = &mut net.devices[i];
        d.online = true;
        d.last_seen = now;
        if o.ipv4.is_some() {
            // Another device may have had this address before (DHCP): it is no longer there.
            d.ipv4 = o.ipv4.clone();
        }
        for a in &o.ipv6 {
            push_unique(&mut d.ipv6, a, MAX_V6);
        }
        if o.hostname.is_some() {
            d.hostname = o.hostname.clone();
        }
        if o.mdns_name.is_some() {
            d.mdns_name = o.mdns_name.clone();
        }
        if o.model.is_some() {
            d.model = o.model.clone();
        }
        for s in &o.services {
            push_unique(&mut d.services, s, MAX_SERVICES);
        }
        d.is_gateway = o.is_gateway;
        d.is_self = o.is_self;
        if let Some(v) = vendors.get(&d.mac) {
            d.vendor = Some(v.clone());
        }
    }
    // An address now held by another online device is stale on the offline ones.
    let online_v4: Vec<String> = net
        .devices
        .iter()
        .filter(|d| d.online)
        .filter_map(|d| d.ipv4.clone())
        .collect();
    for d in net.devices.iter_mut().filter(|d| !d.online) {
        if d.ipv4.as_ref().is_some_and(|ip| online_v4.contains(ip)) {
            d.ipv4 = None;
        }
    }
    for d in &mut net.devices {
        d.device_type = classify::guess(&Evidence {
            is_gateway: d.is_gateway,
            is_self: d.is_self,
            vendor: d.vendor.as_deref(),
            model: d.model.as_deref(),
            services: &d.services,
            names: [d.mdns_name.as_deref(), d.hostname.as_deref()]
                .into_iter()
                .flatten()
                .collect(),
            open_ports: &d.open_ports,
        });
    }
    if net.devices.len() > MAX_DEVICES {
        net.devices.sort_by_key(|d| std::cmp::Reverse(d.last_seen));
        net.devices.truncate(MAX_DEVICES);
    }
    net.last_scan = Some(now);
    net.last_scan_mode = Some(mode);
    net.devices
        .iter()
        .filter(|d| new_macs.contains(&d.mac))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(mac: &str, ip: &str) -> Observation {
        Observation {
            mac: mac.into(),
            ipv4: Some(ip.into()),
            ..Default::default()
        }
    }

    #[test]
    fn first_scan_is_baseline_then_new_devices() {
        let mut f = LanFile::default();
        let net = f.network_mut("gw:00:24:d4:a1:b2:c3", "Livebox-1234", "en0", 100);
        let mut gw = obs("00:24:d4:a1:b2:c3", "192.168.1.1");
        gw.is_gateway = true;
        let vendors: HashMap<String, String> =
            [("00:24:d4:a1:b2:c3".to_string(), "Freebox SAS".to_string())].into();
        let new = merge(
            net,
            vec![gw.clone(), obs("f0:18:98:aa:bb:cc", "192.168.1.20")],
            &vendors,
            LanScanMode::Active,
            100,
        );
        assert!(new.is_empty());
        assert!(net.devices.iter().all(|d| d.baseline && d.online));
        assert_eq!(net.devices[0].device_type, LanDeviceType::Router);
        assert_eq!(net.devices[0].vendor.as_deref(), Some("Freebox SAS"));
        // Second scan: a phone with a private address joins, the laptop left and its IP was reused.
        let mut phone = obs("3a:5f:12:9c:7e:01", "192.168.1.20");
        phone.services = vec!["_companion-link._tcp".into()];
        phone.model = Some("iPhone15,3".into());
        let new = merge(net, vec![gw, phone], &vendors, LanScanMode::Passive, 200);
        assert_eq!(new.len(), 1);
        assert!(new[0].private_mac && !new[0].baseline);
        assert_eq!(new[0].device_type, LanDeviceType::Phone);
        let laptop = net
            .devices
            .iter()
            .find(|d| d.mac == "f0:18:98:aa:bb:cc")
            .unwrap();
        assert!(!laptop.online && laptop.ipv4.is_none() && laptop.last_seen == 100);
        assert_eq!(net.last_scan_mode, Some(LanScanMode::Passive));
        let v = view(net, true, true);
        assert_eq!(v.devices[0].mac, "00:24:d4:a1:b2:c3");
        assert!(!v.devices.last().unwrap().online);
        let s = f.summaries(
            &["gw:00:24:d4:a1:b2:c3".into()],
            Some("gw:00:24:d4:a1:b2:c3"),
        );
        assert_eq!((s[0].devices, s[0].unknown, s[0].trusted), (3, 2, true));
    }

    #[test]
    fn persistence_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let mut f = LanFile::default();
        f.network_mut("gw:00:11:22:33:44:55", "Bureau", "en7", 5);
        f.save(d.path()).unwrap();
        assert_eq!(LanFile::load(d.path()), f);
        assert_eq!(LanFile::load(&d.path().join("none")), LanFile::default());
    }
}
