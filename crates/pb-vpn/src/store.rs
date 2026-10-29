//! `networks.json`: networks seen (fingerprint, name, last Wi-Fi security, public IP without VPN).

use crate::fsutil;
use crate::netprobe::NetworkSnapshot;
use pb_core::model::NetworkInfo;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Networks kept (least recently seen dropped first).
pub const MAX_NETWORKS: usize = 200;
pub const NETWORKS_FILE: &str = "networks.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StoredNetwork {
    pub id: String,
    pub name: String,
    pub interface: String,
    pub gateway_ip: Option<String>,
    pub gateway_mac: Option<String>,
    pub ssid: Option<String>,
    /// Last known Wi-Fi security (kept when macOS stops reporting it).
    pub security: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Public IPv4 of this network without the VPN (leak test reference).
    pub home_ipv4: Option<String>,
    pub home_checked_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworksFile {
    pub version: u32,
    pub networks: Vec<StoredNetwork>,
}

impl NetworksFile {
    /// Load (an unreadable file starts empty, with a warning).
    pub fn load(dir: &Path) -> Self {
        match fsutil::read_json::<NetworksFile>(&dir.join(NETWORKS_FILE)) {
            Ok(Some(f)) => f,
            Ok(None) => Self::default(),
            Err(e) => {
                tracing::warn!(error = %e, "networks.json unreadable, starting empty");
                Self::default()
            }
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        fsutil::write_json(&dir.join(NETWORKS_FILE), self)
    }

    pub fn get(&self, id: &str) -> Option<&StoredNetwork> {
        self.networks.iter().find(|n| n.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut StoredNetwork> {
        self.networks.iter_mut().find(|n| n.id == id)
    }

    /// Insert or refresh the network of `snap` (needs a router MAC). Returns its id.
    pub fn record(&mut self, snap: &NetworkSnapshot, now: i64) -> Option<String> {
        let id = snap.network_id()?;
        match self.get_mut(&id) {
            Some(n) => {
                n.last_seen = now;
                n.interface = snap.interface.clone();
                n.gateway_ip = snap.gateway_ip.map(|g| g.to_string());
                if snap.ssid.is_some() {
                    n.ssid = snap.ssid.clone();
                    n.name = snap.display_name();
                }
                if snap.security.is_some() {
                    n.security = snap.security.clone();
                }
            }
            None => {
                self.networks.push(StoredNetwork {
                    id: id.clone(),
                    name: snap.display_name(),
                    interface: snap.interface.clone(),
                    gateway_ip: snap.gateway_ip.map(|g| g.to_string()),
                    gateway_mac: snap.gateway_mac.clone(),
                    ssid: snap.ssid.clone(),
                    security: snap.security.clone(),
                    first_seen: now,
                    last_seen: now,
                    home_ipv4: None,
                    home_checked_at: None,
                });
                if self.networks.len() > MAX_NETWORKS {
                    self.networks
                        .sort_by_key(|n| std::cmp::Reverse(n.last_seen));
                    self.networks.truncate(MAX_NETWORKS);
                }
            }
        }
        Some(id)
    }

    /// Public view.
    pub fn info(n: &StoredNetwork, trusted: bool, current: bool) -> NetworkInfo {
        NetworkInfo {
            id: n.id.clone(),
            name: n.name.clone(),
            interface: n.interface.clone(),
            gateway_ip: n.gateway_ip.clone(),
            gateway_mac: n.gateway_mac.clone(),
            ssid: n.ssid.clone(),
            security: n.security.clone(),
            trusted,
            first_seen: n.first_seen,
            last_seen: n.last_seen,
            current,
        }
    }

    /// All networks, current first then most recently seen.
    pub fn list(&self, trusted: &[String], current: Option<&str>) -> Vec<NetworkInfo> {
        let mut v: Vec<NetworkInfo> = self
            .networks
            .iter()
            .map(|n| Self::info(n, trusted.contains(&n.id), current == Some(n.id.as_str())))
            .collect();
        v.sort_by(|a, b| {
            b.current
                .cmp(&a.current)
                .then(b.last_seen.cmp(&a.last_seen))
        });
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(mac: &str, ssid: Option<&str>, sec: Option<&str>) -> NetworkSnapshot {
        NetworkSnapshot {
            interface: "en0".into(),
            gateway_ip: Some("192.168.1.1".parse().unwrap()),
            gateway_mac: Some(mac.into()),
            ssid: ssid.map(str::to_string),
            security: sec.map(str::to_string),
            is_wifi: true,
            ..Default::default()
        }
    }

    #[test]
    fn record_list_and_persist() {
        let d = tempfile::tempdir().unwrap();
        let mut f = NetworksFile::default();
        let a = f
            .record(
                &snap("00:11:22:33:44:55", Some("Home"), Some("WPA2_PSK")),
                10,
            )
            .unwrap();
        let b = f
            .record(&snap("00:11:22:33:44:66", None, None), 20)
            .unwrap();
        // macOS stops reporting the SSID / security: previous values kept.
        f.record(&snap("00:11:22:33:44:55", None, None), 30);
        let home = f.get(&a).unwrap();
        assert_eq!(home.ssid.as_deref(), Some("Home"));
        assert_eq!(home.security.as_deref(), Some("WPA2_PSK"));
        assert_eq!(home.first_seen, 10);
        assert_eq!(home.last_seen, 30);
        let l = f.list(std::slice::from_ref(&a), Some(&b));
        assert_eq!(l[0].id, b);
        assert!(l[0].current && !l[0].trusted);
        assert!(l[1].trusted);
        f.save(d.path()).unwrap();
        assert_eq!(NetworksFile::load(d.path()), f);
        let mut no_mac = snap("00:11:22:33:44:55", None, None);
        no_mac.gateway_mac = None;
        assert_eq!(f.record(&no_mac, 1), None);
    }
}
