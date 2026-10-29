//! Network guard: pure detection on successive [`NetworkSnapshot`]s.
//!
//! - The router's MAC changed for the same router IP on the same interface / Wi-Fi, between two consecutive
//!   polls (no disconnection in between): someone answers ARP for the router (ARP spoofing / man in the
//!   middle) — high.
//! - Another IP of the LAN answers with the router's MAC: classic ARP-poisoning footprint — medium (some
//!   routers legitimately own two addresses).
//! - A Wi-Fi name known as secured is now open: evil twin — high.
//!
//! A new network is only recorded (no alert).

use crate::netprobe::{security_is_open, NetworkSnapshot};
use crate::store::StoredNetwork;
use crate::NetAlert;
use pb_core::model::Severity;

/// Alerts for `cur` given the previous consecutive snapshot (`None` after a disconnection) and the known
/// networks *before* `cur` was recorded.
pub fn detect(
    prev: Option<&NetworkSnapshot>,
    cur: &NetworkSnapshot,
    known: &[StoredNetwork],
) -> Vec<NetAlert> {
    let mut alerts = Vec::new();
    let cur_id = cur.network_id();

    // 1. Router MAC changed under our feet.
    if let (Some(p), Some(gw), Some(new_mac)) = (prev, cur.gateway_ip, cur.gateway_mac.as_deref()) {
        let same_place = p.interface == cur.interface
            && p.gateway_ip == Some(gw)
            && p.ssid == cur.ssid
            && match (&p.bssid, &cur.bssid) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            };
        if let Some(old_mac) = p.gateway_mac.as_deref() {
            if same_place && old_mac != new_mac {
                alerts.push(NetAlert {
                    severity: Severity::High,
                    title: "Usurpation possible du routeur (ARP)".into(),
                    message: format!(
                        "Sur {}, l'adresse du routeur {gw} répond maintenant avec l'adresse matérielle {new_mac} au \
                         lieu de {old_mac}, sans déconnexion. Un appareil du réseau peut intercepter votre trafic \
                         (attaque de l'homme du milieu). Activez le VPN ou quittez ce réseau ; si vous venez de \
                         changer de box, ignorez cette alerte.",
                        cur.display_name()
                    ),
                    network_id: cur_id.clone(),
                    key: format!("arp-spoof:{gw}:{new_mac}"),
                    offer_trust: false,
                });
            }
        }
    }

    // 2. Another host claims the router's MAC.
    if let (Some(gw), Some(mac)) = (cur.gateway_ip, cur.gateway_mac.as_deref()) {
        for e in cur
            .arp
            .iter()
            .filter(|e| e.mac == mac && e.ip != gw && e.interface == cur.interface)
        {
            alerts.push(NetAlert {
                severity: Severity::Medium,
                title: "Adresse matérielle du routeur partagée".into(),
                message: format!(
                    "Sur {}, l'appareil {} utilise la même adresse matérielle ({mac}) que le routeur {gw}. C'est la \
                     trace habituelle d'un empoisonnement ARP, ou d'un routeur qui possède deux adresses.",
                    cur.display_name(),
                    e.ip
                ),
                network_id: cur_id.clone(),
                key: format!("arp-dup:{mac}:{}", e.ip),
                offer_trust: false,
            });
        }
    }

    // 3. Evil twin: a known secured Wi-Fi name is now open.
    if let (Some(ssid), Some(true)) = (cur.ssid.as_deref(), cur.is_open()) {
        let was_secured = known.iter().any(|n| {
            n.ssid.as_deref() == Some(ssid)
                && n.security.as_deref().map(|s| !security_is_open(s)) == Some(true)
        });
        if was_secured {
            alerts.push(NetAlert {
                severity: Severity::High,
                title: "Faux point d'accès Wi-Fi possible".into(),
                message: format!(
                    "Le réseau « {ssid} » était protégé par un mot de passe et apparaît maintenant ouvert : il peut \
                     s'agir d'un faux point d'accès qui imite le vrai (evil twin). Déconnectez-vous ou activez le \
                     VPN avant d'aller plus loin."
                ),
                network_id: cur_id,
                key: format!("evil-twin:{ssid}"),
                offer_trust: false,
            });
        }
    }
    alerts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netprobe::ArpEntry;

    fn snap(mac: &str) -> NetworkSnapshot {
        NetworkSnapshot {
            interface: "en0".into(),
            gateway_ip: Some("192.168.1.254".parse().unwrap()),
            gateway_mac: Some(mac.into()),
            ssid: Some("Livebox-1234".into()),
            bssid: None,
            security: Some("WPA2_PSK".into()),
            is_wifi: true,
            arp: vec![],
            default_via_tunnel: false,
        }
    }

    #[test]
    fn arp_spoofing_between_consecutive_polls() {
        let a = snap("00:24:d4:a1:b2:c3");
        let b = snap("de:ad:be:ef:00:01");
        let alerts = detect(Some(&a), &b, &[]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::High);
        assert_eq!(alerts[0].key, "arp-spoof:192.168.1.254:de:ad:be:ef:00:01");
        assert_eq!(
            alerts[0].network_id.as_deref(),
            Some("gw:de:ad:be:ef:00:01")
        );
        // Same MAC: nothing. After a disconnection (prev None): nothing.
        assert!(detect(Some(&a), &a, &[]).is_empty());
        assert!(detect(None, &b, &[]).is_empty());
        // Different Wi-Fi: a new network, not an attack.
        let mut other = b.clone();
        other.ssid = Some("Cafe".into());
        assert!(detect(Some(&a), &other, &[]).is_empty());
        // Different BSSID (roaming to another router of the same name and IP plan): no alert.
        let mut a2 = a.clone();
        a2.bssid = Some("6c:44:1a:22:33:44".into());
        let mut b2 = b.clone();
        b2.bssid = Some("6c:44:1a:22:33:55".into());
        assert!(detect(Some(&a2), &b2, &[]).is_empty());
    }

    #[test]
    fn duplicate_router_mac() {
        let mut s = snap("00:24:d4:a1:b2:c3");
        s.arp = vec![
            ArpEntry {
                ip: "192.168.1.254".parse().unwrap(),
                mac: "00:24:d4:a1:b2:c3".into(),
                interface: "en0".into(),
            },
            ArpEntry {
                ip: "192.168.1.66".parse().unwrap(),
                mac: "00:24:d4:a1:b2:c3".into(),
                interface: "en0".into(),
            },
            ArpEntry {
                ip: "192.168.1.12".parse().unwrap(),
                mac: "3c:22:fb:01:02:03".into(),
                interface: "en0".into(),
            },
        ];
        let alerts = detect(None, &s, &[]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].severity, Severity::Medium);
        assert!(alerts[0].message.contains("192.168.1.66"));
    }

    #[test]
    fn evil_twin() {
        let known = vec![StoredNetwork {
            id: "gw:00:24:d4:a1:b2:c3".into(),
            ssid: Some("Livebox-1234".into()),
            security: Some("WPA2_PSK".into()),
            ..Default::default()
        }];
        let mut open = snap("12:34:56:78:9a:bc");
        open.security = Some("None".into());
        let alerts = detect(None, &open, &known);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].key, "evil-twin:Livebox-1234");
        // Unknown name, or known as open already: nothing.
        let mut other = open.clone();
        other.ssid = Some("FreeWifi".into());
        assert!(detect(None, &other, &known).is_empty());
        let known_open = vec![StoredNetwork {
            ssid: Some("Livebox-1234".into()),
            security: Some("Open".into()),
            ..Default::default()
        }];
        assert!(detect(None, &open, &known_open).is_empty());
    }
}
