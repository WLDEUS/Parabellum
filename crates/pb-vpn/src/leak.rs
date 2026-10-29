//! Leak test: is the traffic really leaving through the tunnel?
//!
//! Probes (through the default route, i.e. the tunnel when it is up): public IPv4 and IPv6 from ipify, the
//! system DNS servers (`scutil --dns`), the physical interface's IPv6 addresses. [`evaluate`] (pure) turns
//! them into checks: tunnel up, public IPv4 different from the network's IP without VPN, no IPv6 exit with
//! the ISP's prefix, no DNS server outside the tunnel, kill switch healthy.

use crate::sys::System;
use pb_core::model::{KillSwitchState, LeakCheck, LeakTestResult};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub const IPV4_URL: &str = "https://api.ipify.org?format=json";
pub const IPV6_URL: &str = "https://api6.ipify.org?format=json";
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// `{"ip":"203.0.113.7"}`.
pub fn parse_ipify(body: &str) -> Option<IpAddr> {
    let v: serde_json::Value = serde_json::from_str(body.trim()).ok()?;
    v.get("ip")?.as_str()?.trim().parse().ok()
}

/// Public IPv4 / IPv6 as seen by ipify (each `None` when unreachable).
pub async fn probe_public(sys: &dyn System) -> (Option<Ipv4Addr>, Option<Ipv6Addr>) {
    let (v4, v6) = tokio::join!(
        sys.http_get(IPV4_URL, PROBE_TIMEOUT),
        sys.http_get(IPV6_URL, PROBE_TIMEOUT)
    );
    let v4 = v4
        .ok()
        .and_then(|b| parse_ipify(&b))
        .and_then(|ip| match ip {
            IpAddr::V4(a) => Some(a),
            IpAddr::V6(a) => a.to_ipv4_mapped(),
        });
    let v6 = v6
        .ok()
        .and_then(|b| parse_ipify(&b))
        .and_then(|ip| match ip {
            IpAddr::V6(a) if a.to_ipv4_mapped().is_none() => Some(a),
            _ => None,
        });
    (v4, v6)
}

/// Everything [`evaluate`] needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LeakInputs {
    pub ts: i64,
    pub vpn_connected: bool,
    pub tunnel_interface: Option<String>,
    pub public_ipv4: Option<Ipv4Addr>,
    pub public_ipv6: Option<Ipv6Addr>,
    /// Public IPv4 of this network without the VPN.
    pub home_ipv4: Option<Ipv4Addr>,
    /// Global IPv6 addresses of the physical interface.
    pub physical_ipv6: Vec<Ipv6Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub gateway_ip: Option<Ipv4Addr>,
    /// Private ranges bypass the tunnel (`vpn.allow_lan`).
    pub allow_lan: bool,
    pub kill_switch_enabled: bool,
    pub kill_switch: KillSwitchState,
}

fn same_64(a: &Ipv6Addr, b: &Ipv6Addr) -> bool {
    a.segments()[..4] == b.segments()[..4]
}

/// Private / link-local ranges that do not go through the tunnel when the LAN is allowed (198.18.0.0/15,
/// the tunnel's own range, is not one of them).
fn is_lan(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => {
            let s0 = a.segments()[0];
            (s0 & 0xffc0) == 0xfe80 || ((s0 & 0xfe00) == 0xfc00 && !is_tunnel_v6(a))
        }
    }
}

fn is_tunnel_v6(a: &Ipv6Addr) -> bool {
    // fdfe:dcba:9876::/48 (sing-box TUN).
    a.segments()[..3] == [0xfdfe, 0xdcba, 0x9876]
}

fn check(id: &str, ok: bool, detail: String) -> LeakCheck {
    LeakCheck {
        id: id.into(),
        ok,
        detail,
    }
}

/// Turn the probes into checks.
pub fn evaluate(i: &LeakInputs) -> LeakTestResult {
    let mut checks = Vec::new();
    checks.push(if i.vpn_connected {
        check(
            "tunnel",
            true,
            match &i.tunnel_interface {
                Some(t) => format!("Tunnel actif ({t})"),
                None => "Tunnel actif".into(),
            },
        )
    } else {
        check(
            "tunnel",
            false,
            "VPN déconnecté : le trafic ne passe pas par un tunnel".into(),
        )
    });

    checks.push(match (i.public_ipv4, i.home_ipv4) {
        (None, _) => check(
            "ipv4",
            false,
            "Adresse IPv4 publique introuvable (Internet injoignable ?)".into(),
        ),
        (Some(ip), Some(home)) if ip == home => check(
            "ipv4",
            false,
            format!("L'adresse publique {ip} est celle de ce réseau sans VPN : le trafic sort sans tunnel"),
        ),
        (Some(ip), Some(home)) => check(
            "ipv4",
            true,
            format!("Adresse publique {ip} (sans VPN : {home})"),
        ),
        (Some(ip), None) => check(
            "ipv4",
            true,
            format!("Adresse publique {ip} (adresse sans VPN pas encore connue sur ce réseau)"),
        ),
    });

    checks.push(match i.public_ipv6 {
        None => check(
            "ipv6",
            true,
            "IPv6 bloqué ou indisponible : pas de fuite IPv6".into(),
        ),
        Some(v6) if i.physical_ipv6.iter().any(|p| same_64(p, &v6)) => check(
            "ipv6",
            false,
            format!("Fuite IPv6 : {v6} appartient au réseau de votre fournisseur d'accès"),
        ),
        Some(v6) => check(
            "ipv6",
            true,
            format!("Sortie IPv6 {v6} (hors de votre réseau)"),
        ),
    });

    let leaky: Vec<String> = i
        .dns_servers
        .iter()
        .filter(|s| {
            !s.is_loopback()
                && i.allow_lan
                && (is_lan(s) || i.gateway_ip.map(IpAddr::V4).as_ref() == Some(*s))
        })
        .map(|s| s.to_string())
        .collect();
    checks.push(if i.dns_servers.is_empty() {
        check("dns", true, "Aucun serveur DNS système détecté".into())
    } else if leaky.is_empty() {
        let list: Vec<String> = i.dns_servers.iter().map(|s| s.to_string()).collect();
        check("dns", true, format!("Serveurs DNS : {}", list.join(", ")))
    } else {
        check(
            "dns",
            false,
            format!(
                "Requêtes DNS envoyées hors du tunnel à {} : activez le blocage DNS de Parabellum",
                leaky.join(", ")
            ),
        )
    });

    checks.push(if !i.kill_switch_enabled {
        check("kill_switch", true, "Coupe-circuit désactivé".into())
    } else {
        match i.kill_switch {
            KillSwitchState::Armed => check("kill_switch", true, "Coupe-circuit actif".into()),
            KillSwitchState::Blocking => check(
                "kill_switch",
                true,
                "Coupe-circuit actif : trafic bloqué tant que le tunnel est coupé".into(),
            ),
            KillSwitchState::Off => check(
                "kill_switch",
                true,
                "Coupe-circuit en veille (VPN non requis sur ce réseau)".into(),
            ),
            KillSwitchState::Error => check(
                "kill_switch",
                false,
                "Coupe-circuit en erreur : le trafic n'est pas protégé si le tunnel tombe".into(),
            ),
        }
    });

    LeakTestResult {
        ts: i.ts,
        ok: checks.iter().all(|c| c.ok),
        vpn_connected: i.vpn_connected,
        public_ipv4: i.public_ipv4.map(|a| a.to_string()),
        public_ipv6: i.public_ipv6.map(|a| a.to_string()),
        home_ipv4: i.home_ipv4.map(|a| a.to_string()),
        dns_servers: i.dns_servers.iter().map(|s| s.to_string()).collect(),
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::FakeSystem;

    fn healthy() -> LeakInputs {
        LeakInputs {
            ts: 5,
            vpn_connected: true,
            tunnel_interface: Some("utun6".into()),
            public_ipv4: Some("203.0.113.9".parse().unwrap()),
            public_ipv6: None,
            home_ipv4: Some("90.12.34.56".parse().unwrap()),
            physical_ipv6: vec!["2a01:cb00:1234:5600::1".parse().unwrap()],
            dns_servers: vec!["127.0.0.1".parse().unwrap()],
            gateway_ip: Some("192.168.1.254".parse().unwrap()),
            allow_lan: true,
            kill_switch_enabled: true,
            kill_switch: KillSwitchState::Armed,
        }
    }

    fn failing(r: &LeakTestResult) -> Vec<&str> {
        r.checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| c.id.as_str())
            .collect()
    }

    #[test]
    fn healthy_tunnel_passes() {
        let r = evaluate(&healthy());
        assert!(r.ok, "{r:?}");
        assert_eq!(r.checks.len(), 5);
        assert_eq!(r.public_ipv4.as_deref(), Some("203.0.113.9"));
        assert_eq!(r.home_ipv4.as_deref(), Some("90.12.34.56"));
    }

    #[test]
    fn each_leak() {
        let mut i = healthy();
        i.public_ipv4 = i.home_ipv4;
        assert_eq!(failing(&evaluate(&i)), vec!["ipv4"]);
        let mut i = healthy();
        i.public_ipv6 = Some("2a01:cb00:1234:5600:aaaa::9".parse().unwrap());
        assert_eq!(failing(&evaluate(&i)), vec!["ipv6"]);
        let mut i = healthy();
        i.public_ipv6 = Some("2001:db8:ffff::9".parse().unwrap());
        assert!(evaluate(&i).ok);
        let mut i = healthy();
        i.dns_servers = vec![
            "192.168.1.254".parse().unwrap(),
            "198.18.0.2".parse().unwrap(),
        ];
        let r = evaluate(&i);
        assert_eq!(failing(&r), vec!["dns"]);
        assert!(r.checks[3].detail.contains("192.168.1.254"));
        assert!(!r.checks[3].detail.contains("198.18.0.2"));
        // Without LAN bypass the router's DNS is hijacked inside the tunnel.
        i.allow_lan = false;
        assert!(evaluate(&i).ok);
        let mut i = healthy();
        i.kill_switch = KillSwitchState::Error;
        assert_eq!(failing(&evaluate(&i)), vec!["kill_switch"]);
        let mut i = healthy();
        i.vpn_connected = false;
        i.public_ipv4 = None;
        assert_eq!(failing(&evaluate(&i)), vec!["tunnel", "ipv4"]);
        let mut i = healthy();
        i.dns_servers = vec![
            "fdfe:dcba:9876::2".parse().unwrap(),
            "fd00::1".parse().unwrap(),
        ];
        assert_eq!(failing(&evaluate(&i)), vec!["dns"]);
    }

    #[tokio::test]
    async fn probes_parse_ipify() {
        assert_eq!(
            parse_ipify("{\"ip\":\"1.2.3.4\"}"),
            Some("1.2.3.4".parse().unwrap())
        );
        assert_eq!(parse_ipify("nope"), None);
        let sys = FakeSystem::linux();
        sys.http(IPV4_URL, Ok("{\"ip\":\"203.0.113.9\"}"));
        sys.http(IPV6_URL, Err("timeout"));
        let (v4, v6) = probe_public(sys.as_ref()).await;
        assert_eq!(v4, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(v6, None);
    }
}
