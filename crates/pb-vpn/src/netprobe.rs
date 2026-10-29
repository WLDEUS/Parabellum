//! What network is the Mac on? Parsers for `route -n get default`, `netstat -rn -f inet`, `arp -an`,
//! `ipconfig getsummary <if>`, `scutil --dns`, `ifconfig -l` / `ifconfig <if>`, and the probe that combines
//! them into a [`NetworkSnapshot`]. The network is identified by its router's MAC address
//! (`gw:<mac>`): stable, works on Ethernet, needs no Location Services permission (macOS 14.4+ redacts the
//! Wi-Fi name for daemons).

use crate::sys::{System, ARP, CMD_TIMEOUT, IFCONFIG, IPCONFIG, NETSTAT, PING, ROUTE, SCUTIL};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// One ARP cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: Ipv4Addr,
    /// Lowercase, two digits per byte.
    pub mac: String,
    pub interface: String,
}

/// The network the Mac is on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkSnapshot {
    /// Physical interface of the default route (`en0`).
    pub interface: String,
    pub gateway_ip: Option<Ipv4Addr>,
    pub gateway_mac: Option<String>,
    pub ssid: Option<String>,
    pub bssid: Option<String>,
    pub security: Option<String>,
    pub is_wifi: bool,
    /// ARP entries of that interface.
    pub arp: Vec<ArpEntry>,
    /// The default route goes through a tunnel (some VPN is up): the public IP is not the network's own.
    pub default_via_tunnel: bool,
}

impl NetworkSnapshot {
    /// `gw:<router MAC>` when the router's MAC is known.
    pub fn network_id(&self) -> Option<String> {
        let id = format!("gw:{}", self.gateway_mac.as_deref()?);
        pb_core::config::is_network_id(&id).then_some(id)
    }

    /// Display name: Wi-Fi name, else `Ethernet (en7)`.
    pub fn display_name(&self) -> String {
        match &self.ssid {
            Some(s) => s.clone(),
            None if self.is_wifi => format!("Wi-Fi ({})", self.interface),
            None => format!("Ethernet ({})", self.interface),
        }
    }

    /// Security reported as open (no encryption), when known.
    pub fn is_open(&self) -> Option<bool> {
        self.security.as_deref().map(security_is_open)
    }
}

/// `None` / `Open` / `OPEN` mean no encryption.
pub fn security_is_open(s: &str) -> bool {
    let l = s.trim().to_ascii_lowercase();
    l == "none" || l == "open" || l.starts_with("open") || l == "no security"
}

/// Normalise `0:11:2:aa:b:c` -> `00:11:02:aa:0b:0c`. `None` for anything that is not 6 hex bytes.
pub fn normalize_mac(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut out = Vec::with_capacity(6);
    for p in parts {
        if p.is_empty() || p.len() > 2 || !p.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        out.push(format!("{:0>2}", p.to_ascii_lowercase()));
    }
    Some(out.join(":"))
}

/// Multicast / broadcast / all-zero MACs are never a router identity.
pub fn is_unicast_mac(mac: &str) -> bool {
    let first = u8::from_str_radix(&mac[..2.min(mac.len())], 16).unwrap_or(1);
    mac != "ff:ff:ff:ff:ff:ff" && mac != "00:00:00:00:00:00" && first & 1 == 0
}

/// `route -n get default` -> (gateway, interface).
pub fn parse_route_get(out: &str) -> Option<(Option<Ipv4Addr>, String)> {
    let mut gw = None;
    let mut iface = None;
    for line in out.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        match k.trim() {
            "gateway" => gw = v.trim().parse::<Ipv4Addr>().ok(),
            "interface" => iface = Some(v.trim().to_string()).filter(|s| !s.is_empty()),
            _ => {}
        }
    }
    Some((gw, iface?))
}

/// `netstat -rn -f inet`: first `default` route through a physical interface (not utun/ipsec/ppp/lo).
pub fn parse_netstat_default(out: &str) -> Option<(Ipv4Addr, String)> {
    for line in out.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 4 || cols[0] != "default" {
            continue;
        }
        let Ok(gw) = cols[1].parse::<Ipv4Addr>() else {
            continue;
        };
        // Columns: Destination Gateway Flags Netif [Expire]
        let iface = cols[3];
        if is_tunnel_interface(iface) || iface.starts_with("lo") {
            continue;
        }
        return Some((gw, iface.to_string()));
    }
    None
}

/// VPN-ish interfaces.
pub fn is_tunnel_interface(i: &str) -> bool {
    i.starts_with("utun") || i.starts_with("ipsec") || i.starts_with("ppp") || i.starts_with("tun")
}

/// `arp -an`: `? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]`.
pub fn parse_arp(out: &str) -> Vec<ArpEntry> {
    let mut v = Vec::new();
    for line in out.lines() {
        let Some(open) = line.find('(') else { continue };
        let Some(close) = line[open..].find(')').map(|c| c + open) else {
            continue;
        };
        let Ok(ip) = line[open + 1..close].parse::<Ipv4Addr>() else {
            continue;
        };
        let rest = &line[close + 1..];
        let words: Vec<&str> = rest.split_whitespace().collect();
        let mac = words
            .iter()
            .position(|w| *w == "at")
            .and_then(|i| words.get(i + 1))
            .and_then(|m| normalize_mac(m));
        let iface = words
            .iter()
            .position(|w| *w == "on")
            .and_then(|i| words.get(i + 1))
            .map(|s| s.to_string());
        let (Some(mac), Some(interface)) = (mac, iface) else {
            continue; // incomplete
        };
        if !is_unicast_mac(&mac) {
            continue;
        }
        v.push(ArpEntry { ip, mac, interface });
    }
    v
}

/// Top-level `Key : value` pairs of `ipconfig getsummary <if>` (nested dictionaries ignored).
pub fn parse_ipconfig_summary(out: &str) -> (bool, Option<String>, Option<String>, Option<String>) {
    let mut depth = 0i32;
    let (mut wifi, mut ssid, mut bssid, mut security) = (false, None, None, None);
    for line in out.lines() {
        let t = line.trim();
        if depth == 1 {
            if let Some((k, v)) = t.split_once(" : ") {
                let v = v.trim();
                let usable = !v.is_empty() && !v.contains("redacted") && !v.starts_with('<');
                match k.trim() {
                    "InterfaceType" => wifi = v.eq_ignore_ascii_case("wifi"),
                    "SSID" if usable => ssid = Some(clip(v, 64)),
                    "BSSID" if usable => bssid = normalize_mac(v),
                    "Security" if usable => security = Some(clip(v, 64)),
                    _ => {}
                }
            }
        }
        depth += t.matches('{').count() as i32;
        depth -= t.matches('}').count() as i32;
    }
    (wifi, ssid, bssid, security)
}

fn clip(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

/// Default nameservers of `scutil --dns` (first section, resolvers without a `domain`).
pub fn parse_scutil_dns(out: &str) -> Vec<IpAddr> {
    let mut servers = Vec::new();
    let mut cur: Vec<IpAddr> = Vec::new();
    let mut has_domain = false;
    let mut in_resolver = false;
    let flush = |cur: &mut Vec<IpAddr>, has_domain: bool, servers: &mut Vec<IpAddr>| {
        if !has_domain {
            for s in cur.drain(..) {
                if !servers.contains(&s) {
                    servers.push(s);
                }
            }
        }
        cur.clear();
    };
    for line in out.lines() {
        let t = line.trim();
        if t.starts_with("DNS configuration (for scoped queries)") {
            break;
        }
        if t.starts_with("resolver #") {
            if in_resolver {
                flush(&mut cur, has_domain, &mut servers);
            }
            in_resolver = true;
            has_domain = false;
            continue;
        }
        if let Some((k, v)) = t.split_once(':') {
            let k = k.trim();
            if k == "domain" {
                has_domain = true;
            } else if k.starts_with("nameserver[") {
                // IPv6 values contain ':' — take everything after the first " : ".
                let v = t.split_once(" : ").map(|(_, v)| v).unwrap_or(v).trim();
                let v = v.split('%').next().unwrap_or(v);
                if let Ok(ip) = v.parse::<IpAddr>() {
                    cur.push(ip);
                }
            }
        }
    }
    if in_resolver {
        flush(&mut cur, has_domain, &mut servers);
    }
    servers
}

/// `ifconfig -l`.
pub fn parse_ifconfig_list(out: &str) -> Vec<String> {
    out.split_whitespace().map(str::to_string).collect()
}

/// Global IPv6 addresses of `ifconfig <if>` (no link-local, no temporary filtering).
pub fn parse_ifconfig_inet6(out: &str) -> Vec<std::net::Ipv6Addr> {
    out.lines()
        .filter_map(|l| {
            let mut w = l.split_whitespace();
            (w.next()? == "inet6").then(|| w.next())?
        })
        .filter_map(|a| a.split('%').next()?.parse::<std::net::Ipv6Addr>().ok())
        .filter(|a| !a.is_loopback() && (a.segments()[0] & 0xffc0) != 0xfe80)
        .collect()
}

/// Current tunnel interfaces (`utunN`).
pub async fn utun_interfaces(sys: &dyn System) -> Vec<String> {
    if !sys.is_macos() {
        return vec![];
    }
    match sys.run(IFCONFIG, &["-l"], CMD_TIMEOUT).await {
        Ok(o) => parse_ifconfig_list(&o.stdout)
            .into_iter()
            .filter(|i| i.starts_with("utun"))
            .collect(),
        Err(_) => vec![],
    }
}

/// System DNS servers.
pub async fn dns_servers(sys: &dyn System) -> Vec<IpAddr> {
    if !sys.is_macos() {
        return vec![];
    }
    match sys.run(SCUTIL, &["--dns"], CMD_TIMEOUT).await {
        Ok(o) => parse_scutil_dns(&o.stdout),
        Err(_) => vec![],
    }
}

/// Global IPv6 addresses of an interface.
pub async fn interface_ipv6(sys: &dyn System, iface: &str) -> Vec<std::net::Ipv6Addr> {
    if !sys.is_macos() || !iface.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return vec![];
    }
    match sys.run(IFCONFIG, &[iface], CMD_TIMEOUT).await {
        Ok(o) => parse_ifconfig_inet6(&o.stdout),
        Err(_) => vec![],
    }
}

/// Probe the current network. `None` without a default route through a physical interface (offline) or off
/// macOS.
pub async fn probe(sys: &dyn System) -> Option<NetworkSnapshot> {
    if !sys.is_macos() {
        return None;
    }
    let route = sys
        .run(ROUTE, &["-n", "get", "default"], CMD_TIMEOUT)
        .await
        .ok()?;
    let (mut gw, mut iface) = parse_route_get(&route.stdout).unwrap_or((None, String::new()));
    let default_via_tunnel = is_tunnel_interface(&iface);
    if iface.is_empty() || default_via_tunnel || gw.is_none() {
        // A VPN owns the default route: find the physical one.
        let ns = sys
            .run(NETSTAT, &["-rn", "-f", "inet"], CMD_TIMEOUT)
            .await
            .ok()?;
        let (g, i) = parse_netstat_default(&ns.stdout)?;
        gw = Some(g);
        iface = i;
    }
    let gw = gw?;
    if !iface.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let mut arp = arp_table(sys, &iface).await;
    if !arp.iter().any(|e| e.ip == gw) {
        // Populate the ARP cache with one ping to the router.
        let g = gw.to_string();
        let _ = sys
            .run(
                PING,
                &["-c", "1", "-t", "1", "-n", &g],
                Duration::from_secs(3),
            )
            .await;
        arp = arp_table(sys, &iface).await;
    }
    let gateway_mac = arp.iter().find(|e| e.ip == gw).map(|e| e.mac.clone());
    let (is_wifi, ssid, bssid, security) = match sys
        .run(IPCONFIG, &["getsummary", &iface], CMD_TIMEOUT)
        .await
    {
        Ok(o) => parse_ipconfig_summary(&o.stdout),
        Err(_) => (false, None, None, None),
    };
    Some(NetworkSnapshot {
        interface: iface,
        gateway_ip: Some(gw),
        gateway_mac,
        ssid,
        bssid,
        security,
        is_wifi,
        arp,
        default_via_tunnel,
    })
}

async fn arp_table(sys: &dyn System, iface: &str) -> Vec<ArpEntry> {
    match sys.run(ARP, &["-an"], CMD_TIMEOUT).await {
        Ok(o) => parse_arp(&o.stdout)
            .into_iter()
            .filter(|e| e.interface == iface)
            .collect(),
        Err(_) => vec![],
    }
}

#[cfg(test)]
pub(crate) mod fixtures {
    pub const ROUTE_GET: &str = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.254\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n       0         0         0         0         0         0      1500         0\n";
    pub const ROUTE_GET_UTUN: &str = "   route to: default\ndestination: default\n       mask: default\n  interface: utun6\n      flags: <UP,DONE,STATIC,PRCLONING>\n";
    pub const NETSTAT_OUT: &str = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\ndefault            link#22            UCSg                utun6\ndefault            192.168.1.254      UGScIg                en0\n127                127.0.0.1          UCS                   lo0\n";
    pub const ARP_OUT: &str = "? (192.168.1.12) at 3c:22:fb:1:2:3 on en0 ifscope [ethernet]\n? (192.168.1.254) at 0:24:d4:a1:b2:c3 on en0 ifscope [ethernet]\n? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]\n? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n? (10.0.0.1) at 0:11:22:33:44:55 on en7 ifscope [ethernet]\n";
    pub const IPCONFIG_WIFI: &str = "<dictionary> {\n  Hashed-BSSID : 6c:44:1a:22:33:44\n  IPv4 : <array> {\n    0 : <dictionary> {\n      Addresses : <array> {\n        0 : 192.168.1.12\n      }\n    }\n  }\n  InterfaceType : WiFi\n  LinkStatusActive : TRUE\n  NetworkID : 4D4C1F86-1D1A-4E25-9C0C-0D0F3A5B6C7D\n  SSID : Livebox-1234\n  Security : WPA2_PSK\n}\n";
    pub const IPCONFIG_REDACTED: &str =
        "<dictionary> {\n  InterfaceType : WiFi\n  SSID : <redacted>\n  BSSID : <redacted>\n}\n";
    pub const SCUTIL_DNS: &str = "DNS configuration\n\nresolver #1\n  search domain[0] : home\n  nameserver[0] : 127.0.0.1\n  nameserver[1] : fe80::1%en0\n  if_index : 6 (en0)\n  flags    : Request A records\n  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)\n\nresolver #2\n  domain   : local\n  options  : mdns\n  timeout  : 5\n  flags    : Request A records\n  reach    : 0x00000000 (Not Reachable)\n  order    : 300000\n\nresolver #3\n  nameserver[0] : 198.18.0.2\n\nDNS configuration (for scoped queries)\n\nresolver #1\n  nameserver[0] : 192.168.1.254\n  if_index : 6 (en0)\n";
    pub const IFCONFIG_EN0: &str = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether 3c:22:fb:01:02:03\n\tinet6 fe80::1c2b:3a4d:5e6f:7081%en0 prefixlen 64 secured scopeid 0x6\n\tinet 192.168.1.12 netmask 0xffffff00 broadcast 192.168.1.255\n\tinet6 2a01:cb00:1234:5600:1c2b:3a4d:5e6f:7081 prefixlen 64 autoconf secured\n\tinet6 2a01:cb00:1234:5600:aaaa:bbbb:cccc:dddd prefixlen 64 autoconf temporary\n\tstatus: active\n";
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::testutil::FakeSystem;

    #[test]
    fn parsers() {
        assert_eq!(
            parse_route_get(ROUTE_GET),
            Some((Some("192.168.1.254".parse().unwrap()), "en0".into()))
        );
        assert_eq!(
            parse_route_get(ROUTE_GET_UTUN),
            Some((None, "utun6".into()))
        );
        assert_eq!(
            parse_netstat_default(NETSTAT_OUT),
            Some(("192.168.1.254".parse().unwrap(), "en0".into()))
        );
        let arp = parse_arp(ARP_OUT);
        assert_eq!(arp.len(), 3);
        assert_eq!(arp[0].mac, "3c:22:fb:01:02:03");
        assert_eq!(arp[1].mac, "00:24:d4:a1:b2:c3");
        assert_eq!(arp[2].interface, "en7");
        let (wifi, ssid, bssid, sec) = parse_ipconfig_summary(IPCONFIG_WIFI);
        assert!(wifi);
        assert_eq!(ssid.as_deref(), Some("Livebox-1234"));
        assert_eq!(bssid, None);
        assert_eq!(sec.as_deref(), Some("WPA2_PSK"));
        let (wifi, ssid, bssid, _) = parse_ipconfig_summary(IPCONFIG_REDACTED);
        assert!(wifi && ssid.is_none() && bssid.is_none());
        let dns = parse_scutil_dns(SCUTIL_DNS);
        assert_eq!(
            dns,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "fe80::1".parse().unwrap(),
                "198.18.0.2".parse().unwrap()
            ]
        );
        assert_eq!(parse_ifconfig_list("lo0 gif0 en0 utun0 utun1\n").len(), 5);
        let v6 = parse_ifconfig_inet6(IFCONFIG_EN0);
        assert_eq!(v6.len(), 2);
        assert_eq!(
            normalize_mac("A:b:C:d:E:f").as_deref(),
            Some("0a:0b:0c:0d:0e:0f")
        );
        assert_eq!(normalize_mac("a:b:c"), None);
        assert!(!is_unicast_mac("01:00:5e:00:00:fb"));
        assert!(security_is_open("None") && !security_is_open("WPA2_PSK"));
    }

    #[tokio::test]
    async fn probe_combines_tools() {
        let sys = FakeSystem::macos();
        sys.respond(ROUTE, &["-n", "get", "default"], 0, ROUTE_GET_UTUN, "");
        sys.respond(NETSTAT, &["-rn"], 0, NETSTAT_OUT, "");
        sys.respond(ARP, &["-an"], 0, ARP_OUT, "");
        sys.respond(IPCONFIG, &["getsummary", "en0"], 0, IPCONFIG_WIFI, "");
        let s = probe(sys.as_ref()).await.unwrap();
        assert_eq!(s.interface, "en0");
        assert_eq!(s.gateway_mac.as_deref(), Some("00:24:d4:a1:b2:c3"));
        assert_eq!(s.network_id().as_deref(), Some("gw:00:24:d4:a1:b2:c3"));
        assert_eq!(s.display_name(), "Livebox-1234");
        assert_eq!(s.arp.len(), 2);
        assert_eq!(s.is_open(), Some(false));
        assert!(s.default_via_tunnel);
        // No ping needed: the router was in the cache.
        assert_eq!(sys.count(PING, &[]), 0);
        assert!(probe(FakeSystem::linux().as_ref()).await.is_none());
    }

    #[tokio::test]
    async fn probe_pings_router_when_missing() {
        let sys = FakeSystem::macos();
        sys.respond(ROUTE, &["-n", "get", "default"], 0, ROUTE_GET, "");
        sys.respond(ARP, &["-an"], 0, "", "");
        sys.respond(PING, &["-c"], 0, "", "");
        sys.respond(IPCONFIG, &["getsummary"], 1, "", "");
        let s = probe(sys.as_ref()).await.unwrap();
        assert_eq!(sys.count(PING, &["-c", "1"]), 1);
        assert_eq!(s.gateway_mac, None);
        assert_eq!(s.network_id(), None);
        assert_eq!(s.display_name(), "Ethernet (en0)");
    }
}
