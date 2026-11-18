//! Pure parsers of the macOS tools used by the LAN inventory: `ifconfig <if>`, `ndp -an`,
//! `dns-sd -Z <type> local.` (zone-file output of a Bonjour browse + resolve), and the sweep plan of a
//! subnet. ARP (`arp -an`) is parsed by `pb_vpn::netprobe::parse_arp`.

use pb_vpn::netprobe::{is_unicast_mac, normalize_mac};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Hard cap on the addresses swept in one scan (a /24).
pub const MAX_SWEEP_HOSTS: usize = 254;

/// What `ifconfig <if>` says about our own interface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IfaceInfo {
    pub mac: Option<String>,
    pub ipv4: Option<Ipv4Addr>,
    /// Prefix length of `ipv4` (from the hex netmask).
    pub prefix: Option<u8>,
}

/// `ifconfig en0`: `ether 3c:22:fb:01:02:03`, `inet 192.168.1.12 netmask 0xffffff00 broadcast …`
/// (first IPv4 address wins).
pub fn parse_ifconfig(out: &str) -> IfaceInfo {
    let mut info = IfaceInfo::default();
    for line in out.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        match w.first().copied() {
            Some("ether") if info.mac.is_none() => {
                info.mac = w.get(1).and_then(|m| normalize_mac(m));
            }
            Some("inet") if info.ipv4.is_none() => {
                info.ipv4 = w.get(1).and_then(|a| a.parse().ok());
                info.prefix = w
                    .iter()
                    .position(|x| *x == "netmask")
                    .and_then(|i| w.get(i + 1))
                    .and_then(|m| parse_netmask(m));
            }
            _ => {}
        }
    }
    info
}

/// `0xffffff00` or `255.255.255.0` -> 24 (contiguous masks only).
pub fn parse_netmask(s: &str) -> Option<u8> {
    let v = if let Some(hex) = s.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()?
    } else {
        u32::from(s.parse::<Ipv4Addr>().ok()?)
    };
    let ones = v.leading_ones();
    (v.checked_shl(ones).unwrap_or(0) == 0).then_some(ones as u8)
}

/// `192.168.1.0/24`.
pub fn subnet_string(ip: Ipv4Addr, prefix: u8) -> String {
    let p = prefix.min(32);
    let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    format!("{}/{p}", Ipv4Addr::from(u32::from(ip) & mask))
}

/// Addresses to sweep: every host of the subnet when it is a /24 or smaller, otherwise only the /24
/// around our address (large corporate / campus subnets are never swept whole). Network, broadcast and
/// our own address are skipped. Nothing for /31 and /32.
pub fn sweep_targets(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let p = prefix.clamp(24, 32);
    if p >= 31 {
        return vec![];
    }
    let mask = u32::MAX << (32 - p);
    let net = u32::from(ip) & mask;
    let bcast = net | !mask;
    ((net + 1)..bcast)
        .map(Ipv4Addr::from)
        .filter(|a| *a != ip)
        .take(MAX_SWEEP_HOSTS)
        .collect()
}

/// One `ndp -an` neighbour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpEntry {
    pub ip: Ipv6Addr,
    pub mac: String,
    pub interface: String,
}

/// `ndp -an`:
/// `Neighbor  Linklayer Address  Netif Expire St Flgs Prbs` then
/// `fe80::1%en0  0:24:d4:a1:b2:c3  en0 23h59m58s S R`. Incomplete / multicast entries are skipped.
pub fn parse_ndp(out: &str) -> Vec<NdpEntry> {
    let mut v = Vec::new();
    for line in out.lines() {
        let w: Vec<&str> = line.split_whitespace().collect();
        if w.len() < 3 {
            continue;
        }
        let addr = w[0].split('%').next().unwrap_or("");
        let Ok(ip) = addr.parse::<Ipv6Addr>() else {
            continue;
        };
        if ip.is_multicast() {
            continue;
        }
        let Some(mac) = normalize_mac(w[1]) else {
            continue;
        };
        if !is_unicast_mac(&mac) {
            continue;
        }
        v.push(NdpEntry {
            ip,
            mac,
            interface: w[2].to_string(),
        });
    }
    v
}

/// One Bonjour service instance from `dns-sd -Z`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsService {
    /// Unescaped instance name (`Salon de Camille`).
    pub instance: String,
    /// `_airplay._tcp`.
    pub service_type: String,
    /// Target host without the trailing dot (`Apple-TV.local`).
    pub host: Option<String>,
    pub port: Option<u16>,
    pub txt: BTreeMap<String, String>,
}

/// Undo the DNS presentation escapes of `dns-sd`: `\032` (decimal byte) and `\.` / `\\`.
pub fn unescape_dns(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 1 < b.len() {
            if i + 4 <= b.len() && b[i + 1..i + 4].iter().all(u8::is_ascii_digit) {
                let d = |k: usize| u32::from(b[i + k] - b'0');
                let n = d(1) * 100 + d(2) * 10 + d(3);
                if n <= 255 {
                    out.push(n as u8);
                    i += 4;
                    continue;
                }
            }
            out.push(b[i + 1]);
            i += 2;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Split `<instance>.<_type>.<_proto>` (escaped) into (instance, `_type._proto`).
fn split_service_name(n: &str) -> Option<(String, String)> {
    // The last two labels are the service type; the instance may contain escaped dots.
    let mut dots = Vec::new();
    let b = n.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'.' => {
                dots.push(i);
                i += 1;
            }
            _ => i += 1,
        }
    }
    if dots.len() < 2 {
        return None;
    }
    let cut = dots[dots.len() - 2];
    let ty = &n[cut + 1..];
    if !ty.starts_with('_') {
        return None;
    }
    Some((unescape_dns(&n[..cut]), ty.to_string()))
}

/// `"k=v" "flag"` -> map (values unescaped, keys lowercased; at most 64 entries of 256 chars).
fn parse_txt(rest: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match (in_q, c) {
            (false, '"') => {
                in_q = true;
                cur.clear();
            }
            (true, '\\') => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            (true, '"') => {
                in_q = false;
                if m.len() < 64 {
                    let item: String = cur.chars().filter(|c| !c.is_control()).take(256).collect();
                    match item.split_once('=') {
                        Some((k, v)) if !k.is_empty() => {
                            m.insert(k.to_ascii_lowercase(), v.to_string());
                        }
                        None if !item.is_empty() => {
                            m.insert(item.to_ascii_lowercase(), String::new());
                        }
                        _ => {}
                    }
                }
            }
            (true, c) => cur.push(c),
            (false, _) => {}
        }
    }
    m
}

/// `dns-sd -Z _airplay._tcp local.`:
/// ```text
/// _airplay._tcp                                   PTR     Salon._airplay._tcp
/// Salon._airplay._tcp                             SRV     0 0 7000 Apple-TV.local. ; Replace with unicast FQDN of target host
/// Salon._airplay._tcp                             TXT     "deviceid=AA:BB:…" "model=AppleTV11,1"
/// ```
/// Comments, the `lb._dns-sd._udp` line and anything unexpected are ignored.
pub fn parse_dnssd_zone(out: &str) -> Vec<MdnsService> {
    let mut by_name: BTreeMap<String, MdnsService> = BTreeMap::new();
    for line in out.lines() {
        let t = line.trim_end();
        if t.is_empty() || t.starts_with(';') {
            continue;
        }
        // Owner name: up to the first unescaped whitespace.
        let b = t.as_bytes();
        let mut i = 0;
        while i < b.len() && !b[i].is_ascii_whitespace() {
            i += if b[i] == b'\\' { 2 } else { 1 };
        }
        let owner = &t[..i.min(t.len())];
        let rest = t[i.min(t.len())..].trim_start();
        let (rtype, data) = match rest.split_once(char::is_whitespace) {
            Some((r, d)) => (r, d.trim()),
            None => continue,
        };
        if !matches!(rtype, "SRV" | "TXT" | "PTR") {
            continue;
        }
        let key = match rtype {
            "PTR" => data.to_string(),
            _ => owner.to_string(),
        };
        let Some((instance, service_type)) = split_service_name(&key) else {
            continue;
        };
        if by_name.len() >= 256 && !by_name.contains_key(&key) {
            continue;
        }
        let e = by_name.entry(key).or_insert_with(|| MdnsService {
            instance,
            service_type,
            ..Default::default()
        });
        match rtype {
            "SRV" => {
                let w: Vec<&str> = data.split_whitespace().collect();
                if w.len() >= 4 {
                    e.port = w[2].parse().ok();
                    let host = unescape_dns(w[3].trim_end_matches('.'));
                    if !host.is_empty() && host.len() <= 253 {
                        e.host = Some(host);
                    }
                }
            }
            "TXT" => e.txt = parse_txt(data),
            _ => {}
        }
    }
    by_name.into_values().collect()
}

#[cfg(test)]
pub(crate) mod fixtures {
    pub const IFCONFIG_EN0: &str = "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>\n\tether 3c:22:fb:01:02:03\n\tinet6 fe80::1c2b:3a4d:5e6f:7081%en0 prefixlen 64 secured scopeid 0xb\n\tinet 192.168.1.12 netmask 0xffffff00 broadcast 192.168.1.255\n\tinet6 2a01:cb00:1234:5600:1c2b:3a4d:5e6f:7081 prefixlen 64 autoconf secured\n\tnd6 options=201<PERFORMNUD,DAD>\n\tmedia: autoselect\n\tstatus: active\n";
    pub const ARP_AN: &str = "? (192.168.1.1) at 0:24:d4:a1:b2:c3 on en0 ifscope [ethernet]\n? (192.168.1.12) at 3c:22:fb:1:2:3 on en0 ifscope permanent [ethernet]\n? (192.168.1.20) at f0:18:98:aa:bb:cc on en0 ifscope [ethernet]\n? (192.168.1.30) at 90:dd:5d:11:22:33 on en0 ifscope [ethernet]\n? (192.168.1.41) at 3a:5f:12:9c:7e:01 on en0 ifscope [ethernet]\n? (192.168.1.50) at (incomplete) on en0 ifscope [ethernet]\n? (192.168.1.77) at 30:5a:3a:44:55:66 on en0 ifscope [ethernet]\n? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n? (169.254.12.7) at 5e:e9:1:2:3:4 on bridge100 ifscope [bridge]\n";
    pub const NDP_AN: &str = "Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\nfe80::1%en0                             0:24:d4:a1:b2:c3     en0 23h59m58s S  R\nfe80::1c2b:3a4d:5e6f:7081%en0           3c:22:fb:1:2:3       en0 permanent R\nfe80::4a1:9bff:fe3c:2211%en0            f0:18:98:aa:bb:cc    en0 3s        R\n2a01:cb00:1234:5600::1                  0:24:d4:a1:b2:c3     en0 23h59m59s S  R\nfe80::8c:7aff:fe00:abcd%en0             (incomplete)         en0 expired   N\nff02::fb%en0                            33:33:0:0:0:fb       en0 permanent R\n";
    pub const DNSSD_AIRPLAY: &str = "Browsing for _airplay._tcp.local.\nDATE: ---Thu 13 Nov 2026---\n14:02:11.123  ...STARTING...\n\n; To direct clients to browse a different domain, substitute that domain in place of '@'\nlb._dns-sd._udp                                 PTR     @\n\n; In the list of services below, the SRV records will typically reference dot-local Multicast DNS names.\n; When transferring this zone file data to your unicast DNS server, you'll need to replace those dot-local\n; names with the correct fully-qualified (unicast) domain name of the target host offering the service.\n\n_airplay._tcp                                   PTR     Salon._airplay._tcp\nSalon._airplay._tcp                             SRV     0 0 7000 Apple-TV.local. ; Replace with unicast FQDN of target host\nSalon._airplay._tcp                             TXT     \"acl=0\" \"deviceid=90:DD:5D:11:22:33\" \"features=0x4A7FDFD5,0xBC157FDE\" \"model=AppleTV11,1\" \"srcvers=775.3.1\"\n\n_airplay._tcp                                   PTR     MacBook\\032Pro\\032de\\032Camille._airplay._tcp\nMacBook\\032Pro\\032de\\032Camille._airplay._tcp   SRV     0 0 7000 MacBook-Pro-de-Camille.local. ; Replace with unicast FQDN of target host\nMacBook\\032Pro\\032de\\032Camille._airplay._tcp   TXT     \"model=Mac14,2\" \"pw=false\"\n";
    pub const DNSSD_IPP: &str = "\n_ipp._tcp                                       PTR     HP\\032LaserJet\\032Pro\\032M404\\032\\[7E1A2B\\]._ipp._tcp\nHP\\032LaserJet\\032Pro\\032M404\\032\\[7E1A2B\\]._ipp._tcp SRV     0 0 631 HP7E1A2B.local. ; Replace with unicast FQDN of target host\nHP\\032LaserJet\\032Pro\\032M404\\032\\[7E1A2B\\]._ipp._tcp TXT     \"txtvers=1\" \"ty=HP LaserJet Pro M404dn\" \"product=(HP LaserJet Pro M404dn)\" \"note=Bureau \\\"principal\\\"\"\n";
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;

    #[test]
    fn ifconfig_and_masks() {
        let i = parse_ifconfig(IFCONFIG_EN0);
        assert_eq!(i.mac.as_deref(), Some("3c:22:fb:01:02:03"));
        assert_eq!(i.ipv4, Some(Ipv4Addr::new(192, 168, 1, 12)));
        assert_eq!(i.prefix, Some(24));
        assert_eq!(parse_netmask("0xfffffe00"), Some(23));
        assert_eq!(parse_netmask("255.255.255.252"), Some(30));
        assert_eq!(parse_netmask("0xff00ff00"), None);
        assert_eq!(
            parse_ifconfig("lo0: flags=8049<UP>\n"),
            IfaceInfo::default()
        );
        assert_eq!(subnet_string(Ipv4Addr::new(10, 1, 2, 3), 16), "10.1.0.0/16");
    }

    #[test]
    fn sweep_plan() {
        let me = Ipv4Addr::new(192, 168, 1, 12);
        let t = sweep_targets(me, 24);
        assert_eq!(t.len(), 253);
        assert_eq!(t[0], Ipv4Addr::new(192, 168, 1, 1));
        assert!(!t.contains(&me) && !t.contains(&Ipv4Addr::new(192, 168, 1, 255)));
        // A /16 is never swept whole: only our /24.
        let t = sweep_targets(Ipv4Addr::new(10, 20, 30, 40), 16);
        assert_eq!(t.len(), 253);
        assert!(t.iter().all(|a| a.octets()[..3] == [10, 20, 30]));
        assert_eq!(sweep_targets(Ipv4Addr::new(10, 0, 0, 5), 29).len(), 5);
        assert!(sweep_targets(me, 32).is_empty());
    }

    #[test]
    fn ndp() {
        let v = parse_ndp(NDP_AN);
        assert_eq!(v.len(), 4);
        assert_eq!(v[0].ip, "fe80::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(v[0].mac, "00:24:d4:a1:b2:c3");
        assert_eq!(v[2].mac, "f0:18:98:aa:bb:cc");
        assert_eq!(v[3].interface, "en0");
    }

    #[test]
    fn dnssd_zone() {
        let v = parse_dnssd_zone(DNSSD_AIRPLAY);
        assert_eq!(v.len(), 2);
        let mac = v
            .iter()
            .find(|s| s.instance == "MacBook Pro de Camille")
            .unwrap();
        assert_eq!(mac.host.as_deref(), Some("MacBook-Pro-de-Camille.local"));
        assert_eq!(mac.txt.get("model").map(String::as_str), Some("Mac14,2"));
        let tv = v.iter().find(|s| s.instance == "Salon").unwrap();
        assert_eq!(tv.service_type, "_airplay._tcp");
        assert_eq!(tv.port, Some(7000));
        assert_eq!(tv.txt.get("model").map(String::as_str), Some("AppleTV11,1"));
        let p = parse_dnssd_zone(DNSSD_IPP);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].instance, "HP LaserJet Pro M404 [7E1A2B]");
        assert_eq!(p[0].host.as_deref(), Some("HP7E1A2B.local"));
        assert_eq!(
            p[0].txt.get("ty").map(String::as_str),
            Some("HP LaserJet Pro M404dn")
        );
        assert_eq!(
            p[0].txt.get("note").map(String::as_str),
            Some("Bureau \"principal\"")
        );
        assert!(parse_dnssd_zone("garbage\n_x PTR\n").is_empty());
        assert_eq!(unescape_dns("Caf\\195\\169\\032\\.x"), "Café .x");
    }
}
