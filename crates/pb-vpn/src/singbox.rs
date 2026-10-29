//! sing-box configuration generator (format of sing-box ≥ 1.12: typed DNS servers, WireGuard as an
//! endpoint, route rule actions). One TUN inbound with `auto_route` captures all traffic; the profile's
//! outbound (or WireGuard endpoint) is tagged [`PROXY_TAG`] and is the route's `final`.
//!
//! - The server address is the IP pre-resolved by the service (no DNS needed to reach the server, the kill
//!   switch allows exactly these IPs); TLS keeps the original hostname as `server_name`.
//! - DNS: Parabellum's dnscrypt-proxy (`dns.listen`, bound to `lo0`) when DNS blocking is on — its own
//!   upstream traffic then goes through the tunnel — otherwise DNS-over-HTTPS to 1.1.1.1 through the proxy
//!   (or the WireGuard profile's own DNS, inside the tunnel).
//! - IPv6: the TUN always carries an IPv6 address so IPv6 traffic is captured; without `vpn.tunnel_ipv6` it
//!   is rejected (fast fallback to IPv4) instead of leaking around the tunnel.
//! - LAN (`vpn.allow_lan`): private ranges are excluded from the TUN routes and sent direct.

use crate::profile::{Protocol, Tls, Transport, VpnProfile};
use serde_json::{json, Map, Value};
use std::net::{IpAddr, SocketAddr};

/// Tag of the proxy outbound / endpoint.
pub const PROXY_TAG: &str = "proxy";
/// TUN addresses (198.18.0.0/15 is a benchmark range, never a LAN).
pub const TUN_ADDRESS_V4: &str = "198.18.0.1/30";
pub const TUN_ADDRESS_V6: &str = "fdfe:dcba:9876::1/126";
/// DNS address sing-box answers on inside the TUN (next address after the TUN's own).
pub const TUN_DNS_V4: &str = "198.18.0.2";
pub const TUN_DNS_V6: &str = "fdfe:dcba:9876::2";
/// Private ranges kept outside the tunnel when the LAN is allowed.
pub const LAN_RANGES_V4: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
];
pub const LAN_RANGES_V6: &[&str] = &["fe80::/10", "fc00::/7", "ff00::/8"];
/// Public resolver used through the tunnel when Parabellum's DNS blocking is off.
pub const REMOTE_DOH: &str = "1.1.1.1";

/// Inputs besides the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxOptions {
    /// Pre-resolved server address used by the outbound.
    pub server_ip: IpAddr,
    pub tunnel_ipv6: bool,
    pub allow_lan: bool,
    /// dnscrypt-proxy listen address when Parabellum's DNS blocking is enabled.
    pub local_dns: Option<SocketAddr>,
}

fn tls_json(tls: &Tls, original_host: &str) -> Value {
    let mut m = Map::new();
    m.insert("enabled".into(), json!(true));
    let sni = tls.server_name.clone().or_else(|| {
        original_host
            .parse::<IpAddr>()
            .is_err()
            .then(|| original_host.to_string())
    });
    if let Some(s) = sni {
        m.insert("server_name".into(), json!(s));
    }
    if tls.insecure {
        m.insert("insecure".into(), json!(true));
    }
    if !tls.alpn.is_empty() {
        m.insert("alpn".into(), json!(tls.alpn));
    }
    if let Some(fp) = &tls.fingerprint {
        m.insert("utls".into(), json!({"enabled": true, "fingerprint": fp}));
    }
    if let Some(r) = &tls.reality {
        m.insert(
            "reality".into(),
            json!({"enabled": true, "public_key": r.public_key, "short_id": r.short_id}),
        );
    }
    Value::Object(m)
}

fn transport_json(t: &Transport) -> Value {
    match t {
        Transport::Ws {
            path,
            host,
            max_early_data,
        } => {
            let mut m = Map::new();
            m.insert("type".into(), json!("ws"));
            m.insert("path".into(), json!(path));
            if let Some(h) = host {
                m.insert("headers".into(), json!({ "Host": h }));
            }
            if let Some(ed) = max_early_data {
                m.insert("max_early_data".into(), json!(ed));
                m.insert(
                    "early_data_header_name".into(),
                    json!("Sec-WebSocket-Protocol"),
                );
            }
            Value::Object(m)
        }
        Transport::Grpc { service_name } => json!({"type": "grpc", "service_name": service_name}),
        Transport::HttpUpgrade { path, host } => {
            let mut v = json!({"type": "httpupgrade", "path": path});
            if let Some(h) = host {
                v["host"] = json!(h);
            }
            v
        }
        Transport::Http { path, host } => {
            let mut v = json!({"type": "http", "path": path});
            if !host.is_empty() {
                v["host"] = json!(host);
            }
            v
        }
    }
}

/// The proxy outbound (`None` for WireGuard, which is an endpoint).
pub fn outbound(profile: &VpnProfile, server_ip: IpAddr) -> Option<Value> {
    let host = profile.server.as_str();
    let mut o = match &profile.protocol {
        Protocol::Shadowsocks { method, password } => json!({
            "type": "shadowsocks", "method": method, "password": password,
        }),
        Protocol::Vless {
            uuid,
            flow,
            tls,
            transport,
        } => {
            let mut o = json!({"type": "vless", "uuid": uuid, "packet_encoding": "xudp"});
            if let Some(f) = flow {
                o["flow"] = json!(f);
            }
            if let Some(t) = tls {
                o["tls"] = tls_json(t, host);
            }
            if let Some(t) = transport {
                o["transport"] = transport_json(t);
            }
            o
        }
        Protocol::Vmess {
            uuid,
            security,
            alter_id,
            tls,
            transport,
        } => {
            let mut o = json!({
                "type": "vmess", "uuid": uuid, "security": security, "alter_id": alter_id,
                "packet_encoding": "xudp",
            });
            if let Some(t) = tls {
                o["tls"] = tls_json(t, host);
            }
            if let Some(t) = transport {
                o["transport"] = transport_json(t);
            }
            o
        }
        Protocol::Trojan {
            password,
            tls,
            transport,
        } => {
            let mut o = json!({"type": "trojan", "password": password, "tls": tls_json(tls, host)});
            if let Some(t) = transport {
                o["transport"] = transport_json(t);
            }
            o
        }
        Protocol::Hysteria2 {
            password,
            obfs_password,
            server_ports,
            tls,
            up_mbps,
            down_mbps,
        } => {
            let mut o =
                json!({"type": "hysteria2", "password": password, "tls": tls_json(tls, host)});
            if let Some(pw) = obfs_password {
                o["obfs"] = json!({"type": "salamander", "password": pw});
            }
            if !server_ports.is_empty() {
                o["server_ports"] = json!(server_ports);
            }
            if let Some(u) = up_mbps {
                o["up_mbps"] = json!(u);
            }
            if let Some(d) = down_mbps {
                o["down_mbps"] = json!(d);
            }
            o
        }
        Protocol::Tuic {
            uuid,
            password,
            congestion_control,
            udp_relay_mode,
            tls,
        } => {
            let mut o = json!({"type": "tuic", "uuid": uuid, "password": password, "tls": tls_json(tls, host)});
            if let Some(c) = congestion_control {
                o["congestion_control"] = json!(c);
            }
            if let Some(m) = udp_relay_mode {
                o["udp_relay_mode"] = json!(m);
            }
            o
        }
        Protocol::Wireguard(_) => return None,
    };
    o["tag"] = json!(PROXY_TAG);
    o["server"] = json!(server_ip.to_string());
    o["server_port"] = json!(profile.port);
    Some(o)
}

/// The WireGuard endpoint (`None` for the other protocols).
pub fn wireguard_endpoint(profile: &VpnProfile, server_ip: IpAddr) -> Option<Value> {
    let Protocol::Wireguard(w) = &profile.protocol else {
        return None;
    };
    let mut peer = json!({
        "address": server_ip.to_string(),
        "port": profile.port,
        "public_key": w.peer_public_key,
        "allowed_ips": w.allowed_ips,
    });
    if let Some(psk) = &w.pre_shared_key {
        peer["pre_shared_key"] = json!(psk);
    }
    if let Some(k) = w.keepalive {
        peer["persistent_keepalive_interval"] = json!(k);
    }
    if let Some(r) = &w.reserved {
        peer["reserved"] = json!(r);
    }
    let mut e = json!({
        "type": "wireguard",
        "tag": PROXY_TAG,
        "address": w.addresses,
        "private_key": w.private_key,
        "peers": [peer],
    });
    if let Some(m) = w.mtu {
        e["mtu"] = json!(m);
    }
    Some(e)
}

/// The full configuration.
pub fn build_config(profile: &VpnProfile, opts: &SingBoxOptions) -> Value {
    // DNS
    let (servers, final_dns) = match opts.local_dns {
        Some(addr) => (
            vec![json!({
                "type": "udp", "tag": "dns-local",
                "server": addr.ip().to_string(), "server_port": addr.port(),
                "bind_interface": "lo0",
            })],
            "dns-local",
        ),
        None => {
            let wg_dns = match &profile.protocol {
                Protocol::Wireguard(w) => w.dns.first().cloned(),
                _ => None,
            };
            match wg_dns {
                Some(ip) => (
                    vec![
                        json!({"type": "udp", "tag": "dns-tunnel", "server": ip, "detour": PROXY_TAG}),
                    ],
                    "dns-tunnel",
                ),
                None => (
                    vec![
                        json!({"type": "https", "tag": "dns-remote", "server": REMOTE_DOH, "detour": PROXY_TAG}),
                    ],
                    "dns-remote",
                ),
            }
        }
    };
    let mut dns = json!({"servers": servers, "final": final_dns});
    if !opts.tunnel_ipv6 {
        dns["strategy"] = json!("ipv4_only");
    }

    // Inbound
    let mut tun = json!({
        "type": "tun",
        "tag": "tun-in",
        "address": [TUN_ADDRESS_V4, TUN_ADDRESS_V6],
        "auto_route": true,
        "strict_route": true,
    });
    if opts.allow_lan {
        let excl: Vec<&str> = LAN_RANGES_V4
            .iter()
            .chain(LAN_RANGES_V6.iter())
            .copied()
            .collect();
        tun["route_exclude_address"] = json!(excl);
    }

    // Route
    let mut rules = vec![
        json!({"action": "sniff"}),
        json!({"protocol": "dns", "action": "hijack-dns"}),
    ];
    if !opts.tunnel_ipv6 {
        rules.push(json!({"ip_version": 6, "action": "reject"}));
    }
    if opts.allow_lan {
        rules.push(json!({"ip_is_private": true, "outbound": "direct"}));
    }

    let mut cfg = json!({
        "log": {"level": "warn", "timestamp": true},
        "dns": dns,
        "inbounds": [tun],
        "route": {
            "rules": rules,
            "final": PROXY_TAG,
            "auto_detect_interface": true,
            "default_domain_resolver": final_dns,
        },
    });
    let mut outbounds = Vec::new();
    if let Some(o) = outbound(profile, opts.server_ip) {
        outbounds.push(o);
    }
    outbounds.push(json!({"type": "direct", "tag": "direct"}));
    cfg["outbounds"] = json!(outbounds);
    if let Some(e) = wireguard_endpoint(profile, opts.server_ip) {
        cfg["endpoints"] = json!([e]);
    }
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::parse;

    fn opts(local: bool) -> SingBoxOptions {
        SingBoxOptions {
            server_ip: "203.0.113.9".parse().unwrap(),
            tunnel_ipv6: true,
            allow_lan: true,
            local_dns: local.then(|| "127.0.0.1:53".parse().unwrap()),
        }
    }

    #[test]
    fn vless_reality_config() {
        let pbk = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
        let p = parse(&format!(
            "vless://bf000d23-0752-40b4-affe-68f7707a9661@edge.example.net:443?security=reality&sni=www.apple.com&pbk={pbk}&sid=01ab&flow=xtls-rprx-vision"
        ), 0).unwrap();
        let c = build_config(&p, &opts(true));
        let o = &c["outbounds"][0];
        assert_eq!(o["type"], "vless");
        assert_eq!(o["tag"], PROXY_TAG);
        assert_eq!(o["server"], "203.0.113.9");
        assert_eq!(o["server_port"], 443);
        assert_eq!(o["flow"], "xtls-rprx-vision");
        assert_eq!(o["tls"]["server_name"], "www.apple.com");
        assert_eq!(o["tls"]["utls"]["fingerprint"], "chrome");
        assert_eq!(o["tls"]["reality"]["public_key"], pbk);
        assert_eq!(o["tls"]["reality"]["short_id"], "01ab");
        assert_eq!(c["outbounds"][1]["type"], "direct");
        assert!(c.get("endpoints").is_none());
        // DNS through dnscrypt-proxy on loopback.
        assert_eq!(c["dns"]["final"], "dns-local");
        assert_eq!(c["dns"]["servers"][0]["bind_interface"], "lo0");
        assert_eq!(c["dns"]["servers"][0]["server_port"], 53);
        assert_eq!(c["route"]["final"], PROXY_TAG);
        assert_eq!(c["route"]["auto_detect_interface"], true);
        assert_eq!(c["route"]["default_domain_resolver"], "dns-local");
        let tun = &c["inbounds"][0];
        assert_eq!(tun["type"], "tun");
        assert_eq!(tun["auto_route"], true);
        assert_eq!(tun["strict_route"], true);
        assert!(tun["route_exclude_address"]
            .as_array()
            .unwrap()
            .contains(&json!("192.168.0.0/16")));
        let rules = c["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules.last().unwrap()["outbound"], "direct");
    }

    #[test]
    fn tls_server_name_defaults_to_hostname() {
        let p = parse("trojan://pw@tr.example.com:443#t", 0).unwrap();
        let c = build_config(&p, &opts(false));
        assert_eq!(c["outbounds"][0]["tls"]["server_name"], "tr.example.com");
        assert_eq!(c["outbounds"][0]["server"], "203.0.113.9");
        // Remote DoH through the proxy.
        assert_eq!(c["dns"]["final"], "dns-remote");
        assert_eq!(c["dns"]["servers"][0]["type"], "https");
        assert_eq!(c["dns"]["servers"][0]["detour"], PROXY_TAG);
        // IP literal server without SNI: no server_name.
        let p = parse("trojan://pw@198.51.100.4:443", 0).unwrap();
        let c = build_config(&p, &opts(false));
        assert!(c["outbounds"][0]["tls"].get("server_name").is_none());
    }

    #[test]
    fn wireguard_endpoint_and_dns() {
        let conf = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.64.0.2/32\nDNS = 10.64.0.1\nMTU = 1380\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = wg.example.com:51820\nPersistentKeepalive = 25\n";
        let p = parse(conf, 0).unwrap();
        let c = build_config(&p, &opts(false));
        let outs = c["outbounds"].as_array().unwrap();
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0]["type"], "direct");
        let e = &c["endpoints"][0];
        assert_eq!(e["type"], "wireguard");
        assert_eq!(e["tag"], PROXY_TAG);
        assert_eq!(e["mtu"], 1380);
        assert_eq!(e["peers"][0]["address"], "203.0.113.9");
        assert_eq!(e["peers"][0]["port"], 51820);
        assert_eq!(e["peers"][0]["persistent_keepalive_interval"], 25);
        assert_eq!(c["dns"]["final"], "dns-tunnel");
        assert_eq!(c["dns"]["servers"][0]["server"], "10.64.0.1");
    }

    #[test]
    fn ipv6_and_lan_switches() {
        let p = parse(
            "hy2://pw@hy.example.com:443?obfs=salamander&obfs-password=x&mport=1000-2000",
            0,
        )
        .unwrap();
        let mut o = opts(true);
        o.tunnel_ipv6 = false;
        o.allow_lan = false;
        let c = build_config(&p, &o);
        assert_eq!(c["dns"]["strategy"], "ipv4_only");
        assert!(c["inbounds"][0].get("route_exclude_address").is_none());
        let rules = c["route"]["rules"].as_array().unwrap();
        assert!(rules
            .iter()
            .any(|r| r["ip_version"] == 6 && r["action"] == "reject"));
        assert!(!rules.iter().any(|r| r.get("ip_is_private").is_some()));
        let h = &c["outbounds"][0];
        assert_eq!(h["obfs"]["type"], "salamander");
        assert_eq!(h["server_ports"][0], "1000:2000");
        // The TUN always has an IPv6 address so IPv6 never bypasses the tunnel.
        assert_eq!(c["inbounds"][0]["address"][1], TUN_ADDRESS_V6);
    }

    #[test]
    fn every_protocol_produces_a_proxy() {
        let links = [
            "ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:8388",
            "vmess://eyJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJpZCI6ImJmMDAwZDIzLTA3NTItNDBiNC1hZmZlLTY4Zjc3MDdhOTY2MSIsIm5ldCI6ImdycGMiLCJwYXRoIjoic3ZjIiwidGxzIjoidGxzIn0=",
            "tuic://bf000d23-0752-40b4-affe-68f7707a9661:pw@tu.example.com:443",
        ];
        for l in links {
            let p = parse(l, 0).unwrap();
            let c = build_config(&p, &opts(true));
            assert_eq!(c["outbounds"][0]["tag"], PROXY_TAG, "{l}");
            assert_eq!(c["route"]["final"], PROXY_TAG);
        }
        let vm = parse(links[1], 0).unwrap();
        let c = build_config(&vm, &opts(true));
        assert_eq!(c["outbounds"][0]["transport"]["type"], "grpc");
        assert_eq!(c["outbounds"][0]["transport"]["service_name"], "svc");
    }
}
