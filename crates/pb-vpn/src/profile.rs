//! VPN profiles: share links (`ss://`, `vless://`, `vmess://`, `trojan://`, `hysteria2://` / `hy2://`,
//! `tuic://`, `wireguard://` / `wg://`) and WireGuard `.conf` text, parsed into a [`VpnProfile`] that the
//! [`crate::singbox`] module turns into a sing-box outbound / endpoint.
//!
//! Everything is validated strictly (hosts, ports, UUIDs, keys, methods, transports); anything ambiguous or
//! unsupported is refused with a French message rather than guessed. The stored profile holds secrets: it is
//! only written to `state/vpn/profile.json` (root, 0600) and [`VpnProfile::info`] never exposes them.

use crate::VpnError;
use base64::Engine as _;
use pb_core::config::is_host_or_ip;
use pb_core::model::VpnProfileInfo;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Max size of an imported profile text.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;
/// Max length of the display name.
const MAX_NAME: usize = 64;

/// Shadowsocks methods sing-box supports (`none` refused: no encryption).
const SS_METHODS: &[&str] = &[
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

/// uTLS fingerprints accepted by sing-box.
const FINGERPRINTS: &[&str] = &[
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
];

/// VMess `security` values.
const VMESS_SECURITY: &[&str] = &[
    "auto",
    "none",
    "zero",
    "aes-128-gcm",
    "chacha20-poly1305",
    "aes-128-ctr",
];

/// A parsed profile, secrets included.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnProfile {
    /// Display name.
    pub name: String,
    /// Server host as given (hostname or IP literal, without brackets).
    pub server: String,
    pub port: u16,
    pub imported_at: i64,
    pub protocol: Protocol,
}

impl std::fmt::Debug for VpnProfile {
    // Never print secrets (UUIDs, passwords, keys).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpnProfile")
            .field("name", &self.name)
            .field("protocol", &self.protocol.name())
            .field("server", &self.server)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// TLS options of an outbound.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Tls {
    /// SNI; `None` = the server hostname (set by the config generator when the server is pre-resolved).
    pub server_name: Option<String>,
    pub insecure: bool,
    pub alpn: Vec<String>,
    /// uTLS fingerprint (`chrome`…).
    pub fingerprint: Option<String>,
    pub reality: Option<Reality>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reality {
    pub public_key: String,
    pub short_id: String,
}

/// V2Ray transports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Transport {
    Ws {
        path: String,
        #[serde(default)]
        host: Option<String>,
        /// `?ed=2048` early data (Xray convention) moved out of the path.
        #[serde(default)]
        max_early_data: Option<u32>,
    },
    Grpc {
        service_name: String,
    },
    #[serde(rename = "httpupgrade")]
    HttpUpgrade {
        path: String,
        #[serde(default)]
        host: Option<String>,
    },
    /// HTTP/2 transport (`type=http` / `h2`).
    Http {
        path: String,
        #[serde(default)]
        host: Vec<String>,
    },
}

impl Transport {
    fn kind(&self) -> &'static str {
        match self {
            Transport::Ws { .. } => "ws",
            Transport::Grpc { .. } => "grpc",
            Transport::HttpUpgrade { .. } => "httpupgrade",
            Transport::Http { .. } => "h2",
        }
    }
}

/// WireGuard parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuard {
    pub private_key: String,
    /// Interface addresses with prefix (`10.64.0.2/32`).
    pub addresses: Vec<String>,
    pub peer_public_key: String,
    #[serde(default)]
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub keepalive: Option<u16>,
    #[serde(default)]
    pub mtu: Option<u32>,
    /// Cloudflare WARP style reserved bytes.
    #[serde(default)]
    pub reserved: Option<Vec<u8>>,
    /// DNS servers of the `[Interface]` (IPs only), used inside the tunnel.
    #[serde(default)]
    pub dns: Vec<String>,
}

/// Protocol-specific settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Protocol {
    Shadowsocks {
        method: String,
        password: String,
    },
    Vless {
        uuid: String,
        #[serde(default)]
        flow: Option<String>,
        #[serde(default)]
        tls: Option<Tls>,
        #[serde(default)]
        transport: Option<Transport>,
    },
    Vmess {
        uuid: String,
        security: String,
        alter_id: u32,
        #[serde(default)]
        tls: Option<Tls>,
        #[serde(default)]
        transport: Option<Transport>,
    },
    Trojan {
        password: String,
        tls: Tls,
        #[serde(default)]
        transport: Option<Transport>,
    },
    Hysteria2 {
        password: String,
        #[serde(default)]
        obfs_password: Option<String>,
        /// Port hopping ranges, sing-box syntax `"2000:3000"`.
        #[serde(default)]
        server_ports: Vec<String>,
        tls: Tls,
        #[serde(default)]
        up_mbps: Option<u32>,
        #[serde(default)]
        down_mbps: Option<u32>,
    },
    Tuic {
        uuid: String,
        password: String,
        #[serde(default)]
        congestion_control: Option<String>,
        #[serde(default)]
        udp_relay_mode: Option<String>,
        tls: Tls,
    },
    Wireguard(WireGuard),
}

impl Protocol {
    /// Machine name (`VpnProfileInfo::protocol`).
    pub fn name(&self) -> &'static str {
        match self {
            Protocol::Shadowsocks { .. } => "shadowsocks",
            Protocol::Vless { .. } => "vless",
            Protocol::Vmess { .. } => "vmess",
            Protocol::Trojan { .. } => "trojan",
            Protocol::Hysteria2 { .. } => "hysteria2",
            Protocol::Tuic { .. } => "tuic",
            Protocol::Wireguard(_) => "wireguard",
        }
    }

    /// TLS options, when the protocol uses TLS.
    pub fn tls(&self) -> Option<&Tls> {
        match self {
            Protocol::Vless { tls, .. } | Protocol::Vmess { tls, .. } => tls.as_ref(),
            Protocol::Trojan { tls, .. }
            | Protocol::Hysteria2 { tls, .. }
            | Protocol::Tuic { tls, .. } => Some(tls),
            Protocol::Shadowsocks { .. } | Protocol::Wireguard(_) => None,
        }
    }
}

impl VpnProfile {
    /// Public description (no secrets).
    pub fn info(&self) -> VpnProfileInfo {
        VpnProfileInfo {
            name: self.name.clone(),
            protocol: self.protocol.name().to_string(),
            server: self.server.clone(),
            port: self.port,
            transport: Some(self.transport_summary()),
            imported_at: self.imported_at,
        }
    }

    fn transport_summary(&self) -> String {
        let transport = |t: &Option<Transport>| {
            t.as_ref()
                .map(|t| t.kind().to_string())
                .unwrap_or_else(|| "tcp".into())
        };
        let security = |tls: Option<&Tls>| match tls {
            Some(t) if t.reality.is_some() => Some("reality"),
            Some(_) => Some("tls"),
            None => None,
        };
        match &self.protocol {
            Protocol::Shadowsocks { method, .. } => method.clone(),
            Protocol::Vless {
                tls, transport: t, ..
            }
            | Protocol::Vmess {
                tls, transport: t, ..
            } => match security(tls.as_ref()) {
                Some(s) => format!("{s}+{}", transport(t)),
                None => transport(t),
            },
            Protocol::Trojan {
                tls, transport: t, ..
            } => {
                format!("{}+{}", security(Some(tls)).unwrap_or("tls"), transport(t))
            }
            Protocol::Hysteria2 { obfs_password, .. } => {
                if obfs_password.is_some() {
                    "quic+salamander".into()
                } else {
                    "quic".into()
                }
            }
            Protocol::Tuic { .. } => "quic".into(),
            Protocol::Wireguard(_) => "udp".into(),
        }
    }

    /// The server is an IP literal (no resolution needed).
    pub fn server_ip(&self) -> Option<IpAddr> {
        self.server.parse().ok()
    }
}

// ---------------------------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------------------------

fn invalid(msg: impl Into<String>) -> VpnError {
    VpnError::Invalid(msg.into())
}

/// Parse an imported profile text (one share link, a base64 subscription holding exactly one link, or a
/// WireGuard `.conf`).
pub fn parse(text: &str, now: i64) -> Result<VpnProfile, VpnError> {
    if text.len() > MAX_PROFILE_BYTES {
        return Err(invalid("profil trop long (64 Ko au plus)"));
    }
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.is_empty() {
        return Err(invalid("profil vide"));
    }
    if looks_like_wireguard_conf(text) {
        return parse_wg_conf(text, now);
    }
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    if lines.len() > 1 {
        return Err(invalid(
            "plusieurs lignes : importez un seul serveur (un seul lien) à la fois",
        ));
    }
    let line = lines.first().copied().unwrap_or("");
    if !line.contains("://") {
        // Subscription content: base64 of newline-separated links.
        if let Some(decoded) = b64_decode(line).and_then(|b| String::from_utf8(b).ok()) {
            let links: Vec<&str> = decoded
                .lines()
                .map(str::trim)
                .filter(|l| l.contains("://"))
                .collect();
            return match links.as_slice() {
                [one] => parse_link(one, now),
                [] => Err(invalid("format de profil non reconnu")),
                _ => Err(invalid(format!(
                    "abonnement de {} serveurs : importez un seul lien",
                    links.len()
                ))),
            };
        }
        return Err(invalid(
            "format de profil non reconnu (lien ss://, vless://, vmess://, trojan://, hysteria2://, tuic://, \
             wireguard:// ou fichier WireGuard .conf)",
        ));
    }
    parse_link(line, now)
}

fn parse_link(link: &str, now: i64) -> Result<VpnProfile, VpnError> {
    if link.chars().any(|c| c.is_control() || c == ' ') {
        return Err(invalid("lien invalide (espaces ou caractères de contrôle)"));
    }
    let (scheme, rest) = link
        .split_once("://")
        .ok_or_else(|| invalid("lien invalide"))?;
    match scheme.to_ascii_lowercase().as_str() {
        "ss" => parse_ss(rest, now),
        "vless" => parse_vless(rest, now),
        "vmess" => parse_vmess(rest, now),
        "trojan" => parse_trojan(rest, now),
        "hysteria2" | "hy2" => parse_hy2(rest, now),
        "tuic" => parse_tuic(rest, now),
        "wireguard" | "wg" => parse_wg_link(rest, now),
        "ssr" => Err(invalid(
            "ShadowsocksR (ssr://) n'est pas pris en charge par sing-box",
        )),
        "hysteria" => Err(invalid(
            "Hysteria v1 n'est pas pris en charge : utilisez un lien hysteria2://",
        )),
        other => Err(invalid(format!("protocole « {other} » non pris en charge"))),
    }
}

// ---------------------------------------------------------------------------------------------
// Generic link pieces
// ---------------------------------------------------------------------------------------------

/// `userinfo@host:port/path?query#fragment`, split without interpreting the userinfo (which may hold
/// `/`, `+`, `=` from base64).
#[derive(Debug, Default)]
struct LinkParts {
    userinfo: Option<String>,
    host: String,
    port: u16,
    #[allow(dead_code)]
    path: String,
    query: BTreeMap<String, String>,
    fragment: Option<String>,
}

fn pct_decode(s: &str) -> Result<String, VpnError> {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| invalid("encodage pour cent invalide dans le lien"))
}

/// Query string parser: `+` is NOT turned into a space (base64 passwords), keys lowercased.
fn parse_query(q: &str) -> Result<BTreeMap<String, String>, VpnError> {
    let mut m = BTreeMap::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let k = pct_decode(k)?.to_ascii_lowercase();
        let v = pct_decode(v)?;
        if m.insert(k.clone(), v).is_some() {
            return Err(invalid(format!("paramètre « {k} » répété dans le lien")));
        }
    }
    Ok(m)
}

/// Split `host:port` (IPv6 in brackets).
fn split_host_port(hp: &str) -> Result<(String, u16), VpnError> {
    let (host, port) = if let Some(rest) = hp.strip_prefix('[') {
        let (h, after) = rest
            .split_once(']')
            .ok_or_else(|| invalid("adresse IPv6 mal formée"))?;
        let p = after
            .strip_prefix(':')
            .ok_or_else(|| invalid("port manquant"))?;
        (h.to_string(), p)
    } else {
        let (h, p) = hp
            .rsplit_once(':')
            .ok_or_else(|| invalid("port manquant"))?;
        if h.contains(':') {
            return Err(invalid("adresse IPv6 sans crochets"));
        }
        (h.to_string(), p)
    };
    let host = pct_decode(&host)?;
    Ok((validate_host(&host)?, parse_port(port)?))
}

fn validate_host(h: &str) -> Result<String, VpnError> {
    let h = h.trim().trim_end_matches('.');
    if let Ok(ip) = h.parse::<IpAddr>() {
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(invalid(format!("adresse de serveur invalide : {h}")));
        }
        return Ok(ip.to_string());
    }
    if !is_host_or_ip(h) || !h.contains('.') {
        return Err(invalid(format!("nom de serveur invalide : {h}")));
    }
    Ok(h.to_ascii_lowercase())
}

fn parse_port(p: &str) -> Result<u16, VpnError> {
    match p.trim().parse::<u16>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err(invalid(format!("port invalide : {p}"))),
    }
}

fn split_link(rest: &str) -> Result<LinkParts, VpnError> {
    let (before_frag, fragment) = match rest.split_once('#') {
        Some((a, f)) => (a, Some(pct_decode(f)?)),
        None => (rest, None),
    };
    let (before_query, query) = match before_frag.split_once('?') {
        Some((a, q)) => (a, parse_query(q)?),
        None => (before_frag, BTreeMap::new()),
    };
    // The userinfo ends at the LAST '@' (base64 userinfo may contain '/').
    let (userinfo, hostpath) = match before_query.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, before_query),
    };
    let (hostport, path) = match hostpath.find('/') {
        Some(i) => (&hostpath[..i], hostpath[i..].to_string()),
        None => (hostpath, String::new()),
    };
    let (host, port) = split_host_port(hostport)?;
    Ok(LinkParts {
        userinfo,
        host,
        port,
        path,
        query,
        fragment,
    })
}

fn display_name(fragment: Option<&str>, host: &str, port: u16) -> String {
    let cleaned: String = fragment
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect::<String>()
        .trim()
        .to_string();
    if cleaned.is_empty() {
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    } else {
        cleaned
    }
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.is_empty() {
        return None;
    }
    for engine in [&STANDARD, &URL_SAFE, &STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(b) = engine.decode(&s) {
            return Some(b);
        }
    }
    let trimmed = s.trim_end_matches('=');
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        if let Ok(b) = engine.decode(trimmed) {
            return Some(b);
        }
    }
    None
}

fn is_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(n, p)| p.len() == *n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn require_uuid(s: &str) -> Result<String, VpnError> {
    let s = s.trim();
    if is_uuid(s) {
        Ok(s.to_ascii_lowercase())
    } else {
        Err(invalid("identifiant (UUID) invalide"))
    }
}

fn require_secret(s: &str, what: &str) -> Result<String, VpnError> {
    if s.is_empty() || s.len() > 1024 || s.chars().any(char::is_control) {
        return Err(invalid(format!("{what} manquant ou invalide")));
    }
    Ok(s.to_string())
}

/// 32-byte key in standard base64 (WireGuard) — returned normalised.
fn require_wg_key(s: &str, what: &str) -> Result<String, VpnError> {
    use base64::engine::general_purpose::STANDARD;
    let s = s.trim();
    match b64_decode(s) {
        Some(b) if b.len() == 32 => Ok(STANDARD.encode(b)),
        _ => Err(invalid(format!(
            "{what} WireGuard invalide (32 octets en base64)"
        ))),
    }
}

fn flag(q: &BTreeMap<String, String>, keys: &[&str]) -> bool {
    keys.iter().any(|k| {
        q.get(*k)
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false)
    })
}

fn first<'a>(q: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|k| q.get(*k).map(String::as_str).filter(|v| !v.is_empty()))
}

fn parse_sni(v: Option<&str>) -> Result<Option<String>, VpnError> {
    match v {
        None => Ok(None),
        Some(s) => {
            let s = s.trim().trim_end_matches('.');
            if is_host_or_ip(s) {
                Ok(Some(s.to_ascii_lowercase()))
            } else {
                Err(invalid(format!("SNI invalide : {s}")))
            }
        }
    }
}

fn parse_alpn(v: Option<&str>) -> Result<Vec<String>, VpnError> {
    let Some(v) = v else { return Ok(vec![]) };
    let mut out = Vec::new();
    for a in v.split(',').map(str::trim).filter(|a| !a.is_empty()) {
        if a.len() > 32
            || !a
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        {
            return Err(invalid(format!("ALPN invalide : {a}")));
        }
        out.push(a.to_string());
    }
    Ok(out)
}

fn parse_fingerprint(v: Option<&str>) -> Result<Option<String>, VpnError> {
    match v.map(|s| s.trim().to_ascii_lowercase()) {
        None => Ok(None),
        Some(s) if s.is_empty() || s == "none" => Ok(None),
        Some(s) if FINGERPRINTS.contains(&s.as_str()) => Ok(Some(s)),
        Some(s) => Err(invalid(format!("empreinte TLS (fp) inconnue : {s}"))),
    }
}

fn parse_path(v: Option<&str>) -> Result<String, VpnError> {
    let p = v.unwrap_or("/").trim();
    let p = if p.is_empty() { "/" } else { p };
    if p.len() > 512 || p.chars().any(char::is_control) {
        return Err(invalid("chemin de transport invalide"));
    }
    if !p.starts_with('/') {
        return Ok(format!("/{p}"));
    }
    Ok(p.to_string())
}

fn parse_host_header(v: Option<&str>) -> Result<Option<String>, VpnError> {
    match v.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(h) => {
            // `host` may hold several comma-separated names (h2): keep the first for ws/httpupgrade.
            let h = h.split(',').next().unwrap_or(h).trim();
            if is_host_or_ip(h) {
                Ok(Some(h.to_ascii_lowercase()))
            } else {
                Err(invalid(format!("en-tête Host invalide : {h}")))
            }
        }
    }
}

/// `type=` / `net=` transport selection shared by VLESS, VMess and Trojan.
fn parse_transport(
    kind: Option<&str>,
    path: Option<&str>,
    host: Option<&str>,
    service_name: Option<&str>,
    header_type: Option<&str>,
) -> Result<Option<Transport>, VpnError> {
    let kind = kind.unwrap_or("tcp").trim().to_ascii_lowercase();
    match kind.as_str() {
        "" | "tcp" | "raw" => {
            if let Some(h) = header_type.map(str::to_ascii_lowercase) {
                if h == "http" {
                    return Err(invalid(
                        "camouflage HTTP sur TCP (headerType=http) non pris en charge par sing-box",
                    ));
                }
            }
            Ok(None)
        }
        "ws" | "websocket" => {
            let mut p = parse_path(path)?;
            let mut early = None;
            if let Some((base, q)) = p.clone().split_once('?') {
                let params = parse_query(q)?;
                if let Some(ed) = params.get("ed") {
                    early = Some(
                        ed.parse::<u32>()
                            .map_err(|_| invalid("paramètre ed invalide dans le chemin"))?,
                    );
                    p = base.to_string();
                }
            }
            Ok(Some(Transport::Ws {
                path: p,
                host: parse_host_header(host)?,
                max_early_data: early,
            }))
        }
        "grpc" | "gun" => {
            let s = service_name.or(path).unwrap_or("").trim().trim_matches('/');
            if s.is_empty()
                || s.len() > 256
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
            {
                return Err(invalid("serviceName gRPC manquant ou invalide"));
            }
            Ok(Some(Transport::Grpc {
                service_name: s.to_string(),
            }))
        }
        "httpupgrade" => Ok(Some(Transport::HttpUpgrade {
            path: parse_path(path)?,
            host: parse_host_header(host)?,
        })),
        "http" | "h2" => {
            let hosts = match host {
                Some(h) => h
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|s| {
                        if is_host_or_ip(s) {
                            Ok(s.to_ascii_lowercase())
                        } else {
                            Err(invalid(format!("en-tête Host invalide : {s}")))
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                None => vec![],
            };
            Ok(Some(Transport::Http {
                path: parse_path(path)?,
                host: hosts,
            }))
        }
        "xhttp" | "splithttp" => Err(invalid(
            "transport XHTTP / SplitHTTP non pris en charge par sing-box",
        )),
        "kcp" | "mkcp" | "quic" => Err(invalid(format!(
            "transport « {kind} » non pris en charge par sing-box"
        ))),
        other => Err(invalid(format!("transport « {other} » inconnu"))),
    }
}

fn parse_reality(q: &BTreeMap<String, String>) -> Result<Reality, VpnError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let pbk = first(q, &["pbk", "publickey", "public-key"])
        .ok_or_else(|| invalid("REALITY : clé publique (pbk) manquante"))?
        .trim();
    match b64_decode(pbk) {
        Some(b) if b.len() == 32 => {}
        _ => return Err(invalid("REALITY : clé publique (pbk) invalide")),
    }
    let sid = first(q, &["sid", "shortid", "short-id"])
        .unwrap_or("")
        .trim();
    if sid.len() > 16 || !sid.len().is_multiple_of(2) || !sid.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid("REALITY : identifiant court (sid) invalide"));
    }
    let public_key = URL_SAFE_NO_PAD.encode(b64_decode(pbk).unwrap_or_default());
    Ok(Reality {
        public_key,
        short_id: sid.to_ascii_lowercase(),
    })
}

/// TLS from `security=` + the usual query keys. `default_tls`: Trojan / Hysteria2 / TUIC always use TLS.
fn parse_tls(q: &BTreeMap<String, String>, default_tls: bool) -> Result<Option<Tls>, VpnError> {
    let security = q
        .get("security")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let reality = match security.as_str() {
        "reality" => Some(parse_reality(q)?),
        "tls" | "xtls" => None,
        "" | "none" => {
            if !default_tls {
                return Ok(None);
            }
            if security == "none" {
                return Err(invalid("ce protocole exige TLS (security=none refusé)"));
            }
            None
        }
        other => return Err(invalid(format!("sécurité « {other} » inconnue"))),
    };
    let fingerprint = parse_fingerprint(first(q, &["fp", "fingerprint"]))?;
    if reality.is_some() && fingerprint.is_none() {
        // REALITY needs uTLS; chrome is the de-facto default of every client.
        return Ok(Some(Tls {
            server_name: parse_sni(first(q, &["sni", "servername", "peer"]))?,
            insecure: false,
            alpn: parse_alpn(first(q, &["alpn"]))?,
            fingerprint: Some("chrome".into()),
            reality,
        }));
    }
    Ok(Some(Tls {
        server_name: parse_sni(first(q, &["sni", "servername", "peer"]))?,
        insecure: flag(
            q,
            &[
                "allowinsecure",
                "insecure",
                "allow_insecure",
                "skip-cert-verify",
            ],
        ),
        alpn: parse_alpn(first(q, &["alpn"]))?,
        fingerprint,
        reality,
    }))
}

// ---------------------------------------------------------------------------------------------
// Protocols
// ---------------------------------------------------------------------------------------------

fn ss_method_password(s: &str) -> Result<(String, String), VpnError> {
    let (method, password) = s
        .split_once(':')
        .ok_or_else(|| invalid("Shadowsocks : « méthode:mot de passe » attendu"))?;
    let method = method.trim().to_ascii_lowercase();
    if method == "none" || method == "plain" {
        return Err(invalid("Shadowsocks sans chiffrement (none) refusé"));
    }
    if !SS_METHODS.contains(&method.as_str()) {
        return Err(invalid(format!(
            "méthode Shadowsocks « {method} » non prise en charge"
        )));
    }
    Ok((
        method,
        require_secret(password, "mot de passe Shadowsocks")?,
    ))
}

fn parse_ss(rest: &str, now: i64) -> Result<VpnProfile, VpnError> {
    let (body, fragment) = match rest.split_once('#') {
        Some((b, f)) => (b, Some(pct_decode(f)?)),
        None => (rest, None),
    };
    let before_query = body.split_once('?').map(|(a, _)| a).unwrap_or(body);
    if before_query.contains('@') {
        let parts = split_link(rest)?;
        if parts
            .query
            .get("plugin")
            .map(|p| !p.trim().is_empty())
            .unwrap_or(false)
        {
            return Err(invalid(
                "les plugins Shadowsocks (obfs, v2ray-plugin…) ne sont pas pris en charge",
            ));
        }
        let ui = parts.userinfo.as_deref().unwrap_or("");
        let decoded = pct_decode(ui)?;
        let creds = if decoded.contains(':') {
            decoded
        } else {
            let b = b64_decode(&decoded)
                .ok_or_else(|| invalid("Shadowsocks : identifiants base64 illisibles"))?;
            String::from_utf8(b).map_err(|_| invalid("Shadowsocks : identifiants invalides"))?
        };
        let (method, password) = ss_method_password(&creds)?;
        return Ok(VpnProfile {
            name: display_name(parts.fragment.as_deref(), &parts.host, parts.port),
            server: parts.host,
            port: parts.port,
            imported_at: now,
            protocol: Protocol::Shadowsocks { method, password },
        });
    }
    // Legacy: ss://base64(method:password@host:port)#tag
    let decoded = b64_decode(before_query.trim_end_matches('/'))
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| invalid("lien Shadowsocks illisible"))?;
    let (creds, hostport) = decoded
        .rsplit_once('@')
        .ok_or_else(|| invalid("lien Shadowsocks illisible"))?;
    let (method, password) = ss_method_password(creds)?;
    let (host, port) = split_host_port(hostport.trim())?;
    Ok(VpnProfile {
        name: display_name(fragment.as_deref(), &host, port),
        server: host,
        port,
        imported_at: now,
        protocol: Protocol::Shadowsocks { method, password },
    })
}

fn parse_vless(rest: &str, now: i64) -> Result<VpnProfile, VpnError> {
    let p = split_link(rest)?;
    let uuid = require_uuid(&pct_decode(p.userinfo.as_deref().unwrap_or(""))?)?;
    if let Some(enc) = p.query.get("encryption") {
        if !enc.is_empty() && !enc.eq_ignore_ascii_case("none") {
            return Err(invalid(format!(
                "chiffrement VLESS « {enc} » non pris en charge"
            )));
        }
    }
    let flow = match first(&p.query, &["flow"]).map(str::to_ascii_lowercase) {
        None => None,
        Some(f) if f == "xtls-rprx-vision" => Some(f),
        Some(f) if f == "xtls-rprx-vision-udp443" => Some("xtls-rprx-vision".to_string()),
        Some(f) => return Err(invalid(format!("flow VLESS « {f} » non pris en charge"))),
    };
    let tls = parse_tls(&p.query, false)?;
    if flow.is_some() && tls.is_none() {
        return Err(invalid("flow xtls-rprx-vision exige TLS ou REALITY"));
    }
    let transport = parse_transport(
        first(&p.query, &["type", "net"]),
        first(&p.query, &["path"]),
        first(&p.query, &["host"]),
        first(&p.query, &["servicename", "service_name"]),
        first(&p.query, &["headertype"]),
    )?;
    Ok(VpnProfile {
        name: display_name(p.fragment.as_deref(), &p.host, p.port),
        server: p.host,
        port: p.port,
        imported_at: now,
        protocol: Protocol::Vless {
            uuid,
            flow,
            tls,
            transport,
        },
    })
}

fn json_str(v: &serde_json::Value, key: &str) -> Option<String> {
    match v.get(key)? {
        serde_json::Value::String(s) => Some(s.trim().to_string()).filter(|s| !s.is_empty()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn parse_vmess(rest: &str, now: i64) -> Result<VpnProfile, VpnError> {
    let body = rest.split('#').next().unwrap_or(rest);
    let decoded = b64_decode(body)
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| invalid("lien VMess illisible (base64 JSON attendu)"))?;
    let v: serde_json::Value = serde_json::from_str(&decoded)
        .map_err(|_| invalid("lien VMess illisible (JSON invalide)"))?;
    if !v.is_object() {
        return Err(invalid("lien VMess illisible"));
    }
    let host =
        validate_host(&json_str(&v, "add").ok_or_else(|| invalid("VMess : serveur manquant"))?)?;
    let port = parse_port(&json_str(&v, "port").ok_or_else(|| invalid("VMess : port manquant"))?)?;
    let uuid = require_uuid(&json_str(&v, "id").unwrap_or_default())?;
    let alter_id = match json_str(&v, "aid") {
        None => 0,
        Some(a) => a
            .parse::<u32>()
            .map_err(|_| invalid("VMess : alterId invalide"))?,
    };
    if alter_id > 0 {
        return Err(invalid(
            "VMess avec alterId > 0 (ancien protocole MD5) refusé : demandez un lien aid=0",
        ));
    }
    let security = json_str(&v, "scy")
        .unwrap_or_else(|| "auto".into())
        .to_ascii_lowercase();
    if !VMESS_SECURITY.contains(&security.as_str()) {
        return Err(invalid(format!("chiffrement VMess « {security} » inconnu")));
    }
    let mut q = BTreeMap::new();
    let tls_kind = json_str(&v, "tls").unwrap_or_default().to_ascii_lowercase();
    if !tls_kind.is_empty() && tls_kind != "none" {
        q.insert("security".to_string(), tls_kind);
    }
    for (k, key) in [
        ("sni", "sni"),
        ("alpn", "alpn"),
        ("fp", "fp"),
        ("pbk", "pbk"),
        ("sid", "sid"),
    ] {
        if let Some(val) = json_str(&v, key) {
            q.insert(k.to_string(), val);
        }
    }
    if json_str(&v, "allowInsecure").map(|s| s == "1" || s == "true") == Some(true) {
        q.insert("allowinsecure".into(), "1".into());
    }
    let tls = parse_tls(&q, false)?;
    let net = json_str(&v, "net");
    let path = json_str(&v, "path");
    let hosth = json_str(&v, "host");
    let header = json_str(&v, "type");
    // gRPC service name travels in `path` for VMess links.
    let transport = parse_transport(
        net.as_deref(),
        path.as_deref(),
        hosth.as_deref(),
        path.as_deref(),
        header.as_deref(),
    )?;
    let name = json_str(&v, "ps");
    Ok(VpnProfile {
        name: display_name(name.as_deref(), &host, port),
        server: host,
        port,
        imported_at: now,
        protocol: Protocol::Vmess {
            uuid,
            security,
            alter_id,
            tls,
            transport,
        },
    })
}

fn parse_trojan(rest: &str, now: i64) -> Result<VpnProfile, VpnError> {
    let p = split_link(rest)?;
    let password = require_secret(
        &pct_decode(p.userinfo.as_deref().unwrap_or(""))?,
        "mot de passe Trojan",
    )?;
    let tls = parse_tls(&p.query, true)?.unwrap_or_default();
    let transport = parse_transport(
        first(&p.query, &["type", "net"]),
        first(&p.query, &["path"]),
        first(&p.query, &["host"]),
        first(&p.query, &["servicename", "service_name"]),
        first(&p.query, &["headertype"]),
    )?;
    Ok(VpnProfile {
        name: display_name(p.fragment.as_deref(), &p.host, p.port),
        server: p.host,
        port: p.port,
        imported_at: now,
        protocol: Protocol::Trojan {
            password,
            tls,
            transport,
        },
    })
}

/// `mport=2000-3000,4000` -> `["2000:3000", "4000:4000"]`.
fn parse_port_hopping(v: &str) -> Result<Vec<String>, VpnError> {
    let mut out = Vec::new();
    for part in v.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (a, b) = part.split_once('-').unwrap_or((part, part));
        let (a, b) = (parse_port(a)?, parse_port(b)?);
        if a > b {
            return Err(invalid(format!("plage de ports invalide : {part}")));
        }
        out.push(format!("{a}:{b}"));
    }
    Ok(out)
}

fn parse_hy2(rest: &str, now: i64) -> Result<VpnProfile, VpnError> {
    // `hysteria2://auth@host:port,2000-3000/?…` (port list after the first port) is also seen: fold it
    // into mport.
    let p = match split_link(rest) {
        Ok(p) => p,
        Err(_) => {
            let fixed = fold_multi_port(rest).ok_or_else(|| invalid("lien Hysteria2 invalide"))?;
            split_link(&fixed)?
        }
    };
    let password = require_secret(
        &pct_decode(p.userinfo.as_deref().unwrap_or(""))?,
        "mot de passe Hysteria2",
    )?;
    let obfs_password = match first(&p.query, &["obfs"]).map(str::to_ascii_lowercase) {
        None => None,
        Some(o) if o == "salamander" => Some(require_secret(
            first(
                &p.query,
                &["obfs-password", "obfs_password", "obfspassword"],
            )
            .unwrap_or(""),
            "mot de passe d'obfuscation salamander",
        )?),
        Some(o) if o == "none" => None,
        Some(o) => return Err(invalid(format!("obfuscation Hysteria2 « {o} » inconnue"))),
    };
    let server_ports = match first(&p.query, &["mport", "ports"]) {
        Some(m) => parse_port_hopping(m)?,
        None => vec![],
    };
    let tls = Tls {
        server_name: parse_sni(first(&p.query, &["sni", "peer"]))?,
        insecure: flag(&p.query, &["insecure", "allowinsecure", "skip-cert-verify"]),
        alpn: parse_alpn(first(&p.query, &["alpn"]))?,
        fingerprint: None,
        reality: None,
    };
    let mbps = |k: &str| -> Result<Option<u32>, VpnError> {
        match first(&p.query, &[k]) {
            None => Ok(None),
            Some(v) => {
                let digits: String = v.chars().take_while(char::is_ascii_digit).collect();
                digits
                    .parse::<u32>()
                    .map(Some)
                    .map_err(|_| invalid(format!("débit {k} invalide")))
            }
        }
    };
    Ok(VpnProfile {
        name: display_name(p.fragment.as_deref(), &p.host, p.port),
        server: p.host.clone(),
        port: p.port,
        imported_at: now,
        protocol: Protocol::Hysteria2 {
            password,
            obfs_password,
            server_ports,
            tls,
            up_mbps: mbps("upmbps")?,
            down_mbps: mbps("downmbps")?,
        },
    })
}

/// `auth@host:443,2000-3000/?q` -> `auth@host:443/?q&mport=2000-3000`.
fn fold_multi_port(rest: &str) -> Option<String> {
    let at = rest.rfind('@')?;
    let (user, tail) = rest.split_at(at + 1);
    let end = tail.find(['/', '?', '#']).unwrap_or(tail.len());
    let (hostports, after) = tail.split_at(end);
    let (host, ports) = hostports.rsplit_once(':')?;
    let (main, extra) = ports.split_once(',')?;
    let mut after = after.to_string();
    let sep = if after.contains('?') { "&" } else { "?" };
    let insert_at = after.find('#').unwrap_or(after.len());
    after.insert_str(insert_at, &format!("{sep}mport={extra}"));
    Some(format!("{user}{host}:{main}{after}"))
}

fn parse_tuic(rest: &str, now: i64) -> Result<VpnProfile, VpnError> {
    let p = split_link(rest)?;
    let ui = p.userinfo.as_deref().unwrap_or("");
    let (u, pw) = ui
        .split_once(':')
        .ok_or_else(|| invalid("TUIC : « uuid:mot de passe » attendu"))?;
    let uuid = require_uuid(&pct_decode(u)?)?;
    let password = require_secret(&pct_decode(pw)?, "mot de passe TUIC")?;
    let congestion_control = match first(&p.query, &["congestion_control", "congestion-control"]) {
        None => None,
        Some(c) => {
            let c = c.to_ascii_lowercase();
            if !["cubic", "new_reno", "bbr"].contains(&c.as_str()) {
                return Err(invalid(format!(
                    "contrôle de congestion TUIC « {c} » inconnu"
                )));
            }
            Some(c)
        }
    };
    let udp_relay_mode = match first(&p.query, &["udp_relay_mode", "udp-relay-mode"]) {
        None => None,
        Some(m) => {
            let m = m.to_ascii_lowercase();
            if !["native", "quic"].contains(&m.as_str()) {
                return Err(invalid(format!("mode de relais UDP TUIC « {m} » inconnu")));
            }
            Some(m)
        }
    };
    let mut alpn = parse_alpn(first(&p.query, &["alpn"]))?;
    if alpn.is_empty() {
        alpn.push("h3".into());
    }
    let tls = Tls {
        server_name: parse_sni(first(&p.query, &["sni", "peer"]))?,
        insecure: flag(&p.query, &["allow_insecure", "allowinsecure", "insecure"]),
        alpn,
        fingerprint: None,
        reality: None,
    };
    Ok(VpnProfile {
        name: display_name(p.fragment.as_deref(), &p.host, p.port),
        server: p.host,
        port: p.port,
        imported_at: now,
        protocol: Protocol::Tuic {
            uuid,
            password,
            congestion_control,
            udp_relay_mode,
            tls,
        },
    })
}

/// Interface address: `10.0.0.2` (-> /32 or /128) or with prefix.
fn parse_cidr(s: &str, default_prefix: bool) -> Result<String, VpnError> {
    let s = s.trim();
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip, Some(p)),
        None => (s, None),
    };
    let ip: IpAddr = ip
        .trim()
        .parse()
        .map_err(|_| invalid(format!("adresse invalide : {s}")))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(p) => p
            .trim()
            .parse::<u8>()
            .ok()
            .filter(|p| *p <= max)
            .ok_or_else(|| invalid(format!("préfixe invalide : {s}")))?,
        None if default_prefix => max,
        None => return Err(invalid(format!("préfixe manquant : {s}"))),
    };
    Ok(format!("{ip}/{prefix}"))
}

fn split_list(v: &str) -> impl Iterator<Item = &str> {
    v.split(',').map(str::trim).filter(|s| !s.is_empty())
}

fn parse_reserved(v: &str) -> Result<Vec<u8>, VpnError> {
    let parts: Vec<&str> = split_list(v).collect();
    if parts.len() == 3 {
        return parts
            .iter()
            .map(|p| {
                p.parse::<u8>()
                    .map_err(|_| invalid("champ reserved invalide"))
            })
            .collect();
    }
    // Base64 of 3 bytes (`AAAA`).
    match b64_decode(v) {
        Some(b) if b.len() == 3 => Ok(b),
        _ => Err(invalid("champ reserved invalide (3 octets)")),
    }
}

fn dns_ips(v: &str) -> Vec<String> {
    split_list(v)
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .map(|ip| ip.to_string())
        .collect()
}

fn parse_wg_link(rest: &str, now: i64) -> Result<VpnProfile, VpnError> {
    let p = split_link(rest)?;
    let private_key = require_wg_key(
        &pct_decode(p.userinfo.as_deref().unwrap_or(""))?,
        "clé privée",
    )?;
    let peer_public_key = require_wg_key(
        first(&p.query, &["publickey", "public_key", "peer_public_key"])
            .ok_or_else(|| invalid("clé publique du pair manquante"))?,
        "clé publique",
    )?;
    let addresses = split_list(
        first(&p.query, &["address", "ip", "local_address"])
            .ok_or_else(|| invalid("adresse de l'interface WireGuard manquante"))?,
    )
    .map(|a| parse_cidr(a, true))
    .collect::<Result<Vec<_>, _>>()?;
    let pre_shared_key = first(&p.query, &["presharedkey", "pre_shared_key", "psk"])
        .map(|k| require_wg_key(k, "clé pré-partagée"))
        .transpose()?;
    let mtu = first(&p.query, &["mtu"])
        .map(|m| {
            m.parse::<u32>()
                .ok()
                .filter(|m| (576..=9000).contains(m))
                .ok_or_else(|| invalid("MTU invalide"))
        })
        .transpose()?;
    let keepalive = first(&p.query, &["keepalive", "persistentkeepalive"])
        .map(|k| k.parse::<u16>().map_err(|_| invalid("keepalive invalide")))
        .transpose()?;
    let reserved = first(&p.query, &["reserved"])
        .map(parse_reserved)
        .transpose()?;
    let allowed_ips = match first(&p.query, &["allowedips", "allowed_ips"]) {
        Some(a) => split_list(a)
            .map(|c| parse_cidr(c, false))
            .collect::<Result<Vec<_>, _>>()?,
        None => vec!["0.0.0.0/0".into(), "::/0".into()],
    };
    let dns = first(&p.query, &["dns"]).map(dns_ips).unwrap_or_default();
    Ok(VpnProfile {
        name: display_name(p.fragment.as_deref(), &p.host, p.port),
        server: p.host,
        port: p.port,
        imported_at: now,
        protocol: Protocol::Wireguard(WireGuard {
            private_key,
            addresses,
            peer_public_key,
            pre_shared_key,
            allowed_ips,
            keepalive,
            mtu,
            reserved,
            dns,
        }),
    })
}

fn looks_like_wireguard_conf(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .any(|l| l.eq_ignore_ascii_case("[interface]"))
}

fn parse_wg_conf(text: &str, now: i64) -> Result<VpnProfile, VpnError> {
    #[derive(PartialEq)]
    enum Section {
        None,
        Interface,
        Peer,
    }
    let mut section = Section::None;
    let mut peers = 0;
    let mut name: Option<String> = None;
    let mut private_key = None;
    let mut addresses: Vec<String> = Vec::new();
    let mut dns = Vec::new();
    let mut mtu = None;
    let mut public_key = None;
    let mut psk = None;
    let mut endpoint = None;
    let mut allowed: Vec<String> = Vec::new();
    let mut keepalive = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            // `# Name = Paris` (wg-quick UIs) gives a display name.
            if let Some((k, v)) = comment.split_once('=') {
                if k.trim().eq_ignore_ascii_case("name") && name.is_none() {
                    name = Some(v.trim().to_string());
                }
            }
            continue;
        }
        if line.starts_with('[') {
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => Section::Interface,
                "[peer]" => {
                    peers += 1;
                    Section::Peer
                }
                other => return Err(invalid(format!("section WireGuard inconnue : {other}"))),
            };
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| invalid(format!("ligne WireGuard invalide : {line}")))?;
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match (&section, k.as_str()) {
            (Section::Interface, "privatekey") => {
                private_key = Some(require_wg_key(v, "clé privée")?)
            }
            (Section::Interface, "address") => {
                for a in split_list(v) {
                    addresses.push(parse_cidr(a, true)?);
                }
            }
            (Section::Interface, "dns") => dns.extend(dns_ips(v)),
            (Section::Interface, "mtu") => {
                mtu = Some(
                    v.parse::<u32>()
                        .ok()
                        .filter(|m| (576..=9000).contains(m))
                        .ok_or_else(|| invalid("MTU invalide"))?,
                )
            }
            (Section::Interface, "listenport" | "table" | "fwmark" | "saveconfig") => {}
            (_, "preup" | "postup" | "predown" | "postdown") => {
                return Err(invalid(
                    "scripts PreUp/PostUp refusés : retirez-les du fichier WireGuard",
                ))
            }
            (Section::Peer, "publickey") => public_key = Some(require_wg_key(v, "clé publique")?),
            (Section::Peer, "presharedkey") => psk = Some(require_wg_key(v, "clé pré-partagée")?),
            (Section::Peer, "endpoint") => endpoint = Some(split_host_port(v)?),
            (Section::Peer, "allowedips") => {
                for a in split_list(v) {
                    allowed.push(parse_cidr(a, false)?);
                }
            }
            (Section::Peer, "persistentkeepalive") => {
                keepalive = if v.eq_ignore_ascii_case("off") {
                    None
                } else {
                    Some(
                        v.parse::<u16>()
                            .map_err(|_| invalid("keepalive invalide"))?,
                    )
                }
            }
            (Section::None, _) => {
                return Err(invalid("fichier WireGuard : clé hors section"));
            }
            (_, other) => return Err(invalid(format!("clé WireGuard inconnue : {other}"))),
        }
    }
    if peers != 1 {
        return Err(invalid(format!(
            "fichier WireGuard avec {peers} pairs : un seul [Peer] est pris en charge"
        )));
    }
    let private_key = private_key.ok_or_else(|| invalid("PrivateKey manquante"))?;
    if addresses.is_empty() {
        return Err(invalid("Address manquante dans [Interface]"));
    }
    let peer_public_key = public_key.ok_or_else(|| invalid("PublicKey du pair manquante"))?;
    let (host, port) = endpoint.ok_or_else(|| invalid("Endpoint du pair manquant"))?;
    if allowed.is_empty() {
        return Err(invalid("AllowedIPs manquant"));
    }
    let fallback = format!("WireGuard {host}");
    let name = display_name(Some(name.as_deref().unwrap_or(&fallback)), &host, port);
    Ok(VpnProfile {
        name,
        server: host,
        port,
        imported_at: now,
        protocol: Protocol::Wireguard(WireGuard {
            private_key,
            addresses,
            peer_public_key,
            pre_shared_key: psk,
            allowed_ips: allowed,
            keepalive,
            mtu,
            reserved: None,
            dns,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";
    const WG_PRIV: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const WG_PUB: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn p(s: &str) -> VpnProfile {
        parse(s, 100).unwrap_or_else(|e| panic!("{s}: {e}"))
    }
    fn err(s: &str) -> String {
        parse(s, 100).unwrap_err().to_string()
    }

    #[test]
    fn shadowsocks_sip002_and_legacy() {
        let ui = URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:pa@ss/w+rd");
        let pr = p(&format!("ss://{ui}@203.0.113.7:8388/?outline=1#Paris%20SS"));
        assert_eq!(pr.name, "Paris SS");
        assert_eq!(pr.server, "203.0.113.7");
        assert_eq!(pr.port, 8388);
        assert_eq!(
            pr.protocol,
            Protocol::Shadowsocks {
                method: "chacha20-ietf-poly1305".into(),
                password: "pa@ss/w+rd".into()
            }
        );
        // SIP002 plain userinfo (2022 methods).
        let pr =
            p("ss://2022-blake3-aes-128-gcm:8JCsPssfgS8tiRwiMlhARg%3D%3D@[2001:db8::1]:443#v6");
        assert_eq!(pr.server, "2001:db8::1");
        assert!(
            matches!(&pr.protocol, Protocol::Shadowsocks { password, .. } if password == "8JCsPssfgS8tiRwiMlhARg==")
        );
        // Legacy full base64.
        let legacy = STANDARD.encode("aes-256-gcm:secret@vpn.example.com:443");
        let pr = p(&format!("ss://{legacy}#Old"));
        assert_eq!(pr.server, "vpn.example.com");
        assert_eq!(pr.info().transport.as_deref(), Some("aes-256-gcm"));
        assert!(err(&format!(
            "ss://{ui}@203.0.113.7:8388/?plugin=obfs-local%3Bobfs%3Dhttp"
        ))
        .contains("plugins"));
        assert!(err(&format!("ss://{}@1.2.3.4:1", STANDARD.encode("none:x"))).contains("none"));
        assert!(
            err(&format!("ss://{}@1.2.3.4:1", STANDARD.encode("bf-cfb:x")))
                .contains("non prise en charge")
        );
        assert!(err(&format!("ss://{ui}@203.0.113.7:0")).contains("port"));
    }

    #[test]
    fn vless_reality_and_ws() {
        let pbk = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let pr = p(&format!(
            "vless://{UUID}@edge.example.net:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk={pbk}&sid=6ba85179e30d4fc2&type=tcp&flow=xtls-rprx-vision#R%C3%A9alit%C3%A9"
        ));
        assert_eq!(pr.name, "Réalité");
        match &pr.protocol {
            Protocol::Vless {
                uuid,
                flow,
                tls,
                transport,
            } => {
                assert_eq!(uuid, UUID);
                assert_eq!(flow.as_deref(), Some("xtls-rprx-vision"));
                let tls = tls.as_ref().unwrap();
                assert_eq!(tls.server_name.as_deref(), Some("www.microsoft.com"));
                assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
                assert_eq!(tls.reality.as_ref().unwrap().short_id, "6ba85179e30d4fc2");
                assert!(transport.is_none());
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(pr.info().transport.as_deref(), Some("reality+tcp"));
        let pr = p(&format!(
            "vless://{UUID}@1.2.3.4:443?security=tls&type=ws&path=%2Fray%3Fed%3D2048&host=cdn.example.com#ws"
        ));
        match &pr.protocol {
            Protocol::Vless {
                transport:
                    Some(Transport::Ws {
                        path,
                        host,
                        max_early_data,
                    }),
                ..
            } => {
                assert_eq!(path, "/ray");
                assert_eq!(host.as_deref(), Some("cdn.example.com"));
                assert_eq!(*max_early_data, Some(2048));
            }
            other => panic!("{other:?}"),
        }
        let pr = p(&format!(
            "vless://{UUID}@1.2.3.4:443?security=tls&type=grpc&serviceName=grpc-svc"
        ));
        assert!(
            matches!(&pr.protocol, Protocol::Vless { transport: Some(Transport::Grpc { service_name }), .. } if service_name == "grpc-svc")
        );
        assert!(err(&format!("vless://{UUID}@1.2.3.4:443?security=reality")).contains("pbk"));
        assert!(err("vless://not-a-uuid@1.2.3.4:443").contains("UUID"));
        assert!(err(&format!("vless://{UUID}@1.2.3.4:443?type=xhttp")).contains("XHTTP"));
        assert!(
            err(&format!("vless://{UUID}@1.2.3.4:443?flow=xtls-rprx-vision")).contains("exige TLS")
        );
        assert!(err(&format!(
            "vless://{UUID}@1.2.3.4:443?security=tls&fp=netscape"
        ))
        .contains("empreinte"));
        assert!(err(&format!("vless://{UUID}@1.2.3.4:443?sni=a&sni=b")).contains("répété"));
    }

    #[test]
    fn vmess_json() {
        let j = serde_json::json!({
            "v": "2", "ps": "Tokyo", "add": "jp.example.org", "port": 443, "id": UUID, "aid": "0",
            "scy": "auto", "net": "ws", "type": "none", "host": "jp.example.org", "path": "/vm",
            "tls": "tls", "sni": "jp.example.org", "alpn": "h2,http/1.1", "fp": "safari"
        });
        let pr = p(&format!("vmess://{}", STANDARD.encode(j.to_string())));
        assert_eq!(pr.name, "Tokyo");
        assert_eq!(pr.port, 443);
        match &pr.protocol {
            Protocol::Vmess {
                security,
                alter_id,
                tls,
                transport,
                ..
            } => {
                assert_eq!(security, "auto");
                assert_eq!(*alter_id, 0);
                assert_eq!(tls.as_ref().unwrap().alpn, vec!["h2", "http/1.1"]);
                assert!(matches!(transport, Some(Transport::Ws { path, .. }) if path == "/vm"));
            }
            other => panic!("{other:?}"),
        }
        let old = serde_json::json!({"add": "1.2.3.4", "port": "80", "id": UUID, "aid": "64"});
        assert!(err(&format!("vmess://{}", STANDARD.encode(old.to_string()))).contains("alterId"));
        assert!(err("vmess://bm90IGpzb24=").contains("JSON"));
        let tcp_http = serde_json::json!({"add": "1.2.3.4", "port": "80", "id": UUID, "net": "tcp", "type": "http"});
        assert!(err(&format!(
            "vmess://{}",
            STANDARD.encode(tcp_http.to_string())
        ))
        .contains("headerType"));
    }

    #[test]
    fn trojan_hysteria2_tuic() {
        let pr = p("trojan://p%40ss@tr.example.com:443?sni=tr.example.com&allowInsecure=1&type=ws&path=/t#Tr");
        match &pr.protocol {
            Protocol::Trojan {
                password,
                tls,
                transport,
            } => {
                assert_eq!(password, "p@ss");
                assert!(tls.insecure);
                assert!(transport.is_some());
            }
            other => panic!("{other:?}"),
        }
        assert!(err("trojan://x@1.2.3.4:443?security=none").contains("exige TLS"));
        let pr = p("hysteria2://letmein@hy.example.com:443/?sni=hy.example.com&obfs=salamander&obfs-password=cry_me&insecure=0&mport=20000-30000#HY");
        match &pr.protocol {
            Protocol::Hysteria2 {
                password,
                obfs_password,
                server_ports,
                tls,
                ..
            } => {
                assert_eq!(password, "letmein");
                assert_eq!(obfs_password.as_deref(), Some("cry_me"));
                assert_eq!(server_ports, &vec!["20000:30000".to_string()]);
                assert!(!tls.insecure);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(pr.info().transport.as_deref(), Some("quic+salamander"));
        let pr = p("hy2://pw@1.2.3.4:443,5000-6000/?sni=a.example.com");
        assert!(
            matches!(&pr.protocol, Protocol::Hysteria2 { server_ports, .. } if server_ports == &vec!["5000:6000".to_string()])
        );
        assert!(err("hy2://pw@1.2.3.4:443?obfs=salamander").contains("salamander"));
        let pr = p(&format!("tuic://{UUID}:hunter2@tu.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=tu.example.com#T"));
        match &pr.protocol {
            Protocol::Tuic {
                password,
                congestion_control,
                tls,
                ..
            } => {
                assert_eq!(password, "hunter2");
                assert_eq!(congestion_control.as_deref(), Some("bbr"));
                assert_eq!(tls.alpn, vec!["h3"]);
            }
            other => panic!("{other:?}"),
        }
        assert!(err(&format!("tuic://{UUID}@1.2.3.4:443")).contains("uuid:mot de passe"));
    }

    #[test]
    fn wireguard_link_and_conf() {
        let link = format!(
            "wireguard://{}@162.159.192.1:2408?publickey={}&address=172.16.0.2/32,2606:4700:110:8a36::2/128&mtu=1280&reserved=1,2,3#WARP",
            percent_encoding::utf8_percent_encode(WG_PRIV, percent_encoding::NON_ALPHANUMERIC),
            percent_encoding::utf8_percent_encode(WG_PUB, percent_encoding::NON_ALPHANUMERIC),
        );
        let pr = p(&link);
        match &pr.protocol {
            Protocol::Wireguard(w) => {
                assert_eq!(w.private_key, WG_PRIV);
                assert_eq!(
                    w.addresses,
                    vec!["172.16.0.2/32", "2606:4700:110:8a36::2/128"]
                );
                assert_eq!(w.reserved, Some(vec![1, 2, 3]));
                assert_eq!(w.mtu, Some(1280));
                assert_eq!(w.allowed_ips, vec!["0.0.0.0/0", "::/0"]);
            }
            other => panic!("{other:?}"),
        }
        let conf = format!(
            "# Name = Mullvad Paris\n[Interface]\nPrivateKey = {WG_PRIV}\nAddress = 10.64.0.2/32, fc00:bbbb:bbbb:bb01::2/128\nDNS = 10.64.0.1, search.lan\n\n[Peer]\nPublicKey = {WG_PUB}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = fr-par-wg-001.relays.mullvad.net:51820\nPersistentKeepalive = 25\n"
        );
        let pr = p(&conf);
        assert_eq!(pr.name, "Mullvad Paris");
        assert_eq!(pr.server, "fr-par-wg-001.relays.mullvad.net");
        assert_eq!(pr.port, 51820);
        match &pr.protocol {
            Protocol::Wireguard(w) => {
                assert_eq!(w.dns, vec!["10.64.0.1"]);
                assert_eq!(w.keepalive, Some(25));
            }
            other => panic!("{other:?}"),
        }
        assert!(err(&format!(
            "{conf}\n[Peer]\nPublicKey = {WG_PUB}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 1.2.3.4:1\n"
        ))
        .contains("2 pairs"));
        assert!(
            err(&conf.replace("PersistentKeepalive = 25", "PostUp = iptables -A x"))
                .contains("PostUp")
        );
        assert!(err(&conf.replace(WG_PRIV, "short")).contains("clé privée"));
    }

    #[test]
    fn rejects_garbage_and_multiple() {
        assert!(err("").contains("vide"));
        assert!(
            err("hello world").contains("non reconnu") || err("hello world").contains("format")
        );
        assert!(err("http://example.com").contains("non pris en charge"));
        assert!(err("ssr://abc").contains("ShadowsocksR"));
        let two = "trojan://a@1.2.3.4:443\ntrojan://b@1.2.3.5:443".to_string();
        assert!(err(&two).contains("un seul"));
        let sub = STANDARD.encode("trojan://a@1.2.3.4:443\ntrojan://b@1.2.3.5:443\n");
        assert!(err(&sub).contains("2 serveurs"));
        let sub1 = STANDARD.encode("trojan://a@1.2.3.4:443#Only\n");
        assert_eq!(p(&sub1).name, "Only");
        assert!(err("trojan://a@bad_host:443").contains("invalide"));
        assert!(err("trojan://a@2001:db8::1:443").contains("crochets"));
        assert!(parse(&"x".repeat(MAX_PROFILE_BYTES + 1), 0).is_err());
    }

    #[test]
    fn debug_hides_secrets_and_roundtrips() {
        let pr = p("trojan://topsecret@tr.example.com:443#Tr");
        let dbg = format!("{pr:?}");
        assert!(!dbg.contains("topsecret"));
        let json = serde_json::to_string(&pr).unwrap();
        let back: VpnProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pr);
        let info = pr.info();
        assert_eq!(info.protocol, "trojan");
        assert_eq!(info.imported_at, 100);
        assert!(!serde_json::to_string(&info).unwrap().contains("topsecret"));
    }
}
