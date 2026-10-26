//! `dnscrypt-proxy.toml` generation.
//!
//! Option names and the `public-resolvers` source (URLs + minisign key) were checked against
//! `dnscrypt-proxy/example-dnscrypt-proxy.toml` (DNSCrypt/dnscrypt-proxy master, 2026-10-25):
//! `listen_addresses`, `server_names`, `user_name` ("not supported on Windows" ⇒ supported on macOS; the
//! process re-execs itself with the same PID after binding), `require_dnssec/nolog/nofilter`,
//! `bootstrap_resolvers`, `ignore_system_dns`, `netprobe_timeout`, `netprobe_address`, `cache*`,
//! `log_file`, `log_file_latest`, `log_files_max_size/age/backups` (also rotate plugin logs),
//! `[blocked_names] blocked_names_file/log_file/log_format`, `[allowed_names] allowed_names_file`,
//! `[sources.public-resolvers] urls/cache_file/minisign_key/refresh_delay/prefix`. Hot reload stays off
//! (default since 2.1.10): the supervisor restarts the proxy when the lists change.

use crate::DnsError;
use std::net::SocketAddr;
use std::path::Path;

/// Official resolver list URLs (example config, `[sources.public-resolvers]`).
pub const PUBLIC_RESOLVERS_URLS: [&str; 3] = [
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md",
    "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md",
    "https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/public-resolvers.md",
];
/// minisign key of the resolver lists (example config).
pub const PUBLIC_RESOLVERS_MINISIGN_KEY: &str =
    "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

/// Inputs of [`render`].
#[derive(Debug, Clone)]
pub struct ProxyConfigParams<'a> {
    pub listen: &'a str,
    pub server_names: &'a [String],
    pub blocked_names_file: &'a Path,
    pub allowed_names_file: &'a Path,
    /// Writable by the proxy (logs, resolver list cache).
    pub runtime_dir: &'a Path,
    /// Drop privileges to this user after binding port 53 (root only).
    pub user_name: Option<&'a str>,
}

/// Parse and validate the listen address: must be a loopback socket address.
pub fn parse_listen(listen: &str) -> Result<SocketAddr, DnsError> {
    let addr: SocketAddr = listen
        .trim()
        .parse()
        .map_err(|_| DnsError::Config(format!("adresse d'écoute invalide : {listen}")))?;
    if !addr.ip().is_loopback() {
        return Err(DnsError::Config(format!(
            "l'adresse d'écoute doit être locale (127.0.0.1 / ::1) : {listen}"
        )));
    }
    Ok(addr)
}

fn valid_server_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// TOML basic string with escaping.
fn q(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04X}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn qp(p: &Path) -> String {
    q(&p.to_string_lossy())
}

fn list(items: &[String]) -> String {
    format!(
        "[{}]",
        items.iter().map(|s| q(s)).collect::<Vec<_>>().join(", ")
    )
}

/// Render the configuration file.
pub fn render(p: &ProxyConfigParams<'_>) -> Result<String, DnsError> {
    let listen = parse_listen(p.listen)?;
    if let Some(bad) = p.server_names.iter().find(|s| !valid_server_name(s)) {
        return Err(DnsError::Config(format!(
            "nom de serveur invalide : {bad:?}"
        )));
    }
    let mut c = String::with_capacity(4096);
    c.push_str(
        "# Généré par Parabellum (pb-dns) — ne pas modifier, réécrit à chaque changement.\n\n",
    );
    c.push_str(&format!(
        "listen_addresses = {}\n",
        list(&[listen.to_string()])
    ));
    c.push_str("max_clients = 250\n");
    if let Some(u) = p.user_name {
        if !valid_server_name(u) {
            return Err(DnsError::Config(format!("utilisateur invalide : {u:?}")));
        }
        c.push_str(&format!("user_name = {}\n", q(u)));
    }
    if !p.server_names.is_empty() {
        c.push_str(&format!("server_names = {}\n", list(p.server_names)));
    }
    c.push_str(
        "ipv4_servers = true\n\
         ipv6_servers = false\n\
         dnscrypt_servers = true\n\
         doh_servers = true\n\
         odoh_servers = false\n\
         require_dnssec = false\n\
         require_nolog = true\n\
         require_nofilter = false\n\
         force_tcp = false\n\
         timeout = 5000\n\
         keepalive = 30\n\
         cert_refresh_delay = 240\n\
         bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']\n\
         ignore_system_dns = true\n\
         netprobe_timeout = 30\n\
         netprobe_address = '9.9.9.9:53'\n\
         block_ipv6 = false\n\
         block_unqualified = true\n\
         block_undelegated = true\n\
         reject_ttl = 10\n\
         cache = true\n\
         cache_size = 4096\n\
         cache_min_ttl = 600\n\
         cache_max_ttl = 86400\n\
         cache_neg_min_ttl = 60\n\
         cache_neg_max_ttl = 600\n\
         log_level = 2\n",
    );
    c.push_str(&format!(
        "log_file = {}\n",
        qp(&p.runtime_dir.join("dnscrypt-proxy.log"))
    ));
    c.push_str("log_file_latest = true\n");
    c.push_str("log_files_max_size = 5\nlog_files_max_age = 2\nlog_files_max_backups = 1\n\n");

    c.push_str("[blocked_names]\n");
    c.push_str(&format!(
        "blocked_names_file = {}\n",
        qp(p.blocked_names_file)
    ));
    c.push_str(&format!(
        "log_file = {}\n",
        qp(&p.runtime_dir.join(crate::BLOCKED_LOG_FILE))
    ));
    c.push_str("log_format = 'ltsv'\n\n");

    c.push_str("[allowed_names]\n");
    c.push_str(&format!(
        "allowed_names_file = {}\n\n",
        qp(p.allowed_names_file)
    ));

    c.push_str("[sources]\n\n[sources.public-resolvers]\n");
    let urls: Vec<String> = PUBLIC_RESOLVERS_URLS
        .iter()
        .map(|s| s.to_string())
        .collect();
    c.push_str(&format!("urls = {}\n", list(&urls)));
    c.push_str(&format!(
        "cache_file = {}\n",
        qp(&p.runtime_dir.join("public-resolvers.md"))
    ));
    c.push_str(&format!(
        "minisign_key = {}\n",
        q(PUBLIC_RESOLVERS_MINISIGN_KEY)
    ));
    c.push_str("refresh_delay = 73\nprefix = ''\n");
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAPSHOT: &str = r#"# Généré par Parabellum (pb-dns) — ne pas modifier, réécrit à chaque changement.

listen_addresses = ["127.0.0.1:53"]
max_clients = 250
user_name = "nobody"
server_names = ["cloudflare", "quad9-doh-ip4-port443-filter-pri"]
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true
odoh_servers = false
require_dnssec = false
require_nolog = true
require_nofilter = false
force_tcp = false
timeout = 5000
keepalive = 30
cert_refresh_delay = 240
bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']
ignore_system_dns = true
netprobe_timeout = 30
netprobe_address = '9.9.9.9:53'
block_ipv6 = false
block_unqualified = true
block_undelegated = true
reject_ttl = 10
cache = true
cache_size = 4096
cache_min_ttl = 600
cache_max_ttl = 86400
cache_neg_min_ttl = 60
cache_neg_max_ttl = 600
log_level = 2
log_file = "/Library/Application Support/Parabellum/dns/runtime/dnscrypt-proxy.log"
log_file_latest = true
log_files_max_size = 5
log_files_max_age = 2
log_files_max_backups = 1

[blocked_names]
blocked_names_file = "/Library/Application Support/Parabellum/dns/blocked-names.txt"
log_file = "/Library/Application Support/Parabellum/dns/runtime/blocked.log"
log_format = 'ltsv'

[allowed_names]
allowed_names_file = "/Library/Application Support/Parabellum/dns/allowed-names.txt"

[sources]

[sources.public-resolvers]
urls = ["https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md", "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md", "https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/public-resolvers.md"]
cache_file = "/Library/Application Support/Parabellum/dns/runtime/public-resolvers.md"
minisign_key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3"
refresh_delay = 73
prefix = ''
"#;

    fn params<'a>(
        servers: &'a [String],
        rt: &'a Path,
        b: &'a Path,
        a: &'a Path,
    ) -> ProxyConfigParams<'a> {
        ProxyConfigParams {
            listen: "127.0.0.1:53",
            server_names: servers,
            blocked_names_file: b,
            allowed_names_file: a,
            runtime_dir: rt,
            user_name: Some("nobody"),
        }
    }

    #[test]
    fn snapshot_and_valid_toml() {
        let dns = Path::new("/Library/Application Support/Parabellum/dns");
        let rt = dns.join("runtime");
        let (b, a) = (dns.join("blocked-names.txt"), dns.join("allowed-names.txt"));
        let servers = pb_core::config::DnsConfig::default().upstream_servers;
        let out = render(&params(&servers, &rt, &b, &a)).unwrap();
        assert_eq!(out, SNAPSHOT);
        let v: toml::Value = toml::from_str(&out).unwrap();
        assert_eq!(v["listen_addresses"][0].as_str(), Some("127.0.0.1:53"));
        assert_eq!(v["blocked_names"]["log_format"].as_str(), Some("ltsv"));
        assert_eq!(
            v["sources"]["public-resolvers"]["minisign_key"].as_str(),
            Some(PUBLIC_RESOLVERS_MINISIGN_KEY)
        );
        assert_eq!(v["ignore_system_dns"].as_bool(), Some(true));
    }

    #[test]
    fn rejects_bad_inputs() {
        let dns = Path::new("/x");
        let (rt, b, a) = (dns.join("r"), dns.join("b"), dns.join("a"));
        let bad = vec!["cloud\"flare".to_string()];
        assert!(render(&params(&bad, &rt, &b, &a)).is_err());
        let ok: Vec<String> = vec![];
        let mut p = params(&ok, &rt, &b, &a);
        p.listen = "0.0.0.0:53";
        assert!(render(&p).is_err(), "never listen on the LAN");
        p.listen = "[::1]:53";
        assert!(render(&p)
            .unwrap()
            .contains("listen_addresses = [\"[::1]:53\"]"));
        assert_eq!(q("a\"b\\c\n"), "\"a\\\"b\\\\c\\n\"");
    }
}
