//! System DNS switching (macOS `networksetup`) and the saved-original-DNS state file.
//!
//! `dns/saved-dns.json` (also read by the uninstall script when the daemon is gone):
//! `{"version":1,"saved_at":<unix secs>,"services":{"Wi-Fi":["192.168.1.1"],"Ethernet":[]}}` —
//! an empty array means "DHCP" (restored with `networksetup -setdnsservers <svc> Empty`).
//! The file is written **before** any change and never records our own loopback servers.

use crate::DnsError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

/// Absolute paths of the Apple tools used here.
pub const NETWORKSETUP: &str = "/usr/sbin/networksetup";
pub const DSCACHEUTIL: &str = "/usr/bin/dscacheutil";
pub const KILLALL: &str = "/usr/bin/killall";

/// Current saved-dns.json format version.
pub const SAVED_DNS_VERSION: u32 = 1;

/// Original DNS servers of every network service we changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedDns {
    pub version: u32,
    pub saved_at: i64,
    /// Service name → original servers (empty = DHCP / automatic).
    pub services: BTreeMap<String, Vec<String>>,
}

impl SavedDns {
    pub fn new() -> Self {
        Self {
            version: SAVED_DNS_VERSION,
            saved_at: pb_core::now_ts(),
            services: BTreeMap::new(),
        }
    }
}

impl Default for SavedDns {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of reading `saved-dns.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavedState {
    Absent,
    Present(SavedDns),
    /// Unreadable / unparsable (the file is renamed `saved-dns.json.corrupt`).
    Corrupt,
}

/// Read the saved state (bounded).
pub fn load_saved(path: &Path) -> SavedState {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return SavedState::Absent,
        Err(_) => return SavedState::Corrupt,
    };
    if data.len() > 1024 * 1024 {
        return SavedState::Corrupt;
    }
    match serde_json::from_slice::<SavedDns>(&data) {
        Ok(s)
            if s.version == SAVED_DNS_VERSION
                && s.services
                    .values()
                    .flatten()
                    .all(|ip| ip.parse::<std::net::IpAddr>().is_ok()) =>
        {
            SavedState::Present(s)
        }
        _ => SavedState::Corrupt,
    }
}

/// Atomically write the saved state (0644, so the uninstall script can read it).
pub fn write_saved(path: &Path, s: &SavedDns) -> Result<(), DnsError> {
    let bytes = serde_json::to_vec_pretty(s).map_err(|e| DnsError::Io(std::io::Error::other(e)))?;
    crate::fsutil::atomic_write(path, &bytes, 0o644)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// networksetup output parsing
// ---------------------------------------------------------------------------------------------

/// `networksetup -listallnetworkservices`: skip the header ("An asterisk (*) denotes that a network
/// service is disabled.") and disabled services (`*` prefix).
pub fn parse_services(out: &str) -> Vec<String> {
    out.lines()
        .filter(|l| !l.starts_with("An asterisk"))
        .map(|l| l.trim_end_matches(['\r', '\n']))
        .filter(|l| !l.trim().is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

/// `networksetup -getdnsservers <svc>`: one IP per line, or "There aren't any DNS Servers set on <svc>."
/// (= DHCP, empty list). Anything else (unknown service, error text) is an error.
pub fn parse_dns_servers(out: &str) -> Result<Vec<String>, String> {
    if out.contains("There aren't any DNS Servers set") {
        return Ok(Vec::new());
    }
    let mut v = Vec::new();
    for l in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match l.parse::<std::net::IpAddr>() {
            Ok(ip) => v.push(ip.to_string()),
            Err(_) => return Err(l.chars().take(200).collect()),
        }
    }
    if v.is_empty() {
        return Err("réponse vide".into());
    }
    Ok(v)
}

/// True when `current` is non-empty and made only of `ours` (the local proxy addresses).
pub fn is_ours(current: &[String], ours: &[String]) -> bool {
    !current.is_empty() && current.iter().all(|c| ours.iter().any(|o| o == c))
}

// ---------------------------------------------------------------------------------------------
// Backends
// ---------------------------------------------------------------------------------------------

/// In-memory network for unit tests.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct FakeNet {
    pub(crate) services: BTreeMap<String, Vec<String>>,
    pub(crate) set_calls: Vec<(String, Vec<String>)>,
    pub(crate) flushes: u32,
}

/// Where system DNS changes go.
#[derive(Debug, Clone)]
pub(crate) enum Backend {
    /// macOS `networksetup`.
    Mac,
    /// Non-macOS: no services, nothing changed (state files are still maintained).
    Noop,
    #[cfg(test)]
    Fake(std::sync::Arc<std::sync::Mutex<FakeNet>>),
}

async fn networksetup(args: &[&str]) -> Result<String, DnsError> {
    let out = crate::process::run(Path::new(NETWORKSETUP), args, Duration::from_secs(15)).await?;
    if out.code != Some(0) {
        return Err(DnsError::Command(format!(
            "networksetup {} : {}",
            args.first().unwrap_or(&""),
            out.text().trim()
        )));
    }
    Ok(out.text())
}

impl Backend {
    pub(crate) fn system() -> Self {
        if cfg!(target_os = "macos") {
            Backend::Mac
        } else {
            Backend::Noop
        }
    }

    pub(crate) async fn list_services(&self) -> Result<Vec<String>, DnsError> {
        match self {
            Backend::Mac => Ok(parse_services(&networksetup(&["-listallnetworkservices"]).await?)
                .into_iter()
                .filter(|s| {
                    // A service name starting with '-' could be taken for an option: leave it alone.
                    let ok = !s.starts_with('-');
                    if !ok {
                        tracing::warn!(service = %s, "network service name starts with '-', not managed");
                    }
                    ok
                })
                .collect()),
            Backend::Noop => Ok(Vec::new()),
            #[cfg(test)]
            Backend::Fake(f) => Ok(f.lock().unwrap().services.keys().cloned().collect()),
        }
    }

    pub(crate) async fn get_dns(&self, svc: &str) -> Result<Vec<String>, DnsError> {
        match self {
            Backend::Mac => parse_dns_servers(&networksetup(&["-getdnsservers", svc]).await?)
                .map_err(|e| DnsError::Command(format!("networksetup -getdnsservers {svc} : {e}"))),
            Backend::Noop => Ok(Vec::new()),
            #[cfg(test)]
            Backend::Fake(f) => f.lock().unwrap().services.get(svc).cloned().ok_or_else(|| {
                DnsError::Command(format!("{svc} is not a recognized network service"))
            }),
        }
    }

    /// Empty `servers` ⇒ `Empty` (back to DHCP).
    pub(crate) async fn set_dns(&self, svc: &str, servers: &[String]) -> Result<(), DnsError> {
        match self {
            Backend::Mac => {
                let mut args: Vec<&str> = vec!["-setdnsservers", svc];
                if servers.is_empty() {
                    args.push("Empty");
                } else {
                    args.extend(servers.iter().map(String::as_str));
                }
                networksetup(&args).await.map(|_| ())
            }
            Backend::Noop => Ok(()),
            #[cfg(test)]
            Backend::Fake(f) => {
                let mut f = f.lock().unwrap();
                f.set_calls.push((svc.to_string(), servers.to_vec()));
                match f.services.get_mut(svc) {
                    Some(v) => {
                        *v = servers.to_vec();
                        Ok(())
                    }
                    None => Err(DnsError::Command(format!(
                        "{svc} is not a recognized network service"
                    ))),
                }
            }
        }
    }

    /// Flush the resolver caches (`dscacheutil -flushcache`, `killall -HUP mDNSResponder`).
    pub(crate) async fn flush(&self) {
        match self {
            Backend::Mac => {
                for (bin, args) in [
                    (DSCACHEUTIL, &["-flushcache"][..]),
                    (KILLALL, &["-HUP", "mDNSResponder"][..]),
                ] {
                    if let Err(e) =
                        crate::process::run(Path::new(bin), args, Duration::from_secs(10)).await
                    {
                        tracing::warn!(error = %e, tool = bin, "DNS cache flush failed");
                    }
                }
            }
            Backend::Noop => {}
            #[cfg(test)]
            Backend::Fake(f) => f.lock().unwrap().flushes += 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_networksetup_fixtures() {
        let list = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Bluetooth PAN\nThunderbolt Bridge\nUSB 10/100/1000 LAN\n\n";
        assert_eq!(
            parse_services(list),
            vec!["Wi-Fi", "Thunderbolt Bridge", "USB 10/100/1000 LAN"]
        );
        assert_eq!(
            parse_dns_servers("There aren't any DNS Servers set on Wi-Fi.\n"),
            Ok(vec![])
        );
        assert_eq!(
            parse_dns_servers("192.168.1.1\n2001:db8::1\n"),
            Ok(vec!["192.168.1.1".into(), "2001:db8::1".into()])
        );
        assert!(parse_dns_servers(
            "Foo is not a recognized network service.\n** Error: The parameters were not valid.\n"
        )
        .is_err());
        assert!(parse_dns_servers("").is_err());
        let ours = vec!["127.0.0.1".to_string()];
        assert!(is_ours(&ours, &ours));
        assert!(!is_ours(&[], &ours));
        assert!(!is_ours(&["127.0.0.1".into(), "1.1.1.1".into()], &ours));
    }

    #[test]
    fn saved_file_format_and_corruption() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("saved-dns.json");
        assert_eq!(load_saved(&p), SavedState::Absent);
        let mut s = SavedDns::new();
        s.services
            .insert("Wi-Fi".into(), vec!["192.168.1.1".into()]);
        s.services.insert("Ethernet".into(), vec![]);
        write_saved(&p, &s).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap();
        assert_eq!(v["version"], 1);
        assert!(v["saved_at"].is_i64());
        assert_eq!(v["services"]["Wi-Fi"][0], "192.168.1.1");
        assert_eq!(v["services"]["Ethernet"], serde_json::json!([]));
        assert_eq!(load_saved(&p), SavedState::Present(s));
        std::fs::write(&p, b"{not json").unwrap();
        assert_eq!(load_saved(&p), SavedState::Corrupt);
        std::fs::write(
            &p,
            br#"{"version":1,"saved_at":1,"services":{"Wi-Fi":["; rm -rf /"]}}"#,
        )
        .unwrap();
        assert_eq!(load_saved(&p), SavedState::Corrupt);
    }
}
