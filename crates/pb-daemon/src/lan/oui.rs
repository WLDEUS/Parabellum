//! MAC vendor lookup in the IEEE prefix list shipped with the threat DB (`lan/oui.tsv`), and private
//! (locally administered) addresses.
//!
//! The file is only streamed for the MAC addresses of one scan (nothing stays in memory between scans).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// Larger files are refused (the IEEE MA-L + MA-M + MA-S lists take about 2 MB).
pub const MAX_OUI_FILE: u64 = 16 * 1024 * 1024;

/// Locally administered address (bit 1 of the first byte): iOS / Android / macOS / Windows "private"
/// Wi-Fi addresses, virtual machines, some docks. No vendor can be derived from it.
pub fn is_private_mac(mac: &str) -> bool {
    mac.get(..2)
        .and_then(|b| u8::from_str_radix(b, 16).ok())
        .is_some_and(|b| b & 0x02 != 0)
}

/// `aa:bb:cc:dd:ee:ff` -> `AABBCCDDEEFF`.
fn hex12(mac: &str) -> Option<String> {
    let h: String = mac.chars().filter(|c| *c != ':').collect();
    (h.len() == 12 && h.bytes().all(|b| b.is_ascii_hexdigit())).then(|| h.to_ascii_uppercase())
}

/// Vendors of `macs` (lowercase `aa:bb:…`) from a `<prefix>\t<vendor>` stream: longest prefix wins
/// (MA-S 9 digits > MA-M 7 > MA-L 6). Private addresses are never looked up.
pub fn lookup_in<R: Read>(reader: R, macs: &[String]) -> HashMap<String, String> {
    // prefix -> macs that start with it
    let mut wanted: HashMap<String, Vec<&str>> = HashMap::new();
    for m in macs.iter().filter(|m| !is_private_mac(m)) {
        if let Some(h) = hex12(m) {
            for n in [6, 7, 9] {
                wanted.entry(h[..n].to_string()).or_default().push(m);
            }
        }
    }
    let mut best: HashMap<String, (usize, String)> = HashMap::new();
    if wanted.is_empty() {
        return HashMap::new();
    }
    let reader = BufReader::new(reader.take(MAX_OUI_FILE));
    for line in reader.lines() {
        let Ok(line) = line else { break };
        let Some((prefix, vendor)) = line.split_once('\t') else {
            continue;
        };
        let Some(list) = wanted.get(prefix) else {
            continue;
        };
        let vendor: String = vendor
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(80)
            .collect();
        if vendor.is_empty() {
            continue;
        }
        for m in list {
            let better = best.get(*m).is_none_or(|(len, _)| prefix.len() > *len);
            if better {
                best.insert((*m).to_string(), (prefix.len(), vendor.clone()));
            }
        }
    }
    best.into_iter().map(|(k, (_, v))| (k, v)).collect()
}

/// [`lookup_in`] on the bundle file (root-owned DB directory). Missing / unreadable file: no vendors.
pub fn lookup(path: &Path, macs: &[String]) -> HashMap<String, String> {
    match std::fs::File::open(path) {
        Ok(f)
            if f.metadata()
                .map(|m| m.is_file() && m.len() <= MAX_OUI_FILE)
                .unwrap_or(false) =>
        {
            lookup_in(f, macs)
        }
        Ok(_) => {
            tracing::warn!(path = %path.display(), "OUI list ignored (not a regular file or too large)");
            HashMap::new()
        }
        Err(e) => {
            tracing::debug!(error = %e, "no OUI list in the threat DB yet");
            HashMap::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OUI: &str = "001B63\tApple, Inc.\n0024D4\tFreebox SAS\n3C22FB\tApple, Inc.\n70B3D5\tIEEE Registration Authority\n70B3D51\tTiny Vendor (MA-M)\n70B3D5123\tTinier Vendor (MA-S)\n90DD5D\tApple, Inc.\nF01898\tApple, Inc.\n";

    #[test]
    fn private_bit() {
        assert!(is_private_mac("3a:5f:12:9c:7e:01"));
        assert!(is_private_mac("de:ad:be:ef:00:01"));
        assert!(!is_private_mac("3c:22:fb:01:02:03"));
        assert!(!is_private_mac("00:24:d4:a1:b2:c3"));
    }

    #[test]
    fn longest_prefix_wins() {
        let macs: Vec<String> = [
            "00:24:d4:a1:b2:c3",
            "70:b3:d5:12:3f:00",
            "70:b3:d5:1a:00:00",
            "70:b3:d5:ff:00:00",
            "3a:5f:12:9c:7e:01",
            "12:34:56:78:9a:bc",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let v = lookup_in(OUI.as_bytes(), &macs);
        assert_eq!(v["00:24:d4:a1:b2:c3"], "Freebox SAS");
        assert_eq!(v["70:b3:d5:12:3f:00"], "Tinier Vendor (MA-S)");
        assert_eq!(v["70:b3:d5:1a:00:00"], "Tiny Vendor (MA-M)");
        assert_eq!(v["70:b3:d5:ff:00:00"], "IEEE Registration Authority");
        assert!(!v.contains_key("3a:5f:12:9c:7e:01"));
        assert_eq!(v.len(), 4);
        assert!(lookup(Path::new("/nonexistent/oui.tsv"), &macs).is_empty());
    }
}
