//! Blocklist / allowlist normalization and merging into dnscrypt-proxy name files.
//!
//! dnscrypt-proxy pattern semantics (checked in `dnscrypt-proxy/pattern_matcher.go` and
//! `example-blocked-names.txt`, master, 2026-10-25): a plain `example.com` (or `*.example.com`) is a
//! *suffix* rule matching `example.com` **and** every name under it, at a label boundary; `=example.com`
//! matches only `example.com`. Allowlist files use the same patterns and win over blocklists.
//!
//! Parabellum semantics (same as the bundle contract in `pb_core::db`):
//! - list entry `foo.com` (or `*.foo.com`, `||foo.com^`, `0.0.0.0 foo.com`) blocks `foo.com` and its subdomains;
//! - `=foo.com` (custom lists) is exact;
//! - **an allowlist entry `foo.com` allows `foo.com` and all its subdomains**, `=foo.com` only `foo.com`;
//!   allow always wins over block.
//!
//! Output is minimized: blocked names already covered by a blocked parent are dropped, blocked names
//! covered by an allow rule are dropped, and only allow rules that carve an exception out of a blocked
//! parent are written to `allowed-names.txt`.

use std::collections::HashSet;
use std::io::{BufRead, Read};
use std::path::Path;

/// Max bytes read from one source list.
pub const MAX_LIST_BYTES: u64 = 256 * 1024 * 1024;
/// Max accepted entries (all sources together).
pub const MAX_ENTRIES: usize = 4_000_000;
const MAX_LINE: usize = 2048;

/// One normalized rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Rule {
    /// Domain and all its subdomains.
    Suffix(String),
    /// Exactly this name.
    Exact(String),
}

const RESERVED: [&str; 6] = [
    "localhost.localdomain",
    "local.localdomain",
    "ip6-localhost.localdomain",
    "broadcasthost.localdomain",
    "localhost.local",
    "0.0.0.0",
];

/// Validate and normalize a domain name (lowercase, no trailing dot, ASCII only — IDNs must already be
/// punycode `xn--`, LDH + `_` labels, 1..=63 chars per label, <= 253 total, at least two labels, not an
/// IPv4 address).
pub fn normalize_domain(raw: &str) -> Option<String> {
    let d = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if d.is_empty() || d.len() > 253 || !d.is_ascii() {
        return None;
    }
    let labels: Vec<&str> = d.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') {
            return None;
        }
        if !l
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
    }
    if labels.iter().all(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return None; // IPv4 literal
    }
    if RESERVED.contains(&d.as_str()) {
        return None;
    }
    Some(d)
}

fn is_ip_token(t: &str) -> bool {
    t.parse::<std::net::IpAddr>().is_ok() || t == "0"
}

/// Strip a `#` comment (only when `#` starts the line or follows whitespace). Returns `None` if a `#`
/// appears inside a token (adblock cosmetic rules like `site.com##.ad`), which must not be read as a domain.
fn strip_comment(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut cut = line.len();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'#' {
            if i == 0 || bytes[i - 1].is_ascii_whitespace() {
                cut = i;
                break;
            }
            return None;
        }
    }
    Some(&line[..cut])
}

/// Parse one line of a list (plain domains, hosts format, `||domain^` adblock syntax, `=exact`, `*.suffix`),
/// calling `f` for every rule found. Comments (`#`, `!`), headers (`[Adblock Plus]`), exceptions (`@@`),
/// cosmetic and modifier rules are ignored.
pub fn parse_line(line: &str, mut f: impl FnMut(Rule)) {
    if line.len() > MAX_LINE {
        return;
    }
    let t = line.trim_start_matches('\u{feff}').trim();
    if t.is_empty() || t.starts_with('!') || t.starts_with('[') || t.starts_with("@@") {
        return;
    }
    let Some(t) = strip_comment(t) else { return };
    let t = t.trim();
    if t.is_empty() {
        return;
    }
    // Adblock network rule `||domain^` (optionally `$important`).
    if let Some(rest) = t.strip_prefix("||") {
        let body = match rest.split_once('$') {
            Some((b, "important")) => b,
            Some(_) => return,
            None => rest,
        };
        if let Some(d) = body.strip_suffix('^').and_then(normalize_domain) {
            f(Rule::Suffix(d));
        }
        return;
    }
    let tokens: Vec<&str> = t.split_whitespace().collect();
    match tokens.as_slice() {
        [single] => {
            if let Some(r) = parse_pattern(single) {
                f(r);
            }
        }
        [ip, names @ ..] if is_ip_token(ip) => {
            for n in names {
                if let Some(d) = normalize_domain(n) {
                    if d != "localhost" {
                        f(Rule::Suffix(d));
                    }
                }
            }
        }
        _ => {}
    }
}

/// `=exact`, `*.suffix`, `.suffix` or a plain domain.
fn parse_pattern(p: &str) -> Option<Rule> {
    if let Some(e) = p.strip_prefix('=') {
        return normalize_domain(e).map(Rule::Exact);
    }
    let s = p
        .strip_prefix("*.")
        .or_else(|| p.strip_prefix('.'))
        .unwrap_or(p);
    normalize_domain(s).map(Rule::Suffix)
}

/// Strict ancestors of a domain: `a.b.c` → `b.c`, `c`.
fn ancestors(d: &str) -> impl Iterator<Item = &str> {
    d.char_indices()
        .filter(|(_, c)| *c == '.')
        .map(move |(i, _)| &d[i + 1..])
}

/// Accumulates rules and produces the minimized output.
#[derive(Debug, Default)]
pub struct ListBuilder {
    block_suffix: HashSet<Box<str>>,
    block_exact: HashSet<Box<str>>,
    allow_suffix: HashSet<Box<str>>,
    allow_exact: HashSet<Box<str>>,
    total: usize,
    truncated: bool,
}

/// Lines for `blocked-names.txt` / `allowed-names.txt` (sorted, without header).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergedLists {
    pub blocked: Vec<String>,
    pub allowed: Vec<String>,
}

impl ListBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// True when [`MAX_ENTRIES`] was hit and further rules were dropped.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    fn room(&mut self) -> bool {
        if self.total >= MAX_ENTRIES {
            self.truncated = true;
            return false;
        }
        self.total += 1;
        true
    }

    pub fn add_block(&mut self, r: Rule) {
        if !self.room() {
            return;
        }
        match r {
            Rule::Suffix(d) => self.block_suffix.insert(d.into_boxed_str()),
            Rule::Exact(d) => self.block_exact.insert(d.into_boxed_str()),
        };
    }

    pub fn add_allow(&mut self, r: Rule) {
        if !self.room() {
            return;
        }
        match r {
            Rule::Suffix(d) => self.allow_suffix.insert(d.into_boxed_str()),
            Rule::Exact(d) => self.allow_exact.insert(d.into_boxed_str()),
        };
    }

    /// Add every rule of a text (custom entries, one per item).
    pub fn add_entries(&mut self, entries: &[String], allow: bool) {
        for e in entries {
            parse_line(e, |r| {
                if allow {
                    self.add_allow(r)
                } else {
                    self.add_block(r)
                }
            });
        }
    }

    /// Stream a list file (bounded). Missing file ⇒ `Ok(false)`.
    pub fn add_file(&mut self, path: &Path, allow: bool) -> std::io::Result<bool> {
        let f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e),
        };
        if !f.metadata()?.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        let mut reader = std::io::BufReader::with_capacity(256 * 1024, f.take(MAX_LIST_BYTES));
        let mut buf = Vec::with_capacity(256);
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            if buf.len() > MAX_LINE {
                continue;
            }
            if let Ok(line) = std::str::from_utf8(&buf) {
                parse_line(line, |r| {
                    if allow {
                        self.add_allow(r)
                    } else {
                        self.add_block(r)
                    }
                });
            }
        }
        Ok(true)
    }

    fn covered_by_allow(&self, d: &str) -> bool {
        self.allow_suffix.contains(d) || ancestors(d).any(|a| self.allow_suffix.contains(a))
    }

    /// Apply allowlist precedence and parent de-duplication.
    pub fn finish(self) -> MergedLists {
        let kept_suffix: HashSet<&str> = self
            .block_suffix
            .iter()
            .map(|d| &**d)
            .filter(|d| !self.covered_by_allow(d))
            .collect();
        let suffix_covers = |d: &str, include_self: bool| -> bool {
            (include_self && kept_suffix.contains(d))
                || ancestors(d).any(|a| kept_suffix.contains(a))
        };
        let mut blocked: Vec<String> = kept_suffix
            .iter()
            .filter(|d| !suffix_covers(d, false))
            .map(|d| d.to_string())
            .collect();
        blocked.extend(
            self.block_exact
                .iter()
                .map(|d| &**d)
                .filter(|d| {
                    !self.covered_by_allow(d)
                        && !self.allow_exact.contains(*d)
                        && !suffix_covers(d, true)
                })
                .map(|d| format!("={d}")),
        );
        let mut allowed: Vec<String> = self
            .allow_suffix
            .iter()
            .map(|d| &**d)
            .filter(|d| suffix_covers(d, false))
            .map(str::to_string)
            .collect();
        allowed.extend(
            self.allow_exact
                .iter()
                .map(|d| &**d)
                .filter(|d| !self.covered_by_allow(d) && suffix_covers(d, true))
                .map(|d| format!("={d}")),
        );
        blocked.sort_unstable();
        allowed.sort_unstable();
        MergedLists { blocked, allowed }
    }
}

/// Render a name file (header + one pattern per line).
pub fn render_name_file(kind: &str, lines: &[String]) -> String {
    let mut out = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum::<usize>() + 128);
    out.push_str(
        "# Généré par Parabellum (pb-dns) — ne pas modifier, réécrit à chaque mise à jour\n",
    );
    out.push_str(&format!("# {kind} : {} entrées\n", lines.len()));
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(line: &str) -> Vec<Rule> {
        let mut v = Vec::new();
        parse_line(line, |r| v.push(r));
        v
    }

    #[test]
    fn normalizes_formats() {
        let s = |d: &str| Rule::Suffix(d.to_string());
        assert_eq!(rules("Ads.Example.COM."), vec![s("ads.example.com")]);
        assert_eq!(
            rules("0.0.0.0 tracker.example.net # comment"),
            vec![s("tracker.example.net")]
        );
        assert_eq!(
            rules("127.0.0.1 a.example.org b.example.org"),
            vec![s("a.example.org"), s("b.example.org")]
        );
        assert_eq!(rules("::1 v6.example.org"), vec![s("v6.example.org")]);
        assert_eq!(rules("||ads.example.com^"), vec![s("ads.example.com")]);
        assert_eq!(
            rules("||ads.example.com^$important"),
            vec![s("ads.example.com")]
        );
        assert!(rules("||ads.example.com^$third-party").is_empty());
        assert!(rules("@@||good.example.com^").is_empty());
        assert!(
            rules("example.com##.banner").is_empty(),
            "cosmetic rule must not block the site"
        );
        assert!(rules("! Title: list").is_empty());
        assert!(rules("[Adblock Plus 2.0]").is_empty());
        assert!(rules("# comment").is_empty());
        assert_eq!(rules("*.example.com"), vec![s("example.com")]);
        assert_eq!(
            rules("=exact.example.com"),
            vec![Rule::Exact("exact.example.com".into())]
        );
        assert!(rules("0.0.0.0 localhost").is_empty());
        assert!(rules("127.0.0.1 localhost.localdomain").is_empty());
        assert!(rules("com").is_empty(), "single label refused");
        assert!(rules("192.168.1.1").is_empty());
        assert!(rules("exämple.com").is_empty(), "IDN must be punycode");
        assert_eq!(rules("xn--exmple-cua.com"), vec![s("xn--exmple-cua.com")]);
        assert!(rules("-bad.example.com").is_empty());
        assert!(rules("ads*.example.com").is_empty());
        assert!(rules("a b c").is_empty());
        assert_eq!(rules("_dmarc.example.com"), vec![s("_dmarc.example.com")]);
        assert!(rules(&format!("{}.com", "a".repeat(64))).is_empty());
    }

    #[test]
    fn merges_with_allowlist_precedence_and_parent_dedupe() {
        let mut b = ListBuilder::new();
        for l in [
            "ads.com",
            "x.ads.com",
            "y.z.ads.com",
            "tracker.net",
            "evil.org",
            "sub.good.org",
            "keep.example.com",
        ] {
            parse_line(l, |r| b.add_block(r));
        }
        b.add_entries(
            &[
                "=exact.blocked.io".into(),
                "=x.ads.com".into(),
                "custom.io".into(),
            ],
            false,
        );
        // allow: carve an exception under a blocked parent, a full allow, and an exact allow.
        for l in ["fine.ads.com", "good.org", "evil.org"] {
            parse_line(l, |r| b.add_allow(r));
        }
        b.add_entries(&["=custom.io".into(), "unrelated.example".into()], true);
        let m = b.finish();
        assert_eq!(
            m.blocked,
            vec![
                "=exact.blocked.io",
                "ads.com",
                "custom.io",
                "keep.example.com",
                "tracker.net"
            ],
            "subdomains of ads.com dropped, evil.org and sub.good.org allowed"
        );
        // Only exceptions under a blocked parent are written.
        assert_eq!(m.allowed, vec!["=custom.io", "fine.ads.com"]);
    }

    #[test]
    fn reads_files_bounded() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ads.txt");
        std::fs::write(&p, "# header\nads.example.com\n\n0.0.0.0 t.example.com\r\n").unwrap();
        let mut b = ListBuilder::new();
        assert!(b.add_file(&p, false).unwrap());
        assert!(!b.add_file(&d.path().join("missing.txt"), false).unwrap());
        assert!(b.add_file(d.path(), false).is_err());
        assert_eq!(b.finish().blocked, vec!["ads.example.com", "t.example.com"]);
        let r = render_name_file("bloqués", &["a.com".into()]);
        assert!(r.ends_with("a.com\n") && r.starts_with('#'));
    }
}
