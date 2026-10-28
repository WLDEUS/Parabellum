//! Threat-database bundle manifest — the contract between the nightly pipeline (Python, `pipeline/`)
//! and the client (`pb-updater`, `pb-engine`). Full layout in `docs/db-bundle.md`.
//!
//! Bundle = `parabellum-db.tar.gz` containing at its root:
//! ```text
//! manifest.json                       this struct
//! hashes/malware.sha256               sorted, deduplicated raw 32-byte SHA-256 digests (binary, no separators)
//! hashes/malware_names.tsv            "<sha256 hex>\t<family/signature name>" for the subset that has a name (optional),
//!                                     sorted by lowercase hex hash (the engine binary-searches it)
//! hashes/allow.sha256                 sorted raw 32-byte digests of known-good files (FP exclusions)
//! yara/*.yar                          rule sources, already validated by the pipeline with yara-x
//! clamav/parabellum.hsb               extra ClamAV hash sigs (`sha256:size:name:73` lines; size may be `*`)
//! dns/malware.txt                     malware / phishing domains (URLhaus, ThreatFox, Hagezi TIF…)
//! dns/ads.txt                         advertising domains (Hagezi Pro, OISD…)
//! dns/trackers.txt                    tracking / telemetry domains (Hagezi native trackers, EasyPrivacy-derived…)
//!                                     (each: one lowercase domain per line, no wildcards; a domain also blocks its
//!                                     subdomains; all three optional; selected by `dns.block_*` config flags)
//! dns/allowlist.txt                   never blocked (wins over every list)
//! allow/team_ids.txt                  trusted Apple Developer Team IDs, one per line, `#` comments
//! ml/macho_model.json                 LightGBM model dump (see pb-ml), optional
//! ml/model_meta.json                  {"features_version":N,"threshold":f,"version":"YYYY.MM.DD","metrics":{...}}, optional
//!                                     (`version` optional: defaults to a short SHA-256 of the model file)
//! osquery/hunting.json                osquery pack (`{"queries":{name:{query,interval,description}}}`), optional
//! zbt/zero-breach-toolkit.py          Zero Breach Toolkit single-file scanner (Apache-2.0), optional. The pipeline
//!                                     only ships it after `gpg --verify` of the release's `SHA256SUMS.txt.asc` with
//!                                     the pinned publisher key [`ZBT_SIGNER_FINGERPRINT`] and a SHA-256 match; the
//!                                     daemon runs it with `/usr/bin/python3 -I` as the console user, never as root
//! zbt/indicators/*                    its indicator cache (`manifest.json` + published sets fetched by
//!                                     `--update` at the release-pinned commits), flat directory, optional
//! zbt/meta.json                       {"version":"0.1.9","sha256":"<script hex>","indicators_updated_at":<unix>,
//!                                     "signer_fingerprint":"C24E…A53C"}
//! ```
//! `.minisig` (minisign, Ed25519) signs the `.tar.gz`; the client verifies it with the public key
//! compiled into the binary *before* unpacking, then checks every `files` digest.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Bump when the layout changes incompatibly.
pub const DB_FORMAT: u32 = 1;
pub const BUNDLE_FILE: &str = "parabellum-db.tar.gz";
pub const SIGNATURE_FILE: &str = "parabellum-db.tar.gz.minisig";
pub const MANIFEST_FILE: &str = "manifest.json";
/// Zero Breach Toolkit files inside the bundle (see the layout above).
pub const ZBT_SCRIPT: &str = "zbt/zero-breach-toolkit.py";
pub const ZBT_META: &str = "zbt/meta.json";
pub const ZBT_INDICATORS_DIR: &str = "zbt/indicators";
/// Full fingerprint of the Ed25519 key that signs Zero Breach Toolkit releases (docs/VERIFYING.md upstream).
pub const ZBT_SIGNER_FINGERPRINT: &str = "C24EC92B12D6670A2516065F9B4D575499AFA53C";

/// `zbt/meta.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ZbtMeta {
    pub version: String,
    /// Lowercase hex SHA-256 of `zbt/zero-breach-toolkit.py`.
    pub sha256: String,
    /// Unix time of the last successful `--update` of the indicators (0 = unknown).
    pub indicators_updated_at: i64,
    pub signer_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DbManifest {
    pub format: u32,
    /// `YYYY.MM.DD.N`
    pub version: String,
    pub built_at: i64,
    /// Oldest client version able to read this bundle (semver).
    pub min_client_version: String,
    pub sources: Vec<DbSource>,
    /// Relative path -> lowercase hex SHA-256 of the file content.
    pub files: BTreeMap<String, String>,
    pub stats: DbStats,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DbSource {
    pub name: String,
    /// "hashes", "yara", "domains", "clamav", "ml", "allowlist", "spyware"
    pub kind: String,
    pub url: String,
    pub license: String,
    pub count: u64,
    pub fetched_at: i64,
    /// False when the fetch failed and the previous data was carried over.
    #[serde(default = "default_true")]
    pub fresh: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DbStats {
    pub malware_hashes: u64,
    pub allow_hashes: u64,
    pub yara_rules: u64,
    pub yara_rules_rejected_fp: u64,
    pub blocked_domains: u64,
    pub clamav_sigs: u64,
    pub ml_model_version: Option<String>,
    /// Detection rate on the recent macOS malware corpus (0..1), when measured.
    pub detection_rate: Option<f64>,
    /// False-positive rate on the clean corpus (0..1), when measured.
    pub fp_rate: Option<f64>,
}

impl DbManifest {
    /// Basic sanity checks done by the client after signature verification.
    pub fn validate(&self) -> Result<(), String> {
        if self.format != DB_FORMAT {
            return Err(format!("unsupported db format {}", self.format));
        }
        if self.version.is_empty() || self.version.contains('/') || self.version.contains("..") {
            return Err("invalid db version string".into());
        }
        for (path, digest) in &self.files {
            if path.starts_with('/') || path.split('/').any(|c| c == ".." || c.is_empty()) {
                return Err(format!("invalid path in manifest: {path}"));
            }
            if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("invalid digest for {path}"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> DbManifest {
        DbManifest {
            format: DB_FORMAT,
            version: "2026.10.25.1".into(),
            built_at: 0,
            min_client_version: "0.1.0".into(),
            sources: vec![],
            files: BTreeMap::from([("dns/blocklist.txt".to_string(), "a".repeat(64))]),
            stats: DbStats::default(),
        }
    }

    #[test]
    fn validates() {
        assert!(manifest().validate().is_ok());
        let mut m = manifest();
        m.files.insert("../etc/passwd".into(), "a".repeat(64));
        assert!(m.validate().is_err());
        let mut m = manifest();
        m.version = "../x".into();
        assert!(m.validate().is_err());
    }
}
