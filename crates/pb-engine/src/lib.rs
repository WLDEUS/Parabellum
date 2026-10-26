//! Parabellum scanning engine.
//!
//! The engine does not implement detection logic itself; it orchestrates:
//! * the threat-DB **hash sets** (memory-mapped, binary search) and the local allowlist,
//! * **YARA-X** (built-in rules + bundle rules, compiled once and cached),
//! * **ClamAV** (`clamscan`, batched, on-demand only — no resident `clamd`),
//! * the **ML** Mach-O classifier (`pb-ml`, suspicious-only),
//! * **containers**: ZIP / tar / gzip in memory with zip-bomb limits; DMG (`hdiutil`, read-only
//!   mount) and PKG (`pkgutil --expand-full`) on macOS,
//! * Apple **code signing** (`codesign` / `spctl`, macOS),
//! * a reversible **quarantine** ([`quarantine::Quarantine`]).
//!
//! Scoring rules are documented in [`scoring`]. Everything is synchronous: the daemon calls the
//! engine from `spawn_blocking`. An [`Engine`] is immutable after [`Engine::load`] (except the local
//! allowlist and its caches); on a DB update the daemon builds a new one and swaps it.
//!
//! Report paths of container members are `<container path>!/<inner path>`; member verdicts roll up
//! into their container (so the container — the only thing that exists on disk — carries the
//! verdict the daemon acts on). `ScanTotals::threats` counts on-disk items only.

pub mod filetype;
pub mod quarantine;
pub mod scoring;

mod cache;
mod clamav;
mod containers;
mod hashdb;
mod proc;
mod safefs;
mod signing;
mod yara;

pub use clamav::parse_output as parse_clamscan_output;
pub use pb_core::model::{
    Detection, DetectionEngine, FileKind, QuarantineEntry, ScanReport, Severity, SigningInfo,
    Verdict,
};
pub use quarantine::{normalize_path, Quarantine, QuarantineError, QuarantinePolicy};

use cache::TwoGenCache;
use hashdb::{DigestSet, NameIndex};
use pb_core::config::Config;
use pb_core::paths::Paths;
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Read;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Instant;

/// Files up to this size are read once into memory (hash + YARA + ML on the same buffer); larger
/// files (up to `max_file_size`) are hashed in a stream and only their first `IN_MEMORY_LIMIT` bytes
/// are content-scanned (ClamAV, when enabled, still sees the whole file).
pub const IN_MEMORY_LIMIT: u64 = 64 * 1024 * 1024;
const SCAN_CACHE_CAPACITY: usize = 20_000;
const SIGN_CACHE_CAPACITY: usize = 4_096;
const HASH_BUF: usize = 1024 * 1024;
const MAX_ROLLUP_DETECTIONS: usize = 20;
const MIB: u64 = 1024 * 1024;

/// Options of one scan request.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanOptions {
    /// Run ClamAV (`clamscan`, batched) on on-disk files.
    pub use_clamav: bool,
    /// Run the ML classifier on Mach-O files.
    pub use_ml: bool,
    /// Always attach Apple code-signing info to Mach-O reports (otherwise computed only when a
    /// decision needs it). macOS only.
    pub compute_signing: bool,
    /// Descend into directories.
    pub recursive: bool,
    /// Follow symbolic links (files and directories).
    pub follow_symlinks: bool,
    /// Files larger than this are hashed and hash-checked only.
    pub max_file_size: u64,
    /// Nested container depth.
    pub archive_max_depth: u32,
    /// Max uncompressed bytes extracted from one top-level container (all nesting levels).
    pub archive_max_total: u64,
    /// Max entries inspected in one top-level container (all nesting levels).
    pub archive_max_entries: u32,
    /// Mount DMGs read-only and scan their content (macOS).
    pub mount_dmg: bool,
    /// Expand PKGs and scan scripts + payload (macOS).
    pub expand_pkg: bool,
    /// Never scanned (component-wise prefix match).
    pub exclude_prefixes: Vec<PathBuf>,
    /// `scan_paths` only: skip (without hashing or counting) regular files whose type is not
    /// executable / script / container / app-related, decided from path, mode and the first bytes
    /// ([`filetype::is_risky`]). For multi-TB volumes and retro-hunts.
    pub only_risky_types: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self::from_config(&Config::default(), false)
    }
}

impl ScanOptions {
    /// Options from the user configuration. `~` in `scan.exclude_paths` is not expanded (use
    /// [`ScanOptions::from_config_for_user`]); such entries simply never match.
    pub fn from_config(cfg: &Config, use_clamav: bool) -> Self {
        Self {
            use_clamav,
            use_ml: cfg.ml.enabled,
            compute_signing: false,
            recursive: true,
            follow_symlinks: false,
            max_file_size: cfg.scan.max_file_size_mb.saturating_mul(MIB),
            archive_max_depth: cfg.scan.archive_max_depth,
            archive_max_total: cfg.scan.archive_max_total_mb.saturating_mul(MIB),
            archive_max_entries: cfg.scan.archive_max_entries,
            mount_dmg: cfg.scan.mount_dmg,
            expand_pkg: cfg.scan.expand_pkg,
            exclude_prefixes: cfg.scan.exclude_paths.iter().map(PathBuf::from).collect(),
            only_risky_types: false,
        }
    }

    /// Like [`ScanOptions::from_config`], expanding `~` in exclusions with the console user's home.
    pub fn from_config_for_user(cfg: &Config, use_clamav: bool, home: &Path) -> Self {
        let mut o = Self::from_config(cfg, use_clamav);
        o.exclude_prefixes = cfg
            .scan
            .exclude_paths
            .iter()
            .map(|p| pb_core::expand_user_path(p, home))
            .collect();
        o
    }

    /// Fingerprint of everything that changes a report (part of the scan-cache key).
    fn fingerprint(&self) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (
            self.use_clamav,
            self.use_ml,
            self.compute_signing,
            self.max_file_size,
            self.archive_max_depth,
            self.archive_max_total,
            self.archive_max_entries,
            self.mount_dmg,
            self.expand_pkg,
        )
            .hash(&mut h);
        h.finish()
    }
}

/// What the engine has loaded (shown in the status / components views).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct EngineStats {
    pub db_version: Option<String>,
    pub malware_hashes: u64,
    pub allow_hashes: u64,
    /// Compiled YARA rules, built-in rules included.
    pub yara_rules: u64,
    pub ml_model_version: Option<String>,
    pub clamav_available: bool,
    pub clamav_version: Option<String>,
    /// Non-fatal problems found while loading (rejected YARA files, corrupt hash file…).
    pub warnings: Vec<String>,
}

/// Counters of a `scan_paths` call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ScanTotals {
    /// Reports emitted (container members included).
    pub files: u64,
    pub bytes: u64,
    /// On-disk items with verdict != clean (members roll up into their container).
    pub threats: u64,
    /// Reports carrying an `error`.
    pub errors: u64,
    pub cancelled: bool,
}

/// Fatal engine errors.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("yara: {0}")]
    Yara(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Scan-cache key: identity + change markers of the file, and the options fingerprint. The DB
/// version is implicit: the cache lives in the `Engine`, which is rebuilt on every DB update.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
    opts: u64,
}

impl CacheKey {
    fn new(m: &std::fs::Metadata, opts: u64) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.len(),
            mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            ctime_ns: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
            opts,
        }
    }
}

/// The scanning engine. `Send + Sync`; share it behind an `Arc`.
pub struct Engine {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    paths: Paths,
    db_version: Option<String>,
    malware: DigestSet,
    allow: DigestSet,
    names: NameIndex,
    team_ids: HashSet<String>,
    yara: yara::YaraRules,
    ml: Option<pb_ml::MlModel>,
    ml_threshold: f32,
    ml_only_untrusted: bool,
    clamav: Option<clamav::ClamAv>,
    internal_excludes: Vec<PathBuf>,
    warnings: Vec<String>,
    local_allow: RwLock<HashSet<hashdb::Digest>>,
    sign_cache: Mutex<TwoGenCache<hashdb::Digest, Option<SigningInfo>>>,
    scan_cache: Mutex<TwoGenCache<CacheKey, ScanReport>>,
}

/// Per-call scanning context.
pub(crate) struct Ctx<'e> {
    pub opts: &'e ScanOptions,
    pub cancel: &'e AtomicBool,
    pub yara: yara_x::Scanner<'e>,
    pub fingerprint: u64,
}

impl Ctx<'_> {
    pub(crate) fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

/// Top-level analyses waiting for their ClamAV batch.
#[derive(Default)]
struct ClamBatch {
    items: Vec<Analysis>,
    paths: Vec<PathBuf>,
    arg_bytes: usize,
}

/// Shared extraction budget of one top-level container (all nesting levels).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Budget {
    pub bytes: u64,
    pub entries: u32,
}

impl Budget {
    fn for_opts(o: &ScanOptions) -> Self {
        Self {
            bytes: o.archive_max_total,
            entries: o.archive_max_entries,
        }
    }
    /// Consumes one entry; false when exhausted.
    pub(crate) fn take_entry(&mut self) -> bool {
        if self.entries == 0 {
            return false;
        }
        self.entries -= 1;
        true
    }
    pub(crate) fn take_bytes(&mut self, n: u64) {
        self.bytes = self.bytes.saturating_sub(n);
    }
}

/// Member results folded into a container.
#[derive(Debug, Default, Clone)]
pub(crate) struct Rollup {
    pub verdict: Verdict,
    pub score: f32,
    pub detections: Vec<Detection>,
}

impl Rollup {
    /// Adds a member report; `container` is the display path of the container.
    pub(crate) fn add(&mut self, member: &ScanReport, container: &str) {
        if member.verdict == Verdict::Clean {
            return;
        }
        self.verdict = self.verdict.max(member.verdict);
        self.score = self.score.max(member.score);
        let inner = member
            .path
            .strip_prefix(container)
            .and_then(|s| s.strip_prefix("!/"))
            .unwrap_or(&member.path);
        for d in &member.detections {
            if self.detections.len() >= MAX_ROLLUP_DETECTIONS {
                break;
            }
            let mut d = d.clone();
            d.details = Some(match d.details {
                Some(x) => format!("in {inner}: {x}"),
                None => format!("in {inner}"),
            });
            self.detections.push(d);
        }
    }
}

/// In-progress analysis of one item.
pub(crate) struct Analysis {
    pub report: ScanReport,
    pub own: Vec<Detection>,
    pub members: Rollup,
    pub trusted: bool,
    pub allowlisted: bool,
    /// On-disk path eligible for ClamAV (top-level only).
    pub clamav_path: Option<PathBuf>,
    pub cache_key: Option<CacheKey>,
    started: Instant,
    notes: Vec<String>,
    /// Report is already final (scan-cache hit).
    done: bool,
}

impl Analysis {
    fn new(display: String) -> Self {
        Self {
            report: ScanReport {
                path: display,
                ..Default::default()
            },
            own: Vec::new(),
            members: Rollup::default(),
            trusted: false,
            allowlisted: false,
            clamav_path: None,
            cache_key: None,
            started: Instant::now(),
            notes: Vec::new(),
            done: false,
        }
    }

    pub(crate) fn note(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        if !self.notes.contains(&msg) {
            self.notes.push(msg);
        }
    }

    /// Recomputes verdict / score / detections / error / duration from the parts.
    pub(crate) fn finalize(&mut self) {
        if self.done {
            return;
        }
        if self.allowlisted {
            self.report.verdict = Verdict::Clean;
            self.report.score = 0.0;
            self.report.detections.clear();
        } else {
            let (v, s) = scoring::score(&self.own, self.trusted);
            self.report.verdict = v.max(self.members.verdict);
            self.report.score = s.max(self.members.score);
            self.report.detections = self
                .own
                .iter()
                .cloned()
                .chain(self.members.detections.iter().cloned())
                .collect();
        }
        self.report.error = (!self.notes.is_empty()).then(|| self.notes.join("; "));
        self.report.duration_ms = self.started.elapsed().as_millis() as u64;
    }
}

/// Facts about a buffer being analysed.
pub(crate) struct ContentInfo<'p> {
    /// Real on-disk path (top-level files, DMG/PKG members), for codesign and container tools.
    pub disk_path: Option<&'p Path>,
    /// SHA-256 of the whole content (`None` if it could not be computed, e.g. truncated member).
    pub digest: Option<hashdb::Digest>,
    /// Size of the whole content.
    pub size: u64,
    /// `data` is only a prefix of the content.
    pub truncated: bool,
    /// Content too large: hash checks only.
    pub hash_only: bool,
    /// Last bytes of the content (DMG trailer), when `data` does not end at EOF.
    pub tail: Option<Vec<u8>>,
}

fn read_team_ids(path: &Path) -> HashSet<String> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| signing::is_team_id(l))
        .map(str::to_owned)
        .collect()
}

/// Streaming SHA-256 of a file (1 MiB buffer), lowercase hex.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = filetype::open_nonblocking(path)?;
    if !f.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut h = Sha256::new();
    let mut buf = vec![0u8; HASH_BUF];
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Reads up to `keep` bytes into memory while hashing the first `size` bytes of `file`.
fn read_and_hash(
    file: &mut File,
    size: u64,
    keep: u64,
) -> std::io::Result<(hashdb::Digest, Vec<u8>)> {
    let mut h = Sha256::new();
    let keep = keep.min(size);
    let mut data = Vec::with_capacity(keep as usize);
    let mut limited = (&mut *file).take(size);
    (&mut limited).take(keep).read_to_end(&mut data)?;
    h.update(&data);
    let mut buf = vec![0u8; HASH_BUF];
    loop {
        let n = match limited.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
    }
    Ok((h.finalize().into(), data))
}

impl Engine {
    /// Loads the active DB bundle (`paths.db_current()`) and the tools. Always succeeds without a
    /// bundle (built-in rules only); what is missing is logged and listed in
    /// [`EngineStats::warnings`]. Only a failure to compile the built-in rules is an error.
    pub fn load(paths: &Paths, cfg: &Config) -> Result<Self, EngineError> {
        let mut warnings = Vec::new();
        let current = paths.db_current();
        let bundle = std::fs::canonicalize(&current).ok().filter(|p| p.is_dir());
        if bundle.is_none() {
            tracing::warn!(path = %current.display(), "no threat-DB bundle installed: built-in rules only");
            warnings.push("no threat database installed (built-in rules only)".to_string());
        }
        let db_version = bundle.as_ref().and_then(|b| {
            let manifest = b.join(pb_core::db::MANIFEST_FILE);
            match std::fs::read(&manifest).map_err(|e| e.to_string()).and_then(|bytes| {
                serde_json::from_slice::<pb_core::db::DbManifest>(&bytes).map_err(|e| e.to_string())
            }) {
                Ok(m) => Some(m.version),
                Err(e) => {
                    tracing::warn!(error = %e, "cannot read bundle manifest, using the directory name as version");
                    b.file_name().map(|n| n.to_string_lossy().into_owned())
                }
            }
        });

        let mut open_set = |rel: &str| -> DigestSet {
            let Some(b) = &bundle else {
                return DigestSet::default();
            };
            DigestSet::open(&b.join(rel)).unwrap_or_else(|e| {
                tracing::error!(error = %e, "hash database unusable");
                warnings.push(format!("hash database unusable: {e}"));
                DigestSet::default()
            })
        };
        let malware = open_set("hashes/malware.sha256");
        let allow = open_set("hashes/allow.sha256");
        let names = bundle
            .as_ref()
            .map(|b| NameIndex::open(&b.join("hashes/malware_names.tsv")).unwrap_or_default())
            .unwrap_or_default();
        let team_ids = bundle
            .as_ref()
            .map(|b| read_team_ids(&b.join("allow/team_ids.txt")))
            .unwrap_or_default();

        let cache_dir = paths.cache_dir();
        let cache_dir = std::fs::create_dir_all(&cache_dir)
            .is_ok()
            .then_some(cache_dir);
        let yara_dir = bundle.as_ref().map(|b| b.join("yara"));
        let yara = yara::load(
            yara_dir.as_deref(),
            cache_dir.as_deref(),
            db_version.as_deref(),
        )
        .map_err(EngineError::Yara)?;
        for s in &yara.skipped {
            warnings.push(format!("YARA file rejected: {s}"));
        }

        let ml = match bundle.as_ref().map(|b| pb_ml::MlModel::load(b)) {
            Some(Ok(m)) => m,
            Some(Err(e)) => {
                tracing::warn!(error = %e, "ML model not loaded");
                warnings.push(format!("ML model not loaded: {e}"));
                None
            }
            None => None,
        };
        let ml_threshold = ml
            .as_ref()
            .map_or(1.0, |m| m.threshold().max(cfg.ml.suspicious_threshold));

        let clamav = clamav::ClamAv::locate(
            &paths.clamav_db_dir(),
            bundle.as_ref().map(|b| b.join("clamav")).as_deref(),
        );
        if clamav.is_none() {
            tracing::info!("clamscan not found: ClamAV disabled");
        }

        let engine = Self {
            paths: paths.clone(),
            db_version,
            malware,
            allow,
            names,
            team_ids,
            yara,
            ml,
            ml_threshold,
            ml_only_untrusted: cfg.ml.only_untrusted,
            clamav,
            internal_excludes: vec![paths.root.clone()],
            warnings,
            local_allow: RwLock::new(HashSet::new()),
            sign_cache: Mutex::new(TwoGenCache::new(SIGN_CACHE_CAPACITY)),
            scan_cache: Mutex::new(TwoGenCache::new(SCAN_CACHE_CAPACITY)),
        };
        let s = engine.stats();
        tracing::info!(
            db = ?s.db_version, malware_hashes = s.malware_hashes, allow_hashes = s.allow_hashes, yara_rules = s.yara_rules,
            ml = ?s.ml_model_version, clamav = ?s.clamav_version, "engine loaded"
        );
        Ok(engine)
    }

    /// What is loaded.
    pub fn stats(&self) -> EngineStats {
        EngineStats {
            db_version: self.db_version.clone(),
            malware_hashes: self.malware.len(),
            allow_hashes: self.allow.len(),
            yara_rules: self.yara.count,
            ml_model_version: self.ml.as_ref().map(|m| m.version().to_owned()),
            clamav_available: self.clamav.is_some(),
            clamav_version: self.clamav.as_ref().and_then(|c| c.version.clone()),
            warnings: self.warnings.clone(),
        }
    }

    /// Replaces the user-approved hashes (restored files, reported false positives). They win over
    /// every engine. Clears the scan cache.
    pub fn set_local_allowlist(&self, sha256_hex: &[String]) {
        let set: HashSet<hashdb::Digest> = sha256_hex
            .iter()
            .filter_map(|h| hashdb::parse_hex_digest(h))
            .collect();
        if let Ok(mut g) = self.local_allow.write() {
            *g = set;
        }
        if let Ok(mut c) = self.scan_cache.lock() {
            c.clear();
        }
    }

    fn is_allowlisted(&self, d: &hashdb::Digest) -> bool {
        self.local_allow
            .read()
            .map(|g| g.contains(d))
            .unwrap_or(false)
            || self.allow.contains(d)
    }

    /// Hash-DB detection for a digest, if it is listed as malware.
    fn hash_detection(&self, d: &hashdb::Digest) -> Option<Detection> {
        if !self.malware.contains(d) {
            return None;
        }
        let hexd = hex::encode(d);
        Some(Detection {
            engine: DetectionEngine::HashDb,
            name: self
                .names
                .lookup(&hexd)
                .unwrap_or_else(|| "Parabellum.HashDB.Malware".to_string()),
            severity: Severity::Critical,
            confidence: 0.99,
            details: Some(format!(
                "SHA-256 listed in threat database {}",
                self.db_version.as_deref().unwrap_or("?")
            )),
        })
    }

    /// Looks a SHA-256 (hex, any case) up in the threat database without reading any file.
    /// Returns `None` for unknown or allowlisted hashes. Cheap (binary search on a memory map), so
    /// the daemon can re-check its file history against a new DB without re-scanning files.
    pub fn lookup_hash(&self, sha256_hex: &str) -> Option<Detection> {
        let d = hashdb::parse_hex_digest(sha256_hex)?;
        if self.is_allowlisted(&d) {
            return None;
        }
        self.hash_detection(&d)
    }

    /// Code-signing information (macOS: `codesign` + `spctl`), cached by SHA-256. `None` on Linux,
    /// for unreadable paths, or when the tools fail.
    pub fn signing_info(&self, path: &Path) -> Option<SigningInfo> {
        if !cfg!(target_os = "macos") {
            return None;
        }
        let meta = std::fs::metadata(path).ok()?;
        if meta.is_dir() {
            return signing::compute(path, true);
        }
        let digest = hashdb::parse_hex_digest(&sha256_file(path).ok()?)?;
        self.signing_for(path, &digest)
    }

    fn signing_for(&self, path: &Path, digest: &hashdb::Digest) -> Option<SigningInfo> {
        if let Some(hit) = self.sign_cache.lock().ok().and_then(|mut c| c.get(digest)) {
            return hit;
        }
        let info = signing::compute(path, true);
        if let Ok(mut c) = self.sign_cache.lock() {
            c.insert(*digest, info.clone());
        }
        info
    }

    /// Valid signature from Apple, or from a trusted Team ID (bundle `allow/team_ids.txt` + a small
    /// built-in list), and not rejected by Gatekeeper's notarization check.
    pub fn is_trusted_signer(&self, s: &SigningInfo) -> bool {
        s.valid
            && (s.apple
                || s.team_id.as_deref().is_some_and(|t| {
                    self.team_ids.contains(t) || signing::BUILTIN_TEAM_IDS.contains(&t)
                }))
            && s.notarized != Some(false)
    }

    fn is_excluded(&self, path: &Path, opts: &ScanOptions) -> bool {
        self.internal_excludes
            .iter()
            .chain(opts.exclude_prefixes.iter())
            .any(|p| !p.as_os_str().is_empty() && path.starts_with(p))
    }

    fn new_ctx<'e>(&'e self, opts: &'e ScanOptions, cancel: &'e AtomicBool) -> Ctx<'e> {
        Ctx {
            opts,
            cancel,
            yara: yara::new_scanner(&self.yara.rules),
            fingerprint: opts.fingerprint(),
        }
    }

    fn clam_limits(opts: &ScanOptions) -> clamav::ClamLimits {
        clamav::ClamLimits {
            max_file_size: opts.max_file_size,
            max_scan_size: opts.archive_max_total,
            // ClamAV counts its own internal layers (UDIF → partition → HFS+ → file…).
            max_recursion: (opts.archive_max_depth.saturating_mul(4)).clamp(4, 17),
            max_files: opts.archive_max_entries,
        }
    }

    // ------------------------------------------------------------------------------------------
    // Public scanning API
    // ------------------------------------------------------------------------------------------

    /// Scans one file (no container member reports: members roll up into the returned report).
    /// A directory (e.g. an `.app`) is scanned recursively and summarised in one report.
    /// ClamAV runs only if `opts.use_clamav`.
    pub fn scan_file(&self, path: &Path, opts: &ScanOptions) -> ScanReport {
        let not_cancelled = AtomicBool::new(false);
        let display = path.to_string_lossy().into_owned();
        let meta = if opts.follow_symlinks {
            std::fs::metadata(path)
        } else {
            std::fs::symlink_metadata(path)
        };
        if meta.as_ref().is_ok_and(|m| m.is_dir()) {
            return self.scan_directory_summary(path, opts, &not_cancelled);
        }
        let mut ctx = self.new_ctx(opts, &not_cancelled);
        let mut a = self.scan_top(&mut ctx, path, display, &mut |_member| {});
        if let Some(p) = a.clamav_path.take() {
            let mut batch = vec![a];
            self.clamav_merge(&mut batch, &[p], opts, &not_cancelled);
            a = batch
                .pop()
                .unwrap_or_else(|| Analysis::new(path.to_string_lossy().into_owned()));
        }
        self.complete(&mut a);
        a.report
    }

    /// Scans files and directories (recursively if `opts.recursive`), including container members,
    /// calling `on_report` for every report. ClamAV runs in batches and its results are merged into
    /// the reports *before* they are delivered. Checks `cancel` between files.
    pub fn scan_paths(
        &self,
        paths: &[PathBuf],
        opts: &ScanOptions,
        cancel: &AtomicBool,
        on_report: &mut dyn FnMut(&ScanReport),
    ) -> ScanTotals {
        self.scan_paths_impl(paths, opts, cancel, &mut |r, _member| on_report(r))
    }

    fn scan_directory_summary(
        &self,
        dir: &Path,
        opts: &ScanOptions,
        cancel: &AtomicBool,
    ) -> ScanReport {
        let started = Instant::now();
        let display = dir.to_string_lossy().into_owned();
        let mut report = ScanReport {
            path: display.clone(),
            kind: if dir
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("app"))
            {
                FileKind::AppBundle
            } else {
                FileKind::Other
            },
            ..Default::default()
        };
        let mut rollup = Rollup::default();
        let dir_prefix = display.trim_end_matches('/').to_owned();
        let totals = self.scan_paths_impl(&[dir.to_path_buf()], opts, cancel, &mut |r, member| {
            if member {
                return;
            }
            report.size += r.size;
            if r.verdict != Verdict::Clean {
                // Present members as `<dir>!/<relative path>` for the roll-up details.
                let rel = r
                    .path
                    .strip_prefix(&dir_prefix)
                    .map(|s| s.trim_start_matches('/'))
                    .unwrap_or(&r.path);
                let mut shown = r.clone();
                shown.path = format!("{dir_prefix}!/{rel}");
                rollup.add(&shown, &dir_prefix);
            }
        });
        report.verdict = rollup.verdict;
        report.score = rollup.score;
        report.detections = rollup.detections;
        if totals.errors > 0 {
            report.error = Some(format!(
                "{} file(s) could not be fully scanned",
                totals.errors
            ));
        }
        if opts.compute_signing && report.kind == FileKind::AppBundle {
            report.signing = signing::compute(dir, true);
        }
        report.duration_ms = started.elapsed().as_millis() as u64;
        report
    }

    fn scan_paths_impl(
        &self,
        paths: &[PathBuf],
        opts: &ScanOptions,
        cancel: &AtomicBool,
        on_report: &mut dyn FnMut(&ScanReport, bool),
    ) -> ScanTotals {
        let mut totals = ScanTotals::default();
        let mut ctx = self.new_ctx(opts, cancel);
        let mut batch = ClamBatch::default();

        let mut deliver = |r: &ScanReport, member: bool, totals: &mut ScanTotals| {
            totals.files += 1;
            totals.bytes += r.size;
            if r.error.is_some() {
                totals.errors += 1;
            }
            if !member && r.verdict != Verdict::Clean {
                totals.threats += 1;
            }
            on_report(r, member);
        };

        'roots: for root in paths {
            if ctx.cancelled() {
                break;
            }
            if self.is_excluded(root, opts) {
                continue;
            }
            let meta = if opts.follow_symlinks {
                std::fs::metadata(root)
            } else {
                std::fs::symlink_metadata(root)
            };
            let meta = match meta {
                Ok(m) => m,
                Err(e) => {
                    let r = ScanReport {
                        path: root.to_string_lossy().into_owned(),
                        error: Some(format!("cannot access: {e}")),
                        ..Default::default()
                    };
                    deliver(&r, false, &mut totals);
                    continue;
                }
            };
            if meta.is_file() {
                self.process_candidate(
                    &mut ctx,
                    root,
                    Some(meta),
                    &mut batch,
                    &mut |r, member, t| deliver(r, member, t),
                    &mut totals,
                );
                continue;
            }
            if !meta.is_dir() {
                continue;
            }
            let walker = walkdir::WalkDir::new(root)
                .follow_links(opts.follow_symlinks)
                .max_depth(if opts.recursive { usize::MAX } else { 1 })
                .into_iter()
                .filter_entry(|e| !self.is_excluded(e.path(), opts));
            for entry in walker {
                if ctx.cancelled() {
                    break 'roots;
                }
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        let path = e
                            .path()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_else(|| root.to_string_lossy().into_owned());
                        let r = ScanReport {
                            path,
                            error: Some(format!("cannot read: {e}")),
                            ..Default::default()
                        };
                        deliver(&r, false, &mut totals);
                        continue;
                    }
                };
                if !entry.file_type().is_file() {
                    continue;
                }
                let meta = entry.metadata().ok();
                self.process_candidate(
                    &mut ctx,
                    entry.path(),
                    meta,
                    &mut batch,
                    &mut |r, member, t| deliver(r, member, t),
                    &mut totals,
                );
            }
        }
        // Flush what is left (without ClamAV if cancelled).
        self.flush_batch(
            &mut batch,
            opts,
            cancel,
            &mut |r, member, t| deliver(r, member, t),
            &mut totals,
        );
        totals.cancelled = cancel.load(Ordering::Relaxed);
        totals
    }

    fn process_candidate<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        path: &Path,
        meta: Option<std::fs::Metadata>,
        batch: &mut ClamBatch,
        deliver: &mut dyn FnMut(&ScanReport, bool, &mut ScanTotals),
        totals: &mut ScanTotals,
    ) {
        if ctx.cancelled() {
            return;
        }
        if ctx.opts.only_risky_types {
            let mode = meta.as_ref().map_or(0o755, |m| m.mode());
            if !filetype::is_risky(path, mode) {
                return;
            }
        }
        let display = path.to_string_lossy().into_owned();
        let mut a = self.scan_top(ctx, path, display, &mut |member| {
            deliver(&member, true, totals)
        });
        match a.clamav_path.take() {
            Some(p) => {
                batch.arg_bytes += p.as_os_str().len() + 1;
                batch.paths.push(p);
                batch.items.push(a);
                if batch.items.len() >= clamav::BATCH_SIZE
                    || batch.arg_bytes >= clamav::MAX_ARG_BYTES
                {
                    self.flush_batch(batch, ctx.opts, ctx.cancel, deliver, totals);
                }
            }
            None => {
                self.complete(&mut a);
                deliver(&a.report, false, totals);
            }
        }
    }

    /// Runs ClamAV on the pending batch (unless cancelled), then delivers its reports.
    fn flush_batch(
        &self,
        batch: &mut ClamBatch,
        opts: &ScanOptions,
        cancel: &AtomicBool,
        deliver: &mut dyn FnMut(&ScanReport, bool, &mut ScanTotals),
        totals: &mut ScanTotals,
    ) {
        if batch.items.is_empty() {
            return;
        }
        self.clamav_merge(&mut batch.items, &batch.paths, opts, cancel);
        for mut a in batch.items.drain(..) {
            self.complete(&mut a);
            deliver(&a.report, false, totals);
        }
        batch.paths.clear();
        batch.arg_bytes = 0;
    }

    /// Runs clamscan on `files` (same order as `batch`) and merges hits into the analyses.
    fn clamav_merge(
        &self,
        batch: &mut [Analysis],
        files: &[PathBuf],
        opts: &ScanOptions,
        cancel: &AtomicBool,
    ) {
        let Some(clam) = &self.clamav else { return };
        if cancel.load(Ordering::Relaxed) || files.is_empty() {
            return;
        }
        match clam.scan_batch(files, &Self::clam_limits(opts), cancel) {
            Ok(hits) => {
                for (a, p) in batch.iter_mut().zip(files) {
                    if let Some(sigs) = hits.get(p) {
                        for sig in sigs {
                            a.own.push(Detection {
                                engine: DetectionEngine::ClamAv,
                                name: sig.clone(),
                                severity: if sig.starts_with("PUA.")
                                    || sig.starts_with("Heuristics.")
                                {
                                    Severity::Medium
                                } else {
                                    Severity::High
                                },
                                confidence: if sig.starts_with("PUA.")
                                    || sig.starts_with("Heuristics.")
                                {
                                    0.6
                                } else {
                                    0.95
                                },
                                details: Some("ClamAV signature".into()),
                            });
                        }
                    }
                }
            }
            Err(e) if e == "cancelled" => {}
            Err(e) => {
                tracing::warn!(error = %e, files = files.len(), "clamscan batch failed");
                for a in batch.iter_mut() {
                    a.note(format!("clamav: {e}"));
                }
            }
        }
    }

    /// Final verdict + scan-cache store for a top-level analysis.
    fn complete(&self, a: &mut Analysis) {
        a.finalize();
        if let Some(key) = a.cache_key.take() {
            if a.report.error.is_none() {
                let mut stored = a.report.clone();
                stored.path = String::new();
                if let Ok(mut c) = self.scan_cache.lock() {
                    c.insert(key, stored);
                }
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Analysis
    // ------------------------------------------------------------------------------------------

    /// Top-level on-disk file: cache, then full analysis; marks it eligible for ClamAV.
    fn scan_top<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        path: &Path,
        display: String,
        sink: &mut dyn FnMut(ScanReport),
    ) -> Analysis {
        let mut budget = Budget::for_opts(ctx.opts);
        self.analyze_disk(ctx, path, display, 0, &mut budget, sink)
    }

    /// Analyses an on-disk regular file (top-level when `depth == 0`, else a DMG/PKG member).
    pub(crate) fn analyze_disk<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        path: &Path,
        display: String,
        depth: u32,
        budget: &mut Budget,
        sink: &mut dyn FnMut(ScanReport),
    ) -> Analysis {
        let mut a = Analysis::new(display);
        if depth == 0
            && !ctx.opts.follow_symlinks
            && std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
        {
            a.note("symbolic link not followed");
            return a;
        }
        let opened = if ctx.opts.follow_symlinks && depth == 0 {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(path)
        } else {
            filetype::open_nonblocking(path)
        };
        let mut file = match opened {
            Ok(f) => f,
            Err(e) => {
                a.note(format!("cannot open: {e}"));
                return a;
            }
        };
        let meta = match file.metadata() {
            Ok(m) => m,
            Err(e) => {
                a.note(format!("cannot stat: {e}"));
                return a;
            }
        };
        if !meta.is_file() {
            a.note("not a regular file");
            return a;
        }
        let size = meta.len();
        a.report.size = size;
        if depth == 0 {
            let key = CacheKey::new(&meta, ctx.fingerprint);
            if let Some(mut hit) = self.scan_cache.lock().ok().and_then(|mut c| c.get(&key)) {
                hit.path = std::mem::take(&mut a.report.path);
                hit.cached = true;
                hit.duration_ms = a.started.elapsed().as_millis() as u64;
                a.report = hit;
                a.done = true;
                return a;
            }
            a.cache_key = Some(key);
        }
        let hash_only = size > ctx.opts.max_file_size;
        let keep = if hash_only {
            filetype::HEAD_LEN as u64
        } else {
            size.min(IN_MEMORY_LIMIT)
        };
        let (digest, data) = match read_and_hash(&mut file, size, keep) {
            Ok(x) => x,
            Err(e) => {
                a.note(format!("read error: {e}"));
                a.cache_key = None;
                return a;
            }
        };
        let truncated = (data.len() as u64) < size;
        let tail = if truncated && size >= filetype::TAIL_LEN as u64 {
            let mut t = vec![0u8; filetype::TAIL_LEN];
            file.read_exact_at(&mut t, size - filetype::TAIL_LEN as u64)
                .ok()
                .map(|_| t)
        } else {
            None
        };
        drop(file);
        let info = ContentInfo {
            disk_path: Some(path),
            digest: Some(digest),
            size,
            truncated,
            hash_only,
            tail,
        };
        self.analyze_content(ctx, &mut a, &data, &info, depth, budget, sink);
        if depth == 0
            && ctx.opts.use_clamav
            && self.clamav.is_some()
            && !a.allowlisted
            && !hash_only
            && clamav::path_is_batchable(path)
            && scoring::score(&a.own, a.trusted).0 != Verdict::Malicious
        {
            a.clamav_path = Some(path.to_path_buf());
        }
        a
    }

    /// Analyses an in-memory container member and returns its final report.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn analyze_member<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        display: String,
        data: &[u8],
        size: u64,
        digest: Option<hashdb::Digest>,
        depth: u32,
        budget: &mut Budget,
        sink: &mut dyn FnMut(ScanReport),
    ) -> ScanReport {
        let mut a = Analysis::new(display);
        a.report.size = size;
        let truncated = (data.len() as u64) < size;
        let hash_only = size > ctx.opts.max_file_size;
        let info = ContentInfo {
            disk_path: None,
            digest,
            size,
            truncated,
            hash_only,
            tail: None,
        };
        self.analyze_content(ctx, &mut a, data, &info, depth, budget, sink);
        if digest.is_none() {
            a.note("content truncated by archive limits");
        }
        a.finalize();
        a.report
    }

    /// Core pipeline on a buffer: typing, allowlist, hash DB, YARA, containers, signing, ML.
    #[allow(clippy::too_many_arguments)]
    fn analyze_content<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        a: &mut Analysis,
        data: &[u8],
        info: &ContentInfo<'_>,
        depth: u32,
        budget: &mut Budget,
        sink: &mut dyn FnMut(ScanReport),
    ) {
        let head = &data[..data.len().min(filetype::HEAD_LEN)];
        let tail = match &info.tail {
            Some(t) => Some(t.as_slice()),
            None if !info.truncated => Some(data),
            None => None,
        };
        let kind = filetype::detect(head, tail, Path::new(&a.report.path));
        a.report.kind = kind;
        if let Some(d) = &info.digest {
            a.report.sha256 = Some(hex::encode(d));
            if self.is_allowlisted(d) {
                a.allowlisted = true;
                return;
            }
            if let Some(det) = self.hash_detection(d) {
                a.own.push(det);
            }
        }
        if info.hash_only {
            a.note(format!(
                "larger than max_file_size ({} MiB): hash check only",
                ctx.opts.max_file_size / MIB
            ));
            return;
        }
        match yara::scan(&mut ctx.yara, data) {
            Ok(d) => a.own.extend(d),
            Err(e) => a.note(format!("yara: {e}")),
        }
        if ctx.cancelled() {
            return;
        }
        if depth < ctx.opts.archive_max_depth {
            self.scan_container(ctx, a, kind, data, info, depth, budget, sink);
        }

        // Code signing (macOS, on-disk Mach-O only), computed lazily.
        let is_macho = matches!(kind, FileKind::MachO | FileKind::FatMachO);
        let ml_wanted = ctx.opts.use_ml && self.ml.is_some() && is_macho && !info.truncated;
        if is_macho && cfg!(target_os = "macos") {
            if let (Some(path), Some(digest)) = (info.disk_path, info.digest.as_ref()) {
                let high_yara = a.own.iter().any(|d| {
                    matches!(d.engine, DetectionEngine::Yara | DetectionEngine::Heuristic)
                        && d.severity >= Severity::High
                });
                let need_trust = high_yara || (ml_wanted && self.ml_only_untrusted);
                // Unsigned / ad-hoc / no certificate chain can never be trusted: skip codesign.
                let may_be_trusted = pb_ml::code_signature_summary(data)
                    .is_some_and(|s| s.present && !s.adhoc && s.has_cms);
                if ctx.opts.compute_signing || (need_trust && may_be_trusted) {
                    if let Some(s) = self.signing_for(path, digest) {
                        a.trusted = self.is_trusted_signer(&s);
                        a.report.signing = Some(s);
                    }
                }
            }
        }

        if ml_wanted && !(self.ml_only_untrusted && a.trusted) {
            if let Some(model) = &self.ml {
                if let Some(p) = model.score(data) {
                    if p >= self.ml_threshold {
                        a.own.push(Detection {
                            engine: DetectionEngine::Ml,
                            name: "ML.MachO.Suspicious".into(),
                            severity: Severity::Medium,
                            confidence: p,
                            details: Some(format!(
                                "score {p:.3} >= threshold {:.3} (model {})",
                                self.ml_threshold,
                                model.version()
                            )),
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
