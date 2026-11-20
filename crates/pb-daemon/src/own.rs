//! Parabellum's own files, recognised by content ([`pb_core::own`] manifest written by `make pkg`).
//!
//! - **No false positives on ourselves**: the manifest hashes join the engine allowlist (exact content,
//!   wherever the file is), and the guard ignores what our verified binaries do.
//! - **No blind spot**: the root folder stays out of real-time scanning (logs, database, quarantine…),
//!   but the installed trees (`bin/`, `signatures/`, the app) are compared with the manifest: a file
//!   modified, missing or unknown there raises an alert. Malware that obtained root and hid next to the
//!   antivirus, or patched it, shows up within [`INTERVAL`].
//! - **Seal**: the manifest's version + hash are kept in the database; a different manifest with the same
//!   version did not come from an installer.
//!
//! Without a manifest (development, versions before it) everything here is off.

use crate::actions;
use crate::ctx::Ctx;
use crate::store::AlertKey;
use pb_core::model::{AlertAction, AlertKind, AlertStatus, Severity};
use pb_core::own::{resolve, OwnManifest};
use pb_core::paths::Paths;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// First pass after startup, then every [`INTERVAL`].
pub const STARTUP_DELAY: Duration = Duration::from_secs(180);
pub const INTERVAL: Duration = Duration::from_secs(6 * 3600);
/// kv: `<version> <sha256 of manifest.json>` of the last manifest accepted.
pub const KV_SEAL: &str = "own_manifest_seal";
/// Alert keys (`detection` column): one per path, plus the seal and the overflow summary.
const KEY_PREFIX: &str = "own:";
const KEY_SEAL: &str = "own-seal";
const KEY_MANY: &str = "own-many";
/// Beyond this many problems in one pass: one summary alert instead of one per file.
const MAX_FILE_ALERTS: usize = 10;
/// Entries walked per tree (an app bundle has a few hundred).
const MAX_WALK: usize = 50_000;
/// Finder litter, never part of a payload.
const IGNORED_NAMES: &[&str] = &[".DS_Store"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

impl Stamp {
    fn of(m: &std::fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.len(),
            mtime_ns: i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec()),
            ctime_ns: i128::from(m.ctime()) * 1_000_000_000 + i128::from(m.ctime_nsec()),
        }
    }
}

/// The loaded manifest (empty without one).
#[derive(Debug, Default)]
pub struct Own {
    manifest: Option<OwnManifest>,
    /// SHA-256 of `manifest.json` as read.
    manifest_sha: Option<String>,
    /// Why the manifest was not used (present but invalid).
    pub load_error: Option<String>,
    by_path: HashMap<PathBuf, (String, u64)>,
    trees: Vec<PathBuf>,
    /// Content checks already done: path -> (stamp, matches manifest).
    verified: Mutex<HashMap<PathBuf, (Stamp, bool)>>,
}

/// What an integrity pass found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Integrity {
    pub modified: Vec<PathBuf>,
    pub missing: Vec<PathBuf>,
    pub unknown: Vec<PathBuf>,
    pub checked: usize,
}

impl Integrity {
    pub fn is_clean(&self) -> bool {
        self.modified.is_empty() && self.missing.is_empty() && self.unknown.is_empty()
    }
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

impl Own {
    /// Read `<root>/manifest.json`. Missing: empty (feature off). Invalid: empty + `load_error`.
    pub fn load(paths: &Paths) -> Self {
        let file = paths.manifest_file();
        let bytes = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(
                    "no manifest of our own files: self-recognition and integrity checks off"
                );
                return Self::default();
            }
            Err(e) => {
                tracing::error!(path = %file.display(), error = %e, "manifest unreadable");
                return Self {
                    load_error: Some(format!("manifeste illisible : {e}")),
                    ..Self::default()
                };
            }
        };
        match OwnManifest::parse(&bytes) {
            Ok(m) => Self::from_manifest(m, hex::encode(Sha256::digest(&bytes)), &paths.root),
            Err(e) => {
                tracing::error!(path = %file.display(), error = %e, "manifest invalid");
                Self {
                    load_error: Some(format!("manifeste invalide : {e}")),
                    ..Self::default()
                }
            }
        }
    }

    fn from_manifest(m: OwnManifest, manifest_sha: String, root: &Path) -> Self {
        let by_path = m
            .files
            .iter()
            .map(|f| {
                (
                    resolve(&f.path, root),
                    (f.sha256.to_ascii_lowercase(), f.size),
                )
            })
            .collect();
        let trees = m.trees.iter().map(|t| resolve(t, root)).collect();
        tracing::info!(version = %m.version, files = m.files.len(), "manifest of our own files loaded");
        Self {
            manifest: Some(m),
            manifest_sha: Some(manifest_sha),
            load_error: None,
            by_path,
            trees,
            verified: Mutex::new(HashMap::new()),
        }
    }

    pub fn is_active(&self) -> bool {
        self.manifest.is_some()
    }

    pub fn version(&self) -> Option<&str> {
        self.manifest.as_ref().map(|m| m.version.as_str())
    }

    /// Every file hash (lowercase hex), for the engine allowlist.
    pub fn hashes(&self) -> Vec<String> {
        let set: HashSet<&str> = self.by_path.values().map(|(h, _)| h.as_str()).collect();
        set.into_iter().map(str::to_owned).collect()
    }

    /// `path` is one of our files *and* its content is the one we installed (hashed once per change).
    pub fn is_own_image(&self, path: &Path) -> bool {
        let Some((sha, size)) = self.by_path.get(path) else {
            return false;
        };
        let Ok(meta) = std::fs::metadata(path) else {
            return false;
        };
        if meta.len() != *size {
            return false;
        }
        let stamp = Stamp::of(&meta);
        if let Some((s, ok)) = self.lock_verified().get(path) {
            if *s == stamp {
                return *ok;
            }
        }
        let ok = sha256_file(path).is_ok_and(|h| h == *sha);
        self.lock_verified().insert(path.to_path_buf(), (stamp, ok));
        ok
    }

    fn lock_verified(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, (Stamp, bool)>> {
        self.verified.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Compare the installed trees with the manifest (blocking; hashes every file whose stamp changed).
    pub fn check(&self) -> Integrity {
        let mut out = Integrity::default();
        if !self.is_active() {
            return out;
        }
        let mut paths: Vec<&PathBuf> = self.by_path.keys().collect();
        paths.sort();
        for p in paths {
            out.checked += 1;
            match std::fs::symlink_metadata(p) {
                Err(_) => out.missing.push(p.clone()),
                Ok(m) if !m.is_file() => out.modified.push(p.clone()),
                Ok(_) => {
                    if !self.is_own_image(p) {
                        out.modified.push(p.clone());
                    }
                }
            }
        }
        for tree in &self.trees {
            let mut stack = vec![tree.clone()];
            let mut walked = 0usize;
            while let Some(dir) = stack.pop() {
                let Ok(rd) = std::fs::read_dir(&dir) else {
                    continue;
                };
                for e in rd.flatten() {
                    walked += 1;
                    if walked > MAX_WALK {
                        tracing::warn!(tree = %tree.display(), "integrity walk truncated");
                        break;
                    }
                    let p = e.path();
                    let Ok(ty) = e.file_type() else { continue };
                    if ty.is_dir() {
                        stack.push(p);
                    } else if ty.is_file()
                        && !self.by_path.contains_key(&p)
                        && !IGNORED_NAMES.iter().any(|n| e.file_name() == *n)
                    {
                        out.unknown.push(p);
                    }
                }
            }
        }
        out.unknown.sort();
        out
    }
}

/// Seal the manifest: first one or a new version is accepted; same version, different content is not.
/// Returns an alert message when the manifest changed outside an installation.
pub fn check_seal(previous: Option<&str>, version: &str, sha: &str) -> Result<String, String> {
    let new = format!("{version} {sha}");
    match previous {
        None => Ok(new),
        Some(p) if p == new => Ok(new),
        Some(p) => {
            let old_version = p.split_once(' ').map(|(v, _)| v).unwrap_or(p);
            if old_version != version {
                Ok(new)
            } else {
                Err(format!(
                    "Le manifeste des fichiers de Parabellum a changé sans changement de version ({version}). Un \
                     installateur ne fait jamais ça : un programme avec les droits administrateur a pu le réécrire \
                     pour masquer une modification. Réinstallez Parabellum (make pkg && make install), puis lancez \
                     une analyse complète."
                ))
            }
        }
    }
}

fn path_key(p: &Path) -> String {
    format!("{KEY_PREFIX}{}", p.display())
}

async fn open_alerts(ctx: &Arc<Ctx>, key: String) -> Vec<pb_core::model::Alert> {
    ctx.store
        .run(move |s| s.open_alerts_by(AlertKey::Title(&key)))
        .await
        .unwrap_or_default()
}

async fn raise_once(ctx: &Arc<Ctx>, key: String, severity: Severity, title: &str, msg: String) {
    if !open_alerts(ctx, key.clone()).await.is_empty() {
        return; // still open or acknowledged: no duplicate
    }
    let mut a = actions::alert(AlertKind::System, severity, title, msg);
    a.actions = vec![AlertAction::Acknowledge];
    actions::raise_alert(ctx, a, Some(key)).await;
}

/// Resolve the open alerts of this module whose problem is gone (`bad`: keys still failing).
async fn resolve_fixed(ctx: &Arc<Ctx>, bad: &HashSet<String>) {
    let open = ctx
        .store
        .run(|s| s.open_alerts_with_key_prefix(KEY_PREFIX))
        .await
        .unwrap_or_default();
    let many = if bad.len() > MAX_FILE_ALERTS {
        vec![]
    } else {
        open_alerts(ctx, KEY_MANY.into()).await
    };
    for (mut a, key) in open
        .into_iter()
        .chain(many.into_iter().map(|a| (a, KEY_MANY.to_string())))
    {
        if bad.contains(&key) {
            continue;
        }
        a.status = AlertStatus::Resolved;
        a.actions.clear();
        let _ = actions::save_alert(ctx, &a).await;
    }
}

/// One pass: seal, then integrity; alerts deduplicated per path.
pub async fn integrity_pass(ctx: &Arc<Ctx>) -> Option<Integrity> {
    let own = &ctx.own;
    if let Some(err) = &own.load_error {
        raise_once(
            ctx,
            KEY_SEAL.into(),
            Severity::High,
            "Manifeste de Parabellum inutilisable",
            format!(
                "{err}. Parabellum ne peut plus vérifier ses propres fichiers. Réinstallez-le (make pkg && make \
                 install)."
            ),
        )
        .await;
        return None;
    }
    let (Some(version), Some(sha)) = (own.version(), own.manifest_sha.as_deref()) else {
        return None;
    };
    let previous = ctx.store.run(|s| s.kv_get(KV_SEAL)).await.ok().flatten();
    match check_seal(previous.as_deref(), version, sha) {
        Ok(seal) => {
            if previous.as_deref() != Some(seal.as_str()) {
                let _ = ctx.store.run(move |s| s.kv_set(KV_SEAL, &seal)).await;
                // A new installation answers an earlier seal alert.
                for mut a in open_alerts(ctx, KEY_SEAL.into()).await {
                    a.status = AlertStatus::Resolved;
                    a.actions.clear();
                    let _ = actions::save_alert(ctx, &a).await;
                }
            }
        }
        Err(msg) => {
            raise_once(
                ctx,
                KEY_SEAL.into(),
                Severity::Critical,
                "Manifeste de Parabellum modifié",
                msg,
            )
            .await;
            // The manifest cannot be trusted to judge the files: stop here.
            return None;
        }
    }

    let ctx2 = ctx.clone();
    let report = tokio::task::spawn_blocking(move || ctx2.own.check())
        .await
        .ok()?;
    let mut problems: Vec<(&PathBuf, Severity, &str, String)> = Vec::new();
    for p in &report.modified {
        problems.push((
            p,
            Severity::High,
            "Fichier de Parabellum modifié",
            format!(
                "{} ne correspond plus à la version installée ({version}). Si vous ne l'avez pas modifié vous-même, \
                 un programme avec les droits administrateur l'a fait : réinstallez Parabellum (make pkg && make \
                 install), puis lancez une analyse complète.",
                p.display()
            ),
        ));
    }
    for p in &report.unknown {
        problems.push((
            p,
            Severity::High,
            "Fichier inconnu dans Parabellum",
            format!(
                "{} n'a pas été installé par Parabellum. Un logiciel malveillant peut se cacher dans le dossier d'un \
                 antivirus pour ne pas être analysé. S'il ne vient pas de vous, supprimez-le et lancez une analyse \
                 complète.",
                p.display()
            ),
        ));
    }
    for p in &report.missing {
        problems.push((
            p,
            Severity::Medium,
            "Fichier de Parabellum manquant",
            format!(
                "{} a disparu depuis l'installation ({version}). Réinstallez Parabellum si vous ne l'avez pas \
                 supprimé vous-même.",
                p.display()
            ),
        ));
    }
    let bad: HashSet<String> = problems.iter().map(|(p, ..)| path_key(p)).collect();
    if problems.len() > MAX_FILE_ALERTS {
        let list: Vec<String> = problems
            .iter()
            .take(MAX_FILE_ALERTS)
            .map(|(p, _, t, _)| format!("{t} : {}", p.display()))
            .collect();
        raise_once(
            ctx,
            KEY_MANY.into(),
            Severity::High,
            "Fichiers de Parabellum modifiés",
            format!(
                "{} fichiers ne correspondent plus à l'installation ({version}), dont :\n{}\nRéinstallez \
                 Parabellum (make pkg && make install), puis lancez une analyse complète.",
                problems.len(),
                list.join("\n")
            ),
        )
        .await;
    } else {
        for (p, severity, title, msg) in &problems {
            raise_once(ctx, path_key(p), *severity, title, msg.clone()).await;
        }
    }
    resolve_fixed(ctx, &bad).await;
    if report.is_clean() {
        tracing::info!(files = report.checked, "own files intact");
    } else {
        tracing::warn!(
            modified = report.modified.len(),
            missing = report.missing.len(),
            unknown = report.unknown.len(),
            "own files differ from the manifest"
        );
    }
    Some(report)
}

/// Integrity passes: [`STARTUP_DELAY`] after startup, then every [`INTERVAL`].
pub async fn integrity_loop(ctx: Arc<Ctx>) {
    if !ctx.own.is_active() && ctx.own.load_error.is_none() {
        return;
    }
    let mut shutdown = ctx.shutdown_rx();
    let mut wait = STARTUP_DELAY;
    loop {
        tokio::select! {
            _ = crate::system::sleep_until_wall(crate::system::wall_deadline(wait)) => {}
            _ = shutdown.changed() => if *shutdown.borrow() { return; },
        }
        integrity_pass(&ctx).await;
        wait = INTERVAL;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn write_manifest(root: &Path, files: &[(&str, &[u8])], trees: &[&str]) -> Paths {
        let paths = Paths::with_root(root);
        let mut entries = Vec::new();
        for (rel, content) in files {
            let p = resolve(rel, root);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, content).unwrap();
            entries.push(serde_json::json!({
                "path": rel, "sha256": hex::encode(Sha256::digest(content)), "size": content.len()
            }));
        }
        let m =
            serde_json::json!({"format": 1, "version": "1.0.0", "trees": trees, "files": entries});
        std::fs::write(paths.manifest_file(), serde_json::to_vec(&m).unwrap()).unwrap();
        paths
    }

    #[test]
    fn recognises_own_files_by_content_only() {
        let d = tempfile::tempdir().unwrap();
        let paths = write_manifest(
            d.path(),
            &[
                ("@root/bin/parabellumd", b"daemon"),
                ("@root/signatures/builtin.yar", b"rules"),
            ],
            &["@root/bin", "@root/signatures"],
        );
        let own = Own::load(&paths);
        assert!(own.is_active() && own.load_error.is_none());
        let daemon = d.path().join("bin/parabellumd");
        assert!(own.is_own_image(&daemon));
        assert!(!own.is_own_image(Path::new("/usr/bin/true")));
        assert_eq!(own.hashes().len(), 2);
        assert!(own.check().is_clean());

        // Same size, different content: no longer ours.
        std::fs::write(&daemon, b"DAEMON").unwrap();
        assert!(!own.is_own_image(&daemon));
        // Dropped next to our binaries, and one file removed.
        std::fs::write(d.path().join("bin/helper"), b"x").unwrap();
        std::fs::write(d.path().join("bin/.DS_Store"), b"x").unwrap();
        std::fs::remove_file(d.path().join("signatures/builtin.yar")).unwrap();
        let r = own.check();
        assert_eq!(r.modified, vec![daemon]);
        assert_eq!(r.unknown, vec![d.path().join("bin/helper")]);
        assert_eq!(r.missing, vec![d.path().join("signatures/builtin.yar")]);
    }

    #[test]
    fn missing_or_invalid_manifest() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(d.path());
        let own = Own::load(&paths);
        assert!(!own.is_active() && own.load_error.is_none() && own.check().is_clean());
        std::fs::write(paths.manifest_file(), b"{not json").unwrap();
        let own = Own::load(&paths);
        assert!(!own.is_active() && own.load_error.is_some());
    }

    fn ctx_at(root: &Path) -> Arc<Ctx> {
        Arc::new(Ctx::new(
            Paths::with_root(root),
            true,
            crate::store::Store::open_in_memory().unwrap(),
            crate::backends::Backends::unavailable(),
            pb_core::config::Config::default(),
        ))
    }

    async fn own_alerts(ctx: &Arc<Ctx>) -> Vec<(pb_core::model::Alert, String)> {
        ctx.store
            .run(|s| s.open_alerts_with_key_prefix("own"))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn integrity_pass_alerts_once_and_resolves() {
        let d = tempfile::tempdir().unwrap();
        write_manifest(
            d.path(),
            &[
                ("@root/bin/parabellumd", b"daemon"),
                ("@root/bin/parabellum", b"cli"),
            ],
            &["@root/bin"],
        );
        let ctx = ctx_at(d.path());
        assert!(integrity_pass(&ctx).await.unwrap().is_clean());
        assert!(own_alerts(&ctx).await.is_empty());

        let dropped = d.path().join("bin/.updater");
        std::fs::write(&dropped, b"payload").unwrap();
        std::fs::write(d.path().join("bin/parabellum"), b"CLI").unwrap();
        integrity_pass(&ctx).await.unwrap();
        integrity_pass(&ctx).await.unwrap(); // no duplicates
        let alerts = own_alerts(&ctx).await;
        assert_eq!(alerts.len(), 2, "{alerts:?}");
        assert!(alerts
            .iter()
            .all(|(a, _)| a.severity == Severity::High && a.kind == AlertKind::System));

        // Fixed: both resolved.
        std::fs::remove_file(&dropped).unwrap();
        std::fs::write(d.path().join("bin/parabellum"), b"cli").unwrap();
        assert!(integrity_pass(&ctx).await.unwrap().is_clean());
        assert!(own_alerts(&ctx).await.is_empty());
    }

    #[tokio::test]
    async fn rewritten_manifest_same_version_is_refused() {
        let d = tempfile::tempdir().unwrap();
        write_manifest(
            d.path(),
            &[("@root/bin/parabellumd", b"daemon")],
            &["@root/bin"],
        );
        let ctx = ctx_at(d.path());
        integrity_pass(&ctx).await.unwrap();
        // An attacker patches the binary and rewrites the manifest to match, keeping the version.
        let paths = write_manifest(
            d.path(),
            &[("@root/bin/parabellumd", b"evil")],
            &["@root/bin"],
        );
        let ctx2 = Arc::new(Ctx::new(
            paths,
            true,
            ctx.store.clone(),
            crate::backends::Backends::unavailable(),
            pb_core::config::Config::default(),
        ));
        assert!(integrity_pass(&ctx2).await.is_none());
        let alerts = own_alerts(&ctx2).await;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].0.severity, Severity::Critical);
    }

    #[test]
    fn seal() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert_eq!(check_seal(None, "1.0", &a).unwrap(), format!("1.0 {a}"));
        let sealed = format!("1.0 {a}");
        assert!(check_seal(Some(&sealed), "1.0", &a).is_ok());
        // New version (installer): accepted.
        assert_eq!(
            check_seal(Some(&sealed), "1.1", &b).unwrap(),
            format!("1.1 {b}")
        );
        // Same version, different manifest: refused.
        assert!(check_seal(Some(&sealed), "1.0", &b).is_err());
    }
}
