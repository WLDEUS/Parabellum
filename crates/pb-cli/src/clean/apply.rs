//! `clean apply`: re-validate each planned path, then move it to the Trash or delete it.

use super::rules::{self, DevMode, LeftoverKind};
use super::{apps, measure, sys, CleanEnv};
use pb_core::model::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// What applying an item means once validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The path itself (file, folder or link).
    Whole,
    /// Only the files inside modified before the cutoff (logs).
    OldFiles(i64),
    /// Every entry of `~/.Trash`.
    TrashContents,
}

/// Why an item is not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rejection {
    /// Refused by the safety rules.
    Refused(String),
    /// Nothing to do now (vanished, in use).
    Skipped(String),
}

fn refused(m: impl Into<String>) -> Rejection {
    Rejection::Refused(m.into())
}

fn depth_under(base: &Path, p: &Path) -> Option<usize> {
    p.strip_prefix(base).ok().map(|r| r.components().count())
}

/// Check `path` against the rules of `category`. `installed` is computed on first need (leftovers).
pub fn validate(
    env: &CleanEnv,
    category: CleanCategory,
    path: &Path,
    installed: &mut Option<apps::Installed>,
) -> Result<Target, Rejection> {
    let home = &env.home;
    let lib = env.library();
    if !rules::is_clean_path(path) {
        return Err(refused("chemin invalide"));
    }
    let brew_outside = category == CleanCategory::DeveloperCaches
        && env.brew_cache.as_deref() == Some(path)
        && !path.starts_with(home);
    if !brew_outside && (!path.starts_with(home) || path == home) {
        return Err(refused("hors du dossier personnel"));
    }
    if let Some(why) = rules::denied(home, path) {
        return Err(refused(format!("protégé : {why}")));
    }
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Err(Rejection::Skipped("introuvable (déjà supprimé ?)".into())),
    };
    let parent = path.parent().ok_or_else(|| refused("chemin invalide"))?;
    match std::fs::canonicalize(parent) {
        Ok(c) if c == parent => {}
        _ => return Err(refused("lien symbolique dans le chemin")),
    }
    if sys::protected_flags(&meta) {
        return Err(refused("protégé par macOS (verrouillé ou SIP)"));
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let target = match category {
        CleanCategory::Caches => {
            if parent != lib.join("Caches") || rules::cache_entry_denied(name) {
                return Err(refused("pas un cache d'application"));
            }
            Target::Whole
        }
        CleanCategory::BrowserCaches => {
            if !rules::is_browser_cache(home, path) || !meta.is_dir() {
                return Err(refused("pas un cache de navigateur"));
            }
            Target::Whole
        }
        CleanCategory::DeveloperCaches => {
            let ok = rules::developer_caches(home, env.brew_cache.as_deref())
                .iter()
                .any(|d| match d.mode {
                    DevMode::Whole => d.path == path,
                    DevMode::Children => d.path == parent,
                });
            if !ok {
                return Err(refused("pas un cache d'outil de développement"));
            }
            Target::Whole
        }
        CleanCategory::Logs => {
            if depth_under(&lib.join("Logs"), path).unwrap_or(0) == 0 {
                return Err(refused("pas un journal"));
            }
            Target::OldFiles(env.now - rules::OLD_SECS)
        }
        CleanCategory::Downloads => {
            let depth = depth_under(&home.join("Downloads"), path).unwrap_or(0);
            if !(1..=2).contains(&depth) || !meta.is_file() {
                return Err(refused("pas un fichier de Téléchargements"));
            }
            if super::installer_kind(path).is_none() {
                return Err(refused("pas un installeur"));
            }
            if meta.mtime() >= env.now - rules::OLD_SECS {
                return Err(Rejection::Skipped(
                    "téléchargé il y a moins de 30 jours".into(),
                ));
            }
            Target::Whole
        }
        CleanCategory::LargeFiles => {
            let mut a = parent;
            while a != home.as_path() {
                if rules::large_walk_skips(home, a, true) {
                    return Err(refused("dossier exclu (Bibliothèque, Photos, Musique…)"));
                }
                a = a.parent().ok_or_else(|| refused("chemin invalide"))?;
            }
            let big_file = meta.is_file() && meta.blocks() * 512 >= env.large_min;
            let vm_bundle = meta.is_dir() && rules::is_vm_bundle(path);
            if !(big_file || vm_bundle) || rules::large_walk_skips(home, path, meta.is_dir()) {
                return Err(refused("pas un gros fichier"));
            }
            Target::Whole
        }
        CleanCategory::AppLeftovers => {
            let Some((_, kind, _)) = rules::leftover_roots(home)
                .into_iter()
                .find(|(root, _, _)| root == parent)
            else {
                return Err(refused("pas dans un dossier de données d'applications"));
            };
            let inst = installed.get_or_insert_with(|| apps::installed(env));
            if inst.vendors.len() < env.min_installed_vendors {
                return Err(refused("liste des applications installées incomplète"));
            }
            if super::leftover_of(home, kind, path, inst).is_none() {
                return Err(refused("appartient à une application installée"));
            }
            if kind == LeftoverKind::LaunchAgent && !meta.is_file() {
                return Err(refused("pas un agent de démarrage"));
            }
            Target::Whole
        }
        CleanCategory::Trash => {
            if path != home.join(".Trash") || !meta.is_dir() {
                return Err(refused("seule la corbeille entière peut être vidée"));
            }
            Target::TrashContents
        }
    };
    Ok(target)
}

/// `dir/name`, or `dir/stem N.ext` when taken.
pub fn unique_in(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if std::fs::symlink_metadata(&first).is_err() {
        return first;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() && e.len() <= 5 => (s, format!(".{e}")),
        _ => (name, String::new()),
    };
    for n in 2..100_000 {
        let p = dir.join(format!("{stem} {n}{ext}"));
        if std::fs::symlink_metadata(&p).is_err() {
            return p;
        }
    }
    dir.join(format!("{stem} {}{ext}", uuid_like()))
}

fn uuid_like() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

/// `~/.Trash`, created (0700) if missing; refused when it is not a plain folder.
fn trash_dir(env: &CleanEnv) -> std::io::Result<PathBuf> {
    let t = env.home.join(".Trash");
    match std::fs::symlink_metadata(&t) {
        Ok(m) if m.is_dir() => Ok(t),
        Ok(_) => Err(std::io::Error::other("~/.Trash n'est pas un dossier")),
        Err(_) => {
            std::fs::create_dir(&t)?;
            std::fs::set_permissions(&t, std::fs::Permissions::from_mode(0o700))?;
            Ok(t)
        }
    }
}

/// Move `path` (never followed: a link is moved as a link) into the Trash under a unique name.
pub fn move_to_trash(env: &CleanEnv, path: &Path) -> std::io::Result<PathBuf> {
    let trash = trash_dir(env)?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::other("nom invalide"))?;
    let dest = unique_in(&trash, name);
    std::fs::rename(path, &dest)?;
    Ok(dest)
}

/// Delete `path` without following links.
fn delete(path: &Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

/// Files of `dir` modified before `cutoff` (a file item is its own list).
fn old_files(dir: &Path, cutoff: i64) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .flatten()
        .filter(|e| !e.file_type().is_dir())
        .filter(|e| e.metadata().map(|m| m.mtime() < cutoff).unwrap_or(false))
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn io_message(e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(libc::EPERM) {
        "accès refusé par macOS (Accès complet au disque, SIP ou fichier verrouillé)".into()
    } else if e.raw_os_error() == Some(libc::EXDEV) {
        "sur un autre volume : choisis la suppression définitive".into()
    } else {
        e.to_string()
    }
}

/// Apply a plan. `dry_run` only reports what would happen.
pub fn apply(env: &CleanEnv, plan: &CleanPlan, dry_run: bool) -> CleanApplyReport {
    let open = env.resolve_open_files();
    let mut installed: Option<apps::Installed> = None;
    let mut items: Vec<&CleanPlanItem> = plan.items.iter().collect();
    // Empty the Trash before moving anything into it.
    items.sort_by_key(|i| i.category != CleanCategory::Trash);
    let mut seen = std::collections::HashSet::new();
    let mut report = CleanApplyReport {
        dry_run,
        ..Default::default()
    };
    for item in items {
        if !seen.insert((item.category, item.path.clone())) {
            continue;
        }
        let path = PathBuf::from(&item.path);
        let mut result = CleanItemResult {
            category: item.category,
            path: item.path.clone(),
            outcome: CleanOutcome::Skipped,
            bytes: 0,
            trashed_as: None,
            message: None,
        };
        let target = match validate(env, item.category, &path, &mut installed) {
            Ok(t) => t,
            Err(Rejection::Refused(m)) => {
                result.outcome = CleanOutcome::Refused;
                result.message = Some(m);
                report.skipped += 1;
                report.results.push(result);
                continue;
            }
            Err(Rejection::Skipped(m)) => {
                result.message = Some(m);
                report.skipped += 1;
                report.results.push(result);
                continue;
            }
        };
        if target != Target::TrashContents && open.touches(&path) {
            result.message = Some("utilisé par une application ouverte".into());
            report.skipped += 1;
            report.results.push(result);
            continue;
        }
        let permanent =
            item.category == CleanCategory::Trash || plan.permanent.contains(&item.category);
        let outcome = run_one(env, &path, target, permanent, dry_run, &mut result);
        match outcome {
            Ok(()) if result.outcome == CleanOutcome::Skipped => report.skipped += 1,
            Ok(()) => {
                report.cleaned += 1;
                match result.outcome {
                    CleanOutcome::MovedToTrash => report.trashed_bytes += result.bytes,
                    CleanOutcome::Deleted => report.freed_bytes += result.bytes,
                    _ => {}
                }
            }
            Err(e) => {
                result.outcome = CleanOutcome::Failed;
                result.message = Some(io_message(&e));
                report.failed += 1;
            }
        }
        report.results.push(result);
    }
    report
}

fn run_one(
    env: &CleanEnv,
    path: &Path,
    target: Target,
    permanent: bool,
    dry_run: bool,
    result: &mut CleanItemResult,
) -> std::io::Result<()> {
    match target {
        Target::Whole => {
            result.bytes = measure(path, None).bytes;
            if dry_run {
                result.outcome = CleanOutcome::WouldClean;
            } else if permanent {
                delete(path)?;
                result.outcome = CleanOutcome::Deleted;
            } else {
                let dest = move_to_trash(env, path)?;
                result.trashed_as = Some(dest.display().to_string());
                result.outcome = CleanOutcome::MovedToTrash;
            }
        }
        Target::OldFiles(cutoff) => {
            let files = old_files(path, cutoff);
            if files.is_empty() {
                result.message = Some("rien d'assez ancien".into());
                return Ok(());
            }
            result.bytes = measure(path, Some(cutoff)).bytes;
            if dry_run {
                result.outcome = CleanOutcome::WouldClean;
                return Ok(());
            }
            if permanent || (files.len() == 1 && files[0] == path) {
                if permanent {
                    for f in &files {
                        std::fs::remove_file(f)?;
                    }
                    result.outcome = CleanOutcome::Deleted;
                } else {
                    let dest = move_to_trash(env, path)?;
                    result.trashed_as = Some(dest.display().to_string());
                    result.outcome = CleanOutcome::MovedToTrash;
                }
                return Ok(());
            }
            // Old files of a folder: mirrored into one folder of the Trash.
            let trash = trash_dir(env)?;
            let base = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Journaux");
            let folder = unique_in(&trash, &format!("{base} (anciens journaux)"));
            std::fs::create_dir(&folder)?;
            for f in &files {
                let rel = f.strip_prefix(path).map_err(std::io::Error::other)?;
                let dest = folder.join(rel);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::rename(f, &dest)?;
            }
            result.trashed_as = Some(folder.display().to_string());
            result.outcome = CleanOutcome::MovedToTrash;
        }
        Target::TrashContents => {
            result.bytes = measure(path, None).bytes;
            if dry_run {
                result.outcome = CleanOutcome::WouldClean;
                return Ok(());
            }
            let mut first_err = None;
            for e in std::fs::read_dir(path)?.flatten() {
                if let Err(err) = delete(&e.path()) {
                    first_err.get_or_insert(err);
                }
            }
            if let Some(e) = first_err {
                // Partly emptied: report what is left as the failure.
                result.bytes = result.bytes.saturating_sub(measure(path, None).bytes);
                return Err(e);
            }
            result.outcome = CleanOutcome::Deleted;
        }
    }
    Ok(())
}
