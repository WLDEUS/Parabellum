//! Whole-Mac scan, on demand (IPC `full_scan`, origin `full_scan`) and automatic (origin `scheduled`, at
//! most every `full_scan.interval_days`, started while the Mac is idle and on mains power).
//!
//! What is walked: every top-level folder of the startup disk except `/System` (sealed system volume:
//! signed by Apple and read-only; it also holds `/System/Volumes/Data`, i.e. `/Users`, `/Applications`…
//! a second time), `/Volumes`, `/dev` and `/cores`. Below the roots, only directories on the startup
//! disk's volumes (system + data) are entered: devfs, swap, autofs, network shares and disk images
//! mounted inside a home are left alone. Cloud-only files are skipped (reading one downloads it).
//! On request, the mounted external volumes too (local file systems; never Time Machine backups).
//!
//! One full scan at a time; it has its own slot in the job manager ([`crate::jobs`]), so volume,
//! Downloads and manual scans never wait hours behind it. A completed run (manual or automatic) resets
//! the interval; an automatic run that did not complete is retried after [`RETRY_SECS`].

use crate::backends::ScanOpts;
use crate::ctx::Ctx;
use crate::jobs::{self, JobSpec};
use pb_core::config::FullScanConfig;
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::ScanOrigin;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// kv: Unix time of the end of the last completed full scan (manual or automatic).
pub const KV_LAST_DONE: &str = "full_scan_last_done";
/// kv: Unix time of the last automatic start.
pub const KV_LAST_AUTO_ATTEMPT: &str = "full_scan_last_auto_attempt";
/// Top-level entries of `/` never walked (see the module doc). Hidden entries (`/.vol`, `/.fseventsd`,
/// `/.Spotlight-V100`, `/.nofollow`…) are Apple's on the read-only system volume and skipped too.
pub const SKIPPED_TOP: &[&str] = &["System", "Volumes", "dev", "cores"];
/// An automatic run that did not complete (cancelled, failed, daemon restarted) is retried after this.
pub const RETRY_SECS: i64 = 20 * 3600;
/// First check after the daemon starts (the DB update and component install go first).
const STARTUP_DELAY: Duration = Duration::from_secs(15 * 60);
/// Then every…
const CHECK_EVERY: Duration = Duration::from_secs(10 * 60);

/// Full-scan job (manual or automatic).
pub fn is_full(origin: ScanOrigin) -> bool {
    matches!(origin, ScanOrigin::FullScan | ScanOrigin::Scheduled)
}

/// What a full scan walks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub roots: Vec<PathBuf>,
    /// File systems the walk may enter (`st_dev`).
    pub devices: Vec<u64>,
    /// External volumes added to the roots.
    pub volumes: Vec<PathBuf>,
}

/// Roots and file systems of a full scan of the disk mounted at `root` (`/`), external volumes taken
/// from `root/Volumes` when `external`.
pub fn plan(root: &Path, external: bool) -> Plan {
    let mut p = Plan::default();
    for fs_root in [root.to_path_buf(), root.join("System/Volumes/Data")] {
        if let Ok(m) = std::fs::metadata(&fs_root) {
            if !p.devices.contains(&m.dev()) {
                p.devices.push(m.dev());
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(root) {
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') || SKIPPED_TOP.contains(&name.as_ref()) {
                continue;
            }
            let path = e.path();
            let Ok(m) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            // `/etc`, `/tmp`, `/var` → `/private/…`: walked there.
            if m.file_type().is_symlink() {
                continue;
            }
            // Another file system mounted at the top (devfs, autofs…).
            if m.is_dir() && !p.devices.contains(&m.dev()) {
                continue;
            }
            p.roots.push(path);
        }
    }
    p.roots.sort();
    if external {
        for vol in external_volumes(&root.join("Volumes"), &p.devices) {
            if let Ok(m) = std::fs::metadata(&vol) {
                if !p.devices.contains(&m.dev()) {
                    p.devices.push(m.dev());
                }
            }
            p.roots.push(vol.clone());
            p.volumes.push(vol);
        }
    }
    p
}

/// Mounted volumes under `volumes_dir` worth a full scan: real folders (not the startup disk's
/// symlink), another file system than `startup`, local (no network share), not a Time Machine backup.
fn external_volumes(volumes_dir: &Path, startup: &[u64]) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(volumes_dir) else {
        return vec![];
    };
    let exists = |p: &Path| std::fs::symlink_metadata(p).is_ok();
    let mut out: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|v| {
            let Ok(m) = std::fs::symlink_metadata(v) else {
                return false;
            };
            m.is_dir()
                && !startup.contains(&m.dev())
                && is_local_fs(v)
                && !crate::router::is_backup_volume(v, &exists)
                && !v
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        })
        .collect();
    out.sort();
    out
}

/// Local file system (not SMB / NFS / AFP / WebDAV), per `statfs` `MNT_LOCAL`. Other systems: true.
fn is_local_fs(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: statfs fills the zeroed struct from a valid NUL-terminated path; read only on success.
        unsafe {
            let mut st: libc::statfs = std::mem::zeroed();
            if libc::statfs(c.as_ptr(), &mut st) != 0 {
                return false;
            }
            st.f_flags & (libc::MNT_LOCAL as u32) != 0
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        true
    }
}

/// Queue a full scan. `use_clamav` / `external` override the configuration.
pub async fn start(
    ctx: &Arc<Ctx>,
    origin: ScanOrigin,
    use_clamav: Option<bool>,
    external: Option<bool>,
) -> Result<String, IpcError> {
    if ctx.jobs.active().iter().any(|j| is_full(j.origin())) {
        return Err(IpcError::new(
            ErrorCode::Busy,
            "une analyse complète est déjà en cours",
        ));
    }
    let cfg = ctx.config();
    let external = external.unwrap_or(cfg.full_scan.external_volumes);
    let plan = tokio::task::spawn_blocking(move || plan(Path::new("/"), external))
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?;
    if plan.roots.is_empty() {
        return Err(IpcError::new(
            ErrorCode::Internal,
            "aucun dossier à analyser sur le disque de démarrage",
        ));
    }
    // Shown as the job's target: what was asked, not the dozen top-level roots.
    let mut paths = vec!["/".to_string()];
    paths.extend(
        plan.volumes
            .iter()
            .map(|v| v.to_string_lossy().into_owned()),
    );
    let spec = JobSpec {
        report_only: false,
        paths,
        roots: plan.roots,
        opts: ScanOpts {
            origin,
            use_clamav: use_clamav.unwrap_or(cfg.full_scan.clamav),
            recursive: true,
            only_risky_types: false,
            inert_text: false,
            allowed_devices: plan.devices,
            skip_dataless: true,
        },
    };
    // Checked again after the (blocking) plan: a second request may have queued one meanwhile.
    if ctx.jobs.active().iter().any(|j| is_full(j.origin())) {
        return Err(IpcError::new(
            ErrorCode::Busy,
            "une analyse complète est déjà en cours",
        ));
    }
    jobs::submit(ctx, spec).await
}

/// A full scan completed (called by the job runner).
pub async fn record_done(ctx: &Arc<Ctx>, at: i64) {
    let v = at.to_string();
    if let Err(e) = ctx.store.run(move |s| s.kv_set(KV_LAST_DONE, &v)).await {
        tracing::warn!(error = %e, "cannot record the full scan");
    }
}

/// Is an automatic run due? Interval since the last completed scan, and no automatic start in the last
/// [`RETRY_SECS`] (a run you cancelled is not restarted ten minutes later).
pub fn auto_due(
    now: i64,
    last_done: Option<i64>,
    last_attempt: Option<i64>,
    interval_days: u32,
) -> bool {
    let interval = i64::from(interval_days.max(1)) * 86_400;
    last_done.is_none_or(|t| now - t >= interval)
        && last_attempt.is_none_or(|t| now - t >= RETRY_SECS)
}

/// Idle long enough and on mains power (as configured).
async fn conditions_met(fs: &FullScanConfig) -> bool {
    if fs.idle_minutes > 0 {
        let idle = crate::mailagent::idle_seconds().await.unwrap_or(0);
        if idle < u64::from(fs.idle_minutes) * 60 {
            return false;
        }
    }
    !fs.require_ac_power || crate::mailagent::on_ac_power().await
}

/// Automatic full scan: checked every 10 minutes (wall clock, so a Mac that slept catches up).
pub async fn schedule_loop(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    let mut wait = STARTUP_DELAY;
    loop {
        tokio::select! {
            _ = crate::system::sleep_until_wall(crate::system::wall_deadline(wait)) => {}
            _ = shutdown.changed() => if *shutdown.borrow() { return; },
        }
        wait = CHECK_EVERY;
        let cfg = ctx.config();
        if !cfg.full_scan.auto
            || ctx.should_defer_heavy_work()
            || ctx.jobs.active().iter().any(|j| is_full(j.origin()))
            // No threat DB yet (first install): a scan now would find nothing.
            || ctx.engine().db_status().version.is_none()
        {
            continue;
        }
        let (done, attempt) = ctx
            .store
            .run(|s| {
                Ok((
                    s.kv_get_i64(KV_LAST_DONE)?,
                    s.kv_get_i64(KV_LAST_AUTO_ATTEMPT)?,
                ))
            })
            .await
            .unwrap_or((None, None));
        let now = pb_core::now_ts();
        if !auto_due(now, done, attempt, cfg.full_scan.interval_days)
            || !conditions_met(&cfg.full_scan).await
        {
            continue;
        }
        let v = now.to_string();
        let _ = ctx
            .store
            .run(move |s| s.kv_set(KV_LAST_AUTO_ATTEMPT, &v))
            .await;
        match start(&ctx, ScanOrigin::Scheduled, None, None).await {
            Ok(id) => tracing::info!(job = %id, "automatic full scan queued"),
            Err(e) => tracing::info!(error = %e.message, "automatic full scan not started"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_rules() {
        let day = 86_400;
        let now = 100 * day;
        assert!(auto_due(now, None, None, 7), "never done");
        assert!(!auto_due(now, Some(now - 6 * day), None, 7));
        assert!(auto_due(now, Some(now - 7 * day), None, 7));
        // Started 2 h ago and cancelled / interrupted: not again before RETRY_SECS.
        assert!(!auto_due(now, Some(now - 8 * day), Some(now - 7200), 7));
        assert!(auto_due(
            now,
            Some(now - 8 * day),
            Some(now - RETRY_SECS),
            7
        ));
        assert!(
            auto_due(now, Some(now - day), Some(now - day), 0),
            "0 is read as 1 day"
        );
    }

    #[test]
    fn plan_skips_system_hidden_symlinks_and_volumes() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        for dir in [
            "Applications",
            "Users/q",
            "Library",
            "private/var",
            "opt/homebrew",
            "System/Library",
            "System/Volumes/Data/Users",
            "Volumes/Clé",
            "dev",
            "cores",
            ".vol",
            ".fseventsd",
        ] {
            std::fs::create_dir_all(r.join(dir)).unwrap();
        }
        std::os::unix::fs::symlink(r.join("private/var"), r.join("var")).unwrap();
        std::os::unix::fs::symlink(r, r.join("Volumes/Macintosh HD")).unwrap();
        std::fs::write(r.join("top.sh"), "#!/bin/sh\n").unwrap();

        let p = plan(r, false);
        let names: Vec<_> = p
            .roots
            .iter()
            .map(|x| x.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "Applications",
                "Library",
                "Users",
                "opt",
                "private",
                "top.sh"
            ]
        );
        assert!(p.volumes.is_empty());
        let dev = std::fs::metadata(r).unwrap().dev();
        assert_eq!(p.devices, vec![dev]);

        // Same file system here: a "volume" on the startup disk is not an external volume.
        let p = plan(r, true);
        assert!(p.volumes.is_empty(), "{:?}", p.volumes);
    }

    #[test]
    fn backup_volumes_are_recognised() {
        let no = |_: &Path| false;
        assert!(crate::router::is_backup_volume(
            Path::new("/Volumes/Backups of Mac"),
            &no
        ));
        assert!(!crate::router::is_backup_volume(
            Path::new("/Volumes/Clé"),
            &no
        ));
        let marker = |p: &Path| p.ends_with("backup_manifest.plist");
        assert!(crate::router::is_backup_volume(
            Path::new("/Volumes/TM"),
            &marker
        ));
    }
}
