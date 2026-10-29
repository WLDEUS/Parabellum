//! APFS local snapshots of the data volume (`tmutil localsnapshot`, purged by macOS after ~24 h) and restore of
//! a file or folder from one: the snapshot is mounted read-only in a private mount point and `ditto` copies the
//! item **as the console user** to `~/Parabellum-Restauration/<snapshot>/<path relative to home>` (nothing is
//! overwritten, no root write into the home folder).

use crate::ctx::Ctx;
use crate::system::run_command;
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::SnapshotInfo;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

pub const TMUTIL: &str = "/usr/bin/tmutil";
pub const MOUNT_APFS: &str = "/sbin/mount_apfs";
pub const UMOUNT: &str = "/sbin/umount";
pub const DITTO: &str = "/usr/bin/ditto";
pub const DATA_VOLUME: &str = "/System/Volumes/Data";
/// Folder (in the user's home) receiving restored items.
pub const RESTORE_DIR: &str = "Parabellum-Restauration";
/// kv: snapshot dates created by Parabellum (JSON array of `YYYY-MM-DD-HHMMSS`).
pub const KV_OURS: &str = "guard_snapshots_ours";
const CMD_TIMEOUT: Duration = Duration::from_secs(120);

/// `com.apple.TimeMachine.2026-10-29-120000.local` -> `2026-10-29-120000`.
pub fn snapshot_date(name: &str) -> Option<&str> {
    let d = name
        .strip_prefix("com.apple.TimeMachine.")?
        .strip_suffix(".local")?;
    let ok = d.len() == 17
        && d.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 | 10 => b == b'-',
            _ => b.is_ascii_digit(),
        });
    ok.then_some(d)
}

/// Unix time of a snapshot date (local time).
pub fn date_to_ts(d: &str) -> Option<i64> {
    use chrono::{Local, NaiveDateTime, TimeZone};
    let ndt = NaiveDateTime::parse_from_str(d, "%Y-%m-%d-%H%M%S").ok()?;
    Local
        .from_local_datetime(&ndt)
        .earliest()
        .map(|t| t.timestamp())
}

/// `tmutil listlocalsnapshots /` output (one name per line, optional header).
pub fn parse_list(out: &str, ours: &[String]) -> Vec<SnapshotInfo> {
    let mut v: Vec<SnapshotInfo> = out
        .lines()
        .map(str::trim)
        .filter_map(|l| {
            let d = snapshot_date(l)?;
            Some(SnapshotInfo {
                name: l.to_string(),
                created_at: date_to_ts(d),
                ours: ours.iter().any(|o| o == d),
            })
        })
        .collect();
    v.sort_by(|a, b| b.name.cmp(&a.name));
    v.dedup_by(|a, b| a.name == b.name);
    v
}

/// `Created local snapshot with date: 2026-10-29-120000` -> date.
pub fn parse_created(out: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let d = l.trim().rsplit(' ').next()?;
        snapshot_date(&format!("com.apple.TimeMachine.{d}.local")).map(str::to_string)
    })
}

/// Path to restore must be absolute, inside `home`, without `..` / `.` components.
pub fn relative_to_home(path: &Path, home: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("chemin absolu requis".into());
    }
    if path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("chemin invalide".into());
    }
    let rel = path.strip_prefix(home).map_err(|_| {
        "seuls les fichiers de votre dossier personnel peuvent être restaurés".to_string()
    })?;
    if rel.as_os_str().is_empty() {
        return Err("choisissez un fichier ou un dossier, pas tout le dossier personnel".into());
    }
    if rel.starts_with(RESTORE_DIR) {
        return Err("dossier de restauration".into());
    }
    Ok(rel.to_path_buf())
}

async fn ours(ctx: &Ctx) -> Vec<String> {
    ctx.store
        .run(|s| s.kv_get(KV_OURS))
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn unavailable(msg: impl Into<String>) -> IpcError {
    IpcError::new(ErrorCode::Unavailable, msg)
}

/// Local snapshots of the data volume, newest first.
pub async fn list(ctx: &Arc<Ctx>) -> Result<Vec<SnapshotInfo>, IpcError> {
    if !cfg!(target_os = "macos") {
        return Err(unavailable("instantanés APFS : macOS uniquement"));
    }
    let out = run_command(TMUTIL, &["listlocalsnapshots", "/"], CMD_TIMEOUT)
        .await
        .map_err(unavailable)?;
    if !out.success() {
        return Err(unavailable(format!(
            "tmutil listlocalsnapshots : {}",
            out.stderr.trim()
        )));
    }
    let ours = ours(ctx).await;
    Ok(parse_list(&out.stdout, &ours))
}

/// Create a snapshot now.
pub async fn create(ctx: &Arc<Ctx>) -> Result<SnapshotInfo, IpcError> {
    if !cfg!(target_os = "macos") {
        return Err(unavailable("instantanés APFS : macOS uniquement"));
    }
    let out = run_command(TMUTIL, &["localsnapshot"], CMD_TIMEOUT)
        .await
        .map_err(unavailable)?;
    let date = parse_created(&out.stdout)
        .filter(|_| out.success())
        .ok_or_else(|| {
            unavailable(format!(
                "tmutil localsnapshot a échoué : {}",
                if out.stderr.trim().is_empty() {
                    out.stdout.trim()
                } else {
                    out.stderr.trim()
                }
            ))
        })?;
    let mut list = ours(ctx).await;
    list.push(date.clone());
    // Keep the last 200 (macOS purges after ~24 h anyway).
    let skip = list.len().saturating_sub(200);
    let list: Vec<String> = list.into_iter().skip(skip).collect();
    let json = serde_json::to_string(&list).unwrap_or_else(|_| "[]".into());
    ctx.store.run(move |s| s.kv_set(KV_OURS, &json)).await?;
    Ok(SnapshotInfo {
        name: format!("com.apple.TimeMachine.{date}.local"),
        created_at: date_to_ts(&date),
        ours: true,
    })
}

/// Restore `path` from `snapshot` into `~/Parabellum-Restauration/<snapshot date>/<relative path>`.
pub async fn restore(ctx: &Arc<Ctx>, snapshot: &str, path: &str) -> Result<String, IpcError> {
    let bad = |m: String| IpcError::new(ErrorCode::BadRequest, m);
    let date = snapshot_date(snapshot)
        .ok_or_else(|| bad(format!("instantané invalide : {snapshot}")))?
        .to_string();
    let user =
        crate::system::console_user().ok_or_else(|| unavailable("aucun utilisateur connecté"))?;
    if user.uid == 0 {
        return Err(unavailable("restauration impossible pour root"));
    }
    let rel = relative_to_home(Path::new(path), &user.home).map_err(bad)?;
    if !cfg!(target_os = "macos") {
        return Err(unavailable("instantanés APFS : macOS uniquement"));
    }
    let known = list(ctx).await?;
    if !known.iter().any(|s| s.name == snapshot) {
        return Err(IpcError::new(
            ErrorCode::NotFound,
            format!("instantané {snapshot} introuvable"),
        ));
    }
    let gid = crate::system::user_gid(user.uid)
        .ok_or_else(|| unavailable("groupe de l'utilisateur introuvable"))?;
    // Root-owned 0755 mount point outside our private tmp (the user-side ditto must traverse it).
    let mount = PathBuf::from(format!(
        "/private/var/tmp/parabellum-snapshot-{}",
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir(&mount)
        .map_err(|e| IpcError::new(ErrorCode::Internal, format!("point de montage : {e}")))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&mount, std::fs::Permissions::from_mode(0o755));
    }
    let mount_s = mount.to_string_lossy().to_string();
    let mut mounted = false;
    let mut last_err = String::new();
    for volume in [DATA_VOLUME, "/"] {
        match run_command(
            MOUNT_APFS,
            &["-o", "rdonly,nobrowse", "-s", snapshot, volume, &mount_s],
            CMD_TIMEOUT,
        )
        .await
        {
            Ok(o) if o.success() => {
                mounted = true;
                break;
            }
            Ok(o) => last_err = o.stderr.trim().to_string(),
            Err(e) => last_err = e,
        }
    }
    if !mounted {
        let _ = std::fs::remove_dir(&mount);
        return Err(unavailable(format!(
            "montage de l'instantané impossible : {last_err}"
        )));
    }
    // Inside the data-volume snapshot the home folder is at its usual path (`/Users/<name>`).
    let home_in_snap = user
        .home
        .strip_prefix("/")
        .map(|h| mount.join(h))
        .unwrap_or_else(|_| mount.join(&user.home));
    let src = home_in_snap.join(&rel);
    let dest = user.home.join(RESTORE_DIR).join(&date).join(&rel);
    let result = if std::fs::symlink_metadata(&src).is_err() {
        Err(IpcError::new(
            ErrorCode::NotFound,
            format!("{path} n'existait pas dans l'instantané du {date}"),
        ))
    } else {
        let mut cmd = tokio::process::Command::new(DITTO);
        cmd.arg(&src)
            .arg(&dest)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &user.home)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .uid(user.uid)
            .gid(gid);
        match tokio::time::timeout(Duration::from_secs(1800), cmd.output()).await {
            Ok(Ok(o)) if o.status.success() => Ok(dest.to_string_lossy().to_string()),
            Ok(Ok(o)) => Err(IpcError::new(
                ErrorCode::Internal,
                format!("ditto : {}", String::from_utf8_lossy(&o.stderr).trim()),
            )),
            Ok(Err(e)) => Err(IpcError::new(ErrorCode::Internal, format!("ditto : {e}"))),
            Err(_) => Err(IpcError::new(ErrorCode::Internal, "ditto : délai dépassé")),
        }
    };
    let _ = run_command(UMOUNT, &[&mount_s], CMD_TIMEOUT).await;
    let _ = std::fs::remove_dir(&mount);
    if let Ok(d) = &result {
        tracing::info!(snapshot, path, dest = %d, "restored from snapshot");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_dates() {
        assert_eq!(
            snapshot_date("com.apple.TimeMachine.2026-10-29-120000.local"),
            Some("2026-10-29-120000")
        );
        assert_eq!(
            snapshot_date("com.apple.TimeMachine.2026-10-29-120000"),
            None
        );
        assert_eq!(
            snapshot_date("com.apple.TimeMachine.2026-1x-29-120000.local"),
            None
        );
        assert!(date_to_ts("2026-10-29-120000").is_some());
        let out = "Snapshots for disk /:\ncom.apple.TimeMachine.2026-10-29-110000.local\ncom.apple.TimeMachine.2026-10-29-120000.local\ncom.apple.os.update-ABC\n";
        let l = parse_list(out, &["2026-10-29-120000".into()]);
        assert_eq!(l.len(), 2);
        assert_eq!(l[0].name, "com.apple.TimeMachine.2026-10-29-120000.local");
        assert!(l[0].ours && !l[1].ours);
        assert_eq!(
            parse_created("Created local snapshot with date: 2026-10-29-130501\n").as_deref(),
            Some("2026-10-29-130501")
        );
        assert_eq!(parse_created("error"), None);
    }

    #[test]
    fn restore_paths() {
        let home = Path::new("/Users/q");
        assert_eq!(
            relative_to_home(Path::new("/Users/q/Documents/a.docx"), home).unwrap(),
            PathBuf::from("Documents/a.docx")
        );
        assert!(relative_to_home(Path::new("/Users/q"), home).is_err());
        assert!(relative_to_home(Path::new("/Users/q/../other/x"), home).is_err());
        assert!(relative_to_home(Path::new("/etc/passwd"), home).is_err());
        assert!(relative_to_home(Path::new("Documents/a"), home).is_err());
        assert!(relative_to_home(Path::new("/Users/q/Parabellum-Restauration/x"), home).is_err());
    }
}
