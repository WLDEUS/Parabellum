//! Parabellum self-update through a one-shot launchd job.
//!
//! The package's scripts stop and restart `parabellumd`, so the installer must not be a child of the
//! daemon (nor write into pipes the daemon owns). Flow:
//! 1. the downloaded `.pkg` is minisign-verified (by the caller), copied into a fresh root-only
//!    (`0700`) staging directory `state/selfupdate/`, and the **copy** is verified again (it cannot be
//!    swapped afterwards);
//! 2. the marker `state/self-update.marker` is written — the package `preinstall` then skips booting
//!    the daemon out (the postinstall restarts it with `kickstart -k`);
//! 3. `state/selfupdate.plist` (label [`SELFUPDATE_LABEL`]) runs `/usr/sbin/installer -pkg <copy> -target /`
//!    once, output to `<log_dir>/selfupdate.log`, and is loaded with `launchctl bootstrap system`
//!    (a stale job with the same label is booted out first).
//!
//! At the next start the daemon calls [`finish_self_update`] to remove the marker, the staged package and
//! the plist (the finished job itself is not booted out then, in case the installer is still finishing).

use crate::process::{run, RunOpts};
use crate::signing::verify_file_async;
use crate::UpdateError;
use pb_core::paths::Paths;
use std::path::{Path, PathBuf};

/// launchd label of the one-shot installer job.
pub const SELFUPDATE_LABEL: &str = "com.wldeus.parabellum.selfupdate";
const LAUNCHCTL: &str = "/bin/launchctl";
const INSTALLER: &str = "/usr/sbin/installer";

/// `state/self-update.marker` (checked by the package `preinstall`).
pub fn self_update_marker(paths: &Paths) -> PathBuf {
    paths.state_dir().join("self-update.marker")
}

/// `state/selfupdate.plist` (the transient launchd job).
pub fn self_update_plist(paths: &Paths) -> PathBuf {
    paths.state_dir().join("selfupdate.plist")
}

/// `state/selfupdate/` (root-only staging directory of the verified package).
pub fn self_update_staging_dir(paths: &Paths) -> PathBuf {
    paths.state_dir().join("selfupdate")
}

/// `<log_dir>/selfupdate.log` (installer output).
pub fn self_update_log(paths: &Paths) -> PathBuf {
    paths.log_dir.join("selfupdate.log")
}

/// XML plist of the one-shot job (`RunAtLoad`, no `KeepAlive`, output to `log`).
pub(crate) fn render_job_plist(pkg: &Path, log: &Path) -> Result<String, UpdateError> {
    use plist::{Dictionary, Value};
    let mut d = Dictionary::new();
    d.insert("Label".into(), Value::String(SELFUPDATE_LABEL.into()));
    d.insert(
        "ProgramArguments".into(),
        Value::Array(
            [INSTALLER, "-pkg", &pkg.to_string_lossy(), "-target", "/"]
                .iter()
                .map(|s| Value::String((*s).to_string()))
                .collect(),
        ),
    );
    d.insert("RunAtLoad".into(), Value::Boolean(true));
    d.insert("KeepAlive".into(), Value::Boolean(false));
    d.insert("AbandonProcessGroup".into(), Value::Boolean(true));
    d.insert("ProcessType".into(), Value::String("Standard".into()));
    d.insert("StandardOutPath".into(), Value::String(log.to_string_lossy().into_owned()));
    d.insert("StandardErrorPath".into(), Value::String(log.to_string_lossy().into_owned()));
    d.insert("WorkingDirectory".into(), Value::String("/".into()));
    let mut out = Vec::new();
    Value::Dictionary(d)
        .to_writer_xml(&mut out)
        .map_err(|e| UpdateError::Command(format!("plist : {e}")))?;
    String::from_utf8(out).map_err(|e| UpdateError::Command(format!("plist : {e}")))
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_p: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

/// Copy the verified package into a fresh root-only directory and verify the copy again.
/// Returns the staged path.
pub(crate) async fn stage_verified_pkg(
    paths: &Paths,
    downloaded: &Path,
    version: &str,
    sig_text: &str,
    public_key: &str,
) -> Result<PathBuf, UpdateError> {
    if version.is_empty() || !version.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Err(UpdateError::Verification(format!("version invalide : {version}")));
    }
    let staging = self_update_staging_dir(paths);
    match std::fs::remove_dir_all(&staging) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    std::fs::create_dir_all(paths.state_dir())?;
    std::fs::create_dir(&staging)?; // fails if something re-created it meanwhile
    set_mode(&staging, 0o700)?;
    let staged = staging.join(format!("Parabellum-{version}.pkg"));
    {
        let mut src = std::fs::File::open(downloaded)?;
        let mut dst = std::fs::OpenOptions::new().write(true).create_new(true).open(&staged)?;
        std::io::copy(&mut src, &mut dst)?;
        dst.sync_all()?;
    }
    set_mode(&staged, 0o600)?;
    verify_file_async(&staged, sig_text.to_string(), public_key.to_string()).await?;
    Ok(staged)
}

/// Stage + verify the package, write the marker and the job plist, and hand the installation to launchd.
/// Returns immediately; the daemon is restarted by the package's postinstall.
pub(crate) async fn launch_self_update(
    paths: &Paths,
    downloaded: &Path,
    version: &str,
    sig_text: &str,
    public_key: &str,
) -> Result<String, UpdateError> {
    if !cfg!(target_os = "macos") {
        return Err(UpdateError::Unsupported("mise à jour de Parabellum (macOS uniquement)".into()));
    }
    let staged = stage_verified_pkg(paths, downloaded, version, sig_text, public_key).await?;
    let marker = self_update_marker(paths);
    crate::fsutil::atomic_write(&marker, format!("{version}\n{}\n", pb_core::now_ts()).as_bytes())?;
    set_mode(&marker, 0o644)?;
    let log = self_update_log(paths);
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let plist_path = self_update_plist(paths);
    crate::fsutil::atomic_write(&plist_path, render_job_plist(&staged, &log)?.as_bytes())?;
    set_mode(&plist_path, 0o644)?;

    let target = format!("system/{SELFUPDATE_LABEL}");
    // A finished job from a previous update stays loaded: remove it (errors = not loaded).
    let _ = run(Path::new(LAUNCHCTL), ["bootout", target.as_str()], RunOpts::timeout(30)).await;
    let plist_arg = plist_path.to_string_lossy().into_owned();
    let res = run(Path::new(LAUNCHCTL), ["bootstrap", "system", plist_arg.as_str()], RunOpts::timeout(30)).await;
    match res {
        Ok(out) if out.success() => {
            tracing::warn!(version, "Parabellum update handed to launchd; the daemon will be restarted by the package");
            Ok(format!(
                "Installation de Parabellum {version} lancée (journal : {}) — le service va redémarrer",
                log.display()
            ))
        }
        other => {
            let _ = std::fs::remove_file(&marker);
            let why = match other {
                Ok(out) => out.summary(),
                Err(e) => e.to_string(),
            };
            Err(UpdateError::Command(format!("launchctl bootstrap : {why}")))
        }
    }
}

/// Daemon start-up housekeeping after a self-update: returns the version recorded in the marker (if a
/// self-update was in progress) and removes the marker, the staged package and the job plist.
pub fn finish_self_update(paths: &Paths) -> Option<String> {
    let marker = self_update_marker(paths);
    let version = std::fs::read_to_string(&marker)
        .ok()
        .and_then(|s| s.lines().next().map(|l| l.trim().to_string()))
        .filter(|v| !v.is_empty() && v.len() < 32);
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::remove_dir_all(self_update_staging_dir(paths));
    let _ = std::fs::remove_file(self_update_plist(paths));
    version
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::test_keys::TestKey;

    #[test]
    fn job_plist_is_a_one_shot_installer() {
        let xml = render_job_plist(
            Path::new("/Library/Application Support/Parabellum/state/selfupdate/Parabellum-0.2.0.pkg"),
            Path::new("/Library/Logs/Parabellum/selfupdate.log"),
        )
        .unwrap();
        let v = plist::Value::from_reader_xml(xml.as_bytes()).unwrap();
        let d = v.as_dictionary().unwrap();
        assert_eq!(d.get("Label").and_then(|x| x.as_string()), Some(SELFUPDATE_LABEL));
        let args: Vec<&str> = d
            .get("ProgramArguments")
            .and_then(|a| a.as_array())
            .unwrap()
            .iter()
            .map(|x| x.as_string().unwrap())
            .collect();
        assert_eq!(
            args,
            vec![
                "/usr/sbin/installer",
                "-pkg",
                "/Library/Application Support/Parabellum/state/selfupdate/Parabellum-0.2.0.pkg",
                "-target",
                "/"
            ]
        );
        assert_eq!(d.get("RunAtLoad").and_then(|x| x.as_boolean()), Some(true));
        assert_eq!(d.get("KeepAlive").and_then(|x| x.as_boolean()), Some(false));
        assert_eq!(
            d.get("StandardOutPath").and_then(|x| x.as_string()),
            Some("/Library/Logs/Parabellum/selfupdate.log")
        );
        assert_eq!(d.get("StandardErrorPath"), d.get("StandardOutPath"));
        // Special characters are escaped by the plist writer.
        let xml = render_job_plist(Path::new("/x/a&b<c>.pkg"), Path::new("/l")).unwrap();
        assert!(xml.contains("a&amp;b&lt;c&gt;.pkg"));
    }

    #[tokio::test]
    async fn staging_verifies_the_root_only_copy() {
        let key = TestKey::new();
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(d.path());
        let dl = d.path().join("Parabellum-0.2.0.pkg");
        std::fs::write(&dl, b"xar! fake pkg").unwrap();
        let sig = key.sign(b"xar! fake pkg");
        let staged = stage_verified_pkg(&paths, &dl, "0.2.0", &sig, &key.public_b64()).await.unwrap();
        assert_eq!(staged, self_update_staging_dir(&paths).join("Parabellum-0.2.0.pkg"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(self_update_staging_dir(&paths)).unwrap().permissions().mode();
            assert_eq!(m & 0o777, 0o700);
        }
        // Tampered download: the copy fails verification.
        std::fs::write(&dl, b"xar! evil pkg").unwrap();
        assert!(matches!(
            stage_verified_pkg(&paths, &dl, "0.2.0", &sig, &key.public_b64()).await,
            Err(UpdateError::Signature(_))
        ));
        assert!(stage_verified_pkg(&paths, &dl, "../x", &sig, &key.public_b64()).await.is_err());
        if !cfg!(target_os = "macos") {
            assert!(matches!(
                launch_self_update(&paths, &dl, "0.2.0", &sig, &key.public_b64()).await,
                Err(UpdateError::Unsupported(_))
            ));
        }
        // Housekeeping.
        std::fs::write(self_update_marker(&paths), "0.2.0\n1761400000\n").unwrap();
        assert_eq!(finish_self_update(&paths).as_deref(), Some("0.2.0"));
        assert!(!self_update_marker(&paths).exists() && !self_update_staging_dir(&paths).exists());
        assert_eq!(finish_self_update(&paths), None);
    }
}
