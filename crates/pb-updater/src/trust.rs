//! "Is it safe for root to execute this binary?"
//!
//! A binary is *trusted* when its canonical path (symlinks resolved), the file itself and every parent
//! directory up to `/` are owned by root and not writable by group or others. Anything else (Homebrew
//! under `/opt/homebrew`, a user-owned `/usr/local/bin`…) could be replaced by an unprivileged user, so
//! root must not execute it: callers either skip it or run it as the unprivileged owner
//! ([`TrustInfo::run_as`]). The canonical path is what gets executed, so swapping a symlink after the
//! check has no effect.

use std::path::{Path, PathBuf};

/// Result of [`inspect_binary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustInfo {
    /// Canonical path (execute this one).
    pub canonical: PathBuf,
    /// Root-owned, not group/world-writable, all parents too.
    pub trusted: bool,
    /// Why it is not trusted (empty when trusted).
    pub reasons: Vec<String>,
    /// Unprivileged identity `(uid, gid)` to run it as when untrusted: the first non-root owner found
    /// (file, then parents). `None` when trusted or when no unprivileged owner exists.
    pub run_as: Option<(u32, u32)>,
}

/// True when the current process is root (only then does trust matter).
pub fn running_as_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// Inspect `path` (checks every ancestor up to `/`).
pub fn inspect_binary(path: &Path) -> std::io::Result<TrustInfo> {
    inspect_binary_under(path, Path::new("/"))
}

/// Same as [`inspect_binary`], but ancestors are only checked up to (and including) `boundary`
/// (tests run under a temporary directory whose parents, like `/tmp`, are world-writable).
#[cfg(unix)]
pub(crate) fn inspect_binary_under(path: &Path, boundary: &Path) -> std::io::Result<TrustInfo> {
    use std::os::unix::fs::MetadataExt;
    let canonical = std::fs::canonicalize(path)?;
    let md = std::fs::metadata(&canonical)?;
    if !md.is_file() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{} n'est pas un fichier", canonical.display())));
    }
    let mut reasons = Vec::new();
    let mut run_as = None;
    let mut check = |p: &Path, md: &std::fs::Metadata| {
        if md.uid() != 0 {
            reasons.push(format!("{} appartient à l'uid {}", p.display(), md.uid()));
            run_as.get_or_insert((md.uid(), md.gid()));
        }
        if md.mode() & 0o022 != 0 {
            reasons.push(format!("{} est modifiable par le groupe ou par tous", p.display()));
        }
    };
    check(&canonical, &md);
    for dir in canonical.ancestors().skip(1) {
        let dmd = std::fs::metadata(dir)?;
        check(dir, &dmd);
        if dir == boundary {
            break;
        }
    }
    let trusted = reasons.is_empty();
    Ok(TrustInfo { canonical, trusted, reasons, run_as: if trusted { None } else { run_as } })
}

#[cfg(not(unix))]
pub(crate) fn inspect_binary_under(path: &Path, _boundary: &Path) -> std::io::Result<TrustInfo> {
    Ok(TrustInfo { canonical: path.to_path_buf(), trusted: false, reasons: vec!["plateforme non unix".into()], run_as: None })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    #[test]
    fn trusted_only_when_root_owned_and_not_writable() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        mode(root, 0o755);
        let bin_dir = root.join("bin");
        std::fs::create_dir(&bin_dir).unwrap();
        mode(&bin_dir, 0o755);
        let bin = bin_dir.join("tool");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        mode(&bin, 0o755);
        let link = root.join("link");
        std::os::unix::fs::symlink(&bin, &link).unwrap();

        let me = unsafe { libc::geteuid() };
        let info = inspect_binary_under(&link, root).unwrap();
        assert_eq!(info.canonical, std::fs::canonicalize(&bin).unwrap(), "symlinks are resolved");
        assert_eq!(info.trusted, me == 0, "{:?}", info.reasons);

        // World-writable file.
        mode(&bin, 0o777);
        let info = inspect_binary_under(&bin, root).unwrap();
        assert!(!info.trusted);
        assert!(info.reasons.iter().any(|r| r.contains("modifiable")));
        mode(&bin, 0o755);

        // Group-writable parent directory.
        mode(&bin_dir, 0o775);
        assert!(!inspect_binary_under(&bin, root).unwrap().trusted);
        mode(&bin_dir, 0o755);

        if me == 0 {
            // Parent owned by a user (Homebrew-like): untrusted, run as that user.
            std::os::unix::fs::chown(&bin_dir, Some(501), Some(20)).unwrap();
            let info = inspect_binary_under(&bin, root).unwrap();
            assert!(!info.trusted);
            assert_eq!(info.run_as, Some((501, 20)));
            // File owned by another user wins as identity.
            std::os::unix::fs::chown(&bin, Some(502), Some(20)).unwrap();
            assert_eq!(inspect_binary_under(&bin, root).unwrap().run_as, Some((502, 20)));
            std::os::unix::fs::chown(&bin_dir, Some(0), Some(0)).unwrap();
            std::os::unix::fs::chown(&bin, Some(0), Some(0)).unwrap();
            // Root-owned but world-writable dir: untrusted and no unprivileged identity ⇒ must be skipped.
            mode(&bin_dir, 0o777);
            let info = inspect_binary_under(&bin, root).unwrap();
            assert!(!info.trusted && info.run_as.is_none());
            mode(&bin_dir, 0o755);
        }

        // /tmp (sticky, world-writable) is never a trusted ancestor.
        assert!(!inspect_binary(&bin).unwrap().trusted);
        assert!(inspect_binary_under(&bin_dir, root).is_err(), "directories are not binaries");
        assert!(inspect_binary(&root.join("missing")).is_err());
    }
}
