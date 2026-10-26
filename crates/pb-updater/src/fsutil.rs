//! Small filesystem helpers: atomic writes, atomic symlink swap, bounded reads, fsync of directories.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Sibling temporary path (`.<name>.tmp-<pid>-<n>`) in the same directory, so `rename` is atomic.
pub(crate) fn temp_sibling(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".into());
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!(".{name}.tmp-{}-{n}", std::process::id()))
}

/// fsync a directory (makes renames / creations inside it durable).
pub(crate) fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// Write `data` to `path` atomically (temp file + fsync + rename + fsync dir).
pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = temp_sibling(path);
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            let _ = sync_dir(parent);
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Atomically (re)point the symlink `link` to `target` (temp symlink + rename over the old one).
#[cfg(unix)]
pub(crate) fn atomic_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    let tmp = temp_sibling(link);
    std::os::unix::fs::symlink(target, &tmp)?;
    if let Err(e) = std::fs::rename(&tmp, link) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Some(parent) = link.parent() {
        let _ = sync_dir(parent);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn atomic_symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "symlinks require unix",
    ))
}

/// Read at most `max` bytes; error if the file is larger.
pub(crate) fn read_capped(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let mut out = Vec::new();
    f.take(max + 1).read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} exceeds {max} bytes", path.display()),
        ));
    }
    Ok(out)
}

/// Name of the last component of a symlink's target (`db/current -> versions/X` gives `X`).
pub(crate) fn link_target_name(link: &Path) -> Option<String> {
    let t = std::fs::read_link(link).ok()?;
    t.file_name().map(|n| n.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_ops() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("a.json");
        atomic_write(&f, b"1").unwrap();
        atomic_write(&f, b"22").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"22");
        assert!(read_capped(&f, 1).is_err());
        assert_eq!(read_capped(&f, 2).unwrap(), b"22");
        std::fs::create_dir(d.path().join("v1")).unwrap();
        std::fs::create_dir(d.path().join("v2")).unwrap();
        let link = d.path().join("current");
        atomic_symlink(Path::new("v1"), &link).unwrap();
        assert_eq!(link_target_name(&link).as_deref(), Some("v1"));
        atomic_symlink(Path::new("v2"), &link).unwrap();
        assert_eq!(link_target_name(&link).as_deref(), Some("v2"));
        // No temp leftovers.
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names.len(), 4, "{names:?}");
    }
}
