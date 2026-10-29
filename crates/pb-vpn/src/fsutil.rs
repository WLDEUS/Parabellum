//! Atomic, private (0600) state files in the VPN directory.

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Max size of a state file read back.
const MAX_STATE: u64 = 4 * 1024 * 1024;

/// Write `bytes` to `path` through `path.tmp` (mode 0600, fsync, rename).
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp_name = path.as_os_str().to_os_string();
    tmp_name.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp_name);
    let _ = std::fs::remove_file(&tmp);
    let res = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// Serialize as pretty JSON and [`write_private`].
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    write_private(path, &bytes)
}

/// Read a JSON state file; `Ok(None)` when absent.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> std::io::Result<Option<T>> {
    let md = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !md.is_file() || md.len() > MAX_STATE {
        return Err(std::io::Error::other(format!(
            "{} : fichier d'état invalide",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(std::io::Error::other)
}

/// Remove a file, ignoring "not found".
pub fn remove(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn private_atomic_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub").join("x.json");
        write_json(&p, &vec![1, 2, 3]).unwrap();
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let back: Option<Vec<i32>> = read_json(&p).unwrap();
        assert_eq!(back, Some(vec![1, 2, 3]));
        assert_eq!(read_json::<Vec<i32>>(&d.path().join("none")).unwrap(), None);
        remove(&p).unwrap();
        remove(&p).unwrap();
    }
}
