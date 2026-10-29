//! Small JSON files in `state/privacy/` (root-only): atomic writes (`.tmp` + rename, mode 0600) and tolerant
//! loading (a corrupt file is kept as `<name>.bad` and the state starts empty).

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Read `path`; missing -> `T::default()`, unparsable -> renamed to `<path>.bad`, `T::default()`.
pub(crate) fn load_json<T: DeserializeOwned + Default>(path: &Path) -> T {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return T::default(),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "cannot read privacy state, starting empty");
            return T::default();
        }
    };
    match serde_json::from_slice::<T>(&data) {
        Ok(v) => v,
        Err(e) => {
            let bad = bad_path(path);
            tracing::warn!(path = %path.display(), error = %e, bad = %bad.display(), "corrupt privacy state kept aside, starting empty");
            let _ = std::fs::rename(path, &bad);
            T::default()
        }
    }
}

fn bad_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".bad");
    PathBuf::from(s)
}

/// Atomic write with mode 0600; creates the parent directory (0700) if needed.
pub(crate) fn save_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let data = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    write_private(path, &data)
}

pub(crate) fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
            set_mode(dir, 0o700);
        }
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let res = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn roundtrip_and_corruption() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub").join("x.json");
        let missing: BTreeMap<String, u32> = load_json(&p);
        assert!(missing.is_empty());
        let mut m = BTreeMap::new();
        m.insert("a".to_string(), 1u32);
        save_json(&p, &m).unwrap();
        assert_eq!(load_json::<BTreeMap<String, u32>>(&p), m);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        std::fs::write(&p, b"{not json").unwrap();
        let back: BTreeMap<String, u32> = load_json(&p);
        assert!(back.is_empty());
        assert!(bad_path(&p).is_file());
        assert!(!p.exists());
    }
}
