//! Strict extraction of the (already signature-verified) threat-DB `.tar.gz`.
//!
//! Defense in depth even though the archive is signed: only regular files and directories, only paths
//! listed in the manifest (plus `manifest.json`), no absolute paths / `..` / non-UTF-8 names, no
//! duplicates, entry-count / per-file / total size caps, files created with `O_EXCL` in a fresh directory,
//! SHA-256 computed while writing, every file fsync'ed.

use crate::UpdateError;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Component, Path};

/// Extraction limits.
#[derive(Debug, Clone, Copy)]
pub(crate) struct UnpackLimits {
    pub(crate) max_entries: usize,
    pub(crate) max_file_bytes: u64,
    pub(crate) max_total_bytes: u64,
}

impl Default for UnpackLimits {
    fn default() -> Self {
        Self {
            max_entries: 200_000,
            max_file_bytes: 1 << 30,
            max_total_bytes: 3 << 30,
        }
    }
}

/// Normalize an archive path to `a/b/c` (strips `./`), rejecting anything unsafe.
pub(crate) fn safe_relative_path(p: &Path) -> Result<Option<String>, UpdateError> {
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::Normal(s) => {
                let s = s
                    .to_str()
                    .ok_or_else(|| UpdateError::Archive("nom de fichier non UTF-8".into()))?;
                if s.contains('\\') || s.contains('\0') {
                    return Err(UpdateError::Archive(format!(
                        "nom de fichier interdit : {s:?}"
                    )));
                }
                parts.push(s.to_string());
            }
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(UpdateError::Archive(format!(
                    "chemin interdit : {}",
                    p.display()
                )));
            }
        }
    }
    if parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(parts.join("/")))
    }
}

/// Unpack `archive` (gzip'ed tar) into the *non-existing* directory `dest`.
/// `allowed_files` are the only file paths accepted (besides `manifest.json`).
/// Returns `relative path -> lowercase hex SHA-256` of every extracted file.
pub(crate) fn unpack_bundle(
    archive: &Path,
    dest: &Path,
    allowed_files: &BTreeSet<String>,
    limits: UnpackLimits,
) -> Result<BTreeMap<String, String>, UpdateError> {
    let mut allowed_dirs: BTreeSet<String> = BTreeSet::new();
    for f in allowed_files {
        let mut acc = String::new();
        let comps: Vec<&str> = f.split('/').collect();
        for c in comps.iter().take(comps.len().saturating_sub(1)) {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(c);
            allowed_dirs.insert(acc.clone());
        }
    }

    std::fs::create_dir(dest)?;
    let file = std::fs::File::open(archive)?;
    let gz = flate2::read::GzDecoder::new(std::io::BufReader::new(file));
    let mut ar = tar::Archive::new(gz);
    let mut digests = BTreeMap::new();
    let mut created_dirs: BTreeSet<String> = BTreeSet::new();
    let mut total: u64 = 0;
    let mut count = 0usize;

    let entries = ar
        .entries()
        .map_err(|e| UpdateError::Archive(format!("tar illisible : {e}")))?;
    for entry in entries {
        let mut entry =
            entry.map_err(|e| UpdateError::Archive(format!("entrée tar illisible : {e}")))?;
        count += 1;
        if count > limits.max_entries {
            return Err(UpdateError::Archive(format!(
                "plus de {} entrées",
                limits.max_entries
            )));
        }
        let etype = entry.header().entry_type();
        if etype == tar::EntryType::XGlobalHeader {
            continue;
        }
        let raw_path = entry
            .path()
            .map_err(|e| UpdateError::Archive(format!("chemin illisible : {e}")))?
            .into_owned();
        let Some(rel) = safe_relative_path(&raw_path)? else {
            if etype.is_dir() {
                continue;
            }
            return Err(UpdateError::Archive("entrée sans nom".into()));
        };
        match etype {
            tar::EntryType::Directory => {
                if !allowed_dirs.contains(&rel) {
                    return Err(UpdateError::Archive(format!("dossier inattendu : {rel}")));
                }
                std::fs::create_dir_all(dest.join(&rel))?;
                created_dirs.insert(rel);
            }
            tar::EntryType::Regular => {
                if rel != pb_core::db::MANIFEST_FILE && !allowed_files.contains(&rel) {
                    return Err(UpdateError::Archive(format!(
                        "fichier absent du manifeste : {rel}"
                    )));
                }
                let size = entry
                    .header()
                    .size()
                    .map_err(|e| UpdateError::Archive(e.to_string()))?;
                if size > limits.max_file_bytes {
                    return Err(UpdateError::Archive(format!(
                        "{rel} trop gros ({size} octets)"
                    )));
                }
                total = total.saturating_add(size);
                if total > limits.max_total_bytes {
                    return Err(UpdateError::Archive(
                        "taille totale décompressée excessive".into(),
                    ));
                }
                let target = dest.join(&rel);
                if let Some(parent) = target.parent() {
                    std::fs::create_dir_all(parent)?;
                    if let Some(prel) = Path::new(&rel).parent().and_then(|p| p.to_str()) {
                        if !prel.is_empty() {
                            created_dirs.insert(prel.to_string());
                        }
                    }
                }
                let mut out = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)
                    .map_err(|e| {
                        UpdateError::Archive(format!("{rel} : {e} (entrée dupliquée ?)"))
                    })?;
                let mut hasher = Sha256::new();
                let mut buf = vec![0u8; 64 * 1024];
                let mut written: u64 = 0;
                let mut limited = (&mut entry).take(size + 1);
                loop {
                    let n = limited
                        .read(&mut buf)
                        .map_err(|e| UpdateError::Archive(format!("{rel} : {e}")))?;
                    if n == 0 {
                        break;
                    }
                    written += n as u64;
                    if written > size {
                        return Err(UpdateError::Archive(format!("{rel} : taille incohérente")));
                    }
                    hasher.update(&buf[..n]);
                    out.write_all(&buf[..n])?;
                }
                if written != size {
                    return Err(UpdateError::Archive(format!("{rel} : fichier tronqué")));
                }
                out.sync_all()?;
                set_mode(&target, 0o644)?;
                digests.insert(rel, hex::encode(hasher.finalize()));
            }
            other => {
                return Err(UpdateError::Archive(format!(
                    "type d'entrée interdit ({other:?}) : {rel}"
                )));
            }
        }
    }
    for d in &created_dirs {
        let p = dest.join(d);
        set_mode(&p, 0o755)?;
        let _ = crate::fsutil::sync_dir(&p);
    }
    set_mode(dest, 0o755)?;
    let _ = crate::fsutil::sync_dir(dest);
    Ok(digests)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_normalization() {
        assert_eq!(
            safe_relative_path(Path::new("./a/b.txt"))
                .unwrap()
                .as_deref(),
            Some("a/b.txt")
        );
        assert_eq!(safe_relative_path(Path::new("./")).unwrap(), None);
        assert!(safe_relative_path(Path::new("../x")).is_err());
        assert!(safe_relative_path(Path::new("/etc/passwd")).is_err());
        assert!(safe_relative_path(Path::new("a/../../x")).is_err());
    }
}
