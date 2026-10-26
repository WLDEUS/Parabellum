//! Archive handling for components: extraction of the single `dnscrypt-proxy` binary from the
//! (minisign-verified) release archive, and a safety pre-scan of zips before `ditto` expands them.

use crate::UpdateError;
use std::io::{Read, Write};
use std::path::Path;

/// Max size of the extracted dnscrypt-proxy binary.
const MAX_BINARY: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 5_000;

/// Mach-O 64-bit little-endian magic (`MH_MAGIC_64` as stored on disk) followed by `CPU_TYPE_ARM64`.
const MACHO_ARM64_HEADER: [u8; 8] = [0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01];

fn is_binary_entry(name: &str) -> bool {
    // Expected layout: `macos-arm64/dnscrypt-proxy` (one directory level). Everything else
    // (LICENSE, example-*.toml / *.txt, localhost.pem) is ignored.
    let parts: Vec<&str> = name
        .trim_start_matches("./")
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    matches!(parts.as_slice(), [dir, "dnscrypt-proxy"] if *dir != ".." && *dir != ".")
}

/// Extract the `dnscrypt-proxy` binary from a `.zip` or `.tar.gz` release archive to `dest`
/// (written as `dest.new`, checked to be an arm64 Mach-O, chmod 0755, renamed into place).
pub(crate) fn extract_dnscrypt_binary(archive: &Path, dest: &Path) -> Result<(), UpdateError> {
    let name = archive
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let mut tmp_name = dest.as_os_str().to_os_string();
    tmp_name.push(".new");
    let tmp = std::path::PathBuf::from(tmp_name);
    let _ = std::fs::remove_file(&tmp);
    let res = if name.ends_with(".zip") {
        extract_from_zip(archive, &tmp)
    } else if name.ends_with(".tar.gz") {
        extract_from_targz(archive, &tmp)
    } else {
        Err(UpdateError::Archive(format!("format inconnu : {name}")))
    };
    let res = res.and_then(|()| {
        let mut head = [0u8; 8];
        std::fs::File::open(&tmp)?.read_exact(&mut head)?;
        if head != MACHO_ARM64_HEADER {
            return Err(UpdateError::Archive(
                "dnscrypt-proxy n'est pas un binaire Mach-O arm64".into(),
            ));
        }
        set_exec(&tmp)?;
        std::fs::rename(&tmp, dest)?;
        Ok(())
    });
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn write_bounded(mut r: impl Read, out: &Path) -> Result<(), UpdateError> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)?;
    let n = std::io::copy(&mut (&mut r).take(MAX_BINARY + 1), &mut f)?;
    if n > MAX_BINARY {
        return Err(UpdateError::Archive(
            "binaire dnscrypt-proxy trop gros".into(),
        ));
    }
    f.flush()?;
    f.sync_all()?;
    Ok(())
}

fn extract_from_zip(archive: &Path, out: &Path) -> Result<(), UpdateError> {
    let f = std::fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(f)
        .map_err(|e| UpdateError::Archive(format!("zip illisible : {e}")))?;
    if zip.len() > MAX_ENTRIES {
        return Err(UpdateError::Archive("trop d'entrées".into()));
    }
    for i in 0..zip.len() {
        let entry = zip
            .by_index(i)
            .map_err(|e| UpdateError::Archive(e.to_string()))?;
        if entry.is_file() && is_binary_entry(entry.name()) {
            if entry.size() > MAX_BINARY {
                return Err(UpdateError::Archive(
                    "binaire dnscrypt-proxy trop gros".into(),
                ));
            }
            return write_bounded(entry, out);
        }
    }
    Err(UpdateError::Archive(
        "binaire dnscrypt-proxy absent de l'archive".into(),
    ))
}

fn extract_from_targz(archive: &Path, out: &Path) -> Result<(), UpdateError> {
    let f = std::fs::File::open(archive)?;
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(std::io::BufReader::new(f)));
    let entries = ar
        .entries()
        .map_err(|e| UpdateError::Archive(e.to_string()))?;
    for (n, entry) in entries.enumerate() {
        if n > MAX_ENTRIES {
            break;
        }
        let entry = entry.map_err(|e| UpdateError::Archive(e.to_string()))?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| UpdateError::Archive(e.to_string()))?
            .to_string_lossy()
            .to_string();
        if is_binary_entry(&path) {
            return write_bounded(entry, out);
        }
    }
    Err(UpdateError::Archive(
        "binaire dnscrypt-proxy absent de l'archive".into(),
    ))
}

/// Reject zips with unsafe names (absolute, `..`), too many entries or an excessive expanded size
/// before handing them to `ditto`.
pub(crate) fn prescan_zip(archive: &Path, max_total: u64) -> Result<(), UpdateError> {
    let f = std::fs::File::open(archive)?;
    let mut zip = zip::ZipArchive::new(f)
        .map_err(|e| UpdateError::Archive(format!("zip illisible : {e}")))?;
    if zip.len() > 50_000 {
        return Err(UpdateError::Archive("trop d'entrées".into()));
    }
    let mut total: u64 = 0;
    for i in 0..zip.len() {
        let entry = zip
            .by_index_raw(i)
            .map_err(|e| UpdateError::Archive(e.to_string()))?;
        if entry.enclosed_name().is_none() {
            return Err(UpdateError::Archive(format!(
                "chemin interdit dans le zip : {}",
                entry.name()
            )));
        }
        total = total.saturating_add(entry.size());
        if total > max_total {
            return Err(UpdateError::Archive(
                "zip trop volumineux une fois décompressé".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_exec(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn set_exec(_p: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use zip::write::SimpleFileOptions;

    pub(crate) fn fake_macho() -> Vec<u8> {
        let mut v = MACHO_ARM64_HEADER.to_vec();
        v.extend_from_slice(&[0u8; 120]);
        v
    }

    pub(crate) fn dnscrypt_zip(binary: &[u8]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let o = SimpleFileOptions::default();
        w.add_directory("macos-arm64/", o).unwrap();
        w.start_file("macos-arm64/LICENSE", o).unwrap();
        w.write_all(b"ISC").unwrap();
        w.start_file("macos-arm64/example-dnscrypt-proxy.toml", o)
            .unwrap();
        w.write_all(b"# example").unwrap();
        w.start_file("macos-arm64/dnscrypt-proxy", o.unix_permissions(0o755))
            .unwrap();
        w.write_all(binary).unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn extracts_only_the_binary() {
        let d = tempfile::tempdir().unwrap();
        let zip_path = d.path().join("dnscrypt-proxy-macos_arm64-2.1.20.zip");
        std::fs::write(&zip_path, dnscrypt_zip(&fake_macho())).unwrap();
        prescan_zip(&zip_path, 1 << 20).unwrap();
        let dest = d.path().join("dnscrypt-proxy");
        extract_dnscrypt_binary(&zip_path, &dest).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), fake_macho());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        // Not a Mach-O arm64 → refused, nothing left behind.
        std::fs::write(&zip_path, dnscrypt_zip(b"#!/bin/sh\necho pwned\n")).unwrap();
        let dest2 = d.path().join("other");
        assert!(extract_dnscrypt_binary(&zip_path, &dest2).is_err());
        assert!(!dest2.exists());
        assert!(!d.path().join("other.new").exists());
    }

    #[test]
    fn targz_and_entry_names() {
        assert!(is_binary_entry("macos-arm64/dnscrypt-proxy"));
        assert!(is_binary_entry("./macos-arm64/dnscrypt-proxy"));
        assert!(!is_binary_entry("dnscrypt-proxy"));
        assert!(!is_binary_entry("../dnscrypt-proxy"));
        assert!(!is_binary_entry("a/b/dnscrypt-proxy"));
        let d = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        let bin = fake_macho();
        let mut h = tar::Header::new_gnu();
        h.set_size(bin.len() as u64);
        h.set_mode(0o755);
        h.set_cksum();
        b.append_data(&mut h, "macos-arm64/dnscrypt-proxy", bin.as_slice())
            .unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&b.into_inner().unwrap()).unwrap();
        let p = d.path().join("x.tar.gz");
        std::fs::write(&p, gz.finish().unwrap()).unwrap();
        extract_dnscrypt_binary(&p, &d.path().join("bin")).unwrap();
    }
}
