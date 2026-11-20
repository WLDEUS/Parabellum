//! Manifest of Parabellum's own files: SHA-256 of every file the installer lays down, written by
//! `scripts/build-manifest.sh` during `make pkg` and installed as `<root>/manifest.json`.
//!
//! It lets the daemon recognise its own files by content, never by location: a byte changed and the
//! file is a stranger again. It also turns the installation trees into a tripwire (a file modified,
//! missing, or unknown inside them raises an alert).
//!
//! Not signed on its own: CI keeps the release key away from the build job, so the manifest's
//! authenticity is the package's (minisign-verified before every self-update). The daemon also seals
//! it (version + hash in its database) and alerts if it changes without a version change.
//!
//! Paths: `@root/…` is relative to the Parabellum root (`/Library/Application Support/Parabellum`),
//! anything else is absolute (`/Applications/Parabellum.app/…`, `/Library/LaunchDaemons/…`).

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

pub const MANIFEST_FILE: &str = "manifest.json";
pub const MANIFEST_FORMAT: u32 = 1;
pub const ROOT_PREFIX: &str = "@root/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnManifest {
    pub format: u32,
    pub version: String,
    #[serde(default)]
    pub built_at: i64,
    /// Directories entirely made of manifest files: anything else found inside is unknown.
    #[serde(default)]
    pub trees: Vec<String>,
    pub files: Vec<OwnFile>,
}

impl OwnManifest {
    /// Parse and validate (format, hex digests, no relative / `..` paths, no duplicates).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let m: OwnManifest = serde_json::from_slice(bytes).map_err(|e| format!("JSON : {e}"))?;
        if m.format != MANIFEST_FORMAT {
            return Err(format!("format {} non pris en charge", m.format));
        }
        if m.files.is_empty() {
            return Err("aucun fichier".into());
        }
        let mut seen = std::collections::HashSet::new();
        for f in &m.files {
            if f.sha256.len() != 64 || !f.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(format!("empreinte invalide pour {}", f.path));
            }
            check_path(&f.path)?;
            if !seen.insert(f.path.as_str()) {
                return Err(format!("chemin en double : {}", f.path));
            }
        }
        for t in &m.trees {
            check_path(t)?;
        }
        Ok(m)
    }
}

fn check_path(p: &str) -> Result<(), String> {
    let rest = p.strip_prefix(ROOT_PREFIX).or_else(|| p.strip_prefix('/'));
    let ok = rest.is_some_and(|r| {
        !r.is_empty()
            && Path::new(r)
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
    });
    if ok {
        Ok(())
    } else {
        Err(format!("chemin invalide : {p}"))
    }
}

/// Resolve a manifest path against the Parabellum root.
pub fn resolve(p: &str, root: &Path) -> PathBuf {
    match p.strip_prefix(ROOT_PREFIX) {
        Some(rel) => root.join(rel),
        None => PathBuf::from(p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(files: &str) -> String {
        format!(r#"{{"format":1,"version":"1.2.0","trees":["@root/bin"],"files":[{files}]}}"#)
    }

    #[test]
    fn parse_and_resolve() {
        let sha = "a".repeat(64);
        let m = OwnManifest::parse(
            manifest(&format!(
                r#"{{"path":"@root/bin/parabellumd","sha256":"{sha}","size":3}},
                   {{"path":"/Applications/Parabellum.app/Contents/MacOS/Parabellum","sha256":"{sha}","size":4}}"#
            ))
            .as_bytes(),
        )
        .unwrap();
        assert_eq!(m.files.len(), 2);
        let root = Path::new("/Library/Application Support/Parabellum");
        assert_eq!(
            resolve(&m.files[0].path, root),
            root.join("bin/parabellumd")
        );
        assert_eq!(
            resolve(&m.files[1].path, root),
            PathBuf::from("/Applications/Parabellum.app/Contents/MacOS/Parabellum")
        );
    }

    #[test]
    fn rejects_bad_manifests() {
        let sha = "b".repeat(64);
        for files in [
            format!(r#"{{"path":"bin/x","sha256":"{sha}","size":1}}"#),
            format!(r#"{{"path":"@root/../etc/x","sha256":"{sha}","size":1}}"#),
            r#"{"path":"@root/x","sha256":"zz","size":1}"#.to_string(),
            format!(
                r#"{{"path":"@root/x","sha256":"{sha}","size":1}},{{"path":"@root/x","sha256":"{sha}","size":1}}"#
            ),
        ] {
            assert!(
                OwnManifest::parse(manifest(&files).as_bytes()).is_err(),
                "{files}"
            );
        }
        assert!(OwnManifest::parse(br#"{"format":2,"version":"x","files":[]}"#).is_err());
    }
}
