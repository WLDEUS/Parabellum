//! Ollama, the local model server of the mail agent. Not in the regular component list: it is installed
//! (and updated) only when the mail agent is enabled, from the pin of the signed threat DB
//! (`components/ollama.json`): the download must match the pinned SHA-256, then the extracted `ollama`
//! and `llama-server` must pass `codesign --verify --strict` against a Developer ID requirement with Ollama's Team ID, and
//! Gatekeeper's notarization check on the primary signature (not `--type execute`, which only takes apps).
//!
//! Layout: `components/ollama/<version>/` (root-owned, 0755) and `components/ollama/current` -> `<version>`.

use super::apple;
use crate::fsutil::{atomic_symlink, read_capped};
use crate::http::{Http, LARGE_TIMEOUT};
use crate::process::{run, RunOpts};
use crate::UpdateError;
use pb_core::db::{ComponentPin, ComponentPins};
use pb_core::paths::Paths;
use std::path::{Path, PathBuf};

/// Pin file in the signed bundle.
pub const OLLAMA_PINS: &str = "components/ollama.json";
/// Apple Team ID of Ollama's Developer ID builds (Infra Technologies, Inc).
pub const OLLAMA_TEAM_ID: &str = "3MU9H2V9Y9";
const ASSET: &str = "ollama-darwin.tgz";
const MAX_ASSET: u64 = 400 * 1024 * 1024;
const TAR: &str = "/usr/bin/tar";

fn dir(paths: &Paths) -> PathBuf {
    paths.components_dir().join("ollama")
}

/// `components/ollama/current/ollama` (may not exist).
pub fn ollama_binary(paths: &Paths) -> PathBuf {
    dir(paths).join("current").join("ollama")
}

/// Installed version (target of `current`).
pub fn ollama_installed_version(paths: &Paths) -> Option<String> {
    let t = std::fs::read_link(dir(paths).join("current")).ok()?;
    let v = t.file_name()?.to_str()?.to_string();
    valid_version(&v).then_some(v)
}

fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 6 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Validate a pin: vendor URL of exactly this version and asset, SHA-256, binary name.
pub fn validate_pin(p: &ComponentPin) -> bool {
    valid_version(&p.version)
        && p.asset == ASSET
        && p.url
            == format!(
                "https://github.com/ollama/ollama/releases/download/v{}/{ASSET}",
                p.version
            )
        && p.sha256.len() == 64
        && p.sha256.bytes().all(|b| b.is_ascii_hexdigit())
        && p.binary == "ollama"
}

/// Pin from the active signed bundle, validated.
pub fn read_ollama_pin(paths: &Paths) -> Option<ComponentPin> {
    let bytes = read_capped(&paths.db_current().join(OLLAMA_PINS), 256 * 1024).ok()?;
    let pins: ComponentPins = serde_json::from_slice(&bytes).ok()?;
    let pin = pins.pins.get("ollama")?.clone();
    if validate_pin(&pin) {
        Some(pin)
    } else {
        tracing::warn!("invalid pin in components/ollama.json, ignored");
        None
    }
}

/// Install (or update to) the pinned version. Returns the version now installed.
pub async fn install_ollama(paths: &Paths) -> Result<String, UpdateError> {
    let pin = read_ollama_pin(paths).ok_or_else(|| {
        UpdateError::Verification("épingle Ollama absente de la base signée".into())
    })?;
    if ollama_installed_version(paths).as_deref() == Some(pin.version.as_str())
        && ollama_binary(paths).is_file()
    {
        return Ok(pin.version);
    }
    if !cfg!(target_os = "macos") {
        return Err(UpdateError::Unsupported("Ollama : macOS uniquement".into()));
    }
    let base = dir(paths);
    std::fs::create_dir_all(&base)?;
    set_mode(&base, 0o755)?;
    let downloads = base.join(".download");
    let _ = std::fs::remove_dir_all(&downloads);
    std::fs::create_dir_all(&downloads)?;
    let archive = downloads.join(ASSET);
    let http = Http::new(None)?;
    http.download_to_file(&pin.url, &archive, MAX_ASSET, None, LARGE_TIMEOUT)
        .await?;
    let a = archive.clone();
    let digest = tokio::task::spawn_blocking(move || crate::fsutil::sha256_file(&a))
        .await
        .map_err(|e| UpdateError::Archive(e.to_string()))??;
    if !digest.eq_ignore_ascii_case(&pin.sha256) {
        let _ = std::fs::remove_dir_all(&downloads);
        return Err(UpdateError::Verification(format!(
            "Ollama : empreinte SHA-256 différente de la base signée ({digest})"
        )));
    }
    // The archive is now the exact file the pipeline checked. bsdtar keeps the code-signature xattrs.
    let staging = base.join(format!(".staging-{}", pin.version));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)?;
    let out = run(
        Path::new(TAR),
        [
            std::ffi::OsStr::new("-xzf"),
            archive.as_os_str(),
            std::ffi::OsStr::new("-C"),
            staging.as_os_str(),
            std::ffi::OsStr::new("--no-same-owner"),
        ],
        RunOpts::timeout(600),
    )
    .await?;
    let _ = std::fs::remove_dir_all(&downloads);
    if !out.success() {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(UpdateError::Archive(format!("tar : {}", out.summary())));
    }
    let checked = async {
        check_tree(&staging)?;
        for exe in ["ollama", "llama-server"] {
            let p = staging.join(exe);
            if p.exists() {
                apple::verify_binary(&p, OLLAMA_TEAM_ID).await?;
            }
        }
        Ok::<(), UpdateError>(())
    }
    .await;
    if let Err(e) = checked {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    let final_dir = base.join(&pin.version);
    let _ = std::fs::remove_dir_all(&final_dir);
    std::fs::rename(&staging, &final_dir)?;
    set_mode(&final_dir, 0o755)?;
    atomic_symlink(Path::new(&pin.version), &base.join("current"))?;
    prune(&base, &pin.version);
    tracing::info!(version = %pin.version, "ollama installed");
    Ok(pin.version)
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
}

/// Regular files, directories (at most 3 levels) and relative links that stay inside their directory;
/// nothing setuid, setgid or world-writable.
fn check_tree(root: &Path) -> Result<(), UpdateError> {
    let main = std::fs::symlink_metadata(root.join("ollama"))?;
    if !main.is_file() {
        return Err(UpdateError::Archive("ollama absent de l'archive".into()));
    }
    check_dir(root, 0)
}

fn check_dir(dir: &Path, depth: usize) -> Result<(), UpdateError> {
    use std::os::unix::fs::PermissionsExt;
    let bad = |m: String| Err(UpdateError::Archive(m));
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let md = std::fs::symlink_metadata(e.path())?;
        let mode = md.permissions().mode();
        if !md.is_symlink() && (mode & 0o6000 != 0 || mode & 0o002 != 0) {
            return bad(format!("droits interdits dans l'archive : {name}"));
        }
        if md.is_symlink() {
            let t = std::fs::read_link(e.path())?;
            if t.is_absolute()
                || t.components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                return bad(format!("lien interdit dans l'archive : {name}"));
            }
        } else if md.is_dir() {
            if depth >= 2 {
                return bad(format!("arborescence trop profonde : {name}"));
            }
            check_dir(&e.path(), depth + 1)?;
        } else if !md.is_file() {
            return bad(format!("entrée inattendue dans l'archive : {name}"));
        }
    }
    Ok(())
}

fn prune(base: &Path, keep: &str) {
    if let Ok(rd) = std::fs::read_dir(base) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if n != keep && n != "current" && (valid_version(&n) || n.starts_with(".staging-")) {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin(version: &str, url: &str) -> ComponentPin {
        serde_json::from_value(serde_json::json!({
            "version": version, "asset": ASSET, "url": url, "sha256": "a".repeat(64),
            "binary": "ollama", "verified_by": "x"
        }))
        .unwrap()
    }

    #[test]
    fn pins_are_vendor_only() {
        let ok = "https://github.com/ollama/ollama/releases/download/v0.40.11/ollama-darwin.tgz";
        assert!(validate_pin(&pin("0.40.11", ok)));
        assert!(
            !validate_pin(&pin("0.40.12", ok)),
            "version must match the URL"
        );
        assert!(!validate_pin(&pin(
            "0.40.11",
            "https://evil.example/ollama/ollama/releases/download/v0.40.11/ollama-darwin.tgz"
        )));
        assert!(!validate_pin(&pin("../x", ok)));
    }

    #[test]
    fn tree_checks() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("ollama"), b"x").unwrap();
        std::fs::write(d.path().join("libggml-base.0.dylib"), b"x").unwrap();
        std::os::unix::fs::symlink("libggml-base.0.dylib", d.path().join("libggml-base.dylib"))
            .unwrap();
        assert!(check_tree(d.path()).is_ok());
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("evil")).unwrap();
        assert!(check_tree(d.path()).is_err());
        std::fs::remove_file(d.path().join("evil")).unwrap();
        std::fs::create_dir(d.path().join("mlx_metal_v4")).unwrap();
        std::fs::write(d.path().join("mlx_metal_v4/libmlx.dylib"), b"x").unwrap();
        assert!(check_tree(d.path()).is_ok());
        std::os::unix::fs::symlink("../ollama", d.path().join("mlx_metal_v4/up")).unwrap();
        assert!(check_tree(d.path()).is_err());
    }
}
