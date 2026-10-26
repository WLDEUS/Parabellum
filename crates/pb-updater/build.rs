//! Embeds the minisign public key that signs the threat-DB bundle and the Parabellum `.pkg` releases.
//!
//! Source, in order:
//! 1. env `PARABELLUM_DB_PUBKEY` (either the bare base64 key or the full 2-line `minisign.pub` content),
//! 2. `<workspace>/keys/parabellum-db.pub` (created by `make keys`), may be absent.
//!
//! The result is written to `$OUT_DIR/pubkey.rs` as `const EMBEDDED_PUBKEY: Option<&str>`.
//! Only light syntactic validation is done here; the key is fully parsed at runtime.

use std::path::{Path, PathBuf};

const ENV_KEY: &str = "PARABELLUM_DB_PUBKEY";

fn main() {
    println!("cargo:rerun-if-env-changed={ENV_KEY}");
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let key_file = manifest_dir
        .join("..")
        .join("..")
        .join("keys")
        .join("parabellum-db.pub");
    watch_nearest_existing(&key_file);

    let raw = match std::env::var(ENV_KEY) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => std::fs::read_to_string(&key_file).ok(),
    };
    let key = raw.as_deref().and_then(extract_base64_key);
    if raw.is_some() && key.is_none() {
        println!("cargo:warning=pb-updater: minisign public key found but malformed; DB/app updates will be refused");
    }

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default());
    let code = match key {
        Some(k) => format!("/// Minisign public key (base64) compiled in at build time.\nconst EMBEDDED_PUBKEY: Option<&str> = Some({k:?});\n"),
        None => "/// No minisign public key was available at build time.\nconst EMBEDDED_PUBKEY: Option<&str> = None;\n".to_string(),
    };
    if let Err(e) = std::fs::write(out_dir.join("pubkey.rs"), code) {
        panic!("cannot write pubkey.rs: {e}");
    }
}

/// `rerun-if-changed` on a missing path makes cargo rerun the build script on every build, so watch the
/// file if it exists, otherwise its nearest existing ancestor directory (whose mtime changes when the
/// file / directory gets created).
fn watch_nearest_existing(path: &Path) {
    let mut p = Some(path);
    while let Some(cur) = p {
        if cur.exists() {
            println!("cargo:rerun-if-changed={}", cur.display());
            return;
        }
        p = cur.parent();
    }
}

/// Accept the bare base64 key or the 2-line `.pub` file (`untrusted comment: …` + base64).
fn extract_base64_key(s: &str) -> Option<String> {
    let line = s
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))?;
    // Ed25519 minisign public key = 2 (alg) + 8 (key id) + 32 (key) = 42 bytes = 56 base64 chars.
    let ok = line.len() == 56
        && line.starts_with("RW")
        && line
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=');
    ok.then(|| line.to_string())
}
