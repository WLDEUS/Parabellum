//! Embeds the minisign public keys: the threat-DB key (nightly bundle) and the release key (Parabellum
//! `.pkg` self-updates). Two keys so that the nightly job, which handles untrusted feeds and malware
//! samples, can never sign an installer that the daemon would run as root.
//!
//! Sources, in order, for each key:
//! 1. env `PARABELLUM_DB_PUBKEY` / `PARABELLUM_RELEASE_PUBKEY` (bare base64 key or full `.pub` content),
//! 2. `<workspace>/keys/parabellum-db.pub` / `keys/parabellum-release.pub` (`make keys`), may be absent.
//!
//! Written to `$OUT_DIR/pubkey.rs` as `EMBEDDED_PUBKEY` and `EMBEDDED_RELEASE_PUBKEY` (`Option<&str>`).
//! Only light syntactic validation is done here; the key is fully parsed at runtime.

use std::path::{Path, PathBuf};

const ENV_KEY: &str = "PARABELLUM_DB_PUBKEY";
const ENV_RELEASE_KEY: &str = "PARABELLUM_RELEASE_PUBKEY";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let keys_dir = manifest_dir.join("..").join("..").join("keys");
    let db = load_key(ENV_KEY, &keys_dir.join("parabellum-db.pub"), "DB");
    let release = load_key(
        ENV_RELEASE_KEY,
        &keys_dir.join("parabellum-release.pub"),
        "release",
    );
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap_or_default());
    let code = format!(
        "/// Minisign public key (base64) of the threat-DB bundle, compiled in at build time.\n\
         const EMBEDDED_PUBKEY: Option<&str> = {};\n\
         /// Minisign public key (base64) of the Parabellum `.pkg` releases, compiled in at build time.\n\
         const EMBEDDED_RELEASE_PUBKEY: Option<&str> = {};\n",
        render(&db),
        render(&release)
    );
    if let Err(e) = std::fs::write(out_dir.join("pubkey.rs"), code) {
        panic!("cannot write pubkey.rs: {e}");
    }
}

fn render(k: &Option<String>) -> String {
    match k {
        Some(k) => format!("Some({k:?})"),
        None => "None".to_string(),
    }
}

fn load_key(env: &str, file: &Path, what: &str) -> Option<String> {
    println!("cargo:rerun-if-env-changed={env}");
    watch_nearest_existing(file);
    let raw = match std::env::var(env) {
        Ok(v) if !v.trim().is_empty() => Some(v),
        _ => std::fs::read_to_string(file).ok(),
    };
    let key = raw.as_deref().and_then(extract_base64_key);
    if raw.is_some() && key.is_none() {
        println!("cargo:warning=pb-updater: {what} minisign public key found but malformed; it is ignored");
    }
    key
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
