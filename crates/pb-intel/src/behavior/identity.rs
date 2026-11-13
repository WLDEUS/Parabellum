//! Who did it and what kind of thing it touched: process identities (stable across updates and user
//! names), interpreter detection and file categories.

/// Process facts needed by the baseline (built by the daemon from eslogger's `es_process_t`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcInfo {
    pub path: String,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub platform: bool,
    pub adhoc: bool,
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn is_hexish(s: &str) -> bool {
    s.len() >= 16 && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

fn is_versionish(s: &str) -> bool {
    s.as_bytes().first().is_some_and(u8::is_ascii_digit)
        && s.contains(['.', '_'])
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Path with the variable parts folded: user home → `~`, per-user temp dirs → `$TMPDIR`, App
/// Translocation ids, version directories (`3.6.0`) and long hex ids → `*`, `name-<hex>` → `name-*`.
pub fn normalize_path(path: &str) -> String {
    let comps: Vec<&str> = path.split('/').collect();
    let mut out: Vec<String> = Vec::with_capacity(comps.len());
    let mut i = 0;
    while i < comps.len() {
        let c = comps[i];
        // /Users/<name>/… → ~/…
        if i == 1 && c == "Users" && comps.len() > 2 && comps[2] != "Shared" {
            out.clear();
            out.push("~".into());
            i += 2; // skip "Users" and the user name
            continue;
        }
        // /private/var/folders/xx/yyyy/T/… and /var/folders/… → $TMPDIR/…
        if c == "folders" && i >= 1 && comps[i - 1] == "var" && comps.len() > i + 3 {
            out.retain(|_| false);
            out.push("$TMPDIR".into());
            i += 4;
            continue;
        }
        if c == "AppTranslocation" && comps.len() > i + 1 {
            out.push(c.into());
            out.push("*".into());
            i += 2;
            continue;
        }
        if is_versionish(c) || is_hexish(c) {
            out.push("*".into());
        } else if let Some((stem, tail)) = c.rsplit_once('-') {
            if tail.len() >= 8 && tail.bytes().all(|b| b.is_ascii_hexdigit()) {
                out.push(format!("{stem}-*"));
            } else {
                out.push(c.into());
            }
        } else {
            out.push(c.into());
        }
        i += 1;
    }
    let s = out.join("/");
    if s.is_empty() {
        "/".into()
    } else {
        s
    }
}

/// Team ID usable as an identity (present, not ad-hoc).
fn team(p: &ProcInfo) -> Option<&str> {
    p.team_id
        .as_deref()
        .filter(|t| !t.is_empty() && !p.adhoc && !p.platform)
}

/// Fine-grained identity of an actor (whose profile is learnt): `(key, label)`.
pub fn actor_identity(p: &ProcInfo) -> (String, String) {
    let label = normalize_path(&p.path);
    let key = if p.platform {
        format!(
            "apple:{}",
            p.signing_id.as_deref().unwrap_or(basename(&p.path))
        )
    } else if let Some(t) = team(p) {
        format!(
            "team:{t}:{}",
            p.signing_id.as_deref().unwrap_or(basename(&p.path))
        )
    } else {
        format!("path:{label}")
    };
    (key, label)
}

/// Coarse identity used as a feature value (a vendor's helpers collapse into one value).
pub fn coarse_identity(p: &ProcInfo) -> String {
    if p.platform {
        format!(
            "apple:{}",
            p.signing_id.as_deref().unwrap_or(basename(&p.path))
        )
    } else if let Some(t) = team(p) {
        format!("team:{t}")
    } else {
        format!("path:{}", normalize_path(&p.path))
    }
}

const INTERPRETERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "tcsh",
    "csh",
    "fish",
    "python",
    "perl",
    "ruby",
    "osascript",
    "node",
    "php",
    "tclsh",
    "lua",
    "pwsh",
    "bun",
    "deno",
    "jsc",
    "swift",
    "awk",
];

/// Interpreter name (`python3.12` → `python`) when the executable is a shell / script interpreter.
pub fn interpreter(path: &str) -> Option<&'static str> {
    let b = basename(path);
    let stem = b.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    INTERPRETERS.iter().copied().find(|i| *i == stem || *i == b)
}

/// Category of a file touched by a process; `None` for uninteresting places.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileCategory {
    UserLaunchAgents,
    SystemLaunchAgents,
    LaunchDaemons,
    CredentialStore,
    BrowserData,
    CryptoWallet,
    HiddenInHome,
    UsersShared,
    Temp,
    Applications,
    Downloads,
    Documents,
}

impl FileCategory {
    pub fn key(self) -> &'static str {
        match self {
            FileCategory::UserLaunchAgents => "launch_agents_user",
            FileCategory::SystemLaunchAgents => "launch_agents_system",
            FileCategory::LaunchDaemons => "launch_daemons",
            FileCategory::CredentialStore => "credential_store",
            FileCategory::BrowserData => "browser_data",
            FileCategory::CryptoWallet => "crypto_wallet",
            FileCategory::HiddenInHome => "hidden_in_home",
            FileCategory::UsersShared => "users_shared",
            FileCategory::Temp => "temp",
            FileCategory::Applications => "applications",
            FileCategory::Downloads => "downloads",
            FileCategory::Documents => "documents",
        }
    }

    /// French label for alerts / UI.
    pub fn label(self) -> &'static str {
        match self {
            FileCategory::UserLaunchAgents => "LaunchAgents de l'utilisateur",
            FileCategory::SystemLaunchAgents => "LaunchAgents système",
            FileCategory::LaunchDaemons => "LaunchDaemons",
            FileCategory::CredentialStore => "trousseaux et mots de passe",
            FileCategory::BrowserData => "données de navigateur",
            FileCategory::CryptoWallet => "portefeuilles de cryptomonnaies",
            FileCategory::HiddenInHome => "dossier caché du dossier personnel",
            FileCategory::UsersShared => "/Users/Shared",
            FileCategory::Temp => "dossiers temporaires",
            FileCategory::Applications => "Applications",
            FileCategory::Downloads => "Téléchargements",
            FileCategory::Documents => "Documents / Bureau",
        }
    }

    pub fn from_key(k: &str) -> Option<Self> {
        ALL_CATEGORIES.iter().copied().find(|c| c.key() == k)
    }

    /// How much a first-time access of this category matters (0..1).
    pub fn weight(self) -> f32 {
        match self {
            FileCategory::UserLaunchAgents
            | FileCategory::SystemLaunchAgents
            | FileCategory::LaunchDaemons
            | FileCategory::CredentialStore
            | FileCategory::BrowserData
            | FileCategory::CryptoWallet => 1.0,
            FileCategory::HiddenInHome => 0.8,
            FileCategory::UsersShared => 0.7,
            FileCategory::Applications => 0.6,
            FileCategory::Temp => 0.5,
            FileCategory::Downloads | FileCategory::Documents => 0.3,
        }
    }
}

pub const ALL_CATEGORIES: [FileCategory; 12] = [
    FileCategory::UserLaunchAgents,
    FileCategory::SystemLaunchAgents,
    FileCategory::LaunchDaemons,
    FileCategory::CredentialStore,
    FileCategory::BrowserData,
    FileCategory::CryptoWallet,
    FileCategory::HiddenInHome,
    FileCategory::UsersShared,
    FileCategory::Temp,
    FileCategory::Applications,
    FileCategory::Downloads,
    FileCategory::Documents,
];

/// Classifies an absolute path.
pub fn file_category(path: &str) -> Option<FileCategory> {
    let n = normalize_path(path);
    let lower = n.to_ascii_lowercase();
    let in_home = n.starts_with("~/");
    let credential_names = [
        "/library/keychains/",
        "login data",
        "logins.json",
        "key4.db",
        "key3.db",
        "cookies.binarycookies",
        "/cookies",
        "web data",
        "signons.sqlite",
    ];
    if credential_names.iter().any(|c| lower.contains(c)) {
        return Some(FileCategory::CredentialStore);
    }
    let wallets = [
        "/exodus/",
        "/electrum/",
        "/atomic/",
        "/ledger live/",
        "/trezor",
        "/coinomi/",
        "/guarda/",
        "/wasabi",
        "/bitcoin/",
        "/monero",
        "/ethereum/",
        "nkbihfbeogaeaoehlefnkodbefgpgknn",
    ];
    if wallets.iter().any(|w| lower.contains(w)) {
        return Some(FileCategory::CryptoWallet);
    }
    let browsers = [
        "/application support/google/chrome/",
        "/application support/bravesoftware/",
        "/application support/microsoft edge/",
        "/application support/firefox/profiles/",
        "/application support/arc/",
        "/application support/vivaldi/",
        "/application support/com.operasoftware.opera/",
        "/library/safari/",
        "/library/containers/com.apple.safari/",
    ];
    if browsers.iter().any(|b| lower.contains(b)) {
        return Some(FileCategory::BrowserData);
    }
    if n.starts_with("~/Library/LaunchAgents/") {
        return Some(FileCategory::UserLaunchAgents);
    }
    if n.starts_with("/Library/LaunchAgents/") {
        return Some(FileCategory::SystemLaunchAgents);
    }
    if n.starts_with("/Library/LaunchDaemons/") {
        return Some(FileCategory::LaunchDaemons);
    }
    if in_home {
        let rest = &n[2..];
        if rest.starts_with('.') && !rest.starts_with(".Trash") && rest.contains('/') {
            return Some(FileCategory::HiddenInHome);
        }
        if rest.starts_with("Downloads/") {
            return Some(FileCategory::Downloads);
        }
        if rest.starts_with("Documents/") || rest.starts_with("Desktop/") {
            return Some(FileCategory::Documents);
        }
        if rest.starts_with("Applications/") {
            return Some(FileCategory::Applications);
        }
        return None;
    }
    if n.starts_with("/Users/Shared/") {
        return Some(FileCategory::UsersShared);
    }
    if n.starts_with("$TMPDIR/")
        || ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"]
            .iter()
            .any(|p| n.starts_with(p))
    {
        return Some(FileCategory::Temp);
    }
    if n.starts_with("/Applications/") {
        return Some(FileCategory::Applications);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(path: &str, team: Option<&str>, platform: bool) -> ProcInfo {
        ProcInfo {
            path: path.into(),
            team_id: team.map(str::to_string),
            signing_id: None,
            platform,
            adhoc: false,
        }
    }

    #[test]
    fn path_normalization() {
        assert_eq!(
            normalize_path("/Users/camille/Library/LaunchAgents/x.plist"),
            "~/Library/LaunchAgents/x.plist"
        );
        assert_eq!(normalize_path("/Users/Shared/x"), "/Users/Shared/x");
        assert_eq!(
            normalize_path("/private/var/folders/zz/abc123/T/tmp.X/run"),
            "$TMPDIR/tmp.X/run"
        );
        assert_eq!(
            normalize_path(
                "/private/var/folders/zz/abc/T/AppTranslocation/0B1C2D3E-1111-2222-3333-444455556666/d/Foo.app/Contents/MacOS/Foo"
            ),
            "$TMPDIR/AppTranslocation/*/d/Foo.app/Contents/MacOS/Foo"
        );
        assert_eq!(
            normalize_path("/opt/homebrew/Cellar/fish/3.6.0/bin/fish"),
            "/opt/homebrew/Cellar/fish/*/bin/fish"
        );
        assert_eq!(
            normalize_path("/Users/camille/dev/x/target/debug/deps/pb_ml-0123456789abcdef"),
            "~/dev/x/target/debug/deps/pb_ml-*"
        );
    }

    #[test]
    fn identities() {
        let (k, l) = actor_identity(&p(
            "/Applications/Foo.app/Contents/MacOS/Foo",
            Some("ABCDE12345"),
            false,
        ));
        assert_eq!(k, "team:ABCDE12345:Foo");
        assert_eq!(l, "/Applications/Foo.app/Contents/MacOS/Foo");
        assert_eq!(
            coarse_identity(&p(
                "/Applications/Foo.app/Contents/MacOS/Helper",
                Some("ABCDE12345"),
                false
            )),
            "team:ABCDE12345"
        );
        assert_eq!(actor_identity(&p("/bin/zsh", None, true)).0, "apple:zsh");
        let mut adhoc = p("/Users/camille/bin/tool", Some("ABCDE12345"), false);
        adhoc.adhoc = true;
        assert_eq!(actor_identity(&adhoc).0, "path:~/bin/tool");
    }

    #[test]
    fn interpreters_and_categories() {
        assert_eq!(interpreter("/bin/zsh"), Some("zsh"));
        assert_eq!(interpreter("/opt/homebrew/bin/python3.12"), Some("python"));
        assert_eq!(interpreter("/usr/bin/osascript"), Some("osascript"));
        assert_eq!(interpreter("/usr/bin/curl"), None);
        assert_eq!(
            file_category("/Users/camille/Library/LaunchAgents/com.x.plist"),
            Some(FileCategory::UserLaunchAgents)
        );
        assert_eq!(
            file_category(
                "/Users/camille/Library/Application Support/Google/Chrome/Default/Login Data"
            ),
            Some(FileCategory::CredentialStore)
        );
        assert_eq!(
            file_category(
                "/Users/camille/Library/Application Support/Exodus/exodus.wallet/seed.seco"
            ),
            Some(FileCategory::CryptoWallet)
        );
        assert_eq!(
            file_category("/Users/camille/.local/bin/x"),
            Some(FileCategory::HiddenInHome)
        );
        assert_eq!(file_category("/private/tmp/a.sh"), Some(FileCategory::Temp));
        assert_eq!(file_category("/Users/camille/Music/a.mp3"), None);
        assert_eq!(
            file_category("/Library/LaunchDaemons/x.plist"),
            Some(FileCategory::LaunchDaemons)
        );
        for c in ALL_CATEGORIES {
            assert_eq!(FileCategory::from_key(c.key()), Some(c));
        }
    }
}
