//! What may be cleaned: allow / deny lists per category. Every path given to `clean apply` is checked
//! against these rules again, so a forged plan cannot reach anything the scanner would not list.
//!
//! Deny list (never touched, whatever the category): Keychains, Mail, Messages, iCloud Drive
//! (`Mobile Documents`, `CloudStorage`), cookies, Safari history/bookmarks (`~/Library/Safari`), iPhone
//! backups (`MobileSync`), contacts / calendars / call history, Apple group containers, `~/.ssh`,
//! `~/.gnupg`, Photos / Music libraries, and anything named `com.apple.*` except the three Apple caches
//! listed explicitly (Safari's web cache, Safari's container cache, Xcode's cache).
//!
//! Caches (`~/Library/Caches/<entry>`): everything except `com.apple.*`, `CloudKit`, `FamilyCircle`,
//! `GeoServices`, `Metadata` (Spotlight), `TemporaryItems`, hidden files, Parabellum's own cache, and
//! entries claimed by the browser / developer / leftover categories (listed there instead).

use pb_core::model::{CleanCategory, CleanSafety};
use std::path::{Component, Path, PathBuf};

/// Size threshold of the large-files category.
pub const LARGE_FILE_MIN: u64 = 500_000_000;
/// "Not opened for 6 months".
pub const LARGE_FILE_IDLE_SECS: i64 = 182 * 86_400;
/// Logs, crash reports and installers older than this are listed.
pub const OLD_SECS: i64 = 30 * 86_400;

/// `~/Library/...` relative paths never touched.
const DENIED_LIBRARY: &[&str] = &[
    "Keychains",
    "Mail",
    "Messages",
    "Mobile Documents",
    "CloudStorage",
    "Cookies",
    "Safari",
    "Accounts",
    "Calendars",
    "IdentityServices",
    "Sharing",
    "Suggestions",
    "Photos",
    "Application Support/MobileSync",
    "Application Support/AddressBook",
    "Application Support/CallHistoryDB",
    "Application Support/CallHistoryTransactions",
    "Application Support/Knowledge",
    "Application Support/com.apple.TCC",
    "Containers/com.apple.mail",
];

/// Home-relative paths never touched.
const DENIED_HOME: &[&str] = &[".ssh", ".gnupg", ".Trash/.DS_Store"];

/// Bundle extensions that are user libraries (never entered, never cleaned).
const LIBRARY_BUNDLES: &[&str] = &[
    "photoslibrary",
    "photolibrary",
    "musiclibrary",
    "tvlibrary",
    "imovielibrary",
    "fcpbundle",
];

/// Apple paths that are plain caches (allowed despite the `com.apple.` rule).
pub fn apple_cache_exceptions(home: &Path) -> Vec<PathBuf> {
    let lib = home.join("Library");
    vec![
        lib.join("Caches/com.apple.Safari"),
        lib.join("Containers/com.apple.Safari/Data/Library/Caches"),
        lib.join("Caches/com.apple.dt.Xcode"),
    ]
}

/// Path is absolute, normalised (no `.` / `..`, no empty component) and valid UTF-8.
pub fn is_clean_path(p: &Path) -> bool {
    p.is_absolute()
        && p.to_str().is_some()
        && p.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
}

fn lower_ext(p: &Path) -> Option<String> {
    p.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
}

/// A Photos / Music / iMovie library bundle.
pub fn is_library_bundle(p: &Path) -> bool {
    lower_ext(p).is_some_and(|e| LIBRARY_BUNDLES.contains(&e.as_str()))
}

/// Deny list shared by every category (see the module docs).
pub fn denied(home: &Path, p: &Path) -> Option<&'static str> {
    let Ok(rel) = p.strip_prefix(home) else {
        return None;
    };
    if rel.as_os_str().is_empty() {
        return Some("dossier personnel");
    }
    for d in DENIED_HOME {
        if rel.starts_with(d) {
            return Some("dossier protégé");
        }
    }
    if let Ok(lib_rel) = rel.strip_prefix("Library") {
        if lib_rel.as_os_str().is_empty() {
            return Some("Bibliothèque");
        }
        for d in DENIED_LIBRARY {
            if lib_rel.starts_with(d) {
                return Some("données personnelles (Mail, Messages, iCloud, trousseaux…)");
            }
        }
        if lib_rel.starts_with("Group Containers")
            && lib_rel
                .components()
                .nth(1)
                .and_then(|c| c.as_os_str().to_str())
                .is_some_and(|n| n.contains("com.apple"))
        {
            return Some("conteneur Apple");
        }
    }
    if rel
        .components()
        .any(|c| is_library_bundle(Path::new(c.as_os_str())))
    {
        return Some("bibliothèque Photos / Musique");
    }
    let exceptions = apple_cache_exceptions(home);
    let apple = rel.components().any(|c| {
        c.as_os_str()
            .to_str()
            .is_some_and(|n| n.starts_with("com.apple.") || n.starts_with("group.com.apple."))
    });
    if apple && !exceptions.iter().any(|e| p.starts_with(e)) {
        return Some("élément d'Apple / du système");
    }
    None
}

/// Entries of `~/Library/Caches` never listed by the caches category.
pub fn cache_entry_denied(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "CloudKit",
        "FamilyCircle",
        "GeoServices",
        "Metadata",
        "TemporaryItems",
        "PassKit",
        "com.apple",
    ];
    let lower = name.to_ascii_lowercase();
    name.starts_with('.')
        || name.starts_with("com.apple.")
        || EXACT.contains(&name)
        || lower.contains("parabellum")
        || lower.starts_with("com.wldeus")
}

/// A known browser cache folder.
#[derive(Debug, Clone)]
pub struct BrowserCache {
    pub path: PathBuf,
    pub name: String,
    pub bundle_id: Option<&'static str>,
}

/// Chromium "User Data" roots (Application Support) whose GPU / shader caches are listed.
const CHROMIUM_DATA: &[(&str, &str, &str)] = &[
    ("Google/Chrome", "Google Chrome", "com.google.Chrome"),
    ("BraveSoftware/Brave-Browser", "Brave", "com.brave.Browser"),
    ("Microsoft Edge", "Microsoft Edge", "com.microsoft.edgemac"),
    ("Vivaldi", "Vivaldi", "com.vivaldi.Vivaldi"),
    ("Arc/User Data", "Arc", "company.thebrowser.Browser"),
];
/// Per-profile GPU caches.
const CHROMIUM_PROFILE_CACHES: &[&str] = &["GPUCache", "DawnGraphiteCache", "DawnWebGPUCache"];
/// User-Data-level shader caches.
const CHROMIUM_SHADER_CACHES: &[&str] = &["ShaderCache", "GrShaderCache", "GraphiteDawnCache"];

/// `~/Library/Caches/<dir>` of each browser (whole folder: pure cache).
const BROWSER_CACHE_DIRS: &[(&str, &str, Option<&str>)] = &[
    ("Google/Chrome", "Google Chrome", Some("com.google.Chrome")),
    (
        "BraveSoftware/Brave-Browser",
        "Brave",
        Some("com.brave.Browser"),
    ),
    (
        "Microsoft Edge",
        "Microsoft Edge",
        Some("com.microsoft.edgemac"),
    ),
    ("Firefox", "Firefox", Some("org.mozilla.firefox")),
    ("Arc", "Arc", Some("company.thebrowser.Browser")),
    (
        "company.thebrowser.Browser",
        "Arc",
        Some("company.thebrowser.Browser"),
    ),
    ("Vivaldi", "Vivaldi", Some("com.vivaldi.Vivaldi")),
    (
        "com.operasoftware.Opera",
        "Opera",
        Some("com.operasoftware.Opera"),
    ),
    ("com.apple.Safari", "Safari", Some("com.apple.Safari")),
];

fn is_profile_dir(name: &str) -> bool {
    name == "Default"
        || name.starts_with("Profile ")
        || name == "Guest Profile"
        || name == "System Profile"
}

/// Every browser cache folder that exists (never cookies, history, logins or profiles themselves).
pub fn browser_caches(home: &Path) -> Vec<BrowserCache> {
    let lib = home.join("Library");
    let mut out = Vec::new();
    for (rel, name, id) in BROWSER_CACHE_DIRS {
        out.push(BrowserCache {
            path: lib.join("Caches").join(rel),
            name: (*name).to_string(),
            bundle_id: *id,
        });
    }
    out.push(BrowserCache {
        path: lib.join("Containers/com.apple.Safari/Data/Library/Caches"),
        name: "Safari (conteneur)".into(),
        bundle_id: Some("com.apple.Safari"),
    });
    for (rel, name, id) in CHROMIUM_DATA {
        let root = lib.join("Application Support").join(rel);
        for s in CHROMIUM_SHADER_CACHES {
            out.push(BrowserCache {
                path: root.join(s),
                name: format!("{name} — {s}"),
                bundle_id: Some(id),
            });
        }
        let Ok(rd) = std::fs::read_dir(&root) else {
            continue;
        };
        let mut profiles: Vec<String> = rd
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|n| is_profile_dir(n))
            .collect();
        profiles.sort();
        for p in profiles {
            for c in CHROMIUM_PROFILE_CACHES {
                out.push(BrowserCache {
                    path: root.join(&p).join(c),
                    name: format!("{name} — {c} ({p})"),
                    bundle_id: Some(id),
                });
            }
        }
    }
    out.retain(|b| {
        std::fs::symlink_metadata(&b.path)
            .map(|m| m.is_dir())
            .unwrap_or(false)
    });
    out
}

/// `p` is one of the browser cache folders (re-validation of `clean apply`).
pub fn is_browser_cache(home: &Path, p: &Path) -> bool {
    let lib = home.join("Library");
    if BROWSER_CACHE_DIRS
        .iter()
        .any(|(rel, _, _)| p == lib.join("Caches").join(rel))
        || p == lib.join("Containers/com.apple.Safari/Data/Library/Caches")
    {
        return true;
    }
    CHROMIUM_DATA.iter().any(|(rel, _, _)| {
        let root = lib.join("Application Support").join(rel);
        let Ok(r) = p.strip_prefix(&root) else {
            return false;
        };
        let parts: Vec<&str> = r.iter().filter_map(|c| c.to_str()).collect();
        match parts.as_slice() {
            [s] => CHROMIUM_SHADER_CACHES.contains(s),
            [profile, c] => is_profile_dir(profile) && CHROMIUM_PROFILE_CACHES.contains(c),
            _ => false,
        }
    })
}

/// How a developer cache is listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevMode {
    /// The folder is one item.
    Whole,
    /// Each entry of the folder is an item (DerivedData projects, archives, device support).
    Children,
}

#[derive(Debug, Clone)]
pub struct DevCache {
    pub path: PathBuf,
    pub name: &'static str,
    pub safety: CleanSafety,
    pub mode: DevMode,
}

/// Developer caches (re-downloadable / rebuildable). Project `target/` / `node_modules` folders are never
/// listed: only global caches.
pub fn developer_caches(home: &Path, brew_cache: Option<&Path>) -> Vec<DevCache> {
    use CleanSafety::*;
    use DevMode::*;
    let lib = home.join("Library");
    let dev = lib.join("Developer");
    let caches = lib.join("Caches");
    let mut v = vec![
        (
            dev.join("Xcode/DerivedData"),
            "Xcode — DerivedData",
            Safe,
            Children,
        ),
        (
            dev.join("Xcode/Archives"),
            "Xcode — archives",
            Review,
            Children,
        ),
        (
            dev.join("Xcode/iOS DeviceSupport"),
            "Xcode — iOS DeviceSupport",
            Moderate,
            Children,
        ),
        (
            dev.join("Xcode/watchOS DeviceSupport"),
            "Xcode — watchOS DeviceSupport",
            Moderate,
            Children,
        ),
        (
            dev.join("Xcode/tvOS DeviceSupport"),
            "Xcode — tvOS DeviceSupport",
            Moderate,
            Children,
        ),
        (
            dev.join("Xcode/visionOS DeviceSupport"),
            "Xcode — visionOS DeviceSupport",
            Moderate,
            Children,
        ),
        (
            dev.join("Xcode/macOS DeviceSupport"),
            "Xcode — macOS DeviceSupport",
            Moderate,
            Children,
        ),
        (
            dev.join("CoreSimulator/Caches"),
            "Simulateurs — caches",
            Safe,
            Whole,
        ),
        (
            caches.join("com.apple.dt.Xcode"),
            "Xcode — cache",
            Safe,
            Whole,
        ),
        (home.join(".npm/_cacache"), "npm — cache", Safe, Whole),
        (home.join(".npm/_npx"), "npx — cache", Safe, Whole),
        (caches.join("Yarn"), "Yarn — cache", Safe, Whole),
        (caches.join("pip"), "pip — cache", Safe, Whole),
        (
            home.join(".cargo/registry/cache"),
            "cargo — archives des crates",
            Safe,
            Whole,
        ),
        (
            home.join(".cargo/registry/src"),
            "cargo — sources extraites",
            Safe,
            Whole,
        ),
        (
            home.join(".cargo/git/checkouts"),
            "cargo — dépôts git extraits",
            Moderate,
            Whole,
        ),
        (
            home.join(".cargo/git/db"),
            "cargo — dépôts git",
            Moderate,
            Whole,
        ),
        (
            caches.join("go-build"),
            "Go — cache de compilation",
            Safe,
            Whole,
        ),
        (caches.join("CocoaPods"), "CocoaPods — cache", Safe, Whole),
        (
            caches.join("ms-playwright"),
            "Playwright — navigateurs",
            Moderate,
            Whole,
        ),
        (
            home.join(".gradle/caches"),
            "Gradle — caches",
            Moderate,
            Whole,
        ),
    ];
    let brew = brew_cache
        .map(Path::to_path_buf)
        .unwrap_or_else(|| caches.join("Homebrew"));
    v.push((brew, "Homebrew — téléchargements", Safe, Whole));
    v.into_iter()
        .map(|(path, name, safety, mode)| DevCache {
            path,
            name,
            safety,
            mode,
        })
        .collect()
}

/// Folders that may hold leftovers, with the safety of what is found there.
pub fn leftover_roots(home: &Path) -> Vec<(PathBuf, LeftoverKind, CleanSafety)> {
    let lib = home.join("Library");
    use LeftoverKind::*;
    [
        ("Application Support", Plain, CleanSafety::Review),
        ("Caches", Plain, CleanSafety::Safe),
        ("Preferences", PlistFile, CleanSafety::Review),
        ("Containers", Plain, CleanSafety::Review),
        ("Group Containers", Group, CleanSafety::Review),
        ("Saved Application State", SavedState, CleanSafety::Safe),
        ("HTTPStorages", Http, CleanSafety::Safe),
        ("WebKit", Plain, CleanSafety::Safe),
        ("LaunchAgents", LaunchAgent, CleanSafety::Review),
    ]
    .into_iter()
    .map(|(d, k, s)| (lib.join(d), k, s))
    .collect()
}

/// How entry names of a leftover root map to bundle ids.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftoverKind {
    /// `<id>` folder.
    Plain,
    /// `<id>.plist`.
    PlistFile,
    /// `group.<id>` / `<TEAMID>.<id>` / `<TEAMID>.group.<id>`.
    Group,
    /// `<id>.savedState`.
    SavedState,
    /// `<id>` folder or `<id>.binarycookies`.
    Http,
    /// `<label>.plist`, also checked against its program path.
    LaunchAgent,
}

/// Reverse-DNS bundle id with at least three components (`com.vendor.app`).
pub fn looks_like_bundle_id(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 64
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        && parts[0].len() >= 2
        && parts[0].bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_team_id(s: &str) -> bool {
    s.len() == 10
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Bundle id named by an entry of a leftover root.
pub fn leftover_id(kind: LeftoverKind, name: &str) -> Option<String> {
    let id = match kind {
        LeftoverKind::Plain => name,
        LeftoverKind::PlistFile | LeftoverKind::LaunchAgent => name.strip_suffix(".plist")?,
        LeftoverKind::SavedState => name.strip_suffix(".savedState")?,
        LeftoverKind::Http => name.strip_suffix(".binarycookies").unwrap_or(name),
        LeftoverKind::Group => {
            let rest = match name.split_once('.') {
                Some((team, rest)) if is_team_id(team) => rest,
                _ => name,
            };
            rest.strip_prefix("group.").unwrap_or(rest)
        }
    };
    looks_like_bundle_id(id).then(|| id.to_string())
}

/// `com.vendor` (lowercase) of a bundle id.
pub fn vendor(id: &str) -> String {
    let mut it = id.split('.');
    match (it.next(), it.next()) {
        (Some(a), Some(b)) => format!("{}.{}", a, b).to_ascii_lowercase(),
        _ => id.to_ascii_lowercase(),
    }
}

/// Never reported as leftovers: Apple, Parabellum, system groups.
pub fn protected_id(id: &str) -> bool {
    let v = vendor(id);
    v == "com.apple"
        || v.starts_with("apple.")
        || v.ends_with(".apple")
        || v == "com.wldeus"
        || id.starts_with("systemgroup.")
        || id.to_ascii_lowercase().contains("parabellum")
}

/// Installer kinds recognised in Downloads by extension alone.
pub fn installer_ext(p: &Path) -> Option<&'static str> {
    match lower_ext(p)?.as_str() {
        "dmg" => Some("image disque"),
        "pkg" | "mpkg" => Some("paquet d'installation"),
        "xip" => Some("archive Xcode"),
        _ => None,
    }
}

/// VM disk images / bundles (listed but never preselected, with a note).
pub fn is_vm_image(p: &Path) -> bool {
    lower_ext(p).is_some_and(|e| {
        matches!(
            e.as_str(),
            "vmdk" | "qcow2" | "vdi" | "vhd" | "vhdx" | "utm" | "pvm" | "vmwarevm" | "hdd" | "raw"
        )
    })
}

/// VM bundles treated as one file by the large-files walk.
pub fn is_vm_bundle(p: &Path) -> bool {
    lower_ext(p).is_some_and(|e| matches!(e.as_str(), "utm" | "pvm" | "vmwarevm"))
}

/// Folders skipped by the large-files walk (relative to home at the top, anywhere for the others).
pub fn large_walk_skips(home: &Path, p: &Path, is_dir: bool) -> bool {
    if !is_dir {
        return false;
    }
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.starts_with('.') || is_library_bundle(p) || name.ends_with(".app") {
        return true;
    }
    if p.parent() == Some(home) {
        return matches!(name, "Library" | "Music" | "Applications");
    }
    name == "Photo Booth Library"
}

/// Safety of a category (most items share it).
pub fn category_safety(c: CleanCategory) -> CleanSafety {
    match c {
        CleanCategory::Caches | CleanCategory::BrowserCaches | CleanCategory::Logs => {
            CleanSafety::Safe
        }
        CleanCategory::DeveloperCaches | CleanCategory::Trash => CleanSafety::Moderate,
        CleanCategory::Downloads | CleanCategory::LargeFiles | CleanCategory::AppLeftovers => {
            CleanSafety::Review
        }
    }
}

/// French title and description of a category.
pub fn category_text(c: CleanCategory) -> (&'static str, &'static str) {
    match c {
        CleanCategory::Caches => (
            "Caches des applications",
            "Fichiers temporaires que les applications recréent toutes seules. Les caches d'Apple et du système ne sont jamais touchés.",
        ),
        CleanCategory::BrowserCaches => (
            "Caches des navigateurs",
            "Pages et images gardées par Chrome, Brave, Edge, Firefox, Safari… Jamais les cookies, l'historique, les mots de passe ni les profils.",
        ),
        CleanCategory::DeveloperCaches => (
            "Outils de développement",
            "Xcode, simulateurs, Homebrew, npm, Yarn, pip, cargo, Go… Recréés ou retéléchargés à la demande ; les dossiers des projets ne sont jamais touchés.",
        ),
        CleanCategory::Logs => (
            "Journaux",
            "Journaux et rapports de plantage de plus de 30 jours.",
        ),
        CleanCategory::Downloads => (
            "Installeurs téléchargés",
            "Images disque, paquets et archives d'applications de plus de 30 jours dans Téléchargements. À vérifier : rien n'est coché d'office.",
        ),
        CleanCategory::LargeFiles => (
            "Gros fichiers anciens",
            "Plus de 500 Mo, pas ouverts depuis 6 mois (hors Bibliothèque, Photos et Musique). À vérifier : rien n'est coché d'office.",
        ),
        CleanCategory::AppLeftovers => (
            "Restes d'applications",
            "Données d'applications désinstallées. Les caches sont cochés ; réglages et données sont à vérifier.",
        ),
        CleanCategory::Trash => ("Corbeille", "Vider la corbeille est définitif."),
    }
}
