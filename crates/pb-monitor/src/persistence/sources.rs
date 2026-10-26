//! Enumeration of every persistence location. Each source is independently failure-tolerant: a
//! source (or a directory) that cannot be read is reported in [`ScanOutcome`] so the watcher can
//! carry the previous items over instead of reporting them as removed.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use pb_core::model::{PersistenceItem, PersistenceKind, PersistenceStatus};

use super::item_id;
use super::parsers::{
    chrome_message, chrome_message_key, crontab_entries, file_url_to_path, parse_bundle_info,
    parse_chrome_manifest, parse_launchd_plist, parse_login_hooks, parse_pluginkit,
    parse_profiles_xml, parse_sfltool_dumpbtm, parse_systemextensionsctl,
};
use crate::user::user_name;
use crate::util::{read_file_bounded, run_command, run_command_ok, sha256_bytes, sha256_file};
use crate::{ConsoleUser, MonitorError};

/// Max size of a plist / manifest / script we parse.
const MAX_CONFIG_FILE: u64 = 1024 * 1024;
/// Programs larger than this are not hashed.
const MAX_HASHED_PROGRAM: u64 = 200 * 1024 * 1024;
/// Max entries read from one directory.
const MAX_DIR_ENTRIES: usize = 2000;
/// Max hash cache entries.
const MAX_HASH_CACHE: usize = 8192;

pub(crate) const SYSTEM_LAUNCH_AGENTS: &str = "/Library/LaunchAgents";
pub(crate) const SYSTEM_LAUNCH_DAEMONS: &str = "/Library/LaunchDaemons";
const CRON_TABS: &str = "/usr/lib/cron/tabs";
const SFLTOOL: &str = "/usr/bin/sfltool";
const PROFILES: &str = "/usr/bin/profiles";
const SYSEXTCTL: &str = "/usr/bin/systemextensionsctl";
const PLUGINKIT: &str = "/usr/bin/pluginkit";
const LAUNCHCTL: &str = "/bin/launchctl";
const SUDO: &str = "/usr/bin/sudo";
const SYSTEM_EXTENSIONS_DIR: &str = "/Library/SystemExtensions";
pub(crate) const KEXT_DIRS: &[&str] = &["/Library/Extensions", "/Library/StagedExtensions"];
pub(crate) const AUTH_PLUGINS_DIR: &str = "/Library/Security/SecurityAgentPlugins";
pub(crate) const PERIODIC_DIRS: &[&str] = &[
    "/etc/periodic/daily",
    "/etc/periodic/weekly",
    "/etc/periodic/monthly",
    "/usr/local/etc/periodic/daily",
    "/usr/local/etc/periodic/weekly",
    "/usr/local/etc/periodic/monthly",
];
pub(crate) const PERIODIC_FILES: &[&str] = &[
    "/etc/periodic.conf",
    "/etc/periodic.conf.local",
    "/etc/daily.local",
    "/etc/weekly.local",
    "/etc/monthly.local",
];
pub(crate) const SYSTEM_CRONTAB: &str = "/etc/crontab";
pub(crate) const USER_SHELL_FILES: &[&str] = &[
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".zlogin",
    ".zlogout",
    ".bash_profile",
    ".bashrc",
    ".bash_login",
    ".profile",
];
pub(crate) const SYSTEM_SHELL_FILES: &[&str] = &[
    "/etc/zshrc",
    "/etc/zprofile",
    "/etc/zshenv",
    "/etc/profile",
    "/etc/bashrc",
];
const LOGINWINDOW_PLISTS: &[&str] = &[
    "/var/root/Library/Preferences/com.apple.loginwindow.plist",
    "/Library/Preferences/com.apple.loginwindow.plist",
];
/// Chromium-based browsers: (name, path relative to the home).
const CHROMIUM_ROOTS: &[(&str, &str)] = &[
    ("chrome", "Library/Application Support/Google/Chrome"),
    (
        "chrome_beta",
        "Library/Application Support/Google/Chrome Beta",
    ),
    ("chromium", "Library/Application Support/Chromium"),
    (
        "brave",
        "Library/Application Support/BraveSoftware/Brave-Browser",
    ),
    ("edge", "Library/Application Support/Microsoft Edge"),
    ("arc", "Library/Application Support/Arc/User Data"),
];
const SAFARI_PROTOCOLS: &[&str] = &[
    "com.apple.Safari.web-extension",
    "com.apple.Safari.content-blocker",
    "com.apple.Safari.extension",
];

/// A persistence source (unit of failure tolerance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Source {
    Launchd,
    Btm,
    Cron,
    Periodic,
    ShellProfiles,
    ConfigProfiles,
    SystemExtensions,
    KernelExtensions,
    AuthPlugins,
    ChromeExtensions,
    SafariExtensions,
    LoginHooks,
}

impl Source {
    /// Sources that spawn a system tool (run at start, on BTM triggers and on full scans only).
    pub(crate) fn is_slow(self) -> bool {
        matches!(
            self,
            Source::Btm
                | Source::ConfigProfiles
                | Source::SystemExtensions
                | Source::SafariExtensions
        )
    }
}

/// Which source produced an item.
pub(crate) fn source_of(item: &PersistenceItem) -> Source {
    match item.kind {
        PersistenceKind::LaunchAgent | PersistenceKind::LaunchDaemon => Source::Launchd,
        PersistenceKind::LoginItem | PersistenceKind::BackgroundItem => Source::Btm,
        PersistenceKind::Cron => Source::Cron,
        PersistenceKind::Periodic => Source::Periodic,
        PersistenceKind::ShellProfile => Source::ShellProfiles,
        PersistenceKind::ConfigurationProfile => Source::ConfigProfiles,
        PersistenceKind::SystemExtension => Source::SystemExtensions,
        PersistenceKind::KernelExtension => Source::KernelExtensions,
        PersistenceKind::AuthorizationPlugin => Source::AuthPlugins,
        PersistenceKind::BrowserExtension => {
            if item.arguments.iter().any(|a| a == "browser=safari") {
                Source::SafariExtensions
            } else {
                Source::ChromeExtensions
            }
        }
        PersistenceKind::Other => Source::LoginHooks,
    }
}

/// Result of a scan.
#[derive(Debug, Default)]
pub(crate) struct ScanOutcome {
    pub items: Vec<PersistenceItem>,
    /// Sources that failed entirely (previous items must be carried over).
    pub failed_sources: BTreeSet<Source>,
    /// Directories that could not be read (previous items below them must be carried over).
    pub failed_prefixes: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
struct CachedHash {
    len: u64,
    mtime: i128,
    ino: u64,
    sha256: String,
}

/// A tool-based source runner.
type SlowSource =
    fn(&mut Scanner, i64, Option<&ConsoleUser>, &mut ScanOutcome) -> Result<(), MonitorError>;

/// Stateful scanner (keeps a program hash cache keyed by size/mtime/inode between scans).
#[derive(Debug, Default)]
pub(crate) struct Scanner {
    hashes: HashMap<PathBuf, CachedHash>,
}

fn new_item(
    kind: PersistenceKind,
    path: String,
    label: Option<String>,
    now: i64,
) -> PersistenceItem {
    PersistenceItem {
        id: item_id(kind, &path, label.as_deref()),
        kind,
        label,
        path,
        program: None,
        arguments: Vec::new(),
        user: None,
        signing: None,
        program_sha256: None,
        first_seen: now,
        last_seen: now,
        status: PersistenceStatus::New,
        verdict: None,
    }
}

fn home_user(home: &Path) -> Option<String> {
    home.file_name().map(|n| n.to_string_lossy().into_owned())
}

/// Lists a directory (bounded). `Ok(None)` when it does not exist.
fn list_dir(dir: &Path) -> Result<Option<Vec<PathBuf>>, std::io::Error> {
    match std::fs::read_dir(dir) {
        Ok(rd) => {
            let mut v: Vec<PathBuf> = rd
                .flatten()
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .take(MAX_DIR_ENTRIES)
                .map(|e| e.path())
                .collect();
            v.sort();
            Ok(Some(v))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// `path` is a launchd plist location already covered by the plist scan.
fn in_launchd_dir(path: &str) -> bool {
    let p = Path::new(path);
    if p.starts_with(SYSTEM_LAUNCH_AGENTS) || p.starts_with(SYSTEM_LAUNCH_DAEMONS) {
        return true;
    }
    let comps: Vec<String> = p
        .components()
        .take(5)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    (comps.len() == 5 && comps[1] == "Users" && comps[3] == "Library" && comps[4] == "LaunchAgents")
        || p.starts_with("/var/root/Library/LaunchAgents")
}

impl Scanner {
    /// SHA-256 of a program, cached by (size, mtime, inode).
    pub(crate) fn hash(&mut self, path: &Path) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path).ok()?;
        if !meta.is_file() || meta.len() > MAX_HASHED_PROGRAM {
            return None;
        }
        let mtime = i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec());
        if let Some(c) = self.hashes.get(path) {
            if c.len == meta.len() && c.mtime == mtime && c.ino == meta.ino() {
                return Some(c.sha256.clone());
            }
        }
        let sha = sha256_file(path, MAX_HASHED_PROGRAM)?;
        if self.hashes.len() >= MAX_HASH_CACHE {
            self.hashes.clear();
        }
        self.hashes.insert(
            path.to_path_buf(),
            CachedHash {
                len: meta.len(),
                mtime,
                ino: meta.ino(),
                sha256: sha.clone(),
            },
        );
        Some(sha)
    }

    fn hash_program(&mut self, program: Option<&str>) -> Option<String> {
        let p = Path::new(program?);
        if p.is_absolute() {
            self.hash(p)
        } else {
            None
        }
    }

    /// Runs every source (`include_slow`: also the tool-based ones).
    pub(crate) fn scan(
        &mut self,
        homes: &[PathBuf],
        console: Option<&ConsoleUser>,
        include_slow: bool,
    ) -> ScanOutcome {
        let now = pb_core::now_ts();
        let mut out = ScanOutcome::default();

        // launchd
        self.scan_launchd_dir(
            Path::new(SYSTEM_LAUNCH_AGENTS),
            PersistenceKind::LaunchAgent,
            None,
            now,
            &mut out,
        );
        self.scan_launchd_dir(
            Path::new(SYSTEM_LAUNCH_DAEMONS),
            PersistenceKind::LaunchDaemon,
            None,
            now,
            &mut out,
        );
        for home in homes {
            self.scan_launchd_dir(
                &home.join("Library/LaunchAgents"),
                PersistenceKind::LaunchAgent,
                home_user(home),
                now,
                &mut out,
            );
        }
        self.scan_cron(now, &mut out);
        self.scan_periodic(now, &mut out);
        self.scan_shell_profiles(homes, now, &mut out);
        self.scan_kexts(now, &mut out);
        self.scan_auth_plugins(now, &mut out);
        for home in homes {
            self.scan_chromium(home, now, &mut out);
        }
        self.scan_login_hooks(now, &mut out);

        if include_slow {
            let runs: [(Source, SlowSource); 4] = [
                (Source::Btm, |s, now, _, out| s.scan_btm(now, out)),
                (Source::ConfigProfiles, |s, now, _, out| {
                    s.scan_profiles(now, out)
                }),
                (Source::SystemExtensions, |s, now, _, out| {
                    s.scan_system_extensions(now, out)
                }),
                (Source::SafariExtensions, |s, now, console, out| {
                    s.scan_safari(now, console, out)
                }),
            ];
            for (source, f) in runs {
                if let Err(e) = f(self, now, console, &mut out) {
                    tracing::debug!(?source, error = %e, "persistence source unavailable");
                    out.failed_sources.insert(source);
                }
            }
        }

        // De-duplicate by id (first wins).
        let mut seen = HashSet::new();
        out.items.retain(|i| seen.insert(i.id.clone()));
        out
    }

    fn scan_launchd_dir(
        &mut self,
        dir: &Path,
        kind: PersistenceKind,
        user: Option<String>,
        now: i64,
        out: &mut ScanOutcome,
    ) {
        let entries = match list_dir(dir) {
            Ok(Some(v)) => v,
            Ok(None) => return,
            Err(e) => {
                tracing::debug!(dir = %dir.display(), error = %e, "launchd folder unreadable");
                out.failed_prefixes.push(dir.to_path_buf());
                return;
            }
        };
        for path in entries {
            if !std::fs::metadata(&path)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                continue;
            }
            // Unparsable plists are still reported (path only): they are suspicious by themselves.
            let parsed = read_file_bounded(&path, MAX_CONFIG_FILE)
                .ok()
                .and_then(|b| parse_launchd_plist(&b).ok());
            let label = parsed.as_ref().and_then(|p| p.label.clone());
            let mut item = new_item(kind, path.to_string_lossy().into_owned(), label, now);
            if let Some(p) = parsed {
                item.program_sha256 = self.hash_program(p.program.as_deref());
                item.program = p.program;
                item.arguments = p.arguments;
                item.user = user.clone().or(p.user_name);
            } else {
                item.user = user.clone();
            }
            out.items.push(item);
        }
    }

    /// Item for a file that is itself executed / sourced (script, crontab, profile): `program` is
    /// the file, `program_sha256` its content hash.
    fn file_item(
        &mut self,
        kind: PersistenceKind,
        path: &Path,
        user: Option<String>,
        entries: bool,
        now: i64,
    ) -> Option<PersistenceItem> {
        if !std::fs::metadata(path)
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            return None;
        }
        let label = path.file_name().map(|n| n.to_string_lossy().into_owned());
        let path_s = path.to_string_lossy().into_owned();
        let mut item = new_item(kind, path_s.clone(), label, now);
        item.program = Some(path_s);
        item.user = user;
        match read_file_bounded(path, MAX_CONFIG_FILE) {
            Ok(bytes) => {
                item.program_sha256 = Some(sha256_bytes(&bytes));
                if entries {
                    item.arguments = crontab_entries(&String::from_utf8_lossy(&bytes));
                }
            }
            Err(_) => item.program_sha256 = self.hash(path),
        }
        Some(item)
    }

    fn scan_files_in(
        &mut self,
        dir: &Path,
        kind: PersistenceKind,
        user_from_name: bool,
        entries: bool,
        now: i64,
        out: &mut ScanOutcome,
    ) {
        match list_dir(dir) {
            Ok(Some(files)) => {
                for f in files {
                    let user = if user_from_name {
                        f.file_name().map(|n| n.to_string_lossy().into_owned())
                    } else {
                        None
                    };
                    if let Some(i) = self.file_item(kind, &f, user, entries, now) {
                        out.items.push(i);
                    }
                }
            }
            Ok(None) => {}
            Err(_) => out.failed_prefixes.push(dir.to_path_buf()),
        }
    }

    fn scan_cron(&mut self, now: i64, out: &mut ScanOutcome) {
        self.scan_files_in(
            Path::new(CRON_TABS),
            PersistenceKind::Cron,
            true,
            true,
            now,
            out,
        );
        if let Some(i) = self.file_item(
            PersistenceKind::Cron,
            Path::new(SYSTEM_CRONTAB),
            None,
            true,
            now,
        ) {
            out.items.push(i);
        }
    }

    fn scan_periodic(&mut self, now: i64, out: &mut ScanOutcome) {
        for d in PERIODIC_DIRS {
            self.scan_files_in(
                Path::new(d),
                PersistenceKind::Periodic,
                false,
                false,
                now,
                out,
            );
        }
        for f in PERIODIC_FILES {
            if let Some(i) =
                self.file_item(PersistenceKind::Periodic, Path::new(f), None, false, now)
            {
                out.items.push(i);
            }
        }
    }

    fn scan_shell_profiles(&mut self, homes: &[PathBuf], now: i64, out: &mut ScanOutcome) {
        for f in SYSTEM_SHELL_FILES {
            if let Some(i) = self.file_item(
                PersistenceKind::ShellProfile,
                Path::new(f),
                None,
                false,
                now,
            ) {
                out.items.push(i);
            }
        }
        for home in homes {
            for f in USER_SHELL_FILES {
                if let Some(i) = self.file_item(
                    PersistenceKind::ShellProfile,
                    &home.join(f),
                    home_user(home),
                    false,
                    now,
                ) {
                    out.items.push(i);
                }
            }
        }
    }

    /// Bundle item (kext, auth plugin, system extension): label = bundle id, program = main executable.
    fn bundle_item(&mut self, kind: PersistenceKind, bundle: &Path, now: i64) -> PersistenceItem {
        let info = read_file_bounded(&bundle.join("Contents/Info.plist"), MAX_CONFIG_FILE)
            .ok()
            .and_then(|b| parse_bundle_info(&b).ok())
            .unwrap_or_default();
        let mut item = new_item(
            kind,
            bundle.to_string_lossy().into_owned(),
            info.identifier.clone(),
            now,
        );
        if let Some(exe) = &info.executable {
            let p = bundle.join("Contents/MacOS").join(exe);
            item.program_sha256 = self.hash(&p);
            item.program = Some(p.to_string_lossy().into_owned());
        }
        if let Some(v) = info.version {
            item.arguments.push(format!("version={v}"));
        }
        item
    }

    fn scan_kexts(&mut self, now: i64, out: &mut ScanOutcome) {
        for dir in KEXT_DIRS {
            let root = Path::new(dir);
            if !root.exists() {
                continue;
            }
            let mut walker = walkdir::WalkDir::new(root)
                .max_depth(6)
                .follow_links(false)
                .into_iter();
            let mut count = 0usize;
            loop {
                let entry = match walker.next() {
                    None => break,
                    Some(Ok(e)) => e,
                    Some(Err(e)) => {
                        if e.depth() == 0 {
                            out.failed_prefixes.push(root.to_path_buf());
                            break;
                        }
                        continue;
                    }
                };
                if entry.file_type().is_dir()
                    && entry
                        .path()
                        .extension()
                        .map(|x| x == "kext")
                        .unwrap_or(false)
                {
                    walker.skip_current_dir();
                    out.items.push(self.bundle_item(
                        PersistenceKind::KernelExtension,
                        entry.path(),
                        now,
                    ));
                    count += 1;
                    if count >= 512 {
                        break;
                    }
                }
            }
        }
    }

    fn scan_auth_plugins(&mut self, now: i64, out: &mut ScanOutcome) {
        match list_dir(Path::new(AUTH_PLUGINS_DIR)) {
            Ok(Some(entries)) => {
                for b in entries.into_iter().filter(|p| p.is_dir()) {
                    out.items
                        .push(self.bundle_item(PersistenceKind::AuthorizationPlugin, &b, now));
                }
            }
            Ok(None) => {}
            Err(_) => out.failed_prefixes.push(PathBuf::from(AUTH_PLUGINS_DIR)),
        }
    }

    fn scan_chromium(&mut self, home: &Path, now: i64, out: &mut ScanOutcome) {
        for (browser, rel) in CHROMIUM_ROOTS {
            let root = home.join(rel);
            let Ok(Some(profiles)) = list_dir(&root) else {
                continue;
            };
            for profile in profiles.into_iter().take(32) {
                let ext_dir = profile.join("Extensions");
                let ids = match list_dir(&ext_dir) {
                    Ok(Some(v)) => v,
                    Ok(None) => continue,
                    Err(_) => {
                        out.failed_prefixes.push(ext_dir);
                        continue;
                    }
                };
                let profile_name = profile
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                for ext in ids.into_iter().take(512) {
                    let id = ext
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    if id == "Temp" || !ext.is_dir() {
                        continue;
                    }
                    // Newest version directory that has a manifest.
                    let Ok(Some(mut versions)) = list_dir(&ext) else {
                        continue;
                    };
                    versions.retain(|v| v.join("manifest.json").is_file());
                    versions.sort_by_key(|v| std::fs::metadata(v).and_then(|m| m.modified()).ok());
                    let Some(vdir) = versions.last() else {
                        continue;
                    };
                    let Ok(bytes) = read_file_bounded(&vdir.join("manifest.json"), MAX_CONFIG_FILE)
                    else {
                        continue;
                    };
                    let Ok(m) = parse_chrome_manifest(&bytes) else {
                        continue;
                    };
                    let mut name = m.name.clone();
                    if let Some(key) = chrome_message_key(&m.name) {
                        let locale = m.default_locale.clone().unwrap_or_else(|| "en".into());
                        name = read_file_bounded(
                            &vdir.join("_locales").join(&locale).join("messages.json"),
                            MAX_CONFIG_FILE,
                        )
                        .ok()
                        .and_then(|b| chrome_message(&b, key))
                        .unwrap_or_else(|| id.clone());
                    }
                    if name.is_empty() {
                        name = id.clone();
                    }
                    let mut item = new_item(
                        PersistenceKind::BrowserExtension,
                        ext.to_string_lossy().into_owned(),
                        Some(name),
                        now,
                    );
                    item.arguments = vec![
                        format!("browser={browser}"),
                        format!("profile={profile_name}"),
                        format!("id={id}"),
                    ];
                    if let Some(v) = m.version {
                        item.arguments.push(format!("version={v}"));
                    }
                    item.user = home_user(home);
                    out.items.push(item);
                }
            }
        }
    }

    fn scan_login_hooks(&mut self, now: i64, out: &mut ScanOutcome) {
        for plist in LOGINWINDOW_PLISTS {
            let path = Path::new(plist);
            let bytes = match read_file_bounded(path, MAX_CONFIG_FILE) {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    out.failed_prefixes.push(path.to_path_buf());
                    continue;
                }
            };
            let Ok(hooks) = parse_login_hooks(&bytes) else {
                continue;
            };
            for (key, script) in hooks {
                let mut item = new_item(PersistenceKind::Other, plist.to_string(), Some(key), now);
                item.program_sha256 = self.hash_program(Some(&script));
                item.program = Some(script);
                out.items.push(item);
            }
        }
    }

    // ---- slow sources (system tools) -------------------------------------------------------

    fn scan_btm(&mut self, now: i64, out: &mut ScanOutcome) -> Result<(), MonitorError> {
        let stdout = run_command_ok(
            SFLTOOL,
            &["dumpbtm"],
            Duration::from_secs(30),
            8 * 1024 * 1024,
        )?;
        let text = String::from_utf8_lossy(&stdout);
        let records = parse_sfltool_dumpbtm(&text);
        if records.is_empty() && !text.contains("Records for UID") {
            return Err(MonitorError::Parse("unexpected sfltool output".into()));
        }
        for r in records {
            let ty = r.item_type.to_ascii_lowercase();
            if ty.contains("developer") {
                continue;
            }
            let url_path = r.url.as_deref().map(file_url_to_path);
            if ty.contains("legacy") && url_path.as_deref().map(in_launchd_dir).unwrap_or(false) {
                continue; // already reported by the launchd plist scan
            }
            let Some(path) = url_path
                .clone()
                .or_else(|| r.executable_path.clone())
                .or_else(|| r.identifier.clone())
            else {
                continue;
            };
            let kind = if ty.contains("login item") {
                PersistenceKind::LoginItem
            } else {
                PersistenceKind::BackgroundItem
            };
            let mut item = new_item(
                kind,
                path.clone(),
                r.identifier.clone().or_else(|| r.name.clone()),
                now,
            );
            item.program = r.executable_path.clone().or_else(|| {
                if path.ends_with(".app") {
                    Some(path.clone())
                } else {
                    None
                }
            });
            item.program_sha256 = self.hash_program(item.program.as_deref());
            item.user = r
                .uid
                .filter(|u| *u >= 0)
                .map(|u| user_name(u as u32).unwrap_or_else(|| u.to_string()));
            if !r.item_type.is_empty() {
                item.arguments.push(format!("type={}", r.item_type));
            }
            if let Some(t) = &r.team_id {
                item.arguments.push(format!("team={t}"));
            }
            if let Some(d) = &r.developer_name {
                item.arguments.push(format!("developer={d}"));
            }
            out.items.push(item);
        }
        Ok(())
    }

    fn scan_profiles(&mut self, now: i64, out: &mut ScanOutcome) -> Result<(), MonitorError> {
        let first = run_command(
            PROFILES,
            &["show", "-all", "-output", "stdout-xml"],
            Duration::from_secs(30),
            8 * 1024 * 1024,
        )?;
        let stdout = if first.success {
            first.stdout
        } else {
            run_command_ok(
                PROFILES,
                &["show", "-output", "stdout-xml"],
                Duration::from_secs(30),
                8 * 1024 * 1024,
            )?
        };
        let trimmed = String::from_utf8_lossy(&stdout);
        let looks_plist = trimmed.trim_start().starts_with('<') || stdout.starts_with(b"bplist");
        let records = if looks_plist {
            parse_profiles_xml(&stdout)?
        } else if trimmed
            .to_ascii_lowercase()
            .contains("no configuration profiles")
            || trimmed.trim().is_empty()
        {
            Vec::new()
        } else {
            return Err(MonitorError::Parse("unexpected profiles output".into()));
        };
        for r in records {
            let scope = r.user.clone().unwrap_or_else(|| "computer".into());
            let path = format!("profile:{scope}/{}", r.identifier);
            let mut item = new_item(
                PersistenceKind::ConfigurationProfile,
                path,
                r.display_name.clone().or(Some(r.identifier.clone())),
                now,
            );
            item.user = r.user.clone();
            if let Some(u) = &r.uuid {
                item.arguments.push(format!("uuid={u}"));
            }
            if let Some(o) = &r.organization {
                item.arguments.push(format!("organization={o}"));
            }
            item.arguments
                .extend(r.payload_types.iter().map(|t| format!("payload={t}")));
            out.items.push(item);
        }
        Ok(())
    }

    fn scan_system_extensions(
        &mut self,
        now: i64,
        out: &mut ScanOutcome,
    ) -> Result<(), MonitorError> {
        let res = run_command(SYSEXTCTL, &["list"], Duration::from_secs(15), 1024 * 1024)?;
        let text = String::from_utf8_lossy(&res.stdout);
        if !text.contains("extension(s)") {
            return Err(MonitorError::Command {
                program: SYSEXTCTL.into(),
                message: res.stderr.trim().to_string(),
            });
        }
        // bundle id -> bundle path on disk (/Library/SystemExtensions/<UUID>/<id>.systemextension)
        let mut on_disk: HashMap<String, PathBuf> = HashMap::new();
        if let Ok(Some(uuids)) = list_dir(Path::new(SYSTEM_EXTENSIONS_DIR)) {
            for u in uuids.into_iter().take(256) {
                if let Ok(Some(bundles)) = list_dir(&u) {
                    for b in bundles.into_iter().take(16) {
                        if let Some(stem) = b
                            .file_name()
                            .and_then(|n| n.to_str())
                            .and_then(|n| n.strip_suffix(".systemextension"))
                        {
                            on_disk.insert(stem.to_string(), b);
                        }
                    }
                }
            }
        }
        for r in parse_systemextensionsctl(&text) {
            let mut item = match on_disk.get(&r.bundle_id) {
                Some(b) => {
                    let mut i = self.bundle_item(PersistenceKind::SystemExtension, b, now);
                    i.arguments.clear();
                    i.label = Some(r.bundle_id.clone());
                    i.id = item_id(
                        PersistenceKind::SystemExtension,
                        &i.path,
                        i.label.as_deref(),
                    );
                    i
                }
                None => new_item(
                    PersistenceKind::SystemExtension,
                    format!("sysext:{}", r.bundle_id),
                    Some(r.bundle_id.clone()),
                    now,
                ),
            };
            if let Some(c) = &r.category {
                item.arguments.push(format!("category={c}"));
            }
            if let Some(t) = &r.team_id {
                item.arguments.push(format!("team={t}"));
            }
            if let Some(v) = &r.version {
                item.arguments.push(format!("version={v}"));
            }
            if let Some(s) = &r.state {
                item.arguments.push(format!("state={s}"));
            }
            out.items.push(item);
        }
        Ok(())
    }

    fn scan_safari(
        &mut self,
        now: i64,
        console: Option<&ConsoleUser>,
        out: &mut ScanOutcome,
    ) -> Result<(), MonitorError> {
        if !Path::new(PLUGINKIT).is_file() {
            return Err(MonitorError::NotFound(PLUGINKIT.into()));
        }
        // SAFETY: geteuid has no preconditions.
        let is_root = unsafe { libc::geteuid() } == 0;
        for proto in SAFARI_PROTOCOLS {
            let stdout = match (is_root, console) {
                // PlugInKit is per user: query the console user's registry from their bootstrap
                // namespace, with their identity.
                (true, Some(u)) => {
                    let uid = u.uid.to_string();
                    let sudo_user = format!("#{}", u.uid);
                    run_command_ok(
                        LAUNCHCTL,
                        &[
                            "asuser", &uid, SUDO, "-n", "-u", &sudo_user, PLUGINKIT, "-mAvvv",
                            "-p", proto,
                        ],
                        Duration::from_secs(20),
                        1024 * 1024,
                    )?
                }
                (true, None) => return Ok(()), // nobody logged in: nothing to enumerate
                (false, _) => run_command_ok(
                    PLUGINKIT,
                    &["-mAvvv", "-p", proto],
                    Duration::from_secs(20),
                    1024 * 1024,
                )?,
            };
            for r in parse_pluginkit(&String::from_utf8_lossy(&stdout)) {
                let path = r
                    .path
                    .clone()
                    .unwrap_or_else(|| format!("pluginkit:{}", r.bundle_id));
                let label = r
                    .display_name
                    .clone()
                    .unwrap_or_else(|| r.bundle_id.clone());
                let mut item = new_item(PersistenceKind::BrowserExtension, path, Some(label), now);
                item.arguments = vec!["browser=safari".into(), format!("id={}", r.bundle_id)];
                if let Some(v) = &r.version {
                    item.arguments.push(format!("version={v}"));
                }
                item.arguments
                    .push(format!("type={}", r.sdk.as_deref().unwrap_or(proto)));
                item.user = console.map(|u| u.name.clone());
                out.items.push(item);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launchd_dir_detection() {
        assert!(in_launchd_dir(
            "/Library/LaunchDaemons/com.docker.vmnetd.plist"
        ));
        assert!(in_launchd_dir("/Users/q/Library/LaunchAgents/x.plist"));
        assert!(!in_launchd_dir("/Applications/Docker.app"));
        assert!(!in_launchd_dir("/Users/q/Library/Application Support/x"));
    }

    #[test]
    fn scans_a_fake_home() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("alice");
        let la = home.join("Library/LaunchAgents");
        std::fs::create_dir_all(&la).unwrap();
        let prog = home.join("agent.sh");
        std::fs::write(&prog, b"#!/bin/sh\necho hi\n").unwrap();
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
            <key>Label</key><string>com.alice.agent</string>
            <key>ProgramArguments</key><array><string>{}</string><string>-x</string></array>
            <key>RunAtLoad</key><true/></dict></plist>"#,
            prog.display()
        );
        std::fs::write(la.join("com.alice.agent.plist"), plist).unwrap();
        std::fs::write(la.join("broken.plist"), b"garbage").unwrap();
        std::fs::write(home.join(".zshrc"), b"export PATH=/evil:$PATH\n").unwrap();
        let ext = home.join("Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0_0");
        std::fs::create_dir_all(ext.join("_locales/en")).unwrap();
        std::fs::write(
            ext.join("manifest.json"),
            br#"{"name":"__MSG_name__","version":"1.0.0","default_locale":"en"}"#,
        )
        .unwrap();
        std::fs::write(
            ext.join("_locales/en/messages.json"),
            br#"{"name":{"message":"Evil Ext"}}"#,
        )
        .unwrap();

        let mut s = Scanner::default();
        let out = s.scan(std::slice::from_ref(&home), None, false);
        let agent = out
            .items
            .iter()
            .find(|i| i.label.as_deref() == Some("com.alice.agent"))
            .expect("agent");
        assert_eq!(agent.kind, PersistenceKind::LaunchAgent);
        assert_eq!(agent.program.as_deref(), Some(prog.to_str().unwrap()));
        assert_eq!(agent.arguments, vec!["-x".to_string()]);
        assert_eq!(agent.user.as_deref(), Some("alice"));
        assert_eq!(
            agent.program_sha256.as_deref(),
            Some(sha256_bytes(b"#!/bin/sh\necho hi\n").as_str())
        );
        assert_eq!(agent.status, PersistenceStatus::New);
        assert_eq!(agent.id.len(), 16);
        let broken = out
            .items
            .iter()
            .find(|i| i.path.ends_with("broken.plist"))
            .expect("broken plist reported");
        assert!(broken.label.is_none() && broken.program.is_none());
        let zshrc = out
            .items
            .iter()
            .find(|i| i.kind == PersistenceKind::ShellProfile && i.user.as_deref() == Some("alice"))
            .expect("zshrc");
        assert_eq!(
            zshrc.program_sha256.as_deref(),
            Some(sha256_bytes(b"export PATH=/evil:$PATH\n").as_str())
        );
        let chrome = out
            .items
            .iter()
            .find(|i| i.kind == PersistenceKind::BrowserExtension)
            .expect("chrome ext");
        assert_eq!(chrome.label.as_deref(), Some("Evil Ext"));
        assert!(chrome
            .path
            .ends_with("Extensions/abcdefghijklmnopabcdefghijklmnop"));
        assert!(chrome.arguments.contains(&"version=1.0.0".to_string()));
        assert_eq!(source_of(chrome), Source::ChromeExtensions);
        // slow sources skipped
        assert!(out.failed_sources.is_empty());

        // hash cache returns the same value; a modified program changes it
        let h1 = s.hash(&prog).unwrap();
        std::fs::write(&prog, b"#!/bin/sh\necho changed, longer\n").unwrap();
        let h2 = s.hash(&prog).unwrap();
        assert_ne!(h1, h2);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn slow_sources_fail_gracefully_off_macos() {
        let mut s = Scanner::default();
        let out = s.scan(&[], None, true);
        assert!(out.failed_sources.contains(&Source::Btm));
        assert!(out.failed_sources.contains(&Source::ConfigProfiles));
        assert!(out.failed_sources.contains(&Source::SystemExtensions));
        assert!(out.failed_sources.contains(&Source::SafariExtensions));
    }
}
