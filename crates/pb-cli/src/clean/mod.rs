//! Mac cleaning (`parabellum clean scan|apply`), run **as the user** by the app — never by the root daemon.
//!
//! `scan` lists what could be cleaned per [`CleanCategory`], with sizes, a safety level and a default
//! selection (a dry run: nothing is touched). `apply` takes a [`CleanPlan`] (category + path), checks
//! every path again against the category rules ([`rules`]), then moves it to `~/.Trash` (default,
//! recoverable) or deletes it (`permanent` categories, and the Trash itself). Symbolic links are never
//! followed, nothing outside the home folder is touched (except the Homebrew download cache when
//! `brew --cache` points elsewhere), files held open by running apps are skipped, protected
//! (SIP / locked) files are refused.

pub mod apply;
pub mod apps;
pub mod command;
pub mod rules;
pub mod sys;
#[cfg(test)]
mod tests;

pub use apply::apply;

use pb_core::model::*;
use rules::{DevMode, LeftoverKind};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use walkdir::WalkDir;

/// Items listed per category (largest first).
pub const MAX_ITEMS: usize = 1_000;
/// Entries visited by one size measurement before giving up.
const MAX_MEASURE_ENTRIES: u64 = 5_000_000;

/// Where and how to clean (the real Mac, or a fixture home in tests).
#[derive(Debug, Clone)]
pub struct CleanEnv {
    /// Canonical home folder.
    pub home: PathBuf,
    pub uid: u32,
    pub now: i64,
    /// Searched (3 levels) for `.app` bundles.
    pub app_dirs: Vec<PathBuf>,
    /// Homebrew Caskroom folders (4 levels).
    pub caskroom_dirs: Vec<PathBuf>,
    /// Ask Spotlight for installed apps and last-opened dates.
    pub spotlight: bool,
    /// Ask `lsof` for open files (when `open_files` is `None`).
    pub lsof: bool,
    pub open_files: Option<sys::OpenFiles>,
    /// `brew --cache`.
    pub brew_cache: Option<PathBuf>,
    /// Size threshold of the large-files category ([`rules::LARGE_FILE_MIN`]).
    pub large_min: u64,
    /// Bounds of the large-files walk.
    pub large_walk_entries: u64,
    pub large_walk_time: Duration,
    /// Fewer installed vendors than this: the app list is unreliable, leftovers are not searched.
    pub min_installed_vendors: usize,
}

impl CleanEnv {
    /// The current user's Mac. Refuses root: cleaning acts on one person's home folder.
    pub fn system() -> Result<Self, String> {
        let (uid, home) = sys::user_home().ok_or("dossier personnel introuvable")?;
        if uid == 0 {
            return Err(
                "le nettoyage agit sur ton dossier personnel : lance-le sans sudo".to_string(),
            );
        }
        let home = std::fs::canonicalize(&home)
            .map_err(|e| format!("dossier personnel illisible : {e}"))?;
        let mut env = Self::for_home(home);
        env.uid = uid;
        env.app_dirs = vec![
            PathBuf::from("/Applications"),
            env.home.join("Applications"),
            PathBuf::from("/System/Applications"),
            PathBuf::from("/System/Library/CoreServices"),
        ];
        env.caskroom_dirs = vec![
            PathBuf::from("/opt/homebrew/Caskroom"),
            PathBuf::from("/usr/local/Caskroom"),
        ];
        env.spotlight = true;
        env.lsof = true;
        env.brew_cache = sys::brew_cache(&env.home).filter(|p| acceptable_brew_cache(&env, p));
        Ok(env)
    }

    /// A fixture home: no external tools, no app folders (tests add what they need).
    pub fn for_home(home: PathBuf) -> Self {
        Self {
            home,
            // SAFETY: geteuid has no preconditions.
            uid: unsafe { libc::geteuid() },
            now: pb_core::now_ts(),
            app_dirs: vec![],
            caskroom_dirs: vec![],
            spotlight: false,
            lsof: false,
            open_files: None,
            brew_cache: None,
            large_min: rules::LARGE_FILE_MIN,
            large_walk_entries: 3_000_000,
            large_walk_time: Duration::from_secs(90),
            min_installed_vendors: 3,
        }
    }

    /// Open files: injected, else `lsof` (best effort), else none.
    pub fn resolve_open_files(&self) -> sys::OpenFiles {
        if let Some(o) = &self.open_files {
            return o.clone();
        }
        if self.lsof {
            if let Some(o) = sys::open_files(self.uid, &self.home) {
                return o;
            }
        }
        sys::OpenFiles::default()
    }

    pub fn library(&self) -> PathBuf {
        self.home.join("Library")
    }
}

/// `brew --cache` outside the home folder is used only when it is a plain folder owned by the user and
/// not a system location.
fn acceptable_brew_cache(env: &CleanEnv, p: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(p) else {
        return false;
    };
    if !meta.is_dir() || meta.uid() != env.uid || !rules::is_clean_path(p) {
        return false;
    }
    if p.starts_with(&env.home) {
        return p != env.home;
    }
    const SYSTEM: &[&str] = &[
        "/System",
        "/usr",
        "/bin",
        "/sbin",
        "/etc",
        "/private",
        "/var",
        "/Library",
        "/Applications",
        "/Users",
        "/Volumes",
        "/opt/homebrew/bin",
        "/opt/homebrew/Cellar",
    ];
    p.components().count() >= 3
        && !SYSTEM
            .iter()
            .any(|s| p == Path::new(s) || p.parent() == Some(Path::new(s)))
}

/// Size of a tree on disk.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Measure {
    /// Allocated bytes (what deleting frees), hard links counted once.
    pub bytes: u64,
    pub files: u64,
    /// Newest modification time of the files counted.
    pub newest: Option<i64>,
    pub unreadable: u64,
    pub truncated: bool,
}

fn allocated(meta: &std::fs::Metadata) -> u64 {
    meta.blocks().saturating_mul(512)
}

/// Measure `path` without following symbolic links. `older_than`: only files modified before it.
pub fn measure(path: &Path, older_than: Option<i64>) -> Measure {
    let mut m = Measure::default();
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut visited = 0u64;
    for e in WalkDir::new(path).follow_links(false) {
        visited += 1;
        if visited > MAX_MEASURE_ENTRIES {
            m.truncated = true;
            break;
        }
        let Ok(e) = e else {
            m.unreadable += 1;
            continue;
        };
        if e.file_type().is_dir() {
            continue;
        }
        let Ok(meta) = e.metadata() else {
            m.unreadable += 1;
            continue;
        };
        let mtime = meta.mtime();
        if older_than.is_some_and(|cut| mtime >= cut) {
            continue;
        }
        if meta.nlink() > 1 && !seen.insert((meta.dev(), meta.ino())) {
            continue;
        }
        m.bytes += allocated(&meta);
        m.files += 1;
        m.newest = Some(m.newest.map_or(mtime, |n| n.max(mtime)));
    }
    m
}

/// Stable id of an item.
pub fn item_id(category: CleanCategory, path: &Path) -> String {
    let wire = serde_json::to_value(category)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    let digest = Sha256::digest(format!("{wire}|{}", path.display()).as_bytes());
    hex::encode(digest)[..16].to_string()
}

struct ItemSpec<'a> {
    category: CleanCategory,
    path: &'a Path,
    name: String,
    m: Measure,
    safety: CleanSafety,
    bundle_id: Option<String>,
    note: Option<String>,
    last_used: Option<i64>,
}

fn make_item(spec: ItemSpec<'_>, open: &sys::OpenFiles) -> CleanItem {
    let in_use = spec.category != CleanCategory::Trash && open.touches(spec.path);
    let note = if in_use {
        Some("utilisé par une application ouverte : quitte-la pour le nettoyer".to_string())
    } else {
        spec.note
    };
    CleanItem {
        id: item_id(spec.category, spec.path),
        path: spec.path.display().to_string(),
        name: spec.name,
        size: spec.m.bytes,
        files: spec.m.files,
        modified: spec.m.newest,
        last_used: spec.last_used,
        safety: spec.safety,
        selected: spec.safety != CleanSafety::Review && !in_use,
        in_use,
        bundle_id: spec.bundle_id,
        note,
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

fn days_ago(now: i64, t: i64) -> i64 {
    ((now - t) / 86_400).max(0)
}

/// Sorted entries of a folder (empty when unreadable; `Err` keeps the reason).
fn entries(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)?
        .flatten()
        .map(|e| e.path())
        .collect();
    v.sort();
    Ok(v)
}

fn unreadable_message(dir: &Path, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(libc::EPERM) {
        format!(
            "{} : accès refusé — autorise Parabellum dans Réglages Système › Confidentialité et sécurité › Accès complet au disque.",
            dir.display()
        )
    } else {
        format!("{} : {e}", dir.display())
    }
}

/// Result of one category scanner.
#[derive(Debug, Default)]
struct Found {
    items: Vec<CleanItem>,
    error: Option<String>,
    warnings: Vec<String>,
}

/// Scanner state shared between categories.
struct Ctx<'a> {
    env: &'a CleanEnv,
    open: sys::OpenFiles,
    /// Paths listed by browser / developer / leftover categories (not repeated in Caches).
    claimed: HashSet<PathBuf>,
    installed: Option<apps::Installed>,
    names: HashMap<String, String>,
}

impl Ctx<'_> {
    fn installed(&mut self) -> &apps::Installed {
        if self.installed.is_none() {
            let inst = apps::installed(self.env);
            self.names = inst.names.clone();
            self.installed = Some(inst);
        }
        self.installed.as_ref().expect("just set")
    }
}

fn scan_trash(cx: &mut Ctx<'_>) -> Found {
    let trash = cx.env.home.join(".Trash");
    let mut f = Found::default();
    match std::fs::read_dir(&trash) {
        Ok(rd) => {
            let n = rd
                .flatten()
                .filter(|e| e.file_name() != ".DS_Store")
                .count();
            if n > 0 {
                let m = measure(&trash, None);
                f.items.push(make_item(
                    ItemSpec {
                        category: CleanCategory::Trash,
                        path: &trash,
                        name: "Corbeille".into(),
                        m,
                        safety: CleanSafety::Moderate,
                        bundle_id: None,
                        note: Some(format!("{n} élément(s), suppression définitive")),
                        last_used: None,
                    },
                    &cx.open,
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => f.error = Some(unreadable_message(&trash, &e)),
    }
    f
}

fn scan_browsers(cx: &mut Ctx<'_>) -> Found {
    let mut f = Found::default();
    for b in rules::browser_caches(&cx.env.home) {
        cx.claimed.insert(b.path.clone());
        if rules::denied(&cx.env.home, &b.path).is_some() {
            continue;
        }
        let m = measure(&b.path, None);
        if m.bytes == 0 {
            continue;
        }
        f.items.push(make_item(
            ItemSpec {
                category: CleanCategory::BrowserCaches,
                path: &b.path,
                name: b.name,
                m,
                safety: CleanSafety::Safe,
                bundle_id: b.bundle_id.map(str::to_string),
                note: None,
                last_used: None,
            },
            &cx.open,
        ));
    }
    f
}

/// `Name-abcdefgh…` (DerivedData folder) -> `Name`.
fn derived_data_name(name: &str) -> String {
    match name.rsplit_once('-') {
        Some((n, hash)) if hash.len() >= 20 && hash.bytes().all(|b| b.is_ascii_lowercase()) => {
            n.to_string()
        }
        _ => name.to_string(),
    }
}

fn scan_developer(cx: &mut Ctx<'_>) -> Found {
    let mut f = Found::default();
    for d in rules::developer_caches(&cx.env.home, cx.env.brew_cache.as_deref()) {
        cx.claimed.insert(d.path.clone());
        let Ok(meta) = std::fs::symlink_metadata(&d.path) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let targets: Vec<(PathBuf, String)> = match d.mode {
            DevMode::Whole => vec![(d.path.clone(), d.name.to_string())],
            DevMode::Children => entries(&d.path)
                .unwrap_or_default()
                .into_iter()
                .filter(|p| !file_name(p).starts_with('.'))
                .map(|p| {
                    let n = derived_data_name(&file_name(&p));
                    (p, format!("{} — {n}", d.name))
                })
                .collect(),
        };
        for (p, name) in targets {
            let m = measure(&p, None);
            if m.bytes == 0 {
                continue;
            }
            f.items.push(make_item(
                ItemSpec {
                    category: CleanCategory::DeveloperCaches,
                    path: &p,
                    name,
                    m,
                    safety: d.safety,
                    bundle_id: None,
                    note: (d.safety == CleanSafety::Review).then(|| {
                        "archive d'app publiée : nécessaire pour symboliser ses rapports de plantage"
                            .to_string()
                    }),
                    last_used: None,
                },
                &cx.open,
            ));
        }
    }
    f
}

/// Program of a LaunchAgent plist (`Program`, else `ProgramArguments[0]`).
pub fn launch_agent_program(plist_path: &Path) -> Option<PathBuf> {
    let meta = std::fs::symlink_metadata(plist_path).ok()?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return None;
    }
    let v = plist::Value::from_file(plist_path).ok()?;
    let d = v.as_dictionary()?;
    let prog = d.get("Program").and_then(|p| p.as_string()).or_else(|| {
        d.get("ProgramArguments")
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(|p| p.as_string())
    })?;
    Some(PathBuf::from(prog))
}

/// A LaunchAgent is a leftover only when its program is known and gone.
fn launch_agent_orphaned(plist_path: &Path) -> bool {
    match launch_agent_program(plist_path) {
        Some(p) => p.is_absolute() && std::fs::symlink_metadata(&p).is_err(),
        None => false,
    }
}

/// Why an entry of a leftover root is a leftover (its bundle id), or `None`.
pub fn leftover_of(
    home: &Path,
    kind: LeftoverKind,
    path: &Path,
    installed: &apps::Installed,
) -> Option<String> {
    let id = rules::leftover_id(kind, path.file_name()?.to_str()?)?;
    if rules::protected_id(&id) || installed.owns(&id) || rules::denied(home, path).is_some() {
        return None;
    }
    if kind == LeftoverKind::LaunchAgent && !launch_agent_orphaned(path) {
        return None;
    }
    Some(id)
}

fn scan_leftovers(cx: &mut Ctx<'_>) -> Found {
    let mut f = Found::default();
    let (vendors, apps) = {
        let inst = cx.installed();
        (inst.vendors.len(), inst.apps)
    };
    if vendors < cx.env.min_installed_vendors {
        f.error = Some(format!(
            "Liste des applications installées incomplète ({apps} trouvée(s)) : restes non recherchés par prudence."
        ));
        return f;
    }
    let home = cx.env.home.clone();
    for (root, kind, safety) in rules::leftover_roots(&home) {
        let list = match entries(&root) {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                f.warnings.push(unreadable_message(&root, &e));
                continue;
            }
        };
        for p in list {
            let installed = cx.installed.as_ref().expect("computed above");
            let Some(id) = leftover_of(&home, kind, &p, installed) else {
                continue;
            };
            let m = measure(&p, None);
            if m.bytes == 0 && kind != LeftoverKind::LaunchAgent {
                continue;
            }
            cx.claimed.insert(p.clone());
            let what = root
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            f.items.push(make_item(
                ItemSpec {
                    category: CleanCategory::AppLeftovers,
                    path: &p,
                    name: format!("{id} — {what}"),
                    m,
                    safety,
                    bundle_id: Some(id.clone()),
                    note: Some(match kind {
                        LeftoverKind::LaunchAgent => {
                            "agent de démarrage dont le programme a disparu".to_string()
                        }
                        _ => "aucune application installée de cet éditeur".to_string(),
                    }),
                    last_used: None,
                },
                &cx.open,
            ));
        }
    }
    f
}

fn scan_caches(cx: &mut Ctx<'_>) -> Found {
    let mut f = Found::default();
    let caches = cx.env.library().join("Caches");
    let list = match entries(&caches) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return f,
        Err(e) => {
            f.error = Some(unreadable_message(&caches, &e));
            return f;
        }
    };
    for p in list {
        let name = file_name(&p);
        if rules::cache_entry_denied(&name)
            || cx.claimed.contains(&p)
            || cx.claimed.iter().any(|c| c.starts_with(&p))
            || rules::denied(&cx.env.home, &p).is_some()
        {
            continue;
        }
        let m = measure(&p, None);
        if m.bytes == 0 {
            continue;
        }
        let display = cx.names.get(&name).cloned().unwrap_or_else(|| name.clone());
        let bundle_id = rules::looks_like_bundle_id(&name).then(|| name.clone());
        f.items.push(make_item(
            ItemSpec {
                category: CleanCategory::Caches,
                path: &p,
                name: display,
                m,
                safety: CleanSafety::Safe,
                bundle_id,
                note: None,
                last_used: None,
            },
            &cx.open,
        ));
    }
    f
}

fn scan_logs(cx: &mut Ctx<'_>) -> Found {
    let mut f = Found::default();
    let logs = cx.env.library().join("Logs");
    let cutoff = cx.env.now - rules::OLD_SECS;
    let list = match entries(&logs) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return f,
        Err(e) => {
            f.error = Some(unreadable_message(&logs, &e));
            return f;
        }
    };
    for p in list {
        if rules::denied(&cx.env.home, &p).is_some() || file_name(&p) == ".DS_Store" {
            continue;
        }
        let m = measure(&p, Some(cutoff));
        if m.files == 0 {
            continue;
        }
        let name = match file_name(&p).as_str() {
            "DiagnosticReports" => "Rapports de plantage".to_string(),
            n => n.to_string(),
        };
        f.items.push(make_item(
            ItemSpec {
                category: CleanCategory::Logs,
                path: &p,
                name,
                m,
                safety: CleanSafety::Safe,
                bundle_id: None,
                note: Some(format!("{} fichier(s) de plus de 30 jours", m.files)),
                last_used: None,
            },
            &cx.open,
        ));
    }
    f
}

/// A `.zip` whose top level holds an application bundle.
pub fn zip_has_app(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let Ok(archive) = zip::ZipArchive::new(file) else {
        return false;
    };
    let found = archive.file_names().take(5_000).any(|n| {
        let Ok(n) = n else { return false };
        let mut parts = n.split('/');
        let first = parts.next().unwrap_or("");
        let first = if first == "__MACOSX" { "" } else { first };
        first.ends_with(".app") && parts.next().is_some()
    });
    found
}

/// Installer kind of a download (`None`: not an installer).
pub fn installer_kind(path: &Path) -> Option<&'static str> {
    if let Some(k) = rules::installer_ext(path) {
        return Some(k);
    }
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    (ext == "zip" && zip_has_app(path)).then_some("archive d'application")
}

fn scan_downloads(cx: &mut Ctx<'_>) -> Found {
    let mut f = Found::default();
    let dl = cx.env.home.join("Downloads");
    if !dl.is_dir() {
        return f;
    }
    let cutoff = cx.env.now - rules::OLD_SECS;
    for e in WalkDir::new(&dl)
        .follow_links(false)
        .min_depth(1)
        .max_depth(2)
        .into_iter()
        .filter_entry(|e| !e.file_name().to_string_lossy().starts_with('.'))
    {
        let Ok(e) = e else {
            continue;
        };
        if !e.file_type().is_file() {
            continue;
        }
        let Ok(meta) = e.metadata() else {
            continue;
        };
        if meta.mtime() >= cutoff {
            continue;
        }
        let Some(kind) = installer_kind(e.path()) else {
            continue;
        };
        let m = Measure {
            bytes: allocated(&meta),
            files: 1,
            newest: Some(meta.mtime()),
            ..Default::default()
        };
        f.items.push(make_item(
            ItemSpec {
                category: CleanCategory::Downloads,
                path: e.path(),
                name: file_name(e.path()),
                m,
                safety: CleanSafety::Review,
                bundle_id: None,
                note: Some(format!(
                    "{kind}, téléchargé il y a {} jours",
                    days_ago(cx.env.now, meta.mtime())
                )),
                last_used: None,
            },
            &cx.open,
        ));
    }
    f
}

fn scan_large(cx: &mut Ctx<'_>) -> Found {
    let mut f = Found::default();
    let home = cx.env.home.clone();
    let started = Instant::now();
    let mut visited = 0u64;
    // (path, bytes, mtime, atime)
    let mut candidates: Vec<(PathBuf, Measure, i64)> = Vec::new();
    let mut it = WalkDir::new(&home)
        .follow_links(false)
        .min_depth(1)
        .into_iter();
    loop {
        let e = match it.next() {
            None => break,
            Some(Err(_)) => continue,
            Some(Ok(e)) => e,
        };
        visited += 1;
        if visited > cx.env.large_walk_entries || started.elapsed() > cx.env.large_walk_time {
            f.warnings.push(
                "Recherche des gros fichiers interrompue (dossier personnel très volumineux) : liste partielle."
                    .into(),
            );
            break;
        }
        let p = e.path();
        if e.file_type().is_dir() {
            if rules::large_walk_skips(&home, p, true) {
                it.skip_current_dir();
            } else if rules::is_vm_bundle(p) {
                it.skip_current_dir();
                let m = measure(p, None);
                if m.bytes >= cx.env.large_min {
                    // A bundle folder's access time says nothing: its files' mtime (and Spotlight) decide.
                    candidates.push((p.to_path_buf(), m, 0));
                }
            }
            continue;
        }
        if !e.file_type().is_file() {
            continue;
        }
        let Ok(meta) = e.metadata() else {
            continue;
        };
        let bytes = allocated(&meta);
        if bytes >= cx.env.large_min {
            candidates.push((
                p.to_path_buf(),
                Measure {
                    bytes,
                    files: 1,
                    newest: Some(meta.mtime()),
                    ..Default::default()
                },
                meta.atime(),
            ));
        }
    }
    let idle_cutoff = cx.env.now - rules::LARGE_FILE_IDLE_SECS;
    for (i, (p, m, atime)) in candidates.into_iter().enumerate() {
        let mtime = m.newest.unwrap_or(0);
        let spotlight = (cx.env.spotlight && i < 300)
            .then(|| sys::last_used(&p, &home))
            .flatten();
        let last_used = match spotlight {
            Some(t) => t.max(mtime),
            None => atime.max(mtime),
        };
        if last_used >= idle_cutoff {
            continue;
        }
        let vm = rules::is_vm_image(&p);
        f.items.push(make_item(
            ItemSpec {
                category: CleanCategory::LargeFiles,
                path: &p,
                name: file_name(&p),
                m,
                safety: CleanSafety::Review,
                bundle_id: None,
                note: Some(if vm {
                    "image de machine virtuelle".to_string()
                } else {
                    format!(
                        "pas ouvert depuis {} jours",
                        days_ago(cx.env.now, last_used)
                    )
                }),
                last_used: Some(last_used),
            },
            &cx.open,
        ));
    }
    f
}

/// Display order of the categories.
pub const ALL_CATEGORIES: [CleanCategory; 8] = [
    CleanCategory::Caches,
    CleanCategory::BrowserCaches,
    CleanCategory::DeveloperCaches,
    CleanCategory::Logs,
    CleanCategory::AppLeftovers,
    CleanCategory::Downloads,
    CleanCategory::LargeFiles,
    CleanCategory::Trash,
];

fn report_of(c: CleanCategory, mut found: Found) -> (CleanCategoryReport, Vec<String>) {
    found
        .items
        .sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    let truncated = found.items.len() > MAX_ITEMS;
    found.items.truncate(MAX_ITEMS);
    let (title, description) = rules::category_text(c);
    let size = found.items.iter().map(|i| i.size).sum();
    let selected_size = found
        .items
        .iter()
        .filter(|i| i.selected)
        .map(|i| i.size)
        .sum();
    (
        CleanCategoryReport {
            category: c,
            title: title.into(),
            description: description.into(),
            safety: rules::category_safety(c),
            size,
            selected_size,
            items: found.items,
            truncated,
            trashable: c != CleanCategory::Trash,
            error: found.error,
        },
        found.warnings,
    )
}

/// Scan the requested categories (all when empty). Nothing is modified.
pub fn scan(env: &CleanEnv, only: &[CleanCategory]) -> CleanScanReport {
    let started = Instant::now();
    let wanted = |c: CleanCategory| only.is_empty() || only.contains(&c);
    let mut cx = Ctx {
        env,
        open: env.resolve_open_files(),
        claimed: HashSet::new(),
        installed: None,
        names: HashMap::new(),
    };
    // Claiming order: specific categories first, generic caches after them.
    let mut results: HashMap<CleanCategory, Found> = HashMap::new();
    if wanted(CleanCategory::Trash) {
        results.insert(CleanCategory::Trash, scan_trash(&mut cx));
    }
    let browsers = scan_browsers(&mut cx);
    if wanted(CleanCategory::BrowserCaches) {
        results.insert(CleanCategory::BrowserCaches, browsers);
    }
    let dev = scan_developer(&mut cx);
    if wanted(CleanCategory::DeveloperCaches) {
        results.insert(CleanCategory::DeveloperCaches, dev);
    }
    if wanted(CleanCategory::AppLeftovers) {
        results.insert(CleanCategory::AppLeftovers, scan_leftovers(&mut cx));
    }
    if wanted(CleanCategory::Caches) {
        results.insert(CleanCategory::Caches, scan_caches(&mut cx));
    }
    if wanted(CleanCategory::Logs) {
        results.insert(CleanCategory::Logs, scan_logs(&mut cx));
    }
    if wanted(CleanCategory::Downloads) {
        results.insert(CleanCategory::Downloads, scan_downloads(&mut cx));
    }
    if wanted(CleanCategory::LargeFiles) {
        results.insert(CleanCategory::LargeFiles, scan_large(&mut cx));
    }
    let mut categories = Vec::new();
    let mut warnings = Vec::new();
    for c in ALL_CATEGORIES {
        if let Some(found) = results.remove(&c) {
            let (r, w) = report_of(c, found);
            warnings.extend(w);
            categories.push(r);
        }
    }
    CleanScanReport {
        generated_at: env.now,
        duration_ms: started.elapsed().as_millis() as u64,
        home: env.home.display().to_string(),
        total_size: categories.iter().map(|c| c.size).sum(),
        reclaimable_size: categories.iter().map(|c| c.selected_size).sum(),
        categories,
        warnings,
    }
}
