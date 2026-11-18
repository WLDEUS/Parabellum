//! Installed applications and the bundle ids they own (main app, helpers, extensions, XPC services,
//! wrapped iOS apps), used to recognise leftovers conservatively.

use super::rules::vendor;
use super::CleanEnv;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Bundle extensions whose Info.plist names an id that may own containers / preferences.
const BUNDLE_EXTS: &[&str] = &["app", "appex", "xpc", "systemextension", "bundle"];
const MAX_ENTRIES_PER_APP: usize = 20_000;
const MAX_APPS: usize = 5_000;

#[derive(Debug, Default, Clone)]
pub struct Installed {
    pub ids: HashSet<String>,
    /// `com.vendor` of every id (lowercase).
    pub vendors: HashSet<String>,
    /// Main bundle id -> application name (file name without `.app`).
    pub names: HashMap<String, String>,
    pub apps: usize,
}

impl Installed {
    pub fn add(&mut self, id: &str) {
        self.vendors.insert(vendor(id));
        self.ids.insert(id.to_string());
    }

    /// Conservative ownership: an installed bundle shares the vendor (`com.google.*` keeps every
    /// `com.google.*` entry while any Google app is installed).
    pub fn owns(&self, id: &str) -> bool {
        self.ids.contains(id) || self.vendors.contains(&vendor(id))
    }
}

fn ext_of(p: &Path) -> Option<&str> {
    p.extension().and_then(|e| e.to_str())
}

/// `CFBundleIdentifier` of a bundle folder (`Contents/Info.plist`, else `Info.plist`).
pub fn bundle_id(bundle: &Path) -> Option<String> {
    for plist_path in [
        bundle.join("Contents/Info.plist"),
        bundle.join("Info.plist"),
    ] {
        let Ok(meta) = std::fs::symlink_metadata(&plist_path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > 4 * 1024 * 1024 {
            continue;
        }
        if let Ok(v) = plist::Value::from_file(&plist_path) {
            if let Some(id) = v
                .as_dictionary()
                .and_then(|d| d.get("CFBundleIdentifier"))
                .and_then(|v| v.as_string())
            {
                return Some(id.to_string());
            }
        }
    }
    None
}

/// Ids of an application and of the bundles it embeds.
pub fn app_ids(app: &Path, out: &mut Installed) {
    if let Some(id) = bundle_id(app) {
        if let Some(stem) = app.file_stem().and_then(|s| s.to_str()) {
            out.names
                .entry(id.clone())
                .or_insert_with(|| stem.to_string());
        }
        out.add(&id);
    }
    let walker = WalkDir::new(app)
        .follow_links(false)
        .min_depth(1)
        .max_depth(8)
        .into_iter()
        .filter_entry(|e| {
            let n = e.file_name().to_str().unwrap_or("");
            !(n.ends_with(".lproj") || n == "_CodeSignature" || n == "Headers" || n == "Resources")
        });
    for e in walker.flatten().take(MAX_ENTRIES_PER_APP) {
        if e.file_type().is_dir() && ext_of(e.path()).is_some_and(|x| BUNDLE_EXTS.contains(&x)) {
            if let Some(id) = bundle_id(e.path()) {
                out.add(&id);
            }
        }
    }
}

/// `.app` bundles up to `depth` levels under `dir` (not inside other apps).
pub fn apps_in(dir: &Path, depth: usize) -> Vec<PathBuf> {
    let mut v = Vec::new();
    let mut it = WalkDir::new(dir)
        .follow_links(false)
        .min_depth(1)
        .max_depth(depth)
        .into_iter();
    while let Some(Ok(e)) = it.next() {
        if e.file_type().is_dir() && ext_of(e.path()) == Some("app") {
            v.push(e.path().to_path_buf());
            it.skip_current_dir();
        }
    }
    v
}

/// Everything installed: application folders, Homebrew Caskroom, and Spotlight's list of apps.
pub fn installed(env: &CleanEnv) -> Installed {
    let mut apps: Vec<PathBuf> = Vec::new();
    for d in &env.app_dirs {
        apps.extend(apps_in(d, 3));
    }
    for d in &env.caskroom_dirs {
        apps.extend(apps_in(d, 4));
    }
    if env.spotlight {
        if let Some(found) = super::sys::spotlight_apps(&env.home) {
            let trash = env.home.join(".Trash");
            apps.extend(found.into_iter().filter(|p| !p.starts_with(&trash)));
        }
    }
    apps.sort();
    apps.dedup();
    let mut out = Installed::default();
    for a in apps.iter().take(MAX_APPS) {
        app_ids(a, &mut out);
    }
    out.apps = apps.len().min(MAX_APPS);
    out
}
