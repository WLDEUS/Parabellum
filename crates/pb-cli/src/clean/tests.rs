//! Scanner / apply tests on synthetic home folders (fictional user, temp dirs).

use super::apply::{unique_in, validate, Rejection, Target};
use super::rules::{self, LeftoverKind};
use super::sys::{parse_mdls_date, OpenFiles};
use super::*;
use filetime::{set_file_mtime, set_file_times, FileTime};
use std::fs;
use std::io::Write;

const DAY: i64 = 86_400;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    env: CleanEnv,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(dir.path()).unwrap();
        let home = root.join("Users/camille");
        fs::create_dir_all(home.join("Library")).unwrap();
        let mut env = CleanEnv::for_home(home);
        env.now = 1_793_000_000;
        env.min_installed_vendors = 1;
        env.large_min = 64 * 1024;
        env.open_files = Some(OpenFiles::default());
        Fixture {
            _dir: dir,
            root,
            env,
        }
    }

    fn home(&self) -> &Path {
        &self.env.home
    }

    fn lib(&self, rel: &str) -> PathBuf {
        self.env.home.join("Library").join(rel)
    }

    /// File with `len` bytes of data (allocated), modified `age_days` ago.
    fn file(&self, p: &Path, len: usize, age_days: i64) -> PathBuf {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = fs::File::create(p).unwrap();
        f.write_all(&vec![7u8; len]).unwrap();
        drop(f);
        let t = FileTime::from_unix_time(self.env.now - age_days * DAY, 0);
        set_file_times(p, t, t).unwrap();
        p.to_path_buf()
    }

    fn app(&self, name: &str, id: &str, nested: &[(&str, &str)]) {
        let apps = self.root.join("Applications");
        let app = apps.join(format!("{name}.app"));
        write_plist(&app.join("Contents/Info.plist"), id);
        for (rel, nid) in nested {
            write_plist(
                &app.join("Contents").join(rel).join("Contents/Info.plist"),
                nid,
            );
        }
    }

    fn with_apps(mut self) -> Self {
        self.env.app_dirs = vec![self.root.join("Applications")];
        self
    }
}

fn write_plist(p: &Path, id: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    let mut d = plist::Dictionary::new();
    d.insert("CFBundleIdentifier".into(), plist::Value::String(id.into()));
    plist::Value::Dictionary(d).to_file_xml(p).unwrap();
}

fn agent_plist(p: &Path, program: &str) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    let mut d = plist::Dictionary::new();
    d.insert("Label".into(), plist::Value::String("x".into()));
    d.insert(
        "ProgramArguments".into(),
        plist::Value::Array(vec![plist::Value::String(program.into())]),
    );
    plist::Value::Dictionary(d).to_file_xml(p).unwrap();
}

fn category(r: &CleanScanReport, c: CleanCategory) -> &CleanCategoryReport {
    r.categories.iter().find(|x| x.category == c).unwrap()
}

fn paths(c: &CleanCategoryReport) -> Vec<String> {
    let mut v: Vec<String> = c.items.iter().map(|i| i.path.clone()).collect();
    v.sort();
    v
}

fn plan(items: &[(CleanCategory, &Path)]) -> CleanPlan {
    CleanPlan {
        items: items
            .iter()
            .map(|(c, p)| CleanPlanItem {
                category: *c,
                path: p.display().to_string(),
            })
            .collect(),
        permanent: vec![],
    }
}

#[test]
fn caches_skip_apple_and_claimed_entries() {
    let fx = Fixture::new();
    let spotify = fx.file(&fx.lib("Caches/com.spotify.client/data.bin"), 8192, 1);
    fx.file(&fx.lib("Caches/com.apple.Music/x"), 8192, 1);
    fx.file(&fx.lib("Caches/CloudKit/x"), 8192, 1);
    fx.file(&fx.lib("Caches/Google/Chrome/Default/Cache/f"), 8192, 1);
    fx.file(&fx.lib("Caches/Homebrew/downloads/x.tar.gz"), 8192, 1);
    fx.file(&fx.lib("Caches/com.parabellum.app/x"), 8192, 1);
    fx.file(&fx.lib("Caches/.hidden"), 8192, 1);
    fx.file(&fx.lib("Caches/com.apple.Safari/Cache.db"), 8192, 1);
    let r = scan(&fx.env, &[]);
    let caches = category(&r, CleanCategory::Caches);
    assert_eq!(
        paths(caches),
        vec![spotify.parent().unwrap().display().to_string()]
    );
    assert!(caches.items[0].selected);
    assert_eq!(
        caches.items[0].bundle_id.as_deref(),
        Some("com.spotify.client")
    );
    let browsers = paths(category(&r, CleanCategory::BrowserCaches));
    assert!(browsers.iter().any(|p| p.ends_with("Caches/Google/Chrome")));
    assert!(browsers
        .iter()
        .any(|p| p.ends_with("Caches/com.apple.Safari")));
    let dev = paths(category(&r, CleanCategory::DeveloperCaches));
    assert!(dev.iter().any(|p| p.ends_with("Caches/Homebrew")));
    assert_eq!(
        r.reclaimable_size,
        r.categories.iter().map(|c| c.selected_size).sum::<u64>()
    );
    // Only what was asked
    let r = scan(&fx.env, &[CleanCategory::Logs]);
    assert_eq!(r.categories.len(), 1);
}

#[test]
fn browser_profiles_and_cookies() {
    let fx = Fixture::new();
    let data = fx.lib("Application Support/Google/Chrome");
    fx.file(&data.join("Default/GPUCache/data_0"), 8192, 1);
    fx.file(&data.join("Profile 1/GPUCache/data_0"), 8192, 1);
    fx.file(&data.join("ShaderCache/x"), 8192, 1);
    fx.file(&data.join("Default/Cookies"), 8192, 1);
    fx.file(&data.join("Default/History"), 8192, 1);
    let r = scan(&fx.env, &[CleanCategory::BrowserCaches]);
    let got = paths(category(&r, CleanCategory::BrowserCaches));
    assert_eq!(got.len(), 3, "{got:?}");
    assert!(got
        .iter()
        .all(|p| !p.contains("Cookies") && !p.contains("History")));
    let home = fx.home();
    assert!(rules::is_browser_cache(
        home,
        &data.join("Default/GPUCache")
    ));
    assert!(rules::is_browser_cache(home, &data.join("ShaderCache")));
    assert!(!rules::is_browser_cache(home, &data.join("Default")));
    assert!(!rules::is_browser_cache(
        home,
        &data.join("Default/Cookies")
    ));
    assert!(!rules::is_browser_cache(
        home,
        &data.join("Default/Extensions/GPUCache")
    ));
}

#[test]
fn developer_caches_never_touch_projects() {
    let fx = Fixture::new();
    let dd = fx.lib("Developer/Xcode/DerivedData");
    fx.file(
        &dd.join("MyApp-abcdefghijklmnopqrstuvwxyz/Build/x"),
        8192,
        1,
    );
    fx.file(
        &fx.lib("Developer/Xcode/Archives/2026-01-02/a.xcarchive/x"),
        8192,
        1,
    );
    fx.file(
        &fx.home().join(".cargo/registry/cache/index/x.crate"),
        8192,
        1,
    );
    fx.file(&fx.home().join("code/proj/target/debug/big"), 8192, 1);
    fx.file(&fx.home().join(".npm/_cacache/x"), 8192, 1);
    let r = scan(&fx.env, &[CleanCategory::DeveloperCaches]);
    let c = category(&r, CleanCategory::DeveloperCaches);
    let names: Vec<&str> = c.items.iter().map(|i| i.name.as_str()).collect();
    assert!(names.contains(&"Xcode — DerivedData — MyApp"), "{names:?}");
    assert!(c.items.iter().all(|i| !i.path.contains("/target/")));
    let archive = c
        .items
        .iter()
        .find(|i| i.path.contains("Archives"))
        .unwrap();
    assert_eq!(archive.safety, CleanSafety::Review);
    assert!(!archive.selected);
    let mut inst = None;
    let proj = fx.home().join("code/proj/target");
    assert!(matches!(
        validate(&fx.env, CleanCategory::DeveloperCaches, &proj, &mut inst),
        Err(Rejection::Refused(_))
    ));
    assert_eq!(
        validate(
            &fx.env,
            CleanCategory::DeveloperCaches,
            &dd.join("MyApp-abcdefghijklmnopqrstuvwxyz"),
            &mut inst
        ),
        Ok(Target::Whole)
    );
    // DerivedData itself is not an item (only its children).
    assert!(validate(&fx.env, CleanCategory::DeveloperCaches, &dd, &mut inst).is_err());
}

#[test]
fn logs_only_old_files() {
    let fx = Fixture::new();
    let old = fx.file(&fx.lib("Logs/Foo/old.log"), 8192, 45);
    let recent = fx.file(&fx.lib("Logs/Foo/new.log"), 8192, 2);
    let crash = fx.file(&fx.lib("Logs/DiagnosticReports/App.ips"), 4096, 40);
    fx.file(&fx.lib("Logs/Bar/new.log"), 4096, 1);
    let r = scan(&fx.env, &[CleanCategory::Logs]);
    let c = category(&r, CleanCategory::Logs);
    assert_eq!(c.items.len(), 2, "{:?}", paths(c));
    let foo = c
        .items
        .iter()
        .find(|i| i.path.ends_with("Logs/Foo"))
        .unwrap();
    assert_eq!(foo.files, 1);
    assert!(c.items.iter().any(|i| i.name == "Rapports de plantage"));
    // Apply: old files go to one Trash folder, the recent one stays.
    let foo_dir = fx.lib("Logs/Foo");
    let rep = apply(
        &fx.env,
        &plan(&[
            (CleanCategory::Logs, &foo_dir),
            (CleanCategory::Logs, crash.parent().unwrap()),
        ]),
        false,
    );
    assert_eq!((rep.cleaned, rep.failed), (2, 0), "{:?}", rep.results);
    assert!(!old.exists() && recent.exists() && !crash.exists());
    let moved = PathBuf::from(rep.results[0].trashed_as.clone().unwrap());
    assert!(moved.starts_with(fx.home().join(".Trash")));
    assert!(moved.join("old.log").is_file());
    assert!(rep.trashed_bytes > 0);
    // Nothing old left: skipped.
    let again = apply(&fx.env, &plan(&[(CleanCategory::Logs, &foo_dir)]), false);
    assert_eq!(again.skipped, 1);
}

fn zip_with(p: &Path, names: &[&str]) {
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    let f = fs::File::create(p).unwrap();
    let mut z = zip::ZipWriter::new(f);
    for n in names {
        if n.ends_with('/') {
            z.add_directory(
                n.trim_end_matches('/'),
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        } else {
            z.start_file(*n, zip::write::SimpleFileOptions::default())
                .unwrap();
            z.write_all(b"x").unwrap();
        }
    }
    z.finish().unwrap();
}

#[test]
fn downloads_old_installers_only() {
    let fx = Fixture::new();
    let dl = fx.home().join("Downloads");
    let dmg = fx.file(&dl.join("Tool-1.2.dmg"), 8192, 60);
    fx.file(&dl.join("Recent.dmg"), 8192, 3);
    fx.file(&dl.join("photo.jpg"), 8192, 90);
    fx.file(&dl.join("sub/Setup.pkg"), 8192, 40);
    fx.file(&dl.join("sub/deeper/Old.pkg"), 8192, 40);
    let appzip = dl.join("App.zip");
    zip_with(&appzip, &["App.app/", "App.app/Contents/Info.plist"]);
    set_file_mtime(&appzip, FileTime::from_unix_time(fx.env.now - 50 * DAY, 0)).unwrap();
    let docs = dl.join("docs.zip");
    zip_with(&docs, &["report.pdf"]);
    set_file_mtime(&docs, FileTime::from_unix_time(fx.env.now - 50 * DAY, 0)).unwrap();
    let r = scan(&fx.env, &[CleanCategory::Downloads]);
    let c = category(&r, CleanCategory::Downloads);
    let mut got: Vec<String> = paths(c)
        .into_iter()
        .map(|p| p.rsplit('/').next().unwrap().to_string())
        .collect();
    got.sort();
    assert_eq!(got, ["App.zip", "Setup.pkg", "Tool-1.2.dmg"]);
    assert!(c
        .items
        .iter()
        .all(|i| !i.selected && i.safety == CleanSafety::Review));
    assert_eq!(c.selected_size, 0);
    let mut inst = None;
    let recent = dl.join("Recent.dmg");
    assert!(matches!(
        validate(&fx.env, CleanCategory::Downloads, &recent, &mut inst),
        Err(Rejection::Skipped(_))
    ));
    assert!(matches!(
        validate(&fx.env, CleanCategory::Downloads, &docs, &mut inst),
        Err(Rejection::Refused(_))
    ));
    assert_eq!(
        validate(&fx.env, CleanCategory::Downloads, &dmg, &mut inst),
        Ok(Target::Whole)
    );
}

#[test]
fn large_old_files_outside_library() {
    let fx = Fixture::new();
    let big_old = fx.file(&fx.home().join("Documents/backup.iso"), 128 * 1024, 400);
    fx.file(&fx.home().join("Documents/recent.mov"), 128 * 1024, 10);
    fx.file(&fx.home().join("Documents/small.txt"), 1024, 400);
    fx.file(&fx.home().join("Library/Big/blob"), 128 * 1024, 400);
    fx.file(&fx.home().join("Music/song-pack.zip"), 128 * 1024, 400);
    fx.file(&fx.home().join(".ollama/models/m.bin"), 128 * 1024, 400);
    fx.file(
        &fx.home()
            .join("Pictures/Photos Library.photoslibrary/originals/x"),
        128 * 1024,
        400,
    );
    let vm = fx.home().join("VMs/Linux.utm");
    fx.file(&vm.join("Data/disk.qcow2"), 128 * 1024, 300);
    let r = scan(&fx.env, &[CleanCategory::LargeFiles]);
    let c = category(&r, CleanCategory::LargeFiles);
    assert_eq!(
        paths(c),
        vec![big_old.display().to_string(), vm.display().to_string()]
    );
    assert!(c.items.iter().all(|i| !i.selected));
    let vm_item = c.items.iter().find(|i| i.path.ends_with(".utm")).unwrap();
    assert_eq!(vm_item.note.as_deref(), Some("image de machine virtuelle"));
    let mut inst = None;
    let lib_blob = fx.home().join("Library/Big/blob");
    assert!(validate(&fx.env, CleanCategory::LargeFiles, &lib_blob, &mut inst).is_err());
    let music = fx.home().join("Music/song-pack.zip");
    assert!(validate(&fx.env, CleanCategory::LargeFiles, &music, &mut inst).is_err());
    let small = fx.home().join("Documents/small.txt");
    assert!(validate(&fx.env, CleanCategory::LargeFiles, &small, &mut inst).is_err());
    assert_eq!(
        validate(&fx.env, CleanCategory::LargeFiles, &big_old, &mut inst),
        Ok(Target::Whole)
    );
}

#[test]
fn leftovers_conservative_matching() {
    let fx = Fixture::new().with_apps();
    fx.app(
        "Foo",
        "com.foo.app",
        &[("PlugIns/Share.appex", "com.foo.app.share")],
    );
    fx.app("Chrome", "com.google.Chrome", &[]);
    let gone_container = fx.lib("Containers/com.gone.app");
    fx.file(&gone_container.join("Data/x"), 8192, 10);
    fx.file(&fx.lib("Containers/com.foo.app.share/Data/x"), 8192, 10);
    let gone_pref = fx.file(&fx.lib("Preferences/com.gone.app.plist"), 4096, 10);
    let gone_cache = fx.lib("Caches/com.gone.app");
    fx.file(&gone_cache.join("x"), 8192, 10);
    fx.file(&fx.lib("Application Support/com.apple.foo/x"), 8192, 10);
    fx.file(&fx.lib("Application Support/Google/x"), 8192, 10);
    // Same vendor as an installed app: kept (Google updater while Chrome is installed).
    fx.file(
        &fx.lib("Application Support/com.google.Keystone/x"),
        8192,
        10,
    );
    let gone_group = fx.lib("Group Containers/ABCDE12345.com.gone.shared");
    fx.file(&gone_group.join("x"), 8192, 10);
    fx.file(&fx.lib("Group Containers/group.com.foo.shared/x"), 8192, 10);
    fx.file(
        &fx.lib("Group Containers/group.com.apple.notes/x"),
        8192,
        10,
    );
    let orphan_agent = fx.lib("LaunchAgents/com.gone.agent.plist");
    agent_plist(&orphan_agent, "/nonexistent/gone-helper");
    let live_prog = fx.file(&fx.root.join("bin/helper"), 16, 1);
    agent_plist(
        &fx.lib("LaunchAgents/com.other.agent.plist"),
        live_prog.to_str().unwrap(),
    );
    let r = scan(&fx.env, &[]);
    let c = category(&r, CleanCategory::AppLeftovers);
    assert_eq!(c.error, None);
    let mut expected = vec![
        gone_container.display().to_string(),
        gone_pref.display().to_string(),
        gone_cache.display().to_string(),
        gone_group.display().to_string(),
        orphan_agent.display().to_string(),
    ];
    expected.sort();
    assert_eq!(paths(c), expected);
    let cache_item = c
        .items
        .iter()
        .find(|i| i.path.ends_with("Caches/com.gone.app"))
        .unwrap();
    assert!(cache_item.selected);
    let pref_item = c
        .items
        .iter()
        .find(|i| i.path.ends_with(".plist") && i.path.contains("Preferences"))
        .unwrap();
    assert!(!pref_item.selected);
    // Claimed by leftovers: not repeated in Caches.
    assert!(paths(category(&r, CleanCategory::Caches)).is_empty());
    // Re-validation refuses an installed app's data.
    let mut inst = None;
    let owned = fx.lib("Containers/com.foo.app.share");
    assert!(matches!(
        validate(&fx.env, CleanCategory::AppLeftovers, &owned, &mut inst),
        Err(Rejection::Refused(_))
    ));
    assert_eq!(
        validate(
            &fx.env,
            CleanCategory::AppLeftovers,
            &gone_container,
            &mut inst
        ),
        Ok(Target::Whole)
    );
    // No application found at all: refuse to guess.
    let mut env = fx.env.clone();
    env.app_dirs.clear();
    env.min_installed_vendors = 3;
    let r = scan(&env, &[CleanCategory::AppLeftovers]);
    let c = category(&r, CleanCategory::AppLeftovers);
    assert!(c.items.is_empty() && c.error.is_some());
}

#[test]
fn bundle_id_rules() {
    assert_eq!(
        rules::leftover_id(LeftoverKind::Group, "ABCDE12345.group.com.foo.bar").as_deref(),
        Some("com.foo.bar")
    );
    assert_eq!(
        rules::leftover_id(LeftoverKind::Group, "group.com.foo.bar").as_deref(),
        Some("com.foo.bar")
    );
    assert_eq!(
        rules::leftover_id(LeftoverKind::PlistFile, "com.foo.bar.plist").as_deref(),
        Some("com.foo.bar")
    );
    assert_eq!(
        rules::leftover_id(LeftoverKind::PlistFile, "com.foo.bar"),
        None
    );
    assert_eq!(
        rules::leftover_id(LeftoverKind::SavedState, "com.foo.bar.savedState").as_deref(),
        Some("com.foo.bar")
    );
    assert_eq!(
        rules::leftover_id(LeftoverKind::Http, "com.foo.bar.binarycookies").as_deref(),
        Some("com.foo.bar")
    );
    assert_eq!(rules::leftover_id(LeftoverKind::Plain, "Google"), None);
    assert_eq!(rules::leftover_id(LeftoverKind::Plain, "com.foo"), None);
    assert_eq!(
        rules::leftover_id(LeftoverKind::Plain, "Foo Bar.baz.qux"),
        None
    );
    assert!(rules::protected_id("com.apple.Safari"));
    assert!(rules::protected_id("com.wldeus.parabellum"));
    assert!(!rules::protected_id("com.spotify.client"));
    assert_eq!(rules::vendor("com.Google.Chrome"), "com.google");
    assert_eq!(
        derived_data_name("MyApp-abcdefghijklmnopqrstuvwxyz"),
        "MyApp"
    );
    assert_eq!(derived_data_name("My-App"), "My-App");
    let mut inst = apps::Installed::default();
    inst.add("com.google.Chrome");
    assert!(inst.owns("com.google.Keystone.Agent"));
    assert!(!inst.owns("com.googleplus.x"));
}

#[test]
fn deny_list() {
    let home = Path::new("/Users/camille");
    for p in [
        "Library/Keychains/login.keychain-db",
        "Library/Mail/V10",
        "Library/Mobile Documents/com~apple~CloudDocs",
        "Library/Application Support/MobileSync/Backup",
        "Library/Group Containers/group.com.apple.notes",
        "Library/Caches/com.apple.Music",
        ".ssh/id_ed25519",
        "Pictures/Photos Library.photoslibrary",
        "Library",
        "",
    ] {
        assert!(rules::denied(home, &home.join(p)).is_some(), "{p}");
    }
    for p in [
        "Library/Caches/com.apple.Safari",
        "Library/Containers/com.apple.Safari/Data/Library/Caches",
        "Library/Caches/com.spotify.client",
        "Downloads/x.dmg",
    ] {
        assert!(rules::denied(home, &home.join(p)).is_none(), "{p}");
    }
    assert!(!rules::is_clean_path(Path::new("/Users/camille/../x")));
    assert!(!rules::is_clean_path(Path::new("relative/x")));
    assert!(rules::is_clean_path(Path::new("/Users/camille/x")));
}

#[test]
fn apply_moves_to_trash_with_unique_names() {
    let fx = Fixture::new();
    let cache = fx.lib("Caches/com.spotify.client");
    fx.file(&cache.join("a"), 8192, 1);
    fx.file(&fx.home().join(".Trash/com.spotify.client/old"), 10, 1);
    let rep = apply(&fx.env, &plan(&[(CleanCategory::Caches, &cache)]), false);
    assert_eq!(rep.cleaned, 1, "{:?}", rep.results);
    assert_eq!(rep.results[0].outcome, CleanOutcome::MovedToTrash);
    let dest = rep.results[0].trashed_as.clone().unwrap();
    assert!(dest.ends_with(".Trash/com.spotify.client 2"), "{dest}");
    assert!(!cache.exists() && Path::new(&dest).join("a").is_file());
    assert!(rep.trashed_bytes >= 8192 && rep.freed_bytes == 0);
    assert_eq!(
        unique_in(&fx.home().join(".Trash"), "com.spotify.client"),
        fx.home().join(".Trash/com.spotify.client 3")
    );
    fs::write(fx.root.join("f.tar.gz"), b"x").unwrap();
    assert_eq!(unique_in(&fx.root, "f.tar.gz"), fx.root.join("f.tar 2.gz"));
}

#[test]
fn apply_permanent_and_dry_run() {
    let fx = Fixture::new();
    let a = fx.lib("Caches/com.a.app");
    let b = fx.lib("Caches/com.b.app");
    fx.file(&a.join("x"), 8192, 1);
    fx.file(&b.join("x"), 8192, 1);
    let dry = apply(&fx.env, &plan(&[(CleanCategory::Caches, &a)]), true);
    assert!(dry.dry_run && a.exists());
    assert_eq!(dry.results[0].outcome, CleanOutcome::WouldClean);
    assert!(dry.results[0].bytes >= 8192);
    let mut p = plan(&[(CleanCategory::Caches, &a), (CleanCategory::Caches, &b)]);
    p.permanent = vec![CleanCategory::Caches];
    let rep = apply(&fx.env, &p, false);
    assert_eq!(rep.cleaned, 2);
    assert!(!a.exists() && !b.exists());
    assert!(!fx.home().join(".Trash").exists());
    assert!(rep.freed_bytes >= 16384);
}

#[test]
fn apply_refusals() {
    let fx = Fixture::new();
    let outside = fx.root.join("elsewhere");
    fx.file(&outside.join("precious"), 100, 1);
    let docs = fx.file(&fx.home().join("Documents/thesis.pdf"), 100, 1);
    let keychain = fx.file(&fx.lib("Keychains/login.keychain-db"), 100, 1);
    // Symlinked ancestor: Caches/linked -> outside
    fs::create_dir_all(fx.lib("Caches")).unwrap();
    std::os::unix::fs::symlink(&outside, fx.lib("Caches/linked")).unwrap();
    let through_link = fx.lib("Caches/linked/precious");
    let cases: Vec<(CleanCategory, PathBuf)> = vec![
        (CleanCategory::Caches, outside.join("precious")),
        (CleanCategory::Caches, docs.clone()),
        (CleanCategory::LargeFiles, keychain.clone()),
        (CleanCategory::Caches, through_link.clone()),
        (
            CleanCategory::Caches,
            PathBuf::from(format!(
                "{}/Library/Caches/../../Documents",
                fx.home().display()
            )),
        ),
        (CleanCategory::Trash, fx.home().join("Documents")),
        (CleanCategory::Caches, fx.lib("Caches")),
        (CleanCategory::Caches, fx.home().to_path_buf()),
    ];
    let p = CleanPlan {
        items: cases
            .iter()
            .map(|(c, p)| CleanPlanItem {
                category: *c,
                path: p.display().to_string(),
            })
            .collect(),
        permanent: vec![CleanCategory::Caches, CleanCategory::LargeFiles],
    };
    let rep = apply(&fx.env, &p, false);
    assert_eq!(rep.cleaned, 0, "{:?}", rep.results);
    assert!(
        rep.results
            .iter()
            .all(|r| r.outcome == CleanOutcome::Refused),
        "{:?}",
        rep.results
    );
    assert!(outside.join("precious").is_file() && docs.is_file() && keychain.is_file());
    // A symlink item is moved as a link: its target survives.
    let link_item = fx.lib("Caches/com.link.app");
    std::os::unix::fs::symlink(&outside, &link_item).unwrap();
    let mut p = plan(&[(CleanCategory::Caches, &link_item)]);
    p.permanent = vec![CleanCategory::Caches];
    let rep = apply(&fx.env, &p, false);
    assert_eq!(rep.cleaned, 1, "{:?}", rep.results);
    assert!(fs::symlink_metadata(&link_item).is_err());
    assert!(outside.join("precious").is_file());
    // Vanished path: skipped, not failed.
    let rep = apply(
        &fx.env,
        &plan(&[(CleanCategory::Caches, &fx.lib("Caches/gone"))]),
        false,
    );
    assert_eq!((rep.skipped, rep.failed), (1, 0));
}

#[test]
fn in_use_items_are_skipped() {
    let mut fx = Fixture::new();
    let chrome_cache = fx.lib("Caches/com.busy.app");
    let open = fx.file(&chrome_cache.join("index"), 8192, 1);
    fx.env.open_files = Some(OpenFiles::from_paths([open.display().to_string()]));
    let r = scan(&fx.env, &[CleanCategory::Caches]);
    let item = &category(&r, CleanCategory::Caches).items[0];
    assert!(item.in_use && !item.selected);
    let rep = apply(
        &fx.env,
        &plan(&[(CleanCategory::Caches, &chrome_cache)]),
        false,
    );
    assert_eq!(rep.skipped, 1);
    assert!(chrome_cache.exists());
}

#[test]
fn trash_is_emptied_not_removed() {
    let fx = Fixture::new();
    let trash = fx.home().join(".Trash");
    fx.file(&trash.join("old.dmg"), 8192, 5);
    fx.file(&trash.join("folder/x"), 8192, 5);
    let r = scan(&fx.env, &[CleanCategory::Trash]);
    let c = category(&r, CleanCategory::Trash);
    assert_eq!(c.items.len(), 1);
    assert!(!c.trashable && c.items[0].selected);
    let rep = apply(&fx.env, &plan(&[(CleanCategory::Trash, &trash)]), false);
    assert_eq!(rep.results[0].outcome, CleanOutcome::Deleted);
    assert!(rep.freed_bytes >= 16384);
    assert!(trash.is_dir() && fs::read_dir(&trash).unwrap().next().is_none());
    // Trash first, then moves into it: a cache trashed in the same plan survives the emptying.
    fx.file(&trash.join("older"), 10, 5);
    let cache = fx.lib("Caches/com.spotify.client");
    fx.file(&cache.join("a"), 8192, 1);
    let rep = apply(
        &fx.env,
        &plan(&[
            (CleanCategory::Caches, &cache),
            (CleanCategory::Trash, &trash),
        ]),
        false,
    );
    assert_eq!(rep.cleaned, 2, "{:?}", rep.results);
    assert!(trash.join("com.spotify.client/a").is_file());
    assert!(!trash.join("older").exists());
}

#[test]
fn tool_output_parsers() {
    let lsof = "p123\nfcwd\nn/Users/camille\nftxt\nn/Applications/Foo.app/Contents/MacOS/Foo\nf12\nn/Users/camille/Library/Caches/com.foo.app/Cache.db\nf13\nn127.0.0.1:443->1.2.3.4:5\np456\nf3\nn/dev/null\n";
    let o = OpenFiles::parse_lsof(lsof);
    assert!(o.touches(Path::new("/Users/camille/Library/Caches/com.foo.app")));
    assert!(!o.touches(Path::new("/Users/camille/Library/Caches/com.foo")));
    assert!(!o.touches(Path::new("/Users/camille/Library/Caches/com.bar.app")));
    // Home itself is open (cwd): every path under it would match, so only exact children count.
    assert!(o.touches(Path::new("/Users/camille")));
    assert!(OpenFiles::parse_lsof("").is_empty());
    assert_eq!(
        parse_mdls_date("2026-03-01 10:22:11 +0000\n"),
        Some(1_772_360_531)
    );
    assert_eq!(parse_mdls_date("(null)"), None);
    assert_eq!(parse_mdls_date(""), None);
    assert_eq!(
        sys::parse_path_lines("/Applications/A.app\nnot a path\n/System/Applications/B.app\n"),
        vec![
            PathBuf::from("/Applications/A.app"),
            PathBuf::from("/System/Applications/B.app")
        ]
    );
    assert_eq!(command::human_size(0), "0 octets");
    assert_eq!(command::human_size(1_234_000), "1,2 Mo");
    assert_eq!(command::human_size(4_350_000_000), "4,3 Go");
}

#[test]
fn plan_from_selection_and_wire_format() {
    let fx = Fixture::new();
    fx.file(&fx.lib("Caches/com.a.app/x"), 8192, 1);
    fx.file(&fx.home().join("Downloads/Old.dmg"), 8192, 60);
    let r = scan(&fx.env, &[CleanCategory::Caches, CleanCategory::Downloads]);
    let p = command::plan_of_selected(&r, true);
    assert_eq!(p.items.len(), 1);
    assert_eq!(p.items[0].category, CleanCategory::Caches);
    assert_eq!(
        p.permanent,
        vec![CleanCategory::Caches, CleanCategory::Downloads]
    );
    let json = serde_json::to_value(&p).unwrap();
    assert_eq!(json["items"][0]["category"], "caches");
    let back: CleanPlan =
        serde_json::from_str(r#"{"items":[{"category":"browser_caches","path":"/x"}]}"#).unwrap();
    assert!(back.permanent.is_empty());
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(v["categories"][0]["category"], "caches");
    assert!(v["categories"][0]["items"][0]["id"].as_str().unwrap().len() == 16);
    assert_eq!(
        item_id(CleanCategory::Caches, Path::new("/a")),
        item_id(CleanCategory::Caches, Path::new("/a"))
    );
    assert_ne!(
        item_id(CleanCategory::Caches, Path::new("/a")),
        item_id(CleanCategory::Logs, Path::new("/a"))
    );
    assert_eq!(command::all_categories().len(), 8);
}
