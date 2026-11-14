//! Vault state logic against a fake hdiutil / lsof / fdesetup.

use super::command::{run_with, Passwords, VaultArgs, VaultCmd};
use super::tools::{Runner, ToolOutput};
use super::*;
use crate::commands::Output;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone)]
struct Call {
    program: String,
    args: Vec<String>,
    stdin: Option<Vec<u8>>,
}

/// Scripted runner. Responses are queued per "<tool> <first arg>" key; `hdiutil info` answers with
/// the current `attached` state; `hdiutil create` makes a fake bundle like the real tool.
#[derive(Default)]
struct Fake {
    calls: RefCell<Vec<Call>>,
    queued: RefCell<HashMap<String, VecDeque<ToolOutput>>>,
    /// (bundle, mount point) reported by `hdiutil info`.
    attached: RefCell<Option<(String, String)>>,
}

fn ok(stdout: &str) -> ToolOutput {
    ToolOutput {
        status: 0,
        stdout: stdout.as_bytes().to_vec(),
        ..Default::default()
    }
}

fn fail(status: i32, stderr: &str) -> ToolOutput {
    ToolOutput {
        status,
        stderr: stderr.as_bytes().to_vec(),
        ..Default::default()
    }
}

fn info_xml(attached: Option<&(String, String)>) -> String {
    let images = match attached {
        None => String::new(),
        Some((bundle, mount)) => format!(
            r#"<dict>
  <key>image-encrypted</key><true/>
  <key>image-path</key><string>{bundle}</string>
  <key>image-type</key><string>sparse bundle disk image</string>
  <key>system-entities</key>
  <array>
    <dict><key>content-hint</key><string>GUID_partition_scheme</string><key>dev-entry</key><string>/dev/disk4</string></dict>
    <dict><key>content-hint</key><string>Apple_APFS</string><key>dev-entry</key><string>/dev/disk4s1</string></dict>
    <dict><key>dev-entry</key><string>/dev/disk5s1</string><key>mount-point</key><string>{mount}</string><key>volume-kind</key><string>apfs</string></dict>
    <dict><key>dev-entry</key><string>/dev/disk5</string></dict>
  </array>
</dict>"#
        ),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>framework</key><string>671</string><key>images</key><array>{images}</array></dict></plist>"#
    )
}

fn attach_xml(mount: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>system-entities</key><array>
<dict><key>dev-entry</key><string>/dev/disk4</string><key>content-hint</key><string>GUID_partition_scheme</string></dict>
<dict><key>dev-entry</key><string>/dev/disk5s1</string><key>mount-point</key><string>{mount}</string></dict>
</array></dict></plist>"#
    )
}

const BUNDLE_INFO: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>band-size</key><integer>8388608</integer>
<key>diskimage-bundle-type</key><string>com.apple.diskimage.sparsebundle</string>
<key>size</key><integer>21474836480</integer></dict></plist>"#;

fn make_bundle(path: &Path) {
    std::fs::create_dir_all(path.join("bands")).unwrap();
    std::fs::write(path.join("Info.plist"), BUNDLE_INFO).unwrap();
    std::fs::write(path.join("Info.bckup"), BUNDLE_INFO).unwrap();
    std::fs::write(path.join("token"), vec![1u8; 4096]).unwrap();
    std::fs::write(path.join("bands/0"), vec![7u8; 100_000]).unwrap();
}

impl Fake {
    fn queue(&self, key: &str, out: ToolOutput) {
        self.queued
            .borrow_mut()
            .entry(key.to_string())
            .or_default()
            .push_back(out);
    }

    fn set_attached(&self, bundle: &Path, mount: &Path) {
        *self.attached.borrow_mut() = Some((
            bundle.to_string_lossy().into_owned(),
            mount.to_string_lossy().into_owned(),
        ));
    }

    fn calls_to(&self, sub: &str) -> Vec<Call> {
        self.calls
            .borrow()
            .iter()
            .filter(|c| c.args.first().map(String::as_str) == Some(sub))
            .cloned()
            .collect()
    }
}

impl Runner for Fake {
    fn run(
        &self,
        program: &str,
        args: &[String],
        stdin: Option<&[u8]>,
        _timeout: std::time::Duration,
    ) -> std::io::Result<ToolOutput> {
        assert!(program.starts_with('/'), "absolute tool path: {program}");
        self.calls.borrow_mut().push(Call {
            program: program.to_string(),
            args: args.to_vec(),
            stdin: stdin.map(<[u8]>::to_vec),
        });
        let tool = program.rsplit('/').next().unwrap_or(program);
        let key = format!("{tool} {}", args.first().map(String::as_str).unwrap_or(""));
        if let Some(out) = self
            .queued
            .borrow_mut()
            .get_mut(&key)
            .and_then(VecDeque::pop_front)
        {
            if key == "hdiutil create" && out.ok() {
                make_bundle(Path::new(args.last().unwrap()));
            }
            if key == "hdiutil detach" && out.ok() {
                *self.attached.borrow_mut() = None;
            }
            return Ok(out);
        }
        Ok(match key.as_str() {
            "hdiutil info" => ok(&info_xml(self.attached.borrow().as_ref())),
            "fdesetup status" => ok("FileVault is On.\n"),
            _ => fail(1, "unexpected call"),
        })
    }
}

struct Env {
    _dir: tempfile::TempDir,
    home: PathBuf,
    paths: VaultPaths,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().canonicalize().unwrap().join("camille");
    std::fs::create_dir_all(&home).unwrap();
    let paths = VaultPaths {
        bundle: VaultPaths::default_bundle(&home),
        mountpoint: None,
    };
    Env {
        _dir: dir,
        home,
        paths,
    }
}

fn pw(s: &str) -> Secret {
    Secret::new(s.as_bytes().to_vec())
}

const GOOD: &str = "correct-horse-battery-staple";

#[test]
fn status_without_vault() {
    let e = env();
    let f = Fake::default();
    let s = status(&f, &e.paths, &e.home, 5).unwrap();
    assert!(!s.exists && !s.mounted && !s.encrypted);
    assert_eq!(s.filevault, FileVaultState::On);
    assert!(s
        .bundle_path
        .ends_with("Parabellum/Vault/Coffre.sparsebundle"));
    // No bundle: hdiutil is not even asked.
    assert!(f.calls_to("info").is_empty());
}

#[test]
fn create_passes_password_on_stdin_only() {
    let e = env();
    let f = Fake::default();
    f.queue(
        "hdiutil create",
        ok("<plist version=\"1.0\"><array><string>x</string></array></plist>"),
    );
    let s = create(&f, &e.paths, &e.home, 20 << 30, "Coffre", &pw(GOOD)).unwrap();
    assert!(s.exists && s.encrypted && !s.mounted);
    assert_eq!(s.capacity_bytes, Some(20 << 30));
    assert!(s.allocated_bytes.unwrap() >= 100_000);
    let c = &f.calls_to("create")[0];
    assert_eq!(c.program, "/usr/bin/hdiutil");
    let a = c.args.join(" ");
    for want in [
        "-size 20480m",
        "-type SPARSEBUNDLE",
        "-fs APFS",
        "-volname Coffre",
        "-encryption AES-256",
        "-stdinpass",
        "-mode 0700",
        "-plist",
    ] {
        assert!(a.contains(want), "{want} missing in {a}");
    }
    assert_eq!(c.args.last().unwrap(), &e.paths.bundle.to_string_lossy());
    assert!(!a.contains(GOOD));
    assert_eq!(c.stdin.as_deref(), Some(format!("{GOOD}\0").as_bytes()));
    let parent = e.paths.bundle.parent().unwrap();
    assert_eq!(std::fs::metadata(parent).unwrap().mode() & 0o777, 0o700);
    // Second creation: refused before hdiutil.
    let n = f.calls.borrow().len();
    assert!(matches!(
        create(&f, &e.paths, &e.home, 20 << 30, "Coffre", &pw(GOOD)),
        Err(VaultError::AlreadyExists(_))
    ));
    assert_eq!(f.calls.borrow().len(), n);
}

#[test]
fn create_validation() {
    let e = env();
    let f = Fake::default();
    let weak = create(&f, &e.paths, &e.home, 20 << 30, "Coffre", &pw("court"));
    assert!(matches!(weak, Err(VaultError::WeakPassword(_))));
    let ctl = create(
        &f,
        &e.paths,
        &e.home,
        20 << 30,
        "Coffre",
        &pw("abcdefghijkl\tmnop"),
    );
    assert!(matches!(ctl, Err(VaultError::WeakPassword(_))));
    assert!(matches!(
        create(&f, &e.paths, &e.home, 1 << 20, "Coffre", &pw(GOOD)),
        Err(VaultError::Unsafe(_))
    ));
    assert!(matches!(
        create(&f, &e.paths, &e.home, 20 << 30, "a/b", &pw(GOOD)),
        Err(VaultError::Unsafe(_))
    ));
    let other = VaultPaths {
        bundle: e.home.join("Coffre.dmg"),
        mountpoint: None,
    };
    assert!(matches!(
        create(&f, &other, &e.home, 20 << 30, "Coffre", &pw(GOOD)),
        Err(VaultError::Unsafe(_))
    ));
    f.queue(
        "hdiutil create",
        fail(1, "hdiutil: create failed - No space left on device"),
    );
    match create(&f, &e.paths, &e.home, 20 << 30, "Coffre", &pw(GOOD)) {
        Err(VaultError::Tool(m)) => assert!(m.contains("No space left")),
        other => panic!("{other:?}"),
    }
    assert_eq!(f.calls_to("create").len(), 1);
}

#[test]
fn attach_and_detach() {
    let e = env();
    make_bundle(&e.paths.bundle);
    let mount = e.home.join("vol");
    std::fs::create_dir_all(&mount).unwrap();
    std::fs::write(mount.join("note.txt"), "x").unwrap();
    let f = Fake::default();

    f.queue(
        "hdiutil attach",
        fail(1, "hdiutil: attach failed - Authentication error"),
    );
    assert!(matches!(
        attach(&f, &e.paths, &e.home, &pw("wrong password!")),
        Err(VaultError::BadPassword)
    ));

    f.queue("hdiutil attach", ok(&attach_xml(&mount.to_string_lossy())));
    // The fake tool reports the image attached from now on.
    f.set_attached(&e.paths.bundle, &mount);
    // Attach sees it already attached: idempotent, no second attach call.
    let s = attach(&f, &e.paths, &e.home, &pw(GOOD)).unwrap();
    assert!(s.mounted);
    assert_eq!(s.device.as_deref(), Some("/dev/disk4"));
    assert_eq!(s.mount_point.as_deref(), Some(&*mount.to_string_lossy()));
    assert!(s.volume_total_bytes.is_some());
    assert_eq!(f.calls_to("attach").len(), 1);
    let first = &f.calls_to("attach")[0];
    let a = first.args.join(" ");
    assert!(a.starts_with("attach -stdinpass -plist -owners on"));
    assert!(!a.contains("-mountpoint"));
    assert_eq!(first.stdin.as_deref(), Some(&b"wrong password!\0"[..]));

    let s = status(&f, &e.paths, &e.home, 10).unwrap();
    assert_eq!(s.recent.len(), 1);
    assert_eq!(s.recent[0].name, "note.txt");

    // Busy: holders come from lsof.
    f.queue(
        "hdiutil detach",
        fail(16, "hdiutil: couldn't unmount \"disk4\" - Resource busy"),
    );
    f.queue(
        "lsof -n",
        ToolOutput {
            status: 0,
            stdout: format!("p812\ncPreview\nf12\nn{}/note.txt\n", mount.display()).into_bytes(),
            ..Default::default()
        },
    );
    match detach(&f, &e.paths, &e.home, false) {
        Err(VaultError::Busy(h)) => {
            assert_eq!(h.len(), 1);
            assert_eq!(h[0].command, "Preview");
        }
        other => panic!("{other:?}"),
    }
    let lsof = f
        .calls
        .borrow()
        .iter()
        .find(|c| c.program == "/usr/sbin/lsof")
        .cloned()
        .unwrap();
    assert_eq!(lsof.args.last().unwrap(), &mount.to_string_lossy());
    assert!(lsof.args.contains(&"+f".to_string()));

    f.queue("hdiutil detach", ok(""));
    let s = detach(&f, &e.paths, &e.home, true).unwrap();
    assert!(!s.mounted);
    let last = f.calls_to("detach").pop().unwrap();
    assert_eq!(last.args, vec!["detach", "/dev/disk4", "-force"]);
    // Already locked: no-op.
    let n = f.calls_to("detach").len();
    detach(&f, &e.paths, &e.home, false).unwrap();
    assert_eq!(f.calls_to("detach").len(), n);
}

#[test]
fn custom_mountpoint_must_be_empty_and_is_cleaned_up() {
    let e = env();
    make_bundle(&e.paths.bundle);
    let mp = e.home.join("Coffre");
    let p = VaultPaths {
        bundle: e.paths.bundle.clone(),
        mountpoint: Some(mp.clone()),
    };
    let f = Fake::default();
    std::fs::create_dir_all(&mp).unwrap();
    std::fs::write(mp.join("plain.txt"), "not encrypted").unwrap();
    assert!(matches!(
        attach(&f, &p, &e.home, &pw(GOOD)),
        Err(VaultError::Unsafe(_))
    ));
    assert!(f.calls_to("attach").is_empty());
    std::fs::remove_file(mp.join("plain.txt")).unwrap();
    std::fs::write(mp.join(".DS_Store"), "finder").unwrap();
    f.queue("hdiutil attach", ok(&attach_xml(&mp.to_string_lossy())));
    attach(&f, &p, &e.home, &pw(GOOD)).unwrap();
    let a = f.calls_to("attach")[0].args.join(" ");
    assert!(a.contains(&format!("-mountpoint {}", mp.display())));
    // Detached: the empty folder disappears so nothing is saved there in clear.
    detach(&f, &p, &e.home, false).unwrap();
    assert!(!mp.exists());
    // Missing folder: created (0700) for the attach.
    f.queue(
        "hdiutil attach",
        fail(1, "hdiutil: attach failed - Authentication error"),
    );
    assert!(matches!(
        attach(&f, &p, &e.home, &pw(GOOD)),
        Err(VaultError::BadPassword)
    ));
    assert!(!mp.exists(), "cleaned up after a failed attach");
}

#[test]
fn resize_compact_chpass() {
    let e = env();
    make_bundle(&e.paths.bundle);
    let f = Fake::default();
    let mount = e.home.join("vol");
    std::fs::create_dir_all(&mount).unwrap();
    f.set_attached(&e.paths.bundle, &mount);
    assert!(matches!(
        resize(&f, &e.paths, &e.home, 40 << 30, &pw(GOOD)),
        Err(VaultError::Mounted)
    ));
    assert!(matches!(
        compact(&f, &e.paths, &e.home, &pw(GOOD)),
        Err(VaultError::Mounted)
    ));
    *f.attached.borrow_mut() = None;
    f.queue("hdiutil resize", ok(""));
    resize(&f, &e.paths, &e.home, 40 << 30, &pw(GOOD)).unwrap();
    let c = &f.calls_to("resize")[0];
    assert_eq!(c.args[..4], ["resize", "-size", "40960m", "-stdinpass"]);
    assert_eq!(c.stdin.as_deref(), Some(format!("{GOOD}\0").as_bytes()));
    f.queue(
        "hdiutil compact",
        fail(1, "hdiutil: compact failed - Authentication error"),
    );
    assert!(matches!(
        compact(&f, &e.paths, &e.home, &pw("nope-nope-nope")),
        Err(VaultError::BadPassword)
    ));
    f.queue("hdiutil chpass", ok(""));
    change_password(
        &f,
        &e.paths,
        &e.home,
        &pw(GOOD),
        &pw("un nouveau mot de passe"),
    )
    .unwrap();
    let c = &f.calls_to("chpass")[0];
    assert_eq!(
        c.args,
        vec![
            "chpass".to_string(),
            "-oldstdinpass".into(),
            "-newstdinpass".into(),
            e.paths.bundle.to_string_lossy().into_owned()
        ]
    );
    assert_eq!(
        c.stdin.as_deref(),
        Some(format!("{GOOD}\0un nouveau mot de passe\0").as_bytes())
    );
    assert!(matches!(
        change_password(&f, &e.paths, &e.home, &pw(GOOD), &pw("court")),
        Err(VaultError::WeakPassword(_))
    ));
    assert_eq!(f.calls_to("chpass").len(), 1);
}

#[test]
fn destroy_checks_shape_and_lock() {
    let e = env();
    let f = Fake::default();
    // A random folder named like a bundle is not destroyed.
    std::fs::create_dir_all(&e.paths.bundle).unwrap();
    std::fs::write(e.paths.bundle.join("mes-photos.jpg"), "x").unwrap();
    assert!(matches!(
        destroy(&f, &e.paths, &e.home, true),
        Err(VaultError::Unsafe(_))
    ));
    assert!(e.paths.bundle.join("mes-photos.jpg").exists());
    std::fs::remove_dir_all(&e.paths.bundle).unwrap();
    assert!(matches!(
        destroy(&f, &e.paths, &e.home, true),
        Err(VaultError::NotFound(_))
    ));

    make_bundle(&e.paths.bundle);
    let mount = e.home.join("vol");
    std::fs::create_dir_all(&mount).unwrap();
    f.set_attached(&e.paths.bundle, &mount);
    f.queue("hdiutil detach", fail(16, "Resource busy"));
    assert!(matches!(
        destroy(&f, &e.paths, &e.home, false),
        Err(VaultError::Busy(_))
    ));
    assert!(e.paths.bundle.exists());
    f.queue("hdiutil detach", ok(""));
    let s = destroy(&f, &e.paths, &e.home, true).unwrap();
    assert!(!s.exists);
    assert!(!e.paths.bundle.exists());
    assert_eq!(f.calls_to("detach").last().unwrap().args[2], "-force");

    // A symlink to a bundle is refused (never followed).
    let real = e.home.join("real.sparsebundle");
    make_bundle(&real);
    std::os::unix::fs::symlink(&real, &e.paths.bundle).unwrap();
    assert!(matches!(
        destroy(&f, &e.paths, &e.home, true),
        Err(VaultError::Unsafe(_))
    ));
    assert!(real.join("token").exists());
}

#[test]
fn secrets_from_stdin() {
    let one = |s: &[u8]| read_secrets(&mut &s[..], 1).map(|v| v[0].as_bytes().to_vec());
    assert_eq!(one(b"secret").unwrap(), b"secret");
    assert_eq!(one(b"secret\n").unwrap(), b"secret");
    assert_eq!(one(b"secret\r\n").unwrap(), b"secret");
    assert_eq!(one(b"secret\0").unwrap(), b"secret");
    assert_eq!(one(b"two words \n").unwrap(), b"two words ");
    assert!(one(b"").is_err());
    assert!(one(b"\n").is_err());
    assert!(one(b"a\0b").is_err());
    assert!(one(&vec![b'x'; MAX_PASSWORD_BYTES + 1]).is_err());
    let two = read_secrets(&mut &b"old pass\0new pass\0"[..], 2).unwrap();
    assert_eq!(two[0].as_bytes(), b"old pass");
    assert_eq!(two[1].as_bytes(), b"new pass");
    assert!(read_secrets(&mut &b"only one"[..], 2).is_err());
    assert!(read_secrets(&mut &b"a\0\0"[..], 2).is_err());
    assert!(read_secrets(&mut &b"a\0b\0c"[..], 2).is_err());
    assert_eq!(format!("{:?}", pw("x")), "Secret(…)");
}

#[test]
fn names_paths_and_warnings() {
    assert!(validate_volume_name("Coffre").is_ok());
    assert!(validate_volume_name("Coffre de Camille").is_ok());
    for bad in [
        "",
        ".cache",
        "a:b",
        "a/b",
        "un nom beaucoup trop long pour hfs",
    ] {
        assert!(validate_volume_name(bad).is_err(), "{bad}");
    }
    assert_eq!(
        normalize(Path::new("/Users/./camille/Coffre")),
        Some(PathBuf::from("/Users/camille/Coffre"))
    );
    assert_eq!(normalize(Path::new("/Users/../etc")), None);
    assert_eq!(normalize(Path::new("rel")), None);
    let home = Path::new("/Users/camille");
    assert!(sync_warning(home, &VaultPaths::default_bundle(home)).is_none());
    assert!(sync_warning(
        home,
        Path::new("/Users/camille/Library/Mobile Documents/com~apple~CloudDocs/C.sparsebundle")
    )
    .is_some());
    assert!(sync_warning(home, Path::new("/Users/camille/Documents/C.sparsebundle")).is_some());
    assert!(home_dir().is_some_and(|h| h.is_absolute()));
}

#[test]
fn recent_items_skip_hidden_and_sort() {
    let d = tempfile::tempdir().unwrap();
    let m = d.path();
    std::fs::create_dir_all(m.join("Dossier")).unwrap();
    std::fs::create_dir_all(m.join(".fseventsd")).unwrap();
    std::fs::write(m.join(".fseventsd/x"), "x").unwrap();
    std::fs::write(m.join(".DS_Store"), "x").unwrap();
    for (i, n) in ["a.txt", "Dossier/b.pdf", "c.key"].iter().enumerate() {
        let p = m.join(n);
        std::fs::write(&p, "data").unwrap();
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        let t = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(1_700_000_000 + i as u64 * 60);
        f.set_modified(t).unwrap();
    }
    let r = recent_items(m, 2);
    assert_eq!(
        r.iter().map(|i| i.name.as_str()).collect::<Vec<_>>(),
        vec!["c.key", "b.pdf"]
    );
    assert_eq!(r[0].size, 4);
    assert_eq!(r[1].modified, 1_700_000_060);
    assert!(recent_items(m, 0).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Command level (JSON contract with the app)
// ---------------------------------------------------------------------------------------------

fn run_cmd(
    action: VaultCmd,
    f: &Fake,
    e: &Env,
    stdin: &[u8],
    mountpoint: Option<PathBuf>,
) -> (i32, serde_json::Value, String) {
    let a = VaultArgs {
        bundle: Some(e.paths.bundle.clone()),
        mountpoint,
        action,
    };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let mut input = stdin;
    let mut src = Passwords::Pipe(&mut input);
    let code = run_with(
        true,
        &mut Output {
            out: &mut out,
            err: &mut err,
            progress: false,
            is_root: false,
        },
        &a,
        f,
        &mut src,
        &e.home,
    )
    .unwrap();
    let v = serde_json::from_slice(&out).unwrap_or(serde_json::Value::Null);
    (code, v, String::from_utf8(err).unwrap())
}

#[test]
fn json_contract() {
    let e = env();
    let f = Fake::default();
    let (code, v, _) = run_cmd(VaultCmd::Status { recent: 3 }, &f, &e, b"", None);
    assert_eq!(code, 0);
    assert_eq!(v["exists"], false);
    assert_eq!(v["filevault"], "on");
    assert_eq!(v["recent"], serde_json::json!([]));
    assert!(v.get("mount_point").is_none());

    // Error envelope.
    let (code, v, _) = run_cmd(VaultCmd::Attach, &f, &e, b"whatever-password\n", None);
    assert_eq!(code, 2);
    assert_eq!(v["error"]["code"], "not_found");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("aucun coffre"));
    assert!(v["error"].get("holders").is_none());

    f.queue("hdiutil create", ok("<plist><array/></plist>"));
    let (code, v, _) = run_cmd(
        VaultCmd::Create {
            size: "1g".into(),
            name: "Coffre".into(),
        },
        &f,
        &e,
        format!("{GOOD}\n").as_bytes(),
        None,
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["exists"], true);
    assert_eq!(v["encrypted"], true);
    assert_eq!(
        f.calls_to("create")[0].stdin.as_deref(),
        Some(format!("{GOOD}\0").as_bytes())
    );

    let (code, v, _) = run_cmd(
        VaultCmd::Resize {
            size: "lots".into(),
        },
        &f,
        &e,
        b"x",
        None,
    );
    assert_eq!(code, 2);
    assert_eq!(v["error"]["code"], "unsafe");

    // Busy detach lists the holders.
    let mount = e.home.join("vol");
    std::fs::create_dir_all(&mount).unwrap();
    f.set_attached(&e.paths.bundle, &mount);
    f.queue("hdiutil detach", fail(16, "Resource busy"));
    f.queue(
        "lsof -n",
        ok(&format!("p77\ncTextEdit\nn{}/a.txt\n", mount.display())),
    );
    let (code, v, _) = run_cmd(VaultCmd::Detach { force: false }, &f, &e, b"", None);
    assert_eq!(code, 2);
    assert_eq!(v["error"]["code"], "busy");
    assert_eq!(v["error"]["holders"][0]["command"], "TextEdit");
    assert!(v["error"]["message"].as_str().unwrap().contains("TextEdit"));

    // Shred inside the open vault: plain deletion; outside: overwrite.
    std::fs::write(mount.join("dans-le-coffre.txt"), "secret").unwrap();
    std::fs::write(e.home.join("dehors.txt"), "secret").unwrap();
    let (code, v, _) = run_cmd(
        VaultCmd::Shred {
            paths: vec![mount.join("dans-le-coffre.txt"), e.home.join("dehors.txt")],
            dry_run: false,
        },
        &f,
        &e,
        b"",
        None,
    );
    assert_eq!(code, 0, "{v}");
    assert_eq!(v[0]["zone"], "vault");
    assert_eq!(v[0]["outcome"], "deleted");
    assert_eq!(v[0]["overwritten_bytes"], 0);
    assert_eq!(v[1]["zone"], "home");
    assert_eq!(v[1]["overwritten_bytes"], 6);
    // The bundle itself is never shredded.
    let (code, v, _) = run_cmd(
        VaultCmd::Shred {
            paths: vec![e.paths.bundle.clone()],
            dry_run: true,
        },
        &f,
        &e,
        b"",
        None,
    );
    assert_eq!(code, 2);
    assert_eq!(v[0]["outcome"], "refused");

    f.queue("hdiutil detach", fail(16, "Resource busy"));
    let (code, v, _) = run_cmd(
        VaultCmd::Destroy {
            yes: true,
            force: false,
        },
        &f,
        &e,
        b"",
        None,
    );
    assert_eq!(code, 2);
    assert_eq!(v["error"]["code"], "busy");

    let (code, v, _) = run_cmd(VaultCmd::Filevault, &f, &e, b"", None);
    assert_eq!(code, 0);
    assert_eq!(v["filevault"], "on");
}

#[test]
fn root_is_refused() {
    let cli = crate::Cli::try_parse_args(["parabellum", "--json", "vault", "status"]).unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = crate::run(
        &cli,
        &mut Output {
            out: &mut out,
            err: &mut err,
            progress: false,
            is_root: true,
        },
    );
    assert_eq!(code, 2);
    assert!(String::from_utf8(err).unwrap().contains("sans sudo"));
}

#[test]
fn cli_parsing() {
    let p = |a: &[&str]| {
        crate::Cli::try_parse_args(std::iter::once("parabellum").chain(a.iter().copied()))
    };
    let c = p(&["vault", "--bundle", "/tmp/C.sparsebundle", "attach"]).unwrap();
    match c.command {
        crate::cli::Command::Vault(v) => {
            assert!(matches!(v.action, VaultCmd::Attach));
            assert_eq!(v.bundle.unwrap(), PathBuf::from("/tmp/C.sparsebundle"));
        }
        _ => panic!(),
    }
    // Global vault options after the subcommand too.
    assert!(p(&[
        "vault",
        "detach",
        "--force",
        "--mountpoint",
        "/Users/c/Coffre",
        "--json"
    ])
    .is_ok());
    assert!(p(&["vault", "shred"]).is_err());
    assert!(p(&["vault", "shred", "a", "b", "--dry-run"]).is_ok());
    assert!(p(&["vault", "empty-trash"]).is_ok());
    assert!(p(&["vault", "create", "--size", "5g", "--name", "Perso"]).is_ok());
    assert!(!crate::commands::needs_admin(
        &p(&["vault", "destroy", "--yes"]).unwrap().command
    ));
}

// ---------------------------------------------------------------------------------------------
// Fixtures shared with the Swift tests (app/Tests/ParabellumKitTests/Fixtures)
// ---------------------------------------------------------------------------------------------

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../app/Tests/ParabellumKitTests/Fixtures")
}

fn sample_fixtures() -> Vec<(&'static str, serde_json::Value)> {
    let open = VaultStatus {
        bundle_path:
            "/Users/camille/Library/Application Support/Parabellum/Vault/Coffre.sparsebundle".into(),
        exists: true,
        encrypted: true,
        mounted: true,
        mount_point: Some("/Volumes/Coffre".into()),
        device: Some("/dev/disk4".into()),
        capacity_bytes: Some(20 << 30),
        allocated_bytes: Some(1_288_490_189),
        volume_total_bytes: Some(21_474_836_480),
        volume_free_bytes: Some(20_186_346_291),
        filevault: FileVaultState::Off,
        sync_warning: None,
        recent: vec![VaultItem {
            name: "Impôts 2026.pdf".into(),
            path: "/Volumes/Coffre/Impôts 2026.pdf".into(),
            size: 482_133,
            modified: 1_793_000_000,
        }],
    };
    let absent = VaultStatus {
        bundle_path: open.bundle_path.clone(),
        filevault: FileVaultState::On,
        sync_warning: sync_warning(
            Path::new("/Users/camille"),
            Path::new("/Users/camille/Documents/Coffre.sparsebundle"),
        ),
        ..Default::default()
    };
    let busy = VaultError::Busy(vec![super::tools::Holder {
        pid: 812,
        command: "Preview".into(),
        paths: vec!["/Volumes/Coffre/Impôts 2026.pdf".into()],
    }]);
    let error = serde_json::json!({ "error": command::ErrorBody {
        code: busy.code(),
        message: busy.to_string(),
        holders: match &busy { VaultError::Busy(h) => h, _ => &[] },
    }});
    let shred = vec![
        shred::ShredReport {
            path: "/Users/camille/Downloads/relevé.pdf".into(),
            outcome: shred::Outcome::Deleted,
            zone: Some(shred::Zone::Home),
            files: 1,
            dirs: 0,
            bytes: 52_000,
            overwritten_bytes: 52_000,
            not_overwritten: 0,
            warnings: vec![],
            error: None,
        },
        shred::ShredReport {
            path: "/System/Library".into(),
            outcome: shred::Outcome::Refused,
            zone: None,
            files: 0,
            dirs: 0,
            bytes: 0,
            overwritten_bytes: 0,
            not_overwritten: 0,
            warnings: vec![],
            error: Some("hors de votre dossier personnel et des volumes externes : refusé".into()),
        },
    ];
    vec![
        (
            "vault_status_open.json",
            serde_json::to_value(&open).unwrap(),
        ),
        (
            "vault_status_absent.json",
            serde_json::to_value(&absent).unwrap(),
        ),
        ("vault_error_busy.json", error),
        ("shred_reports.json", serde_json::to_value(&shred).unwrap()),
    ]
}

/// The Swift decoding tests read these files: they must match the serde shapes. Regenerate with
/// `PB_UPDATE_FIXTURES=1 cargo test -p pb-cli vault::tests::fixtures`.
#[test]
fn fixtures_match_serde() {
    let dir = fixture_dir();
    let update = std::env::var_os("PB_UPDATE_FIXTURES").is_some();
    for (name, value) in sample_fixtures() {
        let path = dir.join(name);
        let text = serde_json::to_string_pretty(&value).unwrap() + "\n";
        if update {
            std::fs::write(&path, &text).unwrap();
            continue;
        }
        let on_disk = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("{} missing: PB_UPDATE_FIXTURES=1", path.display()));
        let parsed: serde_json::Value = serde_json::from_str(&on_disk).unwrap();
        assert_eq!(parsed, value, "{name} is stale: PB_UPDATE_FIXTURES=1");
    }
}
