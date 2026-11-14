//! Run as the user: resolve TCC clients (bundle id or path) to app name / path / "still installed" / code
//! signature, and reset a permission with `tccutil`.

use pb_core::model::{AppIdentity, SigningInfo, TccResetResult};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const CODESIGN: &str = "/usr/bin/codesign";
pub const SPCTL: &str = "/usr/sbin/spctl";
pub const MDFIND: &str = "/usr/bin/mdfind";
pub const TCCUTIL: &str = "/usr/bin/tccutil";

/// Services `tccutil reset` accepts from the app (short names).
pub const RESETTABLE: &[&str] = &[
    "Accessibility",
    "ScreenCapture",
    "SystemPolicyAllFiles",
    "ListenEvent",
    "PostEvent",
    "DeveloperTool",
    "AppleEvents",
    "SystemPolicyAppBundles",
    "Camera",
    "Microphone",
    "SystemPolicySysAdminFiles",
    "Photos",
    "AddressBook",
    "Calendar",
    "Reminders",
    "SystemPolicyDesktopFolder",
    "SystemPolicyDocumentsFolder",
    "SystemPolicyDownloadsFolder",
    "SystemPolicyNetworkVolumes",
    "SystemPolicyRemovableVolumes",
    "SystemPolicyAppData",
    "PhotosAdd",
    "BluetoothAlways",
    "MediaLibrary",
    "SpeechRecognition",
];

/// Run a tool with a cleared environment (`LANG`/`LC_ALL=C`) and a timeout: (exit ok, stdout, stderr).
pub fn run(program: &str, args: &[&str], timeout: Duration) -> Option<(bool, String, String)> {
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let (mut out, mut err) = (child.stdout.take()?, child.stderr.take()?);
    let t_out = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::Read::take(&mut out, 1 << 20), &mut s);
        s
    });
    let t_err = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = std::io::Read::read_to_string(&mut std::io::Read::take(&mut err, 1 << 20), &mut s);
        s
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let (o, e) = (
        t_out.join().unwrap_or_default(),
        t_err.join().unwrap_or_default(),
    );
    status.map(|s| (s.success(), o, e))
}

/// `codesign -dv --verbose=4` (stderr) -> signing facts (validity not verified: `valid` = signed).
pub fn parse_codesign(stderr: &str) -> SigningInfo {
    let mut s = SigningInfo::default();
    if stderr.contains("code object is not signed at all") {
        return s;
    }
    let mut authorities = Vec::new();
    for l in stderr.lines().map(str::trim) {
        if let Some(v) = l.strip_prefix("Authority=") {
            authorities.push(v.to_string());
        } else if let Some(v) = l.strip_prefix("TeamIdentifier=") {
            if v != "not set" && !v.is_empty() {
                s.team_id = Some(v.to_string());
            }
        } else if let Some(v) = l.strip_prefix("Identifier=") {
            s.identifier = Some(v.to_string());
        } else if l == "Signature=adhoc" || (l.starts_with("CodeDirectory ") && l.contains("adhoc"))
        {
            s.adhoc = true;
        }
        if l.starts_with("CodeDirectory ") {
            s.signed = true;
        }
    }
    s.signed |= s.adhoc || !authorities.is_empty();
    s.valid = s.signed;
    s.apple = !s.adhoc
        && authorities
            .iter()
            .any(|a| a == "Software Signing" || a == "Apple Mac OS Application Signing");
    s.authority = authorities.into_iter().next();
    s
}

/// `spctl --assess -vv` stderr -> notarized / App Store / Apple (true), rejected (false), unknown (None).
pub fn parse_spctl(stderr: &str) -> Option<bool> {
    let first = stderr.lines().next().unwrap_or("");
    if first.contains(": rejected") {
        return (!first.contains("does not seem to be an app")).then_some(false);
    }
    let source = stderr
        .lines()
        .find_map(|l| l.trim().strip_prefix("source="))
        .unwrap_or("");
    (first.contains(": accepted")
        && (source.starts_with("Notarized")
            || source.starts_with("Apple")
            || source == "Mac App Store"))
        .then_some(true)
}

fn signing(path: &Path) -> Option<SigningInfo> {
    let p = path.to_str()?;
    let (_, _, err) = run(
        CODESIGN,
        &["-dv", "--verbose=4", p],
        Duration::from_secs(20),
    )?;
    let mut s = parse_codesign(&err);
    if s.signed && !s.adhoc && !s.apple && p.ends_with(".app") {
        if let Some((_, _, e)) = run(
            SPCTL,
            &["--assess", "--type", "execute", "-vv", p],
            Duration::from_secs(30),
        ) {
            s.notarized = parse_spctl(&e);
            if e.contains("invalid") || e.contains("modified") {
                s.valid = false;
            }
        }
    }
    Some(s)
}

/// (bundle id, display name) from an app's `Contents/Info.plist`.
pub fn bundle_info(app: &Path) -> Option<(String, String)> {
    let v = plist::Value::from_file(app.join("Contents/Info.plist")).ok()?;
    let d = v.as_dictionary()?;
    let id = d.get("CFBundleIdentifier")?.as_string()?.to_string();
    let name = ["CFBundleDisplayName", "CFBundleName"]
        .iter()
        .find_map(|k| {
            d.get(k)
                .and_then(|x| x.as_string())
                .filter(|s| !s.is_empty())
        })
        .map(str::to_string)
        .or_else(|| app.file_stem().map(|s| s.to_string_lossy().into_owned()))?;
    Some((id, name))
}

/// `*.app` bundles of the usual folders (two levels deep), bundle id -> (path, name).
pub fn app_index(home: &Path) -> HashMap<String, (PathBuf, String)> {
    let roots = [
        PathBuf::from("/Applications"),
        home.join("Applications"),
        PathBuf::from("/System/Applications"),
        PathBuf::from("/System/Library/CoreServices"),
    ];
    let mut m = HashMap::new();
    let visit = |dir: &Path, depth: u8, m: &mut HashMap<String, (PathBuf, String)>| {
        fn walk(dir: &Path, depth: u8, m: &mut HashMap<String, (PathBuf, String)>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten().take(2000) {
                let p = e.path();
                let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                if p.extension().is_some_and(|x| x == "app") {
                    if let Some((id, name)) = bundle_info(&p) {
                        m.entry(id).or_insert((p, name));
                    }
                } else if is_dir && depth > 0 {
                    walk(&p, depth - 1, m);
                }
            }
        }
        walk(dir, depth, m);
    };
    for r in &roots {
        visit(r, 1, &mut m);
    }
    m
}

/// Spotlight lookup of a bundle id (validated by the caller).
fn mdfind(id: &str) -> Option<PathBuf> {
    let q = format!("kMDItemCFBundleIdentifier == \"{id}\"");
    let (_, out, _) = run(MDFIND, &[&q], Duration::from_secs(8))?;
    out.lines()
        .map(PathBuf::from)
        .find(|p| p.is_absolute() && p.exists())
}

fn valid_bundle_id(c: &str) -> bool {
    !c.is_empty()
        && c.len() <= 255
        && c.as_bytes()[0].is_ascii_alphanumeric()
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The `.app` containing a path (`/Applications/X.app/Contents/MacOS/x` -> `/Applications/X.app`).
pub fn enclosing_app(p: &Path) -> Option<PathBuf> {
    p.ancestors()
        .find(|a| a.extension().is_some_and(|x| x == "app"))
        .map(Path::to_path_buf)
}

/// Resolve every client (bundle ids and absolute paths).
pub fn resolve(clients: &[String], home: &Path) -> Vec<AppIdentity> {
    let index = app_index(home);
    let one = |c: &String| -> AppIdentity {
        let mut id = AppIdentity {
            client: c.clone(),
            name: None,
            path: None,
            installed: None,
            signing: None,
        };
        let target = if c.starts_with('/') {
            let p = Path::new(c);
            if std::fs::symlink_metadata(p).is_err() {
                id.installed = Some(false);
                return id;
            }
            let app = enclosing_app(p);
            id.name = app
                .as_ref()
                .and_then(|a| bundle_info(a).map(|(_, n)| n))
                .or_else(|| p.file_name().map(|n| n.to_string_lossy().into_owned()));
            app.unwrap_or_else(|| p.to_path_buf())
        } else if !valid_bundle_id(c) {
            return id;
        } else if let Some((p, name)) = index.get(c) {
            id.name = Some(name.clone());
            p.clone()
        } else if let Some(p) = mdfind(c) {
            id.name = bundle_info(&p)
                .map(|(_, n)| n)
                .or_else(|| p.file_stem().map(|s| s.to_string_lossy().into_owned()));
            p
        } else {
            // Apple's own daemons are not in /Applications: unknown rather than "removed".
            id.installed = (!c.starts_with("com.apple.")).then_some(false);
            return id;
        };
        id.installed = Some(true);
        id.path = Some(target.display().to_string());
        id.signing = signing(&target);
        id
    };
    let mut out: Vec<AppIdentity> = Vec::with_capacity(clients.len());
    for chunk in clients.chunks(clients.len().div_ceil(4).max(1)) {
        let part: Vec<AppIdentity> = std::thread::scope(|s| {
            let hs: Vec<_> = chunk.iter().map(|c| s.spawn(|| one(c))).collect();
            hs.into_iter().filter_map(|h| h.join().ok()).collect()
        });
        out.extend(part);
    }
    out
}

/// `kTCCServiceCamera` / `Camera` -> `Camera` when resettable.
pub fn reset_service(service: &str) -> Option<&'static str> {
    let short = service.strip_prefix("kTCCService").unwrap_or(service);
    RESETTABLE.iter().copied().find(|s| *s == short)
}

/// `tccutil reset <Service> <bundle id>` as the current user.
pub fn reset(service: &str, bundle_id: &str) -> Result<TccResetResult, String> {
    let svc = reset_service(service).ok_or_else(|| format!("service inconnu : {service}"))?;
    if !valid_bundle_id(bundle_id) {
        return Err(format!("identifiant d'app invalide : {bundle_id}"));
    }
    let (ok, out, err) = run(TCCUTIL, &["reset", svc, bundle_id], Duration::from_secs(20))
        .ok_or("tccutil : lancement impossible ou délai dépassé")?;
    let msg = format!("{}{}", out.trim(), err.trim());
    Ok(TccResetResult {
        ok,
        service: svc.to_string(),
        bundle_id: bundle_id.to_string(),
        message: if ok {
            format!("Autorisation « {svc} » retirée à {bundle_id}.")
        } else {
            format!(
                "tccutil a refusé ({}) : retire-la dans Réglages Système > Confidentialité et sécurité.",
                msg.chars().take(300).collect::<String>()
            )
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codesign_parsing() {
        let dev = "Executable=/Applications/Zoom.app/Contents/MacOS/zoom.us\nIdentifier=us.zoom.xos\nFormat=app bundle with Mach-O universal (x86_64 arm64)\nCodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=28+7 location=embedded\nAuthority=Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)\nAuthority=Developer ID Certification Authority\nAuthority=Apple Root CA\nTeamIdentifier=BJ4HAAB9B3\n";
        let s = parse_codesign(dev);
        assert!(s.signed && !s.adhoc && !s.apple);
        assert_eq!(s.team_id.as_deref(), Some("BJ4HAAB9B3"));
        let adhoc = "Executable=/Users/camille/bin/tool\nIdentifier=tool\nCodeDirectory v=20400 size=500 flags=0x20002(adhoc,linker-signed) hashes=10+0 location=embedded\nSignature=adhoc\nTeamIdentifier=not set\n";
        let s = parse_codesign(adhoc);
        assert!(s.signed && s.adhoc && s.team_id.is_none());
        let apple = "Identifier=com.apple.Terminal\nCodeDirectory v=20400 size=800 flags=0x0(none)\nAuthority=Software Signing\nAuthority=Apple Code Signing Certification Authority\n";
        assert!(parse_codesign(apple).apple);
        assert!(!parse_codesign("/x: code object is not signed at all\n").signed);
        assert_eq!(
            parse_spctl("/Applications/Zoom.app: accepted\nsource=Notarized Developer ID\n"),
            Some(true)
        );
        assert_eq!(
            parse_spctl("/Applications/X.app: rejected\nsource=Unnotarized Developer ID\n"),
            Some(false)
        );
        assert_eq!(
            parse_spctl("/x: rejected (the code is valid but does not seem to be an app)\n"),
            None
        );
    }

    #[test]
    fn resolution_and_reset_validation() {
        let d = tempfile::tempdir().unwrap();
        let app = d.path().join("Applications/Clicker.app/Contents");
        std::fs::create_dir_all(app.join("MacOS")).unwrap();
        std::fs::write(
            app.join("Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.clicker</string><key>CFBundleName</key><string>Clicker</string></dict></plist>"#,
        )
        .unwrap();
        let idx = app_index(d.path());
        assert_eq!(idx["com.example.clicker"].1, "Clicker");
        let exe = app.join("MacOS/clicker");
        std::fs::write(&exe, b"x").unwrap();
        assert_eq!(
            enclosing_app(&exe).unwrap(),
            d.path().join("Applications/Clicker.app")
        );
        let r = resolve(
            &[
                exe.display().to_string(),
                "/nonexistent/tool".into(),
                "com.apple.some.daemon".into(),
                "bad id;".into(),
            ],
            d.path(),
        );
        assert_eq!(r[0].name.as_deref(), Some("Clicker"));
        assert_eq!(r[0].installed, Some(true));
        assert_eq!(r[1].installed, Some(false));
        assert_eq!(r[2].installed, None);
        assert_eq!(r[3].installed, None);
        assert_eq!(reset_service("kTCCServiceCamera"), Some("Camera"));
        assert_eq!(reset_service("All"), None);
        assert!(reset("Camera", "-x").is_err());
        assert!(reset("Nope", "com.example.app").is_err());
    }
}
