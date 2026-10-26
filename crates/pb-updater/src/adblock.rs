//! uBlock Origin Lite status (never installed by us — the stores keep it updated).
//!
//! - Chrome: extension id `ddkjiahejlhfcafbddmgiahcphecmpfh` (Chrome Web Store link published in the
//!   official uBOL-home README, github.com/uBlockOrigin/uBOL-home). Every Chrome profile's `Preferences` and
//!   `Secure Preferences` JSON is inspected for `extensions.settings.<id>`; `state == 0` or a non-empty
//!   `disable_reasons` means installed but disabled.
//! - Safari: app "uBlock Origin Lite" by Raymond Hill on the Mac App Store (id6745342698, link from the same
//!   README). The extension bundle id is read from the app's `Contents/PlugIns/*.appex` whose
//!   `NSExtensionPointIdentifier` is `com.apple.Safari.web-extension`, then `pluginkit -m -v -i <id>` is run
//!   as the console user: a leading `+` means enabled, `-` disabled. Best effort: `Unknown` on failure
//!   (pluginkit's election state may not reflect the per-profile toggle in Safari's settings).

use pb_core::model::ExtensionState;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// uBlock Origin Lite id on the Chrome Web Store.
pub const CHROME_UBOL_EXTENSION_ID: &str = "ddkjiahejlhfcafbddmgiahcphecmpfh";
/// Chrome Web Store page (from the uBOL-home README, checked 2026-10-25).
pub const CHROME_UBOL_STORE_URL: &str =
    "https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh";
/// Mac App Store page of uBlock Origin Lite for Safari (from the uBOL-home README, checked 2026-10-25).
pub const SAFARI_UBOL_STORE_URL: &str =
    "https://apps.apple.com/app/ublock-origin-lite/id6745342698";

/// App bundle names looked for in `/Applications` (App Store name "uBlock Origin Lite").
const SAFARI_APP_CANDIDATES: [&str; 2] = [
    "/Applications/uBlock Origin Lite.app",
    "/Applications/uBO Lite.app",
];
const SAFARI_WEB_EXTENSION_POINT: &str = "com.apple.Safari.web-extension";
const CHROME_SUPPORT_DIR: &str = "Library/Application Support/Google/Chrome";
const MAX_PREFS_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PROFILES: usize = 64;

/// `(chrome, safari)` uBlock Origin Lite states for the user owning `user_home`.
/// The console uid is taken from the owner of `user_home`.
pub fn adblock_extension_states(user_home: &Path) -> (ExtensionState, ExtensionState) {
    adblock_extension_states_for(user_home, home_owner_uid(user_home))
}

/// Same as [`adblock_extension_states`] with an explicit console uid (used to run `pluginkit`).
pub fn adblock_extension_states_for(
    user_home: &Path,
    console_uid: Option<u32>,
) -> (ExtensionState, ExtensionState) {
    (chrome_state(user_home), safari_state(console_uid))
}

#[cfg(unix)]
fn home_owner_uid(home: &Path) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(home)
        .ok()
        .map(|m| m.uid())
        .filter(|u| *u != 0)
}

#[cfg(not(unix))]
fn home_owner_uid(_home: &Path) -> Option<u32> {
    None
}

// ---------------------------------------------------------------------------------------------
// Chrome
// ---------------------------------------------------------------------------------------------

/// State of `ext_id` in one parsed Preferences document (`None` = not present).
pub(crate) fn chrome_state_from_prefs(prefs: &Value, ext_id: &str) -> Option<ExtensionState> {
    let entry = prefs.get("extensions")?.get("settings")?.get(ext_id)?;
    if !entry.is_object() {
        return None;
    }
    let disabled_by_reasons = match entry.get("disable_reasons") {
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Number(n)) => n.as_u64().is_some_and(|v| v != 0),
        _ => false,
    };
    let disabled_by_state = entry.get("state").and_then(Value::as_i64) == Some(0);
    if disabled_by_reasons || disabled_by_state {
        Some(ExtensionState::InstalledDisabled)
    } else {
        Some(ExtensionState::Enabled)
    }
}

/// Read a regular file (never follows symlinks, never opens FIFOs/devices), bounded.
fn read_regular(path: &Path, max: u64) -> Option<Vec<u8>> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.file_type().is_file() || md.len() > max {
        return None;
    }
    crate::fsutil::read_capped(path, max).ok()
}

fn chrome_state(home: &Path) -> ExtensionState {
    let dir = home.join(CHROME_SUPPORT_DIR);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return ExtensionState::NotInstalled;
    };
    let mut profiles: Vec<PathBuf> = rd
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .map(|e| e.path())
        .take(MAX_PROFILES * 4)
        .collect();
    profiles.sort();
    let mut best: Option<ExtensionState> = None;
    for profile in profiles.iter().take(MAX_PROFILES) {
        for file in ["Secure Preferences", "Preferences"] {
            let Some(bytes) = read_regular(&profile.join(file), MAX_PREFS_BYTES) else {
                continue;
            };
            let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            match chrome_state_from_prefs(&v, CHROME_UBOL_EXTENSION_ID) {
                Some(ExtensionState::Enabled) => return ExtensionState::Enabled,
                Some(s) => best = Some(s),
                None => {}
            }
        }
    }
    best.unwrap_or(ExtensionState::NotInstalled)
}

// ---------------------------------------------------------------------------------------------
// Safari
// ---------------------------------------------------------------------------------------------

/// Bundle id of the Safari web extension embedded in `app` (`Contents/PlugIns/*.appex`).
pub(crate) fn safari_extension_bundle_id(app: &Path) -> Option<String> {
    let rd = std::fs::read_dir(app.join("Contents/PlugIns")).ok()?;
    for e in rd.flatten().take(64) {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("appex") {
            continue;
        }
        let Some(bytes) = read_regular(&p.join("Contents/Info.plist"), 4 * 1024 * 1024) else {
            continue;
        };
        let Ok(v) = plist::Value::from_reader(std::io::Cursor::new(bytes)) else {
            continue;
        };
        let Some(d) = v.as_dictionary() else { continue };
        let point = d
            .get("NSExtension")
            .and_then(|n| n.as_dictionary())
            .and_then(|n| n.get("NSExtensionPointIdentifier"))
            .and_then(|s| s.as_string());
        if point == Some(SAFARI_WEB_EXTENSION_POINT) {
            if let Some(id) = d.get("CFBundleIdentifier").and_then(|s| s.as_string()) {
                if !id.is_empty()
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
                {
                    return Some(id.to_string());
                }
            }
        }
    }
    None
}

/// Parse `pluginkit -m -v -i <id>` output: `+` enabled, `-` disabled, anything else unknown.
pub(crate) fn parse_pluginkit(out: &str, bundle_id: &str) -> ExtensionState {
    for l in out.lines() {
        let t = l.trim_start();
        let rest = t.get(1..).unwrap_or("").trim_start();
        if rest.starts_with(bundle_id) || t.starts_with(bundle_id) {
            return match t.chars().next() {
                Some('+') => ExtensionState::Enabled,
                Some('-') => ExtensionState::InstalledDisabled,
                _ => ExtensionState::Unknown,
            };
        }
    }
    ExtensionState::Unknown
}

fn safari_state(console_uid: Option<u32>) -> ExtensionState {
    let Some(app) = SAFARI_APP_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_dir())
    else {
        return ExtensionState::NotInstalled;
    };
    let Some(ext_id) = safari_extension_bundle_id(&app) else {
        return ExtensionState::Unknown;
    };
    match run_pluginkit(&ext_id, console_uid) {
        Some(out) => parse_pluginkit(&out, &ext_id),
        None => ExtensionState::Unknown,
    }
}

/// Run pluginkit in the console user's context (`launchctl asuser <uid> sudo -n -u #<uid> pluginkit …`)
/// when we are root, directly otherwise. Synchronous with a 10 s timeout.
fn run_pluginkit(ext_id: &str, console_uid: Option<u32>) -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let pluginkit = "/usr/bin/pluginkit";
    let mut args: Vec<String> = Vec::new();
    let program: &str;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        let uid = console_uid?;
        program = "/bin/launchctl";
        args.extend([
            "asuser".into(),
            uid.to_string(),
            "/usr/bin/sudo".into(),
            "-n".into(),
            "-u".into(),
            format!("#{uid}"),
        ]);
        args.push(pluginkit.into());
    } else {
        program = pluginkit;
    }
    args.extend(["-m".into(), "-v".into(), "-i".into(), ext_id.into()]);
    run_sync(Path::new(program), &args, Duration::from_secs(10))
}

/// Minimal synchronous subprocess with timeout (stdout captured, bounded).
fn run_sync(program: &Path, args: &[String], timeout: Duration) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut stdout).take(1 << 20).read_to_end(&mut buf);
        buf
    });
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    reader
        .join()
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_prefs_fixture() {
        let v: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/chrome_secure_preferences.json"
        ))
        .unwrap();
        assert_eq!(
            chrome_state_from_prefs(&v, CHROME_UBOL_EXTENSION_ID),
            Some(ExtensionState::Enabled)
        );
        assert_eq!(
            chrome_state_from_prefs(&v, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Some(ExtensionState::InstalledDisabled)
        );
        assert_eq!(
            chrome_state_from_prefs(&v, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            Some(ExtensionState::InstalledDisabled)
        );
        assert_eq!(
            chrome_state_from_prefs(&v, "cccccccccccccccccccccccccccccccc"),
            None
        );
        assert_eq!(
            chrome_state_from_prefs(&serde_json::json!({}), CHROME_UBOL_EXTENSION_ID),
            None
        );
    }

    #[test]
    fn chrome_profiles_scan() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(chrome_state(home.path()), ExtensionState::NotInstalled);
        let base = home.path().join(CHROME_SUPPORT_DIR);
        std::fs::create_dir_all(base.join("Default")).unwrap();
        std::fs::create_dir_all(base.join("Profile 1")).unwrap();
        std::fs::write(
            base.join("Default/Preferences"),
            r#"{"extensions":{"settings":{}}}"#,
        )
        .unwrap();
        assert_eq!(chrome_state(home.path()), ExtensionState::NotInstalled);
        let disabled = format!(
            r#"{{"extensions":{{"settings":{{"{CHROME_UBOL_EXTENSION_ID}":{{"disable_reasons":[1]}}}}}}}}"#
        );
        std::fs::write(base.join("Profile 1/Secure Preferences"), disabled).unwrap();
        assert_eq!(chrome_state(home.path()), ExtensionState::InstalledDisabled);
        let enabled = format!(
            r#"{{"extensions":{{"settings":{{"{CHROME_UBOL_EXTENSION_ID}":{{"state":1}}}}}}}}"#
        );
        std::fs::write(base.join("Default/Secure Preferences"), enabled).unwrap();
        assert_eq!(chrome_state(home.path()), ExtensionState::Enabled);
    }

    #[test]
    fn pluginkit_and_appex() {
        let id = "net.raymondhill.uBOLite.Extension";
        let out = format!("+    {id}(2025.1012)\tC2E1A5B0-0000-0000-0000-000000000000\t2026-10-20 10:00:00 +0000\t/Applications/uBlock Origin Lite.app/Contents/PlugIns/uBOLite Extension.appex\n");
        assert_eq!(parse_pluginkit(&out, id), ExtensionState::Enabled);
        assert_eq!(
            parse_pluginkit(&out.replacen('+', "-", 1), id),
            ExtensionState::InstalledDisabled
        );
        assert_eq!(
            parse_pluginkit(&out.replacen('+', " ", 1), id),
            ExtensionState::Unknown
        );
        assert_eq!(parse_pluginkit("", id), ExtensionState::Unknown);

        let d = tempfile::tempdir().unwrap();
        let appex = d.path().join("X.app/Contents/PlugIns/Ext.appex/Contents");
        std::fs::create_dir_all(&appex).unwrap();
        std::fs::write(
            appex.join("Info.plist"),
            format!(r#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>{id}</string><key>NSExtension</key><dict><key>NSExtensionPointIdentifier</key><string>com.apple.Safari.web-extension</string></dict></dict></plist>"#),
        )
        .unwrap();
        assert_eq!(
            safari_extension_bundle_id(&d.path().join("X.app")).as_deref(),
            Some(id)
        );
    }
}
