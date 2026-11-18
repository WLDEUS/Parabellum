//! Browser extensions of the current user (run as the user, never by the root daemon):
//! - Chromium family: `<root>/<profile>/Preferences` + `Secure Preferences` (`extensions.settings`),
//!   manifests from `<profile>/Extensions/<id>/<version>/manifest.json` (or the unpacked folder);
//! - Firefox: `Profiles/<profile>/extensions.json`;
//! - Safari: `pluginkit -mAvvv -p com.apple.Safari.web-extension` + each `.appex`'s `manifest.json`.

use pb_core::model::{BrowserExtension, Severity};
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// Chromium browsers: (key, data folder relative to the home folder).
pub const CHROMIUM: &[(&str, &str)] = &[
    ("chrome", "Library/Application Support/Google/Chrome"),
    (
        "brave",
        "Library/Application Support/BraveSoftware/Brave-Browser",
    ),
    ("edge", "Library/Application Support/Microsoft Edge"),
    ("arc", "Library/Application Support/Arc/User Data"),
    ("chromium", "Library/Application Support/Chromium"),
    ("vivaldi", "Library/Application Support/Vivaldi"),
];
pub const FIREFOX_PROFILES: &str = "Library/Application Support/Firefox/Profiles";
pub const PLUGINKIT: &str = "/usr/bin/pluginkit";
const MAX_JSON: u64 = 32 * 1024 * 1024;

/// API permissions that matter, with what they allow (French).
const SENSITIVE: &[(&str, &str)] = &[
    ("debugger", "contrôle des onglets comme un débogueur"),
    (
        "nativeMessaging",
        "dialogue avec un programme installé sur le Mac",
    ),
    ("proxy", "redirection de tout le trafic web"),
    ("webRequest", "observation des requêtes web"),
    ("webRequestBlocking", "modification des requêtes web"),
    ("cookies", "lecture des cookies (sessions connectées)"),
    ("scripting", "injection de code dans les pages"),
    ("management", "gestion des autres extensions"),
    ("history", "historique de navigation"),
    ("tabs", "adresses et titres des onglets"),
    ("clipboardRead", "lecture du presse-papiers"),
    ("downloads", "téléchargements"),
    ("privacy", "réglages de confidentialité du navigateur"),
    ("webNavigation", "suivi de la navigation"),
    ("desktopCapture", "capture de l'écran"),
    ("tabCapture", "capture des onglets"),
];
const WITH_ALL_HOSTS_HIGH: &[&str] = &[
    "cookies",
    "webRequest",
    "webRequestBlocking",
    "scripting",
    "nativeMessaging",
    "proxy",
    "debugger",
];

/// `<all_urls>`, `*://*/*`, `https://*/*`…: every site.
pub fn is_all_hosts(h: &str) -> bool {
    if h == "<all_urls>" {
        return true;
    }
    match h.split_once("://") {
        Some((_, rest)) => rest.split('/').next() == Some("*"),
        None => false,
    }
}

fn bump(s: Severity, up: bool) -> Severity {
    use Severity::*;
    match (s, up) {
        (Info, true) => Low,
        (Low, true) => Medium,
        (Medium, true) | (High, true) | (Critical, true) => High,
        (High, false) | (Critical, false) => Medium,
        (Medium, false) => Low,
        (Low, false) | (Info, false) => Info,
    }
}

/// Risk of an extension and why (French).
pub fn score(
    perms: &[String],
    hosts: &[String],
    from_store: Option<bool>,
    unpacked: bool,
    enabled: Option<bool>,
) -> (Severity, Vec<String>) {
    let all = hosts.iter().any(|h| is_all_hosts(h));
    let has = |p: &str| perms.iter().any(|x| x == p);
    let mut reasons = Vec::new();
    if all {
        reasons.push("Peut lire et modifier toutes les pages web".to_string());
    }
    for (p, what) in SENSITIVE {
        if has(p) {
            reasons.push(format!("{p} : {what}"));
        }
    }
    let mut sev = if has("debugger") || (all && WITH_ALL_HOSTS_HIGH.iter().any(|p| has(p))) {
        Severity::High
    } else if all || has("nativeMessaging") || has("proxy") || has("management") {
        Severity::Medium
    } else if SENSITIVE.iter().any(|(p, _)| has(p)) || !hosts.is_empty() {
        Severity::Low
    } else {
        Severity::Info
    };
    if unpacked {
        reasons.push("Chargée depuis un dossier (mode développeur)".into());
        sev = bump(sev, true).max(Severity::Medium);
    } else if from_store == Some(false) {
        reasons.push("Installée hors de la boutique officielle".into());
        sev = bump(sev, true);
    }
    if enabled == Some(false) {
        reasons.push("Désactivée".into());
        sev = bump(sev, false);
    }
    (sev, reasons)
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn clean(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

/// Read a JSON file (bounded, no symlink as last component).
pub fn read_json(path: &Path) -> Option<Value> {
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() || md.len() > MAX_JSON {
        return None;
    }
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

/// `__MSG_name__` -> the message of the default locale.
fn localize(name: &str, manifest: &Value, dir: Option<&Path>) -> String {
    let Some(key) = name
        .strip_prefix("__MSG_")
        .and_then(|k| k.strip_suffix("__"))
    else {
        return name.to_string();
    };
    let locale = manifest
        .get("default_locale")
        .and_then(Value::as_str)
        .unwrap_or("en");
    let msgs = dir.and_then(|d| read_json(&d.join("_locales").join(locale).join("messages.json")));
    msgs.as_ref()
        .and_then(Value::as_object)
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(key))
                .and_then(|(_, v)| v.get("message"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| key.to_string())
}

/// Host patterns and API permissions of a manifest (MV2 mixes hosts into `permissions`).
fn manifest_permissions(m: &Value) -> (Vec<String>, Vec<String>) {
    let mut perms = Vec::new();
    let mut hosts = strings(m.get("host_permissions"));
    for p in strings(m.get("permissions")) {
        if p.contains("://") || p == "<all_urls>" {
            hosts.push(p);
        } else {
            perms.push(p);
        }
    }
    if let Some(cs) = m.get("content_scripts").and_then(Value::as_array) {
        for c in cs {
            hosts.extend(strings(c.get("matches")));
        }
    }
    hosts.sort();
    hosts.dedup();
    (perms, hosts)
}

fn chromium_enabled(s: &Value) -> bool {
    match s.get("disable_reasons") {
        Some(Value::Array(a)) if !a.is_empty() => return false,
        Some(Value::Number(n)) if n.as_i64() != Some(0) => return false,
        _ => {}
    }
    s.get("state").and_then(Value::as_i64) != Some(0)
}

/// Extensions of one Chromium profile from its merged `extensions.settings`. `ext_dir` = the profile's
/// `Extensions` folder (manifests of store installs).
pub fn chromium_profile(
    browser: &str,
    profile: &str,
    settings: &Map<String, Value>,
    ext_dir: Option<&Path>,
) -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    for (id, s) in settings {
        let location = s.get("location").and_then(Value::as_i64).unwrap_or(0);
        if matches!(location, 5 | 10) {
            continue; // component extensions shipped with the browser
        }
        let rel = s.get("path").and_then(Value::as_str).unwrap_or("");
        let unpacked = matches!(location, 4 | 8);
        let dir: Option<PathBuf> = if rel.starts_with('/') {
            Some(PathBuf::from(rel))
        } else if !rel.is_empty() && !rel.contains("..") {
            ext_dir.map(|d| d.join(rel))
        } else {
            None
        };
        let manifest = s.get("manifest").cloned().or_else(|| {
            dir.as_ref()
                .and_then(|d| read_json(&d.join("manifest.json")))
        });
        let Some(manifest) = manifest else { continue };
        let name = manifest.get("name").and_then(Value::as_str).unwrap_or(id);
        let name = clean(&localize(name, &manifest, dir.as_deref()), 120);
        let (mut perms, mut hosts) = manifest_permissions(&manifest);
        if let Some(g) = s
            .get("granted_permissions")
            .or_else(|| s.get("active_permissions"))
        {
            let api = strings(g.get("api"));
            if !api.is_empty() {
                perms = api;
            }
            let mut gh = strings(g.get("explicit_host"));
            gh.extend(strings(g.get("scriptable_host")));
            if !gh.is_empty() {
                gh.sort();
                gh.dedup();
                hosts = gh;
            }
        }
        let update_url = manifest
            .get("update_url")
            .and_then(Value::as_str)
            .unwrap_or("");
        let from_store = if unpacked {
            Some(false)
        } else {
            Some(
                s.get("from_webstore")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                    || update_url.contains("clients2.google.com/service/update2/crx")
                    || update_url.contains("edge.microsoft.com/extensionwebstorebase"),
            )
        };
        let enabled = Some(chromium_enabled(s));
        let (risk, reasons) = score(&perms, &hosts, from_store, unpacked, enabled);
        out.push(BrowserExtension {
            id: format!("{browser}:{profile}:{id}"),
            browser: browser.into(),
            profile: profile.into(),
            extension_id: clean(id, 128),
            name,
            version: manifest
                .get("version")
                .and_then(Value::as_str)
                .map(|v| clean(v, 32)),
            enabled,
            from_store,
            unpacked,
            permissions: perms,
            host_permissions: hosts,
            risk,
            reasons,
            path: dir.map(|d| d.display().to_string()),
        });
    }
    out
}

/// `extensions.settings` of `Secure Preferences` overlaid on `Preferences`.
pub fn merged_settings(prefs: Option<&Value>, secure: Option<&Value>) -> Map<String, Value> {
    let mut m = Map::new();
    for doc in [prefs, secure].into_iter().flatten() {
        if let Some(s) = doc
            .pointer("/extensions/settings")
            .and_then(Value::as_object)
        {
            for (k, v) in s {
                match (m.get_mut(k), v) {
                    (Some(Value::Object(a)), Value::Object(b)) => {
                        for (bk, bv) in b {
                            a.insert(bk.clone(), bv.clone());
                        }
                    }
                    _ => {
                        m.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }
    m
}

/// Every profile of a Chromium browser.
pub fn chromium(browser: &str, root: &Path, errors: &mut Vec<String>) -> Vec<BrowserExtension> {
    let Ok(rd) = std::fs::read_dir(root) else {
        return vec![];
    };
    let names = read_json(&root.join("Local State"));
    let mut out = Vec::new();
    let mut dirs: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    dirs.sort();
    for dir in dirs.into_iter().take(64) {
        let Some(folder) = dir.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
            continue;
        };
        if folder == "System Profile" || folder == "Guest Profile" {
            continue;
        }
        let prefs = read_json(&dir.join("Preferences"));
        if prefs.is_none() {
            continue;
        }
        let secure = read_json(&dir.join("Secure Preferences"));
        let label = names
            .as_ref()
            .and_then(|n| {
                n.pointer(&format!(
                    "/profile/info_cache/{}/name",
                    folder.replace('~', "~0").replace('/', "~1")
                ))
            })
            .and_then(Value::as_str)
            .map(|s| clean(s, 64))
            .unwrap_or_else(|| folder.clone());
        let settings = merged_settings(prefs.as_ref(), secure.as_ref());
        if settings.is_empty() && secure.is_none() {
            errors.push(format!(
                "{browser} ({label}) : préférences sans liste d'extensions"
            ));
        }
        out.extend(chromium_profile(
            browser,
            &label,
            &settings,
            Some(&dir.join("Extensions")),
        ));
    }
    out
}

/// Add-ons of one Firefox profile (`extensions.json`).
pub fn firefox_profile(profile: &str, doc: &Value) -> Vec<BrowserExtension> {
    let mut out = Vec::new();
    for a in doc
        .get("addons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if a.get("type").and_then(Value::as_str) != Some("extension") {
            continue;
        }
        let location = a.get("location").and_then(Value::as_str).unwrap_or("");
        if location.starts_with("app-builtin") || location.starts_with("app-system") {
            continue;
        }
        let Some(id) = a.get("id").and_then(Value::as_str) else {
            continue;
        };
        let up = a.get("userPermissions");
        let perms = strings(up.and_then(|u| u.get("permissions")));
        let hosts = strings(up.and_then(|u| u.get("origins")));
        let unpacked = location == "app-temporary";
        let source = a
            .pointer("/installTelemetryInfo/source")
            .and_then(Value::as_str);
        let uri = a.get("sourceURI").and_then(Value::as_str).unwrap_or("");
        let from_store =
            Some(source == Some("amo") || uri.starts_with("https://addons.mozilla.org/"));
        let enabled = Some(a.get("active").and_then(Value::as_bool).unwrap_or(false));
        let (risk, reasons) = score(&perms, &hosts, from_store, unpacked, enabled);
        let name = a
            .pointer("/defaultLocale/name")
            .and_then(Value::as_str)
            .unwrap_or(id);
        out.push(BrowserExtension {
            id: format!("firefox:{profile}:{id}"),
            browser: "firefox".into(),
            profile: profile.into(),
            extension_id: clean(id, 128),
            name: clean(name, 120),
            version: a
                .get("version")
                .and_then(Value::as_str)
                .map(|v| clean(v, 32)),
            enabled,
            from_store,
            unpacked,
            permissions: perms,
            host_permissions: hosts,
            risk,
            reasons,
            path: a
                .get("path")
                .and_then(Value::as_str)
                .map(|p| clean(p, 1024)),
        });
    }
    out
}

/// Every Firefox profile.
pub fn firefox(root: &Path) -> Vec<BrowserExtension> {
    let Ok(rd) = std::fs::read_dir(root) else {
        return vec![];
    };
    let mut out = Vec::new();
    for e in rd.flatten().take(64) {
        let folder = e.file_name().to_string_lossy().into_owned();
        let Some(doc) = read_json(&e.path().join("extensions.json")) else {
            continue;
        };
        // `abcd1234.default-release` -> `default-release`
        let label = folder
            .split_once('.')
            .map(|(_, n)| n.to_string())
            .unwrap_or(folder);
        out.extend(firefox_profile(&label, &doc));
    }
    out
}

/// One `pluginkit -mAvvv` entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PluginkitEntry {
    pub flag: char,
    pub bundle_id: String,
    pub version: Option<String>,
    pub path: Option<String>,
    pub display_name: Option<String>,
    pub parent: Option<String>,
}

/// `pluginkit -mAvvv -p com.apple.Safari.web-extension`.
pub fn parse_pluginkit(out: &str) -> Vec<PluginkitEntry> {
    let mut v: Vec<PluginkitEntry> = Vec::new();
    for line in out.lines() {
        if let Some((k, val)) = line.split_once(" = ") {
            if let Some(e) = v.last_mut() {
                let val = val.trim().to_string();
                match k.trim() {
                    "Path" => e.path = Some(val),
                    "Display Name" => e.display_name = Some(val),
                    "Parent Bundle" => e.parent = Some(val),
                    _ => {}
                }
            }
            continue;
        }
        let t = line.trim_end();
        let Some(open) = t.rfind('(') else { continue };
        if !t.ends_with(')') {
            continue;
        }
        let head = t[..open].trim();
        let (flag, id) = match head.chars().next() {
            Some(c @ ('+' | '-' | '=' | '!')) => (c, head[1..].trim()),
            _ => (' ', head),
        };
        if id.is_empty() || id.contains(char::is_whitespace) {
            continue;
        }
        v.push(PluginkitEntry {
            flag,
            bundle_id: id.to_string(),
            version: Some(t[open + 1..t.len() - 1].to_string()).filter(|s| !s.is_empty()),
            ..Default::default()
        });
    }
    v
}

/// Safari web extensions from `pluginkit` output.
pub fn safari(entries: &[PluginkitEntry]) -> Vec<BrowserExtension> {
    entries
        .iter()
        .map(|e| {
            let manifest = e
                .path
                .as_ref()
                .and_then(|p| read_json(&Path::new(p).join("Contents/Resources/manifest.json")));
            let (perms, hosts) = manifest
                .as_ref()
                .map(manifest_permissions)
                .unwrap_or_default();
            let from_store = e
                .parent
                .as_ref()
                .map(|p| Path::new(p).join("Contents/_MASReceipt/receipt").is_file());
            let enabled = (e.flag == '-').then_some(false);
            // Outside the App Store, Safari extensions are still signed and notarized: no penalty.
            let (risk, reasons) = score(&perms, &hosts, None, false, enabled);
            let name = e
                .display_name
                .clone()
                .or_else(|| {
                    manifest
                        .as_ref()
                        .and_then(|m| m.get("name").and_then(Value::as_str).map(str::to_string))
                })
                .unwrap_or_else(|| e.bundle_id.clone());
            BrowserExtension {
                id: format!("safari:default:{}", e.bundle_id),
                browser: "safari".into(),
                profile: "Safari".into(),
                extension_id: clean(&e.bundle_id, 128),
                name: clean(&name, 120),
                version: e.version.clone(),
                enabled,
                from_store,
                unpacked: false,
                permissions: perms,
                host_permissions: hosts,
                risk,
                reasons,
                path: e.path.clone(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFS: &str = r#"{"extensions":{"settings":{
      "cjpalhdlnbpafiamejdnhcphjbkeiagm":{"location":1,"from_webstore":true,"path":"cjpalhdlnbpafiamejdnhcphjbkeiagm/1.62.0_0","state":1,
        "granted_permissions":{"api":["storage","webRequest","webRequestBlocking","tabs"],"explicit_host":["<all_urls>"],"scriptable_host":["http://*/*","https://*/*"]}},
      "abcdefghijklmnopabcdefghijklmnop":{"location":4,"path":"/Users/camille/dev/my-ext","disable_reasons":[]},
      "mhjfbmdgcfjbbpaeojofohoefgiehjai":{"location":5,"manifest":{"name":"Chrome PDF Viewer"}},
      "ghbmnnjooekpmoecnnnilnnbdlolhkhi":{"location":1,"from_webstore":true,"disable_reasons":[1],
        "manifest":{"name":"__MSG_extName__","version":"1.9","permissions":["storage"],"update_url":"https://clients2.google.com/service/update2/crx"}}
    }}}"#;
    const SECURE: &str = r#"{"extensions":{"settings":{"cjpalhdlnbpafiamejdnhcphjbkeiagm":{"manifest":{"name":"uBlock Origin","version":"1.62.0"}}}}}"#;

    #[test]
    fn chromium_settings() {
        let prefs: Value = serde_json::from_str(PREFS).unwrap();
        let secure: Value = serde_json::from_str(SECURE).unwrap();
        let s = merged_settings(Some(&prefs), Some(&secure));
        let d = tempfile::tempdir().unwrap();
        let unpacked = d.path().join("my-ext");
        std::fs::create_dir_all(&unpacked).unwrap();
        std::fs::write(
            unpacked.join("manifest.json"),
            r#"{"name":"Mon outil","version":"0.1","manifest_version":3,"permissions":["cookies","nativeMessaging"],"host_permissions":["<all_urls>"]}"#,
        )
        .unwrap();
        // Point the unpacked entry at the temp folder.
        let mut s = s;
        s.get_mut("abcdefghijklmnopabcdefghijklmnop").unwrap()["path"] =
            Value::String(unpacked.display().to_string());
        let v = chromium_profile("chrome", "Personnel", &s, Some(d.path()));
        assert_eq!(v.len(), 3, "component extension skipped");
        let ubo = v.iter().find(|e| e.name == "uBlock Origin").unwrap();
        assert_eq!(ubo.risk, Severity::High);
        assert_eq!(ubo.from_store, Some(true));
        assert_eq!(ubo.enabled, Some(true));
        assert!(ubo.host_permissions.contains(&"<all_urls>".to_string()));
        assert_eq!(ubo.id, "chrome:Personnel:cjpalhdlnbpafiamejdnhcphjbkeiagm");
        let dev = v.iter().find(|e| e.unpacked).unwrap();
        assert_eq!(dev.name, "Mon outil");
        assert_eq!(dev.risk, Severity::High);
        assert!(dev.reasons.iter().any(|r| r.contains("mode développeur")));
        let off = v
            .iter()
            .find(|e| e.extension_id.starts_with("ghbm"))
            .unwrap();
        assert_eq!(off.enabled, Some(false));
        assert_eq!(off.name, "extName");
        assert_eq!(off.risk, Severity::Info);
    }

    #[test]
    fn firefox_addons() {
        let doc: Value = serde_json::from_str(r#"{"schemaVersion":36,"addons":[
          {"id":"uBlock0@raymondhill.net","type":"extension","location":"app-profile","active":true,"version":"1.62.0",
           "defaultLocale":{"name":"uBlock Origin"},"sourceURI":"https://addons.mozilla.org/firefox/downloads/file/1/x.xpi",
           "installTelemetryInfo":{"source":"amo"},
           "userPermissions":{"permissions":["dns","tabs","webRequest","webRequestBlocking"],"origins":["<all_urls>"]}},
          {"id":"helper@local","type":"extension","location":"app-temporary","active":true,"defaultLocale":{"name":"Test"},
           "userPermissions":{"permissions":["storage"],"origins":[]}},
          {"id":"formautofill@mozilla.org","type":"extension","location":"app-builtin","active":true},
          {"id":"fr@dictionaries","type":"dictionary","location":"app-profile","active":true}
        ]}"#).unwrap();
        let v = firefox_profile("default-release", &doc);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].risk, Severity::High);
        assert_eq!(v[0].from_store, Some(true));
        assert!(v[1].unpacked && v[1].risk == Severity::Medium);
    }

    #[test]
    fn pluginkit_output() {
        let out = "+    com.example.Notes.SafariExt(2.1)\n\t            Path = /Applications/Notes Helper.app/Contents/PlugIns/SafariExt.appex\n\t            UUID = 0D3F2B1A-1111-2222-3333-444455556666\n\t       Timestamp = 2026-10-02 08:12:44 +0000\n\t             SDK = com.apple.Safari.web-extension\n\t   Parent Bundle = /Applications/Notes Helper.app\n\t    Display Name = Notes Helper\n\t     Short Name = Notes\n-    org.example.Blocker.Extension(1.0)\n\t            Path = /Applications/Blocker.app/Contents/PlugIns/Extension.appex\n\t    Display Name = Blocker\n";
        let v = parse_pluginkit(out);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].flag, '+');
        assert_eq!(v[0].bundle_id, "com.example.Notes.SafariExt");
        assert_eq!(v[0].version.as_deref(), Some("2.1"));
        assert_eq!(
            v[0].parent.as_deref(),
            Some("/Applications/Notes Helper.app")
        );
        let s = safari(&v);
        assert_eq!(s[0].name, "Notes Helper");
        assert_eq!(s[1].enabled, Some(false));
        assert_eq!(s[0].from_store, Some(false));
    }

    #[test]
    fn host_patterns() {
        assert!(
            is_all_hosts("<all_urls>") && is_all_hosts("*://*/*") && is_all_hosts("https://*/")
        );
        assert!(!is_all_hosts("https://*.example.com/*") && !is_all_hosts("storage"));
        assert_eq!(
            score(&[], &[], Some(true), false, Some(true)).0,
            Severity::Info
        );
        assert_eq!(
            score(&["history".into()], &[], Some(false), false, Some(true)).0,
            Severity::Medium
        );
    }
}
