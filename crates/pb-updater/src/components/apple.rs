//! Apple tool wrappers (absolute paths, argument vectors, timeouts) and their output parsers.
//! The parsers are platform-independent and unit-tested; the wrappers only make sense on macOS.

use crate::process::{run, RunOpts};
use crate::UpdateError;
use std::path::{Path, PathBuf};

pub(crate) const PKGUTIL: &str = "/usr/sbin/pkgutil";
pub(crate) const SPCTL: &str = "/usr/sbin/spctl";
pub(crate) const INSTALLER: &str = "/usr/sbin/installer";
pub(crate) const CODESIGN: &str = "/usr/bin/codesign";
pub(crate) const HDIUTIL: &str = "/usr/bin/hdiutil";
pub(crate) const DITTO: &str = "/usr/bin/ditto";
pub(crate) const LAUNCHCTL: &str = "/bin/launchctl";
pub(crate) const SUDO: &str = "/usr/bin/sudo";
pub(crate) const OPEN: &str = "/usr/bin/open";
pub(crate) const SYSTEMEXTENSIONSCTL: &str = "/usr/bin/systemextensionsctl";

// ---------------------------------------------------------------------------------------------
// Parsers
// ---------------------------------------------------------------------------------------------

/// Parse `pkgutil --check-signature <pkg>` output. Requires a Developer ID signature
/// (`Status: signed by a developer certificate issued by Apple for distribution`) and returns the Team ID
/// of the leaf certificate (`1. Developer ID Installer: Name (TEAMID)`).
pub(crate) fn parse_pkgutil_signature(out: &str) -> Result<String, String> {
    let status = out
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("Status:"))
        .map(str::trim)
        .ok_or_else(|| "pas de signature".to_string())?;
    if !status.starts_with("signed by a developer certificate issued by Apple") {
        return Err(format!("signature non Developer ID : {status}"));
    }
    let leaf = out
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("1. "))
        .ok_or_else(|| "chaîne de certificats absente".to_string())?;
    if !leaf.starts_with("Developer ID Installer:") {
        return Err(format!("certificat inattendu : {leaf}"));
    }
    team_in_parens(leaf).ok_or_else(|| format!("Team ID introuvable : {leaf}"))
}

fn team_in_parens(s: &str) -> Option<String> {
    let open = s.rfind('(')?;
    let close = s[open..].find(')')? + open;
    let id = &s[open + 1..close];
    (id.len() == 10
        && id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
    .then(|| id.to_string())
}

/// `TeamIdentifier=XXXX` from `codesign -dv --verbose=2` (printed on stderr).
pub(crate) fn parse_codesign_team(out: &str) -> Option<String> {
    out.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("TeamIdentifier="))
        .map(str::trim)
        .filter(|t| *t != "not set" && !t.is_empty())
        .map(str::to_string)
}

/// Mount points from `hdiutil attach -plist` output (`system-entities[].mount-point`).
pub(crate) fn parse_hdiutil_mount_points(plist_xml: &[u8]) -> Vec<PathBuf> {
    let Ok(v) = plist::Value::from_reader(std::io::Cursor::new(plist_xml)) else {
        return vec![];
    };
    let Some(ents) = v
        .as_dictionary()
        .and_then(|d| d.get("system-entities"))
        .and_then(|e| e.as_array())
    else {
        return vec![];
    };
    ents.iter()
        .filter_map(|e| {
            e.as_dictionary()?
                .get("mount-point")?
                .as_string()
                .map(PathBuf::from)
        })
        .collect()
}

/// `systemextensionsctl list`: true when `bundle_id` is listed `[activated enabled]`.
pub(crate) fn parse_system_extension_active(out: &str, bundle_id: &str) -> Option<bool> {
    let mut seen = false;
    for l in out.lines() {
        if l.contains(bundle_id) {
            seen = true;
            if l.contains("[activated enabled]") {
                return Some(true);
            }
        }
    }
    seen.then_some(false)
}

/// `ClamAV 1.5.4/27800/…` → `1.5.4`.
pub(crate) fn parse_clamscan_version(out: &str) -> Option<String> {
    let rest = out.trim().strip_prefix("ClamAV ")?;
    let v: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    (!v.is_empty()).then_some(v)
}

/// `osqueryi version 5.24.0` → `5.24.0`.
pub(crate) fn parse_osquery_version(out: &str) -> Option<String> {
    let idx = out.find("version ")?;
    let v: String = out[idx + 8..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    (!v.is_empty()).then_some(v)
}

/// `CFBundleShortVersionString` of an `Info.plist` (XML or binary), bounded read.
pub(crate) fn bundle_short_version(info_plist: &Path) -> Option<String> {
    let bytes = crate::fsutil::read_capped(info_plist, 4 * 1024 * 1024).ok()?;
    let v = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
    v.as_dictionary()?
        .get("CFBundleShortVersionString")?
        .as_string()
        .map(|s| s.trim().to_string())
}

/// `CFBundleExecutable` of an app bundle (validated as a plain file name).
pub(crate) fn bundle_executable(app: &Path) -> Option<PathBuf> {
    let bytes =
        crate::fsutil::read_capped(&app.join("Contents/Info.plist"), 4 * 1024 * 1024).ok()?;
    let v = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
    let name = v
        .as_dictionary()?
        .get("CFBundleExecutable")?
        .as_string()?
        .to_string();
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return None;
    }
    Some(app.join("Contents/MacOS").join(name))
}

// ---------------------------------------------------------------------------------------------
// Wrappers
// ---------------------------------------------------------------------------------------------

fn p(s: &str) -> &Path {
    Path::new(s)
}

/// Developer ID Installer signature with the expected Team ID + Gatekeeper install assessment.
pub(crate) async fn verify_pkg(pkg: &Path, team_id: &str) -> Result<(), UpdateError> {
    let out = run(
        p(PKGUTIL),
        [p("--check-signature"), pkg],
        RunOpts::timeout(120),
    )
    .await?;
    let team = parse_pkgutil_signature(&out.combined()).map_err(UpdateError::Verification)?;
    if !out.success() {
        return Err(UpdateError::Verification(format!(
            "pkgutil : {}",
            out.summary()
        )));
    }
    if team != team_id {
        return Err(UpdateError::Verification(format!(
            "Team ID {team} ≠ {team_id} attendu"
        )));
    }
    let out = run(
        p(SPCTL),
        [p("--assess"), p("--type"), p("install"), pkg],
        RunOpts::timeout(120),
    )
    .await?;
    if !out.success() {
        return Err(UpdateError::Verification(format!(
            "Gatekeeper refuse le paquet : {}",
            out.summary()
        )));
    }
    Ok(())
}

/// Code signature (deep, strict) with the expected Team ID + Gatekeeper execute assessment (notarization).
pub(crate) async fn verify_app(app: &Path, team_id: &str) -> Result<(), UpdateError> {
    let out = run(
        p(CODESIGN),
        [p("--verify"), p("--deep"), p("--strict"), app],
        RunOpts::timeout(300),
    )
    .await?;
    if !out.success() {
        return Err(UpdateError::Verification(format!(
            "codesign : {}",
            out.summary()
        )));
    }
    let out = run(
        p(CODESIGN),
        [p("-dv"), p("--verbose=2"), app],
        RunOpts::timeout(60),
    )
    .await?;
    let team = parse_codesign_team(&out.combined())
        .ok_or_else(|| UpdateError::Verification("Team ID absent de la signature".into()))?;
    if team != team_id {
        return Err(UpdateError::Verification(format!(
            "Team ID {team} ≠ {team_id} attendu"
        )));
    }
    let out = run(
        p(SPCTL),
        [p("--assess"), p("--type"), p("execute"), app],
        RunOpts::timeout(120),
    )
    .await?;
    if !out.success() {
        return Err(UpdateError::Verification(format!(
            "Gatekeeper refuse l'application : {}",
            out.summary()
        )));
    }
    Ok(())
}

/// `installer -pkg <pkg> -target /` (third-party packages; Parabellum's own update goes through a
/// launchd job, see `crate::selfupdate`).
pub(crate) async fn install_pkg(pkg: &Path) -> Result<String, UpdateError> {
    let out = run(p(INSTALLER), [p("-pkg"), pkg, p("-target"), p("/")], RunOpts::timeout(20 * 60)).await?;
    if !out.success() {
        return Err(UpdateError::Command(format!(
            "installer : {}",
            out.summary()
        )));
    }
    Ok(out
        .combined()
        .lines()
        .next_back()
        .unwrap_or("installé")
        .to_string())
}

/// Mount a DMG read-only, hidden, without auto-open, at a random point under `parent`.
pub(crate) async fn attach_dmg(dmg: &Path, parent: &Path) -> Result<PathBuf, UpdateError> {
    let out = run(
        p(HDIUTIL),
        [
            p("attach"),
            p("-readonly"),
            p("-nobrowse"),
            p("-noautoopen"),
            p("-mountrandom"),
            parent,
            p("-plist"),
            dmg,
        ],
        RunOpts::timeout(180),
    )
    .await?;
    if !out.success() {
        return Err(UpdateError::Command(format!(
            "hdiutil attach : {}",
            out.summary()
        )));
    }
    parse_hdiutil_mount_points(out.stdout.as_bytes())
        .into_iter()
        .find(|m| m.starts_with(parent))
        .ok_or_else(|| UpdateError::Command("hdiutil : point de montage introuvable".into()))
}

pub(crate) async fn detach_dmg(mount: &Path) {
    let res = run(
        p(HDIUTIL),
        [p("detach"), mount, p("-force")],
        RunOpts::timeout(120),
    )
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, mount = %mount.display(), "hdiutil detach failed");
    }
}

/// `ditto -x -k <zip> <dest>` (preserves bundle symlinks, permissions and extended attributes).
pub(crate) async fn ditto_unzip(zip: &Path, dest: &Path) -> Result<(), UpdateError> {
    let out = run(
        p(DITTO),
        [p("-x"), p("-k"), zip, dest],
        RunOpts::timeout(300),
    )
    .await?;
    if !out.success() {
        return Err(UpdateError::Command(format!("ditto : {}", out.summary())));
    }
    Ok(())
}

/// `ditto <src> <dst>` (copy an app bundle).
pub(crate) async fn ditto_copy(src: &Path, dst: &Path) -> Result<(), UpdateError> {
    let out = run(p(DITTO), [src, dst], RunOpts::timeout(300)).await?;
    if !out.success() {
        return Err(UpdateError::Command(format!("ditto : {}", out.summary())));
    }
    Ok(())
}

/// Open an app in the console user's GUI session, as that user:
/// `launchctl asuser <uid> sudo -u #<uid> open -a <app>`.
pub(crate) async fn open_app_as_user(app: &Path, uid: u32) -> Result<(), UpdateError> {
    let uid_s = uid.to_string();
    let as_user = format!("#{uid}");
    let out = run(
        p(LAUNCHCTL),
        [
            p("asuser"),
            p(&uid_s),
            p(SUDO),
            p("-n"),
            p("-u"),
            p(&as_user),
            p(OPEN),
            p("-a"),
            app,
        ],
        RunOpts::timeout(60),
    )
    .await?;
    if !out.success() {
        return Err(UpdateError::Command(format!("open : {}", out.summary())));
    }
    Ok(())
}

/// Whether a system extension is `[activated enabled]` (`None` if not listed / tool failed).
pub(crate) async fn system_extension_active(bundle_id: &str) -> Option<bool> {
    let out = run(p(SYSTEMEXTENSIONSCTL), ["list"], RunOpts::timeout(30))
        .await
        .ok()?;
    parse_system_extension_active(&out.stdout, bundle_id)
}

/// Output of `<bin> <flag>` (version probes of installed tools). A binary root must not trust
/// (e.g. Homebrew's, user-owned) is run as its unprivileged owner.
pub(crate) async fn version_output(bin: &Path, flag: &str) -> Option<String> {
    if !bin.is_file() {
        return None;
    }
    let out = match run(bin, [flag], RunOpts::timeout(30).as_owner_if_untrusted()).await {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!(binary = %bin.display(), error = %e, "version probe skipped");
            return None;
        }
    };
    out.success().then(|| out.combined())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PKGUTIL_OK: &str = r#"Package "clamav-1.5.4.macos.universal.pkg":
   Status: signed by a developer certificate issued by Apple for distribution
   Notarization: trusted by the Apple notary service
   Signed with a trusted timestamp on: 2026-09-30 17:01:02 +0000
   Certificate Chain:
    1. Developer ID Installer: Cisco (DE8Y96K9QP)
       Expires: 2030-01-01 00:00:00 +0000
       SHA256 Fingerprint:
           AA BB
       ------------------------------------------------------------------------
    2. Developer ID Certification Authority
       Expires: 2031-09-17 00:00:00 +0000
    3. Apple Root CA
"#;

    #[test]
    fn pkgutil_parsing() {
        assert_eq!(parse_pkgutil_signature(PKGUTIL_OK).unwrap(), "DE8Y96K9QP");
        assert!(parse_pkgutil_signature("Package \"x.pkg\":\n   Status: no signature\n").is_err());
        let apple = PKGUTIL_OK.replace(
            "signed by a developer certificate issued by Apple for distribution",
            "signed by a certificate trusted by macOS",
        );
        assert!(parse_pkgutil_signature(&apple).is_err());
        let app_cert = PKGUTIL_OK.replace("Developer ID Installer", "Developer ID Application");
        assert!(parse_pkgutil_signature(&app_cert).is_err());
    }

    #[test]
    fn codesign_and_versions() {
        let cs = "Executable=/x/LuLu.app/Contents/MacOS/LuLu\nIdentifier=com.objective-see.lulu.app\nAuthority=Developer ID Application: Objective-See, LLC (VBG97UB4TA)\nTeamIdentifier=VBG97UB4TA\n";
        assert_eq!(parse_codesign_team(cs).as_deref(), Some("VBG97UB4TA"));
        assert_eq!(parse_codesign_team("TeamIdentifier=not set\n"), None);
        assert_eq!(
            parse_clamscan_version("ClamAV 1.5.4/27800/Sat Oct 25 07:21:00 2026\n").as_deref(),
            Some("1.5.4")
        );
        assert_eq!(parse_clamscan_version("nope"), None);
        assert_eq!(
            parse_osquery_version("osqueryi version 5.24.0\n").as_deref(),
            Some("5.24.0")
        );
    }

    #[test]
    fn systemextensions_parsing() {
        let out = "1 extension(s)\n--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tVBG97UB4TA\tcom.objective-see.lulu.extension (4.5.3/4.5.3)\tLuLu\t[activated enabled]\n";
        assert_eq!(
            parse_system_extension_active(out, "com.objective-see.lulu.extension"),
            Some(true)
        );
        let waiting = out.replace("[activated enabled]", "[activated waiting for user]");
        assert_eq!(
            parse_system_extension_active(&waiting, "com.objective-see.lulu.extension"),
            Some(false)
        );
        assert_eq!(
            parse_system_extension_active("0 extension(s)\n", "com.objective-see.lulu.extension"),
            None
        );
    }

    #[test]
    fn hdiutil_plist_and_info_plist() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>system-entities</key><array>
<dict><key>content-hint</key><string>GUID_partition_scheme</string><key>dev-entry</key><string>/dev/disk4</string></dict>
<dict><key>content-hint</key><string>Apple_HFS</string><key>dev-entry</key><string>/dev/disk4s1</string><key>mount-point</key><string>/tmp/pb/dmg.Ab12Cd</string></dict>
</array></dict></plist>"#;
        assert_eq!(
            parse_hdiutil_mount_points(xml),
            vec![PathBuf::from("/tmp/pb/dmg.Ab12Cd")]
        );
        assert!(parse_hdiutil_mount_points(b"garbage").is_empty());

        let d = tempfile::tempdir().unwrap();
        let app = d.path().join("X.app");
        std::fs::create_dir_all(app.join("Contents")).unwrap();
        std::fs::write(
            app.join("Contents/Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>4.5.3</string><key>CFBundleExecutable</key><string>LuLu Installer</string></dict></plist>"#,
        )
        .unwrap();
        assert_eq!(
            bundle_short_version(&app.join("Contents/Info.plist")).as_deref(),
            Some("4.5.3")
        );
        assert_eq!(
            bundle_executable(&app),
            Some(app.join("Contents/MacOS/LuLu Installer"))
        );
    }
}
