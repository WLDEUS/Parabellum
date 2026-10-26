//! Apple code-signing information through Apple's own tools (macOS only):
//! * `/usr/bin/codesign -dv --verbose=4 <path>` (details on stderr: `Authority=`, `TeamIdentifier=`,
//!   `Identifier=`, `Signature=adhoc`, `CodeDirectory … flags=0x…(adhoc,…)`),
//! * `/usr/bin/codesign --verify --strict <path>` (exit 0 = valid),
//! * `/usr/sbin/spctl --assess --type execute -vv <path>` (Gatekeeper / notarization:
//!   `<path>: accepted|rejected`, `source=Notarized Developer ID` …).
//!
//! The parsers are platform-independent (unit-tested on Linux); [`compute`] returns `None` on other
//! platforms.

#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use pb_core::model::SigningInfo;

/// Authorities that mean "signed by Apple" (platform binaries, Apple-distributed App Store apps).
const APPLE_AUTHORITIES: &[&str] = &["Software Signing", "Apple Mac OS Application Signing"];

/// Parsed `codesign -dv --verbose=4` output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CodesignDetails {
    pub signed: bool,
    pub adhoc: bool,
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    pub authorities: Vec<String>,
}

pub(crate) fn parse_codesign_details(stderr: &str) -> CodesignDetails {
    let mut d = CodesignDetails::default();
    if stderr.contains("code object is not signed at all") {
        return d;
    }
    for line in stderr.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("Authority=") {
            d.authorities.push(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("TeamIdentifier=") {
            let v = v.trim();
            if !v.is_empty() && v != "not set" {
                d.team_id = Some(v.to_owned());
            }
        } else if let Some(v) = line.strip_prefix("Identifier=") {
            if !v.trim().is_empty() {
                d.identifier = Some(v.trim().to_owned());
            }
        } else if line == "Signature=adhoc" {
            d.adhoc = true;
        } else if line.starts_with("CodeDirectory ") {
            d.signed = true;
            if let Some(flags) = line
                .split_whitespace()
                .find_map(|w| w.strip_prefix("flags="))
            {
                if flags.split(['(', ')', ',']).any(|f| f == "adhoc") {
                    d.adhoc = true;
                }
            }
        }
    }
    if d.adhoc || !d.authorities.is_empty() || d.identifier.is_some() {
        d.signed = true;
    }
    d
}

/// Parses `spctl --assess -vv` stderr: `Some(true)` = notarized / Apple / App Store,
/// `Some(false)` = rejected, `None` = not applicable or unknown (e.g. "does not seem to be an app",
/// or accepted as legacy un-notarized Developer ID).
pub(crate) fn parse_spctl(stderr: &str) -> Option<bool> {
    let first = stderr.lines().next().unwrap_or("");
    let source = stderr
        .lines()
        .find_map(|l| l.trim().strip_prefix("source="))
        .map(str::trim)
        .unwrap_or("");
    if first.contains(": rejected") {
        if first.contains("does not seem to be an app") {
            return None;
        }
        return Some(false);
    }
    if first.contains(": accepted") {
        return match source {
            "Notarized Developer ID"
            | "Apple System"
            | "Mac App Store"
            | "Apple"
            | "Notarized Apple System" => Some(true),
            s if s.starts_with("Notarized") => Some(true),
            _ => None,
        };
    }
    None
}

/// Builds the public [`SigningInfo`].
pub(crate) fn to_signing_info(
    d: &CodesignDetails,
    valid: bool,
    notarized: Option<bool>,
) -> SigningInfo {
    SigningInfo {
        signed: d.signed,
        valid: d.signed && valid,
        adhoc: d.adhoc,
        team_id: d.team_id.clone(),
        identifier: d.identifier.clone(),
        authority: d.authorities.first().cloned(),
        notarized,
        apple: d.signed
            && !d.adhoc
            && d.authorities
                .iter()
                .any(|a| APPLE_AUTHORITIES.contains(&a.as_str())),
    }
}

/// Runs codesign / spctl on `path` (absolute). `check_notarization` should be true only for app
/// bundles and main executables (spctl's `execute` assessment is meaningless for libraries).
#[cfg(target_os = "macos")]
pub(crate) fn compute(path: &std::path::Path, check_notarization: bool) -> Option<SigningInfo> {
    use crate::proc;
    use std::process::Command;
    use std::time::Duration;
    const CODESIGN: &str = "/usr/bin/codesign";
    const SPCTL: &str = "/usr/sbin/spctl";
    let path = std::path::absolute(path).ok()?;
    let mut cmd = Command::new(CODESIGN);
    cmd.args(["-dv", "--verbose=4"]).arg(&path);
    let out = proc::run(cmd, None, Duration::from_secs(20), None, 256 * 1024).ok()?;
    if out.timed_out {
        return None;
    }
    let details = parse_codesign_details(&String::from_utf8_lossy(&out.stderr));
    if !details.signed {
        return Some(to_signing_info(&details, false, None));
    }
    let mut cmd = Command::new(CODESIGN);
    cmd.args(["--verify", "--strict"]).arg(&path);
    let valid = proc::run(cmd, None, Duration::from_secs(60), None, 64 * 1024)
        .map(|o| o.success())
        .unwrap_or(false);
    let notarized = if check_notarization && !details.adhoc {
        let mut cmd = Command::new(SPCTL);
        cmd.args(["--assess", "--type", "execute", "-vv"])
            .arg(&path);
        match proc::run(cmd, None, Duration::from_secs(30), None, 64 * 1024) {
            Ok(o) if !o.timed_out => parse_spctl(&String::from_utf8_lossy(&o.stderr)),
            _ => None,
        }
    } else {
        None
    };
    Some(to_signing_info(&details, valid, notarized))
}

/// Non-macOS stub: Apple code signing cannot be evaluated.
#[cfg(not(target_os = "macos"))]
pub(crate) fn compute(_path: &std::path::Path, _check_notarization: bool) -> Option<SigningInfo> {
    None
}

/// Small built-in list of trusted Apple Developer Team IDs (in addition to the bundle's
/// `allow/team_ids.txt`): vendors whose software is ubiquitous on a developer Mac.
pub(crate) const BUILTIN_TEAM_IDS: &[&str] = &[
    "EQHXZ8M8AV", // Google LLC
    "UBF8T346G9", // Microsoft Corporation
    "43AQ936H96", // Mozilla Corporation
    "VBG97UB4TA", // Objective-See, LLC
];

/// Is `s` a plausible Team ID (10 uppercase alphanumerics)?
pub(crate) fn is_team_id(s: &str) -> bool {
    s.len() == 10
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV_ID: &str = "Executable=/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
Identifier=com.google.Chrome
Format=app bundle with Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=1234 flags=0x12a00(kill,restrict,library-validation,runtime) hashes=28+7 location=embedded
Hash type=sha256 size=32
CDHash=0123456789abcdef
Signature size=8971
Authority=Developer ID Application: Google LLC (EQHXZ8M8AV)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Oct 20, 2026 at 10:00:00
Info.plist entries=40
TeamIdentifier=EQHXZ8M8AV
Runtime Version=14.0.0
Sealed Resources version=2 rules=13 files=100
Internal requirements count=1 size=164
";

    const ADHOC: &str = "Executable=/tmp/a.out
Identifier=a.out
Format=Mach-O thin (arm64)
CodeDirectory v=20400 size=500 flags=0x20002(adhoc,linker-signed) hashes=10+0 location=embedded
Signature=adhoc
Info.plist=not bound
TeamIdentifier=not set
Sealed Resources=none
Internal requirements=none
";

    const APPLE: &str = "Executable=/bin/ls
Identifier=com.apple.ls
Format=Mach-O universal (x86_64 arm64e)
CodeDirectory v=20400 size=800 flags=0x0(none) hashes=20+2 location=embedded
Platform identifier=15
Signature size=4442
Authority=Software Signing
Authority=Apple Code Signing Certification Authority
Authority=Apple Root CA
TeamIdentifier=not set
";

    #[test]
    fn parses_codesign() {
        let d = parse_codesign_details(DEV_ID);
        assert!(d.signed && !d.adhoc);
        assert_eq!(d.team_id.as_deref(), Some("EQHXZ8M8AV"));
        assert_eq!(d.identifier.as_deref(), Some("com.google.Chrome"));
        let s = to_signing_info(&d, true, Some(true));
        assert!(!s.apple && s.valid);
        assert_eq!(
            s.authority.as_deref(),
            Some("Developer ID Application: Google LLC (EQHXZ8M8AV)")
        );

        let d = parse_codesign_details(ADHOC);
        assert!(d.signed && d.adhoc && d.team_id.is_none());

        let d = parse_codesign_details(APPLE);
        let s = to_signing_info(&d, true, Some(true));
        assert!(s.apple && s.team_id.is_none());

        let d = parse_codesign_details("/tmp/x: code object is not signed at all\n");
        assert!(!d.signed);
        assert!(!to_signing_info(&d, true, None).valid);
    }

    #[test]
    fn parses_spctl() {
        assert_eq!(parse_spctl("/A.app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: X (ABCDE12345)\n"), Some(true));
        assert_eq!(
            parse_spctl("/bin/ls: accepted\nsource=Apple System\n"),
            Some(true)
        );
        assert_eq!(
            parse_spctl("/A.app: rejected\nsource=Unnotarized Developer ID\n"),
            Some(false)
        );
        assert_eq!(
            parse_spctl("/x.dylib: rejected (the code is valid but does not seem to be an app)\n"),
            None
        );
        assert_eq!(parse_spctl("/A.app: accepted\nsource=Developer ID\n"), None);
        assert_eq!(parse_spctl(""), None);
        assert!(is_team_id("EQHXZ8M8AV") && !is_team_id("eqhxz8m8av") && !is_team_id("SHORT"));
    }
}
