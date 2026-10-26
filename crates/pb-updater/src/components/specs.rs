//! Static description of every managed component. All release / asset / signing facts below were
//! checked on 2026-10-25 (sources cited per constant). Re-verify when a vendor changes its packaging.

use regex::Regex;
use std::sync::OnceLock;

/// Cisco (ClamAV) Apple Developer Team ID. Source: appcatalog.cloud/apps/clamav, code requirement
/// `anchor apple generic and certificate leaf[subject.OU] = DE8Y96K9QP` (bundle id `com.cisco.ClamAV`).
pub const CLAMAV_TEAM_ID: &str = "DE8Y96K9QP";
/// osquery Team ID. Source: desktopinsights.com/apps/osqueryd — "Developer ID Application: OSQUERY A Series
/// of LF Projects, LLC (3522FA9PXF)".
pub const OSQUERY_TEAM_ID: &str = "3522FA9PXF";
/// Objective-See, LLC Team ID. Source: `SIGNING_AUTH` = "Developer ID Application: Objective-See, LLC
/// (VBG97UB4TA)" in objective-see/LuLu `LuLu/Shared/consts.h`, BlockBlock `Shared/consts.h`,
/// OverSight `Shared/Consts.h` (master branches).
pub const OBJECTIVE_SEE_TEAM_ID: &str = "VBG97UB4TA";
/// dnscrypt-proxy release signing key (minisign). Source: github.com/DNSCrypt/dnscrypt-proxy wiki,
/// page "Installation", section "Verification of downloaded files"
/// (`minisign -Vm dnscrypt-proxy-*.tar.gz -P RWTk1x…jB5`).
pub const DNSCRYPT_MINISIGN_KEY: &str = "RWTk1xXqcTODeYttYMCMLo0YJHaFEHn7a3akqHlb/7QvIQXHVPxKbjB5";

/// Where the official ClamAV `.pkg` installs (docs.clamav.net "Installing" → macOS: "installs to
/// /usr/local/clamav").
pub const CLAMAV_PKG_CLAMSCAN: &str = "/usr/local/clamav/bin/clamscan";
/// Homebrew ClamAV (not managed by us when present alone).
pub const CLAMAV_BREW_CLAMSCAN: &str = "/opt/homebrew/bin/clamscan";
/// osquery `.pkg` layout (osquery.readthedocs.io "Installing on macOS": app bundle at
/// `/opt/osquery/lib/osquery.app`, `osqueryi` linked from `/usr/local/bin`).
pub const OSQUERYI: &str = "/usr/local/bin/osqueryi";
pub const OSQUERY_APP_PLIST: &str = "/opt/osquery/lib/osquery.app/Contents/Info.plist";
/// LuLu: the DMG contains `LuLu.app`, to be copied to /Applications and launched so the user approves
/// the system extension + network filter (objective-see.org/products/lulu.html).
pub const LULU_APP: &str = "/Applications/LuLu.app";
/// LuLu network extension bundle id (`EXT_BUNDLE_ID` in LuLu/Shared/consts.h).
pub const LULU_EXTENSION_ID: &str = "com.objective-see.lulu.extension";
/// BlockBlock launch daemon app (`INSTALL_DIRECTORY` + `LAUNCH_DAEMON` in BlockBlock/Shared/consts.h)
/// and its login-item helper (`/Applications/` + `APP_NAME`).
pub const BLOCKBLOCK_DAEMON_APP: &str = "/Library/Objective-See/BlockBlock/BlockBlock.app";
pub const BLOCKBLOCK_HELPER_APP: &str = "/Applications/BlockBlock Helper.app";
/// OverSight app (`APPS_FOLDER` + `APP_NAME` in OverSight/Shared/Consts.h).
pub const OVERSIGHT_APP: &str = "/Applications/OverSight.app";
/// Objective-See installers accept `-install` on the command line when run as root
/// (`CMD_INSTALL @"-install"`, handled in `Installer/Source/main.m` of BlockBlock and OverSight).
pub const OBJECTIVE_SEE_INSTALL_FLAG: &str = "-install";

/// Component kinds handled by the manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Kind {
    Clamav,
    Osquery,
    Dnscrypt,
    Lulu,
    BlockBlock,
    OverSight,
    Parabellum,
}

/// How a downloaded artifact is authenticated before installation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verify {
    /// Flat `.pkg` signed with a Developer ID Installer certificate of this Team ID + Gatekeeper (`spctl`).
    PkgTeamId(&'static str),
    /// `.app` signed (Developer ID Application) by this Team ID + notarized (`spctl --type execute`).
    AppTeamId(&'static str),
    /// Detached `.minisig` next to the asset, verified with the dnscrypt-proxy project key.
    MinisignDnscrypt,
    /// Detached `.minisig` verified with Parabellum's embedded key.
    MinisignEmbedded,
}

/// Static description of a component.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Spec {
    pub(crate) kind: Kind,
    pub(crate) name: &'static str,
    pub(crate) display_name: &'static str,
    /// `owner/repo` on GitHub (Parabellum uses `updates.app_releases_api` instead).
    pub(crate) repo: &'static str,
    pub(crate) required: bool,
    /// Installed automatically by `auto_update()` when missing.
    pub(crate) auto_install: bool,
    pub(crate) verify: Verify,
    /// Regex over asset names; capture group 1 = version. Asset name patterns checked on the release pages:
    /// ClamAV `clamav-1.5.4.macos.universal.pkg` (tag `clamav-1.5.4`), osquery `osquery-5.24.0.pkg` (tag
    /// `5.24.0`), dnscrypt-proxy `dnscrypt-proxy-macos_arm64-2.1.20.zip` + `.zip.minisig` (tag `2.1.20`;
    /// older releases used `.tar.gz`), LuLu `LuLu_4.5.3.dmg` (tag `v4.5.3`), BlockBlock `BlockBlock_2.5.2.zip`
    /// (tag `v2.5.2`), OverSight `OverSight_2.4.0.zip` (tag `v2.4.0`).
    pub(crate) asset_pattern: &'static str,
    /// Max download size of the asset.
    pub(crate) max_bytes: u64,
}

const MIB: u64 = 1024 * 1024;

pub(crate) const SPECS: [Spec; 7] = [
    Spec {
        kind: Kind::Clamav,
        name: "clamav",
        display_name: "ClamAV",
        repo: "Cisco-Talos/clamav",
        required: true,
        auto_install: true,
        verify: Verify::PkgTeamId(CLAMAV_TEAM_ID),
        asset_pattern: r"^clamav-(\d+(?:\.\d+)+)\.macos\.universal\.pkg$",
        max_bytes: 512 * MIB,
    },
    Spec {
        kind: Kind::Osquery,
        name: "osquery",
        display_name: "osquery",
        repo: "osquery/osquery",
        required: true,
        auto_install: true,
        verify: Verify::PkgTeamId(OSQUERY_TEAM_ID),
        asset_pattern: r"^osquery-(\d+(?:\.\d+)+)\.pkg$",
        max_bytes: 512 * MIB,
    },
    Spec {
        kind: Kind::Dnscrypt,
        name: "dnscrypt-proxy",
        display_name: "dnscrypt-proxy",
        repo: "DNSCrypt/dnscrypt-proxy",
        required: true,
        auto_install: true,
        verify: Verify::MinisignDnscrypt,
        asset_pattern: r"^dnscrypt-proxy-macos_arm64-(\d+(?:\.\d+)+)\.(?:zip|tar\.gz)$",
        max_bytes: 64 * MIB,
    },
    Spec {
        kind: Kind::Lulu,
        name: "lulu",
        display_name: "LuLu (pare-feu sortant)",
        repo: "objective-see/LuLu",
        required: false,
        auto_install: false,
        verify: Verify::AppTeamId(OBJECTIVE_SEE_TEAM_ID),
        asset_pattern: r"^LuLu_(\d+(?:\.\d+)+)\.dmg$",
        max_bytes: 256 * MIB,
    },
    Spec {
        kind: Kind::BlockBlock,
        name: "blockblock",
        display_name: "BlockBlock (persistance)",
        repo: "objective-see/BlockBlock",
        required: false,
        auto_install: false,
        verify: Verify::AppTeamId(OBJECTIVE_SEE_TEAM_ID),
        asset_pattern: r"^BlockBlock_(\d+(?:\.\d+)+)\.zip$",
        max_bytes: 256 * MIB,
    },
    Spec {
        kind: Kind::OverSight,
        name: "oversight",
        display_name: "OverSight (micro/caméra)",
        repo: "objective-see/OverSight",
        required: false,
        auto_install: false,
        verify: Verify::AppTeamId(OBJECTIVE_SEE_TEAM_ID),
        asset_pattern: r"^OverSight_(\d+(?:\.\d+)+)\.zip$",
        max_bytes: 256 * MIB,
    },
    Spec {
        kind: Kind::Parabellum,
        name: "parabellum",
        display_name: "Parabellum",
        repo: pb_core::GITHUB_REPO,
        required: true,
        auto_install: false,
        verify: Verify::MinisignEmbedded,
        asset_pattern: r"^Parabellum-(\d+\.\d+\.\d+)\.pkg$",
        max_bytes: 512 * MIB,
    },
];

impl Spec {
    pub(crate) fn by_name(name: &str) -> Option<&'static Spec> {
        SPECS.iter().find(|s| s.name == name)
    }

    fn regex(&self) -> Option<&'static Regex> {
        static CACHE: OnceLock<Vec<Option<Regex>>> = OnceLock::new();
        let all = CACHE.get_or_init(|| {
            SPECS
                .iter()
                .map(|s| Regex::new(s.asset_pattern).ok())
                .collect()
        });
        let idx = SPECS.iter().position(|s| s.name == self.name)?;
        all.get(idx)?.as_ref()
    }

    /// Version captured from an asset name, if it matches this component's pattern.
    pub(crate) fn asset_version(&self, asset_name: &str) -> Option<String> {
        self.regex()?
            .captures(asset_name)?
            .get(1)
            .map(|m| m.as_str().to_string())
    }

    /// Name of the detached minisign signature asset, when the component uses one.
    pub(crate) fn signature_asset(&self, asset_name: &str) -> Option<String> {
        match self.verify {
            Verify::MinisignDnscrypt | Verify::MinisignEmbedded => {
                Some(format!("{asset_name}.minisig"))
            }
            _ => None,
        }
    }

    /// Public release page (shown as `action_url`).
    pub(crate) fn release_page(&self) -> String {
        format!("https://github.com/{}/releases/latest", self.repo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_patterns_match_verified_names() {
        let v = |n: &str, a: &str| Spec::by_name(n).unwrap().asset_version(a);
        assert_eq!(
            v("clamav", "clamav-1.5.4.macos.universal.pkg").as_deref(),
            Some("1.5.4")
        );
        assert_eq!(v("clamav", "clamav-1.5.4.macos.universal.pkg.sig"), None);
        assert_eq!(v("clamav", "clamav-1.5.4.linux.x86_64.deb"), None);
        assert_eq!(
            v("osquery", "osquery-5.24.0.pkg").as_deref(),
            Some("5.24.0")
        );
        assert_eq!(v("osquery", "osquery-5.24.0_1.macos_arm64.tar.gz"), None);
        assert_eq!(
            v("dnscrypt-proxy", "dnscrypt-proxy-macos_arm64-2.1.20.zip").as_deref(),
            Some("2.1.20")
        );
        assert_eq!(
            v("dnscrypt-proxy", "dnscrypt-proxy-macos_arm64-2.1.5.tar.gz").as_deref(),
            Some("2.1.5")
        );
        assert_eq!(
            v("dnscrypt-proxy", "dnscrypt-proxy-macos_x86_64-2.1.20.zip"),
            None
        );
        assert_eq!(
            v(
                "dnscrypt-proxy",
                "dnscrypt-proxy-macos_arm64-2.1.20.zip.minisig"
            ),
            None
        );
        assert_eq!(v("lulu", "LuLu_4.5.3.dmg").as_deref(), Some("4.5.3"));
        assert_eq!(
            v("blockblock", "BlockBlock_2.5.2.zip").as_deref(),
            Some("2.5.2")
        );
        assert_eq!(
            v("oversight", "OverSight_2.4.0.zip").as_deref(),
            Some("2.4.0")
        );
        assert_eq!(
            v("parabellum", "Parabellum-0.2.0.pkg").as_deref(),
            Some("0.2.0")
        );
        let dns = Spec::by_name("dnscrypt-proxy").unwrap();
        assert_eq!(
            dns.signature_asset("dnscrypt-proxy-macos_arm64-2.1.20.zip")
                .as_deref(),
            Some("dnscrypt-proxy-macos_arm64-2.1.20.zip.minisig")
        );
        assert_eq!(
            Spec::by_name("lulu")
                .unwrap()
                .signature_asset("LuLu_4.5.3.dmg"),
            None
        );
    }
}
