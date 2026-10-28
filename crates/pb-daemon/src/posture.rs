//! macOS security posture: SIP, Gatekeeper, FileVault, application firewall, automatic security updates,
//! XProtect, guest account, remote login, screen sharing. Checked daily (and on demand through the
//! `posture` command) as root with absolute tool paths and timeouts. Each failing check of severity
//! medium or more raises one deduplicated `system` alert; the alert is resolved once the setting is fixed.
//!
//! The parsers are pure (unit-tested with real output samples); only [`collect`] touches the system.

use crate::actions;
use crate::ctx::Ctx;
use crate::store::AlertKey;
use pb_core::ipc::IpcError;
use pb_core::model::*;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Timeout of each system tool.
pub const CMD_TIMEOUT: Duration = Duration::from_secs(15);
/// `posture` with `refresh` re-runs the checks at most this often.
pub const MIN_REFRESH_SECS: i64 = 30;
/// First daily check after startup.
pub const STARTUP_DELAY: Duration = Duration::from_secs(600);
/// Alert dedupe key prefix (stored in the `detection` column).
pub const ALERT_KEY_PREFIX: &str = "posture:";

pub const CSRUTIL: &str = "/usr/bin/csrutil";
pub const SPCTL: &str = "/usr/sbin/spctl";
pub const FDESETUP: &str = "/usr/bin/fdesetup";
pub const SOCKETFILTERFW: &str = "/usr/libexec/ApplicationFirewall/socketfilterfw";
pub const DEFAULTS: &str = "/usr/bin/defaults";
pub const PLUTIL: &str = "/usr/bin/plutil";
pub const LAUNCHCTL: &str = "/bin/launchctl";
pub const SOFTWARE_UPDATE_PREFS: &str = "/Library/Preferences/com.apple.SoftwareUpdate";
pub const LOGINWINDOW_PREFS: &str = "/Library/Preferences/com.apple.loginwindow";
/// XProtect signature bundles (macOS 15 moved the live copy under /private/var/protected).
pub const XPROTECT_PLISTS: [&str; 2] = [
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist",
    "/private/var/protected/xprotect/XProtect.bundle/Contents/Info.plist",
];
pub const XPROTECT_REMEDIATOR: &str = "/Library/Apple/System/Library/CoreServices/XProtect.app";

/// Tri-state result of a parser: `None` = output not understood.
pub type Parsed = Option<bool>;

/// `csrutil status`: "System Integrity Protection status: enabled." A custom configuration (some
/// protections off) or "disabled" is not safe.
pub fn parse_csrutil(out: &str) -> Parsed {
    let l = out.to_ascii_lowercase();
    if !l.contains("system integrity protection status") {
        return None;
    }
    if l.contains("custom configuration") || l.contains("status: disabled") {
        Some(false)
    } else if l.contains("status: enabled") {
        Some(true)
    } else {
        None
    }
}

/// `spctl --status`: "assessments enabled" / "assessments disabled".
pub fn parse_spctl(out: &str) -> Parsed {
    let l = out.to_ascii_lowercase();
    if l.contains("assessments enabled") {
        Some(true)
    } else if l.contains("assessments disabled") {
        Some(false)
    } else {
        None
    }
}

/// `fdesetup status`: "FileVault is On." / "FileVault is Off." / "Encryption in progress: …" (ok:
/// it will be on) / "Decryption in progress: …" (not ok).
pub fn parse_fdesetup(out: &str) -> Parsed {
    let l = out.to_ascii_lowercase();
    if l.contains("decryption in progress") || l.contains("filevault is off") {
        Some(false)
    } else if l.contains("filevault is on") || l.contains("encryption in progress") {
        Some(true)
    } else {
        None
    }
}

/// `socketfilterfw --getglobalstate`: "Firewall is enabled. (State = 1)", "(State = 2)" = block all,
/// "Firewall is disabled. (State = 0)".
pub fn parse_firewall(out: &str) -> Parsed {
    if out.contains("(State = 1)") || out.contains("(State = 2)") {
        return Some(true);
    }
    if out.contains("(State = 0)") {
        return Some(false);
    }
    let l = out.to_ascii_lowercase();
    if l.contains("firewall is disabled") {
        Some(false)
    } else if l.contains("firewall is enabled") || l.contains("blocking all") {
        Some(true)
    } else {
        None
    }
}

/// Integer keys of a `defaults read <domain>` dump (old-style plist: `    Key = 1;`).
pub fn parse_defaults_ints(out: &str) -> BTreeMap<String, i64> {
    let mut m = BTreeMap::new();
    for line in out.lines() {
        let Some((k, v)) = line.split_once(" = ") else {
            continue;
        };
        let key = k.trim().trim_matches('"');
        let val = v.trim().trim_end_matches(';').trim().trim_matches('"');
        if key.is_empty() || key.contains(char::is_whitespace) {
            continue;
        }
        if let Ok(n) = val.parse::<i64>() {
            m.insert(key.to_string(), n);
        }
    }
    m
}

/// State of a launchd service in `launchctl print-disabled system`. `Some(true)` = the service is
/// enabled (macOS 11+: `"label" => enabled`; older: `"label" => false`), `Some(false)` = disabled,
/// `None` = not listed (the plist default applies: off for sshd and screen sharing).
pub fn parse_launchd_enabled(out: &str, label: &str) -> Option<bool> {
    let needle = format!("\"{label}\" =>");
    let line = out.lines().find(|l| l.trim_start().starts_with(&needle))?;
    let state = line.split("=>").nth(1)?.trim().to_ascii_lowercase();
    match state.as_str() {
        "enabled" | "false" => Some(true),
        "disabled" | "true" => Some(false),
        _ => None,
    }
}

/// Raw outputs gathered from the system (`None` = the tool failed / timed out / file absent).
#[derive(Debug, Clone, Default)]
pub struct RawPosture {
    pub csrutil: Option<String>,
    pub spctl: Option<String>,
    pub fdesetup: Option<String>,
    pub firewall: Option<String>,
    pub software_update: Option<String>,
    /// Highest XProtect version found (`CFBundleShortVersionString`).
    pub xprotect_version: Option<String>,
    pub xprotect_remediator: bool,
    pub loginwindow: Option<String>,
    pub launchd_disabled: Option<String>,
}

fn check(
    id: &str,
    title: &str,
    state: Parsed,
    severity: Severity,
    ok_detail: &str,
    bad_detail: &str,
    fix: &str,
) -> PostureCheck {
    match state {
        Some(true) => PostureCheck {
            id: id.into(),
            title: title.into(),
            ok: true,
            severity,
            detail: ok_detail.into(),
            fix: String::new(),
        },
        Some(false) => PostureCheck {
            id: id.into(),
            title: title.into(),
            ok: false,
            severity,
            detail: bad_detail.into(),
            fix: fix.into(),
        },
        None => unknown(id, title),
    }
}

fn unknown(id: &str, title: &str) -> PostureCheck {
    PostureCheck {
        id: id.into(),
        title: title.into(),
        ok: false,
        severity: Severity::Info,
        detail: "Vérification impossible (outil absent, délai dépassé ou sortie inattendue)".into(),
        fix: String::new(),
    }
}

/// Turn raw outputs into the check list (pure).
pub fn evaluate(raw: &RawPosture) -> Vec<PostureCheck> {
    let mut v = Vec::with_capacity(10);
    v.push(check(
        "sip",
        "Protection de l'intégrité du système (SIP)",
        raw.csrutil.as_deref().and_then(parse_csrutil),
        Severity::High,
        "SIP activée",
        "SIP désactivée ou partiellement désactivée : les fichiers système ne sont plus protégés",
        "Redémarrer en mode de récupération (maintenir le bouton d'alimentation), ouvrir Utilitaires > Terminal, \
         lancer « csrutil enable » puis redémarrer",
    ));
    v.push(check(
        "gatekeeper",
        "Gatekeeper",
        raw.spctl.as_deref().and_then(parse_spctl),
        Severity::High,
        "Gatekeeper actif : les apps non signées ou non notarisées sont bloquées",
        "Gatekeeper désactivé : n'importe quelle app téléchargée peut s'exécuter",
        "Réglages Système > Confidentialité et sécurité > Sécurité : autoriser les applications de l'App Store \
         et des développeurs identifiés (ou « sudo spctl --global-enable »)",
    ));
    v.push(check(
        "filevault",
        "FileVault (chiffrement du disque)",
        raw.fdesetup.as_deref().and_then(parse_fdesetup),
        Severity::Medium,
        "FileVault activé",
        "FileVault désactivé : en cas de vol, le contenu du disque est lisible",
        "Réglages Système > Confidentialité et sécurité > FileVault : Activer",
    ));
    v.push(check(
        "firewall",
        "Coupe-feu de l'application",
        raw.firewall.as_deref().and_then(parse_firewall),
        Severity::Medium,
        "Coupe-feu activé",
        "Coupe-feu désactivé : les connexions entrantes vers les services ouverts sont acceptées",
        "Réglages Système > Réseau > Coupe-feu : activer",
    ));
    let su = raw.software_update.as_deref().map(parse_defaults_ints);
    // Keys absent = macOS defaults (security responses and system data files are installed automatically).
    let security_updates = su.as_ref().map(|m| {
        m.get("CriticalUpdateInstall").copied().unwrap_or(1) != 0
            && m.get("ConfigDataInstall").copied().unwrap_or(1) != 0
    });
    v.push(check(
        "security_updates",
        "Réponses de sécurité et fichiers système",
        security_updates,
        Severity::Medium,
        "Installation automatique des correctifs de sécurité et des données XProtect activée",
        "Les correctifs de sécurité rapides ou les données XProtect ne s'installent pas automatiquement",
        "Réglages Système > Général > Mise à jour de logiciels > Mises à jour automatiques (i) : activer \
         « Installer les réponses de sécurité et les fichiers système »",
    ));
    let macos_updates = su.as_ref().map(|m| {
        m.get("AutomaticallyInstallMacOSUpdates")
            .copied()
            .unwrap_or(0)
            != 0
    });
    v.push(check(
        "macos_updates",
        "Mises à jour de macOS automatiques",
        macos_updates,
        Severity::Low,
        "Les mises à jour de macOS s'installent automatiquement",
        "Les mises à jour de macOS ne s'installent pas automatiquement",
        "Réglages Système > Général > Mise à jour de logiciels > Mises à jour automatiques (i) : activer \
         « Installer les mises à jour de macOS »",
    ));
    let xprotect = PostureCheck {
        id: "xprotect".into(),
        title: "XProtect (antivirus intégré d'Apple)".into(),
        ok: raw.xprotect_version.is_some() && raw.xprotect_remediator,
        severity: Severity::Medium,
        detail: match (&raw.xprotect_version, raw.xprotect_remediator) {
            (Some(ver), true) => format!("XProtect {ver} et XProtect Remediator présents"),
            (Some(ver), false) => format!("XProtect {ver} présent, XProtect Remediator absent"),
            (None, _) => "Signatures XProtect introuvables".into(),
        },
        fix: if raw.xprotect_version.is_some() && raw.xprotect_remediator {
            String::new()
        } else {
            "Activer « Installer les réponses de sécurité et les fichiers système » puis lancer \
             « sudo softwareupdate --background-critical » (ou installer la dernière mise à jour de macOS)"
                .into()
        },
    };
    v.push(xprotect);
    let guest = raw.loginwindow.as_deref().map(|o| {
        parse_defaults_ints(o)
            .get("GuestEnabled")
            .copied()
            .unwrap_or(0)
            == 0
    });
    v.push(check(
        "guest_account",
        "Compte invité",
        guest,
        Severity::Medium,
        "Compte invité désactivé",
        "Compte invité activé : n'importe qui peut ouvrir une session sur ce Mac",
        "Réglages Système > Utilisateurs et groupes > Utilisateur invité : désactiver",
    ));
    let disabled = raw.launchd_disabled.as_deref();
    let remote = disabled.map(|o| parse_launchd_enabled(o, "com.openssh.sshd") != Some(true));
    v.push(check(
        "remote_login",
        "Session à distance (SSH)",
        remote,
        Severity::Medium,
        "Session à distance désactivée",
        "Session à distance (SSH) activée : ce Mac accepte des connexions SSH",
        "Réglages Système > Général > Partage : désactiver « Session à distance » si tu ne t'en sers pas",
    ));
    let screen =
        disabled.map(|o| parse_launchd_enabled(o, "com.apple.screensharing") != Some(true));
    v.push(check(
        "screen_sharing",
        "Partage d'écran",
        screen,
        Severity::Medium,
        "Partage d'écran désactivé",
        "Partage d'écran activé : ce Mac peut être contrôlé à distance",
        "Réglages Système > Général > Partage : désactiver « Partage d'écran » (et « Gestion à distance »)",
    ));
    v
}

/// Run every system tool (macOS only; elsewhere every check is "unknown").
pub async fn collect() -> RawPosture {
    #[cfg(target_os = "macos")]
    {
        use crate::system::run_command;
        async fn out(program: &str, args: &[&str]) -> Option<String> {
            match run_command(program, args, CMD_TIMEOUT).await {
                Ok(o) => Some(format!("{}\n{}", o.stdout, o.stderr)),
                Err(e) => {
                    tracing::debug!(program, error = %e, "posture check failed");
                    None
                }
            }
        }
        async fn plist_version(path: &str) -> Option<String> {
            let o = run_command(
                PLUTIL,
                &[
                    "-extract",
                    "CFBundleShortVersionString",
                    "raw",
                    "-o",
                    "-",
                    path,
                ],
                CMD_TIMEOUT,
            )
            .await
            .ok()?;
            let v = o.stdout.trim().to_string();
            (o.success() && !v.is_empty() && v.len() < 64).then_some(v)
        }
        let (csrutil, spctl, fdesetup, firewall, software_update, loginwindow, launchd_disabled) = tokio::join!(
            out(CSRUTIL, &["status"]),
            out(SPCTL, &["--status"]),
            out(FDESETUP, &["status"]),
            out(SOCKETFILTERFW, &["--getglobalstate"]),
            // A missing domain/key exits non-zero: keep the (empty) output, absent keys mean defaults.
            out(DEFAULTS, &["read", SOFTWARE_UPDATE_PREFS]),
            out(DEFAULTS, &["read", LOGINWINDOW_PREFS]),
            out(LAUNCHCTL, &["print-disabled", "system"]),
        );
        let mut xprotect_version: Option<String> = None;
        for p in XPROTECT_PLISTS {
            if let Some(v) = plist_version(p).await {
                let newer = match &xprotect_version {
                    Some(cur) => version_key(&v) > version_key(cur),
                    None => true,
                };
                if newer {
                    xprotect_version = Some(v);
                }
            }
        }
        RawPosture {
            csrutil,
            spctl,
            fdesetup,
            firewall,
            software_update,
            xprotect_version,
            xprotect_remediator: std::path::Path::new(XPROTECT_REMEDIATOR).is_dir(),
            loginwindow,
            launchd_disabled,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        RawPosture::default()
    }
}

/// Numeric sort key of a dotted version ("5321", "2.0.1").
pub fn version_key(v: &str) -> Vec<u64> {
    v.split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

static CACHE: Mutex<Option<(i64, Vec<PostureCheck>)>> = Mutex::new(None);

fn cached() -> Option<(i64, Vec<PostureCheck>)> {
    CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// `posture` command: last results, or a fresh run when asked (rate-limited) or when none exist.
pub async fn get(ctx: &Arc<Ctx>, refresh: bool) -> Result<Vec<PostureCheck>, IpcError> {
    let now = pb_core::now_ts();
    if let Some((at, list)) = cached() {
        if !refresh || now - at < MIN_REFRESH_SECS {
            return Ok(list);
        }
    }
    Ok(run_and_alert(ctx).await)
}

/// Run all checks, cache them, raise / resolve alerts.
pub async fn run_and_alert(ctx: &Arc<Ctx>) -> Vec<PostureCheck> {
    let list = evaluate(&collect().await);
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((pb_core::now_ts(), list.clone()));
    if cfg!(target_os = "macos") {
        sync_alerts(ctx, &list).await;
    }
    list
}

/// Alert to raise for a failing check (None below medium or when unknown).
pub fn alert_for(c: &PostureCheck) -> Option<Alert> {
    if c.ok || c.severity < Severity::Medium {
        return None;
    }
    let mut message = c.detail.clone();
    if !c.fix.is_empty() {
        message.push_str(".\nCorrection : ");
        message.push_str(&c.fix);
    }
    Some(actions::alert(
        AlertKind::System,
        c.severity,
        format!("Sécurité macOS : {}", c.title),
        message,
    ))
}

async fn sync_alerts(ctx: &Arc<Ctx>, list: &[PostureCheck]) {
    for c in list {
        if c.severity == Severity::Info {
            continue; // could not check: keep whatever alert exists
        }
        let key = format!("{ALERT_KEY_PREFIX}{}", c.id);
        let k2 = key.clone();
        let open = ctx
            .store
            .run(move |s| s.open_alerts_by(AlertKey::Title(&k2)))
            .await
            .unwrap_or_default();
        if c.ok {
            for mut a in open {
                a.status = AlertStatus::Resolved;
                if let Err(e) = actions::save_alert(ctx, &a).await {
                    tracing::warn!(error = %e.message, "cannot resolve posture alert");
                }
            }
        } else if open.is_empty() {
            if let Some(a) = alert_for(c) {
                actions::raise_alert(ctx, a, Some(key)).await;
            }
        }
    }
}

/// Daily check (10 min after startup, then every 24 h), when `security.posture_checks` is on.
pub async fn daily_loop(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    let mut wait = STARTUP_DELAY;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => if *shutdown.borrow() { return; },
        }
        if ctx.config().security.posture_checks {
            let list = run_and_alert(&ctx).await;
            let failing = list
                .iter()
                .filter(|c| !c.ok && c.severity >= Severity::Medium)
                .count();
            tracing::info!(checks = list.len(), failing, "security posture checked");
        }
        wait = Duration::from_secs(86_400 + crate::scheduler::jitter(1800) as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip() {
        assert_eq!(
            parse_csrutil("System Integrity Protection status: enabled.\n"),
            Some(true)
        );
        assert_eq!(
            parse_csrutil("System Integrity Protection status: disabled.\n"),
            Some(false)
        );
        let custom = "System Integrity Protection status: unknown (Custom Configuration).\n\n\
                      Configuration:\n\tApple Internal: disabled\n\tKext Signing: disabled\n";
        assert_eq!(parse_csrutil(custom), Some(false));
        assert_eq!(parse_csrutil("csrutil: command not found"), None);
    }

    #[test]
    fn gatekeeper_filevault_firewall() {
        assert_eq!(parse_spctl("assessments enabled\n"), Some(true));
        assert_eq!(parse_spctl("assessments disabled\n"), Some(false));
        assert_eq!(parse_spctl(""), None);
        assert_eq!(parse_fdesetup("FileVault is On.\n"), Some(true));
        assert_eq!(parse_fdesetup("FileVault is Off.\n"), Some(false));
        assert_eq!(
            parse_fdesetup("FileVault is On.\nEncryption in progress: Percent completed = 34.5\n"),
            Some(true)
        );
        assert_eq!(
            parse_fdesetup("FileVault is On.\nDecryption in progress: Percent completed = 10\n"),
            Some(false)
        );
        assert_eq!(
            parse_firewall("Firewall is enabled. (State = 1)\n"),
            Some(true)
        );
        assert_eq!(
            parse_firewall(
                "Firewall is blocking all non-essential incoming connections. (State = 2)"
            ),
            Some(true)
        );
        assert_eq!(
            parse_firewall("Firewall is disabled. (State = 0)\n"),
            Some(false)
        );
        assert_eq!(parse_firewall("weird"), None);
    }

    #[test]
    fn defaults_and_launchd() {
        let su = "{\n    AutomaticCheckEnabled = 1;\n    AutomaticDownload = 1;\n    \
                  AutomaticallyInstallMacOSUpdates = 0;\n    ConfigDataInstall = 1;\n    \
                  CriticalUpdateInstall = 1;\n    LastFullSuccessfulDate = \"2026-10-27 08:00:00 +0000\";\n}\n";
        let m = parse_defaults_ints(su);
        assert_eq!(m.get("CriticalUpdateInstall"), Some(&1));
        assert_eq!(m.get("AutomaticallyInstallMacOSUpdates"), Some(&0));
        assert!(!m.contains_key("LastFullSuccessfulDate"));
        let ld = "disabled services = {\n\t\"com.apple.screensharing\" => disabled\n\t\
                  \"com.openssh.sshd\" => enabled\n\t\"com.apple.ftp-proxy\" => true\n}\n";
        assert_eq!(parse_launchd_enabled(ld, "com.openssh.sshd"), Some(true));
        assert_eq!(
            parse_launchd_enabled(ld, "com.apple.screensharing"),
            Some(false)
        );
        assert_eq!(
            parse_launchd_enabled(ld, "com.apple.ftp-proxy"),
            Some(false)
        );
        assert_eq!(parse_launchd_enabled(ld, "com.example.none"), None);
        // Catalina format: false = not disabled = running.
        let old = "\t\"com.openssh.sshd\" => false\n";
        assert_eq!(parse_launchd_enabled(old, "com.openssh.sshd"), Some(true));
    }

    fn healthy() -> RawPosture {
        RawPosture {
            csrutil: Some("System Integrity Protection status: enabled.".into()),
            spctl: Some("assessments enabled".into()),
            fdesetup: Some("FileVault is On.".into()),
            firewall: Some("Firewall is enabled. (State = 1)".into()),
            software_update: Some(
                "{\n    AutomaticallyInstallMacOSUpdates = 1;\n    CriticalUpdateInstall = 1;\n}"
                    .into(),
            ),
            xprotect_version: Some("5321".into()),
            xprotect_remediator: true,
            loginwindow: Some("{\n    GuestEnabled = 0;\n}".into()),
            launchd_disabled: Some("\t\"com.openssh.sshd\" => disabled\n".into()),
        }
    }

    #[test]
    fn evaluate_healthy_and_failures() {
        let list = evaluate(&healthy());
        assert_eq!(list.len(), 10);
        assert!(list.iter().all(|c| c.ok), "{list:#?}");
        assert!(list.iter().all(|c| alert_for(c).is_none()));

        let mut raw = healthy();
        raw.csrutil = Some("System Integrity Protection status: disabled.".into());
        raw.firewall = Some("Firewall is disabled. (State = 0)".into());
        raw.software_update = Some("{\n    CriticalUpdateInstall = 0;\n}".into());
        raw.loginwindow = Some("{\n    GuestEnabled = 1;\n}".into());
        raw.launchd_disabled = Some("\t\"com.apple.screensharing\" => enabled\n".into());
        raw.fdesetup = None;
        let list = evaluate(&raw);
        let by = |id: &str| list.iter().find(|c| c.id == id).unwrap().clone();
        let sip = by("sip");
        assert!(!sip.ok && sip.severity == Severity::High && sip.fix.contains("csrutil enable"));
        let a = alert_for(&sip).unwrap();
        assert_eq!(a.kind, AlertKind::System);
        assert_eq!(a.severity, Severity::High);
        assert!(a.message.contains("Correction"));
        assert!(!by("firewall").ok);
        assert!(by("firewall").fix.starts_with("Réglages Système"));
        assert!(!by("security_updates").ok);
        assert!(!by("macos_updates").ok);
        assert!(
            alert_for(&by("macos_updates")).is_none(),
            "low: dashboard only"
        );
        assert!(!by("guest_account").ok);
        assert!(!by("screen_sharing").ok);
        assert!(by("remote_login").ok, "sshd not listed = default off");
        let fv = by("filevault");
        assert_eq!(fv.severity, Severity::Info);
        assert!(alert_for(&fv).is_none(), "unknown state: no alert");
        assert!(by("xprotect").ok && by("xprotect").fix.is_empty());
    }

    #[test]
    fn xprotect_versions() {
        assert!(version_key("5321") > version_key("5300"));
        assert!(version_key("2.10") > version_key("2.9"));
        let mut raw = healthy();
        raw.xprotect_remediator = false;
        let x = evaluate(&raw)
            .into_iter()
            .find(|c| c.id == "xprotect")
            .unwrap();
        assert!(!x.ok && x.detail.contains("Remediator"));
    }
}
