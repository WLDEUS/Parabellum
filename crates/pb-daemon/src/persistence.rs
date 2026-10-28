//! Persistence items (LaunchAgents/Daemons, login & background items…): first-run baseline, enrichment
//! of new items (code signature + scan of the program), alerts, approval and removal.

use crate::actions::{self, ReportContext};
use crate::backends::ScanOpts;
use crate::ctx::Ctx;
use crate::store::{AlertKey, StatField};
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Ordered worker for persistence events.
pub async fn run_worker(
    ctx: Arc<Ctx>,
    mut rx: mpsc::Receiver<(PersistenceItem, PersistenceChangeKind)>,
) {
    while let Some((item, change)) = rx.recv().await {
        handle_event(&ctx, item, change).await;
    }
}

fn differs(old: &PersistenceItem, new: &PersistenceItem) -> bool {
    old.program != new.program
        || old.arguments != new.arguments
        || old.path != new.path
        || old.label != new.label
        || (new.program_sha256.is_some() && old.program_sha256 != new.program_sha256)
}

/// French label of a persistence kind.
pub fn kind_label(k: PersistenceKind) -> &'static str {
    match k {
        PersistenceKind::LaunchAgent => "LaunchAgent",
        PersistenceKind::LaunchDaemon => "LaunchDaemon",
        PersistenceKind::LoginItem => "Élément d'ouverture",
        PersistenceKind::BackgroundItem => "Élément en arrière-plan",
        PersistenceKind::Cron => "Tâche cron",
        PersistenceKind::Periodic => "Script periodic",
        PersistenceKind::ShellProfile => "Profil de shell",
        PersistenceKind::ConfigurationProfile => "Profil de configuration",
        PersistenceKind::BrowserExtension => "Extension de navigateur",
        PersistenceKind::SystemExtension => "Extension système",
        PersistenceKind::KernelExtension => "Extension du noyau",
        PersistenceKind::AuthorizationPlugin => "Plug-in d'autorisation",
        PersistenceKind::Other => "Persistance",
    }
}

/// Signed, valid, not ad-hoc, and Apple / trusted Team ID / notarized.
pub fn signer_trusted(ctx: &Ctx, s: &SigningInfo) -> bool {
    if !s.signed || !s.valid || s.adhoc {
        return false;
    }
    s.apple
        || s.notarized == Some(true)
        || s.team_id
            .as_deref()
            .map(|t| ctx.engine().is_trusted_team(t))
            .unwrap_or(false)
}

fn signer_desc(s: Option<&SigningInfo>) -> String {
    match s {
        None => "signature inconnue".into(),
        Some(s) if !s.signed => "non signé".into(),
        Some(s) if !s.valid => "signature invalide".into(),
        Some(s) if s.adhoc => "signature ad hoc".into(),
        Some(s) if s.apple => "signé par Apple".into(),
        Some(s) => match (&s.authority, &s.team_id) {
            (Some(a), _) => format!("signé : {a}"),
            (None, Some(t)) => format!("signé, Team ID {t}"),
            _ => "signé".into(),
        },
    }
}

/// Handle one persistence change from the watcher.
pub async fn handle_event(
    ctx: &Arc<Ctx>,
    mut item: PersistenceItem,
    change: PersistenceChangeKind,
) {
    let now = pb_core::now_ts();
    let id = item.id.clone();
    let existing = match ctx.store.run(move |s| s.get_persistence(&id)).await {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "persistence lookup failed");
            return;
        }
    };
    if change == PersistenceChangeKind::Removed {
        if let Some(mut e) = existing {
            if e.status != PersistenceStatus::Quarantined {
                e.status = PersistenceStatus::Removed;
            }
            e.last_seen = now;
            let _ = ctx.store.run(move |s| s.upsert_persistence(&e)).await;
        }
        return;
    }
    if existing.is_none() && crate::baseline::in_window(ctx, crate::baseline::Kind::Persistence) {
        item.status = PersistenceStatus::Baseline;
        item.first_seen = now;
        item.last_seen = now;
        let _ = ctx.store.run(move |s| s.upsert_persistence(&item)).await;
        return;
    }
    if let Some(e) = &existing {
        let gone = matches!(
            e.status,
            PersistenceStatus::Removed | PersistenceStatus::Quarantined
        );
        if !gone && !differs(e, &item) {
            let mut e = e.clone();
            e.last_seen = now;
            let _ = ctx.store.run(move |s| s.upsert_persistence(&e)).await;
            return;
        }
    }
    let modified = existing
        .as_ref()
        .map(|e| e.status != PersistenceStatus::Removed)
        .unwrap_or(false)
        && change == PersistenceChangeKind::Modified;
    enrich(ctx, &mut item).await;
    item.status = PersistenceStatus::New;
    item.first_seen = existing.as_ref().map(|e| e.first_seen).unwrap_or(now);
    item.last_seen = now;
    let stored = item.clone();
    if let Err(e) = ctx.store.run(move |s| s.upsert_persistence(&stored)).await {
        tracing::error!(error = %e, "cannot store persistence item");
        return;
    }
    ctx.bump_stat(StatField::PersistenceNew, 1).await;

    let trusted = item
        .signing
        .as_ref()
        .map(|s| signer_trusted(ctx, s))
        .unwrap_or(false);
    let bad_verdict = item
        .verdict
        .map(|v| v >= Verdict::Suspicious)
        .unwrap_or(false);
    let severity = if !trusted || bad_verdict {
        Severity::High
    } else {
        Severity::Low
    };
    let what = item.label.clone().unwrap_or_else(|| item.path.clone());
    let program = item
        .program
        .clone()
        .unwrap_or_else(|| "programme inconnu".into());
    let verdict_note = match item.verdict {
        Some(Verdict::Malicious) => " Le programme est détecté comme malveillant.",
        Some(Verdict::Suspicious) => " Le programme est jugé suspect.",
        _ => "",
    };
    let mut a = actions::alert(
        AlertKind::Persistence,
        severity,
        if modified {
            "Élément de persistance modifié"
        } else {
            "Nouvel élément de persistance"
        },
        format!(
            "{} « {what} » lance {program} ({}).{verdict_note}",
            kind_label(item.kind),
            signer_desc(item.signing.as_ref())
        ),
    );
    a.actions = vec![
        AlertAction::ApprovePersistence,
        AlertAction::RemovePersistence,
        AlertAction::Acknowledge,
    ];
    a.persistence_id = Some(item.id.clone());
    a.path = Some(item.path.clone());
    a.sha256 = item.program_sha256.clone();
    actions::raise_alert(ctx, a, None).await;
}

/// Code signature + scan of the program (scan results go through the normal verdict policy).
async fn enrich(ctx: &Arc<Ctx>, item: &mut PersistenceItem) {
    let Some(program) = item.program.clone().filter(|p| p.starts_with('/')) else {
        return;
    };
    let path = PathBuf::from(&program);
    if tokio::fs::symlink_metadata(&path).await.is_err() {
        return;
    }
    let engine = ctx.engine();
    let cfg = ctx.config();
    let p = path.clone();
    let res = tokio::task::spawn_blocking(move || {
        let signing = engine.signing_info(&p);
        let report = engine.scan_file(&p, &cfg, &ScanOpts::realtime(&cfg));
        (signing, report)
    })
    .await;
    let Ok((signing, report)) = res else { return };
    if signing.is_some() {
        item.signing = signing;
    }
    if report.sha256.is_some() {
        item.program_sha256 = report.sha256.clone();
    }
    if report.sha256.is_some() {
        let verdict = actions::process_report(ctx, report, &ReportContext::realtime(), &path).await;
        item.verdict = Some(verdict);
    }
}

/// Approve, or remove (unload + quarantine) a persistence item.
pub async fn set_status(
    ctx: &Arc<Ctx>,
    id: &str,
    status: PersistenceStatus,
) -> Result<PersistenceItem, IpcError> {
    let id2 = id.to_string();
    let mut item = ctx
        .store
        .run(move |s| s.get_persistence(&id2))
        .await?
        .ok_or_else(|| {
            IpcError::new(
                ErrorCode::NotFound,
                format!("élément de persistance {id} introuvable"),
            )
        })?;
    match status {
        PersistenceStatus::Approved => {
            item.status = PersistenceStatus::Approved;
        }
        PersistenceStatus::Removed | PersistenceStatus::Quarantined => {
            remove_item(ctx, &mut item).await?;
        }
        PersistenceStatus::Baseline | PersistenceStatus::New => {
            return Err(IpcError::new(
                ErrorCode::BadRequest,
                "statut attendu : approved ou removed/quarantined",
            ));
        }
    }
    let stored = item.clone();
    ctx.store
        .run(move |s| s.upsert_persistence(&stored))
        .await?;
    let pid = item.id.clone();
    let open = ctx
        .store
        .run(move |s| s.open_alerts_by(AlertKey::Persistence(&pid)))
        .await
        .unwrap_or_default();
    for mut a in open {
        a.status = AlertStatus::Resolved;
        a.actions.clear();
        let _ = actions::save_alert(ctx, &a).await;
    }
    Ok(item)
}

/// launchd domain target for `launchctl bootout`.
pub fn bootout_target(
    item: &PersistenceItem,
    plist_owner_uid: Option<u32>,
    console_uid: Option<u32>,
) -> Option<String> {
    let label = item
        .label
        .as_deref()
        .filter(|l| !l.is_empty() && !l.contains('/') && !l.contains(char::is_whitespace))?;
    match item.kind {
        PersistenceKind::LaunchDaemon => Some(format!("system/{label}")),
        PersistenceKind::LaunchAgent => {
            let uid = if item.path.starts_with("/Users/") {
                plist_owner_uid.filter(|u| *u != 0)
            } else {
                None
            }
            .or(console_uid)?;
            Some(format!("gui/{uid}/{label}"))
        }
        _ => None,
    }
}

/// Where a launch item lives: a user's own domain, or the system domain (root-owned `/Library/Launch*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Domain {
    User { uid: u32, home: PathBuf },
    System,
}

/// Locations a user can write to besides their home (programs of user items may live there).
pub fn user_writable_roots() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = ["/Users/Shared", "/private/tmp", "/private/var/folders"]
        .iter()
        .map(PathBuf::from)
        .collect();
    if !cfg!(target_os = "macos") {
        v.push(std::env::temp_dir());
    }
    v
}

/// Domain of a (canonical) plist path given its owner.
pub fn domain_of(plist: &Path, owner_uid: u32, owner_home: Option<&Path>) -> Option<Domain> {
    if owner_uid != 0 {
        let home = owner_home?;
        return plist.starts_with(home).then(|| Domain::User {
            uid: owner_uid,
            home: home.to_path_buf(),
        });
    }
    (plist.starts_with("/Library/LaunchAgents") || plist.starts_with("/Library/LaunchDaemons"))
        .then_some(Domain::System)
}

/// A user item may only take down a program that user owns, inside their home or a user-writable root.
pub fn user_program_allowed(program: &Path, program_owner: u32, uid: u32, home: &Path) -> bool {
    program_owner == uid
        && (program.starts_with(home)
            || user_writable_roots().iter().any(|r| program.starts_with(r)))
}

fn deny(msg: impl Into<String>) -> IpcError {
    IpcError::new(ErrorCode::PermissionDenied, msg)
}

async fn remove_item(ctx: &Arc<Ctx>, item: &mut PersistenceItem) -> Result<(), IpcError> {
    use std::os::unix::fs::MetadataExt;
    let launchd = matches!(
        item.kind,
        PersistenceKind::LaunchAgent | PersistenceKind::LaunchDaemon
    );
    if !launchd
        && !matches!(
            item.kind,
            PersistenceKind::LoginItem | PersistenceKind::BackgroundItem
        )
    {
        return Err(IpcError::new(
            ErrorCode::Unavailable,
            format!(
                "suppression automatique non prise en charge pour : {} (à retirer manuellement)",
                kind_label(item.kind)
            ),
        ));
    }
    let q = ctx.backends.quarantine.clone();
    // The plist goes through the same policy as every quarantine (allowed roots, no symlink in the path).
    let plist = q
        .check_path(Path::new(&item.path))
        .map_err(IpcError::from)?;
    let plist_md = std::fs::symlink_metadata(&plist).ok();
    let owner = plist_md.as_ref().map(|m| m.uid());
    let owner_home = owner
        .filter(|u| *u != 0)
        .and_then(crate::system::user_by_uid)
        .map(|(_, h)| h);
    let domain = match owner {
        Some(o) => domain_of(&plist, o, owner_home.as_deref()).ok_or_else(|| {
            deny("emplacement de l'élément incohérent avec son propriétaire : refusé")
        })?,
        // Plist already gone (login / background items): judge the program alone, as a user item of the console user.
        None => match crate::system::console_user() {
            Some(u) => Domain::User {
                uid: u.uid,
                home: u.home,
            },
            None => return Err(deny("aucun utilisateur connecté : refusé")),
        },
    };
    let detection = Detection {
        engine: DetectionEngine::Heuristic,
        name: format!(
            "Persistance retirée : {}",
            item.label.clone().unwrap_or_else(|| item.path.clone())
        ),
        severity: Severity::Medium,
        confidence: 1.0,
        details: None,
    };
    let mut quarantined_any = false;
    if launchd {
        let console = crate::system::console_user().map(|u| u.uid);
        if let Some(target) = bootout_target(item, owner, console) {
            if let Err(e) = crate::system::launchctl_bootout(&target).await {
                tracing::warn!(error = %e, "bootout failed (item may not be loaded)");
            }
        }
        if plist_md.map(|m| m.is_file()).unwrap_or(false) {
            actions::quarantine_path(
                ctx,
                &plist,
                None,
                std::slice::from_ref(&detection),
                "persistence",
            )
            .await?;
            quarantined_any = true;
        }
    }
    if let Some(program) = item.program.clone().filter(|p| p.starts_with('/')) {
        match program_to_quarantine(ctx, item, &domain, Path::new(&program)).await {
            Ok(Some((path, sha))) => {
                match actions::quarantine_path(
                    ctx,
                    &path,
                    Some(&sha),
                    std::slice::from_ref(&detection),
                    "persistence",
                )
                .await
                {
                    Ok(_) => quarantined_any = true,
                    Err(e) => {
                        tracing::warn!(program, error = %e.message, "cannot quarantine program")
                    }
                }
            }
            Ok(None) => {}
            Err(why) => tracing::warn!(program, why, "program left in place"),
        }
    }
    if !launchd && !quarantined_any {
        return Err(IpcError::new(
            ErrorCode::Unavailable,
            "rien à mettre en quarantaine pour cet élément",
        ));
    }
    item.status = if quarantined_any {
        PersistenceStatus::Quarantined
    } else {
        PersistenceStatus::Removed
    };
    Ok(())
}

/// Decide whether the program of a removed item may be quarantined. `Ok(Some((canonical path, sha256)))`.
async fn program_to_quarantine(
    ctx: &Arc<Ctx>,
    item: &PersistenceItem,
    domain: &Domain,
    program: &Path,
) -> Result<Option<(PathBuf, String)>, &'static str> {
    use std::os::unix::fs::MetadataExt;
    let Ok(canonical) = std::fs::canonicalize(program) else {
        return Ok(None);
    };
    let canonical = ctx
        .backends
        .quarantine
        .check_path(&canonical)
        .map_err(|_| "hors des emplacements autorisés")?;
    let md = std::fs::metadata(&canonical).map_err(|_| "illisible")?;
    if !md.is_file() {
        return Err("pas un fichier");
    }
    if let Domain::User { uid, home } = domain {
        if !user_program_allowed(&canonical, md.uid(), *uid, home) {
            return Err("programme hors du domaine de l'utilisateur");
        }
    }
    let engine = ctx.engine();
    let c2 = canonical.clone();
    let (signing, sha) = tokio::task::spawn_blocking(move || {
        (engine.signing_info(&c2), pb_engine::sha256_file(&c2).ok())
    })
    .await
    .map_err(|_| "tâche interrompue")?;
    if signing.map(|s| s.apple).unwrap_or(false)
        || item.signing.as_ref().map(|s| s.apple).unwrap_or(false)
    {
        return Err("binaire Apple");
    }
    let sha = sha.ok_or("empreinte impossible")?;
    match (&item.program_sha256, domain) {
        (Some(expected), _) if !expected.eq_ignore_ascii_case(&sha) => {
            Err("programme modifié depuis l'analyse")
        }
        (None, Domain::User { .. }) => Err("empreinte d'origine inconnue"),
        _ => Ok(Some((canonical, sha))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: PersistenceKind, path: &str, label: Option<&str>) -> PersistenceItem {
        PersistenceItem {
            id: "i".into(),
            kind,
            label: label.map(Into::into),
            path: path.into(),
            program: Some("/x".into()),
            arguments: vec![],
            user: None,
            signing: None,
            program_sha256: None,
            first_seen: 0,
            last_seen: 0,
            status: PersistenceStatus::New,
            verdict: None,
        }
    }

    #[test]
    fn bootout_targets() {
        let d = item(
            PersistenceKind::LaunchDaemon,
            "/Library/LaunchDaemons/a.plist",
            Some("com.a"),
        );
        assert_eq!(
            bootout_target(&d, Some(0), Some(501)).as_deref(),
            Some("system/com.a")
        );
        let a = item(
            PersistenceKind::LaunchAgent,
            "/Users/q/Library/LaunchAgents/b.plist",
            Some("com.b"),
        );
        assert_eq!(
            bootout_target(&a, Some(502), Some(501)).as_deref(),
            Some("gui/502/com.b")
        );
        let g = item(
            PersistenceKind::LaunchAgent,
            "/Library/LaunchAgents/c.plist",
            Some("com.c"),
        );
        assert_eq!(
            bootout_target(&g, Some(0), Some(501)).as_deref(),
            Some("gui/501/com.c")
        );
        assert_eq!(bootout_target(&g, Some(0), None), None);
        let bad = item(
            PersistenceKind::LaunchDaemon,
            "/Library/LaunchDaemons/x.plist",
            Some("../x"),
        );
        assert_eq!(bootout_target(&bad, None, None), None);
        let nolabel = item(
            PersistenceKind::LaunchDaemon,
            "/Library/LaunchDaemons/x.plist",
            None,
        );
        assert_eq!(bootout_target(&nolabel, None, None), None);
    }

    #[test]
    fn domains_and_user_programs() {
        let home = Path::new("/Users/q");
        assert_eq!(
            domain_of(
                Path::new("/Users/q/Library/LaunchAgents/a.plist"),
                501,
                Some(home)
            ),
            Some(Domain::User {
                uid: 501,
                home: home.to_path_buf()
            })
        );
        assert_eq!(
            domain_of(
                Path::new("/Users/x/Library/LaunchAgents/a.plist"),
                501,
                Some(home)
            ),
            None
        );
        assert_eq!(
            domain_of(Path::new("/Library/LaunchDaemons/a.plist"), 0, None),
            Some(Domain::System)
        );
        assert_eq!(
            domain_of(Path::new("/Users/q/Library/LaunchAgents/a.plist"), 0, None),
            None
        );
        assert!(user_program_allowed(
            Path::new("/Users/q/.local/bin/x"),
            501,
            501,
            home
        ));
        assert!(user_program_allowed(
            Path::new("/Users/Shared/x"),
            501,
            501,
            home
        ));
        assert!(!user_program_allowed(
            Path::new("/Users/q/.local/bin/x"),
            0,
            501,
            home
        ));
        assert!(!user_program_allowed(
            Path::new("/Applications/LuLu.app/Contents/MacOS/LuLu"),
            501,
            501,
            home
        ));
        assert!(!user_program_allowed(
            Path::new("/private/etc/sudoers"),
            501,
            501,
            home
        ));
    }

    #[test]
    fn change_detection() {
        let a = item(PersistenceKind::LaunchAgent, "/p", Some("l"));
        let mut b = a.clone();
        assert!(!differs(&a, &b));
        b.last_seen = 99;
        assert!(!differs(&a, &b));
        b.program = Some("/y".into());
        assert!(differs(&a, &b));
        let mut c = a.clone();
        c.program_sha256 = Some("ff".into());
        assert!(differs(&a, &c));
    }

    #[test]
    fn signer_descriptions() {
        assert_eq!(signer_desc(None), "signature inconnue");
        let s = SigningInfo {
            signed: true,
            valid: true,
            adhoc: true,
            ..Default::default()
        };
        assert_eq!(signer_desc(Some(&s)), "signature ad hoc");
        let s = SigningInfo {
            signed: true,
            valid: true,
            team_id: Some("T".into()),
            ..Default::default()
        };
        assert_eq!(signer_desc(Some(&s)), "signé, Team ID T");
    }
}
