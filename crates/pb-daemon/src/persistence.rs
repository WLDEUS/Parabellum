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
        let verdict = actions::process_report(ctx, report, &ReportContext::realtime()).await;
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

async fn remove_item(ctx: &Arc<Ctx>, item: &mut PersistenceItem) -> Result<(), IpcError> {
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
    let plist = PathBuf::from(&item.path);
    if crate::system::is_protected_system_path(&plist) {
        return Err(IpcError::new(
            ErrorCode::PermissionDenied,
            "élément système protégé",
        ));
    }
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
        use std::os::unix::fs::MetadataExt;
        let owner = std::fs::symlink_metadata(&plist).ok().map(|m| m.uid());
        let console = crate::system::console_user().map(|u| u.uid);
        if let Some(target) = bootout_target(item, owner, console) {
            if let Err(e) = crate::system::launchctl_bootout(&target).await {
                tracing::warn!(error = %e, "bootout failed (item may not be loaded)");
            }
        }
        if is_regular_file(&plist) {
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
        let p = PathBuf::from(&program);
        let apple = item.signing.as_ref().map(|s| s.apple).unwrap_or(false) || {
            let engine = ctx.engine();
            let p2 = p.clone();
            tokio::task::spawn_blocking(move || engine.signing_info(&p2))
                .await
                .ok()
                .flatten()
                .map(|s| s.apple)
                .unwrap_or(false)
        };
        if apple || crate::system::is_protected_system_path(&p) {
            tracing::info!(program, "program is a system/Apple binary, left in place");
        } else if is_regular_file(&p) {
            match actions::quarantine_path(
                ctx,
                &p,
                item.program_sha256.as_deref(),
                std::slice::from_ref(&detection),
                "persistence",
            )
            .await
            {
                Ok(_) => quarantined_any = true,
                Err(e) => tracing::warn!(program, error = %e.message, "cannot quarantine program"),
            }
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

fn is_regular_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p)
        .map(|m| m.is_file())
        .unwrap_or(false)
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
