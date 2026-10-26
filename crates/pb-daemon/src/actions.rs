//! What happens after a verdict: local allow/block lists, auto-quarantine, alerts (deduplicated),
//! optional VirusTotal follow-up, and the user's answers to alerts (quarantine / restore / allow / FP).
//! Files are never deleted here.

use crate::backends::ScanEngine;
use crate::ctx::Ctx;
use crate::store::{StatField, StoreError};
use pb_core::ipc::{DaemonEvent, ErrorCode, IpcError};
use pb_core::model::*;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

/// Alerts with the same sha256 + path + kind within this window are merged.
pub const DEDUPE_WINDOW: i64 = 86_400;
/// VirusTotal engines needed to upgrade a file to `malicious`.
pub const VT_MALICIOUS_THRESHOLD: u32 = 5;

impl From<StoreError> for IpcError {
    fn from(e: StoreError) -> Self {
        IpcError::new(ErrorCode::Internal, format!("base locale : {e}"))
    }
}

/// Process information when the report comes from an `exec` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecInfo {
    pub pid: i32,
    pub killed: bool,
}

/// Where a report comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportContext {
    pub origin: ScanOrigin,
    pub job_id: Option<String>,
    pub exec: Option<ExecInfo>,
}

impl ReportContext {
    pub fn realtime() -> Self {
        Self {
            origin: ScanOrigin::Realtime,
            job_id: None,
            exec: None,
        }
    }
}

/// The report holds a detection strong enough to act on automatically: the engine's signature-grade rule
/// (hash DB, ClamAV non-PUA, YARA/heuristic high+ from an untrusted signer — never ML), or a hash the daemon
/// put in its local blocklist after VirusTotal confirmation.
pub fn signature_grade(engine: &dyn ScanEngine, r: &ScanReport) -> bool {
    r.detections.iter().any(|d| {
        d.engine == DetectionEngine::VirusTotal || engine.is_signature_grade(d, r.signing.as_ref())
    })
}

/// Push the local allowlist (store) into the engine.
pub async fn sync_allowlist(ctx: &Arc<Ctx>) {
    match ctx.store.run(|s| s.allowlist_all()).await {
        Ok(list) => {
            let engine = ctx.engine();
            let _ = tokio::task::spawn_blocking(move || engine.set_local_allowlist(&list)).await;
        }
        Err(e) => tracing::warn!(error = %e, "cannot read local allowlist"),
    }
}

/// Highest-severity (then most confident) detection.
pub fn primary_detection(r: &ScanReport) -> Option<&Detection> {
    r.detections.iter().max_by(|a, b| {
        a.severity.cmp(&b.severity).then(
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    })
}

/// French label of an engine.
pub fn engine_label(e: DetectionEngine) -> &'static str {
    match e {
        DetectionEngine::HashDb => "base de hachages",
        DetectionEngine::ClamAv => "ClamAV",
        DetectionEngine::Yara => "YARA",
        DetectionEngine::Ml => "modèle ML",
        DetectionEngine::Heuristic => "heuristique",
        DetectionEngine::VirusTotal => "VirusTotal",
    }
}

/// `<container>!/<inner>` → `<container>` (the file we can actually quarantine).
pub fn container_path(path: &str) -> &str {
    path.split_once("!/").map(|(c, _)| c).unwrap_or(path)
}

fn new_alert(
    kind: AlertKind,
    severity: Severity,
    title: String,
    message: String,
    actions: Vec<AlertAction>,
) -> Alert {
    Alert {
        id: 0,
        ts: pb_core::now_ts(),
        kind,
        severity,
        title,
        message,
        path: None,
        sha256: None,
        device_id: None,
        persistence_id: None,
        quarantine_id: None,
        status: AlertStatus::Open,
        actions,
    }
}

/// Build an alert skeleton (id 0, now, open).
pub fn alert(
    kind: AlertKind,
    severity: Severity,
    title: impl Into<String>,
    message: impl Into<String>,
) -> Alert {
    new_alert(
        kind,
        severity,
        title.into(),
        message.into(),
        vec![AlertAction::Acknowledge],
    )
}

/// Insert + publish an alert. `key` is stored in the `detection` column (weekly top list / dedupe key).
pub async fn raise_alert(ctx: &Arc<Ctx>, alert: Alert, key: Option<String>) -> Option<Alert> {
    match ctx
        .store
        .run(move |s| s.insert_alert(&alert, key.as_deref()))
        .await
    {
        Ok(a) => {
            tracing::info!(id = a.id, kind = ?a.kind, severity = ?a.severity, title = %a.title, "alert");
            ctx.bus.publish(DaemonEvent::Alert(a.clone()));
            ctx.status_dirty.notify_one();
            Some(a)
        }
        Err(e) => {
            tracing::error!(error = %e, "cannot store alert");
            None
        }
    }
}

/// Update + publish an existing alert.
pub async fn save_alert(ctx: &Arc<Ctx>, alert: &Alert) -> Result<(), IpcError> {
    let a = alert.clone();
    ctx.store.run(move |s| s.update_alert(&a)).await?;
    ctx.bus.publish(DaemonEvent::Alert(alert.clone()));
    ctx.status_dirty.notify_one();
    Ok(())
}

/// File alert with dedupe on (sha256, path, kind) within 24 h. A duplicate is only refreshed (and re-published)
/// when something new happened (a quarantine).
async fn raise_file_alert(ctx: &Arc<Ctx>, alert: Alert, key: Option<String>) -> Option<Alert> {
    if let (Some(sha), Some(path)) = (alert.sha256.clone(), alert.path.clone()) {
        let since = pb_core::now_ts() - DEDUPE_WINDOW;
        let existing = ctx
            .store
            .run(move |s| s.find_recent_alert(&sha, &path, since))
            .await
            .ok()
            .flatten();
        if let Some(mut ex) = existing.filter(|e| e.kind == alert.kind) {
            if alert.quarantine_id.is_some() && ex.quarantine_id != alert.quarantine_id {
                ex.quarantine_id = alert.quarantine_id.clone();
                ex.actions = alert.actions.clone();
                ex.severity = ex.severity.max(alert.severity);
                ex.title = alert.title.clone();
                ex.message = alert.message.clone();
                ex.status = AlertStatus::Open;
                ex.ts = alert.ts;
                if let Err(e) = save_alert(ctx, &ex).await {
                    tracing::warn!(error = %e.message, "cannot refresh alert");
                }
            } else {
                tracing::debug!(id = ex.id, "duplicate alert suppressed");
            }
            return Some(ex);
        }
    }
    raise_alert(ctx, alert, key).await
}

/// Apply the daemon's policy to a scan report. Returns the effective verdict (after local lists).
///
/// Boxed (not `async fn`) because the VirusTotal follow-up re-enters it from a spawned task.
pub fn process_report<'a>(
    ctx: &'a Arc<Ctx>,
    report: ScanReport,
    rc: &'a ReportContext,
) -> Pin<Box<dyn Future<Output = Verdict> + Send + 'a>> {
    Box::pin(process_report_inner(ctx, report, rc))
}

async fn process_report_inner(
    ctx: &Arc<Ctx>,
    mut report: ScanReport,
    rc: &ReportContext,
) -> Verdict {
    let sha = report.sha256.as_deref().map(str::to_ascii_lowercase);
    if let Some(sha) = sha.clone() {
        let s2 = sha.clone();
        if ctx
            .store
            .run(move |s| s.allowlist_contains(&s2))
            .await
            .unwrap_or(false)
        {
            return Verdict::Clean;
        }
        if let Ok(Some(entry)) = ctx.store.run(move |s| s.blocklist_get(&sha)).await {
            report.detections.push(Detection {
                engine: DetectionEngine::VirusTotal,
                name: entry.name.clone(),
                severity: Severity::High,
                confidence: 0.9,
                details: Some(format!("liste de blocage locale ({})", entry.source)),
            });
            report.verdict = Verdict::Malicious;
        }
    }
    if report.verdict == Verdict::Clean {
        return Verdict::Clean;
    }
    let container = container_path(&report.path).to_string();
    let live = matches!(rc.origin, ScanOrigin::Realtime | ScanOrigin::Downloads);
    if live {
        if let Some(sha) = report.sha256.as_deref() {
            if ctx.was_restored(&container, sha) || ctx.was_restored(&report.path, sha) {
                tracing::info!(path = %report.path, "restored by the user, no action");
                return report.verdict;
            }
        }
    }
    ctx.bump_stat(StatField::Threats, 1).await;

    let cfg = ctx.config();
    let paused = live && ctx.is_paused(pb_core::now_ts());
    let signature = signature_grade(ctx.engine().as_ref(), &report);
    let (name, engine) = primary_detection(&report)
        .map(|d| (d.name.clone(), engine_label(d.engine)))
        .unwrap_or_else(|| ("menace inconnue".into(), "moteur"));
    let process_note = match &rc.exec {
        Some(ExecInfo { pid, killed: true }) => format!(" Le processus {pid} a été arrêté."),
        Some(ExecInfo { pid, killed: false }) => format!(" Lancé par le processus {pid}."),
        None => String::new(),
    };
    let paused_note = if paused {
        " Protection en pause : aucune action automatique."
    } else {
        ""
    };

    let mut alert = match report.verdict {
        Verdict::Malicious => {
            let mut quarantined = None;
            let mut failure = None;
            if cfg.realtime.auto_quarantine && signature && !paused {
                match quarantine_path(
                    ctx,
                    Path::new(&container),
                    report.sha256.as_deref(),
                    &report.detections,
                    "auto",
                )
                .await
                {
                    Ok(entry) => quarantined = Some(entry),
                    Err(e) => failure = Some(e.message),
                }
            }
            match quarantined {
                Some(entry) => {
                    let critical = report
                        .detections
                        .iter()
                        .any(|d| d.severity == Severity::Critical);
                    let mut a = new_alert(
                        AlertKind::Malware,
                        if critical { Severity::Critical } else { Severity::High },
                        "Menace mise en quarantaine".into(),
                        format!(
                            "{name} détecté par {engine} dans {}. Le fichier a été isolé et peut être restauré.{process_note}",
                            report.path
                        ),
                        vec![AlertAction::Restore, AlertAction::ReportFalsePositive, AlertAction::Acknowledge],
                    );
                    a.quarantine_id = Some(entry.id.clone());
                    a
                }
                None => {
                    let why = match failure {
                        Some(f) => format!(" Mise en quarantaine automatique impossible : {f}."),
                        None => " Mettez le fichier en quarantaine ou autorisez-le.".into(),
                    };
                    new_alert(
                        AlertKind::Malware,
                        Severity::High,
                        "Menace détectée".into(),
                        format!(
                            "{name} détecté par {engine} dans {}.{why}{process_note}{paused_note}",
                            report.path
                        ),
                        vec![
                            AlertAction::Quarantine,
                            AlertAction::Allow,
                            AlertAction::Acknowledge,
                        ],
                    )
                }
            }
        }
        _ => new_alert(
            AlertKind::Suspicious,
            Severity::Medium,
            "Fichier suspect".into(),
            format!(
                "{name} ({engine}, score {:.2}) : {}.{process_note}{paused_note}",
                report.score, report.path
            ),
            vec![
                AlertAction::Quarantine,
                AlertAction::Allow,
                AlertAction::ReportFalsePositive,
            ],
        ),
    };
    alert.path = Some(report.path.clone());
    alert.sha256 = report.sha256.as_deref().map(str::to_ascii_lowercase);
    let raised = raise_file_alert(ctx, alert, Some(name)).await;

    let verdict = report.verdict;
    if verdict == Verdict::Suspicious && cfg.privacy.virustotal_lookup {
        let key = cfg.privacy.virustotal_api_key.clone().unwrap_or_default();
        if !key.trim().is_empty() && report.sha256.is_some() {
            let ctx2 = ctx.clone();
            let rc2 = rc.clone();
            let alert_id = raised.map(|a| a.id);
            tokio::spawn(async move { vt_followup(ctx2, report, rc2, key, alert_id).await });
        }
    }
    verdict
}

/// Ask VirusTotal about a suspicious file; ≥ 5 engines ⇒ local blocklist + act as malicious.
async fn vt_followup(
    ctx: Arc<Ctx>,
    report: ScanReport,
    rc: ReportContext,
    key: String,
    alert_id: Option<i64>,
) {
    let Some(sha) = report.sha256.clone() else {
        return;
    };
    match ctx.backends.reputation.malicious_engines(&sha, &key).await {
        Ok(Some(n)) if n >= VT_MALICIOUS_THRESHOLD => {
            tracing::warn!(%sha, engines = n, "VirusTotal confirms malicious file");
            let name = format!("VirusTotal ({n} moteurs)");
            let s2 = sha.clone();
            if let Err(e) = ctx
                .store
                .run(move |s| s.blocklist_add(&s2, &name, "virustotal", pb_core::now_ts()))
                .await
            {
                tracing::warn!(error = %e, "cannot update local blocklist");
            }
            if let Some(id) = alert_id {
                if let Ok(Some(mut a)) = ctx.store.run(move |s| s.get_alert(id)).await {
                    a.status = AlertStatus::Resolved;
                    a.actions.clear();
                    let _ = save_alert(&ctx, &a).await;
                }
            }
            // Re-process: the blocklist hit upgrades the verdict to malicious.
            process_report(&ctx, report, &rc).await;
        }
        Ok(n) => tracing::debug!(%sha, engines = ?n, "VirusTotal: below threshold"),
        Err(e) => tracing::warn!(%sha, error = %e, "VirusTotal lookup failed"),
    }
}

/// Quarantine a file through the engine's quarantine, after safety checks. Publishes `quarantined`.
pub async fn quarantine_path(
    ctx: &Arc<Ctx>,
    path: &Path,
    sha256: Option<&str>,
    detections: &[Detection],
    reason: &str,
) -> Result<QuarantineEntry, IpcError> {
    check_quarantinable(ctx, path)?;
    let q = ctx.backends.quarantine.clone();
    let (p, s, d, r) = (
        path.to_path_buf(),
        sha256.map(str::to_string),
        detections.to_vec(),
        reason.to_string(),
    );
    let entry = tokio::task::spawn_blocking(move || q.quarantine(&p, s.as_deref(), &d, &r))
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?
        .map_err(IpcError::from)?;
    tracing::warn!(path = %path.display(), id = %entry.id, reason, "file quarantined");
    ctx.bump_stat(StatField::Quarantined, 1).await;
    ctx.bus.publish(DaemonEvent::Quarantined(entry.clone()));
    ctx.status_dirty.notify_one();
    Ok(entry)
}

/// Refuse system locations, our own tree and symlinks.
pub fn check_quarantinable(ctx: &Ctx, path: &Path) -> Result<(), IpcError> {
    if !path.is_absolute() {
        return Err(IpcError::new(ErrorCode::BadRequest, "chemin absolu requis"));
    }
    if crate::system::is_protected_system_path(path) {
        return Err(IpcError::new(
            ErrorCode::PermissionDenied,
            "fichier système protégé : jamais mis en quarantaine",
        ));
    }
    if path.starts_with(&ctx.paths.root) {
        return Err(IpcError::new(
            ErrorCode::PermissionDenied,
            "fichier de Parabellum : refusé",
        ));
    }
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(IpcError::new(
            ErrorCode::NotFound,
            format!("fichier introuvable : {}", path.display()),
        )),
        Err(e) => Err(IpcError::new(
            ErrorCode::Internal,
            format!("{}: {e}", path.display()),
        )),
        Ok(md) if md.file_type().is_symlink() => Err(IpcError::new(
            ErrorCode::BadRequest,
            "lien symbolique : mettez en quarantaine sa cible",
        )),
        Ok(_) => Ok(()),
    }
}

/// Manual quarantine (`QuarantinePath`): also refuses Apple-signed files.
pub async fn quarantine_manual(ctx: &Arc<Ctx>, path: &str) -> Result<QuarantineEntry, IpcError> {
    let p = PathBuf::from(path);
    check_quarantinable(ctx, &p)?;
    let engine = ctx.engine();
    let p2 = p.clone();
    let signing = tokio::task::spawn_blocking(move || engine.signing_info(&p2))
        .await
        .ok()
        .flatten();
    if signing.map(|s| s.apple && s.valid).unwrap_or(false) {
        return Err(IpcError::new(
            ErrorCode::PermissionDenied,
            "binaire signé par Apple : refusé",
        ));
    }
    quarantine_path(ctx, &p, None, &[], "user").await
}

async fn quarantine_get(ctx: &Arc<Ctx>, id: &str) -> Result<QuarantineEntry, IpcError> {
    let q = ctx.backends.quarantine.clone();
    let id = id.to_string();
    tokio::task::spawn_blocking(move || q.get(&id))
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?
        .map_err(IpcError::from)
}

/// Resolve every alert pointing at a quarantine entry.
async fn resolve_alerts_for_entry(ctx: &Arc<Ctx>, entry_id: &str) {
    let id = entry_id.to_string();
    let alerts = ctx
        .store
        .run(move |s| s.alerts_by_quarantine(&id))
        .await
        .unwrap_or_default();
    for mut a in alerts {
        if a.status != AlertStatus::Resolved || !a.actions.is_empty() {
            a.status = AlertStatus::Resolved;
            a.actions.clear();
            let _ = save_alert(ctx, &a).await;
        }
    }
}

/// Restore a quarantined file. `allow` also adds its hash to the local allowlist.
pub async fn restore_entry(
    ctx: &Arc<Ctx>,
    entry_id: &str,
    allow: bool,
) -> Result<String, IpcError> {
    let entry = quarantine_get(ctx, entry_id).await?;
    let sha = entry.sha256.to_ascii_lowercase();
    if allow {
        let s2 = sha.clone();
        ctx.store
            .run(move |s| s.allowlist_add(&s2, "restauré et autorisé", pb_core::now_ts()))
            .await?;
        sync_allowlist(ctx).await;
    } else {
        // Before the file reappears, so the real-time pipeline does not grab it again.
        ctx.remember_restored(&entry.original_path, &sha);
    }
    let q = ctx.backends.quarantine.clone();
    let id = entry_id.to_string();
    let restored = tokio::task::spawn_blocking(move || q.restore(&id))
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?
        .map_err(IpcError::from)?;
    tracing::info!(id = entry_id, path = %restored.display(), allow, "file restored");
    resolve_alerts_for_entry(ctx, entry_id).await;
    ctx.status_dirty.notify_one();
    Ok(restored.to_string_lossy().into_owned())
}

/// Permanently delete a quarantined file (explicit user action only).
pub async fn delete_entry(ctx: &Arc<Ctx>, entry_id: &str) -> Result<(), IpcError> {
    let q = ctx.backends.quarantine.clone();
    let id = entry_id.to_string();
    tokio::task::spawn_blocking(move || q.delete(&id))
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?
        .map_err(IpcError::from)?;
    tracing::warn!(id = entry_id, "quarantined file deleted by the user");
    resolve_alerts_for_entry(ctx, entry_id).await;
    ctx.status_dirty.notify_one();
    Ok(())
}

/// Record a false positive: allowlist + FP log + weekly counter.
pub async fn report_false_positive(
    ctx: &Arc<Ctx>,
    sha256: &str,
    path: Option<String>,
    note: Option<String>,
) -> Result<(), IpcError> {
    if !crate::virustotal::is_sha256_hex(sha256) {
        return Err(IpcError::new(
            ErrorCode::BadRequest,
            "SHA-256 invalide (64 caractères hexadécimaux)",
        ));
    }
    let note = note.map(|n| n.chars().take(2000).collect::<String>());
    let path = path.map(|p| p.chars().take(4096).collect::<String>());
    let sha = sha256.to_ascii_lowercase();
    ctx.store
        .run(move |s| {
            let now = pb_core::now_ts();
            s.allowlist_add(&sha, "faux positif signalé", now)?;
            s.add_false_positive(&sha, path.as_deref(), note.as_deref(), now)
        })
        .await?;
    sync_allowlist(ctx).await;
    ctx.bump_stat(StatField::FalsePositives, 1).await;
    Ok(())
}

/// Apply one of an alert's actions.
pub async fn resolve_alert(
    ctx: &Arc<Ctx>,
    alert_id: i64,
    action: AlertAction,
) -> Result<Alert, IpcError> {
    let mut alert = ctx
        .store
        .run(move |s| s.get_alert(alert_id))
        .await?
        .ok_or_else(|| {
            IpcError::new(
                ErrorCode::NotFound,
                format!("alerte {alert_id} introuvable"),
            )
        })?;
    if !matches!(action, AlertAction::Acknowledge | AlertAction::Dismiss)
        && !alert.actions.contains(&action)
    {
        return Err(IpcError::new(
            ErrorCode::BadRequest,
            "action non proposée pour cette alerte",
        ));
    }
    let missing = |what: &str| IpcError::new(ErrorCode::BadRequest, format!("alerte sans {what}"));
    match action {
        AlertAction::Acknowledge => {
            alert.status = AlertStatus::Acknowledged;
        }
        AlertAction::Dismiss => {
            alert.status = AlertStatus::Resolved;
            alert.actions.clear();
        }
        AlertAction::Quarantine => {
            let path = alert.path.clone().ok_or_else(|| missing("chemin"))?;
            let entry = quarantine_path(
                ctx,
                Path::new(container_path(&path)),
                alert.sha256.as_deref(),
                &[],
                "user",
            )
            .await?;
            alert.quarantine_id = Some(entry.id);
            alert.status = AlertStatus::Resolved;
            alert.actions = vec![AlertAction::Restore];
        }
        AlertAction::Allow => {
            let sha = alert.sha256.clone().ok_or_else(|| missing("empreinte"))?;
            ctx.store
                .run(move |s| {
                    s.allowlist_add(&sha, "autorisé depuis une alerte", pb_core::now_ts())
                })
                .await?;
            sync_allowlist(ctx).await;
            if let Some(q) = alert.quarantine_id.clone() {
                match restore_entry(ctx, &q, true).await {
                    Ok(_) => {}
                    Err(e) if e.code == ErrorCode::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            alert.status = AlertStatus::Resolved;
            alert.actions.clear();
        }
        AlertAction::Restore => {
            let q = alert
                .quarantine_id
                .clone()
                .ok_or_else(|| missing("entrée de quarantaine"))?;
            restore_entry(ctx, &q, false).await?;
            alert.status = AlertStatus::Resolved;
            alert.actions.clear();
        }
        AlertAction::ReportFalsePositive => {
            let sha = alert.sha256.clone().ok_or_else(|| missing("empreinte"))?;
            report_false_positive(
                ctx,
                &sha,
                alert.path.clone(),
                Some(format!("alerte {}", alert.id)),
            )
            .await?;
            if let Some(q) = alert.quarantine_id.clone() {
                match restore_entry(ctx, &q, true).await {
                    Ok(_) => {}
                    Err(e) if e.code == ErrorCode::NotFound => {}
                    Err(e) => return Err(e),
                }
            }
            alert.status = AlertStatus::Resolved;
            alert.actions.clear();
        }
        AlertAction::TrustDevice | AlertAction::BlockDevice => {
            let id = alert
                .device_id
                .clone()
                .ok_or_else(|| missing("périphérique"))?;
            let trust = if action == AlertAction::TrustDevice {
                DeviceTrust::Trusted
            } else {
                DeviceTrust::Blocked
            };
            crate::devices::set_device_trust(ctx, &id, trust).await?;
            alert.status = AlertStatus::Resolved;
            alert.actions.clear();
        }
        AlertAction::ApprovePersistence | AlertAction::RemovePersistence => {
            let id = alert
                .persistence_id
                .clone()
                .ok_or_else(|| missing("élément de persistance"))?;
            let status = if action == AlertAction::ApprovePersistence {
                PersistenceStatus::Approved
            } else {
                PersistenceStatus::Quarantined
            };
            crate::persistence::set_status(ctx, &id, status).await?;
            alert.status = AlertStatus::Resolved;
            alert.actions.clear();
        }
    }
    // Re-read: the sub-actions may have updated this alert (e.g. restore resolves linked alerts).
    let fresh_id = alert.id;
    if let Ok(Some(fresh)) = ctx.store.run(move |s| s.get_alert(fresh_id)).await {
        if fresh.quarantine_id.is_some() && alert.quarantine_id.is_none() {
            alert.quarantine_id = fresh.quarantine_id;
        }
    }
    save_alert(ctx, &alert).await?;
    Ok(alert)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn det(engine: DetectionEngine, sev: Severity, conf: f32, name: &str) -> Detection {
        Detection {
            engine,
            name: name.into(),
            severity: sev,
            confidence: conf,
            details: None,
        }
    }

    #[test]
    fn signature_classification() {
        let e = crate::backends::NullEngine;
        let r = |d: Detection| ScanReport {
            detections: vec![d],
            ..Default::default()
        };
        assert!(signature_grade(
            &e,
            &r(det(DetectionEngine::HashDb, Severity::Low, 1.0, "a"))
        ));
        assert!(signature_grade(
            &e,
            &r(det(DetectionEngine::ClamAv, Severity::Medium, 1.0, "a"))
        ));
        assert!(signature_grade(
            &e,
            &r(det(DetectionEngine::Yara, Severity::High, 1.0, "a"))
        ));
        assert!(signature_grade(
            &e,
            &r(det(DetectionEngine::VirusTotal, Severity::High, 1.0, "a"))
        ));
        assert!(!signature_grade(
            &e,
            &r(det(DetectionEngine::Yara, Severity::Medium, 1.0, "a"))
        ));
        assert!(!signature_grade(
            &e,
            &r(det(DetectionEngine::Ml, Severity::Critical, 1.0, "a"))
        ));
        assert!(!signature_grade(&e, &ScanReport::default()));
    }

    #[test]
    fn primary_and_container() {
        let r = ScanReport {
            detections: vec![
                det(DetectionEngine::Ml, Severity::Medium, 0.9, "ml"),
                det(DetectionEngine::Yara, Severity::High, 0.5, "y1"),
                det(DetectionEngine::ClamAv, Severity::High, 0.9, "c1"),
            ],
            ..Default::default()
        };
        assert_eq!(primary_detection(&r).unwrap().name, "c1");
        assert_eq!(container_path("/a/b.dmg!/x.app/y"), "/a/b.dmg");
        assert_eq!(container_path("/a/b"), "/a/b");
    }
}
