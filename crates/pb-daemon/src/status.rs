//! `StatusInfo` computation and the task pushing `status_changed` when something significant changes.

use crate::ctx::Ctx;
use pb_core::config::Config;
use pb_core::ipc::DaemonEvent;
use pb_core::model::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Status issues (French, shown as-is by the app).
/// Ad-hoc signing changes the code identity at every update, so TCC forgets the grant.
pub const ISSUE_NO_FDA: &str =
    "Accès complet au disque non accordé à parabellumd (à ré-accorder après chaque mise à jour)";
pub const ISSUE_DB_STALE: &str = "Base de menaces absente ou âgée de plus de 3 jours";
pub const ISSUE_NO_CLAMAV: &str = "ClamAV non installé";
pub const ISSUE_ESLOGGER: &str = "eslogger inactif";
pub const ISSUE_FSEVENTS: &str = "Surveillance des fichiers (FSEvents) inactive";
pub const ISSUE_PERSISTENCE: &str = "Surveillance de la persistance inactive";
pub const ISSUE_REALTIME_OFF: &str = "Protection temps réel désactivée dans la configuration";
pub const ISSUE_ENGINE: &str = "Moteur d'analyse indisponible";
pub const ISSUE_CONFIG: &str = "Configuration invalide : configuration de secours utilisée";
pub const ISSUE_DNS: &str = "Blocage DNS activé mais dnscrypt-proxy ne répond pas";

/// How long a Full Disk Access check is cached.
pub const FDA_CACHE: Duration = Duration::from_secs(300);
/// Periodic recomputation.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(60);
/// Max DB age before the status is degraded.
pub const DB_MAX_AGE: i64 = 3 * 86_400;

async fn full_disk_access(ctx: &Arc<Ctx>) -> bool {
    if let Some((v, at)) = ctx.state().fda {
        if at.elapsed() < FDA_CACHE {
            return v;
        }
    }
    let m = ctx.backends.monitors.clone();
    let v = tokio::task::spawn_blocking(move || m.has_full_disk_access())
        .await
        .unwrap_or(false);
    ctx.state().fda = Some((v, Instant::now()));
    v
}

/// Inputs of [`issues`] (kept separate so the rules are unit-testable).
#[derive(Debug, Clone, Default)]
pub struct IssueInputs {
    pub fda: bool,
    pub health: RealtimeStatus,
    pub db_built_at: Option<i64>,
    pub db_version: Option<String>,
    pub clamav: bool,
    pub engine_error: bool,
    pub config_error: bool,
    pub dns_running: bool,
}

/// French list of problems degrading protection.
pub fn issues(cfg: &Config, i: &IssueInputs, now: i64) -> Vec<String> {
    let mut v = Vec::new();
    if i.config_error {
        v.push(ISSUE_CONFIG);
    }
    if i.engine_error {
        v.push(ISSUE_ENGINE);
    }
    if !i.fda {
        v.push(ISSUE_NO_FDA);
    }
    let fresh = i.db_version.is_some()
        && i.db_built_at
            .map(|t| now - t <= DB_MAX_AGE)
            .unwrap_or(false);
    if !fresh {
        v.push(ISSUE_DB_STALE);
    }
    if !i.clamav {
        v.push(ISSUE_NO_CLAMAV);
    }
    if !cfg.realtime.enabled {
        v.push(ISSUE_REALTIME_OFF);
    } else {
        if cfg.realtime.eslogger && !i.health.eslogger {
            v.push(ISSUE_ESLOGGER);
        }
        if cfg.realtime.fsevents && !i.health.fsevents {
            v.push(ISSUE_FSEVENTS);
        }
    }
    if cfg.persistence.enabled && !i.health.persistence_monitor {
        v.push(ISSUE_PERSISTENCE);
    }
    if cfg.dns.enabled && !i.dns_running {
        v.push(ISSUE_DNS);
    }
    v.into_iter().map(String::from).collect()
}

/// DB status: engine counters + updater bookkeeping.
pub fn merged_db_status(ctx: &Ctx) -> DbStatus {
    let mut db = ctx.engine().db_status();
    let upd = ctx.backends.updater.db_update_status(&ctx.config());
    db.last_check = upd.last_check.or(db.last_check);
    db.last_success = upd.last_success.or(db.last_success);
    db.last_error = upd.last_error.or(db.last_error);
    db.previous_version = db.previous_version.or(upd.previous_version);
    if db.version.is_none() {
        db.version = upd.version.clone();
    }
    if db.version == upd.version {
        db.built_at = db.built_at.or(upd.built_at);
    }
    if db.blocked_domains == 0 {
        db.blocked_domains = upd.blocked_domains;
    }
    db.clamav_version = db.clamav_version.or(upd.clamav_version);
    db.ml_model_version = db.ml_model_version.or(upd.ml_model_version);
    db
}

/// Compute the full status now.
pub async fn compute(ctx: &Arc<Ctx>) -> StatusInfo {
    let cfg = ctx.config();
    let now = pb_core::now_ts();
    let fda = full_disk_access(ctx).await;
    let db = merged_db_status(ctx);
    let engine = ctx.engine();
    let open_alerts = ctx.store.run(|s| s.count_open_alerts()).await.unwrap_or(0);
    let last_scan = ctx
        .store
        .run(|s| s.last_scan_finished())
        .await
        .ok()
        .flatten();
    let q = ctx.backends.quarantine.clone();
    let quarantined = tokio::task::spawn_blocking(move || q.list().map(|l| l.len()).unwrap_or(0))
        .await
        .unwrap_or(0);
    let components = ctx.backends.updater.list_components(&ctx.config()).await;
    let attention = components
        .iter()
        .filter(|c| {
            matches!(
                c.state,
                ComponentState::Error | ComponentState::NeedsUserAction
            ) || (c.required && c.state == ComponentState::NotInstalled)
        })
        .count();
    let dns_running = if cfg.dns.enabled {
        ctx.backends.dns.status(&cfg).await.running
    } else {
        false
    };
    let (paused_until, health, battery, config_error, engine_error) = {
        let st = ctx.state();
        (
            st.paused_until,
            st.health.clone(),
            st.battery,
            st.config_error.is_some(),
            st.engine_error.is_some(),
        )
    };
    let inputs = IssueInputs {
        fda,
        health: health.clone(),
        db_built_at: db.built_at,
        db_version: db.version.clone(),
        clamav: engine.clamav_available(),
        engine_error,
        config_error,
        dns_running,
    };
    let issues = issues(&cfg, &inputs, now);
    let paused_until = paused_until.filter(|t| *t > now);
    let protection = if paused_until.is_some() {
        ProtectionState::Paused
    } else if !issues.is_empty() {
        ProtectionState::Degraded
    } else {
        ProtectionState::Active
    };
    StatusInfo {
        version: pb_core::VERSION.to_string(),
        protection,
        paused_until,
        issues,
        realtime: RealtimeStatus {
            full_disk_access: fda,
            ..health
        },
        db,
        open_alerts,
        quarantined: quarantined.min(u32::MAX as usize) as u32,
        last_scan,
        dns_enabled: cfg.dns.enabled,
        on_battery: battery.on_battery,
        components_needing_attention: attention.min(u32::MAX as usize) as u32,
        ml_enabled: cfg.ml.enabled && engine.ml_loaded(),
        uptime_secs: ctx.started.elapsed().as_secs(),
        rss_bytes: crate::system::rss_bytes(),
    }
}

fn significant(s: &StatusInfo) -> StatusInfo {
    StatusInfo {
        uptime_secs: 0,
        rss_bytes: 0,
        ..s.clone()
    }
}

/// Recompute and push `status_changed` if it differs from the last push. Returns the status.
pub async fn refresh(ctx: &Arc<Ctx>) -> StatusInfo {
    let s = compute(ctx).await;
    let changed = {
        let mut st = ctx.state();
        let differs = st
            .last_status
            .as_ref()
            .map(|l| significant(l) != significant(&s))
            .unwrap_or(true);
        if differs {
            st.last_status = Some(s.clone());
        }
        differs
    };
    if changed {
        ctx.bus.publish(DaemonEvent::StatusChanged(s.clone()));
    }
    s
}

/// Status task: every minute, or soon after something relevant happened.
pub async fn run(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    loop {
        refresh(&ctx).await;
        tokio::select! {
            _ = tokio::time::sleep(STATUS_INTERVAL) => {}
            _ = ctx.status_dirty.notified() => {
                // Coalesce bursts (a scan finding many threats).
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> IssueInputs {
        IssueInputs {
            fda: true,
            health: RealtimeStatus {
                fsevents: true,
                eslogger: true,
                full_disk_access: true,
                persistence_monitor: true,
                device_monitor: true,
            },
            db_built_at: Some(1_000_000),
            db_version: Some("2026.10.25.1".into()),
            clamav: true,
            engine_error: false,
            config_error: false,
            dns_running: false,
        }
    }

    #[test]
    fn healthy_has_no_issue() {
        assert!(issues(&Config::default(), &healthy(), 1_000_000 + 3600).is_empty());
    }

    #[test]
    fn each_issue() {
        let cfg = Config::default();
        let now = 1_000_000 + 3600;
        let mut i = healthy();
        i.fda = false;
        assert_eq!(issues(&cfg, &i, now), vec![ISSUE_NO_FDA]);
        let i = healthy();
        assert_eq!(
            issues(&cfg, &i, 1_000_000 + 4 * 86_400),
            vec![ISSUE_DB_STALE]
        );
        let mut i = healthy();
        i.db_version = None;
        assert_eq!(issues(&cfg, &i, now), vec![ISSUE_DB_STALE]);
        let mut i = healthy();
        i.clamav = false;
        i.health.eslogger = false;
        assert_eq!(issues(&cfg, &i, now), vec![ISSUE_NO_CLAMAV, ISSUE_ESLOGGER]);
        let mut c2 = cfg.clone();
        c2.realtime.enabled = false;
        let mut i = healthy();
        i.health.eslogger = false;
        assert_eq!(issues(&c2, &i, now), vec![ISSUE_REALTIME_OFF]);
        let mut c3 = cfg.clone();
        c3.dns.enabled = true;
        assert_eq!(issues(&c3, &healthy(), now), vec![ISSUE_DNS]);
    }
}
