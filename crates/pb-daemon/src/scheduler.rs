//! Scheduled work: daily updates (DB → engine swap → DNS lists → retro-hunt; freshclam; components; app),
//! osquery hunting, nightly hash retro-check, store pruning, battery polling, first-run component install,
//! DNS block counters.

use crate::actions::{self, ReportContext};
use crate::backends::ScanOpts;
use crate::ctx::Ctx;
use crate::jobs::{self, JobSpec};
use crate::store::{AlertKey, StatField};
use chrono::{DateTime, Days, Local, TimeZone};
use pb_core::ipc::{DaemonEvent, ErrorCode, IpcError};
use pb_core::model::*;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// kv: Unix time of the last successful DB update.
pub const KV_LAST_DB_SUCCESS: &str = "last_db_update_success";
/// kv: Unix time of the first daemon start.
pub const KV_FIRST_RUN: &str = "first_run_at";
/// kv: all required components installed at least once.
pub const KV_COMPONENTS_BOOTSTRAP: &str = "components_bootstrap_done";
/// kv: first osquery hunt done (its rows are the baseline).
pub const KV_OSQUERY_BASELINE: &str = "osquery_baseline_done";

/// Delay before the catch-up update at startup.
pub const STARTUP_UPDATE_DELAY: Duration = Duration::from_secs(120);
/// Delay before installing missing components on first run.
pub const BOOTSTRAP_DELAY: Duration = Duration::from_secs(300);
/// Battery polling interval.
pub const BATTERY_INTERVAL: Duration = Duration::from_secs(300);
/// The daily run waits at most this long for the battery to recover.
pub const MAX_BATTERY_DEFERRAL: Duration = Duration::from_secs(6 * 3600);
/// Max retro-hunt window.
pub const MAX_RETRO_DAYS: u32 = 90;
/// Files re-scanned by one retro-hunt.
pub const MAX_RETRO_FILES: u32 = 50_000;

/// Next daily run strictly after `now`: `hour`:00 local + `jitter_secs`.
pub fn next_daily<Tz: TimeZone>(
    now: &DateTime<Tz>,
    hour: u8,
    jitter_secs: i64,
) -> Option<DateTime<Tz>> {
    let tz = now.timezone();
    let at = |day: chrono::NaiveDate| {
        (0..3u32).find_map(|extra| {
            day.and_hms_opt((u32::from(hour.min(23)) + extra).min(23), 0, 0)
                .and_then(|n| tz.from_local_datetime(&n).earliest())
        })
    };
    let today = at(now.date_naive())? + chrono::Duration::seconds(jitter_secs);
    if today > *now {
        return Some(today);
    }
    Some(
        at(now.date_naive().checked_add_days(Days::new(1))?)?
            + chrono::Duration::seconds(jitter_secs),
    )
}

/// Random jitter in `[0, max_secs)` (no extra RNG dependency: UUID v4 randomness).
pub fn jitter(max_secs: u64) -> i64 {
    if max_secs == 0 {
        return 0;
    }
    (uuid::Uuid::new_v4().as_u128() % u128::from(max_secs)) as i64
}

fn to_duration(target: DateTime<Local>) -> Duration {
    let secs = target.timestamp() - Local::now().timestamp();
    Duration::from_secs(secs.max(1) as u64)
}

/// Main scheduler task.
pub async fn run(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    let mut cfg_rx = ctx.config_rx();
    let now = pb_core::now_ts();
    let last = ctx
        .store
        .run(|s| s.kv_get_i64(KV_LAST_DB_SUCCESS))
        .await
        .ok()
        .flatten();
    let mut catch_up = last.map(|t| now - t > 86_400).unwrap_or(true);
    let mut hour = ctx.config().updates.daily_hour;
    let mut next = next_daily(&Local::now(), hour, jitter(20 * 60));
    loop {
        let wait = if catch_up {
            STARTUP_UPDATE_DELAY
        } else {
            next.map(to_duration).unwrap_or(Duration::from_secs(3600))
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {
                catch_up = false;
                daily_run(&ctx).await;
                next = next_daily(&Local::now(), ctx.config().updates.daily_hour, jitter(20 * 60));
            }
            r = cfg_rx.changed() => {
                if r.is_err() { break; }
                let h = cfg_rx.borrow_and_update().updates.daily_hour;
                if h != hour {
                    hour = h;
                    next = next_daily(&Local::now(), hour, jitter(20 * 60));
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
    }
}

/// Wait (bounded) while on low battery. Returns false on shutdown.
async fn wait_for_power(ctx: &Arc<Ctx>, max: Duration) -> bool {
    let mut shutdown = ctx.shutdown_rx();
    let deadline = tokio::time::Instant::now() + max;
    while ctx.should_defer_heavy_work() && tokio::time::Instant::now() < deadline {
        tracing::info!("low battery: deferring scheduled work");
        tokio::select! {
            _ = tokio::time::sleep(BATTERY_INTERVAL) => {}
            _ = shutdown.changed() => if *shutdown.borrow() { return false; },
        }
    }
    !ctx.is_shutting_down()
}

/// Everything done once a day.
pub async fn daily_run(ctx: &Arc<Ctx>) {
    if !wait_for_power(ctx, MAX_BATTERY_DEFERRAL).await {
        return;
    }
    tracing::info!("daily run");
    if let Err(e) = run_updates(ctx, UpdateTarget::All).await {
        tracing::warn!(error = %e.message, "daily update skipped");
    }
    if ctx.config().persistence.osquery_hunting {
        osquery_hunt(ctx).await;
    }
    hash_retro_check(ctx, 30).await;
    if let Err(e) = ctx.store.run(|s| s.prune(pb_core::now_ts())).await {
        tracing::warn!(error = %e, "store pruning failed");
    }
}

/// Reload the engine from the current DB (after an update / ML toggle). Returns false on failure.
pub async fn reload_engine(ctx: &Arc<Ctx>) -> bool {
    let loader = ctx.backends.engine_loader.clone();
    let (paths, cfg) = (ctx.paths.clone(), ctx.config());
    match tokio::task::spawn_blocking(move || loader.load(&paths, &cfg)).await {
        Ok(Ok(engine)) => {
            ctx.swap_engine(engine);
            ctx.state().engine_error = None;
            actions::sync_allowlist(ctx).await;
            let st = ctx.engine().db_status();
            tracing::info!(version = ?st.version, hashes = st.malware_hashes, yara = st.yara_rules, "engine loaded");
            true
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "engine load failed");
            ctx.state().engine_error = Some(e.to_string());
            ctx.status_dirty.notify_one();
            false
        }
        Err(e) => {
            tracing::error!(error = %e, "engine load task failed");
            false
        }
    }
}

struct UpdateRunGuard<'a>(&'a Ctx);
impl Drop for UpdateRunGuard<'_> {
    fn drop(&mut self) {
        self.0.update_running.store(false, Ordering::SeqCst);
    }
}

/// Run the requested update steps (one at a time daemon-wide). Each step is logged and published as an
/// `update_finished` event; `All` additionally publishes a combined result.
pub async fn run_updates(
    ctx: &Arc<Ctx>,
    target: UpdateTarget,
) -> Result<Vec<UpdateResult>, IpcError> {
    if ctx
        .update_running
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return Err(IpcError::new(
            ErrorCode::Busy,
            "une mise à jour est déjà en cours",
        ));
    }
    let _guard = UpdateRunGuard(ctx);
    let started = pb_core::now_ts();
    let steps: &[UpdateTarget] = match target {
        UpdateTarget::All => &[
            UpdateTarget::Db,
            UpdateTarget::Components,
            UpdateTarget::App,
        ],
        UpdateTarget::Db => &[UpdateTarget::Db],
        UpdateTarget::Components => &[UpdateTarget::Components],
        UpdateTarget::App => &[UpdateTarget::App],
    };
    let mut results = Vec::new();
    for step in steps {
        let r = match step {
            UpdateTarget::Db => update_db_step(ctx).await,
            UpdateTarget::Components => components_step(ctx).await,
            _ => app_step(ctx).await,
        };
        let logged = r.clone();
        if let Err(e) = ctx.store.run(move |s| s.log_update(&logged)).await {
            tracing::warn!(error = %e, "cannot log update");
        }
        ctx.bus.publish(DaemonEvent::UpdateFinished(r.clone()));
        results.push(r);
    }
    if target == UpdateTarget::All {
        let combined = UpdateResult {
            target: UpdateTarget::All,
            ok: results.iter().all(|r| r.ok),
            started_at: started,
            finished_at: pb_core::now_ts(),
            messages: results.iter().flat_map(|r| r.messages.clone()).collect(),
            new_db_version: results.iter().find_map(|r| r.new_db_version.clone()),
        };
        ctx.bus.publish(DaemonEvent::UpdateFinished(combined));
    }
    ctx.status_dirty.notify_one();
    Ok(results)
}

async fn update_db_step(ctx: &Arc<Ctx>) -> UpdateResult {
    let started = pb_core::now_ts();
    let cfg = ctx.config();
    let before = ctx.engine().db_status();
    let mut messages = Vec::new();
    let mut new_version = None;
    let ok = match ctx.backends.updater.update_db(&cfg).await {
        Ok(outcome) => {
            messages.extend(outcome.messages.iter().cloned());
            if outcome.updated {
                new_version = outcome.version.clone();
                messages.push(format!(
                    "Base de menaces mise à jour : {}",
                    outcome.version.as_deref().unwrap_or("?")
                ));
                if reload_engine(ctx).await {
                    after_db_change(ctx, &before, &mut messages).await;
                } else {
                    messages.push(
                        "Rechargement du moteur impossible (version précédente conservée)".into(),
                    );
                }
                ctx.bump_stat(StatField::DbUpdates, 1).await;
            } else {
                messages.push("Base de menaces déjà à jour".into());
            }
            let now = pb_core::now_ts().to_string();
            let _ = ctx
                .store
                .run(move |s| s.kv_set(KV_LAST_DB_SUCCESS, &now))
                .await;
            ctx.state().last_update_error = None;
            true
        }
        Err(e) => {
            messages.push(format!("Mise à jour de la base impossible : {e}"));
            ctx.state().last_update_error = Some(e.to_string());
            stale_db_alert(ctx, &e.to_string()).await;
            false
        }
    };
    let mut freshclam_ok = true;
    if cfg.updates.freshclam {
        match ctx.backends.updater.freshclam(&cfg).await {
            Ok(m) => messages.push(m),
            Err(e) => {
                freshclam_ok = false;
                messages.push(format!("freshclam : {e}"));
            }
        }
    }
    UpdateResult {
        target: UpdateTarget::Db,
        ok: ok && freshclam_ok,
        started_at: started,
        finished_at: pb_core::now_ts(),
        messages,
        new_db_version: new_version,
    }
}

/// After a new DB: rebuild DNS lists, retro-hunt if the YARA rule set changed.
async fn after_db_change(ctx: &Arc<Ctx>, before: &DbStatus, messages: &mut Vec<String>) {
    let cfg = ctx.config();
    if cfg.dns.enabled {
        match ctx.backends.dns.rebuild_lists(&cfg).await {
            Ok(n) => messages.push(format!("Listes DNS reconstruites : {n} domaines")),
            Err(e) => messages.push(format!("Listes DNS : {e}")),
        }
    }
    let after = ctx.engine().db_status();
    // New hashes or rules: files seen recently may now be detected. A pure hash re-check is enough when
    // only the hash DB changed and the engine supports it; otherwise re-scan (risky types, background QoS).
    let rules_changed = after.yara_rules != before.yara_rules;
    let hashes_changed =
        after.malware_hashes != before.malware_hashes || after.version != before.version;
    if rules_changed || (hashes_changed && !ctx.engine().supports_hash_lookup()) {
        match start_retro_hunt(ctx, 30).await {
            Ok(id) => messages.push(format!("Base modifiée : rétro-chasse lancée ({id})")),
            Err(e) => messages.push(format!("Rétro-chasse impossible : {}", e.message)),
        }
    } else if hashes_changed {
        hash_retro_check(ctx, 30).await;
    }
}

/// Alert when the DB has not been updated successfully for more than 3 days (deduplicated per day).
async fn stale_db_alert(ctx: &Arc<Ctx>, error: &str) {
    let now = pb_core::now_ts();
    let (last, first_run) = ctx
        .store
        .run(|s| {
            Ok((
                s.kv_get_i64(KV_LAST_DB_SUCCESS)?,
                s.kv_get_i64(KV_FIRST_RUN)?,
            ))
        })
        .await
        .unwrap_or((None, None));
    let reference = last.or(first_run).unwrap_or(now);
    if now - reference <= 3 * 86_400 {
        return;
    }
    let since = now - 86_400;
    let recent = ctx
        .store
        .run(move |s| s.find_recent_alert_by(AlertKind::Update, AlertKey::None, since))
        .await
        .ok()
        .flatten();
    if recent.is_some() {
        return;
    }
    let days = (now - reference) / 86_400;
    let a = actions::alert(
        AlertKind::Update,
        Severity::High,
        "Base de menaces non mise à jour",
        format!("Aucune mise à jour réussie depuis {days} jours. Dernière erreur : {error}"),
    );
    actions::raise_alert(ctx, a, None).await;
}

async fn components_step(ctx: &Arc<Ctx>) -> UpdateResult {
    let started = pb_core::now_ts();
    let cfg = ctx.config();
    let (ok, messages) = if !cfg.updates.auto_update_components {
        (
            true,
            vec!["Mise à jour automatique des composants désactivée".to_string()],
        )
    } else {
        match ctx.backends.updater.update_components(&cfg).await {
            Ok(m) => (true, m),
            Err(e) => (false, vec![format!("Composants : {e}")]),
        }
    };
    for c in ctx.backends.updater.list_components(&ctx.config()).await {
        ctx.bus.publish(DaemonEvent::Component(c));
    }
    UpdateResult {
        target: UpdateTarget::Components,
        ok,
        started_at: started,
        finished_at: pb_core::now_ts(),
        messages,
        new_db_version: None,
    }
}

async fn app_step(ctx: &Arc<Ctx>) -> UpdateResult {
    let started = pb_core::now_ts();
    let cfg = ctx.config();
    let (ok, messages) = match ctx.backends.updater.check_app_update(&cfg).await {
        Ok(m) => (true, vec![m]),
        Err(e) => (false, vec![format!("Application : {e}")]),
    };
    UpdateResult {
        target: UpdateTarget::App,
        ok,
        started_at: started,
        finished_at: pb_core::now_ts(),
        messages,
        new_db_version: None,
    }
}

/// Queue a retro-hunt over the files seen in the last `days` days.
pub async fn start_retro_hunt(ctx: &Arc<Ctx>, days: u32) -> Result<String, IpcError> {
    let days = days.clamp(1, MAX_RETRO_DAYS);
    if ctx.jobs.has_active(ScanOrigin::RetroHunt) {
        return Err(IpcError::new(
            ErrorCode::Busy,
            "une rétro-chasse est déjà en cours",
        ));
    }
    let since = pb_core::now_ts() - i64::from(days) * 86_400;
    let files = ctx
        .store
        .run(move |s| s.files_seen_since(since, MAX_RETRO_FILES))
        .await?;
    let roots: Vec<PathBuf> = tokio::task::spawn_blocking(move || {
        files
            .into_iter()
            .map(|f| PathBuf::from(f.path))
            .filter(|p| {
                std::fs::symlink_metadata(p)
                    .map(|m| m.is_file())
                    .unwrap_or(false)
            })
            .collect()
    })
    .await
    .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?;
    let cfg = ctx.config();
    let spec = JobSpec {
        paths: vec![format!(
            "Fichiers vus ces {days} derniers jours ({})",
            roots.len()
        )],
        roots,
        opts: ScanOpts {
            origin: ScanOrigin::RetroHunt,
            use_clamav: cfg.scan.clamav_on_demand,
            recursive: false,
            only_risky_types: true,
        },
    };
    jobs::submit(ctx, spec).await
}

/// Cheap nightly check: hashes of files seen recently against the (new) hash DB; hits are re-scanned.
pub async fn hash_retro_check(ctx: &Arc<Ctx>, days: u32) {
    let since = pb_core::now_ts() - i64::from(days) * 86_400;
    let Ok(files) = ctx
        .store
        .run(move |s| s.files_seen_since(since, MAX_RETRO_FILES))
        .await
    else {
        return;
    };
    let engine = ctx.engine();
    let hits: Vec<PathBuf> = tokio::task::spawn_blocking(move || {
        files
            .into_iter()
            .filter(|f| f.verdict == Verdict::Clean && engine.lookup_hash(&f.sha256).is_some())
            .map(|f| PathBuf::from(f.path))
            .collect()
    })
    .await
    .unwrap_or_default();
    if hits.is_empty() {
        return;
    }
    tracing::warn!(
        count = hits.len(),
        "hash retro-check: previously clean files now known bad"
    );
    let rc = ReportContext {
        origin: ScanOrigin::RetroHunt,
        job_id: None,
        exec: None,
    };
    for p in hits {
        if !p.is_file() {
            continue;
        }
        let engine = ctx.engine();
        let cfg = ctx.config();
        let opts = ScanOpts {
            origin: ScanOrigin::RetroHunt,
            use_clamav: false,
            recursive: false,
            only_risky_types: false,
        };
        let p2 = p.clone();
        if let Ok(report) =
            tokio::task::spawn_blocking(move || engine.scan_file(&p2, &cfg, &opts)).await
        {
            actions::process_report(ctx, report, &rc, &p).await;
        }
    }
}

/// Stable hash of an osquery result row.
pub fn row_hash(query: &str, columns: &std::collections::BTreeMap<String, String>) -> String {
    let mut h = Sha256::new();
    h.update(query.as_bytes());
    for (k, v) in columns {
        h.update([0u8]);
        h.update(k.as_bytes());
        h.update([1u8]);
        h.update(v.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Run the osquery hunting pack; alert on new rows of alerting queries (first hunt = silent baseline).
pub async fn osquery_hunt(ctx: &Arc<Ctx>) {
    let pack = ctx.paths.db_current().join("osquery").join("hunting.json");
    let pack = pack.is_file().then_some(pack);
    let rows = match ctx.backends.monitors.run_osquery_pack(pack).await {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(error = %e, "osquery hunt skipped");
            return;
        }
    };
    let baseline_done = ctx
        .store
        .run(|s| s.kv_get(KV_OSQUERY_BASELINE))
        .await
        .ok()
        .flatten()
        .is_some();
    let now = pb_core::now_ts();
    let mut alerts = 0usize;
    for row in rows {
        let h = row_hash(&row.query, &row.columns);
        let q = row.query.clone();
        let fresh = ctx
            .store
            .run(move |s| s.osquery_mark_seen(&h, &q, now))
            .await
            .unwrap_or(false);
        if !(fresh && row.alert && baseline_done) || alerts >= 20 {
            continue;
        }
        alerts += 1;
        let summary: String = row
            .columns
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
            .chars()
            .take(600)
            .collect();
        let desc = row.description.clone().unwrap_or_else(|| row.query.clone());
        let a = actions::alert(
            AlertKind::System,
            Severity::Medium,
            format!("Chasse osquery : {}", row.query),
            format!("{desc} — {summary}"),
        );
        actions::raise_alert(ctx, a, Some(format!("osquery:{}", row.query))).await;
    }
    if !baseline_done {
        let _ = ctx
            .store
            .run(move |s| s.kv_set(KV_OSQUERY_BASELINE, &now.to_string()))
            .await;
    }
}

/// Poll the power source every 5 minutes.
pub async fn battery_loop(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    loop {
        let b = crate::system::battery_state().await;
        let changed = {
            let mut st = ctx.state();
            let c = st.battery != b;
            st.battery = b;
            c
        };
        if changed {
            ctx.status_dirty.notify_one();
            ctx.jobs.poke();
        }
        tokio::select! {
            _ = tokio::time::sleep(BATTERY_INTERVAL) => {}
            _ = shutdown.changed() => if *shutdown.borrow() { break; },
        }
    }
}

/// First run: install missing required components (after 5 minutes, respecting the battery).
pub async fn bootstrap_components(ctx: Arc<Ctx>) {
    if ctx
        .store
        .run(|s| s.kv_get(KV_COMPONENTS_BOOTSTRAP))
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return;
    }
    let mut shutdown = ctx.shutdown_rx();
    tokio::select! {
        _ = tokio::time::sleep(BOOTSTRAP_DELAY) => {}
        _ = shutdown.changed() => return,
    }
    if !wait_for_power(&ctx, MAX_BATTERY_DEFERRAL).await {
        return;
    }
    let cfg = ctx.config();
    let mut all_ok = true;
    for c in ctx.backends.updater.list_components(&ctx.config()).await {
        if !(c.required && c.state == ComponentState::NotInstalled) {
            continue;
        }
        tracing::info!(component = %c.name, "installing required component");
        match ctx.backends.updater.install_component(&c.name, &cfg).await {
            Ok(st) => ctx.bus.publish(DaemonEvent::Component(st)),
            Err(e) => {
                all_ok = false;
                tracing::warn!(component = %c.name, error = %e, "component install failed");
            }
        }
    }
    if all_ok {
        let now = pb_core::now_ts().to_string();
        let _ = ctx
            .store
            .run(move |s| s.kv_set(KV_COMPONENTS_BOOTSTRAP, &now))
            .await;
    }
    ctx.status_dirty.notify_one();
}

/// Hourly: record DNS blocked-query counters for the weekly report.
pub async fn dns_stats_loop(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(3600)) => {}
            _ = shutdown.changed() => if *shutdown.borrow() { break; },
        }
        let cfg = ctx.config();
        if !cfg.dns.enabled {
            continue;
        }
        if let Some(n) = ctx.backends.dns.status(&cfg).await.queries_blocked_24h {
            let date = crate::system::local_date(pb_core::now_ts());
            let _ = ctx
                .store
                .run(move |s| s.max_daily(&date, StatField::DnsBlocked, n))
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn daily_schedule() {
        let now = Utc.with_ymd_and_hms(2026, 10, 25, 2, 0, 0).unwrap();
        assert_eq!(
            next_daily(&now, 3, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 25, 3, 0, 0).unwrap()
        );
        assert_eq!(
            next_daily(&now, 3, 600).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 25, 3, 10, 0).unwrap()
        );
        let later = Utc.with_ymd_and_hms(2026, 10, 25, 3, 0, 0).unwrap();
        assert_eq!(
            next_daily(&later, 3, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 26, 3, 0, 0).unwrap()
        );
        assert_eq!(
            next_daily(&later, 3, 60).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 25, 3, 1, 0).unwrap()
        );
        assert_eq!(
            next_daily(&now, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 26, 0, 0, 0).unwrap()
        );
    }

    #[test]
    fn jitter_range() {
        for _ in 0..100 {
            let j = jitter(1200);
            assert!((0..1200).contains(&j));
        }
        assert_eq!(jitter(0), 0);
    }

    #[test]
    fn row_hashes_are_stable_and_distinct() {
        let mut a = std::collections::BTreeMap::new();
        a.insert("path".to_string(), "/x".to_string());
        let mut b = a.clone();
        b.insert("pid".to_string(), "1".to_string());
        assert_eq!(row_hash("q", &a), row_hash("q", &a.clone()));
        assert_ne!(row_hash("q", &a), row_hash("q", &b));
        assert_ne!(row_hash("q", &a), row_hash("r", &a));
    }
}
