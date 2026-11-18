//! Activity reports: week (Monday 00:00 local time → next Monday 00:00), month (1st 00:00 → next 1st) or a
//! custom range of days; plus the background task that samples VPN uptime / leak tests for them and
//! announces the monthly report on the 1st.

use crate::ctx::Ctx;
use crate::store::{Store, StoreError};
use chrono::{DateTime, Datelike, Days, Local, Months, NaiveDate, TimeZone, Timelike};
use pb_core::ipc::{DaemonEvent, ErrorCode, IpcError};
use pb_core::model::*;
use std::sync::Arc;
use std::time::Duration;

/// Max weeks back.
pub const MAX_WEEK_OFFSET: u32 = 520;
/// Max months back.
pub const MAX_MONTH_OFFSET: u32 = 120;
/// Longest custom range (daily stats are kept 400 days).
pub const MAX_CUSTOM_DAYS: i64 = 400;
/// Named counters of `daily_counters`.
pub const COUNTER_VPN_SECS: &str = "vpn_connected_secs";
pub const COUNTER_LEAK_TESTS: &str = "leak_tests";
pub const COUNTER_LEAK_FAILED: &str = "leak_tests_failed";
/// kv: month (`YYYY-MM`) whose report was last announced.
pub const KV_MONTHLY_SENT: &str = "report_monthly_sent";
/// kv: timestamp of the last leak test counted.
pub const KV_LAST_LEAK_TS: &str = "report_last_leak_ts";
/// Sampling period of the report task (also the wall-clock check of the monthly announcement).
pub const REPORT_TICK: Duration = Duration::from_secs(10 * 60);
/// A gap longer than this between two VPN samples is not counted (the Mac was asleep).
pub const MAX_UPTIME_GAP: i64 = 15 * 60;
/// The monthly report is announced from this local hour on the 1st (or later if the Mac was off).
pub const MONTHLY_ANNOUNCE_HOUR: u32 = 9;

fn local_midnight<Tz: TimeZone>(tz: &Tz, d: NaiveDate) -> Option<DateTime<Tz>> {
    // Midnight may not exist on DST days in some zones: fall back to the first valid hour.
    (0..4).find_map(|h| {
        d.and_hms_opt(h, 0, 0)
            .and_then(|n| tz.from_local_datetime(&n).earliest())
    })
}

/// `[start, end)` Unix timestamps + ISO dates of the week `offset` weeks before the one containing `now`.
pub fn week_bounds<Tz: TimeZone>(
    now: &DateTime<Tz>,
    offset: u32,
) -> Option<(i64, i64, String, String)> {
    let tz = now.timezone();
    let today = now.date_naive();
    let monday =
        today.checked_sub_days(Days::new(u64::from(today.weekday().num_days_from_monday())))?;
    let start_day = monday.checked_sub_days(Days::new(7 * u64::from(offset)))?;
    let end_day = start_day.checked_add_days(Days::new(7))?;
    let start = local_midnight(&tz, start_day)?.timestamp();
    let end = local_midnight(&tz, end_day)?.timestamp();
    Some((
        start,
        end,
        start_day.format("%Y-%m-%d").to_string(),
        end_day.format("%Y-%m-%d").to_string(),
    ))
}

/// Period resolved to timestamps and dates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bounds {
    pub start: i64,
    pub end: i64,
    /// First day (inclusive) and day after the last one (exclusive), `YYYY-MM-DD`.
    pub from_date: String,
    pub end_date: String,
    /// Last day (inclusive).
    pub last_date: String,
}

fn bounds_of<Tz: TimeZone>(tz: &Tz, first: NaiveDate, after_last: NaiveDate) -> Option<Bounds> {
    Some(Bounds {
        start: local_midnight(tz, first)?.timestamp(),
        end: local_midnight(tz, after_last)?.timestamp(),
        from_date: first.format("%Y-%m-%d").to_string(),
        end_date: after_last.format("%Y-%m-%d").to_string(),
        last_date: after_last.pred_opt()?.format("%Y-%m-%d").to_string(),
    })
}

/// Month `offset` months before the one containing `now`.
pub fn month_bounds<Tz: TimeZone>(now: &DateTime<Tz>, offset: u32) -> Option<Bounds> {
    let first = now
        .date_naive()
        .with_day(1)?
        .checked_sub_months(Months::new(offset))?;
    bounds_of(
        &now.timezone(),
        first,
        first.checked_add_months(Months::new(1))?,
    )
}

/// `from` → `to` inclusive (`YYYY-MM-DD`).
pub fn custom_bounds<Tz: TimeZone>(tz: &Tz, from: &str, to: &str) -> Result<Bounds, String> {
    let parse = |s: &str| {
        NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
            .map_err(|_| format!("date invalide : {s} (AAAA-MM-JJ attendu)"))
    };
    let (a, b) = (parse(from)?, parse(to)?);
    if b < a {
        return Err("la date de fin précède la date de début".into());
    }
    if (b - a).num_days() >= MAX_CUSTOM_DAYS {
        return Err(format!("période limitée à {MAX_CUSTOM_DAYS} jours"));
    }
    let after = b.succ_opt().ok_or("date hors limites")?;
    bounds_of(tz, a, after).ok_or_else(|| "calcul de la période impossible".into())
}

/// Resolve a period request against `now`.
pub fn resolve<Tz: TimeZone>(
    now: &DateTime<Tz>,
    period: ReportPeriod,
    offset: u32,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<Bounds, IpcError> {
    let bad = |m: String| IpcError::new(ErrorCode::BadRequest, m);
    let internal = || IpcError::new(ErrorCode::Internal, "calcul de la période impossible");
    match period {
        ReportPeriod::Week => {
            if offset > MAX_WEEK_OFFSET {
                return Err(bad("offset trop grand".into()));
            }
            let (start, end, from_date, end_date) =
                week_bounds(now, offset).ok_or_else(internal)?;
            let last_date = NaiveDate::parse_from_str(&end_date, "%Y-%m-%d")
                .ok()
                .and_then(|d| d.pred_opt())
                .map(|d| d.format("%Y-%m-%d").to_string())
                .ok_or_else(internal)?;
            Ok(Bounds {
                start,
                end,
                from_date,
                end_date,
                last_date,
            })
        }
        ReportPeriod::Month => {
            if offset > MAX_MONTH_OFFSET {
                return Err(bad("offset trop grand".into()));
            }
            month_bounds(now, offset).ok_or_else(internal)
        }
        ReportPeriod::Custom => {
            let (Some(f), Some(t)) = (from, to) else {
                return Err(bad("période personnalisée : from et to requis".into()));
            };
            custom_bounds(&now.timezone(), f, t).map_err(bad)
        }
    }
}

/// Everything the store knows about `b` (no daemon state): the core of [`build`], unit-tested.
pub fn aggregate(
    store: &Store,
    b: &Bounds,
    period: ReportPeriod,
) -> Result<ActivityReport, StoreError> {
    let (start, end) = (b.start, b.end);
    let totals = store.daily_totals(&b.from_date, &b.end_date)?;
    let updates = store.updates_between(start, end)?;
    let scans_by_origin = store.jobs_by_origin(start, end)?;
    let kinds = store.alerts_by_kind(start, end)?;
    let kind_count = |k: AlertKind| {
        let name = crate::store::enum_str(&k);
        kinds
            .iter()
            .find(|n| n.name == name)
            .map(|n| n.count)
            .unwrap_or(0)
    };
    let mut daily = store.daily_rows(&b.from_date, &b.end_date)?;
    let (mut vpn_secs, mut leak_tests, mut leak_failed) = (0u64, 0u64, 0u64);
    for (date, name, value) in store.counters_between(&b.from_date, &b.end_date)? {
        match name.as_str() {
            COUNTER_VPN_SECS => {
                vpn_secs += value;
                match daily.iter_mut().find(|d| d.date == date) {
                    Some(d) => d.vpn_connected_secs += value,
                    None => daily.push(ReportDay {
                        date,
                        vpn_connected_secs: value,
                        ..Default::default()
                    }),
                }
            }
            COUNTER_LEAK_TESTS => leak_tests += value,
            COUNTER_LEAK_FAILED => leak_failed += value,
            _ => {}
        }
    }
    daily.sort_by(|a, c| a.date.cmp(&c.date));
    let mut component_updates: Vec<String> = Vec::new();
    for u in updates
        .iter()
        .filter(|u| u.target == UpdateTarget::Components || u.target == UpdateTarget::App)
    {
        for m in &u.messages {
            if !component_updates.contains(m) && component_updates.len() < 50 {
                component_updates.push(m.clone());
            }
        }
    }
    Ok(ActivityReport {
        period,
        start,
        end,
        from_date: b.from_date.clone(),
        to_date: b.last_date.clone(),
        elapsed_secs: 0,
        generated_at: pb_core::now_ts(),
        files_scanned: totals.files_scanned,
        threats_detected: totals.threats,
        quarantined: totals.quarantined,
        false_positives_reported: store.count_false_positives(start, end)?,
        persistence_new: totals.persistence_new,
        devices_new: totals.devices_new,
        scans: scans_by_origin.iter().map(|n| n.count).sum(),
        scans_by_origin,
        top_detections: store.top_detections(start, end, 10)?,
        behavior_detections: kind_count(AlertKind::Behavior),
        db_updates: updates
            .iter()
            .filter(|u| u.ok && u.target == UpdateTarget::Db && u.new_db_version.is_some())
            .count() as u64,
        db_version: updates.iter().rev().find_map(|u| u.new_db_version.clone()),
        component_updates,
        dns_blocked_queries: (totals.dns_blocked > 0).then_some(totals.dns_blocked),
        top_blocked_domains: vec![],
        vpn_connected_secs: vpn_secs,
        leak_tests,
        leak_tests_failed: leak_failed,
        network_alerts: kind_count(AlertKind::Network),
        alerts_total: kinds.iter().map(|n| n.count).sum(),
        top_alert_kinds: kinds,
        privacy: None,
        removal_requests_sent: 0,
        removal_requests_completed: 0,
        breaches_found: 0,
        breach_names: vec![],
        daily,
    })
}

/// Fill the privacy part from the GDPR requests / breach findings.
pub fn add_privacy(
    r: &mut ActivityReport,
    summary: RemovalSummary,
    requests: &[RemovalRequest],
    breaches: &[BreachFinding],
) {
    let within = |t: Option<i64>| t.is_some_and(|t| t >= r.start && t < r.end);
    r.removal_requests_sent = requests.iter().filter(|q| within(q.sent_at)).count() as u64;
    r.removal_requests_completed = requests
        .iter()
        .filter(|q| q.status == RemovalStatus::Completed && within(q.closed_at))
        .count() as u64;
    let mut names: Vec<String> = Vec::new();
    let mut found = 0u64;
    for b in breaches.iter().filter(|b| within(Some(b.first_seen))) {
        found += 1;
        if !names.contains(&b.breach) && names.len() < 20 {
            names.push(b.breach.clone());
        }
    }
    r.breaches_found = found;
    r.breach_names = names;
    r.privacy = (summary.total > 0).then_some(summary);
}

/// Build the report of a period (IPC `report`).
pub async fn build(
    ctx: &Arc<Ctx>,
    period: ReportPeriod,
    offset: u32,
    from: Option<String>,
    to: Option<String>,
) -> Result<ActivityReport, IpcError> {
    let now = Local::now();
    let b = resolve(&now, period, offset, from.as_deref(), to.as_deref())?;
    let b2 = b.clone();
    let mut r = ctx.store.run(move |s| aggregate(s, &b2, period)).await?;
    let now_ts = now.timestamp();
    r.elapsed_secs = (r.end.min(now_ts) - r.start).max(0) as u64;
    let current = r.start <= now_ts && now_ts < r.end;
    if r.db_version.is_none() && current {
        r.db_version = ctx.engine().db_status().version;
    }
    if ctx.config().dns.enabled && r.dns_blocked_queries.is_none() {
        r.dns_blocked_queries = Some(0);
    }
    let dir = ctx.paths.dns_dir().join(pb_dns::RUNTIME_DIR);
    let (start, end) = (r.start, r.end);
    r.top_blocked_domains = tokio::task::spawn_blocking(move || {
        pb_dns::querylog::top_blocked_between(&dir, pb_dns::BLOCKED_LOG_FILE, start, end, 10)
    })
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(name, count)| NamedCount { name, count })
    .collect();
    if let Ok(svc) = crate::privacy::service(ctx) {
        let cfg = ctx.config();
        let summary = svc.summary(&cfg).await;
        let requests = svc.requests().await;
        let breaches = svc.breaches().await;
        add_privacy(&mut r, summary, &requests, &breaches);
    }
    Ok(r)
}

/// Build the report of week `offset` (0 = current week): the historical `weekly_report` shape.
pub async fn weekly(ctx: &Arc<Ctx>, offset: u32) -> Result<WeeklyReport, IpcError> {
    let r = build(ctx, ReportPeriod::Week, offset, None, None).await?;
    Ok(WeeklyReport {
        week_start: r.start,
        week_end: r.end,
        files_scanned: r.files_scanned,
        threats_detected: r.threats_detected,
        quarantined: r.quarantined,
        false_positives_reported: r.false_positives_reported,
        persistence_new: r.persistence_new,
        devices_new: r.devices_new,
        db_updates: r.db_updates,
        db_version: r.db_version,
        component_updates: r.component_updates,
        top_detections: r.top_detections,
        dns_blocked_queries: r.dns_blocked_queries,
    })
}

// ---------------------------------------------------------------------------------------------
// Background task: VPN uptime / leak test sampling, monthly announcement
// ---------------------------------------------------------------------------------------------

/// Turns VPN state samples into connected seconds (gaps longer than [`MAX_UPTIME_GAP`] are dropped:
/// timers stop while the Mac sleeps, the tunnel did not carry traffic then).
#[derive(Debug, Default, Clone)]
pub struct UptimeMeter {
    last: Option<(i64, bool)>,
}

impl UptimeMeter {
    /// Record a sample; returns the seconds to credit since the previous one.
    pub fn observe(&mut self, now: i64, connected: bool) -> u64 {
        let credit = match self.last {
            Some((t, true)) if now > t => (now - t).min(MAX_UPTIME_GAP) as u64,
            _ => 0,
        };
        // A clock going backwards restarts the measure.
        self.last = Some((now, connected));
        credit
    }
}

/// French "d'octobre" / "de novembre".
pub fn month_phrase(month: u32) -> String {
    const NAMES: [&str; 12] = [
        "janvier",
        "février",
        "mars",
        "avril",
        "mai",
        "juin",
        "juillet",
        "août",
        "septembre",
        "octobre",
        "novembre",
        "décembre",
    ];
    let name = NAMES[(month.clamp(1, 12) - 1) as usize];
    if name.starts_with(['a', 'o']) {
        format!("d'{name}")
    } else {
        format!("de {name}")
    }
}

/// `12345` -> `12 345`.
pub fn fr_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push('\u{202f}');
        }
        out.push(c);
    }
    out
}

/// Month to announce now, if any: the previous month (`YYYY-MM`, its month number) when it was not
/// announced yet, it is at least [`MONTHLY_ANNOUNCE_HOUR`], and the daemon already ran before this month.
pub fn monthly_due<Tz: TimeZone>(
    now: &DateTime<Tz>,
    last_sent: Option<&str>,
    first_run: Option<i64>,
) -> Option<(String, u32)> {
    if now.hour() < MONTHLY_ANNOUNCE_HOUR && now.day() == 1 {
        return None;
    }
    let this_month = month_bounds(now, 0)?;
    if first_run.is_some_and(|t| t >= this_month.start) {
        return None;
    }
    let prev = now.date_naive().with_day(1)?.pred_opt()?;
    let key = prev.format("%Y-%m").to_string();
    (last_sent != Some(key.as_str())).then_some((key, prev.month()))
}

/// The alert announcing the report of `month` (`YYYY-MM`).
pub fn monthly_alert(key: &str, month: u32, r: &ActivityReport) -> Alert {
    let mut parts = vec![
        format!("{} fichiers analysés", fr_count(r.files_scanned)),
        match r.threats_detected {
            0 => "aucune menace".to_string(),
            1 => "1 menace".to_string(),
            n => format!("{} menaces", fr_count(n)),
        },
    ];
    if let Some(n) = r.dns_blocked_queries.filter(|n| *n > 0) {
        parts.push(format!("{} publicités et traqueurs bloqués", fr_count(n)));
    }
    let mut a = crate::actions::alert(
        AlertKind::System,
        Severity::Info,
        format!("Ton rapport {} est prêt", month_phrase(month)),
        format!(
            "{}. Ouvre-le pour le détail et l'export PDF.",
            parts.join(", ")
        ),
    );
    a.open_section = Some(format!("report?period=month&month={key}"));
    a
}

/// Credit VPN uptime and count new leak tests from a status.
async fn record_vpn(ctx: &Arc<Ctx>, st: &VpnStatus, meter: &mut UptimeMeter, last_leak: &mut i64) {
    let now = pb_core::now_ts();
    let credit = meter.observe(now, st.state == VpnState::Connected);
    let date = crate::system::local_date(now);
    let leak = st
        .last_leak_test
        .as_ref()
        .filter(|t| t.ts > *last_leak)
        .map(|t| (t.ts, t.ok));
    if credit == 0 && leak.is_none() {
        return;
    }
    if let Some((ts, _)) = leak {
        *last_leak = ts;
    }
    let res = ctx
        .store
        .run(move |s| {
            s.bump_counter(&date, COUNTER_VPN_SECS, credit)?;
            if let Some((ts, ok)) = leak {
                s.bump_counter(&date, COUNTER_LEAK_TESTS, 1)?;
                s.bump_counter(&date, COUNTER_LEAK_FAILED, u64::from(!ok))?;
                s.kv_set(KV_LAST_LEAK_TS, &ts.to_string())?;
            }
            Ok(())
        })
        .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, "report counters update failed");
    }
}

/// Announce last month's report once (1st of the month, from 09:00, or after wake-up).
async fn maybe_announce(ctx: &Arc<Ctx>) {
    let now = Local::now();
    let (last, first_run) = ctx
        .store
        .run(|s| {
            Ok((
                s.kv_get(KV_MONTHLY_SENT)?,
                s.kv_get_i64(crate::scheduler::KV_FIRST_RUN)?,
            ))
        })
        .await
        .unwrap_or((None, None));
    let Some((key, month)) = monthly_due(&now, last.as_deref(), first_run) else {
        return;
    };
    let Ok(r) = build(ctx, ReportPeriod::Month, 1, None, None).await else {
        return;
    };
    let alert = monthly_alert(&key, month, &r);
    if crate::actions::raise_alert(ctx, alert, Some(format!("report:{key}")))
        .await
        .is_some()
    {
        let _ = ctx
            .store
            .run(move |s| s.kv_set(KV_MONTHLY_SENT, &key))
            .await;
    }
}

/// Report task: samples the VPN every [`REPORT_TICK`] and on every VPN event, announces monthly reports.
pub async fn monthly_loop(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    let mut events = Some(ctx.bus.subscribe());
    let mut meter = UptimeMeter::default();
    let mut last_leak = ctx
        .store
        .run(|s| s.kv_get_i64(KV_LAST_LEAK_TS))
        .await
        .ok()
        .flatten()
        .unwrap_or(0);
    // First announcement check shortly after start (the Mac may have been off on the 1st).
    let mut wait = Duration::from_secs(90);
    loop {
        let next_event = async {
            match events.as_mut() {
                Some(rx) => Some(rx.recv().await),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {
                wait = REPORT_TICK;
                if let Ok(svc) = crate::vpn::service(&ctx) {
                    let st = svc.status().await;
                    record_vpn(&ctx, &st, &mut meter, &mut last_leak).await;
                }
                maybe_announce(&ctx).await;
            }
            ev = next_event => match ev {
                Some(Ok(DaemonEvent::Vpn(st))) => record_vpn(&ctx, &st, &mut meter, &mut last_leak).await,
                Some(Err(tokio::sync::broadcast::error::RecvError::Closed)) => events = None,
                _ => {}
            },
            _ = shutdown.changed() => if *shutdown.borrow() { break; },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{FixedOffset, Utc};

    #[test]
    fn monday_to_monday() {
        // Wednesday 2026-10-28 15:00 UTC.
        let now = Utc.with_ymd_and_hms(2026, 10, 28, 15, 0, 0).unwrap();
        let (s, e, fd, td) = week_bounds(&now, 0).unwrap();
        assert_eq!(fd, "2026-10-26");
        assert_eq!(td, "2026-11-02");
        assert_eq!(
            s,
            Utc.with_ymd_and_hms(2026, 10, 26, 0, 0, 0)
                .unwrap()
                .timestamp()
        );
        assert_eq!(e - s, 7 * 86_400);
        let (_, _, fd1, td1) = week_bounds(&now, 1).unwrap();
        assert_eq!((fd1.as_str(), td1.as_str()), ("2026-10-19", "2026-10-26"));
        // A Monday belongs to its own week.
        let monday = Utc.with_ymd_and_hms(2026, 10, 26, 0, 0, 1).unwrap();
        assert_eq!(week_bounds(&monday, 0).unwrap().2, "2026-10-26");
        // Sunday night belongs to the previous Monday.
        let sunday = Utc.with_ymd_and_hms(2026, 11, 1, 23, 59, 0).unwrap();
        assert_eq!(week_bounds(&sunday, 0).unwrap().2, "2026-10-26");
    }

    #[test]
    fn honours_timezone() {
        let paris = FixedOffset::east_opt(3600).unwrap();
        let now = paris.with_ymd_and_hms(2026, 10, 26, 0, 30, 0).unwrap();
        let (s, _, fd, _) = week_bounds(&now, 0).unwrap();
        assert_eq!(fd, "2026-10-26");
        assert_eq!(
            s,
            Utc.with_ymd_and_hms(2026, 10, 25, 23, 0, 0)
                .unwrap()
                .timestamp()
        );
    }

    #[test]
    fn month_and_custom_bounds() {
        let now = Utc.with_ymd_and_hms(2026, 11, 14, 10, 0, 0).unwrap();
        let b = month_bounds(&now, 0).unwrap();
        assert_eq!(
            (b.from_date.as_str(), b.last_date.as_str()),
            ("2026-11-01", "2026-11-30")
        );
        assert_eq!(b.end_date, "2026-12-01");
        assert_eq!(b.end - b.start, 30 * 86_400);
        let b = month_bounds(&now, 1).unwrap();
        assert_eq!(
            (b.from_date.as_str(), b.last_date.as_str()),
            ("2026-10-01", "2026-10-31")
        );
        let b = month_bounds(&now, 11).unwrap();
        assert_eq!(b.from_date, "2025-12-01");
        let b = custom_bounds(&Utc, "2026-10-01", "2026-10-01").unwrap();
        assert_eq!(b.end - b.start, 86_400);
        assert_eq!(b.last_date, "2026-10-01");
        assert!(custom_bounds(&Utc, "2026-10-02", "2026-10-01").is_err());
        assert!(custom_bounds(&Utc, "2026-13-01", "2026-10-01").is_err());
        assert!(custom_bounds(&Utc, "2025-01-01", "2026-10-01").is_err());
        let e = resolve(&now, ReportPeriod::Custom, 0, Some("2026-10-01"), None).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadRequest);
        let e = resolve(&now, ReportPeriod::Month, MAX_MONTH_OFFSET + 1, None, None).unwrap_err();
        assert_eq!(e.code, ErrorCode::BadRequest);
        let w = resolve(&now, ReportPeriod::Week, 0, None, None).unwrap();
        assert_eq!(
            (w.from_date.as_str(), w.last_date.as_str()),
            ("2026-11-09", "2026-11-15")
        );
    }

    fn job(id: &str, origin: ScanOrigin, started: i64) -> ScanJobSummary {
        ScanJobSummary {
            job_id: id.into(),
            origin,
            paths: vec![],
            state: JobState::Finished,
            started_at: started,
            finished_at: Some(started + 1),
            files_scanned: 1,
            bytes_scanned: 1,
            threats: 0,
            errors: 0,
            current_path: None,
        }
    }

    #[test]
    fn aggregates_a_month() {
        let s = Store::open_in_memory().unwrap();
        let b = custom_bounds(&Utc, "2026-10-01", "2026-10-31").unwrap();
        let t = b.start + 3600;
        use crate::store::StatField;
        s.bump_daily("2026-10-02", StatField::FilesScanned, 100)
            .unwrap();
        s.bump_daily("2026-10-03", StatField::Threats, 2).unwrap();
        s.bump_daily("2026-10-03", StatField::Quarantined, 1)
            .unwrap();
        s.max_daily("2026-10-03", StatField::DnsBlocked, 50)
            .unwrap();
        s.bump_daily("2026-11-01", StatField::FilesScanned, 999)
            .unwrap();
        s.bump_counter("2026-10-02", COUNTER_VPN_SECS, 600).unwrap();
        s.bump_counter("2026-10-02", COUNTER_VPN_SECS, 600).unwrap();
        s.bump_counter("2026-10-05", COUNTER_VPN_SECS, 300).unwrap();
        s.bump_counter("2026-10-05", COUNTER_LEAK_TESTS, 2).unwrap();
        s.bump_counter("2026-10-05", COUNTER_LEAK_FAILED, 1)
            .unwrap();
        s.bump_counter("2026-09-30", COUNTER_LEAK_TESTS, 7).unwrap();
        s.upsert_job(&job("a", ScanOrigin::Manual, t)).unwrap();
        s.upsert_job(&job("b", ScanOrigin::Realtime, t)).unwrap();
        s.upsert_job(&job("c", ScanOrigin::Realtime, t + 5))
            .unwrap();
        s.upsert_job(&job("d", ScanOrigin::Manual, b.end + 1))
            .unwrap();
        let mk = |kind, ts| {
            let mut a = crate::actions::alert(kind, Severity::High, "t", "m");
            a.ts = ts;
            a
        };
        s.insert_alert(&mk(AlertKind::Malware, t), Some("MacOS.Stealer.AMOS"))
            .unwrap();
        s.insert_alert(&mk(AlertKind::Network, t), None).unwrap();
        s.insert_alert(&mk(AlertKind::Network, t + 1), None)
            .unwrap();
        s.insert_alert(&mk(AlertKind::Behavior, t), None).unwrap();
        s.insert_alert(&mk(AlertKind::Network, b.start - 1), None)
            .unwrap();
        s.add_false_positive(&"a".repeat(64), None, None, t)
            .unwrap();
        s.log_update(&UpdateResult {
            target: UpdateTarget::Db,
            ok: true,
            started_at: t,
            finished_at: t,
            messages: vec![],
            new_db_version: Some("2026.10.04.1".into()),
        })
        .unwrap();
        let r = aggregate(&s, &b, ReportPeriod::Custom).unwrap();
        assert_eq!(r.files_scanned, 100);
        assert_eq!((r.threats_detected, r.quarantined), (2, 1));
        assert_eq!(r.dns_blocked_queries, Some(50));
        assert_eq!(r.vpn_connected_secs, 1500);
        assert_eq!((r.leak_tests, r.leak_tests_failed), (2, 1));
        assert_eq!(r.scans, 3);
        assert_eq!(
            r.scans_by_origin[0],
            NamedCount {
                name: "realtime".into(),
                count: 2
            }
        );
        assert_eq!(r.alerts_total, 4);
        assert_eq!(r.network_alerts, 2);
        assert_eq!(r.behavior_detections, 1);
        assert_eq!(r.top_alert_kinds[0].name, "network");
        assert_eq!(r.top_detections[0].name, "MacOS.Stealer.AMOS");
        assert_eq!(r.false_positives_reported, 1);
        assert_eq!(r.db_updates, 1);
        assert_eq!(r.db_version.as_deref(), Some("2026.10.04.1"));
        let dates: Vec<&str> = r.daily.iter().map(|d| d.date.as_str()).collect();
        assert_eq!(dates, ["2026-10-02", "2026-10-03", "2026-10-05"]);
        assert_eq!(r.daily[0].vpn_connected_secs, 1200);
        assert_eq!(r.daily[2].vpn_connected_secs, 300);
        assert_eq!(
            (r.from_date.as_str(), r.to_date.as_str()),
            ("2026-10-01", "2026-10-31")
        );
        // empty period
        let e = custom_bounds(&Utc, "2025-01-01", "2025-01-31").unwrap();
        let r = aggregate(&s, &e, ReportPeriod::Custom).unwrap();
        assert_eq!(
            (r.scans, r.alerts_total, r.dns_blocked_queries),
            (0, 0, None)
        );
        assert!(r.daily.is_empty());
    }

    #[test]
    fn privacy_part() {
        let mut r = ActivityReport {
            start: 100,
            end: 200,
            ..Default::default()
        };
        let req = |sent: Option<i64>, closed: Option<i64>, status| RemovalRequest {
            id: "r".into(),
            broker_id: "b".into(),
            broker_name: "B".into(),
            broker_email: None,
            status,
            created_at: 0,
            sent_at: sent,
            due_at: None,
            reminded_at: None,
            closed_at: closed,
            opt_out_url: None,
            draft_path: None,
            note: None,
            last_error: None,
        };
        let breach = |name: &str, seen| BreachFinding {
            email: "camille.martin@example.com".into(),
            breach: name.into(),
            breach_date: None,
            data_classes: vec![],
            first_seen: seen,
            new: false,
        };
        add_privacy(
            &mut r,
            RemovalSummary {
                total: 3,
                completed: 1,
                ..Default::default()
            },
            &[
                req(Some(150), Some(160), RemovalStatus::Completed),
                req(Some(50), Some(199), RemovalStatus::Completed),
                req(Some(120), None, RemovalStatus::Sent),
                req(Some(210), Some(210), RemovalStatus::Completed),
            ],
            &[breach("A", 150), breach("A", 160), breach("B", 300)],
        );
        assert_eq!(r.removal_requests_sent, 2);
        assert_eq!(r.removal_requests_completed, 2);
        assert_eq!(r.breaches_found, 2);
        assert_eq!(r.breach_names, ["A"]);
        assert_eq!(r.privacy.as_ref().unwrap().total, 3);
        add_privacy(&mut r, RemovalSummary::default(), &[], &[]);
        assert!(r.privacy.is_none());
    }

    #[test]
    fn uptime_meter() {
        let mut m = UptimeMeter::default();
        assert_eq!(m.observe(1000, true), 0);
        assert_eq!(m.observe(1600, true), 600);
        assert_eq!(m.observe(1700, false), 100);
        assert_eq!(m.observe(2300, true), 0);
        // asleep for hours: capped
        assert_eq!(m.observe(2300 + 5 * 3600, true), MAX_UPTIME_GAP as u64);
        // clock going backwards
        assert_eq!(m.observe(100, true), 0);
        assert_eq!(m.observe(160, true), 60);
    }

    #[test]
    fn monthly_announcement() {
        let at = |d, h| Utc.with_ymd_and_hms(2026, 11, d, h, 0, 0).unwrap();
        let first_run = Some(
            Utc.with_ymd_and_hms(2026, 9, 1, 0, 0, 0)
                .unwrap()
                .timestamp(),
        );
        assert_eq!(monthly_due(&at(1, 8), None, first_run), None);
        assert_eq!(
            monthly_due(&at(1, 9), None, first_run),
            Some(("2026-10".to_string(), 10))
        );
        assert_eq!(monthly_due(&at(1, 9), Some("2026-10"), first_run), None);
        // Mac off on the 1st: announced later, any hour.
        assert_eq!(
            monthly_due(&at(3, 7), Some("2026-09"), first_run),
            Some(("2026-10".to_string(), 10))
        );
        // Installed this month: nothing to report.
        let new_install = Some(at(1, 2).timestamp());
        assert_eq!(monthly_due(&at(5, 12), None, new_install), None);
        assert!(monthly_due(&at(5, 12), None, None).is_some());
        let jan = Utc.with_ymd_and_hms(2027, 1, 1, 10, 0, 0).unwrap();
        assert_eq!(
            monthly_due(&jan, None, None),
            Some(("2026-12".to_string(), 12))
        );
        assert_eq!(month_phrase(10), "d'octobre");
        assert_eq!(month_phrase(8), "d'août");
        assert_eq!(month_phrase(4), "d'avril");
        assert_eq!(month_phrase(11), "de novembre");
        assert_eq!(fr_count(0), "0");
        assert_eq!(fr_count(999), "999");
        assert_eq!(fr_count(1234567), "1\u{202f}234\u{202f}567");
        let r = ActivityReport {
            files_scanned: 15_234,
            threats_detected: 0,
            dns_blocked_queries: Some(40_211),
            ..Default::default()
        };
        let a = monthly_alert("2026-10", 10, &r);
        assert_eq!(a.title, "Ton rapport d'octobre est prêt");
        assert!(a.message.contains("aucune menace"), "{}", a.message);
        assert!(a.message.contains("40\u{202f}211"));
        assert_eq!(a.kind, AlertKind::System);
        assert_eq!(a.severity, Severity::Info);
        assert_eq!(
            a.open_section.as_deref(),
            Some("report?period=month&month=2026-10")
        );
    }
}
