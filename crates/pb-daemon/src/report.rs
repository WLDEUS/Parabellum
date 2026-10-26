//! Weekly report (week = Monday 00:00 local time → next Monday 00:00).

use crate::ctx::Ctx;
use chrono::{DateTime, Datelike, Days, Local, NaiveDate, TimeZone};
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::*;
use std::sync::Arc;

/// Max weeks back.
pub const MAX_WEEK_OFFSET: u32 = 520;

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

/// Build the report of week `offset` (0 = current week).
pub async fn weekly(ctx: &Arc<Ctx>, offset: u32) -> Result<WeeklyReport, IpcError> {
    if offset > MAX_WEEK_OFFSET {
        return Err(IpcError::new(
            ErrorCode::BadRequest,
            "week_offset trop grand",
        ));
    }
    let (start, end, from_date, to_date) = week_bounds(&Local::now(), offset)
        .ok_or_else(|| IpcError::new(ErrorCode::Internal, "calcul de la semaine impossible"))?;
    let (totals, fps, top, updates) = ctx
        .store
        .run(move |s| {
            Ok((
                s.daily_totals(&from_date, &to_date)?,
                s.count_false_positives(start, end)?,
                s.top_detections(start, end, 10)?,
                s.updates_between(start, end)?,
            ))
        })
        .await?;
    let db_updates = updates
        .iter()
        .filter(|u| u.ok && u.target == UpdateTarget::Db && u.new_db_version.is_some())
        .count() as u64;
    let db_version = updates
        .iter()
        .rev()
        .find_map(|u| u.new_db_version.clone())
        .or_else(|| {
            if offset == 0 {
                ctx.engine().db_status().version
            } else {
                None
            }
        });
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
    let dns_enabled = ctx.config().dns.enabled;
    Ok(WeeklyReport {
        week_start: start,
        week_end: end,
        files_scanned: totals.files_scanned,
        threats_detected: totals.threats,
        quarantined: totals.quarantined,
        false_positives_reported: fps,
        persistence_new: totals.persistence_new,
        devices_new: totals.devices_new,
        db_updates,
        db_version,
        component_updates,
        top_detections: top,
        dns_blocked_queries: (dns_enabled || totals.dns_blocked > 0).then_some(totals.dns_blocked),
    })
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
}
