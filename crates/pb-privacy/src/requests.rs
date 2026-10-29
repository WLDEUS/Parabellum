//! GDPR request lifecycle (pure functions; persistence and sending live in [`crate::PrivacyService`]).
//!
//! ```text
//! Queued ──(SMTP send / draft handed out)──> DraftReady ──(user: sent)──> Sent
//! Queued ──(SMTP send ok)──────────────────────────────────────────────> Sent
//! Queued ──(SMTP error, 3rd attempt)──> Failed            (earlier errors: stays Queued, retried next day)
//! Sent ──(due_at passed: reminder sent / user marks reminded)──> Reminded
//! Reminded ──(escalate_after_days passed)──> Escalated (alert: CNIL complaint)
//! any ──(user)──> Completed | Refused | NeedsForm | Sent | Reminded | Queued
//! Completed ──(repeat_every_days passed)──> new Queued request (brokers re-collect data)
//! no email ──> NeedsForm (web form, opt_out_url)
//! ```

use pb_core::model::{BrokerInfo, RemovalRequest, RemovalStatus, RemovalSummary};
use serde::{Deserialize, Serialize};

pub const DAY: i64 = 86_400;
/// Attempts before a sending error becomes `Failed`.
pub const MAX_ATTEMPTS: u32 = 3;
/// Minimum spacing between two emails.
pub const SEND_SPACING_SECS: i64 = 30;

/// A request plus the bookkeeping the IPC model does not expose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRequest {
    #[serde(flatten)]
    pub req: RemovalRequest,
    /// Broker region (`eu`, `global`, `us`) and website, for the letter language and the complaint.
    #[serde(default)]
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    /// Failed sending attempts of the current letter.
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_attempt_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escalated_at: Option<i64>,
}

/// `requests.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RequestsFile {
    pub format: u32,
    pub requests: Vec<StoredRequest>,
    /// Last day (`YYYY-MM-DD`, local) a "reminders ready" alert was raised (drafts mode).
    pub reminders_alerted_day: String,
}

/// `outbox.json`: daily quota.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Outbox {
    /// Local day the counter belongs to.
    pub day: String,
    pub sent: u32,
    pub last_sent_at: i64,
}

impl Outbox {
    /// Sent today (0 when `day` is another day).
    pub fn sent_today(&self, today: &str) -> u32 {
        if self.day == today {
            self.sent
        } else {
            0
        }
    }

    pub fn can_send(&self, today: &str, now: i64, max_per_day: u32) -> bool {
        self.sent_today(today) < max_per_day && now - self.last_sent_at >= SEND_SPACING_SECS
    }

    pub fn record(&mut self, today: &str, now: i64) {
        if self.day != today {
            self.day = today.to_string();
            self.sent = 0;
        }
        self.sent += 1;
        self.last_sent_at = now;
    }

    /// When the next email may leave (`next_day_start` = start of the next local day).
    pub fn next_send_at(
        &self,
        today: &str,
        now: i64,
        max_per_day: u32,
        next_day_start: i64,
    ) -> i64 {
        if self.sent_today(today) >= max_per_day {
            next_day_start
        } else {
            now.max(self.last_sent_at + SEND_SPACING_SECS)
        }
    }
}

/// Open = still in progress (not completed, refused or failed for good).
pub fn is_open(s: RemovalStatus) -> bool {
    !matches!(
        s,
        RemovalStatus::Completed | RemovalStatus::Refused | RemovalStatus::Failed
    )
}

fn new_request(b: &BrokerInfo, now: i64) -> StoredRequest {
    let status = if b.email.is_some() {
        RemovalStatus::Queued
    } else {
        RemovalStatus::NeedsForm
    };
    StoredRequest {
        req: RemovalRequest {
            id: uuid::Uuid::new_v4().to_string(),
            broker_id: b.id.clone(),
            broker_name: b.name.clone(),
            broker_email: b.email.clone(),
            status,
            created_at: now,
            sent_at: None,
            due_at: None,
            reminded_at: None,
            closed_at: None,
            opt_out_url: b.opt_out_url.clone(),
            draft_path: None,
            note: None,
            last_error: None,
        },
        region: b.region.clone(),
        website: b.website.clone(),
        attempts: 0,
        next_attempt_at: None,
        escalated_at: None,
    }
}

/// New requests for every broker (or only `only`) that has no open request.
pub fn plan(
    existing: &[StoredRequest],
    brokers: &[BrokerInfo],
    only: Option<&[String]>,
    now: i64,
) -> Vec<StoredRequest> {
    brokers
        .iter()
        .filter(|b| only.is_none_or(|ids| ids.iter().any(|i| i == &b.id)))
        .filter(|b| {
            !existing
                .iter()
                .any(|r| r.req.broker_id == b.id && is_open(r.req.status))
        })
        .map(|b| new_request(b, now))
        .collect()
}

/// The letter was sent (by the daemon or by the user from a draft).
pub fn mark_sent(r: &mut StoredRequest, now: i64, reminder_after_days: u32) {
    r.req.status = RemovalStatus::Sent;
    r.req.sent_at = Some(now);
    r.req.due_at = Some(now + i64::from(reminder_after_days) * DAY);
    r.req.reminded_at = None;
    r.req.closed_at = None;
    r.req.last_error = None;
    r.attempts = 0;
    r.next_attempt_at = None;
    r.escalated_at = None;
}

pub fn mark_reminded(r: &mut StoredRequest, now: i64) {
    r.req.status = RemovalStatus::Reminded;
    r.req.reminded_at = Some(now);
    r.req.last_error = None;
    r.attempts = 0;
    r.next_attempt_at = None;
}

/// A sending error: retried the next day, `Failed` after [`MAX_ATTEMPTS`].
pub fn mark_send_error(r: &mut StoredRequest, now: i64, error: &str) {
    r.attempts += 1;
    r.req.last_error = Some(error.chars().take(500).collect());
    if r.attempts >= MAX_ATTEMPTS {
        r.req.status = RemovalStatus::Failed;
        r.req.closed_at = Some(now);
        r.next_attempt_at = None;
    } else {
        r.next_attempt_at = Some(now + DAY);
    }
}

/// Retry delay elapsed (or no error yet).
pub fn retry_ready(r: &StoredRequest, now: i64) -> bool {
    r.next_attempt_at.is_none_or(|t| t <= now)
}

/// The initial letter must leave (SMTP mode).
pub fn wants_initial(r: &StoredRequest, now: i64) -> bool {
    r.req.status == RemovalStatus::Queued && r.req.broker_email.is_some() && retry_ready(r, now)
}

/// The one-month deadline passed without an answer.
pub fn is_overdue(r: &StoredRequest, now: i64) -> bool {
    r.req.status == RemovalStatus::Sent && r.req.due_at.is_some_and(|d| d <= now)
}

/// The reminder must leave (SMTP mode).
pub fn wants_reminder(r: &StoredRequest, now: i64) -> bool {
    is_overdue(r, now) && r.req.broker_email.is_some() && retry_ready(r, now)
}

/// Reminded and still unanswered after `escalate_after_days`.
pub fn needs_escalation(r: &StoredRequest, now: i64, escalate_after_days: u32) -> bool {
    r.req.status == RemovalStatus::Reminded
        && r.req
            .reminded_at
            .is_some_and(|t| t + i64::from(escalate_after_days) * DAY <= now)
}

pub fn mark_escalated(r: &mut StoredRequest, now: i64) {
    r.req.status = RemovalStatus::Escalated;
    r.escalated_at = Some(now);
}

/// Completed long enough ago to send a new request.
pub fn due_for_repeat(r: &StoredRequest, now: i64, repeat_every_days: u32) -> bool {
    repeat_every_days > 0
        && r.req.status == RemovalStatus::Completed
        && r.req
            .closed_at
            .is_some_and(|t| t + i64::from(repeat_every_days) * DAY <= now)
}

/// Apply a status recorded by the user (`privacy_update_request`).
pub fn apply_user_update(
    r: &mut StoredRequest,
    status: RemovalStatus,
    note: Option<String>,
    now: i64,
    reminder_after_days: u32,
) {
    if let Some(n) = note {
        let n: String = n
            .chars()
            .filter(|c| !c.is_control() || *c == '\n')
            .take(2000)
            .collect();
        r.req.note = if n.trim().is_empty() { None } else { Some(n) };
    }
    match status {
        RemovalStatus::Sent => mark_sent(r, now, reminder_after_days),
        RemovalStatus::Reminded => {
            if r.req.sent_at.is_none() {
                r.req.sent_at = Some(now);
            }
            mark_reminded(r, now)
        }
        RemovalStatus::Escalated => mark_escalated(r, now),
        RemovalStatus::Completed | RemovalStatus::Refused | RemovalStatus::Failed => {
            r.req.status = status;
            r.req.closed_at = Some(now);
            r.next_attempt_at = None;
        }
        RemovalStatus::Queued | RemovalStatus::DraftReady => {
            r.req.status = status;
            r.req.sent_at = None;
            r.req.due_at = None;
            r.req.reminded_at = None;
            r.req.closed_at = None;
            r.req.last_error = None;
            r.attempts = 0;
            r.next_attempt_at = None;
            r.escalated_at = None;
        }
        RemovalStatus::NeedsForm => {
            r.req.status = status;
            r.req.closed_at = None;
        }
    }
}

/// Campaign counters.
pub fn summary(
    reqs: &[StoredRequest],
    now: i64,
    escalate_after_days: u32,
    next_send_at: Option<i64>,
) -> RemovalSummary {
    let mut s = RemovalSummary {
        total: reqs.len() as u64,
        next_send_at,
        ..Default::default()
    };
    for r in reqs {
        match r.req.status {
            RemovalStatus::Queued => s.queued += 1,
            RemovalStatus::DraftReady | RemovalStatus::NeedsForm | RemovalStatus::Failed => {
                s.needs_action += 1
            }
            RemovalStatus::Sent => {
                if is_overdue(r, now) {
                    s.overdue += 1
                } else {
                    s.waiting_answer += 1
                }
            }
            RemovalStatus::Reminded => {
                if needs_escalation(r, now, escalate_after_days) {
                    s.overdue += 1
                } else {
                    s.waiting_answer += 1
                }
            }
            RemovalStatus::Escalated => {
                s.overdue += 1;
                s.needs_action += 1;
            }
            RemovalStatus::Completed => s.completed += 1,
            RemovalStatus::Refused => s.needs_action += 1,
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::brokers::sample;

    #[test]
    fn plan_skips_open_and_form_only() {
        let mut form = sample("form", "us", None);
        form.opt_out_url = Some("https://form.example/optout".into());
        let brokers = vec![
            sample("a", "eu", Some("dpo@a.fr")),
            sample("b", "eu", Some("dpo@b.fr")),
            form,
        ];
        let first = plan(&[], &brokers, None, 100);
        assert_eq!(first.len(), 3);
        assert_eq!(first[0].req.status, RemovalStatus::Queued);
        assert_eq!(first[2].req.status, RemovalStatus::NeedsForm);
        assert_eq!(
            first[2].req.opt_out_url.as_deref(),
            Some("https://form.example/optout")
        );
        // Everything open -> nothing new.
        assert!(plan(&first, &brokers, None, 200).is_empty());
        let mut done = first.clone();
        done[0].req.status = RemovalStatus::Completed;
        done[1].req.status = RemovalStatus::Failed;
        let again = plan(
            &done,
            &brokers,
            Some(&["a".to_string(), "c".to_string()]),
            300,
        );
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].req.broker_id, "a");
        assert_ne!(again[0].req.id, done[0].req.id);
    }

    #[test]
    fn lifecycle() {
        let mut r = plan(&[], &[sample("a", "eu", Some("dpo@a.fr"))], None, 0).remove(0);
        assert!(wants_initial(&r, 0));
        mark_send_error(&mut r, 10, "boom");
        assert_eq!(r.req.status, RemovalStatus::Queued);
        assert!(!wants_initial(&r, 20));
        assert!(wants_initial(&r, 10 + DAY));
        mark_send_error(&mut r, 20, "boom");
        mark_send_error(&mut r, 30, "boom");
        assert_eq!(r.req.status, RemovalStatus::Failed);
        assert!(!is_open(r.req.status));

        let mut r = plan(&[], &[sample("a", "eu", Some("dpo@a.fr"))], None, 0).remove(0);
        mark_sent(&mut r, 1000, 30);
        assert_eq!(r.req.due_at, Some(1000 + 30 * DAY));
        assert!(!is_overdue(&r, 1000 + 29 * DAY));
        assert!(is_overdue(&r, 1000 + 30 * DAY));
        assert!(wants_reminder(&r, 1000 + 30 * DAY));
        mark_reminded(&mut r, 1000 + 30 * DAY);
        assert!(!needs_escalation(&r, 1000 + 44 * DAY, 15));
        assert!(needs_escalation(&r, 1000 + 45 * DAY, 15));
        mark_escalated(&mut r, 1000 + 45 * DAY);
        let s = summary(std::slice::from_ref(&r), 1000 + 46 * DAY, 15, None);
        assert_eq!((s.total, s.overdue, s.needs_action), (1, 1, 1));
        apply_user_update(
            &mut r,
            RemovalStatus::Completed,
            Some("ok\u{7}".into()),
            5 * DAY,
            30,
        );
        assert_eq!(r.req.closed_at, Some(5 * DAY));
        assert_eq!(r.req.note.as_deref(), Some("ok"));
        assert!(!due_for_repeat(&r, 5 * DAY + 179 * DAY, 180));
        assert!(due_for_repeat(&r, 5 * DAY + 180 * DAY, 180));
        assert!(!due_for_repeat(&r, 5 * DAY + 999 * DAY, 0));
        apply_user_update(&mut r, RemovalStatus::Queued, None, 6 * DAY, 30);
        assert_eq!(r.req.sent_at, None);
        assert_eq!(r.req.note.as_deref(), Some("ok"));
    }

    #[test]
    fn outbox_quota() {
        let mut o = Outbox::default();
        assert!(o.can_send("2026-10-29", 1000, 2));
        o.record("2026-10-29", 1000);
        assert!(!o.can_send("2026-10-29", 1010, 2));
        assert!(o.can_send("2026-10-29", 1030, 2));
        o.record("2026-10-29", 1030);
        assert!(!o.can_send("2026-10-29", 5000, 2));
        assert_eq!(o.next_send_at("2026-10-29", 5000, 2, 9000), 9000);
        assert!(o.can_send("2026-10-30", 9000, 2));
        assert_eq!(o.next_send_at("2026-10-30", 9000, 2, 99_000), 9000);
        o.record("2026-10-30", 9000);
        assert_eq!(o.sent, 1);
    }
}
