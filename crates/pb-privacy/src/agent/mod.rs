//! Mail agent: reads the brokers' answers in a dedicated mailbox and updates the GDPR requests.
//!
//! ```text
//! IMAP (EXAMINE, BODY.PEEK) ──> parse ──> match to a request (reference in the subject, our Message-ID in
//!   In-Reply-To/References, else the broker's domain when unambiguous) ──> label (headers, else the local
//!   model, JSON schema with a closed enum) ──> decide (fixed table below) ──> request status + alert
//! ```
//!
//! Safety rules, whatever a message says:
//! * the agent never sends a mail, never answers a broker and never reveals data: asking for an identity
//!   document, more information or a web form always ends with **you** (`needs_you` / `needs_form`);
//! * messages that match no request are not shown to the model at all;
//! * a message whose DKIM/DMARC check failed at your mail provider is ignored (spoofed sender);
//! * a closed request (erased, refused, failed) is never reopened by a message.

pub mod classify;
pub mod imap;
pub mod ollama;
pub mod parse;
pub mod vault;

use crate::requests::StoredRequest;
use pb_core::model::{MailAgentEvent, RemovalStatus, ReplyKind};
use serde::{Deserialize, Serialize};

/// Events kept (newest first).
pub const MAX_EVENTS: usize = 200;
const MAX_SEEN: usize = 5000;

/// `agent.json` (root-only, in the privacy directory).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentFile {
    pub format: u32,
    /// Mailbox identity: `host|user|mailbox` (a change restarts from scratch).
    pub mailbox_key: String,
    pub uid_validity: Option<u32>,
    pub last_uid: u32,
    pub last_run_at: Option<i64>,
    pub last_error: Option<String>,
    pub last_fetched: u32,
    pub last_matched: u32,
    pub last_updated: u32,
    pub events: Vec<MailAgentEvent>,
    /// Message-IDs already handled (a message copied or re-delivered is not applied twice).
    pub seen: Vec<String>,
    /// Message on which the model failed last, and how many times in a row.
    pub stuck_uid: Option<u32>,
    pub stuck_count: u32,
}

impl AgentFile {
    pub fn record(&mut self, e: MailAgentEvent) {
        self.events.insert(0, e);
        self.events.truncate(MAX_EVENTS);
    }

    pub fn mark_seen(&mut self, id: &str) {
        if !id.is_empty() && !self.seen.iter().any(|s| s == id) {
            self.seen.push(id.to_string());
            if self.seen.len() > MAX_SEEN {
                let drop = self.seen.len() - MAX_SEEN;
                self.seen.drain(..drop);
            }
        }
    }

    pub fn was_seen(&self, id: &str) -> bool {
        !id.is_empty() && self.seen.iter().any(|s| s == id)
    }
}

/// Reference put in the subject of every letter (`[Réf. PB-1a2b3c4d]`).
pub fn reference(request_id: &str) -> String {
    let short: String = request_id
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("PB-{short}")
}

/// Message-ID of the letters sent by SMTP: `<pb.<request id>.<ts>@<sender domain>>`.
pub fn message_id(request_id: &str, ts: i64, from_address: &str) -> String {
    let domain = from_address
        .rsplit_once('@')
        .map(|(_, d)| d.to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "parabellum.invalid".into());
    format!("<pb.{request_id}.{ts}@{domain}>")
}

fn subject_reference(subject: &str) -> Option<String> {
    let lower = subject.to_ascii_lowercase();
    let i = lower.find("pb-")?;
    let hex: String = lower[i + 3..].chars().take(8).collect();
    (hex.len() == 8 && hex.chars().all(|c| c.is_ascii_hexdigit())).then_some(hex)
}

fn ref_request_id(r: &str) -> Option<String> {
    let lower = r.to_ascii_lowercase();
    let i = lower.find("pb.")?;
    let rest = &lower[i + 3..];
    let id: String = rest.chars().take(36).collect();
    let ok = id.len() == 36
        && id.char_indices().all(|(k, c)| {
            if matches!(k, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    ok.then_some(id)
}

/// How a message was tied to its request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchBy {
    MessageId,
    Reference,
    Domain,
}

fn broker_domain(r: &StoredRequest) -> String {
    r.req
        .broker_email
        .as_deref()
        .and_then(|e| e.rsplit_once('@'))
        .map(|(_, d)| d.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Index of the request this message answers.
pub fn match_request(m: &parse::ParsedMail, reqs: &[StoredRequest]) -> Option<(usize, MatchBy)> {
    // 1. Our Message-ID in In-Reply-To / References.
    for r in &m.refs {
        if let Some(id) = ref_request_id(r) {
            if let Some(i) = reqs.iter().position(|x| x.req.id.eq_ignore_ascii_case(&id)) {
                return Some((i, MatchBy::MessageId));
            }
        }
    }
    // 2. Reference in the subject, if it designates exactly one request of a broker from that sender's site
    //    (a reference is guessable: it must also come from the broker).
    if let Some(short) = subject_reference(&m.subject) {
        let hits: Vec<usize> = reqs
            .iter()
            .enumerate()
            .filter(|(_, x)| reference(&x.req.id) == format!("PB-{short}"))
            .map(|(i, _)| i)
            .collect();
        if let [i] = hits[..] {
            let d = broker_domain(&reqs[i]);
            if d.is_empty() || classify::same_site(&m.from_domain, &d) {
                return Some((i, MatchBy::Reference));
            }
        }
    }
    // 3. Sender domain: only when one open request comes from that site.
    if m.from_domain.is_empty() {
        return None;
    }
    let open: Vec<usize> = reqs
        .iter()
        .enumerate()
        .filter(|(_, x)| crate::requests::is_open(x.req.status) && x.req.sent_at.is_some())
        .filter(|(_, x)| {
            let d = broker_domain(x);
            !d.is_empty() && classify::same_site(&m.from_domain, &d)
        })
        .map(|(i, _)| i)
        .collect();
    match open[..] {
        [i] => Some((i, MatchBy::Domain)),
        _ => None,
    }
}

/// What a label does to a request: the only place where the agent changes anything.
pub fn decide(current: RemovalStatus, kind: ReplyKind) -> Option<RemovalStatus> {
    if matches!(
        current,
        RemovalStatus::Completed | RemovalStatus::Refused | RemovalStatus::Failed
    ) {
        return None; // closed requests are never reopened by a message
    }
    match kind {
        ReplyKind::Erased | ReplyKind::NoData => Some(RemovalStatus::Completed),
        ReplyKind::IdentityRequested | ReplyKind::InfoRequested | ReplyKind::Other => {
            Some(RemovalStatus::NeedsYou)
        }
        ReplyKind::FormRequired => Some(RemovalStatus::NeedsForm),
        ReplyKind::Refused => Some(RemovalStatus::Refused),
        ReplyKind::Bounce => Some(RemovalStatus::Failed),
        ReplyKind::Acknowledged | ReplyKind::AutoReply => None,
    }
    .filter(|s| *s != current)
}

/// Apply a labelled answer to its request. Returns the new status when it changed.
pub fn apply(
    r: &mut StoredRequest,
    kind: ReplyKind,
    summary: &str,
    form_url: Option<String>,
    now: i64,
) -> Option<RemovalStatus> {
    r.req.last_reply_at = Some(now);
    r.req.last_reply_kind = Some(kind);
    r.req.last_reply_summary = (!summary.is_empty()).then(|| summary.to_string());
    let new = decide(r.req.status, kind)?;
    r.req.status = new;
    match new {
        RemovalStatus::Completed | RemovalStatus::Refused | RemovalStatus::Failed => {
            r.req.closed_at = Some(now);
            r.next_attempt_at = None;
            if new == RemovalStatus::Failed {
                r.req.last_error = Some("l'adresse de l'organisme a rejeté le message".into());
            }
        }
        RemovalStatus::NeedsForm => {
            if let Some(u) = form_url {
                r.req.opt_out_url = Some(u);
            }
        }
        _ => {}
    }
    Some(new)
}

/// One event for the log.
pub fn event(
    r: &StoredRequest,
    kind: ReplyKind,
    by: &str,
    summary: &str,
    new_status: Option<RemovalStatus>,
    now: i64,
) -> MailAgentEvent {
    MailAgentEvent {
        ts: now,
        request_id: Some(r.req.id.clone()),
        broker_name: r.req.broker_name.clone(),
        kind,
        classified_by: by.to_string(),
        summary: summary.to_string(),
        new_status,
    }
}

/// Default summary of a label decided by the headers.
pub fn header_summary(kind: ReplyKind) -> &'static str {
    match kind {
        ReplyKind::Bounce => "Le message n'a pas pu être remis à l'organisme.",
        ReplyKind::AutoReply => "Réponse automatique (absence).",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requests::StoredRequest;
    use pb_core::model::RemovalRequest;

    pub(crate) fn stored(id: &str, email: &str, status: RemovalStatus) -> StoredRequest {
        StoredRequest {
            req: RemovalRequest {
                id: id.into(),
                broker_id: email.into(),
                broker_name: email.into(),
                broker_email: Some(email.into()),
                status,
                created_at: 1,
                sent_at: Some(2),
                due_at: None,
                reminded_at: None,
                closed_at: None,
                opt_out_url: None,
                draft_path: None,
                note: None,
                last_error: None,
                last_reply_at: None,
                last_reply_kind: None,
                last_reply_summary: None,
            },
            region: "eu".into(),
            website: None,
            attempts: 0,
            next_attempt_at: None,
            escalated_at: None,
        }
    }

    fn mail(from: &str, subject: &str, refs: &[&str]) -> parse::ParsedMail {
        parse::ParsedMail {
            from: from.into(),
            from_domain: from.rsplit_once('@').unwrap().1.into(),
            subject: subject.into(),
            refs: refs.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    const A: &str = "aaaaaaaa-1111-4111-8111-111111111111";
    const B: &str = "bbbbbbbb-2222-4222-8222-222222222222";

    #[test]
    fn matching() {
        let reqs = vec![
            stored(A, "dpo@acme.example", RemovalStatus::Sent),
            stored(B, "privacy@other.example", RemovalStatus::Sent),
        ];
        let id = message_id(B, 5, "me@mine.example");
        assert_eq!(id, format!("<pb.{B}.5@mine.example>"));
        assert_eq!(
            match_request(&mail("x@random.example", "Re: x", &[&id]), &reqs),
            Some((1, MatchBy::MessageId))
        );
        let subj = format!("Re: demande [Réf. {}]", reference(A));
        assert_eq!(reference(A), "PB-aaaaaaaa");
        assert_eq!(
            match_request(&mail("support@help.acme.example", &subj, &[]), &reqs),
            Some((0, MatchBy::Reference))
        );
        // A guessed reference from another site does not match by reference.
        assert_eq!(
            match_request(&mail("x@evil.example", &subj, &[]), &reqs),
            None
        );
        assert_eq!(
            match_request(
                &mail("noreply@mail.other.example", "Votre demande", &[]),
                &reqs
            ),
            Some((1, MatchBy::Domain))
        );
        // Two open requests on the same site: ambiguous.
        let mut two = reqs.clone();
        two.push(stored(
            "cccccccc-3333-4333-8333-333333333333",
            "legal@acme.example",
            RemovalStatus::Sent,
        ));
        assert_eq!(
            match_request(&mail("x@acme.example", "Hello", &[]), &two),
            None
        );
    }

    #[test]
    fn decisions_never_reopen_or_send() {
        use RemovalStatus as S;
        assert_eq!(decide(S::Sent, ReplyKind::Erased), Some(S::Completed));
        assert_eq!(
            decide(S::Reminded, ReplyKind::IdentityRequested),
            Some(S::NeedsYou)
        );
        assert_eq!(decide(S::Sent, ReplyKind::Acknowledged), None);
        assert_eq!(decide(S::Completed, ReplyKind::Refused), None);
        assert_eq!(decide(S::Refused, ReplyKind::Erased), None);
        assert_eq!(decide(S::Sent, ReplyKind::Bounce), Some(S::Failed));
        let mut r = stored(A, "dpo@acme.example", S::Sent);
        assert_eq!(
            apply(
                &mut r,
                ReplyKind::FormRequired,
                "form",
                Some("https://acme.example/f".into()),
                9
            ),
            Some(S::NeedsForm)
        );
        assert_eq!(r.req.opt_out_url.as_deref(), Some("https://acme.example/f"));
        assert_eq!(r.req.last_reply_at, Some(9));
        assert_eq!(
            apply(&mut r, ReplyKind::Erased, "ok", None, 10),
            Some(S::Completed)
        );
        assert_eq!(r.req.closed_at, Some(10));
    }

    #[test]
    fn seen_ids_are_bounded() {
        let mut f = AgentFile::default();
        for i in 0..(MAX_SEEN + 10) {
            f.mark_seen(&format!("<{i}>"));
        }
        assert_eq!(f.seen.len(), MAX_SEEN);
        assert!(!f.was_seen("<0>") && f.was_seen(&format!("<{}>", MAX_SEEN + 9)));
    }
}
