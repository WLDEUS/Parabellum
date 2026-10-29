//! Privacy features of Parabellum — the open-source "Incogni" part.
//!
//! - GDPR erasure campaign ([`PrivacyService`]): the signed broker list from the threat DB
//!   (`privacy/brokers.json`: Datenanfragen CC0 + Eraser MIT), letters adapted from the Datenanfragen CC0
//!   templates (French / English: art. 17 erasure + art. 21 objection, art. 12(3) one-month deadline, art. 19
//!   recipients), sending through the user's SMTP account (rate-limited) or drafts the app/CLI hands to the
//!   user's mail app, deadline tracking, formal reminder, CNIL complaint text, periodic re-runs.
//! - Breach monitoring: XposedOrNot (free) or Have I Been Pwned (API key) for the configured addresses.
//! - Email aliases: addy.io / SimpleLogin API (both open source, self-hostable).
//! - [`pwned`]: Pwned Passwords range API (k-anonymity: only 5 hex chars of the SHA-1 leave the Mac), used by
//!   the CLI and the app — passwords never reach the daemon.
//! - [`metadata`]: removes EXIF/XMP/IPTC/GPS (JPEG, PNG, WebP) and document properties (docx/xlsx/pptx) into
//!   a cleaned copy; other formats through `exiftool` when installed. Used by the CLI (runs as the user).
//!
//! State lives in `paths.privacy_dir()` (root-only, written atomically, mode 0600): `profile.json`
//! ([`IdentityProfile`]), `requests.json` ([`requests::RequestsFile`]), `breaches.json` ([`BreachesFile`]),
//! `aliases.json` ([`AliasesFile`]), `outbox.json` ([`requests::Outbox`], daily quota).
//!
//! Daemon integration (`pb-daemon/src/privacy.rs`):
//! ```text
//! let privacy = PrivacyService::new(paths.clone(), hooks);   // hooks: alerts
//! tokio::spawn(privacy.clone().run(config_rx, shutdown_rx)); // quota sender, reminders, breach checks
//! // IPC: get_profile / set_profile / brokers / requests / summary / start_removal / update_request /
//! //      draft / complaint / breaches / check_breaches / aliases / create_alias
//! ```

pub mod aliases;
pub mod breach;
pub mod brokers;
pub mod letters;
pub mod mail;
pub mod metadata;
pub mod pwned;
pub mod requests;
mod store;

use async_trait::async_trait;
use chrono::TimeZone;
use letters::Lang;
use mail::{LettreSender, MailSender, OutgoingMail, SmtpSettings};
use pb_core::config::{is_email, Config, SendMode};
use pb_core::model::{
    BreachFinding, BrokerInfo, ComplaintDraft, EmailAlias, IdentityProfile, MailDraft,
    RemovalRequest, RemovalStatus, RemovalSummary, Severity,
};
use pb_core::paths::Paths;
use requests::{Outbox, RequestsFile, StoredRequest};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivacyError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Failed(String),
}

/// Alert raised by the privacy service (kind `privacy`), deduplicated by the daemon on `key` for 24 h.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyAlert {
    pub severity: Severity,
    pub title: String,
    pub message: String,
    pub key: String,
}

#[async_trait]
pub trait PrivacyHooks: Send + Sync + 'static {
    fn alert(&self, alert: PrivacyAlert);
}

// ---------------------------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------------------------

fn mask_word(w: &str) -> String {
    let mut c = w.chars();
    match c.next() {
        Some(first) => {
            let rest = c.count();
            format!("{first}{}", "*".repeat(rest))
        }
        None => String::new(),
    }
}

fn mask_email(e: &str) -> String {
    match e.rsplit_once('@') {
        Some((local, domain)) => {
            let first: String = local.chars().take(1).collect();
            format!("{first}***@{domain}")
        }
        None => "***".into(),
    }
}

fn mask_phone(p: &str) -> String {
    let digits: Vec<char> = p.chars().filter(char::is_ascii_digit).collect();
    if digits.len() <= 2 {
        return "**".into();
    }
    let tail: String = digits[digits.len() - 2..].iter().collect();
    format!("{}{tail}", "*".repeat(digits.len() - 2))
}

/// Masked copy of an identity for display without administrator approval
/// (`Camille Martin` -> `C****** M*****`, `c.m@example.com` -> `c***@example.com`).
pub fn mask_profile(p: &IdentityProfile) -> IdentityProfile {
    let masked_text = |s: &str| {
        if s.trim().is_empty() {
            String::new()
        } else {
            "***".into()
        }
    };
    IdentityProfile {
        full_name: p
            .full_name
            .split_whitespace()
            .map(mask_word)
            .collect::<Vec<_>>()
            .join(" "),
        emails: p.emails.iter().map(|e| mask_email(e)).collect(),
        phones: p.phones.iter().map(|e| mask_phone(e)).collect(),
        postal_address: masked_text(&p.postal_address),
        previous_addresses: p
            .previous_addresses
            .iter()
            .map(|a| masked_text(a))
            .collect(),
        birth_date: if p.birth_date.trim().is_empty() {
            String::new()
        } else {
            "****-**-**".into()
        },
        country: p.country.clone(),
    }
}

fn single_line(s: &str, max: usize) -> String {
    s.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

/// Validate and normalise an identity (trimmed, deduplicated, bounded).
pub fn validate_profile(p: IdentityProfile) -> Result<IdentityProfile, PrivacyError> {
    let bad = |m: &str| Err(PrivacyError::Invalid(m.into()));
    let full_name = single_line(&p.full_name, 200)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if full_name.is_empty() {
        return bad("nom complet requis");
    }
    let mut emails: Vec<String> = Vec::new();
    for e in &p.emails {
        let e = e.trim().to_string();
        if e.is_empty() {
            continue;
        }
        if !is_email(&e) {
            return Err(PrivacyError::Invalid(format!(
                "adresse e-mail invalide : {e}"
            )));
        }
        if !emails.iter().any(|x| x.eq_ignore_ascii_case(&e)) {
            emails.push(e);
        }
    }
    if emails.is_empty() {
        return bad("au moins une adresse e-mail requise");
    }
    if emails.len() > 10 {
        return bad("10 adresses e-mail au plus");
    }
    let mut phones = Vec::new();
    for ph in &p.phones {
        let ph = ph.trim().to_string();
        if ph.is_empty() {
            continue;
        }
        if ph.len() > 32
            || !ph
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '+' | ' ' | '(' | ')' | '.' | '-'))
        {
            return Err(PrivacyError::Invalid(format!(
                "numéro de téléphone invalide : {ph}"
            )));
        }
        phones.push(ph);
    }
    if phones.len() > 5 {
        return bad("5 numéros de téléphone au plus");
    }
    let multi = |s: &str| -> String {
        s.lines()
            .map(|l| single_line(l, 200))
            .filter(|l| !l.is_empty())
            .take(8)
            .collect::<Vec<_>>()
            .join("\n")
    };
    let postal_address = multi(&p.postal_address);
    let previous_addresses: Vec<String> = p
        .previous_addresses
        .iter()
        .map(|a| multi(a))
        .filter(|a| !a.is_empty())
        .collect();
    if previous_addresses.len() > 10 {
        return bad("10 anciennes adresses au plus");
    }
    let birth_date = p.birth_date.trim().to_string();
    if !birth_date.is_empty() && chrono::NaiveDate::parse_from_str(&birth_date, "%Y-%m-%d").is_err()
    {
        return bad("date de naissance au format AAAA-MM-JJ");
    }
    let country = p.country.trim().to_ascii_uppercase();
    let country = if country.is_empty() {
        "FR".to_string()
    } else {
        country
    };
    if country.len() != 2 || !country.bytes().all(|b| b.is_ascii_uppercase()) {
        return bad("pays : code ISO à deux lettres (FR)");
    }
    Ok(IdentityProfile {
        full_name,
        emails,
        phones,
        postal_address,
        previous_addresses,
        birth_date,
        country,
    })
}

fn profile_ready(p: &IdentityProfile) -> bool {
    !p.full_name.trim().is_empty() && !p.emails.is_empty()
}

// ---------------------------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------------------------

/// `breaches.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BreachesFile {
    pub format: u32,
    /// Last completed check (Unix time).
    pub last_check: i64,
    pub findings: Vec<BreachFinding>,
}

/// `aliases.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AliasesFile {
    pub format: u32,
    pub aliases: Vec<EmailAlias>,
}

const PROFILE_FILE: &str = "profile.json";
const REQUESTS_FILE: &str = "requests.json";
const BREACHES_FILE: &str = "breaches.json";
const ALIASES_FILE: &str = "aliases.json";
const OUTBOX_FILE: &str = "outbox.json";

#[derive(Debug, Default)]
struct State {
    profile: IdentityProfile,
    requests: RequestsFile,
    breaches: BreachesFile,
    aliases: AliasesFile,
    outbox: Outbox,
}

/// Local calendar day `YYYY-MM-DD` of `ts`.
fn local_day(ts: i64) -> String {
    chrono::Local
        .timestamp_opt(ts, 0)
        .single()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// Start of the next local day after `ts`.
fn next_local_midnight(ts: i64) -> i64 {
    let Some(d) = chrono::Local.timestamp_opt(ts, 0).single() else {
        return ts + requests::DAY;
    };
    let tomorrow = d
        .date_naive()
        .succ_opt()
        .and_then(|n| n.and_hms_opt(0, 0, 0));
    tomorrow
        .and_then(|t| chrono::Local.from_local_datetime(&t).earliest())
        .map(|t| t.timestamp())
        .unwrap_or(ts + requests::DAY)
}

fn short_hash(parts: &[String]) -> String {
    let mut h = sha2::Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    hex::encode(&h.finalize()[..8])
}

// ---------------------------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------------------------

/// Which letter a request needs now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LetterKind {
    Initial,
    Reminder,
}

pub struct PrivacyService {
    paths: Paths,
    hooks: Arc<dyn PrivacyHooks>,
    sender: Arc<dyn MailSender>,
    endpoints: breach::Endpoints,
    state: tokio::sync::Mutex<State>,
    /// One sending loop at a time.
    send_lock: tokio::sync::Mutex<()>,
    /// Last configuration seen (for `update_request`, which gets none).
    config: std::sync::Mutex<Arc<Config>>,
    /// Pause between two emails (30 s; shorter in tests).
    spacing: Duration,
}

impl PrivacyService {
    pub fn new(paths: Paths, hooks: Arc<dyn PrivacyHooks>) -> Arc<Self> {
        Self::with_sender(paths, hooks, Arc::new(LettreSender))
    }

    /// Same as [`PrivacyService::new`] with another mail transport (tests, dry runs).
    pub fn with_sender(
        paths: Paths,
        hooks: Arc<dyn PrivacyHooks>,
        sender: Arc<dyn MailSender>,
    ) -> Arc<Self> {
        Arc::new(Self::build(paths, hooks, sender))
    }

    fn build(paths: Paths, hooks: Arc<dyn PrivacyHooks>, sender: Arc<dyn MailSender>) -> Self {
        let dir = paths.privacy_dir();
        let state = State {
            profile: store::load_json(&dir.join(PROFILE_FILE)),
            requests: store::load_json(&dir.join(REQUESTS_FILE)),
            breaches: store::load_json(&dir.join(BREACHES_FILE)),
            aliases: store::load_json(&dir.join(ALIASES_FILE)),
            outbox: store::load_json(&dir.join(OUTBOX_FILE)),
        };
        Self {
            paths,
            hooks,
            sender,
            endpoints: breach::Endpoints::default(),
            state: tokio::sync::Mutex::new(state),
            send_lock: tokio::sync::Mutex::new(()),
            config: std::sync::Mutex::new(Arc::new(Config::default())),
            spacing: Duration::from_secs(requests::SEND_SPACING_SECS as u64),
        }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.paths.privacy_dir().join(name)
    }

    fn save<T: Serialize>(&self, name: &str, v: &T) {
        if let Err(e) = store::save_json(&self.file(name), v) {
            tracing::error!(file = name, error = %e, "cannot save privacy state");
        }
    }

    fn remember_config(&self, cfg: &Config) {
        let mut g = self.config.lock().unwrap_or_else(|e| e.into_inner());
        if **g != *cfg {
            *g = Arc::new(cfg.clone());
        }
    }

    fn last_config(&self) -> Arc<Config> {
        self.config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Background work until shutdown: sends queued requests within `data_removal.max_emails_per_day`
    /// (SMTP mode), moves overdue requests to reminders and escalations (alerts), re-queues brokers every
    /// `repeat_every_days`, checks breaches every `breach.check_interval_hours`.
    pub async fn run(
        self: Arc<Self>,
        config: watch::Receiver<Arc<Config>>,
        mut shutdown: watch::Receiver<bool>,
    ) {
        let mut wait = Duration::from_secs(60);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(wait) => {}
                r = shutdown.changed() => {
                    if r.is_err() || *shutdown.borrow() {
                        return;
                    }
                    continue;
                }
            }
            if *shutdown.borrow() {
                return;
            }
            wait = Duration::from_secs(600);
            let cfg = config.borrow().clone();
            self.remember_config(&cfg);
            self.tick(&cfg, pb_core::now_ts(), &mut shutdown).await;
        }
    }

    /// One pass of the background work (public for tests and for a manual "run now").
    pub async fn tick(&self, cfg: &Config, now: i64, shutdown: &mut watch::Receiver<bool>) {
        if cfg.data_removal.enabled {
            self.housekeeping(cfg, now).await;
            if cfg.data_removal.send_mode == SendMode::Smtp {
                self.send_due(cfg, shutdown).await;
            }
        }
        if cfg.breach.enabled && !cfg.breach.emails.is_empty() {
            let last = self.state.lock().await.breaches.last_check;
            if now - last >= i64::from(cfg.breach.check_interval_hours) * 3600 {
                if let Err(e) = self.check_breaches(cfg).await {
                    tracing::warn!(error = %e, "breach check failed");
                }
            }
        }
    }

    /// Repeats, escalations, "reminders ready" alert (drafts mode).
    async fn housekeeping(&self, cfg: &Config, now: i64) {
        let d = &cfg.data_removal;
        let brokers = brokers::load(&self.paths.db_current())
            .map(|b| brokers::filter(b, &d.regions))
            .unwrap_or_default();
        let mut st = self.state.lock().await;
        let mut changed = false;
        // Repeat: the latest request of a broker was completed long ago.
        if d.repeat_every_days > 0 && !brokers.is_empty() {
            let mut latest: BTreeMap<String, usize> = BTreeMap::new();
            for (i, r) in st.requests.requests.iter().enumerate() {
                let e = latest.entry(r.req.broker_id.clone()).or_insert(i);
                if st.requests.requests[*e].req.created_at <= r.req.created_at {
                    *e = i;
                }
            }
            let due: Vec<String> = latest
                .values()
                .filter(|&&i| {
                    requests::due_for_repeat(&st.requests.requests[i], now, d.repeat_every_days)
                })
                .map(|&i| st.requests.requests[i].req.broker_id.clone())
                .collect();
            if !due.is_empty() {
                let new = requests::plan(&st.requests.requests, &brokers, Some(&due), now);
                if !new.is_empty() {
                    tracing::info!(
                        count = new.len(),
                        "GDPR requests re-queued (periodic repeat)"
                    );
                    st.requests.requests.extend(new);
                    changed = true;
                }
            }
        }
        // Escalations.
        let mut escalated = Vec::new();
        for r in st.requests.requests.iter_mut() {
            if requests::needs_escalation(r, now, d.escalate_after_days) {
                requests::mark_escalated(r, now);
                escalated.push(r.req.broker_name.clone());
                changed = true;
            }
        }
        // Drafts mode: reminders ready.
        let today = local_day(now);
        let overdue: Vec<String> = st
            .requests
            .requests
            .iter()
            .filter(|r| requests::is_overdue(r, now))
            .map(|r| r.req.broker_name.clone())
            .collect();
        let alert_reminders = d.send_mode == SendMode::Drafts
            && !overdue.is_empty()
            && st.requests.reminders_alerted_day != today;
        if alert_reminders {
            st.requests.reminders_alerted_day = today.clone();
            changed = true;
        }
        if changed {
            self.save(REQUESTS_FILE, &st.requests);
        }
        drop(st);
        if !escalated.is_empty() {
            self.hooks.alert(PrivacyAlert {
                severity: Severity::Medium,
                title: format!(
                    "RGPD : {} organisme(s) sans réponse après relance",
                    escalated.len()
                ),
                message: format!(
                    "Aucune réponse malgré la relance : {}. Vous pouvez saisir la CNIL (Parabellum prépare le texte \
de la réclamation).",
                    list_names(&escalated)
                ),
                key: format!("privacy:escalated:{}", short_hash(&escalated)),
            });
        }
        if alert_reminders {
            self.hooks.alert(PrivacyAlert {
                severity: Severity::Low,
                title: format!("RGPD : {} relance(s) à envoyer", overdue.len()),
                message: format!(
                    "Le délai d'un mois est dépassé sans réponse pour : {}. Les relances sont prêtes dans \
Parabellum (Vie privée > Demandes).",
                    list_names(&overdue)
                ),
                key: format!("privacy:reminders:{today}"),
            });
        }
    }

    /// SMTP mode: send what is due (reminders first) within the daily quota, one every 30 s.
    async fn send_due(&self, cfg: &Config, shutdown: &mut watch::Receiver<bool>) {
        let Ok(_guard) = self.send_lock.try_lock() else {
            return;
        };
        let d = &cfg.data_removal;
        loop {
            let now = pb_core::now_ts();
            let today = local_day(now);
            let job = {
                let st = self.state.lock().await;
                if !st.outbox.can_send(&today, now, d.max_emails_per_day) {
                    None
                } else if !profile_ready(&st.profile) {
                    drop(st);
                    self.hooks.alert(PrivacyAlert {
                        severity: Severity::Low,
                        title: "RGPD : identité à compléter".into(),
                        message: "Les demandes d'effacement attendent : renseignez votre nom et votre adresse \
e-mail dans Parabellum (Vie privée)."
                            .into(),
                        key: format!("privacy:profile:{today}"),
                    });
                    None
                } else {
                    st.requests
                        .requests
                        .iter()
                        .find(|r| requests::wants_reminder(r, now))
                        .map(|r| (r, LetterKind::Reminder))
                        .or_else(|| {
                            st.requests
                                .requests
                                .iter()
                                .find(|r| requests::wants_initial(r, now))
                                .map(|r| (r, LetterKind::Initial))
                        })
                        .map(|(r, kind)| {
                            let mail = compose(&st.profile, r, kind, &d.language);
                            (r.req.id.clone(), kind, mail, st.profile.full_name.clone())
                        })
                }
            };
            let Some((id, kind, mail, name)) = job else {
                return;
            };
            let smtp = match SmtpSettings::from_config(d, &name) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "SMTP not configured");
                    return;
                }
            };
            let res = self.sender.send(&smtp, &mail).await;
            let now = pb_core::now_ts();
            let mut st = self.state.lock().await;
            st.outbox.record(&today, now);
            if res.is_err() {
                // Failures do not consume the quota, only the spacing.
                st.outbox.sent = st.outbox.sent.saturating_sub(1);
            }
            let reminder_days = d.reminder_after_days;
            if let Some(r) = st.requests.requests.iter_mut().find(|r| r.req.id == id) {
                match &res {
                    Ok(()) => match kind {
                        LetterKind::Initial => requests::mark_sent(r, now, reminder_days),
                        LetterKind::Reminder => requests::mark_reminded(r, now),
                    },
                    Err(e) => requests::mark_send_error(r, now, e),
                }
            }
            self.save(REQUESTS_FILE, &st.requests);
            self.save(OUTBOX_FILE, &st.outbox);
            drop(st);
            match res {
                Ok(()) => tracing::info!(request = %id, ?kind, "GDPR email sent"),
                Err(e) => {
                    tracing::warn!(request = %id, error = %e, "GDPR email failed");
                    self.hooks.alert(PrivacyAlert {
                        severity: Severity::Medium,
                        title: "RGPD : envoi des demandes impossible".into(),
                        message: format!(
                            "Le serveur SMTP a refusé l'envoi ({e}). Vérifiez le compte SMTP (serveur, port, mot \
de passe d'application) dans les réglages ; nouvel essai demain."
                        ),
                        key: format!("privacy:smtp:{today}"),
                    });
                    return;
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(self.spacing) => {}
                r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { return; },
            }
            if *shutdown.borrow() {
                return;
            }
        }
    }

    /// Stored identity; masked unless `reveal`.
    pub async fn get_profile(&self, reveal: bool) -> IdentityProfile {
        let st = self.state.lock().await;
        if reveal {
            st.profile.clone()
        } else {
            mask_profile(&st.profile)
        }
    }

    /// Validate and store; returns the masked profile.
    pub async fn set_profile(
        &self,
        profile: IdentityProfile,
    ) -> Result<IdentityProfile, PrivacyError> {
        let p = validate_profile(profile)?;
        let mut st = self.state.lock().await;
        st.profile = p;
        store::save_json(&self.file(PROFILE_FILE), &st.profile)
            .map_err(|e| PrivacyError::Failed(format!("enregistrement impossible : {e}")))?;
        Ok(mask_profile(&st.profile))
    }

    /// Brokers of the configured regions from `db/current/privacy/brokers.json`.
    pub async fn brokers(&self, cfg: &Config) -> Vec<BrokerInfo> {
        self.remember_config(cfg);
        match brokers::load(&self.paths.db_current()) {
            Ok(b) => brokers::filter(b, &cfg.data_removal.regions),
            Err(e) => {
                tracing::debug!(error = %e, "no broker list");
                vec![]
            }
        }
    }

    /// Newest first.
    pub async fn requests(&self) -> Vec<RemovalRequest> {
        let st = self.state.lock().await;
        let mut v: Vec<RemovalRequest> =
            st.requests.requests.iter().map(|r| r.req.clone()).collect();
        v.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
                .then(a.broker_name.cmp(&b.broker_name))
        });
        v
    }

    pub async fn summary(&self, cfg: &Config) -> RemovalSummary {
        self.remember_config(cfg);
        let now = pb_core::now_ts();
        let d = &cfg.data_removal;
        let st = self.state.lock().await;
        let queued = st
            .requests
            .requests
            .iter()
            .any(|r| requests::wants_initial(r, now) || requests::wants_reminder(r, now));
        let next = (d.enabled && d.send_mode == SendMode::Smtp && queued).then(|| {
            let today = local_day(now);
            st.outbox
                .next_send_at(&today, now, d.max_emails_per_day, next_local_midnight(now))
        });
        requests::summary(&st.requests.requests, now, d.escalate_after_days, next)
    }

    /// Queue requests for every broker of the configured regions (or `broker_ids`) without an open request.
    pub async fn start_removal(
        &self,
        cfg: &Config,
        broker_ids: Option<Vec<String>>,
    ) -> Result<RemovalSummary, PrivacyError> {
        self.remember_config(cfg);
        if !cfg.data_removal.enabled {
            return Err(PrivacyError::Invalid(
                "activez d'abord la suppression des données (data_removal.enabled)".into(),
            ));
        }
        if !profile_ready(&self.state.lock().await.profile) {
            return Err(PrivacyError::Invalid(
                "renseignez d'abord votre identité (nom et adresse e-mail)".into(),
            ));
        }
        let all = brokers::load(&self.paths.db_current()).map_err(PrivacyError::Unavailable)?;
        let list = brokers::filter(all, &cfg.data_removal.regions);
        if let Some(ids) = &broker_ids {
            let unknown: Vec<&String> = ids
                .iter()
                .filter(|i| !list.iter().any(|b| &b.id == *i))
                .collect();
            if !unknown.is_empty() {
                return Err(PrivacyError::NotFound(format!(
                    "organisme(s) inconnu(s) dans les régions choisies : {}",
                    unknown
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
        let now = pb_core::now_ts();
        {
            let mut st = self.state.lock().await;
            let new = requests::plan(&st.requests.requests, &list, broker_ids.as_deref(), now);
            tracing::info!(count = new.len(), "GDPR erasure requests queued");
            st.requests.requests.extend(new);
            st.requests.format = 1;
            store::save_json(&self.file(REQUESTS_FILE), &st.requests)
                .map_err(|e| PrivacyError::Failed(format!("enregistrement impossible : {e}")))?;
        }
        Ok(self.summary(cfg).await)
    }

    pub async fn update_request(
        &self,
        id: &str,
        status: RemovalStatus,
        note: Option<String>,
    ) -> Result<RemovalRequest, PrivacyError> {
        let reminder_days = self.last_config().data_removal.reminder_after_days;
        let mut st = self.state.lock().await;
        let r = st
            .requests
            .requests
            .iter_mut()
            .find(|r| r.req.id == id)
            .ok_or_else(|| PrivacyError::NotFound(format!("demande {id} introuvable")))?;
        requests::apply_user_update(r, status, note, pb_core::now_ts(), reminder_days);
        let out = r.req.clone();
        store::save_json(&self.file(REQUESTS_FILE), &st.requests)
            .map_err(|e| PrivacyError::Failed(format!("enregistrement impossible : {e}")))?;
        Ok(out)
    }

    /// The email to send now for this request (first letter, or the reminder when overdue). In drafts mode,
    /// handing it out marks a queued request `draft_ready`.
    pub async fn draft(&self, cfg: &Config, id: &str) -> Result<MailDraft, PrivacyError> {
        self.remember_config(cfg);
        let now = pb_core::now_ts();
        let mut st = self.state.lock().await;
        if !profile_ready(&st.profile) {
            return Err(PrivacyError::Invalid(
                "renseignez d'abord votre identité (nom et adresse e-mail)".into(),
            ));
        }
        let idx = st
            .requests
            .requests
            .iter()
            .position(|r| r.req.id == id)
            .ok_or_else(|| PrivacyError::NotFound(format!("demande {id} introuvable")))?;
        let r = &st.requests.requests[idx];
        let kind = match r.req.status {
            RemovalStatus::Queued | RemovalStatus::DraftReady | RemovalStatus::Failed => {
                LetterKind::Initial
            }
            RemovalStatus::Sent if requests::is_overdue(r, now) => LetterKind::Reminder,
            RemovalStatus::Sent => LetterKind::Initial,
            RemovalStatus::Reminded | RemovalStatus::Escalated => LetterKind::Reminder,
            RemovalStatus::NeedsForm => {
                return Err(PrivacyError::Invalid(match &r.req.opt_out_url {
                    Some(u) => format!("cet organisme n'accepte que son formulaire web : {u}"),
                    None => "cet organisme n'accepte que son formulaire web".into(),
                }))
            }
            RemovalStatus::Completed | RemovalStatus::Refused => {
                return Err(PrivacyError::Invalid("demande close".into()))
            }
        };
        let to = r.req.broker_email.clone().ok_or_else(|| {
            PrivacyError::Invalid("aucune adresse e-mail pour cet organisme".into())
        })?;
        let mail = compose(&st.profile, r, kind, &cfg.data_removal.language);
        if r.req.status == RemovalStatus::Queued && cfg.data_removal.send_mode == SendMode::Drafts {
            st.requests.requests[idx].req.status = RemovalStatus::DraftReady;
            store::save_json(&self.file(REQUESTS_FILE), &st.requests)
                .map_err(|e| PrivacyError::Failed(format!("enregistrement impossible : {e}")))?;
        }
        Ok(MailDraft {
            request_id: id.to_string(),
            to,
            subject: mail.subject,
            body: mail.body,
        })
    }

    pub async fn complaint(&self, cfg: &Config, id: &str) -> Result<ComplaintDraft, PrivacyError> {
        self.remember_config(cfg);
        let st = self.state.lock().await;
        if !profile_ready(&st.profile) {
            return Err(PrivacyError::Invalid(
                "renseignez d'abord votre identité (nom et adresse e-mail)".into(),
            ));
        }
        let r = st
            .requests
            .requests
            .iter()
            .find(|r| r.req.id == id)
            .ok_or_else(|| PrivacyError::NotFound(format!("demande {id} introuvable")))?;
        let french = st.profile.country.is_empty() || st.profile.country.eq_ignore_ascii_case("FR");
        let lang = if french || cfg.data_removal.language == "fr" {
            Lang::Fr
        } else {
            Lang::En
        };
        let (authority, url, text) =
            letters::complaint(&st.profile, &r.req, r.website.as_deref(), lang);
        Ok(ComplaintDraft {
            authority,
            url,
            text,
        })
    }

    pub async fn breaches(&self) -> Vec<BreachFinding> {
        let st = self.state.lock().await;
        let mut v = st.breaches.findings.clone();
        v.sort_by(|a, b| {
            b.new
                .cmp(&a.new)
                .then(b.first_seen.cmp(&a.first_seen))
                .then(a.email.cmp(&b.email))
        });
        v
    }

    pub async fn check_breaches(&self, cfg: &Config) -> Result<Vec<BreachFinding>, PrivacyError> {
        self.remember_config(cfg);
        let b = &cfg.breach;
        let mut emails: Vec<String> = Vec::new();
        for e in &b.emails {
            let e = e.trim().to_ascii_lowercase();
            if is_email(&e) && !emails.contains(&e) {
                emails.push(e);
            }
        }
        if emails.is_empty() {
            return Err(PrivacyError::Invalid(
                "aucune adresse à surveiller (breach.emails)".into(),
            ));
        }
        let pause = match b.provider {
            pb_core::config::BreachProvider::Hibp => Duration::from_millis(6500),
            pb_core::config::BreachProvider::XposedOrNot => Duration::from_millis(1500),
        };
        let mut results: Vec<(String, Vec<breach::Hit>)> = Vec::new();
        let mut error: Option<String> = None;
        for (i, e) in emails.iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(pause).await;
            }
            match breach::lookup(b.provider, e, b.hibp_api_key.as_deref(), &self.endpoints).await {
                Ok(h) => results.push((e.clone(), h)),
                Err(err) => {
                    error = Some(err.to_string());
                    break;
                }
            }
        }
        if results.is_empty() {
            return Err(PrivacyError::Unavailable(
                error.unwrap_or_else(|| "aucun résultat".into()),
            ));
        }
        let now = pb_core::now_ts();
        let (findings, new) = {
            let mut st = self.state.lock().await;
            let new = merge_findings(&mut st.breaches.findings, &results, now);
            if error.is_none() {
                st.breaches.last_check = now;
            }
            st.breaches.format = 1;
            self.save(BREACHES_FILE, &st.breaches);
            (st.breaches.findings.clone(), new)
        };
        if !new.is_empty() {
            let passwords = new
                .iter()
                .any(|f| breach::exposes_passwords(&f.data_classes));
            let lines: Vec<String> = new
                .iter()
                .take(15)
                .map(|f| {
                    let mut l = format!("{} : {}", f.email, f.breach);
                    if let Some(d) = &f.breach_date {
                        l.push_str(&format!(" ({d})"));
                    }
                    if !f.data_classes.is_empty() {
                        l.push_str(&format!(" — {}", f.data_classes.join(", ")));
                    }
                    l
                })
                .collect();
            let mut message = lines.join("\n");
            if new.len() > 15 {
                message.push_str(&format!("\n… et {} autre(s)", new.len() - 15));
            }
            if passwords {
                message.push_str(
                    "\nDes mots de passe ont fuité : changez-les sur ces sites et partout où vous les avez réutilisés, \
puis activez la double authentification.",
                );
            }
            self.hooks.alert(PrivacyAlert {
                severity: if passwords {
                    Severity::High
                } else {
                    Severity::Medium
                },
                title: format!("Fuite de données : {} nouvelle(s) exposition(s)", new.len()),
                message,
                key: format!(
                    "privacy:breach:{}",
                    short_hash(
                        &new.iter()
                            .map(|f| format!("{}|{}", f.email, f.breach))
                            .collect::<Vec<_>>()
                    )
                ),
            });
        }
        if let Some(e) = error {
            tracing::warn!(error = %e, "breach check incomplete");
        }
        let mut v = findings;
        v.sort_by(|a, b| {
            b.new
                .cmp(&a.new)
                .then(b.first_seen.cmp(&a.first_seen))
                .then(a.email.cmp(&b.email))
        });
        Ok(v)
    }

    pub async fn aliases(&self) -> Vec<EmailAlias> {
        let st = self.state.lock().await;
        let mut v = st.aliases.aliases.clone();
        v.sort_by_key(|a| std::cmp::Reverse(a.created_at));
        v
    }

    pub async fn create_alias(
        &self,
        cfg: &Config,
        label: &str,
    ) -> Result<EmailAlias, PrivacyError> {
        self.remember_config(cfg);
        let alias = aliases::create(&cfg.aliases, label, pb_core::now_ts())
            .await
            .map_err(PrivacyError::Failed)?;
        let mut st = self.state.lock().await;
        st.aliases.format = 1;
        st.aliases
            .aliases
            .retain(|a| !(a.provider == alias.provider && a.id == alias.id));
        st.aliases.aliases.push(alias.clone());
        self.save(ALIASES_FILE, &st.aliases);
        Ok(alias)
    }
}

fn list_names(names: &[String]) -> String {
    let mut v: Vec<&str> = names.iter().map(String::as_str).take(10).collect();
    v.sort_unstable();
    let mut s = v.join(", ");
    if names.len() > 10 {
        s.push_str(&format!(" et {} autre(s)", names.len() - 10));
    }
    s
}

fn compose(
    p: &IdentityProfile,
    r: &StoredRequest,
    kind: LetterKind,
    language: &str,
) -> OutgoingMail {
    let lang = letters::language_for(
        language,
        &r.region,
        r.req.broker_email.as_deref(),
        r.website.as_deref(),
    );
    let l = match kind {
        LetterKind::Initial => letters::erasure(p, &r.req.broker_name, lang),
        LetterKind::Reminder => letters::reminder(
            p,
            &r.req.broker_name,
            r.req.sent_at.unwrap_or(r.req.created_at),
            lang,
        ),
    };
    OutgoingMail {
        to: r.req.broker_email.clone().unwrap_or_default(),
        subject: l.subject,
        body: l.body,
    }
}

/// Merge lookup results; returns the findings seen for the first time (flag `new` reset on the others).
fn merge_findings(
    findings: &mut Vec<BreachFinding>,
    results: &[(String, Vec<breach::Hit>)],
    now: i64,
) -> Vec<BreachFinding> {
    for f in findings.iter_mut() {
        f.new = false;
    }
    let mut seen: HashSet<(String, String)> = findings
        .iter()
        .map(|f| (f.email.to_ascii_lowercase(), f.breach.to_lowercase()))
        .collect();
    let mut new = Vec::new();
    for (email, hits) in results {
        for h in hits {
            let key = (email.to_ascii_lowercase(), h.breach.to_lowercase());
            if let Some(f) = findings
                .iter_mut()
                .find(|f| (f.email.to_ascii_lowercase(), f.breach.to_lowercase()) == key)
            {
                if f.breach_date.is_none() {
                    f.breach_date = h.date.clone();
                }
                if f.data_classes.is_empty() {
                    f.data_classes = h.data_classes.clone();
                }
                continue;
            }
            if !seen.insert(key) {
                continue;
            }
            let f = BreachFinding {
                email: email.clone(),
                breach: h.breach.clone(),
                breach_date: h.date.clone(),
                data_classes: h.data_classes.clone(),
                first_seen: now,
                new: true,
            };
            new.push(f.clone());
            findings.push(f);
        }
    }
    new
}

#[cfg(test)]
mod tests;
