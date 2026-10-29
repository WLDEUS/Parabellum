//! Service-level tests (fake SMTP, temporary state and threat-DB directories).

use super::*;
use pb_core::db::{BrokersFile, PRIVACY_BROKERS};
use std::sync::Mutex;

#[derive(Default)]
struct Hooks(Mutex<Vec<PrivacyAlert>>);

impl PrivacyHooks for Hooks {
    fn alert(&self, alert: PrivacyAlert) {
        self.0.lock().unwrap().push(alert);
    }
}

#[derive(Default)]
struct FakeSmtp {
    sent: Mutex<Vec<OutgoingMail>>,
    fail: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl MailSender for FakeSmtp {
    async fn send(&self, smtp: &SmtpSettings, mail: &OutgoingMail) -> Result<(), String> {
        assert_eq!(smtp.host, "smtp.example.com");
        assert_eq!(smtp.from_name, "Camille Test");
        if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("535 authentication failed".into());
        }
        self.sent.lock().unwrap().push(mail.clone());
        Ok(())
    }
}

struct Env {
    _dir: tempfile::TempDir,
    paths: Paths,
    hooks: Arc<Hooks>,
    smtp: Arc<FakeSmtp>,
    svc: Arc<PrivacyService>,
}

fn broker(id: &str, email: Option<&str>, website: &str, region: &str) -> BrokerInfo {
    BrokerInfo {
        id: id.into(),
        name: format!("Org {id}"),
        email: email.map(str::to_string),
        website: Some(website.into()),
        opt_out_url: email
            .is_none()
            .then(|| format!("https://{id}.example/optout")),
        region: region.into(),
        category: "ads".into(),
        source: "datenanfragen".into(),
    }
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(dir.path());
    let db = paths.db_current();
    std::fs::create_dir_all(db.join("privacy")).unwrap();
    let file = BrokersFile {
        format: 1,
        sources: BTreeMap::new(),
        brokers: vec![
            broker("sls", Some("dpo@sls-data.fr"), "https://sls-data.fr", "eu"),
            broker(
                "criteo",
                Some("dpo@criteo.com"),
                "https://www.criteo.com",
                "eu",
            ),
            broker("formonly", None, "https://formonly.example", "global"),
            broker(
                "spokeo",
                Some("privacy@spokeo.com"),
                "https://www.spokeo.com",
                "us",
            ),
        ],
    };
    std::fs::write(db.join(PRIVACY_BROKERS), serde_json::to_vec(&file).unwrap()).unwrap();
    let hooks = Arc::new(Hooks::default());
    let smtp = Arc::new(FakeSmtp::default());
    let mut svc = PrivacyService::build(paths.clone(), hooks.clone(), smtp.clone());
    svc.spacing = Duration::from_millis(1);
    Env {
        _dir: dir,
        paths,
        hooks,
        smtp,
        svc: Arc::new(svc),
    }
}

fn me() -> IdentityProfile {
    IdentityProfile {
        full_name: "  Camille   Test ".into(),
        emails: vec!["q@example.fr".into(), "Q@example.fr".into(), "".into()],
        phones: vec!["+33 6 12 34 56 78".into()],
        postal_address: "1 rue de la Paix\n\n75002 Paris".into(),
        previous_addresses: vec![],
        birth_date: String::new(),
        country: String::new(),
    }
}

fn cfg(mode: SendMode) -> Config {
    let mut c = Config::default();
    c.data_removal.enabled = true;
    c.data_removal.send_mode = mode;
    c.data_removal.smtp_host = "smtp.example.com".into();
    c.data_removal.from_address = "q@example.fr".into();
    c.data_removal.smtp_password = Some("pw".into());
    c
}

#[test]
fn masking_and_validation() {
    let p = validate_profile(me()).unwrap();
    assert_eq!(p.full_name, "Camille Test");
    assert_eq!(p.emails, vec!["q@example.fr"]);
    assert_eq!(p.postal_address, "1 rue de la Paix\n75002 Paris");
    assert_eq!(p.country, "FR");
    let m = mask_profile(&p);
    assert_eq!(m.full_name, "C****** T***");
    assert_eq!(m.emails, vec!["q***@example.fr"]);
    assert_eq!(m.phones, vec!["*********78"]);
    assert_eq!(m.postal_address, "***");
    assert!(m.birth_date.is_empty());
    let mut bad = me();
    bad.emails = vec!["nope".into()];
    assert!(validate_profile(bad).is_err());
    let mut bad = me();
    bad.birth_date = "02/01/1999".into();
    assert!(validate_profile(bad).is_err());
    let mut bad = me();
    bad.full_name = " ".into();
    assert!(validate_profile(bad).is_err());
    let mut bad = me();
    bad.phones = vec!["call me; rm -rf".into()];
    assert!(validate_profile(bad).is_err());
}

#[tokio::test]
async fn profile_persistence() {
    let e = env();
    assert_eq!(e.svc.get_profile(true).await, IdentityProfile::default());
    let masked = e.svc.set_profile(me()).await.unwrap();
    assert_eq!(masked.emails, vec!["q***@example.fr"]);
    assert_eq!(e.svc.get_profile(true).await.full_name, "Camille Test");
    // Reload from disk.
    let again = PrivacyService::with_sender(e.paths.clone(), e.hooks.clone(), e.smtp.clone());
    assert_eq!(again.get_profile(true).await.emails, vec!["q@example.fr"]);
    assert_eq!(again.get_profile(false).await.full_name, "C****** T***");
}

#[tokio::test]
async fn smtp_campaign() {
    let e = env();
    let c = cfg(SendMode::Smtp);
    assert!(
        e.svc.start_removal(&c, None).await.is_err(),
        "profile required"
    );
    e.svc.set_profile(me()).await.unwrap();
    let mut off = c.clone();
    off.data_removal.enabled = false;
    assert!(e.svc.start_removal(&off, None).await.is_err());
    assert_eq!(e.svc.brokers(&c).await.len(), 3, "eu + global by default");
    let s = e.svc.start_removal(&c, None).await.unwrap();
    assert_eq!((s.total, s.queued, s.needs_action), (3, 2, 1));
    assert!(s.next_send_at.is_some());
    // Idempotent.
    assert_eq!(e.svc.start_removal(&c, None).await.unwrap().total, 3);
    assert!(
        e.svc
            .start_removal(&c, Some(vec!["spokeo".into()]))
            .await
            .is_err(),
        "us not selected"
    );

    let (_tx, mut rx) = watch::channel(false);
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    // Spacing (30 s) stops the loop after one email.
    {
        let sent = e.smtp.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].to == "dpo@sls-data.fr" || sent[0].to == "dpo@criteo.com");
    }
    e.svc.state.lock().await.outbox.last_sent_at -= 60;
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    let sent = e.smtp.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    let fr = sent.iter().find(|m| m.to == "dpo@sls-data.fr").unwrap();
    assert!(fr.subject.starts_with("Demande d'effacement"));
    let en = sent.iter().find(|m| m.to == "dpo@criteo.com").unwrap();
    assert!(en.subject.starts_with("Request for erasure"));
    let reqs = e.svc.requests().await;
    assert_eq!(
        reqs.iter()
            .filter(|r| r.status == RemovalStatus::Sent)
            .count(),
        2
    );
    assert!(
        reqs.iter()
            .all(|r| r.status != RemovalStatus::Sent
                || r.due_at == r.sent_at.map(|t| t + 30 * 86_400))
    );
    let st = e.svc.state.lock().await;
    assert_eq!(st.outbox.sent_today(&local_day(pb_core::now_ts())), 2);
    drop(st);
    // Quota: max 2 per day.
    let mut c2 = c.clone();
    c2.data_removal.max_emails_per_day = 2;
    {
        let mut st = e.svc.state.lock().await;
        st.outbox.last_sent_at -= 60;
        let r = st
            .requests
            .requests
            .iter_mut()
            .find(|r| r.req.status == RemovalStatus::Sent)
            .unwrap();
        r.req.due_at = Some(0);
    }
    e.svc.tick(&c2, pb_core::now_ts(), &mut rx).await;
    assert_eq!(e.smtp.sent.lock().unwrap().len(), 2, "quota reached");
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    let sent = e.smtp.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 3);
    assert!(sent[2].subject.starts_with("Relance") || sent[2].subject.starts_with("Reminder"));
    assert!(e
        .svc
        .requests()
        .await
        .iter()
        .any(|r| r.status == RemovalStatus::Reminded));
    // Files are private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(e.paths.privacy_dir().join(REQUESTS_FILE)).unwrap();
        assert_eq!(m.permissions().mode() & 0o777, 0o600);
    }
}

#[tokio::test]
async fn smtp_failure_alerts_and_retries() {
    let e = env();
    let c = cfg(SendMode::Smtp);
    e.svc.set_profile(me()).await.unwrap();
    e.svc
        .start_removal(&c, Some(vec!["sls".into()]))
        .await
        .unwrap();
    e.smtp.fail.store(true, std::sync::atomic::Ordering::SeqCst);
    let (_tx, mut rx) = watch::channel(false);
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    let reqs = e.svc.requests().await;
    assert_eq!(reqs[0].status, RemovalStatus::Queued);
    assert!(reqs[0].last_error.as_deref().unwrap().contains("535"));
    let alerts = e.hooks.0.lock().unwrap().clone();
    assert!(alerts.iter().any(|a| a.title.contains("envoi")));
    // Not retried before tomorrow.
    e.svc.state.lock().await.outbox.last_sent_at -= 60;
    e.smtp
        .fail
        .store(false, std::sync::atomic::Ordering::SeqCst);
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    assert!(e.smtp.sent.lock().unwrap().is_empty());
    assert_eq!(
        e.svc.state.lock().await.outbox.sent,
        0,
        "failures do not consume the quota"
    );
}

#[tokio::test]
async fn drafts_reminder_escalation_complaint() {
    let e = env();
    let c = cfg(SendMode::Drafts);
    e.svc.set_profile(me()).await.unwrap();
    e.svc.start_removal(&c, None).await.unwrap();
    let reqs = e.svc.requests().await;
    let sls = reqs.iter().find(|r| r.broker_id == "sls").unwrap().clone();
    let form = reqs
        .iter()
        .find(|r| r.broker_id == "formonly")
        .unwrap()
        .clone();
    assert!(e
        .svc
        .draft(&c, &form.id)
        .await
        .unwrap_err()
        .to_string()
        .contains("formulaire"));
    let d = e.svc.draft(&c, &sls.id).await.unwrap();
    assert_eq!(d.to, "dpo@sls-data.fr");
    assert!(d.body.contains("- Nom : Camille Test"));
    assert_eq!(
        e.svc
            .requests()
            .await
            .iter()
            .find(|r| r.id == sls.id)
            .unwrap()
            .status,
        RemovalStatus::DraftReady
    );
    let (_tx, mut rx) = watch::channel(false);
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    assert!(
        e.smtp.sent.lock().unwrap().is_empty(),
        "drafts mode never sends"
    );
    // The user sent it 31 days ago.
    e.svc
        .update_request(
            &sls.id,
            RemovalStatus::Sent,
            Some("envoyé depuis Mail".into()),
        )
        .await
        .unwrap();
    {
        let mut st = e.svc.state.lock().await;
        let r = st
            .requests
            .requests
            .iter_mut()
            .find(|r| r.req.id == sls.id)
            .unwrap();
        r.req.sent_at = Some(pb_core::now_ts() - 31 * 86_400);
        r.req.due_at = Some(pb_core::now_ts() - 86_400);
    }
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    assert!(e
        .hooks
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|a| a.title.contains("relance")));
    let n = e.hooks.0.lock().unwrap().len();
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    assert_eq!(
        e.hooks.0.lock().unwrap().len(),
        n,
        "one reminder alert per day"
    );
    let rem = e.svc.draft(&c, &sls.id).await.unwrap();
    assert!(rem.subject.starts_with("Relance"));
    e.svc
        .update_request(&sls.id, RemovalStatus::Reminded, None)
        .await
        .unwrap();
    {
        let mut st = e.svc.state.lock().await;
        let r = st
            .requests
            .requests
            .iter_mut()
            .find(|r| r.req.id == sls.id)
            .unwrap();
        r.req.reminded_at = Some(pb_core::now_ts() - 16 * 86_400);
    }
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    let r = e
        .svc
        .requests()
        .await
        .into_iter()
        .find(|r| r.id == sls.id)
        .unwrap();
    assert_eq!(r.status, RemovalStatus::Escalated);
    assert!(e
        .hooks
        .0
        .lock()
        .unwrap()
        .iter()
        .any(|a| a.title.contains("sans réponse")));
    let comp = e.svc.complaint(&c, &sls.id).await.unwrap();
    assert_eq!(comp.authority, "CNIL");
    assert!(comp
        .text
        .contains("Org sls\ndpo@sls-data.fr\nhttps://sls-data.fr"));
    let s = e.svc.summary(&c).await;
    assert!(s.overdue >= 1 && s.next_send_at.is_none());
    // Completed + repeat.
    e.svc
        .update_request(&sls.id, RemovalStatus::Completed, None)
        .await
        .unwrap();
    {
        let mut st = e.svc.state.lock().await;
        let r = st
            .requests
            .requests
            .iter_mut()
            .find(|r| r.req.id == sls.id)
            .unwrap();
        r.req.closed_at = Some(pb_core::now_ts() - 181 * 86_400);
    }
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    let open_sls = e
        .svc
        .requests()
        .await
        .into_iter()
        .filter(|r| r.broker_id == "sls" && r.status == RemovalStatus::Queued)
        .count();
    assert_eq!(open_sls, 1);
    e.svc.tick(&c, pb_core::now_ts(), &mut rx).await;
    assert_eq!(
        e.svc
            .requests()
            .await
            .iter()
            .filter(|r| r.broker_id == "sls")
            .count(),
        2,
        "no duplicate repeat"
    );
}

#[test]
fn findings_merge() {
    let mut f = vec![];
    let hit = |n: &str| breach::Hit {
        breach: n.into(),
        date: Some("2015".into()),
        data_classes: vec!["Passwords".into()],
    };
    let new = merge_findings(
        &mut f,
        &[("a@x.fr".into(), vec![hit("A"), hit("B"), hit("a")])],
        10,
    );
    assert_eq!(new.len(), 2);
    let new = merge_findings(&mut f, &[("a@x.fr".into(), vec![hit("A"), hit("C")])], 20);
    assert_eq!(new.len(), 1);
    assert_eq!(new[0].breach, "C");
    assert_eq!(f.iter().filter(|x| x.new).count(), 1);
    assert_eq!(f.len(), 3);
}

#[test]
fn local_days() {
    let now = pb_core::now_ts();
    let next = next_local_midnight(now);
    assert!(next > now && next - now <= 25 * 3600);
    assert_ne!(local_day(now), local_day(next));
}
