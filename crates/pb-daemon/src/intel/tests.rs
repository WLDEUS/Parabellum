use super::*;
use crate::backends::Backends;
use crate::store::Store;
use pb_core::paths::Paths;

fn cfg() -> Config {
    Config::default()
}

fn inner() -> Inner {
    Inner {
        scorer: Arc::new(DomainScorer::heuristic_only()),
        ..Default::default()
    }
}

#[test]
fn allowlist_and_targets() {
    let allow = vec!["example.com".to_string()];
    assert!(allowlisted("example.com", &allow));
    assert!(allowlisted("a.b.example.com", &allow));
    assert!(!allowlisted("badexample.com", &allow));
    assert_eq!(block_target("login.paypal-check.xyz"), "paypal-check.xyz");
    assert_eq!(
        block_target("evil-paypal.github.io"),
        "evil-paypal.github.io"
    );
    assert_eq!(block_target("github.io"), "github.io");
}

#[test]
fn first_seen_names_are_scored_once_and_flagged() {
    let mut g = inner();
    let c = cfg();
    let out = process_name(&mut g, "paypal.com.account-verify.xyz", &c, 1000);
    let f = out.alert.expect("flagged by the rules fallback");
    assert_eq!(f.registrable, "account-verify.xyz");
    assert!(!f.blocked, "rules fallback never blocks");
    assert!(!out.blocked_now);
    assert_eq!(g.scored_total, 1);
    assert_eq!(g.domains.flagged_total, 1);
    // Seen again: no new score, hit counted.
    let out = process_name(&mut g, "PAYPAL.com.account-verify.xyz.", &c, 1001);
    assert_eq!(out, NameOutcome::default());
    assert_eq!(g.domains.flagged[0].hits, 2);
    assert_eq!(g.scored_total, 1);
    // Benign and local names.
    assert!(process_name(&mut g, "www.lemonde.fr", &c, 1002)
        .alert
        .is_none());
    assert!(process_name(&mut g, "printer.local", &c, 1002)
        .alert
        .is_none());
    assert_eq!(g.scored_total, 2);
    // Alerts off: still recorded, no alert.
    let mut c2 = cfg();
    c2.intelligence.domain_alerts = false;
    assert!(process_name(&mut g, "xn--80ak6aa92e.com", &c2, 1003)
        .alert
        .is_none());
    assert_eq!(g.domains.flagged.len(), 2);
}

#[test]
fn allowlisted_and_rate_limited_names_are_not_scored() {
    let mut g = inner();
    let mut c = cfg();
    c.intelligence.domain_allowlist = vec!["account-verify.xyz".into()];
    assert!(process_name(&mut g, "paypal.com.account-verify.xyz", &c, 5)
        .alert
        .is_none());
    assert_eq!(g.scored_total, 0);
    let c = cfg();
    for i in 0..(SCORE_RATE + 20) {
        process_name(&mut g, &format!("host{i}.example.org"), &c, 7);
    }
    assert_eq!(g.scored_total, u64::from(SCORE_RATE));
    // Dropped names were not marked seen: scored later.
    process_name(
        &mut g,
        &format!("host{}.example.org", SCORE_RATE + 1),
        &c,
        8,
    );
    assert_eq!(g.scored_total, u64::from(SCORE_RATE) + 1);
}

#[test]
fn blocking_needs_model_confidence_and_opt_in() {
    let model = pb_intel::domain::model::DomainModelMeta {
        features_version: pb_intel::domain::FEATURES_VERSION,
        threshold: 0.9,
        block_threshold: Some(0.95),
        version: Some("t".into()),
        brands_sha256: None,
        metrics: serde_json::Value::Null,
    };
    let names = pb_intel::domain::feature_names();
    let idx = names.iter().position(|n| *n == "brand_in_sub").unwrap();
    let dump = serde_json::json!({
        "num_class": 1, "num_tree_per_iteration": 1, "max_feature_idx": names.len() - 1,
        "objective": "binary sigmoid:1", "feature_names": names,
        "tree_info": [{"num_cat": 0, "tree_structure": {"split_feature": idx, "threshold": 0.5,
            "decision_type": "<=", "default_left": true, "missing_type": "None",
            "left_child": {"leaf_value": -5.0}, "right_child": {"leaf_value": 5.0}}}]
    })
    .to_string();
    let scorer = DomainScorer::from_parts(&dump, &model, None).unwrap();
    let mut g = Inner {
        scorer: Arc::new(scorer),
        ..Default::default()
    };
    let c = cfg();
    let out = process_name(&mut g, "paypal.secure-check.com", &c, 1);
    assert!(out.alert.is_some() && !out.blocked_now, "opt-in off");
    let mut c = cfg();
    c.intelligence.block_ml_domains = true;
    let out = process_name(&mut g, "login.paypal.verify-now.com", &c, 2);
    assert!(out.blocked_now);
    assert!(g.domains.ml_blocked.contains_key("verify-now.com"));
    assert!(out.alert.unwrap().blocked);
    assert!(g.rebuild_wanted);
}

fn test_ctx(dir: &Path) -> Arc<Ctx> {
    Arc::new(Ctx::new(
        Paths::with_root(dir),
        true,
        Store::open_in_memory().unwrap(),
        Backends::unavailable(),
        Config::default(),
    ))
}

#[tokio::test]
async fn behaviour_pipeline_alerts_after_learning_and_mark_normal() {
    let d = tempfile::tempdir().unwrap();
    let ctx = test_ctx(d.path());
    let mut c = Config::default();
    c.intelligence.learning_days = 1;
    ctx.publish_config(c);
    // Pretend learning started 2 days ago with a routine.
    let now = pb_core::now_ts();
    let mut b = Baseline::new(now - 2 * 86_400);
    let agent = ProcInfo {
        path: "/Library/Backup/agent".into(),
        team_id: Some("FGHIJ67890".into()),
        signing_id: Some("com.example.backup".into()),
        ..Default::default()
    };
    for i in 0..300 {
        b.observe(
            &BehaviorEvent::File {
                process: agent.clone(),
                path: "/private/tmp/backup.lock".into(),
                hour: 2,
            },
            now - 2 * 86_400 + i,
            1,
        );
    }
    ctx.intel.lock().baseline = Some(b);
    let (tx, rx) = mpsc::channel(16);
    let task = tokio::spawn(run_behavior(ctx.clone(), rx));
    // run_behavior loads the (absent) baseline file first: wait until it kept ours.
    tokio::time::sleep(Duration::from_millis(100)).await;
    if ctx.intel.lock().baseline.is_none() {
        panic!("baseline lost");
    }
    tx.send(BehaviorEvent::File {
        process: agent.clone(),
        path: "/Users/camille/Library/LaunchAgents/com.x.plist".into(),
        hour: 3,
    })
    .await
    .unwrap();
    let mut alert = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let alerts = ctx.store.run(|s| s.list_alerts(10, false)).await.unwrap();
        if let Some(a) = alerts.into_iter().find(|a| a.kind == AlertKind::Behavior) {
            alert = Some(a);
            break;
        }
    }
    let alert = alert.expect("behaviour alert raised");
    assert!(alert.actions.contains(&AlertAction::MarkNormal));
    let st = status(&ctx);
    assert!(!st.behavior.learning);
    assert_eq!(st.behavior.recent_anomalies.len(), 1);
    assert_eq!(st.behavior.recent_anomalies[0].kind, AnomalyKind::File);
    assert_eq!(st.behavior.recent_anomalies[0].alert_id, Some(alert.id));
    // Resolve through the alert action.
    let resolved = crate::actions::resolve_alert(&ctx, alert.id, AlertAction::MarkNormal)
        .await
        .unwrap();
    assert_eq!(resolved.status, AlertStatus::Resolved);
    assert!(status(&ctx).behavior.recent_anomalies[0].marked_normal);
    // Shutdown saves the baseline.
    ctx.shutdown.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(baseline_file(&ctx).is_file());
    reset_baseline(&ctx).await;
    assert!(status(&ctx).behavior.learning);
}

#[tokio::test]
async fn domain_status_score_and_allow() {
    let d = tempfile::tempdir().unwrap();
    let ctx = test_ctx(d.path());
    std::fs::create_dir_all(ctx.paths.state_dir()).unwrap();
    let v = score_domain(&ctx, "paypal.com.account-verify.xyz").unwrap();
    assert!(v.flagged && !v.would_block);
    assert_eq!(v.source.as_deref(), Some("heuristic"));
    assert!(score_domain(&ctx, "bad name").is_err());
    assert_eq!(
        score_domain(&ctx, "www.paypal.com")
            .unwrap()
            .skipped
            .as_deref(),
        Some("domaine officiel d'une marque")
    );
    {
        let c = ctx.config();
        let mut g = ctx.intel.lock();
        g.scorer = Arc::new(DomainScorer::heuristic_only());
        process_name(&mut g, "paypal.com.account-verify.xyz", &c, 1);
    }
    let st = status(&ctx);
    assert_eq!(st.domains.top_flagged.len(), 1);
    assert!(!st.domains.model_loaded);
    assert!(st.domains.message.is_some(), "DNS off");
    assert_eq!(st.models.len(), 2);
    allow_domain(&ctx, "login.account-verify.xyz")
        .await
        .unwrap();
    assert_eq!(
        ctx.config().intelligence.domain_allowlist,
        vec!["account-verify.xyz".to_string()]
    );
    assert!(status(&ctx).domains.top_flagged[0].allowed);
    assert!(
        score_domain(&ctx, "paypal.com.account-verify.xyz")
            .unwrap()
            .allowed
    );
    assert!(allow_domain(&ctx, "nodot").await.is_err());
}
