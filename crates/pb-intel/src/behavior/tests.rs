//! Synthetic event streams: a week of "normal" life, then novelties.

use super::*;

const DAY: i64 = 86_400;
const T0: i64 = 1_762_000_000;

fn app(path: &str, team: &str, sid: &str) -> ProcInfo {
    ProcInfo {
        path: path.into(),
        team_id: Some(team.into()),
        signing_id: Some(sid.into()),
        platform: false,
        adhoc: false,
    }
}

fn apple(path: &str, sid: &str) -> ProcInfo {
    ProcInfo {
        path: path.into(),
        team_id: None,
        signing_id: Some(sid.into()),
        platform: true,
        adhoc: false,
    }
}

fn exec(parent: &ProcInfo, target: &ProcInfo, hour: u8) -> BehaviorEvent {
    BehaviorEvent::Exec {
        parent: Some(parent.clone()),
        target: target.clone(),
        hour,
    }
}

fn editor() -> ProcInfo {
    app(
        "/Applications/Editor.app/Contents/MacOS/Editor",
        "ABCDE12345",
        "com.example.editor",
    )
}
fn helper() -> ProcInfo {
    app(
        "/Applications/Editor.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper",
        "ABCDE12345",
        "com.example.editor.helper",
    )
}
fn backup() -> ProcInfo {
    app("/Library/Backup/agent", "FGHIJ67890", "com.example.backup")
}
fn launchd() -> ProcInfo {
    apple("/sbin/launchd", "com.apple.xpc.launchd")
}

/// A week of routine: the editor spawns its helper during the day, the backup agent runs at night
/// and writes to temp, launchd starts both.
fn learn_week(b: &mut Baseline) {
    for day in 0..7 {
        for i in 0..40 {
            let t = T0 + day * DAY + i * 600;
            let hour = 9 + (i % 9) as u8;
            assert!(b
                .observe(&exec(&editor(), &helper(), hour), t, 7)
                .is_empty());
            assert!(b
                .observe(&exec(&launchd(), &editor(), hour), t, 7)
                .is_empty());
        }
        for i in 0..20 {
            let t = T0 + day * DAY + 3600 * 2 + i * 60;
            assert!(b.observe(&exec(&launchd(), &backup(), 2), t, 7).is_empty());
            let ev = BehaviorEvent::File {
                process: backup(),
                path: "/private/tmp/backup.lock".into(),
                hour: 2,
            };
            assert!(b.observe(&ev, t, 7).is_empty());
        }
    }
}

#[test]
fn learning_period_is_silent_then_novelty_scores() {
    let mut b = Baseline::new(T0);
    assert!(b.is_learning(T0 + DAY, 7));
    assert!((b.progress(T0 + 3 * DAY + DAY / 2, 7) - 0.5).abs() < 1e-3);
    learn_week(&mut b);
    let after = T0 + 7 * DAY + 3600;
    assert!(!b.is_learning(after, 7));

    // Routine continues: nothing to report.
    assert!(b
        .observe(&exec(&editor(), &helper(), 10), after, 7)
        .is_empty());

    // The narrow backup agent suddenly starts a shell: strong anomaly.
    let sh = apple("/bin/zsh", "com.apple.zsh");
    let out = b.observe(&exec(&backup(), &sh, 2), after + 10, 7);
    let a = out
        .iter()
        .find(|a| a.actor_key.starts_with("team:FGHIJ67890"))
        .expect("anomaly on the backup agent");
    assert!(a.score >= 0.7, "score {}", a.score);
    assert_eq!(a.main().unwrap().kind, ObsKind::Interpreter);
    assert!(AnomalyRecord::describe(a.main().unwrap()).contains("zsh"));

    // Seen once: the same thing no longer scores.
    let out = b.observe(&exec(&backup(), &sh, 2), after + 20, 7);
    assert!(out
        .iter()
        .all(|a| !a.actor_key.starts_with("team:FGHIJ67890")));

    // The backup agent writing a LaunchAgent (never seen anywhere on this Mac).
    let ev = BehaviorEvent::File {
        process: backup(),
        path: "/Users/camille/Library/LaunchAgents/com.evil.plist".into(),
        hour: 2,
    };
    let out = b.observe(&ev, after + 30, 7);
    assert_eq!(out.len(), 1);
    assert!(out[0].score >= 0.7, "score {}", out[0].score);
    assert_eq!(out[0].features[0].value, "launch_agents_user");
}

#[test]
fn unknown_processes_and_launchers_score_low() {
    let mut b = Baseline::new(T0);
    learn_week(&mut b);
    let after = T0 + 8 * DAY;
    // A brand-new app launched by launchd: launchd's novelty is expected-ish and the new app has no
    // history, so nothing reaches a typical alert threshold.
    let newapp = app(
        "/Applications/New.app/Contents/MacOS/New",
        "KLMNO11111",
        "com.example.new",
    );
    for a in b.observe(&exec(&launchd(), &newapp, 11), after, 7) {
        assert!(a.score < 0.7, "{a:?}");
    }
    // The new app spawning a shell right away: little history ⇒ low score.
    let sh = apple("/bin/sh", "com.apple.sh");
    for a in b.observe(&exec(&newapp, &sh, 11), after + 5, 7) {
        assert!(a.score < 0.5, "{a:?}");
    }
}

#[test]
fn unusual_hour_alone_stays_below_alert_level() {
    let mut b = Baseline::new(T0);
    learn_week(&mut b);
    let after = T0 + 8 * DAY;
    let out = b.observe(&exec(&editor(), &helper(), 3), after, 7);
    let a = out
        .iter()
        .find(|a| a.actor_key.contains("editor.helper"))
        .expect("hour novelty");
    assert_eq!(a.features[0].kind, ObsKind::Hour);
    assert!(a.score > 0.0 && a.score < 0.5, "score {}", a.score);
}

#[test]
fn mark_normal_suppresses_and_persists() {
    let mut b = Baseline::new(T0);
    learn_week(&mut b);
    let after = T0 + 8 * DAY;
    let curl = app("/opt/homebrew/bin/rclone", "PQRST22222", "rclone");
    let out = b.observe(&exec(&backup(), &curl, 2), after, 7);
    let a = out
        .into_iter()
        .find(|a| a.actor_key.starts_with("team:FGHIJ67890"))
        .unwrap();
    let id = a.id.clone();
    b.remember(a);
    assert!(b.mark_normal(&id, after + 1));
    assert!(!b.mark_normal("nope", after + 1));
    assert!(b.recent().next().unwrap().marked_normal);
    assert_eq!(b.stats().muted, 1);

    // Persistence round trip (gzip JSON), bounded and compact.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("baseline.json.gz");
    assert!(Baseline::load(&p).unwrap().is_none());
    let n = b.save(&p).unwrap();
    assert!(n < 400 * 1024, "{n} bytes");
    let back = Baseline::load(&p).unwrap().unwrap();
    assert_eq!(back, b);
    std::fs::write(&p, b"garbage").unwrap();
    assert!(Baseline::load(&p).is_err());
}

#[test]
fn bounded_actor_table() {
    let mut b = Baseline::new(T0);
    for i in 0..(MAX_ACTORS + 50) {
        let p = ProcInfo {
            path: format!("/opt/tools/t{i}"),
            ..Default::default()
        };
        let ev = BehaviorEvent::File {
            process: p,
            path: "/private/tmp/x".into(),
            hour: 1,
        };
        b.observe(&ev, T0 + i as i64, 7);
    }
    assert!(b.stats().actors as usize <= MAX_ACTORS);
    assert_eq!(b.stats().events, (MAX_ACTORS + 50) as u64);
}

#[test]
fn decay_keeps_seen_pairs() {
    let mut b = Baseline::new(T0);
    learn_week(&mut b);
    let later = T0 + 60 * DAY;
    // Long after: sketch halved, but routine pairs are still known.
    assert!(b
        .observe(&exec(&editor(), &helper(), 10), later, 7)
        .is_empty());
}
