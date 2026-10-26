//! End-to-end: an in-process daemon (dev mode, temp root, real engine + quarantine + updater, DNS and
//! monitors stubbed) driven through the `parabellum` CLI code and a raw subscriber connection.

use pb_cli::client::Client;
use pb_cli::{run, Cli, Output};
use pb_core::config::Config;
use pb_core::events::{FileEventSource, MonitorEvent};
use pb_core::ipc::*;
use pb_core::model::*;
use pb_core::paths::Paths;
use pb_daemon::backends::{NullDns, NullMonitors};
use pb_daemon::daemon::{start, Daemon, DaemonOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

async fn daemon(root: &Path, skip_baselines: bool) -> Daemon {
    let paths = Paths::with_root(root);
    pb_daemon::setup::prepare_dirs(&paths, false).unwrap();
    if skip_baselines {
        let s = pb_daemon::store::Store::open(&paths.state_db()).unwrap();
        s.kv_set(pb_daemon::baseline::Kind::Persistence.kv_key(), "1")
            .unwrap();
        s.kv_set(pb_daemon::baseline::Kind::Devices.kv_key(), "1")
            .unwrap();
    }
    let mut backends = pb_daemon::adapters::production(&paths);
    backends.dns = Arc::new(NullDns);
    backends.monitors = Arc::new(NullMonitors);
    start(DaemonOptions {
        paths,
        dev_mode: true,
        backends,
        start_monitors: false,
        start_scheduler: false,
    })
    .await
    .expect("daemon starts")
}

/// Run the CLI with `args` against `sock`: (exit code, stdout, stderr).
async fn cli(sock: &Path, args: &[&str]) -> (i32, String, String) {
    let mut v: Vec<String> = vec![
        "parabellum".into(),
        "--socket".into(),
        sock.display().to_string(),
    ];
    v.extend(args.iter().map(|s| s.to_string()));
    tokio::task::spawn_blocking(move || {
        let cli = Cli::try_parse_args(v).expect("valid command line");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(
            &cli,
            &mut Output {
                out: &mut out,
                err: &mut err,
                progress: false,
            },
        );
        (
            code,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    })
    .await
    .unwrap()
}

async fn cli_json<T: serde::de::DeserializeOwned>(sock: &Path, args: &[&str]) -> T {
    let mut a = vec!["--json"];
    a.extend_from_slice(args);
    let (code, out, err) = cli(sock, &a).await;
    assert_eq!(code, 0, "{args:?}: {err}");
    serde_json::from_str(&out).unwrap_or_else(|e| panic!("{args:?}: {e}: {out}"))
}

/// Collect events from a subscribed connection in a background thread.
fn subscriber(sock: &Path) -> std::sync::mpsc::Receiver<DaemonEvent> {
    let mut c = Client::connect(sock, Some(Duration::from_secs(5))).unwrap();
    c.subscribe().unwrap();
    c.set_timeout(Some(Duration::from_secs(30))).unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        while let Ok(ev) = c.next_event() {
            if tx.send(ev).is_err() {
                break;
            }
        }
    });
    rx
}

fn drain(rx: &std::sync::mpsc::Receiver<DaemonEvent>, wait: Duration) -> Vec<DaemonEvent> {
    let mut v = Vec::new();
    let deadline = std::time::Instant::now() + wait;
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(e) => v.push(e),
            Err(_) => break,
        }
    }
    v
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn basic_commands_and_config() {
    let root = tempfile::tempdir().unwrap();
    let d = daemon(root.path(), false).await;
    let sock = d.ctx().paths.socket.clone();

    let (code, out, _) = cli(&sock, &["ping"]).await;
    assert_eq!(code, 0);
    assert!(out.contains("protocole 1"), "{out}");

    let st: StatusInfo = cli_json(&sock, &["status"]).await;
    assert_eq!(st.version, pb_core::VERSION);
    assert_eq!(st.protection, ProtectionState::Degraded);
    assert!(st
        .issues
        .iter()
        .any(|i| i.contains("Accès complet au disque")));
    let (code, out, _) = cli(&sock, &["status"]).await;
    assert_eq!(code, 0);
    assert!(out.contains("protection dégradée"), "{out}");

    // config get / set
    let (code, toml_text, _) = cli(&sock, &["config", "get"]).await;
    assert_eq!(code, 0);
    assert_eq!(Config::from_toml(&toml_text).unwrap(), Config::default());
    let mut cfg = Config::default();
    cfg.updates.daily_hour = 5;
    cfg.privacy.virustotal_api_key = Some("k3y".into());
    let f = root.path().join("new.toml");
    std::fs::write(&f, cfg.to_toml().unwrap()).unwrap();
    let (code, out, err) = cli(&sock, &["config", "set", f.to_str().unwrap()]).await;
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("enregistrée"));
    let got: Config = cli_json(&sock, &["config", "get"]).await;
    assert_eq!(got.updates.daily_hour, 5);
    assert_eq!(
        got.privacy.virustotal_api_key.as_deref(),
        Some("k3y"),
        "authorized peer sees secrets"
    );
    assert_eq!(
        Config::load(&d.ctx().paths.config_file())
            .unwrap()
            .updates
            .daily_hour,
        5
    );
    // Invalid file refused client-side.
    std::fs::write(&f, "[updates]\ndaily_hour = 99\n").unwrap();
    let (code, _, err) = cli(&sock, &["config", "set", f.to_str().unwrap()]).await;
    assert_eq!(code, 2);
    assert!(err.contains("daily_hour"), "{err}");

    // alerts, pause / resume, report, dns, components, fp
    let (code, out, _) = cli(&sock, &["alerts"]).await;
    assert_eq!((code, out.as_str()), (0, "Aucune alerte.\n"));
    let st: StatusInfo = cli_json(&sock, &["pause", "15"]).await;
    assert_eq!(st.protection, ProtectionState::Paused);
    assert!(st.paused_until.unwrap() > pb_core::now_ts());
    let st: StatusInfo = cli_json(&sock, &["resume"]).await;
    assert_ne!(st.protection, ProtectionState::Paused);
    let r: WeeklyReport = cli_json(&sock, &["report"]).await;
    assert!(r.week_end - r.week_start >= 6 * 86_400);
    let dns: DnsStatus = cli_json(&sock, &["dns", "status"]).await;
    assert!(!dns.enabled);
    let (code, out, err) = cli(&sock, &["dns", "off"]).await;
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("désactivé"));
    let comps: Vec<ComponentStatus> = cli_json(&sock, &["components"]).await;
    assert!(comps.iter().any(|c| c.name == "threat-db"));
    let (code, _, err) = cli(&sock, &["fp", &"ab".repeat(32), "--note", "test"]).await;
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = cli(&sock, &["fp", "nothex"]).await;
    assert_eq!(code, 2);
    assert!(err.contains("SHA-256"));
    let (code, _, err) = cli(&sock, &["resolve", "999", "acknowledge"]).await;
    assert_eq!(code, 2);
    assert!(err.contains("introuvable"), "{err}");
    let (code, _, err) = cli(&sock, &["job", "nope"]).await;
    assert_eq!(code, 2);
    assert!(err.contains("introuvable"), "{err}");

    // Malformed input never kills the server; the connection keeps working.
    let mut raw = std::os::unix::net::UnixStream::connect(&sock).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    raw.write_all(b"this is not json\n{\"id\":5,\"cmd\":\"bogus\"}\n{\"id\":6,\"cmd\":\"ping\"}\n")
        .unwrap();
    let mut r = BufReader::new(raw.try_clone().unwrap());
    let mut lines = Vec::new();
    for _ in 0..3 {
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        lines.push(serde_json::from_str::<ResponseEnvelope>(l.trim()).unwrap());
    }
    assert_eq!((lines[0].id, lines[0].ok), (0, false));
    assert_eq!(lines[0].error.as_ref().unwrap().code, ErrorCode::BadRequest);
    assert_eq!((lines[1].id, lines[1].ok), (5, false));
    assert_eq!((lines[2].id, lines[2].ok), (6, true));

    let sock_path = sock.clone();
    d.shutdown().await;
    assert!(!sock_path.exists(), "socket removed at shutdown");
    let (code, _, err) = cli(&sock_path, &["ping"]).await;
    assert_eq!(code, 2);
    assert!(err.contains("impossible de joindre"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_quarantines_eicar_and_restores() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let d = daemon(root.path(), false).await;
    let sock = d.ctx().paths.socket.clone();
    let events = subscriber(&sock);

    let eicar = data.path().join("eicar.com");
    std::fs::write(&eicar, EICAR).unwrap();
    std::fs::create_dir(data.path().join("sub")).unwrap();
    std::fs::write(data.path().join("sub/notes.txt"), b"just some notes").unwrap();

    let (code, out, err) = cli(&sock, &["scan", data.path().to_str().unwrap()]).await;
    assert_eq!(code, 1, "threats ⇒ exit 1\n{out}\n{err}");
    assert!(out.contains("EICAR-Test-File"), "{out}");
    assert!(!eicar.exists(), "EICAR moved to quarantine");
    assert!(data.path().join("sub/notes.txt").exists());

    let q: Vec<QuarantineEntry> = cli_json(&sock, &["quarantine"]).await;
    assert_eq!(q.len(), 1);
    assert_eq!(
        Path::new(&q[0].original_path),
        std::fs::canonicalize(data.path())
            .unwrap()
            .join("eicar.com")
    );
    let alerts: Vec<Alert> = cli_json(&sock, &["alerts"]).await;
    assert_eq!(alerts.len(), 1);
    let a = &alerts[0];
    assert_eq!(a.kind, AlertKind::Malware);
    assert!(a.severity >= Severity::High);
    assert_eq!(a.quarantine_id.as_deref(), Some(q[0].id.as_str()));
    assert!(a.actions.contains(&AlertAction::Restore));

    let jobs: Vec<ScanJobSummary> = cli_json(&sock, &["jobs"]).await;
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].state, JobState::Finished);
    assert_eq!(jobs[0].threats, 1);
    assert!(jobs[0].files_scanned >= 2);
    let detail: ScanJobDetail = cli_json(&sock, &["job", &jobs[0].job_id]).await;
    assert!(detail
        .findings
        .iter()
        .any(|f| f.verdict == Verdict::Malicious));

    let evs = drain(&events, Duration::from_millis(1500));
    assert!(
        evs.iter()
            .any(|e| matches!(e, DaemonEvent::Quarantined(x) if x.id == q[0].id)),
        "{evs:?}"
    );
    assert!(evs
        .iter()
        .any(|e| matches!(e, DaemonEvent::Alert(x) if x.id == a.id)));
    assert!(evs
        .iter()
        .any(|e| matches!(e, DaemonEvent::ScanFinished(j) if j.threats == 1)));
    assert!(evs
        .iter()
        .any(|e| matches!(e, DaemonEvent::StatusChanged(_))));

    // Restore + allow: the file comes back and is no longer a threat.
    let (code, out, err) = cli(&sock, &["quarantine", "restore", &q[0].id, "--allow"]).await;
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("restauré"));
    assert!(eicar.exists());
    let alerts: Vec<Alert> = cli_json(&sock, &["alerts"]).await;
    assert!(alerts.is_empty(), "linked alert resolved: {alerts:?}");
    let (code, out, _) = cli(&sock, &["scan", eicar.to_str().unwrap()]).await;
    assert_eq!(code, 0, "allowlisted ⇒ clean\n{out}");
    let q: Vec<QuarantineEntry> = cli_json(&sock, &["quarantine"]).await;
    assert!(q.is_empty());

    // --no-wait returns the job id at once; cancel of a finished job is not found.
    let j: JobStarted =
        cli_json(&sock, &["scan", "--no-wait", data.path().to_str().unwrap()]).await;
    assert!(!j.job_id.is_empty());
    let (code, _, err) = cli(&sock, &["scan", "/definitely/not/here"]).await;
    assert_eq!(code, 2);
    assert!(err.contains("introuvable"), "{err}");

    let st: StatusInfo = cli_json(&sock, &["status"]).await;
    assert!(st.last_scan.is_some());
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn manual_quarantine_and_delete() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let d = daemon(root.path(), false).await;
    let sock = d.ctx().paths.socket.clone();
    let f = data.path().join("doubt.bin");
    std::fs::write(&f, b"whatever").unwrap();
    let e: QuarantineEntry = cli_json(&sock, &["quarantine", "add", f.to_str().unwrap()]).await;
    assert!(!f.exists());
    let (code, _, err) = cli(&sock, &["quarantine", "delete", &e.id]).await;
    assert_eq!(code, 0, "{err}");
    let q: Vec<QuarantineEntry> = cli_json(&sock, &["quarantine"]).await;
    assert!(q.is_empty());
    // Our own files and system paths are refused.
    let own = d.ctx().paths.config_file();
    let (code, _, err) = cli(&sock, &["quarantine", "add", own.to_str().unwrap()]).await;
    assert_eq!(code, 2);
    assert!(err.contains("Parabellum"), "{err}");
    d.shutdown().await;
}

async fn wait_for<T>(mut f: impl FnMut() -> Option<T>, what: &str) -> T {
    for _ in 0..100 {
        if let Some(v) = f() {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timeout waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn monitor_events_realtime_devices_persistence() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let d = daemon(root.path(), true).await;
    let sock = d.ctx().paths.socket.clone();
    let tx = d.monitor_sender();

    // Real-time: file activity on an EICAR file ⇒ debounce ⇒ scan ⇒ auto-quarantine.
    let eicar = data.path().join("dl-eicar.com");
    std::fs::write(&eicar, EICAR).unwrap();
    for _ in 0..3 {
        tx.send(MonitorEvent::FileActivity {
            path: eicar.to_string_lossy().into_owned(),
            source: FileEventSource::FsEvents,
            process: None,
        })
        .await
        .unwrap();
    }
    let ctx = d.ctx().clone();
    wait_for(|| (!eicar.exists()).then_some(()), "real-time quarantine").await;
    let alerts = wait_for(
        || {
            let a = ctx.store.list_alerts(10, false).ok()?;
            (!a.is_empty()).then_some(a)
        },
        "alert",
    )
    .await;
    assert_eq!(alerts[0].kind, AlertKind::Malware);
    assert!(alerts[0].quarantine_id.is_some());
    assert!(ctx
        .store
        .files_seen_since(0, 10)
        .unwrap()
        .iter()
        .any(|f| f.path.ends_with("dl-eicar.com")));

    // New keyboard (not built-in) ⇒ high device alert; trust it from the CLI.
    let mut details = std::collections::BTreeMap::new();
    details.insert("is_keyboard".to_string(), "true".to_string());
    details.insert("built_in".to_string(), "false".to_string());
    let kb = DeviceInfo {
        id: "hid:dead:beef:1".into(),
        kind: DeviceKind::Hid,
        name: "USB Keyboard".into(),
        vendor: None,
        vendor_id: Some(0xdead),
        product_id: Some(0xbeef),
        serial: None,
        transport: Some("USB".into()),
        details,
        first_seen: 0,
        last_seen: 0,
        connected: true,
        trust: DeviceTrust::Unknown,
        baseline: false,
    };
    tx.send(MonitorEvent::Device(DeviceEvent {
        device: kb.clone(),
        change: DeviceChange::Connected,
    }))
    .await
    .unwrap();
    let a = wait_for(
        || {
            ctx.store
                .list_alerts(10, false)
                .ok()?
                .into_iter()
                .find(|a| a.kind == AlertKind::Device)
        },
        "device alert",
    )
    .await;
    assert_eq!(a.severity, Severity::High);
    assert_eq!(a.device_id.as_deref(), Some(kb.id.as_str()));
    let (code, _, err) = cli(&sock, &["resolve", &a.id.to_string(), "trust-device"]).await;
    assert_eq!(code, 0, "{err}");
    let devs: Vec<DeviceInfo> = cli_json(&sock, &["devices", "--kind", "hid"]).await;
    assert_eq!(devs.len(), 1);
    assert_eq!(devs[0].trust, DeviceTrust::Trusted);

    // Volumes mounted by the engine under tmp/ are ignored.
    let mut vd = std::collections::BTreeMap::new();
    vd.insert(
        "mount_point".to_string(),
        d.ctx()
            .paths
            .tmp_dir()
            .join("dmg1")
            .to_string_lossy()
            .into_owned(),
    );
    let vol = DeviceInfo {
        id: "vol:own".into(),
        kind: DeviceKind::Volume,
        name: "X".into(),
        details: vd,
        ..kb.clone()
    };
    tx.send(MonitorEvent::Device(DeviceEvent {
        device: vol,
        change: DeviceChange::Connected,
    }))
    .await
    .unwrap();

    // New LaunchAgent (unsigned program) ⇒ persistence alert; approve it from the CLI.
    let prog = data.path().join("agent");
    std::fs::write(&prog, b"#!/bin/sh\necho hi\n").unwrap();
    let item = PersistenceItem {
        id: "0123456789abcdef".into(),
        kind: PersistenceKind::LaunchAgent,
        label: Some("com.example.agent".into()),
        path: data
            .path()
            .join("com.example.agent.plist")
            .to_string_lossy()
            .into_owned(),
        program: Some(prog.to_string_lossy().into_owned()),
        arguments: vec![],
        user: None,
        signing: None,
        program_sha256: None,
        first_seen: 0,
        last_seen: 0,
        status: PersistenceStatus::New,
        verdict: None,
    };
    tx.send(MonitorEvent::Persistence {
        item,
        change: PersistenceChangeKind::Added,
    })
    .await
    .unwrap();
    let p = wait_for(
        || {
            ctx.store
                .list_alerts(10, false)
                .ok()?
                .into_iter()
                .find(|a| a.kind == AlertKind::Persistence)
        },
        "persistence alert",
    )
    .await;
    assert_eq!(p.severity, Severity::High, "unsigned ⇒ high");
    let items: Vec<PersistenceItem> = cli_json(&sock, &["persistence", "--new"]).await;
    assert_eq!(items.len(), 1);
    assert!(
        items[0].program_sha256.is_some(),
        "program hashed during enrichment"
    );
    let (code, _, err) = cli(&sock, &["persistence", "approve", "0123456789abcdef"]).await;
    assert_eq!(code, 0, "{err}");
    let items: Vec<PersistenceItem> = cli_json(&sock, &["persistence", "--new"]).await;
    assert!(items.is_empty());
    assert!(ctx.store.get_alert(p.id).unwrap().unwrap().status == AlertStatus::Resolved);

    // Health events feed the status.
    tx.send(MonitorEvent::MonitorHealth {
        monitor: "fsevents".into(),
        ok: true,
        message: "ok".into(),
    })
    .await
    .unwrap();
    wait_for(|| ctx.state().health.fsevents.then_some(()), "health").await;
    let devs: Vec<DeviceInfo> = cli_json(&sock, &["devices"]).await;
    assert!(devs.iter().all(|d| d.id != "vol:own"));
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_run_baseline_is_silent() {
    let root = tempfile::tempdir().unwrap();
    let d = daemon(root.path(), false).await;
    let tx = d.monitor_sender();
    let dev = DeviceInfo {
        id: "wifi:Home".into(),
        kind: DeviceKind::WifiNetwork,
        name: "Home".into(),
        vendor: None,
        vendor_id: None,
        product_id: None,
        serial: None,
        transport: None,
        details: Default::default(),
        first_seen: 0,
        last_seen: 0,
        connected: true,
        trust: DeviceTrust::Unknown,
        baseline: false,
    };
    tx.send(MonitorEvent::Device(DeviceEvent {
        device: dev,
        change: DeviceChange::Connected,
    }))
    .await
    .unwrap();
    let ctx = d.ctx().clone();
    wait_for(
        || ctx.store.get_device("wifi:Home").ok().flatten(),
        "device stored",
    )
    .await;
    assert!(ctx.store.get_device("wifi:Home").unwrap().unwrap().baseline);
    assert!(ctx.store.list_alerts(10, true).unwrap().is_empty());
    d.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn archive_member_detection_quarantines_the_container_once() {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let d = daemon(root.path(), false).await;
    let sock = d.ctx().paths.socket.clone();
    let zip_path = data.path().join("bundle.zip");
    {
        let f = std::fs::File::create(&zip_path).unwrap();
        let mut z = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default();
        z.start_file("readme.txt", opts).unwrap();
        z.write_all(b"hello").unwrap();
        z.start_file("inner/eicar.com", opts).unwrap();
        z.write_all(EICAR).unwrap();
        z.finish().unwrap();
    }
    let (code, out, err) = cli(&sock, &["scan", zip_path.to_str().unwrap()]).await;
    assert_eq!(code, 1, "{out}\n{err}");
    assert!(!zip_path.exists(), "container quarantined");
    let q: Vec<QuarantineEntry> = cli_json(&sock, &["quarantine"]).await;
    assert_eq!(q.len(), 1);
    assert!(q[0].original_path.ends_with("bundle.zip"));
    let alerts: Vec<Alert> = cli_json(&sock, &["alerts"]).await;
    assert_eq!(alerts.len(), 1, "{alerts:?}");
    let jobs: Vec<ScanJobSummary> = cli_json(&sock, &["jobs"]).await;
    assert_eq!(jobs[0].threats, 1, "member + container count once");
    let detail: ScanJobDetail = cli_json(&sock, &["job", &jobs[0].job_id]).await;
    assert!(
        detail
            .findings
            .iter()
            .any(|f| f.path.contains("!/inner/eicar.com")),
        "{:?}",
        detail.findings
    );
    d.shutdown().await;
}
