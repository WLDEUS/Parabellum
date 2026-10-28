//! Writes one JSON fixture per IPC payload type, so the Swift side (`app/Tests`) can check it decodes
//! exactly what the Rust daemon emits.
//!
//! `cargo run -p pb-core --example gen_fixtures -- app/Tests/ParabellumKitTests/Fixtures`

use pb_core::config::Config;
use pb_core::ipc::*;
use pb_core::model::*;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn detection() -> Detection {
    Detection {
        engine: DetectionEngine::Yara,
        name: "MacOS.Stealer.AMOS".into(),
        severity: Severity::High,
        confidence: 0.95,
        details: Some("rule macos_amos_osascript_prompt".into()),
    }
}

fn report() -> ScanReport {
    ScanReport {
        path: "/Users/q/Downloads/Installer.dmg!/Installer.app/Contents/MacOS/Installer".into(),
        sha256: Some("a".repeat(64)),
        size: 123_456,
        kind: FileKind::MachO,
        verdict: Verdict::Malicious,
        score: 0.97,
        detections: vec![
            detection(),
            Detection {
                engine: DetectionEngine::ClamAv,
                name: "Osx.Trojan.Amos-1".into(),
                severity: Severity::Critical,
                confidence: 1.0,
                details: None,
            },
        ],
        signing: Some(SigningInfo {
            signed: true,
            valid: true,
            adhoc: true,
            ..Default::default()
        }),
        error: None,
        duration_ms: 42,
        cached: false,
    }
}

fn job(state: JobState) -> ScanJobSummary {
    ScanJobSummary {
        job_id: "5f8e2c1a-0000-4000-8000-000000000001".into(),
        origin: ScanOrigin::Manual,
        paths: vec!["/Users/q/Downloads".into()],
        state,
        started_at: 1_793_000_000,
        finished_at: if state == JobState::Running {
            None
        } else {
            Some(1_793_000_060)
        },
        files_scanned: 1534,
        bytes_scanned: 987_654_321,
        threats: 1,
        errors: 2,
        current_path: if state == JobState::Running {
            Some("/Users/q/Downloads/x.zip".into())
        } else {
            None
        },
    }
}

fn alert() -> Alert {
    Alert {
        id: 12,
        ts: 1_793_000_100,
        kind: AlertKind::Malware,
        severity: Severity::Critical,
        title: "Menace mise en quarantaine".into(),
        message: "MacOS.Stealer.AMOS détecté dans Installer.dmg".into(),
        path: Some("/Users/q/Downloads/Installer.dmg".into()),
        sha256: Some("a".repeat(64)),
        device_id: None,
        persistence_id: None,
        quarantine_id: Some("1b4e28ba-2fa1-11d2-883f-0016d3cca427".into()),
        status: AlertStatus::Open,
        actions: vec![
            AlertAction::Restore,
            AlertAction::ReportFalsePositive,
            AlertAction::Acknowledge,
        ],
    }
}

fn device(kind: DeviceKind) -> DeviceInfo {
    let mut details = BTreeMap::new();
    details.insert("location_id".into(), "0x01100000".into());
    DeviceInfo {
        id: "hid:05ac:024f:0x01100000".into(),
        kind,
        name: "USB Keyboard".into(),
        vendor: Some("Unknown Vendor".into()),
        vendor_id: Some(0x05ac),
        product_id: Some(0x024f),
        serial: None,
        transport: Some("USB".into()),
        details,
        first_seen: 1_793_000_200,
        last_seen: 1_793_000_200,
        connected: true,
        trust: DeviceTrust::Unknown,
        baseline: false,
    }
}

fn persistence() -> PersistenceItem {
    PersistenceItem {
        id: "0123456789abcdef".into(),
        kind: PersistenceKind::LaunchAgent,
        label: Some("com.apple.updater.helper".into()),
        path: "/Users/q/Library/LaunchAgents/com.apple.updater.helper.plist".into(),
        program: Some("/Users/q/.local/helper".into()),
        arguments: vec!["/Users/q/.local/helper".into(), "--daemon".into()],
        user: Some("q".into()),
        signing: Some(SigningInfo::default()),
        program_sha256: Some("b".repeat(64)),
        first_seen: 1_793_000_300,
        last_seen: 1_793_000_300,
        status: PersistenceStatus::New,
        verdict: Some(Verdict::Suspicious),
    }
}

fn component() -> ComponentStatus {
    ComponentStatus {
        name: "lulu".into(),
        display_name: "LuLu (pare-feu sortant)".into(),
        installed_version: Some("3.1.5".into()),
        latest_version: Some("3.1.6".into()),
        state: ComponentState::UpdateAvailable,
        last_check: Some(1_793_000_400),
        auto_update: true,
        required: false,
        message: None,
        action_url: Some("https://objective-see.org/products/lulu.html".into()),
    }
}

fn db_status() -> DbStatus {
    DbStatus {
        version: Some("2026.10.25.1".into()),
        built_at: Some(1_793_000_000),
        previous_version: Some("2026.10.24.1".into()),
        last_check: Some(1_793_000_500),
        last_success: Some(1_793_000_500),
        last_error: None,
        malware_hashes: 812_345,
        yara_rules: 431,
        blocked_domains: 402_113,
        clamav_version: Some("ClamAV 1.4.3/27800".into()),
        ml_model_version: Some("2026.10.20".into()),
    }
}

fn dns() -> DnsStatus {
    DnsStatus {
        enabled: true,
        running: true,
        listen: "127.0.0.1:53".into(),
        blocked_domains: 402_113,
        list_version: Some("2026.10.25.1".into()),
        queries_blocked_24h: Some(5321),
        managed_services: vec!["Wi-Fi".into(), "USB 10/100/1000 LAN".into()],
        message: None,
    }
}

fn status() -> StatusInfo {
    StatusInfo {
        version: pb_core::VERSION.into(),
        protection: ProtectionState::Degraded,
        paused_until: None,
        issues: vec!["Accès complet au disque non accordé à parabellumd".into()],
        realtime: RealtimeStatus {
            fsevents: true,
            eslogger: false,
            full_disk_access: false,
            persistence_monitor: true,
            device_monitor: true,
        },
        db: db_status(),
        open_alerts: 3,
        quarantined: 1,
        last_scan: Some(1_793_000_060),
        dns_enabled: true,
        on_battery: false,
        components_needing_attention: 2,
        ml_enabled: true,
        uptime_secs: 3600,
        rss_bytes: 58_000_000,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "fixtures".into()));
    std::fs::create_dir_all(&dir)?;
    let w = |name: &str, v: serde_json::Value| -> Result<(), Box<dyn std::error::Error>> {
        std::fs::write(
            dir.join(format!("{name}.json")),
            serde_json::to_string_pretty(&v)? + "\n",
        )?;
        Ok(())
    };

    // Payloads
    w("status", serde_json::to_value(status())?)?;
    w("scan_report", serde_json::to_value(report())?)?;
    w("job_running", serde_json::to_value(job(JobState::Running))?)?;
    w(
        "job_detail",
        serde_json::to_value(ScanJobDetail {
            summary: job(JobState::Finished),
            findings: vec![report()],
        })?,
    )?;
    w("alerts", serde_json::to_value(vec![alert()])?)?;
    w(
        "posture",
        serde_json::to_value(vec![
            PostureCheck {
                id: "sip".into(),
                title: "Protection de l'intégrité du système (SIP)".into(),
                ok: true,
                severity: Severity::High,
                detail: "SIP activée".into(),
                fix: String::new(),
            },
            PostureCheck {
                id: "firewall".into(),
                title: "Coupe-feu de l'application".into(),
                ok: false,
                severity: Severity::Medium,
                detail: "Coupe-feu désactivé".into(),
                fix: "Réglages Système > Réseau > Coupe-feu : activer".into(),
            },
        ])?,
    )?;
    w(
        "quarantine",
        serde_json::to_value(vec![QuarantineEntry {
            id: "1b4e28ba-2fa1-11d2-883f-0016d3cca427".into(),
            original_path: "/Users/q/Downloads/Installer.dmg".into(),
            sha256: "a".repeat(64),
            size: 123_456,
            detections: vec![detection()],
            quarantined_at: 1_793_000_100,
            owner_uid: 501,
            owner_gid: 20,
            mode: 0o644,
            reason: "auto".into(),
        }])?,
    )?;
    w("persistence", serde_json::to_value(vec![persistence()])?)?;
    w(
        "devices",
        serde_json::to_value(vec![device(DeviceKind::Hid), {
            let mut d = device(DeviceKind::Volume);
            d.id = "vol:7C3B2A10-1111-2222-3333-444455556666".into();
            d.name = "KINGSTON".into();
            d.trust = DeviceTrust::Trusted;
            d.connected = false;
            d.details
                .insert("mount_point".into(), "/Volumes/KINGSTON".into());
            d
        }])?,
    )?;
    w("components", serde_json::to_value(vec![component()])?)?;
    w("dns", serde_json::to_value(dns())?)?;
    w(
        "adblock",
        serde_json::to_value(AdblockStatus {
            chrome_ublock: ExtensionState::Enabled,
            safari_ublock: ExtensionState::NotInstalled,
            dns: dns(),
            chrome_store_url:
                "https://chromewebstore.google.com/detail/ddkjiahejlhfcafbddmgiahcphecmpfh".into(),
            safari_store_url: "https://apps.apple.com/app/ublock-origin-lite/id6745342698".into(),
        })?,
    )?;
    w("config", serde_json::to_value(Config::default())?)?;
    w(
        "weekly_report",
        serde_json::to_value(WeeklyReport {
            week_start: 1_792_540_800,
            week_end: 1_793_145_600,
            files_scanned: 15_234,
            threats_detected: 2,
            quarantined: 1,
            false_positives_reported: 0,
            persistence_new: 1,
            devices_new: 3,
            db_updates: 7,
            db_version: Some("2026.10.25.1".into()),
            component_updates: vec!["clamav 1.4.3 -> 1.5.0".into()],
            top_detections: vec![NamedCount {
                name: "MacOS.Stealer.AMOS".into(),
                count: 2,
            }],
            dns_blocked_queries: Some(40_211),
        })?,
    )?;
    w(
        "ping",
        serde_json::to_value(PingResponse {
            version: pb_core::VERSION.into(),
            protocol: PROTOCOL_VERSION,
        })?,
    )?;
    w(
        "job_started",
        serde_json::to_value(JobStarted {
            job_id: "5f8e2c1a-0000-4000-8000-000000000001".into(),
        })?,
    )?;

    // Whole server lines (response + every event kind) as JSON-lines.
    let mut lines = Vec::new();
    lines.push(serde_json::to_string(&ResponseEnvelope::ok(1, &status()))?);
    lines.push(serde_json::to_string(&ResponseEnvelope::ok_empty(2))?);
    lines.push(serde_json::to_string(&ResponseEnvelope::err(
        3,
        IpcError::new(ErrorCode::NotFound, "alerte introuvable"),
    ))?);
    let events = vec![
        DaemonEvent::Alert(alert()),
        DaemonEvent::ScanProgress(job(JobState::Running)),
        DaemonEvent::ScanFinished(job(JobState::Finished)),
        DaemonEvent::StatusChanged(status()),
        DaemonEvent::Device(DeviceEvent {
            device: device(DeviceKind::Hid),
            change: DeviceChange::New,
        }),
        DaemonEvent::UpdateFinished(UpdateResult {
            target: UpdateTarget::All,
            ok: true,
            started_at: 1_793_000_000,
            finished_at: 1_793_000_090,
            messages: vec!["Base 2026.10.25.1 installée".into(), "ClamAV à jour".into()],
            new_db_version: Some("2026.10.25.1".into()),
        }),
        DaemonEvent::Component(component()),
        DaemonEvent::Quarantined(QuarantineEntry {
            id: "1b4e28ba-2fa1-11d2-883f-0016d3cca427".into(),
            original_path: "/Users/q/Downloads/eicar.com".into(),
            sha256: "c".repeat(64),
            size: 68,
            detections: vec![detection()],
            quarantined_at: 1_793_000_100,
            owner_uid: 501,
            owner_gid: 20,
            mode: 0o644,
            reason: "auto".into(),
        }),
    ];
    for e in &events {
        lines.push(serde_json::to_string(e)?);
    }
    std::fs::write(dir.join("server_lines.jsonl"), lines.join("\n") + "\n")?;

    // Every request kind, as the Swift client must encode them (one per line).
    let reqs = vec![
        Request::Ping,
        Request::Status,
        Request::Scan {
            paths: vec!["/Users/q/Downloads".into()],
            recursive: true,
            use_clamav: Some(true),
        },
        Request::CancelScan { job_id: "j".into() },
        Request::ListJobs { limit: 20 },
        Request::GetJob { job_id: "j".into() },
        Request::ListAlerts {
            limit: 50,
            include_resolved: false,
        },
        Request::ResolveAlert {
            alert_id: 12,
            action: AlertAction::Quarantine,
        },
        Request::ListQuarantine,
        Request::QuarantinePath {
            path: "/tmp/x".into(),
        },
        Request::Restore {
            entry_id: "e".into(),
            allow: true,
        },
        Request::DeleteQuarantined {
            entry_id: "e".into(),
        },
        Request::ReportFalsePositive {
            sha256: "a".repeat(64),
            path: Some("/tmp/x".into()),
            note: None,
        },
        Request::ListPersistence { only_new: true },
        Request::SetPersistenceStatus {
            item_id: "0123456789abcdef".into(),
            status: PersistenceStatus::Approved,
        },
        Request::ListDevices {
            kind: Some(DeviceKind::Hid),
        },
        Request::SetDeviceTrust {
            device_id: "hid:05ac:024f:0x01100000".into(),
            trust: DeviceTrust::Blocked,
        },
        Request::UpdateNow {
            target: UpdateTarget::All,
        },
        Request::ListComponents,
        Request::InstallComponent {
            name: "lulu".into(),
        },
        Request::SetComponentAutoUpdate {
            name: "lulu".into(),
            auto_update: false,
        },
        Request::GetDns,
        Request::SetDns { enabled: true },
        Request::AdblockStatus,
        Request::GetConfig,
        Request::SetConfig {
            config: Config::default(),
        },
        Request::SetProtection { paused_minutes: 30 },
        Request::WeeklyReport { week_offset: 1 },
        Request::RetroHunt { days: 30 },
        Request::SpywareScan,
        Request::Posture { refresh: true },
        Request::Subscribe,
    ];
    // Which commands need administrator approval (`auth` or root), same order/ids as requests.jsonl.
    let admin: Vec<String> = reqs
        .iter()
        .enumerate()
        .map(|(i, r)| {
            format!(
                "{{\"id\":{},\"requires_admin\":{}}}",
                i + 1,
                r.requires_admin()
            )
        })
        .collect();
    std::fs::write(dir.join("requires_admin.jsonl"), admin.join("\n") + "\n")?;
    let lines: Vec<String> = reqs
        .into_iter()
        .enumerate()
        .map(|(i, request)| {
            serde_json::to_string(&RequestEnvelope {
                id: i as u64 + 1,
                auth: None,
                request,
            })
        })
        .collect::<Result<_, _>>()?;
    std::fs::write(dir.join("requests.jsonl"), lines.join("\n") + "\n")?;
    println!("fixtures written to {}", dir.display());
    Ok(())
}
