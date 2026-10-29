//! Writes one JSON fixture per IPC payload type, so the Swift side (`app/Tests`) can check it decodes
//! exactly what the Rust daemon emits.
//!
//! `cargo run -p pb-core --example gen_fixtures -- app/Tests/ParabellumKitTests/Fixtures`

use pb_core::config::{AliasProvider, Config, VpnBackend, VpnMode};
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
        process_pid: None,
        process_path: None,
        network_id: None,
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

fn network(current: bool) -> NetworkInfo {
    NetworkInfo {
        id: "gw:00:24:d4:a1:b2:c3".into(),
        name: "Livebox-1234".into(),
        interface: "en0".into(),
        gateway_ip: Some("192.168.1.254".into()),
        gateway_mac: Some("00:24:d4:a1:b2:c3".into()),
        ssid: Some("Livebox-1234".into()),
        security: Some("WPA2 Personal".into()),
        trusted: true,
        first_seen: 1_792_900_000,
        last_seen: 1_793_000_000,
        current,
    }
}

fn vpn_status() -> VpnStatus {
    VpnStatus {
        mode: VpnMode::UntrustedNetworks,
        backend: VpnBackend::SingBox,
        state: VpnState::Connected,
        wanted: true,
        manual_override: Some(true),
        profile: Some(VpnProfileInfo {
            name: "Paris".into(),
            protocol: "vless".into(),
            server: "203.0.113.9".into(),
            port: 443,
            transport: Some("reality".into()),
            imported_at: 1_792_950_000,
        }),
        external_service: None,
        connected_since: Some(1_793_000_000),
        interface: Some("utun5".into()),
        kill_switch: KillSwitchState::Armed,
        network: Some(network(true)),
        last_leak_test: Some(LeakTestResult {
            ts: 1_793_000_200,
            ok: false,
            vpn_connected: true,
            public_ipv4: Some("203.0.113.9".into()),
            public_ipv6: None,
            home_ipv4: Some("198.51.100.20".into()),
            dns_servers: vec!["127.0.0.1".into()],
            checks: vec![
                LeakCheck {
                    id: "ipv4".into(),
                    ok: true,
                    detail: "IP publique du serveur VPN".into(),
                },
                LeakCheck {
                    id: "ipv6".into(),
                    ok: false,
                    detail: "IPv6 joignable hors du tunnel".into(),
                },
            ],
        }),
        engine_installed: true,
        message: None,
    }
}

fn removal_request(status: RemovalStatus) -> RemovalRequest {
    RemovalRequest {
        id: "2f1c8a4e-0000-4000-8000-000000000002".into(),
        broker_id: "acxiom".into(),
        broker_name: "Acxiom".into(),
        broker_email: Some("privacy@acxiom.example".into()),
        status,
        created_at: 1_792_000_000,
        sent_at: Some(1_792_100_000),
        due_at: Some(1_794_692_000),
        reminded_at: None,
        closed_at: None,
        opt_out_url: None,
        draft_path: None,
        note: None,
        last_error: None,
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

    // VPN, behaviour guard, privacy payloads.
    w("vpn_status", serde_json::to_value(vpn_status())?)?;
    w(
        "vpn_status_default",
        serde_json::to_value(VpnStatus::default())?,
    )?;
    w(
        "networks",
        serde_json::to_value(vec![network(true), {
            let mut n = network(false);
            n.id = "gw:12:34:56:78:9a:bc".into();
            n.name = "Gare-WiFi".into();
            n.ssid = Some("Gare-WiFi".into());
            n.security = None;
            n.gateway_ip = None;
            n.trusted = false;
            n
        }])?,
    )?;
    w(
        "vpn_services",
        serde_json::to_value(vec![ExternalVpnService {
            name: "Shadowrocket".into(),
            provider: Some("com.liguangming.Shadowrocket".into()),
            state: VpnState::Disconnected,
        }])?,
    )?;
    w(
        "guard_status",
        serde_json::to_value(GuardStatus {
            stealer_detection: true,
            ransomware_detection: true,
            canaries: vec!["/Users/q/Documents/.~0000-budget.xlsx".into()],
            snapshots_enabled: true,
            last_snapshot: Some(1_793_000_000),
            snapshot_error: None,
            suspended: vec![SuspendedProcess {
                pid: 4242,
                path: "/private/tmp/locker".into(),
                since: 1_793_000_300,
                alert_id: Some(31),
            }],
            detections_7d: 2,
        })?,
    )?;
    w(
        "snapshots",
        serde_json::to_value(vec![
            SnapshotInfo {
                name: "com.apple.TimeMachine.2026-10-29-120000.local".into(),
                created_at: Some(1_793_012_400),
                ours: true,
            },
            SnapshotInfo {
                name: "com.apple.os.update-ABCDEF".into(),
                created_at: None,
                ours: false,
            },
        ])?,
    )?;
    w(
        "identity",
        serde_json::to_value(IdentityProfile {
            full_name: "C****** M*****".into(),
            emails: vec!["c***@example.com".into()],
            phones: vec![],
            postal_address: String::new(),
            previous_addresses: vec![],
            birth_date: String::new(),
            country: "FR".into(),
        })?,
    )?;
    w(
        "brokers",
        serde_json::to_value(vec![BrokerInfo {
            id: "acxiom".into(),
            name: "Acxiom".into(),
            email: Some("privacy@acxiom.example".into()),
            website: Some("https://www.acxiom.com".into()),
            opt_out_url: None,
            region: "global".into(),
            category: "marketing".into(),
            source: "eraser".into(),
        }])?,
    )?;
    w(
        "removal_requests",
        serde_json::to_value(vec![removal_request(RemovalStatus::Sent), {
            let mut r = removal_request(RemovalStatus::NeedsForm);
            r.id = "2f1c8a4e-0000-4000-8000-000000000003".into();
            r.broker_email = None;
            r.sent_at = None;
            r.due_at = None;
            r.opt_out_url = Some("https://example.com/opt-out".into());
            r
        }])?,
    )?;
    w(
        "removal_summary",
        serde_json::to_value(RemovalSummary {
            total: 120,
            queued: 80,
            waiting_answer: 30,
            overdue: 2,
            completed: 6,
            needs_action: 4,
            next_send_at: Some(1_793_050_000),
        })?,
    )?;
    w(
        "mail_draft",
        serde_json::to_value(MailDraft {
            request_id: "2f1c8a4e-0000-4000-8000-000000000002".into(),
            to: "privacy@acxiom.example".into(),
            subject: "Demande d'effacement (article 17 du RGPD)".into(),
            body: "Madame, Monsieur,\n\nJe vous demande d'effacer mes données.\n".into(),
        })?,
    )?;
    w(
        "complaint",
        serde_json::to_value(ComplaintDraft {
            authority: "CNIL".into(),
            url: "https://www.cnil.fr/fr/plaintes".into(),
            text: "Plainte".into(),
        })?,
    )?;
    w(
        "breaches",
        serde_json::to_value(vec![BreachFinding {
            email: "c.m@example.com".into(),
            breach: "ExampleShop".into(),
            breach_date: Some("2024-05-01".into()),
            data_classes: vec!["Email addresses".into(), "Passwords".into()],
            first_seen: 1_793_000_000,
            new: true,
        }])?,
    )?;
    w(
        "aliases",
        serde_json::to_value(vec![EmailAlias {
            id: "42".into(),
            email: "shop.x7k2@addy.example".into(),
            label: "boutique".into(),
            provider: AliasProvider::Addy,
            created_at: 1_793_000_000,
            active: true,
        }])?,
    )?;
    w(
        "behavior_alert",
        serde_json::to_value({
            let mut a = alert();
            a.id = 31;
            a.kind = AlertKind::Behavior;
            a.title = "Rançongiciel suspendu".into();
            a.path = None;
            a.sha256 = None;
            a.quarantine_id = None;
            a.process_pid = Some(4242);
            a.process_path = Some("/private/tmp/locker".into());
            a.network_id = Some("gw:00:24:d4:a1:b2:c3".into());
            a.actions = vec![
                AlertAction::KillProcess,
                AlertAction::ResumeProcess,
                AlertAction::TrustNetwork,
            ];
            a
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
        DaemonEvent::Vpn(vpn_status()),
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
        Request::VpnStatus,
        Request::VpnConnect,
        Request::VpnDisconnect,
        Request::VpnImportProfile {
            profile: "trojan://pw@203.0.113.9:443#Paris".into(),
        },
        Request::VpnRemoveProfile,
        Request::VpnLeakTest,
        Request::VpnListServices,
        Request::ListNetworks,
        Request::SetNetworkTrust {
            network_id: "gw:00:24:d4:a1:b2:c3".into(),
            trusted: true,
        },
        Request::SetNetworkTrust {
            network_id: "gw:00:24:d4:a1:b2:c3".into(),
            trusted: false,
        },
        Request::GuardStatus,
        Request::ListSnapshots,
        Request::CreateSnapshot,
        Request::RestoreFromSnapshot {
            snapshot: "com.apple.TimeMachine.2026-10-29-120000.local".into(),
            path: "/Users/q/Documents/budget.xlsx".into(),
        },
        Request::PrivacyGetProfile { reveal: false },
        Request::PrivacyGetProfile { reveal: true },
        Request::PrivacySetProfile {
            profile: IdentityProfile {
                full_name: "Camille Martin".into(),
                emails: vec!["c.m@example.com".into()],
                country: "FR".into(),
                ..Default::default()
            },
        },
        Request::PrivacyListBrokers,
        Request::PrivacyListRequests,
        Request::PrivacySummary,
        Request::PrivacyStartRemoval { broker_ids: None },
        Request::PrivacyStartRemoval {
            broker_ids: Some(vec!["acxiom".into()]),
        },
        Request::PrivacyUpdateRequest {
            request_id: "r".into(),
            status: RemovalStatus::Completed,
            note: Some("confirmé".into()),
        },
        Request::PrivacyDraft {
            request_id: "r".into(),
        },
        Request::PrivacyComplaint {
            request_id: "r".into(),
        },
        Request::BreachList,
        Request::BreachCheckNow,
        Request::AliasList,
        Request::AliasCreate {
            label: "boutique".into(),
        },
        Request::ResolveAlert {
            alert_id: 31,
            action: AlertAction::KillProcess,
        },
        Request::ResolveAlert {
            alert_id: 31,
            action: AlertAction::ResumeProcess,
        },
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
