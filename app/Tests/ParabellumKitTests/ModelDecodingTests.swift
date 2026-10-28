import Foundation
import ParabellumKit
import XCTest

/// Every payload fixture emitted by the Rust types must decode.
final class ModelDecodingTests: XCTestCase {
    func testStatus() throws {
        let status = try Fixtures.decode(StatusInfo.self, from: "status.json")
        XCTAssertEqual(status.protection, .degraded)
        XCTAssertEqual(status.issues.count, 1)
        XCTAssertFalse(status.realtime.fullDiskAccess)
        XCTAssertTrue(status.realtime.fsevents)
        XCTAssertEqual(status.db.version, "2026.10.25.1")
        XCTAssertEqual(status.db.malwareHashes, 812_345)
        XCTAssertEqual(status.db.yaraRules, 431)
        XCTAssertNil(status.db.lastError)
        XCTAssertEqual(status.openAlerts, 3)
        XCTAssertEqual(status.componentsNeedingAttention, 2)
        XCTAssertEqual(status.rssBytes, 58_000_000)
        XCTAssertEqual(status.uptimeSecs, 3600)
        XCTAssertEqual(status.lastScan, 1_793_000_060)
        XCTAssertNil(status.pausedUntil)
        XCTAssertEqual(status.lastScanDate, Date(timeIntervalSince1970: 1_793_000_060))
    }

    func testScanReport() throws {
        let report = try Fixtures.decode(ScanReport.self, from: "scan_report.json")
        XCTAssertEqual(report.kind, .macho)
        XCTAssertEqual(report.verdict, .malicious)
        XCTAssertEqual(report.size, 123_456)
        XCTAssertEqual(report.score, 0.97, accuracy: 1e-6)
        XCTAssertEqual(report.detections.count, 2)
        XCTAssertEqual(report.detections[0].engine, .yara)
        XCTAssertEqual(report.detections[0].severity, .high)
        XCTAssertEqual(report.detections[0].confidence, 0.95, accuracy: 1e-6)
        XCTAssertEqual(report.detections[1].engine, .clamav)
        XCTAssertNil(report.detections[1].details)
        XCTAssertEqual(report.signing?.adhoc, true)
        XCTAssertNil(report.signing?.teamId)
        XCTAssertEqual(report.sha256?.count, 64)
        XCTAssertEqual(report.durationMs, 42)
        XCTAssertFalse(report.cached)
        XCTAssertEqual(report.containerPath, "/Users/q/Downloads/Installer.dmg")
    }

    func testJobs() throws {
        let running = try Fixtures.decode(ScanJobSummary.self, from: "job_running.json")
        XCTAssertEqual(running.state, .running)
        XCTAssertTrue(running.state.isActive)
        XCTAssertNil(running.finishedAt)
        XCTAssertEqual(running.currentPath, "/Users/q/Downloads/x.zip")
        XCTAssertEqual(running.origin, .manual)
        XCTAssertEqual(running.bytesScanned, 987_654_321)

        let detail = try Fixtures.decode(ScanJobDetail.self, from: "job_detail.json")
        XCTAssertEqual(detail.summary.state, .finished)
        XCTAssertEqual(detail.summary.finishedAt, 1_793_000_060)
        XCTAssertNil(detail.summary.currentPath)
        XCTAssertEqual(detail.findings.count, 1)
        XCTAssertEqual(detail.findings[0], try Fixtures.decode(ScanReport.self, from: "scan_report.json"))

        let started = try Fixtures.decode(JobStarted.self, from: "job_started.json")
        XCTAssertEqual(started.jobId, "5f8e2c1a-0000-4000-8000-000000000001")
    }

    func testAlerts() throws {
        let alerts = try Fixtures.decode([SecurityAlert].self, from: "alerts.json")
        XCTAssertEqual(alerts.count, 1)
        let alert = alerts[0]
        XCTAssertEqual(alert.id, 12)
        XCTAssertEqual(alert.kind, .malware)
        XCTAssertEqual(alert.severity, .critical)
        XCTAssertEqual(alert.status, .open)
        XCTAssertEqual(alert.actions, [.restore, .reportFalsePositive, .acknowledge])
        XCTAssertEqual(alert.quarantineId, "1b4e28ba-2fa1-11d2-883f-0016d3cca427")
        XCTAssertNil(alert.deviceId)
        XCTAssertNil(alert.persistenceId)
        XCTAssertEqual(alert.title, "Menace mise en quarantaine")
    }

    func testQuarantine() throws {
        let entries = try Fixtures.decode([QuarantineEntry].self, from: "quarantine.json")
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].ownerUid, 501)
        XCTAssertEqual(entries[0].ownerGid, 20)
        XCTAssertEqual(entries[0].mode, 0o644)
        XCTAssertEqual(entries[0].reason, "auto")
        XCTAssertEqual(entries[0].fileName, "Installer.dmg")
        XCTAssertEqual(entries[0].detections.first?.name, "MacOS.Stealer.AMOS")
    }

    func testPersistence() throws {
        let items = try Fixtures.decode([PersistenceItem].self, from: "persistence.json")
        XCTAssertEqual(items.count, 1)
        let item = items[0]
        XCTAssertEqual(item.kind, .launchAgent)
        XCTAssertEqual(item.status, .new)
        XCTAssertEqual(item.verdict, .suspicious)
        XCTAssertEqual(item.arguments, ["/Users/q/.local/helper", "--daemon"])
        XCTAssertEqual(item.signing?.signed, false)
        XCTAssertEqual(item.programSha256?.count, 64)
        XCTAssertEqual(item.user, "q")
    }

    func testDevices() throws {
        let devices = try Fixtures.decode([DeviceInfo].self, from: "devices.json")
        XCTAssertEqual(devices.count, 2)
        let keyboard = devices[0]
        XCTAssertEqual(keyboard.kind, .hid)
        XCTAssertEqual(keyboard.vendorId, 0x05ac)
        XCTAssertEqual(keyboard.productId, 0x024f)
        XCTAssertEqual(keyboard.usbIdentifier, "0x05ac:0x024f")
        XCTAssertEqual(keyboard.trust, .unknown)
        XCTAssertTrue(keyboard.isProbableKeyboard)
        XCTAssertNil(keyboard.serial)
        let volume = devices[1]
        XCTAssertEqual(volume.kind, .volume)
        XCTAssertEqual(volume.trust, .trusted)
        XCTAssertEqual(volume.details["mount_point"], "/Volumes/KINGSTON")
        XCTAssertFalse(volume.connected)
        XCTAssertFalse(volume.isProbableKeyboard)
    }

    func testComponentsDnsAdblock() throws {
        let components = try Fixtures.decode([ComponentStatus].self, from: "components.json")
        XCTAssertEqual(components.first?.state, .updateAvailable)
        XCTAssertEqual(components.first?.latestVersion, "3.1.6")
        XCTAssertEqual(components.first?.actionUrl, "https://objective-see.org/products/lulu.html")
        XCTAssertEqual(components.first?.lastCheck, 1_793_000_400)

        let dns = try Fixtures.decode(DnsStatus.self, from: "dns.json")
        XCTAssertTrue(dns.enabled)
        XCTAssertEqual(dns.queriesBlocked24h, 5321)
        XCTAssertEqual(dns.managedServices, ["Wi-Fi", "USB 10/100/1000 LAN"])

        let adblock = try Fixtures.decode(AdblockStatus.self, from: "adblock.json")
        XCTAssertEqual(adblock.chromeUblock, .enabled)
        XCTAssertEqual(adblock.safariUblock, .notInstalled)
        XCTAssertEqual(adblock.dns, dns)
        XCTAssertTrue(adblock.safariStoreUrl.hasPrefix("https://apps.apple.com/"))
    }

    func testWeeklyReportAndPing() throws {
        let report = try Fixtures.decode(WeeklyReport.self, from: "weekly_report.json")
        XCTAssertEqual(report.filesScanned, 15_234)
        let expected = try JSONDecoder().decode(NamedCount.self, from: Data(#"{"name":"MacOS.Stealer.AMOS","count":2}"#.utf8))
        XCTAssertEqual(report.topDetections, [expected])
        XCTAssertEqual(report.componentUpdates, ["clamav 1.4.3 -> 1.5.0"])
        XCTAssertEqual(report.dnsBlockedQueries, 40_211)

        let ping = try Fixtures.decode(PingResponse.self, from: "ping.json")
        XCTAssertEqual(ping.protocolVersion, DaemonProtocol.protocolVersion)
        XCTAssertFalse(ping.version.isEmpty)
    }

    /// `#[serde(default)]` collections may be missing.
    func testDefaultedCollections() throws {
        let json = #"""
        {"path":"/x","size":1,"kind":"other","verdict":"clean","score":0.0,"duration_ms":0}
        """#
        let report = try JSONDecoder().decode(ScanReport.self, from: Data(json.utf8))
        XCTAssertEqual(report.detections, [])
        XCTAssertFalse(report.cached)

        let statusJSON = try Fixtures.json("status.json")
        guard case .object(var object) = statusJSON else { return XCTFail("status.json n'est pas un objet") }
        object.removeValue(forKey: "issues")
        let status = try JSONValue.object(object).decode(as: StatusInfo.self)
        XCTAssertEqual(status.issues, [])
    }

    /// A newer daemon must never crash this build.
    func testUnknownEnumValuesAreTolerated() throws {
        let json = #"""
        {"id":1,"ts":2,"kind":"quantum","severity":"apocalyptic","title":"t","message":"m",
         "status":"snoozed","actions":["acknowledge","teleport"]}
        """#
        let alert = try JSONDecoder().decode(SecurityAlert.self, from: Data(json.utf8))
        XCTAssertEqual(alert.kind, .unknown)
        XCTAssertEqual(alert.severity, .unknown)
        XCTAssertEqual(alert.status, .unknown)
        XCTAssertEqual(alert.actions, [.acknowledge, .unknown])
        XCTAssertEqual(alert.knownActions, [.acknowledge])

        XCTAssertEqual(try JSONDecoder().decode(FileKind.self, from: Data(#""elf""#.utf8)), .other)
        XCTAssertEqual(try JSONDecoder().decode(PersistenceKind.self, from: Data(#""udev_rule""#.utf8)), .other)
        XCTAssertEqual(try JSONDecoder().decode(ComponentState.self, from: Data(#""rolling_back""#.utf8)), .unknown)
        XCTAssertEqual(try JSONDecoder().decode(ErrorCode.self, from: Data(#""internal""#.utf8)), .internalError)
        XCTAssertEqual(try JSONDecoder().decode(ErrorCode.self, from: Data(#""auth_required""#.utf8)), .authRequired)
        XCTAssertEqual(try JSONDecoder().decode(DetectionEngine.self, from: Data(#""virus_total""#.utf8)), .virusTotal)
        XCTAssertEqual(try JSONDecoder().decode(FileKind.self, from: Data(#""fat_macho""#.utf8)), .fatMacho)
    }

    func testEnumRawValuesMatchRust() throws {
        // Spot checks of the snake_case strings serde produces.
        XCTAssertEqual(FileKind.macho.rawValue, "macho")
        XCTAssertEqual(FileKind.appBundle.rawValue, "app_bundle")
        XCTAssertEqual(DetectionEngine.hashDb.rawValue, "hash_db")
        XCTAssertEqual(AlertAction.removePersistence.rawValue, "remove_persistence")
        XCTAssertEqual(ExtensionState.installedDisabled.rawValue, "installed_disabled")
        XCTAssertEqual(DeviceKind.networkInterface.rawValue, "network_interface")
        XCTAssertEqual(DeviceKind.wifiNetwork.rawValue, "wifi_network")
        XCTAssertEqual(ScanOrigin.retroHunt.rawValue, "retro_hunt")
        XCTAssertEqual(ComponentState.needsUserAction.rawValue, "needs_user_action")
        XCTAssertEqual(PersistenceKind.authorizationPlugin.rawValue, "authorization_plugin")
        XCTAssertTrue(Severity.critical > Severity.high)
        XCTAssertTrue(Severity.low > Severity.info)
        XCTAssertTrue(Verdict.malicious > Verdict.suspicious)
    }

    func testFormatting() {
        XCTAssertEqual(PBFormat.duration(seconds: 45), "45 s")
        XCTAssertEqual(PBFormat.duration(seconds: 720), "12 min")
        XCTAssertEqual(PBFormat.duration(seconds: 3600), "1 h")
        XCTAssertEqual(PBFormat.duration(seconds: 3 * 3600 + 5 * 60), "3 h 05 min")
        XCTAssertEqual(PBFormat.duration(seconds: 2 * 86_400 + 4 * 3600), "2 j 4 h")
        XCTAssertEqual(PBFormat.bytes(68), "68 octets")
        XCTAssertTrue(PBFormat.bytes(987_654_321).hasSuffix(" Mo"))
        XCTAssertEqual(PBFormat.mode(0o644), "0644")
        XCTAssertEqual(PBFormat.shortHash(String(repeating: "a", count: 64)), "aaaaaaaaaa…aaaaaa")
        XCTAssertEqual(PBFormat.percent(0.95), "95 %")
    }
}
