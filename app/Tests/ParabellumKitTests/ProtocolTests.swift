import Foundation
import ParabellumKit
import XCTest

/// Wire format: requests, responses, events, config round-trip.
final class ProtocolTests: XCTestCase {
    /// Same requests, same order, same ids as `gen_fixtures.rs`.
    private var fixtureRequests: [Request] {
        [
            .ping,
            .status,
            .scan(paths: ["/Users/q/Downloads"], recursive: true, useClamav: true),
            .cancelScan(jobId: "j"),
            .listJobs(limit: 20),
            .getJob(jobId: "j"),
            .listAlerts(limit: 50, includeResolved: false),
            .resolveAlert(alertId: 12, action: .quarantine),
            .listQuarantine,
            .quarantinePath(path: "/tmp/x"),
            .restore(entryId: "e", allow: true),
            .deleteQuarantined(entryId: "e"),
            .reportFalsePositive(sha256: String(repeating: "a", count: 64), path: "/tmp/x", note: nil),
            .listPersistence(onlyNew: true),
            .setPersistenceStatus(itemId: "0123456789abcdef", status: .approved),
            .listDevices(kind: .hid),
            .setDeviceTrust(deviceId: "hid:05ac:024f:0x01100000", trust: .blocked),
            .updateNow(target: .all),
            .listComponents,
            .installComponent(name: "lulu"),
            .setComponentAutoUpdate(name: "lulu", autoUpdate: false),
            .getDns,
            .setDns(enabled: true),
            .adblockStatus,
            .getConfig,
            .setConfig(Config()),
            .setProtection(pausedMinutes: 30),
            .weeklyReport(weekOffset: 1),
            .retroHunt(days: 30),
            .spywareScan,
            .posture(refresh: true),
            .subscribe,
        ]
    }

    func testRequestsMatchRustEncoding() throws {
        let expectedLines = try Fixtures.lines("requests.jsonl")
        let requests = fixtureRequests
        XCTAssertEqual(expectedLines.count, requests.count, "requests.jsonl ne contient pas le même nombre de commandes")
        for (index, request) in requests.enumerated() where index < expectedLines.count {
            let id = UInt64(index + 1)
            let expected = try JSONValue(data: expectedLines[index])
            let actual = try JSONValue(data: request.encode(id: id))
            XCTAssertTrue(
                actual.isApproximatelyEqual(to: expected),
                "commande \(request.command) :\n attendu \(expected)\n obtenu  \(actual)"
            )
            XCTAssertEqual(expected["cmd"]?.stringValue, request.command)
        }
    }

    func testRequestLineIsSingleLine() throws {
        let line = try Request.setConfig(Config()).encodeLine(id: 9)
        XCTAssertEqual(line.last, 0x0A)
        XCTAssertEqual(line.filter { $0 == 0x0A }.count, 1, "une requête = une seule ligne")
    }

    func testOptionalFieldsOmitted() throws {
        let scan = try JSONValue(data: Request.scan(paths: ["/a"]).encode(id: 1))
        XCTAssertNil(scan["use_clamav"])
        XCTAssertEqual(scan["recursive"], .bool(true))
        let devices = try JSONValue(data: Request.listDevices().encode(id: 2))
        XCTAssertNil(devices["kind"])
        let fp = try JSONValue(data: Request.reportFalsePositive(sha256: "x").encode(id: 3))
        XCTAssertNil(fp["path"])
        XCTAssertNil(fp["note"])
    }

    /// `requires_admin.jsonl` = `Request::requires_admin()` for each line of `requests.jsonl`.
    func testRequiresAdminMatchesRust() throws {
        let lines = try Fixtures.lines("requires_admin.jsonl")
        let requests = fixtureRequests
        XCTAssertEqual(lines.count, requests.count)
        for line in lines {
            let entry = try JSONValue(data: line)
            let id = try XCTUnwrap(entry["id"]?.intValue)
            guard case .bool(let expected)? = entry["requires_admin"] else {
                XCTFail("requires_admin manquant pour id \(id)")
                continue
            }
            let index = Int(id) - 1
            guard requests.indices.contains(index) else {
                XCTFail("id \(id) hors de requests.jsonl")
                continue
            }
            XCTAssertEqual(requests[index].requiresAdmin, expected, "requires_admin pour \(requests[index].command) (id \(id))")
        }
    }

    /// Same edge cases as the Rust unit test.
    func testRequiresAdminEdgeCases() {
        XCTAssertTrue(Request.setDns(enabled: false).requiresAdmin)
        XCTAssertFalse(Request.setDns(enabled: true).requiresAdmin)
        XCTAssertFalse(Request.setProtection(pausedMinutes: 0).requiresAdmin)
        XCTAssertTrue(Request.setProtection(pausedMinutes: 10).requiresAdmin)
        XCTAssertFalse(Request.setDeviceTrust(deviceId: "d", trust: .blocked).requiresAdmin)
        XCTAssertTrue(Request.setDeviceTrust(deviceId: "d", trust: .trusted).requiresAdmin)
        XCTAssertTrue(Request.setDeviceTrust(deviceId: "d", trust: .unknown).requiresAdmin)
        XCTAssertFalse(Request.setComponentAutoUpdate(name: "lulu", autoUpdate: true).requiresAdmin)
        XCTAssertTrue(Request.setComponentAutoUpdate(name: "lulu", autoUpdate: false).requiresAdmin)
        for action in [AlertAction.allow, .restore, .trustDevice, .approvePersistence, .removePersistence, .reportFalsePositive] {
            XCTAssertTrue(Request.resolveAlert(alertId: 1, action: action).requiresAdmin, action.rawValue)
        }
        for action in [AlertAction.acknowledge, .quarantine, .blockDevice, .dismiss] {
            XCTAssertFalse(Request.resolveAlert(alertId: 1, action: action).requiresAdmin, action.rawValue)
        }
        XCTAssertTrue(Request.restore(entryId: "e").requiresAdmin)
        XCTAssertTrue(Request.setConfig(Config()).requiresAdmin)
        XCTAssertFalse(Request.getConfig.requiresAdmin)
        XCTAssertFalse(Request.scan(paths: ["/a"]).requiresAdmin)
    }

    /// `auth` travels next to `id` / `cmd` and is omitted when absent (Rust: `{"id":1,"auth":"QUJD","cmd":"get_config"}`).
    func testAuthIsEncodedNextToId() throws {
        let withAuth = try JSONValue(data: Request.getConfig.encode(id: 1, auth: "QUJD"))
        let expected = try JSONValue(data: Data(#"{"id":1,"auth":"QUJD","cmd":"get_config"}"#.utf8))
        XCTAssertEqual(withAuth, expected)
        let withoutAuth = try JSONValue(data: Request.getConfig.encode(id: 1))
        XCTAssertNil(withoutAuth["auth"])
        XCTAssertEqual(DaemonProtocol.adminRight, "com.wldeus.parabellum.admin")
    }

    func testMutatingClassificationMatchesRust() {
        XCTAssertFalse(Request.status.isMutating)
        XCTAssertFalse(Request.subscribe.isMutating)
        XCTAssertFalse(Request.listAlerts().isMutating)
        XCTAssertTrue(Request.setDns(enabled: true).isMutating)
        XCTAssertTrue(Request.restore(entryId: "x").isMutating)
        XCTAssertTrue(Request.scan(paths: []).isMutating)
    }

    // MARK: Config

    func testConfigFixtureDecodesToRustDefaults() throws {
        var config = try Fixtures.decode(Config.self, from: "config.json")
        XCTAssertTrue(config.realtime.killMaliciousProcesses)
        XCTAssertEqual(config.ml.suspiciousThreshold, 0.85, accuracy: 1e-6)
        XCTAssertNil(config.updates.githubToken)
        XCTAssertNil(config.privacy.virustotalApiKey)
        XCTAssertEqual(config.notifications.minSeverity, .medium)
        // Rust f32 0.85 is printed as 0.8500000238418579 by serde_json::to_value.
        config.ml.suspiciousThreshold = 0.85
        XCTAssertEqual(config, Config(), "les valeurs par défaut Swift doivent être celles de Rust")
    }

    func testConfigRoundTripKeepsEveryField() throws {
        let fixture = try Fixtures.json("config.json")
        let config = try fixture.decode(as: Config.self)
        let reencoded = try JSONValue(encoding: config)
        XCTAssertTrue(reencoded.isApproximatelyEqual(to: fixture), "attendu \(fixture)\nobtenu \(reencoded)")
        // Option<String> without skip_serializing_if: explicit null, like Rust.
        XCTAssertEqual(reencoded["updates"]?["github_token"], .null)
        XCTAssertEqual(reencoded["privacy"]?["virustotal_api_key"], .null)
    }

    func testPartialConfigUsesDefaults() throws {
        let partial = try JSONDecoder().decode(Config.self, from: Data(#"{"dns":{"enabled":true}}"#.utf8))
        XCTAssertTrue(partial.dns.enabled)
        XCTAssertEqual(partial.dns.listen, "127.0.0.1:53")
        XCTAssertEqual(partial.scan, ScanConfig())
        XCTAssertEqual(partial.realtime, RealtimeConfig())

        let empty = try JSONDecoder().decode(Config.self, from: Data("{}".utf8))
        XCTAssertEqual(empty, Config())
        XCTAssertTrue(empty.security.spywareScanWeekly)
        XCTAssertEqual(empty.security.spywareScanWeekday, 3)
    }

    func testSetConfigPreservesUnknownKeys() throws {
        guard case .object(var root) = try Fixtures.json("config.json") else {
            return XCTFail("config.json n'est pas un objet")
        }
        root["future_section"] = .object(["x": .int(1)])
        if case .object(var scan) = root["scan"] ?? .null {
            scan["future_field"] = .bool(true)
            root["scan"] = .object(scan)
        }
        let raw = JSONValue.object(root)
        var config = try raw.decode(as: Config.self)
        config.dns.enabled = true
        config.updates.githubToken = "ghp_test"

        let encoded = try JSONValue(data: Request.setConfig(config, preserving: raw).encode(id: 4))
        let sent = try XCTUnwrap(encoded["config"])
        XCTAssertEqual(sent["future_section"]?["x"], .int(1))
        XCTAssertEqual(sent["scan"]?["future_field"], .bool(true))
        XCTAssertEqual(sent["dns"]?["enabled"], .bool(true))
        XCTAssertEqual(sent["updates"]?["github_token"], .string("ghp_test"))
        XCTAssertEqual(sent["realtime"]?["kill_malicious_processes"], .bool(true))
    }

    func testConfigValidationMirrorsRust() {
        var config = Config()
        XCTAssertEqual(config.validationErrors(), [])
        config.scan.maxFileSizeMb = 0
        config.scan.archiveMaxDepth = 11
        config.ml.suspiciousThreshold = 3
        config.updates.dailyHour = 24
        config.energy.pauseOnBatteryBelow = 101
        XCTAssertEqual(config.validationErrors().count, 5)
    }

    // MARK: Server lines

    func testServerLines() throws {
        let lines = try Fixtures.lines("server_lines.jsonl")
        XCTAssertEqual(lines.count, 11)
        let messages = try lines.map { try ServerMessage.parse($0) }
        guard messages.count == 11 else { return }

        // 1: response with StatusInfo
        guard case .response(let first) = messages[0] else { return XCTFail("ligne 1 : réponse attendue") }
        XCTAssertEqual(first.id, 1)
        XCTAssertTrue(first.ok)
        let status = try first.decodeData(as: StatusInfo.self)
        XCTAssertEqual(status, try Fixtures.decode(StatusInfo.self, from: "status.json"))

        // 2: ok without data
        guard case .response(let second) = messages[1] else { return XCTFail("ligne 2 : réponse attendue") }
        XCTAssertTrue(second.ok)
        XCTAssertNil(second.data)
        XCTAssertEqual(try second.decodeData(as: JSONValue.self), .null)

        // 3: error
        guard case .response(let third) = messages[2] else { return XCTFail("ligne 3 : réponse attendue") }
        XCTAssertFalse(third.ok)
        XCTAssertEqual(third.error?.code, .notFound)
        XCTAssertEqual(third.error?.message, "alerte introuvable")
        XCTAssertThrowsError(try third.decodeData(as: StatusInfo.self)) { error in
            XCTAssertEqual(error as? DaemonClientError, .daemon(IpcError(code: .notFound, message: "alerte introuvable")))
        }

        // 4…11: one event of each kind
        let expectedNames = [
            "alert", "scan_progress", "scan_finished", "status_changed",
            "device", "update_finished", "component", "quarantined",
        ]
        for (offset, name) in expectedNames.enumerated() {
            guard case .event(let event) = messages[3 + offset] else {
                XCTFail("ligne \(4 + offset) : événement attendu")
                continue
            }
            XCTAssertEqual(event.name, name)
        }

        if case .event(.alert(let alert)) = messages[3] {
            XCTAssertEqual(alert, try Fixtures.decode([SecurityAlert].self, from: "alerts.json").first)
        } else {
            XCTFail("alert")
        }
        if case .event(.scanProgress(let job)) = messages[4] {
            XCTAssertEqual(job, try Fixtures.decode(ScanJobSummary.self, from: "job_running.json"))
        } else {
            XCTFail("scan_progress")
        }
        if case .event(.scanFinished(let job)) = messages[5] {
            XCTAssertEqual(job.state, .finished)
        } else {
            XCTFail("scan_finished")
        }
        if case .event(.statusChanged(let changed)) = messages[6] {
            XCTAssertEqual(changed, status)
        } else {
            XCTFail("status_changed")
        }
        if case .event(.device(let deviceEvent)) = messages[7] {
            XCTAssertEqual(deviceEvent.change, .new)
            XCTAssertEqual(deviceEvent.device.kind, .hid)
            XCTAssertTrue(deviceEvent.device.isProbableKeyboard)
        } else {
            XCTFail("device")
        }
        if case .event(.updateFinished(let result)) = messages[8] {
            XCTAssertEqual(result.target, .all)
            XCTAssertTrue(result.ok)
            XCTAssertEqual(result.messages.count, 2)
            XCTAssertEqual(result.newDbVersion, "2026.10.25.1")
        } else {
            XCTFail("update_finished")
        }
        if case .event(.component(let component)) = messages[9] {
            XCTAssertEqual(component, try Fixtures.decode([ComponentStatus].self, from: "components.json").first)
        } else {
            XCTFail("component")
        }
        if case .event(.quarantined(let entry)) = messages[10] {
            XCTAssertEqual(entry.size, 68)
            XCTAssertEqual(entry.originalPath, "/Users/q/Downloads/eicar.com")
        } else {
            XCTFail("quarantined")
        }
    }

    func testUnknownEventIsTolerated() throws {
        let message = try ServerMessage.parse(Data(#"{"event":"future_event","data":{"x":1}}"#.utf8))
        XCTAssertEqual(message, .event(.unknown("future_event")))
    }
}
