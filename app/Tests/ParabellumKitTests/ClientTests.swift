import Foundation
import ParabellumKit
import XCTest

/// Line framing + the real client against a local Unix-socket server.
final class ClientTests: XCTestCase {
    // MARK: LineBuffer

    func testLineBufferSplitsAcrossChunks() throws {
        var buffer = LineBuffer(maxLineBytes: 64)
        let none = try buffer.append(Array("abc".utf8))
        XCTAssertEqual(none, [])
        let lines = try buffer.append(Array("def\nghi\n\njk".utf8))
        XCTAssertEqual(lines.map { String(decoding: $0, as: UTF8.self) }, ["abcdef", "ghi"])
        XCTAssertEqual(buffer.pendingCount, 2)
        let rest = try buffer.append(Array("l\n".utf8))
        XCTAssertEqual(rest.map { String(decoding: $0, as: UTF8.self) }, ["jkl"])
        XCTAssertEqual(buffer.pendingCount, 0)
    }

    func testLineBufferEnforcesMaxLine() throws {
        var exact = LineBuffer(maxLineBytes: 8)
        let exactLines = try exact.append(Array("12345678\n".utf8))
        XCTAssertEqual(exactLines.count, 1)

        var unterminated = LineBuffer(maxLineBytes: 8)
        XCTAssertThrowsError(try unterminated.append(Array("123456789".utf8)))

        var split = LineBuffer(maxLineBytes: 8)
        XCTAssertNoThrow(try split.append(Array("12345".utf8)))
        XCTAssertThrowsError(try split.append(Array("6789\n".utf8)))
    }

    // MARK: Client against a fake daemon

    private static func fakeDaemon() throws -> TestSocketServer {
        let statusJSON = String(decoding: try Fixtures.data("status.json"), as: UTF8.self)
            .replacingOccurrences(of: "\n", with: "")
        let alertEvent = String(decoding: try Fixtures.lines("server_lines.jsonl")[3], as: UTF8.self)
        return try TestSocketServer { request in
            guard let id = request["id"]?.intValue, let cmd = request["cmd"]?.stringValue else { return [] }
            switch cmd {
            case "ping":
                return [#"{"id":\#(id),"ok":true,"data":{"version":"0.1.0","protocol":1}}"#]
            case "status":
                return [#"{"id":\#(id),"ok":true,"data":\#(statusJSON)}"#]
            case "cancel_scan":
                return [#"{"id":\#(id),"ok":true}"#]
            case "get_job":
                return [#"{"id":\#(id),"ok":false,"error":{"code":"not_found","message":"tâche inconnue"}}"#]
            case "subscribe":
                return [#"{"id":\#(id),"ok":true}"#, alertEvent]
            case "retro_hunt":
                return [] // never answers: exercises the timeout
            case "set_dns":
                // Like the daemon: disabling DNS needs `auth`; echo it back to check the wire format.
                if let auth = request["auth"]?.stringValue {
                    return [#"{"id":\#(id),"ok":true,"data":{"auth":"\#(auth)"}}"#]
                }
                return [#"{"id":\#(id),"ok":false,"error":{"code":"auth_required","message":"autorisation requise"}}"#]
            default:
                return [#"{"id":\#(id),"ok":false,"error":{"code":"bad_request","message":"?"}}"#]
            }
        }
    }

    func testCallRoundTrip() async throws {
        let server = try Self.fakeDaemon()
        defer { server.stop() }
        let client = DaemonClient(socketPath: server.path)
        let ping = try await withTimeout(5) {
            try await client.call(.ping, as: PingResponse.self)
        }
        XCTAssertEqual(ping.protocolVersion, 1)
        XCTAssertEqual(ping.version, "0.1.0")
    }

    func testConcurrentCallsAreCorrelatedById() async throws {
        let server = try Self.fakeDaemon()
        defer { server.stop() }
        let client = DaemonClient(socketPath: server.path)
        let (ping, status) = try await withTimeout(5) { () -> (PingResponse, StatusInfo) in
            async let ping = client.call(.ping, as: PingResponse.self)
            async let status = client.call(.status, as: StatusInfo.self)
            return try await (ping, status)
        }
        XCTAssertEqual(ping.protocolVersion, 1)
        XCTAssertEqual(status.protection, .degraded)
    }

    func testVoidCallAndDaemonError() async throws {
        let server = try Self.fakeDaemon()
        defer { server.stop() }
        let client = DaemonClient(socketPath: server.path)
        try await withTimeout(5) {
            try await client.callVoid(.cancelScan(jobId: "j"))
        }
        do {
            _ = try await withTimeout(5) {
                try await client.call(.getJob(jobId: "x"), as: ScanJobDetail.self)
            }
            XCTFail("une erreur du service était attendue")
        } catch let error as DaemonClientError {
            guard case .daemon(let ipcError) = error else { return XCTFail("erreur inattendue : \(error)") }
            XCTAssertEqual(ipcError.code, .notFound)
        }
    }

    func testAuthIsSentAndAuthRequiredIsReported() async throws {
        let server = try Self.fakeDaemon()
        defer { server.stop() }
        let client = DaemonClient(socketPath: server.path)
        do {
            _ = try await withTimeout(5) {
                try await client.call(.setDns(enabled: false), as: JSONValue.self)
            }
            XCTFail("auth_required attendu")
        } catch let error as DaemonClientError {
            guard case .daemon(let ipcError) = error else { return XCTFail("erreur inattendue : \(error)") }
            XCTAssertEqual(ipcError.code, .authRequired)
        }
        let echoed = try await withTimeout(5) {
            try await client.call(.setDns(enabled: false), as: JSONValue.self, auth: "QUJD")
        }
        XCTAssertEqual(echoed["auth"], .string("QUJD"))
    }

    func testTimeout() async throws {
        let server = try Self.fakeDaemon()
        defer { server.stop() }
        let client = DaemonClient(socketPath: server.path)
        do {
            _ = try await withTimeout(5) {
                try await client.call(.retroHunt(days: 1), as: JobStarted.self, timeout: 0.3)
            }
            XCTFail("timeout attendu")
        } catch let error as DaemonClientError {
            XCTAssertEqual(error, .timeout)
        }
        // The connection is still usable afterwards.
        let ping = try await withTimeout(5) {
            try await client.call(.ping, as: PingResponse.self)
        }
        XCTAssertEqual(ping.protocolVersion, 1)
    }

    func testNotRunning() async throws {
        let client = DaemonClient(socketPath: "/tmp/pbt-absent-\(UUID().uuidString.prefix(6)).sock")
        do {
            _ = try await client.call(.ping, as: PingResponse.self)
            XCTFail("notRunning attendu")
        } catch let error as DaemonClientError {
            XCTAssertEqual(error, .notRunning)
        }
    }

    func testSubscriptionDeliversConnectedThenEvents() async throws {
        let server = try Self.fakeDaemon()
        defer { server.stop() }
        let client = DaemonClient(socketPath: server.path)
        let items = try await withTimeout(5) { () -> [DaemonStreamItem] in
            var received: [DaemonStreamItem] = []
            for await item in client.subscribe() {
                received.append(item)
                if received.count == 2 {
                    break
                }
            }
            return received
        }
        XCTAssertEqual(items.first, .connected)
        guard items.count == 2, case .event(.alert(let alert)) = items[1] else {
            return XCTFail("événement alert attendu, reçu \(items)")
        }
        XCTAssertEqual(alert.id, 12)
    }

    func testSubscriptionReportsDisconnected() async throws {
        let client = DaemonClient(socketPath: "/tmp/pbt-absent-\(UUID().uuidString.prefix(6)).sock")
        let first = try await withTimeout(5) { () -> DaemonStreamItem? in
            for await item in client.subscribe() {
                return item
            }
            return nil
        }
        XCTAssertEqual(first, .disconnected(.notRunning))
    }
}
