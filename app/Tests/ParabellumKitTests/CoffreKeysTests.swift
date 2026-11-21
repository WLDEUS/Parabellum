import Foundation
@testable import ParabellumKit
import XCTest

final class CoffreKeysTests: XCTestCase {
    func testKeyFileSealsAndOpensThePassword() throws {
        let keyFile = CoffreKeys.newKeyFile()
        XCTAssertTrue(String(decoding: keyFile, as: UTF8.self).hasPrefix("PARABELLUM-COFFRE-CLE-1\n"))
        let slot = try CoffreKeys.keyFileSlot(password: "correct horse battery", keyFile: keyFile)
        XCTAssertEqual(slot.kind, .keyFile)
        XCTAssertNil(slot.seKey)
        XCTAssertFalse(String(decoding: slot.sealed, as: UTF8.self).contains("correct horse"))
        let keys = CoffreKeys.Keys(slots: [slot])
        XCTAssertTrue(keys.hasKeyFile)
        XCTAssertFalse(keys.hasTouchID)
        XCTAssertEqual(try CoffreKeys.password(from: keys, keyFile: keyFile), "correct horse battery")
        // Line endings changed by a copy (CRLF) still work.
        let crlf = Data(String(decoding: keyFile, as: UTF8.self).replacingOccurrences(of: "\n", with: "\r\n").utf8)
        XCTAssertEqual(try CoffreKeys.password(from: keys, keyFile: crlf), "correct horse battery")
    }

    func testOtherKeyFilesAndGarbageAreRefused() throws {
        let slot = try CoffreKeys.keyFileSlot(password: "secret secret", keyFile: CoffreKeys.newKeyFile())
        let keys = CoffreKeys.Keys(slots: [slot])
        XCTAssertThrowsError(try CoffreKeys.password(from: keys, keyFile: CoffreKeys.newKeyFile())) {
            XCTAssertEqual($0 as? CoffreKeys.Failure, .wrongKey)
        }
        XCTAssertThrowsError(try CoffreKeys.password(from: keys, keyFile: Data("hello\nworld\n".utf8))) {
            XCTAssertEqual($0 as? CoffreKeys.Failure, .invalidKeyFile)
        }
        XCTAssertThrowsError(try CoffreKeys.keyFileSlot(password: "x", keyFile: Data()))
    }

    func testKeysRoundTripOnDisk() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("coffre-\(UUID().uuidString).coffre")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        XCTAssertEqual(CoffreKeys.load(package: dir), CoffreKeys.Keys())
        let keyFile = CoffreKeys.newKeyFile()
        let keys = CoffreKeys.Keys(slots: [try CoffreKeys.keyFileSlot(password: "p4ssw0rd-long", keyFile: keyFile)])
        try CoffreKeys.save(keys, package: dir)
        let loaded = CoffreKeys.load(package: dir)
        XCTAssertEqual(loaded, keys)
        XCTAssertEqual(try CoffreKeys.password(from: loaded, keyFile: keyFile), "p4ssw0rd-long")
        let json = try String(contentsOf: dir.appendingPathComponent("keys.json"), encoding: .utf8)
        XCTAssertTrue(json.contains("\"kind\" : \"key_file\""))
        let mode = try FileManager.default.attributesOfItem(atPath: dir.appendingPathComponent("keys.json").path)[.posixPermissions] as? Int
        XCTAssertEqual(mode, 0o600)
    }

    func testTouchIDSlotNeedsTheSecureEnclave() async throws {
        // CI virtual machines have no Secure Enclave: the slot is refused cleanly, never faked.
        try XCTSkipIf(CoffreKeys.touchIDAvailable, "real Touch ID Mac: not exercised in unit tests (it would prompt)")
        XCTAssertThrowsError(try CoffreKeys.touchIDSlot(password: "x"))
        do {
            _ = try await CoffreKeys.passwordWithTouchID(from: CoffreKeys.Keys(), reason: "test")
            XCTFail("no Touch ID slot")
        } catch {
            XCTAssertTrue(error is CoffreKeys.Failure)
        }
    }
}
