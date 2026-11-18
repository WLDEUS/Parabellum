import Foundation
import ParabellumKit
import XCTest

/// `parabellum vault … --json` payloads (fixtures written by the Rust golden test
/// `vault::tests::fixtures_match_serde`) and the recovery key helpers.
final class VaultTests: XCTestCase {
    func testOpenVaultStatus() throws {
        let s = try Fixtures.decode(VaultStatus.self, from: "vault_status_open.json")
        XCTAssertTrue(s.exists)
        XCTAssertTrue(s.encrypted)
        XCTAssertTrue(s.mounted)
        XCTAssertEqual(s.mountPoint, "/Volumes/Coffre")
        XCTAssertEqual(s.device, "/dev/disk4")
        XCTAssertEqual(s.capacityBytes, 21_474_836_480)
        XCTAssertEqual(s.allocatedBytes, 1_288_490_189)
        XCTAssertEqual(s.usedBytes, 21_474_836_480 - 20_186_346_291)
        XCTAssertEqual(s.fillRatio ?? 0, 0.06, accuracy: 0.001)
        XCTAssertEqual(s.filevault, .off)
        XCTAssertNil(s.syncWarning)
        XCTAssertEqual(s.recent.count, 1)
        XCTAssertEqual(s.recent[0].name, "Impôts 2026.pdf")
        XCTAssertEqual(s.recent[0].size, 482_133)
        XCTAssertEqual(s.recent[0].modifiedDate, Date(timeIntervalSince1970: 1_793_000_000))
    }

    func testAbsentVaultOmitsOptionals() throws {
        let s = try Fixtures.decode(VaultStatus.self, from: "vault_status_absent.json")
        XCTAssertFalse(s.exists)
        XCTAssertFalse(s.mounted)
        XCTAssertNil(s.mountPoint)
        XCTAssertNil(s.capacityBytes)
        XCTAssertNil(s.usedBytes)
        XCTAssertNil(s.fillRatio)
        XCTAssertEqual(s.filevault, .on)
        XCTAssertNotNil(s.syncWarning)
        XCTAssertTrue(s.recent.isEmpty)
    }

    func testErrorEnvelopeIsThrown() throws {
        let data = try Fixtures.data("vault_error_busy.json")
        XCTAssertThrowsError(try VaultCLI.decode(VaultStatus.self, from: data)) { error in
            guard let e = error as? VaultCLIError else {
                return XCTFail("\(error)")
            }
            XCTAssertTrue(e.isBusy)
            XCTAssertEqual(e.holders.first?.command, "Preview")
            XCTAssertEqual(e.holders.first?.pid, 812)
            XCTAssertEqual(e.holders.first?.paths, ["/Volumes/Coffre/Impôts 2026.pdf"])
            XCTAssertTrue(e.errorDescription?.hasPrefix("Des fichiers du coffre") == true)
        }
        let bad = Data(#"{"error":{"code":"bad_password","message":"mot de passe incorrect"}}"#.utf8)
        XCTAssertThrowsError(try VaultCLI.decode(VaultStatus.self, from: bad)) { error in
            XCTAssertEqual((error as? VaultCLIError)?.isBadPassword, true)
            XCTAssertEqual((error as? VaultCLIError)?.holders, [])
        }
    }

    func testShredReports() throws {
        let reports = try Fixtures.decode([ShredReport].self, from: "shred_reports.json")
        XCTAssertEqual(reports.count, 2)
        XCTAssertEqual(reports[0].outcome, .deleted)
        XCTAssertEqual(reports[0].zone, .home)
        XCTAssertEqual(reports[0].overwrittenBytes, 52_000)
        XCTAssertEqual(reports[0].name, "relevé.pdf")
        XCTAssertTrue(reports[0].isActionable)
        XCTAssertEqual(reports[1].outcome, .refused)
        XCTAssertNil(reports[1].zone)
        XCTAssertFalse(reports[1].isActionable)
        XCTAssertNotNil(reports[1].error)
        let future = Data(#"[{"path":"/x","outcome":"vaporized","zone":"cloud"}]"#.utf8)
        let decoded = try JSONDecoder().decode([ShredReport].self, from: future)
        XCTAssertEqual(decoded[0].outcome, .unknown)
        XCTAssertEqual(decoded[0].zone, .unknown)
    }

    func testRecoveryKeyShape() {
        let key = RecoveryKey.generate()
        XCTAssertEqual(key.count, 39)
        XCTAssertEqual(key.split(separator: "-").count, 8)
        XCTAssertTrue(RecoveryKey.looksLikeKey(key))
        XCTAssertNotEqual(key, RecoveryKey.generate())
        for ch in key where ch != "-" {
            XCTAssertTrue(RecoveryKey.alphabet.contains(ch), "\(ch)")
        }
    }

    func testRecoveryKeyNormalization() {
        let key = "7KQ2-M9XA-0001-ZZZZ-ABCD-EFGH-JKMN-PQRS"
        XCTAssertEqual(RecoveryKey.normalize(key), key)
        XCTAssertEqual(RecoveryKey.normalize("7kq2 m9xa oooi zzzz abcd efgh jkmn pqrs"), key)
        XCTAssertEqual(RecoveryKey.normalize("7KQ2M9XA0OIlZZZZABCDEFGHJKMNPQRS"), "7KQ2-M9XA-0011-ZZZZ-ABCD-EFGH-JKMN-PQRS")
        // A chosen password is never rewritten.
        XCTAssertEqual(RecoveryKey.normalize("mon mot de passe à moi"), "mon mot de passe à moi")
        XCTAssertFalse(RecoveryKey.looksLikeKey("mon mot de passe à moi"))
        XCTAssertFalse(RecoveryKey.looksLikeKey("UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU-UUUU"))
    }

    func testLocationArguments() {
        XCTAssertEqual(VaultLocation().arguments, ["vault"])
        XCTAssertEqual(
            VaultLocation(bundle: "/Users/camille/C.sparsebundle", mountpoint: "/Users/camille/Coffre").arguments,
            ["vault", "--bundle", "/Users/camille/C.sparsebundle", "--mountpoint", "/Users/camille/Coffre"]
        )
    }
}
