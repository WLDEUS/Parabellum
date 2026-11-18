import Foundation
import ParabellumKit
import XCTest

/// `DbStatus.models` (ML classifier versions and metrics) decoding.
final class MlModelInfoTests: XCTestCase {
    func testStatusFixtureCarriesModels() throws {
        let status = try Fixtures.decode(StatusInfo.self, from: "status.json")
        let models = status.db.modelInfos
        XCTAssertEqual(models.map(\.id), ["macho", "script"])
        let macho = models[0]
        XCTAssertTrue(macho.loaded)
        XCTAssertEqual(macho.displayName, "Classifieur Mach-O")
        XCTAssertEqual(macho.version, "2026.10.20")
        XCTAssertEqual(macho.featuresVersion, 2)
        XCTAssertEqual(macho.trees, 214)
        XCTAssertEqual(macho.calibration, "isotonic")
        XCTAssertEqual(macho.threshold ?? 0, 0.9375, accuracy: 1e-9)
        XCTAssertEqual(macho.trainedDate, Date(timeIntervalSince1970: 1_792_900_000))
        XCTAssertEqual(macho.metrics.prAuc ?? 0, 0.9712, accuracy: 1e-9)
        XCTAssertEqual(macho.metrics.tprAtFpr01 ?? 0, 0.902, accuracy: 1e-9)
        XCTAssertEqual(macho.metrics.holdoutPos, 366)
        XCTAssertEqual(macho.metrics.families, 41)
        XCTAssertNil(macho.error)
        let script = models[1]
        XCTAssertFalse(script.loaded)
        XCTAssertNil(script.version)
        XCTAssertNil(script.metrics.rocAuc)
        XCTAssertNotNil(script.error)
    }

    func testOlderDaemonWithoutModels() throws {
        let json = #"{"malware_hashes":1,"yara_rules":2,"blocked_domains":3}"#
        let db = try JSONDecoder().decode(DbStatus.self, from: Data(json.utf8))
        XCTAssertNil(db.models)
        XCTAssertTrue(db.modelInfos.isEmpty)
    }

    func testMinimalModelInfo() throws {
        let json = #"{"name":"script","display_name":"Classifieur de scripts","loaded":false,"features_version":1}"#
        let m = try JSONDecoder().decode(ModelInfo.self, from: Data(json.utf8))
        XCTAssertEqual(m.metrics, .empty)
        XCTAssertNil(m.threshold)
    }
}
