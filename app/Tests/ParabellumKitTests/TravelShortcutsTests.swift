import Foundation
import ParabellumKit
import XCTest

/// Travel mode payloads (from `gen_fixtures.rs`), its per-user rules, and the `parabellum://` URL parser.
final class TravelShortcutsTests: XCTestCase {
    // MARK: Travel mode

    func testTravelStatusFixture() throws {
        let s = try Fixtures.decode(TravelStatus.self, from: "travel_status.json")
        XCTAssertTrue(s.active)
        XCTAssertEqual(s.since, 1_793_000_200)
        XCTAssertFalse(s.automatic)
        XCTAssertEqual(s.network, "Gare-WiFi-Gratuit")
        XCTAssertEqual(s.changes.map(\.id), ["vpn_mode", "stealth"])
        XCTAssertEqual(s.warnings.count, 1)
        XCTAssertNil(s.message)
        XCTAssertTrue(s.untrustedNetwork)
    }

    func testTravelStatusDefaultFixture() throws {
        let s = try Fixtures.decode(TravelStatus.self, from: "travel_status_default.json")
        XCTAssertFalse(s.active)
        XCTAssertNil(s.since)
        XCTAssertTrue(s.changes.isEmpty)
    }

    func testStatusInfoTravelFlag() throws {
        XCTAssertTrue(try Fixtures.decode(StatusInfo.self, from: "status.json").travelActive)
    }

    func testTravelConfigDefaultsMatchRust() throws {
        let config = try Fixtures.decode(Config.self, from: "config.json")
        XCTAssertEqual(config.travel, TravelConfig())
        let encoded = try JSONValue(encoding: config.travel)
        XCTAssertEqual(encoded["suggest_on_untrusted"], .bool(true))
        XCTAssertEqual(encoded["bluetooth_off"], .bool(false))
    }

    func testTravelRequestsClassification() throws {
        XCTAssertFalse(Request.travelStatus.isMutating)
        XCTAssertTrue(Request.travelEnable.isMutating)
        XCTAssertFalse(Request.travelEnable.requiresAdmin)
        XCTAssertTrue(Request.travelDisable.requiresAdmin)
        XCTAssertFalse(Request.resolveAlert(alertId: 1, action: .enableTravelMode).requiresAdmin)
        let line = try JSONValue(data: Request.travelEnable.encode(id: 3))
        XCTAssertEqual(line["cmd"]?.stringValue, "travel_enable")
    }

    func testLocalPlanEnableAndRestore() {
        var config = TravelConfig()
        config.bluetoothOff = true
        let before = TravelLocalSettings(airdropMode: "Contacts Only", bluetoothOn: true)
        let applied = TravelLocalPlan.enable(current: before, config: config)
        XCTAssertEqual(applied, TravelLocalSettings(airdropMode: "Off", bluetoothOn: false))
        // Untouched since: everything goes back.
        let back = TravelLocalPlan.restore(before: before, applied: applied, current: applied)
        XCTAssertEqual(back.target, before)
        XCTAssertTrue(back.kept.isEmpty)
        // Bluetooth turned back on by hand while travelling: kept as is, AirDrop restored.
        var current = applied
        current.airdropMode = "Off"
        current.bluetoothOn = true
        let r = TravelLocalPlan.restore(before: before, applied: applied, current: current)
        XCTAssertEqual(r.target.bluetoothOn, true)
        XCTAssertEqual(r.target.airdropMode, "Contacts Only")
        XCTAssertTrue(r.kept.isEmpty, "back to the previous value: nothing to report")
        // AirDrop set to Everyone by hand: kept and reported.
        current.airdropMode = "Everyone"
        let k = TravelLocalPlan.restore(before: before, applied: applied, current: current)
        XCTAssertEqual(k.target.airdropMode, "Everyone")
        XCTAssertEqual(k.kept, ["AirDrop"])
        // Unknown values are never touched.
        let unknown = TravelLocalPlan.enable(current: TravelLocalSettings(), config: config)
        XCTAssertEqual(unknown, TravelLocalSettings())
    }

    // MARK: URL scheme

    private func parse(_ s: String) -> Result<ParabellumURLAction, ParabellumURLError> {
        ParabellumURL.parse(URL(string: s)!)
    }

    private func action(_ s: String, file: StaticString = #filePath, line: UInt = #line) -> ParabellumURLAction? {
        switch parse(s) {
        case .success(let a): return a
        case .failure(let e):
            XCTFail("\(s) refusé : \(e.message)", file: file, line: line)
            return nil
        }
    }

    private func rejected(_ s: String, file: StaticString = #filePath, line: UInt = #line) {
        if case .success(let a) = parse(s) {
            XCTFail("\(s) accepté : \(a)", file: file, line: line)
        }
    }

    func testURLActions() {
        XCTAssertEqual(action("parabellum://scan/downloads"), .scanDownloads)
        XCTAssertEqual(action("PARABELLUM://Scan/Downloads"), .scanDownloads)
        XCTAssertEqual(action("parabellum:scan/downloads"), .scanDownloads)
        XCTAssertEqual(action("parabellum://vpn/connect"), .vpnConnect)
        XCTAssertEqual(action("parabellum://vpn/disconnect"), .vpnDisconnect)
        XCTAssertEqual(action("parabellum://travel/on"), .travelOn)
        XCTAssertEqual(action("parabellum://travel/off/"), .travelOff)
        XCTAssertEqual(action("parabellum://pause?minutes=15"), .pause(minutes: 15))
        XCTAssertEqual(action("parabellum://pause"), .pause(minutes: 15))
        XCTAssertEqual(action("parabellum://resume"), .resume)
        XCTAssertEqual(action("parabellum://update"), .update(target: .all))
        XCTAssertEqual(action("parabellum://update?target=db"), .update(target: .db))
        XCTAssertEqual(action("parabellum://open"), .open(section: nil))
        XCTAssertEqual(action("parabellum://open/alerts"), .open(section: "alerts"))
    }

    func testURLScanPaths() {
        XCTAssertEqual(
            action("parabellum://scan?path=/Users/camille/Downloads/Mon%20fichier.dmg"),
            .scan(paths: ["/Users/camille/Downloads/Mon fichier.dmg"])
        )
        XCTAssertEqual(
            action("parabellum://scan?path=/a&path=/b/c"),
            .scan(paths: ["/a", "/b/c"])
        )
        rejected("parabellum://scan")
        rejected("parabellum://scan?path=")
        rejected("parabellum://scan?path=relative/file")
        rejected("parabellum://scan?path=/Users/../etc/passwd")
        rejected("parabellum://scan?path=/Users/./x")
        rejected("parabellum://scan?path=/a//b")
        rejected("parabellum://scan?path=/a%00b")
        rejected("parabellum://scan?path=/a%0Ab")
        rejected("parabellum://scan?path=/a&recursive=false")
        let many = (0...ParabellumURL.maxPaths).map { "path=/f\($0)" }.joined(separator: "&")
        rejected("parabellum://scan?\(many)")
    }

    func testURLRejectsOddInput() {
        rejected("https://scan/downloads")
        rejected("parabellum://")
        rejected("parabellum://format/disk")
        rejected("parabellum://vpn")
        rejected("parabellum://vpn/connect?x=1")
        rejected("parabellum://pause?minutes=0")
        rejected("parabellum://pause?minutes=-5")
        rejected("parabellum://pause?minutes=1e3")
        rejected("parabellum://pause?minutes=99999")
        rejected("parabellum://pause?minutes=10&minutes=20")
        rejected("parabellum://update?target=everything")
        rejected("parabellum://open/../settings")
        rejected("parabellum://open/al3rts")
        rejected("parabellum://open/a/b")
        rejected("parabellum://user:pw@resume")
        rejected("parabellum://resume:8080")
    }

    func testURLExamplesAllParse() {
        for example in ParabellumURL.examples {
            XCTAssertNotNil(action(example.url), example.title)
        }
    }
}
