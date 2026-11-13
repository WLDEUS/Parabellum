import Foundation
@testable import ParabellumKit
import XCTest

/// Decoding of the LAN inventory and permissions audit payloads (fixtures from gen_fixtures.rs).
final class LanPermissionsTests: XCTestCase {
    func testLanStatusDecodes() throws {
        let s = try Fixtures.decode(LanStatus.self, from: "lan_status.json")
        XCTAssertTrue(s.enabled)
        XCTAssertFalse(s.scanning)
        XCTAssertEqual(s.intervalMinutes, 15)
        let net = try XCTUnwrap(s.network)
        XCTAssertEqual(net.id, "gw:00:24:d4:a1:b2:c3")
        XCTAssertEqual(net.subnet, "192.168.1.0/24")
        XCTAssertEqual(net.lastScanMode, .active)
        XCTAssertEqual(net.devices.count, 3)
        let router = net.devices[0]
        XCTAssertTrue(router.isGateway)
        XCTAssertEqual(router.deviceType, .router)
        XCTAssertFalse(router.isUnknown)
        let tv = net.devices[1]
        XCTAssertEqual(tv.displayName, "Apple TV du salon")
        XCTAssertEqual(tv.services, ["_airplay._tcp", "_raop._tcp"])
        XCTAssertTrue(tv.trusted)
        let phone = net.devices[2]
        XCTAssertTrue(phone.privateMac)
        XCTAssertTrue(phone.isUnknown)
        XCTAssertEqual(phone.openPorts, [62078])
        XCTAssertEqual(phone.displayName, "Appareil (adresse privée)")
        XCTAssertNil(phone.vendor)
        XCTAssertEqual(s.networks.first?.unknown, 1)
    }

    func testLanEventDecodes() throws {
        let line = try XCTUnwrap(try Fixtures.lines("lan_event.jsonl").first)
        guard case .event(.lan(let s)) = try ServerMessage.parse(line) else {
            return XCTFail("événement lan attendu")
        }
        XCTAssertTrue(s.scanning)
        XCTAssertEqual(s.progress, 0.4, accuracy: 0.001)
        XCTAssertEqual(s.phase, "Balayage léger du sous-réseau")
        XCTAssertNil(s.network)
    }

    func testPermissionsReportDecodes() throws {
        let r = try Fixtures.decode(PermissionsReport.self, from: "permissions_report.json")
        XCTAssertTrue(r.systemDbRead && r.userDbRead)
        XCTAssertEqual(r.grants.count, 2)
        let ax = r.grants[0]
        XCTAssertEqual(ax.risk, .high)
        XCTAssertEqual(ax.auth, .allowed)
        XCTAssertEqual(ax.signing?.adhoc, true)
        XCTAssertTrue(ax.canReset)
        XCTAssertEqual(ax.settingsUrl, "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
        let ae = r.grants[1]
        XCTAssertEqual(ae.targetName, "Finder")
        XCTAssertEqual(ae.installed, false)
        XCTAssertFalse(ae.canReset)
        XCTAssertNil(ae.lastModified)
        XCTAssertEqual(r.configurationProfiles, ["Profil Wi-Fi du bureau"])
    }

    func testExtensionsAndResetDecode() throws {
        let e = try Fixtures.decode(ExtensionsReport.self, from: "extensions_report.json")
        XCTAssertEqual(e.extensions.first?.name, "uBlock Origin")
        XCTAssertEqual(e.extensions.first?.hostPermissions, ["<all_urls>"])
        XCTAssertEqual(e.extensions.first?.fromStore, true)
        XCTAssertEqual(BrowserLabels.label("chrome"), "Google Chrome")
        XCTAssertEqual(e.errors.count, 1)
        let r = try Fixtures.decode(TccResetResult.self, from: "tcc_reset.json")
        XCTAssertTrue(r.ok)
        XCTAssertEqual(r.bundleId, "us.zoom.xos")
    }

    func testRequestsClassification() {
        XCTAssertFalse(Request.lanStatus().isMutating)
        XCTAssertTrue(Request.lanScan().isMutating)
        XCTAssertTrue(Request.permissionsAudit().isMutating)
        XCTAssertFalse(Request.permissionsAudit().requiresAdmin)
        XCTAssertTrue(Request.lanSetDevice(networkId: "gw:x", mac: "m", trusted: true).requiresAdmin)
        XCTAssertFalse(Request.lanSetDevice(networkId: "gw:x", mac: "m", name: "n").requiresAdmin)
        XCTAssertTrue(Request.resolveAlert(alertId: 1, action: .trustLanDevice).requiresAdmin)
        XCTAssertEqual(AlertAction.trustLanDevice.label, "Je connais cet appareil")
    }

    func testConfigSectionsRoundTrip() throws {
        let cfg = try Fixtures.decode(Config.self, from: "config.json")
        XCTAssertEqual(cfg.lan.scanIntervalMinutes, 15)
        XCTAssertTrue(cfg.lan.activeOnTrusted)
        XCTAssertEqual(cfg.permissionsAudit.intervalHours, 24)
        var bad = cfg
        bad.lan.scanIntervalMinutes = 1
        XCTAssertFalse(bad.validationErrors().isEmpty)
        let json = try JSONValue(encoding: cfg)
        XCTAssertNotNil(json["permissions"]?["interval_hours"])
    }
}
