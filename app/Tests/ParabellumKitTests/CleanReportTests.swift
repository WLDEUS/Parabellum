import Foundation
import ParabellumKit
import XCTest

/// Activity report (`report`) and Mac cleaning (`parabellum clean … --json`) payloads.
final class CleanReportTests: XCTestCase {
    func testActivityReportDecodes() throws {
        let r = try Fixtures.decode(ActivityReport.self, from: "activity_report.json")
        XCTAssertEqual(r.period, .month)
        XCTAssertEqual(r.fromDate, "2026-10-01")
        XCTAssertEqual(r.toDate, "2026-10-31")
        XCTAssertEqual(r.filesScanned, 15_234)
        XCTAssertEqual(r.scansByOrigin.first?.name, "realtime")
        XCTAssertEqual(r.topBlockedDomains.first?.count, 5_120)
        XCTAssertEqual(r.dnsBlockedQueries, 40_211)
        XCTAssertEqual(r.leakTestsFailed, 1)
        XCTAssertEqual(r.privacy?.completed, 15)
        XCTAssertEqual(r.breachNames, ["ExempleShop"])
        XCTAssertEqual(r.daily.count, 2)
        XCTAssertEqual(r.daily[0].vpnConnectedSecs, 43_200)
        XCTAssertGreaterThan(r.vpnUptimeFraction, 0.5)
        XCTAssertLessThanOrEqual(r.vpnUptimeFraction, 1)
    }

    func testActivityReportToleratesMissingFields() throws {
        let json = #"{"period":"fortnight","start":1,"end":2,"from_date":"2026-10-01","to_date":"2026-10-01"}"#
        let r = try JSONDecoder().decode(ActivityReport.self, from: Data(json.utf8))
        XCTAssertEqual(r.period, .week)
        XCTAssertNil(r.dnsBlockedQueries)
        XCTAssertNil(r.privacy)
        XCTAssertTrue(r.daily.isEmpty)
        XCTAssertEqual(r.vpnUptimeFraction, 0)
    }

    func testReportAlertCarriesSection() throws {
        let alert = try Fixtures.decode(SecurityAlert.self, from: "report_alert.json")
        XCTAssertEqual(alert.kind, .system)
        let link = try XCTUnwrap(alert.openSection.flatMap(SectionLink.init))
        XCTAssertEqual(link.section, "report")
        XCTAssertEqual(link.query["period"], "month")
        XCTAssertEqual(link.query["month"], "2026-10")
        let plain = try Fixtures.decode([SecurityAlert].self, from: "alerts.json")
        XCTAssertNil(plain.first?.openSection)
    }

    func testSectionLinkAndMonthOffset() {
        XCTAssertNil(SectionLink(""))
        XCTAssertEqual(SectionLink("cleaning")?.section, "cleaning")
        XCTAssertEqual(SectionLink("cleaning")?.query, [:])
        XCTAssertEqual(SectionLink("report?bad&a=b")?.query, ["a": "b"])
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "Europe/Paris")!
        let nov = calendar.date(from: DateComponents(year: 2026, month: 11, day: 14))!
        XCTAssertEqual(monthOffset(of: "2026-10", now: nov, calendar: calendar), 1)
        XCTAssertEqual(monthOffset(of: "2025-11", now: nov, calendar: calendar), 12)
        XCTAssertEqual(monthOffset(of: "2026-11", now: nov, calendar: calendar), 0)
        XCTAssertNil(monthOffset(of: "2026-12", now: nov, calendar: calendar))
        XCTAssertNil(monthOffset(of: "2026-13", now: nov, calendar: calendar))
    }

    func testCleanScanDecodes() throws {
        let r = try Fixtures.decode(CleanScanReport.self, from: "clean_scan.json")
        XCTAssertEqual(r.reclaimableSize, 4_350_000_000)
        XCTAssertEqual(r.categories.map(\.category), [.caches, .largeFiles, .trash])
        let cache = r.categories[0].items[0]
        XCTAssertTrue(cache.selected)
        XCTAssertFalse(cache.inUse)
        XCTAssertEqual(cache.bundleId, "com.spotify.client")
        let vm = r.categories[1].items[0]
        XCTAssertEqual(vm.safety, .review)
        XCTAssertFalse(vm.selected)
        XCTAssertNotNil(vm.lastUsed)
        XCTAssertFalse(r.categories[2].trashable)
        XCTAssertNotNil(r.categories[2].error)
    }

    func testCleanApplyDecodes() throws {
        let r = try Fixtures.decode(CleanApplyReport.self, from: "clean_apply.json")
        XCTAssertEqual(r.freedBytes, 1_200_000_000)
        XCTAssertEqual(r.results.map(\.outcome), [.movedToTrash, .deleted, .skipped])
        XCTAssertEqual(r.results[0].trashedAs, "/Users/q/.Trash/com.spotify.client 2")
        XCTAssertEqual(r.results[2].category, .browserCaches)
    }

    func testCleanPlanEncodesLikeSerde() throws {
        let plan = CleanPlan(
            items: [CleanPlanItem(category: .browserCaches, path: "/Users/q/Library/Caches/Google/Chrome")],
            permanent: [.logs]
        )
        let v = try JSONValue(data: JSONEncoder().encode(plan))
        guard case .array(let items)? = v["items"], case .array(let permanent)? = v["permanent"] else {
            return XCTFail("items / permanent attendus")
        }
        XCTAssertEqual(items.first?["category"]?.stringValue, "browser_caches")
        XCTAssertEqual(permanent.first?.stringValue, "logs")
        XCTAssertEqual(CleanCategory(rawValue: "large_files"), .largeFiles)
    }
}
