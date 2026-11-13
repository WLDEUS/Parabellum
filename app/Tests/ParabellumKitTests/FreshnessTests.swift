import Foundation
import ParabellumKit
import XCTest

/// Stale-while-revalidate bookkeeping used by AppModel and the feature stores.
final class FreshnessTests: XCTestCase {
    /// Settable clock shared with the tracker.
    private final class FakeClock: @unchecked Sendable {
        private let lock = NSLock()
        private var value: TimeInterval = 1000

        var now: TimeInterval {
            lock.lock()
            defer { lock.unlock() }
            return value
        }

        func advance(_ seconds: TimeInterval) {
            lock.lock()
            value += seconds
            lock.unlock()
        }
    }

    func testFreshUntilMaxAge() {
        let clock = FakeClock()
        var tracker = FreshnessTracker(now: { clock.now })
        XCTAssertTrue(tracker.needsRefresh("alerts", maxAge: 30))
        XCTAssertFalse(tracker.hasLoaded("alerts"))
        XCTAssertNil(tracker.age("alerts"))

        tracker.markFresh("alerts")
        XCTAssertFalse(tracker.needsRefresh("alerts", maxAge: 30))
        XCTAssertTrue(tracker.hasLoaded("alerts"))
        clock.advance(29.9)
        XCTAssertFalse(tracker.needsRefresh("alerts", maxAge: 30))
        clock.advance(0.1)
        XCTAssertTrue(tracker.needsRefresh("alerts", maxAge: 30))
        XCTAssertEqual(tracker.age("alerts") ?? -1, 30, accuracy: 0.001)
        // maxAge 0 = forced refresh.
        tracker.markFresh("alerts")
        XCTAssertTrue(tracker.needsRefresh("alerts", maxAge: 0))
        // Keys are independent.
        XCTAssertTrue(tracker.needsRefresh("devices", maxAge: 30))
    }

    func testInvalidationKeepsDataDisplayable() {
        let clock = FakeClock()
        var tracker = FreshnessTracker(now: { clock.now })
        tracker.markFresh("guard")
        tracker.markFresh("guard.snapshots")
        tracker.markFresh("guardian")
        tracker.markFresh("lan")

        tracker.invalidate("lan")
        XCTAssertTrue(tracker.needsRefresh("lan", maxAge: 30))
        XCTAssertTrue(tracker.hasLoaded("lan"), "stale data stays on screen while revalidating")
        tracker.markFresh("lan")
        XCTAssertFalse(tracker.needsRefresh("lan", maxAge: 30))

        tracker.invalidate(prefix: "guard")
        XCTAssertTrue(tracker.needsRefresh("guard", maxAge: 30))
        XCTAssertTrue(tracker.needsRefresh("guard.snapshots", maxAge: 30))
        XCTAssertFalse(tracker.needsRefresh("guardian", maxAge: 30), "prefix stops at a separator")

        // Invalidating a key never loaded does not make it "loaded".
        tracker.invalidate("vault")
        XCTAssertFalse(tracker.hasLoaded("vault"))

        tracker.invalidateAll()
        for key in ["guard", "guard.snapshots", "guardian", "lan"] {
            XCTAssertTrue(tracker.needsRefresh(key, maxAge: 3600), key)
            XCTAssertTrue(tracker.hasLoaded(key), key)
        }
    }

    func testOnlyTheLatestLoadMayApply() {
        var tracker = FreshnessTracker()
        let first = tracker.begin("alerts")
        let second = tracker.begin("alerts")
        let other = tracker.begin("devices")
        XCTAssertFalse(tracker.isLatest("alerts", ticket: first), "older answer must be dropped")
        XCTAssertTrue(tracker.isLatest("alerts", ticket: second))
        XCTAssertTrue(tracker.isLatest("devices", ticket: other))
        XCTAssertFalse(tracker.isLatest("quarantine", ticket: second))
    }

    func testFailureState() {
        var tracker = FreshnessTracker()
        _ = tracker.begin("report")
        tracker.markFailed("report")
        XCTAssertTrue(tracker.hasFailed("report"))
        XCTAssertTrue(tracker.needsRefresh("report", maxAge: 30))
        _ = tracker.begin("report")
        XCTAssertFalse(tracker.hasFailed("report"), "a new attempt clears the failure")
        tracker.markFailed("report")
        tracker.markFresh("report")
        XCTAssertFalse(tracker.hasFailed("report"))
        XCTAssertFalse(tracker.needsRefresh("report", maxAge: 30))
    }
}
