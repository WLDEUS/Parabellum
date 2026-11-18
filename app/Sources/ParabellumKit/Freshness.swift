import Foundation

/// Per-key bookkeeping for stale-while-revalidate screens:
/// - when each key was last loaded successfully (`needsRefresh` / `markFresh` / `invalidate`),
/// - which load of a key is the latest one (`begin` / `isLatest`), so an older, slower answer never
///   overwrites a newer one when two loads of the same list overlap.
///
/// Value type without UI dependency. The app keeps one in `AppModel`, deliberately not `@Published`:
/// bookkeeping must never re-render the window.
public struct FreshnessTracker: Sendable {
    /// Monotonic clock in seconds.
    public typealias Clock = @Sendable () -> TimeInterval

    private let now: Clock
    private var loadedAt: [String: TimeInterval] = [:]
    private var stale: Set<String> = []
    private var failed: Set<String> = []
    private var tickets: [String: UInt64] = [:]
    private var lastTicket: UInt64 = 0

    /// `now`: monotonic seconds (default: system uptime, unaffected by wall-clock changes).
    public init(now: @escaping Clock = { ProcessInfo.processInfo.systemUptime }) {
        self.now = now
    }

    /// True when `key` was never loaded, was invalidated, or was loaded `maxAge` seconds ago or more
    /// (`maxAge` 0 always refreshes).
    public func needsRefresh(_ key: String, maxAge: TimeInterval) -> Bool {
        guard let at = loadedAt[key], !stale.contains(key) else { return true }
        return now() - at >= maxAge
    }

    /// Loaded successfully at least once (even if stale since): the screen has something to show.
    public func hasLoaded(_ key: String) -> Bool {
        loadedAt[key] != nil
    }

    /// The last load of `key` failed (cleared when another load begins or one succeeds): a screen with
    /// nothing loaded can show its empty / error state instead of a spinner.
    public func hasFailed(_ key: String) -> Bool {
        failed.contains(key)
    }

    /// Seconds since the last successful load, nil if never loaded.
    public func age(_ key: String) -> TimeInterval? {
        loadedAt[key].map { now() - $0 }
    }

    public mutating func markFresh(_ key: String) {
        loadedAt[key] = now()
        stale.remove(key)
        failed.remove(key)
    }

    public mutating func markFailed(_ key: String) {
        failed.insert(key)
    }

    /// The data of `key` changed: the next `needsRefresh` is true (what was loaded stays displayable).
    public mutating func invalidate(_ key: String) {
        if loadedAt[key] != nil {
            stale.insert(key)
        }
    }

    /// Invalidates every key equal to `prefix` or starting with `prefix.` / `prefix-`.
    public mutating func invalidate(prefix: String) {
        for key in loadedAt.keys where key == prefix || key.hasPrefix(prefix + ".") || key.hasPrefix(prefix + "-") {
            stale.insert(key)
        }
    }

    /// Everything must be reloaded (reconnection: the daemon may have changed anything meanwhile).
    public mutating func invalidateAll() {
        stale.formUnion(loadedAt.keys)
    }

    /// Starts a load of `key` and returns its ticket; any earlier ticket of the same key becomes outdated.
    public mutating func begin(_ key: String) -> UInt64 {
        lastTicket &+= 1
        tickets[key] = lastTicket
        failed.remove(key)
        return lastTicket
    }

    /// True if no load of `key` started after the one holding `ticket`: its answer may be applied.
    public func isLatest(_ key: String, ticket: UInt64) -> Bool {
        tickets[key] == ticket
    }
}
