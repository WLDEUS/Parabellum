import Foundation

// MARK: - Activity report (`report`)

public enum ReportPeriod: String, TolerantEnum {
    case week, month, custom
    public static let fallback: ReportPeriod = .week
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

/// One local day of an `ActivityReport` (chart series).
public struct ReportDay: Codable, Sendable, Hashable, Identifiable {
    /// `YYYY-MM-DD`
    public let date: String
    public let filesScanned: Int
    public let threats: Int
    public let quarantined: Int
    public let dnsBlocked: Int
    public let vpnConnectedSecs: Int

    public var id: String { date }

    /// Local midnight of `date`.
    public var day: Date {
        ReportDay.parser.date(from: date) ?? Date(timeIntervalSince1970: 0)
    }

    static let parser: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    enum CodingKeys: String, CodingKey {
        case date
        case filesScanned = "files_scanned"
        case threats, quarantined
        case dnsBlocked = "dns_blocked"
        case vpnConnectedSecs = "vpn_connected_secs"
    }
}

/// Everything Parabellum did over a period (`crates/pb-core/src/model.rs` `ActivityReport`).
public struct ActivityReport: Codable, Sendable, Hashable {
    public let period: ReportPeriod
    public let start: Int64
    public let end: Int64
    public let fromDate: String
    public let toDate: String
    public let elapsedSecs: Int
    public let generatedAt: Int64
    public let filesScanned: Int
    public let threatsDetected: Int
    public let quarantined: Int
    public let falsePositivesReported: Int
    public let persistenceNew: Int
    public let devicesNew: Int
    public let scans: Int
    public let scansByOrigin: [NamedCount]
    public let topDetections: [NamedCount]
    public let behaviorDetections: Int
    public let dbUpdates: Int
    public let dbVersion: String?
    public let componentUpdates: [String]
    public let dnsBlockedQueries: Int?
    public let topBlockedDomains: [NamedCount]
    public let vpnConnectedSecs: Int
    public let leakTests: Int
    public let leakTestsFailed: Int
    public let networkAlerts: Int
    public let alertsTotal: Int
    public let topAlertKinds: [NamedCount]
    public let privacy: RemovalSummary?
    public let removalRequestsSent: Int
    public let removalRequestsCompleted: Int
    public let breachesFound: Int
    public let breachNames: [String]
    public let daily: [ReportDay]

    public var startDate: Date { Date(unixSeconds: start) }
    /// Last instant of the period (exclusive end minus one second).
    public var lastDate: Date { Date(unixSeconds: end - 1) }

    /// Share of the elapsed period with the VPN up (0…1).
    public var vpnUptimeFraction: Double {
        guard elapsedSecs > 0 else { return 0 }
        return min(1, Double(vpnConnectedSecs) / Double(elapsedSecs))
    }

    enum CodingKeys: String, CodingKey {
        case period, start, end
        case fromDate = "from_date"
        case toDate = "to_date"
        case elapsedSecs = "elapsed_secs"
        case generatedAt = "generated_at"
        case filesScanned = "files_scanned"
        case threatsDetected = "threats_detected"
        case quarantined
        case falsePositivesReported = "false_positives_reported"
        case persistenceNew = "persistence_new"
        case devicesNew = "devices_new"
        case scans
        case scansByOrigin = "scans_by_origin"
        case topDetections = "top_detections"
        case behaviorDetections = "behavior_detections"
        case dbUpdates = "db_updates"
        case dbVersion = "db_version"
        case componentUpdates = "component_updates"
        case dnsBlockedQueries = "dns_blocked_queries"
        case topBlockedDomains = "top_blocked_domains"
        case vpnConnectedSecs = "vpn_connected_secs"
        case leakTests = "leak_tests"
        case leakTestsFailed = "leak_tests_failed"
        case networkAlerts = "network_alerts"
        case alertsTotal = "alerts_total"
        case topAlertKinds = "top_alert_kinds"
        case privacy
        case removalRequestsSent = "removal_requests_sent"
        case removalRequestsCompleted = "removal_requests_completed"
        case breachesFound = "breaches_found"
        case breachNames = "breach_names"
        case daily
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        period = try c.decodeOr(.period, ReportPeriod.week)
        start = try c.decode(Int64.self, forKey: .start)
        end = try c.decode(Int64.self, forKey: .end)
        fromDate = try c.decode(String.self, forKey: .fromDate)
        toDate = try c.decode(String.self, forKey: .toDate)
        elapsedSecs = try c.decodeOr(.elapsedSecs, 0)
        generatedAt = try c.decodeOr(.generatedAt, 0)
        filesScanned = try c.decodeOr(.filesScanned, 0)
        threatsDetected = try c.decodeOr(.threatsDetected, 0)
        quarantined = try c.decodeOr(.quarantined, 0)
        falsePositivesReported = try c.decodeOr(.falsePositivesReported, 0)
        persistenceNew = try c.decodeOr(.persistenceNew, 0)
        devicesNew = try c.decodeOr(.devicesNew, 0)
        scans = try c.decodeOr(.scans, 0)
        scansByOrigin = try c.decodeOr(.scansByOrigin, [NamedCount]())
        topDetections = try c.decodeOr(.topDetections, [NamedCount]())
        behaviorDetections = try c.decodeOr(.behaviorDetections, 0)
        dbUpdates = try c.decodeOr(.dbUpdates, 0)
        dbVersion = try c.decodeIfPresent(String.self, forKey: .dbVersion)
        componentUpdates = try c.decodeOr(.componentUpdates, [String]())
        dnsBlockedQueries = try c.decodeIfPresent(Int.self, forKey: .dnsBlockedQueries)
        topBlockedDomains = try c.decodeOr(.topBlockedDomains, [NamedCount]())
        vpnConnectedSecs = try c.decodeOr(.vpnConnectedSecs, 0)
        leakTests = try c.decodeOr(.leakTests, 0)
        leakTestsFailed = try c.decodeOr(.leakTestsFailed, 0)
        networkAlerts = try c.decodeOr(.networkAlerts, 0)
        alertsTotal = try c.decodeOr(.alertsTotal, 0)
        topAlertKinds = try c.decodeOr(.topAlertKinds, [NamedCount]())
        privacy = try c.decodeIfPresent(RemovalSummary.self, forKey: .privacy)
        removalRequestsSent = try c.decodeOr(.removalRequestsSent, 0)
        removalRequestsCompleted = try c.decodeOr(.removalRequestsCompleted, 0)
        breachesFound = try c.decodeOr(.breachesFound, 0)
        breachNames = try c.decodeOr(.breachNames, [String]())
        daily = try c.decodeOr(.daily, [ReportDay]())
    }
}

// MARK: - Navigation hints (`Alert.open_section`)

/// `report?period=month&month=2026-10` → section `report`, query `["period": "month", "month": "2026-10"]`.
public struct SectionLink: Sendable, Hashable {
    public let section: String
    public let query: [String: String]

    public init?(_ raw: String) {
        let parts = raw.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        guard let first = parts.first, !first.isEmpty else { return nil }
        section = String(first)
        var q: [String: String] = [:]
        if parts.count == 2 {
            for pair in parts[1].split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard kv.count == 2, !kv[0].isEmpty else { continue }
                q[String(kv[0])] = String(kv[1]).removingPercentEncoding ?? String(kv[1])
            }
        }
        query = q
    }
}

/// Months between two `YYYY-MM` keys (`monthOffset(of: "2026-10", now: <nov 2026>)` = 1); nil when invalid
/// or in the future.
public func monthOffset(of key: String, now: Date = Date(), calendar: Calendar = .current) -> Int? {
    let parts = key.split(separator: "-")
    guard parts.count == 2, let y = Int(parts[0]), let m = Int(parts[1]), (1...12).contains(m) else { return nil }
    let comps = calendar.dateComponents([.year, .month], from: now)
    guard let ny = comps.year, let nm = comps.month else { return nil }
    let offset = (ny - y) * 12 + (nm - m)
    return offset >= 0 ? offset : nil
}
