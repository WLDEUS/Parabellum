import Foundation

// Daily report (IPC `daily_report`, `list_daily_reports`, `generate_daily_report`, event `daily_report`).
// Same conventions as Models.swift: explicit snake_case keys, Unix-second timestamps, every field the
// daemon marks `#[serde(default)]` decoded with a fallback.

public enum DailyVerdict: String, TolerantEnum, Comparable {
    case ok, attention, critical, unknown
    public static let fallback: DailyVerdict = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }

    private var rank: Int {
        switch self {
        case .unknown: return 0
        case .ok: return 1
        case .attention: return 2
        case .critical: return 3
        }
    }

    public static func < (a: DailyVerdict, b: DailyVerdict) -> Bool { a.rank < b.rank }
}

public enum SummarySource: String, TolerantEnum {
    case template, localAi = "local_ai", unknown
    public static let fallback: SummarySource = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct DailyAlertLine: Codable, Sendable, Hashable, Identifiable {
    public let id: Int64
    public let ts: Int64
    public let severity: Severity
    public let kind: AlertKind
    public let title: String
}

public struct DailyFacts: Codable, Sendable, Hashable {
    public var periodStart: Int64 = 0
    public var periodEnd: Int64 = 0
    public var protectionNow: ProtectionState = .unknown
    public var issuesNow: [String] = []
    public var unseenCritical = 0
    public var unseenHigh = 0
    public var unseenOther = 0
    public var topUnseen: [DailyAlertLine] = []
    public var alertsYesterday = 0
    public var threatsYesterday = 0
    public var quarantinedYesterday = 0
    public var filesScannedYesterday = 0
    public var persistenceNewYesterday = 0
    public var devicesNewYesterday = 0
    public var dnsBlockedYesterday: Int?
    public var dbVersion: String?
    public var dbAgeHours: Int?
    public var lastFullScan: Int64?
    public var postureFailing: [String] = []
    public var quarantinedNow = 0

    public init() {}

    enum CodingKeys: String, CodingKey {
        case periodStart = "period_start"
        case periodEnd = "period_end"
        case protectionNow = "protection_now"
        case issuesNow = "issues_now"
        case unseenCritical = "unseen_critical"
        case unseenHigh = "unseen_high"
        case unseenOther = "unseen_other"
        case topUnseen = "top_unseen"
        case alertsYesterday = "alerts_yesterday"
        case threatsYesterday = "threats_yesterday"
        case quarantinedYesterday = "quarantined_yesterday"
        case filesScannedYesterday = "files_scanned_yesterday"
        case persistenceNewYesterday = "persistence_new_yesterday"
        case devicesNewYesterday = "devices_new_yesterday"
        case dnsBlockedYesterday = "dns_blocked_yesterday"
        case dbVersion = "db_version"
        case dbAgeHours = "db_age_hours"
        case lastFullScan = "last_full_scan"
        case postureFailing = "posture_failing"
        case quarantinedNow = "quarantined_now"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        periodStart = try c.decodeOr(.periodStart, 0)
        periodEnd = try c.decodeOr(.periodEnd, 0)
        protectionNow = try c.decodeOr(.protectionNow, .unknown)
        issuesNow = try c.decodeOr(.issuesNow, [])
        unseenCritical = try c.decodeOr(.unseenCritical, 0)
        unseenHigh = try c.decodeOr(.unseenHigh, 0)
        unseenOther = try c.decodeOr(.unseenOther, 0)
        topUnseen = try c.decodeOr(.topUnseen, [])
        alertsYesterday = try c.decodeOr(.alertsYesterday, 0)
        threatsYesterday = try c.decodeOr(.threatsYesterday, 0)
        quarantinedYesterday = try c.decodeOr(.quarantinedYesterday, 0)
        filesScannedYesterday = try c.decodeOr(.filesScannedYesterday, 0)
        persistenceNewYesterday = try c.decodeOr(.persistenceNewYesterday, 0)
        devicesNewYesterday = try c.decodeOr(.devicesNewYesterday, 0)
        dnsBlockedYesterday = try c.decodeIfPresent(Int.self, forKey: .dnsBlockedYesterday)
        dbVersion = try c.decodeIfPresent(String.self, forKey: .dbVersion)
        dbAgeHours = try c.decodeIfPresent(Int.self, forKey: .dbAgeHours)
        lastFullScan = try c.decodeIfPresent(Int64.self, forKey: .lastFullScan)
        postureFailing = try c.decodeOr(.postureFailing, [])
        quarantinedNow = try c.decodeOr(.quarantinedNow, 0)
    }

    public var unseenTotal: Int { unseenCritical + unseenHigh + unseenOther }
}

public struct DailyReport: Codable, Sendable, Hashable, Identifiable {
    /// Local date `YYYY-MM-DD`.
    public let date: String
    public let generatedAt: Int64
    public let verdict: DailyVerdict
    public let headline: String
    public let highlights: [String]
    public let summary: String
    public let summarySource: SummarySource
    public let summaryModel: String?
    public let facts: DailyFacts

    public var id: String { date }
    public var generatedDate: Date { Date(unixSeconds: generatedAt) }

    enum CodingKeys: String, CodingKey {
        case date
        case generatedAt = "generated_at"
        case verdict, headline, highlights, summary
        case summarySource = "summary_source"
        case summaryModel = "summary_model"
        case facts
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        date = try c.decode(String.self, forKey: .date)
        generatedAt = try c.decode(Int64.self, forKey: .generatedAt)
        verdict = try c.decodeOr(.verdict, .unknown)
        headline = try c.decodeOr(.headline, "")
        highlights = try c.decodeOr(.highlights, [])
        summary = try c.decodeOr(.summary, "")
        summarySource = try c.decodeOr(.summarySource, .template)
        summaryModel = try c.decodeIfPresent(String.self, forKey: .summaryModel)
        facts = try c.decodeOr(.facts, DailyFacts())
    }
}

public struct DailyReportSummary: Codable, Sendable, Hashable, Identifiable {
    public let date: String
    public let generatedAt: Int64
    public let verdict: DailyVerdict
    public let headline: String
    public let highlights: [String]

    public var id: String { date }

    enum CodingKeys: String, CodingKey {
        case date
        case generatedAt = "generated_at"
        case verdict, headline, highlights
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        date = try c.decode(String.self, forKey: .date)
        generatedAt = try c.decode(Int64.self, forKey: .generatedAt)
        verdict = try c.decodeOr(.verdict, .unknown)
        headline = try c.decodeOr(.headline, "")
        highlights = try c.decodeOr(.highlights, [])
    }
}
