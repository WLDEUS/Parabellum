import Foundation

// Mirrors the intelligence part of `crates/pb-core/src/model.rs` and `config.rs` (`[intelligence]`):
// domain model (phishing / malicious domains seen through the local DNS) and behavioural baseline.

/// `[intelligence]`.
public struct IntelligenceConfig: Codable, Sendable, Hashable {
    /// Score every never-seen domain (needs DNS blocking).
    public var domainModel: Bool = true
    public var domainAlerts: Bool = true
    /// Opt-in: block high-confidence model verdicts in the DNS.
    public var blockMlDomains: Bool = false
    /// Domains the model never flags or blocks.
    public var domainAllowlist: [String] = []
    public var behaviorAnomaly: Bool = true
    public var learningDays: Int = 7
    public var anomalyThreshold: Double = 0.75
    public var maxAnomalyAlertsPerDay: Int = 10

    public init() {}

    enum CodingKeys: String, CodingKey {
        case domainModel = "domain_model"
        case domainAlerts = "domain_alerts"
        case blockMlDomains = "block_ml_domains"
        case domainAllowlist = "domain_allowlist"
        case behaviorAnomaly = "behavior_anomaly"
        case learningDays = "learning_days"
        case anomalyThreshold = "anomaly_threshold"
        case maxAnomalyAlertsPerDay = "max_anomaly_alerts_per_day"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        domainModel = try c.decodeOr(.domainModel, domainModel)
        domainAlerts = try c.decodeOr(.domainAlerts, domainAlerts)
        blockMlDomains = try c.decodeOr(.blockMlDomains, blockMlDomains)
        domainAllowlist = try c.decodeOr(.domainAllowlist, domainAllowlist)
        behaviorAnomaly = try c.decodeOr(.behaviorAnomaly, behaviorAnomaly)
        learningDays = try c.decodeOr(.learningDays, learningDays)
        anomalyThreshold = try c.decodeOr(.anomalyThreshold, anomalyThreshold)
        maxAnomalyAlertsPerDay = try c.decodeOr(.maxAnomalyAlertsPerDay, maxAnomalyAlertsPerDay)
    }

    /// Same rules as the intelligence part of `Config::validate`.
    public func validationErrors() -> [String] {
        var errors: [String] = []
        if !(1...60).contains(learningDays) {
            errors.append("La période d'apprentissage doit être comprise entre 1 et 60 jours.")
        }
        if !(0.5...0.99).contains(anomalyThreshold) {
            errors.append("Le seuil d'anomalie doit être compris entre 0,5 et 0,99.")
        }
        if !(1...100).contains(maxAnomalyAlertsPerDay) {
            errors.append("Le nombre d'alertes d'anomalie par jour doit être compris entre 1 et 100.")
        }
        if domainAllowlist.count > 1000 {
            errors.append("La liste des domaines autorisés est limitée à 1000 entrées.")
        }
        for d in domainAllowlist where !d.contains(".") || !ConfigSyntax.isHostOrIp(d) || d != d.lowercased() {
            errors.append("Domaine autorisé invalide : \(d)")
        }
        return errors
    }
}

/// What a behaviour anomaly is about.
public enum AnomalyKind: String, TolerantEnum {
    case exec, interpreter
    case launchedBy = "launched_by"
    case file, hour
    case unknown
    public static let fallback: AnomalyKind = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct BehaviorAnomaly: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let ts: Int64
    public let process: String
    public let kind: AnomalyKind
    public let summary: String
    public let details: [String]
    public let score: Double
    public let alertId: Int64?
    public let markedNormal: Bool

    public var date: Date { Date(unixSeconds: ts) }

    enum CodingKeys: String, CodingKey {
        case id, ts, process, kind, summary, details, score
        case alertId = "alert_id"
        case markedNormal = "marked_normal"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        ts = try c.decode(Int64.self, forKey: .ts)
        process = try c.decode(String.self, forKey: .process)
        kind = try c.decodeOr(.kind, AnomalyKind.unknown)
        summary = try c.decodeOr(.summary, "")
        details = try c.decodeOr(.details, [String]())
        score = try c.decodeOr(.score, 0)
        alertId = try c.decodeIfPresent(Int64.self, forKey: .alertId)
        markedNormal = try c.decodeOr(.markedNormal, false)
    }
}

public struct BehaviorStatus: Codable, Sendable, Hashable {
    public let enabled: Bool
    public let learning: Bool
    /// 0…1
    public let learningProgress: Double
    public let learningStartedAt: Int64?
    public let learningUntil: Int64?
    public let eventsObserved: Int64
    public let profiles: Int
    public let behaviors: Int
    public let anomalies24h: Int
    public let anomalies7d: Int
    public let baselineBytes: Int64
    public let recentAnomalies: [BehaviorAnomaly]
    public let message: String?

    public var learningUntilDate: Date? { learningUntil.map(Date.init(unixSeconds:)) }

    enum CodingKeys: String, CodingKey {
        case enabled, learning, profiles, behaviors, message
        case learningProgress = "learning_progress"
        case learningStartedAt = "learning_started_at"
        case learningUntil = "learning_until"
        case eventsObserved = "events_observed"
        case anomalies24h = "anomalies_24h"
        case anomalies7d = "anomalies_7d"
        case baselineBytes = "baseline_bytes"
        case recentAnomalies = "recent_anomalies"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, false)
        learning = try c.decodeOr(.learning, false)
        learningProgress = try c.decodeOr(.learningProgress, 0)
        learningStartedAt = try c.decodeIfPresent(Int64.self, forKey: .learningStartedAt)
        learningUntil = try c.decodeIfPresent(Int64.self, forKey: .learningUntil)
        eventsObserved = try c.decodeOr(.eventsObserved, 0)
        profiles = try c.decodeOr(.profiles, 0)
        behaviors = try c.decodeOr(.behaviors, 0)
        anomalies24h = try c.decodeOr(.anomalies24h, 0)
        anomalies7d = try c.decodeOr(.anomalies7d, 0)
        baselineBytes = try c.decodeOr(.baselineBytes, 0)
        recentAnomalies = try c.decodeOr(.recentAnomalies, [BehaviorAnomaly]())
        message = try c.decodeIfPresent(String.self, forKey: .message)
    }
}

public struct FlaggedDomain: Codable, Sendable, Hashable, Identifiable {
    public let domain: String
    public let registrable: String
    public let score: Double
    public let firstSeen: Int64
    public let lastSeen: Int64
    public let hits: Int
    public let reasons: [String]
    public let blocked: Bool
    public let allowed: Bool
    public let alertId: Int64?

    public var id: String { domain }
    public var lastSeenDate: Date { Date(unixSeconds: lastSeen) }

    enum CodingKeys: String, CodingKey {
        case domain, registrable, score, hits, reasons, blocked, allowed
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
        case alertId = "alert_id"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        domain = try c.decode(String.self, forKey: .domain)
        registrable = try c.decodeOr(.registrable, domain)
        score = try c.decodeOr(.score, 0)
        firstSeen = try c.decodeOr(.firstSeen, 0)
        lastSeen = try c.decodeOr(.lastSeen, 0)
        hits = try c.decodeOr(.hits, 0)
        reasons = try c.decodeOr(.reasons, [String]())
        blocked = try c.decodeOr(.blocked, false)
        allowed = try c.decodeOr(.allowed, false)
        alertId = try c.decodeIfPresent(Int64.self, forKey: .alertId)
    }
}

public struct DomainIntelStatus: Codable, Sendable, Hashable {
    public let enabled: Bool
    public let dnsActive: Bool
    public let modelLoaded: Bool
    public let blockEnabled: Bool
    public let alertThreshold: Double
    public let blockThreshold: Double
    public let scoredTotal: Int64
    public let scored24h: Int64
    public let flaggedTotal: Int64
    public let blockedCount: Int
    public let topFlagged: [FlaggedDomain]
    public let message: String?

    enum CodingKeys: String, CodingKey {
        case enabled, message
        case dnsActive = "dns_active"
        case modelLoaded = "model_loaded"
        case blockEnabled = "block_enabled"
        case alertThreshold = "alert_threshold"
        case blockThreshold = "block_threshold"
        case scoredTotal = "scored_total"
        case scored24h = "scored_24h"
        case flaggedTotal = "flagged_total"
        case blockedCount = "blocked_count"
        case topFlagged = "top_flagged"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, false)
        dnsActive = try c.decodeOr(.dnsActive, false)
        modelLoaded = try c.decodeOr(.modelLoaded, false)
        blockEnabled = try c.decodeOr(.blockEnabled, false)
        alertThreshold = try c.decodeOr(.alertThreshold, 0)
        blockThreshold = try c.decodeOr(.blockThreshold, 0)
        scoredTotal = try c.decodeOr(.scoredTotal, 0)
        scored24h = try c.decodeOr(.scored24h, 0)
        flaggedTotal = try c.decodeOr(.flaggedTotal, 0)
        blockedCount = try c.decodeOr(.blockedCount, 0)
        topFlagged = try c.decodeOr(.topFlagged, [FlaggedDomain]())
        message = try c.decodeIfPresent(String.self, forKey: .message)
    }
}

/// A predictive model and its evaluation (domain, behaviour; Mach-O / script models are merged in by the
/// app from their own status).
public struct IntelModelInfo: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let name: String
    public let loaded: Bool
    public let version: String?
    public let threshold: Double?
    public let metrics: [String: Double]
    public let detail: String?

    public init(
        id: String, name: String, loaded: Bool, version: String? = nil, threshold: Double? = nil,
        metrics: [String: Double] = [:], detail: String? = nil
    ) {
        self.id = id
        self.name = name
        self.loaded = loaded
        self.version = version
        self.threshold = threshold
        self.metrics = metrics
        self.detail = detail
    }

    enum CodingKeys: String, CodingKey {
        case id, name, loaded, version, threshold, metrics, detail
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decodeOr(.name, id)
        loaded = try c.decodeOr(.loaded, false)
        version = try c.decodeIfPresent(String.self, forKey: .version)
        threshold = try c.decodeIfPresent(Double.self, forKey: .threshold)
        metrics = try c.decodeOr(.metrics, [String: Double]())
        detail = try c.decodeIfPresent(String.self, forKey: .detail)
    }
}

public struct IntelligenceStatus: Codable, Sendable, Hashable {
    public let behavior: BehaviorStatus
    public let domains: DomainIntelStatus
    public let models: [IntelModelInfo]

    enum CodingKeys: String, CodingKey {
        case behavior, domains, models
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        behavior = try c.decode(BehaviorStatus.self, forKey: .behavior)
        domains = try c.decode(DomainIntelStatus.self, forKey: .domains)
        models = try c.decodeOr(.models, [IntelModelInfo]())
    }
}

/// `intel_score_domain` response.
public struct DomainVerdictInfo: Codable, Sendable, Hashable {
    public let domain: String
    public let registrable: String?
    public let score: Double?
    public let flagged: Bool
    public let wouldBlock: Bool
    /// `model` or `heuristic`.
    public let source: String?
    public let skipped: String?
    public let reasons: [String]
    public let allowed: Bool

    enum CodingKeys: String, CodingKey {
        case domain, registrable, score, flagged, source, skipped, reasons, allowed
        case wouldBlock = "would_block"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        domain = try c.decode(String.self, forKey: .domain)
        registrable = try c.decodeIfPresent(String.self, forKey: .registrable)
        score = try c.decodeIfPresent(Double.self, forKey: .score)
        flagged = try c.decodeOr(.flagged, false)
        wouldBlock = try c.decodeOr(.wouldBlock, false)
        source = try c.decodeIfPresent(String.self, forKey: .source)
        skipped = try c.decodeIfPresent(String.self, forKey: .skipped)
        reasons = try c.decodeOr(.reasons, [String]())
        allowed = try c.decodeOr(.allowed, false)
    }
}

extension AnomalyKind {
    public var label: String {
        switch self {
        case .exec: return "Nouveau programme lancé"
        case .interpreter: return "Interpréteur inhabituel"
        case .launchedBy: return "Parent inhabituel"
        case .file: return "Nouvel emplacement modifié"
        case .hour: return "Heure inhabituelle"
        case .unknown: return "Anomalie"
        }
    }

    public var systemImage: String {
        switch self {
        case .exec: return "app.badge"
        case .interpreter: return "terminal"
        case .launchedBy: return "arrow.triangle.branch"
        case .file: return "doc.badge.gearshape"
        case .hour: return "clock.badge.exclamationmark"
        case .unknown: return "questionmark.circle"
        }
    }
}
