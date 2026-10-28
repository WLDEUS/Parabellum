import Foundation

// Mirrors `crates/pb-core/src/model.rs` and the payload types of `crates/pb-core/src/ipc.rs`.
// Conventions: explicit snake_case `CodingKeys` (no key strategy), timestamps are Int64 Unix seconds,
// Rust `Option` → Swift optional (omitted when nil), `#[serde(default)]` collections → decoded as empty
// when missing, unknown enum strings → `fallback`.

// MARK: - Verdicts & detections

public enum Verdict: String, TolerantEnum, Comparable {
    case clean, suspicious, malicious, unknown
    public static let fallback: Verdict = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }

    public var rank: Int {
        switch self {
        case .unknown: return -1
        case .clean: return 0
        case .suspicious: return 1
        case .malicious: return 2
        }
    }

    public static func < (lhs: Verdict, rhs: Verdict) -> Bool { lhs.rank < rhs.rank }
}

public enum Severity: String, TolerantEnum, Comparable {
    case info, low, medium, high, critical, unknown
    public static let fallback: Severity = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }

    /// Known severities, lowest first (for pickers).
    public static let known: [Severity] = [.info, .low, .medium, .high, .critical]

    public var rank: Int {
        switch self {
        case .unknown: return -1
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (lhs: Severity, rhs: Severity) -> Bool { lhs.rank < rhs.rank }
}

public enum DetectionEngine: String, TolerantEnum {
    case hashDb = "hash_db"
    case clamav
    case yara
    case ml
    case heuristic
    case virusTotal = "virus_total"
    case unknown
    public static let fallback: DetectionEngine = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct Detection: Codable, Sendable, Hashable {
    public let engine: DetectionEngine
    /// Signature / rule / family name, e.g. `MacOS.Stealer.AMOS`.
    public let name: String
    public let severity: Severity
    /// 0.0 – 1.0
    public let confidence: Double
    public let details: String?

    enum CodingKeys: String, CodingKey {
        case engine, name, severity, confidence, details
    }
}

public enum FileKind: String, TolerantEnum {
    case macho
    case fatMacho = "fat_macho"
    case dmg, pkg, zip, script
    case appBundle = "app_bundle"
    case document, archive, other
    public static let fallback: FileKind = .other
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct SigningInfo: Codable, Sendable, Hashable {
    public let signed: Bool
    /// Signature verifies (not tampered).
    public let valid: Bool
    public let adhoc: Bool
    public let teamId: String?
    public let identifier: String?
    /// Leaf authority, e.g. `Developer ID Application: Foo (TEAMID)`.
    public let authority: String?
    public let notarized: Bool?
    public let apple: Bool

    enum CodingKeys: String, CodingKey {
        case signed, valid, adhoc
        case teamId = "team_id"
        case identifier, authority, notarized, apple
    }
}

public struct ScanReport: Codable, Sendable, Hashable, Identifiable {
    /// For archive / DMG / PKG members: `<container path>!/<inner path>`.
    public let path: String
    public let sha256: String?
    public let size: Int
    public let kind: FileKind
    public let verdict: Verdict
    /// Combined score 0.0 – 1.0.
    public let score: Double
    public let detections: [Detection]
    public let signing: SigningInfo?
    public let error: String?
    public let durationMs: Int
    public let cached: Bool

    public var id: String { path }

    /// The file on disk that holds this report (the container for archive members).
    public var containerPath: String {
        if let range = path.range(of: "!/") {
            return String(path[path.startIndex..<range.lowerBound])
        }
        return path
    }

    enum CodingKeys: String, CodingKey {
        case path, sha256, size, kind, verdict, score, detections, signing, error
        case durationMs = "duration_ms"
        case cached
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = try c.decode(String.self, forKey: .path)
        sha256 = try c.decodeIfPresent(String.self, forKey: .sha256)
        size = try c.decode(Int.self, forKey: .size)
        kind = try c.decode(FileKind.self, forKey: .kind)
        verdict = try c.decode(Verdict.self, forKey: .verdict)
        score = try c.decode(Double.self, forKey: .score)
        detections = try c.decodeOr(.detections, [Detection]())
        signing = try c.decodeIfPresent(SigningInfo.self, forKey: .signing)
        error = try c.decodeIfPresent(String.self, forKey: .error)
        durationMs = try c.decode(Int.self, forKey: .durationMs)
        cached = try c.decodeOr(.cached, false)
    }
}

// MARK: - Scan jobs

public enum ScanOrigin: String, TolerantEnum {
    case manual, downloads, volume, realtime, scheduled
    case retroHunt = "retro_hunt"
    case unknown
    public static let fallback: ScanOrigin = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum JobState: String, TolerantEnum {
    case queued, running, finished, cancelled, failed, unknown
    public static let fallback: JobState = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }

    /// Queued or running.
    public var isActive: Bool { self == .queued || self == .running }
}

public struct ScanJobSummary: Codable, Sendable, Hashable, Identifiable {
    public let jobId: String
    public let origin: ScanOrigin
    public let paths: [String]
    public let state: JobState
    public let startedAt: Int64
    public let finishedAt: Int64?
    public let filesScanned: Int
    public let bytesScanned: Int
    /// Files with verdict != clean.
    public let threats: Int
    public let errors: Int
    public let currentPath: String?

    public var id: String { jobId }
    public var startedDate: Date { Date(unixSeconds: startedAt) }
    public var finishedDate: Date? { finishedAt.map(Date.init(unixSeconds:)) }

    enum CodingKeys: String, CodingKey {
        case jobId = "job_id"
        case origin, paths, state
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case filesScanned = "files_scanned"
        case bytesScanned = "bytes_scanned"
        case threats, errors
        case currentPath = "current_path"
    }
}

public struct ScanJobDetail: Codable, Sendable, Hashable {
    public let summary: ScanJobSummary
    /// Non-clean reports and reports with errors only.
    public let findings: [ScanReport]

    enum CodingKeys: String, CodingKey {
        case summary, findings
    }
}

// MARK: - Quarantine

public struct QuarantineEntry: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let originalPath: String
    public let sha256: String
    public let size: Int
    public let detections: [Detection]
    public let quarantinedAt: Int64
    public let ownerUid: Int
    public let ownerGid: Int
    /// Original permission bits.
    public let mode: Int
    /// "auto", "user", "persistence"…
    public let reason: String

    public var quarantinedDate: Date { Date(unixSeconds: quarantinedAt) }
    public var fileName: String { (originalPath as NSString).lastPathComponent }

    enum CodingKeys: String, CodingKey {
        case id
        case originalPath = "original_path"
        case sha256, size, detections
        case quarantinedAt = "quarantined_at"
        case ownerUid = "owner_uid"
        case ownerGid = "owner_gid"
        case mode, reason
    }
}

/// `restore` response: `{"restored_path": "…"}`.
public struct RestoredPath: Codable, Sendable, Hashable {
    public let restoredPath: String

    enum CodingKeys: String, CodingKey {
        case restoredPath = "restored_path"
    }
}

// MARK: - Alerts

public enum AlertKind: String, TolerantEnum {
    case malware, suspicious, persistence, device, network, update, system, unknown
    public static let fallback: AlertKind = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum AlertStatus: String, TolerantEnum {
    case open, acknowledged, resolved, unknown
    public static let fallback: AlertStatus = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum AlertAction: String, TolerantEnum {
    case acknowledge, quarantine, allow, restore
    case trustDevice = "trust_device"
    case blockDevice = "block_device"
    case approvePersistence = "approve_persistence"
    case removePersistence = "remove_persistence"
    case reportFalsePositive = "report_false_positive"
    case dismiss
    case unknown
    public static let fallback: AlertAction = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct SecurityAlert: Codable, Sendable, Hashable, Identifiable {
    /// SQLite row id.
    public let id: Int64
    public let ts: Int64
    public let kind: AlertKind
    public let severity: Severity
    public let title: String
    public let message: String
    public let path: String?
    public let sha256: String?
    public let deviceId: String?
    public let persistenceId: String?
    public let quarantineId: String?
    public let status: AlertStatus
    /// Actions the UI should offer for this alert.
    public let actions: [AlertAction]

    public var date: Date { Date(unixSeconds: ts) }
    /// Actions this build knows how to send back.
    public var knownActions: [AlertAction] { actions.filter { $0 != .unknown } }

    enum CodingKeys: String, CodingKey {
        case id, ts, kind, severity, title, message, path, sha256
        case deviceId = "device_id"
        case persistenceId = "persistence_id"
        case quarantineId = "quarantine_id"
        case status, actions
    }
}

// MARK: - Devices

public enum DeviceKind: String, TolerantEnum {
    case volume, hid, usb, bluetooth
    case networkInterface = "network_interface"
    case thunderbolt
    case wifiNetwork = "wifi_network"
    case unknown
    public static let fallback: DeviceKind = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum DeviceTrust: String, TolerantEnum {
    case unknown, trusted, blocked
    public static let fallback: DeviceTrust = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct DeviceInfo: Codable, Sendable, Hashable, Identifiable {
    /// Stable identifier, e.g. `hid:05ac:0281:<serial-or-location>`, `vol:<uuid>`.
    public let id: String
    public let kind: DeviceKind
    public let name: String
    public let vendor: String?
    public let vendorId: Int?
    public let productId: Int?
    public let serial: String?
    /// "USB", "SPI", "Bluetooth", "Thunderbolt"…
    public let transport: String?
    /// Free-form extra properties (mount point, filesystem, BSD name, MAC…).
    public let details: [String: String]
    public let firstSeen: Int64
    public let lastSeen: Int64
    public let connected: Bool
    public let trust: DeviceTrust
    /// Present when Parabellum first ran (never alerted on).
    public let baseline: Bool

    public var firstSeenDate: Date { Date(unixSeconds: firstSeen) }
    public var lastSeenDate: Date { Date(unixSeconds: lastSeen) }

    /// HID device that reports a keyboard interface (or HID without the detail: assume keyboard).
    public var isProbableKeyboard: Bool {
        guard kind == .hid else { return false }
        if let flag = details["is_keyboard"] {
            return flag.lowercased() == "true"
        }
        return true
    }

    /// `0x05ac:0x024f` style identifier when known.
    public var usbIdentifier: String? {
        guard let vendorId, let productId else { return nil }
        return "0x\(Self.hex4(vendorId)):0x\(Self.hex4(productId))"
    }

    private static func hex4(_ value: Int) -> String {
        let digits = String(value, radix: 16)
        return digits.count >= 4 ? digits : String(repeating: "0", count: 4 - digits.count) + digits
    }

    enum CodingKeys: String, CodingKey {
        case id, kind, name, vendor
        case vendorId = "vendor_id"
        case productId = "product_id"
        case serial, transport, details
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
        case connected, trust, baseline
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        kind = try c.decode(DeviceKind.self, forKey: .kind)
        name = try c.decode(String.self, forKey: .name)
        vendor = try c.decodeIfPresent(String.self, forKey: .vendor)
        vendorId = try c.decodeIfPresent(Int.self, forKey: .vendorId)
        productId = try c.decodeIfPresent(Int.self, forKey: .productId)
        serial = try c.decodeIfPresent(String.self, forKey: .serial)
        transport = try c.decodeIfPresent(String.self, forKey: .transport)
        details = try c.decodeOr(.details, [String: String]())
        firstSeen = try c.decode(Int64.self, forKey: .firstSeen)
        lastSeen = try c.decode(Int64.self, forKey: .lastSeen)
        connected = try c.decode(Bool.self, forKey: .connected)
        trust = try c.decode(DeviceTrust.self, forKey: .trust)
        baseline = try c.decode(Bool.self, forKey: .baseline)
    }
}

public enum DeviceChange: String, TolerantEnum {
    case new, connected, disconnected, unknown
    public static let fallback: DeviceChange = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct DeviceEvent: Codable, Sendable, Hashable {
    public let device: DeviceInfo
    public let change: DeviceChange

    enum CodingKeys: String, CodingKey {
        case device, change
    }
}

// MARK: - Persistence

public enum PersistenceKind: String, TolerantEnum {
    case launchAgent = "launch_agent"
    case launchDaemon = "launch_daemon"
    case loginItem = "login_item"
    case backgroundItem = "background_item"
    case cron, periodic
    case shellProfile = "shell_profile"
    case configurationProfile = "configuration_profile"
    case browserExtension = "browser_extension"
    case systemExtension = "system_extension"
    case kernelExtension = "kernel_extension"
    case authorizationPlugin = "authorization_plugin"
    case other
    public static let fallback: PersistenceKind = .other
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum PersistenceStatus: String, TolerantEnum {
    case baseline, new, approved, removed, quarantined, unknown
    public static let fallback: PersistenceStatus = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct PersistenceItem: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let kind: PersistenceKind
    public let label: String?
    /// Plist / config / profile path that creates the persistence.
    public let path: String
    /// Program that will be executed, when known.
    public let program: String?
    public let arguments: [String]
    public let user: String?
    public let signing: SigningInfo?
    public let programSha256: String?
    public let firstSeen: Int64
    public let lastSeen: Int64
    public let status: PersistenceStatus
    public let verdict: Verdict?

    public var firstSeenDate: Date { Date(unixSeconds: firstSeen) }

    enum CodingKeys: String, CodingKey {
        case id, kind, label, path, program, arguments, user, signing
        case programSha256 = "program_sha256"
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
        case status, verdict
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        kind = try c.decode(PersistenceKind.self, forKey: .kind)
        label = try c.decodeIfPresent(String.self, forKey: .label)
        path = try c.decode(String.self, forKey: .path)
        program = try c.decodeIfPresent(String.self, forKey: .program)
        arguments = try c.decodeOr(.arguments, [String]())
        user = try c.decodeIfPresent(String.self, forKey: .user)
        signing = try c.decodeIfPresent(SigningInfo.self, forKey: .signing)
        programSha256 = try c.decodeIfPresent(String.self, forKey: .programSha256)
        firstSeen = try c.decode(Int64.self, forKey: .firstSeen)
        lastSeen = try c.decode(Int64.self, forKey: .lastSeen)
        status = try c.decode(PersistenceStatus.self, forKey: .status)
        verdict = try c.decodeIfPresent(Verdict.self, forKey: .verdict)
    }
}

// MARK: - Components & DB

public enum ComponentState: String, TolerantEnum {
    case notInstalled = "not_installed"
    case installed
    case updateAvailable = "update_available"
    case updating, error, disabled
    case needsUserAction = "needs_user_action"
    case unknown
    public static let fallback: ComponentState = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct ComponentStatus: Codable, Sendable, Hashable, Identifiable {
    /// Machine name: `clamav`, `osquery`, `dnscrypt-proxy`, `lulu`, `blockblock`, `ublock-chrome`…
    public let name: String
    public let displayName: String
    public let installedVersion: String?
    public let latestVersion: String?
    public let state: ComponentState
    public let lastCheck: Int64?
    public let autoUpdate: Bool
    /// Required for full protection.
    public let required: Bool
    public let message: String?
    /// Where the user can act (store page, System Settings deep link, release page).
    public let actionUrl: String?

    public var id: String { name }
    /// Browser extensions cannot be installed by the daemon: the user must go through the store.
    public var isBrowserExtension: Bool { name.hasPrefix("ublock") }

    enum CodingKeys: String, CodingKey {
        case name
        case displayName = "display_name"
        case installedVersion = "installed_version"
        case latestVersion = "latest_version"
        case state
        case lastCheck = "last_check"
        case autoUpdate = "auto_update"
        case required, message
        case actionUrl = "action_url"
    }
}

public struct DbStatus: Codable, Sendable, Hashable {
    public let version: String?
    public let builtAt: Int64?
    public let previousVersion: String?
    public let lastCheck: Int64?
    public let lastSuccess: Int64?
    public let lastError: String?
    public let malwareHashes: Int
    public let yaraRules: Int
    public let blockedDomains: Int
    public let clamavVersion: String?
    public let mlModelVersion: String?

    public var builtDate: Date? { builtAt.map(Date.init(unixSeconds:)) }
    public var lastSuccessDate: Date? { lastSuccess.map(Date.init(unixSeconds:)) }

    enum CodingKeys: String, CodingKey {
        case version
        case builtAt = "built_at"
        case previousVersion = "previous_version"
        case lastCheck = "last_check"
        case lastSuccess = "last_success"
        case lastError = "last_error"
        case malwareHashes = "malware_hashes"
        case yaraRules = "yara_rules"
        case blockedDomains = "blocked_domains"
        case clamavVersion = "clamav_version"
        case mlModelVersion = "ml_model_version"
    }
}

public enum UpdateTarget: String, TolerantEnum {
    case db, components, app, all, unknown
    public static let fallback: UpdateTarget = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct UpdateResult: Codable, Sendable, Hashable {
    public let target: UpdateTarget
    public let ok: Bool
    public let startedAt: Int64
    public let finishedAt: Int64
    /// Human-readable lines (one per component / step).
    public let messages: [String]
    public let newDbVersion: String?

    public var finishedDate: Date { Date(unixSeconds: finishedAt) }

    enum CodingKeys: String, CodingKey {
        case target, ok
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case messages
        case newDbVersion = "new_db_version"
    }
}

// MARK: - DNS & ad blocking

public struct DnsStatus: Codable, Sendable, Hashable {
    public let enabled: Bool
    /// dnscrypt-proxy process alive and answering.
    public let running: Bool
    public let listen: String
    public let blockedDomains: Int
    public let listVersion: String?
    public let queriesBlocked24h: Int?
    /// Network services whose DNS servers were changed (restored when disabled).
    public let managedServices: [String]
    public let message: String?

    enum CodingKeys: String, CodingKey {
        case enabled, running, listen
        case blockedDomains = "blocked_domains"
        case listVersion = "list_version"
        case queriesBlocked24h = "queries_blocked_24h"
        case managedServices = "managed_services"
        case message
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decode(Bool.self, forKey: .enabled)
        running = try c.decode(Bool.self, forKey: .running)
        listen = try c.decode(String.self, forKey: .listen)
        blockedDomains = try c.decode(Int.self, forKey: .blockedDomains)
        listVersion = try c.decodeIfPresent(String.self, forKey: .listVersion)
        queriesBlocked24h = try c.decodeIfPresent(Int.self, forKey: .queriesBlocked24h)
        managedServices = try c.decodeOr(.managedServices, [String]())
        message = try c.decodeIfPresent(String.self, forKey: .message)
    }
}

public enum ExtensionState: String, TolerantEnum {
    case notInstalled = "not_installed"
    case installedDisabled = "installed_disabled"
    case enabled
    case unknown
    public static let fallback: ExtensionState = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct AdblockStatus: Codable, Sendable, Hashable {
    public let chromeUblock: ExtensionState
    public let safariUblock: ExtensionState
    public let dns: DnsStatus
    public let chromeStoreUrl: String
    public let safariStoreUrl: String

    enum CodingKeys: String, CodingKey {
        case chromeUblock = "chrome_ublock"
        case safariUblock = "safari_ublock"
        case dns
        case chromeStoreUrl = "chrome_store_url"
        case safariStoreUrl = "safari_store_url"
    }
}

// MARK: - Daemon status & reports

public enum ProtectionState: String, TolerantEnum {
    case active, paused, degraded, unknown
    public static let fallback: ProtectionState = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct RealtimeStatus: Codable, Sendable, Hashable {
    public let fsevents: Bool
    public let eslogger: Bool
    public let fullDiskAccess: Bool
    public let persistenceMonitor: Bool
    public let deviceMonitor: Bool

    enum CodingKeys: String, CodingKey {
        case fsevents, eslogger
        case fullDiskAccess = "full_disk_access"
        case persistenceMonitor = "persistence_monitor"
        case deviceMonitor = "device_monitor"
    }
}

public struct StatusInfo: Codable, Sendable, Hashable {
    public let version: String
    public let protection: ProtectionState
    public let pausedUntil: Int64?
    /// Why protection is degraded (empty when active).
    public let issues: [String]
    public let realtime: RealtimeStatus
    public let db: DbStatus
    public let openAlerts: Int
    public let quarantined: Int
    public let lastScan: Int64?
    public let dnsEnabled: Bool
    public let onBattery: Bool
    public let componentsNeedingAttention: Int
    public let mlEnabled: Bool
    public let uptimeSecs: Int
    /// Resident memory of the daemon, bytes.
    public let rssBytes: Int

    public var pausedUntilDate: Date? { pausedUntil.map(Date.init(unixSeconds:)) }
    public var lastScanDate: Date? { lastScan.map(Date.init(unixSeconds:)) }

    enum CodingKeys: String, CodingKey {
        case version, protection
        case pausedUntil = "paused_until"
        case issues, realtime, db
        case openAlerts = "open_alerts"
        case quarantined
        case lastScan = "last_scan"
        case dnsEnabled = "dns_enabled"
        case onBattery = "on_battery"
        case componentsNeedingAttention = "components_needing_attention"
        case mlEnabled = "ml_enabled"
        case uptimeSecs = "uptime_secs"
        case rssBytes = "rss_bytes"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        version = try c.decode(String.self, forKey: .version)
        protection = try c.decode(ProtectionState.self, forKey: .protection)
        pausedUntil = try c.decodeIfPresent(Int64.self, forKey: .pausedUntil)
        issues = try c.decodeOr(.issues, [String]())
        realtime = try c.decode(RealtimeStatus.self, forKey: .realtime)
        db = try c.decode(DbStatus.self, forKey: .db)
        openAlerts = try c.decode(Int.self, forKey: .openAlerts)
        quarantined = try c.decode(Int.self, forKey: .quarantined)
        lastScan = try c.decodeIfPresent(Int64.self, forKey: .lastScan)
        dnsEnabled = try c.decode(Bool.self, forKey: .dnsEnabled)
        onBattery = try c.decode(Bool.self, forKey: .onBattery)
        componentsNeedingAttention = try c.decode(Int.self, forKey: .componentsNeedingAttention)
        mlEnabled = try c.decode(Bool.self, forKey: .mlEnabled)
        uptimeSecs = try c.decode(Int.self, forKey: .uptimeSecs)
        rssBytes = try c.decode(Int.self, forKey: .rssBytes)
    }
}

public struct NamedCount: Codable, Sendable, Hashable, Identifiable {
    public let name: String
    public let count: Int

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, count
    }
}

public struct WeeklyReport: Codable, Sendable, Hashable {
    public let weekStart: Int64
    public let weekEnd: Int64
    public let filesScanned: Int
    public let threatsDetected: Int
    public let quarantined: Int
    public let falsePositivesReported: Int
    public let persistenceNew: Int
    public let devicesNew: Int
    public let dbUpdates: Int
    public let dbVersion: String?
    public let componentUpdates: [String]
    public let topDetections: [NamedCount]
    public let dnsBlockedQueries: Int?

    public var weekStartDate: Date { Date(unixSeconds: weekStart) }
    public var weekEndDate: Date { Date(unixSeconds: weekEnd) }

    enum CodingKeys: String, CodingKey {
        case weekStart = "week_start"
        case weekEnd = "week_end"
        case filesScanned = "files_scanned"
        case threatsDetected = "threats_detected"
        case quarantined
        case falsePositivesReported = "false_positives_reported"
        case persistenceNew = "persistence_new"
        case devicesNew = "devices_new"
        case dbUpdates = "db_updates"
        case dbVersion = "db_version"
        case componentUpdates = "component_updates"
        case topDetections = "top_detections"
        case dnsBlockedQueries = "dns_blocked_queries"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        weekStart = try c.decode(Int64.self, forKey: .weekStart)
        weekEnd = try c.decode(Int64.self, forKey: .weekEnd)
        filesScanned = try c.decode(Int.self, forKey: .filesScanned)
        threatsDetected = try c.decode(Int.self, forKey: .threatsDetected)
        quarantined = try c.decode(Int.self, forKey: .quarantined)
        falsePositivesReported = try c.decode(Int.self, forKey: .falsePositivesReported)
        persistenceNew = try c.decode(Int.self, forKey: .persistenceNew)
        devicesNew = try c.decode(Int.self, forKey: .devicesNew)
        dbUpdates = try c.decode(Int.self, forKey: .dbUpdates)
        dbVersion = try c.decodeIfPresent(String.self, forKey: .dbVersion)
        componentUpdates = try c.decodeOr(.componentUpdates, [String]())
        topDetections = try c.decodeOr(.topDetections, [NamedCount]())
        dnsBlockedQueries = try c.decodeIfPresent(Int.self, forKey: .dnsBlockedQueries)
    }
}

// MARK: - IPC payloads

public struct PingResponse: Codable, Sendable, Hashable {
    public let version: String
    /// Rust field `protocol` (a Swift keyword).
    public let protocolVersion: Int

    enum CodingKeys: String, CodingKey {
        case version
        case protocolVersion = "protocol"
    }
}

public struct JobStarted: Codable, Sendable, Hashable {
    public let jobId: String

    enum CodingKeys: String, CodingKey {
        case jobId = "job_id"
    }
}

public enum ErrorCode: String, TolerantEnum {
    case badRequest = "bad_request"
    case notFound = "not_found"
    case permissionDenied = "permission_denied"
    /// Needs administrator approval: retry with `auth` (see `Request.requiresAdmin`).
    case authRequired = "auth_required"
    case busy, unavailable
    case internalError = "internal"
    case unknown
    public static let fallback: ErrorCode = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct IpcError: Codable, Sendable, Hashable, Error, LocalizedError {
    public let code: ErrorCode
    public let message: String

    public init(code: ErrorCode, message: String) {
        self.code = code
        self.message = message
    }

    public var errorDescription: String? { message }

    enum CodingKeys: String, CodingKey {
        case code, message
    }
}

// MARK: - Dates

extension Date {
    /// Date from a Rust `i64` Unix timestamp (seconds).
    public init(unixSeconds: Int64) {
        self.init(timeIntervalSince1970: TimeInterval(unixSeconds))
    }

    public var unixSeconds: Int64 { Int64(timeIntervalSince1970.rounded(.down)) }
}
