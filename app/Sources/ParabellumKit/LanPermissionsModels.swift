import Foundation

// Mirrors the LAN inventory and permissions audit types of `crates/pb-core/src/model.rs`.
// Same conventions as Models.swift: snake_case keys, Unix-second timestamps, optionals omitted when nil,
// `#[serde(default)]` fields decoded with their default when missing, unknown enum strings → fallback.

// MARK: - Local network

public enum LanDeviceType: String, TolerantEnum {
    case router, computer, phone, tablet, tv, speaker, printer, camera, nas, console, iot
    case unknown
    public static let fallback: LanDeviceType = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum LanScanMode: String, TolerantEnum {
    /// System caches only (ARP / NDP), no packet sent.
    case passive
    /// Light sweep of the /24, IPv6 all-nodes ping, Bonjour.
    case active
    case unknown
    public static let fallback: LanScanMode = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

/// A device seen on a local network (its MAC address is its id on that network).
public struct LanDevice: Codable, Sendable, Hashable, Identifiable {
    public let mac: String
    public let ipv4: String?
    public let ipv6: [String]
    /// Bonjour host name (`Apple-TV.local`).
    public let hostname: String?
    /// Bonjour instance name (`Salon`).
    public let mdnsName: String?
    /// Name given by the user.
    public let name: String?
    public let vendor: String?
    /// Locally administered ("private") address: no vendor, may change.
    public let privateMac: Bool
    public let deviceType: LanDeviceType
    public let model: String?
    public let services: [String]
    public let openPorts: [Int]
    public let portsCheckedAt: Int64?
    public let firstSeen: Int64
    public let lastSeen: Int64
    public let online: Bool
    public let trusted: Bool
    /// Present at the first scan of the network.
    public let baseline: Bool
    public let isGateway: Bool
    public let isSelf: Bool

    public var id: String { mac }
    public var firstSeenDate: Date { Date(unixSeconds: firstSeen) }
    public var lastSeenDate: Date { Date(unixSeconds: lastSeen) }
    public var portsCheckedDate: Date? { portsCheckedAt.map(Date.init(unixSeconds:)) }

    /// Neither known by the user, nor this Mac / the router.
    public var isUnknown: Bool { !trusted && !isSelf && !isGateway }

    /// First seen in the last 24 hours, after the network's first scan.
    public func isNew(now: Date = Date()) -> Bool {
        !baseline && now.timeIntervalSince(firstSeenDate) < 86_400
    }

    /// Best label: user name, Bonjour name, host name, vendor, MAC.
    public var displayName: String {
        if let name, !name.isEmpty { return name }
        if let mdnsName, !mdnsName.isEmpty { return mdnsName }
        if let hostname, !hostname.isEmpty { return hostname.replacingOccurrences(of: ".local", with: "") }
        if isSelf { return "Ce Mac" }
        if let vendor { return "Appareil \(vendor)" }
        return privateMac ? "Appareil (adresse privée)" : mac
    }

    enum CodingKeys: String, CodingKey {
        case mac, ipv4, ipv6, hostname
        case mdnsName = "mdns_name"
        case name, vendor
        case privateMac = "private_mac"
        case deviceType = "device_type"
        case model, services
        case openPorts = "open_ports"
        case portsCheckedAt = "ports_checked_at"
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
        case online, trusted, baseline
        case isGateway = "is_gateway"
        case isSelf = "is_self"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mac = try c.decode(String.self, forKey: .mac)
        ipv4 = try c.decodeIfPresent(String.self, forKey: .ipv4)
        ipv6 = try c.decodeOr(.ipv6, [String]())
        hostname = try c.decodeIfPresent(String.self, forKey: .hostname)
        mdnsName = try c.decodeIfPresent(String.self, forKey: .mdnsName)
        name = try c.decodeIfPresent(String.self, forKey: .name)
        vendor = try c.decodeIfPresent(String.self, forKey: .vendor)
        privateMac = try c.decodeOr(.privateMac, false)
        deviceType = try c.decodeOr(.deviceType, LanDeviceType.unknown)
        model = try c.decodeIfPresent(String.self, forKey: .model)
        services = try c.decodeOr(.services, [String]())
        openPorts = try c.decodeOr(.openPorts, [Int]())
        portsCheckedAt = try c.decodeIfPresent(Int64.self, forKey: .portsCheckedAt)
        firstSeen = try c.decode(Int64.self, forKey: .firstSeen)
        lastSeen = try c.decode(Int64.self, forKey: .lastSeen)
        online = try c.decodeOr(.online, false)
        trusted = try c.decodeOr(.trusted, false)
        baseline = try c.decodeOr(.baseline, false)
        isGateway = try c.decodeOr(.isGateway, false)
        isSelf = try c.decodeOr(.isSelf, false)
    }
}

public struct LanNetwork: Codable, Sendable, Hashable, Identifiable {
    /// `gw:<router MAC>`.
    public let id: String
    public let name: String
    public let interface: String
    public let subnet: String?
    public let trusted: Bool
    public let current: Bool
    public let lastScan: Int64?
    public let lastScanMode: LanScanMode?
    public let devices: [LanDevice]

    public var lastScanDate: Date? { lastScan.map(Date.init(unixSeconds:)) }

    enum CodingKeys: String, CodingKey {
        case id, name, interface, subnet, trusted, current
        case lastScan = "last_scan"
        case lastScanMode = "last_scan_mode"
        case devices
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        interface = try c.decodeOr(.interface, "")
        subnet = try c.decodeIfPresent(String.self, forKey: .subnet)
        trusted = try c.decodeOr(.trusted, false)
        current = try c.decodeOr(.current, false)
        lastScan = try c.decodeIfPresent(Int64.self, forKey: .lastScan)
        lastScanMode = try c.decodeIfPresent(LanScanMode.self, forKey: .lastScanMode)
        devices = try c.decodeOr(.devices, [LanDevice]())
    }
}

public struct LanNetworkSummary: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let name: String
    public let trusted: Bool
    public let current: Bool
    public let devices: Int
    public let unknown: Int
    public let lastScan: Int64?

    enum CodingKeys: String, CodingKey {
        case id, name, trusted, current, devices, unknown
        case lastScan = "last_scan"
    }
}

/// `lan_status` answer and `lan` event.
public struct LanStatus: Codable, Sendable, Hashable {
    public let enabled: Bool
    public let scanning: Bool
    /// 0.0 – 1.0 while scanning.
    public let progress: Double
    public let phase: String?
    public let network: LanNetwork?
    public let networks: [LanNetworkSummary]
    public let message: String?
    public let intervalMinutes: Int

    enum CodingKeys: String, CodingKey {
        case enabled, scanning, progress, phase, network, networks, message
        case intervalMinutes = "interval_minutes"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, true)
        scanning = try c.decodeOr(.scanning, false)
        progress = try c.decodeOr(.progress, 0)
        phase = try c.decodeIfPresent(String.self, forKey: .phase)
        network = try c.decodeIfPresent(LanNetwork.self, forKey: .network)
        networks = try c.decodeOr(.networks, [LanNetworkSummary]())
        message = try c.decodeIfPresent(String.self, forKey: .message)
        intervalMinutes = try c.decodeOr(.intervalMinutes, 15)
    }
}

// MARK: - Permissions audit

public enum TccAuthValue: String, TolerantEnum {
    case denied, allowed, limited, unknown
    public static let fallback: TccAuthValue = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

/// One privacy permission (a row of a `TCC.db`).
public struct TccGrant: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    /// `kTCCServiceCamera`…
    public let service: String
    public let serviceLabel: String
    /// Bundle id, or executable path when `clientIsPath`.
    public let client: String
    public let clientIsPath: Bool
    public let appName: String?
    public let appPath: String?
    /// `false`: the app is gone (stale grant); nil: unknown.
    public let installed: Bool?
    public let auth: TccAuthValue
    public let systemWide: Bool
    public let lastModified: Int64?
    /// Automation target bundle id.
    public let target: String?
    public let targetName: String?
    public let signing: SigningInfo?
    public let risk: Severity
    public let reasons: [String]
    public let settingsUrl: String?

    public var lastModifiedDate: Date? { lastModified.map(Date.init(unixSeconds:)) }
    public var displayName: String { appName ?? client }
    public var isGranted: Bool { auth == .allowed || auth == .limited }
    /// `tccutil reset` needs a bundle id.
    public var canReset: Bool { !clientIsPath }

    enum CodingKeys: String, CodingKey {
        case id, service
        case serviceLabel = "service_label"
        case client
        case clientIsPath = "client_is_path"
        case appName = "app_name"
        case appPath = "app_path"
        case installed, auth
        case systemWide = "system_wide"
        case lastModified = "last_modified"
        case target
        case targetName = "target_name"
        case signing, risk, reasons
        case settingsUrl = "settings_url"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        service = try c.decode(String.self, forKey: .service)
        serviceLabel = try c.decode(String.self, forKey: .serviceLabel)
        client = try c.decode(String.self, forKey: .client)
        clientIsPath = try c.decodeOr(.clientIsPath, false)
        appName = try c.decodeIfPresent(String.self, forKey: .appName)
        appPath = try c.decodeIfPresent(String.self, forKey: .appPath)
        installed = try c.decodeIfPresent(Bool.self, forKey: .installed)
        auth = try c.decodeOr(.auth, TccAuthValue.unknown)
        systemWide = try c.decodeOr(.systemWide, false)
        lastModified = try c.decodeIfPresent(Int64.self, forKey: .lastModified)
        target = try c.decodeIfPresent(String.self, forKey: .target)
        targetName = try c.decodeIfPresent(String.self, forKey: .targetName)
        signing = try c.decodeIfPresent(SigningInfo.self, forKey: .signing)
        risk = try c.decode(Severity.self, forKey: .risk)
        reasons = try c.decodeOr(.reasons, [String]())
        settingsUrl = try c.decodeIfPresent(String.self, forKey: .settingsUrl)
    }
}

public struct PermissionsReport: Codable, Sendable, Hashable {
    public let generatedAt: Int64
    public let grants: [TccGrant]
    public let systemDbRead: Bool
    public let userDbRead: Bool
    public let configurationProfiles: [String]
    public let errors: [String]

    public var generatedDate: Date { Date(unixSeconds: generatedAt) }

    enum CodingKeys: String, CodingKey {
        case generatedAt = "generated_at"
        case grants
        case systemDbRead = "system_db_read"
        case userDbRead = "user_db_read"
        case configurationProfiles = "configuration_profiles"
        case errors
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        generatedAt = try c.decode(Int64.self, forKey: .generatedAt)
        grants = try c.decodeOr(.grants, [TccGrant]())
        systemDbRead = try c.decodeOr(.systemDbRead, false)
        userDbRead = try c.decodeOr(.userDbRead, false)
        configurationProfiles = try c.decodeOr(.configurationProfiles, [String]())
        errors = try c.decodeOr(.errors, [String]())
    }
}

/// A browser extension (`parabellum permissions extensions --json`, run as the user).
public struct BrowserExtension: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    /// `chrome`, `brave`, `edge`, `arc`, `chromium`, `vivaldi`, `firefox`, `safari`.
    public let browser: String
    public let profile: String
    public let extensionId: String
    public let name: String
    public let version: String?
    public let enabled: Bool?
    public let fromStore: Bool?
    public let unpacked: Bool
    public let permissions: [String]
    public let hostPermissions: [String]
    public let risk: Severity
    public let reasons: [String]
    public let path: String?

    enum CodingKeys: String, CodingKey {
        case id, browser, profile
        case extensionId = "extension_id"
        case name, version, enabled
        case fromStore = "from_store"
        case unpacked, permissions
        case hostPermissions = "host_permissions"
        case risk, reasons, path
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        browser = try c.decode(String.self, forKey: .browser)
        profile = try c.decodeOr(.profile, "")
        extensionId = try c.decode(String.self, forKey: .extensionId)
        name = try c.decode(String.self, forKey: .name)
        version = try c.decodeIfPresent(String.self, forKey: .version)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled)
        fromStore = try c.decodeIfPresent(Bool.self, forKey: .fromStore)
        unpacked = try c.decodeOr(.unpacked, false)
        permissions = try c.decodeOr(.permissions, [String]())
        hostPermissions = try c.decodeOr(.hostPermissions, [String]())
        risk = try c.decode(Severity.self, forKey: .risk)
        reasons = try c.decodeOr(.reasons, [String]())
        path = try c.decodeIfPresent(String.self, forKey: .path)
    }
}

public struct ExtensionsReport: Codable, Sendable, Hashable {
    public let generatedAt: Int64
    public let extensions: [BrowserExtension]
    public let errors: [String]

    enum CodingKeys: String, CodingKey {
        case generatedAt = "generated_at"
        case extensions, errors
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        generatedAt = try c.decode(Int64.self, forKey: .generatedAt)
        extensions = try c.decodeOr(.extensions, [BrowserExtension]())
        errors = try c.decodeOr(.errors, [String]())
    }
}

/// `parabellum permissions reset --json`.
public struct TccResetResult: Codable, Sendable, Hashable {
    public let ok: Bool
    public let service: String
    public let bundleId: String
    public let message: String

    enum CodingKeys: String, CodingKey {
        case ok, service
        case bundleId = "bundle_id"
        case message
    }
}

// MARK: - Labels

extension LanDeviceType {
    public var label: String {
        switch self {
        case .router: return "Routeur"
        case .computer: return "Ordinateur"
        case .phone: return "Téléphone"
        case .tablet: return "Tablette"
        case .tv: return "Téléviseur"
        case .speaker: return "Enceinte"
        case .printer: return "Imprimante"
        case .camera: return "Caméra"
        case .nas: return "Stockage réseau"
        case .console: return "Console"
        case .iot: return "Objet connecté"
        case .unknown: return "Appareil"
        }
    }

    /// SF Symbol available on macOS 14.
    public var symbol: String {
        switch self {
        case .router: return "wifi.router"
        case .computer: return "laptopcomputer"
        case .phone: return "iphone"
        case .tablet: return "ipad"
        case .tv: return "tv"
        case .speaker: return "hifispeaker"
        case .printer: return "printer"
        case .camera: return "web.camera"
        case .nas: return "externaldrive.connected.to.line.below"
        case .console: return "gamecontroller"
        case .iot: return "lightbulb"
        case .unknown: return "questionmark.app.dashed"
        }
    }
}

extension TccAuthValue {
    public var label: String {
        switch self {
        case .denied: return "Refusé"
        case .allowed: return "Autorisé"
        case .limited: return "Limité"
        case .unknown: return "Inconnu"
        }
    }
}

/// Browser keys of `BrowserExtension.browser`.
public enum BrowserLabels {
    public static func label(_ key: String) -> String {
        switch key {
        case "chrome": return "Google Chrome"
        case "brave": return "Brave"
        case "edge": return "Microsoft Edge"
        case "arc": return "Arc"
        case "chromium": return "Chromium"
        case "vivaldi": return "Vivaldi"
        case "firefox": return "Firefox"
        case "safari": return "Safari"
        default: return key
        }
    }
}
