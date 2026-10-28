import Foundation

// Mirrors `crates/pb-core/src/config.rs`. Every section and field has the same default as in Rust and a
// missing key decodes to that default (`#[serde(default)]`). Rust serializes `Option<String>` config
// fields without `skip_serializing_if`, i.e. as an explicit `null`: `UpdatesConfig` and `PrivacyConfig`
// encode them the same way.
//
// Integers are `Int` on the Swift side (Rust u8/u32/u64): values are range-checked by `validationErrors()`
// with the same rules as `Config::validate`.

public struct Config: Codable, Sendable, Hashable {
    public var scan = ScanConfig()
    public var realtime = RealtimeConfig()
    public var ml = MlConfig()
    public var dns = DnsConfig()
    public var devices = DevicesConfig()
    public var persistence = PersistenceConfig()
    public var updates = UpdatesConfig()
    public var energy = EnergyConfig()
    public var privacy = PrivacyConfig()
    public var notifications = NotificationsConfig()
    public var security = SecurityConfig()

    public init() {}

    enum CodingKeys: String, CodingKey {
        case scan, realtime, ml, dns, devices, persistence, updates, energy, privacy, notifications, security
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        scan = try c.decodeOr(.scan, scan)
        realtime = try c.decodeOr(.realtime, realtime)
        ml = try c.decodeOr(.ml, ml)
        dns = try c.decodeOr(.dns, dns)
        devices = try c.decodeOr(.devices, devices)
        persistence = try c.decodeOr(.persistence, persistence)
        updates = try c.decodeOr(.updates, updates)
        energy = try c.decodeOr(.energy, energy)
        privacy = try c.decodeOr(.privacy, privacy)
        notifications = try c.decodeOr(.notifications, notifications)
        security = try c.decodeOr(.security, security)
    }

    /// Same rules as `Config::validate` in Rust (messages in French). Empty = valid.
    public func validationErrors() -> [String] {
        var errors: [String] = []
        if scan.maxFileSizeMb <= 0 {
            errors.append("La taille maximale de fichier doit être supérieure à 0 Mo.")
        }
        if scan.archiveMaxDepth < 0 || scan.archiveMaxDepth > 10 {
            errors.append("La profondeur d'archives imbriquées doit être comprise entre 0 et 10.")
        }
        if scan.archiveMaxTotalMb < 0 || scan.archiveMaxEntries < 0 {
            errors.append("Les limites d'archives ne peuvent pas être négatives.")
        }
        if !(0.0...1.0).contains(ml.suspiciousThreshold) {
            errors.append("Le seuil ML doit être compris entre 0 et 1.")
        }
        if updates.dailyHour < 0 || updates.dailyHour > 23 {
            errors.append("L'heure de mise à jour doit être comprise entre 0 et 23.")
        }
        if energy.pauseOnBatteryBelow < 0 || energy.pauseOnBatteryBelow > 100 {
            errors.append("Le seuil de batterie doit être compris entre 0 et 100 %.")
        }
        if security.spywareScanWeekday < 1 || security.spywareScanWeekday > 7 {
            errors.append("Le jour de l'analyse anti-spyware doit être compris entre 1 (lundi) et 7 (dimanche).")
        }
        if security.spywareScanHour < 0 || security.spywareScanHour > 23 {
            errors.append("L'heure de l'analyse anti-spyware doit être comprise entre 0 et 23.")
        }
        if persistence.fullScanIntervalMinutes < 0 {
            errors.append("L'intervalle d'énumération de la persistance ne peut pas être négatif.")
        }
        return errors
    }
}

public struct ScanConfig: Codable, Sendable, Hashable {
    /// Files larger than this are hashed but not content-scanned.
    public var maxFileSizeMb: Int = 200
    /// Nested archive depth (zip in dmg in zip…), 0…10.
    public var archiveMaxDepth: Int = 3
    /// Max total uncompressed bytes extracted from one archive (zip-bomb guard).
    public var archiveMaxTotalMb: Int = 1024
    /// Max number of entries inspected per archive.
    public var archiveMaxEntries: Int = 20_000
    /// Folders watched for new files (`~` = console user's home).
    public var watchPaths: [String] = ["~/Downloads", "~/Desktop", "~/Documents", "/Applications", "~/Applications"]
    /// Never scanned (prefix match after `~` expansion).
    public var excludePaths: [String] = []
    public var clamavOnDemand: Bool = true
    public var clamavRealtime: Bool = false
    public var mountDmg: Bool = true
    public var expandPkg: Bool = true

    public init() {}

    enum CodingKeys: String, CodingKey {
        case maxFileSizeMb = "max_file_size_mb"
        case archiveMaxDepth = "archive_max_depth"
        case archiveMaxTotalMb = "archive_max_total_mb"
        case archiveMaxEntries = "archive_max_entries"
        case watchPaths = "watch_paths"
        case excludePaths = "exclude_paths"
        case clamavOnDemand = "clamav_on_demand"
        case clamavRealtime = "clamav_realtime"
        case mountDmg = "mount_dmg"
        case expandPkg = "expand_pkg"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        maxFileSizeMb = try c.decodeOr(.maxFileSizeMb, maxFileSizeMb)
        archiveMaxDepth = try c.decodeOr(.archiveMaxDepth, archiveMaxDepth)
        archiveMaxTotalMb = try c.decodeOr(.archiveMaxTotalMb, archiveMaxTotalMb)
        archiveMaxEntries = try c.decodeOr(.archiveMaxEntries, archiveMaxEntries)
        watchPaths = try c.decodeOr(.watchPaths, watchPaths)
        excludePaths = try c.decodeOr(.excludePaths, excludePaths)
        clamavOnDemand = try c.decodeOr(.clamavOnDemand, clamavOnDemand)
        clamavRealtime = try c.decodeOr(.clamavRealtime, clamavRealtime)
        mountDmg = try c.decodeOr(.mountDmg, mountDmg)
        expandPkg = try c.decodeOr(.expandPkg, expandPkg)
    }
}

public struct RealtimeConfig: Codable, Sendable, Hashable {
    public var enabled: Bool = true
    /// Apple `eslogger` (Endpoint Security, observe-only).
    public var eslogger: Bool = true
    /// FSEvents on `scan.watch_paths`.
    public var fsevents: Bool = true
    /// Quarantine signature-engine `malicious` files automatically (ML alone never quarantines).
    public var autoQuarantine: Bool = true
    /// Scan executables when they are launched.
    public var scanOnExec: Bool = true
    /// SIGKILL a process right after launch when its executable is `malicious` per a signature engine.
    public var killMaliciousProcesses: Bool = true

    public init() {}

    enum CodingKeys: String, CodingKey {
        case enabled, eslogger, fsevents
        case autoQuarantine = "auto_quarantine"
        case scanOnExec = "scan_on_exec"
        case killMaliciousProcesses = "kill_malicious_processes"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, enabled)
        eslogger = try c.decodeOr(.eslogger, eslogger)
        fsevents = try c.decodeOr(.fsevents, fsevents)
        autoQuarantine = try c.decodeOr(.autoQuarantine, autoQuarantine)
        scanOnExec = try c.decodeOr(.scanOnExec, scanOnExec)
        killMaliciousProcesses = try c.decodeOr(.killMaliciousProcesses, killMaliciousProcesses)
    }
}

public struct MlConfig: Codable, Sendable, Hashable {
    public var enabled: Bool = true
    /// Score above which a Mach-O is reported as `suspicious` (Rust `f32`).
    public var suspiciousThreshold: Double = 0.85
    /// Only score unsigned / ad-hoc / non-notarized binaries.
    public var onlyUntrusted: Bool = true

    public init() {}

    enum CodingKeys: String, CodingKey {
        case enabled
        case suspiciousThreshold = "suspicious_threshold"
        case onlyUntrusted = "only_untrusted"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, enabled)
        suspiciousThreshold = try c.decodeOr(.suspiciousThreshold, suspiciousThreshold)
        onlyUntrusted = try c.decodeOr(.onlyUntrusted, onlyUntrusted)
    }
}

public struct DnsConfig: Codable, Sendable, Hashable {
    public var enabled: Bool = false
    public var listen: String = "127.0.0.1:53"
    /// dnscrypt-proxy `server_names`.
    public var upstreamServers: [String] = ["cloudflare", "quad9-doh-ip4-port443-filter-pri"]
    public var blockMalware: Bool = true
    public var blockAds: Bool = true
    public var blockTrackers: Bool = true
    /// Exact domain or `*.domain`.
    public var customAllow: [String] = []
    public var customBlock: [String] = []

    public init() {}

    enum CodingKeys: String, CodingKey {
        case enabled, listen
        case upstreamServers = "upstream_servers"
        case blockMalware = "block_malware"
        case blockAds = "block_ads"
        case blockTrackers = "block_trackers"
        case customAllow = "custom_allow"
        case customBlock = "custom_block"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, enabled)
        listen = try c.decodeOr(.listen, listen)
        upstreamServers = try c.decodeOr(.upstreamServers, upstreamServers)
        blockMalware = try c.decodeOr(.blockMalware, blockMalware)
        blockAds = try c.decodeOr(.blockAds, blockAds)
        blockTrackers = try c.decodeOr(.blockTrackers, blockTrackers)
        customAllow = try c.decodeOr(.customAllow, customAllow)
        customBlock = try c.decodeOr(.customBlock, customBlock)
    }
}

public struct DevicesConfig: Codable, Sendable, Hashable {
    public var scanVolumes: Bool = true
    public var alertNewHid: Bool = true
    /// Best-effort: block input of unknown keyboards until approved.
    public var blockNewHid: Bool = false
    public var alertBluetooth: Bool = true
    public var alertNetworkInterfaces: Bool = true
    public var alertThunderbolt: Bool = true
    public var alertWifiNetworks: Bool = true
    public var alertOtherUsb: Bool = true

    public init() {}

    enum CodingKeys: String, CodingKey {
        case scanVolumes = "scan_volumes"
        case alertNewHid = "alert_new_hid"
        case blockNewHid = "block_new_hid"
        case alertBluetooth = "alert_bluetooth"
        case alertNetworkInterfaces = "alert_network_interfaces"
        case alertThunderbolt = "alert_thunderbolt"
        case alertWifiNetworks = "alert_wifi_networks"
        case alertOtherUsb = "alert_other_usb"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        scanVolumes = try c.decodeOr(.scanVolumes, scanVolumes)
        alertNewHid = try c.decodeOr(.alertNewHid, alertNewHid)
        blockNewHid = try c.decodeOr(.blockNewHid, blockNewHid)
        alertBluetooth = try c.decodeOr(.alertBluetooth, alertBluetooth)
        alertNetworkInterfaces = try c.decodeOr(.alertNetworkInterfaces, alertNetworkInterfaces)
        alertThunderbolt = try c.decodeOr(.alertThunderbolt, alertThunderbolt)
        alertWifiNetworks = try c.decodeOr(.alertWifiNetworks, alertWifiNetworks)
        alertOtherUsb = try c.decodeOr(.alertOtherUsb, alertOtherUsb)
    }
}

public struct PersistenceConfig: Codable, Sendable, Hashable {
    public var enabled: Bool = true
    public var fullScanIntervalMinutes: Int = 360
    public var osqueryHunting: Bool = true

    public init() {}

    enum CodingKeys: String, CodingKey {
        case enabled
        case fullScanIntervalMinutes = "full_scan_interval_minutes"
        case osqueryHunting = "osquery_hunting"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, enabled)
        fullScanIntervalMinutes = try c.decodeOr(.fullScanIntervalMinutes, fullScanIntervalMinutes)
        osqueryHunting = try c.decodeOr(.osqueryHunting, osqueryHunting)
    }
}

public struct UpdatesConfig: Codable, Sendable, Hashable {
    public var dbBaseUrl: String = "https://github.com/WLDEUS/Parabellum/releases/download/db-latest"
    public var appReleasesApi: String = "https://api.github.com/repos/WLDEUS/Parabellum/releases"
    /// Optional read-only GitHub token (private repository). Encoded as `null` when nil, like Rust.
    public var githubToken: String?
    /// Local hour (0-23) of the daily update run.
    public var dailyHour: Int = 3
    public var autoUpdateComponents: Bool = true
    public var autoUpdateApp: Bool = false
    public var freshclam: Bool = true

    public init() {}

    enum CodingKeys: String, CodingKey {
        case dbBaseUrl = "db_base_url"
        case appReleasesApi = "app_releases_api"
        case githubToken = "github_token"
        case dailyHour = "daily_hour"
        case autoUpdateComponents = "auto_update_components"
        case autoUpdateApp = "auto_update_app"
        case freshclam
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        dbBaseUrl = try c.decodeOr(.dbBaseUrl, dbBaseUrl)
        appReleasesApi = try c.decodeOr(.appReleasesApi, appReleasesApi)
        githubToken = try c.decodeIfPresent(String.self, forKey: .githubToken)
        dailyHour = try c.decodeOr(.dailyHour, dailyHour)
        autoUpdateComponents = try c.decodeOr(.autoUpdateComponents, autoUpdateComponents)
        autoUpdateApp = try c.decodeOr(.autoUpdateApp, autoUpdateApp)
        freshclam = try c.decodeOr(.freshclam, freshclam)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(dbBaseUrl, forKey: .dbBaseUrl)
        try c.encode(appReleasesApi, forKey: .appReleasesApi)
        if let githubToken {
            try c.encode(githubToken, forKey: .githubToken)
        } else {
            try c.encodeNil(forKey: .githubToken)
        }
        try c.encode(dailyHour, forKey: .dailyHour)
        try c.encode(autoUpdateComponents, forKey: .autoUpdateComponents)
        try c.encode(autoUpdateApp, forKey: .autoUpdateApp)
        try c.encode(freshclam, forKey: .freshclam)
    }
}

public struct SecurityConfig: Codable, Sendable, Hashable {
    /// Weekly mercenary-spyware check (Zero Breach Toolkit), also after an indicator update (at most daily).
    public var spywareScanWeekly: Bool = true
    /// 1 = Monday … 7 = Sunday.
    public var spywareScanWeekday: Int = 3
    /// Local hour 0-23.
    public var spywareScanHour: Int = 13
    /// Daily macOS security settings check (SIP, Gatekeeper, FileVault, firewall…).
    public var postureChecks: Bool = true

    public init() {}

    enum CodingKeys: String, CodingKey {
        case spywareScanWeekly = "spyware_scan_weekly"
        case spywareScanWeekday = "spyware_scan_weekday"
        case spywareScanHour = "spyware_scan_hour"
        case postureChecks = "posture_checks"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        spywareScanWeekly = try c.decodeOr(.spywareScanWeekly, spywareScanWeekly)
        spywareScanWeekday = try c.decodeOr(.spywareScanWeekday, spywareScanWeekday)
        spywareScanHour = try c.decodeOr(.spywareScanHour, spywareScanHour)
        postureChecks = try c.decodeOr(.postureChecks, postureChecks)
    }
}

public struct EnergyConfig: Codable, Sendable, Hashable {
    /// Defer scheduled / batch scans on battery below this percentage (0 = never).
    public var pauseOnBatteryBelow: Int = 20
    /// Background QoS (efficiency cores) for scans.
    public var backgroundQos: Bool = true

    public init() {}

    enum CodingKeys: String, CodingKey {
        case pauseOnBatteryBelow = "pause_on_battery_below"
        case backgroundQos = "background_qos"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        pauseOnBatteryBelow = try c.decodeOr(.pauseOnBatteryBelow, pauseOnBatteryBelow)
        backgroundQos = try c.decodeOr(.backgroundQos, backgroundQos)
    }
}

public struct PrivacyConfig: Codable, Sendable, Hashable {
    /// Opt-in VirusTotal hash lookups (never the file).
    public var virustotalLookup: Bool = false
    /// Encoded as `null` when nil, like Rust.
    public var virustotalApiKey: String?

    public init() {}

    enum CodingKeys: String, CodingKey {
        case virustotalLookup = "virustotal_lookup"
        case virustotalApiKey = "virustotal_api_key"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        virustotalLookup = try c.decodeOr(.virustotalLookup, virustotalLookup)
        virustotalApiKey = try c.decodeIfPresent(String.self, forKey: .virustotalApiKey)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(virustotalLookup, forKey: .virustotalLookup)
        if let virustotalApiKey {
            try c.encode(virustotalApiKey, forKey: .virustotalApiKey)
        } else {
            try c.encodeNil(forKey: .virustotalApiKey)
        }
    }
}

public struct NotificationsConfig: Codable, Sendable, Hashable {
    public var enabled: Bool = true
    /// Minimum severity that triggers a macOS notification.
    public var minSeverity: Severity = .medium

    public init() {}

    enum CodingKeys: String, CodingKey {
        case enabled
        case minSeverity = "min_severity"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, enabled)
        minSeverity = try c.decodeOr(.minSeverity, minSeverity)
    }
}
