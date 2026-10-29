import Foundation

// Mirrors the `vpn`, `guard`, `network`, `data_removal`, `breach` and `aliases` sections of
// `crates/pb-core/src/config.rs`: same defaults, missing keys decode to the default, `Option<String>`
// fields encoded as an explicit `null` (no `skip_serializing_if` in Rust).

// MARK: - Enums

/// When the VPN must be up.
public enum VpnMode: String, TolerantEnum {
    case off, always
    case untrustedNetworks = "untrusted_networks"
    /// Unknown values fall back to `off` (the safe default).
    public static let fallback: VpnMode = .off
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

/// Which VPN engine Parabellum drives.
public enum VpnBackend: String, TolerantEnum {
    /// sing-box (open source) run by the daemon from the imported profile.
    case singBox = "sing_box"
    /// A VPN already configured in macOS (Shadowrocket, WireGuard…), driven with `scutil --nc`.
    case external
    public static let fallback: VpnBackend = .singBox
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

/// How GDPR erasure requests leave the Mac.
public enum SendMode: String, TolerantEnum {
    /// Ready-to-send emails opened in Mail.
    case drafts
    /// Sent by the daemon through your SMTP account (rate-limited).
    case smtp
    public static let fallback: SendMode = .drafts
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum BreachProvider: String, TolerantEnum {
    /// XposedOrNot (free, no key).
    case xposedOrNot = "xposed_or_not"
    /// Have I Been Pwned (paid API key).
    case hibp
    public static let fallback: BreachProvider = .xposedOrNot
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum AliasProvider: String, TolerantEnum {
    /// No alias service (Rust `none`; not named `none` to avoid `Optional.none` ambiguities).
    case disabled = "none"
    case addy
    case simpleLogin = "simple_login"
    public static let fallback: AliasProvider = .disabled
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

// MARK: - Sections

public struct VpnConfig: Codable, Sendable, Hashable {
    public var mode: VpnMode = .off
    public var backend: VpnBackend = .singBox
    /// External backend: name of the macOS VPN service (`scutil --nc list`), e.g. `Shadowrocket`.
    public var externalService: String?
    /// External backend: VPN server hosts / IPs the kill switch lets through.
    public var externalServerAddresses: [String] = []
    /// Network fingerprints (`gw:<router MAC>`) considered safe for `untrusted_networks` mode.
    public var trustedNetworks: [String] = []
    /// Block every packet that does not go through the tunnel while the VPN should be up.
    public var killSwitch: Bool = false
    /// Keep the local network (printers, NAS, AirDrop, DHCP) reachable outside the tunnel.
    public var allowLan: Bool = true
    /// sing-box: route IPv6 into the tunnel too (otherwise IPv6 is blocked while connected).
    public var tunnelIpv6: Bool = true
    /// Automatic leak test while connected, minutes (0 = on demand only).
    public var leakTestIntervalMinutes: Int = 60

    public init() {}

    enum CodingKeys: String, CodingKey {
        case mode, backend
        case externalService = "external_service"
        case externalServerAddresses = "external_server_addresses"
        case trustedNetworks = "trusted_networks"
        case killSwitch = "kill_switch"
        case allowLan = "allow_lan"
        case tunnelIpv6 = "tunnel_ipv6"
        case leakTestIntervalMinutes = "leak_test_interval_minutes"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode = try c.decodeOr(.mode, mode)
        backend = try c.decodeOr(.backend, backend)
        externalService = try c.decodeIfPresent(String.self, forKey: .externalService)
        externalServerAddresses = try c.decodeOr(.externalServerAddresses, externalServerAddresses)
        trustedNetworks = try c.decodeOr(.trustedNetworks, trustedNetworks)
        killSwitch = try c.decodeOr(.killSwitch, killSwitch)
        allowLan = try c.decodeOr(.allowLan, allowLan)
        tunnelIpv6 = try c.decodeOr(.tunnelIpv6, tunnelIpv6)
        leakTestIntervalMinutes = try c.decodeOr(.leakTestIntervalMinutes, leakTestIntervalMinutes)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(mode, forKey: .mode)
        try c.encode(backend, forKey: .backend)
        if let externalService {
            try c.encode(externalService, forKey: .externalService)
        } else {
            try c.encodeNil(forKey: .externalService)
        }
        try c.encode(externalServerAddresses, forKey: .externalServerAddresses)
        try c.encode(trustedNetworks, forKey: .trustedNetworks)
        try c.encode(killSwitch, forKey: .killSwitch)
        try c.encode(allowLan, forKey: .allowLan)
        try c.encode(tunnelIpv6, forKey: .tunnelIpv6)
        try c.encode(leakTestIntervalMinutes, forKey: .leakTestIntervalMinutes)
    }
}

/// `[guard]`: info-stealer and ransomware behaviour detection, APFS snapshots.
public struct GuardConfig: Codable, Sendable, Hashable {
    public var stealerDetection: Bool = true
    /// Kill the offending process on a high-confidence match (never Apple system services).
    public var killOnDetection: Bool = true
    /// Team IDs allowed to read browser / keychain data on top of the DB allowlist (password managers…).
    public var trustedTeamIds: [String] = []
    public var ransomwareDetection: Bool = true
    /// Suspend suspected ransomware until you decide (kill or resume) instead of only alerting.
    public var suspendRansomware: Bool = true
    /// Periodic APFS local snapshots of the data volume.
    public var snapshots: Bool = true
    public var snapshotIntervalMinutes: Int = 60

    public init() {}

    enum CodingKeys: String, CodingKey {
        case stealerDetection = "stealer_detection"
        case killOnDetection = "kill_on_detection"
        case trustedTeamIds = "trusted_team_ids"
        case ransomwareDetection = "ransomware_detection"
        case suspendRansomware = "suspend_ransomware"
        case snapshots
        case snapshotIntervalMinutes = "snapshot_interval_minutes"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        stealerDetection = try c.decodeOr(.stealerDetection, stealerDetection)
        killOnDetection = try c.decodeOr(.killOnDetection, killOnDetection)
        trustedTeamIds = try c.decodeOr(.trustedTeamIds, trustedTeamIds)
        ransomwareDetection = try c.decodeOr(.ransomwareDetection, ransomwareDetection)
        suspendRansomware = try c.decodeOr(.suspendRansomware, suspendRansomware)
        snapshots = try c.decodeOr(.snapshots, snapshots)
        snapshotIntervalMinutes = try c.decodeOr(.snapshotIntervalMinutes, snapshotIntervalMinutes)
    }
}

/// `[network]`: ARP spoofing / evil twin detection on the current network.
public struct NetworkGuardConfig: Codable, Sendable, Hashable {
    public var enabled: Bool = true
    /// Polling period of the routing table / ARP cache, seconds.
    public var pollSeconds: Int = 20

    public init() {}

    enum CodingKeys: String, CodingKey {
        case enabled
        case pollSeconds = "poll_seconds"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, enabled)
        pollSeconds = try c.decodeOr(.pollSeconds, pollSeconds)
    }
}

/// `[data_removal]`: GDPR erasure requests to data brokers.
public struct DataRemovalConfig: Codable, Sendable, Hashable {
    public var enabled: Bool = false
    /// `eu`, `global`, `us`.
    public var regions: [String] = ["eu", "global"]
    public var sendMode: SendMode = .drafts
    public var smtpHost: String = ""
    public var smtpPort: Int = 587
    public var smtpUsername: String = ""
    /// Secret (app password); redacted over IPC.
    public var smtpPassword: String?
    /// Sender address (also where brokers answer).
    public var fromAddress: String = ""
    public var maxEmailsPerDay: Int = 20
    public var reminderAfterDays: Int = 30
    public var escalateAfterDays: Int = 15
    /// `fr` or `en`.
    public var language: String = "fr"
    /// New request every N days (0 = never).
    public var repeatEveryDays: Int = 180

    public static let knownRegions = ["eu", "global", "us"]

    public init() {}

    enum CodingKeys: String, CodingKey {
        case enabled, regions
        case sendMode = "send_mode"
        case smtpHost = "smtp_host"
        case smtpPort = "smtp_port"
        case smtpUsername = "smtp_username"
        case smtpPassword = "smtp_password"
        case fromAddress = "from_address"
        case maxEmailsPerDay = "max_emails_per_day"
        case reminderAfterDays = "reminder_after_days"
        case escalateAfterDays = "escalate_after_days"
        case language
        case repeatEveryDays = "repeat_every_days"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, enabled)
        regions = try c.decodeOr(.regions, regions)
        sendMode = try c.decodeOr(.sendMode, sendMode)
        smtpHost = try c.decodeOr(.smtpHost, smtpHost)
        smtpPort = try c.decodeOr(.smtpPort, smtpPort)
        smtpUsername = try c.decodeOr(.smtpUsername, smtpUsername)
        smtpPassword = try c.decodeIfPresent(String.self, forKey: .smtpPassword)
        fromAddress = try c.decodeOr(.fromAddress, fromAddress)
        maxEmailsPerDay = try c.decodeOr(.maxEmailsPerDay, maxEmailsPerDay)
        reminderAfterDays = try c.decodeOr(.reminderAfterDays, reminderAfterDays)
        escalateAfterDays = try c.decodeOr(.escalateAfterDays, escalateAfterDays)
        language = try c.decodeOr(.language, language)
        repeatEveryDays = try c.decodeOr(.repeatEveryDays, repeatEveryDays)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(enabled, forKey: .enabled)
        try c.encode(regions, forKey: .regions)
        try c.encode(sendMode, forKey: .sendMode)
        try c.encode(smtpHost, forKey: .smtpHost)
        try c.encode(smtpPort, forKey: .smtpPort)
        try c.encode(smtpUsername, forKey: .smtpUsername)
        if let smtpPassword {
            try c.encode(smtpPassword, forKey: .smtpPassword)
        } else {
            try c.encodeNil(forKey: .smtpPassword)
        }
        try c.encode(fromAddress, forKey: .fromAddress)
        try c.encode(maxEmailsPerDay, forKey: .maxEmailsPerDay)
        try c.encode(reminderAfterDays, forKey: .reminderAfterDays)
        try c.encode(escalateAfterDays, forKey: .escalateAfterDays)
        try c.encode(language, forKey: .language)
        try c.encode(repeatEveryDays, forKey: .repeatEveryDays)
    }
}

/// `[breach]`: known data breaches for your addresses.
public struct BreachConfig: Codable, Sendable, Hashable {
    public var enabled: Bool = false
    /// Only the address is sent to the provider.
    public var emails: [String] = []
    public var provider: BreachProvider = .xposedOrNot
    /// Secret; redacted over IPC.
    public var hibpApiKey: String?
    public var checkIntervalHours: Int = 24 * 7

    public init() {}

    enum CodingKeys: String, CodingKey {
        case enabled, emails, provider
        case hibpApiKey = "hibp_api_key"
        case checkIntervalHours = "check_interval_hours"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeOr(.enabled, enabled)
        emails = try c.decodeOr(.emails, emails)
        provider = try c.decodeOr(.provider, provider)
        hibpApiKey = try c.decodeIfPresent(String.self, forKey: .hibpApiKey)
        checkIntervalHours = try c.decodeOr(.checkIntervalHours, checkIntervalHours)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(enabled, forKey: .enabled)
        try c.encode(emails, forKey: .emails)
        try c.encode(provider, forKey: .provider)
        if let hibpApiKey {
            try c.encode(hibpApiKey, forKey: .hibpApiKey)
        } else {
            try c.encodeNil(forKey: .hibpApiKey)
        }
        try c.encode(checkIntervalHours, forKey: .checkIntervalHours)
    }
}

/// `[aliases]`: email alias service.
public struct AliasConfig: Codable, Sendable, Hashable {
    public var provider: AliasProvider = .disabled
    /// Secret; redacted over IPC.
    public var apiKey: String?
    /// Empty = the provider's public instance; set it for a self-hosted one (https only).
    public var baseUrl: String = ""
    /// addy.io: alias domain (empty = account default).
    public var domain: String = ""

    public init() {}

    enum CodingKeys: String, CodingKey {
        case provider
        case apiKey = "api_key"
        case baseUrl = "base_url"
        case domain
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        provider = try c.decodeOr(.provider, provider)
        apiKey = try c.decodeIfPresent(String.self, forKey: .apiKey)
        baseUrl = try c.decodeOr(.baseUrl, baseUrl)
        domain = try c.decodeOr(.domain, domain)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(provider, forKey: .provider)
        if let apiKey {
            try c.encode(apiKey, forKey: .apiKey)
        } else {
            try c.encodeNil(forKey: .apiKey)
        }
        try c.encode(baseUrl, forKey: .baseUrl)
        try c.encode(domain, forKey: .domain)
    }
}

// MARK: - Validation (same rules as `Config::validate_protection`)

public enum ConfigSyntax {
    /// `host`, `host.domain`, IPv4 or IPv6 literal (no scheme, port or path).
    public static func isHostOrIp(_ s: String) -> Bool {
        if isIpLiteral(s) {
            return true
        }
        guard !s.isEmpty, s.utf8.count <= 253 else { return false }
        return s.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-") }
        }
    }

    static func isIpLiteral(_ s: String) -> Bool {
        var v4 = in_addr()
        var v6 = in6_addr()
        return s.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
    }

    /// `gw:<router MAC, lowercase aa:bb:cc:dd:ee:ff>`.
    public static func isNetworkId(_ s: String) -> Bool {
        guard s.hasPrefix("gw:") else { return false }
        let parts = s.dropFirst(3).split(separator: ":", omittingEmptySubsequences: false)
        return parts.count == 6 && parts.allSatisfy { part in
            part.count == 2 && part.unicodeScalars.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
        }
    }

    /// Apple Developer Team ID: 10 uppercase letters / digits.
    public static func isTeamId(_ s: String) -> Bool {
        s.count == 10 && s.unicodeScalars.allSatisfy { ("A"..."Z").contains($0) || ("0"..."9").contains($0) }
    }

    /// `local@domain.tld`, no spaces / control characters / angle brackets.
    public static func isEmail(_ s: String) -> Bool {
        guard let at = s.lastIndex(of: "@") else { return false }
        let local = s[s.startIndex..<at]
        let domain = String(s[s.index(after: at)...])
        let forbidden = CharacterSet.whitespacesAndNewlines.union(.controlCharacters).union(CharacterSet(charactersIn: "<>,;\""))
        return !local.isEmpty && local.utf8.count <= 64 && s.utf8.count <= 254 && domain.contains(".")
            && isHostOrIp(domain) && s.unicodeScalars.allSatisfy { !forbidden.contains($0) }
    }
}

extension Config {
    /// Same rules as `Config::validate_protection` in Rust (messages in French).
    public func protectionValidationErrors() -> [String] {
        var errors: [String] = []
        if vpn.leakTestIntervalMinutes < 0 || vpn.leakTestIntervalMinutes > 7 * 24 * 60 {
            errors.append("L'intervalle du test de fuite doit être compris entre 0 et 10 080 minutes.")
        }
        if let service = vpn.externalService {
            let trimmed = service.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || service.count > 128 || service.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) {
                errors.append("Le nom du VPN macOS est invalide.")
            }
        }
        for address in vpn.externalServerAddresses where !ConfigSyntax.isHostOrIp(address) {
            errors.append("Adresse de serveur VPN invalide : \(address)")
        }
        for id in vpn.trustedNetworks where !ConfigSyntax.isNetworkId(id) {
            errors.append("Identifiant de réseau invalide : \(id)")
        }
        if !(15...(24 * 60)).contains(behaviorGuard.snapshotIntervalMinutes) {
            errors.append("L'intervalle des instantanés doit être compris entre 15 et 1 440 minutes.")
        }
        for team in behaviorGuard.trustedTeamIds where !ConfigSyntax.isTeamId(team) {
            errors.append("Team ID invalide : \(team) (10 lettres majuscules ou chiffres)")
        }
        if !(5...600).contains(networkGuard.pollSeconds) {
            errors.append("La fréquence de surveillance du réseau doit être comprise entre 5 et 600 secondes.")
        }
        errors.append(contentsOf: dataRemovalErrors())
        for email in breach.emails where !ConfigSyntax.isEmail(email) {
            errors.append("Adresse surveillée invalide : \(email)")
        }
        if !(1...(24 * 30)).contains(breach.checkIntervalHours) {
            errors.append("L'intervalle de vérification des fuites doit être compris entre 1 et 720 heures.")
        }
        if !aliases.baseUrl.isEmpty && !aliases.baseUrl.hasPrefix("https://") {
            errors.append("L'adresse du service d'alias doit commencer par https://")
        }
        return errors
    }

    private func dataRemovalErrors() -> [String] {
        var errors: [String] = []
        let d = dataRemoval
        if !(1...200).contains(d.maxEmailsPerDay) {
            errors.append("Le nombre d'e-mails par jour doit être compris entre 1 et 200.")
        }
        if !(7...90).contains(d.reminderAfterDays) || !(7...90).contains(d.escalateAfterDays) {
            errors.append("Les délais de relance et d'escalade doivent être compris entre 7 et 90 jours.")
        }
        if d.repeatEveryDays != 0 && !(30...730).contains(d.repeatEveryDays) {
            errors.append("Le renouvellement des demandes doit être 0 (jamais) ou compris entre 30 et 730 jours.")
        }
        for region in d.regions where !DataRemovalConfig.knownRegions.contains(region) {
            errors.append("Région de courtiers inconnue : \(region)")
        }
        if d.language != "fr" && d.language != "en" {
            errors.append("La langue des courriers doit être fr ou en.")
        }
        if d.sendMode == .smtp {
            let host = d.smtpHost.trimmingCharacters(in: .whitespaces)
            if host.isEmpty || !ConfigSyntax.isHostOrIp(host) {
                errors.append("Le serveur SMTP est requis en mode envoi automatique.")
            }
            if d.smtpPort <= 0 || d.smtpPort > 65_535 {
                errors.append("Le port SMTP doit être compris entre 1 et 65 535.")
            }
            if !ConfigSyntax.isEmail(d.fromAddress) {
                errors.append("L'adresse d'expédition est requise en mode envoi automatique.")
            }
        } else if !d.fromAddress.isEmpty && !ConfigSyntax.isEmail(d.fromAddress) {
            errors.append("L'adresse d'expédition est invalide.")
        }
        return errors
    }
}
