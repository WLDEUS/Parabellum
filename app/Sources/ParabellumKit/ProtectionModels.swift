import Foundation

// Mirrors the VPN / behaviour guard / privacy types of `crates/pb-core/src/model.rs`.
// Same conventions as Models.swift: explicit snake_case keys, Unix-second timestamps, optionals omitted
// when nil, `#[serde(default)]` collections decoded as empty when missing, unknown enum strings → fallback.

// MARK: - VPN & networks

public enum VpnState: String, TolerantEnum {
    case disconnected, connecting, connected, disconnecting, error
    case unknown
    public static let fallback: VpnState = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum KillSwitchState: String, TolerantEnum {
    /// Not enabled, or the VPN is not wanted right now.
    case off
    /// Rules loaded, tunnel up: only tunnel / LAN / VPN-server traffic leaves the Mac.
    case armed
    /// Rules loaded, tunnel down: Internet traffic is blocked until it comes back.
    case blocking
    case error
    case unknown
    public static let fallback: KillSwitchState = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

/// Imported VPN profile, without its secrets.
public struct VpnProfileInfo: Codable, Sendable, Hashable {
    public let name: String
    /// `shadowsocks`, `vless`, `vmess`, `trojan`, `hysteria2`, `tuic`, `wireguard`.
    public let protocolName: String
    public let server: String
    public let port: Int
    /// Transport / security summary, e.g. `tls+ws`, `reality`, `udp`.
    public let transport: String?
    public let importedAt: Int64

    public var importedDate: Date { Date(unixSeconds: importedAt) }

    enum CodingKeys: String, CodingKey {
        case name
        case protocolName = "protocol"
        case server, port, transport
        case importedAt = "imported_at"
    }
}

/// A network the Mac joined, identified by its router (`gw:<router MAC>`).
public struct NetworkInfo: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    /// Wi-Fi name when macOS reveals it, else `Ethernet` / interface name.
    public let name: String
    public let interface: String
    public let gatewayIp: String?
    public let gatewayMac: String?
    public let ssid: String?
    /// Wi-Fi security as reported by macOS (`WPA2 Personal`, `None`…), when known.
    public let security: String?
    public let trusted: Bool
    public let firstSeen: Int64
    public let lastSeen: Int64
    /// The Mac is on this network right now.
    public let current: Bool

    public var lastSeenDate: Date { Date(unixSeconds: lastSeen) }

    enum CodingKeys: String, CodingKey {
        case id, name, interface
        case gatewayIp = "gateway_ip"
        case gatewayMac = "gateway_mac"
        case ssid, security, trusted
        case firstSeen = "first_seen"
        case lastSeen = "last_seen"
        case current
    }
}

/// One check of a leak test.
public struct LeakCheck: Codable, Sendable, Hashable, Identifiable {
    /// `tunnel`, `ipv4`, `ipv6`, `dns`, `kill_switch`.
    public let id: String
    public let ok: Bool
    /// What was observed (French).
    public let detail: String

    enum CodingKeys: String, CodingKey {
        case id, ok, detail
    }
}

public struct LeakTestResult: Codable, Sendable, Hashable {
    public let ts: Int64
    /// Every check passed.
    public let ok: Bool
    public let vpnConnected: Bool
    public let publicIpv4: String?
    public let publicIpv6: String?
    /// Public IPv4 of this network without the VPN (remembered per network).
    public let homeIpv4: String?
    public let dnsServers: [String]
    public let checks: [LeakCheck]

    public var date: Date { Date(unixSeconds: ts) }

    enum CodingKeys: String, CodingKey {
        case ts, ok
        case vpnConnected = "vpn_connected"
        case publicIpv4 = "public_ipv4"
        case publicIpv6 = "public_ipv6"
        case homeIpv4 = "home_ipv4"
        case dnsServers = "dns_servers"
        case checks
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        ts = try c.decode(Int64.self, forKey: .ts)
        ok = try c.decode(Bool.self, forKey: .ok)
        vpnConnected = try c.decode(Bool.self, forKey: .vpnConnected)
        publicIpv4 = try c.decodeIfPresent(String.self, forKey: .publicIpv4)
        publicIpv6 = try c.decodeIfPresent(String.self, forKey: .publicIpv6)
        homeIpv4 = try c.decodeIfPresent(String.self, forKey: .homeIpv4)
        dnsServers = try c.decodeOr(.dnsServers, [String]())
        checks = try c.decodeOr(.checks, [LeakCheck]())
    }
}

/// A VPN configured in macOS (Network settings), as listed by `scutil --nc list`.
public struct ExternalVpnService: Codable, Sendable, Hashable, Identifiable {
    public let name: String
    /// Provider bundle id (`com.liguangming.Shadowrocket`…), when shown.
    public let provider: String?
    public let state: VpnState

    public var id: String { name }

    enum CodingKeys: String, CodingKey {
        case name, provider, state
    }
}

public struct VpnStatus: Codable, Sendable, Hashable {
    public let mode: VpnMode
    public let backend: VpnBackend
    public let state: VpnState
    /// The daemon wants the tunnel up right now (mode + network + manual override).
    public let wanted: Bool
    /// `true`: connected by hand; `false`: disconnected by hand until the next network change.
    public let manualOverride: Bool?
    public let profile: VpnProfileInfo?
    public let externalService: String?
    public let connectedSince: Int64?
    /// Tunnel interface (`utun5`).
    public let interface: String?
    public let killSwitch: KillSwitchState
    public let network: NetworkInfo?
    public let lastLeakTest: LeakTestResult?
    /// sing-box binary installed (backend `sing_box`).
    public let engineInstalled: Bool
    public let message: String?

    public var connectedSinceDate: Date? { connectedSince.map(Date.init(unixSeconds:)) }

    /// Internet is cut on purpose (kill switch with the tunnel down).
    public var isBlocking: Bool { killSwitch == .blocking }

    enum CodingKeys: String, CodingKey {
        case mode, backend, state, wanted
        case manualOverride = "manual_override"
        case profile
        case externalService = "external_service"
        case connectedSince = "connected_since"
        case interface
        case killSwitch = "kill_switch"
        case network
        case lastLeakTest = "last_leak_test"
        case engineInstalled = "engine_installed"
        case message
    }
}

// MARK: - Behaviour guard & snapshots

/// APFS local snapshot (`tmutil listlocalsnapshots /`).
public struct SnapshotInfo: Codable, Sendable, Hashable, Identifiable {
    /// Full name, e.g. `com.apple.TimeMachine.2026-10-29-120000.local`.
    public let name: String
    public let createdAt: Int64?
    /// Created by Parabellum (vs. Time Machine / the system).
    public let ours: Bool

    public var id: String { name }
    public var createdDate: Date? { createdAt.map(Date.init(unixSeconds:)) }

    enum CodingKeys: String, CodingKey {
        case name
        case createdAt = "created_at"
        case ours
    }
}

public struct SuspendedProcess: Codable, Sendable, Hashable, Identifiable {
    public let pid: Int
    public let path: String
    public let since: Int64
    public let alertId: Int64?

    public var id: Int { pid }
    public var sinceDate: Date { Date(unixSeconds: since) }

    enum CodingKeys: String, CodingKey {
        case pid, path, since
        case alertId = "alert_id"
    }
}

public struct GuardStatus: Codable, Sendable, Hashable {
    public let stealerDetection: Bool
    public let ransomwareDetection: Bool
    /// Decoy files in place.
    public let canaries: [String]
    public let snapshotsEnabled: Bool
    public let lastSnapshot: Int64?
    public let snapshotError: String?
    /// Processes suspended by Parabellum, waiting for a decision.
    public let suspended: [SuspendedProcess]
    /// Detections in the last 7 days.
    public let detections7d: Int

    public var lastSnapshotDate: Date? { lastSnapshot.map(Date.init(unixSeconds:)) }

    enum CodingKeys: String, CodingKey {
        case stealerDetection = "stealer_detection"
        case ransomwareDetection = "ransomware_detection"
        case canaries
        case snapshotsEnabled = "snapshots_enabled"
        case lastSnapshot = "last_snapshot"
        case snapshotError = "snapshot_error"
        case suspended
        case detections7d = "detections_7d"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        stealerDetection = try c.decode(Bool.self, forKey: .stealerDetection)
        ransomwareDetection = try c.decode(Bool.self, forKey: .ransomwareDetection)
        canaries = try c.decodeOr(.canaries, [String]())
        snapshotsEnabled = try c.decode(Bool.self, forKey: .snapshotsEnabled)
        lastSnapshot = try c.decodeIfPresent(Int64.self, forKey: .lastSnapshot)
        snapshotError = try c.decodeIfPresent(String.self, forKey: .snapshotError)
        suspended = try c.decodeOr(.suspended, [SuspendedProcess]())
        detections7d = try c.decodeOr(.detections7d, 0)
    }
}

/// `restore_from_snapshot` response: `{"restored_to": "…"}`.
public struct RestoredTo: Codable, Sendable, Hashable {
    public let restoredTo: String

    enum CodingKeys: String, CodingKey {
        case restoredTo = "restored_to"
    }
}

// MARK: - Privacy

/// The person data brokers must erase. Masked over IPC unless revealed with administrator approval.
public struct IdentityProfile: Codable, Sendable, Hashable {
    public var fullName: String = ""
    /// Every address brokers may know (the first one is the contact address).
    public var emails: [String] = []
    public var phones: [String] = []
    /// Current postal address (multi-line).
    public var postalAddress: String = ""
    public var previousAddresses: [String] = []
    /// `YYYY-MM-DD`, optional.
    public var birthDate: String = ""
    /// ISO country code of residence (`FR`): selects the supervisory authority (CNIL).
    public var country: String = ""

    public init() {}

    /// Name and at least one email: enough to start a campaign.
    public var isComplete: Bool {
        !fullName.trimmingCharacters(in: .whitespaces).isEmpty
            && emails.contains { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    /// Fields hold `*` masks (profile fetched without `reveal`).
    public var isMasked: Bool { fullName.contains("*") || emails.contains { $0.contains("*") } }

    enum CodingKeys: String, CodingKey {
        case fullName = "full_name"
        case emails, phones
        case postalAddress = "postal_address"
        case previousAddresses = "previous_addresses"
        case birthDate = "birth_date"
        case country
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        fullName = try c.decodeOr(.fullName, fullName)
        emails = try c.decodeOr(.emails, emails)
        phones = try c.decodeOr(.phones, phones)
        postalAddress = try c.decodeOr(.postalAddress, postalAddress)
        previousAddresses = try c.decodeOr(.previousAddresses, previousAddresses)
        birthDate = try c.decodeOr(.birthDate, birthDate)
        country = try c.decodeOr(.country, country)
    }
}

/// One organisation from the signed broker list (`privacy/brokers.json` in the threat DB).
public struct BrokerInfo: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let name: String
    /// Privacy / DPO address; brokers without one need the web form (`optOutUrl`).
    public let email: String?
    public let website: String?
    public let optOutUrl: String?
    /// `eu`, `global`, `us`.
    public let region: String
    /// `ads`, `addresses`, `credit`, `people-search`, `marketing`, `background-check`…
    public let category: String
    /// `datenanfragen` (CC0) or `eraser` (MIT).
    public let source: String

    enum CodingKeys: String, CodingKey {
        case id, name, email, website
        case optOutUrl = "opt_out_url"
        case region, category, source
    }
}

public enum RemovalStatus: String, TolerantEnum {
    case queued
    case draftReady = "draft_ready"
    case sent, reminded, escalated, completed, refused
    case needsForm = "needs_form"
    case failed
    case unknown
    public static let fallback: RemovalStatus = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }

    /// Statuses the user can set by hand (`privacy_update_request`).
    public static let settable: [RemovalStatus] = [.sent, .reminded, .completed, .refused, .needsForm, .queued]

    /// Closed: nothing more to do.
    public var isClosed: Bool { self == .completed || self == .refused }
}

public struct RemovalRequest: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let brokerId: String
    public let brokerName: String
    public let brokerEmail: String?
    public let status: RemovalStatus
    public let createdAt: Int64
    public let sentAt: Int64?
    /// Legal answer deadline (sent + one month).
    public let dueAt: Int64?
    public let remindedAt: Int64?
    public let closedAt: Int64?
    public let optOutUrl: String?
    public let draftPath: String?
    public let note: String?
    public let lastError: String?

    public var dueDate: Date? { dueAt.map(Date.init(unixSeconds:)) }
    public var sentDate: Date? { sentAt.map(Date.init(unixSeconds:)) }

    /// Answer deadline passed while the request is still waiting.
    public func isOverdue(now: Date = Date()) -> Bool {
        guard let due = dueDate else { return false }
        return due < now && (status == .sent || status == .reminded)
    }

    /// An email can be produced for it (first letter or reminder).
    public var canDraft: Bool {
        brokerEmail != nil && !status.isClosed && status != .needsForm && status != .unknown
    }

    enum CodingKeys: String, CodingKey {
        case id
        case brokerId = "broker_id"
        case brokerName = "broker_name"
        case brokerEmail = "broker_email"
        case status
        case createdAt = "created_at"
        case sentAt = "sent_at"
        case dueAt = "due_at"
        case remindedAt = "reminded_at"
        case closedAt = "closed_at"
        case optOutUrl = "opt_out_url"
        case draftPath = "draft_path"
        case note
        case lastError = "last_error"
    }
}

/// Counters of the removal campaign.
public struct RemovalSummary: Codable, Sendable, Hashable {
    public let total: Int
    public let queued: Int
    public let waitingAnswer: Int
    public let overdue: Int
    public let completed: Int
    public let needsAction: Int
    public let nextSendAt: Int64?

    enum CodingKeys: String, CodingKey {
        case total, queued
        case waitingAnswer = "waiting_answer"
        case overdue, completed
        case needsAction = "needs_action"
        case nextSendAt = "next_send_at"
    }
}

/// A ready-to-send email (drafts mode, reminders).
public struct MailDraft: Codable, Sendable, Hashable {
    public let requestId: String
    public let to: String
    public let subject: String
    /// Plain-text body (UTF-8, `\n` line breaks).
    public let body: String

    public init(requestId: String, to: String, subject: String, body: String) {
        self.requestId = requestId
        self.to = to
        self.subject = subject
        self.body = body
    }

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id"
        case to, subject, body
    }

    /// RFC 5322 message that Mail opens as a new message to send (`X-Unsent: 1`), same format as the CLI
    /// (`parabellum privacy drafts`): UTF-8 subject in an encoded word, base64 body in 76-column lines.
    public func emlData() -> Data {
        let subjectWord = "=?UTF-8?B?\(Data(subject.utf8).base64EncodedString())?="
        let crlfBody = body.replacingOccurrences(of: "\r\n", with: "\n").replacingOccurrences(of: "\n", with: "\r\n")
        let encoded = Data(crlfBody.utf8).base64EncodedString()
        var wrapped: [String] = []
        var index = encoded.startIndex
        while index < encoded.endIndex {
            let end = encoded.index(index, offsetBy: 76, limitedBy: encoded.endIndex) ?? encoded.endIndex
            wrapped.append(String(encoded[index..<end]))
            index = end
        }
        let headers = [
            "X-Unsent: 1",
            "To: \(to)",
            "Subject: \(subjectWord)",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=UTF-8",
            "Content-Transfer-Encoding: base64",
        ]
        let text = headers.joined(separator: "\r\n") + "\r\n\r\n" + wrapped.joined(separator: "\r\n") + "\r\n"
        return Data(text.utf8)
    }

    /// File name for the `.eml`: the broker name reduced to safe characters.
    public static func fileName(brokerName: String, requestId: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_"))
        let base = brokerName.unicodeScalars.map { allowed.contains($0) ? String($0) : "-" }.joined()
        let trimmed = base.trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        let prefix = String((trimmed.isEmpty ? "demande" : trimmed).prefix(60))
        return "\(prefix)-\(requestId.prefix(8)).eml"
    }
}

/// GDPR complaint draft for the supervisory authority.
public struct ComplaintDraft: Codable, Sendable, Hashable {
    public let authority: String
    /// Where to file it (CNIL online form).
    public let url: String
    public let text: String

    enum CodingKeys: String, CodingKey {
        case authority, url, text
    }
}

public struct BreachFinding: Codable, Sendable, Hashable, Identifiable {
    public let email: String
    public let breach: String
    public let breachDate: String?
    /// Exposed data classes (`Passwords`, `Email addresses`…), when the provider says.
    public let dataClasses: [String]
    public let firstSeen: Int64
    /// Seen for the first time by the last check.
    public let new: Bool

    public var id: String { "\(email)|\(breach)" }
    /// The breach exposed passwords: change it everywhere it was reused.
    public var exposesPasswords: Bool { dataClasses.contains { $0.lowercased().contains("password") } }

    enum CodingKeys: String, CodingKey {
        case email, breach
        case breachDate = "breach_date"
        case dataClasses = "data_classes"
        case firstSeen = "first_seen"
        case new
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        email = try c.decode(String.self, forKey: .email)
        breach = try c.decode(String.self, forKey: .breach)
        breachDate = try c.decodeIfPresent(String.self, forKey: .breachDate)
        dataClasses = try c.decodeOr(.dataClasses, [String]())
        firstSeen = try c.decode(Int64.self, forKey: .firstSeen)
        new = try c.decodeOr(.new, false)
    }
}

public struct EmailAlias: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let email: String
    /// What it is for (site name).
    public let label: String
    public let provider: AliasProvider
    public let createdAt: Int64
    public let active: Bool

    public var createdDate: Date { Date(unixSeconds: createdAt) }

    enum CodingKeys: String, CodingKey {
        case id, email, label, provider
        case createdAt = "created_at"
        case active
    }
}

// MARK: - Local tools (run by the app as the user, not by the daemon)

/// One file cleaned by `parabellum privacy clean --json`.
public struct CleanReport: Codable, Sendable, Hashable, Identifiable {
    public let input: String
    /// Cleaned copy (`<name>.clean.<ext>`), nil when nothing was written.
    public let output: String?
    /// What was removed (French), e.g. `GPS`.
    public let removed: [String]
    /// `native` or `exiftool`.
    public let method: String
    public let error: String?

    public var id: String { input }

    enum CodingKeys: String, CodingKey {
        case input, output, removed, method, error
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        input = try c.decode(String.self, forKey: .input)
        output = try c.decodeIfPresent(String.self, forKey: .output)
        removed = try c.decodeOr(.removed, [String]())
        method = try c.decodeOr(.method, "")
        error = try c.decodeIfPresent(String.self, forKey: .error)
    }
}

/// One leaked entry of `parabellum privacy password-check --csv … --json`.
public struct LeakedPasswordEntry: Codable, Sendable, Hashable, Identifiable {
    public let name: String
    public let url: String
    public let username: String
    /// Times the password appears in known breaches.
    public let count: Int

    public var id: String { "\(name)|\(url)|\(username)" }

    enum CodingKeys: String, CodingKey {
        case name, url, username, count
    }
}
