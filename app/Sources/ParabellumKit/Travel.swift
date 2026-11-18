import Foundation

// Travel mode ("Mode Voyage"): mirrors `TravelStatus` / `TravelItem` of `crates/pb-core/src/model.rs` and
// `TravelConfig` of `config.rs`, plus the pure rules of the per-user part (AirDrop, Bluetooth) the app applies.

/// One setting travel mode changed (and will put back).
public struct TravelItem: Codable, Sendable, Hashable, Identifiable {
    /// `vpn_mode`, `kill_switch`, `dns`, `firewall`, `stealth`, `block_all`.
    public let id: String
    public let label: String

    public init(id: String, label: String) {
        self.id = id
        self.label = label
    }
}

public struct TravelStatus: Codable, Sendable, Hashable {
    public let active: Bool
    public let since: Int64?
    /// Enabled by the daemon on an untrusted network, not by hand.
    public let automatic: Bool
    /// Name of the network it was enabled on.
    public let network: String?
    public let changes: [TravelItem]
    public let warnings: [String]
    /// Outcome of the last change (settings kept because you changed them meanwhile…).
    public let message: String?
    /// The Mac is on a network that is not trusted right now.
    public let untrustedNetwork: Bool

    public var sinceDate: Date? { since.map(Date.init(unixSeconds:)) }

    enum CodingKeys: String, CodingKey {
        case active, since, automatic, network, changes, warnings, message
        case untrustedNetwork = "untrusted_network"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        active = try c.decode(Bool.self, forKey: .active)
        since = try c.decodeIfPresent(Int64.self, forKey: .since)
        automatic = try c.decodeOr(.automatic, false)
        network = try c.decodeIfPresent(String.self, forKey: .network)
        changes = try c.decodeOr(.changes, [TravelItem]())
        warnings = try c.decodeOr(.warnings, [String]())
        message = try c.decodeIfPresent(String.self, forKey: .message)
        untrustedNetwork = try c.decodeOr(.untrustedNetwork, false)
    }
}

/// `[travel]` section.
public struct TravelConfig: Codable, Sendable, Hashable {
    /// Alert offering travel mode on networks that are not trusted.
    public var suggestOnUntrusted: Bool = true
    /// Enable it by itself on untrusted networks (restored when back on a trusted one).
    public var autoEnable: Bool = false
    /// The firewall also blocks every incoming connection (AirPlay receiver, sharing…).
    public var blockAllIncoming: Bool = false
    /// Turn AirDrop off while travelling (the app does it, as you).
    public var airdropOff: Bool = true
    /// Turn Bluetooth off while travelling (disconnects AirPods, keyboards, mice).
    public var bluetoothOff: Bool = false

    public init() {}

    enum CodingKeys: String, CodingKey {
        case suggestOnUntrusted = "suggest_on_untrusted"
        case autoEnable = "auto_enable"
        case blockAllIncoming = "block_all_incoming"
        case airdropOff = "airdrop_off"
        case bluetoothOff = "bluetooth_off"
    }

    public init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        suggestOnUntrusted = try c.decodeOr(.suggestOnUntrusted, suggestOnUntrusted)
        autoEnable = try c.decodeOr(.autoEnable, autoEnable)
        blockAllIncoming = try c.decodeOr(.blockAllIncoming, blockAllIncoming)
        airdropOff = try c.decodeOr(.airdropOff, airdropOff)
        bluetoothOff = try c.decodeOr(.bluetoothOff, bluetoothOff)
    }
}

// MARK: - Per-user part (AirDrop, Bluetooth)

/// The per-user settings travel mode touches. `nil` = unknown / not readable.
public struct TravelLocalSettings: Codable, Sendable, Hashable {
    /// `com.apple.sharingd DiscoverableMode`: `Off`, `Contacts Only`, `Everyone`.
    public var airdropMode: String?
    public var bluetoothOn: Bool?

    public init(airdropMode: String? = nil, bluetoothOn: Bool? = nil) {
        self.airdropMode = airdropMode
        self.bluetoothOn = bluetoothOn
    }

    public static let airdropOffValue = "Off"
}

/// Saved by the app (UserDefaults) while travel mode is on, so it survives a restart of the app.
public struct TravelLocalSnapshot: Codable, Sendable, Hashable {
    /// `TravelStatus.since` of the session it belongs to.
    public var session: Int64
    public var before: TravelLocalSettings
    public var applied: TravelLocalSettings

    public init(session: Int64, before: TravelLocalSettings, applied: TravelLocalSettings) {
        self.session = session
        self.before = before
        self.applied = applied
    }
}

/// Same rules as the daemon (`plan_enable` / `plan_restore` in `travel.rs`).
public enum TravelLocalPlan {
    /// Target values; unknown current values are left alone.
    public static func enable(current: TravelLocalSettings, config: TravelConfig) -> TravelLocalSettings {
        var t = current
        if config.airdropOff, current.airdropMode != nil {
            t.airdropMode = TravelLocalSettings.airdropOffValue
        }
        if config.bluetoothOff, current.bluetoothOn != nil {
            t.bluetoothOn = false
        }
        return t
    }

    /// What to set back: the previous value of each setting travel mode changed, unless you changed it since.
    public static func restore(
        before: TravelLocalSettings,
        applied: TravelLocalSettings,
        current: TravelLocalSettings
    ) -> (target: TravelLocalSettings, kept: [String]) {
        var t = current
        var kept: [String] = []
        if before.airdropMode != applied.airdropMode, current.airdropMode != before.airdropMode {
            if current.airdropMode == applied.airdropMode || current.airdropMode == nil {
                t.airdropMode = before.airdropMode
            } else {
                kept.append("AirDrop")
            }
        }
        if before.bluetoothOn != applied.bluetoothOn, current.bluetoothOn != before.bluetoothOn {
            if current.bluetoothOn == applied.bluetoothOn || current.bluetoothOn == nil {
                t.bluetoothOn = before.bluetoothOn
            } else {
                kept.append("Bluetooth")
            }
        }
        return (t, kept)
    }
}
