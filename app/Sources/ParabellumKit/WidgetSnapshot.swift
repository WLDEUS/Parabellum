import Foundation

/// What the desktop widget shows. Written by the app (as the user) into the widget's own sandbox container
/// — the only place a sandboxed widget can read without an App Group (which needs a paid Team ID) — and read
/// by the widget from its home directory. Foundation-only: this file is also compiled into the widget
/// extension by `scripts/build-widget.sh`.
public struct WidgetSnapshot: Codable, Sendable, Hashable {
    /// `active`, `paused`, `degraded`, `unreachable`.
    public var protection: String
    /// French, e.g. `Protection active`.
    public var protectionLabel: String
    public var openAlerts: Int
    /// French VPN state (`connecté`, `déconnecté`…); nil when no VPN is configured.
    public var vpnLabel: String?
    public var vpnConnected: Bool
    public var travelActive: Bool
    /// Unix time of the last finished scan.
    public var lastScan: Int64?
    /// Unix time this snapshot was written.
    public var updatedAt: Int64

    public init(
        protection: String,
        protectionLabel: String,
        openAlerts: Int,
        vpnLabel: String?,
        vpnConnected: Bool,
        travelActive: Bool,
        lastScan: Int64?,
        updatedAt: Int64
    ) {
        self.protection = protection
        self.protectionLabel = protectionLabel
        self.openAlerts = openAlerts
        self.vpnLabel = vpnLabel
        self.vpnConnected = vpnConnected
        self.travelActive = travelActive
        self.lastScan = lastScan
        self.updatedAt = updatedAt
    }

    enum CodingKeys: String, CodingKey {
        case protection
        case protectionLabel = "protection_label"
        case openAlerts = "open_alerts"
        case vpnLabel = "vpn_label"
        case vpnConnected = "vpn_connected"
        case travelActive = "travel_active"
        case lastScan = "last_scan"
        case updatedAt = "updated_at"
    }

    /// Bundle identifier of the widget extension (must start with the app's).
    public static let widgetBundleId = "com.wldeus.parabellum.widget"
    public static let fileName = "widget-status.json"

    /// The widget's container data directory, seen from the (non-sandboxed) app. It exists only once macOS
    /// has run the widget (added to the desktop / Notification Center); the app never creates it.
    public static func containerDataDirectory(home: URL) -> URL {
        home.appendingPathComponent("Library/Containers", isDirectory: true)
            .appendingPathComponent(widgetBundleId, isDirectory: true)
            .appendingPathComponent("Data", isDirectory: true)
    }

    public static let placeholder = WidgetSnapshot(
        protection: "active",
        protectionLabel: "Protection active",
        openAlerts: 0,
        vpnLabel: "connecté",
        vpnConnected: true,
        travelActive: false,
        lastScan: nil,
        updatedAt: 0
    )
}
