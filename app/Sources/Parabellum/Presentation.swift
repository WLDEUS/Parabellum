import ParabellumKit
import SwiftUI

// Colors and SF Symbols for model enums (French labels live in ParabellumKit/Labels.swift).

extension Verdict {
    var color: Color {
        switch self {
        case .clean: return .green
        case .suspicious: return .orange
        case .malicious: return .red
        case .unknown: return .gray
        }
    }

    var symbol: String {
        switch self {
        case .clean: return "checkmark.seal.fill"
        case .suspicious: return "exclamationmark.triangle.fill"
        case .malicious: return "xmark.octagon.fill"
        case .unknown: return "questionmark.circle"
        }
    }
}

extension Severity {
    var color: Color {
        switch self {
        case .info: return .blue
        case .low: return .teal
        case .medium: return .yellow
        case .high: return .orange
        case .critical: return .red
        case .unknown: return .gray
        }
    }

    var symbol: String {
        switch self {
        case .info: return "info.circle.fill"
        case .low: return "exclamationmark.circle"
        case .medium: return "exclamationmark.circle.fill"
        case .high: return "exclamationmark.triangle.fill"
        case .critical: return "xmark.octagon.fill"
        case .unknown: return "questionmark.circle"
        }
    }
}

extension ProtectionState {
    var color: Color {
        switch self {
        case .active: return .green
        case .paused: return .gray
        case .degraded: return .orange
        case .unknown: return .gray
        }
    }

    var symbol: String {
        switch self {
        case .active: return "checkmark.shield.fill"
        case .paused: return "pause.circle.fill"
        case .degraded: return "exclamationmark.shield.fill"
        case .unknown: return "shield"
        }
    }
}

extension ComponentState {
    var color: Color {
        switch self {
        case .installed: return .green
        case .updateAvailable, .updating: return .blue
        case .needsUserAction: return .orange
        case .error: return .red
        case .notInstalled, .disabled, .unknown: return .gray
        }
    }
}

extension ExtensionState {
    var color: Color {
        switch self {
        case .enabled: return .green
        case .installedDisabled: return .orange
        case .notInstalled: return .red
        case .unknown: return .gray
        }
    }

    var symbol: String {
        switch self {
        case .enabled: return "checkmark.circle.fill"
        case .installedDisabled: return "pause.circle.fill"
        case .notInstalled: return "xmark.circle.fill"
        case .unknown: return "questionmark.circle"
        }
    }
}

extension AlertKind {
    var symbol: String {
        switch self {
        case .malware: return "ladybug.fill"
        case .suspicious: return "exclamationmark.triangle"
        case .persistence: return "arrow.triangle.2.circlepath"
        case .device: return "cable.connector"
        case .network: return "network"
        case .update: return "arrow.down.circle"
        case .system: return "gearshape"
        case .unknown: return "bell"
        }
    }
}

extension DeviceKind {
    var symbol: String {
        switch self {
        case .volume: return "externaldrive"
        case .hid: return "keyboard"
        case .usb: return "cable.connector"
        case .bluetooth: return "antenna.radiowaves.left.and.right"
        case .networkInterface: return "network"
        case .thunderbolt: return "bolt.horizontal"
        case .wifiNetwork: return "wifi"
        case .unknown: return "questionmark.circle"
        }
    }

    /// Display order of the device sections (keyboards first: BadUSB).
    static let displayOrder: [DeviceKind] = [
        .hid, .volume, .usb, .thunderbolt, .bluetooth, .networkInterface, .wifiNetwork, .unknown,
    ]
}

extension DeviceTrust {
    var color: Color {
        switch self {
        case .unknown: return .orange
        case .trusted: return .green
        case .blocked: return .red
        }
    }
}

extension PersistenceStatus {
    var color: Color {
        switch self {
        case .new: return .orange
        case .approved, .baseline: return .green
        case .removed, .quarantined: return .gray
        case .unknown: return .gray
        }
    }
}

extension JobState {
    var color: Color {
        switch self {
        case .queued, .running: return .blue
        case .finished: return .green
        case .cancelled: return .gray
        case .failed: return .red
        case .unknown: return .gray
        }
    }
}

extension SigningInfo {
    /// One-line French summary.
    var summary: String {
        if !signed {
            return "Non signé"
        }
        if !valid {
            return "Signature invalide"
        }
        if apple {
            return "Signé par Apple"
        }
        if adhoc {
            return "Signature ad hoc"
        }
        var parts: [String] = []
        if let authority {
            parts.append(authority)
        } else if let teamId {
            parts.append("Team ID \(teamId)")
        } else {
            parts.append("Signé")
        }
        if let notarized {
            parts.append(notarized ? "notarisé" : "non notarisé")
        }
        return parts.joined(separator: " · ")
    }

    var isTrustworthy: Bool {
        signed && valid && !adhoc && (apple || notarized == true)
    }
}
