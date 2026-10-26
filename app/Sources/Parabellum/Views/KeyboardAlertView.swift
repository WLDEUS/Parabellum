import ParabellumKit
import SwiftUI

/// Content of the floating BadUSB panel. Mouse only: no keyboard shortcut on any button.
struct KeyboardAlertView: View {
    let device: DeviceInfo
    let onTrust: () -> Void
    let onBlock: () -> Void
    let onLater: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "keyboard.fill")
                    .font(.system(size: 34))
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 6) {
                    Text("Nouveau clavier détecté : \(device.name)\(vendorSuffix)")
                        .font(.headline)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("C'est toi qui l'as branché ?")
                        .font(.title3.weight(.semibold))
                    Text("Un périphérique qui se déclare clavier peut taper des commandes à ta place (attaque BadUSB). Réponds avec la souris.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if let details = technicalDetails {
                        Text(details)
                            .font(.caption.monospaced())
                            .foregroundStyle(.tertiary)
                    }
                }
            }
            HStack {
                Button("Plus tard", action: onLater)
                    .buttonStyle(.link)
                Spacer()
                Button(role: .destructive, action: onBlock) {
                    Label("Bloquer", systemImage: "hand.raised.fill")
                        .padding(.horizontal, 6)
                }
                .controlSize(.large)
                Button(action: onTrust) {
                    Label("Faire confiance", systemImage: "checkmark")
                        .padding(.horizontal, 6)
                }
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(22)
        .frame(width: 460)
    }

    private var vendorSuffix: String {
        guard let vendor = device.vendor, !vendor.isEmpty else { return "" }
        return " (\(vendor))"
    }

    private var technicalDetails: String? {
        var parts: [String] = []
        if let usb = device.usbIdentifier {
            parts.append(usb)
        }
        if let transport = device.transport {
            parts.append(transport)
        }
        if let serial = device.serial {
            parts.append("n° \(serial)")
        }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }
}
