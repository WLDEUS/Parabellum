import ParabellumKit
import SwiftUI

struct DevicesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showDisconnected = true

    private var visibleDevices: [DeviceInfo] {
        showDisconnected ? model.devices : model.devices.filter { $0.connected }
    }

    private var groups: [(kind: DeviceKind, devices: [DeviceInfo])] {
        let byKind = Dictionary(grouping: visibleDevices) { $0.kind }
        return DeviceKind.displayOrder.compactMap { (kind: DeviceKind) -> (kind: DeviceKind, devices: [DeviceInfo])? in
            guard let devices = byKind[kind], !devices.isEmpty else { return nil }
            let sorted = devices.sorted { lhs, rhs in
                if lhs.connected != rhs.connected {
                    return lhs.connected
                }
                return lhs.lastSeen > rhs.lastSeen
            }
            return (kind: kind, devices: sorted)
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Toggle("Afficher les périphériques déconnectés", isOn: $showDisconnected)
                    .toggleStyle(.checkbox)
                Spacer()
                let unknownKeyboards = model.devices.filter { $0.kind == .hid && $0.trust == .unknown && !$0.baseline }.count
                if unknownKeyboards > 0 {
                    Label("\(unknownKeyboards) clavier(s)/HID non vérifié(s)", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                }
            }
            .padding(10)
            Divider()
            if groups.isEmpty {
                ContentUnavailableView(
                    "Aucun périphérique",
                    systemImage: "cable.connector",
                    description: Text("Volumes, claviers, USB, Bluetooth, Thunderbolt, interfaces et réseaux Wi-Fi apparaîtront ici.")
                )
            } else {
                List {
                    ForEach(groups, id: \.kind) { group in
                        Section {
                            ForEach(group.devices) { device in
                                DeviceRow(device: device)
                            }
                        } header: {
                            Label(group.kind.label, systemImage: group.kind.symbol)
                        }
                    }
                }
            }
        }
        .navigationTitle("Périphériques")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("devices")) {
                    Task { await model.loadDevices() }
                }
            }
        }
        .task {
            await model.loadDevices()
        }
    }
}

private struct DeviceRow: View {
    @EnvironmentObject private var model: AppModel
    let device: DeviceInfo
    @State private var showDetails = false

    /// Unknown, non-baseline keyboards / HID: possible BadUSB.
    private var needsAttention: Bool {
        device.kind == .hid && device.trust == .unknown && !device.baseline
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Circle()
                    .fill(device.connected ? Color.green : Color.gray.opacity(0.5))
                    .frame(width: 8, height: 8)
                    .help(device.connected ? "Connecté" : "Déconnecté")
                Image(systemName: device.kind.symbol)
                    .foregroundStyle(needsAttention ? Color.orange : Color.secondary)
                Text(device.name).font(.headline)
                if let vendor = device.vendor {
                    Text(vendor).foregroundStyle(.secondary)
                }
                if let usb = device.usbIdentifier {
                    Text(usb)
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                }
                Spacer()
                if device.baseline {
                    Text("présent à l'installation")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                Pill(text: device.trust.label, color: device.trust.color)
            }
            HStack(spacing: 12) {
                if let transport = device.transport {
                    Text(transport).font(.caption).foregroundStyle(.secondary)
                }
                Text("Vu la première fois \(PBFormat.dateTime(device.firstSeenDate)) · dernière fois \(PBFormat.relative(device.lastSeenDate))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if !device.details.isEmpty {
                    Button(showDetails ? "Masquer les détails" : "Détails") {
                        showDetails.toggle()
                    }
                    .buttonStyle(.link)
                    .font(.caption)
                }
                if device.trust != .trusted {
                    Button("Faire confiance") {
                        Task { await model.setDeviceTrust(device.id, trust: .trusted) }
                    }
                }
                if device.trust != .blocked {
                    Button("Bloquer", role: .destructive) {
                        Task { await model.setDeviceTrust(device.id, trust: .blocked) }
                    }
                }
            }
            .controlSize(.small)
            .disabled(model.isBusy("device-\(device.id)"))
            if showDetails {
                VStack(alignment: .leading, spacing: 2) {
                    InfoRow(label: "Identifiant", value: device.id, monospaced: true)
                    if let serial = device.serial {
                        InfoRow(label: "Numéro de série", value: serial, monospaced: true)
                    }
                    ForEach(device.details.keys.sorted(), id: \.self) { key in
                        InfoRow(label: key, value: device.details[key] ?? "", monospaced: true)
                    }
                }
                .font(.caption)
            }
        }
        .padding(8)
        .background(needsAttention ? Color.orange.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .strokeBorder(needsAttention ? Color.orange.opacity(0.6) : Color.clear, lineWidth: 1)
        }
    }
}
