import AppKit
import ParabellumKit
import SwiftUI

// Travel mode ("Mode Voyage") and shortcuts: menu bar card, dashboard tile, VPN section card, settings.

/// Prominent glass card of the menu bar window: one switch for travel mode.
struct TravelMenuCard: View {
    @ObservedObject var store: TravelStore

    var body: some View {
        let active = store.isActive
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                Image(systemName: active ? "airplane.circle.fill" : "airplane.circle")
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(active ? Brand.cyan : Color.secondary)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Mode Voyage")
                        .font(.system(.headline, design: .rounded))
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
                Spacer(minLength: 4)
                if store.isBusy {
                    ProgressView().controlSize(.small)
                }
                Toggle("Mode Voyage", isOn: Binding(
                    get: { store.isActive },
                    set: { _ in Task { await store.toggle() } }
                ))
                .labelsHidden()
                .toggleStyle(.switch)
                .disabled(store.isBusy)
            }
            if !active && store.onUntrustedNetwork {
                Label("Réseau non approuvé : activez-le sur un Wi-Fi public", systemImage: "wifi.exclamationmark")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(12)
        .glassSurface(cornerRadius: 18, tint: cardTint)
        .task { await store.load() }
    }

    private var cardTint: Color? {
        if store.isActive {
            return Brand.cyan
        }
        return store.onUntrustedNetwork ? Color.orange : nil
    }

    private var subtitle: String {
        guard let status = store.status, status.active else {
            return "VPN, coupe-circuit, DNS et coupe-feu furtif en un clic"
        }
        if let network = status.network {
            return "Actif\(status.automatic ? " (automatique)" : "") · \(network)"
        }
        return status.automatic ? "Actif (automatique)" : "Actif"
    }
}

/// Dashboard tile (tap = toggle).
struct TravelDashboardTile: View {
    @ObservedObject var store: TravelStore

    var body: some View {
        Button {
            Task { await store.toggle() }
        } label: {
            StatTile(
                value: store.isActive ? "Actif" : "Inactif",
                caption: store.isActive ? "Mode Voyage · toucher pour rétablir" : "Mode Voyage · toucher pour activer",
                symbol: "airplane",
                tint: store.isActive ? Brand.cyan : (store.onUntrustedNetwork ? .orange : Brand.accent)
            )
        }
        .buttonStyle(.plain)
        .disabled(store.isBusy)
        .help("Wi-Fi public : VPN permanent avec coupe-circuit, blocage DNS, coupe-feu furtif, AirDrop coupé")
        .task { await store.load() }
    }
}

/// Card of the VPN section: what travel mode does / did, and the switch.
struct TravelCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: TravelStore

    var body: some View {
        Card(title: "Mode Voyage", symbol: "airplane", content: {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    if let status = store.status, status.active {
                        Pill(text: status.automatic ? "Actif (automatique)" : "Actif", color: Brand.cyan, symbol: "checkmark.circle.fill")
                        if let since = status.sinceDate {
                            Text("depuis \(PBFormat.time(since))")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        Pill(text: "Inactif", color: .secondary)
                        if store.onUntrustedNetwork {
                            Pill(text: "Réseau non approuvé", color: .orange, symbol: "wifi.exclamationmark")
                        }
                    }
                    Spacer()
                    Button(store.isActive ? "Désactiver et rétablir" : "Activer") {
                        Task { await store.toggle() }
                    }
                    .buttonStyle(.brand)
                    .disabled(store.isBusy)
                }
                if let status = store.status, status.active, !status.changes.isEmpty {
                    ForEach(status.changes) { change in
                        Label(change.label, systemImage: "checkmark")
                            .font(.callout)
                    }
                } else {
                    Text(explanation)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(store.status?.warnings ?? [], id: \.self) { warning in
                    Label(warning, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                if let message = store.status?.message {
                    Text(message).font(.caption).foregroundStyle(.secondary)
                }
                if let message = store.localMessage {
                    Text(message).font(.caption).foregroundStyle(.secondary)
                }
            }
        }, tint: Brand.cyan)
        .task { await store.load() }
    }

    private var explanation: String {
        let travel = model.config?.travel ?? TravelConfig()
        var items = ["VPN permanent avec coupe-circuit", "blocage DNS", "coupe-feu activé et furtif"]
        if travel.blockAllIncoming { items.append("connexions entrantes bloquées") }
        if travel.airdropOff { items.append("AirDrop coupé") }
        if travel.bluetoothOff { items.append("Bluetooth coupé") }
        return "Pour les Wi-Fi publics (gare, hôtel, café) : \(items.joined(separator: ", ")). La désactivation rétablit exactement vos réglages d'avant (ceux que vous avez changés entre-temps sont conservés)."
    }
}

/// Settings: travel mode options (part of the config draft).
struct TravelSettingsSection: View {
    @Binding var travel: TravelConfig

    var body: some View {
        Section {
            Toggle("Proposer le mode Voyage sur un réseau non approuvé", isOn: $travel.suggestOnUntrusted)
            Toggle("L'activer automatiquement sur un réseau non approuvé", isOn: $travel.autoEnable)
            Toggle("Bloquer toutes les connexions entrantes (plus strict)", isOn: $travel.blockAllIncoming)
            Toggle("Couper AirDrop", isOn: $travel.airdropOff)
            Toggle("Couper le Bluetooth (déconnecte AirPods, claviers, souris)", isOn: $travel.bluetoothOff)
        } header: {
            Text("Mode Voyage")
        } footer: {
            Text("Activé automatiquement, il est rétabli dès le retour sur un réseau approuvé (VPN > Réseaux).")
        }
    }
}

/// Settings: ready-to-copy links and commands for the Shortcuts app, Raycast, Alfred, scripts.
struct ShortcutsSettingsSection: View {
    @EnvironmentObject private var model: AppModel

    private static let commands: [(title: String, command: String)] = [
        ("État de la protection", "/usr/local/bin/parabellum status"),
        ("Analyser un dossier", "/usr/local/bin/parabellum scan ~/Downloads"),
        ("Mode Voyage", "/usr/local/bin/parabellum travel on"),
        ("Connecter le VPN", "/usr/local/bin/parabellum vpn connect"),
        ("État en JSON (pour un script)", "/usr/local/bin/parabellum --json status"),
    ]

    var body: some View {
        Section {
            Text("Dans l'app Raccourcis : action « Ouvrir l'URL » avec un lien ci-dessous, ou « Exécuter un script shell » avec une commande. Les actions qui réduisent la protection demandent toujours votre mot de passe.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            ForEach(ParabellumURL.examples, id: \.url) { example in
                copyRow(title: example.title, value: example.url)
            }
            ForEach(Self.commands, id: \.command) { item in
                copyRow(title: item.title, value: item.command)
            }
            HStack {
                Spacer()
                Button("Ouvrir Raccourcis") {
                    openShortcuts()
                }
            }
        } header: {
            Text("Raccourcis")
        }
    }

    private func copyRow(title: String, value: String) -> some View {
        LabeledContent(title) {
            HStack(spacing: 6) {
                Text(value)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Button {
                    model.copyToPasteboard(value)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copier")
            }
        }
    }

    private func openShortcuts() {
        if let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.shortcuts") {
            NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration(), completionHandler: nil)
        } else {
            model.open(urlString: "shortcuts://")
        }
    }
}
