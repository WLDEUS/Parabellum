import ParabellumKit
import SwiftUI

/// VPN: state, profile, kill switch, leak test and known networks.
struct VpnView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showImport = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let status = model.vpnStatus {
                    VpnStatusCard(status: status)
                    if status.backend == .singBox {
                        VpnProfileCard(status: status, showImport: $showImport)
                    } else {
                        VpnExternalCard(status: status)
                    }
                    LeakTestCard(result: status.lastLeakTest)
                } else if model.isBusy("vpn-status") {
                    ProgressView("Chargement…").padding(40)
                } else {
                    ContentUnavailableView("État du VPN indisponible", systemImage: "lock.shield")
                }
                NetworksCard()
            }
            .padding(20)
        }
        .navigationTitle("VPN")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("vpn-status") || model.isBusy("networks")) {
                    Task { await model.loadVpn() }
                }
            }
        }
        .sheet(isPresented: $showImport) {
            VpnImportSheet()
                .environmentObject(model)
        }
        .task {
            await model.loadVpn()
        }
    }
}

private struct VpnStatusCard: View {
    @EnvironmentObject private var model: AppModel
    let status: VpnStatus

    var body: some View {
        Card(title: "Tunnel", symbol: "lock.shield") {
            VStack(alignment: .leading, spacing: 10) {
                header
                details
                if let message = status.message, !message.isEmpty {
                    Label(message, systemImage: status.state == .error ? "exclamationmark.triangle.fill" : "info.circle")
                        .font(.callout)
                        .foregroundStyle(status.state == .error ? Color.orange : Color.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if status.isBlocking {
                    Label(
                        "Le kill switch coupe Internet tant que le tunnel n'est pas rétabli. Déconnecte le VPN pour retrouver l'accès direct.",
                        systemImage: "hand.raised.fill"
                    )
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                }
                buttons
            }
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: status.state.symbol)
                .font(.system(size: 34))
                .foregroundStyle(status.state.color)
            VStack(alignment: .leading, spacing: 4) {
                Text(status.state.label)
                    .font(.title2.weight(.semibold))
                HStack(spacing: 6) {
                    Pill(text: status.mode.label, color: .secondary)
                    Pill(text: "Kill switch : \(status.killSwitch.label)", color: status.killSwitch.color)
                    if let manual = status.manualOverride {
                        Pill(text: manual ? "Connecté à la main" : "Coupé à la main", color: .blue)
                    }
                }
            }
        }
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 6) {
            InfoRow(label: "Moteur", value: status.backend.label)
            if let since = status.connectedSinceDate {
                InfoRow(label: "Connecté depuis", value: PBFormat.relative(since))
            }
            if let interface = status.interface {
                InfoRow(label: "Interface", value: interface, monospaced: true)
            }
            if let network = status.network {
                InfoRow(label: "Réseau actuel", value: network.trusted ? "\(network.name) (de confiance)" : "\(network.name) (non fiable)")
            }
            if status.backend == .singBox && !status.engineInstalled {
                Label("sing-box sera téléchargé (version épinglée et vérifiée) à la première connexion.", systemImage: "arrow.down.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var buttons: some View {
        HStack(spacing: 10) {
            if status.state == .connected || status.state == .connecting || status.wanted {
                Button {
                    Task { await model.vpnDisconnect() }
                } label: {
                    Label("Déconnecter", systemImage: "lock.fill")
                }
                .disabled(model.isBusy("vpn-disconnect"))
                .help("Couper le VPN demande une autorisation administrateur")
            }
            if status.state != .connected {
                Button {
                    Task { await model.vpnConnect() }
                } label: {
                    if model.isBusy("vpn-connect") {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("Connecter", systemImage: "power")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isBusy("vpn-connect") || !canConnect)
            }
            Button {
                Task { await model.runLeakTest() }
            } label: {
                if model.isBusy("vpn-leak") {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Tester les fuites", systemImage: "drop.triangle")
                }
            }
            .disabled(model.isBusy("vpn-leak"))
            Spacer()
            Button("Réglages du VPN") {
                model.section = .settings
            }
            .buttonStyle(.link)
        }
    }

    private var canConnect: Bool {
        switch status.backend {
        case .singBox: return status.profile != nil
        case .external: return status.externalService != nil
        }
    }
}

private struct VpnProfileCard: View {
    @EnvironmentObject private var model: AppModel
    let status: VpnStatus
    @Binding var showImport: Bool
    @State private var confirmRemove = false

    var body: some View {
        Card(title: "Serveur (sing-box)", symbol: "server.rack") {
            VStack(alignment: .leading, spacing: 8) {
                if let profile = status.profile {
                    InfoRow(label: "Nom", value: profile.name)
                    InfoRow(label: "Protocole", value: profile.protocolName)
                    InfoRow(label: "Serveur", value: "\(profile.server):\(profile.port)", monospaced: true)
                    if let transport = profile.transport {
                        InfoRow(label: "Transport", value: transport)
                    }
                    InfoRow(label: "Importé", value: PBFormat.dateTime(profile.importedDate))
                } else {
                    Text("Aucun serveur importé. Colle le lien de partage de ton nœud (celui que tu utilises dans Shadowrocket fonctionne : ss://, vless://, vmess://, trojan://, hysteria2://, tuic://, wireguard://), un abonnement, ou importe un fichier WireGuard .conf.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 10) {
                    Button {
                        showImport = true
                    } label: {
                        Label("Coller un lien…", systemImage: "link")
                    }
                    Button {
                        model.pickAndImportVpnFile()
                    } label: {
                        Label("Importer un fichier…", systemImage: "doc.badge.plus")
                    }
                    if status.profile != nil {
                        Button(role: .destructive) {
                            confirmRemove = true
                        } label: {
                            Label("Supprimer", systemImage: "trash")
                        }
                    }
                }
                .disabled(model.isBusy("vpn-import") || model.isBusy("vpn-remove"))
                Text("Le profil (clés comprises) reste dans le dossier du service, lisible par root uniquement. Importer ou supprimer un profil demande une autorisation administrateur.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .confirmationDialog("Supprimer le profil VPN ?", isPresented: $confirmRemove) {
            Button("Supprimer", role: .destructive) {
                Task { await model.removeVpnProfile() }
            }
            Button("Annuler", role: .cancel) {}
        }
    }
}

private struct VpnExternalCard: View {
    @EnvironmentObject private var model: AppModel
    let status: VpnStatus

    var body: some View {
        Card(title: "VPN macOS piloté", symbol: "switch.2") {
            VStack(alignment: .leading, spacing: 8) {
                if let service = status.externalService {
                    InfoRow(label: "Service", value: service)
                } else {
                    Text("Aucun service choisi. Dans Réglages › VPN, choisis le VPN déjà configuré dans macOS (Shadowrocket, WireGuard…).")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !model.externalVpnServices.isEmpty {
                    Divider()
                    Text("VPN configurés dans macOS").font(.subheadline.weight(.semibold))
                    ForEach(model.externalVpnServices) { service in
                        HStack {
                            Text(service.name)
                            if let provider = service.provider {
                                Text(provider).font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(service.state.label).foregroundStyle(service.state.color)
                        }
                    }
                }
                Text("Avec un VPN externe, renseigne aussi l'adresse de son serveur dans les réglages pour que le kill switch le laisse passer.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .task {
            await model.loadExternalVpnServices()
        }
    }
}

private struct LeakTestCard: View {
    let result: LeakTestResult?

    var body: some View {
        Card(title: "Dernier test de fuite", symbol: "drop.triangle") {
            if let result {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 8) {
                        Image(systemName: result.ok ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                            .foregroundStyle(result.ok ? Color.green : Color.orange)
                        Text(result.ok ? "Aucune fuite détectée" : "Point(s) à corriger")
                            .font(.headline)
                        Spacer()
                        Text(PBFormat.relative(result.date))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    ForEach(result.checks) { check in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: check.ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(check.ok ? Color.green : Color.red)
                            Text(PrivacyLabels.leakCheck(check.id))
                                .frame(width: 90, alignment: .leading)
                            Text(check.detail)
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    if let ip = result.publicIpv4 {
                        InfoRow(label: "IPv4 publique", value: ip, monospaced: true)
                    }
                    if let ip = result.publicIpv6 {
                        InfoRow(label: "IPv6 publique", value: ip, monospaced: true)
                    }
                    if let home = result.homeIpv4 {
                        InfoRow(label: "IPv4 sans VPN", value: home, monospaced: true)
                    }
                    if !result.dnsServers.isEmpty {
                        InfoRow(label: "Serveurs DNS", value: result.dnsServers.joined(separator: ", "), monospaced: true)
                    }
                }
            } else {
                Text("Pas encore de test. Il compare ton IP publique avec celle de ton réseau, vérifie IPv6, les DNS et le kill switch.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct NetworksCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Card(title: "Réseaux connus", symbol: "wifi") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Un réseau est reconnu par l'adresse matérielle de sa box (pas besoin de la localisation). En mode « réseaux non fiables », le VPN s'active partout sauf sur les réseaux de confiance. Parabellum signale aussi une usurpation de la box (ARP spoofing) ou un faux point d'accès.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if model.networks.isEmpty {
                    Text("Aucun réseau enregistré pour l'instant.").foregroundStyle(.secondary)
                } else {
                    ForEach(model.networks) { network in
                        NetworkRow(network: network)
                        if network.id != model.networks.last?.id {
                            Divider()
                        }
                    }
                }
            }
        }
    }
}

private struct NetworkRow: View {
    @EnvironmentObject private var model: AppModel
    let network: NetworkInfo

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: network.ssid != nil ? "wifi" : "cable.connector")
                .foregroundStyle(network.current ? Color.accentColor : Color.secondary)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(network.name).fontWeight(network.current ? .semibold : .regular)
                    if network.current {
                        Pill(text: "Actuel", color: .accentColor)
                    }
                    if let security = network.security {
                        Text(security).font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text("\(network.interface) · box \(network.gatewayIp ?? "?") · vu \(PBFormat.relative(network.lastSeenDate))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Toggle("De confiance", isOn: Binding(
                get: { network.trusted },
                set: { newValue in Task { await model.setNetworkTrust(network.id, trusted: newValue) } }
            ))
            .toggleStyle(.switch)
            .disabled(model.isBusy("network-\(network.id)"))
            .help("Faire confiance demande une autorisation administrateur")
        }
    }
}

/// Paste a share link, a subscription or a WireGuard configuration.
private struct VpnImportSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Importer un serveur VPN").font(.title3.weight(.semibold))
            Text("Colle un lien de partage (ss://, vless://, vmess://, trojan://, hysteria2://, tuic://, wireguard://), un abonnement en base64 ou le contenu d'un fichier WireGuard. Dans Shadowrocket : appui long sur le nœud › Partager › Copier le lien.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            TextEditor(text: $text)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 160)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3)))
            HStack {
                Spacer()
                Button("Annuler") {
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Button {
                    let value = text
                    Task {
                        if await model.importVpnProfile(value) {
                            dismiss()
                        }
                    }
                } label: {
                    Label("Importer", systemImage: "lock.fill")
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.isBusy("vpn-import"))
            }
        }
        .padding(20)
        .frame(width: 560)
    }
}
