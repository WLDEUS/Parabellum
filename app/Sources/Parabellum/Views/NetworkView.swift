import ParabellumKit
import SwiftUI

struct NetworkView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let adblock = model.adblock {
                    dnsCard(adblock.dns)
                    extensionsCard(adblock)
                    Card(title: "YouTube", symbol: "play.rectangle") {
                        Text("Le blocage des pubs YouTube est fait au mieux par uBlock Origin Lite (listes mises à jour par le Store). Le DNS seul ne suffit pas : pubs et vidéos partagent les mêmes domaines.")
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } else if model.isBusy("adblock") {
                    ProgressView("Chargement…").padding(40)
                } else {
                    ContentUnavailableView("État indisponible", systemImage: "network")
                }
            }
            .padding(20)
        }
        .navigationTitle("Réseau & pubs")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("adblock")) {
                    Task { await model.loadAdblock() }
                }
            }
        }
        .task {
            await model.loadAdblock()
        }
    }

    private func dnsCard(_ dns: DnsStatus) -> some View {
        Card(title: "Blocage DNS global", symbol: "network.badge.shield.half.filled") {
            VStack(alignment: .leading, spacing: 8) {
                Toggle(isOn: Binding(
                    get: { dns.enabled },
                    set: { newValue in Task { await model.setDns(enabled: newValue) } }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Bloquer pubs, traqueurs et domaines malveillants pour tout le Mac")
                        Text("Les DNS système passent par dnscrypt-proxy en local ; s'il tombe, les DNS d'origine sont restaurés automatiquement.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .toggleStyle(.switch)
                .disabled(model.isBusy("dns"))

                HStack(spacing: 6) {
                    Image(systemName: dns.running ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(dns.running ? Color.green : (dns.enabled ? Color.red : Color.secondary))
                    Text(dns.running ? "Résolveur local actif" : "Résolveur local arrêté")
                }
                InfoRow(label: "Écoute", value: dns.listen, monospaced: true)
                InfoRow(label: "Domaines bloqués", value: PBFormat.count(dns.blockedDomains))
                if let blocked = dns.queriesBlocked24h {
                    InfoRow(label: "Requêtes bloquées (24 h)", value: PBFormat.count(blocked))
                }
                if let version = dns.listVersion {
                    InfoRow(label: "Version des listes", value: version)
                }
                if !dns.managedServices.isEmpty {
                    InfoRow(label: "Services réseau gérés", value: dns.managedServices.joined(separator: ", "))
                }
                if let message = dns.message, !message.isEmpty {
                    Label(message, systemImage: "info.circle")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func extensionsCard(_ adblock: AdblockStatus) -> some View {
        Card(title: "uBlock Origin Lite dans les navigateurs", symbol: "puzzlepiece.extension") {
            VStack(alignment: .leading, spacing: 12) {
                extensionRow(
                    browser: "Google Chrome",
                    state: adblock.chromeUblock,
                    help: "Installe l'extension depuis le Chrome Web Store, puis vérifie qu'elle est activée dans chrome://extensions."
                ) {
                    model.openInChrome(urlString: adblock.chromeStoreUrl)
                }
                Divider()
                extensionRow(
                    browser: "Safari",
                    state: adblock.safariUblock,
                    help: "Installe l'app depuis l'App Store, puis active l'extension dans Safari › Réglages › Extensions."
                ) {
                    model.openInAppStore(urlString: adblock.safariStoreUrl)
                }
            }
        }
    }

    private func extensionRow(browser: String, state: ExtensionState, help: String, install: @escaping () -> Void) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: state.symbol)
                .foregroundStyle(state.color)
                .font(.title3)
            VStack(alignment: .leading, spacing: 3) {
                Text(browser).font(.headline)
                Text(state.label).foregroundStyle(state.color)
                if state != .enabled {
                    Text(help)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
            Button(state == .notInstalled || state == .unknown ? "Installer" : "Ouvrir le Store", action: install)
        }
    }
}
