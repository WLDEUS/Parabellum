import AppKit
import ParabellumKit
import SwiftUI

/// Content of the menu bar window (`.menuBarExtraStyle(.window)`).
struct MenuBarContentView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            header
            Divider()
            switch model.connection {
            case .unreachable(let message):
                UnreachableView(message: message, compact: true)
            case .connecting:
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Connexion au service…").foregroundStyle(.secondary)
                }
            case .connected:
                details
                Divider()
                actions
            }
            Divider()
            footer
        }
        .padding(14)
        .frame(width: 340)
        .onAppear {
            model.registerOpenWindow(openWindow)
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Image(systemName: model.menuBarSymbol)
                .font(.title)
                .foregroundStyle(headerColor)
            VStack(alignment: .leading, spacing: 2) {
                Text("Parabellum").font(.headline)
                Text(headerSubtitle)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }

    private var headerColor: Color {
        switch model.connection {
        case .connected:
            return model.status?.protection.color ?? .gray
        case .unreachable:
            return .red
        case .connecting:
            return .gray
        }
    }

    private var headerSubtitle: String {
        switch model.connection {
        case .connecting:
            return "Connexion…"
        case .unreachable:
            return "Service injoignable"
        case .connected:
            guard let status = model.status else { return "Chargement…" }
            if status.protection == .paused, let until = status.pausedUntilDate {
                return "En pause jusqu'à \(PBFormat.time(until))"
            }
            return status.protection.label
        }
    }

    @ViewBuilder
    private var details: some View {
        if let status = model.status {
            VStack(alignment: .leading, spacing: 6) {
                ForEach(status.issues, id: \.self) { issue in
                    Label(issue, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                        .font(.callout)
                }
                Button {
                    model.showMainWindow(section: .alerts)
                } label: {
                    HStack {
                        Label(alertsText(status.openAlerts), systemImage: status.openAlerts > 0 ? "bell.badge.fill" : "bell")
                        Spacer()
                        Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .foregroundStyle(status.openAlerts > 0 ? Color.orange : Color.primary)

                HStack {
                    Label(dbText(status.db), systemImage: "cylinder.split.1x2")
                    Spacer()
                }
                .font(.callout)
                .foregroundStyle(.secondary)

                if let update = model.lastUpdate, !update.ok {
                    Label("Dernière mise à jour en échec", systemImage: "xmark.circle")
                        .font(.callout)
                        .foregroundStyle(.red)
                }
            }
        } else {
            ProgressView().controlSize(.small)
        }
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 4) {
            MenuActionButton(title: "Analyser les Téléchargements", symbol: "arrow.down.circle") {
                Task { await model.scanDownloads() }
            }
            .disabled(model.isBusy("scan"))
            MenuActionButton(title: "Analyser un dossier…", symbol: "folder.badge.gearshape") {
                model.pickAndScan()
            }
            MenuActionButton(
                title: model.updateInProgress ? "Mise à jour en cours…" : "Mettre à jour maintenant",
                symbol: "arrow.triangle.2.circlepath"
            ) {
                Task { await model.updateNow(.all) }
            }
            .disabled(model.updateInProgress || model.isBusy("update"))

            Toggle(isOn: dnsBinding) {
                Label("DNS anti-pub et anti-malware", systemImage: "network.badge.shield.half.filled")
            }
            .toggleStyle(.switch)
            .controlSize(.small)
            .disabled(model.isBusy("dns"))
            .padding(.vertical, 4)

            if let vpn = model.vpnStatus, vpn.profile != nil || vpn.externalService != nil {
                Toggle(isOn: vpnBinding(vpn)) {
                    Label("VPN · \(vpn.state.label.lowercased())", systemImage: vpn.state.symbol)
                        .foregroundStyle(vpn.isBlocking ? Color.orange : Color.primary)
                }
                .toggleStyle(.switch)
                .controlSize(.small)
                .disabled(model.isBusy("vpn-connect") || model.isBusy("vpn-disconnect"))
                .padding(.vertical, 2)
            }

            if model.status?.protection == .paused {
                MenuActionButton(title: "Reprendre la protection", symbol: "play.circle") {
                    Task { await model.setProtection(pausedMinutes: 0) }
                }
            } else {
                HStack(spacing: 8) {
                    Image(systemName: "pause.circle").frame(width: 18)
                    Text("Pause")
                    Spacer()
                    Button("15 min") {
                        Task { await model.setProtection(pausedMinutes: 15) }
                    }
                    Button("1 h") {
                        Task { await model.setProtection(pausedMinutes: 60) }
                    }
                }
                .controlSize(.small)
                .disabled(model.isBusy("protection"))
                .padding(.vertical, 2)
            }
        }
    }

    private var footer: some View {
        HStack {
            Button("Ouvrir Parabellum") {
                model.showMainWindow()
            }
            .keyboardShortcut("o")
            Spacer()
            Button("Quitter") {
                NSApp.terminate(nil)
            }
            .help("Ferme l'app de la barre de menus ; la protection (parabellumd) continue de tourner.")
        }
    }

    /// On = connected or connecting; switching off asks for administrator approval.
    private func vpnBinding(_ vpn: VpnStatus) -> Binding<Bool> {
        Binding(
            get: { vpn.state == .connected || vpn.state == .connecting },
            set: { newValue in
                Task {
                    if newValue {
                        await model.vpnConnect()
                    } else {
                        await model.vpnDisconnect()
                    }
                }
            }
        )
    }

    private var dnsBinding: Binding<Bool> {
        Binding(
            get: { model.status?.dnsEnabled ?? false },
            set: { newValue in
                Task { await model.setDns(enabled: newValue) }
            }
        )
    }

    private func alertsText(_ count: Int) -> String {
        switch count {
        case 0: return "Aucune alerte ouverte"
        case 1: return "1 alerte ouverte"
        default: return "\(count) alertes ouvertes"
        }
    }

    private func dbText(_ db: DbStatus) -> String {
        guard let version = db.version else { return "Base de menaces absente" }
        if let built = db.builtDate {
            return "Base \(version) · \(PBFormat.relative(built))"
        }
        return "Base \(version)"
    }
}

/// Full-width, menu-like button row.
struct MenuActionButton: View {
    let title: String
    let symbol: String
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: symbol).frame(width: 18)
                Text(title)
                Spacer()
            }
            .padding(.vertical, 4)
            .padding(.horizontal, 6)
            .contentShape(Rectangle())
            .background(hovering ? Color.accentColor.opacity(0.15) : Color.clear, in: RoundedRectangle(cornerRadius: 5))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
    }
}
