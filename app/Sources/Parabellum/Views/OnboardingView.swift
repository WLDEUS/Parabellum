import ParabellumKit
import SwiftUI
import UserNotifications

/// First-launch guide: daemon, Full Disk Access, recommended components, DNS, notifications.
struct OnboardingView: View {
    @EnvironmentObject private var model: AppModel
    @State private var step = 0
    private let lastStep = 4

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 6) {
                ForEach(0...lastStep, id: \.self) { index in
                    Capsule()
                        .fill(index <= step ? Color.accentColor : Color.secondary.opacity(0.25))
                        .frame(height: 4)
                }
            }
            .padding([.horizontal, .top], 24)

            Group {
                switch step {
                case 0: welcome
                case 1: fullDiskAccess
                case 2: components
                case 3: dns
                default: notifications
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .padding(24)

            Divider()
            HStack {
                Button("Passer") {
                    model.finishOnboarding()
                }
                .buttonStyle(.link)
                Spacer()
                if step > 0 {
                    Button("Précédent") {
                        step -= 1
                    }
                }
                if step < lastStep {
                    Button("Suivant") {
                        step += 1
                    }
                    .buttonStyle(.borderedProminent)
                } else {
                    Button("Terminer") {
                        model.finishOnboarding()
                    }
                    .buttonStyle(.borderedProminent)
                }
            }
            .padding(16)
        }
        .frame(width: 620, height: 520)
        .task {
            await model.refreshStatus()
            await model.loadComponents()
            await model.loadAdblock()
            await model.refreshNotificationStatus()
        }
    }

    // MARK: Steps

    private var welcome: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Bienvenue dans Parabellum", systemImage: "checkmark.shield.fill")
                .font(.title.weight(.semibold))
            Text("Parabellum protège ce Mac en orchestrant des outils open source éprouvés : ClamAV, YARA-X, eslogger (Endpoint Security), osquery, les outils d'Objective-See, dnscrypt-proxy et uBlock Origin Lite.")
                .fixedSize(horizontal: false, vertical: true)
            Text("La protection tourne dans un service système, parabellumd (LaunchDaemon, root). Cette app n'est que l'interface : la quitter n'arrête pas la protection.")
                .fixedSize(horizontal: false, vertical: true)
            connectionStatus
            Text("Quelques réglages en 4 étapes et c'est parti.")
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var connectionStatus: some View {
        switch model.connection {
        case .connected:
            Label("Service parabellumd connecté", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
        case .connecting:
            Label("Connexion au service…", systemImage: "hourglass")
                .foregroundStyle(.secondary)
        case .unreachable(let message):
            VStack(alignment: .leading, spacing: 6) {
                Label(message, systemImage: "xmark.circle.fill")
                    .foregroundStyle(.red)
                Text(AppModel.kickstartCommand)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                Button("Réessayer") {
                    model.retryConnection()
                }
            }
        }
    }

    private var fullDiskAccess: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Accès complet au disque", systemImage: "lock.shield")
                .font(.title2.weight(.semibold))
            Text("Pour voir les exécutions et créations de fichiers (eslogger) et analyser tout le disque, parabellumd a besoin de l'accès complet au disque :")
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                Text("1. Ouvre Réglages Système › Confidentialité et sécurité › Accès complet au disque.")
                Text("2. Clique sur « + », puis ⌘⇧G et colle le chemin du service.")
                Text("3. Active l'interrupteur de parabellumd, puis reviens ici et vérifie.")
            }
            .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 6) {
                Text(DaemonProtocol.daemonBinaryPath)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(6)
                    .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
            }
            HStack {
                Button("Ouvrir Réglages Système") {
                    model.open(urlString: AppModel.fullDiskAccessSettingsURL)
                }
                Button("Copier le chemin") {
                    model.copyToPasteboard(DaemonProtocol.daemonBinaryPath)
                }
                Button("Vérifier à nouveau") {
                    Task { await model.refreshStatus() }
                }
            }
            fdaStatus
        }
    }

    @ViewBuilder
    private var fdaStatus: some View {
        if let status = model.status {
            if status.realtime.fullDiskAccess {
                Label("Accès complet au disque accordé", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            } else {
                Label("Accès pas encore accordé (le service peut mettre quelques secondes à le détecter)", systemImage: "xmark.circle.fill")
                    .foregroundStyle(.orange)
            }
        } else {
            Label("État inconnu : service non connecté", systemImage: "questionmark.circle")
                .foregroundStyle(.secondary)
        }
    }

    private var components: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Compléments recommandés", systemImage: "puzzlepiece.extension")
                .font(.title2.weight(.semibold))
            Text("Ils sont installés depuis leurs sources officielles, signature vérifiée, puis tenus à jour automatiquement.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            componentRow(name: "lulu", title: "LuLu", subtitle: "Pare-feu sortant (Objective-See)")
            componentRow(name: "blockblock", title: "BlockBlock", subtitle: "Alerte sur les nouvelles persistances (Objective-See)")
            Divider()
            if let adblock = model.adblock {
                browserRow(title: "uBlock Origin Lite pour Chrome", state: adblock.chromeUblock) {
                    model.openInChrome(urlString: adblock.chromeStoreUrl)
                }
                browserRow(title: "uBlock Origin Lite pour Safari", state: adblock.safariUblock) {
                    model.openInAppStore(urlString: adblock.safariStoreUrl)
                }
            } else {
                Text("État des extensions de navigateur indisponible.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func componentRow(name: String, title: String, subtitle: String) -> some View {
        let component = model.components.first { $0.name == name }
        let installing = model.installingComponents.contains(name) || model.isBusy("install-\(name)")
        return HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let component, component.state == .installed {
                Label("Installé", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            } else if installing || component?.state == .updating {
                ProgressView().controlSize(.small)
            } else if let component, component.state == .needsUserAction, let url = component.actionUrl {
                Button("Terminer l'installation") {
                    model.open(urlString: url)
                }
            } else {
                Button("Installer") {
                    Task { await model.installComponent(name) }
                }
            }
        }
    }

    private func browserRow(title: String, state: ExtensionState, install: @escaping () -> Void) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.headline)
                Text(state.label).font(.caption).foregroundStyle(state.color)
            }
            Spacer()
            if state == .enabled {
                Label("Actif", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
            } else {
                Button("Installer", action: install)
            }
        }
    }

    private var dns: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Blocage DNS des pubs et menaces", systemImage: "network.badge.shield.half.filled")
                .font(.title2.weight(.semibold))
            Text("Parabellum peut faire passer les DNS du Mac par un résolveur local (dnscrypt-proxy) qui bloque publicités, traqueurs et domaines malveillants dans toutes les apps, pas seulement le navigateur.")
                .fixedSize(horizontal: false, vertical: true)
            Text("Si le résolveur tombe, les DNS d'origine sont restaurés automatiquement : Internet n'est jamais coupé.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Toggle(isOn: Binding(
                get: { model.status?.dnsEnabled ?? false },
                set: { newValue in Task { await model.setDns(enabled: newValue) } }
            )) {
                Text("Activer le blocage DNS")
            }
            .toggleStyle(.switch)
            .disabled(model.isBusy("dns") || model.status == nil)
        }
    }

    private var notifications: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Notifications", systemImage: "bell.badge")
                .font(.title2.weight(.semibold))
            Text("Parabellum te prévient quand une menace est trouvée, qu'une nouvelle persistance apparaît ou qu'un nouveau clavier est branché, avec des boutons d'action directement dans la notification.")
                .fixedSize(horizontal: false, vertical: true)
            switch model.notificationStatus {
            case .authorized, .provisional:
                Label("Notifications autorisées", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            case .denied:
                VStack(alignment: .leading, spacing: 8) {
                    Label("Notifications refusées : les alertes resteront visibles dans l'app et la barre de menus.", systemImage: "bell.slash")
                        .foregroundStyle(.orange)
                    Button("Ouvrir Réglages Système") {
                        model.open(urlString: AppModel.notificationSettingsURL)
                    }
                }
            default:
                Button("Autoriser les notifications") {
                    Task { await model.requestNotificationPermission() }
                }
                .buttonStyle(.borderedProminent)
                .disabled(!NotificationManager.isAvailable)
            }
            if !NotificationManager.isAvailable {
                Text("Notifications indisponibles hors du bundle Parabellum.app (build de développement).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
