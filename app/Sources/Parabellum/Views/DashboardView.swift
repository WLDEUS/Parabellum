import ParabellumKit
import SwiftUI
import UserNotifications

struct DashboardView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            if let status = model.status {
                VStack(alignment: .leading, spacing: 16) {
                    protectionCard(status)
                    if !status.issues.isEmpty || !status.realtime.fullDiskAccess {
                        issuesCard(status)
                    }
                    if model.notificationStatus == .denied {
                        notificationsDeniedCard
                    }
                    HStack(alignment: .top, spacing: 16) {
                        databaseCard(status.db)
                        countersCard(status)
                    }
                    HStack(alignment: .top, spacing: 16) {
                        monitorsCard(status.realtime)
                        daemonCard(status)
                    }
                    quickActions
                }
                .padding(20)
            } else {
                ProgressView("Chargement de l'état…")
                    .padding(40)
            }
        }
        .navigationTitle("Tableau de bord")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("status")) {
                    Task { await model.refreshStatus() }
                }
            }
        }
        .task {
            await model.refreshStatus()
            await model.refreshNotificationStatus()
        }
    }

    private func protectionCard(_ status: StatusInfo) -> some View {
        HStack(spacing: 16) {
            Image(systemName: status.protection.symbol)
                .font(.system(size: 48))
                .foregroundStyle(status.protection.color)
            VStack(alignment: .leading, spacing: 4) {
                Text(status.protection.label)
                    .font(.title.weight(.semibold))
                if status.protection == .paused, let until = status.pausedUntilDate {
                    Text("Reprise automatique à \(PBFormat.time(until)) (\(PBFormat.relative(until)))")
                        .foregroundStyle(.secondary)
                } else if let lastScan = status.lastScanDate {
                    Text("Dernière analyse \(PBFormat.relative(lastScan))")
                        .foregroundStyle(.secondary)
                } else {
                    Text("Aucune analyse manuelle pour l'instant")
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
            if status.protection == .paused {
                Button("Reprendre") {
                    Task { await model.setProtection(pausedMinutes: 0) }
                }
                .buttonStyle(.borderedProminent)
            } else {
                Menu("Mettre en pause") {
                    Button("15 minutes") { Task { await model.setProtection(pausedMinutes: 15) } }
                    Button("1 heure") { Task { await model.setProtection(pausedMinutes: 60) } }
                    Button("4 heures") { Task { await model.setProtection(pausedMinutes: 240) } }
                }
                .fixedSize()
            }
        }
        .padding(16)
        .background(status.protection.color.opacity(0.08), in: RoundedRectangle(cornerRadius: 12))
    }

    private func issuesCard(_ status: StatusInfo) -> some View {
        Card(title: "Points à corriger", symbol: "wrench.and.screwdriver") {
            VStack(alignment: .leading, spacing: 10) {
                if !status.realtime.fullDiskAccess {
                    fullDiskAccessRow
                }
                ForEach(status.issues, id: \.self) { issue in
                    HStack(alignment: .firstTextBaseline) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        Text(issue)
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer()
                        fixButton(for: issue)
                    }
                }
            }
        }
    }

    private var fullDiskAccessRow: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: "lock.shield").foregroundStyle(.orange)
                Text("parabellumd n'a pas l'accès complet au disque : la surveillance temps réel (eslogger) est limitée.")
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("Ouvrir Réglages Système") {
                    model.open(urlString: AppModel.fullDiskAccessSettingsURL)
                }
                Button("Copier le chemin du service") {
                    model.copyToPasteboard(DaemonProtocol.daemonBinaryPath)
                }
                Button("Vérifier à nouveau") {
                    Task { await model.refreshStatus() }
                }
            }
            .controlSize(.small)
        }
    }

    @ViewBuilder
    private func fixButton(for issue: String) -> some View {
        let lowered = issue.lowercased()
        if lowered.contains("base") || lowered.contains("signature") {
            Button("Mettre à jour") {
                Task { await model.updateNow(.db) }
            }
            .controlSize(.small)
        } else if lowered.contains("composant") || lowered.contains("clamav") || lowered.contains("osquery") {
            Button("Voir les composants") {
                model.section = .components
            }
            .controlSize(.small)
        } else if lowered.contains("dns") {
            Button("Réseau & pubs") {
                model.section = .network
            }
            .controlSize(.small)
        } else if lowered.contains("disque") || lowered.contains("disk") {
            Button("Ouvrir Réglages") {
                model.open(urlString: AppModel.fullDiskAccessSettingsURL)
            }
            .controlSize(.small)
        }
    }

    private var notificationsDeniedCard: some View {
        Card(title: "Notifications désactivées", symbol: "bell.slash") {
            HStack {
                Text("Les alertes ne s'affichent que dans l'app. Autorise les notifications de Parabellum dans Réglages Système.")
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                Button("Ouvrir Réglages") {
                    model.open(urlString: AppModel.notificationSettingsURL)
                }
            }
        }
    }

    private func databaseCard(_ db: DbStatus) -> some View {
        Card(title: "Base de menaces", symbol: "cylinder.split.1x2") {
            VStack(alignment: .leading, spacing: 6) {
                InfoRow(label: "Version", value: db.version ?? "Aucune")
                if let built = db.builtDate {
                    InfoRow(label: "Construite", value: "\(PBFormat.dateTime(built)) (\(PBFormat.relative(built)))")
                }
                if let success = db.lastSuccessDate {
                    InfoRow(label: "Dernière MAJ", value: PBFormat.relative(success))
                }
                InfoRow(label: "Hash malveillants", value: PBFormat.count(db.malwareHashes))
                InfoRow(label: "Règles YARA", value: PBFormat.count(db.yaraRules))
                InfoRow(label: "Domaines bloqués", value: PBFormat.count(db.blockedDomains))
                InfoRow(label: "ClamAV", value: db.clamavVersion ?? "—")
                InfoRow(label: "Modèle ML", value: db.mlModelVersion ?? "—")
                if let previous = db.previousVersion {
                    InfoRow(label: "Version précédente", value: previous)
                }
                if let error = db.lastError {
                    Label(error, systemImage: "xmark.circle")
                        .foregroundStyle(.red)
                        .font(.callout)
                }
                Button {
                    Task { await model.updateNow(.db) }
                } label: {
                    Label(model.updateInProgress ? "Mise à jour en cours…" : "Mettre à jour la base", systemImage: "arrow.down.circle")
                }
                .disabled(model.updateInProgress)
                .padding(.top, 4)
            }
        }
    }

    private func countersCard(_ status: StatusInfo) -> some View {
        Card(title: "Activité", symbol: "list.bullet.rectangle") {
            VStack(alignment: .leading, spacing: 10) {
                counterRow("Alertes ouvertes", value: status.openAlerts, symbol: "bell.badge", color: status.openAlerts > 0 ? .orange : .secondary) {
                    model.section = .alerts
                }
                counterRow("En quarantaine", value: status.quarantined, symbol: "archivebox", color: .secondary) {
                    model.section = .quarantine
                }
                counterRow("Composants à traiter", value: status.componentsNeedingAttention, symbol: "puzzlepiece.extension", color: status.componentsNeedingAttention > 0 ? .orange : .secondary) {
                    model.section = .components
                }
                InfoRow(label: "Dernière analyse", value: status.lastScanDate.map { PBFormat.dateTime($0) } ?? "Jamais", selectable: false)
                InfoRow(label: "DNS anti-pub", value: status.dnsEnabled ? "Activé" : "Désactivé", selectable: false)
            }
        }
    }

    private func counterRow(_ title: String, value: Int, symbol: String, color: Color, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack {
                Image(systemName: symbol).foregroundStyle(color).frame(width: 20)
                Text(title)
                Spacer()
                Text("\(value)").font(.title3.monospacedDigit().weight(.semibold))
                Image(systemName: "chevron.right").foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func monitorsCard(_ realtime: RealtimeStatus) -> some View {
        Card(title: "Surveillance temps réel", symbol: "eye") {
            VStack(alignment: .leading, spacing: 6) {
                monitorRow("FSEvents (dossiers surveillés)", realtime.fsevents)
                monitorRow("eslogger (Endpoint Security)", realtime.eslogger)
                monitorRow("Accès complet au disque", realtime.fullDiskAccess)
                monitorRow("Persistance", realtime.persistenceMonitor)
                monitorRow("Périphériques", realtime.deviceMonitor)
            }
        }
    }

    private func monitorRow(_ title: String, _ ok: Bool) -> some View {
        HStack {
            Image(systemName: ok ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(ok ? Color.green : Color.red)
            Text(title)
            Spacer()
        }
    }

    private func daemonCard(_ status: StatusInfo) -> some View {
        Card(title: "Service parabellumd", symbol: "cpu") {
            VStack(alignment: .leading, spacing: 6) {
                InfoRow(label: "Version", value: status.version)
                InfoRow(label: "Actif depuis", value: PBFormat.duration(seconds: status.uptimeSecs), selectable: false)
                InfoRow(label: "Mémoire (RSS)", value: PBFormat.bytes(status.rssBytes), selectable: false)
                InfoRow(label: "Alimentation", value: status.onBattery ? "Sur batterie" : "Secteur", selectable: false)
                InfoRow(label: "Classifieur ML", value: status.mlEnabled ? "Activé" : "Désactivé", selectable: false)
            }
        }
    }

    private var quickActions: some View {
        Card(title: "Actions rapides", symbol: "bolt") {
            HStack(spacing: 10) {
                Button {
                    model.section = .scan
                    Task { await model.scanDownloads() }
                } label: {
                    Label("Analyser les Téléchargements", systemImage: "arrow.down.circle")
                }
                Button {
                    model.pickAndScan()
                } label: {
                    Label("Analyser un dossier…", systemImage: "folder")
                }
                Button {
                    Task { await model.retroHunt(days: 30) }
                } label: {
                    Label("Rétro-chasse (30 j)", systemImage: "clock.arrow.circlepath")
                }
                .help("Ré-analyse les fichiers vus ces 30 derniers jours avec la base actuelle")
                Button {
                    Task { await model.updateNow(.all) }
                } label: {
                    Label("Tout mettre à jour", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(model.updateInProgress)
            }
        }
    }
}
