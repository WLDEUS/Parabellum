import ParabellumKit
import SwiftUI
import UserNotifications

struct DashboardView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            if let status = model.status {
                VStack(alignment: .leading, spacing: 18) {
                    protectionCard(status)
                    statTiles(status)
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
                    if !model.posture.isEmpty {
                        postureCard
                    }
                    quickActions
                }
                .padding(24)
                .frame(maxWidth: 1180)
                .frame(maxWidth: .infinity)
            } else if model.isFirstLoad("status") {
                ProgressView("Chargement de l'état…")
                    .padding(40)
            } else {
                ContentUnavailableView("État indisponible", systemImage: "shield")
            }
        }
        .navigationTitle("Tableau de bord")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("status")) {
                    Task { await model.refresh(section: .dashboard, force: true) }
                }
            }
        }
        .onAppear {
            model.revalidateSection(.dashboard)
        }
    }

    private var postureCard: some View {
        Card(title: "Sécurité de macOS", symbol: "checkmark.shield") {
            VStack(alignment: .leading, spacing: 8) {
                ForEach(model.posture) { check in
                    postureRow(check)
                }
                Button {
                    Task { await model.loadPosture(refresh: true) }
                } label: {
                    Label(model.isBusy("posture") ? "Vérification…" : "Vérifier à nouveau", systemImage: "arrow.clockwise")
                }
                .disabled(model.isBusy("posture"))
                .controlSize(.small)
                .padding(.top, 4)
            }
        }
    }

    private func postureRow(_ check: PostureCheck) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: check.ok ? "checkmark.circle.fill" : (check.isUnknown ? "questionmark.circle" : "exclamationmark.triangle.fill"))
                    .foregroundStyle(check.ok ? Color.green : (check.isUnknown ? Color.secondary : check.severity.color))
                Text(check.title)
                Spacer()
                if !check.ok && !check.isUnknown {
                    SeverityBadge(severity: check.severity)
                }
            }
            Text(check.detail)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if !check.ok && !check.fix.isEmpty {
                Text(check.fix)
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
        }
    }

    private func protectionScore(_ status: StatusInfo) -> Double {
        switch status.protection {
        case .active: return status.issues.isEmpty ? 1 : 0.85
        case .degraded: return max(0.3, 0.7 - Double(status.issues.count) * 0.08)
        case .paused: return 0.35
        case .unknown: return 0.1
        }
    }

    private func protectionCard(_ status: StatusInfo) -> some View {
        HStack(spacing: 24) {
            StatusRing(
                progress: protectionScore(status),
                color: status.protection.color,
                symbol: status.protection.symbol,
                size: 120
            )
            VStack(alignment: .leading, spacing: 6) {
                Text("PROTECTION")
                    .font(.caption.weight(.bold))
                    .tracking(1.6)
                    .foregroundStyle(.secondary)
                Text(status.protection.label)
                    .font(.system(size: 30, weight: .bold, design: .rounded))
                Group {
                    if status.protection == .paused, let until = status.pausedUntilDate {
                        Text("Reprise automatique à \(PBFormat.time(until)) (\(PBFormat.relative(until)))")
                    } else if let lastScan = status.lastScanDate {
                        Text("Dernière analyse \(PBFormat.relative(lastScan))")
                    } else {
                        Text("Aucune analyse manuelle pour l'instant")
                    }
                }
                .foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    if status.protection == .paused {
                        Button("Reprendre la protection") {
                            Task { await model.setProtection(pausedMinutes: 0) }
                        }
                        .buttonStyle(.brand)
                    } else {
                        Button {
                            model.section = .scan
                            Task { await model.scanDownloads() }
                        } label: {
                            Label("Analyse rapide", systemImage: "sparkle.magnifyingglass")
                        }
                        .buttonStyle(.brand)
                        Menu("Mettre en pause") {
                            Button("15 minutes") { Task { await model.setProtection(pausedMinutes: 15) } }
                            Button("1 heure") { Task { await model.setProtection(pausedMinutes: 60) } }
                            Button("4 heures") { Task { await model.setProtection(pausedMinutes: 240) } }
                        }
                        .fixedSize()
                    }
                }
                .padding(.top, 6)
            }
            Spacer(minLength: 0)
        }
        .padding(24)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassSurface(cornerRadius: 26, tint: status.protection.color)
    }

    private func statTiles(_ status: StatusInfo) -> some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 14)], spacing: 14) {
            Button { model.section = .alerts } label: {
                StatTile(
                    value: PBFormat.count(status.openAlerts),
                    caption: "Alertes ouvertes",
                    symbol: "bell.badge.fill",
                    tint: status.openAlerts > 0 ? .orange : Brand.accent
                )
            }
            .buttonStyle(.plain)
            Button { model.section = .quarantine } label: {
                StatTile(value: PBFormat.count(status.quarantined), caption: "En quarantaine", symbol: "archivebox.fill")
            }
            .buttonStyle(.plain)
            StatTile(value: PBFormat.count(status.db.malwareHashes), caption: "Signatures de malwares", symbol: "cylinder.split.1x2.fill", tint: Brand.violet)
            StatTile(value: PBFormat.count(status.db.blockedDomains), caption: "Domaines bloqués", symbol: "network.badge.shield.half.filled", tint: Brand.cyan)
        }
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
        Card(title: "Actions rapides", symbol: "bolt.fill") {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 200), spacing: 10)], spacing: 10) {
                QuickAction(title: "Analyser les Téléchargements", symbol: "arrow.down.circle.fill") {
                    model.section = .scan
                    Task { await model.scanDownloads() }
                }
                QuickAction(title: "Analyser un dossier…", symbol: "folder.fill") {
                    model.pickAndScan()
                }
                QuickAction(title: "Rétro-chasse (30 j)", symbol: "clock.arrow.circlepath") {
                    Task { await model.retroHunt(days: 30) }
                }
                .help("Ré-analyse les fichiers vus ces 30 derniers jours avec la base actuelle")
                QuickAction(title: "Analyse anti-spyware", symbol: "eye.trianglebadge.exclamationmark.fill") {
                    model.section = .scan
                    Task { await model.spywareScan() }
                }
                .disabled(model.isBusy("spyware"))
                .help("Recherche des traces de logiciels espions (Pegasus, Predator, Graphite…) avec Zero Breach Toolkit, en lecture seule")
                QuickAction(title: "Tout mettre à jour", symbol: "arrow.triangle.2.circlepath") {
                    Task { await model.updateNow(.all) }
                }
                .disabled(model.updateInProgress)
            }
        }
    }
}

/// Glass action tile (icon + title) for the dashboard.
private struct QuickAction: View {
    let title: String
    let symbol: String
    let action: () -> Void
    @Environment(\.isEnabled) private var isEnabled
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: symbol)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Brand.gradient)
                    .frame(width: 22)
                Text(title)
                    .font(.callout.weight(.medium))
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 11)
            .background(
                RoundedRectangle(cornerRadius: Brand.Radius.control, style: .continuous)
                    .fill(Color.primary.opacity(hovering ? 0.09 : 0.05))
            )
            .overlay(
                RoundedRectangle(cornerRadius: Brand.Radius.control, style: .continuous)
                    .strokeBorder(Color.primary.opacity(0.08), lineWidth: 0.6)
            )
            .contentShape(Rectangle())
            .opacity(isEnabled ? 1 : 0.5)
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .animation(.snappy(duration: 0.15), value: hovering)
    }
}
