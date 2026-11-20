import AppKit
import ParabellumKit
import SwiftUI

/// How the alert list is ordered.
enum AlertSort: String, CaseIterable, Identifiable {
    case severity, date
    var id: String { rawValue }
    var label: String {
        switch self {
        case .severity: return String(localized: "Gravité")
        case .date: return String(localized: "Date")
        }
    }
}

struct AlertsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var kindFilter: AlertKind?
    /// Severities shown (chips); all by default.
    @State private var severities: Set<Severity> = Set(Severity.known)
    @State private var sort: AlertSort = .severity
    @State private var selection: Set<Int64> = []

    /// Kind filter only (the severity chips show their counts for it).
    private var kindFiltered: [SecurityAlert] {
        model.alerts.filter { kindFilter == nil || $0.kind == kindFilter }
    }

    /// Critical first, then by date (newest first); or by date only.
    private func ordered(_ alerts: [SecurityAlert]) -> [SecurityAlert] {
        alerts.sorted { a, b in
            if sort == .severity && a.severity != b.severity { return a.severity > b.severity }
            if a.ts != b.ts { return a.ts > b.ts }
            return a.id > b.id
        }
    }

    private var selectedAlerts: [SecurityAlert] {
        model.alerts.filter { selection.contains($0.id) }
    }

    var body: some View {
        let base = kindFiltered
        let visible = ordered(base.filter { severities.contains($0.severity) || !Severity.known.contains($0.severity) })
        return Group {
            if visible.isEmpty {
                // Nothing to list: one full-width pane, filters pinned on top, no detail column.
                VStack(spacing: 0) {
                    filterBar(base)
                    Divider()
                    emptyState(hidden: model.alerts.count)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            } else {
                HSplitView {
                    VStack(spacing: 0) {
                        filterBar(base)
                        Divider()
                        alertList(visible)
                    }
                    .frame(minWidth: 340, idealWidth: 420, maxHeight: .infinity, alignment: .top)

                    Group {
                        let picked = selectedAlerts
                        if picked.count > 1 {
                            BulkAlertsView(alerts: picked) { selection = [] }
                        } else if let alert = picked.first {
                            AlertDetailView(alert: alert)
                        } else {
                            ContentUnavailableView(
                                "Sélectionne une alerte",
                                systemImage: "bell",
                                description: Text("⌘-clic ou ⇧-clic pour en sélectionner plusieurs, ⌘A pour toutes.")
                            )
                        }
                    }
                    .frame(minWidth: 360, maxWidth: .infinity, maxHeight: .infinity)
                }
            }
        }
        .navigationTitle("Alertes")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("alerts")) {
                    Task { await model.refresh(section: .alerts, force: true) }
                }
            }
        }
        .onAppear {
            if let id = model.selectedAlertId { selection = [id] }
            model.revalidateSection(.alerts)
        }
        .onChange(of: selection) { _, new in
            // One alert selected: it is "the" selected alert (notifications, deep links use it).
            if new.count == 1 { model.selectedAlertId = new.first } else if new.isEmpty { model.selectedAlertId = nil }
        }
        .onChange(of: model.selectedAlertId) { _, id in
            if let id, selection != [id] { selection = [id] }
        }
        .onChange(of: model.alerts) { _, alerts in
            // Drop what disappeared (resolved and hidden, cleaned up).
            let ids = Set(alerts.map(\.id))
            if !selection.isSubset(of: ids) { selection = selection.intersection(ids) }
        }
        .onChange(of: model.includeResolvedAlerts) { _, _ in
            Task { await model.loadAlerts() }
        }
    }

    /// `hidden`: alerts loaded but filtered out.
    @ViewBuilder
    private func emptyState(hidden: Int) -> some View {
        if model.isFirstLoad("alerts") {
            ProgressView("Chargement des alertes…")
        } else if hidden > 0 {
            ContentUnavailableView {
                Label("Aucune alerte pour ces filtres", systemImage: "line.3.horizontal.decrease.circle")
            } description: {
                Text(hidden == 1 ? "1 alerte est masquée par les filtres." : "\(hidden) alertes sont masquées par les filtres.")
            } actions: {
                Button("Réinitialiser les filtres") {
                    kindFilter = nil
                    severities = Set(Severity.known)
                }
            }
        } else {
            ContentUnavailableView(
                model.includeResolvedAlerts ? "Aucune alerte" : "Aucune alerte ouverte",
                systemImage: "checkmark.shield",
                description: Text(model.includeResolvedAlerts
                    ? "Parabellum n'a encore rien signalé."
                    : "Tout est traité. « Toutes » affiche aussi les alertes vues et résolues.")
            )
        }
    }

    @ViewBuilder
    private func alertList(_ visible: [SecurityAlert]) -> some View {
        List(selection: $selection) {
            if sort == .severity {
                ForEach(Severity.known.reversed(), id: \.self) { severity in
                    let group = visible.filter { $0.severity == severity }
                    if !group.isEmpty {
                        Section {
                            ForEach(group) { AlertRow(alert: $0) }
                        } header: {
                            SeverityHeader(severity: severity, count: group.count)
                        }
                    }
                }
                let other = visible.filter { !Severity.known.contains($0.severity) }
                if !other.isEmpty {
                    Section("Autres") { ForEach(other) { AlertRow(alert: $0) } }
                }
            } else {
                ForEach(visible) { AlertRow(alert: $0) }
            }
        }
        .contextMenu(forSelectionType: Int64.self) { ids in
            selectionMenu(ids)
        }
    }

    @ViewBuilder
    private func selectionMenu(_ ids: Set<Int64>) -> some View {
        let alerts = model.alerts.filter { ids.contains($0.id) && $0.status != .resolved }
        let common = BulkAlertsView.commonActions(alerts).filter { !$0.isDestructive }
        if common.isEmpty {
            Text("Aucune action commune")
        } else {
            ForEach(common, id: \.self) { action in
                Button(alerts.count > 1 ? "\(action.label) (\(alerts.count))" : action.label) {
                    let targets = alerts.map(\.id)
                    Task { await model.resolveMany(targets, action: action) }
                }
            }
        }
    }

    private func filterBar(_ base: [SecurityAlert]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 10) {
                Picker("État", selection: $model.includeResolvedAlerts) {
                    Text("Ouvertes").tag(false)
                    Text("Toutes").tag(true)
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()

                Picker("Type", selection: $kindFilter) {
                    Text("Tous les types").tag(AlertKind?.none)
                    ForEach(AlertKind.allCases.filter { $0 != .unknown }, id: \.self) { kind in
                        Text(kind.label).tag(AlertKind?.some(kind))
                    }
                }
                .labelsHidden()
                .fixedSize()

                Picker("Tri", selection: $sort) {
                    ForEach(AlertSort.allCases) { Text("Tri : \($0.label)").tag($0) }
                }
                .labelsHidden()
                .fixedSize()
                Spacer()
            }
            HStack(spacing: 6) {
                ForEach(Severity.known.reversed(), id: \.self) { severity in
                    SeverityChip(
                        severity: severity,
                        count: base.filter { $0.severity == severity }.count,
                        isOn: severities.contains(severity)
                    ) {
                        toggle(severity)
                    }
                }
                Spacer()
                if severities.count != Severity.known.count {
                    Button("Toutes") { severities = Set(Severity.known) }
                        .buttonStyle(.link)
                        .font(.caption)
                }
            }
        }
        .padding(10)
    }

    /// Click: toggle. ⌥-click: only this severity.
    private func toggle(_ severity: Severity) {
        if NSEvent.modifierFlags.contains(.option) {
            severities = [severity]
        } else if severities.contains(severity) {
            severities.remove(severity)
        } else {
            severities.insert(severity)
        }
    }
}

private struct SeverityHeader: View {
    let severity: Severity
    let count: Int

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(severity.color).frame(width: 8, height: 8)
            Text(severity.label)
            Text("\(count)").foregroundStyle(.secondary).monospacedDigit()
        }
    }
}

private struct SeverityChip: View {
    let severity: Severity
    let count: Int
    let isOn: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Circle().fill(severity.color).frame(width: 7, height: 7)
                Text(severity.label)
                Text("\(count)").monospacedDigit().foregroundStyle(.secondary)
            }
            .font(.caption)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
                Capsule().fill(isOn ? severity.color.opacity(0.18) : Color.clear)
            )
            .overlay(
                Capsule().strokeBorder(isOn ? severity.color.opacity(0.6) : Color.secondary.opacity(0.3))
            )
            .opacity(isOn ? 1 : 0.55)
            .contentShape(Capsule())
        }
        .buttonStyle(.plain)
        .help(isOn ? "Masquer les alertes « \(severity.label) » (⌥-clic : seulement celles-ci)" : "Afficher les alertes « \(severity.label) »")
        .accessibilityAddTraits(isOn ? .isSelected : [])
    }
}

/// Several alerts selected: summary and the actions they all accept.
private struct BulkAlertsView: View {
    @EnvironmentObject private var model: AppModel
    let alerts: [SecurityAlert]
    let clearSelection: () -> Void
    @State private var pendingAction: AlertAction?

    /// Actions every non-resolved selected alert offers, in the order of the first one.
    static func commonActions(_ alerts: [SecurityAlert]) -> [AlertAction] {
        guard let first = alerts.first else { return [] }
        return first.knownActions.filter { action in alerts.allSatisfy { $0.knownActions.contains(action) } }
    }

    private var actionable: [SecurityAlert] { alerts.filter { $0.status != .resolved } }

    var body: some View {
        let actionable = self.actionable
        let common = Self.commonActions(actionable)
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(alignment: .firstTextBaseline) {
                    Text("\(alerts.count) alertes sélectionnées")
                        .font(.title2.weight(.semibold))
                    Spacer()
                    Button("Tout désélectionner", action: clearSelection)
                        .buttonStyle(.link)
                }
                HStack(spacing: 6) {
                    ForEach(Severity.known.reversed(), id: \.self) { severity in
                        let n = alerts.filter { $0.severity == severity }.count
                        if n > 0 { Pill(text: "\(severity.label) · \(n)", color: severity.color) }
                    }
                }
                Divider()
                Text("Actions groupées").font(.headline)
                if actionable.isEmpty {
                    Text("Toutes ces alertes sont déjà résolues.").foregroundStyle(.secondary)
                } else if common.isEmpty {
                    Text("Ces alertes n'ont aucune action en commun : affine la sélection (par type ou gravité).")
                        .foregroundStyle(.secondary)
                } else {
                    HStack(spacing: 8) {
                        ForEach(common, id: \.self) { action in
                            Button {
                                if action.isDestructive { pendingAction = action } else { run(action) }
                            } label: {
                                if Request.resolveAlert(alertId: 0, action: action).requiresAdmin {
                                    Label("\(action.label) (\(actionable.count))", systemImage: "lock.fill")
                                } else {
                                    Text("\(action.label) (\(actionable.count))")
                                }
                            }
                            .disabled(model.isBusy("resolve-bulk"))
                        }
                    }
                    if model.isBusy("resolve-bulk") {
                        ProgressView().controlSize(.small)
                    }
                    if actionable.count < alerts.count {
                        Text("\(alerts.count - actionable.count) alerte(s) déjà résolue(s) ignorée(s).")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(alerts.prefix(12)) { alert in
                        HStack(spacing: 8) {
                            Image(systemName: alert.kind.symbol).foregroundStyle(alert.severity.color).frame(width: 18)
                            Text(alert.title).lineLimit(1)
                            Spacer()
                            Text(PBFormat.relative(alert.date)).font(.caption).foregroundStyle(.tertiary)
                        }
                    }
                    if alerts.count > 12 {
                        Text("… et \(alerts.count - 12) autres").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .confirmationDialog(
            pendingAction.map { String(localized: "\($0.label) sur \(actionable.count) alertes ?") } ?? "",
            isPresented: Binding(get: { pendingAction != nil }, set: { if !$0 { pendingAction = nil } }),
            presenting: pendingAction
        ) { action in
            Button("\(action.label) (\(actionable.count))", role: .destructive) { run(action) }
            Button("Annuler", role: .cancel) {}
        }
    }

    private func run(_ action: AlertAction) {
        pendingAction = nil
        let ids = actionable.map(\.id)
        Task { await model.resolveMany(ids, action: action) }
    }
}

private struct AlertRow: View {
    let alert: SecurityAlert

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: alert.kind.symbol)
                .foregroundStyle(alert.severity.color)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 3) {
                Text(alert.title)
                    .fontWeight(alert.status == .open ? .semibold : .regular)
                    .lineLimit(1)
                Text(alert.message)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                Text(PBFormat.relative(alert.date))
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }
            Spacer(minLength: 4)
            if alert.status != .open {
                Text(alert.status.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 3)
    }
}

private struct AlertDetailView: View {
    @EnvironmentObject private var model: AppModel
    let alert: SecurityAlert
    @State private var pendingAction: AlertAction?

    // The body is split into small computed views: one big ViewBuilder expression makes the Swift
    // type-checker time out ("unable to type-check this expression in reasonable time").
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                header
                Text(alert.message)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                details
                actionsSection
                links
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .confirmationDialog(
            pendingAction.map { "\($0.label) ?" } ?? "",
            isPresented: Binding(
                get: { pendingAction != nil },
                set: { if !$0 { pendingAction = nil } }
            ),
            presenting: pendingAction
        ) { action in
            Button(action.label, role: .destructive) {
                run(action)
            }
            Button("Annuler", role: .cancel) {}
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: alert.kind.symbol)
                .font(.system(size: 30))
                .foregroundStyle(alert.severity.color)
            VStack(alignment: .leading, spacing: 6) {
                Text(alert.title)
                    .font(.title2.weight(.semibold))
                    .textSelection(.enabled)
                HStack(spacing: 6) {
                    SeverityBadge(severity: alert.severity)
                    Pill(text: alert.kind.label, color: .secondary)
                    Pill(text: alert.status.label, color: statusColor)
                }
            }
        }
    }

    private var statusColor: Color {
        alert.status == .open ? .orange : .green
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 6) {
            InfoRow(label: String(localized: "Date"), value: PBFormat.dateTime(alert.date))
            if let path = alert.path {
                InfoRow(label: String(localized: "Fichier"), value: path, monospaced: true)
            }
            if let sha = alert.sha256 {
                InfoRow(label: String(localized: "SHA-256"), value: sha, monospaced: true)
            }
            if let deviceId = alert.deviceId {
                InfoRow(label: String(localized: "Périphérique"), value: deviceId, monospaced: true)
            }
            if let persistenceId = alert.persistenceId {
                InfoRow(label: String(localized: "Persistance"), value: persistenceId, monospaced: true)
            }
            if let quarantineId = alert.quarantineId {
                InfoRow(label: String(localized: "Quarantaine"), value: quarantineId, monospaced: true)
            }
            if let processPath = alert.processPath {
                InfoRow(label: String(localized: "Processus"), value: alert.processPid.map { "\(processPath) (PID \($0))" } ?? processPath, monospaced: true)
            }
            if let networkId = alert.networkId {
                InfoRow(label: String(localized: "Réseau"), value: networkId, monospaced: true)
            }
        }
    }

    @ViewBuilder
    private var actionsSection: some View {
        if !alert.knownActions.isEmpty && alert.status != .resolved {
            Divider()
            Text("Actions").font(.headline)
            HStack(spacing: 8) {
                ForEach(alert.knownActions, id: \.self) { action in
                    actionButton(action)
                }
            }
        }
    }

    private func actionButton(_ action: AlertAction) -> some View {
        let needsAdmin = Request.resolveAlert(alertId: alert.id, action: action).requiresAdmin
        return Button {
            if action.isDestructive {
                pendingAction = action
            } else {
                run(action)
            }
        } label: {
            if needsAdmin {
                Label(action.label, systemImage: "lock.fill")
            } else {
                Text(action.label)
            }
        }
        .disabled(model.isBusy("resolve-\(alert.id)"))
    }

    @ViewBuilder
    private var links: some View {
        HStack(spacing: 12) {
            if let path = alert.path {
                Button("Afficher dans le Finder") {
                    model.revealInFinder(path)
                }
            }
            if alert.quarantineId != nil {
                Button("Voir la quarantaine") {
                    model.section = .quarantine
                }
            }
            if alert.persistenceId != nil {
                Button("Voir la persistance") {
                    model.section = .persistence
                }
            }
            if alert.deviceId != nil {
                Button("Voir les périphériques") {
                    model.section = .devices
                }
            }
            if alert.networkId != nil {
                Button("Voir le VPN et les réseaux") {
                    model.section = .vpn
                }
            }
            if alert.kind == .behavior {
                Button("Voir la protection anti-vol") {
                    model.section = .behavior
                }
            }
            if alert.kind == .privacy {
                Button("Voir la vie privée") {
                    model.section = .privacy
                }
            }
            if let link = alert.openSection, let target = SectionLink(link).flatMap({ SidebarSection(rawValue: $0.section) }) {
                Button("Ouvrir « \(target.title) »") {
                    model.openSectionLink(link)
                }
            }
        }
        .buttonStyle(.link)
    }

    private func run(_ action: AlertAction) {
        pendingAction = nil
        let id = alert.id
        Task { await model.resolve(alertId: id, action: action) }
    }
}
