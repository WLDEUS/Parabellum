import ParabellumKit
import SwiftUI

struct AlertsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var kindFilter: AlertKind?
    @State private var minimumSeverity: Severity = .info

    private var filteredAlerts: [SecurityAlert] {
        model.alerts.filter { alert in
            (kindFilter == nil || alert.kind == kindFilter) && alert.severity >= minimumSeverity
        }
    }

    private var selectedAlert: SecurityAlert? {
        guard let id = model.selectedAlertId else { return nil }
        return model.alerts.first { $0.id == id }
    }

    var body: some View {
        HSplitView {
            VStack(spacing: 0) {
                filterBar
                Divider()
                if filteredAlerts.isEmpty {
                    ContentUnavailableView(
                        model.includeResolvedAlerts ? "Aucune alerte" : "Aucune alerte ouverte",
                        systemImage: "checkmark.shield",
                        description: Text("Parabellum n'a rien signalé pour ces filtres.")
                    )
                } else {
                    List(selection: $model.selectedAlertId) {
                        ForEach(filteredAlerts) { alert in
                            AlertRow(alert: alert)
                        }
                    }
                }
            }
            .frame(minWidth: 320, idealWidth: 400)

            Group {
                if let alert = selectedAlert {
                    AlertDetailView(alert: alert)
                } else {
                    ContentUnavailableView("Sélectionne une alerte", systemImage: "bell")
                }
            }
            .frame(minWidth: 360, maxWidth: .infinity, maxHeight: .infinity)
        }
        .navigationTitle("Alertes")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("alerts")) {
                    Task { await model.loadAlerts() }
                }
            }
        }
        .task {
            await model.loadAlerts()
        }
        .onChange(of: model.includeResolvedAlerts) { _, _ in
            Task { await model.loadAlerts() }
        }
    }

    private var filterBar: some View {
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

            Picker("Gravité", selection: $minimumSeverity) {
                ForEach(Severity.known, id: \.self) { severity in
                    Text("≥ \(severity.label)").tag(severity)
                }
            }
            .labelsHidden()
            .fixedSize()
            Spacer()
        }
        .padding(10)
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
            InfoRow(label: "Date", value: PBFormat.dateTime(alert.date))
            if let path = alert.path {
                InfoRow(label: "Fichier", value: path, monospaced: true)
            }
            if let sha = alert.sha256 {
                InfoRow(label: "SHA-256", value: sha, monospaced: true)
            }
            if let deviceId = alert.deviceId {
                InfoRow(label: "Périphérique", value: deviceId, monospaced: true)
            }
            if let persistenceId = alert.persistenceId {
                InfoRow(label: "Persistance", value: persistenceId, monospaced: true)
            }
            if let quarantineId = alert.quarantineId {
                InfoRow(label: "Quarantaine", value: quarantineId, monospaced: true)
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
        }
        .buttonStyle(.link)
    }

    private func run(_ action: AlertAction) {
        pendingAction = nil
        let id = alert.id
        Task { await model.resolve(alertId: id, action: action) }
    }
}
