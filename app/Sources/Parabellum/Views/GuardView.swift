import ParabellumKit
import SwiftUI

/// Behaviour guard (info-stealers, ransomware), suspended processes and APFS snapshots.
struct GuardView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let status = model.guardStatus {
                    GuardStatusCard(status: status)
                    if !status.suspended.isEmpty {
                        SuspendedCard(processes: status.suspended)
                    }
                } else if model.isBusy("guard") {
                    ProgressView("Chargement…").padding(40)
                } else {
                    ContentUnavailableView("État indisponible", systemImage: "eye.trianglebadge.exclamationmark")
                }
                SnapshotsCard()
            }
            .padding(20)
        }
        .navigationTitle("Vols & rançongiciels")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("guard") || model.isBusy("snapshots")) {
                    Task { await model.loadGuard() }
                }
            }
        }
        .task {
            await model.loadGuard()
        }
    }
}

private struct GuardStatusCard: View {
    @EnvironmentObject private var model: AppModel
    let status: GuardStatus

    var body: some View {
        Card(title: "Détection comportementale", symbol: "eye.trianglebadge.exclamationmark") {
            VStack(alignment: .leading, spacing: 10) {
                featureRow(
                    on: status.stealerDetection,
                    title: "Vol de mots de passe et de cookies",
                    detail: "Lecture des cookies et mots de passe des navigateurs, du Trousseau ou de portefeuilles crypto par un programme non approuvé, fausse fenêtre de mot de passe (osascript), vérification de mot de passe (dscl), exfiltration (curl). Le programme est arrêté sur une détection sûre."
                )
                featureRow(
                    on: status.ransomwareDetection,
                    title: "Rançongiciels",
                    detail: "Fichiers leurres dans tes dossiers et détection des rafales de chiffrement / renommage. Le programme suspect est suspendu jusqu'à ta décision."
                )
                Divider()
                InfoRow(label: "Détections (7 jours)", value: PBFormat.count(status.detections7d))
                InfoRow(label: "Fichiers leurres", value: status.canaries.isEmpty ? "aucun" : "\(status.canaries.count) en place")
                if !status.canaries.isEmpty {
                    DisclosureGroup("Voir les leurres") {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(status.canaries, id: \.self) { path in
                                Text(path)
                                    .font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                            Text("Ne les ouvre pas et ne les déplace pas : toute modification déclenche une alerte.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                HStack {
                    Spacer()
                    Button("Réglages de la détection") {
                        model.section = .settings
                    }
                    .buttonStyle(.link)
                }
            }
        }
    }

    private func featureRow(on: Bool, title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: on ? "checkmark.shield.fill" : "shield.slash")
                .foregroundStyle(on ? Color.green : Color.secondary)
                .font(.title3)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.headline)
                Text(on ? detail : "Désactivé dans les réglages.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct SuspendedCard: View {
    @EnvironmentObject private var model: AppModel
    let processes: [SuspendedProcess]
    @State private var pendingKill: SuspendedProcess?

    var body: some View {
        Card(title: "Processus suspendus", symbol: "pause.circle.fill") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Parabellum a gelé ces programmes car ils se comportaient comme un rançongiciel. Arrête-les si tu ne les reconnais pas.")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(processes) { process in
                    row(process)
                }
            }
        }
        .confirmationDialog(
            "Arrêter ce processus ?",
            isPresented: Binding(get: { pendingKill != nil }, set: { if !$0 { pendingKill = nil } }),
            presenting: pendingKill
        ) { process in
            Button("Arrêter", role: .destructive) {
                act(process, .killProcess)
            }
            Button("Annuler", role: .cancel) {}
        }
    }

    private func row(_ process: SuspendedProcess) -> some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text((process.path as NSString).lastPathComponent).font(.headline)
                Text(process.path)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                Text("PID \(process.pid) · suspendu \(PBFormat.relative(process.sinceDate))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if process.alertId != nil {
                Button(role: .destructive) {
                    pendingKill = process
                } label: {
                    Label("Arrêter", systemImage: "xmark.octagon")
                }
                Button {
                    act(process, .resumeProcess)
                } label: {
                    Label("Reprendre", systemImage: "lock.fill")
                }
                .help("Reprendre demande une autorisation administrateur")
            } else {
                Text("Voir les alertes").font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func act(_ process: SuspendedProcess, _ action: AlertAction) {
        pendingKill = nil
        guard let alertId = process.alertId else { return }
        Task {
            await model.resolve(alertId: alertId, action: action)
            await model.loadGuard()
        }
    }
}

private struct SnapshotsCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        Card(title: "Instantanés APFS", symbol: "clock.arrow.circlepath") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Points de restauration locaux du disque (Time Machine local), créés régulièrement et purgés par macOS après environ 24 h. Si des fichiers sont chiffrés, récupère-les ici : la copie est écrite dans ~/Parabellum-Restauration, rien n'est écrasé.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let status = model.guardStatus {
                    if let last = status.lastSnapshotDate {
                        InfoRow(label: "Dernier instantané", value: PBFormat.relative(last))
                    }
                    if !status.snapshotsEnabled {
                        Label("Instantanés automatiques désactivés dans les réglages.", systemImage: "info.circle")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    if let error = status.snapshotError {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .font(.callout)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                HStack {
                    Button {
                        Task { await model.createSnapshot() }
                    } label: {
                        if model.isBusy("snapshot-create") {
                            ProgressView().controlSize(.small)
                        } else {
                            Label("Créer un instantané maintenant", systemImage: "plus.circle")
                        }
                    }
                    .disabled(model.isBusy("snapshot-create"))
                    Spacer()
                }
                if model.snapshots.isEmpty {
                    Text("Aucun instantané local pour l'instant.").foregroundStyle(.secondary)
                } else {
                    ForEach(model.snapshots) { snapshot in
                        SnapshotRow(snapshot: snapshot)
                    }
                }
            }
        }
    }
}

private struct SnapshotRow: View {
    @EnvironmentObject private var model: AppModel
    let snapshot: SnapshotInfo

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "clock.arrow.circlepath").foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(snapshot.createdDate.map { PBFormat.dateTime($0) } ?? snapshot.name)
                Text(snapshot.name)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            if snapshot.ours {
                Pill(text: "Parabellum", color: .blue)
            }
            Spacer()
            Button {
                model.pickAndRestore(from: snapshot)
            } label: {
                Label("Restaurer un fichier…", systemImage: "lock.fill")
            }
            .disabled(model.isBusy("snapshot-restore"))
            .help("Restaurer demande une autorisation administrateur")
        }
    }
}
