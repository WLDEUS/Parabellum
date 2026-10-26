import AppKit
import ParabellumKit
import SwiftUI

struct ScanView: View {
    @EnvironmentObject private var model: AppModel
    @State private var useClamav = true
    @State private var clamavInitialized = false
    @State private var isDropTargeted = false
    @State private var volumes: [URL] = []

    var body: some View {
        VSplitView {
            VStack(alignment: .leading, spacing: 14) {
                dropZone
                quickTargets
                if !model.activeJobs.isEmpty {
                    activeJobsView
                }
                recentJobsView
            }
            .padding(20)
            .frame(minHeight: 280)

            findingsView
                .frame(minHeight: 180)
        }
        .navigationTitle("Analyse")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("jobs")) {
                    Task { await model.loadJobs() }
                }
            }
        }
        .task {
            if !clamavInitialized, let config = model.config {
                useClamav = config.scan.clamavOnDemand
                clamavInitialized = true
            }
            volumes = AppModel.externalVolumes()
            await model.loadJobs()
            if let selected = model.selectedJobId, model.jobDetails[selected] == nil {
                await model.loadJobDetail(selected)
            }
        }
    }

    /// nil = daemon default (`scan.clamav_on_demand`).
    private var clamavOverride: Bool? {
        guard let config = model.config else { return useClamav }
        return useClamav == config.scan.clamavOnDemand ? nil : useClamav
    }

    private var dropZone: some View {
        VStack(spacing: 8) {
            Image(systemName: "tray.and.arrow.down")
                .font(.system(size: 30))
                .foregroundStyle(isDropTargeted ? Color.accentColor : Color.secondary)
            Text("Glisse ici des fichiers, dossiers, DMG ou PKG à analyser")
                .foregroundStyle(.secondary)
            HStack {
                Button("Choisir…") {
                    model.pickAndScan(useClamav: clamavOverride)
                }
                Toggle("Inclure ClamAV (plus lent, plus complet)", isOn: $useClamav)
                    .toggleStyle(.checkbox)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(18)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [6, 4]))
                .foregroundStyle(isDropTargeted ? Color.accentColor : Color.secondary.opacity(0.5))
        )
        .dropDestination(for: URL.self) { urls, _ in
            let paths = urls.filter { $0.isFileURL }.map { $0.path }
            guard !paths.isEmpty else { return false }
            let override = clamavOverride
            Task { await model.startScan(paths: paths, useClamav: override) }
            return true
        } isTargeted: { targeted in
            isDropTargeted = targeted
        }
    }

    private var quickTargets: some View {
        HStack(spacing: 8) {
            Text("Cibles rapides :").foregroundStyle(.secondary)
            Button {
                scan(AppModel.downloadsPath)
            } label: {
                Label("Téléchargements", systemImage: "arrow.down.circle")
            }
            Button {
                scan(AppModel.applicationsPath)
            } label: {
                Label("Applications", systemImage: "app.badge")
            }
            Button {
                scan(AppModel.desktopPath)
            } label: {
                Label("Bureau", systemImage: "menubar.dock.rectangle")
            }
            Menu {
                if volumes.isEmpty {
                    Text("Aucun volume externe monté")
                }
                ForEach(volumes, id: \.self) { volume in
                    Button(volume.lastPathComponent) {
                        scan(volume.path)
                    }
                }
                Divider()
                Button("Actualiser la liste") {
                    volumes = AppModel.externalVolumes()
                }
            } label: {
                Label("Volume externe", systemImage: "externaldrive")
            }
            .fixedSize()
            Spacer()
        }
        .disabled(model.isBusy("scan"))
    }

    private func scan(_ path: String) {
        let override = clamavOverride
        Task { await model.startScan(paths: [path], useClamav: override) }
    }

    private var activeJobsView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("En cours").font(.headline)
            ForEach(model.activeJobs) { job in
                HStack(alignment: .top, spacing: 12) {
                    ProgressView().controlSize(.small)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(job.paths.joined(separator: ", "))
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Text("\(PBFormat.count(job.filesScanned)) fichiers · \(PBFormat.bytes(job.bytesScanned)) · \(job.threats) menace(s) · \(job.errors) erreur(s)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        if let current = job.currentPath {
                            Text(current)
                                .font(.caption.monospaced())
                                .foregroundStyle(.tertiary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    Spacer()
                    Text(job.origin.label).font(.caption).foregroundStyle(.secondary)
                    Button("Annuler") {
                        Task { await model.cancelScan(job.jobId) }
                    }
                    .controlSize(.small)
                }
                .padding(10)
                .background(Color.accentColor.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
            }
        }
    }

    private var recentJobsView: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("Analyses récentes").font(.headline)
            if model.recentJobs.isEmpty {
                Text("Aucune analyse récente.").foregroundStyle(.secondary)
            } else {
                List(selection: $model.selectedJobId) {
                    ForEach(model.recentJobs) { job in
                        JobRow(job: job)
                    }
                }
                .listStyle(.bordered(alternatesRowBackgrounds: true))
                .onChange(of: model.selectedJobId) { _, newValue in
                    guard let jobId = newValue, model.jobDetails[jobId] == nil else { return }
                    Task { await model.loadJobDetail(jobId) }
                }
            }
        }
    }

    @ViewBuilder
    private var findingsView: some View {
        if let jobId = model.selectedJobId {
            if let detail = model.jobDetails[jobId] {
                FindingsList(detail: detail)
            } else if model.isBusy("job-\(jobId)") {
                ProgressView("Chargement des résultats…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if let job = model.liveJobs[jobId], job.state.isActive {
                Text("Résultats disponibles à la fin de l'analyse.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                Button("Charger les résultats") {
                    Task { await model.loadJobDetail(jobId) }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        } else {
            ContentUnavailableView(
                "Aucune analyse sélectionnée",
                systemImage: "magnifyingglass",
                description: Text("Lance une analyse ou sélectionne une analyse récente pour voir ses résultats.")
            )
        }
    }
}

private struct JobRow: View {
    let job: ScanJobSummary

    var body: some View {
        HStack(spacing: 10) {
            Circle().fill(job.state.color).frame(width: 8, height: 8)
            VStack(alignment: .leading, spacing: 2) {
                Text(job.paths.joined(separator: ", "))
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text("\(job.origin.label) · \(PBFormat.dateTime(job.startedDate)) · \(job.state.label)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text("\(PBFormat.count(job.filesScanned)) fichiers")
                .font(.caption)
                .foregroundStyle(.secondary)
            if job.threats > 0 {
                Pill(text: "\(job.threats) menace(s)", color: .red)
            } else if !job.state.isActive {
                Pill(text: "Rien trouvé", color: .green)
            }
        }
        .padding(.vertical, 2)
    }
}

/// Findings of one job, with Quarantaine / Faux positif actions.
private struct FindingsList: View {
    @EnvironmentObject private var model: AppModel
    let detail: ScanJobDetail

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Résultats").font(.headline)
                Text("\(PBFormat.count(detail.summary.filesScanned)) fichiers analysés · \(PBFormat.bytes(detail.summary.bytesScanned))")
                    .foregroundStyle(.secondary)
                Spacer()
                if let finished = detail.summary.finishedDate {
                    Text("Durée : \(PBFormat.duration(seconds: Int(finished.timeIntervalSince(detail.summary.startedDate))))")
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 10)
            Divider()
            if detail.findings.isEmpty {
                ContentUnavailableView(
                    "Aucune menace",
                    systemImage: "checkmark.shield",
                    description: Text("Aucun fichier suspect ni erreur dans cette analyse.")
                )
            } else {
                List {
                    ForEach(Array(detail.findings.enumerated()), id: \.offset) { _, report in
                        FindingRow(report: report)
                    }
                }
            }
        }
    }
}

private struct FindingRow: View {
    @EnvironmentObject private var model: AppModel
    let report: ScanReport
    @State private var confirmQuarantine = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                VerdictBadge(verdict: report.verdict)
                Text(report.path)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                Spacer()
                Text("\(report.kind.label) · \(PBFormat.bytes(report.size))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if !report.detections.isEmpty {
                DetectionList(detections: report.detections)
            }
            HStack(spacing: 12) {
                if let signing = report.signing {
                    Label(signing.summary, systemImage: signing.isTrustworthy ? "checkmark.seal" : "seal")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Text("Score \(PBFormat.percent(report.score))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let error = report.error {
                    Label(error, systemImage: "exclamationmark.circle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                Spacer()
                if report.verdict != .clean && report.verdict != .unknown {
                    Button("Quarantaine") {
                        confirmQuarantine = true
                    }
                    .controlSize(.small)
                    Button("Faux positif") {
                        if let sha = report.sha256 {
                            Task { await model.reportFalsePositive(sha256: sha, path: report.path) }
                        }
                    }
                    .controlSize(.small)
                    .disabled(report.sha256 == nil)
                    .help(report.sha256 == nil ? "Empreinte SHA-256 inconnue" : "Ajoute ce fichier à la liste d'autorisation locale")
                }
                Button {
                    model.revealInFinder(report.containerPath)
                } label: {
                    Image(systemName: "magnifyingglass")
                }
                .buttonStyle(.borderless)
                .help("Afficher dans le Finder")
            }
        }
        .padding(.vertical, 4)
        .confirmationDialog(
            "Mettre en quarantaine « \((report.containerPath as NSString).lastPathComponent) » ?",
            isPresented: $confirmQuarantine
        ) {
            Button("Mettre en quarantaine", role: .destructive) {
                Task { await model.quarantineFile(path: report.containerPath) }
            }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("Le fichier est neutralisé et déplacé ; il reste restaurable depuis l'onglet Quarantaine.")
        }
    }
}
