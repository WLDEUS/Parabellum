import ParabellumKit
import SwiftUI

extension DailyVerdict {
    var color: Color {
        switch self {
        case .ok: return .green
        case .attention: return .orange
        case .critical: return .red
        case .unknown: return .secondary
        }
    }

    var symbol: String {
        switch self {
        case .ok: return "checkmark.seal.fill"
        case .attention: return "exclamationmark.triangle.fill"
        case .critical: return "xmark.octagon.fill"
        case .unknown: return "questionmark.circle"
        }
    }
}

/// Dashboard › « Rapport du jour »: verdict, key points, summary (template or local AI), the unseen
/// alerts that matter most, and the last 30 days.
struct DailyReportCard: View {
    @Environment(AppModel.self) private var model
    @State private var showHistory = false

    var body: some View {
        Card(title: String(localized: "Rapport du jour"), symbol: "sun.horizon") {
            if let report = model.dailyReport {
                content(report)
            } else if model.isFirstLoad("daily-report") {
                ProgressView().controlSize(.small)
            } else {
                HStack {
                    Text("Le premier rapport sera prêt demain matin.")
                        .foregroundStyle(.secondary)
                    Spacer()
                    generateButton
                }
            }
        }
        .sheet(isPresented: $showHistory) {
            DailyReportHistoryView()
                .environment(model)
        }
    }

    @ViewBuilder
    private func content(_ report: DailyReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: report.verdict.symbol)
                    .foregroundStyle(report.verdict.color)
                Text(report.headline)
                    .font(.title3.weight(.semibold))
                Spacer()
                Text(report.generatedDate, format: .dateTime.weekday(.wide).day().month().hour().minute())
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if !report.highlights.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(report.highlights, id: \.self) { point in
                        Label(point, systemImage: "arrow.right.circle")
                            .font(.callout)
                    }
                }
            }
            Text(report.summary)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
            if !report.facts.topUnseen.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 4) {
                    Text("Non vues")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    ForEach(report.facts.topUnseen) { line in
                        Button {
                            model.selectedAlertId = line.id
                            model.section = .alerts
                        } label: {
                            HStack(spacing: 6) {
                                Circle().fill(line.severity.color).frame(width: 7, height: 7)
                                Text(line.title).lineLimit(1).truncationMode(.middle)
                                Spacer()
                            }
                        }
                        .buttonStyle(.plain)
                        .font(.callout)
                    }
                }
            }
            HStack {
                if report.summarySource == .localAi {
                    Label("Résumé rédigé par le modèle local", systemImage: "cpu")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
                Spacer()
                Button("Historique…") { showHistory = true }
                generateButton
            }
        }
    }

    private var generateButton: some View {
        Button {
            Task { await model.generateDailyReport() }
        } label: {
            if model.isBusy("daily-generate") {
                ProgressView().controlSize(.small)
            } else {
                Text("Générer maintenant")
            }
        }
        .disabled(model.isBusy("daily-generate"))
    }
}

/// The last 30 reports; picking one shows it on the dashboard card.
struct DailyReportHistoryView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("Rapports des 30 derniers jours").font(.headline)
                Spacer()
                Button("Fermer") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(16)
            Divider()
            if model.dailyReports.isEmpty {
                ContentUnavailableView("Aucun rapport", systemImage: "sun.horizon")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(model.dailyReports) { summary in
                    Button {
                        Task {
                            await model.loadDailyReport(date: summary.date)
                            dismiss()
                        }
                    } label: {
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Image(systemName: summary.verdict.symbol)
                                .foregroundStyle(summary.verdict.color)
                            Text(summary.date).monospacedDigit()
                            Text(summary.headline).foregroundStyle(.secondary).lineLimit(1)
                            Spacer()
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
        .frame(width: 560, height: 460)
    }
}
