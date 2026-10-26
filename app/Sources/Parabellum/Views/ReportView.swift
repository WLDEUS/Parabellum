import Charts
import ParabellumKit
import SwiftUI

struct ReportView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                weekPicker
                if let report = model.weeklyReport {
                    summary(report)
                    detectionsChart(report)
                    if !report.componentUpdates.isEmpty {
                        Card(title: "Mises à jour des composants", symbol: "puzzlepiece.extension") {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(report.componentUpdates, id: \.self) { line in
                                    Text(line).font(.system(.body, design: .monospaced))
                                }
                            }
                        }
                    }
                } else if model.isBusy("report") {
                    ProgressView("Chargement du rapport…").padding(40)
                } else {
                    ContentUnavailableView("Rapport indisponible", systemImage: "chart.bar.xaxis")
                }
            }
            .padding(20)
        }
        .navigationTitle("Rapport hebdomadaire")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("report")) {
                    Task { await model.loadReport() }
                }
            }
        }
        .task {
            await model.loadReport()
        }
        .onChange(of: model.reportWeekOffset) { _, _ in
            Task { await model.loadReport() }
        }
    }

    private var weekPicker: some View {
        HStack {
            Picker("Semaine", selection: $model.reportWeekOffset) {
                ForEach(0..<13, id: \.self) { offset in
                    Text(weekLabel(offset)).tag(offset)
                }
            }
            .fixedSize()
            Spacer()
            if let report = model.weeklyReport {
                Text("Du \(PBFormat.day(report.weekStartDate)) au \(PBFormat.day(report.weekEndDate))")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func weekLabel(_ offset: Int) -> String {
        switch offset {
        case 0: return "Cette semaine"
        case 1: return "Semaine dernière"
        default: return "Il y a \(offset) semaines"
        }
    }

    private func summary(_ report: WeeklyReport) -> some View {
        Card(title: "Résumé", symbol: "list.bullet.rectangle") {
            Grid(alignment: .leading, horizontalSpacing: 30, verticalSpacing: 10) {
                GridRow {
                    stat("Fichiers analysés", PBFormat.count(report.filesScanned), "doc.text.magnifyingglass")
                    stat("Menaces détectées", PBFormat.count(report.threatsDetected), "ladybug", highlight: report.threatsDetected > 0)
                    stat("Mises en quarantaine", PBFormat.count(report.quarantined), "archivebox")
                }
                GridRow {
                    stat("Faux positifs signalés", PBFormat.count(report.falsePositivesReported), "hand.thumbsup")
                    stat("Nouvelles persistances", PBFormat.count(report.persistenceNew), "arrow.triangle.2.circlepath", highlight: report.persistenceNew > 0)
                    stat("Nouveaux périphériques", PBFormat.count(report.devicesNew), "cable.connector")
                }
                GridRow {
                    stat("Mises à jour de la base", PBFormat.count(report.dbUpdates), "cylinder.split.1x2")
                    stat("Version de la base", report.dbVersion ?? "—", "number")
                    stat("Requêtes DNS bloquées", report.dnsBlockedQueries.map { PBFormat.count($0) } ?? "—", "network.badge.shield.half.filled")
                }
            }
        }
    }

    private func stat(_ title: String, _ value: String, _ symbol: String, highlight: Bool = false) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.title3)
                .foregroundStyle(highlight ? Color.orange : Color.secondary)
                .frame(width: 26)
            VStack(alignment: .leading, spacing: 2) {
                Text(value).font(.title3.weight(.semibold).monospacedDigit())
                Text(title).font(.caption).foregroundStyle(.secondary)
            }
        }
    }

    private func detectionsChart(_ report: WeeklyReport) -> some View {
        Card(title: "Familles les plus détectées", symbol: "chart.bar.xaxis") {
            if report.topDetections.isEmpty {
                Text("Aucune détection cette semaine.")
                    .foregroundStyle(.secondary)
            } else {
                Chart(report.topDetections) { item in
                    BarMark(
                        x: .value("Détections", item.count),
                        y: .value("Famille", item.name)
                    )
                    .foregroundStyle(Color.red.gradient)
                    .annotation(position: .trailing) {
                        Text("\(item.count)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .chartXAxisLabel("Détections")
                .frame(height: max(120, CGFloat(report.topDetections.count) * 32))
            }
        }
    }
}
