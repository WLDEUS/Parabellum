import Charts
import ParabellumKit
import SwiftUI

struct ReportView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: ReportStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                periodBar
                if let report = store.current {
                    header(report)
                    figures(report)
                    HStack(alignment: .top, spacing: 16) {
                        Card(title: "Activité quotidienne", symbol: "chart.bar.fill") {
                            DailyActivityChart(report: report)
                        }
                        Card(title: "Réseau & VPN", symbol: "lock.shield") {
                            NetworkSummary(report: report)
                        }
                        .frame(maxWidth: 380)
                    }
                    HStack(alignment: .top, spacing: 16) {
                        Card(title: "Pubs et traqueurs bloqués", symbol: "hand.raised.slash") {
                            VStack(alignment: .leading, spacing: 12) {
                                DnsBlockedChart(report: report)
                                if !report.topBlockedDomains.isEmpty {
                                    Text("Domaines les plus bloqués").font(.subheadline.weight(.semibold))
                                    TopListChart(items: report.topBlockedDomains, color: Brand.violet)
                                }
                            }
                        }
                        Card(title: "Alertes par type", symbol: "bell.badge") {
                            AlertKindsChart(report: report)
                        }
                    }
                    HStack(alignment: .top, spacing: 16) {
                        Card(title: "Familles les plus détectées", symbol: "ladybug") {
                            TopListChart(items: report.topDetections, color: .red, empty: "Aucune détection sur cette période.")
                        }
                        Card(title: "Analyses par origine", symbol: "magnifyingglass") {
                            TopListChart(items: report.scansByOrigin, label: ReportText.origin, empty: "Aucune analyse.")
                        }
                    }
                    Card(title: "Vie privée", symbol: "hand.raised") {
                        PrivacySummaryView(report: report)
                    }
                    updates(report)
                } else if store.isLoading {
                    ProgressView("Chargement du rapport…").frame(maxWidth: .infinity).padding(40)
                } else {
                    ContentUnavailableView(
                        "Rapport indisponible",
                        systemImage: "chart.bar.xaxis",
                        description: Text(store.lastError ?? "")
                    )
                }
            }
            .padding(20)
        }
        .navigationTitle("Rapport")
        .toolbar {
            ToolbarItemGroup {
                if let report = store.current {
                    Button {
                        store.exportPDF(report)
                    } label: {
                        Label("Exporter en PDF", systemImage: "arrow.down.doc")
                    }
                    .help("Exporter ce rapport en PDF")
                }
                RefreshButton(isLoading: store.isLoading) {
                    Task { await store.load() }
                }
            }
        }
        .task { await store.load() }
        .onChange(of: store.period) { _, _ in
            store.offset = 0
            Task { await store.load() }
        }
        .onChange(of: store.offset) { _, _ in Task { await store.load() } }
        .onChange(of: store.customFrom) { _, _ in Task { await store.load() } }
        .onChange(of: store.customTo) { _, _ in Task { await store.load() } }
    }

    private var periodBar: some View {
        HStack(spacing: 12) {
            Picker("Période", selection: $store.period) {
                Text("Semaine").tag(ReportPeriod.week)
                Text("Mois").tag(ReportPeriod.month)
                Text("Personnalisée").tag(ReportPeriod.custom)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .fixedSize()
            switch store.period {
            case .custom:
                DatePicker("Du", selection: $store.customFrom, in: ...Date(), displayedComponents: .date)
                    .fixedSize()
                DatePicker("au", selection: $store.customTo, in: ...Date(), displayedComponents: .date)
                    .fixedSize()
            case .week, .month:
                Picker("Quand", selection: $store.offset) {
                    ForEach(0..<13, id: \.self) { offset in
                        Text(store.offsetLabel(offset)).tag(offset)
                    }
                }
                .labelsHidden()
                .fixedSize()
            }
            Spacer()
            if store.isLoading && store.current != nil {
                ProgressView().controlSize(.small)
            }
        }
    }

    private func header(_ report: ActivityReport) -> some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(store.title(for: report))
                    .font(.system(.title2, design: .rounded).weight(.bold))
                Text("Du \(PBFormat.day(report.startDate)) au \(PBFormat.day(report.lastDate))")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let version = report.dbVersion {
                Pill(text: "Base \(version)", color: .teal)
            }
        }
    }

    private func figures(_ report: ActivityReport) -> some View {
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
            ForEach(Array(ReportText.figures(report).enumerated()), id: \.offset) { _, f in
                StatTile(value: f.0, caption: f.1, symbol: f.2, tint: f.3)
            }
        }
    }

    @ViewBuilder
    private func updates(_ report: ActivityReport) -> some View {
        if !report.componentUpdates.isEmpty || report.persistenceNew > 0 || report.devicesNew > 0 {
            Card(title: "Système et mises à jour", symbol: "puzzlepiece.extension") {
                VStack(alignment: .leading, spacing: 6) {
                    Text("\(report.persistenceNew) nouvelle(s) persistance(s), \(report.devicesNew) nouveau(x) périphérique(s).")
                    ForEach(report.componentUpdates, id: \.self) { line in
                        Text(line).font(.system(.callout, design: .monospaced))
                    }
                }
            }
        }
    }
}
