import AppKit
import Charts
import ParabellumKit
import SwiftUI

/// Multi-page A4 PDF of an activity report: dedicated print layout (white paper, no glass), each page
/// rendered with `ImageRenderer` into a PDF context.
enum ReportPDF {
    /// A4 in points.
    static let pageSize = CGSize(width: 595, height: 842)

    @MainActor
    static func write(_ report: ActivityReport, title: String, to url: URL) throws {
        var box = CGRect(origin: .zero, size: pageSize)
        guard let context = CGContext(url as CFURL, mediaBox: &box, nil) else {
            throw CocoaError(.fileWriteUnknown)
        }
        let pages = ReportPrintPages(report: report, title: title).pages
        for (index, page) in pages.enumerated() {
            let content = PrintPage(title: title, number: index + 1, count: pages.count) { page }
                .frame(width: pageSize.width, height: pageSize.height)
                .environment(\.colorScheme, .light)
            let renderer = ImageRenderer(content: content)
            renderer.proposedSize = ProposedViewSize(pageSize)
            renderer.render { _, draw in
                context.beginPDFPage(nil)
                draw(context)
                context.endPDFPage()
            }
        }
        context.closePDF()
    }
}

/// Page frame: header, content, footer with page number.
private struct PrintPage<Content: View>: View {
    let title: String
    let number: Int
    let count: Int
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                BrandMark(size: 16)
                Text("Parabellum").font(.system(size: 13, weight: .bold, design: .rounded))
                Spacer()
                Text(title).font(.system(size: 10)).foregroundStyle(.secondary)
            }
            Divider()
            content()
            Spacer(minLength: 0)
            Divider()
            HStack {
                Text("Généré le \(PBFormat.dateTime(Date()))")
                Spacer()
                Text("Page \(number) / \(count)")
            }
            .font(.system(size: 9))
            .foregroundStyle(.secondary)
        }
        .padding(36)
        .background(Color.white)
        .foregroundStyle(Color.black)
    }
}

/// Plain bordered section for paper.
private struct PrintSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 12, weight: .semibold))
            content()
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .overlay(RoundedRectangle(cornerRadius: 8).stroke(Color.black.opacity(0.12), lineWidth: 0.8))
    }
}

/// The pages of the print layout (fixed split, so long lists never overflow).
private struct ReportPrintPages {
    let report: ActivityReport
    let title: String

    var pages: [AnyView] {
        var v: [AnyView] = [AnyView(summary), AnyView(network)]
        if !report.componentUpdates.isEmpty || report.privacy != nil || report.breachesFound > 0 {
            v.append(AnyView(privacyAndUpdates))
        }
        return v
    }

    private var summary: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title).font(.system(size: 20, weight: .bold, design: .rounded))
            Text("Du \(PBFormat.day(report.startDate)) au \(PBFormat.day(report.lastDate))")
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
            Grid(alignment: .leading, horizontalSpacing: 18, verticalSpacing: 10) {
                let figures = ReportText.figures(report)
                ForEach(0..<(figures.count / 2), id: \.self) { row in
                    GridRow {
                        figure(figures[row * 2])
                        figure(figures[row * 2 + 1])
                    }
                }
            }
            PrintSection(title: String(localized: "Activité quotidienne")) {
                DailyActivityChart(report: report)
            }
            PrintSection(title: String(localized: "Familles les plus détectées")) {
                TopListChart(items: Array(report.topDetections.prefix(8)), color: .red, empty: String(localized: "Aucune détection sur cette période."))
            }
        }
    }

    private func figure(_ f: (String, String, String, Color)) -> some View {
        HStack(spacing: 8) {
            Image(systemName: f.2).foregroundStyle(f.3).frame(width: 18)
            Text(f.0).font(.system(size: 14, weight: .semibold)).monospacedDigit()
            Text(f.1).font(.system(size: 10)).foregroundStyle(.secondary)
        }
    }

    private var network: some View {
        VStack(alignment: .leading, spacing: 14) {
            PrintSection(title: String(localized: "Réseau & VPN")) {
                NetworkSummary(report: report)
            }
            PrintSection(title: String(localized: "Pubs et traqueurs bloqués")) {
                DnsBlockedChart(report: report)
                TopListChart(items: Array(report.topBlockedDomains.prefix(8)), color: Brand.violet, empty: String(localized: "Aucun domaine bloqué enregistré."))
            }
            PrintSection(title: String(localized: "Alertes par type")) {
                AlertKindsChart(report: report)
            }
        }
    }

    private var privacyAndUpdates: some View {
        VStack(alignment: .leading, spacing: 14) {
            PrintSection(title: String(localized: "Vie privée")) {
                PrivacySummaryView(report: report)
            }
            PrintSection(title: String(localized: "Système et mises à jour")) {
                Text("\(report.persistenceNew) nouvelle(s) persistance(s), \(report.devicesNew) nouveau(x) périphérique(s), \(report.dbUpdates) mise(s) à jour de la base\(report.dbVersion.map { " (version \($0))" } ?? "").")
                    .font(.system(size: 11))
                ForEach(Array(report.componentUpdates.prefix(30)), id: \.self) { line in
                    Text(line).font(.system(size: 9, design: .monospaced))
                }
            }
        }
    }
}
