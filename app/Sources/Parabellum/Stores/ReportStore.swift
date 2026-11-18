import AppKit
import Foundation
import ParabellumKit
import SwiftUI
import UniformTypeIdentifiers

/// State and actions of the "Rapport" section: period picker, cached reports, PDF export.
@MainActor
final class ReportStore: ObservableObject {
    unowned let model: AppModel

    @Published var period: ReportPeriod = .week
    /// 0 = current week / month, 1 = previous…
    @Published var offset = 0
    @Published var customFrom: Date = Calendar.current.date(byAdding: .day, value: -29, to: Date()) ?? Date()
    @Published var customTo = Date()
    /// Last report per request key: switching back to a period shows it at once.
    @Published private(set) var reports: [String: ActivityReport] = [:]
    @Published private(set) var lastError: String?

    init(model: AppModel) {
        self.model = model
    }

    static let dayFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    private var request: Request {
        switch period {
        case .custom:
            let from = min(customFrom, customTo)
            let to = max(customFrom, customTo)
            return .report(
                period: .custom,
                from: Self.dayFormatter.string(from: from),
                to: Self.dayFormatter.string(from: to)
            )
        case .week, .month:
            return .report(period: period, offset: offset)
        }
    }

    private var key: String {
        switch request {
        case let .report(period, offset, from, to):
            return "\(period.rawValue)|\(offset)|\(from ?? "")|\(to ?? "")"
        default:
            return ""
        }
    }

    /// Report of the current selection (cached until reloaded).
    var current: ActivityReport? { reports[key] }

    var isLoading: Bool { model.isBusy("report") }

    /// Called when the section is shown, after (re)connection and when the period changes. Cheap when
    /// cached: the request is still sent, but the cached report stays on screen meanwhile.
    func load() async {
        let request = self.request
        let key = self.key
        let result = await model.perform("report", quiet: true) {
            try await self.model.call(request, as: ActivityReport.self, timeout: 30)
        }
        if let result {
            reports[key] = result
            lastError = nil
        } else if reports[key] == nil {
            lastError = "Rapport indisponible (le service est-il à jour ?)."
        }
    }

    /// Navigation from an alert / notification (`report?period=month&month=2026-10`).
    func open(_ link: SectionLink) {
        if link.query["period"] == "month" {
            period = .month
            if let month = link.query["month"], let off = monthOffset(of: month) {
                offset = off
            } else if let off = link.query["offset"].flatMap(Int.init) {
                offset = max(0, off)
            }
        } else if link.query["period"] == "week" {
            period = .week
            offset = max(0, link.query["offset"].flatMap(Int.init) ?? 0)
        }
    }

    // MARK: - Labels

    func offsetLabel(_ offset: Int) -> String {
        switch (period, offset) {
        case (.week, 0): return "Cette semaine"
        case (.week, 1): return "Semaine dernière"
        case (.week, _): return "Il y a \(offset) semaines"
        case (.month, _):
            guard let date = Calendar.current.date(byAdding: .month, value: -offset, to: Date()) else { return "" }
            return Self.monthFormatter.string(from: date).capitalized(with: PBFormat.locale)
        default: return ""
        }
    }

    static let monthFormatter: DateFormatter = {
        let f = DateFormatter()
        f.locale = PBFormat.locale
        f.dateFormat = "LLLL yyyy"
        return f
    }()

    func title(for report: ActivityReport) -> String {
        switch report.period {
        case .month:
            return "Rapport de " + Self.monthFormatter.string(from: report.startDate)
        case .week:
            return "Rapport de la semaine du \(PBFormat.day(report.startDate))"
        case .custom:
            return "Rapport du \(PBFormat.day(report.startDate)) au \(PBFormat.day(report.lastDate))"
        }
    }

    // MARK: - PDF export

    /// Renders the print layout (A4 pages) to a PDF chosen with a save panel.
    func exportPDF(_ report: ActivityReport) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.pdf]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "Parabellum – \(title(for: report)).pdf"
        NSApp.activate()
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try ReportPDF.write(report, title: title(for: report), to: url)
            model.banner = Banner(message: "Rapport exporté : \(url.lastPathComponent)", isError: false)
            NSWorkspace.shared.activateFileViewerSelecting([url])
        } catch {
            model.banner = Banner(message: "Export PDF impossible : \(error.localizedDescription)", isError: true)
        }
    }
}
