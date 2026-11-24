import AppKit
import ParabellumKit
import SwiftUI
import UniformTypeIdentifiers

/// Alertes › Exporter… : full alert report as PDF, HTML, CSV, JSON or Markdown. The daemon renders it
/// (`export_alerts`, same output as `parabellum export-alerts`); PDF = that HTML, paginated by WebKit.
struct AlertExportSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    enum Format: String, CaseIterable, Identifiable {
        case pdf, html, csv, json, markdown
        var id: String { rawValue }

        var label: String {
            switch self {
            case .pdf: return String(localized: "PDF (à imprimer ou partager)")
            case .html: return String(localized: "HTML (page web autonome)")
            case .csv: return String(localized: "CSV (Excel, Numbers)")
            case .json: return String(localized: "JSON (outils, scripts)")
            case .markdown: return String(localized: "Markdown (notes, Obsidian)")
            }
        }

        /// What the daemon renders.
        var wire: AlertExportFormat {
            switch self {
            case .pdf, .html: return .html
            case .csv: return .csv
            case .json: return .json
            case .markdown: return .markdown
            }
        }

        var fileExtension: String { self == .pdf ? "pdf" : wire.fileExtension }

        var contentType: UTType {
            switch self {
            case .pdf: return .pdf
            case .html: return .html
            case .csv: return .commaSeparatedText
            case .json: return .json
            case .markdown: return UTType(filenameExtension: "md") ?? .plainText
            }
        }
    }

    enum Period: String, CaseIterable, Identifiable {
        case all, week, month, year, custom
        var id: String { rawValue }

        var label: String {
            switch self {
            case .all: return String(localized: "Toutes les alertes")
            case .week: return String(localized: "7 derniers jours")
            case .month: return String(localized: "30 derniers jours")
            case .year: return String(localized: "12 derniers mois")
            case .custom: return String(localized: "Période personnalisée")
            }
        }

        /// Days back from today (inclusive range), nil = no lower bound.
        var days: Int? {
            switch self {
            case .all, .custom: return nil
            case .week: return 6
            case .month: return 29
            case .year: return 364
            }
        }
    }

    @State private var format: Format = .pdf
    @State private var period: Period = .all
    @State private var from = Calendar.current.date(byAdding: .day, value: -29, to: Date()) ?? Date()
    @State private var to = Date()
    @State private var includeResolved = true
    @State private var minSeverity: Severity?
    @State private var working = false
    @State private var error: String?

    private static let day: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = .current
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    /// The report follows the app's language.
    private var lang: String {
        (Bundle.main.preferredLocalizations.first ?? "fr").hasPrefix("en") ? "en" : "fr"
    }

    private var range: (from: String?, to: String?) {
        switch period {
        case .all:
            return (nil, nil)
        case .custom:
            return (Self.day.string(from: min(from, to)), Self.day.string(from: max(from, to)))
        default:
            let start = Calendar.current.date(byAdding: .day, value: -(period.days ?? 0), to: Date()) ?? Date()
            return (Self.day.string(from: start), Self.day.string(from: Date()))
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Exporter un rapport des alertes", systemImage: "square.and.arrow.up")
                .font(.title3.weight(.semibold))
            Form {
                Picker("Format", selection: $format) {
                    ForEach(Format.allCases) { Text($0.label).tag($0) }
                }
                Picker("Période", selection: $period) {
                    ForEach(Period.allCases) { Text($0.label).tag($0) }
                }
                if period == .custom {
                    DatePicker("Du", selection: $from, in: ...Date(), displayedComponents: .date)
                    DatePicker("Au", selection: $to, in: ...Date(), displayedComponents: .date)
                }
                Picker("Gravité minimale", selection: $minSeverity) {
                    Text("Toutes").tag(Severity?.none)
                    ForEach(Severity.known, id: \.self) { s in
                        Text(s.label).tag(Optional(s))
                    }
                }
                Toggle("Inclure les alertes vues et résolues", isOn: $includeResolved)
            }
            .formStyle(.grouped)
            Text("Le rapport contient un résumé (par gravité, statut et type) puis chaque alerte avec sa date, son message, le fichier, l'empreinte SHA-256 et le processus en cause. Il ne quitte pas ce Mac : rien n'est envoyé.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            if let error {
                Text(error).font(.callout).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                if working {
                    ProgressView().controlSize(.small)
                    Text("Préparation du rapport…").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Annuler", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(working)
                Button("Exporter…") { Task { await export() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(working)
            }
        }
        .padding(22)
        .frame(width: 520)
    }

    private func export() async {
        error = nil
        working = true
        defer { working = false }
        let (fromDay, toDay) = range
        let request = Request.exportAlerts(
            format: format.wire,
            from: fromDay,
            to: toDay,
            includeResolved: includeResolved,
            minSeverity: minSeverity,
            lang: lang
        )
        guard let report = await model.perform("alerts-export", { try await model.call(request, as: AlertExport.self) }) else {
            error = String(localized: "Le service n'a pas pu préparer le rapport.")
            return
        }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [format.contentType]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = (report.fileName as NSString).deletingPathExtension + "." + format.fileExtension
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            if format == .pdf {
                try await HTMLToPDF.write(html: report.content, to: url)
            } else {
                try report.content.write(to: url, atomically: true, encoding: .utf8)
            }
        } catch {
            self.error = String(localized: "Export impossible : \(error.localizedDescription)")
            return
        }
        let message = report.truncated
            ? String(localized: "Rapport exporté : \(report.count) alertes les plus récentes sur \(report.total) (réduisez la période pour le reste).")
            : String(localized: "Rapport exporté : \(report.count) alerte(s).")
        model.banner = Banner(message: message, isError: report.truncated)
        NSWorkspace.shared.activateFileViewerSelecting([url])
        dismiss()
    }
}
