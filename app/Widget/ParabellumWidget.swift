// Desktop / Notification Center widget (WidgetKit extension). Not part of Package.swift: built by
// scripts/build-widget.sh with swiftc into Parabellum.app/Contents/PlugIns/ParabellumWidget.appex, together
// with app/Sources/ParabellumKit/WidgetSnapshot.swift. Sandboxed: it only reads the JSON the app writes into
// this extension's own container (its home directory).
import SwiftUI
import WidgetKit

struct StatusEntry: TimelineEntry {
    let date: Date
    let snapshot: WidgetSnapshot?
}

enum SnapshotFile {
    static func load() -> WidgetSnapshot? {
        let url = URL(fileURLWithPath: NSHomeDirectory(), isDirectory: true)
            .appendingPathComponent(WidgetSnapshot.fileName)
        guard let data = try? Data(contentsOf: url), data.count < 64 * 1024 else { return nil }
        return try? JSONDecoder().decode(WidgetSnapshot.self, from: data)
    }
}

struct StatusProvider: TimelineProvider {
    func placeholder(in context: Context) -> StatusEntry {
        StatusEntry(date: Date(), snapshot: .placeholder)
    }

    func getSnapshot(in context: Context, completion: @escaping (StatusEntry) -> Void) {
        completion(StatusEntry(date: Date(), snapshot: SnapshotFile.load() ?? .placeholder))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<StatusEntry>) -> Void) {
        // The app asks for a reload when something changes; this is only a safety net.
        let entry = StatusEntry(date: Date(), snapshot: SnapshotFile.load())
        completion(Timeline(entries: [entry], policy: .after(Date().addingTimeInterval(15 * 60))))
    }
}

struct StatusWidgetView: View {
    let entry: StatusEntry
    @Environment(\.widgetFamily) private var family

    private var color: Color {
        switch entry.snapshot?.protection {
        case "active": return .green
        case "paused": return .orange
        case "degraded", "unreachable": return .red
        default: return .gray
        }
    }

    private var symbol: String {
        switch entry.snapshot?.protection {
        case "active": return "checkmark.shield.fill"
        case "paused": return "pause.circle.fill"
        default: return "exclamationmark.shield.fill"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: symbol)
                    .font(.title2)
                    .foregroundStyle(color)
                Text("Parabellum")
                    .font(.headline)
            }
            if let s = entry.snapshot {
                Text(s.protectionLabel)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(color)
                    .lineLimit(1)
                if s.openAlerts > 0 {
                    Label("\(s.openAlerts) alerte\(s.openAlerts > 1 ? "s" : "")", systemImage: "bell.badge.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                if let vpn = s.vpnLabel {
                    Label("VPN \(vpn)", systemImage: s.vpnConnected ? "lock.fill" : "lock.open")
                        .font(.caption)
                }
                if s.travelActive {
                    Label("Mode Voyage", systemImage: "airplane")
                        .font(.caption)
                        .foregroundStyle(.cyan)
                }
                if family != .systemSmall, let last = s.lastScan {
                    Text("Dernière analyse : \(Date(timeIntervalSince1970: TimeInterval(last)).formatted(date: .abbreviated, time: .shortened))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("Ouvrez Parabellum une fois pour afficher l'état.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .containerBackground(for: .widget) {
            Color.clear
        }
        .widgetURL(URL(string: "parabellum://open"))
    }
}

struct ParabellumStatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "ParabellumStatus", provider: StatusProvider()) { entry in
            StatusWidgetView(entry: entry)
        }
        .configurationDisplayName("Parabellum")
        .description("État de la protection, du VPN et du mode Voyage.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

@main
struct ParabellumWidgets: WidgetBundle {
    var body: some Widget {
        ParabellumStatusWidget()
    }
}
