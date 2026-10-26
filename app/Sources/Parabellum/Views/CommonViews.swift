import AppKit
import ParabellumKit
import SwiftUI

/// Small colored capsule.
struct Pill: View {
    let text: String
    let color: Color
    var symbol: String?

    var body: some View {
        HStack(spacing: 4) {
            if let symbol {
                Image(systemName: symbol)
            }
            Text(text)
        }
        .font(.caption.weight(.semibold))
        .padding(.horizontal, 7)
        .padding(.vertical, 2)
        .foregroundStyle(color)
        .background(color.opacity(0.15), in: Capsule())
    }
}

struct VerdictBadge: View {
    let verdict: Verdict

    var body: some View {
        Pill(text: verdict.label, color: verdict.color, symbol: verdict.symbol)
    }
}

struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        Pill(text: severity.label, color: severity.color, symbol: severity.symbol)
    }
}

/// "Label    value" row for detail panes.
struct InfoRow: View {
    let label: String
    let value: String
    var monospaced = false
    var selectable = true

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(label)
                .foregroundStyle(.secondary)
                .frame(width: 150, alignment: .leading)
            Group {
                if selectable {
                    Text(value).textSelection(.enabled)
                } else {
                    Text(value)
                }
            }
            .font(monospaced ? .system(.body, design: .monospaced) : .body)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

/// Detections table used by scans, quarantine and alerts.
struct DetectionList: View {
    let detections: [Detection]

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(Array(detections.enumerated()), id: \.offset) { _, detection in
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: detection.severity.symbol)
                        .foregroundStyle(detection.severity.color)
                    Text(detection.name)
                        .font(.system(.callout, design: .monospaced))
                        .textSelection(.enabled)
                    Text(detection.engine.label)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(PBFormat.percent(detection.confidence))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if let details = detection.details {
                        Text(details)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
            }
        }
    }
}

/// Banner at the top of the main window (errors and confirmations).
struct BannerView: View {
    let banner: Banner
    let onClose: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: banner.isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                .foregroundStyle(banner.isError ? Color.orange : Color.green)
            Text(banner.message)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            Button {
                onClose()
            } label: {
                Image(systemName: "xmark")
            }
            .buttonStyle(.borderless)
            .help("Fermer")
        }
        .padding(10)
        .background((banner.isError ? Color.orange : Color.green).opacity(0.12))
    }
}

/// Section card used by the dashboard and other screens.
struct Card<Content: View>: View {
    let title: String
    var symbol: String?
    @ViewBuilder let content: () -> Content

    var body: some View {
        GroupBox {
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(6)
        } label: {
            if let symbol {
                Label(title, systemImage: symbol).font(.headline)
            } else {
                Text(title).font(.headline)
            }
        }
    }
}

/// Toolbar refresh button with a spinner while loading.
struct RefreshButton: View {
    let isLoading: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            if isLoading {
                ProgressView().controlSize(.small)
            } else {
                Label("Actualiser", systemImage: "arrow.clockwise")
            }
        }
        .help("Actualiser")
        .disabled(isLoading)
    }
}

/// Gives access to the hosting `NSWindow`.
struct WindowAccessor: NSViewRepresentable {
    let onWindow: (NSWindow) -> Void

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        DispatchQueue.main.async { [weak view] in
            if let window = view?.window {
                onWindow(window)
            }
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {}
}

/// Edits a list of strings (paths, domains, resolvers) one line per item.
struct StringListEditor: View {
    let title: String
    var placeholder = ""
    @Binding var items: [String]

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
            ForEach(Array(items.enumerated()), id: \.offset) { index, _ in
                HStack {
                    TextField(placeholder, text: binding(for: index))
                        .textFieldStyle(.roundedBorder)
                    Button {
                        if index < items.count {
                            items.remove(at: index)
                        }
                    } label: {
                        Image(systemName: "minus.circle")
                    }
                    .buttonStyle(.borderless)
                    .help("Retirer")
                }
            }
            Button {
                items.append("")
            } label: {
                Label("Ajouter", systemImage: "plus.circle")
            }
            .buttonStyle(.borderless)
        }
    }

    private func binding(for index: Int) -> Binding<String> {
        Binding(
            get: { index < items.count ? items[index] : "" },
            set: { newValue in
                if index < items.count {
                    items[index] = newValue
                }
            }
        )
    }
}
