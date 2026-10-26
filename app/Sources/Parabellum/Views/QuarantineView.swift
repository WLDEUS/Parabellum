import ParabellumKit
import SwiftUI

struct QuarantineView: View {
    @EnvironmentObject private var model: AppModel
    @State private var pendingDelete: QuarantineEntry?

    var body: some View {
        Group {
            if model.quarantine.isEmpty {
                ContentUnavailableView(
                    "Quarantaine vide",
                    systemImage: "archivebox",
                    description: Text("Les fichiers neutralisés apparaîtront ici. Rien n'est jamais supprimé sans ton accord.")
                )
            } else {
                List {
                    ForEach(model.quarantine) { entry in
                        QuarantineRow(entry: entry) {
                            pendingDelete = entry
                        }
                    }
                }
            }
        }
        .navigationTitle("Quarantaine")
        .toolbar {
            ToolbarItemGroup {
                Button {
                    model.pickAndQuarantine()
                } label: {
                    Label("Mettre un fichier en quarantaine…", systemImage: "plus")
                }
                .help("Mettre un fichier en quarantaine")
                RefreshButton(isLoading: model.isBusy("quarantine")) {
                    Task { await model.loadQuarantine() }
                }
            }
        }
        .task {
            await model.loadQuarantine()
        }
        .confirmationDialog(
            "Supprimer définitivement ce fichier ?",
            isPresented: Binding(
                get: { pendingDelete != nil },
                set: { if !$0 { pendingDelete = nil } }
            ),
            presenting: pendingDelete
        ) { entry in
            Button("Supprimer définitivement", role: .destructive) {
                pendingDelete = nil
                Task { await model.deleteQuarantined(entry) }
            }
            Button("Annuler", role: .cancel) {}
        } message: { entry in
            Text("« \(entry.originalPath) » sera effacé. Cette action est irréversible.")
        }
    }
}

private struct QuarantineRow: View {
    @EnvironmentObject private var model: AppModel
    let entry: QuarantineEntry
    let onDelete: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: "doc.badge.ellipsis").foregroundStyle(.secondary)
                Text(entry.fileName).font(.headline)
                Text(PBFormat.bytes(entry.size)).foregroundStyle(.secondary)
                Spacer()
                Text("\(PBFormat.dateTime(entry.quarantinedDate)) · \(reasonLabel)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(entry.originalPath)
                .font(.system(.callout, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
                .lineLimit(1)
                .truncationMode(.middle)
            if !entry.detections.isEmpty {
                DetectionList(detections: entry.detections)
            }
            HStack(spacing: 8) {
                Text("SHA-256 \(PBFormat.shortHash(entry.sha256)) · uid \(entry.ownerUid) · mode \(PBFormat.mode(entry.mode))")
                    .font(.caption.monospaced())
                    .foregroundStyle(.tertiary)
                    .textSelection(.enabled)
                Spacer()
                Button("Restaurer") {
                    Task { await model.restore(entry, allow: false) }
                }
                .help("Remet le fichier à son emplacement d'origine (avec ses droits)")
                Button("Restaurer et autoriser") {
                    Task { await model.restore(entry, allow: true) }
                }
                .help("Restaure et ajoute son empreinte à la liste d'autorisation (faux positif)")
                Button("Supprimer…", role: .destructive) {
                    onDelete()
                }
            }
            .controlSize(.small)
            .disabled(model.isBusy("restore-\(entry.id)") || model.isBusy("delete-\(entry.id)"))
        }
        .padding(.vertical, 6)
    }

    private var reasonLabel: String {
        switch entry.reason {
        case "auto": return "automatique"
        case "user": return "manuelle"
        case "persistence": return "persistance"
        default: return entry.reason
        }
    }
}
