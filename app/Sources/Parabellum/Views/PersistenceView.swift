import ParabellumKit
import SwiftUI

struct PersistenceView: View {
    @EnvironmentObject private var model: AppModel
    @State private var onlyNew = false
    @State private var pendingRemoval: PersistenceItem?

    /// New items first, then most recent.
    private var items: [PersistenceItem] {
        let list = onlyNew ? model.persistence.filter { $0.status == .new } : model.persistence
        return list.sorted { lhs, rhs in
            let lhsNew = lhs.status == .new
            let rhsNew = rhs.status == .new
            if lhsNew != rhsNew {
                return lhsNew
            }
            return lhs.firstSeen > rhs.firstSeen
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Toggle("Seulement les nouveaux éléments", isOn: $onlyNew)
                    .toggleStyle(.checkbox)
                Spacer()
                Text("\(model.persistence.filter { $0.status == .new }.count) nouveau(x) sur \(model.persistence.count)")
                    .foregroundStyle(.secondary)
            }
            .padding(10)
            Divider()
            if items.isEmpty {
                ContentUnavailableView(
                    onlyNew ? "Aucun nouvel élément" : "Aucun élément de persistance",
                    systemImage: "checkmark.shield",
                    description: Text("LaunchAgents, LaunchDaemons, éléments de connexion, profils… apparaîtront ici.")
                )
            } else {
                List {
                    ForEach(items) { item in
                        PersistenceRow(item: item) {
                            pendingRemoval = item
                        }
                    }
                }
            }
        }
        .navigationTitle("Persistance")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("persistence")) {
                    Task { await model.loadPersistence() }
                }
            }
        }
        .task {
            await model.loadPersistence()
        }
        .confirmationDialog(
            "Supprimer cet élément de persistance ?",
            isPresented: Binding(
                get: { pendingRemoval != nil },
                set: { if !$0 { pendingRemoval = nil } }
            ),
            presenting: pendingRemoval
        ) { item in
            Button("Décharger et mettre en quarantaine", role: .destructive) {
                pendingRemoval = nil
                Task { await model.setPersistence(item, status: .removed) }
            }
            Button("Annuler", role: .cancel) {}
        } message: { item in
            Text("L'élément « \(item.label ?? item.path) » sera déchargé, et son plist et son programme mis en quarantaine (restaurables).")
        }
    }
}

private struct PersistenceRow: View {
    @EnvironmentObject private var model: AppModel
    let item: PersistenceItem
    let onRemove: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Pill(text: item.status.label, color: item.status.color)
                Text(item.label ?? (item.path as NSString).lastPathComponent)
                    .font(.headline)
                    .textSelection(.enabled)
                Text(item.kind.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Spacer()
                if let verdict = item.verdict {
                    VerdictBadge(verdict: verdict)
                }
            }
            InfoRow(label: "Fichier", value: item.path, monospaced: true)
            if let program = item.program {
                InfoRow(label: "Programme", value: program, monospaced: true)
            }
            if item.arguments.count > 1 || (item.arguments.count == 1 && item.arguments.first != item.program) {
                InfoRow(label: "Arguments", value: item.arguments.joined(separator: " "), monospaced: true)
            }
            if let signing = item.signing {
                HStack {
                    Text("Signature")
                        .foregroundStyle(.secondary)
                        .frame(width: 150, alignment: .leading)
                    Label(signing.summary, systemImage: signing.isTrustworthy ? "checkmark.seal.fill" : "seal")
                        .foregroundStyle(signing.isTrustworthy ? Color.green : Color.orange)
                }
            }
            if let sha = item.programSha256 {
                InfoRow(label: "SHA-256", value: sha, monospaced: true)
            }
            HStack {
                Text(seenText)
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                Spacer()
                if item.status == .new {
                    Button("Approuver") {
                        Task { await model.setPersistence(item, status: .approved) }
                    }
                }
                if item.status == .new || item.status == .approved || item.status == .baseline {
                    Button("Supprimer…", role: .destructive) {
                        onRemove()
                    }
                }
                Button {
                    model.revealInFinder(item.path)
                } label: {
                    Image(systemName: "magnifyingglass")
                }
                .buttonStyle(.borderless)
                .help("Afficher dans le Finder")
            }
            .controlSize(.small)
            .disabled(model.isBusy("persistence-\(item.id)"))
        }
        .padding(8)
        .background(item.status == .new ? Color.orange.opacity(0.07) : Color.clear, in: RoundedRectangle(cornerRadius: 8))
    }

    private var seenText: String {
        var text = "Vu pour la première fois " + PBFormat.relative(item.firstSeenDate)
        if let user = item.user {
            text += " · utilisateur " + user
        }
        return text
    }
}
