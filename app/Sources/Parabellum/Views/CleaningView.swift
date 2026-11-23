import Charts
import ParabellumKit
import SwiftUI

/// "Nettoyage": what can be reclaimed, by category, with a reviewable selection. Runs as the user.
struct CleaningView: View {
    @Environment(AppModel.self) private var model
    @ObservedObject var store: CleaningStore
    @State private var confirming = false
    @State private var startupToDisable: PersistenceItem?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let error = store.lastError, store.scan == nil {
                    ContentUnavailableView("Analyse impossible", systemImage: "exclamationmark.triangle", description: Text(error))
                } else if store.scan == nil {
                    VStack(spacing: 14) {
                        ProgressView()
                        Text("Recherche de ce qui peut être nettoyé…").foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(60)
                } else {
                    hero
                    if let summary = store.lastSummary {
                        summaryCard(summary)
                    }
                    ForEach(store.categories) { category in
                        CleaningCategoryCard(store: store, category: category)
                    }
                    startupCard
                    if let warnings = store.scan?.warnings, !warnings.isEmpty {
                        Card(title: String(localized: "Non analysé"), symbol: "eye.slash") {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(warnings, id: \.self) { Text($0).font(.callout).foregroundStyle(.secondary) }
                            }
                        }
                    }
                }
            }
            .padding(20)
        }
        .navigationTitle("Nettoyage")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: store.isScanning) {
                    Task { await store.rescan() }
                }
                .disabled(store.isCleaning)
            }
        }
        .task { await store.load() }
        .confirmationDialog(confirmTitle, isPresented: $confirming, titleVisibility: .visible) {
            Button("Nettoyer", role: .destructive) {
                Task { await store.clean() }
            }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text(confirmMessage)
        }
        .confirmationDialog(
            "Désactiver « \(startupToDisable?.label ?? "") » ?",
            isPresented: Binding(get: { startupToDisable != nil }, set: { if !$0 { startupToDisable = nil } }),
            titleVisibility: .visible
        ) {
            Button("Décharger et mettre en quarantaine", role: .destructive) {
                if let item = startupToDisable {
                    Task { await model.setPersistence(item, status: .removed) }
                }
                startupToDisable = nil
            }
            Button("Annuler", role: .cancel) { startupToDisable = nil }
        } message: {
            Text("L'élément est déchargé et son fichier mis en quarantaine (restaurable). Mot de passe administrateur requis.")
        }
    }

    // MARK: - Hero

    private var hero: some View {
        HStack(alignment: .center, spacing: 28) {
            ZStack {
                Chart(store.categories.filter { $0.size > 0 }) { category in
                    SectorMark(
                        angle: .value("Taille", category.size),
                        innerRadius: .ratio(0.72),
                        angularInset: 1.5
                    )
                    .cornerRadius(4)
                    .foregroundStyle(CleaningPalette.color(category.category))
                    .opacity(store.selectedSize(category) > 0 ? 1 : 0.35)
                }
                .chartLegend(.hidden)
                if store.categories.allSatisfy({ $0.size == 0 }) {
                    Circle().stroke(Color.green.opacity(0.35), lineWidth: 18)
                }
                VStack(spacing: 2) {
                    Text(PBFormat.bytes(store.selectedSize))
                        .font(.system(size: 30, weight: .bold, design: .rounded))
                        .monospacedDigit()
                        .contentTransition(.numericText())
                    Text("récupérables").font(.callout).foregroundStyle(.secondary)
                }
            }
            .frame(width: 210, height: 210)
            .animation(.smooth, value: store.selectedSize)

            VStack(alignment: .leading, spacing: 12) {
                Text(store.selectedSize > 0 ? "Prêt à faire de la place" : "Ton Mac est propre")
                    .font(.system(.title2, design: .rounded).weight(.bold))
                Text("\(store.selectedCount) élément(s) cochés sur \(PBFormat.bytes(store.scan?.totalSize ?? 0)) trouvés. Par défaut tout va à la corbeille : rien n'est perdu tant qu'elle n'est pas vidée.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                legend
                HStack(spacing: 12) {
                    Button {
                        confirming = true
                    } label: {
                        Label("Nettoyer", systemImage: "sparkles")
                    }
                    .buttonStyle(.brand)
                    .disabled(store.selectedCount == 0 || store.isCleaning || store.isScanning)
                    if store.isCleaning {
                        ProgressView(value: store.progress) {
                            Text(store.progressLabel).font(.caption)
                        }
                        .frame(width: 200)
                    } else if store.isScanning {
                        ProgressView().controlSize(.small)
                        Text("Analyse…").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Toggle("Me rappeler chaque mois ce qui est récupérable", isOn: $store.remindersEnabled)
                    .toggleStyle(.checkbox)
                    .font(.callout)
            }
            Spacer(minLength: 0)
        }
        .padding(22)
        .glassSurface()
    }

    private var legend: some View {
        let shown = store.categories.filter { $0.size > 0 }
        return LazyVGrid(columns: [GridItem(.adaptive(minimum: 190), alignment: .leading)], alignment: .leading, spacing: 6) {
            ForEach(shown) { category in
                HStack(spacing: 6) {
                    Circle().fill(CleaningPalette.color(category.category)).frame(width: 8, height: 8)
                    Text(category.title).font(.caption)
                    Text(PBFormat.bytes(category.size)).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var confirmTitle: String {
        String(localized: "Nettoyer \(PBFormat.bytes(store.selectedSize)) ?")
    }

    private var confirmMessage: String {
        var parts: [String] = []
        let permanent = store.categories.filter { store.permanent.contains($0.category) && store.selectedSize($0) > 0 }
        if permanent.isEmpty {
            parts.append(String(localized: "Les éléments cochés vont à la corbeille."))
        } else {
            parts.append(String(localized: "Suppression définitive pour : \(permanent.map(\.title).joined(separator: ", ")). Le reste va à la corbeille."))
        }
        if let trash = store.categories.first(where: { $0.category == .trash }), store.selectedSize(trash) > 0 {
            parts.append(String(localized: "La corbeille actuelle sera vidée définitivement."))
        }
        parts.append(String(localized: "Les applications ouvertes gardent leurs fichiers : quitte-les pour un nettoyage complet."))
        return parts.joined(separator: " ")
    }

    // MARK: - Result

    private func summaryCard(_ s: CleaningSummary) -> some View {
        Card(title: s.failed == 0 ? String(localized: "Nettoyage terminé") : String(localized: "Nettoyage terminé avec des erreurs"), symbol: s.failed == 0 ? "checkmark.seal.fill" : "exclamationmark.triangle.fill") {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    StatTile(value: PBFormat.bytes(s.freedBytes), caption: String(localized: "libérés"), symbol: "externaldrive.badge.checkmark", tint: .green)
                    StatTile(value: PBFormat.bytes(s.trashedBytes), caption: String(localized: "dans la corbeille"), symbol: "trash", tint: Brand.indigo)
                    StatTile(value: PBFormat.count(s.cleaned), caption: String(localized: "éléments nettoyés"), symbol: "sparkles", tint: Brand.cyan)
                    StatTile(value: PBFormat.count(s.skipped + s.failed), caption: String(localized: "ignorés ou en échec"), symbol: "forward", tint: .orange)
                }
                if s.trashedBytes > 0 {
                    Text("L'espace mis à la corbeille sera libéré quand tu la videras (catégorie « Corbeille » ci-dessous).")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                if !s.messages.isEmpty {
                    DisclosureGroup("Détails (\(s.messages.count))") {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(s.messages, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                        }
                    }
                }
                Button("Masquer") { store.dismissSummary() }.buttonStyle(.link)
            }
        }
    }

    // MARK: - Startup items

    @ViewBuilder
    private var startupCard: some View {
        let items = store.startupItems
        Card(title: String(localized: "Démarrage et agents (\(items.count))"), symbol: "power") {
            VStack(alignment: .leading, spacing: 8) {
                Text("Programmes lancés à l'ouverture de session ou en arrière-plan, tels que les voit la surveillance des persistances.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                if items.isEmpty {
                    Text("Aucun élément de démarrage connu.").foregroundStyle(.secondary)
                }
                ForEach(items.prefix(30)) { item in
                    HStack(spacing: 10) {
                        Image(systemName: item.kind == .loginItem ? "person.crop.circle.badge.checkmark" : "gearshape.2")
                            .foregroundStyle(Brand.indigo)
                            .frame(width: 20)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(item.label ?? (item.path as NSString).lastPathComponent).lineLimit(1)
                            Text(item.program ?? item.path).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        Button("Afficher") { model.revealInFinder(item.path) }
                            .buttonStyle(.link)
                        Button {
                            startupToDisable = item
                        } label: {
                            Label("Désactiver…", systemImage: "lock.fill")
                        }
                        .disabled(model.isBusy("persistence-\(item.id)"))
                    }
                }
                Button("Tout voir dans Persistance") { model.section = .persistence }
                    .buttonStyle(.link)
            }
        }
    }
}

enum CleaningPalette {
    static func color(_ c: CleanCategory) -> Color {
        switch c {
        case .caches: return Brand.indigo
        case .browserCaches: return Brand.cyan
        case .developerCaches: return Brand.violet
        case .logs: return .teal
        case .appLeftovers: return .pink
        case .downloads: return .orange
        case .largeFiles: return .yellow
        case .trash: return .gray
        case .unknown: return .secondary
        }
    }

    static func safety(_ s: CleanSafety) -> (String, Color) {
        switch s {
        case .safe: return (String(localized: "Sûr"), .green)
        case .moderate: return (String(localized: "Retéléchargeable"), .orange)
        case .review: return (String(localized: "À vérifier"), .red)
        }
    }
}

/// One category: tri-state checkbox, size, safety, expandable item list.
private struct CleaningCategoryCard: View {
    @Environment(AppModel.self) private var model
    @ObservedObject var store: CleaningStore
    let category: CleanCategoryReport
    private static let maxShown = 200

    private var isExpanded: Binding<Bool> {
        Binding(
            get: { store.expanded.contains(category.category) },
            set: { open in
                if open { store.expanded.insert(category.category) } else { store.expanded.remove(category.category) }
            }
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                Button {
                    store.toggle(category)
                } label: {
                    Image(systemName: checkSymbol)
                        .font(.title3)
                        .foregroundStyle(store.check(category) == .empty ? Color.secondary : CleaningPalette.color(category.category))
                }
                .buttonStyle(.plain)
                .disabled(category.items.isEmpty)
                .help("Tout cocher / décocher")
                RoundedRectangle(cornerRadius: 3).fill(CleaningPalette.color(category.category)).frame(width: 4, height: 30)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 8) {
                        Text(category.title).font(.system(.headline, design: .rounded))
                        let safety = CleaningPalette.safety(category.safety)
                        Pill(text: safety.0, color: safety.1)
                    }
                    Text(category.description).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    Text(PBFormat.bytes(category.size)).font(.headline.monospacedDigit())
                    Text("\(PBFormat.bytes(store.selectedSize(category))) cochés").font(.caption).foregroundStyle(.secondary)
                }
                Button {
                    withAnimation(.snappy) { isExpanded.wrappedValue.toggle() }
                } label: {
                    Image(systemName: "chevron.right")
                        .rotationEffect(.degrees(isExpanded.wrappedValue ? 90 : 0))
                }
                .buttonStyle(.plain)
                .disabled(category.items.isEmpty)
            }
            if let error = category.error {
                Label(error, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(.orange)
            }
            if isExpanded.wrappedValue && !category.items.isEmpty {
                Divider()
                if category.trashable {
                    Toggle("Supprimer définitivement (sans passer par la corbeille)", isOn: permanentBinding)
                        .toggleStyle(.checkbox)
                        .font(.callout)
                }
                LazyVStack(alignment: .leading, spacing: 6) {
                    ForEach(category.items.prefix(Self.maxShown)) { item in
                        itemRow(item)
                    }
                }
                if category.items.count > Self.maxShown || category.truncated {
                    Text("Seuls les \(min(category.items.count, Self.maxShown)) plus gros éléments sont affichés.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(16)
        .glassSurface()
    }

    private var checkSymbol: String {
        switch store.check(category) {
        case .full: return "checkmark.circle.fill"
        case .partial: return "minus.circle.fill"
        case .empty: return "circle"
        }
    }

    private var permanentBinding: Binding<Bool> {
        Binding(
            get: { store.permanent.contains(category.category) },
            set: { on in
                if on { store.permanent.insert(category.category) } else { store.permanent.remove(category.category) }
            }
        )
    }

    private func itemRow(_ item: CleanItem) -> some View {
        HStack(spacing: 10) {
            Toggle("", isOn: Binding(get: { store.selection.contains(item.id) }, set: { _ in store.toggle(item) }))
                .toggleStyle(.checkbox)
                .labelsHidden()
                .disabled(item.inUse)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(item.name).lineLimit(1).truncationMode(.middle)
                    if item.inUse {
                        Pill(text: String(localized: "Utilisé"), color: .orange, symbol: "lock")
                    } else if item.safety != category.safety {
                        let safety = CleaningPalette.safety(item.safety)
                        Pill(text: safety.0, color: safety.1)
                    }
                }
                Text(item.note ?? item.path)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .help(item.path)
            }
            Spacer()
            if let used = item.lastUsed {
                Text(PBFormat.relative(Date(unixSeconds: used))).font(.caption).foregroundStyle(.secondary)
            }
            Text(PBFormat.bytes(item.size)).font(.callout.monospacedDigit()).frame(minWidth: 80, alignment: .trailing)
            Button {
                model.revealInFinder(item.path)
            } label: {
                Image(systemName: "magnifyingglass.circle")
            }
            .buttonStyle(.plain)
            .help("Afficher dans le Finder")
        }
    }
}
