import AppKit
import ParabellumKit
import SwiftUI

// Coffre: encrypted vault (AES-256 APFS image unlocked with Touch ID) and secure delete.

struct VaultView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore
    @State private var changingPassword = false
    @State private var destroying = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                if let status = store.status {
                    VaultHero(store: store, status: status)
                    if let warning = status.syncWarning {
                        Label(warning, systemImage: "icloud.and.arrow.up")
                            .font(.callout)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                            .padding(12)
                            .glassSurface(cornerRadius: 14, tint: .orange)
                    }
                    if status.exists {
                        tiles(status)
                        if status.mounted {
                            HStack(alignment: .top, spacing: 16) {
                                AddToVaultCard(store: store)
                                RecentItemsCard(store: store, items: status.recent)
                            }
                        }
                    } else {
                        CreateVaultCard(store: store)
                    }
                    ShredCard(store: store)
                    FileVaultCard(store: store, state: status.filevault)
                    VaultSettingsCard(store: store, changingPassword: $changingPassword, destroying: $destroying)
                } else if model.isBusy("vault-status") {
                    ProgressView("Lecture de l'état du coffre…")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else {
                    ContentUnavailableView {
                        Label("Coffre indisponible", systemImage: "lock.trianglebadge.exclamationmark")
                    } description: {
                        Text("L'outil parabellum n'a pas répondu. Réinstallez Parabellum si le problème persiste.")
                    } actions: {
                        Button("Réessayer") { Task { await store.refresh(quiet: false) } }
                    }
                }
            }
            .padding(24)
            .frame(maxWidth: 1180)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle("Coffre")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("vault-status")) {
                    Task { await store.refresh(quiet: false) }
                }
            }
        }
        .task { await store.load() }
        .sheet(item: Binding(
            get: { store.recoveryKeyToShow.map(RecoveryKeyItem.init) },
            set: { if $0 == nil { store.recoveryKeyToShow = nil } }
        )) { item in
            RecoveryKeySheet(store: store, key: item.key)
                .environmentObject(model)
        }
        .sheet(item: $store.passwordPrompt) { prompt in
            PasswordPromptSheet(store: store, prompt: prompt)
                .environmentObject(model)
        }
        .sheet(item: $store.shredPlan) { plan in
            ShredConfirmSheet(store: store, plan: plan, filevault: store.status?.filevault ?? .unknown)
                .environmentObject(model)
        }
        .sheet(isPresented: $store.showHolders) {
            HoldersSheet(store: store)
                .environmentObject(model)
        }
        .sheet(isPresented: $changingPassword) {
            ChangePasswordSheet(store: store)
                .environmentObject(model)
        }
        .sheet(isPresented: $destroying) {
            DestroyVaultSheet(store: store)
                .environmentObject(model)
        }
    }

    private func tiles(_ status: VaultStatus) -> some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 170), spacing: 14)], spacing: 14) {
            StatTile(
                value: status.capacityBytes.map(PBFormat.bytes) ?? "—",
                caption: "Taille maximale",
                symbol: "externaldrive.fill",
                tint: Brand.violet
            )
            StatTile(
                value: status.allocatedBytes.map(PBFormat.bytes) ?? "—",
                caption: "Place prise sur le Mac (chiffrée)",
                symbol: "internaldrive.fill",
                tint: Brand.cyan
            )
            StatTile(
                value: status.usedBytes.map(PBFormat.bytes) ?? "Verrouillé",
                caption: status.mounted ? "Contenu du coffre" : "Contenu illisible sans le mot de passe",
                symbol: status.mounted ? "doc.on.doc.fill" : "lock.fill"
            )
            StatTile(
                value: store.autoLockMinutes == 0 ? "Jamais" : "\(store.autoLockMinutes) min",
                caption: "Verrouillage après inactivité",
                symbol: "timer",
                tint: .orange
            )
        }
    }
}

/// `String` wrapped for `.sheet(item:)`.
private struct RecoveryKeyItem: Identifiable {
    let key: String
    var id: String { key }
}

// MARK: - Hero

private struct VaultHero: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore
    let status: VaultStatus

    private var color: Color {
        if !status.exists { return .gray }
        return status.mounted ? .orange : .green
    }

    private var title: String {
        if !status.exists { return "Aucun coffre" }
        return status.mounted ? "Coffre ouvert" : "Coffre verrouillé"
    }

    private var subtitle: String {
        if !status.exists {
            return "Un dossier chiffré (AES-256) qui ne s'ouvre qu'avec Touch ID ou votre mot de passe."
        }
        if status.mounted {
            let place = status.mountPoint.map { ($0 as NSString).abbreviatingWithTildeInPath } ?? "?"
            if let used = status.usedBytes, let total = status.volumeTotalBytes {
                return "\(place) · \(PBFormat.bytes(used)) sur \(PBFormat.bytes(total)) · pensez à le verrouiller après usage"
            }
            return place
        }
        return status.encrypted
            ? "Contenu chiffré sur le disque. Touch ID ou votre mot de passe pour l'ouvrir."
            : "Attention : cette image n'est pas chiffrée."
    }

    var body: some View {
        HStack(spacing: 22) {
            StatusRing(
                progress: status.mounted ? max(0.04, status.fillRatio ?? 0.04) : (status.exists ? 1 : 0.1),
                color: color,
                symbol: status.mounted ? "lock.open.fill" : (status.exists ? "lock.fill" : "lock.slash"),
                size: 112
            )
            VStack(alignment: .leading, spacing: 8) {
                Text(title)
                    .font(.system(.largeTitle, design: .rounded).weight(.bold))
                Text(subtitle)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 10) {
                    if status.exists {
                        if status.mounted {
                            Button {
                                Task { await store.lock() }
                            } label: {
                                busyLabel("Verrouiller", symbol: "lock.fill", key: "vault-lock")
                            }
                            .buttonStyle(.brand)
                            .keyboardShortcut("l", modifiers: [.command, .shift])
                            Button {
                                store.revealInFinder()
                            } label: {
                                Label("Afficher dans le Finder", systemImage: "folder")
                            }
                        } else {
                            Button {
                                Task { await store.unlock() }
                            } label: {
                                busyLabel("Déverrouiller", symbol: "touchid", key: "vault-unlock")
                            }
                            .buttonStyle(.brand)
                            .disabled(model.isBusy("vault-unlock"))
                        }
                    }
                }
                .padding(.top, 4)
            }
            Spacer(minLength: 0)
        }
        .padding(22)
        .glassSurface(cornerRadius: 26, tint: color)
    }

    @ViewBuilder
    private func busyLabel(_ title: String, symbol: String, key: String) -> some View {
        if model.isBusy(key) {
            HStack(spacing: 6) {
                ProgressView().controlSize(.small)
                Text(title)
            }
        } else {
            Label(title, systemImage: symbol)
        }
    }
}

// MARK: - Creation

private struct CreateVaultCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore
    @State private var generateKey = true
    @State private var password = ""
    @State private var confirmation = ""
    @State private var sizeGB = 20

    private var passwordProblem: String? {
        guard !generateKey else { return nil }
        if password.count < 12 { return "12 caractères au minimum (une phrase de plusieurs mots est idéale)." }
        if password != confirmation { return "Les deux mots de passe diffèrent." }
        return nil
    }

    var body: some View {
        Card(title: "Créer le coffre", symbol: "lock.rectangle.stack") {
            VStack(alignment: .leading, spacing: 12) {
                Text("Image disque APFS chiffrée en AES-256 par macOS. Elle ne prend sur le disque que la place de son contenu. Le mot de passe est rangé dans votre trousseau et ne sort qu'après Touch ID ou votre mot de passe de session.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Picker("Clé", selection: $generateKey) {
                    Text("Clé générée (recommandé)").tag(true)
                    Text("Mon propre mot de passe").tag(false)
                }
                .pickerStyle(.segmented)
                .frame(maxWidth: 420)
                if generateKey {
                    Label("Une clé de 32 caractères est générée ; elle s'affichera une seule fois comme clé de récupération à imprimer ou noter.", systemImage: "key.viewfinder")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    SecureField("Mot de passe (12 caractères minimum)", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 360)
                    SecureField("Confirmation", text: $confirmation)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 360)
                    if let passwordProblem, !password.isEmpty {
                        Text(passwordProblem).font(.caption).foregroundStyle(.orange)
                    }
                }
                HStack {
                    Picker("Taille maximale", selection: $sizeGB) {
                        ForEach(VaultStore.sizeChoicesGB, id: \.self) { size in
                            Text("\(size) Go").tag(size)
                        }
                    }
                    .frame(maxWidth: 260)
                    Spacer()
                }
                HStack(spacing: 6) {
                    Text("Emplacement :").foregroundStyle(.secondary)
                    Text(store.bundleDisplayPath)
                        .font(.system(.callout, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Button("Modifier…") { store.chooseLocation() }
                        .buttonStyle(.link)
                }
                .font(.callout)
                Button {
                    let chosen = generateKey ? nil : password
                    Task {
                        if await store.create(sizeGB: sizeGB, chosenPassword: chosen) {
                            password = ""
                            confirmation = ""
                        }
                    }
                } label: {
                    if model.isBusy("vault-create") {
                        HStack(spacing: 6) {
                            ProgressView().controlSize(.small)
                            Text("Création…")
                        }
                    } else {
                        Label("Créer le coffre", systemImage: "plus.circle.fill")
                    }
                }
                .buttonStyle(.brand)
                .disabled(passwordProblem != nil || model.isBusy("vault-create"))
            }
        }
    }
}

// MARK: - Drop zones

/// Dashed glass drop target for Finder files, with a "Choisir…" fallback.
private struct VaultDropZone: View {
    let title: String
    let subtitle: String
    let symbol: String
    var tint: Color = Brand.accent
    var chooseTitle = "Choisir…"
    let onURLs: ([URL]) -> Void
    @State private var targeted = false

    var body: some View {
        VStack(spacing: 8) {
            Image(systemName: symbol)
                .font(.system(size: 28, weight: .semibold))
                .foregroundStyle(tint)
                .symbolRenderingMode(.hierarchical)
            Text(title).font(.headline)
            Text(subtitle)
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .fixedSize(horizontal: false, vertical: true)
            Button(chooseTitle) { choose() }
                .buttonStyle(.link)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 150)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(tint.opacity(targeted ? 0.14 : 0.04))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [7, 5]))
                .foregroundStyle(targeted ? tint : Color.secondary.opacity(0.45))
        )
        .animation(.snappy(duration: 0.18), value: targeted)
        .dropDestination(for: URL.self) { urls, _ in
            let files = urls.filter(\.isFileURL)
            guard !files.isEmpty else { return false }
            onURLs(files)
            return true
        } isTargeted: { targeted = $0 }
    }

    private func choose() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Choisir"
        NSApp.activate()
        guard panel.runModal() == .OK else { return }
        onURLs(panel.urls)
    }
}

private struct AddToVaultCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore
    @State private var removeOriginals = false

    var body: some View {
        Card(title: "Ajouter au coffre", symbol: "tray.and.arrow.down.fill", content: {
            VStack(alignment: .leading, spacing: 10) {
                VaultDropZone(
                    title: model.isBusy("vault-add") ? "Copie en cours…" : "Déposez des fichiers ici",
                    subtitle: "Ils sont copiés dans le coffre chiffré.",
                    symbol: "lock.doc.fill",
                    tint: .green
                ) { urls in
                    Task { await store.addToVault(urls, removeOriginals: removeOriginals) }
                }
                Toggle("Puis supprimer définitivement les originaux (avec confirmation)", isOn: $removeOriginals)
                    .font(.callout)
            }
        }, tint: .green)
    }
}

private struct RecentItemsCard: View {
    @ObservedObject var store: VaultStore
    let items: [VaultItem]

    var body: some View {
        Card(title: "Modifiés récemment", symbol: "clock.arrow.circlepath") {
            if items.isEmpty {
                Text("Le coffre est vide.").foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(items) { item in
                        Button {
                            store.reveal(item)
                        } label: {
                            HStack(spacing: 8) {
                                Image(nsImage: NSWorkspace.shared.icon(forFile: item.path))
                                    .resizable()
                                    .frame(width: 18, height: 18)
                                Text(item.name).lineLimit(1).truncationMode(.middle)
                                Spacer()
                                Text(PBFormat.bytes(item.size)).font(.caption).foregroundStyle(.secondary)
                                Text(PBFormat.relative(item.modifiedDate)).font(.caption).foregroundStyle(.tertiary)
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .help("Afficher dans le Finder")
                    }
                }
            }
        }
    }
}

// MARK: - Secure delete

private struct ShredCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore

    var body: some View {
        Card(title: "Effacement sûr", symbol: "flame.fill", content: {
            VStack(alignment: .leading, spacing: 12) {
                HStack(alignment: .top, spacing: 14) {
                    VaultDropZone(
                        title: model.isBusy("vault-shred") ? "Suppression…" : "Supprimer définitivement",
                        subtitle: "Contenu réécrit puis supprimé, sans passer par la Corbeille. Confirmation demandée.",
                        symbol: "flame",
                        tint: .red
                    ) { urls in
                        Task { await store.prepareShred(urls: urls) }
                    }
                    VStack(alignment: .leading, spacing: 10) {
                        Button {
                            Task { await store.prepareEmptyTrash() }
                        } label: {
                            Label("Vider la Corbeille de façon sûre…", systemImage: "trash.slash")
                        }
                        .disabled(model.isBusy("vault-shred-plan") || model.isBusy("vault-shred"))
                        Text("Sur un SSD, réécrire un fichier ne garantit pas que les anciens blocs disparaissent : le disque écrit ailleurs pour s'user uniformément, et macOS peut garder des copies (instantanés, clones). La vraie garantie est le chiffrement : FileVault pour tout le disque, le coffre pour vos fichiers sensibles.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: 320, alignment: .leading)
                }
                if !store.lastShred.isEmpty {
                    Divider()
                    Text("Dernière suppression").font(.subheadline.weight(.semibold))
                    ForEach(store.lastShred) { report in
                        ShredReportRow(report: report)
                    }
                }
            }
        }, tint: .red)
    }
}

private struct ShredReportRow: View {
    let report: ShredReport

    private var symbol: (String, Color) {
        switch report.outcome {
        case .deleted, .planned: return ("checkmark.circle.fill", .green)
        case .refused: return ("hand.raised.fill", .orange)
        case .failed, .unknown: return ("xmark.circle.fill", .red)
        }
    }

    private var detail: String {
        if let error = report.error {
            return error
        }
        var parts: [String] = []
        if report.files > 0 { parts.append("\(report.files) fichier(s)") }
        if report.dirs > 0 { parts.append("\(report.dirs) dossier(s)") }
        parts.append(PBFormat.bytes(report.bytes))
        switch report.zone {
        case .vault: parts.append("dans le coffre : suppression simple")
        case .some: parts.append("\(PBFormat.bytes(report.overwrittenBytes)) réécrits")
        case nil: break
        }
        return parts.joined(separator: " · ")
    }

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: symbol.0).foregroundStyle(symbol.1)
            VStack(alignment: .leading, spacing: 2) {
                Text(report.name).lineLimit(1).truncationMode(.middle)
                Text(detail).font(.caption).foregroundStyle(.secondary)
                ForEach(report.warnings, id: \.self) { warning in
                    Text(warning).font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
        .help(report.path)
    }
}

private struct ShredConfirmSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: VaultStore
    let plan: VaultStore.ShredPlan
    let filevault: FileVaultState

    private var title: String {
        switch plan.source {
        case .files: return "Supprimer définitivement ?"
        case .trash: return "Vider la Corbeille de façon sûre ?"
        case .originals: return "Supprimer définitivement les originaux ?"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(title, systemImage: "flame.fill")
                .font(.title2.weight(.semibold))
                .foregroundStyle(.red)
            if plan.actionable.isEmpty {
                Text("Aucun élément ne peut être supprimé ici.").foregroundStyle(.secondary)
            } else {
                Text("\(plan.actionable.count) élément(s), \(plan.totalFiles) fichier(s), \(PBFormat.bytes(plan.totalBytes)). Irréversible : ils ne passent pas par la Corbeille.")
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(plan.reports) { report in
                        ShredReportRow(report: report)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxHeight: 240)
            if plan.touchesOutsideVault {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Ce que « définitivement » veut dire ici").font(.headline)
                    Text("Le contenu de chaque fichier est remplacé une fois par des données aléatoires, puis le fichier est renommé et supprimé. Sur un SSD, cela ne garantit pas que les anciennes données soient physiquement effacées : le disque écrit les nouvelles données ailleurs, et macOS peut en garder des copies (instantanés Time Machine locaux, copies APFS). Les fichiers compressés par macOS ou restés dans iCloud sont seulement supprimés.")
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(filevault == .on
                         ? "FileVault est activé : les anciens blocs restent chiffrés et illisibles sans votre session. C'est cette protection qui compte."
                         : "FileVault n'est pas activé : activez-le, c'est la seule vraie garantie que les anciens blocs restent illisibles.")
                        .font(.callout.weight(.medium))
                        .foregroundStyle(filevault == .on ? Color.green : Color.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(12)
                .glassSurface(cornerRadius: 14, tint: filevault == .on ? .green : .orange)
            }
            HStack {
                Spacer()
                Button("Annuler", role: .cancel) {
                    store.shredPlan = nil
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Button(role: .destructive) {
                    Task { await store.executeShred(plan) }
                    dismiss()
                } label: {
                    Text("Supprimer définitivement")
                }
                .disabled(plan.actionable.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 560)
    }
}

// MARK: - FileVault

private struct FileVaultCard: View {
    @ObservedObject var store: VaultStore
    let state: FileVaultState

    var body: some View {
        Card(title: "FileVault", symbol: "lock.laptopcomputer", content: {
            HStack(alignment: .top) {
                Text(text)
                    .font(.callout)
                    .foregroundStyle(state == .on ? Color.secondary : Color.orange)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                if state != .on && state != .encrypting {
                    Button("Ouvrir les réglages") { store.openFileVaultSettings() }
                }
            }
        }, tint: state == .on ? .green : .orange)
    }

    private var text: String {
        switch state {
        case .on: return "Activé : tout le disque est chiffré. Les fichiers supprimés restent illisibles, même sur un SSD."
        case .encrypting: return "Chiffrement du disque en cours."
        case .off: return "Désactivé : en cas de vol, le disque est lisible, y compris des fichiers supprimés. Activez-le (Réglages Système > Confidentialité et sécurité > FileVault)."
        case .decrypting: return "Déchiffrement en cours : le disque ne sera bientôt plus protégé."
        case .unknown: return "État inconnu."
        }
    }
}

// MARK: - Settings

private struct VaultSettingsCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore
    @Binding var changingPassword: Bool
    @Binding var destroying: Bool
    @State private var resizeGB = 50

    private var locked: Bool { store.exists && !store.isOpen }

    var body: some View {
        Card(title: "Réglages du coffre", symbol: "slider.horizontal.3") {
            VStack(alignment: .leading, spacing: 12) {
                Picker("Verrouiller après", selection: $store.autoLockMinutes) {
                    ForEach(VaultStore.autoLockChoices, id: \.self) { minutes in
                        Text(minutes == 0 ? "Jamais" : "\(minutes) min sans activité").tag(minutes)
                    }
                }
                .frame(maxWidth: 360)
                Toggle("Verrouiller quand l'écran se verrouille ou s'éteint", isOn: $store.lockOnScreenLock)
                Toggle("Verrouiller quand le Mac se met en veille", isOn: $store.lockOnSleep)
                Toggle("Verrouiller en quittant Parabellum", isOn: $store.lockOnQuit)
                Toggle("Forcer le verrouillage (veille, écran) même si des fichiers sont ouverts", isOn: $store.forceLockOnSleep)
                    .help("Les modifications non enregistrées dans les apps qui utilisent ces fichiers seront perdues.")
                Divider()
                HStack(spacing: 6) {
                    Text("Image :").foregroundStyle(.secondary)
                    Text(store.bundleDisplayPath)
                        .font(.system(.callout, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                    Spacer()
                    Button("Modifier…") { store.chooseLocation() }
                        .disabled(store.isOpen)
                    if !store.bundlePath.isEmpty {
                        Button("Par défaut") { store.resetLocation() }
                            .disabled(store.isOpen)
                    }
                }
                .font(.callout)
                Toggle("Ouvrir dans ~/Coffre plutôt que dans /Volumes", isOn: $store.useHomeMountpoint)
                    .disabled(store.isOpen)
                    .help("Le dossier ~/Coffre est retiré à chaque verrouillage, pour que rien n'y soit enregistré en clair.")
                if let backend = store.keychainBackend {
                    Label(backend.label, systemImage: "key.fill")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if store.exists {
                    Divider()
                    HStack(spacing: 10) {
                        Button("Changer le mot de passe…") { changingPassword = true }
                            .disabled(model.isBusy("vault-chpass"))
                        Picker("Taille maximale", selection: $resizeGB) {
                            ForEach(VaultStore.sizeChoicesGB, id: \.self) { Text("\($0) Go").tag($0) }
                        }
                        .frame(maxWidth: 220)
                        Button("Appliquer") { Task { await store.resize(sizeGB: resizeGB) } }
                            .disabled(!locked || model.isBusy("vault-resize"))
                            .help("Coffre verrouillé uniquement.")
                        Button("Récupérer l'espace") { Task { await store.compact() } }
                            .disabled(!locked || model.isBusy("vault-compact"))
                            .help("Rend au Mac la place des fichiers supprimés du coffre (coffre verrouillé).")
                        Spacer()
                        Button(role: .destructive) {
                            destroying = true
                        } label: {
                            Label("Détruire le coffre…", systemImage: "trash")
                        }
                    }
                    .controlSize(.small)
                }
            }
        }
        .onAppear {
            if let capacity = store.status?.capacityBytes {
                let gb = capacity / (1 << 30)
                resizeGB = VaultStore.sizeChoicesGB.first { $0 > gb } ?? VaultStore.sizeChoicesGB.last ?? 50
            }
        }
    }
}

// MARK: - Sheets

private struct RecoveryKeySheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: VaultStore
    let key: String
    @State private var saved = false
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Label("Clé de récupération", systemImage: "key.horizontal.fill")
                .font(.title2.weight(.semibold))
            Text("Elle ouvre le coffre si le trousseau est perdu (nouveau Mac, réinstallation). Elle n'est affichée qu'une fois : imprimez-la ou notez-la, et rangez-la hors de l'ordinateur.")
                .fixedSize(horizontal: false, vertical: true)
            Text(key)
                .font(.system(size: 22, weight: .semibold, design: .monospaced))
                .textSelection(.enabled)
                .padding(16)
                .frame(maxWidth: .infinity)
                .glassSurface(cornerRadius: 14, tint: Brand.indigo)
            HStack {
                Button {
                    store.copyRecoveryKey(key)
                    copied = true
                } label: {
                    Label(copied ? "Copiée (effacée du presse-papiers dans 60 s)" : "Copier", systemImage: "doc.on.doc")
                }
                Button {
                    store.printRecoveryKey(key)
                } label: {
                    Label("Imprimer / PDF…", systemImage: "printer")
                }
                Spacer()
            }
            Toggle("J'ai mis la clé en lieu sûr", isOn: $saved)
            HStack {
                Spacer()
                Button("Terminé") {
                    store.recoveryKeyToShow = nil
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!saved)
            }
        }
        .padding(24)
        .frame(width: 560)
        .interactiveDismissDisabled(!saved)
    }
}

private struct PasswordPromptSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: VaultStore
    let prompt: VaultStore.PasswordPrompt
    @State private var password = ""
    @State private var remember = true

    private var isUnlock: Bool {
        if case .unlock = prompt.purpose { return true }
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Mot de passe du coffre", systemImage: "lock.fill")
                .font(.title2.weight(.semibold))
            Text(prompt.message)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            SecureField("Mot de passe ou clé de récupération", text: $password)
                .textFieldStyle(.roundedBorder)
                .onSubmit(submit)
            if isUnlock {
                Toggle("Le ranger dans le trousseau (Touch ID la prochaine fois)", isOn: $remember)
            }
            HStack {
                Spacer()
                Button("Annuler", role: .cancel) {
                    store.passwordPrompt = nil
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Button("Valider", action: submit)
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty)
            }
        }
        .padding(24)
        .frame(width: 460)
    }

    private func submit() {
        guard !password.isEmpty else { return }
        let typed = password
        password = ""
        Task { await store.submitPassword(typed, remember: remember) }
        dismiss()
    }
}

private struct HoldersSheet: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Fichiers encore ouverts", systemImage: "exclamationmark.lock.fill")
                .font(.title2.weight(.semibold))
                .foregroundStyle(.orange)
            Text("Fermez ces fichiers (ou quittez ces apps) puis verrouillez. Forcer peut faire perdre les modifications non enregistrées.")
                .fixedSize(horizontal: false, vertical: true)
            if store.holders.isEmpty {
                Text("macOS n'a pas indiqué quelle app les utilise.").foregroundStyle(.secondary)
            }
            ForEach(store.holders) { holder in
                VStack(alignment: .leading, spacing: 2) {
                    Text(holder.command).fontWeight(.semibold)
                    ForEach(holder.paths, id: \.self) { path in
                        Text((path as NSString).lastPathComponent)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            HStack {
                Spacer()
                Button("Fermer") {
                    store.showHolders = false
                    dismiss()
                }
                .keyboardShortcut(.cancelAction)
                Button("Réessayer") {
                    Task { await store.lock() }
                }
                Button("Forcer le verrouillage", role: .destructive) {
                    Task { await store.lock(force: true) }
                    dismiss()
                }
            }
            .disabled(model.isBusy("vault-lock"))
        }
        .padding(24)
        .frame(width: 480)
    }
}

private struct ChangePasswordSheet: View {
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: VaultStore
    @State private var generateKey = true
    @State private var password = ""
    @State private var confirmation = ""

    private var valid: Bool {
        generateKey || (password.count >= 12 && password == confirmation)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Changer le mot de passe du coffre", systemImage: "key.fill")
                .font(.title2.weight(.semibold))
            Text("L'ancien mot de passe (et l'ancienne clé de récupération) ne fonctionneront plus. Touch ID est demandé pour lire l'actuel dans le trousseau.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Picker("Nouvelle clé", selection: $generateKey) {
                Text("Nouvelle clé générée").tag(true)
                Text("Mon propre mot de passe").tag(false)
            }
            .pickerStyle(.segmented)
            if !generateKey {
                SecureField("Nouveau mot de passe (12 caractères minimum)", text: $password)
                    .textFieldStyle(.roundedBorder)
                SecureField("Confirmation", text: $confirmation)
                    .textFieldStyle(.roundedBorder)
            }
            HStack {
                Spacer()
                Button("Annuler", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Changer") {
                    let chosen = generateKey ? nil : password
                    password = ""
                    confirmation = ""
                    dismiss()
                    Task { await store.changePassword(newPassword: chosen) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(!valid)
            }
        }
        .padding(24)
        .frame(width: 480)
    }
}

private struct DestroyVaultSheet: View {
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore
    @State private var confirmation = ""

    private static let word = "DÉTRUIRE"

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Détruire le coffre ?", systemImage: "trash.fill")
                .font(.title2.weight(.semibold))
                .foregroundStyle(.red)
            Text("L'image chiffrée est supprimée, puis sa clé est effacée du trousseau. Sans clé, les données chiffrées restées sur le disque sont illisibles : c'est un effacement cryptographique, fiable même sur SSD. Exception : une sauvegarde Time Machine du coffre reste lisible avec l'ancienne clé de récupération — détruisez-la aussi.")
                .fixedSize(horizontal: false, vertical: true)
            if store.isOpen {
                Text("Le coffre est ouvert : il sera verrouillé de force (modifications non enregistrées perdues).")
                    .foregroundStyle(.orange)
            }
            TextField("Tapez \(Self.word) pour confirmer", text: $confirmation)
                .textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                Button("Annuler", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Détruire le coffre", role: .destructive) {
                    dismiss()
                    Task { await store.destroy(force: true) }
                }
                .disabled(confirmation.trimmingCharacters(in: .whitespaces).uppercased() != Self.word || model.isBusy("vault-destroy"))
            }
        }
        .padding(24)
        .frame(width: 500)
    }
}

// MARK: - Menu bar row & dashboard tile

/// Vault state in the menu bar window, with lock / Touch ID unlock.
struct VaultMenuRow: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore

    var body: some View {
        if store.exists {
            HStack(spacing: 8) {
                Image(systemName: store.isOpen ? "lock.open.fill" : "lock.fill")
                    .foregroundStyle(store.isOpen ? Color.orange : Color.green)
                    .frame(width: 18)
                Text(store.isOpen ? "Coffre ouvert" : "Coffre verrouillé")
                Spacer()
                Button(store.isOpen ? "Verrouiller" : "Déverrouiller") {
                    Task {
                        if store.isOpen {
                            await store.lock()
                        } else {
                            await store.unlock()
                        }
                    }
                }
                .disabled(model.isBusy("vault-lock") || model.isBusy("vault-unlock"))
            }
            .controlSize(.small)
            .padding(.vertical, 2)
        }
    }
}

/// Dashboard tile: vault state, opens the section.
struct VaultDashboardTile: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore

    var body: some View {
        Button {
            model.section = .vault
        } label: {
            StatTile(
                value: store.exists ? (store.isOpen ? "Ouvert" : "Verrouillé") : "Aucun",
                caption: "Coffre chiffré",
                symbol: store.isOpen ? "lock.open.fill" : "lock.fill",
                tint: store.exists ? (store.isOpen ? .orange : .green) : .gray
            )
        }
        .buttonStyle(.plain)
    }
}
