import ParabellumKit
import SwiftUI

/// Privacy: GDPR erasure campaign towards data brokers, breaches, email aliases, local tools.
struct PrivacyView: View {
    enum Tab: String, CaseIterable, Identifiable {
        case removal, breaches, aliases, tools
        var id: String { rawValue }

        var title: String {
            switch self {
            case .removal: return "Effacement RGPD"
            case .breaches: return "Fuites"
            case .aliases: return "Alias e-mail"
            case .tools: return "Outils"
            }
        }
    }

    @EnvironmentObject private var model: AppModel
    @State private var tab: Tab = .removal

    var body: some View {
        VStack(spacing: 0) {
            Picker("Vue", selection: $tab) {
                ForEach(Tab.allCases) { tab in
                    Text(tab.title).tag(tab)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(12)
            Divider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    switch tab {
                    case .removal: RemovalTab()
                    case .breaches: BreachesTab()
                    case .aliases: AliasesTab()
                    case .tools: PrivacyToolsTab()
                    }
                }
                .padding(20)
            }
        }
        .navigationTitle("Vie privée")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy("privacy")) {
                    Task { await model.loadPrivacy() }
                }
            }
        }
        .task {
            await model.loadPrivacy()
        }
    }
}

// MARK: - GDPR removal

private struct RemovalTab: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if model.config?.dataRemoval.enabled != true {
                Card(title: "Effacement auprès des courtiers en données", symbol: "hand.raised") {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Comme Incogni, en open source : Parabellum envoie en ton nom des demandes d'effacement (article 17 du RGPD) aux courtiers en données, suit le délai légal d'un mois, relance, puis prépare une plainte CNIL si l'organisme ne répond pas. Les listes de courtiers (Datenanfragen, Eraser) arrivent avec la base signée.")
                            .fixedSize(horizontal: false, vertical: true)
                        Button("Activer dans les réglages") {
                            model.section = .settings
                        }
                    }
                }
            }
            IdentityCard()
            CampaignCard()
            RequestsCard()
        }
    }
}

private struct IdentityCard: View {
    @EnvironmentObject private var model: AppModel
    @State private var editing: EditableIdentity?

    var body: some View {
        Card(title: "Identité à effacer", symbol: "person.text.rectangle") {
            VStack(alignment: .leading, spacing: 6) {
                if let identity = model.identity, identity.isComplete {
                    InfoRow(label: "Nom", value: identity.fullName)
                    InfoRow(label: "E-mails", value: identity.emails.joined(separator: ", "))
                    if !identity.phones.isEmpty {
                        InfoRow(label: "Téléphones", value: identity.phones.joined(separator: ", "))
                    }
                    if !identity.country.isEmpty {
                        InfoRow(label: "Pays", value: identity.country)
                    }
                } else {
                    Text("Renseigne ton nom et les adresses e-mail que les courtiers peuvent connaître (plus ton téléphone et ton adresse postale si tu veux qu'ils les effacent aussi).")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Button {
                        Task { await beginEditing() }
                    } label: {
                        Label(model.identity?.isComplete == true ? "Modifier…" : "Renseigner…", systemImage: "lock.fill")
                    }
                    .disabled(model.isBusy("privacy-reveal"))
                    Spacer()
                }
                Text("Stockée par le service (lisible par root uniquement) et affichée masquée ; l'afficher ou la modifier demande une autorisation administrateur.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .sheet(item: $editing) { item in
            IdentityEditor(initial: item.profile) {
                editing = nil
            }
            .environmentObject(model)
        }
    }

    private func beginEditing() async {
        if model.identity?.isComplete == true {
            guard let clear = await model.revealIdentity() else { return }
            editing = EditableIdentity(profile: clear)
        } else {
            var fresh = model.identity ?? IdentityProfile()
            if fresh.isMasked {
                fresh = IdentityProfile()
            }
            if fresh.country.isEmpty {
                fresh.country = "FR"
            }
            editing = EditableIdentity(profile: fresh)
        }
    }
}

/// `IdentityProfile` wrapped for `.sheet(item:)`.
private struct EditableIdentity: Identifiable {
    let id = UUID()
    let profile: IdentityProfile
}

private struct IdentityEditor: View {
    @EnvironmentObject private var model: AppModel
    @State private var draft: IdentityProfile
    let onClose: () -> Void

    init(initial: IdentityProfile, onClose: @escaping () -> Void) {
        _draft = State(initialValue: initial)
        self.onClose = onClose
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    TextField("Nom complet", text: $draft.fullName)
                    StringListEditor(title: "Adresses e-mail (la première sert de contact)", placeholder: "prenom.nom@exemple.fr", items: $draft.emails)
                    StringListEditor(title: "Téléphones", placeholder: "+33 6 …", items: $draft.phones)
                } header: {
                    Text("Identité")
                }
                Section {
                    TextEditor(text: $draft.postalAddress)
                        .frame(minHeight: 60)
                    StringListEditor(title: "Anciennes adresses", placeholder: "Adresse sur une ligne", items: $draft.previousAddresses)
                    TextField("Date de naissance (AAAA-MM-JJ, facultatif)", text: $draft.birthDate)
                    TextField("Pays de résidence (code ISO, ex. FR)", text: $draft.country)
                } header: {
                    Text("Adresse postale")
                } footer: {
                    Text("Ne donne que ce que tu veux faire effacer : chaque courrier contient ces informations pour que l'organisme te retrouve.")
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                Button("Annuler", action: onClose)
                    .keyboardShortcut(.cancelAction)
                Button {
                    let profile = cleaned
                    Task {
                        if await model.saveIdentity(profile) {
                            onClose()
                        }
                    }
                } label: {
                    Label("Enregistrer", systemImage: "lock.fill")
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!cleaned.isComplete || model.isBusy("privacy-save"))
            }
            .padding(12)
        }
        .frame(width: 560, height: 560)
    }

    private var cleaned: IdentityProfile {
        var p = draft
        let trim: (String) -> String = { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        p.fullName = trim(p.fullName)
        p.emails = p.emails.map(trim).filter { !$0.isEmpty }
        p.phones = p.phones.map(trim).filter { !$0.isEmpty }
        p.previousAddresses = p.previousAddresses.map(trim).filter { !$0.isEmpty }
        p.postalAddress = trim(p.postalAddress)
        p.birthDate = trim(p.birthDate)
        p.country = trim(p.country).uppercased()
        return p
    }
}

private struct CampaignCard: View {
    @EnvironmentObject private var model: AppModel
    @State private var confirmStart = false

    var body: some View {
        Card(title: "Campagne d'effacement", symbol: "paperplane") {
            VStack(alignment: .leading, spacing: 10) {
                if let summary = model.removalSummary {
                    HStack(spacing: 18) {
                        counter("Demandes", summary.total)
                        counter("En file", summary.queued)
                        counter("En attente de réponse", summary.waitingAnswer)
                        counter("En retard", summary.overdue, warn: summary.overdue > 0)
                        counter("Effacées", summary.completed)
                        counter("À traiter", summary.needsAction, warn: summary.needsAction > 0)
                    }
                    if let next = summary.nextSendAt {
                        Text("Prochain envoi : \(PBFormat.dateTime(unixSeconds: next))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Text("\(model.brokers.count) organisme(s) dans tes régions (\(regionsText)).")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                HStack(spacing: 10) {
                    Button {
                        confirmStart = true
                    } label: {
                        Label("Lancer / compléter la campagne", systemImage: "lock.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canStart || model.isBusy("privacy-start"))
                    if model.config?.dataRemoval.sendMode == .drafts {
                        Button {
                            Task { await model.writeAllDrafts() }
                        } label: {
                            Label("Préparer les e-mails à envoyer", systemImage: "envelope")
                        }
                        .disabled(model.removalRequests.isEmpty)
                    }
                    Spacer()
                }
                if !canStart {
                    Text("Active l'effacement dans les réglages et renseigne ton identité pour lancer la campagne.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .confirmationDialog("Envoyer des demandes d'effacement en ton nom ?", isPresented: $confirmStart) {
            Button("Lancer") {
                Task { await model.startRemoval() }
            }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text(startMessage)
        }
    }

    private var canStart: Bool {
        model.config?.dataRemoval.enabled == true && model.identity?.isComplete == true
    }

    private var regionsText: String {
        let regions = model.config?.dataRemoval.regions ?? []
        return regions.isEmpty ? "aucune" : regions.map(PrivacyLabels.region).joined(separator: ", ")
    }

    private var startMessage: String {
        if model.config?.dataRemoval.sendMode == .smtp {
            let perDay = model.config?.dataRemoval.maxEmailsPerDay ?? 20
            return "Les e-mails partiront de ton compte SMTP, au plus \(perDay) par jour. Chacun contient ton identité."
        }
        return "Les e-mails seront préparés comme brouillons à envoyer depuis Mail. Chacun contient ton identité."
    }

    private func counter(_ title: String, _ value: Int, warn: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("\(value)")
                .font(.title2.weight(.semibold))
                .foregroundStyle(warn ? Color.orange : Color.primary)
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }
}

private struct RequestsCard: View {
    enum Filter: String, CaseIterable, Identifiable {
        case todo, waiting, closed, all
        var id: String { rawValue }

        var title: String {
            switch self {
            case .todo: return "À traiter"
            case .waiting: return "En attente"
            case .closed: return "Terminées"
            case .all: return "Toutes"
            }
        }
    }

    private static let todoStatuses: [RemovalStatus] = [.queued, .draftReady, .needsForm, .failed, .escalated]

    @EnvironmentObject private var model: AppModel
    @State private var filter: Filter = .todo
    @State private var complaint: ComplaintItem?

    private var filtered: [RemovalRequest] {
        let now = Date()
        return model.removalRequests.filter { request in
            switch filter {
            case .todo:
                return Self.todoStatuses.contains(request.status) || request.isOverdue(now: now)
            case .waiting:
                return (request.status == .sent || request.status == .reminded) && !request.isOverdue(now: now)
            case .closed:
                return request.status.isClosed
            case .all:
                return true
            }
        }
    }

    var body: some View {
        Card(title: "Demandes", symbol: "list.bullet.rectangle") {
            VStack(alignment: .leading, spacing: 8) {
                Picker("Filtre", selection: $filter) {
                    ForEach(Filter.allCases) { filter in
                        Text(filter.title).tag(filter)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                if filtered.isEmpty {
                    Text("Aucune demande dans cette catégorie.").foregroundStyle(.secondary)
                } else {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(filtered) { request in
                            RequestRow(request: request) { draft in
                                complaint = ComplaintItem(draft: draft)
                            }
                            Divider()
                        }
                    }
                }
            }
        }
        .sheet(item: $complaint) { item in
            ComplaintSheet(draft: item.draft) {
                complaint = nil
            }
            .environmentObject(model)
        }
    }
}

private struct ComplaintItem: Identifiable {
    let id = UUID()
    let draft: ComplaintDraft
}

private struct RequestRow: View {
    @EnvironmentObject private var model: AppModel
    let request: RemovalRequest
    let showComplaint: (ComplaintDraft) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(request.brokerName).fontWeight(.semibold)
                    Pill(text: request.status.label, color: request.status.color)
                    if request.isOverdue() {
                        Pill(text: "Délai dépassé", color: .orange)
                    }
                }
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let error = request.lastError {
                    Text(error).font(.caption).foregroundStyle(.red)
                }
                if let note = request.note, !note.isEmpty {
                    Text(note).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer()
            actions
        }
        .padding(.vertical, 6)
    }

    private var subtitle: String {
        var parts: [String] = []
        if let email = request.brokerEmail {
            parts.append(email)
        }
        if let sent = request.sentDate {
            parts.append("envoyée \(PBFormat.day(sent))")
        }
        if let due = request.dueDate, !request.status.isClosed {
            parts.append("réponse due le \(PBFormat.day(due))")
        }
        return parts.joined(separator: " · ")
    }

    private var actions: some View {
        HStack(spacing: 6) {
            if request.canDraft {
                Button {
                    Task { await model.openDraft(for: request) }
                } label: {
                    Label(request.isOverdue() ? "Relancer" : "E-mail", systemImage: "envelope")
                }
                .disabled(model.isBusy("draft-\(request.id)"))
                .help("Ouvre l'e-mail prêt à envoyer dans Mail (autorisation administrateur : il contient ton identité)")
            }
            if let form = request.optOutUrl {
                Button {
                    model.open(urlString: form)
                } label: {
                    Label("Formulaire", systemImage: "safari")
                }
            }
            Menu {
                ForEach(RemovalStatus.settable, id: \.self) { status in
                    Button(status.label) {
                        Task { await model.updateRequest(request, status: status) }
                    }
                }
                if request.status == .escalated || request.isOverdue() {
                    Divider()
                    Button("Préparer une plainte CNIL…") {
                        Task {
                            if let draft = await model.complaint(for: request) {
                                showComplaint(draft)
                            }
                        }
                    }
                }
            } label: {
                Text("Marquer")
            }
            .fixedSize()
            .disabled(model.isBusy("request-\(request.id)"))
        }
    }
}

private struct ComplaintSheet: View {
    @EnvironmentObject private var model: AppModel
    let draft: ComplaintDraft
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Plainte auprès de la \(draft.authority)").font(.title3.weight(.semibold))
            Text("Copie ce texte dans le formulaire en ligne de l'autorité et joins-y ta demande initiale et ta relance.")
                .font(.callout)
                .foregroundStyle(.secondary)
            ScrollView {
                Text(draft.text)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .frame(minHeight: 260)
            .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
            HStack {
                Button {
                    model.copyToPasteboard(draft.text)
                } label: {
                    Label("Copier le texte", systemImage: "doc.on.doc")
                }
                Button {
                    model.open(urlString: draft.url)
                } label: {
                    Label("Ouvrir le formulaire", systemImage: "safari")
                }
                Spacer()
                Button("Fermer", action: onClose)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 620, height: 520)
    }
}
