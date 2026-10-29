import AppKit
import ParabellumKit
import SwiftUI
import UniformTypeIdentifiers

// Privacy tabs: data breaches, email aliases, local tools (passwords, metadata).

// MARK: - Breaches

struct BreachesTab: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            breachCard
            PasswordCheckCard()
        }
    }

    private var breachCard: some View {
        Card(title: "Tes adresses dans des fuites connues", symbol: "exclamationmark.lock") {
            VStack(alignment: .leading, spacing: 10) {
                if let breach = model.config?.breach {
                    if breach.enabled && !breach.emails.isEmpty {
                        Text("Surveillées avec \(breach.provider.label) : \(breach.emails.joined(separator: ", ")). Seule l'adresse est envoyée au service.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    } else {
                        HStack {
                            Text("Surveillance désactivée ou aucune adresse renseignée.")
                                .foregroundStyle(.secondary)
                            Button("Réglages") {
                                model.section = .settings
                            }
                            .buttonStyle(.link)
                        }
                    }
                }
                HStack {
                    Button {
                        Task { await model.checkBreachesNow() }
                    } label: {
                        if model.isBusy("breach-check") {
                            ProgressView().controlSize(.small)
                        } else {
                            Label("Vérifier maintenant", systemImage: "arrow.clockwise")
                        }
                    }
                    .disabled(model.isBusy("breach-check") || model.config?.breach.emails.isEmpty != false)
                    Spacer()
                }
                if model.breaches.isEmpty {
                    Text("Aucune fuite connue pour l'instant.").foregroundStyle(.secondary)
                } else {
                    ForEach(model.breaches) { finding in
                        BreachRow(finding: finding)
                        Divider()
                    }
                }
            }
        }
    }
}

private struct BreachRow: View {
    let finding: BreachFinding

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack(spacing: 6) {
                Text(finding.breach).fontWeight(.semibold)
                if finding.new {
                    Pill(text: "Nouveau", color: .orange)
                }
                if let date = finding.breachDate {
                    Text(date).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
                Text(finding.email).font(.caption).foregroundStyle(.secondary)
            }
            if !finding.dataClasses.isEmpty {
                Text(finding.dataClasses.joined(separator: ", "))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            if finding.exposesPasswords {
                Label("Des mots de passe ont fuité : change celui de ce site et partout où tu l'as réutilisé.", systemImage: "key.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(.vertical, 4)
    }
}

private struct PasswordCheckCard: View {
    @EnvironmentObject private var model: AppModel
    @State private var password = ""
    @State private var result: Int?
    @State private var exportResults: [LeakedPasswordEntry]?

    var body: some View {
        Card(title: "Mots de passe compromis (Pwned Passwords)", symbol: "key") {
            VStack(alignment: .leading, spacing: 10) {
                Text("k-anonymat : seuls les 5 premiers caractères de l'empreinte SHA-1 quittent le Mac, jamais le mot de passe.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    SecureField("Mot de passe à vérifier", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .frame(maxWidth: 320)
                        .onSubmit(check)
                    Button("Vérifier", action: check)
                        .disabled(password.isEmpty || model.isBusy("pwned"))
                }
                if let result {
                    if result > 0 {
                        Label("Présent \(PBFormat.count(result)) fois dans des fuites : ne l'utilise plus.", systemImage: "xmark.octagon.fill")
                            .foregroundStyle(.red)
                    } else {
                        Label("Absent des fuites connues.", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                    }
                }
                Divider()
                HStack {
                    Button {
                        pickExport()
                    } label: {
                        if model.isBusy("pwned-csv") {
                            ProgressView().controlSize(.small)
                        } else {
                            Label("Vérifier un export CSV de mots de passe…", systemImage: "tablecells")
                        }
                    }
                    .disabled(model.isBusy("pwned-csv"))
                    Spacer()
                }
                Text("Export depuis Chrome, Safari, Firefox ou Bitwarden. Supprime le fichier (et vide la Corbeille) après la vérification : il contient tes mots de passe en clair.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let exportResults {
                    exportList(exportResults)
                }
            }
        }
    }

    @ViewBuilder
    private func exportList(_ entries: [LeakedPasswordEntry]) -> some View {
        if entries.isEmpty {
            Label("Aucun mot de passe de l'export n'apparaît dans les fuites connues.", systemImage: "checkmark.seal.fill")
                .foregroundStyle(.green)
        } else {
            Text("\(entries.count) mot(s) de passe compromis à changer :").font(.headline)
            ForEach(entries) { entry in
                HStack {
                    Text(entry.name.isEmpty ? entry.url : entry.name)
                    Text(entry.username).foregroundStyle(.secondary)
                    Spacer()
                    Text("\(PBFormat.count(entry.count)) fuites").foregroundStyle(.red)
                }
                .font(.callout)
            }
        }
    }

    private func check() {
        let value = password
        guard !value.isEmpty else { return }
        Task {
            result = await model.checkPassword(value)
            password = ""
        }
    }

    private func pickExport() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.commaSeparatedText]
        panel.prompt = "Vérifier"
        NSApp.activate()
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            exportResults = await model.checkPasswordExport(url: url)
        }
    }
}

// MARK: - Aliases

struct AliasesTab: View {
    @EnvironmentObject private var model: AppModel
    @State private var label = ""

    private var provider: AliasProvider {
        model.config?.aliases.provider ?? .disabled
    }

    var body: some View {
        Card(title: "Alias e-mail", symbol: "at") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Une adresse différente pour chaque inscription : elle redirige vers ta vraie boîte, et tu la coupes si elle reçoit du spam ou fuit. Moins de données arrivent chez les courtiers.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if provider == .disabled {
                    HStack {
                        Text("Aucun service configuré (addy.io ou SimpleLogin, tous deux open source).")
                            .foregroundStyle(.secondary)
                        Button("Réglages") {
                            model.section = .settings
                        }
                        .buttonStyle(.link)
                    }
                } else {
                    HStack {
                        TextField("Pour quel site ? (ex. boutique-exemple.fr)", text: $label)
                            .textFieldStyle(.roundedBorder)
                            .frame(maxWidth: 340)
                            .onSubmit(create)
                        Button("Créer un alias", action: create)
                            .buttonStyle(.borderedProminent)
                            .disabled(label.trimmingCharacters(in: .whitespaces).isEmpty || model.isBusy("alias-create"))
                    }
                    Text("Service : \(provider.label). L'alias créé est copié dans le presse-papiers.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                if !model.emailAliases.isEmpty {
                    Divider()
                    ForEach(model.emailAliases) { alias in
                        aliasRow(alias)
                    }
                }
            }
        }
    }

    private func aliasRow(_ alias: EmailAlias) -> some View {
        HStack(spacing: 8) {
            Image(systemName: alias.active ? "envelope.fill" : "envelope.badge.shield.half.filled")
                .foregroundStyle(alias.active ? Color.accentColor : Color.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(alias.email)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
                Text("\(alias.label) · \(PBFormat.day(alias.createdDate))\(alias.active ? "" : " · désactivé")")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                model.copyToPasteboard(alias.email)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copier")
        }
    }

    private func create() {
        let value = label.trimmingCharacters(in: .whitespaces)
        guard !value.isEmpty else { return }
        Task {
            if await model.createAlias(label: value) != nil {
                label = ""
            }
        }
    }
}

// MARK: - Local tools

struct PrivacyToolsTab: View {
    @EnvironmentObject private var model: AppModel
    @State private var reports: [CleanReport] = []
    @State private var dropTargeted = false

    var body: some View {
        Card(title: "Retirer les métadonnées", symbol: "location.slash") {
            VStack(alignment: .leading, spacing: 10) {
                Text("Photos et documents gardent souvent la position GPS, l'appareil, l'auteur ou la date. Parabellum écrit une copie nettoyée (« .clean ») à côté de l'original, avec tes droits. JPEG, PNG, WebP et documents Office en natif ; le reste via exiftool s'il est installé (Homebrew).")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                dropZone
                if !reports.isEmpty {
                    ForEach(reports) { report in
                        reportRow(report)
                    }
                }
            }
        }
    }

    private var dropZone: some View {
        VStack(spacing: 8) {
            Image(systemName: "photo.on.rectangle.angled")
                .font(.system(size: 28))
                .foregroundStyle(.secondary)
            Text("Dépose des fichiers ici").foregroundStyle(.secondary)
            Button {
                pickFiles()
            } label: {
                if model.isBusy("metadata") {
                    ProgressView().controlSize(.small)
                } else {
                    Text("Choisir des fichiers…")
                }
            }
            .disabled(model.isBusy("metadata"))
        }
        .frame(maxWidth: .infinity, minHeight: 130)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [6]))
                .foregroundStyle(dropTargeted ? Color.accentColor : Color.secondary.opacity(0.5))
        )
        .onDrop(of: [UTType.fileURL], isTargeted: $dropTargeted) { providers in
            loadDropped(providers)
            return true
        }
    }

    private func reportRow(_ report: CleanReport) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: report.error == nil ? "checkmark.circle.fill" : "xmark.circle.fill")
                .foregroundStyle(report.error == nil ? Color.green : Color.red)
            VStack(alignment: .leading, spacing: 2) {
                Text((report.input as NSString).lastPathComponent)
                Text(reportDetail(report))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if let output = report.output {
                Button("Afficher") {
                    model.revealInFinder(output)
                }
                .buttonStyle(.link)
            }
        }
    }

    private func reportDetail(_ report: CleanReport) -> String {
        if let error = report.error {
            return "Échec : \(error)"
        }
        if report.output == nil {
            return "Rien à retirer."
        }
        if report.removed.isEmpty {
            return "Copie écrite (\(report.method)), rien d'identifiant trouvé."
        }
        return "Retiré : \(report.removed.joined(separator: ", ")) (\(report.method))"
    }

    private func pickFiles() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.prompt = "Nettoyer"
        NSApp.activate()
        guard panel.runModal() == .OK else { return }
        clean(panel.urls)
    }

    private func loadDropped(_ providers: [NSItemProvider]) {
        Task { @MainActor in
            var urls: [URL] = []
            for provider in providers {
                if let url = await Self.fileURL(from: provider) {
                    urls.append(url)
                }
            }
            clean(urls)
        }
    }

    private static func fileURL(from provider: NSItemProvider) async -> URL? {
        await withCheckedContinuation { (continuation: CheckedContinuation<URL?, Never>) in
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                continuation.resume(returning: url?.isFileURL == true ? url : nil)
            }
        }
    }

    private func clean(_ urls: [URL]) {
        guard !urls.isEmpty else { return }
        Task {
            reports = await model.cleanMetadata(urls: urls)
        }
    }
}
