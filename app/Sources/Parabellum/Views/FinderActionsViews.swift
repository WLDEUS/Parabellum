import AppKit
import ParabellumKit
import SwiftUI

/// Content of the Finder actions window (see `FinderActions`).
struct FinderActionsRoot: View {
    @ObservedObject var actions: FinderActions

    var body: some View {
        Group {
            switch actions.screen {
            case .encrypt(let url):
                EncryptFolderView(actions: actions, source: url)
            case .unlock(let url, let keys, let message):
                UnlockCoffreView(actions: actions, package: url, keys: keys, initialMessage: message)
            case nil:
                Color.clear.frame(width: 1, height: 1)
            }
        }
        .id(actions.screen?.id)
    }
}

// MARK: - Chiffrer

struct EncryptFolderView: View {
    @ObservedObject var actions: FinderActions
    let source: URL

    @State private var password = ""
    @State private var confirmation = ""
    @State private var touchID = CoffreKeys.touchIDAvailable
    @State private var keyFile = false
    @State private var deleteOriginal = true
    @State private var working = false
    @State private var error: String?

    private static let minLength = 12
    private var name: String { source.lastPathComponent }
    private var problem: String? {
        if password.count < Self.minLength {
            return String(localized: "Au moins \(Self.minLength) caractères.")
        }
        if password != confirmation {
            return String(localized: "Les deux mots de passe diffèrent.")
        }
        return nil
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Chiffrer « \(name) »", systemImage: "lock.doc.fill")
                .font(.title3.weight(.semibold))
            Text("Le contenu est copié dans « \(name).coffre », une image disque chiffrée (AES-256), puis vérifié fichier par fichier. Double-cliquez dessus pour l'ouvrir comme un dossier normal.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            SecureField("Mot de passe", text: $password)
            SecureField("Confirmez le mot de passe", text: $confirmation)
            Text("Notez-le : c'est l'accès de secours, il ouvre le coffre même sans Parabellum. Sans lui (ni Touch ID, ni fichier clé), le contenu est perdu.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Toggle("Ouvrir aussi avec Touch ID sur ce Mac", isOn: $touchID)
                .disabled(!CoffreKeys.touchIDAvailable)
            if !CoffreKeys.touchIDAvailable {
                Text("Touch ID n'est pas disponible sur ce Mac (ou aucune empreinte n'est enregistrée).")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Toggle("Créer aussi un fichier clé (à garder ailleurs, sur une clé USB par exemple)", isOn: $keyFile)
            Toggle("Supprimer définitivement l'original après vérification", isOn: $deleteOriginal)
            if deleteOriginal {
                Text("Vous confirmerez la suppression dans la fenêtre suivante.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            if let error {
                Text(error).font(.callout).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            } else if !password.isEmpty, let problem {
                Text(problem).font(.caption).foregroundStyle(.orange)
            }

            HStack {
                if working {
                    ProgressView().controlSize(.small)
                    Text("Chiffrement et vérification…").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Annuler", role: .cancel) { actions.close() }
                    .keyboardShortcut(.cancelAction)
                    .disabled(working)
                Button("Chiffrer") { Task { await submit() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(problem != nil || working)
            }
        }
        .padding(22)
        .frame(width: 480)
    }

    private func submit() async {
        error = nil
        var destination: URL?
        if keyFile {
            let panel = NSSavePanel()
            panel.title = String(localized: "Enregistrer le fichier clé")
            panel.nameFieldStringValue = "\(name).\(CoffreKeys.keyFileExtension)"
            panel.message = String(localized: "Rangez-le ailleurs que le dossier chiffré : qui a ce fichier peut l'ouvrir.")
            guard panel.runModal() == .OK, let url = panel.url else { return }
            destination = url
        }
        working = true
        let options = FinderActions.EncryptOptions(
            password: password,
            touchID: touchID,
            keyFileDestination: destination,
            deleteOriginal: deleteOriginal
        )
        error = await actions.runEncryption(source, options)
        working = false
    }
}

// MARK: - Ouvrir

struct UnlockCoffreView: View {
    @ObservedObject var actions: FinderActions
    let package: URL
    let keys: CoffreKeys.Keys
    let initialMessage: String?

    @State private var password = ""
    @State private var working = false
    @State private var error: String?

    private var name: String { package.deletingPathExtension().lastPathComponent }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Ouvrir « \(name) »", systemImage: "lock.open.fill")
                .font(.title3.weight(.semibold))
            if let message = error ?? initialMessage {
                Text(message).font(.callout).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
            }
            SecureField("Mot de passe", text: $password)
                .onSubmit { Task { await unlock(password) } }
            HStack {
                if keys.hasTouchID {
                    Button {
                        Task { await actions.openCoffre(package) }
                    } label: {
                        Label("Touch ID", systemImage: "touchid")
                    }
                    .disabled(working)
                }
                if keys.hasKeyFile {
                    Button("Fichier clé…") { Task { await useKeyFile() } }
                        .disabled(working)
                }
                Spacer()
                if working { ProgressView().controlSize(.small) }
                Button("Annuler", role: .cancel) { actions.close() }
                    .keyboardShortcut(.cancelAction)
                Button("Ouvrir") { Task { await unlock(password) } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(password.isEmpty || working)
            }
        }
        .padding(22)
        .frame(width: 440)
    }

    private func unlock(_ secret: String) async {
        working = true
        defer { working = false }
        if await actions.attach(package, password: secret) {
            actions.close()
        } else {
            error = String(localized: "Mot de passe incorrect.")
        }
    }

    private func useKeyFile() async {
        let panel = NSOpenPanel()
        panel.title = String(localized: "Choisir le fichier clé")
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data = try Data(contentsOf: url, options: [.uncached])
            let secret = try CoffreKeys.password(from: keys, keyFile: data)
            await unlock(secret)
        } catch {
            self.error = error.localizedDescription
        }
    }
}
