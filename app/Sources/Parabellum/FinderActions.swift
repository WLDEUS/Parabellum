import AppKit
import ParabellumKit
import SwiftUI

/// What the Finder asks for (right-click › Parabellum, Quick Actions / Services, double-click on a
/// `.coffre`): scan, clean metadata, encrypt a folder, open / lock an encrypted folder, delete for good.
///
/// Everything that destroys or encrypts goes through a window of this app that the user confirms: a
/// `parabellum://` link can come from any app or web page, so a link alone never deletes anything.
@MainActor
final class FinderActions: ObservableObject {
    static let shared = FinderActions()

    enum Screen: Identifiable, Equatable {
        case encrypt(URL)
        case unlock(URL, CoffreKeys.Keys, message: String?)

        var id: String {
            switch self {
            case .encrypt(let url): return "encrypt:" + url.path
            case .unlock(let url, _, _): return "unlock:" + url.path
            }
        }
    }

    @Published var screen: Screen?
    private var panel: NSPanel?
    private var model: AppModel { AppModel.shared }

    // MARK: - Entry points

    func scan(_ urls: [URL]) async {
        guard !urls.isEmpty else { return }
        model.showMainWindow(section: .scan)
        await model.startScan(paths: urls.map(\.path))
    }

    /// Cleaned copies next to the originals, then shown in the Finder.
    func cleanMetadata(_ urls: [URL]) async {
        let files = urls.filter { !$0.hasDirectoryPath }
        guard !files.isEmpty else {
            notify(String(localized: "Choisissez des fichiers (photos, PDF, documents) : les dossiers ne sont pas nettoyés."), isError: true)
            return
        }
        let reports = await model.cleanMetadata(urls: files)
        let outputs = reports.compactMap(\.output).map { URL(fileURLWithPath: $0) }
        let failed = reports.filter { $0.error != nil }
        if !outputs.isEmpty {
            NSWorkspace.shared.activateFileViewerSelecting(outputs)
        }
        if failed.isEmpty {
            notify(String(localized: "\(outputs.count) copie(s) sans métadonnées créée(s) à côté des originaux."), isError: false)
        } else {
            notify(String(localized: "\(outputs.count) fichier(s) nettoyé(s), \(failed.count) en échec : \(failed[0].error ?? "")"), isError: true)
        }
    }

    /// A folder or a regular file (not a link, not an encrypted folder already).
    func encrypt(_ url: URL) {
        let values = try? url.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
        let usable = values.map { $0.isSymbolicLink != true && ($0.isDirectory == true || $0.isRegularFile == true) } ?? false
        guard usable, !CoffrePackage.isPackage(url) else {
            notify(String(localized: "Choisissez un dossier ou un fichier à chiffrer."), isError: true)
            return
        }
        present(.encrypt(url))
    }

    /// Dry run then the usual confirmation (in the Coffre section), with the snapshot option.
    func shred(_ urls: [URL]) async {
        guard !urls.isEmpty else { return }
        model.showMainWindow(section: .vault)
        await model.vault.prepareShred(urls: urls)
    }

    /// Touch ID first when this folder has it, else the password / key file window.
    func openCoffre(_ url: URL) async {
        guard CoffrePackage.isPackage(url) else { return }
        let location = CoffrePackage.location(url)
        if let status = try? await VaultCLI.status(location, recent: 0), status.mounted, let mount = status.mountPoint {
            NSWorkspace.shared.open(URL(fileURLWithPath: mount))
            return
        }
        let keys = CoffreKeys.load(package: url)
        var message: String?
        if keys.hasTouchID {
            do {
                let password = try await CoffreKeys.passwordWithTouchID(
                    from: keys,
                    reason: String(localized: "ouvrir le dossier chiffré « \(url.deletingPathExtension().lastPathComponent) »")
                )
                if await attach(url, password: password) { return }
                message = String(localized: "Le mot de passe enregistré pour Touch ID ne fonctionne plus : saisissez-le.")
            } catch CoffreKeys.Failure.cancelled {
                message = nil
            } catch {
                message = error.localizedDescription
            }
        }
        present(.unlock(url, keys, message: message))
    }

    func lockCoffre(_ url: URL) async {
        let result = await model.perform("coffre-lock") {
            try await VaultCLI.detach(CoffrePackage.location(url), force: false)
        }
        if result != nil {
            notify(String(localized: "Dossier chiffré verrouillé : \(url.deletingPathExtension().lastPathComponent)"), isError: false)
        }
    }

    // MARK: - Work behind the windows

    /// Unlocks and shows the folder. False on a wrong password (the window says so).
    func attach(_ url: URL, password: String) async -> Bool {
        do {
            let status = try await VaultCLI.attach(CoffrePackage.location(url), password: password)
            if let mount = status.mountPoint {
                NSWorkspace.shared.open(URL(fileURLWithPath: mount))
            }
            return true
        } catch let error as VaultCLIError where error.isBadPassword {
            return false
        } catch {
            notify(error.localizedDescription, isError: true)
            return true
        }
    }

    struct EncryptOptions {
        var password: String
        var touchID: Bool
        var keyFileDestination: URL?
        var deleteOriginal: Bool
    }

    /// Encrypts, adds the chosen ways in, then hands the original to « Supprimer définitivement ».
    /// Returns an error message to show in the window, nil when done.
    func runEncryption(_ source: URL, _ options: EncryptOptions) async -> String? {
        let result: FolderEncryption
        do {
            result = try await VaultCLI.encryptFolder(source: source.path, password: options.password)
        } catch {
            return error.localizedDescription
        }
        let package = URL(fileURLWithPath: result.package)
        var keys = CoffreKeys.Keys()
        var warnings: [String] = []
        if options.touchID {
            do {
                keys.slots.append(try CoffreKeys.touchIDSlot(password: options.password))
            } catch {
                warnings.append(String(localized: "Touch ID non ajouté : \(error.localizedDescription)"))
            }
        }
        if let destination = options.keyFileDestination {
            let keyFile = CoffreKeys.newKeyFile()
            do {
                try keyFile.write(to: destination, options: [.atomic, .withoutOverwriting])
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
                keys.slots.append(try CoffreKeys.keyFileSlot(password: options.password, keyFile: keyFile))
            } catch {
                warnings.append(String(localized: "Fichier clé non créé : \(error.localizedDescription)"))
            }
        }
        if !keys.slots.isEmpty {
            do {
                try CoffreKeys.save(keys, package: package)
            } catch {
                warnings.append(String(localized: "Accès sans mot de passe non enregistrés : \(error.localizedDescription)"))
            }
        }
        close()
        NSWorkspace.shared.activateFileViewerSelecting([package])
        let summary = String(localized: "Dossier chiffré : \(package.lastPathComponent) (\(result.files) fichier(s) vérifié(s)).")
        notify(([summary] + warnings).joined(separator: " "), isError: !warnings.isEmpty)
        if options.deleteOriginal {
            model.showMainWindow(section: .vault)
            await model.vault.prepareShred(urls: [source], source: .originals)
        }
        return nil
    }

    // MARK: - Window

    func present(_ screen: Screen) {
        self.screen = screen
        let panel = self.panel ?? makePanel()
        self.panel = panel
        switch screen {
        case .encrypt(let url):
            let isDir = (try? url.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory ?? url.hasDirectoryPath
            panel.title = isDir
                ? String(localized: "Chiffrer un dossier")
                : String(localized: "Chiffrer un fichier")
        case .unlock: panel.title = String(localized: "Ouvrir un dossier chiffré")
        }
        panel.center()
        NSApp.activate()
        panel.makeKeyAndOrderFront(nil)
    }

    func close() {
        screen = nil
        panel?.orderOut(nil)
    }

    private func makePanel() -> NSPanel {
        let panel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 420),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        panel.isReleasedWhenClosed = false
        panel.hidesOnDeactivate = false
        panel.contentView = NSHostingView(rootView: FinderActionsRoot(actions: self))
        return panel
    }

    /// Banner in the app plus a notification: the Finder is usually in front.
    private func notify(_ message: String, isError: Bool) {
        model.banner = Banner(message: message, isError: isError)
        let notifications = model.notifications
        Task { await notifications.postMessage(title: "Parabellum", body: message) }
    }
}
