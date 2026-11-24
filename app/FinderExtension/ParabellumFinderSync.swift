import Cocoa
import FinderSync

/// Finder › clic droit › Parabellum (Finder Sync extension, sandboxed). It only builds the submenu and
/// hands the selection to the app through `parabellum://` links: the app does the work and asks for every
/// confirmation (encryption password, « Supprimer définitivement »).
@objc(ParabellumFinderSync)
final class ParabellumFinderSync: FIFinderSync {
    private static let maxPaths = 20

    override init() {
        super.init()
        // The whole disk and mounted volumes: the menu appears everywhere.
        FIFinderSyncController.default().directoryURLs = [URL(fileURLWithPath: "/")]
    }

    private var selection: [URL] {
        Array((FIFinderSyncController.default().selectedItemURLs() ?? []).prefix(Self.maxPaths))
    }

    private static func isFolder(_ url: URL) -> Bool {
        if url.hasDirectoryPath { return true }
        return (try? url.resourceValues(forKeys: [.isDirectoryKey]))?.isDirectory ?? false
    }

    private static func isCoffre(_ url: URL) -> Bool {
        url.standardizedFileURL.pathExtension.lowercased() == "coffre"
    }

    override func menu(for menuKind: FIMenuKind) -> NSMenu? {
        guard menuKind == .contextualMenuForItems else { return nil }
        let items = selection
        guard !items.isEmpty else { return nil }
        let sub = NSMenu(title: "Parabellum")
        func add(_ title: String, _ symbol: String, _ action: Selector) {
            let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
            item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
            sub.addItem(item)
        }
        let single = items.count == 1 ? items[0] : nil
        if let single, Self.isCoffre(single) {
            add(String(localized: "Ouvrir le dossier chiffré"), "lock.open", #selector(openCoffre(_:)))
            add(String(localized: "Verrouiller le dossier chiffré"), "lock", #selector(lockCoffre(_:)))
            sub.addItem(.separator())
        }
        add(String(localized: "Analyser"), "magnifyingglass", #selector(scan(_:)))
        if !items.contains(where: Self.isFolder) {
            add(String(localized: "Supprimer les métadonnées"), "eye.slash", #selector(cleanMetadata(_:)))
        }
        // A folder or a file (the app refuses links and anything else).
        if let single, !Self.isCoffre(single) {
            add(String(localized: "Chiffrer…"), "lock.doc", #selector(encrypt(_:)))
        }
        sub.addItem(.separator())
        add(String(localized: "Supprimer définitivement…"), "flame", #selector(shred(_:)))

        let menu = NSMenu(title: "")
        let parent = NSMenuItem(title: "Parabellum", action: nil, keyEquivalent: "")
        parent.image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: nil)
        parent.submenu = sub
        menu.addItem(parent)
        return menu
    }

    private func open(_ action: String, _ urls: [URL]) {
        var c = URLComponents()
        c.scheme = "parabellum"
        c.host = action
        c.queryItems = urls.map { URLQueryItem(name: "path", value: $0.standardizedFileURL.path) }
        guard let link = c.url else { return }
        NSWorkspace.shared.open(link)
    }

    private func openCoffreLink(_ verb: String) {
        guard let url = selection.first else { return }
        var c = URLComponents()
        c.scheme = "parabellum"
        c.host = "coffre"
        c.path = "/" + verb
        c.queryItems = [URLQueryItem(name: "path", value: url.standardizedFileURL.path)]
        if let link = c.url {
            NSWorkspace.shared.open(link)
        }
    }

    @objc func scan(_ sender: AnyObject?) { open("scan", selection) }
    @objc func cleanMetadata(_ sender: AnyObject?) { open("clean", selection) }
    @objc func encrypt(_ sender: AnyObject?) { open("encrypt", Array(selection.prefix(1))) }
    @objc func shred(_ sender: AnyObject?) { open("shred", selection) }
    @objc func openCoffre(_ sender: AnyObject?) { openCoffreLink("open") }
    @objc func lockCoffre(_ sender: AnyObject?) { openCoffreLink("lock") }
}
