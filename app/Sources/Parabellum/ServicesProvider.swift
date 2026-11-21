import AppKit
import ParabellumKit

/// Finder › clic droit › Actions rapides / Services (`NSServices` in Info.plist). Same actions as the
/// Finder extension's submenu, for when the extension is not enabled. AppKit calls these on the main
/// thread; the work is handed to `FinderActions` on the main actor.
final class ServicesProvider: NSObject {
    private func files(_ pboard: NSPasteboard) -> [URL] {
        let options: [NSPasteboard.ReadingOptionKey: Any] = [.urlReadingFileURLsOnly: true]
        let urls = pboard.readObjects(forClasses: [NSURL.self], options: options) as? [URL] ?? []
        return urls.filter(\.isFileURL).prefix(ParabellumURL.maxPaths).map(\.standardizedFileURL)
    }

    @objc func scanFiles(_ pboard: NSPasteboard, userData: String?, error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        let urls = files(pboard)
        Task { @MainActor in await FinderActions.shared.scan(urls) }
    }

    @objc func cleanMetadata(_ pboard: NSPasteboard, userData: String?, error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        let urls = files(pboard)
        Task { @MainActor in await FinderActions.shared.cleanMetadata(urls) }
    }

    @objc func encryptFolder(_ pboard: NSPasteboard, userData: String?, error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        guard let url = files(pboard).first else { return }
        Task { @MainActor in FinderActions.shared.encrypt(url) }
    }

    @objc func shredFiles(_ pboard: NSPasteboard, userData: String?, error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        let urls = files(pboard)
        Task { @MainActor in await FinderActions.shared.shred(urls) }
    }
}
