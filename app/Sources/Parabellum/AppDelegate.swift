import AppKit
import Darwin
import Foundation
import ParabellumKit

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// `parabellum://` links: Apple Event handler installed before launch events are processed (so a link
    /// that launches the app is not lost); `application(_:open:)` covers the case where AppKit / SwiftUI
    /// keeps its own handler.
    func applicationWillFinishLaunching(_ notification: Notification) {
        NSAppleEventManager.shared().setEventHandler(
            self,
            andSelector: #selector(handleGetURL(_:withReplyEvent:)),
            forEventClass: AEEventClass(kInternetEventClass),
            andEventID: AEEventID(kAEGetURL)
        )
    }

    @objc private func handleGetURL(_ event: NSAppleEventDescriptor, withReplyEvent reply: NSAppleEventDescriptor) {
        guard let text = event.paramDescriptor(forKeyword: AEKeyword(keyDirectObject))?.stringValue,
              let url = URL(string: text) else { return }
        open(url)
    }

    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            open(url)
        }
    }

    private func open(_ url: URL) {
        guard url.scheme?.lowercased() == ParabellumURL.scheme else { return }
        AppModel.shared.start()
        Task { await URLActionRunner.handle(url, model: AppModel.shared) }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // The socket uses SO_NOSIGPIPE; this is a second safety net.
        signal(SIGPIPE, SIG_IGN)
        // Menu bar app: no Dock icon unless the main window is open (also covers `swift run`,
        // where there is no Info.plist with LSUIElement).
        NSApp.setActivationPolicy(.accessory)
        AppModel.shared.start()
        // Coffre: auto-lock observers (screen lock, sleep, idle) and first status.
        AppModel.shared.vault.start()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    /// Clicking the app again in Finder / Launchpad opens the main window.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            AppModel.shared.showMainWindow()
        }
        return true
    }

    // MARK: Coffre

    /// Lock the vault before quitting (asks before forcing when files are still open).
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        let vault = AppModel.shared.vault
        guard vault.needsLockOnQuit else { return .terminateNow }
        Task { @MainActor in
            await vault.lockForQuit()
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
