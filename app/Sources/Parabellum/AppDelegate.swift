import AppKit
import Darwin
import Foundation

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
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
