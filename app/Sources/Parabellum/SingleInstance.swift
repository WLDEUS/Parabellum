import AppKit
import Darwin
import Foundation

/// One Parabellum app per user session.
///
/// At login several launchers can race: the LaunchAgent (`com.wldeus.parabellum.ui`), macOS « Rouvrir les
/// fenêtres » (loginwindow relaunch list) and LaunchServices answering a `parabellum://` link, a Service or
/// a double-click on a `.coffre` before the first copy has checked in. Each copy used to start its own
/// menu bar icon, event stream and window.
///
/// The first copy takes an exclusive `flock` on a per-user lock file (released by the kernel when the
/// process dies, so a crash never blocks the next launch). A later copy keeps nothing: it forwards the
/// links / files it was launched for to the running copy over a distributed notification, brings that copy
/// forward and exits 0 (the LaunchAgent's `KeepAlive.SuccessfulExit = false` does not restart it).
///
/// The forwarded payload is a plain URL string handled exactly like a link opened by any other app
/// (`ParabellumURL.parse` + the usual confirmations): the channel grants nothing a `parabellum://` link
/// does not already grant.
@MainActor
enum SingleInstance {
    static let forwardNotification = Notification.Name("com.wldeus.parabellum.forward-open")
    private static let urlKey = "url"
    /// Links / files accepted per forward, like `ParabellumURL.maxPaths`.
    private static let maxForwarded = 20
    private static var lockFD: Int32 = -1
    private(set) static var isSecondary = false
    private static var pending: [URL] = []

    /// Called from `applicationWillFinishLaunching`, before any scene or handler does work.
    /// Returns false when another copy already runs (this one is then on its way out).
    @discardableResult
    static func claim() -> Bool {
        guard lockFD < 0 else { return true }
        let fd = open(lockPath(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else {
            // Cannot tell (unwritable home…): behave as the only copy rather than refuse to start.
            return true
        }
        if flock(fd, LOCK_EX | LOCK_NB) == 0 {
            lockFD = fd
            return true
        }
        close(fd)
        isSecondary = true
        // Collect the Apple Events that launched this copy (they arrive just after launch), then hand
        // them over and leave.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
            MainActor.assumeIsolated { handOverAndExit() }
        }
        return false
    }

    /// The running copy listens for links / files opened while a duplicate was launching.
    static func listen(_ handler: @escaping @MainActor (URL) -> Void) {
        DistributedNotificationCenter.default().addObserver(
            forName: forwardNotification, object: nil, queue: .main
        ) { note in
            guard let text = note.userInfo?[urlKey] as? String, text.utf8.count <= 64 * 1024,
                  let url = URL(string: text) else { return }
            MainActor.assumeIsolated { handler(url) }
        }
    }

    /// A duplicate keeps what it was launched for instead of acting on it.
    static func deferIfSecondary(_ url: URL) -> Bool {
        guard isSecondary else { return false }
        if pending.count < maxForwarded {
            pending.append(url)
        }
        return true
    }

    private static func handOverAndExit() {
        let center = DistributedNotificationCenter.default()
        for url in pending {
            center.postNotificationName(
                forwardNotification, object: nil,
                userInfo: [urlKey: url.absoluteString], deliverImmediately: true
            )
        }
        let me = ProcessInfo.processInfo.processIdentifier
        if pending.isEmpty, let bundleId = Bundle.main.bundleIdentifier,
           let other = NSRunningApplication.runningApplications(withBundleIdentifier: bundleId)
               .first(where: { $0.processIdentifier != me }) {
            other.activate()
        }
        NSLog("Parabellum : une autre instance tourne déjà, celle-ci (pid %d) se ferme", me)
        // Let the notifications leave before exiting.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { exit(0) }
    }

    private static func lockPath() -> String {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let dir = base.appendingPathComponent("Parabellum", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        return dir.appendingPathComponent("ui.lock").path
    }
}
