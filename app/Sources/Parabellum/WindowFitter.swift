import AppKit

/// Keeps the main window filling the visible part of its screen (menu bar and Dock excluded).
///
/// - Fitted each time the window is shown, and again when the display set or resolution changes
///   (`didChangeScreenParametersNotification`) or the window is dragged to another screen.
/// - The green button keeps giving true full screen (`fullScreenPrimary`); nothing is refitted while in it.
/// - The window is never larger than its screen: SwiftUI's minimum size (900 × 600) is lowered to the
///   screen size on small displays so nothing overflows.
@MainActor
final class WindowFitter {
    static let shared = WindowFitter()

    private weak var window: NSWindow?
    private var observers: [NSObjectProtocol] = []

    func attach(_ window: NSWindow) {
        if self.window !== window {
            detach()
            self.window = window
            window.collectionBehavior.insert(.fullScreenPrimary)
            window.isRestorable = false
            let center = NotificationCenter.default
            observers.append(center.addObserver(
                forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: .main
            ) { [weak self] _ in MainActor.assumeIsolated { self?.fit() } })
            observers.append(center.addObserver(
                forName: NSWindow.didChangeScreenNotification, object: window, queue: .main
            ) { [weak self] _ in MainActor.assumeIsolated { self?.fit() } })
        }
        fit()
    }

    func detach() {
        observers.forEach(NotificationCenter.default.removeObserver)
        observers.removeAll()
        window = nil
    }

    func fit() {
        guard let window, !window.styleMask.contains(.fullScreen),
              let screen = window.screen ?? NSScreen.main else { return }
        let target = Self.frame(visible: screen.visibleFrame)
        let minimum = NSSize(width: min(900, target.width), height: min(600, target.height))
        window.minSize = minimum
        window.contentMinSize = minimum
        guard window.frame != target else { return }
        // No animation: an animated resize of a large SwiftUI window re-lays out every frame.
        window.setFrame(target, display: true, animate: false)
    }

    /// The visible frame, rounded to whole points (half points blur text on non-Retina displays).
    nonisolated static func frame(visible: NSRect) -> NSRect {
        NSRect(x: visible.minX.rounded(.up), y: visible.minY.rounded(.up),
               width: visible.width.rounded(.down), height: visible.height.rounded(.down))
    }
}
