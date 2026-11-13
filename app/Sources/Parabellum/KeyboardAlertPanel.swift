import AppKit
import ParabellumKit
import SwiftUI

/// Floating panel that never becomes key: a BadUSB "keyboard" cannot answer it by typing,
/// only a real mouse click can.
final class MouseOnlyPanel: NSPanel {
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

/// Lets the first click act on the buttons even though the panel is never key.
final class FirstMouseHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}

/// Progress of the decision shown in a panel (the panel stays open until the daemon applied it).
@MainActor
final class KeyboardAlertState: ObservableObject {
    @Published var busy = false
    @Published var error: String?
}

/// Shows one always-on-top panel per newly connected keyboard (BadUSB check).
@MainActor
final class KeyboardAlertPanelController {
    weak var model: AppModel?
    private var panels: [String: (panel: NSPanel, state: KeyboardAlertState)] = [:]

    func present(device: DeviceInfo) {
        if let existing = panels[device.id] {
            existing.panel.orderFrontRegardless()
            return
        }
        let deviceId = device.id
        let state = KeyboardAlertState()
        let view = KeyboardAlertView(
            device: device,
            state: state,
            onTrust: { [weak self] in self?.decide(deviceId, trust: .trusted) },
            onBlock: { [weak self] in self?.decide(deviceId, trust: .blocked) },
            onLater: { [weak self] in self?.decide(deviceId, trust: nil) }
        )
        let hosting = FirstMouseHostingView(rootView: view)
        let size = hosting.fittingSize
        let panel = MouseOnlyPanel(
            contentRect: NSRect(x: 0, y: 0, width: max(size.width, 460), height: max(size.height, 200)),
            styleMask: [.titled, .nonactivatingPanel, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        panel.title = "Nouveau clavier détecté"
        panel.titleVisibility = .hidden
        panel.titlebarAppearsTransparent = true
        panel.isFloatingPanel = true
        panel.level = .floating
        panel.hidesOnDeactivate = false
        panel.isReleasedWhenClosed = false
        panel.isMovableByWindowBackground = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.contentView = hosting
        panel.center()
        if !panels.isEmpty {
            // Cascade when several keyboards appear at once.
            let offset = CGFloat(panels.count) * 28
            var origin = panel.frame.origin
            origin.x += offset
            origin.y -= offset
            panel.setFrameOrigin(origin)
        }
        panel.orderFrontRegardless()
        panels[deviceId] = (panel, state)
        NSSound.beep()
    }

    /// "Plus tard" closes at once. "Bloquer" / "Faire confiance" keep the panel open until the daemon
    /// confirms; a failure (or a cancelled administrator prompt) is shown in the panel, which can be retried.
    private func decide(_ deviceId: String, trust: DeviceTrust?) {
        guard let entry = panels[deviceId] else { return }
        guard let trust else {
            close(deviceId)
            return
        }
        guard let model else {
            entry.state.error = "Parabellum n'est pas prêt : réessaie dans un instant."
            return
        }
        guard !entry.state.busy else { return }
        entry.state.busy = true
        entry.state.error = nil
        Task { [weak self] in
            let failure = await model.decideKeyboardTrust(deviceId, trust: trust)
            entry.state.busy = false
            if let failure {
                entry.state.error = failure
                self?.resize(deviceId)
            } else {
                self?.close(deviceId)
            }
        }
    }

    private func close(_ deviceId: String) {
        panels.removeValue(forKey: deviceId)?.panel.close()
    }

    /// Fits the panel to its content (an error line was added).
    private func resize(_ deviceId: String) {
        guard let panel = panels[deviceId]?.panel, let content = panel.contentView else { return }
        let size = content.fittingSize
        var frame = panel.frame
        let height = max(size.height, 200)
        frame.origin.y += frame.height - height
        frame.size.height = height
        panel.setFrame(frame, display: true)
    }
}
