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

/// Shows one always-on-top panel per newly connected keyboard (BadUSB check).
@MainActor
final class KeyboardAlertPanelController {
    weak var model: AppModel?
    private var panels: [String: NSPanel] = [:]

    func present(device: DeviceInfo) {
        if let existing = panels[device.id] {
            existing.orderFrontRegardless()
            return
        }
        let deviceId = device.id
        let view = KeyboardAlertView(
            device: device,
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
        panels[deviceId] = panel
        NSSound.beep()
    }

    private func decide(_ deviceId: String, trust: DeviceTrust?) {
        panels.removeValue(forKey: deviceId)?.close()
        guard let trust, let model else { return }
        Task { await model.setDeviceTrust(deviceId, trust: trust) }
    }
}
