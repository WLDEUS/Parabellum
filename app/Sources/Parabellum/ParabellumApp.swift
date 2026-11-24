import ParabellumKit
import SwiftUI

@main
struct ParabellumApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    private var model: AppModel { AppModel.shared }

    @MainActor init() {
        // Before any scene is built: a second copy must not add a menu bar icon or restore a window.
        // State restoration off: the main window opens on request only (menu bar, link, notification).
        UserDefaults.standard.register(defaults: [
            "NSQuitAlwaysKeepsWindows": false,
            "ApplePersistenceIgnoreState": true,
        ])
        SingleInstance.claim()
    }

    var body: some Scene {
        MenuBarExtra(isInserted: .constant(!SingleInstance.isSecondary)) {
            MenuBarContentView()
                .environment(model)
        } label: {
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.window)

        Window("Parabellum", id: AppModel.mainWindowId) {
            MainWindowView()
                .environment(model)
        }
        .defaultSize(width: 1040, height: 700)
        .windowResizability(.contentMinSize)
    }
}

/// Menu bar icon reflecting the protection state. Also captures `openWindow` as early as possible.
struct MenuBarLabel: View {
    var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: model.menuBarSymbol)
            .accessibilityLabel("Parabellum")
            .onAppear {
                model.registerOpenWindow(openWindow)
            }
    }
}
