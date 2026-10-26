import ParabellumKit
import SwiftUI

@main
struct ParabellumApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    private var model: AppModel { AppModel.shared }

    var body: some Scene {
        MenuBarExtra {
            MenuBarContentView()
                .environmentObject(model)
        } label: {
            MenuBarLabel(model: model)
        }
        .menuBarExtraStyle(.window)

        Window("Parabellum", id: AppModel.mainWindowId) {
            MainWindowView()
                .environmentObject(model)
        }
        .defaultSize(width: 1040, height: 700)
    }
}

/// Menu bar icon reflecting the protection state. Also captures `openWindow` as early as possible.
struct MenuBarLabel: View {
    @ObservedObject var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: model.menuBarSymbol)
            .accessibilityLabel("Parabellum")
            .onAppear {
                model.registerOpenWindow(openWindow)
            }
    }
}
