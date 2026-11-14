import AppKit
import Foundation
import ParabellumKit

/// Runs `parabellum://` links (Shortcuts "Ouvrir l'URL", Raycast, Alfred, `open parabellum://…`).
/// Parsing is strict (`ParabellumURL.parse`); protection-lowering actions go through the usual
/// administrator prompt of `AppModel.call`, so a link alone can never weaken protection.
@MainActor
enum URLActionRunner {
    static func handle(_ url: URL, model: AppModel) async {
        switch ParabellumURL.parse(url) {
        case .failure(let error):
            model.banner = Banner(message: "Lien Parabellum refusé : \(error.message)", isError: true)
            model.showMainWindow()
        case .success(let action):
            await run(action, model: model)
        }
    }

    private static func run(_ action: ParabellumURLAction, model: AppModel) async {
        switch action {
        case .scan(let paths):
            let missing = paths.filter { !FileManager.default.fileExists(atPath: $0) }
            if let first = missing.first {
                model.banner = Banner(message: "Introuvable : \(first)", isError: true)
                model.showMainWindow(section: .scan)
                return
            }
            model.showMainWindow(section: .scan)
            await model.startScan(paths: paths)
        case .scanDownloads:
            model.showMainWindow(section: .scan)
            await model.scanDownloads()
        case .vpnConnect:
            await model.vpnConnect()
        case .vpnDisconnect:
            NSApp.activate()
            await model.vpnDisconnect()
        case .travelOn:
            await model.travel.enable()
        case .travelOff:
            NSApp.activate()
            await model.travel.disable()
        case .pause(let minutes):
            NSApp.activate()
            await model.setProtection(pausedMinutes: minutes)
        case .resume:
            await model.setProtection(pausedMinutes: 0)
        case .update(let target):
            await model.updateNow(target)
        case .open(let name):
            guard let name else {
                model.showMainWindow(section: .dashboard)
                return
            }
            guard let section = SidebarSection(rawValue: name) else {
                model.banner = Banner(message: "Section inconnue : \(name)", isError: true)
                model.showMainWindow()
                return
            }
            model.showMainWindow(section: section)
        }
    }
}
