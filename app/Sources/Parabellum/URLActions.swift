import AppKit
import Foundation
import ParabellumKit

/// Runs `parabellum://` links (Shortcuts "Ouvrir l'URL", Raycast, Alfred, `open parabellum://…`).
/// Parsing is strict (`ParabellumURL.parse`). Any process can open a link, so protection-lowering actions
/// ask for an in-app confirmation naming the action and then a fresh administrator authorization (never
/// the one cached for ~5 min after an in-app action), and no link retries `auth_required` with a prompt
/// (`URLActionPolicy`).
@MainActor
enum URLActionRunner {
    static func handle(_ url: URL, model: AppModel) async {
        switch ParabellumURL.parse(url) {
        case .failure(let error):
            model.banner = Banner(message: String(localized: "Lien Parabellum refusé : \(error.message)"), isError: true)
            model.showMainWindow()
        case .success(let action):
            let policy = action.policy
            if policy.requiresConfirmation && !confirm(policy) {
                model.banner = Banner(message: String(localized: "Action du lien annulée."), isError: false)
                return
            }
            await model.runURLAction(policy: policy) {
                await run(action, model: model)
            }
        }
    }

    /// In-app confirmation (the system prompt that follows cannot be driven by synthetic input either).
    private static func confirm(_ policy: URLActionPolicy) -> Bool {
        NSApp.activate()
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = policy.confirmationTitle ?? String(localized: "Un lien demande de réduire la protection.")
        alert.informativeText = String(localized: "N'importe quelle app ou page web peut ouvrir un lien parabellum://. ")
            + String(localized: "Ne continuez que si c'est vous qui l'avez lancé (raccourci, Raycast, Alfred…).")
        alert.addButton(withTitle: "Annuler")
        alert.addButton(withTitle: "Continuer")
        return alert.runModal() == .alertSecondButtonReturn
    }

    private static func run(_ action: ParabellumURLAction, model: AppModel) async {
        switch action {
        case .scan(let paths):
            let missing = paths.filter { !FileManager.default.fileExists(atPath: $0) }
            if let first = missing.first {
                model.banner = Banner(message: String(localized: "Introuvable : \(first)"), isError: true)
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
                model.banner = Banner(message: String(localized: "Section inconnue : \(name)"), isError: true)
                model.showMainWindow()
                return
            }
            model.showMainWindow(section: section)
        }
    }
}
