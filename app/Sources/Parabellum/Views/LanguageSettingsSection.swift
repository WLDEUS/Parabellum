import AppKit
import ParabellumKit
import SwiftUI

/// Réglages › Langue: interface language (macOS `AppleLanguages` for this app), applied on relaunch.
struct LanguageSettingsSection: View {
    @State private var choice = AppLanguage.stored()
    /// Language of the running process (what the window shows now).
    private let running = AppLanguage.resolved

    private var needsRelaunch: Bool {
        let wanted: String
        switch choice {
        case .french: wanted = "fr"
        case .english: wanted = "en"
        case .system: wanted = Locale.preferredLanguages.first?.hasPrefix("en") == true ? "en" : "fr"
        }
        return wanted != running
    }

    var body: some View {
        Section {
            Picker("Langue de l'interface", selection: $choice) {
                ForEach(AppLanguage.allCases) { language in
                    Text(verbatim: language.label).tag(language)
                }
            }
            .onChange(of: choice) { _, new in
                AppLanguage.store(new)
            }
            if needsRelaunch {
                HStack {
                    Text("La nouvelle langue s'applique au prochain lancement.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Relancer maintenant", action: Self.relaunch)
                        .buttonStyle(.borderedProminent)
                }
            }
            Text("Les messages du service (alertes, notifications) suivent la même langue à partir de leur prochaine création.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        } header: {
            Text("Langue")
        }
    }

    /// Start a fresh instance, then quit this one.
    static func relaunch() {
        let config = NSWorkspace.OpenConfiguration()
        config.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: config) { _, _ in
            DispatchQueue.main.async { NSApp.terminate(nil) }
        }
    }
}
