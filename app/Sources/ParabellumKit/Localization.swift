import Foundation

/// Interface language: French (source) or English (`app/Localization/en.lproj/Localizable.strings`).
///
/// The choice is stored the macOS way (`AppleLanguages` in the app's defaults), so every API follows it:
/// SwiftUI `Text`, `String(localized:)`, formatters. It applies at the next launch of the app.
public enum AppLanguage: String, CaseIterable, Sendable, Identifiable {
    case system
    case french = "fr"
    case english = "en"

    public var id: String { rawValue }

    /// Shown in its own language, so anyone can find theirs.
    public var label: String {
        switch self {
        case .system: return String(localized: "Langue du système")
        case .french: return "Français" // l10n-ignore
        case .english: return "English"
        }
    }

    private static let defaultsKey = "AppleLanguages"

    /// What the user picked (Réglages › Langue).
    public static func stored(_ defaults: UserDefaults = .standard) -> AppLanguage {
        guard let list = defaults.persistentDomain(forName: Bundle.main.bundleIdentifier ?? "")?[defaultsKey]
            as? [String], let first = list.first
        else { return .system }
        if first.hasPrefix("fr") { return .french }
        if first.hasPrefix("en") { return .english }
        return .system
    }

    /// Saves the choice for the next launch (`system`: follow macOS again).
    public static func store(_ language: AppLanguage, _ defaults: UserDefaults = .standard) {
        switch language {
        case .system: defaults.removeObject(forKey: defaultsKey)
        case .french, .english: defaults.set([language.rawValue], forKey: defaultsKey)
        }
    }

    /// Language actually used by this process: `fr` or `en`. Outside the app bundle (tests, tools),
    /// where no English table ships, French.
    public static var resolved: String {
        // Our English table, not just any "en" folder (the XCTest runner has one).
        guard Bundle.main.path(forResource: "Localizable", ofType: "strings", inDirectory: nil, forLocalization: "en")
            != nil
        else { return "fr" }
        return Bundle.main.preferredLocalizations.first?.hasPrefix("en") == true ? "en" : "fr"
    }

    public static var isEnglish: Bool { resolved == "en" }

    /// Locale for dates and numbers: the interface language with the user's region (24 h clock and
    /// day-month order kept in France while reading English).
    public static var locale: Locale {
        let region = Locale.current.region?.identifier ?? "FR"
        return Locale(identifier: "\(resolved)_\(region)")
    }
}

extension String.LocalizationValue.StringInterpolation {
    /// Anything else (errors, enums, optionals…) interpolated as `"\(value)"` would print it (`%@`).
    public mutating func appendInterpolation<T>(_ value: T) {
        appendInterpolation(String(describing: value))
    }
}
