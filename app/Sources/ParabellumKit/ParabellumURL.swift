import Foundation

/// Actions reachable through the `parabellum://` URL scheme (Shortcuts "Ouvrir l'URL", Raycast, Alfred, a
/// link…). Anything that lowers protection still goes through the administrator prompt in the app.
public enum ParabellumURLAction: Equatable, Sendable {
    /// `parabellum://scan?path=/Users/me/file.dmg` (`path` may repeat, absolute paths only).
    case scan(paths: [String])
    /// `parabellum://scan/downloads`
    case scanDownloads
    /// `parabellum://vpn/connect`
    case vpnConnect
    /// `parabellum://vpn/disconnect` (admin)
    case vpnDisconnect
    /// `parabellum://travel/on`
    case travelOn
    /// `parabellum://travel/off` (admin)
    case travelOff
    /// `parabellum://pause?minutes=15` (admin)
    case pause(minutes: Int)
    /// `parabellum://resume`
    case resume
    /// `parabellum://update` or `parabellum://update?target=db|components|app|all`
    case update(target: UpdateTarget)
    /// `parabellum://open/<section>` (the app checks the section exists); `parabellum://open` = dashboard.
    case open(section: String?)
}

public struct ParabellumURLError: Error, Equatable, LocalizedError, Sendable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}

public enum ParabellumURL {
    public static let scheme = "parabellum"
    /// Longest pause accepted (same as the daemon: 7 days).
    public static let maxPauseMinutes = 7 * 24 * 60
    public static let maxPaths = 20
    public static let maxPathLength = 4096

    /// Strict parser: unknown actions, unexpected parameters, relative or odd paths are rejected.
    public static func parse(_ url: URL) -> Result<ParabellumURLAction, ParabellumURLError> {
        guard let c = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return .failure(ParabellumURLError("Lien illisible."))
        }
        guard c.scheme?.lowercased() == scheme else {
            return .failure(ParabellumURLError("Ce lien n'est pas un lien parabellum://."))
        }
        if c.user != nil || c.password != nil || c.port != nil {
            return .failure(ParabellumURLError("Lien parabellum:// invalide."))
        }
        // `parabellum://scan/downloads` (host + path) and `parabellum:scan/downloads` (path only).
        var segments: [String] = []
        if let host = c.host, !host.isEmpty {
            segments.append(host.lowercased())
        }
        segments += c.path.split(separator: "/").map { String($0).lowercased() }
        let items = c.queryItems ?? []
        var query: [String: [String]] = [:]
        for item in items {
            query[item.name, default: []].append(item.value ?? "")
        }

        func only(_ allowed: Set<String>) -> ParabellumURLError? {
            let unknown = Set(query.keys).subtracting(allowed)
            if let name = unknown.sorted().first {
                return ParabellumURLError("Paramètre inconnu : \(name).")
            }
            for (name, values) in query where name != "path" && values.count > 1 {
                return ParabellumURLError("Paramètre répété : \(name).")
            }
            return nil
        }
        func done(_ action: ParabellumURLAction, params: Set<String> = []) -> Result<ParabellumURLAction, ParabellumURLError> {
            if let e = only(params) {
                return .failure(e)
            }
            return .success(action)
        }

        switch segments {
        case ["scan"]:
            if let e = only(["path"]) {
                return .failure(e)
            }
            let paths = query["path"] ?? []
            if paths.isEmpty {
                return .failure(ParabellumURLError("Indiquez le fichier à analyser : parabellum://scan?path=/chemin/absolu"))
            }
            if paths.count > maxPaths {
                return .failure(ParabellumURLError("Au plus \(maxPaths) chemins par lien."))
            }
            for p in paths {
                if let e = validatePath(p) {
                    return .failure(e)
                }
            }
            return .success(.scan(paths: paths))
        case ["scan", "downloads"]:
            return done(.scanDownloads)
        case ["vpn", "connect"]:
            return done(.vpnConnect)
        case ["vpn", "disconnect"]:
            return done(.vpnDisconnect)
        case ["travel", "on"]:
            return done(.travelOn)
        case ["travel", "off"]:
            return done(.travelOff)
        case ["pause"]:
            if let e = only(["minutes"]) {
                return .failure(e)
            }
            let raw = query["minutes"]?.first ?? "15"
            guard !raw.isEmpty, raw.count <= 5, raw.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let minutes = Int(raw), (1...maxPauseMinutes).contains(minutes) else {
                return .failure(ParabellumURLError("Durée de pause invalide (1 à \(maxPauseMinutes) minutes)."))
            }
            return .success(.pause(minutes: minutes))
        case ["resume"]:
            return done(.resume)
        case ["update"]:
            if let e = only(["target"]) {
                return .failure(e)
            }
            guard let raw = query["target"]?.first else {
                return .success(.update(target: .all))
            }
            guard let target = UpdateTarget(rawValue: raw.lowercased()), target != .unknown else {
                return .failure(ParabellumURLError("Cible de mise à jour inconnue : \(raw) (db, components, app, all)."))
            }
            return .success(.update(target: target))
        case ["open"]:
            return done(.open(section: nil))
        case let s where s.count == 2 && s[0] == "open":
            let section = s[1]
            guard (1...32).contains(section.count), section.allSatisfy({ $0.isASCII && $0.isLetter }) else {
                return .failure(ParabellumURLError("Section inconnue : \(section)."))
            }
            return done(.open(section: section))
        default:
            let shown = segments.joined(separator: "/")
            return .failure(ParabellumURLError("Action inconnue : \(shown.isEmpty ? "(vide)" : shown)."))
        }
    }

    /// Absolute, normalized, printable path (no `..`, `.`, `//`, NUL or control characters).
    static func validatePath(_ p: String) -> ParabellumURLError? {
        guard p.hasPrefix("/"), p.utf8.count <= maxPathLength else {
            return ParabellumURLError("Chemin absolu requis : \(p.prefix(200))")
        }
        if p.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) {
            return ParabellumURLError("Chemin invalide (caractère de contrôle).")
        }
        let parts = p.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        if p != "/" && parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) {
            return ParabellumURLError("Chemin non normalisé refusé : \(p.prefix(200))")
        }
        return nil
    }

    /// Example links, for the "Raccourcis" settings section.
    public static let examples: [(title: String, url: String)] = [
        ("Analyser les téléchargements", "parabellum://scan/downloads"),
        ("Analyser un fichier", "parabellum://scan?path=/Users/moi/Downloads/fichier.dmg"),
        ("Connecter le VPN", "parabellum://vpn/connect"),
        ("Déconnecter le VPN", "parabellum://vpn/disconnect"),
        ("Activer le mode Voyage", "parabellum://travel/on"),
        ("Désactiver le mode Voyage", "parabellum://travel/off"),
        ("Pause de 15 minutes", "parabellum://pause?minutes=15"),
        ("Reprendre la protection", "parabellum://resume"),
        ("Tout mettre à jour", "parabellum://update"),
        ("Ouvrir les alertes", "parabellum://open/alerts"),
    ]
}
