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
    /// `parabellum://clean?path=…` (repeatable): copies without metadata next to the files.
    case cleanMetadata(paths: [String])
    /// `parabellum://encrypt?path=/folder-or-file`: opens the « Chiffrer » window (nothing happens without it).
    case encrypt(path: String)
    /// `parabellum://shred?path=…` (repeatable): opens the « Supprimer définitivement » confirmation.
    case shred(paths: [String])
    /// `parabellum://coffre/open?path=/x.coffre`
    case openCoffre(path: String)
    /// `parabellum://coffre/lock?path=/x.coffre`
    case lockCoffre(path: String)
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
            return .failure(ParabellumURLError(String(localized: "Ce lien n'est pas un lien parabellum://.")))
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
                return ParabellumURLError(String(localized: "Paramètre inconnu : \(name)."))
            }
            for (name, values) in query where name != "path" && values.count > 1 {
                return ParabellumURLError(String(localized: "Paramètre répété : \(name)."))
            }
            return nil
        }
        func done(_ action: ParabellumURLAction, params: Set<String> = []) -> Result<ParabellumURLAction, ParabellumURLError> {
            if let e = only(params) {
                return .failure(e)
            }
            return .success(action)
        }

        /// `path` parameters (1…maxPaths, absolute, validated).
        func pathList(_ hint: String) -> Result<[String], ParabellumURLError> {
            if let e = only(["path"]) {
                return .failure(e)
            }
            let paths = query["path"] ?? []
            if paths.isEmpty {
                return .failure(ParabellumURLError(hint))
            }
            if paths.count > maxPaths {
                return .failure(ParabellumURLError(String(localized: "Au plus \(maxPaths) chemins par lien.")))
            }
            for p in paths {
                if let e = validatePath(p) {
                    return .failure(e)
                }
            }
            return .success(paths)
        }
        func singlePath(_ hint: String) -> Result<String, ParabellumURLError> {
            pathList(hint).flatMap { paths in
                paths.count == 1 ? .success(paths[0]) : .failure(ParabellumURLError(String(localized: "Un seul chemin pour cette action.")))
            }
        }

        switch segments {
        case ["clean"]:
            return pathList(String(localized: "Indiquez les fichiers : parabellum://clean?path=/chemin/absolu")).map { .cleanMetadata(paths: $0) }
        case ["encrypt"]:
            return singlePath(String(localized: "Indiquez le dossier ou le fichier : parabellum://encrypt?path=/chemin/absolu")).map { .encrypt(path: $0) }
        case ["shred"]:
            return pathList(String(localized: "Indiquez les éléments : parabellum://shred?path=/chemin/absolu")).map { .shred(paths: $0) }
        case ["coffre", "open"]:
            return singlePath(String(localized: "Indiquez le dossier chiffré : parabellum://coffre/open?path=/x.coffre")).map { .openCoffre(path: $0) }
        case ["coffre", "lock"]:
            return singlePath(String(localized: "Indiquez le dossier chiffré : parabellum://coffre/lock?path=/x.coffre")).map { .lockCoffre(path: $0) }
        case ["scan"]:
            if let e = only(["path"]) {
                return .failure(e)
            }
            let paths = query["path"] ?? []
            if paths.isEmpty {
                return .failure(ParabellumURLError(String(localized: "Indiquez le fichier à analyser : parabellum://scan?path=/chemin/absolu")))
            }
            if paths.count > maxPaths {
                return .failure(ParabellumURLError(String(localized: "Au plus \(maxPaths) chemins par lien.")))
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
                return .failure(ParabellumURLError(String(localized: "Durée de pause invalide (1 à \(maxPauseMinutes) minutes).")))
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
                return .failure(ParabellumURLError(String(localized: "Cible de mise à jour inconnue : \(raw) (db, components, app, all).")))
            }
            return .success(.update(target: target))
        case ["open"]:
            return done(.open(section: nil))
        case let s where s.count == 2 && s[0] == "open":
            let section = s[1]
            guard (1...32).contains(section.count), section.allSatisfy({ $0.isASCII && $0.isLetter }) else {
                return .failure(ParabellumURLError(String(localized: "Section inconnue : \(section).")))
            }
            return done(.open(section: section))
        default:
            let shown = segments.joined(separator: "/")
            let shownOrEmpty = shown.isEmpty ? String(localized: "(vide)") : shown
            return .failure(ParabellumURLError(String(localized: "Action inconnue : \(shownOrEmpty).")))
        }
    }

    /// Absolute, normalized, printable path (no `..`, `.`, `//`, NUL or control characters).
    static func validatePath(_ p: String) -> ParabellumURLError? {
        guard p.hasPrefix("/"), p.utf8.count <= maxPathLength else {
            return ParabellumURLError(String(localized: "Chemin absolu requis : \(String(p.prefix(200)))"))
        }
        if p.unicodeScalars.contains(where: { $0.properties.generalCategory == .control }) {
            return ParabellumURLError(String(localized: "Chemin invalide (caractère de contrôle)."))
        }
        let parts = p.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        if p != "/" && parts.contains(where: { $0.isEmpty || $0 == "." || $0 == ".." }) {
            return ParabellumURLError(String(localized: "Chemin non normalisé refusé : \(String(p.prefix(200)))"))
        }
        return nil
    }

    /// Example links, for the "Raccourcis" settings section.
    public static let examples: [(title: String, url: String)] = [
        (String(localized: "Analyser les téléchargements"), "parabellum://scan/downloads"),
        (String(localized: "Analyser un fichier"), "parabellum://scan?path=/Users/moi/Downloads/fichier.dmg"),
        (String(localized: "Connecter le VPN"), "parabellum://vpn/connect"),
        (String(localized: "Déconnecter le VPN"), "parabellum://vpn/disconnect"),
        (String(localized: "Activer le mode Voyage"), "parabellum://travel/on"),
        (String(localized: "Désactiver le mode Voyage"), "parabellum://travel/off"),
        ("Pause de 15 minutes", "parabellum://pause?minutes=15"),
        (String(localized: "Reprendre la protection"), "parabellum://resume"),
        (String(localized: "Tout mettre à jour"), "parabellum://update"),
        (String(localized: "Ouvrir les alertes"), "parabellum://open/alerts"),
    ]
}

// MARK: - URL action security policy (v2-new review #1)

/// How the app must run a `parabellum://` action. Any process (malware, a web page via the browser) can
/// open a link, so a link never benefits from an administrator authorization obtained earlier for an
/// in-app action: protection-lowering actions show an in-app confirmation naming the action, then ask for
/// a fresh authorization; and an `auth_required` answer (e.g. a scan of a protected folder) is never
/// retried with a prompt — the user gets a banner instead.
public struct URLActionPolicy: Equatable, Sendable {
    /// Show an in-app confirmation (naming the action) before doing anything.
    public let requiresConfirmation: Bool
    /// Drop the cached administrator authorization first, so the system prompt always appears.
    public let freshAuthorization: Bool
    /// Retry an `auth_required` answer with an administrator prompt. Always false for links.
    public let retryOnAuthRequired: Bool
    /// French title of the confirmation ("Couper le VPN ?").
    public let confirmationTitle: String?
}

extension ParabellumURLAction {
    /// The daemon request that lowers protection, if the action sends one (`nil` otherwise).
    public var protectionLoweringRequest: Request? {
        switch self {
        case .vpnDisconnect: return .vpnDisconnect
        case .travelOff: return .travelDisable
        case .pause(let minutes): return .setProtection(pausedMinutes: minutes)
        // The Finder actions never act on a link alone: each opens its own window (encrypt, shred) or
        // only creates copies (clean) / opens or locks an encrypted folder.
        case .scan, .scanDownloads, .vpnConnect, .travelOn, .resume, .update, .open,
             .cleanMetadata, .encrypt, .shred, .openCoffre, .lockCoffre: return nil
        }
    }

    public var policy: URLActionPolicy {
        let lowering = protectionLoweringRequest?.requiresAdmin ?? false
        return URLActionPolicy(
            requiresConfirmation: lowering,
            freshAuthorization: lowering,
            retryOnAuthRequired: false,
            confirmationTitle: lowering ? confirmationTitle : nil
        )
    }

    private var confirmationTitle: String {
        switch self {
        case .vpnDisconnect: return String(localized: "Un lien demande de couper le VPN.")
        case .travelOff: return String(localized: "Un lien demande de désactiver le mode Voyage.")
        case .pause(let minutes): return String(localized: "Un lien demande de mettre la protection en pause pendant \(Self.duration(minutes)).")
        default: return String(localized: "Un lien demande de réduire la protection.")
        }
    }

    static func duration(_ minutes: Int) -> String {
        if minutes < 60 { return "\(minutes) min" }
        if minutes % (24 * 60) == 0 { return "\(minutes / (24 * 60)) j" }
        if minutes % 60 == 0 { return "\(minutes / 60) h" }
        return "\(minutes / 60) h \(minutes % 60) min"
    }
}
