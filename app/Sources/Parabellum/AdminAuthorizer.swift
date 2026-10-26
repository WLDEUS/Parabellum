import Foundation
import ParabellumKit
import Security

enum AdminAuthorizationError: Error, Equatable, LocalizedError {
    /// The user closed the password / Touch ID prompt.
    case cancelled
    /// Wrong credentials or not an administrator.
    case denied
    case failed(OSStatus)

    var errorDescription: String? {
        switch self {
        case .cancelled:
            return "Action annulée : autorisation administrateur non accordée."
        case .denied:
            return "Autorisation administrateur refusée."
        case .failed(let status):
            return "Impossible d'obtenir l'autorisation administrateur (erreur \(status))."
        }
    }
}

/// Obtains administrator approval for `DaemonProtocol.adminRight` (password / Touch ID prompt drawn by
/// SecurityAgent, which synthetic input cannot drive) and hands out its `AuthorizationExternalForm`
/// (base64) for the `auth` field of `Request.requiresAdmin` commands.
///
/// The `AuthorizationRef` is kept ~5 minutes and reused: the right is not shared, so the daemon still
/// re-checks it on every request. All Security calls run on one serial queue (the prompt blocks).
final class AdminAuthorizer: @unchecked Sendable {
    static let defaultPrompt = "Parabellum a besoin de votre autorisation pour réduire la protection."
    /// How long an obtained authorization is reused before asking again.
    let lifetime: TimeInterval

    private let queue = DispatchQueue(label: "com.wldeus.parabellum.authorization", qos: .userInitiated)
    // Only touched on `queue`.
    private var authorizationRef: AuthorizationRef?
    private var externalForm: String?
    private var obtainedAt: Date?

    init(lifetime: TimeInterval = 300) {
        self.lifetime = lifetime
    }

    deinit {
        if let authorizationRef {
            _ = AuthorizationFree(authorizationRef, [.destroyRights])
        }
    }

    /// Base64 external form of an authorization holding the admin right. May show the system prompt.
    func authorization(prompt: String = AdminAuthorizer.defaultPrompt) async throws -> String {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
            queue.async {
                do {
                    continuation.resume(returning: try self.obtain(prompt: prompt))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Forget the cached authorization (the daemon rejected it, e.g. expired): the next call prompts again.
    func invalidate() {
        queue.async {
            self.reset()
        }
    }

    // MARK: - On `queue`

    private func obtain(prompt: String) throws -> String {
        if let externalForm, let obtainedAt, authorizationRef != nil, Date().timeIntervalSince(obtainedAt) < lifetime {
            return externalForm
        }
        reset()

        var created: AuthorizationRef?
        let createStatus = AuthorizationCreate(nil, nil, [], &created)
        guard createStatus == 0, let reference = created else {
            throw AdminAuthorizationError.failed(createStatus)
        }

        let copyStatus = Self.copyAdminRight(reference, prompt: prompt)
        guard copyStatus == 0 else {
            _ = AuthorizationFree(reference, [.destroyRights])
            if Int(copyStatus) == Int(errAuthorizationCanceled) {
                throw AdminAuthorizationError.cancelled
            }
            if Int(copyStatus) == Int(errAuthorizationDenied) {
                throw AdminAuthorizationError.denied
            }
            throw AdminAuthorizationError.failed(copyStatus)
        }

        var form = AuthorizationExternalForm()
        let formStatus = AuthorizationMakeExternalForm(reference, &form)
        guard formStatus == 0 else {
            _ = AuthorizationFree(reference, [.destroyRights])
            throw AdminAuthorizationError.failed(formStatus)
        }
        // 32 bytes (kAuthorizationExternalFormLength).
        let encoded = withUnsafeBytes(of: form) { Data($0) }.base64EncodedString()

        authorizationRef = reference
        externalForm = encoded
        obtainedAt = Date()
        return encoded
    }

    /// `AuthorizationCopyRights` for the admin right with a French prompt (blocks until the user answers).
    private static func copyAdminRight(_ reference: AuthorizationRef, prompt: String) -> OSStatus {
        DaemonProtocol.adminRight.withCString { rightName -> OSStatus in
            kAuthorizationEnvironmentPrompt.withCString { promptKey -> OSStatus in
                prompt.withCString { promptText -> OSStatus in
                    var rightItem = AuthorizationItem(name: rightName, valueLength: 0, value: nil, flags: 0)
                    var promptItem = AuthorizationItem(
                        name: promptKey,
                        valueLength: strlen(promptText),
                        value: UnsafeMutableRawPointer(mutating: UnsafeRawPointer(promptText)),
                        flags: 0
                    )
                    return withUnsafeMutablePointer(to: &rightItem) { rightPointer -> OSStatus in
                        withUnsafeMutablePointer(to: &promptItem) { promptPointer -> OSStatus in
                            var rights = AuthorizationRights(count: 1, items: rightPointer)
                            var environment = AuthorizationEnvironment(count: 1, items: promptPointer)
                            let flags: AuthorizationFlags = [.interactionAllowed, .extendRights, .preAuthorize]
                            return AuthorizationCopyRights(reference, &rights, &environment, flags, nil)
                        }
                    }
                }
            }
        }
    }

    private func reset() {
        if let authorizationRef {
            _ = AuthorizationFree(authorizationRef, [.destroyRights])
        }
        authorizationRef = nil
        externalForm = nil
        obtainedAt = nil
    }
}

extension Request {
    /// French end of "Parabellum a besoin de votre autorisation pour …" shown in the system prompt.
    var adminPromptReason: String {
        switch self {
        case .restore: return "restaurer un fichier mis en quarantaine"
        case .deleteQuarantined: return "supprimer définitivement un fichier en quarantaine"
        case .reportFalsePositive: return "autoriser un fichier signalé comme faux positif"
        case .setConfig: return "modifier les réglages de protection"
        case .getConfig: return "afficher les secrets des réglages"
        case .quarantinePath: return "mettre un fichier en quarantaine"
        case .setPersistenceStatus: return "modifier un élément de persistance"
        case .setDns: return "désactiver le blocage DNS"
        case .setProtection: return "mettre la protection en pause"
        case .setDeviceTrust: return "faire confiance à un périphérique"
        case .setComponentAutoUpdate: return "désactiver la mise à jour automatique d'un composant"
        case .resolveAlert: return "appliquer cette action sur l'alerte"
        default: return "réduire la protection"
        }
    }

    var adminPrompt: String {
        "Parabellum a besoin de votre autorisation pour \(adminPromptReason)."
    }
}
