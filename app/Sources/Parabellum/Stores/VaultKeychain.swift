import Foundation
import LocalAuthentication
import Security

/// The vault passphrase in the user's keychain, released only after Touch ID / the session password.
///
/// Two storages, tried in this order:
/// 1. Data protection keychain with `SecAccessControl(.userPresence)`: the keychain itself refuses to
///    release the item without biometry or the password. It needs a `keychain-access-groups` /
///    application-identifier entitlement, which macOS only accepts with a provisioning profile (paid or
///    personal Apple developer team): the self-signed / ad-hoc build gets `errSecMissingEntitlement`.
/// 2. Login keychain (file-based, no access group, never synced to iCloud): its ACL trusts only this
///    app's code signature (other apps trigger a keychain password prompt), and the app asks for Touch
///    ID / the password with LocalAuthentication before reading it. With the stable "Parabellum Local
///    Signing" certificate the ACL survives updates; ad-hoc builds re-prompt after each update.
enum VaultKeychain {
    static let service = "com.wldeus.parabellum.vault"
    static let account = "Coffre"
    private static let label = "Parabellum — mot de passe du coffre"

    enum Backend: String {
        /// Enforced by the keychain (data protection keychain + access control).
        case dataProtection
        /// Login keychain, user presence checked by the app.
        case login

        var label: String {
            switch self {
            case .dataProtection: return "Trousseau protégé (Touch ID exigé par macOS)"
            case .login: return "Trousseau de session (Touch ID demandé par Parabellum)"
            }
        }
    }

    enum Failure: Error, LocalizedError, Equatable {
        case cancelled
        case notFound
        case status(OSStatus)
        case authentication(String)

        var errorDescription: String? {
            switch self {
            case .cancelled:
                return "Déverrouillage annulé."
            case .notFound:
                return "Mot de passe du coffre absent du trousseau : saisissez-le (ou la clé de récupération)."
            case .status(let status):
                let message = SecCopyErrorMessageString(status, nil) as String? ?? "code \(status)"
                return "Trousseau : \(message)"
            case .authentication(let message):
                return message
            }
        }
    }

    // MARK: - Write

    /// Stores (replaces) the passphrase; returns where it went.
    @discardableResult
    static func save(_ password: String) throws -> Backend {
        delete()
        let data = Data(password.utf8)
        var error: Unmanaged<CFError>?
        if let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .userPresence,
            &error
        ) {
            var query = baseQuery(dataProtection: true)
            query[kSecAttrAccessControl as String] = access
            query[kSecAttrLabel as String] = label
            query[kSecValueData as String] = data
            if SecItemAdd(query as CFDictionary, nil) == errSecSuccess {
                return .dataProtection
            }
            // errSecMissingEntitlement (-34018) on self-signed builds: fall through to the login keychain.
        } else {
            error?.release()
        }
        var query = baseQuery(dataProtection: false)
        query[kSecAttrLabel as String] = label
        query[kSecAttrDescription as String] = "mot de passe du coffre"
        query[kSecValueData as String] = data
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw Failure.status(status)
        }
        return .login
    }

    /// Deletes the passphrase from both keychains (crypto-shred of the vault key copy).
    static func delete() {
        for dataProtection in [true, false] {
            SecItemDelete(baseQuery(dataProtection: dataProtection) as CFDictionary)
        }
    }

    // MARK: - Read

    /// Asks for Touch ID / the session password, then reads the passphrase.
    static func read(reason: String) async throws -> String {
        let context = LAContext()
        context.localizedCancelTitle = "Annuler"
        do {
            _ = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel, .userFallback:
                throw Failure.cancelled
            default:
                throw Failure.authentication("Authentification impossible : \(error.localizedDescription)")
            }
        }
        // Data protection item: the evaluated context satisfies its access control (no second prompt).
        if let password = try copy(dataProtection: true, context: context) {
            return password
        }
        if let password = try copy(dataProtection: false, context: nil) {
            return password
        }
        throw Failure.notFound
    }

    /// Where the passphrase is stored, without reading it (no prompt).
    static func backend() -> Backend? {
        for dataProtection in [true, false] {
            var query = baseQuery(dataProtection: dataProtection)
            query[kSecReturnAttributes as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            let context = LAContext()
            context.interactionNotAllowed = true
            query[kSecUseAuthenticationContext as String] = context
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            // An item protected by access control answers "interaction not allowed": it exists.
            if status == errSecSuccess || status == errSecInteractionNotAllowed {
                return dataProtection ? .dataProtection : .login
            }
        }
        return nil
    }

    private static func copy(dataProtection: Bool, context: LAContext?) throws -> String? {
        var query = baseQuery(dataProtection: dataProtection)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, let password = String(data: data, encoding: .utf8) else {
                throw Failure.status(errSecDecode)
            }
            return password
        case errSecItemNotFound, errSecMissingEntitlement:
            return nil
        case errSecUserCanceled:
            throw Failure.cancelled
        default:
            throw Failure.status(status)
        }
    }

    private static func baseQuery(dataProtection: Bool) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: false,
            kSecUseDataProtectionKeychain as String: dataProtection,
        ]
    }
}
