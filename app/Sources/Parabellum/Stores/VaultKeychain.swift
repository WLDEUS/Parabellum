import Darwin
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
///    The login keychain is opened by its path (from the user database, not `$HOME`) and every add /
///    read / delete names it: `security default-keychain` / `list-keychains` are user settings any
///    process can change without a prompt, so relying on the default keychain would let malware hide the
///    real item and receive the password re-typed by the user in a keychain it controls (audit APP-2).
enum VaultKeychain {
    static let service = "com.wldeus.parabellum.vault"
    static let account = "Coffre"
    private static let label = String(localized: "Parabellum — mot de passe du coffre")

    enum Backend: String {
        /// Enforced by the keychain (data protection keychain + access control).
        case dataProtection
        /// Login keychain, user presence checked by the app.
        case login

        var label: String {
            switch self {
            case .dataProtection: return String(localized: "Trousseau protégé (Touch ID exigé par macOS)")
            case .login: return String(localized: "Trousseau de session (Touch ID demandé par Parabellum)")
            }
        }
    }

    enum Failure: Error, LocalizedError, Equatable {
        case cancelled
        case notFound
        case status(OSStatus)
        case authentication(String)
        /// The login keychain could not be opened at its expected place.
        case loginKeychainUnavailable(String)
        /// The stored password belongs to another vault image than the one configured now.
        case otherVault(String)

        var isOtherVault: Bool {
            if case .otherVault = self { return true }
            return false
        }

        var errorDescription: String? {
            switch self {
            case .cancelled:
                return String(localized: "Déverrouillage annulé.")
            case .notFound:
                return String(localized: "Mot de passe du coffre absent du trousseau : saisissez-le (ou la clé de récupération).")
            case .status(let status):
                let message = SecCopyErrorMessageString(status, nil) as String? ?? String(localized: "code \(Int(status))")
                return String(localized: "Trousseau : \(message)")
            case .authentication(let message):
                return message
            case .otherVault(let path):
                return String(localized: "Le mot de passe enregistré appartient à un autre coffre que « \(path) ». Vérifiez l'emplacement du coffre, puis saisissez le mot de passe de ce coffre.")
            case .loginKeychainUnavailable(let detail):
                return String(localized: "Trousseau de session introuvable ou modifié (\(detail)) : le mot de passe n'est pas enregistré.")
            }
        }
    }

    // MARK: - Write


    /// Stores (replaces) the passphrase, bound to the vault image it opens (`binding`: the configured
    /// bundle path, "" for the default one); returns where it went. `vault.bundlePath` lives in
    /// UserDefaults, which any process of the user can rewrite: the binding keeps Touch ID from silently
    /// opening (and the app from writing into) an image someone else put there (audit APP-5).
    @discardableResult
    static func save(_ password: String, binding: String) throws -> Backend {
        delete()
        let data = Data(password.utf8)
        let bound = Data((bindingPrefix + binding).utf8)
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
            query[kSecAttrGeneric as String] = bound
            query[kSecValueData as String] = data
            if SecItemAdd(query as CFDictionary, nil) == errSecSuccess {
                return .dataProtection
            }
            // errSecMissingEntitlement (-34018) on self-signed builds: fall through to the login keychain.
        } else {
            error?.release()
        }
        var query = baseQuery(dataProtection: false)
        query[kSecUseKeychain as String] = try loginKeychain()
        query[kSecAttrLabel as String] = label
        query[kSecAttrDescription as String] = String(localized: "mot de passe du coffre")
        query[kSecAttrGeneric as String] = bound
        query[kSecValueData as String] = data
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw Failure.status(status)
        }
        return .login
    }

    /// Deletes the passphrase from both keychains (crypto-shred of the vault key copy).
    static func delete() {
        SecItemDelete(baseQuery(dataProtection: true) as CFDictionary)
        if let query = try? loginQuery() {
            SecItemDelete(query as CFDictionary)
        }
    }

    // MARK: - Read

    /// Asks for Touch ID / the session password, then reads the passphrase. `binding`: the vault image
    /// configured now; a password saved for another one throws `.otherVault` (items saved before the
    /// binding existed are accepted once and re-bound by the caller's next save).
    static func read(reason: String, binding: String) async throws -> Stored {
        let context = LAContext()
        context.localizedCancelTitle = "Annuler"
        do {
            _ = try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel, .userFallback:
                throw Failure.cancelled
            default:
                throw Failure.authentication(String(localized: "Authentification impossible : \(error.localizedDescription)"))
            }
        }
        // Data protection item: the evaluated context satisfies its access control (no second prompt).
        let found = try copy(dataProtection: true, context: context) ?? copy(dataProtection: false, context: nil)
        guard let found else {
            throw Failure.notFound
        }
        if let bound = found.1, bound != binding {
            throw Failure.otherVault(binding.isEmpty ? String(localized: "emplacement par défaut") : binding)
        }
        return Stored(password: found.0, unbound: found.1 == nil)
    }

    struct Stored {
        let password: String
        /// Saved before bindings existed: the caller re-saves it bound to the current vault.
        let unbound: Bool
    }

    private static let bindingPrefix = "bundle:"

    /// The binding stored with an item, nil for items saved before bindings existed.
    static func decodeBinding(_ data: Data?) -> String? {
        guard let data, let text = String(data: data, encoding: .utf8), text.hasPrefix(bindingPrefix) else {
            return nil
        }
        return String(text.dropFirst(bindingPrefix.count))
    }

    /// Where the passphrase is stored, without reading it (no prompt).
    static func backend() -> Backend? {
        for dataProtection in [true, false] {
            var query: [String: Any]
            if dataProtection {
                query = baseQuery(dataProtection: true)
            } else if let login = try? loginQuery() {
                query = login
            } else {
                continue
            }
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

    private static func copy(dataProtection: Bool, context: LAContext?) throws -> (String, String?)? {
        var query: [String: Any]
        if dataProtection {
            query = baseQuery(dataProtection: true)
        } else {
            query = try loginQuery()
        }
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        if let context {
            query[kSecUseAuthenticationContext as String] = context
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let item = result as? [String: Any],
                  let data = item[kSecValueData as String] as? Data,
                  let password = String(data: data, encoding: .utf8) else {
                throw Failure.status(errSecDecode)
            }
            return (password, decodeBinding(item[kSecAttrGeneric as String] as? Data))
        case errSecItemNotFound, errSecMissingEntitlement:
            return nil
        case errSecUserCanceled:
            throw Failure.cancelled
        default:
            throw Failure.status(status)
        }
    }

    /// Login-keychain query restricted to the real login keychain (never the default / search list).
    private static func loginQuery() throws -> [String: Any] {
        var query = baseQuery(dataProtection: false)
        query[kSecMatchSearchList as String] = [try loginKeychain()] as CFArray
        return query
    }

    /// `~/Library/Keychains/login.keychain-db` of the current user, home taken from the user database
    /// (an environment variable can be changed by any process that relaunches the app). Refused when it
    /// is missing or a symbolic link.
    static func loginKeychain() throws -> SecKeychain {
        guard let path = loginKeychainPath() else {
            throw Failure.loginKeychainUnavailable(String(localized: "dossier personnel inconnu"))
        }
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == getuid() else {
            throw Failure.loginKeychainUnavailable(path)
        }
        var keychain: SecKeychain?
        let status = SecKeychainOpen(path, &keychain)
        guard status == errSecSuccess, let keychain else {
            throw Failure.status(status)
        }
        return keychain
    }

    static func loginKeychainPath() -> String? {
        guard let pw = getpwuid(getuid()), let dir = pw.pointee.pw_dir else { return nil }
        let home = String(cString: dir)
        guard home.hasPrefix("/") else { return nil }
        return (home as NSString).appendingPathComponent("Library/Keychains/login.keychain-db")
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
