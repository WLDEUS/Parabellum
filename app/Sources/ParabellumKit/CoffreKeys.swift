import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// The ways to open a `.coffre` package (folder encrypted from the Finder) other than its password.
///
/// The disk image inside the package is encrypted by `hdiutil` with the password, which always works
/// (even without Parabellum: « Afficher le contenu du paquet », double-click on the image). `keys.json`,
/// next to the image, holds copies of that password sealed (AES-256-GCM) by:
/// - **Touch ID**: an ECDH key agreement with a P-256 key created *in the Secure Enclave* with a biometric
///   access control (CryptoKit, no keychain entitlement needed). The private key never leaves the chip,
///   only works on this Mac and only after a fingerprint; `keys.json` stores its encrypted handle.
/// - **a key file**: 32 random bytes in a small file you keep elsewhere (USB key…); HKDF-SHA256 of its
///   content seals the password.
/// Deleting a slot (or the key file) removes that way in; the password stays.
public enum CoffreKeys {
    public static let fileName = "keys.json"
    public static let keyFileExtension = "coffrekey"
    static let info = Data("parabellum-coffre-v1".utf8)
    static let keyFileHeader = "PARABELLUM-COFFRE-CLE-1"

    public enum Failure: Error, LocalizedError, Equatable {
        case cancelled
        case unavailable(String)
        case wrongKey
        case invalidKeyFile
        case corrupt

        public var errorDescription: String? {
            switch self {
            case .cancelled: return String(localized: "Déverrouillage annulé.")
            case .unavailable(let message): return message
            case .wrongKey: return String(localized: "Ce fichier clé n'ouvre pas ce dossier chiffré.")
            case .invalidKeyFile: return String(localized: "Ce fichier n'est pas un fichier clé Parabellum.")
            case .corrupt: return String(localized: "Les accès du dossier chiffré sont illisibles : utilisez le mot de passe.")
            }
        }
    }

    // MARK: keys.json

    public struct Slot: Codable, Sendable, Hashable {
        public enum Kind: String, Codable, Sendable {
            case secureEnclave = "secure_enclave"
            case keyFile = "key_file"
        }

        public let kind: Kind
        public let createdAt: Int64
        /// Secure Enclave: the encrypted key handle (`dataRepresentation`), usable only on this Mac.
        public let seKey: Data?
        /// Secure Enclave: the ephemeral public key of the key agreement (X9.63).
        public let ephemeralPublicKey: Data?
        /// Key file: HKDF salt.
        public let salt: Data?
        /// Key file: first bytes of SHA-256(key), to tell key files apart.
        public let keyId: String?
        /// AES-GCM nonce + ciphertext + tag of the password.
        public let sealed: Data

        enum CodingKeys: String, CodingKey {
            case kind, salt, sealed
            case createdAt = "created_at"
            case seKey = "se_key"
            case ephemeralPublicKey = "ephemeral_public_key"
            case keyId = "key_id"
        }
    }

    public struct Keys: Codable, Sendable, Hashable {
        public var version: Int = 1
        public var slots: [Slot] = []

        public init(slots: [Slot] = []) {
            self.slots = slots
        }

        public var hasTouchID: Bool { slots.contains { $0.kind == .secureEnclave } }
        public var hasKeyFile: Bool { slots.contains { $0.kind == .keyFile } }
    }

    public static func load(package: URL) -> Keys {
        guard let data = try? Data(contentsOf: package.appendingPathComponent(fileName)),
              let keys = try? JSONDecoder().decode(Keys.self, from: data) else {
            return Keys()
        }
        return keys
    }

    public static func save(_ keys: Keys, package: URL) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let url = package.appendingPathComponent(fileName)
        try encoder.encode(keys).write(to: url, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    // MARK: Key file

    /// Contents of a new key file (text, so it survives being copied around).
    public static func newKeyFile() -> Data {
        let key = SymmetricKey(size: .bits256)
        let raw = key.withUnsafeBytes { Data($0) }
        return Data("\(keyFileHeader)\n\(raw.base64EncodedString())\n".utf8)
    }

    static func keyMaterial(_ keyFile: Data) throws -> SymmetricKey {
        let text = String(decoding: keyFile.prefix(4096), as: UTF8.self)
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        guard lines.count >= 2, lines[0] == keyFileHeader,
              let raw = Data(base64Encoded: lines[1]), raw.count == 32 else {
            throw Failure.invalidKeyFile
        }
        return SymmetricKey(data: raw)
    }

    static func keyId(_ key: SymmetricKey) -> String {
        let digest = key.withUnsafeBytes { SHA256.hash(data: Data($0)) }
        return digest.prefix(6).map { String(format: "%02x", $0) }.joined()
    }

    public static func keyFileSlot(password: String, keyFile: Data, now: Date = Date()) throws -> Slot {
        let ikm = try keyMaterial(keyFile)
        let salt = SymmetricKey(size: .bits128).withUnsafeBytes { Data($0) }
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: info, outputByteCount: 32)
        guard let sealed = try AES.GCM.seal(Data(password.utf8), using: key).combined else {
            throw Failure.corrupt
        }
        return Slot(kind: .keyFile, createdAt: Int64(now.timeIntervalSince1970), seKey: nil,
                    ephemeralPublicKey: nil, salt: salt, keyId: keyId(ikm), sealed: sealed)
    }

    /// The password, from a key file that matches one of the slots.
    public static func password(from keys: Keys, keyFile: Data) throws -> String {
        let ikm = try keyMaterial(keyFile)
        let id = keyId(ikm)
        for slot in keys.slots where slot.kind == .keyFile && (slot.keyId == nil || slot.keyId == id) {
            guard let salt = slot.salt else { continue }
            let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: ikm, salt: salt, info: info, outputByteCount: 32)
            if let box = try? AES.GCM.SealedBox(combined: slot.sealed),
               let plain = try? AES.GCM.open(box, using: key),
               let password = String(data: plain, encoding: .utf8) {
                return password
            }
        }
        throw Failure.wrongKey
    }

    // MARK: Touch ID (Secure Enclave)

    /// A Secure Enclave and at least one enrolled fingerprint.
    public static var touchIDAvailable: Bool {
        guard SecureEnclave.isAvailable else { return false }
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }

    static func sealingKey(shared: SharedSecret, ephemeral: P256.KeyAgreement.PublicKey, recipient: P256.KeyAgreement.PublicKey) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: ephemeral.x963Representation + recipient.x963Representation,
            sharedInfo: info,
            outputByteCount: 32
        )
    }

    /// Seals the password for this Mac's Secure Enclave. No prompt: only the public half is used.
    public static func touchIDSlot(password: String, now: Date = Date()) throws -> Slot {
        guard touchIDAvailable else {
            throw Failure.unavailable(String(localized: "Touch ID n'est pas disponible sur ce Mac (ou aucune empreinte n'est enregistrée)."))
        }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            // Current set only: a fingerprint added later (by anyone who knows the Mac's login password)
            // invalidates this key instead of opening the folder; the password / key file still work.
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            let message = error?.takeRetainedValue().localizedDescription ?? "SecAccessControl"
            throw Failure.unavailable(message)
        }
        let enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: enclaveKey.publicKey)
        let key = sealingKey(shared: shared, ephemeral: ephemeral.publicKey, recipient: enclaveKey.publicKey)
        guard let sealed = try AES.GCM.seal(Data(password.utf8), using: key).combined else {
            throw Failure.corrupt
        }
        return Slot(kind: .secureEnclave, createdAt: Int64(now.timeIntervalSince1970),
                    seKey: enclaveKey.dataRepresentation,
                    ephemeralPublicKey: ephemeral.publicKey.x963Representation,
                    salt: nil, keyId: nil, sealed: sealed)
    }

    /// Asks for a fingerprint, then unseals the password in the Secure Enclave.
    public static func passwordWithTouchID(from keys: Keys, reason: String) async throws -> String {
        guard let slot = keys.slots.first(where: { $0.kind == .secureEnclave }),
              let handle = slot.seKey, let ephemeralRaw = slot.ephemeralPublicKey else {
            throw Failure.unavailable(String(localized: "Ce dossier chiffré ne s'ouvre pas avec Touch ID sur ce Mac."))
        }
        let context = LAContext()
        context.localizedCancelTitle = String(localized: "Utiliser le mot de passe")
        do {
            _ = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
        } catch let error as LAError {
            switch error.code {
            case .userCancel, .appCancel, .systemCancel, .userFallback:
                throw Failure.cancelled
            default:
                throw Failure.unavailable(error.localizedDescription)
            }
        }
        // The evaluated context satisfies the key's access control: no second prompt.
        let password: String = try await Task.detached(priority: .userInitiated) {
            let enclaveKey: SecureEnclave.P256.KeyAgreement.PrivateKey
            do {
                enclaveKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
                    dataRepresentation: handle,
                    authenticationContext: context
                )
            } catch {
                throw Failure.unavailable(String(localized: "La clé Touch ID de ce dossier chiffré n'existe pas sur ce Mac : utilisez le mot de passe."))
            }
            let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: ephemeralRaw)
            let shared = try enclaveKey.sharedSecretFromKeyAgreement(with: ephemeral)
            let key = sealingKey(shared: shared, ephemeral: ephemeral, recipient: enclaveKey.publicKey)
            guard let box = try? AES.GCM.SealedBox(combined: slot.sealed),
                  let plain = try? AES.GCM.open(box, using: key),
                  let password = String(data: plain, encoding: .utf8) else {
                throw Failure.corrupt
            }
            return password
        }.value
        return password
    }
}
