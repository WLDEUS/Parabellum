import Foundation
import Security

// Coffre & effacement sûr: models mirroring `parabellum vault … --json` (crates/pb-cli/src/vault) and the
// CLI calls. Everything runs as the user; passphrases are written to the CLI's stdin, never in argv/env.

// MARK: - Models

/// `fdesetup status`.
public enum FileVaultState: String, TolerantEnum {
    case on, off, encrypting, decrypting
    case unknown
    public static let fallback: FileVaultState = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

/// A recently modified file of the open vault.
public struct VaultItem: Codable, Sendable, Hashable, Identifiable {
    public let name: String
    public let path: String
    public let size: Int
    /// Unix seconds.
    public let modified: Int64

    public var id: String { path }
    public var modifiedDate: Date { Date(timeIntervalSince1970: TimeInterval(modified)) }

    enum CodingKeys: String, CodingKey {
        case name, path, size, modified
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decodeOr(.name, "")
        path = try c.decode(String.self, forKey: .path)
        size = try c.decodeOr(.size, 0)
        modified = try c.decodeOr(.modified, Int64(0))
    }
}

/// `parabellum vault status --json` (returned by every vault action).
public struct VaultStatus: Codable, Sendable, Hashable {
    public let bundlePath: String
    public let exists: Bool
    public let encrypted: Bool
    public let mounted: Bool
    public let mountPoint: String?
    public let device: String?
    public let capacityBytes: Int?
    public let allocatedBytes: Int?
    public let volumeTotalBytes: Int?
    public let volumeFreeBytes: Int?
    public let filevault: FileVaultState
    public let syncWarning: String?
    public let recent: [VaultItem]

    /// Bytes stored in the open vault.
    public var usedBytes: Int? {
        guard let total = volumeTotalBytes, let free = volumeFreeBytes else { return nil }
        return max(0, total - free)
    }

    /// 0…1 fill of the open vault (nil when locked).
    public var fillRatio: Double? {
        guard let used = usedBytes, let total = volumeTotalBytes, total > 0 else { return nil }
        return min(1, Double(used) / Double(total))
    }

    enum CodingKeys: String, CodingKey {
        case bundlePath = "bundle_path"
        case exists, encrypted, mounted
        case mountPoint = "mount_point"
        case device
        case capacityBytes = "capacity_bytes"
        case allocatedBytes = "allocated_bytes"
        case volumeTotalBytes = "volume_total_bytes"
        case volumeFreeBytes = "volume_free_bytes"
        case filevault
        case syncWarning = "sync_warning"
        case recent
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        bundlePath = try c.decodeOr(.bundlePath, "")
        exists = try c.decodeOr(.exists, false)
        encrypted = try c.decodeOr(.encrypted, false)
        mounted = try c.decodeOr(.mounted, false)
        mountPoint = try c.decodeIfPresent(String.self, forKey: .mountPoint)
        device = try c.decodeIfPresent(String.self, forKey: .device)
        capacityBytes = try c.decodeIfPresent(Int.self, forKey: .capacityBytes)
        allocatedBytes = try c.decodeIfPresent(Int.self, forKey: .allocatedBytes)
        volumeTotalBytes = try c.decodeIfPresent(Int.self, forKey: .volumeTotalBytes)
        volumeFreeBytes = try c.decodeIfPresent(Int.self, forKey: .volumeFreeBytes)
        filevault = try c.decodeOr(.filevault, FileVaultState.unknown)
        syncWarning = try c.decodeIfPresent(String.self, forKey: .syncWarning)
        recent = try c.decodeOr(.recent, [VaultItem]())
    }
}

/// A process keeping files of the vault open.
public struct VaultHolder: Codable, Sendable, Hashable, Identifiable {
    public let pid: Int32
    public let command: String
    public let paths: [String]

    public var id: Int32 { pid }

    enum CodingKeys: String, CodingKey {
        case pid, command, paths
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        pid = try c.decode(Int32.self, forKey: .pid)
        command = try c.decodeOr(.command, "")
        paths = try c.decodeOr(.paths, [String]())
    }
}

/// `{"error": {"code", "message", "holders"?}}` printed by the CLI on failure.
public struct VaultCLIError: Error, LocalizedError, Codable, Sendable, Hashable {
    public let code: String
    public let message: String
    public let holders: [VaultHolder]

    public var isBusy: Bool { code == "busy" }
    public var isBadPassword: Bool { code == "bad_password" }
    public var isNotFound: Bool { code == "not_found" }

    public var errorDescription: String? {
        guard let first = message.first else { return "Erreur du coffre" }
        return first.uppercased() + message.dropFirst()
    }

    enum CodingKeys: String, CodingKey {
        case code, message, holders
    }

    public init(code: String, message: String, holders: [VaultHolder] = []) {
        self.code = code
        self.message = message
        self.holders = holders
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        code = try c.decode(String.self, forKey: .code)
        message = try c.decodeOr(.message, "")
        holders = try c.decodeOr(.holders, [VaultHolder]())
    }
}

private struct VaultErrorEnvelope: Decodable {
    let error: VaultCLIError
}

/// Where a secure-delete target is.
public enum ShredZone: String, TolerantEnum {
    /// Inside the open vault: plain deletion.
    case vault
    case home
    case external
    case unknown
    public static let fallback: ShredZone = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum ShredOutcome: String, TolerantEnum {
    case deleted, planned, refused, failed
    case unknown
    public static let fallback: ShredOutcome = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

/// One item of `parabellum vault shred|empty-trash --json`.
public struct ShredReport: Codable, Sendable, Hashable, Identifiable {
    public let path: String
    public let outcome: ShredOutcome
    public let zone: ShredZone?
    public let files: Int
    public let dirs: Int
    public let bytes: Int
    public let overwrittenBytes: Int
    public let notOverwritten: Int
    public let warnings: [String]
    public let error: String?

    public var id: String { path }
    public var name: String { (path as NSString).lastPathComponent }
    public var isActionable: Bool { outcome == .planned || outcome == .deleted }

    enum CodingKeys: String, CodingKey {
        case path, outcome, zone, files, dirs, bytes
        case overwrittenBytes = "overwritten_bytes"
        case notOverwritten = "not_overwritten"
        case warnings, error
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = try c.decode(String.self, forKey: .path)
        outcome = try c.decodeOr(.outcome, ShredOutcome.unknown)
        zone = try c.decodeIfPresent(ShredZone.self, forKey: .zone)
        files = try c.decodeOr(.files, 0)
        dirs = try c.decodeOr(.dirs, 0)
        bytes = try c.decodeOr(.bytes, 0)
        overwrittenBytes = try c.decodeOr(.overwrittenBytes, 0)
        notOverwritten = try c.decodeOr(.notOverwritten, 0)
        warnings = try c.decodeOr(.warnings, [String]())
        error = try c.decodeIfPresent(String.self, forKey: .error)
    }
}

// MARK: - Recovery key

/// Generated vault passphrase, shown once as the recovery key: 32 Crockford base32 characters
/// (160 bits) in groups of 4, e.g. `7KQ2-…`. No I, L, O or U, so it reads back without ambiguity.
public enum RecoveryKey {
    public static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    public static let length = 32
    public static let groupSize = 4

    /// New random key (SecRandomCopyBytes; 256 is a multiple of 32, so `byte & 31` is unbiased).
    public static func generate() -> String {
        var bytes = [UInt8](repeating: 0, count: length)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        if status != errSecSuccess {
            // Practically never; fall back to the system CSPRNG behind SystemRandomNumberGenerator.
            var rng = SystemRandomNumberGenerator()
            bytes = (0..<length).map { _ in UInt8.random(in: 0...255, using: &rng) }
        }
        let chars = bytes.map { alphabet[Int($0 & 31)] }
        for index in bytes.indices { bytes[index] = 0 }
        return format(chars)
    }

    static func format(_ chars: [Character]) -> String {
        stride(from: 0, to: chars.count, by: groupSize)
            .map { String(chars[$0..<min($0 + groupSize, chars.count)]) }
            .joined(separator: "-")
    }

    /// What the user typed, in canonical form when it is a recovery key (case, spaces, dashes and the
    /// look-alikes O→0, I/L→1 are forgiven); anything else (a chosen password) is returned unchanged.
    public static func normalize(_ input: String) -> String {
        var chars: [Character] = []
        for ch in input.uppercased() {
            switch ch {
            case " ", "-", "\t", "\n": continue
            case "O": chars.append("0")
            case "I", "L": chars.append("1")
            default: chars.append(ch)
            }
        }
        guard chars.count == length, chars.allSatisfy({ alphabet.contains($0) }) else {
            return input
        }
        return format(chars)
    }

    /// `input` has the shape of a recovery key (after normalization).
    public static func looksLikeKey(_ input: String) -> Bool {
        let key = normalize(input)
        let groups = key.split(separator: "-")
        return groups.count == length / groupSize
            && groups.allSatisfy { $0.count == groupSize && $0.allSatisfy { alphabet.contains($0) } }
    }
}

// MARK: - CLI

/// Location of the vault, passed to every `parabellum vault` call.
public struct VaultLocation: Sendable, Hashable {
    /// `….sparsebundle`; nil = CLI default (~/Library/Application Support/Parabellum/Vault/Coffre.sparsebundle).
    public var bundle: String?
    /// Custom mount point; nil = /Volumes/<name> (visible in the Finder).
    public var mountpoint: String?

    public init(bundle: String? = nil, mountpoint: String? = nil) {
        self.bundle = bundle
        self.mountpoint = mountpoint
    }

    public var arguments: [String] {
        var args = ["vault"]
        if let bundle, !bundle.isEmpty {
            args += ["--bundle", bundle]
        }
        if let mountpoint, !mountpoint.isEmpty {
            args += ["--mountpoint", mountpoint]
        }
        return args
    }
}

/// `parabellum vault …` as the current user.
public enum VaultCLI {
    /// Decodes `T`, or throws the CLI's `VaultCLIError` when it printed one.
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        let decoder = JSONDecoder()
        if let envelope = try? decoder.decode(VaultErrorEnvelope.self, from: data) {
            throw envelope.error
        }
        return try decoder.decode(T.self, from: data)
    }

    /// Password bytes as the CLI reads them: `pass\0`.
    static func stdin(_ passwords: [String]) -> Data {
        var data = Data()
        for password in passwords {
            data.append(Data(password.utf8))
            data.append(0)
        }
        return data
    }

    private static func call<T: Decodable>(
        _ type: T.Type,
        _ location: VaultLocation,
        _ arguments: [String],
        passwords: [String] = [],
        timeout: TimeInterval
    ) async throws -> T {
        var input: Data? = passwords.isEmpty ? nil : stdin(passwords)
        defer {
            // Best effort: wipe our copy of the passphrases.
            let count = input?.count ?? 0
            input?.resetBytes(in: 0..<count)
        }
        let data = try await ParabellumCLI.runJSON(location.arguments + arguments, input: input, timeout: timeout)
        return try decode(T.self, from: data)
    }

    public static func status(_ location: VaultLocation, recent: Int = 8) async throws -> VaultStatus {
        try await call(VaultStatus.self, location, ["status", "--recent", String(recent)], timeout: 30)
    }

    /// `size` in hdiutil syntax (`20g`).
    public static func create(_ location: VaultLocation, size: String, name: String, password: String) async throws -> VaultStatus {
        try await call(VaultStatus.self, location, ["create", "--size", size, "--name", name], passwords: [password], timeout: 300)
    }

    public static func attach(_ location: VaultLocation, password: String) async throws -> VaultStatus {
        try await call(VaultStatus.self, location, ["attach"], passwords: [password], timeout: 120)
    }

    public static func detach(_ location: VaultLocation, force: Bool) async throws -> VaultStatus {
        try await call(VaultStatus.self, location, force ? ["detach", "--force"] : ["detach"], timeout: 90)
    }

    public static func holders(_ location: VaultLocation) async throws -> [VaultHolder] {
        try await call([VaultHolder].self, location, ["holders"], timeout: 30)
    }

    public static func resize(_ location: VaultLocation, size: String, password: String) async throws -> VaultStatus {
        try await call(VaultStatus.self, location, ["resize", "--size", size], passwords: [password], timeout: 900)
    }

    public static func compact(_ location: VaultLocation, password: String) async throws -> VaultStatus {
        try await call(VaultStatus.self, location, ["compact"], passwords: [password], timeout: 1800)
    }

    public static func changePassword(_ location: VaultLocation, old: String, new: String) async throws -> VaultStatus {
        try await call(VaultStatus.self, location, ["chpass"], passwords: [old, new], timeout: 120)
    }

    public static func destroy(_ location: VaultLocation, force: Bool) async throws -> VaultStatus {
        try await call(VaultStatus.self, location, ["destroy", "--yes"] + (force ? ["--force"] : []), timeout: 120)
    }

    public static func shred(_ location: VaultLocation, paths: [String], dryRun: Bool) async throws -> [ShredReport] {
        try await call([ShredReport].self, location, ["shred"] + (dryRun ? ["--dry-run"] : []) + ["--"] + paths, timeout: 3600)
    }

    public static func emptyTrash(_ location: VaultLocation, dryRun: Bool) async throws -> [ShredReport] {
        try await call([ShredReport].self, location, ["empty-trash"] + (dryRun ? ["--dry-run"] : []), timeout: 3600)
    }
}

extension ParabellumCLI {
    /// `parabellum --json <arguments>` with `input` written to its stdin (then closed). Same result rules
    /// as `runJSON(_:timeout:)`: JSON on stdout is returned even with a non-zero exit.
    public static func runJSON(_ arguments: [String], input: Data?, timeout: TimeInterval) async throws -> Data {
        guard FileManager.default.isExecutableFile(atPath: path) else {
            throw Failure.notInstalled
        }
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: path)
                process.arguments = ["--json"] + arguments
                let out = Pipe()
                let err = Pipe()
                process.standardOutput = out
                process.standardError = err
                let inPipe: Pipe? = input == nil ? nil : Pipe()
                if let inPipe {
                    process.standardInput = inPipe
                } else {
                    process.standardInput = FileHandle.nullDevice
                }
                do {
                    try process.run()
                } catch {
                    continuation.resume(throwing: Failure.failed("lancement impossible : \(error.localizedDescription)"))
                    return
                }
                if let inPipe, let input {
                    let handle = inPipe.fileHandleForWriting
                    // Small payload (a passphrase): fits in the pipe buffer, no deadlock.
                    try? handle.write(contentsOf: input)
                    try? handle.close()
                }
                let timer = DispatchWorkItem { if process.isRunning { process.terminate() } }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
                let errBox = VaultDataBox()
                let group = DispatchGroup()
                group.enter()
                let errHandle = err.fileHandleForReading
                DispatchQueue.global().async {
                    errBox.set(errHandle.readDataToEndOfFile())
                    group.leave()
                }
                let outData = out.fileHandleForReading.readDataToEndOfFile()
                group.wait()
                process.waitUntilExit()
                timer.cancel()
                let trimmed = outData.drop { $0 == 0x20 || $0 == 0x0A }
                if process.terminationStatus == 0 || trimmed.first == UInt8(ascii: "[") || trimmed.first == UInt8(ascii: "{") {
                    continuation.resume(returning: outData)
                } else {
                    let message = String(decoding: errBox.get(), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    continuation.resume(throwing: Failure.failed(message.isEmpty ? "échec (code \(process.terminationStatus))" : message))
                }
            }
        }
    }
}

/// Data written by one thread and read by another after a `DispatchGroup.wait()`.
private final class VaultDataBox: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()

    func set(_ value: Data) {
        lock.lock()
        data = value
        lock.unlock()
    }

    func get() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return data
    }
}
