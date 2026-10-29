import CryptoKit
import Foundation

/// Pwned Passwords range API (k-anonymity): only the first 5 hex characters of the SHA-1 leave the Mac.
public enum PwnedPasswords {
    public static let rangeURL = "https://api.pwnedpasswords.com/range/"

    /// Uppercase hex SHA-1 of the UTF-8 password.
    public static func sha1Hex(_ password: String) -> String {
        Insecure.SHA1.hash(data: Data(password.utf8)).map { String(format: "%02X", $0) }.joined()
    }

    /// Occurrences of `suffix` (35 hex chars) in a range response (`SUFFIX:COUNT` lines; padding lines
    /// have a count of 0).
    public static func count(suffix: String, in response: String) -> Int {
        let wanted = suffix.uppercased()
        for line in response.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":", maxSplits: 1)
            guard parts.count == 2 else { continue }
            if parts[0].trimmingCharacters(in: .whitespaces).uppercased() == wanted {
                return Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0
            }
        }
        return 0
    }

    /// Times the password appears in known breaches (0 = not found).
    public static func check(_ password: String, session: URLSession = .shared) async throws -> Int {
        let hash = sha1Hex(password)
        let prefix = String(hash.prefix(5))
        let suffix = String(hash.dropFirst(5))
        guard let url = URL(string: rangeURL + prefix) else {
            throw URLError(.badURL)
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
        request.setValue("true", forHTTPHeaderField: "Add-Padding")
        request.setValue("Parabellum", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            throw URLError(.badServerResponse)
        }
        return count(suffix: suffix, in: String(decoding: data, as: UTF8.self))
    }
}

/// Runs the installed `parabellum` CLI as the current user for the commands that never involve the daemon
/// (metadata cleaning, password export check): the files stay the user's, nothing runs as root.
public enum ParabellumCLI {
    /// Installed by the package (root-owned, never resolved through `PATH`).
    public static let path = "/Library/Application Support/Parabellum/bin/parabellum"

    public enum Failure: Error, LocalizedError {
        case notInstalled
        case failed(String)

        public var errorDescription: String? {
            switch self {
            case .notInstalled:
                return "L'outil en ligne de commande Parabellum est introuvable (\(ParabellumCLI.path))."
            case .failed(let message):
                return message
            }
        }
    }

    /// `parabellum --json <arguments>`; returns stdout. A non-zero exit with JSON on stdout (some files
    /// failed) still returns it; otherwise stderr becomes the error.
    public static func runJSON(_ arguments: [String], timeout: TimeInterval = 300) async throws -> Data {
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
                process.standardInput = FileHandle.nullDevice
                do {
                    try process.run()
                } catch {
                    continuation.resume(throwing: Failure.failed("lancement impossible : \(error.localizedDescription)"))
                    return
                }
                let timer = DispatchWorkItem { if process.isRunning { process.terminate() } }
                DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: timer)
                // Drain stderr concurrently so a chatty process never blocks on a full pipe.
                let errBox = DataBox()
                let group = DispatchGroup()
                group.enter()
                let errHandle = err.fileHandleForReading
                DispatchQueue.global().async {
                    errBox.set(errHandle.readDataToEndOfFile())
                    group.leave()
                }
                let outData = out.fileHandleForReading.readDataToEndOfFile()
                group.wait()
                let errData = errBox.get()
                process.waitUntilExit()
                timer.cancel()
                let trimmed = outData.drop { $0 == 0x20 || $0 == 0x0A }
                if process.terminationStatus == 0 || trimmed.first == UInt8(ascii: "[") || trimmed.first == UInt8(ascii: "{") {
                    continuation.resume(returning: outData)
                } else {
                    let message = String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                    continuation.resume(throwing: Failure.failed(message.isEmpty ? "échec (code \(process.terminationStatus))" : message))
                }
            }
        }
    }

    /// `parabellum privacy clean <files>`: cleaned copies next to the originals.
    public static func cleanMetadata(_ paths: [String]) async throws -> [CleanReport] {
        let data = try await runJSON(["privacy", "clean"] + paths)
        return try JSONDecoder().decode([CleanReport].self, from: data)
    }

    /// `parabellum privacy password-check --csv <file>`: leaked entries only.
    public static func checkPasswordExport(_ path: String) async throws -> [LeakedPasswordEntry] {
        let data = try await runJSON(["privacy", "password-check", "--csv", path])
        return try JSONDecoder().decode([LeakedPasswordEntry].self, from: data)
    }
}

/// Data written by one thread and read by another after a `DispatchGroup.wait()`.
private final class DataBox: @unchecked Sendable {
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
