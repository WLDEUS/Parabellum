import Darwin
import Foundation
import ParabellumKit
import XCTest

/// Fixtures generated from the real Rust types:
/// `cargo run -p pb-core --example gen_fixtures -- app/Tests/ParabellumKitTests/Fixtures`
enum Fixtures {
    struct Missing: Error, CustomStringConvertible {
        let name: String
        var description: String { "fixture introuvable : \(name)" }
    }

    static func data(_ name: String) throws -> Data {
        let base = (name as NSString).deletingPathExtension
        let ext = (name as NSString).pathExtension
        guard let url = Bundle.module.url(forResource: base, withExtension: ext, subdirectory: "Fixtures") else {
            throw Missing(name: name)
        }
        return try Data(contentsOf: url)
    }

    /// Non-empty lines of a `.jsonl` fixture.
    static func lines(_ name: String) throws -> [Data] {
        let text = String(decoding: try data(name), as: UTF8.self)
        return text.split(separator: "\n").map { Data($0.utf8) }
    }

    static func decode<T: Decodable>(_ type: T.Type, from name: String) throws -> T {
        try JSONDecoder().decode(T.self, from: data(name))
    }

    static func json(_ name: String) throws -> JSONValue {
        try JSONValue(data: data(name))
    }
}

struct TestTimeout: Error {}

/// Runs `operation`, failing with `TestTimeout` after `seconds` (so a bug never hangs CI).
func withTimeout<T: Sendable>(_ seconds: Double, _ operation: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask {
            try await operation()
        }
        group.addTask {
            try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
            throw TestTimeout()
        }
        defer { group.cancelAll() }
        guard let result = try await group.next() else {
            throw TestTimeout()
        }
        return result
    }
}

/// Minimal JSON-lines Unix-socket server standing in for `parabellumd`.
/// `respond` gets each request (as JSON) and returns the lines to write back (possibly none).
final class TestSocketServer: @unchecked Sendable {
    let path: String
    private let listenFD: Int32
    private let respond: @Sendable (JSONValue) -> [String]
    private let lock = NSLock()
    private var stopped = false

    init(respond: @escaping @Sendable (JSONValue) -> [String]) throws {
        let socketPath = "/tmp/pbt-\(UUID().uuidString.prefix(8)).sock"
        self.respond = respond
        self.path = socketPath
        unlink(socketPath)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(socketPath.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: bytes)
        }
        let length = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, length) }
        }
        guard bound == 0, listen(fd, 8) == 0 else {
            close(fd)
            throw POSIXError(.EADDRINUSE)
        }
        listenFD = fd
        let thread = Thread { [self] in
            self.acceptLoop()
        }
        thread.start()
    }

    private var isStopped: Bool {
        lock.lock()
        defer { lock.unlock() }
        return stopped
    }

    private func acceptLoop() {
        while true {
            let client = accept(listenFD, nil, nil)
            if isStopped {
                if client >= 0 { close(client) }
                break
            }
            if client < 0 {
                if errno == EINTR { continue }
                break
            }
            var one: Int32 = 1
            _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            let thread = Thread { [self] in
                self.serve(client)
            }
            thread.start()
        }
        close(listenFD)
    }

    private func serve(_ client: Int32) {
        var buffer = LineBuffer()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = chunk.withUnsafeMutableBytes { read(client, $0.baseAddress, $0.count) }
            if count <= 0 { break }
            guard let lines = try? buffer.append(chunk[0..<count]) else { break }
            for line in lines {
                guard let request = try? JSONValue(data: line) else { continue }
                for reply in respond(request) {
                    writeAll(client, reply + "\n")
                }
            }
        }
        close(client)
    }

    private func writeAll(_ fd: Int32, _ text: String) {
        let bytes = Array(text.utf8)
        var offset = 0
        while offset < bytes.count {
            let written = bytes[offset...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            if written <= 0 { return }
            offset += written
        }
    }

    func stop() {
        lock.lock()
        stopped = true
        lock.unlock()
        // Wake the blocking accept().
        if let socket = try? LineSocketProbe.connect(path: path) {
            close(socket)
        }
        unlink(path)
    }
}

/// Raw connect used only to wake the test server.
enum LineSocketProbe {
    static func connect(path: String) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EIO) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: bytes)
        }
        let length = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, length) }
        }
        guard result == 0 else {
            close(fd)
            throw POSIXError(.ECONNREFUSED)
        }
        return fd
    }
}

extension JSONValue {
    var intValue: Int64? {
        if case .int(let value) = self { return value }
        return nil
    }

    var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }
}
