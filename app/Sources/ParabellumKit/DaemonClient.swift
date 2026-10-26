import Darwin
import Foundation

/// Protocol constants shared with `crates/pb-core/src/ipc.rs` / `paths.rs`.
public enum DaemonProtocol {
    /// `MAX_FRAME`: max size of a single JSON line.
    public static let maxLineBytes = 8 * 1024 * 1024
    /// `PROTOCOL_VERSION` this build speaks.
    public static let protocolVersion = 1
    public static let defaultSocketPath = "/var/run/parabellum.sock"
    /// Env var overriding the socket path (talk to a dev daemon).
    public static let socketEnvironmentKey = "PARABELLUM_SOCKET"
    /// launchd label, for the "daemon unreachable" hint.
    public static let daemonLabel = "com.wldeus.parabellum.daemon"
    /// Installed daemon binary (needs Full Disk Access).
    public static let daemonBinaryPath = "/Library/Application Support/Parabellum/bin/parabellumd"
    /// `ADMIN_RIGHT`: authorization right (rule `authenticate-admin`, not shared) required by
    /// `Request.requiresAdmin` commands.
    public static let adminRight = "com.wldeus.parabellum.admin"
    /// Placeholder the daemon puts in secret config fields when `get_config` is sent without `auth`.
    /// Sending it back in `set_config` keeps the stored secret.
    public static let redactedSecret = "********"

    /// `$PARABELLUM_SOCKET` when set and non-empty, else `/var/run/parabellum.sock`.
    public static var socketPath: String {
        if let value = ProcessInfo.processInfo.environment[socketEnvironmentKey], !value.isEmpty {
            return value
        }
        return defaultSocketPath
    }
}

public enum DaemonClientError: Error, Equatable, LocalizedError {
    /// No socket / nobody listening.
    case notRunning
    /// The socket exists but this user may not open it (socket is `root:admin 0660`).
    case permissionDenied
    case timeout
    /// The connection dropped before the response arrived.
    case connectionLost
    /// Malformed line, line too long, undecodable payload…
    case protocolError(String)
    /// The daemon answered `ok: false`.
    case daemon(IpcError)

    public var errorDescription: String? {
        switch self {
        case .notRunning:
            return "Le service Parabellum (parabellumd) ne répond pas."
        case .permissionDenied:
            return "Accès refusé au socket du service Parabellum."
        case .timeout:
            return "Le service Parabellum n'a pas répondu à temps."
        case .connectionLost:
            return "La connexion au service Parabellum a été interrompue."
        case .protocolError(let detail):
            return "Réponse inattendue du service : \(detail)"
        case .daemon(let error):
            return error.message
        }
    }

    /// The daemon cannot be reached at all (as opposed to an error it returned).
    public var isConnectivityProblem: Bool {
        switch self {
        case .notRunning, .permissionDenied, .connectionLost, .timeout:
            return true
        case .protocolError, .daemon:
            return false
        }
    }
}

// MARK: - Line framing

/// Splits a byte stream on `\n`, enforcing the max line size. Pure value type (unit-tested).
public struct LineBuffer {
    public let maxLineBytes: Int
    private var pending: [UInt8] = []

    public init(maxLineBytes: Int = DaemonProtocol.maxLineBytes) {
        self.maxLineBytes = maxLineBytes
    }

    /// Bytes received but not yet terminated by a newline.
    public var pendingCount: Int { pending.count }

    /// Feeds a chunk; returns the complete, non-empty lines it terminates (newline stripped).
    public mutating func append(_ chunk: ArraySlice<UInt8>) throws -> [Data] {
        var lines: [Data] = []
        var lineStart = chunk.startIndex
        var index = chunk.startIndex
        while index < chunk.endIndex {
            if chunk[index] == 0x0A {
                let partLength = index - lineStart
                if pending.count + partLength > maxLineBytes {
                    throw DaemonClientError.protocolError("ligne de plus de \(maxLineBytes) octets")
                }
                if pending.isEmpty {
                    if partLength > 0 {
                        lines.append(Data(chunk[lineStart..<index]))
                    }
                } else {
                    pending.append(contentsOf: chunk[lineStart..<index])
                    lines.append(Data(pending))
                    pending.removeAll(keepingCapacity: false)
                }
                lineStart = index + 1
            }
            index += 1
        }
        if lineStart < chunk.endIndex {
            pending.append(contentsOf: chunk[lineStart..<chunk.endIndex])
            if pending.count > maxLineBytes {
                throw DaemonClientError.protocolError("ligne de plus de \(maxLineBytes) octets")
            }
        }
        return lines
    }

    public mutating func append(_ bytes: [UInt8]) throws -> [Data] {
        try append(bytes[bytes.startIndex..<bytes.endIndex])
    }
}

// MARK: - Socket

/// A connected `AF_UNIX` stream socket with a dedicated reader thread (blocking `read`, zero CPU when idle).
///
/// The file descriptor is closed only in `deinit`, i.e. once both the owner and the reader thread let go
/// of the object, so it can never be reused while a `write` or `read` is in flight.
final class LineSocket: @unchecked Sendable {
    private let fd: Int32
    private let lock = NSLock()
    private var closed = false
    private var started = false

    private init(fd: Int32) {
        self.fd = fd
    }

    deinit {
        _ = Darwin.close(fd)
    }

    /// Connects to the daemon socket. Throws `notRunning` / `permissionDenied`.
    static func connect(path: String, sendTimeoutSeconds: Int = 10) throws -> LineSocket {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw DaemonClientError.notRunning
        }
        // Never die of SIGPIPE when the daemon goes away mid-write.
        var one: Int32 = 1
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        // Bound blocking writes.
        var sendTimeout = timeval(tv_sec: sendTimeoutSeconds, tv_usec: 0)
        _ = Darwin.setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout, socklen_t(MemoryLayout<timeval>.size))

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard !pathBytes.isEmpty, pathBytes.count < capacity else {
            _ = Darwin.close(fd)
            throw DaemonClientError.protocolError("chemin de socket invalide ou trop long : \(path)")
        }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let addressLength = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { socketAddress in
                Darwin.connect(fd, socketAddress, addressLength)
            }
        }
        if result != 0 {
            let code = errno
            _ = Darwin.close(fd)
            if code == EACCES || code == EPERM {
                throw DaemonClientError.permissionDenied
            }
            throw DaemonClientError.notRunning
        }
        return LineSocket(fd: fd)
    }

    var isOpen: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !closed
    }

    /// Starts the reader thread (once). `onLine` is called on that thread for every line, in order;
    /// `onClose` exactly once when the connection ends (EOF, error, `close()`), with the cause if any.
    func start(onLine: @escaping @Sendable (Data) -> Void, onClose: @escaping @Sendable (Error?) -> Void) {
        lock.lock()
        let alreadyStarted = started
        started = true
        lock.unlock()
        guard !alreadyStarted else { return }
        let thread = Thread { [self] in
            self.readLoop(onLine: onLine, onClose: onClose)
        }
        thread.name = "Parabellum socket reader"
        thread.qualityOfService = .utility
        thread.start()
    }

    private func readLoop(onLine: @Sendable (Data) -> Void, onClose: @Sendable (Error?) -> Void) {
        let descriptor = fd
        var buffer = LineBuffer()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        var failure: Error?
        while true {
            let count = chunk.withUnsafeMutableBytes { raw -> Int in
                Darwin.read(descriptor, raw.baseAddress, raw.count)
            }
            if count > 0 {
                do {
                    let lines = try buffer.append(chunk[0..<count])
                    for line in lines {
                        onLine(line)
                    }
                } catch {
                    failure = error
                    break
                }
            } else if count == 0 {
                break
            } else {
                let code = errno
                if code == EINTR {
                    continue
                }
                failure = DaemonClientError.connectionLost
                break
            }
        }
        close()
        onClose(failure)
    }

    /// Writes all bytes (blocking, bounded by `SO_SNDTIMEO`). Serialized by a lock.
    func send(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        guard !closed else {
            throw DaemonClientError.connectionLost
        }
        let descriptor = fd
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard var pointer = raw.baseAddress else { return }
            var remaining = raw.count
            while remaining > 0 {
                let written = Darwin.write(descriptor, pointer, remaining)
                if written > 0 {
                    pointer = pointer.advanced(by: written)
                    remaining -= written
                } else if written < 0 && errno == EINTR {
                    continue
                } else {
                    throw DaemonClientError.connectionLost
                }
            }
        }
    }

    /// Shuts the connection down; the reader thread then ends and reports `onClose`.
    func close() {
        lock.lock()
        let wasClosed = closed
        closed = true
        lock.unlock()
        if !wasClosed {
            _ = Darwin.shutdown(fd, SHUT_RDWR)
        }
    }
}

// MARK: - Request / response correlation

/// Continuations waiting for a response, keyed by request id. Thread-safe; every continuation is
/// resumed exactly once (response, timeout, cancellation or connection loss).
final class PendingRequests: @unchecked Sendable {
    private struct Entry {
        let continuation: CheckedContinuation<Data, Error>
        var timeout: Task<Void, Never>?
    }

    private let lock = NSLock()
    private var entries: [UInt64: Entry] = [:]
    private var closedError: Error?

    func register(_ id: UInt64, _ continuation: CheckedContinuation<Data, Error>) {
        lock.lock()
        if let error = closedError {
            lock.unlock()
            continuation.resume(throwing: error)
            return
        }
        entries[id] = Entry(continuation: continuation, timeout: nil)
        lock.unlock()
    }

    func attachTimeout(_ id: UInt64, _ task: Task<Void, Never>) {
        lock.lock()
        if entries[id] != nil {
            entries[id]?.timeout = task
            lock.unlock()
        } else {
            lock.unlock()
            task.cancel()
        }
    }

    func resolve(_ id: UInt64, with result: Result<Data, Error>) {
        lock.lock()
        let entry = entries.removeValue(forKey: id)
        lock.unlock()
        guard let entry else { return }
        entry.timeout?.cancel()
        entry.continuation.resume(with: result)
    }

    func failAll(_ error: Error) {
        lock.lock()
        closedError = error
        let all = Array(entries.values)
        entries.removeAll()
        lock.unlock()
        for entry in all {
            entry.timeout?.cancel()
            entry.continuation.resume(throwing: error)
        }
    }
}

/// The request connection: one socket + its pending table. Events are not expected here.
final class RequestConnection: @unchecked Sendable {
    let socket: LineSocket
    let pending = PendingRequests()

    init(socket: LineSocket) {
        self.socket = socket
        let pending = self.pending
        socket.start(
            onLine: { line in
                guard let id = LineProbe.responseId(in: line) else { return }
                pending.resolve(id, with: .success(line))
            },
            onClose: { error in
                pending.failAll(error ?? DaemonClientError.connectionLost)
            }
        )
    }

    var isOpen: Bool { socket.isOpen }

    func close() {
        socket.close()
    }
}

private enum WriteFailure: Error {
    case failed
}

// MARK: - Client

/// Client of the `parabellumd` JSON-lines protocol.
///
/// - Requests go through one lazily-opened connection, correlated by `id` (works with concurrent calls).
///   The connection is re-opened transparently after a daemon restart.
/// - Events come from a separate long-lived connection (`subscribe()`), reconnected with backoff.
public actor DaemonClient {
    public nonisolated let socketPath: String
    /// Default per-request timeout. Scans / updates return a job id immediately, so 30 s is plenty.
    public static let defaultTimeout: TimeInterval = 30

    private var connection: RequestConnection?
    private var nextId: UInt64 = 1

    public init(socketPath: String = DaemonProtocol.socketPath) {
        self.socketPath = socketPath
    }

    deinit {
        connection?.close()
    }

    /// Sends `request` and decodes the response `data` as `T`.
    /// `auth`: base64 `AuthorizationExternalForm` for `Request.requiresAdmin` commands (omitted when nil).
    public func call<T: Decodable>(
        _ request: Request,
        as type: T.Type,
        auth: String? = nil,
        timeout: TimeInterval = DaemonClient.defaultTimeout
    ) async throws -> T {
        let line = try await send(request, auth: auth, timeout: timeout)
        return try ResponseDecoding.decode(line, as: T.self)
    }

    /// Sends `request` whose response `data` is `null` / irrelevant; throws on `ok: false`.
    public func callVoid(_ request: Request, auth: String? = nil, timeout: TimeInterval = DaemonClient.defaultTimeout) async throws {
        let line = try await send(request, auth: auth, timeout: timeout)
        try ResponseDecoding.check(line)
    }

    /// Raw response line (for debugging / custom decoding).
    public func callRaw(_ request: Request, auth: String? = nil, timeout: TimeInterval = DaemonClient.defaultTimeout) async throws -> Data {
        try await send(request, auth: auth, timeout: timeout)
    }

    /// Closes the request connection (the next call reconnects).
    public func disconnect() {
        connection?.close()
        connection = nil
    }

    private func openConnection() throws -> RequestConnection {
        if let existing = connection, existing.isOpen {
            return existing
        }
        connection?.close()
        connection = nil
        let fresh = RequestConnection(socket: try LineSocket.connect(path: socketPath))
        connection = fresh
        return fresh
    }

    private func dropConnection(_ stale: RequestConnection) {
        stale.close()
        if connection === stale {
            connection = nil
        }
    }

    private func allocateId() -> UInt64 {
        let id = nextId
        nextId = nextId == UInt64.max ? 1 : nextId + 1
        return id
    }

    private func send(_ request: Request, auth: String?, timeout: TimeInterval) async throws -> Data {
        var attempt = 0
        while true {
            attempt += 1
            try Task.checkCancellation()
            let conn = try openConnection()
            let id = allocateId()
            let payload = try request.encodeLine(id: id, auth: auth)
            do {
                return try await Self.exchange(conn, id: id, payload: payload, timeout: timeout)
            } catch WriteFailure.failed {
                // The request never reached the daemon (stale connection after a restart): retry once.
                dropConnection(conn)
                if attempt >= 2 {
                    throw DaemonClientError.connectionLost
                }
            } catch let error as DaemonClientError where error == .connectionLost {
                dropConnection(conn)
                throw error
            }
        }
    }

    private static func exchange(_ conn: RequestConnection, id: UInt64, payload: Data, timeout: TimeInterval) async throws -> Data {
        let nanoseconds = UInt64(Swift.max(timeout, 0.1) * 1_000_000_000)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
                conn.pending.register(id, continuation)
                do {
                    try conn.socket.send(payload)
                } catch {
                    conn.pending.resolve(id, with: .failure(WriteFailure.failed))
                    return
                }
                let timer = Task.detached(priority: .utility) {
                    try? await Task.sleep(nanoseconds: nanoseconds)
                    if Task.isCancelled { return }
                    conn.pending.resolve(id, with: .failure(DaemonClientError.timeout))
                }
                conn.pending.attachTimeout(id, timer)
            }
        } onCancel: {
            conn.pending.resolve(id, with: .failure(CancellationError()))
        }
    }
}

// MARK: - Event subscription

/// What the event stream delivers: connection state changes and daemon events.
public enum DaemonStreamItem: Sendable, Equatable {
    /// Subscribed (initially and after every reconnection): refresh any cached state.
    case connected
    /// Lost or could not reach the daemon; reconnection continues in the background with backoff.
    case disconnected(DaemonClientError)
    case event(DaemonEvent)
}

extension DaemonClient {
    /// Long-lived event connection: sends `subscribe`, yields `.connected`, then every event; on loss
    /// yields `.disconnected` and reconnects with exponential backoff (1 s → 30 s). Cancelling the
    /// consuming task (or dropping the stream) closes the connection.
    public nonisolated func subscribe() -> AsyncStream<DaemonStreamItem> {
        let path = socketPath
        return AsyncStream(DaemonStreamItem.self, bufferingPolicy: .bufferingNewest(512)) { continuation in
            let task = Task.detached(priority: .utility) {
                await EventSubscription.run(path: path, continuation: continuation)
            }
            continuation.onTermination = { @Sendable _ in
                task.cancel()
            }
        }
    }

    /// Daemon events only (connection state changes are dropped).
    public nonisolated func events() -> AsyncStream<DaemonEvent> {
        let upstream = subscribe()
        return AsyncStream(DaemonEvent.self, bufferingPolicy: .bufferingNewest(512)) { continuation in
            let task = Task.detached(priority: .utility) {
                for await item in upstream {
                    if case .event(let event) = item {
                        continuation.yield(event)
                    }
                }
                continuation.finish()
            }
            continuation.onTermination = { @Sendable _ in
                task.cancel()
            }
        }
    }
}

/// Flag shared between the reader thread and the reconnect loop.
private final class SessionState: @unchecked Sendable {
    private let lock = NSLock()
    private var _established = false
    private var _failure: DaemonClientError?

    var established: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _established
    }

    var failure: DaemonClientError? {
        lock.lock()
        defer { lock.unlock() }
        return _failure
    }

    func markEstablished() {
        lock.lock()
        _established = true
        lock.unlock()
    }

    func fail(_ error: DaemonClientError) {
        lock.lock()
        _failure = error
        lock.unlock()
    }
}

enum EventSubscription {
    static let subscribeRequestId: UInt64 = 1
    static let maxBackoffSeconds: UInt64 = 30

    static func run(path: String, continuation: AsyncStream<DaemonStreamItem>.Continuation) async {
        var backoff: UInt64 = 1
        var reportedDown = false
        while !Task.isCancelled {
            var failure: DaemonClientError = .notRunning
            do {
                let socket = try LineSocket.connect(path: path)
                let state = SessionState()
                let closeError = await session(socket: socket, state: state, continuation: continuation)
                if state.established {
                    backoff = 1
                    reportedDown = false
                }
                if let stateFailure = state.failure {
                    failure = stateFailure
                } else if let clientError = closeError as? DaemonClientError {
                    failure = clientError
                } else {
                    failure = .connectionLost
                }
            } catch let error as DaemonClientError {
                failure = error
            } catch {
                failure = .notRunning
            }
            if Task.isCancelled {
                break
            }
            if !reportedDown {
                continuation.yield(.disconnected(failure))
                reportedDown = true
            }
            try? await Task.sleep(nanoseconds: backoff * 1_000_000_000)
            backoff = Swift.min(backoff * 2, maxBackoffSeconds)
        }
        continuation.finish()
    }

    /// Runs one subscribed connection until it closes; returns the close cause.
    private static func session(
        socket: LineSocket,
        state: SessionState,
        continuation: AsyncStream<DaemonStreamItem>.Continuation
    ) async -> Error? {
        await withTaskCancellationHandler {
            await withCheckedContinuation { (done: CheckedContinuation<Error?, Never>) in
                socket.start(
                    onLine: { line in
                        EventSubscription.handle(line: line, socket: socket, state: state, continuation: continuation)
                    },
                    onClose: { error in
                        done.resume(returning: error)
                    }
                )
                do {
                    try socket.send(Request.subscribe.encodeLine(id: EventSubscription.subscribeRequestId))
                } catch {
                    socket.close()
                }
            }
        } onCancel: {
            socket.close()
        }
    }

    private static func handle(
        line: Data,
        socket: LineSocket,
        state: SessionState,
        continuation: AsyncStream<DaemonStreamItem>.Continuation
    ) {
        guard let message = try? ServerMessage.parse(line) else {
            // Undecodable line (newer payload shape?): skip it rather than dropping the connection.
            return
        }
        switch message {
        case .event(let event):
            continuation.yield(.event(event))
        case .response(let response):
            guard response.id == subscribeRequestId else { return }
            if response.ok {
                state.markEstablished()
                continuation.yield(.connected)
            } else {
                state.fail(.daemon(response.error ?? IpcError(code: .unknown, message: "Abonnement refusé")))
                socket.close()
            }
        }
    }
}
