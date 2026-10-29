import Foundation

/// Events pushed by the daemon after `subscribe` (`{"event":"…","data":…}`), mirroring `DaemonEvent`.
public enum DaemonEvent: Sendable, Equatable {
    case alert(SecurityAlert)
    /// Sent at most every 500 ms per running job.
    case scanProgress(ScanJobSummary)
    case scanFinished(ScanJobSummary)
    case statusChanged(StatusInfo)
    case device(DeviceEvent)
    case updateFinished(UpdateResult)
    case component(ComponentStatus)
    case quarantined(QuarantineEntry)
    /// VPN state, kill switch, current network or leak test changed.
    case vpn(VpnStatus)
    /// An event name this build does not know (newer daemon); its payload is ignored.
    case unknown(String)

    /// Wire name (`event`).
    public var name: String {
        switch self {
        case .alert: return "alert"
        case .scanProgress: return "scan_progress"
        case .scanFinished: return "scan_finished"
        case .statusChanged: return "status_changed"
        case .device: return "device"
        case .updateFinished: return "update_finished"
        case .component: return "component"
        case .quarantined: return "quarantined"
        case .vpn: return "vpn"
        case .unknown(let name): return name
        }
    }
}

extension DaemonEvent: Decodable {
    private enum CodingKeys: String, CodingKey {
        case event, data
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let name = try c.decode(String.self, forKey: .event)
        switch name {
        case "alert":
            self = .alert(try c.decode(SecurityAlert.self, forKey: .data))
        case "scan_progress":
            self = .scanProgress(try c.decode(ScanJobSummary.self, forKey: .data))
        case "scan_finished":
            self = .scanFinished(try c.decode(ScanJobSummary.self, forKey: .data))
        case "status_changed":
            self = .statusChanged(try c.decode(StatusInfo.self, forKey: .data))
        case "device":
            self = .device(try c.decode(DeviceEvent.self, forKey: .data))
        case "update_finished":
            self = .updateFinished(try c.decode(UpdateResult.self, forKey: .data))
        case "component":
            self = .component(try c.decode(ComponentStatus.self, forKey: .data))
        case "quarantined":
            self = .quarantined(try c.decode(QuarantineEntry.self, forKey: .data))
        case "vpn":
            self = .vpn(try c.decode(VpnStatus.self, forKey: .data))
        default:
            self = .unknown(name)
        }
    }
}

/// Response to a request (`{"id":N,"ok":true,"data":…}` / `{"id":N,"ok":false,"error":{…}}`).
public struct ResponseEnvelope: Decodable, Sendable, Equatable {
    public let id: UInt64
    public let ok: Bool
    /// Absent when the result is `null`.
    public let data: JSONValue?
    public let error: IpcError?

    enum CodingKeys: String, CodingKey {
        case id, ok, data, error
    }

    /// Typed `data`, or the daemon error.
    public func decodeData<T: Decodable>(as type: T.Type) throws -> T {
        guard ok else {
            throw DaemonClientError.daemon(error ?? IpcError(code: .unknown, message: "Erreur inconnue du service"))
        }
        return try (data ?? .null).decode(as: T.self)
    }
}

/// One line received from the daemon: an event (has `"event"`) or a response.
public enum ServerMessage: Sendable, Equatable {
    case event(DaemonEvent)
    case response(ResponseEnvelope)

    /// Parses one line (without its trailing newline).
    public static func parse(_ line: Data) throws -> ServerMessage {
        try JSONDecoder().decode(ServerMessage.self, from: line)
    }
}

extension ServerMessage: Decodable {
    private enum ProbeKeys: String, CodingKey {
        case event
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: ProbeKeys.self)
        if c.contains(.event) {
            self = .event(try DaemonEvent(from: decoder))
        } else {
            self = .response(try ResponseEnvelope(from: decoder))
        }
    }
}

/// Cheap first pass over a line: is it a response (and to which id) or an event?
struct LineProbe: Decodable {
    let id: UInt64?
    let event: String?

    /// Request id when the line is a response, nil for events and garbage.
    static func responseId(in line: Data) -> UInt64? {
        guard let probe = try? JSONDecoder().decode(LineProbe.self, from: line), probe.event == nil else {
            return nil
        }
        return probe.id
    }
}

/// Typed decoding of a response line for `T`.
struct TypedResponse<T: Decodable>: Decodable {
    let ok: Bool
    let data: T?
    let error: IpcError?
}

/// Response line when the payload is ignored.
struct UntypedResponse: Decodable {
    let ok: Bool
    let error: IpcError?
}

enum ResponseDecoding {
    static func decode<T: Decodable>(_ line: Data, as type: T.Type) throws -> T {
        let decoder = JSONDecoder()
        let typed: TypedResponse<T>
        do {
            typed = try decoder.decode(TypedResponse<T>.self, from: line)
        } catch {
            // An error response may carry no data at all: report the daemon error rather than a parse failure.
            if let untyped = try? decoder.decode(UntypedResponse.self, from: line), !untyped.ok {
                throw DaemonClientError.daemon(untyped.error ?? IpcError(code: .unknown, message: "Erreur inconnue du service"))
            }
            throw DaemonClientError.protocolError("Réponse illisible (\(T.self)) : \(error)")
        }
        guard typed.ok else {
            throw DaemonClientError.daemon(typed.error ?? IpcError(code: .unknown, message: "Erreur inconnue du service"))
        }
        if let data = typed.data {
            return data
        }
        if let empty = JSONValue.null as? T {
            return empty
        }
        throw DaemonClientError.protocolError("Réponse sans données pour \(T.self)")
    }

    static func check(_ line: Data) throws {
        let untyped: UntypedResponse
        do {
            untyped = try JSONDecoder().decode(UntypedResponse.self, from: line)
        } catch {
            throw DaemonClientError.protocolError("Réponse illisible : \(error)")
        }
        guard untyped.ok else {
            throw DaemonClientError.daemon(untyped.error ?? IpcError(code: .unknown, message: "Erreur inconnue du service"))
        }
    }
}
