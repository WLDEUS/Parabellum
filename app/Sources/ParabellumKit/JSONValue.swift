import Foundation

/// An arbitrary JSON value.
///
/// Used for untyped payloads (`ResponseEnvelope.data`), for building requests field by field, and to keep
/// configuration keys this build does not know about when the app writes the config back (`set_config`).
public enum JSONValue: Sendable, Hashable {
    case null
    case bool(Bool)
    case int(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])
}

extension JSONValue: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .int(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Valeur JSON non reconnue")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null:
            try container.encodeNil()
        case .bool(let value):
            try container.encode(value)
        case .int(let value):
            try container.encode(value)
        case .double(let value):
            try container.encode(value)
        case .string(let value):
            try container.encode(value)
        case .array(let value):
            try container.encode(value)
        case .object(let value):
            try container.encode(value)
        }
    }
}

extension JSONValue {
    /// Converts any `Encodable` value to its JSON tree.
    public init<T: Encodable>(encoding value: T) throws {
        let data = try JSONEncoder().encode(value)
        self = try JSONDecoder().decode(JSONValue.self, from: data)
    }

    /// Parses raw JSON bytes.
    public init(data: Data) throws {
        self = try JSONDecoder().decode(JSONValue.self, from: data)
    }

    /// Decodes this tree into a typed value.
    public func decode<T: Decodable>(as type: T.Type) throws -> T {
        let data = try JSONEncoder().encode(self)
        return try JSONDecoder().decode(T.self, from: data)
    }

    /// Deep merge: objects are merged key by key (recursively), any other value of `overlay` replaces `self`.
    /// Keys that only exist in `self` are kept — this is how unknown config fields survive a round-trip.
    public func merging(_ overlay: JSONValue) -> JSONValue {
        guard case .object(var base) = self, case .object(let top) = overlay else {
            return overlay
        }
        for entry in top {
            if let existing = base[entry.key] {
                base[entry.key] = existing.merging(entry.value)
            } else {
                base[entry.key] = entry.value
            }
        }
        return .object(base)
    }

    /// Member of an object, `nil` for other kinds.
    public subscript(key: String) -> JSONValue? {
        if case .object(let object) = self {
            return object[key]
        }
        return nil
    }

    /// Numeric value of `.int` / `.double`.
    public var numberValue: Double? {
        switch self {
        case .int(let value):
            return Double(value)
        case .double(let value):
            return value
        default:
            return nil
        }
    }

    /// Structural equality where numbers compare with a relative tolerance (Rust `f32` values are
    /// printed with different precisions depending on the serializer).
    public func isApproximatelyEqual(to other: JSONValue, tolerance: Double = 1e-6) -> Bool {
        switch (self, other) {
        case (.null, .null):
            return true
        case let (.bool(a), .bool(b)):
            return a == b
        case let (.string(a), .string(b)):
            return a == b
        case let (.array(a), .array(b)):
            guard a.count == b.count else { return false }
            for index in a.indices where !a[index].isApproximatelyEqual(to: b[index], tolerance: tolerance) {
                return false
            }
            return true
        case let (.object(a), .object(b)):
            guard Set(a.keys) == Set(b.keys) else { return false }
            for entry in a {
                guard let counterpart = b[entry.key],
                      entry.value.isApproximatelyEqual(to: counterpart, tolerance: tolerance)
                else { return false }
            }
            return true
        default:
            guard let x = numberValue, let y = other.numberValue else { return false }
            let scale = Swift.max(1.0, Swift.max(abs(x), abs(y)))
            return abs(x - y) <= tolerance * scale
        }
    }
}
