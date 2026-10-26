import Foundation

/// String enums mirrored from Rust (`#[serde(rename_all = "snake_case")]`).
///
/// A newer daemon may send values this build does not know: instead of failing the whole decode, they map
/// to `fallback` (usually an `unknown` case). Each conforming enum declares
/// `public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }`
/// so the tolerant decoding always wins over the standard `RawRepresentable` one.
public protocol TolerantEnum: RawRepresentable, CaseIterable, Codable, Hashable, Sendable where RawValue == String {
    /// Value used for strings this build does not know.
    static var fallback: Self { get }
}

extension TolerantEnum {
    /// Decodes the raw string, mapping unknown values to `fallback` instead of throwing.
    public static func decodeTolerantly(from decoder: Decoder) throws -> Self {
        let raw = try decoder.singleValueContainer().decode(String.self)
        return Self(rawValue: raw) ?? fallback
    }
}

extension KeyedDecodingContainer {
    /// `#[serde(default)]` semantics: missing (or `null`) key → `fallback`.
    func decodeOr<T: Decodable>(_ key: Key, _ fallback: T) throws -> T {
        try decodeIfPresent(T.self, forKey: key) ?? fallback
    }
}
