import Foundation

/// French formatting helpers (`fr_FR`), independent of the system language.
public enum PBFormat {
    public static let locale = Locale(identifier: "fr_FR")

    private static let decimalFormatter: NumberFormatter = {
        let formatter = NumberFormatter()
        formatter.locale = locale
        formatter.numberStyle = .decimal
        formatter.maximumFractionDigits = 1
        formatter.minimumFractionDigits = 0
        return formatter
    }()

    private static let integerFormatter: NumberFormatter = {
        let formatter = NumberFormatter()
        formatter.locale = locale
        formatter.numberStyle = .decimal
        formatter.maximumFractionDigits = 0
        return formatter
    }()

    private static let dateTimeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.dateStyle = .medium
        formatter.timeStyle = .short
        return formatter
    }()

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.dateStyle = .long
        formatter.timeStyle = .none
        return formatter
    }()

    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.dateStyle = .none
        formatter.timeStyle = .short
        return formatter
    }()

    private static let relativeFormatter: RelativeDateTimeFormatter = {
        let formatter = RelativeDateTimeFormatter()
        formatter.locale = locale
        formatter.unitsStyle = .full
        formatter.dateTimeStyle = .named
        return formatter
    }()

    /// "812 345"
    public static func count(_ value: Int) -> String {
        integerFormatter.string(from: NSNumber(value: value)) ?? String(value)
    }

    /// Decimal (SI) byte count: "68 octets", "987,7 Mo", "1,2 Go".
    public static func bytes(_ value: Int) -> String {
        let units = ["octets", "Ko", "Mo", "Go", "To", "Po"]
        if value < 1000 {
            return "\(value) \(value <= 1 ? "octet" : "octets")"
        }
        var amount = Double(value)
        var unitIndex = 0
        while amount >= 1000, unitIndex < units.count - 1 {
            amount /= 1000
            unitIndex += 1
        }
        let number = decimalFormatter.string(from: NSNumber(value: amount)) ?? String(format: "%.1f", amount)
        return "\(number) \(units[unitIndex])"
    }

    /// Compact French duration: "45 s", "12 min", "3 h 05 min", "2 j 4 h".
    public static func duration(seconds: Int) -> String {
        let total = max(0, seconds)
        let days = total / 86_400
        let hours = (total % 86_400) / 3600
        let minutes = (total % 3600) / 60
        let secs = total % 60
        if days > 0 {
            return hours > 0 ? "\(days) j \(hours) h" : "\(days) j"
        }
        if hours > 0 {
            return minutes > 0 ? "\(hours) h \(twoDigits(minutes)) min" : "\(hours) h"
        }
        if minutes > 0 {
            return "\(minutes) min"
        }
        return "\(secs) s"
    }

    /// "25 oct. 2026 à 14:32"
    public static func dateTime(_ date: Date) -> String {
        dateTimeFormatter.string(from: date)
    }

    public static func dateTime(unixSeconds: Int64) -> String {
        dateTime(Date(unixSeconds: unixSeconds))
    }

    /// "25 octobre 2026"
    public static func day(_ date: Date) -> String {
        dateFormatter.string(from: date)
    }

    /// "14:32"
    public static func time(_ date: Date) -> String {
        timeFormatter.string(from: date)
    }

    /// "il y a 3 heures", "hier", "dans 15 minutes".
    public static func relative(_ date: Date, now: Date = Date()) -> String {
        relativeFormatter.localizedString(for: date, relativeTo: now)
    }

    /// "95 %"
    public static func percent(_ fraction: Double) -> String {
        let value = Int((fraction * 100).rounded())
        return "\(value) %"
    }

    /// Shortened SHA-256 for lists: "aaaaaaaa…aaaa".
    public static func shortHash(_ hash: String) -> String {
        guard hash.count > 16 else { return hash }
        return "\(hash.prefix(10))…\(hash.suffix(6))"
    }

    /// Unix permission bits: "0644".
    public static func mode(_ mode: Int) -> String {
        let octal = String(mode & 0o7777, radix: 8)
        return octal.count >= 4 ? octal : String(repeating: "0", count: 4 - octal.count) + octal
    }

    private static func twoDigits(_ value: Int) -> String {
        value < 10 ? "0\(value)" : "\(value)"
    }
}
