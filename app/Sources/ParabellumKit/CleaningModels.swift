import Foundation

// MARK: - Mac cleaning (`parabellum clean scan|apply --json`, run as the user)

public enum CleanCategory: String, TolerantEnum {
    case caches
    case browserCaches = "browser_caches"
    case developerCaches = "developer_caches"
    case logs, downloads
    case largeFiles = "large_files"
    case appLeftovers = "app_leftovers"
    case trash
    case unknown
    public static let fallback: CleanCategory = .unknown
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum CleanSafety: String, TolerantEnum {
    case safe, moderate, review
    public static let fallback: CleanSafety = .review
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public enum CleanOutcome: String, TolerantEnum {
    case movedToTrash = "moved_to_trash"
    case deleted
    case wouldClean = "would_clean"
    case skipped, refused, failed
    public static let fallback: CleanOutcome = .failed
    public init(from decoder: Decoder) throws { self = try Self.decodeTolerantly(from: decoder) }
}

public struct CleanItem: Codable, Sendable, Hashable, Identifiable {
    public let id: String
    public let path: String
    public let name: String
    public let size: Int
    public let files: Int
    public let modified: Int64?
    public let lastUsed: Int64?
    public let safety: CleanSafety
    public let selected: Bool
    public let inUse: Bool
    public let bundleId: String?
    public let note: String?

    enum CodingKeys: String, CodingKey {
        case id, path, name, size, files, modified
        case lastUsed = "last_used"
        case safety, selected
        case inUse = "in_use"
        case bundleId = "bundle_id"
        case note
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        path = try c.decode(String.self, forKey: .path)
        name = try c.decode(String.self, forKey: .name)
        size = try c.decode(Int.self, forKey: .size)
        files = try c.decodeOr(.files, 0)
        modified = try c.decodeIfPresent(Int64.self, forKey: .modified)
        lastUsed = try c.decodeIfPresent(Int64.self, forKey: .lastUsed)
        safety = try c.decodeOr(.safety, CleanSafety.review)
        selected = try c.decodeOr(.selected, false)
        inUse = try c.decodeOr(.inUse, false)
        bundleId = try c.decodeIfPresent(String.self, forKey: .bundleId)
        note = try c.decodeIfPresent(String.self, forKey: .note)
    }
}

public struct CleanCategoryReport: Codable, Sendable, Hashable, Identifiable {
    public let category: CleanCategory
    public let title: String
    public let description: String
    public let safety: CleanSafety
    public let size: Int
    public let selectedSize: Int
    public let items: [CleanItem]
    public let truncated: Bool
    public let trashable: Bool
    public let error: String?

    public var id: String { category.rawValue }

    enum CodingKeys: String, CodingKey {
        case category, title, description, safety, size
        case selectedSize = "selected_size"
        case items, truncated, trashable, error
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        category = try c.decode(CleanCategory.self, forKey: .category)
        title = try c.decode(String.self, forKey: .title)
        description = try c.decodeOr(.description, "")
        safety = try c.decodeOr(.safety, CleanSafety.review)
        size = try c.decodeOr(.size, 0)
        selectedSize = try c.decodeOr(.selectedSize, 0)
        items = try c.decodeOr(.items, [CleanItem]())
        truncated = try c.decodeOr(.truncated, false)
        trashable = try c.decodeOr(.trashable, true)
        error = try c.decodeIfPresent(String.self, forKey: .error)
    }
}

public struct CleanScanReport: Codable, Sendable, Hashable {
    public let generatedAt: Int64
    public let durationMs: Int
    public let home: String
    public let totalSize: Int
    public let reclaimableSize: Int
    public let categories: [CleanCategoryReport]
    public let warnings: [String]

    enum CodingKeys: String, CodingKey {
        case generatedAt = "generated_at"
        case durationMs = "duration_ms"
        case home
        case totalSize = "total_size"
        case reclaimableSize = "reclaimable_size"
        case categories, warnings
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        generatedAt = try c.decodeOr(.generatedAt, 0)
        durationMs = try c.decodeOr(.durationMs, 0)
        home = try c.decodeOr(.home, "")
        totalSize = try c.decodeOr(.totalSize, 0)
        reclaimableSize = try c.decodeOr(.reclaimableSize, 0)
        categories = try c.decodeOr(.categories, [CleanCategoryReport]())
        warnings = try c.decodeOr(.warnings, [String]())
    }
}

public struct CleanPlanItem: Codable, Sendable, Hashable {
    public let category: CleanCategory
    public let path: String

    public init(category: CleanCategory, path: String) {
        self.category = category
        self.path = path
    }
}

/// Input of `clean apply --plan`.
public struct CleanPlan: Codable, Sendable, Hashable {
    public var items: [CleanPlanItem]
    /// Categories deleted permanently instead of moved to the Trash.
    public var permanent: [CleanCategory]

    public init(items: [CleanPlanItem] = [], permanent: [CleanCategory] = []) {
        self.items = items
        self.permanent = permanent
    }
}

public struct CleanItemResult: Codable, Sendable, Hashable {
    public let category: CleanCategory
    public let path: String
    public let outcome: CleanOutcome
    public let bytes: Int
    public let trashedAs: String?
    public let message: String?

    enum CodingKeys: String, CodingKey {
        case category, path, outcome, bytes
        case trashedAs = "trashed_as"
        case message
    }
}

public struct CleanApplyReport: Codable, Sendable, Hashable {
    public let dryRun: Bool
    public let freedBytes: Int
    public let trashedBytes: Int
    public let cleaned: Int
    public let skipped: Int
    public let failed: Int
    public let results: [CleanItemResult]

    enum CodingKeys: String, CodingKey {
        case dryRun = "dry_run"
        case freedBytes = "freed_bytes"
        case trashedBytes = "trashed_bytes"
        case cleaned, skipped, failed, results
    }
}

extension ParabellumCLI {
    /// `parabellum clean scan` (nothing is modified). Scanning the whole home can take a while.
    public static func cleanScan(categories: [CleanCategory] = []) async throws -> CleanScanReport {
        var args = ["clean", "scan"]
        for c in categories where c != .unknown {
            args += ["--category", c.rawValue.replacingOccurrences(of: "_", with: "-")]
        }
        let data = try await runJSON(args, timeout: 900)
        return try JSONDecoder().decode(CleanScanReport.self, from: data)
    }

    /// `parabellum clean apply --plan <file> --yes`: the plan goes through a private temporary file
    /// (0600, removed afterwards); the CLI re-validates every path.
    public static func cleanApply(_ plan: CleanPlan, dryRun: Bool = false) async throws -> CleanApplyReport {
        let dir = FileManager.default.temporaryDirectory
        let url = dir.appendingPathComponent("parabellum-clean-\(UUID().uuidString).json")
        let data = try JSONEncoder().encode(plan)
        guard FileManager.default.createFile(atPath: url.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
            throw Failure.failed("plan de nettoyage impossible à écrire")
        }
        defer { try? FileManager.default.removeItem(at: url) }
        var args = ["clean", "apply", "--plan", url.path]
        args.append(dryRun ? "--dry-run" : "--yes")
        let out = try await runJSON(args, timeout: 900)
        return try JSONDecoder().decode(CleanApplyReport.self, from: out)
    }
}
