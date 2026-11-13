import AppKit
import Foundation
import ParabellumKit

enum PermissionsTab: String, CaseIterable, Identifiable {
    case apps, extensions

    var id: String { rawValue }

    var label: String {
        switch self {
        case .apps: return "Apps"
        case .extensions: return "Extensions de navigateur"
        }
    }
}

/// Minimum risk shown.
enum RiskFilter: String, CaseIterable, Identifiable {
    case all, mediumUp, high

    var id: String { rawValue }

    var label: String {
        switch self {
        case .all: return "Tous les niveaux"
        case .mediumUp: return "Moyen et plus"
        case .high: return "Élevé seulement"
        }
    }

    func accepts(_ s: Severity) -> Bool {
        switch self {
        case .all: return true
        case .mediumUp: return s >= .medium
        case .high: return s >= .high
        }
    }
}

/// One permission with its grants (UI grouping).
struct PermissionGroup: Identifiable {
    let service: String
    let label: String
    let grants: [TccGrant]

    var id: String { service }
    var maxRisk: Severity { grants.map(\.risk).max() ?? .info }
}

/// State and actions of the "Permissions" feature. Owned by AppModel (`model.*`), survives section switches.
@MainActor
final class PermissionsStore: ObservableObject {
    unowned let model: AppModel

    @Published private(set) var report: PermissionsReport?
    @Published private(set) var extensions: ExtensionsReport?
    @Published var tab: PermissionsTab = .apps
    @Published var riskFilter: RiskFilter = .all
    @Published var showDenied = false
    @Published var search = ""
    private var loadedAt: Date?
    private var extensionsLoadedAt: Date?
    private var icons: [String: NSImage] = [:]

    static let auditKey = "permissions.audit"
    static let extensionsKey = "permissions.extensions"
    /// The daemon caches its audit; asking again within this delay is pointless.
    static let freshness: TimeInterval = 300

    init(model: AppModel) {
        self.model = model
    }

    /// Called when the section is shown and after (re)connection; must return quickly when data is cached.
    func load() async {
        async let audit: Void = loadAuditIfStale()
        async let ext: Void = loadExtensionsIfStale()
        _ = await (audit, ext)
    }

    var isFirstLoad: Bool { report == nil && model.isBusy(Self.auditKey) }

    private func loadAuditIfStale() async {
        if let loadedAt, Date().timeIntervalSince(loadedAt) < Self.freshness, report != nil { return }
        await refreshAudit(force: false)
    }

    private func loadExtensionsIfStale() async {
        if let extensionsLoadedAt, Date().timeIntervalSince(extensionsLoadedAt) < Self.freshness, extensions != nil {
            return
        }
        await refreshExtensions()
    }

    /// `force`: re-run the audit in the daemon (codesign on every app: up to a few minutes).
    func refreshAudit(force: Bool) async {
        await model.perform(Self.auditKey, quiet: report != nil && !force) {
            self.report = try await self.model.call(.permissionsAudit(refresh: force), as: PermissionsReport.self, timeout: 300)
            self.loadedAt = Date()
        }
    }

    func refreshExtensions() async {
        await model.perform(Self.extensionsKey, quiet: extensions != nil) {
            self.extensions = try await ParabellumCLI.browserExtensions()
            self.extensionsLoadedAt = Date()
        }
    }

    func refreshAll() async {
        async let a: Void = refreshAudit(force: true)
        async let e: Void = refreshExtensions()
        _ = await (a, e)
    }

    // MARK: Derived data

    private func matches(_ text: [String?]) -> Bool {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return true }
        return text.compactMap { $0?.lowercased() }.contains { $0.contains(q) }
    }

    var groups: [PermissionGroup] {
        let grants = (report?.grants ?? []).filter { g in
            (showDenied || g.isGranted) && riskFilter.accepts(g.risk)
                && matches([g.appName, g.client, g.serviceLabel, g.targetName])
        }
        let byService = Dictionary(grouping: grants, by: \.service)
        return byService.map { service, list in
            PermissionGroup(
                service: service,
                label: list.first?.serviceLabel ?? service,
                grants: list.sorted { ($0.risk, $1.displayName) > ($1.risk, $0.displayName) }
            )
        }
        .sorted { ($0.maxRisk, $1.label) > ($1.maxRisk, $0.label) }
    }

    var extensionGroups: [(browser: String, items: [BrowserExtension])] {
        let list = (extensions?.extensions ?? []).filter { e in
            riskFilter.accepts(e.risk) && (showDenied || e.enabled != false)
                && matches([e.name, e.extensionId, e.profile, BrowserLabels.label(e.browser)])
        }
        return Dictionary(grouping: list, by: \.browser)
            .map { (browser: $0.key, items: $0.value.sorted { ($0.risk, $1.name) > ($1.risk, $0.name) }) }
            .sorted { BrowserLabels.label($0.browser) < BrowserLabels.label($1.browser) }
    }

    func count(risk: Severity) -> Int {
        (report?.grants ?? []).filter { $0.isGranted && $0.risk == risk }.count
    }

    var staleCount: Int { (report?.grants ?? []).filter { $0.installed == false && $0.isGranted }.count }
    var riskyExtensions: Int { (extensions?.extensions ?? []).filter { $0.risk >= .high && $0.enabled != false }.count }

    // MARK: Actions

    /// Opens the System Settings pane where this permission is revoked.
    func openSettings(_ grant: TccGrant) {
        let fallback = "x-apple.systempreferences:com.apple.preference.security?Privacy"
        if let url = URL(string: grant.settingsUrl ?? fallback) {
            NSWorkspace.shared.open(url)
        }
    }

    /// `tccutil reset <service> <bundle id>` as the user (confirmed by the view).
    func reset(_ grant: TccGrant) async {
        guard grant.canReset else { return }
        let result = await model.perform("permissions.reset.\(grant.id)") {
            try await ParabellumCLI.resetPermission(service: grant.service, bundleId: grant.client)
        }
        if let result {
            model.banner = Banner(message: result.message, isError: !result.ok)
            if !result.ok {
                openSettings(grant)
            }
        }
        await refreshAudit(force: true)
    }

    func revealInFinder(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    /// Finder icon of an app / executable (cached); nil when unknown.
    func icon(for path: String?) -> NSImage? {
        guard let path, !path.isEmpty, FileManager.default.fileExists(atPath: path) else { return nil }
        if let cached = icons[path] { return cached }
        let image = NSWorkspace.shared.icon(forFile: path)
        icons[path] = image
        return image
    }
}
