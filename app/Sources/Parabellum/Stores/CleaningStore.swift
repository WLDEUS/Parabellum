import AppKit
import Foundation
import ParabellumKit

/// Outcome of one "Nettoyer" run (sum of the per-category `clean apply` calls).
struct CleaningSummary: Equatable {
    var freedBytes = 0
    var trashedBytes = 0
    var cleaned = 0
    var skipped = 0
    var failed = 0
    /// Skipped / refused / failed items, for the result card.
    var messages: [String] = []
}

/// State and actions of the "Nettoyage" feature. Owned by AppModel (`model.cleaning`), survives section
/// switches. Everything runs as the user through `parabellum clean … --json` (never the root daemon).
@MainActor
final class CleaningStore: ObservableObject {
    unowned let model: AppModel

    @Published private(set) var scan: CleanScanReport?
    @Published private(set) var isScanning = false
    @Published private(set) var isCleaning = false
    /// 0…1 while cleaning.
    @Published private(set) var progress: Double = 0
    @Published private(set) var progressLabel = ""
    @Published private(set) var lastSummary: CleaningSummary?
    @Published private(set) var lastError: String?
    /// Selected item ids.
    @Published var selection: Set<String> = []
    /// Categories deleted permanently instead of moved to the Trash.
    @Published var permanent: Set<CleanCategory> = []
    @Published var expanded: Set<CleanCategory> = []

    static let reminderEnabledKey = "cleaning.monthlyReminder"
    static let lastReminderKey = "cleaning.lastReminderAt"
    /// Reminder only when at least this much is reclaimable.
    static let reminderMinimum = 1_000_000_000
    private var reminderTask: Task<Void, Never>?

    init(model: AppModel) {
        self.model = model
    }

    // MARK: - Loading

    /// Called when the section is shown: scans once (spinner only the first time), then keeps the result.
    func load() async {
        if model.persistence.isEmpty {
            await model.loadPersistence()
        }
        guard scan == nil, !isScanning else { return }
        await rescan()
    }

    func rescan() async {
        guard !isScanning, !isCleaning else { return }
        isScanning = true
        defer { isScanning = false }
        do {
            let report = try await ParabellumCLI.cleanScan()
            apply(scan: report)
            lastError = nil
        } catch {
            lastError = error.localizedDescription
        }
    }

    /// New scan: preselected items are selected; choices made on items still present are kept.
    private func apply(scan report: CleanScanReport) {
        let previous = scan.map { Set($0.categories.flatMap { $0.items.map(\.id) }) } ?? []
        var next: Set<String> = []
        for category in report.categories {
            for item in category.items where !item.inUse {
                if previous.contains(item.id) ? selection.contains(item.id) : item.selected {
                    next.insert(item.id)
                }
            }
        }
        scan = report
        selection = next
    }

    // MARK: - Derived

    var categories: [CleanCategoryReport] { scan?.categories ?? [] }

    func selectedSize(_ category: CleanCategoryReport) -> Int {
        category.items.filter { selection.contains($0.id) }.reduce(0) { $0 + $1.size }
    }

    var selectedSize: Int { categories.reduce(0) { $0 + selectedSize($1) } }

    var selectedCount: Int {
        categories.reduce(0) { total, c in total + c.items.filter { selection.contains($0.id) }.count }
    }

    enum Check { case empty, partial, full }

    func check(_ category: CleanCategoryReport) -> Check {
        let selectable = category.items.filter { !$0.inUse }
        let n = selectable.filter { selection.contains($0.id) }.count
        if n == 0 { return .empty }
        return n == selectable.count ? .full : .partial
    }

    func toggle(_ category: CleanCategoryReport) {
        let ids = category.items.filter { !$0.inUse }.map(\.id)
        if check(category) == .full {
            selection.subtract(ids)
        } else {
            selection.formUnion(ids)
        }
    }

    func toggle(_ item: CleanItem) {
        guard !item.inUse else { return }
        if selection.contains(item.id) {
            selection.remove(item.id)
        } else {
            selection.insert(item.id)
        }
    }

    /// Startup items the user may want to disable (data from the daemon's persistence list).
    var startupItems: [PersistenceItem] {
        let kinds: [PersistenceKind] = [.launchAgent, .loginItem, .backgroundItem]
        return model.persistence.filter { item in
            kinds.contains(item.kind)
                && item.status != .removed && item.status != .quarantined
                && !(item.path.hasPrefix("/System/"))
        }
    }

    // MARK: - Cleaning

    /// Cleans the selection category by category (Trash first), then rescans.
    func clean() async {
        guard let scan, !isCleaning, !isScanning else { return }
        let plans: [(CleanCategoryReport, CleanPlan)] = scan.categories
            .sorted { ($0.category == .trash ? 0 : 1) < ($1.category == .trash ? 0 : 1) }
            .compactMap { category in
                let items = category.items
                    .filter { selection.contains($0.id) && !$0.inUse }
                    .map { CleanPlanItem(category: category.category, path: $0.path) }
                guard !items.isEmpty else { return nil }
                let perm = permanent.contains(category.category) ? [category.category] : []
                return (category, CleanPlan(items: items, permanent: perm))
            }
        guard !plans.isEmpty else { return }
        isCleaning = true
        progress = 0
        var summary = CleaningSummary()
        for (index, entry) in plans.enumerated() {
            progressLabel = entry.0.title
            do {
                let r = try await ParabellumCLI.cleanApply(entry.1)
                summary.freedBytes += r.freedBytes
                summary.trashedBytes += r.trashedBytes
                summary.cleaned += r.cleaned
                summary.skipped += r.skipped
                summary.failed += r.failed
                for result in r.results {
                    if let message = result.message, summary.messages.count < 50 {
                        let name = (result.path as NSString).lastPathComponent
                        summary.messages.append("\(name) : \(message)")
                    }
                }
            } catch {
                summary.failed += entry.1.items.count
                summary.messages.append("\(entry.0.title) : \(error.localizedDescription)")
            }
            progress = Double(index + 1) / Double(plans.count)
        }
        lastSummary = summary
        isCleaning = false
        progressLabel = ""
        await rescan()
    }

    func dismissSummary() {
        lastSummary = nil
    }

    // MARK: - Monthly reminder

    var remindersEnabled: Bool {
        get { UserDefaults.standard.object(forKey: Self.reminderEnabledKey) as? Bool ?? true }
        set {
            objectWillChange.send()
            UserDefaults.standard.set(newValue, forKey: Self.reminderEnabledKey)
        }
    }

    /// Every 6 h: if the last reminder is over 30 days old (and not on battery), scan quietly and post
    /// "X Go récupérables" when it is worth it. The first launch only starts the clock.
    func startReminders() {
        guard reminderTask == nil else { return }
        reminderTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 10 * 60 * 1_000_000_000)
            while !Task.isCancelled {
                await self?.reminderTick()
                try? await Task.sleep(nanoseconds: 6 * 3600 * 1_000_000_000)
            }
        }
    }

    private func reminderTick() async {
        let defaults = UserDefaults.standard
        guard remindersEnabled else { return }
        let now = Date()
        guard let last = defaults.object(forKey: Self.lastReminderKey) as? Date else {
            defaults.set(now, forKey: Self.lastReminderKey)
            return
        }
        guard now.timeIntervalSince(last) >= 30 * 86_400, model.status?.onBattery != true, !isCleaning else { return }
        defaults.set(now, forKey: Self.lastReminderKey)
        await rescan()
        guard let reclaimable = scan.map({ _ in selectedSize }), reclaimable >= Self.reminderMinimum else { return }
        await model.notifications.postReminder(
            identifier: "pb.cleaning.monthly",
            title: String(localized: "\(PBFormat.bytes(reclaimable)) récupérables"),
            body: String(localized: "Caches, journaux et restes d'applications peuvent être nettoyés. Rien n'est supprimé sans ton accord."),
            section: SidebarSection.cleaning.rawValue
        )
    }
}
