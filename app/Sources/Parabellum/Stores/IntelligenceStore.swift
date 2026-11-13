import Foundation
import ParabellumKit

/// State and actions of the "Intelligence" feature. Owned by AppModel (`model.*`), survives section switches.
@MainActor
final class IntelligenceStore: ObservableObject {
    unowned let model: AppModel

    /// Last status from the daemon (shown immediately when the section reopens).
    @Published private(set) var status: IntelligenceStatus?
    @Published private(set) var lastRefresh: Date?
    /// "Tester un domaine".
    @Published var testDomain: String = ""
    @Published private(set) var verdict: DomainVerdictInfo?

    static let refreshKey = "intel-refresh"
    static let scoreKey = "intel-score"
    static let resetKey = "intel-reset"

    init(model: AppModel) {
        self.model = model
    }

    /// Called when the section is shown and after (re)connection; must return quickly when data is cached.
    func load() async {
        if let lastRefresh, status != nil, Date().timeIntervalSince(lastRefresh) < 15 {
            return
        }
        await refresh()
    }

    /// Background refresh: cached data stays on screen, errors stay quiet when data exists.
    func refresh() async {
        guard !model.isBusy(Self.refreshKey) else { return }
        let quiet = status != nil
        if let fresh = await model.perform(Self.refreshKey, quiet: quiet, {
            try await self.model.call(.intelStatus, as: IntelligenceStatus.self)
        }) {
            status = fresh
            lastRefresh = Date()
        }
    }

    /// Every model to show in the "Modèles" card.
    var models: [ModelInfo] {
        var list = status?.models ?? []
        // TODO(integration): merge the Mach-O and script model entries published by the ml-files worker
        // (DbStatus / model inventory) here, e.g. `list.append(contentsOf: model.fileModels)`.
        list.sort { $0.id < $1.id }
        return list
    }

    func scoreTestDomain() async {
        let domain = testDomain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !domain.isEmpty else { return }
        verdict = await model.perform(Self.scoreKey) {
            try await self.model.call(.intelScoreDomain(domain: domain), as: DomainVerdictInfo.self)
        }
    }

    static func allowKey(_ domain: String) -> String { "intel-allow-\(domain)" }
    static func normalKey(_ id: String) -> String { "intel-normal-\(id)" }

    /// "Autoriser ce domaine" (administrator approval).
    func allow(domain: String) async {
        if let fresh = await model.perform(Self.allowKey(domain), {
            try await self.model.call(.intelAllowDomain(domain: domain), as: IntelligenceStatus.self)
        }) {
            status = fresh
            lastRefresh = Date()
            model.banner = Banner(message: "\(domain) est autorisé : le modèle ne le signalera plus.", isError: false)
            _ = await model.loadConfig()
        }
    }

    /// "C'est normal" (administrator approval).
    func markNormal(_ anomaly: BehaviorAnomaly) async {
        if let fresh = await model.perform(Self.normalKey(anomaly.id), {
            try await self.model.call(.intelMarkNormal(anomalyId: anomaly.id), as: IntelligenceStatus.self)
        }) {
            status = fresh
            lastRefresh = Date()
        }
    }

    /// Forget the baseline and start learning again (administrator approval).
    func resetBaseline() async {
        if let fresh = await model.perform(Self.resetKey, {
            try await self.model.call(.intelResetBaseline, as: IntelligenceStatus.self)
        }) {
            status = fresh
            lastRefresh = Date()
            model.banner = Banner(message: "Référence effacée : nouvelle période d'apprentissage.", isError: false)
        }
    }
}
