import Foundation
import ParabellumKit

/// Stale-while-revalidate loading: every screen shows what is cached immediately, reloads in the background
/// only what is older than `freshFor` (or invalidated by an event), and never replaces content by a
/// full-screen spinner. After (re)connection every section is prefetched, a few at a time, so first visits
/// are instant too.
///
/// Feature stores reuse the same bookkeeping (keys prefixed with their section's raw value, e.g. `lan` or
/// `lan.devices`, so `refresh(section:force: true)` invalidates them):
///
///     func load() async {
///         await model.revalidate("lan") {
///             guard let list = await model.perform("lan", quiet: true, {
///                 try await model.call(.lanDevices, as: [LanDevice].self)
///             }) else { return false }
///             if devices != list { devices = list }   // unchanged data: no re-render
///             return true
///         }
///     }
extension AppModel {
    /// Data younger than this is not reloaded when a screen appears (the refresh button always reloads).
    static let freshFor: TimeInterval = 30

    // MARK: - Freshness API (also for the feature stores)

    /// True when `key` was never loaded, was invalidated, or is older than `maxAge`.
    func needsRefresh(_ key: String, maxAge: TimeInterval = AppModel.freshFor) -> Bool {
        freshness.needsRefresh(key, maxAge: maxAge)
    }

    func markFresh(_ key: String) {
        freshness.markFresh(key)
    }

    /// The data behind `key` changed: reloaded at the next visit (still shown meanwhile).
    func invalidate(_ key: String) {
        freshness.invalidate(key)
    }

    /// Loaded successfully at least once since launch.
    func hasLoaded(_ key: String) -> Bool {
        freshness.hasLoaded(key)
    }

    /// Nothing to show yet for `key` and a load is running or about to: a screen may show a spinner.
    func isFirstLoad(_ key: String) -> Bool {
        !freshness.hasLoaded(key) && (isBusy(key) || (!freshness.hasFailed(key) && connection == .connected))
    }

    /// Runs `load` (which returns true on success) unless `key` is fresh or already loading; marks the key
    /// fresh on success.
    func revalidate(_ key: String, maxAge: TimeInterval = AppModel.freshFor, force: Bool = false, _ load: () async -> Bool) async {
        guard force || (freshness.needsRefresh(key, maxAge: maxAge) && !isBusy(key)) else { return }
        if await load() {
            freshness.markFresh(key)
        } else {
            freshness.markFailed(key)
        }
    }

    // MARK: - Loading with out-of-order protection

    /// Runs `operation` under the busy key `key` and applies its result unless a newer load of the same key
    /// started meanwhile (the daemon answers up to 8 requests in parallel: answers may come back out of
    /// order). Marks `key` fresh on success. Returns false on failure (banner unless `quiet`).
    @discardableResult
    func fetch<T>(_ key: String, quiet: Bool = true, _ operation: () async throws -> T, apply: (T) -> Void) async -> Bool {
        let ticket = freshness.begin(key)
        guard let value = await perform(key, quiet: quiet, operation) else {
            if freshness.isLatest(key, ticket: ticket) {
                freshness.markFailed(key)
            }
            return false
        }
        guard freshness.isLatest(key, ticket: ticket) else { return true }
        apply(value)
        freshness.markFresh(key)
        return true
    }

    /// `fetch` of one request.
    @discardableResult
    func fetch<T: Decodable>(
        _ key: String,
        _ request: Request,
        as type: T.Type,
        timeout: TimeInterval = DaemonClient.defaultTimeout,
        quiet: Bool = true,
        apply: (T) -> Void
    ) async -> Bool {
        await fetch(key, quiet: quiet, { try await self.call(request, as: T.self, timeout: timeout) }, apply: apply)
    }

    /// Runs independent loads concurrently.
    func concurrently(_ loads: (@Sendable @MainActor () async -> Void)...) async {
        await withTaskGroup(of: Void.self) { group in
            for load in loads {
                group.addTask { await load() }
            }
        }
    }

    // MARK: - Sections

    /// Called by each screen when it appears. Not tied to the view's lifetime: a load started here completes
    /// (and is cached) even if the user switches to another section meanwhile.
    func revalidateSection(_ section: SidebarSection) {
        Task { await self.refresh(section: section) }
    }

    /// Reloads what `section` shows: only stale keys, or everything with `force` (refresh button).
    func refresh(section: SidebarSection, force: Bool = false) async {
        let maxAge = force ? 0 : Self.freshFor
        // Forced loads run even if a background load of the same key is in flight (its answer is older).
        func due(_ key: String) -> Bool {
            freshness.needsRefresh(key, maxAge: maxAge) && (force || !isBusy(key))
        }
        switch section {
        case .dashboard:
            let status = due("status"), posture = due("posture")
            await concurrently(
                { if status { await self.refreshStatus() } },
                { await self.refreshNotificationStatus() },
                { if posture { await self.loadPosture() } }
            )
        case .scan:
            if due("jobs") { await loadJobs() }
            if let selected = selectedJobId, jobDetails[selected] == nil, !isBusy("job-\(selected)") {
                await loadJobDetail(selected)
            }
        case .alerts:
            if due("alerts") { await loadAlerts() }
        case .quarantine:
            if due("quarantine") { await loadQuarantine() }
        case .persistence:
            if due("persistence") { await loadPersistence() }
        case .devices:
            if due("devices") { await loadDevices() }
        case .network:
            if due("adblock") { await loadAdblock() }
        case .vpn:
            let status = due("vpn-status"), networks = due("networks")
            await concurrently(
                { if status { await self.loadVpnStatus() } },
                { if networks { await self.loadNetworks() } }
            )
            if wantsExternalVpnServices, due("vpn-services") { await loadExternalVpnServices() }
        case .behavior:
            let guardStatus = due("guard"), snapshots = due("snapshots")
            await concurrently(
                { if guardStatus { await self.loadGuardStatus() } },
                { if snapshots { await self.loadSnapshots() } }
            )
        case .privacy:
            await loadPrivacy(onlyStale: !force)
        case .components:
            if due("components") { await loadComponents() }
        case .report:
            if due("report") { await loadReport() }
        case .settings:
            if due("config") { await loadConfig() }
            if due("vpn-services") { await loadExternalVpnServices() }
        case .intelligence, .lan, .permissions, .cleaning, .vault:
            if force { freshness.invalidate(prefix: section.rawValue) }
            switch section {
            case .intelligence: await intelligence.load()
            case .lan: await lan.load()
            case .permissions: await permissionsAudit.load()
            case .cleaning: await cleaning.load()
            default: await vault.load()
            }
        }
    }

    /// External VPN services matter (VPN screen) only with the external backend.
    var wantsExternalVpnServices: Bool {
        vpnStatus?.backend == .external || config?.vpn.backend == .external
    }

    // MARK: - Connection

    /// Sections prefetched after (re)connection, a batch at a time (the current section loads first).
    static let prefetchBatches: [[SidebarSection]] = [
        [.dashboard, .quarantine, .persistence],
        [.devices, .network, .behavior],
        [.vpn, .privacy, .report],
        [.settings, .scan, .alerts, .components],
        [.intelligence, .lan, .permissions, .cleaning, .vault],
    ]

    /// After (re)connection: what every screen and the menu bar need (in parallel), then the visible
    /// section, then every other section in the background.
    func refreshAfterConnect() async {
        prefetchTask?.cancel()
        // The daemon may have changed anything while we were away (restart, update): all stale, all kept.
        freshness.invalidateAll()
        await concurrently(
            { await self.refreshStatus() },
            { _ = await self.loadConfig() },
            { await self.loadAlerts() },
            { await self.loadVpnStatus() },
            { await self.loadJobs() },
            { await self.loadComponents() }
        )
        guard connection == .connected else { return }
        await refresh(section: section ?? .dashboard)
        startPrefetch()
    }

    /// Background, low-priority prefetch of every section (skips what is already fresh). Cancelled on
    /// disconnection.
    func startPrefetch() {
        prefetchTask?.cancel()
        prefetchTask = Task(priority: .utility) { [weak self] in
            for batch in AppModel.prefetchBatches {
                try? await Task.sleep(nanoseconds: 250_000_000)
                guard let self, !Task.isCancelled, self.connection == .connected else { return }
                await withTaskGroup(of: Void.self) { group in
                    for section in batch {
                        group.addTask { await self.refresh(section: section) }
                    }
                }
            }
        }
    }

    func cancelPrefetch() {
        prefetchTask?.cancel()
        prefetchTask = nil
    }

    /// Events that change data no event carries: mark it stale so the next visit reloads it.
    func invalidateForEvent(_ event: DaemonEvent) {
        switch event {
        case .alert(let alert):
            switch alert.kind {
            case .persistence: freshness.invalidate("persistence")
            case .device: freshness.invalidate("devices")
            case .behavior: freshness.invalidate("guard")
            case .network: freshness.invalidate("networks")
            case .privacy:
                freshness.invalidate("breaches")
                freshness.invalidate("privacy")
            default: break
            }
        case .statusChanged(let newStatus):
            if newStatus.quarantined != status?.quarantined { freshness.invalidate("quarantine") }
            if newStatus.dnsEnabled != status?.dnsEnabled { freshness.invalidate("adblock") }
            if newStatus.componentsNeedingAttention != status?.componentsNeedingAttention {
                freshness.invalidate("components")
            }
        case .scanFinished:
            freshness.invalidate("report")
        default:
            break
        }
    }
}
