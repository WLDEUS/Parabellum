import AppKit
import Foundation
import ParabellumKit
import SwiftUI
import UserNotifications

/// Connection to `parabellumd`, driven by the event stream.
enum ConnectionState: Equatable {
    case connecting
    case connected
    case unreachable(String)
}

/// Message shown at the top of the main window.
struct Banner: Identifiable, Equatable {
    let id = UUID()
    let message: String
    let isError: Bool
}

/// Sidebar sections of the main window.
enum SidebarSection: String, CaseIterable, Identifiable, Hashable {
    case dashboard, scan, alerts, quarantine, persistence, devices, network, components, report, settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dashboard: return "Tableau de bord"
        case .scan: return "Analyse"
        case .alerts: return "Alertes"
        case .quarantine: return "Quarantaine"
        case .persistence: return "Persistance"
        case .devices: return "Périphériques"
        case .network: return "Réseau & pubs"
        case .components: return "Composants"
        case .report: return "Rapport"
        case .settings: return "Réglages"
        }
    }

    var symbol: String {
        switch self {
        case .dashboard: return "gauge.with.dots.needle.33percent"
        case .scan: return "magnifyingglass"
        case .alerts: return "bell.badge"
        case .quarantine: return "archivebox"
        case .persistence: return "arrow.triangle.2.circlepath"
        case .devices: return "cable.connector"
        case .network: return "network.badge.shield.half.filled"
        case .components: return "puzzlepiece.extension"
        case .report: return "chart.bar.xaxis"
        case .settings: return "gearshape"
        }
    }
}

/// Owns the daemon client and every piece of state shown by the UI. Views stay thin and call these methods.
@MainActor
final class AppModel: ObservableObject {
    static let shared = AppModel()
    static let onboardingDefaultsKey = "onboardingSeen"
    static let mainWindowId = "main"
    static let fullDiskAccessSettingsURL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
    static let notificationSettingsURL = "x-apple.systempreferences:com.apple.Notifications-Settings.extension"
    static let kickstartCommand = "sudo launchctl kickstart -k system/\(DaemonProtocol.daemonLabel)"

    let client: DaemonClient
    let authorizer: AdminAuthorizer
    let notifications: NotificationManager
    let keyboardPanels: KeyboardAlertPanelController

    // Connection & status
    @Published private(set) var connection: ConnectionState = .connecting
    @Published private(set) var status: StatusInfo?

    // Alerts
    @Published private(set) var alerts: [SecurityAlert] = []
    @Published var includeResolvedAlerts = false
    @Published var selectedAlertId: Int64?

    // Scans
    @Published private(set) var liveJobs: [String: ScanJobSummary] = [:]
    @Published private(set) var recentJobs: [ScanJobSummary] = []
    @Published private(set) var jobDetails: [String: ScanJobDetail] = [:]
    @Published var activeScanJobId: String?
    @Published var selectedJobId: String?

    // Lists
    @Published private(set) var quarantine: [QuarantineEntry] = []
    @Published private(set) var persistence: [PersistenceItem] = []
    @Published private(set) var devices: [DeviceInfo] = []
    @Published private(set) var components: [ComponentStatus] = []
    @Published private(set) var installingComponents: Set<String> = []
    @Published private(set) var adblock: AdblockStatus?
    @Published private(set) var weeklyReport: WeeklyReport?
    /// macOS security settings (`posture`), shown on the dashboard.
    @Published private(set) var posture: [PostureCheck] = []
    @Published var reportWeekOffset = 0

    // Config (+ raw JSON to preserve unknown keys on save)
    @Published private(set) var config: Config?
    private(set) var rawConfig: JSONValue?

    // Updates
    @Published private(set) var updateInProgress = false
    @Published private(set) var lastUpdate: UpdateResult?

    // UI
    @Published var section: SidebarSection? = .dashboard
    @Published var banner: Banner?
    @Published var showOnboarding = false
    @Published private(set) var inFlight: Set<String> = []
    @Published private(set) var notificationStatus: UNAuthorizationStatus = .notDetermined

    private var openWindowAction: OpenWindowAction?
    private var pendingWindowOpen = false
    private var mainWindowRequested = false
    private let launchDate = Date()
    private var eventTask: Task<Void, Never>?
    private var refreshTask: Task<Void, Never>?
    private var started = false
    private var notifiedAlertIds: Set<Int64> = []
    private static let maxRecentJobs = 50

    init(client: DaemonClient = DaemonClient()) {
        self.client = client
        self.authorizer = AdminAuthorizer()
        self.notifications = NotificationManager()
        self.keyboardPanels = KeyboardAlertPanelController()
    }

    // MARK: - Lifecycle

    /// Called once from `applicationDidFinishLaunching`.
    func start() {
        guard !started else { return }
        started = true
        notifications.activate(model: self)
        keyboardPanels.model = self
        startEventStream()
        startStatusRefresh()
        Task { await refreshNotificationStatus() }
        if !UserDefaults.standard.bool(forKey: Self.onboardingDefaultsKey) {
            showOnboarding = true
            showMainWindow()
        }
    }

    /// Event connection: drives `connection`, keeps state in sync, triggers notifications.
    private func startEventStream() {
        eventTask?.cancel()
        let stream = client.subscribe()
        eventTask = Task { [weak self] in
            for await item in stream {
                guard let self else { return }
                self.handle(item)
            }
        }
    }

    /// The only periodic work: a status refresh every 60 s (cheap, one request).
    private func startStatusRefresh() {
        refreshTask?.cancel()
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 60 * 1_000_000_000)
                guard let self else { return }
                if self.connection == .connected {
                    await self.refreshStatus()
                }
            }
        }
    }

    /// "Réessayer": reconnect immediately instead of waiting for the backoff.
    func retryConnection() {
        connection = .connecting
        startEventStream()
    }

    // MARK: - Windows

    /// Captured from any SwiftUI view (menu bar label, menu content, main window).
    func registerOpenWindow(_ action: OpenWindowAction) {
        openWindowAction = action
        if pendingWindowOpen {
            pendingWindowOpen = false
            showMainWindow()
        }
    }

    func showMainWindow(section: SidebarSection? = nil) {
        if let section {
            self.section = section
        }
        mainWindowRequested = true
        guard let openWindowAction else {
            pendingWindowOpen = true
            return
        }
        openWindowAction(id: Self.mainWindowId)
        NSApp.activate()
    }

    /// SwiftUI may open/restore the `Window` scene at launch: close it unless it was asked for.
    func mainWindowAppeared(_ window: NSWindow) {
        if !mainWindowRequested && Date().timeIntervalSince(launchDate) < 5 {
            window.close()
            return
        }
        NSApp.setActivationPolicy(.regular)
        NSApp.activate()
    }

    func mainWindowDisappeared() {
        NSApp.setActivationPolicy(.accessory)
    }

    func finishOnboarding() {
        UserDefaults.standard.set(true, forKey: Self.onboardingDefaultsKey)
        showOnboarding = false
    }

    // MARK: - Derived state

    var menuBarSymbol: String {
        switch connection {
        case .connecting:
            return "shield"
        case .unreachable:
            return "xmark.shield"
        case .connected:
            guard let status else { return "shield" }
            switch status.protection {
            case .paused:
                return "pause.circle"
            case .degraded, .unknown:
                return "exclamationmark.shield.fill"
            case .active:
                return status.openAlerts > 0 ? "exclamationmark.shield.fill" : "checkmark.shield.fill"
            }
        }
    }

    var openAlertsCount: Int {
        status?.openAlerts ?? alerts.filter { $0.status == .open }.count
    }

    var activeJobs: [ScanJobSummary] {
        liveJobs.values.filter { $0.state.isActive }.sorted { $0.startedAt > $1.startedAt }
    }

    func isBusy(_ key: String) -> Bool {
        inFlight.contains(key)
    }

    func badgeCount(for section: SidebarSection) -> Int {
        switch section {
        case .alerts:
            return openAlertsCount
        case .quarantine:
            return status?.quarantined ?? 0
        case .components:
            return status?.componentsNeedingAttention ?? 0
        case .persistence:
            return persistence.filter { $0.status == .new }.count
        default:
            return 0
        }
    }

    // MARK: - Events

    private func handle(_ item: DaemonStreamItem) {
        switch item {
        case .connected:
            connection = .connected
            Task { await refreshAfterConnect() }
        case .disconnected(let error):
            connection = .unreachable(error.errorDescription ?? "Service injoignable")
            updateInProgress = false
        case .event(let event):
            handle(event)
        }
    }

    private func handle(_ event: DaemonEvent) {
        switch event {
        case .alert(let alert):
            handleAlert(alert)
        case .scanProgress(let job), .scanFinished(let job):
            handleJob(job)
        case .statusChanged(let newStatus):
            status = newStatus
        case .device(let deviceEvent):
            handleDevice(deviceEvent)
        case .updateFinished(let result):
            lastUpdate = result
            updateInProgress = false
            if result.ok {
                let version = result.newDbVersion.map { " — base \($0)" } ?? ""
                banner = Banner(message: "Mise à jour terminée\(version).", isError: false)
            } else {
                // Every step reports a line ("ClamAV à jour", "Base : erreur…"): show them all, the failing
                // step is rarely the last one.
                let detail = result.messages.isEmpty
                    ? "voir le journal du service"
                    : result.messages.joined(separator: " · ")
                banner = Banner(message: "Échec de la mise à jour : \(detail)", isError: true)
            }
            Task { await refreshStatus() }
        case .component(let component):
            upsert(component, into: &components, atTop: false)
            if component.state != .updating {
                installingComponents.remove(component.name)
            }
        case .quarantined(let entry):
            upsert(entry, into: &quarantine)
        case .unknown:
            break
        }
    }

    private func handleAlert(_ alert: SecurityAlert) {
        if alert.status == .open || includeResolvedAlerts {
            upsert(alert, into: &alerts)
        } else {
            alerts.removeAll { $0.id == alert.id }
        }
        guard alert.status == .open, !notifiedAlertIds.contains(alert.id) else { return }
        notifiedAlertIds.insert(alert.id)
        let preferences = config?.notifications ?? NotificationsConfig()
        guard preferences.enabled, alert.severity >= preferences.minSeverity else { return }
        let notifications = self.notifications
        Task { await notifications.post(alert) }
    }

    private func handleJob(_ job: ScanJobSummary) {
        if job.state.isActive {
            liveJobs[job.jobId] = job
        } else {
            liveJobs.removeValue(forKey: job.jobId)
        }
        upsert(job, into: &recentJobs)
        if recentJobs.count > Self.maxRecentJobs {
            recentJobs.removeLast(recentJobs.count - Self.maxRecentJobs)
        }
        if !job.state.isActive && (job.jobId == activeScanJobId || job.jobId == selectedJobId) {
            Task { await loadJobDetail(job.jobId) }
        }
    }

    private func handleDevice(_ event: DeviceEvent) {
        let device = event.device
        upsert(device, into: &devices, atTop: false)
        let wantsAlert = config?.devices.alertNewHid ?? true
        if event.change == .new, wantsAlert, device.isProbableKeyboard, device.trust == .unknown, !device.baseline {
            keyboardPanels.present(device: device)
        }
    }

    private func upsert<T: Identifiable>(_ item: T, into list: inout [T], atTop: Bool = true) {
        if let index = list.firstIndex(where: { $0.id == item.id }) {
            list[index] = item
        } else if atTop {
            list.insert(item, at: 0)
        } else {
            list.append(item)
        }
    }

    private func refreshAfterConnect() async {
        await refreshStatus()
        await loadConfig()
        await loadAlerts()
        if let section, section != .dashboard, section != .alerts, section != .settings {
            await refresh(section: section)
        }
    }

    // MARK: - Request helper

    /// Runs one request; errors become a banner (unless `quiet`). Returns nil on failure.
    @discardableResult
    private func perform<T>(_ key: String, quiet: Bool = false, _ operation: () async throws -> T) async -> T? {
        inFlight.insert(key)
        defer { inFlight.remove(key) }
        do {
            return try await operation()
        } catch {
            if !quiet {
                report(error)
            }
            return nil
        }
    }

    // MARK: - Administrator approval

    /// Every request goes through here: `requiresAdmin` commands get `auth` (system prompt, reused for
    /// ~5 min); an `auth_required` answer (expired authorization, newer daemon) is retried once with a
    /// fresh one. User cancellation throws `AdminAuthorizationError.cancelled` and nothing is sent.
    private func call<T: Decodable>(_ request: Request, as type: T.Type, forceAuth: Bool = false) async throws -> T {
        try await withAdminAuth(request, forceAuth: forceAuth) { auth in
            try await self.client.call(request, as: T.self, auth: auth)
        }
    }

    private func callVoid(_ request: Request) async throws {
        try await withAdminAuth(request, forceAuth: false) { auth in
            try await self.client.callVoid(request, auth: auth)
        }
    }

    private func withAdminAuth<T>(
        _ request: Request,
        forceAuth: Bool,
        _ send: (String?) async throws -> T
    ) async throws -> T {
        var auth: String?
        if forceAuth || request.requiresAdmin {
            auth = try await authorizer.authorization(prompt: request.adminPrompt)
        }
        do {
            return try await send(auth)
        } catch DaemonClientError.daemon(let ipcError) where ipcError.code == .authRequired {
            authorizer.invalidate()
            let fresh = try await authorizer.authorization(prompt: request.adminPrompt)
            return try await send(fresh)
        }
    }

    func report(_ error: Error) {
        if error is CancellationError {
            return
        }
        if let authError = error as? AdminAuthorizationError {
            // Cancelling the password prompt is a normal choice: discreet, not an error.
            banner = Banner(message: authError.errorDescription ?? "Action annulée.", isError: authError != .cancelled)
            return
        }
        if let clientError = error as? DaemonClientError {
            if case .daemon(let ipcError) = clientError, ipcError.code == .permissionDenied {
                banner = Banner(
                    message: "\(ipcError.message) — les commandes qui modifient l'état ne sont acceptées que depuis l'app installée dans /Applications.",
                    isError: true
                )
                return
            }
            banner = Banner(message: clientError.errorDescription ?? "Erreur", isError: true)
            return
        }
        banner = Banner(message: error.localizedDescription, isError: true)
    }

    // MARK: - Loading

    func refresh(section: SidebarSection) async {
        switch section {
        case .dashboard: await refreshStatus()
        case .scan: await loadJobs()
        case .alerts: await loadAlerts()
        case .quarantine: await loadQuarantine()
        case .persistence: await loadPersistence()
        case .devices: await loadDevices()
        case .network: await loadAdblock()
        case .components: await loadComponents()
        case .report: await loadReport()
        case .settings: await loadConfig()
        }
    }

    func refreshStatus() async {
        await perform("status", quiet: true) {
            self.status = try await self.call(.status, as: StatusInfo.self)
        }
    }

    func loadAlerts() async {
        await perform("alerts", quiet: true) {
            let list = try await self.call(
                .listAlerts(limit: 200, includeResolved: self.includeResolvedAlerts),
                as: [SecurityAlert].self
            )
            self.alerts = list
            for alert in list {
                self.notifiedAlertIds.insert(alert.id)
            }
        }
    }

    /// `get_config`. Without auth the daemon redacts secrets (`DaemonProtocol.redactedSecret`);
    /// `withSecrets` asks for administrator approval first and returns them in clear.
    @discardableResult
    func loadConfig(withSecrets: Bool = false) async -> Bool {
        let loaded: Void? = await perform(withSecrets ? "config-secrets" : "config", quiet: !withSecrets) {
            let raw = try await self.call(.getConfig, as: JSONValue.self, forceAuth: withSecrets)
            self.config = try raw.decode(as: Config.self)
            self.rawConfig = raw
        }
        return loaded != nil
    }

    func loadJobs() async {
        await perform("jobs", quiet: true) {
            let jobs = try await self.call(.listJobs(limit: 20), as: [ScanJobSummary].self)
            self.recentJobs = jobs
            for job in jobs where job.state.isActive {
                self.liveJobs[job.jobId] = job
            }
        }
    }

    func loadJobDetail(_ jobId: String) async {
        await perform("job-\(jobId)", quiet: false) {
            self.jobDetails[jobId] = try await self.call(.getJob(jobId: jobId), as: ScanJobDetail.self)
        }
    }

    func loadQuarantine() async {
        await perform("quarantine", quiet: true) {
            self.quarantine = try await self.call(.listQuarantine, as: [QuarantineEntry].self)
        }
    }

    func loadPersistence() async {
        await perform("persistence", quiet: true) {
            self.persistence = try await self.call(.listPersistence(onlyNew: false), as: [PersistenceItem].self)
        }
    }

    func loadDevices() async {
        await perform("devices", quiet: true) {
            self.devices = try await self.call(.listDevices(kind: nil), as: [DeviceInfo].self)
        }
    }

    func loadComponents() async {
        await perform("components", quiet: true) {
            self.components = try await self.call(.listComponents, as: [ComponentStatus].self)
        }
    }

    func loadAdblock() async {
        await perform("adblock", quiet: true) {
            self.adblock = try await self.call(.adblockStatus, as: AdblockStatus.self)
        }
    }

    func loadReport() async {
        let offset = reportWeekOffset
        await perform("report", quiet: true) {
            self.weeklyReport = try await self.call(.weeklyReport(weekOffset: offset), as: WeeklyReport.self)
        }
    }

    // MARK: - Scans

    func startScan(paths: [String], useClamav: Bool? = nil) async {
        guard !paths.isEmpty else { return }
        let started = await perform("scan") {
            try await self.call(.scan(paths: paths, recursive: true, useClamav: useClamav), as: JobStarted.self)
        }
        if let started {
            activeScanJobId = started.jobId
            selectedJobId = started.jobId
        }
    }

    func cancelScan(_ jobId: String) async {
        await perform("cancel-\(jobId)") {
            try await self.callVoid(.cancelScan(jobId: jobId))
        }
    }

    /// NSOpenPanel → scan (files and folders, multiple selection).
    func pickAndScan(useClamav: Bool? = nil) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Analyser"
        panel.message = "Choisis les fichiers ou dossiers à analyser"
        NSApp.activate()
        guard panel.runModal() == .OK else { return }
        let paths = panel.urls.map { $0.path }
        section = .scan
        Task { await startScan(paths: paths, useClamav: useClamav) }
    }

    func scanDownloads() async {
        section = .scan
        await startScan(paths: [Self.downloadsPath])
    }

    static var downloadsPath: String {
        FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first?.path
            ?? (NSHomeDirectory() as NSString).appendingPathComponent("Downloads")
    }

    static var desktopPath: String {
        FileManager.default.urls(for: .desktopDirectory, in: .userDomainMask).first?.path
            ?? (NSHomeDirectory() as NSString).appendingPathComponent("Desktop")
    }

    static let applicationsPath = "/Applications"

    /// Mounted volumes under /Volumes that are not the internal disk (USB keys, external disks, DMGs).
    static func externalVolumes() -> [URL] {
        let keys: [URLResourceKey] = [.volumeIsInternalKey, .volumeNameKey]
        let volumes = FileManager.default.mountedVolumeURLs(includingResourceValuesForKeys: keys, options: [.skipHiddenVolumes]) ?? []
        return volumes.filter { url in
            guard url.path.hasPrefix("/Volumes/") else { return false }
            let values = try? url.resourceValues(forKeys: Set(keys))
            return values?.volumeIsInternal != true
        }
    }

    // MARK: - Alerts

    func resolve(alertId: Int64, action: AlertAction) async {
        let updated = await perform("resolve-\(alertId)") {
            try await self.call(.resolveAlert(alertId: alertId, action: action), as: SecurityAlert.self)
        }
        if let updated {
            if updated.status == .open || includeResolvedAlerts {
                upsert(updated, into: &alerts)
            } else {
                alerts.removeAll { $0.id == updated.id }
            }
            await refreshStatus()
        }
    }

    // MARK: - Quarantine & false positives

    func restore(_ entry: QuarantineEntry, allow: Bool) async {
        let restored = await perform("restore-\(entry.id)") {
            try await self.call(.restore(entryId: entry.id, allow: allow), as: RestoredPath.self)
        }
        if let restored {
            quarantine.removeAll { $0.id == entry.id }
            banner = Banner(message: "Fichier restauré : \(restored.restoredPath)", isError: false)
            await refreshStatus()
        }
    }

    func deleteQuarantined(_ entry: QuarantineEntry) async {
        let done: Void? = await perform("delete-\(entry.id)") {
            try await self.callVoid(.deleteQuarantined(entryId: entry.id))
        }
        if done != nil {
            quarantine.removeAll { $0.id == entry.id }
            await refreshStatus()
        }
    }

    func quarantineFile(path: String) async {
        let entry = await perform("quarantine-\(path)") {
            try await self.call(.quarantinePath(path: path), as: QuarantineEntry.self)
        }
        if let entry {
            upsert(entry, into: &quarantine)
            banner = Banner(message: "Mis en quarantaine : \(entry.fileName)", isError: false)
            await refreshStatus()
        }
    }

    func pickAndQuarantine() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Mettre en quarantaine"
        NSApp.activate()
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task { await quarantineFile(path: url.path) }
    }

    func reportFalsePositive(sha256: String, path: String?) async {
        let done: Void? = await perform("fp-\(sha256)") {
            try await self.callVoid(.reportFalsePositive(sha256: sha256, path: path, note: nil))
        }
        if done != nil {
            banner = Banner(message: "Faux positif signalé : ce fichier est désormais autorisé.", isError: false)
        }
    }

    // MARK: - Persistence & devices

    func setPersistence(_ item: PersistenceItem, status newStatus: PersistenceStatus) async {
        let updated = await perform("persistence-\(item.id)") {
            try await self.call(.setPersistenceStatus(itemId: item.id, status: newStatus), as: PersistenceItem.self)
        }
        if let updated {
            upsert(updated, into: &persistence, atTop: false)
        }
    }

    func setDeviceTrust(_ deviceId: String, trust: DeviceTrust) async {
        let updated = await perform("device-\(deviceId)") {
            try await self.call(.setDeviceTrust(deviceId: deviceId, trust: trust), as: DeviceInfo.self)
        }
        if let updated {
            upsert(updated, into: &devices, atTop: false)
        }
    }

    // MARK: - Components, updates, protection

    func installComponent(_ name: String) async {
        let started = await perform("install-\(name)") {
            try await self.call(.installComponent(name: name), as: JobStarted.self)
        }
        if started != nil {
            installingComponents.insert(name)
        }
    }

    func setAutoUpdate(_ name: String, enabled: Bool) async {
        let list = await perform("autoupdate-\(name)") {
            try await self.call(.setComponentAutoUpdate(name: name, autoUpdate: enabled), as: [ComponentStatus].self)
        }
        if let list {
            components = list
        }
    }

    func updateNow(_ target: UpdateTarget) async {
        let started = await perform("update") {
            try await self.call(.updateNow(target: target), as: JobStarted.self)
        }
        if started != nil {
            updateInProgress = true
            banner = Banner(message: "Mise à jour lancée (\(target.label.lowercased()))…", isError: false)
        }
    }

    func retroHunt(days: Int = 30) async {
        let started = await perform("retrohunt") {
            try await self.call(.retroHunt(days: days), as: JobStarted.self)
        }
        if let started {
            activeScanJobId = started.jobId
            selectedJobId = started.jobId
            banner = Banner(message: "Rétro-chasse lancée sur les fichiers des \(days) derniers jours.", isError: false)
        }
    }

    /// Mercenary-spyware check (Zero Breach Toolkit, up to 30 min, followed like a scan).
    func spywareScan() async {
        let started = await perform("spyware") {
            try await self.call(.spywareScan, as: JobStarted.self)
        }
        if let started {
            activeScanJobId = started.jobId
            selectedJobId = started.jobId
            banner = Banner(
                message: "Analyse anti-spyware lancée (Zero Breach Toolkit, jusqu'à 30 minutes). Les résultats arrivent dans les alertes.",
                isError: false
            )
        }
    }

    func loadPosture(refresh: Bool = false) async {
        await perform("posture", quiet: !refresh) {
            self.posture = try await self.call(.posture(refresh: refresh), as: [PostureCheck].self)
        }
    }

    func setProtection(pausedMinutes: Int) async {
        let newStatus = await perform("protection") {
            try await self.call(.setProtection(pausedMinutes: pausedMinutes), as: StatusInfo.self)
        }
        if let newStatus {
            status = newStatus
        }
    }

    func setDns(enabled: Bool) async {
        let dns = await perform("dns") {
            try await self.call(.setDns(enabled: enabled), as: DnsStatus.self)
        }
        if let dns, let message = dns.message, !message.isEmpty {
            banner = Banner(message: message, isError: !dns.running && dns.enabled)
        }
        await refreshStatus()
        await loadAdblock()
    }

    // MARK: - Config

    /// Validates locally, sends `set_config` (keeping unknown keys), stores the daemon's answer.
    func saveConfig(_ draft: Config) async -> Bool {
        let errors = draft.validationErrors()
        guard errors.isEmpty else {
            banner = Banner(message: errors.joined(separator: "\n"), isError: true)
            return false
        }
        let preserved = rawConfig
        let saved: Void? = await perform("saveConfig") {
            let raw = try await self.call(.setConfig(draft, preserving: preserved), as: JSONValue.self)
            self.config = try raw.decode(as: Config.self)
            self.rawConfig = raw
        }
        if saved != nil {
            banner = Banner(message: "Réglages enregistrés.", isError: false)
            return true
        }
        return false
    }

    // MARK: - Notifications

    func refreshNotificationStatus() async {
        notificationStatus = await notifications.authorizationStatus()
    }

    func requestNotificationPermission() async {
        _ = await notifications.requestAuthorization()
        await refreshNotificationStatus()
    }

    /// Notification button or tap.
    func handleNotificationResponse(actionIdentifier: String, alertId: Int64?) {
        if actionIdentifier == UNNotificationDismissActionIdentifier {
            return
        }
        guard let alertId else {
            showMainWindow(section: .alerts)
            return
        }
        if actionIdentifier.hasPrefix(NotificationKeys.resolvePrefix) {
            let raw = String(actionIdentifier.dropFirst(NotificationKeys.resolvePrefix.count))
            if let action = AlertAction(rawValue: raw), action != .unknown {
                Task { await resolve(alertId: alertId, action: action) }
                return
            }
        }
        selectedAlertId = alertId
        showMainWindow(section: .alerts)
        Task { await loadAlerts() }
    }

    // MARK: - System helpers

    func open(urlString: String) {
        guard let url = URL(string: urlString) else { return }
        NSWorkspace.shared.open(url)
    }

    /// Chrome Web Store links open in Chrome when installed.
    func openInChrome(urlString: String) {
        guard let url = URL(string: urlString) else { return }
        if let chrome = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.google.Chrome") {
            NSWorkspace.shared.open([url], withApplicationAt: chrome, configuration: NSWorkspace.OpenConfiguration(), completionHandler: nil)
        } else {
            NSWorkspace.shared.open(url)
        }
    }

    /// apps.apple.com links open directly in the App Store app.
    func openInAppStore(urlString: String) {
        guard var components = URLComponents(string: urlString) else { return }
        if components.host == "apps.apple.com" {
            components.scheme = "macappstore"
        }
        if let url = components.url {
            NSWorkspace.shared.open(url)
        }
    }

    func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    func revealInFinder(_ path: String) {
        NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "")
    }
}
