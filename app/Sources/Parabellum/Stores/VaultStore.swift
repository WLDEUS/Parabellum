import AppKit
import CoreServices
import Foundation
import ParabellumKit
import UserNotifications

/// State and actions of the "Coffre" feature (encrypted vault + secure delete). Owned by AppModel
/// (`model.vault`), survives section switches. Everything runs as the user through `parabellum vault`;
/// the passphrase comes from the keychain after Touch ID / the session password and goes to the CLI's
/// stdin only.
@MainActor
final class VaultStore: ObservableObject {
    unowned let model: AppModel

    // MARK: State

    @Published private(set) var status: VaultStatus?
    @Published private(set) var keychainBackend: VaultKeychain.Backend?
    /// Processes that kept the vault from locking (last attempt).
    @Published var holders: [VaultHolder] = []
    @Published var showHolders = false
    /// Recovery key shown once (after creation or a key change).
    @Published var recoveryKeyToShow: String?
    /// A typed password is needed (keychain item missing or out of date).
    @Published var passwordPrompt: PasswordPrompt?
    /// Secure-delete confirmation sheet.
    @Published var shredPlan: ShredPlan?
    @Published private(set) var lastShred: [ShredReport] = []

    // MARK: Settings (UserDefaults "vault.*")

    /// 0 = never.
    @Published var autoLockMinutes: Int {
        didSet { defaults.set(autoLockMinutes, forKey: Keys.autoLock) }
    }
    @Published var lockOnScreenLock: Bool {
        didSet { defaults.set(lockOnScreenLock, forKey: Keys.screenLock) }
    }
    @Published var lockOnSleep: Bool {
        didSet { defaults.set(lockOnSleep, forKey: Keys.sleep) }
    }
    @Published var lockOnQuit: Bool {
        didSet { defaults.set(lockOnQuit, forKey: Keys.quit) }
    }
    /// Lock on sleep / screen lock even when files are open (unsaved changes in other apps are lost).
    @Published var forceLockOnSleep: Bool {
        didSet { defaults.set(forceLockOnSleep, forKey: Keys.forceSleep) }
    }
    /// Custom `….sparsebundle`; empty = default location.
    @Published var bundlePath: String {
        didSet { defaults.set(bundlePath, forKey: Keys.bundle) }
    }
    /// Open in ~/Coffre instead of /Volumes/Coffre.
    @Published var useHomeMountpoint: Bool {
        didSet { defaults.set(useHomeMountpoint, forKey: Keys.homeMount) }
    }

    static let autoLockChoices = [0, 5, 15, 30, 60]
    static let sizeChoicesGB = [5, 10, 20, 50, 100, 250]
    static let defaultBundleDisplay = "~/Library/Application Support/Parabellum/Vault/Coffre.sparsebundle"

    private enum Keys {
        static let autoLock = "vault.autoLockMinutes"
        static let screenLock = "vault.lockOnScreenLock"
        static let sleep = "vault.lockOnSleep"
        static let quit = "vault.lockOnQuit"
        static let forceSleep = "vault.forceLockOnSleep"
        static let bundle = "vault.bundlePath"
        static let homeMount = "vault.useHomeMountpoint"
    }

    private let defaults = UserDefaults.standard
    private let activity = VaultActivityMonitor()
    private var started = false
    private var loading = false
    private var observers: [(NotificationCenter, NSObjectProtocol)] = []
    private var idleTimer: Timer?
    private var nextIdleAttempt = Date.distantPast

    init(model: AppModel) {
        self.model = model
        let d = UserDefaults.standard
        autoLockMinutes = d.object(forKey: Keys.autoLock) as? Int ?? 15
        lockOnScreenLock = d.object(forKey: Keys.screenLock) as? Bool ?? true
        lockOnSleep = d.object(forKey: Keys.sleep) as? Bool ?? true
        lockOnQuit = d.object(forKey: Keys.quit) as? Bool ?? true
        forceLockOnSleep = d.object(forKey: Keys.forceSleep) as? Bool ?? false
        bundlePath = d.string(forKey: Keys.bundle) ?? ""
        useHomeMountpoint = d.object(forKey: Keys.homeMount) as? Bool ?? false
    }

    // MARK: - Derived

    var location: VaultLocation {
        VaultLocation(
            bundle: bundlePath.isEmpty ? nil : bundlePath,
            mountpoint: useHomeMountpoint ? (NSHomeDirectory() as NSString).appendingPathComponent("Coffre") : nil
        )
    }

    var exists: Bool { status?.exists == true }
    var isOpen: Bool { status?.mounted == true }
    var needsLockOnQuit: Bool { lockOnQuit && isOpen }

    var bundleDisplayPath: String {
        bundlePath.isEmpty ? Self.defaultBundleDisplay : (bundlePath as NSString).abbreviatingWithTildeInPath
    }

    // MARK: - Lifecycle

    /// Called once at launch (AppDelegate): system observers, idle timer, first status.
    func start() {
        guard !started else { return }
        started = true
        let workspace = NSWorkspace.shared.notificationCenter
        let screenEvents: [Notification.Name] = [
            NSWorkspace.screensDidSleepNotification,
            NSWorkspace.sessionDidResignActiveNotification,
        ]
        for name in screenEvents {
            observe(workspace, name) { store in
                if store.lockOnScreenLock { await store.lockForSystemEvent() }
            }
        }
        observe(DistributedNotificationCenter.default(), Notification.Name("com.apple.screenIsLocked")) { store in
            if store.lockOnScreenLock { await store.lockForSystemEvent() }
        }
        observe(workspace, NSWorkspace.willSleepNotification) { store in
            if store.lockOnSleep { await store.lockForSystemEvent() }
        }
        // Mounted / ejected elsewhere (Finder, Terminal): keep the state honest.
        for name in [NSWorkspace.didMountNotification, NSWorkspace.didUnmountNotification] {
            observe(workspace, name) { store in await store.refresh() }
        }
        idleTimer = Timer.scheduledTimer(withTimeInterval: 30, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.idleTick() }
        }
        Task { await refresh() }
    }

    private func observe(_ center: NotificationCenter, _ name: Notification.Name, _ handler: @escaping @MainActor (VaultStore) async -> Void) {
        let token = center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                await handler(self)
            }
        }
        observers.append((center, token))
    }

    /// Called when the section is shown; cheap (one CLI call), cached data stays on screen meanwhile.
    func load() async {
        await refresh()
    }

    func refresh(quiet: Bool = true) async {
        guard !loading else { return }
        loading = true
        defer { loading = false }
        await model.perform("vault-status", quiet: quiet) {
            let s = try await VaultCLI.status(self.location)
            self.apply(s)
            self.keychainBackend = VaultKeychain.backend()
        }
    }

    private func apply(_ s: VaultStatus) {
        status = s
        if s.mounted, let mount = s.mountPoint {
            activity.start(path: mount)
        } else {
            activity.stop()
        }
    }

    // MARK: - Create

    /// Creates the vault, keeps the passphrase in the keychain, opens it. `chosenPassword` nil = generated
    /// key (shown once as the recovery key).
    @discardableResult
    func create(sizeGB: Int, chosenPassword: String?) async -> Bool {
        let password = chosenPassword ?? RecoveryKey.generate()
        let done: Bool? = await model.perform("vault-create") {
            // Keychain first: a vault whose key was never stored would be lost.
            let backend = try VaultKeychain.save(password)
            do {
                _ = try await VaultCLI.create(self.location, size: "\(sizeGB)g", name: "Coffre", password: password)
            } catch {
                VaultKeychain.delete()
                throw error
            }
            self.keychainBackend = backend
            let s = try await VaultCLI.attach(self.location, password: password)
            self.apply(s)
            self.activity.touch()
            return true
        }
        guard done == true else { return false }
        if chosenPassword == nil {
            recoveryKeyToShow = password
        } else {
            model.banner = Banner(
                message: "Coffre créé et ouvert. Votre mot de passe est la seule clé : sans lui, le contenu est irrécupérable.",
                isError: false
            )
        }
        return true
    }

    // MARK: - Unlock / lock

    /// Touch ID (or the session password) → keychain → `vault attach`.
    func unlock() async {
        guard exists else { return }
        await model.perform("vault-unlock") {
            let password: String
            do {
                password = try await VaultKeychain.read(reason: "ouvrir le coffre")
            } catch VaultKeychain.Failure.cancelled {
                return
            } catch VaultKeychain.Failure.notFound {
                self.passwordPrompt = PasswordPrompt(purpose: .unlock, message: VaultKeychain.Failure.notFound.errorDescription ?? "")
                return
            }
            try await self.attach(password: password, remember: false)
        }
    }

    private func attach(password: String, remember: Bool) async throws {
        do {
            let s = try await VaultCLI.attach(location, password: password)
            apply(s)
            activity.touch()
            if remember {
                keychainBackend = try VaultKeychain.save(password)
            }
        } catch let error as VaultCLIError where error.isBadPassword {
            passwordPrompt = PasswordPrompt(
                purpose: .unlock,
                message: remember
                    ? "Mot de passe refusé. Réessayez (la clé de récupération fonctionne aussi)."
                    : "Le mot de passe du trousseau ne correspond plus au coffre : saisissez-le (ou la clé de récupération)."
            )
        }
    }

    /// Locks; open files → `holders` (shown unless `quietBusy`). Returns true when locked.
    @discardableResult
    func lock(force: Bool = false, quietBusy: Bool = false) async -> Bool {
        let locked: Bool? = await model.perform("vault-lock", quiet: quietBusy) {
            do {
                let s = try await VaultCLI.detach(self.location, force: force)
                self.apply(s)
                self.holders = []
                self.showHolders = false
                return true
            } catch let error as VaultCLIError where error.isBusy {
                self.holders = error.holders
                if !quietBusy {
                    self.showHolders = true
                }
                return false
            }
        }
        return locked ?? false
    }

    private func lockForSystemEvent() async {
        guard isOpen else { return }
        if await lock(force: forceLockOnSleep, quietBusy: true) {
            return
        }
        let names = Set(holders.map(\.command)).sorted().joined(separator: ", ")
        notify(
            title: "Coffre resté ouvert",
            body: names.isEmpty
                ? "Des fichiers du coffre sont ouverts : fermez-les pour qu'il se verrouille."
                : "Fichiers ouverts par \(names) : fermez-les pour qu'il se verrouille."
        )
    }

    /// Every 30 s: lock after `autoLockMinutes` without file activity (FSEvents). Open files postpone it.
    private func idleTick() {
        guard autoLockMinutes > 0, isOpen, Date() >= nextIdleAttempt else { return }
        let idle = Date().timeIntervalSince(activity.lastActivity)
        guard idle >= Double(autoLockMinutes) * 60 else { return }
        nextIdleAttempt = Date().addingTimeInterval(120)
        let minutes = autoLockMinutes
        Task {
            if await lock(quietBusy: true) {
                notify(title: "Coffre verrouillé", body: "Aucune activité depuis \(minutes) min.")
            }
        }
    }

    /// App quit (AppDelegate `applicationShouldTerminate`): lock, asking before forcing.
    func lockForQuit() async {
        guard isOpen else { return }
        if await lock(quietBusy: true) {
            return
        }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Le coffre est encore utilisé"
        let names = Set(holders.map(\.command)).sorted().joined(separator: ", ")
        alert.informativeText = "Des fichiers du coffre sont ouverts\(names.isEmpty ? "" : " par \(names)"). Forcer le verrouillage peut faire perdre les modifications non enregistrées dans ces apps."
        alert.addButton(withTitle: "Laisser ouvert")
        alert.addButton(withTitle: "Forcer le verrouillage")
        NSApp.activate()
        if alert.runModal() == .alertSecondButtonReturn {
            await lock(force: true, quietBusy: true)
        }
    }

    // MARK: - Typed password

    struct PasswordPrompt: Identifiable {
        enum Purpose {
            case unlock
            case changePassword(newPassword: String?)
            case resize(sizeGB: Int)
            case compact
        }

        let id = UUID()
        let purpose: Purpose
        let message: String
    }

    /// Typed password (or recovery key) for the pending prompt.
    func submitPassword(_ typed: String, remember: Bool) async {
        guard let prompt = passwordPrompt else { return }
        passwordPrompt = nil
        let password = RecoveryKey.normalize(typed)
        switch prompt.purpose {
        case .unlock:
            await model.perform("vault-unlock") {
                try await self.attach(password: password, remember: remember)
            }
        case .changePassword(let newPassword):
            await changePassword(newPassword: newPassword, oldPassword: password)
        case .resize(let sizeGB):
            await resize(sizeGB: sizeGB, password: password)
        case .compact:
            await compact(password: password)
        }
    }

    /// Keychain password for a maintenance action; nil (and a prompt) when it must be typed.
    private func keychainPassword(reason: String, purpose: PasswordPrompt.Purpose) async throws -> String? {
        do {
            return try await VaultKeychain.read(reason: reason)
        } catch VaultKeychain.Failure.cancelled {
            return nil
        } catch VaultKeychain.Failure.notFound {
            passwordPrompt = PasswordPrompt(purpose: purpose, message: VaultKeychain.Failure.notFound.errorDescription ?? "")
            return nil
        }
    }

    private func promptOnBadPassword(_ error: Error, purpose: PasswordPrompt.Purpose) throws {
        if let cliError = error as? VaultCLIError, cliError.isBadPassword {
            passwordPrompt = PasswordPrompt(purpose: purpose, message: "Mot de passe refusé : saisissez le mot de passe actuel (ou la clé de récupération).")
            return
        }
        throw error
    }

    // MARK: - Maintenance

    /// New passphrase (generated key when `newPassword` is nil). `oldPassword` nil = from the keychain.
    func changePassword(newPassword: String?, oldPassword: String? = nil) async {
        let new = newPassword ?? RecoveryKey.generate()
        let purpose = PasswordPrompt.Purpose.changePassword(newPassword: newPassword)
        await model.perform("vault-chpass") {
            var old = oldPassword
            if old == nil {
                old = try await self.keychainPassword(reason: "changer le mot de passe du coffre", purpose: purpose)
            }
            guard let old else { return }
            do {
                let s = try await VaultCLI.changePassword(self.location, old: old, new: new)
                self.apply(s)
            } catch {
                try self.promptOnBadPassword(error, purpose: purpose)
                return
            }
            // The vault now only opens with `new`: show it before anything else can fail.
            if newPassword == nil {
                self.recoveryKeyToShow = new
            }
            self.keychainBackend = try VaultKeychain.save(new)
            if newPassword != nil {
                self.model.banner = Banner(message: "Mot de passe du coffre changé.", isError: false)
            }
        }
    }

    func resize(sizeGB: Int, password: String? = nil) async {
        let purpose = PasswordPrompt.Purpose.resize(sizeGB: sizeGB)
        await model.perform("vault-resize") {
            var pass = password
            if pass == nil {
                pass = try await self.keychainPassword(reason: "redimensionner le coffre", purpose: purpose)
            }
            guard let pass else { return }
            do {
                let s = try await VaultCLI.resize(self.location, size: "\(sizeGB)g", password: pass)
                self.apply(s)
                self.model.banner = Banner(message: "Taille maximale du coffre : \(sizeGB) Go.", isError: false)
            } catch {
                try self.promptOnBadPassword(error, purpose: purpose)
            }
        }
    }

    func compact(password: String? = nil) async {
        await model.perform("vault-compact") {
            var pass = password
            if pass == nil {
                pass = try await self.keychainPassword(reason: "récupérer l'espace du coffre", purpose: .compact)
            }
            guard let pass else { return }
            let before = self.status?.allocatedBytes ?? 0
            do {
                let s = try await VaultCLI.compact(self.location, password: pass)
                self.apply(s)
                let freed = max(0, before - (s.allocatedBytes ?? before))
                self.model.banner = Banner(message: "Espace récupéré : \(PBFormat.bytes(freed)).", isError: false)
            } catch {
                try self.promptOnBadPassword(error, purpose: .compact)
            }
        }
    }

    /// Crypto-shred: deletes the encrypted image, then the keychain copy of its key.
    @discardableResult
    func destroy(force: Bool) async -> Bool {
        let done: Bool? = await model.perform("vault-destroy") {
            do {
                let s = try await VaultCLI.destroy(self.location, force: force)
                VaultKeychain.delete()
                self.keychainBackend = nil
                self.apply(s)
                return true
            } catch let error as VaultCLIError where error.isBusy {
                self.holders = error.holders
                self.showHolders = true
                return false
            }
        }
        if done == true {
            model.banner = Banner(
                message: "Coffre détruit : son contenu est irrécupérable. Détruisez aussi la clé de récupération imprimée ou notée.",
                isError: false
            )
        }
        return done == true
    }

    // MARK: - Files

    func revealInFinder() {
        guard let mount = status?.mountPoint else { return }
        NSWorkspace.shared.open(URL(fileURLWithPath: mount, isDirectory: true))
    }

    func reveal(_ item: VaultItem) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.path)])
    }

    /// Copies files into the open vault; with `removeOriginals`, then asks to securely delete them.
    func addToVault(_ urls: [URL], removeOriginals: Bool) async {
        guard isOpen, let mount = status?.mountPoint, !urls.isEmpty else { return }
        let copied: [URL]? = await model.perform("vault-add") {
            try await Task.detached(priority: .userInitiated) {
                try VaultStore.copy(urls, into: mount)
            }.value
        }
        guard let copied else { return }
        activity.touch()
        await refresh()
        model.banner = Banner(message: "\(copied.count) élément(s) copié(s) dans le coffre.", isError: false)
        if removeOriginals && !copied.isEmpty {
            await prepareShred(urls: copied, source: .originals)
        }
    }

    /// Copies (FileManager keeps attributes) under a free name; items already inside the vault are skipped.
    nonisolated static func copy(_ urls: [URL], into mount: String) throws -> [URL] {
        let fm = FileManager.default
        let root = URL(fileURLWithPath: mount, isDirectory: true)
        var done: [URL] = []
        for url in urls {
            let source = url.resolvingSymlinksInPath().path
            if source == mount || source.hasPrefix(mount + "/") {
                continue
            }
            let name = url.lastPathComponent
            let base = (name as NSString).deletingPathExtension
            let ext = (name as NSString).pathExtension
            var dest = root.appendingPathComponent(name)
            var n = 2
            while fm.fileExists(atPath: dest.path) {
                dest = root.appendingPathComponent(ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)")
                n += 1
            }
            try fm.copyItem(at: url, to: dest)
            done.append(url)
        }
        return done
    }

    // MARK: - Secure delete

    struct ShredPlan: Identifiable {
        enum Source {
            case files, trash, originals
        }

        let id = UUID()
        let source: Source
        let reports: [ShredReport]

        var actionable: [ShredReport] { reports.filter(\.isActionable) }
        var refused: [ShredReport] { reports.filter { !$0.isActionable } }
        var totalBytes: Int { actionable.reduce(0) { $0 + $1.bytes } }
        var totalFiles: Int { actionable.reduce(0) { $0 + $1.files } }
        var touchesOutsideVault: Bool { actionable.contains { $0.zone != .vault } }
    }

    /// Dry run (safety rules + sizes), then the confirmation sheet.
    func prepareShred(urls: [URL], source: ShredPlan.Source = .files) async {
        let paths = urls.map(\.path)
        guard !paths.isEmpty else { return }
        let reports = await model.perform("vault-shred-plan") {
            try await VaultCLI.shred(self.location, paths: paths, dryRun: true)
        }
        if let reports {
            shredPlan = ShredPlan(source: source, reports: reports)
        }
    }

    func prepareEmptyTrash() async {
        let reports = await model.perform("vault-shred-plan") {
            try await VaultCLI.emptyTrash(self.location, dryRun: true)
        }
        guard let reports else { return }
        if reports.isEmpty {
            model.banner = Banner(message: "La Corbeille est déjà vide.", isError: false)
        } else {
            shredPlan = ShredPlan(source: .trash, reports: reports)
        }
    }

    /// Deletes exactly the items the user confirmed.
    func executeShred(_ plan: ShredPlan) async {
        shredPlan = nil
        let paths = plan.actionable.map(\.path)
        guard !paths.isEmpty else { return }
        let reports = await model.perform("vault-shred") {
            try await VaultCLI.shred(self.location, paths: paths, dryRun: false)
        }
        guard let reports else { return }
        lastShred = reports
        let deleted = reports.filter { $0.outcome == .deleted }
        let failed = reports.count - deleted.count
        let written = deleted.reduce(0) { $0 + $1.overwrittenBytes }
        model.banner = Banner(
            message: failed == 0
                ? "\(deleted.count) élément(s) supprimé(s) définitivement (\(PBFormat.bytes(written)) réécrits)."
                : "\(deleted.count) élément(s) supprimé(s), \(failed) en échec : voir le détail dans Coffre.",
            isError: failed > 0
        )
        if reports.contains(where: { $0.zone == .vault }) {
            await refresh()
        }
    }

    // MARK: - Settings

    /// New location (folder for a new vault, or an existing `.sparsebundle`). Only while locked.
    func chooseLocation() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.canCreateDirectories = true
        panel.prompt = "Choisir"
        panel.message = "Dossier du nouveau coffre, ou coffre existant (.sparsebundle). Évitez les dossiers synchronisés (iCloud Drive, Dropbox)."
        NSApp.activate()
        guard panel.runModal() == .OK, let url = panel.url else { return }
        bundlePath = url.pathExtension == "sparsebundle" ? url.path : url.appendingPathComponent("Coffre.sparsebundle").path
        Task { await refresh() }
    }

    func resetLocation() {
        bundlePath = ""
        Task { await refresh() }
    }

    func openFileVaultSettings() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?FileVault") {
            NSWorkspace.shared.open(url)
        }
    }

    // MARK: - Recovery key

    /// Copies the key; the clipboard is cleared after 60 s unless something else was copied meanwhile.
    func copyRecoveryKey(_ key: String) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(key, forType: .string)
        let change = pasteboard.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + 60) {
            if NSPasteboard.general.changeCount == change {
                NSPasteboard.general.clearContents()
            }
        }
    }

    /// Print dialog (its PDF menu saves a copy): a plain text page, nothing kept by the app.
    func printRecoveryKey(_ key: String) {
        let text = NSMutableAttributedString(
            string: "Parabellum — clé de récupération du coffre\n\n",
            attributes: [.font: NSFont.systemFont(ofSize: 18, weight: .semibold)]
        )
        text.append(NSAttributedString(
            string: key + "\n\n",
            attributes: [.font: NSFont.monospacedSystemFont(ofSize: 20, weight: .medium)]
        ))
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "fr_FR")
        formatter.dateStyle = .long
        formatter.timeStyle = .short
        text.append(NSAttributedString(
            string: """
            Créée le \(formatter.string(from: Date())).

            Cette clé ouvre le coffre si le trousseau est perdu (nouveau Mac, réinstallation). \
            Quiconque la possède avec l'image du coffre peut le lire : rangez cette feuille en lieu sûr, \
            hors de l'ordinateur, et ne la photographiez pas.
            """,
            attributes: [.font: NSFont.systemFont(ofSize: 12)]
        ))
        let view = NSTextView(frame: NSRect(x: 0, y: 0, width: 480, height: 640))
        view.textStorage?.setAttributedString(text)
        let info = (NSPrintInfo.shared.copy() as? NSPrintInfo) ?? NSPrintInfo()
        info.horizontalPagination = .fit
        info.verticalPagination = .automatic
        info.isHorizontallyCentered = false
        info.isVerticallyCentered = false
        let operation = NSPrintOperation(view: view, printInfo: info)
        operation.showsPrintPanel = true
        operation.showsProgressPanel = false
        NSApp.activate()
        operation.run()
    }

    // MARK: - Notifications

    private func notify(title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        let request = UNNotificationRequest(identifier: "vault-\(UUID().uuidString)", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request) { _ in }
    }
}

/// Last file activity inside the open vault (FSEvents on its mount point). Writes only: reading a file
/// is not an event, but a file still open makes the auto-lock wait (the CLI reports it busy).
final class VaultActivityMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private var last = Date()
    /// Main thread only.
    private var stream: FSEventStreamRef?
    private var path: String?

    var lastActivity: Date {
        lock.lock()
        defer { lock.unlock() }
        return last
    }

    func touch() {
        lock.lock()
        last = Date()
        lock.unlock()
    }

    func start(path: String) {
        guard self.path != path else { return }
        stop()
        self.path = path
        touch()
        var context = FSEventStreamContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )
        let callback: FSEventStreamCallback = { _, info, _, _, _, _ in
            guard let info else { return }
            Unmanaged<VaultActivityMonitor>.fromOpaque(info).takeUnretainedValue().touch()
        }
        guard let created = FSEventStreamCreate(
            kCFAllocatorDefault,
            callback,
            &context,
            [path] as CFArray,
            FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
            2.0,
            FSEventStreamCreateFlags(kFSEventStreamCreateFlagNone)
        ) else { return }
        FSEventStreamSetDispatchQueue(created, DispatchQueue.global(qos: .utility))
        FSEventStreamStart(created)
        stream = created
    }

    func stop() {
        if let stream {
            FSEventStreamStop(stream)
            FSEventStreamInvalidate(stream)
            FSEventStreamRelease(stream)
        }
        stream = nil
        path = nil
    }

    deinit {
        stop()
    }
}
