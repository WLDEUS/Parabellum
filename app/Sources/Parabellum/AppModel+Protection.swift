import AppKit
import Foundation
import ParabellumKit

/// VPN, behaviour guard and privacy actions. Same pattern as AppModel: one request per method, errors
/// become a banner, administrator approval asked by `call` when the command needs it.
extension AppModel {
    // MARK: - VPN & networks

    func loadVpnStatus() async {
        await perform("vpn-status", quiet: true) {
            self.vpnStatus = try await self.call(.vpnStatus, as: VpnStatus.self)
        }
    }

    func loadVpn() async {
        await loadVpnStatus()
        await loadNetworks()
        if vpnStatus?.backend == .external || config?.vpn.backend == .external {
            await loadExternalVpnServices()
        }
    }

    func loadNetworks() async {
        await perform("networks", quiet: true) {
            self.networks = try await self.call(.listNetworks, as: [NetworkInfo].self)
        }
    }

    func loadExternalVpnServices() async {
        await perform("vpn-services", quiet: true) {
            self.externalVpnServices = try await self.call(.vpnListServices, as: [ExternalVpnService].self)
        }
    }

    func vpnConnect() async {
        let status = await perform("vpn-connect") {
            try await self.call(.vpnConnect, as: VpnStatus.self, timeout: 60)
        }
        if let status {
            vpnStatus = status
            if status.state == .error, let message = status.message {
                banner = Banner(message: message, isError: true)
            }
        }
    }

    func vpnDisconnect() async {
        let status = await perform("vpn-disconnect") {
            try await self.call(.vpnDisconnect, as: VpnStatus.self, timeout: 60)
        }
        if let status {
            vpnStatus = status
        }
    }

    /// Imports a share link / subscription / WireGuard `.conf`. Returns true on success.
    @discardableResult
    func importVpnProfile(_ text: String) async -> Bool {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        let info = await perform("vpn-import") {
            try await self.call(.vpnImportProfile(profile: trimmed), as: VpnProfileInfo.self, timeout: 60)
        }
        guard let info else { return false }
        banner = Banner(message: "Profil importé : \(info.name) (\(info.protocolName), \(info.server):\(info.port)).", isError: false)
        await loadVpnStatus()
        return true
    }

    /// NSOpenPanel → WireGuard `.conf` (or a text file holding links) → import.
    func pickAndImportVpnFile() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Importer"
        panel.message = "Fichier WireGuard (.conf) ou fichier texte contenant un lien de partage"
        NSApp.activate()
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let size = (try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
        guard size <= 1_000_000, let text = try? String(contentsOf: url, encoding: .utf8) else {
            banner = Banner(message: "Fichier illisible ou trop gros (1 Mo maximum).", isError: true)
            return
        }
        Task { await importVpnProfile(text) }
    }

    func removeVpnProfile() async {
        let done: Void? = await perform("vpn-remove") {
            try await self.callVoid(.vpnRemoveProfile)
        }
        if done != nil {
            banner = Banner(message: "Profil VPN supprimé.", isError: false)
            await loadVpnStatus()
        }
    }

    func runLeakTest() async {
        let result = await perform("vpn-leak") {
            try await self.call(.vpnLeakTest, as: LeakTestResult.self, timeout: 90)
        }
        if let result {
            banner = Banner(
                message: result.ok ? "Test de fuite réussi : aucune fuite détectée." : "Test de fuite : au moins un point à corriger (détails dans la section VPN).",
                isError: !result.ok
            )
            await loadVpnStatus()
        }
    }

    func setNetworkTrust(_ id: String, trusted: Bool) async {
        let updated = await perform("network-\(id)") {
            try await self.call(.setNetworkTrust(networkId: id, trusted: trusted), as: NetworkInfo.self)
        }
        if let updated {
            upsert(updated, into: &networks, atTop: false)
            await loadVpnStatus()
            await loadConfig()
        }
    }

    // MARK: - Behaviour guard & snapshots

    func loadGuard() async {
        await perform("guard", quiet: true) {
            self.guardStatus = try await self.call(.guardStatus, as: GuardStatus.self)
        }
        await loadSnapshots()
    }

    func loadSnapshots() async {
        await perform("snapshots", quiet: true) {
            self.snapshots = try await self.call(.listSnapshots, as: [SnapshotInfo].self, timeout: 60)
        }
    }

    func createSnapshot() async {
        let snapshot = await perform("snapshot-create") {
            try await self.call(.createSnapshot, as: SnapshotInfo.self, timeout: 120)
        }
        if let snapshot {
            banner = Banner(message: "Instantané créé : \(snapshot.name)", isError: false)
            await loadGuard()
        }
    }

    /// Picks a file or folder of the home folder, then copies its version from `snapshot` next to it
    /// (`~/Parabellum-Restauration/…`, nothing is overwritten).
    func pickAndRestore(from snapshot: SnapshotInfo) {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.directoryURL = FileManager.default.homeDirectoryForCurrentUser
        panel.prompt = "Restaurer"
        panel.message = "Fichier ou dossier de ton dossier personnel à récupérer tel qu'il était dans l'instantané"
        NSApp.activate()
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let path = url.path
        Task { await restore(path: path, from: snapshot) }
    }

    func restore(path: String, from snapshot: SnapshotInfo) async {
        let restored = await perform("snapshot-restore") {
            try await self.call(.restoreFromSnapshot(snapshot: snapshot.name, path: path), as: RestoredTo.self, timeout: 600)
        }
        if let restored {
            banner = Banner(message: "Copie restaurée : \(restored.restoredTo)", isError: false)
            revealInFinder(restored.restoredTo)
        }
    }

    // MARK: - Privacy

    func loadPrivacy() async {
        await perform("privacy", quiet: true) {
            self.removalSummary = try await self.call(.privacySummary, as: RemovalSummary.self)
            self.removalRequests = try await self.call(.privacyListRequests, as: [RemovalRequest].self)
        }
        await perform("privacy-profile", quiet: true) {
            self.identity = try await self.call(.privacyGetProfile(reveal: false), as: IdentityProfile.self)
        }
        await perform("brokers", quiet: true) {
            self.brokers = try await self.call(.privacyListBrokers, as: [BrokerInfo].self)
        }
        await perform("breaches", quiet: true) {
            self.breaches = try await self.call(.breachList, as: [BreachFinding].self)
        }
        await perform("aliases", quiet: true) {
            self.emailAliases = try await self.call(.aliasList, as: [EmailAlias].self)
        }
    }

    /// Identity in clear (administrator approval) for editing.
    func revealIdentity() async -> IdentityProfile? {
        await perform("privacy-reveal") {
            try await self.call(.privacyGetProfile(reveal: true), as: IdentityProfile.self)
        }
    }

    @discardableResult
    func saveIdentity(_ profile: IdentityProfile) async -> Bool {
        let saved = await perform("privacy-save") {
            try await self.call(.privacySetProfile(profile), as: IdentityProfile.self)
        }
        guard let saved else { return false }
        identity = saved
        banner = Banner(message: "Identité enregistrée (stockée par le service, lisible par root uniquement).", isError: false)
        return true
    }

    func startRemoval(brokerIds: [String]? = nil) async {
        let summary = await perform("privacy-start") {
            try await self.call(.privacyStartRemoval(brokerIds: brokerIds), as: RemovalSummary.self)
        }
        if let summary {
            removalSummary = summary
            banner = Banner(message: "\(summary.queued) demande(s) d'effacement en file d'attente sur \(summary.total).", isError: false)
            await loadPrivacy()
        }
    }

    func updateRequest(_ request: RemovalRequest, status: RemovalStatus, note: String? = nil) async {
        let updated = await perform("request-\(request.id)") {
            try await self.call(.privacyUpdateRequest(requestId: request.id, status: status, note: note), as: RemovalRequest.self)
        }
        if let updated {
            upsert(updated, into: &removalRequests, atTop: false)
            await perform("privacy-summary", quiet: true) {
                self.removalSummary = try await self.call(.privacySummary, as: RemovalSummary.self)
            }
        }
    }

    /// Folder where the `.eml` drafts are written (the user's own Downloads).
    static var draftsFolder: URL {
        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Downloads")
        return downloads.appendingPathComponent("Parabellum-RGPD", isDirectory: true)
    }

    /// Writes the email of one request as an `.eml` and opens it in Mail (new message ready to send).
    func openDraft(for request: RemovalRequest) async {
        guard let url = await writeDraft(for: request) else { return }
        NSWorkspace.shared.open(url)
        banner = Banner(message: "E-mail ouvert dans Mail. Envoie-le, puis marque la demande comme envoyée.", isError: false)
        await loadPrivacy()
    }

    /// Writes every pending email (first letters and reminders) into the drafts folder and shows it.
    func writeAllDrafts() async {
        let pending = removalRequests.filter { request in
            request.canDraft && (request.status == .queued || request.status == .draftReady || request.isOverdue())
        }
        guard !pending.isEmpty else {
            banner = Banner(message: "Aucun e-mail à préparer pour l'instant.", isError: false)
            return
        }
        var written = 0
        for request in pending {
            if await writeDraft(for: request) != nil {
                written += 1
            } else {
                break
            }
        }
        if written > 0 {
            NSWorkspace.shared.open(Self.draftsFolder)
            banner = Banner(
                message: "\(written) e-mail(s) prêts dans Téléchargements › Parabellum-RGPD : ouvre chacun dans Mail et envoie-le, puis marque les demandes comme envoyées.",
                isError: false
            )
        }
        await loadPrivacy()
    }

    private func writeDraft(for request: RemovalRequest) async -> URL? {
        let draft = await perform("draft-\(request.id)") {
            try await self.call(.privacyDraft(requestId: request.id), as: MailDraft.self)
        }
        guard let draft else { return nil }
        let folder = Self.draftsFolder
        let file = folder.appendingPathComponent(MailDraft.fileName(brokerName: request.brokerName, requestId: request.id))
        do {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            try draft.emlData().write(to: file, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            return file
        } catch {
            report(error)
            return nil
        }
    }

    func complaint(for request: RemovalRequest) async -> ComplaintDraft? {
        await perform("complaint-\(request.id)") {
            try await self.call(.privacyComplaint(requestId: request.id), as: ComplaintDraft.self)
        }
    }

    func checkBreachesNow() async {
        let list = await perform("breach-check") {
            try await self.call(.breachCheckNow, as: [BreachFinding].self, timeout: 120)
        }
        if let list {
            breaches = list
            let fresh = list.filter { $0.new }.count
            banner = Banner(
                message: fresh > 0 ? "\(fresh) nouvelle(s) fuite(s) trouvée(s)." : "Aucune nouvelle fuite pour tes adresses.",
                isError: fresh > 0
            )
        }
    }

    func createAlias(label: String) async -> EmailAlias? {
        let alias = await perform("alias-create") {
            try await self.call(.aliasCreate(label: label), as: EmailAlias.self, timeout: 60)
        }
        if let alias {
            upsert(alias, into: &emailAliases)
            copyToPasteboard(alias.email)
            banner = Banner(message: "Alias créé et copié : \(alias.email)", isError: false)
        }
        return alias
    }

    // MARK: - Local tools (as the user)

    func cleanMetadata(urls: [URL]) async -> [CleanReport] {
        let paths = urls.map(\.path)
        guard !paths.isEmpty else { return [] }
        let reports = await perform("metadata") {
            try await ParabellumCLI.cleanMetadata(paths)
        }
        return reports ?? []
    }

    func checkPassword(_ password: String) async -> Int? {
        await perform("pwned") {
            try await PwnedPasswords.check(password)
        }
    }

    func checkPasswordExport(url: URL) async -> [LeakedPasswordEntry]? {
        await perform("pwned-csv") {
            try await ParabellumCLI.checkPasswordExport(url.path)
        }
    }
}
