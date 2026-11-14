import Combine
import Foundation
import ParabellumKit
import WidgetKit

/// Feeds the optional desktop widget: writes a `WidgetSnapshot` into the widget extension's own sandbox
/// container (only when macOS already created it, i.e. the widget is in use) and asks WidgetKit to reload.
@MainActor
final class WidgetBridge {
    static let shared = WidgetBridge()

    private var subscription: AnyCancellable?
    private var lastWritten: WidgetSnapshot?

    func start(model: AppModel) {
        guard subscription == nil else { return }
        subscription = Publishers.CombineLatest3(model.$status, model.$vpnStatus, model.$connection)
            .debounce(for: .seconds(2), scheduler: RunLoop.main)
            .sink { [weak self] status, vpn, connection in
                MainActor.assumeIsolated {
                    self?.publish(status: status, vpn: vpn, connection: connection)
                }
            }
    }

    private func publish(status: StatusInfo?, vpn: VpnStatus?, connection: ConnectionState) {
        let dir = WidgetSnapshot.containerDataDirectory(home: FileManager.default.homeDirectoryForCurrentUser)
        var isDir: ObjCBool = false
        // Never create the container ourselves: macOS does when the widget first runs.
        guard FileManager.default.fileExists(atPath: dir.path, isDirectory: &isDir), isDir.boolValue else { return }
        let reachable = connection == .connected && status != nil
        let vpnConfigured = vpn.map { $0.profile != nil || $0.externalService != nil } ?? false
        var snapshot = WidgetSnapshot(
            protection: reachable ? (status?.protection.rawValue ?? "unreachable") : "unreachable",
            protectionLabel: reachable ? (status?.protection.label ?? "Inconnu") : "Service injoignable",
            openAlerts: status?.openAlerts ?? 0,
            vpnLabel: vpnConfigured ? vpn?.state.label.lowercased() : nil,
            vpnConnected: vpn?.state == .connected,
            travelActive: status?.travelActive ?? false,
            lastScan: status?.lastScan,
            updatedAt: 0
        )
        guard snapshot != lastWritten else { return }
        lastWritten = snapshot
        snapshot.updatedAt = Int64(Date().timeIntervalSince1970)
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        do {
            try data.write(to: dir.appendingPathComponent(WidgetSnapshot.fileName), options: .atomic)
            WidgetCenter.shared.reloadAllTimelines()
        } catch {
            // Widget data is best effort (container access may be refused by the user).
        }
    }
}
