import Foundation
import ParabellumKit

/// Device filters of the "Réseau local" screen.
enum LanFilter: String, CaseIterable, Identifiable {
    case all, unknown, new, online

    var id: String { rawValue }

    var label: String {
        switch self {
        case .all: return "Tous"
        case .unknown: return "Inconnus"
        case .new: return "Nouveaux"
        case .online: return "En ligne"
        }
    }
}

/// State and actions of the "Réseau local" feature. Owned by AppModel (`model.*`), survives section switches.
@MainActor
final class LanStore: ObservableObject {
    unowned let model: AppModel

    @Published private(set) var status: LanStatus?
    /// nil = the current network.
    @Published var selectedNetworkId: String?
    @Published var filter: LanFilter = .all
    @Published var search = ""
    private var loadedAt: Date?

    static let statusKey = "lan.status"
    static let scanKey = "lan.scan"
    /// Cached data younger than this is shown without asking the daemon again.
    static let freshness: TimeInterval = 30

    init(model: AppModel) {
        self.model = model
    }

    /// Called when the section is shown and after (re)connection; must return quickly when data is cached.
    func load() async {
        if let loadedAt, Date().timeIntervalSince(loadedAt) < Self.freshness, status != nil {
            return
        }
        await refresh()
    }

    /// Spinner only while nothing is cached yet.
    var isFirstLoad: Bool { status == nil && model.isBusy(Self.statusKey) }

    func refresh() async {
        let networkId = selectedNetworkId
        await model.perform(Self.statusKey, quiet: status != nil) {
            let s = try await self.model.call(.lanStatus(networkId: networkId), as: LanStatus.self)
            if self.selectedNetworkId == networkId {
                self.status = s
                self.loadedAt = Date()
            }
        }
    }

    func select(network id: String?) async {
        selectedNetworkId = id
        loadedAt = nil
        await refresh()
    }

    /// `lan` event: progress and results of the current network.
    func apply(_ s: LanStatus) {
        guard selectedNetworkId == nil || selectedNetworkId == s.network?.id else {
            // Keep the viewed network, but follow the scan progress.
            if let current = status {
                status = current.with(scanning: s.scanning, progress: s.progress, phase: s.phase)
            }
            return
        }
        if s.network == nil, let current = status, s.scanning {
            status = current.with(scanning: true, progress: s.progress, phase: s.phase)
        } else {
            status = s
        }
        loadedAt = Date()
    }

    var network: LanNetwork? { status?.network }
    var isScanning: Bool { status?.scanning == true }

    var devices: [LanDevice] {
        let all = network?.devices ?? []
        let query = search.trimmingCharacters(in: .whitespaces).lowercased()
        return all.filter { d in
            switch filter {
            case .all: break
            case .unknown: if !d.isUnknown { return false }
            case .new: if !d.isNew() { return false }
            case .online: if !d.online { return false }
            }
            guard !query.isEmpty else { return true }
            let haystack = [d.displayName, d.vendor ?? "", d.ipv4 ?? "", d.mac, d.model ?? "", d.deviceType.label]
                .joined(separator: " ")
                .lowercased()
            return haystack.contains(query)
        }
    }

    func count(_ f: LanFilter) -> Int {
        let all = network?.devices ?? []
        switch f {
        case .all: return all.count
        case .unknown: return all.filter(\.isUnknown).count
        case .new: return all.filter { $0.isNew() }.count
        case .online: return all.filter(\.online).count
        }
    }

    /// `active`: nil = policy, true = full scan (asked by the user), false = caches only.
    func scan(active: Bool? = nil) async {
        await model.perform(Self.scanKey) {
            let s = try await self.model.call(.lanScan(active: active), as: LanStatus.self)
            self.apply(s)
        }
    }

    func rename(_ device: LanDevice, to name: String) async {
        guard let networkId = network?.id else { return }
        await model.perform("lan.device.\(device.mac)") {
            _ = try await self.model.call(
                .lanSetDevice(networkId: networkId, mac: device.mac, name: name.trimmingCharacters(in: .whitespaces)),
                as: LanDevice.self
            )
        }
        await refresh()
    }

    func setKnown(_ device: LanDevice, _ known: Bool) async {
        guard let networkId = network?.id else { return }
        await model.perform("lan.device.\(device.mac)") {
            _ = try await self.model.call(
                .lanSetDevice(networkId: networkId, mac: device.mac, trusted: known),
                as: LanDevice.self
            )
        }
        await refresh()
    }

    func forget(_ device: LanDevice) async {
        guard let networkId = network?.id else { return }
        await model.perform("lan.device.\(device.mac)") {
            try await self.model.callVoid(.lanForgetDevice(networkId: networkId, mac: device.mac))
        }
        await refresh()
    }

    /// Returns the updated device (open ports filled).
    @discardableResult
    func checkPorts(_ device: LanDevice) async -> LanDevice? {
        let updated = await model.perform("lan.ports.\(device.mac)") {
            try await self.model.call(.lanPorts(mac: device.mac), as: LanDevice.self, timeout: 60)
        }
        await refresh()
        return updated
    }

    func device(_ mac: String) -> LanDevice? {
        network?.devices.first { $0.mac == mac }
    }
}

extension LanStatus {
    /// Copy with new scan progress (the struct is immutable: re-encoded through JSON).
    func with(scanning: Bool, progress: Double, phase: String?) -> LanStatus {
        guard var json = try? JSONValue(encoding: self), case .object(var o) = json else { return self }
        o["scanning"] = .bool(scanning)
        o["progress"] = .double(progress)
        if let phase {
            o["phase"] = .string(phase)
        } else {
            o.removeValue(forKey: "phase")
        }
        json = .object(o)
        guard let data = try? JSONEncoder().encode(json),
              let copy = try? JSONDecoder().decode(LanStatus.self, from: data)
        else { return self }
        return copy
    }
}
