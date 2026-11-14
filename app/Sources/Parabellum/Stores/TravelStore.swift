import AppKit
import Combine
import Darwin
import Foundation
import ParabellumKit

/// State and actions of the "Mode Voyage" feature. Owned by AppModel (`model.*`), survives section switches.
///
/// The daemon (root) handles VPN, kill switch, DNS and the firewall. The per-user part (AirDrop, Bluetooth) is
/// done here, as the user, whenever `StatusInfo.travelActive` changes — also when the daemon enabled travel
/// mode by itself on an untrusted network, or while the app was not running (snapshot kept in UserDefaults).
@MainActor
final class TravelStore: ObservableObject {
    unowned let model: AppModel

    @Published private(set) var status: TravelStatus?
    /// Outcome of the per-user part (French), shown under the toggle.
    @Published private(set) var localMessage: String?

    private var lastLoad: Date?
    private var activeSubscription: AnyCancellable?
    private static let snapshotKey = "travelLocalSnapshot"
    private static let reloadInterval: TimeInterval = 5

    init(model: AppModel) {
        self.model = model
    }

    var isActive: Bool { status?.active ?? model.status?.travelActive ?? false }

    /// The Mac is on a network that is not trusted (from the VPN status, refreshed live).
    var onUntrustedNetwork: Bool {
        if let network = model.vpnStatus?.network {
            return !network.trusted
        }
        return status?.untrustedNetwork ?? false
    }

    var isBusy: Bool { model.isBusy("travel") }

    /// Follow `StatusInfo.travelActive` (called once from `AppModel.start()`).
    func activate() {
        guard activeSubscription == nil else { return }
        activeSubscription = model.$status
            .map { $0?.travelActive }
            .removeDuplicates()
            .sink { [weak self] active in
                guard let self, active != nil else { return }
                Task { await self.load(force: true) }
            }
    }

    /// Called when the section is shown and after (re)connection; returns at once when data is fresh.
    func load() async {
        await load(force: false)
    }

    func load(force: Bool) async {
        if !force, let lastLoad, Date().timeIntervalSince(lastLoad) < Self.reloadInterval, status != nil {
            return
        }
        lastLoad = Date()
        let loaded = await model.perform("travel-status", quiet: true) {
            try await self.model.call(.travelStatus, as: TravelStatus.self)
        }
        if let loaded {
            status = loaded
            reconcileLocal()
        }
    }

    func toggle() async {
        if isActive {
            await disable()
        } else {
            await enable()
        }
    }

    func enable() async {
        let result = await model.perform("travel") {
            try await self.model.call(.travelEnable, as: TravelStatus.self, timeout: 60)
        }
        guard let result else { return }
        status = result
        lastLoad = Date()
        reconcileLocal()
        var parts = ["Mode Voyage activé."]
        parts.append(contentsOf: result.warnings)
        model.banner = Banner(message: parts.joined(separator: " "), isError: false)
        await model.refreshStatus()
    }

    func disable() async {
        let result = await model.perform("travel") {
            try await self.model.call(.travelDisable, as: TravelStatus.self, timeout: 60)
        }
        guard let result else { return }
        status = result
        lastLoad = Date()
        reconcileLocal()
        let message = ["Mode Voyage désactivé : réglages précédents rétablis.", result.message, localMessage]
            .compactMap { $0 }
            .joined(separator: " ")
        model.banner = Banner(message: message, isError: false)
        await model.refreshStatus()
    }

    // MARK: - Per-user part

    private var config: TravelConfig { model.config?.travel ?? TravelConfig() }

    private var savedSnapshot: TravelLocalSnapshot? {
        get {
            guard let data = UserDefaults.standard.data(forKey: Self.snapshotKey) else { return nil }
            return try? JSONDecoder().decode(TravelLocalSnapshot.self, from: data)
        }
        set {
            if let newValue, let data = try? JSONEncoder().encode(newValue) {
                UserDefaults.standard.set(data, forKey: Self.snapshotKey)
            } else {
                UserDefaults.standard.removeObject(forKey: Self.snapshotKey)
            }
        }
    }

    /// Apply (travel on, no snapshot for this session yet) or restore (travel off, snapshot present).
    private func reconcileLocal() {
        guard let status else { return }
        if status.active {
            let session = status.since ?? 0
            if let saved = savedSnapshot, saved.session == session {
                return
            }
            let config = self.config
            let current = TravelLocal.read(includeBluetooth: config.bluetoothOff)
            let target = TravelLocalPlan.enable(current: current, config: config)
            // Saved before changing anything.
            savedSnapshot = TravelLocalSnapshot(session: session, before: current, applied: target)
            let failures = TravelLocal.apply(from: current, to: target)
            let achieved = TravelLocal.read(includeBluetooth: config.bluetoothOff || current.bluetoothOn != nil)
            var applied = target
            if achieved.airdropMode != target.airdropMode {
                applied.airdropMode = current.airdropMode
            }
            if achieved.bluetoothOn != target.bluetoothOn {
                applied.bluetoothOn = current.bluetoothOn
            }
            savedSnapshot = TravelLocalSnapshot(session: session, before: current, applied: applied)
            localMessage = failures.isEmpty ? nil : failures.joined(separator: " ; ")
        } else if let saved = savedSnapshot {
            let current = TravelLocal.read(includeBluetooth: saved.before.bluetoothOn != saved.applied.bluetoothOn)
            let plan = TravelLocalPlan.restore(before: saved.before, applied: saved.applied, current: current)
            let failures = TravelLocal.apply(from: current, to: plan.target)
            savedSnapshot = nil
            var parts: [String] = []
            if !plan.kept.isEmpty {
                parts.append("Modifiés entre-temps, conservés : \(plan.kept.joined(separator: ", ")).")
            }
            parts.append(contentsOf: failures)
            localMessage = parts.isEmpty ? nil : parts.joined(separator: " ")
        }
    }
}

/// AirDrop and Bluetooth, read and written as the logged-in user.
enum TravelLocal {
    static let sharingDomain = "com.apple.sharingd" as CFString
    static let discoverableKey = "DiscoverableMode" as CFString
    /// macOS default when the key was never written.
    static let airdropDefault = "Contacts Only"

    static func read(includeBluetooth: Bool) -> TravelLocalSettings {
        CFPreferencesAppSynchronize(sharingDomain)
        let mode = CFPreferencesCopyAppValue(discoverableKey, sharingDomain) as? String
        return TravelLocalSettings(
            airdropMode: mode ?? airdropDefault,
            bluetoothOn: includeBluetooth ? Bluetooth.isPoweredOn() : nil
        )
    }

    /// Returns French failure messages.
    static func apply(from current: TravelLocalSettings, to target: TravelLocalSettings) -> [String] {
        var failures: [String] = []
        if let mode = target.airdropMode, mode != current.airdropMode {
            CFPreferencesSetAppValue(discoverableKey, mode as CFString, sharingDomain)
            if CFPreferencesAppSynchronize(sharingDomain) {
                // sharingd only reads the preference at launch: restart it (launchd relaunches it on demand).
                runTool("/usr/bin/killall", ["sharingd"])
            } else {
                failures.append("AirDrop n'a pas pu être modifié")
            }
        }
        if let on = target.bluetoothOn, on != current.bluetoothOn {
            if !Bluetooth.setPower(on) {
                failures.append("Bluetooth n'a pas pu être \(on ? "rallumé" : "coupé") (réglez-le dans le Centre de contrôle)")
            }
        }
        return failures
    }

    private static func runTool(_ path: String, _ arguments: [String]) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            // Best effort: the new value applies at the next start of sharingd.
        }
    }
}

/// Bluetooth power through IOBluetooth's preference functions (private but long-standing, used by
/// `blueutil`), looked up at run time so a missing symbol only disables the feature.
enum Bluetooth {
    private typealias GetPower = @convention(c) () -> Int32
    private typealias SetPower = @convention(c) (Int32) -> Void

    private static let handle: UnsafeMutableRawPointer? = dlopen(
        "/System/Library/Frameworks/IOBluetooth.framework/IOBluetooth", RTLD_LAZY
    )

    private static func symbol<T>(_ name: String, as type: T.Type) -> T? {
        guard let handle, let sym = dlsym(handle, name) else { return nil }
        return unsafeBitCast(sym, to: type)
    }

    /// nil when the functions are unavailable.
    static func isPoweredOn() -> Bool? {
        guard let get = symbol("IOBluetoothPreferenceGetControllerPowerState", as: GetPower.self) else { return nil }
        return get() != 0
    }

    static func setPower(_ on: Bool) -> Bool {
        guard let set = symbol("IOBluetoothPreferenceSetControllerPowerState", as: SetPower.self) else { return false }
        set(on ? 1 : 0)
        // The controller takes a moment to change state.
        for _ in 0..<20 {
            if isPoweredOn() == on {
                return true
            }
            usleep(100_000)
        }
        return isPoweredOn() == on
    }
}
