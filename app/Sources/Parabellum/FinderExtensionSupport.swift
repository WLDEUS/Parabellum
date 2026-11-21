import AppKit
import FinderSync

/// The Finder extension (Finder › clic droit › Parabellum): turned on once for this user, and a way to
/// open the system settings where it can be switched on or off.
@MainActor
enum FinderExtensionSupport {
    static let bundleId = "com.wldeus.parabellum.finder"
    private static let enabledOnceKey = "finderExtensionEnabledOnce"

    static var isEnabled: Bool { FIFinderSyncController.isExtensionEnabled }

    /// First launch with the extension inside the app: `pluginkit -e use` (as the user, no prompt).
    /// Later choices made in System Settings are left alone.
    static func enableOnce() {
        let defaults = UserDefaults.standard
        guard !defaults.bool(forKey: enabledOnceKey),
              let plugins = Bundle.main.builtInPlugInsURL,
              FileManager.default.fileExists(atPath: plugins.appendingPathComponent("ParabellumFinder.appex").path) else {
            return
        }
        let id = bundleId
        let key = enabledOnceKey
        DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 3) {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/pluginkit")
            process.arguments = ["-e", "use", "-i", id]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            guard (try? process.run()) != nil else { return }
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                UserDefaults.standard.set(true, forKey: key)
            }
        }
    }

    static func openSettings() {
        FIFinderSyncController.showExtensionManagementInterface()
    }
}
