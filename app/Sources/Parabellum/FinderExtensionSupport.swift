import AppKit
import FinderSync

/// The Finder extension (Finder › clic droit › Parabellum): registered and turned on at every launch
/// unless the user switched it off, with a diagnosis and a repair for Réglages › Finder.
///
/// Why at every launch: the old « once » flag was set as soon as `pluginkit -e use` exited 0, even when
/// the extension was not registered yet (app copied by the installer before LaunchServices saw it), and
/// was never retried: the submenu stayed missing while the Services (same actions) worked.
enum FinderExtensionSupport {
    static let bundleId = "com.wldeus.parabellum.finder"
    private static let pluginkit = "/usr/bin/pluginkit"
    private static let lsregister =
        "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"

    enum State: Equatable {
        /// Not built into this copy of the app (`PARABELLUM_FINDER_EXTENSION=0`, failed optional build).
        case missing
        /// Built in, but unknown to PlugInKit (LaunchServices has not registered it).
        case unregistered
        /// Registered, no choice made yet.
        case undecided
        case enabled
        /// Switched off by the user (System Settings or `pluginkit -e ignore`): left alone.
        case disabledByUser
    }

    static var appexURL: URL? {
        guard let plugins = Bundle.main.builtInPlugInsURL else { return nil }
        let url = plugins.appendingPathComponent("ParabellumFinder.appex")
        return FileManager.default.fileExists(atPath: url.path) ? url : nil
    }

    static var isEnabled: Bool { FIFinderSyncController.isExtensionEnabled }

    /// `pluginkit -m -A -D -i <id>`: one line per registered copy, `+` enabled, `-` ignored, blank undecided.
    static func parse(_ output: String) -> State {
        let lines = output.split(separator: "\n").map(String.init).filter { $0.contains(bundleId) }
        guard !lines.isEmpty else { return .unregistered }
        let marks = lines.compactMap { $0.trimmingCharacters(in: .whitespaces).first }
        if marks.contains("+") { return .enabled }
        if marks.contains("-") { return .disabledByUser }
        return .undecided
    }

    static func state() async -> State {
        guard appexURL != nil else { return .missing }
        let out = await run(pluginkit, ["-m", "-A", "-D", "-i", bundleId]).output
        return parse(out)
    }

    /// Every launch: register when unknown, enable when undecided. A user's « off » is respected.
    static func ensureEnabled() {
        Task.detached(priority: .utility) {
            // Let LaunchServices finish with a freshly installed app first.
            try? await Task.sleep(nanoseconds: 3 * 1_000_000_000)
            _ = await repair(force: false)
        }
    }

    /// Réglages › Finder › « Réparer » (`force`: also re-enables an extension switched off) and launch.
    /// Returns the state reached.
    @discardableResult
    static func repair(force: Bool) async -> State {
        guard let appex = appexURL else { return .missing }
        let app = Bundle.main.bundleURL
        var current = parse(await run(pluginkit, ["-m", "-A", "-D", "-i", bundleId]).output)
        if current == .disabledByUser && !force { return current }
        if current == .unregistered || force {
            _ = await run(lsregister, ["-f", "-R", "-trusted", app.path])
            _ = await run(pluginkit, ["-a", appex.path])
        }
        if current != .enabled {
            _ = await run(pluginkit, ["-e", "use", "-i", bundleId])
        }
        current = parse(await run(pluginkit, ["-m", "-A", "-D", "-i", bundleId]).output)
        if current == .enabled && force {
            // The Finder loads extensions when it starts.
            _ = await run("/usr/bin/killall", ["Finder"])
        }
        return current
    }

    @MainActor
    static func openSettings() {
        FIFinderSyncController.showExtensionManagementInterface()
    }

    /// Short-lived tool, no shell, fixed absolute paths; 10 s timeout.
    private static func run(_ tool: String, _ args: [String]) async -> (status: Int32, output: String) {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .utility).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: tool)
                process.arguments = args
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = FileHandle.nullDevice
                guard (try? process.run()) != nil else {
                    cont.resume(returning: (-1, ""))
                    return
                }
                let timer = DispatchWorkItem { if process.isRunning { process.terminate() } }
                DispatchQueue.global().asyncAfter(deadline: .now() + 10, execute: timer)
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                timer.cancel()
                cont.resume(returning: (process.terminationStatus, String(decoding: data.prefix(64 * 1024), as: UTF8.self)))
            }
        }
    }
}
