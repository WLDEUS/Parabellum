import Foundation
import ParabellumKit
import UserNotifications

/// Identifiers shared by the delegate (any queue) and the manager (main actor).
enum NotificationKeys {
    static let resolvePrefix = "pb.resolve."
    static let viewActionIdentifier = "pb.view"
    static let alertId = "alert_id"
}

/// `UNUserNotificationCenterDelegate` kept non-isolated: the system may call it on any queue. It only
/// extracts plain values and forwards them to the main actor.
final class NotificationDelegate: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    private let onResponse: @Sendable (String, Int64?) -> Void

    init(onResponse: @escaping @Sendable (String, Int64?) -> Void) {
        self.onResponse = onResponse
    }

    /// Show banners even while the app is frontmost.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list, .sound])
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let actionIdentifier = response.actionIdentifier
        let userInfo = response.notification.request.content.userInfo
        let alertId = (userInfo[NotificationKeys.alertId] as? NSNumber)?.int64Value
        onResponse(actionIdentifier, alertId)
        completionHandler()
    }
}

/// Posts one notification per alert (severity ≥ `notifications.min_severity`), with action buttons
/// mapped to `resolve_alert`.
@MainActor
final class NotificationManager {
    /// Actions that make sense straight from a notification (others need the app).
    private static let notificationActions: [AlertAction] = [
        .killProcess, .quarantine, .allow, .approvePersistence, .trustDevice, .blockDevice, .removePersistence,
    ]

    private weak var model: AppModel?
    private var delegate: NotificationDelegate?
    private var categories: [String: UNNotificationCategory] = [:]

    /// `UNUserNotificationCenter` raises an exception outside an `.app` bundle (e.g. `swift run`).
    static var isAvailable: Bool {
        Bundle.main.bundleIdentifier != nil && Bundle.main.bundleURL.pathExtension == "app"
    }

    private var center: UNUserNotificationCenter? {
        Self.isAvailable ? UNUserNotificationCenter.current() : nil
    }

    /// Sets the delegate (must happen at launch so taps that launched the app are delivered).
    func activate(model: AppModel) {
        self.model = model
        guard let center else { return }
        let delegate = NotificationDelegate { [weak self] actionIdentifier, alertId in
            Task { @MainActor in
                self?.model?.handleNotificationResponse(actionIdentifier: actionIdentifier, alertId: alertId)
            }
        }
        self.delegate = delegate
        center.delegate = delegate
    }

    func authorizationStatus() async -> UNAuthorizationStatus {
        guard let center else { return .denied }
        let settings = await center.notificationSettings()
        return settings.authorizationStatus
    }

    func requestAuthorization() async -> Bool {
        guard let center else { return false }
        do {
            return try await center.requestAuthorization(options: [.alert, .sound, .badge])
        } catch {
            return false
        }
    }

    func post(_ alert: SecurityAlert) async {
        guard let center else { return }
        let status = await authorizationStatus()
        guard status == .authorized || status == .provisional else { return }

        let content = UNMutableNotificationContent()
        content.title = alert.title
        content.subtitle = "\(alert.kind.label) · gravité \(alert.severity.label.lowercased())"
        content.body = alert.message
        content.sound = .default
        content.threadIdentifier = alert.kind.rawValue
        content.categoryIdentifier = registerCategory(for: alert, in: center)
        content.userInfo = [NotificationKeys.alertId: NSNumber(value: alert.id)]

        let request = UNNotificationRequest(identifier: "pb.alert.\(alert.id)", content: content, trigger: nil)
        do {
            try await center.add(request)
        } catch {
            // Notifications are best-effort: the alert is still listed in the app.
        }
    }

    /// One category per combination of actions (categories are fixed sets of buttons).
    private func registerCategory(for alert: SecurityAlert, in center: UNUserNotificationCenter) -> String {
        let actions = alert.knownActions.filter { Self.notificationActions.contains($0) }.prefix(3)
        let identifier = "pb.alert." + (actions.isEmpty ? "view" : actions.map { $0.rawValue }.joined(separator: "+"))
        if categories[identifier] == nil {
            var buttons: [UNNotificationAction] = actions.map { action in
                UNNotificationAction(
                    identifier: NotificationKeys.resolvePrefix + action.rawValue,
                    title: Self.buttonTitle(for: action),
                    options: action == .removePersistence || action == .killProcess ? [.destructive] : []
                )
            }
            buttons.append(UNNotificationAction(identifier: NotificationKeys.viewActionIdentifier, title: "Voir", options: [.foreground]))
            categories[identifier] = UNNotificationCategory(
                identifier: identifier,
                actions: buttons,
                intentIdentifiers: [],
                options: []
            )
            center.setNotificationCategories(Set(categories.values))
        }
        return identifier
    }

    private static func buttonTitle(for action: AlertAction) -> String {
        switch action {
        case .quarantine: return "Mettre en quarantaine"
        case .allow, .approvePersistence: return "Autoriser"
        case .trustDevice: return "Faire confiance"
        case .blockDevice: return "Bloquer"
        case .removePersistence: return "Supprimer"
        case .killProcess: return "Arrêter le processus"
        default: return action.label
        }
    }
}
