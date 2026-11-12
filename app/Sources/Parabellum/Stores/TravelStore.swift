import Foundation
import ParabellumKit

/// State and actions of the "Mode Voyage" feature. Owned by AppModel (`model.*`), survives section switches.
@MainActor
final class TravelStore: ObservableObject {
    unowned let model: AppModel

    init(model: AppModel) {
        self.model = model
    }

    /// Called when the section is shown and after (re)connection; must return quickly when data is cached.
    func load() async {}
}
