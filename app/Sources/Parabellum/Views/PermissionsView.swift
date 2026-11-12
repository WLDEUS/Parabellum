import ParabellumKit
import SwiftUI

struct PermissionsView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: PermissionsStore

    var body: some View {
        ContentUnavailableView("Permissions", systemImage: "checklist.checked", description: Text("Bientôt disponible."))
            .navigationTitle("Permissions")
            .task { await store.load() }
    }
}
