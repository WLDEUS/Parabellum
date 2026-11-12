import ParabellumKit
import SwiftUI

struct VaultView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: VaultStore

    var body: some View {
        ContentUnavailableView("Coffre", systemImage: "lock.rectangle.stack", description: Text("Bientôt disponible."))
            .navigationTitle("Coffre")
            .task { await store.load() }
    }
}
