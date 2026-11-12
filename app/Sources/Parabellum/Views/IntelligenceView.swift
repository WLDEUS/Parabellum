import ParabellumKit
import SwiftUI

struct IntelligenceView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: IntelligenceStore

    var body: some View {
        ContentUnavailableView("Intelligence", systemImage: "brain.head.profile", description: Text("Bientôt disponible."))
            .navigationTitle("Intelligence")
            .task { await store.load() }
    }
}
