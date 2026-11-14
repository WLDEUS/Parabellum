import ParabellumKit
import SwiftUI

struct CleaningView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: CleaningStore

    var body: some View {
        ContentUnavailableView("Nettoyage", systemImage: "sparkles", description: Text("Bientôt disponible."))
            .navigationTitle("Nettoyage")
            .task { await store.load() }
    }
}
