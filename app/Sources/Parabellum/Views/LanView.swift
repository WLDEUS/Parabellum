import ParabellumKit
import SwiftUI

struct LanView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: LanStore

    var body: some View {
        ContentUnavailableView("Réseau local", systemImage: "wifi.router", description: Text("Bientôt disponible."))
            .navigationTitle("Réseau local")
            .task { await store.load() }
    }
}
