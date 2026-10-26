import ParabellumKit
import SwiftUI

struct ComponentsView: View {
    @EnvironmentObject private var model: AppModel

    /// Required components first, then by display name.
    private var rows: [ComponentStatus] {
        model.components.sorted { lhs, rhs in
            if lhs.required != rhs.required {
                return lhs.required
            }
            return lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName) == .orderedAscending
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            if rows.isEmpty {
                if model.isBusy("components") {
                    ProgressView("Chargement des composants…")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ContentUnavailableView("Aucun composant", systemImage: "puzzlepiece.extension")
                }
            } else {
                Table(rows) {
                    TableColumn("Composant") { (component: ComponentStatus) in
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 4) {
                                Text(component.displayName)
                                if component.required {
                                    Text("requis")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            if let message = component.message, !message.isEmpty {
                                Text(message)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(2)
                            }
                        }
                    }
                    .width(min: 200, ideal: 260)

                    TableColumn("Version") { (component: ComponentStatus) in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(component.installedVersion ?? "—")
                                .font(.system(.body, design: .monospaced))
                            if let latest = component.latestVersion, latest != component.installedVersion {
                                Text("dernière : \(latest)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                    .width(min: 110, ideal: 140)

                    TableColumn("État") { (component: ComponentStatus) in
                        HStack(spacing: 4) {
                            if model.installingComponents.contains(component.name) || component.state == .updating {
                                ProgressView().controlSize(.mini)
                            }
                            Pill(text: component.state.label, color: component.state.color)
                        }
                    }
                    .width(min: 130, ideal: 170)

                    TableColumn("MAJ auto") { (component: ComponentStatus) in
                        Toggle("", isOn: autoUpdateBinding(for: component))
                            .labelsHidden()
                            .toggleStyle(.checkbox)
                            .disabled(component.isBrowserExtension)
                            .help(component.isBrowserExtension ? "Mis à jour par le Store du navigateur" : "Installer automatiquement les nouvelles versions")
                    }
                    .width(70)

                    TableColumn("") { (component: ComponentStatus) in
                        actionButton(for: component)
                    }
                    .width(min: 110, ideal: 130)
                }
            }
        }
        .navigationTitle("Composants")
        .toolbar {
            ToolbarItemGroup {
                Button {
                    Task { await model.updateNow(.components) }
                } label: {
                    Label("Tout mettre à jour", systemImage: "arrow.triangle.2.circlepath")
                }
                .disabled(model.updateInProgress || model.isBusy("update"))
                .help("Tout mettre à jour")
                RefreshButton(isLoading: model.isBusy("components")) {
                    Task { await model.loadComponents() }
                }
            }
        }
        .task {
            await model.loadComponents()
        }
    }

    private func autoUpdateBinding(for component: ComponentStatus) -> Binding<Bool> {
        Binding(
            get: { component.autoUpdate },
            set: { newValue in
                Task { await model.setAutoUpdate(component.name, enabled: newValue) }
            }
        )
    }

    @ViewBuilder
    private func actionButton(for component: ComponentStatus) -> some View {
        let busy = model.installingComponents.contains(component.name) || model.isBusy("install-\(component.name)")
        switch component.state {
        case .notInstalled:
            if component.isBrowserExtension, let url = component.actionUrl {
                Button("Installer") { openStore(url, for: component) }
            } else {
                Button("Installer") {
                    Task { await model.installComponent(component.name) }
                }
                .disabled(busy)
            }
        case .updateAvailable:
            Button("Mettre à jour") {
                Task { await model.installComponent(component.name) }
            }
            .disabled(busy)
        case .error:
            Button("Réessayer") {
                Task { await model.installComponent(component.name) }
            }
            .disabled(busy)
        case .needsUserAction, .disabled:
            if let url = component.actionUrl {
                Button("Ouvrir") { openStore(url, for: component) }
            }
        case .installed, .updating, .unknown:
            if let url = component.actionUrl {
                Button("Ouvrir") { model.open(urlString: url) }
                    .buttonStyle(.link)
            }
        }
    }

    private func openStore(_ url: String, for component: ComponentStatus) {
        if component.name == "ublock-chrome" {
            model.openInChrome(urlString: url)
        } else if component.name == "ublock-safari" {
            model.openInAppStore(urlString: url)
        } else {
            model.open(urlString: url)
        }
    }
}
