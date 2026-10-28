import AppKit
import ParabellumKit
import SwiftUI

/// Main window: sidebar + one screen per section.
struct MainWindowView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView {
            List(selection: $model.section) {
                // Plain tagged rows (no NavigationLink): the tag type must be exactly the selection type
                // (`SidebarSection?`), otherwise macOS rows are not selectable.
                ForEach(SidebarSection.allCases) { section in
                    Label(section.title, systemImage: section.symbol)
                        .badge(model.badgeCount(for: section))
                        .tag(Optional(section))
                }
            }
            .navigationSplitViewColumnWidth(min: 190, ideal: 215)
        } detail: {
            VStack(spacing: 0) {
                if let banner = model.banner {
                    BannerView(banner: banner) {
                        model.banner = nil
                    }
                    Divider()
                }
                detail
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 860, minHeight: 560)
        .sheet(isPresented: $model.showOnboarding) {
            OnboardingView()
                .environmentObject(model)
        }
        .background(
            WindowAccessor { window in
                model.mainWindowAppeared(window)
            }
        )
        .onAppear {
            model.registerOpenWindow(openWindow)
        }
        .onDisappear {
            model.mainWindowDisappeared()
        }
    }

    @ViewBuilder
    private var detail: some View {
        switch model.connection {
        case .unreachable(let message):
            UnreachableView(message: message, compact: false)
        case .connecting:
            ProgressView("Connexion au service Parabellum…")
        case .connected:
            switch model.section ?? .dashboard {
            case .dashboard: DashboardView()
            case .scan: ScanView()
            case .alerts: AlertsView()
            case .quarantine: QuarantineView()
            case .persistence: PersistenceView()
            case .devices: DevicesView()
            case .network: NetworkView()
            case .components: ComponentsView()
            case .report: ReportView()
            case .settings: SettingsView()
            }
        }
    }
}

/// Shown when `parabellumd` cannot be reached.
struct UnreachableView: View {
    @EnvironmentObject private var model: AppModel
    let message: String
    let compact: Bool

    var body: some View {
        VStack(alignment: compact ? .leading : .center, spacing: compact ? 8 : 14) {
            if !compact {
                Image(systemName: "xmark.shield")
                    .font(.system(size: 54))
                    .foregroundStyle(.red)
                Text("Le service Parabellum ne répond pas")
                    .font(.title2.weight(.semibold))
            } else {
                Label("Le service ne répond pas", systemImage: "xmark.shield")
                    .foregroundStyle(.red)
                    .font(.headline)
            }
            Text(message)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(compact ? .leading : .center)
            Text("La protection temps réel est assurée par parabellumd (LaunchDaemon). Pour le relancer, dans le Terminal :")
                .font(.callout)
                .multilineTextAlignment(compact ? .leading : .center)
                .fixedSize(horizontal: false, vertical: true)
            HStack(spacing: 6) {
                Text(AppModel.kickstartCommand)
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(6)
                    .background(Color.secondary.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
                Button {
                    model.copyToPasteboard(AppModel.kickstartCommand)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .buttonStyle(.borderless)
                .help("Copier la commande")
            }
            Button {
                model.retryConnection()
            } label: {
                Label("Réessayer", systemImage: "arrow.clockwise")
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(compact ? 0 : 40)
        .frame(maxWidth: compact ? .infinity : 620)
    }
}
