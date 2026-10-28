import AppKit
import ParabellumKit
import SwiftUI

/// Main window: sidebar + one screen per section.
struct MainWindowView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        NavigationSplitView {
            // Explicit buttons instead of `List(selection:)`: list selection is unreliable in this
            // menu-bar (accessory) app, rows were not clickable on the user's Mac.
            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(SidebarSection.allCases) { section in
                        SidebarRow(
                            section: section,
                            selected: (model.section ?? .dashboard) == section,
                            badge: model.badgeCount(for: section)
                        ) {
                            model.section = section
                        }
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 10)
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

/// One clickable sidebar entry (icon, title, optional badge, selection highlight).
private struct SidebarRow: View {
    let section: SidebarSection
    let selected: Bool
    let badge: Int
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: section.symbol)
                    .frame(width: 18)
                Text(section.title)
                Spacer(minLength: 4)
                if badge > 0 {
                    Text("\(badge)")
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(Color.secondary.opacity(0.25)))
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .foregroundStyle(selected ? Color.white : Color.primary)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(selected ? Color.accentColor : Color.clear)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(section.title)
    }
}
