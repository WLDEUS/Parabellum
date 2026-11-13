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
                    BrandWordmark()
                        .padding(.horizontal, 8)
                        .padding(.top, 4)
                        .padding(.bottom, 14)
                    ForEach(SidebarGroup.allCases) { group in
                        Text(group.title.uppercased())
                            .font(.system(size: 10, weight: .bold))
                            .tracking(1.2)
                            .foregroundStyle(.tertiary)
                            .padding(.horizontal, 10)
                            .padding(.top, group == .protection ? 0 : 12)
                            .padding(.bottom, 2)
                        ForEach(group.sections) { section in
                            SidebarRow(
                                section: section,
                                selected: (model.section ?? .dashboard) == section,
                                badge: model.badgeCount(for: section)
                            ) {
                                model.section = section
                            }
                        }
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 10)
            }
            .navigationSplitViewColumnWidth(min: 200, ideal: 228)
        } detail: {
            detail
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .scrollContentBackground(.hidden)
                .auroraBackground()
                .overlay(alignment: .top) {
                    if let banner = model.banner {
                        BannerView(banner: banner) {
                            withAnimation(.snappy) { model.banner = nil }
                        }
                    }
                }
                .animation(.snappy(duration: 0.3), value: model.banner?.message)
        }
        .tint(Brand.accent)
        .frame(minWidth: 900, minHeight: 600)
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

    /// Before the first connection: connection screens. Afterwards the current screen stays mounted while
    /// the service is away (a daemon restart must not discard an unsaved Settings draft or an open sheet):
    /// a bar at the bottom tells what happens.
    @ViewBuilder
    private var detail: some View {
        if model.hasConnectedOnce {
            sectionView
                .overlay(alignment: .bottom) {
                    if model.connection != .connected {
                        DisconnectedBar()
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }
                }
                .animation(.snappy(duration: 0.3), value: model.connection == .connected)
        } else {
            switch model.connection {
            case .unreachable(let message):
                UnreachableView(message: message, compact: false)
            case .connecting:
                ProgressView("Connexion au service Parabellum…")
            case .connected:
                sectionView
            }
        }
    }

    @ViewBuilder
    private var sectionView: some View {
        switch model.section ?? .dashboard {
        case .dashboard: DashboardView()
        case .scan: ScanView()
        case .alerts: AlertsView()
        case .quarantine: QuarantineView()
        case .persistence: PersistenceView()
        case .devices: DevicesView()
        case .network: NetworkView()
        case .vpn: VpnView()
        case .behavior: GuardView()
        case .privacy: PrivacyView()
        case .components: ComponentsView()
        case .report: ReportView()
        case .settings: SettingsView()
        case .intelligence: IntelligenceView(store: model.intelligence)
        case .lan: LanView(store: model.lan)
        case .permissions: PermissionsView(store: model.permissionsAudit)
        case .cleaning: CleaningView(store: model.cleaning)
        case .vault: VaultView(store: model.vault)
        }
    }
}

/// Shown over the current screen while the service is unreachable (it reconnects on its own).
private struct DisconnectedBar: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "xmark.shield")
                .foregroundStyle(.red)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.callout.weight(.semibold))
                Text("Les données affichées datent d'avant la coupure ; les actions échoueront jusqu'au retour du service. Relance : \(AppModel.kickstartCommand)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button {
                model.copyToPasteboard(AppModel.kickstartCommand)
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copier la commande de relance")
            Button("Réessayer") {
                model.retryConnection()
            }
            .disabled(model.connection == .connecting)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .glassSurface(cornerRadius: 14, tint: .red)
        .padding(16)
    }

    private var title: String {
        switch model.connection {
        case .unreachable(let message):
            return "Service Parabellum injoignable — reconnexion automatique (\(message))"
        case .connecting, .connected:
            return "Reconnexion au service Parabellum…"
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
                StatusRing(progress: 0.08, color: .red, symbol: "xmark.shield", size: 110)
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
            .buttonStyle(.brand)
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
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: section.symbol)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(selected ? AnyShapeStyle(Color.white) : AnyShapeStyle(Brand.gradient))
                    .frame(width: 20)
                Text(section.title)
                    .fontWeight(selected ? .semibold : .regular)
                Spacer(minLength: 4)
                if badge > 0 {
                    Text("\(badge)")
                        .font(.caption2.weight(.bold))
                        .monospacedDigit()
                        .foregroundStyle(.white)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(Capsule(style: .continuous).fill(selected ? Color.white.opacity(0.28) : Color.orange))
                }
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 7)
            .frame(maxWidth: .infinity, alignment: .leading)
            .foregroundStyle(selected ? Color.white : Color.primary)
            .background {
                if selected {
                    RoundedRectangle(cornerRadius: Brand.Radius.row, style: .continuous)
                        .fill(Brand.gradient)
                        .shadow(color: Brand.indigo.opacity(0.35), radius: 8, y: 3)
                } else if hovering {
                    RoundedRectangle(cornerRadius: Brand.Radius.row, style: .continuous)
                        .fill(Color.primary.opacity(0.06))
                }
            }
            .contentShape(Rectangle())
            .onHover { hovering = $0 }
            .animation(.snappy(duration: 0.2), value: selected)
        }
        .buttonStyle(.plain)
        .help(section.title)
    }
}
