import AppKit
import ParabellumKit
import SwiftUI

/// "Permissions": who holds the sensitive privacy permissions, and the browser extensions.
struct PermissionsView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: PermissionsStore
    @State private var pendingReset: TccGrant?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                summary
                controls
                switch store.tab {
                case .apps: appsTab
                case .extensions: extensionsTab
                }
            }
            .padding(20)
        }
        .auroraBackground()
        .navigationTitle("Permissions")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy(PermissionsStore.auditKey) || model.isBusy(PermissionsStore.extensionsKey)) {
                    Task { await store.refreshAll() }
                }
            }
        }
        .confirmationDialog(
            "Retirer cette autorisation ?",
            isPresented: Binding(get: { pendingReset != nil }, set: { if !$0 { pendingReset = nil } }),
            titleVisibility: .visible,
            presenting: pendingReset
        ) { grant in
            Button("Retirer « \(grant.serviceLabel) » à \(grant.displayName)", role: .destructive) {
                Task { await store.reset(grant) }
            }
            Button("Ouvrir Réglages Système") { store.openSettings(grant) }
            Button("Annuler", role: .cancel) {}
        } message: { grant in
            Text("macOS redemandera l'autorisation la prochaine fois que \(grant.displayName) en aura besoin (tccutil reset, exécuté avec ton compte).")
        }
        .task { await store.load() }
    }

    // MARK: Summary

    private var summary: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Qui a accès à quoi")
                        .font(.system(.title2, design: .rounded).weight(.semibold))
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if model.isBusy(PermissionsStore.auditKey) && store.report != nil {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Audit en cours…").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            HStack(spacing: 12) {
                StatTile(value: "\(store.count(risk: .high))", caption: "Risque élevé", symbol: "exclamationmark.triangle.fill", tint: .orange)
                StatTile(value: "\(store.count(risk: .medium))", caption: "Accès puissants à vérifier", symbol: "eye", tint: .yellow)
                StatTile(value: "\(store.staleCount)", caption: "Autorisations orphelines", symbol: "trash.slash", tint: Brand.cyan)
                StatTile(value: "\(store.riskyExtensions)", caption: "Extensions à risque", symbol: "puzzlepiece.extension", tint: Brand.violet)
            }
            if let report = store.report {
                ForEach(report.errors, id: \.self) { e in
                    Label(e, systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if !report.configurationProfiles.isEmpty {
                    Label(
                        "Profils de configuration installés : \(report.configurationProfiles.joined(separator: ", ")). Un profil peut accorder des permissions sans les afficher ici.",
                        systemImage: "doc.badge.gearshape"
                    )
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .padding(20)
        .glassSurface()
    }

    private var subtitle: String {
        guard let r = store.report else { return "Lecture des autorisations de confidentialité…" }
        return "\(r.grants.filter(\.isGranted).count) autorisations accordées · audit \(PBFormat.relative(r.generatedDate)) · bases lues : "
            + [r.systemDbRead ? "système" : nil, r.userDbRead ? "utilisateur" : nil].compactMap { $0 }.joined(separator: " + ")
    }

    private var controls: some View {
        HStack(spacing: 12) {
            Picker("Vue", selection: $store.tab) {
                ForEach(PermissionsTab.allCases) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 360)
            Picker("Risque", selection: $store.riskFilter) {
                ForEach(RiskFilter.allCases) { Text($0.label).tag($0) }
            }
            .labelsHidden()
            .frame(width: 170)
            Toggle(store.tab == .apps ? "Afficher les refus" : "Afficher les désactivées", isOn: $store.showDenied)
                .toggleStyle(.checkbox)
            Spacer(minLength: 0)
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Rechercher", text: $store.search)
                    .textFieldStyle(.plain)
                    .frame(width: 150)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .glassCapsule()
        }
    }

    // MARK: Apps

    @ViewBuilder
    private var appsTab: some View {
        if store.isFirstLoad {
            ProgressView("Audit des permissions (signature de chaque app)…")
                .frame(maxWidth: .infinity)
                .padding(50)
        } else if store.groups.isEmpty {
            ContentUnavailableView(
                store.report == nil ? "Audit indisponible" : "Rien à afficher",
                systemImage: "checklist.checked",
                description: Text(store.report == nil ? "Le service Parabellum n'a pas pu lire les permissions." : "Aucune autorisation ne correspond aux filtres.")
            )
            .frame(maxWidth: .infinity)
            .padding(30)
            .glassSurface()
        } else {
            ForEach(store.groups) { group in
                PermissionGroupCard(group: group, store: store, onReset: { pendingReset = $0 })
            }
        }
    }

    // MARK: Extensions

    @ViewBuilder
    private var extensionsTab: some View {
        if store.extensions == nil && model.isBusy(PermissionsStore.extensionsKey) {
            ProgressView("Lecture des profils des navigateurs…")
                .frame(maxWidth: .infinity)
                .padding(50)
        } else if store.extensionGroups.isEmpty {
            ContentUnavailableView(
                "Aucune extension",
                systemImage: "puzzlepiece.extension",
                description: Text("Aucune extension ne correspond aux filtres (Chrome, Brave, Edge, Arc, Chromium, Vivaldi, Firefox et Safari sont examinés).")
            )
            .frame(maxWidth: .infinity)
            .padding(30)
            .glassSurface()
        } else {
            ForEach(store.extensionGroups, id: \.browser) { group in
                Card(title: BrowserLabels.label(group.browser), symbol: "safari") {
                    VStack(spacing: 0) {
                        ForEach(group.items) { ext in
                            ExtensionRow(ext: ext)
                            if ext.id != group.items.last?.id {
                                Divider().opacity(0.4)
                            }
                        }
                    }
                }
            }
            ForEach(store.extensions?.errors ?? [], id: \.self) { e in
                Label(e, systemImage: "info.circle").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// MARK: - Grants

private struct PermissionGroupCard: View {
    let group: PermissionGroup
    @ObservedObject var store: PermissionsStore
    let onReset: (TccGrant) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: PermissionsView.symbol(for: group.service))
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(group.maxRisk.color)
                    .frame(width: 30, height: 30)
                    .background(group.maxRisk.color.opacity(0.14), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                Text(group.label).font(.system(.headline, design: .rounded))
                Text("\(group.grants.count)").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if let first = group.grants.first {
                    Button("Réglages") { store.openSettings(first) }
                        .buttonStyle(.link)
                        .font(.caption)
                }
            }
            VStack(spacing: 0) {
                ForEach(group.grants) { grant in
                    GrantRow(grant: grant, store: store, onReset: onReset)
                    if grant.id != group.grants.last?.id {
                        Divider().opacity(0.4)
                    }
                }
            }
        }
        .padding(18)
        .glassSurface(tint: group.maxRisk >= .high ? Color.orange : nil)
    }
}

private struct GrantRow: View {
    @EnvironmentObject private var model: AppModel
    let grant: TccGrant
    @ObservedObject var store: PermissionsStore
    let onReset: (TccGrant) -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            appIcon
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(grant.displayName).font(.body.weight(.medium)).lineLimit(1)
                    if let target = grant.targetName ?? grant.target {
                        Image(systemName: "arrow.right").font(.caption2).foregroundStyle(.secondary)
                        Text(target).font(.callout).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                Text(grant.client)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                HStack(spacing: 4) {
                    SeverityBadge(severity: grant.risk)
                    signingPill
                    if grant.installed == false {
                        Pill(text: "App absente", color: Brand.cyan, symbol: "trash.slash")
                    }
                    if grant.auth != .allowed {
                        Pill(text: grant.auth.label, color: .secondary)
                    }
                    Pill(text: grant.systemWide ? "Système" : "Utilisateur", color: .secondary)
                }
                if let reason = grant.reasons.first, grant.risk >= .medium || grant.installed == false {
                    Text(grant.reasons.prefix(2).joined(separator: " · "))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityLabel(reason)
                }
            }
            Spacer(minLength: 8)
            actions
        }
        .padding(.vertical, 9)
    }

    @ViewBuilder
    private var appIcon: some View {
        if let image = store.icon(for: grant.appPath ?? (grant.clientIsPath ? grant.client : nil)) {
            Image(nsImage: image)
                .resizable()
                .frame(width: 32, height: 32)
        } else {
            Image(systemName: grant.clientIsPath ? "terminal" : "app.dashed")
                .font(.system(size: 20))
                .foregroundStyle(.secondary)
                .frame(width: 32, height: 32)
        }
    }

    @ViewBuilder
    private var signingPill: some View {
        if let s = grant.signing {
            if s.apple {
                Pill(text: "Apple", color: .green, symbol: "apple.logo")
            } else if !s.signed {
                Pill(text: "Non signée", color: .red, symbol: "xmark.seal")
            } else if s.adhoc {
                Pill(text: "Signature ad hoc", color: .orange, symbol: "seal")
            } else if s.notarized == false {
                Pill(text: "Non notarisée", color: .orange, symbol: "seal")
            } else if let team = s.teamId {
                Pill(text: "Développeur \(team)", color: .green, symbol: "checkmark.seal")
            }
        }
    }

    private var actions: some View {
        HStack(spacing: 6) {
            if let path = grant.appPath {
                Button {
                    store.revealInFinder(path)
                } label: {
                    Image(systemName: "folder")
                }
                .buttonStyle(.borderless)
                .help("Afficher dans le Finder")
            }
            Button {
                store.openSettings(grant)
            } label: {
                Image(systemName: "gearshape")
            }
            .buttonStyle(.borderless)
            .help("Ouvrir le volet de Réglages Système correspondant")
            if grant.canReset && grant.isGranted {
                Button("Réinitialiser") { onReset(grant) }
                    .controlSize(.small)
                    .disabled(model.isBusy("permissions.reset.\(grant.id)"))
            }
        }
    }
}

// MARK: - Extensions

private struct ExtensionRow: View {
    let ext: BrowserExtension
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 10) {
                Image(systemName: "puzzlepiece.extension.fill")
                    .foregroundStyle(ext.risk.color)
                    .frame(width: 28, height: 28)
                    .background(ext.risk.color.opacity(0.12), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(ext.name).font(.body.weight(.medium)).lineLimit(1)
                        if let v = ext.version {
                            Text(v).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Text("\(ext.profile) · \(ext.extensionId)")
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                Spacer()
                SeverityBadge(severity: ext.risk)
                if ext.unpacked {
                    Pill(text: "Non empaquetée", color: .orange)
                } else if ext.fromStore == false && ext.browser != "safari" {
                    Pill(text: "Hors boutique", color: .orange)
                }
                if ext.enabled == false {
                    Pill(text: "Désactivée", color: .secondary)
                }
                Button {
                    withAnimation(.snappy) { expanded.toggle() }
                } label: {
                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(expanded ? "Masquer le détail" : "Afficher le détail")
            }
            if expanded {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(ext.reasons, id: \.self) { r in
                        Label(r, systemImage: "smallcircle.filled.circle").font(.caption)
                    }
                    if !ext.hostPermissions.isEmpty {
                        Text("Sites : \(ext.hostPermissions.prefix(8).joined(separator: ", "))\(ext.hostPermissions.count > 8 ? "…" : "")")
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    if let path = ext.path {
                        Text(path)
                            .font(.system(.caption2, design: .monospaced))
                            .foregroundStyle(.tertiary)
                            .textSelection(.enabled)
                    }
                    Text("Pour la retirer : menu Extensions du navigateur › Supprimer.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.leading, 38)
                .transition(.opacity)
            }
        }
        .padding(.vertical, 8)
    }
}

extension PermissionsView {
    /// SF Symbol per TCC service (macOS 14).
    static func symbol(for service: String) -> String {
        switch service {
        case "kTCCServiceAccessibility": return "accessibility"
        case "kTCCServiceScreenCapture": return "rectangle.dashed.badge.record"
        case "kTCCServiceSystemPolicyAllFiles", "kTCCServiceSystemPolicySysAdminFiles": return "internaldrive"
        case "kTCCServiceListenEvent": return "keyboard"
        case "kTCCServicePostEvent": return "cursorarrow.click.2"
        case "kTCCServiceEndpointSecurityClient": return "shield.lefthalf.filled"
        case "kTCCServiceDeveloperTool": return "hammer"
        case "kTCCServiceAppleEvents": return "gearshape.2"
        case "kTCCServiceSystemPolicyAppBundles", "kTCCServiceSystemPolicyAppData": return "app.badge"
        case "kTCCServiceCamera": return "camera"
        case "kTCCServiceMicrophone": return "mic"
        case "kTCCServicePhotos", "kTCCServicePhotosAdd": return "photo.on.rectangle"
        case "kTCCServiceAddressBook": return "person.crop.circle"
        case "kTCCServiceCalendar": return "calendar"
        case "kTCCServiceReminders": return "checklist"
        case "kTCCServiceLocation": return "location"
        case "kTCCServiceBluetoothAlways": return "antenna.radiowaves.left.and.right"
        case "kTCCServiceMediaLibrary": return "music.note"
        case "kTCCServiceSpeechRecognition": return "waveform"
        default:
            return service.hasPrefix("kTCCServiceSystemPolicy") ? "folder" : "lock.shield"
        }
    }
}
