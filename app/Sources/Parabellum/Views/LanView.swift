import AppKit
import ParabellumKit
import SwiftUI

/// "Réseau local": devices of the current network, unknown / new badges, scan with progress.
struct LanView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: LanStore
    @State private var selected: LanDevice?
    @State private var confirmFullScan = false

    private let columns = [GridItem(.adaptive(minimum: 250, maximum: 360), spacing: 14)]

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if store.isFirstLoad {
                    ProgressView("Lecture du réseau local…")
                        .frame(maxWidth: .infinity)
                        .padding(60)
                } else if let network = store.network {
                    LanHeaderCard(store: store, network: network, confirmFullScan: $confirmFullScan)
                    filterBar
                    if store.devices.isEmpty {
                        emptyDevices(network)
                    } else {
                        LazyVGrid(columns: columns, spacing: 14) {
                            ForEach(store.devices) { device in
                                LanDeviceCard(device: device)
                                    .onTapGesture { selected = device }
                                    .contextMenu { contextMenu(device) }
                            }
                        }
                    }
                    if network.lastScanMode == .passive {
                        Label(
                            "Analyse passive : seuls les appareils qui ont échangé récemment avec ce Mac apparaissent.",
                            systemImage: "info.circle"
                        )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    }
                } else {
                    ContentUnavailableView(
                        "Aucun réseau local",
                        systemImage: "wifi.slash",
                        description: Text(store.status?.message ?? "Connecte ce Mac à un réseau pour voir ses appareils.")
                    )
                    .padding(.top, 40)
                }
            }
            .padding(20)
        }
        .auroraBackground()
        .navigationTitle("Réseau local")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy(LanStore.statusKey)) {
                    Task { await store.refresh() }
                }
            }
        }
        .sheet(item: $selected) { device in
            LanDeviceSheet(store: store, mac: device.mac)
                .environmentObject(model)
        }
        .confirmationDialog(
            "Analyser complètement ce réseau ?",
            isPresented: $confirmFullScan,
            titleVisibility: .visible
        ) {
            Button("Lancer l'analyse complète") {
                Task { await store.scan(active: true) }
            }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("Ce réseau n'est pas marqué de confiance. Une analyse complète envoie un petit paquet à chaque adresse du réseau et interroge Bonjour : sur un Wi-Fi public, cela peut être perçu comme une démarche hostile.")
        }
        .task { await store.load() }
    }

    private var filterBar: some View {
        HStack(spacing: 12) {
            Picker("Filtre", selection: $store.filter) {
                ForEach(LanFilter.allCases) { f in
                    Text("\(f.label) (\(store.count(f)))").tag(f)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 480)
            Spacer(minLength: 0)
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Nom, IP, fabricant…", text: $store.search)
                    .textFieldStyle(.plain)
                    .frame(width: 180)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .glassCapsule()
        }
    }

    private func emptyDevices(_ network: LanNetwork) -> some View {
        ContentUnavailableView(
            network.devices.isEmpty ? "Aucun appareil pour l'instant" : "Aucun appareil ne correspond",
            systemImage: "wifi.router",
            description: Text(network.devices.isEmpty ? "Lance une analyse pour inventorier le réseau." : "Modifie le filtre ou la recherche.")
        )
        .frame(maxWidth: .infinity)
        .padding(30)
        .glassSurface()
    }

    @ViewBuilder
    private func contextMenu(_ device: LanDevice) -> some View {
        Button("Détails…") { selected = device }
        if !device.isSelf && !device.isGateway {
            if device.trusted {
                Button("Ne plus considérer comme connu") { Task { await store.setKnown(device, false) } }
            } else {
                Button("Je connais cet appareil") { Task { await store.setKnown(device, true) } }
            }
        }
        if device.online && !device.isSelf && device.ipv4 != nil {
            Button("Vérifier les ports ouverts") { Task { await store.checkPorts(device) } }
        }
        Divider()
        Button("Copier l'adresse IP") { copy(device.ipv4 ?? "") }
        Button("Copier l'adresse matérielle") { copy(device.mac) }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(s, forType: .string)
    }
}

// MARK: - Header

private struct LanHeaderCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: LanStore
    let network: LanNetwork
    @Binding var confirmFullScan: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 16) {
                ZStack {
                    Circle().fill(Brand.indigo.opacity(0.18)).frame(width: 64, height: 64)
                    Image(systemName: network.trusted ? "wifi.router.fill" : "wifi.router")
                        .font(.system(size: 28, weight: .semibold))
                        .foregroundStyle(Brand.gradient)
                }
                VStack(alignment: .leading, spacing: 6) {
                    HStack(spacing: 8) {
                        Text(network.name.isEmpty ? "Réseau actuel" : network.name)
                            .font(.system(.title2, design: .rounded).weight(.semibold))
                        networkPicker
                    }
                    HStack(spacing: 6) {
                        Pill(
                            text: network.trusted ? "Réseau de confiance" : "Réseau non fiable",
                            color: network.trusted ? .green : .orange,
                            symbol: network.trusted ? "checkmark.shield.fill" : "exclamationmark.shield"
                        )
                        if let subnet = network.subnet {
                            Pill(text: subnet, color: .secondary)
                        }
                        if let mode = network.lastScanMode {
                            Pill(text: mode == .active ? "Analyse complète" : "Analyse passive", color: Brand.cyan)
                        }
                    }
                    Text(lastScanText)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                scanControls
            }
            if store.isScanning {
                VStack(alignment: .leading, spacing: 6) {
                    ProgressView(value: store.status?.progress ?? 0)
                        .tint(Brand.indigo)
                    Text(store.status?.phase ?? "Analyse en cours…")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .transition(.opacity)
            }
            if let message = store.status?.message, !store.isScanning {
                Label(message, systemImage: "info.circle")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 12) {
                StatTile(value: "\(store.count(.all))", caption: "Appareils connus de Parabellum", symbol: "square.grid.2x2", tint: Brand.indigo)
                StatTile(value: "\(store.count(.online))", caption: "En ligne maintenant", symbol: "dot.radiowaves.left.and.right", tint: .green)
                StatTile(value: "\(store.count(.unknown))", caption: "Non reconnus", symbol: "questionmark.circle", tint: .orange)
                StatTile(value: "\(store.count(.new))", caption: "Nouveaux (24 h)", symbol: "sparkles", tint: Brand.violet)
            }
        }
        .padding(20)
        .glassSurface()
        .animation(.smooth(duration: 0.3), value: store.isScanning)
    }

    private var lastScanText: String {
        guard let date = network.lastScanDate else { return "Jamais analysé" }
        let every = store.status?.intervalMinutes ?? 15
        return "Dernière analyse \(PBFormat.relative(date)) · automatique toutes les \(every) min"
    }

    @ViewBuilder
    private var networkPicker: some View {
        let others = store.status?.networks ?? []
        if others.count > 1 {
            Menu {
                Button("Réseau actuel") { Task { await store.select(network: nil) } }
                Divider()
                ForEach(others) { n in
                    Button("\(n.name) — \(n.devices) appareil(s)") { Task { await store.select(network: n.id) } }
                }
            } label: {
                Image(systemName: "chevron.down.circle")
            }
            .menuStyle(.button)
            .buttonStyle(.borderless)
            .fixedSize()
            .help("Voir un autre réseau connu")
        }
    }

    private var scanControls: some View {
        VStack(alignment: .trailing, spacing: 8) {
            Button {
                if network.trusted || !network.current {
                    Task { await store.scan() }
                } else {
                    confirmFullScan = true
                }
            } label: {
                if store.isScanning || model.isBusy(LanStore.scanKey) {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small).tint(.white)
                        Text("Analyse…")
                    }
                } else {
                    Label("Analyser maintenant", systemImage: "dot.radiowaves.up.forward")
                }
            }
            .buttonStyle(.brand)
            .disabled(store.isScanning || !network.current)
            if !network.trusted && network.current {
                Button("Lecture passive seulement") { Task { await store.scan(active: false) } }
                    .buttonStyle(.link)
                    .font(.caption)
                    .disabled(store.isScanning)
            }
        }
    }
}

// MARK: - Device card

struct LanDeviceCard: View {
    let device: LanDevice
    @State private var hover = false

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            ZStack(alignment: .bottomTrailing) {
                Image(systemName: device.deviceType.symbol)
                    .font(.system(size: 22, weight: .medium))
                    .foregroundStyle(tint)
                    .frame(width: 46, height: 46)
                    .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                Circle()
                    .fill(device.online ? Color.green : Color.gray.opacity(0.6))
                    .frame(width: 10, height: 10)
                    .overlay(Circle().stroke(.background, lineWidth: 2))
                    .offset(x: 3, y: 3)
                    .accessibilityLabel(device.online ? "En ligne" : "Hors ligne")
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(device.displayName)
                    .font(.headline)
                    .lineLimit(1)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                HStack(spacing: 6) {
                    Text(device.ipv4 ?? "—")
                        .font(.system(.caption, design: .monospaced))
                    Text("·").foregroundStyle(.tertiary)
                    Text(device.online ? "en ligne" : "vu \(PBFormat.relative(device.lastSeenDate))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                badges
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassSurface(cornerRadius: 16, tint: device.isUnknown && device.isNew() ? Color.orange : nil)
        .scaleEffect(hover ? 1.015 : 1)
        .animation(.snappy(duration: 0.18), value: hover)
        .onHover { hover = $0 }
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }

    private var tint: Color {
        if device.isGateway || device.isSelf { return Brand.indigo }
        return device.isUnknown ? .orange : Brand.cyan
    }

    private var subtitle: String {
        var parts = [device.deviceType.label]
        if device.privateMac {
            parts.append("adresse privée")
        } else if let vendor = device.vendor {
            parts.append(vendor)
        }
        if let model = device.model {
            parts.append(model)
        }
        return parts.joined(separator: " · ")
    }

    private var badges: some View {
        HStack(spacing: 4) {
            if device.isSelf {
                Pill(text: "Ce Mac", color: Brand.indigo)
            } else if device.isGateway {
                Pill(text: "Routeur", color: Brand.indigo)
            } else if device.trusted {
                Pill(text: "Connu", color: .green, symbol: "checkmark")
            } else {
                Pill(text: "Inconnu", color: .orange, symbol: "questionmark")
            }
            if device.isNew() && !device.isSelf {
                Pill(text: "Nouveau", color: Brand.violet, symbol: "sparkles")
            }
            if !device.openPorts.isEmpty {
                Pill(text: "\(device.openPorts.count) port(s)", color: .secondary)
            }
        }
        .padding(.top, 2)
    }
}

// MARK: - Device sheet

private struct LanDeviceSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @ObservedObject var store: LanStore
    let mac: String
    @State private var name = ""
    @State private var confirmForget = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let device = store.device(mac) {
                header(device)
                Form {
                    Section("Nom") {
                        HStack {
                            TextField("Nom affiché", text: $name, prompt: Text(device.mdnsName ?? device.hostname ?? "Ex. iPhone de Camille"))
                            Button("Enregistrer") { Task { await store.rename(device, to: name) } }
                                .disabled(model.isBusy("lan.device.\(mac)") || name == (device.name ?? ""))
                        }
                    }
                    Section("Identité") {
                        InfoRow(label: "Adresse IPv4", value: device.ipv4 ?? "—", monospaced: true)
                        InfoRow(label: "Adresse matérielle", value: device.mac, monospaced: true)
                        if device.privateMac {
                            Text("Adresse privée : le téléphone, la tablette ou l'ordinateur masque son adresse réelle. Le fabricant n'est pas identifiable et l'appareil peut revenir avec une autre adresse.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } else {
                            InfoRow(label: "Fabricant", value: device.vendor ?? "Inconnu")
                        }
                        if let model = device.model {
                            InfoRow(label: "Modèle", value: model)
                        }
                        if let host = device.hostname {
                            InfoRow(label: "Nom Bonjour", value: host, monospaced: true)
                        }
                        if !device.ipv6.isEmpty {
                            InfoRow(label: "IPv6", value: device.ipv6.joined(separator: "\n"), monospaced: true)
                        }
                        InfoRow(label: "Vu pour la première fois", value: PBFormat.dateTime(device.firstSeenDate))
                        InfoRow(label: "Vu pour la dernière fois", value: PBFormat.dateTime(device.lastSeenDate))
                    }
                    if !device.services.isEmpty {
                        Section("Services Bonjour") {
                            Text(device.services.joined(separator: ", "))
                                .font(.system(.callout, design: .monospaced))
                                .textSelection(.enabled)
                        }
                    }
                    Section("Ports ouverts") {
                        portsSection(device)
                    }
                }
                .formStyle(.grouped)
                footer(device)
            } else {
                ContentUnavailableView("Appareil oublié", systemImage: "questionmark.app.dashed")
                Button("Fermer") { dismiss() }
            }
        }
        .padding(20)
        .frame(minWidth: 520, minHeight: 560)
        .onAppear { name = store.device(mac)?.name ?? "" }
        .confirmationDialog("Oublier cet appareil ?", isPresented: $confirmForget) {
            Button("Oublier", role: .destructive) {
                if let d = store.device(mac) {
                    Task {
                        await store.forget(d)
                        dismiss()
                    }
                }
            }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("Il sera signalé comme nouveau s'il revient sur le réseau.")
        }
    }

    private func header(_ device: LanDevice) -> some View {
        HStack(spacing: 14) {
            Image(systemName: device.deviceType.symbol)
                .font(.system(size: 30, weight: .medium))
                .foregroundStyle(Brand.gradient)
                .frame(width: 60, height: 60)
                .glassSurface(cornerRadius: 16)
            VStack(alignment: .leading, spacing: 4) {
                Text(device.displayName).font(.title2.weight(.semibold))
                Text(device.deviceType.label).foregroundStyle(.secondary)
            }
            Spacer()
            Button {
                dismiss()
            } label: {
                Image(systemName: "xmark.circle.fill").font(.title2)
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .keyboardShortcut(.cancelAction)
        }
    }

    @ViewBuilder
    private func portsSection(_ device: LanDevice) -> some View {
        if let checked = device.portsCheckedDate {
            if device.openPorts.isEmpty {
                Text("Aucun des 20 ports courants n'est ouvert (vérifié \(PBFormat.relative(checked))).")
                    .foregroundStyle(.secondary)
            } else {
                Text(device.openPorts.map { "\($0) \(Self.portName($0))" }.joined(separator: "\n"))
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
        HStack {
            Button {
                Task { await store.checkPorts(device) }
            } label: {
                if model.isBusy("lan.ports.\(mac)") {
                    ProgressView().controlSize(.small)
                } else {
                    Label("Vérifier les 20 ports courants", systemImage: "network")
                }
            }
            .disabled(!device.online || device.isSelf || device.ipv4 == nil || model.isBusy("lan.ports.\(mac)"))
            Spacer()
        }
        Text("Uniquement à ta demande : quelques connexions TCP vers cet appareil, rien d'autre.")
            .font(.caption)
            .foregroundStyle(.secondary)
    }

    private func footer(_ device: LanDevice) -> some View {
        HStack {
            if !device.isSelf && !device.isGateway {
                Button(role: .destructive) {
                    confirmForget = true
                } label: {
                    Label("Oublier", systemImage: "trash")
                }
            }
            Spacer()
            if !device.isSelf && !device.isGateway {
                if device.trusted {
                    Button("Ne plus considérer comme connu") { Task { await store.setKnown(device, false) } }
                } else {
                    Button {
                        Task { await store.setKnown(device, true) }
                    } label: {
                        Label("Je connais cet appareil", systemImage: "checkmark.seal")
                    }
                    .buttonStyle(.brand)
                    .help("Demande une autorisation administrateur")
                }
            }
        }
        .disabled(model.isBusy("lan.device.\(mac)"))
    }

    static func portName(_ port: Int) -> String {
        switch port {
        case 21: return "FTP"
        case 22: return "SSH"
        case 23: return "Telnet (non chiffré)"
        case 25: return "SMTP"
        case 53: return "DNS"
        case 80: return "HTTP"
        case 139, 445: return "Partage de fichiers (SMB)"
        case 443: return "HTTPS"
        case 515, 631, 9100: return "Impression"
        case 548: return "AFP"
        case 554: return "Flux vidéo (RTSP)"
        case 3389: return "Bureau à distance"
        case 5000: return "UPnP / NAS"
        case 5900: return "Partage d'écran (VNC)"
        case 8008, 8080: return "HTTP alternatif"
        case 8443: return "HTTPS alternatif"
        default: return ""
        }
    }
}
