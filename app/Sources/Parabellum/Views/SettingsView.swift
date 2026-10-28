import ParabellumKit
import SwiftUI
import UserNotifications

/// Form bound to a local copy of `Config`; "Enregistrer" sends `set_config` (unknown keys preserved).
struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var draft = Config()
    @State private var loaded = false
    @State private var saving = false

    private var isDirty: Bool {
        guard let config = model.config else { return false }
        return draft != config
    }

    var body: some View {
        VStack(spacing: 0) {
            if loaded {
                Form {
                    scanSection
                    realtimeSection
                    mlSection
                    dnsSection
                    devicesSection
                    persistenceSection
                    updatesSection
                    energySection
                    securitySection
                    privacySection
                    notificationsSection
                }
                .formStyle(.grouped)
                Divider()
                bottomBar
            } else {
                ProgressView("Chargement des réglages…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .navigationTitle("Réglages")
        .task {
            await model.loadConfig()
            resetDraft()
        }
        .onChange(of: model.config) { _, _ in
            if !isDirty || !loaded {
                resetDraft()
            }
        }
    }

    private func resetDraft() {
        guard let config = model.config else { return }
        var copy = config
        if copy.notifications.minSeverity == .unknown {
            copy.notifications.minSeverity = .medium
        }
        draft = copy
        loaded = true
    }

    private var bottomBar: some View {
        HStack {
            let errors = draft.validationErrors()
            if let first = errors.first {
                Label(first, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            } else if isDirty {
                Text("Modifications non enregistrées").foregroundStyle(.secondary)
            }
            Spacer()
            Button("Annuler") {
                resetDraft()
            }
            .disabled(!isDirty || saving)
            Button {
                saving = true
                let toSave = draft
                Task {
                    _ = await model.saveConfig(toSave)
                    saving = false
                }
            } label: {
                Label("Enregistrer", systemImage: "lock.fill")
            }
            .help("Enregistrer demande une autorisation administrateur")
            .keyboardShortcut("s", modifiers: .command)
            .buttonStyle(.borderedProminent)
            .disabled(!isDirty || saving || !errors.isEmpty)
        }
        .padding(12)
    }

    // MARK: Sections

    private var scanSection: some View {
        Section {
            Toggle("Utiliser ClamAV pour les analyses manuelles, volumes et planifiées", isOn: $draft.scan.clamavOnDemand)
            Toggle("Utiliser aussi ClamAV en temps réel (coûteux en mémoire)", isOn: $draft.scan.clamavRealtime)
            Toggle("Analyser le contenu des DMG (montage en lecture seule)", isOn: $draft.scan.mountDmg)
            Toggle("Analyser le contenu des PKG (scripts et charge utile)", isOn: $draft.scan.expandPkg)
            Stepper(value: $draft.scan.maxFileSizeMb, in: 1...4096, step: 10) {
                LabeledContent("Taille max. analysée", value: "\(draft.scan.maxFileSizeMb) Mo")
            }
            Stepper(value: $draft.scan.archiveMaxDepth, in: 0...10) {
                LabeledContent("Archives imbriquées (profondeur)", value: "\(draft.scan.archiveMaxDepth)")
            }
            Stepper(value: $draft.scan.archiveMaxTotalMb, in: 16...16_384, step: 64) {
                LabeledContent("Décompression max. par archive", value: "\(draft.scan.archiveMaxTotalMb) Mo")
            }
            Stepper(value: $draft.scan.archiveMaxEntries, in: 100...1_000_000, step: 1000) {
                LabeledContent("Entrées max. par archive", value: PBFormat.count(draft.scan.archiveMaxEntries))
            }
            StringListEditor(title: "Dossiers surveillés (~ = ton dossier personnel)", placeholder: "~/Downloads", items: $draft.scan.watchPaths)
            StringListEditor(title: "Exclusions (préfixes de chemin)", placeholder: "~/Projets/vm", items: $draft.scan.excludePaths)
        } header: {
            Text("Analyse")
        } footer: {
            Text("Au-delà de la taille max., les fichiers sont seulement hachés. Les limites d'archives protègent contre les bombes de décompression.")
        }
    }

    private var realtimeSection: some View {
        Section {
            Toggle("Protection temps réel", isOn: $draft.realtime.enabled)
            Group {
                Toggle("FSEvents (dossiers surveillés)", isOn: $draft.realtime.fsevents)
                Toggle("eslogger (Endpoint Security, observation)", isOn: $draft.realtime.eslogger)
                Toggle("Analyser les exécutables à leur lancement", isOn: $draft.realtime.scanOnExec)
                Toggle("Quarantaine automatique des fichiers malveillants", isOn: $draft.realtime.autoQuarantine)
                Toggle("Tuer immédiatement un processus malveillant détecté au lancement", isOn: $draft.realtime.killMaliciousProcesses)
            }
            .disabled(!draft.realtime.enabled)
        } header: {
            Text("Temps réel")
        } footer: {
            Text("Sans entitlement Endpoint Security, Parabellum ne peut pas bloquer avant l'exécution : il détecte, met en quarantaine et peut tuer le processus juste après son lancement (jamais sur un verdict ML seul ni pour un binaire Apple).")
        }
    }

    private var mlSection: some View {
        Section {
            Toggle("Classifieur ML sur les exécutables Mach-O", isOn: $draft.ml.enabled)
            Toggle("Seulement les binaires non signés, ad hoc ou non notarisés", isOn: $draft.ml.onlyUntrusted)
                .disabled(!draft.ml.enabled)
            LabeledContent("Seuil « suspect »") {
                HStack {
                    Slider(value: $draft.ml.suspiciousThreshold, in: 0.5...0.99, step: 0.01)
                        .frame(maxWidth: 240)
                    Text(String(format: "%.2f", draft.ml.suspiciousThreshold))
                        .monospacedDigit()
                        .frame(width: 40, alignment: .trailing)
                }
            }
            .disabled(!draft.ml.enabled)
        } header: {
            Text("Apprentissage automatique")
        } footer: {
            Text("Le ML ne rend jamais un fichier « malveillant » et ne met rien en quarantaine : il signale seulement des fichiers suspects.")
        }
    }

    private var dnsSection: some View {
        Section {
            Toggle("Blocage DNS global", isOn: $draft.dns.enabled)
            Toggle("Bloquer les domaines malveillants et de phishing", isOn: $draft.dns.blockMalware)
            Toggle("Bloquer les publicités", isOn: $draft.dns.blockAds)
            Toggle("Bloquer les traqueurs et la télémétrie", isOn: $draft.dns.blockTrackers)
            TextField("Adresse d'écoute", text: $draft.dns.listen)
            StringListEditor(title: "Résolveurs amont (noms dnscrypt-proxy)", placeholder: "cloudflare", items: $draft.dns.upstreamServers)
            StringListEditor(title: "Toujours autoriser", placeholder: "exemple.fr ou *.exemple.fr", items: $draft.dns.customAllow)
            StringListEditor(title: "Toujours bloquer", placeholder: "pub.exemple.com", items: $draft.dns.customBlock)
        } header: {
            Text("DNS anti-pub et anti-malware")
        } footer: {
            Text("Si le résolveur local tombe, les DNS d'origine sont restaurés : Internet n'est jamais coupé.")
        }
    }

    private var devicesSection: some View {
        Section {
            Toggle("Analyser les volumes externes à leur montage", isOn: $draft.devices.scanVolumes)
            Toggle("Alerter pour tout nouveau clavier / HID (BadUSB)", isOn: $draft.devices.alertNewHid)
            Toggle("Bloquer les nouveaux claviers jusqu'à approbation (expérimental)", isOn: $draft.devices.blockNewHid)
            Toggle("Alerter pour les nouveaux périphériques Bluetooth", isOn: $draft.devices.alertBluetooth)
            Toggle("Alerter pour les nouvelles interfaces réseau", isOn: $draft.devices.alertNetworkInterfaces)
            Toggle("Alerter pour les nouveaux périphériques Thunderbolt", isOn: $draft.devices.alertThunderbolt)
            Toggle("Alerter pour les nouveaux réseaux Wi-Fi", isOn: $draft.devices.alertWifiNetworks)
            Toggle("Alerter pour les autres nouveaux périphériques USB", isOn: $draft.devices.alertOtherUsb)
        } header: {
            Text("Périphériques")
        }
    }

    private var persistenceSection: some View {
        Section {
            Toggle("Surveiller la persistance (LaunchAgents, éléments de connexion…)", isOn: $draft.persistence.enabled)
            Stepper(value: $draft.persistence.fullScanIntervalMinutes, in: 15...1440, step: 15) {
                LabeledContent("Énumération complète toutes les", value: PBFormat.duration(seconds: draft.persistence.fullScanIntervalMinutes * 60))
            }
            .disabled(!draft.persistence.enabled)
            Toggle("Chasse quotidienne avec osquery (si installé)", isOn: $draft.persistence.osqueryHunting)
        } header: {
            Text("Persistance")
        }
    }

    private var updatesSection: some View {
        Section {
            Picker("Heure de la mise à jour quotidienne", selection: $draft.updates.dailyHour) {
                ForEach(0..<24, id: \.self) { hour in
                    Text(hour < 10 ? "0\(hour):00" : "\(hour):00").tag(hour)
                }
            }
            Toggle("Mettre à jour automatiquement les composants tiers", isOn: $draft.updates.autoUpdateComponents)
            Toggle("Installer automatiquement les nouvelles versions de Parabellum", isOn: $draft.updates.autoUpdateApp)
            Toggle("Mettre à jour les signatures ClamAV (freshclam)", isOn: $draft.updates.freshclam)
            TextField("URL de la base de menaces", text: $draft.updates.dbBaseUrl)
            TextField("API des releases de l'app", text: $draft.updates.appReleasesApi)
            secretField("Jeton GitHub (dépôt privé, optionnel)", $draft.updates.githubToken)
        } header: {
            Text("Mises à jour")
        } footer: {
            Text("La base est vérifiée (signature minisign) avant d'être activée ; la version précédente est gardée pour revenir en arrière.")
        }
    }

    private var energySection: some View {
        Section {
            Stepper(value: $draft.energy.pauseOnBatteryBelow, in: 0...100, step: 5) {
                LabeledContent(
                    "Reporter les analyses sur batterie sous",
                    value: draft.energy.pauseOnBatteryBelow == 0 ? "jamais" : "\(draft.energy.pauseOnBatteryBelow) %"
                )
            }
            Toggle("Analyses en priorité basse (cœurs efficience)", isOn: $draft.energy.backgroundQos)
        } header: {
            Text("Énergie")
        }
    }

    private static let weekdays = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]

    private var securitySection: some View {
        Section {
            Toggle("Analyse anti-spyware hebdomadaire (Zero Breach Toolkit)", isOn: $draft.security.spywareScanWeekly)
            Picker("Jour", selection: $draft.security.spywareScanWeekday) {
                ForEach(1...7, id: \.self) { day in
                    Text(Self.weekdays[day - 1]).tag(day)
                }
            }
            .disabled(!draft.security.spywareScanWeekly)
            Stepper(value: $draft.security.spywareScanHour, in: 0...23) {
                LabeledContent("Heure", value: "\(draft.security.spywareScanHour) h")
            }
            .disabled(!draft.security.spywareScanWeekly)
            Toggle("Vérifier chaque jour les réglages de sécurité de macOS", isOn: $draft.security.postureChecks)
        } header: {
            Text("Sécurité")
        } footer: {
            Text("L'analyse anti-spyware tourne en lecture seule, sans réseau, avec tes droits (jamais en root). Elle est aussi relancée quand ses indicateurs changent (au plus une fois par jour).")
        }
    }

    private var privacySection: some View {
        Section {
            Toggle("Vérifier l'empreinte des fichiers suspects sur VirusTotal", isOn: $draft.privacy.virustotalLookup)
            secretField("Clé API VirusTotal", $draft.privacy.virustotalApiKey)
                .disabled(!draft.privacy.virustotalLookup)
        } header: {
            Text("Confidentialité")
        } footer: {
            Text("Seule l'empreinte SHA-256 est envoyée, jamais le fichier. Désactivé par défaut.")
        }
    }

    private var notificationsSection: some View {
        Section {
            Toggle("Notifications macOS", isOn: $draft.notifications.enabled)
            Picker("Gravité minimale", selection: $draft.notifications.minSeverity) {
                ForEach(Severity.known, id: \.self) { severity in
                    Text(severity.label).tag(severity)
                }
            }
            .disabled(!draft.notifications.enabled)
            if model.notificationStatus == .denied {
                HStack {
                    Label("Notifications refusées dans Réglages Système", systemImage: "bell.slash")
                        .foregroundStyle(.orange)
                    Spacer()
                    Button("Ouvrir Réglages") {
                        model.open(urlString: AppModel.notificationSettingsURL)
                    }
                }
            } else if model.notificationStatus == .notDetermined {
                Button("Autoriser les notifications") {
                    Task { await model.requestNotificationPermission() }
                }
            }
        } header: {
            Text("Notifications")
        }
    }

    /// Secret config field. Secrets arrive redacted (`********`) unless the config was fetched with
    /// administrator approval: then show "définie" and a "Modifier…" button that asks for it.
    @ViewBuilder
    private func secretField(_ title: String, _ value: Binding<String?>) -> some View {
        if value.wrappedValue == DaemonProtocol.redactedSecret {
            LabeledContent(title) {
                HStack(spacing: 8) {
                    Label("définie", systemImage: "lock.fill")
                        .foregroundStyle(.secondary)
                    Button("Modifier…") {
                        Task { await revealSecrets() }
                    }
                    .disabled(model.isBusy("config-secrets"))
                    .help("Demande une autorisation administrateur pour afficher et modifier la valeur")
                }
            }
        } else {
            SecureField(title, text: optionalText(value), prompt: Text(value.wrappedValue == nil ? "non définie" : ""))
        }
    }

    /// Fetches the config with administrator approval and puts the clear secrets into the draft
    /// (other unsaved edits are kept).
    private func revealSecrets() async {
        guard await model.loadConfig(withSecrets: true), let fresh = model.config else { return }
        if draft.updates.githubToken == DaemonProtocol.redactedSecret {
            draft.updates.githubToken = fresh.updates.githubToken
        }
        if draft.privacy.virustotalApiKey == DaemonProtocol.redactedSecret {
            draft.privacy.virustotalApiKey = fresh.privacy.virustotalApiKey
        }
    }

    /// `String?` ⇄ text field ("" = nil).
    private func optionalText(_ binding: Binding<String?>) -> Binding<String> {
        Binding(
            get: { binding.wrappedValue ?? "" },
            set: { newValue in
                let trimmed = newValue.trimmingCharacters(in: .whitespacesAndNewlines)
                binding.wrappedValue = trimmed.isEmpty ? nil : trimmed
            }
        )
    }
}
