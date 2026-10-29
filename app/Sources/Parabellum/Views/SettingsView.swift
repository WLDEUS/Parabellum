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
                    Group {
                        vpnSection
                        guardSection
                        networkGuardSection
                        dataRemovalSection
                        breachSection
                        aliasesSection
                    }
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
            await model.loadExternalVpnServices()
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

    // MARK: Protection sections (VPN, guard, network, privacy services)

    private var vpnSection: some View {
        Section {
            Picker("Connexion automatique", selection: $draft.vpn.mode) {
                ForEach(VpnMode.allCases, id: \.self) { mode in
                    Text(mode.label).tag(mode)
                }
            }
            Picker("Moteur", selection: $draft.vpn.backend) {
                ForEach(VpnBackend.allCases, id: \.self) { backend in
                    Text(backend.label).tag(backend)
                }
            }
            if draft.vpn.backend == .external {
                externalServicePicker
                StringListEditor(
                    title: "Serveurs du VPN autorisés par le kill switch (nom ou IP)",
                    placeholder: "vpn.exemple.com",
                    items: $draft.vpn.externalServerAddresses
                )
            } else {
                Toggle("Faire passer IPv6 dans le tunnel (sinon IPv6 est bloqué pendant la connexion)", isOn: $draft.vpn.tunnelIpv6)
            }
            Toggle("Kill switch : bloquer tout trafic hors du tunnel quand le VPN doit être actif", isOn: $draft.vpn.killSwitch)
            Toggle("Laisser passer le réseau local (imprimante, NAS, AirDrop)", isOn: $draft.vpn.allowLan)
            Stepper(value: $draft.vpn.leakTestIntervalMinutes, in: 0...1440, step: 15) {
                LabeledContent(
                    "Test de fuite automatique",
                    value: draft.vpn.leakTestIntervalMinutes == 0 ? "à la demande" : "toutes les \(PBFormat.duration(seconds: draft.vpn.leakTestIntervalMinutes * 60))"
                )
            }
            LabeledContent("Réseaux de confiance", value: "\(draft.vpn.trustedNetworks.count) (gérés dans la section VPN)")
        } header: {
            Text("VPN")
        } footer: {
            Text("sing-box (open source) reprend les liens de ton fournisseur ou de Shadowrocket. Le kill switch utilise le pare-feu pf de macOS ; il est retiré si le service s'arrête, pour ne jamais te laisser sans Internet.")
        }
    }

    @ViewBuilder
    private var externalServicePicker: some View {
        let names = model.externalVpnServices.map(\.name)
        Picker("VPN configuré dans macOS", selection: $draft.vpn.externalService) {
            Text("Aucun").tag(String?.none)
            ForEach(names, id: \.self) { name in
                Text(name).tag(String?.some(name))
            }
            if let current = draft.vpn.externalService, !names.contains(current) {
                Text("\(current) (introuvable)").tag(String?.some(current))
            }
        }
    }

    private var guardSection: some View {
        Section {
            Toggle("Détecter les vols de mots de passe, cookies et portefeuilles (infostealers)", isOn: $draft.behaviorGuard.stealerDetection)
            Toggle("Arrêter le programme sur une détection sûre", isOn: $draft.behaviorGuard.killOnDetection)
                .disabled(!draft.behaviorGuard.stealerDetection)
            StringListEditor(
                title: "Team ID autorisés à lire les données des navigateurs (gestionnaires de mots de passe…)",
                placeholder: "2BUA8C4S2C",
                items: $draft.behaviorGuard.trustedTeamIds
            )
            Toggle("Détecter les rançongiciels (fichiers leurres, rafales de chiffrement)", isOn: $draft.behaviorGuard.ransomwareDetection)
            Toggle("Suspendre le programme suspect jusqu'à ma décision", isOn: $draft.behaviorGuard.suspendRansomware)
                .disabled(!draft.behaviorGuard.ransomwareDetection)
            Toggle("Instantanés APFS automatiques", isOn: $draft.behaviorGuard.snapshots)
            Stepper(value: $draft.behaviorGuard.snapshotIntervalMinutes, in: 15...1440, step: 15) {
                LabeledContent("Un instantané toutes les", value: PBFormat.duration(seconds: draft.behaviorGuard.snapshotIntervalMinutes * 60))
            }
            .disabled(!draft.behaviorGuard.snapshots)
        } header: {
            Text("Vols de données et rançongiciels")
        } footer: {
            Text("Les binaires Apple et les applications signées par un Team ID de confiance ne sont jamais arrêtés.")
        }
    }

    private var networkGuardSection: some View {
        Section {
            Toggle("Surveiller le réseau (usurpation de la box, faux point d'accès)", isOn: $draft.networkGuard.enabled)
            Stepper(value: $draft.networkGuard.pollSeconds, in: 5...600, step: 5) {
                LabeledContent("Vérification toutes les", value: "\(draft.networkGuard.pollSeconds) s")
            }
            .disabled(!draft.networkGuard.enabled)
        } header: {
            Text("Réseau")
        }
    }

    private var dataRemovalSection: some View {
        Section {
            Toggle("Demander l'effacement de mes données aux courtiers (RGPD)", isOn: $draft.dataRemoval.enabled)
            if hasMaskedIdentifiers {
                maskedIdentifiersRow
            }
            Group {
                ForEach(DataRemovalConfig.knownRegions, id: \.self) { region in
                    Toggle("Courtiers : \(PrivacyLabels.region(region))", isOn: regionBinding(region))
                }
                Picker("Envoi", selection: $draft.dataRemoval.sendMode) {
                    ForEach(SendMode.allCases, id: \.self) { mode in
                        Text(mode.label).tag(mode)
                    }
                }
                TextField("Adresse d'expédition (les réponses y arrivent)", text: $draft.dataRemoval.fromAddress)
                if draft.dataRemoval.sendMode == .smtp {
                    TextField("Serveur SMTP", text: $draft.dataRemoval.smtpHost, prompt: Text("smtp.gmail.com"))
                    TextField("Port SMTP", value: $draft.dataRemoval.smtpPort, format: .number)
                    TextField("Identifiant SMTP", text: $draft.dataRemoval.smtpUsername)
                    secretField("Mot de passe d'application SMTP", $draft.dataRemoval.smtpPassword)
                    Stepper(value: $draft.dataRemoval.maxEmailsPerDay, in: 1...200) {
                        LabeledContent("E-mails par jour au maximum", value: "\(draft.dataRemoval.maxEmailsPerDay)")
                    }
                }
                Stepper(value: $draft.dataRemoval.reminderAfterDays, in: 7...90) {
                    LabeledContent("Relance sans réponse après", value: "\(draft.dataRemoval.reminderAfterDays) jours")
                }
                Stepper(value: $draft.dataRemoval.escalateAfterDays, in: 7...90) {
                    LabeledContent("Plainte CNIL proposée après la relance", value: "\(draft.dataRemoval.escalateAfterDays) jours")
                }
                Stepper(value: $draft.dataRemoval.repeatEveryDays, in: 0...720, step: 30) {
                    LabeledContent(
                        "Renouveler les demandes",
                        value: draft.dataRemoval.repeatEveryDays == 0 ? "jamais" : "tous les \(draft.dataRemoval.repeatEveryDays) jours"
                    )
                }
                Picker("Langue des courriers", selection: $draft.dataRemoval.language) {
                    Text("Français").tag("fr")
                    Text("Anglais").tag("en")
                }
            }
            .disabled(!draft.dataRemoval.enabled)
        } header: {
            Text("Effacement auprès des courtiers en données")
        } footer: {
            Text("L'organisme a un mois pour répondre (article 12 du RGPD). Les courtiers recollectent les données : renouveler les demandes tous les six mois est raisonnable. Les organismes hors UE reçoivent toujours le courrier en anglais.")
        }
    }

    private var breachSection: some View {
        Section {
            Toggle("Surveiller mes adresses dans les fuites de données", isOn: $draft.breach.enabled)
            if hasMaskedIdentifiers {
                maskedIdentifiersRow
            }
            StringListEditor(title: "Adresses surveillées", placeholder: "prenom.nom@exemple.fr", items: $draft.breach.emails)
            Picker("Service", selection: $draft.breach.provider) {
                ForEach(BreachProvider.allCases, id: \.self) { provider in
                    Text(provider.label).tag(provider)
                }
            }
            if draft.breach.provider == .hibp {
                secretField("Clé API Have I Been Pwned", $draft.breach.hibpApiKey)
            }
            Picker("Vérification", selection: $draft.breach.checkIntervalHours) {
                Text("Chaque jour").tag(24)
                Text("Tous les 3 jours").tag(72)
                Text("Chaque semaine").tag(168)
                Text("Chaque mois").tag(720)
                if ![24, 72, 168, 720].contains(draft.breach.checkIntervalHours) {
                    Text("Toutes les \(draft.breach.checkIntervalHours) h").tag(draft.breach.checkIntervalHours)
                }
            }
        } header: {
            Text("Fuites de données")
        } footer: {
            Text("Seule l'adresse e-mail est envoyée au service, jamais de mot de passe.")
        }
    }

    private var aliasesSection: some View {
        Section {
            Picker("Service d'alias", selection: $draft.aliases.provider) {
                ForEach(AliasProvider.allCases, id: \.self) { provider in
                    Text(provider.label).tag(provider)
                }
            }
            if draft.aliases.provider != .disabled {
                secretField("Clé API", $draft.aliases.apiKey)
                TextField("Instance auto-hébergée (https://…, vide = service public)", text: $draft.aliases.baseUrl)
                if draft.aliases.provider == .addy {
                    TextField("Domaine des alias (vide = celui du compte)", text: $draft.aliases.domain)
                }
            }
        } header: {
            Text("Alias e-mail")
        } footer: {
            Text("addy.io et SimpleLogin sont open source. Une adresse par site : tu la coupes si elle fuit.")
        }
    }

    /// Addresses arrive masked (`c***1a2b@…`) unless the config was fetched with administrator approval;
    /// sending them back unchanged keeps the stored values.
    private var hasMaskedIdentifiers: Bool {
        draft.breach.emails.contains { $0.contains("***") }
            || draft.dataRemoval.fromAddress.contains("***")
            || draft.dataRemoval.smtpUsername.contains("***")
    }

    private var maskedIdentifiersRow: some View {
        LabeledContent("Adresses masquées") {
            Button("Afficher…") {
                Task { await revealSecrets() }
            }
            .disabled(model.isBusy("config-secrets"))
            .help("Demande une autorisation administrateur pour afficher et modifier les adresses")
        }
    }

    /// Region on/off over `data_removal.regions` (order kept as in `knownRegions`).
    private func regionBinding(_ region: String) -> Binding<Bool> {
        Binding(
            get: { draft.dataRemoval.regions.contains(region) },
            set: { enabled in
                var set = Set(draft.dataRemoval.regions)
                if enabled {
                    set.insert(region)
                } else {
                    set.remove(region)
                }
                draft.dataRemoval.regions = DataRemovalConfig.knownRegions.filter { set.contains($0) }
                    + draft.dataRemoval.regions.filter { !DataRemovalConfig.knownRegions.contains($0) && set.contains($0) }
            }
        )
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
        let before = model.config
        guard await model.loadConfig(withSecrets: true), let fresh = model.config else { return }
        // Masked identifiers (`c***1a2b@…`) still untouched in the draft get their clear value.
        if let before {
            if draft.breach.emails == before.breach.emails {
                draft.breach.emails = fresh.breach.emails
            }
            if draft.dataRemoval.fromAddress == before.dataRemoval.fromAddress {
                draft.dataRemoval.fromAddress = fresh.dataRemoval.fromAddress
            }
            if draft.dataRemoval.smtpUsername == before.dataRemoval.smtpUsername {
                draft.dataRemoval.smtpUsername = fresh.dataRemoval.smtpUsername
            }
        }
        if draft.updates.githubToken == DaemonProtocol.redactedSecret {
            draft.updates.githubToken = fresh.updates.githubToken
        }
        if draft.privacy.virustotalApiKey == DaemonProtocol.redactedSecret {
            draft.privacy.virustotalApiKey = fresh.privacy.virustotalApiKey
        }
        if draft.dataRemoval.smtpPassword == DaemonProtocol.redactedSecret {
            draft.dataRemoval.smtpPassword = fresh.dataRemoval.smtpPassword
        }
        if draft.breach.hibpApiKey == DaemonProtocol.redactedSecret {
            draft.breach.hibpApiKey = fresh.breach.hibpApiKey
        }
        if draft.aliases.apiKey == DaemonProtocol.redactedSecret {
            draft.aliases.apiKey = fresh.aliases.apiKey
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
