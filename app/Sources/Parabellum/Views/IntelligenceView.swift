import ParabellumKit
import SwiftUI

/// Intelligence: behavioural baseline learnt on this Mac, phishing-domain model on DNS queries, models.
struct IntelligenceView: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: IntelligenceStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if let status = store.status {
                    IntelHero(status: status)
                    IntelStats(status: status)
                    HStack(alignment: .top, spacing: 16) {
                        AnomaliesCard(store: store, behavior: status.behavior)
                        FlaggedDomainsCard(store: store, domains: status.domains)
                    }
                    HStack(alignment: .top, spacing: 16) {
                        DomainTestCard(store: store)
                        ModelsCard(models: store.models)
                    }
                    BaselineCard(store: store, behavior: status.behavior)
                } else if model.isBusy(IntelligenceStore.refreshKey) {
                    ProgressView("Chargement…")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else {
                    ContentUnavailableView(
                        "Intelligence indisponible",
                        systemImage: "brain.head.profile",
                        description: Text("Le service Parabellum ne répond pas encore.")
                    )
                }
            }
            .padding(20)
        }
        .navigationTitle("Intelligence")
        .toolbar {
            ToolbarItem {
                RefreshButton(isLoading: model.isBusy(IntelligenceStore.refreshKey)) {
                    Task { await store.refresh() }
                }
            }
        }
        .task {
            await store.load()
            // Live-ish while the section is visible (cheap read-only request).
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                if Task.isCancelled { break }
                await store.refresh()
            }
        }
    }
}

// MARK: - Helpers

private func scoreColor(_ score: Double) -> Color {
    if score >= 0.95 { return .red }
    if score >= 0.85 { return .orange }
    return .yellow
}

private func scoreText(_ score: Double) -> String {
    "\(Int((score * 100).rounded())) %"
}

// MARK: - Hero

private struct IntelHero: View {
    let status: IntelligenceStatus

    private var behavior: BehaviorStatus { status.behavior }
    private var domains: DomainIntelStatus { status.domains }

    private var ringColor: Color {
        if !behavior.enabled { return .secondary }
        return behavior.learning ? Brand.cyan : .green
    }

    private var title: String {
        if !behavior.enabled { return "Analyse comportementale désactivée" }
        if behavior.learning {
            return "Apprentissage en cours — \(PBFormat.percent(behavior.learningProgress))"
        }
        return "Ce Mac est sous surveillance comportementale"
    }

    private var subtitle: String {
        if behavior.learning, let until = behavior.learningUntilDate {
            return "Parabellum observe vos habitudes jusqu'au \(PBFormat.dateTime(until)) ; aucune alerte d'anomalie avant."
        }
        if behavior.enabled {
            return "Toute nouveauté d'un programme connu (interpréteur lancé, emplacement sensible modifié…) est notée et signalée au-delà du seuil."
        }
        return "Activez-la dans Réglages › Intelligence."
    }

    var body: some View {
        HStack(spacing: 22) {
            StatusRing(
                progress: behavior.learning ? behavior.learningProgress : 1,
                color: ringColor,
                symbol: behavior.learning ? "brain" : "brain.head.profile"
            )
            VStack(alignment: .leading, spacing: 8) {
                Text(title)
                    .font(.system(.title2, design: .rounded).weight(.semibold))
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    Pill(
                        text: domains.dnsActive ? "DNS Parabellum actif" : "DNS Parabellum inactif",
                        color: domains.dnsActive ? .green : .orange,
                        symbol: "network"
                    )
                    Pill(
                        text: domains.modelLoaded ? "Modèle de domaines chargé" : "Règles de secours",
                        color: domains.modelLoaded ? Brand.indigo : .secondary,
                        symbol: "cpu"
                    )
                    if domains.blockEnabled {
                        Pill(text: "Blocage ML", color: .red, symbol: "hand.raised.fill")
                    }
                    Pill(text: "Données locales uniquement", color: Brand.cyan, symbol: "lock.fill")
                }
                if let message = domains.message ?? behavior.message {
                    Label(message, systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(20)
        .glassSurface(tint: ringColor.opacity(0.08))
    }
}

// MARK: - Stats

private struct IntelStats: View {
    let status: IntelligenceStatus

    var body: some View {
        let b = status.behavior
        let d = status.domains
        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 3), spacing: 12) {
            StatTile(value: PBFormat.count(b.profiles), caption: "Programmes profilés", symbol: "person.text.rectangle")
            StatTile(value: PBFormat.count(b.behaviors), caption: "Comportements connus", symbol: "point.3.connected.trianglepath.dotted")
            StatTile(
                value: PBFormat.count(b.anomalies7d),
                caption: "Anomalies (7 jours)",
                symbol: "exclamationmark.triangle",
                tint: b.anomalies7d > 0 ? .orange : Brand.accent
            )
            StatTile(value: PBFormat.count(Int(d.scored24h)), caption: "Domaines analysés (24 h)", symbol: "globe")
            StatTile(
                value: PBFormat.count(Int(d.flaggedTotal)),
                caption: "Domaines suspects",
                symbol: "exclamationmark.shield",
                tint: d.flaggedTotal > 0 ? .orange : Brand.accent
            )
            StatTile(
                value: d.blockEnabled ? PBFormat.count(d.blockedCount) : "—",
                caption: d.blockEnabled ? "Bloqués par le modèle" : "Blocage ML désactivé",
                symbol: "hand.raised",
                tint: .red
            )
        }
    }
}

// MARK: - Anomalies

private struct AnomaliesCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: IntelligenceStore
    let behavior: BehaviorStatus

    var body: some View {
        Card(title: "Anomalies récentes", symbol: "waveform.path.ecg") {
            if behavior.recentAnomalies.isEmpty {
                Text(behavior.learning ? "Rien à signaler pendant l'apprentissage." : "Aucune nouveauté au-delà du seuil.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(behavior.recentAnomalies.prefix(12)) { a in
                        row(a)
                        if a.id != behavior.recentAnomalies.prefix(12).last?.id {
                            Divider()
                        }
                    }
                }
            }
        }
    }

    private func row(_ a: BehaviorAnomaly) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: a.kind.systemImage)
                .foregroundStyle(scoreColor(a.score))
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 3) {
                Text(a.summary)
                    .font(.callout.weight(.medium))
                    .fixedSize(horizontal: false, vertical: true)
                Text(a.process)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                HStack(spacing: 6) {
                    Pill(text: scoreText(a.score), color: scoreColor(a.score))
                    Text(PBFormat.relative(a.date))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
            if a.markedNormal {
                Pill(text: "Normal", color: .green, symbol: "checkmark")
            } else {
                Button("C'est normal") {
                    Task { await store.markNormal(a) }
                }
                .controlSize(.small)
                .disabled(model.isBusy(IntelligenceStore.normalKey(a.id)))
                .help("Ajouter ce comportement à la référence (autorisation administrateur)")
            }
        }
    }
}

// MARK: - Domains

private struct FlaggedDomainsCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: IntelligenceStore
    let domains: DomainIntelStatus

    var body: some View {
        Card(title: "Domaines signalés", symbol: "globe.badge.chevron.backward") {
            if domains.topFlagged.isEmpty {
                Text(domains.dnsActive ? "Aucun domaine suspect consulté." : "Activez le blocage DNS pour analyser les domaines consultés.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(domains.topFlagged.prefix(12)) { f in
                        row(f)
                        if f.id != domains.topFlagged.prefix(12).last?.id {
                            Divider()
                        }
                    }
                }
            }
        }
    }

    private func row(_ f: FlaggedDomain) -> some View {
        HStack(alignment: .top, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(f.domain)
                    .font(.callout.monospaced().weight(.medium))
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                if let reason = f.reasons.first {
                    Text(reason)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: 6) {
                    Pill(text: scoreText(f.score), color: scoreColor(f.score))
                    if f.blocked {
                        Pill(text: "Bloqué", color: .red, symbol: "hand.raised.fill")
                    }
                    if f.hits > 1 {
                        Text("\(f.hits) requêtes · \(PBFormat.relative(f.lastSeenDate))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text(PBFormat.relative(f.lastSeenDate))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            Spacer(minLength: 0)
            if f.allowed {
                Pill(text: "Autorisé", color: .green, symbol: "checkmark")
            } else {
                Button("Autoriser") {
                    Task { await store.allow(domain: f.registrable) }
                }
                .controlSize(.small)
                .disabled(model.isBusy(IntelligenceStore.allowKey(f.registrable)))
                .help("Ne plus jamais signaler ni bloquer \(f.registrable) (autorisation administrateur)")
            }
        }
    }
}

private struct DomainTestCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: IntelligenceStore

    var body: some View {
        Card(title: "Tester un domaine", symbol: "magnifyingglass") {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    TextField("exemple : paypa1-securite.com", text: $store.testDomain)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { Task { await store.scoreTestDomain() } }
                    Button("Évaluer") {
                        Task { await store.scoreTestDomain() }
                    }
                    .buttonStyle(.brand)
                    .disabled(store.testDomain.trimmingCharacters(in: .whitespaces).isEmpty
                        || model.isBusy(IntelligenceStore.scoreKey))
                }
                if let v = store.verdict {
                    verdictView(v)
                } else {
                    Text("Le nom est évalué localement par le modèle, sans être consulté ni enregistré.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    @ViewBuilder
    private func verdictView(_ v: DomainVerdictInfo) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Text(v.domain).font(.callout.monospaced().weight(.medium))
                if let skipped = v.skipped {
                    Pill(text: "Non évalué : \(skipped)", color: .secondary)
                } else if v.wouldBlock {
                    Pill(text: "Malveillant", color: .red, symbol: "xmark.octagon.fill")
                } else if v.flagged {
                    Pill(text: "Suspect", color: .orange, symbol: "exclamationmark.triangle.fill")
                } else {
                    Pill(text: "Rien d'anormal", color: .green, symbol: "checkmark.seal.fill")
                }
                if let score = v.score {
                    Text(scoreText(score)).font(.caption).monospacedDigit().foregroundStyle(.secondary)
                }
                if v.allowed {
                    Pill(text: "Autorisé", color: .green)
                }
            }
            if v.source == "heuristic" {
                Text("Évalué par les règles de secours (modèle pas encore disponible).")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            ForEach(v.reasons, id: \.self) { r in
                Label(r, systemImage: "smallcircle.filled.circle")
                    .font(.caption)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassSurface(cornerRadius: Brand.Radius.row)
    }
}

// MARK: - Models

private struct ModelsCard: View {
    let models: [IntelModelInfo]

    var body: some View {
        Card(title: "Modèles", symbol: "cpu") {
            if models.isEmpty {
                Text("Aucun modèle chargé.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(models) { m in
                        row(m)
                    }
                }
            }
        }
    }

    private func metric(_ m: IntelModelInfo, _ key: String, _ label: String, percent: Bool) -> String? {
        guard let v = m.metrics[key] else { return nil }
        return percent ? "\(label) \(String(format: "%.2f", v * 100)) %" : "\(label) \(String(format: "%.3f", v))"
    }

    private func row(_ m: IntelModelInfo) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 8) {
                Text(m.name).font(.callout.weight(.medium))
                Spacer(minLength: 0)
                Pill(
                    text: m.loaded ? "Actif" : "Inactif",
                    color: m.loaded ? .green : .secondary,
                    symbol: m.loaded ? "checkmark.circle.fill" : "pause.circle"
                )
            }
            let facts = [
                m.version.map { "version \($0)" },
                m.threshold.map { "seuil \(String(format: "%.2f", $0))" },
                metric(m, "auc", "AUC", percent: false),
                metric(m, "tpr_at_threshold", "détection", percent: true),
                metric(m, "fpr_at_threshold", "faux positifs", percent: true),
            ].compactMap { $0 }
            if !facts.isEmpty {
                Text(facts.joined(separator: " · "))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            if let detail = m.detail {
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

// MARK: - Baseline

private struct BaselineCard: View {
    @EnvironmentObject private var model: AppModel
    @ObservedObject var store: IntelligenceStore
    let behavior: BehaviorStatus
    @State private var confirmReset = false

    var body: some View {
        Card(title: "Référence comportementale", symbol: "externaldrive.badge.checkmark") {
            VStack(alignment: .leading, spacing: 8) {
                InfoRow(label: "Événements observés", value: PBFormat.count(Int(behavior.eventsObserved)))
                InfoRow(label: "Taille sur le disque", value: PBFormat.bytes(Int(behavior.baselineBytes)))
                if let start = behavior.learningStartedAt {
                    InfoRow(label: "Apprentissage commencé", value: PBFormat.dateTime(unixSeconds: start))
                }
                Text("La référence est stockée dans le dossier de Parabellum (lisible par root uniquement), bornée en taille, et n'est jamais envoyée hors de ce Mac.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    Spacer()
                    Button("Recommencer l'apprentissage…", role: .destructive) {
                        confirmReset = true
                    }
                    .disabled(model.isBusy(IntelligenceStore.resetKey))
                }
            }
        }
        .confirmationDialog(
            "Effacer la référence comportementale ?",
            isPresented: $confirmReset,
            titleVisibility: .visible
        ) {
            Button("Effacer et réapprendre", role: .destructive) {
                Task { await store.resetBaseline() }
            }
        } message: {
            Text("Parabellum oubliera ce qu'il a appris et ne signalera plus d'anomalie pendant la nouvelle période d'apprentissage.")
        }
    }
}
