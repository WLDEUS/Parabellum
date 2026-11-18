import Charts
import ParabellumKit
import SwiftUI

// Charts and figures of the activity report, shared by the screen (`ReportView`) and the PDF pages
// (`ReportPDF`). Each view only needs the report: no environment objects (ImageRenderer-safe).

enum ReportText {
    static func count(_ n: Int) -> String { PBFormat.count(n) }

    static func hours(_ secs: Int) -> String {
        secs < 60 ? "0 min" : PBFormat.duration(seconds: secs)
    }

    static func alertKind(_ raw: String) -> String {
        AlertKind(rawValue: raw).map { $0 == .unknown ? raw : $0.label } ?? raw
    }

    static func origin(_ raw: String) -> String {
        ScanOrigin(rawValue: raw).map { $0.label } ?? raw
    }

    /// Key figures (value, caption, SF Symbol, tint).
    static func figures(_ r: ActivityReport) -> [(String, String, String, Color)] {
        [
            (count(r.filesScanned), "fichiers analysés", "doc.text.magnifyingglass", Brand.indigo),
            (count(r.threatsDetected), "menaces détectées", "ladybug.fill", r.threatsDetected > 0 ? .red : .green),
            (count(r.quarantined), "mises en quarantaine", "archivebox.fill", .orange),
            (count(r.scans), "analyses", "magnifyingglass", Brand.cyan),
            (r.dnsBlockedQueries.map { count($0) } ?? "—", "pubs et traqueurs bloqués", "hand.raised.slash.fill", Brand.violet),
            (count(r.alertsTotal), "alertes", "bell.badge.fill", .orange),
            (count(r.falsePositivesReported), "faux positifs signalés", "hand.thumbsup.fill", Color.gray),
            (count(r.dbUpdates), "mises à jour de la base", "cylinder.split.1x2.fill", .teal),
        ]
    }
}

/// Files scanned per day (bars) with threats (red points).
struct DailyActivityChart: View {
    let report: ActivityReport

    var body: some View {
        if report.daily.isEmpty {
            Text("Pas encore d'activité enregistrée sur cette période.")
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, minHeight: 80)
        } else {
            Chart {
                ForEach(report.daily) { day in
                    BarMark(
                        x: .value("Jour", day.day, unit: .day),
                        y: .value("Fichiers analysés", day.filesScanned)
                    )
                    .foregroundStyle(Brand.gradient)
                    .cornerRadius(3)
                }
                ForEach(report.daily.filter { $0.threats > 0 }) { day in
                    PointMark(
                        x: .value("Jour", day.day, unit: .day),
                        y: .value("Fichiers analysés", day.filesScanned)
                    )
                    .foregroundStyle(.red)
                    .symbolSize(70)
                    .annotation(position: .top) {
                        Text("\(day.threats) ⚠︎").font(.caption2.bold()).foregroundStyle(.red)
                    }
                }
            }
            .chartYAxisLabel("Fichiers analysés")
            .frame(height: 170)
        }
    }
}

/// Blocked queries per day.
struct DnsBlockedChart: View {
    let report: ActivityReport

    var body: some View {
        let days = report.daily.filter { $0.dnsBlocked > 0 }
        if days.isEmpty {
            Text(report.dnsBlockedQueries == nil ? "Blocage DNS désactivé sur cette période." : "Aucun blocage enregistré.")
                .foregroundStyle(.secondary)
        } else {
            Chart(days) { day in
                AreaMark(
                    x: .value("Jour", day.day, unit: .day),
                    y: .value("Requêtes bloquées", day.dnsBlocked)
                )
                .foregroundStyle(
                    LinearGradient(colors: [Brand.violet.opacity(0.55), Brand.violet.opacity(0.05)], startPoint: .top, endPoint: .bottom)
                )
                .interpolationMethod(.catmullRom)
                LineMark(
                    x: .value("Jour", day.day, unit: .day),
                    y: .value("Requêtes bloquées", day.dnsBlocked)
                )
                .foregroundStyle(Brand.violet)
                .interpolationMethod(.catmullRom)
            }
            .frame(height: 130)
        }
    }
}

/// Horizontal bars of a top list.
struct TopListChart: View {
    let items: [NamedCount]
    var color: Color = Brand.indigo
    var label: (String) -> String = { $0 }
    var empty = "Rien sur cette période."

    var body: some View {
        if items.isEmpty {
            Text(empty).foregroundStyle(.secondary)
        } else {
            Chart(items) { item in
                BarMark(
                    x: .value("Nombre", item.count),
                    y: .value("Nom", label(item.name))
                )
                .foregroundStyle(color.gradient)
                .cornerRadius(3)
                .annotation(position: .trailing) {
                    Text(PBFormat.count(item.count)).font(.caption).foregroundStyle(.secondary)
                }
            }
            .chartXAxis(.hidden)
            .frame(height: max(60, CGFloat(items.count) * 26))
        }
    }
}

/// Alerts per kind (donut).
struct AlertKindsChart: View {
    let report: ActivityReport

    var body: some View {
        if report.topAlertKinds.isEmpty {
            Text("Aucune alerte sur cette période.").foregroundStyle(.secondary)
        } else {
            HStack(alignment: .center, spacing: 18) {
                Chart(report.topAlertKinds) { kind in
                    SectorMark(
                        angle: .value("Alertes", kind.count),
                        innerRadius: .ratio(0.62),
                        angularInset: 1.5
                    )
                    .cornerRadius(3)
                    .foregroundStyle(by: .value("Type", ReportText.alertKind(kind.name)))
                }
                .chartLegend(.hidden)
                .frame(width: 120, height: 120)
                .overlay {
                    VStack(spacing: 0) {
                        Text(PBFormat.count(report.alertsTotal)).font(.title3.bold()).monospacedDigit()
                        Text("alertes").font(.caption2).foregroundStyle(.secondary)
                    }
                }
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(report.topAlertKinds) { kind in
                        HStack {
                            Text(ReportText.alertKind(kind.name))
                            Spacer()
                            Text(PBFormat.count(kind.count)).monospacedDigit().foregroundStyle(.secondary)
                        }
                        .font(.callout)
                    }
                }
            }
        }
    }
}

/// VPN uptime ring + leak tests + network alerts.
struct NetworkSummary: View {
    let report: ActivityReport

    var body: some View {
        HStack(spacing: 20) {
            ZStack {
                Circle().stroke(Brand.cyan.opacity(0.18), lineWidth: 10)
                Circle()
                    .trim(from: 0, to: max(0.001, report.vpnUptimeFraction))
                    .stroke(Brand.cyan, style: StrokeStyle(lineWidth: 10, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                VStack(spacing: 0) {
                    Text(PBFormat.percent(report.vpnUptimeFraction)).font(.headline).monospacedDigit()
                    Text("VPN").font(.caption2).foregroundStyle(.secondary)
                }
            }
            .frame(width: 86, height: 86)
            VStack(alignment: .leading, spacing: 6) {
                row("VPN connecté", ReportText.hours(report.vpnConnectedSecs), "lock.shield")
                row(
                    "Tests de fuite",
                    report.leakTestsFailed > 0
                        ? "\(report.leakTests) dont \(report.leakTestsFailed) en échec"
                        : "\(report.leakTests), tous réussis",
                    "drop.triangle",
                    warn: report.leakTestsFailed > 0
                )
                row("Alertes réseau", ReportText.count(report.networkAlerts), "wifi.exclamationmark", warn: report.networkAlerts > 0)
                row("Détections comportementales", ReportText.count(report.behaviorDetections), "eye.trianglebadge.exclamationmark", warn: report.behaviorDetections > 0)
            }
        }
    }

    private func row(_ title: String, _ value: String, _ symbol: String, warn: Bool = false) -> some View {
        HStack(spacing: 8) {
            Image(systemName: symbol).foregroundStyle(warn ? Color.orange : Brand.cyan).frame(width: 18)
            Text(title).foregroundStyle(.secondary)
            Spacer(minLength: 8)
            Text(value).monospacedDigit()
        }
        .font(.callout)
    }
}

/// GDPR campaign progress + breaches.
struct PrivacySummaryView: View {
    let report: ActivityReport

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let p = report.privacy, p.total > 0 {
                let parts = [
                    PrivacyPart(name: "Abouties", count: p.completed, color: .green),
                    PrivacyPart(name: "En attente de réponse", count: p.waitingAnswer, color: Brand.cyan),
                    PrivacyPart(name: "En retard", count: p.overdue, color: .orange),
                    PrivacyPart(name: "À envoyer", count: p.queued, color: .gray),
                    PrivacyPart(name: "Action requise", count: p.needsAction, color: .red),
                ]
                Chart(parts.filter { $0.count > 0 }) { part in
                    BarMark(x: .value("Demandes", part.count), y: .value("Campagne", "RGPD"))
                        .foregroundStyle(by: .value("État", part.name))
                }
                .chartForegroundStyleScale(domain: parts.map { $0.name }, range: parts.map { $0.color })
                .chartYAxis(.hidden)
                .frame(height: 64)
                Text("\(p.completed) demande(s) d'effacement abouties sur \(p.total) — \(report.removalRequestsSent) envoyée(s) et \(report.removalRequestsCompleted) aboutie(s) sur la période.")
                    .font(.callout)
            } else {
                Text("Aucune demande d'effacement RGPD en cours.").foregroundStyle(.secondary)
            }
            if report.breachesFound > 0 {
                Label(
                    "\(report.breachesFound) fuite(s) de données trouvée(s) : \(report.breachNames.joined(separator: ", "))",
                    systemImage: "exclamationmark.lock.fill"
                )
                .foregroundStyle(.orange)
            } else {
                Label("Aucune nouvelle fuite de données.", systemImage: "checkmark.seal")
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct PrivacyPart: Identifiable {
    let name: String
    let count: Int
    let color: Color
    var id: String { name }
}
