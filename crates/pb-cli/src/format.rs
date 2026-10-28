//! Human-readable output (French).

use chrono::TimeZone;
use pb_core::ipc::DaemonEvent;
use pb_core::model::*;
use std::fmt::Write as _;

/// Max characters per table cell.
pub const MAX_CELL: usize = 70;

/// Local `YYYY-MM-DD HH:MM`.
pub fn ts(t: i64) -> String {
    match chrono::Local.timestamp_opt(t, 0) {
        chrono::LocalResult::Single(d) | chrono::LocalResult::Ambiguous(d, _) => {
            d.format("%Y-%m-%d %H:%M").to_string()
        }
        chrono::LocalResult::None => t.to_string(),
    }
}

/// Local `HH:MM:SS`.
pub fn time_of_day(t: i64) -> String {
    match chrono::Local.timestamp_opt(t, 0) {
        chrono::LocalResult::Single(d) | chrono::LocalResult::Ambiguous(d, _) => {
            d.format("%H:%M:%S").to_string()
        }
        chrono::LocalResult::None => t.to_string(),
    }
}

/// `1,5 Mo` style sizes.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["o", "Ko", "Mo", "Go", "To"];
    if n < 1024 {
        return format!("{n} o");
    }
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{:.1} {}", v, UNITS[i]).replace('.', ",")
}

/// `2 j 3 h`, `3 h 12 min`, `45 s`.
pub fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, (secs % 86_400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d} j {h} h")
    } else if h > 0 {
        format!("{h} h {m} min")
    } else if m > 0 {
        format!("{m} min")
    } else {
        format!("{secs} s")
    }
}

fn cut(s: &str) -> String {
    let s = s.replace(['\n', '\t'], " ");
    if s.chars().count() <= MAX_CELL {
        s
    } else {
        let mut t: String = s.chars().take(MAX_CELL - 1).collect();
        t.push('…');
        t
    }
}

/// Left-aligned text table.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let rows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| r.iter().map(|c| cut(c)).collect())
        .collect();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(c.chars().count());
            }
        }
    }
    let line = |cells: &[String]| -> String {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            let w = widths.get(i).copied().unwrap_or(0);
            if i + 1 == cells.len() {
                s.push_str(c);
            } else {
                s.push_str(c);
                s.push_str(&" ".repeat(w.saturating_sub(c.chars().count()) + 2));
            }
        }
        s.trim_end().to_string()
    };
    let mut out = line(&headers.iter().map(|h| h.to_string()).collect::<Vec<_>>());
    out.push('\n');
    for r in &rows {
        out.push_str(&line(r));
        out.push('\n');
    }
    out
}

fn wire<T: serde::Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => "?".into(),
    }
}

pub fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "faible",
        Severity::Medium => "moyenne",
        Severity::High => "élevée",
        Severity::Critical => "critique",
    }
}

pub fn verdict(v: Verdict) -> &'static str {
    match v {
        Verdict::Clean => "sain",
        Verdict::Suspicious => "suspect",
        Verdict::Malicious => "malveillant",
    }
}

pub fn job_state(s: JobState) -> &'static str {
    match s {
        JobState::Queued => "en attente",
        JobState::Running => "en cours",
        JobState::Finished => "terminée",
        JobState::Cancelled => "annulée",
        JobState::Failed => "échouée",
    }
}

pub fn origin(o: ScanOrigin) -> &'static str {
    match o {
        ScanOrigin::Manual => "manuelle",
        ScanOrigin::Downloads => "téléchargements",
        ScanOrigin::Volume => "volume",
        ScanOrigin::Realtime => "temps réel",
        ScanOrigin::Scheduled => "planifiée",
        ScanOrigin::RetroHunt => "rétro-chasse",
        ScanOrigin::Spyware => "anti-spyware",
    }
}

fn alert_status(s: AlertStatus) -> &'static str {
    match s {
        AlertStatus::Open => "ouverte",
        AlertStatus::Acknowledged => "vue",
        AlertStatus::Resolved => "résolue",
    }
}

fn component_state(s: ComponentState) -> &'static str {
    match s {
        ComponentState::NotInstalled => "non installé",
        ComponentState::Installed => "installé",
        ComponentState::UpdateAvailable => "mise à jour disponible",
        ComponentState::Updating => "mise à jour en cours",
        ComponentState::Error => "erreur",
        ComponentState::Disabled => "désactivé",
        ComponentState::NeedsUserAction => "action requise",
    }
}

fn extension_state(s: ExtensionState) -> &'static str {
    match s {
        ExtensionState::NotInstalled => "non installée",
        ExtensionState::InstalledDisabled => "installée mais désactivée",
        ExtensionState::Enabled => "active",
        ExtensionState::Unknown => "inconnu",
    }
}

fn yes(b: bool) -> &'static str {
    if b {
        "ok"
    } else {
        "inactif"
    }
}

fn opt<T: std::fmt::Display>(o: &Option<T>) -> String {
    o.as_ref()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "—".into())
}

pub fn status(s: &StatusInfo) -> String {
    let mut o = String::new();
    let prot = match s.protection {
        ProtectionState::Active => "active".to_string(),
        ProtectionState::Paused => match s.paused_until {
            Some(t) => format!("en pause jusqu'à {}", ts(t)),
            None => "en pause".into(),
        },
        ProtectionState::Degraded => "dégradée".into(),
    };
    let _ = writeln!(o, "Parabellum {} — protection {prot}", s.version);
    if !s.issues.is_empty() {
        let _ = writeln!(o, "Problèmes :");
        for i in &s.issues {
            let _ = writeln!(o, "  - {i}");
        }
    }
    let r = &s.realtime;
    let _ = writeln!(
        o,
        "Temps réel     : FSEvents {}, eslogger {}, accès complet au disque {}, persistance {}, périphériques {}",
        yes(r.fsevents),
        yes(r.eslogger),
        if r.full_disk_access { "accordé" } else { "non accordé" },
        yes(r.persistence_monitor),
        yes(r.device_monitor)
    );
    let db = &s.db;
    let built = db
        .built_at
        .map(|t| format!(" du {}", ts(t)))
        .unwrap_or_default();
    let _ = writeln!(
        o,
        "Base           : {}{built} — {} hachages, {} règles YARA, {} domaines bloqués",
        db.version.as_deref().unwrap_or("absente"),
        db.malware_hashes,
        db.yara_rules,
        db.blocked_domains
    );
    if let Some(e) = &db.last_error {
        let _ = writeln!(o, "                 dernière erreur de mise à jour : {e}");
    }
    let _ = writeln!(
        o,
        "Alertes        : {} ouvertes — quarantaine : {} fichier(s)",
        s.open_alerts, s.quarantined
    );
    let _ = writeln!(
        o,
        "Dernière analyse : {}",
        s.last_scan.map(ts).unwrap_or_else(|| "jamais".into())
    );
    let _ = writeln!(
        o,
        "DNS {} — ML {} — {} — composants à vérifier : {}",
        if s.dns_enabled {
            "activé"
        } else {
            "désactivé"
        },
        if s.ml_enabled { "actif" } else { "inactif" },
        if s.on_battery {
            "sur batterie"
        } else {
            "sur secteur"
        },
        s.components_needing_attention
    );
    let _ = writeln!(
        o,
        "Daemon actif depuis {} — mémoire {}",
        duration(s.uptime_secs),
        bytes(s.rss_bytes)
    );
    o
}

pub fn jobs(list: &[ScanJobSummary]) -> String {
    if list.is_empty() {
        return "Aucune analyse.\n".into();
    }
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|j| {
            vec![
                j.job_id.clone(),
                origin(j.origin).into(),
                job_state(j.state).into(),
                ts(j.started_at),
                j.files_scanned.to_string(),
                j.threats.to_string(),
                j.errors.to_string(),
                j.paths.join(", "),
            ]
        })
        .collect();
    table(
        &[
            "ID", "TYPE", "ÉTAT", "DÉBUT", "FICHIERS", "MENACES", "ERREURS", "CHEMINS",
        ],
        &rows,
    )
}

/// One-line progress of a running job.
pub fn progress(j: &ScanJobSummary) -> String {
    format!(
        "{} fichiers ({}) — {} menace(s), {} erreur(s){}",
        j.files_scanned,
        bytes(j.bytes_scanned),
        j.threats,
        j.errors,
        j.current_path
            .as_deref()
            .map(|p| format!(" — {}", cut(p)))
            .unwrap_or_default()
    )
}

pub fn job(d: &ScanJobDetail) -> String {
    let s = &d.summary;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "Analyse {} ({}) : {}",
        s.job_id,
        origin(s.origin),
        job_state(s.state)
    );
    let _ = writeln!(o, "Chemins  : {}", s.paths.join(", "));
    let end = s.finished_at.map(|f| {
        format!(
            " → {} ({})",
            ts(f),
            duration((f - s.started_at).max(0) as u64)
        )
    });
    let _ = writeln!(
        o,
        "Période  : {}{}",
        ts(s.started_at),
        end.unwrap_or_default()
    );
    let _ = writeln!(
        o,
        "Résultat : {} fichiers ({}), {} menace(s), {} erreur(s)",
        s.files_scanned,
        bytes(s.bytes_scanned),
        s.threats,
        s.errors
    );
    let threats: Vec<&ScanReport> = d
        .findings
        .iter()
        .filter(|r| r.verdict != Verdict::Clean)
        .collect();
    if !threats.is_empty() {
        let rows: Vec<Vec<String>> = threats
            .iter()
            .map(|r| {
                let names = r
                    .detections
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                vec![verdict(r.verdict).into(), names, r.path.clone()]
            })
            .collect();
        o.push('\n');
        o.push_str(&table(&["VERDICT", "DÉTECTION", "FICHIER"], &rows));
    }
    let errors = d
        .findings
        .iter()
        .filter(|r| r.verdict == Verdict::Clean && r.error.is_some())
        .count();
    if errors > 0 {
        let _ = writeln!(
            o,
            "\n{errors} fichier(s) n'ont pas pu être analysés (voir --json pour le détail)."
        );
    }
    o
}

pub fn alerts(list: &[Alert]) -> String {
    if list.is_empty() {
        return "Aucune alerte.\n".into();
    }
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|a| {
            vec![
                a.id.to_string(),
                ts(a.ts),
                severity(a.severity).into(),
                alert_status(a.status).into(),
                a.title.clone(),
                a.actions
                    .iter()
                    .map(|x| wire(x).replace('_', "-"))
                    .collect::<Vec<_>>()
                    .join(" "),
            ]
        })
        .collect();
    let mut o = table(
        &["N°", "DATE", "GRAVITÉ", "ÉTAT", "TITRE", "ACTIONS"],
        &rows,
    );
    o.push_str("\nDétail : parabellum alerts --json ; agir : parabellum resolve <n°> <action>\n");
    o
}

/// macOS security settings.
pub fn posture(list: &[PostureCheck]) -> String {
    if list.is_empty() {
        return "Aucune vérification disponible (macOS uniquement).\n".into();
    }
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|c| {
            vec![
                if c.ok {
                    "OK".into()
                } else if c.severity == Severity::Info {
                    "?".into()
                } else {
                    "À CORRIGER".into()
                },
                severity(c.severity).into(),
                c.title.clone(),
                c.detail.clone(),
            ]
        })
        .collect();
    let mut o = table(&["ÉTAT", "GRAVITÉ", "RÉGLAGE", "CONSTAT"], &rows);
    let fixes: Vec<&PostureCheck> = list.iter().filter(|c| !c.ok && !c.fix.is_empty()).collect();
    if !fixes.is_empty() {
        o.push_str("\nCorrections :\n");
        for c in fixes {
            o.push_str(&format!("- {} : {}\n", c.title, c.fix));
        }
    }
    o
}

/// Full text of one alert.
pub fn alert(a: &Alert) -> String {
    let mut o = format!(
        "Alerte {} [{}] {} — {}\n{}\n",
        a.id,
        severity(a.severity),
        alert_status(a.status),
        a.title,
        a.message
    );
    if let Some(p) = &a.path {
        let _ = writeln!(o, "Fichier : {p}");
    }
    if let Some(q) = &a.quarantine_id {
        let _ = writeln!(o, "Quarantaine : {q}");
    }
    o
}

pub fn quarantine(list: &[QuarantineEntry]) -> String {
    if list.is_empty() {
        return "Quarantaine vide.\n".into();
    }
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|e| {
            vec![
                e.id.clone(),
                ts(e.quarantined_at),
                bytes(e.size),
                e.detections
                    .first()
                    .map(|d| d.name.clone())
                    .unwrap_or_else(|| e.reason.clone()),
                e.original_path.clone(),
            ]
        })
        .collect();
    table(
        &["ID", "DATE", "TAILLE", "MOTIF", "CHEMIN D'ORIGINE"],
        &rows,
    )
}

pub fn quarantine_entry(e: &QuarantineEntry) -> String {
    format!(
        "{} mis en quarantaine (entrée {}).\n",
        e.original_path, e.id
    )
}

fn persistence_status(s: PersistenceStatus) -> &'static str {
    match s {
        PersistenceStatus::Baseline => "initial",
        PersistenceStatus::New => "nouveau",
        PersistenceStatus::Approved => "approuvé",
        PersistenceStatus::Removed => "disparu",
        PersistenceStatus::Quarantined => "retiré",
    }
}

pub fn persistence(list: &[PersistenceItem]) -> String {
    if list.is_empty() {
        return "Aucun élément de persistance.\n".into();
    }
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|p| {
            let signer = match &p.signing {
                None => "?".to_string(),
                Some(s) if s.apple => "Apple".into(),
                Some(s) if !s.signed => "non signé".into(),
                Some(s) if s.adhoc => "ad hoc".into(),
                Some(s) => s.team_id.clone().unwrap_or_else(|| "signé".into()),
            };
            vec![
                p.id.clone(),
                wire(&p.kind),
                persistence_status(p.status).into(),
                p.label.clone().unwrap_or_default(),
                p.program.clone().unwrap_or_default(),
                signer,
            ]
        })
        .collect();
    table(
        &["ID", "TYPE", "ÉTAT", "LABEL", "PROGRAMME", "SIGNATURE"],
        &rows,
    )
}

pub fn persistence_item(p: &PersistenceItem) -> String {
    format!(
        "{} ({}) : {}\n",
        p.label.as_deref().unwrap_or(&p.path),
        p.id,
        persistence_status(p.status)
    )
}

fn trust(t: DeviceTrust) -> &'static str {
    match t {
        DeviceTrust::Unknown => "inconnu",
        DeviceTrust::Trusted => "de confiance",
        DeviceTrust::Blocked => "bloqué",
    }
}

pub fn devices(list: &[DeviceInfo]) -> String {
    if list.is_empty() {
        return "Aucun périphérique connu.\n".into();
    }
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|d| {
            vec![
                d.id.clone(),
                wire(&d.kind),
                d.name.clone(),
                trust(d.trust).into(),
                if d.connected {
                    "connecté".into()
                } else {
                    "déconnecté".into()
                },
                ts(d.last_seen),
            ]
        })
        .collect();
    table(&["ID", "TYPE", "NOM", "CONFIANCE", "ÉTAT", "VU LE"], &rows)
}

pub fn device(d: &DeviceInfo) -> String {
    format!("{} ({}) : {}\n", d.name, d.id, trust(d.trust))
}

pub fn components(list: &[ComponentStatus]) -> String {
    if list.is_empty() {
        return "Aucun composant géré.\n".into();
    }
    let rows: Vec<Vec<String>> = list
        .iter()
        .map(|c| {
            vec![
                c.name.clone(),
                component_state(c.state).into(),
                opt(&c.installed_version),
                opt(&c.latest_version),
                if c.auto_update {
                    "auto".into()
                } else {
                    "manuelle".into()
                },
                if c.required {
                    "requis".into()
                } else {
                    String::new()
                },
                c.message.clone().unwrap_or_default(),
            ]
        })
        .collect();
    table(
        &[
            "NOM",
            "ÉTAT",
            "INSTALLÉ",
            "DISPONIBLE",
            "MAJ",
            "",
            "MESSAGE",
        ],
        &rows,
    )
}

pub fn dns(d: &DnsStatus) -> String {
    let mut o = format!(
        "Blocage DNS : {} — dnscrypt-proxy {} sur {} — {} domaines bloqués",
        if d.enabled { "activé" } else { "désactivé" },
        if d.running { "actif" } else { "arrêté" },
        if d.listen.is_empty() {
            "—"
        } else {
            &d.listen
        },
        d.blocked_domains
    );
    if let Some(v) = &d.list_version {
        let _ = write!(o, " (listes {v})");
    }
    o.push('\n');
    if let Some(n) = d.queries_blocked_24h {
        let _ = writeln!(o, "Requêtes bloquées (24 h) : {n}");
    }
    if !d.managed_services.is_empty() {
        let _ = writeln!(
            o,
            "Services réseau gérés : {}",
            d.managed_services.join(", ")
        );
    }
    if let Some(m) = &d.message {
        let _ = writeln!(o, "{m}");
    }
    o
}

pub fn adblock(a: &AdblockStatus) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "uBlock Origin Lite (Chrome) : {}",
        extension_state(a.chrome_ublock)
    );
    if a.chrome_ublock != ExtensionState::Enabled {
        let _ = writeln!(o, "  installer : {}", a.chrome_store_url);
    }
    let _ = writeln!(
        o,
        "uBlock Origin Lite (Safari) : {}",
        extension_state(a.safari_ublock)
    );
    if a.safari_ublock != ExtensionState::Enabled {
        let _ = writeln!(o, "  installer : {}", a.safari_store_url);
    }
    o.push_str(&dns(&a.dns));
    o
}

pub fn report(r: &WeeklyReport) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "Rapport du {} au {}", ts(r.week_start), ts(r.week_end));
    let _ = writeln!(o, "Fichiers analysés        : {}", r.files_scanned);
    let _ = writeln!(o, "Menaces détectées        : {}", r.threats_detected);
    let _ = writeln!(o, "Mises en quarantaine     : {}", r.quarantined);
    let _ = writeln!(
        o,
        "Faux positifs signalés   : {}",
        r.false_positives_reported
    );
    let _ = writeln!(o, "Nouvelles persistances   : {}", r.persistence_new);
    let _ = writeln!(o, "Nouveaux périphériques   : {}", r.devices_new);
    let _ = writeln!(
        o,
        "Mises à jour de la base  : {} (version {})",
        r.db_updates,
        opt(&r.db_version)
    );
    if let Some(n) = r.dns_blocked_queries {
        let _ = writeln!(o, "Requêtes DNS bloquées    : {n}");
    }
    if !r.top_detections.is_empty() {
        let _ = writeln!(o, "Détections les plus fréquentes :");
        for d in &r.top_detections {
            let _ = writeln!(o, "  {:>5}  {}", d.count, d.name);
        }
    }
    if !r.component_updates.is_empty() {
        let _ = writeln!(o, "Composants :");
        for c in &r.component_updates {
            let _ = writeln!(o, "  - {c}");
        }
    }
    o
}

pub fn update(u: &UpdateResult) -> String {
    let mut o = format!(
        "Mise à jour {} : {}{}\n",
        wire(&u.target),
        if u.ok { "réussie" } else { "en échec" },
        u.new_db_version
            .as_deref()
            .map(|v| format!(" (base {v})"))
            .unwrap_or_default()
    );
    for m in &u.messages {
        let _ = writeln!(o, "  - {m}");
    }
    o
}

/// One line per pushed event (`watch`).
pub fn event(ev: &DaemonEvent) -> String {
    let now = time_of_day(chrono::Local::now().timestamp());
    match ev {
        DaemonEvent::Alert(a) => format!(
            "[{now}] alerte {} ({}) : {} — {}",
            a.id,
            severity(a.severity),
            a.title,
            a.message
        ),
        DaemonEvent::ScanProgress(j) => format!("[{now}] analyse {} : {}", j.job_id, progress(j)),
        DaemonEvent::ScanFinished(j) => format!(
            "[{now}] analyse {} {} : {} fichiers, {} menace(s)",
            j.job_id,
            job_state(j.state),
            j.files_scanned,
            j.threats
        ),
        DaemonEvent::StatusChanged(s) => {
            format!("[{now}] état : protection {}", wire(&s.protection))
                + &if s.issues.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", s.issues.join(" ; "))
                }
        }
        DaemonEvent::Device(d) => {
            format!(
                "[{now}] périphérique {} : {} ({})",
                wire(&d.change),
                d.device.name,
                d.device.id
            )
        }
        DaemonEvent::UpdateFinished(u) => {
            format!("[{now}] {}", update(u).trim_end().replace('\n', " "))
        }
        DaemonEvent::Component(c) => format!(
            "[{now}] composant {} : {}",
            c.name,
            component_state(c.state)
        ),
        DaemonEvent::Quarantined(q) => {
            format!("[{now}] quarantaine : {} ({})", q.original_path, q.id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(bytes(512), "512 o");
        assert_eq!(bytes(1536), "1,5 Ko");
        assert_eq!(bytes(3 * 1024 * 1024), "3,0 Mo");
        assert_eq!(duration(45), "45 s");
        assert_eq!(duration(3 * 3600 + 12 * 60), "3 h 12 min");
        assert_eq!(duration(2 * 86_400 + 3600), "2 j 1 h");
    }

    #[test]
    fn posture_table() {
        let list = vec![
            PostureCheck {
                id: "sip".into(),
                title: "SIP".into(),
                ok: true,
                severity: Severity::High,
                detail: "SIP activée".into(),
                fix: String::new(),
            },
            PostureCheck {
                id: "firewall".into(),
                title: "Coupe-feu".into(),
                ok: false,
                severity: Severity::Medium,
                detail: "désactivé".into(),
                fix: "Réglages Système > Réseau > Coupe-feu".into(),
            },
        ];
        let o = posture(&list);
        assert!(o.contains("À CORRIGER") && o.contains("Corrections") && o.contains("Coupe-feu"));
        assert!(posture(&[]).contains("macOS"));
        assert_eq!(origin(ScanOrigin::Spyware), "anti-spyware");
    }

    #[test]
    fn tables_align() {
        let t = table(
            &["A", "BB"],
            &[vec!["xxx".into(), "y".into()], vec!["z".into(), "w".into()]],
        );
        assert_eq!(t, "A    BB\nxxx  y\nz    w\n");
        let long = "é".repeat(100);
        let t = table(&["X"], &[vec![long]]);
        assert_eq!(t.lines().nth(1).unwrap().chars().count(), MAX_CELL);
    }

    #[test]
    fn status_text() {
        let s = StatusInfo {
            version: "0.1.0".into(),
            protection: ProtectionState::Degraded,
            issues: vec!["ClamAV non installé".into()],
            uptime_secs: 3700,
            rss_bytes: 40 * 1024 * 1024,
            ..Default::default()
        };
        let t = status(&s);
        assert!(t.starts_with("Parabellum 0.1.0 — protection dégradée"));
        assert!(t.contains("  - ClamAV non installé"));
        assert!(t.contains("Base           : absente"));
        assert!(t.contains("1 h 1 min"));
        assert!(t.contains("40,0 Mo"));
    }

    #[test]
    fn alerts_and_jobs() {
        assert_eq!(alerts(&[]), "Aucune alerte.\n");
        let a = Alert {
            id: 7,
            ts: 0,
            kind: AlertKind::Malware,
            severity: Severity::Critical,
            title: "Menace mise en quarantaine".into(),
            message: "m".into(),
            path: Some("/x".into()),
            sha256: None,
            device_id: None,
            persistence_id: None,
            quarantine_id: Some("q".into()),
            status: AlertStatus::Open,
            actions: vec![AlertAction::Restore, AlertAction::ReportFalsePositive],
        };
        let t = alerts(std::slice::from_ref(&a));
        assert!(t.contains("critique") && t.contains("restore report-false-positive"));
        assert!(alert(&a).contains("Quarantaine : q"));
        let j = ScanJobSummary {
            job_id: "j1".into(),
            origin: ScanOrigin::Manual,
            paths: vec!["/tmp".into()],
            state: JobState::Finished,
            started_at: 0,
            finished_at: Some(65),
            files_scanned: 3,
            bytes_scanned: 2048,
            threats: 1,
            errors: 0,
            current_path: None,
        };
        assert!(jobs(std::slice::from_ref(&j)).contains("terminée"));
        let d = ScanJobDetail {
            summary: j,
            findings: vec![ScanReport {
                path: "/tmp/eicar".into(),
                verdict: Verdict::Malicious,
                detections: vec![Detection {
                    engine: DetectionEngine::ClamAv,
                    name: "Eicar-Test-Signature".into(),
                    severity: Severity::High,
                    confidence: 1.0,
                    details: None,
                }],
                ..Default::default()
            }],
        };
        let t = job(&d);
        assert!(
            t.contains("Eicar-Test-Signature") && t.contains("malveillant") && t.contains("1 min")
        );
    }

    #[test]
    fn events_are_single_lines() {
        let ev = DaemonEvent::UpdateFinished(UpdateResult {
            target: UpdateTarget::Db,
            ok: false,
            started_at: 0,
            finished_at: 1,
            messages: vec!["a".into(), "b".into()],
            new_db_version: None,
        });
        let l = event(&ev);
        assert!(!l.contains('\n') && l.contains("en échec"));
    }
}
