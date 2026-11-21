//! Full alert report (IPC `export_alerts`, app « Exporter… », `parabellum alerts export`): HTML (also the
//! source of the app's PDF), CSV, JSON or Markdown, in French or English.
//!
//! Alert texts come from what was scanned (file names, paths, process names, network names): attacker
//! controlled. Every format escapes them: HTML entities (and a page that loads nothing: CSP
//! `default-src 'none'`), CSV cells that a spreadsheet would run as a formula (`=`, `+`, `-`, `@`, tab, CR)
//! prefixed with `'`, Markdown table cells with `|`, backticks and line breaks neutralised.

use crate::ctx::Ctx;
use chrono::{DateTime, Local, NaiveDate, TimeZone};
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::{Alert, AlertExport, AlertExportFormat, AlertKind, AlertStatus, Severity};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

/// Most alerts read for one report.
pub const MAX_ALERTS: u32 = 50_000;
/// Rendered size kept under the IPC frame (8 MB) with room for JSON escaping of the content.
pub const MAX_CONTENT: usize = 5 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Fr,
    En,
}

impl Lang {
    pub fn parse(s: Option<&str>) -> Lang {
        match s.map(str::to_ascii_lowercase).as_deref() {
            Some(l) if l.starts_with("en") => Lang::En,
            _ => Lang::Fr,
        }
    }
}

/// What the report covers.
#[derive(Debug, Clone)]
pub struct Scope {
    /// `[start, end)` Unix time; None = from the first alert / until now.
    pub start: Option<i64>,
    pub end: Option<i64>,
    /// `YYYY-MM-DD` as asked (inclusive `to`).
    pub from_date: Option<String>,
    pub to_date: Option<String>,
    pub include_resolved: bool,
    pub min_severity: Option<Severity>,
}

pub struct Meta {
    pub generated_at: i64,
    pub version: String,
    pub db_version: Option<String>,
    pub total: u32,
    pub truncated: bool,
}

fn t(lang: Lang, fr: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::Fr => fr,
        Lang::En => en,
    }
}

pub fn severity_label(s: Severity, l: Lang) -> &'static str {
    match s {
        Severity::Info => "Info",
        Severity::Low => t(l, "Faible", "Low"),
        Severity::Medium => t(l, "Moyenne", "Medium"),
        Severity::High => t(l, "Élevée", "High"),
        Severity::Critical => t(l, "Critique", "Critical"),
    }
}

pub fn kind_label(k: AlertKind, l: Lang) -> &'static str {
    match k {
        AlertKind::Malware => "Malware",
        AlertKind::Suspicious => t(l, "Fichier suspect", "Suspicious file"),
        AlertKind::Persistence => t(l, "Persistance", "Persistence"),
        AlertKind::Device => t(l, "Périphérique", "Device"),
        AlertKind::Network => t(l, "Réseau", "Network"),
        AlertKind::Update => t(l, "Mise à jour", "Update"),
        AlertKind::System => t(l, "Système", "System"),
        AlertKind::Behavior => t(l, "Comportement", "Behavior"),
        AlertKind::Privacy => t(l, "Vie privée", "Privacy"),
    }
}

pub fn status_label(s: AlertStatus, l: Lang) -> &'static str {
    match s {
        AlertStatus::Open => t(l, "Ouverte", "Open"),
        AlertStatus::Acknowledged => t(l, "Vue", "Acknowledged"),
        AlertStatus::Resolved => t(l, "Résolue", "Resolved"),
    }
}

fn snake<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn local<Tz: TimeZone>(tz: &Tz, ts: i64) -> Option<DateTime<Tz>> {
    tz.timestamp_opt(ts, 0).single()
}

/// `2026-11-21 15:02:07` (local).
fn human<Tz: TimeZone>(tz: &Tz, ts: i64) -> String
where
    Tz::Offset: std::fmt::Display,
{
    local(tz, ts).map_or_else(
        || ts.to_string(),
        |d| d.format("%Y-%m-%d %H:%M:%S").to_string(),
    )
}

/// `2026-11-21T15:02:07+01:00`.
fn iso<Tz: TimeZone>(tz: &Tz, ts: i64) -> String
where
    Tz::Offset: std::fmt::Display,
{
    local(tz, ts).map_or_else(
        || ts.to_string(),
        |d| d.format("%Y-%m-%dT%H:%M:%S%:z").to_string(),
    )
}

fn process(a: &Alert) -> Option<String> {
    match (&a.process_path, a.process_pid) {
        (Some(p), Some(pid)) => Some(format!("{p} (pid {pid})")),
        (Some(p), None) => Some(p.clone()),
        (None, Some(pid)) => Some(format!("pid {pid}")),
        (None, None) => None,
    }
}

/// Optional fields worth a line: (French, English) label, value.
fn details(a: &Alert) -> Vec<((&'static str, &'static str), String)> {
    let mut v = Vec::new();
    let mut push = |label, value: &Option<String>| {
        if let Some(x) = value.as_ref().filter(|x| !x.is_empty()) {
            v.push((label, x.clone()));
        }
    };
    push(("Chemin", "Path"), &a.path);
    push(("SHA-256", "SHA-256"), &a.sha256);
    push(("Processus", "Process"), &process(a));
    push(("Périphérique", "Device"), &a.device_id);
    push(("Réseau", "Network"), &a.network_id);
    push(("Persistance", "Persistence item"), &a.persistence_id);
    push(("Quarantaine", "Quarantine"), &a.quarantine_id);
    v
}

/// Period line, e.g. « du 2026-11-01 au 2026-11-21 ».
fn period(scope: &Scope, l: Lang) -> String {
    match (&scope.from_date, &scope.to_date) {
        (Some(a), Some(b)) => format!("{} {a} {} {b}", t(l, "du", "from"), t(l, "au", "to")),
        (Some(a), None) => format!("{} {a}", t(l, "depuis le", "since")),
        (None, Some(b)) => format!("{} {b}", t(l, "jusqu'au", "until")),
        (None, None) => t(l, "toutes les alertes", "all alerts").to_string(),
    }
}

fn filters(scope: &Scope, l: Lang) -> String {
    let mut f = vec![if scope.include_resolved {
        t(
            l,
            "ouvertes, vues et résolues",
            "open, acknowledged and resolved",
        )
    } else {
        t(l, "ouvertes seulement", "open only")
    }
    .to_string()];
    if let Some(s) = scope.min_severity {
        f.push(format!(
            "{} {}",
            t(l, "gravité ≥", "severity ≥"),
            severity_label(s, l)
        ));
    }
    f.join(", ")
}

/// Counts by severity (most severe first), status and kind.
struct Summary {
    severity: Vec<(Severity, usize)>,
    status: Vec<(AlertStatus, usize)>,
    kind: Vec<(String, usize)>,
}

fn summarize(alerts: &[Alert], l: Lang) -> Summary {
    let sev = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    let sts = [
        AlertStatus::Open,
        AlertStatus::Acknowledged,
        AlertStatus::Resolved,
    ];
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for a in alerts {
        *kinds.entry(kind_label(a.kind, l).to_string()).or_default() += 1;
    }
    let mut kind: Vec<(String, usize)> = kinds.into_iter().collect();
    kind.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    Summary {
        severity: sev
            .iter()
            .map(|s| (*s, alerts.iter().filter(|a| a.severity == *s).count()))
            .collect(),
        status: sts
            .iter()
            .map(|s| (*s, alerts.iter().filter(|a| a.status == *s).count()))
            .collect(),
        kind,
    }
}

// ----- Escaping --------------------------------------------------------------------------------

fn html_escape(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => o.push('\u{FFFD}'),
            c => o.push(c),
        }
    }
    o
}

/// A CSV cell: quoted when needed; a spreadsheet must never run it as a formula.
pub fn csv_cell(s: &str) -> String {
    let mut v = s.replace('\0', "");
    if v.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        v.insert(0, '\'');
    }
    if v.contains([',', '"', '\n', '\r', ';']) || v.starts_with(' ') || v.ends_with(' ') {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v
    }
}

/// A Markdown table cell: one line, no column break, no code span or HTML.
pub fn md_cell(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\n' | '\r' => ' ',
            c => c,
        })
        .collect::<String>()
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('`', "\\`")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ----- Formats ---------------------------------------------------------------------------------

fn title(l: Lang) -> &'static str {
    t(
        l,
        "Rapport des alertes Parabellum",
        "Parabellum alert report",
    )
}

pub fn render<Tz: TimeZone>(
    format: AlertExportFormat,
    alerts: &[Alert],
    scope: &Scope,
    meta: &Meta,
    l: Lang,
    tz: &Tz,
) -> String
where
    Tz::Offset: std::fmt::Display,
{
    match format {
        AlertExportFormat::Html => html(alerts, scope, meta, l, tz),
        AlertExportFormat::Csv => csv(alerts, l, tz),
        AlertExportFormat::Json => json(alerts, scope, meta, l, tz),
        AlertExportFormat::Markdown => markdown(alerts, scope, meta, l, tz),
    }
}

fn csv<Tz: TimeZone>(alerts: &[Alert], l: Lang, tz: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let head = match l {
        Lang::Fr => [
            "ID",
            "Date",
            "Gravité",
            "Type",
            "Statut",
            "Titre",
            "Message",
            "Chemin",
            "SHA-256",
            "Processus",
            "Périphérique",
            "Réseau",
            "Persistance",
            "Quarantaine",
        ],
        Lang::En => [
            "ID",
            "Date",
            "Severity",
            "Kind",
            "Status",
            "Title",
            "Message",
            "Path",
            "SHA-256",
            "Process",
            "Device",
            "Network",
            "Persistence item",
            "Quarantine",
        ],
    };
    // BOM: Excel opens UTF-8 (accents) correctly.
    let mut o = String::from("\u{FEFF}");
    o.push_str(&head.map(csv_cell).join(","));
    o.push_str("\r\n");
    for a in alerts {
        let opt = |x: &Option<String>| x.clone().unwrap_or_default();
        let row = [
            a.id.to_string(),
            iso(tz, a.ts),
            severity_label(a.severity, l).to_string(),
            kind_label(a.kind, l).to_string(),
            status_label(a.status, l).to_string(),
            a.title.clone(),
            a.message.clone(),
            opt(&a.path),
            opt(&a.sha256),
            process(a).unwrap_or_default(),
            opt(&a.device_id),
            opt(&a.network_id),
            opt(&a.persistence_id),
            opt(&a.quarantine_id),
        ];
        o.push_str(
            &row.iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        o.push_str("\r\n");
    }
    o
}

fn json<Tz: TimeZone>(alerts: &[Alert], scope: &Scope, meta: &Meta, l: Lang, tz: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let s = summarize(alerts, l);
    let items: Vec<serde_json::Value> = alerts
        .iter()
        .map(|a| {
            let mut v = serde_json::to_value(a).unwrap_or_default();
            if let Some(o) = v.as_object_mut() {
                o.insert("date".into(), iso(tz, a.ts).into());
                o.remove("actions");
            }
            v
        })
        .collect();
    let doc = serde_json::json!({
        "report": "parabellum.alerts",
        "version": 1,
        "generated_at": iso(tz, meta.generated_at),
        "parabellum_version": meta.version,
        "threat_db_version": meta.db_version,
        "period": {
            "from": scope.from_date,
            "to": scope.to_date,
        },
        "filters": {
            "include_resolved": scope.include_resolved,
            "min_severity": scope.min_severity.map(|s| snake(&s)),
        },
        "total": meta.total,
        "count": alerts.len(),
        "truncated": meta.truncated,
        "summary": {
            "by_severity": s.severity.iter().map(|(k, n)| (snake(k), *n)).collect::<BTreeMap<_, _>>(),
            "by_status": s.status.iter().map(|(k, n)| (snake(k), *n)).collect::<BTreeMap<_, _>>(),
            "by_kind": alerts.iter().fold(BTreeMap::<String, usize>::new(), |mut m, a| {
                *m.entry(snake(&a.kind)).or_default() += 1;
                m
            }),
        },
        "alerts": items,
    });
    let mut out = serde_json::to_string_pretty(&doc).unwrap_or_default();
    out.push('\n');
    out
}

fn markdown<Tz: TimeZone>(alerts: &[Alert], scope: &Scope, meta: &Meta, l: Lang, tz: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let s = summarize(alerts, l);
    let mut o = String::new();
    let _ = writeln!(o, "# {}\n", title(l));
    let _ = writeln!(
        o,
        "- {} : {}",
        t(l, "Période", "Period"),
        md_cell(&period(scope, l))
    );
    let _ = writeln!(
        o,
        "- {} : {}",
        t(l, "Filtres", "Filters"),
        md_cell(&filters(scope, l))
    );
    let _ = writeln!(
        o,
        "- {} : {}",
        t(l, "Généré le", "Generated"),
        human(tz, meta.generated_at)
    );
    let _ = writeln!(
        o,
        "- Parabellum {}{}",
        md_cell(&meta.version),
        meta.db_version
            .as_ref()
            .map(|d| format!(", {} {}", t(l, "base", "database"), md_cell(d)))
            .unwrap_or_default()
    );
    let _ = writeln!(o, "- {} : {}", t(l, "Alertes", "Alerts"), alerts.len());
    if meta.truncated {
        let _ = writeln!(o, "- **{}**", truncated_note(meta, alerts.len(), l));
    }
    let _ = writeln!(o, "\n## {}\n", t(l, "Résumé", "Summary"));
    let _ = writeln!(
        o,
        "| {} | {} |\n|---|---:|",
        t(l, "Gravité", "Severity"),
        t(l, "Alertes", "Alerts")
    );
    for (k, n) in &s.severity {
        let _ = writeln!(o, "| {} | {n} |", severity_label(*k, l));
    }
    let _ = writeln!(
        o,
        "\n| {} | {} |\n|---|---:|",
        t(l, "Statut", "Status"),
        t(l, "Alertes", "Alerts")
    );
    for (k, n) in &s.status {
        let _ = writeln!(o, "| {} | {n} |", status_label(*k, l));
    }
    let _ = writeln!(
        o,
        "\n| {} | {} |\n|---|---:|",
        t(l, "Type", "Kind"),
        t(l, "Alertes", "Alerts")
    );
    for (k, n) in &s.kind {
        let _ = writeln!(o, "| {} | {n} |", md_cell(k));
    }
    let _ = writeln!(o, "\n## {}\n", t(l, "Alertes", "Alerts"));
    if alerts.is_empty() {
        let _ = writeln!(
            o,
            "{}",
            t(
                l,
                "Aucune alerte sur cette période.",
                "No alert in this period."
            )
        );
    }
    for a in alerts {
        let _ = writeln!(
            o,
            "### {} — {}\n\n| | |\n|---|---|\n| {} | {} |\n| {} | {} |\n| {} | {} |\n| Message | {} |",
            md_cell(&human(tz, a.ts)),
            md_cell(&a.title),
            t(l, "Gravité", "Severity"),
            severity_label(a.severity, l),
            t(l, "Type", "Kind"),
            kind_label(a.kind, l),
            t(l, "Statut", "Status"),
            status_label(a.status, l),
            md_cell(&a.message),
        );
        for ((fr, en), v) in details(a) {
            let _ = writeln!(o, "| {} | {} |", t(l, fr, en), md_cell(&v));
        }
        let _ = writeln!(o, "| ID | {} |\n", a.id);
    }
    o
}

fn truncated_note(meta: &Meta, count: usize, l: Lang) -> String {
    match l {
        Lang::Fr => format!(
            "Rapport tronqué : les {count} alertes les plus récentes sur {} (réduisez la période pour le reste).",
            meta.total
        ),
        Lang::En => format!(
            "Truncated report: the {count} most recent alerts out of {} (narrow the period for the rest).",
            meta.total
        ),
    }
}

fn severity_class(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn html<Tz: TimeZone>(alerts: &[Alert], scope: &Scope, meta: &Meta, l: Lang, tz: &Tz) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let s = summarize(alerts, l);
    let e = html_escape;
    let mut o = String::new();
    let _ = write!(
        o,
        r#"<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light; --c:#b42318; --h:#c4320a; --m:#b54708; --l:#475467; --i:#344054; }}
body {{ font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Helvetica Neue", Arial, sans-serif; color:#101828; margin: 32px auto; max-width: 980px; padding: 0 20px; }}
h1 {{ font-size: 22px; margin: 0 0 4px; }}
h2 {{ font-size: 16px; margin: 28px 0 10px; border-bottom: 1px solid #eaecf0; padding-bottom: 4px; }}
.meta {{ color:#475467; margin: 0 0 4px; }}
.warn {{ background:#fffaeb; border:1px solid #fedf89; padding:8px 12px; border-radius:6px; }}
.cards {{ display:flex; gap:10px; flex-wrap:wrap; }}
.card {{ border:1px solid #eaecf0; border-radius:8px; padding:8px 12px; min-width:92px; }}
.card b {{ display:block; font-size:20px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align:left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid #eaecf0; }}
th {{ background:#f9fafb; font-weight:600; }}
td.msg {{ white-space: pre-wrap; }}
.small {{ color:#475467; font-size: 12px; word-break: break-all; }}
.sev {{ display:inline-block; padding:1px 8px; border-radius: 10px; font-size: 12px; font-weight:600; color:#fff; white-space: nowrap; }}
.sev.critical {{ background: var(--c); }} .sev.high {{ background: var(--h); }} .sev.medium {{ background: var(--m); }}
.sev.low {{ background: var(--l); }} .sev.info {{ background: var(--i); }}
tr {{ page-break-inside: avoid; }}
@media print {{ body {{ margin: 0; max-width: none; }} }}
</style>
</head>
<body>
<h1>{title}</h1>
"#,
        lang = t(l, "fr", "en"),
        title = title(l),
    );
    let _ = writeln!(
        o,
        "<p class=\"meta\">{} : {} · {} : {}</p>",
        t(l, "Période", "Period"),
        e(&period(scope, l)),
        t(l, "Filtres", "Filters"),
        e(&filters(scope, l))
    );
    let _ = writeln!(
        o,
        "<p class=\"meta\">{} {} · Parabellum {}{}</p>",
        t(l, "Généré le", "Generated on"),
        e(&human(tz, meta.generated_at)),
        e(&meta.version),
        meta.db_version
            .as_ref()
            .map(|d| format!(" · {} {}", t(l, "base", "database"), e(d)))
            .unwrap_or_default()
    );
    if meta.truncated {
        let _ = writeln!(
            o,
            "<p class=\"warn\">{}</p>",
            e(&truncated_note(meta, alerts.len(), l))
        );
    }
    let _ = writeln!(
        o,
        "<h2>{}</h2>\n<div class=\"cards\">",
        t(l, "Résumé", "Summary")
    );
    let _ = writeln!(
        o,
        "<div class=\"card\"><b>{}</b>{}</div>",
        alerts.len(),
        t(l, "alertes", "alerts")
    );
    for (k, n) in &s.severity {
        let _ = writeln!(
            o,
            "<div class=\"card\"><b>{n}</b><span class=\"sev {}\">{}</span></div>",
            severity_class(*k),
            severity_label(*k, l)
        );
    }
    let _ = writeln!(o, "</div>");
    let _ = writeln!(
        o,
        "<table style=\"margin-top:12px\"><tr><th>{}</th><th>{}</th></tr>",
        t(l, "Statut", "Status"),
        t(l, "Alertes", "Alerts")
    );
    for (k, n) in &s.status {
        let _ = writeln!(o, "<tr><td>{}</td><td>{n}</td></tr>", status_label(*k, l));
    }
    let _ = writeln!(
        o,
        "</table>\n<table style=\"margin-top:12px\"><tr><th>{}</th><th>{}</th></tr>",
        t(l, "Type", "Kind"),
        t(l, "Alertes", "Alerts")
    );
    for (k, n) in &s.kind {
        let _ = writeln!(o, "<tr><td>{}</td><td>{n}</td></tr>", e(k));
    }
    let _ = writeln!(o, "</table>\n<h2>{}</h2>", t(l, "Alertes", "Alerts"));
    if alerts.is_empty() {
        let _ = writeln!(
            o,
            "<p>{}</p>",
            t(
                l,
                "Aucune alerte sur cette période.",
                "No alert in this period."
            )
        );
    } else {
        let _ = writeln!(
            o,
            "<table><tr><th>{}</th><th>{}</th><th>{}</th><th>{}</th></tr>",
            t(l, "Date", "Date"),
            t(l, "Gravité", "Severity"),
            t(l, "Alerte", "Alert"),
            t(l, "Type · statut", "Kind · status"),
        );
        for a in alerts {
            let mut detail = String::new();
            for ((fr, en), v) in details(a) {
                let _ = write!(
                    detail,
                    "<div class=\"small\">{} : {}</div>",
                    t(l, fr, en),
                    e(&v)
                );
            }
            let _ = writeln!(
                o,
                "<tr><td style=\"white-space:nowrap\">{}<div class=\"small\">#{}</div></td><td><span class=\"sev {}\">{}</span></td><td><b>{}</b><div class=\"msg\">{}</div>{}</td><td>{}<div class=\"small\">{}</div></td></tr>",
                e(&human(tz, a.ts)),
                a.id,
                severity_class(a.severity),
                severity_label(a.severity, l),
                e(&a.title),
                e(&a.message),
                detail,
                kind_label(a.kind, l),
                status_label(a.status, l),
            );
        }
        let _ = writeln!(o, "</table>");
    }
    let _ = writeln!(o, "</body>\n</html>");
    o
}

// ----- Request ---------------------------------------------------------------------------------

fn day_start<Tz: TimeZone>(tz: &Tz, s: &str) -> Result<i64, String> {
    let d = NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
        .map_err(|_| format!("date invalide : {s} (AAAA-MM-JJ attendu)"))?;
    crate::report::local_midnight(tz, d)
        .map(|d| d.timestamp())
        .ok_or_else(|| format!("date hors limites : {s}"))
}

/// Scope from the request: `to` inclusive (until the next local midnight).
pub fn scope<Tz: TimeZone>(
    tz: &Tz,
    from: Option<String>,
    to: Option<String>,
    include_resolved: bool,
    min_severity: Option<Severity>,
) -> Result<Scope, String> {
    let start = from.as_deref().map(|f| day_start(tz, f)).transpose()?;
    let end = match to.as_deref() {
        Some(d) => {
            let day = NaiveDate::parse_from_str(d.trim(), "%Y-%m-%d")
                .map_err(|_| format!("date invalide : {d} (AAAA-MM-JJ attendu)"))?;
            let next = day.succ_opt().ok_or("date hors limites")?;
            Some(
                crate::report::local_midnight(tz, next)
                    .map(|x| x.timestamp())
                    .ok_or("date hors limites")?,
            )
        }
        None => None,
    };
    if let (Some(a), Some(b)) = (start, end) {
        if b <= a {
            return Err("la date de fin précède la date de début".into());
        }
    }
    Ok(Scope {
        start,
        end,
        from_date: from.map(|s| s.trim().to_string()),
        to_date: to.map(|s| s.trim().to_string()),
        include_resolved,
        min_severity,
    })
}

/// Keeps the newest alerts that fit in [`MAX_CONTENT`] once rendered.
pub fn render_bounded<Tz: TimeZone>(
    format: AlertExportFormat,
    alerts: &[Alert],
    scope: &Scope,
    meta: &mut Meta,
    l: Lang,
    tz: &Tz,
    max: usize,
) -> (String, usize)
where
    Tz::Offset: std::fmt::Display,
{
    let mut n = alerts.len();
    loop {
        meta.truncated = meta.truncated || n < alerts.len();
        let out = render(format, &alerts[..n], scope, meta, l, tz);
        if out.len() <= max || n == 0 {
            return (out, n);
        }
        // Proportional cut, at least one alert less.
        let ratio = max as f64 / out.len() as f64;
        n = ((n as f64 * ratio * 0.95) as usize).min(n - 1);
    }
}

pub fn file_name<Tz: TimeZone>(format: AlertExportFormat, l: Lang, tz: &Tz, now: i64) -> String
where
    Tz::Offset: std::fmt::Display,
{
    let day = local(tz, now).map_or_else(String::new, |d| d.format("%Y-%m-%d").to_string());
    format!(
        "Parabellum – {} {day}.{}",
        t(l, "alertes", "alerts"),
        format.extension()
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn export(
    ctx: &Arc<Ctx>,
    format: AlertExportFormat,
    from: Option<String>,
    to: Option<String>,
    include_resolved: bool,
    min_severity: Option<Severity>,
    lang: Option<String>,
) -> Result<AlertExport, IpcError> {
    let l = Lang::parse(lang.as_deref());
    let tz = Local;
    let scope = scope(&tz, from, to, include_resolved, min_severity)
        .map_err(|m| IpcError::new(ErrorCode::BadRequest, m))?;
    let (start, end) = (
        scope.start.unwrap_or(i64::MIN),
        scope.end.unwrap_or(i64::MAX),
    );
    let (mut alerts, mut total) = ctx
        .store
        .run(move |s| s.alerts_between(start, end, include_resolved, MAX_ALERTS))
        .await?;
    if let Some(min) = min_severity {
        // Filtered here (severity lives in the JSON): `total` counts what was read.
        let before = alerts.len();
        alerts.retain(|a| a.severity >= min);
        total = total.saturating_sub((before - alerts.len()) as u32);
    }
    let now = pb_core::now_ts();
    let mut meta = Meta {
        generated_at: now,
        version: env!("CARGO_PKG_VERSION").to_string(),
        db_version: ctx.engine().db_status().version,
        total,
        truncated: (alerts.len() as u32) < total,
    };
    let (content, count) = render_bounded(format, &alerts, &scope, &mut meta, l, &tz, MAX_CONTENT);
    Ok(AlertExport {
        format,
        file_name: file_name(format, l, &tz, now),
        mime: format.mime().to_string(),
        content,
        count: count as u32,
        total: meta.total,
        truncated: meta.truncated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::FixedOffset;

    fn alert(id: i64, ts: i64, sev: Severity, title: &str, path: Option<&str>) -> Alert {
        Alert {
            id,
            ts,
            kind: AlertKind::Malware,
            severity: sev,
            title: title.into(),
            message: "Ligne 1\nLigne 2".into(),
            path: path.map(Into::into),
            sha256: Some("ab".repeat(32)),
            device_id: None,
            persistence_id: None,
            quarantine_id: None,
            status: AlertStatus::Open,
            actions: vec![pb_core::model::AlertAction::Acknowledge],
            process_pid: Some(4242),
            process_path: Some("/tmp/evil".into()),
            process_started_at: None,
            network_id: None,
            open_section: None,
        }
    }

    fn fixture() -> (Vec<Alert>, Scope, Meta) {
        let alerts = vec![
            alert(
                3,
                1_790_000_200,
                Severity::Critical,
                "Menace détectée",
                Some("/Users/q/Downloads/=cmd|' /C calc'!A0.dmg"),
            ),
            alert(
                2,
                1_790_000_100,
                Severity::Low,
                "<script>alert(1)</script>",
                Some("/tmp/a|b`c`.sh"),
            ),
            alert(1, 1_790_000_000, Severity::Medium, "Persistance", None),
        ];
        let scope = Scope {
            start: None,
            end: None,
            from_date: Some("2026-09-01".into()),
            to_date: Some("2026-09-30".into()),
            include_resolved: true,
            min_severity: None,
        };
        let meta = Meta {
            generated_at: 1_790_000_300,
            version: "0.1.0".into(),
            db_version: Some("2026.09.30".into()),
            total: 3,
            truncated: false,
        };
        (alerts, scope, meta)
    }

    fn paris() -> FixedOffset {
        FixedOffset::east_opt(3600).unwrap()
    }

    #[test]
    fn csv_is_formula_safe_and_complete() {
        let (a, ..) = fixture();
        let out = render(
            AlertExportFormat::Csv,
            &a,
            &fixture().1,
            &fixture().2,
            Lang::Fr,
            &paris(),
        );
        assert!(out.starts_with('\u{FEFF}'));
        let lines: Vec<&str> = out.trim_start_matches('\u{FEFF}').split("\r\n").collect();
        assert!(lines[0].starts_with("ID,Date,Gravité,Type,Statut,Titre,Message,Chemin"));
        // The dangerous path is neither run as a formula nor split into columns.
        assert!(
            out.contains("\"'=cmd|' /C calc'!A0.dmg\"") || out.contains("/Users/q/Downloads/=cmd")
        );
        assert_eq!(csv_cell("=1+1"), "'=1+1");
        assert_eq!(csv_cell("-2"), "'-2");
        assert_eq!(csv_cell("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("dit \"oui\""), "\"dit \"\"oui\"\"\"");
        assert_eq!(csv_cell("simple"), "simple");
        // Multi-line message kept in one quoted cell; local time with offset.
        assert!(out.contains("\"Ligne 1\nLigne 2\""));
        assert!(out.contains("2026-09-21T"), "{out}");
        assert!(out.contains("+01:00"));
        // Header + 3 rows + final CRLF.
        assert_eq!(out.matches("\r\n").count(), 4);
    }

    #[test]
    fn html_escapes_and_loads_nothing() {
        let (a, s, m) = fixture();
        let out = render(AlertExportFormat::Html, &a, &s, &m, Lang::Fr, &paris());
        assert!(out.contains("default-src 'none'"));
        assert!(!out.contains("<script>"));
        assert!(out.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(out.contains("<span class=\"sev critical\">Critique</span>"));
        assert!(out.contains("du 2026-09-01 au 2026-09-30"));
        for external in ["src=", "href=", "url(", "@import", "https:", "http:"] {
            assert!(!out.contains(external), "external resource: {external}");
        }
        let en = render(AlertExportFormat::Html, &a, &s, &m, Lang::En, &paris());
        assert!(en.contains("Parabellum alert report") && en.contains(">Critical<"));
    }

    #[test]
    fn markdown_cells_cannot_break_the_tables() {
        let (a, s, m) = fixture();
        let out = render(AlertExportFormat::Markdown, &a, &s, &m, Lang::Fr, &paris());
        assert!(out.starts_with("# Rapport des alertes Parabellum"));
        assert!(out.contains("/tmp/a\\|b\\`c\\`.sh"));
        assert!(out.contains("&lt;script&gt;"));
        assert!(out.contains("Ligne 1 Ligne 2"));
        assert!(out.contains("| Critique | 1 |"));
    }

    #[test]
    fn json_is_machine_readable() {
        let (a, s, m) = fixture();
        let out = render(AlertExportFormat::Json, &a, &s, &m, Lang::Fr, &paris());
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["report"], "parabellum.alerts");
        assert_eq!(v["count"], 3);
        assert_eq!(v["alerts"][0]["severity"], "critical");
        assert_eq!(v["alerts"][0]["id"], 3);
        assert!(v["alerts"][0]["date"].as_str().unwrap().ends_with("+01:00"));
        assert!(v["alerts"][0].get("actions").is_none());
        assert_eq!(v["summary"]["by_severity"]["critical"], 1);
        assert_eq!(v["summary"]["by_kind"]["malware"], 3);
        assert_eq!(v["threat_db_version"], "2026.09.30");
    }

    #[test]
    fn oversized_reports_keep_the_newest_alerts() {
        let (base, s, _) = fixture();
        let alerts: Vec<Alert> = (0..400)
            .map(|i| {
                let mut a = base[0].clone();
                a.id = 1000 - i;
                a.ts = 1_790_000_000 - i * 60;
                a
            })
            .collect();
        let mut meta = Meta {
            generated_at: 1_790_000_300,
            version: "0.1.0".into(),
            db_version: None,
            total: 400,
            truncated: false,
        };
        let (out, n) = render_bounded(
            AlertExportFormat::Csv,
            &alerts,
            &s,
            &mut meta,
            Lang::Fr,
            &paris(),
            20_000,
        );
        assert!(out.len() <= 20_000);
        assert!(n > 0 && n < 400);
        assert!(meta.truncated);
        assert!(
            out.contains(",1000,") || out.contains("\r\n1000,"),
            "newest kept"
        );
    }

    #[test]
    fn scope_and_names() {
        let tz = paris();
        let s = scope(
            &tz,
            Some("2026-11-01".into()),
            Some("2026-11-21".into()),
            true,
            None,
        )
        .unwrap();
        assert_eq!(s.end.unwrap() - s.start.unwrap(), 21 * 86_400);
        assert!(scope(
            &tz,
            Some("2026-11-21".into()),
            Some("2026-11-01".into()),
            true,
            None
        )
        .is_err());
        assert!(scope(&tz, Some("21/11/2026".into()), None, true, None).is_err());
        let open = scope(&tz, None, None, false, Some(Severity::High)).unwrap();
        assert!(open.start.is_none() && open.end.is_none());
        assert_eq!(
            file_name(AlertExportFormat::Markdown, Lang::Fr, &tz, 1_790_000_000),
            "Parabellum – alertes 2026-09-21.md"
        );
        assert_eq!(Lang::parse(Some("en-GB")), Lang::En);
        assert_eq!(Lang::parse(None), Lang::Fr);
    }
}
