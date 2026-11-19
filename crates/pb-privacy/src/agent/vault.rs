//! Obsidian-compatible notes of the GDPR campaign: one note per broker (YAML properties + history), a
//! dashboard and the agent's journal, linked with `[[wikilinks]]`. Written by the CLI **as you** into
//! your folder (the daemon never writes there); the daemon's own store stays the source of truth, so
//! editing the notes can never steer the agent. Everything under the `## Mes notes` heading of a broker
//! note is kept when the note is regenerated.

use pb_core::model::{MailAgentEvent, RemovalRequest, RemovalStatus, ReplyKind};

pub const DASHBOARD: &str = "Tableau de bord.md";
pub const JOURNAL: &str = "Journal de l'agent.md";
pub const BROKERS_DIR: &str = "Organismes";
pub const USER_SECTION: &str = "## Mes notes";
const GENERATED: &str =
    "<!-- Généré par Parabellum : tout ce qui est au-dessus de « Mes notes » est réécrit. -->";

pub fn status_label(s: RemovalStatus) -> &'static str {
    match s {
        RemovalStatus::Queued => "en file",
        RemovalStatus::DraftReady => "brouillon prêt",
        RemovalStatus::Sent => "envoyée",
        RemovalStatus::Reminded => "relancée",
        RemovalStatus::Escalated => "plainte conseillée",
        RemovalStatus::Completed => "effacée",
        RemovalStatus::Refused => "refusée",
        RemovalStatus::NeedsForm => "formulaire web",
        RemovalStatus::NeedsYou => "à toi de répondre",
        RemovalStatus::Failed => "échec",
    }
}

pub fn kind_label(k: ReplyKind) -> &'static str {
    match k {
        ReplyKind::Erased => "données effacées",
        ReplyKind::NoData => "aucune donnée",
        ReplyKind::Acknowledged => "accusé de réception",
        ReplyKind::IdentityRequested => "pièce d'identité demandée",
        ReplyKind::InfoRequested => "informations demandées",
        ReplyKind::FormRequired => "formulaire exigé",
        ReplyKind::Refused => "refus",
        ReplyKind::AutoReply => "réponse automatique",
        ReplyKind::Bounce => "adresse rejetée",
        ReplyKind::Other => "à lire",
    }
}

fn status_key(s: RemovalStatus) -> &'static str {
    match s {
        RemovalStatus::Queued => "queued",
        RemovalStatus::DraftReady => "draft_ready",
        RemovalStatus::Sent => "sent",
        RemovalStatus::Reminded => "reminded",
        RemovalStatus::Escalated => "escalated",
        RemovalStatus::Completed => "completed",
        RemovalStatus::Refused => "refused",
        RemovalStatus::NeedsForm => "needs_form",
        RemovalStatus::NeedsYou => "needs_you",
        RemovalStatus::Failed => "failed",
    }
}

/// A file name safe on APFS and in Obsidian links (no `/ \ : # ^ [ ] |`, no leading dot).
pub fn note_name(broker: &str) -> String {
    let s: String = broker
        .chars()
        .map(|c| {
            if c.is_control()
                || matches!(
                    c,
                    '/' | '\\' | ':' | '#' | '^' | '[' | ']' | '|' | '*' | '?' | '"' | '<' | '>'
                )
            {
                '-'
            } else {
                c
            }
        })
        .collect();
    let s = s.trim().trim_start_matches('.').trim();
    let s: String = s.chars().take(80).collect();
    if s.is_empty() {
        "Organisme".into()
    } else {
        s
    }
}

fn day(ts: Option<i64>) -> String {
    use chrono::TimeZone;
    ts.and_then(|t| chrono::Local.timestamp_opt(t, 0).single())
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// YAML string (always double-quoted, escaped).
fn yaml(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars().filter(|c| !c.is_control()) {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Text that cannot open a link, an embed, a tag or HTML in Obsidian.
fn text(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '[' | ']' | '<' | '>' | '|' | '`' => ' ',
            '#' => '♯',
            _ => c,
        })
        .collect()
}

/// Latest request per broker (several requests exist after periodic repeats).
fn latest(requests: &[RemovalRequest]) -> Vec<&RemovalRequest> {
    let mut by: std::collections::BTreeMap<String, &RemovalRequest> = Default::default();
    for r in requests {
        let e = by.entry(note_name(&r.broker_name)).or_insert(r);
        if r.created_at >= e.created_at {
            *e = r;
        }
    }
    by.into_values().collect()
}

/// Every generated file: `(relative path, content)`.
pub fn render(
    requests: &[RemovalRequest],
    events: &[MailAgentEvent],
    now: i64,
) -> Vec<(String, String)> {
    let mut files = Vec::new();
    let reqs = latest(requests);
    for r in &reqs {
        let name = note_name(&r.broker_name);
        let mut s = String::new();
        s.push_str("---\n");
        s.push_str(&format!("organisme: {}\n", yaml(&r.broker_name)));
        s.push_str(&format!("statut: {}\n", status_key(r.status)));
        if let Some(e) = &r.broker_email {
            s.push_str(&format!("email: {}\n", yaml(e)));
        }
        for (k, v) in [
            ("creee", Some(r.created_at)),
            ("envoyee", r.sent_at),
            ("echeance", r.due_at),
            ("relancee", r.reminded_at),
            ("close", r.closed_at),
            ("derniere_reponse", r.last_reply_at),
        ] {
            if v.is_some() {
                s.push_str(&format!("{k}: {}\n", day(v)));
            }
        }
        if let Some(u) = &r.opt_out_url {
            s.push_str(&format!("formulaire: {}\n", yaml(u)));
        }
        s.push_str("tags: [rgpd]\n---\n");
        s.push_str(GENERATED);
        s.push_str(&format!(
            "\n\n# {}\n\nStatut : **{}**",
            text(&r.broker_name),
            status_label(r.status)
        ));
        if let Some(k) = r.last_reply_kind {
            s.push_str(&format!(" — dernière réponse : {}", kind_label(k)));
        }
        s.push('\n');
        if let Some(sum) = &r.last_reply_summary {
            s.push_str(&format!("\n> {}\n", text(sum)));
        }
        if matches!(r.status, RemovalStatus::NeedsYou | RemovalStatus::NeedsForm) {
            s.push_str("\n**À faire :** lire la réponse dans la boîte RGPD et y répondre toi-même, puis changer le statut dans Parabellum.\n");
        }
        let hist: Vec<&MailAgentEvent> = events
            .iter()
            .filter(|e| note_name(&e.broker_name) == name)
            .take(50)
            .collect();
        s.push_str("\n## Historique\n\n");
        if hist.is_empty() {
            s.push_str("_Aucune réponse lue pour l'instant._\n");
        }
        for e in hist {
            s.push_str(&format!(
                "- {} — {} : {}\n",
                day(Some(e.ts)),
                kind_label(e.kind),
                text(&e.summary)
            ));
        }
        s.push_str(&format!("\n{USER_SECTION}\n\n"));
        files.push((format!("{BROKERS_DIR}/{name}.md"), s));
    }
    // Dashboard.
    let mut d = String::new();
    d.push_str("---\ntags: [rgpd]\n---\n");
    d.push_str(GENERATED);
    d.push_str(&format!(
        "\n\n# Effacement de mes données — tableau de bord\n\nMis à jour le {}.\n",
        day(Some(now))
    ));
    let groups: [(&str, &[RemovalStatus]); 4] = [
        (
            "À toi de jouer",
            &[
                RemovalStatus::NeedsYou,
                RemovalStatus::NeedsForm,
                RemovalStatus::Escalated,
                RemovalStatus::DraftReady,
            ],
        ),
        (
            "En attente de réponse",
            &[
                RemovalStatus::Queued,
                RemovalStatus::Sent,
                RemovalStatus::Reminded,
            ],
        ),
        ("Terminées", &[RemovalStatus::Completed]),
        (
            "Refus et échecs",
            &[RemovalStatus::Refused, RemovalStatus::Failed],
        ),
    ];
    for (title, set) in groups {
        let list: Vec<&&RemovalRequest> = reqs.iter().filter(|r| set.contains(&r.status)).collect();
        d.push_str(&format!("\n## {title} ({})\n\n", list.len()));
        for r in list {
            d.push_str(&format!(
                "- [[{}/{}|{}]] — {}\n",
                BROKERS_DIR,
                note_name(&r.broker_name),
                text(&r.broker_name),
                status_label(r.status)
            ));
        }
    }
    d.push_str(&format!(
        "\nVoir aussi : [[{}]]\n",
        JOURNAL.trim_end_matches(".md")
    ));
    files.push((DASHBOARD.to_string(), d));
    // Journal.
    let mut j = String::new();
    j.push_str("---\ntags: [rgpd]\n---\n");
    j.push_str(GENERATED);
    j.push_str(
        "\n\n# Journal de l'agent\n\nRéponses lues par l'agent local (le plus récent en haut).\n\n",
    );
    for e in events.iter().take(200) {
        j.push_str(&format!(
            "- {} — [[{}/{}|{}]] — {} ({}) : {}\n",
            day(Some(e.ts)),
            BROKERS_DIR,
            note_name(&e.broker_name),
            text(&e.broker_name),
            kind_label(e.kind),
            text(&e.classified_by),
            text(&e.summary)
        ));
    }
    files.push((JOURNAL.to_string(), j));
    files
}

/// Keep the user's `## Mes notes` section of `existing` under the regenerated note.
pub fn merge(existing: Option<&str>, generated: &str) -> String {
    let Some(old) = existing else {
        return generated.to_string();
    };
    let Some(pos) = old.find(USER_SECTION) else {
        return generated.to_string();
    };
    let user = &old[pos + USER_SECTION.len()..];
    match generated.find(USER_SECTION) {
        Some(g) => format!("{}{}{}", &generated[..g], USER_SECTION, user),
        None => generated.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(name: &str, status: RemovalStatus) -> RemovalRequest {
        RemovalRequest {
            id: "11111111-2222-4333-8444-555555555555".into(),
            broker_id: "acme".into(),
            broker_name: name.into(),
            broker_email: Some("privacy@acme.example".into()),
            status,
            created_at: 1_700_000_000,
            sent_at: Some(1_700_000_100),
            due_at: None,
            reminded_at: None,
            closed_at: None,
            opt_out_url: None,
            draft_path: None,
            note: None,
            last_error: None,
            last_reply_at: Some(1_700_100_000),
            last_reply_kind: Some(ReplyKind::IdentityRequested),
            last_reply_summary: Some("Demande une [[pièce]] d'identité #urgent".into()),
        }
    }

    #[test]
    fn renders_obsidian_notes() {
        let ev = MailAgentEvent {
            ts: 1_700_100_000,
            request_id: None,
            broker_name: "Acme/Data: \"FR\"".into(),
            kind: ReplyKind::IdentityRequested,
            classified_by: "qwen3:4b".into(),
            summary: "pièce d'identité".into(),
            new_status: Some(RemovalStatus::NeedsYou),
        };
        let files = render(
            &[req("Acme/Data: \"FR\"", RemovalStatus::NeedsYou)],
            &[ev],
            1_700_200_000,
        );
        let (path, note) = &files[0];
        assert_eq!(path, "Organismes/Acme-Data- -FR-.md");
        assert!(note.starts_with("---\norganisme: \"Acme/Data: \\\"FR\\\"\"\nstatut: needs_you\n"));
        assert!(!note.contains("[[pièce]]") && !note.contains("#urgent"));
        assert!(note.contains("**À faire :**"));
        let dash = &files.iter().find(|(p, _)| p == DASHBOARD).unwrap().1;
        assert!(dash.contains("## À toi de jouer (1)"));
        assert!(dash.contains("[[Organismes/Acme-Data- -FR-|"));
    }

    #[test]
    fn keeps_user_notes() {
        let old = "old\n## Mes notes\n\nappelé le DPO le 3 mars\n";
        let new = "new\n## Mes notes\n\n";
        assert_eq!(
            merge(Some(old), new),
            "new\n## Mes notes\n\nappelé le DPO le 3 mars\n"
        );
        assert_eq!(merge(None, new), new);
        assert_eq!(note_name("..secret"), "secret");
        assert_eq!(note_name(""), "Organisme");
    }
}
