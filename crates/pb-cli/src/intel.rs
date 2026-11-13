//! `intel` command: domain model and behavioural baseline (execution + French output).

use crate::cli::{Cli, IntelCmd};
use crate::client::Client;
use crate::commands::{CliError, Output, EXIT_OK, EXIT_THREATS};
use crate::format::ts;
use pb_core::ipc::Request;
use pb_core::model::*;
use serde::Serialize;

fn emit<T: Serialize>(
    cli: &Cli,
    io: &mut Output<'_>,
    v: &T,
    human: impl FnOnce(&T) -> String,
) -> Result<(), CliError> {
    if cli.json {
        let s = serde_json::to_string_pretty(v).map_err(|e| CliError::Usage(e.to_string()))?;
        writeln!(io.out, "{s}")?;
    } else {
        write!(io.out, "{}", human(v))?;
    }
    Ok(())
}

fn pct(x: f32) -> String {
    format!("{:.0} %", x * 100.0)
}

/// Human output of `intel status`.
pub fn status(s: &IntelligenceStatus) -> String {
    let mut o = String::new();
    let b = &s.behavior;
    o.push_str("Comportement (appris sur ce Mac)\n");
    if !b.enabled {
        o.push_str("  désactivé\n");
    } else if b.learning {
        o.push_str(&format!(
            "  apprentissage : {}{}\n",
            pct(b.learning_progress),
            b.learning_until
                .map(|t| format!(" (jusqu'au {})", ts(t)))
                .unwrap_or_default()
        ));
    } else {
        o.push_str("  surveillance active\n");
    }
    o.push_str(&format!(
        "  {} événements, {} programmes profilés, {} comportements connus, référence {} Ko\n",
        b.events_observed,
        b.profiles,
        b.behaviors,
        b.baseline_bytes / 1024
    ));
    o.push_str(&format!(
        "  anomalies : {} (24 h), {} (7 j)\n",
        b.anomalies_24h, b.anomalies_7d
    ));
    if let Some(m) = &b.message {
        o.push_str(&format!("  note : {m}\n"));
    }
    for a in b.recent_anomalies.iter().take(10) {
        o.push_str(&format!(
            "  [{}] {} {}  — {}{}\n",
            a.id,
            ts(a.ts),
            pct(a.score),
            a.summary,
            if a.marked_normal { " (normal)" } else { "" }
        ));
    }
    let d = &s.domains;
    o.push_str("\nDomaines (hameçonnage)\n");
    o.push_str(&format!(
        "  {} ; DNS Parabellum {} ; modèle {} ; blocage ML {}\n",
        if d.enabled { "activé" } else { "désactivé" },
        if d.dns_active { "actif" } else { "inactif" },
        if d.model_loaded {
            "chargé"
        } else {
            "absent (règles)"
        },
        if d.block_enabled {
            "activé"
        } else {
            "désactivé"
        }
    ));
    o.push_str(&format!(
        "  {} noms analysés ({} en 24 h), {} signalés, {} bloqués\n",
        d.scored_total, d.scored_24h, d.flagged_total, d.blocked_count
    ));
    if let Some(m) = &d.message {
        o.push_str(&format!("  note : {m}\n"));
    }
    for f in d.top_flagged.iter().take(15) {
        o.push_str(&format!(
            "  {} {}  {}{}{}\n",
            pct(f.score),
            f.domain,
            f.reasons.first().cloned().unwrap_or_default(),
            if f.blocked { " [bloqué]" } else { "" },
            if f.allowed { " [autorisé]" } else { "" }
        ));
    }
    o.push_str("\nModèles\n");
    for m in &s.models {
        o.push_str(&format!(
            "  {} : {}{}{}\n",
            m.name,
            if m.loaded { "chargé" } else { "non chargé" },
            m.version
                .as_ref()
                .map(|v| format!(", version {v}"))
                .unwrap_or_default(),
            m.metrics
                .get("auc")
                .map(|a| format!(", AUC {a:.3}"))
                .unwrap_or_default()
        ));
    }
    o
}

/// Human output of `intel score`.
pub fn verdict(v: &DomainVerdictInfo) -> String {
    let mut o = format!("{}\n", v.domain);
    if let Some(why) = &v.skipped {
        o.push_str(&format!("  non évalué : {why}\n"));
        return o;
    }
    o.push_str(&format!(
        "  score : {} ({}){}\n",
        v.score.map(pct).unwrap_or_default(),
        match v.source.as_deref() {
            Some("model") => "modèle",
            _ => "règles de secours",
        },
        if v.allowed {
            " — autorisé par vous"
        } else {
            ""
        }
    ));
    o.push_str(&format!(
        "  verdict : {}\n",
        if v.would_block {
            "malveillant (serait bloqué si le blocage ML est activé)"
        } else if v.flagged {
            "suspect"
        } else {
            "rien d'anormal"
        }
    ));
    for r in &v.reasons {
        o.push_str(&format!("  - {r}\n"));
    }
    o
}

pub fn intel(
    cli: &Cli,
    io: &mut Output<'_>,
    c: &mut Client,
    action: &Option<IntelCmd>,
) -> Result<i32, CliError> {
    match action.as_ref().unwrap_or(&IntelCmd::Status) {
        IntelCmd::Status => {
            let s: IntelligenceStatus = c.call(Request::IntelStatus)?;
            emit(cli, io, &s, status)?;
        }
        IntelCmd::Score { domain } => {
            let v: DomainVerdictInfo = c.call(Request::IntelScoreDomain {
                domain: domain.clone(),
            })?;
            emit(cli, io, &v, verdict)?;
            if v.flagged {
                return Ok(EXIT_THREATS);
            }
        }
        IntelCmd::AllowDomain { domain } => {
            let s: IntelligenceStatus = c.call(Request::IntelAllowDomain {
                domain: domain.clone(),
            })?;
            emit(cli, io, &s, |_| format!("{domain} autorisé.\n"))?;
        }
        IntelCmd::MarkNormal { anomaly_id } => {
            let s: IntelligenceStatus = c.call(Request::IntelMarkNormal {
                anomaly_id: anomaly_id.clone(),
            })?;
            emit(cli, io, &s, |_| "Ajouté à la référence.\n".to_string())?;
        }
        IntelCmd::ResetBaseline => {
            let s: IntelligenceStatus = c.call(Request::IntelResetBaseline)?;
            emit(cli, io, &s, |_| {
                "Référence effacée : nouvelle période d'apprentissage.\n".to_string()
            })?;
        }
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_status_and_verdict() {
        let mut s = IntelligenceStatus::default();
        s.behavior.enabled = true;
        s.behavior.learning = true;
        s.behavior.learning_progress = 0.5;
        s.domains.top_flagged.push(FlaggedDomain {
            domain: "paypa1-login.xyz".into(),
            registrable: "paypa1-login.xyz".into(),
            score: 0.97,
            first_seen: 0,
            last_seen: 0,
            hits: 1,
            reasons: vec!["Ressemble à « paypal »".into()],
            blocked: true,
            allowed: false,
            alert_id: None,
        });
        let out = status(&s);
        assert!(out.contains("apprentissage : 50 %"));
        assert!(out.contains("97 % paypa1-login.xyz"));
        assert!(out.contains("[bloqué]"));
        let v = DomainVerdictInfo {
            domain: "x.local".into(),
            registrable: None,
            score: None,
            flagged: false,
            would_block: false,
            source: None,
            skipped: Some("nom local".into()),
            reasons: vec![],
            allowed: false,
        };
        assert!(verdict(&v).contains("non évalué : nom local"));
    }
}
