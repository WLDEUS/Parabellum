//! `parabellum travel [status|on|off]` (Mode Voyage).

use crate::cli::{Cli, DnsArg};
use crate::client::Client;
use crate::commands::{CliError, Output, EXIT_OK};
use crate::format::ts;
use pb_core::ipc::Request;
use pb_core::model::TravelStatus;

/// Human-readable travel status (French).
pub fn status_text(s: &TravelStatus) -> String {
    let mut o = String::new();
    if s.active {
        o.push_str(&format!(
            "Mode Voyage : ACTIF{}{}\n",
            s.since
                .map(|t| format!(" depuis {}", ts(t)))
                .unwrap_or_default(),
            if s.automatic { " (automatique)" } else { "" }
        ));
        if let Some(n) = &s.network {
            o.push_str(&format!("Réseau        : {n}\n"));
        }
        for c in &s.changes {
            o.push_str(&format!("  - {}\n", c.label));
        }
    } else {
        o.push_str("Mode Voyage : inactif\n");
        if s.untrusted_network {
            o.push_str("Réseau actuel non approuvé : parabellum travel on\n");
        }
    }
    for w in &s.warnings {
        o.push_str(&format!("Attention : {w}\n"));
    }
    if let Some(m) = &s.message {
        o.push_str(&format!("{m}\n"));
    }
    o
}

pub fn run(cli: &Cli, io: &mut Output<'_>, c: &mut Client, state: DnsArg) -> Result<i32, CliError> {
    let req = match state {
        DnsArg::Status => Request::TravelStatus,
        DnsArg::On => Request::TravelEnable,
        DnsArg::Off => Request::TravelDisable,
    };
    let s: TravelStatus = c.call(req)?;
    if cli.json {
        let j = serde_json::to_string_pretty(&s).map_err(|e| CliError::Usage(e.to_string()))?;
        writeln!(io.out, "{j}")?;
    } else {
        write!(io.out, "{}", status_text(&s))?;
    }
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_core::model::TravelItem;

    #[test]
    fn text_and_admin() {
        let s = TravelStatus {
            active: true,
            network: Some("Gare-WiFi".into()),
            changes: vec![TravelItem {
                id: "dns".into(),
                label: "Blocage DNS".into(),
            }],
            warnings: vec!["VPN non configuré".into()],
            ..Default::default()
        };
        let t = status_text(&s);
        assert!(t.starts_with("Mode Voyage : ACTIF"));
        assert!(t.contains("  - Blocage DNS") && t.contains("Attention : VPN non configuré"));
        let off = TravelStatus {
            untrusted_network: true,
            ..Default::default()
        };
        assert!(status_text(&off).contains("parabellum travel on"));
        let parse = |a: &[&str]| {
            Cli::try_parse_args(std::iter::once("parabellum").chain(a.iter().copied())).unwrap()
        };
        assert!(crate::commands::needs_admin(
            &parse(&["travel", "off"]).command
        ));
        assert!(!crate::commands::needs_admin(
            &parse(&["travel", "on"]).command
        ));
        assert!(!crate::commands::needs_admin(&parse(&["travel"]).command));
    }
}
