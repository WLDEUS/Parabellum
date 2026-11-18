//! `parabellum lan …` and `parabellum permissions …`.
//!
//! `permissions extensions | resolve | reset` run locally as the calling user (no daemon): they read the
//! user's browser profiles, app bundles and talk to `tccutil`. The daemon runs `resolve` as the console user.

pub mod apps;
pub mod extensions;

use crate::cli::{Cli, Command, LanCmd, PermissionsCmd};
use crate::client::Client;
use crate::commands::{CliError, Output, EXIT_OK};
use crate::format::{table, ts};
use pb_core::ipc::Request;
use pb_core::model::*;
use serde::Serialize;
use std::path::PathBuf;

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

/// Commands handled here that need `sudo` (same policy as the daemon).
pub fn needs_admin(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Lan {
            action: Some(LanCmd::Trust { .. })
        }
    )
}

/// Commands that run without the daemon.
pub fn is_local(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Permissions {
            action: Some(
                PermissionsCmd::Extensions
                    | PermissionsCmd::Resolve { .. }
                    | PermissionsCmd::Reset { .. }
            )
        }
    )
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/empty"))
}

/// Every browser extension of the current user.
pub fn extensions_report() -> ExtensionsReport {
    let home = home();
    let mut errors = Vec::new();
    let mut list = Vec::new();
    for (browser, rel) in extensions::CHROMIUM {
        list.extend(extensions::chromium(browser, &home.join(rel), &mut errors));
    }
    list.extend(extensions::firefox(
        &home.join(extensions::FIREFOX_PROFILES),
    ));
    if cfg!(target_os = "macos") {
        match apps::run(
            extensions::PLUGINKIT,
            &["-mAvvv", "-p", "com.apple.Safari.web-extension"],
            std::time::Duration::from_secs(20),
        ) {
            Some((_, out, _)) => {
                list.extend(extensions::safari(&extensions::parse_pluginkit(&out)))
            }
            None => errors.push("Safari : pluginkit n'a pas répondu".into()),
        }
    }
    list.sort_by(|a, b| b.risk.cmp(&a.risk).then_with(|| a.name.cmp(&b.name)));
    ExtensionsReport {
        generated_at: pb_core::now_ts(),
        extensions: list,
        errors,
    }
}

pub fn local(cli: &Cli, io: &mut Output<'_>) -> Result<i32, CliError> {
    let Command::Permissions {
        action: Some(action),
    } = &cli.command
    else {
        return Err(CliError::Usage("commande locale".into()));
    };
    match action {
        PermissionsCmd::Extensions => {
            let r = extensions_report();
            emit(cli, io, &r, |r| {
                let rows: Vec<Vec<String>> = r
                    .extensions
                    .iter()
                    .map(|e| {
                        vec![
                            severity(e.risk).into(),
                            e.browser.clone(),
                            e.name.clone(),
                            match e.enabled {
                                Some(false) => "désactivée".into(),
                                _ => "active".into(),
                            },
                            e.reasons.first().cloned().unwrap_or_default(),
                        ]
                    })
                    .collect();
                table(
                    &["Risque", "Navigateur", "Extension", "État", "Pourquoi"],
                    &rows,
                )
            })?;
        }
        PermissionsCmd::Resolve { clients } => {
            let ids = apps::resolve(clients, &home());
            emit(cli, io, &ids, |ids| {
                ids.iter()
                    .map(|i| format!("{}\t{}\n", i.client, i.name.clone().unwrap_or_default()))
                    .collect()
            })?;
        }
        PermissionsCmd::Reset { service, bundle_id } => {
            let r = apps::reset(service, bundle_id).map_err(CliError::Usage)?;
            let ok = r.ok;
            emit(cli, io, &r, |r| format!("{}\n", r.message))?;
            if !ok {
                return Ok(crate::commands::EXIT_ERROR);
            }
        }
        PermissionsCmd::Audit { .. } => return Err(CliError::Usage("commande du daemon".into())),
    }
    Ok(EXIT_OK)
}

fn severity(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "faible",
        Severity::Medium => "moyen",
        Severity::High => "élevé",
        Severity::Critical => "critique",
    }
}

fn device_type(t: LanDeviceType) -> &'static str {
    match t {
        LanDeviceType::Router => "routeur",
        LanDeviceType::Computer => "ordinateur",
        LanDeviceType::Phone => "téléphone",
        LanDeviceType::Tablet => "tablette",
        LanDeviceType::Tv => "TV",
        LanDeviceType::Speaker => "enceinte",
        LanDeviceType::Printer => "imprimante",
        LanDeviceType::Camera => "caméra",
        LanDeviceType::Nas => "NAS",
        LanDeviceType::Console => "console",
        LanDeviceType::Iot => "objet connecté",
        LanDeviceType::Unknown => "inconnu",
    }
}

/// Human view of a LAN status.
pub fn lan_status(s: &LanStatus) -> String {
    let mut o = String::new();
    match &s.network {
        Some(n) => {
            o.push_str(&format!(
                "Réseau {} ({}){}{} — dernière analyse : {}\n",
                n.name,
                n.id,
                if n.trusted { ", de confiance" } else { "" },
                n.subnet
                    .as_deref()
                    .map(|x| format!(", {x}"))
                    .unwrap_or_default(),
                n.last_scan.map(ts).unwrap_or_else(|| "jamais".into())
            ));
            let rows: Vec<Vec<String>> = n
                .devices
                .iter()
                .map(|d| {
                    vec![
                        if d.online { "●".into() } else { "○".into() },
                        d.ipv4.clone().unwrap_or_default(),
                        d.mac.clone(),
                        device_type(d.device_type).into(),
                        d.name
                            .clone()
                            .or_else(|| d.mdns_name.clone())
                            .or_else(|| d.hostname.clone())
                            .unwrap_or_default(),
                        if d.private_mac {
                            "adresse privée".into()
                        } else {
                            d.vendor.clone().unwrap_or_default()
                        },
                        if d.trusted || d.is_self || d.is_gateway {
                            "connu".into()
                        } else {
                            "inconnu".into()
                        },
                    ]
                })
                .collect();
            o.push_str(&table(
                &["", "IPv4", "MAC", "Type", "Nom", "Fabricant", "Statut"],
                &rows,
            ));
        }
        None => o.push_str("Aucun réseau.\n"),
    }
    if s.scanning {
        o.push_str(&format!("Analyse en cours : {:.0} %\n", s.progress * 100.0));
    }
    if let Some(m) = &s.message {
        o.push_str(&format!("{m}\n"));
    }
    o
}

pub fn lan(
    cli: &Cli,
    io: &mut Output<'_>,
    c: &mut Client,
    action: &Option<LanCmd>,
) -> Result<i32, CliError> {
    match action {
        None => {
            let s: LanStatus = c.call(Request::LanStatus { network_id: None })?;
            emit(cli, io, &s, lan_status)?;
        }
        Some(LanCmd::Status { network }) => {
            let s: LanStatus = c.call(Request::LanStatus {
                network_id: network.clone(),
            })?;
            emit(cli, io, &s, lan_status)?;
        }
        Some(LanCmd::Scan { active, passive }) => {
            let active = if *active {
                Some(true)
            } else if *passive {
                Some(false)
            } else {
                None
            };
            let s: LanStatus = c.call(Request::LanScan { active })?;
            emit(cli, io, &s, |_| {
                "Analyse lancée (parabellum lan pour le résultat).\n".into()
            })?;
        }
        Some(LanCmd::Ports { mac }) => {
            let d: LanDevice = c.call(Request::LanPorts { mac: mac.clone() })?;
            emit(cli, io, &d, |d| {
                if d.open_ports.is_empty() {
                    "Aucun port ouvert parmi les 20 vérifiés.\n".into()
                } else {
                    format!(
                        "Ports ouverts : {}\n",
                        d.open_ports
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                }
            })?;
        }
        Some(LanCmd::Rename { network, mac, name }) => {
            let d: LanDevice = c.call(Request::LanSetDevice {
                network_id: network.clone(),
                mac: mac.clone(),
                name: Some(name.clone()),
                trusted: None,
            })?;
            emit(cli, io, &d, |_| "Appareil renommé.\n".into())?;
        }
        Some(LanCmd::Trust { network, mac }) | Some(LanCmd::Untrust { network, mac }) => {
            let trusted = matches!(action, Some(LanCmd::Trust { .. }));
            let d: LanDevice = c.call(Request::LanSetDevice {
                network_id: network.clone(),
                mac: mac.clone(),
                name: None,
                trusted: Some(trusted),
            })?;
            emit(cli, io, &d, |d| {
                if d.trusted {
                    "Appareil marqué comme connu.\n".into()
                } else {
                    "Appareil marqué comme inconnu.\n".into()
                }
            })?;
        }
        Some(LanCmd::Forget { network, mac }) => {
            c.call::<serde_json::Value>(Request::LanForgetDevice {
                network_id: network.clone(),
                mac: mac.clone(),
            })?;
            if !cli.json {
                writeln!(io.out, "Appareil oublié.")?;
            }
        }
    }
    Ok(EXIT_OK)
}

pub fn permissions(
    cli: &Cli,
    io: &mut Output<'_>,
    c: &mut Client,
    action: &Option<PermissionsCmd>,
) -> Result<i32, CliError> {
    let refresh = matches!(action, Some(PermissionsCmd::Audit { refresh: true }));
    let r: PermissionsReport = c.call(Request::PermissionsAudit { refresh })?;
    emit(cli, io, &r, |r| {
        let rows: Vec<Vec<String>> = r
            .grants
            .iter()
            .filter(|g| g.auth != TccAuthValue::Denied)
            .map(|g| {
                vec![
                    severity(g.risk).into(),
                    g.service_label.clone(),
                    g.app_name.clone().unwrap_or_else(|| g.client.clone()),
                    match g.installed {
                        Some(false) => "absente".into(),
                        _ => String::new(),
                    },
                    g.reasons.first().cloned().unwrap_or_default(),
                ]
            })
            .collect();
        let mut o = table(&["Risque", "Permission", "App", "", "Pourquoi"], &rows);
        for e in &r.errors {
            o.push_str(&format!("⚠ {e}\n"));
        }
        o
    })?;
    Ok(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Cli {
        Cli::try_parse_args(std::iter::once("parabellum").chain(args.iter().copied())).unwrap()
    }

    #[test]
    fn classification() {
        assert!(is_local(&p(&["permissions", "extensions"]).command));
        assert!(is_local(
            &p(&["permissions", "resolve", "--", "com.a", "/x"]).command
        ));
        assert!(is_local(
            &p(&["permissions", "reset", "Camera", "com.a"]).command
        ));
        assert!(!is_local(&p(&["permissions", "audit"]).command));
        assert!(!is_local(&p(&["permissions"]).command));
        assert!(needs_admin(
            &p(&["lan", "trust", "gw:00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"]).command
        ));
        assert!(!needs_admin(
            &p(&[
                "lan",
                "untrust",
                "gw:00:11:22:33:44:55",
                "aa:bb:cc:dd:ee:ff"
            ])
            .command
        ));
        assert!(crate::commands::needs_admin(
            &p(&["lan", "trust", "gw:x", "m"]).command
        ));
        assert!(
            Cli::try_parse_args(["parabellum", "lan", "scan", "--active", "--passive"]).is_err()
        );
    }

    #[test]
    fn lan_table() {
        let s = LanStatus {
            enabled: true,
            network: Some(LanNetwork {
                id: "gw:00:24:d4:a1:b2:c3".into(),
                name: "Livebox".into(),
                interface: "en0".into(),
                subnet: Some("192.168.1.0/24".into()),
                trusted: true,
                current: true,
                last_scan: None,
                last_scan_mode: None,
                devices: vec![],
            }),
            interval_minutes: 15,
            ..Default::default()
        };
        let t = lan_status(&s);
        assert!(t.contains("Livebox") && t.contains("de confiance") && t.contains("jamais"));
    }
}
