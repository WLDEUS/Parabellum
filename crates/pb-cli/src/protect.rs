//! `vpn`, `guard` and `privacy` commands (execution + French output).

use crate::cli::*;
use crate::client::Client;
use crate::commands::{CliError, Output, EXIT_OK, EXIT_THREATS};
use crate::format::{table, ts};
use pb_core::config::{Config, VpnBackend, VpnMode};
use pb_core::ipc::Request;
use pb_core::model::*;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

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

fn yes_no(b: bool) -> &'static str {
    if b {
        "oui"
    } else {
        "non"
    }
}

// ---------------------------------------------------------------------------------------------
// Admin classification (mirrors pb-core's `Request::requires_admin`)
// ---------------------------------------------------------------------------------------------

/// Representative request of a protection command, for the sudo check.
pub fn admin_probe(cmd: &Command) -> Option<Request> {
    let s = String::new;
    Some(match cmd {
        Command::Vpn { action: Some(a) } => match a {
            VpnCmd::Disconnect => Request::VpnDisconnect,
            VpnCmd::Import { .. } => Request::VpnImportProfile { profile: s() },
            VpnCmd::Remove => Request::VpnRemoveProfile,
            VpnCmd::Trust { .. } => Request::SetNetworkTrust {
                network_id: s(),
                trusted: true,
            },
            VpnCmd::Mode { .. } | VpnCmd::Backend { .. } | VpnCmd::KillSwitch { .. } => {
                Request::SetConfig {
                    config: Config::default(),
                }
            }
            _ => return None,
        },
        Command::Guard {
            action: Some(GuardCmd::Restore { .. }),
        } => Request::RestoreFromSnapshot {
            snapshot: s(),
            path: s(),
        },
        Command::Privacy { action } => match action {
            PrivacyCmd::Profile {
                action: Some(ProfileCmd::Show { reveal: true }),
            } => Request::PrivacyGetProfile { reveal: true },
            PrivacyCmd::Profile {
                action: Some(ProfileCmd::Set { .. }),
            } => Request::PrivacySetProfile {
                profile: IdentityProfile::default(),
            },
            PrivacyCmd::Start { .. } => Request::PrivacyStartRemoval { broker_ids: None },
            PrivacyCmd::Drafts { .. } => Request::PrivacyDraft { request_id: s() },
            PrivacyCmd::Complaint { .. } => Request::PrivacyComplaint { request_id: s() },
            _ => return None,
        },
        _ => return None,
    })
}

/// Commands that run locally, without the daemon.
pub fn is_local(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Privacy {
            action: PrivacyCmd::Clean { .. } | PrivacyCmd::PasswordCheck { .. }
        }
    )
}

// ---------------------------------------------------------------------------------------------
// VPN
// ---------------------------------------------------------------------------------------------

fn vpn_state(s: VpnState) -> &'static str {
    match s {
        VpnState::Disconnected => "déconnecté",
        VpnState::Connecting => "connexion…",
        VpnState::Connected => "connecté",
        VpnState::Disconnecting => "déconnexion…",
        VpnState::Error => "erreur",
    }
}

fn kill_switch(s: KillSwitchState) -> &'static str {
    match s {
        KillSwitchState::Off => "inactif",
        KillSwitchState::Armed => "armé (trafic limité au tunnel)",
        KillSwitchState::Blocking => "BLOQUE le trafic (tunnel coupé)",
        KillSwitchState::Error => "erreur",
    }
}

fn mode(m: VpnMode) -> &'static str {
    match m {
        VpnMode::Off => "manuel",
        VpnMode::Always => "toujours",
        VpnMode::UntrustedNetworks => "réseaux non approuvés",
    }
}

pub fn vpn_status(s: &VpnStatus) -> String {
    let mut o = String::new();
    let line = |o: &mut String, k: &str, v: String| o.push_str(&format!("{k:<16}{v}\n"));
    line(&mut o, "VPN", vpn_state(s.state).to_string());
    line(
        &mut o,
        "Mode",
        format!(
            "{}{}",
            mode(s.mode),
            match s.manual_override {
                Some(true) => " (connecté à la main)",
                Some(false) => " (déconnecté à la main)",
                None => "",
            }
        ),
    );
    line(
        &mut o,
        "Moteur",
        match s.backend {
            VpnBackend::SingBox => format!(
                "sing-box{}",
                if s.engine_installed {
                    ""
                } else {
                    " (non installé)"
                }
            ),
            VpnBackend::External => format!(
                "VPN de macOS « {} »",
                s.external_service.as_deref().unwrap_or("?")
            ),
        },
    );
    if let Some(p) = &s.profile {
        line(
            &mut o,
            "Profil",
            format!(
                "{} — {} {}:{}{}",
                p.name,
                p.protocol,
                p.server,
                p.port,
                p.transport
                    .as_deref()
                    .map(|t| format!(" ({t})"))
                    .unwrap_or_default()
            ),
        );
    }
    if let Some(t) = s.connected_since {
        line(
            &mut o,
            "Connecté depuis",
            format!(
                "{}{}",
                ts(t),
                s.interface
                    .as_deref()
                    .map(|i| format!(" ({i})"))
                    .unwrap_or_default()
            ),
        );
    }
    line(
        &mut o,
        "Kill switch",
        kill_switch(s.kill_switch).to_string(),
    );
    if let Some(n) = &s.network {
        line(
            &mut o,
            "Réseau",
            format!(
                "{} [{}] — {}",
                n.name,
                n.id,
                if n.trusted {
                    "approuvé"
                } else {
                    "non approuvé"
                }
            ),
        );
    }
    if let Some(l) = &s.last_leak_test {
        line(
            &mut o,
            "Test de fuite",
            format!("{} ({})", if l.ok { "OK" } else { "FUITE" }, ts(l.ts)),
        );
    }
    if let Some(m) = &s.message {
        line(&mut o, "Message", m.clone());
    }
    o
}

pub fn leak(l: &LeakTestResult) -> String {
    let mut o = format!(
        "Test de fuite du {} : {}\n",
        ts(l.ts),
        if l.ok {
            "aucune fuite"
        } else {
            "FUITE DÉTECTÉE"
        }
    );
    let rows: Vec<Vec<String>> = l
        .checks
        .iter()
        .map(|c| {
            vec![
                c.id.clone(),
                if c.ok { "ok".into() } else { "ÉCHEC".into() },
                c.detail.clone(),
            ]
        })
        .collect();
    o.push_str(&table(&["VÉRIF.", "RÉSULTAT", "DÉTAIL"], &rows));
    if let Some(ip) = &l.public_ipv4 {
        o.push_str(&format!("IPv4 publique : {ip}\n"));
    }
    if let Some(ip) = &l.public_ipv6 {
        o.push_str(&format!("IPv6 publique : {ip}\n"));
    }
    if !l.dns_servers.is_empty() {
        o.push_str(&format!("DNS : {}\n", l.dns_servers.join(", ")));
    }
    o
}

pub fn networks(l: &[NetworkInfo]) -> String {
    if l.is_empty() {
        return "Aucun réseau enregistré.\n".into();
    }
    let rows: Vec<Vec<String>> = l
        .iter()
        .map(|n| {
            vec![
                format!("{}{}", if n.current { "* " } else { "  " }, n.id),
                n.name.clone(),
                n.security.clone().unwrap_or_default(),
                if n.trusted {
                    "approuvé".into()
                } else {
                    "—".into()
                },
                ts(n.last_seen),
            ]
        })
        .collect();
    table(&["RÉSEAU", "NOM", "SÉCURITÉ", "CONFIANCE", "VU"], &rows)
}

pub fn services(l: &[ExternalVpnService]) -> String {
    if l.is_empty() {
        return "Aucun VPN configuré dans macOS.\n".into();
    }
    let rows: Vec<Vec<String>> = l
        .iter()
        .map(|s| {
            vec![
                s.name.clone(),
                s.provider.clone().unwrap_or_default(),
                vpn_state(s.state).into(),
            ]
        })
        .collect();
    table(&["NOM", "FOURNISSEUR", "ÉTAT"], &rows)
}

fn read_profile_source(src: &str) -> Result<String, CliError> {
    if src == "-" {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin().take(64 * 1024), &mut s)?;
        return Ok(s);
    }
    if src.contains("://") {
        return Ok(src.to_string());
    }
    let p = Path::new(src);
    let md = std::fs::metadata(p)?;
    if md.len() > 64 * 1024 {
        return Err(CliError::Usage("fichier de profil trop gros".into()));
    }
    Ok(std::fs::read_to_string(p)?)
}

use std::io::Read as _;

fn update_config(c: &mut Client, f: impl FnOnce(&mut Config)) -> Result<Config, CliError> {
    let mut cfg: Config = c.call(Request::GetConfig)?;
    f(&mut cfg);
    Ok(c.call(Request::SetConfig { config: cfg })?)
}

pub fn vpn(
    cli: &Cli,
    io: &mut Output<'_>,
    c: &mut Client,
    action: &Option<VpnCmd>,
) -> Result<i32, CliError> {
    match action.as_ref().unwrap_or(&VpnCmd::Status) {
        VpnCmd::Status => {
            let s: VpnStatus = c.call(Request::VpnStatus)?;
            emit(cli, io, &s, vpn_status)?;
        }
        VpnCmd::Connect => {
            let s: VpnStatus = c.call(Request::VpnConnect)?;
            emit(cli, io, &s, vpn_status)?;
        }
        VpnCmd::Disconnect => {
            let s: VpnStatus = c.call(Request::VpnDisconnect)?;
            emit(cli, io, &s, vpn_status)?;
        }
        VpnCmd::Import { source } => {
            let profile = read_profile_source(source)?;
            let p: VpnProfileInfo = c.call(Request::VpnImportProfile { profile })?;
            emit(cli, io, &p, |p| {
                format!(
                    "Profil importé : {} ({} {}:{}). Le secret reste dans le daemon (lecture root uniquement).\n",
                    p.name, p.protocol, p.server, p.port
                )
            })?;
        }
        VpnCmd::Remove => {
            c.call_raw(Request::VpnRemoveProfile)?;
            if !cli.json {
                writeln!(io.out, "Profil VPN supprimé.")?;
            }
        }
        VpnCmd::LeakTest => {
            let l: LeakTestResult = c.call(Request::VpnLeakTest)?;
            emit(cli, io, &l, leak)?;
            if !l.ok {
                return Ok(EXIT_THREATS);
            }
        }
        VpnCmd::Services => {
            let l: Vec<ExternalVpnService> = c.call(Request::VpnListServices)?;
            emit(cli, io, &l, |l| services(l))?;
        }
        VpnCmd::Networks => {
            let l: Vec<NetworkInfo> = c.call(Request::ListNetworks)?;
            emit(cli, io, &l, |l| networks(l))?;
        }
        VpnCmd::Trust { id } | VpnCmd::Untrust { id } => {
            let trusted = matches!(action, Some(VpnCmd::Trust { .. }));
            let n: NetworkInfo = c.call(Request::SetNetworkTrust {
                network_id: id.clone(),
                trusted,
            })?;
            emit(cli, io, &n, |n| {
                format!(
                    "Réseau {} ({}) : {}\n",
                    n.name,
                    n.id,
                    if n.trusted {
                        "approuvé"
                    } else {
                        "non approuvé"
                    }
                )
            })?;
        }
        VpnCmd::Mode { mode: m } => {
            let m = match m {
                VpnModeArg::Off => VpnMode::Off,
                VpnModeArg::Always => VpnMode::Always,
                VpnModeArg::Untrusted => VpnMode::UntrustedNetworks,
            };
            let cfg = update_config(c, |cfg| cfg.vpn.mode = m)?;
            emit(cli, io, &cfg.vpn, |v| {
                format!("Mode VPN : {}\n", mode(v.mode))
            })?;
        }
        VpnCmd::Backend {
            backend,
            service,
            servers,
        } => {
            let cfg = update_config(c, |cfg| {
                cfg.vpn.backend = match backend {
                    VpnBackendArg::SingBox => VpnBackend::SingBox,
                    VpnBackendArg::External => VpnBackend::External,
                };
                if let Some(s) = service {
                    cfg.vpn.external_service = Some(s.clone());
                }
                if !servers.is_empty() {
                    cfg.vpn.external_server_addresses = servers.clone();
                }
            })?;
            emit(cli, io, &cfg.vpn, |v| {
                format!(
                    "Moteur VPN : {}\n",
                    match v.backend {
                        VpnBackend::SingBox => "sing-box".to_string(),
                        VpnBackend::External => format!(
                            "VPN de macOS « {} »",
                            v.external_service.as_deref().unwrap_or("?")
                        ),
                    }
                )
            })?;
        }
        VpnCmd::KillSwitch { state } => {
            let on = *state == OnOff::On;
            let cfg = update_config(c, |cfg| cfg.vpn.kill_switch = on)?;
            emit(cli, io, &cfg.vpn, |v| {
                format!(
                    "Kill switch {}.\n",
                    if v.kill_switch {
                        "activé"
                    } else {
                        "désactivé"
                    }
                )
            })?;
        }
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------------------------
// Guard
// ---------------------------------------------------------------------------------------------

pub fn guard_status(g: &GuardStatus) -> String {
    let mut o = String::new();
    o.push_str(&format!(
        "Détection des voleurs de données : {}\n",
        yes_no(g.stealer_detection)
    ));
    o.push_str(&format!(
        "Détection des rançongiciels      : {}\n",
        yes_no(g.ransomware_detection)
    ));
    o.push_str(&format!(
        "Fichiers leurres                 : {}\n",
        g.canaries.len()
    ));
    o.push_str(&format!(
        "Instantanés APFS                 : {}{}\n",
        yes_no(g.snapshots_enabled),
        g.last_snapshot
            .map(|t| format!(" (dernier : {})", ts(t)))
            .unwrap_or_default()
    ));
    if let Some(e) = &g.snapshot_error {
        o.push_str(&format!("  erreur : {e}\n"));
    }
    o.push_str(&format!(
        "Détections (7 jours)             : {}\n",
        g.detections_7d
    ));
    if !g.suspended.is_empty() {
        o.push_str("Processus suspendus :\n");
        for s in &g.suspended {
            o.push_str(&format!(
                "  pid {} {} depuis {}{}\n",
                s.pid,
                s.path,
                ts(s.since),
                s.alert_id
                    .map(|a| format!(" (alerte {a})"))
                    .unwrap_or_default()
            ));
        }
    }
    o
}

pub fn snapshots(l: &[SnapshotInfo]) -> String {
    if l.is_empty() {
        return "Aucun instantané local.\n".into();
    }
    let rows: Vec<Vec<String>> = l
        .iter()
        .map(|s| {
            vec![
                s.name.clone(),
                s.created_at.map(ts).unwrap_or_default(),
                if s.ours {
                    "Parabellum".into()
                } else {
                    "système".into()
                },
            ]
        })
        .collect();
    table(&["INSTANTANÉ", "DATE", "CRÉÉ PAR"], &rows)
}

pub fn guard(
    cli: &Cli,
    io: &mut Output<'_>,
    c: &mut Client,
    action: &Option<GuardCmd>,
) -> Result<i32, CliError> {
    match action.as_ref().unwrap_or(&GuardCmd::Status) {
        GuardCmd::Status => {
            let g: GuardStatus = c.call(Request::GuardStatus)?;
            emit(cli, io, &g, guard_status)?;
        }
        GuardCmd::Snapshots => {
            let l: Vec<SnapshotInfo> = c.call(Request::ListSnapshots)?;
            emit(cli, io, &l, |l| snapshots(l))?;
        }
        GuardCmd::Snapshot => {
            let s: SnapshotInfo = c.call(Request::CreateSnapshot)?;
            emit(cli, io, &s, |s| format!("Instantané créé : {}\n", s.name))?;
        }
        GuardCmd::Restore { snapshot, path } => {
            let abs = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()?.join(path)
            };
            let v = c.call_raw(Request::RestoreFromSnapshot {
                snapshot: snapshot.clone(),
                path: abs.to_string_lossy().into_owned(),
            })?;
            emit(cli, io, &v, |v| {
                format!(
                    "Restauré dans : {}\n",
                    v.get("restored_to").and_then(|p| p.as_str()).unwrap_or("?")
                )
            })?;
        }
    }
    Ok(EXIT_OK)
}

// ---------------------------------------------------------------------------------------------
// Privacy
// ---------------------------------------------------------------------------------------------

pub fn profile(p: &IdentityProfile) -> String {
    if p.full_name.is_empty() && p.emails.is_empty() {
        return "Aucune identité enregistrée (parabellum privacy profile set <fichier>).\n".into();
    }
    let mut o = String::new();
    o.push_str(&format!("Nom             {}\n", p.full_name));
    o.push_str(&format!("E-mails         {}\n", p.emails.join(", ")));
    if !p.phones.is_empty() {
        o.push_str(&format!("Téléphones      {}\n", p.phones.join(", ")));
    }
    if !p.postal_address.is_empty() {
        o.push_str(&format!(
            "Adresse         {}\n",
            p.postal_address.replace('\n', ", ")
        ));
    }
    if !p.previous_addresses.is_empty() {
        o.push_str(&format!("Anciennes adr.  {}\n", p.previous_addresses.len()));
    }
    if !p.birth_date.is_empty() {
        o.push_str(&format!("Naissance       {}\n", p.birth_date));
    }
    o.push_str(&format!("Pays            {}\n", p.country));
    o
}

fn removal_status(s: RemovalStatus) -> &'static str {
    match s {
        RemovalStatus::Queued => "en file",
        RemovalStatus::DraftReady => "brouillon prêt",
        RemovalStatus::Sent => "envoyée",
        RemovalStatus::Reminded => "relancée",
        RemovalStatus::Escalated => "plainte conseillée",
        RemovalStatus::Completed => "effacée",
        RemovalStatus::Refused => "refusée",
        RemovalStatus::NeedsForm => "formulaire web",
        RemovalStatus::Failed => "échec",
    }
}

pub fn requests(l: &[RemovalRequest]) -> String {
    if l.is_empty() {
        return "Aucune demande (parabellum privacy start).\n".into();
    }
    let rows: Vec<Vec<String>> = l
        .iter()
        .map(|r| {
            vec![
                r.id.chars().take(8).collect(),
                r.broker_name.clone(),
                removal_status(r.status).into(),
                r.sent_at.map(ts).unwrap_or_default(),
                r.due_at.map(ts).unwrap_or_default(),
            ]
        })
        .collect();
    table(
        &["DEMANDE", "COURTIER", "STATUT", "ENVOYÉE", "ÉCHÉANCE"],
        &rows,
    )
}

pub fn summary(s: &RemovalSummary) -> String {
    format!(
        "{} demande(s) : {} en file, {} en attente de réponse ({} en retard), {} effacée(s), {} à traiter à la main{}\n",
        s.total,
        s.queued,
        s.waiting_answer,
        s.overdue,
        s.completed,
        s.needs_action,
        s.next_send_at.map(|t| format!(" ; prochain envoi {}", ts(t))).unwrap_or_default()
    )
}

pub fn brokers(l: &[BrokerInfo]) -> String {
    if l.is_empty() {
        return "Aucun courtier (la liste arrive avec la base de menaces signée).\n".into();
    }
    let rows: Vec<Vec<String>> = l
        .iter()
        .map(|b| {
            vec![
                b.id.clone(),
                b.name.clone(),
                b.region.clone(),
                b.category.clone(),
                b.email.clone().unwrap_or_else(|| "formulaire".into()),
            ]
        })
        .collect();
    table(&["ID", "NOM", "RÉGION", "CATÉGORIE", "CONTACT"], &rows)
}

pub fn breaches(l: &[BreachFinding]) -> String {
    if l.is_empty() {
        return "Aucune fuite connue pour vos adresses.\n".into();
    }
    let rows: Vec<Vec<String>> = l
        .iter()
        .map(|b| {
            vec![
                format!("{}{}", if b.new { "* " } else { "" }, b.email),
                b.breach.clone(),
                b.breach_date.clone().unwrap_or_default(),
                b.data_classes.join(", "),
            ]
        })
        .collect();
    table(&["ADRESSE", "FUITE", "DATE", "DONNÉES EXPOSÉES"], &rows)
}

pub fn aliases(l: &[EmailAlias]) -> String {
    if l.is_empty() {
        return "Aucun alias.\n".into();
    }
    let rows: Vec<Vec<String>> = l
        .iter()
        .map(|a| {
            vec![
                a.email.clone(),
                a.label.clone(),
                ts(a.created_at),
                yes_no(a.active).into(),
            ]
        })
        .collect();
    table(&["ALIAS", "POUR", "CRÉÉ", "ACTIF"], &rows)
}

/// RFC 5322 message, opened as a new message by Mail (`X-Unsent: 1`).
pub fn eml(d: &MailDraft) -> String {
    use base64::Engine as _;
    let subject = format!(
        "=?UTF-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(d.subject.as_bytes())
    );
    let body =
        base64::engine::general_purpose::STANDARD.encode(d.body.replace('\n', "\r\n").as_bytes());
    let mut wrapped = String::new();
    for chunk in body.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        wrapped.push_str("\r\n");
    }
    format!(
        "X-Unsent: 1\r\nTo: {}\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{wrapped}",
        d.to
    )
}

fn safe_file_stem(s: &str) -> String {
    let t: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    if t.is_empty() {
        "demande".into()
    } else {
        t
    }
}

/// Files written under sudo go back to the invoking user.
fn chown_to_sudo_user(p: &Path) {
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    let gid = std::env::var("SUDO_GID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok());
    if let (Some(u), Some(g)) = (uid, gid) {
        let _ = std::os::unix::fs::chown(p, Some(u), Some(g));
    }
}

pub fn privacy(
    cli: &Cli,
    io: &mut Output<'_>,
    c: &mut Client,
    action: &PrivacyCmd,
) -> Result<i32, CliError> {
    match action {
        PrivacyCmd::Profile { action } => match action {
            None => {
                let p: IdentityProfile = c.call(Request::PrivacyGetProfile { reveal: false })?;
                emit(cli, io, &p, profile)?;
            }
            Some(ProfileCmd::Show { reveal }) => {
                let p: IdentityProfile = c.call(Request::PrivacyGetProfile { reveal: *reveal })?;
                emit(cli, io, &p, profile)?;
            }
            Some(ProfileCmd::Set { file }) => {
                let md = std::fs::metadata(file)?;
                if md.len() > 256 * 1024 {
                    return Err(CliError::Usage("fichier trop gros".into()));
                }
                let text = std::fs::read_to_string(file)?;
                let p: IdentityProfile =
                    if file.extension().and_then(|e| e.to_str()) == Some("json") {
                        serde_json::from_str(&text)
                            .map_err(|e| CliError::Usage(format!("JSON invalide : {e}")))?
                    } else {
                        toml::from_str(&text)
                            .map_err(|e| CliError::Usage(format!("TOML invalide : {e}")))?
                    };
                let saved: IdentityProfile = c.call(Request::PrivacySetProfile { profile: p })?;
                emit(cli, io, &saved, profile)?;
            }
        },
        PrivacyCmd::Brokers => {
            let l: Vec<BrokerInfo> = c.call(Request::PrivacyListBrokers)?;
            emit(cli, io, &l, |l| brokers(l))?;
        }
        PrivacyCmd::Requests => {
            let l: Vec<RemovalRequest> = c.call(Request::PrivacyListRequests)?;
            let s: RemovalSummary = c.call(Request::PrivacySummary)?;
            if cli.json {
                emit(cli, io, &l, |_| String::new())?;
            } else {
                write!(io.out, "{}{}", requests(&l), summary(&s))?;
            }
        }
        PrivacyCmd::Start { brokers: ids } => {
            let s: RemovalSummary = c.call(Request::PrivacyStartRemoval {
                broker_ids: (!ids.is_empty()).then(|| ids.clone()),
            })?;
            emit(cli, io, &s, summary)?;
        }
        PrivacyCmd::Mark { id, status, note } => {
            let st: RemovalStatus = parse_wire_enum(status).ok_or_else(|| {
                CliError::Usage(format!(
                    "statut inconnu « {status} » (sent, completed, refused, needs-form, queued)"
                ))
            })?;
            let id = resolve_request_id(c, id)?;
            let r: RemovalRequest = c.call(Request::PrivacyUpdateRequest {
                request_id: id,
                status: st,
                note: note.clone(),
            })?;
            emit(cli, io, &r, |r| {
                format!("{} : {}\n", r.broker_name, removal_status(r.status))
            })?;
        }
        PrivacyCmd::Drafts { out, id } => {
            let ids: Vec<String> = match id {
                Some(i) => vec![resolve_request_id(c, i)?],
                None => {
                    let l: Vec<RemovalRequest> = c.call(Request::PrivacyListRequests)?;
                    l.into_iter()
                        .filter(|r| {
                            matches!(
                                r.status,
                                RemovalStatus::Queued
                                    | RemovalStatus::DraftReady
                                    | RemovalStatus::Reminded
                            ) && r.broker_email.is_some()
                        })
                        .map(|r| r.id)
                        .collect()
                }
            };
            std::fs::create_dir_all(out)?;
            let mut written: Vec<PathBuf> = Vec::new();
            for rid in ids {
                let d: MailDraft = c.call(Request::PrivacyDraft {
                    request_id: rid.clone(),
                })?;
                let p = out.join(format!(
                    "{}.eml",
                    safe_file_stem(&d.to.replace('@', "-at-"))
                ));
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(&p)?;
                f.write_all(eml(&d).as_bytes())?;
                chown_to_sudo_user(&p);
                written.push(p);
            }
            if cli.json {
                emit(cli, io, &written, |_| String::new())?;
            } else {
                writeln!(
                    io.out,
                    "{} e-mail(s) écrit(s) dans {}. Ouvrez-les avec Mail, envoyez-les, puis : parabellum privacy mark <id> sent",
                    written.len(),
                    out.display()
                )?;
            }
        }
        PrivacyCmd::Complaint { id } => {
            let id = resolve_request_id(c, id)?;
            let d: ComplaintDraft = c.call(Request::PrivacyComplaint { request_id: id })?;
            emit(cli, io, &d, |d| {
                format!(
                    "Autorité : {}\nDéposer la plainte : {}\n\n{}\n",
                    d.authority, d.url, d.text
                )
            })?;
        }
        PrivacyCmd::Breaches { check } => {
            let l: Vec<BreachFinding> = if *check {
                c.call(Request::BreachCheckNow)?
            } else {
                c.call(Request::BreachList)?
            };
            emit(cli, io, &l, |l| breaches(l))?;
            if l.iter().any(|b| b.new) {
                return Ok(EXIT_THREATS);
            }
        }
        PrivacyCmd::Alias { action } => match action {
            None | Some(AliasCmd::List) => {
                let l: Vec<EmailAlias> = c.call(Request::AliasList)?;
                emit(cli, io, &l, |l| aliases(l))?;
            }
            Some(AliasCmd::New { label }) => {
                let a: EmailAlias = c.call(Request::AliasCreate {
                    label: label.clone(),
                })?;
                emit(cli, io, &a, |a| {
                    format!("Nouvel alias pour {} : {}\n", a.label, a.email)
                })?;
            }
        },
        PrivacyCmd::PasswordCheck { .. } | PrivacyCmd::Clean { .. } => {
            return Err(CliError::Usage("commande locale".into()))
        }
    }
    Ok(EXIT_OK)
}

/// Accept a full id or a unique prefix (as shown by `privacy requests`).
fn resolve_request_id(c: &mut Client, id: &str) -> Result<String, CliError> {
    if id.len() >= 32 {
        return Ok(id.to_string());
    }
    let l: Vec<RemovalRequest> = c.call(Request::PrivacyListRequests)?;
    let m: Vec<&RemovalRequest> = l.iter().filter(|r| r.id.starts_with(id)).collect();
    match m.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => Err(CliError::Usage(format!("aucune demande {id}"))),
        _ => Err(CliError::Usage(format!("préfixe ambigu : {id}"))),
    }
}

// ---------------------------------------------------------------------------------------------
// Local commands (no daemon): metadata cleaning, Pwned Passwords
// ---------------------------------------------------------------------------------------------

/// Read a line from the terminal without echo.
fn read_password(prompt: &str) -> Result<String, CliError> {
    use std::io::BufRead;
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")?;
    let fd = std::os::fd::AsRawFd::as_raw_fd(&tty);
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    // SAFETY: fd is an open terminal, `term` a valid termios.
    let has_term = unsafe { libc::tcgetattr(fd, &mut term) } == 0;
    let saved = term;
    if has_term {
        term.c_lflag &= !libc::ECHO;
        // SAFETY: same fd / struct.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) };
    }
    let mut w = &tty;
    let _ = write!(w, "{prompt}");
    let _ = w.flush();
    let mut line = String::new();
    let r = std::io::BufReader::new(&tty).read_line(&mut line);
    if has_term {
        // SAFETY: restore the saved attributes.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
    }
    let _ = writeln!(w);
    r?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

pub fn local(cli: &Cli, io: &mut Output<'_>) -> Result<i32, CliError> {
    let Command::Privacy { action } = &cli.command else {
        return Err(CliError::Usage("commande inattendue".into()));
    };
    match action {
        PrivacyCmd::Clean { files, in_place } => {
            let reports: Vec<pb_privacy::metadata::CleanReport> = files
                .iter()
                .map(|f| pb_privacy::metadata::clean_file(f, *in_place))
                .collect();
            let failed = reports.iter().any(|r| r.error.is_some());
            emit(cli, io, &reports, |rs| {
                let mut o = String::new();
                for r in rs {
                    match (&r.error, &r.output) {
                        (Some(e), _) => {
                            o.push_str(&format!("{} : échec — {e}\n", r.input.display()))
                        }
                        (None, Some(out)) => o.push_str(&format!(
                            "{} -> {} ({}){}\n",
                            r.input.display(),
                            out.display(),
                            r.method,
                            if r.removed.is_empty() {
                                " : rien à retirer".to_string()
                            } else {
                                format!(" : retiré {}", r.removed.join(", "))
                            }
                        )),
                        (None, None) => o.push_str(&format!("{} : inchangé\n", r.input.display())),
                    }
                }
                o
            })?;
            Ok(if failed {
                crate::commands::EXIT_ERROR
            } else {
                EXIT_OK
            })
        }
        PrivacyCmd::PasswordCheck { csv } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            match csv {
                Some(path) => {
                    let res = rt
                        .block_on(pb_privacy::pwned::check_csv(path))
                        .map_err(|e| CliError::Usage(e.to_string()))?;
                    let leaked: Vec<_> = res.iter().filter(|r| r.count > 0).cloned().collect();
                    emit(cli, io, &leaked, |l| {
                        let mut o = format!(
                            "{} mot(s) de passe vérifié(s), {} présent(s) dans des fuites connues.\n",
                            res.len(),
                            l.len()
                        );
                        if !l.is_empty() {
                            let rows: Vec<Vec<String>> = l
                                .iter()
                                .map(|r| {
                                    vec![
                                        r.name.clone(),
                                        r.url.clone(),
                                        r.username.clone(),
                                        r.count.to_string(),
                                    ]
                                })
                                .collect();
                            o.push_str(&table(&["NOM", "SITE", "IDENTIFIANT", "FUITES"], &rows));
                            o.push_str(
                                "Changez ces mots de passe. Supprimez l'export CSV maintenant.\n",
                            );
                        }
                        o
                    })?;
                    Ok(if leaked.is_empty() {
                        EXIT_OK
                    } else {
                        EXIT_THREATS
                    })
                }
                None => {
                    let pw = read_password("Mot de passe (non affiché) : ")?;
                    let n = rt
                        .block_on(pb_privacy::pwned::check_password(&pw))
                        .map_err(|e| CliError::Usage(e.to_string()))?;
                    drop(pw);
                    emit(cli, io, &serde_json::json!({ "count": n }), |_| {
                        if n == 0 {
                            "Ce mot de passe n'apparaît dans aucune fuite connue.\n".into()
                        } else {
                            format!("Ce mot de passe apparaît {n} fois dans des fuites : ne l'utilisez plus.\n")
                        }
                    })?;
                    Ok(if n == 0 { EXIT_OK } else { EXIT_THREATS })
                }
            }
        }
        _ => Err(CliError::Usage("commande inattendue".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eml_is_valid_and_utf8() {
        let d = MailDraft {
            request_id: "r".into(),
            to: "dpo@example.com".into(),
            subject: "Demande d'effacement (article 17 du RGPD)".into(),
            body: "Bonjour,\nÀ qui de droit".into(),
        };
        let e = eml(&d);
        assert!(e.starts_with("X-Unsent: 1\r\nTo: dpo@example.com\r\nSubject: =?UTF-8?B?"));
        assert!(e.contains("charset=UTF-8"));
        assert_eq!(safe_file_stem("dpo-at-example.com"), "dpo-at-example-com");
    }

    #[test]
    fn admin_classification() {
        let p = |a: &[&str]| {
            Cli::try_parse_args(std::iter::once("parabellum").chain(a.iter().copied())).unwrap()
        };
        let needs = |a: &[&str]| {
            admin_probe(&p(a).command)
                .map(|r| r.requires_admin())
                .unwrap_or(false)
        };
        assert!(needs(&["vpn", "import", "ss://x"]));
        assert!(needs(&["vpn", "disconnect"]));
        assert!(needs(&["vpn", "kill-switch", "off"]));
        assert!(!needs(&["vpn", "connect"]));
        assert!(!needs(&["vpn", "untrust", "gw:00:11:22:33:44:55"]));
        assert!(needs(&["vpn", "trust", "gw:00:11:22:33:44:55"]));
        assert!(needs(&["guard", "restore", "s", "/Users/q/a"]));
        assert!(!needs(&["guard", "snapshot"]));
        assert!(needs(&["privacy", "profile", "show", "--reveal"]));
        assert!(!needs(&["privacy", "profile", "show"]));
        assert!(needs(&["privacy", "start"]));
        assert!(needs(&["privacy", "drafts"]));
        assert!(!needs(&["privacy", "requests"]));
        assert!(is_local(&p(&["privacy", "clean", "a.jpg"]).command));
        assert!(!is_local(&p(&["privacy", "requests"]).command));
    }

    #[test]
    fn formats() {
        let s = VpnStatus::default();
        assert!(vpn_status(&s).contains("déconnecté"));
        assert!(networks(&[]).contains("Aucun"));
        let r = RemovalSummary {
            total: 3,
            queued: 1,
            ..Default::default()
        };
        assert!(summary(&r).starts_with("3 demande(s)"));
        let _ = crate::format::severity(Severity::Low);
    }
}
