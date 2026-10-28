//! Command execution. Exit codes: 0 OK, 1 threats found / update failed, 2 error.

use crate::cli::*;
use crate::client::{default_socket, Client, ClientError};
use crate::format;
use pb_core::config::Config;
use pb_core::ipc::*;
use pb_core::model::*;
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const EXIT_OK: i32 = 0;
pub const EXIT_THREATS: i32 = 1;
pub const EXIT_ERROR: i32 = 2;

/// Max size of a config file given to `config set`.
const MAX_CONFIG_FILE: u64 = 1024 * 1024;
/// Max wait for an update to finish.
const UPDATE_WAIT: Duration = Duration::from_secs(30 * 60);

/// CLI errors.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error(transparent)]
    Client(#[from] ClientError),
    #[error("{0}")]
    Usage(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Shown when a protection-weakening command is run without root.
pub const SUDO_MESSAGE: &str =
    "Cette commande réduit la protection : relancez-la avec sudo (sudo parabellum …)";

/// Where output goes.
pub struct Output<'a> {
    pub out: &'a mut dyn Write,
    pub err: &'a mut dyn Write,
    /// Show live progress on `err` (it is a terminal).
    pub progress: bool,
    /// Running as root (`sudo`): needed for commands that weaken protection.
    pub is_root: bool,
}

/// Representative request of a command, for the `requires_admin` policy of pb-core.
fn admin_probe(cmd: &Command) -> Option<Request> {
    let none = String::new;
    Some(match cmd {
        Command::Resolve { alert_id, action } => Request::ResolveAlert {
            alert_id: *alert_id,
            action: parse_wire_enum(action)?,
        },
        Command::Quarantine {
            action: Some(QuarantineCmd::Add { .. }),
        } => Request::QuarantinePath { path: none() },
        Command::Quarantine {
            action: Some(QuarantineCmd::Restore { allow, .. }),
        } => Request::Restore {
            entry_id: none(),
            allow: *allow,
        },
        Command::Quarantine {
            action: Some(QuarantineCmd::Delete { .. }),
        } => Request::DeleteQuarantined { entry_id: none() },
        Command::Fp { .. } => Request::ReportFalsePositive {
            sha256: none(),
            path: None,
            note: None,
        },
        Command::Persistence {
            action: Some(_), ..
        } => Request::SetPersistenceStatus {
            item_id: none(),
            status: PersistenceStatus::Approved,
        },
        Command::Devices {
            action: Some(c), ..
        } => Request::SetDeviceTrust {
            device_id: none(),
            trust: match c {
                DevicesCmd::Trust { .. } => DeviceTrust::Trusted,
                DevicesCmd::Block { .. } => DeviceTrust::Blocked,
                DevicesCmd::Forget { .. } => DeviceTrust::Unknown,
            },
        },
        Command::Dns { state: DnsArg::Off } => Request::SetDns { enabled: false },
        Command::Config {
            action: ConfigCmd::Set { .. },
        } => Request::SetConfig {
            config: Config::default(),
        },
        Command::Pause { minutes } => Request::SetProtection {
            paused_minutes: *minutes,
        },
        Command::Components {
            action: Some(ComponentsCmd::Auto { state, .. }),
        } => Request::SetComponentAutoUpdate {
            name: none(),
            auto_update: *state == OnOff::On,
        },
        _ => return None,
    })
}

/// The command needs administrator approval (`sudo`).
pub fn needs_admin(cmd: &Command) -> bool {
    admin_probe(cmd)
        .map(|r| r.requires_admin())
        .unwrap_or(false)
}

/// Run a parsed command line; returns the process exit code.
pub fn run(cli: &Cli, io: &mut Output<'_>) -> i32 {
    if needs_admin(&cli.command) && !io.is_root {
        let _ = writeln!(io.err, "parabellum : {SUDO_MESSAGE}");
        return EXIT_ERROR;
    }
    match execute(cli, io) {
        Ok(code) => code,
        Err(CliError::Client(ClientError::Daemon(e))) if e.code == ErrorCode::AuthRequired => {
            let _ = writeln!(io.err, "parabellum : {SUDO_MESSAGE}");
            EXIT_ERROR
        }
        Err(e) => {
            let _ = writeln!(io.err, "parabellum : {e}");
            EXIT_ERROR
        }
    }
}

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

fn absolute(p: &Path) -> Result<String, CliError> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()?.join(p)
    };
    let abs = std::fs::canonicalize(&abs).unwrap_or(abs);
    abs.to_str()
        .map(str::to_string)
        .ok_or_else(|| CliError::Usage(format!("chemin non UTF-8 : {}", p.display())))
}

fn connect(cli: &Cli) -> Result<Client, CliError> {
    let socket: PathBuf = cli.socket.clone().unwrap_or_else(default_socket);
    Ok(Client::connect(
        &socket,
        Some(Duration::from_secs(cli.timeout.max(1))),
    )?)
}

fn execute(cli: &Cli, io: &mut Output<'_>) -> Result<i32, CliError> {
    let mut c = connect(cli)?;
    match &cli.command {
        Command::Ping => {
            let p: PingResponse = c.call(Request::Ping)?;
            emit(cli, io, &p, |p| {
                format!("parabellumd {} (protocole {})\n", p.version, p.protocol)
            })?;
            if p.protocol != PROTOCOL_VERSION {
                writeln!(
                    io.err,
                    "attention : protocole {} attendu, le daemon parle {}",
                    PROTOCOL_VERSION, p.protocol
                )?;
            }
        }
        Command::Status => {
            let s: StatusInfo = c.call(Request::Status)?;
            emit(cli, io, &s, format::status)?;
        }
        Command::Scan(a) => return scan(cli, io, &mut c, a),
        Command::Jobs { limit } => {
            let l: Vec<ScanJobSummary> = c.call(Request::ListJobs { limit: *limit })?;
            emit(cli, io, &l, |l| format::jobs(l))?;
        }
        Command::Job { id } => {
            let d: ScanJobDetail = c.call(Request::GetJob { job_id: id.clone() })?;
            emit(cli, io, &d, format::job)?;
        }
        Command::Cancel { id } => {
            c.call_raw(Request::CancelScan { job_id: id.clone() })?;
            if !cli.json {
                writeln!(io.out, "Analyse {id} annulée.")?;
            }
        }
        Command::Alerts { all, limit } => {
            let l: Vec<Alert> = c.call(Request::ListAlerts {
                limit: *limit,
                include_resolved: *all,
            })?;
            emit(cli, io, &l, |l| format::alerts(l))?;
        }
        Command::Resolve { alert_id, action } => {
            let action: AlertAction = parse_wire_enum(action).ok_or_else(|| {
                CliError::Usage(format!(
                    "action inconnue « {action} » (acknowledge, quarantine, allow, restore, trust-device, block-device, \
                     approve-persistence, remove-persistence, report-false-positive, dismiss)"
                ))
            })?;
            let a: Alert = c.call(Request::ResolveAlert {
                alert_id: *alert_id,
                action,
            })?;
            emit(cli, io, &a, format::alert)?;
        }
        Command::Quarantine { action } => match action {
            None | Some(QuarantineCmd::List) => {
                let l: Vec<QuarantineEntry> = c.call(Request::ListQuarantine)?;
                emit(cli, io, &l, |l| format::quarantine(l))?;
            }
            Some(QuarantineCmd::Add { path }) => {
                let e: QuarantineEntry = c.call(Request::QuarantinePath {
                    path: absolute(path)?,
                })?;
                emit(cli, io, &e, format::quarantine_entry)?;
            }
            Some(QuarantineCmd::Restore { id, allow }) => {
                let v = c.call_raw(Request::Restore {
                    entry_id: id.clone(),
                    allow: *allow,
                })?;
                emit(cli, io, &v, |v| {
                    format!(
                        "Fichier restauré : {}\n",
                        v.get("restored_path")
                            .and_then(|p| p.as_str())
                            .unwrap_or("?")
                    )
                })?;
            }
            Some(QuarantineCmd::Delete { id }) => {
                c.call_raw(Request::DeleteQuarantined {
                    entry_id: id.clone(),
                })?;
                if !cli.json {
                    writeln!(io.out, "Entrée {id} supprimée définitivement.")?;
                }
            }
        },
        Command::Fp { sha256, path, note } => {
            c.call_raw(Request::ReportFalsePositive {
                sha256: sha256.clone(),
                path: path.clone(),
                note: note.clone(),
            })?;
            if !cli.json {
                writeln!(
                    io.out,
                    "Faux positif enregistré ; cette empreinte est désormais autorisée."
                )?;
            }
        }
        Command::Persistence { new, action } => match action {
            None => {
                let l: Vec<PersistenceItem> =
                    c.call(Request::ListPersistence { only_new: *new })?;
                emit(cli, io, &l, |l| format::persistence(l))?;
            }
            Some(cmd) => {
                let (id, status) = match cmd {
                    PersistenceCmd::Approve { id } => (id, PersistenceStatus::Approved),
                    PersistenceCmd::Remove { id } => (id, PersistenceStatus::Quarantined),
                };
                let p: PersistenceItem = c.call(Request::SetPersistenceStatus {
                    item_id: id.clone(),
                    status,
                })?;
                emit(cli, io, &p, format::persistence_item)?;
            }
        },
        Command::Devices { kind, action } => match action {
            None => {
                let kind = match kind {
                    Some(k) => Some(
                        parse_wire_enum::<DeviceKind>(k)
                            .ok_or_else(|| CliError::Usage(format!("type inconnu : {k}")))?,
                    ),
                    None => None,
                };
                let l: Vec<DeviceInfo> = c.call(Request::ListDevices { kind })?;
                emit(cli, io, &l, |l| format::devices(l))?;
            }
            Some(cmd) => {
                let (id, trust) = match cmd {
                    DevicesCmd::Trust { id } => (id, DeviceTrust::Trusted),
                    DevicesCmd::Block { id } => (id, DeviceTrust::Blocked),
                    DevicesCmd::Forget { id } => (id, DeviceTrust::Unknown),
                };
                let d: DeviceInfo = c.call(Request::SetDeviceTrust {
                    device_id: id.clone(),
                    trust,
                })?;
                emit(cli, io, &d, format::device)?;
            }
        },
        Command::Update { target, no_wait } => {
            return update(cli, io, &mut c, (*target).into(), *no_wait)
        }
        Command::Components { action } => match action {
            None | Some(ComponentsCmd::List) => {
                let l: Vec<ComponentStatus> = c.call(Request::ListComponents)?;
                emit(cli, io, &l, |l| format::components(l))?;
            }
            Some(ComponentsCmd::Install { name }) => {
                let j: JobStarted = c.call(Request::InstallComponent { name: name.clone() })?;
                emit(cli, io, &j, |_| {
                    format!("Installation de {name} lancée (suivi : parabellum watch).\n")
                })?;
            }
            Some(ComponentsCmd::Auto { name, state }) => {
                let l: Vec<ComponentStatus> = c.call(Request::SetComponentAutoUpdate {
                    name: name.clone(),
                    auto_update: *state == OnOff::On,
                })?;
                emit(cli, io, &l, |l| format::components(l))?;
            }
        },
        Command::Dns { state } => {
            let req = match state {
                DnsArg::On => Request::SetDns { enabled: true },
                DnsArg::Off => Request::SetDns { enabled: false },
                DnsArg::Status => Request::GetDns,
            };
            let d: DnsStatus = c.call(req)?;
            emit(cli, io, &d, format::dns)?;
        }
        Command::Adblock => {
            let a: AdblockStatus = c.call(Request::AdblockStatus)?;
            emit(cli, io, &a, format::adblock)?;
        }
        Command::Config { action } => match action {
            ConfigCmd::Get => {
                let cfg: Config = c.call(Request::GetConfig)?;
                if cli.json {
                    emit(cli, io, &cfg, |_| String::new())?;
                } else {
                    write!(
                        io.out,
                        "{}",
                        cfg.to_toml().map_err(|e| CliError::Usage(e.to_string()))?
                    )?;
                }
            }
            ConfigCmd::Set { file } => {
                let config = read_config(file)?;
                let saved: Config = c.call(Request::SetConfig { config })?;
                if cli.json {
                    emit(cli, io, &saved, |_| String::new())?;
                } else {
                    writeln!(io.out, "Configuration enregistrée.")?;
                }
            }
        },
        Command::Pause { minutes } => {
            if *minutes == 0 {
                return Err(CliError::Usage(
                    "durée en minutes > 0 attendue (ou : parabellum resume)".into(),
                ));
            }
            let s: StatusInfo = c.call(Request::SetProtection {
                paused_minutes: *minutes,
            })?;
            emit(cli, io, &s, format::status)?;
        }
        Command::Resume => {
            let s: StatusInfo = c.call(Request::SetProtection { paused_minutes: 0 })?;
            emit(cli, io, &s, format::status)?;
        }
        Command::Report { week } => {
            let r: WeeklyReport = c.call(Request::WeeklyReport { week_offset: *week })?;
            emit(cli, io, &r, format::report)?;
        }
        Command::RetroHunt { days } => {
            let j: JobStarted = c.call(Request::RetroHunt { days: *days })?;
            emit(cli, io, &j, |j| {
                format!(
                    "Rétro-chasse lancée : {} (suivi : parabellum job {})\n",
                    j.job_id, j.job_id
                )
            })?;
        }
        Command::Watch => {
            c.subscribe()?;
            c.set_timeout(None)?;
            loop {
                let ev = c.next_event()?;
                if cli.json {
                    writeln!(
                        io.out,
                        "{}",
                        serde_json::to_string(&ev).map_err(|e| CliError::Usage(e.to_string()))?
                    )?;
                } else {
                    writeln!(io.out, "{}", format::event(&ev))?;
                }
                io.out.flush()?;
            }
        }
    }
    Ok(EXIT_OK)
}

/// Read and validate a TOML configuration file.
pub fn read_config(file: &Path) -> Result<Config, CliError> {
    let md = std::fs::metadata(file)?;
    if md.len() > MAX_CONFIG_FILE {
        return Err(CliError::Usage(
            "fichier de configuration trop grand".into(),
        ));
    }
    let text = std::fs::read_to_string(file)?;
    Config::from_toml(&text).map_err(|e| CliError::Usage(format!("{} : {e}", file.display())))
}

fn scan(cli: &Cli, io: &mut Output<'_>, c: &mut Client, a: &ScanArgs) -> Result<i32, CliError> {
    let paths = a
        .paths
        .iter()
        .map(|p| absolute(p))
        .collect::<Result<Vec<_>, _>>()?;
    let use_clamav = if a.clamav {
        Some(true)
    } else if a.no_clamav {
        Some(false)
    } else {
        None
    };
    let req = Request::Scan {
        paths,
        recursive: !a.no_recursive,
        use_clamav,
    };
    if a.no_wait {
        let j: JobStarted = c.call(req)?;
        emit(cli, io, &j, |j| {
            format!(
                "Analyse lancée : {} (suivi : parabellum job {})\n",
                j.job_id, j.job_id
            )
        })?;
        return Ok(EXIT_OK);
    }
    c.subscribe()?;
    let j: JobStarted = c.call(req)?;
    if !cli.json {
        writeln!(io.out, "Analyse {} lancée…", j.job_id)?;
        io.out.flush()?;
    }
    c.set_timeout(None)?;
    let mut shown = false;
    loop {
        match c.next_event()? {
            DaemonEvent::ScanProgress(s) if s.job_id == j.job_id => {
                if io.progress && !cli.json {
                    write!(io.err, "\r\x1b[2K{}", format::progress(&s))?;
                    io.err.flush()?;
                    shown = true;
                }
            }
            DaemonEvent::ScanFinished(s) if s.job_id == j.job_id => break,
            _ => {}
        }
    }
    if shown {
        writeln!(io.err)?;
    }
    c.set_timeout(Some(Duration::from_secs(cli.timeout.max(1))))?;
    let d: ScanJobDetail = c.call(Request::GetJob {
        job_id: j.job_id.clone(),
    })?;
    emit(cli, io, &d, format::job)?;
    Ok(scan_exit_code(&d.summary))
}

/// 1 when threats were found, 2 when the scan failed, else 0.
pub fn scan_exit_code(s: &ScanJobSummary) -> i32 {
    if s.threats > 0 {
        EXIT_THREATS
    } else if s.state == JobState::Failed {
        EXIT_ERROR
    } else {
        EXIT_OK
    }
}

fn update(
    cli: &Cli,
    io: &mut Output<'_>,
    c: &mut Client,
    target: UpdateTarget,
    no_wait: bool,
) -> Result<i32, CliError> {
    if no_wait {
        let j: JobStarted = c.call(Request::UpdateNow { target })?;
        emit(cli, io, &j, |_| "Mise à jour lancée.\n".to_string())?;
        return Ok(EXIT_OK);
    }
    c.subscribe()?;
    c.call_raw(Request::UpdateNow { target })?;
    if !cli.json {
        writeln!(io.out, "Mise à jour en cours…")?;
        io.out.flush()?;
    }
    c.set_timeout(Some(UPDATE_WAIT))?;
    loop {
        if let DaemonEvent::UpdateFinished(u) = c.next_event()? {
            if u.target == target {
                emit(cli, io, &u, format::update)?;
                return Ok(if u.ok { EXIT_OK } else { EXIT_THREATS });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        let mut s = ScanJobSummary {
            job_id: "j".into(),
            origin: ScanOrigin::Manual,
            paths: vec![],
            state: JobState::Finished,
            started_at: 0,
            finished_at: None,
            files_scanned: 0,
            bytes_scanned: 0,
            threats: 0,
            errors: 0,
            current_path: None,
        };
        assert_eq!(scan_exit_code(&s), EXIT_OK);
        s.state = JobState::Failed;
        assert_eq!(scan_exit_code(&s), EXIT_ERROR);
        s.threats = 2;
        assert_eq!(scan_exit_code(&s), EXIT_THREATS);
    }

    #[test]
    fn config_files() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("c.toml");
        std::fs::write(&f, "[dns]\nenabled = true\n").unwrap();
        assert!(read_config(&f).unwrap().dns.enabled);
        std::fs::write(&f, "[ml]\nsuspicious_threshold = 7.0\n").unwrap();
        assert!(matches!(read_config(&f), Err(CliError::Usage(_))));
        assert!(read_config(&d.path().join("missing.toml")).is_err());
    }

    #[test]
    fn unreachable_daemon_is_exit_2() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "parabellum",
            "--socket",
            "/nonexistent/x.sock",
            "dns",
            "off",
        ])
        .unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(
            &cli,
            &mut Output {
                out: &mut out,
                err: &mut err,
                progress: false,
                is_root: true,
            },
        );
        assert_eq!(code, EXIT_ERROR);
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("impossible de joindre parabellumd"));
    }

    #[test]
    fn admin_commands_need_sudo() {
        use clap::Parser;
        let p = |a: &[&str]| {
            Cli::try_parse_from(std::iter::once("parabellum").chain(a.iter().copied())).unwrap()
        };
        for args in [
            &["dns", "off"][..],
            &["fp", "ab"],
            &["pause", "10"],
            &["config", "set", "x.toml"],
            &["quarantine", "restore", "id"],
            &["quarantine", "add", "/x"],
            &["devices", "trust", "d"],
            &["devices", "forget", "d"],
            &["persistence", "approve", "i"],
            &["resolve", "1", "allow"],
            &["components", "auto", "clamav", "off"],
        ] {
            assert!(needs_admin(&p(args).command), "{args:?}");
        }
        for args in [
            &["dns", "on"][..],
            &["status"],
            &["devices", "block", "d"],
            &["resolve", "1", "quarantine"],
            &["scan", "/x"],
            &["components", "auto", "clamav", "on"],
            &["resume"],
        ] {
            assert!(!needs_admin(&p(args).command), "{args:?}");
        }
        // Refused before connecting.
        let cli = p(&["--socket", "/nonexistent/x.sock", "dns", "off"]);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run(
            &cli,
            &mut Output {
                out: &mut out,
                err: &mut err,
                progress: false,
                is_root: false,
            },
        );
        assert_eq!(code, EXIT_ERROR);
        assert!(String::from_utf8(err)
            .unwrap()
            .contains("relancez-la avec sudo"));
    }

    #[test]
    fn relative_paths_become_absolute() {
        let p = absolute(Path::new(".")).unwrap();
        assert!(p.starts_with('/'));
    }
}
