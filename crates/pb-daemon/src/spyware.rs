//! Mercenary-spyware check with Zero Breach Toolkit (ZBT, Apache-2.0 code, CC0 indicators).
//!
//! Trust chain: the publisher's GPG signature (pinned key [`ZBT_SIGNER_FINGERPRINT`]) is verified by our
//! nightly CI, which ships the single-file scanner and its indicator cache inside the minisign-signed
//! threat DB (`zbt/`, see `pb_core::db`). The daemon never runs it as root: the script and a copy of the
//! indicators go to a fresh private temp directory owned by the console user, and
//! `/usr/bin/python3 -I <script> --no-menu --quick --indicator-cache <copy> --json <out>` runs with that
//! user's uid/gid (no supplementary groups), a clean environment, background QoS and a 30 min timeout.
//! ZBT is offline and read-only. Exit codes: 0 clean, 1 error, 2 match, 3 clean but incomplete, 4 no scan.

use crate::actions;
use crate::backends::ScanOpts;
use crate::ctx::Ctx;
use crate::jobs::{self, JobSpec};
use crate::store::AlertKey;
use chrono::{DateTime, Datelike, Days, TimeZone};
use pb_core::db::{
    DbManifest, ZbtMeta, MANIFEST_FILE, ZBT_INDICATORS_DIR, ZBT_META, ZBT_SCRIPT,
    ZBT_SIGNER_FINGERPRINT,
};
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub const COMPONENT_NAME: &str = "zero-breach-toolkit";
pub const ACTION_URL: &str = "https://github.com/interplains/Zero-Breach-Toolkit";
pub const PYTHON: &str = "/usr/bin/python3";
pub const XCODE_SELECT: &str = "/usr/bin/xcode-select";
pub const TASKPOLICY: &str = "/usr/sbin/taskpolicy";
/// Hard limit of one run.
pub const RUN_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Bounded reads.
pub const MAX_REPORT_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_SCRIPT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_META_BYTES: u64 = 64 * 1024;
pub const MAX_INDICATORS_BYTES: u64 = 512 * 1024 * 1024;
/// Findings turned into alerts per run (the rest is summarised).
pub const MAX_FINDING_ALERTS: usize = 50;
/// kv: Unix time of the last finished run / last automatic start / fingerprint of the shipped indicators.
pub const KV_LAST_RUN: &str = "spyware_last_run";
pub const KV_LAST_AUTO: &str = "spyware_last_auto_run";
pub const KV_INDICATORS_FP: &str = "spyware_indicators_fp";
/// First (catch-up) run after startup when the last one is older than a week.
pub const STARTUP_DELAY: Duration = Duration::from_secs(30 * 60);
/// Alert dedupe keys (`detection` column).
pub const KEY_GAPS: &str = "zbt:gaps";
pub const KEY_ERROR: &str = "zbt:error";

// ---------------------------------------------------------------------------------------------
// Bundle files
// ---------------------------------------------------------------------------------------------

fn read_bounded(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let f = open_nofollow(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    if meta.len() > max {
        return Err(std::io::Error::other(format!("larger than {max} bytes")));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(std::io::Error::other(format!("larger than {max} bytes")));
    }
    Ok(buf)
}

fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

/// `zbt/meta.json` of the active DB.
pub fn read_meta(db: &Path) -> Option<ZbtMeta> {
    let data = read_bounded(&db.join(ZBT_META), MAX_META_BYTES).ok()?;
    serde_json::from_slice(&data).ok()
}

/// Script + meta present in the active DB.
pub fn is_installed(db: &Path) -> bool {
    db.join(ZBT_SCRIPT).is_file() && read_meta(db).is_some()
}

/// Entry of the `list_components` answer.
pub fn component_status(db: &Path) -> ComponentStatus {
    let meta = read_meta(db).filter(|_| db.join(ZBT_SCRIPT).is_file());
    let message = match &meta {
        Some(m) => {
            let mut s = String::from(
                "Fourni par la base de menaces (signature GPG de l'éditeur vérifiée en CI)",
            );
            if m.indicators_updated_at > 0 {
                s.push_str(&format!(
                    ", indicateurs du {}",
                    crate::system::local_date(m.indicators_updated_at)
                ));
            }
            s
        }
        None => {
            "Absent de la base de menaces actuelle (arrive avec la prochaine mise à jour)".into()
        }
    };
    ComponentStatus {
        name: COMPONENT_NAME.into(),
        display_name: "Zero Breach Toolkit (anti-spyware)".into(),
        installed_version: meta
            .as_ref()
            .map(|m| m.version.clone())
            .filter(|v| !v.is_empty()),
        latest_version: None,
        state: if meta.is_some() {
            ComponentState::Installed
        } else {
            ComponentState::NotInstalled
        },
        last_check: meta
            .as_ref()
            .map(|m| m.indicators_updated_at)
            .filter(|t| *t > 0),
        auto_update: true,
        required: false,
        message: Some(message),
        action_url: Some(ACTION_URL.into()),
    }
}

/// Fingerprint of the ZBT files of the active DB (from the manifest digests), `None` when absent.
pub fn indicators_fingerprint(db: &Path) -> Option<String> {
    let data = read_bounded(&db.join(MANIFEST_FILE), 64 * 1024 * 1024).ok()?;
    let m: DbManifest = serde_json::from_slice(&data).ok()?;
    let mut h = Sha256::new();
    let mut any = false;
    for (path, digest) in m.files.iter().filter(|(p, _)| p.starts_with("zbt/")) {
        any = true;
        h.update(path.as_bytes());
        h.update(b"\t");
        h.update(digest.as_bytes());
        h.update(b"\n");
    }
    any.then(|| hex::encode(h.finalize()))
}

// ---------------------------------------------------------------------------------------------
// Report parsing (tolerant: unknown / missing fields are ignored)
// ---------------------------------------------------------------------------------------------

/// One actionable indicator match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Family / vendor when known (Pegasus, Predator, Graphite…), else the indicator source.
    pub name: String,
    pub indicator: String,
    /// ZBT evidence grade (`on-disk`, `contacted`, `dns-record`…).
    pub evidence: String,
    pub location: String,
    pub detail: String,
    pub source: String,
    pub module: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParsedReport {
    pub version: Option<String>,
    pub findings: Vec<Finding>,
    /// What could not be checked ("module/check : reason").
    pub gaps: Vec<String>,
    pub checks_ran: u64,
}

fn s(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .map(|x| x.chars().filter(|c| !c.is_control()).take(500).collect())
        .unwrap_or_default()
}

/// Parse the `--json` report.
pub fn parse_report(data: &[u8]) -> Option<ParsedReport> {
    let doc: Value = serde_json::from_slice(data).ok()?;
    if !doc.is_object() {
        return None;
    }
    let mut r = ParsedReport {
        version: doc
            .pointer("/tool/version")
            .and_then(Value::as_str)
            .map(|v| v.chars().take(32).collect()),
        ..Default::default()
    };
    if let Some(modules) = doc.get("modules").and_then(Value::as_object) {
        for (mname, md) in modules {
            for c in md
                .get("checks")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if c.get("ran").and_then(Value::as_bool) == Some(true) {
                    r.checks_ran += 1;
                }
            }
            for h in md
                .get("hits")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let evidence = s(h, "evidence");
                // `referenced` = the string only appears in saved content; withdrawn = every publisher
                // retracted the indicator. Neither counts as a finding (same rule as ZBT's verdict).
                if evidence == "referenced"
                    || h.get("withdrawn_only").and_then(Value::as_bool) == Some(true)
                {
                    continue;
                }
                let indicator = s(h, "indicator");
                let family = s(h, "family");
                let source = s(h, "source");
                let name = [&family, &source, &indicator]
                    .into_iter()
                    .find(|x| !x.is_empty())
                    .cloned()
                    .unwrap_or_else(|| "indicateur inconnu".into());
                r.findings.push(Finding {
                    name,
                    indicator,
                    evidence,
                    location: s(h, "location"),
                    detail: s(h, "detail"),
                    source,
                    module: mname.chars().take(64).collect(),
                });
            }
        }
    }
    let not_checked = doc
        .pointer("/coverage/not_checked")
        .and_then(Value::as_array);
    if let Some(list) = not_checked {
        for g in list {
            let reason = s(g, "reason");
            let what = format!("{}/{}", s(g, "module"), s(g, "check"));
            r.gaps.push(if reason.is_empty() {
                what
            } else {
                format!("{what} : {reason}")
            });
        }
    } else if let Some(list) = doc.pointer("/verdict/gaps").and_then(Value::as_array) {
        r.gaps.extend(
            list.iter()
                .filter_map(Value::as_str)
                .map(|g| g.chars().filter(|c| !c.is_control()).take(300).collect()),
        );
    }
    Some(r)
}

/// Result of one run, as acted upon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Clean {
        checks: u64,
    },
    Found {
        findings: Vec<Finding>,
        gaps: Vec<String>,
    },
    Incomplete {
        gaps: Vec<String>,
        checks: u64,
    },
    Error(String),
    Cancelled,
}

/// Combine exit code and report (the exit code is authoritative; the report adds the details).
pub fn outcome(exit: Option<i32>, report: Option<ParsedReport>, stderr_tail: &str) -> Outcome {
    let err_tail = || {
        let t = stderr_tail.trim();
        if t.is_empty() {
            String::new()
        } else {
            format!(
                " : {}",
                t.chars()
                    .rev()
                    .take(300)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<String>()
            )
        }
    };
    match (exit, report) {
        (Some(2), Some(r)) if !r.findings.is_empty() => Outcome::Found {
            findings: r.findings,
            gaps: r.gaps,
        },
        (Some(2), _) => Outcome::Found {
            findings: vec![Finding {
                name: "correspondance non détaillée".into(),
                indicator: String::new(),
                evidence: String::new(),
                location: "rapport JSON illisible".into(),
                detail: "Zero Breach Toolkit a signalé une correspondance (code 2) sans rapport exploitable".into(),
                source: String::new(),
                module: String::new(),
            }],
            gaps: vec![],
        },
        (Some(0), r) => Outcome::Clean {
            checks: r.map(|r| r.checks_ran).unwrap_or(0),
        },
        (Some(3), r) => {
            let (gaps, checks) = r.map(|r| (r.gaps, r.checks_ran)).unwrap_or_default();
            Outcome::Incomplete { gaps, checks }
        }
        (Some(4), _) => Outcome::Error(format!("aucune analyse effectuée (code 4){}", err_tail())),
        (Some(code), _) => Outcome::Error(format!("échec de Zero Breach Toolkit (code {code}){}", err_tail())),
        (None, _) => Outcome::Error(format!("Zero Breach Toolkit interrompu par un signal{}", err_tail())),
    }
}

fn evidence_label(e: &str) -> &str {
    match e {
        "on-disk" => "fichier connu présent sur le disque",
        "file-pattern" => "motif de fichier (à vérifier)",
        "persistence" => "cité dans un démarrage automatique",
        "ran-command" => "cité dans une commande exécutée",
        "execution-record" => "trace d'exécution",
        "inventory-record" => "inventaire de fichiers",
        "on-device" => "présent sur l'appareil",
        "device-log" => "journaux de l'appareil",
        "received" => "dans un message reçu",
        "contacted" => "connexion établie avec le serveur",
        "dns-record" => "résolution DNS",
        "attempted" => "tentative de connexion bloquée",
        "configured" => "présent dans une configuration",
        "" => "non précisé",
        other => other,
    }
}

/// Dedupe key of a finding (stored in the `detection` column; the family stays readable).
pub fn finding_key(f: &Finding) -> String {
    let mut h = Sha256::new();
    h.update(f.indicator.as_bytes());
    h.update(b"\0");
    h.update(f.location.as_bytes());
    let digest = hex::encode(h.finalize());
    format!("zbt:{}:{}", f.name, &digest[..12])
}

/// Alerts (with their dedupe key) for an outcome.
pub fn alerts_for(o: &Outcome) -> Vec<(Alert, String)> {
    let mut out = Vec::new();
    match o {
        Outcome::Found { findings, .. } => {
            for f in findings.iter().take(MAX_FINDING_ALERTS) {
                let mut msg = format!(
                    "Indice : {} ({})",
                    evidence_label(&f.evidence),
                    if f.evidence.is_empty() {
                        "?"
                    } else {
                        &f.evidence
                    }
                );
                if !f.location.is_empty() {
                    msg.push_str(&format!("\nOù : {}", f.location));
                }
                if !f.indicator.is_empty() {
                    msg.push_str(&format!("\nIndicateur : {}", f.indicator));
                }
                if !f.source.is_empty() {
                    msg.push_str(&format!("\nSource : {}", f.source));
                }
                if !f.detail.is_empty() {
                    msg.push_str(&format!("\n{}", f.detail));
                }
                msg.push_str(
                    "\nNe supprime rien et n'éteins pas le Mac : garde-le en l'état et contacte un service d'aide \
                     spécialisé (Amnesty Security Lab, Access Now Digital Security Helpline).",
                );
                out.push((
                    actions::alert(
                        AlertKind::Malware,
                        Severity::Critical,
                        format!("Traces de logiciel espion : {}", f.name),
                        msg,
                    ),
                    finding_key(f),
                ));
            }
            if findings.len() > MAX_FINDING_ALERTS {
                out.push((
                    actions::alert(
                        AlertKind::Malware,
                        Severity::Critical,
                        "Traces de logiciel espion : autres correspondances",
                        format!(
                            "{} correspondances supplémentaires : relance « parabellum spyware-scan » pour le détail",
                            findings.len() - MAX_FINDING_ALERTS
                        ),
                    ),
                    "zbt:more".into(),
                ));
            }
        }
        Outcome::Incomplete { gaps, .. } => {
            let mut msg = String::from(
                "Aucune trace connue de logiciel espion, mais certaines vérifications n'ont pas pu être faites :",
            );
            for g in gaps.iter().take(15) {
                msg.push_str("\n• ");
                msg.push_str(g);
            }
            if gaps.len() > 15 {
                msg.push_str(&format!("\n… et {} autres", gaps.len() - 15));
            }
            if gaps.is_empty() {
                msg.push_str("\n• (détail absent du rapport)");
            }
            out.push((
                actions::alert(
                    AlertKind::System,
                    Severity::Info,
                    "Analyse anti-spyware incomplète",
                    msg,
                ),
                KEY_GAPS.into(),
            ));
        }
        Outcome::Error(e) => out.push((
            actions::alert(
                AlertKind::System,
                Severity::Low,
                "Analyse anti-spyware impossible",
                e.clone(),
            ),
            KEY_ERROR.into(),
        )),
        Outcome::Clean { .. } | Outcome::Cancelled => {}
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct RunOutput {
    pub exit: Option<i32>,
    pub report: Option<Vec<u8>>,
    pub stderr_tail: String,
    pub cancelled: bool,
}

/// Private work directory owned by `uid:gid`, removed on drop.
struct WorkDir(PathBuf);

impl Drop for WorkDir {
    fn drop(&mut self) {
        // remove_dir_all does not follow symlinks planted by the user.
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn work_base() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/private/tmp")
    } else {
        std::env::temp_dir()
    }
}

/// Copy the script and the indicator cache into a fresh `0700` directory, then hand it to the user.
fn prepare(db: &Path, meta: &ZbtMeta, uid: u32, gid: u32) -> Result<WorkDir, String> {
    use std::os::unix::fs::DirBuilderExt;
    let script = read_bounded(&db.join(ZBT_SCRIPT), MAX_SCRIPT_BYTES)
        .map_err(|e| format!("script illisible : {e}"))?;
    let digest = hex::encode(Sha256::digest(&script));
    if meta.sha256.is_empty() || !meta.sha256.eq_ignore_ascii_case(&digest) {
        return Err(
            "empreinte SHA-256 du script différente de zbt/meta.json : exécution refusée".into(),
        );
    }
    if !meta.signer_fingerprint.is_empty()
        && !meta
            .signer_fingerprint
            .replace(' ', "")
            .eq_ignore_ascii_case(ZBT_SIGNER_FINGERPRINT)
    {
        return Err("signataire inattendu dans zbt/meta.json : exécution refusée".into());
    }
    let dir = work_base().join(format!("parabellum-zbt-{}", uuid::Uuid::new_v4().simple()));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| format!("{} : {e}", dir.display()))?;
    let wd = WorkDir(dir.clone());
    let ind = dir.join("indicators");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&ind)
        .map_err(|e| e.to_string())?;
    let write = |p: &Path, data: &[u8]| -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p)
            .map_err(|e| format!("{} : {e}", p.display()))?;
        f.write_all(data).map_err(|e| e.to_string())?;
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(|e| format!("chown : {e}"))
    };
    write(&dir.join("zero-breach-toolkit.py"), &script)?;
    let src = db.join(ZBT_INDICATORS_DIR);
    let mut total = 0u64;
    if let Ok(rd) = std::fs::read_dir(&src) {
        for entry in rd.flatten() {
            let name = entry.file_name();
            let Some(n) = name.to_str() else { continue };
            if n.starts_with('.') || n.contains('/') {
                continue;
            }
            let Ok(data) = read_bounded(&entry.path(), MAX_INDICATORS_BYTES) else {
                continue; // not a regular file
            };
            total += data.len() as u64;
            if total > MAX_INDICATORS_BYTES {
                return Err("cache d'indicateurs trop volumineux".into());
            }
            write(&ind.join(n), &data)?;
        }
    }
    write(&dir.join("stderr.log"), b"")?;
    std::os::unix::fs::chown(&ind, Some(uid), Some(gid)).map_err(|e| format!("chown : {e}"))?;
    std::os::unix::fs::chown(&dir, Some(uid), Some(gid)).map_err(|e| format!("chown : {e}"))?;
    Ok(wd)
}

fn tail(path: &Path, n: usize) -> String {
    match read_bounded(path, 8 * 1024 * 1024) {
        Ok(d) => {
            let start = d.len().saturating_sub(n);
            String::from_utf8_lossy(&d[start..])
                .chars()
                .filter(|c| !c.is_control() || *c == '\n')
                .collect()
        }
        Err(_) => String::new(),
    }
}

/// Run ZBT once as the console user.
pub async fn execute(ctx: &Arc<Ctx>, cancel: &AtomicBool) -> Result<RunOutput, String> {
    let db = ctx.paths.db_current();
    let meta = read_meta(&db).ok_or("Zero Breach Toolkit absent de la base de menaces")?;
    let user = crate::system::console_user().ok_or("aucun utilisateur connecté à la console")?;
    if user.uid == 0 {
        return Err("refus d'exécuter Zero Breach Toolkit en root".into());
    }
    let gid = crate::system::user_gid(user.uid).ok_or("groupe de l'utilisateur introuvable")?;
    if !Path::new(PYTHON).exists() {
        return Err(format!("{PYTHON} introuvable"));
    }
    #[cfg(target_os = "macos")]
    {
        // /usr/bin/python3 is a shim: without the Command Line Tools it only shows an install prompt.
        let ok = crate::system::run_command(XCODE_SELECT, &["-p"], Duration::from_secs(10))
            .await
            .map(|o| o.success())
            .unwrap_or(false);
        if !ok {
            return Err(
                "Python 3 d'Apple indisponible : installe les outils de ligne de commande (« xcode-select --install »)"
                    .into(),
            );
        }
    }
    let (db2, meta2, uid) = (db.clone(), meta.clone(), user.uid);
    let wd = tokio::task::spawn_blocking(move || prepare(&db2, &meta2, uid, gid))
        .await
        .map_err(|e| e.to_string())??;
    let dir = wd.0.clone();
    let script = dir.join("zero-breach-toolkit.py");
    let report = dir.join("report.json");
    let stderr_path = dir.join("stderr.log");
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .open(&stderr_path)
        .map_err(|e| e.to_string())?;
    let zbt_args: Vec<std::ffi::OsString> = vec![
        "-I".into(),
        script.into_os_string(),
        "--no-menu".into(),
        "--no-banner".into(),
        "--quick".into(),
        "--indicator-cache".into(),
        dir.join("indicators").into_os_string(),
        "--json".into(),
        report.clone().into_os_string(),
    ];
    let background = ctx.config().energy.background_qos && Path::new(TASKPOLICY).exists();
    let mut cmd = if cfg!(target_os = "macos") && background {
        let mut c = tokio::process::Command::new(TASKPOLICY);
        c.arg("-b").arg(PYTHON);
        c
    } else {
        tokio::process::Command::new(PYTHON)
    };
    cmd.args(&zbt_args)
        .current_dir(&dir)
        .env_clear()
        .env("HOME", &user.home)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("TMPDIR", &dir)
        .env("LANG", "en_US.UTF-8")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(stderr))
        .kill_on_drop(true)
        // std drops every supplementary group when switching from root (setgroups(0)).
        .uid(user.uid)
        .gid(gid);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("lancement impossible : {e}"))?;
    tracing::info!(uid = user.uid, version = %meta.version, "zero breach toolkit started");
    let deadline = tokio::time::Instant::now() + RUN_TIMEOUT;
    let mut out = RunOutput::default();
    loop {
        tokio::select! {
            r = child.wait() => {
                let status = r.map_err(|e| e.to_string())?;
                out.exit = status.code();
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if cancel.load(Ordering::SeqCst) || ctx.is_shutting_down() {
                    let _ = child.kill().await;
                    out.cancelled = true;
                    return Ok(out);
                }
                if tokio::time::Instant::now() >= deadline {
                    let _ = child.kill().await;
                    return Err(format!("délai dépassé ({} min)", RUN_TIMEOUT.as_secs() / 60));
                }
            }
        }
    }
    let (rp, sp) = (report.clone(), stderr_path.clone());
    let (rep, err) = tokio::task::spawn_blocking(move || {
        (read_bounded(&rp, MAX_REPORT_BYTES).ok(), tail(&sp, 2048))
    })
    .await
    .map_err(|e| e.to_string())?;
    out.report = rep;
    out.stderr_tail = err;
    drop(wd);
    Ok(out)
}

/// Summary handed back to the job runner.
#[derive(Debug, Default, Clone, Copy)]
pub struct JobCounters {
    pub checks: u64,
    pub threats: u64,
    pub errors: u64,
    pub failed: bool,
    pub cancelled: bool,
}

/// Body of a `spyware` job: run, raise alerts, remember the run.
pub async fn scan(ctx: &Arc<Ctx>, cancel: &AtomicBool) -> JobCounters {
    let o = match execute(ctx, cancel).await {
        Ok(r) if r.cancelled => Outcome::Cancelled,
        Ok(r) => {
            let parsed = r.report.as_deref().and_then(parse_report);
            outcome(r.exit, parsed, &r.stderr_tail)
        }
        Err(e) => Outcome::Error(e),
    };
    let mut c = JobCounters::default();
    match &o {
        Outcome::Clean { checks } => c.checks = *checks,
        Outcome::Found { findings, .. } => c.threats = findings.len() as u64,
        Outcome::Incomplete { checks, gaps } => {
            c.checks = *checks;
            c.errors = gaps.len() as u64;
        }
        Outcome::Error(e) => {
            tracing::warn!(error = %e, "spyware scan failed");
            c.errors = 1;
            c.failed = true;
        }
        Outcome::Cancelled => c.cancelled = true,
    }
    for (alert, key) in alerts_for(&o) {
        let k2 = key.clone();
        let open = ctx
            .store
            .run(move |s| s.open_alerts_by(AlertKey::Title(&k2)))
            .await
            .unwrap_or_default();
        if open.is_empty() {
            actions::raise_alert(ctx, alert, Some(key)).await;
        }
    }
    if !matches!(o, Outcome::Cancelled) {
        let now = pb_core::now_ts().to_string();
        let _ = ctx.store.run(move |s| s.kv_set(KV_LAST_RUN, &now)).await;
    }
    c
}

// ---------------------------------------------------------------------------------------------
// Starting & scheduling
// ---------------------------------------------------------------------------------------------

/// Queue a spyware job (IPC `spyware_scan`, weekly schedule, DB update).
pub async fn start(ctx: &Arc<Ctx>) -> Result<String, IpcError> {
    let db = ctx.paths.db_current();
    let meta = tokio::task::spawn_blocking(move || {
        read_meta(&db).filter(|_| db.join(ZBT_SCRIPT).is_file())
    })
    .await
    .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?
    .ok_or_else(|| {
        IpcError::new(
            ErrorCode::Unavailable,
            "Zero Breach Toolkit n'est pas encore dans la base de menaces : lance une mise à jour",
        )
    })?;
    if ctx.jobs.has_active(ScanOrigin::Spyware) {
        return Err(IpcError::new(
            ErrorCode::Busy,
            "une analyse anti-spyware est déjà en cours",
        ));
    }
    let spec = JobSpec {
        paths: vec![format!(
            "Zero Breach Toolkit {} : traces de logiciels espions",
            meta.version
        )],
        roots: vec![],
        opts: ScanOpts {
            origin: ScanOrigin::Spyware,
            use_clamav: false,
            recursive: false,
            only_risky_types: false,
        },
    };
    jobs::submit(ctx, spec).await
}

/// Automatic start (weekly / after a DB update): waits for power, records the start.
async fn auto_start(ctx: &Arc<Ctx>, why: &str) {
    if !crate::scheduler::wait_for_power(ctx, crate::scheduler::MAX_BATTERY_DEFERRAL).await {
        return;
    }
    match start(ctx).await {
        Ok(id) => {
            tracing::info!(job = %id, reason = why, "spyware scan queued");
            let now = pb_core::now_ts().to_string();
            let _ = ctx.store.run(move |s| s.kv_set(KV_LAST_AUTO, &now)).await;
        }
        Err(e) => tracing::info!(reason = why, error = %e.message, "spyware scan not started"),
    }
}

/// Next `weekday` (1 = Monday … 7 = Sunday) at `hour`:00 local + `jitter_secs`, strictly after `now`.
pub fn next_weekly<Tz: TimeZone>(
    now: &DateTime<Tz>,
    weekday: u8,
    hour: u8,
    jitter_secs: i64,
) -> Option<DateTime<Tz>> {
    let tz = now.timezone();
    let weekday = u32::from(weekday.clamp(1, 7));
    for add in 0..=7u64 {
        let day = now.date_naive().checked_add_days(Days::new(add))?;
        if day.weekday().number_from_monday() != weekday {
            continue;
        }
        let at = (0..3u32).find_map(|extra| {
            day.and_hms_opt((u32::from(hour.min(23)) + extra).min(23), 0, 0)
                .and_then(|n| tz.from_local_datetime(&n).earliest())
        })? + chrono::Duration::seconds(jitter_secs);
        if at > *now {
            return Some(at);
        }
    }
    None
}

/// Weekly schedule (+ a catch-up run 30 min after startup when the last run is older than 8 days).
pub async fn schedule_loop(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    let mut cfg_rx = ctx.config_rx();
    let last = ctx
        .store
        .run(|s| s.kv_get_i64(KV_LAST_RUN))
        .await
        .ok()
        .flatten();
    let mut catch_up = last
        .map(|t| pb_core::now_ts() - t > 8 * 86_400)
        .unwrap_or(true);
    loop {
        let sec = ctx.config().security.clone();
        let wait = if !sec.spyware_scan_weekly {
            Duration::from_secs(86_400)
        } else if catch_up {
            STARTUP_DELAY
        } else {
            next_weekly(
                &chrono::Local::now(),
                sec.spyware_scan_weekday,
                sec.spyware_scan_hour,
                crate::scheduler::jitter(30 * 60),
            )
            .map(|t| {
                Duration::from_secs((t.timestamp() - chrono::Local::now().timestamp()).max(1) as u64)
            })
            .unwrap_or(Duration::from_secs(86_400))
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {
                catch_up = false;
                if ctx.config().security.spyware_scan_weekly {
                    auto_start(&ctx, "weekly").await;
                }
            }
            r = cfg_rx.changed() => {
                if r.is_err() { return; }
                let _ = cfg_rx.borrow_and_update();
            }
            _ = shutdown.changed() => if *shutdown.borrow() { return; },
        }
    }
}

/// After a DB swap: re-run when the shipped ZBT files changed (at most once a day).
pub async fn after_db_update(ctx: &Arc<Ctx>) {
    let db = ctx.paths.db_current();
    let Ok(Some(fp)) = tokio::task::spawn_blocking(move || indicators_fingerprint(&db)).await
    else {
        return;
    };
    let (prev, last_auto) = ctx
        .store
        .run(|s| Ok((s.kv_get(KV_INDICATORS_FP)?, s.kv_get_i64(KV_LAST_AUTO)?)))
        .await
        .unwrap_or((None, None));
    if prev.as_deref() == Some(fp.as_str()) {
        return;
    }
    let fp2 = fp.clone();
    let _ = ctx
        .store
        .run(move |s| s.kv_set(KV_INDICATORS_FP, &fp2))
        .await;
    if !ctx.config().security.spyware_scan_weekly {
        return;
    }
    if last_auto.is_some_and(|t| pb_core::now_ts() - t < 86_400) {
        return;
    }
    let ctx2 = ctx.clone();
    tokio::spawn(async move { auto_start(&ctx2, "indicators updated").await });
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT_HIT: &str = r#"{
      "schema_version": 3,
      "tool": {"name": "zero-breach-toolkit", "version": "0.1.9"},
      "modules": {
        "browser": {
          "status": "HIT",
          "checks": [{"name": "history", "ran": true}, {"name": "cache", "ran": false, "reason": "locked"}],
          "hits": [
            {"indicator": "evil-cdn.example", "location": "Chrome history (Default)", "detail": "visited 2026-09-01",
             "tier": "infra", "confidence": "high", "source": "Amnesty", "evidence": "contacted",
             "family": "Predator", "withdrawn_only": false},
            {"indicator": "x.example", "location": "Notes", "detail": "", "evidence": "referenced", "family": "Pegasus"},
            {"indicator": "old.example", "location": "DNS cache", "evidence": "dns-record", "family": "Candiru",
             "withdrawn_only": true}
          ]
        },
        "hash": {"checks": [{"name": "downloads", "ran": true}], "hits": []}
      },
      "verdict": {"status": "HITS", "findings_total": 1, "gaps": ["browser/cache: locked"]},
      "coverage": {"checked": [], "not_checked": [{"module": "browser", "check": "cache", "reason": "locked"}]},
      "exit_code": 2
    }"#;

    #[test]
    fn parses_findings_and_gaps() {
        let r = parse_report(REPORT_HIT.as_bytes()).unwrap();
        assert_eq!(r.version.as_deref(), Some("0.1.9"));
        assert_eq!(r.checks_ran, 2);
        assert_eq!(
            r.findings.len(),
            1,
            "referenced and withdrawn are not findings"
        );
        let f = &r.findings[0];
        assert_eq!(f.name, "Predator");
        assert_eq!(f.evidence, "contacted");
        assert_eq!(f.module, "browser");
        assert_eq!(r.gaps, vec!["browser/cache : locked".to_string()]);
        assert!(parse_report(b"not json").is_none());
        assert!(parse_report(b"[1]").is_none());
        // Tolerant: missing everything.
        assert_eq!(parse_report(b"{}").unwrap(), ParsedReport::default());
    }

    #[test]
    fn outcomes_and_alerts() {
        let r = parse_report(REPORT_HIT.as_bytes());
        let o = outcome(Some(2), r, "");
        let alerts = alerts_for(&o);
        assert_eq!(alerts.len(), 1);
        let (a, key) = &alerts[0];
        assert_eq!(a.kind, AlertKind::Malware);
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.title, "Traces de logiciel espion : Predator");
        assert!(a.message.contains("connexion établie") && a.message.contains("Chrome history"));
        assert_eq!(a.actions, vec![AlertAction::Acknowledge]);
        assert!(key.starts_with("zbt:Predator:"));

        // Exit 2 without a readable report still alerts.
        let o = outcome(Some(2), None, "");
        assert!(matches!(&o, Outcome::Found { findings, .. } if findings.len() == 1));

        let gaps = r#"{"coverage":{"not_checked":[{"module":"host","check":"dns","reason":"no access"}]},
                        "modules":{"host":{"checks":[{"name":"x","ran":true}]}}}"#;
        let o = outcome(Some(3), parse_report(gaps.as_bytes()), "");
        assert_eq!(
            o,
            Outcome::Incomplete {
                gaps: vec!["host/dns : no access".into()],
                checks: 1
            }
        );
        let a = alerts_for(&o);
        assert_eq!(a[0].0.kind, AlertKind::System);
        assert_eq!(a[0].0.severity, Severity::Info);
        assert!(a[0].0.message.contains("host/dns"));
        assert_eq!(a[0].1, KEY_GAPS);

        assert_eq!(outcome(Some(0), None, ""), Outcome::Clean { checks: 0 });
        let e = outcome(Some(1), None, "Traceback\nerror: boom\n");
        assert!(matches!(&e, Outcome::Error(m) if m.contains("code 1") && m.contains("boom")));
        let a = alerts_for(&e);
        assert_eq!(a[0].0.severity, Severity::Low);
        assert_eq!(a[0].0.kind, AlertKind::System);
        assert!(matches!(outcome(Some(4), None, ""), Outcome::Error(_)));
        assert!(matches!(outcome(None, None, ""), Outcome::Error(_)));
        assert!(alerts_for(&Outcome::Clean { checks: 3 }).is_empty());
    }

    #[test]
    fn many_findings_are_capped() {
        let findings: Vec<Finding> = (0..60)
            .map(|i| Finding {
                name: "Pegasus".into(),
                indicator: format!("d{i}.example"),
                evidence: "dns-record".into(),
                location: "x".into(),
                detail: String::new(),
                source: String::new(),
                module: "host".into(),
            })
            .collect();
        let a = alerts_for(&Outcome::Found {
            findings,
            gaps: vec![],
        });
        assert_eq!(a.len(), MAX_FINDING_ALERTS + 1);
        let keys: std::collections::BTreeSet<_> = a.iter().map(|(_, k)| k.clone()).collect();
        assert_eq!(keys.len(), a.len(), "distinct dedupe keys");
    }

    fn write_bundle(dir: &Path, script: &[u8], meta_sha: Option<&str>) {
        std::fs::create_dir_all(dir.join(ZBT_INDICATORS_DIR)).unwrap();
        std::fs::write(dir.join(ZBT_SCRIPT), script).unwrap();
        std::fs::write(dir.join(ZBT_INDICATORS_DIR).join("manifest.json"), b"{}").unwrap();
        let meta = ZbtMeta {
            version: "0.1.9".into(),
            sha256: meta_sha
                .map(str::to_string)
                .unwrap_or_else(|| hex::encode(Sha256::digest(script))),
            indicators_updated_at: 1_793_000_000,
            signer_fingerprint: ZBT_SIGNER_FINGERPRINT.into(),
        };
        std::fs::write(dir.join(ZBT_META), serde_json::to_vec(&meta).unwrap()).unwrap();
    }

    #[test]
    fn component_and_prepare() {
        let d = tempfile::tempdir().unwrap();
        let st = component_status(d.path());
        assert_eq!(st.state, ComponentState::NotInstalled);
        assert_eq!(st.name, COMPONENT_NAME);
        write_bundle(d.path(), b"print('hi')\n", None);
        let st = component_status(d.path());
        assert_eq!(st.state, ComponentState::Installed);
        assert_eq!(st.installed_version.as_deref(), Some("0.1.9"));
        assert!(st.auto_update && !st.required);
        assert_eq!(st.action_url.as_deref(), Some(ACTION_URL));
        assert!(is_installed(d.path()));

        let meta = read_meta(d.path()).unwrap();
        let uid = crate::system::euid();
        let gid = unsafe { libc::getegid() };
        let wd = prepare(d.path(), &meta, uid, gid).unwrap();
        let dir = wd.0.clone();
        assert!(dir.join("zero-breach-toolkit.py").is_file());
        assert!(dir.join("indicators/manifest.json").is_file());
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
        drop(wd);
        assert!(!dir.exists(), "work dir removed");

        // Tampered script: refused.
        let d2 = tempfile::tempdir().unwrap();
        write_bundle(d2.path(), b"evil", Some(&"0".repeat(64)));
        let meta = read_meta(d2.path()).unwrap();
        assert!(prepare(d2.path(), &meta, uid, gid).is_err());
    }

    #[test]
    fn fingerprint_from_manifest() {
        let d = tempfile::tempdir().unwrap();
        assert!(indicators_fingerprint(d.path()).is_none());
        let mk = |digest: &str| {
            serde_json::json!({
                "format": 1, "version": "v", "built_at": 0, "min_client_version": "0.1.0", "sources": [],
                "files": {"zbt/meta.json": digest, "yara/a.yar": "b".repeat(64)},
                "stats": {}
            })
            .to_string()
        };
        std::fs::write(d.path().join(MANIFEST_FILE), mk(&"a".repeat(64))).unwrap();
        let a = indicators_fingerprint(d.path()).unwrap();
        std::fs::write(d.path().join(MANIFEST_FILE), mk(&"c".repeat(64))).unwrap();
        let b = indicators_fingerprint(d.path()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn weekly_schedule() {
        use chrono::Utc;
        // 2026-10-28 is a Wednesday.
        let now = Utc.with_ymd_and_hms(2026, 10, 28, 10, 0, 0).unwrap();
        let t = next_weekly(&now, 3, 13, 0).unwrap();
        assert_eq!(t, Utc.with_ymd_and_hms(2026, 10, 28, 13, 0, 0).unwrap());
        let now = Utc.with_ymd_and_hms(2026, 10, 28, 14, 0, 0).unwrap();
        let t = next_weekly(&now, 3, 13, 60).unwrap();
        assert_eq!(t, Utc.with_ymd_and_hms(2026, 11, 4, 13, 1, 0).unwrap());
        let t = next_weekly(&now, 7, 9, 0).unwrap();
        assert_eq!(t, Utc.with_ymd_and_hms(2026, 11, 1, 9, 0, 0).unwrap());
    }
}
