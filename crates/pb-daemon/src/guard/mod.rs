//! Behaviour guard: info-stealer detection, ransomware detection (decoy files + mass encryption) and APFS
//! snapshots. Fed by the real-time dispatcher with eslogger `exec` / `create` / `rename` events and FSEvents
//! file activity; acts by killing (stealers) or suspending (ransomware) the responsible process, and raises
//! `behavior` alerts offering kill / resume / quarantine.
//!
//! Design limits (no Endpoint Security entitlement): everything is observed just after it happened. A fake
//! password dialog is killed as soon as it appears, a keychain read is detected when `security` starts, a
//! staging copy when the file is created; reads done with the stealer's own code (no tool, no copy) are
//! not visible to eslogger without the very noisy `open` event, which is not subscribed.

pub mod ransomware;
pub mod rules;
pub mod snapshots;

use crate::actions;
use crate::ctx::Ctx;
use pb_core::events::{EsProcessInfo, FileEventSource};
use pb_core::model::*;
use ransomware::{BurstDetector, Canary, CanaryState};
use rules::{Correlator, IndicatorKind};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Indicators of one actor are correlated over this window.
pub const CORRELATION_WINDOW: Duration = Duration::from_secs(600);
/// Same alert (rule + actor) at most once per this window.
pub const ALERT_DEDUPE: Duration = Duration::from_secs(600);
/// Canary integrity check period.
pub const CANARY_CHECK: Duration = Duration::from_secs(15);
/// kv: the canary registry (JSON `Vec<Canary>`).
pub const KV_CANARIES: &str = "guard_canaries";
/// Non-Apple processes remembered to find ransomware suspects.
const RECENT_EXECS: usize = 512;
/// Folders (relative to the console user's home) receiving decoys.
pub const CANARY_DIRS: [&str; 3] = ["Documents", "Desktop", "Pictures"];
const ES_CS_ADHOC: u32 = 0x2;

#[derive(Debug, Clone)]
struct RecentExec {
    pid: i32,
    path: String,
    team_id: Option<String>,
    adhoc: bool,
    at: Instant,
}

#[derive(Debug)]
struct Inner {
    correlator: Correlator,
    burst: BurstDetector,
    recent: VecDeque<RecentExec>,
    alerted: HashMap<String, Instant>,
    canaries: Vec<Canary>,
    suspended: Vec<SuspendedProcess>,
    last_snapshot: Option<i64>,
    snapshot_error: Option<String>,
    /// Canary modifications already handled (path -> when), to avoid re-alerting every check.
    tripped_canaries: HashMap<PathBuf, Instant>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            correlator: Correlator::new(CORRELATION_WINDOW),
            burst: BurstDetector::default(),
            recent: VecDeque::new(),
            alerted: HashMap::new(),
            canaries: Vec::new(),
            suspended: Vec::new(),
            last_snapshot: None,
            snapshot_error: None,
            tripped_canaries: HashMap::new(),
        }
    }
}

/// Guard state shared through [`Ctx`].
#[derive(Debug, Default)]
pub struct GuardState {
    inner: Mutex<Inner>,
}

impl GuardState {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `true` if `key` was not alerted within [`ALERT_DEDUPE`] (and records it).
    fn should_alert(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut g = self.lock();
        g.alerted
            .retain(|_, at| now.duration_since(*at) < ALERT_DEDUPE);
        if g.alerted.contains_key(key) {
            return false;
        }
        g.alerted.insert(key.to_string(), now);
        true
    }

    fn is_canary(&self, p: &str) -> Option<PathBuf> {
        let g = self.lock();
        g.canaries
            .iter()
            .find(|c| {
                let cp = c.path.to_string_lossy();
                p == cp || (p.starts_with(cp.as_ref()) && p.as_bytes().get(cp.len()) == Some(&b'.'))
            })
            .map(|c| c.path.clone())
    }

    pub fn remove_suspended(&self, pid: i32) {
        self.lock().suspended.retain(|s| s.pid != pid);
    }
}

// ---------------------------------------------------------------------------------------------
// Event entry points (called by the real-time dispatcher; cheap, spawn the slow parts)
// ---------------------------------------------------------------------------------------------

/// `exec` seen by eslogger.
pub fn on_exec(
    ctx: &Arc<Ctx>,
    target: &EsProcessInfo,
    args: &[String],
    parent: Option<&EsProcessInfo>,
) {
    if !target.is_platform_binary && !rules::is_system_path(&target.path) {
        let mut g = ctx.guard.lock();
        if g.recent.len() >= RECENT_EXECS {
            g.recent.pop_front();
        }
        g.recent.push_back(RecentExec {
            pid: target.pid,
            path: target.path.clone(),
            team_id: target.team_id.clone(),
            adhoc: target.codesigning_flags & ES_CS_ADHOC != 0,
            at: Instant::now(),
        });
    }
    let cfg = ctx.config();
    if !cfg.guard.stealer_detection || ctx.is_paused(pb_core::now_ts()) {
        return;
    }
    let Some(kind) = rules::exec_indicator(&target.path, args) else {
        return;
    };
    let ev = IndicatorEvent {
        kind,
        tool: Some(target.clone()),
        args: args.to_vec(),
        file: None,
        start_pid: parent.map(|p| p.ppid).unwrap_or(target.ppid),
        parent_image: parent.cloned(),
    };
    let ctx = ctx.clone();
    tokio::spawn(async move { handle_indicator(&ctx, ev).await });
}

/// File activity (eslogger create / rename, FSEvents).
pub fn on_file(
    ctx: &Arc<Ctx>,
    path: &str,
    from: Option<&str>,
    source: FileEventSource,
    process: Option<&EsProcessInfo>,
) {
    let cfg = ctx.config();
    if ctx.is_paused(pb_core::now_ts()) {
        return;
    }
    // Stealer staging: a credential store copied out of its folder.
    if cfg.guard.stealer_detection && source != FileEventSource::FsEvents {
        if let Some(kind) = rules::file_indicator(Path::new(path)) {
            let ev = IndicatorEvent {
                kind,
                tool: process.cloned(),
                args: vec![],
                file: Some(path.to_string()),
                start_pid: process.map(|p| p.pid).unwrap_or(-1),
                parent_image: None,
            };
            let ctx2 = ctx.clone();
            tokio::spawn(async move { handle_indicator(&ctx2, ev).await });
        }
    }
    if !cfg.guard.ransomware_detection {
        return;
    }
    // Decoy touched (modified in place, renamed, renamed away).
    let canary = ctx
        .guard
        .is_canary(path)
        .or_else(|| from.and_then(|f| ctx.guard.is_canary(f)));
    if let Some(c) = canary {
        let ctx2 = ctx.clone();
        let culprit = process.cloned();
        tokio::spawn(async move { check_one_canary(&ctx2, &c, culprit).await });
        return;
    }
    // Mass encryption by one process.
    let Some(p) = process else { return };
    let suspicious = match (source, from) {
        (FileEventSource::EsRename, Some(f)) => ransomware::is_encryption_rename(f, path),
        (FileEventSource::EsCreate, _) => ransomware::is_encrypted_copy_name(path),
        _ => false,
    };
    if suspicious && ctx.guard.lock().burst.record(p.pid, Instant::now()) {
        let ctx2 = ctx.clone();
        let culprit = p.clone();
        let reason = format!(
            "{} renomme ou chiffre des fichiers en masse (dernier : {path}).",
            culprit.path
        );
        tokio::spawn(async move { ransomware_trip(&ctx2, reason, Some(culprit)).await });
    }
}

// ---------------------------------------------------------------------------------------------
// Stealer handling
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct IndicatorEvent {
    kind: IndicatorKind,
    /// The tool that ran (exec) or the process that created the file.
    tool: Option<EsProcessInfo>,
    args: Vec<String>,
    file: Option<String>,
    /// Where to start looking for the responsible non-Apple process.
    start_pid: i32,
    /// exec: the image before exec (signing facts of the actor when it forked itself).
    parent_image: Option<EsProcessInfo>,
}

/// The process held responsible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub pid: i32,
    pub path: String,
    pub team_id: Option<String>,
    pub signed: bool,
    pub adhoc: bool,
    pub apple: bool,
}

/// Walk up the process tree to the first non-Apple, non-terminal ancestor. `None` with `interactive = true`
/// when a terminal / editor / sshd is reached first (typed by a person).
fn find_actor_pid(
    start: i32,
    lookup: impl Fn(i32) -> Option<(String, Option<i32>)>,
) -> (Option<(i32, String)>, bool) {
    let mut pid = start;
    for _ in 0..8 {
        if pid <= 1 {
            break;
        }
        let Some((path, ppid)) = lookup(pid) else {
            break;
        };
        if rules::is_interactive_host(&path) {
            return (None, true);
        }
        if !rules::is_system_path(&path) {
            return (Some((pid, path)), false);
        }
        match ppid {
            Some(p) if p != pid => pid = p,
            _ => break,
        }
    }
    (None, false)
}

fn proc_lookup(pid: i32) -> Option<(String, Option<i32>)> {
    let path = crate::system::pid_path(pid)?;
    Some((
        path.to_string_lossy().into_owned(),
        crate::system::parent_pid(pid),
    ))
}

async fn resolve_actor(ctx: &Arc<Ctx>, ev: &IndicatorEvent) -> (Option<Actor>, bool) {
    // File creation by a non-Apple process: that process is the actor.
    if ev.file.is_some() {
        if let Some(p) = ev.tool.as_ref().filter(|p| {
            !p.is_platform_binary
                && !rules::is_system_path(&p.path)
                && !rules::is_interactive_host(&p.path)
        }) {
            return (Some(actor_from_es(p, p.pid)), false);
        }
    }
    let start = if ev.file.is_some() {
        ev.tool.as_ref().map(|p| p.ppid).unwrap_or(-1)
    } else {
        ev.start_pid
    };
    let (found, interactive) =
        tokio::task::spawn_blocking(move || find_actor_pid(start, proc_lookup))
            .await
            .unwrap_or((None, false));
    let Some((pid, path)) = found else {
        return (None, interactive);
    };
    // The pre-exec image of a self-forking actor carries its signing facts.
    if let Some(img) = ev.parent_image.as_ref().filter(|i| i.path == path) {
        return (Some(actor_from_es(img, pid)), false);
    }
    let engine = ctx.engine();
    let p2 = PathBuf::from(&path);
    let signing = tokio::task::spawn_blocking(move || engine.signing_info(&p2))
        .await
        .ok()
        .flatten();
    let s = signing.unwrap_or_default();
    (
        Some(Actor {
            pid,
            path,
            team_id: s.team_id.clone(),
            signed: s.signed && s.valid,
            adhoc: s.adhoc,
            apple: s.apple,
        }),
        false,
    )
}

fn actor_from_es(p: &EsProcessInfo, pid: i32) -> Actor {
    Actor {
        pid,
        path: p.path.clone(),
        team_id: p.team_id.clone(),
        signed: p.codesigning_flags & 0x1 != 0,
        adhoc: p.codesigning_flags & ES_CS_ADHOC != 0,
        apple: p.is_platform_binary,
    }
}

/// May the guard kill this actor automatically? Unsigned / ad-hoc, non-Apple, not trusted.
pub fn actor_killable(a: &Actor, trusted: impl Fn(&str) -> bool) -> bool {
    if a.apple
        || a.pid <= 1
        || rules::is_system_path(&a.path)
        || rules::is_interactive_host(&a.path)
    {
        return false;
    }
    match a.team_id.as_deref() {
        Some(t) if trusted(t) => false,
        Some(_) if a.signed && !a.adhoc => false,
        _ => true,
    }
}

/// Arguments for display: bounded, secrets removed (`dscl -authonly <user> <password>`, curl headers / users).
pub fn summarize_args(args: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut redact_next = 0usize;
    for (i, a) in args.iter().enumerate() {
        if redact_next > 0 {
            redact_next -= 1;
            out.push("••••".into());
            continue;
        }
        let lower = a.to_ascii_lowercase();
        if lower == "-authonly" {
            out.push(a.clone());
            // user, then password
            if let Some(u) = args.get(i + 1) {
                out.push(u.clone());
            }
            out.push("••••".into());
            return finish(out);
        }
        if matches!(
            lower.as_str(),
            "-h" | "--header" | "-u" | "--user" | "--oauth2-bearer" | "-p" | "--password"
        ) {
            out.push(a.clone());
            redact_next = 1;
            continue;
        }
        out.push(a.clone());
    }
    finish(out)
}

fn finish(parts: Vec<String>) -> String {
    let s = parts.join(" ");
    if s.chars().count() > 400 {
        let cut: String = s.chars().take(400).collect();
        format!("{cut}…")
    } else {
        s
    }
}

fn is_trusted_team(ctx: &Ctx, team: &str) -> bool {
    ctx.config()
        .guard
        .trusted_team_ids
        .iter()
        .any(|t| t == team)
        || ctx.engine().is_trusted_team(team)
}

async fn handle_indicator(ctx: &Arc<Ctx>, ev: IndicatorEvent) {
    let cfg = ctx.config();
    let (actor, interactive) = resolve_actor(ctx, &ev).await;
    let actor_key = actor
        .as_ref()
        .map(|a| a.pid)
        .or(ev.tool.as_ref().map(|t| t.pid))
        .unwrap_or(-1);
    let corr = ctx
        .guard
        .lock()
        .correlator
        .record(actor_key, ev.kind, Instant::now());
    let Some(base) = ev
        .kind
        .base_severity()
        .or(corr.confirmed.then_some(Severity::High))
    else {
        tracing::info!(
            kind = ev.kind.id(),
            "guard: corroborating indicator recorded"
        );
        return;
    };
    let severity = if corr.confirmed {
        Severity::Critical
    } else {
        base
    };
    let mut done: Vec<String> = Vec::new();

    // 1. Kill the tool (fake dialog, keychain dump, confirmed exfiltration).
    let kill_tool = cfg.guard.kill_on_detection
        && (matches!(
            ev.kind,
            IndicatorKind::FakePasswordPrompt | IndicatorKind::KeychainDump
        ) || (ev.kind == IndicatorKind::Exfiltration && corr.confirmed));
    if kill_tool && ev.file.is_none() {
        if let Some(t) = &ev.tool {
            match crate::system::kill_if_path(t.pid, Path::new(&t.path)) {
                Ok(true) => done.push(format!("{} (pid {}) arrêté", short(&t.path), t.pid)),
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, "guard: cannot kill tool"),
            }
        }
    }
    // 2. Kill the actor when the evidence is strong and it is not a signed / trusted program.
    let mut actor_killed = false;
    if let Some(a) = &actor {
        let strong = corr.confirmed || severity >= Severity::Critical;
        if cfg.guard.kill_on_detection && strong && actor_killable(a, |t| is_trusted_team(ctx, t)) {
            match crate::system::kill_if_path(a.pid, Path::new(&a.path)) {
                Ok(true) => {
                    actor_killed = true;
                    done.push(format!("{} (pid {}) arrêté", short(&a.path), a.pid));
                }
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, "guard: cannot kill actor"),
            }
        }
    }
    // 3. Quarantine the actor's executable once confirmed.
    let mut quarantine_id = None;
    if let Some(a) = actor.as_ref().filter(|a| {
        actor_killed
            && corr.confirmed
            && cfg.realtime.auto_quarantine
            && !rules::is_interpreter(&a.path)
    }) {
        let det = Detection {
            engine: DetectionEngine::Heuristic,
            name: "MacOS.Behavior.Stealer".into(),
            severity: Severity::Critical,
            confidence: 0.9,
            details: Some(
                corr.kinds
                    .iter()
                    .map(|k| k.id())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
        };
        match actions::quarantine_path(ctx, Path::new(&a.path), None, &[det], "behavior").await {
            Ok(e) => {
                done.push("exécutable mis en quarantaine".into());
                quarantine_id = Some(e.id);
            }
            Err(e) => {
                tracing::warn!(error = %e.message, path = %a.path, "guard: quarantine failed")
            }
        }
    }

    let key = if corr.confirmed {
        format!("guard:stealer:{actor_key}")
    } else {
        format!("guard:{}:{actor_key}", ev.kind.id())
    };
    if !ctx.guard.should_alert(&key) && done.is_empty() {
        return;
    }
    let title = if corr.confirmed {
        "Voleur de données (stealer) détecté".to_string()
    } else {
        ev.kind.title().to_string()
    };
    let mut msg = ev.kind.explanation().to_string();
    if let Some(t) = &ev.tool {
        if ev.file.is_none() {
            msg.push_str(&format!("\nCommande : {}", summarize_args(&ev.args)));
        } else {
            msg.push_str(&format!("\nProcessus : {} (pid {})", t.path, t.pid));
        }
    }
    if let Some(f) = &ev.file {
        msg.push_str(&format!("\nFichier : {f}"));
    }
    match &actor {
        Some(a) => msg.push_str(&format!(
            "\nResponsable : {} (pid {}, {})",
            a.path,
            a.pid,
            match (&a.team_id, a.adhoc, a.signed) {
                (Some(t), false, true) => format!("signé, Team ID {t}"),
                (_, true, _) => "signature ad hoc".into(),
                _ => "non signé".into(),
            }
        )),
        None if interactive => msg.push_str("\nLancé depuis un terminal ou un éditeur."),
        None => {}
    }
    if corr.confirmed {
        let kinds: Vec<&str> = corr.kinds.iter().map(|k| k.title()).collect();
        msg.push_str(&format!(
            "\nComportements observés : {}.",
            kinds.join(" ; ")
        ));
    }
    if !done.is_empty() {
        msg.push_str(&format!("\nActions : {}.", done.join(", ")));
    }
    msg.push_str(
        "\nSi vous avez saisi votre mot de passe : changez-le, ainsi que ceux enregistrés dans le navigateur, \
         et déconnectez vos sessions (cookies volés).",
    );
    let mut alert = actions::alert(AlertKind::Behavior, severity, title, msg);
    if let Some(a) = &actor {
        alert.path = Some(a.path.clone());
        alert.process_pid = Some(a.pid);
        alert.process_path = Some(a.path.clone());
        alert.process_started_at = crate::system::process_identity(a.pid).map(|(_, start)| start);
        alert.quarantine_id = quarantine_id.clone();
        let interpreter = rules::is_interpreter(&a.path);
        alert.actions = if quarantine_id.is_some() {
            vec![AlertAction::Restore, AlertAction::Acknowledge]
        } else if actor_killed && interpreter {
            vec![AlertAction::Acknowledge]
        } else if actor_killed {
            vec![AlertAction::Quarantine, AlertAction::Acknowledge]
        } else if interpreter {
            vec![AlertAction::KillProcess, AlertAction::Acknowledge]
        } else {
            vec![
                AlertAction::KillProcess,
                AlertAction::Quarantine,
                AlertAction::Acknowledge,
            ]
        };
    }
    ctx.bump_stat(crate::store::StatField::Threats, 1).await;
    actions::raise_alert(ctx, alert, Some(key)).await;
}

fn short(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// ---------------------------------------------------------------------------------------------
// Ransomware
// ---------------------------------------------------------------------------------------------

/// Ransomware evidence: suspend the culprit (or recent untrusted processes) and alert.
async fn ransomware_trip(ctx: &Arc<Ctx>, reason: String, culprit: Option<EsProcessInfo>) {
    let cfg = ctx.config();
    if !ctx.guard.should_alert("guard:ransomware") {
        return;
    }
    let mut suspects: Vec<Actor> = Vec::new();
    if let Some(p) = &culprit {
        if !p.is_platform_binary && !rules::is_system_path(&p.path) {
            suspects.push(actor_from_es(p, p.pid));
        } else {
            let ev = IndicatorEvent {
                kind: IndicatorKind::FileEncryption,
                tool: Some(p.clone()),
                args: vec![],
                file: None,
                start_pid: p.ppid,
                parent_image: None,
            };
            if let (Some(a), _) = resolve_actor(ctx, &ev).await {
                suspects.push(a);
            }
        }
    }
    if suspects.is_empty() {
        // No attribution (FSEvents): untrusted programs of the console user started in the last 30 minutes and
        // still running. Never other users' or root's processes: the decoys are user-writable, so anyone able
        // to touch them must not be able to make root freeze system services.
        let console_uid = crate::system::console_user().map(|u| u.uid);
        let recent: Vec<RecentExec> = ctx.guard.lock().recent.iter().cloned().collect();
        let mut seen = std::collections::HashSet::new();
        for r in recent.iter().rev() {
            if r.at.elapsed() > Duration::from_secs(1800) || !seen.insert(r.pid) {
                continue;
            }
            let alive = crate::system::pid_path(r.pid)
                .map(|p| p.to_string_lossy() == r.path)
                .unwrap_or(false);
            if !alive {
                continue;
            }
            match crate::system::process_identity(r.pid) {
                Some((uid, _)) if uid != 0 && Some(uid) == console_uid => {}
                _ => continue,
            }
            let a = Actor {
                pid: r.pid,
                path: r.path.clone(),
                team_id: r.team_id.clone(),
                signed: r.team_id.is_some() && !r.adhoc,
                adhoc: r.adhoc,
                apple: false,
            };
            if actor_killable(&a, |t| is_trusted_team(ctx, t)) {
                suspects.push(a);
            }
            if suspects.len() >= 5 {
                break;
            }
        }
    }
    if suspects.is_empty() {
        let msg = format!(
            "{reason}\nAucun programme suspect n'a pu être identifié. Fermez les applications inconnues, débranchez \
             les disques externes et restaurez vos fichiers depuis un instantané (Parabellum > Protection)."
        );
        let a = actions::alert(
            AlertKind::Behavior,
            Severity::Critical,
            "Activité de rançongiciel détectée",
            msg,
        );
        actions::raise_alert(ctx, a, Some("guard:ransomware".into())).await;
        return;
    }
    for s in suspects {
        let mut suspended = false;
        let started_at = crate::system::process_identity(s.pid).map(|(_, start)| start);
        if cfg.guard.suspend_ransomware {
            match crate::system::signal_if_path(s.pid, Path::new(&s.path), libc::SIGSTOP) {
                Ok(true) => {
                    suspended = true;
                    ctx.guard.lock().suspended.push(SuspendedProcess {
                        pid: s.pid,
                        path: s.path.clone(),
                        since: pb_core::now_ts(),
                        alert_id: None,
                    });
                }
                Ok(false) => {}
                Err(e) => tracing::warn!(error = %e, pid = s.pid, "guard: cannot suspend"),
            }
        }
        let title = if suspended {
            "Rançongiciel probable : processus suspendu"
        } else {
            "Rançongiciel probable"
        };
        let msg = format!(
            "{reason}\nProcessus : {} (pid {}).{}\nTuez-le s'il ne s'agit pas d'un programme que vous utilisez, puis \
             restaurez les fichiers touchés depuis un instantané.",
            s.path,
            s.pid,
            if suspended {
                " Il est suspendu (aucun fichier n'est plus modifié) en attendant votre décision."
            } else {
                ""
            }
        );
        let mut a = actions::alert(AlertKind::Behavior, Severity::Critical, title, msg);
        a.path = Some(s.path.clone());
        a.process_pid = Some(s.pid);
        a.process_path = Some(s.path.clone());
        a.process_started_at = started_at;
        a.actions = if suspended {
            vec![
                AlertAction::KillProcess,
                AlertAction::ResumeProcess,
                AlertAction::Quarantine,
            ]
        } else {
            vec![
                AlertAction::KillProcess,
                AlertAction::Quarantine,
                AlertAction::Acknowledge,
            ]
        };
        if rules::is_interpreter(&s.path) {
            a.actions.retain(|x| *x != AlertAction::Quarantine);
        }
        if let Some(saved) =
            actions::raise_alert(ctx, a, Some(format!("guard:ransomware:{}", s.pid))).await
        {
            let mut g = ctx.guard.lock();
            if let Some(e) = g.suspended.iter_mut().find(|e| e.pid == s.pid) {
                e.alert_id = Some(saved.id);
            }
        }
    }
    ctx.bump_stat(crate::store::StatField::Threats, 1).await;
}

/// Kill or resume a process named in an alert (`kill_process` / `resume_process` actions): only if the pid
/// still designates the very process of the alert (same start time and executable).
pub fn act_on_process(
    ctx: &Ctx,
    pid: i32,
    path: &str,
    started_at: i64,
    resume: bool,
) -> Result<bool, String> {
    let signal = if resume { libc::SIGCONT } else { libc::SIGKILL };
    let r = crate::system::signal_if_same_process(pid, Path::new(path), started_at, signal);
    if r.is_ok() {
        ctx.guard.remove_suspended(pid);
    }
    r
}

// ---------------------------------------------------------------------------------------------
// Canaries
// ---------------------------------------------------------------------------------------------

fn hash_file(path: &Path) -> Option<(u64, String)> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() {
        // Replaced by a symlink / directory: report as a different content.
        return Some((u64::MAX, String::new()));
    }
    // O_NONBLOCK: a decoy swapped for a FIFO between the check above and the open must not block root
    // forever (that would silently stop the decoy checks and snapshots).
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    if !f.metadata().map(|m| m.is_file()).unwrap_or(false) {
        return Some((u64::MAX, String::new()));
    }
    let mut h = Sha256::new();
    let mut buf = [0u8; 16 * 1024];
    let mut total = 0u64;
    let mut r = f.take(4 * 1024 * 1024);
    loop {
        let n = r.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        total += n as u64;
        h.update(&buf[..n]);
    }
    Some((total, hex::encode(h.finalize())))
}

fn siblings(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .take(10_000)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

async fn check_one_canary(ctx: &Arc<Ctx>, path: &Path, culprit: Option<EsProcessInfo>) {
    let Some(c) = ctx
        .guard
        .lock()
        .canaries
        .iter()
        .find(|c| c.path == path)
        .cloned()
    else {
        return;
    };
    let c2 = c.clone();
    let state = tokio::task::spawn_blocking(move || {
        let cur = hash_file(&c2.path);
        let sib = c2.path.parent().map(siblings).unwrap_or_default();
        ransomware::evaluate_canary(&c2, cur, &sib)
    })
    .await
    .unwrap_or(CanaryState::Intact);
    match state {
        CanaryState::Intact => {}
        CanaryState::Missing => {
            tracing::info!(path = %c.path.display(), "decoy file missing; it will be recreated");
            ctx.guard.lock().canaries.retain(|x| x.path != c.path);
        }
        CanaryState::Modified | CanaryState::Renamed(_) => {
            {
                let mut g = ctx.guard.lock();
                let now = Instant::now();
                if g.tripped_canaries
                    .get(&c.path)
                    .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(600))
                {
                    return;
                }
                g.tripped_canaries.insert(c.path.clone(), now);
                g.canaries.retain(|x| x.path != c.path);
            }
            let what = match &state {
                CanaryState::Renamed(to) => format!("renommé en {}", to.display()),
                _ => "chiffré ou modifié".into(),
            };
            let reason = format!(
                "Un fichier leurre de Parabellum ({}) a été {what} : un programme est en train de chiffrer vos \
                 documents.",
                c.path.display()
            );
            ransomware_trip(ctx, reason, culprit).await;
        }
    }
}

/// Create the missing decoys (as the console user) and drop those of other folders / users.
async fn ensure_canaries(ctx: &Arc<Ctx>) {
    let Some(user) = crate::system::console_user() else {
        return;
    };
    if user.uid == 0 {
        return;
    }
    let Some(gid) = crate::system::user_gid(user.uid) else {
        return;
    };
    let mut changed = false;
    for dir in CANARY_DIRS {
        let d = user.home.join(dir);
        if !std::fs::symlink_metadata(&d)
            .map(|m| m.is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        for name in ransomware::CANARY_NAMES {
            let p = d.join(name);
            if ctx.guard.lock().canaries.iter().any(|c| c.path == p) {
                continue;
            }
            let content = ransomware::canary_content(&p);
            if std::fs::symlink_metadata(&p).is_err()
                && !write_as_user(&p, &content, user.uid, gid).await
            {
                continue;
            }
            // Adopt an existing decoy only if it is ours (same content).
            let p2 = p.clone();
            let cur = tokio::task::spawn_blocking(move || hash_file(&p2))
                .await
                .ok()
                .flatten();
            use sha2::{Digest, Sha256};
            let expected = hex::encode(Sha256::digest(&content));
            if cur.as_ref().map(|(_, h)| h == &expected).unwrap_or(false) {
                ctx.guard.lock().canaries.push(Canary {
                    path: p,
                    sha256: expected,
                    size: content.len() as u64,
                });
                changed = true;
            }
        }
    }
    {
        let mut g = ctx.guard.lock();
        let before = g.canaries.len();
        g.canaries.retain(|c| c.path.starts_with(&user.home));
        changed |= before != g.canaries.len();
    }
    if changed {
        save_canaries(ctx).await;
    }
}

/// Write a decoy as the user (`set -C` refuses to follow or clobber anything), then hide it in Finder.
async fn write_as_user(path: &Path, content: &[u8], uid: u32, gid: u32) -> bool {
    use tokio::io::AsyncWriteExt;
    let mut cmd = tokio::process::Command::new("/bin/sh");
    cmd.args([
        "-c",
        "set -C; umask 022; /bin/cat > \"$1\" && /usr/bin/chflags hidden \"$1\"",
        "sh",
    ])
    .arg(path)
    .env_clear()
    .env("PATH", "/usr/bin:/bin")
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .kill_on_drop(true)
    .uid(uid)
    .gid(gid);
    let Ok(mut child) = cmd.spawn() else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(content).await.is_err() {
            let _ = child.kill().await;
            return false;
        }
    }
    matches!(
        tokio::time::timeout(Duration::from_secs(10), child.wait()).await,
        Ok(Ok(s)) if s.success()
    )
}

/// Remove our decoys (ransomware detection turned off), as the user.
async fn remove_canaries(ctx: &Arc<Ctx>) {
    let list: Vec<Canary> = std::mem::take(&mut ctx.guard.lock().canaries);
    if list.is_empty() {
        return;
    }
    if let Some(user) = crate::system::console_user().filter(|u| u.uid != 0) {
        if let Some(gid) = crate::system::user_gid(user.uid) {
            for c in &list {
                let mut cmd = tokio::process::Command::new("/bin/rm");
                cmd.arg("-f")
                    .arg(&c.path)
                    .env_clear()
                    .uid(user.uid)
                    .gid(gid)
                    .kill_on_drop(true);
                let _ = tokio::time::timeout(Duration::from_secs(10), cmd.status()).await;
            }
        }
    }
    save_canaries(ctx).await;
}

async fn save_canaries(ctx: &Arc<Ctx>) {
    let json = serde_json::to_string(&ctx.guard.lock().canaries).unwrap_or_else(|_| "[]".into());
    if let Err(e) = ctx.store.run(move |s| s.kv_set(KV_CANARIES, &json)).await {
        tracing::warn!(error = %e, "cannot save the decoy registry");
    }
}

async fn load_canaries(ctx: &Arc<Ctx>) {
    let list: Vec<Canary> = ctx
        .store
        .run(|s| s.kv_get(KV_CANARIES))
        .await
        .ok()
        .flatten()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    ctx.guard.lock().canaries = list;
}

// ---------------------------------------------------------------------------------------------
// Background loop, status
// ---------------------------------------------------------------------------------------------

/// Decoys (create / check every 15 s) and periodic snapshots. macOS only.
pub async fn run(ctx: Arc<Ctx>) {
    if !cfg!(target_os = "macos") {
        return;
    }
    load_canaries(&ctx).await;
    let mut shutdown = ctx.shutdown_rx();
    let mut next_snapshot = tokio::time::Instant::now() + Duration::from_secs(300);
    let mut tick = tokio::time::interval(CANARY_CHECK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => if *shutdown.borrow() { return; },
        }
        let cfg = ctx.config();
        if cfg.guard.ransomware_detection {
            ensure_canaries(&ctx).await;
            let paths: Vec<PathBuf> = ctx
                .guard
                .lock()
                .canaries
                .iter()
                .map(|c| c.path.clone())
                .collect();
            for p in paths {
                check_one_canary(&ctx, &p, None).await;
            }
        } else {
            remove_canaries(&ctx).await;
        }
        if cfg.guard.snapshots && tokio::time::Instant::now() >= next_snapshot {
            next_snapshot = tokio::time::Instant::now()
                + Duration::from_secs(u64::from(cfg.guard.snapshot_interval_minutes.max(15)) * 60);
            match snapshots::create(&ctx).await {
                Ok(s) => {
                    let mut g = ctx.guard.lock();
                    g.last_snapshot = s.created_at.or(Some(pb_core::now_ts()));
                    g.snapshot_error = None;
                }
                Err(e) => {
                    tracing::warn!(error = %e.message, "APFS snapshot failed");
                    let first = ctx
                        .guard
                        .lock()
                        .snapshot_error
                        .replace(e.message.clone())
                        .is_none();
                    if first && ctx.guard.should_alert("guard:snapshot-error") {
                        let a = actions::alert(
                            AlertKind::System,
                            Severity::Low,
                            "Instantanés APFS indisponibles",
                            format!(
                                "Parabellum ne peut pas créer d'instantané local : {}. Activez Time Machine \
                                 (Réglages Système > Général > Time Machine) pour disposer de points de restauration.",
                                e.message
                            ),
                        );
                        actions::raise_alert(&ctx, a, Some("guard:snapshot-error".into())).await;
                    }
                }
            }
        }
    }
}

/// `guard_status` command.
pub async fn status(ctx: &Arc<Ctx>) -> GuardStatus {
    let cfg = ctx.config();
    let now = pb_core::now_ts();
    let detections_7d = ctx
        .store
        .run(move |s| s.count_alerts(AlertKind::Behavior, now - 7 * 86_400, now + 1))
        .await
        .unwrap_or(0);
    let g = ctx.guard.lock();
    GuardStatus {
        stealer_detection: cfg.guard.stealer_detection,
        ransomware_detection: cfg.guard.ransomware_detection,
        canaries: g
            .canaries
            .iter()
            .map(|c| c.path.to_string_lossy().into_owned())
            .collect(),
        snapshots_enabled: cfg.guard.snapshots,
        last_snapshot: g.last_snapshot,
        snapshot_error: g.snapshot_error.clone(),
        suspended: g.suspended.clone(),
        detections_7d,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_walk() {
        // 300 osascript <- 200 sh <- 100 payload <- 1 launchd
        let tree = |pid: i32| -> Option<(String, Option<i32>)> {
            match pid {
                200 => Some(("/bin/sh".into(), Some(100))),
                100 => Some(("/private/tmp/.hidden/payload".into(), Some(1))),
                150 => Some(("/bin/zsh".into(), Some(120))),
                120 => Some((
                    "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal".into(),
                    Some(1),
                )),
                _ => None,
            }
        };
        assert_eq!(
            find_actor_pid(200, tree),
            (Some((100, "/private/tmp/.hidden/payload".into())), false)
        );
        assert_eq!(find_actor_pid(150, tree), (None, true));
        assert_eq!(find_actor_pid(1, tree), (None, false));
    }

    #[test]
    fn killable() {
        let a = Actor {
            pid: 100,
            path: "/private/tmp/payload".into(),
            team_id: None,
            signed: false,
            adhoc: true,
            apple: false,
        };
        assert!(actor_killable(&a, |_| false));
        let signed = Actor {
            team_id: Some("ABCDE12345".into()),
            signed: true,
            adhoc: false,
            ..a.clone()
        };
        assert!(!actor_killable(&signed, |_| false));
        let revoked_adhoc_team = Actor {
            team_id: Some("ABCDE12345".into()),
            signed: false,
            adhoc: false,
            ..a.clone()
        };
        assert!(actor_killable(&revoked_adhoc_team, |_| false));
        assert!(!actor_killable(&revoked_adhoc_team, |t| t == "ABCDE12345"));
        let sys = Actor {
            path: "/usr/bin/python3".into(),
            ..a.clone()
        };
        assert!(!actor_killable(&sys, |_| false));
        let init = Actor { pid: 1, ..a };
        assert!(!actor_killable(&init, |_| false));
    }

    #[test]
    fn args_are_redacted() {
        let v = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let s = summarize_args(&v(&["dscl", "/Local/Default", "-authonly", "q", "hunter2"]));
        assert!(!s.contains("hunter2") && s.contains("q ••••"), "{s}");
        let s = summarize_args(&v(&[
            "curl",
            "-H",
            "Authorization: Bearer abc",
            "-F",
            "f=@/tmp/a.zip",
            "https://x",
        ]));
        assert!(!s.contains("Bearer") && s.contains("f=@/tmp/a.zip"), "{s}");
        let long = "x".repeat(1000);
        assert!(summarize_args(&v(&["a", &long])).chars().count() <= 401);
    }
}
