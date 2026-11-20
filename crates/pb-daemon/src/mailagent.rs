//! Mail agent scheduling: runs [`pb_privacy::PrivacyService::agent_run`] when the Mac is idle (no keyboard
//! or mouse input for `mail_agent.idle_minutes`, on mains power if required), at most every
//! `interval_hours` unless asked (`mail_agent_run`).
//!
//! The local model server (Ollama, pinned and signature-checked by `pb-updater`) is started only when a
//! message actually needs a label — not for an empty mailbox — as the `nobody` account, on a random
//! loopback port, and stopped at the end of the run or as soon as you touch the Mac again. Afterwards the
//! Obsidian notes are refreshed by the installed CLI running **as the console user** (the daemon never
//! writes into a home folder).

use crate::ctx::Ctx;
use async_trait::async_trait;
use pb_core::config::Config;
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::{MailAgentState, MailAgentStatus};
use pb_privacy::agent::classify::{Classification, Classifier, ClassifyInput};
use pb_privacy::agent::ollama::Ollama;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// macOS `nobody`.
const NOBODY_UID: u32 = 0xFFFF_FFFE;
const IOREG: &str = "/usr/sbin/ioreg";
const PMSET: &str = "/usr/bin/pmset";
/// Once running: you are back if the idle time drops under this.
const ACTIVE_AGAIN: Duration = Duration::from_secs(60);

struct Runtime {
    state: MailAgentState,
    requested: bool,
}

static RUNTIME: Mutex<Runtime> = Mutex::new(Runtime {
    state: MailAgentState::Disabled,
    requested: false,
});

fn rt() -> std::sync::MutexGuard<'static, Runtime> {
    RUNTIME.lock().unwrap_or_else(|e| e.into_inner())
}

fn kick() -> &'static tokio::sync::Notify {
    static N: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

fn active(cfg: &Config) -> bool {
    cfg.mail_agent.enabled && cfg.data_removal.enabled
}

/// `mail_agent_status`.
pub async fn status(ctx: &Arc<Ctx>) -> Result<MailAgentStatus, IpcError> {
    let cfg = ctx.config();
    let state = if active(&cfg) {
        rt().state
    } else {
        MailAgentState::Disabled
    };
    let base = MailAgentStatus {
        state,
        model: cfg.mail_agent.model.clone(),
        ollama_installed: pb_updater::ollama_binary(&ctx.paths).is_file(),
        ollama_version: pb_updater::ollama_installed_version(&ctx.paths),
        ..Default::default()
    };
    Ok(crate::privacy::service(ctx)?.agent_status(base).await)
}

/// `mail_agent_run`: run at the next idle moment, without waiting for the interval.
pub async fn request_run(ctx: &Arc<Ctx>) -> Result<MailAgentStatus, IpcError> {
    if !active(&ctx.config()) {
        return Err(IpcError::new(
            ErrorCode::BadRequest,
            "agent courrier désactivé (Réglages › Effacement : activer l'effacement et l'agent)",
        ));
    }
    rt().requested = true;
    kick().notify_one();
    status(ctx).await
}

// ----- idle & power ---------------------------------------------------------------------------------

/// Seconds since the last keyboard / mouse input (`HIDIdleTime`, ns). Non-macOS: always idle.
async fn idle_seconds() -> Option<u64> {
    if !cfg!(target_os = "macos") {
        return Some(u64::MAX);
    }
    let out = crate::system::run_command(
        IOREG,
        &["-c", "IOHIDSystem", "-d", "4", "-r", "-k", "HIDIdleTime"],
        Duration::from_secs(10),
    )
    .await
    .ok()?;
    parse_idle(&out.stdout)
}

pub fn parse_idle(out: &str) -> Option<u64> {
    out.lines()
        .find(|l| l.contains("\"HIDIdleTime\""))
        .and_then(|l| l.rsplit('=').next())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|ns| ns / 1_000_000_000)
}

async fn on_ac_power() -> bool {
    if !cfg!(target_os = "macos") {
        return true;
    }
    match crate::system::run_command(PMSET, &["-g", "ps"], Duration::from_secs(10)).await {
        Ok(o) => parse_ac(&o.stdout),
        Err(_) => false,
    }
}

pub fn parse_ac(out: &str) -> bool {
    out.lines().next().is_some_and(|l| l.contains("'AC Power'"))
}

async fn may_run(cfg: &Config) -> bool {
    let a = &cfg.mail_agent;
    let idle_ok = idle_seconds()
        .await
        .is_some_and(|s| s >= u64::from(a.idle_minutes) * 60);
    idle_ok && (!a.require_ac_power || on_ac_power().await)
}

// ----- loop -----------------------------------------------------------------------------------------

pub async fn run_loop(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    // First look a few minutes after start-up.
    let mut wait = Duration::from_secs(180);
    loop {
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = kick().notified() => {}
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { return; },
        }
        if ctx.is_shutting_down() {
            return;
        }
        wait = Duration::from_secs(60);
        let cfg = ctx.config();
        if !active(&cfg) {
            rt().state = MailAgentState::Disabled;
            continue;
        }
        {
            let mut r = rt();
            if r.state == MailAgentState::Disabled {
                r.state = MailAgentState::Waiting;
            }
        }
        let Ok(svc) = crate::privacy::service(&ctx) else {
            continue;
        };
        let last = svc
            .agent_status(MailAgentStatus::default())
            .await
            .last_run_at
            .unwrap_or(0);
        let due = rt().requested
            || pb_core::now_ts() - last >= i64::from(cfg.mail_agent.interval_hours) * 3600;
        if !due || !may_run(&cfg).await {
            continue;
        }
        rt().requested = false;
        rt().state = MailAgentState::Running;
        let ok = run_once(&ctx, &cfg).await;
        rt().state = if ok {
            MailAgentState::Waiting
        } else {
            MailAgentState::Error
        };
    }
}

/// One run; `false` on failure (recorded in the agent state).
async fn run_once(ctx: &Arc<Ctx>, cfg: &Arc<Config>) -> bool {
    let Ok(svc) = crate::privacy::service(ctx) else {
        return false;
    };
    let cancel = Arc::new(AtomicBool::new(false));
    // Stop as soon as you are back (or the daemon stops).
    let watcher = {
        let cancel = cancel.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let back = idle_seconds()
                    .await
                    .is_some_and(|s| s < ACTIVE_AGAIN.as_secs());
                if back || ctx.is_shutting_down() {
                    cancel.store(true, Ordering::SeqCst);
                    return;
                }
            }
        })
    };
    let model = LazyOllama::new(ctx.clone(), cfg.mail_agent.model.clone(), cancel.clone());
    let res = svc.agent_run(cfg, &model, &cancel).await;
    model.stop().await;
    watcher.abort();
    let ok = match res {
        Ok(r) => {
            tracing::info!(
                fetched = r.fetched,
                matched = r.matched,
                updated = r.updated,
                error = ?r.error,
                "mail agent run"
            );
            r.error.is_none()
        }
        Err(e) => {
            tracing::warn!(error = %e, "mail agent run failed");
            false
        }
    };
    if !cfg.mail_agent.notes_dir.is_empty() {
        write_notes().await;
    }
    ok
}

// ----- Ollama, started on first use ------------------------------------------------------------------

struct Server {
    child: tokio::process::Child,
    client: Ollama,
}

/// Starts (installing it if needed) the model server the first time a message needs a label.
struct LazyOllama {
    ctx: Arc<Ctx>,
    model: String,
    cancel: Arc<AtomicBool>,
    server: tokio::sync::Mutex<Option<Server>>,
    failed: Mutex<Option<String>>,
}

/// Last DB refresh asked for a missing Ollama pin (Unix seconds).
static LAST_PIN_REFRESH: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
const PIN_REFRESH_EVERY: i64 = 30 * 60;

/// The installed DB predates the Ollama pin (published the same night, after this Mac's daily check):
/// fetch the current DB now instead of failing until tomorrow. At most every 30 minutes.
async fn refresh_db_for_pin(ctx: &Arc<Ctx>) {
    let now = pb_core::now_ts();
    let last = LAST_PIN_REFRESH.load(Ordering::Relaxed);
    if now - last < PIN_REFRESH_EVERY
        || LAST_PIN_REFRESH
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
    {
        return;
    }
    tracing::info!("Ollama pin missing from the installed DB: checking for a newer DB");
    if let Err(e) = crate::scheduler::run_updates(ctx, pb_core::model::UpdateTarget::Db).await {
        tracing::warn!(error = %e.message, "DB refresh for the Ollama pin skipped");
    }
}

impl LazyOllama {
    fn new(ctx: Arc<Ctx>, model: String, cancel: Arc<AtomicBool>) -> Self {
        Self {
            ctx,
            model,
            cancel,
            server: tokio::sync::Mutex::new(None),
            failed: Mutex::new(None),
        }
    }

    async fn stop(&self) {
        if let Some(mut s) = self.server.lock().await.take() {
            let _ = s.child.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(10), s.child.wait()).await;
            tracing::info!("ollama stopped");
        }
    }

    async fn start(&self) -> Result<Server, String> {
        let paths = &self.ctx.paths;
        if pb_updater::read_ollama_pin(paths).is_none() {
            refresh_db_for_pin(&self.ctx).await;
        }
        pb_updater::install_ollama(paths)
            .await
            .map_err(|e| format!("installation d'Ollama : {e}"))?;
        let bin = pb_updater::ollama_binary(paths);
        let models = paths.components_dir().join("ollama-models");
        let ids = models_dir(&models)?;
        let port = free_port()?;
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(paths.log_file().with_file_name("ollama.log"))
            .map_err(|e| e.to_string())?;
        let mut cmd = tokio::process::Command::new(&bin);
        cmd.arg("serve")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &models)
            .env("OLLAMA_HOST", format!("127.0.0.1:{port}"))
            .env("OLLAMA_MODELS", &models)
            .env("OLLAMA_KEEP_ALIVE", "5m")
            .env("OLLAMA_NOHISTORY", "1")
            .current_dir(&models)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::from(log))
            .kill_on_drop(true);
        if let Some((uid, gid)) = ids {
            cmd.uid(uid).gid(gid);
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("lancement d'Ollama : {e}"))?;
        let client = Ollama::new(port, &self.model)?;
        let mut server = Server { child, client };
        let ready = async {
            server.client.wait_ready(Duration::from_secs(60)).await?;
            if !server.client.has_model().await? {
                tracing::info!(model = %self.model, "pulling the mail agent model");
                // Interrupted (and resumed next time: Ollama keeps the downloaded layers) if you come back.
                tokio::select! {
                    r = server.client.pull() => r?,
                    _ = until_cancelled(&self.cancel) => {
                        return Err("interrompu : le Mac est de nouveau utilisé".to_string())
                    }
                }
            }
            Ok::<(), String>(())
        };
        match ready.await {
            Ok(()) => Ok(server),
            Err(e) => {
                let _ = server.child.start_kill();
                Err(e)
            }
        }
    }
}

#[async_trait]
impl Classifier for LazyOllama {
    fn name(&self) -> String {
        self.model.clone()
    }

    async fn classify(&self, input: &ClassifyInput<'_>) -> Result<Classification, String> {
        if let Some(e) = self
            .failed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        {
            return Err(e);
        }
        if self.cancel.load(Ordering::SeqCst) {
            return Err("interrompu : le Mac est de nouveau utilisé".into());
        }
        let mut guard = self.server.lock().await;
        if guard.is_none() {
            match self.start().await {
                Ok(s) => *guard = Some(s),
                Err(e) => {
                    *self.failed.lock().unwrap_or_else(|e| e.into_inner()) = Some(e.clone());
                    return Err(e);
                }
            }
        }
        let client = guard
            .as_ref()
            .map(|s| s.client.clone())
            .ok_or("serveur absent")?;
        drop(guard);
        client.classify(input).await
    }
}

/// Models directory owned by `nobody` (0700) under the root-owned components directory. Returns the ids
/// to run the server as (`None` when the daemon is not root: development).
fn models_dir(dir: &std::path::Path) -> Result<Option<(u32, u32)>, String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    if !crate::system::is_root() {
        return Ok(None);
    }
    let gid = crate::system::user_gid(NOBODY_UID).unwrap_or(NOBODY_UID);
    let md = std::fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !md.is_dir() {
        return Err("dossier des modèles invalide".into());
    }
    if md.uid() != NOBODY_UID {
        std::os::unix::fs::lchown(dir, Some(NOBODY_UID), Some(gid)).map_err(|e| e.to_string())?;
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    Ok(Some((NOBODY_UID, gid)))
}

async fn until_cancelled(c: &AtomicBool) {
    while !c.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn free_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
    l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())
}

// ----- notes ----------------------------------------------------------------------------------------

/// `parabellum privacy notes` as the console user (installed CLI only).
async fn write_notes() {
    let cli = std::path::Path::new(crate::ipc::CLI_EXECUTABLE);
    if !cli.is_file() {
        return;
    }
    let Some(user) = crate::system::console_user() else {
        return;
    };
    let Some(gid) = crate::system::user_gid(user.uid) else {
        return;
    };
    let mut cmd = tokio::process::Command::new(cli);
    cmd.args(["privacy", "notes"])
        .env_clear()
        .env("HOME", &user.home)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "fr_FR.UTF-8")
        .current_dir(&user.home)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .uid(user.uid)
        .gid(gid);
    match tokio::time::timeout(Duration::from_secs(60), cmd.status()).await {
        Ok(Ok(s)) if s.success() => tracing::debug!("mail agent notes written"),
        Ok(Ok(s)) => tracing::warn!(code = ?s.code(), "mail agent notes failed"),
        Ok(Err(e)) => tracing::warn!(error = %e, "mail agent notes failed"),
        Err(_) => tracing::warn!("mail agent notes timed out"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_and_power_parsing() {
        let io = "+-o IOHIDSystem  <class IOHIDSystem>\n    {\n      \"HIDIdleTime\" = 742000000000\n    }\n";
        assert_eq!(parse_idle(io), Some(742));
        assert_eq!(parse_idle("nothing"), None);
        assert!(parse_ac(
            "Now drawing from 'AC Power'\n -InternalBattery-0 100%"
        ));
        assert!(!parse_ac("Now drawing from 'Battery Power'\n"));
    }
}
