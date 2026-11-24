//! Daemon lifecycle: start every task, graceful shutdown.

use crate::backends::{Backends, MonitorContext};
use crate::ctx::Ctx;
use crate::ipc::AccessPolicy;
use crate::store::Store;
use crate::{actions, baseline, ipc, jobs, realtime, router, scheduler, setup, status};
use pb_core::events::MonitorEvent;
use pb_core::model::*;
use pb_core::paths::Paths;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Capacity of the monitor → daemon event channel.
pub const MONITOR_CHANNEL: usize = 4096;
/// Max time given to tasks to stop.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How to start.
pub struct DaemonOptions {
    pub paths: Paths,
    /// Unprivileged development instance.
    pub dev_mode: bool,
    pub backends: Backends,
    /// Start pb-monitor watchers (off in tests: events are injected with [`Daemon::monitor_sender`]).
    pub start_monitors: bool,
    /// Start scheduled work (updates, battery polling, component bootstrap, DNS stats).
    pub start_scheduler: bool,
    /// Override the access policy (tests); default: [`AccessPolicy::for_mode`]`(dev_mode)`.
    pub access: Option<AccessPolicy>,
}

/// kv: version of the daemon that ran last (detects updates).
pub const KV_LAST_VERSION: &str = "daemon_version";
/// Set when the daemon restarts itself after an internal task panicked (`<unix ts> <message>`): the next
/// start raises an alert, then clears it.
pub const KV_CRASH_NOTE: &str = "daemon_crash_note";
/// How often [`Daemon::supervise`] looks at the background tasks.
const SUPERVISE_EVERY: Duration = Duration::from_secs(5);

/// A running daemon.
pub struct Daemon {
    ctx: Arc<Ctx>,
    monitor_tx: mpsc::Sender<MonitorEvent>,
    server: JoinHandle<()>,
    tasks: Vec<JoinHandle<()>>,
}

/// Start the daemon (directories, config, store, engine, IPC server, tasks).
pub async fn start(opts: DaemonOptions) -> anyhow::Result<Daemon> {
    let as_root = !opts.dev_mode && crate::system::is_root();
    setup::prepare_dirs(&opts.paths, as_root)?;
    // The caller holds the instance lock (main acquires it first).
    setup::wipe_tmp(&opts.paths)?;
    let loaded = setup::load_config(&opts.paths);
    let store = Store::open(&opts.paths.state_db())?;
    let now = pb_core::now_ts();
    let interrupted = store.fail_interrupted_jobs(now)?;
    if interrupted > 0 {
        tracing::warn!(
            interrupted,
            "scan jobs interrupted by the previous shutdown"
        );
    }
    if store.kv_get(scheduler::KV_FIRST_RUN)?.is_none() {
        store.kv_set(scheduler::KV_FIRST_RUN, &now.to_string())?;
    }
    let paused = store
        .kv_get_i64(router::KV_PAUSED_UNTIL)?
        .filter(|t| *t > now);

    let last_version = store.kv_get(KV_LAST_VERSION)?;
    store.kv_set(KV_LAST_VERSION, pb_core::VERSION)?;
    let mut c = Ctx::new(
        opts.paths.clone(),
        opts.dev_mode,
        store,
        opts.backends,
        loaded.config.clone(),
    );
    if let Some(a) = opts.access {
        c.access = a;
    }
    let ctx = Arc::new(c);
    if as_root {
        match tokio::task::spawn_blocking(crate::auth::register_admin_right).await {
            Ok(Ok(true)) => tracing::info!(
                right = pb_core::ipc::ADMIN_RIGHT,
                "authorization right registered"
            ),
            Ok(Ok(false)) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "cannot register the authorization right"),
            Err(e) => tracing::error!(error = %e, "authorization right task failed"),
        }
    }
    {
        let mut st = ctx.state();
        st.paused_until = paused;
        st.config_error = loaded.fallback_error.clone();
    }
    if let Some(until) = paused {
        router::schedule_resume_notice(ctx.clone(), until);
    }
    report_previous_crash(&ctx).await;
    if let Some(err) = loaded.fallback_error {
        let a = actions::alert(
            AlertKind::System,
            Severity::High,
            "Configuration invalide",
            err,
        );
        actions::raise_alert(&ctx, a, None).await;
    }
    let upd = ctx.backends.updater.clone();
    if let Ok(Some(msg)) = tokio::task::spawn_blocking(move || upd.startup_housekeeping()).await {
        tracing::info!(%msg, "self-update finished");
    }
    if !scheduler::reload_engine(&ctx).await {
        tracing::warn!("running without a scanning engine (no threat DB yet?)");
    }
    if last_version
        .as_deref()
        .is_some_and(|v| v != pb_core::VERSION)
    {
        let m = ctx.backends.monitors.clone();
        let fda = tokio::task::spawn_blocking(move || m.has_full_disk_access())
            .await
            .unwrap_or(false);
        if !fda {
            let a = actions::alert(
                AlertKind::System,
                Severity::High,
                "Ré-accorder l'accès complet au disque à parabellumd après la mise à jour",
                format!(
                    "Parabellum est passé de la version {} à {} : macOS a retiré l'accès complet au disque. \
                     Réglages Système > Confidentialité et sécurité > Accès complet au disque : réactivez parabellumd.",
                    last_version.as_deref().unwrap_or("?"),
                    pb_core::VERSION
                ),
            );
            actions::raise_alert(&ctx, a, None).await;
        }
    }

    let listener = ipc::bind(&ctx.paths, ctx.dev_mode)?;
    tracing::info!(socket = %ctx.paths.socket.display(), version = pb_core::VERSION, "parabellumd listening");
    let server = tokio::spawn(ipc::serve(ctx.clone(), listener));

    let mut tasks = vec![
        tokio::spawn(jobs::run_jobs(ctx.clone())),
        tokio::spawn(status::run(ctx.clone())),
    ];
    baseline::init(&ctx, baseline::Kind::Persistence).await;
    baseline::init(&ctx, baseline::Kind::Devices).await;

    let (monitor_tx, monitor_rx) = mpsc::channel(MONITOR_CHANNEL);
    tasks.push(tokio::spawn(realtime::run_dispatcher(
        ctx.clone(),
        monitor_rx,
    )));
    if opts.start_monitors {
        let snapshot = ctx
            .store
            .run(|s| s.list_persistence(false))
            .await
            .unwrap_or_default();
        let devices = ctx
            .store
            .run(|s| s.list_devices(None))
            .await
            .unwrap_or_default();
        let mctx = MonitorContext {
            paths: ctx.paths.clone(),
            events: monitor_tx.clone(),
            config: ctx.config_rx(),
            shutdown: ctx.shutdown_rx(),
            persistence_snapshot: snapshot
                .into_iter()
                .filter(|p| p.status != PersistenceStatus::Removed)
                .collect(),
            known_devices: devices,
            console_home: ctx.console_home(),
        };
        tasks.extend(ctx.backends.monitors.start(mctx));
    }

    // VPN / kill switch / network guard and privacy services (their system work is macOS-only).
    tasks.push(crate::vpn::start(&ctx).await);
    tasks.push(crate::privacy::start(&ctx));
    if opts.start_monitors {
        tasks.push(tokio::spawn(crate::guard::run(ctx.clone())));
    }
    // Intelligence: before the DNS supervisor (the query tap must exist when the proxy starts).
    tasks.extend(crate::intel::start(&ctx));
    tasks.push(tokio::spawn(dns_startup(ctx.clone())));
    if let Some(h) = ctx
        .backends
        .dns
        .start_supervisor(ctx.config_rx(), ctx.shutdown_rx())
    {
        tasks.push(h);
    }
    if opts.start_scheduler {
        tasks.push(tokio::spawn(scheduler::run(ctx.clone())));
        tasks.push(tokio::spawn(scheduler::battery_loop(ctx.clone())));
        tasks.push(tokio::spawn(scheduler::bootstrap_components(ctx.clone())));
        tasks.push(tokio::spawn(scheduler::dns_stats_loop(ctx.clone())));
        tasks.push(tokio::spawn(crate::spyware::schedule_loop(ctx.clone())));
        tasks.push(tokio::spawn(crate::fullscan::schedule_loop(ctx.clone())));
        tasks.push(tokio::spawn(crate::posture::daily_loop(ctx.clone())));
        // Our own files against the installer's manifest (tripwire on the root folder).
        tasks.push(tokio::spawn(crate::own::integrity_loop(ctx.clone())));
        // speed: first posture answer ready before the app asks.
        tasks.push(tokio::spawn(crate::posture::warm_up(ctx.clone())));
        // ----- Local network & permissions audit -----
        tasks.push(tokio::spawn(crate::lan::run_loop(ctx.clone())));
        tasks.push(tokio::spawn(crate::permissions::periodic_loop(ctx.clone())));
        // GDPR mail agent (idle-time, local model).
        tasks.push(tokio::spawn(crate::mailagent::run_loop(ctx.clone())));
        // Activity report: VPN uptime / leak test sampling, monthly announcement.
        tasks.push(tokio::spawn(crate::report::monthly_loop(ctx.clone())));
        // Daily report on the Mac's situation (+ local AI summary when idle on mains power).
        tasks.push(tokio::spawn(crate::daily::run_loop(ctx.clone())));
    }
    let c2 = ctx.clone();
    tokio::spawn(async move {
        if let Err(e) = c2.store.run(|s| s.prune(pb_core::now_ts())).await {
            tracing::warn!(error = %e, "store pruning failed");
        }
    });
    Ok(Daemon {
        ctx,
        monitor_tx,
        server,
        tasks,
    })
}

/// Prepare DNS blocking files if enabled. Never applies the system DNS itself: the supervisor does, once its
/// own proxy answers (and recovers from a crashed run).
async fn dns_startup(ctx: Arc<Ctx>) {
    ctx.backends.dns.recover_on_startup().await;
    let cfg = ctx.config();
    if cfg.dns.enabled {
        match ctx.backends.dns.enable(&cfg).await {
            Ok(st) => tracing::info!(
                domains = st.blocked_domains,
                "DNS blocking prepared (supervisor applies it)"
            ),
            Err(e) => tracing::warn!(error = %e, "DNS blocking not prepared"),
        }
        ctx.status_dirty.notify_one();
    }
}

impl Daemon {
    pub fn ctx(&self) -> &Arc<Ctx> {
        &self.ctx
    }

    /// Watch one more background task (tests, extra producers).
    pub fn adopt_task(&mut self, task: JoinHandle<()>) {
        self.tasks.push(task);
    }

    /// Returns only when a background task (real-time dispatcher, monitors, jobs, IPC server…) has
    /// panicked, with the panic message. Before, the task just vanished: the daemon kept answering
    /// « protection active » with a dead watcher. The caller shuts down cleanly and exits non-zero so
    /// launchd (`KeepAlive`) starts a fresh daemon, which raises an alert about it ([`KV_CRASH_NOTE`]).
    /// Tasks that end normally (one-shot start-up work) are simply dropped from the watch.
    pub async fn supervise(&mut self) -> String {
        loop {
            tokio::time::sleep(SUPERVISE_EVERY).await;
            if self.server.is_finished() {
                let outcome = (&mut self.server).await;
                // Re-arm with a task that never ends so `shutdown` can still abort it.
                self.server = tokio::spawn(std::future::pending());
                if let Err(e) = outcome {
                    if e.is_panic() {
                        return format!("serveur IPC : {}", panic_message(e));
                    }
                }
            }
            let mut i = 0;
            while i < self.tasks.len() {
                if !self.tasks[i].is_finished() {
                    i += 1;
                    continue;
                }
                let handle = self.tasks.swap_remove(i);
                if let Err(e) = handle.await {
                    if e.is_panic() {
                        return panic_message(e);
                    }
                }
            }
        }
    }

    /// Inject monitor events (tests, or extra producers).
    pub fn monitor_sender(&self) -> mpsc::Sender<MonitorEvent> {
        self.monitor_tx.clone()
    }

    /// Stop watchers and tasks (≤ 5 s), restore system DNS (fail-open), flush the store, remove the socket.
    pub async fn shutdown(self) {
        tracing::info!("parabellumd stopping");
        let ctx = self.ctx;
        ctx.shutdown.send_replace(true);
        for j in ctx.jobs.active() {
            j.cancel();
        }
        self.server.abort();
        drop(self.monitor_tx);
        let tasks = self.tasks;
        let aborts: Vec<_> = tasks.iter().map(|t| t.abort_handle()).collect();
        if tokio::time::timeout(SHUTDOWN_GRACE, futures::future::join_all(tasks))
            .await
            .is_err()
        {
            tracing::warn!("some tasks did not stop in time, aborting them");
            for a in aborts {
                a.abort();
            }
        }
        if let Some(vpn) = ctx.vpn.get() {
            // Fail open: stop the tunnel and remove the kill switch.
            if tokio::time::timeout(Duration::from_secs(10), vpn.shutdown())
                .await
                .is_err()
            {
                tracing::error!("VPN shutdown timed out");
            }
        }
        match tokio::time::timeout(
            Duration::from_secs(10),
            ctx.backends.dns.restore_system_dns(),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::error!(error = %e, "cannot restore system DNS"),
            Err(_) => tracing::error!("restoring system DNS timed out"),
        }
        let store = ctx.store.clone();
        let _ = tokio::task::spawn_blocking(move || store.checkpoint()).await;
        let _ = std::fs::remove_file(&ctx.paths.socket);
        tracing::info!("parabellumd stopped");
    }
}

fn panic_message(e: tokio::task::JoinError) -> String {
    let payload = e.into_panic();
    let text = payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "panique sans message".to_string());
    text.chars().take(300).collect()
}

/// Called at start-up: alert about a self-restart recorded by the previous run.
pub(crate) async fn report_previous_crash(ctx: &Arc<Ctx>) {
    let Ok(Some(note)) = ctx.store.run(|s| s.kv_get(KV_CRASH_NOTE)).await else {
        return;
    };
    let _ = ctx.store.run(|s| s.kv_delete(KV_CRASH_NOTE)).await;
    let (ts, message) = note.split_once(' ').unwrap_or(("", note.as_str()));
    tracing::error!(
        at = ts,
        message,
        "previous run restarted after an internal error"
    );
    let alert = actions::alert(
        AlertKind::System,
        Severity::High,
        "Parabellum a redémarré après une erreur interne",
        format!(
            "Une tâche interne du service s'est arrêtée sur une erreur ({message}). Le service a été \
             redémarré automatiquement et la protection a repris. Si ce message revient, exporte le \
             journal (/Library/Logs/Parabellum) et signale-le."
        ),
    );
    actions::raise_alert(ctx, alert, None).await;
}
