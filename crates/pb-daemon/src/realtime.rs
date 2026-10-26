//! Real-time pipeline: consumes [`MonitorEvent`]s from pb-monitor.
//!
//! - `FileActivity` → per-path debounce (quiet 2 s, max delay 30 s) → single-file scan (no ClamAV unless
//!   `scan.clamav_realtime`, in which case clean files are batched into a `downloads` job with ClamAV).
//! - `ProcessExec` → skip platform / trusted binaries, cache by cdhash, scan the executable; a signature hit
//!   kills the process (if still the same image) before quarantine.
//! - `Persistence` / `Device` → ordered worker tasks ([`crate::persistence`], [`crate::devices`]).
//! - `MonitorHealth` → watcher flags in the status.

use crate::actions::{self, ExecInfo, ReportContext};
use crate::backends::ScanOpts;
use crate::ctx::Ctx;
use crate::jobs::{self, JobSpec};
use crate::store::StatField;
use crate::system::{QosGuard, ScanPriority};
use pb_core::events::{EsProcessInfo, MonitorEvent};
use pb_core::model::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// A path is scanned once no event arrived for this long…
pub const DEBOUNCE_QUIET: Duration = Duration::from_secs(2);
/// …or at the latest this long after its first event (a file being written for minutes).
pub const DEBOUNCE_MAX_DELAY: Duration = Duration::from_secs(30);
/// Paths tracked by the debouncer at once (beyond: the oldest are flushed immediately).
pub const DEBOUNCE_CAP: usize = 10_000;
/// Real-time scans waiting for a slot (beyond: dropped with a warning; FSEvents storms).
pub const MAX_PENDING_SCANS: usize = 20_000;
/// Downloads batch flushed after this delay or this many files.
pub const BATCH_DELAY: Duration = Duration::from_secs(60);
pub const BATCH_MAX: usize = 100;
/// Exec verdict cache size.
pub const EXEC_CACHE_MAX: usize = 4_096;

/// ES `codesigning_flags`.
pub const CS_VALID: u32 = 0x1;
pub const CS_ADHOC: u32 = 0x2;

/// Per-path debouncer (pure, time passed in).
#[derive(Debug)]
pub struct Debouncer {
    quiet: Duration,
    max_delay: Duration,
    cap: usize,
    entries: HashMap<PathBuf, (Instant, Instant)>,
}

impl Debouncer {
    pub fn new(quiet: Duration, max_delay: Duration, cap: usize) -> Self {
        Self {
            quiet,
            max_delay,
            cap: cap.max(1),
            entries: HashMap::new(),
        }
    }

    /// Record an event for `path`. Returns paths that must be flushed right away because of the cap.
    pub fn touch(&mut self, path: PathBuf, now: Instant) -> Vec<PathBuf> {
        let mut evicted = Vec::new();
        if !self.entries.contains_key(&path) && self.entries.len() >= self.cap {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (first, _))| *first)
                .map(|(p, _)| p.clone())
            {
                self.entries.remove(&oldest);
                evicted.push(oldest);
            }
        }
        self.entries
            .entry(path)
            .and_modify(|(_, last)| *last = now)
            .or_insert((now, now));
        evicted
    }

    fn due(&self, first: Instant, last: Instant) -> Instant {
        (last + self.quiet).min(first + self.max_delay)
    }

    /// Earliest instant at which some path becomes ready.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.entries.values().map(|(f, l)| self.due(*f, *l)).min()
    }

    /// Remove and return the paths ready at `now`.
    pub fn take_ready(&mut self, now: Instant) -> Vec<PathBuf> {
        let ready: Vec<PathBuf> = self
            .entries
            .iter()
            .filter(|(_, (f, l))| self.due(*f, *l) <= now)
            .map(|(p, _)| p.clone())
            .collect();
        for p in &ready {
            self.entries.remove(p);
        }
        ready
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// State shared by the dispatcher and the scan tasks it spawns.
#[derive(Default)]
pub struct RealtimeShared {
    exec_cache: Mutex<HashMap<String, (Verdict, u64, Instant)>>,
    batch: Mutex<Vec<PathBuf>>,
    pending: AtomicUsize,
}

impl RealtimeShared {
    fn exec_cached(&self, key: &str, generation: u64) -> Option<Verdict> {
        let g = self.exec_cache.lock().unwrap_or_else(|e| e.into_inner());
        g.get(key)
            .filter(|(_, gen, at)| *gen == generation && at.elapsed() < Duration::from_secs(86_400))
            .map(|v| v.0)
    }

    fn exec_remember(&self, key: String, verdict: Verdict, generation: u64) {
        let mut g = self.exec_cache.lock().unwrap_or_else(|e| e.into_inner());
        if g.len() >= EXEC_CACHE_MAX {
            g.retain(|_, (_, gen, at)| {
                *gen == generation && at.elapsed() < Duration::from_secs(3600)
            });
            if g.len() >= EXEC_CACHE_MAX {
                g.clear();
            }
        }
        g.insert(key, (verdict, generation, Instant::now()));
    }
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
        None => std::future::pending::<()>().await,
    }
}

/// Dispatcher task: runs until the monitor channel closes or shutdown.
pub async fn run_dispatcher(ctx: Arc<Ctx>, mut rx: mpsc::Receiver<MonitorEvent>) {
    let shared = Arc::new(RealtimeShared::default());
    let mut deb = Debouncer::new(DEBOUNCE_QUIET, DEBOUNCE_MAX_DELAY, DEBOUNCE_CAP);
    let mut shutdown = ctx.shutdown_rx();
    let (ptx, prx) = mpsc::channel(1024);
    let (dtx, drx) = mpsc::channel(1024);
    tokio::spawn(crate::persistence::run_worker(ctx.clone(), prx));
    tokio::spawn(crate::devices::run_worker(ctx.clone(), drx));
    loop {
        let deadline = deb.next_deadline();
        tokio::select! {
            ev = rx.recv() => match ev {
                None => break,
                Some(MonitorEvent::FileActivity { path, .. }) => {
                    let cfg = ctx.config();
                    if !cfg.realtime.enabled {
                        continue;
                    }
                    let p = PathBuf::from(path);
                    if !p.is_absolute() || ctx.is_excluded(&p, &cfg) {
                        continue;
                    }
                    for evicted in deb.touch(p, Instant::now()) {
                        spawn_file_scan(&ctx, &shared, evicted);
                    }
                }
                Some(MonitorEvent::ProcessExec { target, .. }) => {
                    let cfg = ctx.config();
                    if cfg.realtime.enabled && cfg.realtime.scan_on_exec && !target.is_platform_binary {
                        spawn_exec_scan(&ctx, &shared, target);
                    }
                }
                Some(MonitorEvent::Persistence { item, change }) => {
                    if ptx.send((item, change)).await.is_err() {
                        tracing::error!("persistence worker gone");
                    }
                }
                Some(MonitorEvent::Device(ev)) => {
                    if dtx.send(ev).await.is_err() {
                        tracing::error!("device worker gone");
                    }
                }
                Some(MonitorEvent::MonitorHealth { monitor, ok, message }) => {
                    apply_health(&ctx, &monitor, ok, &message);
                }
            },
            _ = sleep_until_opt(deadline) => {
                for p in deb.take_ready(Instant::now()) {
                    spawn_file_scan(&ctx, &shared, p);
                }
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    tracing::info!("real-time dispatcher stopped");
}

/// Update watcher flags from a `MonitorHealth` event.
pub fn apply_health(ctx: &Ctx, monitor: &str, ok: bool, message: &str) {
    if ok {
        tracing::info!(monitor, message, "monitor healthy");
    } else {
        tracing::warn!(monitor, message, "monitor unhealthy");
    }
    let name = monitor.to_ascii_lowercase();
    {
        let mut st = ctx.state();
        if name.contains("fsevent") {
            st.health.fsevents = ok;
        } else if name.contains("eslogger") || name.contains("endpoint") {
            st.health.eslogger = ok;
        } else if name.contains("persist") {
            st.health.persistence_monitor = ok;
        } else if name.contains("device") || name.contains("volume") {
            st.health.device_monitor = ok;
        }
    }
    ctx.status_dirty.notify_one();
}

fn spawn_file_scan(ctx: &Arc<Ctx>, shared: &Arc<RealtimeShared>, path: PathBuf) {
    if shared.pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_SCANS {
        shared.pending.fetch_sub(1, Ordering::SeqCst);
        tracing::warn!(path = %path.display(), "real-time backlog full, event dropped");
        return;
    }
    let (ctx, shared) = (ctx.clone(), shared.clone());
    tokio::spawn(async move {
        scan_file_realtime(&ctx, &shared, path).await;
        shared.pending.fetch_sub(1, Ordering::SeqCst);
    });
}

fn mtime_secs(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn scan_one(ctx: &Arc<Ctx>, path: &Path) -> Option<ScanReport> {
    let _permit = ctx.realtime_slots.clone().acquire_owned().await.ok()?;
    let cfg = ctx.config();
    let engine = ctx.engine();
    let p = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let _qos = QosGuard::enter(ScanPriority::Utility, cfg.energy.background_qos);
        engine.scan_file(&p, &cfg, &ScanOpts::realtime(&cfg))
    })
    .await
    .ok()
}

async fn record_history(
    ctx: &Arc<Ctx>,
    report: &ScanReport,
    md: &std::fs::Metadata,
    verdict: Verdict,
) {
    ctx.bump_stat(StatField::FilesScanned, 1).await;
    let Some(sha) = report.sha256.clone() else {
        return;
    };
    let (path, size, mtime) = (report.path.clone(), md.len(), mtime_secs(md));
    if let Err(e) = ctx
        .store
        .run(move |s| s.record_file(&path, &sha, size, mtime, verdict, pb_core::now_ts()))
        .await
    {
        tracing::warn!(error = %e, "cannot record file history");
    }
}

/// Scan one file that settled after file activity.
pub async fn scan_file_realtime(ctx: &Arc<Ctx>, shared: &Arc<RealtimeShared>, path: PathBuf) {
    let cfg = ctx.config();
    if !cfg.realtime.enabled || ctx.is_shutting_down() {
        return;
    }
    let Ok(md) = tokio::fs::symlink_metadata(&path).await else {
        return; // gone already (temporary file)
    };
    let is_app = md.is_dir() && path.extension().map(|e| e == "app").unwrap_or(false);
    if !(md.is_file() && md.len() > 0) && !is_app {
        return;
    }
    let Some(report) = scan_one(ctx, &path).await else {
        return;
    };
    if let Some(err) = &report.error {
        tracing::debug!(path = %path.display(), error = %err, "real-time scan error");
    }
    let verdict = actions::process_report(ctx, report.clone(), &ReportContext::realtime()).await;
    record_history(ctx, &report, &md, verdict).await;
    if cfg.scan.clamav_realtime
        && verdict == Verdict::Clean
        && report.sha256.is_some()
        && md.is_file()
    {
        add_to_batch(ctx, shared, path).await;
    }
}

async fn add_to_batch(ctx: &Arc<Ctx>, shared: &Arc<RealtimeShared>, path: PathBuf) {
    let (flush_now, schedule) = {
        let mut b = shared.batch.lock().unwrap_or_else(|e| e.into_inner());
        if !b.contains(&path) {
            b.push(path);
        }
        (b.len() >= BATCH_MAX, b.len() == 1)
    };
    if flush_now {
        flush_batch(ctx, shared).await;
    } else if schedule {
        let (ctx, shared) = (ctx.clone(), shared.clone());
        tokio::spawn(async move {
            tokio::time::sleep(BATCH_DELAY).await;
            flush_batch(&ctx, &shared).await;
        });
    }
}

async fn flush_batch(ctx: &Arc<Ctx>, shared: &Arc<RealtimeShared>) {
    let files: Vec<PathBuf> =
        std::mem::take(&mut *shared.batch.lock().unwrap_or_else(|e| e.into_inner()));
    if files.is_empty() {
        return;
    }
    let spec = JobSpec {
        paths: files
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        roots: files,
        opts: ScanOpts {
            origin: ScanOrigin::Downloads,
            use_clamav: true,
            recursive: false,
            only_risky_types: false,
        },
    };
    if let Err(e) = jobs::submit(ctx, spec).await {
        tracing::warn!(error = %e.message, "cannot queue downloads batch");
    }
}

fn spawn_exec_scan(ctx: &Arc<Ctx>, shared: &Arc<RealtimeShared>, target: EsProcessInfo) {
    if shared.pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_SCANS {
        shared.pending.fetch_sub(1, Ordering::SeqCst);
        return;
    }
    let (ctx, shared) = (ctx.clone(), shared.clone());
    tokio::spawn(async move {
        scan_exec(&ctx, &shared, target).await;
        shared.pending.fetch_sub(1, Ordering::SeqCst);
    });
}

/// Cache key of an executed image: cdhash when ES gives it, else path + size + mtime.
fn exec_key(target: &EsProcessInfo, md: &std::fs::Metadata) -> String {
    match target.cdhash.as_deref().filter(|c| !c.is_empty()) {
        Some(c) => format!("cd:{}", c.to_ascii_lowercase()),
        None => format!("p:{}:{}:{}", target.path, md.len(), mtime_secs(md)),
    }
}

/// Scan a just-executed binary; kill it on a signature hit.
pub async fn scan_exec(ctx: &Arc<Ctx>, shared: &Arc<RealtimeShared>, target: EsProcessInfo) {
    let cfg = ctx.config();
    let path = PathBuf::from(&target.path);
    if target.is_platform_binary || !path.is_absolute() || ctx.is_excluded(&path, &cfg) {
        return;
    }
    let valid = target.codesigning_flags & CS_VALID != 0;
    let adhoc = target.codesigning_flags & CS_ADHOC != 0;
    if valid && !adhoc {
        if let Some(team) = target.team_id.as_deref().filter(|t| !t.is_empty()) {
            if ctx.engine().is_trusted_team(team) {
                return;
            }
        }
    }
    let Ok(md) = tokio::fs::metadata(&path).await else {
        return;
    };
    let key = exec_key(&target, &md);
    let generation = ctx.engine_generation();
    if shared.exec_cached(&key, generation) == Some(Verdict::Clean) {
        return;
    }
    let Some(report) = scan_one(ctx, &path).await else {
        return;
    };
    let mut killed = false;
    let signature_hit = report.verdict == Verdict::Malicious
        && actions::signature_grade(ctx.engine().as_ref(), &report);
    if signature_hit && cfg.realtime.kill_malicious_processes && !ctx.is_paused(pb_core::now_ts()) {
        let allowed = match report.sha256.clone() {
            Some(sha) => ctx
                .store
                .run(move |s| s.allowlist_contains(&sha))
                .await
                .unwrap_or(false),
            None => false,
        };
        if !allowed {
            match crate::system::kill_if_path(target.pid, &path) {
                Ok(k) => killed = k,
                Err(e) => {
                    tracing::warn!(pid = target.pid, error = %e, "cannot kill malicious process")
                }
            }
            if killed {
                tracing::warn!(pid = target.pid, path = %path.display(), "malicious process killed");
            }
        }
    }
    let rc = ReportContext {
        origin: ScanOrigin::Realtime,
        job_id: None,
        exec: Some(ExecInfo {
            pid: target.pid,
            killed,
        }),
    };
    let verdict = actions::process_report(ctx, report.clone(), &rc).await;
    if report.sha256.is_some() {
        shared.exec_remember(key, verdict, generation);
    }
    record_history(ctx, &report, &md, verdict).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debounce_quiet_and_max_delay() {
        let t0 = Instant::now();
        let mut d = Debouncer::new(Duration::from_secs(2), Duration::from_secs(30), 100);
        assert!(d.next_deadline().is_none());
        d.touch("/a".into(), t0);
        assert_eq!(d.next_deadline(), Some(t0 + Duration::from_secs(2)));
        assert!(d.take_ready(t0 + Duration::from_secs(1)).is_empty());
        d.touch("/a".into(), t0 + Duration::from_secs(1));
        assert!(d.take_ready(t0 + Duration::from_secs(2)).is_empty());
        assert_eq!(
            d.take_ready(t0 + Duration::from_secs(3)),
            vec![PathBuf::from("/a")]
        );
        assert!(d.is_empty());

        // A file written continuously is still scanned after 30 s.
        let mut t = t0;
        d.touch("/b".into(), t);
        let mut got = vec![];
        for _ in 0..40 {
            t += Duration::from_secs(1);
            d.touch("/b".into(), t);
            got.extend(d.take_ready(t));
            if !got.is_empty() {
                break;
            }
        }
        assert_eq!(got, vec![PathBuf::from("/b")]);
        assert!(t - t0 <= Duration::from_secs(30));
    }

    #[test]
    fn debounce_cap_evicts_oldest() {
        let t0 = Instant::now();
        let mut d = Debouncer::new(Duration::from_secs(2), Duration::from_secs(30), 2);
        assert!(d.touch("/a".into(), t0).is_empty());
        assert!(d
            .touch("/b".into(), t0 + Duration::from_millis(1))
            .is_empty());
        assert!(d
            .touch("/b".into(), t0 + Duration::from_millis(2))
            .is_empty());
        assert_eq!(
            d.touch("/c".into(), t0 + Duration::from_millis(3)),
            vec![PathBuf::from("/a")]
        );
        assert_eq!(d.len(), 2);
    }

    #[test]
    fn exec_cache_generations() {
        let s = RealtimeShared::default();
        s.exec_remember("k".into(), Verdict::Clean, 1);
        assert_eq!(s.exec_cached("k", 1), Some(Verdict::Clean));
        assert_eq!(s.exec_cached("k", 2), None);
        assert_eq!(s.exec_cached("x", 1), None);
    }
}
