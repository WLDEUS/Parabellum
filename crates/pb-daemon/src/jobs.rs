//! Scan job manager: one heavy job at a time (manual, volume, downloads batch, scheduled, retro-hunt),
//! the others queued; cancellation flag; progress events throttled to 500 ms; jobs and findings persisted.
//! Real-time single-file scans do not go through here (see [`crate::realtime`]).

use crate::actions::{self, ReportContext};
use crate::backends::ScanOpts;
use crate::ctx::Ctx;
use crate::store::StatField;
use crate::system::{QosGuard, ScanPriority};
use pb_core::ipc::DaemonEvent;
use pb_core::model::*;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Notify};

/// Interval between `scan_progress` events of a running job.
pub const PROGRESS_INTERVAL: Duration = Duration::from_millis(500);
/// Max queued jobs (beyond that, new requests get `busy`).
pub const MAX_QUEUED: usize = 32;
/// Findings persisted per job (counters keep counting beyond).
pub const MAX_FINDINGS_STORED: u64 = 10_000;

/// What to scan.
#[derive(Debug, Clone)]
pub struct JobSpec {
    /// Shown to the user.
    pub paths: Vec<String>,
    /// Files / directories handed to the engine.
    pub roots: Vec<PathBuf>,
    pub opts: ScanOpts,
}

/// A queued or running job with live counters.
#[derive(Debug)]
pub struct Job {
    pub id: String,
    pub spec: JobSpec,
    state: Mutex<JobState>,
    created_at: i64,
    started_at: AtomicI64,
    finished_at: AtomicI64,
    files: AtomicU64,
    bytes: AtomicU64,
    threats: AtomicU64,
    errors: AtomicU64,
    stored_findings: AtomicU64,
    current: Mutex<Option<String>>,
    cancel: AtomicBool,
}

impl Job {
    pub fn new(spec: JobSpec) -> Arc<Self> {
        let now = pb_core::now_ts();
        Arc::new(Self {
            id: uuid::Uuid::new_v4().to_string(),
            spec,
            state: Mutex::new(JobState::Queued),
            created_at: now,
            started_at: AtomicI64::new(0),
            finished_at: AtomicI64::new(0),
            files: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            threats: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            stored_findings: AtomicU64::new(0),
            current: Mutex::new(None),
            cancel: AtomicBool::new(false),
        })
    }

    pub fn origin(&self) -> ScanOrigin {
        self.spec.opts.origin
    }

    pub fn state(&self) -> JobState {
        *self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_state(&self, s: JobState) {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = s;
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Count a scanned file (called from the engine thread).
    fn account(&self, r: &ScanReport) {
        self.files.fetch_add(1, Ordering::Relaxed);
        if !is_member(r) {
            self.bytes.fetch_add(r.size, Ordering::Relaxed);
        }
        if r.error.is_some() {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some(r.path.clone());
    }

    fn counters(&self) -> (u64, u64, u64, u64) {
        (
            self.files.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            self.threats.load(Ordering::Relaxed),
            self.errors.load(Ordering::Relaxed),
        )
    }

    /// Wire summary with live counters.
    pub fn summary(&self) -> ScanJobSummary {
        let state = self.state();
        let started = self.started_at.load(Ordering::Relaxed);
        let finished = self.finished_at.load(Ordering::Relaxed);
        let (files, bytes, threats, errors) = self.counters();
        ScanJobSummary {
            job_id: self.id.clone(),
            origin: self.origin(),
            paths: self.spec.paths.clone(),
            state,
            started_at: if started > 0 {
                started
            } else {
                self.created_at
            },
            finished_at: (finished > 0).then_some(finished),
            files_scanned: files,
            bytes_scanned: bytes,
            threats,
            errors,
            current_path: if state == JobState::Running {
                self.current
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
            } else {
                None
            },
        }
    }
}

/// Outcome of a cancel request.
#[derive(Debug)]
pub enum CancelOutcome {
    /// Running job flagged; it will finish as `cancelled`.
    Signalled,
    /// Queued job removed (caller persists it).
    Dequeued(Arc<Job>),
    NotFound,
}

#[derive(Default)]
struct Inner {
    queue: VecDeque<Arc<Job>>,
    running: Option<Arc<Job>>,
}

/// Queue + running slot.
#[derive(Default)]
pub struct JobManager {
    inner: Mutex<Inner>,
    wake: Notify,
}

/// Origins whose jobs wait while on low battery.
pub fn is_deferrable(origin: ScanOrigin) -> bool {
    matches!(origin, ScanOrigin::RetroHunt | ScanOrigin::Scheduled)
}

impl JobManager {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Queue a job. Fails when the queue is full.
    pub fn enqueue(&self, job: Arc<Job>) -> Result<(), Arc<Job>> {
        {
            let mut g = self.lock();
            if g.queue.len() >= MAX_QUEUED {
                return Err(job);
            }
            g.queue.push_back(job);
        }
        self.wake.notify_one();
        Ok(())
    }

    /// Queued or running job by id.
    pub fn get(&self, id: &str) -> Option<Arc<Job>> {
        let g = self.lock();
        g.running
            .iter()
            .chain(g.queue.iter())
            .find(|j| j.id == id)
            .cloned()
    }

    /// Running job first, then queued ones.
    pub fn active(&self) -> Vec<Arc<Job>> {
        let g = self.lock();
        g.running.iter().chain(g.queue.iter()).cloned().collect()
    }

    /// Wake the runner (battery state changed: deferred jobs may run now).
    pub fn poke(&self) {
        self.wake.notify_one();
    }

    pub fn queued_len(&self) -> usize {
        self.lock().queue.len()
    }

    /// Is a job with this origin queued or running?
    pub fn has_active(&self, origin: ScanOrigin) -> bool {
        self.active().iter().any(|j| j.origin() == origin)
    }

    pub fn cancel(&self, id: &str) -> CancelOutcome {
        let mut g = self.lock();
        if let Some(r) = g.running.as_ref().filter(|j| j.id == id) {
            r.cancel();
            return CancelOutcome::Signalled;
        }
        if let Some(pos) = g.queue.iter().position(|j| j.id == id) {
            if let Some(j) = g.queue.remove(pos) {
                j.cancel();
                j.set_state(JobState::Cancelled);
                j.finished_at.store(pb_core::now_ts(), Ordering::Relaxed);
                return CancelOutcome::Dequeued(j);
            }
        }
        CancelOutcome::NotFound
    }

    /// Pop the next runnable job (skipping deferrable ones when `defer`), marking it running.
    fn take_next(&self, defer: bool) -> Option<Arc<Job>> {
        let mut g = self.lock();
        if g.running.is_some() {
            return None;
        }
        let pos = g
            .queue
            .iter()
            .position(|j| !(defer && is_deferrable(j.origin())))?;
        let job = g.queue.remove(pos)?;
        g.running = Some(job.clone());
        Some(job)
    }

    fn finish_running(&self) {
        self.lock().running = None;
    }
}

/// Create, persist and queue a job. Returns its id.
pub async fn submit(ctx: &Arc<Ctx>, spec: JobSpec) -> Result<String, pb_core::ipc::IpcError> {
    use pb_core::ipc::{ErrorCode, IpcError};
    let job = Job::new(spec);
    let summary = job.summary();
    ctx.jobs
        .enqueue(job.clone())
        .map_err(|_| IpcError::new(ErrorCode::Busy, "trop d'analyses en attente"))?;
    if let Err(e) = ctx.store.run(move |s| s.upsert_job(&summary)).await {
        tracing::warn!(error = %e, "cannot persist job");
    }
    tracing::info!(job = %job.id, origin = ?job.origin(), paths = job.spec.roots.len(), "scan job queued");
    Ok(job.id.clone())
}

/// Persist a cancelled-while-queued job and tell subscribers.
pub async fn finalize_dequeued(ctx: &Arc<Ctx>, job: Arc<Job>) {
    let summary = job.summary();
    let s2 = summary.clone();
    if let Err(e) = ctx.store.run(move |s| s.upsert_job(&s2)).await {
        tracing::warn!(error = %e, "cannot persist job");
    }
    ctx.bus.publish(DaemonEvent::ScanFinished(summary));
}

/// Job runner task: runs queued jobs one by one until shutdown.
pub async fn run_jobs(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    loop {
        if *shutdown.borrow() {
            break;
        }
        let defer = ctx.should_defer_heavy_work();
        if let Some(job) = ctx.jobs.take_next(defer) {
            run_job(&ctx, job).await;
            ctx.jobs.finish_running();
            continue;
        }
        let waiting = ctx.jobs.queued_len() > 0;
        tokio::select! {
            _ = ctx.jobs.wake.notified() => {}
            // Deferred jobs: re-check the battery periodically.
            _ = tokio::time::sleep(Duration::from_secs(60)), if waiting => {}
            _ = shutdown.changed() => {}
        }
    }
    // Cancel whatever is left so the store reflects reality.
    for j in ctx.jobs.active() {
        j.cancel();
    }
}

async fn persist(ctx: &Arc<Ctx>, job: &Arc<Job>) {
    let summary = job.summary();
    if let Err(e) = ctx.store.run(move |s| s.upsert_job(&summary)).await {
        tracing::warn!(error = %e, "cannot persist job");
    }
}

/// Run one job to completion.
pub async fn run_job(ctx: &Arc<Ctx>, job: Arc<Job>) {
    job.started_at.store(pb_core::now_ts(), Ordering::Relaxed);
    job.set_state(JobState::Running);
    persist(ctx, &job).await;
    ctx.bus.publish(DaemonEvent::ScanProgress(job.summary()));

    let (tx, mut rx) = mpsc::channel::<ScanReport>(256);
    let engine = ctx.engine();
    let cfg = ctx.config();
    let job2 = job.clone();
    let priority = if job.origin() == ScanOrigin::Manual {
        ScanPriority::Utility
    } else {
        ScanPriority::Background
    };
    let handle = tokio::task::spawn_blocking(move || {
        let _qos = QosGuard::enter(priority, cfg.energy.background_qos);
        let mut sink = |r: ScanReport| -> bool {
            job2.account(&r);
            let keep = r.verdict != Verdict::Clean || r.error.is_some();
            let delivered = !keep || tx.blocking_send(r).is_ok();
            delivered && !job2.is_cancelled()
        };
        engine.scan_tree(
            &job2.spec.roots,
            &cfg,
            &job2.spec.opts,
            &job2.cancel,
            &mut sink,
        );
    });

    let rc = ReportContext {
        origin: job.origin(),
        job_id: Some(job.id.clone()),
        exec: None,
    };
    let mut ticker = tokio::time::interval(PROGRESS_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last = job.counters();
    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Some(report) => handle_finding(ctx, &job, report, &rc).await,
                None => break,
            },
            _ = ticker.tick() => {
                let now = job.counters();
                if now != last {
                    last = now;
                    ctx.bus.publish(DaemonEvent::ScanProgress(job.summary()));
                }
            }
        }
    }
    let failed = match handle.await {
        Ok(()) => false,
        Err(e) => {
            tracing::error!(job = %job.id, error = %e, "scan task failed");
            true
        }
    };
    job.finished_at.store(pb_core::now_ts(), Ordering::Relaxed);
    job.set_state(if failed {
        JobState::Failed
    } else if job.is_cancelled() {
        JobState::Cancelled
    } else {
        JobState::Finished
    });
    persist(ctx, &job).await;
    let summary = job.summary();
    ctx.bump_stat(StatField::FilesScanned, summary.files_scanned)
        .await;
    tracing::info!(
        job = %job.id, state = ?summary.state, files = summary.files_scanned,
        threats = summary.threats, errors = summary.errors, "scan job done"
    );
    ctx.bus.publish(DaemonEvent::ScanFinished(summary));
    ctx.status_dirty.notify_one();
}

/// Report of a file inside a container (`<container>!/<inner>`): informative only; the engine rolls its
/// verdict up into the container report, which is the one acted upon.
pub fn is_member(r: &ScanReport) -> bool {
    r.path.contains("!/")
}

async fn handle_finding(ctx: &Arc<Ctx>, job: &Arc<Job>, report: ScanReport, rc: &ReportContext) {
    if is_member(&report) {
        store_finding(ctx, job, report).await;
        return;
    }
    let effective = actions::process_report(ctx, report.clone(), rc).await;
    let mut stored = report;
    if effective != Verdict::Clean {
        job.threats.fetch_add(1, Ordering::Relaxed);
    }
    if effective == Verdict::Clean && stored.error.is_none() {
        return; // allowlisted locally
    }
    stored.verdict = effective;
    store_finding(ctx, job, stored).await;
}

async fn store_finding(ctx: &Arc<Ctx>, job: &Arc<Job>, report: ScanReport) {
    if job.stored_findings.fetch_add(1, Ordering::Relaxed) < MAX_FINDINGS_STORED {
        let id = job.id.clone();
        if let Err(e) = ctx.store.run(move |s| s.add_finding(&id, &report)).await {
            tracing::warn!(error = %e, "cannot persist finding");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(origin: ScanOrigin) -> JobSpec {
        JobSpec {
            paths: vec!["/x".into()],
            roots: vec![PathBuf::from("/x")],
            opts: ScanOpts {
                origin,
                use_clamav: false,
                recursive: true,
                only_risky_types: false,
            },
        }
    }

    #[test]
    fn queue_order_deferral_and_cancel() {
        let m = JobManager::new();
        let retro = Job::new(spec(ScanOrigin::RetroHunt));
        let manual = Job::new(spec(ScanOrigin::Manual));
        let manual2 = Job::new(spec(ScanOrigin::Manual));
        m.enqueue(retro.clone()).unwrap();
        m.enqueue(manual.clone()).unwrap();
        m.enqueue(manual2.clone()).unwrap();
        assert!(m.has_active(ScanOrigin::RetroHunt));
        // Low battery: the retro-hunt waits, the manual scan runs.
        let j = m.take_next(true).unwrap();
        assert_eq!(j.id, manual.id);
        assert!(m.take_next(false).is_none(), "one heavy job at a time");
        assert!(matches!(m.cancel(&manual.id), CancelOutcome::Signalled));
        assert!(manual.is_cancelled());
        m.finish_running();
        match m.cancel(&manual2.id) {
            CancelOutcome::Dequeued(j) => assert_eq!(j.state(), JobState::Cancelled),
            other => panic!("{other:?}"),
        }
        assert!(matches!(m.cancel("nope"), CancelOutcome::NotFound));
        assert_eq!(m.take_next(false).unwrap().id, retro.id);
        assert_eq!(m.get(&retro.id).unwrap().id, retro.id);
    }

    #[test]
    fn queue_is_bounded() {
        let m = JobManager::new();
        for _ in 0..MAX_QUEUED {
            m.enqueue(Job::new(spec(ScanOrigin::Manual))).unwrap();
        }
        assert!(m.enqueue(Job::new(spec(ScanOrigin::Manual))).is_err());
    }

    #[test]
    fn members_are_detected() {
        assert!(is_member(&ScanReport {
            path: "/a.dmg!/x.app/y".into(),
            ..Default::default()
        }));
        assert!(!is_member(&ScanReport {
            path: "/a.dmg".into(),
            ..Default::default()
        }));
    }

    #[test]
    fn summary_counts() {
        let j = Job::new(spec(ScanOrigin::Manual));
        j.account(&ScanReport {
            path: "/a".into(),
            size: 10,
            ..Default::default()
        });
        j.account(&ScanReport {
            path: "/b".into(),
            size: 5,
            error: Some("x".into()),
            ..Default::default()
        });
        let s = j.summary();
        assert_eq!((s.files_scanned, s.bytes_scanned, s.errors), (2, 15, 1));
        assert_eq!(s.state, JobState::Queued);
        assert!(s.current_path.is_none());
        j.set_state(JobState::Running);
        assert_eq!(j.summary().current_path.as_deref(), Some("/b"));
    }
}
