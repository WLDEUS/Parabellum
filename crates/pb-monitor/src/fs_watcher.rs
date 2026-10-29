//! [`FileWatcher`]: FSEvents (via `notify`; inotify on Linux) on `config.scan.watch_paths`.
//!
//! Emits `FileActivity { source: FsEvents }` for files created, modified or renamed into a watched
//! folder. In-progress download artefacts are ignored until renamed to their final name, excluded
//! paths and our own root are dropped, and each path produces at most one event every 2 s
//! (leading edge + one trailing event if more activity happened in the window).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::event::{CreateKind, ModifyKind, RenameMode};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use pb_core::config::Config;
use pb_core::events::{FileEventSource, MonitorEvent};
use tokio::sync::mpsc;

use crate::util::{
    expand_paths, is_shutdown, send_health, sleep_or_shutdown, under_any, wait_shutdown, Backoff,
};
use crate::{console_user, MonitorContext, MonitorError, MONITOR_FSEVENTS};

/// Minimum delay between two events for the same path.
pub const COALESCE_WINDOW: Duration = Duration::from_secs(2);
/// Bound of the internal notify -> async channel (events beyond are dropped and counted).
const RAW_CHANNEL: usize = 4096;
/// Max paths remembered by the coalescer.
const COALESCE_MAX_ENTRIES: usize = 16_384;
/// Housekeeping period (console user refresh, missing folders re-check, drop stats).
const HOUSEKEEPING: Duration = Duration::from_secs(60);

/// Watches `scan.watch_paths` and reports new / modified files.
#[derive(Debug, Clone, Copy, Default)]
pub struct FileWatcher;

/// True for in-progress download artefacts (`.crdownload`, `.part`, `.partial`, `.tmp`, Office
/// `~$` lock files, anything inside a Safari `.download` bundle) and Finder noise (`.DS_Store`).
pub fn is_ignored_artefact(path: &Path) -> bool {
    let mut components = path.components().peekable();
    while let Some(c) = components.next() {
        let name = c.as_os_str().to_string_lossy();
        let lower = name.to_ascii_lowercase();
        let is_last = components.peek().is_none();
        // Safari downloads into `<name>.download/` bundles (directory) until complete.
        if lower.ends_with(".download") {
            return true;
        }
        if is_last
            && (lower.ends_with(".crdownload")
                || lower.ends_with(".part")
                || lower.ends_with(".partial")
                || lower.ends_with(".tmp")
                || lower.starts_with("~$")
                || lower == ".ds_store")
        {
            return true;
        }
    }
    false
}

/// Per-path rate limiter: leading-edge emission, then at most one trailing emission per window.
#[derive(Debug, Default)]
pub(crate) struct Coalescer {
    entries: HashMap<PathBuf, (Instant, bool)>,
}

impl Coalescer {
    /// Returns `true` if an event for `path` must be emitted now.
    pub(crate) fn offer(&mut self, path: &Path, now: Instant) -> bool {
        if let Some((last, pending)) = self.entries.get_mut(path) {
            if now.duration_since(*last) >= COALESCE_WINDOW {
                *last = now;
                *pending = false;
                true
            } else {
                *pending = true;
                false
            }
        } else {
            if self.entries.len() >= COALESCE_MAX_ENTRIES {
                self.purge(now);
                if self.entries.len() >= COALESCE_MAX_ENTRIES {
                    // Pathological burst: forget everything rather than grow without bound.
                    self.entries.clear();
                }
            }
            self.entries.insert(path.to_path_buf(), (now, false));
            true
        }
    }

    /// Paths whose trailing event is due; they are marked as emitted at `now`.
    pub(crate) fn due(&mut self, now: Instant) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for (p, (last, pending)) in self.entries.iter_mut() {
            if *pending && now.duration_since(*last) >= COALESCE_WINDOW {
                *pending = false;
                *last = now;
                out.push(p.clone());
            }
        }
        out
    }

    /// Earliest pending trailing deadline.
    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.entries
            .values()
            .filter(|(_, pending)| *pending)
            .map(|(last, _)| *last + COALESCE_WINDOW)
            .min()
    }

    /// Forgets idle entries.
    pub(crate) fn purge(&mut self, now: Instant) {
        self.entries
            .retain(|_, (last, pending)| *pending || now.duration_since(*last) < COALESCE_WINDOW);
    }
}

/// Paths of a notify event that may denote a file created / written / renamed into place.
pub(crate) fn candidate_paths(event: &Event) -> Vec<PathBuf> {
    match &event.kind {
        EventKind::Create(CreateKind::Folder) => Vec::new(),
        EventKind::Create(_) => event.paths.clone(),
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => Vec::new(),
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            event.paths.get(1).cloned().into_iter().collect()
        }
        EventKind::Modify(ModifyKind::Metadata(_)) => Vec::new(),
        EventKind::Modify(_) => event.paths.clone(),
        EventKind::Any | EventKind::Other => event.paths.clone(),
        EventKind::Access(_) | EventKind::Remove(_) => Vec::new(),
    }
}

/// Folders to watch for a config and home (missing folders are skipped by the caller).
pub(crate) fn watch_targets(cfg: &Config, home: Option<&Path>) -> Vec<PathBuf> {
    expand_paths(&cfg.scan.watch_paths, home)
}

struct Filter {
    excludes: Vec<PathBuf>,
    own_root: PathBuf,
}

impl Filter {
    fn accept(&self, path: &Path) -> bool {
        if path.starts_with(&self.own_root)
            || under_any(path, &self.excludes)
            || is_ignored_artefact(path)
        {
            return false;
        }
        // Regular files only (no directories, no symlinks).
        std::fs::symlink_metadata(path)
            .map(|m| m.file_type().is_file())
            .unwrap_or(false)
    }
}

/// Active notify watcher and the folders it covers.
struct Active {
    _watcher: notify::RecommendedWatcher,
    watched: Vec<PathBuf>,
    missing: Vec<PathBuf>,
}

fn start_watcher(
    targets: &[PathBuf],
    raw_tx: mpsc::Sender<Event>,
    dropped: Arc<AtomicU64>,
) -> Result<Active, MonitorError> {
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<Event>| match res {
        Ok(ev) => {
            if raw_tx.try_send(ev).is_err() {
                dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        Err(e) => tracing::warn!(error = %e, "fsevents error"),
    })?;
    let mut watched = Vec::new();
    let mut missing = Vec::new();
    for t in targets {
        if !t.is_dir() {
            missing.push(t.clone());
            continue;
        }
        match watcher.watch(t, RecursiveMode::Recursive) {
            Ok(()) => watched.push(t.clone()),
            Err(e) => {
                tracing::warn!(path = %t.display(), error = %e, "cannot watch folder");
                missing.push(t.clone());
            }
        }
    }
    Ok(Active {
        _watcher: watcher,
        watched,
        missing,
    })
}

enum Exit {
    Shutdown,
    Restart(String),
}

impl FileWatcher {
    /// Runs until shutdown. Honors `realtime.enabled && realtime.fsevents` (idle otherwise).
    pub async fn run(self, mut ctx: MonitorContext) {
        let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(300));
        loop {
            if is_shutdown(&ctx.shutdown) {
                return;
            }
            match self.run_once(&mut ctx).await {
                Exit::Shutdown => return,
                Exit::Restart(msg) => {
                    send_health(&ctx.tx, MONITOR_FSEVENTS, false, msg).await;
                    if sleep_or_shutdown(backoff.next_delay(), &mut ctx.shutdown).await {
                        return;
                    }
                }
            }
        }
    }

    async fn run_once(&self, ctx: &mut MonitorContext) -> Exit {
        let mut user = ctx.user.clone().or_else(console_user);
        let (raw_tx, mut raw_rx) = mpsc::channel::<Event>(RAW_CHANNEL);
        let dropped = Arc::new(AtomicU64::new(0));
        let mut coalescer = Coalescer::default();
        let mut active: Option<Active> = None;
        let mut current_targets: Vec<PathBuf> = Vec::new();
        let mut filter = Filter {
            excludes: Vec::new(),
            own_root: ctx.paths.root.clone(),
        };
        let mut housekeeping =
            tokio::time::interval_at(tokio::time::Instant::now() + HOUSEKEEPING, HOUSEKEEPING);
        housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut reconfigure = true;
        let mut sent_dropped: u64 = 0;

        loop {
            if reconfigure {
                reconfigure = false;
                let cfg = ctx.config.borrow_and_update().clone();
                let home = user.as_ref().map(|u| u.home.clone());
                filter.excludes = expand_paths(&cfg.scan.exclude_paths, home.as_deref());
                if !(cfg.realtime.enabled && cfg.realtime.fsevents) {
                    if active.take().is_some() || current_targets.is_empty() {
                        send_health(
                            &ctx.tx,
                            MONITOR_FSEVENTS,
                            false,
                            "FSEvents désactivé (configuration)",
                        )
                        .await;
                    }
                    current_targets.clear();
                } else {
                    let targets = watch_targets(&cfg, home.as_deref());
                    let needs_restart = active.is_none() || targets != current_targets;
                    if needs_restart {
                        // Drop the previous watcher (and its kernel watches) before creating the next one.
                        drop(active.take());
                        match start_watcher(&targets, raw_tx.clone(), dropped.clone()) {
                            Ok(a) => {
                                let msg = if a.missing.is_empty() {
                                    format!("{} dossier(s) surveillé(s)", a.watched.len())
                                } else {
                                    format!(
                                        "{} dossier(s) surveillé(s), absents : {}",
                                        a.watched.len(),
                                        a.missing
                                            .iter()
                                            .map(|p| p.display().to_string())
                                            .collect::<Vec<_>>()
                                            .join(", ")
                                    )
                                };
                                let ok = !a.watched.is_empty() || targets.is_empty();
                                send_health(&ctx.tx, MONITOR_FSEVENTS, ok, msg).await;
                                active = Some(a);
                                current_targets = targets;
                            }
                            Err(e) => return Exit::Restart(format!("FSEvents indisponible : {e}")),
                        }
                    }
                }
            }

            let trailing = coalescer.next_deadline();
            tokio::select! {
                _ = wait_shutdown(&mut ctx.shutdown) => return Exit::Shutdown,
                changed = ctx.config.changed() => {
                    if changed.is_err() {
                        return Exit::Shutdown;
                    }
                    reconfigure = true;
                }
                Some(ev) = raw_rx.recv() => {
                    let now = Instant::now();
                    for p in candidate_paths(&ev) {
                        if filter.accept(&p) && coalescer.offer(&p, now) && !emit(&ctx.tx, p) {
                            return Exit::Shutdown;
                        }
                    }
                }
                _ = sleep_until_opt(trailing) => {
                    for p in coalescer.due(Instant::now()) {
                        if filter.accept(&p) && !emit(&ctx.tx, p) {
                            return Exit::Shutdown;
                        }
                    }
                }
                _ = housekeeping.tick() => {
                    coalescer.purge(Instant::now());
                    let fresh = console_user();
                    if fresh.is_some() && fresh != user {
                        user = fresh;
                        reconfigure = true;
                    }
                    if active.as_ref().map(|a| a.missing.iter().any(|p| p.is_dir())).unwrap_or(false)
                        || active.as_ref().map(|a| a.watched.iter().any(|p| !p.is_dir())).unwrap_or(false)
                    {
                        // A watched folder appeared or vanished: rebuild the watch set.
                        active = None;
                        reconfigure = true;
                    }
                    let d = dropped.load(Ordering::Relaxed);
                    if d > sent_dropped {
                        send_health(&ctx.tx, MONITOR_FSEVENTS, true, format!("{} événement(s) FSEvents ignoré(s) (surcharge)", d - sent_dropped)).await;
                        sent_dropped = d;
                    }
                }
            }
        }
    }
}

async fn sleep_until_opt(deadline: Option<Instant>) {
    match deadline {
        Some(d) => tokio::time::sleep_until(tokio::time::Instant::from_std(d)).await,
        None => std::future::pending::<()>().await,
    }
}

/// Non-blocking send of a file event; returns `false` if the daemon is gone.
fn emit(tx: &mpsc::Sender<MonitorEvent>, path: PathBuf) -> bool {
    let ev = MonitorEvent::FileActivity {
        path: path.to_string_lossy().into_owned(),
        from: None,
        source: FileEventSource::FsEvents,
        process: None,
    };
    match tx.try_send(ev) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            tracing::debug!("monitor channel full, file event dropped");
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_core::paths::Paths;
    use tokio::sync::watch;

    #[test]
    fn ignores_download_artefacts() {
        assert!(is_ignored_artefact(Path::new(
            "/Users/q/Downloads/a.dmg.crdownload"
        )));
        assert!(is_ignored_artefact(Path::new(
            "/Users/q/Downloads/a.zip.part"
        )));
        assert!(is_ignored_artefact(Path::new(
            "/Users/q/Downloads/a.partial"
        )));
        assert!(is_ignored_artefact(Path::new("/Users/q/Downloads/x.tmp")));
        assert!(is_ignored_artefact(Path::new(
            "/Users/q/Documents/~$rapport.docx"
        )));
        assert!(is_ignored_artefact(Path::new(
            "/Users/q/Downloads/a.dmg.download/a.dmg"
        )));
        assert!(is_ignored_artefact(Path::new(
            "/Users/q/Downloads/a.dmg.download"
        )));
        assert!(is_ignored_artefact(Path::new(
            "/Users/q/Downloads/.DS_Store"
        )));
        assert!(!is_ignored_artefact(Path::new("/Users/q/Downloads/a.dmg")));
        assert!(!is_ignored_artefact(Path::new(
            "/Users/q/Downloads/partners.pdf"
        )));
    }

    #[test]
    fn coalescer_leading_and_trailing() {
        let mut c = Coalescer::default();
        let t0 = Instant::now();
        let p = Path::new("/x/a");
        assert!(c.offer(p, t0));
        assert!(!c.offer(p, t0 + Duration::from_millis(500)));
        assert!(!c.offer(p, t0 + Duration::from_millis(900)));
        assert_eq!(c.next_deadline(), Some(t0 + COALESCE_WINDOW));
        assert!(c.due(t0 + Duration::from_secs(1)).is_empty());
        assert_eq!(c.due(t0 + Duration::from_secs(2)), vec![p.to_path_buf()]);
        assert_eq!(c.next_deadline(), None);
        // window restarted at the trailing emission
        assert!(!c.offer(p, t0 + Duration::from_secs(3)));
        assert!(c.offer(p, t0 + Duration::from_secs(5)));
        c.purge(t0 + Duration::from_secs(60));
        assert!(c.entries.is_empty());
    }

    #[test]
    fn candidate_paths_by_kind() {
        let mk = |kind: EventKind, paths: &[&str]| Event {
            kind,
            paths: paths.iter().map(PathBuf::from).collect(),
            attrs: Default::default(),
        };
        assert_eq!(
            candidate_paths(&mk(EventKind::Create(CreateKind::File), &["/a"])).len(),
            1
        );
        assert!(candidate_paths(&mk(EventKind::Create(CreateKind::Folder), &["/a"])).is_empty());
        assert_eq!(
            candidate_paths(&mk(
                EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
                &["/a", "/b"]
            )),
            vec![PathBuf::from("/b")]
        );
        assert!(candidate_paths(&mk(
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            &["/a"]
        ))
        .is_empty());
        assert!(candidate_paths(&mk(
            EventKind::Remove(notify::event::RemoveKind::File),
            &["/a"]
        ))
        .is_empty());
    }

    #[tokio::test]
    async fn reports_new_files_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let watched = dir.path().join("watched");
        std::fs::create_dir(&watched).unwrap();
        let mut cfg = Config::default();
        cfg.scan.watch_paths = vec![watched.to_string_lossy().into_owned()];
        cfg.scan.exclude_paths = vec![watched.join("skip").to_string_lossy().into_owned()];
        let (_cfg_tx, cfg_rx) = watch::channel(cfg);
        let (stop_tx, stop_rx) = watch::channel(false);
        let (tx, mut rx) = mpsc::channel(64);
        let ctx = MonitorContext {
            paths: Paths::with_root(dir.path().join("pbroot")),
            config: cfg_rx,
            user: None,
            tx,
            shutdown: stop_rx,
        };
        let task = tokio::spawn(FileWatcher.run(ctx));

        // first event is the health report
        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(ev, MonitorEvent::MonitorHealth { ok: true, .. }),
            "{ev:?}"
        );

        std::fs::create_dir(watched.join("skip")).unwrap();
        std::fs::write(watched.join("skip").join("ignored.bin"), b"x").unwrap();
        std::fs::write(watched.join("x.crdownload"), b"x").unwrap();
        std::fs::write(watched.join("payload.bin"), b"hello").unwrap();

        let ev = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        match ev {
            MonitorEvent::FileActivity { path, source, .. } => {
                assert!(path.ends_with("payload.bin"), "{path}");
                assert_eq!(source, FileEventSource::FsEvents);
            }
            other => panic!("unexpected {other:?}"),
        }
        stop_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}
