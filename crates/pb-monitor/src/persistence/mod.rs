//! Persistence monitoring: enumeration ([`scan_all`]), change detection ([`diff`]) and the
//! [`PersistenceWatcher`].
//!
//! Locations: `/Library/LaunchAgents`, `/Library/LaunchDaemons`, each user's
//! `~/Library/LaunchAgents`, Background Task Management (`sfltool dumpbtm`), cron
//! (`/usr/lib/cron/tabs/*`, `/etc/crontab`), periodic (`/etc/periodic/*`, `/usr/local/etc/periodic/*`,
//! `/etc/*.local`), shell profiles (per user and `/etc`), configuration profiles (`profiles show`),
//! system extensions (`systemextensionsctl list`), kernel extensions (`/Library/Extensions`,
//! `/Library/StagedExtensions`), authorization plugins (`/Library/Security/SecurityAgentPlugins`),
//! Chromium-based browser extensions, Safari extensions (`pluginkit`) and loginwindow hooks.
//!
//! The monitor never decides anything: every item is reported with status `New`; the daemon owns
//! the baseline, approvals and alerts.

pub mod parsers;
mod sources;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use pb_core::events::MonitorEvent;
use pb_core::model::{PersistenceChangeKind, PersistenceItem, PersistenceKind, PersistenceStatus};
use tokio::sync::mpsc;

use crate::util::{is_shutdown, send_health, sleep_or_shutdown, under_any, wait_shutdown, Backoff};
use crate::{
    console_user, persistence_trigger, user_homes, ConsoleUser, MonitorContext, MONITOR_PERSISTENCE,
};
use sources::{ScanOutcome, Scanner};

/// snake_case name of a kind (as serialized in JSON), used in [`item_id`].
pub fn kind_name(kind: PersistenceKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{kind:?}"))
}

/// Stable id: first 16 hex chars of SHA-256(`<kind snake_case>|<path>|<label or empty>`).
pub fn item_id(kind: PersistenceKind, path: &str, label: Option<&str>) -> String {
    let digest = crate::util::sha256_bytes(
        format!("{}|{}|{}", kind_name(kind), path, label.unwrap_or("")).as_bytes(),
    );
    digest[..16].to_string()
}

/// Enumerates every persistence location (all sources, including the tool-based ones) for the given
/// home directories. Failing sources are skipped (logged). Blocking: call from `spawn_blocking`.
pub fn scan_all(user_homes: &[PathBuf]) -> Vec<PersistenceItem> {
    let console = console_user();
    Scanner::default()
        .scan(user_homes, console.as_ref(), true)
        .items
}

fn changed(old: &PersistenceItem, new: &PersistenceItem) -> bool {
    old.program != new.program
        || old.arguments != new.arguments
        || old.label != new.label
        || old.user != new.user
        || matches!((&old.program_sha256, &new.program_sha256), (Some(a), Some(b)) if a != b)
}

/// Compares two snapshots by id: `Added` (new only), `Modified` (program, arguments, label, user or
/// program hash changed; a hash that could not be computed is not a change) and `Removed` (old
/// only; the old item is returned).
pub fn diff(
    old: &[PersistenceItem],
    new: &[PersistenceItem],
) -> Vec<(PersistenceItem, PersistenceChangeKind)> {
    let old_map: HashMap<&str, &PersistenceItem> = old.iter().map(|i| (i.id.as_str(), i)).collect();
    let new_ids: HashSet<&str> = new.iter().map(|i| i.id.as_str()).collect();
    let mut out = Vec::new();
    for n in new {
        match old_map.get(n.id.as_str()) {
            None => out.push((n.clone(), PersistenceChangeKind::Added)),
            Some(o) if changed(o, n) => out.push((n.clone(), PersistenceChangeKind::Modified)),
            Some(_) => {}
        }
    }
    for o in old {
        if !new_ids.contains(o.id.as_str()) {
            out.push((o.clone(), PersistenceChangeKind::Removed));
        }
    }
    out
}

/// Adds the previous items of sources / folders that were not (successfully) scanned.
fn carry_over(
    prev: &[PersistenceItem],
    outcome: ScanOutcome,
    scanned_slow: bool,
) -> Vec<PersistenceItem> {
    let mut items = outcome.items;
    let ids: HashSet<String> = items.iter().map(|i| i.id.clone()).collect();
    for p in prev {
        let src = sources::source_of(p);
        let carry = outcome.failed_sources.contains(&src)
            || (!scanned_slow && src.is_slow())
            || under_any(Path::new(&p.path), &outcome.failed_prefixes);
        if carry && !ids.contains(&p.id) {
            items.push(p.clone());
        }
    }
    items
}

/// Cheap change detector for files that are not watched with FSEvents (shell profiles in busy home
/// folders, crontabs, periodic config): (size, mtime, inode) per path, polled every minute.
fn stat_signature(paths: &[PathBuf]) -> Vec<Option<(u64, i64, i64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    paths
        .iter()
        .map(|p| {
            std::fs::metadata(p)
                .ok()
                .map(|m| (m.len(), m.mtime(), m.mtime_nsec(), m.ino()))
        })
        .collect()
}

fn polled_files(homes: &[PathBuf]) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = sources::SYSTEM_SHELL_FILES
        .iter()
        .map(PathBuf::from)
        .collect();
    v.extend(sources::PERIODIC_FILES.iter().map(PathBuf::from));
    v.push(PathBuf::from(sources::SYSTEM_CRONTAB));
    for h in homes {
        v.extend(sources::USER_SHELL_FILES.iter().map(|f| h.join(f)));
    }
    v
}

/// Quiet folders watched with FSEvents (non-recursive) to trigger a fast rescan.
fn watched_dirs(homes: &[PathBuf]) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = vec![
        PathBuf::from(sources::SYSTEM_LAUNCH_AGENTS),
        PathBuf::from(sources::SYSTEM_LAUNCH_DAEMONS),
        PathBuf::from(sources::AUTH_PLUGINS_DIR),
        PathBuf::from("/usr/lib/cron/tabs"),
    ];
    v.extend(sources::KEXT_DIRS.iter().map(PathBuf::from));
    v.extend(sources::PERIODIC_DIRS.iter().map(PathBuf::from));
    for h in homes {
        v.push(h.join("Library/LaunchAgents"));
    }
    v.into_iter()
        .filter(|p| p.is_dir())
        .filter_map(|p| std::fs::canonicalize(&p).ok().or(Some(p)))
        .collect()
}

/// Watches persistence locations. `known` is the daemon's last snapshot (from its database): at
/// startup the watcher reports what changed since then (items whose status is `Removed` are
/// considered absent).
#[derive(Debug, Clone, Default)]
pub struct PersistenceWatcher {
    pub known: Vec<PersistenceItem>,
}

/// Delay between an FSEvents / stat change and the fast rescan (lets installers finish writing).
const FAST_DEBOUNCE: Duration = Duration::from_secs(3);
/// Delay between a BTM trigger and the full rescan.
const FULL_DEBOUNCE: Duration = Duration::from_secs(2);
const STAT_POLL: Duration = Duration::from_secs(60);

enum ScanKind {
    Fast,
    Full,
}

impl PersistenceWatcher {
    /// Runs until shutdown. Honors `persistence.enabled` (idle otherwise).
    pub async fn run(self, mut ctx: MonitorContext) {
        let mut current: Vec<PersistenceItem> = self
            .known
            .into_iter()
            .filter(|i| i.status != PersistenceStatus::Removed)
            .collect();
        let mut scanner = Some(Scanner::default());
        let mut backoff = Backoff::new(Duration::from_secs(5), Duration::from_secs(600));
        let mut first = true;
        loop {
            if is_shutdown(&ctx.shutdown) {
                return;
            }
            let enabled = ctx.config.borrow_and_update().persistence.enabled;
            if !enabled {
                send_health(
                    &ctx.tx,
                    MONITOR_PERSISTENCE,
                    false,
                    "Surveillance de la persistance désactivée (configuration)",
                )
                .await;
                tokio::select! {
                    _ = wait_shutdown(&mut ctx.shutdown) => return,
                    r = ctx.config.changed() => if r.is_err() { return },
                }
                continue;
            }
            match run_loop(&mut ctx, &mut current, &mut scanner, &mut first).await {
                Ok(()) => return,
                Err(msg) => {
                    send_health(&ctx.tx, MONITOR_PERSISTENCE, false, msg).await;
                    if sleep_or_shutdown(backoff.next_delay(), &mut ctx.shutdown).await {
                        return;
                    }
                }
            }
        }
    }
}

/// Runs one scan in a blocking thread and emits the differences. `Err` = internal failure.
async fn scan_and_emit(
    tx: &mpsc::Sender<MonitorEvent>,
    current: &mut Vec<PersistenceItem>,
    scanner: &mut Option<Scanner>,
    homes: &[PathBuf],
    console: Option<ConsoleUser>,
    kind: ScanKind,
) -> Result<usize, String> {
    let mut s = scanner.take().unwrap_or_default();
    let homes_owned = homes.to_vec();
    let slow = matches!(kind, ScanKind::Full);
    let joined = tokio::task::spawn_blocking(move || {
        let outcome = s.scan(&homes_owned, console.as_ref(), slow);
        (s, outcome)
    })
    .await;
    let (s, outcome) = joined.map_err(|e| format!("analyse de persistance interrompue : {e}"))?;
    *scanner = Some(s);
    let failed = outcome.failed_sources.len();
    let new = carry_over(current, outcome, slow);
    let changes = diff(current, &new);
    for (item, change) in changes.iter().cloned() {
        if tx
            .send(MonitorEvent::Persistence { item, change })
            .await
            .is_err()
        {
            return Err("canal du daemon fermé".into());
        }
    }
    if failed > 0 {
        tracing::debug!(
            failed,
            "some persistence sources unavailable, previous items kept"
        );
    }
    *current = new;
    Ok(changes.len())
}

async fn run_loop(
    ctx: &mut MonitorContext,
    current: &mut Vec<PersistenceItem>,
    scanner: &mut Option<Scanner>,
    first: &mut bool,
) -> Result<(), String> {
    let mut console = console_user().or_else(|| ctx.user.clone());
    let mut homes = user_homes(console.as_ref());
    let trigger = persistence_trigger();

    if *first {
        scan_and_emit(
            &ctx.tx,
            current,
            scanner,
            &homes,
            console.clone(),
            ScanKind::Full,
        )
        .await?;
        *first = false;
    }
    send_health(
        &ctx.tx,
        MONITOR_PERSISTENCE,
        true,
        format!("{} élément(s) de persistance suivis", current.len()),
    )
    .await;

    // FSEvents on quiet folders -> fast rescan.
    let (raw_tx, mut raw_rx) = mpsc::channel::<()>(64);
    let make_watcher = |dirs: &[PathBuf],
                        raw_tx: mpsc::Sender<()>|
     -> Option<notify::RecommendedWatcher> {
        use notify::Watcher;
        let mut w = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if res.is_ok() {
                let _ = raw_tx.try_send(());
            }
        })
        .map_err(|e| tracing::warn!(error = %e, "persistence watcher unavailable, polling only"))
        .ok()?;
        for d in dirs {
            if let Err(e) = w.watch(d, notify::RecursiveMode::NonRecursive) {
                tracing::debug!(dir = %d.display(), error = %e, "cannot watch persistence folder");
            }
        }
        Some(w)
    };
    let mut fs_watcher = make_watcher(&watched_dirs(&homes), raw_tx.clone());

    let interval_minutes = |ctx: &MonitorContext| {
        u64::from(
            ctx.config
                .borrow()
                .persistence
                .full_scan_interval_minutes
                .max(5),
        )
    };
    let mut next_full =
        tokio::time::Instant::now() + Duration::from_secs(interval_minutes(ctx) * 60);
    let mut pending_fast: Option<tokio::time::Instant> = None;
    let mut pending_full: Option<tokio::time::Instant> = None;
    let mut polled = polled_files(&homes);
    let mut signature = stat_signature(&polled);
    let mut stat_tick =
        tokio::time::interval_at(tokio::time::Instant::now() + STAT_POLL, STAT_POLL);
    stat_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let deadline = [Some(next_full), pending_fast, pending_full]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(next_full);
        tokio::select! {
            _ = wait_shutdown(&mut ctx.shutdown) => return Ok(()),
            r = ctx.config.changed() => {
                if r.is_err() {
                    return Ok(());
                }
                if !ctx.config.borrow().persistence.enabled {
                    return Err("Surveillance de la persistance désactivée (configuration)".into());
                }
                next_full = next_full.min(tokio::time::Instant::now() + Duration::from_secs(interval_minutes(ctx) * 60));
            }
            Some(()) = raw_rx.recv() => {
                pending_fast.get_or_insert(tokio::time::Instant::now() + FAST_DEBOUNCE);
            }
            _ = trigger.notified() => {
                pending_full.get_or_insert(tokio::time::Instant::now() + FULL_DEBOUNCE);
            }
            _ = stat_tick.tick() => {
                let fresh = console_user();
                if fresh.is_some() && fresh != console {
                    console = fresh;
                    homes = user_homes(console.as_ref());
                    polled = polled_files(&homes);
                    drop(fs_watcher.take());
                    fs_watcher = make_watcher(&watched_dirs(&homes), raw_tx.clone());
                    pending_fast.get_or_insert(tokio::time::Instant::now());
                }
                let sig = stat_signature(&polled);
                if sig != signature {
                    signature = sig;
                    pending_fast.get_or_insert(tokio::time::Instant::now());
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                let now = tokio::time::Instant::now();
                let full_due = now >= next_full || pending_full.map(|d| now >= d).unwrap_or(false);
                let fast_due = pending_fast.map(|d| now >= d).unwrap_or(false);
                if full_due {
                    pending_full = None;
                    pending_fast = None;
                    next_full = now + Duration::from_secs(interval_minutes(ctx) * 60);
                    scan_and_emit(&ctx.tx, current, scanner, &homes, console.clone(), ScanKind::Full).await?;
                } else if fast_due {
                    pending_fast = None;
                    scan_and_emit(&ctx.tx, current, scanner, &homes, console.clone(), ScanKind::Fast).await?;
                }
                signature = stat_signature(&polled);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_core::config::Config;
    use pb_core::paths::Paths;
    use tokio::sync::watch;

    fn item(kind: PersistenceKind, path: &str, label: Option<&str>) -> PersistenceItem {
        PersistenceItem {
            id: item_id(kind, path, label),
            kind,
            label: label.map(str::to_string),
            path: path.into(),
            program: Some("/bin/x".into()),
            arguments: vec![],
            user: None,
            signing: None,
            program_sha256: Some("aa".into()),
            first_seen: 0,
            last_seen: 0,
            status: PersistenceStatus::New,
            verdict: None,
        }
    }

    #[test]
    fn ids_are_stable_and_documented() {
        let id = item_id(
            PersistenceKind::LaunchAgent,
            "/Library/LaunchAgents/a.plist",
            Some("a"),
        );
        assert_eq!(
            id,
            crate::util::sha256_bytes(b"launch_agent|/Library/LaunchAgents/a.plist|a")[..16]
        );
        assert_ne!(
            id,
            item_id(
                PersistenceKind::LaunchDaemon,
                "/Library/LaunchAgents/a.plist",
                Some("a")
            )
        );
        assert_eq!(
            item_id(PersistenceKind::Cron, "/etc/crontab", None),
            crate::util::sha256_bytes(b"cron|/etc/crontab|")[..16]
        );
        assert_eq!(
            kind_name(PersistenceKind::BackgroundItem),
            "background_item"
        );
    }

    #[test]
    fn diff_detects_changes() {
        let a = item(PersistenceKind::LaunchAgent, "/a.plist", Some("a"));
        let b = item(PersistenceKind::LaunchDaemon, "/b.plist", Some("b"));
        let c = item(PersistenceKind::Cron, "/c", None);
        let mut b2 = b.clone();
        b2.program_sha256 = Some("bb".into());
        let mut a_unknown_hash = a.clone();
        a_unknown_hash.program_sha256 = None;
        let changes = diff(
            &[a.clone(), b.clone()],
            &[a_unknown_hash, b2.clone(), c.clone()],
        );
        assert_eq!(changes.len(), 2);
        assert!(changes.contains(&(b2, PersistenceChangeKind::Modified)));
        assert!(changes.contains(&(c.clone(), PersistenceChangeKind::Added)));
        let changes = diff(&[a.clone(), c.clone()], &[c]);
        assert_eq!(changes, vec![(a, PersistenceChangeKind::Removed)]);
    }

    #[test]
    fn failed_sources_are_carried_over() {
        let btm = item(
            PersistenceKind::BackgroundItem,
            "/Applications/X.app",
            Some("x"),
        );
        let la = item(
            PersistenceKind::LaunchAgent,
            "/Users/q/Library/LaunchAgents/a.plist",
            Some("a"),
        );
        let gone = item(
            PersistenceKind::LaunchAgent,
            "/Library/LaunchAgents/gone.plist",
            Some("g"),
        );
        let prev = vec![btm.clone(), la.clone(), gone.clone()];
        // fast scan: slow sources not scanned, user folder unreadable, /Library/LaunchAgents read fine
        let outcome = ScanOutcome {
            failed_prefixes: vec![PathBuf::from("/Users/q/Library/LaunchAgents")],
            ..Default::default()
        };
        let merged = carry_over(&prev, outcome, false);
        assert!(merged.contains(&btm) && merged.contains(&la) && !merged.contains(&gone));
        // full scan where sfltool failed
        let mut outcome = ScanOutcome::default();
        outcome.failed_sources.insert(sources::Source::Btm);
        let merged = carry_over(&prev, outcome, true);
        assert_eq!(merged, vec![btm]);
    }

    #[tokio::test]
    async fn watcher_reports_startup_diff_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let ghost = item(
            PersistenceKind::LaunchDaemon,
            "/Library/LaunchDaemons/parabellum-test-ghost.plist",
            Some("ghost"),
        );
        let mut already_removed = item(
            PersistenceKind::LaunchDaemon,
            "/Library/LaunchDaemons/parabellum-test-old.plist",
            Some("old"),
        );
        already_removed.status = PersistenceStatus::Removed;
        let (_c, cfg_rx) = watch::channel(Config::default());
        let (stop_tx, stop_rx) = watch::channel(false);
        let (tx, mut rx) = mpsc::channel(1024);
        let ctx = MonitorContext {
            paths: Paths::with_root(dir.path()),
            config: cfg_rx,
            user: None,
            tx,
            shutdown: stop_rx,
        };
        let task = tokio::spawn(
            PersistenceWatcher {
                known: vec![ghost.clone(), already_removed],
            }
            .run(ctx),
        );
        let mut saw_ghost_removed = false;
        let mut saw_old = false;
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(60), rx.recv())
                .await
                .unwrap()
                .unwrap();
            match ev {
                MonitorEvent::Persistence { item, change } => {
                    if item.id == ghost.id {
                        assert_eq!(change, PersistenceChangeKind::Removed);
                        saw_ghost_removed = true;
                    }
                    if item.label.as_deref() == Some("old") {
                        saw_old = true;
                    }
                }
                MonitorEvent::MonitorHealth { ok, .. } => {
                    assert!(ok);
                    break;
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(saw_ghost_removed);
        assert!(
            !saw_old,
            "items already removed in the DB are not reported again"
        );
        stop_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
    }
}
