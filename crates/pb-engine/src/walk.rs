//! What a scan visits, and how many threads analyse it.
//!
//! **Each file system object once.** Roots are deduplicated by `(st_dev, st_ino)`: the same folder
//! given twice, or under two names (`/tmp` and `/private/tmp`, a symlink, a firmlink), is walked once.
//! A root inside another root (`~` and `~/Downloads`) is skipped where the outer walk meets it and
//! walked on its own, so it is never walked twice. A file given as a root is not scanned again when the
//! walk of a folder root meets it. With `follow_symlinks`, a folder reached twice through links is
//! entered once. Hard links and copies of the same content still go through the scan cache.
//!
//! **Parallel analysis.** One thread walks and feeds a bounded queue; `ScanOptions::workers` threads
//! analyse (each with its own YARA scanner), all at the caller thread's QoS and I/O policy; reports are
//! delivered on the caller thread, as before. ClamAV stays one batch / one `clamscan` at a time (≈ 1 GB
//! of RAM each), and heavy files (large ones, disk images, packages, archives) one at a time, so N
//! workers never hold N × 64 MB buffers or N mounted DMGs.

use crate::{is_dataless, Analysis, ClamBatch, Ctx, Engine, ScanOptions, ScanTotals};
use pb_core::model::ScanReport;
use std::collections::HashSet;
use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex, MutexGuard};

/// Files at least this large are analysed one at a time (their first 64 MB are held in memory).
pub const HEAVY_BYTES: u64 = 8 * 1024 * 1024;
/// Extensions of containers mounted / expanded / unpacked during analysis: one at a time too.
const HEAVY_EXTENSIONS: &[&str] = &[
    "dmg",
    "sparseimage",
    "sparsebundle",
    "iso",
    "pkg",
    "mpkg",
    "xip",
    "zip",
    "jar",
    "ipa",
    "apk",
    "tar",
    "gz",
    "tgz",
    "bz2",
    "xz",
    "7z",
    "rar",
];
/// Upper bound of automatic worker counts.
pub const MAX_AUTO_WORKERS: usize = 6;
/// Upper bound of `ScanOptions::workers`.
pub const MAX_WORKERS: usize = 16;

/// Worker threads when the configuration says "automatic": half the cores (on Apple silicon,
/// background-QoS work runs on the efficiency cores anyway), between 1 and [`MAX_AUTO_WORKERS`].
pub fn auto_workers() -> usize {
    let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
    (cores / 2).clamp(1, MAX_AUTO_WORKERS)
}

pub(crate) fn is_heavy(path: &Path, size: u64) -> bool {
    size >= HEAVY_BYTES
        || path.extension().is_some_and(|e| {
            let e = e.to_string_lossy();
            HEAVY_EXTENSIONS.iter().any(|h| e.eq_ignore_ascii_case(h))
        })
}

/// One thing found by the walk.
pub(crate) enum Item {
    File(PathBuf, Option<Metadata>),
    /// Unreadable root / folder.
    Error(ScanReport),
}

type Id = (u64, u64);

fn id(m: &Metadata) -> Id {
    (m.dev(), m.ino())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

enum Root {
    File(PathBuf, Metadata),
    Dir(PathBuf),
}

/// Walks `paths` (see the module doc), emitting every regular file to analyse once.
pub(crate) fn walk(
    engine: &Engine,
    paths: &[PathBuf],
    opts: &ScanOptions,
    cancel: &AtomicBool,
    emit: &mut dyn FnMut(Item),
) {
    let error = |path: &Path, msg: String| {
        Item::Error(ScanReport {
            path: path.to_string_lossy().into_owned(),
            error: Some(msg),
            ..Default::default()
        })
    };
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    let mut dir_ids = HashSet::new();
    let mut file_ids = HashSet::new();
    for root in paths {
        if engine.is_excluded(root, opts) {
            continue;
        }
        let meta = if opts.follow_symlinks {
            std::fs::metadata(root)
        } else {
            std::fs::symlink_metadata(root)
        };
        let meta = match meta {
            Ok(m) => m,
            Err(e) => {
                emit(error(root, format!("cannot access: {e}")));
                continue;
            }
        };
        // The same object twice (or under two names).
        if !seen.insert(id(&meta)) {
            continue;
        }
        if meta.is_file() {
            if opts.skip_dataless && is_dataless(&meta) {
                continue;
            }
            file_ids.insert(id(&meta));
            roots.push(Root::File(root.clone(), meta));
        } else if meta.is_dir() {
            dir_ids.insert(id(&meta));
            roots.push(Root::Dir(root.clone()));
        }
    }
    // Folder identities are only needed when two walks could meet.
    let track_dirs = dir_ids.len() > 1 || opts.follow_symlinks;
    let mut visited: HashSet<Id> = if opts.follow_symlinks {
        dir_ids.clone()
    } else {
        HashSet::new()
    };

    for root in roots {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let root = match root {
            Root::File(p, m) => {
                emit(Item::File(p, Some(m)));
                continue;
            }
            Root::Dir(p) => p,
        };
        let walker = walkdir::WalkDir::new(&root)
            .follow_links(opts.follow_symlinks)
            .max_depth(if opts.recursive { usize::MAX } else { 1 })
            .into_iter()
            .filter_entry(|e| {
                if engine.is_excluded(e.path(), opts) || !Engine::walk_allowed(e, opts) {
                    return false;
                }
                if e.depth() == 0 || !track_dirs || !e.file_type().is_dir() {
                    return true;
                }
                let Ok(m) = e.metadata() else {
                    return true;
                };
                let d = id(&m);
                // Another root: walked on its own.
                if dir_ids.contains(&d) {
                    return false;
                }
                // Reached again through a followed link.
                !opts.follow_symlinks || visited.insert(d)
            });
        for entry in walker {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    let path = e.path().map_or_else(|| root.clone(), Path::to_path_buf);
                    emit(error(&path, format!("cannot read: {e}")));
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let meta = entry.metadata().ok();
            if let Some(m) = &meta {
                if opts.skip_dataless && is_dataless(m) {
                    continue;
                }
                // Given as a root: already scanned.
                if !file_ids.is_empty() && file_ids.contains(&id(m)) {
                    continue;
                }
            }
            emit(Item::File(entry.into_path(), meta));
        }
    }
}

impl Engine {
    /// Analyses what [`walk`] finds with `opts.workers` threads; `deliver` runs on the caller thread.
    pub(crate) fn scan_parallel(
        &self,
        paths: &[PathBuf],
        opts: &ScanOptions,
        cancel: &AtomicBool,
        deliver: &mut dyn FnMut(&ScanReport, bool),
    ) {
        let workers = opts.workers.clamp(1, MAX_WORKERS);
        let qos = qos::ThreadQos::current();
        let (job_tx, job_rx) = mpsc::sync_channel::<(PathBuf, Option<Metadata>)>(workers * 32);
        let job_rx = Mutex::new(job_rx);
        let (rep_tx, rep_rx) = mpsc::sync_channel::<(ScanReport, bool)>(256);
        let shared = Mutex::new(ClamBatch::default());
        let clam_run = Mutex::new(());
        let heavy = Mutex::new(());

        std::thread::scope(|s| {
            let walk_tx = rep_tx.clone();
            s.spawn(move || {
                qos.apply();
                walk(self, paths, opts, cancel, &mut |item| match item {
                    Item::File(p, m) => {
                        let _ = job_tx.send((p, m));
                    }
                    Item::Error(r) => {
                        let _ = walk_tx.send((r, false));
                    }
                });
            });
            for _ in 0..workers {
                let tx = rep_tx.clone();
                let (job_rx, shared, clam_run, heavy) = (&job_rx, &shared, &clam_run, &heavy);
                s.spawn(move || {
                    qos.apply();
                    let mut ctx = self.new_ctx(opts, cancel);
                    let send = |r: &ScanReport, member: bool| {
                        let _ = tx.send((r.clone(), member));
                    };
                    loop {
                        let next = lock(job_rx).recv();
                        let Ok((path, meta)) = next else { break };
                        // Cancelled: drain the queue so the walker never blocks.
                        if ctx.cancelled() {
                            continue;
                        }
                        self.analyse_shared(&mut ctx, &path, meta, shared, clam_run, heavy, &send);
                    }
                });
            }
            drop(rep_tx);
            for (r, member) in rep_rx {
                // Cancelled: what the workers still had in hand is drained, not delivered (the serial
                // scan would not have analysed it either).
                if !cancel.load(Ordering::Relaxed) {
                    deliver(&r, member);
                }
            }
        });
        // What is left of the ClamAV batch (without ClamAV if cancelled).
        let mut batch = shared.into_inner().unwrap_or_else(|e| e.into_inner());
        self.flush_batch(
            &mut batch,
            opts,
            cancel,
            &mut |r, member, _| deliver(r, member),
            &mut ScanTotals::default(),
        );
    }

    /// [`Engine::process_candidate`] for a worker: shared ClamAV batch, heavy files one at a time.
    #[allow(clippy::too_many_arguments)]
    fn analyse_shared<'e>(
        &'e self,
        ctx: &mut Ctx<'e>,
        path: &Path,
        meta: Option<Metadata>,
        shared: &Mutex<ClamBatch>,
        clam_run: &Mutex<()>,
        heavy: &Mutex<()>,
        send: &dyn Fn(&ScanReport, bool),
    ) {
        if !Self::wanted(ctx.opts, path, meta.as_ref()) {
            return;
        }
        let size = meta.as_ref().map_or(0, Metadata::len);
        let gate = is_heavy(path, size).then(|| lock(heavy));
        let display = path.to_string_lossy().into_owned();
        let mut a: Analysis = self.scan_top(ctx, path, display, &mut |m| send(&m, true));
        drop(gate);
        let Some(p) = a.clamav_path.take() else {
            self.complete(&mut a);
            send(&a.report, false);
            return;
        };
        let full = {
            let mut b = lock(shared);
            b.push(a, p);
            b.is_full().then(|| std::mem::take(&mut *b))
        };
        if let Some(mut b) = full {
            {
                let _one_clamscan = lock(clam_run);
                self.clamav_merge(&mut b.items, &b.paths, ctx.opts, ctx.cancel);
            }
            for mut a in b.items.drain(..) {
                self.complete(&mut a);
                send(&a.report, false);
            }
        }
    }
}

/// The caller's QoS class and disk I/O policy, applied to the scan threads (macOS; no-op elsewhere).
mod qos {
    #[derive(Debug, Clone, Copy)]
    pub struct ThreadQos {
        #[cfg(target_os = "macos")]
        class: u32,
        #[cfg(target_os = "macos")]
        io: libc::c_int,
    }

    #[cfg(target_os = "macos")]
    mod ffi {
        // <sys/qos.h>, <sys/resource.h>
        pub const QOS_CLASS_UNSPECIFIED: u32 = 0x00;
        pub const IOPOL_TYPE_DISK: libc::c_int = 0;
        pub const IOPOL_SCOPE_THREAD: libc::c_int = 1;
        extern "C" {
            pub fn pthread_set_qos_class_self_np(
                qos_class: u32,
                relative_priority: libc::c_int,
            ) -> libc::c_int;
            pub fn qos_class_self() -> u32;
            pub fn setiopolicy_np(
                iotype: libc::c_int,
                scope: libc::c_int,
                policy: libc::c_int,
            ) -> libc::c_int;
            pub fn getiopolicy_np(iotype: libc::c_int, scope: libc::c_int) -> libc::c_int;
        }
    }

    impl ThreadQos {
        pub fn current() -> Self {
            #[cfg(target_os = "macos")]
            {
                // SAFETY: plain libSystem queries on the current thread.
                unsafe {
                    Self {
                        class: ffi::qos_class_self(),
                        io: ffi::getiopolicy_np(ffi::IOPOL_TYPE_DISK, ffi::IOPOL_SCOPE_THREAD),
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                Self {}
            }
        }

        /// On the current (new) thread.
        pub fn apply(self) {
            #[cfg(target_os = "macos")]
            {
                // SAFETY: plain libSystem calls acting on the current thread; failures are harmless.
                unsafe {
                    if self.class != ffi::QOS_CLASS_UNSPECIFIED {
                        ffi::pthread_set_qos_class_self_np(self.class, 0);
                    }
                    if self.io >= 0 {
                        ffi::setiopolicy_np(ffi::IOPOL_TYPE_DISK, ffi::IOPOL_SCOPE_THREAD, self.io);
                    }
                }
            }
        }
    }
}
