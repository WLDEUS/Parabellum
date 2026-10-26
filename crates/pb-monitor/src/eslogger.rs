//! [`EsLoggerWatcher`]: real-time process / file / persistence / mount events from Apple's
//! `/usr/bin/eslogger` (Endpoint Security, observe-only; requires root + Full Disk Access for the
//! responsible process, i.e. `parabellumd`).
//!
//! eslogger prints one JSON object per line ("JSON Lines"). There is no formal schema: the data is
//! modelled on `es_message_t` (field names follow the C structs). Top level: `schema_version`,
//! `event_type` (number), `time`, `process` (`es_process_t`: `audit_token{pid,euid,…}`, `ppid`,
//! `executable{path,stat}`, `signing_id`, `team_id`, `cdhash`, `is_platform_binary`,
//! `codesigning_flags`…) and `event: { "<short event name>": {…} }`. Parsing is tolerant: unknown
//! fields are ignored and events missing a required field are skipped.
//!
//! Events used: `exec` (-> `ProcessExec`, platform binaries skipped), `create` / `rename`
//! (-> `FileActivity` for interesting locations only), optional `close` with `modified == true`,
//! `btm_launch_item_add` (-> [`crate::persistence_trigger`]), `mount` / `unmount`
//! (-> [`crate::volume_trigger`]). eslogger itself suppresses events from its own process group,
//! i.e. from the daemon and every tool it spawns.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use pb_core::events::{EsProcessInfo, FileEventSource, MonitorEvent};
use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};
use tokio::sync::mpsc;

use crate::util::{
    expand_paths, is_shutdown, send_health, sleep_or_shutdown, under_any, wait_shutdown, Backoff,
};
use crate::{console_user, persistence_trigger, volume_trigger, MonitorContext, MONITOR_ESLOGGER};

/// Absolute path of Apple's tool.
pub const ESLOGGER_PATH: &str = "/usr/bin/eslogger";
/// Health message when the daemon lacks Full Disk Access (eslogger cannot create its ES client).
pub const FDA_REQUIRED_MESSAGE: &str = "Accès complet au disque requis pour parabellumd";
/// Retry period while Full Disk Access is missing.
const FDA_RETRY: Duration = Duration::from_secs(60);
/// Capacity of the stderr line buffer.
const STDERR_LINE_MAX: usize = 8 * 1024;

/// Tunables of [`EsLoggerWatcher`]; [`EsLoggerWatcher::run`] uses `Default`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsLoggerOptions {
    /// Also subscribe to `close` (reported only when `modified == true`). Off by default: ES emits
    /// a `close` for every file close on the system, which costs CPU in eslogger and here, and
    /// FSEvents + `create`/`rename` already cover the watched locations.
    pub include_close: bool,
    /// Lines beyond this rate are dropped without being parsed (counted and reported).
    pub max_events_per_sec: u32,
    /// Longer lines are discarded.
    pub max_line_bytes: usize,
}

impl Default for EsLoggerOptions {
    fn default() -> Self {
        Self {
            include_close: false,
            max_events_per_sec: 2_000,
            max_line_bytes: 1024 * 1024,
        }
    }
}

/// eslogger arguments: `--format json <events…>`.
pub fn eslogger_args(opts: &EsLoggerOptions) -> Vec<&'static str> {
    let mut v = vec![
        "--format",
        "json",
        "exec",
        "create",
        "rename",
        "btm_launch_item_add",
        "mount",
        "unmount",
    ];
    if opts.include_close {
        v.push("close");
    }
    v
}

/// Streams eslogger events (see module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct EsLoggerWatcher;

// ---------------------------------------------------------------------------------------------
// Parsing (pure, tested on Linux with fixtures)
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
struct RawAuditToken {
    pid: Option<i32>,
    euid: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
struct RawStat {
    st_mode: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
struct RawFile {
    path: Option<String>,
    #[serde(default)]
    path_truncated: bool,
    stat: Option<RawStat>,
}

#[derive(Debug, Deserialize, Default)]
struct RawProcess {
    audit_token: Option<RawAuditToken>,
    ppid: Option<i32>,
    executable: Option<RawFile>,
    signing_id: Option<String>,
    team_id: Option<String>,
    cdhash: Option<String>,
    is_platform_binary: Option<bool>,
    codesigning_flags: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct RawExec {
    target: RawProcess,
    #[serde(default)]
    args: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct RawCreate {
    destination: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct RawRename {
    destination: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct RawClose {
    #[serde(default)]
    modified: bool,
    target: Option<RawFile>,
}

#[derive(Debug, Deserialize, Default)]
struct RawEvent {
    exec: Option<RawExec>,
    create: Option<RawCreate>,
    rename: Option<RawRename>,
    close: Option<RawClose>,
    btm_launch_item_add: Option<serde::de::IgnoredAny>,
    mount: Option<serde::de::IgnoredAny>,
    unmount: Option<serde::de::IgnoredAny>,
}

#[derive(Debug, Deserialize)]
struct RawMessage {
    process: Option<RawProcess>,
    event: RawEvent,
}

/// Maximum number of `exec` arguments kept, and characters per argument.
const MAX_ARGS: usize = 64;
const MAX_ARG_CHARS: usize = 1024;

/// One eslogger line, decoded.
#[derive(Debug, Clone, PartialEq)]
pub enum EsEvent {
    Exec {
        target: EsProcessInfo,
        args: Vec<String>,
        parent: Option<EsProcessInfo>,
    },
    File {
        path: String,
        source: FileEventSource,
        process: Option<EsProcessInfo>,
        is_dir: bool,
    },
    BtmLaunchItemAdd,
    Mount,
    Unmount,
}

fn process_info(p: &RawProcess) -> Option<EsProcessInfo> {
    let exe = p.executable.as_ref()?;
    let path = exe.path.clone().filter(|s| !s.is_empty())?;
    let token = p.audit_token.as_ref();
    Some(EsProcessInfo {
        pid: token.and_then(|t| t.pid).unwrap_or(-1),
        ppid: p.ppid.unwrap_or(-1),
        path,
        signing_id: p.signing_id.clone().filter(|s| !s.is_empty()),
        team_id: p.team_id.clone().filter(|s| !s.is_empty()),
        cdhash: p.cdhash.clone().filter(|s| !s.is_empty()),
        is_platform_binary: p.is_platform_binary.unwrap_or(false),
        codesigning_flags: p
            .codesigning_flags
            .map(|f| (f & 0xffff_ffff) as u32)
            .unwrap_or(0),
        uid: token.and_then(|t| t.euid).unwrap_or(u32::MAX),
    })
}

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

fn file_from_value(v: &Value) -> Option<(String, bool)> {
    let path = v.get("path")?.as_str()?.to_string();
    if path.is_empty()
        || v.get("path_truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    {
        return None;
    }
    let is_dir = v
        .get("stat")
        .and_then(|s| s.get("st_mode"))
        .and_then(Value::as_u64)
        .map(|m| (m as u32) & S_IFMT == S_IFDIR)
        .unwrap_or(false);
    Some((path, is_dir))
}

/// Destination of `create` / `rename`: `{"existing_file": file}` or
/// `{"new_path": {"dir": file, "filename": "…", "mode": n}}` (C union in `es_event_create_t`).
/// A bare file object is accepted too.
fn destination_path(dest: &Value) -> Option<(String, bool)> {
    if let Some(f) = dest.get("existing_file") {
        return file_from_value(f);
    }
    if let Some(np) = dest.get("new_path") {
        let (dir, _) = file_from_value(np.get("dir")?)?;
        let name = np.get("filename")?.as_str()?;
        if name.is_empty() || name.contains('/') {
            return None;
        }
        let is_dir = np
            .get("mode")
            .and_then(Value::as_u64)
            .map(|m| (m as u32) & S_IFMT == S_IFDIR)
            .unwrap_or(false);
        let joined = if dir.ends_with('/') {
            format!("{dir}{name}")
        } else {
            format!("{dir}/{name}")
        };
        return Some((joined, is_dir));
    }
    file_from_value(dest)
}

/// Decodes one eslogger JSON line. Returns `None` for malformed lines, unknown event kinds,
/// `close` without modification and events missing required fields.
pub fn parse_line(line: &[u8]) -> Option<EsEvent> {
    let msg: RawMessage = match serde_json::from_slice(line) {
        Ok(m) => m,
        Err(e) => {
            tracing::trace!(error = %e, "unparsable eslogger line");
            return None;
        }
    };
    let process = msg.process.as_ref().and_then(process_info);
    let ev = msg.event;
    if let Some(exec) = ev.exec {
        let target = process_info(&exec.target)?;
        let args = exec
            .args
            .iter()
            .take(MAX_ARGS)
            .map(|a| match a {
                Value::String(s) => crate::util::clip(s, MAX_ARG_CHARS),
                other => crate::util::clip(&other.to_string(), MAX_ARG_CHARS),
            })
            .collect();
        return Some(EsEvent::Exec {
            target,
            args,
            parent: process,
        });
    }
    if let Some(c) = ev.create {
        let (path, is_dir) = destination_path(c.destination.as_ref()?)?;
        return Some(EsEvent::File {
            path,
            source: FileEventSource::EsCreate,
            process,
            is_dir,
        });
    }
    if let Some(r) = ev.rename {
        let (path, is_dir) = destination_path(r.destination.as_ref()?)?;
        return Some(EsEvent::File {
            path,
            source: FileEventSource::EsRename,
            process,
            is_dir,
        });
    }
    if let Some(c) = ev.close {
        if !c.modified {
            return None;
        }
        let t = c.target?;
        if t.path_truncated {
            return None;
        }
        let path = t.path.filter(|p| !p.is_empty())?;
        let is_dir = t
            .stat
            .and_then(|s| s.st_mode)
            .map(|m| m & S_IFMT == S_IFDIR)
            .unwrap_or(false);
        return Some(EsEvent::File {
            path,
            source: FileEventSource::EsCloseModified,
            process,
            is_dir,
        });
    }
    if ev.btm_launch_item_add.is_some() {
        return Some(EsEvent::BtmLaunchItemAdd);
    }
    if ev.mount.is_some() {
        return Some(EsEvent::Mount);
    }
    if ev.unmount.is_some() {
        return Some(EsEvent::Unmount);
    }
    None
}

/// Which eslogger file events are interesting: watched folders, launchd persistence folders,
/// temp folders and `/Users/Shared`; never our own root, never excluded paths.
#[derive(Debug, Clone)]
pub(crate) struct EsFilter {
    pub own_pid: i32,
    pub own_root: PathBuf,
    pub prefixes: Vec<PathBuf>,
    pub excludes: Vec<PathBuf>,
}

/// Fixed locations always reported (in addition to `scan.watch_paths`).
pub(crate) const ALWAYS_WATCHED: &[&str] = &[
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/tmp",
    "/private/tmp",
    "/var/tmp",
    "/private/var/tmp",
    "/Users/Shared",
];

impl EsFilter {
    pub(crate) fn new(cfg: &pb_core::config::Config, home: Option<&Path>, own_root: &Path) -> Self {
        let mut prefixes = expand_paths(&cfg.scan.watch_paths, home);
        for p in ALWAYS_WATCHED {
            prefixes.push(PathBuf::from(p));
        }
        Self {
            own_pid: std::process::id() as i32,
            own_root: own_root.to_path_buf(),
            prefixes,
            excludes: expand_paths(&cfg.scan.exclude_paths, home),
        }
    }

    pub(crate) fn accept_file(&self, path: &str, process: Option<&EsProcessInfo>) -> bool {
        if process.map(|p| p.pid == self.own_pid).unwrap_or(false) {
            return false;
        }
        let p = Path::new(path);
        if !p.is_absolute() || p.starts_with(&self.own_root) || under_any(p, &self.excludes) {
            return false;
        }
        if crate::fs_watcher::is_ignored_artefact(p) {
            return false;
        }
        if under_any(p, &self.prefixes) {
            return true;
        }
        // Any user's ~/Library/LaunchAgents.
        let mut comps = p
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned());
        let first: Vec<String> = comps.by_ref().take(5).collect();
        first.len() == 5
            && first[1] == "Users"
            && first[3] == "Library"
            && first[4] == "LaunchAgents"
    }
}

// ---------------------------------------------------------------------------------------------
// Bounded line reader (cancel-safe: all state lives in the struct)
// ---------------------------------------------------------------------------------------------

/// Outcome of [`LineReader::next_line`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Line {
    /// A complete line (without the `\n`) is in [`LineReader::line`].
    Ready,
    /// A line longer than the limit was skipped.
    TooLong,
    Eof,
}

pub(crate) struct LineReader<R> {
    inner: R,
    max: usize,
    pub(crate) line: Vec<u8>,
    discarding: bool,
    ready: bool,
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    pub(crate) fn new(inner: R, max: usize) -> Self {
        Self {
            inner,
            max,
            line: Vec::new(),
            discarding: false,
            ready: false,
        }
    }

    /// Reads the next line. Cancel-safe: bytes already consumed are kept in `self.line`.
    pub(crate) async fn next_line(&mut self) -> std::io::Result<Line> {
        if self.ready {
            self.line.clear();
            self.ready = false;
        }
        loop {
            let buf = self.inner.fill_buf().await?;
            if buf.is_empty() {
                if !self.line.is_empty() && !self.discarding {
                    self.ready = true;
                    return Ok(Line::Ready);
                }
                return Ok(Line::Eof);
            }
            let (chunk, found) = match buf.iter().position(|&b| b == b'\n') {
                Some(i) => (&buf[..i], Some(i + 1)),
                None => (buf, None),
            };
            if !self.discarding {
                if self.line.len() + chunk.len() > self.max {
                    self.discarding = true;
                    self.line.clear();
                } else {
                    self.line.extend_from_slice(chunk);
                }
            }
            let consumed = found.unwrap_or(buf.len());
            self.inner.consume(consumed);
            if found.is_some() {
                if self.discarding {
                    self.discarding = false;
                    self.line.clear();
                    return Ok(Line::TooLong);
                }
                self.ready = true;
                return Ok(Line::Ready);
            }
        }
    }
}

/// Fixed-window rate limiter (events per second).
#[derive(Debug)]
pub(crate) struct RateLimiter {
    max: u32,
    window_start: Instant,
    count: u32,
    pub(crate) dropped: u64,
}

impl RateLimiter {
    pub(crate) fn new(max: u32, now: Instant) -> Self {
        Self {
            max: max.max(1),
            window_start: now,
            count: 0,
            dropped: 0,
        }
    }
    pub(crate) fn allow(&mut self, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.count = 0;
        }
        if self.count >= self.max {
            self.dropped += 1;
            false
        } else {
            self.count += 1;
            true
        }
    }
}

/// Classification of eslogger's stderr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StderrKind {
    NeedsFullDiskAccess,
    NotRoot,
    Other,
}

pub(crate) fn classify_stderr(line: &str) -> StderrKind {
    let l = line.to_ascii_lowercase();
    if l.contains("not_permitted")
        || l.contains("not permitted")
        || l.contains("full disk access")
        || l.contains("tcc")
    {
        StderrKind::NeedsFullDiskAccess
    } else if l.contains("not_privileged")
        || l.contains("not privileged")
        || l.contains("must be run as root")
        || l.contains("super-user")
    {
        StderrKind::NotRoot
    } else {
        StderrKind::Other
    }
}

// ---------------------------------------------------------------------------------------------
// Watcher
// ---------------------------------------------------------------------------------------------

enum Outcome {
    Shutdown,
    NeedsFda,
    NotRoot,
    Reconfigure,
    Exited(String),
}

impl EsLoggerWatcher {
    /// Runs with [`EsLoggerOptions::default`] until shutdown.
    pub async fn run(self, ctx: MonitorContext) {
        self.run_with_options(ctx, EsLoggerOptions::default()).await
    }

    /// Runs until shutdown. Honors `realtime.enabled && realtime.eslogger`. On Linux it reports
    /// `ok=false "eslogger indisponible (macOS uniquement)"` and idles.
    pub async fn run_with_options(self, mut ctx: MonitorContext, opts: EsLoggerOptions) {
        if !cfg!(target_os = "macos") {
            send_health(
                &ctx.tx,
                MONITOR_ESLOGGER,
                false,
                "eslogger indisponible (macOS uniquement)",
            )
            .await;
            wait_shutdown(&mut ctx.shutdown).await;
            return;
        }
        let mut backoff = Backoff::new(Duration::from_secs(2), Duration::from_secs(300));
        loop {
            if is_shutdown(&ctx.shutdown) {
                return;
            }
            let enabled = {
                let c = ctx.config.borrow_and_update();
                c.realtime.enabled && c.realtime.eslogger
            };
            if !enabled {
                send_health(
                    &ctx.tx,
                    MONITOR_ESLOGGER,
                    false,
                    "eslogger désactivé (configuration)",
                )
                .await;
                tokio::select! {
                    _ = wait_shutdown(&mut ctx.shutdown) => return,
                    r = ctx.config.changed() => if r.is_err() { return },
                }
                continue;
            }
            if !Path::new(ESLOGGER_PATH).is_file() {
                send_health(
                    &ctx.tx,
                    MONITOR_ESLOGGER,
                    false,
                    "eslogger introuvable (macOS 13 ou plus requis)",
                )
                .await;
                if sleep_or_shutdown(Duration::from_secs(3600), &mut ctx.shutdown).await {
                    return;
                }
                continue;
            }
            let started = Instant::now();
            match run_child(&mut ctx, &opts).await {
                Outcome::Shutdown => return,
                Outcome::Reconfigure => continue,
                Outcome::NeedsFda => {
                    send_health(&ctx.tx, MONITOR_ESLOGGER, false, FDA_REQUIRED_MESSAGE).await;
                    if sleep_or_shutdown(FDA_RETRY, &mut ctx.shutdown).await {
                        return;
                    }
                }
                Outcome::NotRoot => {
                    send_health(
                        &ctx.tx,
                        MONITOR_ESLOGGER,
                        false,
                        "eslogger exige les droits root",
                    )
                    .await;
                    if sleep_or_shutdown(Duration::from_secs(600), &mut ctx.shutdown).await {
                        return;
                    }
                }
                Outcome::Exited(msg) => {
                    if started.elapsed() > Duration::from_secs(600) {
                        backoff.reset();
                    }
                    send_health(&ctx.tx, MONITOR_ESLOGGER, false, msg).await;
                    if sleep_or_shutdown(backoff.next_delay(), &mut ctx.shutdown).await {
                        return;
                    }
                }
            }
        }
    }
}

/// Spawns eslogger and pumps its output until it exits, the config changes or shutdown.
async fn run_child(ctx: &mut MonitorContext, opts: &EsLoggerOptions) -> Outcome {
    let mut cmd = tokio::process::Command::new(ESLOGGER_PATH);
    cmd.args(eslogger_args(opts))
        .env_clear()
        .env("PATH", crate::util::TOOL_PATH_ENV)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Outcome::Exited(format!("eslogger n'a pas pu démarrer : {e}")),
    };
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill().await;
        return Outcome::Exited("eslogger : flux de sortie indisponibles".into());
    };

    // stderr: classify in a separate task, report the first fatal kind.
    let (err_tx, mut err_rx) = mpsc::channel::<(StderrKind, String)>(8);
    let stderr_task = tokio::spawn(async move {
        let mut reader = LineReader::new(tokio::io::BufReader::new(stderr), STDERR_LINE_MAX);
        while let Ok(Line::Ready | Line::TooLong) = reader.next_line().await {
            let text = String::from_utf8_lossy(&reader.line).trim().to_string();
            if text.is_empty() {
                continue;
            }
            let kind = classify_stderr(&text);
            tracing::warn!(line = %text, "eslogger stderr");
            // Receiver gone or busy: nothing else to do with the line.
            let _ = err_tx.try_send((kind, text));
        }
    });

    let mut user = ctx.user.clone().or_else(console_user);
    let mut filter = {
        let cfg = ctx.config.borrow_and_update();
        EsFilter::new(
            &cfg,
            user.as_ref().map(|u| u.home.as_path()),
            &ctx.paths.root,
        )
    };
    let mut reader = LineReader::new(
        tokio::io::BufReader::with_capacity(256 * 1024, stdout),
        opts.max_line_bytes,
    );
    let mut limiter = RateLimiter::new(opts.max_events_per_sec, Instant::now());
    let mut channel_drops: u64 = 0;
    let mut reported_drops: u64 = 0;
    let mut healthy = false;
    let mut fatal: Option<StderrKind> = None;
    let grace = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(grace);
    let mut periodic = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(60),
        Duration::from_secs(60),
    );
    periodic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let outcome = loop {
        tokio::select! {
            _ = wait_shutdown(&mut ctx.shutdown) => break Outcome::Shutdown,
            r = ctx.config.changed() => {
                if r.is_err() {
                    break Outcome::Shutdown;
                }
                let cfg = ctx.config.borrow_and_update().clone();
                if !(cfg.realtime.enabled && cfg.realtime.eslogger) {
                    break Outcome::Reconfigure;
                }
                filter = EsFilter::new(&cfg, user.as_ref().map(|u| u.home.as_path()), &ctx.paths.root);
            }
            Some((kind, text)) = err_rx.recv() => {
                if kind != StderrKind::Other {
                    fatal = Some(kind);
                } else if !healthy {
                    tracing::debug!(line = %text, "eslogger diagnostic");
                }
            }
            _ = &mut grace, if !healthy => {
                healthy = true;
                send_health(&ctx.tx, MONITOR_ESLOGGER, true, "eslogger actif").await;
            }
            _ = periodic.tick() => {
                let fresh = console_user();
                if fresh.is_some() && fresh != user {
                    user = fresh;
                    let cfg = ctx.config.borrow().clone();
                    filter = EsFilter::new(&cfg, user.as_ref().map(|u| u.home.as_path()), &ctx.paths.root);
                }
                let total = limiter.dropped + channel_drops;
                if total > reported_drops {
                    send_health(&ctx.tx, MONITOR_ESLOGGER, true, format!("{} événement(s) eslogger ignoré(s) (débit trop élevé)", total - reported_drops)).await;
                    reported_drops = total;
                }
            }
            line = reader.next_line() => {
                match line {
                    Ok(Line::Ready) => {
                        if !healthy {
                            healthy = true;
                            send_health(&ctx.tx, MONITOR_ESLOGGER, true, "eslogger actif").await;
                        }
                        if !limiter.allow(Instant::now()) {
                            continue;
                        }
                        let Some(ev) = parse_line(&reader.line) else { continue };
                        match dispatch(ev, &filter, &ctx.tx) {
                            Dispatch::Sent | Dispatch::Skipped => {}
                            Dispatch::Dropped => channel_drops += 1,
                            Dispatch::Closed => break Outcome::Shutdown,
                        }
                    }
                    Ok(Line::TooLong) => tracing::debug!("eslogger line too long, skipped"),
                    Ok(Line::Eof) | Err(_) => {
                        // Give stderr a moment to deliver the reason.
                        let _ = tokio::time::timeout(Duration::from_millis(500), async {
                            while let Some((kind, _)) = err_rx.recv().await {
                                if kind != StderrKind::Other {
                                    fatal = Some(kind);
                                    break;
                                }
                            }
                        }).await;
                        let status = tokio::time::timeout(Duration::from_secs(5), child.wait()).await;
                        break match fatal {
                            Some(StderrKind::NeedsFullDiskAccess) => Outcome::NeedsFda,
                            Some(StderrKind::NotRoot) => Outcome::NotRoot,
                            _ => Outcome::Exited(match status {
                                Ok(Ok(s)) => format!("eslogger s'est arrêté ({s})"),
                                _ => "eslogger s'est arrêté".to_string(),
                            }),
                        };
                    }
                }
            }
        }
    };
    let _ = child.kill().await;
    let _ = child.wait().await;
    stderr_task.abort();
    outcome
}

enum Dispatch {
    Sent,
    Skipped,
    Dropped,
    Closed,
}

fn dispatch(ev: EsEvent, filter: &EsFilter, tx: &mpsc::Sender<MonitorEvent>) -> Dispatch {
    let out = match ev {
        EsEvent::BtmLaunchItemAdd => {
            persistence_trigger().notify_one();
            return Dispatch::Skipped;
        }
        EsEvent::Mount | EsEvent::Unmount => {
            volume_trigger().notify_one();
            return Dispatch::Skipped;
        }
        EsEvent::Exec {
            target,
            args,
            parent,
        } => {
            if target.is_platform_binary
                || target.pid == filter.own_pid
                || Path::new(&target.path).starts_with(&filter.own_root)
            {
                return Dispatch::Skipped;
            }
            MonitorEvent::ProcessExec {
                target,
                args,
                parent,
            }
        }
        EsEvent::File {
            path,
            source,
            process,
            is_dir,
        } => {
            if is_dir || !filter.accept_file(&path, process.as_ref()) {
                return Dispatch::Skipped;
            }
            MonitorEvent::FileActivity {
                path,
                source,
                process,
            }
        }
    };
    match tx.try_send(out) {
        Ok(()) => Dispatch::Sent,
        Err(mpsc::error::TrySendError::Full(_)) => Dispatch::Dropped,
        Err(mpsc::error::TrySendError::Closed(_)) => Dispatch::Closed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<Vec<u8>> {
        let text = include_str!("../tests/fixtures/eslogger.jsonl");
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.as_bytes().to_vec())
            .collect()
    }

    #[test]
    fn parses_fixture_events() {
        let events: Vec<Option<EsEvent>> = fixture().iter().map(|l| parse_line(l)).collect();
        // 0: exec of an unsigned Homebrew binary from fish
        match &events[0] {
            Some(EsEvent::Exec {
                target,
                args,
                parent,
            }) => {
                assert_eq!(target.path, "/opt/homebrew/bin/payload");
                assert_eq!(target.pid, 14522);
                assert_eq!(target.ppid, 14518);
                assert_eq!(target.uid, 501);
                assert!(!target.is_platform_binary);
                assert_eq!(target.team_id, None);
                assert_eq!(target.signing_id.as_deref(), Some("payload-55554944"));
                assert_eq!(
                    target.cdhash.as_deref(),
                    Some("98C4FF44079AA2402973634BE3356FB3032594C1")
                );
                assert_eq!(target.codesigning_flags, 570425859);
                assert_eq!(args, &vec!["payload".to_string(), "--install".to_string()]);
                assert_eq!(
                    parent.as_ref().map(|p| p.path.as_str()),
                    Some("/opt/homebrew/Cellar/fish/3.6.0/bin/fish")
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        // 1: exec of a platform binary
        assert!(
            matches!(&events[1], Some(EsEvent::Exec { target, .. }) if target.is_platform_binary && target.path == "/bin/date")
        );
        // 2: create (existing_file), instigator kept
        match &events[2] {
            Some(EsEvent::File {
                path,
                source,
                process,
                is_dir,
            }) => {
                assert_eq!(path, "/Users/q/Library/LaunchAgents/com.evil.agent.plist");
                assert_eq!(*source, FileEventSource::EsCreate);
                assert!(!is_dir);
                assert_eq!(
                    process.as_ref().map(|p| p.path.as_str()),
                    Some("/opt/homebrew/bin/payload")
                );
            }
            other => panic!("unexpected {other:?}"),
        }
        // 3: create (new_path)
        assert!(
            matches!(&events[3], Some(EsEvent::File { path, source: FileEventSource::EsCreate, is_dir: false, .. }) if path == "/private/tmp/stage2.sh")
        );
        // 4: rename -> destination new_path
        assert!(
            matches!(&events[4], Some(EsEvent::File { path, source: FileEventSource::EsRename, .. }) if path == "/Users/q/Downloads/Installer.dmg")
        );
        // 5: close modified
        assert!(
            matches!(&events[5], Some(EsEvent::File { path, source: FileEventSource::EsCloseModified, .. }) if path == "/Users/Shared/.hidden/run.sh")
        );
        // 6: close not modified -> skipped
        assert_eq!(events[6], None);
        // 7: btm_launch_item_add, 8: mount, 9: unmount
        assert_eq!(events[7], Some(EsEvent::BtmLaunchItemAdd));
        assert_eq!(events[8], Some(EsEvent::Mount));
        assert_eq!(events[9], Some(EsEvent::Unmount));
        // 10: create of a directory -> is_dir
        assert!(matches!(
            &events[10],
            Some(EsEvent::File { is_dir: true, .. })
        ));
        // 11: unknown event kind, 12: garbage, 13: exec without target executable
        assert_eq!(events[11], None);
        assert_eq!(events[12], None);
        assert_eq!(events[13], None);
    }

    #[test]
    fn filter_keeps_interesting_locations_only() {
        let mut cfg = pb_core::config::Config::default();
        cfg.scan.exclude_paths = vec!["~/Downloads/vm".into()];
        let f = EsFilter::new(
            &cfg,
            Some(Path::new("/Users/q")),
            Path::new("/Library/Application Support/Parabellum"),
        );
        assert!(f.accept_file("/Users/q/Downloads/a.dmg", None));
        assert!(!f.accept_file("/Users/q/Downloads/vm/disk.img", None));
        assert!(!f.accept_file("/Users/q/Downloads/a.dmg.crdownload", None));
        assert!(f.accept_file("/private/tmp/x.sh", None));
        assert!(f.accept_file("/Users/other/Library/LaunchAgents/x.plist", None));
        assert!(f.accept_file("/Library/LaunchDaemons/x.plist", None));
        assert!(!f.accept_file("/Users/q/Library/Caches/x", None));
        assert!(!f.accept_file("/Library/Application Support/Parabellum/tmp/x", None));
        assert!(!f.accept_file("relative/path", None));
        let me = EsProcessInfo {
            pid: f.own_pid,
            path: "/x".into(),
            ..Default::default()
        };
        assert!(!f.accept_file("/tmp/x", Some(&me)));
    }

    #[test]
    fn args_and_stderr_classification() {
        assert_eq!(
            eslogger_args(&EsLoggerOptions::default()),
            vec![
                "--format",
                "json",
                "exec",
                "create",
                "rename",
                "btm_launch_item_add",
                "mount",
                "unmount"
            ]
        );
        assert!(eslogger_args(&EsLoggerOptions {
            include_close: true,
            ..Default::default()
        })
        .contains(&"close"));
        assert_eq!(
            classify_stderr(
                "ERROR: Failed to create new ES client: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED"
            ),
            StderrKind::NeedsFullDiskAccess
        );
        assert_eq!(
            classify_stderr("ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED"),
            StderrKind::NotRoot
        );
        assert_eq!(classify_stderr("something else"), StderrKind::Other);
    }

    #[test]
    fn rate_limiter_drops_excess() {
        let t0 = Instant::now();
        let mut r = RateLimiter::new(2, t0);
        assert!(r.allow(t0));
        assert!(r.allow(t0));
        assert!(!r.allow(t0 + Duration::from_millis(10)));
        assert_eq!(r.dropped, 1);
        assert!(r.allow(t0 + Duration::from_secs(1)));
    }

    #[tokio::test]
    async fn line_reader_bounds_lines() {
        let data: &[u8] = b"short\nthis line is way too long\nok\nlast-line";
        let mut r = LineReader::new(tokio::io::BufReader::with_capacity(4, data), 10);
        assert_eq!(r.next_line().await.unwrap(), Line::Ready);
        assert_eq!(r.line, b"short");
        assert_eq!(r.next_line().await.unwrap(), Line::TooLong);
        assert_eq!(r.next_line().await.unwrap(), Line::Ready);
        assert_eq!(r.line, b"ok");
        assert_eq!(r.next_line().await.unwrap(), Line::Ready);
        assert_eq!(r.line, b"last-line");
        assert_eq!(r.next_line().await.unwrap(), Line::Eof);
    }

    #[tokio::test]
    async fn dispatch_routes_events() {
        let cfg = pb_core::config::Config::default();
        let f = EsFilter::new(&cfg, Some(Path::new("/Users/q")), Path::new("/pbroot"));
        let (tx, mut rx) = mpsc::channel(4);
        let lines = fixture();
        for l in &lines {
            if let Some(ev) = parse_line(l) {
                let _ = dispatch(ev, &f, &tx);
            }
        }
        let mut got = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            got.push(ev);
        }
        // exec (non-platform) + LaunchAgent create + /private/tmp create + Downloads rename;
        // the channel holds 4, so the close event beyond capacity was dropped.
        assert_eq!(got.len(), 4, "{got:?}");
        assert!(matches!(got[0], MonitorEvent::ProcessExec { .. }));
        assert!(matches!(
            dispatch(EsEvent::Mount, &f, &tx),
            Dispatch::Skipped
        ));
        assert!(matches!(
            dispatch(EsEvent::BtmLaunchItemAdd, &f, &tx),
            Dispatch::Skipped
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[tokio::test]
    async fn linux_reports_unavailable() {
        use pb_core::paths::Paths;
        use tokio::sync::watch;
        let (_c, cfg_rx) = watch::channel(pb_core::config::Config::default());
        let (stop_tx, stop_rx) = watch::channel(false);
        let (tx, mut rx) = mpsc::channel(4);
        let ctx = MonitorContext {
            paths: Paths::with_root("/tmp/pbx"),
            config: cfg_rx,
            user: None,
            tx,
            shutdown: stop_rx,
        };
        let t = tokio::spawn(EsLoggerWatcher.run(ctx));
        let ev = rx.recv().await.unwrap();
        assert!(
            matches!(ev, MonitorEvent::MonitorHealth { ok: false, ref message, .. } if message.contains("macOS"))
        );
        stop_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(2), t)
            .await
            .unwrap()
            .unwrap();
    }
}
