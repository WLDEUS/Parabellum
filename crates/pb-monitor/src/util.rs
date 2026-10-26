//! Internal helpers: shutdown handling, backoff, health events, bounded subprocesses and reads.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use pb_core::events::MonitorEvent;
use tokio::sync::{mpsc, watch};

use crate::MonitorError;

/// Minimal, predictable environment for every system tool we run (English output, UTF-8).
pub(crate) const TOOL_PATH_ENV: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// True once the daemon asked us to stop (or dropped the sender).
pub(crate) fn is_shutdown(rx: &watch::Receiver<bool>) -> bool {
    *rx.borrow() || rx.has_changed().is_err()
}

/// Resolves when shutdown is requested (or the sender is gone).
pub(crate) async fn wait_shutdown(rx: &mut watch::Receiver<bool>) {
    loop {
        if *rx.borrow_and_update() {
            return;
        }
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Sleeps `d`; returns `true` if shutdown was requested meanwhile.
pub(crate) async fn sleep_or_shutdown(d: Duration, rx: &mut watch::Receiver<bool>) -> bool {
    if is_shutdown(rx) {
        return true;
    }
    tokio::select! {
        _ = tokio::time::sleep(d) => is_shutdown(rx),
        _ = wait_shutdown(rx) => true,
    }
}

/// Exponential backoff (doubling, capped).
#[derive(Debug, Clone)]
pub(crate) struct Backoff {
    cur: Duration,
    min: Duration,
    max: Duration,
}

impl Backoff {
    pub(crate) fn new(min: Duration, max: Duration) -> Self {
        Self { cur: min, min, max }
    }
    /// Delay to wait now; the next one is doubled.
    pub(crate) fn next_delay(&mut self) -> Duration {
        let d = self.cur;
        self.cur = (self.cur * 2).min(self.max);
        d
    }
    pub(crate) fn reset(&mut self) {
        self.cur = self.min;
    }
}

/// Sends a `MonitorHealth` event (waits for channel capacity; ignores a closed channel).
pub(crate) async fn send_health(
    tx: &mpsc::Sender<MonitorEvent>,
    monitor: &str,
    ok: bool,
    message: impl Into<String>,
) {
    let message = message.into();
    if ok {
        tracing::info!(monitor, %message, "monitor healthy");
    } else {
        tracing::warn!(monitor, %message, "monitor degraded");
    }
    let _ = tx
        .send(MonitorEvent::MonitorHealth {
            monitor: monitor.to_string(),
            ok,
            message,
        })
        .await;
}

/// Result of a bounded subprocess run.
#[derive(Debug, Clone)]
pub(crate) struct CmdOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: String,
    /// stdout exceeded the limit (the rest was drained and discarded).
    pub truncated: bool,
}

fn read_bounded<R: Read>(mut r: R, max: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::with_capacity(max.min(64 * 1024));
    let mut buf = [0u8; 16 * 1024];
    let mut truncated = false;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = max.saturating_sub(out.len());
                if room > 0 {
                    out.extend_from_slice(&buf[..n.min(room)]);
                }
                if n > room {
                    truncated = true; // keep draining so the child never blocks on a full pipe
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (out, truncated)
}

/// Builds a `Command` with a clean environment (absolute program path expected).
pub(crate) fn tool_command(program: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", TOOL_PATH_ENV)
        .env("LANG", "en_US.UTF-8")
        .env("LC_ALL", "en_US.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

/// Runs a prepared command synchronously with a timeout and an stdout cap. Kills the child on
/// timeout. Meant to be called from blocking contexts (`spawn_blocking`, scanner threads).
pub(crate) fn run_prepared(
    mut cmd: Command,
    label: &str,
    timeout: Duration,
    max_stdout: usize,
) -> Result<CmdOutput, MonitorError> {
    let mut child = cmd.spawn().map_err(|e| MonitorError::Command {
        program: label.to_string(),
        message: e.to_string(),
    })?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_t = std::thread::Builder::new()
        .name("pb-cmd-out".into())
        .spawn(move || {
            stdout
                .map(|s| read_bounded(s, max_stdout))
                .unwrap_or_default()
        })
        .map_err(MonitorError::Io)?;
    let err_t = std::thread::Builder::new()
        .name("pb-cmd-err".into())
        .spawn(move || {
            stderr
                .map(|s| read_bounded(s, 64 * 1024))
                .unwrap_or_default()
        })
        .map_err(MonitorError::Io)?;
    let deadline = Instant::now() + timeout;
    let mut sleep = Duration::from_millis(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(MonitorError::Io(e));
            }
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_t.join();
            let _ = err_t.join();
            return Err(MonitorError::Timeout(label.to_string()));
        }
        std::thread::sleep(sleep);
        sleep = (sleep * 2).min(Duration::from_millis(100));
    };
    let (stdout, truncated) = out_t.join().unwrap_or_default();
    let (stderr, _) = err_t.join().unwrap_or_default();
    Ok(CmdOutput {
        success: status.success(),
        code: status.code(),
        stdout,
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated,
    })
}

/// Runs `program args…` (absolute path, argument vector, clean env) with a timeout and stdout cap.
pub(crate) fn run_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
    max_stdout: usize,
) -> Result<CmdOutput, MonitorError> {
    if !Path::new(program).is_file() {
        return Err(MonitorError::NotFound(program.to_string()));
    }
    run_prepared(tool_command(program, args), program, timeout, max_stdout)
}

/// Like [`run_command`] but requires a zero exit status; returns stdout.
pub(crate) fn run_command_ok(
    program: &str,
    args: &[&str],
    timeout: Duration,
    max_stdout: usize,
) -> Result<Vec<u8>, MonitorError> {
    let out = run_command(program, args, timeout, max_stdout)?;
    if !out.success {
        return Err(MonitorError::Command {
            program: program.to_string(),
            message: format!("exit {:?}: {}", out.code, out.stderr.trim()),
        });
    }
    if out.truncated {
        tracing::warn!(program, "command output truncated");
    }
    Ok(out.stdout)
}

/// Reads a whole file if it is a regular file of at most `max` bytes.
pub(crate) fn read_file_bounded(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if meta.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file too large",
        ));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    f.take(max + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file too large",
        ));
    }
    Ok(buf)
}

/// Streaming SHA-256 of a regular file of at most `max` bytes (lowercase hex).
pub(crate) fn sha256_file(path: &Path, max: u64) -> Option<String> {
    use sha2::{Digest, Sha256};
    let f = std::fs::File::open(path).ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.len() > max {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut reader = f.take(max + 1);
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if total > max {
                    return None;
                }
                hasher.update(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(hex::encode(hasher.finalize()))
}

/// SHA-256 of a byte slice (lowercase hex).
pub(crate) fn sha256_bytes(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Truncates a string to at most `max` characters (char boundary safe).
pub(crate) fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// Expands `~` paths for an optional home; `~` paths are dropped when there is no home.
pub(crate) fn expand_paths(list: &[String], home: Option<&Path>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in list {
        let p = p.trim();
        if p.is_empty() {
            continue;
        }
        let expanded = if p == "~" || p.starts_with("~/") {
            match home {
                Some(h) => pb_core::expand_user_path(p, h),
                None => continue,
            }
        } else {
            PathBuf::from(p)
        };
        if expanded.is_absolute() && !out.contains(&expanded) {
            out.push(expanded);
        }
    }
    out
}

/// Component-wise prefix test against any of `prefixes`.
pub(crate) fn under_any(path: &Path, prefixes: &[PathBuf]) -> bool {
    prefixes.iter().any(|p| path.starts_with(p))
}

/// Unix seconds of a `SystemTime` (0 when before the epoch).
pub(crate) fn unix_secs(t: std::time::SystemTime) -> i64 {
    t.duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(5));
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(2));
        assert_eq!(b.next_delay(), Duration::from_secs(4));
        assert_eq!(b.next_delay(), Duration::from_secs(5));
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn runs_commands_with_limits() {
        let out = run_command(
            "/bin/sh",
            &["-c", "printf 'hello world'"],
            Duration::from_secs(5),
            5,
        )
        .unwrap();
        assert!(out.success);
        assert_eq!(out.stdout, b"hello");
        assert!(out.truncated);
        let err = run_command(
            "/bin/sh",
            &["-c", "sleep 5"],
            Duration::from_millis(200),
            10,
        )
        .unwrap_err();
        assert!(matches!(err, MonitorError::Timeout(_)));
        assert!(matches!(
            run_command("/nonexistent/tool", &[], Duration::from_secs(1), 10),
            Err(MonitorError::NotFound(_))
        ));
        // clean environment
        let out = run_command(
            "/bin/sh",
            &["-c", "printf \"$HOME|$PATH\""],
            Duration::from_secs(5),
            1024,
        )
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("|{TOOL_PATH_ENV}")
        );
    }

    #[test]
    fn bounded_reads_and_hashes() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(read_file_bounded(&p, 3).unwrap(), b"abc");
        assert!(read_file_bounded(&p, 2).is_err());
        assert!(read_file_bounded(d.path(), 100).is_err());
        assert_eq!(
            sha256_file(&p, 10).as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert_eq!(sha256_file(&p, 2), None);
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn expands_and_matches_prefixes() {
        let home = Path::new("/Users/q");
        let v = expand_paths(
            &[
                "~/Downloads".into(),
                "/Applications".into(),
                "rel".into(),
                "~/Downloads".into(),
            ],
            Some(home),
        );
        assert_eq!(
            v,
            vec![
                PathBuf::from("/Users/q/Downloads"),
                PathBuf::from("/Applications")
            ]
        );
        assert_eq!(
            expand_paths(&["~/Downloads".into()], None),
            Vec::<PathBuf>::new()
        );
        assert!(under_any(Path::new("/Users/q/Downloads/x.dmg"), &v));
        assert!(!under_any(Path::new("/Users/q/DownloadsX/x.dmg"), &v));
        assert_eq!(clip("héllo", 2), "hé");
    }
}
