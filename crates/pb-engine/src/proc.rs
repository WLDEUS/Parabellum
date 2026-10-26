//! Subprocess helper: absolute program paths, argument vectors, timeout, cancellation, bounded output.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Result of [`run`].
#[derive(Debug)]
pub(crate) struct ProcOutput {
    /// `None` when the process was killed (timeout / cancel).
    pub status: Option<ExitStatus>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub cancelled: bool,
}

impl ProcOutput {
    /// Exit code, when the process exited normally.
    pub(crate) fn code(&self) -> Option<i32> {
        self.status.and_then(|s| s.code())
    }
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(crate) fn success(&self) -> bool {
        self.status.is_some_and(|s| s.success())
    }
}

fn drain<R: Read + Send + 'static>(r: Option<R>, max: usize) -> Option<mpsc::Receiver<Vec<u8>>> {
    let mut r = r?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let room = max.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                    // keep reading (and discarding) so the child never blocks on a full pipe
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        let _ = tx.send(kept);
    });
    Some(rx)
}

/// Kills the child's whole process group (it was spawned as a group leader), then the child.
fn kill(child: &mut Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        if pid > 0 {
            // SAFETY: plain syscall; `-pid` targets the process group created by `process_group(0)`.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Output of a drain thread; after a kill, grandchildren that escaped the group could keep the
/// pipe open, so the wait is bounded.
fn collect(rx: Option<mpsc::Receiver<Vec<u8>>>, killed: bool) -> Vec<u8> {
    let Some(rx) = rx else { return Vec::new() };
    let wait = if killed {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(30)
    };
    rx.recv_timeout(wait).unwrap_or_default()
}

/// Runs `cmd` with piped stdout/stderr (each capped to `max_output` bytes, the rest discarded),
/// optional stdin data, a hard `timeout` and an optional cancellation flag (polled).
pub(crate) fn run(
    mut cmd: Command,
    stdin: Option<Vec<u8>>,
    timeout: Duration,
    cancel: Option<&AtomicBool>,
    max_output: usize,
) -> std::io::Result<ProcOutput> {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.process_group(0);
    let mut child = cmd.spawn()?;
    let writer = match (stdin, child.stdin.take()) {
        (Some(data), Some(mut pipe)) => Some(std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
            // pipe dropped here -> EOF for the child
        })),
        _ => None,
    };
    let out = drain(child.stdout.take(), max_output);
    let err = drain(child.stderr.take(), max_output);
    let start = Instant::now();
    let mut sleep = Duration::from_millis(2);
    let mut timed_out = false;
    let mut cancelled = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(e) => {
                kill(&mut child);
                return Err(e);
            }
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            kill(&mut child);
            break None;
        }
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            cancelled = true;
            kill(&mut child);
            break None;
        }
        std::thread::sleep(sleep);
        sleep = (sleep * 2).min(Duration::from_millis(100));
    };
    // The stdin writer thread ends on its own (EOF written or EPIPE); never block on it.
    drop(writer);
    let killed = status.is_none();
    let stdout = collect(out, killed);
    let stderr = collect(err, killed);
    Ok(ProcOutput {
        status,
        stdout,
        stderr,
        timed_out,
        cancelled,
    })
}

/// `Command` for `program`, wrapped in `/usr/sbin/taskpolicy -b` on macOS (darwin background:
/// throttled CPU and I/O on efficiency cores). `taskpolicy` execs the program in place
/// (`POSIX_SPAWN_SETEXEC`), so killing the child kills the program.
pub(crate) fn background_command(program: &std::path::Path, background: bool) -> Command {
    #[cfg(target_os = "macos")]
    {
        const TASKPOLICY: &str = "/usr/sbin/taskpolicy";
        if background && std::path::Path::new(TASKPOLICY).is_file() {
            let mut c = Command::new(TASKPOLICY);
            c.arg("-b").arg(program);
            return c;
        }
    }
    let _ = background;
    Command::new(program)
}

/// uid/gid of the `nobody` account when the daemon runs as root (`None` otherwise: there is no
/// privilege to drop, or the account does not exist).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn unprivileged_ids() -> Option<(u32, u32)> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    lookup_user(c"nobody")
}

/// `getpwnam_r` lookup (thread-safe).
fn lookup_user(name: &std::ffi::CStr) -> Option<(u32, u32)> {
    // SAFETY: zeroed passwd is a valid out-value (only plain fields and pointers).
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call; `buf` outlives its use.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some((pwd.pw_uid, pwd.pw_gid))
}

/// Fresh work directory (created `0700` by us under `base`, then chowned to `ids` when given) for
/// a helper running unprivileged. Removed when the guard drops.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn unprivileged_workspace(
    base: &std::path::Path,
    ids: Option<(u32, u32)>,
) -> std::io::Result<tempfile::TempDir> {
    let d = tempfile::Builder::new()
        .prefix("pb-unpriv-")
        .tempdir_in(base)?;
    if let Some((uid, gid)) = ids {
        std::os::unix::fs::chown(d.path(), Some(uid), Some(gid))?;
    }
    Ok(d)
}

/// Runs the command as `ids` (std performs `setgid`, `setgroups(0)` and `setuid` in the child
/// before `exec`).
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn drop_privileges(cmd: &mut Command, ids: Option<(u32, u32)>) {
    if let Some((uid, gid)) = ids {
        cmd.uid(uid).gid(gid);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_runs_as_nobody() {
        let Some(ids) = unprivileged_ids() else {
            return;
        }; // not root: nothing to drop
        let base = tempfile::tempdir().unwrap();
        let ws = unprivileged_workspace(base.path(), Some(ids)).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(ws.path()).unwrap().uid(), ids.0);
        let mut c = Command::new("/bin/sh");
        drop_privileges(&mut c, Some(ids));
        c.args(["-c", "id -u; touch \"$1/ok\" && echo wrote", "sh"])
            .arg(ws.path());
        let o = run(c, None, Duration::from_secs(10), None, 1024).unwrap();
        let out = String::from_utf8_lossy(&o.stdout);
        assert_eq!(out.lines().next(), Some(ids.0.to_string().as_str()));
        assert!(out.contains("wrote"));
        assert_eq!(
            std::fs::metadata(ws.path().join("ok")).unwrap().uid(),
            ids.0
        );
    }

    #[test]
    fn captures_output_and_status() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "echo out; echo err >&2; exit 3"]);
        let o = run(c, None, Duration::from_secs(10), None, 1024).unwrap();
        assert_eq!(o.code(), Some(3));
        assert_eq!(o.stdout, b"out\n");
        assert_eq!(o.stderr, b"err\n");
    }

    #[test]
    fn times_out_and_bounds_output() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "yes | head -c 100000; sleep 30"]);
        let t = Instant::now();
        let o = run(c, None, Duration::from_millis(300), None, 1000).unwrap();
        assert!(o.timed_out);
        assert!(o.status.is_none());
        assert_eq!(o.stdout.len(), 1000);
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn feeds_stdin_and_honours_cancel() {
        let c = Command::new("/bin/cat");
        let o = run(
            c,
            Some(b"hello".to_vec()),
            Duration::from_secs(10),
            None,
            1024,
        )
        .unwrap();
        assert_eq!(o.stdout, b"hello");
        let flag = AtomicBool::new(true);
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "sleep 30"]);
        let o = run(c, None, Duration::from_secs(60), Some(&flag), 1024).unwrap();
        assert!(o.cancelled);
    }
}
