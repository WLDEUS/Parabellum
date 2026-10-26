//! Pidfile of the supervised dnscrypt-proxy (`dns/dnscrypt-proxy.pid`, root-owned directory) and
//! removal of a stale proxy left behind by a daemon that was killed (SIGKILL / crash): an orphan proxy
//! still bound to :53 would answer health probes in place of the supervisor's own child.
//! A pid is only signalled when the process's executable is the managed binary (`proc_pidpath` on macOS,
//! `/proc/<pid>/exe` on Linux; process name `dnscrypt-proxy` as a fallback when the path is unavailable,
//! e.g. after the binary was replaced by an update).

use std::path::{Path, PathBuf};
use std::time::Duration;

const PROXY_NAME: &str = "dnscrypt-proxy";

pub(crate) fn write_pidfile(path: &Path, pid: u32) -> std::io::Result<()> {
    crate::fsutil::atomic_write(path, format!("{pid}\n").as_bytes(), 0o644)
}

pub(crate) fn read_pidfile(path: &Path) -> Option<i32> {
    let s = std::fs::read(path).ok()?;
    if s.len() > 32 {
        return None;
    }
    let pid: i32 = std::str::from_utf8(&s).ok()?.trim().parse().ok()?;
    (pid > 1).then_some(pid)
}

pub(crate) fn remove_pidfile(path: &Path) {
    let _ = std::fs::remove_file(path);
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks for existence / permission.
    let rc = unsafe { libc::kill(pid, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "macos")]
fn process_exe(pid: i32) -> Option<PathBuf> {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: buffer pointer/size are valid; proc_pidpath writes at most `buffersize` bytes.
    let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(PathBuf::from(String::from_utf8_lossy(&buf).into_owned()))
}

#[cfg(target_os = "linux")]
fn process_exe(pid: i32) -> Option<PathBuf> {
    let p = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let s = p.to_string_lossy();
    Some(PathBuf::from(s.strip_suffix(" (deleted)").unwrap_or(&s).to_string()))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn process_exe(_pid: i32) -> Option<PathBuf> {
    None
}

#[cfg(target_os = "macos")]
fn process_name(pid: i32) -> Option<String> {
    let mut buf = vec![0u8; 256];
    // SAFETY: buffer pointer/size are valid.
    let n = unsafe { libc::proc_name(pid, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

#[cfg(target_os = "linux")]
fn process_name(pid: i32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm")).ok().map(|s| s.trim().to_string())
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn process_name(_pid: i32) -> Option<String> {
    None
}

/// Whether `pid` runs the managed proxy `binary`.
pub(crate) fn process_matches(pid: i32, binary: &Path) -> bool {
    match process_exe(pid) {
        Some(exe) => {
            let canon = std::fs::canonicalize(binary).unwrap_or_else(|_| binary.to_path_buf());
            exe == binary || exe == canon
        }
        None => process_name(pid).as_deref() == Some(PROXY_NAME),
    }
}

/// Kill the proxy recorded in `pidfile` if it is still running `binary` (SIGTERM, then SIGKILL after 3 s).
/// The pidfile is removed in every case. Returns the pid that was signalled.
pub(crate) async fn kill_stale(pidfile: &Path, binary: &Path) -> Option<i32> {
    let pid = read_pidfile(pidfile);
    remove_pidfile(pidfile);
    let pid = pid?;
    if pid == std::process::id() as i32 || !alive(pid) || !process_matches(pid, binary) {
        return None;
    }
    tracing::warn!(pid, "stale dnscrypt-proxy found: stopping it");
    // SAFETY: plain signal delivery to a pid we just identified.
    unsafe { libc::kill(pid, libc::SIGTERM) };
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if !alive(pid) {
            return Some(pid);
        }
    }
    if process_matches(pid, binary) {
        // SAFETY: as above.
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    Some(pid)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[tokio::test]
    async fn kills_only_the_recorded_proxy() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("dnscrypt-proxy");
        std::fs::copy("/bin/sleep", &bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pidfile = d.path().join("dnscrypt-proxy.pid");

        // A process running another executable is never signalled (pid reuse).
        let mut other = tokio::process::Command::new("/bin/sleep").arg("30").kill_on_drop(true).spawn().unwrap();
        write_pidfile(&pidfile, other.id().unwrap()).unwrap();
        assert_eq!(kill_stale(&pidfile, &bin).await, None);
        assert!(other.try_wait().unwrap().is_none(), "unrelated process untouched");
        assert!(!pidfile.exists());
        let _ = other.start_kill();

        // The recorded proxy is stopped.
        let mut proxy = tokio::process::Command::new(&bin).arg("30").kill_on_drop(true).spawn().unwrap();
        let pid = proxy.id().unwrap();
        write_pidfile(&pidfile, pid).unwrap();
        assert_eq!(read_pidfile(&pidfile), Some(pid as i32));
        assert!(process_matches(pid as i32, &bin));
        let (killed, status) = tokio::join!(kill_stale(&pidfile, &bin), proxy.wait());
        assert_eq!(killed, Some(pid as i32));
        assert!(!status.unwrap().success());

        // Garbage / missing pidfiles.
        std::fs::write(&pidfile, "1\n").unwrap();
        assert_eq!(kill_stale(&pidfile, &bin).await, None);
        std::fs::write(&pidfile, "not a pid").unwrap();
        assert_eq!(read_pidfile(&pidfile), None);
        assert_eq!(kill_stale(&d.path().join("missing.pid"), &bin).await, None);
    }
}
