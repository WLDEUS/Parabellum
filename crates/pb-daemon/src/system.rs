//! Platform helpers: identity, peer credentials, process info, QoS, subprocesses, battery.
//!
//! macOS-specific code sits behind `cfg(target_os = "macos")`; the Linux fallbacks exist so the daemon
//! builds and its tests run in CI containers.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

/// Gid of the `admin` group on macOS.
pub const ADMIN_GID: u32 = 80;

/// Effective uid of this process.
pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Running as root.
pub fn is_root() -> bool {
    euid() == 0
}

/// The user logged in at the console (owner of `/dev/console` on macOS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleUser {
    pub uid: u32,
    pub name: String,
    pub home: PathBuf,
}

/// Console user. macOS: owner of `/dev/console` (`None` at the login window, owned by root).
/// Other platforms (dev only): the user running the daemon.
pub fn console_user() -> Option<ConsoleUser> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata("/dev/console").ok()?.uid();
        if uid == 0 {
            return None;
        }
        let (name, home) = user_by_uid(uid)?;
        Some(ConsoleUser { uid, name, home })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let uid = euid();
        let (name, home) = user_by_uid(uid)?;
        Some(ConsoleUser { uid, name, home })
    }
}

/// `(login name, home directory)` of a uid.
pub fn user_by_uid(uid: u32) -> Option<(String, PathBuf)> {
    use std::ffi::CStr;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call; `buf` outlives the use of `pwd`'s strings.
    let rc = unsafe {
        libc::getpwuid_r(
            uid as libc::uid_t,
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || pwd.pw_name.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, the strings point into `buf` and are NUL-terminated.
    let name = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    let home = unsafe { CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .into_owned();
    Some((name, PathBuf::from(home)))
}

/// Credentials of the process at the other end of a Unix socket (captured when it connected).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
    /// macOS `audit_token_t` (`LOCAL_PEERTOKEN`): pid in `val[5]`, pidversion in `val[7]`.
    pub audit_token: Option<[u32; 8]>,
}

/// Peer credentials of a connected Unix socket (`getpeereid` + `LOCAL_PEERPID` on macOS, `SO_PEERCRED` on Linux).
pub fn peer_credentials(fd: std::os::fd::RawFd) -> std::io::Result<PeerCred> {
    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: fd is a connected socket owned by the caller; out-pointers are valid.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: LOCAL_PEERPID writes a pid_t into the provided buffer of `len` bytes.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                &mut pid as *mut libc::pid_t as *mut libc::c_void,
                &mut len,
            )
        };
        let pid = if rc == 0 && len as usize == std::mem::size_of::<libc::pid_t>() && pid > 0 {
            Some(pid)
        } else {
            None
        };
        let mut token = [0u32; 8];
        let mut tlen = std::mem::size_of::<[u32; 8]>() as libc::socklen_t;
        // SAFETY: LOCAL_PEERTOKEN writes an `audit_token_t` (8 x u32) into the buffer of `tlen` bytes.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                token.as_mut_ptr() as *mut libc::c_void,
                &mut tlen,
            )
        };
        let audit_token = (rc == 0 && tlen as usize == std::mem::size_of::<[u32; 8]>()).then_some(token);
        let pid = audit_token.map(|t| t[5] as i32).filter(|p| *p > 0).or(pid);
        Ok(PeerCred { uid, gid, pid, audit_token })
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: SO_PEERCRED writes a `struct ucred` into the provided buffer of `len` bytes.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut libc::ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(PeerCred {
            uid: cred.uid,
            gid: cred.gid,
            pid: if cred.pid > 0 { Some(cred.pid) } else { None },
            audit_token: None,
        })
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = fd;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "peer credentials unsupported",
        ))
    }
}

#[cfg(target_os = "macos")]
mod audit_ffi {
    /// `audit_token_t`.
    #[repr(C)]
    pub struct AuditToken {
        pub val: [u32; 8],
    }
    extern "C" {
        /// libproc (macOS 11+): path of the process named by the token; fails when the pid exited or its
        /// pidversion changed (process gone, pid reused, or `execve` since the token was taken).
        pub fn proc_pidpath_audittoken(
            audittoken: *mut AuditToken,
            buffer: *mut libc::c_void,
            buffersize: u32,
        ) -> libc::c_int;
    }
}

/// Current executable of a socket peer, re-validated at each call: with an audit token the path is only
/// returned while the connecting process still runs the same image (pid + pidversion); otherwise falls back
/// to the pid (racy: pid reuse).
pub fn peer_executable(cred: &PeerCred) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    if let Some(token) = cred.audit_token {
        let mut t = audit_ffi::AuditToken { val: token };
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: token and buffer are valid; the buffer size is within [PROC_PIDPATHINFO_SIZE, MAXSIZE].
        let n = unsafe {
            audit_ffi::proc_pidpath_audittoken(&mut t, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
        };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        use std::os::unix::ffi::OsStringExt;
        return Some(PathBuf::from(std::ffi::OsString::from_vec(buf)));
    }
    cred.pid.and_then(pid_path)
}

/// Executable path of a process (`proc_pidpath` on macOS, `/proc/<pid>/exe` on Linux).
pub fn pid_path(pid: i32) -> Option<PathBuf> {
    if pid <= 0 {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        // SAFETY: buffer is valid for `buf.len()` bytes; proc_pidpath returns the number of bytes written.
        let n = unsafe {
            libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
        };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        use std::os::unix::ffi::OsStringExt;
        Some(PathBuf::from(std::ffi::OsString::from_vec(buf)))
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}

/// Resident memory of this process in bytes.
pub fn rss_bytes() -> u64 {
    #[cfg(target_os = "macos")]
    {
        let mut info: libc::rusage_info_v2 = unsafe { std::mem::zeroed() };
        // SAFETY: RUSAGE_INFO_V2 fills a `rusage_info_v2`; the C API takes it as `rusage_info_t *`.
        let rc = unsafe {
            libc::proc_pid_rusage(
                libc::getpid(),
                libc::RUSAGE_INFO_V2,
                &mut info as *mut libc::rusage_info_v2 as *mut libc::rusage_info_t,
            )
        };
        if rc == 0 {
            info.ri_resident_size
        } else {
            0
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let Ok(s) = std::fs::read_to_string("/proc/self/statm") else {
            return 0;
        };
        let pages: u64 = s
            .split_whitespace()
            .nth(1)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // SAFETY: sysconf has no preconditions.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        pages.saturating_mul(if page > 0 { page as u64 } else { 4096 })
    }
}

/// Scheduling class for scan threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPriority {
    /// User-visible work (manual scans, real-time): `QOS_CLASS_UTILITY` + `IOPOL_UTILITY`.
    Utility,
    /// Deferred work (retro-hunts, volume scans, batches): `QOS_CLASS_BACKGROUND` + `IOPOL_THROTTLE`
    /// (efficiency cores, throttled I/O).
    Background,
}

#[cfg(target_os = "macos")]
mod qos_ffi {
    // <pthread/qos.h>, <sys/qos.h>: `qos_class_t` is an `unsigned int` enum.
    pub const QOS_CLASS_DEFAULT: u32 = 0x15;
    pub const QOS_CLASS_UTILITY: u32 = 0x11;
    pub const QOS_CLASS_BACKGROUND: u32 = 0x09;
    pub const QOS_CLASS_UNSPECIFIED: u32 = 0x00;
    // <sys/resource.h>
    pub const IOPOL_TYPE_DISK: libc::c_int = 0;
    pub const IOPOL_SCOPE_PROCESS: libc::c_int = 0;
    pub const IOPOL_SCOPE_THREAD: libc::c_int = 1;
    pub const IOPOL_THROTTLE: libc::c_int = 3;
    pub const IOPOL_UTILITY: libc::c_int = 4;
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

/// RAII guard lowering the current thread's QoS and I/O policy; restores them on drop
/// (tokio reuses blocking threads). No-op outside macOS or when `enabled` is false.
pub struct QosGuard {
    #[cfg(target_os = "macos")]
    restore: Option<(u32, libc::c_int)>,
}

impl QosGuard {
    pub fn enter(priority: ScanPriority, enabled: bool) -> Self {
        #[cfg(target_os = "macos")]
        {
            use qos_ffi::*;
            if !enabled {
                return Self { restore: None };
            }
            let (class, io) = match priority {
                ScanPriority::Utility => (QOS_CLASS_UTILITY, IOPOL_UTILITY),
                ScanPriority::Background => (QOS_CLASS_BACKGROUND, IOPOL_THROTTLE),
            };
            // SAFETY: plain libSystem calls acting on the current thread.
            unsafe {
                let prev_class = qos_class_self();
                let prev_io = getiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD);
                if pthread_set_qos_class_self_np(class, 0) != 0 {
                    tracing::debug!("pthread_set_qos_class_self_np failed");
                }
                if setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD, io) != 0 {
                    tracing::debug!("setiopolicy_np failed");
                }
                Self {
                    restore: Some((prev_class, prev_io)),
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (priority, enabled);
            Self {}
        }
    }
}

impl Drop for QosGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some((class, io)) = self.restore.take() {
            use qos_ffi::*;
            let class = if class == QOS_CLASS_UNSPECIFIED {
                QOS_CLASS_DEFAULT
            } else {
                class
            };
            // SAFETY: plain libSystem calls acting on the current thread.
            unsafe {
                let _ = pthread_set_qos_class_self_np(class, 0);
                if io >= 0 {
                    let _ = setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD, io);
                }
            }
        }
    }
}

/// Lower the whole daemon a little: `nice +5` and, on macOS, utility-class disk I/O. Scan threads go further
/// down with [`QosGuard`]; IPC stays responsive.
pub fn lower_process_priority() {
    // SAFETY: setpriority on our own process.
    unsafe {
        let _ = libc::setpriority(libc::PRIO_PROCESS, 0, 5);
    }
    #[cfg(target_os = "macos")]
    // SAFETY: process-wide I/O policy of our own process.
    unsafe {
        let _ = qos_ffi::setiopolicy_np(
            qos_ffi::IOPOL_TYPE_DISK,
            qos_ffi::IOPOL_SCOPE_PROCESS,
            qos_ffi::IOPOL_UTILITY,
        );
    }
}

/// SIGKILL `pid` only if it still runs `expected` (guards against pid reuse). Never pid ≤ 1 nor ourselves.
pub fn kill_if_path(pid: i32, expected: &Path) -> Result<bool, String> {
    // SAFETY: getpid has no preconditions.
    if pid <= 1 || pid == unsafe { libc::getpid() } {
        return Err(format!("pid {pid} refusé"));
    }
    let Some(actual) = pid_path(pid) else {
        return Ok(false);
    };
    let canonical = std::fs::canonicalize(expected).ok();
    if actual != expected && canonical.as_deref() != Some(actual.as_path()) {
        return Ok(false);
    }
    // SAFETY: sending a signal to a validated pid.
    if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
        Ok(true)
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

/// Output of a subprocess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }
}

const MAX_CMD_OUTPUT: usize = 1024 * 1024;

/// Run a system tool by absolute path with an argument vector, a clean environment and a timeout.
pub async fn run_command(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<CmdOutput, String> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    match tokio::time::timeout(timeout, cmd.output()).await {
        Err(_) => Err(format!("{program}: délai dépassé ({}s)", timeout.as_secs())),
        Ok(Err(e)) => Err(format!("{program}: {e}")),
        Ok(Ok(out)) => {
            let cut =
                |v: &[u8]| String::from_utf8_lossy(&v[..v.len().min(MAX_CMD_OUTPUT)]).into_owned();
            Ok(CmdOutput {
                status: out.status.code(),
                stdout: cut(&out.stdout),
                stderr: cut(&out.stderr),
            })
        }
    }
}

/// Run a system tool synchronously (startup only), output discarded, killed after `timeout`.
/// Returns true on exit status 0.
pub fn run_sync(program: &str, args: &[&std::ffi::OsStr], timeout: Duration) -> bool {
    let child = std::process::Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return false };
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// Power source state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BatteryState {
    pub on_battery: bool,
    pub percent: Option<u8>,
}

/// Parse `pmset -g batt`:
/// ```text
/// Now drawing from 'Battery Power'
///  -InternalBattery-0 (id=4653155)<TAB>85%; discharging; 4:30 remaining present: true
/// ```
pub fn parse_pmset_batt(s: &str) -> Option<BatteryState> {
    let first = s.lines().next()?;
    if !first.contains("drawing from") {
        return None;
    }
    let on_battery = first.contains("'Battery Power'");
    let percent = s
        .lines()
        .filter(|l| l.contains("InternalBattery"))
        .find_map(|l| {
            l.split(['\t', ' ', ';'])
                .find_map(|t| t.strip_suffix('%').and_then(|n| n.parse::<u8>().ok()))
        });
    Some(BatteryState {
        on_battery,
        percent,
    })
}

/// Current power state (`/usr/bin/pmset -g batt`); always "on AC" outside macOS.
pub async fn battery_state() -> BatteryState {
    #[cfg(target_os = "macos")]
    {
        match run_command("/usr/bin/pmset", &["-g", "batt"], Duration::from_secs(10)).await {
            Ok(out) if out.success() => parse_pmset_batt(&out.stdout).unwrap_or_default(),
            Ok(out) => {
                tracing::debug!(stderr = %out.stderr, "pmset failed");
                BatteryState::default()
            }
            Err(e) => {
                tracing::debug!(error = %e, "pmset failed");
                BatteryState::default()
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        BatteryState::default()
    }
}

/// `launchctl bootout <target>` (`system/<label>` or `gui/<uid>/<label>`).
pub async fn launchctl_bootout(target: &str) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("launchctl indisponible sur cette plateforme".into());
    }
    let out = run_command(
        "/bin/launchctl",
        &["bootout", target],
        Duration::from_secs(30),
    )
    .await?;
    if out.success() {
        Ok(())
    } else {
        Err(format!(
            "launchctl bootout {target}: {} {}",
            out.status.unwrap_or(-1),
            out.stderr.trim()
        ))
    }
}

/// `diskutil unmount force <mount point>`.
pub async fn diskutil_unmount_force(mount: &str) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("diskutil indisponible sur cette plateforme".into());
    }
    let out = run_command(
        "/usr/sbin/diskutil",
        &["unmount", "force", mount],
        Duration::from_secs(60),
    )
    .await?;
    if out.success() {
        Ok(())
    } else {
        Err(format!(
            "diskutil unmount force {mount}: {}",
            out.stderr.trim()
        ))
    }
}

/// Local calendar date `YYYY-MM-DD` of a Unix timestamp.
pub fn local_date(ts: i64) -> String {
    use chrono::TimeZone;
    match chrono::Local.timestamp_opt(ts, 0) {
        chrono::LocalResult::Single(d) | chrono::LocalResult::Ambiguous(d, _) => {
            d.format("%Y-%m-%d").to_string()
        }
        chrono::LocalResult::None => chrono::DateTime::from_timestamp(ts, 0)
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default(),
    }
}

/// Paths the daemon must never quarantine / modify (system volume, Apple binaries).
pub fn is_protected_system_path(path: &Path) -> bool {
    const PROTECTED: &[&str] = &[
        "/System",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/libexec",
        "/usr/share",
        "/usr/standalone",
        "/bin",
        "/sbin",
        "/private/var/db",
        "/Library/Apple",
        "/dev",
    ];
    if path == Path::new("/") || path == Path::new("/usr") {
        return true;
    }
    PROTECTED.iter().any(|p| path.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pmset_parsing() {
        let batt = "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=4653155)\t85%; discharging; 4:30 remaining present: true\n";
        assert_eq!(
            parse_pmset_batt(batt),
            Some(BatteryState {
                on_battery: true,
                percent: Some(85)
            })
        );
        let ac = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=1)\t100%; charged; 0:00 remaining present: true\n";
        assert_eq!(
            parse_pmset_batt(ac),
            Some(BatteryState {
                on_battery: false,
                percent: Some(100)
            })
        );
        let desktop = "Now drawing from 'AC Power'\n";
        assert_eq!(
            parse_pmset_batt(desktop),
            Some(BatteryState {
                on_battery: false,
                percent: None
            })
        );
        assert_eq!(parse_pmset_batt("garbage"), None);
        assert_eq!(parse_pmset_batt(""), None);
    }

    #[test]
    fn protected_paths() {
        assert!(is_protected_system_path(Path::new("/System/Library/x")));
        assert!(is_protected_system_path(Path::new("/usr/bin/ssh")));
        assert!(is_protected_system_path(Path::new("/usr")));
        assert!(!is_protected_system_path(Path::new("/usr/local/bin/x")));
        assert!(!is_protected_system_path(Path::new(
            "/Users/q/Downloads/a.dmg"
        )));
        assert!(!is_protected_system_path(Path::new("/Systemx")));
    }

    #[test]
    fn identity_helpers() {
        let me = euid();
        assert!(user_by_uid(me).is_some());
        assert!(console_user().is_some());
        assert!(rss_bytes() > 0);
        assert!(pid_path(std::process::id() as i32).is_some());
        assert!(pid_path(0).is_none());
    }

    #[test]
    fn kill_guards() {
        assert!(kill_if_path(1, Path::new("/sbin/init")).is_err());
        assert!(kill_if_path(std::process::id() as i32, Path::new("/x")).is_err());
        // A pid that does not run `/nonexistent` is left alone.
        let child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        assert_eq!(kill_if_path(pid, Path::new("/nonexistent")), Ok(false));
        let real = pid_path(pid).unwrap();
        assert_eq!(kill_if_path(pid, &real), Ok(true));
        let mut child = child;
        let _ = child.wait();
    }

    #[test]
    fn unix_socket_peer_credentials() {
        use std::os::fd::AsRawFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let c = peer_credentials(a.as_raw_fd()).unwrap();
        assert_eq!(c.uid, euid());
        assert_eq!(c.pid, Some(std::process::id() as i32));
        assert_eq!(peer_executable(&c), pid_path(std::process::id() as i32));
    }

    #[tokio::test]
    async fn commands_and_timeouts() {
        let out = run_command("/bin/echo", &["hi"], Duration::from_secs(5))
            .await
            .unwrap();
        assert!(out.success());
        assert_eq!(out.stdout.trim(), "hi");
        assert!(
            run_command("/bin/sleep", &["5"], Duration::from_millis(100))
                .await
                .is_err()
        );
        assert!(
            run_command("/nonexistent/tool", &[], Duration::from_secs(1))
                .await
                .is_err()
        );
    }

    #[test]
    fn sync_commands_time_out() {
        assert!(run_sync("/bin/true", &[], Duration::from_secs(5)));
        assert!(!run_sync("/bin/false", &[], Duration::from_secs(5)));
        let t = std::time::Instant::now();
        assert!(!run_sync(
            "/bin/sleep",
            &[std::ffi::OsStr::new("10")],
            Duration::from_millis(200)
        ));
        assert!(t.elapsed() < Duration::from_secs(5));
        assert!(!run_sync("/nonexistent", &[], Duration::from_secs(1)));
    }

    #[test]
    fn local_dates() {
        assert_eq!(local_date(1_761_350_400).len(), 10);
    }

    #[test]
    fn qos_guard_is_harmless() {
        let _g = QosGuard::enter(ScanPriority::Background, true);
    }
}
