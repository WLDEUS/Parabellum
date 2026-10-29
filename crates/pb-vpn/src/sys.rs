//! System access behind a trait, so the orchestration is testable on Linux with scripted outputs.
//!
//! [`RealSystem`] runs tools with absolute paths, a cleared environment and timeouts; [`System::is_macos`]
//! tells the service whether macOS-only tools (pfctl, scutil, route, arp, ipconfig) may be used at all.

use async_trait::async_trait;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Absolute tool paths (macOS).
pub const PFCTL: &str = "/sbin/pfctl";
pub const SCUTIL: &str = "/usr/sbin/scutil";
pub const ROUTE: &str = "/sbin/route";
pub const NETSTAT: &str = "/usr/sbin/netstat";
pub const ARP: &str = "/usr/sbin/arp";
pub const PING: &str = "/sbin/ping";
pub const IPCONFIG: &str = "/usr/sbin/ipconfig";
pub const IFCONFIG: &str = "/sbin/ifconfig";
pub const LAUNCHCTL: &str = "/bin/launchctl";
/// `PATH` given to child processes.
pub const TOOL_PATH_ENV: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// Default timeout of the small system tools.
pub const CMD_TIMEOUT: Duration = Duration::from_secs(10);
/// Captured output cap per stream.
const MAX_OUTPUT: usize = 1024 * 1024;

/// Result of a finished command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmdOutput {
    /// Exit code (`None` when killed by a signal).
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }

    /// stdout + stderr (pfctl and scutil print useful lines on stderr).
    pub fn combined(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else if self.stdout.is_empty() {
            self.stderr.clone()
        } else {
            format!("{}\n{}", self.stdout, self.stderr)
        }
    }
}

/// A long-running child process (sing-box).
#[async_trait]
pub trait ProcessHandle: Send + Sync {
    /// Process id (None once reaped).
    fn pid(&self) -> Option<u32>;
    /// `Some(description)` once the process has exited.
    async fn exited(&self) -> Option<String>;
    /// SIGTERM, then SIGKILL after `grace`; reaps the child.
    async fn terminate(&self, grace: Duration);
}

/// Everything the VPN service needs from the operating system.
#[async_trait]
pub trait System: Send + Sync + 'static {
    /// macOS tools are available (false on Linux: system steps are skipped).
    fn is_macos(&self) -> bool;
    /// Run `program args…` and capture its output.
    async fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CmdOutput, String>;
    /// Same, in the console user's bootstrap namespace (`launchctl asuser <uid> program args…`).
    async fn run_as_console_user(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CmdOutput, String>;
    /// HTTPS GET, body as text (bounded).
    async fn http_get(&self, url: &str, timeout: Duration) -> Result<String, String>;
    /// Resolve a hostname with the system resolver.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>;
    /// Start a long-running process, stdout/stderr appended to `log`.
    async fn spawn(
        &self,
        program: &Path,
        args: &[String],
        log: &Path,
    ) -> Result<Box<dyn ProcessHandle>, String>;
    /// Does process `pid` run the executable `exe`? (stale pid files)
    fn process_runs(&self, pid: i32, exe: &Path) -> bool;
    /// Send a signal.
    fn signal(&self, pid: i32, signal: i32);
}

/// Production implementation.
#[derive(Debug, Clone)]
pub struct RealSystem {
    http: reqwest::Client,
}

impl Default for RealSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl RealSystem {
    pub fn new() -> Self {
        let http = reqwest::Client::builder()
            .user_agent(concat!("Parabellum/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::limited(3))
            .build()
            .unwrap_or_default();
        Self { http }
    }
}

/// uid of the logged-in GUI user (owner of `/dev/console`), `None` at the login window / off macOS.
pub fn console_uid() -> Option<u32> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata("/dev/console").ok()?.uid();
        (uid != 0).then_some(uid)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

fn clip_output(bytes: &[u8]) -> String {
    let b = if bytes.len() > MAX_OUTPUT {
        &bytes[..MAX_OUTPUT]
    } else {
        bytes
    };
    String::from_utf8_lossy(b).into_owned()
}

async fn run_command(program: &str, args: &[&str], timeout: Duration) -> Result<CmdOutput, String> {
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", TOOL_PATH_ENV)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    let child = cmd
        .spawn()
        .map_err(|e| format!("{program} : lancement impossible : {e}"))?;
    match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(out)) => Ok(CmdOutput {
            status: out.status.code(),
            stdout: clip_output(&out.stdout),
            stderr: clip_output(&out.stderr),
        }),
        Ok(Err(e)) => Err(format!("{program} : {e}")),
        Err(_) => Err(format!(
            "{program} : délai dépassé ({} s)",
            timeout.as_secs()
        )),
    }
}

#[async_trait]
impl System for RealSystem {
    fn is_macos(&self) -> bool {
        cfg!(target_os = "macos")
    }

    async fn run(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CmdOutput, String> {
        run_command(program, args, timeout).await
    }

    async fn run_as_console_user(
        &self,
        program: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CmdOutput, String> {
        let uid = console_uid().ok_or("aucun utilisateur connecté")?;
        let uid_s = uid.to_string();
        let mut full: Vec<&str> = vec!["asuser", &uid_s, program];
        full.extend_from_slice(args);
        run_command(LAUNCHCTL, &full, timeout).await
    }

    async fn http_get(&self, url: &str, timeout: Duration) -> Result<String, String> {
        let resp = self
            .http
            .get(url)
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("HTTP {}", resp.status()));
        }
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        if bytes.len() > 64 * 1024 {
            return Err("réponse trop grande".into());
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        let fut = tokio::net::lookup_host((host, 0u16));
        let addrs = tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .map_err(|_| format!("résolution de {host} : délai dépassé"))?
            .map_err(|e| format!("résolution de {host} : {e}"))?;
        let mut ips: Vec<IpAddr> = Vec::new();
        for a in addrs {
            if !ips.contains(&a.ip()) {
                ips.push(a.ip());
            }
        }
        if ips.is_empty() {
            return Err(format!("{host} : aucune adresse"));
        }
        Ok(ips)
    }

    async fn spawn(
        &self,
        program: &Path,
        args: &[String],
        log: &Path,
    ) -> Result<Box<dyn ProcessHandle>, String> {
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .map_err(|e| format!("journal {} : {e}", log.display()))?;
        let err_file = log_file
            .try_clone()
            .map_err(|e| format!("journal {} : {e}", log.display()))?;
        let mut cmd = tokio::process::Command::new(program);
        cmd.args(args)
            .env_clear()
            .env("PATH", TOOL_PATH_ENV)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(err_file))
            .kill_on_drop(true);
        let child = cmd
            .spawn()
            .map_err(|e| format!("{} : lancement impossible : {e}", program.display()))?;
        Ok(Box::new(RealProcess {
            pid: child.id(),
            child: tokio::sync::Mutex::new(Some(child)),
            exit: std::sync::Mutex::new(None),
        }))
    }

    fn process_runs(&self, pid: i32, exe: &Path) -> bool {
        if pid <= 1 {
            return false;
        }
        pid_executable(pid).map(|p| p == exe).unwrap_or(false)
    }

    fn signal(&self, pid: i32, signal: i32) {
        if pid > 1 {
            // SAFETY: plain kill(2) on a pid we checked belongs to our binary.
            unsafe {
                libc::kill(pid, signal);
            }
        }
    }
}

/// Executable path of a pid (macOS `proc_pidpath`, Linux `/proc/<pid>/exe`).
pub fn pid_executable(pid: i32) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let mut buf = vec![0u8; 4096];
        // SAFETY: buffer of PROC_PIDPATHINFO_MAXSIZE bytes, length passed.
        let n = unsafe {
            libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32)
        };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        Some(PathBuf::from(String::from_utf8_lossy(&buf).into_owned()))
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok()
    }
}

struct RealProcess {
    pid: Option<u32>,
    child: tokio::sync::Mutex<Option<tokio::process::Child>>,
    exit: std::sync::Mutex<Option<String>>,
}

#[async_trait]
impl ProcessHandle for RealProcess {
    fn pid(&self) -> Option<u32> {
        if self
            .exit
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
        {
            return None;
        }
        self.pid
    }

    async fn exited(&self) -> Option<String> {
        if let Some(e) = self.exit.lock().unwrap_or_else(|e| e.into_inner()).clone() {
            return Some(e);
        }
        let mut g = self.child.lock().await;
        let child = g.as_mut()?;
        match child.try_wait() {
            Ok(Some(status)) => {
                let msg = format!("sing-box s'est arrêté ({status})");
                *self.exit.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg.clone());
                *g = None;
                Some(msg)
            }
            Ok(None) => None,
            Err(e) => Some(format!("sing-box : {e}")),
        }
    }

    async fn terminate(&self, grace: Duration) {
        let mut g = self.child.lock().await;
        let Some(child) = g.as_mut() else {
            return;
        };
        if let Some(pid) = child.id() {
            // SAFETY: our own child, not yet reaped.
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
        if tokio::time::timeout(grace, child.wait()).await.is_err() {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        *self.exit.lock().unwrap_or_else(|e| e.into_inner()) = Some("arrêté".into());
        *g = None;
    }
}
