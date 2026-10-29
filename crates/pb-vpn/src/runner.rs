//! sing-box child process: `sing-box --disable-color run -c <vpn dir>/sing-box.json -D <vpn dir>`, output
//! appended to `sing-box.log` (rotated at 1 MiB), pid recorded in `sing-box.pid` for crash recovery. The TUN
//! interface it creates is found by diffing the `utun*` interfaces before / after the start.

use crate::fsutil;
use crate::netprobe::utun_interfaces;
use crate::sys::{ProcessHandle, System};
use crate::VpnError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const CONFIG_FILE: &str = "sing-box.json";
pub const LOG_FILE: &str = "sing-box.log";
pub const PID_FILE: &str = "sing-box.pid";
const MAX_LOG: u64 = 1024 * 1024;
/// SIGTERM grace before SIGKILL.
pub const STOP_GRACE: Duration = Duration::from_secs(5);
/// A started process that shows no TUN interface after this long is reported as stuck.
pub const INTERFACE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PidRecord {
    pid: i32,
    binary: PathBuf,
}

/// What [`SingBoxRunner::poll`] saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerState {
    NotRunning,
    /// Started, TUN interface not seen yet.
    Starting,
    Running {
        interface: String,
    },
    /// The process exited (message with the end of its log) or never brought its interface up.
    Failed(String),
}

pub struct SingBoxRunner {
    sys: Arc<dyn System>,
    dir: PathBuf,
    proc: Option<Box<dyn ProcessHandle>>,
    before: Vec<String>,
    interface: Option<String>,
    started: Option<Instant>,
}

/// Last meaningful lines of the log (ANSI codes stripped).
pub fn log_tail(dir: &Path, lines: usize) -> String {
    let path = dir.join(LOG_FILE);
    let Ok(data) = std::fs::read(&path) else {
        return String::new();
    };
    let start = data.len().saturating_sub(4096);
    let text = String::from_utf8_lossy(&data[start..]);
    let ansi = regex::Regex::new(r"\x1b\[[0-9;]*m").expect("static regex");
    let cleaned = ansi.replace_all(&text, "");
    let v: Vec<&str> = cleaned
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    v[v.len().saturating_sub(lines)..].join(" / ")
}

impl SingBoxRunner {
    pub fn new(sys: Arc<dyn System>, dir: &Path) -> Self {
        Self {
            sys,
            dir: dir.to_path_buf(),
            proc: None,
            before: vec![],
            interface: None,
            started: None,
        }
    }

    pub fn is_running(&self) -> bool {
        self.proc.is_some()
    }

    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }

    /// Write the config and start sing-box.
    pub async fn start(
        &mut self,
        binary: &Path,
        config: &serde_json::Value,
    ) -> Result<(), VpnError> {
        if self.proc.is_some() {
            self.stop().await;
        }
        let cfg_path = self.dir.join(CONFIG_FILE);
        let bytes =
            serde_json::to_vec_pretty(config).map_err(|e| VpnError::Failed(e.to_string()))?;
        fsutil::write_private(&cfg_path, &bytes)
            .map_err(|e| VpnError::Failed(format!("configuration sing-box : {e}")))?;
        let log = self.dir.join(LOG_FILE);
        if std::fs::metadata(&log)
            .map(|m| m.len() > MAX_LOG)
            .unwrap_or(false)
        {
            let _ = std::fs::rename(&log, self.dir.join(format!("{LOG_FILE}.1")));
        }
        self.before = utun_interfaces(self.sys.as_ref()).await;
        let args = vec![
            "--disable-color".to_string(),
            "run".to_string(),
            "-c".to_string(),
            cfg_path.to_string_lossy().into_owned(),
            "-D".to_string(),
            self.dir.to_string_lossy().into_owned(),
        ];
        let proc = self
            .sys
            .spawn(binary, &args, &log)
            .await
            .map_err(VpnError::Failed)?;
        if let Some(pid) = proc.pid() {
            let rec = PidRecord {
                pid: pid as i32,
                binary: binary.to_path_buf(),
            };
            if let Err(e) = fsutil::write_json(&self.dir.join(PID_FILE), &rec) {
                tracing::warn!(error = %e, "cannot write sing-box pid file");
            }
        }
        self.proc = Some(proc);
        self.interface = None;
        self.started = Some(Instant::now());
        tracing::info!("sing-box started");
        Ok(())
    }

    /// Check the process and look for its TUN interface.
    pub async fn poll(&mut self) -> RunnerState {
        let Some(proc) = &self.proc else {
            return RunnerState::NotRunning;
        };
        if let Some(msg) = proc.exited().await {
            let tail = log_tail(&self.dir, 3);
            self.proc = None;
            self.interface = None;
            let _ = fsutil::remove(&self.dir.join(PID_FILE));
            return RunnerState::Failed(if tail.is_empty() {
                msg
            } else {
                format!("{msg} : {tail}")
            });
        }
        if let Some(i) = &self.interface {
            return RunnerState::Running {
                interface: i.clone(),
            };
        }
        let now = utun_interfaces(self.sys.as_ref()).await;
        if let Some(new) = now.iter().find(|i| !self.before.contains(i)) {
            self.interface = Some(new.clone());
            return RunnerState::Running {
                interface: new.clone(),
            };
        }
        if !self.sys.is_macos() {
            // No interfaces to observe off macOS (tests): consider it up.
            self.interface = Some("utun".into());
            return RunnerState::Running {
                interface: "utun".into(),
            };
        }
        if self
            .started
            .map(|s| s.elapsed() > INTERFACE_TIMEOUT)
            .unwrap_or(false)
        {
            let tail = log_tail(&self.dir, 3);
            self.stop().await;
            return RunnerState::Failed(format!(
                "sing-box n'a pas créé d'interface TUN en {} s {tail}",
                INTERFACE_TIMEOUT.as_secs()
            ));
        }
        RunnerState::Starting
    }

    /// Stop the process (SIGTERM, SIGKILL after 5 s).
    pub async fn stop(&mut self) {
        if let Some(p) = self.proc.take() {
            p.terminate(STOP_GRACE).await;
            tracing::info!("sing-box stopped");
        }
        self.interface = None;
        self.started = None;
        let _ = fsutil::remove(&self.dir.join(PID_FILE));
    }

    /// A sing-box left by a previous daemon run (pid file) is terminated.
    pub async fn recover_stale(&self) {
        let path = self.dir.join(PID_FILE);
        let rec: Option<PidRecord> = fsutil::read_json(&path).ok().flatten();
        let Some(rec) = rec else {
            return;
        };
        if self.sys.process_runs(rec.pid, &rec.binary) {
            tracing::warn!(
                pid = rec.pid,
                "stale sing-box from a previous run: stopping it"
            );
            self.sys.signal(rec.pid, libc::SIGTERM);
            for _ in 0..50 {
                if !self.sys.process_runs(rec.pid, &rec.binary) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            if self.sys.process_runs(rec.pid, &rec.binary) {
                self.sys.signal(rec.pid, libc::SIGKILL);
            }
        }
        let _ = fsutil::remove(&path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::IFCONFIG;
    use crate::testutil::FakeSystem;
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn start_detects_interface_and_stops() {
        let d = tempfile::tempdir().unwrap();
        let sys = FakeSystem::macos();
        sys.respond(IFCONFIG, &["-l"], 0, "lo0 en0 utun0 utun1\n", "");
        let mut r = SingBoxRunner::new(sys.clone(), d.path());
        r.start(Path::new("/pb/sing-box"), &serde_json::json!({"log": {}}))
            .await
            .unwrap();
        let p = sys.last_process().unwrap();
        assert_eq!(p.program, Path::new("/pb/sing-box"));
        assert_eq!(p.args[0], "--disable-color");
        assert_eq!(p.args[1], "run");
        assert!(d.path().join(CONFIG_FILE).exists());
        assert!(d.path().join(PID_FILE).exists());
        assert_eq!(r.poll().await, RunnerState::Starting);
        sys.respond(IFCONFIG, &["-l"], 0, "lo0 en0 utun0 utun1 utun5\n", "");
        assert_eq!(
            r.poll().await,
            RunnerState::Running {
                interface: "utun5".into()
            }
        );
        assert_eq!(r.interface(), Some("utun5"));
        r.stop().await;
        assert!(p.terminated.load(Ordering::SeqCst));
        assert!(!d.path().join(PID_FILE).exists());
        assert_eq!(r.poll().await, RunnerState::NotRunning);
    }

    #[tokio::test]
    async fn exit_reports_log_tail() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join(LOG_FILE),
            "\x1b[31mFATAL\x1b[0m[0000] start service: initialize outbound[0]: missing tls\n",
        )
        .unwrap();
        let sys = FakeSystem::macos();
        sys.respond(IFCONFIG, &["-l"], 0, "lo0\n", "");
        let mut r = SingBoxRunner::new(sys.clone(), d.path());
        r.start(Path::new("/pb/sing-box"), &serde_json::json!({}))
            .await
            .unwrap();
        sys.last_process()
            .unwrap()
            .exited
            .store(true, Ordering::SeqCst);
        match r.poll().await {
            RunnerState::Failed(m) => {
                assert!(m.contains("missing tls"), "{m}");
                assert!(!m.contains("\x1b["));
            }
            other => panic!("{other:?}"),
        }
        assert!(!r.is_running());
    }

    #[tokio::test]
    async fn recover_stale_kills_our_binary_only() {
        let d = tempfile::tempdir().unwrap();
        fsutil::write_json(
            &d.path().join(PID_FILE),
            &PidRecord {
                pid: 4242,
                binary: "/pb/sing-box".into(),
            },
        )
        .unwrap();
        let sys = FakeSystem::macos();
        // The pid now belongs to something else: no signal.
        sys.running_pids
            .lock()
            .unwrap()
            .push((4242, "/usr/bin/other".into()));
        SingBoxRunner::new(sys.clone(), d.path())
            .recover_stale()
            .await;
        assert!(sys.signals.lock().unwrap().is_empty());
        assert!(!d.path().join(PID_FILE).exists());
        fsutil::write_json(
            &d.path().join(PID_FILE),
            &PidRecord {
                pid: 4242,
                binary: "/pb/sing-box".into(),
            },
        )
        .unwrap();
        sys.running_pids
            .lock()
            .unwrap()
            .push((4242, "/pb/sing-box".into()));
        let r = SingBoxRunner::new(sys.clone(), d.path());
        tokio::time::pause();
        r.recover_stale().await;
        let sigs = sys.signals.lock().unwrap().clone();
        assert_eq!(sigs[0], (4242, libc::SIGTERM));
        assert_eq!(sigs.last().unwrap(), &(4242, libc::SIGKILL));
    }
}
