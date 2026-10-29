//! Scripted [`System`] for unit tests.

use crate::sys::{CmdOutput, ProcessHandle, System};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type Response = (String, Vec<String>, Result<CmdOutput, String>);

#[derive(Default)]
pub struct FakeSystem {
    macos: bool,
    responses: Mutex<Vec<Response>>,
    calls: Mutex<Vec<(String, Vec<String>)>>,
    http: Mutex<HashMap<String, Result<String, String>>>,
    dns: Mutex<HashMap<String, Vec<IpAddr>>>,
    pub spawned: Mutex<Vec<Arc<FakeProcess>>>,
    /// Responses registered when the next process is spawned (e.g. the TUN interface it creates).
    after_spawn: Mutex<Vec<Response>>,
    pub spawn_error: Mutex<Option<String>>,
    pub running_pids: Mutex<Vec<(i32, PathBuf)>>,
    pub signals: Mutex<Vec<(i32, i32)>>,
    next_pid: AtomicU32,
}

impl FakeSystem {
    pub fn macos() -> Arc<Self> {
        Arc::new(Self {
            macos: true,
            next_pid: AtomicU32::new(1000),
            ..Default::default()
        })
    }

    pub fn linux() -> Arc<Self> {
        Arc::new(Self {
            macos: false,
            next_pid: AtomicU32::new(1000),
            ..Default::default()
        })
    }

    /// Answer `program` called with arguments starting with `prefix` (the latest registration wins).
    pub fn respond(&self, program: &str, prefix: &[&str], status: i32, stdout: &str, stderr: &str) {
        self.responses.lock().unwrap().push((
            program.to_string(),
            prefix.iter().map(|s| s.to_string()).collect(),
            Ok(CmdOutput {
                status: Some(status),
                stdout: stdout.into(),
                stderr: stderr.into(),
            }),
        ));
    }

    /// Like [`respond`](Self::respond), but only takes effect once a process has been spawned.
    pub fn respond_after_spawn(
        &self,
        program: &str,
        prefix: &[&str],
        status: i32,
        stdout: &str,
        stderr: &str,
    ) {
        self.after_spawn.lock().unwrap().push((
            program.to_string(),
            prefix.iter().map(|s| s.to_string()).collect(),
            Ok(CmdOutput {
                status: Some(status),
                stdout: stdout.into(),
                stderr: stderr.into(),
            }),
        ));
    }

    #[allow(dead_code)]
    pub fn fail(&self, program: &str, prefix: &[&str], err: &str) {
        self.responses.lock().unwrap().push((
            program.to_string(),
            prefix.iter().map(|s| s.to_string()).collect(),
            Err(err.into()),
        ));
    }

    pub fn http(&self, url: &str, body: Result<&str, &str>) {
        self.http
            .lock()
            .unwrap()
            .insert(url.into(), body.map(str::to_string).map_err(str::to_string));
    }

    pub fn dns(&self, host: &str, ips: &[&str]) {
        self.dns.lock().unwrap().insert(
            host.into(),
            ips.iter().map(|i| i.parse().unwrap()).collect(),
        );
    }

    pub fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().unwrap().clone()
    }

    pub fn count(&self, program: &str, prefix: &[&str]) -> usize {
        self.calls()
            .iter()
            .filter(|(p, a)| {
                p == program && a.len() >= prefix.len() && a.iter().zip(prefix).all(|(x, y)| x == y)
            })
            .count()
    }

    pub fn last_process(&self) -> Option<Arc<FakeProcess>> {
        self.spawned.lock().unwrap().last().cloned()
    }

    fn lookup(&self, program: &str, args: &[&str]) -> Result<CmdOutput, String> {
        self.calls.lock().unwrap().push((
            program.to_string(),
            args.iter().map(|s| s.to_string()).collect(),
        ));
        let resp = self.responses.lock().unwrap();
        resp.iter()
            .rev()
            .find(|(p, prefix, _)| {
                p == program
                    && args.len() >= prefix.len()
                    && args.iter().zip(prefix).all(|(a, b)| *a == b)
            })
            .map(|(_, _, r)| r.clone())
            .unwrap_or_else(|| Err(format!("no fake response for {program} {args:?}")))
    }
}

#[async_trait]
impl System for FakeSystem {
    fn is_macos(&self) -> bool {
        self.macos
    }

    async fn run(&self, program: &str, args: &[&str], _t: Duration) -> Result<CmdOutput, String> {
        self.lookup(program, args)
    }

    async fn run_as_console_user(
        &self,
        program: &str,
        args: &[&str],
        _t: Duration,
    ) -> Result<CmdOutput, String> {
        self.lookup(&format!("asuser:{program}"), args)
    }

    async fn http_get(&self, url: &str, _t: Duration) -> Result<String, String> {
        self.calls
            .lock()
            .unwrap()
            .push(("http".into(), vec![url.to_string()]));
        self.http
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .unwrap_or_else(|| Err("unreachable".into()))
    }

    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        self.dns
            .lock()
            .unwrap()
            .get(host)
            .cloned()
            .ok_or_else(|| format!("{host} : introuvable"))
    }

    async fn spawn(
        &self,
        program: &Path,
        args: &[String],
        _log: &Path,
    ) -> Result<Box<dyn ProcessHandle>, String> {
        if let Some(e) = self.spawn_error.lock().unwrap().clone() {
            return Err(e);
        }
        let p = Arc::new(FakeProcess {
            pid: self.next_pid.fetch_add(1, Ordering::SeqCst),
            program: program.to_path_buf(),
            args: args.to_vec(),
            exited: AtomicBool::new(false),
            terminated: AtomicBool::new(false),
        });
        self.spawned.lock().unwrap().push(p.clone());
        let pending: Vec<Response> = self.after_spawn.lock().unwrap().drain(..).collect();
        self.responses.lock().unwrap().extend(pending);
        Ok(Box::new(SharedProcess(p)))
    }

    fn process_runs(&self, pid: i32, exe: &Path) -> bool {
        self.running_pids
            .lock()
            .unwrap()
            .iter()
            .any(|(p, e)| *p == pid && e == exe)
    }

    fn signal(&self, pid: i32, signal: i32) {
        self.signals.lock().unwrap().push((pid, signal));
    }
}

pub struct FakeProcess {
    pub pid: u32,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub exited: AtomicBool,
    pub terminated: AtomicBool,
}

struct SharedProcess(Arc<FakeProcess>);

#[async_trait]
impl ProcessHandle for SharedProcess {
    fn pid(&self) -> Option<u32> {
        (!self.0.exited.load(Ordering::SeqCst)).then_some(self.0.pid)
    }
    async fn exited(&self) -> Option<String> {
        self.0
            .exited
            .load(Ordering::SeqCst)
            .then(|| "sing-box s'est arrêté (exit status: 1)".to_string())
    }
    async fn terminate(&self, _grace: Duration) {
        self.0.terminated.store(true, Ordering::SeqCst);
        self.0.exited.store(true, Ordering::SeqCst);
    }
}
