//! [`DnsSupervisor`]: runs dnscrypt-proxy while DNS blocking is enabled, health-checks it, fails open.
//!
//! - Spawns `components/dnscrypt-proxy/dnscrypt-proxy -config dns/dnscrypt-proxy.toml` (only when
//!   `dns.enabled` and the binary exists), restarts it with exponential backoff (1 s → 5 min).
//! - Health check every 30 s (10 s after a failure, 2 s right after a start): one UDP `A` query for
//!   `example.com` to the listen address; NOERROR/NXDOMAIN = healthy.
//! - First healthy answer ⇒ system DNS switched to the proxy ([`DnsManager::apply_system_dns`]).
//! - **Fail-open**: 3 unhealthy checks in a row ⇒ original DNS restored, `running=false` + message;
//!   re-applied automatically once healthy again.
//! - Every 60 s while applied: newly appeared network services are switched too.
//! - Restarts the proxy when the lists (`dns/lists-state.json`) or the binary change (component update),
//!   or when the `[dns]` config section changes (lists rebuilt for custom rules).
//! - On shutdown (or when disabled): original DNS restored, proxy stopped.

use crate::manager::{our_servers, DnsManager};
use crate::packet::probe;
use crate::proxy_config::parse_listen;
use pb_core::config::{Config, DnsConfig};
use std::borrow::Borrow;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::process::{Child, Command};
use tokio::sync::watch;
use tokio::time::{sleep_until, Instant};

const HEALTH_INTERVAL: Duration = Duration::from_secs(30);
const HEALTH_RETRY: Duration = Duration::from_secs(10);
const HEALTH_AFTER_START: Duration = Duration::from_secs(2);
const NETWORK_POLL: Duration = Duration::from_secs(60);
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const FAIL_OPEN_AFTER: u32 = 3;
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(300);
/// A proxy up this long resets the restart backoff.
const STABLE_AFTER: Duration = Duration::from_secs(600);

/// Supervises dnscrypt-proxy. Construct with the shared [`DnsManager`] and run it in its own task.
pub struct DnsSupervisor {
    manager: Arc<DnsManager>,
}

/// Fingerprint of what the running proxy was started with.
#[derive(Debug, Clone, PartialEq)]
struct Generation {
    lists: Option<SystemTime>,
    binary: Option<SystemTime>,
}

fn mtime(p: &Path) -> Option<SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

struct Proc {
    child: Child,
    started: Instant,
    generation: Generation,
}

fn dns_of<C: Borrow<Config>>(rx: &watch::Receiver<C>) -> DnsConfig {
    let guard = rx.borrow();
    let c: &Config = (*guard).borrow();
    c.dns.clone()
}

async fn wait_child(p: &mut Option<Proc>) -> std::io::Result<std::process::ExitStatus> {
    match p {
        Some(p) => p.child.wait().await,
        None => std::future::pending().await,
    }
}

async fn stop(p: &mut Option<Proc>, pidfile: &Path) {
    if let Some(mut proc_) = p.take() {
        let _ = proc_.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), proc_.child.wait()).await;
    }
    crate::pidfile::remove_pidfile(pidfile);
}

/// The supervised child is still running (not exited, not yet reaped).
fn child_alive(p: &mut Option<Proc>) -> bool {
    p.as_mut().is_some_and(|p| matches!(p.child.try_wait(), Ok(None)))
}

/// Last non-empty line of the proxy log (for error messages), bounded.
fn last_log_line(dir: &Path) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(dir.join("dnscrypt-proxy.log")).ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(4096))).ok()?;
    let mut buf = Vec::new();
    f.take(4096).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    text.lines()
        .rfind(|l| !l.trim().is_empty())
        .map(|l| l.chars().take(200).collect())
}

impl DnsSupervisor {
    pub fn new(manager: Arc<DnsManager>) -> Self {
        Self { manager }
    }

    fn generation(&self) -> Generation {
        Generation {
            lists: mtime(&self.manager.lists_state_path()),
            binary: mtime(&self.manager.proxy_binary()),
        }
    }

    async fn spawn(&self, dns: &DnsConfig, rebuild_lists: bool) -> Result<Proc, String> {
        let config = self
            .manager
            .prepare(dns, rebuild_lists)
            .await
            .map_err(|e| e.to_string())?;
        let bin: PathBuf = self.manager.checked_proxy_binary().map_err(|e| e.to_string())?;
        let child = Command::new(&bin)
            .arg("-config")
            .arg(&config)
            .current_dir(self.manager.dns_dir())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("lancement de dnscrypt-proxy impossible : {e}"))?;
        tracing::info!(pid = child.id(), "dnscrypt-proxy started");
        if let Some(pid) = child.id() {
            if let Err(e) = crate::pidfile::write_pidfile(&self.manager.pidfile_path(), pid) {
                tracing::warn!(error = %e, "cannot write the dnscrypt-proxy pidfile");
            }
        }
        Ok(Proc {
            child,
            started: Instant::now(),
            generation: self.generation(),
        })
    }

    /// Run until `shutdown` becomes `true` (or a sender is dropped). Calls
    /// [`DnsManager::recover_on_startup`] first. Restores the original DNS before returning.
    /// `C` is `Config` or `Arc<Config>` (anything that borrows as a [`Config`]).
    pub async fn run<C>(self, mut cfg: watch::Receiver<C>, mut shutdown: watch::Receiver<bool>)
    where
        C: Borrow<Config> + Send + Sync + 'static,
    {
        let m = self.manager.clone();
        let initial = dns_of(&cfg);
        let pidfile = m.pidfile_path();
        // An orphan proxy from a killed daemon would hold :53 and answer our health probes.
        if let Some(pid) = crate::pidfile::kill_stale(&pidfile, &m.proxy_binary()).await {
            tracing::warn!(pid, "stale dnscrypt-proxy stopped");
        }
        if let Err(e) = m.recover_on_startup(&initial).await {
            tracing::error!(error = %e, "DNS recovery at startup failed");
        }
        let mut proc_: Option<Proc> = None;
        let mut running_cfg: Option<DnsConfig> = None;
        let mut applied = false; // system DNS currently points at us
        let mut failures: u32 = 0;
        let mut backoff = BACKOFF_MIN;
        let mut next_spawn = Instant::now();
        let mut next_health = Instant::now() + HEALTH_INTERVAL;
        let mut next_net = Instant::now() + NETWORK_POLL;

        loop {
            if *shutdown.borrow() {
                break;
            }
            let dns = dns_of(&cfg);
            // Refuse a non-loopback / non-53 listen address and a missing or untrusted binary.
            let blocked = if !dns.enabled {
                None
            } else if let Err(e) = our_servers(&dns.listen) {
                Some(e.to_string())
            } else if let Err(e) = m.checked_proxy_binary() {
                Some(e.to_string())
            } else {
                None
            };
            let want = dns.enabled && blocked.is_none();

            if !want {
                if proc_.is_some() || applied || running_cfg.is_some() {
                    if let Err(e) = m.restore_system_dns().await {
                        tracing::error!(error = %e, "restoring system DNS failed");
                    }
                    stop(&mut proc_, &pidfile).await;
                    applied = false;
                    running_cfg = None;
                    failures = 0;
                    m.set_runtime(|r| r.failed_open = false);
                }
                let reason = blocked.clone();
                m.set_runtime(|r| r.message = reason);
            } else {
                // Config changed while running: rebuild lists (custom rules) and restart.
                let changed = running_cfg.as_ref().is_some_and(|c| c != &dns);
                if changed {
                    tracing::info!("DNS configuration changed: restarting dnscrypt-proxy");
                    stop(&mut proc_, &pidfile).await;
                    next_spawn = Instant::now();
                }
                if proc_.is_none() && Instant::now() >= next_spawn {
                    // Lists are rebuilt on the first start (custom rules may have changed while stopped)
                    // and whenever the [dns] section changed.
                    let rebuild = changed || running_cfg.is_none();
                    match self.spawn(&dns, rebuild).await {
                        Ok(p) => {
                            proc_ = Some(p);
                            running_cfg = Some(dns.clone());
                            next_health = Instant::now() + HEALTH_AFTER_START;
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "cannot start dnscrypt-proxy");
                            m.set_runtime(|r| r.message = Some(e));
                            next_spawn = Instant::now() + backoff;
                            backoff = (backoff * 2).min(BACKOFF_MAX);
                            running_cfg = Some(dns.clone());
                        }
                    }
                }
            }

            let restart_at = if want && proc_.is_none() {
                Some(next_spawn)
            } else {
                None
            };
            tokio::select! {
                r = shutdown.changed() => {
                    if r.is_err() || *shutdown.borrow() { break; }
                }
                r = cfg.changed() => {
                    if r.is_err() { break; }
                }
                status = wait_child(&mut proc_) => {
                    let detail = last_log_line(&m.runtime_dir()).unwrap_or_default();
                    tracing::warn!(?status, %detail, "dnscrypt-proxy exited");
                    let stable = proc_.as_ref().is_some_and(|p| p.started.elapsed() >= STABLE_AFTER);
                    proc_ = None;
                    if stable { backoff = BACKOFF_MIN; }
                    next_spawn = Instant::now() + backoff;
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    next_health = Instant::now();
                    m.set_runtime(|r| r.message = Some(format!("dnscrypt-proxy s'est arrêté ({detail}) — redémarrage")));
                }
                _ = sleep_until(restart_at.unwrap_or_else(|| Instant::now() + Duration::from_secs(3600))), if restart_at.is_some() => {}
                _ = sleep_until(next_health), if want => {
                    // Only our own, still running child counts: an answer from anything else on the
                    // listen address must never make us switch the system DNS.
                    let healthy = match (child_alive(&mut proc_), parse_listen(&dns.listen)) {
                        (true, Ok(addr)) => {
                            matches!(probe(addr, PROBE_TIMEOUT).await, Ok(info) if info.is_healthy())
                                && child_alive(&mut proc_)
                        }
                        _ => false,
                    };
                    if healthy {
                        failures = 0;
                        if !applied {
                            match m.apply_system_dns(&dns, false).await {
                                Ok(svcs) => {
                                    applied = true;
                                    tracing::info!(services = ?svcs, "DNS blocking active");
                                }
                                Err(e) => tracing::error!(error = %e, "cannot switch system DNS"),
                            }
                        }
                        m.set_runtime(|r| { r.failed_open = false; r.message = None; });
                        if proc_.as_ref().is_some_and(|p| p.started.elapsed() >= STABLE_AFTER) {
                            backoff = BACKOFF_MIN;
                        }
                        // New lists / new binary: restart to load them (hot reload is off).
                        if proc_.as_ref().is_some_and(|p| p.generation != self.generation()) {
                            tracing::info!("DNS lists or dnscrypt-proxy binary changed: restarting");
                            stop(&mut proc_, &pidfile).await;
                            next_spawn = Instant::now();
                        }
                        next_health = Instant::now() + HEALTH_INTERVAL;
                    } else {
                        failures += 1;
                        tracing::warn!(failures, "dnscrypt-proxy health check failed");
                        if failures >= FAIL_OPEN_AFTER && applied {
                            match m.restore_system_dns().await {
                                Ok(_) => {
                                    applied = false;
                                    m.set_runtime(|r| {
                                        r.failed_open = true;
                                        r.message = Some("dnscrypt-proxy ne répond pas : DNS d'origine restaurés (fail-open), nouvel essai automatique".into());
                                    });
                                }
                                Err(e) => tracing::error!(error = %e, "fail-open restore failed"),
                            }
                        }
                        next_health = Instant::now() + HEALTH_RETRY;
                    }
                }
                _ = sleep_until(next_net), if applied => {
                    if let Err(e) = m.apply_system_dns(&dns, true).await {
                        tracing::warn!(error = %e, "network change pass failed");
                    }
                    next_net = Instant::now() + NETWORK_POLL;
                }
            }
        }

        if let Err(e) = m.restore_system_dns().await {
            tracing::error!(error = %e, "restoring system DNS at shutdown failed");
        }
        stop(&mut proc_, &pidfile).await;
        tracing::info!("DNS supervisor stopped");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::manager::tests::fake_manager;
    use crate::packet::tests::make_response;
    use std::os::unix::fs::PermissionsExt;

    /// Fake "proxy": the supervisor spawns a shell script; the DNS answers come from a UDP responder
    /// running in the test (listen address chosen by the test, port 53 is not needed for the probe path).
    #[tokio::test]
    async fn spawns_applies_and_restores_on_shutdown() {
        let d = tempfile::tempdir().unwrap();
        let (m, net) = fake_manager(d.path(), &[("Wi-Fi", &["192.168.1.1"])]);
        let m = Arc::new(m);
        let bin = m.proxy_binary();
        std::fs::create_dir_all(bin.parent().unwrap()).unwrap();
        std::fs::write(&bin, "#!/bin/sh\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();

        // UDP responder on 127.0.0.1:<port>: apply_system_dns requires port 53, so the supervisor will log
        // the error but the health path is still exercised; use a listen on 127.0.0.1:53 only if free.
        let sock = match tokio::net::UdpSocket::bind("127.0.0.1:53").await {
            Ok(s) => s,
            Err(_) => return, // not root / port busy: skip (covered by manager tests)
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let _ = sock.send_to(&make_response(&buf[..n], 0), peer).await;
            }
        });
        let mut config = Config::default();
        config.dns.enabled = true;
        let (cfg_tx, cfg_rx) = watch::channel(config.clone());
        let (sd_tx, sd_rx) = watch::channel(false);
        let task = tokio::spawn(DnsSupervisor::new(m.clone()).run(cfg_rx, sd_rx));
        for _ in 0..100 {
            if net.lock().unwrap().services["Wi-Fi"] == vec!["127.0.0.1".to_string()] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            net.lock().unwrap().services["Wi-Fi"],
            vec!["127.0.0.1".to_string()]
        );
        sd_tx.send(true).unwrap();
        task.await.unwrap();
        assert_eq!(
            net.lock().unwrap().services["Wi-Fi"],
            vec!["192.168.1.1".to_string()]
        );
        drop(cfg_tx);
    }

    #[tokio::test]
    async fn disabled_config_restores_leftovers_and_exits_on_shutdown() {
        let d = tempfile::tempdir().unwrap();
        let (m, net) = fake_manager(d.path(), &[("Wi-Fi", &["127.0.0.1"])]);
        let mut s = crate::system::SavedDns::new();
        s.services.insert("Wi-Fi".into(), vec!["1.1.1.1".into()]);
        crate::system::write_saved(&m.saved_dns_path(), &s).unwrap();
        let (_cfg_tx, cfg_rx) = watch::channel(Arc::new(Config::default()));
        let (sd_tx, sd_rx) = watch::channel(false);
        let task = tokio::spawn(DnsSupervisor::new(Arc::new(m)).run(cfg_rx, sd_rx));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            net.lock().unwrap().services["Wi-Fi"],
            vec!["1.1.1.1".to_string()]
        );
        sd_tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }
}
