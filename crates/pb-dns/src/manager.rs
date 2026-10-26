//! [`DnsManager`]: lists, proxy configuration, system DNS switching (with saved originals) and status.

use crate::lists::{render_name_file, ListBuilder};
use crate::packet::probe;
use crate::proxy_config::{parse_listen, render, ProxyConfigParams};
use crate::system::{is_ours, load_saved, write_saved, Backend, SavedDns, SavedState};
use crate::{querylog, DnsError};
use crate::{
    ALLOWED_NAMES_FILE, BLOCKED_LOG_FILE, BLOCKED_NAMES_FILE, LISTS_STATE_FILE, PROXY_CONFIG_FILE,
    RUNTIME_DIR, SAVED_DNS_FILE,
};
use pb_core::config::DnsConfig;
use pb_core::model::DnsStatus;
use pb_core::paths::Paths;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Unprivileged account dnscrypt-proxy switches to after binding port 53 (macOS, when run as root).
pub const PROXY_USER: &str = "nobody";

/// `dns/lists-state.json`: summary of the last list build (read by `status`, watched by the supervisor).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ListsState {
    pub built_at: i64,
    pub blocked: u64,
    pub allowed: u64,
    pub list_version: Option<String>,
    pub truncated: bool,
}

/// Live information shared with the supervisor.
#[derive(Debug, Clone, Default)]
pub(crate) struct RuntimeInfo {
    pub(crate) message: Option<String>,
    pub(crate) failed_open: bool,
    pub(crate) listen: Option<String>,
}

/// System-wide DNS blocking manager. Share it in an `Arc` with the [`crate::DnsSupervisor`].
pub struct DnsManager {
    paths: Paths,
    backend: Backend,
    proxy_user: Option<String>,
    switch_lock: tokio::sync::Mutex<()>,
    runtime: std::sync::Mutex<RuntimeInfo>,
    /// Ancestors checked by the trust policy stop here (`/` in production; a temp dir in tests).
    trust_boundary: PathBuf,
}

impl std::fmt::Debug for DnsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsManager")
            .field("dns_dir", &self.paths.dns_dir())
            .finish()
    }
}

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// The system DNS servers pointing at our proxy (the listen IP; the port must be 53).
pub fn our_servers(listen: &str) -> Result<Vec<String>, DnsError> {
    let addr: SocketAddr = parse_listen(listen)?;
    if addr.port() != 53 {
        return Err(DnsError::Config(format!(
            "le port d'écoute doit être 53 pour servir de DNS système (actuel : {})",
            addr.port()
        )));
    }
    Ok(vec![addr.ip().to_string()])
}

/// Build the merged lists into `dns_dir` (blocking; call from `spawn_blocking` for big lists).
fn rebuild_lists_at(
    dns_dir: &Path,
    cfg: &DnsConfig,
    bundle_dir: Option<&Path>,
) -> Result<ListsState, DnsError> {
    std::fs::create_dir_all(dns_dir)?;
    let mut b = ListBuilder::new();
    let mut list_version = None;
    if let Some(dir) = bundle_dir {
        for (enabled, file) in [
            (cfg.block_malware, "malware.txt"),
            (cfg.block_ads, "ads.txt"),
            (cfg.block_trackers, "trackers.txt"),
        ] {
            if enabled {
                b.add_file(&dir.join("dns").join(file), false)?;
            }
        }
        b.add_file(&dir.join("dns").join("allowlist.txt"), true)?;
        list_version = bundle_version(dir);
    }
    b.add_entries(&cfg.custom_block, false);
    b.add_entries(&cfg.custom_allow, true);
    let truncated = b.truncated();
    let merged = b.finish();
    crate::fsutil::atomic_write(
        &dns_dir.join(BLOCKED_NAMES_FILE),
        render_name_file("bloqués", &merged.blocked).as_bytes(),
        0o644,
    )?;
    crate::fsutil::atomic_write(
        &dns_dir.join(ALLOWED_NAMES_FILE),
        render_name_file("autorisés", &merged.allowed).as_bytes(),
        0o644,
    )?;
    let st = ListsState {
        built_at: pb_core::now_ts(),
        blocked: merged.blocked.len() as u64,
        allowed: merged.allowed.len() as u64,
        list_version,
        truncated,
    };
    let bytes =
        serde_json::to_vec_pretty(&st).map_err(|e| DnsError::Io(std::io::Error::other(e)))?;
    crate::fsutil::atomic_write(&dns_dir.join(LISTS_STATE_FILE), &bytes, 0o644)?;
    if truncated {
        tracing::warn!(
            "DNS lists truncated at {} entries",
            crate::lists::MAX_ENTRIES
        );
    }
    tracing::info!(
        blocked = st.blocked,
        allowed = st.allowed,
        "DNS lists rebuilt"
    );
    Ok(st)
}

/// `version` of the bundle manifest (`<bundle>/manifest.json`), bounded read.
fn bundle_version(dir: &Path) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(dir.join(pb_core::db::MANIFEST_FILE)).ok()?;
    let mut buf = Vec::new();
    f.take(32 * 1024 * 1024).read_to_end(&mut buf).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&buf).ok()?;
    v.get("version")?.as_str().map(str::to_string)
}

impl DnsManager {
    /// Manager for the real system (macOS `networksetup`; no-op backend elsewhere).
    pub fn new(paths: Paths) -> Self {
        let proxy_user = (cfg!(target_os = "macos") && is_root()).then(|| PROXY_USER.to_string());
        Self::with_backend(paths, Backend::system(), proxy_user)
    }

    pub(crate) fn with_backend(paths: Paths, backend: Backend, proxy_user: Option<String>) -> Self {
        Self {
            paths,
            backend,
            proxy_user,
            switch_lock: tokio::sync::Mutex::new(()),
            runtime: std::sync::Mutex::new(RuntimeInfo::default()),
            trust_boundary: PathBuf::from("/"),
        }
    }

    #[cfg(test)]
    pub(crate) fn set_trust_boundary(&mut self, b: &Path) {
        self.trust_boundary = b.to_path_buf();
    }

    /// `dns/dnscrypt-proxy.pid` (root-owned directory, written by the supervisor).
    pub fn pidfile_path(&self) -> PathBuf {
        self.dns_dir().join(crate::PIDFILE)
    }

    /// The proxy binary, checked: present and — when running as root — root-owned and not writable by
    /// group/others along its whole path. Returns the canonical path to execute.
    pub fn checked_proxy_binary(&self) -> Result<PathBuf, DnsError> {
        let bin = self.proxy_binary();
        if !bin.is_file() {
            return Err(DnsError::ProxyMissing);
        }
        let info = crate::trust::inspect_binary_under(&bin, &self.trust_boundary)?;
        if crate::trust::running_as_root() && !info.trusted {
            return Err(DnsError::Untrusted(format!("{} : {}", bin.display(), info.reasons.join(" ; "))));
        }
        Ok(info.canonical)
    }

    // ----- paths -----

    pub fn dns_dir(&self) -> PathBuf {
        self.paths.dns_dir()
    }
    /// `components/dnscrypt-proxy/dnscrypt-proxy` (installed by pb-updater).
    pub fn proxy_binary(&self) -> PathBuf {
        crate::proxy_binary(&self.paths)
    }
    pub fn proxy_config_path(&self) -> PathBuf {
        self.dns_dir().join(PROXY_CONFIG_FILE)
    }
    pub fn saved_dns_path(&self) -> PathBuf {
        self.dns_dir().join(SAVED_DNS_FILE)
    }
    pub fn runtime_dir(&self) -> PathBuf {
        self.dns_dir().join(RUNTIME_DIR)
    }
    pub(crate) fn lists_state_path(&self) -> PathBuf {
        self.dns_dir().join(LISTS_STATE_FILE)
    }

    pub(crate) fn set_runtime(&self, f: impl FnOnce(&mut RuntimeInfo)) {
        let mut g = self.runtime.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut g);
    }

    fn runtime(&self) -> RuntimeInfo {
        self.runtime
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Last list build summary.
    pub fn lists_state(&self) -> Option<ListsState> {
        let bytes = std::fs::read(self.lists_state_path()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Network services whose DNS we changed (keys of `saved-dns.json`).
    pub fn managed_services(&self) -> Vec<String> {
        match load_saved(&self.saved_dns_path()) {
            SavedState::Present(s) => s.services.keys().cloned().collect(),
            _ => Vec::new(),
        }
    }

    // ----- lists & config -----

    /// Merge the bundle lists (`<bundle>/dns/{malware,ads,trackers}.txt` per `block_*`, minus
    /// `dns/allowlist.txt`) with `custom_block` / `custom_allow`, write `dns/blocked-names.txt` and
    /// `dns/allowed-names.txt`. Returns the number of blocked patterns. CPU/IO heavy for big lists: call it
    /// from `spawn_blocking`. The supervisor restarts dnscrypt-proxy when it sees the new lists.
    pub fn rebuild_lists(
        &self,
        cfg: &DnsConfig,
        bundle_dir: Option<&Path>,
    ) -> Result<u64, DnsError> {
        rebuild_lists_at(&self.dns_dir(), cfg, bundle_dir).map(|s| s.blocked)
    }

    fn ensure_runtime_dir(&self) -> Result<(), DnsError> {
        let rt = self.runtime_dir();
        std::fs::create_dir_all(&rt)?;
        crate::fsutil::set_mode(&rt, 0o755)?;
        #[cfg(unix)]
        if let Some(user) = &self.proxy_user {
            if let Some((uid, gid)) = lookup_user(user) {
                std::os::unix::fs::chown(&rt, Some(uid), Some(gid))?;
                // Files created earlier by a root-run proxy must stay writable after the switch.
                if let Ok(rd) = std::fs::read_dir(&rt) {
                    for e in rd.flatten().take(64) {
                        if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                            let _ = std::os::unix::fs::lchown(e.path(), Some(uid), Some(gid));
                        }
                    }
                }
            } else {
                return Err(DnsError::Config(format!("utilisateur {user} introuvable")));
            }
        }
        Ok(())
    }

    /// Write `dns/dnscrypt-proxy.toml` (and prepare `dns/runtime/`). Returns its path.
    pub fn write_proxy_config(&self, cfg: &DnsConfig) -> Result<PathBuf, DnsError> {
        std::fs::create_dir_all(self.dns_dir())?;
        self.ensure_runtime_dir()?;
        let (b, a, rt) = (
            self.dns_dir().join(BLOCKED_NAMES_FILE),
            self.dns_dir().join(ALLOWED_NAMES_FILE),
            self.runtime_dir(),
        );
        let text = render(&ProxyConfigParams {
            listen: &cfg.listen,
            server_names: &cfg.upstream_servers,
            blocked_names_file: &b,
            allowed_names_file: &a,
            runtime_dir: &rt,
            user_name: self.proxy_user.as_deref(),
        })?;
        let path = self.proxy_config_path();
        crate::fsutil::atomic_write(&path, text.as_bytes(), 0o644)?;
        Ok(path)
    }

    /// Make sure lists + config exist (lists are built from `db/current` if missing).
    pub(crate) async fn prepare(
        &self,
        cfg: &DnsConfig,
        force_lists: bool,
    ) -> Result<PathBuf, DnsError> {
        if force_lists || !self.dns_dir().join(BLOCKED_NAMES_FILE).exists() {
            let dns_dir = self.dns_dir();
            let cfg2 = cfg.clone();
            let current = self.paths.db_current();
            tokio::task::spawn_blocking(move || {
                let bundle = current.exists().then_some(current);
                rebuild_lists_at(&dns_dir, &cfg2, bundle.as_deref())
            })
            .await
            .map_err(|e| DnsError::Io(std::io::Error::other(e)))??;
        }
        self.write_proxy_config(cfg)
    }

    // ----- system DNS -----

    /// Point every enabled network service at the proxy. Originals are saved to `saved-dns.json` **before**
    /// any change; services already saved keep their recorded originals; current values that are already
    /// ours are recorded as DHCP (never as our loopback address). With `only_new`, services already
    /// managed are left untouched (periodic network-change pass). Returns the managed services.
    pub(crate) async fn apply_system_dns(
        &self,
        cfg: &DnsConfig,
        only_new: bool,
    ) -> Result<Vec<String>, DnsError> {
        let ours = our_servers(&cfg.listen)?;
        let _g = self.switch_lock.lock().await;
        let services = self.backend.list_services().await?;
        let path = self.saved_dns_path();
        let (mut saved, existed) = match load_saved(&path) {
            SavedState::Present(s) => (s, true),
            SavedState::Absent => (SavedDns::new(), false),
            SavedState::Corrupt => {
                tracing::error!("saved-dns.json is corrupt; keeping it aside");
                let _ = std::fs::rename(&path, path.with_extension("json.corrupt"));
                (SavedDns::new(), false)
            }
        };
        let mut to_set = Vec::new();
        let mut added = false;
        for svc in &services {
            if saved.services.contains_key(svc) {
                if !only_new {
                    to_set.push(svc.clone());
                }
                continue;
            }
            let current = match self.backend.get_dns(svc).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(service = %svc, error = %e, "cannot read DNS servers; service skipped");
                    continue;
                }
            };
            let original = if is_ours(&current, &ours) {
                Vec::new()
            } else {
                current
            };
            saved.services.insert(svc.clone(), original);
            to_set.push(svc.clone());
            added = true;
        }
        if added || (!existed && !saved.services.is_empty()) {
            saved.saved_at = pb_core::now_ts();
            write_saved(&path, &saved)?;
        }
        let mut changed = false;
        let mut first_err = None;
        for svc in &to_set {
            match self.backend.get_dns(svc).await {
                Ok(cur) if cur == ours => continue,
                _ => {}
            }
            match self.backend.set_dns(svc, &ours).await {
                Ok(()) => changed = true,
                Err(e) => {
                    tracing::warn!(service = %svc, error = %e, "cannot set DNS servers");
                    first_err.get_or_insert(e);
                }
            }
        }
        if changed {
            self.backend.flush().await;
            tracing::info!(services = ?to_set, "system DNS pointed at dnscrypt-proxy");
        }
        self.set_runtime(|r| r.listen = Some(cfg.listen.clone()));
        match first_err {
            Some(e) if !changed => Err(e),
            _ => Ok(saved.services.keys().cloned().collect()),
        }
    }

    /// Restore the original DNS of every managed service (DHCP for empty entries), flush caches and delete
    /// `saved-dns.json`. Does **not** touch the configuration (`dns.enabled` stays as is, so the next start
    /// re-applies): this is the fast path for daemon shutdown (SIGTERM) and for fail-open.
    /// Returns the restored services. A no-op when nothing is saved.
    pub async fn restore_system_dns(&self) -> Result<Vec<String>, DnsError> {
        let _g = self.switch_lock.lock().await;
        let path = self.saved_dns_path();
        let saved = load_saved(&path);
        if saved == SavedState::Absent {
            return Ok(Vec::new());
        }
        let services = self.backend.list_services().await.unwrap_or_default();
        let mut restored = Vec::new();
        let mut failed = SavedDns::new();
        match saved {
            SavedState::Present(s) => {
                for (svc, original) in s.services {
                    if !services.contains(&svc) {
                        continue; // service gone: nothing to restore
                    }
                    match self.backend.set_dns(&svc, &original).await {
                        Ok(()) => restored.push(svc),
                        Err(e) => {
                            tracing::error!(service = %svc, error = %e, "cannot restore DNS servers");
                            failed.services.insert(svc, original);
                        }
                    }
                }
            }
            SavedState::Corrupt => {
                // Originals unknown: never leave a service pointing at a dead local proxy — back to DHCP.
                let ours = ["127.0.0.1".to_string(), "::1".to_string()];
                for svc in &services {
                    if let Ok(cur) = self.backend.get_dns(svc).await {
                        if is_ours(&cur, &ours) && self.backend.set_dns(svc, &[]).await.is_ok() {
                            restored.push(svc.clone());
                        }
                    }
                }
                let _ = std::fs::rename(&path, path.with_extension("json.corrupt"));
            }
            SavedState::Absent => {}
        }
        self.backend.flush().await;
        if failed.services.is_empty() {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            tracing::info!(services = ?restored, "original system DNS restored");
            Ok(restored)
        } else {
            write_saved(&path, &failed)?;
            Err(DnsError::Command(format!(
                "restauration incomplète : {}",
                failed
                    .services
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    }

    // ----- high level -----

    /// Validate the configuration (loopback listen address on port 53, trusted proxy binary) and write
    /// the lists + `dnscrypt-proxy.toml`. It does **not** touch the system DNS: only the
    /// [`crate::DnsSupervisor`] does, once its *own* dnscrypt-proxy child answers. The caller then
    /// publishes `dns.enabled = true` on the config channel.
    pub async fn enable(&self, cfg: &DnsConfig) -> Result<DnsStatus, DnsError> {
        our_servers(&cfg.listen)?;
        self.checked_proxy_binary()?;
        self.prepare(cfg, false).await?;
        let mut on = cfg.clone();
        on.enabled = true;
        self.set_runtime(|r| {
            r.message = Some("Activation en cours (démarrage de dnscrypt-proxy)…".into());
            r.listen = Some(cfg.listen.clone());
        });
        Ok(self.status(&on).await)
    }

    /// Restore the system DNS. The caller sets `dns.enabled = false` in the config (the supervisor then
    /// stops the proxy).
    pub async fn disable(&self) -> Result<DnsStatus, DnsError> {
        self.restore_system_dns().await?;
        self.set_runtime(|r| {
            r.message = None;
            r.failed_open = false;
        });
        let listen = self
            .runtime()
            .listen
            .unwrap_or_else(|| DnsConfig::default().listen);
        Ok(self
            .status(&DnsConfig {
                enabled: false,
                listen,
                ..DnsConfig::default()
            })
            .await)
    }

    /// Current status (cheap: a 700 ms local UDP probe when enabled, small file reads).
    pub async fn status(&self, cfg: &DnsConfig) -> DnsStatus {
        let ls = self.lists_state().unwrap_or_default();
        let rt = self.runtime();
        let running = if cfg.enabled {
            match parse_listen(&cfg.listen) {
                Ok(addr) => probe(addr, Duration::from_millis(700)).await.is_ok(),
                Err(_) => false,
            }
        } else {
            false
        };
        let since = pb_core::now_ts() - 86_400;
        DnsStatus {
            enabled: cfg.enabled,
            running,
            listen: cfg.listen.clone(),
            blocked_domains: ls.blocked,
            list_version: ls.list_version,
            queries_blocked_24h: querylog::count_blocked_since(
                &self.runtime_dir(),
                BLOCKED_LOG_FILE,
                since,
            ),
            managed_services: self.managed_services(),
            message: if cfg.enabled { rt.message } else { None },
        }
    }

    /// Crash safety at daemon start: if DNS blocking is disabled (or the proxy binary is missing) but
    /// `saved-dns.json` exists, the previous run died while the system DNS pointed at us — restore it.
    pub async fn recover_on_startup(&self, cfg: &DnsConfig) -> Result<(), DnsError> {
        if load_saved(&self.saved_dns_path()) == SavedState::Absent {
            return Ok(());
        }
        if !cfg.enabled {
            tracing::warn!("saved DNS found while DNS blocking is disabled: restoring");
            self.restore_system_dns().await?;
        } else if !self.proxy_binary().is_file() {
            tracing::warn!("dnscrypt-proxy missing: restoring the original DNS (fail-open)");
            self.restore_system_dns().await?;
            self.set_runtime(|r| {
                r.failed_open = true;
                r.message = Some("dnscrypt-proxy absent : DNS d'origine restaurés".into());
            });
        }
        Ok(())
    }
}

/// uid/gid of a user (`getpwnam_r`).
#[cfg(unix)]
fn lookup_user(name: &str) -> Option<(u32, u32)> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: `passwd` is plain old data; zeroed is a valid initial value for an out-parameter.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the duration of the call; buf length is passed correctly.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::system::FakeNet;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    pub(crate) fn fake_manager(
        root: &Path,
        services: &[(&str, &[&str])],
    ) -> (DnsManager, Arc<Mutex<FakeNet>>) {
        let paths = Paths::with_root(root);
        for d in paths.all_dirs() {
            std::fs::create_dir_all(d).unwrap();
        }
        let net = Arc::new(Mutex::new(FakeNet {
            services: services
                .iter()
                .map(|(n, s)| (n.to_string(), s.iter().map(|x| x.to_string()).collect()))
                .collect::<BTreeMap<_, _>>(),
            ..Default::default()
        }));
        (
            {
                let mut m = DnsManager::with_backend(paths, Backend::Fake(net.clone()), None);
                m.set_trust_boundary(root);
                m
            },
            net,
        )
    }

    fn saved(m: &DnsManager) -> SavedDns {
        match load_saved(&m.saved_dns_path()) {
            SavedState::Present(s) => s,
            o => panic!("{o:?}"),
        }
    }

    #[tokio::test]
    async fn saved_dns_state_machine() {
        let d = tempfile::tempdir().unwrap();
        let (m, net) = fake_manager(
            d.path(),
            &[
                ("Wi-Fi", &["192.168.1.1"]),
                ("Ethernet", &[]),
                ("VPN", &["127.0.0.1"]),
            ],
        );
        let cfg = DnsConfig {
            enabled: true,
            ..Default::default()
        };

        let managed = m.apply_system_dns(&cfg, false).await.unwrap();
        assert_eq!(managed, vec!["Ethernet", "VPN", "Wi-Fi"]);
        let s = saved(&m);
        assert_eq!(s.services["Wi-Fi"], vec!["192.168.1.1"]);
        assert_eq!(s.services["Ethernet"], Vec::<String>::new());
        assert_eq!(
            s.services["VPN"],
            Vec::<String>::new(),
            "our own 127.0.0.1 is never saved as an original"
        );
        for v in net.lock().unwrap().services.values() {
            assert_eq!(v, &vec!["127.0.0.1".to_string()]);
        }
        assert_eq!(net.lock().unwrap().flushes, 1);

        // Re-applying never overwrites the saved originals with our values.
        m.apply_system_dns(&cfg, false).await.unwrap();
        assert_eq!(saved(&m).services["Wi-Fi"], vec!["192.168.1.1"]);

        // A new service appears: only it is saved and switched.
        net.lock()
            .unwrap()
            .services
            .insert("iPhone USB".into(), vec!["10.0.0.1".into()]);
        let calls_before = net.lock().unwrap().set_calls.len();
        m.apply_system_dns(&cfg, true).await.unwrap();
        assert_eq!(saved(&m).services["iPhone USB"], vec!["10.0.0.1"]);
        assert_eq!(net.lock().unwrap().set_calls.len(), calls_before + 1);
        assert_eq!(
            m.status(&DnsConfig::default()).await.managed_services.len(),
            4
        );

        // Restore: originals back (DHCP = empty), file deleted; a vanished service is skipped.
        net.lock().unwrap().services.remove("VPN");
        let restored = m.restore_system_dns().await.unwrap();
        assert_eq!(restored, vec!["Ethernet", "Wi-Fi", "iPhone USB"]);
        {
            let n = net.lock().unwrap();
            assert_eq!(n.services["Wi-Fi"], vec!["192.168.1.1"]);
            assert_eq!(n.services["Ethernet"], Vec::<String>::new());
            assert_eq!(n.services["iPhone USB"], vec!["10.0.0.1"]);
        }
        assert_eq!(load_saved(&m.saved_dns_path()), SavedState::Absent);
        // Idempotent.
        assert!(m.restore_system_dns().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn recovery_and_corrupt_state() {
        let d = tempfile::tempdir().unwrap();
        let (m, net) = fake_manager(
            d.path(),
            &[("Wi-Fi", &["127.0.0.1"]), ("Ethernet", &["9.9.9.9"])],
        );
        let cfg = DnsConfig::default(); // disabled
                                        // Crash left the system pointed at us with a saved file.
        let mut s = SavedDns::new();
        s.services
            .insert("Wi-Fi".into(), vec!["192.168.1.254".into()]);
        write_saved(&m.saved_dns_path(), &s).unwrap();
        m.recover_on_startup(&cfg).await.unwrap();
        assert_eq!(net.lock().unwrap().services["Wi-Fi"], vec!["192.168.1.254"]);
        assert_eq!(load_saved(&m.saved_dns_path()), SavedState::Absent);

        // Corrupt file: services still pointing at loopback go back to DHCP, others untouched.
        net.lock()
            .unwrap()
            .services
            .insert("Wi-Fi".into(), vec!["127.0.0.1".into()]);
        std::fs::write(m.saved_dns_path(), b"garbage").unwrap();
        m.restore_system_dns().await.unwrap();
        assert_eq!(net.lock().unwrap().services["Wi-Fi"], Vec::<String>::new());
        assert_eq!(net.lock().unwrap().services["Ethernet"], vec!["9.9.9.9"]);

        // Enabled but binary missing: fail-open on startup.
        let mut s = SavedDns::new();
        s.services.insert("Ethernet".into(), vec!["9.9.9.9".into()]);
        write_saved(&m.saved_dns_path(), &s).unwrap();
        m.recover_on_startup(&DnsConfig {
            enabled: true,
            ..Default::default()
        })
        .await
        .unwrap();
        assert_eq!(load_saved(&m.saved_dns_path()), SavedState::Absent);

        // Port other than 53 cannot be used as system DNS.
        assert!(our_servers("127.0.0.1:5353").is_err());
        assert!(m
            .apply_system_dns(
                &DnsConfig {
                    listen: "127.0.0.1:5353".into(),
                    ..Default::default()
                },
                false
            )
            .await
            .is_err());
        // enable() without the proxy binary is refused.
        assert!(matches!(
            m.enable(&DnsConfig::default()).await,
            Err(DnsError::ProxyMissing)
        ));
    }

    #[tokio::test]
    async fn rebuilds_lists_from_bundle_and_custom() {
        let d = tempfile::tempdir().unwrap();
        let (m, _net) = fake_manager(d.path(), &[]);
        let bundle = d.path().join("bundle");
        std::fs::create_dir_all(bundle.join("dns")).unwrap();
        std::fs::write(
            bundle.join("manifest.json"),
            br#"{"version":"2026.10.25.1"}"#,
        )
        .unwrap();
        std::fs::write(
            bundle.join("dns/malware.txt"),
            "evil.example\nx.evil.example\n",
        )
        .unwrap();
        std::fs::write(bundle.join("dns/ads.txt"), "ads.example\n").unwrap();
        std::fs::write(bundle.join("dns/trackers.txt"), "t.example\n").unwrap();
        std::fs::write(bundle.join("dns/allowlist.txt"), "ok.ads.example\n").unwrap();
        let cfg = DnsConfig {
            block_trackers: false,
            custom_block: vec!["mine.example".into()],
            custom_allow: vec!["*.mine.example".into()],
            ..Default::default()
        };
        let n = m.rebuild_lists(&cfg, Some(&bundle)).unwrap();
        assert_eq!(
            n, 2,
            "evil.example + ads.example (custom block fully allowed, trackers off)"
        );
        let blocked = std::fs::read_to_string(m.dns_dir().join(BLOCKED_NAMES_FILE)).unwrap();
        assert!(blocked.contains("\nevil.example\n") && blocked.contains("\nads.example\n"));
        assert!(!blocked.contains("t.example") && !blocked.contains("mine.example"));
        let allowed = std::fs::read_to_string(m.dns_dir().join(ALLOWED_NAMES_FILE)).unwrap();
        assert!(allowed.contains("\nok.ads.example\n"));
        let st = m.status(&cfg).await;
        assert_eq!(st.blocked_domains, 2);
        assert_eq!(st.list_version.as_deref(), Some("2026.10.25.1"));
        assert!(!st.running && st.queries_blocked_24h.is_none());
        let p = m.write_proxy_config(&cfg).unwrap();
        let text = std::fs::read_to_string(p).unwrap();
        assert!(text.contains("blocked-names.txt") && !text.contains("user_name"));
        assert!(m.runtime_dir().is_dir());
    }
}
