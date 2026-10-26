//! Production backends: the daemon's integration traits implemented with pb-engine, pb-monitor,
//! pb-updater and pb-dns.

use crate::backends::*;
use async_trait::async_trait;
use pb_core::config::{Config, UpdatesConfig};
use pb_core::model::*;
use pb_core::paths::Paths;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Backends used by `parabellumd`.
pub fn production(paths: &Paths) -> Backends {
    let quarantine: Arc<dyn QuarantineStore> =
        match pb_engine::Quarantine::open(&paths.quarantine_dir()) {
            Ok(q) => Arc::new(QuarantineAdapter { q }),
            Err(e) => {
                tracing::error!(error = %e, "quarantine unavailable");
                Arc::new(NullQuarantine)
            }
        };
    Backends {
        engine_loader: Arc::new(EngineLoaderImpl),
        quarantine,
        monitors: Arc::new(MonitorsAdapter::default()),
        updater: Arc::new(UpdaterAdapter::new(paths.clone())),
        dns: Arc::new(DnsAdapter::new(paths.clone())),
        reputation: Arc::new(crate::virustotal::VirusTotal::new()),
    }
}

// ---------------------------------------------------------------------------------------------
// pb-engine
// ---------------------------------------------------------------------------------------------

/// Builds [`EngineAdapter`]s with `pb_engine::Engine::load`.
#[derive(Debug, Default)]
pub struct EngineLoaderImpl;

impl EngineLoader for EngineLoaderImpl {
    fn load(&self, paths: &Paths, cfg: &Config) -> Result<Arc<dyn ScanEngine>, BackendError> {
        let engine =
            pb_engine::Engine::load(paths, cfg).map_err(|e| BackendError::Failed(e.to_string()))?;
        for w in engine.stats().warnings {
            tracing::warn!(warning = %w, "engine");
        }
        Ok(Arc::new(EngineAdapter::new(engine)))
    }
}

/// `pb_engine::Engine` behind [`ScanEngine`].
pub struct EngineAdapter {
    engine: pb_engine::Engine,
    home: Mutex<Option<(Option<PathBuf>, Instant)>>,
}

impl EngineAdapter {
    pub fn new(engine: pb_engine::Engine) -> Self {
        Self {
            engine,
            home: Mutex::new(None),
        }
    }

    /// Console user's home, cached for a minute (`~` in exclusions).
    fn home(&self) -> Option<PathBuf> {
        let mut g = self.home.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((h, at)) = g.as_ref() {
            if at.elapsed() < Duration::from_secs(60) {
                return h.clone();
            }
        }
        let h = crate::system::console_user().map(|u| u.home);
        *g = Some((h.clone(), Instant::now()));
        h
    }

    fn options(&self, cfg: &Config, opts: &ScanOpts) -> pb_engine::ScanOptions {
        let mut o = match self.home() {
            Some(h) => pb_engine::ScanOptions::from_config_for_user(cfg, opts.use_clamav, &h),
            None => pb_engine::ScanOptions::from_config(cfg, opts.use_clamav),
        };
        o.recursive = opts.recursive;
        o.only_risky_types = opts.only_risky_types;
        o
    }
}

impl ScanEngine for EngineAdapter {
    fn scan_file(&self, path: &Path, cfg: &Config, opts: &ScanOpts) -> ScanReport {
        self.engine.scan_file(path, &self.options(cfg, opts))
    }

    fn scan_tree(
        &self,
        roots: &[PathBuf],
        cfg: &Config,
        opts: &ScanOpts,
        cancel: &AtomicBool,
        sink: ReportSink<'_>,
    ) {
        let o = self.options(cfg, opts);
        let totals = self
            .engine
            .scan_paths(roots, &o, cancel, &mut |r: &ScanReport| {
                if !sink(r.clone()) {
                    cancel.store(true, Ordering::SeqCst);
                }
            });
        tracing::debug!(?totals, "scan_paths done");
    }

    fn signing_info(&self, path: &Path) -> Option<SigningInfo> {
        self.engine.signing_info(path)
    }

    fn is_trusted_team(&self, team_id: &str) -> bool {
        let s = SigningInfo {
            signed: true,
            valid: true,
            team_id: Some(team_id.to_string()),
            ..Default::default()
        };
        self.engine.is_trusted_signer(&s)
    }

    fn lookup_hash(&self, sha256: &str) -> Option<Detection> {
        self.engine.lookup_hash(sha256)
    }

    fn supports_hash_lookup(&self) -> bool {
        true
    }

    fn db_status(&self) -> DbStatus {
        let s = self.engine.stats();
        DbStatus {
            version: s.db_version,
            malware_hashes: s.malware_hashes,
            yara_rules: s.yara_rules,
            clamav_version: s.clamav_version,
            ml_model_version: s.ml_model_version,
            ..Default::default()
        }
    }

    fn clamav_available(&self) -> bool {
        self.engine.stats().clamav_available
    }

    fn ml_loaded(&self) -> bool {
        self.engine.stats().ml_model_version.is_some()
    }

    fn is_signature_grade(&self, d: &Detection, signing: Option<&SigningInfo>) -> bool {
        let trusted = signing
            .map(|s| self.engine.is_trusted_signer(s))
            .unwrap_or(false);
        pb_engine::scoring::is_signature_grade(d, trusted)
    }

    fn set_local_allowlist(&self, sha256_hex: &[String]) {
        self.engine.set_local_allowlist(sha256_hex);
    }
}

/// `pb_engine::Quarantine` behind [`QuarantineStore`].
pub struct QuarantineAdapter {
    q: pb_engine::Quarantine,
}

fn qerr(e: pb_engine::QuarantineError) -> BackendError {
    use pb_engine::QuarantineError as Q;
    match e {
        Q::NotFound(id) => BackendError::NotFound(format!("entrée de quarantaine inconnue : {id}")),
        Q::InvalidId(id) => {
            BackendError::Invalid(format!("identifiant de quarantaine invalide : {id}"))
        }
        Q::Unsupported(m) => BackendError::Invalid(format!("mise en quarantaine impossible : {m}")),
        other => BackendError::Failed(other.to_string()),
    }
}

impl QuarantineStore for QuarantineAdapter {
    fn quarantine(
        &self,
        path: &Path,
        _sha256: Option<&str>,
        detections: &[Detection],
        reason: &str,
    ) -> Result<QuarantineEntry, BackendError> {
        self.q.quarantine(path, detections, reason).map_err(qerr)
    }
    fn list(&self) -> Result<Vec<QuarantineEntry>, BackendError> {
        self.q.list().map_err(qerr)
    }
    fn get(&self, id: &str) -> Result<QuarantineEntry, BackendError> {
        self.q.get(id).map_err(qerr)
    }
    fn restore(&self, id: &str) -> Result<PathBuf, BackendError> {
        self.q.restore(id).map_err(qerr)
    }
    fn delete(&self, id: &str) -> Result<(), BackendError> {
        self.q.delete(id).map_err(qerr)
    }
}

// ---------------------------------------------------------------------------------------------
// pb-monitor
// ---------------------------------------------------------------------------------------------

/// Watchers, HID blocker, osquery.
#[derive(Default)]
pub struct MonitorsAdapter {
    hid: Arc<pb_monitor::HidBlocker>,
}

/// Max size of a hunting pack file.
const MAX_PACK_BYTES: u64 = 1024 * 1024;

/// `queries.<name>.alert` flags of a pack (default `true`).
pub fn pack_alert_flags(pack_json: &str) -> BTreeMap<String, bool> {
    let mut out = BTreeMap::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(pack_json) {
        if let Some(q) = v.get("queries").and_then(|q| q.as_object()) {
            for (name, def) in q {
                out.insert(
                    name.clone(),
                    def.get("alert").and_then(|a| a.as_bool()).unwrap_or(true),
                );
            }
        }
    }
    out
}

#[async_trait]
impl Monitors for MonitorsAdapter {
    fn start(&self, ctx: MonitorContext) -> Vec<JoinHandle<()>> {
        // pb-monitor takes a `watch::Receiver<Config>`; bridge from the daemon's `Arc<Config>` channel.
        let (cfg_tx, cfg_rx) = watch::channel((**ctx.config.borrow()).clone());
        let mut src = ctx.config.clone();
        let mut stop = ctx.shutdown.clone();
        let bridge = tokio::spawn(async move {
            loop {
                tokio::select! {
                    r = src.changed() => {
                        if r.is_err() { break; }
                        let c = (**src.borrow_and_update()).clone();
                        cfg_tx.send_replace(c);
                    }
                    _ = stop.changed() => if *stop.borrow() { break; },
                }
            }
        });
        let mctx = pb_monitor::MonitorContext {
            paths: ctx.paths,
            config: cfg_rx,
            user: pb_monitor::console_user(),
            tx: ctx.events,
            shutdown: ctx.shutdown,
        };
        vec![
            bridge,
            tokio::spawn(pb_monitor::FileWatcher.run(mctx.clone())),
            tokio::spawn(pb_monitor::EsLoggerWatcher.run(mctx.clone())),
            tokio::spawn(
                pb_monitor::PersistenceWatcher {
                    known: ctx.persistence_snapshot,
                }
                .run(mctx.clone()),
            ),
            tokio::spawn(pb_monitor::DeviceWatcher.run(mctx)),
        ]
    }

    fn has_full_disk_access(&self) -> bool {
        pb_monitor::has_full_disk_access()
    }

    fn block_hid(&self, device: &DeviceInfo) -> Result<(), BackendError> {
        self.hid
            .block(&device.id)
            .map(|n| tracing::warn!(device = %device.id, interfaces = n, "HID device blocked"))
            .map_err(|e| BackendError::Unavailable(e.to_string()))
    }

    fn unblock_hid(&self, device_id: &str) -> Result<(), BackendError> {
        if self.hid.unblock(device_id) {
            tracing::info!(device = device_id, "HID device unblocked");
        }
        Ok(())
    }

    async fn run_osquery_pack(
        &self,
        pack: Option<PathBuf>,
    ) -> Result<Vec<OsqueryRow>, BackendError> {
        tokio::task::spawn_blocking(move || {
            let bin = pb_monitor::osquery::find_osqueryi()
                .ok_or_else(|| BackendError::Unavailable("osquery non installé".into()))?;
            let json = pack
                .filter(|p| {
                    std::fs::metadata(p)
                        .map(|m| m.len() <= MAX_PACK_BYTES)
                        .unwrap_or(false)
                })
                .and_then(|p| std::fs::read_to_string(p).ok())
                .unwrap_or_else(|| pb_monitor::osquery::DEFAULT_HUNTING_PACK.to_string());
            let flags = pack_alert_flags(&json);
            let mut rows = Vec::new();
            for r in pb_monitor::osquery::run_pack(&bin, &json, Duration::from_secs(60)) {
                if let Some(e) = &r.error {
                    tracing::warn!(query = %r.query, error = %e, "osquery query failed");
                }
                let alert = flags.get(&r.query).copied().unwrap_or(true);
                for columns in r.rows {
                    rows.push(OsqueryRow {
                        query: r.query.clone(),
                        alert,
                        description: r.description.clone(),
                        columns,
                    });
                }
            }
            Ok(rows)
        })
        .await
        .map_err(|e| BackendError::Failed(e.to_string()))?
    }
}

// ---------------------------------------------------------------------------------------------
// pb-updater
// ---------------------------------------------------------------------------------------------

type CmKey = (UpdatesConfig, Option<PathBuf>, Option<u32>);

/// Threat DB, freshclam, components, app updates, uBlock status.
pub struct UpdaterAdapter {
    paths: Paths,
    db: Mutex<Option<(UpdatesConfig, Arc<pb_updater::DbUpdater>)>>,
    cm: Mutex<Option<(CmKey, Arc<pb_updater::ComponentManager>)>>,
}

fn uerr(e: pb_updater::UpdateError) -> BackendError {
    use pb_updater::UpdateError as U;
    match e {
        U::NotFound(_) => BackendError::NotFound(e.to_string()),
        U::MissingPublicKey | U::Unsupported(_) | U::Busy | U::CoolDown(_) | U::RateLimited => {
            BackendError::Unavailable(e.to_string())
        }
        other => BackendError::Failed(other.to_string()),
    }
}

impl UpdaterAdapter {
    pub fn new(paths: Paths) -> Self {
        Self {
            paths,
            db: Mutex::new(None),
            cm: Mutex::new(None),
        }
    }

    fn db(&self, updates: &UpdatesConfig) -> Arc<pb_updater::DbUpdater> {
        let mut g = self.db.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((k, d)) = g.as_ref() {
            if k == updates {
                return d.clone();
            }
        }
        let key = pb_updater::embedded_public_key().map(str::to_string);
        let d = Arc::new(pb_updater::DbUpdater::new(
            self.paths.clone(),
            updates.clone(),
            key,
        ));
        *g = Some((updates.clone(), d.clone()));
        d
    }

    fn cm(&self, updates: &UpdatesConfig) -> Arc<pb_updater::ComponentManager> {
        let user = crate::system::console_user();
        let key: CmKey = (
            updates.clone(),
            user.as_ref().map(|u| u.home.clone()),
            user.as_ref().map(|u| u.uid),
        );
        let mut g = self.cm.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((k, c)) = g.as_ref() {
            if *k == key {
                return c.clone();
            }
        }
        let c = Arc::new(pb_updater::ComponentManager::new(
            self.paths.clone(),
            key.0.clone(),
            key.1.clone(),
            key.2,
        ));
        *g = Some((key, c.clone()));
        c
    }

    fn all_statuses(&self, cfg: &Config) -> Vec<ComponentStatus> {
        let mut v = vec![self.db(&cfg.updates).component_status()];
        v.extend(self.cm(&cfg.updates).statuses());
        v
    }
}

#[async_trait]
impl Updater for UpdaterAdapter {
    async fn update_db(&self, cfg: &Config) -> Result<DbUpdateOutcome, BackendError> {
        let o = self
            .db(&cfg.updates)
            .check_and_update()
            .await
            .map_err(uerr)?;
        let mut messages = Vec::new();
        if let Some(p) = &o.previous {
            messages.push(format!(
                "Version précédente conservée pour retour arrière : {p}"
            ));
        }
        Ok(DbUpdateOutcome {
            updated: o.updated,
            version: Some(o.version),
            messages,
        })
    }

    async fn freshclam(&self, _cfg: &Config) -> Result<String, BackendError> {
        pb_updater::run_freshclam(&self.paths).await.map_err(uerr)
    }

    async fn update_components(&self, cfg: &Config) -> Result<Vec<String>, BackendError> {
        Ok(self.cm(&cfg.updates).auto_update().await)
    }

    async fn check_app_update(&self, cfg: &Config) -> Result<String, BackendError> {
        let cm = self.cm(&cfg.updates);
        let st = cm
            .check_all()
            .await
            .into_iter()
            .find(|c| c.name == "parabellum");
        let Some(st) = st else {
            return Ok("Parabellum : état inconnu".into());
        };
        if st.state != ComponentState::UpdateAvailable {
            return Ok(format!(
                "Parabellum à jour ({})",
                st.installed_version.as_deref().unwrap_or(pb_core::VERSION)
            ));
        }
        let latest = st.latest_version.clone().unwrap_or_else(|| "?".into());
        if cfg.updates.auto_update_app {
            // The package's postinstall restarts the daemon: this may never return.
            cm.install("parabellum").await.map_err(uerr)
        } else {
            Ok(format!("Parabellum {latest} disponible (installer : parabellum components install parabellum)"))
        }
    }

    async fn list_components(&self, cfg: &Config) -> Vec<ComponentStatus> {
        self.all_statuses(cfg)
    }

    async fn install_component(
        &self,
        name: &str,
        cfg: &Config,
    ) -> Result<ComponentStatus, BackendError> {
        if name == "threat-db" {
            self.db(&cfg.updates)
                .check_and_update()
                .await
                .map_err(uerr)?;
            return Ok(self.db(&cfg.updates).component_status());
        }
        let cm = self.cm(&cfg.updates);
        let msg = cm.install(name).await.map_err(uerr)?;
        let mut st = cm
            .statuses()
            .into_iter()
            .find(|c| c.name == name)
            .ok_or_else(|| BackendError::NotFound(format!("composant inconnu : {name}")))?;
        st.message = Some(msg);
        Ok(st)
    }

    async fn set_component_auto_update(
        &self,
        name: &str,
        auto_update: bool,
        cfg: &Config,
    ) -> Result<Vec<ComponentStatus>, BackendError> {
        self.cm(&cfg.updates)
            .set_auto_update(name, auto_update)
            .map_err(uerr)?;
        Ok(self.all_statuses(cfg))
    }

    async fn extension_states(
        &self,
        console_home: Option<PathBuf>,
    ) -> (ExtensionState, ExtensionState) {
        let Some(home) = console_home else {
            return (ExtensionState::Unknown, ExtensionState::Unknown);
        };
        let uid = crate::system::console_user().map(|u| u.uid);
        tokio::task::spawn_blocking(move || pb_updater::adblock_extension_states_for(&home, uid))
            .await
            .unwrap_or((ExtensionState::Unknown, ExtensionState::Unknown))
    }

    fn db_update_status(&self, cfg: &Config) -> DbStatus {
        self.db(&cfg.updates).status()
    }
}

// ---------------------------------------------------------------------------------------------
// pb-dns
// ---------------------------------------------------------------------------------------------

/// dnscrypt-proxy + system DNS.
pub struct DnsAdapter {
    paths: Paths,
    mgr: Arc<pb_dns::DnsManager>,
}

fn derr(e: pb_dns::DnsError) -> BackendError {
    match e {
        pb_dns::DnsError::ProxyMissing => BackendError::Unavailable(e.to_string()),
        pb_dns::DnsError::Config(_) => BackendError::Invalid(e.to_string()),
        other => BackendError::Failed(other.to_string()),
    }
}

impl DnsAdapter {
    pub fn new(paths: Paths) -> Self {
        Self {
            mgr: Arc::new(pb_dns::DnsManager::new(paths.clone())),
            paths,
        }
    }
}

#[async_trait]
impl Dns for DnsAdapter {
    /// The supervisor runs `recover_on_startup` itself (with the live config).
    async fn recover_on_startup(&self) {}

    async fn enable(&self, cfg: &Config) -> Result<DnsStatus, BackendError> {
        self.mgr.enable(&cfg.dns).await.map_err(derr)
    }

    async fn disable(&self) -> Result<DnsStatus, BackendError> {
        self.mgr.disable().await.map_err(derr)
    }

    async fn restore_system_dns(&self) -> Result<(), BackendError> {
        self.mgr
            .restore_system_dns()
            .await
            .map(|_| ())
            .map_err(derr)
    }

    async fn status(&self, cfg: &Config) -> DnsStatus {
        self.mgr.status(&cfg.dns).await
    }

    async fn rebuild_lists(&self, cfg: &Config) -> Result<u64, BackendError> {
        let (mgr, dns, bundle) = (self.mgr.clone(), cfg.dns.clone(), self.paths.db_current());
        tokio::task::spawn_blocking(move || mgr.rebuild_lists(&dns, Some(&bundle)))
            .await
            .map_err(|e| BackendError::Failed(e.to_string()))?
            .map_err(derr)
    }

    fn start_supervisor(
        &self,
        config: watch::Receiver<Arc<Config>>,
        shutdown: watch::Receiver<bool>,
    ) -> Option<JoinHandle<()>> {
        let sup = pb_dns::DnsSupervisor::new(self.mgr.clone());
        Some(tokio::spawn(sup.run(config, shutdown)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_flags() {
        let f =
            pack_alert_flags(r#"{"queries":{"a":{"query":"x"},"b":{"query":"y","alert":false}}}"#);
        assert_eq!(f.get("a"), Some(&true));
        assert_eq!(f.get("b"), Some(&false));
        assert!(pack_alert_flags("nope").is_empty());
    }

    #[test]
    fn engine_adapter_loads_without_bundle() {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(d.path());
        let e = EngineLoaderImpl.load(&paths, &Config::default()).unwrap();
        assert!(e.db_status().yara_rules > 0, "built-in rules");
        let f = d.path().join("clean.txt");
        std::fs::write(&f, b"hello").unwrap();
        let cfg = Config::default();
        let r = e.scan_file(&f, &cfg, &ScanOpts::realtime(&cfg));
        assert_eq!(r.verdict, Verdict::Clean);
        assert!(r.sha256.is_some());
    }
}
