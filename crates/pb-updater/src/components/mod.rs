//! Third-party component manager: version discovery from GitHub releases (cached 12 h in
//! `components/state.json`), signature-verified installation, auto-update, Parabellum self-update and
//! uBlock Origin Lite status.
//!
//! Nothing is ever installed unless its signature check passed (Apple Team ID + Gatekeeper for `.pkg` /
//! `.app`, minisign for dnscrypt-proxy and Parabellum). The failure reason is surfaced in
//! `ComponentStatus.message`.

mod apple;
mod archive;
mod specs;

pub use specs::{
    BLOCKBLOCK_DAEMON_APP, CLAMAV_PKG_CLAMSCAN, CLAMAV_TEAM_ID, DNSCRYPT_MINISIGN_KEY, LULU_APP,
    OBJECTIVE_SEE_TEAM_ID, OSQUERYI, OSQUERY_TEAM_ID, OVERSIGHT_APP,
};

use crate::adblock::{adblock_extension_states_for, CHROME_UBOL_STORE_URL, SAFARI_UBOL_STORE_URL};
use crate::fsutil::{atomic_write, read_capped};
use crate::github::{self, AssetSource, GhRelease};
use crate::http::{Http, LARGE_TIMEOUT, SMALL_TIMEOUT};
use crate::process::{run, RunOpts};
use crate::signing::{verify_file_async, MAX_SIGNATURE_BYTES};
use crate::version::compare_release_versions;
use crate::UpdateError;
use pb_core::config::UpdatesConfig;
use pb_core::model::{ComponentState, ComponentStatus, ExtensionState};
use pb_core::paths::Paths;
use serde::{Deserialize, Serialize};
use specs::{Kind, Spec, Verify, SPECS};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Every component name reported by [`ComponentManager::check_all`] / [`ComponentManager::statuses`].
pub const COMPONENT_NAMES: [&str; 9] = [
    "clamav",
    "osquery",
    "dnscrypt-proxy",
    "lulu",
    "blockblock",
    "oversight",
    "parabellum",
    "ublock-chrome",
    "ublock-safari",
];

const STATE_FILE: &str = "state.json";
const CHECK_INTERVAL_SECS: i64 = 12 * 3600;
const ERROR_RETRY_SECS: i64 = 3600;
const INSTALL_RETRY_SECS: i64 = 24 * 3600;
/// Re-use a release lookup this recent when installing.
const FRESH_RELEASE_SECS: i64 = 3600;

/// Path of the managed dnscrypt-proxy binary (`components/dnscrypt-proxy/dnscrypt-proxy`), shared with pb-dns.
pub fn dnscrypt_proxy_binary(paths: &Paths) -> PathBuf {
    paths
        .components_dir()
        .join("dnscrypt-proxy")
        .join("dnscrypt-proxy")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct ComponentsState {
    version: u32,
    components: BTreeMap<String, Record>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Record {
    /// Last successful release lookup.
    last_check: Option<i64>,
    /// Last lookup attempt (success or failure).
    last_attempt: Option<i64>,
    latest: Option<LatestRelease>,
    remote_error: Option<String>,
    installed_version: Option<String>,
    /// User override of auto-update (`None` = config default).
    auto_update: Option<bool>,
    state: Option<ComponentState>,
    message: Option<String>,
    last_install_attempt: Option<i64>,
    last_install_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct LatestRelease {
    version: String,
    asset_name: String,
    asset: AssetSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<AssetSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    release_url: Option<String>,
}

/// Manages third-party tools and Parabellum self-update. Cheap to construct; share it in an `Arc`.
pub struct ComponentManager {
    paths: Paths,
    updates: UpdatesConfig,
    console_user_home: Option<PathBuf>,
    console_uid: Option<u32>,
    github_api: String,
    public_key: Option<String>,
    dnscrypt_key: String,
    state_lock: std::sync::Mutex<()>,
    install_lock: tokio::sync::Mutex<()>,
    #[cfg(test)]
    test_http: Option<Http>,
}

impl ComponentManager {
    /// `console_user_home` / `console_uid`: the logged-in GUI user (to launch LuLu/OverSight for them and
    /// to read uBlock Origin Lite state); `None` when nobody is logged in.
    pub fn new(
        paths: Paths,
        updates: UpdatesConfig,
        console_user_home: Option<PathBuf>,
        console_uid: Option<u32>,
    ) -> Self {
        Self {
            paths,
            updates,
            console_user_home,
            console_uid,
            github_api: github::GITHUB_API.to_string(),
            public_key: crate::embedded_public_key().map(str::to_string),
            dnscrypt_key: DNSCRYPT_MINISIGN_KEY.to_string(),
            state_lock: std::sync::Mutex::new(()),
            install_lock: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            test_http: None,
        }
    }

    #[cfg(test)]
    fn for_tests(
        mut self,
        api: String,
        http: Http,
        public_key: Option<String>,
        dnscrypt_key: String,
    ) -> Self {
        self.github_api = api;
        self.test_http = Some(http);
        self.public_key = public_key;
        self.dnscrypt_key = dnscrypt_key;
        self
    }

    fn http(&self) -> Result<Http, UpdateError> {
        #[cfg(test)]
        if let Some(h) = &self.test_http {
            return Ok(h.clone());
        }
        Http::new(self.updates.github_token.clone())
    }

    // -----------------------------------------------------------------------------------------
    // State file
    // -----------------------------------------------------------------------------------------

    fn state_path(&self) -> PathBuf {
        self.paths.components_dir().join(STATE_FILE)
    }

    fn load_state(&self) -> ComponentsState {
        read_capped(&self.state_path(), 4 * 1024 * 1024)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Load-modify-save one record under the state lock (never held across an await).
    fn update_record(&self, name: &str, f: impl FnOnce(&mut Record)) {
        let _g = self.state_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut st = self.load_state();
        st.version = 1;
        f(st.components.entry(name.to_string()).or_default());
        let res = std::fs::create_dir_all(self.paths.components_dir())
            .and_then(|()| serde_json::to_vec_pretty(&st).map_err(std::io::Error::other))
            .and_then(|b| atomic_write(&self.state_path(), &b));
        if let Err(e) = res {
            tracing::warn!(error = %e, "cannot write components/state.json");
        }
    }

    fn record(&self, name: &str) -> Record {
        self.load_state()
            .components
            .get(name)
            .cloned()
            .unwrap_or_default()
    }

    fn default_auto_update(&self, spec: &Spec) -> bool {
        if spec.kind == Kind::Parabellum {
            self.updates.auto_update_app
        } else {
            self.updates.auto_update_components
        }
    }

    fn effective_auto_update(&self, spec: &Spec, rec: &Record) -> bool {
        rec.auto_update
            .unwrap_or_else(|| self.default_auto_update(spec))
    }

    // -----------------------------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------------------------

    /// Refresh local versions and (at most every 12 h per component, 1 h after an error) the latest
    /// release from GitHub, then return every status. Never fails: errors go into `message`.
    pub async fn check_all(&self) -> Vec<ComponentStatus> {
        self.check_all_with(false).await
    }

    /// Like [`Self::check_all`]; `force` bypasses the 12 h cache (explicit "check now" from the UI).
    pub async fn check_all_with(&self, force: bool) -> Vec<ComponentStatus> {
        let http = self.http();
        let now = pb_core::now_ts();
        for spec in SPECS.iter() {
            let rec = self.record(spec.name);
            let interval = if rec.remote_error.is_some() {
                ERROR_RETRY_SECS
            } else {
                CHECK_INTERVAL_SECS
            };
            let due = force
                || rec
                    .last_attempt
                    .is_none_or(|t| now - t >= interval || t > now);
            if due {
                let res = match &http {
                    Ok(h) => self.fetch_latest(h, spec).await,
                    Err(e) => Err(UpdateError::Http(e.to_string())),
                };
                self.update_record(spec.name, |r| {
                    r.last_attempt = Some(now);
                    match res {
                        Ok(latest) => {
                            r.last_check = Some(now);
                            r.remote_error = None;
                            r.latest = latest;
                        }
                        Err(e) => {
                            tracing::warn!(component = spec.name, error = %e, "release lookup failed");
                            r.remote_error = Some(e.to_string());
                        }
                    }
                });
            }
            let rec = self.record(spec.name);
            let installed = self.detect_installed(spec, &rec).await;
            let (state, message) = self.compute_state(spec, &rec, installed.as_deref()).await;
            self.update_record(spec.name, |r| {
                r.installed_version = installed;
                r.state = Some(state);
                r.message = message;
            });
        }
        self.refresh_adblock().await;
        self.statuses()
    }

    /// Cached statuses (from `components/state.json`, no network, no subprocess).
    pub fn statuses(&self) -> Vec<ComponentStatus> {
        let st = self.load_state();
        let empty = Record::default();
        let mut out: Vec<ComponentStatus> = SPECS
            .iter()
            .map(|spec| self.to_status(spec, st.components.get(spec.name).unwrap_or(&empty)))
            .collect();
        for (name, display, url) in [
            (
                "ublock-chrome",
                "uBlock Origin Lite (Chrome)",
                CHROME_UBOL_STORE_URL,
            ),
            (
                "ublock-safari",
                "uBlock Origin Lite (Safari)",
                SAFARI_UBOL_STORE_URL,
            ),
        ] {
            let rec = st.components.get(name).unwrap_or(&empty);
            out.push(ComponentStatus {
                name: name.into(),
                display_name: display.into(),
                installed_version: None,
                latest_version: None,
                state: rec.state.unwrap_or(ComponentState::NotInstalled),
                last_check: rec.last_check,
                auto_update: false,
                required: false,
                message: rec
                    .message
                    .clone()
                    .or_else(|| Some("Mis à jour par le store".into())),
                action_url: Some(url.into()),
            });
        }
        out
    }

    /// Override auto-update for one component (persisted in `components/state.json`).
    pub fn set_auto_update(&self, name: &str, enabled: bool) -> Result<(), UpdateError> {
        if Spec::by_name(name).is_none() {
            return Err(UpdateError::NotFound(format!("composant inconnu : {name}")));
        }
        self.update_record(name, |r| r.auto_update = Some(enabled));
        Ok(())
    }

    /// Install (or update / reinstall) a component from its latest release, after signature verification.
    /// Returns a user-facing message.
    ///
    /// For `parabellum`, the verified package is copied to a root-only directory, re-verified, and handed to
    /// a one-shot launchd job (`crate::selfupdate`); this returns right away and the package's postinstall
    /// restarts the daemon a little later. At its next start the daemon calls [`crate::finish_self_update`].
    pub async fn install(&self, name: &str) -> Result<String, UpdateError> {
        if name.starts_with("ublock-") {
            return Err(UpdateError::Unsupported(
                "uBlock Origin Lite s'installe depuis le Chrome Web Store / l'App Store".into(),
            ));
        }
        let spec = Spec::by_name(name)
            .ok_or_else(|| UpdateError::NotFound(format!("composant inconnu : {name}")))?;
        let _g = self.install_lock.lock().await;
        let now = pb_core::now_ts();
        self.update_record(name, |r| {
            r.last_install_attempt = Some(now);
            r.state = Some(ComponentState::Updating);
        });
        let res = self.install_locked(spec).await;
        let dl = self.downloads_dir();
        let _ = std::fs::remove_dir_all(&dl);
        let rec = self.record(name);
        let installed = self.detect_installed(spec, &rec).await;
        match res {
            Ok((msg, needs_user)) => {
                let (mut state, mut message) = self
                    .compute_state(
                        spec,
                        &Record {
                            last_install_error: None,
                            ..rec
                        },
                        installed.as_deref(),
                    )
                    .await;
                if needs_user && state == ComponentState::Installed {
                    state = ComponentState::NeedsUserAction;
                    message = Some(msg.clone());
                }
                self.update_record(name, |r| {
                    r.installed_version = installed;
                    r.last_install_error = None;
                    r.state = Some(state);
                    r.message = message;
                });
                tracing::info!(component = name, "{msg}");
                Ok(msg)
            }
            Err(e) => {
                tracing::error!(component = name, error = %e, "component installation failed");
                let text = e.to_string();
                self.update_record(name, |r| {
                    r.installed_version = installed;
                    r.last_install_error = Some(text.clone());
                    r.state = Some(ComponentState::Error);
                    r.message = Some(text);
                });
                Err(e)
            }
        }
    }

    /// Daily maintenance: refresh statuses, update installed components whose auto-update is on, install
    /// *required* components that are missing (`updates.auto_update_components`), and finally Parabellum
    /// itself when `updates.auto_update_app` (last, since it restarts the daemon). Returns one line per action.
    pub async fn auto_update(&self) -> Vec<String> {
        if let Ok(_g) = self.install_lock.try_lock() {
            let _ = std::fs::remove_dir_all(self.downloads_dir());
        }
        let statuses = self.check_all().await;
        let now = pb_core::now_ts();
        let mut msgs = Vec::new();
        let mut app_update: Option<&Spec> = None;
        for spec in SPECS.iter() {
            let Some(status) = statuses.iter().find(|s| s.name == spec.name) else {
                continue;
            };
            let rec = self.record(spec.name);
            let auto = self.effective_auto_update(spec, &rec);
            let installed = status.installed_version.is_some();
            let update_available = status.state == ComponentState::UpdateAvailable;
            if spec.kind == Kind::Parabellum {
                if update_available {
                    if auto {
                        app_update = Some(spec);
                    } else if let Some(v) = &status.latest_version {
                        msgs.push(format!("Parabellum {v} disponible (installation manuelle)"));
                    }
                }
                continue;
            }
            let recently_failed = rec.last_install_error.is_some()
                && rec
                    .last_install_attempt
                    .is_some_and(|t| now - t < INSTALL_RETRY_SECS && t <= now);
            let should = if installed {
                update_available && auto
            } else {
                spec.auto_install
                    && self.updates.auto_update_components
                    && rec.auto_update != Some(false)
            };
            if !should || recently_failed {
                continue;
            }
            match self.install(spec.name).await {
                Ok(m) => msgs.push(format!("{} : {m}", spec.display_name)),
                Err(e) => msgs.push(format!("{} : échec — {e}", spec.display_name)),
            }
        }
        if let Some(spec) = app_update {
            match self.install(spec.name).await {
                Ok(m) => msgs.push(format!("Parabellum : {m}")),
                Err(e) => msgs.push(format!("Parabellum : échec — {e}")),
            }
        }
        msgs
    }

    // -----------------------------------------------------------------------------------------
    // Discovery
    // -----------------------------------------------------------------------------------------

    async fn fetch_latest(
        &self,
        http: &Http,
        spec: &Spec,
    ) -> Result<Option<LatestRelease>, UpdateError> {
        let releases = if spec.kind == Kind::Parabellum {
            github::list_releases_at(http, &self.updates.app_releases_api).await?
        } else {
            github::list_releases(http, &self.github_api, spec.repo).await?
        };
        Ok(select_latest(spec, &releases, http.has_token()))
    }

    async fn detect_installed(&self, spec: &Spec, rec: &Record) -> Option<String> {
        match spec.kind {
            Kind::Clamav => {
                if let Some(o) =
                    apple::version_output(Path::new(CLAMAV_PKG_CLAMSCAN), "--version").await
                {
                    return apple::parse_clamscan_version(&o);
                }
                let o = apple::version_output(Path::new(specs::CLAMAV_BREW_CLAMSCAN), "--version")
                    .await?;
                apple::parse_clamscan_version(&o)
            }
            Kind::Osquery => match apple::version_output(Path::new(OSQUERYI), "--version").await {
                Some(o) => apple::parse_osquery_version(&o),
                None => apple::bundle_short_version(Path::new(specs::OSQUERY_APP_PLIST)),
            },
            Kind::Dnscrypt => {
                let bin = dnscrypt_proxy_binary(&self.paths);
                if !bin.is_file() {
                    return None;
                }
                if let Some(v) = rec
                    .installed_version
                    .clone()
                    .filter(|v| crate::version::parse_release_version(v).is_some())
                {
                    return Some(v);
                }
                let probed = apple::version_output(&bin, "-version")
                    .await
                    .and_then(|o| crate::version::normalize_release_version(o.trim()));
                Some(probed.unwrap_or_else(|| "?".into()))
            }
            Kind::Lulu => {
                apple::bundle_short_version(&Path::new(LULU_APP).join("Contents/Info.plist"))
            }
            Kind::BlockBlock => apple::bundle_short_version(
                &Path::new(BLOCKBLOCK_DAEMON_APP).join("Contents/Info.plist"),
            )
            .or_else(|| {
                apple::bundle_short_version(
                    &Path::new(specs::BLOCKBLOCK_HELPER_APP).join("Contents/Info.plist"),
                )
            }),
            Kind::OverSight => {
                apple::bundle_short_version(&Path::new(OVERSIGHT_APP).join("Contents/Info.plist"))
            }
            Kind::Parabellum => Some(pb_core::VERSION.to_string()),
        }
    }

    async fn compute_state(
        &self,
        spec: &Spec,
        rec: &Record,
        installed: Option<&str>,
    ) -> (ComponentState, Option<String>) {
        let latest = rec.latest.as_ref().map(|l| l.version.as_str());
        let newer = match (installed, latest) {
            (Some(i), Some(l)) => compare_release_versions(l, i) == Ordering::Greater,
            _ => false,
        };
        if let Some(err) = &rec.last_install_error {
            if installed.is_none() || newer {
                return (ComponentState::Error, Some(err.clone()));
            }
        }
        let remote_note = rec
            .remote_error
            .as_ref()
            .map(|e| format!("vérification des versions impossible : {e}"));
        let Some(installed) = installed else {
            let base = if spec.required {
                "Requis pour une protection complète"
            } else {
                "Recommandé (optionnel)"
            };
            let msg = match remote_note {
                Some(n) => format!("{base} — {n}"),
                None => base.to_string(),
            };
            return (ComponentState::NotInstalled, Some(msg));
        };
        if newer {
            let l = latest.unwrap_or_default();
            return (
                ComponentState::UpdateAvailable,
                Some(format!("Version {l} disponible (installée : {installed})")),
            );
        }
        if spec.kind == Kind::Clamav && !Path::new(CLAMAV_PKG_CLAMSCAN).is_file() {
            return (
                ComponentState::Installed,
                Some("Installé via Homebrew (mises à jour gérées par Homebrew)".into()),
            );
        }
        if spec.kind == Kind::Lulu && cfg!(target_os = "macos") {
            if let Some(false) | None =
                apple::system_extension_active(specs::LULU_EXTENSION_ID).await
            {
                return (
                    ComponentState::NeedsUserAction,
                    Some("Ouvrir LuLu et autoriser son extension réseau (Réglages Système › Général › Ouverture et extensions)".into()),
                );
            }
        }
        (ComponentState::Installed, remote_note)
    }

    fn to_status(&self, spec: &Spec, rec: &Record) -> ComponentStatus {
        ComponentStatus {
            name: spec.name.into(),
            display_name: spec.display_name.into(),
            installed_version: rec.installed_version.clone(),
            latest_version: rec.latest.as_ref().map(|l| l.version.clone()),
            state: rec.state.unwrap_or(if rec.installed_version.is_some() {
                ComponentState::Installed
            } else {
                ComponentState::NotInstalled
            }),
            last_check: rec.last_check,
            auto_update: self.effective_auto_update(spec, rec),
            required: spec.required,
            message: rec.message.clone(),
            action_url: Some(
                rec.latest
                    .as_ref()
                    .and_then(|l| l.release_url.clone())
                    .filter(|u| u.starts_with("https://"))
                    .unwrap_or_else(|| spec.release_page()),
            ),
        }
    }

    async fn refresh_adblock(&self) {
        let Some(home) = self.console_user_home.clone() else {
            return;
        };
        let uid = self.console_uid;
        let Ok((chrome, safari)) =
            tokio::task::spawn_blocking(move || adblock_extension_states_for(&home, uid)).await
        else {
            return;
        };
        let now = pb_core::now_ts();
        for (name, st, browser) in [
            ("ublock-chrome", chrome, "Chrome"),
            ("ublock-safari", safari, "Safari"),
        ] {
            let (state, message) = match st {
                ExtensionState::Enabled => (ComponentState::Installed, "Actif".to_string()),
                ExtensionState::InstalledDisabled => {
                    (ComponentState::NeedsUserAction, format!("Installé mais désactivé dans {browser}"))
                }
                ExtensionState::NotInstalled => {
                    (ComponentState::NotInstalled, format!("Installer uBlock Origin Lite pour {browser} depuis le store"))
                }
                ExtensionState::Unknown => (
                    ComponentState::Installed,
                    format!("Installé ; activation non vérifiable — vérifier dans les réglages d'extensions de {browser}"),
                ),
            };
            self.update_record(name, |r| {
                r.state = Some(state);
                r.message = Some(message);
                r.last_check = Some(now);
            });
        }
    }

    // -----------------------------------------------------------------------------------------
    // Installation
    // -----------------------------------------------------------------------------------------

    fn downloads_dir(&self) -> PathBuf {
        self.paths.components_dir().join("downloads")
    }

    /// Returns `(message, needs_user_action)`.
    async fn install_locked(&self, spec: &Spec) -> Result<(String, bool), UpdateError> {
        if spec.verify == Verify::MinisignEmbedded && self.public_key.is_none() {
            return Err(UpdateError::MissingPublicKey);
        }
        let platform_ok = cfg!(target_os = "macos") || spec.kind == Kind::Dnscrypt;
        if !platform_ok {
            return Err(UpdateError::Unsupported(format!(
                "{} ne s'installe que sur macOS",
                spec.display_name
            )));
        }
        let http = self.http()?;
        let now = pb_core::now_ts();
        let rec = self.record(spec.name);
        let cached = rec.latest.clone().filter(|_| {
            rec.last_check
                .is_some_and(|t| now - t < FRESH_RELEASE_SECS && t <= now)
        });
        let latest = match cached {
            Some(l) => l,
            None => {
                let l = self.fetch_latest(&http, spec).await?;
                let l2 = l.clone();
                self.update_record(spec.name, |r| {
                    r.latest = l2;
                    r.last_check = Some(now);
                    r.last_attempt = Some(now);
                    r.remote_error = None;
                });
                l.ok_or_else(|| {
                    UpdateError::NotFound(format!(
                        "aucune release de {} avec l'asset attendu",
                        spec.display_name
                    ))
                })?
            }
        };
        // Asset names were matched by a strict regex, so they are safe file names.
        if spec.asset_version(&latest.asset_name).is_none() {
            return Err(UpdateError::Verification(format!(
                "nom d'asset inattendu : {}",
                latest.asset_name
            )));
        }
        let dl = self.downloads_dir();
        let _ = std::fs::remove_dir_all(&dl);
        std::fs::create_dir_all(&dl)?;
        let asset_path = dl.join(&latest.asset_name);
        http.download_to_file(
            &latest.asset.url,
            &asset_path,
            spec.max_bytes,
            latest.asset.accept.as_deref(),
            LARGE_TIMEOUT,
        )
        .await?;

        // Detached minisign signatures are checked right away, before anything else touches the file.
        let mut minisig: Option<(String, String)> = None;
        match spec.verify {
            Verify::MinisignDnscrypt | Verify::MinisignEmbedded => {
                let sig_src = latest.signature.clone().ok_or_else(|| {
                    UpdateError::Verification("signature .minisig absente de la release".into())
                })?;
                let sig = http
                    .get_bytes(
                        &sig_src.url,
                        MAX_SIGNATURE_BYTES,
                        sig_src.accept.as_deref(),
                        SMALL_TIMEOUT,
                    )
                    .await?;
                let sig = String::from_utf8(sig)
                    .map_err(|_| UpdateError::Signature("signature non UTF-8".into()))?;
                let key = if spec.verify == Verify::MinisignDnscrypt {
                    self.dnscrypt_key.clone()
                } else {
                    self.public_key
                        .clone()
                        .ok_or(UpdateError::MissingPublicKey)?
                };
                verify_file_async(&asset_path, sig.clone(), key.clone()).await?;
                minisig = Some((sig, key));
            }
            Verify::PkgTeamId(_) | Verify::AppTeamId(_) => {}
        }

        let v = &latest.version;
        match (spec.kind, spec.verify) {
            (Kind::Dnscrypt, _) => {
                let dest = dnscrypt_proxy_binary(&self.paths);
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let a = asset_path.clone();
                tokio::task::spawn_blocking(move || archive::extract_dnscrypt_binary(&a, &dest))
                    .await
                    .map_err(|e| UpdateError::Archive(e.to_string()))??;
                let ver = v.clone();
                self.update_record(spec.name, |r| r.installed_version = Some(ver));
                Ok((
                    format!("dnscrypt-proxy {v} installé (signature minisign vérifiée)"),
                    false,
                ))
            }
            (Kind::Clamav | Kind::Osquery, Verify::PkgTeamId(team)) => {
                apple::verify_pkg(&asset_path, team).await?;
                apple::install_pkg(&asset_path).await?;
                Ok((
                    format!(
                        "{} {v} installé (Team ID {team} vérifié)",
                        spec.display_name
                    ),
                    false,
                ))
            }
            (Kind::Parabellum, _) => {
                let (sig, key) = minisig.ok_or(UpdateError::MissingPublicKey)?;
                let msg = crate::selfupdate::launch_self_update(&self.paths, &asset_path, v, &sig, &key).await?;
                Ok((msg, false))
            }
            (Kind::Lulu, Verify::AppTeamId(team)) => self.install_lulu(&asset_path, team, v).await,
            (Kind::BlockBlock | Kind::OverSight, Verify::AppTeamId(team)) => {
                self.install_with_objective_see_installer(spec, &asset_path, team, v)
                    .await
            }
            _ => Err(UpdateError::Unsupported(format!(
                "installation de {} non prise en charge",
                spec.name
            ))),
        }
    }

    fn scratch_dir(&self, label: &str) -> Result<PathBuf, UpdateError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let dir = self
            .paths
            .tmp_dir()
            .join(format!("{label}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(dir)
    }

    async fn install_lulu(
        &self,
        dmg: &Path,
        team: &str,
        version: &str,
    ) -> Result<(String, bool), UpdateError> {
        let mnt_parent = self.scratch_dir("dmg")?;
        let mount = match apple::attach_dmg(dmg, &mnt_parent).await {
            Ok(m) => m,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&mnt_parent);
                return Err(e);
            }
        };
        let res = async {
            let src = mount.join("LuLu.app");
            if !src.is_dir() {
                return Err(UpdateError::NotFound(
                    "LuLu.app absent de l'image disque".into(),
                ));
            }
            apple::verify_app(&src, team).await?;
            install_app_bundle(&src, Path::new(LULU_APP), team).await
        }
        .await;
        apple::detach_dmg(&mount).await;
        let _ = std::fs::remove_dir(&mount);
        let _ = std::fs::remove_dir(&mnt_parent);
        res?;
        let launched = self.launch_for_user(Path::new(LULU_APP)).await;
        let mut msg = format!(
            "LuLu {version} installé (Team ID {team} vérifié) — autoriser son extension système et son filtre réseau dans Réglages Système"
        );
        if !launched {
            msg.push_str(" ; ouvrir /Applications/LuLu.app pour terminer");
        }
        Ok((msg, true))
    }

    async fn install_with_objective_see_installer(
        &self,
        spec: &Spec,
        zip: &Path,
        team: &str,
        version: &str,
    ) -> Result<(String, bool), UpdateError> {
        let z = zip.to_path_buf();
        tokio::task::spawn_blocking(move || archive::prescan_zip(&z, 1 << 30))
            .await
            .map_err(|e| UpdateError::Archive(e.to_string()))??;
        let dir = self.scratch_dir(spec.name)?;
        let res = async {
            apple::ditto_unzip(zip, &dir).await?;
            let app = find_installer_app(&dir).ok_or_else(|| {
                UpdateError::NotFound("application d'installation absente du zip".into())
            })?;
            apple::verify_app(&app, team).await?;
            let exe = apple::bundle_executable(&app)
                .filter(|e| e.is_file())
                .ok_or_else(|| {
                    UpdateError::NotFound("exécutable de l'installeur introuvable".into())
                })?;
            let out = run(
                &exe,
                [specs::OBJECTIVE_SEE_INSTALL_FLAG],
                RunOpts::timeout(600),
            )
            .await?;
            if !out.success() {
                return Err(UpdateError::Command(format!(
                    "installeur {} : {}",
                    spec.display_name,
                    out.summary()
                )));
            }
            Ok(())
        }
        .await;
        let _ = std::fs::remove_dir_all(&dir);
        res?;
        let msg = match spec.kind {
            Kind::BlockBlock => format!(
                "BlockBlock {version} installé (Team ID {team} vérifié) — lui accorder l'accès complet au disque (Réglages Système › Confidentialité et sécurité)"
            ),
            _ => {
                let launched = self.launch_for_user(Path::new(OVERSIGHT_APP)).await;
                let mut m = format!("OverSight {version} installé (Team ID {team} vérifié)");
                if !launched {
                    m.push_str(" — ouvrir /Applications/OverSight.app pour l'activer");
                }
                m
            }
        };
        Ok((msg, true))
    }

    async fn launch_for_user(&self, app: &Path) -> bool {
        let Some(uid) = self.console_uid else {
            return false;
        };
        match apple::open_app_as_user(app, uid).await {
            Ok(()) => true,
            Err(e) => {
                tracing::warn!(error = %e, app = %app.display(), "cannot launch app for the console user");
                false
            }
        }
    }
}

/// Newest release (non-draft, non-prerelease) having an asset matching the component's pattern
/// (and its `.minisig` when required).
fn select_latest(spec: &Spec, releases: &[GhRelease], has_token: bool) -> Option<LatestRelease> {
    let mut best: Option<LatestRelease> = None;
    for rel in releases.iter().filter(|r| !r.draft && !r.prerelease) {
        // Prefer `.zip` over `.tar.gz` when both exist (sorted for determinism).
        let mut assets: Vec<_> = rel
            .assets
            .iter()
            .filter(|a| spec.asset_version(&a.name).is_some())
            .collect();
        assets.sort_by_key(|a| !a.name.ends_with(".zip"));
        for asset in assets {
            let Some(version) = spec.asset_version(&asset.name) else {
                continue;
            };
            let signature = match spec.signature_asset(&asset.name) {
                Some(sig_name) => match rel.asset(&sig_name) {
                    Some(s) => Some(AssetSource::for_asset(s, has_token)),
                    None => continue,
                },
                None => None,
            };
            let better = best.as_ref().is_none_or(|b| {
                compare_release_versions(&version, &b.version) == Ordering::Greater
            });
            if better {
                best = Some(LatestRelease {
                    version,
                    asset_name: asset.name.clone(),
                    asset: AssetSource::for_asset(asset, has_token),
                    signature,
                    release_url: rel.html_url.clone(),
                });
            }
            break;
        }
    }
    best
}

/// Top-level (or one level down) `*.app` in an expanded zip, preferring one named `* Installer.app`.
fn find_installer_app(dir: &Path) -> Option<PathBuf> {
    let mut apps = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), 0u8)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten().take(256) {
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if !ft.is_dir() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if name == "__MACOSX" {
                continue;
            }
            if name.ends_with(".app") {
                apps.push(p);
            } else if depth < 1 {
                stack.push((p, depth + 1));
            }
        }
    }
    apps.sort();
    apps.iter()
        .find(|a| a.to_string_lossy().ends_with("Installer.app"))
        .cloned()
        .or_else(|| if apps.len() == 1 { apps.pop() } else { None })
}

/// Copy a verified app bundle into place: `ditto` to a staging name, re-verify the copy, swap.
async fn install_app_bundle(src: &Path, dest: &Path, team: &str) -> Result<(), UpdateError> {
    let parent = dest
        .parent()
        .ok_or_else(|| UpdateError::NotFound("dossier de destination".into()))?;
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let staging = parent.join(format!(".{name}.parabellum-new"));
    let old = parent.join(format!(".{name}.parabellum-old"));
    let _ = std::fs::remove_dir_all(&staging);
    let _ = std::fs::remove_dir_all(&old);
    apple::ditto_copy(src, &staging).await?;
    if let Err(e) = apple::verify_app(&staging, team).await {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(e);
    }
    let app_mgmt_hint = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            UpdateError::Command(format!(
                "macOS bloque le remplacement de {} : autoriser Parabellum dans Réglages Système › Confidentialité et sécurité › Gestion des apps ({e})",
                dest.display()
            ))
        } else {
            UpdateError::Io(e)
        }
    };
    if dest.exists() {
        if let Err(e) = std::fs::rename(dest, &old) {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(app_mgmt_hint(e));
        }
    }
    if let Err(e) = std::fs::rename(&staging, dest) {
        if old.exists() {
            let _ = std::fs::rename(&old, dest);
        }
        let _ = std::fs::remove_dir_all(&staging);
        return Err(app_mgmt_hint(e));
    }
    let _ = std::fs::remove_dir_all(&old);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::test_keys::TestKey;
    use crate::testutil::TestServer;
    use serde_json::json;

    fn release(tag: &str, assets: &[&str], base: &str, prerelease: bool) -> serde_json::Value {
        json!({
            "tag_name": tag,
            "draft": false,
            "prerelease": prerelease,
            "html_url": format!("https://github.com/x/y/releases/tag/{tag}"),
            "assets": assets.iter().enumerate().map(|(i, n)| json!({
                "name": n,
                "url": format!("{base}/api/assets/{tag}/{i}"),
                "browser_download_url": format!("{base}/dl/{tag}/{n}"),
                "size": 1
            })).collect::<Vec<_>>()
        })
    }

    #[test]
    fn selects_newest_signed_asset() {
        let rels: Vec<GhRelease> = serde_json::from_value(json!([
            release(
                "2.1.21",
                &["dnscrypt-proxy-macos_arm64-2.1.21.zip"],
                "https://x",
                false
            ), // no .minisig
            release(
                "2.1.20",
                &[
                    "dnscrypt-proxy-macos_arm64-2.1.20.zip",
                    "dnscrypt-proxy-macos_arm64-2.1.20.zip.minisig",
                    "dnscrypt-proxy-macos_arm64-2.1.20.tar.gz",
                    "dnscrypt-proxy-macos_arm64-2.1.20.tar.gz.minisig"
                ],
                "https://x",
                false
            ),
            release(
                "2.1.30",
                &[
                    "dnscrypt-proxy-macos_arm64-2.1.30.zip",
                    "dnscrypt-proxy-macos_arm64-2.1.30.zip.minisig"
                ],
                "https://x",
                true
            ),
            release(
                "2.1.19",
                &[
                    "dnscrypt-proxy-macos_arm64-2.1.19.tar.gz",
                    "dnscrypt-proxy-macos_arm64-2.1.19.tar.gz.minisig"
                ],
                "https://x",
                false
            ),
        ]))
        .unwrap();
        let spec = Spec::by_name("dnscrypt-proxy").unwrap();
        let l = select_latest(spec, &rels, false).unwrap();
        assert_eq!(l.version, "2.1.20");
        assert_eq!(l.asset_name, "dnscrypt-proxy-macos_arm64-2.1.20.zip");
        assert!(l.signature.unwrap().url.ends_with(".zip.minisig"));
        let p = Spec::by_name("parabellum").unwrap();
        let rels: Vec<GhRelease> = serde_json::from_value(json!([
            release(
                "db-latest",
                &["manifest.json", "parabellum-db.tar.gz"],
                "https://x",
                false
            ),
            release(
                "v0.3.0",
                &["Parabellum-0.3.0.pkg", "Parabellum-0.3.0.pkg.minisig"],
                "https://x",
                false
            ),
            release(
                "v0.2.0",
                &["Parabellum-0.2.0.pkg", "Parabellum-0.2.0.pkg.minisig"],
                "https://x",
                false
            ),
        ]))
        .unwrap();
        let l = select_latest(p, &rels, true).unwrap();
        assert_eq!(l.version, "0.3.0");
        assert!(l.asset.url.contains("/api/assets/"));
        assert_eq!(l.asset.accept.as_deref(), Some(crate::http::OCTET_STREAM));
    }

    struct Env {
        _d: tempfile::TempDir,
        srv: TestServer,
        mgr: ComponentManager,
        paths: Paths,
    }

    async fn env(dnscrypt_key: &TestKey) -> Env {
        let d = tempfile::tempdir().unwrap();
        let paths = Paths::with_root(d.path());
        for dir in paths.all_dirs() {
            std::fs::create_dir_all(dir).unwrap();
        }
        let srv = TestServer::start(vec![]).await;
        let base = srv.url("");
        for (repo, tag, assets) in [
            (
                "Cisco-Talos/clamav",
                "clamav-1.5.4",
                vec![
                    "clamav-1.5.4.macos.universal.pkg",
                    "clamav-1.5.4.macos.universal.pkg.sig",
                ],
            ),
            ("osquery/osquery", "5.24.0", vec!["osquery-5.24.0.pkg"]),
            (
                "DNSCrypt/dnscrypt-proxy",
                "2.1.20",
                vec![
                    "dnscrypt-proxy-macos_arm64-2.1.20.zip",
                    "dnscrypt-proxy-macos_arm64-2.1.20.zip.minisig",
                ],
            ),
            ("objective-see/LuLu", "v4.5.3", vec!["LuLu_4.5.3.dmg"]),
            (
                "objective-see/BlockBlock",
                "v2.5.2",
                vec!["BlockBlock_2.5.2.zip"],
            ),
            (
                "objective-see/OverSight",
                "v2.4.0",
                vec!["OverSight_2.4.0.zip"],
            ),
        ] {
            let body = serde_json::to_vec(&json!([release(tag, &assets, &base, false)])).unwrap();
            srv.set(&format!("/repos/{repo}/releases?per_page=100"), body);
        }
        let app_rel = serde_json::to_vec(&json!([release(
            "v99.0.0",
            &["Parabellum-99.0.0.pkg", "Parabellum-99.0.0.pkg.minisig"],
            &base,
            false
        )]))
        .unwrap();
        srv.set("/app/releases?per_page=100", app_rel);
        let zip = archive::tests::dnscrypt_zip(&archive::tests::fake_macho());
        srv.set(
            "/dl/2.1.20/dnscrypt-proxy-macos_arm64-2.1.20.zip.minisig",
            dnscrypt_key.sign(&zip).into_bytes(),
        );
        srv.set("/dl/2.1.20/dnscrypt-proxy-macos_arm64-2.1.20.zip", zip);
        let updates = UpdatesConfig {
            app_releases_api: srv.url("/app/releases"),
            ..Default::default()
        };
        let mgr = ComponentManager::new(paths.clone(), updates, None, None).for_tests(
            srv.url(""),
            Http::new_for_tests(None),
            None,
            dnscrypt_key.public_b64(),
        );
        Env {
            _d: d,
            srv,
            mgr,
            paths,
        }
    }

    #[tokio::test]
    async fn check_all_discovers_versions_and_caches() {
        let key = TestKey::new();
        let e = env(&key).await;
        let st = e.mgr.check_all().await;
        assert_eq!(st.len(), COMPONENT_NAMES.len());
        let get = |n: &str| st.iter().find(|s| s.name == n).unwrap().clone();
        assert_eq!(get("clamav").latest_version.as_deref(), Some("1.5.4"));
        assert_eq!(get("osquery").latest_version.as_deref(), Some("5.24.0"));
        assert_eq!(
            get("dnscrypt-proxy").latest_version.as_deref(),
            Some("2.1.20")
        );
        assert_eq!(get("lulu").latest_version.as_deref(), Some("4.5.3"));
        assert_eq!(get("blockblock").latest_version.as_deref(), Some("2.5.2"));
        assert_eq!(get("oversight").latest_version.as_deref(), Some("2.4.0"));
        let app = get("parabellum");
        assert_eq!(app.state, ComponentState::UpdateAvailable);
        assert_eq!(app.installed_version.as_deref(), Some(pb_core::VERSION));
        assert!(!app.auto_update, "auto_update_app defaults to false");
        assert_eq!(get("dnscrypt-proxy").state, ComponentState::NotInstalled);
        assert!(get("clamav").required && !get("lulu").required);
        assert_eq!(
            get("ublock-chrome").action_url.as_deref(),
            Some(CHROME_UBOL_STORE_URL)
        );

        // Second check within 12 h: no new request to GitHub.
        let before = e.srv.requests().len();
        let _ = e.mgr.check_all().await;
        assert_eq!(e.srv.requests().len(), before);
        // Forced: new requests.
        let _ = e.mgr.check_all_with(true).await;
        assert!(e.srv.requests().len() > before);
        // statuses() is served from the cache.
        assert_eq!(
            e.mgr
                .statuses()
                .iter()
                .find(|s| s.name == "lulu")
                .unwrap()
                .latest_version
                .as_deref(),
            Some("4.5.3")
        );

        e.mgr.set_auto_update("lulu", false).unwrap();
        assert!(
            !e.mgr
                .statuses()
                .iter()
                .find(|s| s.name == "lulu")
                .unwrap()
                .auto_update
        );
        assert!(e.mgr.set_auto_update("nope", true).is_err());
    }

    #[tokio::test]
    async fn installs_dnscrypt_after_minisign_check() {
        let key = TestKey::new();
        let e = env(&key).await;
        let msg = e.mgr.install("dnscrypt-proxy").await.unwrap();
        assert!(msg.contains("2.1.20"), "{msg}");
        let bin = dnscrypt_proxy_binary(&e.paths);
        assert_eq!(std::fs::read(&bin).unwrap(), archive::tests::fake_macho());
        assert!(!e.paths.components_dir().join("downloads").exists());
        let st = e.mgr.check_all().await;
        let d = st.iter().find(|s| s.name == "dnscrypt-proxy").unwrap();
        assert_eq!(d.installed_version.as_deref(), Some("2.1.20"));
        assert_eq!(d.state, ComponentState::Installed);
    }

    #[tokio::test]
    async fn refuses_dnscrypt_with_bad_signature() {
        let key = TestKey::new();
        let e = env(&key).await;
        let other = TestKey::new();
        let zip = archive::tests::dnscrypt_zip(&archive::tests::fake_macho());
        e.srv.set(
            "/dl/2.1.20/dnscrypt-proxy-macos_arm64-2.1.20.zip.minisig",
            other.sign(&zip).into_bytes(),
        );
        let err = e.mgr.install("dnscrypt-proxy").await.unwrap_err();
        assert!(matches!(err, UpdateError::Signature(_)), "{err}");
        assert!(!dnscrypt_proxy_binary(&e.paths).exists());
        let s = e
            .mgr
            .statuses()
            .into_iter()
            .find(|s| s.name == "dnscrypt-proxy")
            .unwrap();
        assert_eq!(s.state, ComponentState::Error);
        assert!(s.message.unwrap().contains("signature"));
        // Missing Parabellum key / non-macOS / store-managed refusals.
        assert!(matches!(
            e.mgr.install("parabellum").await.unwrap_err(),
            UpdateError::MissingPublicKey
        ));
        assert!(matches!(
            e.mgr.install("ublock-chrome").await.unwrap_err(),
            UpdateError::Unsupported(_)
        ));
        assert!(matches!(
            e.mgr.install("nope").await.unwrap_err(),
            UpdateError::NotFound(_)
        ));
        if !cfg!(target_os = "macos") {
            assert!(matches!(
                e.mgr.install("lulu").await.unwrap_err(),
                UpdateError::Unsupported(_)
            ));
        }
    }

    #[tokio::test]
    async fn auto_update_installs_missing_required_only() {
        let key = TestKey::new();
        let e = env(&key).await;
        let msgs = e.mgr.auto_update().await;
        assert!(
            msgs.iter()
                .any(|m| m.starts_with("dnscrypt-proxy : dnscrypt-proxy 2.1.20 installé")),
            "{msgs:?}"
        );
        assert!(
            msgs.iter()
                .any(|m| m.contains("Parabellum 99.0.0 disponible")),
            "{msgs:?}"
        );
        assert!(
            !msgs.iter().any(|m| m.starts_with("LuLu")),
            "optional components are never auto-installed"
        );
        assert!(dnscrypt_proxy_binary(&e.paths).exists());
    }

    #[test]
    fn finds_installer_app() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("BlockBlock Installer.app/Contents")).unwrap();
        std::fs::create_dir_all(d.path().join("__MACOSX/x.app")).unwrap();
        assert_eq!(
            find_installer_app(d.path()),
            Some(d.path().join("BlockBlock Installer.app"))
        );
    }
}
