//! Threat-DB bundle updates: download, minisign verification, strict unpacking, digest checks,
//! atomic `db/current` swap, rollback, pruning, status.
//!
//! Layout (see `pb_core::paths`): `db/versions/<version>/` unpacked bundles, `db/current` and
//! `db/previous` relative symlinks (`versions/<version>`), `db/downloads/` scratch, `db/state.json`.

use crate::fsutil::{atomic_symlink, atomic_write, link_target_name, read_capped};
use crate::github::{self, AssetSource};
use crate::http::{Http, LARGE_TIMEOUT, SMALL_TIMEOUT};
use crate::signing::{verify_file_async, MAX_SIGNATURE_BYTES};
use crate::unpack::{unpack_bundle, UnpackLimits};
use crate::version::{client_satisfies, compare_db_versions, parse_db_version};
use crate::UpdateError;
use pb_core::config::UpdatesConfig;
use pb_core::db::{DbManifest, BUNDLE_FILE, MANIFEST_FILE, SIGNATURE_FILE};
use pb_core::model::{ComponentState, ComponentStatus, DbStatus};
use pb_core::paths::Paths;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Max size of the remote `manifest.json`.
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
/// Max size of the bundle archive.
pub const MAX_BUNDLE_BYTES: u64 = 1024 * 1024 * 1024;
/// Max size of the manifest inside an unpacked bundle.
const MAX_LOCAL_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const STATE_FILE: &str = "state.json";

/// Result of [`DbUpdater::check_and_update`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbUpdateOutcome {
    /// A new bundle was installed (the daemon must reload its engine).
    pub updated: bool,
    /// Active version after the call.
    pub version: String,
    /// Version now referenced by `db/previous`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<String>,
}

/// Persistent updater state (`db/state.json`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct DbState {
    last_check: Option<i64>,
    last_success: Option<i64>,
    last_error: Option<String>,
    /// Version the user rolled back *from*: never re-installed automatically (a newer one will be).
    rolled_back_from: Option<String>,
}

/// Threat-DB updater. Cheap to construct; all I/O happens in the methods.
pub struct DbUpdater {
    paths: Paths,
    updates: UpdatesConfig,
    public_key: Option<String>,
    client_version: String,
    github_api: String,
    lock: tokio::sync::Mutex<()>,
    #[cfg(test)]
    test_http: Option<Http>,
}

impl DbUpdater {
    /// `public_key`: minisign public key (bare base64 or 2-line `.pub`), normally
    /// `embedded_public_key().map(str::to_string)`. `None` ⇒ updates are refused.
    pub fn new(paths: Paths, updates: UpdatesConfig, public_key: Option<String>) -> Self {
        Self {
            paths,
            updates,
            public_key: public_key.filter(|k| !k.trim().is_empty()),
            client_version: pb_core::VERSION.to_string(),
            github_api: github::GITHUB_API.to_string(),
            lock: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            test_http: None,
        }
    }

    #[cfg(test)]
    fn with_test_http(mut self, http: Http) -> Self {
        self.test_http = Some(http);
        self
    }

    fn http(&self) -> Result<Http, UpdateError> {
        #[cfg(test)]
        if let Some(h) = &self.test_http {
            return Ok(h.clone());
        }
        Http::new(self.updates.github_token.clone())
    }

    fn state_path(&self) -> PathBuf {
        self.paths.db_dir().join(STATE_FILE)
    }

    fn load_state(&self) -> DbState {
        read_capped(&self.state_path(), 1024 * 1024)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_state(&self, st: &DbState) {
        let res = serde_json::to_vec_pretty(st)
            .map_err(std::io::Error::other)
            .and_then(|b| atomic_write(&self.state_path(), &b));
        if let Err(e) = res {
            tracing::warn!(error = %e, "cannot write db/state.json");
        }
    }

    /// Fetch the remote manifest and install the bundle if it is newer than the active one.
    ///
    /// The archive's minisign signature is verified (streaming) **before** anything is unpacked; the
    /// daemon reloads its engine itself when `updated == true`.
    pub async fn check_and_update(&self) -> Result<DbUpdateOutcome, UpdateError> {
        let _guard = self.lock.try_lock().map_err(|_| UpdateError::Busy)?;
        let mut st = self.load_state();
        st.last_check = Some(pb_core::now_ts());
        self.save_state(&st);
        let res = self.update_inner(&st).await;
        let mut st = self.load_state();
        match &res {
            Ok(outcome) => {
                st.last_success = Some(pb_core::now_ts());
                st.last_error = None;
                if outcome.updated {
                    st.rolled_back_from = None;
                }
            }
            Err(e) => st.last_error = Some(e.to_string()),
        }
        self.save_state(&st);
        let _ = std::fs::remove_dir_all(self.paths.db_downloads_dir());
        res
    }

    async fn update_inner(&self, st: &DbState) -> Result<DbUpdateOutcome, UpdateError> {
        let public_key = self
            .public_key
            .clone()
            .ok_or(UpdateError::MissingPublicKey)?;
        // Fail early on a malformed embedded key.
        crate::signing::parse_public_key(&public_key)?;
        let http = self.http()?;
        let base = self.updates.db_base_url.trim_end_matches('/').to_string();
        let sources = self.resolve_sources(&http, &base).await?;

        let remote_bytes = http
            .get_bytes(
                &sources.manifest.url,
                MAX_MANIFEST_BYTES,
                sources.manifest.accept.as_deref(),
                SMALL_TIMEOUT,
            )
            .await?;
        let remote: DbManifest = serde_json::from_slice(&remote_bytes)
            .map_err(|e| UpdateError::Manifest(format!("manifest.json distant : {e}")))?;
        remote.validate().map_err(UpdateError::Manifest)?;
        if parse_db_version(&remote.version).is_none() {
            return Err(UpdateError::Manifest(format!(
                "version invalide : {}",
                remote.version
            )));
        }
        self.check_client_version(&remote)?;

        let current = self.current_manifest();
        let previous = link_target_name(&self.paths.db_previous());
        if let Some(cur) = &current {
            match compare_db_versions(&remote.version, &cur.version) {
                Some(Ordering::Greater) => {}
                Some(Ordering::Less) => {
                    tracing::warn!(remote = %remote.version, current = %cur.version, "remote DB is older; downgrade refused");
                    return Ok(DbUpdateOutcome {
                        updated: false,
                        version: cur.version.clone(),
                        previous,
                    });
                }
                _ => {
                    return Ok(DbUpdateOutcome {
                        updated: false,
                        version: cur.version.clone(),
                        previous,
                    })
                }
            }
        }
        if st.rolled_back_from.as_deref() == Some(remote.version.as_str()) {
            tracing::info!(version = %remote.version, "skipping a version the user rolled back from");
            let version = current.map(|c| c.version).unwrap_or_default();
            return Ok(DbUpdateOutcome {
                updated: false,
                version,
                previous,
            });
        }

        // Download archive + signature.
        let dl = self.paths.db_downloads_dir();
        let _ = std::fs::remove_dir_all(&dl);
        std::fs::create_dir_all(&dl)?;
        let archive = dl.join(BUNDLE_FILE);
        http.download_to_file(
            &sources.bundle.url,
            &archive,
            MAX_BUNDLE_BYTES,
            sources.bundle.accept.as_deref(),
            LARGE_TIMEOUT,
        )
        .await?;
        let sig_bytes = http
            .get_bytes(
                &sources.signature.url,
                MAX_SIGNATURE_BYTES,
                sources.signature.accept.as_deref(),
                SMALL_TIMEOUT,
            )
            .await?;
        let sig_text = String::from_utf8(sig_bytes)
            .map_err(|_| UpdateError::Signature("signature non UTF-8".into()))?;

        // Verify the signature over the whole archive BEFORE unpacking.
        let trusted = verify_file_async(&archive, sig_text, public_key).await?;
        tracing::info!(version = %remote.version, trusted_comment = %trusted, "DB bundle signature OK");

        // Unpack + verify on the blocking pool.
        let paths = self.paths.clone();
        let client_version = self.client_version.clone();
        let remote2 = remote.clone();
        let installed_dir = tokio::task::spawn_blocking(move || {
            install_bundle(&paths, &archive, &remote2, &client_version)
        })
        .await
        .map_err(|e| UpdateError::Archive(format!("installation interrompue : {e}")))??;

        // Swap symlinks atomically: previous -> old current, current -> new.
        let old_current = link_target_name(&self.paths.db_current());
        if let Some(old) = &old_current {
            atomic_symlink(&Path::new("versions").join(old), &self.paths.db_previous())?;
        }
        atomic_symlink(
            &Path::new("versions").join(&remote.version),
            &self.paths.db_current(),
        )?;
        tracing::info!(version = %remote.version, dir = %installed_dir.display(), "threat DB activated");
        self.prune();
        Ok(DbUpdateOutcome {
            updated: true,
            version: remote.version.clone(),
            previous: old_current.or(previous),
        })
    }

    fn check_client_version(&self, m: &DbManifest) -> Result<(), UpdateError> {
        match client_satisfies(&m.min_client_version, &self.client_version) {
            Ok(true) => Ok(()),
            Ok(false) => Err(UpdateError::ClientTooOld {
                required: m.min_client_version.clone(),
                current: self.client_version.clone(),
            }),
            Err(e) => Err(UpdateError::Manifest(e)),
        }
    }

    /// Where to fetch the three files. With a GitHub token and a `github.com/<o>/<r>/releases/download/<tag>`
    /// base URL, go through the API asset URLs (required for private repositories).
    async fn resolve_sources(&self, http: &Http, base: &str) -> Result<DbSources, UpdateError> {
        if http.has_token() {
            if let Some((owner, repo, tag)) = github::parse_release_download_base(base) {
                let rel =
                    github::release_by_tag(http, &self.github_api, &owner, &repo, &tag).await?;
                let find = |name: &str| -> Result<AssetSource, UpdateError> {
                    rel.asset(name)
                        .map(|a| AssetSource::for_asset(a, true))
                        .ok_or_else(|| {
                            UpdateError::NotFound(format!("asset {name} dans la release {tag}"))
                        })
                };
                return Ok(DbSources {
                    manifest: find(MANIFEST_FILE)?,
                    bundle: find(BUNDLE_FILE)?,
                    signature: find(SIGNATURE_FILE)?,
                });
            }
        }
        Ok(DbSources {
            manifest: AssetSource::direct(format!("{base}/{MANIFEST_FILE}")),
            bundle: AssetSource::direct(format!("{base}/{BUNDLE_FILE}")),
            signature: AssetSource::direct(format!("{base}/{SIGNATURE_FILE}")),
        })
    }

    /// Swap `db/current` and `db/previous`. Returns the version now active.
    /// The version rolled back from is remembered and not re-installed automatically.
    pub fn rollback(&self) -> Result<String, UpdateError> {
        let _guard = self.lock.try_lock().map_err(|_| UpdateError::Busy)?;
        let prev = link_target_name(&self.paths.db_previous()).ok_or(UpdateError::NoPrevious)?;
        let prev_dir = self.paths.db_versions_dir().join(&prev);
        let m = read_manifest(&prev_dir).ok_or(UpdateError::NoPrevious)?;
        m.validate().map_err(UpdateError::Manifest)?;
        if m.version != prev {
            return Err(UpdateError::Manifest(format!(
                "{prev} : version du manifeste incohérente ({})",
                m.version
            )));
        }
        let cur = link_target_name(&self.paths.db_current());
        atomic_symlink(&Path::new("versions").join(&prev), &self.paths.db_current())?;
        if let Some(c) = &cur {
            atomic_symlink(&Path::new("versions").join(c), &self.paths.db_previous())?;
        }
        let mut st = self.load_state();
        st.rolled_back_from = cur;
        self.save_state(&st);
        tracing::warn!(version = %prev, "threat DB rolled back");
        Ok(prev)
    }

    /// Manifest of the active bundle (`db/current/manifest.json`), if any.
    pub fn current_manifest(&self) -> Option<DbManifest> {
        read_manifest(&self.paths.db_current())
    }

    /// Status for the UI (`StatusInfo.db`).
    pub fn status(&self) -> DbStatus {
        let st = self.load_state();
        let m = self.current_manifest();
        DbStatus {
            version: m.as_ref().map(|m| m.version.clone()),
            built_at: m.as_ref().map(|m| m.built_at),
            previous_version: link_target_name(&self.paths.db_previous()),
            last_check: st.last_check,
            last_success: st.last_success,
            last_error: st.last_error,
            malware_hashes: m.as_ref().map(|m| m.stats.malware_hashes).unwrap_or(0),
            yara_rules: m.as_ref().map(|m| m.stats.yara_rules).unwrap_or(0),
            blocked_domains: m.as_ref().map(|m| m.stats.blocked_domains).unwrap_or(0),
            clamav_version: clamav_daily_version(&self.paths.clamav_db_dir()),
            ml_model_version: m.as_ref().and_then(|m| m.stats.ml_model_version.clone()),
        }
    }

    /// The threat DB as a `threat-db` [`ComponentStatus`] (for `list_components`).
    pub fn component_status(&self) -> ComponentStatus {
        let s = self.status();
        let state = if self.public_key.is_none() {
            ComponentState::Error
        } else if s.version.is_none() {
            ComponentState::NotInstalled
        } else if s.last_error.is_some() {
            ComponentState::Error
        } else {
            ComponentState::Installed
        };
        let message = if self.public_key.is_none() {
            Some(crate::MISSING_KEY_MESSAGE.to_string())
        } else {
            s.last_error.clone()
        };
        ComponentStatus {
            name: "threat-db".into(),
            display_name: "Base de menaces Parabellum".into(),
            installed_version: s.version,
            latest_version: None,
            state,
            last_check: s.last_check,
            auto_update: true,
            required: true,
            message,
            action_url: None,
        }
    }

    /// Keep `current`, `previous` and the newest other version; delete older versions and stale `.tmp` dirs.
    fn prune(&self) {
        let dir = self.paths.db_versions_dir();
        let keep: BTreeSet<String> = [
            link_target_name(&self.paths.db_current()),
            link_target_name(&self.paths.db_previous()),
        ]
        .into_iter()
        .flatten()
        .collect();
        let Ok(rd) = std::fs::read_dir(&dir) else {
            return;
        };
        let mut others: Vec<String> = Vec::new();
        for e in rd.flatten().take(10_000) {
            let name = e.file_name().to_string_lossy().to_string();
            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if !is_dir {
                continue;
            }
            if name.ends_with(".tmp") {
                let _ = std::fs::remove_dir_all(e.path());
            } else if parse_db_version(&name).is_some() && !keep.contains(&name) {
                others.push(name);
            }
        }
        others.sort_by(|a, b| compare_db_versions(b, a).unwrap_or(Ordering::Equal));
        for old in others.iter().skip(1) {
            tracing::info!(version = %old, "pruning old threat DB");
            let _ = std::fs::remove_dir_all(dir.join(old));
        }
    }
}

struct DbSources {
    manifest: AssetSource,
    bundle: AssetSource,
    signature: AssetSource,
}

fn read_manifest(dir: &Path) -> Option<DbManifest> {
    let bytes = read_capped(&dir.join(MANIFEST_FILE), MAX_LOCAL_MANIFEST_BYTES).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Unpack into `versions/<v>.tmp`, check the inner manifest and every digest, then rename to `versions/<v>`.
fn install_bundle(
    paths: &Paths,
    archive: &Path,
    remote: &DbManifest,
    client_version: &str,
) -> Result<PathBuf, UpdateError> {
    let versions = paths.db_versions_dir();
    std::fs::create_dir_all(&versions)?;
    let tmp = versions.join(format!("{}.tmp", remote.version));
    let final_dir = versions.join(&remote.version);
    if tmp.exists() {
        std::fs::remove_dir_all(&tmp)?;
    }
    let res = (|| {
        let allowed: BTreeSet<String> = remote.files.keys().cloned().collect();
        let digests = unpack_bundle(archive, &tmp, &allowed, UnpackLimits::default())?;
        let inner = read_manifest(&tmp).ok_or_else(|| {
            UpdateError::Manifest("manifest.json absent ou illisible dans l'archive".into())
        })?;
        inner.validate().map_err(UpdateError::Manifest)?;
        if inner.version != remote.version {
            return Err(UpdateError::Manifest(format!(
                "version signée {} ≠ version annoncée {}",
                inner.version, remote.version
            )));
        }
        match client_satisfies(&inner.min_client_version, client_version) {
            Ok(true) => {}
            Ok(false) => {
                return Err(UpdateError::ClientTooOld {
                    required: inner.min_client_version.clone(),
                    current: client_version.to_string(),
                })
            }
            Err(e) => return Err(UpdateError::Manifest(e)),
        }
        for (path, expected) in &inner.files {
            match digests.get(path) {
                Some(actual) if actual.eq_ignore_ascii_case(expected) => {}
                Some(_) => return Err(UpdateError::Digest(path.clone())),
                None => return Err(UpdateError::Digest(format!("{path} absent de l'archive"))),
            }
        }
        if let Some(extra) = digests
            .keys()
            .find(|p| p.as_str() != MANIFEST_FILE && !inner.files.contains_key(*p))
        {
            return Err(UpdateError::Archive(format!("fichier non listé : {extra}")));
        }
        Ok(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    if final_dir.exists() {
        // Same version installed earlier (e.g. the `previous` target after a rollback): replace it.
        std::fs::remove_dir_all(&final_dir)?;
    }
    std::fs::rename(&tmp, &final_dir)?;
    let _ = crate::fsutil::sync_dir(&versions);
    Ok(final_dir)
}

/// Version of the official ClamAV `daily` database (`daily.cld` / `daily.cvd` 512-byte header
/// `ClamAV-VDB:<time>:<version>:<sigs>:…`).
pub(crate) fn clamav_daily_version(db_dir: &Path) -> Option<String> {
    use std::io::Read;
    for name in ["daily.cld", "daily.cvd"] {
        let Ok(f) = std::fs::File::open(db_dir.join(name)) else {
            continue;
        };
        let mut head = Vec::with_capacity(512);
        if f.take(512).read_to_end(&mut head).is_err() {
            continue;
        }
        let text = String::from_utf8_lossy(&head);
        let mut fields = text.split(':');
        if fields.next() != Some("ClamAV-VDB") {
            continue;
        }
        if let Some(v) = fields
            .nth(1)
            .map(str::trim)
            .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        {
            return Some(v.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::test_keys::TestKey;
    use crate::testutil::TestServer;
    use pb_core::db::{DbStats, DB_FORMAT};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;

    struct Bundle {
        manifest: DbManifest,
        archive: Vec<u8>,
    }

    enum Extra {
        None,
        Symlink,
        Traversal,
        Unlisted,
    }

    fn manifest_for(version: &str, files: &[(&str, &[u8])]) -> DbManifest {
        DbManifest {
            format: DB_FORMAT,
            version: version.into(),
            built_at: 1_700_000_000,
            min_client_version: "0.1.0".into(),
            sources: vec![],
            files: files
                .iter()
                .map(|(p, c)| (p.to_string(), hex::encode(Sha256::digest(c))))
                .collect::<BTreeMap<_, _>>(),
            stats: DbStats {
                malware_hashes: 2,
                yara_rules: 1,
                blocked_domains: 3,
                ..Default::default()
            },
        }
    }

    fn append_raw(
        builder: &mut tar::Builder<Vec<u8>>,
        name: &str,
        etype: tar::EntryType,
        data: &[u8],
        link: Option<&str>,
    ) {
        let mut h = tar::Header::new_gnu();
        // Write the name bytes directly so that unsafe names (`../x`) can be produced for the tests.
        {
            let gnu = h.as_gnu_mut().unwrap();
            gnu.name[..name.len()].copy_from_slice(name.as_bytes());
        }
        h.set_entry_type(etype);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        if let Some(l) = link {
            h.set_link_name(l).unwrap();
        }
        h.set_cksum();
        builder.append(&h, data).unwrap();
    }

    fn make_bundle(version: &str, tamper_file: bool, extra: Extra) -> Bundle {
        let files: Vec<(&str, &[u8])> = vec![
            ("hashes/malware.sha256", &[1u8; 64]),
            ("yara/test.yar", b"rule t { condition: false }"),
            ("dns/malware.txt", b"evil.example\n"),
        ];
        let manifest = manifest_for(version, &files);
        let mut b = tar::Builder::new(Vec::new());
        append_raw(
            &mut b,
            "manifest.json",
            tar::EntryType::Regular,
            &serde_json::to_vec(&manifest).unwrap(),
            None,
        );
        append_raw(&mut b, "hashes/", tar::EntryType::Directory, b"", None);
        for (p, c) in &files {
            let data: Vec<u8> = if tamper_file && *p == "yara/test.yar" {
                b"rule t { condition: true }".to_vec()
            } else {
                c.to_vec()
            };
            append_raw(&mut b, p, tar::EntryType::Regular, &data, None);
        }
        match extra {
            Extra::None => {}
            Extra::Symlink => append_raw(
                &mut b,
                "dns/ads.txt",
                tar::EntryType::Symlink,
                b"",
                Some("/etc/passwd"),
            ),
            Extra::Traversal => {
                append_raw(&mut b, "../escape.txt", tar::EntryType::Regular, b"x", None)
            }
            Extra::Unlisted => append_raw(
                &mut b,
                "dns/unlisted.txt",
                tar::EntryType::Regular,
                b"x",
                None,
            ),
        }
        let tar_bytes = b.into_inner().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
        Bundle {
            manifest,
            archive: gz.finish().unwrap(),
        }
    }

    async fn serve(srv: &TestServer, key: &TestKey, b: &Bundle) {
        srv.set(
            "/db/manifest.json",
            serde_json::to_vec(&b.manifest).unwrap(),
        );
        srv.set("/db/parabellum-db.tar.gz", b.archive.clone());
        srv.set(
            "/db/parabellum-db.tar.gz.minisig",
            key.sign(&b.archive).into_bytes(),
        );
    }

    fn updater(root: &Path, srv: &TestServer, key: Option<String>) -> DbUpdater {
        let paths = Paths::with_root(root);
        for d in paths.all_dirs() {
            std::fs::create_dir_all(d).unwrap();
        }
        let updates = UpdatesConfig {
            db_base_url: srv.url("/db"),
            ..Default::default()
        };
        DbUpdater::new(paths, updates, key).with_test_http(Http::new_for_tests(None))
    }

    #[tokio::test]
    async fn full_update_rollback_and_downgrade() {
        let key = TestKey::new();
        let srv = TestServer::start(vec![]).await;
        let d = tempfile::tempdir().unwrap();
        let up = updater(d.path(), &srv, Some(key.public_file()));

        serve(&srv, &key, &make_bundle("2026.10.24.1", false, Extra::None)).await;
        let o = up.check_and_update().await.unwrap();
        assert_eq!(
            o,
            DbUpdateOutcome {
                updated: true,
                version: "2026.10.24.1".into(),
                previous: None
            }
        );
        assert_eq!(up.current_manifest().unwrap().version, "2026.10.24.1");
        assert!(d.path().join("db/current/yara/test.yar").exists());

        // Same version again: no-op.
        let o = up.check_and_update().await.unwrap();
        assert!(!o.updated);

        serve(&srv, &key, &make_bundle("2026.10.25.1", false, Extra::None)).await;
        let o = up.check_and_update().await.unwrap();
        assert_eq!(o.version, "2026.10.25.1");
        assert_eq!(o.previous.as_deref(), Some("2026.10.24.1"));
        let st = up.status();
        assert_eq!(st.version.as_deref(), Some("2026.10.25.1"));
        assert_eq!(st.previous_version.as_deref(), Some("2026.10.24.1"));
        assert_eq!(st.malware_hashes, 2);
        assert!(st.last_success.is_some() && st.last_error.is_none());

        // Downgrade refused.
        serve(&srv, &key, &make_bundle("2026.10.20.1", false, Extra::None)).await;
        let o = up.check_and_update().await.unwrap();
        assert!(!o.updated);
        assert_eq!(o.version, "2026.10.25.1");

        // Rollback swaps current and previous, and the rolled-back version is not re-installed.
        assert_eq!(up.rollback().unwrap(), "2026.10.24.1");
        assert_eq!(up.current_manifest().unwrap().version, "2026.10.24.1");
        assert_eq!(
            up.status().previous_version.as_deref(),
            Some("2026.10.25.1")
        );
        serve(&srv, &key, &make_bundle("2026.10.25.1", false, Extra::None)).await;
        assert!(!up.check_and_update().await.unwrap().updated);
        // A newer one is installed again.
        serve(&srv, &key, &make_bundle("2026.10.26.1", false, Extra::None)).await;
        let o = up.check_and_update().await.unwrap();
        assert!(o.updated);
        assert_eq!(o.previous.as_deref(), Some("2026.10.24.1"));

        // Pruning keeps current + previous + one more.
        serve(&srv, &key, &make_bundle("2026.10.27.1", false, Extra::None)).await;
        up.check_and_update().await.unwrap();
        serve(&srv, &key, &make_bundle("2026.10.28.1", false, Extra::None)).await;
        up.check_and_update().await.unwrap();
        let mut versions: Vec<String> = std::fs::read_dir(d.path().join("db/versions"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        versions.sort();
        assert_eq!(
            versions,
            vec!["2026.10.26.1", "2026.10.27.1", "2026.10.28.1"]
        );
        assert!(!d.path().join("db/downloads").exists());
    }

    async fn expect_failure(
        b: Bundle,
        sign_with: Option<&TestKey>,
    ) -> (UpdateError, tempfile::TempDir) {
        let key = TestKey::new();
        let srv = TestServer::start(vec![]).await;
        let d = tempfile::tempdir().unwrap();
        let up = updater(d.path(), &srv, Some(key.public_b64()));
        serve(&srv, sign_with.unwrap_or(&key), &b).await;
        let err = up.check_and_update().await.unwrap_err();
        assert!(up.current_manifest().is_none(), "nothing must be activated");
        assert!(up.status().last_error.is_some());
        let leftovers: Vec<_> = std::fs::read_dir(d.path().join("db/versions"))
            .unwrap()
            .collect();
        assert!(leftovers.is_empty(), "no unpacked leftovers");
        (err, d)
    }

    #[tokio::test]
    async fn bad_signature_is_rejected_before_unpacking() {
        let other = TestKey::new();
        let (err, _d) = expect_failure(
            make_bundle("2026.10.25.1", false, Extra::None),
            Some(&other),
        )
        .await;
        assert!(matches!(err, UpdateError::Signature(_)), "{err}");
    }

    #[tokio::test]
    async fn tampered_digest_is_rejected() {
        let (err, _d) = expect_failure(make_bundle("2026.10.25.1", true, Extra::None), None).await;
        assert!(matches!(err, UpdateError::Digest(_)), "{err}");
    }

    #[tokio::test]
    async fn traversal_entry_is_rejected() {
        let (err, d) =
            expect_failure(make_bundle("2026.10.25.1", false, Extra::Traversal), None).await;
        assert!(matches!(err, UpdateError::Archive(_)), "{err}");
        assert!(!d.path().join("db/escape.txt").exists());
    }

    #[tokio::test]
    async fn symlink_entry_is_rejected() {
        let (err, _d) =
            expect_failure(make_bundle("2026.10.25.1", false, Extra::Symlink), None).await;
        assert!(matches!(err, UpdateError::Archive(_)), "{err}");
    }

    #[tokio::test]
    async fn unlisted_file_is_rejected() {
        let (err, _d) =
            expect_failure(make_bundle("2026.10.25.1", false, Extra::Unlisted), None).await;
        assert!(matches!(err, UpdateError::Archive(_)), "{err}");
    }

    #[tokio::test]
    async fn version_mismatch_between_outer_and_signed_manifest() {
        let key = TestKey::new();
        let srv = TestServer::start(vec![]).await;
        let d = tempfile::tempdir().unwrap();
        let up = updater(d.path(), &srv, Some(key.public_b64()));
        let b = make_bundle("2026.10.25.1", false, Extra::None);
        serve(&srv, &key, &b).await;
        let mut fake = b.manifest.clone();
        fake.version = "2026.12.31.1".into();
        srv.set("/db/manifest.json", serde_json::to_vec(&fake).unwrap());
        let err = up.check_and_update().await.unwrap_err();
        assert!(matches!(err, UpdateError::Manifest(_)), "{err}");
    }

    #[tokio::test]
    async fn missing_key_and_old_client_are_refused() {
        let key = TestKey::new();
        let srv = TestServer::start(vec![]).await;
        let d = tempfile::tempdir().unwrap();
        let up = updater(d.path(), &srv, None);
        let mut b = make_bundle("2026.10.25.1", false, Extra::None);
        serve(&srv, &key, &b).await;
        let err = up.check_and_update().await.unwrap_err();
        assert!(matches!(err, UpdateError::MissingPublicKey));
        assert!(err.to_string().contains("make keys"));
        assert_eq!(up.component_status().state, ComponentState::Error);

        let up = updater(d.path(), &srv, Some(key.public_b64()));
        b.manifest.min_client_version = "99.0.0".into();
        serve(&srv, &key, &b).await;
        assert!(matches!(
            up.check_and_update().await.unwrap_err(),
            UpdateError::ClientTooOld { .. }
        ));
        assert!(matches!(
            up.rollback().unwrap_err(),
            UpdateError::NoPrevious
        ));
    }

    #[test]
    fn reads_clamav_daily_header() {
        let d = tempfile::tempdir().unwrap();
        let mut head =
            b"ClamAV-VDB:25 Oct 2026 07-21 -0400:27800:2075478:90:X:Y:raynman:1761391283".to_vec();
        head.resize(512, b' ');
        std::fs::write(d.path().join("daily.cld"), head).unwrap();
        assert_eq!(clamav_daily_version(d.path()).as_deref(), Some("27800"));
        assert_eq!(clamav_daily_version(&d.path().join("nope")), None);
    }
}
