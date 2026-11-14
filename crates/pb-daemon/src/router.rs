//! IPC request router: one function per command of [`pb_core::ipc::Request`].
//! Authorization (mutating commands) is enforced by the server before calling [`handle`].

use crate::actions;
use crate::backends::ScanOpts;
use crate::ctx::Ctx;
use crate::jobs::{self, CancelOutcome, JobSpec};
use crate::scheduler;
use pb_core::config::Config;
use pb_core::ipc::*;
use pb_core::model::*;
use serde::Serialize;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;

/// Placeholder returned instead of secrets to peers that may not change the configuration.
pub const REDACTED: &str = "********";
/// Max paths in one `scan` request.
pub const MAX_SCAN_PATHS: usize = 1_000;
/// Max pause.
pub const MAX_PAUSE_MINUTES: u32 = 7 * 24 * 60;
/// uBlock Origin Lite store pages.
pub const CHROME_UBOL_URL: &str =
    "https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh";
pub const SAFARI_UBOL_URL: &str = "https://apps.apple.com/app/id6745342698";
/// kv key holding the pause deadline.
pub const KV_PAUSED_UNTIL: &str = "paused_until";

/// The connected client, as seen by the router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
    pub pid: Option<i32>,
    pub exe: Option<PathBuf>,
    /// Allowed to run mutating commands.
    pub can_mutate: bool,
    /// Root or administrator-approved for this request (secrets may be returned).
    pub admin: bool,
}

fn json<T: Serialize>(v: &T) -> Result<Value, IpcError> {
    serde_json::to_value(v).map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))
}

fn bad(msg: impl Into<String>) -> IpcError {
    IpcError::new(ErrorCode::BadRequest, msg)
}

async fn blocking<T, F>(f: F) -> Result<T, IpcError>
where
    F: FnOnce() -> Result<T, crate::backends::BackendError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?
        .map_err(IpcError::from)
}

/// Every secret field of the configuration.
fn secrets_mut(c: &mut Config) -> [&mut Option<String>; 5] {
    [
        &mut c.updates.github_token,
        &mut c.privacy.virustotal_api_key,
        &mut c.data_removal.smtp_password,
        &mut c.breach.hibp_api_key,
        &mut c.aliases.api_key,
    ]
}

/// `q.m@example.com` -> `q***1a2b@example.com` (first character, `***`, 4 hex digits of the SHA-256 of the
/// value so two masked values never collide, domain); without `@`: `q***1a2b`. Empty stays empty.
pub fn mask_identifier(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let Some(first) = s.chars().next() else {
        return String::new();
    };
    let tag: String = hex::encode(Sha256::digest(s.as_bytes()))
        .chars()
        .take(4)
        .collect();
    match s.rsplit_once('@') {
        Some((_, domain)) => format!("{first}***{tag}@{domain}"),
        None => format!("{first}***{tag}"),
    }
}

/// Hide secrets and mask personal identifiers (monitored addresses, SMTP sender and login), like the GDPR
/// identity: shown in clear only with administrator approval.
pub fn redact(cfg: &Config) -> Config {
    let mut c = cfg.clone();
    for s in secrets_mut(&mut c) {
        if s.is_some() {
            *s = Some(REDACTED.into());
        }
    }
    for e in &mut c.breach.emails {
        *e = mask_identifier(e);
    }
    c.data_removal.from_address = mask_identifier(&c.data_removal.from_address);
    c.data_removal.smtp_username = mask_identifier(&c.data_removal.smtp_username);
    c
}

/// Original of a masked value sent back (masks are unique per value).
fn unmask(value: &str, originals: &[String]) -> Option<String> {
    if !value.contains("***") {
        return None;
    }
    originals
        .iter()
        .find(|o| mask_identifier(o) == value)
        .cloned()
}

/// A client sending back a redacted config keeps the stored secrets and identifiers.
pub fn unredact(new: &mut Config, old: &Config) {
    let mut old_c = old.clone();
    for (n, o) in secrets_mut(new).into_iter().zip(secrets_mut(&mut old_c)) {
        if n.as_deref() == Some(REDACTED) {
            *n = o.clone();
        }
    }
    for e in &mut new.breach.emails {
        if let Some(o) = unmask(e, &old.breach.emails) {
            *e = o;
        }
    }
    let from = std::slice::from_ref(&old.data_removal.from_address);
    if let Some(o) = unmask(&new.data_removal.from_address, from) {
        new.data_removal.from_address = o;
    }
    let user = std::slice::from_ref(&old.data_removal.smtp_username);
    if let Some(o) = unmask(&new.data_removal.smtp_username, user) {
        new.data_removal.smtp_username = o;
    }
}

/// Dispatch one request. `Subscribe` is handled by the server (this returns `null` for it).
pub async fn handle(ctx: &Arc<Ctx>, peer: &Peer, req: Request) -> Result<Value, IpcError> {
    match req {
        Request::Ping => json(&PingResponse {
            version: pb_core::VERSION.into(),
            protocol: PROTOCOL_VERSION,
        }),
        Request::Status => json(&crate::status::refresh(ctx).await),
        Request::Scan {
            paths,
            recursive,
            use_clamav,
        } => scan(ctx, peer, paths, recursive, use_clamav).await,
        Request::CancelScan { job_id } => match ctx.jobs.cancel(&job_id) {
            CancelOutcome::Signalled => Ok(Value::Null),
            CancelOutcome::Dequeued(j) => {
                jobs::finalize_dequeued(ctx, j).await;
                Ok(Value::Null)
            }
            CancelOutcome::NotFound => Err(IpcError::new(
                ErrorCode::NotFound,
                "aucune analyse en cours avec cet identifiant",
            )),
        },
        Request::ListJobs { limit } => {
            let limit = limit.clamp(1, 1_000);
            let mut list = ctx.store.run(move |s| s.list_jobs(limit)).await?;
            for j in ctx.jobs.active() {
                let live = j.summary();
                match list.iter_mut().find(|s| s.job_id == live.job_id) {
                    Some(s) => *s = live,
                    None => list.insert(0, live),
                }
            }
            list.truncate(limit as usize);
            json(&list)
        }
        Request::GetJob { job_id } => {
            let id = job_id.clone();
            let mut detail = ctx
                .store
                .run(move |s| s.get_job(&id))
                .await?
                .ok_or_else(|| {
                    IpcError::new(ErrorCode::NotFound, format!("analyse {job_id} introuvable"))
                })?;
            if let Some(live) = ctx.jobs.get(&job_id) {
                detail.summary = live.summary();
            }
            json(&detail)
        }
        Request::ListAlerts {
            limit,
            include_resolved,
        } => {
            let limit = limit.clamp(1, 10_000);
            json(
                &ctx.store
                    .run(move |s| s.list_alerts(limit, include_resolved))
                    .await?,
            )
        }
        Request::ResolveAlert { alert_id, action } => {
            json(&actions::resolve_alert(ctx, alert_id, action).await?)
        }
        Request::ListQuarantine => {
            let q = ctx.backends.quarantine.clone();
            let mut list = blocking(move || q.list()).await?;
            list.sort_by_key(|e| std::cmp::Reverse(e.quarantined_at));
            json(&list)
        }
        Request::QuarantinePath { path } => json(&actions::quarantine_manual(ctx, &path).await?),
        Request::Restore { entry_id, allow } => {
            let restored = actions::restore_entry(ctx, &entry_id, allow).await?;
            Ok(serde_json::json!({ "restored_path": restored }))
        }
        Request::DeleteQuarantined { entry_id } => {
            actions::delete_entry(ctx, &entry_id).await?;
            Ok(Value::Null)
        }
        Request::ReportFalsePositive { sha256, path, note } => {
            actions::report_false_positive(ctx, &sha256, path, note).await?;
            Ok(Value::Null)
        }
        Request::ListPersistence { only_new } => {
            json(&ctx.store.run(move |s| s.list_persistence(only_new)).await?)
        }
        Request::SetPersistenceStatus { item_id, status } => {
            json(&crate::persistence::set_status(ctx, &item_id, status).await?)
        }
        Request::ListDevices { kind } => json(&ctx.store.run(move |s| s.list_devices(kind)).await?),
        Request::SetDeviceTrust { device_id, trust } => {
            json(&crate::devices::set_device_trust(ctx, &device_id, trust).await?)
        }
        Request::UpdateNow { target } => {
            // Claimed before answering: a scheduled run racing this request yields `Busy` here
            // instead of a started job that never reports.
            scheduler::claim_update(ctx)?;
            let ctx2 = ctx.clone();
            tokio::spawn(async move {
                scheduler::run_claimed_updates(&ctx2, target).await;
            });
            json(&JobStarted {
                job_id: uuid::Uuid::new_v4().to_string(),
            })
        }
        Request::ListComponents => {
            let mut list = ctx.backends.updater.list_components(&ctx.config()).await;
            let db = ctx.paths.db_current();
            if let Ok(zbt) =
                tokio::task::spawn_blocking(move || crate::spyware::component_status(&db)).await
            {
                list.push(zbt);
            }
            json(&list)
        }
        Request::InstallComponent { name } => {
            validate_component_name(&name)?;
            let ctx2 = ctx.clone();
            tokio::spawn(async move {
                // Zero Breach Toolkit ships inside the signed threat-DB bundle: "installing" it means
                // fetching the latest bundle, then reporting its status (the app waits for this event).
                if name == crate::spyware::COMPONENT_NAME {
                    if let Err(e) =
                        crate::scheduler::run_updates(&ctx2, pb_core::model::UpdateTarget::Db).await
                    {
                        tracing::info!(error = %e.message, "zero-breach-toolkit: DB update skipped");
                    }
                    let db = ctx2.paths.db_current();
                    if let Ok(mut st) =
                        tokio::task::spawn_blocking(move || crate::spyware::component_status(&db))
                            .await
                    {
                        if st.state == ComponentState::NotInstalled {
                            st.message = Some(
                                "absent de la base actuelle : il arrive avec la prochaine base de menaces"
                                    .into(),
                            );
                        }
                        ctx2.bus.publish(DaemonEvent::Component(st));
                    }
                    ctx2.status_dirty.notify_one();
                    return;
                }
                let cfg = ctx2.config();
                match ctx2.backends.updater.install_component(&name, &cfg).await {
                    Ok(st) => ctx2.bus.publish(DaemonEvent::Component(st)),
                    Err(e) => {
                        tracing::warn!(component = %name, error = %e, "install failed");
                        if let Some(mut st) = ctx2
                            .backends
                            .updater
                            .list_components(&ctx2.config())
                            .await
                            .into_iter()
                            .find(|c| c.name == name)
                        {
                            st.state = ComponentState::Error;
                            st.message = Some(e.to_string());
                            ctx2.bus.publish(DaemonEvent::Component(st));
                        }
                    }
                }
                ctx2.status_dirty.notify_one();
            });
            json(&JobStarted {
                job_id: uuid::Uuid::new_v4().to_string(),
            })
        }
        Request::SetComponentAutoUpdate { name, auto_update } => {
            validate_component_name(&name)?;
            json(
                &ctx.backends
                    .updater
                    .set_component_auto_update(&name, auto_update, &ctx.config())
                    .await?,
            )
        }
        Request::GetDns => json(&ctx.backends.dns.status(&ctx.config()).await),
        Request::SetDns { enabled } => json(&set_dns(ctx, enabled).await?),
        Request::AdblockStatus => {
            let cfg = ctx.config();
            let (chrome, safari) = ctx
                .backends
                .updater
                .extension_states(ctx.console_home())
                .await;
            json(&AdblockStatus {
                chrome_ublock: chrome,
                safari_ublock: safari,
                dns: ctx.backends.dns.status(&cfg).await,
                chrome_store_url: CHROME_UBOL_URL.into(),
                safari_store_url: SAFARI_UBOL_URL.into(),
            })
        }
        Request::GetConfig => {
            let cfg = ctx.config();
            json(&if peer.admin {
                (*cfg).clone()
            } else {
                redact(&cfg)
            })
        }
        // Answered redacted like GetConfig for non-admins: the client keeps it, and sends it back as is.
        Request::SetConfig { config } => json(&redact(&set_config(ctx, config).await?)),
        Request::SetProtection { paused_minutes } => {
            json(&set_protection(ctx, paused_minutes).await?)
        }
        Request::WeeklyReport { week_offset } => {
            json(&crate::report::weekly(ctx, week_offset).await?)
        }
        Request::RetroHunt { days } => json(&JobStarted {
            job_id: scheduler::start_retro_hunt(ctx, days).await?,
        }),
        Request::SpywareScan => json(&JobStarted {
            job_id: crate::spyware::start(ctx).await?,
        }),
        Request::Posture { refresh } => json(&crate::posture::get(ctx, refresh).await?),

        // ----- VPN & networks -----
        Request::VpnStatus => json(&crate::vpn::service(ctx)?.status().await),
        Request::VpnConnect => json(
            &crate::vpn::service(ctx)?
                .connect()
                .await
                .map_err(crate::vpn::err)?,
        ),
        Request::VpnDisconnect => json(
            &crate::vpn::service(ctx)?
                .disconnect()
                .await
                .map_err(crate::vpn::err)?,
        ),
        Request::VpnImportProfile { profile } => {
            if profile.len() > 64 * 1024 {
                return Err(bad("profil trop long"));
            }
            json(
                &crate::vpn::service(ctx)?
                    .import_profile(&profile)
                    .await
                    .map_err(crate::vpn::err)?,
            )
        }
        Request::VpnRemoveProfile => {
            crate::vpn::service(ctx)?
                .remove_profile()
                .await
                .map_err(crate::vpn::err)?;
            Ok(Value::Null)
        }
        Request::VpnLeakTest => json(
            &crate::vpn::service(ctx)?
                .leak_test()
                .await
                .map_err(crate::vpn::err)?,
        ),
        Request::VpnListServices => json(&crate::vpn::service(ctx)?.list_services().await),
        Request::ListNetworks => json(&crate::vpn::service(ctx)?.networks().await),
        Request::SetNetworkTrust {
            network_id,
            trusted,
        } => json(&crate::vpn::set_network_trust(ctx, &network_id, trusted).await?),

        // ----- Behaviour guard & snapshots -----
        Request::GuardStatus => json(&crate::guard::status(ctx).await),
        Request::ListSnapshots => json(&crate::guard::snapshots::list(ctx).await?),
        Request::CreateSnapshot => json(&crate::guard::snapshots::create(ctx).await?),
        Request::RestoreFromSnapshot { snapshot, path } => {
            let dest = crate::guard::snapshots::restore(ctx, &snapshot, &path).await?;
            Ok(serde_json::json!({ "restored_to": dest }))
        }

        // ----- Privacy -----
        Request::PrivacyGetProfile { reveal } => json(
            &crate::privacy::service(ctx)?
                .get_profile(reveal && peer.admin)
                .await,
        ),
        Request::PrivacySetProfile { profile } => json(
            &crate::privacy::service(ctx)?
                .set_profile(profile)
                .await
                .map_err(crate::privacy::err)?,
        ),
        Request::PrivacyListBrokers => {
            json(&crate::privacy::service(ctx)?.brokers(&ctx.config()).await)
        }
        Request::PrivacyListRequests => json(&crate::privacy::service(ctx)?.requests().await),
        Request::PrivacySummary => {
            json(&crate::privacy::service(ctx)?.summary(&ctx.config()).await)
        }
        Request::PrivacyStartRemoval { broker_ids } => json(
            &crate::privacy::service(ctx)?
                .start_removal(&ctx.config(), broker_ids)
                .await
                .map_err(crate::privacy::err)?,
        ),
        Request::PrivacyUpdateRequest {
            request_id,
            status,
            note,
        } => {
            if note.as_ref().is_some_and(|n| n.len() > 4096) {
                return Err(bad("note trop longue"));
            }
            json(
                &crate::privacy::service(ctx)?
                    .update_request(&request_id, status, note)
                    .await
                    .map_err(crate::privacy::err)?,
            )
        }
        Request::PrivacyDraft { request_id } => json(
            &crate::privacy::service(ctx)?
                .draft(&ctx.config(), &request_id)
                .await
                .map_err(crate::privacy::err)?,
        ),
        Request::PrivacyComplaint { request_id } => json(
            &crate::privacy::service(ctx)?
                .complaint(&ctx.config(), &request_id)
                .await
                .map_err(crate::privacy::err)?,
        ),
        Request::BreachList => json(&crate::privacy::service(ctx)?.breaches().await),
        Request::BreachCheckNow => json(
            &crate::privacy::service(ctx)?
                .check_breaches(&ctx.config())
                .await
                .map_err(crate::privacy::err)?,
        ),
        Request::AliasList => json(&crate::privacy::service(ctx)?.aliases().await),
        Request::AliasCreate { label } => {
            let label = label.trim().to_string();
            if label.is_empty() || label.len() > 200 || label.chars().any(char::is_control) {
                return Err(bad("libellé invalide (1 à 200 caractères)"));
            }
            json(
                &crate::privacy::service(ctx)?
                    .create_alias(&ctx.config(), &label)
                    .await
                    .map_err(crate::privacy::err)?,
            )
        }
        Request::Subscribe => Ok(Value::Null),
        // ----- Intelligence -----
        Request::IntelStatus => json(&crate::intel::status(ctx)),
        Request::IntelScoreDomain { domain } => json(&crate::intel::score_domain(ctx, &domain)?),
        Request::IntelAllowDomain { domain } => {
            crate::intel::allow_domain(ctx, &domain).await?;
            json(&crate::intel::status(ctx))
        }
        Request::IntelMarkNormal { anomaly_id } => {
            let id = anomaly_id.trim();
            if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(bad("identifiant d'anomalie invalide"));
            }
            let alert = crate::intel::mark_normal(ctx, id).await?;
            crate::intel::resolve_linked_alert(ctx, alert).await;
            json(&crate::intel::status(ctx))
        }
        Request::IntelResetBaseline => {
            crate::intel::reset_baseline(ctx).await;
            json(&crate::intel::status(ctx))
        }

        // ----- Local network (LAN inventory) -----
        Request::LanStatus { network_id } => {
            json(&crate::lan::status(ctx, network_id.as_deref()).await?)
        }
        Request::LanScan { active } => json(&crate::lan::scan_now(ctx, active).await?),
        Request::LanSetDevice {
            network_id,
            mac,
            name,
            trusted,
        } => json(&crate::lan::set_device(ctx, &network_id, &mac, name, trusted).await?),
        Request::LanForgetDevice { network_id, mac } => {
            crate::lan::forget_device(ctx, &network_id, &mac).await?;
            Ok(Value::Null)
        }
        Request::LanPorts { mac } => json(&crate::lan::check_ports(ctx, &mac).await?),

        // ----- Permissions audit -----
        Request::PermissionsAudit { refresh } => {
            json(&crate::permissions::get(ctx, refresh).await?)
        }
    }
}

fn validate_component_name(name: &str) -> Result<(), IpcError> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(bad("nom de composant invalide"));
    }
    Ok(())
}

/// Under a user's home, stores macOS protects even from that user's own processes (TCC) or that hold
/// other apps' data: a non-administrator peer may not have the root daemon enumerate them.
pub const PROTECTED_HOME_DIRS: &[&str] = &[
    "Library/Messages",
    "Library/Mail",
    "Library/Safari",
    "Library/Cookies",
    "Library/Containers",
    "Library/Group Containers",
    "Library/Daemon Containers",
    "Library/Application Support/com.apple.TCC",
    "Library/Application Support/AddressBook",
    "Library/Application Support/CallHistoryDB",
    "Library/Application Support/CallHistoryTransactions",
    "Library/Application Support/Knowledge",
    "Library/Application Support/com.apple.sharedfilelist",
    "Library/Calendars",
    "Library/Reminders",
    "Library/HomeKit",
    "Library/IdentityServices",
    "Library/Accounts",
    "Library/Biome",
    "Library/Suggestions",
    "Library/PersonalizationPortrait",
    "Library/Metadata/CoreSpotlight",
    "Library/Mobile Documents",
    "Library/Sharing",
    "Library/Trial",
    "Pictures/Photos Library.photoslibrary",
];

/// Shared or removable locations any local user can already list.
pub const SHARED_SCAN_ROOTS: &[&str] =
    &["/Applications", "/Volumes", "/Users/Shared", "/private/tmp"];

/// May a non-administrator peer whose home is `home` start a manual scan of `path`? Both canonical
/// (no symlink, no `..`). Allowed: the home (without [`PROTECTED_HOME_DIRS`], nor any folder holding
/// one, like the home itself or `~/Library`) and [`SHARED_SCAN_ROOTS`]. The rest (system folders,
/// other users) needs administrator approval: job progress shows every file path.
pub fn scan_root_allowed(path: &std::path::Path, home: Option<&std::path::Path>) -> bool {
    if SHARED_SCAN_ROOTS.iter().any(|r| path.starts_with(r)) {
        return true;
    }
    let Some(home) = home.filter(|h| h.is_absolute() && h.components().count() > 2) else {
        return false;
    };
    path.starts_with(home)
        && !PROTECTED_HOME_DIRS.iter().any(|d| {
            let d = home.join(d);
            path.starts_with(&d) || d.starts_with(path)
        })
}

async fn scan(
    ctx: &Arc<Ctx>,
    peer: &Peer,
    paths: Vec<String>,
    recursive: bool,
    use_clamav: Option<bool>,
) -> Result<Value, IpcError> {
    if paths.is_empty() {
        return Err(bad("aucun chemin à analyser"));
    }
    if paths.len() > MAX_SCAN_PATHS {
        return Err(bad(format!("au plus {MAX_SCAN_PATHS} chemins par analyse")));
    }
    let mut roots = Vec::with_capacity(paths.len());
    // Non-administrator peers: canonical roots inside the allowed locations (see scan_root_allowed).
    let home = (!peer.admin)
        .then(|| crate::system::user_by_uid(peer.uid))
        .flatten()
        .and_then(|(_, h)| std::fs::canonicalize(h).ok());
    for p in &paths {
        if p.contains('\0') || !p.starts_with('/') {
            return Err(bad(format!("chemin absolu requis : {p}")));
        }
        let mut pb = PathBuf::from(p);
        if std::fs::symlink_metadata(&pb).is_err() {
            return Err(IpcError::new(
                ErrorCode::NotFound,
                format!("introuvable : {p}"),
            ));
        }
        if !peer.admin {
            let canon = std::fs::canonicalize(&pb)
                .map_err(|_| IpcError::new(ErrorCode::NotFound, format!("introuvable : {p}")))?;
            if !scan_root_allowed(&canon, home.as_deref()) {
                tracing::warn!(uid = peer.uid, path = %canon.display(), "manual scan outside the user's locations: approval required");
                return Err(IpcError::new(
                    ErrorCode::AuthRequired,
                    format!(
                        "analyse de {p} : dossier système, protégé ou d'un autre utilisateur, autorisation administrateur requise"
                    ),
                ));
            }
            // Scan what was checked, not a symlink that could be swapped afterwards.
            pb = canon;
        }
        roots.push(pb);
    }
    let cfg = ctx.config();
    let spec = JobSpec {
        paths,
        roots,
        opts: ScanOpts {
            origin: ScanOrigin::Manual,
            use_clamav: use_clamav.unwrap_or(cfg.scan.clamav_on_demand),
            recursive,
            only_risky_types: false,
        },
    };
    json(&JobStarted {
        job_id: jobs::submit(ctx, spec).await?,
    })
}

/// Toggle DNS blocking: apply first, then persist the choice.
pub async fn set_dns(ctx: &Arc<Ctx>, enabled: bool) -> Result<DnsStatus, IpcError> {
    let write = ctx.config_write.lock().await;
    let mut cfg = (*ctx.config()).clone();
    cfg.dns.enabled = enabled;
    let mut status = if enabled {
        ctx.backends.dns.enable(&cfg).await?
    } else {
        ctx.backends.dns.disable().await?
    };
    crate::setup::save_config(&ctx.paths, &cfg)
        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?;
    ctx.publish_config(cfg.clone());
    drop(write);
    if enabled {
        // The supervisor starts its proxy and switches the system DNS: report what it achieved.
        for _ in 0..16 {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            status = ctx.backends.dns.status(&cfg).await;
            if status.running {
                break;
            }
        }
    }
    tracing::info!(enabled, "DNS blocking toggled");
    Ok(status)
}

/// Validate, save and apply a new configuration.
pub async fn set_config(ctx: &Arc<Ctx>, mut new: Config) -> Result<Config, IpcError> {
    let _write = ctx.config_write.lock().await;
    let old = ctx.config();
    unredact(&mut new, &old);
    new.validate().map_err(|e| bad(e.to_string()))?;
    crate::setup::save_config(&ctx.paths, &new)
        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?;
    ctx.state().config_error = None;
    ctx.publish_config(new.clone());
    tracing::info!("configuration updated");
    if old.dns != new.dns {
        let res = if new.dns.enabled {
            ctx.backends.dns.enable(&new).await.map(|_| ())
        } else if old.dns.enabled {
            ctx.backends.dns.disable().await.map(|_| ())
        } else {
            Ok(())
        };
        if let Err(e) = res {
            tracing::warn!(error = %e, "DNS settings not applied");
        }
    }
    if old.ml != new.ml || old.scan != new.scan {
        let ctx2 = ctx.clone();
        tokio::spawn(async move {
            scheduler::reload_engine(&ctx2).await;
        });
    }
    Ok(new)
}

/// Pause (minutes > 0) or resume (0) real-time protection.
pub async fn set_protection(ctx: &Arc<Ctx>, minutes: u32) -> Result<StatusInfo, IpcError> {
    if minutes > MAX_PAUSE_MINUTES {
        return Err(bad(format!("pause limitée à {MAX_PAUSE_MINUTES} minutes")));
    }
    if minutes == 0 {
        ctx.state().paused_until = None;
        ctx.store.run(|s| s.kv_delete(KV_PAUSED_UNTIL)).await?;
        tracing::info!("protection resumed");
    } else {
        let until = pb_core::now_ts() + i64::from(minutes) * 60;
        ctx.state().paused_until = Some(until);
        ctx.store
            .run(move |s| s.kv_set(KV_PAUSED_UNTIL, &until.to_string()))
            .await?;
        tracing::warn!(minutes, "protection paused");
        schedule_resume_notice(ctx.clone(), until);
    }
    Ok(crate::status::refresh(ctx).await)
}

/// Wake the status task when a pause expires (so `status_changed` is pushed on time).
pub fn schedule_resume_notice(ctx: Arc<Ctx>, until: i64) {
    tokio::spawn(async move {
        let secs = (until - pb_core::now_ts()).max(0) as u64 + 1;
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        ctx.status_dirty.notify_one();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_roundtrip() {
        let mut cfg = Config::default();
        cfg.privacy.virustotal_api_key = Some("secret".into());
        let r = redact(&cfg);
        assert_eq!(r.privacy.virustotal_api_key.as_deref(), Some(REDACTED));
        assert_eq!(r.updates.github_token, None);
        let mut back = r.clone();
        unredact(&mut back, &cfg);
        assert_eq!(back, cfg);
        let mut changed = r;
        changed.privacy.virustotal_api_key = Some("new".into());
        unredact(&mut changed, &cfg);
        assert_eq!(changed.privacy.virustotal_api_key.as_deref(), Some("new"));
    }

    #[test]
    fn new_secrets_are_redacted() {
        let mut cfg = Config::default();
        cfg.data_removal.smtp_password = Some("app-password".into());
        cfg.breach.hibp_api_key = Some("hibp".into());
        cfg.aliases.api_key = Some("addy".into());
        let r = redact(&cfg);
        assert_eq!(r.data_removal.smtp_password.as_deref(), Some(REDACTED));
        assert_eq!(r.breach.hibp_api_key.as_deref(), Some(REDACTED));
        assert_eq!(r.aliases.api_key.as_deref(), Some(REDACTED));
        let mut back = r;
        unredact(&mut back, &cfg);
        assert_eq!(back, cfg);
    }

    #[test]
    fn identifiers_are_masked_and_restored() {
        let mut cfg = Config::default();
        cfg.breach.emails = vec!["c.m@example.com".into(), "c.n@example.com".into()];
        cfg.data_removal.from_address = "c.m@example.com".into();
        cfg.data_removal.smtp_username = "cm".into();
        let r = redact(&cfg);
        assert!(
            r.breach.emails[0].starts_with("c***") && r.breach.emails[0].ends_with("@example.com")
        );
        assert_ne!(r.breach.emails[0], r.breach.emails[1]);
        assert!(!r.breach.emails[0].contains("c.m"));
        assert_eq!(r.data_removal.from_address, r.breach.emails[0]);
        assert!(r.data_removal.smtp_username.starts_with("c***"));
        assert_eq!(mask_identifier(""), "");
        let mut back = r.clone();
        unredact(&mut back, &cfg);
        assert_eq!(back, cfg);
        // Removing one masked address and adding a new one keeps the right originals.
        let mut edited = r.clone();
        edited.breach.emails.remove(0);
        edited.breach.emails.push("new@example.org".into());
        unredact(&mut edited, &cfg);
        assert_eq!(
            edited.breach.emails,
            vec!["c.n@example.com", "new@example.org"]
        );
    }

    /// DNS stub whose `disable` takes a while (window for a concurrent config write).
    struct SlowDns;

    #[async_trait::async_trait]
    impl crate::backends::Dns for SlowDns {
        async fn recover_on_startup(&self) {}
        async fn enable(&self, cfg: &Config) -> Result<DnsStatus, crate::backends::BackendError> {
            crate::backends::NullDns.enable(cfg).await
        }
        async fn disable(&self) -> Result<DnsStatus, crate::backends::BackendError> {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            Ok(DnsStatus::default())
        }
        async fn restore_system_dns(&self) -> Result<(), crate::backends::BackendError> {
            Ok(())
        }
        async fn status(&self, cfg: &Config) -> DnsStatus {
            crate::backends::NullDns.status(cfg).await
        }
        async fn rebuild_lists(&self, cfg: &Config) -> Result<u64, crate::backends::BackendError> {
            crate::backends::NullDns.rebuild_lists(cfg).await
        }
        fn start_supervisor(
            &self,
            _c: tokio::sync::watch::Receiver<Arc<Config>>,
            _s: tokio::sync::watch::Receiver<bool>,
        ) -> Option<tokio::task::JoinHandle<()>> {
            None
        }
    }

    /// A config write that started while another one was waiting on the DNS backend is not lost.
    #[tokio::test]
    async fn concurrent_config_writes_are_not_lost() {
        use pb_vpn::VpnHooks;
        let d = tempfile::tempdir().unwrap();
        let paths = pb_core::paths::Paths::with_root(d.path());
        crate::setup::prepare_dirs(&paths, false).unwrap();
        let mut backends = crate::backends::Backends::unavailable();
        backends.dns = Arc::new(SlowDns);
        let mut initial = Config::default();
        initial.dns.enabled = true;
        let ctx = Arc::new(Ctx::new(
            paths,
            true,
            crate::store::Store::open_in_memory().unwrap(),
            backends,
            initial,
        ));
        let a = tokio::spawn({
            let ctx = ctx.clone();
            async move { set_dns(&ctx, false).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let net = "gw:aa:bb:cc:dd:ee:ff".to_string();
        crate::vpn::DaemonVpnHooks::new(&ctx)
            .save_trusted_networks(vec![net.clone()])
            .await
            .unwrap();
        a.await.unwrap().unwrap();
        for cfg in [
            (*ctx.config()).clone(),
            Config::load(&ctx.paths.config_file()).unwrap(),
        ] {
            assert!(!cfg.dns.enabled);
            assert_eq!(cfg.vpn.trusted_networks, vec![net.clone()]);
        }
        // No temporary file left behind.
        let dir = ctx.paths.config_file().parent().unwrap().to_path_buf();
        assert!(!std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains(".tmp")));
    }

    #[test]
    fn scan_root_policy() {
        use std::path::Path;
        let home = Path::new("/Users/camille");
        let cases: &[(&str, bool)] = &[
            ("/Users/camille/Downloads", true),
            ("/Users/camille/Desktop/a.dmg", true),
            ("/Users/camille/Documents/projet", true),
            ("/Users/camille/Library/LaunchAgents", true),
            ("/Users/camille/Library/Application Support/Zoom", true),
            ("/Applications", true),
            ("/Applications/Foo.app", true),
            ("/Volumes/CLE USB", true),
            ("/Users/Shared/x", true),
            ("/private/tmp/x.pkg", true),
            // Holding protected stores, or inside one.
            ("/Users/camille", false),
            ("/Users/camille/Library", false),
            ("/Users/camille/Library/Application Support", false),
            ("/Users/camille/Library/Messages/chat.db", false),
            ("/Users/camille/Library/Mail/V10", false),
            ("/Users/camille/Library/Containers/com.apple.mail", false),
            (
                "/Users/camille/Library/Application Support/com.apple.TCC",
                false,
            ),
            (
                "/Users/camille/Pictures/Photos Library.photoslibrary",
                false,
            ),
            // Other users, system, prefix tricks.
            ("/Users/dominique/Documents", false),
            ("/Users/camille2/Documents", false),
            ("/Users", false),
            ("/", false),
            ("/private/var/root", false),
            ("/Library/Application Support/com.apple.TCC", false),
            ("/System/Volumes/Data/Users/camille/Documents", false),
            ("/ApplicationsX", false),
        ];
        for (p, want) in cases {
            assert_eq!(scan_root_allowed(Path::new(p), Some(home)), *want, "{p}");
        }
        // Unknown home: shared locations only; a bogus home grants nothing.
        assert!(scan_root_allowed(Path::new("/Applications"), None));
        assert!(!scan_root_allowed(
            Path::new("/Users/camille/Downloads"),
            None
        ));
        assert!(!scan_root_allowed(
            Path::new("/etc/x"),
            Some(Path::new("/"))
        ));
    }

    #[test]
    fn component_names() {
        assert!(validate_component_name("dnscrypt-proxy").is_ok());
        assert!(validate_component_name("../x").is_err());
        assert!(validate_component_name("").is_err());
        assert!(validate_component_name("ClamAV").is_err());
    }
}
