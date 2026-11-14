//! "Permissions": who holds the sensitive macOS privacy permissions (TCC).
//!
//! - The daemon (root, Full Disk Access) reads the system database and the console user's database,
//!   symlink-safe ([`safefile`]), from a private copy (with its `-wal`).
//! - App names, paths, "still installed" and code signatures are resolved by the installed CLI
//!   (`parabellum --json permissions resolve -- <clients…>`) run **as the console user**: root never
//!   opens app bundles in user-writable folders. Results are cached for an hour.
//! - Each grant is risk-scored ([`tcc::score`]); a new high-risk grant raises one `system` alert (the first
//!   audit is the baseline). Periodic re-audit every `permissions.interval_hours`.
//! - Revoking is the user's: the app opens the right System Settings pane or runs
//!   `parabellum permissions reset` (tccutil, as the user). Browser extensions are audited by the CLI as the
//!   user too (`parabellum permissions extensions`), not by the daemon.
//! - Location grants live in `locationd`'s private store, not in TCC: not covered.

pub mod safefile;
pub mod tcc;

use crate::actions;
use crate::ctx::Ctx;
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tcc::TccRow;

/// `permissions_audit` with `refresh` re-runs at most this often.
pub const MIN_REFRESH_SECS: i64 = 30;
pub const STARTUP_DELAY: Duration = Duration::from_secs(900);
/// The resolver (codesign / spctl on every app) may take a while.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(240);
const IDENTITY_TTL: i64 = 3600;
pub const STATE_FILE: &str = "permissions.json";
pub const MAX_ALERTS: usize = 5;
/// Clients passed to one resolver run.
pub const MAX_CLIENTS: usize = 400;

/// What the alerting remembers (`state/permissions.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuditState {
    pub baseline_done: bool,
    /// High-risk grants seen by the last audit.
    pub known_high: Vec<String>,
}

static CACHE: Mutex<Option<(i64, PermissionsReport)>> = Mutex::new(None);
static IDENTITIES: Mutex<Option<HashMap<String, (i64, AppIdentity)>>> = Mutex::new(None);
static RUNNING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Rows of both databases (`true` = system database).
#[derive(Debug, Default)]
pub struct DbRows {
    pub rows: Vec<(TccRow, bool)>,
    pub system_ok: bool,
    pub user_ok: bool,
    pub errors: Vec<String>,
}

/// Read both databases (blocking).
pub fn read_dbs(system_db: &Path, user: Option<(u32, &Path)>, work: &Path) -> DbRows {
    let mut out = DbRows::default();
    match tcc::read_db(system_db, 0, work) {
        Ok(Some(rows)) => {
            out.system_ok = true;
            out.rows.extend(rows.into_iter().map(|r| (r, true)));
        }
        Ok(None) => out.errors.push("Base TCC du système absente".into()),
        Err(e) => out.errors.push(format!(
            "Base TCC du système illisible ({e}) : vérifie l'accès complet au disque de Parabellum"
        )),
    }
    match user {
        Some((uid, home)) => match tcc::read_db(&home.join(tcc::USER_DB), uid, work) {
            Ok(Some(rows)) => {
                out.user_ok = true;
                out.rows.extend(rows.into_iter().map(|r| (r, false)));
            }
            Ok(None) => out.errors.push("Base TCC de l'utilisateur absente".into()),
            Err(e) => out
                .errors
                .push(format!("Base TCC de l'utilisateur illisible ({e})")),
        },
        None => out
            .errors
            .push("Aucun utilisateur connecté : base TCC de l'utilisateur non lue".into()),
    }
    out
}

/// Bundle ids / absolute paths only (they are passed as arguments to the resolver).
pub fn valid_client(c: &str) -> bool {
    if c.starts_with('/') {
        c.len() <= 1024 && !c.chars().any(char::is_control)
    } else {
        !c.is_empty()
            && c.len() <= 255
            && c.as_bytes()[0].is_ascii_alphanumeric()
            && c.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    }
}

/// Assemble the report (pure).
pub fn build_report(
    db: &DbRows,
    ids: &HashMap<String, AppIdentity>,
    configuration_profiles: Vec<String>,
    now: i64,
) -> PermissionsReport {
    let mut grants: Vec<TccGrant> = db
        .rows
        .iter()
        .filter(|(r, _)| !r.service.is_empty() && !r.client.is_empty())
        .map(|(r, system)| {
            let id = ids.get(&r.client);
            let signing = id.and_then(|i| i.signing.clone());
            let installed = id.and_then(|i| i.installed);
            let (risk, reasons) = tcc::score(&tcc::RiskInput {
                service: &r.service,
                auth: r.auth,
                client: &r.client,
                client_is_path: r.client_is_path,
                installed,
                signing: signing.as_ref(),
            });
            TccGrant {
                id: tcc::grant_id(*system, &r.service, &r.client, r.target.as_deref()),
                service: r.service.clone(),
                service_label: tcc::service_label(&r.service),
                client: r.client.clone(),
                client_is_path: r.client_is_path,
                app_name: id.and_then(|i| i.name.clone()).or_else(|| {
                    r.client_is_path
                        .then(|| {
                            Path::new(&r.client)
                                .file_name()
                                .map(|n| n.to_string_lossy().into_owned())
                        })
                        .flatten()
                }),
                app_path: id.and_then(|i| i.path.clone()),
                installed,
                auth: r.auth,
                system_wide: *system,
                last_modified: r.last_modified,
                target: r.target.clone(),
                target_name: r
                    .target
                    .as_ref()
                    .and_then(|t| ids.get(t))
                    .and_then(|i| i.name.clone()),
                signing,
                risk,
                reasons,
                settings_url: Some(tcc::settings_url(&r.service)),
            }
        })
        .collect();
    grants.sort_by(|a, b| {
        b.risk
            .cmp(&a.risk)
            .then_with(|| a.service_label.cmp(&b.service_label))
            .then_with(|| a.client.cmp(&b.client))
    });
    grants.dedup_by(|a, b| a.id == b.id);
    PermissionsReport {
        generated_at: now,
        grants,
        system_db_read: db.system_ok,
        user_db_read: db.user_ok,
        configuration_profiles,
        errors: db.errors.clone(),
    }
}

/// High-risk grants that are allowed (alert material).
pub fn high_risk_ids(r: &PermissionsReport) -> Vec<String> {
    r.grants
        .iter()
        .filter(|g| {
            g.risk >= Severity::High
                && matches!(g.auth, TccAuthValue::Allowed | TccAuthValue::Limited)
        })
        .map(|g| g.id.clone())
        .collect()
}

/// Alerts for high-risk grants not in `state` (none for the baseline audit); updates `state`.
pub fn new_alerts(state: &mut AuditState, r: &PermissionsReport) -> Vec<(Alert, String)> {
    let high = high_risk_ids(r);
    let mut out = Vec::new();
    if state.baseline_done {
        for g in r
            .grants
            .iter()
            .filter(|g| high.contains(&g.id) && !state.known_high.contains(&g.id))
            .take(MAX_ALERTS)
        {
            let who = g.app_name.clone().unwrap_or_else(|| g.client.clone());
            let mut a = actions::alert(
                AlertKind::System,
                Severity::High,
                format!("Nouvelle permission sensible : {who} ({})", g.service_label),
                format!(
                    "{who} a reçu l'autorisation « {} ». {}. Si tu ne l'as pas accordée toi-même, retire-la dans \
                     Réglages Système > Confidentialité et sécurité > {}, puis analyse l'app.",
                    g.service_label,
                    g.reasons.join(". "),
                    g.service_label
                ),
            );
            a.path = g
                .app_path
                .clone()
                .or_else(|| g.client_is_path.then(|| g.client.clone()));
            out.push((a, format!("tcc:{}", g.id)));
        }
    }
    state.baseline_done = true;
    state.known_high = high;
    out
}

fn cached() -> Option<(i64, PermissionsReport)> {
    CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Resolve clients through the CLI run as the console user (cached for an hour).
async fn resolve(ctx: &Arc<Ctx>, clients: Vec<String>) -> HashMap<String, AppIdentity> {
    let now = pb_core::now_ts();
    let mut out = HashMap::new();
    let mut missing = Vec::new();
    {
        let g = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
        for c in clients {
            match g.as_ref().and_then(|m| m.get(&c)) {
                Some((at, id)) if now - at < IDENTITY_TTL => {
                    out.insert(c, id.clone());
                }
                _ => missing.push(c),
            }
        }
    }
    missing.retain(|c| valid_client(c));
    missing.truncate(MAX_CLIENTS);
    if missing.is_empty() || !cfg!(target_os = "macos") {
        return out;
    }
    match run_resolver(ctx, &missing).await {
        Ok(list) => {
            let mut g = IDENTITIES.lock().unwrap_or_else(|e| e.into_inner());
            let m = g.get_or_insert_with(HashMap::new);
            for id in list {
                if missing.contains(&id.client) {
                    m.insert(id.client.clone(), (now, id.clone()));
                    out.insert(id.client.clone(), id);
                }
            }
        }
        Err(e) => tracing::warn!(error = %e, "permissions: app resolution failed"),
    }
    out
}

async fn run_resolver(ctx: &Arc<Ctx>, clients: &[String]) -> Result<Vec<AppIdentity>, String> {
    let cli = ctx.paths.bin_dir().join("parabellum");
    if !cli.is_file() {
        return Err(format!("{} absent", cli.display()));
    }
    let user = crate::system::console_user().ok_or("aucun utilisateur connecté")?;
    if user.uid == 0 {
        return Err("utilisateur root".into());
    }
    let gid = crate::system::user_gid(user.uid).ok_or("groupe introuvable")?;
    let mut cmd = tokio::process::Command::new(&cli);
    cmd.args(["--json", "permissions", "resolve", "--"])
        .args(clients)
        .current_dir("/")
        .env_clear()
        .env("HOME", &user.home)
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .uid(user.uid)
        .gid(gid);
    let out = tokio::time::timeout(RESOLVE_TIMEOUT, cmd.output())
        .await
        .map_err(|_| "délai dépassé".to_string())?
        .map_err(|e| e.to_string())?;
    if out.stdout.len() > 8 * 1024 * 1024 {
        return Err("réponse trop longue".into());
    }
    serde_json::from_slice(&out.stdout).map_err(|e| format!("réponse illisible : {e}"))
}

async fn configuration_profiles(ctx: &Arc<Ctx>) -> Vec<String> {
    ctx.store
        .run(|s| s.list_persistence(false))
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|p| {
            p.kind == PersistenceKind::ConfigurationProfile
                && p.status != PersistenceStatus::Removed
        })
        .map(|p| p.label.unwrap_or(p.path))
        .collect()
}

/// Run the audit, cache it, alert on new high-risk grants.
pub async fn run_audit(ctx: &Arc<Ctx>) -> PermissionsReport {
    let _g = RUNNING.lock().await;
    let work = ctx.paths.tmp_dir();
    let user = crate::system::console_user();
    let db = if cfg!(target_os = "macos") {
        let u = user.clone();
        tokio::task::spawn_blocking(move || {
            read_dbs(
                Path::new(tcc::SYSTEM_DB),
                u.as_ref().map(|u| (u.uid, u.home.as_path())),
                &work,
            )
        })
        .await
        .unwrap_or_default()
    } else {
        DbRows {
            errors: vec!["Audit des permissions disponible sur macOS uniquement".into()],
            ..Default::default()
        }
    };
    let clients: BTreeSet<String> = db
        .rows
        .iter()
        .flat_map(|(r, _)| std::iter::once(r.client.clone()).chain(r.target.clone()))
        .collect();
    let ids = resolve(ctx, clients.into_iter().collect()).await;
    let report = build_report(
        &db,
        &ids,
        configuration_profiles(ctx).await,
        pb_core::now_ts(),
    );
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = Some((report.generated_at, report.clone()));
    if db.system_ok || db.user_ok {
        sync_alerts(ctx, &report).await;
    }
    report
}

async fn sync_alerts(ctx: &Arc<Ctx>, report: &PermissionsReport) {
    let dir = ctx.paths.state_dir();
    let mut state = pb_vpn::fsutil::read_json::<AuditState>(&dir.join(STATE_FILE))
        .ok()
        .flatten()
        .unwrap_or_default();
    let alerts = new_alerts(&mut state, report);
    if let Err(e) = pb_vpn::fsutil::write_json(&dir.join(STATE_FILE), &state) {
        tracing::warn!(error = %e, "permissions.json not saved");
    }
    if ctx.config().permissions.alert_high_risk {
        for (a, key) in alerts {
            actions::raise_alert(ctx, a, Some(key)).await;
        }
    }
}

/// `permissions_audit`.
pub async fn get(ctx: &Arc<Ctx>, refresh: bool) -> Result<PermissionsReport, IpcError> {
    if let Some((at, r)) = cached() {
        if !refresh || pb_core::now_ts() - at < MIN_REFRESH_SECS {
            return Ok(r);
        }
    }
    if !cfg!(target_os = "macos") && cached().is_none() && refresh {
        return Err(IpcError::new(
            ErrorCode::Unavailable,
            "audit des permissions : macOS uniquement",
        ));
    }
    Ok(run_audit(ctx).await)
}

/// Periodic audit (`permissions.interval_hours`), deferred on low battery.
pub async fn periodic_loop(ctx: Arc<Ctx>) {
    let mut shutdown = ctx.shutdown_rx();
    tokio::select! {
        _ = tokio::time::sleep(STARTUP_DELAY) => {}
        _ = shutdown.changed() => return,
    }
    loop {
        let cfg = ctx.config();
        let interval = i64::from(cfg.permissions.interval_hours) * 3600;
        let due = cached().is_none_or(|(at, _)| pb_core::now_ts() - at >= interval - 60);
        if cfg.permissions.enabled
            && cfg!(target_os = "macos")
            && due
            && !ctx.should_defer_heavy_work()
        {
            let r = run_audit(&ctx).await;
            tracing::info!(
                grants = r.grants.len(),
                high = high_risk_ids(&r).len(),
                "permissions audit done"
            );
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(1800)) => {}
            _ = shutdown.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident(client: &str, name: &str, installed: Option<bool>, adhoc: bool) -> AppIdentity {
        AppIdentity {
            client: client.into(),
            name: Some(name.into()),
            path: Some(format!("/Applications/{name}.app")),
            installed,
            signing: Some(SigningInfo {
                signed: true,
                valid: true,
                adhoc,
                team_id: (!adhoc).then(|| "ABCDE12345".into()),
                identifier: Some(client.into()),
                authority: None,
                notarized: (!adhoc).then_some(true),
                apple: false,
            }),
        }
    }

    #[test]
    fn report_from_synthetic_databases() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().canonicalize().unwrap();
        let sys_db = root.join("system/TCC.db");
        std::fs::create_dir_all(sys_db.parent().unwrap()).unwrap();
        tcc::tests::make_db(
            &sys_db,
            &[
                (
                    "kTCCServiceAccessibility",
                    "com.example.clicker",
                    0,
                    2,
                    "UNUSED",
                    1_760_000_000,
                ),
                (
                    "kTCCServiceScreenCapture",
                    "us.zoom.xos",
                    0,
                    2,
                    "UNUSED",
                    1_760_000_000,
                ),
                (
                    "kTCCServiceSystemPolicyAllFiles",
                    "com.old.backup",
                    0,
                    2,
                    "UNUSED",
                    1_700_000_000,
                ),
            ],
        );
        let home = root.join("home");
        let user_db = home.join(tcc::USER_DB);
        std::fs::create_dir_all(user_db.parent().unwrap()).unwrap();
        tcc::tests::make_db(
            &user_db,
            &[
                (
                    "kTCCServiceCamera",
                    "us.zoom.xos",
                    0,
                    2,
                    "UNUSED",
                    1_760_000_000,
                ),
                (
                    "kTCCServiceAppleEvents",
                    "com.example.clicker",
                    0,
                    2,
                    "com.apple.finder",
                    1_760_000_000,
                ),
                (
                    "kTCCServiceMicrophone",
                    "com.example.clicker",
                    0,
                    0,
                    "UNUSED",
                    1_760_000_000,
                ),
            ],
        );
        let work = root.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let me = crate::system::euid();
        // The system copy must be root's: on a non-root test run, read it as "ours".
        let db = if me == 0 {
            read_dbs(&sys_db, Some((me, &home)), &work)
        } else {
            let mut a = read_dbs(&root.join("absent.db"), Some((me, &home)), &work);
            let sys = tcc::read_db(&sys_db, me, &work).unwrap().unwrap();
            a.rows.extend(sys.into_iter().map(|r| (r, true)));
            a.system_ok = true;
            a
        };
        assert!(db.user_ok && db.system_ok);
        assert_eq!(db.rows.len(), 6);
        let mut ids = HashMap::new();
        ids.insert(
            "com.example.clicker".into(),
            ident("com.example.clicker", "Clicker", Some(true), true),
        );
        ids.insert(
            "us.zoom.xos".into(),
            ident("us.zoom.xos", "zoom.us", Some(true), false),
        );
        ids.insert(
            "com.old.backup".into(),
            AppIdentity {
                client: "com.old.backup".into(),
                name: None,
                path: None,
                installed: Some(false),
                signing: None,
            },
        );
        ids.insert(
            "com.apple.finder".into(),
            AppIdentity {
                client: "com.apple.finder".into(),
                name: Some("Finder".into()),
                path: None,
                installed: Some(true),
                signing: None,
            },
        );
        let r = build_report(&db, &ids, vec!["Profil MDM".into()], 1_770_000_000);
        assert_eq!(r.grants.len(), 6);
        let top = &r.grants[0];
        assert_eq!(top.risk, Severity::High);
        assert_eq!(top.service, "kTCCServiceAccessibility");
        assert_eq!(top.app_name.as_deref(), Some("Clicker"));
        assert!(top.system_wide);
        assert!(top
            .settings_url
            .as_deref()
            .unwrap()
            .ends_with("Privacy_Accessibility"));
        let ae = r
            .grants
            .iter()
            .find(|g| g.service == "kTCCServiceAppleEvents")
            .unwrap();
        assert_eq!(ae.target_name.as_deref(), Some("Finder"));
        assert!(!ae.system_wide);
        let stale = r
            .grants
            .iter()
            .find(|g| g.client == "com.old.backup")
            .unwrap();
        assert_eq!(stale.installed, Some(false));
        assert_eq!(stale.risk, Severity::Low);
        let mic = r
            .grants
            .iter()
            .find(|g| g.service == "kTCCServiceMicrophone")
            .unwrap();
        assert_eq!((mic.auth, mic.risk), (TccAuthValue::Denied, Severity::Info));
        assert_eq!(r.configuration_profiles, vec!["Profil MDM".to_string()]);

        // Alerts: baseline first, then only new high-risk grants.
        let mut st = AuditState::default();
        assert!(new_alerts(&mut st, &r).is_empty());
        assert!(st.baseline_done && st.known_high.len() == 1);
        assert!(new_alerts(&mut st, &r).is_empty());
        let mut r2 = r.clone();
        let mut g = r2.grants[0].clone();
        g.id = "feedfeedfeedfeed".into();
        g.service_label = "Enregistrement de l'écran".into();
        r2.grants.push(g);
        let a = new_alerts(&mut st, &r2);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].1, "tcc:feedfeedfeedfeed");
        assert!(a[0].0.title.contains("Clicker"));
        assert_eq!(a[0].0.path.as_deref(), Some("/Applications/Clicker.app"));
    }

    #[test]
    fn client_validation() {
        assert!(valid_client("com.example.app-2_x"));
        assert!(valid_client("/usr/local/bin/tool"));
        assert!(!valid_client("--json"));
        assert!(!valid_client("com.example;rm"));
        assert!(!valid_client("/x\ny"));
        assert!(!valid_client(""));
    }
}
