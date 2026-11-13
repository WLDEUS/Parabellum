//! Intelligence: the phishing / malicious-domain model on DNS queries and the on-device behavioural
//! baseline on eslogger events (see `pb-intel`).
//!
//! Domains: dnscrypt-proxy's query log is piped to [`run_domains`] (lossy channel, never slows
//! resolution). Each first-seen name is scored inline (microseconds); suspicious ones are remembered
//! (`state/intel/domains.json`, bounded), alerted (deduplicated per registrable domain, daily cap) and,
//! only when `intelligence.block_ml_domains` is on and the *trained model* is confident enough,
//! appended to `dns/ml-blocked.txt` followed by a debounced list rebuild. Query names themselves are
//! never written to disk.
//!
//! Behaviour: the real-time dispatcher forwards exec / file events ([`on_exec`], [`on_file`],
//! non-blocking); [`run_behavior`] feeds the baseline (`state/intel/baseline.json.gz`, saved every
//! 10 minutes and at shutdown), and alerts on novelties above `intelligence.anomaly_threshold` after the
//! learning period, with dedupe and a daily cap. Nothing leaves the Mac.

use crate::actions;
use crate::ctx::Ctx;
use crate::store::AlertKey;
use chrono::Timelike;
use pb_core::config::Config;
use pb_core::events::EsProcessInfo;
use pb_core::ipc::{ErrorCode, IpcError};
use pb_core::model::*;
use pb_intel::behavior::identity::ProcInfo;
use pb_intel::behavior::{AnomalyRecord, Baseline, BehaviorEvent, ObsKind};
use pb_intel::domain::{normalize, suffix};
use pb_intel::{DomainScorer, Scored, VerdictSource};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Query names buffered between the DNS reader and the scorer.
pub const QUERY_CHANNEL: usize = 4096;
/// Behaviour events buffered between the dispatcher and the baseline.
pub const BEHAVIOR_CHANNEL: usize = 4096;
/// Distinct names remembered as already scored (cleared by halves beyond).
const SEEN_MAX: usize = 50_000;
/// New names scored per second at most (beyond: dropped, scored when seen again later).
const SCORE_RATE: u32 = 100;
const FLAGGED_MAX: usize = 500;
const ML_BLOCKED_MAX: usize = 5_000;
const DOMAIN_ALERTS_PER_DAY: u32 = 20;
const ALERT_DEDUPE_SECS: i64 = 86_400;
/// First rebuild this long after a change, then at most every [`REBUILD_MIN_GAP`].
const REBUILD_DEBOUNCE: Duration = Duration::from_secs(30);
const REBUILD_MIN_GAP: Duration = Duration::from_secs(600);
const SAVE_EVERY: Duration = Duration::from_secs(600);
/// Alert key prefixes (stored in the alerts' `detection` column).
pub const DOMAIN_KEY: &str = "intel-domain:";
pub const ANOMALY_KEY: &str = "intel-anomaly:";
/// ES `codesigning_flags` CS_ADHOC.
const CS_ADHOC: u32 = 0x2;

/// Persisted domain-side state (`state/intel/domains.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct DomainState {
    flagged: Vec<FlaggedDomain>,
    flagged_total: u64,
    /// Domain -> when it was added to the ML blocklist.
    ml_blocked: BTreeMap<String, i64>,
}

#[derive(Default)]
struct Inner {
    scorer: Arc<DomainScorer>,
    scorer_error: Option<String>,
    seen: HashMap<String, i64>,
    scored_total: u64,
    /// (hour index, count) for the last 24 hours.
    scored_hours: VecDeque<(i64, u64)>,
    domains: DomainState,
    domains_dirty: bool,
    domain_alerts: (String, u32),
    rate: (i64, u32),
    rebuild_wanted: bool,
    baseline: Option<Baseline>,
    baseline_dirty: bool,
    baseline_bytes: u64,
    baseline_error: Option<String>,
    anomaly_alerts: (String, u32),
    anomaly_alerted: HashMap<String, i64>,
}

/// Shared intelligence state (in [`Ctx`]).
#[derive(Default)]
pub struct IntelState {
    inner: Mutex<Inner>,
    behavior_tx: OnceLock<mpsc::Sender<BehaviorEvent>>,
}

impl std::fmt::Debug for IntelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntelState").finish_non_exhaustive()
    }
}

impl IntelState {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn intel_dir(ctx: &Ctx) -> PathBuf {
    ctx.paths.state_dir().join("intel")
}
fn domains_file(ctx: &Ctx) -> PathBuf {
    intel_dir(ctx).join("domains.json")
}
fn baseline_file(ctx: &Ctx) -> PathBuf {
    intel_dir(ctx).join("baseline.json.gz")
}
fn ml_blocked_file(ctx: &Ctx) -> PathBuf {
    ctx.paths.dns_dir().join(pb_dns::ML_BLOCKED_FILE)
}

/// Atomic write (fresh temp file, never through a symlink, then rename).
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = o.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

fn today() -> String {
    crate::system::local_date(pb_core::now_ts())
}

/// Bumps a per-day counter; `false` when `max` is already reached today.
fn take_daily(slot: &mut (String, u32), max: u32) -> bool {
    let d = today();
    if slot.0 != d {
        *slot = (d, 0);
    }
    if slot.1 >= max {
        return false;
    }
    slot.1 += 1;
    true
}

/// Start the intelligence tasks. Call before the DNS supervisor starts (the query tap must be in place
/// when dnscrypt-proxy is spawned).
pub fn start(ctx: &Arc<Ctx>) -> Vec<JoinHandle<()>> {
    let (qtx, qrx) = mpsc::channel(QUERY_CHANNEL);
    ctx.backends.dns.set_query_tap(qtx);
    let (btx, brx) = mpsc::channel(BEHAVIOR_CHANNEL);
    let _ = ctx.intel.behavior_tx.set(btx);
    vec![
        tokio::spawn(run_domains(ctx.clone(), qrx)),
        tokio::spawn(run_behavior(ctx.clone(), brx)),
    ]
}

// ---------------------------------------------------------------------------------------------
// Domain model
// ---------------------------------------------------------------------------------------------

/// (Re)load the domain model from the current threat-DB bundle (startup and after DB updates).
pub async fn reload_model(ctx: &Arc<Ctx>) {
    let dir = ctx.paths.db_current();
    let res = tokio::task::spawn_blocking(move || DomainScorer::load(&dir)).await;
    let mut g = ctx.intel.lock();
    match res {
        Ok(Ok(s)) => {
            tracing::info!(model = s.has_model(), version = ?s.version(), brands = s.brands().len(), "domain model loaded");
            g.scorer = Arc::new(s);
            g.scorer_error = None;
            // New model: names seen before may score differently now.
            g.seen.clear();
        }
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "domain model unusable, rules-only fallback");
            g.scorer = Arc::new(DomainScorer::heuristic_only());
            g.scorer_error = Some(format!("modèle de domaines inutilisable : {e}"));
        }
        Err(e) => tracing::warn!(error = %e, "domain model load task failed"),
    }
}

fn load_domain_state(path: &Path) -> DomainState {
    let Ok(bytes) = std::fs::read(path) else {
        return DomainState::default();
    };
    match serde_json::from_slice::<DomainState>(&bytes) {
        Ok(mut s) => {
            s.flagged.truncate(FLAGGED_MAX);
            while s.ml_blocked.len() > ML_BLOCKED_MAX {
                s.ml_blocked.pop_first();
            }
            s
        }
        Err(e) => {
            tracing::warn!(error = %e, "intel domains state unreadable, starting empty");
            DomainState::default()
        }
    }
}

/// `host` (or a parent) is in the allowlist.
fn allowlisted(host: &str, allow: &[String]) -> bool {
    allow.iter().any(|a| {
        host == a
            || (host.len() > a.len()
                && host.ends_with(a.as_str())
                && host.as_bytes()[host.len() - a.len() - 1] == b'.')
    })
}

/// What to put in the blocklist / allowlist for a host: its registrable domain, or the host itself on a
/// shared platform (never block `github.io`).
fn block_target(host: &str) -> String {
    let sp = suffix::split(host);
    if sp.shared_platform || sp.sld.is_empty() {
        host.to_string()
    } else {
        sp.registrable.to_string()
    }
}

/// Outcome of [`process_name`] (for the caller's follow-up work).
#[derive(Debug, Default, PartialEq)]
struct NameOutcome {
    alert: Option<FlaggedDomain>,
    blocked_now: bool,
}

/// Score one query name (pure state update; alerts / rebuilds are done by the caller).
fn process_name(g: &mut Inner, raw: &str, cfg: &Config, now: i64) -> NameOutcome {
    let mut out = NameOutcome::default();
    let Some(host) = normalize(raw) else {
        return out;
    };
    if let Some(last) = g.seen.get_mut(&host) {
        *last = now;
        if let Some(f) = g.domains.flagged.iter_mut().find(|f| f.domain == host) {
            f.hits = f.hits.saturating_add(1);
            f.last_seen = now;
            g.domains_dirty = true;
        }
        return out;
    }
    if g.rate.0 != now {
        g.rate = (now, 0);
    }
    if g.rate.1 >= SCORE_RATE {
        return out;
    }
    g.rate.1 += 1;
    if g.seen.len() >= SEEN_MAX {
        let mut v: Vec<(String, i64)> = g.seen.drain().collect();
        v.sort_by_key(|e| std::cmp::Reverse(e.1));
        v.truncate(SEEN_MAX / 2);
        g.seen = v.into_iter().collect();
    }
    g.seen.insert(host.clone(), now);
    if allowlisted(&host, &cfg.intelligence.domain_allowlist) {
        return out;
    }
    let verdict = match g.scorer.score(&host) {
        Scored::Skipped(_) => return out,
        Scored::Verdict(v) => v,
    };
    g.scored_total += 1;
    let hour = now / 3600;
    match g.scored_hours.back_mut() {
        Some((h, n)) if *h == hour => *n += 1,
        _ => g.scored_hours.push_back((hour, 1)),
    }
    while g.scored_hours.front().is_some_and(|(h, _)| *h <= hour - 24) {
        g.scored_hours.pop_front();
    }
    if !verdict.flagged {
        return out;
    }
    g.domains.flagged_total += 1;
    g.domains_dirty = true;
    let target = block_target(&verdict.host);
    let block = cfg.intelligence.block_ml_domains
        && verdict.block
        && verdict.source == VerdictSource::Model;
    if block && !g.domains.ml_blocked.contains_key(&target) {
        if g.domains.ml_blocked.len() >= ML_BLOCKED_MAX {
            if let Some(oldest) = g
                .domains
                .ml_blocked
                .iter()
                .min_by_key(|e| *e.1)
                .map(|e| e.0.clone())
            {
                g.domains.ml_blocked.remove(&oldest);
            }
        }
        g.domains.ml_blocked.insert(target.clone(), now);
        g.rebuild_wanted = true;
        out.blocked_now = true;
    }
    let entry = FlaggedDomain {
        domain: verdict.host.clone(),
        registrable: verdict.registrable.clone(),
        score: verdict.score,
        first_seen: now,
        last_seen: now,
        hits: 1,
        reasons: verdict.reasons.clone(),
        blocked: g.domains.ml_blocked.contains_key(&target),
        allowed: false,
        alert_id: None,
    };
    if g.domains.flagged.len() >= FLAGGED_MAX {
        // Drop the lowest-scored oldest entry.
        if let Some(i) = g
            .domains
            .flagged
            .iter()
            .enumerate()
            .min_by(|a, b| {
                a.1.score
                    .partial_cmp(&b.1.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then(a.1.last_seen.cmp(&b.1.last_seen))
            })
            .map(|(i, _)| i)
        {
            g.domains.flagged.remove(i);
        }
    }
    g.domains.flagged.push(entry.clone());
    if cfg.intelligence.domain_alerts {
        out.alert = Some(entry);
    }
    out
}

async fn raise_domain_alert(ctx: &Arc<Ctx>, f: FlaggedDomain) {
    let key = format!("{DOMAIN_KEY}{}", block_target(&f.domain));
    let since = pb_core::now_ts() - ALERT_DEDUPE_SECS;
    let k2 = key.clone();
    if let Ok(Some(_)) = ctx
        .store
        .run(move |s| s.find_recent_alert_by(AlertKind::Network, AlertKey::Title(&k2), since))
        .await
    {
        return;
    }
    if !take_daily(&mut ctx.intel.lock().domain_alerts, DOMAIN_ALERTS_PER_DAY) {
        tracing::info!(domain = %f.domain, "domain alert suppressed (daily cap)");
        return;
    }
    let pct = (f.score * 100.0).round();
    let mut msg = format!(
        "Le modèle de domaines de Parabellum juge {} suspect (score {pct} %). Ce nom n'avait jamais été consulté depuis ce Mac.",
        f.domain
    );
    if !f.reasons.is_empty() {
        msg.push_str("\nIndices : ");
        msg.push_str(&f.reasons.join(" ; "));
        msg.push('.');
    }
    msg.push_str(if f.blocked {
        "\nCe domaine est désormais bloqué par le DNS de Parabellum (blocage ML activé)."
    } else {
        "\nIl n'a pas été bloqué. N'y saisissez aucun mot de passe ni information bancaire."
    });
    let mut a = actions::alert(
        AlertKind::Network,
        if f.blocked || f.score >= 0.98 {
            Severity::High
        } else {
            Severity::Medium
        },
        format!("Domaine suspect : {}", f.domain),
        msg,
    );
    a.actions = vec![AlertAction::AllowDomain, AlertAction::Acknowledge];
    if let Some(saved) = actions::raise_alert(ctx, a, Some(key)).await {
        let mut g = ctx.intel.lock();
        if let Some(e) = g.domains.flagged.iter_mut().find(|e| e.domain == f.domain) {
            e.alert_id = Some(saved.id);
            g.domains_dirty = true;
        }
    }
}

/// Write `dns/ml-blocked.txt` from the state (or remove it when blocking is off) and rebuild the lists.
async fn sync_ml_blocklist(ctx: &Arc<Ctx>) {
    let cfg = ctx.config();
    let (path, lines) = {
        let g = ctx.intel.lock();
        let lines: Vec<String> = if cfg.intelligence.block_ml_domains {
            g.domains
                .ml_blocked
                .keys()
                .filter(|d| !allowlisted(d, &cfg.intelligence.domain_allowlist))
                .cloned()
                .collect()
        } else {
            vec![]
        };
        (ml_blocked_file(ctx), lines)
    };
    let res = tokio::task::spawn_blocking(move || -> std::io::Result<bool> {
        if lines.is_empty() {
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e),
            }
        } else {
            let mut text = String::from(
                "# Domaines bloqués par le modèle de domaines de Parabellum (intelligence)\n",
            );
            for l in &lines {
                text.push_str(l);
                text.push('\n');
            }
            write_atomic(&path, text.as_bytes(), 0o644).map(|_| true)
        }
    })
    .await;
    match res {
        Ok(Ok(changed)) => {
            if changed && cfg.dns.enabled {
                match ctx.backends.dns.rebuild_lists(&cfg).await {
                    Ok(n) => tracing::info!(domains = n, "DNS lists rebuilt (ML blocklist)"),
                    Err(e) => tracing::warn!(error = %e, "DNS rebuild for the ML blocklist failed"),
                }
            }
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "cannot write the ML blocklist"),
        Err(e) => tracing::warn!(error = %e, "ML blocklist task failed"),
    }
}

async fn save_domains(ctx: &Arc<Ctx>) {
    let (bytes, path) = {
        let mut g = ctx.intel.lock();
        if !g.domains_dirty {
            return;
        }
        g.domains_dirty = false;
        (serde_json::to_vec(&g.domains), domains_file(ctx))
    };
    let Ok(bytes) = bytes else { return };
    if let Ok(Err(e)) =
        tokio::task::spawn_blocking(move || write_atomic(&path, &bytes, 0o600)).await
    {
        tracing::warn!(error = %e, "cannot save the intel domains state");
    }
}

/// Domain task: scores query names, raises alerts, maintains the ML blocklist.
pub async fn run_domains(ctx: Arc<Ctx>, mut rx: mpsc::Receiver<String>) {
    let path = domains_file(&ctx);
    let state = tokio::task::spawn_blocking(move || load_domain_state(&path))
        .await
        .unwrap_or_default();
    ctx.intel.lock().domains = state;
    reload_model(&ctx).await;
    let mut shutdown = ctx.shutdown_rx();
    let mut cfg_rx = ctx.config_rx();
    let mut last_block_cfg = ctx.config().intelligence.block_ml_domains;
    let mut next_rebuild: Option<Instant> = None;
    let mut last_rebuild: Option<Instant> = None;
    let mut save_tick = tokio::time::interval(SAVE_EVERY);
    save_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break; },
            r = cfg_rx.changed() => {
                if r.is_err() { break; }
                let block = cfg_rx.borrow_and_update().intelligence.block_ml_domains;
                if block != last_block_cfg {
                    last_block_cfg = block;
                    next_rebuild = Some(Instant::now());
                }
            }
            name = rx.recv() => {
                let Some(name) = name else { break };
                let cfg = ctx.config();
                if !cfg.intelligence.domain_model {
                    continue;
                }
                let out = {
                    let mut g = ctx.intel.lock();
                    process_name(&mut g, &name, &cfg, pb_core::now_ts())
                };
                if out.blocked_now && next_rebuild.is_none() {
                    let earliest = last_rebuild.map(|t| t + REBUILD_MIN_GAP).unwrap_or_else(Instant::now);
                    next_rebuild = Some(earliest.max(Instant::now() + REBUILD_DEBOUNCE));
                }
                if let Some(f) = out.alert {
                    let c = ctx.clone();
                    tokio::spawn(async move { raise_domain_alert(&c, f).await });
                }
            }
            _ = sleep_until_opt(next_rebuild) => {
                next_rebuild = None;
                last_rebuild = Some(Instant::now());
                ctx.intel.lock().rebuild_wanted = false;
                sync_ml_blocklist(&ctx).await;
                save_domains(&ctx).await;
            }
            _ = save_tick.tick() => save_domains(&ctx).await,
        }
    }
    save_domains(&ctx).await;
}

async fn sleep_until_opt(t: Option<Instant>) {
    match t {
        Some(t) => tokio::time::sleep_until(tokio::time::Instant::from_std(t)).await,
        None => std::future::pending().await,
    }
}

/// Score one domain on demand (nothing recorded).
pub fn score_domain(ctx: &Arc<Ctx>, domain: &str) -> Result<DomainVerdictInfo, IpcError> {
    let host = normalize(domain)
        .ok_or_else(|| IpcError::new(ErrorCode::BadRequest, "nom de domaine invalide"))?;
    let cfg = ctx.config();
    let scorer = ctx.intel.lock().scorer.clone();
    let allowed = allowlisted(&host, &cfg.intelligence.domain_allowlist);
    Ok(match scorer.score(&host) {
        Scored::Skipped(why) => DomainVerdictInfo {
            domain: host,
            registrable: None,
            score: None,
            flagged: false,
            would_block: false,
            source: None,
            skipped: Some(why.to_string()),
            reasons: vec![],
            allowed,
        },
        Scored::Verdict(v) => DomainVerdictInfo {
            registrable: Some(v.registrable.clone()),
            score: Some(v.score),
            flagged: v.flagged && !allowed,
            would_block: v.block && !allowed,
            source: Some(match v.source {
                VerdictSource::Model => "model".into(),
                VerdictSource::Heuristic => "heuristic".into(),
            }),
            skipped: None,
            reasons: v.reasons,
            allowed,
            domain: v.host,
        },
    })
}

/// "Autoriser ce domaine": allowlist (config), drop from the ML blocklist, mark flagged entries.
pub async fn allow_domain(ctx: &Arc<Ctx>, domain: &str) -> Result<(), IpcError> {
    let host = normalize(domain)
        .filter(|h| h.contains('.'))
        .ok_or_else(|| IpcError::new(ErrorCode::BadRequest, "nom de domaine invalide"))?;
    let target = block_target(&host);
    let mut cfg = (*ctx.config()).clone();
    if !cfg.intelligence.domain_allowlist.contains(&target) {
        cfg.intelligence.domain_allowlist.push(target.clone());
        cfg.intelligence.domain_allowlist.sort();
        crate::router::set_config(ctx, cfg).await?;
    }
    let removed = {
        let mut g = ctx.intel.lock();
        let before = g.domains.ml_blocked.len();
        g.domains
            .ml_blocked
            .retain(|d, _| !(d == &target || allowlisted(d, std::slice::from_ref(&target))));
        for f in g.domains.flagged.iter_mut() {
            if allowlisted(&f.domain, std::slice::from_ref(&target)) {
                f.allowed = true;
                f.blocked = false;
            }
        }
        g.domains_dirty = true;
        before != g.domains.ml_blocked.len()
    };
    if removed {
        sync_ml_blocklist(ctx).await;
    }
    save_domains(ctx).await;
    let linked: Vec<i64> = ctx
        .intel
        .lock()
        .domains
        .flagged
        .iter()
        .filter(|f| f.allowed)
        .filter_map(|f| f.alert_id)
        .collect();
    for id in linked {
        resolve_linked_alert(ctx, Some(id)).await;
    }
    tracing::info!(domain = %target, "domain allowed for the domain model");
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Behaviour baseline
// ---------------------------------------------------------------------------------------------

fn proc_info(p: &EsProcessInfo) -> ProcInfo {
    ProcInfo {
        path: p.path.clone(),
        team_id: p.team_id.clone(),
        signing_id: p.signing_id.clone(),
        platform: p.is_platform_binary,
        adhoc: p.codesigning_flags & CS_ADHOC != 0,
    }
}

fn local_hour() -> u8 {
    chrono::Local::now().hour() as u8
}

fn wants_behavior(ctx: &Ctx, path: &str) -> bool {
    ctx.config().intelligence.behavior_anomaly && !Path::new(path).starts_with(&ctx.paths.root)
}

/// eslogger `exec` (called by the real-time dispatcher; never blocks).
pub fn on_exec(ctx: &Arc<Ctx>, target: &EsProcessInfo, parent: Option<&EsProcessInfo>) {
    if !wants_behavior(ctx, &target.path) {
        return;
    }
    if let Some(tx) = ctx.intel.behavior_tx.get() {
        let _ = tx.try_send(BehaviorEvent::Exec {
            parent: parent.map(proc_info),
            target: proc_info(target),
            hour: local_hour(),
        });
    }
}

/// eslogger file event with its process (called by the real-time dispatcher; never blocks).
pub fn on_file(ctx: &Arc<Ctx>, path: &str, process: Option<&EsProcessInfo>) {
    let Some(p) = process else { return };
    if !wants_behavior(ctx, &p.path) {
        return;
    }
    if let Some(tx) = ctx.intel.behavior_tx.get() {
        let _ = tx.try_send(BehaviorEvent::File {
            process: proc_info(p),
            path: path.to_string(),
            hour: local_hour(),
        });
    }
}

fn anomaly_kind(k: ObsKind) -> AnomalyKind {
    match k {
        ObsKind::Exec => AnomalyKind::Exec,
        ObsKind::Interpreter => AnomalyKind::Interpreter,
        ObsKind::LaunchedBy => AnomalyKind::LaunchedBy,
        ObsKind::File => AnomalyKind::File,
        ObsKind::Hour => AnomalyKind::Hour,
    }
}

fn to_model(r: &AnomalyRecord) -> BehaviorAnomaly {
    let main = r.main();
    BehaviorAnomaly {
        id: r.id.clone(),
        ts: r.ts,
        process: r.actor_label.clone(),
        kind: main
            .map(|m| anomaly_kind(m.kind))
            .unwrap_or(AnomalyKind::Exec),
        summary: main
            .map(|m| {
                format!(
                    "{} {}",
                    short_name(&r.actor_label),
                    AnomalyRecord::describe(m)
                )
            })
            .unwrap_or_default(),
        details: r.features.iter().map(AnomalyRecord::describe).collect(),
        score: r.score,
        alert_id: r.alert_id,
        marked_normal: r.marked_normal,
    }
}

fn short_name(label: &str) -> &str {
    label.rsplit('/').next().unwrap_or(label)
}

async fn raise_anomaly_alert(
    ctx: &Arc<Ctx>,
    rec: &AnomalyRecord,
    learning_days: u32,
) -> Option<i64> {
    let m = to_model(rec);
    let pct = (rec.score * 100.0).round();
    let mut msg = format!(
        "{} {} (score {pct} %). Parabellum a appris le fonctionnement habituel de ce Mac pendant {learning_days} jour(s) : c'est nouveau pour ce programme.",
        rec.actor_label,
        rec.main().map(AnomalyRecord::describe).unwrap_or_default()
    );
    if m.details.len() > 1 {
        msg.push_str("\nÉgalement : ");
        msg.push_str(&m.details[1..].join(" ; "));
        msg.push('.');
    }
    msg.push_str("\nSi c'est attendu (mise à jour, nouvel outil, script à vous), choisissez « C'est normal » : ce comportement sera ajouté à la référence.");
    let mut a = actions::alert(
        AlertKind::Behavior,
        if rec.score >= 0.9 {
            Severity::Medium
        } else {
            Severity::Low
        },
        format!("Comportement inhabituel : {}", short_name(&rec.actor_label)),
        msg,
    );
    a.process_path = Some(rec.actor_label.clone());
    a.actions = vec![AlertAction::MarkNormal, AlertAction::Acknowledge];
    actions::raise_alert(ctx, a, Some(format!("{ANOMALY_KEY}{}", rec.id)))
        .await
        .map(|a| a.id)
}

async fn save_baseline(ctx: &Arc<Ctx>, force: bool) {
    let (b, path) = {
        let mut g = ctx.intel.lock();
        if !(g.baseline_dirty || force) {
            return;
        }
        let Some(b) = g.baseline.clone() else { return };
        g.baseline_dirty = false;
        (b, baseline_file(ctx))
    };
    let res = tokio::task::spawn_blocking(move || {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        b.save(&path)
    })
    .await;
    match res {
        Ok(Ok(n)) => ctx.intel.lock().baseline_bytes = n,
        Ok(Err(e)) => tracing::warn!(error = %e, "cannot save the behaviour baseline"),
        Err(e) => tracing::warn!(error = %e, "baseline save task failed"),
    }
}

/// Behaviour task: feeds the baseline, alerts on novelties, saves periodically.
pub async fn run_behavior(ctx: Arc<Ctx>, mut rx: mpsc::Receiver<BehaviorEvent>) {
    let path = baseline_file(&ctx);
    let loaded = tokio::task::spawn_blocking(move || {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        (Baseline::load(&path), size)
    })
    .await;
    {
        let mut g = ctx.intel.lock();
        match loaded {
            Ok((Ok(Some(b)), size)) => {
                g.baseline = Some(b);
                g.baseline_bytes = size;
            }
            Ok((Ok(None), _)) => {}
            Ok((Err(e), _)) => {
                tracing::warn!(error = %e, "behaviour baseline unreadable: learning again");
                g.baseline_error = Some(format!("référence illisible, nouvel apprentissage : {e}"));
            }
            Err(e) => tracing::warn!(error = %e, "baseline load task failed"),
        }
    }
    let mut shutdown = ctx.shutdown_rx();
    let mut save_tick = tokio::time::interval(SAVE_EVERY);
    save_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            r = shutdown.changed() => if r.is_err() || *shutdown.borrow() { break; },
            _ = save_tick.tick() => save_baseline(&ctx, false).await,
            ev = rx.recv() => {
                let Some(ev) = ev else { break };
                let cfg = ctx.config();
                let ic = &cfg.intelligence;
                if !ic.behavior_anomaly {
                    continue;
                }
                let now = pb_core::now_ts();
                let found: Vec<AnomalyRecord> = {
                    let mut g = ctx.intel.lock();
                    let b = g.baseline.get_or_insert_with(|| Baseline::new(now));
                    let recs = b.observe(&ev, now, ic.learning_days);
                    g.baseline_dirty = true;
                    let mut keep = Vec::new();
                    for r in recs {
                        if r.score < ic.anomaly_threshold {
                            continue;
                        }
                        g.anomaly_alerted.retain(|_, t| now - *t < ALERT_DEDUPE_SECS);
                        if g.anomaly_alerted.contains_key(&r.id) {
                            continue;
                        }
                        g.anomaly_alerted.insert(r.id.clone(), now);
                        keep.push(r);
                    }
                    keep
                };
                for mut rec in found {
                    let paused = ctx.is_paused(now);
                    let allowed = !paused
                        && take_daily(&mut ctx.intel.lock().anomaly_alerts, ic.max_anomaly_alerts_per_day);
                    if allowed {
                        rec.alert_id = raise_anomaly_alert(&ctx, &rec, ic.learning_days).await;
                    } else {
                        tracing::info!(id = %rec.id, score = rec.score, "anomaly recorded without alert (cap / pause)");
                    }
                    let mut g = ctx.intel.lock();
                    if let Some(b) = g.baseline.as_mut() {
                        b.remember(rec);
                    }
                }
            }
        }
    }
    save_baseline(&ctx, false).await;
}

/// "C'est normal" (from the Intelligence view or an alert).
pub async fn mark_normal(ctx: &Arc<Ctx>, anomaly_id: &str) -> Result<Option<i64>, IpcError> {
    let alert_id = {
        let mut g = ctx.intel.lock();
        let b = g.baseline.as_mut().ok_or_else(|| {
            IpcError::new(ErrorCode::NotFound, "aucune référence comportementale")
        })?;
        if !b.mark_normal(anomaly_id, pb_core::now_ts()) {
            return Err(IpcError::new(
                ErrorCode::NotFound,
                format!("anomalie {anomaly_id} inconnue"),
            ));
        }
        g.baseline_dirty = true;
        g.baseline.as_ref().and_then(|b| {
            b.recent()
                .find(|r| r.id == anomaly_id)
                .and_then(|r| r.alert_id)
        })
    };
    save_baseline(ctx, false).await;
    Ok(alert_id)
}

/// Forget everything and start a new learning period.
pub async fn reset_baseline(ctx: &Arc<Ctx>) {
    {
        let mut g = ctx.intel.lock();
        g.baseline = Some(Baseline::new(pb_core::now_ts()));
        g.baseline_dirty = true;
        g.baseline_error = None;
        g.anomaly_alerted.clear();
    }
    save_baseline(ctx, true).await;
    tracing::warn!("behaviour baseline reset: new learning period");
}

// ---------------------------------------------------------------------------------------------
// IPC
// ---------------------------------------------------------------------------------------------

fn numeric_metrics(v: &serde_json::Value) -> BTreeMap<String, f64> {
    v.as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_f64().map(|f| (k.clone(), f)))
                .collect()
        })
        .unwrap_or_default()
}

/// `intel_status`.
pub fn status(ctx: &Arc<Ctx>) -> IntelligenceStatus {
    let cfg = ctx.config();
    let ic = &cfg.intelligence;
    let now = pb_core::now_ts();
    let g = ctx.intel.lock();
    let behavior = {
        let mut st = BehaviorStatus {
            enabled: ic.behavior_anomaly,
            learning: true,
            baseline_bytes: g.baseline_bytes,
            message: g.baseline_error.clone(),
            ..Default::default()
        };
        if let Some(b) = &g.baseline {
            let s = b.stats();
            st.learning = b.is_learning(now, ic.learning_days);
            st.learning_progress = b.progress(now, ic.learning_days);
            st.learning_started_at = Some(b.started_at());
            st.learning_until = Some(b.learning_until(ic.learning_days));
            st.events_observed = s.events;
            st.profiles = s.actors;
            st.behaviors = s.features;
            st.anomalies_24h = b.recent().filter(|r| now - r.ts < 86_400).count() as u32;
            st.anomalies_7d = b.recent().filter(|r| now - r.ts < 7 * 86_400).count() as u32;
            st.recent_anomalies = b.recent().take(50).map(to_model).collect();
        } else if ic.behavior_anomaly && st.message.is_none() {
            st.message = Some(
                "En attente des premiers événements eslogger (accès complet au disque requis)"
                    .into(),
            );
        }
        st
    };
    let mut top = g.domains.flagged.clone();
    top.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.last_seen.cmp(&a.last_seen))
    });
    top.truncate(50);
    let scorer = g.scorer.clone();
    let domains = DomainIntelStatus {
        enabled: ic.domain_model,
        dns_active: cfg.dns.enabled,
        model_loaded: scorer.has_model(),
        block_enabled: ic.block_ml_domains,
        alert_threshold: scorer.threshold(),
        block_threshold: if scorer.block_threshold().is_finite() {
            scorer.block_threshold()
        } else {
            1.0
        },
        scored_total: g.scored_total,
        scored_24h: g.scored_hours.iter().map(|(_, n)| *n).sum(),
        flagged_total: g.domains.flagged_total,
        blocked_count: if ic.block_ml_domains {
            g.domains.ml_blocked.len() as u32
        } else {
            0
        },
        top_flagged: top,
        message: if !cfg.dns.enabled && ic.domain_model {
            Some("Activez le blocage DNS : les domaines consultés passent alors par Parabellum et peuvent être analysés.".into())
        } else if let Some(e) = &g.scorer_error {
            Some(e.clone())
        } else if !scorer.has_model() {
            Some("Modèle pas encore publié : règles de secours (marques imitées) seulement, sans blocage.".into())
        } else {
            None
        },
    };
    let models = vec![
        IntelModelInfo {
            id: "domain".into(),
            name: "Domaines (hameçonnage, typosquatting)".into(),
            loaded: scorer.has_model(),
            version: scorer.version().map(str::to_string),
            threshold: scorer.has_model().then(|| scorer.threshold()),
            metrics: numeric_metrics(scorer.metrics()),
            detail: Some(format!(
                "LightGBM sur {} caractéristiques lexicales, {} marques surveillées",
                pb_intel::domain::feature_names().len(),
                scorer.brands().len()
            )),
        },
        IntelModelInfo {
            id: "behavior".into(),
            name: "Comportement (appris sur ce Mac)".into(),
            loaded: ic.behavior_anomaly && g.baseline.is_some(),
            version: None,
            threshold: Some(ic.anomaly_threshold),
            metrics: BTreeMap::new(),
            detail: Some(
                "Profils par exécutable, nouveautés notées localement ; rien ne quitte le Mac"
                    .into(),
            ),
        },
        // TODO(integration): append the Mach-O and script model entries (ml-files worker).
    ];
    IntelligenceStatus {
        behavior,
        domains,
        models,
    }
}

/// Subject of an intelligence alert (`intel-domain:<d>` / `intel-anomaly:<id>`).
async fn alert_subject(ctx: &Arc<Ctx>, alert_id: i64, prefix: &str) -> Result<String, IpcError> {
    let key = ctx
        .store
        .run(move |s| s.alert_detection(alert_id))
        .await?
        .unwrap_or_default();
    key.strip_prefix(prefix)
        .map(str::to_string)
        .ok_or_else(|| IpcError::new(ErrorCode::BadRequest, "alerte sans sujet d'intelligence"))
}

/// `resolve_alert` with `allow_domain` / `mark_normal`.
pub async fn resolve_alert_action(
    ctx: &Arc<Ctx>,
    alert: &mut Alert,
    action: AlertAction,
) -> Result<(), IpcError> {
    match action {
        AlertAction::AllowDomain => {
            let d = alert_subject(ctx, alert.id, DOMAIN_KEY).await?;
            allow_domain(ctx, &d).await?;
            alert.message.push_str(&format!(
                "\n{d} est autorisé : le modèle ne le signalera plus."
            ));
        }
        AlertAction::MarkNormal => {
            let id = alert_subject(ctx, alert.id, ANOMALY_KEY).await?;
            mark_normal(ctx, &id).await?;
            alert
                .message
                .push_str("\nAjouté à la référence : ce comportement ne sera plus signalé.");
        }
        _ => return Err(IpcError::new(ErrorCode::BadRequest, "action inconnue")),
    }
    alert.status = AlertStatus::Resolved;
    alert.actions.clear();
    Ok(())
}

/// After `intel_mark_normal` from the view: resolve the linked alert too.
pub async fn resolve_linked_alert(ctx: &Arc<Ctx>, alert_id: Option<i64>) {
    let Some(id) = alert_id else { return };
    if let Ok(Some(mut a)) = ctx.store.run(move |s| s.get_alert(id)).await {
        if a.status != AlertStatus::Resolved {
            a.status = AlertStatus::Resolved;
            a.actions.clear();
            let _ = actions::save_alert(ctx, &a).await;
        }
    }
}

#[cfg(test)]
mod tests;
