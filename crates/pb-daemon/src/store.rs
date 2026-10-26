//! SQLite persistence (`state/parabellum.sqlite`).
//!
//! One connection behind a `Mutex`, WAL journal, `busy_timeout`, versioned migrations. All methods are
//! synchronous; async code calls them through [`Store::run`] (which uses `spawn_blocking`) so the
//! tokio workers never block on disk I/O.
//!
//! Rich objects (alerts, jobs, findings, devices, persistence items, update results) are stored as JSON
//! next to the few columns we filter or sort on.

use pb_core::model::*;
use rusqlite::{params, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// Store errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("store task failed: {0}")]
    Task(String),
}

/// Result alias for store operations.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Max findings returned by [`Store::get_job`] (a scan of a malware corpus could produce many).
pub const MAX_FINDINGS_RETURNED: u32 = 5_000;
/// Hard cap on `file_history` rows (oldest `last_seen` pruned first).
pub const FILE_HISTORY_CAP: i64 = 200_000;

const MIGRATIONS: &[(i64, &str)] = &[(
    1,
    r#"
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    path TEXT,
    sha256 TEXT,
    device_id TEXT,
    persistence_id TEXT,
    quarantine_id TEXT,
    detection TEXT,
    json TEXT NOT NULL
);
CREATE INDEX alerts_status_ts ON alerts(status, ts);
CREATE INDEX alerts_sha_path ON alerts(sha256, path);
CREATE INDEX alerts_quarantine ON alerts(quarantine_id);
CREATE INDEX alerts_kind_ts ON alerts(kind, ts);

CREATE TABLE scan_jobs (
    job_id TEXT PRIMARY KEY,
    origin TEXT NOT NULL,
    state TEXT NOT NULL,
    started_at INTEGER NOT NULL,
    finished_at INTEGER,
    json TEXT NOT NULL
);
CREATE INDEX scan_jobs_started ON scan_jobs(started_at);

CREATE TABLE scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES scan_jobs(job_id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    verdict TEXT NOT NULL,
    json TEXT NOT NULL
);
CREATE INDEX scan_findings_job ON scan_findings(job_id);

CREATE TABLE file_history (
    path TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    mtime INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    verdict TEXT NOT NULL
);
CREATE INDEX file_history_last_seen ON file_history(last_seen);
CREATE INDEX file_history_sha ON file_history(sha256);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    trust TEXT NOT NULL,
    baseline INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    json TEXT NOT NULL
);

CREATE TABLE persistence (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    last_seen INTEGER NOT NULL,
    json TEXT NOT NULL
);

CREATE TABLE local_allowlist (
    sha256 TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    added_at INTEGER NOT NULL
);

CREATE TABLE local_blocklist (
    sha256 TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    added_at INTEGER NOT NULL
);

CREATE TABLE false_positives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    path TEXT,
    note TEXT
);
CREATE INDEX false_positives_ts ON false_positives(ts);

CREATE TABLE daily_stats (
    date TEXT PRIMARY KEY,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    threats INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0,
    dns_blocked INTEGER NOT NULL DEFAULT 0,
    persistence_new INTEGER NOT NULL DEFAULT 0,
    devices_new INTEGER NOT NULL DEFAULT 0,
    false_positives INTEGER NOT NULL DEFAULT 0,
    db_updates INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE update_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    target TEXT NOT NULL,
    ok INTEGER NOT NULL,
    new_db_version TEXT,
    json TEXT NOT NULL
);
CREATE INDEX update_log_ts ON update_log(ts);

CREATE TABLE osquery_seen (
    row_hash TEXT PRIMARY KEY,
    query TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);

CREATE TABLE kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#,
)];

/// Counters kept per local day in `daily_stats`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatField {
    FilesScanned,
    Threats,
    Quarantined,
    DnsBlocked,
    PersistenceNew,
    DevicesNew,
    FalsePositives,
    DbUpdates,
}

impl StatField {
    fn column(self) -> &'static str {
        match self {
            StatField::FilesScanned => "files_scanned",
            StatField::Threats => "threats",
            StatField::Quarantined => "quarantined",
            StatField::DnsBlocked => "dns_blocked",
            StatField::PersistenceNew => "persistence_new",
            StatField::DevicesNew => "devices_new",
            StatField::FalsePositives => "false_positives",
            StatField::DbUpdates => "db_updates",
        }
    }
}

/// Sums of `daily_stats` over a date range.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DailyTotals {
    pub files_scanned: u64,
    pub threats: u64,
    pub quarantined: u64,
    pub dns_blocked: u64,
    pub persistence_new: u64,
    pub devices_new: u64,
    pub false_positives: u64,
    pub db_updates: u64,
    /// Number of days that had a row.
    pub days: u64,
}

/// One `file_history` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRecord {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub mtime: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub verdict: Verdict,
}

/// Local allowlist / blocklist entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashListEntry {
    pub sha256: String,
    pub name: String,
    pub source: String,
    pub added_at: i64,
}

/// Cloneable handle to the SQLite database.
#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

/// Serialize a unit enum to its snake_case JSON string.
pub(crate) fn enum_str<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        Ok(other) => other.to_string(),
        Err(_) => String::new(),
    }
}

/// Parse a snake_case enum string.
pub(crate) fn parse_enum<T: DeserializeOwned>(s: &str) -> Option<T> {
    serde_json::from_value(serde_json::Value::String(s.to_string())).ok()
}

fn from_json<T: DeserializeOwned>(s: &str) -> rusqlite::Result<T> {
    serde_json::from_str(s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

impl Store {
    /// Open (or create) the database file and apply migrations.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::init(conn)
    }

    /// In-memory database (tests).
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        // `journal_mode` returns a row; in-memory databases answer "memory".
        let _mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        conn.execute_batch(
            "PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;",
        )?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);",
        )?;
        let current: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )?;
        for (version, sql) in MIGRATIONS {
            if *version <= current {
                continue;
            }
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?1, ?2)",
                params![version, pb_core::now_ts()],
            )?;
            tx.commit()?;
            tracing::info!(version, "store migration applied");
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run `f` on a blocking thread (for async callers).
    pub async fn run<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Store) -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let s = self.clone();
        tokio::task::spawn_blocking(move || f(&s))
            .await
            .map_err(|e| StoreError::Task(e.to_string()))?
    }

    /// Current schema version.
    pub fn schema_version(&self) -> Result<i64> {
        Ok(self.lock().query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |r| r.get(0),
        )?)
    }

    // -----------------------------------------------------------------------------------------
    // kv
    // -----------------------------------------------------------------------------------------

    pub fn kv_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .lock()
            .query_row("SELECT value FROM kv WHERE key = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        self.lock().execute(
            "INSERT INTO kv(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn kv_delete(&self, key: &str) -> Result<()> {
        self.lock()
            .execute("DELETE FROM kv WHERE key = ?1", [key])?;
        Ok(())
    }

    pub fn kv_get_i64(&self, key: &str) -> Result<Option<i64>> {
        Ok(self.kv_get(key)?.and_then(|v| v.parse().ok()))
    }

    // -----------------------------------------------------------------------------------------
    // alerts
    // -----------------------------------------------------------------------------------------

    /// Insert an alert; returns it with its row id. `detection` = main detection name (weekly top list).
    pub fn insert_alert(&self, alert: &Alert, detection: Option<&str>) -> Result<Alert> {
        let conn = self.lock();
        let mut a = alert.clone();
        a.id = 0;
        conn.execute(
            "INSERT INTO alerts(ts, kind, severity, status, path, sha256, device_id, persistence_id, quarantine_id, detection, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, '{}')",
            params![
                a.ts,
                enum_str(&a.kind),
                enum_str(&a.severity),
                enum_str(&a.status),
                a.path,
                a.sha256,
                a.device_id,
                a.persistence_id,
                a.quarantine_id,
                detection
            ],
        )?;
        a.id = conn.last_insert_rowid();
        conn.execute(
            "UPDATE alerts SET json = ?1 WHERE id = ?2",
            params![serde_json::to_string(&a)?, a.id],
        )?;
        Ok(a)
    }

    /// Replace an existing alert (by id).
    pub fn update_alert(&self, a: &Alert) -> Result<()> {
        self.lock().execute(
            "UPDATE alerts SET ts = ?2, kind = ?3, severity = ?4, status = ?5, path = ?6, sha256 = ?7, device_id = ?8,
             persistence_id = ?9, quarantine_id = ?10, json = ?11 WHERE id = ?1",
            params![
                a.id,
                a.ts,
                enum_str(&a.kind),
                enum_str(&a.severity),
                enum_str(&a.status),
                a.path,
                a.sha256,
                a.device_id,
                a.persistence_id,
                a.quarantine_id,
                serde_json::to_string(a)?
            ],
        )?;
        Ok(())
    }

    pub fn get_alert(&self, id: i64) -> Result<Option<Alert>> {
        let conn = self.lock();
        let json: Option<String> = conn
            .query_row("SELECT json FROM alerts WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        Ok(match json {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    /// Newest first.
    pub fn list_alerts(&self, limit: u32, include_resolved: bool) -> Result<Vec<Alert>> {
        let conn = self.lock();
        let sql = if include_resolved {
            "SELECT json FROM alerts ORDER BY ts DESC, id DESC LIMIT ?1"
        } else {
            "SELECT json FROM alerts WHERE status != 'resolved' ORDER BY ts DESC, id DESC LIMIT ?1"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([limit.min(10_000)], |r| {
            from_json::<Alert>(&r.get::<_, String>(0)?)
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Most recent alert with the same sha256 + path since `since` (dedupe).
    pub fn find_recent_alert(&self, sha256: &str, path: &str, since: i64) -> Result<Option<Alert>> {
        let conn = self.lock();
        let json: Option<String> = conn
            .query_row(
                "SELECT json FROM alerts WHERE sha256 = ?1 AND path = ?2 AND ts >= ?3 ORDER BY ts DESC, id DESC LIMIT 1",
                params![sha256, path, since],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match json {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    /// Most recent alert of `kind` matching an optional key column, since `since`.
    pub fn find_recent_alert_by(
        &self,
        kind: AlertKind,
        key: AlertKey<'_>,
        since: i64,
    ) -> Result<Option<Alert>> {
        let conn = self.lock();
        let (col, val) = match key {
            AlertKey::Device(d) => ("device_id", Some(d)),
            AlertKey::Persistence(p) => ("persistence_id", Some(p)),
            AlertKey::Title(t) => ("detection", Some(t)),
            AlertKey::None => ("id", None),
        };
        let json: Option<String> = match val {
            Some(v) => conn
                .query_row(
                    &format!(
                        "SELECT json FROM alerts WHERE kind = ?1 AND {col} = ?2 AND ts >= ?3 ORDER BY ts DESC, id DESC LIMIT 1"
                    ),
                    params![enum_str(&kind), v, since],
                    |r| r.get(0),
                )
                .optional()?,
            None => conn
                .query_row(
                    "SELECT json FROM alerts WHERE kind = ?1 AND ts >= ?2 ORDER BY ts DESC, id DESC LIMIT 1",
                    params![enum_str(&kind), since],
                    |r| r.get(0),
                )
                .optional()?,
        };
        Ok(match json {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    /// Alerts referring to a quarantine entry.
    pub fn alerts_by_quarantine(&self, quarantine_id: &str) -> Result<Vec<Alert>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT json FROM alerts WHERE quarantine_id = ?1 ORDER BY id")?;
        let rows = stmt.query_map([quarantine_id], |r| {
            from_json::<Alert>(&r.get::<_, String>(0)?)
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Open alerts referring to a persistence item / device.
    pub fn open_alerts_by(&self, key: AlertKey<'_>) -> Result<Vec<Alert>> {
        let conn = self.lock();
        let (col, val) = match key {
            AlertKey::Device(d) => ("device_id", d),
            AlertKey::Persistence(p) => ("persistence_id", p),
            AlertKey::Title(t) => ("detection", t),
            AlertKey::None => return Ok(vec![]),
        };
        let mut stmt = conn.prepare(&format!(
            "SELECT json FROM alerts WHERE {col} = ?1 AND status != 'resolved' ORDER BY id"
        ))?;
        let rows = stmt.query_map([val], |r| from_json::<Alert>(&r.get::<_, String>(0)?))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn count_open_alerts(&self) -> Result<u32> {
        let n: i64 = self.lock().query_row(
            "SELECT COUNT(*) FROM alerts WHERE status = 'open'",
            [],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u32)
    }

    /// Count alerts of `kind` in `[from, to)`.
    pub fn count_alerts(&self, kind: AlertKind, from: i64, to: i64) -> Result<u64> {
        let n: i64 = self.lock().query_row(
            "SELECT COUNT(*) FROM alerts WHERE kind = ?1 AND ts >= ?2 AND ts < ?3",
            params![enum_str(&kind), from, to],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    /// Most frequent detection names of malware/suspicious alerts in `[from, to)`.
    pub fn top_detections(&self, from: i64, to: i64, limit: u32) -> Result<Vec<NamedCount>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT detection, COUNT(*) AS c FROM alerts
             WHERE kind IN ('malware', 'suspicious') AND detection IS NOT NULL AND ts >= ?1 AND ts < ?2
             GROUP BY detection ORDER BY c DESC, detection ASC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![from, to, limit], |r| {
            Ok(NamedCount {
                name: r.get(0)?,
                count: r.get::<_, i64>(1)?.max(0) as u64,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // -----------------------------------------------------------------------------------------
    // scan jobs
    // -----------------------------------------------------------------------------------------

    pub fn upsert_job(&self, j: &ScanJobSummary) -> Result<()> {
        self.lock().execute(
            "INSERT INTO scan_jobs(job_id, origin, state, started_at, finished_at, json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(job_id) DO UPDATE SET state = excluded.state, started_at = excluded.started_at,
             finished_at = excluded.finished_at, json = excluded.json",
            params![
                j.job_id,
                enum_str(&j.origin),
                enum_str(&j.state),
                j.started_at,
                j.finished_at,
                serde_json::to_string(j)?
            ],
        )?;
        Ok(())
    }

    pub fn add_finding(&self, job_id: &str, r: &ScanReport) -> Result<()> {
        self.lock().execute(
            "INSERT INTO scan_findings(job_id, path, verdict, json) VALUES (?1, ?2, ?3, ?4)",
            params![
                job_id,
                r.path,
                enum_str(&r.verdict),
                serde_json::to_string(r)?
            ],
        )?;
        Ok(())
    }

    /// Newest first.
    pub fn list_jobs(&self, limit: u32) -> Result<Vec<ScanJobSummary>> {
        let conn = self.lock();
        let mut stmt = conn
            .prepare("SELECT json FROM scan_jobs ORDER BY started_at DESC, rowid DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit.min(10_000)], |r| {
            from_json::<ScanJobSummary>(&r.get::<_, String>(0)?)
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_job_summary(&self, job_id: &str) -> Result<Option<ScanJobSummary>> {
        let conn = self.lock();
        let json: Option<String> = conn
            .query_row(
                "SELECT json FROM scan_jobs WHERE job_id = ?1",
                [job_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match json {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    pub fn get_findings(&self, job_id: &str, limit: u32) -> Result<Vec<ScanReport>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT json FROM scan_findings WHERE job_id = ?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![job_id, limit], |r| {
            from_json::<ScanReport>(&r.get::<_, String>(0)?)
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_job(&self, job_id: &str) -> Result<Option<ScanJobDetail>> {
        let Some(summary) = self.get_job_summary(job_id)? else {
            return Ok(None);
        };
        let findings = self.get_findings(job_id, MAX_FINDINGS_RETURNED)?;
        Ok(Some(ScanJobDetail { summary, findings }))
    }

    /// Mark jobs left `queued`/`running` by a previous daemon instance as failed. Returns how many.
    pub fn fail_interrupted_jobs(&self, now: i64) -> Result<usize> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT json FROM scan_jobs WHERE state IN ('queued', 'running')")?;
        let jobs = stmt
            .query_map([], |r| from_json::<ScanJobSummary>(&r.get::<_, String>(0)?))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        for mut j in jobs.iter().cloned() {
            j.state = JobState::Failed;
            j.finished_at = Some(now);
            j.current_path = None;
            conn.execute(
                "UPDATE scan_jobs SET state = 'failed', finished_at = ?2, json = ?3 WHERE job_id = ?1",
                params![j.job_id, now, serde_json::to_string(&j)?],
            )?;
        }
        Ok(jobs.len())
    }

    /// `finished_at` of the most recent finished job.
    pub fn last_scan_finished(&self) -> Result<Option<i64>> {
        Ok(self.lock().query_row(
            "SELECT MAX(finished_at) FROM scan_jobs WHERE state = 'finished'",
            [],
            |r| r.get::<_, Option<i64>>(0),
        )?)
    }

    // -----------------------------------------------------------------------------------------
    // file history
    // -----------------------------------------------------------------------------------------

    pub fn record_file(
        &self,
        path: &str,
        sha256: &str,
        size: u64,
        mtime: i64,
        verdict: Verdict,
        now: i64,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO file_history(path, sha256, size, mtime, first_seen, last_seen, verdict)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
             ON CONFLICT(path) DO UPDATE SET
                first_seen = CASE WHEN file_history.sha256 = excluded.sha256 THEN file_history.first_seen ELSE excluded.first_seen END,
                sha256 = excluded.sha256, size = excluded.size, mtime = excluded.mtime,
                last_seen = excluded.last_seen, verdict = excluded.verdict",
            params![path, sha256, size as i64, mtime, now, enum_str(&verdict)],
        )?;
        Ok(())
    }

    /// Files seen since `since`, most recent first.
    pub fn files_seen_since(&self, since: i64, limit: u32) -> Result<Vec<FileRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT path, sha256, size, mtime, first_seen, last_seen, verdict FROM file_history
             WHERE last_seen >= ?1 ORDER BY last_seen DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![since, limit], |r| {
            Ok(FileRecord {
                path: r.get(0)?,
                sha256: r.get(1)?,
                size: r.get::<_, i64>(2)?.max(0) as u64,
                mtime: r.get(3)?,
                first_seen: r.get(4)?,
                last_seen: r.get(5)?,
                verdict: parse_enum(&r.get::<_, String>(6)?).unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // -----------------------------------------------------------------------------------------
    // devices
    // -----------------------------------------------------------------------------------------

    pub fn upsert_device(&self, d: &DeviceInfo) -> Result<()> {
        self.lock().execute(
            "INSERT INTO devices(id, kind, trust, baseline, last_seen, json) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, trust = excluded.trust, baseline = excluded.baseline,
             last_seen = excluded.last_seen, json = excluded.json",
            params![d.id, enum_str(&d.kind), enum_str(&d.trust), d.baseline, d.last_seen, serde_json::to_string(d)?],
        )?;
        Ok(())
    }

    pub fn get_device(&self, id: &str) -> Result<Option<DeviceInfo>> {
        let conn = self.lock();
        let json: Option<String> = conn
            .query_row("SELECT json FROM devices WHERE id = ?1", [id], |r| r.get(0))
            .optional()?;
        Ok(match json {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    /// Most recently seen first.
    pub fn list_devices(&self, kind: Option<DeviceKind>) -> Result<Vec<DeviceInfo>> {
        let conn = self.lock();
        let rows = match kind {
            Some(k) => {
                let mut stmt = conn
                    .prepare("SELECT json FROM devices WHERE kind = ?1 ORDER BY last_seen DESC")?;
                let v = stmt
                    .query_map([enum_str(&k)], |r| {
                        from_json::<DeviceInfo>(&r.get::<_, String>(0)?)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                v
            }
            None => {
                let mut stmt = conn.prepare("SELECT json FROM devices ORDER BY last_seen DESC")?;
                let v = stmt
                    .query_map([], |r| from_json::<DeviceInfo>(&r.get::<_, String>(0)?))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                v
            }
        };
        Ok(rows)
    }

    // -----------------------------------------------------------------------------------------
    // persistence
    // -----------------------------------------------------------------------------------------

    pub fn upsert_persistence(&self, p: &PersistenceItem) -> Result<()> {
        self.lock().execute(
            "INSERT INTO persistence(id, kind, status, last_seen, json) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, status = excluded.status,
             last_seen = excluded.last_seen, json = excluded.json",
            params![
                p.id,
                enum_str(&p.kind),
                enum_str(&p.status),
                p.last_seen,
                serde_json::to_string(p)?
            ],
        )?;
        Ok(())
    }

    pub fn get_persistence(&self, id: &str) -> Result<Option<PersistenceItem>> {
        let conn = self.lock();
        let json: Option<String> = conn
            .query_row("SELECT json FROM persistence WHERE id = ?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(match json {
            Some(j) => Some(serde_json::from_str(&j)?),
            None => None,
        })
    }

    pub fn list_persistence(&self, only_new: bool) -> Result<Vec<PersistenceItem>> {
        let conn = self.lock();
        let sql = if only_new {
            "SELECT json FROM persistence WHERE status = 'new' ORDER BY last_seen DESC"
        } else {
            "SELECT json FROM persistence ORDER BY last_seen DESC"
        };
        let mut stmt = conn.prepare(sql)?;
        let rows = stmt.query_map([], |r| {
            from_json::<PersistenceItem>(&r.get::<_, String>(0)?)
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn count_persistence(&self) -> Result<u64> {
        let n: i64 = self
            .lock()
            .query_row("SELECT COUNT(*) FROM persistence", [], |r| r.get(0))?;
        Ok(n.max(0) as u64)
    }

    // -----------------------------------------------------------------------------------------
    // allow / block lists, false positives
    // -----------------------------------------------------------------------------------------

    pub fn allowlist_add(&self, sha256: &str, reason: &str, now: i64) -> Result<()> {
        self.lock().execute(
            "INSERT INTO local_allowlist(sha256, reason, added_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(sha256) DO UPDATE SET reason = excluded.reason",
            params![sha256.to_ascii_lowercase(), reason, now],
        )?;
        Ok(())
    }

    pub fn allowlist_contains(&self, sha256: &str) -> Result<bool> {
        let n: i64 = self.lock().query_row(
            "SELECT COUNT(*) FROM local_allowlist WHERE sha256 = ?1",
            [sha256.to_ascii_lowercase()],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Every locally allowed hash (pushed into the engine).
    pub fn allowlist_all(&self) -> Result<Vec<String>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT sha256 FROM local_allowlist ORDER BY added_at LIMIT 1000000")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn allowlist_remove(&self, sha256: &str) -> Result<bool> {
        let n = self.lock().execute(
            "DELETE FROM local_allowlist WHERE sha256 = ?1",
            [sha256.to_ascii_lowercase()],
        )?;
        Ok(n > 0)
    }

    pub fn blocklist_add(&self, sha256: &str, name: &str, source: &str, now: i64) -> Result<()> {
        self.lock().execute(
            "INSERT INTO local_blocklist(sha256, name, source, added_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(sha256) DO UPDATE SET name = excluded.name, source = excluded.source",
            params![sha256.to_ascii_lowercase(), name, source, now],
        )?;
        Ok(())
    }

    pub fn blocklist_get(&self, sha256: &str) -> Result<Option<HashListEntry>> {
        Ok(self
            .lock()
            .query_row(
                "SELECT sha256, name, source, added_at FROM local_blocklist WHERE sha256 = ?1",
                [sha256.to_ascii_lowercase()],
                |r| {
                    Ok(HashListEntry {
                        sha256: r.get(0)?,
                        name: r.get(1)?,
                        source: r.get(2)?,
                        added_at: r.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn add_false_positive(
        &self,
        sha256: &str,
        path: Option<&str>,
        note: Option<&str>,
        now: i64,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO false_positives(ts, sha256, path, note) VALUES (?1, ?2, ?3, ?4)",
            params![now, sha256.to_ascii_lowercase(), path, note],
        )?;
        Ok(())
    }

    pub fn count_false_positives(&self, from: i64, to: i64) -> Result<u64> {
        let n: i64 = self.lock().query_row(
            "SELECT COUNT(*) FROM false_positives WHERE ts >= ?1 AND ts < ?2",
            params![from, to],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    // -----------------------------------------------------------------------------------------
    // daily stats
    // -----------------------------------------------------------------------------------------

    /// Add `n` to a counter of day `date` (`YYYY-MM-DD`, local time).
    pub fn bump_daily(&self, date: &str, field: StatField, n: u64) -> Result<()> {
        if n == 0 {
            return Ok(());
        }
        let col = field.column();
        self.lock().execute(
            &format!(
                "INSERT INTO daily_stats(date, {col}) VALUES (?1, ?2)
                 ON CONFLICT(date) DO UPDATE SET {col} = {col} + excluded.{col}"
            ),
            params![date, n as i64],
        )?;
        Ok(())
    }

    /// Raise a counter of day `date` to at least `value` (used for rolling counters such as DNS blocks).
    pub fn max_daily(&self, date: &str, field: StatField, value: u64) -> Result<()> {
        let col = field.column();
        self.lock().execute(
            &format!(
                "INSERT INTO daily_stats(date, {col}) VALUES (?1, ?2)
                 ON CONFLICT(date) DO UPDATE SET {col} = MAX({col}, excluded.{col})"
            ),
            params![date, value as i64],
        )?;
        Ok(())
    }

    /// Sum of counters for dates in `[from_date, to_date)` (ISO dates compare lexicographically).
    pub fn daily_totals(&self, from_date: &str, to_date: &str) -> Result<DailyTotals> {
        Ok(self.lock().query_row(
            "SELECT COALESCE(SUM(files_scanned),0), COALESCE(SUM(threats),0), COALESCE(SUM(quarantined),0),
                    COALESCE(SUM(dns_blocked),0), COALESCE(SUM(persistence_new),0), COALESCE(SUM(devices_new),0),
                    COALESCE(SUM(false_positives),0), COALESCE(SUM(db_updates),0), COUNT(*)
             FROM daily_stats WHERE date >= ?1 AND date < ?2",
            params![from_date, to_date],
            |r| {
                let g = |i: usize| -> rusqlite::Result<u64> { Ok(r.get::<_, i64>(i)?.max(0) as u64) };
                Ok(DailyTotals {
                    files_scanned: g(0)?,
                    threats: g(1)?,
                    quarantined: g(2)?,
                    dns_blocked: g(3)?,
                    persistence_new: g(4)?,
                    devices_new: g(5)?,
                    false_positives: g(6)?,
                    db_updates: g(7)?,
                    days: g(8)?,
                })
            },
        )?)
    }

    // -----------------------------------------------------------------------------------------
    // update log
    // -----------------------------------------------------------------------------------------

    pub fn log_update(&self, r: &UpdateResult) -> Result<()> {
        self.lock().execute(
            "INSERT INTO update_log(ts, target, ok, new_db_version, json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![r.finished_at, enum_str(&r.target), r.ok, r.new_db_version, serde_json::to_string(r)?],
        )?;
        Ok(())
    }

    /// Update results in `[from, to)`, oldest first.
    pub fn updates_between(&self, from: i64, to: i64) -> Result<Vec<UpdateResult>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT json FROM update_log WHERE ts >= ?1 AND ts < ?2 ORDER BY ts, id")?;
        let rows = stmt.query_map(params![from, to], |r| {
            from_json::<UpdateResult>(&r.get::<_, String>(0)?)
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // -----------------------------------------------------------------------------------------
    // osquery
    // -----------------------------------------------------------------------------------------

    /// Record a result-row hash; returns `true` when it was never seen before.
    pub fn osquery_mark_seen(&self, row_hash: &str, query: &str, now: i64) -> Result<bool> {
        let conn = self.lock();
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO osquery_seen(row_hash, query, first_seen, last_seen) VALUES (?1, ?2, ?3, ?3)",
            params![row_hash, query, now],
        )?;
        if inserted == 0 {
            conn.execute(
                "UPDATE osquery_seen SET last_seen = ?2 WHERE row_hash = ?1",
                params![row_hash, now],
            )?;
        }
        Ok(inserted > 0)
    }

    // -----------------------------------------------------------------------------------------
    // maintenance
    // -----------------------------------------------------------------------------------------

    /// Drop old rows: file history > 90 days (and above [`FILE_HISTORY_CAP`]), jobs > 90 days, resolved alerts
    /// > 180 days, update log > 180 days, osquery rows unseen for 180 days, daily stats > 400 days.
    pub fn prune(&self, now: i64) -> Result<()> {
        let day = 86_400;
        let conn = self.lock();
        conn.execute(
            "DELETE FROM file_history WHERE last_seen < ?1",
            [now - 90 * day],
        )?;
        conn.execute(
            "DELETE FROM file_history WHERE path IN (SELECT path FROM file_history ORDER BY last_seen DESC LIMIT -1 OFFSET ?1)",
            [FILE_HISTORY_CAP],
        )?;
        conn.execute(
            "DELETE FROM scan_jobs WHERE started_at < ?1 AND state NOT IN ('queued', 'running')",
            [now - 90 * day],
        )?;
        conn.execute(
            "DELETE FROM alerts WHERE status = 'resolved' AND ts < ?1",
            [now - 180 * day],
        )?;
        conn.execute("DELETE FROM update_log WHERE ts < ?1", [now - 180 * day])?;
        conn.execute(
            "DELETE FROM osquery_seen WHERE last_seen < ?1",
            [now - 180 * day],
        )?;
        let cutoff = chrono::DateTime::from_timestamp(now - 400 * day, 0)
            .map(|d| d.format("%Y-%m-%d").to_string())
            .unwrap_or_default();
        conn.execute("DELETE FROM daily_stats WHERE date < ?1", [cutoff])?;
        Ok(())
    }

    /// Flush the WAL into the main database file (shutdown).
    pub fn checkpoint(&self) -> Result<()> {
        let conn = self.lock();
        let _ = conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        Ok(())
    }
}

/// Key used to look up alerts linked to an object.
#[derive(Debug, Clone, Copy)]
pub enum AlertKey<'a> {
    Device(&'a str),
    Persistence(&'a str),
    /// Matches the `detection` column (also used as a dedupe key for system alerts).
    Title(&'a str),
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(path: &str, sha: &str, ts: i64) -> Alert {
        Alert {
            id: 0,
            ts,
            kind: AlertKind::Malware,
            severity: Severity::High,
            title: "t".into(),
            message: "m".into(),
            path: Some(path.into()),
            sha256: Some(sha.into()),
            device_id: None,
            persistence_id: None,
            quarantine_id: None,
            status: AlertStatus::Open,
            actions: vec![AlertAction::Acknowledge],
        }
    }

    fn job(id: &str, state: JobState, started: i64) -> ScanJobSummary {
        ScanJobSummary {
            job_id: id.into(),
            origin: ScanOrigin::Manual,
            paths: vec!["/tmp".into()],
            state,
            started_at: started,
            finished_at: None,
            files_scanned: 0,
            bytes_scanned: 0,
            threats: 0,
            errors: 0,
            current_path: None,
        }
    }

    #[test]
    fn migrations_are_idempotent_on_disk() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("s.sqlite");
        let s = Store::open(&p).unwrap();
        assert_eq!(s.schema_version().unwrap(), 1);
        s.kv_set("a", "1").unwrap();
        drop(s);
        let s = Store::open(&p).unwrap();
        assert_eq!(s.schema_version().unwrap(), 1);
        assert_eq!(s.kv_get("a").unwrap().as_deref(), Some("1"));
        assert_eq!(s.kv_get_i64("a").unwrap(), Some(1));
        s.kv_delete("a").unwrap();
        assert_eq!(s.kv_get("a").unwrap(), None);
    }

    #[test]
    fn alerts_roundtrip_dedupe_and_counts() {
        let s = Store::open_in_memory().unwrap();
        let a = s
            .insert_alert(&alert("/x", "aa", 100), Some("Fam.A"))
            .unwrap();
        assert!(a.id > 0);
        let b = s
            .insert_alert(&alert("/y", "bb", 200), Some("Fam.A"))
            .unwrap();
        assert_eq!(s.get_alert(a.id).unwrap().unwrap(), a);
        assert_eq!(s.count_open_alerts().unwrap(), 2);
        let list = s.list_alerts(10, false).unwrap();
        assert_eq!(
            list.iter().map(|a| a.id).collect::<Vec<_>>(),
            vec![b.id, a.id]
        );
        assert!(s.find_recent_alert("aa", "/x", 50).unwrap().is_some());
        assert!(s.find_recent_alert("aa", "/x", 150).unwrap().is_none());
        assert!(s.find_recent_alert("aa", "/y", 0).unwrap().is_none());

        let mut r = b.clone();
        r.status = AlertStatus::Resolved;
        r.quarantine_id = Some("q1".into());
        s.update_alert(&r).unwrap();
        assert_eq!(s.list_alerts(10, false).unwrap().len(), 1);
        assert_eq!(s.list_alerts(10, true).unwrap().len(), 2);
        assert_eq!(s.alerts_by_quarantine("q1").unwrap(), vec![r]);
        assert_eq!(s.count_open_alerts().unwrap(), 1);
        assert_eq!(s.count_alerts(AlertKind::Malware, 0, 1000).unwrap(), 2);
        let top = s.top_detections(0, 1000, 5).unwrap();
        assert_eq!(
            top,
            vec![NamedCount {
                name: "Fam.A".into(),
                count: 2
            }]
        );
    }

    #[test]
    fn alert_lookup_by_key() {
        let s = Store::open_in_memory().unwrap();
        let mut a = alert("/x", "aa", 100);
        a.kind = AlertKind::Device;
        a.device_id = Some("hid:1".into());
        s.insert_alert(&a, None).unwrap();
        assert!(s
            .find_recent_alert_by(AlertKind::Device, AlertKey::Device("hid:1"), 0)
            .unwrap()
            .is_some());
        assert!(s
            .find_recent_alert_by(AlertKind::Device, AlertKey::Device("hid:2"), 0)
            .unwrap()
            .is_none());
        assert!(s
            .find_recent_alert_by(AlertKind::Device, AlertKey::None, 0)
            .unwrap()
            .is_some());
        assert_eq!(
            s.open_alerts_by(AlertKey::Device("hid:1")).unwrap().len(),
            1
        );
    }

    #[test]
    fn jobs_findings_and_interrupted() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_job(&job("j1", JobState::Running, 10)).unwrap();
        let mut j2 = job("j2", JobState::Finished, 20);
        j2.finished_at = Some(25);
        s.upsert_job(&j2).unwrap();
        s.add_finding(
            "j1",
            &ScanReport {
                path: "/a".into(),
                verdict: Verdict::Malicious,
                ..Default::default()
            },
        )
        .unwrap();
        let d = s.get_job("j1").unwrap().unwrap();
        assert_eq!(d.findings.len(), 1);
        assert_eq!(s.list_jobs(10).unwrap()[0].job_id, "j2");
        assert_eq!(s.fail_interrupted_jobs(30).unwrap(), 1);
        let j1 = s.get_job_summary("j1").unwrap().unwrap();
        assert_eq!(j1.state, JobState::Failed);
        assert_eq!(j1.finished_at, Some(30));
        assert_eq!(s.last_scan_finished().unwrap(), Some(25));
        assert!(s.get_job("nope").unwrap().is_none());
    }

    #[test]
    fn file_history_and_prune() {
        let s = Store::open_in_memory().unwrap();
        let now = 1_000_000_000;
        s.record_file("/a", "h1", 10, 5, Verdict::Clean, now - 100 * 86_400)
            .unwrap();
        s.record_file("/b", "h2", 10, 5, Verdict::Clean, now - 10)
            .unwrap();
        s.record_file("/b", "h2", 11, 6, Verdict::Suspicious, now)
            .unwrap();
        let recent = s.files_seen_since(now - 86_400, 100).unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].first_seen, now - 10);
        assert_eq!(recent[0].verdict, Verdict::Suspicious);
        s.prune(now).unwrap();
        assert_eq!(s.files_seen_since(0, 100).unwrap().len(), 1);
    }

    #[test]
    fn devices_and_persistence() {
        let s = Store::open_in_memory().unwrap();
        let d = DeviceInfo {
            id: "vol:1".into(),
            kind: DeviceKind::Volume,
            name: "KEY".into(),
            vendor: None,
            vendor_id: None,
            product_id: None,
            serial: None,
            transport: None,
            details: Default::default(),
            first_seen: 1,
            last_seen: 2,
            connected: true,
            trust: DeviceTrust::Unknown,
            baseline: false,
        };
        s.upsert_device(&d).unwrap();
        let mut d2 = d.clone();
        d2.trust = DeviceTrust::Trusted;
        s.upsert_device(&d2).unwrap();
        assert_eq!(
            s.get_device("vol:1").unwrap().unwrap().trust,
            DeviceTrust::Trusted
        );
        assert_eq!(s.list_devices(Some(DeviceKind::Volume)).unwrap().len(), 1);
        assert_eq!(s.list_devices(Some(DeviceKind::Hid)).unwrap().len(), 0);
        assert_eq!(s.list_devices(None).unwrap().len(), 1);

        let p = PersistenceItem {
            id: "abcd".into(),
            kind: PersistenceKind::LaunchAgent,
            label: Some("com.x".into()),
            path: "/Library/LaunchAgents/com.x.plist".into(),
            program: None,
            arguments: vec![],
            user: None,
            signing: None,
            program_sha256: None,
            first_seen: 1,
            last_seen: 1,
            status: PersistenceStatus::New,
            verdict: None,
        };
        s.upsert_persistence(&p).unwrap();
        assert_eq!(s.list_persistence(true).unwrap().len(), 1);
        let mut p2 = p.clone();
        p2.status = PersistenceStatus::Approved;
        s.upsert_persistence(&p2).unwrap();
        assert!(s.list_persistence(true).unwrap().is_empty());
        assert_eq!(
            s.get_persistence("abcd").unwrap().unwrap().status,
            PersistenceStatus::Approved
        );
        assert_eq!(s.count_persistence().unwrap(), 1);
    }

    #[test]
    fn hash_lists_and_fps() {
        let s = Store::open_in_memory().unwrap();
        s.allowlist_add("ABCD", "fp", 1).unwrap();
        assert!(s.allowlist_contains("abcd").unwrap());
        assert_eq!(s.allowlist_all().unwrap(), vec!["abcd".to_string()]);
        assert!(s.allowlist_remove("abcd").unwrap());
        assert!(!s.allowlist_contains("abcd").unwrap());
        s.blocklist_add("ef01", "VT:12", "virustotal", 2).unwrap();
        assert_eq!(s.blocklist_get("EF01").unwrap().unwrap().name, "VT:12");
        s.add_false_positive("ab", Some("/p"), None, 10).unwrap();
        assert_eq!(s.count_false_positives(0, 11).unwrap(), 1);
        assert_eq!(s.count_false_positives(11, 20).unwrap(), 0);
    }

    #[test]
    fn daily_stats_accumulate() {
        let s = Store::open_in_memory().unwrap();
        s.bump_daily("2026-10-19", StatField::FilesScanned, 10)
            .unwrap();
        s.bump_daily("2026-10-19", StatField::FilesScanned, 5)
            .unwrap();
        s.bump_daily("2026-10-20", StatField::Threats, 1).unwrap();
        s.max_daily("2026-10-20", StatField::DnsBlocked, 7).unwrap();
        s.max_daily("2026-10-20", StatField::DnsBlocked, 3).unwrap();
        s.bump_daily("2026-10-27", StatField::Threats, 9).unwrap();
        let t = s.daily_totals("2026-10-19", "2026-10-26").unwrap();
        assert_eq!(t.files_scanned, 15);
        assert_eq!(t.threats, 1);
        assert_eq!(t.dns_blocked, 7);
        assert_eq!(t.days, 2);
    }

    #[test]
    fn update_log_and_osquery() {
        let s = Store::open_in_memory().unwrap();
        let r = UpdateResult {
            target: UpdateTarget::Db,
            ok: true,
            started_at: 1,
            finished_at: 2,
            messages: vec!["ok".into()],
            new_db_version: Some("2026.10.25.1".into()),
        };
        s.log_update(&r).unwrap();
        assert_eq!(s.updates_between(0, 10).unwrap(), vec![r]);
        assert!(s.osquery_mark_seen("h", "q", 1).unwrap());
        assert!(!s.osquery_mark_seen("h", "q", 2).unwrap());
    }

    #[tokio::test]
    async fn run_on_blocking_thread() {
        let s = Store::open_in_memory().unwrap();
        s.run(|s| s.kv_set("k", "v")).await.unwrap();
        let v = s.run(|s| s.kv_get("k")).await.unwrap();
        assert_eq!(v.as_deref(), Some("v"));
    }

    #[test]
    fn enum_helpers() {
        assert_eq!(enum_str(&AlertKind::Malware), "malware");
        assert_eq!(
            parse_enum::<Verdict>("suspicious"),
            Some(Verdict::Suspicious)
        );
        assert_eq!(parse_enum::<Verdict>("nope"), None);
    }
}
