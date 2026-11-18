//! On-device behavioural baseline: learns what each executable normally does on this Mac and scores
//! novelty. Private by construction (nothing leaves the Mac), bounded in memory and on disk, cheap
//! (one hash-map lookup + a count-min sketch update per observation, no model at runtime).
//!
//! Observations (from eslogger events the daemon already receives):
//! * `exec`: the image that called exec (the *parent*) gains an [`ObsKind::Exec`] (child's coarse
//!   identity) or [`ObsKind::Interpreter`] (shell / script interpreter) observation; the new image
//!   gains [`ObsKind::LaunchedBy`] (parent's coarse identity) and [`ObsKind::Hour`] (4-hour bucket).
//! * file `create` / `rename` with a known process: [`ObsKind::File`] with the category of the path
//!   (LaunchAgents, credential stores, browser data, wallets, temp…).
//!
//! Scoring of an observation `(actor a, feature f)` never seen before for `a` (`count == 0`):
//! ```text
//! p_new    = (k_a + 1) / (n_a + 2)          Bayesian (Laplace) estimate of "a produces something new
//!                                           of this kind": k = distinct values of the kind a produced,
//!                                           n = all observations of a (it was seen n times without it)
//! s_actor  = clamp(-log10(p_new) / 2.5, 0, 1)
//! s_global = 0.5 + 0.5 / (1 + d_f)          d_f = distinct actors that already showed f on this Mac
//! s        = weight(kind, f) · s_actor · s_global      (hours: s_global = 1; weights: interpreter 0.9,
//!                                           exec 0.8 (0.3 from Apple launchers), launched-by 0.5,
//!                                           hour 0.4, files by category 0.3..1)
//! event    = 1 − Π (1 − s)                  over the features of one actor in one event
//! ```
//! A feature already seen (`count > 0`) scores 0. Hence a narrow, well-known process doing something
//! new scores high; a "launcher" that constantly does new things (Finder, shells, IDEs) or an unknown
//! process (little history) scores low. During the learning period nothing is reported.

pub mod identity;
pub mod sketch;

use identity::{coarse_identity, file_category, interpreter, ProcInfo};
use serde::{Deserialize, Serialize};
use sketch::{stable_hash, CountMin};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::Path;

/// Kinds of observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObsKind {
    Exec,
    Interpreter,
    LaunchedBy,
    File,
    Hour,
}

impl ObsKind {
    fn idx(self) -> usize {
        match self {
            ObsKind::Exec => 0,
            ObsKind::Interpreter => 1,
            ObsKind::LaunchedBy => 2,
            ObsKind::File => 3,
            ObsKind::Hour => 4,
        }
    }
    fn key(self) -> &'static str {
        match self {
            ObsKind::Exec => "exec",
            ObsKind::Interpreter => "interp",
            ObsKind::LaunchedBy => "parent",
            ObsKind::File => "file",
            ObsKind::Hour => "hour",
        }
    }
}

const KINDS: usize = 5;
/// (kind, value, weight) of one observation.
type Feat = (ObsKind, String, f32);
/// Actors kept (least recently seen evicted beyond).
pub const MAX_ACTORS: usize = 8_192;
/// Features whose prevalence is tracked.
pub const MAX_FEATURES: usize = 32_768;
/// Pairs marked "normal" by the user.
pub const MAX_MUTED: usize = 4_096;
/// Anomalies remembered for the UI.
pub const MAX_RECENT: usize = 100;
const MAX_LABEL: usize = 200;
/// Persisted file larger than this is refused (corrupt / hostile).
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
const SKETCH_WIDTH_LOG2: u8 = 16;
const SKETCH_DEPTH: u8 = 4;
/// Counts added to a pair marked normal.
const NORMAL_BOOST: u16 = 8;
/// Below this many observations an actor's hour-of-day is not scored.
const HOUR_MIN_OBS: u32 = 50;
/// Sketch counters are halved this often (ageing).
const DECAY_PERIOD: i64 = 30 * 86_400;
const FORMAT_VERSION: u32 = 1;

/// One observed event, already reduced to identities (built by the daemon from eslogger events).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BehaviorEvent {
    Exec {
        parent: Option<ProcInfo>,
        target: ProcInfo,
        /// Local hour (0..=23).
        hour: u8,
    },
    File {
        process: ProcInfo,
        path: String,
        hour: u8,
    },
}

/// A feature of an anomaly, with its own score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyFeature {
    pub kind: ObsKind,
    pub value: String,
    pub score: f32,
}

/// A scored observation set for one actor (only produced after the learning period).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyRecord {
    /// Stable id (hex) of actor + main feature.
    pub id: String,
    pub ts: i64,
    pub actor_key: String,
    pub actor_label: String,
    pub score: f32,
    pub features: Vec<AnomalyFeature>,
    #[serde(default)]
    pub alert_id: Option<i64>,
    #[serde(default)]
    pub marked_normal: bool,
}

impl AnomalyRecord {
    /// The highest-scoring feature.
    pub fn main(&self) -> Option<&AnomalyFeature> {
        self.features.iter().max_by(|a, b| {
            a.score
                .partial_cmp(&b.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// French one-line explanation of a feature.
    pub fn describe(f: &AnomalyFeature) -> String {
        match f.kind {
            ObsKind::Exec => format!("lance pour la première fois {}", pretty_identity(&f.value)),
            ObsKind::Interpreter => format!("lance un interpréteur inhabituel ({})", f.value),
            ObsKind::LaunchedBy => {
                format!(
                    "est lancé par un parent inhabituel ({})",
                    pretty_identity(&f.value)
                )
            }
            ObsKind::File => format!(
                "écrit pour la première fois dans : {}",
                identity::FileCategory::from_key(&f.value)
                    .map(|c| c.label().to_string())
                    .unwrap_or_else(|| f.value.clone())
            ),
            ObsKind::Hour => format!(
                "s'exécute à une heure inhabituelle ({})",
                hour_label(&f.value)
            ),
        }
    }
}

fn pretty_identity(v: &str) -> String {
    if let Some(rest) = v.strip_prefix("path:") {
        rest.to_string()
    } else if let Some(rest) = v.strip_prefix("apple:") {
        format!("{rest} (Apple)")
    } else if let Some(rest) = v.strip_prefix("team:") {
        format!("une app de l'éditeur {rest}")
    } else {
        v.to_string()
    }
}

fn hour_label(v: &str) -> String {
    match v.parse::<u8>() {
        Ok(b) if b < 6 => format!("{:02}h–{:02}h", b * 4, b * 4 + 4),
        _ => v.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
struct ActorStats {
    label: String,
    n: [u32; KINDS],
    k: [u32; KINDS],
    first_seen: i64,
    last_seen: i64,
}

impl ActorStats {
    fn total(&self) -> u32 {
        self.n.iter().fold(0u32, |a, b| a.saturating_add(*b))
    }
}

/// Counters for the status page.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BaselineStats {
    pub started_at: i64,
    pub events: u64,
    pub actors: u32,
    pub features: u32,
    pub sketch_load: f32,
    pub muted: u32,
}

/// The persisted baseline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    version: u32,
    started_at: i64,
    last_decay: i64,
    events: u64,
    actors: HashMap<u64, ActorStats>,
    prevalence: HashMap<u64, u16>,
    pairs: CountMin,
    muted: HashMap<u64, i64>,
    recent: VecDeque<AnomalyRecord>,
}

fn clip(s: &str) -> String {
    if s.len() <= MAX_LABEL {
        return s.to_string();
    }
    let mut end = MAX_LABEL;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn feature_key(kind: ObsKind, value: &str) -> String {
    format!("{}:{value}", kind.key())
}

impl Baseline {
    pub fn new(now: i64) -> Self {
        Self {
            version: FORMAT_VERSION,
            started_at: now,
            last_decay: now,
            events: 0,
            actors: HashMap::new(),
            prevalence: HashMap::new(),
            pairs: CountMin::new(SKETCH_WIDTH_LOG2, SKETCH_DEPTH),
            muted: HashMap::new(),
            recent: VecDeque::new(),
        }
    }

    pub fn started_at(&self) -> i64 {
        self.started_at
    }

    pub fn learning_until(&self, learning_days: u32) -> i64 {
        self.started_at + i64::from(learning_days) * 86_400
    }

    pub fn is_learning(&self, now: i64, learning_days: u32) -> bool {
        now < self.learning_until(learning_days)
    }

    /// 0..=1 progress of the learning period.
    pub fn progress(&self, now: i64, learning_days: u32) -> f32 {
        let total = (i64::from(learning_days) * 86_400).max(1);
        ((now - self.started_at) as f32 / total as f32).clamp(0.0, 1.0)
    }

    pub fn stats(&self) -> BaselineStats {
        BaselineStats {
            started_at: self.started_at,
            events: self.events,
            actors: self.actors.len() as u32,
            features: self.prevalence.len() as u32,
            sketch_load: self.pairs.load(),
            muted: self.muted.len() as u32,
        }
    }

    pub fn recent(&self) -> impl Iterator<Item = &AnomalyRecord> {
        self.recent.iter().rev()
    }

    pub fn recent_mut(&mut self, id: &str) -> Option<&mut AnomalyRecord> {
        self.recent.iter_mut().find(|r| r.id == id)
    }

    /// Feeds one event. Returns the anomalies (score > 0) of the actors involved — only after the
    /// learning period; the caller applies its threshold, dedupe and rate limits.
    pub fn observe(
        &mut self,
        ev: &BehaviorEvent,
        now: i64,
        learning_days: u32,
    ) -> Vec<AnomalyRecord> {
        self.maybe_decay(now);
        self.events = self.events.saturating_add(1);
        let report = !self.is_learning(now, learning_days);
        let mut groups: Vec<(ProcInfo, Vec<Feat>)> = Vec::new();
        match ev {
            BehaviorEvent::Exec {
                parent,
                target,
                hour,
            } => {
                if let Some(p) = parent {
                    // Apple launchers (launchd, xpcproxy, Finder, shells) start every new program:
                    // what they launch says little.
                    let exec_weight = if p.platform { 0.3 } else { 0.8 };
                    let f = match interpreter(&target.path) {
                        Some(i) => (ObsKind::Interpreter, i.to_string(), 0.9),
                        None => (ObsKind::Exec, coarse_identity(target), exec_weight),
                    };
                    groups.push((p.clone(), vec![f]));
                }
                let mut tf = vec![(ObsKind::Hour, ((*hour).min(23) / 4).to_string(), 0.4)];
                if let Some(p) = parent {
                    tf.push((ObsKind::LaunchedBy, coarse_identity(p), 0.5));
                }
                groups.push((target.clone(), tf));
            }
            BehaviorEvent::File {
                process,
                path,
                hour: _,
            } => {
                if let Some(c) = file_category(path) {
                    groups.push((
                        process.clone(),
                        vec![(ObsKind::File, c.key().to_string(), c.weight())],
                    ));
                }
            }
        }
        let mut out = Vec::new();
        for (proc_, feats) in groups {
            if let Some(a) = self.observe_actor(&proc_, &feats, now, report) {
                out.push(a);
            }
        }
        out
    }

    fn observe_actor(
        &mut self,
        p: &ProcInfo,
        feats: &[Feat],
        now: i64,
        report: bool,
    ) -> Option<AnomalyRecord> {
        let (key, label) = identity::actor_identity(p);
        let ah = stable_hash(&[&key]);
        if !self.actors.contains_key(&ah) && self.actors.len() >= MAX_ACTORS {
            self.evict_actors();
        }
        let mut scored = Vec::new();
        let mut keep = 1.0f32;
        {
            let stats = self.actors.get(&ah).cloned().unwrap_or_default();
            for (kind, value, weight) in feats {
                let fk = feature_key(*kind, value);
                let ph = stable_hash(&[&key, &fk]);
                let fh = stable_hash(&[&fk]);
                let count = self.pairs.estimate(ph);
                if count > 0 || !report || self.muted.contains_key(&ph) {
                    continue;
                }
                if *kind == ObsKind::Hour && stats.total() < HOUR_MIN_OBS {
                    continue;
                }
                // k: distinct values of this kind the actor produced; n: everything it was seen doing.
                let i = kind.idx();
                let p_new = (stats.k[i] as f32 + 1.0) / (stats.total() as f32 + 2.0);
                let s_actor = (-p_new.log10() / 2.5).clamp(0.0, 1.0);
                let s_global = if *kind == ObsKind::Hour {
                    1.0
                } else {
                    let d = self.prevalence.get(&fh).copied().unwrap_or(0);
                    0.5 + 0.5 / (1.0 + f32::from(d))
                };
                let s = (weight * s_actor * s_global).clamp(0.0, 1.0);
                if s > 0.0 {
                    keep *= 1.0 - s;
                    scored.push(AnomalyFeature {
                        kind: *kind,
                        value: value.clone(),
                        score: s,
                    });
                }
            }
        }
        // Update counts after scoring.
        let stats = self.actors.entry(ah).or_insert_with(|| ActorStats {
            label: clip(&label),
            first_seen: now,
            ..Default::default()
        });
        stats.last_seen = now;
        for (kind, value, _) in feats {
            let fk = feature_key(*kind, value);
            let ph = stable_hash(&[&key, &fk]);
            let i = kind.idx();
            stats.n[i] = stats.n[i].saturating_add(1);
            if self.pairs.estimate(ph) == 0 {
                stats.k[i] = stats.k[i].saturating_add(1);
                let fh = stable_hash(&[&fk]);
                if let Some(d) = self.prevalence.get_mut(&fh) {
                    *d = d.saturating_add(1);
                } else if self.prevalence.len() < MAX_FEATURES {
                    self.prevalence.insert(fh, 1);
                } else {
                    self.prevalence.retain(|_, d| *d > 1);
                }
            }
            self.pairs.add(ph, 1);
        }
        if scored.is_empty() {
            return None;
        }
        let score = 1.0 - keep;
        let main = scored
            .iter()
            .max_by(|a, b| {
                a.score
                    .partial_cmp(&b.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|f| feature_key(f.kind, &f.value))
            .unwrap_or_default();
        Some(AnomalyRecord {
            id: format!("{:016x}", stable_hash(&[&key, &main])),
            ts: now,
            actor_key: key,
            actor_label: clip(&label),
            score,
            features: scored,
            alert_id: None,
            marked_normal: false,
        })
    }

    fn evict_actors(&mut self) {
        let mut v: Vec<(u64, i64)> = self.actors.iter().map(|(k, s)| (*k, s.last_seen)).collect();
        v.sort_by_key(|e| e.1);
        for (k, _) in v.into_iter().take(MAX_ACTORS / 10) {
            self.actors.remove(&k);
        }
    }

    fn maybe_decay(&mut self, now: i64) {
        if now - self.last_decay >= DECAY_PERIOD {
            self.pairs.halve();
            self.last_decay = now;
        }
    }

    /// Remember an anomaly for the UI (and its alert id).
    pub fn remember(&mut self, rec: AnomalyRecord) {
        if let Some(existing) = self.recent.iter_mut().find(|r| r.id == rec.id) {
            *existing = rec;
            return;
        }
        if self.recent.len() >= MAX_RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(rec);
    }

    /// "C'est normal": teach the baseline that these features are normal for this actor and never
    /// report them again. Returns false when the anomaly id is unknown.
    pub fn mark_normal(&mut self, id: &str, now: i64) -> bool {
        let Some(rec) = self.recent.iter_mut().find(|r| r.id == id) else {
            return false;
        };
        rec.marked_normal = true;
        let (key, feats) = (rec.actor_key.clone(), rec.features.clone());
        for f in feats {
            let ph = stable_hash(&[&key, &feature_key(f.kind, &f.value)]);
            self.pairs.add(ph, NORMAL_BOOST);
            if self.muted.len() >= MAX_MUTED {
                if let Some(oldest) = self.muted.iter().min_by_key(|e| *e.1).map(|e| *e.0) {
                    self.muted.remove(&oldest);
                }
            }
            self.muted.insert(ph, now);
        }
        true
    }

    // ----- persistence (gzip JSON, bounded) -----

    /// Serializes to gzip-compressed JSON.
    pub fn to_bytes(&self) -> std::io::Result<Vec<u8>> {
        let json = serde_json::to_vec(self).map_err(std::io::Error::other)?;
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&json)?;
        enc.finish()
    }

    pub fn from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        let mut dec = flate2::read::GzDecoder::new(bytes).take(8 * MAX_FILE_BYTES);
        let mut json = Vec::new();
        dec.read_to_end(&mut json)?;
        let b: Baseline = serde_json::from_slice(&json).map_err(std::io::Error::other)?;
        if b.version != FORMAT_VERSION
            || !b.pairs.is_valid()
            || b.actors.len() > MAX_ACTORS
            || b.prevalence.len() > MAX_FEATURES
            || b.muted.len() > MAX_MUTED
            || b.recent.len() > MAX_RECENT
        {
            return Err(std::io::Error::other(
                "baseline file rejected (format or bounds)",
            ));
        }
        Ok(b)
    }

    /// Loads `path`; `Ok(None)` when absent.
    pub fn load(path: &Path) -> std::io::Result<Option<Self>> {
        let f = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut buf = Vec::new();
        f.take(MAX_FILE_BYTES + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > MAX_FILE_BYTES {
            return Err(std::io::Error::other("baseline file too large"));
        }
        Self::from_bytes(&buf).map(Some)
    }

    /// Atomic write (temp file + rename) with mode 0600.
    pub fn save(&self, path: &Path) -> std::io::Result<u64> {
        let bytes = self.to_bytes()?;
        let tmp = path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create_new(true);
            // create_new = O_CREAT|O_EXCL: never follows a planted symlink.
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(bytes.len() as u64)
    }
}

#[cfg(test)]
mod tests;
