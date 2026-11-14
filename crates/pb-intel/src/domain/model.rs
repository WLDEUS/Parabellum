//! The shipped domain model: LightGBM dump + calibrated thresholds + the brand list it was trained with.
//!
//! Bundle layout (all under `ml/`, optional as a whole):
//! ```text
//! ml/domain_model.json        LightGBM Booster.dump_model() over [`super::feature_names`]
//! ml/domain_model_meta.json   {"features_version":N,"threshold":f,"block_threshold":f,"version":"…",
//!                              "brands_sha256":"…","metrics":{…}}
//! ml/domain_brands.txt        the brands.txt used for training (falls back to the compiled-in list)
//! ml/domain_top.txt           popular registrable domains never scored (optional)
//! ```
//! Without a model, [`DomainScorer`] falls back to a few conservative brand rules (alert only, never
//! block), so homograph / brand-in-subdomain lures are still reported before the first model ships.

use super::{is_local_or_special, normalize, Brands, DomainFeatures, FEATURES_VERSION};
use pb_ml::{GbdtModel, MlError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

pub const DOMAIN_MODEL_FILE: &str = "ml/domain_model.json";
pub const DOMAIN_META_FILE: &str = "ml/domain_model_meta.json";
pub const DOMAIN_BRANDS_FILE: &str = "ml/domain_brands.txt";
pub const DOMAIN_TOP_FILE: &str = "ml/domain_top.txt";

const MAX_MODEL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_META_BYTES: u64 = 1024 * 1024;
const MAX_LIST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_TOP: usize = 200_000;
/// Threshold of the rule-based fallback.
pub const HEURISTIC_THRESHOLD: f32 = 0.9;

/// `ml/domain_model_meta.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainModelMeta {
    pub features_version: u32,
    /// Alert threshold (calibrated for a tiny false-positive rate on popular domains).
    pub threshold: f32,
    /// Block threshold (stricter); defaults to `threshold` when absent.
    #[serde(default)]
    pub block_threshold: Option<f32>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub brands_sha256: Option<String>,
    #[serde(default)]
    pub metrics: serde_json::Value,
}

/// Where a verdict comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictSource {
    Model,
    Heuristic,
}

/// Outcome of [`DomainScorer::score`].
#[derive(Debug, Clone, PartialEq)]
pub enum Scored {
    /// Not scored (local name, popular or official domain, invalid name).
    Skipped(&'static str),
    Verdict(DomainVerdict),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DomainVerdict {
    pub host: String,
    pub registrable: String,
    pub score: f32,
    pub threshold: f32,
    pub block_threshold: f32,
    pub flagged: bool,
    /// Confident enough to be blocked (only ever true for [`VerdictSource::Model`]).
    pub block: bool,
    pub source: VerdictSource,
    pub reasons: Vec<String>,
    pub shared_platform: bool,
}

/// Loaded model + brand list + popular-domain skip list.
#[derive(Debug, Clone)]
pub struct DomainScorer {
    model: Option<GbdtModel>,
    threshold: f32,
    block_threshold: f32,
    version: Option<String>,
    metrics: serde_json::Value,
    brands: Brands,
    popular: HashSet<String>,
}

fn read_bounded(path: &Path, max: u64) -> Result<String, MlError> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut s = String::new();
    f.take(max + 1).read_to_string(&mut s)?;
    if s.len() as u64 > max {
        return Err(MlError::Model(format!(
            "{} is larger than {max} bytes",
            path.display()
        )));
    }
    Ok(s)
}

impl Default for DomainScorer {
    fn default() -> Self {
        Self::heuristic_only()
    }
}

impl DomainScorer {
    /// No model: built-in brands, rule-based fallback.
    pub fn heuristic_only() -> Self {
        Self {
            model: None,
            threshold: HEURISTIC_THRESHOLD,
            block_threshold: f32::INFINITY,
            version: None,
            metrics: serde_json::Value::Null,
            brands: Brands::builtin(),
            popular: HashSet::new(),
        }
    }

    /// Loads the model files from a bundle directory. Missing model ⇒ heuristic-only scorer; a present
    /// but invalid / incompatible model is an error (the caller keeps the heuristic and reports it).
    pub fn load(dir: &Path) -> Result<Self, MlError> {
        let mut s = Self::heuristic_only();
        let brands_path = dir.join(DOMAIN_BRANDS_FILE);
        if brands_path.is_file() {
            let b = Brands::parse(&read_bounded(&brands_path, MAX_LIST_BYTES)?);
            if !b.is_empty() {
                s.brands = b;
            }
        }
        let top_path = dir.join(DOMAIN_TOP_FILE);
        if top_path.is_file() {
            s.popular = read_bounded(&top_path, MAX_LIST_BYTES)?
                .lines()
                .map(|l| l.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|l| !l.is_empty() && !l.starts_with('#') && l.contains('.'))
                .take(MAX_TOP)
                .collect();
        }
        let (mp, metap) = (dir.join(DOMAIN_MODEL_FILE), dir.join(DOMAIN_META_FILE));
        match (mp.is_file(), metap.is_file()) {
            (false, false) => return Ok(s),
            (true, true) => {}
            _ => {
                return Err(MlError::Model(
                    "domain model or its metadata is missing".into(),
                ))
            }
        }
        let meta: DomainModelMeta = serde_json::from_str(&read_bounded(&metap, MAX_META_BYTES)?)?;
        let json = read_bounded(&mp, MAX_MODEL_BYTES)?;
        s.apply_model(
            &json,
            &meta,
            brands_path
                .is_file()
                .then(|| std::fs::read(&brands_path).ok())
                .flatten(),
        )?;
        Ok(s)
    }

    fn apply_model(
        &mut self,
        json: &str,
        meta: &DomainModelMeta,
        brands_bytes: Option<Vec<u8>>,
    ) -> Result<(), MlError> {
        if meta.features_version != FEATURES_VERSION {
            return Err(MlError::FeatureMismatch(format!(
                "domain model trained on features v{}, binary computes v{FEATURES_VERSION}",
                meta.features_version
            )));
        }
        let ok = |t: f32| t > 0.0 && t <= 1.0;
        if !ok(meta.threshold) || meta.block_threshold.is_some_and(|b| !ok(b)) {
            return Err(MlError::Model("domain thresholds out of (0, 1]".into()));
        }
        // The brand features depend on the list: refuse a model trained on another list.
        if let Some(want) = &meta.brands_sha256 {
            let have = hex::encode(Sha256::digest(
                brands_bytes
                    .as_deref()
                    .unwrap_or(super::brands::BUILTIN_BRANDS.as_bytes()),
            ));
            if !want.eq_ignore_ascii_case(&have) {
                return Err(MlError::FeatureMismatch(
                    "domain model trained with another brand list".into(),
                ));
            }
        }
        let model = GbdtModel::from_json_with_names(json, super::feature_names())?;
        self.threshold = meta.threshold;
        self.block_threshold = meta
            .block_threshold
            .unwrap_or(meta.threshold)
            .max(meta.threshold);
        self.version = Some(
            meta.version
                .clone()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| {
                    format!(
                        "sha256:{}",
                        &hex::encode(Sha256::digest(json.as_bytes()))[..12]
                    )
                }),
        );
        self.metrics = meta.metrics.clone();
        self.model = Some(model);
        Ok(())
    }

    /// Builds a scorer from in-memory parts (tests, CLI).
    pub fn from_parts(
        json: &str,
        meta: &DomainModelMeta,
        brands: Option<&str>,
    ) -> Result<Self, MlError> {
        let mut s = Self::heuristic_only();
        if let Some(b) = brands {
            s.brands = Brands::parse(b);
        }
        s.apply_model(json, meta, brands.map(|b| b.as_bytes().to_vec()))?;
        Ok(s)
    }

    pub fn has_model(&self) -> bool {
        self.model.is_some()
    }
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
    pub fn threshold(&self) -> f32 {
        self.threshold
    }
    pub fn block_threshold(&self) -> f32 {
        self.block_threshold
    }
    pub fn metrics(&self) -> &serde_json::Value {
        &self.metrics
    }
    pub fn brands(&self) -> &Brands {
        &self.brands
    }
    pub fn popular_count(&self) -> usize {
        self.popular.len()
    }

    /// `registrable` or `host` (or one of its parents) is in the popular list.
    fn is_popular(&self, host: &str, registrable: &str) -> bool {
        if self.popular.is_empty() {
            return false;
        }
        if self.popular.contains(registrable) {
            return true;
        }
        let mut h = host;
        while let Some(i) = h.find('.') {
            if self.popular.contains(h) {
                return true;
            }
            h = &h[i + 1..];
        }
        false
    }

    /// Scores a raw query name. Cheap (microseconds): safe to call inline for each first-seen name.
    pub fn score(&self, raw: &str) -> Scored {
        let Some(host) = normalize(raw) else {
            return Scored::Skipped("nom invalide");
        };
        if is_local_or_special(&host) {
            return Scored::Skipped("nom local");
        }
        let f = DomainFeatures::extract(&host, &self.brands);
        if f.official {
            return Scored::Skipped("domaine officiel d'une marque");
        }
        // Popular registrable domains are skipped, except on shared platforms where the "registrable"
        // part belongs to an arbitrary customer.
        if !f.shared_platform && self.is_popular(&host, &f.registrable) {
            return Scored::Skipped("domaine populaire");
        }
        let reasons = f.reasons();
        let (score, source) = match &self.model {
            Some(m) => (m.predict_proba(&f.values), VerdictSource::Model),
            None => (heuristic_score(&f), VerdictSource::Heuristic),
        };
        let flagged = score >= self.threshold;
        let block = source == VerdictSource::Model && score >= self.block_threshold;
        Scored::Verdict(DomainVerdict {
            host,
            registrable: f.registrable.clone(),
            score,
            threshold: self.threshold,
            block_threshold: self.block_threshold,
            flagged,
            block,
            source,
            reasons,
            shared_platform: f.shared_platform,
        })
    }
}

/// Conservative rules used without a model (score in 0..1; >= [`HEURISTIC_THRESHOLD`] = flagged).
pub fn heuristic_score(f: &DomainFeatures) -> f32 {
    let v = |name: &str| {
        super::feature_names()
            .iter()
            .position(|n| *n == name)
            .and_then(|i| f.values.get(i).copied())
            .unwrap_or(0.0)
    };
    let lure = v("keyword_hits") >= 1.0 || v("tld_abused") > 0.0 || f.shared_platform;
    if f.brand.homoglyph.is_some() {
        return 0.97;
    }
    if f.brand.in_sub.is_some() && lure {
        return 0.95;
    }
    if let Some((d, b)) = &f.brand.typo {
        if *d == 1 && b.len() >= 6 && lure {
            return 0.92;
        }
    }
    if f.brand.in_sld.is_some() && v("keyword_in_sld") >= 1.0 && v("tld_abused") > 0.0 {
        return 0.91;
    }
    let mut s: f32 = 0.0;
    if f.brand.in_sld.is_some() || f.brand.in_sub.is_some() || f.brand.typo.is_some() {
        s += 0.4;
    }
    if lure {
        s += 0.2;
    }
    if v("sld_entropy") >= 3.8 && v("sld_len") >= 12.0 {
        s += 0.2;
    }
    s.min(0.85)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// One-split model on `name`: `<= thr` → -4 (benign), else +4 (malicious).
    pub(crate) fn one_split(name: &str, thr: f64) -> String {
        let names = crate::domain::feature_names();
        let idx = names.iter().position(|n| *n == name).unwrap();
        serde_json::json!({
            "name": "tree", "version": "v4", "num_class": 1, "num_tree_per_iteration": 1,
            "label_index": 0, "max_feature_idx": names.len() - 1, "objective": "binary sigmoid:1",
            "average_output": false, "feature_names": names,
            "tree_info": [{"tree_index": 0, "num_leaves": 2, "num_cat": 0, "shrinkage": 1,
              "tree_structure": {"split_index": 0, "split_feature": idx, "split_gain": 1.0,
                "threshold": thr, "decision_type": "<=", "default_left": true, "missing_type": "None",
                "internal_value": 0, "internal_weight": 0, "internal_count": 2,
                "left_child": {"leaf_index": 0, "leaf_value": -4.0, "leaf_count": 1},
                "right_child": {"leaf_index": 1, "leaf_value": 4.0, "leaf_count": 1}}}]
        })
        .to_string()
    }

    fn meta(thr: f32, block: Option<f32>) -> DomainModelMeta {
        DomainModelMeta {
            features_version: FEATURES_VERSION,
            threshold: thr,
            block_threshold: block,
            version: Some("2026.11.13".into()),
            brands_sha256: None,
            metrics: serde_json::json!({"auc": 0.99}),
        }
    }

    #[test]
    fn heuristic_fallback() {
        let s = DomainScorer::heuristic_only();
        assert!(!s.has_model());
        match s.score("paypal.com.account-verify.xyz.") {
            Scored::Verdict(v) => {
                assert!(v.flagged && !v.block);
                assert_eq!(v.source, VerdictSource::Heuristic);
                assert_eq!(v.registrable, "account-verify.xyz");
            }
            other => panic!("{other:?}"),
        }
        match s.score("xn--80ak6aa92e.com") {
            Scored::Verdict(v) => assert!(v.flagged),
            other => panic!("{other:?}"),
        }
        match s.score("www.lemonde.fr") {
            Scored::Verdict(v) => assert!(!v.flagged, "{v:?}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(s.score("printer.local"), Scored::Skipped("nom local"));
        assert_eq!(
            s.score("www.paypal.com"),
            Scored::Skipped("domaine officiel d'une marque")
        );
        assert_eq!(s.score("bad name"), Scored::Skipped("nom invalide"));
    }

    #[test]
    fn model_scoring_and_thresholds() {
        let s = DomainScorer::from_parts(
            &one_split("brand_in_sub", 0.5),
            &meta(0.9, Some(0.99)),
            None,
        )
        .unwrap();
        assert!(s.has_model());
        assert_eq!(s.version(), Some("2026.11.13"));
        match s.score("paypal.secure-check.com") {
            Scored::Verdict(v) => {
                assert!(v.score > 0.98 && v.flagged && !v.block, "{v:?}");
                assert_eq!(v.source, VerdictSource::Model);
            }
            other => panic!("{other:?}"),
        }
        let s = DomainScorer::from_parts(
            &one_split("brand_in_sub", 0.5),
            &meta(0.9, Some(0.95)),
            None,
        )
        .unwrap();
        match s.score("paypal.secure-check.com") {
            Scored::Verdict(v) => assert!(v.block),
            other => panic!("{other:?}"),
        }
        match s.score("blog.example.org") {
            Scored::Verdict(v) => assert!(!v.flagged && v.score < 0.05),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn loads_from_bundle_and_rejects_mismatches() {
        let d = tempfile::tempdir().unwrap();
        assert!(!DomainScorer::load(d.path()).unwrap().has_model());
        std::fs::create_dir_all(d.path().join("ml")).unwrap();
        std::fs::write(
            d.path().join(DOMAIN_MODEL_FILE),
            one_split("tld_abused", 0.5),
        )
        .unwrap();
        assert!(DomainScorer::load(d.path()).is_err(), "meta missing");
        let brands = "paypal paypal.com\n";
        std::fs::write(d.path().join(DOMAIN_BRANDS_FILE), brands).unwrap();
        std::fs::write(
            d.path().join(DOMAIN_TOP_FILE),
            "example.org\n# c\nbig-cdn.net\n",
        )
        .unwrap();
        let mut m = meta(0.9, None);
        m.brands_sha256 = Some(hex::encode(Sha256::digest(brands.as_bytes())));
        std::fs::write(
            d.path().join(DOMAIN_META_FILE),
            serde_json::to_string(&m).unwrap(),
        )
        .unwrap();
        let s = DomainScorer::load(d.path()).unwrap();
        assert!(s.has_model());
        assert_eq!(s.brands().len(), 1);
        assert_eq!(s.popular_count(), 2);
        assert!((s.block_threshold() - 0.9).abs() < 1e-6);
        assert_eq!(
            s.score("x.big-cdn.net"),
            Scored::Skipped("domaine populaire")
        );
        // Wrong brand list hash.
        m.brands_sha256 = Some("00".into());
        std::fs::write(
            d.path().join(DOMAIN_META_FILE),
            serde_json::to_string(&m).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            DomainScorer::load(d.path()),
            Err(MlError::FeatureMismatch(_))
        ));
        // Wrong feature version.
        let mut m = meta(0.9, None);
        m.features_version = FEATURES_VERSION + 1;
        std::fs::write(
            d.path().join(DOMAIN_META_FILE),
            serde_json::to_string(&m).unwrap(),
        )
        .unwrap();
        assert!(DomainScorer::load(d.path()).is_err());
        // Model over another layout.
        let m = meta(0.9, None);
        std::fs::write(
            d.path().join(DOMAIN_META_FILE),
            serde_json::to_string(&m).unwrap(),
        )
        .unwrap();
        std::fs::write(
            d.path().join(DOMAIN_MODEL_FILE),
            pb_ml::test_model_json("str_osascript", 0.5, -1.0, 1.0),
        )
        .unwrap();
        assert!(DomainScorer::load(d.path()).is_err());
    }
}
