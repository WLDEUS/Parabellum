//! The shipped ML models: LightGBM dump + calibrated threshold (+ optional probability
//! calibration), loaded from a threat-DB bundle.
//!
//! Bundle layout (see `pb_core::db`):
//! ```text
//! ml/macho_model.json          LightGBM Booster.dump_model() JSON (Mach-O features)
//! ml/model_meta.json           {"features_version":N,"threshold":f,"version":"…","metrics":{…},"calibration":{…}}
//! ml/script_model.json         same, script features (crate::script)
//! ml/script_model_meta.json    same shape
//! ```
//! `calibration` (optional): `{"method":"platt","a":f,"b":f}` maps the raw margin `m` (sum of the
//! leaves) to `1 / (1 + exp(-(a*m + b)))`; `{"method":"isotonic","x":[…],"y":[…]}` maps the model
//! probability through the piecewise-linear non-decreasing curve (clamped at both ends). Unknown
//! methods are ignored (the raw probability is used). The decision threshold always applies to the
//! *raw* probability; the calibrated value is only what the user sees as confidence.

use crate::{extract_features, GbdtModel, MlError, FEATURES_VERSION};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Mach-O model file, relative to the bundle root.
pub const MODEL_FILE: &str = "ml/macho_model.json";
/// Mach-O model metadata file, relative to the bundle root.
pub const MODEL_META_FILE: &str = "ml/model_meta.json";
/// Script model file, relative to the bundle root.
pub const SCRIPT_MODEL_FILE: &str = "ml/script_model.json";
/// Script model metadata file, relative to the bundle root.
pub const SCRIPT_MODEL_META_FILE: &str = "ml/script_model_meta.json";
/// Max size of the model JSON accepted.
const MAX_MODEL_BYTES: u64 = 64 * 1024 * 1024;
/// Max size of the metadata JSON accepted.
const MAX_META_BYTES: u64 = 1024 * 1024;
/// Max points of an isotonic calibration curve.
const MAX_ISOTONIC_POINTS: usize = 10_000;

/// Which file family a model scores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    /// Mach-O executables / libraries ([`crate::extract_features`]).
    #[serde(rename = "macho")]
    MachO,
    /// Shell / AppleScript / Python / JavaScript / Perl scripts ([`crate::extract_script_features`]).
    Script,
}

impl ModelKind {
    /// Machine name (`macho`, `script`).
    pub fn name(self) -> &'static str {
        match self {
            Self::MachO => "macho",
            Self::Script => "script",
        }
    }
    /// Model file relative to the bundle root.
    pub fn model_file(self) -> &'static str {
        match self {
            Self::MachO => MODEL_FILE,
            Self::Script => SCRIPT_MODEL_FILE,
        }
    }
    /// Metadata file relative to the bundle root.
    pub fn meta_file(self) -> &'static str {
        match self {
            Self::MachO => MODEL_META_FILE,
            Self::Script => SCRIPT_MODEL_META_FILE,
        }
    }
    /// Feature names compiled into this binary.
    pub fn feature_names(self) -> &'static [&'static str] {
        match self {
            Self::MachO => crate::feature_names(),
            Self::Script => crate::script_feature_names(),
        }
    }
    /// Feature layout version compiled into this binary.
    pub fn features_version(self) -> u32 {
        match self {
            Self::MachO => FEATURES_VERSION,
            Self::Script => crate::SCRIPT_FEATURES_VERSION,
        }
    }
}

/// `ml/model_meta.json` / `ml/script_model_meta.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMeta {
    /// Must equal the compiled-in layout version of the model kind.
    pub features_version: u32,
    /// Probability threshold (0 < t <= 1) at or above which a file is suspicious.
    pub threshold: f32,
    /// Model version label (e.g. training date); optional in older bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Free-form evaluation metrics recorded by the trainer.
    #[serde(default)]
    pub metrics: Value,
    /// Optional probability calibration (see the module docs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration: Option<Value>,
}

/// Probability calibration shipped in the metadata.
#[derive(Debug, Clone, PartialEq)]
pub enum Calibration {
    /// `1 / (1 + exp(-(a * margin + b)))`.
    Platt { a: f64, b: f64 },
    /// Piecewise-linear interpolation of the probability through `(x, y)`.
    Isotonic { x: Vec<f64>, y: Vec<f64> },
}

impl Calibration {
    /// Parses the `calibration` object. `Ok(None)` for an unknown method (forward compatibility),
    /// `Err` for a known method with invalid parameters.
    pub fn parse(v: &Value) -> Result<Option<Self>, MlError> {
        let bad = |m: &str| MlError::Model(format!("invalid calibration: {m}"));
        let method = v.get("method").and_then(Value::as_str).unwrap_or("");
        match method {
            "platt" => {
                let a = v.get("a").and_then(Value::as_f64).ok_or_else(|| bad("a"))?;
                let b = v.get("b").and_then(Value::as_f64).ok_or_else(|| bad("b"))?;
                if !(a.is_finite() && b.is_finite() && a > 0.0) {
                    return Err(bad("platt parameters must be finite with a > 0"));
                }
                Ok(Some(Self::Platt { a, b }))
            }
            "isotonic" => {
                let arr = |k: &str| -> Result<Vec<f64>, MlError> {
                    v.get(k)
                        .and_then(Value::as_array)
                        .ok_or_else(|| bad(k))?
                        .iter()
                        .map(|x| x.as_f64().filter(|f| f.is_finite()).ok_or_else(|| bad(k)))
                        .collect()
                };
                let (x, y) = (arr("x")?, arr("y")?);
                if x.is_empty() || x.len() != y.len() || x.len() > MAX_ISOTONIC_POINTS {
                    return Err(bad("x / y lengths"));
                }
                let sorted = |s: &[f64]| s.windows(2).all(|w| w[0] <= w[1]);
                if !sorted(&x) || !sorted(&y) || y.iter().any(|p| !(0.0..=1.0).contains(p)) {
                    return Err(bad("x and y must be non-decreasing, y in [0, 1]"));
                }
                Ok(Some(Self::Isotonic { x, y }))
            }
            _ => Ok(None),
        }
    }

    /// Method name (`platt`, `isotonic`).
    pub fn method(&self) -> &'static str {
        match self {
            Self::Platt { .. } => "platt",
            Self::Isotonic { .. } => "isotonic",
        }
    }

    /// Calibrated probability from the raw margin and the raw probability.
    pub fn apply(&self, margin: f64, probability: f32) -> f32 {
        let p = match self {
            Self::Platt { a, b } => 1.0 / (1.0 + (-(a * margin + b)).exp()),
            Self::Isotonic { x, y } => interpolate(x, y, f64::from(probability)),
        };
        if p.is_finite() {
            p.clamp(0.0, 1.0) as f32
        } else {
            probability
        }
    }
}

fn interpolate(x: &[f64], y: &[f64], v: f64) -> f64 {
    let (Some(&x0), Some(&xn)) = (x.first(), x.last()) else {
        return v;
    };
    if v <= x0 {
        return y[0];
    }
    if v >= xn {
        return y[y.len() - 1];
    }
    // First index with x[i] > v (exists since v < xn); i >= 1 since v > x0.
    let i = x.partition_point(|&xi| xi <= v);
    let (xa, xb, ya, yb) = (x[i - 1], x[i], y[i - 1], y[i]);
    if xb > xa {
        ya + (yb - ya) * (v - xa) / (xb - xa)
    } else {
        yb
    }
}

/// Result of scoring one file.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score {
    /// Raw model probability (what the threshold applies to).
    pub probability: f32,
    /// Calibrated probability (equals `probability` without calibration).
    pub calibrated: f32,
}

/// A loaded, version-checked model ready to score files of its [`ModelKind`].
#[derive(Debug, Clone)]
pub struct MlModel {
    kind: ModelKind,
    model: GbdtModel,
    threshold: f32,
    version: String,
    metrics: Value,
    calibration: Option<Calibration>,
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

impl MlModel {
    /// Loads the Mach-O model (`ml/macho_model.json` + `ml/model_meta.json`) from the bundle `dir`.
    ///
    /// `Ok(None)` when neither file exists (bundle without a model). Errors when only one exists,
    /// when the feature layout or version differs from this binary, or when the model is invalid.
    pub fn load(dir: &Path) -> Result<Option<Self>, MlError> {
        Self::load_kind(dir, ModelKind::MachO)
    }

    /// Loads the script model (`ml/script_model.json` + `ml/script_model_meta.json`); same rules.
    pub fn load_script(dir: &Path) -> Result<Option<Self>, MlError> {
        Self::load_kind(dir, ModelKind::Script)
    }

    /// Loads the model of `kind` from the bundle directory `dir`.
    pub fn load_kind(dir: &Path, kind: ModelKind) -> Result<Option<Self>, MlError> {
        let model_path = dir.join(kind.model_file());
        let meta_path = dir.join(kind.meta_file());
        match (model_path.is_file(), meta_path.is_file()) {
            (false, false) => return Ok(None),
            (true, false) => {
                return Err(MlError::Model(format!(
                    "{} is missing",
                    meta_path.display()
                )))
            }
            (false, true) => {
                return Err(MlError::Model(format!(
                    "{} is missing",
                    model_path.display()
                )))
            }
            (true, true) => {}
        }
        let meta: ModelMeta = serde_json::from_str(&read_bounded(&meta_path, MAX_META_BYTES)?)?;
        let json = read_bounded(&model_path, MAX_MODEL_BYTES)?;
        let version = meta
            .version
            .clone()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                let digest = Sha256::digest(json.as_bytes());
                format!("sha256:{}", &hex::encode(digest)[..12])
            });
        Self::from_parts_kind(kind, &json, &meta, version).map(Some)
    }

    /// Builds a Mach-O model from an in-memory dump and metadata.
    pub fn from_parts(json: &str, meta: &ModelMeta, version: String) -> Result<Self, MlError> {
        Self::from_parts_kind(ModelKind::MachO, json, meta, version)
    }

    /// Builds a model of `kind` from an in-memory dump and metadata.
    pub fn from_parts_kind(
        kind: ModelKind,
        json: &str,
        meta: &ModelMeta,
        version: String,
    ) -> Result<Self, MlError> {
        if meta.features_version != kind.features_version() {
            return Err(MlError::FeatureMismatch(format!(
                "{} model trained on features v{}, binary computes v{}",
                kind.name(),
                meta.features_version,
                kind.features_version()
            )));
        }
        if !(meta.threshold > 0.0 && meta.threshold <= 1.0) {
            return Err(MlError::Model(format!(
                "threshold {} out of (0, 1]",
                meta.threshold
            )));
        }
        let calibration = match &meta.calibration {
            Some(v) => Calibration::parse(v)?,
            None => None,
        };
        let model = GbdtModel::from_json_with_names(json, kind.feature_names())?;
        Ok(Self {
            kind,
            model,
            threshold: meta.threshold,
            version,
            metrics: meta.metrics.clone(),
            calibration,
        })
    }

    /// What this model scores.
    pub fn kind(&self) -> ModelKind {
        self.kind
    }

    /// Calibrated threshold from the metadata.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Model version label.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Trainer metrics from the metadata (free-form JSON object, `Null` when absent).
    pub fn metrics(&self) -> &Value {
        &self.metrics
    }

    /// Probability calibration, if the metadata provides a known one.
    pub fn calibration(&self) -> Option<&Calibration> {
        self.calibration.as_ref()
    }

    /// Underlying tree ensemble.
    pub fn gbdt(&self) -> &GbdtModel {
        &self.model
    }

    /// Raw + calibrated probability for an already-extracted feature vector.
    pub fn score_features_detailed(&self, features: &[f32]) -> Score {
        let margin = self.model.predict_raw(features);
        let probability = self.model.predict_proba(features);
        let calibrated = self
            .calibration
            .as_ref()
            .map_or(probability, |c| c.apply(margin, probability));
        Score {
            probability,
            calibrated,
        }
    }

    /// Probability that `bytes` (a Mach-O) is malicious; `None` if it is not a parsable Mach-O or
    /// this is not a Mach-O model.
    pub fn score(&self, bytes: &[u8]) -> Option<f32> {
        self.score_detailed(bytes).map(|s| s.probability)
    }

    /// Like [`MlModel::score`], with the calibrated probability.
    pub fn score_detailed(&self, bytes: &[u8]) -> Option<Score> {
        if self.kind != ModelKind::MachO {
            return None;
        }
        let features = extract_features(bytes).ok()?;
        Some(self.score_features_detailed(&features))
    }

    /// Scores a script (`path` gives the extension used for type detection); `None` when `bytes`
    /// is not recognised as a script or this is not a script model.
    pub fn score_script(&self, bytes: &[u8], path: Option<&Path>) -> Option<Score> {
        if self.kind != ModelKind::Script {
            return None;
        }
        let features = crate::extract_script_features(bytes, path).ok()?;
        Some(self.score_features_detailed(&features))
    }

    /// Probability for an already-extracted feature vector.
    pub fn score_features(&self, features: &[f32]) -> f32 {
        self.model.predict_proba(features)
    }
}

/// Test helper: a valid single-split dump over the real feature layout, splitting on `feature`.
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub fn test_model_json(feature: &str, threshold: f64, left: f64, right: f64) -> String {
    test_model_json_for(crate::feature_names(), feature, threshold, left, right)
}

/// Test helper: like [`test_model_json`] over an explicit feature layout (e.g. the script one).
#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub fn test_model_json_for(
    names: &[&str],
    feature: &str,
    threshold: f64,
    left: f64,
    right: f64,
) -> String {
    let idx = names.iter().position(|n| *n == feature).unwrap_or(0);
    serde_json::json!({
        "name": "tree", "version": "v4", "num_class": 1, "num_tree_per_iteration": 1, "label_index": 0,
        "max_feature_idx": names.len() - 1, "objective": "binary sigmoid:1", "average_output": false,
        "feature_names": names,
        "tree_info": [{
            "tree_index": 0, "num_leaves": 2, "num_cat": 0, "shrinkage": 1,
            "tree_structure": {
                "split_index": 0, "split_feature": idx, "split_gain": 1.0, "threshold": threshold,
                "decision_type": "<=", "default_left": true, "missing_type": "None",
                "internal_value": 0, "internal_weight": 0, "internal_count": 2,
                "left_child": {"leaf_index": 0, "leaf_value": left, "leaf_weight": 1, "leaf_count": 1},
                "right_child": {"leaf_index": 1, "leaf_value": right, "leaf_weight": 1, "leaf_count": 1}
            }
        }]
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MachOBuilder;

    fn write_bundle(dir: &Path, json: &str, meta: &str) {
        std::fs::create_dir_all(dir.join("ml")).unwrap();
        std::fs::write(dir.join(MODEL_FILE), json).unwrap();
        std::fs::write(dir.join(MODEL_META_FILE), meta).unwrap();
    }

    #[test]
    fn absent_model_is_none() {
        let d = tempfile::tempdir().unwrap();
        assert!(MlModel::load(d.path()).unwrap().is_none());
        std::fs::create_dir_all(d.path().join("ml")).unwrap();
        std::fs::write(d.path().join(MODEL_FILE), "{}").unwrap();
        assert!(MlModel::load(d.path()).is_err());
    }

    #[test]
    fn loads_and_scores() {
        let d = tempfile::tempdir().unwrap();
        // str_osascript <= 0.5 -> -3 (benign), else +3 (malicious)
        let json = test_model_json("str_osascript", 0.5, -3.0, 3.0);
        write_bundle(
            d.path(),
            &json,
            &format!(
                r#"{{"features_version":{FEATURES_VERSION},"threshold":0.9,"version":"2026.10.25","metrics":{{"auc":0.99}}}}"#
            ),
        );
        let m = MlModel::load(d.path()).unwrap().unwrap();
        assert_eq!(m.version(), "2026.10.25");
        assert!((m.threshold() - 0.9).abs() < 1e-6);
        let bad = MachOBuilder::new_arm64_execute()
            .cstrings(&["osascript -e"])
            .build();
        let good = MachOBuilder::new_arm64_execute()
            .cstrings(&["hello"])
            .build();
        assert!(m.score(&bad).unwrap() > 0.95);
        assert!(m.score(&good).unwrap() < 0.05);
        assert!(m.score(b"#!/bin/sh\n").is_none());
    }

    #[test]
    fn version_falls_back_to_digest_and_rejects_layout_mismatch() {
        let d = tempfile::tempdir().unwrap();
        let json = test_model_json("str_osascript", 0.5, -3.0, 3.0);
        write_bundle(
            d.path(),
            &json,
            &format!(r#"{{"features_version":{FEATURES_VERSION},"threshold":0.8}}"#),
        );
        assert!(MlModel::load(d.path())
            .unwrap()
            .unwrap()
            .version()
            .starts_with("sha256:"));
        write_bundle(
            d.path(),
            &json,
            &format!(
                r#"{{"features_version":{},"threshold":0.8}}"#,
                FEATURES_VERSION + 1
            ),
        );
        assert!(matches!(
            MlModel::load(d.path()),
            Err(MlError::FeatureMismatch(_))
        ));
        write_bundle(
            d.path(),
            &json,
            &format!(r#"{{"features_version":{FEATURES_VERSION},"threshold":1.5}}"#),
        );
        assert!(MlModel::load(d.path()).is_err());
    }

    #[test]
    fn calibration_parsing_and_application() {
        let platt = Calibration::parse(&serde_json::json!({"method":"platt","a":0.5,"b":-1.0}))
            .unwrap()
            .unwrap();
        assert_eq!(platt.method(), "platt");
        let expected = 1.0 / (1.0 + (-(0.5f64 * 2.0 - 1.0)).exp());
        assert!((f64::from(platt.apply(2.0, 0.9)) - expected).abs() < 1e-6);
        let iso = Calibration::parse(
            &serde_json::json!({"method":"isotonic","x":[0.1,0.5,0.9],"y":[0.0,0.2,0.8]}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(iso.apply(0.0, 0.05), 0.0);
        assert!((iso.apply(0.0, 0.7) - 0.5).abs() < 1e-6);
        assert!((iso.apply(0.0, 0.99) - 0.8).abs() < 1e-6);
        // Unknown method: ignored. Invalid parameters: rejected.
        assert!(Calibration::parse(&serde_json::json!({"method":"beta"}))
            .unwrap()
            .is_none());
        for bad in [
            serde_json::json!({"method":"platt","a":-1.0,"b":0.0}),
            serde_json::json!({"method":"isotonic","x":[0.5,0.1],"y":[0.0,1.0]}),
            serde_json::json!({"method":"isotonic","x":[0.1],"y":[1.5]}),
            serde_json::json!({"method":"isotonic","x":[0.1,0.2],"y":[0.1]}),
        ] {
            assert!(Calibration::parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn script_model_loads_scores_and_is_independent() {
        let d = tempfile::tempdir().unwrap();
        // No script model: Ok(None), and a Mach-O model alone does not create one.
        assert!(MlModel::load_script(d.path()).unwrap().is_none());
        std::fs::create_dir_all(d.path().join("ml")).unwrap();
        let json = test_model_json_for(
            crate::script_feature_names(),
            "ind_keychain",
            0.5,
            -3.0,
            3.0,
        );
        std::fs::write(d.path().join(SCRIPT_MODEL_FILE), &json).unwrap();
        std::fs::write(
            d.path().join(SCRIPT_MODEL_META_FILE),
            format!(
                r#"{{"features_version":{},"threshold":0.9,"version":"s-1","metrics":{{"pr_auc":0.9}},"calibration":{{"method":"platt","a":1.0,"b":-2.0}}}}"#,
                crate::SCRIPT_FEATURES_VERSION
            ),
        )
        .unwrap();
        assert!(MlModel::load(d.path()).unwrap().is_none());
        let m = MlModel::load_script(d.path()).unwrap().unwrap();
        assert_eq!(m.kind(), ModelKind::Script);
        assert_eq!(m.version(), "s-1");
        assert_eq!(m.metrics()["pr_auc"], 0.9);
        assert_eq!(m.calibration().map(Calibration::method), Some("platt"));
        // TEST STRING: shaped like a keychain dump, harmless.
        let bad = b"#!/bin/sh\nsecurity find-generic-password -ga test-fixture\n";
        let s = m.score_script(bad, None).unwrap();
        assert!(s.probability > 0.95);
        assert!((f64::from(s.calibrated) - 1.0 / (1.0 + (-(3.0f64 - 2.0)).exp())).abs() < 1e-6);
        let good = m.score_script(b"#!/bin/sh\necho hello\n", None).unwrap();
        assert!(good.probability < 0.05);
        assert!(m.score_script(b"\x00\x01", None).is_none());
        // Kinds do not cross: a script model never scores Mach-O and vice versa.
        assert!(m
            .score(&MachOBuilder::new_arm64_execute().build())
            .is_none());
        // Mach-O layout dump under the script name is rejected.
        std::fs::write(
            d.path().join(SCRIPT_MODEL_FILE),
            test_model_json("str_osascript", 0.5, -3.0, 3.0),
        )
        .unwrap();
        assert!(matches!(
            MlModel::load_script(d.path()),
            Err(MlError::FeatureMismatch(_))
        ));
    }
}
