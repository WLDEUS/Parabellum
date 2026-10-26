//! The shipped ML model: LightGBM dump + calibrated threshold, loaded from a threat-DB bundle.
//!
//! Bundle layout (see `pb_core::db`):
//! ```text
//! ml/macho_model.json   LightGBM Booster.dump_model() JSON
//! ml/model_meta.json    {"features_version":N,"threshold":f,"version":"…","metrics":{…}}
//! ```

use crate::{extract_features, GbdtModel, MlError, FEATURES_VERSION};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Model file, relative to the bundle root.
pub const MODEL_FILE: &str = "ml/macho_model.json";
/// Model metadata file, relative to the bundle root.
pub const MODEL_META_FILE: &str = "ml/model_meta.json";
/// Max size of the model JSON accepted.
const MAX_MODEL_BYTES: u64 = 64 * 1024 * 1024;
/// Max size of the metadata JSON accepted.
const MAX_META_BYTES: u64 = 1024 * 1024;

/// `ml/model_meta.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelMeta {
    /// Must equal [`FEATURES_VERSION`].
    pub features_version: u32,
    /// Calibrated probability threshold (0 < t <= 1) above which a Mach-O is suspicious.
    pub threshold: f32,
    /// Model version label (e.g. training date); optional in older bundles.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Free-form evaluation metrics recorded by the trainer.
    #[serde(default)]
    pub metrics: serde_json::Value,
}

/// A loaded, version-checked model ready to score Mach-O files.
#[derive(Debug, Clone)]
pub struct MlModel {
    model: GbdtModel,
    threshold: f32,
    version: String,
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
    /// Loads `ml/macho_model.json` + `ml/model_meta.json` from the bundle directory `dir`.
    ///
    /// `Ok(None)` when neither file exists (bundle without a model). Errors when only one exists,
    /// when the feature layout or version differs from this binary, or when the model is invalid.
    pub fn load(dir: &Path) -> Result<Option<Self>, MlError> {
        let model_path = dir.join(MODEL_FILE);
        let meta_path = dir.join(MODEL_META_FILE);
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
        Self::from_parts(&json, &meta, version).map(Some)
    }

    /// Builds a model from an in-memory dump and metadata.
    pub fn from_parts(json: &str, meta: &ModelMeta, version: String) -> Result<Self, MlError> {
        if meta.features_version != FEATURES_VERSION {
            return Err(MlError::FeatureMismatch(format!(
                "model trained on features v{}, binary computes v{FEATURES_VERSION}",
                meta.features_version
            )));
        }
        if !(meta.threshold > 0.0 && meta.threshold <= 1.0) {
            return Err(MlError::Model(format!(
                "threshold {} out of (0, 1]",
                meta.threshold
            )));
        }
        let model = GbdtModel::from_json(json)?;
        Ok(Self {
            model,
            threshold: meta.threshold,
            version,
        })
    }

    /// Calibrated threshold from the metadata.
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    /// Model version label.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Underlying tree ensemble.
    pub fn gbdt(&self) -> &GbdtModel {
        &self.model
    }

    /// Probability that `bytes` (a Mach-O) is malicious; `None` if it is not a parsable Mach-O.
    pub fn score(&self, bytes: &[u8]) -> Option<f32> {
        let features = extract_features(bytes).ok()?;
        Some(self.model.predict_proba(&features))
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
    let names = crate::feature_names();
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
}
