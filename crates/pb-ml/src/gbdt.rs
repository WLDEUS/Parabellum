//! Evaluation of LightGBM models exported with `Booster.dump_model()` (JSON).
//!
//! Supported: `num_class == 1` boosted trees (`gbdt`, `goss`, `dart`; `rf` through `average_output`)
//! with numerical splits, objectives `binary sigmoid:<s>` and `cross_entropy`. Rejected: categorical
//! splits (`decision_type == "=="`), linear trees, multiclass, other objectives.
//!
//! Prediction follows LightGBM's `Tree::NumericalDecision` exactly:
//! ```text
//! if isnan(x) && missing_type != NaN: x = 0
//! if (missing_type == Zero && |x| <= 1e-35f) || (missing_type == NaN && isnan(x)):
//!     go default_left ? left : right
//! else go x <= threshold ? left : right
//! ```
//! Features absent from the input slice are treated as NaN. Comparisons are done in `f64`, like
//! LightGBM (`f32` inputs are widened exactly).

use crate::MlError;
use serde_json::Value;

/// Max trees accepted in a model.
pub const MAX_TREES: usize = 20_000;
/// Max depth of a tree (deeper JSON would also exceed serde_json's recursion limit).
pub const MAX_DEPTH: usize = 100;
/// Max nodes (splits + leaves) in one tree.
pub const MAX_NODES_PER_TREE: usize = 1 << 17;
/// LightGBM's `kZeroThreshold` (`1e-35f` widened to double).
const ZERO_THRESHOLD: f64 = 1e-35_f32 as f64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissingType {
    None,
    Zero,
    NaN,
}

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Split {
        feature: u32,
        threshold: f64,
        default_left: bool,
        missing: MissingType,
        left: u32,
        right: u32,
    },
    Leaf(f64),
}

#[derive(Debug, Clone, PartialEq)]
struct Tree {
    /// Pre-order: children always have a larger index than their parent, so traversal terminates.
    nodes: Vec<Node>,
}

impl Tree {
    fn eval(&self, x: &[f32]) -> f64 {
        let mut i = 0usize;
        // Each step strictly increases `i`, so at most `nodes.len()` iterations.
        for _ in 0..=self.nodes.len() {
            match self.nodes.get(i) {
                Some(Node::Leaf(v)) => return *v,
                Some(Node::Split {
                    feature,
                    threshold,
                    default_left,
                    missing,
                    left,
                    right,
                }) => {
                    let mut fval = x.get(*feature as usize).map_or(f64::NAN, |v| f64::from(*v));
                    if fval.is_nan() && *missing != MissingType::NaN {
                        fval = 0.0;
                    }
                    let go_left = if (*missing == MissingType::Zero
                        && (-ZERO_THRESHOLD..=ZERO_THRESHOLD).contains(&fval))
                        || (*missing == MissingType::NaN && fval.is_nan())
                    {
                        *default_left
                    } else {
                        fval <= *threshold
                    };
                    let next = if go_left { *left } else { *right } as usize;
                    if next <= i {
                        return 0.0; // cannot happen with trees built by `parse_tree`
                    }
                    i = next;
                }
                None => return 0.0,
            }
        }
        0.0
    }
}

/// A LightGBM binary classifier loaded from a `dump_model()` JSON document.
#[derive(Debug, Clone, PartialEq)]
pub struct GbdtModel {
    trees: Vec<Tree>,
    sigmoid: f64,
    average_output: bool,
    num_features: usize,
}

impl GbdtModel {
    /// Parses a LightGBM JSON dump. Fails unless `feature_names` equals [`crate::feature_names`]
    /// exactly (same names, same order), so a model trained on another layout can never be used.
    pub fn from_json(json: &str) -> Result<Self, MlError> {
        Self::from_json_with_names(json, crate::feature_names())
    }

    /// Like [`GbdtModel::from_json`] but checks against an explicit feature-name list.
    pub fn from_json_with_names(json: &str, expected_names: &[&str]) -> Result<Self, MlError> {
        let v: Value = serde_json::from_str(json)?;
        let obj = v
            .as_object()
            .ok_or_else(|| MlError::Model("top level is not an object".into()))?;

        let names: Vec<&str> = obj
            .get("feature_names")
            .and_then(Value::as_array)
            .ok_or_else(|| MlError::Model("missing feature_names".into()))?
            .iter()
            .map(|n| n.as_str().unwrap_or(""))
            .collect();
        if names != expected_names {
            let first_diff = names.iter().zip(expected_names).position(|(a, b)| a != b);
            return Err(MlError::FeatureMismatch(format!(
                "model has {} features, binary expects {} (first difference at index {:?})",
                names.len(),
                expected_names.len(),
                first_diff
            )));
        }
        if let Some(mfi) = obj.get("max_feature_idx").and_then(Value::as_i64) {
            if mfi + 1 != expected_names.len() as i64 {
                return Err(MlError::FeatureMismatch(format!(
                    "max_feature_idx {mfi} does not match feature count"
                )));
            }
        }
        let num_class = obj.get("num_class").and_then(Value::as_i64).unwrap_or(1);
        let per_iter = obj
            .get("num_tree_per_iteration")
            .and_then(Value::as_i64)
            .unwrap_or(1);
        if num_class != 1 || per_iter != 1 {
            return Err(MlError::Model(format!(
                "only binary models are supported (num_class={num_class})"
            )));
        }
        let objective = obj.get("objective").and_then(Value::as_str).unwrap_or("");
        let sigmoid = parse_objective(objective)?;
        let average_output = obj
            .get("average_output")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let infos = obj
            .get("tree_info")
            .and_then(Value::as_array)
            .ok_or_else(|| MlError::Model("missing tree_info".into()))?;
        if infos.is_empty() {
            return Err(MlError::Model("model has no trees".into()));
        }
        if infos.len() > MAX_TREES {
            return Err(MlError::Model(format!("too many trees ({})", infos.len())));
        }
        if infos
            .iter()
            .any(|t| t.get("num_cat").and_then(Value::as_i64).unwrap_or(0) > 0)
        {
            return Err(MlError::Model(
                "categorical splits are not supported".into(),
            ));
        }
        let trees = infos
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let root = t
                    .get("tree_structure")
                    .ok_or_else(|| MlError::Model(format!("tree {i}: missing tree_structure")))?;
                parse_tree(root, expected_names.len())
                    .map_err(|e| MlError::Model(format!("tree {i}: {e}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            trees,
            sigmoid,
            average_output,
            num_features: expected_names.len(),
        })
    }

    /// Number of trees.
    pub fn num_trees(&self) -> usize {
        self.trees.len()
    }

    /// Number of input features expected.
    pub fn num_features(&self) -> usize {
        self.num_features
    }

    /// Raw score (sum of leaf values, averaged for random-forest models).
    pub fn predict_raw(&self, features: &[f32]) -> f64 {
        let sum: f64 = self.trees.iter().map(|t| t.eval(features)).sum();
        if self.average_output {
            sum / self.trees.len() as f64
        } else {
            sum
        }
    }

    /// Probability of the positive (malicious) class: `1 / (1 + exp(-sigmoid * raw))`.
    pub fn predict_proba(&self, features: &[f32]) -> f32 {
        let raw = self.predict_raw(features);
        let p = 1.0 / (1.0 + (-self.sigmoid * raw).exp());
        if p.is_nan() {
            0.0
        } else {
            p as f32
        }
    }
}

fn parse_objective(objective: &str) -> Result<f64, MlError> {
    let mut parts = objective.split_whitespace();
    match parts.next() {
        Some("binary") => {
            let mut sigmoid = 1.0;
            for p in parts {
                if let Some(v) = p.strip_prefix("sigmoid:") {
                    sigmoid = v
                        .parse::<f64>()
                        .map_err(|_| MlError::Model(format!("bad sigmoid in {objective:?}")))?;
                }
            }
            if !(sigmoid.is_finite() && sigmoid > 0.0) {
                return Err(MlError::Model(format!("bad sigmoid in {objective:?}")));
            }
            Ok(sigmoid)
        }
        Some("cross_entropy") | Some("xentropy") => Ok(1.0),
        _ => Err(MlError::Model(format!(
            "unsupported objective {objective:?}"
        ))),
    }
}

/// Flattens one `tree_structure` into pre-order nodes, iteratively.
fn parse_tree(root: &Value, num_features: usize) -> Result<Tree, String> {
    let mut nodes: Vec<Node> = Vec::new();
    /// (json node, depth, parent index + is_left)
    type Pending<'v> = (&'v Value, usize, Option<(usize, bool)>);
    let mut stack: Vec<Pending<'_>> = vec![(root, 0, None)];
    while let Some((v, depth, parent)) = stack.pop() {
        if depth > MAX_DEPTH {
            return Err(format!("tree deeper than {MAX_DEPTH}"));
        }
        if nodes.len() >= MAX_NODES_PER_TREE {
            return Err("too many nodes".into());
        }
        let idx = nodes.len();
        if let Some((p, is_left)) = parent {
            match nodes.get_mut(p) {
                Some(Node::Split { left, right, .. }) => {
                    if is_left {
                        *left = idx as u32;
                    } else {
                        *right = idx as u32;
                    }
                }
                _ => return Err("internal: parent is not a split".into()),
            }
        }
        let o = v.as_object().ok_or("node is not an object")?;
        if o.contains_key("split_feature") {
            let decision = o
                .get("decision_type")
                .and_then(Value::as_str)
                .unwrap_or("<=");
            if decision != "<=" {
                return Err(format!(
                    "unsupported decision_type {decision:?} (categorical)"
                ));
            }
            let feature = o
                .get("split_feature")
                .and_then(Value::as_u64)
                .ok_or("bad split_feature")?;
            if feature as usize >= num_features {
                return Err(format!("split_feature {feature} out of range"));
            }
            let threshold = o
                .get("threshold")
                .and_then(Value::as_f64)
                .ok_or("bad threshold")?;
            let default_left = o
                .get("default_left")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let missing = match o
                .get("missing_type")
                .and_then(Value::as_str)
                .unwrap_or("None")
            {
                "None" => MissingType::None,
                "Zero" => MissingType::Zero,
                "NaN" => MissingType::NaN,
                other => return Err(format!("unknown missing_type {other:?}")),
            };
            let left = o.get("left_child").ok_or("missing left_child")?;
            let right = o.get("right_child").ok_or("missing right_child")?;
            nodes.push(Node::Split {
                feature: feature as u32,
                threshold,
                default_left,
                missing,
                left: 0,
                right: 0,
            });
            stack.push((right, depth + 1, Some((idx, false))));
            stack.push((left, depth + 1, Some((idx, true))));
        } else if let Some(value) = o.get("leaf_value").and_then(Value::as_f64) {
            if o.get("leaf_coeff")
                .and_then(Value::as_array)
                .is_some_and(|c| !c.is_empty())
            {
                return Err("linear trees are not supported".into());
            }
            if !value.is_finite() {
                return Err("non-finite leaf value".into());
            }
            nodes.push(Node::Leaf(value));
        } else {
            return Err("node is neither a split nor a leaf".into());
        }
    }
    // Every split must have received both children.
    for n in &nodes {
        if let Node::Split { left, right, .. } = n {
            if *left == 0 || *right == 0 {
                return Err("split without children".into());
            }
        }
    }
    Ok(Tree { nodes })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAMES: &[&str] = &["a", "b", "c"];

    /// Hand-written dump (shape produced by LightGBM 4.x `dump_model()`).
    fn dump() -> String {
        r#"{
          "name": "tree", "version": "v4", "num_class": 1, "num_tree_per_iteration": 1, "label_index": 0,
          "max_feature_idx": 2, "objective": "binary sigmoid:1", "average_output": false,
          "feature_names": ["a", "b", "c"], "monotone_constraints": [], "feature_infos": {},
          "tree_info": [
            {"tree_index": 0, "num_leaves": 3, "num_cat": 0, "shrinkage": 1,
             "tree_structure": {
               "split_index": 0, "split_feature": 0, "split_gain": 10, "threshold": 0.5,
               "decision_type": "<=", "default_left": true, "missing_type": "NaN",
               "internal_value": 0, "internal_weight": 0, "internal_count": 100,
               "left_child": {"leaf_index": 0, "leaf_value": -1.0, "leaf_weight": 1, "leaf_count": 50},
               "right_child": {
                 "split_index": 1, "split_feature": 1, "split_gain": 5, "threshold": 2.0,
                 "decision_type": "<=", "default_left": false, "missing_type": "Zero",
                 "internal_value": 0, "internal_weight": 0, "internal_count": 50,
                 "left_child": {"leaf_index": 1, "leaf_value": 0.5, "leaf_weight": 1, "leaf_count": 25},
                 "right_child": {"leaf_index": 2, "leaf_value": 2.0, "leaf_weight": 1, "leaf_count": 25}
               }
             }},
            {"tree_index": 1, "num_leaves": 2, "num_cat": 0, "shrinkage": 0.1,
             "tree_structure": {
               "split_index": 0, "split_feature": 2, "split_gain": 1, "threshold": 1.0e-35,
               "decision_type": "<=", "default_left": true, "missing_type": "None",
               "internal_value": 0, "internal_weight": 0, "internal_count": 100,
               "left_child": {"leaf_index": 0, "leaf_value": 0.25, "leaf_weight": 1, "leaf_count": 50},
               "right_child": {"leaf_index": 1, "leaf_value": -0.25, "leaf_weight": 1, "leaf_count": 50}
             }},
            {"tree_index": 2, "num_leaves": 1, "num_cat": 0, "shrinkage": 1,
             "tree_structure": {"leaf_value": 0.125, "leaf_count": 100}}
          ],
          "feature_importances": {}, "pandas_categorical": null
        }"#
        .to_string()
    }

    fn model() -> GbdtModel {
        GbdtModel::from_json_with_names(&dump(), NAMES).unwrap()
    }

    #[test]
    fn evaluates_with_lightgbm_missing_semantics() {
        let m = model();
        assert_eq!(m.num_trees(), 3);
        let nan = f32::NAN;
        // tree0: a=0.2 -> left (-1.0); tree1: c=0 -> 0 <= 1e-35 -> left (0.25); tree2: 0.125
        assert!((m.predict_raw(&[0.2, 9.0, 0.0]) - (-1.0 + 0.25 + 0.125)).abs() < 1e-12);
        // a = NaN with missing NaN, default_left -> left
        assert!((m.predict_raw(&[nan, 9.0, 5.0]) - (-1.0 - 0.25 + 0.125)).abs() < 1e-12);
        // a=1 -> right; b=0 with missing Zero & default_left=false -> right (2.0) even though 0 <= 2
        assert!((m.predict_raw(&[1.0, 0.0, 5.0]) - (2.0 - 0.25 + 0.125)).abs() < 1e-12);
        // b = NaN with missing Zero -> NaN becomes 0 -> zero -> default right (2.0)
        assert!((m.predict_raw(&[1.0, nan, 5.0]) - (2.0 - 0.25 + 0.125)).abs() < 1e-12);
        // b = 1.5 -> regular comparison -> left (0.5)
        assert!((m.predict_raw(&[1.0, 1.5, 5.0]) - (0.5 - 0.25 + 0.125)).abs() < 1e-12);
        // c = NaN with missing None -> treated as 0 -> left (0.25)
        assert!((m.predict_raw(&[1.0, 1.5, nan]) - (0.5 + 0.25 + 0.125)).abs() < 1e-12);
        // missing features (short slice) are NaN
        assert!((m.predict_raw(&[1.0]) - (2.0 + 0.25 + 0.125)).abs() < 1e-12);
        let p = m.predict_proba(&[1.0, 1.5, 5.0]);
        let expected = 1.0 / (1.0 + (-(0.5f64 - 0.25 + 0.125)).exp());
        assert!((f64::from(p) - expected).abs() < 1e-6);
    }

    #[test]
    fn sigmoid_parameter_and_average_output() {
        let j = dump()
            .replace("binary sigmoid:1", "binary sigmoid:2")
            .replace("\"average_output\": false", "\"average_output\": true");
        let m = GbdtModel::from_json_with_names(&j, NAMES).unwrap();
        let raw = (0.5 - 0.25 + 0.125) / 3.0;
        assert!((m.predict_raw(&[1.0, 1.5, 5.0]) - raw).abs() < 1e-12);
        let expected = 1.0 / (1.0 + (-2.0 * raw).exp());
        assert!((f64::from(m.predict_proba(&[1.0, 1.5, 5.0])) - expected).abs() < 1e-6);
    }

    #[test]
    fn rejects_feature_mismatch() {
        let err = GbdtModel::from_json_with_names(&dump(), &["a", "b", "x"]).unwrap_err();
        assert!(matches!(err, MlError::FeatureMismatch(_)));
        let err = GbdtModel::from_json_with_names(&dump(), &["a", "b"]).unwrap_err();
        assert!(matches!(err, MlError::FeatureMismatch(_)));
        // And against the real compiled-in layout.
        assert!(matches!(
            GbdtModel::from_json(&dump()),
            Err(MlError::FeatureMismatch(_))
        ));
    }

    #[test]
    fn rejects_unsupported_models() {
        let cat = dump().replacen("\"decision_type\": \"<=\"", "\"decision_type\": \"==\"", 1);
        assert!(GbdtModel::from_json_with_names(&cat, NAMES).is_err());
        let multi = dump().replace("\"num_class\": 1", "\"num_class\": 3");
        assert!(GbdtModel::from_json_with_names(&multi, NAMES).is_err());
        let reg = dump().replace("binary sigmoid:1", "regression");
        assert!(GbdtModel::from_json_with_names(&reg, NAMES).is_err());
        let oob = dump().replace("\"split_feature\": 2", "\"split_feature\": 7");
        assert!(GbdtModel::from_json_with_names(&oob, NAMES).is_err());
        let linear = dump().replace(
            "\"leaf_value\": 0.125, \"leaf_count\": 100",
            "\"leaf_value\": 0.125, \"leaf_count\": 100, \"leaf_coeff\": [1.0]",
        );
        assert!(GbdtModel::from_json_with_names(&linear, NAMES).is_err());
        assert!(GbdtModel::from_json_with_names("{}", NAMES).is_err());
        assert!(GbdtModel::from_json_with_names("[1,2", NAMES).is_err());
    }

    #[test]
    fn deep_tree_is_rejected_not_overflowing() {
        // Build a degenerate chain deeper than MAX_DEPTH (but within serde_json's recursion limit
        // is not guaranteed — either error is fine, no panic / stack overflow).
        let mut node = r#"{"leaf_value": 1.0}"#.to_string();
        for _ in 0..(MAX_DEPTH + 5) {
            node = format!(
                r#"{{"split_feature":0,"threshold":0.5,"decision_type":"<=","default_left":true,"missing_type":"None","left_child":{node},"right_child":{{"leaf_value":0.0}}}}"#
            );
        }
        let j = format!(
            r#"{{"num_class":1,"num_tree_per_iteration":1,"max_feature_idx":2,"objective":"binary sigmoid:1","feature_names":["a","b","c"],"tree_info":[{{"num_cat":0,"tree_structure":{node}}}]}}"#
        );
        assert!(GbdtModel::from_json_with_names(&j, NAMES).is_err());
    }
}
