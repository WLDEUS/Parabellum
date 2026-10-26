"""LightGBM training, threshold selection, metrics, promotion gate and export (``pb_ml`` contract)."""

from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path

import lightgbm as lgb
import numpy as np

from .dump_eval import MAX_TREES, DumpModel
from .features import FeatureRow

#: Hash buckets (first 32 bits of the SHA-256 mod 100). Assignment depends on the sample only, so it
#: is stable week after week: a holdout sample never leaks into training. Independent of the label,
#: hence stratified in expectation (both classes are split 20/15/65).
HOLDOUT_BUCKETS = range(0, 20)
VALID_BUCKETS = range(20, 35)
MAX_FPR = 0.001
SEED = 1337


def bucket(sha256: str) -> int:
    return int(sha256[:8], 16) % 100


def split(rows: list[FeatureRow]) -> tuple[list[FeatureRow], list[FeatureRow], list[FeatureRow]]:
    train, valid, hold = [], [], []
    for r in rows:
        b = bucket(r.sha256)
        (hold if b in HOLDOUT_BUCKETS else valid if b in VALID_BUCKETS else train).append(r)
    return train, valid, hold


def matrix(rows: list[FeatureRow]) -> tuple[np.ndarray, np.ndarray]:
    x = np.array([r.features for r in rows], dtype=np.float32).reshape(len(rows), -1)
    y = np.array([r.label for r in rows], dtype=np.int32)
    return x.astype(np.float64), y


def roc_auc(y: np.ndarray, s: np.ndarray) -> float:
    """Mann-Whitney AUC with average ranks for ties (no sklearn dependency)."""
    pos, neg = int((y == 1).sum()), int((y == 0).sum())
    if pos == 0 or neg == 0:
        return math.nan
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), dtype=np.float64)
    sorted_s = s[order]
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        ranks[order[i : j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return float((ranks[y == 1].sum() - pos * (pos + 1) / 2.0) / (pos * neg))


def pick_threshold(neg_scores: np.ndarray, max_fpr: float = MAX_FPR) -> float:
    """Smallest threshold with FPR <= ``max_fpr`` on these negatives, robust to ``>`` or ``>=``.

    k = floor(max_fpr * n) negatives may be flagged; the threshold is the next float32 strictly above
    the (k+1)-th highest negative score, so at most k negatives satisfy ``score >= threshold``.
    """
    if len(neg_scores) == 0:
        return 1.0
    s = np.sort(neg_scores.astype(np.float32))[::-1]
    k = math.floor(max_fpr * len(s) + 1e-9)
    pivot = s[min(k, len(s) - 1)]
    # pb-ml requires 0 < threshold <= 1: a saturated pivot (1.0) yields 1.0, and the holdout FPR check
    # of the promotion gate then decides whether such a model is acceptable.
    return min(float(np.nextafter(np.float32(pivot), np.float32(np.inf))), 1.0)


def rates(y: np.ndarray, s: np.ndarray, threshold: float) -> tuple[float, float]:
    """(TPR, FPR) with the client's rule ``score >= threshold``."""
    flagged = s >= np.float32(threshold)
    pos, neg = (y == 1), (y == 0)
    tpr = float(flagged[pos].mean()) if pos.any() else math.nan
    fpr = float(flagged[neg].mean()) if neg.any() else math.nan
    return tpr, fpr


@dataclass
class Evaluation:
    auc: float
    tpr: float
    fpr: float
    threshold: float
    n_pos: int
    n_neg: int


def evaluate(y: np.ndarray, s: np.ndarray, threshold: float) -> Evaluation:
    tpr, fpr = rates(y, s, threshold)
    return Evaluation(roc_auc(y, s), tpr, fpr, threshold, int((y == 1).sum()), int((y == 0).sum()))


def train(
    x: np.ndarray, y: np.ndarray, xv: np.ndarray, yv: np.ndarray, names: list[str], num_rounds: int = 300
) -> lgb.Booster:
    """Small binary GBDT: <= 300 trees, <= 31 leaves, class-weighted, deterministic."""
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    params = {
        "objective": "binary",
        "boosting": "gbdt",
        "num_leaves": 31,
        "max_depth": -1,
        "learning_rate": 0.05,
        "min_data_in_leaf": 20,
        "feature_fraction": 0.8,
        "bagging_fraction": 0.8,
        "bagging_freq": 1,
        "lambda_l2": 1.0,
        "scale_pos_weight": (n_neg / n_pos) if n_pos else 1.0,
        "linear_tree": False,
        "seed": SEED,
        "deterministic": True,
        "force_row_wise": True,
        "num_threads": 2,
        "verbose": -1,
    }
    dtrain = lgb.Dataset(x, y, feature_name=names, categorical_feature=[], free_raw_data=False)
    dvalid = lgb.Dataset(xv, yv, reference=dtrain, feature_name=names, categorical_feature=[], free_raw_data=False)
    return lgb.train(
        params,
        dtrain,
        num_boost_round=min(num_rounds, 300),
        valid_sets=[dvalid],
        callbacks=[lgb.early_stopping(30, verbose=False)],
    )


def predict(booster: lgb.Booster, x: np.ndarray) -> np.ndarray:
    """Probabilities rounded to f32, like ``GbdtModel::predict_proba``."""
    it = booster.best_iteration if booster.best_iteration and booster.best_iteration > 0 else None
    return booster.predict(x, num_iteration=it).astype(np.float32)


def predict_dump(model: DumpModel, x: np.ndarray) -> np.ndarray:
    return np.array([model.predict_proba(row) for row in x], dtype=np.float32)


@dataclass
class GateDecision:
    promote: bool
    reason: str


def gate(new: Evaluation, current: Evaluation | None, max_fpr: float = MAX_FPR) -> GateDecision:
    """Promote only if the new model keeps FPR <= max_fpr on the holdout and its TPR is >= the current one."""
    if math.isnan(new.fpr) or new.fpr > max_fpr:
        return GateDecision(False, f"new model FPR {new.fpr:.5f} > {max_fpr} on the holdout")
    if current is None:
        return GateDecision(True, "no current model")
    if math.isnan(current.fpr) or current.fpr > max_fpr:
        return GateDecision(True, f"current model drifted (holdout FPR {current.fpr:.5f} > {max_fpr})")
    if new.tpr >= current.tpr:
        return GateDecision(True, f"TPR {new.tpr:.4f} >= current {current.tpr:.4f} at FPR <= {max_fpr}")
    return GateDecision(False, f"TPR {new.tpr:.4f} < current {current.tpr:.4f}: keeping the current model")


def check_dump(dump: dict, names: list[str]) -> None:
    """Refuse anything ``pb_ml::GbdtModel`` would reject."""
    if dump.get("feature_names") != names:
        raise ValueError("dump feature_names differ from pb-features --names")
    if not str(dump.get("objective", "")).startswith("binary sigmoid:"):
        raise ValueError(f"unexpected objective {dump.get('objective')!r}")
    if int(dump.get("num_class", 1)) != 1 or len(dump.get("tree_info", [])) > MAX_TREES:
        raise ValueError("model shape not supported by pb-ml")
    if dump.get("max_feature_idx") != len(names) - 1:
        raise ValueError("max_feature_idx does not match the feature count")

    def walk(node: dict) -> None:
        if "leaf_value" in node:
            return
        if node.get("decision_type") != "<=":
            raise ValueError("categorical split in model")
        walk(node["left_child"])
        walk(node["right_child"])

    for t in dump.get("tree_info", []):
        if int(t.get("num_cat", 0)) != 0:
            raise ValueError("categorical feature in model")
        walk(t["tree_structure"])


def export(
    booster: lgb.Booster,
    names: list[str],
    out_dir: Path,
    features_version: int,
    threshold: float,
    version: str,
    metrics: dict[str, object],
) -> dict:
    """Write ``macho_model.json`` (LightGBM dump), ``model_meta.json`` and ``macho_model.txt``."""
    it = booster.best_iteration if booster.best_iteration and booster.best_iteration > 0 else None
    dump = booster.dump_model(num_iteration=it)
    check_dump(dump, names)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "macho_model.json").write_text(json.dumps(dump, separators=(",", ":")), encoding="utf-8")
    meta = {"features_version": features_version, "threshold": threshold, "version": version, "metrics": metrics}
    (out_dir / "model_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    (out_dir / "macho_model.txt").write_text(booster.model_to_string(num_iteration=it), encoding="utf-8")
    return dump


def evaluation_json(e: Evaluation | None) -> dict[str, object] | None:
    if e is None:
        return None
    return {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in asdict(e).items()}
