"""LightGBM training, threshold selection, calibration, metrics, promotion gate and export (``pb_ml``
contract), shared by the Mach-O and the script classifiers.

Data hygiene, in order:

1. :func:`dedupe` — rows with an identical feature vector and label collapse into the earliest one
   (repacked / re-signed builds of one sample would otherwise sit on both sides of the split and
   dominate their family); a vector seen with both labels is dropped as unlearnable.
2. :func:`split` — **time split** for dated positives (MalwareBazaar ``first_seen``): oldest 65 %
   train, next 15 % validation (early stopping, threshold, calibration), newest 20 % holdout (gate
   and published metrics), so the model is always judged on samples newer than anything it saw.
   Negatives (and undated positives) use stable hash buckets of their *group* (clean-corpus package
   / family, else SHA-256), so one package never straddles train and holdout.
3. :func:`sample_weights` — ``1/sqrt(group size)`` per row, each class rescaled to half of the total
   weight: class balance without ``scale_pos_weight`` and without letting one big family (or one big
   package) dictate the trees.
"""

from __future__ import annotations

import hashlib
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
#: Time split of dated positives (fractions of the newest samples).
HOLDOUT_FRAC = 0.20
VALID_FRAC = 0.15
MAX_FPR = 0.001
SEED = 1337
#: Isotonic calibration needs enough validation samples; Platt scaling otherwise.
ISOTONIC_MIN_POS = 200
ISOTONIC_MIN_NEG = 1000
MAX_ISOTONIC_POINTS = 10_000

#: Bundle file names per model kind: (model json, meta json, native text dump).
KIND_FILES = {
    "macho": ("macho_model.json", "model_meta.json", "macho_model.txt"),
    "script": ("script_model.json", "script_model_meta.json", "script_model.txt"),
}


def bucket(sha256: str) -> int:
    return int(sha256[:8], 16) % 100


def group_key(r: FeatureRow) -> str:
    """Leakage / weighting group: family (positives) or clean package (negatives), else the sample."""
    return f"{r.label}:{r.family}" if r.family else f"sha:{r.sha256}"


def _group_bucket(r: FeatureRow) -> int:
    return int(hashlib.sha256(group_key(r).encode()).hexdigest()[:8], 16) % 100


def dedupe(rows: list[FeatureRow]) -> tuple[list[FeatureRow], dict[str, int]]:
    """Collapse identical (label, feature vector) rows into the earliest (first_seen, sha256) one;
    drop vectors seen with both labels."""
    groups: dict[bytes, list[FeatureRow]] = {}
    for r in rows:
        key = np.asarray(r.features, dtype=np.float32).tobytes()
        groups.setdefault(key, []).append(r)
    out: list[FeatureRow] = []
    stats = {"duplicates": 0, "ambiguous": 0}
    for members in groups.values():
        if len({m.label for m in members}) > 1:
            stats["ambiguous"] += len(members)
            continue
        keep = min(members, key=lambda m: (m.first_seen if m.first_seen > 0 else 2**62, m.sha256))
        stats["duplicates"] += len(members) - 1
        out.append(keep)
    return sorted(out, key=lambda r: r.sha256), stats


@dataclass
class SplitInfo:
    #: Holdout positives are those first seen at or after this time (None: no dated positive).
    holdout_since: int | None = None
    dated_pos: int = 0


def split(rows: list[FeatureRow]) -> tuple[list[FeatureRow], list[FeatureRow], list[FeatureRow]]:
    tr, va, ho, _ = split_with_info(rows)
    return tr, va, ho


def split_with_info(
    rows: list[FeatureRow],
) -> tuple[list[FeatureRow], list[FeatureRow], list[FeatureRow], SplitInfo]:
    """Time split for dated positives, stable group-hash buckets for everything else."""
    train, valid, hold = [], [], []
    dated = sorted((r for r in rows if r.label == 1 and r.first_seen > 0), key=lambda r: (r.first_seen, r.sha256))
    info = SplitInfo(dated_pos=len(dated))
    n = len(dated)
    n_hold, n_valid = round(n * HOLDOUT_FRAC), round(n * VALID_FRAC)
    cut_v, cut_h = n - n_hold - n_valid, n - n_hold
    train += dated[:cut_v]
    valid += dated[cut_v:cut_h]
    hold += dated[cut_h:]
    if dated[cut_h:]:
        info.holdout_since = dated[cut_h].first_seen
    for r in rows:
        if r.label == 1 and r.first_seen > 0:
            continue
        b = _group_bucket(r) if r.family else bucket(r.sha256)
        (hold if b in HOLDOUT_BUCKETS else valid if b in VALID_BUCKETS else train).append(r)
    return train, valid, hold, info


def sample_weights(rows: list[FeatureRow]) -> np.ndarray:
    """``1/sqrt(group size)``, each class rescaled to carry half of the total weight."""
    sizes: dict[str, int] = {}
    for r in rows:
        sizes[group_key(r)] = sizes.get(group_key(r), 0) + 1
    w = np.array([1.0 / math.sqrt(sizes[group_key(r)]) for r in rows], dtype=np.float64)
    y = np.array([r.label for r in rows])
    for label in (0, 1):
        mask = y == label
        total = w[mask].sum()
        if total > 0:
            w[mask] *= (len(rows) / 2.0) / total
    return w


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


def average_precision(y: np.ndarray, s: np.ndarray) -> float:
    """Area under the precision-recall curve (step-wise average precision, ties grouped)."""
    pos = int((y == 1).sum())
    if pos == 0:
        return math.nan
    order = np.argsort(-s.astype(np.float64), kind="mergesort")
    ys, ss = y[order], s[order]
    tp = np.cumsum(ys == 1)
    # last index of each run of equal scores
    last = np.r_[np.nonzero(np.diff(ss))[0], len(ss) - 1]
    precision = tp[last] / (last + 1)
    recall = tp[last] / pos
    prev = np.r_[0.0, recall[:-1]]
    return float(np.sum((recall - prev) * precision))


def tpr_at_fpr(y: np.ndarray, s: np.ndarray, max_fpr: float = MAX_FPR) -> float:
    """Best TPR with FPR <= ``max_fpr`` on this very set (oracle threshold; reporting only)."""
    if not (y == 0).any():
        return math.nan
    return rates(y, s, pick_threshold(s[y == 0], max_fpr))[0]


def brier(y: np.ndarray, p: np.ndarray) -> float:
    return float(np.mean((p.astype(np.float64) - y) ** 2)) if len(y) else math.nan


@dataclass
class Evaluation:
    auc: float
    tpr: float
    fpr: float
    threshold: float
    n_pos: int
    n_neg: int
    pr_auc: float = math.nan
    tpr_at_fpr: float = math.nan
    brier: float = math.nan


def evaluate(y: np.ndarray, s: np.ndarray, threshold: float, calibrated: np.ndarray | None = None) -> Evaluation:
    tpr, fpr = rates(y, s, threshold)
    return Evaluation(
        roc_auc(y, s),
        tpr,
        fpr,
        threshold,
        int((y == 1).sum()),
        int((y == 0).sum()),
        pr_auc=average_precision(y, s),
        tpr_at_fpr=tpr_at_fpr(y, s),
        brier=brier(y, calibrated if calibrated is not None else s),
    )


# --- calibration (mirrors pb_ml::Calibration) ----------------------------------------------------


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -500, 500)))


def fit_platt(margin: np.ndarray, y: np.ndarray, iters: int = 100) -> tuple[float, float]:
    """Platt scaling ``p = sigmoid(a*m + b)`` with Platt's smoothed targets (Newton, damped)."""
    m = margin.astype(np.float64)
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    t = np.where(y == 1, (n_pos + 1.0) / (n_pos + 2.0), 1.0 / (n_neg + 2.0))
    a, b = 1.0, 0.0
    for _ in range(iters):
        p = _sigmoid(a * m + b)
        g = np.array([np.sum((p - t) * m), np.sum(p - t)])
        w = np.maximum(p * (1 - p), 1e-12)
        h = np.array([[np.sum(w * m * m), np.sum(w * m)], [np.sum(w * m), np.sum(w)]]) + 1e-9 * np.eye(2)
        step = np.linalg.solve(h, g)
        a, b = a - step[0], b - step[1]
        if np.max(np.abs(step)) < 1e-10:
            break
    if not (math.isfinite(a) and math.isfinite(b)) or a <= 0:
        return 1.0, 0.0  # degenerate data: identity on the margin
    return float(a), float(b)


def fit_isotonic(p: np.ndarray, y: np.ndarray) -> tuple[list[float], list[float]]:
    """Pool-adjacent-violators on (probability, label); returns the non-decreasing curve points."""
    order = np.argsort(p, kind="mergesort")
    xs, ys = p[order].astype(np.float64), y[order].astype(np.float64)
    # blocks: [sum_y, count, x_min, x_max]
    blocks: list[list[float]] = []
    for x, t in zip(xs, ys, strict=True):
        if blocks and blocks[-1][3] == x:  # tie: same x always in one block
            b = blocks[-1]
            b[0] += t
            b[1] += 1
        else:
            blocks.append([t, 1.0, x, x])
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] >= blocks[-1][0] / blocks[-1][1]:
            last = blocks.pop()
            prev = blocks[-1]
            prev[0] += last[0]
            prev[1] += last[1]
            prev[3] = last[3]
    cx: list[float] = []
    cy: list[float] = []
    for s_y, cnt, lo, hi in blocks:
        v = s_y / cnt
        cx.append(lo)
        cy.append(v)
        if hi > lo:
            cx.append(hi)
            cy.append(v)
    if len(cx) > MAX_ISOTONIC_POINTS:
        idx = np.unique(np.linspace(0, len(cx) - 1, MAX_ISOTONIC_POINTS).round().astype(int))
        cx, cy = [cx[i] for i in idx], [cy[i] for i in idx]
    return cx, cy


def fit_calibration(margin: np.ndarray, p: np.ndarray, y: np.ndarray) -> dict[str, object]:
    """Isotonic when the validation set is large enough, Platt otherwise (fitted on validation)."""
    if int((y == 1).sum()) >= ISOTONIC_MIN_POS and int((y == 0).sum()) >= ISOTONIC_MIN_NEG:
        x, v = fit_isotonic(p, y)
        return {"method": "isotonic", "x": x, "y": v}
    a, b = fit_platt(margin, y)
    return {"method": "platt", "a": a, "b": b}


def apply_calibration(cal: dict[str, object] | None, margin: np.ndarray, p: np.ndarray) -> np.ndarray:
    """Calibrated probability, exactly like ``pb_ml::Calibration::apply`` (rounded to f32)."""
    if not cal:
        return p.astype(np.float32)
    if cal.get("method") == "platt":
        out = _sigmoid(float(cal["a"]) * margin.astype(np.float64) + float(cal["b"]))  # type: ignore[arg-type]
    elif cal.get("method") == "isotonic":
        out = np.interp(p.astype(np.float64), cal["x"], cal["y"])  # type: ignore[arg-type]
    else:
        return p.astype(np.float32)
    return np.clip(out, 0.0, 1.0).astype(np.float32)


def train(
    x: np.ndarray,
    y: np.ndarray,
    xv: np.ndarray,
    yv: np.ndarray,
    names: list[str],
    num_rounds: int = 300,
    w: np.ndarray | None = None,
    wv: np.ndarray | None = None,
) -> lgb.Booster:
    """Small binary GBDT: <= 300 trees, <= 31 leaves, deterministic, early-stopped on the validation
    set. Class balance comes from ``w`` (see :func:`sample_weights`) when given, else from
    ``scale_pos_weight``."""
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
        "scale_pos_weight": 1.0 if w is not None else ((n_neg / n_pos) if n_pos else 1.0),
        "linear_tree": False,
        "seed": SEED,
        "deterministic": True,
        "force_row_wise": True,
        "num_threads": 2,
        "verbose": -1,
    }
    dtrain = lgb.Dataset(x, y, weight=w, feature_name=names, categorical_feature=[], free_raw_data=False)
    dvalid = lgb.Dataset(
        xv, yv, weight=wv, reference=dtrain, feature_name=names, categorical_feature=[], free_raw_data=False
    )
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


def predict_margin(booster: lgb.Booster, x: np.ndarray) -> np.ndarray:
    """Raw margin (sum of leaves), what Platt calibration consumes (``GbdtModel::predict_raw``)."""
    it = booster.best_iteration if booster.best_iteration and booster.best_iteration > 0 else None
    return booster.predict(x, num_iteration=it, raw_score=True).astype(np.float64)


def predict_dump(model: DumpModel, x: np.ndarray) -> np.ndarray:
    return np.array([model.predict_proba(row) for row in x], dtype=np.float32)


def predict_dump_margin(model: DumpModel, x: np.ndarray) -> np.ndarray:
    return np.array([model.predict_raw(row) for row in x], dtype=np.float64)


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
    kind: str = "macho",
    calibration: dict[str, object] | None = None,
) -> dict:
    """Write the LightGBM dump, the meta and the native text model (names: :data:`KIND_FILES`)."""
    model_name, meta_name, txt_name = KIND_FILES[kind]
    it = booster.best_iteration if booster.best_iteration and booster.best_iteration > 0 else None
    dump = booster.dump_model(num_iteration=it)
    check_dump(dump, names)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / model_name).write_text(json.dumps(dump, separators=(",", ":")), encoding="utf-8")
    meta: dict[str, object] = {
        "features_version": features_version,
        "threshold": threshold,
        "version": version,
        "metrics": metrics,
    }
    if calibration:
        meta["calibration"] = calibration
    (out_dir / meta_name).write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    (out_dir / txt_name).write_text(booster.model_to_string(num_iteration=it), encoding="utf-8")
    return dump


def evaluation_json(e: Evaluation | None) -> dict[str, object] | None:
    if e is None:
        return None
    return {k: (None if isinstance(v, float) and math.isnan(v) else v) for k, v in asdict(e).items()}
