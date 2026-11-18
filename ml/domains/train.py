"""Daily phishing / malicious-domain model training.

    python -m ml.domains.train --pb-domain-features target/release/pb-domain-features \\
        --state-dir state --out out/ml-domain [--dataset-in prev/domains.csv.gz] \\
        [--metrics-in prev/metrics.jsonl] [--current-model current] [--tranco-zip t.zip --tranco-sub-zip s.zip]

Outputs in ``--out``: ``domains.csv.gz`` (cumulative positives with first-seen day, never negatives),
``metrics.jsonl`` (history), ``decision.json``, and ``model/`` (``domain_model.json``,
``domain_model_meta.json``, ``domain_brands.txt``, ``domain_top.txt``, ``domain_model.txt``) only when the
new model passes the gate.

Split: positives first seen in the last ``--holdout-days`` days are the holdout (new campaigns) when older
positives exist; otherwise SHA-256 buckets. Negatives: buckets (20 % holdout, 15 % validation). Alert
threshold = FPR <= 0.05 % on validation negatives, block threshold = FPR <= 0.01 %. Gate: holdout FPR at the
alert threshold <= 0.05 % and TPR >= the current model's (when comparable).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from ml import model as gbdt
from ml.dump_eval import DumpModel, ModelError

from . import data

log = logging.getLogger("ml.domains")
REPO_ROOT = Path(__file__).resolve().parents[2]
ALERT_FPR = 0.0005
BLOCK_FPR = 0.0001
TIMEOUT_S = 1800


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m ml.domains.train")
    p.add_argument("--pb-domain-features", type=Path, required=True)
    p.add_argument("--state-dir", type=Path, required=True, help="extracted pipeline-state.tar.gz")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--brands", type=Path, default=REPO_ROOT / "pipeline" / "data" / "brands.txt")
    p.add_argument("--dataset-in", type=Path)
    p.add_argument("--metrics-in", type=Path)
    p.add_argument("--current-model", type=Path, help="directory with the ml-domain-latest files")
    p.add_argument("--tranco-zip", type=Path, help="local top-1m.csv.zip (default: download)")
    p.add_argument("--tranco-sub-zip", type=Path, help="local top-1m-incl-subdomains.csv.zip (default: download)")
    p.add_argument("--neg-top", type=int, default=100_000)
    p.add_argument("--neg-tail", type=int, default=100_000)
    p.add_argument("--neg-sub", type=int, default=100_000)
    p.add_argument("--popular", type=int, default=20_000, help="size of domain_top.txt")
    p.add_argument("--holdout-days", type=int, default=14)
    p.add_argument("--min-pos", type=int, default=1000)
    p.add_argument("--min-neg", type=int, default=10_000)
    p.add_argument("--now", type=int, help=argparse.SUPPRESS)
    return p.parse_args(argv)


# --- features (pb-domain-features) -----------------------------------------------------------------


def feature_names(binary: Path) -> list[str]:
    out = subprocess.run([str(binary), "--names"], capture_output=True, text=True, timeout=60, check=True)
    names = json.loads(out.stdout)
    if not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names):
        raise ValueError("pb-domain-features --names did not return a list of strings")
    return names


def features_version(binary: Path) -> int:
    out = subprocess.run([str(binary), "--version-info"], capture_output=True, text=True, timeout=60, check=True)
    return int(json.loads(out.stdout)["features_version"])


def extract(binary: Path, brands: Path, domains: list[str], n_features: int) -> tuple[list[str], np.ndarray]:
    """Feature matrix (float32 values widened to float64) for the names the binary accepted."""
    proc = subprocess.run(
        [str(binary), "--brands", str(brands)],
        input="\n".join(domains) + "\n",
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
        check=True,
    )
    names: list[str] = []
    rows: list[list[float]] = []
    for line in proc.stdout.splitlines():
        if not line.startswith("{"):
            continue
        doc = json.loads(line)
        feats = doc["features"]
        if len(feats) != n_features:
            raise ValueError("pb-domain-features returned a vector of the wrong length")
        names.append(str(doc["domain"]))
        rows.append([math.nan if v is None else float(v) for v in feats])
    x = np.array(rows, dtype=np.float32).reshape(len(rows), n_features).astype(np.float64)
    return names, x


# --- current model ---------------------------------------------------------------------------------


def current_scores(
    model_dir: Path | None, names: list[str], fv: int, brands_sha: str, x: np.ndarray
) -> tuple[np.ndarray | None, float | None, str]:
    if model_dir is None or not (model_dir / "domain_model.json").is_file():
        return None, None, "no current model"
    try:
        meta = json.loads((model_dir / "domain_model_meta.json").read_text(encoding="utf-8"))
        cur = DumpModel.load(model_dir / "domain_model.json")
    except (OSError, ValueError, ModelError, KeyError) as e:
        return None, None, f"current model unreadable: {e}"
    if int(meta.get("features_version", -1)) != fv or cur.feature_names != names:
        return None, None, "current model uses another feature layout"
    if meta.get("brands_sha256") and meta["brands_sha256"] != brands_sha:
        return None, None, "current model uses another brand list"
    return gbdt.predict_dump(cur, x), float(meta["threshold"]), "ok"


# --- run -------------------------------------------------------------------------------------------


def load_tranco(path: Path | None, url: str) -> list[str]:
    if path is not None:
        return data.parse_tranco(path.read_bytes())
    from pipeline.http import Http

    return data.parse_tranco(Http().get_bytes(url, max_bytes=128 * 1024 * 1024))


def export(
    booster,  # type: ignore[no-untyped-def]
    names: list[str],
    out_dir: Path,
    meta: dict[str, object],
    brands: Path,
    popular: list[str],
) -> dict:
    it = booster.best_iteration if booster.best_iteration and booster.best_iteration > 0 else None
    dump = booster.dump_model(num_iteration=it)
    gbdt.check_dump(dump, names)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "domain_model.json").write_text(json.dumps(dump, separators=(",", ":")), encoding="utf-8")
    (out_dir / "domain_model.txt").write_text(booster.model_to_string(num_iteration=it), encoding="utf-8")
    shutil.copyfile(brands, out_dir / "domain_brands.txt")
    (out_dir / "domain_top.txt").write_text("\n".join(popular) + "\n", encoding="ascii")
    (out_dir / "domain_model_meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return dump


def run(args: argparse.Namespace) -> int:
    now = args.now or int(time.time())
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    binary = args.pb_domain_features
    names = feature_names(binary)
    fv = features_version(binary)
    brands_sha = hashlib.sha256(args.brands.read_bytes()).hexdigest()
    decision: dict[str, object] = {"trained": False, "promoted": False, "at": now, "features_version": fv}

    fresh = data.read_positive_sources(args.state_dir)
    existing = data.load_dataset(args.dataset_in)
    positives_rows, added = data.merge_positives(existing, fresh, now)
    data.save_dataset(out / "domains.csv.gz", positives_rows)
    decision.update({"positives_in_feeds": len(fresh), "positives_added": added, "n_pos": len(positives_rows)})

    metrics_lines: list[str] = []
    if args.metrics_in and args.metrics_in.is_file():
        metrics_lines = [ln for ln in args.metrics_in.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def finish(code: int) -> int:
        line = json.dumps(decision, sort_keys=True, default=str)
        (out / "metrics.jsonl").write_text("\n".join([*metrics_lines, line]) + "\n", encoding="utf-8")
        (out / "decision.json").write_text(json.dumps(decision, indent=2, default=str) + "\n", encoding="utf-8")
        return code

    pos_set = {r.domain for r in positives_rows}
    tranco = load_tranco(args.tranco_zip, data.TRANCO_URL)
    tranco_sub = load_tranco(args.tranco_sub_zip, data.TRANCO_SUB_URL)
    neg = data.negatives(tranco, tranco_sub, pos_set, args.neg_top, args.neg_tail, args.neg_sub, seed=now // data.DAY)
    decision["n_neg"] = len(neg)
    if len(positives_rows) < args.min_pos or len(neg) < args.min_neg:
        decision["reason"] = f"not enough data ({len(positives_rows)} positives, {len(neg)} negatives)"
        log.warning("%s: training skipped", decision["reason"])
        return finish(0)

    # Holdout: recent positives when there is history, else hash buckets.
    cutoff = now - now % data.DAY - args.holdout_days * data.DAY
    recent = [r for r in positives_rows if r.first_seen >= cutoff]
    older = [r for r in positives_rows if r.first_seen < cutoff]
    time_split = len(recent) >= 200 and len(older) >= args.min_pos // 2
    if time_split:
        pos_hold = [r.domain for r in recent]
        pos_rest = [r.domain for r in older]
    else:
        pos_hold = [r.domain for r in positives_rows if data.bucket(r.domain) < 20]
        pos_rest = [r.domain for r in positives_rows if data.bucket(r.domain) >= 20]
    pos_valid = [d for d in pos_rest if data.bucket(d) % 7 == 0]
    pos_train = [d for d in pos_rest if data.bucket(d) % 7 != 0]
    neg_hold = [d for d in neg if data.bucket(d) < 20]
    neg_valid = [d for d in neg if 20 <= data.bucket(d) < 35]
    neg_train = [d for d in neg if data.bucket(d) >= 35]
    decision["time_split"] = time_split

    def matrix(pos: list[str], negs: list[str]) -> tuple[np.ndarray, np.ndarray]:
        _, xp = extract(binary, args.brands, pos, len(names))
        _, xn = extract(binary, args.brands, negs, len(names))
        x = np.vstack([xp, xn]) if len(xp) and len(xn) else (xp if len(xp) else xn)
        y = np.concatenate([np.ones(len(xp), dtype=np.int32), np.zeros(len(xn), dtype=np.int32)])
        return x, y

    x, y = matrix(pos_train, neg_train)
    xv, yv = matrix(pos_valid, neg_valid)
    xh, yh = matrix(pos_hold, neg_hold)
    for part, yy in (("train", y), ("validation", yv), ("holdout", yh)):
        if len(set(yy.tolist())) < 2:
            decision["reason"] = f"{part} split lacks one class"
            return finish(0)

    booster = gbdt.train(x, y, xv, yv, names)
    sv = gbdt.predict(booster, xv)
    threshold = gbdt.pick_threshold(sv[yv == 0], ALERT_FPR)
    block_threshold = max(threshold, gbdt.pick_threshold(sv[yv == 0], BLOCK_FPR))
    sh = gbdt.predict(booster, xh)
    new_eval = gbdt.evaluate(yh, sh, threshold)
    block_tpr, block_fpr = gbdt.rates(yh, sh, block_threshold)
    cur, cur_thr, cur_note = current_scores(args.current_model, names, fv, brands_sha, xh)
    cur_eval = gbdt.evaluate(yh, cur, cur_thr) if cur is not None and cur_thr is not None else None
    dec = gbdt.gate(new_eval, cur_eval, ALERT_FPR)
    version = datetime.fromtimestamp(now, tz=UTC).strftime("%Y.%m.%d")
    decision.update(
        {
            "trained": True,
            "promoted": dec.promote,
            "reason": dec.reason,
            "version": version,
            "trees": booster.num_trees(),
            "new": gbdt.evaluation_json(new_eval),
            "block": {"threshold": block_threshold, "tpr": block_tpr, "fpr": block_fpr},
            "current": gbdt.evaluation_json(cur_eval),
            "current_note": cur_note,
        }
    )
    if not dec.promote:
        return finish(0)
    metrics = {
        "auc": None if math.isnan(new_eval.auc) else round(new_eval.auc, 6),
        "tpr_at_threshold": new_eval.tpr,
        "fpr_at_threshold": new_eval.fpr,
        "tpr_at_block": block_tpr,
        "fpr_at_block": block_fpr,
        "n_pos": int((np.concatenate([y, yv, yh]) == 1).sum()),
        "n_neg": int((np.concatenate([y, yv, yh]) == 0).sum()),
        "time_split": 1.0 if time_split else 0.0,
        "trained_at": now,
    }
    meta = {
        "features_version": fv,
        "threshold": threshold,
        "block_threshold": block_threshold,
        "version": version,
        "brands_sha256": brands_sha,
        "metrics": metrics,
    }
    popular = data.popular_list(tranco, pos_set, args.popular)
    dump = export(booster, names, out / "model", meta, args.brands, popular)
    probe = xh[: min(len(xh), 200)]
    diff = np.abs(gbdt.predict_dump(DumpModel(dump), probe) - gbdt.predict(booster, probe))
    if float(diff.max(initial=0.0)) > 1e-5:
        shutil.rmtree(out / "model", ignore_errors=True)
        decision.update({"promoted": False, "reason": f"dump/booster mismatch {float(diff.max()):.2e}"})
    return finish(0)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        return run(parse_args(argv))
    except Exception:
        log.exception("domain model training failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
