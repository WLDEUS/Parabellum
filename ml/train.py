"""Weekly Mach-O classifier training.

    python -m ml.train --pb-features target/release/pb-features --out out/ml \
        [--dataset-in prev/dataset.csv.gz] [--current-model prev/ml-latest] [--metrics-in prev/metrics.jsonl] \
        [--corpus-cache .cache/corpus] [--extra-clean ml/data/extra_clean_features.jsonl] [--no-malware]

Outputs in ``--out``: ``dataset.csv.gz`` (cumulative features, no samples), ``metrics.jsonl`` (history,
one line appended per run), ``decision.json``, and ``model/`` (``macho_model.json``,
``model_meta.json``, ``macho_model.txt``) only when the new model passes the promotion gate.
Env: ``ABUSECH_AUTH_KEY`` (positives from MalwareBazaar).
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from pipeline.abusech import MalwareBazaar
from pipeline.corpus import classify, ensure_corpus, iter_files, load_spec
from pipeline.http import Http
from pipeline.sources import env_key, load_settings

from . import dataset, model
from .dump_eval import DumpModel, ModelError
from .features import FeatureRow, extract, feature_names
from .samples import collect_positives

log = logging.getLogger("ml")
REPO_ROOT = Path(__file__).resolve().parent.parent


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m ml.train")
    p.add_argument("--pb-features", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--dataset-in", type=Path)
    p.add_argument("--current-model", type=Path, help="directory with the ml-latest macho_model.json + model_meta.json")
    p.add_argument("--metrics-in", type=Path)
    p.add_argument("--corpus-cache", type=Path)
    p.add_argument("--corpus-spec", type=Path, default=REPO_ROOT / "pipeline" / "data" / "clean_corpus.toml")
    p.add_argument("--sources", type=Path, default=REPO_ROOT / "pipeline" / "sources.toml")
    p.add_argument("--extra-clean", type=Path, default=REPO_ROOT / "ml" / "data" / "extra_clean_features.jsonl")
    p.add_argument("--max-new-samples", type=int, default=300)
    p.add_argument("--no-malware", action="store_true", help="do not download samples this run")
    p.add_argument("--min-pos", type=int, default=200)
    p.add_argument("--min-neg", type=int, default=1000)
    p.add_argument("--now", type=int, help=argparse.SUPPRESS)
    return p.parse_args(argv)


def current_evaluation(
    model_dir: Path | None, names: list[str], version: int, x: np.ndarray, y: np.ndarray
) -> tuple[model.Evaluation | None, str]:
    if model_dir is None or not (model_dir / "macho_model.json").is_file():
        return None, "no current model"
    try:
        meta = json.loads((model_dir / "model_meta.json").read_text(encoding="utf-8"))
        cur = DumpModel.load(model_dir / "macho_model.json")
    except (OSError, ValueError, ModelError, KeyError) as e:
        return None, f"current model unreadable: {e}"
    if int(meta.get("features_version", -1)) != version or cur.feature_names != names:
        return None, "current model uses another feature layout"
    scores = model.predict_dump(cur, x)
    return model.evaluate(y, scores, float(meta["threshold"])), "ok"


def run(args: argparse.Namespace, http: object | None = None) -> int:
    now = args.now or int(time.time())
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    names = feature_names(args.pb_features)
    key = env_key()
    http = http or Http(secrets=[key] if key else [])
    decision: dict[str, object] = {"trained": False, "promoted": False, "at": now}

    # 1. negatives: clean corpus Mach-O + owner-provided JSONL
    new_rows: list[FeatureRow] = []
    if args.corpus_cache:
        spec = load_spec(args.corpus_spec)
        items = ensure_corpus(spec, args.corpus_cache, http)  # type: ignore[arg-type]
        machos = [p for p in iter_files([i.root for i in items], 512 * 1024 * 1024) if classify(p) == "macho"]
        new_rows += extract(args.pb_features, machos, 0)
    new_rows += dataset.load_jsonl(args.extra_clean, 0)
    existing = dataset.load(args.dataset_in) if args.dataset_in else []
    versions = [r.features_version for r in new_rows] or [r.features_version for r in existing]
    if not versions:
        log.error("no feature rows at all (empty corpus and dataset)")
        return 1
    fv = max(set(versions), key=versions.count)

    # 2. positives: new MalwareBazaar Mach-O samples (features only)
    if not args.no_malware and key:
        settings = load_settings(args.sources)
        mb = MalwareBazaar(http, key)  # type: ignore[arg-type]
        known = {r.sha256 for r in existing}
        pos, errors = collect_positives(
            mb, args.pb_features, known, settings.mb_tags, settings.families, args.max_new_samples
        )
        decision["positives_errors"] = errors[:50]
        new_rows += pos
    elif not args.no_malware:
        log.warning("ABUSECH_AUTH_KEY not set: no new positives this run")

    rows, merge_stats = dataset.merge(existing, new_rows, fv, len(names))
    n_saved = dataset.save(out / "dataset.csv.gz", rows, names)
    n_pos = sum(1 for r in rows if r.label == 1)
    n_neg = n_saved - n_pos
    decision.update({"features_version": fv, "n_pos": n_pos, "n_neg": n_neg, "merge": merge_stats})
    log.info("dataset: %d rows (%d malicious, %d clean)", n_saved, n_pos, n_neg)

    metrics_lines: list[str] = []
    if args.metrics_in and args.metrics_in.is_file():
        metrics_lines = [line for line in args.metrics_in.read_text(encoding="utf-8").splitlines() if line.strip()]

    def finish(code: int) -> int:
        line = json.dumps(decision, sort_keys=True, default=str)
        (out / "metrics.jsonl").write_text("\n".join([*metrics_lines, line]) + "\n", encoding="utf-8")
        (out / "decision.json").write_text(json.dumps(decision, indent=2, default=str) + "\n", encoding="utf-8")
        return code

    if n_pos < args.min_pos or n_neg < args.min_neg:
        decision["reason"] = (
            f"not enough data ({n_pos} < {args.min_pos} positives or {n_neg} < {args.min_neg} negatives)"
        )
        log.warning("%s: training skipped", decision["reason"])
        return finish(0)

    result = train_and_gate(rows, names, fv, now, out / "model", args.current_model)
    decision.update(result)
    if not result["promoted"]:
        shutil.rmtree(out / "model", ignore_errors=True)
    log.info("promotion: %s (%s)", result["promoted"], result["reason"])
    return finish(0)


def train_and_gate(
    rows: list[FeatureRow], names: list[str], fv: int, now: int, model_dir: Path, current_dir: Path | None
) -> dict[str, object]:
    tr, va, ho = model.split(rows)
    for part, label in ((tr, "train"), (va, "validation"), (ho, "holdout")):
        if len({r.label for r in part}) < 2:
            return {"trained": False, "promoted": False, "reason": f"{label} split lacks one class"}
    x, y = model.matrix(tr)
    xv, yv = model.matrix(va)
    xh, yh = model.matrix(ho)
    booster = model.train(x, y, xv, yv, names)
    threshold = model.pick_threshold(model.predict(booster, xv)[yv == 0])
    new_eval = model.evaluate(yh, model.predict(booster, xh), threshold)
    cur_eval, cur_note = current_evaluation(current_dir, names, fv, xh, yh)
    dec = model.gate(new_eval, cur_eval)
    version = datetime.fromtimestamp(now, tz=UTC).strftime("%Y.%m.%d")
    out: dict[str, object] = {
        "trained": True,
        "promoted": dec.promote,
        "reason": dec.reason,
        "version": version,
        "trees": booster.num_trees(),
        "new": model.evaluation_json(new_eval),
        "current": model.evaluation_json(cur_eval),
        "current_note": cur_note,
    }
    if dec.promote:
        metrics = {
            "auc": None if np.isnan(new_eval.auc) else round(new_eval.auc, 6),
            "tpr_at_threshold": new_eval.tpr,
            "fpr_at_threshold": new_eval.fpr,
            "n_pos": int((np.concatenate([y, yv, yh]) == 1).sum()),
            "n_neg": int((np.concatenate([y, yv, yh]) == 0).sum()),
            "trained_at": now,
        }
        dump = model.export(booster, names, model_dir, fv, threshold, version, metrics)
        # The exported dump must score exactly like LightGBM (pb-ml evaluates the dump, not the booster).
        probe = xh[: min(len(xh), 200)]
        diff = np.abs(model.predict_dump(DumpModel(dump), probe) - model.predict(booster, probe))
        if float(diff.max(initial=0.0)) > 1e-5:
            return {**out, "promoted": False, "reason": f"dump/booster mismatch {float(diff.max()):.2e}"}
    return out


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        return run(parse_args(argv))
    except Exception:
        log.exception("training failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
