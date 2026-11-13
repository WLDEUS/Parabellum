"""Weekly classifier training: Mach-O (``--kind macho``, default) or scripts (``--kind script``).

    python -m ml.train --pb-features target/release/pb-features --out out/ml \
        [--dataset-in prev/dataset.csv.gz] [--current-model prev/ml-latest] [--metrics-in prev/metrics.jsonl] \
        [--corpus-cache .cache/corpus] [--extra-clean ml/data/extra_clean_features.jsonl] [--no-malware]

Outputs in ``--out``: ``dataset.csv.gz`` (cumulative features, no samples), ``metrics.jsonl`` (history,
one line appended per run), ``decision.json``, and ``model/`` (``macho_model.json``,
``model_meta.json``, ``macho_model.txt``) only when the new model passes the promotion gate.
With ``--kind script`` every name gets a ``script_`` prefix (``script_dataset.csv.gz``,
``script_metrics.jsonl``, ``script_decision.json``, ``model/script_model.json``,
``model/script_model_meta.json``, ``model/script_model.txt``) so both kinds share the releases.
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
from .features import FeatureRow, extract, feature_names, features_version
from .samples import Wanted, collect_positives, featurize

log = logging.getLogger("ml")
REPO_ROOT = Path(__file__).resolve().parent.parent

#: Per-kind output names and defaults.
KIND_DEFAULTS: dict[str, dict[str, object]] = {
    "macho": {
        "prefix": "",
        "extra_clean": REPO_ROOT / "ml" / "data" / "extra_clean_features.jsonl",
        "min_pos": 200,
        "min_neg": 1000,
    },
    "script": {
        "prefix": "script_",
        "extra_clean": REPO_ROOT / "ml" / "data" / "extra_clean_script_features.jsonl",
        "min_pos": 100,
        "min_neg": 2000,
    },
}
SCRIPT_SCAN_MAX = 4 * 1024 * 1024


def out_name(kind: str, name: str) -> str:
    """``dataset.csv.gz`` -> ``script_dataset.csv.gz`` for the script classifier."""
    return f"{KIND_DEFAULTS[kind]['prefix']}{name}"


def _corpus_files(items: list, max_bytes: int) -> list[tuple[Path, str]]:
    """(file, clean package name) for every file of the extracted corpus items."""
    out = []
    for item in items:
        group = "clean:" + str(item.name).split("-")[0] if str(item.name).startswith("brew:") else f"clean:{item.name}"
        out += [(p, group) for p in iter_files([item.root], max_bytes)]
    return out


def _is_script_candidate(p: Path) -> bool:
    """Scripts by magic / shebang / extension, plus small extension-less files (pb-features sniffs)."""
    c = classify(p)
    if c == "script":
        return True
    try:
        return c == "other" and not p.suffix and p.stat().st_size <= SCRIPT_SCAN_MAX
    except OSError:
        return False


def clean_rows(args: argparse.Namespace, http: object) -> list[FeatureRow]:
    """Negatives of ``args.kind`` from the clean corpus (+ the script corpus), family = package."""
    rows: list[FeatureRow] = []
    if not args.corpus_cache:
        return rows
    items = ensure_corpus(load_spec(args.corpus_spec), args.corpus_cache, http)  # type: ignore[arg-type]
    if args.kind == "script" and args.script_corpus_cache:
        # Separate cache dir: ensure_corpus prunes entries absent from the spec it is given.
        items += ensure_corpus(load_spec(args.script_corpus_spec), args.script_corpus_cache, http)  # type: ignore[arg-type]
    files = _corpus_files(items, 512 * 1024 * 1024)
    keep = (lambda p: classify(p) == "macho") if args.kind == "macho" else _is_script_candidate
    by_group: dict[str, list[Path]] = {}
    for p, group in files:
        if keep(p):
            by_group.setdefault(group, []).append(p)
    for group, paths in sorted(by_group.items()):
        for r in extract(args.pb_features, paths, 0, args.kind):
            r.family, r.path = group, ""
            rows.append(r)
    return rows


def script_queries(path: Path) -> tuple[list[str], list[str]]:
    import tomllib

    doc = tomllib.loads(path.read_text(encoding="utf-8")).get("malwarebazaar", {})
    return [str(x) for x in doc.get("file_types", [])], [str(x) for x in doc.get("tags", [])]


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
    p.add_argument("--extra-clean", type=Path, help="owner-provided clean JSONL (default per --kind)")
    p.add_argument("--max-new-samples", type=int, default=300)
    p.add_argument("--no-malware", action="store_true", help="do not download samples this run")
    p.add_argument("--min-pos", type=int, help="default 200 (macho) / 100 (script)")
    p.add_argument("--min-neg", type=int, help="default 1000 (macho) / 2000 (script)")
    # --- ml-files: kinds, script corpus, re-featurization ---
    p.add_argument("--kind", choices=sorted(KIND_DEFAULTS), default="macho")
    p.add_argument("--script-corpus-spec", type=Path, default=REPO_ROOT / "ml" / "data" / "script_corpus.toml")
    p.add_argument("--script-corpus-cache", type=Path, help="cache dir of the script corpus (not --corpus-cache)")
    p.add_argument("--script-sources", type=Path, default=REPO_ROOT / "ml" / "data" / "script_sources.toml")
    p.add_argument(
        "--refeaturize-max",
        type=int,
        default=0,
        help="re-download up to N positives stored with an older feature layout (by SHA-256)",
    )
    p.add_argument("--now", type=int, help=argparse.SUPPRESS)
    return p.parse_args(argv)


def current_evaluation(
    model_dir: Path | None, names: list[str], version: int, x: np.ndarray, y: np.ndarray, kind: str = "macho"
) -> tuple[model.Evaluation | None, str]:
    model_name, meta_name, _ = model.KIND_FILES[kind]
    if model_dir is None or not (model_dir / model_name).is_file():
        return None, "no current model"
    try:
        meta = json.loads((model_dir / meta_name).read_text(encoding="utf-8"))
        cur = DumpModel.load(model_dir / model_name)
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
    kind: str = args.kind
    names = feature_names(args.pb_features, kind)
    extra_clean: Path = args.extra_clean or KIND_DEFAULTS[kind]["extra_clean"]  # type: ignore[assignment]
    min_pos = args.min_pos if args.min_pos is not None else int(KIND_DEFAULTS[kind]["min_pos"])  # type: ignore[call-overload]
    min_neg = args.min_neg if args.min_neg is not None else int(KIND_DEFAULTS[kind]["min_neg"])  # type: ignore[call-overload]
    key = env_key()
    http = http or Http(secrets=[key] if key else [])
    decision: dict[str, object] = {"kind": kind, "trained": False, "promoted": False, "at": now}

    # 1. negatives: clean corpus files of this kind (family = package) + owner-provided JSONL
    new_rows: list[FeatureRow] = clean_rows(args, http)
    new_rows += dataset.load_jsonl(extra_clean, 0, "clean:owner-mac")
    existing = dataset.load(args.dataset_in) if args.dataset_in else []
    versions = [r.features_version for r in new_rows] or [r.features_version for r in existing]
    fv_bin = features_version(args.pb_features, kind)
    if fv_bin is None and not versions:
        log.error("no feature rows at all (empty corpus and dataset)")
        return 1
    fv = fv_bin if fv_bin is not None else max(set(versions), key=versions.count)

    # 2. positives: new MalwareBazaar samples of this kind (features only), then positives stored
    # with an older feature layout, re-downloaded by SHA-256 (--refeaturize-max).
    stale = dataset.stale_positives(existing, fv)
    if not args.no_malware and key:
        settings = load_settings(args.sources)
        mb = MalwareBazaar(http, key)  # type: ignore[arg-type]
        known = {r.sha256 for r in existing}
        if kind == "script":
            file_types, tags = script_queries(args.script_sources)
        else:
            file_types, tags = ["macho"], settings.mb_tags
        pos, errors = collect_positives(
            mb,
            args.pb_features,
            known,
            tags,
            settings.families,
            args.max_new_samples,
            kind=kind,
            file_types=file_types,
        )
        if args.refeaturize_max > 0 and stale:
            todo = [Wanted(r.sha256, r.first_seen, r.family) for r in stale[: args.refeaturize_max]]
            again, errs = featurize(mb, args.pb_features, todo, kind)
            pos += again
            errors += errs
            decision["refeaturized"] = len(again)
        decision["positives_errors"] = errors[:50]
        new_rows += pos
    elif not args.no_malware:
        log.warning("ABUSECH_AUTH_KEY not set: no new positives this run")

    rows, merge_stats = dataset.merge(existing, new_rows, fv, len(names))
    done = {r.sha256 for r in rows}
    pending = [r for r in stale if r.sha256 not in done]  # kept until re-featurized
    decision["stale_positives"] = len(pending)
    n_saved = dataset.save(out / out_name(kind, "dataset.csv.gz"), [*rows, *pending], names) - len(pending)
    n_pos = sum(1 for r in rows if r.label == 1)
    n_neg = n_saved - n_pos
    decision.update({"features_version": fv, "n_pos": n_pos, "n_neg": n_neg, "merge": merge_stats})
    log.info("dataset: %d rows (%d malicious, %d clean)", n_saved, n_pos, n_neg)

    metrics_lines: list[str] = []
    if args.metrics_in and args.metrics_in.is_file():
        metrics_lines = [line for line in args.metrics_in.read_text(encoding="utf-8").splitlines() if line.strip()]

    def finish(code: int) -> int:
        line = json.dumps(decision, sort_keys=True, default=str)
        (out / out_name(kind, "metrics.jsonl")).write_text("\n".join([*metrics_lines, line]) + "\n", encoding="utf-8")
        (out / out_name(kind, "decision.json")).write_text(
            json.dumps(decision, indent=2, default=str) + "\n", encoding="utf-8"
        )
        return code

    if n_pos < min_pos or n_neg < min_neg:
        decision["reason"] = f"not enough data ({n_pos} < {min_pos} positives or {n_neg} < {min_neg} negatives)"
        log.warning("%s: training skipped", decision["reason"])
        return finish(0)

    result = train_and_gate(rows, names, fv, now, out / "model", args.current_model, kind)
    decision.update(result)
    if not result["promoted"]:
        shutil.rmtree(out / "model", ignore_errors=True)
    log.info("promotion: %s (%s)", result["promoted"], result["reason"])
    return finish(0)


def train_and_gate(
    rows: list[FeatureRow],
    names: list[str],
    fv: int,
    now: int,
    model_dir: Path,
    current_dir: Path | None,
    kind: str = "macho",
) -> dict[str, object]:
    rows, dedupe_stats = model.dedupe(rows)
    tr, va, ho, info = model.split_with_info(rows)
    for part, label in ((tr, "train"), (va, "validation"), (ho, "holdout")):
        if len({r.label for r in part}) < 2:
            return {"trained": False, "promoted": False, "reason": f"{label} split lacks one class"}
    x, y = model.matrix(tr)
    xv, yv = model.matrix(va)
    xh, yh = model.matrix(ho)
    booster = model.train(x, y, xv, yv, names, w=model.sample_weights(tr), wv=model.sample_weights(va))
    pv = model.predict(booster, xv)
    threshold = model.pick_threshold(pv[yv == 0])
    calibration = model.fit_calibration(model.predict_margin(booster, xv), pv, yv)
    ph = model.predict(booster, xh)
    cal_h = model.apply_calibration(calibration, model.predict_margin(booster, xh), ph)
    new_eval = model.evaluate(yh, ph, threshold, cal_h)
    cur_eval, cur_note = current_evaluation(current_dir, names, fv, xh, yh, kind)
    dec = model.gate(new_eval, cur_eval)
    version = datetime.fromtimestamp(now, tz=UTC).strftime("%Y.%m.%d")
    y_all = np.concatenate([y, yv, yh])
    out: dict[str, object] = {
        "trained": True,
        "promoted": dec.promote,
        "reason": dec.reason,
        "version": version,
        "trees": booster.num_trees(),
        "best_iteration": booster.best_iteration,
        "dedupe": dedupe_stats,
        "split": {"train": len(tr), "validation": len(va), "holdout": len(ho), "dated_pos": info.dated_pos},
        "calibration": calibration["method"],
        "new": model.evaluation_json(new_eval),
        "current": model.evaluation_json(cur_eval),
        "current_note": cur_note,
    }
    if dec.promote:

        def num(v: float, nd: int = 6) -> float | None:
            return None if np.isnan(v) else round(float(v), nd)

        metrics = {
            "roc_auc": num(new_eval.auc),
            "pr_auc": num(new_eval.pr_auc),
            "tpr_at_threshold": new_eval.tpr,
            "fpr_at_threshold": new_eval.fpr,
            "tpr_at_fpr_0_1": num(new_eval.tpr_at_fpr),
            "brier": num(new_eval.brier),
            "n_pos": int((y_all == 1).sum()),
            "n_neg": int((y_all == 0).sum()),
            "holdout_pos": new_eval.n_pos,
            "holdout_neg": new_eval.n_neg,
            "holdout_since": info.holdout_since,
            "families": len({r.family for r in rows if r.label == 1 and r.family}),
            "best_iteration": booster.best_iteration,
            "trained_at": now,
        }
        dump = model.export(booster, names, model_dir, fv, threshold, version, metrics, kind, calibration)
        # The exported dump must score exactly like LightGBM (pb-ml evaluates the dump, not the booster).
        probe = xh[: min(len(xh), 200)]
        dm = DumpModel(dump)
        diff = np.abs(model.predict_dump(dm, probe) - model.predict(booster, probe))
        diff_m = np.abs(model.predict_dump_margin(dm, probe) - model.predict_margin(booster, probe))
        worst = max(float(diff.max(initial=0.0)), float(diff_m.max(initial=0.0)) * 1e-2)
        if worst > 1e-5:
            return {**out, "promoted": False, "reason": f"dump/booster mismatch {worst:.2e}"}
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
