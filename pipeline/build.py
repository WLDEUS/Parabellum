"""Nightly threat-DB bundle builder.

    python -m pipeline.build --out dist/db [--previous prev/parabellum-db.tar.gz] [--state prev/pipeline-state.tar.gz]
        [--sources pipeline/sources.toml] [--corpus-cache .cache/corpus] [--ml-dir ml-latest]
        [--pb-features target/release/pb-features] [--build-number N] [--sign] [--allow-shrink]

Outputs in ``--out``: ``parabellum-db.tar.gz`` (+ ``.minisig`` with ``--sign``), ``manifest.json``,
``pipeline-state.tar.gz`` (+ ``.minisig``), ``report.json``, and ``stage/`` (the unpacked bundle).
Exit codes: 0 ok, 2 sanity guard refused the bundle (yesterday's release stays), 1 error.
Env: ``ABUSECH_AUTH_KEY`` (abuse.ch sources), ``MINISIGN_SECRET_KEY`` (``--sign``),
``MALWARE_CORPUS=1`` (detection measurement), ``GITHUB_RUN_NUMBER`` (default build number).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path

from . import BUNDLE_FILE, MANIFEST_FILE, STATE_FILE
from .abusech import MalwareBazaar
from .bundle import (
    Manifest,
    Stats,
    deterministic_tar_gz,
    load_manifest,
    make_version,
    safe_extract,
    sanity_problems,
    verify_files,
    write_manifest,
)
from .corpus import CorpusItem, ensure_corpus, iter_files, load_spec
from .detection import measure
from .domains import Exclusions, prune_subdomains, render
from .fpgate import fp_rate, run_fp_gate
from .hashes import (
    HashIndex,
    is_sha256,
    read_digest_file,
    read_hsb,
    read_names_tsv,
    write_digest_file,
    write_hsb,
    write_names_tsv,
)
from .http import Fetcher, Http
from .sign import sign
from .sources import DOMAIN_CATEGORIES, Context, env_key, fetch_all, load_settings
from .yara_rules import validate

log = logging.getLogger("pipeline")
REPO_ROOT = Path(__file__).resolve().parent.parent


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m pipeline.build", description=__doc__.split("\n\n")[0])
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--previous", type=Path, help="previous bundle (.tar.gz, already signature-checked) or directory")
    p.add_argument("--state", type=Path, help="previous pipeline-state.tar.gz or directory")
    p.add_argument("--sources", type=Path, default=REPO_ROOT / "pipeline" / "sources.toml")
    p.add_argument("--corpus-spec", type=Path, default=REPO_ROOT / "pipeline" / "data" / "clean_corpus.toml")
    p.add_argument("--corpus-cache", type=Path, help="clean corpus cache dir (FP gate is skipped without it)")
    p.add_argument("--allow-hashes", type=Path, default=REPO_ROOT / "pipeline" / "data" / "allow_hashes.txt")
    p.add_argument("--shared-hosts", type=Path, default=REPO_ROOT / "pipeline" / "data" / "shared_hosts.txt")
    p.add_argument("--ml-dir", type=Path, help="directory holding the ml-latest model files")
    p.add_argument("--pb-features", type=Path, help="pb-features binary (ML FP rate / detection)")
    p.add_argument("--build-number", type=int, default=int(os.environ.get("GITHUB_RUN_NUMBER", "0") or 0))
    p.add_argument("--sign", action="store_true", help="sign with MINISIGN_SECRET_KEY or --secret-key-file")
    p.add_argument("--secret-key-file", type=Path)
    p.add_argument("--allow-shrink", action="store_true", help="publish even if the sanity guard objects")
    p.add_argument("--offline", action="store_true", help="skip every network source (local data only)")
    p.add_argument("--now", type=int, help=argparse.SUPPRESS)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args(argv)


def _open_dir(path: Path | None, work: Path, name: str) -> Path | None:
    """A directory for a bundle/state given as .tar.gz or directory (None when absent)."""
    if path is None or not path.exists():
        return None
    if path.is_dir():
        return path
    dest = work / name
    shutil.rmtree(dest, ignore_errors=True)
    try:
        safe_extract(path, dest)
    except (OSError, ValueError) as e:
        log.warning("cannot open %s: %s", path, e)
        return None
    return dest


def gha(level: str, message: str) -> None:
    """GitHub Actions annotation (visible in the check run without reading the logs)."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{message.replace(chr(10), ' ')[:900]}", flush=True)


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines() if path.is_file() else []


def build(args: argparse.Namespace, http: Fetcher | None = None) -> int:
    now = args.now or int(time.time())
    out: Path = args.out
    work = out / "work"
    stage = out / "stage"
    shutil.rmtree(work, ignore_errors=True)
    shutil.rmtree(stage, ignore_errors=True)
    work.mkdir(parents=True)
    stage.mkdir(parents=True)

    settings = load_settings(args.sources)
    key = env_key()
    if http is None:
        http = Http(secrets=[key] if key else [])
    report: dict[str, object] = {"built_at": now}

    prev_dir = _open_dir(args.previous, work, "previous")
    prev_manifest = load_manifest(prev_dir) if prev_dir else None
    if prev_dir and prev_manifest:
        bad = verify_files(prev_dir, prev_manifest)
        if bad:
            log.warning("previous bundle has %d files not matching its manifest; ignoring it", len(bad))
            prev_dir, prev_manifest = None, None
    state_dir = _open_dir(args.state, work, "state-in")
    last_success: dict[str, dict[str, int]] = {}
    if state_dir and (state_dir / "sources.json").is_file():
        last_success = json.loads((state_dir / "sources.json").read_text(encoding="utf-8"))

    # --- hashes: rolling index from the state (or seeded from the previous bundle) ---
    index = HashIndex.load(state_dir / "hashes") if state_dir else HashIndex()
    if not index.index and prev_dir and (prev_dir / "hashes" / "malware.sha256").is_file():
        seeded = read_digest_file(prev_dir / "hashes" / "malware.sha256")
        index.index = dict.fromkeys(seeded, 0)
        names = (
            read_names_tsv(prev_dir / "hashes" / "malware_names.tsv")
            if (prev_dir / "hashes" / "malware_names.tsv").is_file()
            else {}
        )
        hsb = (
            read_hsb(prev_dir / "clamav" / "parabellum.hsb")
            if (prev_dir / "clamav" / "parabellum.hsb").is_file()
            else {}
        )
        for h in set(names) | set(hsb):
            size, fam = hsb.get(h, (None, None))
            index.macos[h] = (0, size, names.get(h) or fam)
        log.info("seeded the hash index from the previous bundle (%d hashes)", len(seeded))

    ctx = Context(
        http=http,
        repo_root=REPO_ROOT,
        settings=settings,
        now=now,
        key=key,
        ml_dir=args.ml_dir,
        index_size=len(index.index),
        prev_dir=prev_dir,
    )
    network_fetchers = {
        "mb_export",
        "mb_api_macos",
        "urlhaus_export",
        "threatfox_export",
        "domain_list",
        "yara_tarball",
        "yara_raw",
        "zbt_release",
    }
    payloads, infos, errors = fetch_all(
        ctx, state_dir, prev_dir, last_success, only=lambda s: not (args.offline and s.fetcher in network_fetchers)
    )
    report["source_errors"] = errors
    for name, err in errors.items():
        gha("warning", f"source {name} failed (previous data carried over): {err}")

    for name, got in payloads.items():
        if got.malware:
            added = index.add(got.malware)
            log.info("%s: %d entries (%d new)", name, len(got.malware), added)
    index.prune(now, settings.hash_window_days, settings.max_malware_hashes, settings.max_macos_named)

    # --- domains ---
    excl = Exclusions.from_lines(
        _read_lines(REPO_ROOT / "pipeline" / "data" / "dns_allowlist.txt"), _read_lines(args.shared_hosts)
    )
    categories: dict[str, set[str]] = {c: set() for c in DOMAIN_CATEGORIES}
    for got in payloads.values():
        for cat, doms in got.domains.items():
            categories[cat] |= doms
    domain_report: dict[str, dict[str, int]] = {}
    for cat in DOMAIN_CATEGORIES:
        kept, removed = excl.apply(categories[cat])
        pruned = prune_subdomains(kept)
        domain_report[cat] = {"raw": len(categories[cat]), "excluded": removed, "final": len(pruned)}
        categories[cat] = pruned
    report["domains"] = domain_report

    # --- YARA: validate each file with yara-x ---
    rule_files = [f for got in payloads.values() for f in got.yara]
    vrep = validate(rule_files)
    report["yara_rejected_compile"] = [{"file": f, "error": e} for f, e in vrep.rejected_files]
    report["yara_duplicates_removed"] = [{"file": f, "rule": r} for f, r in vrep.renamed_away]
    kept_rules = vrep.accepted

    # --- FP gate on the clean corpus ---
    clean_hashes: set[str] = {
        h for h in (line.split("#")[0].strip().lower() for line in _read_lines(args.allow_hashes)) if is_sha256(h)
    }
    rejected_fp = 0
    fp: float | None = None
    corpus_items: list[CorpusItem] = []
    ml_scorer = None
    ml_dir_for_scoring = None
    if "ml/macho_model.json" in {k for got in payloads.values() for k in got.files}:
        ml_dir_for_scoring = work / "ml-model"
        ml_dir_for_scoring.mkdir(exist_ok=True)
        for got in payloads.values():
            for rel, data in got.files.items():
                if rel.startswith("ml/"):
                    (ml_dir_for_scoring / rel.split("/", 1)[1]).write_bytes(data)
    if args.pb_features and ml_dir_for_scoring:
        try:
            from ml.score import MlScorer

            ml_scorer = MlScorer(args.pb_features, ml_dir_for_scoring)
        except Exception as e:  # incompatible model / binary: no ML numbers, not fatal
            log.warning("ML scoring disabled: %s", e)
    if args.corpus_cache:
        spec = load_spec(args.corpus_spec)
        corpus_items = ensure_corpus(spec, args.corpus_cache, http)
        roots = {str(i.root): i.name for i in corpus_items}

        def label(p: Path) -> str:
            for r, n in roots.items():
                if str(p).startswith(r + os.sep):
                    return f"{n}:{p.relative_to(r)}"
            return p.name

        files = list(iter_files([i.root for i in corpus_items], spec.max_scan_bytes))
        gate = run_fp_gate(kept_rules, files, label)
        kept_rules = gate.kept
        rejected_fp = gate.rules_rejected
        clean_hashes |= gate.clean_hashes
        clean_hashes |= {i.sha256 for i in corpus_items}
        removed = index.discard(clean_hashes)
        ml_flagged = 0
        if ml_scorer is not None and gate.macho_files:
            scores = ml_scorer(gate.macho_files)
            ml_flagged = sum(1 for s in scores.values() if s >= ml_scorer.threshold)
        fp = fp_rate(gate.files_scanned, 0, 0, ml_flagged)
        report["fp_gate"] = {
            "corpus_entries": len(corpus_items),
            "files_scanned": gate.files_scanned,
            "files_matched_before_gate": gate.files_matched_before,
            "rules_rejected": [r.to_json() for r in gate.rejected],
            "files_dropped": gate.dropped_files,
            "malware_hashes_removed_as_clean": removed,
            "ml_flagged": ml_flagged,
            "scan_errors": gate.timeouts,
        }
    else:
        log.warning("no --corpus-cache: FP gate skipped")
        index.discard(clean_hashes)

    # --- detection measurement (opt-in) ---
    detection_rate = None
    if os.environ.get("MALWARE_CORPUS") == "1" and key and not args.offline:
        mb = MalwareBazaar(http, key)
        det = measure(
            mb,
            kept_rules,
            now - settings.detection_days * 86400,
            settings.detection_max_samples,
            settings.mb_file_types,
            settings.mb_tags,
            settings.families,
            ml_scorer,
            ml_scorer.threshold if ml_scorer else None,
        )
        detection_rate = det.rate
        report["detection"] = det.to_json()

    # --- stage the bundle ---
    malware = index.malware_set() - clean_hashes
    n_malware = write_digest_file(stage / "hashes" / "malware.sha256", malware)
    names = {h: n for h, (_t, _s, n) in index.macos.items() if n and h in malware}
    write_names_tsv(stage / "hashes" / "malware_names.tsv", names)
    n_allow = write_digest_file(stage / "hashes" / "allow.sha256", clean_hashes)
    n_hsb = write_hsb(
        stage / "clamav" / "parabellum.hsb", {h: (s, n) for h, (_t, s, n) in index.macos.items() if h in malware}
    )
    for f in kept_rules:
        (stage / "yara").mkdir(exist_ok=True)
        (stage / "yara" / f.name).write_text(f.text, encoding="utf-8")
    for cat in DOMAIN_CATEGORIES:
        (stage / "dns").mkdir(exist_ok=True)
        (stage / "dns" / f"{cat}.txt").write_text(render(categories[cat]), encoding="ascii")
    ml_version = None
    for got in payloads.values():
        for rel, data in got.files.items():
            dest = stage / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            if rel == "ml/model_meta.json":
                ml_version = str(json.loads(data).get("version") or "") or None

    stats = Stats(
        malware_hashes=n_malware,
        allow_hashes=n_allow,
        yara_rules=sum(len(f.rules) for f in kept_rules),
        yara_rules_rejected_fp=rejected_fp,
        blocked_domains=len(set().union(*categories.values())),
        clamav_sigs=n_hsb,
        ml_model_version=ml_version,
        detection_rate=detection_rate,
        fp_rate=fp,
    )
    prev_version = str(prev_manifest.get("version", "")) if prev_manifest else None
    manifest = Manifest(
        version=make_version(now, prev_version, args.build_number or None),
        built_at=now,
        min_client_version=settings.min_client_version,
        sources=infos,
        stats=stats,
    )
    manifest_bytes = write_manifest(stage, manifest)
    report["version"] = manifest.version
    report["stats"] = stats.to_json()

    prev_stats = prev_manifest.get("stats") if prev_manifest else None
    problems = sanity_problems(stats, prev_stats if isinstance(prev_stats, dict) else None, settings.sanity_max_drop)
    report["sanity_problems"] = problems
    (out / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
    if problems and not args.allow_shrink:
        for p in problems:
            log.error("sanity guard: %s", p)
            gha("error", f"sanity guard: {p}")
        log.error("refusing to publish %s; yesterday's bundle stays in place", manifest.version)
        return 2

    # --- package, state, sign ---
    deterministic_tar_gz(stage, out / BUNDLE_FILE)
    (out / MANIFEST_FILE).write_bytes(manifest_bytes)
    state_out = work / "state-out"
    index.save(state_out / "hashes")
    new_success = dict(last_success)
    for info in infos:
        if info.fresh:
            new_success[info.name] = {"fetched_at": info.fetched_at, "count": info.count}
    (state_out / "domains").mkdir(parents=True, exist_ok=True)
    for name, got in payloads.items():
        fresh = name not in errors and not got.skipped
        if got.domains and fresh:
            doms = set().union(*got.domains.values())
            (state_out / "domains" / f"{name}.txt").write_text(render(doms), encoding="ascii")
        elif state_dir and (state_dir / "domains" / f"{name}.txt").is_file():
            shutil.copy2(state_dir / "domains" / f"{name}.txt", state_out / "domains" / f"{name}.txt")
    (state_out / "sources.json").write_text(json.dumps(new_success, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    deterministic_tar_gz(state_out, out / STATE_FILE)

    if args.sign:
        secret = os.environ.get("MINISIGN_SECRET_KEY")
        comment = f"parabellum-db {manifest.version}"
        sign(out / BUNDLE_FILE, secret, args.secret_key_file, comment)
        sign(out / STATE_FILE, secret, args.secret_key_file, f"parabellum-state {manifest.version}")
    shutil.rmtree(work, ignore_errors=True)
    gha(
        "notice",
        f"threat DB {manifest.version}: {stats.malware_hashes} hashes, {stats.yara_rules} YARA rules "
        f"({stats.yara_rules_rejected_fp} rejected by the FP gate), {stats.blocked_domains} domains, "
        f"{stats.clamav_sigs} ClamAV sigs, ML {stats.ml_model_version or 'none'}, fp_rate={stats.fp_rate}, "
        f"detection_rate={stats.detection_rate}",
    )
    log.info(
        "bundle %s: %d malware hashes, %d YARA rules (%d rejected by FP gate), %d blocked domains",
        manifest.version,
        stats.malware_hashes,
        stats.yara_rules,
        stats.yara_rules_rejected_fp,
        stats.blocked_domains,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )
    try:
        return build(args)
    except Exception:
        log.exception("pipeline failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
