"""False-positive gate: scan the clean corpus with every YARA rule, drop the rules that match.

A scan error or timeout is never read as "no match": the file is rescanned rule file by rule file,
and a rule file that still fails on a clean file is rejected as a whole (the engine would hit the same
error on the Mac). A clean file that no rule file can scan is reported in ``unscannable`` (the build
refuses to publish, since the gate could not vouch for the rules on it).

Also produces the clean-hash set (``hashes/allow.sha256``, and removal of malware hashes that are
in fact clean) and the post-gate FP rate (YARA + hash DB + ML when a model is available).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .corpus import classify, sha256_file
from .yara_rules import (
    Match,
    RuleFile,
    compile_all,
    compile_one,
    namespace_for,
    new_scanner,
    remove_rules,
    rule_names,
    scan_file,
)

log = logging.getLogger(__name__)

#: ``paths -> {path: score}`` for Mach-O files (see ``ml.score``); None when no model.
MlScorer = Callable[[list[Path]], dict[Path, float]]


@dataclass
class Rejection:
    file: str
    rule: str
    sample: str

    def to_json(self) -> dict[str, str]:
        return {"file": self.file, "rule": self.rule, "sample": self.sample}


@dataclass
class FpGateResult:
    kept: list[RuleFile]
    rejected: list[Rejection] = field(default_factory=list)
    dropped_files: list[str] = field(default_factory=list)
    files_scanned: int = 0
    files_matched_before: int = 0
    clean_hashes: set[str] = field(default_factory=set)
    macho_files: list[Path] = field(default_factory=list)
    #: Corpus files whose combined scan failed (error or timeout), rescanned per rule file.
    timeouts: int = 0
    #: Clean files that every rule file failed to scan on its own (corpus problem, not a rule problem).
    unscannable: list[str] = field(default_factory=list)

    @property
    def rules_rejected(self) -> int:
        return len({(r.file, r.rule) for r in self.rejected})


def run_fp_gate(
    rule_files: list[RuleFile],
    corpus_files: Iterable[Path],
    corpus_root_of: Callable[[Path], str] = lambda p: p.name,
    extra_clean_hashes: Iterable[str] = (),
    timeout_s: int = 60,
) -> FpGateResult:
    """Scan every corpus file; remove each matching rule from its file (whole file if it then breaks)."""
    result = FpGateResult(kept=[])
    by_ns = {namespace_for(f.name): f for f in rule_files}
    scanner = new_scanner(compile_all(rule_files), timeout_s) if rule_files else None
    hits: dict[str, dict[str, str]] = {}
    single: dict[str, object] = {}  # rule file name -> its own scanner, compiled on first fallback
    errored: dict[str, str] = {}  # rule file name -> clean file it failed to scan alone
    for path in corpus_files:
        result.files_scanned += 1
        kind = classify(path)
        if kind in ("macho", "script", "archive"):
            result.clean_hashes.add(sha256_file(path))
        if kind == "macho":
            result.macho_files.append(path)
        if scanner is None:
            continue
        try:
            matches = scan_file(scanner, path)
        except Exception as e:  # yara_x.TimeoutError / ScanError
            result.timeouts += 1
            log.warning("scan of %s failed (%s): rescanning rule file by rule file", corpus_root_of(path), e)
            matches, failed = _scan_each(rule_files, single, path, timeout_s)
            if len(failed) == len(rule_files):
                result.unscannable.append(corpus_root_of(path))
            else:
                for name, err in failed.items():
                    errored.setdefault(name, f"{corpus_root_of(path)} ({err})")
        if matches:
            result.files_matched_before += 1
        for m in matches:
            f = by_ns.get(m.namespace)
            if f is not None:
                hits.setdefault(f.name, {}).setdefault(m.rule, corpus_root_of(path))
    result.clean_hashes.update(extra_clean_hashes)

    for f in rule_files:
        if f.name in errored:
            for rule in f.rules or rule_names(f.text):
                result.rejected.append(Rejection(f.name, rule, f"(scan error on clean file {errored[f.name]})"))
            log.warning("FP gate: %s dropped: scan failed on clean file %s", f.name, errored[f.name])
            result.dropped_files.append(f.name)
            continue
        bad = hits.get(f.name)
        if not bad:
            result.kept.append(f if f.rules else RuleFile(f.name, f.source, f.text, rule_names(f.text)))
            continue
        for rule, sample in sorted(bad.items()):
            result.rejected.append(Rejection(f.name, rule, sample))
            log.warning("FP gate: %s:%s matched clean file %s", f.name, rule, sample)
        text = remove_rules(f.text, bad)
        names = rule_names(text)
        if not names or compile_one(text, f.name) is not None:
            # Remaining rules referenced a removed one (or nothing is left): drop the whole file.
            for rule in names:
                result.rejected.append(Rejection(f.name, rule, "(file dropped with a rejected rule)"))
            result.dropped_files.append(f.name)
            continue
        result.kept.append(RuleFile(f.name, f.source, text, names))
    return result


def _scan_each(
    rule_files: list[RuleFile], cache: dict[str, object], path: Path, timeout_s: int
) -> tuple[list[Match], dict[str, str]]:
    """Scan ``path`` with each rule file alone: (all matches, {rule file name: error})."""
    matches: list[Match] = []
    failed: dict[str, str] = {}
    for f in rule_files:
        try:
            if f.name not in cache:
                cache[f.name] = new_scanner(compile_all([f]), timeout_s)
            matches += scan_file(cache[f.name], path)  # type: ignore[arg-type]
        except Exception as e:  # compile/scan error or timeout of this file alone
            failed[f.name] = (str(e).strip().splitlines() or [type(e).__name__])[0][:200]
    return matches, failed


def corpus_problems(
    expected: int,
    current: Mapping[str, object],
    unscannable: list[str],
    previous: Mapping[str, object] | None,
    min_ratio: float,
) -> list[str]:
    """Reasons the FP gate result cannot be trusted (the build then refuses to publish).

    ``current``/``previous``: ``{"spec", "corpus_entries", "files_scanned"}`` of this run and of the
    last published run (pipeline state). A corpus shrunk by download failures or rate limiting lets a
    rule that matches a missing clean binary through; scanned files are only compared within the same
    corpus spec (editing clean_corpus.toml legitimately changes them).
    """
    problems: list[str] = []
    available = int(current.get("corpus_entries", 0) or 0)  # type: ignore[call-overload]
    if expected > 0 and available < expected * min_ratio:
        problems.append(f"clean corpus incomplete: {available}/{expected} entries available (< {min_ratio:.0%})")
    if unscannable:
        problems.append(f"FP gate could not scan {len(unscannable)} clean file(s): {', '.join(unscannable[:5])}")
    if previous and previous.get("spec") == current.get("spec"):
        try:
            old = int(previous.get("files_scanned", 0) or 0)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            old = 0
        new = int(current.get("files_scanned", 0) or 0)  # type: ignore[call-overload]
        if old > 0 and new < old * min_ratio:
            problems.append(f"FP gate scanned {new} clean files, {old} last time (< {min_ratio:.0%})")
    return problems


def fp_rate(
    files_scanned: int,
    yara_flagged: int,
    hash_flagged: int,
    ml_flagged: int,
) -> float | None:
    if files_scanned <= 0:
        return None
    return min(1.0, (yara_flagged + hash_flagged + ml_flagged) / files_scanned)
