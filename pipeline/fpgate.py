"""False-positive gate: scan the clean corpus with every YARA rule, drop the rules that match.

Also produces the clean-hash set (``hashes/allow.sha256``, and removal of malware hashes that are
in fact clean) and the post-gate FP rate (YARA + hash DB + ML when a model is available).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from .corpus import classify, sha256_file
from .yara_rules import (
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
    timeouts: int = 0

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
            log.warning("scan of %s failed: %s", corpus_root_of(path), e)
            continue
        if matches:
            result.files_matched_before += 1
        for m in matches:
            f = by_ns.get(m.namespace)
            if f is not None:
                hits.setdefault(f.name, {}).setdefault(m.rule, corpus_root_of(path))
    result.clean_hashes.update(extra_clean_hashes)

    for f in rule_files:
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


def fp_rate(
    files_scanned: int,
    yara_flagged: int,
    hash_flagged: int,
    ml_flagged: int,
) -> float | None:
    if files_scanned <= 0:
        return None
    return min(1.0, (yara_flagged + hash_flagged + ml_flagged) / files_scanned)
