"""Cumulative feature table (``dataset.csv.gz`` asset of the ``ml-dataset`` release).

Only feature vectors are stored — never samples. Columns:
``sha256,label,features_version,first_seen,family,<names…>`` (``first_seen``: MalwareBazaar first
submission, Unix seconds, 0 when unknown; ``family``: malware family or clean-corpus package, used by
the time split and the family-aware weighting). Files written before these two columns existed
(``sha256,label,features_version,<names…>``) are still read.

Rows are deduplicated by SHA-256; rows of another ``features_version`` (or with a different vector
length) are dropped from training. After a layout bump, ``python -m ml.train --refeaturize-max N``
re-downloads the positives of the old layout by SHA-256 (MalwareBazaar) to rebuild them.
"""

from __future__ import annotations

import csv
import gzip
import json
import logging
import math
from collections.abc import Iterable
from pathlib import Path

from .features import FeatureRow, parse_rows

log = logging.getLogger(__name__)


def _fmt(v: float) -> str:
    if math.isnan(v):
        return "nan"
    # repr() of a float is the shortest string that round-trips; pb-features values are f32 widened to
    # f64, so this is exact.
    return repr(float(v))


META = ["sha256", "label", "features_version", "first_seen", "family"]
_OLD_META = META[:3]


def _clean_family(family: str) -> str:
    """Families end up in a CSV cell: keep them short and printable."""
    return "".join(c for c in family if c.isprintable() and c not in ',"\r\n')[:80]


def save(path: Path, rows: Iterable[FeatureRow], names: list[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with gzip.open(path, "wt", encoding="utf-8", newline="", compresslevel=9) as f:
        w = csv.writer(f)
        w.writerow([*META, *names])
        for r in sorted(rows, key=lambda r: r.sha256):
            meta = [r.sha256, r.label, r.features_version, int(r.first_seen or 0), _clean_family(r.family)]
            w.writerow([*meta, *(_fmt(v) for v in r.features)])
            n += 1
    return n


def load(path: Path) -> list[FeatureRow]:
    rows: list[FeatureRow] = []
    if not path.is_file():
        return rows
    with gzip.open(path, "rt", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header and header[:5] == META:
            n_meta = 5
        elif header and header[:3] == _OLD_META:
            n_meta = 3
        else:
            log.warning("%s: unexpected header, ignoring the file", path)
            return rows
        for rec in reader:
            try:
                first_seen, family = (int(rec[3]), rec[4]) if n_meta == 5 else (0, "")
                rows.append(
                    FeatureRow(
                        rec[0].lower(),
                        int(rec[1]),
                        int(rec[2]),
                        [float(x) for x in rec[n_meta:]],
                        first_seen=first_seen,
                        family=family,
                    )
                )
            except (ValueError, IndexError):
                continue
    return rows


def load_jsonl(path: Path, label: int, family: str = "") -> list[FeatureRow]:
    """Extra rows produced by ``pb-features --label 0 /Applications > extra_clean_features.jsonl``."""
    if not path.is_file():
        return []
    rows = parse_rows(path.read_text(encoding="utf-8"), label)
    out = [r for r in rows if r.label == label]
    for r in out:
        r.family = r.family or family
    return out


def stale_positives(rows: Iterable[FeatureRow], features_version: int) -> list[FeatureRow]:
    """Positives stored with another layout (candidates for ``--refeaturize-max``), newest first."""
    old = [r for r in rows if r.label == 1 and r.features_version != features_version]
    return sorted(old, key=lambda r: (-r.first_seen, r.sha256))


def merge(
    existing: Iterable[FeatureRow], new: Iterable[FeatureRow], features_version: int, n_features: int
) -> tuple[list[FeatureRow], dict[str, int]]:
    """Dedupe by SHA-256 (new rows win, but the earliest known ``first_seen`` and a non-empty
    ``family`` are kept), drop other versions / bad lengths / label conflicts."""
    stats = {"dropped_version": 0, "dropped_length": 0, "conflicts": 0}
    by_sha: dict[str, FeatureRow] = {}
    labels: dict[str, set[int]] = {}
    seen: dict[str, int] = {}
    fams: dict[str, str] = {}
    all_rows = [*existing, *new]
    for r in all_rows:
        if r.first_seen > 0:
            seen[r.sha256] = min(seen.get(r.sha256, r.first_seen), r.first_seen)
        if r.family and r.label == 1:
            fams.setdefault(r.sha256, r.family)
    for r in all_rows:
        if r.features_version != features_version:
            stats["dropped_version"] += 1
            continue
        if len(r.features) != n_features or r.label not in (0, 1):
            stats["dropped_length"] += 1
            continue
        labels.setdefault(r.sha256, set()).add(r.label)
        r.first_seen = seen.get(r.sha256, r.first_seen)
        if not r.family:
            r.family = fams.get(r.sha256, "")
        by_sha[r.sha256] = r
    out = []
    for sha, r in by_sha.items():
        if len(labels[sha]) > 1:  # the same file seen as clean and malicious: unusable label
            stats["conflicts"] += 1
            continue
        out.append(r)
    return sorted(out, key=lambda r: r.sha256), stats


def previous_rows(decision_path: Path | None) -> int | None:
    """Rows of the published dataset per its ``decision.json`` (``n_rows``, else ``n_pos + n_neg``).

    None when there is no previous decision (first run) or it predates the dataset counts.
    """
    if decision_path is None or not decision_path.is_file():
        return None
    try:
        doc = json.loads(decision_path.read_text(encoding="utf-8"))
        if "n_rows" in doc:
            return int(doc["n_rows"])
        if "n_pos" in doc and "n_neg" in doc:
            return int(doc["n_pos"]) + int(doc["n_neg"])
    except (OSError, ValueError, TypeError, AttributeError) as e:
        raise ValueError(f"{decision_path}: unreadable previous decision ({e})") from e
    return None


def previous_features_version(decision_path: Path | None) -> int | None:
    """``features_version`` of the published dataset per its ``decision.json`` (None if unknown)."""
    if decision_path is None or not decision_path.is_file():
        return None
    try:
        doc = json.loads(decision_path.read_text(encoding="utf-8"))
        return int(doc["features_version"]) if "features_version" in doc else None
    except (OSError, ValueError, TypeError, AttributeError, KeyError):
        return None


def shrink_problem(prev_rows: int | None, loaded: int, saved: int, conflicts: int = 0) -> str | None:
    """Why publishing ``saved`` rows would lose accumulated data (None if it would not).

    ``loaded`` < ``prev_rows``: the downloaded dataset is missing, truncated or unreadable.
    ``saved`` + ``conflicts`` < ``prev_rows``: the merge dropped rows (``features_version`` change);
    rows removed as label conflicts (same file seen clean and malicious) are expected.
    """
    if not prev_rows:
        return None
    if loaded < prev_rows:
        return f"previous dataset has {loaded} readable rows, {prev_rows} were published"
    if saved + conflicts < prev_rows:
        return f"dataset would shrink from {prev_rows} to {saved} rows (feature layout change?)"
    return None
