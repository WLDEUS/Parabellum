"""Cumulative feature table (``dataset.csv.gz`` asset of the ``ml-dataset`` release).

Only feature vectors are stored — never samples. Columns: ``sha256,label,features_version,<names…>``.
Rows are deduplicated by SHA-256; rows of another ``features_version`` (or with a different vector
length) are dropped, so a layout change in ``pb-ml`` restarts the accumulation cleanly.
"""

from __future__ import annotations

import csv
import gzip
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


def save(path: Path, rows: Iterable[FeatureRow], names: list[str]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with gzip.open(path, "wt", encoding="ascii", newline="", compresslevel=9) as f:
        w = csv.writer(f)
        w.writerow(["sha256", "label", "features_version", *names])
        for r in sorted(rows, key=lambda r: r.sha256):
            w.writerow([r.sha256, r.label, r.features_version, *(_fmt(v) for v in r.features)])
            n += 1
    return n


def load(path: Path) -> list[FeatureRow]:
    rows: list[FeatureRow] = []
    if not path.is_file():
        return rows
    with gzip.open(path, "rt", encoding="ascii", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if not header or header[:3] != ["sha256", "label", "features_version"]:
            log.warning("%s: unexpected header, ignoring the file", path)
            return rows
        for rec in reader:
            try:
                rows.append(FeatureRow(rec[0].lower(), int(rec[1]), int(rec[2]), [float(x) for x in rec[3:]]))
            except (ValueError, IndexError):
                continue
    return rows


def load_jsonl(path: Path, label: int) -> list[FeatureRow]:
    """Extra rows produced by ``pb-features --label 0 /Applications > extra_clean_features.jsonl``."""
    if not path.is_file():
        return []
    rows = parse_rows(path.read_text(encoding="utf-8"), label)
    return [r for r in rows if r.label == label]


def merge(
    existing: Iterable[FeatureRow], new: Iterable[FeatureRow], features_version: int, n_features: int
) -> tuple[list[FeatureRow], dict[str, int]]:
    """Dedupe by SHA-256 (new rows win), drop other versions / bad lengths / label conflicts."""
    stats = {"dropped_version": 0, "dropped_length": 0, "conflicts": 0}
    by_sha: dict[str, FeatureRow] = {}
    labels: dict[str, set[int]] = {}
    for r in [*existing, *new]:
        if r.features_version != features_version:
            stats["dropped_version"] += 1
            continue
        if len(r.features) != n_features or r.label not in (0, 1):
            stats["dropped_length"] += 1
            continue
        labels.setdefault(r.sha256, set()).add(r.label)
        by_sha[r.sha256] = r
    out = []
    for sha, r in by_sha.items():
        if len(labels[sha]) > 1:  # the same file seen as clean and malicious: unusable label
            stats["conflicts"] += 1
            continue
        out.append(r)
    return sorted(out, key=lambda r: r.sha256), stats
