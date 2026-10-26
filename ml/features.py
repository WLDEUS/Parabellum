"""Wrapper around the ``pb-features`` binary (crate ``pb-ml``).

``pb-features --names``                    -> JSON array of feature names
``pb-features [--label 0|1] <paths…>``     -> JSON lines
``{"sha256","path","label","features_version","features":[…]}``
"""

from __future__ import annotations

import json
import logging
import math
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

CHUNK = 200
TIMEOUT_S = 600


@dataclass
class FeatureRow:
    sha256: str
    label: int
    features_version: int
    features: list[float]
    path: str = ""


def feature_names(pb_features: Path) -> list[str]:
    out = subprocess.run([str(pb_features), "--names"], capture_output=True, text=True, timeout=60, check=True)
    names = json.loads(out.stdout)
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names) or not names:
        raise ValueError("pb-features --names did not return a list of strings")
    return names


def _num(v: object) -> float:
    if v is None:
        return math.nan
    return float(v)  # type: ignore[arg-type]


def parse_rows(text: str, default_label: int | None = None) -> list[FeatureRow]:
    rows: list[FeatureRow] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            doc = json.loads(line)
            sha = str(doc["sha256"]).lower()
            label = doc.get("label", default_label)
            if label is None:
                label = -1  # unlabeled (scoring)
            if len(sha) != 64:
                continue
            rows.append(
                FeatureRow(
                    sha256=sha,
                    label=int(label),
                    features_version=int(doc["features_version"]),
                    features=[_num(v) for v in doc["features"]],
                    path=str(doc.get("path", "")),
                )
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as e:
            log.debug("bad pb-features line: %s", e)
    return rows


def extract(pb_features: Path, paths: Iterable[Path], label: int | None) -> list[FeatureRow]:
    """Run ``pb-features`` over ``paths`` in chunks; non-Mach-O files are skipped by the binary."""
    plist = [str(p) for p in paths]
    rows: list[FeatureRow] = []
    for i in range(0, len(plist), CHUNK):
        cmd = [str(pb_features)]
        if label is not None:
            cmd += ["--label", str(label)]
        cmd += ["--", *plist[i : i + CHUNK]]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_S, check=False)
        if proc.returncode not in (0, 1):
            log.warning("pb-features exited %s: %s", proc.returncode, proc.stderr[-300:])
        rows.extend(parse_rows(proc.stdout, label))
    return rows
