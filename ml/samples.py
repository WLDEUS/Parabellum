"""Positives: features of recent MalwareBazaar Mach-O samples, extracted without keeping the samples.

Each sample is downloaded (AES zip), decrypted in memory, written to a private temp dir (0700/0600,
never executable) only for the time ``pb-features`` reads it, then deleted. Only direct Mach-O samples
(MalwareBazaar file type ``macho``) are used: binaries found *inside* malicious DMGs may be benign
helpers and would poison the labels.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import time
import zipfile
from collections.abc import Callable, Mapping
from pathlib import Path

from pipeline.abusech import MalwareBazaar, extract_sample
from pipeline.corpus import classify
from pipeline.http import FetchError

from .features import FeatureRow, extract

log = logging.getLogger(__name__)


def collect_positives(
    mb: MalwareBazaar,
    pb_features: Path,
    known: set[str],
    tags: list[str],
    families: Mapping[str, str],
    max_new: int,
    pause_s: float = 1.0,
    extractor: Callable[[Path, list[Path], int | None], list[FeatureRow]] = extract,
) -> tuple[list[FeatureRow], list[str]]:
    """Return (feature rows labelled 1, errors). ``known`` = SHA-256 already in the dataset."""
    entries, errors = mb.macos_entries(["macho"], tags, families, limit=1000)
    todo = sorted((e for e in entries if e.sha256 not in known), key=lambda e: (-e.first_seen, e.sha256))[:max_new]
    rows: list[FeatureRow] = []
    for e in todo:
        tmp = Path(tempfile.mkdtemp(prefix="pb-ml-sample-"))
        try:
            members = extract_sample(mb.download_sample(e.sha256))
            paths = []
            for i, (_name, data) in enumerate(members):
                p = tmp / f"s{i}"
                p.write_bytes(data)
                p.chmod(0o600)
                if classify(p) == "macho":
                    paths.append(p)
            for r in extractor(pb_features, paths, 1):
                rows.append(r)
        except (FetchError, RuntimeError, OSError, ValueError, zipfile.BadZipFile) as exc:
            errors.append(f"{e.sha256}: {exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        time.sleep(pause_s)  # be gentle with the community API
    return rows, errors
