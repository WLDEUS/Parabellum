"""Positives: features of MalwareBazaar samples, extracted without keeping the samples.

Each sample is downloaded (AES zip), decrypted in memory, written to a private temp dir (0700/0600,
never executable) only for the time ``pb-features`` reads it, then deleted. Nothing is executed.

* ``kind="macho"``: only direct Mach-O samples (MalwareBazaar file type ``macho``) are used: binaries
  found *inside* malicious DMGs may be benign helpers and would poison the labels.
* ``kind="script"``: direct script samples (shell, AppleScript, JXA, Python, JavaScript, Perl). The
  member's extension is preserved (type detection uses it); ``pb-features --kind script`` decides
  what is a script (magic, shebang, extension, script-like text). Mach-O members are skipped.

Every row carries the sample's ``first_seen`` (time split) and family (signature or tag).
"""

from __future__ import annotations

import logging
import re
import shutil
import tempfile
import time
import zipfile
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from pipeline.abusech import MalwareBazaar, extract_sample
from pipeline.corpus import classify
from pipeline.http import FetchError

from .features import FeatureRow, extract

log = logging.getLogger(__name__)

Extractor = Callable[[Path, list[Path], int | None, str], list[FeatureRow]]
_SUFFIX = re.compile(r"\.([A-Za-z0-9]{1,12})$")


@dataclass
class Wanted:
    """One sample to featurize."""

    sha256: str
    first_seen: int = 0
    family: str = ""


def _suffix(member: str) -> str:
    m = _SUFFIX.search(member.rsplit("/", 1)[-1])
    return f".{m.group(1).lower()}" if m else ""


def featurize(
    mb: MalwareBazaar,
    pb_features: Path,
    wanted: Iterable[Wanted],
    kind: str = "macho",
    pause_s: float = 1.0,
    extractor: Extractor = extract,
) -> tuple[list[FeatureRow], list[str]]:
    """Download, featurize (label 1) and delete each sample. Returns (rows, errors)."""
    rows: list[FeatureRow] = []
    errors: list[str] = []
    for w in wanted:
        tmp = Path(tempfile.mkdtemp(prefix="pb-ml-sample-"))
        try:
            members = extract_sample(mb.download_sample(w.sha256))
            paths = []
            for i, (name, data) in enumerate(members):
                p = tmp / f"s{i}{_suffix(name) if kind == 'script' else ''}"
                p.write_bytes(data)
                p.chmod(0o600)
                c = classify(p)
                if (kind == "macho" and c == "macho") or (kind == "script" and c not in ("macho", "archive")):
                    paths.append(p)
            for r in extractor(pb_features, paths, 1, kind):
                r.first_seen = w.first_seen
                r.family = w.family
                r.path = ""
                rows.append(r)
        except (FetchError, RuntimeError, OSError, ValueError, zipfile.BadZipFile) as exc:
            errors.append(f"{w.sha256}: {exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        time.sleep(pause_s)  # be gentle with the community API
    return rows, errors


def collect_positives(
    mb: MalwareBazaar,
    pb_features: Path,
    known: set[str],
    tags: list[str],
    families: Mapping[str, str],
    max_new: int,
    pause_s: float = 1.0,
    extractor: Extractor = extract,
    kind: str = "macho",
    file_types: list[str] | None = None,
) -> tuple[list[FeatureRow], list[str]]:
    """New samples (not in ``known``) by file type and tag, newest first. Returns (rows, errors)."""
    types = file_types if file_types is not None else ["macho"]
    entries, errors = mb.macos_entries(types, tags, families, limit=1000)
    todo = sorted((e for e in entries if e.sha256 not in known), key=lambda e: (-e.first_seen, e.sha256))[:max_new]
    wanted = [Wanted(e.sha256, e.first_seen, e.name or "") for e in todo]
    rows, errs = featurize(mb, pb_features, wanted, kind, pause_s, extractor)
    return rows, errors + errs
