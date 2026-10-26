"""Detection measurement on today's macOS samples from MalwareBazaar (opt-in: ``MALWARE_CORPUS=1``).

Safety rules (see pipeline/README.md):
* samples are decrypted **in memory**; containers (DMG/PKG/ZIP) and Mach-O handed to ``pb-features``
  are written to a private temp dir (0700, files 0600, never executable) that is deleted right after
  each sample;
* nothing is ever executed, uploaded, cached or attached as a CI artifact;
* only aggregate numbers (and SHA-256s) are reported.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .abusech import MalwareBazaar, extract_sample
from .corpus import ExtractError, Limits, classify, extract_any, find_7zip, iter_files
from .http import FetchError
from .yara_rules import RuleFile, compile_all, new_scanner, scan_bytes, scan_file

log = logging.getLogger(__name__)

HIGH_SEVERITIES = {"high", "critical"}


def is_high(severity: str | None) -> bool:
    """Engine policy: ``high``/``critical`` (or Elastic-style numeric >= 70) means malicious."""
    if severity is None:
        return False
    s = severity.strip().lower()
    if s in HIGH_SEVERITIES:
        return True
    try:
        return float(s) >= 70
    except ValueError:
        return False


@dataclass
class DetectionReport:
    samples: int = 0
    detected: int = 0
    yara_any: int = 0
    yara_high: int = 0
    ml: int = 0
    errors: list[str] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)

    @property
    def rate(self) -> float | None:
        return self.detected / self.samples if self.samples else None

    def to_json(self) -> dict[str, object]:
        return {
            "samples": self.samples,
            "detected": self.detected,
            "detection_rate": self.rate,
            "yara_any": self.yara_any,
            "yara_high": self.yara_high,
            "ml": self.ml,
            "missed_sha256": self.missed[:200],
            "errors": self.errors[:50],
        }


_CONTAINER_MAGIC = (b"xar!", b"PK\x03\x04")


def _is_dmg(data: bytes) -> bool:
    """UDIF images end with a 512-byte ``koly`` trailer."""
    return len(data) >= 512 and data[-512:-508] == b"koly"


def measure(
    mb: MalwareBazaar,
    rule_files: list[RuleFile],
    since_ts: int,
    max_samples: int,
    file_types: list[str],
    tags: list[str],
    families: Mapping[str, str],
    ml_scorer: Callable[[list[Path]], dict[Path, float]] | None = None,
    ml_threshold: float | None = None,
) -> DetectionReport:
    rep = DetectionReport()
    entries, errors = mb.macos_entries(file_types, tags, families, limit=200)
    rep.errors.extend(errors)
    recent = sorted((e for e in entries if e.first_seen >= since_ts), key=lambda e: (-e.first_seen, e.sha256))
    if not recent or not rule_files:
        return rep
    scanner = new_scanner(compile_all(rule_files), 30)
    seven_zip = find_7zip()
    limits = Limits(max_total_bytes=1024 * 1024 * 1024, max_file_bytes=256 * 1024 * 1024)
    for e in recent[:max_samples]:
        tmp = Path(tempfile.mkdtemp(prefix="pb-sample-"))  # mkdtemp: mode 0700
        try:
            members = extract_sample(mb.download_sample(e.sha256))
            if not members:
                rep.errors.append(f"{e.sha256}: empty archive")
                continue
            rep.samples += 1
            yara_any = yara_high = ml_hit = False
            macho_paths: list[Path] = []
            for idx, (_name, data) in enumerate(members):
                for m in scan_bytes(scanner, data):
                    yara_any = True
                    yara_high |= is_high(m.severity)
                is_container = (
                    data[:4] in _CONTAINER_MAGIC or _is_dmg(data) or _name.lower().endswith((".dmg", ".pkg", ".zip"))
                )
                if is_container or ml_scorer is not None:
                    path = tmp / f"m{idx}"
                    path.write_bytes(data)
                    path.chmod(0o600)
                    if is_container:
                        try:
                            ext = tmp / f"x{idx}"
                            fmt = "dmg" if _is_dmg(data) else "auto"
                            extract_any(path, ext, fmt, limits, seven_zip)
                            for f in iter_files([ext], limits.max_file_bytes):
                                for m in scan_file(scanner, f):
                                    yara_any = True
                                    yara_high |= is_high(m.severity)
                                if classify(f) == "macho":
                                    macho_paths.append(f)
                        except (ExtractError, OSError, ValueError) as exc:
                            rep.errors.append(f"{e.sha256}: extraction: {exc}")
                    elif classify(path) == "macho":
                        macho_paths.append(path)
            if ml_scorer is not None and ml_threshold is not None and macho_paths:
                scores = ml_scorer(macho_paths)
                ml_hit = any(s >= ml_threshold for s in scores.values())
            rep.yara_any += yara_any
            rep.yara_high += yara_high
            rep.ml += ml_hit
            if yara_any or ml_hit:
                rep.detected += 1
            else:
                rep.missed.append(e.sha256)
        except (FetchError, RuntimeError, OSError, ValueError, zipfile.BadZipFile) as exc:
            rep.errors.append(f"{e.sha256}: {exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return rep
