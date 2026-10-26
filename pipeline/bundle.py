"""Bundle assembly: manifest (``pb_core::db::DbManifest``), deterministic tar.gz, sanity guard."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import tarfile
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from . import DB_FORMAT, MANIFEST_FILE

_VERSION_RE = re.compile(r"^(\d{4})\.(\d{2})\.(\d{2})\.(\d+)$")
#: Hard caps when reading a previous bundle (it is our own signed artefact, but stay defensive).
MAX_BUNDLE_MEMBER = 1024 * 1024 * 1024
MAX_BUNDLE_MEMBERS = 10_000


@dataclass
class SourceInfo:
    """``pb_core::db::DbSource``."""

    name: str
    kind: str
    url: str
    license: str
    count: int
    fetched_at: int
    fresh: bool = True


@dataclass
class Stats:
    """``pb_core::db::DbStats`` (optional fields omitted when None)."""

    malware_hashes: int = 0
    allow_hashes: int = 0
    yara_rules: int = 0
    yara_rules_rejected_fp: int = 0
    blocked_domains: int = 0
    clamav_sigs: int = 0
    ml_model_version: str | None = None
    detection_rate: float | None = None
    fp_rate: float | None = None

    def to_json(self) -> dict[str, object]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Manifest:
    version: str
    built_at: int
    min_client_version: str
    sources: list[SourceInfo] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    stats: Stats = field(default_factory=Stats)

    def to_json(self) -> dict[str, object]:
        return {
            "format": DB_FORMAT,
            "version": self.version,
            "built_at": self.built_at,
            "min_client_version": self.min_client_version,
            "sources": [asdict(s) for s in self.sources],
            "files": dict(sorted(self.files.items())),
            "stats": self.stats.to_json(),
        }

    def dumps(self) -> bytes:
        return (json.dumps(self.to_json(), indent=2, ensure_ascii=True) + "\n").encode()


def parse_version(v: str) -> tuple[int, int, int, int] | None:
    m = _VERSION_RE.match(v or "")
    if not m:
        return None
    y, mo, d, n = (int(x) for x in m.groups())
    return y, mo, d, n


def make_version(now: int, previous: str | None, build_number: int | None) -> str:
    """``YYYY.MM.DD.N`` (UTC). N = ``build_number`` (CI run number) or previous same-day N + 1.

    The result is always strictly greater than ``previous`` so clients never see a downgrade.
    """
    day = datetime.fromtimestamp(now, tz=UTC)
    date = (day.year, day.month, day.day)
    prev = parse_version(previous or "")
    if build_number is not None and build_number > 0:
        n = build_number
    elif prev and prev[:3] == date:
        n = prev[3] + 1
    else:
        n = 1
    cand = (*date, n)
    if prev and cand <= prev:  # same day with a smaller run number, or the clock went backwards
        cand = (*prev[:3], prev[3] + 1)
    return f"{cand[0]:04d}.{cand[1]:02d}.{cand[2]:02d}.{cand[3]}"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digests(stage: Path) -> dict[str, str]:
    """Every regular file under ``stage`` except the manifest -> lowercase hex SHA-256."""
    out: dict[str, str] = {}
    for p in sorted(stage.rglob("*")):
        if p.is_file() and not p.is_symlink():
            rel = p.relative_to(stage).as_posix()
            if rel == MANIFEST_FILE:
                continue
            h = hashlib.sha256()
            with p.open("rb") as f:
                while chunk := f.read(1024 * 1024):
                    h.update(chunk)
            out[rel] = h.hexdigest()
    return out


def write_manifest(stage: Path, manifest: Manifest) -> bytes:
    manifest.files = file_digests(stage)
    data = manifest.dumps()
    (stage / MANIFEST_FILE).write_bytes(data)
    return data


def _tarinfo(name: str, is_dir: bool, size: int = 0) -> tarfile.TarInfo:
    ti = tarfile.TarInfo(name)
    ti.type = tarfile.DIRTYPE if is_dir else tarfile.REGTYPE
    ti.mode = 0o755 if is_dir else 0o644
    ti.size = 0 if is_dir else size
    ti.mtime = 0
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti


def deterministic_tar_gz(stage: Path, out: Path) -> str:
    """Pack ``stage`` (sorted entries, mtime 0, uid/gid 0, only dirs + regular files). Returns SHA-256."""
    entries = sorted(p for p in stage.rglob("*") if not p.is_symlink() and (p.is_dir() or p.is_file()))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for p in entries:
            rel = p.relative_to(stage).as_posix()
            if p.is_dir():
                tf.addfile(_tarinfo(rel + "/", True))
            else:
                data = p.read_bytes()
                tf.addfile(_tarinfo(rel, False, len(data)), io.BytesIO(data))
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("wb") as f, gzip.GzipFile(filename="", mode="wb", fileobj=f, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return sha256_hex(out.read_bytes())


def safe_extract(tar_path: Path, dest: Path) -> None:
    """Extract a bundle/state tarball: regular files and dirs only, no absolute paths or ``..``."""
    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    with tarfile.open(tar_path, mode="r:gz") as tf:
        for m in tf:
            count += 1
            if count > MAX_BUNDLE_MEMBERS:
                raise ValueError("too many members")
            name = m.name.lstrip("./") if m.name.startswith("./") else m.name
            parts = [p for p in name.split("/") if p]
            if not parts or name.startswith("/") or ".." in parts:
                raise ValueError(f"unsafe member {m.name!r}")
            target = dest.joinpath(*parts)
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif m.isfile():
                if m.size > MAX_BUNDLE_MEMBER:
                    raise ValueError(f"member too large {m.name!r}")
                target.parent.mkdir(parents=True, exist_ok=True)
                f = tf.extractfile(m)
                if f is not None:
                    target.write_bytes(f.read())
            # links, devices, fifos: ignored


def load_manifest(directory: Path) -> dict[str, object] | None:
    p = directory / MANIFEST_FILE
    if not p.is_file():
        return None
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return doc if isinstance(doc, dict) else None


def verify_files(directory: Path, manifest: Mapping[str, object]) -> list[str]:
    """Paths whose digest does not match the manifest (used on the previous bundle)."""
    bad = []
    files = manifest.get("files")
    if not isinstance(files, dict):
        return ["<files missing>"]
    for rel, digest in files.items():
        p = directory / str(rel)
        if not p.is_file() or sha256_hex(p.read_bytes()) != digest:
            bad.append(str(rel))
    return bad


def sanity_problems(stats: Stats, previous: Mapping[str, object] | None, max_drop: float) -> list[str]:
    """Reasons to refuse publishing (keep yesterday's release)."""
    problems: list[str] = []
    if stats.malware_hashes == 0 and stats.blocked_domains == 0 and stats.yara_rules == 0:
        problems.append("bundle is empty (no hashes, no domains, no YARA rules)")
    if not previous:
        return problems
    for key in ("malware_hashes", "blocked_domains"):
        try:
            old = int(previous.get(key, 0) or 0)  # type: ignore[call-overload]
        except (TypeError, ValueError):
            old = 0
        new = int(getattr(stats, key))
        if old > 0 and new < old * (1.0 - max_drop):
            problems.append(f"{key} dropped from {old} to {new} (> {max_drop:.0%})")
    return problems
