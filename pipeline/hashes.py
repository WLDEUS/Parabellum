"""Malware hash bookkeeping: MalwareBazaar parsing, rolling index, bundle files.

Two populations are tracked in the pipeline state (``state/hashes/*.tsv``), not in the bundle:

* ``index``: every MalwareBazaar SHA-256 (all platforms) with its first-seen time. Entries older
  than ``hash_window_days`` are dropped and the newest ``max_malware_hashes`` are kept
  (2 M x 32 bytes = 64 MB worst case for ``hashes/malware.sha256``). Windows/Linux hashes are still
  useful on a Mac: they catch malware lying in Downloads or on a USB key before it is forwarded.
* ``macos``: macOS-relevant samples (Mach-O, DMG, PKG, app, macOS tags) with size and family name.
  They feed ``hashes/malware_names.tsv`` and ``clamav/parabellum.hsb`` and are kept regardless of
  the window (they are few — a few thousand a year — and highly relevant), capped at
  ``max_macos_named``.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

#: MalwareBazaar ``file_type`` / ``file_type_guess`` values considered macOS-relevant.
MACOS_FILE_TYPES = frozenset({"macho", "dmg", "pkg", "app", "mach-o", "osx", "macos", "scpt", "applescript"})
MACOS_MIME_TYPES = frozenset({"application/x-mach-binary", "application/x-apple-diskimage", "application/x-xar"})
MACOS_TAGS = frozenset({"macos", "osx", "mac", "macho", "mach-o", "dmg", "apple", "darwin"})

#: Columns of the MalwareBazaar CSV export when no header line is present (unchanged in the v2 exports).
MB_CSV_COLUMNS = (
    "first_seen_utc",
    "sha256_hash",
    "md5_hash",
    "sha1_hash",
    "reporter",
    "file_name",
    "file_type_guess",
    "mime_type",
    "signature",
    "clamav",
    "vtpercent",
    "imphash",
    "ssdeep",
    "tlsh",
)


@dataclass(frozen=True)
class MalwareEntry:
    sha256: str
    first_seen: int
    size: int | None = None
    name: str | None = None
    macos: bool = False


def is_sha256(value: str) -> bool:
    return bool(_HEX64.match(value))


def parse_mb_time(value: str | None) -> int | None:
    """``2026-10-25 12:34:56`` (UTC) -> Unix seconds."""
    if not value:
        return None
    v = value.strip().strip('"')
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return int(datetime.strptime(v, fmt).replace(tzinfo=UTC).timestamp())
        except ValueError:
            continue
    return None


_NAME_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def clean_name(value: str | None) -> str | None:
    """Family / signature name safe for TSV and ClamAV (.hsb forbids ``:``); None for ``n/a``."""
    if not value:
        return None
    v = value.strip()
    if not v or v.lower() in {"n/a", "none", "null", "unknown"}:
        return None
    v = _NAME_RE.sub("_", v).strip("_.-")
    return v[:64] or None


def family_from_tags(tags: Iterable[str], families: Mapping[str, str]) -> str | None:
    """Map MalwareBazaar tags to a canonical family using ``families`` (lowercase tag -> family)."""
    for t in tags:
        fam = families.get(t.strip().lower())
        if fam:
            return fam
    return None


def _is_macos(file_type: str | None, mime: str | None, tags: Iterable[str]) -> bool:
    ft = (file_type or "").strip().lower()
    mt = (mime or "").strip().lower()
    return ft in MACOS_FILE_TYPES or mt in MACOS_MIME_TYPES or any(t.strip().lower() in MACOS_TAGS for t in tags)


def parse_mb_csv(text: str) -> list[MalwareEntry]:
    """Parse a MalwareBazaar CSV export (``#`` comment lines, ``", "`` separators, optional commented header)."""
    columns: tuple[str, ...] = MB_CSV_COLUMNS
    data_lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            if "sha256_hash" in body:
                columns = tuple(c.strip().strip('"') for c in next(csv.reader([body], skipinitialspace=True)))
            continue
        if line.strip():
            data_lines.append(line)
    out: list[MalwareEntry] = []
    for row in csv.reader(io.StringIO("\n".join(data_lines)), skipinitialspace=True):
        rec = dict(zip(columns, (c.strip() for c in row), strict=False))
        sha = rec.get("sha256_hash", "").lower()
        if not is_sha256(sha):
            continue
        first_seen = parse_mb_time(rec.get("first_seen_utc")) or 0
        macos = _is_macos(rec.get("file_type_guess"), rec.get("mime_type"), ())
        name = clean_name(rec.get("signature")) if macos else None
        out.append(MalwareEntry(sha, first_seen, None, name, macos))
    return out


def parse_mb_api(
    payload: bytes, families: Mapping[str, str] | None = None, force_macos: bool = True
) -> list[MalwareEntry]:
    """Parse a MalwareBazaar API answer (``get_file_type`` / ``get_taginfo`` / ``get_siginfo``)."""
    families = families or {}
    doc = json.loads(payload)
    status = doc.get("query_status")
    if status != "ok":
        if status in ("no_results", "tag_not_found", "signature_not_found", "file_type_not_found"):
            return []
        raise ValueError(f"MalwareBazaar query_status={status!r}")
    out: list[MalwareEntry] = []
    for item in doc.get("data") or []:
        if not isinstance(item, dict):
            continue
        sha = str(item.get("sha256_hash", "")).lower()
        if not is_sha256(sha):
            continue
        tags = [str(t) for t in (item.get("tags") or []) if isinstance(t, str)]
        size = item.get("file_size")
        name = clean_name(item.get("signature")) or family_from_tags(tags, families)
        macos = force_macos or _is_macos(item.get("file_type"), item.get("file_type_mime"), tags)
        out.append(
            MalwareEntry(
                sha,
                parse_mb_time(item.get("first_seen")) or 0,
                int(size) if isinstance(size, int) and size > 0 else None,
                name,
                macos,
            )
        )
    return out


class HashIndex:
    """Rolling all-platform index + macOS named table (persisted in the pipeline state)."""

    def __init__(self) -> None:
        self.index: dict[str, int] = {}
        self.macos: dict[str, tuple[int, int | None, str | None]] = {}

    def add(self, entries: Iterable[MalwareEntry]) -> int:
        n = 0
        for e in entries:
            prev = self.index.get(e.sha256)
            if prev is None:
                n += 1
            if prev is None or (e.first_seen and (prev == 0 or e.first_seen < prev)):
                self.index[e.sha256] = e.first_seen
            if e.macos:
                old = self.macos.get(e.sha256)
                if old is None:
                    self.macos[e.sha256] = (e.first_seen, e.size, e.name)
                else:
                    self.macos[e.sha256] = (
                        min(x for x in (old[0], e.first_seen) if x) if (old[0] or e.first_seen) else 0,
                        e.size or old[1],
                        e.name or old[2],
                    )
        return n

    def prune(self, now: int, window_days: int, max_hashes: int, max_macos: int) -> None:
        cutoff = now - window_days * 86400
        # Unknown first_seen (0, e.g. seeded from an old bundle) counts as "now" for the window.
        kept = {h: (t or now) for h, t in self.index.items() if (t or now) >= cutoff}
        if len(kept) > max_hashes:
            newest = sorted(kept.items(), key=lambda kv: (-kv[1], kv[0]))[:max_hashes]
            kept = dict(newest)
        self.index = kept
        if len(self.macos) > max_macos:
            newest_m = sorted(self.macos.items(), key=lambda kv: (-(kv[1][0] or now), kv[0]))[:max_macos]
            self.macos = dict(newest_m)

    def malware_set(self) -> set[str]:
        return set(self.index) | set(self.macos)

    def discard(self, hashes: Iterable[str]) -> int:
        n = 0
        for h in hashes:
            if self.index.pop(h, None) is not None:
                n += 1
            self.macos.pop(h, None)
        return n

    # --- persistence (gzip TSV, sorted -> deterministic) ---
    def save(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        with gzip.open(directory / "index.tsv.gz", "wt", encoding="ascii", compresslevel=6) as f:
            for h in sorted(self.index):
                f.write(f"{h}\t{self.index[h]}\n")
        with gzip.open(directory / "macos.tsv.gz", "wt", encoding="utf-8", compresslevel=6) as f:
            for h in sorted(self.macos):
                t, size, name = self.macos[h]
                f.write(f"{h}\t{t}\t{size if size else '*'}\t{name or ''}\n")

    @classmethod
    def load(cls, directory: Path) -> HashIndex:
        idx = cls()
        p = directory / "index.tsv.gz"
        if p.is_file():
            with gzip.open(p, "rt", encoding="ascii") as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) == 2 and is_sha256(parts[0]) and parts[1].isdigit():
                        idx.index[parts[0]] = int(parts[1])
        p = directory / "macos.tsv.gz"
        if p.is_file():
            with gzip.open(p, "rt", encoding="utf-8") as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) == 4 and is_sha256(parts[0]) and parts[1].isdigit():
                        size = int(parts[2]) if parts[2].isdigit() else None
                        idx.macos[parts[0]] = (int(parts[1]), size, parts[3] or None)
        return idx


# --- bundle files ---


def write_digest_file(path: Path, hexes: Iterable[str]) -> int:
    """Write sorted, deduplicated raw 32-byte digests (``hashes/*.sha256``). Returns the count."""
    digests = sorted({bytes.fromhex(h) for h in hexes if is_sha256(h)})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        for d in digests:
            f.write(d)
    return len(digests)


def read_digest_file(path: Path) -> set[str]:
    data = path.read_bytes()
    if len(data) % 32:
        raise ValueError(f"{path}: size {len(data)} is not a multiple of 32")
    return {data[i : i + 32].hex() for i in range(0, len(data), 32)}


def write_names_tsv(path: Path, names: Mapping[str, str]) -> int:
    lines = [f"{h}\t{n}\n" for h, n in sorted(names.items()) if is_sha256(h) and n]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(lines), encoding="utf-8")
    return len(lines)


def read_names_tsv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        if len(parts) == 2 and is_sha256(parts[0]) and parts[1]:
            out[parts[0]] = parts[1]
    return out


def hsb_line(sha256: str, size: int | None, family: str | None) -> str:
    """ClamAV SHA-256 hash signature: ``HashString:FileSize:MalwareName:73``.

    The wildcard size ``*`` requires functionality level >= 73 (ClamAV docs, "Hash-based signatures");
    we set 73 on every line for uniformity.
    """
    name = f"Parabellum.Osx.{clean_name(family) or 'Malware'}"
    return f"{sha256}:{size if size else '*'}:{name}:73"


def write_hsb(path: Path, entries: Mapping[str, tuple[int | None, str | None]]) -> int:
    lines = sorted(hsb_line(h, size, name) for h, (size, name) in entries.items() if is_sha256(h))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(f"{line}\n" for line in lines), encoding="ascii")
    return len(lines)


def read_hsb(path: Path) -> dict[str, tuple[int | None, str | None]]:
    out: dict[str, tuple[int | None, str | None]] = {}
    for line in path.read_text(encoding="ascii", errors="replace").splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and is_sha256(parts[0]):
            size = int(parts[1]) if parts[1].isdigit() else None
            fam = parts[2].removeprefix("Parabellum.Osx.")
            out[parts[0]] = (size, None if fam == "Malware" else fam)
    return out
