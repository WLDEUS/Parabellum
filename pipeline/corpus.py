"""Clean corpus for the FP gate and for ML negatives.

``pipeline/data/clean_corpus.toml`` lists pinned (URL + SHA-256) release archives of well-known
macOS software plus Homebrew formulae whose arm64 bottles are resolved through the formulae.brew.sh
API and pulled anonymously from ghcr.io (``Authorization: Bearer QQ==``, exactly what ``brew`` does
— see ``Library/Homebrew/brew.sh``). Everything is cached under ``--corpus-cache`` (restored by
``actions/cache``) as ``dl/<sha256>`` + ``x/<sha256>/`` (extracted tree).

Extraction is pure Python for tar/zip/xar(pkg)/gzip/pbzx/cpio; DMGs need ``7zz``/``7z`` and are
skipped without it. Every extractor refuses absolute paths, ``..``, links and special files and is
bounded in entries and bytes. Corpus archives are pinned by hash, but the same code also opens
untrusted malware DMG/PKG samples in the detection step, hence the defensive limits.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import logging
import lzma
import os
import shutil
import stat
import struct
import subprocess
import tarfile
import tomllib
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .http import Fetcher, FetchError

log = logging.getLogger(__name__)

FORMULA_API = "https://formulae.brew.sh/api/formula/{name}.json"
#: Anonymous GitHub Packages token used by Homebrew itself (``HOMEBREW_GITHUB_PACKAGES_AUTH`` default).
GHCR_ANON_AUTH = {"Authorization": "Bearer QQ=="}


@dataclass
class Limits:
    max_entries: int = 200_000
    max_total_bytes: int = 4 * 1024 * 1024 * 1024
    max_file_bytes: int = 512 * 1024 * 1024
    max_depth: int = 3
    seven_zip_timeout: int = 600


@dataclass
class ArchiveSpec:
    name: str
    url: str
    sha256: str
    format: str


@dataclass
class CorpusSpec:
    version: int
    archives: list[ArchiveSpec] = field(default_factory=list)
    homebrew_formulae: list[str] = field(default_factory=list)
    bottle_tags: list[str] = field(default_factory=lambda: ["arm64_sequoia", "arm64_tahoe", "arm64_sonoma", "all"])
    max_scan_bytes: int = 100 * 1024 * 1024


def load_spec(path: Path) -> CorpusSpec:
    doc = tomllib.loads(path.read_text(encoding="utf-8"))
    spec = CorpusSpec(version=int(doc.get("version", 1)))
    spec.max_scan_bytes = int(doc.get("max_scan_bytes", spec.max_scan_bytes))
    for a in doc.get("archive", []):
        spec.archives.append(ArchiveSpec(a["name"], a["url"], a["sha256"].lower(), a.get("format", "auto")))
    hb = doc.get("homebrew", {})
    spec.homebrew_formulae = list(hb.get("formulae", []))
    if "bottle_tags" in hb:
        spec.bottle_tags = list(hb["bottle_tags"])
    return spec


# --- safe extraction -------------------------------------------------------------------------


class ExtractError(Exception):
    pass


class _Budget:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.entries = 0
        self.bytes = 0

    def take(self, size: int) -> None:
        self.entries += 1
        self.bytes += max(size, 0)
        if self.entries > self.limits.max_entries:
            raise ExtractError("too many entries")
        if self.bytes > self.limits.max_total_bytes:
            raise ExtractError("too many bytes")


def _safe_rel(name: str) -> str | None:
    """Relative, normalised member path, or None for absolute / ``..`` / empty names."""
    n = name.replace("\\", "/")
    if n.startswith("/"):
        return None
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def _write(dest: Path, rel: str, data: bytes | io.BufferedIOBase, size: int, budget: _Budget) -> None:
    budget.take(size)
    if size > budget.limits.max_file_bytes:
        return
    out = dest / rel
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        # Never create executable files: 0o600, the corpus is only read.
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    except OSError as e:  # path conflict (file vs directory), link in the way…
        log.debug("skip member %s: %s", rel, e)
        return
    with os.fdopen(fd, "wb") as f:
        if isinstance(data, bytes):
            f.write(data)
        else:
            remaining = budget.limits.max_file_bytes
            while chunk := data.read(1024 * 1024):
                remaining -= len(chunk)
                if remaining < 0:
                    raise ExtractError("member larger than declared")
                f.write(chunk)


def extract_tar(src: Path, dest: Path, budget: _Budget) -> None:
    with tarfile.open(src, mode="r:*") as tf:
        for m in tf:
            rel = _safe_rel(m.name)
            if rel is None or not m.isfile():
                continue
            fobj = tf.extractfile(m)
            if fobj is not None:
                _write(dest, rel, fobj, m.size, budget)


def extract_zip(src: Path, dest: Path, budget: _Budget) -> None:
    with zipfile.ZipFile(src) as zf:
        for info in zf.infolist():
            rel = _safe_rel(info.filename)
            if rel is None or info.is_dir():
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if mode and not stat.S_ISREG(mode):  # symlinks stored by macOS zips
                continue
            with zf.open(info) as f:
                _write(dest, rel, f, info.file_size, budget)


def extract_gzip_single(src: Path, dest: Path, budget: _Budget) -> None:
    name = src.name[:-3] if src.name.endswith(".gz") else src.name + ".out"
    with gzip.open(src, "rb") as f:
        _write(dest, name, f, 0, budget)


# xar (flat .pkg) -----------------------------------------------------------------------------

_XAR_MAGIC = b"xar!"
_MAX_TOC = 16 * 1024 * 1024


def _xar_files(toc: ET.Element) -> Iterator[tuple[str, ET.Element]]:
    def walk(node: ET.Element, prefix: str) -> Iterator[tuple[str, ET.Element]]:
        for f in node.findall("file"):
            name = (f.findtext("name") or "").strip()
            path = f"{prefix}/{name}" if prefix else name
            yield path, f
            yield from walk(f, path)

    root = toc.find("toc")
    if root is not None:
        yield from walk(root, "")


def extract_xar(src: Path, dest: Path, budget: _Budget) -> None:
    with src.open("rb") as fh:
        head = fh.read(28)
        if len(head) < 28 or head[:4] != _XAR_MAGIC:
            raise ExtractError("not a xar archive")
        hsize, _ver, toc_c, toc_u, _alg = struct.unpack(">HHQQI", head[4:28])
        if toc_c > _MAX_TOC or toc_u > _MAX_TOC:
            raise ExtractError("xar TOC too large")
        fh.seek(hsize)
        toc_xml = zlib.decompress(fh.read(toc_c), bufsize=int(toc_u) or 16384)
        heap = hsize + toc_c
        toc = ET.fromstring(toc_xml)  # expat >= 2.4 guards against entity expansion bombs
        for path, node in _xar_files(toc):
            if (node.findtext("type") or "file") != "file":
                continue
            data_node = node.find("data")
            rel = _safe_rel(path)
            if data_node is None or rel is None:
                continue
            length = int(data_node.findtext("length") or 0)
            offset = int(data_node.findtext("offset") or 0)
            size = int(data_node.findtext("size") or 0)
            enc_node = data_node.find("encoding")
            enc = enc_node.get("style", "") if enc_node is not None else "application/octet-stream"
            if length > budget.limits.max_file_bytes or size > budget.limits.max_file_bytes:
                budget.take(size)
                continue
            fh.seek(heap + offset)
            raw = fh.read(length)
            if enc == "application/x-gzip":
                data = zlib.decompress(raw, bufsize=size or 16384)
            elif enc == "application/x-bzip2":
                data = bz2.decompress(raw)
            else:
                data = raw
            _write(dest, rel, data, len(data), budget)


# Payload / Scripts of component packages: gzip or pbzx wrapping a cpio archive -----------------


def _pbzx_decode(data: bytes, max_bytes: int) -> bytes:
    if data[:4] != b"pbzx":
        raise ExtractError("not pbzx")
    pos = 12
    out = bytearray()
    while pos + 16 <= len(data):
        _flags, length = struct.unpack(">QQ", data[pos : pos + 16])
        pos += 16
        chunk = data[pos : pos + length]
        pos += length
        out += lzma.decompress(chunk) if chunk[:6] == b"\xfd7zXZ\x00" else chunk
        if len(out) > max_bytes:
            raise ExtractError("pbzx payload too large")
    return bytes(out)


def _cpio_entries(data: bytes) -> Iterator[tuple[str, int, bytes]]:
    pos = 0
    while pos + 6 <= len(data):
        magic = data[pos : pos + 6]
        if magic == b"070707":  # odc
            hdr = data[pos : pos + 76]
            if len(hdr) < 76:
                return
            mode = int(hdr[18:24], 8)
            namesize = int(hdr[59:65], 8)
            filesize = int(hdr[65:76], 8)
            name_start = pos + 76
            data_start = name_start + namesize
            next_pos = data_start + filesize
        elif magic in (b"070701", b"070702"):  # newc / crc
            hdr = data[pos : pos + 110]
            if len(hdr) < 110:
                return
            mode = int(hdr[14:22], 16)
            filesize = int(hdr[54:62], 16)
            namesize = int(hdr[94:102], 16)
            name_start = pos + 110
            data_start = (name_start + namesize + 3) & ~3
            next_pos = (data_start + filesize + 3) & ~3
        else:
            return
        name = data[name_start : name_start + namesize].rstrip(b"\0").decode("utf-8", errors="replace")
        if name == "TRAILER!!!":
            return
        yield name, mode, data[data_start : data_start + filesize]
        pos = next_pos


def extract_payload(src: Path, dest: Path, budget: _Budget) -> None:
    """``Payload`` / ``Scripts`` of a component pkg (gzip | pbzx | bzip2) + cpio."""
    raw = src.read_bytes()
    cap = budget.limits.max_total_bytes
    if raw[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        raw = d.decompress(raw, cap)
    elif raw[:4] == b"pbzx":
        raw = _pbzx_decode(raw, cap)
    elif raw[:3] == b"BZh":
        raw = bz2.decompress(raw)
    for name, mode, content in _cpio_entries(raw):
        rel = _safe_rel(name)
        if rel is None or not stat.S_ISREG(mode):
            continue
        _write(dest, rel, content, len(content), budget)


def find_7zip() -> str | None:
    for exe in ("7zz", "7z"):
        p = shutil.which(exe)
        if p:
            return p
    return None


def extract_dmg(src: Path, dest: Path, budget: _Budget, seven_zip: str | None) -> None:
    if not seven_zip:
        raise ExtractError("7zz/7z not available: DMG skipped")
    dest.mkdir(parents=True, exist_ok=True)
    # -snl would *store* links; by default 7-Zip refuses dangerous link targets. Links are skipped anyway.
    cmd = [seven_zip, "x", "-y", "-bd", "-bb0", f"-o{dest}", "--", str(src)]
    proc = subprocess.run(cmd, capture_output=True, timeout=budget.limits.seven_zip_timeout, check=False)
    # 1 = warnings (HFS+ metadata). 2 is also returned when 7-Zip refuses a "dangerous" link such as
    # the usual `Applications -> /Applications` alias in installer DMGs: keep what was extracted.
    benign_2 = proc.returncode == 2 and all(
        b"Dangerous link path was ignored" in line for line in proc.stderr.splitlines() if line.startswith(b"ERROR")
    )
    if proc.returncode not in (0, 1) and not benign_2:
        raise ExtractError(f"7z exit {proc.returncode}: {proc.stderr[-300:]!r}")
    for root, dirs, files in os.walk(dest, followlinks=False):
        for name in files + dirs:
            p = Path(root, name)
            if p.is_symlink():
                p.unlink()
        for name in files:
            p = Path(root, name)
            try:
                st = p.lstat()
            except OSError:
                continue
            budget.take(st.st_size)
            p.chmod(0o600)


def detect_format(path: Path, declared: str = "auto") -> str:
    if declared != "auto":
        return declared
    with path.open("rb") as f:
        head = f.read(512)
    n = path.name.lower()
    if head[:4] == _XAR_MAGIC:
        return "pkg"
    if head[:2] == b"PK":
        return "zip"
    if n.endswith(".dmg"):
        return "dmg"
    if n.endswith((".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar")) or head[257:262] == b"ustar":
        return "tar"
    if head[:2] == b"\x1f\x8b":
        return "tar" if _gz_is_tar(path) else "gz"
    if head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00":
        return "tar"
    return "file"


def _gz_is_tar(path: Path) -> bool:
    try:
        with gzip.open(path, "rb") as f:
            return f.read(512)[257:262] == b"ustar"
    except OSError:
        return False


def extract_any(
    src: Path,
    dest: Path,
    fmt: str = "auto",
    limits: Limits | None = None,
    seven_zip: str | None = None,
    _depth: int = 0,
    _budget: _Budget | None = None,
) -> None:
    """Extract ``src`` into ``dest`` and recurse into nested pkg/Payload/dmg/zip up to ``max_depth``."""
    limits = limits or Limits()
    budget = _budget or _Budget(limits)
    fmt = detect_format(src, fmt)
    dest.mkdir(parents=True, exist_ok=True)
    if fmt == "tar":
        extract_tar(src, dest, budget)
    elif fmt == "zip":
        extract_zip(src, dest, budget)
    elif fmt == "pkg":
        extract_xar(src, dest, budget)
    elif fmt == "dmg":
        extract_dmg(src, dest, budget, seven_zip)
    elif fmt == "gz":
        extract_gzip_single(src, dest, budget)
    elif fmt == "payload":
        extract_payload(src, dest, budget)
    else:
        _write(dest, src.name, src.read_bytes(), src.stat().st_size, budget)
        return
    if _depth >= limits.max_depth:
        return
    # Nested containers: component pkgs' Payload/Scripts, pkgs/dmgs/zips inside dmgs and zips.
    for p in sorted(dest.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        nested: str | None = None
        if p.name in ("Payload", "Scripts"):
            nested = "payload"
        elif p.suffix.lower() in (".pkg", ".dmg", ".zip", ".mpkg"):
            nested = detect_format(p)
            if nested == "file":
                nested = None
        if nested:
            sub = p.with_name(p.name + ".x")
            try:
                extract_any(p, sub, nested, limits, seven_zip, _depth + 1, budget)
            except (
                ExtractError,
                OSError,
                zipfile.BadZipFile,
                tarfile.TarError,
                zlib.error,
                lzma.LZMAError,
                ET.ParseError,
                ValueError,
                subprocess.TimeoutExpired,
            ) as e:
                log.info("nested extraction of %s skipped: %s", p.name, e)


# --- classification ---------------------------------------------------------------------------

_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
}
_SCRIPT_EXT = {
    ".sh",
    ".command",
    ".tool",
    ".py",
    ".rb",
    ".pl",
    ".js",
    ".applescript",
    ".scpt",
    ".zsh",
    ".bash",
    ".php",
    ".swift",
}


def classify(path: Path) -> str:
    """``macho`` | ``script`` | ``archive`` | ``other`` (cheap: reads 8 bytes)."""
    try:
        with path.open("rb") as f:
            head = f.read(8)
    except OSError:
        return "other"
    if head[:4] in _MACHO_MAGICS:
        # 0xCAFEBABE is shared with Java class files: fat headers have a small arch count.
        if head[:4] == b"\xca\xfe\xba\xbe" and int.from_bytes(head[4:8], "big") > 30:
            return "other"
        return "macho"
    if head[:2] == b"#!" or path.suffix.lower() in _SCRIPT_EXT or head.startswith(b"FasdUAS"):
        return "script"
    if head[:4] in (_XAR_MAGIC, b"PK\x03\x04") or path.suffix.lower() in (".dmg", ".pkg", ".zip"):
        return "archive"
    return "other"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def iter_files(roots: list[Path], max_bytes: int) -> Iterator[Path]:
    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames):
                p = Path(dirpath, name)
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and 0 < st.st_size <= max_bytes and not name.endswith(".complete"):
                    yield p


# --- download + cache -------------------------------------------------------------------------


@dataclass
class CorpusItem:
    name: str
    sha256: str
    root: Path
    archive: Path


def _resolve_bottle(http: Fetcher, formula: str, tags: list[str]) -> ArchiveSpec | None:
    doc = json.loads(http.get_bytes(FORMULA_API.format(name=formula), max_bytes=8 * 1024 * 1024))
    files = (((doc.get("bottle") or {}).get("stable") or {}).get("files")) or {}
    version = (doc.get("versions") or {}).get("stable", "")
    for tag in tags:
        f = files.get(tag)
        if f and f.get("url") and f.get("sha256"):
            return ArchiveSpec(f"brew:{formula}-{version}-{tag}", f["url"], f["sha256"].lower(), "tar")
    return None


def ensure_corpus(
    spec: CorpusSpec, cache: Path, http: Fetcher, limits: Limits | None = None, prune: bool = True
) -> list[CorpusItem]:
    """Download (or reuse from cache) and extract every corpus entry. Failures are logged and skipped."""
    limits = limits or Limits()
    seven_zip = find_7zip()
    dl_dir, x_dir = cache / "dl", cache / "x"
    dl_dir.mkdir(parents=True, exist_ok=True)
    x_dir.mkdir(parents=True, exist_ok=True)
    wanted: list[ArchiveSpec] = list(spec.archives)
    for formula in spec.homebrew_formulae:
        try:
            b = _resolve_bottle(http, formula, spec.bottle_tags)
            if b:
                wanted.append(b)
            else:
                log.warning("no arm64 bottle for %s", formula)
        except (FetchError, ValueError, KeyError) as e:
            log.warning("cannot resolve bottle %s: %s", formula, e)
    items: list[CorpusItem] = []
    for a in wanted:
        archive = dl_dir / a.sha256
        root = x_dir / a.sha256
        marker = x_dir / f"{a.sha256}.complete"
        try:
            if not archive.is_file() or sha256_file(archive) != a.sha256:
                headers = GHCR_ANON_AUTH if a.url.startswith("https://ghcr.io/") else None
                http.download(a.url, archive, headers=headers, sha256=a.sha256)
            if not marker.is_file():
                shutil.rmtree(root, ignore_errors=True)
                # The archive itself keeps its name (useful for hashing e.g. the .dmg users download).
                fmt = a.format if a.format != "auto" else detect_format(archive)
                if fmt == "dmg" and not seven_zip:
                    log.warning("%s: DMG skipped (no 7zz/7z)", a.name)
                    continue
                extract_any(archive, root, fmt, limits, seven_zip)
                marker.write_text(a.name + "\n")
            items.append(CorpusItem(a.name, a.sha256, root, archive))
        except (
            FetchError,
            ExtractError,
            OSError,
            zipfile.BadZipFile,
            tarfile.TarError,
            zlib.error,
            lzma.LZMAError,
            ET.ParseError,
            ValueError,
            subprocess.TimeoutExpired,
        ) as e:
            log.warning("corpus entry %s skipped: %s", a.name, e)
    if prune:
        keep = {i.sha256 for i in items} | {a.sha256 for a in wanted}
        for p in list(dl_dir.iterdir()) + list(x_dir.iterdir()):
            key = p.name.split(".")[0]
            if key not in keep:
                shutil.rmtree(p, ignore_errors=True) if p.is_dir() else p.unlink(missing_ok=True)
    return items
