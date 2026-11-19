"""Pinned third-party components: ``components/pins.json`` (``pb_core::db::ComponentPins``).

sing-box publishes no signature the Mac could check, but its release workflow attests every artefact
with GitHub build provenance (Sigstore, ``actions/attest``). Trust chain:
vendor attestation -> this CI step (``gh attestation verify --repo SagerNet/sing-box``) -> SHA-256 pinned in
our minisign-signed bundle -> parabellumd verifies the download against the pin.

1. Latest stable release through the GitHub API (drafts and prereleases skipped, ``>= 1.12`` and ``< 2``).
2. Asset ``sing-box-<v>-darwin-arm64.tar.gz`` (64 MB cap), SHA-256, cross-checked with the API ``digest``
   field when present.
3. The tarball must contain ``sing-box-<v>-darwin-arm64/sing-box``, a regular arm64 Mach-O.
4. ``gh attestation verify`` must succeed. Any failure raises :class:`FetchError`: the builder keeps the
   previous bundle's pin (or ships none).
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .http import FetchError

log = logging.getLogger(__name__)

BUNDLE_PATH = "components/pins.json"
DEFAULT_REPO = "SagerNet/sing-box"
DEFAULT_COMPONENT = "sing-box"
MAX_ASSET = 64 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024
#: ``MH_MAGIC_64`` little-endian + ``CPU_TYPE_ARM64``.
MACHO_ARM64 = bytes([0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01])
_TAG = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def api_url(repo: str) -> str:
    return f"https://api.github.com/repos/{repo}/releases?per_page=30"


def _github_headers(url: str) -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        h["Authorization"] = f"Bearer {token}"
    return h


@dataclass
class Candidate:
    version: str
    asset: str
    url: str
    digest: str | None


def parse_version(tag: str) -> tuple[int, int, int] | None:
    m = _TAG.match(tag.strip())
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def select_release(releases: object, min_version: tuple[int, int, int] = (1, 12, 0), max_major: int = 2) -> Candidate:
    """Newest stable release in ``[min_version, max_major)`` that has the darwin-arm64 tarball."""
    if not isinstance(releases, list):
        raise FetchError("unexpected releases JSON")
    best: tuple[tuple[int, int, int], Candidate] | None = None
    for rel in releases:
        if not isinstance(rel, dict) or rel.get("draft") or rel.get("prerelease"):
            continue
        v = parse_version(str(rel.get("tag_name", "")))
        if v is None or v < min_version or v[0] >= max_major:
            continue
        version = ".".join(map(str, v))
        name = f"sing-box-{version}-darwin-arm64.tar.gz"
        for a in rel.get("assets", []):
            if not isinstance(a, dict) or a.get("name") != name:
                continue
            url = str(a.get("browser_download_url", ""))
            if not url.startswith("https://github.com/"):
                continue
            digest = a.get("digest")
            dig = None
            if isinstance(digest, str) and digest.startswith("sha256:") and re.fullmatch(r"[0-9a-f]{64}", digest[7:]):
                dig = digest[7:]
            cand = Candidate(version, name, url, dig)
            if best is None or v > best[0]:
                best = (v, cand)
    if best is None:
        raise FetchError("no stable sing-box release with a darwin-arm64 tarball in range")
    return best[1]


def check_tarball(data: bytes, binary: str) -> None:
    """The archive holds ``binary`` as a regular arm64 Mach-O file."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for m in tf:
                if m.name.removeprefix("./") != binary:
                    continue
                if not m.isreg() or not (0 < m.size <= MAX_BINARY):
                    raise FetchError(f"{binary}: not a regular file of a sane size")
                f = tf.extractfile(m)
                head = f.read(8) if f else b""
                if head != MACHO_ARM64:
                    raise FetchError(f"{binary} is not an arm64 Mach-O")
                return
    except tarfile.TarError as e:
        raise FetchError(f"archive unreadable: {e}") from e
    raise FetchError(f"{binary} missing from the archive")


class Attestor(Protocol):
    def verify(self, file: Path, repo: str) -> None:
        """Raise FetchError unless ``file`` carries a valid build-provenance attestation from ``repo``."""
        ...


class GhAttestor:
    """``gh attestation verify <file> --repo <repo>`` (needs gh and GH_TOKEN / GITHUB_TOKEN)."""

    def __init__(self, gh: str | None = None, timeout: float = 300.0) -> None:
        self.gh = gh or shutil.which("gh") or "gh"
        self.timeout = timeout

    def verify(self, file: Path, repo: str) -> None:
        keep = ("PATH", "HOME", "GH_TOKEN", "GITHUB_TOKEN", "HTTPS_PROXY", "https_proxy", "SSL_CERT_FILE")
        env = {k: v for k, v in os.environ.items() if k in keep}
        try:
            r = subprocess.run(
                [self.gh, "attestation", "verify", str(file), "--repo", repo],
                capture_output=True,
                timeout=self.timeout,
                check=False,
                env=env,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            raise FetchError(f"gh attestation verify could not run: {e}") from e
        if r.returncode != 0:
            tail = (r.stderr or r.stdout).decode(errors="replace").strip()[-400:]
            raise FetchError(f"attestation verification failed: {tail}")


def fetch_pin(
    http: object,
    attestor: Attestor,
    repo: str = DEFAULT_REPO,
    component: str = DEFAULT_COMPONENT,
    min_version: tuple[int, int, int] = (1, 12, 0),
    max_major: int = 2,
) -> tuple[bytes, str]:
    """``components/pins.json`` content and the pinned version. Raises FetchError on any doubt."""
    url = api_url(repo)
    releases = json.loads(http.get_bytes(url, headers=_github_headers(url), max_bytes=16 * 1024 * 1024))  # type: ignore[attr-defined]
    cand = select_release(releases, min_version, max_major)
    with tempfile.TemporaryDirectory(prefix="pins-") as tmp:
        dest = Path(tmp) / cand.asset
        digest = http.download(cand.url, dest, max_bytes=MAX_ASSET)  # type: ignore[attr-defined]
        data = dest.read_bytes()
        if hashlib.sha256(data).hexdigest() != digest:
            raise FetchError("download digest mismatch")
        if cand.digest and cand.digest != digest:
            raise FetchError(f"{cand.asset}: SHA-256 differs from the release API digest")
        binary = f"sing-box-{cand.version}-darwin-arm64/sing-box"
        check_tarball(data, binary)
        attestor.verify(dest, repo)
    pins = {
        "format": 1,
        "pins": {
            component: {
                "version": cand.version,
                "asset": cand.asset,
                "url": cand.url,
                "sha256": digest,
                "binary": binary,
                "verified_by": f"github-attestation:{repo}",
            }
        },
    }
    log.info("pinned %s %s (%s)", component, cand.version, digest)
    return (json.dumps(pins, indent=1, sort_keys=True) + "\n").encode(), cand.version


def carry_over(prev_dir: Path) -> dict[str, bytes]:
    p = prev_dir / BUNDLE_PATH
    return {BUNDLE_PATH: p.read_bytes()} if p.is_file() and not p.is_symlink() else {}


# --- Ollama (local model server of the mail agent) ----------------------------------------------------
#
# Ollama publishes no build-provenance attestation, but ships a notarized Developer ID build. Trust chain:
# GitHub release API digest (computed by GitHub at upload) == SHA-256 of our download -> the archive holds a
# Mach-O `ollama` whose embedded signing certificate names Ollama's Apple Team ID (sanity check here;
# parabellumd verifies the real code signature with `codesign` before running it) -> SHA-256 pinned in our
# minisign-signed bundle (components/ollama.json, same format as pins.json) -> the daemon checks the download.

OLLAMA_BUNDLE_PATH = "components/ollama.json"
OLLAMA_REPO = "ollama/ollama"
OLLAMA_ASSET = "ollama-darwin.tgz"
OLLAMA_TEAM_ID = "3MU9H2V9Y9"
MAX_OLLAMA_ASSET = 400 * 1024 * 1024
#: Mach-O universal (fat) or thin arm64.
_MACHO_HEADS = (bytes([0xCA, 0xFE, 0xBA, 0xBE]), MACHO_ARM64[:4])


def select_ollama(releases: object, min_version: tuple[int, int, int] = (0, 12, 0)) -> Candidate:
    """Newest stable Ollama release with ``ollama-darwin.tgz`` and a GitHub digest (required)."""
    if not isinstance(releases, list):
        raise FetchError("unexpected releases JSON")
    best: tuple[tuple[int, int, int], Candidate] | None = None
    for rel in releases:
        if not isinstance(rel, dict) or rel.get("draft") or rel.get("prerelease"):
            continue
        tag = str(rel.get("tag_name", ""))
        v = parse_version(tag)
        if v is None or v < min_version:
            continue
        for a in rel.get("assets", []):
            if not isinstance(a, dict) or a.get("name") != OLLAMA_ASSET:
                continue
            url = str(a.get("browser_download_url", ""))
            if url != f"https://github.com/{OLLAMA_REPO}/releases/download/{tag}/{OLLAMA_ASSET}":
                continue
            digest = a.get("digest")
            hexd = digest[7:] if isinstance(digest, str) and digest.startswith("sha256:") else ""
            if not re.fullmatch(r"[0-9a-f]{64}", hexd):
                continue
            cand = Candidate(".".join(map(str, v)), OLLAMA_ASSET, url, hexd)
            if best is None or v > best[0]:
                best = (v, cand)
    if best is None:
        raise FetchError("no stable Ollama release with ollama-darwin.tgz and a digest")
    return best[1]


def check_ollama_tarball(path: Path, team_id: str = OLLAMA_TEAM_ID) -> None:
    """``ollama`` is a regular Mach-O signed with a certificate naming ``team_id``; no link or absolute path."""
    try:
        with tarfile.open(path, mode="r:gz") as tf:
            found = False
            for m in tf:
                name = m.name.removeprefix("./")
                if name.startswith("/") or ".." in name.split("/"):
                    raise FetchError(f"unsafe path in the archive: {name}")
                if m.issym() or m.islnk():
                    target = m.linkname
                    if target.startswith("/") or ".." in target.split("/"):
                        raise FetchError(f"unsafe link in the archive: {name} -> {target}")
                if name != "ollama":
                    continue
                if not m.isreg() or not (0 < m.size <= MAX_BINARY):
                    raise FetchError("ollama: not a regular file of a sane size")
                f = tf.extractfile(m)
                data = f.read() if f else b""
                if not data.startswith(_MACHO_HEADS):
                    raise FetchError("ollama is not a Mach-O")
                if f"({team_id})".encode() not in data or b"Developer ID Application" not in data:
                    raise FetchError(f"ollama is not signed with Team ID {team_id}")
                found = True
    except tarfile.TarError as e:
        raise FetchError(f"archive unreadable: {e}") from e
    if not found:
        raise FetchError("ollama missing from the archive")


def fetch_ollama_pin(http: object, min_version: tuple[int, int, int] = (0, 12, 0)) -> tuple[bytes, str]:
    """``components/ollama.json`` content and the pinned version. Raises FetchError on any doubt."""
    url = api_url(OLLAMA_REPO)
    releases = json.loads(http.get_bytes(url, headers=_github_headers(url), max_bytes=16 * 1024 * 1024))  # type: ignore[attr-defined]
    cand = select_ollama(releases, min_version)
    with tempfile.TemporaryDirectory(prefix="pins-ollama-") as tmp:
        dest = Path(tmp) / cand.asset
        digest = http.download(cand.url, dest, max_bytes=MAX_OLLAMA_ASSET)  # type: ignore[attr-defined]
        h = hashlib.sha256()
        with dest.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != digest:
            raise FetchError("download digest mismatch")
        if cand.digest != digest:
            raise FetchError(f"{cand.asset}: SHA-256 differs from the release API digest")
        check_ollama_tarball(dest)
    pins = {
        "format": 1,
        "pins": {
            "ollama": {
                "version": cand.version,
                "asset": cand.asset,
                "url": cand.url,
                "sha256": digest,
                "binary": "ollama",
                "verified_by": f"github-release-digest+team-id:{OLLAMA_TEAM_ID}",
            }
        },
    }
    log.info("pinned ollama %s (%s)", cand.version, digest)
    return (json.dumps(pins, indent=1, sort_keys=True) + "\n").encode(), cand.version


def carry_over_ollama(prev_dir: Path) -> dict[str, bytes]:
    p = prev_dir / OLLAMA_BUNDLE_PATH
    return {OLLAMA_BUNDLE_PATH: p.read_bytes()} if p.is_file() and not p.is_symlink() else {}
