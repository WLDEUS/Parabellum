"""Zero Breach Toolkit (ZBT): mercenary-spyware trace checker shipped inside the threat-DB bundle.

Trust chain: publisher GPG signature -> this CI step -> our minisign-signed bundle -> parabellumd.

1. Discover the latest release through the GitHub API; asset names are matched at runtime
   (``zero-breach-toolkit.py``, ``SHA256SUMS.txt``, ``SHA256SUMS.txt.asc``, the public key
   ``*key*.asc`` when published).
2. Import the publisher key in a throw-away GnuPG home (keys.openpgp.org, the release's key asset, then
   ``pipeline/data/zbt-signing-key.asc`` when committed) and refuse unless ``gpg --verify`` of
   ``SHA256SUMS.txt`` succeeds with a signature whose primary key is exactly the pinned fingerprint
   :data:`PINNED_FINGERPRINT`, and the script's SHA-256 matches its line in ``SHA256SUMS.txt``.
3. Run ``python3 -I zero-breach-toolkit.py --update --indicator-cache <dir> --no-menu`` (network, CI only;
   the cache is seeded with the previous bundle's copy so a failed source keeps its previous list).
4. Bundle ``zbt/zero-breach-toolkit.py``, ``zbt/indicators/*`` and ``zbt/meta.json``.

Any failure raises :class:`FetchError`: the builder then carries the previous ``zbt/`` over.
Code licence: Apache-2.0; indicators: CC0 / their publishers' terms.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .http import FetchError

log = logging.getLogger(__name__)

PINNED_FINGERPRINT = "C24EC92B12D6670A2516065F9B4D575499AFA53C"
DEFAULT_API = "https://api.github.com/repos/interplains/Zero-Breach-Toolkit/releases/latest"
KEYSERVER = "hkps://keys.openpgp.org"
SCRIPT_NAME = "zero-breach-toolkit.py"
BUNDLE_SCRIPT = "zbt/zero-breach-toolkit.py"
BUNDLE_META = "zbt/meta.json"
BUNDLE_INDICATORS = "zbt/indicators"
MAX_SCRIPT = 16 * 1024 * 1024
MAX_SMALL = 1024 * 1024
MAX_INDICATORS = 256 * 1024 * 1024
UPDATE_TIMEOUT = 15 * 60
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION = re.compile(r"^[0-9A-Za-z][0-9A-Za-z.+-]{0,31}$")


def norm_fpr(fpr: str) -> str:
    return re.sub(r"\s+", "", fpr).upper()


@dataclass
class Release:
    tag: str
    script_name: str
    script_url: str
    sums_url: str
    sums_sig_url: str
    key_urls: list[str] = field(default_factory=list)


def pick_assets(release: object) -> Release:
    """Find the scanner, the checksum manifest, its detached signature and the public key by name."""
    if not isinstance(release, dict):
        raise FetchError("unexpected release JSON")
    assets = {
        str(a.get("name", "")): str(a.get("browser_download_url", ""))
        for a in release.get("assets", [])
        if isinstance(a, dict)
    }
    assets = {n: u for n, u in assets.items() if n and u.startswith("https://")}

    def first(pred: Callable[[str], bool]) -> str | None:
        return next((n for n in sorted(assets) if pred(n)), None)

    script = SCRIPT_NAME if SCRIPT_NAME in assets else first(lambda n: re.fullmatch(r"zero-breach-toolkit.*\.py", n))
    sums = (
        "SHA256SUMS.txt"
        if "SHA256SUMS.txt" in assets
        else first(lambda n: n.upper().startswith("SHA256SUMS") and not n.endswith((".asc", ".sig")))
    )
    if not script or not sums:
        raise FetchError(f"release assets not found (have: {', '.join(sorted(assets)) or 'none'})")
    sig = next((n for n in (sums + ".asc", sums + ".sig") if n in assets), None)
    if not sig:
        raise FetchError(f"no detached signature for {sums}")
    keys = [assets[n] for n in sorted(assets) if n.endswith(".asc") and "key" in n.lower()]
    return Release(
        tag=str(release.get("tag_name", "")),
        script_name=script,
        script_url=assets[script],
        sums_url=assets[sums],
        sums_sig_url=assets[sig],
        key_urls=keys,
    )


def parse_sums(text: str, name: str) -> str:
    """SHA-256 of ``name`` in a ``sha256sum`` manifest (``<hex>  name`` or ``<hex> *name``)."""
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and parts[1].lstrip("*").strip() == name and re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            return parts[0].lower()
    raise FetchError(f"{name} is not listed in SHA256SUMS")


def check_status(status: str, fingerprint: str) -> str:
    """Validate ``gpg --status-fd`` output: a VALIDSIG made by the pinned (primary) key and no bad signature."""
    want = norm_fpr(fingerprint)
    lines = [ln.split() for ln in status.splitlines() if ln.startswith("[GNUPG:] ")]
    if any(t[1] in ("BADSIG", "ERRSIG", "EXPKEYSIG", "REVKEYSIG") for t in lines if len(t) > 1):
        raise FetchError("bad, expired or revoked signature")
    for t in lines:
        if len(t) > 2 and t[1] == "VALIDSIG":
            signer = norm_fpr(t[2])
            primary = norm_fpr(t[11]) if len(t) > 11 else signer
            if want in (signer, primary):
                return want
            raise FetchError(f"signature made by an unexpected key {primary}")
    raise FetchError("no valid signature")


class Verifier(Protocol):
    def verify(self, data: bytes, signature: bytes, keys: list[bytes]) -> str:
        """Verify a detached signature; returns the signer's primary-key fingerprint or raises FetchError."""
        ...


class GpgVerifier:
    """Detached-signature check with GnuPG in a throw-away keyring, pinned to one key."""

    def __init__(
        self,
        fingerprint: str = PINNED_FINGERPRINT,
        gpg: str | None = None,
        keyserver: str | None = KEYSERVER,
        timeout: float = 120.0,
    ) -> None:
        self.fingerprint = norm_fpr(fingerprint)
        self.gpg = gpg or shutil.which("gpg") or "gpg"
        self.keyserver = keyserver
        self.timeout = timeout

    def _run(self, home: str, args: list[str], data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [self.gpg, "--homedir", home, "--batch", "--no-tty", *args],
            input=data,
            capture_output=True,
            timeout=self.timeout,
            check=False,
        )

    def verify(self, data: bytes, signature: bytes, keys: list[bytes]) -> str:
        with tempfile.TemporaryDirectory(prefix="zbt-gpg-") as home:
            Path(home).chmod(0o700)
            if self.keyserver:
                try:
                    r = self._run(home, ["--keyserver", self.keyserver, "--recv-keys", self.fingerprint])
                    if r.returncode != 0:
                        log.info("keyserver: %s", r.stderr.decode(errors="replace").strip()[:200])
                except (OSError, subprocess.TimeoutExpired) as e:
                    log.info("keyserver unreachable: %s", e)
            for k in keys:
                try:
                    self._run(home, ["--import"], k)
                except (OSError, subprocess.TimeoutExpired) as e:
                    log.info("key import failed: %s", e)
            listed = self._run(home, ["--with-colons", "--fingerprint", self.fingerprint])
            fprs = {norm_fpr(ln.split(":")[9]) for ln in listed.stdout.decode().splitlines() if ln.startswith("fpr:")}
            if self.fingerprint not in fprs:
                raise FetchError(f"publisher key {self.fingerprint} not available (keyserver and key files failed)")
            d = Path(home)
            (d / "data").write_bytes(data)
            (d / "data.sig").write_bytes(signature)
            r = self._run(home, ["--status-fd", "1", "--verify", str(d / "data.sig"), str(d / "data")])
            signer = check_status(r.stdout.decode(errors="replace"), self.fingerprint)
            if r.returncode != 0:
                raise FetchError("gpg --verify failed")
            return signer


Runner = Callable[[Path, Path], int]


def run_update(script: Path, cache: Path) -> int:
    """``python3 -I <script> --update --indicator-cache <cache> --no-menu`` in an empty directory."""
    python = shutil.which("python3") or sys.executable
    with tempfile.TemporaryDirectory(prefix="zbt-run-") as cwd:
        env = {"PATH": "/usr/bin:/bin", "HOME": cwd, "LANG": "C.UTF-8"}
        for k in ("HTTPS_PROXY", "https_proxy", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
            if os.environ.get(k):
                env[k] = os.environ[k]
        r = subprocess.run(
            [python, "-I", str(script), "--update", "--indicator-cache", str(cache), "--no-menu", "--no-banner"],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=UPDATE_TIMEOUT,
            check=False,
        )
    for line in (r.stdout + r.stderr).decode(errors="replace").splitlines()[-30:]:
        log.info("zbt: %s", line)
    return r.returncode


def _github_headers(url: str) -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        h["Authorization"] = f"Bearer {token}"
    return h


def fetch_release(
    api_url: str,
    http: object,
    now: int,
    verifier: Verifier,
    runner: Runner,
    key_file: Path | None = None,
    previous: Path | None = None,
) -> tuple[dict[str, bytes], int]:
    """Bundle files for ZBT and the number of indicator sources. Raises FetchError on any doubt."""
    get = http.get_bytes  # type: ignore[attr-defined]
    rel = pick_assets(json.loads(get(api_url, headers=_github_headers(api_url), max_bytes=4 * MAX_SMALL)))
    version = rel.tag[1:] if rel.tag[:1] in ("v", "V") else rel.tag
    if not _VERSION.match(version):
        raise FetchError(f"unexpected release tag {rel.tag!r}")
    script = get(rel.script_url, max_bytes=MAX_SCRIPT)
    sums = get(rel.sums_url, max_bytes=MAX_SMALL)
    sig = get(rel.sums_sig_url, max_bytes=MAX_SMALL)
    keys: list[bytes] = []
    for url in rel.key_urls:
        try:
            keys.append(get(url, max_bytes=MAX_SMALL))
        except FetchError as e:
            log.info("key asset %s: %s", url, e)
    if key_file is not None and key_file.is_file():
        keys.append(key_file.read_bytes())
    signer = norm_fpr(verifier.verify(sums, sig, keys))
    if signer != PINNED_FINGERPRINT:
        raise FetchError(f"SHA256SUMS signed by {signer}, expected {PINNED_FINGERPRINT}")
    digest = hashlib.sha256(script).hexdigest()
    if parse_sums(sums.decode("utf-8", errors="replace"), rel.script_name) != digest:
        raise FetchError(f"{rel.script_name}: SHA-256 does not match the signed SHA256SUMS")

    files: dict[str, bytes] = {BUNDLE_SCRIPT: script}
    with tempfile.TemporaryDirectory(prefix="zbt-") as tmp:
        work = Path(tmp)
        (work / "bin").mkdir()
        (work / "bin" / SCRIPT_NAME).write_bytes(script)
        cache = work / "cache"
        cache.mkdir()
        if previous is not None and previous.is_dir():
            for p in previous.iterdir():
                if p.is_file() and not p.is_symlink() and _SAFE_NAME.match(p.name):
                    shutil.copyfile(p, cache / p.name)
        code = runner(work / "bin" / SCRIPT_NAME, cache)
        if code not in (0, 1):
            raise FetchError(f"zero-breach-toolkit --update exited with {code}")
        try:
            manifest = json.loads((cache / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise FetchError(f"indicator cache has no usable manifest.json: {e}") from e
        sources = manifest.get("sources") if isinstance(manifest, dict) else None
        if not isinstance(sources, dict) or not sources:
            raise FetchError("indicator manifest lists no source")
        if code == 1:
            log.warning("zbt --update: some indicator sources failed (previous copies kept when available)")
        total = 0
        for p in sorted(cache.iterdir()):
            if p.name.startswith(".") or not _SAFE_NAME.match(p.name) or p.is_symlink() or not p.is_file():
                continue
            data = p.read_bytes()
            total += len(data)
            if total > MAX_INDICATORS:
                raise FetchError("indicator cache exceeds the size limit")
            files[f"{BUNDLE_INDICATORS}/{p.name}"] = data
    meta = {
        "version": version,
        "sha256": digest,
        "indicators_updated_at": now,
        "signer_fingerprint": PINNED_FINGERPRINT,
    }
    files[BUNDLE_META] = (json.dumps(meta, indent=1, sort_keys=True) + "\n").encode()
    return files, len(sources)


def carry_over(prev_dir: Path) -> dict[str, bytes]:
    """Previous bundle's ``zbt/`` (all or nothing)."""
    root = prev_dir / "zbt"
    if not (root / SCRIPT_NAME).is_file() or not (root / "meta.json").is_file():
        return {}
    out: dict[str, bytes] = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink():
            out[p.relative_to(prev_dir).as_posix()] = p.read_bytes()
    return out
