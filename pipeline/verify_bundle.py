"""Independent check of a freshly built threat-DB bundle before it is signed (audit SC-4).

``build-db`` downloads hostile data, unpacks malware samples and runs third-party code, so it must be
assumed compromisable. This module runs in a separate job (``verify-db`` in nightly-db.yml: fresh
runner, read-only token, no secret) and re-derives, from sources ``build-db`` cannot influence, every
part of the bundle that can be checked without rebuilding it:

* curated files (``local_file`` sources of sources.toml: trusted Team IDs, DNS allowlist, osquery
  hunting pack) must be byte-identical to the repository;
* ``zbt/zero-breach-toolkit.py`` (Python executed by the daemon) must be the previous signed bundle's
  copy, or a script listed in an upstream ``SHA256SUMS`` signed by the pinned publisher key;
* every ``ml/`` file must be the previous bundle's copy or a signed asset of ml-latest /
  ml-domain-latest (``--ml-dir``, filled by scripts/fetch-ml-models.sh, which checks the signatures);
* ``components/*.json`` pins (binaries the daemon downloads and runs) must be the previous bundle's or
  match the upstream release: GitHub-computed asset digest, and for sing-box a valid build-provenance
  attestation;
* ``hashes/allow.sha256`` (known-good digests, they silence detection): bounded growth, and hashes the
  previous bundle called malware may only move to the allowlist in small numbers;
* coarse counts recomputed from the files (malware hashes, YARA rule files, blocked domains) must not
  drop by more than half, like the builder's own guard;
* the bundle's ``manifest.json`` digests must match its files, and the ``manifest.json`` published next to
  it must be the same bytes.

What it cannot check is the content of the feeds themselves (malware hashes, domains, YARA rules from
third parties): that is what the sanity guard, the FP gate and the client's own limits are for.

Usage: ``python -m pipeline.verify_bundle --bundle dist/db/parabellum-db.tar.gz [--manifest dist/db/manifest.json]
[--previous prev/…]
[--ml-dir ml-verified] [--allow-shrink] [--allow-allowlist-growth]``. Exit 0 = OK, 2 = refused.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import re
import sys
import tempfile
import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path

from . import MANIFEST_FILE, zbt
from . import pins as pins_mod
from .bundle import safe_extract, verify_files
from .http import FetchError

log = logging.getLogger(__name__)

#: New allowlist entries accepted without ``--allow-allowlist-growth``: max(floor, ratio × previous).
ALLOW_GROWTH_FLOOR = 5000
ALLOW_GROWTH_RATIO = 0.10
#: Hashes flagged as malware by the previous bundle that may move to the allowlist in one night.
ALLOW_FROM_MALWARE_MAX = 25
#: Largest accepted drop of a recomputed count (same spirit as settings.sanity_max_drop).
MAX_DROP = 0.5

PIN_FILES = (pins_mod.BUNDLE_PATH, pins_mod.OLLAMA_BUNDLE_PATH)
_PIN_REPOS = {"sing-box": pins_mod.DEFAULT_REPO, "ollama": pins_mod.OLLAMA_REPO}
_SHA = re.compile(r"^[0-9a-f]{64}$")

#: ``(repo, tag) -> release JSON`` (raises FetchError).
ReleaseLookup = Callable[[str, str], Mapping[str, object]]
#: ``(repo, asset URL, sha256, binary inside the tarball)``: raise FetchError unless attested upstream.
AttestCheck = Callable[[str, str, str, str], None]
#: ``(version, script bytes)``: raise FetchError unless listed in the publisher's signed SHA256SUMS.
ZbtCheck = Callable[[str, bytes], None]


def _read(p: Path) -> bytes | None:
    return p.read_bytes() if p.is_file() and not p.is_symlink() else None


def _digests(p: Path) -> set[bytes]:
    data = _read(p) or b""
    if len(data) % 32:
        raise ValueError(f"{p.name}: size {len(data)} is not a multiple of 32")
    return {data[i : i + 32] for i in range(0, len(data), 32)}


def curated_files(sources_toml: Path) -> dict[str, str]:
    """``dest -> repo path`` of the ``local_file`` sources."""
    doc = tomllib.loads(sources_toml.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for s in doc.get("source", []):
        if isinstance(s, dict) and s.get("fetcher") == "local_file":
            out[str(s["dest"])] = str(s["path"])
    return out


def check_curated(new: Path, repo_root: Path, curated: Mapping[str, str]) -> list[str]:
    problems = []
    for dest, path in sorted(curated.items()):
        want = _read(repo_root / path)
        got = _read(new / dest)
        if want is None:
            problems.append(f"curated source {path} missing from the checkout")
        elif got != want:
            problems.append(f"{dest} differs from {path} in the repository")
    return problems


def check_manifest(new: Path) -> list[str]:
    p = new / MANIFEST_FILE
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return [f"{MANIFEST_FILE}: unreadable ({e})"]
    if not isinstance(doc, dict):
        return [f"{MANIFEST_FILE}: not an object"]
    bad = verify_files(new, doc)
    listed = set(doc.get("files", {}) if isinstance(doc.get("files"), dict) else {})
    on_disk = {q.relative_to(new).as_posix() for q in new.rglob("*") if q.is_file()} - {MANIFEST_FILE}
    out = [f"{MANIFEST_FILE}: digest mismatch for {b}" for b in bad]
    out += [f"{MANIFEST_FILE}: {x} is not listed" for x in sorted(on_disk - listed)]
    return out


def check_ml(new: Path, prev: Path | None, ml_dir: Path | None) -> list[str]:
    problems = []
    root = new / "ml"
    if not root.is_dir():
        return problems
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            continue
        rel = p.relative_to(root).as_posix()
        data = _read(p)
        if prev is not None and data is not None and _read(prev / "ml" / rel) == data:
            continue
        if ml_dir is not None and "/" not in rel and data is not None and _read(ml_dir / rel) == data:
            continue
        problems.append(f"ml/{rel} is neither the previous bundle's copy nor a signed ML release asset")
    return problems


def upstream_zbt_check(http: object, verifier: zbt.Verifier, repo: str = "interplains/Zero-Breach-Toolkit") -> ZbtCheck:
    """``(version, script)`` -> raise unless the release ``version`` lists the script in a signed SHA256SUMS."""

    def check(version: str, script: bytes) -> None:
        get = http.get_bytes  # type: ignore[attr-defined]
        last: Exception | None = None
        for tag in (f"v{version}", version):
            url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
            try:
                rel = zbt.pick_assets(
                    json.loads(get(url, headers=zbt._github_headers(url), max_bytes=4 * zbt.MAX_SMALL))
                )
            except (FetchError, ValueError) as e:
                last = e
                continue
            sums = get(rel.sums_url, max_bytes=zbt.MAX_SMALL)
            sig = get(rel.sums_sig_url, max_bytes=zbt.MAX_SMALL)
            keys = []
            for k in rel.key_urls:
                try:
                    keys.append(get(k, max_bytes=zbt.MAX_SMALL))
                except FetchError as e:
                    log.info("key asset %s: %s", k, e)
            signer = zbt.norm_fpr(verifier.verify(sums, sig, keys))
            if signer != zbt.PINNED_FINGERPRINT:
                raise FetchError(f"SHA256SUMS signed by {signer}")
            if (
                zbt.parse_sums(sums.decode("utf-8", errors="replace"), rel.script_name)
                != hashlib.sha256(script).hexdigest()
            ):
                raise FetchError(f"{rel.script_name} does not match the signed SHA256SUMS of {tag}")
            return
        raise FetchError(f"release {version} not found upstream: {last}")

    return check


def check_zbt(new: Path, prev: Path | None, upstream: ZbtCheck) -> list[str]:
    script = _read(new / zbt.BUNDLE_SCRIPT)
    meta_raw = _read(new / zbt.BUNDLE_META)
    if script is None and meta_raw is None and not (new / "zbt").exists():
        return []
    if script is None or meta_raw is None:
        return ["zbt/: script or meta.json missing"]
    try:
        meta = json.loads(meta_raw)
    except ValueError:
        return ["zbt/meta.json is not JSON"]
    digest = hashlib.sha256(script).hexdigest()
    if not isinstance(meta, dict) or meta.get("sha256") != digest:
        return ["zbt/meta.json sha256 does not match the script"]
    if zbt.norm_fpr(str(meta.get("signer_fingerprint", ""))) != zbt.PINNED_FINGERPRINT:
        return ["zbt/meta.json names an unexpected signer"]
    if prev is not None and _read(prev / zbt.BUNDLE_SCRIPT) == script:
        return []
    version = str(meta.get("version", ""))
    if not zbt._VERSION.match(version):
        return [f"zbt/meta.json: bad version {version!r}"]
    try:
        upstream(version, script)
    except (FetchError, OSError, ValueError) as e:
        return [f"zbt script {version} not confirmed upstream: {e}"]
    return []


def github_release_lookup(http: object) -> ReleaseLookup:
    def lookup(repo: str, tag: str) -> Mapping[str, object]:
        url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
        doc = json.loads(http.get_bytes(url, headers=pins_mod._github_headers(url), max_bytes=16 * 1024 * 1024))  # type: ignore[attr-defined]
        if not isinstance(doc, dict):
            raise FetchError("unexpected release JSON")
        return doc

    return lookup


def gh_attest_check(http: object, attestor: pins_mod.Attestor) -> AttestCheck:
    """Download the asset, check its digest, the binary inside, and the build-provenance attestation."""

    def check(repo: str, url: str, sha256: str, binary: str) -> None:
        with tempfile.TemporaryDirectory(prefix="verify-pin-") as tmp:
            dest = Path(tmp) / url.rsplit("/", 1)[-1]
            got = http.download(url, dest, max_bytes=pins_mod.MAX_ASSET)  # type: ignore[attr-defined]
            if got != sha256:
                raise FetchError("downloaded asset does not match the pin")
            if binary:
                pins_mod.check_tarball(dest.read_bytes(), binary)
            attestor.verify(dest, repo)

    return check


def check_pins(new: Path, prev: Path | None, lookup: ReleaseLookup, attest: AttestCheck) -> list[str]:
    problems: list[str] = []
    for rel in PIN_FILES:
        data = _read(new / rel)
        if data is None or (prev is not None and _read(prev / rel) == data):
            continue
        try:
            entries = json.loads(data)["pins"]
        except (ValueError, KeyError, TypeError):
            entries = None
        if not isinstance(entries, dict) or not entries:
            problems.append(f"{rel}: malformed")
            continue
        for name, pin in entries.items():
            repo = _PIN_REPOS.get(str(name))
            if repo is None or not isinstance(pin, dict):
                problems.append(f"{rel}: unknown component {name!r}")
                continue
            version, asset = str(pin.get("version", "")), str(pin.get("asset", ""))
            url, sha = str(pin.get("url", "")), str(pin.get("sha256", ""))
            if not _SHA.match(sha) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
                problems.append(f"{rel}: {name}: bad version or sha256")
                continue
            tag = f"v{version}"
            if url != f"https://github.com/{repo}/releases/download/{tag}/{asset}":
                problems.append(f"{rel}: {name}: URL {url!r} is not the {repo} release asset")
                continue
            try:
                release = lookup(repo, tag)
                if release.get("draft") or release.get("prerelease"):
                    raise FetchError("draft or prerelease")
                digests = {
                    str(a.get("name")): str(a.get("digest", ""))
                    for a in release.get("assets", [])  # type: ignore[union-attr]
                    if isinstance(a, dict)
                }
                if digests.get(asset) != f"sha256:{sha}":
                    raise FetchError(f"GitHub digest of {asset} is {digests.get(asset)!r}, pin says sha256:{sha}")
                if name == "sing-box":
                    attest(repo, url, sha, str(pin.get("binary", "")))
            except (FetchError, OSError, ValueError) as e:
                problems.append(f"{rel}: {name} {version} not confirmed upstream: {e}")
    return problems


def check_allowlist(new: Path, prev: Path | None) -> list[str]:
    if prev is None:
        return []
    allow_new = _digests(new / "hashes" / "allow.sha256")
    allow_old = _digests(prev / "hashes" / "allow.sha256")
    mal_old = _digests(prev / "hashes" / "malware.sha256")
    added = allow_new - allow_old
    limit = max(ALLOW_GROWTH_FLOOR, int(ALLOW_GROWTH_RATIO * len(allow_old)))
    problems = []
    if len(added) > limit:
        problems.append(f"allow.sha256 grows by {len(added)} digests (limit {limit})")
    moved = added & mal_old
    if len(moved) > ALLOW_FROM_MALWARE_MAX:
        problems.append(
            f"{len(moved)} digests flagged as malware yesterday are now allowlisted (limit {ALLOW_FROM_MALWARE_MAX})"
        )
    return problems


def counts(root: Path) -> dict[str, int]:
    domains: set[str] = set()
    dns = root / "dns"
    if dns.is_dir():
        for p in dns.glob("*.txt"):
            if p.name != "allowlist.txt" and p.is_file():
                domains.update(ln for ln in p.read_text(encoding="ascii", errors="replace").split() if ln[:1] != "#")
    yara = root / "yara"
    return {
        "malware_hashes": len(_digests(root / "hashes" / "malware.sha256")),
        "yara_files": sum(1 for p in yara.glob("*.yar") if p.is_file()) if yara.is_dir() else 0,
        "blocked_domains": len(domains),
    }


def check_shrink(new: Path, prev: Path | None) -> list[str]:
    if prev is None:
        return []
    a, b = counts(prev), counts(new)
    return [
        f"{k} drops from {a[k]} to {b[k]} (recounted from the files)"
        for k in a
        if a[k] > 0 and b[k] < a[k] * (1 - MAX_DROP)
    ]


def verify(
    bundle: Path,
    previous: Path | None,
    ml_dir: Path | None,
    repo_root: Path,
    sources_toml: Path,
    zbt_upstream: ZbtCheck,
    release_lookup: ReleaseLookup,
    attest: AttestCheck,
    allow_shrink: bool = False,
    allow_growth: bool = False,
    external_manifest: Path | None = None,
) -> tuple[list[str], list[str]]:
    """``(blocking problems, overridden problems)``."""
    with tempfile.TemporaryDirectory(prefix="verify-db-") as tmp:
        new = Path(tmp) / "new"
        safe_extract(bundle, new)
        prev = None
        if previous is not None and previous.is_file():
            prev = Path(tmp) / "prev"
            safe_extract(previous, prev)
        hard = check_manifest(new)
        if external_manifest is not None and _read(external_manifest) != _read(new / MANIFEST_FILE):
            hard.append(f"the published {MANIFEST_FILE} differs from the bundle's")
        hard += check_curated(new, repo_root, curated_files(sources_toml))
        hard += check_zbt(new, prev, zbt_upstream)
        hard += check_ml(new, prev, ml_dir)
        hard += check_pins(new, prev, release_lookup, attest)
        growth = check_allowlist(new, prev)
        shrink = check_shrink(new, prev)
    blocking, overridden = list(hard), []
    (overridden if allow_growth else blocking).extend(growth)
    (overridden if allow_shrink else blocking).extend(shrink)
    return blocking, overridden


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bundle", type=Path, required=True)
    ap.add_argument("--manifest", type=Path, help="manifest.json published next to the bundle")
    ap.add_argument("--previous", type=Path, help="previous bundle, signature already verified")
    ap.add_argument("--ml-dir", type=Path, help="ML assets whose signatures were verified")
    ap.add_argument("--repo-root", type=Path, default=Path())
    ap.add_argument("--sources", type=Path, default=Path("pipeline/sources.toml"))
    ap.add_argument("--allow-shrink", action="store_true")
    ap.add_argument("--allow-allowlist-growth", action="store_true")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from .http import Http

    http = Http()
    blocking, overridden = verify(
        args.bundle,
        args.previous,
        args.ml_dir,
        args.repo_root,
        args.sources,
        upstream_zbt_check(http, zbt.GpgVerifier()),
        github_release_lookup(http),
        gh_attest_check(http, pins_mod.GhAttestor()),
        allow_shrink=args.allow_shrink,
        allow_growth=args.allow_allowlist_growth,
        external_manifest=args.manifest,
    )
    for p in overridden:
        print(f"::warning::verify-db (overridden): {p}")
    for p in blocking:
        print(f"::error::verify-db: {p}")
    if blocking:
        print("bundle refused: nothing will be signed", file=sys.stderr)
        return 2
    print("bundle verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
