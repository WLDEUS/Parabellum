"""pipeline.verify_bundle: the signing job's independent re-check of the nightly bundle (audit SC-4)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from pipeline import verify_bundle as vb
from pipeline import zbt
from pipeline.bundle import Manifest, Stats, deterministic_tar_gz, write_manifest
from pipeline.http import FetchError

SOURCES = """
[[source]]
name = "trusted-team-ids"
kind = "allowlist"
fetcher = "local_file"
url = "https://example.invalid/"
license = "MIT"
path = "pipeline/data/trusted_team_ids.txt"
dest = "allow/team_ids.txt"
"""
SINGBOX_SHA = "ab" * 32


def _repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "pipeline" / "data").mkdir(parents=True, exist_ok=True)
    (root / "pipeline" / "sources.toml").write_text(SOURCES)
    (root / "pipeline" / "data" / "trusted_team_ids.txt").write_text("ABCDE12345\n")
    return root


def _digests(*n: int) -> bytes:
    return b"".join(sorted(hashlib.sha256(str(i).encode()).digest() for i in n))


def _bundle(tmp_path: Path, name: str, files: dict[str, bytes]) -> Path:
    stage = tmp_path / f"stage-{name}"
    base = {
        "allow/team_ids.txt": b"ABCDE12345\n",
        "hashes/malware.sha256": _digests(*range(100)),
        "hashes/allow.sha256": _digests(*range(1000, 1100)),
        "dns/malware.txt": b"".join(f"d{i}.example\n".encode() for i in range(50)),
        "yara/a__x.yar": b"rule x { condition: false }\n",
    }
    base.update(files)
    for rel, data in base.items():
        if data is None:
            continue
        p = stage / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    write_manifest(stage, Manifest("2026.11.25.1", 0, "0.1.0", [], stats=Stats()))
    out = tmp_path / f"{name}.tar.gz"
    deterministic_tar_gz(stage, out)
    return out


def _no_upstream(*_a: object) -> None:
    raise FetchError("offline")


def _run(tmp_path, new, prev=None, ml_dir=None, zbt_up=_no_upstream, lookup=_no_upstream, attest=_no_upstream, **kw):
    root = _repo(tmp_path)
    return vb.verify(new, prev, ml_dir, root, root / "pipeline" / "sources.toml", zbt_up, lookup, attest, **kw)


def test_clean_bundle_passes(tmp_path):
    prev = _bundle(tmp_path, "prev", {})
    new = _bundle(tmp_path, "new", {"dns/malware.txt": b"".join(f"n{i}.example\n".encode() for i in range(40))})
    assert _run(tmp_path, new, prev) == ([], [])


def test_curated_file_tampering_is_refused(tmp_path):
    new = _bundle(tmp_path, "new", {"allow/team_ids.txt": b"ABCDE12345\nEVILTEAM01\n"})
    blocking, _ = _run(tmp_path, new)
    assert any("allow/team_ids.txt differs" in p for p in blocking)


def test_file_not_in_manifest_is_refused(tmp_path):
    new = _bundle(tmp_path, "new", {})
    stage = tmp_path / "stage-new"
    (stage / "yara" / "planted.yar").write_text("rule p { condition: false }")
    deterministic_tar_gz(stage, new)
    blocking, _ = _run(tmp_path, new)
    assert any("planted.yar is not listed" in p for p in blocking)


def test_ml_must_come_from_previous_bundle_or_signed_assets(tmp_path):
    prev = _bundle(tmp_path, "prev", {"ml/macho_model.json": b'{"old":1}'})
    same = _bundle(tmp_path, "same", {"ml/macho_model.json": b'{"old":1}'})
    assert _run(tmp_path, same, prev)[0] == []
    new = _bundle(tmp_path, "new", {"ml/macho_model.json": b'{"new":1}'})
    blocking, _ = _run(tmp_path, new, prev)
    assert any("ml/macho_model.json" in p for p in blocking)
    signed = tmp_path / "ml-verified"
    signed.mkdir()
    (signed / "macho_model.json").write_bytes(b'{"new":1}')
    assert _run(tmp_path, new, prev, ml_dir=signed)[0] == []


def _zbt_files(script: bytes, version: str = "1.2.3") -> dict[str, bytes]:
    meta = {
        "version": version,
        "sha256": hashlib.sha256(script).hexdigest(),
        "signer_fingerprint": zbt.PINNED_FINGERPRINT,
        "indicators_updated_at": 0,
    }
    return {zbt.BUNDLE_SCRIPT: script, zbt.BUNDLE_META: json.dumps(meta).encode()}


def test_new_zbt_script_needs_upstream_confirmation(tmp_path):
    prev = _bundle(tmp_path, "prev", _zbt_files(b"print('v1')\n"))
    carried = _bundle(tmp_path, "carried", _zbt_files(b"print('v1')\n"))
    assert _run(tmp_path, carried, prev)[0] == []  # same script: no network needed

    new = _bundle(tmp_path, "new", _zbt_files(b"print('v2')\n", "1.2.4"))
    blocking, _ = _run(tmp_path, new, prev)
    assert any("not confirmed upstream" in p for p in blocking)

    seen = []
    ok = _run(tmp_path, new, prev, zbt_up=lambda v, s: seen.append((v, s)))
    assert ok[0] == [] and seen == [("1.2.4", b"print('v2')\n")]


def test_zbt_meta_must_match_script(tmp_path):
    files = _zbt_files(b"print('v1')\n")
    files[zbt.BUNDLE_SCRIPT] = b"import os; os.system('evil')\n"
    blocking, _ = _run(tmp_path, _bundle(tmp_path, "new", files))
    assert blocking == ["zbt/meta.json sha256 does not match the script"]


def _pin(url: str, sha: str = SINGBOX_SHA, version: str = "1.12.3") -> bytes:
    pin = {"version": version, "asset": url.rsplit("/", 1)[-1], "url": url, "sha256": sha, "binary": "x/sing-box"}
    return json.dumps({"format": 1, "pins": {"sing-box": pin}}).encode()


def test_changed_pin_must_match_upstream_digest_and_attestation(tmp_path):
    asset = "sing-box-1.12.3-darwin-arm64.tar.gz"
    url = f"https://github.com/SagerNet/sing-box/releases/download/v1.12.3/{asset}"
    new = _bundle(tmp_path, "new", {"components/pins.json": _pin(url)})
    release = {"assets": [{"name": asset, "digest": f"sha256:{SINGBOX_SHA}"}]}
    attested = []
    ok = _run(tmp_path, new, lookup=lambda r, t: release, attest=lambda *a: attested.append(a))
    assert ok[0] == [] and attested[0][:3] == ("SagerNet/sing-box", url, SINGBOX_SHA)

    evil = _bundle(tmp_path, "evil", {"components/pins.json": _pin(url, "cd" * 32)})
    blocking, _ = _run(tmp_path, evil, lookup=lambda r, t: release, attest=lambda *a: None)
    assert any("not confirmed upstream" in p for p in blocking)

    other = _bundle(tmp_path, "other", {"components/pins.json": _pin("https://evil.example/sing-box.tar.gz")})
    blocking, _ = _run(tmp_path, other, lookup=lambda r, t: release, attest=lambda *a: None)
    assert any("is not the SagerNet/sing-box release asset" in p for p in blocking)


def test_allowlist_growth_and_malware_moves_are_bounded(tmp_path):
    prev = _bundle(tmp_path, "prev", {})
    # 30 of yesterday's malware hashes allowlisted: blocked unless overridden.
    moved = _bundle(tmp_path, "moved", {"hashes/allow.sha256": _digests(*range(1000, 1100), *range(30))})
    blocking, _ = _run(tmp_path, moved, prev)
    assert any("flagged as malware yesterday" in p for p in blocking)
    blocking, overridden = _run(tmp_path, moved, prev, allow_growth=True)
    assert blocking == [] and overridden

    big = _bundle(tmp_path, "big", {"hashes/allow.sha256": _digests(*range(1000, 1100 + vb.ALLOW_GROWTH_FLOOR + 1))})
    blocking, _ = _run(tmp_path, big, prev)
    assert any("allow.sha256 grows" in p for p in blocking)


def test_recounted_shrink_is_refused(tmp_path):
    prev = _bundle(tmp_path, "prev", {})
    new = _bundle(tmp_path, "new", {"hashes/malware.sha256": _digests(1, 2, 3)})
    blocking, _ = _run(tmp_path, new, prev)
    assert any("malware_hashes drops" in p for p in blocking)
    assert _run(tmp_path, new, prev, allow_shrink=True)[0] == []


@pytest.mark.parametrize("member", ["../escape", "/abs"])
def test_unsafe_tar_is_refused(tmp_path, member):
    import io
    import tarfile

    p = tmp_path / "bad.tar.gz"
    with tarfile.open(p, "w:gz") as tf:
        ti = tarfile.TarInfo(member)
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))
    with pytest.raises(ValueError):
        _run(tmp_path, p)


def test_published_manifest_must_match_the_bundle(tmp_path):
    new = _bundle(tmp_path, "new", {})
    ext = tmp_path / "manifest.json"
    ext.write_bytes((tmp_path / "stage-new" / "manifest.json").read_bytes())
    assert _run(tmp_path, new, external_manifest=ext)[0] == []
    ext.write_text('{"version": "2099.01.01.1"}')
    blocking, _ = _run(tmp_path, new, external_manifest=ext)
    assert blocking == ["the published manifest.json differs from the bundle's"]
