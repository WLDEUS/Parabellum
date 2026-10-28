"""Zero Breach Toolkit source: asset discovery, signature pinning, checksum, indicator cache, carry-over."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from pipeline import sources, zbt
from pipeline.http import FetchError
from pipeline.sources import Context, Settings, SourceSpec

from .conftest import FakeHttp

API = zbt.DEFAULT_API
DL = "https://github.com/interplains/Zero-Breach-Toolkit/releases/download/v0.1.9/"
SCRIPT = b"#!/usr/bin/env python3\nprint('zbt')\n"


def release_json(names: list[str]) -> bytes:
    return json.dumps(
        {"tag_name": "v0.1.9", "assets": [{"name": n, "browser_download_url": DL + n} for n in names]}
    ).encode()


def routes(script: bytes = SCRIPT, listed: bytes | None = None) -> dict[str, bytes]:
    digest = hashlib.sha256(listed if listed is not None else script).hexdigest()
    names = [
        "zero-breach-toolkit.py",
        "zero-breach-toolkit.py.asc",
        "SHA256SUMS.txt",
        "SHA256SUMS.txt.asc",
        "archivegenocide-signing-key.asc",
    ]
    return {
        API: release_json(names),
        DL + "zero-breach-toolkit.py": script,
        DL + "SHA256SUMS.txt": f"{digest}  zero-breach-toolkit.py\n{'0' * 64}  other.txt\n".encode(),
        DL + "SHA256SUMS.txt.asc": b"-----BEGIN PGP SIGNATURE-----\n",
        DL + "archivegenocide-signing-key.asc": b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
    }


class FakeVerifier:
    def __init__(self, signer: str = zbt.PINNED_FINGERPRINT, fail: bool = False) -> None:
        self.signer, self.fail = signer, fail
        self.keys: list[bytes] = []

    def verify(self, data: bytes, signature: bytes, keys: list[bytes]) -> str:
        self.keys = keys
        if self.fail:
            raise FetchError("bad signature")
        return self.signer


def fake_runner(code: int = 0, sources_doc: object | None = None):
    calls: list[tuple[Path, Path]] = []

    def run(script: Path, cache: Path) -> int:
        calls.append((script, cache))
        assert script.read_bytes() == SCRIPT
        doc = sources_doc if sources_doc is not None else {"mvt-pegasus": {"file": "pegasus.stix2"}}
        (cache / "manifest.json").write_text(json.dumps({"tool": "zero-breach-toolkit", "sources": doc}))
        (cache / "pegasus.stix2").write_text('{"type": "bundle"}')
        (cache / ".manifest.tmp").write_text("partial")
        return code

    run.calls = calls  # type: ignore[attr-defined]
    return run


def test_pick_assets_and_sums() -> None:
    rel = zbt.pick_assets(json.loads(routes()[API]))
    assert rel.tag == "v0.1.9"
    assert rel.script_url.endswith("/zero-breach-toolkit.py")
    assert rel.sums_sig_url.endswith("/SHA256SUMS.txt.asc")
    assert rel.key_urls == [DL + "archivegenocide-signing-key.asc"]
    with pytest.raises(FetchError):
        zbt.pick_assets({"assets": [{"name": "zero-breach-toolkit.py", "browser_download_url": DL + "x"}]})
    with pytest.raises(FetchError):  # checksum manifest without signature
        zbt.pick_assets(json.loads(release_json(["zero-breach-toolkit.py", "SHA256SUMS.txt"])))
    text = f"{'a' * 64} *zero-breach-toolkit.py\n"
    assert zbt.parse_sums(text, "zero-breach-toolkit.py") == "a" * 64
    with pytest.raises(FetchError):
        zbt.parse_sums(text, "other.py")


def test_fetch_release_ok(tmp_path: Path) -> None:
    key_file = tmp_path / "key.asc"
    key_file.write_bytes(b"committed key")
    v = FakeVerifier()
    run = fake_runner()
    files, count = zbt.fetch_release(API, FakeHttp(routes()), 1_793_000_000, v, run, key_file)
    assert count == 1
    assert files["zbt/zero-breach-toolkit.py"] == SCRIPT
    assert files["zbt/indicators/manifest.json"].startswith(b"{")
    assert "zbt/indicators/pegasus.stix2" in files
    assert not any(".manifest" in k for k in files), "hidden temp files are not bundled"
    meta = json.loads(files["zbt/meta.json"])
    assert meta == {
        "version": "0.1.9",
        "sha256": hashlib.sha256(SCRIPT).hexdigest(),
        "indicators_updated_at": 1_793_000_000,
        "signer_fingerprint": zbt.PINNED_FINGERPRINT,
    }
    assert v.keys == [b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n", b"committed key"]


@pytest.mark.parametrize(
    ("verifier", "route_kw", "runner", "message"),
    [
        (FakeVerifier(fail=True), {}, fake_runner(), "bad signature"),
        (FakeVerifier(signer="0" * 40), {}, fake_runner(), "expected"),
        (FakeVerifier(), {"listed": b"something else"}, fake_runner(), "SHA-256"),
        (FakeVerifier(), {}, fake_runner(code=2), "exited with 2"),
        (FakeVerifier(), {}, fake_runner(sources_doc={}), "no source"),
    ],
)
def test_fetch_release_refuses(verifier, route_kw, runner, message) -> None:
    with pytest.raises(FetchError, match=message):
        zbt.fetch_release(API, FakeHttp(routes(**route_kw)), 0, verifier, runner)
    if message in ("bad signature", "expected", "SHA-256"):
        assert not runner.calls, "downloaded code never runs before verification"


def test_previous_cache_seeds_update(tmp_path: Path) -> None:
    prev = tmp_path / "prev"
    prev.mkdir()
    (prev / "echap.csv").write_text("old")
    seen: list[str] = []

    def run(script: Path, cache: Path) -> int:
        seen.extend(sorted(p.name for p in cache.iterdir()))
        (cache / "manifest.json").write_text(json.dumps({"sources": {"echap": {}}}))
        return 1  # one source failed: previous copy kept

    files, _ = zbt.fetch_release(API, FakeHttp(routes()), 0, FakeVerifier(), run, previous=prev)
    assert seen == ["echap.csv"]
    assert files["zbt/indicators/echap.csv"] == b"old"


def test_check_status() -> None:
    fpr = zbt.PINNED_FINGERPRINT
    sub = "A" * 40
    ok = (
        "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 9B4D575499AFA53C ArchiveGenocide\n"
        f"[GNUPG:] VALIDSIG {sub} 2026-10-01 1790000000 0 4 0 22 10 00 {fpr}\n"
    )
    assert zbt.check_status(ok, fpr) == fpr
    with pytest.raises(FetchError, match="unexpected key"):
        zbt.check_status(ok.replace(fpr, "B" * 40), fpr)
    with pytest.raises(FetchError, match="bad"):
        zbt.check_status("[GNUPG:] BADSIG 9B4D575499AFA53C x\n", fpr)
    with pytest.raises(FetchError, match="no valid"):
        zbt.check_status("", fpr)


@pytest.mark.skipif(shutil.which("gpg") is None, reason="gpg not installed")
def test_gpg_verifier_real_signature(tmp_path: Path) -> None:
    """End to end with a throw-away Ed25519 key: good signature accepted, tampered data and other keys refused."""
    home = tmp_path / "signer"
    home.mkdir(mode=0o700)

    def gpg(*args: str, data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                "gpg",
                "--homedir",
                str(home),
                "--batch",
                "--no-tty",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                *args,
            ],
            input=data,
            capture_output=True,
            check=True,
            timeout=60,
        )

    gpg("--quick-gen-key", "Test Signer <test@example.invalid>", "ed25519", "sign", "never")
    listing = gpg("--with-colons", "--fingerprint").stdout.decode()
    fpr = next(ln.split(":")[9] for ln in listing.splitlines() if ln.startswith("fpr:"))
    pub = gpg("--armor", "--export", fpr).stdout
    data = b"abc  zero-breach-toolkit.py\n"
    sig = gpg("--armor", "--detach-sign", "--output", "-", data=data).stdout

    v = zbt.GpgVerifier(fingerprint=fpr, keyserver=None, timeout=60)
    assert v.verify(data, sig, [pub]) == fpr
    with pytest.raises(FetchError):
        v.verify(data + b"x", sig, [pub])
    with pytest.raises(FetchError, match="not available"):
        zbt.GpgVerifier(fingerprint="C" * 40, keyserver=None).verify(data, sig, [pub])
    with pytest.raises(FetchError, match="not available"):
        v.verify(data, sig, [])


def ctx_for(tmp_path: Path, http: FakeHttp, prev: Path | None = None) -> Context:
    return Context(http=http, repo_root=tmp_path, settings=Settings(), now=1_793_000_000, prev_dir=prev)


SPEC = SourceSpec(name="zero-breach-toolkit", kind="spyware", fetcher="zbt_release", url=API, license="Apache-2.0")


def test_fetch_all_carries_previous_zbt_over(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prev = tmp_path / "prev"
    (prev / "zbt" / "indicators").mkdir(parents=True)
    (prev / "zbt" / "zero-breach-toolkit.py").write_bytes(SCRIPT)
    (prev / "zbt" / "meta.json").write_text("{}")
    (prev / "zbt" / "indicators" / "manifest.json").write_text("{}")
    (prev / "zbt" / "indicators" / "a.stix2").write_text("{}")
    ctx = ctx_for(tmp_path, FakeHttp(), prev)
    ctx.settings.sources = [SPEC]
    payloads, infos, errors = sources.fetch_all(ctx, None, prev, {"zero-breach-toolkit": {"fetched_at": 5}})
    assert "zero-breach-toolkit" in errors
    got = payloads["zero-breach-toolkit"]
    assert set(got.files) == {
        "zbt/zero-breach-toolkit.py",
        "zbt/meta.json",
        "zbt/indicators/manifest.json",
        "zbt/indicators/a.stix2",
    }
    assert got.count == 1
    assert infos[0].fresh is False and infos[0].fetched_at == 5

    # Nothing to carry over: the source is not listed at all.
    ctx = ctx_for(tmp_path, FakeHttp())
    ctx.settings.sources = [SPEC]
    payloads, infos, errors = sources.fetch_all(ctx, None, None, {})
    assert infos == [] and "zero-breach-toolkit" in errors

    # Fresh fetch through the registry with injected verifier / runner.
    monkeypatch.setattr(sources, "ZBT_VERIFIER", FakeVerifier)
    monkeypatch.setattr(sources, "ZBT_RUNNER", fake_runner())
    ctx = ctx_for(tmp_path, FakeHttp(routes()))
    ctx.settings.sources = [SPEC]
    payloads, infos, errors = sources.fetch_all(ctx, None, None, {})
    assert errors == {}
    assert infos[0].fresh and infos[0].count == 1
    assert "zbt/meta.json" in payloads["zero-breach-toolkit"].files
