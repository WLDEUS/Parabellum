"""sing-box pin: release selection, tarball checks, attestation, digest cross-check, build integration."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile

import pytest

from pipeline import pins, sources
from pipeline.build import SHADOWROCKET_FILE, build, parse_args
from pipeline.http import FetchError

from .conftest import FakeHttp
from .test_build import NOW, setup
from .test_privacy import DN, ER, ERASER_YAML, sample_tarball

API = pins.api_url("SagerNet/sing-box")
DL = "https://github.com/SagerNet/sing-box/releases/download/"
MACHO = pins.MACHO_ARM64 + b"\x00" * 64


def tarball(version: str, binary: bytes = MACHO, with_binary: bool = True) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        files = {f"sing-box-{version}-darwin-arm64/LICENSE": b"GPL"}
        if with_binary:
            files[f"sing-box-{version}-darwin-arm64/sing-box"] = binary
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def release(tag: str, prerelease: bool = False, digest: str | None = None, draft: bool = False) -> dict:
    v = tag.lstrip("v")
    asset = {
        "name": f"sing-box-{v}-darwin-arm64.tar.gz",
        "browser_download_url": f"{DL}{tag}/sing-box-{v}-darwin-arm64.tar.gz",
    }
    if digest:
        asset["digest"] = f"sha256:{digest}"
    other = {"name": f"sing-box-{v}-linux-amd64.tar.gz", "browser_download_url": f"{DL}{tag}/x"}
    return {"tag_name": tag, "prerelease": prerelease, "draft": draft, "assets": [other, asset]}


class FakeAttestor:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, str]] = []

    def verify(self, file, repo: str) -> None:
        self.calls.append((file.name, repo))
        if self.fail:
            raise FetchError("attestation verification failed: no matching attestation")


def routes(digest_ok: bool = True, data: bytes | None = None) -> dict[str, bytes]:
    data = data if data is not None else tarball("1.14.4")
    digest = hashlib.sha256(data).hexdigest() if digest_ok else "0" * 64
    rels = [
        release("v1.15.0-alpha.13", prerelease=True),
        release("v2.0.0"),
        release("v1.14.4", digest=digest),
        release("v1.14.5", draft=True),
        release("v1.11.15"),
    ]
    return {API: json.dumps(rels).encode(), f"{DL}v1.14.4/sing-box-1.14.4-darwin-arm64.tar.gz": data}


def test_select_release() -> None:
    c = pins.select_release(json.loads(routes()[API]))
    assert c.version == "1.14.4" and c.asset == "sing-box-1.14.4-darwin-arm64.tar.gz" and c.digest
    with pytest.raises(FetchError):
        pins.select_release([release("v1.11.0")])
    with pytest.raises(FetchError):
        pins.select_release({"message": "rate limited"})
    assert pins.parse_version("v1.15.0-alpha.13") is None and pins.parse_version("1.12.0") == (1, 12, 0)


def test_fetch_pin_ok() -> None:
    att = FakeAttestor()
    data, version = pins.fetch_pin(FakeHttp(routes()), att)
    doc = json.loads(data)
    pin = doc["pins"]["sing-box"]
    assert doc["format"] == 1 and version == "1.14.4"
    assert pin["binary"] == "sing-box-1.14.4-darwin-arm64/sing-box"
    assert pin["sha256"] == hashlib.sha256(tarball("1.14.4")).hexdigest()
    assert pin["url"].startswith("https://github.com/SagerNet/sing-box/releases/download/v1.14.4/")
    assert pin["verified_by"] == "github-attestation:SagerNet/sing-box"
    assert att.calls == [("sing-box-1.14.4-darwin-arm64.tar.gz", "SagerNet/sing-box")]


@pytest.mark.parametrize(
    "r,att,msg",
    [
        (routes(digest_ok=False), FakeAttestor(), "API digest"),
        (routes(), FakeAttestor(fail=True), "attestation"),
        (routes(data=tarball("1.14.4", with_binary=False)), FakeAttestor(), "missing"),
        (routes(data=tarball("1.14.4", binary=b"#!/bin/sh\necho hi\n")), FakeAttestor(), "arm64 Mach-O"),
    ],
)
def test_fetch_pin_refusals(r, att, msg) -> None:
    if "API digest" not in msg:
        # Keep the API digest consistent with the served file for the other cases.
        data = r[f"{DL}v1.14.4/sing-box-1.14.4-darwin-arm64.tar.gz"]
        rels = json.loads(r[API])
        rels[2]["assets"][1]["digest"] = "sha256:" + hashlib.sha256(data).hexdigest()
        r[API] = json.dumps(rels).encode()
    with pytest.raises(FetchError, match=msg):
        pins.fetch_pin(FakeHttp(r), att)


def test_build_ships_brokers_pins_and_shadowrocket_list(tmp_path, monkeypatch) -> None:
    srcs, corpus, http = setup(tmp_path, monkeypatch)
    srcs.write_text(
        srcs.read_text()
        + f"""
[[source]]
name = "data-brokers"
kind = "privacy"
fetcher = "privacy_brokers"
url = "https://github.com/datenanfragen/data"
license = "CC0-1.0 + MIT"
datenanfragen_commit = "{DN}"
eraser_commit = "{ER}"
min_brokers = 5
[[source]]
name = "sing-box"
kind = "components"
fetcher = "component_pin"
url = "{API}"
license = "GPL-3.0"
"""
    )
    from pipeline import privacy

    http.routes.update(routes())
    http.routes[privacy.DATENANFRAGEN_TARBALL.format(commit=DN)] = sample_tarball()
    http.routes[privacy.ERASER_YAML.format(commit=ER)] = ERASER_YAML
    monkeypatch.setattr(sources, "PINS_ATTESTOR", FakeAttestor)

    def run(out: str, *extra: str) -> int:
        args = parse_args(
            [
                "--out",
                str(tmp_path / out),
                "--sources",
                str(srcs),
                "--corpus-spec",
                str(corpus),
                "--corpus-cache",
                str(tmp_path / "cache"),
                "--allow-hashes",
                str(tmp_path / "none.txt"),
                "--now",
                str(NOW),
                *extra,
            ]
        )
        return build(args, http)

    assert run("day1") == 0
    out = tmp_path / "day1"
    stage = out / "stage"
    assert json.loads((stage / "privacy" / "brokers.json").read_text())["format"] == 1
    assert json.loads((stage / "components" / "pins.json").read_text())["pins"]["sing-box"]["version"] == "1.14.4"
    manifest = json.loads((out / "manifest.json").read_text())
    assert {"privacy/brokers.json", "components/pins.json"} <= set(manifest["files"])
    src = {s["name"]: s for s in manifest["sources"]}
    assert src["data-brokers"]["count"] == 7 and src["sing-box"]["fresh"] is True
    report = json.loads((out / "report.json").read_text())
    assert report["privacy_brokers"] == 7 and report["component_pins"] == {"sing-box": "1.14.4"}
    sr = (out / SHADOWROCKET_FILE).read_text()
    assert sr.startswith("# Parabellum threat DB 2026.10.25.1")
    assert (
        "DOMAIN-SET,https://github.com/WLDEUS/Parabellum/releases/download/db-latest/shadowrocket-reject.list,REJECT"
        in sr
    )
    assert [ln for ln in sr.splitlines() if not ln.startswith("#")] == [".ads.example.com", ".evil.example.net"]

    # Day 2: both upstreams down -> previous files carried over, fresh=false.
    for u in list(http.routes):
        if "sing-box" in u or "datenanfragen" in u or "eraser" in u:
            del http.routes[u]
    assert (
        run("day2", "--previous", str(out / "parabellum-db.tar.gz"), "--state", str(out / "pipeline-state.tar.gz")) == 0
    )
    stage2 = tmp_path / "day2" / "stage"
    assert (stage2 / "privacy" / "brokers.json").read_bytes() == (stage / "privacy" / "brokers.json").read_bytes()
    assert (stage2 / "components" / "pins.json").read_bytes() == (stage / "components" / "pins.json").read_bytes()
    src2 = {s["name"]: s for s in json.loads((tmp_path / "day2" / "manifest.json").read_text())["sources"]}
    assert src2["data-brokers"]["fresh"] is False and src2["data-brokers"]["count"] == 7
    assert src2["sing-box"]["fresh"] is False

    # Offline: network-only sources skipped entirely.
    assert run("offline", "--offline") == 0
    assert not (tmp_path / "offline" / "stage" / "privacy").exists()
