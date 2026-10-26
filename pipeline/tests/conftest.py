"""Shared fixtures: an in-memory fetcher (no network in tests) and helpers."""

from __future__ import annotations

import hashlib
import io
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest

from pipeline.http import FetchError


class FakeHttp:
    """URL -> bytes map; unknown URLs raise FetchError (like a failed fetch)."""

    def __init__(self, routes: Mapping[str, bytes] | None = None) -> None:
        self.routes: dict[str, bytes] = dict(routes or {})
        self.calls: list[str] = []

    def _get(self, url: str) -> bytes:
        self.calls.append(url)
        if url not in self.routes:
            raise FetchError(f"GET {url}: 404")
        return self.routes[url]

    def get_bytes(self, url, headers=None, max_bytes=0):
        return self._get(url)

    def post_form(self, url, form, headers=None, max_bytes=0):
        return self._get(f"{url}?{'&'.join(f'{k}={v}' for k, v in sorted(form.items()))}")

    def post_json(self, url, payload, headers=None, max_bytes=0):
        return self._get(url)

    def download(self, url, dest: Path, headers=None, max_bytes=0, sha256=None):
        data = self._get(url)
        digest = hashlib.sha256(data).hexdigest()
        if sha256 and digest != sha256:
            raise FetchError("sha256 mismatch")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return digest


def zip_bytes(files: Mapping[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


#: 64-bit little-endian Mach-O header prefix (enough for the magic checks of our rules).
MACHO = b"\xcf\xfa\xed\xfe" + b"\x0c\x00\x00\x01" + b"\x00" * 24


@pytest.fixture
def fake_http() -> FakeHttp:
    return FakeHttp()
