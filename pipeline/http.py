"""Minimal HTTP client (stdlib only): retries with backoff, response-size caps, secret redaction.

Secrets (the abuse.ch Auth-Key travels in the URL *path* of the v2 exports) are registered on the
client and scrubbed from every exception message, so a failing fetch never leaks them into CI logs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Protocol

log = logging.getLogger(__name__)

USER_AGENT = "parabellum-pipeline/1 (+https://github.com/WLDEUS/Parabellum)"
#: Default cap for in-memory responses.
DEFAULT_MAX_BYTES = 256 * 1024 * 1024
#: Default cap for streamed downloads.
DEFAULT_MAX_DOWNLOAD = 2 * 1024 * 1024 * 1024
_CHUNK = 1024 * 1024


class FetchError(Exception):
    """A network fetch failed (after retries) or returned an unusable response."""


class Fetcher(Protocol):
    """What the source fetchers need; tests provide an in-memory fake."""

    def get_bytes(
        self, url: str, headers: Mapping[str, str] | None = None, max_bytes: int = DEFAULT_MAX_BYTES
    ) -> bytes: ...

    def post_form(
        self,
        url: str,
        form: Mapping[str, str],
        headers: Mapping[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> bytes: ...

    def post_json(
        self,
        url: str,
        payload: object,
        headers: Mapping[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> bytes: ...

    def download(
        self,
        url: str,
        dest: Path,
        headers: Mapping[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_DOWNLOAD,
        sha256: str | None = None,
    ) -> str: ...


def redact(text: str, secrets: Iterable[str]) -> str:
    """Replace every non-empty secret in ``text`` with ``***``."""
    for s in secrets:
        if s:
            text = text.replace(s, "***")
            quoted = urllib.parse.quote(s, safe="")
            if quoted != s:
                text = text.replace(quoted, "***")
    return text


class _StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Drop ``Authorization`` when a redirect leaves the original host.

    ghcr.io answers blob requests with a redirect to a pre-signed storage URL that rejects (or must
    not receive) the registry bearer token; curl behaves the same way by default.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            old_host = urllib.parse.urlsplit(req.full_url).hostname
            new_host = urllib.parse.urlsplit(newurl).hostname
            if old_host != new_host:
                new.remove_header("Authorization")
                new.remove_header("Auth-key")
        return new


class Http:
    """Real network client used in CI."""

    def __init__(
        self,
        secrets: Iterable[str] = (),
        retries: int = 3,
        timeout: float = 120.0,
        backoff: float = 5.0,
    ) -> None:
        self.secrets = [s for s in secrets if s]
        self.retries = max(1, retries)
        self.timeout = timeout
        self.backoff = backoff
        self._opener = urllib.request.build_opener(_StripAuthOnRedirect())

    def _request(
        self,
        url: str,
        data: bytes | None,
        headers: Mapping[str, str] | None,
        content_type: str | None = None,
    ) -> urllib.request.Request:
        if not url.startswith("https://"):
            raise FetchError(f"refusing non-HTTPS URL: {self._safe(url)}")
        h = {"User-Agent": USER_AGENT, "Accept-Encoding": "identity"}
        if content_type:
            h["Content-Type"] = content_type
        h.update(headers or {})
        return urllib.request.Request(url, data=data, headers=h, method="POST" if data is not None else "GET")

    def _safe(self, text: str) -> str:
        return redact(text, self.secrets)

    def _with_retries(self, what: str, fn):  # type: ignore[no-untyped-def]
        last: Exception | None = None
        for attempt in range(1, self.retries + 1):
            try:
                return fn()
            except urllib.error.HTTPError as e:
                last = e
                # 4xx (except 408/429) will not get better by retrying.
                if 400 <= e.code < 500 and e.code not in (408, 429):
                    break
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last = e
            if attempt < self.retries:
                time.sleep(self.backoff * attempt)
        raise FetchError(self._safe(f"{what}: {last}")) from None

    def _read_capped(self, resp, max_bytes: int, what: str) -> bytes:  # type: ignore[no-untyped-def]
        buf = bytearray()
        while True:
            chunk = resp.read(_CHUNK)
            if not chunk:
                return bytes(buf)
            buf += chunk
            if len(buf) > max_bytes:
                raise FetchError(self._safe(f"{what}: response larger than {max_bytes} bytes"))

    def _fetch(self, req: urllib.request.Request, max_bytes: int) -> bytes:
        what = f"{req.get_method()} {req.full_url}"

        def run() -> bytes:
            with self._opener.open(req, timeout=self.timeout) as resp:
                return self._read_capped(resp, max_bytes, what)

        return self._with_retries(self._safe(what), run)

    def get_bytes(
        self, url: str, headers: Mapping[str, str] | None = None, max_bytes: int = DEFAULT_MAX_BYTES
    ) -> bytes:
        return self._fetch(self._request(url, None, headers), max_bytes)

    def post_form(
        self,
        url: str,
        form: Mapping[str, str],
        headers: Mapping[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> bytes:
        body = urllib.parse.urlencode(form).encode()
        req = self._request(url, body, headers, "application/x-www-form-urlencoded")
        return self._fetch(req, max_bytes)

    def post_json(
        self,
        url: str,
        payload: object,
        headers: Mapping[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> bytes:
        req = self._request(url, json.dumps(payload).encode(), headers, "application/json")
        return self._fetch(req, max_bytes)

    def download(
        self,
        url: str,
        dest: Path,
        headers: Mapping[str, str] | None = None,
        max_bytes: int = DEFAULT_MAX_DOWNLOAD,
        sha256: str | None = None,
    ) -> str:
        """Stream ``url`` to ``dest`` (atomically) and return its SHA-256; verify it when given."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_name(dest.name + ".part")
        what = self._safe(f"GET {url}")

        def run() -> str:
            h = hashlib.sha256()
            size = 0
            with (
                self._opener.open(self._request(url, None, headers), timeout=self.timeout) as resp,
                tmp.open("wb") as f,
            ):
                while True:
                    chunk = resp.read(_CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > max_bytes:
                        raise FetchError(f"{what}: larger than {max_bytes} bytes")
                    h.update(chunk)
                    f.write(chunk)
            return h.hexdigest()

        try:
            digest = self._with_retries(what, run)
            if sha256 and digest != sha256.lower():
                raise FetchError(f"{what}: sha256 mismatch (got {digest}, expected {sha256})")
            tmp.replace(dest)
            return digest
        finally:
            tmp.unlink(missing_ok=True)
