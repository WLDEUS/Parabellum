"""abuse.ch clients: MalwareBazaar, URLhaus, ThreatFox.

Authentication (verified 2026-10): every abuse.ch request needs a free Auth-Key
(https://auth.abuse.ch/). The keyless download URLs (``bazaar.abuse.ch/export/...``,
``urlhaus.abuse.ch/downloads/...``, ``threatfox.abuse.ch/export/...``) answer ``410 Gone`` since
2026-10-21; bulk exports moved to ``https://<service>-api.abuse.ch/v2/files/exports/<AUTH-KEY>/<file>``
(key in the URL *path*), while the query APIs keep the ``Auth-Key`` HTTP header.
The key is therefore registered as a secret on the HTTP client and redacted from every error.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .domains import host_from_url, normalize_domain
from .hashes import MalwareEntry, parse_mb_api, parse_mb_csv
from .http import Fetcher, FetchError

MB_API = "https://mb-api.abuse.ch/api/v1/"
#: MalwareBazaar zips every sample with AES and this password (documented on bazaar.abuse.ch/api).
SAMPLE_PASSWORD = b"infected"
#: Hard caps for untrusted archives coming from abuse.ch.
MAX_EXPORT_BYTES = 1024 * 1024 * 1024
MAX_SAMPLE_ZIP = 64 * 1024 * 1024
MAX_SAMPLE_BYTES = 200 * 1024 * 1024


def auth_headers(key: str) -> dict[str, str]:
    return {"Auth-Key": key}


def fill_key(template: str, key: str) -> str:
    """Substitute ``{ABUSECH_AUTH_KEY}`` in an export URL template."""
    if "{ABUSECH_AUTH_KEY}" in template and not key:
        raise FetchError("ABUSECH_AUTH_KEY is not set")
    return template.replace("{ABUSECH_AUTH_KEY}", key)


def maybe_unzip(data: bytes, max_bytes: int = MAX_EXPORT_BYTES) -> str:
    """Exports may be plain CSV or a zip holding one CSV; return the text."""
    if data[:2] != b"PK":
        return data.decode("utf-8", errors="replace")
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        members = [i for i in zf.infolist() if not i.is_dir()]
        if not members:
            raise FetchError("empty zip export")
        info = max(members, key=lambda i: i.file_size)
        if info.file_size > max_bytes:
            raise FetchError(f"export member too large ({info.file_size} bytes)")
        with zf.open(info) as f:
            raw = f.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise FetchError("export member too large")
        return raw.decode("utf-8", errors="replace")


def _csv_rows(text: str, default_columns: tuple[str, ...]) -> Iterable[dict[str, str]]:
    """abuse.ch CSVs: ``#`` comment lines, the last commented line carrying the header."""
    columns = default_columns
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("#"):
            body = line.lstrip("#").strip()
            if body and ("," in body) and any(k in body for k in ("url", "ioc", "sha256_hash", "dateadded")):
                columns = tuple(c.strip().strip('"') for c in next(csv.reader([body], skipinitialspace=True)))
            continue
        if line.strip():
            lines.append(line)
    for row in csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=True):
        yield dict(zip(columns, (c.strip() for c in row), strict=False))


URLHAUS_COLUMNS = ("id", "dateadded", "url", "url_status", "last_online", "threat", "tags", "urlhaus_link", "reporter")
THREATFOX_COLUMNS = (
    "first_seen_utc",
    "ioc_id",
    "ioc_value",
    "ioc_type",
    "threat_type",
    "fk_malware",
    "malware_alias",
    "malware_printable",
    "last_seen_utc",
    "confidence_level",
    "reference",
    "tags",
    "anonymous",
    "reporter",
)


def parse_urlhaus_csv(text: str) -> set[str]:
    """Domains of URLhaus URLs (IP-based URLs dropped)."""
    out: set[str] = set()
    for rec in _csv_rows(text, URLHAUS_COLUMNS):
        host = host_from_url(rec.get("url", ""))
        if host:
            out.add(host)
    return out


def parse_threatfox_csv(text: str, min_confidence: int = 50) -> set[str]:
    """Domains from ThreatFox IOCs of type ``domain`` and ``url`` with enough confidence."""
    out: set[str] = set()
    for rec in _csv_rows(text, THREATFOX_COLUMNS):
        try:
            conf = int(rec.get("confidence_level", "100") or "100")
        except ValueError:
            conf = 0
        if conf < min_confidence:
            continue
        kind = rec.get("ioc_type", "").strip().lower()
        value = rec.get("ioc_value", "")
        host: str | None = None
        if kind == "domain":
            host = normalize_domain(value)
        elif kind == "url":
            host = host_from_url(value)
        if host:
            out.add(host)
    return out


@dataclass
class MalwareBazaar:
    """MalwareBazaar query API (``Auth-Key`` header)."""

    http: Fetcher
    key: str
    api: str = MB_API

    def query(self, form: Mapping[str, str]) -> bytes:
        if not self.key:
            raise FetchError("ABUSECH_AUTH_KEY is not set")
        return self.http.post_form(self.api, form, headers=auth_headers(self.key), max_bytes=64 * 1024 * 1024)

    def macos_entries(
        self,
        file_types: Iterable[str],
        tags: Iterable[str],
        families: Mapping[str, str],
        limit: int = 1000,
    ) -> tuple[list[MalwareEntry], list[str]]:
        """Recent macOS samples by file type and tag. Returns (entries, per-query errors)."""
        entries: dict[str, MalwareEntry] = {}
        errors: list[str] = []
        queries = [{"query": "get_file_type", "file_type": ft, "limit": str(limit)} for ft in file_types]
        queries += [{"query": "get_taginfo", "tag": t, "limit": str(limit)} for t in tags]
        for form in queries:
            label = f"{form['query']}={form.get('file_type') or form.get('tag')}"
            try:
                for e in parse_mb_api(self.query(form), families, force_macos=True):
                    old = entries.get(e.sha256)
                    if old is None or (not old.name and e.name):
                        entries[e.sha256] = e
            except (FetchError, ValueError, json.JSONDecodeError) as exc:
                errors.append(f"{label}: {exc}")
        return list(entries.values()), errors

    def download_sample(self, sha256: str) -> bytes:
        """The password-protected zip of one sample (never executed, never stored by the pipeline)."""
        data = self.http.post_form(
            self.api,
            {"query": "get_file", "sha256_hash": sha256},
            headers=auth_headers(self.key),
            max_bytes=MAX_SAMPLE_ZIP,
        )
        if data[:2] != b"PK":
            raise FetchError(f"get_file {sha256}: {data[:120]!r}")
        return data


def extract_sample(zip_bytes: bytes, max_bytes: int = MAX_SAMPLE_BYTES) -> list[tuple[str, bytes]]:
    """Decrypt a MalwareBazaar sample zip **in memory**. Returns ``[(member name, content)]``."""
    import pyzipper  # imported lazily: only the detection / ML steps need it

    out: list[tuple[str, bytes]] = []
    with pyzipper.AESZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.setpassword(SAMPLE_PASSWORD)
        total = 0
        for info in zf.infolist()[:16]:
            if info.is_dir():
                continue
            if info.file_size > max_bytes or total + info.file_size > max_bytes:
                continue
            with zf.open(info) as f:
                data = f.read(max_bytes + 1)
            if len(data) > max_bytes:
                continue
            total += len(data)
            out.append((info.filename, data))
    return out


def parse_mb_export(data: bytes) -> list[MalwareEntry]:
    return parse_mb_csv(maybe_unzip(data))
