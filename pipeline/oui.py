"""MAC vendor prefixes for the LAN inventory: ``lan/oui.tsv`` (``pb_core::db::LAN_OUI``).

Source: the IEEE Registration Authority public listings (MA-L 24-bit, MA-M 28-bit, MA-S 36-bit assignments),
CSV columns ``Registry,Assignment,Organization Name,Organization Address``. Output: one
``<6, 7 or 9 uppercase hex digits>\\t<organization>`` line per assignment, sorted, organization names cleaned
(control characters removed, whitespace collapsed, at most 80 characters). The daemon streams the file for the
MAC addresses of a scan (longest prefix wins). Fewer than ``MIN_ENTRIES`` MA-L entries is treated as a failure:
the previous bundle's file is kept.
"""

from __future__ import annotations

import csv
import io
import logging
import re
from pathlib import Path

from .http import FetchError

log = logging.getLogger(__name__)

BUNDLE_PATH = "lan/oui.tsv"
REGISTRIES = {
    "MA-L": "https://standards-oui.ieee.org/oui/oui.csv",
    "MA-M": "https://standards-oui.ieee.org/oui28/mam.csv",
    "MA-S": "https://standards-oui.ieee.org/oui36/oui36.csv",
}
#: Expected assignment length (hex digits) per registry.
PREFIX_LEN = {"MA-L": 6, "MA-M": 7, "MA-S": 9}
MIN_ENTRIES = 20_000
MAX_CSV = 32 * 1024 * 1024
_HEX = re.compile(r"^[0-9A-F]+$")
_WS = re.compile(r"\s+")


def clean_name(s: str) -> str:
    s = "".join(c if ord(c) >= 32 and ord(c) != 127 else " " for c in s)
    return _WS.sub(" ", s).strip()[:80]


def parse_csv(data: bytes, registry: str) -> dict[str, str]:
    """``{prefix: organization}`` of one IEEE CSV (malformed rows skipped)."""
    want = PREFIX_LEN[registry]
    out: dict[str, str] = {}
    text = data.decode("utf-8", errors="replace").lstrip("﻿")
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3 or row[0].strip() != registry:
            continue
        prefix = row[1].strip().upper()
        name = clean_name(row[2])
        if len(prefix) != want or not _HEX.match(prefix) or not name:
            continue
        out[prefix] = name
    return out


def render(entries: dict[str, str]) -> bytes:
    return "".join(f"{p}\t{n}\n" for p, n in sorted(entries.items())).encode("utf-8")


def fetch(
    http: object, registries: tuple[str, ...] = ("MA-L", "MA-M", "MA-S"), min_entries: int = MIN_ENTRIES
) -> tuple[bytes, int]:
    """Download and merge the registries. MA-L is required; the smaller ones are best effort."""
    merged: dict[str, str] = {}
    for reg in registries:
        if reg not in REGISTRIES:
            raise FetchError(f"unknown IEEE registry {reg}")
        try:
            data = http.get_bytes(REGISTRIES[reg], max_bytes=MAX_CSV)  # type: ignore[attr-defined]
        except FetchError:
            if reg == "MA-L":
                raise
            log.warning("IEEE %s listing unavailable, skipped", reg)
            continue
        got = parse_csv(data, reg)
        if reg == "MA-L" and len(got) < min_entries:
            raise FetchError(f"IEEE MA-L listing too small ({len(got)} entries)")
        merged.update(got)
    return render(merged), len(merged)


def carry_over(prev_dir: Path) -> dict[str, bytes]:
    p = prev_dir / BUNDLE_PATH
    return {BUNDLE_PATH: p.read_bytes()} if p.is_file() and not p.is_symlink() else {}


def count(data: bytes) -> int:
    return data.count(b"\n")
