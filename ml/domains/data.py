"""Training data for the domain model: positives from the threat-DB pipeline state, negatives from Tranco.

* Positives: ``domains/<source>.txt`` of the signed ``pipeline-state.tar.gz`` (URLhaus, ThreatFox,
  phishing-filter, HaGeZi TIF — already normalised by ``pipeline/``). Kept cumulatively in
  ``domains.csv.gz`` (``domain,label,first_seen``) so a time-based holdout ("domains first seen in the last
  N days") measures generalisation to *new* campaigns.
* Negatives: Tranco top-1M (``https://tranco-list.eu/top-1m.csv.zip``, registrable domains) and its
  ``-incl-subdomains`` variant (FQDNs, so subdomain depth is not a label leak), minus anything listed as
  malicious. Recomputed each run, never stored. Tranco states no licence of its own; its inputs include
  Cloudflare Radar (CC BY-NC 4.0) and CrUX (CC BY-SA 4.0): fine for this personal project.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import io
import random
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_SUB_URL = "https://tranco-list.eu/top-1m-incl-subdomains.csv.zip"
POSITIVE_SOURCES = ("urlhaus", "threatfox", "phishing-filter", "hagezi-tif-medium")
DAY = 86_400
MAX_POSITIVES = 400_000


@dataclass(frozen=True)
class Row:
    domain: str
    label: int
    first_seen: int


def valid_domain(d: str) -> bool:
    if not d or len(d) > 253 or "." not in d or d != d.lower():
        return False
    return all(
        0 < len(label) <= 63 and all(c.isascii() and (c.isalnum() or c in "-_") for c in label)
        for label in d.split(".")
    )


def bucket(domain: str) -> int:
    """Stable 0..99 bucket of a name (independent of the label)."""
    return int(hashlib.sha256(domain.encode()).hexdigest()[:8], 16) % 100


def read_positive_sources(state_dir: Path, sources: Iterable[str] = POSITIVE_SOURCES) -> set[str]:
    out: set[str] = set()
    for name in sources:
        p = state_dir / "domains" / f"{name}.txt"
        if not p.is_file():
            continue
        for line in p.read_text(encoding="ascii", errors="ignore").split():
            d = line.strip().rstrip(".").lower()
            if valid_domain(d):
                out.add(d)
    return out


def load_dataset(path: Path | None) -> list[Row]:
    if path is None or not path.is_file():
        return []
    rows: list[Row] = []
    with gzip.open(path, "rt", encoding="utf-8", newline="") as f:
        for rec in csv.DictReader(f):
            try:
                d = rec["domain"].strip().lower()
                if valid_domain(d):
                    rows.append(Row(d, int(rec["label"]), int(rec["first_seen"])))
            except (KeyError, ValueError):
                continue
    return rows


def save_dataset(path: Path, rows: Iterable[Row]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with gzip.open(path, "wt", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["domain", "label", "first_seen"])
        for r in sorted(rows, key=lambda r: (r.first_seen, r.domain)):
            w.writerow([r.domain, r.label, r.first_seen])
            n += 1
    return n


def merge_positives(existing: list[Row], fresh: set[str], now: int) -> tuple[list[Row], int]:
    """Keep known positives with their first-seen day, add new ones dated today. Returns (rows, added)."""
    today = now - now % DAY
    known = {r.domain: r for r in existing if r.label == 1}
    added = 0
    for d in fresh:
        if d not in known:
            known[d] = Row(d, 1, today)
            added += 1
    rows = sorted(known.values(), key=lambda r: r.first_seen, reverse=True)[:MAX_POSITIVES]
    return rows, added


def parse_tranco(data: bytes) -> list[str]:
    """``rank,domain`` CSV inside a zip, in rank order."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        name = next((n for n in z.namelist() if n.endswith(".csv")), None)
        if name is None:
            raise ValueError("no CSV in the Tranco archive")
        text = z.read(name).decode("utf-8", errors="ignore")
    out = []
    for line in text.splitlines():
        parts = line.strip().split(",")
        if len(parts) >= 2:
            d = parts[1].strip().rstrip(".").lower()
            if valid_domain(d):
                out.append(d)
    return out


def registrable_guess(d: str) -> str:
    """Last two labels (good enough to exclude listed domains from the negatives)."""
    parts = d.split(".")
    return ".".join(parts[-2:])


def negatives(
    tranco: list[str], tranco_sub: list[str], positives: set[str], n_top: int, n_tail: int, n_sub: int, seed: int
) -> list[str]:
    """Top ``n_top`` + ``n_tail`` sampled from the rest + ``n_sub`` FQDNs, minus anything malicious
    (the name itself or its registrable domain listed; a listed customer subdomain of a shared platform
    does not exclude the platform)."""

    def ok(d: str) -> bool:
        return d not in positives and registrable_guess(d) not in positives

    rng = random.Random(seed)  # noqa: S311 (deterministic sampling, not security)
    head = [d for d in tranco[:n_top] if ok(d)]
    rest = tranco[n_top:]
    tail = [d for d in rng.sample(rest, min(n_tail, len(rest))) if ok(d)]
    subs = [d for d in rng.sample(tranco_sub, min(n_sub, len(tranco_sub))) if ok(d)]
    return sorted(set(head) | set(tail) | set(subs))


def popular_list(tranco: list[str], positives: set[str], n: int) -> list[str]:
    """Registrable domains the client never scores (most popular first), minus anything malicious."""
    out = []
    for d in tranco:
        if d in positives or registrable_guess(d) in positives:
            continue
        out.append(d)
        if len(out) >= n:
            break
    return out
