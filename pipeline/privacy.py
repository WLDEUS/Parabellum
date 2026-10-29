"""Data-broker list for GDPR erasure requests: ``privacy/brokers.json`` (``pb_core::db::BrokersFile``).

Sources, both fetched at **pinned commits** (``sources.toml``):

* Datenanfragen.de company database (CC0 1.0): ``companies/*.json`` from the commit tarball
  (``codeload.github.com``). Kept: categories ``ads`` / ``addresses`` / ``credit agency`` (mapped to
  ``ads`` / ``addresses`` / ``credit``), ``relevant-countries`` containing ``all`` or ``fr``, with a valid
  email; region ``eu``.
* Eraser (MIT, github.com/digisamroc/eraser): ``data/brokers.yaml``; regions ``us`` / ``global`` as given.

Entries are validated (email syntax as in ``pb_core::config::is_email``, HTTPS URLs only), deduplicated by
lowercased email then by name (Datenanfragen first), and get stable slug ids (prefixed by the source on a
collision). Fewer than ``MIN_BROKERS`` entries is treated as a failure: the previous bundle's file is kept.

Supply chain: the daemon emails the user's identity to every address of this list. A poisoned upstream could
add an attacker's address, so upstream data only changes when a reviewed commit bumps the pins.
"""

from __future__ import annotations

import io
import json
import logging
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path

import yaml

from .http import FetchError

log = logging.getLogger(__name__)

BUNDLE_PATH = "privacy/brokers.json"
DATENANFRAGEN_TARBALL = "https://codeload.github.com/datenanfragen/data/tar.gz/{commit}"
ERASER_YAML = "https://raw.githubusercontent.com/digisamroc/eraser/{commit}/data/brokers.yaml"
MIN_BROKERS = 50
MAX_TARBALL = 64 * 1024 * 1024
MAX_YAML = 8 * 1024 * 1024
MAX_COMPANY_JSON = 1024 * 1024
#: Datenanfragen category -> bundle category, in priority order.
CATEGORY_MAP = (("addresses", "addresses"), ("credit agency", "credit"), ("ads", "ads"))
ERASER_REGIONS = ("us", "global")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_SLUG_BAD = re.compile(r"[^a-z0-9._:-]+")


def is_host(s: str) -> bool:
    """Same rule as ``pb_core::config::is_host_or_ip`` for host names."""
    return 0 < len(s) <= 253 and all(_LABEL.match(label) for label in s.split("."))


def is_email(s: str) -> bool:
    """Same rule as ``pb_core::config::is_email``."""
    if "@" not in s or len(s) > 254:
        return False
    local, domain = s.rsplit("@", 1)
    if not local or len(local) > 64 or "." not in domain or not is_host(domain):
        return False
    return not any(c.isspace() or ord(c) < 32 or ord(c) == 127 or c in '<>,;"' for c in s)


def https_url(s: object) -> str | None:
    if not isinstance(s, str):
        return None
    u = s.strip()
    if not u.startswith("https://") or len(u) > 2048 or any(c.isspace() or ord(c) < 32 for c in u):
        return None
    return u


def slugify(s: str) -> str:
    return _SLUG_BAD.sub("-", s.strip().lower()).strip("-")[:128]


@dataclass
class Broker:
    id: str
    name: str
    email: str | None
    website: str | None
    opt_out_url: str | None
    region: str
    category: str
    source: str

    def to_json(self) -> dict[str, str]:
        d = {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "website": self.website,
            "opt_out_url": self.opt_out_url,
            "region": self.region,
            "category": self.category,
            "source": self.source,
        }
        return {k: v for k, v in d.items() if v is not None}


def _clean_name(s: object) -> str:
    if not isinstance(s, str):
        return ""
    return "".join(c for c in s.strip() if ord(c) >= 32)[:256]


def parse_datenanfragen(tar_bytes: bytes, countries: tuple[str, ...] = ("all", "fr")) -> list[Broker]:
    """Companies of the commit tarball (``<top>/companies/*.json``) relevant for ``countries``."""
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
            return _companies(tf, countries)
    except (tarfile.TarError, OSError, EOFError) as e:
        raise FetchError(f"datenanfragen tarball unreadable: {e}") from e


def _companies(tf: tarfile.TarFile, countries: tuple[str, ...]) -> list[Broker]:
    out: list[Broker] = []
    total = 0
    for m in tf:
        parts = m.name.split("/")
        if not m.isreg() or len(parts) != 3 or parts[1] != "companies" or not parts[2].endswith(".json"):
            continue
        if ".." in parts or m.size > MAX_COMPANY_JSON:
            continue
        total += m.size
        if total > 4 * MAX_TARBALL:
            raise FetchError("datenanfragen tarball: companies exceed the size limit")
        f = tf.extractfile(m)
        if f is None:
            continue
        try:
            doc = json.loads(f.read())
        except ValueError:
            log.info("datenanfragen: %s is not JSON", m.name)
            continue
        if not isinstance(doc, dict):
            continue
        cats = [str(c) for c in doc.get("categories", []) if isinstance(c, str)]
        category = next((dest for src, dest in CATEGORY_MAP if src in cats), None)
        rel = [str(c).lower() for c in doc.get("relevant-countries", []) if isinstance(c, str)]
        email = doc.get("email")
        if category is None or not any(c in rel for c in countries):
            continue
        if not isinstance(email, str) or not is_email(email.strip()):
            continue
        slug = slugify(str(doc.get("slug", "")))
        name = _clean_name(doc.get("name"))
        if not slug or not name:
            continue
        out.append(
            Broker(
                id=slug,
                name=name,
                email=email.strip(),
                website=https_url(doc.get("web")),
                opt_out_url=https_url(doc.get("webform")),
                region="eu",
                category=category,
                source="datenanfragen",
            )
        )
    return out


def parse_eraser(yaml_bytes: bytes) -> list[Broker]:
    """``data/brokers.yaml``: ``brokers: [{id, name, email, website, opt_out_url, region, category}]``."""
    try:
        doc = yaml.safe_load(yaml_bytes.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        raise FetchError(f"eraser brokers.yaml unreadable: {e}") from e
    items = doc.get("brokers") if isinstance(doc, dict) else None
    if not isinstance(items, list):
        raise FetchError("eraser brokers.yaml: no `brokers` list")
    out: list[Broker] = []
    for b in items:
        if not isinstance(b, dict):
            continue
        region = str(b.get("region", "")).strip().lower()
        if region not in ERASER_REGIONS:
            continue
        email = b.get("email")
        email = email.strip() if isinstance(email, str) and is_email(email.strip()) else None
        opt_out = https_url(b.get("opt_out_url"))
        slug = slugify(str(b.get("id", "")))
        name = _clean_name(b.get("name"))
        if not slug or not name or (email is None and opt_out is None):
            continue
        out.append(
            Broker(
                id=slug,
                name=name,
                email=email,
                website=https_url(b.get("website")),
                opt_out_url=opt_out,
                region=region,
                category=slugify(str(b.get("category", ""))) or "other",
                source="eraser",
            )
        )
    return out


def merge(*lists: list[Broker]) -> list[Broker]:
    """Deduplicate (lowercased email, then name; earlier lists win), make ids unique, sort by id."""
    emails: set[str] = set()
    names: set[str] = set()
    ids: set[str] = set()
    out: list[Broker] = []
    for lst in lists:
        for b in lst:
            key_email = b.email.lower() if b.email else None
            key_name = b.name.casefold()
            if (key_email and key_email in emails) or key_name in names:
                continue
            bid = b.id
            if bid in ids:
                bid = f"{b.source}-{b.id}"[:128]
                n = 2
                while bid in ids:
                    bid = f"{b.source}-{b.id}-{n}"[:128]
                    n += 1
            b.id = bid
            ids.add(bid)
            names.add(key_name)
            if key_email:
                emails.add(key_email)
            out.append(b)
    return sorted(out, key=lambda b: b.id)


def render(brokers: list[Broker], sources: dict[str, str]) -> bytes:
    doc = {"format": 1, "sources": dict(sorted(sources.items())), "brokers": [b.to_json() for b in brokers]}
    return (json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def fetch(
    http: object,
    datenanfragen_commit: str,
    eraser_commit: str,
    countries: tuple[str, ...] = ("all", "fr"),
    min_brokers: int = MIN_BROKERS,
) -> tuple[bytes, int]:
    """Build the file from both pinned upstreams. Raises FetchError on any doubt."""
    for name, c in (("datenanfragen_commit", datenanfragen_commit), ("eraser_commit", eraser_commit)):
        if not _COMMIT.match(c):
            raise FetchError(f"{name} must be a full 40-hex commit id, got {c!r}")
    get = http.get_bytes  # type: ignore[attr-defined]
    tar = get(DATENANFRAGEN_TARBALL.format(commit=datenanfragen_commit), max_bytes=MAX_TARBALL)
    yml = get(ERASER_YAML.format(commit=eraser_commit), max_bytes=MAX_YAML)
    dn = parse_datenanfragen(tar, countries)
    er = parse_eraser(yml)
    brokers = merge(dn, er)
    log.info("brokers: %d from datenanfragen, %d from eraser, %d after merge", len(dn), len(er), len(brokers))
    if len(brokers) < min_brokers:
        raise FetchError(f"only {len(brokers)} brokers (< {min_brokers}): keeping the previous list")
    data = render(brokers, {"datenanfragen": datenanfragen_commit, "eraser": eraser_commit})
    return data, len(brokers)


def carry_over(prev_dir: Path) -> dict[str, bytes]:
    p = prev_dir / BUNDLE_PATH
    return {BUNDLE_PATH: p.read_bytes()} if p.is_file() and not p.is_symlink() else {}


def count(data: bytes) -> int:
    try:
        return len(json.loads(data).get("brokers", []))
    except (ValueError, AttributeError):
        return 0
