"""Source registry: ``pipeline/sources.toml`` -> fetchers -> normalised payloads, with carry-over.

Each source is fetched independently. When a fetch fails, its data is carried over:
* domain sources from the pipeline state (``state/domains/<source>.txt``), or — first runs, no
  state — from the previous bundle's category file;
* YARA sources from the previous bundle (``yara/<source>__*.yar``);
* hash sources need no carry-over: the rolling index lives in the state;
* the ML model from the previous bundle's ``ml/``.
The source is then reported with ``fresh: false`` and its last successful ``fetched_at``.
"""

from __future__ import annotations

import json
import logging
import os
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .abusech import (
    MB_API,
    MalwareBazaar,
    fill_key,
    maybe_unzip,
    parse_mb_export,
    parse_threatfox_csv,
    parse_urlhaus_csv,
)
from .bundle import SourceInfo
from .domains import parse_list
from .hashes import MalwareEntry
from .http import Fetcher, FetchError, redact
from .yara_rules import RuleFile, bundle_name, iter_tarball_members, load_local_rules

log = logging.getLogger(__name__)

DOMAIN_CATEGORIES = ("malware", "ads", "trackers")
KEY_ENV = "ABUSECH_AUTH_KEY"


@dataclass
class SourceSpec:
    name: str
    kind: str
    fetcher: str
    url: str
    license: str
    options: dict[str, object] = field(default_factory=dict)

    def opt(self, key: str, default: object = None) -> object:
        return self.options.get(key, default)

    @property
    def display_url(self) -> str:
        """URL as published in the manifest (never contains the Auth-Key)."""
        return self.url.replace("{ABUSECH_AUTH_KEY}", "<AUTH-KEY>")


@dataclass
class Settings:
    min_client_version: str = "0.1.0"
    sanity_max_drop: float = 0.5
    hash_window_days: int = 365
    max_malware_hashes: int = 2_000_000
    max_macos_named: int = 200_000
    bootstrap_below: int = 1000
    mb_file_types: list[str] = field(default_factory=list)
    mb_tags: list[str] = field(default_factory=list)
    mb_limit: int = 1000
    families: dict[str, str] = field(default_factory=dict)
    detection_days: int = 2
    detection_max_samples: int = 40
    sources: list[SourceSpec] = field(default_factory=list)


def load_settings(path: Path) -> Settings:
    doc = tomllib.loads(path.read_text(encoding="utf-8"))
    b, h, m, d = doc.get("bundle", {}), doc.get("hashes", {}), doc.get("malwarebazaar", {}), doc.get("detection", {})
    st = Settings(
        min_client_version=str(b.get("min_client_version", "0.1.0")),
        sanity_max_drop=float(b.get("sanity_max_drop", 0.5)),
        hash_window_days=int(h.get("window_days", 365)),
        max_malware_hashes=int(h.get("max_hashes", 2_000_000)),
        max_macos_named=int(h.get("max_macos_named", 200_000)),
        bootstrap_below=int(h.get("bootstrap_below", 1000)),
        mb_file_types=[str(x) for x in m.get("file_types", [])],
        mb_tags=[str(x) for x in m.get("tags", [])],
        mb_limit=int(m.get("limit", 1000)),
        families={str(k).lower(): str(v) for k, v in doc.get("families", {}).items()},
        detection_days=int(d.get("days", 2)),
        detection_max_samples=int(d.get("max_samples", 40)),
    )
    names: set[str] = set()
    for s in doc.get("source", []):
        known = {"name", "kind", "fetcher", "url", "license"}
        spec = SourceSpec(
            name=str(s["name"]),
            kind=str(s["kind"]),
            fetcher=str(s["fetcher"]),
            url=str(s.get("url", "")),
            license=str(s.get("license", "")),
            options={k: v for k, v in s.items() if k not in known},
        )
        if spec.name in names:
            raise ValueError(f"duplicate source name {spec.name}")
        names.add(spec.name)
        st.sources.append(spec)
    return st


@dataclass
class Context:
    http: Fetcher
    repo_root: Path
    settings: Settings
    now: int
    key: str = ""
    ml_dir: Path | None = None
    #: Set by the builder: number of hashes currently in the rolling index (for bootstrap decisions).
    index_size: int = 0


@dataclass
class Fetched:
    """Normalised payload of one source."""

    domains: dict[str, set[str]] = field(default_factory=dict)
    malware: list[MalwareEntry] = field(default_factory=list)
    yara: list[RuleFile] = field(default_factory=list)
    files: dict[str, bytes] = field(default_factory=dict)  # bundle path -> content (local data, ML)
    count: int = 0
    skipped: bool = False  # deliberately not fetched this run (e.g. bootstrap-only source)


class SkipSource(Exception):
    """The source is not applicable this run (missing optional secret, bootstrap done…)."""


# --- fetchers ----------------------------------------------------------------------------------


def _key(ctx: Context) -> str:
    if not ctx.key:
        raise FetchError(f"{KEY_ENV} is not set")
    return ctx.key


def f_mb_export(spec: SourceSpec, ctx: Context) -> Fetched:
    if spec.opt("bootstrap_only", False) and ctx.index_size >= ctx.settings.bootstrap_below:
        raise SkipSource("index already bootstrapped")
    data = ctx.http.get_bytes(fill_key(spec.url, _key(ctx)), max_bytes=2 * 1024 * 1024 * 1024)
    entries = parse_mb_export(data)
    if not entries:
        raise FetchError("export contained no SHA-256")
    return Fetched(malware=entries, count=len(entries))


def f_mb_api_macos(spec: SourceSpec, ctx: Context) -> Fetched:
    mb = MalwareBazaar(ctx.http, _key(ctx), api=spec.url or MB_API)
    s = ctx.settings
    entries, errors = mb.macos_entries(s.mb_file_types, s.mb_tags, s.families, s.mb_limit)
    for e in errors:
        log.info("MalwareBazaar: %s", e)
    if not entries and errors:
        raise FetchError("; ".join(errors[:3]))
    return Fetched(malware=entries, count=len(entries))


def f_urlhaus_export(spec: SourceSpec, ctx: Context) -> Fetched:
    text = maybe_unzip(ctx.http.get_bytes(fill_key(spec.url, _key(ctx))))
    doms = parse_urlhaus_csv(text)
    if not doms:
        raise FetchError("no domain parsed")
    return Fetched(domains={str(spec.opt("category", "malware")): doms}, count=len(doms))


def f_threatfox_export(spec: SourceSpec, ctx: Context) -> Fetched:
    text = maybe_unzip(ctx.http.get_bytes(fill_key(spec.url, _key(ctx))))
    doms = parse_threatfox_csv(text, int(spec.opt("min_confidence", 50)))  # type: ignore[call-overload]
    if not doms:
        raise FetchError("no domain parsed")
    return Fetched(domains={str(spec.opt("category", "malware")): doms}, count=len(doms))


def f_domain_list(spec: SourceSpec, ctx: Context) -> Fetched:
    data = ctx.http.get_bytes(spec.url, max_bytes=256 * 1024 * 1024)
    doms = parse_list(data.decode("utf-8", errors="replace"), str(spec.opt("format", "auto")))
    min_entries = int(spec.opt("min_entries", 10))  # type: ignore[call-overload]
    if len(doms) < min_entries:
        raise FetchError(f"only {len(doms)} domains parsed (< {min_entries})")
    category = str(spec.opt("category", "ads"))
    if category not in DOMAIN_CATEGORIES:
        raise ValueError(f"unknown category {category}")
    return Fetched(domains={category: doms}, count=len(doms))


def f_yara_tarball(spec: SourceSpec, ctx: Context) -> Fetched:
    data = ctx.http.get_bytes(spec.url, max_bytes=512 * 1024 * 1024)
    include = [str(x) for x in spec.opt("include", ["*.yar"])]  # type: ignore[union-attr]
    files = [
        RuleFile(bundle_name(spec.name, rel), spec.name, text) for rel, text in iter_tarball_members(data, include)
    ]
    if not files:
        raise FetchError("no rule file matched")
    return Fetched(yara=files, count=len(files))


def f_yara_raw(spec: SourceSpec, ctx: Context) -> Fetched:
    base = spec.url.rstrip("/")
    files: list[RuleFile] = []
    errors: list[str] = []
    for name in [str(x) for x in spec.opt("files", [])]:  # type: ignore[union-attr]
        try:
            text = ctx.http.get_bytes(f"{base}/{name}", max_bytes=4 * 1024 * 1024).decode("utf-8", errors="replace")
            files.append(RuleFile(bundle_name(spec.name, name), spec.name, text))
        except FetchError as e:
            errors.append(str(e))
    if not files:
        raise FetchError("; ".join(errors[:3]) or "no file")
    return Fetched(yara=files, count=len(files))


def f_yara_local(spec: SourceSpec, ctx: Context) -> Fetched:
    files = load_local_rules(ctx.repo_root / str(spec.opt("path", "rules")), spec.name)
    return Fetched(yara=files, count=len(files))


def f_local_file(spec: SourceSpec, ctx: Context) -> Fetched:
    """Curated file from the repo copied to ``dest`` in the bundle (team IDs, allowlist, osquery pack)."""
    src = ctx.repo_root / str(spec.opt("path"))
    dest = str(spec.opt("dest"))
    data = src.read_bytes()
    if dest.endswith(".json"):
        doc = json.loads(data)
        count = len(doc.get("queries", {})) if isinstance(doc, dict) else 0
    else:
        count = sum(1 for line in data.decode().splitlines() if line.strip() and not line.lstrip().startswith("#"))
    return Fetched(files={dest: data}, count=count)


def f_ml_local(spec: SourceSpec, ctx: Context) -> Fetched:
    """Latest promoted model (``ml-latest`` release, downloaded by the workflow into ``--ml-dir``)."""
    if ctx.ml_dir is None:
        raise FetchError("no --ml-dir given")
    model = ctx.ml_dir / "macho_model.json"
    meta = ctx.ml_dir / "model_meta.json"
    if not (model.is_file() and meta.is_file()):
        raise FetchError("ml-latest has no model yet")
    meta_doc = json.loads(meta.read_text(encoding="utf-8"))
    model_doc = json.loads(model.read_text(encoding="utf-8"))
    if "tree_info" not in model_doc or "threshold" not in meta_doc or "features_version" not in meta_doc:
        raise FetchError("ml-latest model or meta malformed")
    return Fetched(
        files={"ml/macho_model.json": model.read_bytes(), "ml/model_meta.json": meta.read_bytes()},
        count=len(model_doc.get("tree_info", [])),
    )


FETCHERS: dict[str, Callable[[SourceSpec, Context], Fetched]] = {
    "mb_export": f_mb_export,
    "mb_api_macos": f_mb_api_macos,
    "urlhaus_export": f_urlhaus_export,
    "threatfox_export": f_threatfox_export,
    "domain_list": f_domain_list,
    "yara_tarball": f_yara_tarball,
    "yara_raw": f_yara_raw,
    "yara_local": f_yara_local,
    "local_file": f_local_file,
    "ml_local": f_ml_local,
}


# --- carry-over ----------------------------------------------------------------------------------


def carry_over(spec: SourceSpec, state_dir: Path | None, prev_dir: Path | None) -> Fetched:
    """Previous data for a failed source (may be empty when nothing was ever fetched)."""
    out = Fetched()
    if spec.fetcher in ("domain_list", "urlhaus_export", "threatfox_export"):
        cat = str(spec.opt("category", "malware" if spec.fetcher != "domain_list" else "ads"))
        p = state_dir / "domains" / f"{spec.name}.txt" if state_dir else None
        if p is not None and p.is_file():
            doms = set(p.read_text(encoding="ascii").split())
        elif prev_dir is not None and (prev_dir / "dns" / f"{cat}.txt").is_file():
            # Coarse fallback (first run with a state): previous merged category file.
            doms = set((prev_dir / "dns" / f"{cat}.txt").read_text(encoding="ascii").split())
        else:
            doms = set()
        out.domains = {cat: doms}
        out.count = len(doms)
    elif spec.kind == "yara" and prev_dir is not None:
        prefix = f"{spec.name}__"
        for p in sorted((prev_dir / "yara").glob(f"{prefix}*.yar")):
            out.yara.append(RuleFile(p.name, spec.name, p.read_text(encoding="utf-8")))
        out.count = len(out.yara)
    elif spec.fetcher == "ml_local" and prev_dir is not None:
        for name in ("macho_model.json", "model_meta.json"):
            p = prev_dir / "ml" / name
            if p.is_file():
                out.files[f"ml/{name}"] = p.read_bytes()
        out.count = 1 if len(out.files) == 2 else 0
        if out.count == 0:
            out.files = {}
    return out


def fetch_all(
    ctx: Context,
    state_dir: Path | None,
    prev_dir: Path | None,
    last_success: Mapping[str, Mapping[str, int]],
    only: Callable[[SourceSpec], bool] = lambda s: True,
) -> tuple[dict[str, Fetched], list[SourceInfo], dict[str, str]]:
    """Fetch every source (in order). Returns (payloads, manifest source entries, errors)."""
    payloads: dict[str, Fetched] = {}
    infos: list[SourceInfo] = []
    errors: dict[str, str] = {}
    for spec in ctx.settings.sources:
        if not only(spec):
            continue
        fn = FETCHERS.get(spec.fetcher)
        if fn is None:
            raise ValueError(f"source {spec.name}: unknown fetcher {spec.fetcher}")
        fresh = True
        fetched_at = ctx.now
        try:
            got = fn(spec, ctx)
        except SkipSource as e:
            log.info("source %s skipped: %s", spec.name, e)
            payloads[spec.name] = Fetched(skipped=True)
            continue
        except Exception as e:  # each source is failure-tolerant by design
            errors[spec.name] = redact(str(e), [ctx.key])[:500]  # defence in depth: never leak the key
            log.warning("source %s failed, carrying over previous data: %s", spec.name, errors[spec.name])
            got = carry_over(spec, state_dir, prev_dir)
            fresh = False
            fetched_at = int(last_success.get(spec.name, {}).get("fetched_at", 0))
            if got.count == 0 and not got.files and spec.kind in ("ml",):
                payloads[spec.name] = got
                continue  # no model at all: do not list an empty ML source
        payloads[spec.name] = got
        count = got.count
        if not fresh and count == 0 and spec.kind == "hashes":
            # Hashes are carried by the rolling index in the state, not by this payload.
            count = int(last_success.get(spec.name, {}).get("count", 0))
        infos.append(SourceInfo(spec.name, spec.kind, spec.display_url, spec.license, count, fetched_at, fresh))
    return payloads, infos, errors


def env_key() -> str:
    return os.environ.get(KEY_ENV, "").strip()
