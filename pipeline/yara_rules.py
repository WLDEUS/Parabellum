"""YARA rule handling with yara-x (same minor version as the Rust ``yara-x`` crate, 1.22.x).

* every file is compiled on its own; files that fail are dropped (the client must never receive a
  file it cannot compile);
* rule identifiers are made globally unique (a colliding rule is removed from the later file), so the
  bundle compiles whether the engine uses one namespace per file or a single namespace;
* the FP gate removes individual rules (text spans) that match clean files.
"""

from __future__ import annotations

import fnmatch
import io
import re
import tarfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

import yara_x

#: Rule declaration at the start of a line: ``[private|global ]*rule Name [: tags] {``.
_RULE_RE = re.compile(r"^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z_][A-Za-z0-9_]*)\b", re.MULTILINE)
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")
MAX_RULE_FILE = 4 * 1024 * 1024
#: USTAR names are limited to 100 bytes; keep ``yara/<name>`` well under it.
MAX_NAME_LEN = 90


@dataclass
class RuleFile:
    """One ``.yar`` file destined for ``yara/<name>`` in the bundle."""

    name: str
    source: str
    text: str
    rules: list[str] = field(default_factory=list)


def bundle_name(source: str, filename: str) -> str:
    """``<source>__<file>.yar`` with a filesystem/tar-safe charset."""
    base = Path(filename).name
    if base.lower().endswith(".yara"):
        base = base[:-5] + ".yar"
    if not base.lower().endswith(".yar"):
        base += ".yar"
    name = _SAFE_NAME.sub("_", f"{source}__{base}")
    if len(name) > MAX_NAME_LEN:
        name = name[: MAX_NAME_LEN - 4] + ".yar"
    return name


def rule_names(text: str) -> list[str]:
    return [m.group(1) for m in _RULE_RE.finditer(_mask_comments(text))]


def _mask_comments(text: str) -> str:
    """Blank out comments and string literals (same length) so the rule regex ignores them."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def rule_spans(text: str) -> tuple[str, list[tuple[str, int, int]]]:
    """Split a file into (header, [(rule name, start, end)]); a rule ends where the next one starts."""
    masked = _mask_comments(text)
    starts = [(m.group(1), m.start()) for m in _RULE_RE.finditer(masked)]
    if not starts:
        return text, []
    spans = []
    for i, (name, start) in enumerate(starts):
        end = starts[i + 1][1] if i + 1 < len(starts) else len(text)
        spans.append((name, start, end))
    return text[: starts[0][1]], spans


def remove_rules(text: str, names: Iterable[str]) -> str:
    drop = set(names)
    header, spans = rule_spans(text)
    kept = [text[s:e] for n, s, e in spans if n not in drop]
    return header + "".join(kept)


def compile_one(text: str, origin: str) -> str | None:
    """Compile with default yara-x settings (what the engine uses). Returns an error message or None."""
    c = yara_x.Compiler()
    try:
        c.add_source(text, origin=origin)
        c.build()
    except Exception as e:  # yara_x.CompileError and friends
        return str(e).strip().splitlines()[0][:500] if str(e).strip() else type(e).__name__
    return None


@dataclass
class ValidationReport:
    accepted: list[RuleFile]
    rejected_files: list[tuple[str, str]]
    renamed_away: list[tuple[str, str]]

    @property
    def rule_count(self) -> int:
        return sum(len(f.rules) for f in self.accepted)


def validate(files: Iterable[RuleFile]) -> ValidationReport:
    """Compile every file alone, drop failures, enforce globally unique rule identifiers."""
    accepted: list[RuleFile] = []
    rejected: list[tuple[str, str]] = []
    dup_removed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for f in sorted(files, key=lambda x: x.name):
        if len(f.text.encode()) > MAX_RULE_FILE:
            rejected.append((f.name, "file too large"))
            continue
        err = compile_one(f.text, f.name)
        if err:
            rejected.append((f.name, err))
            continue
        names = rule_names(f.text)
        dups = [n for n in names if n in seen]
        text = f.text
        if dups:
            text = remove_rules(text, dups)
            dup_removed.extend((f.name, n) for n in dups)
            names = rule_names(text)
            err = compile_one(text, f.name) if names else "no rule left after de-duplication"
            if err:
                rejected.append((f.name, f"after de-duplication: {err}"))
                continue
        if not names:
            rejected.append((f.name, "no rule"))
            continue
        seen.update(names)
        accepted.append(RuleFile(f.name, f.source, text, names))
    return ValidationReport(accepted, rejected, dup_removed)


def namespace_for(name: str) -> str:
    return re.sub(r"\W", "_", name)


def compile_all(files: Iterable[RuleFile]) -> yara_x.Rules:
    """All files together, one namespace per file (mirrors the engine)."""
    c = yara_x.Compiler()
    for f in files:
        c.new_namespace(namespace_for(f.name))
        c.add_source(f.text, origin=f.name)
    return c.build()


@dataclass
class Match:
    namespace: str
    rule: str
    severity: str | None


def _meta(rule: yara_x.Rule, key: str) -> str | None:
    for k, v in rule.metadata:
        if k == key:
            return str(v)
    return None


def scan_bytes(scanner: yara_x.Scanner, data: bytes) -> list[Match]:
    res = scanner.scan(data)
    return [Match(r.namespace, r.identifier, _meta(r, "severity")) for r in res.matching_rules]


def scan_file(scanner: yara_x.Scanner, path: Path) -> list[Match]:
    res = scanner.scan_file(str(path))
    return [Match(r.namespace, r.identifier, _meta(r, "severity")) for r in res.matching_rules]


def new_scanner(rules: yara_x.Rules, timeout_s: int = 30) -> yara_x.Scanner:
    s = yara_x.Scanner(rules)
    s.set_timeout(timeout_s)
    return s


# --- fetching ---


def iter_tarball_members(data: bytes, include: list[str], max_files: int = 2000) -> Iterator[tuple[str, str]]:
    """Yield (path inside repo, text) for regular files of a GitHub tarball matching ``include`` globs.

    GitHub tarballs have a single top-level ``<repo>-<sha>/`` directory which is stripped. Globs are
    matched case-insensitively (Elastic mixes ``MacOS_`` and ``Macos_`` prefixes).
    """
    pats = [p.lower() for p in include]
    count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for m in tf:
            if not m.isfile() or m.size > MAX_RULE_FILE:
                continue
            parts = m.name.split("/", 1)
            if len(parts) != 2 or ".." in parts[1].split("/"):
                continue
            rel = parts[1]
            if not any(fnmatch.fnmatchcase(rel.lower(), p) for p in pats):
                continue
            fobj = tf.extractfile(m)
            if fobj is None:
                continue
            yield rel, fobj.read().decode("utf-8", errors="replace")
            count += 1
            if count >= max_files:
                return


def load_local_rules(directory: Path, source: str) -> list[RuleFile]:
    out = []
    for p in sorted(directory.glob("*.yar")) + sorted(directory.glob("*.yara")):
        out.append(RuleFile(bundle_name(source, p.name), source, p.read_text(encoding="utf-8")))
    return out
