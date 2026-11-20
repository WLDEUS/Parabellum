#!/usr/bin/env python3
"""Localization check for the macOS app (French source, English translation).

    scripts/check_localization.py [--stringsdata DIR] [--list-keys FILE] [--report]

- Keys: what the Swift compiler extracted (`swift build -Xswiftc -emit-localized-strings
  -Xswiftc -emit-localized-strings-path -Xswiftc DIR`, one `.stringsdata` JSON per file): every literal
  given to `Text`, `Button`, `Label`, `String(localized:)`, `LocalizedStringKey`… with its format
  (`%lld`, `%@`…). French is the source language: the key is the French text.
- Every key must have an English value in app/Localization/en.lproj/Localizable.strings.
- French-looking literals the compiler did NOT extract are reported: they would stay French in the
  English interface (a `String` shown verbatim). Mark deliberate ones with `// l10n-ignore` on the line.

Without --stringsdata (no macOS toolchain) only the literal scan runs (`--report`).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# The widget (app/Widget, built apart with swiftc) has a handful of texts, translated by hand in the same
# table; the app's Swift package is what the compiler extracts.
SOURCES = [REPO / "app/Sources"]
EN_STRINGS = REPO / "app/Localization/en.lproj/Localizable.strings"

FRENCH_WORDS = re.compile(
    r"(?<![\w'])(le|la|les|des|du|un|une|est|sont|pour|sur|avec|dans|aucun|aucune|ton|ta|tes|votre|vos|"
    r"et|ou|pas|ne|plus|cette|ce|ces|au|aux|en|par|qui|que|non|oui)(?![\w'])",
    re.IGNORECASE,
)
ACCENTS = re.compile(r"[àâçéèêëîïôûùüÿœÀÂÇÉÈÊËÎÏÔÛÙÜŸŒ«»’]")
FORMAT_SPEC = re.compile(
    r"%(?:\d+\$)?[-+ #0]*\d*(?:\.\d+)?(?:ll|l|h|hh|q|L|z|t|j)?[@dDiuUxXoOfFeEgGcCsSpaA]"
)


def is_french(text: str) -> bool:
    """Visible French prose (not identifiers, symbols, paths or URLs)."""
    t = text.strip()
    if len(t) < 2 or not re.search(r"[A-Za-zÀ-ÿ]", t):
        return False
    if re.fullmatch(r"[\w.\-/:@%{}$\\()]+", t) and not ACCENTS.search(t):
        return False  # identifier, key path, symbol name, URL, format
    if ACCENTS.search(t):
        return True
    words = re.findall(r"[A-Za-zÀ-ÿ']+", t)
    return len(words) >= 2 and bool(FRENCH_WORDS.search(t))


# ----- Swift literal scanner -----------------------------------------------------------------------


def swift_literals(src: str):
    """Yield (line, text, prefix) for every string literal; interpolations become `\\(…)` verbatim."""
    i, n, line = 0, len(src), 1
    while i < n:
        c = src[i]
        if c == "\n":
            line += 1
            i += 1
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += src.count("\n", i, j)
            i = j
        elif c == '"' or (c == "#" and src.startswith('#"', i)):
            raw = 0
            while src.startswith("#", i + raw):
                raw += 1
            if src[i + raw] != '"':
                i += 1
                continue
            start_line = line
            line_start = src.rfind("\n", 0, i) + 1
            prefix = src[line_start:i]
            multi = src.startswith('"""', i + raw)
            quote = '"""' if multi else '"'
            j = i + raw + len(quote)
            body = []
            closing = quote + "#" * raw
            while j < n:
                if src.startswith(closing, j):
                    j += len(closing)
                    break
                ch = src[j]
                if ch == "\\" and src.startswith("#" * raw, j + 1) and j + 1 + raw < n:
                    k = j + 1 + raw
                    if src[k] == "(":
                        depth, k2 = 1, k + 1
                        while k2 < n and depth:
                            if src[k2] == "(":
                                depth += 1
                            elif src[k2] == ")":
                                depth -= 1
                            elif src[k2] == '"':
                                # nested literal inside an interpolation
                                e = k2 + 1
                                while e < n and src[e] != '"':
                                    e += 2 if src[e] == "\\" else 1
                                k2 = e
                            k2 += 1
                        body.append(src[j:k2])
                        j = k2
                        continue
                    body.append(src[j : k + 1])
                    j = k + 1
                    continue
                if ch == "\n":
                    line += 1
                body.append(ch)
                j += 1
            text = "".join(body)
            if multi:
                text = text.strip("\n")
            yield start_line, text, prefix
            i = j
        else:
            i += 1


def literal_pattern(text: str) -> str:
    """Comparable form of a source literal: interpolations -> %, escapes resolved."""
    out, i = [], 0
    while i < len(text):
        if text.startswith("\\(", i):
            depth, k = 1, i + 2
            while k < len(text) and depth:
                depth += {"(": 1, ")": -1}.get(text[k], 0)
                k += 1
            out.append("\x00")
            i = k
            continue
        if text[i] == "\\" and i + 1 < len(text):
            out.append(
                {"n": "\n", "t": "\t", '"': '"', "\\": "\\", "'": "'"}.get(
                    text[i + 1], text[i + 1]
                )
            )
            i += 2
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def key_pattern(key: str) -> str:
    return FORMAT_SPEC.sub("\x00", key.replace("%%", "%"))


# ----- .strings ------------------------------------------------------------------------------------

STRINGS_LINE = re.compile(r'^\s*"((?:[^"\\]|\\.)*)"\s*=\s*"((?:[^"\\]|\\.)*)"\s*;\s*$')


def unescape(s: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t"}.get(m[1], m[1]), s)


def escape(s: str) -> str:
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\t", "\\t")
    )


def read_strings(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for ln, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.strip().startswith(("/*", "//", "*")):
            continue
        m = STRINGS_LINE.match(line)
        if not m:
            raise SystemExit(f"{path}:{ln}: ligne .strings invalide")
        out[unescape(m[1])] = unescape(m[2])
    return out


def write_strings(path: Path, table: dict[str, str]) -> None:
    lines = [
        "/* English translation. Keys are the French source texts (scripts/check_localization.py). */",
        "",
    ]
    for k in sorted(table, key=lambda s: (s.casefold(), s)):
        lines.append(f'"{escape(k)}" = "{escape(table[k])}";')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def placeholders(s: str) -> list[str]:
    return [
        re.sub(r"^%\d+\$", "%", m) for m in FORMAT_SPEC.findall(s.replace("%%", ""))
    ]


# ----- stringsdata ---------------------------------------------------------------------------------


def extracted_keys(directory: Path) -> dict[str, set[str]]:
    """key -> source files, from the compiler's .stringsdata (Localizable table)."""
    keys: dict[str, set[str]] = {}

    def walk(node, source):
        if isinstance(node, dict):
            if "key" in node and isinstance(node["key"], str):
                keys.setdefault(node["key"], set()).add(source)
            for v in node.values():
                walk(v, source)
        elif isinstance(node, list):
            for v in node:
                walk(v, source)

    for f in sorted(directory.rglob("*.stringsdata")):
        data = json.loads(f.read_text(encoding="utf-8"))
        tables = data.get("tables", {})
        source = Path(data.get("source", f.stem)).name
        for name, entries in tables.items():
            if name == "Localizable":
                walk(entries, source)
    return keys


# ----- main ----------------------------------------------------------------------------------------


def scan_sources():
    for root in SOURCES:
        for f in sorted(root.rglob("*.swift")):
            src = f.read_text(encoding="utf-8")
            lines = src.splitlines()
            for ln, text, prefix in swift_literals(src):
                if "l10n-ignore" in (lines[ln - 1] if ln - 1 < len(lines) else ""):
                    continue
                if is_french(literal_pattern(text).replace("\x00", "")):
                    yield f.relative_to(REPO), ln, text, prefix.strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stringsdata", type=Path)
    ap.add_argument(
        "--list-keys", type=Path, help="write the extracted keys (JSON) here"
    )
    ap.add_argument(
        "--report",
        action="store_true",
        help="only list French literals (no compiler data)",
    )
    args = ap.parse_args()

    literals = list(scan_sources())
    if args.report or not args.stringsdata:
        for path, ln, text, prefix in literals:
            print(f"{path}:{ln}: {prefix[-40:]!s} {text[:90]!r}")
        print(f"{len(literals)} littéraux français", file=sys.stderr)
        return 0

    keys = extracted_keys(args.stringsdata)
    if not keys:
        print("::error::aucune clé extraite (flag -emit-localized-strings ignoré ?)")
        return 1
    if args.list_keys:
        args.list_keys.write_text(
            json.dumps(sorted(keys), ensure_ascii=False, indent=1), encoding="utf-8"
        )
    en = read_strings(EN_STRINGS)
    errors = 0

    # Every key with words needs an entry, even when English is the same ("ClamAV" = "ClamAV"): single
    # French words ("Faible", "Critique") do not look French to a heuristic, the table is the only proof.
    french_keys = {k for k in keys if is_french(k.replace("%", " "))}
    worded = {k for k in keys if re.search(r"[A-Za-zÀ-ÿ]", FORMAT_SPEC.sub("", k))}
    missing = sorted(k for k in worded if k not in en)
    for k in missing:
        print(
            f"MISSING\t{json.dumps(k, ensure_ascii=False)}\t{','.join(sorted(keys[k]))}"
        )
    errors += len(missing)

    for k, v in sorted(en.items()):
        if sorted(placeholders(k)) != sorted(placeholders(v)):
            print(
                f"FORMAT\t{json.dumps(k, ensure_ascii=False)}\t{json.dumps(v, ensure_ascii=False)}"
            )
            errors += 1

    patterns = {key_pattern(k) for k in keys}
    for path, ln, text, prefix in literals:
        if literal_pattern(text) not in patterns:
            print(
                f"NOT_LOCALIZABLE\t{path}:{ln}\t{json.dumps(text, ensure_ascii=False)}"
            )
            errors += 1

    unused = sorted(set(en) - set(keys))
    print(
        f"{len(keys)} clés extraites ({len(french_keys)} visiblement en français), {len(missing)} sans traduction, "
        f"{len(unused)} traductions inutilisées, {errors} problème(s)"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
