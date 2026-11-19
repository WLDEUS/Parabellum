#!/usr/bin/env python3
"""Repository contamination guard, run by CI on every push and PR (``python3 scripts/check_repo_hygiene.py``).

Parabellum handles live malware (MalwareBazaar samples in the ML / detection jobs) and ships a root daemon:
the repository itself must never carry an executable payload, a secret, or a workflow that can be
hijacked. This script fails (exit 1) when a tracked file:

* is an executable or archive (ELF, Mach-O, PE, ZIP/wheel/jar, gzip, xar/pkg, 7z, RAR, DMG) outside
  the short allowlist of test fixtures below — a sample or a dropped tool committed by mistake;
* is larger than ``MAX_BYTES``;
* contains a private key or a minisign secret key;
* is a GitHub workflow that uses an action not pinned to a full commit SHA, uses
  ``pull_request_target`` / ``workflow_run`` (privileged runs of untrusted code), interpolates
  attacker-controllable ``github.event`` / ``github.head_ref`` values inside ``run:`` scripts, or
  grants ``permissions: write-all``.

Standard library only (it must run before any dependency is installed).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

MAX_BYTES = 2 * 1024 * 1024

# Binary test fixtures that are allowed on purpose (path -> reason). Keep this list tiny.
ALLOWED_BINARIES = {
    "crates/pb-ml/tests/fixtures/min_arm64.macho": "hand-built 1 KB Mach-O header for the feature extractor",
}

MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"\xcf\xfa\xed\xfe", "Mach-O"),
    (b"\xce\xfa\xed\xfe", "Mach-O"),
    (b"\xfe\xed\xfa\xcf", "Mach-O"),
    (b"\xfe\xed\xfa\xce", "Mach-O"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal / Java class"),
    (b"MZ", "PE / DOS executable"),
    (b"PK\x03\x04", "ZIP archive (zip, wheel, jar, docx…)"),
    (b"PK\x05\x06", "ZIP archive"),
    (b"\x1f\x8b", "gzip"),
    (b"xar!", "xar archive (.pkg)"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!", "RAR archive"),
    (b"\xfd7zXZ", "xz archive"),
    (b"BZh", "bzip2"),
]

SECRET_PATTERNS = [
    re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    # minisign secret key files start with this comment line (the public key says "public key").
    re.compile(
        rb"^untrusted comment: minisign (?:encrypted )?secret key", re.MULTILINE
    ),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),  # GitHub tokens
    re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
]

USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
SHA_REF = re.compile(r"@[0-9a-f]{40}$")
UNSAFE_CONTEXT = re.compile(
    r"\$\{\{\s*(github\.event\.(?!inputs\.)[^}]*|github\.head_ref[^}]*|inputs\.[^}]*)\}\}"
)


def tracked_files(root: Path) -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]


def is_dmg(path: Path, size: int) -> bool:
    if size < 512:
        return False
    with path.open("rb") as f:
        f.seek(size - 512)
        return f.read(4) == b"koly"


def check_file(root: Path, rel: str) -> list[str]:
    path = root / rel
    if path.is_symlink() or not path.is_file():
        return []
    problems: list[str] = []
    size = path.stat().st_size
    if size > MAX_BYTES:
        problems.append(
            f"{rel}: {size} bytes (> {MAX_BYTES}); large blobs belong in releases, not in git"
        )
    with path.open("rb") as f:
        head = f.read(16)
    kind = next((name for magic, name in MAGIC if head.startswith(magic)), None)
    if kind is None and is_dmg(path, size):
        kind = "disk image (DMG)"
    if kind and rel not in ALLOWED_BINARIES:
        problems.append(
            f"{rel}: {kind} committed (samples, tools and archives must never be in the repository)"
        )
    if size <= MAX_BYTES and not rel.startswith(
        ("crates/pb-updater/tests/fixtures/", "scripts/check_repo_hygiene")
    ):
        data = path.read_bytes()
        for pat in SECRET_PATTERNS:
            if pat.search(data):
                problems.append(f"{rel}: looks like a secret ({pat.pattern[:40]!r})")
    return problems


def check_workflow(rel: str, text: str) -> list[str]:
    problems: list[str] = []
    code = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    if re.search(r"\b(pull_request_target|workflow_run)\b", code):
        problems.append(
            f"{rel}: pull_request_target / workflow_run triggers run untrusted code with privileges"
        )
    if re.search(r"permissions:\s*write-all", text):
        problems.append(f"{rel}: permissions: write-all")
    in_run = False
    run_indent = 0
    for n, line in enumerate(text.splitlines(), 1):
        m = USES.match(line)
        if m:
            ref = m.group(1)
            if not ref.startswith("./") and not SHA_REF.search(ref):
                problems.append(
                    f"{rel}:{n}: action {ref} is not pinned to a full commit SHA"
                )
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if re.match(r"-?\s*run:\s*[|>]", stripped):
            in_run, run_indent = True, indent
            continue
        if in_run and stripped and indent <= run_indent:
            in_run = False
        inline_run = re.match(r"-?\s*run:\s*(\S.*)$", stripped)
        script = line if in_run else (inline_run.group(1) if inline_run else "")
        if script and UNSAFE_CONTEXT.search(script):
            problems.append(
                f"{rel}:{n}: expression interpolated into a shell script ({UNSAFE_CONTEXT.search(script).group(0)}); "
                "pass it through env: instead"
            )
    return problems


def main(argv: list[str]) -> int:
    root = Path(argv[1]) if len(argv) > 1 else Path(__file__).resolve().parent.parent
    problems: list[str] = []
    for rel in tracked_files(root):
        problems += check_file(root, rel)
        if rel.startswith(".github/workflows/") and rel.endswith((".yml", ".yaml")):
            problems += check_workflow(
                rel, (root / rel).read_text(encoding="utf-8", errors="replace")
            )
    for rel in ALLOWED_BINARIES:
        if not (root / rel).is_file():
            problems.append(
                f"{rel}: allowlisted fixture is missing (update ALLOWED_BINARIES)"
            )
    if problems:
        for p in problems:
            print(
                f"::error::{p}" if os.environ.get("GITHUB_ACTIONS") else f"error: {p}"
            )
        print(
            f"{len(problems)} problem(s): repository hygiene check failed",
            file=sys.stderr,
        )
        return 1
    print("repository hygiene: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
