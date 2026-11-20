#!/usr/bin/env bash
# Guard against malware-detection signatures creeping back INTO the compiled binaries.
#
# XProtect flags Parabellum's own (benign) binaries when they embed info-stealer / YARA signature
# strings as contiguous literals. The engine code must stay clean; the signatures ship as data files
# in signatures/ and are loaded at runtime. This script builds the release rlibs of pb-ml, pb-engine
# and pb-monitor plus the shipped release binaries (parabellumd, parabellum, pb-features) and fails if
# any forbidden token appears in them.
#
# String literals are target-independent, so a Linux build + strings/grep check is valid for the Mac.
# The data files under signatures/ and test binaries legitimately contain these tokens and are NOT
# checked here (only the release rlibs/bin are).
#
# Usage: scripts/check-no-embedded-signatures.sh [--skip-build]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

[[ "${1:-}" == "--skip-build" ]] || true  # accepted for compatibility; paths now come from cargo

echo "building release artifacts (pb-ml, pb-engine, pb-monitor libs + parabellumd, parabellum, pb-features)…"
# Ask cargo exactly which files it produced instead of guessing hashed rlib paths under deps/ (a
# restored build cache can report crates as "fresh" and leave the rlib where a glob won't find it).
# compiler-artifact messages carry the real filenames even for fresh units.
build_json="$(mktemp)"
trap 'rm -f "$build_json"' EXIT
cargo build --release --message-format=json \
    -p pb-ml -p pb-engine -p pb-monitor --lib >"$build_json"
cargo build --release --message-format=json -p pb-ml --bin pb-features >>"$build_json"
cargo build --release --message-format=json -p pb-daemon --bin parabellumd -p pb-cli --bin parabellum >>"$build_json"

# Parse the rlibs of pb-ml/pb-engine/pb-monitor and the pb-features binary out of the cargo output.
mapfile -t artifacts < <(python3 - "$build_json" <<'PY'
import json, os, sys
want = {"pb_ml", "pb_engine", "pb_monitor"}  # cargo target names use underscores
bin_names = {"pb-features", "parabellumd", "parabellum"}
libs, bins = {}, {}
for line in open(sys.argv[1], encoding="utf-8"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") != "compiler-artifact":
        continue
    name = m.get("target", {}).get("name")
    for f in m.get("filenames") or []:
        if f.endswith(".rlib") and name in want:
            libs[name] = f
        elif name in bin_names and m.get("executable") == f and os.path.exists(f):
            bins[name] = f
missing = want - set(libs)
if missing:
    sys.stderr.write("ERROR: cargo reported no rlib for: %s\n" % ", ".join(sorted(missing)))
    sys.exit(2)
missing_bins = bin_names - set(bins)
if missing_bins:
    sys.stderr.write("ERROR: cargo reported no binary for: %s\n" % ", ".join(sorted(missing_bins)))
    sys.exit(2)
print("\n".join(list(libs.values()) + list(bins.values())))
PY
)

# Dense signature clusters that must never be compiled into a Parabellum binary.
# Multi-word tokens are split ("display"" dialog") so this script does not match the rules it guards.
tokens=(
    "find-generic-password"
    "find-internet-password"
    "dump-keychain"
    "unlock-keychain"
    "display"" dialog"
    "display"" alert"
    "hidden"" answer"
    "default"" answer"
    "login.keychain"
    "keychain-db"
    "-authonly"
    "Cookies.binarycookies"
    "NoteStore.sqlite"
    "safe storage"
    "AMOS"
    "Poseidon"
    "Banshee"
    "Cuckoo"
    "Exodus"
    "Electrum"
    "MetaMask"
)

if ((${#artifacts[@]} == 0)); then
    echo "ERROR: could not determine artifacts to scan" >&2
    exit 2
fi
printf 'scanning: %s\n' "${artifacts[@]}"

strings_bin="$(command -v strings || true)"
tmp="$(mktemp)"
trap 'rm -f "$tmp" "$build_json"' EXIT
fail=0
for art in "${artifacts[@]}"; do
    if [[ ! -e "$art" ]]; then
        echo "ERROR: expected artifact missing: $art (build first, without --skip-build)" >&2
        exit 2
    fi
    # Dump printable strings ONCE to a file, then grep each token against it. (Piping strings|grep -q
    # is unsafe under `set -o pipefail`: grep -q closes the pipe, strings dies with SIGPIPE, and the
    # pipeline then reports failure even on a real match.)
    if [[ -n "$strings_bin" ]]; then
        "$strings_bin" -a -- "$art" >"$tmp"
    else
        grep -a -o '[[:print:]]\{3,\}' -- "$art" >"$tmp" || true
    fi
    for tok in "${tokens[@]}"; do
        if grep -F -q -e "$tok" -- "$tmp"; then
            echo "FORBIDDEN token embedded in $(basename "$art"): $tok" >&2
            fail=1
        fi
    done
done

if ((fail)); then
    echo >&2
    echo "Detection signatures are compiled into a release artifact. Move them to a signatures/ data" >&2
    echo "file loaded at runtime (see crates/pb-engine/src/yara.rs, pb-monitor/src/sensitive.rs," >&2
    echo "pb-ml/src/{features,script}.rs)." >&2
    exit 1
fi

echo "OK: no embedded malware signatures in the release rlibs/binaries."
