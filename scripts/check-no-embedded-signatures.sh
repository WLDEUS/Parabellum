#!/usr/bin/env bash
# Guard against malware-detection signatures creeping back INTO the compiled binaries.
#
# XProtect flags Parabellum's own (benign) binaries when they embed info-stealer / YARA signature
# strings as contiguous literals. The engine code must stay clean; the signatures ship as data files
# in signatures/ and are loaded at runtime. This script builds the release rlibs of pb-ml, pb-engine
# and pb-monitor plus the pb-features release binary and fails if any forbidden token appears in them.
#
# String literals are target-independent, so a Linux build + strings/grep check is valid for the Mac.
# The data files under signatures/ and test binaries legitimately contain these tokens and are NOT
# checked here (only the release rlibs/bin are).
#
# Usage: scripts/check-no-embedded-signatures.sh [--skip-build]
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

skip_build=0
[[ "${1:-}" == "--skip-build" ]] && skip_build=1

target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
rel="$target_dir/release"

if ((skip_build == 0)); then
    echo "building release artifacts (pb-ml, pb-engine, pb-monitor libs + pb-features bin)…"
    # Drop any stale hashed rlibs so the scan only sees freshly built artifacts.
    rm -f "$rel"/deps/libpb_ml-*.rlib "$rel"/deps/libpb_engine-*.rlib \
        "$rel"/deps/libpb_monitor-*.rlib
    # A restored build cache can leave cargo thinking these crates are fresh, so after deleting the
    # rlib it would not re-emit it and the scan would find nothing. Touch the crate roots to force a
    # real recompile that writes the rlibs back.
    touch crates/pb-ml/src/lib.rs crates/pb-engine/src/lib.rs crates/pb-monitor/src/lib.rs
    cargo build --release -p pb-ml -p pb-engine -p pb-monitor --lib
    cargo build --release -p pb-ml --bin pb-features
fi

# Library crates land as hashed rlibs under release/deps/; collect every matching rlib.
collect_rlibs() {
    local crate="$1"
    find "$rel/deps" -maxdepth 1 -name "lib${crate}-*.rlib" 2>/dev/null || true
}

# Dense signature clusters that must never be compiled into a Parabellum binary.
tokens=(
    "find-generic-password"
    "find-internet-password"
    "dump-keychain"
    "unlock-keychain"
    "display dialog"
    "display alert"
    "hidden answer"
    "default answer"
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

# Release artifacts to scan: the three library rlibs (hashed, under deps/) and the pb-features binary.
artifacts=()
for crate in pb_ml pb_engine pb_monitor; do
    while IFS= read -r f; do
        [[ -n "$f" ]] && artifacts+=("$f")
    done < <(collect_rlibs "$crate")
done
artifacts+=("$rel/pb-features")

# Every crate must have produced at least one rlib, or the scan would silently check nothing.
for crate in pb_ml pb_engine pb_monitor; do
    if [[ -z "$(collect_rlibs "$crate")" ]]; then
        echo "ERROR: no release rlib for $crate under $rel/deps (build first)" >&2
        exit 2
    fi
done

strings_bin="$(command -v strings || true)"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
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

echo "OK: no embedded malware signatures in the release rlibs/bin."
