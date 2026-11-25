#!/usr/bin/env bash
# Download the promoted ML models (releases ml-latest and ml-domain-latest) and keep only the files whose
# minisign signature checks out (audit SC-7). Used by nightly-db.yml (build-db, verify-db).
#
# Usage: scripts/fetch-ml-models.sh <dest-dir> <public-key>
#
# The publish jobs of ml-train.yml / ml-domains.yml sign every model file with the DB key, trusted comment
# `parabellum-ml <set> <file name>`, where <set> is the publishing run id. A model is a group of files
# (Mach-O: model + meta; script: model + meta; domain: model + meta + brand list + top list); a group is
# kept only when every file is present, every signature is valid, every comment names that file, and all
# comments carry the same <set> (no mixing of an old signed model with a newer signed meta). Anything
# else drops the whole group with a warning: the builder then carries the previous bundle's model over.
#
# Env: GH_TOKEN, GH_REPO. Only a 404 ("no release yet") is tolerated; any other gh error fails.
set -euo pipefail

dest="${1:?usage: scripts/fetch-ml-models.sh <dest-dir> <public-key>}"
pub="${2:?usage: scripts/fetch-ml-models.sh <dest-dir> <public-key>}"
[[ -s "$pub" ]] || { echo "::error::public key missing: $pub" >&2; exit 1; }
: "${GH_REPO:?GH_REPO must be set}"
mkdir -p "$dest"

# release_assets <tag>: asset names on stdout, nothing when the release does not exist.
release_assets() {
    local out
    if out="$(gh api "repos/$GH_REPO/releases/tags/$1" --jq '.assets[].name' 2>&1)"; then
        printf '%s\n' "$out"
        return 0
    fi
    if [[ "$out" == *"HTTP 404"* ]]; then
        echo "::notice::no $1 release yet" >&2
        return 0
    fi
    echo "::error::cannot query release $1: $out" >&2
    exit 1
}

# fetch_group <tag> <assets> <file>...: download and verify one model group into $dest, or drop it.
fetch_group() {
    local tag="$1" assets="$2" f set="" got name s f_name
    shift 2
    # No model file at all: nothing promoted yet. A partial group is suspicious: warn and drop it.
    grep -qxF -- "$1" <<<"$assets" || return 0
    for f in "$@"; do
        grep -qxF -- "$f" <<<"$assets" || { echo "::warning::$tag: $f missing, model dropped" >&2; return 0; }
    done
    local tmp
    tmp="$(mktemp -d "${RUNNER_TEMP:-/tmp}/ml.XXXXXX")"
    for f in "$@"; do
        if ! grep -qxF -- "$f.minisig" <<<"$assets"; then
            echo "::warning::$tag: $f is not signed (no $f.minisig), model dropped (previous bundle's copy carried over)" >&2
            rm -rf "$tmp"
            return 0
        fi
    done
    local patterns=()
    for f in "$@"; do patterns+=(-p "$f" -p "$f.minisig"); done
    gh release download "$tag" -R "$GH_REPO" -D "$tmp" --clobber "${patterns[@]}"
    for f in "$@"; do
        if [[ -L "$tmp/$f" || ! -s "$tmp/$f" ]] || ! got="$(minisign -V -Q -p "$pub" -m "$tmp/$f" 2>/dev/null)"; then
            echo "::warning::$tag: invalid signature on $f, model dropped" >&2
            rm -rf "$tmp"
            return 0
        fi
        read -r name s f_name <<<"$got" || true
        if [[ "$name" != parabellum-ml || -z "$s" || "${f_name:-}" != "$f" || "$got" != "parabellum-ml $s $f" ]]; then
            echo "::warning::$tag: $f signed for '$got', model dropped" >&2
            rm -rf "$tmp"
            return 0
        fi
        if [[ -n "$set" && "$s" != "$set" ]]; then
            echo "::warning::$tag: $f belongs to set $s, not $set (mixed releases), model dropped" >&2
            rm -rf "$tmp"
            return 0
        fi
        set="$s"
    done
    for f in "$@"; do install -m 0644 "$tmp/$f" "$dest/$f"; done
    rm -rf "$tmp"
    echo "$tag: $* verified (set $set)"
}

assets="$(release_assets ml-latest)"
if [[ -n "$assets" ]]; then
    fetch_group ml-latest "$assets" macho_model.json model_meta.json
    fetch_group ml-latest "$assets" script_model.json script_model_meta.json
fi
assets="$(release_assets ml-domain-latest)"
if [[ -n "$assets" ]]; then
    fetch_group ml-domain-latest "$assets" domain_model.json domain_model_meta.json domain_brands.txt domain_top.txt
fi
