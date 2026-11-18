#!/usr/bin/env bash
# Publish the weekly training output of `python -m ml.train --out <dir>`.
#
# Usage: ml/publish.sh <out-dir> [macho|script]
#   script: every file name below gets a `script_` prefix (script_dataset.csv.gz, …,
#           script_model.json, script_model_meta.json, script_model.txt), in the same releases.
#   ml-dataset : dataset.csv.gz (cumulative features, never samples), metrics.jsonl (history), decision.json
#   ml-latest  : macho_model.json, model_meta.json, macho_model.txt — only when decision.json says
#                "promoted": true (meta uploaded last so a reader never pairs a new meta with an old model
#                for long; the nightly DB build and this job share a concurrency group anyway).
# Env: GH_TOKEN (or GITHUB_TOKEN), GH_REPO (default WLDEUS/Parabellum).
set -euo pipefail

out="${1:?usage: ml/publish.sh <out-dir> [macho|script]}"
kind="${2:-macho}"
case "$kind" in
    macho) pre=""; model_files=(macho_model.json macho_model.txt); meta_file=model_meta.json ;;
    script) pre="script_"; model_files=(script_model.json script_model.txt); meta_file=script_model_meta.json ;;
    *) echo "error: unknown kind $kind" >&2; exit 2 ;;
esac
repo="${GH_REPO:-WLDEUS/Parabellum}"
export GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"

ensure_release() {
    local tag="$1" title="$2" notes="$3"
    gh release view "$tag" --repo "$repo" >/dev/null 2>&1 ||
        gh release create "$tag" --repo "$repo" --title "$title" --notes "$notes" --latest=false
}

for f in "${pre}dataset.csv.gz" "${pre}metrics.jsonl" "${pre}decision.json"; do
    [[ -s "$out/$f" ]] || { echo "error: missing $out/$f" >&2; exit 1; }
done
ensure_release ml-dataset "ML dataset" "Cumulative Mach-O and script feature tables (no samples) and training metrics history."
gh release upload ml-dataset --repo "$repo" --clobber \
    "$out/${pre}dataset.csv.gz" "$out/${pre}metrics.jsonl" "$out/${pre}decision.json"

promoted="$(python3 -c 'import json, sys; print("1" if json.load(open(sys.argv[1])).get("promoted") else "0")' "$out/${pre}decision.json")"
if [[ "$promoted" == "1" ]]; then
    for f in "${model_files[@]}" "$meta_file"; do
        [[ -s "$out/model/$f" ]] || { echo "error: promoted but $out/model/$f is missing" >&2; exit 1; }
    done
    ensure_release ml-latest "ML model (latest)" "Promoted LightGBM models (Mach-O, scripts), picked up by the nightly threat DB build."
    gh release upload ml-latest --repo "$repo" --clobber "${model_files[@]/#/$out/model/}"
    gh release upload ml-latest --repo "$repo" --clobber "$out/model/$meta_file"
    echo "new $kind model promoted to ml-latest"
else
    echo "$kind model not promoted: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("reason", ""))' "$out/${pre}decision.json")"
fi
