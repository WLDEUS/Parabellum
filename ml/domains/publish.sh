#!/usr/bin/env bash
# Publish the output of `python -m ml.domains.train --out <dir>`.
#
# Usage: ml/domains/publish.sh <out-dir>
#   ml-domain-dataset : domains.csv.gz (cumulative listed domains + first-seen day), metrics.jsonl, decision.json
#   ml-domain-latest  : domain_model.json, domain_model.txt, domain_brands.txt, domain_top.txt, then
#                       domain_model_meta.json last — only when decision.json says "promoted": true.
#                       The nightly DB build checks the brand-list hash against the meta, so a half-updated
#                       release is refused there (previous model carried over).
#                       Every promoted file is signed first (audit SC-7): scripts/ci-minisign.sh with the
#                       DB key, trusted comment `parabellum-ml <run id> <file name>`, uploaded with its
#                       .minisig; scripts/fetch-ml-models.sh drops any unsigned or mixed model.
# Env: GH_TOKEN (or GITHUB_TOKEN), GH_REPO (default WLDEUS/Parabellum); for a promotion also
#      MINISIGN_KEY, MINISIGN_KEY_PASSWORD, MINISIGN_PUB (environment db-signing) and GITHUB_RUN_ID.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

out="${1:?usage: ml/domains/publish.sh <out-dir>}"
repo="${GH_REPO:-WLDEUS/Parabellum}"
export GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"

ensure_release() {
    local tag="$1" title="$2" notes="$3" err
    if err="$(gh release view "$tag" --repo "$repo" --json tagName 2>&1 >/dev/null)"; then
        return 0
    fi
    if ! grep -qi "release not found" <<<"$err"; then
        echo "error: gh release view $tag: $err" >&2
        exit 1
    fi
    gh release create "$tag" --repo "$repo" --title "$title" --notes "$notes" --latest=false
}

for f in domains.csv.gz metrics.jsonl decision.json; do
    [[ -s "$out/$f" ]] || { echo "error: missing $out/$f" >&2; exit 1; }
done
ensure_release ml-domain-dataset "ML domain dataset" "Listed malicious domains with first-seen day (positives of the domain model) and training metrics history."
gh release upload ml-domain-dataset --repo "$repo" --clobber "$out/domains.csv.gz" "$out/metrics.jsonl" "$out/decision.json"

promoted="$(python3 -c 'import json, sys; print("1" if json.load(open(sys.argv[1])).get("promoted") else "0")' "$out/decision.json")"
if [[ "$promoted" == "1" ]]; then
    for f in domain_model.json domain_model.txt domain_brands.txt domain_top.txt domain_model_meta.json; do
        [[ -s "$out/model/$f" ]] || { echo "error: promoted but $out/model/$f is missing" >&2; exit 1; }
    done
    set_id="${GITHUB_RUN_ID:?GITHUB_RUN_ID is needed to sign a promoted model}"
    for f in domain_model.json domain_model.txt domain_brands.txt domain_top.txt domain_model_meta.json; do
        bash "$here/../../scripts/ci-minisign.sh" sign "$out/model/$f" "parabellum-ml $set_id $f"
    done
    ensure_release ml-domain-latest "ML domain model (latest)" "Promoted LightGBM phishing / malicious-domain model, signed (minisign, DB key), picked up by the nightly threat DB build."
    uploads=()
    for f in domain_model.json domain_model.txt domain_brands.txt domain_top.txt; do
        uploads+=("$out/model/$f" "$out/model/$f.minisig")
    done
    gh release upload ml-domain-latest --repo "$repo" --clobber "${uploads[@]}"
    gh release upload ml-domain-latest --repo "$repo" --clobber "$out/model/domain_model_meta.json" \
        "$out/model/domain_model_meta.json.minisig"
    echo "new domain model promoted to ml-domain-latest"
else
    echo "domain model not promoted: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("reason", ""))' "$out/decision.json")"
fi
