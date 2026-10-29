#!/usr/bin/env bash
# Publish a nightly bundle built by `python -m pipeline.build --sign`.
#
# Usage: pipeline/publish.sh <out-dir>
#   1. dated release db-<version> (immutable record): bundle, signature, manifest, report;
#   2. rolling release db-latest (what clients fetch, see UpdatesConfig.db_base_url): bundle and
#      signature first, manifest LAST (a client polling the manifest never sees a new version before
#      the matching bundle/signature are in place), plus the signed pipeline state for tomorrow's run
#      and the Shadowrocket blocklist (shadowrocket-reject.list);
#   3. prune dated db-* releases older than KEEP_DAYS (default 14).
# Env: GH_TOKEN (or GITHUB_TOKEN), GH_REPO (default WLDEUS/Parabellum), KEEP_DAYS.
set -euo pipefail

out="${1:?usage: pipeline/publish.sh <out-dir>}"
repo="${GH_REPO:-WLDEUS/Parabellum}"
keep_days="${KEEP_DAYS:-14}"
export GH_TOKEN="${GH_TOKEN:-${GITHUB_TOKEN:-}}"

for f in parabellum-db.tar.gz parabellum-db.tar.gz.minisig manifest.json pipeline-state.tar.gz \
    pipeline-state.tar.gz.minisig report.json; do
    [[ -s "$out/$f" ]] || { echo "error: missing $out/$f" >&2; exit 1; }
done
version="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' "$out/manifest.json")"
[[ "$version" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$ ]] || { echo "error: bad version '$version'" >&2; exit 1; }

notes="Parabellum threat database $version (built by nightly-db.yml). Verify with: minisign -Vm parabellum-db.tar.gz -p keys/parabellum-db.pub"

# 1. Dated release.
dated="db-$version"
if gh release view "$dated" --repo "$repo" >/dev/null 2>&1; then
    gh release upload "$dated" --repo "$repo" --clobber \
        "$out/parabellum-db.tar.gz" "$out/parabellum-db.tar.gz.minisig" "$out/manifest.json" "$out/report.json"
else
    gh release create "$dated" --repo "$repo" --title "Threat DB $version" --notes "$notes" --latest=false \
        "$out/parabellum-db.tar.gz" "$out/parabellum-db.tar.gz.minisig" "$out/manifest.json" "$out/report.json"
fi

# 2. Rolling release.
if ! gh release view db-latest --repo "$repo" >/dev/null 2>&1; then
    gh release create db-latest --repo "$repo" --title "Threat DB (latest)" --latest=false \
        --notes "Rolling channel fetched by Parabellum clients. Overwritten every night."
fi
gh release upload db-latest --repo "$repo" --clobber "$out/parabellum-db.tar.gz" "$out/parabellum-db.tar.gz.minisig"
gh release upload db-latest --repo "$repo" --clobber \
    "$out/pipeline-state.tar.gz" "$out/pipeline-state.tar.gz.minisig" "$out/report.json"
gh release upload db-latest --repo "$repo" --clobber "$out/manifest.json"
# Shadowrocket DOMAIN-SET (external VPN backend): not part of the signed bundle, fetched by Shadowrocket itself.
if [[ -s "$out/shadowrocket-reject.list" ]]; then
    gh release upload db-latest --repo "$repo" --clobber "$out/shadowrocket-reject.list"
fi
echo "published $version to db-latest and $dated"

# 3. Prune dated releases (tags db-YYYY.MM.DD.N) older than keep_days.
cutoff="$(python3 -c 'import sys, time; print(int(time.time()) - int(sys.argv[1]) * 86400)' "$keep_days")"
gh release list --repo "$repo" --limit 500 --json tagName,createdAt \
    --jq '.[] | select(.tagName | test("^db-[0-9]{4}\\.[0-9]{2}\\.[0-9]{2}\\.[0-9]+$")) | "\(.tagName) \(.createdAt)"' |
    while read -r tag created; do
        ts="$(python3 -c 'import sys, datetime; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00")).timestamp()))' "$created")"
        if ((ts < cutoff)) && [[ "$tag" != "$dated" ]]; then
            echo "pruning $tag ($created)"
            gh release delete "$tag" --repo "$repo" --cleanup-tag --yes || echo "warning: could not delete $tag" >&2
        fi
    done
