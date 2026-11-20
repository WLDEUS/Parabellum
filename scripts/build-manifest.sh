#!/usr/bin/env bash
# Write the manifest of Parabellum's own files (crates/pb-core/src/own.rs): SHA-256 + size of every
# regular file of a staged installer payload, so the daemon recognises its own files by content and
# alerts when one is modified, missing, or joined by an unknown file.
#
#   scripts/build-manifest.sh <payload-root> <version>
#
# <payload-root> is the staged `/` of the package (Applications/, Library/…). The manifest is written to
# <payload-root>/Library/Application Support/Parabellum/manifest.json and lists itself out. Run it after
# the last change to the payload (code signing included) and before pkgbuild. Works on macOS and Linux.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && {
    pb_usage "${BASH_SOURCE[0]}"
    exit 0
}
(($# == 2)) || pb_die "usage : build-manifest.sh <payload-root> <version>"
payload="${1%/}"
version="$2"
[[ -d "$payload" ]] || pb_die "payload introuvable : $payload"
[[ "$version" =~ ^[0-9A-Za-z.+-]+$ ]] || pb_die "version invalide : $version"

readonly root_rel="Library/Application Support/Parabellum"
out="$payload/$root_rel/manifest.json"
[[ -d "$payload/$root_rel" ]] || pb_die "$root_rel absent du payload"

if command -v shasum >/dev/null 2>&1; then
    sha() { shasum -a 256 -- "$1" | cut -d' ' -f1; }
elif command -v sha256sum >/dev/null 2>&1; then
    sha() { sha256sum -- "$1" | cut -d' ' -f1; }
else
    pb_die "shasum ou sha256sum requis"
fi

entries=()
while IFS= read -r -d '' f; do
    rel="${f#"$payload"/}"
    [[ "$rel" == "$root_rel/manifest.json" ]] && continue
    # Quotes, backslashes and control characters would need JSON escaping: nothing we ship has them.
    [[ "$rel" =~ [\"\\[:cntrl:]] ]] && pb_die "nom de fichier non pris en charge : $rel"
    case "$rel" in
        "$root_rel"/*) path="@root/${rel#"$root_rel"/}" ;;
        *) path="/$rel" ;;
    esac
    size="$(wc -c <"$f" | tr -d ' ')"
    entries+=("$(printf '    {"path": "%s", "sha256": "%s", "size": %s}' "$path" "$(sha "$f")" "$size")")
done < <(find "$payload" -type f -print0 | LC_ALL=C sort -z)
((${#entries[@]} > 0)) || pb_die "payload vide"

{
    printf '{\n  "format": 1,\n  "version": "%s",\n  "built_at": %s,\n' "$version" "$(date -u +%s)"
    printf '  "trees": ["/Applications/Parabellum.app", "@root/bin", "@root/signatures"],\n'
    printf '  "files": [\n'
    last=$((${#entries[@]} - 1))
    for i in "${!entries[@]}"; do
        if ((i < last)); then printf '%s,\n' "${entries[$i]}"; else printf '%s\n' "${entries[$i]}"; fi
    done
    printf '  ]\n}\n'
} >"$out"
chmod 0644 "$out"
pb_info "manifeste : ${#entries[@]} fichiers -> ${out#"$payload"}"
