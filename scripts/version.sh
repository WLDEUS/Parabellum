#!/usr/bin/env bash
# Print the Parabellum version (from the workspace Cargo.toml) or the build number.
#   scripts/version.sh            -> 0.1.0
#   scripts/version.sh --build    -> 42 (git commit count) or 202610251830 (UTC date on shallow clones)
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

case "${1:-}" in
    "") pb_version ;;
    --build) pb_build_number ;;
    -h | --help) pb_usage "${BASH_SOURCE[0]}" ;;
    *) pb_die "option inconnue : $1" ;;
esac
