# shellcheck shell=bash
# Shared helpers for the Parabellum build scripts (sourced, never executed).
#
#   source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
#
# Everything here is read-only with respect to the system: no sudo, no writes outside the repo.

# Labels and install paths — must match crates/pb-core/src/{lib.rs,paths.rs}. Used by the callers.
# shellcheck disable=SC2034
readonly PB_BUNDLE_ID="com.wldeus.parabellum"
readonly PB_DAEMON_LABEL="com.wldeus.parabellum.daemon"
readonly PB_UI_AGENT_LABEL="com.wldeus.parabellum.ui"
readonly PB_PKG_ID="com.wldeus.parabellum.pkg"
readonly PB_DAEMON_SIGN_ID="com.wldeus.parabellum.daemon"
readonly PB_CLI_SIGN_ID="com.wldeus.parabellum.cli"
readonly PB_RUST_TARGET="aarch64-apple-darwin"
readonly PB_APP_PRODUCT="Parabellum"
readonly PB_INSTALL_ROOT="/Library/Application Support/Parabellum"
readonly PB_MIN_MACOS_MAJOR=14
# Self-signed code-signing certificate created once by scripts/setup-codesign-cert.sh (make codesign-cert).
readonly PB_SIGN_CERT_NAME="Parabellum Local Signing"

# Repository root (scripts/lib/ -> repo).
PB_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly PB_REPO_ROOT

if [[ -t 2 ]]; then
    _pb_c_info=$'\033[1;34m' _pb_c_warn=$'\033[1;33m' _pb_c_err=$'\033[1;31m' _pb_c_ok=$'\033[1;32m' _pb_c_off=$'\033[0m'
else
    _pb_c_info='' _pb_c_warn='' _pb_c_err='' _pb_c_ok='' _pb_c_off=''
fi

pb_info() { printf '%s==>%s %s\n' "$_pb_c_info" "$_pb_c_off" "$*" >&2; }
pb_ok() { printf '%s ok%s %s\n' "$_pb_c_ok" "$_pb_c_off" "$*" >&2; }
pb_warn() { printf '%sattention:%s %s\n' "$_pb_c_warn" "$_pb_c_off" "$*" >&2; }
# Print the leading comment block of a script (its --help text).
pb_usage() {
    awk 'NR == 1 { next } /^#/ { if ($0 ~ /^# shellcheck/) next; sub(/^# ?/, ""); print; next } { exit }' "$1"
}

pb_die() {
    printf '%serreur:%s %s\n' "$_pb_c_err" "$_pb_c_off" "$*" >&2
    exit 1
}

# Fail clearly unless running natively on macOS >= 14, Apple Silicon.
pb_require_macos_arm64() {
    [[ "$(uname -s)" == "Darwin" ]] || pb_die "ce script doit tourner sur macOS (détecté : $(uname -s))."
    local translated machine
    translated="$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)"
    [[ "$translated" != "1" ]] || pb_die "ce terminal tourne sous Rosetta (x86_64) : relancez-le en natif arm64."
    machine="$(uname -m)"
    [[ "$machine" == "arm64" ]] || pb_die "Mac Apple Silicon (arm64) requis (détecté : $machine)."
    local ver major
    ver="$(/usr/bin/sw_vers -productVersion)"
    major="${ver%%.*}"
    if ! [[ "$major" =~ ^[0-9]+$ ]] || ((major < PB_MIN_MACOS_MAJOR)); then
        pb_die "macOS ${PB_MIN_MACOS_MAJOR}+ requis (détecté : $ver)."
    fi
}

# Fail unless every named command is available.
pb_require_cmds() {
    local c missing=()
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || missing+=("$c")
    done
    ((${#missing[@]} == 0)) || pb_die "outil(s) introuvable(s) : ${missing[*]} (lancez scripts/dev-check.sh)."
}

# Version from `[workspace.package] version` in the root Cargo.toml (override: PARABELLUM_VERSION).
pb_version() {
    local v="${PARABELLUM_VERSION:-}"
    if [[ -z "$v" ]]; then
        v="$(awk '
            /^[[:space:]]*\[/ {
                line = $0; sub(/[[:space:]]*(#.*)?$/, "", line); sub(/^[[:space:]]*/, "", line)
                in_section = (line == "[workspace.package]"); next
            }
            in_section && /^[[:space:]]*version[[:space:]]*=/ {
                sub(/^[^=]*=[[:space:]]*"/, ""); sub(/".*$/, ""); print; exit
            }' "$PB_REPO_ROOT/Cargo.toml")"
    fi
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+.][0-9A-Za-z.-]+)?$ ]] ||
        pb_die "version invalide ou introuvable dans Cargo.toml : '${v}'"
    printf '%s\n' "$v"
}

# Build number: git commit count on a full clone, otherwise UTC date (override: PARABELLUM_BUILD_NUMBER).
pb_build_number() {
    local n="${PARABELLUM_BUILD_NUMBER:-}"
    if [[ -z "$n" ]] && command -v git >/dev/null 2>&1 &&
        git -C "$PB_REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 &&
        [[ "$(git -C "$PB_REPO_ROOT" rev-parse --is-shallow-repository 2>/dev/null)" == "false" ]]; then
        n="$(git -C "$PB_REPO_ROOT" rev-list --count HEAD 2>/dev/null || true)"
    fi
    [[ -n "$n" ]] || n="$(date -u '+%Y%m%d%H%M')"
    [[ "$n" =~ ^[0-9]+(\.[0-9]+){0,2}$ ]] || pb_die "numéro de build invalide : '${n}'"
    printf '%s\n' "$n"
}

# True if the file is a Mach-O binary.
pb_is_macho() {
    [[ -f "$1" && ! -L "$1" ]] && /usr/bin/file -b "$1" | grep -q 'Mach-O'
}

# --- Code signing -----------------------------------------------------------------------------------
# Identity used by every codesign call, resolved once per process (pb_resolve_sign_identity):
#   1. $PARABELLUM_SIGN_IDENTITY when set: certificate name or SHA-1 hash, or "-" to force ad hoc;
#   2. otherwise the "Parabellum Local Signing" identity if it is in the keychain search list;
#   3. otherwise ad hoc ("-").
# With the same certificate, the designated requirement of each binary is stable across rebuilds
# (identifier + certificate hash), so the Full Disk Access grant (TCC) survives updates. An ad-hoc
# requirement is the cdhash of that exact build: the grant is lost at every update.
# $PARABELLUM_SIGN_KEYCHAIN (optional) restricts the identity lookup to one keychain (CI).
PB_SIGN_IDENTITY=""

# Prints the SHA-1 of the first identity named $PB_SIGN_CERT_NAME. $1 = "valid" to require an identity
# trusted for code signing, "any" to also accept untrusted ones. Extra args: keychains to search.
pb_find_sign_identity() {
    local mode="$1"
    shift
    local args=(find-identity -p codesigning)
    [[ "$mode" != "valid" ]] || args+=(-v)
    /usr/bin/security "${args[@]}" "$@" 2>/dev/null |
        awk -v name="\"$PB_SIGN_CERT_NAME\"" '$1 ~ /^[0-9]+\)$/ && $2 ~ /^[0-9A-F]+$/ && index($0, name) { print $2; exit }'
}

pb_resolve_sign_identity() {
    [[ -z "$PB_SIGN_IDENTITY" ]] || return 0
    local kc=() hash
    [[ -z "${PARABELLUM_SIGN_KEYCHAIN:-}" ]] || kc=("$PARABELLUM_SIGN_KEYCHAIN")
    if [[ -n "${PARABELLUM_SIGN_IDENTITY:-}" ]]; then
        PB_SIGN_IDENTITY="$PARABELLUM_SIGN_IDENTITY"
        if [[ "$PB_SIGN_IDENTITY" == "-" ]]; then
            pb_info "Signature : ad hoc (PARABELLUM_SIGN_IDENTITY=-)"
        else
            pb_info "Signature : identité $PB_SIGN_IDENTITY (PARABELLUM_SIGN_IDENTITY)"
        fi
        return 0
    fi
    hash="$(pb_find_sign_identity valid ${kc[@]+"${kc[@]}"})"
    if [[ -n "$hash" ]]; then
        PB_SIGN_IDENTITY="$hash"
        pb_info "Signature : certificat « $PB_SIGN_CERT_NAME » ($hash)"
        return 0
    fi
    hash="$(pb_find_sign_identity any ${kc[@]+"${kc[@]}"})"
    if [[ -n "$hash" ]]; then
        PB_SIGN_IDENTITY="$hash"
        pb_warn "certificat « $PB_SIGN_CERT_NAME » présent mais non approuvé pour la signature de code :" \
            "relancez scripts/setup-codesign-cert.sh (ou Trousseaux > certificat > Se fier > Signature de code : Toujours approuver)"
        return 0
    fi
    PB_SIGN_IDENTITY="-"
    pb_warn "signature AD HOC : l'accès complet au disque de parabellumd sera perdu à chaque mise à jour." \
        "Pour une signature stable : make codesign-cert (une seule fois)"
}

# codesign with the resolved identity and the hardened runtime. Usage: pb_codesign [codesign options…] <path>
pb_codesign() {
    pb_resolve_sign_identity
    local args=(--force --options runtime --timestamp=none --sign "$PB_SIGN_IDENTITY")
    [[ -z "${PARABELLUM_SIGN_KEYCHAIN:-}" || "$PB_SIGN_IDENTITY" == "-" ]] || args+=(--keychain "$PARABELLUM_SIGN_KEYCHAIN")
    /usr/bin/codesign "${args[@]}" "$@"
}

# Print the designated requirement (what TCC records for Full Disk Access).
pb_print_requirement() {
    local req
    req="$(/usr/bin/codesign --display --requirements - "$1" 2>&1 | sed -n 's/^designated => //p' | head -n 1)"
    pb_info "  exigence désignée de $(basename "$1") : ${req:-?}"
}

# Sign one binary (hardened runtime). Usage: pb_sign_binary <file> <identifier> [entitlements]
pb_sign_binary() {
    local file="$1" ident="$2" ent="${3:-}"
    local args=(--identifier "$ident")
    [[ -z "$ent" ]] || args+=(--entitlements "$ent")
    pb_codesign "${args[@]}" "$file"
    /usr/bin/codesign --verify --strict --verbose=1 "$file"
    pb_print_requirement "$file"
}
