#!/usr/bin/env bash
# minisign signing / verification for the GitHub Actions jobs that hold a key (release, threat DB, ML models).
#
# Usage: scripts/ci-minisign.sh sign <file> <trusted comment>
#          env MINISIGN_KEY (secret key file content), MINISIGN_KEY_PASSWORD (empty for an unencrypted key),
#              MINISIGN_PUB (committed public key: the signature is verified right after signing)
#        scripts/ci-minisign.sh verify <pubkey file> <file> <expected trusted comment>
#          fails unless the signature <file>.minisig is valid AND its trusted comment is exactly the one
#          expected (binds the signature to the file name / version it was made for).
#
# The key is written to $RUNNER_TEMP (0600) for the duration of one minisign call. The password goes to
# minisign on stdin (it reads it there when stdin is not a terminal); an unencrypted key ignores it, so
# the jobs work before and after the key is encrypted (scripts/setup-*-key.sh, minisign -C).
# Never prints the key or the password.
set -euo pipefail

KEYFILE=""
cleanup() { [[ -z "$KEYFILE" ]] || rm -f "$KEYFILE"; }
trap cleanup EXIT

die() {
    echo "::error::ci-minisign: $*" >&2
    exit 1
}

sign() {
    local file="$1" comment="$2"
    [[ -n "${MINISIGN_KEY:-}" ]] || die "MINISIGN_KEY is empty (secret not set or job without its environment)"
    [[ -s "${MINISIGN_PUB:-}" ]] || die "MINISIGN_PUB must name the committed public key"
    [[ -f "$file" && ! -L "$file" ]] || die "not a regular file: $file"
    [[ "$comment" != *$'\n'* ]] || die "trusted comment must be one line"
    KEYFILE="$(umask 077 && mktemp "${RUNNER_TEMP:-/tmp}/minisign.XXXXXX")"
    printf '%s\n' "$MINISIGN_KEY" >"$KEYFILE"
    printf '%s\n' "${MINISIGN_KEY_PASSWORD:-}" | minisign -S -s "$KEYFILE" -m "$file" -t "$comment" >/dev/null 2>&1 ||
        die "signing $file failed (wrong MINISIGN_KEY_PASSWORD?)"
    rm -f "$KEYFILE"
    KEYFILE=""
    verify "$MINISIGN_PUB" "$file" "$comment"
}

verify() {
    local pub="$1" file="$2" want="$3" got
    [[ -s "$pub" ]] || die "public key missing: $pub"
    [[ -s "$file.minisig" ]] || die "signature missing: $file.minisig"
    got="$(minisign -V -Q -p "$pub" -m "$file")" || die "invalid signature: $file"
    [[ "$got" == "$want" ]] || die "$file: trusted comment '$got', expected '$want'"
}

case "${1:-}" in
    sign)
        (($# == 3)) || die "usage: sign <file> <trusted comment>"
        sign "$2" "$3"
        ;;
    verify)
        (($# == 4)) || die "usage: verify <pubkey> <file> <expected trusted comment>"
        verify "$2" "$3" "$4"
        ;;
    *) die "usage: $0 sign|verify …" ;;
esac
