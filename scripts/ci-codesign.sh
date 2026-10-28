#!/usr/bin/env bash
# GitHub Actions (macOS runner): make the stable code-signing identity available to the build scripts.
#
# Usage: scripts/ci-codesign.sh import    (before scripts/build-pkg.sh)
#        scripts/ci-codesign.sh cleanup   (last step, `if: always()`)
#
# import: with the secrets MACOS_SIGN_P12 (base64 .p12) and MACOS_SIGN_P12_PASSWORD (both created by
# scripts/setup-codesign-cert.sh), creates a temporary keychain in $RUNNER_TEMP, imports the identity,
# sets the key partition list (codesign without UI), trusts the certificate for code signing, checks a
# test signature, and exports PARABELLUM_SIGN_IDENTITY (SHA-1) + PARABELLUM_SIGN_KEYCHAIN to $GITHUB_ENV.
# Without the secrets: exports PARABELLUM_SIGN_IDENTITY=- (ad hoc) and warns.
# cleanup: deletes the keychain, the trust setting and the temporary files. Never fails.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

: "${RUNNER_TEMP:?RUNNER_TEMP not set (GitHub Actions only)}"
: "${GITHUB_ENV:?GITHUB_ENV not set (GitHub Actions only)}"
readonly KEYCHAIN="$RUNNER_TEMP/parabellum-signing.keychain-db"
readonly CERT_PEM="$RUNNER_TEMP/parabellum-signing.cer.pem"

import() {
    if [[ -z "${MACOS_SIGN_P12:-}" || -z "${MACOS_SIGN_P12_PASSWORD:-}" ]]; then
        echo "::warning title=codesign::MACOS_SIGN_P12 / MACOS_SIGN_P12_PASSWORD not available: ad-hoc signature" \
            "(Full Disk Access must be granted again after installing this build). Run make codesign-cert on the Mac."
        echo "PARABELLUM_SIGN_IDENTITY=-" >>"$GITHUB_ENV"
        return 0
    fi

    local work kc_pass hash
    work="$(mktemp -d "$RUNNER_TEMP/codesign.XXXXXX")"
    chmod 0700 "$work"
    (umask 077 && printf '%s' "$MACOS_SIGN_P12" | tr -d '\r\n ' >"$work/p12.b64")
    /usr/bin/base64 -D -i "$work/p12.b64" -o "$work/sign.p12"
    kc_pass="$(/usr/bin/openssl rand -hex 24)"
    echo "::add-mask::$kc_pass"

    /usr/bin/security create-keychain -p "$kc_pass" "$KEYCHAIN"
    /usr/bin/security set-keychain-settings -lut 21600 "$KEYCHAIN"
    /usr/bin/security unlock-keychain -p "$kc_pass" "$KEYCHAIN"
    /usr/bin/security import "$work/sign.p12" -k "$KEYCHAIN" -f pkcs12 -P "$MACOS_SIGN_P12_PASSWORD" \
        -T /usr/bin/codesign >/dev/null
    rm -rf "$work"
    /usr/bin/security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$kc_pass" "$KEYCHAIN" >/dev/null

    # Put the keychain in the user search list (kept: the existing ones).
    local list=() k
    while IFS= read -r k; do
        k="${k#"${k%%[![:space:]]*}"}"
        k="${k#\"}"
        k="${k%\"}"
        [[ -n "$k" ]] && list+=("$k")
    done < <(/usr/bin/security list-keychains -d user)
    /usr/bin/security list-keychains -d user -s "$KEYCHAIN" ${list[@]+"${list[@]}"}

    # Trust for code signing (admin trust settings; root on the runner, no UI). Best effort.
    /usr/bin/security find-certificate -c "$PB_SIGN_CERT_NAME" -p "$KEYCHAIN" >"$CERT_PEM"
    if ! sudo /usr/bin/security add-trusted-cert -d -r trustRoot -p codeSign -k "$KEYCHAIN" "$CERT_PEM"; then
        echo "::warning title=codesign::could not mark the certificate as trusted for code signing"
    fi

    hash="$(pb_find_sign_identity valid "$KEYCHAIN")"
    [[ -n "$hash" ]] || hash="$(pb_find_sign_identity any "$KEYCHAIN")"
    if [[ -z "$hash" ]]; then
        echo "::error title=codesign::no \"$PB_SIGN_CERT_NAME\" identity in MACOS_SIGN_P12"
        exit 1
    fi

    # Fail now rather than ship an ad-hoc build by accident.
    cp /usr/bin/true "$RUNNER_TEMP/signtest"
    /usr/bin/codesign --force --sign "$hash" --keychain "$KEYCHAIN" --timestamp=none "$RUNNER_TEMP/signtest"
    echo "designated requirement: $(/usr/bin/codesign --display --requirements - "$RUNNER_TEMP/signtest" 2>&1 |
        sed -n 's/^designated => //p')"
    rm -f "$RUNNER_TEMP/signtest"

    {
        echo "PARABELLUM_SIGN_IDENTITY=$hash"
        echo "PARABELLUM_SIGN_KEYCHAIN=$KEYCHAIN"
    } >>"$GITHUB_ENV"
    echo "::notice title=codesign::signing with \"$PB_SIGN_CERT_NAME\" ($hash)"
}

cleanup() {
    if [[ -f "$CERT_PEM" ]]; then
        sudo /usr/bin/security remove-trusted-cert -d "$CERT_PEM" 2>/dev/null || true
    fi
    if [[ -f "$KEYCHAIN" ]]; then
        /usr/bin/security delete-keychain "$KEYCHAIN" 2>/dev/null || true
    fi
    rm -rf "$CERT_PEM" "$RUNNER_TEMP"/codesign.* "$RUNNER_TEMP/signtest" 2>/dev/null || true
    return 0
}

case "${1:-}" in
    import) import ;;
    cleanup) cleanup ;;
    -h | --help) pb_usage "${BASH_SOURCE[0]}" ;;
    *) pb_die "usage : $0 import|cleanup" ;;
esac
