#!/usr/bin/env bash
# Check that this Mac can build Parabellum. Prints what is missing (in French) and how to fix it.
# Exit status: 0 when every required item is present, 1 otherwise. Optional items only warn.
# Usage: scripts/dev-check.sh
set -uo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

missing_count=0
row() { printf '  %-6s %-28s %s\n' "$1" "$2" "$3"; }
ok() { row "OK" "$1" "$2"; }
ko() {
    row "MANQUE" "$1" "$2"
    missing_count=$((missing_count + 1))
}
opt() { row "option" "$1" "$2"; }

# version_ge A B: true if version A >= B (numeric, dot-separated, up to 3 parts).
version_ge() {
    local a1 a2 a3 b1 b2 b3
    IFS=. read -r a1 a2 a3 <<<"$1"
    IFS=. read -r b1 b2 b3 <<<"$2"
    a1=${a1:-0} a2=${a2:-0} a3=${a3:-0} b1=${b1:-0} b2=${b2:-0} b3=${b3:-0}
    local v
    for v in "$a1" "$a2" "$a3" "$b1" "$b2" "$b3"; do
        [[ "$v" =~ ^[0-9]+$ ]] || return 1
    done
    if ((10#$a1 != 10#$b1)); then
        ((10#$a1 > 10#$b1))
        return
    fi
    if ((10#$a2 != 10#$b2)); then
        ((10#$a2 > 10#$b2))
        return
    fi
    ((10#$a3 >= 10#$b3))
}

echo "Parabellum : vérification du poste de développement"
echo

# --- Système -------------------------------------------------------------------------------------
if [[ "$(uname -s)" != "Darwin" ]]; then
    ko "macOS" "système $(uname -s) : seuls make test / lint / dev-daemon fonctionnent ici"
else
    ver="$(/usr/bin/sw_vers -productVersion)"
    if version_ge "$ver" "$PB_MIN_MACOS_MAJOR.0"; then
        ok "macOS $ver" ""
    else
        ko "macOS $ver" "macOS $PB_MIN_MACOS_MAJOR ou plus récent requis"
    fi
    if [[ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" != "1" ]]; then
        ko "Apple Silicon" "Mac Intel : non pris en charge"
    elif [[ "$(/usr/sbin/sysctl -n sysctl.proc_translated 2>/dev/null || echo 0)" == "1" ]]; then
        ko "arm64 natif" "ce terminal tourne sous Rosetta : relancez-le en natif"
    else
        ok "Apple Silicon (arm64)" ""
    fi

    if dev_dir="$(/usr/bin/xcode-select -p 2>/dev/null)"; then
        ok "Outils Xcode" "$dev_dir"
        if [[ "$dev_dir" != *"Xcode"*".app"* ]]; then
            opt "Xcode complet" "recommandé pour « swift test » (XCTest absent des Command Line Tools seuls)"
        fi
    else
        ko "Outils Xcode" "xcode-select --install"
    fi
    for t in pkgbuild productbuild codesign plutil iconutil sips lipo; do
        if command -v "$t" >/dev/null 2>&1; then
            ok "$t" ""
        else
            ko "$t" "fourni par les outils Xcode : xcode-select --install"
        fi
    done
fi

# --- Rust ----------------------------------------------------------------------------------------
rust_min="$(awk -F'"' '/^rust-version[[:space:]]*=/ { print $2; exit }' "$PB_REPO_ROOT/Cargo.toml")"
rust_min="${rust_min:-1.0}"
if command -v rustup >/dev/null 2>&1; then
    ok "rustup" "$(rustup --version 2>/dev/null | head -n1)"
    if rustup target list --installed 2>/dev/null | grep -qx "$PB_RUST_TARGET"; then
        ok "cible $PB_RUST_TARGET" ""
    else
        ko "cible $PB_RUST_TARGET" "rustup target add $PB_RUST_TARGET (make build le fait aussi)"
    fi
else
    ko "rustup" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi
if command -v rustc >/dev/null 2>&1; then
    rv="$(rustc --version | awk '{ print $2 }')"
    rv="${rv%%-*}"
    if version_ge "$rv" "$rust_min"; then
        ok "rustc $rv" "(minimum $rust_min)"
    else
        ko "rustc $rv" "Rust $rust_min minimum : rustup update stable"
    fi
else
    ko "rustc" "installé avec rustup"
fi

# --- Swift ---------------------------------------------------------------------------------------
if command -v swift >/dev/null 2>&1; then
    sv="$(swift --version 2>/dev/null | sed -n 's/.*Swift version \([0-9][0-9.]*\).*/\1/p' | head -n1)"
    need=""
    if [[ -f "$PB_REPO_ROOT/app/Package.swift" ]]; then
        need="$(sed -n 's#^// *swift-tools-version: *\([0-9][0-9.]*\).*#\1#p' "$PB_REPO_ROOT/app/Package.swift" | head -n1)"
    fi
    if [[ -z "$sv" ]]; then
        ko "swift" "version illisible ($(swift --version 2>&1 | head -n1))"
    elif [[ -n "$need" ]] && ! version_ge "$sv" "$need"; then
        ko "swift $sv" "app/Package.swift demande swift-tools-version $need : mettez Xcode à jour"
    else
        ok "swift $sv" "${need:+(tools-version $need)}"
    fi
else
    ko "swift" "xcode-select --install (ou Xcode depuis l'App Store)"
fi

# --- Optionnels ----------------------------------------------------------------------------------
if command -v minisign >/dev/null 2>&1; then
    ok "minisign" "$(minisign -v 2>/dev/null | head -n1)"
else
    opt "minisign" "brew install minisign (vérifier une base à la main, make keys)"
fi
if command -v gh >/dev/null 2>&1; then
    if gh auth status >/dev/null 2>&1; then
        ok "gh" "connecté"
    else
        opt "gh" "installé mais non connecté : gh auth login"
    fi
else
    opt "gh" "brew install gh (secrets GitHub, téléchargement des artefacts CI)"
fi
if command -v shellcheck >/dev/null 2>&1; then
    ok "shellcheck" ""
else
    opt "shellcheck" "brew install shellcheck (make lint vérifie aussi les scripts)"
fi
if [[ -s "$PB_REPO_ROOT/keys/parabellum-db.pub" || -n "${PARABELLUM_DB_PUBKEY:-}" ]]; then
    ok "clé publique de la base" "keys/parabellum-db.pub"
else
    opt "clé publique de la base" "absente : make keys (obligatoire avant make pkg)"
fi

echo
if ((missing_count == 0)); then
    echo "Tout est prêt : make pkg"
    exit 0
fi
echo "$missing_count élément(s) requis manquant(s)."
exit 1
