#!/usr/bin/env bash
# Build the Finder extension (Finder › clic droit › Parabellum) with swiftc, no Xcode project needed.
#
# Usage: scripts/build-finder-extension.sh <Parabellum.app>   build, sign and embed Contents/PlugIns/ParabellumFinder.appex
#        scripts/build-finder-extension.sh --check            build into a temporary bundle only (CI)
#
# A Finder Sync extension (FinderSync.framework), sandboxed (installer/entitlements/finder.entitlements) and
# signed with the same identity as the app. It only builds the submenu and opens parabellum:// links; the
# app does the work. Optional like the widget: the Quick Actions (NSServices) offer the same actions.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

(($# == 1)) || pb_die "usage : scripts/build-finder-extension.sh <Parabellum.app> | --check"
pb_require_macos_arm64
pb_require_cmds /usr/bin/xcrun /usr/bin/codesign /usr/bin/plutil

check_only=0
if [[ "$1" == "--check" ]]; then
    check_only=1
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/parabellum-finder.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT
    app="$tmp/Parabellum.app"
    mkdir -p "$app/Contents"
else
    app="$1"
    [[ -d "$app/Contents" ]] || pb_die "bundle introuvable : $app"
fi

src="$PB_REPO_ROOT/app/FinderExtension/ParabellumFinderSync.swift"
appex="$app/Contents/PlugIns/ParabellumFinder.appex"
sdk="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"

rm -rf "$appex"
mkdir -p "$appex/Contents/MacOS"
pb_info "swiftc ParabellumFinder (SDK $(basename "$sdk"))"
# No main: the extension host enters through NSExtensionMain (Foundation).
/usr/bin/xcrun --sdk macosx swiftc \
    -target arm64-apple-macos14.0 \
    -sdk "$sdk" \
    -O -whole-module-optimization \
    -parse-as-library \
    -application-extension \
    -module-name ParabellumFinder \
    -framework Cocoa -framework FinderSync \
    -Xlinker -application_extension \
    -Xlinker -e -Xlinker _NSExtensionMain \
    "$src" \
    -o "$appex/Contents/MacOS/ParabellumFinder"

sed -e "s/@VERSION@/$(pb_version)/g" \
    -e "s/@BUILD_NUMBER@/$(pb_build_number)/g" \
    "$PB_REPO_ROOT/installer/app/Finder-Info.plist.in" >"$appex/Contents/Info.plist"
/usr/bin/plutil -lint "$appex/Contents/Info.plist" >/dev/null
printf 'XPC!????' >"$appex/Contents/PkgInfo"
mkdir -p "$appex/Contents/Resources"
for lproj in "$PB_REPO_ROOT"/app/Localization/*.lproj; do
    /usr/bin/ditto "$lproj" "$appex/Contents/Resources/$(basename "$lproj")"
done
/usr/bin/xattr -cr "$appex" 2>/dev/null || true

pb_codesign --entitlements "$PB_REPO_ROOT/installer/entitlements/finder.entitlements" "$appex"
/usr/bin/codesign --verify --strict --verbose=1 "$appex"
if ! /usr/bin/codesign --display --entitlements - "$appex" 2>/dev/null | grep -q 'com.apple.security.app-sandbox'; then
    pb_die "ParabellumFinder.appex signé sans bac à sable (le Finder le refuserait)"
fi
if ((check_only)); then
    pb_ok "extension Finder construite (vérification uniquement)"
else
    pb_ok "$appex"
fi
