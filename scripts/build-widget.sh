#!/usr/bin/env bash
# Build the optional desktop widget (WidgetKit extension) with swiftc, no Xcode project needed.
#
# Usage: scripts/build-widget.sh <Parabellum.app>   build, sign and embed Contents/PlugIns/ParabellumWidget.appex
#        scripts/build-widget.sh --check            build into a temporary bundle only (CI)
#
# Optional by design: scripts/build-app.sh ships the app without the widget when this fails (older SDK,
# missing WidgetKit). The extension is sandboxed (installer/entitlements/widget.entitlements) and signed with
# the same identity as the app (ad hoc or "Parabellum Local Signing"); no App Group, no paid account: the app
# writes the widget's data into the extension's own container (see WidgetSnapshot.swift).
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

(($# == 1)) || pb_die "usage : scripts/build-widget.sh <Parabellum.app> | --check"
pb_require_macos_arm64
pb_require_cmds /usr/bin/xcrun /usr/bin/codesign /usr/bin/plutil

check_only=0
if [[ "$1" == "--check" ]]; then
    check_only=1
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/parabellum-widget.XXXXXX")"
    trap 'rm -rf "$tmp"' EXIT
    app="$tmp/Parabellum.app"
    mkdir -p "$app/Contents"
else
    app="$1"
    [[ -d "$app/Contents" ]] || pb_die "bundle introuvable : $app"
fi

src="$PB_REPO_ROOT/app/Widget/ParabellumWidget.swift"
shared="$PB_REPO_ROOT/app/Sources/ParabellumKit/WidgetSnapshot.swift"
appex="$app/Contents/PlugIns/ParabellumWidget.appex"
sdk="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"

rm -rf "$appex"
mkdir -p "$appex/Contents/MacOS"
pb_info "swiftc ParabellumWidget (SDK $(basename "$sdk"))"
/usr/bin/xcrun --sdk macosx swiftc \
    -target arm64-apple-macos14.0 \
    -sdk "$sdk" \
    -O -whole-module-optimization \
    -parse-as-library \
    -application-extension \
    -module-name ParabellumWidget \
    -framework WidgetKit -framework SwiftUI \
    -Xlinker -application_extension \
    "$src" "$shared" \
    -o "$appex/Contents/MacOS/ParabellumWidget"

sed -e "s/@VERSION@/$(pb_version)/g" \
    -e "s/@BUILD_NUMBER@/$(pb_build_number)/g" \
    "$PB_REPO_ROOT/installer/app/Widget-Info.plist.in" >"$appex/Contents/Info.plist"
/usr/bin/plutil -lint "$appex/Contents/Info.plist" >/dev/null
printf 'XPC!????' >"$appex/Contents/PkgInfo"
/usr/bin/xattr -cr "$appex" 2>/dev/null || true

pb_codesign --entitlements "$PB_REPO_ROOT/installer/entitlements/widget.entitlements" "$appex"
/usr/bin/codesign --verify --strict --verbose=1 "$appex"
if ! /usr/bin/codesign --display --entitlements - "$appex" 2>/dev/null | grep -q 'com.apple.security.app-sandbox'; then
    pb_die "ParabellumWidget.appex signé sans bac à sable (WidgetKit le refuserait)"
fi
if ((check_only)); then
    pb_ok "widget construit (vérification uniquement)"
else
    pb_ok "$appex"
fi
