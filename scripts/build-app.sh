#!/usr/bin/env bash
# Assemble dist/Parabellum.app from the SwiftPM build in app/ and sign it (hardened runtime).
#
# Usage: scripts/build-app.sh [--skip-build] [--out <dir>]
#   --skip-build   reuse the existing `swift build -c release --arch arm64` output
#   --out <dir>    output directory (default: <repo>/dist)
#
# Result: <out>/Parabellum.app
#   Contents/MacOS/Parabellum            SwiftPM executable product
#   Contents/Info.plist                  rendered from installer/app/Info.plist.in
#   Contents/Resources/AppIcon.icns      drawn by installer/app/make-icon.swift (skipped on failure)
#   Contents/Resources/*.bundle          SwiftPM resource bundles, if any
#
# Signing: the "Parabellum Local Signing" certificate (make codesign-cert) when present, or
# $PARABELLUM_SIGN_IDENTITY, otherwise ad hoc. See pb_resolve_sign_identity in lib/common.sh.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() { pb_usage "${BASH_SOURCE[0]}"; }

skip_build=0
out_dir="$PB_REPO_ROOT/dist"
while (($# > 0)); do
    case "$1" in
        --skip-build) skip_build=1 ;;
        --out)
            (($# >= 2)) || pb_die "--out attend un dossier"
            out_dir="$2"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) pb_die "option inconnue : $1 (voir --help)" ;;
    esac
    shift
done

pb_require_macos_arm64
pb_require_cmds swift /usr/bin/codesign /usr/bin/security /usr/bin/plutil /usr/bin/lipo /usr/bin/ditto /usr/bin/file

app_src="$PB_REPO_ROOT/app"
[[ -f "$app_src/Package.swift" ]] || pb_die "paquet SwiftPM introuvable : $app_src/Package.swift"

version="$(pb_version)"
build_number="$(pb_build_number)"
year="$(date -u '+%Y')"

mkdir -p "$out_dir"
out_dir="$(cd "$out_dir" && pwd -P)"
app="$out_dir/Parabellum.app"

work="$(mktemp -d "${TMPDIR:-/tmp}/parabellum-app.XXXXXX")"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

swift_args=(-c release --arch arm64)

if ((skip_build == 0)); then
    pb_info "swift build ${swift_args[*]} (app/)"
    (cd "$app_src" && swift build "${swift_args[@]}")
fi

bin_dir="$(cd "$app_src" && swift build "${swift_args[@]}" --show-bin-path)"
exe="$bin_dir/$PB_APP_PRODUCT"
[[ -x "$exe" ]] || pb_die "exécutable introuvable : $exe (lancez sans --skip-build)"
archs="$(/usr/bin/lipo -archs "$exe")"
[[ " $archs " == *" arm64 "* ]] || pb_die "$exe n'est pas arm64 (architectures : $archs)"

pb_info "Assemblage de $app (version $version, build $build_number)"
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
/usr/bin/ditto "$exe" "$app/Contents/MacOS/$PB_APP_PRODUCT"
chmod 0755 "$app/Contents/MacOS/$PB_APP_PRODUCT"
printf 'APPL????' >"$app/Contents/PkgInfo"

sed -e "s/@VERSION@/${version}/g" \
    -e "s/@BUILD_NUMBER@/${build_number}/g" \
    -e "s/@YEAR@/${year}/g" \
    "$PB_REPO_ROOT/installer/app/Info.plist.in" >"$app/Contents/Info.plist"
if grep -q '@[A-Z_]*@' "$app/Contents/Info.plist"; then
    pb_die "Info.plist : placeholder non remplacé"
fi
/usr/bin/plutil -lint "$app/Contents/Info.plist" >/dev/null

# SwiftPM resource bundles (e.g. Parabellum_ParabellumKit.bundle).
# NB: SwiftPM's generated `Bundle.module` looks next to Bundle.main.bundleURL (the .app root), which
# codesign refuses; the app must resolve its bundles via Bundle.main.resourceURL instead.
shopt -s nullglob
bundles=("$bin_dir"/*.bundle)
shopt -u nullglob
# ${a[@]+...}: bash 3.2 (macOS /bin/bash) treats an empty array as unbound under set -u.
for b in ${bundles[@]+"${bundles[@]}"}; do
    case "$(basename "$b")" in
        *Tests.bundle | *Tests.xctest) continue ;; # test-only resources never ship
    esac
    pb_info "Ressources : $(basename "$b")"
    /usr/bin/ditto "$b" "$app/Contents/Resources/$(basename "$b")"
done

# Icon (best effort).
make_icon() {
    local png="$work/icon_1024.png" iconset="$work/AppIcon.iconset" s d
    swift "$PB_REPO_ROOT/installer/app/make-icon.swift" "$png" || return 1
    [[ -s "$png" ]] || return 1
    mkdir -p "$iconset" || return 1
    for s in 16 32 128 256 512; do
        d=$((s * 2))
        /usr/bin/sips -z "$s" "$s" "$png" --out "$iconset/icon_${s}x${s}.png" >/dev/null || return 1
        /usr/bin/sips -z "$d" "$d" "$png" --out "$iconset/icon_${s}x${s}@2x.png" >/dev/null || return 1
    done
    /usr/bin/iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns" || return 1
}
pb_info "Génération de l'icône"
if make_icon; then
    pb_ok "AppIcon.icns"
else
    pb_warn "icône non générée, l'app utilisera l'icône générique"
    rm -f "$app/Contents/Resources/AppIcon.icns"
    /usr/bin/plutil -remove CFBundleIconFile "$app/Contents/Info.plist" || true
fi

# Extended attributes (Finder info, quarantine…) make codesign fail.
/usr/bin/xattr -cr "$app" 2>/dev/null || true

# Signature (stable certificate or ad hoc), hardened runtime: nested Mach-O first (deepest first),
# then the bundle itself.
pb_resolve_sign_identity
main_exe="$app/Contents/MacOS/$PB_APP_PRODUCT"
nested=()
while IFS= read -r -d '' f; do
    [[ "$f" == "$main_exe" ]] && continue
    pb_is_macho "$f" && nested+=("$f")
done < <(find "$app/Contents" -type f -print0)
if ((${#nested[@]} > 0)); then
    while IFS= read -r f; do
        pb_info "  $(basename "$f")"
        pb_codesign "$f"
    done < <(printf '%s\n' "${nested[@]}" | awk -F/ '{ print NF "\t" $0 }' | sort -rn | cut -f2-)
fi
pb_codesign "$app"
/usr/bin/codesign --verify --deep --strict --verbose=2 "$app"
/usr/bin/codesign --display --verbose=2 "$app" 2>&1 | grep -E '^(Identifier|Authority|Signature|TeamIdentifier)' >&2 || true
pb_print_requirement "$app"

pb_ok "$app"
