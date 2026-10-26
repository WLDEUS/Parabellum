#!/usr/bin/env bash
# Build dist/Parabellum-<version>.pkg (unsigned product archive; binaries signed with the stable
# "Parabellum Local Signing" certificate when available, ad hoc otherwise).
#
# Usage: scripts/build-pkg.sh [--skip-build]
#   --skip-build   reuse target/aarch64-apple-darwin/release/{parabellumd,parabellum} and the existing
#                  SwiftPM build (the .app is still re-assembled and re-signed)
#
# Env: PARABELLUM_DB_PUBKEY   minisign public key embedded by pb-updater (else keys/parabellum-db.pub)
#      ALLOW_MISSING_PUBKEY=1 build anyway without a DB public key (DB updates will be rejected)
#      CARGO_TARGET_DIR       honoured when locating the Rust binaries
#      PARABELLUM_SIGN_IDENTITY  signing identity (name or SHA-1, "-" = ad hoc); default: the
#                             "Parabellum Local Signing" certificate if found (make codesign-cert)
#      PARABELLUM_SIGN_KEYCHAIN  keychain holding that identity (CI temporary keychain)
#
# Payload (installed on /):
#   /Applications/Parabellum.app
#   /Library/Application Support/Parabellum/bin/{parabellumd,parabellum,uninstall.sh,restore-dns.sh}
#   /Library/LaunchDaemons/com.wldeus.parabellum.daemon.plist
#   /Library/LaunchAgents/com.wldeus.parabellum.ui.plist
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() { pb_usage "${BASH_SOURCE[0]}"; }

skip_build=0
while (($# > 0)); do
    case "$1" in
        --skip-build) skip_build=1 ;;
        -h | --help)
            usage
            exit 0
            ;;
        *) pb_die "option inconnue : $1 (voir --help)" ;;
    esac
    shift
done

pb_require_macos_arm64
pb_require_cmds cargo swift /usr/bin/pkgbuild /usr/bin/productbuild /usr/bin/codesign /usr/bin/security /usr/bin/plutil \
    /usr/bin/lipo /usr/bin/ditto /usr/bin/shasum /usr/sbin/pkgutil

version="$(pb_version)"
dist="$PB_REPO_ROOT/dist"
installer_dir="$PB_REPO_ROOT/installer"
target_dir="${CARGO_TARGET_DIR:-$PB_REPO_ROOT/target}"
rust_out="$target_dir/$PB_RUST_TARGET/release"
out_pkg="$dist/Parabellum-$version.pkg"

# Signing identity, resolved once and handed to build-app.sh (no second lookup, no duplicate warning).
pb_resolve_sign_identity
export PARABELLUM_SIGN_IDENTITY="$PB_SIGN_IDENTITY"

# 1. Build.
if ((skip_build == 0)); then
    if [[ -z "${PARABELLUM_DB_PUBKEY:-}" && ! -s "$PB_REPO_ROOT/keys/parabellum-db.pub" ]]; then
        if [[ "${ALLOW_MISSING_PUBKEY:-0}" == "1" ]]; then
            pb_warn "aucune clé publique minisign : le client refusera toute base de menaces"
        else
            pb_die "clé publique de la base absente (keys/parabellum-db.pub ou PARABELLUM_DB_PUBKEY) : lancez « make keys » (ou ALLOW_MISSING_PUBKEY=1)"
        fi
    fi
    if ! rustup target list --installed 2>/dev/null | grep -qx "$PB_RUST_TARGET"; then
        pb_info "rustup target add $PB_RUST_TARGET"
        rustup target add "$PB_RUST_TARGET"
    fi
    pb_info "cargo build --release --target $PB_RUST_TARGET -p pb-daemon -p pb-cli"
    (cd "$PB_REPO_ROOT" && MACOSX_DEPLOYMENT_TARGET=14.0 cargo build --locked --release \
        --target "$PB_RUST_TARGET" -p pb-daemon -p pb-cli)
    "$PB_REPO_ROOT/scripts/build-app.sh"
else
    "$PB_REPO_ROOT/scripts/build-app.sh" --skip-build
fi

for b in parabellumd parabellum; do
    [[ -x "$rust_out/$b" ]] || pb_die "binaire introuvable : $rust_out/$b (lancez sans --skip-build)"
    archs="$(/usr/bin/lipo -archs "$rust_out/$b")"
    [[ " $archs " == *" arm64 "* ]] || pb_die "$rust_out/$b n'est pas arm64 ($archs)"
done
[[ -d "$dist/Parabellum.app" ]] || pb_die "$dist/Parabellum.app introuvable"

# 2. Stage the payload.
stage="$(mktemp -d "${TMPDIR:-/tmp}/parabellum-pkg.XXXXXX")"
cleanup() { rm -rf "$stage"; }
trap cleanup EXIT

root="$stage/root"
bin="$root/Library/Application Support/Parabellum/bin"
mkdir -p "$root/Applications" "$bin" "$root/Library/LaunchDaemons" "$root/Library/LaunchAgents" \
    "$stage/pkgs" "$stage/scripts"
chmod 0755 "$root" "$root/Library" "$root/Library/Application Support" \
    "$root/Library/Application Support/Parabellum" "$bin" "$root/Library/LaunchDaemons" "$root/Library/LaunchAgents"
chmod 0775 "$root/Applications"

pb_info "Payload : Parabellum.app"
/usr/bin/ditto "$dist/Parabellum.app" "$root/Applications/Parabellum.app"
/usr/bin/codesign --verify --deep --strict "$root/Applications/Parabellum.app"

pb_info "Payload : binaires (hardened runtime)"
install -m 0755 "$rust_out/parabellumd" "$bin/parabellumd"
install -m 0755 "$rust_out/parabellum" "$bin/parabellum"
# parabellumd: YARA-X runs rules through wasmtime, which needs executable memory (see the plist).
pb_sign_binary "$bin/parabellumd" "$PB_DAEMON_SIGN_ID" "$installer_dir/entitlements/parabellumd.entitlements"
pb_sign_binary "$bin/parabellum" "$PB_CLI_SIGN_ID"
install -m 0755 "$PB_REPO_ROOT/scripts/uninstall.sh" "$bin/uninstall.sh"
install -m 0755 "$PB_REPO_ROOT/scripts/restore-dns.sh" "$bin/restore-dns.sh"

pb_info "Payload : LaunchDaemon + LaunchAgent"
install -m 0644 "$installer_dir/launchd/$PB_DAEMON_LABEL.plist" "$root/Library/LaunchDaemons/$PB_DAEMON_LABEL.plist"
install -m 0644 "$installer_dir/launchd/$PB_UI_AGENT_LABEL.plist" "$root/Library/LaunchAgents/$PB_UI_AGENT_LABEL.plist"
/usr/bin/plutil -lint "$root/Library/LaunchDaemons/$PB_DAEMON_LABEL.plist" \
    "$root/Library/LaunchAgents/$PB_UI_AGENT_LABEL.plist" >/dev/null

find "$root" -name .DS_Store -delete
/usr/bin/xattr -cr "$root" 2>/dev/null || true

install -m 0755 "$installer_dir/scripts/preinstall" "$stage/scripts/preinstall"
install -m 0755 "$installer_dir/scripts/postinstall" "$stage/scripts/postinstall"

# 3. Component package: the app must always land in /Applications and always be replaced.
comp="$stage/component.plist"
/usr/bin/pkgbuild --analyze --root "$root" "$comp" >/dev/null
i=0
while /usr/bin/plutil -extract "$i" xml1 -o /dev/null "$comp" >/dev/null 2>&1; do
    /usr/bin/plutil -replace "$i.BundleIsRelocatable" -bool NO "$comp"
    /usr/bin/plutil -replace "$i.BundleIsVersionChecked" -bool NO "$comp"
    /usr/bin/plutil -replace "$i.BundleOverwriteAction" -string upgrade "$comp"
    i=$((i + 1))
done
((i > 0)) || pb_die "pkgbuild --analyze n'a trouvé aucun bundle dans le payload"

pb_info "pkgbuild ($PB_PKG_ID $version)"
/usr/bin/pkgbuild --root "$root" \
    --component-plist "$comp" \
    --scripts "$stage/scripts" \
    --identifier "$PB_PKG_ID" \
    --version "$version" \
    --install-location / \
    --ownership recommended \
    "$stage/pkgs/Parabellum-component.pkg"

# Sanity check of the payload (paths normalised without a leading "./" or "/").
payload="$(/usr/sbin/pkgutil --payload-files "$stage/pkgs/Parabellum-component.pkg" | sed -e 's#^\./##' -e 's#^/##')"
for expected in \
    "Applications/Parabellum.app/Contents/MacOS/$PB_APP_PRODUCT" \
    "Library/Application Support/Parabellum/bin/parabellumd" \
    "Library/Application Support/Parabellum/bin/parabellum" \
    "Library/Application Support/Parabellum/bin/uninstall.sh" \
    "Library/Application Support/Parabellum/bin/restore-dns.sh" \
    "Library/LaunchDaemons/$PB_DAEMON_LABEL.plist" \
    "Library/LaunchAgents/$PB_UI_AGENT_LABEL.plist"; do
    grep -Fqx "$expected" <<<"$payload" || pb_die "payload incomplet : $expected manquant"
done

# 4. Product archive.
sed -e "s/@VERSION@/${version}/g" "$installer_dir/distribution.xml" >"$stage/distribution.xml"
if command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "$stage/distribution.xml"
fi
/usr/bin/ditto "$installer_dir/resources" "$stage/resources"
[[ -d "$stage/resources/en.lproj" ]] || /usr/bin/ditto "$stage/resources/fr.lproj" "$stage/resources/en.lproj"

mkdir -p "$dist"
rm -f "$out_pkg" "$out_pkg.sha256"
pb_info "productbuild -> $out_pkg"
/usr/bin/productbuild --distribution "$stage/distribution.xml" \
    --resources "$stage/resources" \
    --package-path "$stage/pkgs" \
    "$out_pkg"

(cd "$dist" && /usr/bin/shasum -a 256 "$(basename "$out_pkg")" >"$(basename "$out_pkg").sha256")
sha="$(cut -d ' ' -f1 <"$out_pkg.sha256")"
size="$(du -h "$out_pkg" | cut -f1)"

pb_ok "$out_pkg ($size)"
printf 'SHA-256  %s\n' "$sha"
if [[ "$PB_SIGN_IDENTITY" == "-" ]]; then
    printf 'Signature : ad hoc (accès complet au disque à redonner après installation)\n'
else
    printf 'Signature : %s (accès complet au disque conservé entre versions)\n' "$PB_SIGN_IDENTITY"
fi
printf 'Installer : sudo installer -pkg "%s" -target /\n' "$out_pkg"
