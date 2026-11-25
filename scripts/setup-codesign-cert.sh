#!/usr/bin/env bash
# Create, once, the self-signed code-signing certificate "Parabellum Local Signing" on this Mac.
#
# Usage: scripts/setup-codesign-cert.sh [--force] [--no-secrets] [--repo <owner/repo>]
#   --force        replace an existing certificate (new identity: Full Disk Access must be granted again once)
#   --no-secrets   do not push the secrets MACOS_SIGN_P12 / MACOS_SIGN_P12_PASSWORD (environment codesign)
#   --repo R       repository for the secrets (default: the one gh infers from this clone)
#
# Why: macOS (TCC) stores the Full Disk Access grant of parabellumd with its *designated requirement*.
# Ad hoc, that requirement is the cdhash of one exact build, so every update loses the grant. Signed by
# the same certificate, the requirement is `identifier "…" and certificate root = H"<cert hash>"`: it
# stays identical across rebuilds and updates, and the grant survives. Free: no Apple account needed.
#
# Steps: openssl key + certificate (EKU codeSigning, CA:false, digitalSignature, 10 years) ->
# .p12 in ~/.parabellum/ protected by a password YOU type (kept in your password manager, never written to
# disk — audit APP-1) -> import into the login keychain as NON-extractable, with no application pre-allowed
# (macOS asks before codesign uses the key: answer « Autoriser », not « Toujours autoriser », so no other
# process can silently sign a binary that would inherit parabellumd's Full Disk Access) -> trust for code
# signing only (macOS asks for your password) -> test signature -> secrets of the GitHub environment
# `codesign` (tags v* only) via gh, values on stdin.
# Afterwards keep the .p12 + its password in your password manager and run scripts/secure-local-keys.sh
# purge: the private key then only lives in the login keychain and in the GitHub environment.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
# shellcheck source-path=SCRIPTDIR source=lib/keys.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/keys.sh"

usage() { pb_usage "${BASH_SOURCE[0]}"; }

force=0
push_secrets=1
repo=""
while (($# > 0)); do
    case "$1" in
        --force) force=1 ;;
        --no-secrets) push_secrets=0 ;;
        --repo)
            (($# >= 2)) || pb_die "--repo attend owner/repo"
            repo="$2"
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

[[ "$(uname -s)" == "Darwin" ]] || pb_die "à lancer sur le Mac (macOS), pas ici ($(uname -s))."
[[ "$(id -u)" != "0" ]] || pb_die "à lancer SANS sudo : le certificat va dans votre trousseau de session."
pb_require_cmds /usr/bin/security /usr/bin/openssl /usr/bin/base64 /usr/bin/codesign

readonly OPENSSL=/usr/bin/openssl # LibreSSL on macOS
readonly OUT_DIR="$HOME/.parabellum"
readonly P12="$OUT_DIR/parabellum-codesign.p12"
# Left by older versions of this script (plaintext password): removed here, see secure-local-keys.sh.
readonly LEGACY_PASS_FILE="$OUT_DIR/parabellum-codesign.p12.password"
p12_pass=""
readonly CERT_PEM="$OUT_DIR/parabellum-codesign.cer.pem"
readonly VALID_DAYS=3650

login_kc="$HOME/Library/Keychains/login.keychain-db"
if [[ ! -f "$login_kc" ]]; then
    login_kc="$(/usr/bin/security default-keychain -d user | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//')"
fi
[[ -f "$login_kc" ]] || pb_die "trousseau de session introuvable ($login_kc)"

# SHA-1 hashes of the certificates named $PB_SIGN_CERT_NAME in the login keychain.
existing_hashes() {
    /usr/bin/security find-certificate -a -c "$PB_SIGN_CERT_NAME" -Z "$login_kc" 2>/dev/null |
        awk '/^SHA-1 hash:/ { print $3 }'
}

do_push_secrets() {
    ((push_secrets == 1)) || return 0
    if [[ ! -s "$P12" ]]; then
        pb_warn "$P12 absent : secrets GitHub non mis à jour (restaurez-le depuis votre gestionnaire, ou --force)"
        return 0
    fi
    if ! command -v gh >/dev/null 2>&1; then
        pb_warn "gh absent : secrets MACOS_SIGN_P12 / MACOS_SIGN_P12_PASSWORD (environnement $PB_ENV_CODESIGN) non mis à jour"
        return 0
    fi
    if ! gh auth status >/dev/null 2>&1; then
        pb_warn "gh n'est pas connecté (gh auth login) : secrets GitHub non mis à jour"
        return 0
    fi
    local args=(--env "$PB_ENV_CODESIGN")
    [[ -z "$repo" ]] || args+=(--repo "$repo")
    [[ -n "$p12_pass" ]] || pb_read_password p12_pass "Mot de passe du .p12 (pour les secrets GitHub) : "
    printf '%s\n' "$p12_pass" | "$OPENSSL" pkcs12 -in "$P12" -noout -passin stdin 2>/dev/null ||
        pb_die "mot de passe du .p12 incorrect"
    pb_info "Secrets MACOS_SIGN_P12 et MACOS_SIGN_P12_PASSWORD de l'environnement $PB_ENV_CODESIGN${repo:+ ($repo)}"
    # Values go through stdin, never through the command line.
    (cd "$PB_REPO_ROOT" && /usr/bin/base64 -i "$P12" | tr -d '\n' | gh secret set MACOS_SIGN_P12 "${args[@]}")
    (cd "$PB_REPO_ROOT" && printf '%s' "$p12_pass" | gh secret set MACOS_SIGN_P12_PASSWORD "${args[@]}")
    pb_ok "secrets GitHub à jour : les releases (release.yml, job package) signeront avec ce certificat"
}

show_status() {
    local hash
    hash="$(pb_find_sign_identity valid "$login_kc")"
    if [[ -n "$hash" ]]; then
        pb_ok "identité de signature valide : $hash \"$PB_SIGN_CERT_NAME\""
    else
        pb_warn "identité présente mais non approuvée pour la signature de code. Trousseaux d'accès >" \
            "« $PB_SIGN_CERT_NAME » > Se fier > Signature de code : Toujours approuver"
    fi
}

hashes="$(existing_hashes)"
if [[ -n "$hashes" && $force -eq 0 ]]; then
    pb_info "Le certificat « $PB_SIGN_CERT_NAME » existe déjà dans $login_kc : rien à créer."
    pb_info "(--force en crée un nouveau, mais l'accès complet au disque devra alors être redonné une fois)"
    show_status
    do_push_secrets
    exit 0
fi

if [[ -n "$hashes" ]]; then
    pb_warn "remplacement du certificat existant : redonnez une fois l'accès complet au disque après la prochaine installation"
    while IFS= read -r h; do
        [[ -n "$h" ]] || continue
        /usr/bin/security delete-identity -Z "$h" "$login_kc" >/dev/null 2>&1 ||
            /usr/bin/security delete-certificate -Z "$h" "$login_kc" >/dev/null 2>&1 ||
            pb_warn "impossible de supprimer l'ancien certificat $h (Trousseaux d'accès)"
    done <<<"$hashes"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/parabellum-cert.XXXXXX")"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
chmod 0700 "$work"

# 1. Key + self-signed certificate restricted to code signing.
cat >"$work/openssl.cnf" <<EOF
[ req ]
distinguished_name = dn
prompt = no
x509_extensions = v3_codesign

[ dn ]
CN = $PB_SIGN_CERT_NAME
O = Parabellum (signature locale)

[ v3_codesign ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
subjectKeyIdentifier = hash
EOF

pb_info "Création de la clé et du certificat (RSA 2048, $VALID_DAYS jours)"
(umask 077 && "$OPENSSL" req -x509 -newkey rsa:2048 -sha256 -days "$VALID_DAYS" -nodes \
    -config "$work/openssl.cnf" -keyout "$work/key.pem" -out "$work/cert.pem" 2>/dev/null)
"$OPENSSL" x509 -in "$work/cert.pem" -noout -text | grep -q 'Code Signing' ||
    pb_die "le certificat généré n'a pas l'usage « Code Signing »"

# 2. .p12 in ~/.parabellum/ (0700 / 0600), protected by a password typed here (never written to disk).
mkdir -p "$OUT_DIR"
chmod 0700 "$OUT_DIR"
pb_info "Choisissez le mot de passe du .p12 et gardez-le dans votre gestionnaire de mots de passe."
pb_read_new_password p12_pass
# SHA1/3DES + SHA1 MAC: the PKCS#12 flavour every `security import` reads (OpenSSL 3 defaults do not).
(umask 077 && printf '%s\n' "$p12_pass" | "$OPENSSL" pkcs12 -export -name "$PB_SIGN_CERT_NAME" \
    -inkey "$work/key.pem" -in "$work/cert.pem" -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
    -passout stdin -out "$P12")
rm -f "$work/key.pem" "$LEGACY_PASS_FILE"
cp "$work/cert.pem" "$CERT_PEM"
chmod 0600 "$P12"
chmod 0644 "$CERT_PEM"
pb_ok "$P12 (mot de passe : celui que vous venez de choisir, nulle part sur le disque)"

# 3. Import into the login keychain: non-extractable (-x), no application pre-authorised (no -T): macOS
#    asks before codesign uses the key (audit APP-1).
pb_info "Import dans le trousseau de session"
/usr/bin/security import "$P12" -k "$login_kc" -f pkcs12 -x -P "$p12_pass" >/dev/null

# 4. Trust for code signing only (user trust settings).
pb_info "Approbation du certificat pour la signature de code."
pb_info "macOS va afficher une fenêtre « Vous apportez des modifications aux réglages de confiance » :"
pb_info "saisissez votre mot de passe de session. Cette confiance ne vaut que pour la signature de code."
if ! /usr/bin/security add-trusted-cert -r trustRoot -p codeSign -k "$login_kc" "$work/cert.pem"; then
    pb_warn "approbation refusée ou annulée. À faire à la main : Trousseaux d'accès > « $PB_SIGN_CERT_NAME » >" \
        "Se fier > Signature de code : Toujours approuver"
fi

# 5. Test signature (macOS asks whether codesign can use the key: answer « Autoriser » with your session
#    password; « Toujours autoriser » would let any process run codesign with it silently).
hash="$(pb_find_sign_identity any "$login_kc")"
[[ -n "$hash" ]] || pb_die "identité introuvable après import (security find-identity -p codesigning)"
cp /usr/bin/true "$work/signtest"
pb_info "Signature de test (macOS demande l'accès à la clé : « Autoriser », pas « Toujours autoriser »)"
if /usr/bin/codesign --force --sign "$hash" --timestamp=none "$work/signtest" 2>"$work/sign.err"; then
    req="$(/usr/bin/codesign --display --requirements - "$work/signtest" 2>&1 | sed -n 's/^designated => //p')"
    pb_ok "signature de test OK, exigence désignée : $req"
else
    pb_warn "la signature de test a échoué : $(cat "$work/sign.err")"
fi
show_status

do_push_secrets
p12_pass=""

cat <<EOF

Certificat prêt. À partir de maintenant, make app / make pkg signent avec « $PB_SIGN_CERT_NAME ».
  - Installez un .pkg signé avec ce certificat, puis donnez UNE fois l'accès complet au disque à parabellumd :
    il sera conservé lors des mises à jour suivantes (même certificat = même exigence désignée).
  - Sauvegardez $P12 et son mot de passe dans votre gestionnaire (sans ce .p12, un nouveau certificat
    = accès à redonner une fois), puis : scripts/secure-local-keys.sh purge
  - make pkg demandera l'accès à la clé à chaque signature : répondez « Autoriser ».
  - Validité : $VALID_DAYS jours ; pour le renouveler : scripts/setup-codesign-cert.sh --force
EOF
