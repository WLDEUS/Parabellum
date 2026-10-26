#!/usr/bin/env bash
# Create, once, the self-signed code-signing certificate "Parabellum Local Signing" on this Mac.
#
# Usage: scripts/setup-codesign-cert.sh [--force] [--no-secrets] [--repo <owner/repo>]
#   --force        replace an existing certificate (new identity: Full Disk Access must be granted again once)
#   --no-secrets   do not push the GitHub secrets MACOS_SIGN_P12 / MACOS_SIGN_P12_PASSWORD
#   --repo R       repository for the secrets (default: the one gh infers from this clone)
#
# Why: macOS (TCC) stores the Full Disk Access grant of parabellumd with its *designated requirement*.
# Ad hoc, that requirement is the cdhash of one exact build, so every update loses the grant. Signed by
# the same certificate, the requirement is `identifier "…" and certificate root = H"<cert hash>"`: it
# stays identical across rebuilds and updates, and the grant survives. Free: no Apple account needed.
#
# Steps: openssl key + certificate (EKU codeSigning, CA:false, digitalSignature, 10 years) ->
# password-protected .p12 in ~/.parabellum/ -> import into the login keychain (codesign allowed) ->
# trust for code signing only (macOS asks for your password) -> test signature -> GitHub secrets via gh.
# The private key never leaves ~/.parabellum/, the login keychain and (if pushed) the GitHub secrets.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

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
readonly P12_PASS_FILE="$OUT_DIR/parabellum-codesign.p12.password"
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
    if [[ ! -s "$P12" || ! -s "$P12_PASS_FILE" ]]; then
        pb_warn "$P12 ou son mot de passe absent : secrets GitHub non mis à jour (recréez avec --force)"
        return 0
    fi
    if ! command -v gh >/dev/null 2>&1; then
        pb_warn "gh absent : créez à la main les secrets MACOS_SIGN_P12 (= base64 -i \"$P12\") et MACOS_SIGN_P12_PASSWORD (= contenu de $P12_PASS_FILE)"
        return 0
    fi
    if ! gh auth status >/dev/null 2>&1; then
        pb_warn "gh n'est pas connecté (gh auth login) : secrets GitHub non mis à jour"
        return 0
    fi
    local args=()
    [[ -z "$repo" ]] || args+=(--repo "$repo")
    pb_info "Secrets GitHub MACOS_SIGN_P12 et MACOS_SIGN_P12_PASSWORD${repo:+ ($repo)}"
    # Values go through stdin, never through the command line.
    (cd "$PB_REPO_ROOT" && /usr/bin/base64 -i "$P12" | tr -d '\n' | gh secret set MACOS_SIGN_P12 ${args[@]+"${args[@]}"})
    (cd "$PB_REPO_ROOT" && gh secret set MACOS_SIGN_P12_PASSWORD ${args[@]+"${args[@]}"} <"$P12_PASS_FILE")
    pb_ok "secrets GitHub à jour : la CI signera avec ce certificat"
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

# 2. Password-protected .p12 in ~/.parabellum/ (0700 / 0600).
mkdir -p "$OUT_DIR"
chmod 0700 "$OUT_DIR"
(umask 077 && "$OPENSSL" rand -base64 48 | tr -d '\n/+=' | cut -c1-40 >"$work/pass")
[[ "$(wc -c <"$work/pass" | tr -d ' ')" -ge 32 ]] || pb_die "génération du mot de passe impossible"
# SHA1/3DES + SHA1 MAC: the PKCS#12 flavour every `security import` reads (OpenSSL 3 defaults do not).
(umask 077 && "$OPENSSL" pkcs12 -export -name "$PB_SIGN_CERT_NAME" -inkey "$work/key.pem" -in "$work/cert.pem" \
    -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 -passout "file:$work/pass" -out "$P12")
(umask 077 && tr -d '\n' <"$work/pass" >"$P12_PASS_FILE")
cp "$work/cert.pem" "$CERT_PEM"
chmod 0600 "$P12" "$P12_PASS_FILE"
chmod 0644 "$CERT_PEM"
pb_ok "$P12 (mot de passe : $P12_PASS_FILE)"

# 3. Import into the login keychain; codesign may use the key.
pb_info "Import dans le trousseau de session"
/usr/bin/security import "$P12" -k "$login_kc" -f pkcs12 -P "$(cat "$P12_PASS_FILE")" -T /usr/bin/codesign >/dev/null

# 4. Trust for code signing only (user trust settings).
pb_info "Approbation du certificat pour la signature de code."
pb_info "macOS va afficher une fenêtre « Vous apportez des modifications aux réglages de confiance » :"
pb_info "saisissez votre mot de passe de session. Cette confiance ne vaut que pour la signature de code."
if ! /usr/bin/security add-trusted-cert -r trustRoot -p codeSign -k "$login_kc" "$work/cert.pem"; then
    pb_warn "approbation refusée ou annulée. À faire à la main : Trousseaux d'accès > « $PB_SIGN_CERT_NAME » >" \
        "Se fier > Signature de code : Toujours approuver"
fi

# 5. Test signature (macOS may ask once whether codesign can use the key: answer « Toujours autoriser »).
hash="$(pb_find_sign_identity any "$login_kc")"
[[ -n "$hash" ]] || pb_die "identité introuvable après import (security find-identity -p codesigning)"
cp /usr/bin/true "$work/signtest"
pb_info "Signature de test (si macOS demande l'accès à la clé : « Toujours autoriser »)"
if /usr/bin/codesign --force --sign "$hash" --timestamp=none "$work/signtest" 2>"$work/sign.err"; then
    req="$(/usr/bin/codesign --display --requirements - "$work/signtest" 2>&1 | sed -n 's/^designated => //p')"
    pb_ok "signature de test OK, exigence désignée : $req"
else
    pb_warn "la signature de test a échoué : $(cat "$work/sign.err")"
fi
show_status

do_push_secrets

cat <<EOF

Certificat prêt. À partir de maintenant, make app / make pkg signent avec « $PB_SIGN_CERT_NAME ».
  - Installez un .pkg signé avec ce certificat, puis donnez UNE fois l'accès complet au disque à parabellumd :
    il sera conservé lors des mises à jour suivantes (même certificat = même exigence désignée).
  - Sauvegardez $OUT_DIR (hors du dépôt) : sans ce .p12, un nouveau certificat = accès à redonner une fois.
  - Validité : $VALID_DAYS jours ; pour le renouveler : scripts/setup-codesign-cert.sh --force
EOF
