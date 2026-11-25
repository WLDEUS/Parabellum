#!/usr/bin/env bash
# One-time setup (run on the owner's Mac): minisign key pair for the threat DB and the app releases.
#
# Usage: scripts/setup-signing-keys.sh [--force] [--repo OWNER/NAME]
#   - generates a PASSWORD-PROTECTED key pair (audit SC-2; the password is typed twice, never shown):
#       public  -> keys/parabellum-db.pub          (committed; embedded in the daemon at build time)
#       secret  -> ~/.parabellum/parabellum-db.key (never inside the repository; encrypted with scrypt)
#   - refuses to overwrite an existing secret key unless --force (rotation, see keys/README.md); on
#     rotation the old secret key is deleted, not kept as a .bak;
#   - if `gh` is installed and authenticated, stores the secret key and its password as secrets of the
#     GitHub environment `db-signing` (branch main only, scripts/protect-repo.sh): MINISIGN_SECRET_KEY and
#     MINISIGN_KEY_PASSWORD, both read on stdin (never on the command line, never echoed).
#   Then keep the key file and its password in your password manager and run
#   scripts/secure-local-keys.sh purge: no plaintext signing material stays on this Mac.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/keys.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/keys.sh"

repo="WLDEUS/Parabellum"
force=0
while (($# > 0)); do
    case "$1" in
        --force) force=1 ;;
        --repo)
            repo="${2:?--repo needs OWNER/NAME}"
            shift
            ;;
        -h | --help)
            sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "erreur : option inconnue : $1" >&2
            exit 2
            ;;
    esac
    shift
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
pub="$repo_root/keys/parabellum-db.pub"
key_dir="$HOME/.parabellum"
key="$key_dir/parabellum-db.key"

if ! command -v minisign >/dev/null 2>&1; then
    echo "minisign est introuvable."
    if command -v brew >/dev/null 2>&1; then
        read -r -p "L'installer avec « brew install minisign » ? [o/N] " answer
        if [[ "$answer" =~ ^[oOyY]$ ]]; then
            brew install minisign
        else
            exit 1
        fi
    else
        echo "Installez Homebrew puis « brew install minisign » (ou https://github.com/jedisct1/minisign/releases)." >&2
        exit 1
    fi
fi

case "$key" in
    "$repo_root"/*)
        echo "erreur : la clé secrète ne doit jamais être dans le dépôt ($key)" >&2
        exit 1
        ;;
esac

if [[ -e "$key" && $force -ne 1 ]]; then
    echo "erreur : $key existe déjà. Relancez avec --force pour faire une rotation de clé (voir keys/README.md)." >&2
    exit 1
fi

mkdir -p "$(dirname "$pub")"
umask 077
mkdir -p "$key_dir"
chmod 700 "$key_dir"
password=""
pb_read_new_password password
tmp_key="$key.new"
rm -f "$tmp_key"
# Password on stdin (twice: minisign asks for a confirmation). -f: overwrite the public key on rotation.
printf '%s\n%s\n' "$password" "$password" | minisign -G -f -p "$pub" -s "$tmp_key" >/dev/null
pb_minisign_matches "$tmp_key" "$pub" "$password" || { echo "erreur : la nouvelle clé ne signe pas" >&2; exit 1; }
# Rotation: the old secret key is replaced, not kept around (audit SC-2). Back it up first if needed.
mv -f "$tmp_key" "$key"
chmod 600 "$key"
chmod 644 "$pub"
echo "==> clé publique : $pub"
echo "==> clé secrète  : $key (chiffrée ; gardez ce fichier ET son mot de passe dans votre gestionnaire)"

secret_set=0
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if ! pb_gh_env_exists "$repo" "$PB_ENV_DB"; then
        echo "attention : environnement $PB_ENV_DB absent : lancez d'abord scripts/protect-repo.sh" >&2
    elif pb_gh_env_secret "$repo" "$PB_ENV_DB" MINISIGN_SECRET_KEY <"$key" &&
        printf '%s' "$password" | pb_gh_env_secret "$repo" "$PB_ENV_DB" MINISIGN_KEY_PASSWORD; then
        secret_set=1
        echo "==> secrets MINISIGN_SECRET_KEY + MINISIGN_KEY_PASSWORD enregistrés dans l'environnement $PB_ENV_DB"
    else
        echo "attention : échec de « gh secret set » ; faites-le à la main (étape 2 ci-dessous)." >&2
    fi
else
    echo "attention : gh absent ou non authentifié (« gh auth login ») : secrets non enregistrés." >&2
fi
unset password

cat <<NEXT

Étapes suivantes :
  1. Commitez la clé publique :   git add keys/parabellum-db.pub && git commit -m "keys: threat DB public key"
NEXT
if ((secret_set == 0)); then
    echo "  2. Enregistrez les secrets :   scripts/protect-repo.sh puis scripts/secure-local-keys.sh migrate"
else
    echo "  2. (fait) secrets de l'environnement $PB_ENV_DB"
fi
cat <<NEXT
  3. Clé abuse.ch (gratuite, https://auth.abuse.ch/) :
                                  gh secret set ABUSECH_AUTH_KEY --repo $repo
  4. Lancez la base une première fois : gh workflow run nightly-db.yml --repo $repo
  5. Reconstruisez/réinstallez l'app (make pkg) : le daemon embarque la clé publique à la compilation.
  6. Sauvegardez $key et son mot de passe hors de ce Mac, puis : scripts/secure-local-keys.sh purge
NEXT
