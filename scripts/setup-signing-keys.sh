#!/usr/bin/env bash
# One-time setup (run on the owner's Mac): minisign key pair for the threat DB and the app releases.
#
# Usage: scripts/setup-signing-keys.sh [--force] [--repo OWNER/NAME]
#   - generates an UNENCRYPTED key pair (CI must sign unattended):
#       public  -> keys/parabellum-db.pub          (committed; embedded in the daemon at build time)
#       secret  -> ~/.parabellum/parabellum-db.key (never inside the repository)
#   - refuses to overwrite an existing secret key unless --force (rotation, see keys/README.md);
#   - if `gh` is installed and authenticated, stores the secret key as the MINISIGN_SECRET_KEY
#     repository secret (read from the file on stdin: never on the command line, never echoed).
set -euo pipefail

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
            sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
if [[ -e "$key" ]]; then
    backup="$key.$(date -u +%Y%m%dT%H%M%SZ).bak"
    mv "$key" "$backup"
    echo "ancienne clé secrète sauvegardée dans $backup"
fi
# -W: no password (CI signs unattended). -f: overwrite the public key file on rotation.
minisign -G -W -f -p "$pub" -s "$key"
chmod 600 "$key"
chmod 644 "$pub"
echo "==> clé publique : $pub"
echo "==> clé secrète  : $key (sauvegardez-la hors de ce Mac, p. ex. dans votre gestionnaire de mots de passe)"

secret_set=0
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    if gh secret set MINISIGN_SECRET_KEY --repo "$repo" <"$key"; then
        secret_set=1
        echo "==> secret MINISIGN_SECRET_KEY enregistré sur $repo"
    else
        echo "attention : échec de « gh secret set » ; faites-le à la main (étape 2 ci-dessous)." >&2
    fi
else
    echo "attention : gh absent ou non authentifié (« gh auth login ») : secret non enregistré." >&2
fi

cat <<NEXT

Étapes suivantes :
  1. Commitez la clé publique :   git add keys/parabellum-db.pub && git commit -m "keys: threat DB public key"
NEXT
if ((secret_set == 0)); then
    echo "  2. Enregistrez le secret :     gh secret set MINISIGN_SECRET_KEY --repo $repo < $key"
else
    echo "  2. (fait) secret MINISIGN_SECRET_KEY"
fi
cat <<NEXT
  3. Clé abuse.ch (gratuite, https://auth.abuse.ch/) :
                                  gh secret set ABUSECH_AUTH_KEY --repo $repo
  4. Lancez la base une première fois : gh workflow run nightly-db.yml --repo $repo
  5. Reconstruisez/réinstallez l'app (make pkg) : le daemon embarque la clé publique à la compilation.
NEXT
