#!/usr/bin/env bash
# One-time setup (run on the owner's Mac): a minisign key pair dedicated to the Parabellum `.pkg` releases.
#
# Why a second key: the threat-DB key is handed to the nightly job, which downloads untrusted feeds and
# malware samples. If that job were ever compromised, the stolen DB key must not be able to sign an
# installer that the daemon runs as root. With this key in place the daemon only accepts `.pkg`
# self-updates signed by it (crates/pb-updater/build.rs, `release_public_key`).
#
# Usage: scripts/setup-release-key.sh [--force] [--repo OWNER/NAME] [--no-commit]
#   public  -> keys/parabellum-release.pub          (committed; embedded in the daemon at build time)
#   secret  -> ~/.parabellum/parabellum-release.key (never inside the repository)
#   + repository secret MINISIGN_RELEASE_SECRET_KEY (via `gh`, read from the file on stdin) and a commit
#   of the public key (unless --no-commit). Then: git push, and `make pkg && make install` once.
set -euo pipefail

repo="WLDEUS/Parabellum"
force=0
commit=1
while (($# > 0)); do
    case "$1" in
        --force) force=1 ;;
        --no-commit) commit=0 ;;
        --repo)
            repo="${2:?--repo needs OWNER/NAME}"
            shift
            ;;
        -h | --help)
            sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
pub="$repo_root/keys/parabellum-release.pub"
key_dir="$HOME/.parabellum"
key="$key_dir/parabellum-release.key"

command -v minisign >/dev/null 2>&1 || { echo "minisign introuvable : brew install minisign" >&2; exit 1; }
case "$key" in
    "$repo_root"/*)
        echo "erreur : la clé secrète ne doit jamais être dans le dépôt ($key)" >&2
        exit 1
        ;;
esac
if [[ -e "$key" && $force -ne 1 ]]; then
    echo "erreur : $key existe déjà (--force pour une rotation)." >&2
    exit 1
fi

umask 077
mkdir -p "$key_dir" "$(dirname "$pub")"
chmod 700 "$key_dir"
if [[ -e "$key" ]]; then
    mv "$key" "$key.$(date -u +%Y%m%dT%H%M%SZ).bak"
fi
minisign -G -W -f -p "$pub" -s "$key"
chmod 600 "$key"
chmod 644 "$pub"
echo "==> clé publique : $pub"
echo "==> clé secrète  : $key (sauvegardez-la hors de ce Mac, p. ex. dans votre gestionnaire de mots de passe)"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    gh secret set MINISIGN_RELEASE_SECRET_KEY --repo "$repo" <"$key"
    echo "==> secret MINISIGN_RELEASE_SECRET_KEY enregistré sur $repo"
else
    echo "attention : gh absent ou non authentifié. À faire : gh secret set MINISIGN_RELEASE_SECRET_KEY --repo $repo < $key" >&2
fi

if ((commit)); then
    git -C "$repo_root" add keys/parabellum-release.pub
    git -C "$repo_root" commit -q -m "keys: dedicated release signing key" -- keys/parabellum-release.pub
    echo "==> clé publique commitée : poussez (git push), puis make pkg && make install une fois."
fi
