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
#   secret  -> ~/.parabellum/parabellum-release.key (never inside the repository; password-protected,
#              the password is typed twice and never shown — audit SC-2)
#   + secrets MINISIGN_RELEASE_SECRET_KEY and MINISIGN_RELEASE_KEY_PASSWORD of the GitHub environment
#   `release` (tags v* only, required reviewer — scripts/protect-repo.sh), read on stdin, and a commit
#   of the public key (unless --no-commit). Then: git push, and `make pkg && make install` once.
#   On rotation (--force) the old secret key is replaced, not kept as a .bak. Keep the key file and its
#   password in your password manager, then run scripts/secure-local-keys.sh purge.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/keys.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/keys.sh"

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
            sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
password=""
pb_read_new_password password
tmp_key="$key.new"
rm -f "$tmp_key"
printf '%s\n%s\n' "$password" "$password" | minisign -G -f -p "$pub" -s "$tmp_key" >/dev/null
pb_minisign_matches "$tmp_key" "$pub" "$password" || { echo "erreur : la nouvelle clé ne signe pas" >&2; exit 1; }
mv -f "$tmp_key" "$key"
chmod 600 "$key"
chmod 644 "$pub"
echo "==> clé publique : $pub"
echo "==> clé secrète  : $key (chiffrée ; gardez ce fichier ET son mot de passe dans votre gestionnaire)"

if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1 && pb_gh_env_exists "$repo" "$PB_ENV_RELEASE"; then
    pb_gh_env_secret "$repo" "$PB_ENV_RELEASE" MINISIGN_RELEASE_SECRET_KEY <"$key"
    printf '%s' "$password" | pb_gh_env_secret "$repo" "$PB_ENV_RELEASE" MINISIGN_RELEASE_KEY_PASSWORD
    echo "==> secrets MINISIGN_RELEASE_SECRET_KEY + MINISIGN_RELEASE_KEY_PASSWORD enregistrés dans l'environnement $PB_ENV_RELEASE"
else
    echo "attention : gh absent / non authentifié ou environnement $PB_ENV_RELEASE absent." >&2
    echo "  À faire : scripts/protect-repo.sh puis scripts/secure-local-keys.sh migrate" >&2
fi
unset password

if ((commit)); then
    git -C "$repo_root" add keys/parabellum-release.pub
    git -C "$repo_root" commit -q -m "keys: dedicated release signing key" -- keys/parabellum-release.pub
    echo "==> clé publique commitée : poussez (git push), puis make pkg && make install une fois."
fi
