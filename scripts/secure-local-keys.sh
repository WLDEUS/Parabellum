#!/usr/bin/env bash
# Inventory and clean up the signing material kept on this Mac in ~/.parabellum (audit SC-2 / APP-1).
#
# Usage: scripts/secure-local-keys.sh [status|encrypt|migrate|purge] [--repo OWNER/NAME] [--yes]
#   status   (default) what is in ~/.parabellum: minisign keys (password-protected or not), .bak copies,
#            .p12 and plaintext password files; where the GitHub secrets live (repository or environment).
#            Prints names and states only, never a secret.
#   encrypt  add a password to every plaintext minisign key (`minisign -C`: the public key does not
#            change, no client rebuild). The password is typed twice; keep it in your password manager.
#   migrate  copy the keys and their passwords into the GitHub environments created by
#            scripts/protect-repo.sh (db-signing, release, codesign), check each key against the committed
#            public key first, then delete the repository-level copies of those secrets.
#   purge    after you saved the key files and passwords in your password manager: delete every secret
#            key, .bak copy, .p12 and password file from ~/.parabellum (asks for confirmation unless
#            --yes). Refused while a committed public key is missing or an environment lacks its secret.
#
# A key that only exists as a repository secret (no local file) cannot be moved: GitHub never gives a
# secret back. Rotate it then (setup-signing-keys.sh / setup-release-key.sh --force, new client build).
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=lib/keys.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/keys.sh"

cmd="status"
repo="WLDEUS/Parabellum"
yes=0
while (($# > 0)); do
    case "$1" in
        status | encrypt | migrate | purge) cmd="$1" ;;
        --repo)
            repo="${2:?--repo needs OWNER/NAME}"
            shift
            ;;
        --yes) yes=1 ;;
        -h | --help)
            sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
dir="$HOME/.parabellum"
db_key="$dir/parabellum-db.key"
rel_key="$dir/parabellum-release.key"
p12="$dir/parabellum-codesign.p12"
p12_pass_file="$dir/parabellum-codesign.p12.password"
db_pub="$repo_root/keys/parabellum-db.pub"
rel_pub="$repo_root/keys/parabellum-release.pub"

have_gh() { command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; }

# Secret names of the repository (no environment) or of one environment.
secret_names() {
    if [[ -z "${1:-}" ]]; then
        gh secret list --repo "$repo" --json name --jq '.[].name' 2>/dev/null || true
    else
        gh secret list --repo "$repo" --env "$1" --json name --jq '.[].name' 2>/dev/null || true
    fi
}

# Every file of ~/.parabellum that holds secret material.
secret_files() {
    [[ -d "$dir" ]] || return 0
    find "$dir" -maxdepth 1 \( -type f -o -type l \) \( -name '*.key' -o -name '*.key.*' -o -name '*.p12' \
        -o -name '*.p12.*' -o -name '*.password' \) -print | sort
}

status() {
    echo "== $dir"
    if [[ ! -d "$dir" ]]; then
        echo "   (absent)"
    else
        local f state mode found=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            found=1
            if [[ "$(uname -s)" == Darwin ]]; then mode="$(stat -f '%Lp' "$f")"; else mode="$(stat -c '%a' "$f")"; fi
            case "$f" in
                *.password) state="MOT DE PASSE EN CLAIR (à supprimer : purge)" ;;
                *.bak | *.new) state="copie résiduelle (à supprimer : purge)" ;;
                *.p12) state="identité de signature de code (chiffrée par son mot de passe)" ;;
                *) state="clé minisign $(pb_minisign_key_state "$f")" ;;
            esac
            [[ "$state" == *plaintext* ]] && state="$state — SANS MOT DE PASSE (encrypt)"
            printf '   %-44s %s  (mode %s)\n' "$(basename "$f")" "$state" "$mode"
        done < <(secret_files)
        ((found)) || echo "   aucun secret local"
    fi
    echo "== clés publiques commitées"
    local p
    for p in "$db_pub" "$rel_pub"; do
        if [[ -s "$p" ]]; then echo "   ok   ${p#"$repo_root"/}"; else echo "   MANQUE ${p#"$repo_root"/}"; fi
    done
    if have_gh; then
        echo "== secrets GitHub ($repo)"
        local names e
        names="$(secret_names | tr '\n' ' ')"
        echo "   dépôt (visibles par tout workflow) : ${names:-aucun}"
        for e in "$PB_ENV_DB" "$PB_ENV_RELEASE" "$PB_ENV_CODESIGN"; do
            if pb_gh_env_exists "$repo" "$e"; then
                names="$(secret_names "$e" | tr '\n' ' ')"
                echo "   environnement $e : ${names:-aucun}"
            else
                echo "   environnement $e : ABSENT (scripts/protect-repo.sh)"
            fi
        done
    else
        echo "== secrets GitHub : gh absent ou non authentifié"
    fi
}

encrypt() {
    command -v minisign >/dev/null 2>&1 || { echo "minisign introuvable : brew install minisign" >&2; exit 1; }
    local k pub pw done_any=0
    for k in "$db_key" "$rel_key"; do
        [[ -f "$k" && ! -L "$k" ]] || continue
        [[ "$(pb_minisign_key_state "$k")" == plaintext ]] || { echo "$(basename "$k") : déjà protégée"; continue; }
        pub="$db_pub"
        [[ "$k" == "$rel_key" ]] && pub="$rel_pub"
        pb_minisign_matches "$k" "$pub" "" || { echo "erreur : $(basename "$k") ne correspond pas à ${pub#"$repo_root"/}" >&2; exit 1; }
        echo "== $(basename "$k")"
        pw=""
        pb_read_new_password pw
        cp -p "$k" "$k.new"
        # An unencrypted key asks for no current password: only the new one, twice.
        printf '%s\n%s\n' "$pw" "$pw" | minisign -C -s "$k.new" >/dev/null
        if [[ "$(pb_minisign_key_state "$k.new")" != encrypted ]] || ! pb_minisign_matches "$k.new" "$pub" "$pw"; then
            rm -f "$k.new"
            echo "erreur : chiffrement de $(basename "$k") non vérifié, clé inchangée" >&2
            exit 1
        fi
        mv -f "$k.new" "$k"
        chmod 600 "$k"
        pw=""
        done_any=1
        echo "   protégée par mot de passe (clé publique inchangée)"
    done
    ((done_any)) || echo "rien à chiffrer"
    echo "Ensuite : scripts/secure-local-keys.sh migrate"
}

# migrate_key <key> <pub> <environment> <key secret> <password secret> <repo-level names to delete...>
migrate_key() {
    local key="$1" pub="$2" env="$3" s_key="$4" s_pw="$5" pw
    shift 5
    if [[ ! -f "$key" ]]; then
        echo "   $(basename "$key") absente : rien à migrer (si la clé n'existe plus qu'en secret GitHub, faites une rotation)"
        return 0
    fi
    if [[ "$(pb_minisign_key_state "$key")" != encrypted ]]; then
        echo "erreur : $(basename "$key") n'a pas de mot de passe : lancez d'abord « encrypt »" >&2
        exit 1
    fi
    pw=""
    pb_read_password pw "Mot de passe de $(basename "$key") : "
    pb_minisign_matches "$key" "$pub" "$pw" || { echo "erreur : mot de passe faux ou clé ≠ ${pub#"$repo_root"/}" >&2; exit 1; }
    pb_gh_env_secret "$repo" "$env" "$s_key" <"$key"
    printf '%s' "$pw" | pb_gh_env_secret "$repo" "$env" "$s_pw"
    pw=""
    echo "   $s_key + $s_pw -> environnement $env"
    local n repo_names
    repo_names="$(secret_names)"
    for n in "$@"; do
        if grep -qxF -- "$n" <<<"$repo_names"; then
            gh secret delete "$n" --repo "$repo"
            echo "   secret de dépôt $n supprimé"
        fi
    done
}

migrate() {
    have_gh || { echo "erreur : gh absent ou non authentifié (gh auth login)" >&2; exit 1; }
    command -v minisign >/dev/null 2>&1 || { echo "minisign introuvable : brew install minisign" >&2; exit 1; }
    local e
    for e in "$PB_ENV_DB" "$PB_ENV_RELEASE" "$PB_ENV_CODESIGN"; do
        pb_gh_env_exists "$repo" "$e" || { echo "erreur : environnement $e absent : scripts/protect-repo.sh" >&2; exit 1; }
    done
    echo "== clé de la base -> $PB_ENV_DB"
    migrate_key "$db_key" "$db_pub" "$PB_ENV_DB" MINISIGN_SECRET_KEY MINISIGN_KEY_PASSWORD MINISIGN_SECRET_KEY
    echo "== clé des releases -> $PB_ENV_RELEASE"
    migrate_key "$rel_key" "$rel_pub" "$PB_ENV_RELEASE" MINISIGN_RELEASE_SECRET_KEY MINISIGN_RELEASE_KEY_PASSWORD \
        MINISIGN_RELEASE_SECRET_KEY
    echo "== certificat de signature de code -> $PB_ENV_CODESIGN"
    if [[ -f "$p12" ]]; then
        local pw=""
        if [[ -f "$p12_pass_file" ]]; then
            # Legacy plaintext file of older setup-codesign-cert.sh: read, never printed; purge deletes it.
            pw="$(tr -d '\n' <"$p12_pass_file")"
        else
            pb_read_password pw "Mot de passe du .p12 : "
        fi
        printf '%s\n' "$pw" | /usr/bin/openssl pkcs12 -in "$p12" -noout -passin stdin 2>/dev/null ||
            { echo "erreur : mot de passe du .p12 incorrect" >&2; exit 1; }
        base64 <"$p12" | tr -d '\n' | pb_gh_env_secret "$repo" "$PB_ENV_CODESIGN" MACOS_SIGN_P12
        printf '%s' "$pw" | pb_gh_env_secret "$repo" "$PB_ENV_CODESIGN" MACOS_SIGN_P12_PASSWORD
        pw=""
        echo "   MACOS_SIGN_P12 + MACOS_SIGN_P12_PASSWORD -> environnement $PB_ENV_CODESIGN"
        local n repo_names
        repo_names="$(secret_names)"
        for n in MACOS_SIGN_P12 MACOS_SIGN_P12_PASSWORD; do
            if grep -qxF -- "$n" <<<"$repo_names"; then
                gh secret delete "$n" --repo "$repo"
                echo "   secret de dépôt $n supprimé"
            fi
        done
    else
        echo "   $(basename "$p12") absent : rien à migrer"
    fi
    echo "Ensuite : sauvegardez les fichiers et mots de passe dans votre gestionnaire, puis « purge »."
}

purge() {
    local missing=0 p e want names
    for p in "$db_pub" "$rel_pub"; do
        [[ -s "$p" ]] || { echo "refusé : ${p#"$repo_root"/} n'est pas commitée" >&2; missing=1; }
    done
    if have_gh; then
        for e in "$PB_ENV_DB:MINISIGN_SECRET_KEY" "$PB_ENV_RELEASE:MINISIGN_RELEASE_SECRET_KEY" "$PB_ENV_CODESIGN:MACOS_SIGN_P12"; do
            want="${e#*:}"
            names="$(secret_names "${e%%:*}")"
            grep -qxF -- "$want" <<<"$names" || { echo "refusé : l'environnement ${e%%:*} n'a pas $want (migrate)" >&2; missing=1; }
        done
    else
        echo "refusé : gh absent ou non authentifié, impossible de vérifier les environnements" >&2
        missing=1
    fi
    ((missing == 0)) || exit 1
    local files
    files="$(secret_files)"
    if [[ -z "$files" ]]; then
        echo "aucun secret local"
        return 0
    fi
    echo "Fichiers qui vont être supprimés :"
    sed "s|^$dir/|   |" <<<"$files"
    if ((yes == 0)); then
        local answer=""
        IFS= read -r -p "Clés et mots de passe sauvegardés dans votre gestionnaire ? Tapez « oui » : " answer </dev/tty
        [[ "$answer" == oui ]] || { echo "annulé"; exit 1; }
    fi
    while IFS= read -r p; do
        [[ -n "$p" ]] || continue
        rm -f -- "$p"
    done <<<"$files"
    echo "supprimés. Il reste dans $dir les fichiers publics (certificat .cer.pem)."
}

case "$cmd" in
    status) status ;;
    encrypt) encrypt ;;
    migrate) migrate ;;
    purge) purge ;;
esac
