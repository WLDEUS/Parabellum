# shellcheck shell=bash
# Helpers for the signing-key scripts (setup-signing-keys.sh, setup-release-key.sh, secure-local-keys.sh).
# Sourced, never executed. No secret is ever printed, passed on a command line or written to disk here:
# passwords are read from the terminal and handed to minisign / gh on stdin.

# GitHub environments that hold the signing secrets (created by scripts/protect-repo.sh):
#   db-signing  branch main only          MINISIGN_SECRET_KEY, MINISIGN_KEY_PASSWORD
#   release     tags v* only, reviewer    MINISIGN_RELEASE_SECRET_KEY, MINISIGN_RELEASE_KEY_PASSWORD
#   codesign    tags v* only              MACOS_SIGN_P12, MACOS_SIGN_P12_PASSWORD
# shellcheck disable=SC2034
readonly PB_ENV_DB="db-signing" PB_ENV_RELEASE="release" PB_ENV_CODESIGN="codesign"

# pb_read_new_password <var>: ask twice on the terminal (no echo), at least 16 characters.
pb_read_new_password() {
    local __var="$1" a b
    [[ -r /dev/tty ]] || { echo "erreur : un terminal est nécessaire pour saisir le mot de passe" >&2; return 1; }
    while :; do
        IFS= read -rs -p "Mot de passe de la clé (16 caractères min., à garder dans votre gestionnaire) : " a </dev/tty
        echo >&2
        IFS= read -rs -p "Confirmez : " b </dev/tty
        echo >&2
        if [[ "$a" != "$b" ]]; then
            echo "les deux saisies diffèrent, recommencez" >&2
        elif ((${#a} < 16)); then
            echo "trop court (16 caractères minimum)" >&2
        else
            break
        fi
    done
    printf -v "$__var" '%s' "$a"
}

# pb_read_password <var> <prompt>: ask once on the terminal (no echo).
pb_read_password() {
    local __var="$1" a
    [[ -r /dev/tty ]] || { echo "erreur : un terminal est nécessaire pour saisir le mot de passe" >&2; return 1; }
    IFS= read -rs -p "$2" a </dev/tty
    echo >&2
    printf -v "$__var" '%s' "$a"
}

# pb_minisign_key_state <secret key file>: prints "encrypted", "plaintext" or "invalid".
# Layout of the base64 line: sig_alg "Ed", then kdf_alg "Sc" (scrypt) or two NUL bytes (no password).
pb_minisign_key_state() {
    local line kdf
    line="$(sed -n '2p' "$1" 2>/dev/null)" || { echo invalid; return 0; }
    kdf="$(printf '%s' "$line" | base64 -d 2>/dev/null | head -c 4 | od -An -tx1 | tr -d ' \n')" || kdf=""
    case "$kdf" in
        45645363) echo encrypted ;;   # "EdSc"
        45640000) echo plaintext ;;   # "Ed\0\0"
        *) echo invalid ;;
    esac
}

# pb_minisign_matches <secret key> <public key> <password>: the key signs and the public key verifies.
pb_minisign_matches() {
    local tmp rc=0
    tmp="$(mktemp -d)"
    printf 'parabellum key check\n' >"$tmp/m"
    if ! printf '%s\n' "$3" | minisign -S -s "$1" -m "$tmp/m" -x "$tmp/m.minisig" >/dev/null 2>&1; then
        rc=1
    elif ! minisign -Vq -p "$2" -m "$tmp/m" -x "$tmp/m.minisig" >/dev/null 2>&1; then
        rc=2
    fi
    rm -rf "$tmp"
    return "$rc"
}

# pb_gh_env_secret <repo> <environment> <name>: secret value read from stdin (never on the command line).
pb_gh_env_secret() {
    gh secret set "$3" --repo "$1" --env "$2"
}

# pb_gh_env_exists <repo> <environment>
pb_gh_env_exists() {
    gh api "repos/$1/environments/$2" --silent >/dev/null 2>&1
}
