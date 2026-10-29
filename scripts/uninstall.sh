#!/bin/bash
# Uninstall Parabellum.
#
# Usage: sudo uninstall.sh [--purge] [--yes]
#   --purge   also delete state/ (alert history), config.toml and logs; the quarantine is MOVED to
#             /Users/Shared/Parabellum-quarantine-<date> (root only), never deleted
#   --yes     do not ask for confirmation
#
# Installed as "/Library/Application Support/Parabellum/bin/uninstall.sh" (also: `make uninstall`).
# Order matters: DNS is handed back first (never leave the Mac without working DNS), then the
# daemon and the menu bar app are stopped, then files are removed.
# Third-party components (ClamAV, osquery, LuLu, BlockBlock) are NOT removed: instructions are printed.
# Compatible with macOS /bin/bash 3.2.
set -euo pipefail
PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

readonly ROOT="/Library/Application Support/Parabellum"
readonly BIN="$ROOT/bin"
readonly LOG_DIR="/Library/Logs/Parabellum"
readonly APP="/Applications/Parabellum.app"
readonly CLI_LINK="/usr/local/bin/parabellum"
readonly SOCKET="/var/run/parabellum.sock"
readonly DAEMON_LABEL="com.wldeus.parabellum.daemon"
readonly UI_LABEL="com.wldeus.parabellum.ui"
readonly DAEMON_PLIST="/Library/LaunchDaemons/$DAEMON_LABEL.plist"
readonly AGENT_PLIST="/Library/LaunchAgents/$UI_LABEL.plist"
readonly PKG_ID="com.wldeus.parabellum.pkg"
readonly BUNDLE_ID="com.wldeus.parabellum"

purge=0
assume_yes=0
orig_args="$*"

say() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
warn() { printf 'attention : %s\n' "$*" >&2; }
die() {
    printf 'erreur : %s\n' "$*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --purge) purge=1 ;;
        -y | --yes) assume_yes=1 ;;
        -h | --help)
            /usr/bin/awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
            exit 0
            ;;
        *) die "option inconnue : $1 (voir --help)" ;;
    esac
    shift
done

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] || die "macOS uniquement."
[[ "$(/usr/bin/id -u)" == "0" ]] || die "à lancer en root : sudo \"$0\" $orig_args"

if ((assume_yes == 0)) && [[ -t 0 ]]; then
    if ((purge == 1)); then
        printf 'Désinstaller Parabellum ET effacer historique, config et journaux (quarantaine déplacée) ? [o/N] '
    else
        printf 'Désinstaller Parabellum (quarantaine, historique et config conservés) ? [o/N] '
    fi
    answer=""
    read -r answer || true
    case "$answer" in
        o | O | oui | Oui | OUI | y | Y | yes) ;;
        *)
            echo "Annulé."
            exit 0
            ;;
    esac
fi

# Run "$@" with a time limit (macOS has no timeout(1)). Returns 124 on timeout.
run_with_timeout() {
    local secs="$1" ticks=0 pid rc=0
    shift
    "$@" </dev/null &
    pid=$!
    while /bin/kill -0 "$pid" 2>/dev/null; do
        if ((ticks >= secs * 10)); then
            /bin/kill -TERM "$pid" 2>/dev/null || true
            /bin/sleep 1
            /bin/kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            return 124
        fi
        /bin/sleep 0.1
        ticks=$((ticks + 1))
    done
    wait "$pid" || rc=$?
    return "$rc"
}

console_user="$(/usr/bin/stat -f %Su /dev/console 2>/dev/null || true)"
console_uid=""
case "$console_user" in
    "" | root | loginwindow | _mbsetupuser) console_user="" ;;
    *) console_uid="$(/usr/bin/id -u "$console_user" 2>/dev/null || true)" ;;
esac

work="$(/usr/bin/mktemp -d /tmp/parabellum-uninstall.XXXXXX)"
trap '/bin/rm -rf "$work"' EXIT

# Keep a private copy of restore-dns.sh: bin/ is deleted below.
script_dir="$(cd "$(/usr/bin/dirname "$0")" && pwd -P)"
restore_dns=""
for candidate in "$script_dir/restore-dns.sh" "$BIN/restore-dns.sh"; do
    if [[ -f "$candidate" ]]; then
        /bin/cp "$candidate" "$work/restore-dns.sh"
        /bin/chmod 0700 "$work/restore-dns.sh"
        restore_dns="$work/restore-dns.sh"
        break
    fi
done

# 1. DNS: ask the daemon to put the original servers back.
say "Désactivation du blocage DNS"
cli=""
for candidate in "$BIN/parabellum" "$CLI_LINK"; do
    if [[ -x "$candidate" ]]; then
        cli="$candidate"
        break
    fi
done
if [[ -n "$cli" ]]; then
    if run_with_timeout 30 "$cli" dns off; then
        note "parabellum dns off : OK"
    else
        warn "parabellum dns off a échoué (daemon arrêté ?) : restauration de secours après l'arrêt du daemon"
    fi
else
    note "CLI absente : restauration de secours après l'arrêt du daemon"
fi

# 2. Stop the menu bar app and the daemon.
say "Arrêt de l'app et du daemon"
if [[ -n "$console_uid" ]]; then
    /bin/launchctl bootout "gui/$console_uid/$UI_LABEL" 2>/dev/null || true
fi
/usr/bin/pkill -x Parabellum 2>/dev/null || true
/bin/launchctl bootout "system/$DAEMON_LABEL" 2>/dev/null || true
# Helpers the daemon started from its components/ dir (dnscrypt-proxy…), if any survived.
/usr/bin/pkill -f "^$ROOT/components/" 2>/dev/null || true

# 3. DNS fallback: any service still pointing to the local resolver gets its saved servers (or DHCP).
if [[ -n "$restore_dns" ]]; then
    /bin/bash "$restore_dns" --saved "$ROOT/dns/saved-dns.json" ||
        warn "restauration DNS incomplète : vérifiez Réglages Système > Réseau > (service) > DNS"
else
    warn "restore-dns.sh introuvable. Si Internet ne répond plus : networksetup -setdnsservers Wi-Fi Empty"
fi

# 3b. VPN kill switch fallback (the daemon removes it when it stops; a crashed daemon may have left it):
#     flush our pf anchor and release our pf reference (token saved by the daemon).
readonly PF_ANCHOR="com.apple/250.Parabellum"
if [[ -n "$(/sbin/pfctl -a "$PF_ANCHOR" -sr 2>/dev/null || true)" ]]; then
    /sbin/pfctl -a "$PF_ANCHOR" -F all >/dev/null 2>&1 || true
    note "règles du kill switch retirées"
fi
ks_state="$ROOT/state/vpn/killswitch.json"
if [[ -f "$ks_state" ]]; then
    token="$(/usr/bin/plutil -extract token raw -o - "$ks_state" 2>/dev/null || true)"
    case "$token" in
        '' | *[!0-9]*) ;;
        *) /sbin/pfctl -X "$token" >/dev/null 2>&1 || true ;;
    esac
fi

# 3c. Ransomware decoy files (only ours: same name and Parabellum header).
if [[ -n "$console_user" ]]; then
    uhome="$(/usr/bin/dscl . -read "/Users/$console_user" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{ print $2; exit }' || true)"
    if [[ -n "$uhome" && -d "$uhome" ]]; then
        for d in Documents Desktop Pictures; do
            for f in "$uhome/$d/!Parabellum - fichier leurre - ne pas modifier.docx" \
                "$uhome/$d/~Parabellum - fichier leurre - ne pas modifier.pdf"; do
                if [[ -f "$f" && ! -L "$f" ]] && /usr/bin/head -c 24 "$f" 2>/dev/null | /usr/bin/grep -q "PARABELLUM DECOY FILE"; then
                    /bin/rm -f "$f" && note "fichier leurre supprimé : $f"
                fi
            done
        done
    fi
fi

# 4. Remove the program.
say "Suppression des fichiers"
remove() {
    if [[ -e "$1" || -L "$1" ]]; then
        /bin/rm -rf "$1"
        note "supprimé : $1"
    fi
}
remove "$DAEMON_PLIST"
remove "$AGENT_PLIST"
remove "$APP"
if [[ -L "$CLI_LINK" ]]; then
    case "$(/usr/bin/readlink "$CLI_LINK")" in
        "$ROOT"/*) remove "$CLI_LINK" ;;
        *) warn "$CLI_LINK ne pointe pas vers Parabellum, laissé en place" ;;
    esac
fi
remove "$SOCKET"
for d in bin db clamav components dns cache tmp; do
    remove "$ROOT/$d"
done
if /usr/sbin/pkgutil --forget "$PKG_ID" >/dev/null 2>&1; then
    note "reçu d'installation oublié : $PKG_ID"
fi

# 5. Data.
if ((purge == 1)); then
    say "Purge des données"
    if [[ -d "$ROOT/quarantine" ]] && [[ -n "$(/bin/ls -A "$ROOT/quarantine" 2>/dev/null)" ]]; then
        dest="/Users/Shared/Parabellum-quarantine-$(/bin/date '+%Y%m%d-%H%M%S')"
        /bin/mv "$ROOT/quarantine" "$dest"
        /usr/sbin/chown -R root:wheel "$dest"
        /bin/chmod 0700 "$dest"
        note "quarantaine DÉPLACÉE (pas supprimée) vers : $dest"
        note "fichiers neutralisés, lisibles par root seulement ; supprimez-la vous-même : sudo rm -rf \"$dest\""
    fi
    remove "$ROOT"
    remove "$LOG_DIR"
    if [[ -n "$console_user" ]]; then
        home="$(/usr/bin/dscl . -read "/Users/$console_user" NFSHomeDirectory 2>/dev/null | /usr/bin/awk '{ print $2; exit }' || true)"
        if [[ -n "$home" && -d "$home" ]]; then
            remove "$home/Library/Preferences/$BUNDLE_ID.plist"
            remove "$home/Library/Caches/$BUNDLE_ID"
            remove "$home/Library/HTTPStorages/$BUNDLE_ID"
        fi
    fi
else
    say "Données conservées (relancez avec --purge pour les effacer)"
    for keep in "$ROOT/quarantine" "$ROOT/state" "$ROOT/config.toml" "$LOG_DIR"; do
        if [[ -e "$keep" ]]; then
            note "$keep"
        fi
    done
fi

# 6. What is left to the user.
cat <<'EOF'

Parabellum est désinstallé. Composants tiers NON supprimés (installés depuis leurs paquets officiels) :

  ClamAV       pkgutil --pkgs | grep -i clamav       -> sudo rm -rf /usr/local/clamav
                                                         puis sudo pkgutil --forget <id trouvé>
  osquery      pkgutil --pkgs | grep -i osquery      -> sudo rm -rf /opt/osquery /var/osquery /usr/local/bin/osqueryi
                                                         puis sudo pkgutil --forget <id trouvé>
  LuLu         relancez l'installeur LuLu (objective-see.org) et choisissez « Uninstall »
  BlockBlock   relancez l'installeur BlockBlock (objective-see.org) et choisissez « Uninstall »

À faire à la main :
  - Réglages Système > Confidentialité et sécurité > Accès complet au disque : retirez « parabellumd ».
  - Réglages Système > Général > Ouverture > Autoriser en arrière-plan : l'entrée Parabellum disparaît
    au prochain redémarrage.
  - uBlock Origin Lite (Chrome / Safari) reste installé : retirez-le depuis le navigateur si besoin.
EOF
