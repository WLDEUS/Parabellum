#!/bin/bash
# Restore the system DNS servers that Parabellum replaced with its local resolver (dnscrypt-proxy).
#
# Usage: sudo restore-dns.sh [--saved <saved-dns.json>] [--dry-run]
#
# Only network services whose DNS currently points to a loopback address (127.0.0.0/8 or ::1) are
# touched. They get back the servers recorded by the daemon in dns/saved-dns.json, or DHCP ("Empty")
# when the service is not in the file (or the file is missing or unreadable). Anything else is left
# alone, so running this twice, or after a clean `parabellum dns off`, changes nothing.
#
# saved-dns.json: {"version":1,"saved_at":<unix>,"services":{"Wi-Fi":["192.168.1.1"],"Ethernet":[]}}
# (empty array = DHCP). macOS has no jq/python3: parsed with JXA (osascript), perl JSON::PP as fallback.
#
# Installed as "/Library/Application Support/Parabellum/bin/restore-dns.sh"; used by uninstall.sh and
# by the postinstall script when the daemon fails to start. Compatible with macOS /bin/bash 3.2.
set -euo pipefail
PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH

readonly NETWORKSETUP="/usr/sbin/networksetup"
readonly MAX_SAVED_BYTES=262144

saved="/Library/Application Support/Parabellum/dns/saved-dns.json"
dry_run=0

log() { printf 'parabellum restore-dns: %s\n' "$*"; }
die() {
    printf 'parabellum restore-dns: erreur : %s\n' "$*" >&2
    exit 1
}

while (($# > 0)); do
    case "$1" in
        --saved)
            (($# >= 2)) || die "--saved attend un fichier"
            saved="$2"
            shift
            ;;
        --dry-run) dry_run=1 ;;
        -h | --help)
            /usr/bin/awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
            exit 0
            ;;
        *) die "option inconnue : $1" ;;
    esac
    shift
done

[[ "$(/usr/bin/uname -s)" == "Darwin" ]] || die "macOS uniquement."
[[ -x "$NETWORKSETUP" ]] || die "$NETWORKSETUP introuvable."
if ((dry_run == 0)) && [[ "$(/usr/bin/id -u)" != "0" ]]; then
    die "à lancer en root : sudo $0"
fi

# JXA: prints one "service<TAB>server1 server2" (or "service<TAB>Empty") line per valid saved service.
read -r -d '' JXA_PARSER <<'JXA' || true
ObjC.import("Foundation");
function run(argv) {
    var raw = $.NSString.stringWithContentsOfFileEncodingError(argv[0], $.NSUTF8StringEncoding, $());
    var text = ObjC.unwrap(raw);
    if (typeof text !== "string" || text.length === 0 || text.length > 262144) {
        throw new Error("saved-dns.json unreadable");
    }
    var doc = JSON.parse(text);
    if (!doc || typeof doc !== "object" || !doc.services || typeof doc.services !== "object" ||
        Array.isArray(doc.services)) {
        throw new Error("saved-dns.json: no services object");
    }
    var lines = [];
    Object.keys(doc.services).forEach(function (name) {
        if (name.length === 0 || /[\t\r\n]/.test(name)) { return; }
        var servers = doc.services[name];
        if (servers === null || servers === undefined) { servers = []; }
        if (!Array.isArray(servers)) { return; }
        var valid = servers.every(function (s) {
            return typeof s === "string" && s.length <= 64 && /^[0-9A-Fa-f:.]+(%[A-Za-z0-9]+)?$/.test(s);
        });
        if (!valid) { return; }
        lines.push(name + "\t" + (servers.length > 0 ? servers.join(" ") : "Empty"));
    });
    return lines.join("\n");
}
JXA

parse_saved_jxa() {
    /usr/bin/osascript -l JavaScript -e "$JXA_PARSER" "$1" 2>/dev/null
}

parse_saved_perl() {
    [[ -x /usr/bin/perl ]] || return 1
    # shellcheck disable=SC2016 # Perl code, not shell expansions.
    /usr/bin/perl -MJSON::PP -e '
        binmode(STDOUT, ":encoding(UTF-8)");
        open(my $fh, "<:raw", $ARGV[0]) or exit 2;
        local $/; my $t = <$fh>; close($fh);
        exit 3 if !defined($t) || length($t) == 0 || length($t) > 262144;
        my $d = eval { JSON::PP->new->utf8->decode($t) };
        exit 3 unless ref($d) eq "HASH" && ref($d->{services}) eq "HASH";
        my $s = $d->{services};
        for my $n (sort keys %$s) {
            next if $n eq "" || $n =~ /[\t\r\n]/;
            my $v = $s->{$n};
            $v = [] unless defined $v;
            next unless ref($v) eq "ARRAY";
            next if grep { !defined($_) || ref($_) || length($_) > 64 || $_ !~ /\A[0-9A-Fa-f:.]+(?:%[A-Za-z0-9]+)?\z/ } @$v;
            print $n, "\t", (@$v ? join(" ", @$v) : "Empty"), "\n";
        }' "$1" 2>/dev/null
}

saved_lines=""
if [[ -f "$saved" && ! -L "$saved" ]]; then
    size="$(/usr/bin/stat -f %z "$saved" 2>/dev/null || echo 0)"
    if ((size > MAX_SAVED_BYTES)); then
        log "fichier de sauvegarde trop gros ($size octets), ignoré : $saved"
    elif saved_lines="$(parse_saved_jxa "$saved")"; then
        :
    elif saved_lines="$(parse_saved_perl "$saved")"; then
        log "sauvegarde lue avec perl (osascript indisponible)"
    else
        saved_lines=""
        log "sauvegarde illisible, les services concernés repasseront en DHCP : $saved"
    fi
else
    log "aucune sauvegarde ($saved) : les services concernés repasseront en DHCP"
fi

# Prints the saved servers of service $1 ("Empty" for DHCP); fails when the service was not saved.
saved_servers_for() {
    local name rest
    while IFS=$'\t' read -r name rest; do
        [[ -n "$name" ]] || continue
        if [[ "$name" == "$1" ]]; then
            printf '%s\n' "${rest:-Empty}"
            return 0
        fi
    done <<<"$saved_lines"
    return 1
}

is_loopback_list() {
    printf '%s\n' "$1" | /usr/bin/grep -Eq '^(127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|::1)$'
}

# True when every server of a space-separated list is a loopback address (or the list is empty).
only_loopback() {
    local s
    for s in $1; do
        is_loopback_list "$s" || return 1
    done
    return 0
}

services="$("$NETWORKSETUP" -listallnetworkservices 2>/dev/null |
    /usr/bin/awk 'NR == 1 && /^An asterisk/ { next } { sub(/^\*/, ""); if (length($0) > 0) print }' || true)"
[[ -n "$services" ]] || die "aucun service réseau trouvé (networksetup -listallnetworkservices)."

changed=0
failed=0
while IFS= read -r svc; do
    [[ -n "$svc" ]] || continue
    current="$("$NETWORKSETUP" -getdnsservers "$svc" 2>/dev/null || true)"
    is_loopback_list "$current" || continue

    if target="$(saved_servers_for "$svc")"; then
        if [[ "$target" != "Empty" ]] && only_loopback "$target"; then
            log "$svc : la sauvegarde ne contient que du loopback ($target), retour au DHCP"
            target="Empty"
        fi
    else
        target="Empty"
    fi

    # Word splitting is intended: one networksetup argument per server.
    read -r -a servers <<<"$target"
    log "$svc : $(printf '%s' "$current" | /usr/bin/tr '\n' ' ') -> $target"
    if ((dry_run == 1)); then
        continue
    fi
    if "$NETWORKSETUP" -setdnsservers "$svc" "${servers[@]}"; then
        changed=1
    else
        failed=1
        log "échec pour « $svc » : réglez-le à la main dans Réglages Système > Réseau > $svc > DNS"
    fi
done <<<"$services"

if ((changed == 1)); then
    /usr/bin/dscacheutil -flushcache 2>/dev/null || true
    /usr/bin/killall -HUP mDNSResponder 2>/dev/null || true
    log "DNS restaurés, cache vidé"
elif ((dry_run == 0 && failed == 0)); then
    log "aucun service ne pointe vers le résolveur local : rien à restaurer"
fi
exit "$failed"
