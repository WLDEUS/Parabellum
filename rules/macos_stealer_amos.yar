// Atomic macOS Stealer (AMOS) — Mach-O builds and the AppleScript payload of later versions.
// Mach-O magics: 0xfeedfacf/0xfeedface (thin, little-endian), 0xcafebabe (universal, big-endian).

rule Parabellum_MacOS_AMOS_Stealer_Binary
{
    meta:
        author = "Parabellum"
        description = "AMOS stealer: validates the stolen login password with dscl -authonly, grabs the login keychain, browser and wallet data and posts a zip to its C2"
        family = "AMOS"
        severity = "high"
        reference = "https://www.sentinelone.com/blog/atomic-stealer-threat-actor-spawns-second-variant-of-macos-malware-sold-on-telegram/"
        date = "2026-10-25"
    strings:
        $auth = /dscl\s+\/Local\/Default\s+-authonly/
        $kc = "login.keychain-db"
        $w1 = "Electrum"
        $w2 = "Exodus"
        $w3 = "Coinomi"
        $w4 = "Binance"
        $w5 = "Guarda"
        $w6 = "atomic/Local Storage"
        $b1 = "Login Data"
        $b2 = "Web Data"
        $b3 = "cookies.sqlite"
        $b4 = "formhistory.sqlite"
        $x1 = "joinsystem"
        $x2 = "BuildID"
        $x3 = "--data-binary @/tmp/"
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe)
        and filesize < 30MB
        and $auth and $kc
        and 3 of ($w*)
        and 2 of ($b*)
        and any of ($x*)
}

rule Parabellum_MacOS_AMOS_Stealer_AppleScript
{
    meta:
        author = "Parabellum"
        description = "AMOS AppleScript stage: fake password dialog checked with dscl authonly, filegrabber routine and crypto-wallet collection"
        family = "AMOS"
        severity = "high"
        reference = "https://www.jamf.com/blog/infostealers-pose-threat-to-macos/"
        date = "2026-10-25"
    strings:
        $dlg = "display dialog" nocase
        $hid = "hidden answer" nocase
        $auth = /dscl\s+\.\s+-?authonly/ nocase
        $fg = "filegrabber" nocase
        $w1 = "Electrum" nocase
        $w2 = "Exodus" nocase
        $w3 = "Coinomi" nocase
        $w4 = "Binance" nocase
        $w5 = "Ledger Live" nocase
        $kc = "login.keychain" nocase
    condition:
        filesize < 5MB
        and $dlg and $hid and $auth and $fg and $kc
        and 2 of ($w*)
}
