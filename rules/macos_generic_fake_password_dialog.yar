// Generic: AppleScript fake password prompt + password validation + collection/exfiltration.
// The pattern behind most macOS stealers (AMOS, Poseidon, Banshee, Cthulhu, Cuckoo, MacSync…).

rule Parabellum_MacOS_Generic_Fake_Password_Dialog_Exfil
{
    meta:
        author = "Parabellum"
        description = "AppleScript/osascript dialog asking for the password with a hidden answer, validated with dscl authonly or used on the keychain, followed by archive creation or curl upload"
        family = "Generic.Stealer"
        severity = "medium"
        reference = "https://www.sentinelone.com/blog/session-cookies-keychains-ssh-keys-and-more-7-kinds-of-data-malware-steals/"
        date = "2026-10-25"
    strings:
        $dlg = "display dialog" nocase
        $hid = "hidden answer" nocase
        $def = "default answer" nocase
        $pw = "password" nocase
        $v1 = /dscl\s+(\.|\/Local\/Default)\s+-?authonly/ nocase
        $v2 = "login.keychain" nocase
        $x1 = /curl\s[^\n]{0,200}(-F\s|--form\s|--data-binary\s|-T\s|--upload-file\s)/
        $x2 = /ditto\s+-c\s+-k/
        $x3 = /zip\s+-[a-z]*r[a-z]*\s/
    condition:
        filesize < 10MB
        and $dlg and $hid and $def and $pw
        and any of ($v*)
        and any of ($x*)
}
