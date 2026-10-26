// Parabellum built-in rules, compiled into the binary and always loaded (even without a DB bundle).
// Metadata: `family` = detection name, `severity` = info|low|medium|high|critical,
// `engine` = "heuristic" for generic heuristics (reported as DetectionEngine::Heuristic).
// Keep these conservative: medium severity only makes a file *suspicious*.

rule EICAR_Test_File
{
    meta:
        family = "EICAR-Test-File"
        severity = "high"
        description = "EICAR anti-malware test file (harmless, used to test detection)"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0 and filesize < 256
}

rule MacOS_AppleScript_Password_Phishing
{
    meta:
        family = "Heuristic.MacOS.PasswordPhishingDialog"
        severity = "medium"
        engine = "heuristic"
        description = "AppleScript dialog asking for a hidden answer (password) combined with exfiltration or local password validation (AMOS-style stealers)"
    strings:
        $dialog = "display dialog" nocase
        $hidden = "hidden answer" nocase
        $ex_curl = "curl " nocase
        $ex_http = "http://" nocase
        $ex_https = "https://" nocase
        $ex_dscl = "dscl" nocase
        $ex_authonly = "-authonly" nocase
        $ex_sec = "find-generic-password" nocase
    condition:
        filesize < 50MB and $dialog and $hidden and any of ($ex_*)
}

rule MacOS_Quarantine_Stripping_Dropper
{
    meta:
        family = "Heuristic.MacOS.QuarantineStrippingDropper"
        severity = "medium"
        engine = "heuristic"
        description = "Script that downloads a payload, removes the Gatekeeper quarantine attribute and makes it executable"
    strings:
        $quarantine = "com.apple.quarantine"
        $xattr = /xattr\s+(-[a-zA-Z]+\s+)*-[a-zA-Z]*[dcr]/
        $chmod = /chmod\s+(-R\s+)?(\+x|[ugoa]+\+[rw]*x|[0-7]?7[0-7][0-7])\s/
        $curl = /(curl|wget)\s/
    condition:
        filesize < 5MB and $quarantine and $xattr and $chmod and $curl
}

rule MacOS_Base64_Shell_Loader
{
    meta:
        family = "Heuristic.MacOS.Base64ShellLoader"
        severity = "medium"
        engine = "heuristic"
        description = "Long base64 blob decoded and piped into a shell or eval (common first-stage loader)"
    strings:
        $pipe = /(echo|printf)\s+['"]?[A-Za-z0-9+\/=]{120,4096}['"]?\s*\|\s*base64\s+(-d|-D|--decode)\s*\|\s*(ba|z)?sh/
        $eval = /eval\s+["']?\$\(\s*(echo|printf)\s+['"]?[A-Za-z0-9+\/=]{120,4096}['"]?\s*\|\s*base64\s+(-d|-D|--decode)/
    condition:
        filesize < 2MB and any of them
}
