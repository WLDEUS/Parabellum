// Shlayer / Bundlore droppers: bash scripts shipped in DMGs/apps that decrypt and eval a payload with
// openssl, or fetch an app, strip its quarantine attribute and launch it.

rule Parabellum_MacOS_Shlayer_Openssl_Eval
{
    meta:
        author = "Parabellum"
        description = "Shlayer: shell script decrypting an embedded payload with 'openssl enc -aes-256-cbc' and a hardcoded pass, then eval-ing it"
        family = "Shlayer"
        severity = "high"
        reference = "https://www.intego.com/mac-security-blog/osxshlayer-new-mac-malware-comes-out-of-its-shell/"
        date = "2026-10-25"
    strings:
        $o1 = /openssl\s+enc\s+[^\n]{0,60}-aes-256-cbc[^\n]{0,80}(-pass\s+pass:|-k\s+)/
        $eval = /eval\s+["']?\$\(/
        $src = "BASH_SOURCE"
        $res = "/Resources/"
    condition:
        uint16(0) == 0x2123
        and filesize < 500KB
        and $o1 and $eval
        and ($src or $res)
}

rule Parabellum_MacOS_Bundlore_Dropper_Script
{
    meta:
        author = "Parabellum"
        description = "Bundlore-style dropper: downloads into a mktemp directory, mounts or unzips it, removes com.apple.quarantine and opens the app"
        family = "Bundlore"
        severity = "medium"
        reference = "https://www.sentinelone.com/blog/resourceful-macos-malware-hides-in-named-fork/"
        date = "2026-10-25"
    strings:
        $tmp = /mktemp\s+-d/
        $dl = /curl\s+[^\n]{0,200}(-o|--output)\s/
        $unp1 = /hdiutil\s+attach[^\n]{0,120}-nobrowse/
        $unp2 = /unzip\s+(-q|-o|-qq)/
        $q1 = /xattr\s+(-[a-z]+\s+){0,3}-[a-z]*d[a-z]*\s+com\.apple\.quarantine/
        $q2 = /xattr\s+-c?r?c\s/
        $open = /open\s+(-a\s+|-n\s+)?["']?\$/
    condition:
        uint16(0) == 0x2123
        and filesize < 200KB
        and $tmp and $dl and $open
        and any of ($unp*)
        and any of ($q*)
}
