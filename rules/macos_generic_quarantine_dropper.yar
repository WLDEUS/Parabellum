// Generic: script dropper that downloads into a temporary/shared location, strips the
// com.apple.quarantine attribute (bypassing Gatekeeper) and makes the payload executable.

rule Parabellum_MacOS_Generic_Quarantine_Removal_Dropper
{
    meta:
        author = "Parabellum"
        description = "Shell script downloading to /tmp, /Users/Shared or $TMPDIR, removing com.apple.quarantine and chmod-ing the payload executable"
        family = "Generic.Dropper"
        severity = "medium"
        reference = "https://objective-see.org/blog/blog_0x6E.html"
        date = "2026-10-25"
    strings:
        $dl = /(curl|wget)\s[^\n]{0,300}(-o|-O|--output|>)\s*["']?(\/tmp\/|\/private\/tmp\/|\/Users\/Shared\/|\$TMPDIR|\$\{TMPDIR)/
        $q1 = /xattr\s+(-[a-z]+\s+){0,3}-[a-z]*d[a-z]*\s+com\.apple\.quarantine/
        $q2 = /xattr\s+-(c|cr|rc)\s/
        $x = /chmod\s+(\+x|7[0-7][0-7]|a\+x|u\+x)\s+["']?(\/tmp\/|\/private\/tmp\/|\/Users\/Shared\/|\$TMPDIR|\$\{TMPDIR)/
    condition:
        (uint16(0) == 0x2123 or uint32be(0) == 0x46617364)
        and filesize < 1MB
        and $dl and $x
        and any of ($q*)
}
