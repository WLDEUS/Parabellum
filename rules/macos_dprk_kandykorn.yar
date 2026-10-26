// KANDYKORN intrusion set (DPRK/Lazarus): SUGARLOADER, HLOADER (Discord hijack) and the Python stages.

rule Parabellum_MacOS_KandyKorn_SugarLoader
{
    meta:
        author = "Parabellum"
        description = "SUGARLOADER (KANDYKORN chain): configuration cached as /Library/Caches/com.apple.safari.ck"
        family = "KandyKorn"
        severity = "high"
        reference = "https://www.elastic.co/security-labs/elastic-catches-dprk-passing-out-kandykorn"
        date = "2026-10-25"
    strings:
        $cfg = "/Library/Caches/com.apple.safari.ck"
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe)
        and filesize < 20MB
        and $cfg
}

rule Parabellum_MacOS_KandyKorn_HLoader
{
    meta:
        author = "Parabellum"
        description = "HLOADER (KANDYKORN chain): masquerades as Discord, renaming the real binary to .lock"
        family = "KandyKorn"
        severity = "high"
        reference = "https://www.elastic.co/security-labs/elastic-catches-dprk-passing-out-kandykorn"
        date = "2026-10-25"
    strings:
        $lock = "Discord.app/Contents/MacOS/.lock"
        $disc = "Discord.app/Contents/MacOS/Discord"
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe)
        and filesize < 20MB
        and $lock and $disc
}

rule Parabellum_MacOS_KandyKorn_PythonStage
{
    meta:
        author = "Parabellum"
        description = "KANDYKORN Python stages: Main.py dropping testSpeed.py and FinderTools into /Users/Shared"
        family = "KandyKorn"
        severity = "high"
        reference = "https://www.elastic.co/security-labs/elastic-catches-dprk-passing-out-kandykorn"
        date = "2026-10-25"
    strings:
        $t = "testSpeed.py"
        $f = "FinderTools"
        $s = "/Users/Shared/"
        $u = "urllib" nocase
    condition:
        filesize < 1MB and $t and $f and $s and $u
}
