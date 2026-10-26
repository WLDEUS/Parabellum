// Pirrit adware — first native Apple Silicon malware seen in the wild was the Pirrit variant GoSearch22.

rule Parabellum_MacOS_Pirrit_GoSearch22
{
    meta:
        author = "Parabellum"
        description = "Pirrit adware variant GoSearch22 (Safari extension injecting ads)"
        family = "Pirrit"
        severity = "medium"
        reference = "https://objective-see.org/blog/blog_0x62.html"
        date = "2026-10-25"
    strings:
        $name = "GoSearch22"
        $ext = "Safari" nocase
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe)
        and filesize < 20MB
        and $name and $ext
}
