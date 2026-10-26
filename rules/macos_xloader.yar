// XLoader (Formbook successor) for macOS and look-alike credential stealers: Mach-O that persists as a
// LaunchAgent and reads Chrome and Firefox credential stores.

rule Parabellum_MacOS_XLoader_Like_Credential_Stealer
{
    meta:
        author = "Parabellum"
        description = "XLoader-like Mach-O: LaunchAgent persistence plus Chrome 'Login Data' and Firefox logins.json/key4.db access"
        family = "XLoader"
        severity = "medium"
        reference = "https://www.sentinelone.com/blog/xloaders-latest-trick-new-macos-variant-disguised-as-signed-officenote-app/"
        date = "2026-10-25"
    strings:
        $la = "Library/LaunchAgents"
        $pa = "ProgramArguments"
        $c1 = "Google/Chrome"
        $c2 = "Login Data"
        $f1 = "Firefox/Profiles"
        $f2 = "logins.json"
        $f3 = "key4.db"
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe)
        and filesize < 20MB
        and all of them
}
