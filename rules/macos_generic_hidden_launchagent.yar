// Generic: writer of a LaunchAgent/LaunchDaemon whose program lives in a hidden directory of a
// temporary or shared location, loaded right away with launchctl.

rule Parabellum_MacOS_Generic_Hidden_LaunchAgent_Writer
{
    meta:
        author = "Parabellum"
        description = "Writes a launchd plist (ProgramArguments) pointing into a dot-directory under /Users/Shared, /tmp or Application Support and loads it with launchctl"
        family = "Generic.Persistence"
        severity = "medium"
        reference = "https://attack.mitre.org/techniques/T1543/001/"
        date = "2026-10-25"
    strings:
        $la = /Library\/Launch(Agents|Daemons)\//
        $lc = /launchctl\s+(load|bootstrap|kickstart|enable)/
        $pa = "ProgramArguments"
        $h1 = /\/Users\/Shared\/\.[A-Za-z0-9_-]{2,}/
        $h2 = /\/(private\/)?tmp\/\.[A-Za-z0-9_-]{2,}/
        $h3 = /Library\/Application Support\/\.[A-Za-z0-9_-]{2,}/
    condition:
        filesize < 20MB
        and $la and $lc and $pa
        and any of ($h*)
}
