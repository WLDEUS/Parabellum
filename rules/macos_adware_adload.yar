// Adload adware family: hidden "Application Support/.<UUID>/Services/com.<name>Daemon.app" layout,
// LaunchAgent/LaunchDaemon persistence and machine UUID beaconing.

rule Parabellum_MacOS_Adload
{
    meta:
        author = "Parabellum"
        description = "Adload: hidden Application Support/.<id>/Services/ app layout, launchd persistence and IOPlatformUUID fingerprinting"
        family = "Adload"
        severity = "medium"
        reference = "https://www.sentinelone.com/labs/massive-new-adload-campaign-goes-entirely-undetected-by-apples-xprotect/"
        date = "2026-10-25"
    strings:
        $hid = "Application Support/."
        $svc = "/Services/com."
        $la = "LaunchAgents"
        $ld = "LaunchDaemons"
        $lc = "launchctl"
        $uuid = "IOPlatformUUID"
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe)
        and filesize < 20MB
        and $hid and $svc and $lc and $uuid
        and ($la or $ld)
}
