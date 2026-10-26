// Cuckoo infostealer/spyware — exits on CIS locales, prompts for the password, screenshots, Telegram.

rule Parabellum_MacOS_Cuckoo_Stealer
{
    meta:
        author = "Parabellum"
        description = "Cuckoo stealer: CIS locale kill switch (hy_AM, be_BY, kk_KZ, ru_RU, uk_UA), osascript password dialog, keychain, screencapture/Telegram theft, LaunchAgent persistence"
        family = "Cuckoo"
        severity = "high"
        reference = "https://www.kandji.io/blog/malware-cuckoo-infostealer-spyware"
        date = "2026-10-25"
    strings:
        $l1 = "hy_AM"
        $l2 = "be_BY"
        $l3 = "kk_KZ"
        $l4 = "ru_RU"
        $l5 = "uk_UA"
        $dlg = "display dialog"
        $kc = "login.keychain"
        $sc = "screencapture"
        $tg = "Telegram Desktop"
        $la = "LaunchAgents"
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe)
        and filesize < 30MB
        and 4 of ($l*)
        and $dlg and $kc and $la
        and ($sc or $tg)
}
