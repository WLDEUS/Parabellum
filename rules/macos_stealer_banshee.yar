// Banshee stealer — anti-VM via system_profiler, Russian-language kill switch, fake password prompt.

rule Parabellum_MacOS_Banshee_Stealer
{
    meta:
        author = "Parabellum"
        description = "Banshee stealer: system_profiler 'Model Identifier' VM check, AppleLanguages check, hidden-answer password dialog, keychain and wallet theft"
        family = "Banshee"
        severity = "high"
        reference = "https://www.elastic.co/security-labs/beyond-the-wail"
        date = "2026-10-25"
    strings:
        $vm1 = "SPHardwareDataType"
        $vm2 = "Model Identifier"
        $lang = "AppleLanguages"
        $dlg = "display dialog"
        $hid = "hidden answer"
        $kc = "login.keychain"
        $w1 = "Electrum"
        $w2 = "Exodus"
        $w3 = "Coinomi"
        $w4 = "MetaMask"
        $w5 = "Binance"
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe)
        and filesize < 30MB
        and $vm1 and $vm2 and $lang and $dlg and $hid and $kc
        and 2 of ($w*)
}
