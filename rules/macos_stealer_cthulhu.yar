// Cthulhu Stealer — Go Mach-O asking for the macOS password and the MetaMask password via osascript.

rule Parabellum_MacOS_Cthulhu_Stealer
{
    meta:
        author = "Parabellum"
        description = "Cthulhu stealer: Go binary that shows osascript password dialogs (macOS and MetaMask) and steals keychain and wallet data"
        family = "Cthulhu"
        severity = "high"
        reference = "https://www.cadosecurity.com/blog/from-the-depths-analyzing-the-cthulhu-stealer-malware-for-macos"
        date = "2026-10-25"
    strings:
        $go = "Go build ID:"
        $osa = "osascript"
        $dlg = "display dialog"
        $hid = "hidden answer"
        $mm = "MetaMask"
        $kc = "login.keychain"
        $w1 = "Coinbase"
        $w2 = "Exodus"
        $w3 = "Electrum"
        $w4 = "Binance"
    condition:
        (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe)
        and filesize < 40MB
        and $go and $osa and $dlg and $hid and $mm and $kc
        and 1 of ($w*)
}
