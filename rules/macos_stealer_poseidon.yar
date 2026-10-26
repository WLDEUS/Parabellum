// Poseidon stealer (AMOS spin-off) — also steals FortiClient and WireGuard VPN configurations.

rule Parabellum_MacOS_Poseidon_Stealer
{
    meta:
        author = "Parabellum"
        description = "Poseidon stealer: AMOS-like password/keychain/wallet theft plus FortiClient and WireGuard VPN configuration theft"
        family = "Poseidon"
        severity = "high"
        reference = "https://www.malwarebytes.com/blog/news/2024/06/mac-users-served-info-stealer-malware-through-google-ads"
        date = "2026-10-25"
    strings:
        $auth = /dscl\s+(\.|\/Local\/Default)\s+-?authonly/ nocase
        $kc = "login.keychain" nocase
        $v1 = "FortiClient" nocase
        $v2 = "WireGuard" nocase
        $w1 = "Electrum" nocase
        $w2 = "Exodus" nocase
        $w3 = "Coinomi" nocase
        $w4 = "Binance" nocase
        $w5 = "MetaMask" nocase
        $dlg = "display dialog" nocase
    condition:
        filesize < 30MB
        and $auth and $kc and $v1 and $v2 and $dlg
        and 2 of ($w*)
}
