// Generic: AppleScript hidden behind base64 and piped/evaluated into osascript.

rule Parabellum_MacOS_Generic_Base64_Osascript
{
    meta:
        author = "Parabellum"
        description = "Base64-wrapped AppleScript decoded and executed through osascript (stealer and loader staging)"
        family = "Generic.Loader"
        severity = "medium"
        reference = "https://www.jamf.com/blog/infostealers-pose-threat-to-macos/"
        date = "2026-10-25"
    strings:
        $a = /(echo|printf)\s+["']?[A-Za-z0-9+\/]{60,}={0,2}["']?\s*\|\s*base64\s+(-d|-D|--decode)\s*\|\s*(\/usr\/bin\/)?osascript/
        $b = /osascript\s+-e\s+["']?\$\((echo|printf)\s+["']?[A-Za-z0-9+\/]{60,}={0,2}["']?\s*\|\s*base64\s+(-d|-D|--decode)/
        $c = /base64\s+(-d|-D|--decode)[^\n|]{0,64}\|\s*(\/usr\/bin\/)?osascript(\s+-)?\s*($|[;&\n])/
    condition:
        filesize < 5MB and any of them
}
