// RustBucket (BlueNoroff): "Internal PDF Viewer" AppleScript/Swift stages fetching a payload to /Users/Shared.

rule Parabellum_MacOS_RustBucket_Stage
{
    meta:
        author = "Parabellum"
        description = "RustBucket: 'Internal PDF Viewer' lure that downloads the next stage with curl into a hidden file in /Users/Shared and makes it executable"
        family = "RustBucket"
        severity = "medium"
        reference = "https://www.jamf.com/blog/bluenoroff-apt-targets-macos-rustbucket-malware/"
        date = "2026-10-25"
    strings:
        $lure = "Internal PDF Viewer"
        $curl = "curl" nocase
        $hidden = /\/Users\/Shared\/\.[A-Za-z0-9_]{1,32}/
        $chmod = /chmod\s+(\+x|7[0-7][0-7]|u\+x|a\+x)/
    condition:
        filesize < 20MB and $lure and $curl and $hidden and $chmod
}
