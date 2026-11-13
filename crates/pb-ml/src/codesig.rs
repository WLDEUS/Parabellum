//! Embedded code-signature parsing (`LC_CODE_SIGNATURE` → `SuperBlob`), bounds-checked.
//!
//! This is *not* signature verification (only `codesign --verify` does that); it reads what the
//! signature claims: ad-hoc or not, CMS (certificate) signature present, hardened runtime, team id,
//! identifier, entitlements. `pb-engine` uses it as a cheap pre-filter (an unsigned or ad-hoc binary
//! cannot be a trusted signer, so `codesign` need not be spawned for it).

use crate::macho::{self, read_cstr, read_u32_be};
use goblin::mach::load_command::CommandVariant;
use goblin::mach::MachO;

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade_0c02;
const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade_7171;
const CSMAGIC_BLOBWRAPPER: u32 = 0xfade_0b01;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_REQUIREMENTS: u32 = 2;
const CSSLOT_ENTITLEMENTS: u32 = 5;
const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
const CS_ADHOC: u32 = 0x2;
const CS_RUNTIME: u32 = 0x1_0000;
const CS_LINKER_SIGNED: u32 = 0x2_0000;
/// Max blobs inspected in a SuperBlob.
const MAX_BLOBS: u32 = 64;
/// Max entitlements XML kept (bytes).
const MAX_ENTITLEMENTS: usize = 256 * 1024;

/// What an embedded code signature claims about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeSignatureSummary {
    /// `LC_CODE_SIGNATURE` present and its SuperBlob parsed.
    pub present: bool,
    /// Size of the signature data in bytes.
    pub size: u32,
    /// CodeDirectory has `CS_ADHOC`.
    pub adhoc: bool,
    /// CodeDirectory has `CS_LINKER_SIGNED` (ad-hoc signature added by the linker).
    pub linker_signed: bool,
    /// CodeDirectory has `CS_RUNTIME` (hardened runtime).
    pub runtime: bool,
    /// A non-empty CMS (certificate) signature blob is present.
    pub has_cms: bool,
    /// An internal requirements blob is present.
    pub has_requirements: bool,
    /// Team identifier recorded in the CodeDirectory (unverified!).
    pub team_id: Option<String>,
    /// Signing identifier recorded in the CodeDirectory (unverified!).
    pub identifier: Option<String>,
    /// XML entitlements blob (bounded), when present.
    pub entitlements: Option<String>,
    /// DER entitlements blob present.
    pub der_entitlements: bool,
    /// Raw CodeDirectory flags (`CS_*`).
    pub flags: u32,
    /// Hash type of the primary CodeDirectory (1 = SHA-1, 2 = SHA-256, …; 0 = none).
    pub hash_type: u8,
    /// Number of CodeDirectories (primary + alternates).
    pub code_directories: u32,
    /// The CMS blob carries a secure timestamp (`id-aa-timeStampToken` attribute).
    pub cms_timestamp: bool,
    /// The CMS certificates mention `Developer ID Application` (distribution outside the App Store).
    pub cms_developer_id: bool,
    /// The CMS certificates mention `Apple Development` / `Mac Developer` (development-only identity).
    pub cms_apple_development: bool,
    /// The CMS certificates mention `Apple Mac OS Application Signing` (Mac App Store).
    pub cms_app_store: bool,
    /// The CMS certificates mention `Software Signing` (Apple's own platform binaries).
    pub cms_apple_software: bool,
}

/// DER encoding of the OID 1.2.840.113549.1.9.16.2.14 (`id-aa-timeStampToken`).
const OID_TIMESTAMP_TOKEN: &[u8] = &[
    0x06, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x02, 0x0e,
];
/// Max CMS bytes inspected for certificate hints.
const MAX_CMS_SCAN: usize = 64 * 1024;

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Parses the embedded signature of a Mach-O (for universal binaries: the arm64 slice, else the
/// first parsable one). `None` when `bytes` is not a parsable Mach-O. A Mach-O without signature
/// yields `Some` with `present == false`.
pub fn code_signature_summary(bytes: &[u8]) -> Option<CodeSignatureSummary> {
    if !crate::looks_like_macho(bytes) {
        return None;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let slices = match macho::parse_fat(bytes) {
            Ok(Some(s)) => s,
            Ok(None) => vec![macho::FatSlice {
                cputype: 0,
                offset: 0,
                size: bytes.len(),
            }],
            Err(_) => return None,
        };
        let (_, data, m) = macho::select_slice(bytes, &slices).ok()?;
        Some(summary_for(data, &m))
    }));
    result.ok().flatten()
}

/// Signature summary for an already-parsed slice.
pub(crate) fn summary_for(slice: &[u8], m: &MachO<'_>) -> CodeSignatureSummary {
    for lc in &m.load_commands {
        if let CommandVariant::CodeSignature(cmd) = &lc.command {
            if let Some(blob) = macho::sub(slice, u64::from(cmd.dataoff), u64::from(cmd.datasize)) {
                let mut s = parse_superblob(blob);
                s.size = cmd.datasize;
                return s;
            }
            return CodeSignatureSummary {
                size: cmd.datasize,
                ..Default::default()
            };
        }
    }
    CodeSignatureSummary::default()
}

fn parse_superblob(blob: &[u8]) -> CodeSignatureSummary {
    let mut s = CodeSignatureSummary::default();
    if read_u32_be(blob, 0) != Some(CSMAGIC_EMBEDDED_SIGNATURE) {
        return s;
    }
    let Some(length) = read_u32_be(blob, 4) else {
        return s;
    };
    let blob = &blob[..blob.len().min(length as usize)];
    let Some(count) = read_u32_be(blob, 8) else {
        return s;
    };
    s.present = true;
    let mut best_cd: Option<(u32, usize)> = None; // (slot, offset) — prefer the primary CodeDirectory
    for i in 0..count.min(MAX_BLOBS) as usize {
        let (Some(slot), Some(off)) =
            (read_u32_be(blob, 12 + i * 8), read_u32_be(blob, 16 + i * 8))
        else {
            break;
        };
        let off = off as usize;
        let magic = read_u32_be(blob, off);
        let blen = read_u32_be(blob, off + 4).unwrap_or(0) as usize;
        if magic == Some(CSMAGIC_CODEDIRECTORY) {
            s.code_directories += 1;
        }
        match slot {
            CSSLOT_CODEDIRECTORY => best_cd = Some((slot, off)),
            0x1000..=0x1004 if best_cd.is_none() => best_cd = Some((slot, off)),
            CSSLOT_REQUIREMENTS => s.has_requirements = true,
            CSSLOT_ENTITLEMENTS if magic == Some(CSMAGIC_EMBEDDED_ENTITLEMENTS) => {
                let end = off.saturating_add(blen).min(blob.len());
                if let Some(xml) = blob.get(off + 8..end) {
                    let xml = &xml[..xml.len().min(MAX_ENTITLEMENTS)];
                    s.entitlements = Some(String::from_utf8_lossy(xml).into_owned());
                }
            }
            CSSLOT_DER_ENTITLEMENTS => s.der_entitlements = true,
            CSSLOT_SIGNATURESLOT if magic == Some(CSMAGIC_BLOBWRAPPER) => {
                s.has_cms = blen > 8;
                let end = off.saturating_add(blen).min(blob.len());
                if let Some(cms) = blob.get(off + 8..end) {
                    let cms = &cms[..cms.len().min(MAX_CMS_SCAN)];
                    s.cms_timestamp = contains(cms, OID_TIMESTAMP_TOKEN);
                    s.cms_developer_id = contains(cms, b"Developer ID Application");
                    s.cms_apple_development =
                        contains(cms, b"Apple Development") || contains(cms, b"Mac Developer");
                    s.cms_app_store = contains(cms, b"Apple Mac OS Application Signing");
                    s.cms_apple_software = contains(cms, b"Software Signing");
                }
            }
            _ => {}
        }
    }
    if let Some((_, off)) = best_cd {
        if read_u32_be(blob, off) == Some(CSMAGIC_CODEDIRECTORY) {
            let cd_len = read_u32_be(blob, off + 4).unwrap_or(0) as usize;
            let cd = blob
                .get(off..off.saturating_add(cd_len).min(blob.len()))
                .unwrap_or(&[]);
            let version = read_u32_be(cd, 8).unwrap_or(0);
            let flags = read_u32_be(cd, 12).unwrap_or(0);
            s.flags = flags;
            s.hash_type = cd.get(37).copied().unwrap_or(0);
            s.adhoc = flags & CS_ADHOC != 0;
            s.runtime = flags & CS_RUNTIME != 0;
            s.linker_signed = flags & CS_LINKER_SIGNED != 0;
            if let Some(ident_off) = read_u32_be(cd, 20) {
                s.identifier = cstring(cd, ident_off as usize);
            }
            if version >= 0x20200 {
                if let Some(team_off) = read_u32_be(cd, 48).filter(|&t| t != 0) {
                    s.team_id = cstring(cd, team_off as usize);
                }
            }
        }
    }
    s
}

fn cstring(b: &[u8], off: usize) -> Option<String> {
    let raw = read_cstr(b, off, 1024)?;
    if raw.is_empty() {
        return None;
    }
    std::str::from_utf8(raw).ok().map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::MachOBuilder;

    #[test]
    fn parses_adhoc_signature_with_entitlements() {
        let bin = MachOBuilder::new_arm64_execute()
            .code_signature(true, Some("TEAM123456"), Some("<plist><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>"))
            .build();
        let s = code_signature_summary(&bin).unwrap();
        assert!(s.present);
        assert!(s.adhoc);
        assert!(!s.has_cms);
        assert_eq!(s.team_id.as_deref(), Some("TEAM123456"));
        assert_eq!(s.identifier.as_deref(), Some("com.example.test"));
        assert!(s.entitlements.unwrap().contains("get-task-allow"));
    }

    #[test]
    fn unsigned_binary() {
        let bin = MachOBuilder::new_arm64_execute().build();
        let s = code_signature_summary(&bin).unwrap();
        assert!(!s.present);
        assert!(code_signature_summary(b"not a macho").is_none());
    }
}
