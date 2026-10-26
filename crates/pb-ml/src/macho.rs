//! Low-level, bounds-checked Mach-O helpers that complement goblin.
//!
//! goblin parses headers, load commands, segments and sections well, but some of its helpers are
//! not safe on hostile input (`MachO::exports()` recurses without cycle detection, `imports()` can
//! be asked to materialise billions of entries by one bind opcode, fat 64-bit headers are not
//! supported). The equivalent logic lives here, with explicit caps on every count read from the file.

use crate::MlError;
use goblin::mach::MachO;

pub(crate) const CPU_TYPE_X86: u32 = 7;
pub(crate) const CPU_TYPE_X86_64: u32 = 0x0100_0007;
pub(crate) const CPU_TYPE_ARM: u32 = 12;
pub(crate) const CPU_TYPE_ARM64: u32 = 0x0100_000c;
pub(crate) const CPU_TYPE_ARM64_32: u32 = 0x0200_000c;
pub(crate) const CPU_TYPE_POWERPC: u32 = 18;
pub(crate) const CPU_TYPE_POWERPC64: u32 = 0x0100_0012;

/// Universal headers with more slices than this are rejected (real ones have 1–4).
pub(crate) const MAX_FAT_ARCHES: u32 = 32;
/// Max symbol-table entries inspected.
pub(crate) const MAX_SYMBOLS: usize = 500_000;
/// Max import names collected (bind opcodes + chained fixups + symtab).
pub(crate) const MAX_IMPORTS: usize = 200_000;
/// Max export-trie nodes visited.
pub(crate) const MAX_TRIE_NODES: usize = 200_000;

const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;

/// One architecture slice of a universal binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FatSlice {
    pub cputype: u32,
    pub offset: usize,
    pub size: usize,
}

impl FatSlice {
    pub(crate) fn bytes<'a>(&self, data: &'a [u8]) -> Option<&'a [u8]> {
        data.get(self.offset..self.offset.checked_add(self.size)?)
    }
}

/// Is this a known, plausible CPU type (used to tell universal binaries from Java class files)?
pub(crate) fn is_known_cputype(cputype: u32) -> bool {
    matches!(
        cputype,
        CPU_TYPE_X86
            | CPU_TYPE_X86_64
            | CPU_TYPE_ARM
            | CPU_TYPE_ARM64
            | CPU_TYPE_ARM64_32
            | CPU_TYPE_POWERPC
            | CPU_TYPE_POWERPC64
    )
}

pub(crate) fn read_u32_be(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

pub(crate) fn read_u32(b: &[u8], off: usize, le: bool) -> Option<u32> {
    let s = b.get(off..off.checked_add(4)?)?;
    let a = [s[0], s[1], s[2], s[3]];
    Some(if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    })
}

pub(crate) fn read_u64(b: &[u8], off: usize, le: bool) -> Option<u64> {
    let s = b.get(off..off.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(if le {
        u64::from_le_bytes(a)
    } else {
        u64::from_be_bytes(a)
    })
}

fn read_u64_be(b: &[u8], off: usize) -> Option<u64> {
    read_u64(b, off, false)
}

/// Unsigned LEB128 (at most 10 bytes).
pub(crate) fn read_uleb(b: &[u8], off: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *b.get(*off)?;
        *off += 1;
        if shift < 64 {
            result |= u64::from(byte & 0x7f) << shift;
        }
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 70 {
            return None;
        }
    }
}

/// NUL-terminated byte string starting at `off`, at most `max` bytes long (without the NUL).
pub(crate) fn read_cstr(b: &[u8], off: usize, max: usize) -> Option<&[u8]> {
    let rest = b.get(off..)?;
    let window = &rest[..rest.len().min(max.saturating_add(1))];
    let end = window.iter().position(|&c| c == 0)?;
    Some(&window[..end])
}

/// Byte slice `[off, off+len)` of `b`, if fully in bounds.
pub(crate) fn sub(b: &[u8], off: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(off).ok()?;
    let len = usize::try_from(len).ok()?;
    b.get(start..start.checked_add(len)?)
}

/// Parses a universal header. `Ok(None)` when `bytes` is not a universal binary.
pub(crate) fn parse_fat(bytes: &[u8]) -> Result<Option<Vec<FatSlice>>, MlError> {
    let magic = match read_u32_be(bytes, 0) {
        Some(m) => m,
        None => return Ok(None),
    };
    let entry_size = match magic {
        FAT_MAGIC => 20usize,
        FAT_MAGIC_64 => 32usize,
        _ => return Ok(None),
    };
    let nfat =
        read_u32_be(bytes, 4).ok_or_else(|| MlError::Malformed("truncated fat header".into()))?;
    if nfat == 0 || nfat > MAX_FAT_ARCHES {
        return Err(MlError::Malformed(format!(
            "implausible fat arch count {nfat}"
        )));
    }
    let mut slices = Vec::new();
    for i in 0..nfat as usize {
        let base = 8 + i * entry_size;
        let cputype = read_u32_be(bytes, base)
            .ok_or_else(|| MlError::Malformed("truncated fat arch".into()))?;
        let (offset, size) = if entry_size == 20 {
            (
                read_u32_be(bytes, base + 8).map(u64::from),
                read_u32_be(bytes, base + 12).map(u64::from),
            )
        } else {
            (read_u64_be(bytes, base + 8), read_u64_be(bytes, base + 16))
        };
        let (Some(offset), Some(size)) = (offset, size) else {
            return Err(MlError::Malformed("truncated fat arch".into()));
        };
        let (Ok(offset), Ok(size)) = (usize::try_from(offset), usize::try_from(size)) else {
            continue;
        };
        let slice = FatSlice {
            cputype,
            offset,
            size,
        };
        if size > 0 && slice.bytes(bytes).is_some() {
            slices.push(slice);
        }
    }
    if slices.is_empty() {
        return Err(MlError::Malformed(
            "no valid slice in universal binary".into(),
        ));
    }
    Ok(Some(slices))
}

/// Cheap check that a `0xCAFEBABE` header is a universal binary and not a Java class file:
/// small arch count (Java's major version, >= 45, sits where `nfat_arch` is) and a known first cputype.
pub fn plausible_fat_header(bytes: &[u8]) -> bool {
    let Some(nfat) = read_u32_be(bytes, 4) else {
        return false;
    };
    if nfat == 0 || nfat > 20 {
        return false;
    }
    read_u32_be(bytes, 8).is_some_and(is_known_cputype)
}

/// Picks the slice to analyse: arm64 first, then the first slice goblin can parse.
pub(crate) fn select_slice<'a>(
    bytes: &'a [u8],
    slices: &[FatSlice],
) -> Result<(FatSlice, &'a [u8], MachO<'a>), MlError> {
    let mut order: Vec<FatSlice> = slices
        .iter()
        .copied()
        .filter(|s| s.cputype == CPU_TYPE_ARM64)
        .collect();
    order.extend(
        slices
            .iter()
            .copied()
            .filter(|s| s.cputype != CPU_TYPE_ARM64),
    );
    let mut last_err = String::from("no slice");
    for s in order {
        let Some(data) = s.bytes(bytes) else { continue };
        match MachO::parse_lossy(data, 0) {
            Ok(m) => return Ok((s, data, m)),
            Err(e) => last_err = e.to_string(),
        }
    }
    Err(MlError::Malformed(last_err))
}

// ------------------------------------------------------------------------------------------------
// Imports / exports
// ------------------------------------------------------------------------------------------------

/// Collects the symbol names referenced by a (lazy) bind opcode stream. Linear in the stream size:
/// "bind N times" opcodes are skipped, never expanded.
pub(crate) fn bind_symbol_names<'a>(stream: &'a [u8], out: &mut Vec<&'a [u8]>, cap: usize) {
    let mut off = 0usize;
    while off < stream.len() && out.len() < cap {
        let byte = stream[off];
        off += 1;
        let opcode = byte & 0xf0;
        let imm = byte & 0x0f;
        let ok = match opcode {
            0x00 | 0x10 | 0x30 | 0x50 | 0x90 | 0xb0 => true, // DONE, ORDINAL_IMM, SPECIAL_IMM, TYPE_IMM, DO_BIND, DO_BIND_IMM_SCALED
            0x20 | 0x60 | 0x70 | 0x80 | 0xa0 => read_uleb(stream, &mut off).is_some(), // *_ULEB / SLEB (same encoding length)
            0x40 => match read_cstr(stream, off, 4096) {
                Some(name) => {
                    off += name.len() + 1;
                    if !name.is_empty() {
                        out.push(name);
                    }
                    true
                }
                None => false,
            },
            0xc0 => read_uleb(stream, &mut off).is_some() && read_uleb(stream, &mut off).is_some(),
            0xd0 => match imm {
                0x00 => read_uleb(stream, &mut off).is_some(),
                0x01 => true,
                _ => false,
            },
            _ => false,
        };
        if !ok {
            break;
        }
    }
}

/// Collects import names from an `LC_DYLD_CHAINED_FIXUPS` payload (`dyld_chained_fixups_header`).
pub(crate) fn chained_import_names<'a>(
    data: &'a [u8],
    le: bool,
    out: &mut Vec<&'a [u8]>,
    cap: usize,
) {
    let (
        Some(imports_offset),
        Some(symbols_offset),
        Some(imports_count),
        Some(imports_format),
        Some(symbols_format),
    ) = (
        read_u32(data, 8, le),
        read_u32(data, 12, le),
        read_u32(data, 16, le),
        read_u32(data, 20, le),
        read_u32(data, 24, le),
    )
    else {
        return;
    };
    if symbols_format != 0 {
        return; // zlib-compressed symbol pool: not worth decompressing for features
    }
    let entry = match imports_format {
        1 => 4usize,
        2 => 8,
        3 => 16,
        _ => return,
    };
    let imports_offset = imports_offset as usize;
    let available = data.len().saturating_sub(imports_offset) / entry;
    let n = (imports_count as usize)
        .min(available)
        .min(cap.saturating_sub(out.len()));
    for i in 0..n {
        let at = imports_offset + i * entry;
        let name_offset = if imports_format == 3 {
            match read_u64(data, at, le) {
                Some(raw) => raw >> 32,
                None => break,
            }
        } else {
            match read_u32(data, at, le) {
                Some(raw) => u64::from(raw >> 9),
                None => break,
            }
        };
        let Some(pos) = (symbols_offset as u64)
            .checked_add(name_offset)
            .and_then(|p| usize::try_from(p).ok())
        else {
            continue;
        };
        if let Some(name) = read_cstr(data, pos, 4096) {
            if !name.is_empty() {
                out.push(name);
            }
        }
    }
}

/// Counts terminal nodes (exported symbols) of an export trie, iteratively, with cycle detection.
pub(crate) fn count_trie_exports(trie: &[u8]) -> u64 {
    let mut count = 0u64;
    if trie.is_empty() {
        return 0;
    }
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![0usize];
    while let Some(node) = stack.pop() {
        if visited.len() >= MAX_TRIE_NODES {
            break;
        }
        if !visited.insert(node) {
            continue;
        }
        let mut off = node;
        let Some(terminal_size) = read_uleb(trie, &mut off) else {
            continue;
        };
        if terminal_size > 0 {
            count += 1;
        }
        let Some(children) = usize::try_from(terminal_size)
            .ok()
            .and_then(|t| off.checked_add(t))
        else {
            continue;
        };
        let Some(&nchildren) = trie.get(children) else {
            continue;
        };
        let mut off = children + 1;
        for _ in 0..nchildren {
            let Some(edge) = read_cstr(trie, off, 4096) else {
                break;
            };
            off += edge.len() + 1;
            let Some(child) = read_uleb(trie, &mut off) else {
                break;
            };
            if let Ok(child) = usize::try_from(child) {
                if child < trie.len() && !visited.contains(&child) {
                    stack.push(child);
                }
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uleb() {
        let mut off = 0;
        assert_eq!(read_uleb(&[0xe5, 0x8e, 0x26], &mut off), Some(624_485));
        assert_eq!(off, 3);
        let mut off = 0;
        assert_eq!(read_uleb(&[0x80; 12], &mut off), None);
    }

    #[test]
    fn bind_names_do_not_expand_repeat_opcodes() {
        // SET_SYMBOL "_socket", DO_BIND_ULEB_TIMES_SKIPPING_ULEB(huge, 0), SET_SYMBOL "_connect", DONE
        let mut s = vec![0x40];
        s.extend_from_slice(b"_socket\0");
        s.extend_from_slice(&[0xc0, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x00]);
        s.push(0x40);
        s.extend_from_slice(b"_connect\0");
        s.push(0x00);
        let mut out = Vec::new();
        bind_symbol_names(&s, &mut out, 100);
        assert_eq!(out, vec![&b"_socket"[..], &b"_connect"[..]]);
    }

    #[test]
    fn trie_with_cycle_terminates() {
        // root: terminal_size 0, 1 child "a" -> node at offset 0 (itself)
        let trie = [0x00, 0x01, b'a', 0x00, 0x00];
        assert_eq!(count_trie_exports(&trie), 0);
        // root -> child "_f" at 6: terminal (size 2: flags 0, addr 0), 0 children
        let trie = [0x00, 0x01, b'_', b'f', 0x00, 0x06, 0x02, 0x00, 0x00, 0x00];
        assert_eq!(count_trie_exports(&trie), 1);
    }

    #[test]
    fn fat_header_limits() {
        let mut b = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 45];
        b.resize(64, 0);
        assert!(parse_fat(&b).is_err()); // Java class file (major 45)
        assert!(!plausible_fat_header(&b));
    }
}
