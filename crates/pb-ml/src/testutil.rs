//! Test-only synthesis of small but valid Mach-O files (thin and universal). Enabled for this
//! crate's tests and, through the `test-util` feature, for dependent crates' tests.
#![allow(missing_docs, clippy::too_many_arguments)]

const LC_SEGMENT_64: u32 = 0x19;
const LC_SYMTAB: u32 = 0x2;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_MAIN: u32 = 0x8000_0028;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_RPATH: u32 = 0x8000_001c;

pub const CPU_ARM64: u32 = 0x0100_000c;
pub const CPU_X86_64: u32 = 0x0100_0007;

fn align(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

fn put32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn name16(s: &str) -> [u8; 16] {
    let mut n = [0u8; 16];
    n[..s.len()].copy_from_slice(s.as_bytes());
    n
}

/// Builder for a little-endian 64-bit Mach-O executable.
pub struct MachOBuilder {
    cputype: u32,
    filetype: u32,
    flags: u32,
    text: Vec<u8>,
    cstrings: Vec<u8>,
    dylibs: Vec<String>,
    rpaths: Vec<String>,
    imports: Vec<String>,
    codesig: Option<(bool, Option<String>, Option<String>)>,
}

impl MachOBuilder {
    pub fn new_arm64_execute() -> Self {
        Self {
            cputype: CPU_ARM64,
            filetype: 2,
            flags: 0x0020_0085, // PIE | TWOLEVEL | DYLDLINK | NOUNDEFS
            text: (0..256u32)
                .map(|i| (i.wrapping_mul(37) ^ 0x5a) as u8)
                .collect(),
            cstrings: Vec::new(),
            dylibs: vec!["/usr/lib/libSystem.B.dylib".into()],
            rpaths: Vec::new(),
            imports: Vec::new(),
            codesig: None,
        }
    }
    pub fn cputype(mut self, c: u32) -> Self {
        self.cputype = c;
        self
    }
    pub fn filetype(mut self, t: u32) -> Self {
        self.filetype = t;
        self
    }
    pub fn cstrings(mut self, strings: &[&str]) -> Self {
        for s in strings {
            self.cstrings.extend_from_slice(s.as_bytes());
            self.cstrings.push(0);
        }
        self
    }
    pub fn dylib(mut self, path: &str) -> Self {
        self.dylibs.push(path.into());
        self
    }
    pub fn rpath(mut self, path: &str) -> Self {
        self.rpaths.push(path.into());
        self
    }
    pub fn imports(mut self, names: &[&str]) -> Self {
        self.imports.extend(names.iter().map(|s| s.to_string()));
        self
    }
    pub fn code_signature(mut self, adhoc: bool, team: Option<&str>, ents: Option<&str>) -> Self {
        self.codesig = Some((adhoc, team.map(Into::into), ents.map(Into::into)));
        self
    }

    fn superblob(&self) -> Vec<u8> {
        let Some((adhoc, team, ents)) = &self.codesig else {
            return Vec::new();
        };
        // CodeDirectory (v 0x20400, 88-byte header) + identifier + team id
        let ident = b"com.example.test\0";
        let mut cd = Vec::new();
        let ident_off = 88u32;
        let team_off = if team.is_some() {
            ident_off + ident.len() as u32
        } else {
            0
        };
        let mut tail = ident.to_vec();
        if let Some(t) = team {
            tail.extend_from_slice(t.as_bytes());
            tail.push(0);
        }
        let cd_len = 88 + tail.len() as u32;
        let be = |cd: &mut Vec<u8>, v: u32| cd.extend_from_slice(&v.to_be_bytes());
        be(&mut cd, 0xfade_0c02);
        be(&mut cd, cd_len);
        be(&mut cd, 0x20400);
        be(&mut cd, if *adhoc { 0x2 } else { 0x1_0000 });
        be(&mut cd, cd_len); // hashOffset
        be(&mut cd, ident_off);
        be(&mut cd, 0); // nSpecialSlots
        be(&mut cd, 0); // nCodeSlots
        be(&mut cd, 0); // codeLimit
        cd.extend_from_slice(&[32, 2, 0, 12]); // hashSize, hashType, platform, pageSize
        be(&mut cd, 0); // spare2
        be(&mut cd, 0); // scatterOffset
        be(&mut cd, team_off);
        cd.resize(88, 0);
        cd.extend_from_slice(&tail);

        let mut blobs: Vec<(u32, Vec<u8>)> = vec![(0, cd)];
        if let Some(x) = ents {
            let mut e = Vec::new();
            e.extend_from_slice(&0xfade_7171u32.to_be_bytes());
            e.extend_from_slice(&(8 + x.len() as u32).to_be_bytes());
            e.extend_from_slice(x.as_bytes());
            blobs.push((5, e));
        }
        let mut cms = Vec::new();
        cms.extend_from_slice(&0xfade_0b01u32.to_be_bytes());
        let cms_body: Vec<u8> = if *adhoc { Vec::new() } else { vec![0x30; 64] };
        cms.extend_from_slice(&(8 + cms_body.len() as u32).to_be_bytes());
        cms.extend_from_slice(&cms_body);
        blobs.push((0x10000, cms));

        let header_len = 12 + 8 * blobs.len();
        let total: usize = header_len + blobs.iter().map(|b| b.1.len()).sum::<usize>();
        let mut sb = Vec::new();
        sb.extend_from_slice(&0xfade_0cc0u32.to_be_bytes());
        sb.extend_from_slice(&(total as u32).to_be_bytes());
        sb.extend_from_slice(&(blobs.len() as u32).to_be_bytes());
        let mut off = header_len;
        for (slot, b) in &blobs {
            sb.extend_from_slice(&slot.to_be_bytes());
            sb.extend_from_slice(&(off as u32).to_be_bytes());
            off += b.len();
        }
        for (_, b) in &blobs {
            sb.extend_from_slice(b);
        }
        sb
    }

    pub fn build(self) -> Vec<u8> {
        let dylib_cmd_len = |p: &str| align(24 + p.len() + 1, 8);
        let rpath_cmd_len = |p: &str| align(12 + p.len() + 1, 8);
        let has_sig = self.codesig.is_some();
        let sizeofcmds = 72 // __PAGEZERO
            + 72 + 2 * 80 // __TEXT + 2 sections
            + 72 // __LINKEDIT
            + 24 // LC_SYMTAB
            + self.dylibs.iter().map(|d| dylib_cmd_len(d)).sum::<usize>()
            + self.rpaths.iter().map(|d| rpath_cmd_len(d)).sum::<usize>()
            + 24 // LC_MAIN
            + 24 // LC_BUILD_VERSION
            + if has_sig { 16 } else { 0 };
        let ncmds = 6 + self.dylibs.len() + self.rpaths.len() + usize::from(has_sig);

        let text_off = align(32 + sizeofcmds, 16);
        let cstr_off = text_off + self.text.len();
        let text_end = align(cstr_off + self.cstrings.len(), 16);
        let linkedit_off = text_end;
        // symtab: undefined externals
        let mut strtab = vec![0u8, b' ', 0u8];
        let mut nlist = Vec::new();
        for name in &self.imports {
            let strx = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            put32(&mut nlist, strx);
            nlist.push(0x01); // N_UNDF | N_EXT
            nlist.push(0);
            nlist.extend_from_slice(&0x0100u16.to_le_bytes()); // library ordinal 1
            put64(&mut nlist, 0);
        }
        let symoff = linkedit_off;
        let stroff = symoff + nlist.len();
        let sig = self.superblob();
        let sig_off = align(stroff + strtab.len(), 16);
        let file_end = sig_off + sig.len();

        let mut b = Vec::with_capacity(file_end);
        // mach_header_64
        put32(&mut b, 0xfeed_facf);
        put32(&mut b, self.cputype);
        put32(&mut b, if self.cputype == CPU_X86_64 { 3 } else { 0 });
        put32(&mut b, self.filetype);
        put32(&mut b, ncmds as u32);
        put32(&mut b, sizeofcmds as u32);
        put32(&mut b, self.flags);
        put32(&mut b, 0);

        let segment = |b: &mut Vec<u8>,
                       name: &str,
                       vmaddr: u64,
                       vmsize: u64,
                       fileoff: u64,
                       filesize: u64,
                       prot: u32,
                       nsects: u32| {
            put32(b, LC_SEGMENT_64);
            put32(b, 72 + 80 * nsects);
            b.extend_from_slice(&name16(name));
            put64(b, vmaddr);
            put64(b, vmsize);
            put64(b, fileoff);
            put64(b, filesize);
            put32(b, prot);
            put32(b, prot);
            put32(b, nsects);
            put32(b, 0);
        };
        let section =
            |b: &mut Vec<u8>, sect: &str, seg: &str, addr: u64, size: u64, off: u32, flags: u32| {
                b.extend_from_slice(&name16(sect));
                b.extend_from_slice(&name16(seg));
                put64(b, addr);
                put64(b, size);
                put32(b, off);
                put32(b, 4);
                put32(b, 0);
                put32(b, 0);
                put32(b, flags);
                put32(b, 0);
                put32(b, 0);
                put32(b, 0);
            };
        let base = 0x1_0000_0000u64;
        segment(&mut b, "__PAGEZERO", 0, base, 0, 0, 0, 0);
        segment(
            &mut b,
            "__TEXT",
            base,
            text_end as u64,
            0,
            text_end as u64,
            5,
            2,
        );
        section(
            &mut b,
            "__text",
            "__TEXT",
            base + text_off as u64,
            self.text.len() as u64,
            text_off as u32,
            0x8000_0400,
        );
        section(
            &mut b,
            "__cstring",
            "__TEXT",
            base + cstr_off as u64,
            self.cstrings.len() as u64,
            cstr_off as u32,
            0x2,
        );
        segment(
            &mut b,
            "__LINKEDIT",
            base + text_end as u64,
            align(file_end - linkedit_off, 0x4000) as u64,
            linkedit_off as u64,
            (file_end - linkedit_off) as u64,
            1,
            0,
        );
        // LC_SYMTAB
        put32(&mut b, LC_SYMTAB);
        put32(&mut b, 24);
        put32(&mut b, symoff as u32);
        put32(&mut b, self.imports.len() as u32);
        put32(&mut b, stroff as u32);
        put32(&mut b, strtab.len() as u32);
        for d in &self.dylibs {
            let len = dylib_cmd_len(d);
            let start = b.len();
            put32(&mut b, LC_LOAD_DYLIB);
            put32(&mut b, len as u32);
            put32(&mut b, 24);
            put32(&mut b, 2);
            put32(&mut b, 0x0001_0000);
            put32(&mut b, 0x0001_0000);
            b.extend_from_slice(d.as_bytes());
            b.resize(start + len, 0);
        }
        for r in &self.rpaths {
            let len = rpath_cmd_len(r);
            let start = b.len();
            put32(&mut b, LC_RPATH);
            put32(&mut b, len as u32);
            put32(&mut b, 12);
            b.extend_from_slice(r.as_bytes());
            b.resize(start + len, 0);
        }
        // LC_MAIN
        put32(&mut b, LC_MAIN);
        put32(&mut b, 24);
        put64(&mut b, text_off as u64);
        put64(&mut b, 0);
        // LC_BUILD_VERSION macOS 13.0, sdk 14.2
        put32(&mut b, LC_BUILD_VERSION);
        put32(&mut b, 24);
        put32(&mut b, 1);
        put32(&mut b, 0x000d_0000);
        put32(&mut b, 0x000e_0200);
        put32(&mut b, 0);
        if has_sig {
            put32(&mut b, LC_CODE_SIGNATURE);
            put32(&mut b, 16);
            put32(&mut b, sig_off as u32);
            put32(&mut b, sig.len() as u32);
        }
        assert_eq!(b.len(), 32 + sizeofcmds);
        b.resize(text_off, 0);
        b.extend_from_slice(&self.text);
        b.extend_from_slice(&self.cstrings);
        b.resize(linkedit_off, 0);
        b.extend_from_slice(&nlist);
        b.extend_from_slice(&strtab);
        b.resize(sig_off, 0);
        b.extend_from_slice(&sig);
        b
    }
}

/// Universal binary (FAT_MAGIC, 32-bit fat_arch entries) from `(cputype, slice)` pairs.
pub fn fat(slices: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
    b.extend_from_slice(&(slices.len() as u32).to_be_bytes());
    let mut off = 0x4000usize;
    let mut placed = Vec::new();
    for (cpu, s) in slices {
        b.extend_from_slice(&cpu.to_be_bytes());
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&(off as u32).to_be_bytes());
        b.extend_from_slice(&(s.len() as u32).to_be_bytes());
        b.extend_from_slice(&14u32.to_be_bytes());
        placed.push(off);
        off = align(off + s.len(), 0x4000);
    }
    for ((_, s), at) in slices.iter().zip(placed) {
        b.resize(at, 0);
        b.extend_from_slice(s);
    }
    b
}
