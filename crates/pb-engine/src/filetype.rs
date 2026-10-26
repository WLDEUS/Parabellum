//! File typing by magic bytes (+ extension for scripts), and the cheap "risky type" pre-filter
//! used for scans of very large volumes.

use pb_core::model::FileKind;
use std::io::Read;
use std::path::Path;

/// Bytes of the file head needed by [`detect`] (tar's `ustar` magic sits at offset 257).
pub const HEAD_LEN: usize = 512;
/// Bytes of the file tail needed to recognise a UDIF disk image (`koly` trailer).
pub const TAIL_LEN: usize = 512;

const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh",
    "command",
    "py",
    "rb",
    "pl",
    "js",
    "scpt",
    "applescript",
    "zsh",
    "bash",
    "jxa",
    "tool",
    "csh",
    "ksh",
    "php",
    "lua",
];

/// Container / app-related path components: anything inside them is considered risky.
const BUNDLE_EXTENSIONS: &[&str] = &[
    "app",
    "framework",
    "bundle",
    "plugin",
    "kext",
    "appex",
    "xpc",
    "systemextension",
    "dext",
    "prefPane",
    "saver",
    "qlgenerator",
    "mdimporter",
    "workflow",
    "action",
    "osax",
    "scptd",
];

/// Extensions always considered risky by [`is_risky`].
const RISKY_EXTENSIONS: &[&str] = &[
    // executables, libraries
    "dylib",
    "so",
    "o",
    "a",
    "bin",
    "elf",
    "jar",
    "class",
    "com",
    "exe",
    "dll",
    "scr",
    "msi",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "wsf",
    // containers / installers / disk images
    "pkg",
    "mpkg",
    "dmg",
    "img",
    "smi",
    "iso",
    "sparseimage",
    "sparsebundle",
    "zip",
    "tar",
    "gz",
    "tgz",
    "bz2",
    "tbz",
    "tbz2",
    "xz",
    "txz",
    "7z",
    "rar",
    "xar",
    "cpio",
    "lz",
    "lzma",
    "zst",
    "z",
    "cab",
    // configuration that drives execution
    "plist",
    "mobileconfig",
    "terminal",
    "webloc",
    "inetloc",
    "fileloc",
    "url",
    "desktop",
    // documents that can carry active content
    "pdf",
    "doc",
    "docm",
    "dot",
    "dotm",
    "xls",
    "xlsm",
    "xlsb",
    "xltm",
    "xla",
    "xlam",
    "ppt",
    "pptm",
    "potm",
    "ppsm",
    "rtf",
    "html",
    "htm",
    "hta",
    "svg",
    "chm",
    "one",
];

fn ext_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
}

/// True when `path` has a script extension.
pub fn is_script_extension(path: &Path) -> bool {
    ext_lower(path).is_some_and(|e| SCRIPT_EXTENSIONS.contains(&e.as_str()))
}

fn is_thin_macho(h: &[u8]) -> bool {
    matches!(
        h.get(0..4),
        Some([0xfe, 0xed, 0xfa, 0xce])
            | Some([0xce, 0xfa, 0xed, 0xfe])
            | Some([0xfe, 0xed, 0xfa, 0xcf])
            | Some([0xcf, 0xfa, 0xed, 0xfe])
    )
}

fn is_fat_macho(h: &[u8]) -> bool {
    match h.get(0..4) {
        // FAT_MAGIC / FAT_MAGIC_64: disambiguate from Java class files (same 0xCAFEBABE magic).
        Some([0xca, 0xfe, 0xba, 0xbe]) | Some([0xca, 0xfe, 0xba, 0xbf]) => {
            pb_ml::plausible_fat_header(h)
        }
        // Byte-swapped FAT_CIGAM (never produced by Apple tools, but recognised).
        Some([0xbe, 0xba, 0xfe, 0xca]) => {
            let n = h
                .get(4..8)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0);
            (1..=20).contains(&n)
        }
        _ => false,
    }
}

/// Detects the kind of a file from its first bytes (`head`, ideally [`HEAD_LEN`] bytes), its last
/// bytes (`tail`, for disk images; `None` if unknown) and its path (script extensions).
pub fn detect(head: &[u8], tail: Option<&[u8]>, path: &Path) -> FileKind {
    if is_thin_macho(head) {
        return FileKind::MachO;
    }
    if is_fat_macho(head) {
        return FileKind::FatMachO;
    }
    // UDIF trailer first: compressed DMG data forks may start with zlib/bzip2/lzfse streams.
    if tail.is_some_and(|t| t.len() >= 512 && t[t.len() - 512..].starts_with(b"koly")) {
        return FileKind::Dmg;
    }
    if head.starts_with(b"xar!") {
        return FileKind::Pkg;
    }
    if head.starts_with(b"PK\x03\x04")
        || head.starts_with(b"PK\x05\x06")
        || head.starts_with(b"PK\x07\x08")
    {
        return FileKind::Zip;
    }
    if head.starts_with(&[0x1f, 0x8b])
        || head.starts_with(b"BZh")
        || head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00])
        || head.starts_with(&[b'7', b'z', 0xbc, 0xaf, 0x27, 0x1c])
        || head.starts_with(b"Rar!\x1a\x07")
        || head.get(257..262) == Some(b"ustar")
    {
        return FileKind::Archive;
    }
    if head.starts_with(b"#!") || head.starts_with(b"FasdUAS") || is_script_extension(path) {
        return FileKind::Script;
    }
    if head.starts_with(b"%PDF")
        || head.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
        || head.starts_with(b"{\\rtf")
    {
        return FileKind::Document;
    }
    FileKind::Other
}

/// Is `path` inside (or equal to) an app-like bundle directory (`.app`, `.framework`, …)?
pub fn in_bundle(path: &Path) -> bool {
    path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        s.rsplit_once('.').is_some_and(|(stem, ext)| {
            !stem.is_empty()
                && BUNDLE_EXTENSIONS
                    .iter()
                    .any(|b| b.eq_ignore_ascii_case(ext))
        })
    })
}

/// Cheap pre-filter for huge scans (`ScanOptions::only_risky_types`): decides from the path, the
/// permission bits and at most the first [`HEAD_LEN`] bytes, never the whole file.
///
/// Risky = executable bit set, inside an app-like bundle, risky extension (executables, scripts,
/// archives, disk images, installers, plists/profiles, documents with active content), or magic
/// bytes of a Mach-O / archive / script / PDF / OLE document. Unreadable files count as risky (the
/// full scan will report the error).
pub fn is_risky(path: &Path, mode: u32) -> bool {
    if mode & 0o111 != 0 || in_bundle(path) {
        return true;
    }
    if let Some(e) = ext_lower(path) {
        if RISKY_EXTENSIONS.contains(&e.as_str()) || SCRIPT_EXTENSIONS.contains(&e.as_str()) {
            return true;
        }
    }
    let mut head = [0u8; HEAD_LEN];
    let n = match open_nonblocking(path).and_then(|f| read_up_to(f, &mut head)) {
        Ok(n) => n,
        Err(_) => return true,
    };
    let head = &head[..n];
    if head.starts_with(b"bplist") {
        return true;
    }
    !matches!(detect(head, None, path), FileKind::Other)
}

/// Opens a file for reading without blocking on FIFOs and without following a final symlink.
pub(crate) fn open_nonblocking(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
}

/// Reads until `buf` is full or EOF.
pub(crate) fn read_up_to<R: Read>(mut r: R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> &Path {
        Path::new(s)
    }

    #[test]
    fn magic_detection() {
        assert_eq!(
            detect(&[0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1], None, p("x")),
            FileKind::MachO
        );
        assert_eq!(
            detect(&[0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 7], None, p("x")),
            FileKind::MachO
        );
        let fat = [
            0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2, 0x01, 0, 0, 0x0c, 0, 0, 0, 0,
        ];
        assert_eq!(detect(&fat, None, p("x")), FileKind::FatMachO);
        let java = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34, 0, 0, 0, 0];
        assert_eq!(detect(&java, None, p("A.class")), FileKind::Other);
        assert_eq!(detect(b"xar!\x00\x1c", None, p("x.pkg")), FileKind::Pkg);
        assert_eq!(detect(b"PK\x03\x04rest", None, p("x")), FileKind::Zip);
        assert_eq!(detect(&[0x1f, 0x8b, 8, 0], None, p("x")), FileKind::Archive);
        let mut tar = vec![0u8; 512];
        tar[257..262].copy_from_slice(b"ustar");
        assert_eq!(detect(&tar, None, p("x")), FileKind::Archive);
        let mut tail = vec![0u8; 512];
        tail[..4].copy_from_slice(b"koly");
        assert_eq!(detect(b"\0\0\0\0", Some(&tail), p("x.dmg")), FileKind::Dmg);
        assert_eq!(detect(b"#!/bin/sh\n", None, p("x")), FileKind::Script);
        assert_eq!(detect(b"FasdUAS 1.101.10", None, p("x")), FileKind::Script);
        assert_eq!(detect(b"echo hi", None, p("run.command")), FileKind::Script);
        assert_eq!(detect(b"%PDF-1.7", None, p("x")), FileKind::Document);
        assert_eq!(detect(b"hello", None, p("notes.txt")), FileKind::Other);
    }

    #[test]
    fn bundles_and_risky() {
        assert!(in_bundle(p(
            "/Applications/Foo.app/Contents/Resources/x.png"
        )));
        assert!(in_bundle(p("/Library/Frameworks/X.framework/X")));
        assert!(!in_bundle(p("/Users/q/Pictures/cat.jpg")));
        let d = tempfile::tempdir().unwrap();
        let jpg = d.path().join("cat.jpg");
        std::fs::write(&jpg, [0xff, 0xd8, 0xff, 0xe0]).unwrap();
        assert!(!is_risky(&jpg, 0o644));
        assert!(is_risky(&jpg, 0o755));
        let hidden_macho = d.path().join("photo.jpg");
        std::fs::write(&hidden_macho, [0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]).unwrap();
        assert!(is_risky(&hidden_macho, 0o644));
        assert!(is_risky(&d.path().join("doc.docm"), 0o644));
        assert!(is_risky(&d.path().join("x.plist"), 0o644));
    }
}
