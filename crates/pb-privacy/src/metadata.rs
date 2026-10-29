//! Metadata removal into a cleaned copy (never in place unless asked). Used by the CLI as the user.
//!
//! Native (no dependency): JPEG (EXIF/GPS, XMP, IPTC/Photoshop, comments, MPF and trailing data after the
//! image; ICC colour profiles and JFIF/Adobe segments kept; a minimal EXIF with only the orientation is
//! written back when the photo was rotated), PNG (`tEXt`/`zTXt`/`iTXt`/`eXIf`/`tIME`), WebP (`EXIF`/`XMP `
//! chunks, VP8X flags fixed), Office Open XML (`docx`/`xlsx`/`pptx`…: author, last editor, dates, revision,
//! company / manager). Anything else goes through `exiftool` when it is installed (Homebrew).

use regex::Regex;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// What was done to one file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CleanReport {
    pub input: PathBuf,
    /// Cleaned file written (`<name>.clean.<ext>` next to the input, or the input itself in place).
    pub output: Option<PathBuf>,
    /// Human-readable list of what was removed (French), e.g. `GPS`, `EXIF (appareil, date)`.
    pub removed: Vec<String>,
    /// `native` or `exiftool`.
    pub method: String,
    pub error: Option<String>,
}

/// Inputs above this size are not loaded in memory (exiftool only).
const MAX_NATIVE: u64 = 512 * 1024 * 1024;
/// Where Homebrew installs exiftool (fixed paths: never resolved through `PATH`).
pub const EXIFTOOL_PATHS: [&str; 2] = ["/opt/homebrew/bin/exiftool", "/usr/local/bin/exiftool"];

/// Detected container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Jpeg,
    Png,
    Webp,
    Ooxml,
    Other,
}

/// Format from the content (magic bytes; OOXML = zip with `[Content_Types].xml` + `docProps/`).
pub fn detect(data: &[u8]) -> Format {
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Format::Jpeg
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Format::Png
    } else if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Format::Webp
    } else if data.starts_with(b"PK\x03\x04") && is_ooxml(data) {
        Format::Ooxml
    } else {
        Format::Other
    }
}

fn is_ooxml(data: &[u8]) -> bool {
    let Ok(mut z) = zip::ZipArchive::new(std::io::Cursor::new(data)) else {
        return false;
    };
    let names: Vec<String> = z.file_names().map(str::to_string).collect();
    let _ = &mut z;
    names.iter().any(|n| n == "[Content_Types].xml")
        && names.iter().any(|n| n.starts_with("docProps/"))
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_string());
    }
}

// ---------------------------------------------------------------------------------------------
// JPEG
// ---------------------------------------------------------------------------------------------

/// EXIF facts we care about: orientation (1..8) and whether a GPS IFD is present.
fn exif_facts(tiff: &[u8]) -> (Option<u16>, bool) {
    if tiff.len() < 8 {
        return (None, false);
    }
    let le = match &tiff[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return (None, false),
    };
    let u16_at = |o: usize| -> Option<u16> {
        let b = tiff.get(o..o + 2)?;
        Some(if le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    };
    let u32_at = |o: usize| -> Option<u32> {
        let b = tiff.get(o..o + 4)?;
        Some(if le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        })
    };
    if u16_at(2) != Some(42) {
        return (None, false);
    }
    let Some(ifd) = u32_at(4).map(|v| v as usize) else {
        return (None, false);
    };
    let Some(n) = u16_at(ifd) else {
        return (None, false);
    };
    let mut orientation = None;
    let mut gps = false;
    for i in 0..usize::from(n.min(512)) {
        let e = ifd + 2 + i * 12;
        let (Some(tag), Some(typ)) = (u16_at(e), u16_at(e + 2)) else {
            break;
        };
        match tag {
            0x0112 if typ == 3 => {
                orientation = u16_at(e + 8).filter(|o| (1..=8).contains(o));
            }
            0x8825 => gps = true,
            _ => {}
        }
    }
    (orientation, gps)
}

/// APP1 segment holding a minimal big-endian EXIF with only the Orientation tag.
fn minimal_exif(orientation: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(36);
    p.extend_from_slice(&[0xFF, 0xE1, 0x00, 0x22]);
    p.extend_from_slice(b"Exif\0\0");
    p.extend_from_slice(b"MM\x00\x2a\x00\x00\x00\x08");
    p.extend_from_slice(&[0x00, 0x01]); // one entry
    p.extend_from_slice(&[0x01, 0x12, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01]);
    p.extend_from_slice(&orientation.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x00]);
    p.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // no next IFD
    p
}

/// Clean a JPEG. Returns the new bytes and what was removed.
pub fn clean_jpeg(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), String> {
    if !data.starts_with(&[0xFF, 0xD8]) {
        return Err("JPEG invalide".into());
    }
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&[0xFF, 0xD8]);
    let mut removed = Vec::new();
    let mut orientation: Option<u16> = None;
    let mut insert_at = 2usize;
    let mut first_segment = true;
    let mut pos = 2usize;
    let mut ended = false;
    while pos < data.len() {
        if data[pos] != 0xFF {
            return Err(format!("JPEG invalide (octet inattendu à {pos})"));
        }
        // Fill bytes.
        let mut m = pos + 1;
        while m < data.len() && data[m] == 0xFF {
            m += 1;
        }
        let Some(&marker) = data.get(m) else {
            return Err("JPEG tronqué".into());
        };
        let seg_start = m - 1;
        if marker == 0xD9 {
            out.extend_from_slice(&[0xFF, 0xD9]);
            if m + 1 < data.len() {
                push_unique(&mut removed, "données après la fin de l'image");
            }
            ended = true;
            break;
        }
        if (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            out.extend_from_slice(&[0xFF, marker]);
            pos = m + 1;
            continue;
        }
        let len = data
            .get(m + 1..m + 3)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])))
            .ok_or("JPEG tronqué")?;
        if len < 2 || m + 1 + len > data.len() {
            return Err("JPEG tronqué (segment)".into());
        }
        let seg_end = m + 1 + len;
        let payload = &data[m + 3..seg_end];
        let is_first = first_segment;
        first_segment = false;
        match marker {
            0xDA => {
                // Start of scan: copy the header then the entropy-coded data up to the next real marker.
                out.extend_from_slice(&[0xFF, 0xDA]);
                out.extend_from_slice(&data[m + 1..seg_end]);
                let mut i = seg_end;
                while i + 1 < data.len() {
                    if data[i] == 0xFF {
                        let n = data[i + 1];
                        if n != 0x00 && n != 0xFF && !(0xD0..=0xD7).contains(&n) {
                            break;
                        }
                    }
                    i += 1;
                }
                if i + 1 >= data.len() {
                    // No EOI: keep everything (truncated file).
                    out.extend_from_slice(&data[seg_end..]);
                    pos = data.len();
                    continue;
                }
                out.extend_from_slice(&data[seg_end..i]);
                pos = i;
                continue;
            }
            0xE0 => {
                out.extend_from_slice(&data[seg_start..seg_end]);
                if is_first {
                    insert_at = out.len();
                }
            }
            0xE1 => {
                if payload.starts_with(b"Exif\0\0") {
                    let (o, gps) = exif_facts(&payload[6..]);
                    if o.is_some() {
                        orientation = o;
                    }
                    push_unique(&mut removed, "EXIF (appareil, dates, réglages)");
                    if gps {
                        push_unique(&mut removed, "GPS");
                    }
                } else if payload.starts_with(b"http://ns.adobe.com/") {
                    push_unique(&mut removed, "XMP");
                } else {
                    push_unique(&mut removed, "données d'application (APP1)");
                }
            }
            0xE2 if payload.starts_with(b"ICC_PROFILE\0") => {
                out.extend_from_slice(&data[seg_start..seg_end]);
            }
            0xE2 => push_unique(&mut removed, "MPF / FlashPix (aperçus)"),
            0xED => push_unique(&mut removed, "IPTC / Photoshop"),
            0xEE => out.extend_from_slice(&data[seg_start..seg_end]),
            0xFE => push_unique(&mut removed, "commentaire"),
            0xE3..=0xEF => push_unique(&mut removed, "données d'application"),
            _ => out.extend_from_slice(&data[seg_start..seg_end]),
        }
        pos = seg_end;
    }
    if !ended && pos < data.len() {
        return Err("JPEG invalide".into());
    }
    if let Some(o) = orientation.filter(|o| *o != 1) {
        let seg = minimal_exif(o);
        out.splice(insert_at..insert_at, seg);
    }
    Ok((out, removed))
}

// ---------------------------------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------------------------------

pub fn clean_png(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), String> {
    const SIG: &[u8] = b"\x89PNG\r\n\x1a\n";
    if !data.starts_with(SIG) {
        return Err("PNG invalide".into());
    }
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(SIG);
    let mut removed = Vec::new();
    let mut pos = SIG.len();
    let mut ended = false;
    while pos + 12 <= data.len() {
        let len =
            u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        let end = pos
            .checked_add(12)
            .and_then(|v| v.checked_add(len))
            .filter(|e| *e <= data.len())
            .ok_or("PNG tronqué")?;
        let typ = &data[pos + 4..pos + 8];
        match typ {
            b"tEXt" | b"zTXt" | b"iTXt" => {
                push_unique(&mut removed, "texte (auteur, logiciel, commentaires)")
            }
            b"eXIf" => push_unique(&mut removed, "EXIF"),
            b"tIME" => push_unique(&mut removed, "date de modification"),
            _ => out.extend_from_slice(&data[pos..end]),
        }
        pos = end;
        if typ == b"IEND" {
            ended = true;
            break;
        }
    }
    if !ended {
        return Err("PNG tronqué (IEND absent)".into());
    }
    if pos < data.len() {
        push_unique(&mut removed, "données après la fin de l'image");
    }
    Ok((out, removed))
}

// ---------------------------------------------------------------------------------------------
// WebP
// ---------------------------------------------------------------------------------------------

pub fn clean_webp(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), String> {
    if data.len() < 12 || &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return Err("WebP invalide".into());
    }
    let riff_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
    let end_all = (riff_len + 8).min(data.len());
    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(b"RIFF\0\0\0\0WEBP");
    let mut removed = Vec::new();
    let mut pos = 12usize;
    while pos + 8 <= end_all {
        let fourcc = &data[pos..pos + 4];
        let size = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]])
            as usize;
        let padded = size + (size & 1);
        let body_end = pos + 8 + size;
        if body_end > end_all {
            return Err("WebP tronqué".into());
        }
        let chunk_end = (pos + 8 + padded).min(end_all);
        match fourcc {
            b"EXIF" => push_unique(&mut removed, "EXIF"),
            b"XMP " => push_unique(&mut removed, "XMP"),
            b"VP8X" => {
                let start = out.len();
                out.extend_from_slice(&data[pos..chunk_end]);
                if size >= 1 {
                    // Flags: ICC 0x20, alpha 0x10, EXIF 0x08, XMP 0x04, animation 0x02.
                    out[start + 8] &= !0x0C;
                }
            }
            _ => out.extend_from_slice(&data[pos..chunk_end]),
        }
        if chunk_end - (pos + 8) < padded {
            out.push(0); // keep chunks even-aligned
        }
        pos = pos + 8 + padded;
    }
    if data.len() > riff_len + 8 {
        push_unique(&mut removed, "données après la fin de l'image");
    }
    let size = (out.len() - 8) as u32;
    out[4..8].copy_from_slice(&size.to_le_bytes());
    Ok((out, removed))
}

// ---------------------------------------------------------------------------------------------
// Office Open XML
// ---------------------------------------------------------------------------------------------

fn element_regex(name: &str) -> Regex {
    // Optional namespace prefix; self-closing or with content (no nesting in these properties).
    Regex::new(&format!(
        r"(?s)<(?:[A-Za-z][\w.-]*:)?{name}\b[^>]*?(?:/>|>.*?</(?:[A-Za-z][\w.-]*:)?{name}\s*>)"
    ))
    .expect("static regex")
}

fn core_regexes() -> &'static [(Regex, &'static str)] {
    static R: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        [
            ("creator", "auteur"),
            ("lastModifiedBy", "dernière modification par"),
            ("created", "dates"),
            ("modified", "dates"),
            ("lastPrinted", "dates"),
            ("revision", "nombre de révisions"),
        ]
        .into_iter()
        .map(|(n, l)| (element_regex(n), l))
        .collect()
    })
}

fn app_regexes() -> &'static [(Regex, &'static str, &'static str)] {
    static R: OnceLock<Vec<(Regex, &'static str, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        [
            ("Company", "société"),
            ("Manager", "responsable"),
            ("HyperlinkBase", "base des liens"),
        ]
        .into_iter()
        .map(|(n, l)| (element_regex(n), n, l))
        .collect()
    })
}

/// Remove author / editor / dates / revision from `docProps/core.xml`.
pub fn clean_core_xml(xml: &str, removed: &mut Vec<String>) -> String {
    let mut s = xml.to_string();
    for (re, label) in core_regexes() {
        if re.is_match(&s) {
            push_unique(removed, label);
            s = re.replace_all(&s, "").into_owned();
        }
    }
    s
}

/// Empty Company / Manager / HyperlinkBase in `docProps/app.xml`.
pub fn clean_app_xml(xml: &str, removed: &mut Vec<String>) -> String {
    let mut s = xml.to_string();
    for (re, name, label) in app_regexes() {
        let mut changed = false;
        s = re
            .replace_all(&s, |caps: &regex::Captures<'_>| {
                let m = &caps[0];
                if m.ends_with("/>") || m.ends_with(&format!("<{name}></{name}>")) {
                    m.to_string()
                } else {
                    changed = true;
                    format!("<{name}></{name}>")
                }
            })
            .into_owned();
        if changed {
            push_unique(removed, label);
        }
    }
    s
}

const MAX_ZIP_ENTRIES: usize = 20_000;
const MAX_PROPS_XML: u64 = 4 * 1024 * 1024;

pub fn clean_ooxml(data: &[u8]) -> Result<(Vec<u8>, Vec<String>), String> {
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(data))
        .map_err(|e| format!("document Office illisible : {e}"))?;
    if z.len() > MAX_ZIP_ENTRIES {
        return Err("document Office : trop d'entrées".into());
    }
    let mut removed = Vec::new();
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::with_capacity(data.len())));
    for i in 0..z.len() {
        let name = z
            .by_index_raw(i)
            .map_err(|e| e.to_string())?
            .name()
            .to_string();
        let is_core = name == "docProps/core.xml";
        let is_app = name == "docProps/app.xml";
        if is_core || is_app {
            let mut f = z.by_index(i).map_err(|e| e.to_string())?;
            if f.size() > MAX_PROPS_XML {
                return Err(format!("{name} trop volumineux"));
            }
            let mut xml = String::new();
            f.by_ref()
                .take(MAX_PROPS_XML)
                .read_to_string(&mut xml)
                .map_err(|e| format!("{name} illisible : {e}"))?;
            drop(f);
            let cleaned = if is_core {
                clean_core_xml(&xml, &mut removed)
            } else {
                clean_app_xml(&xml, &mut removed)
            };
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            w.start_file(name.clone(), opts)
                .map_err(|e| e.to_string())?;
            w.write_all(cleaned.as_bytes()).map_err(|e| e.to_string())?;
        } else {
            let f = z.by_index_raw(i).map_err(|e| e.to_string())?;
            w.raw_copy_file(f).map_err(|e| e.to_string())?;
        }
    }
    let out = w.finish().map_err(|e| e.to_string())?.into_inner();
    Ok((out, removed))
}

// ---------------------------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------------------------

/// `<dir>/<stem>.clean.<ext>`, then `<stem>.clean-2.<ext>`… (first that does not exist).
pub fn output_path(input: &Path) -> Option<PathBuf> {
    let dir = input.parent().unwrap_or(Path::new("."));
    let stem = input.file_stem()?.to_string_lossy().to_string();
    let ext = input.extension().map(|e| e.to_string_lossy().to_string());
    for n in 1..=100 {
        let suffix = if n == 1 {
            "clean".to_string()
        } else {
            format!("clean-{n}")
        };
        let name = match &ext {
            Some(e) => format!("{stem}.{suffix}.{e}"),
            None => format!("{stem}.{suffix}"),
        };
        let p = dir.join(name);
        if std::fs::symlink_metadata(&p).is_err() {
            return Some(p);
        }
    }
    None
}

fn write_new(path: &Path, data: &[u8], mode: u32) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

fn file_mode(md: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        0o644
    }
}

fn find_exiftool() -> Option<PathBuf> {
    EXIFTOOL_PATHS
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

fn tmp_sibling(input: &Path) -> PathBuf {
    let dir = input.parent().unwrap_or(Path::new("."));
    let name = input
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    dir.join(format!(
        ".{name}.pbclean-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..8]
    ))
}

/// Clean one file. `in_place` overwrites the input (atomic rename) instead of writing a copy.
pub fn clean_file(input: &Path, in_place: bool) -> CleanReport {
    let mut report = CleanReport {
        input: input.to_path_buf(),
        output: None,
        removed: vec![],
        method: "native".into(),
        error: None,
    };
    match clean_inner(input, in_place, &mut report) {
        Ok(out) => report.output = Some(out),
        Err(e) => report.error = Some(e),
    }
    report
}

fn clean_inner(input: &Path, in_place: bool, report: &mut CleanReport) -> Result<PathBuf, String> {
    let md = std::fs::symlink_metadata(input).map_err(|e| format!("{} : {e}", input.display()))?;
    if md.file_type().is_symlink() {
        return Err("lien symbolique refusé : indiquez le fichier lui-même".into());
    }
    if !md.is_file() {
        return Err("pas un fichier ordinaire".into());
    }
    let mode = file_mode(&md);
    let format = if md.len() <= MAX_NATIVE {
        let mut head = Vec::new();
        std::fs::File::open(input)
            .and_then(|f| f.take(16).read_to_end(&mut head))
            .map_err(|e| format!("lecture impossible : {e}"))?;
        if head.starts_with(b"PK\x03\x04") {
            // Needs the central directory: read everything.
            let data = std::fs::read(input).map_err(|e| format!("lecture impossible : {e}"))?;
            detect(&data)
        } else {
            detect(&head)
        }
    } else {
        Format::Other
    };
    if format == Format::Other {
        return clean_with_exiftool(input, in_place, report);
    }
    let data = std::fs::read(input).map_err(|e| format!("lecture impossible : {e}"))?;
    let (cleaned, removed) = match format {
        Format::Jpeg => clean_jpeg(&data),
        Format::Png => clean_png(&data),
        Format::Webp => clean_webp(&data),
        Format::Ooxml => clean_ooxml(&data),
        Format::Other => unreachable!("handled above"),
    }?;
    report.removed = removed;
    if in_place {
        let tmp = tmp_sibling(input);
        write_new(&tmp, &cleaned, mode).map_err(|e| format!("écriture impossible : {e}"))?;
        if let Err(e) = std::fs::rename(&tmp, input) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("remplacement impossible : {e}"));
        }
        Ok(input.to_path_buf())
    } else {
        let out = output_path(input).ok_or("aucun nom de sortie disponible")?;
        write_new(&out, &cleaned, mode).map_err(|e| format!("écriture impossible : {e}"))?;
        Ok(out)
    }
}

fn clean_with_exiftool(
    input: &Path,
    in_place: bool,
    report: &mut CleanReport,
) -> Result<PathBuf, String> {
    report.method = "exiftool".into();
    let exiftool = find_exiftool()
        .ok_or("format non pris en charge (installez exiftool : brew install exiftool)")?;
    let abs = std::fs::canonicalize(input).map_err(|e| e.to_string())?;
    let tmp = tmp_sibling(&abs);
    let target = if in_place {
        tmp.clone()
    } else {
        output_path(&abs).ok_or("aucun nom de sortie disponible")?
    };
    let status = std::process::Command::new(&exiftool)
        .args([
            "-q",
            "-q",
            "-all=",
            "-tagsfromfile",
            "@",
            "-Orientation",
            "-o",
        ])
        .arg(&target)
        .arg(&abs)
        .stdin(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("exiftool n'a pas pu démarrer : {e}"))?;
    if !status.success() || !target.is_file() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("exiftool a échoué ({status})"));
    }
    report.removed = vec!["toutes les métadonnées (exiftool)".into()];
    if abs
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
    {
        report.removed.push(
            "avertissement : dans un PDF, exiftool laisse les anciennes métadonnées récupérables \
(mise à jour incrémentale) ; réécrivez le fichier (qpdf, Aperçu > Exporter en PDF) pour les supprimer"
                .into(),
        );
    }
    if in_place {
        std::fs::rename(&tmp, &abs).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("remplacement impossible : {e}")
        })?;
        Ok(abs)
    } else {
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn exif_payload(orientation: u16, gps: bool) -> Vec<u8> {
        let mut p = b"Exif\0\0".to_vec();
        p.extend_from_slice(b"II\x2a\x00\x08\x00\x00\x00");
        let n: u16 = if gps { 3 } else { 2 };
        p.extend_from_slice(&n.to_le_bytes());
        // Make (0x010F) ASCII offset 0 (junk), Orientation, optional GPS pointer.
        p.extend_from_slice(&[
            0x0F, 0x01, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, b'C', b'a', b'm', 0,
        ]);
        p.extend_from_slice(&[0x12, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00]);
        p.extend_from_slice(&orientation.to_le_bytes());
        p.extend_from_slice(&[0, 0]);
        if gps {
            p.extend_from_slice(&[
                0x25, 0x88, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0, 0, 0,
            ]);
        }
        p.extend_from_slice(&[0, 0, 0, 0]);
        p
    }

    fn jpeg(orientation: u16) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend(segment(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"));
        v.extend(segment(0xE1, &exif_payload(orientation, true)));
        v.extend(segment(0xE1, b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta/>"));
        v.extend(segment(0xE2, b"ICC_PROFILE\0\x01\x01icc"));
        v.extend(segment(0xED, b"Photoshop 3.0\0"));
        v.extend(segment(0xFE, b"secret comment"));
        v.extend(segment(0xDB, &[0u8; 65]));
        v.extend(segment(0xDA, &[1, 1, 0, 0, 0x3F, 0]));
        v.extend_from_slice(&[0x12, 0xFF, 0x00, 0x34, 0xFF, 0xD0, 0x56]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        v.extend_from_slice(b"TRAILER");
        v
    }

    #[test]
    fn jpeg_cleaning() {
        let (out, removed) = clean_jpeg(&jpeg(6)).unwrap();
        assert!(removed.contains(&"GPS".to_string()));
        assert!(removed.contains(&"XMP".to_string()));
        assert!(removed.contains(&"IPTC / Photoshop".to_string()));
        assert!(removed.contains(&"commentaire".to_string()));
        assert!(removed.contains(&"données après la fin de l'image".to_string()));
        assert!(!out.windows(4).any(|w| w == b"Cam\0"));
        assert!(!out.windows(6).any(|w| w == b"secret"));
        assert!(out.windows(11).any(|w| w == b"ICC_PROFILE"));
        assert!(out.ends_with(&[0x56, 0xFF, 0xD9]));
        // Minimal EXIF right after APP0 with orientation 6.
        let app0_len = 2 + 16;
        assert_eq!(
            &out[2 + app0_len..2 + app0_len + 4],
            &[0xFF, 0xE1, 0x00, 0x22]
        );
        let (o, gps) = exif_facts(&out[2 + app0_len + 10..]);
        assert_eq!((o, gps), (Some(6), false));
        // Orientation 1: no EXIF at all.
        let (out1, _) = clean_jpeg(&jpeg(1)).unwrap();
        assert!(!out1.windows(4).any(|w| w == b"Exif"));
        // Idempotent.
        let (again, removed2) = clean_jpeg(&out).unwrap();
        assert_eq!(again, out);
        assert_eq!(
            removed2,
            vec!["EXIF (appareil, dates, réglages)".to_string()]
        );
        assert!(clean_jpeg(b"\xFF\xD8\xFF\xE1\x00").is_err());
    }

    fn png_chunk(typ: &[u8], data: &[u8]) -> Vec<u8> {
        let mut v = (data.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(typ);
        v.extend_from_slice(data);
        v.extend_from_slice(&[0, 0, 0, 0]); // CRC not checked here
        v
    }

    #[test]
    fn png_cleaning() {
        let mut p = b"\x89PNG\r\n\x1a\n".to_vec();
        p.extend(png_chunk(b"IHDR", &[0; 13]));
        p.extend(png_chunk(b"tEXt", b"Author\0Q"));
        p.extend(png_chunk(b"iCCP", b"icc"));
        p.extend(png_chunk(b"eXIf", b"MM\0*"));
        p.extend(png_chunk(b"tIME", &[0; 7]));
        p.extend(png_chunk(b"IDAT", b"data"));
        p.extend(png_chunk(b"IEND", b""));
        let (out, removed) = clean_png(&p).unwrap();
        assert_eq!(removed.len(), 3);
        assert!(!out.windows(6).any(|w| w == b"Author"));
        assert!(out.windows(4).any(|w| w == b"iCCP"));
        assert!(out.ends_with(&png_chunk(b"IEND", b"")));
        assert!(clean_png(&p[..p.len() - 12]).is_err());
    }

    #[test]
    fn webp_cleaning() {
        let chunk = |f: &[u8], d: &[u8]| {
            let mut v = f.to_vec();
            v.extend_from_slice(&(d.len() as u32).to_le_bytes());
            v.extend_from_slice(d);
            if d.len() % 2 == 1 {
                v.push(0);
            }
            v
        };
        let mut body = b"WEBP".to_vec();
        body.extend(chunk(b"VP8X", &[0x2C, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        body.extend(chunk(b"ICCP", b"icc"));
        body.extend(chunk(b"VP8 ", b"frame"));
        body.extend(chunk(b"EXIF", b"MM\0*gps"));
        body.extend(chunk(b"XMP ", b"<x/>"));
        let mut w = b"RIFF".to_vec();
        w.extend_from_slice(&(body.len() as u32).to_le_bytes());
        w.extend(body);
        let (out, removed) = clean_webp(&w).unwrap();
        assert_eq!(removed, vec!["EXIF".to_string(), "XMP".to_string()]);
        assert_eq!(out[20], 0x20, "EXIF/XMP flags cleared, ICC kept");
        let riff = u32::from_le_bytes([out[4], out[5], out[6], out[7]]) as usize;
        assert_eq!(riff, out.len() - 8);
        assert!(out.windows(5).any(|x| x == b"frame"));
        assert!(!out.windows(4).any(|x| x == b"<x/>"));
    }

    fn docx(core: &str, app: &str) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let o = zip::write::SimpleFileOptions::default();
        for (n, d) in [
            ("[Content_Types].xml", "<Types/>"),
            ("word/document.xml", "<w:document>hello</w:document>"),
            ("docProps/core.xml", core),
            ("docProps/app.xml", app),
        ] {
            w.start_file(n, o).unwrap();
            w.write_all(d.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn ooxml_cleaning() {
        let core = r#"<?xml version="1.0"?><cp:coreProperties xmlns:cp="c" xmlns:dc="d" xmlns:dcterms="t"><dc:title>Rapport</dc:title><dc:creator>Camille M</dc:creator><cp:lastModifiedBy>CM</cp:lastModifiedBy><cp:revision>12</cp:revision><dcterms:created xsi:type="dcterms:W3CDTF">2026-10-01T10:00:00Z</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">2026-10-02T10:00:00Z</dcterms:modified><cp:lastPrinted/></cp:coreProperties>"#;
        let app = r#"<Properties><Company>Capgemini</Company><Manager>Boss</Manager><Pages>3</Pages></Properties>"#;
        let data = docx(core, app);
        assert_eq!(detect(&data), Format::Ooxml);
        let (out, removed) = clean_ooxml(&data).unwrap();
        for l in [
            "auteur",
            "dernière modification par",
            "dates",
            "nombre de révisions",
            "société",
            "responsable",
        ] {
            assert!(removed.contains(&l.to_string()), "{l} in {removed:?}");
        }
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(out)).unwrap();
        let mut s = String::new();
        z.by_name("docProps/core.xml")
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert!(s.contains("<dc:title>Rapport</dc:title>"));
        assert!(
            !s.contains("Camille")
                && !s.contains("2026-10")
                && !s.contains("revision")
                && !s.contains("lastPrinted")
        );
        assert!(s.ends_with("</cp:coreProperties>"));
        let mut a = String::new();
        z.by_name("docProps/app.xml")
            .unwrap()
            .read_to_string(&mut a)
            .unwrap();
        assert_eq!(
            a,
            "<Properties><Company></Company><Manager></Manager><Pages>3</Pages></Properties>"
        );
        let mut d = String::new();
        z.by_name("word/document.xml")
            .unwrap()
            .read_to_string(&mut d)
            .unwrap();
        assert_eq!(d, "<w:document>hello</w:document>");
        let names: Vec<&str> = z.file_names().collect();
        assert_eq!(names.len(), 4);
        // A plain zip is not OOXML.
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        w.start_file("a.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        w.write_all(b"x").unwrap();
        assert_eq!(detect(&w.finish().unwrap().into_inner()), Format::Other);
    }

    #[test]
    fn files_copy_in_place_and_refusals() {
        let d = tempfile::tempdir().unwrap();
        let photo = d.path().join("photo.jpg");
        std::fs::write(&photo, jpeg(1)).unwrap();
        let r = clean_file(&photo, false);
        assert_eq!(r.error, None, "{r:?}");
        assert_eq!(
            r.output.as_deref(),
            Some(d.path().join("photo.clean.jpg").as_path())
        );
        let r2 = clean_file(&photo, false);
        assert_eq!(
            r2.output.as_deref(),
            Some(d.path().join("photo.clean-2.jpg").as_path())
        );
        let before = std::fs::read(&photo).unwrap();
        let r3 = clean_file(&photo, true);
        assert_eq!(r3.output.as_deref(), Some(photo.as_path()));
        assert!(std::fs::read(&photo).unwrap().len() < before.len());
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            3,
            "no temp file left"
        );
        #[cfg(unix)]
        {
            let link = d.path().join("link.jpg");
            std::os::unix::fs::symlink(&photo, &link).unwrap();
            assert!(clean_file(&link, false)
                .error
                .unwrap()
                .contains("lien symbolique"));
        }
        assert!(clean_file(d.path(), false).error.is_some());
        let txt = d.path().join("notes.txt");
        std::fs::write(&txt, b"hello").unwrap();
        let r = clean_file(&txt, false);
        assert_eq!(r.method, "exiftool");
        if find_exiftool().is_none() {
            assert!(r.error.unwrap().contains("brew install exiftool"));
        }
        let noext = d.path().join("README");
        assert_eq!(output_path(&noext), Some(d.path().join("README.clean")));
    }
}
