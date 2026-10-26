//! Hash databases of the threat-DB bundle, memory-mapped (never copied to the heap):
//! `hashes/malware.sha256` / `hashes/allow.sha256` (sorted raw 32-byte digests, binary search) and
//! `hashes/malware_names.tsv` (`<sha256 hex>\t<name>` lines, looked up only on a hit).

use memmap2::Mmap;
use std::fs::File;
use std::path::Path;

/// A raw SHA-256 digest.
pub type Digest = [u8; 32];

/// Parses a 64-char hex digest (case-insensitive).
pub fn parse_hex_digest(s: &str) -> Option<Digest> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s.to_ascii_lowercase(), &mut out).ok()?;
    Some(out)
}

/// Read-only memory map of a bundle file. The bundle directory is immutable once activated (the
/// updater installs new versions in new directories), so the map cannot be truncated under us.
fn map(path: &Path) -> std::io::Result<Option<Mmap>> {
    let file = File::open(path)?;
    if file.metadata()?.len() == 0 {
        return Ok(None);
    }
    // SAFETY: read-only private view of an immutable, root-owned bundle file (see above).
    let m = unsafe { Mmap::map(&file)? };
    Ok(Some(m))
}

/// Sorted set of raw digests backed by a memory map.
#[derive(Default)]
pub struct DigestSet {
    map: Option<Mmap>,
}

impl DigestSet {
    /// Maps `path`. A missing file is an empty set; a length that is not a multiple of 32 is an error.
    pub fn open(path: &Path) -> Result<Self, String> {
        match map(path) {
            Ok(map) => {
                if let Some(m) = &map {
                    if m.len() % 32 != 0 {
                        return Err(format!(
                            "{}: length {} is not a multiple of 32",
                            path.display(),
                            m.len()
                        ));
                    }
                }
                Ok(Self { map })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// Number of digests.
    pub fn len(&self) -> u64 {
        self.map.as_ref().map_or(0, |m| (m.len() / 32) as u64)
    }

    /// True when the set is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Binary search (the file is sorted ascending by the pipeline).
    pub fn contains(&self, d: &Digest) -> bool {
        let Some(m) = &self.map else { return false };
        let n = m.len() / 32;
        let (mut lo, mut hi) = (0usize, n);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let Some(entry) = m.get(mid * 32..mid * 32 + 32) else {
                return false;
            };
            match entry.cmp(&d[..]) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        false
    }
}

/// `malware_names.tsv`, memory-mapped. Lookup = binary search assuming the file is sorted by hash,
/// then a linear scan as fallback (only on a hash-DB hit, which is rare).
#[derive(Default)]
pub struct NameIndex {
    map: Option<Mmap>,
}

const MAX_NAME_LEN: usize = 200;

impl NameIndex {
    /// Maps `path`; missing file = no names.
    pub fn open(path: &Path) -> Result<Self, String> {
        match map(path) {
            Ok(map) => Ok(Self { map }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    fn line_at(data: &[u8], pos: usize) -> (usize, usize) {
        let start = data[..pos]
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        let end = data[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(data.len(), |i| pos + i);
        (start, end)
    }

    fn parse_line(line: &[u8]) -> Option<(&[u8], &[u8])> {
        let tab = line.iter().position(|&b| b == b'\t')?;
        Some((&line[..tab], &line[tab + 1..]))
    }

    fn clean_name(raw: &[u8]) -> Option<String> {
        let s = String::from_utf8_lossy(raw);
        let s: String = s
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_NAME_LEN)
            .collect();
        (!s.is_empty()).then_some(s)
    }

    /// Family / signature name for `hex` (lowercase 64-char hex), if listed.
    pub fn lookup(&self, hex: &str) -> Option<String> {
        let data: &[u8] = self.map.as_deref()?;
        let key = hex.as_bytes();
        // Binary search over line starts.
        let (mut lo, mut hi) = (0usize, data.len());
        let mut guard = 0;
        while lo < hi && guard < 128 {
            guard += 1;
            let mid = lo + (hi - lo) / 2;
            let (start, end) = Self::line_at(data, mid);
            let Some((h, name)) = Self::parse_line(&data[start..end]) else {
                break;
            };
            let h_lower: Vec<u8> = h.iter().map(u8::to_ascii_lowercase).collect();
            match h_lower.as_slice().cmp(key) {
                std::cmp::Ordering::Equal => return Self::clean_name(name),
                std::cmp::Ordering::Less => lo = end + 1,
                std::cmp::Ordering::Greater => hi = start,
            }
        }
        // Fallback: the pipeline did not sort the file.
        for line in data.split(|&b| b == b'\n') {
            if let Some((h, name)) = Self::parse_line(line) {
                if h.eq_ignore_ascii_case(key) {
                    return Self::clean_name(name);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(i: u8) -> Digest {
        let mut d = [0u8; 32];
        d[0] = i;
        d[31] = i.wrapping_mul(7);
        d
    }

    #[test]
    fn digest_set_binary_search() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.sha256");
        let mut all: Vec<Digest> = (0..200u8).step_by(2).map(digest).collect();
        all.sort();
        std::fs::write(&p, all.concat()).unwrap();
        let s = DigestSet::open(&p).unwrap();
        assert_eq!(s.len(), 100);
        for i in 0..200u8 {
            assert_eq!(s.contains(&digest(i)), i % 2 == 0, "{i}");
        }
        assert!(DigestSet::open(&d.path().join("missing"))
            .unwrap()
            .is_empty());
        std::fs::write(&p, [0u8; 33]).unwrap();
        assert!(DigestSet::open(&p).is_err());
        std::fs::write(&p, []).unwrap();
        assert!(!DigestSet::open(&p).unwrap().contains(&digest(0)));
    }

    #[test]
    fn names_sorted_and_unsorted() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("n.tsv");
        let h = |c: char| c.to_string().repeat(64);
        std::fs::write(
            &p,
            format!("{}\tAlpha\n{}\tBeta\n{}\tGamma\n", h('1'), h('5'), h('a')),
        )
        .unwrap();
        let n = NameIndex::open(&p).unwrap();
        assert_eq!(n.lookup(&h('5')).as_deref(), Some("Beta"));
        assert_eq!(n.lookup(&h('a')).as_deref(), Some("Gamma"));
        assert_eq!(n.lookup(&h('1')).as_deref(), Some("Alpha"));
        assert_eq!(n.lookup(&h('2')), None);
        std::fs::write(
            &p,
            format!("{}\tGamma\n{}\tAlpha\n{}\tBeta", h('A'), h('1'), h('5')),
        )
        .unwrap();
        let n = NameIndex::open(&p).unwrap();
        assert_eq!(n.lookup(&h('a')).as_deref(), Some("Gamma"));
        assert_eq!(n.lookup(&h('5')).as_deref(), Some("Beta"));
        assert!(parse_hex_digest(&h('A')).is_some());
        assert!(parse_hex_digest("zz").is_none());
    }
}
