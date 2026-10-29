//! Ransomware detection: decoy ("canary") files in the user's document folders and a detector of mass
//! "encrypt-and-rename" activity (`report.docx` -> `report.docx.locked`, or a new `report.docx.enc` next to the
//! original). Pure logic here; the guard wires it to eslogger / FSEvents and the canary files on disk.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Extensions of files ransomware goes after (lowercase).
pub const DOC_EXTS: &[&str] = &[
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "rtf", "md", "csv", "pages",
    "numbers", "key", "odt", "ods", "odp", "jpg", "jpeg", "png", "heic", "gif", "tif", "tiff",
    "psd", "ai", "sketch", "fig", "mp4", "mov", "m4v", "mp3", "m4a", "wav", "zip", "7z", "rar",
    "json", "xml", "sql", "db", "sqlite", "py", "rs", "swift", "js", "ts", "java", "c", "cpp", "h",
    "go",
];

/// Suffixes appended by legitimate software (downloads, editors, sync, backups).
pub const BENIGN_SUFFIXES: &[&str] = &[
    "download",
    "crdownload",
    "part",
    "partial",
    "tmp",
    "temp",
    "bak",
    "backup",
    "old",
    "orig",
    "swp",
    "swo",
    "lock",
    "icloud",
    "sb",
    "dl",
    "copy",
    "conflict",
    "gz",
    "bz2",
    "xz",
    "zst",
    "sig",
    "asc",
    "sha256",
    "md5",
    "torrent",
    "gpg",
    "age",
];

/// Events needed inside [`BURST_WINDOW`] from one process before it is treated as ransomware.
pub const BURST_THRESHOLD: usize = 12;
pub const BURST_WINDOW: Duration = Duration::from_secs(30);

fn ext_lower(name: &str) -> Option<String> {
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() || ext.len() > 16 {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

fn file_name(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

fn suffix_is_benign(ext: &str) -> bool {
    BENIGN_SUFFIXES.contains(&ext)
        || ext.starts_with("sb-")
        || ext.chars().all(|c| c.is_ascii_digit())
}

/// A rename that looks like encryption: a document gets an extra or replaced unknown extension, same folder.
pub fn is_encryption_rename(from: &str, to: &str) -> bool {
    let (Some(from_dir), Some(to_dir)) = (from.rsplit_once('/'), to.rsplit_once('/')) else {
        return false;
    };
    if from_dir.0 != to_dir.0 {
        return false;
    }
    let (fname, tname) = (file_name(from), file_name(to));
    let Some(old_ext) = ext_lower(fname) else {
        return false;
    };
    if !DOC_EXTS.contains(&old_ext.as_str()) {
        return false;
    }
    let Some(new_ext) = ext_lower(tname) else {
        return false;
    };
    if suffix_is_benign(&new_ext) || DOC_EXTS.contains(&new_ext.as_str()) {
        return false;
    }
    // Appended (`a.docx` -> `a.docx.locked`) or replaced (`a.docx` -> `a.locked`).
    let appended = tname.len() > fname.len() + 1
        && tname.starts_with(fname)
        && tname.as_bytes()[fname.len()] == b'.';
    let replaced = fname.rsplit_once('.').map(|(s, _)| s) == tname.rsplit_once('.').map(|(s, _)| s);
    appended || replaced
}

/// A newly created file named like an encrypted copy (`a.docx.enc`): document extension in the middle,
/// unknown extension at the end.
pub fn is_encrypted_copy_name(path: &str) -> bool {
    let name = file_name(path);
    let mut parts = name.rsplitn(3, '.');
    let (Some(last), Some(middle), Some(stem)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let (last, middle) = (last.to_ascii_lowercase(), middle.to_ascii_lowercase());
    !stem.is_empty()
        && DOC_EXTS.contains(&middle.as_str())
        && !suffix_is_benign(&last)
        && !DOC_EXTS.contains(&last.as_str())
        && last.len() <= 16
}

/// Per-process counter of encryption-like events.
#[derive(Debug, Default)]
pub struct BurstDetector {
    by_pid: HashMap<i32, VecDeque<Instant>>,
    tripped: HashMap<i32, Instant>,
}

impl BurstDetector {
    /// Record one event for `pid`; `true` the first time the threshold is crossed (then quiet 10 min).
    pub fn record(&mut self, pid: i32, now: Instant) -> bool {
        if self.by_pid.len() > 2048 {
            self.by_pid.clear();
        }
        self.tripped
            .retain(|_, at| now.duration_since(*at) < Duration::from_secs(600));
        let q = self.by_pid.entry(pid).or_default();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > BURST_WINDOW)
        {
            q.pop_front();
        }
        q.push_back(now);
        if q.len() >= BURST_THRESHOLD && !self.tripped.contains_key(&pid) {
            self.tripped.insert(pid, now);
            q.clear();
            return true;
        }
        false
    }
}

/// A decoy file and its expected state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Canary {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
}

/// What a canary check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryState {
    Intact,
    /// Content changed (encrypted in place).
    Modified,
    /// Renamed with an extra extension next to its old name (`…docx.locked`).
    Renamed(PathBuf),
    /// Gone (deleted by the user, iCloud, or ransomware that writes a new file and deletes the original).
    Missing,
}

/// Decoy file names per folder: one sorted first, one sorted last (ransomware walks folders in order).
pub const CANARY_NAMES: [&str; 2] = [
    "!Parabellum - fichier leurre - ne pas modifier.docx",
    "~Parabellum - fichier leurre - ne pas modifier.pdf",
];

/// Content of a decoy: a recognisable header, then deterministic pseudo-random bytes (incompressible, like a
/// real document) seeded per path.
pub fn canary_content(path: &Path) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut out = b"PARABELLUM DECOY FILE - do not edit, move or delete. Fichier leurre de Parabellum : ne pas modifier.\n".to_vec();
    let mut seed = Sha256::digest(path.to_string_lossy().as_bytes()).to_vec();
    while out.len() < 48 * 1024 {
        seed = Sha256::digest(&seed).to_vec();
        out.extend_from_slice(&seed);
    }
    out
}

/// Check one canary against the file system. `current` = (size, sha256) of the file now, `None` if absent;
/// `siblings` = names in its folder (to spot a renamed copy).
pub fn evaluate_canary(
    c: &Canary,
    current: Option<(u64, String)>,
    siblings: &[String],
) -> CanaryState {
    match current {
        Some((size, sha)) => {
            if size == c.size && sha.eq_ignore_ascii_case(&c.sha256) {
                CanaryState::Intact
            } else {
                CanaryState::Modified
            }
        }
        None => {
            let Some(name) = c.path.file_name().and_then(|n| n.to_str()) else {
                return CanaryState::Missing;
            };
            let dir = c.path.parent().unwrap_or(Path::new("/"));
            let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
            siblings
                .iter()
                .find(|s| {
                    s.as_str() != name
                        && (s.starts_with(&format!("{name}."))
                            || (s.starts_with(&format!("{stem}.")) && ext_lower(s).is_some()))
                })
                .map(|s| CanaryState::Renamed(dir.join(s)))
                .unwrap_or(CanaryState::Missing)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renames() {
        assert!(is_encryption_rename(
            "/Users/q/Documents/a.docx",
            "/Users/q/Documents/a.docx.lockbit"
        ));
        assert!(is_encryption_rename(
            "/Users/q/Documents/a.pdf",
            "/Users/q/Documents/a.encrypted"
        ));
        assert!(!is_encryption_rename(
            "/Users/q/Downloads/a.dmg.download",
            "/Users/q/Downloads/a.dmg"
        ));
        assert!(!is_encryption_rename(
            "/Users/q/Documents/a.docx",
            "/Users/q/Documents/a.docx.bak"
        ));
        assert!(!is_encryption_rename(
            "/Users/q/Documents/a.docx",
            "/Users/q/Archive/a.docx.x1"
        ));
        assert!(!is_encryption_rename(
            "/Users/q/Documents/a.png",
            "/Users/q/Documents/a.jpg"
        ));
        assert!(!is_encryption_rename(
            "/Users/q/Documents/a.docx",
            "/Users/q/Documents/b.locked"
        ));
        assert!(!is_encryption_rename(
            "/Users/q/Documents/a.docx",
            "/Users/q/Documents/a.docx.sb-1234-xyz"
        ));
    }

    #[test]
    fn encrypted_copies() {
        assert!(is_encrypted_copy_name("/Users/q/Desktop/photo.jpg.crypt"));
        assert!(!is_encrypted_copy_name("/Users/q/Desktop/archive.tar.gz"));
        assert!(!is_encrypted_copy_name(
            "/Users/q/Desktop/report.final.docx"
        ));
        assert!(!is_encrypted_copy_name("/Users/q/Desktop/.docx.x"));
    }

    #[test]
    fn burst() {
        let mut b = BurstDetector::default();
        let t0 = Instant::now();
        for i in 0..BURST_THRESHOLD - 1 {
            assert!(!b.record(7, t0 + Duration::from_millis(i as u64 * 100)));
        }
        assert!(b.record(7, t0 + Duration::from_secs(2)));
        // Quiet afterwards, other pids independent.
        assert!(!b.record(7, t0 + Duration::from_secs(3)));
        assert!(!b.record(8, t0));
        // Slow activity never trips.
        let mut b = BurstDetector::default();
        for i in 0..50u64 {
            assert!(!b.record(9, t0 + Duration::from_secs(i * 5)));
        }
    }

    #[test]
    fn canary_states() {
        let p =
            PathBuf::from("/Users/q/Documents/!Parabellum - fichier leurre - ne pas modifier.docx");
        let content = canary_content(&p);
        assert!(content.len() >= 48 * 1024 && content == canary_content(&p));
        let c = Canary {
            path: p.clone(),
            sha256: "ab".repeat(32),
            size: 10,
        };
        assert_eq!(
            evaluate_canary(&c, Some((10, "AB".repeat(32))), &[]),
            CanaryState::Intact
        );
        assert_eq!(
            evaluate_canary(&c, Some((11, "ab".repeat(32))), &[]),
            CanaryState::Modified
        );
        let renamed = "!Parabellum - fichier leurre - ne pas modifier.docx.locked".to_string();
        assert_eq!(
            evaluate_canary(&c, None, &[renamed.clone(), "other.txt".into()]),
            CanaryState::Renamed(PathBuf::from("/Users/q/Documents").join(renamed))
        );
        assert_eq!(
            evaluate_canary(&c, None, &["other.txt".into()]),
            CanaryState::Missing
        );
    }
}
