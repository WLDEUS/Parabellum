//! Count blocked queries from dnscrypt-proxy's blocked-names log (LTSV).
//!
//! Line format (`FormatLogLine` in `dnscrypt-proxy/common.go`, master 2026-10-25):
//! `time:<unix secs>\thost:<client>\tqname:<name>\tmessage:<rule>`. dnscrypt-proxy rotates plugin logs
//! itself (`log_files_max_size` MB, `log_files_max_backups`): the current file is `blocked.log`, backups
//! are `blocked-<timestamp>.log` in the same directory.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Max bytes read from the end of each log file.
const MAX_TAIL: u64 = 16 * 1024 * 1024;
const MAX_FILES: usize = 4;

/// Unix timestamp of an LTSV line, if any.
pub fn line_time(line: &str) -> Option<i64> {
    line.split('\t')
        .find_map(|f| f.strip_prefix("time:"))
        .and_then(|t| t.trim().parse().ok())
}

fn log_files(dir: &Path, base: &str) -> Vec<PathBuf> {
    let stem = base.trim_end_matches(".log");
    let Ok(rd) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut v: Vec<(std::time::SystemTime, PathBuf)> = rd
        .flatten()
        .filter(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            n == base || (n.starts_with(&format!("{stem}-")) && n.ends_with(".log"))
        })
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.0));
    v.into_iter().take(MAX_FILES).map(|(_, p)| p).collect()
}

/// Number of blocked queries logged at or after `since` (unix secs). `None` when no log exists.
pub fn count_blocked_since(dir: &Path, base: &str, since: i64) -> Option<u64> {
    let files = log_files(dir, base);
    if files.is_empty() {
        return None;
    }
    let mut total = 0u64;
    for f in files {
        let Ok(mut file) = std::fs::File::open(&f) else {
            continue;
        };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let start = len.saturating_sub(MAX_TAIL);
        if file.seek(SeekFrom::Start(start)).is_err() {
            continue;
        }
        let mut buf = Vec::new();
        if file.take(MAX_TAIL).read_to_end(&mut buf).is_err() {
            continue;
        }
        let text = String::from_utf8_lossy(&buf);
        let mut lines = text.lines();
        if start > 0 {
            lines.next(); // partial first line
        }
        total += lines
            .filter(|l| line_time(l).is_some_and(|t| t >= since))
            .count() as u64;
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_recent_lines_across_rotations() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(count_blocked_since(d.path(), "blocked.log", 0), None);
        let now = 1_761_400_000i64;
        let line = |t: i64| {
            format!("time:{t}\thost:127.0.0.1\tqname:ads.example.com\tmessage:*.example.com\n")
        };
        std::fs::write(
            d.path().join("blocked.log"),
            format!("{}{}{}", line(now - 90_000), line(now - 10), line(now)),
        )
        .unwrap();
        std::fs::write(
            d.path().join("blocked-2026-10-24T10-00-00.000.log"),
            line(now - 3600),
        )
        .unwrap();
        std::fs::write(d.path().join("other.log"), line(now)).unwrap();
        assert_eq!(
            count_blocked_since(d.path(), "blocked.log", now - 86_400),
            Some(3)
        );
        assert_eq!(line_time("garbage"), None);
    }
}
