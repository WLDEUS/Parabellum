//! ClamAV wrapper: batched `clamscan` runs (no `clamd`, too much resident RAM).
//!
//! Command line: `clamscan --no-summary --infected --stdout --database=<dir>… --max-filesize=…
//! --max-scansize=… --max-recursion=… --max-files=… -- <files…>` (repeated `--database` is supported:
//! the option is `FLAG_MULTIPLE` in ClamAV's option parser). Files are passed as arguments rather
//! than through `--file-list`, because clamscan reads list lines with a 1024-byte buffer (longer paths
//! would be split) and a list file would need to be readable by a de-privileged clamscan.
//! On macOS the process runs under `taskpolicy -b` (background QoS).
//!
//! Exit codes: 0 = clean, 1 = virus(es) found, 2 = some error (results printed so far still count).
//! Output lines: `<path>: <signature> FOUND`; paths may contain `": "`, so the line is split at the
//! *last* `": "` (signature names never contain spaces).

use crate::proc;
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// Files per clamscan run.
pub const BATCH_SIZE: usize = 256;
/// Max total argument bytes per run (well under `ARG_MAX`).
pub const MAX_ARG_BYTES: usize = 256 * 1024;
const BATCH_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const VERSION_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OUTPUT: usize = 8 * 1024 * 1024;
/// clamscan rejects sizes above ~4 GB.
const MAX_SIZE_MB: u64 = 4000;
/// clamscan rejects `--max-recursion` above this (CLI_MAX_MAXRECLEVEL).
const MAX_RECURSION: u32 = 100;

/// Candidate `clamscan` locations, in order of preference.
#[cfg(target_os = "macos")]
const CANDIDATES: &[&str] = &[
    "/usr/local/clamav/bin/clamscan",
    "/opt/homebrew/bin/clamscan",
    "/usr/local/bin/clamscan",
];
#[cfg(not(target_os = "macos"))]
const CANDIDATES: &[&str] = &[
    "/usr/local/clamav/bin/clamscan",
    "/opt/homebrew/bin/clamscan",
    "/usr/local/bin/clamscan",
    "/usr/bin/clamscan",
];

/// Limits passed to clamscan.
#[derive(Debug, Clone, Copy)]
pub struct ClamLimits {
    pub max_file_size: u64,
    pub max_scan_size: u64,
    pub max_recursion: u32,
    pub max_files: u32,
}

/// A located clamscan binary and the signature directories to load.
#[derive(Debug, Clone)]
pub struct ClamAv {
    pub binary: PathBuf,
    pub version: Option<String>,
    pub db_dirs: Vec<PathBuf>,
    /// Run as this (uid, gid) instead of root: set when the binary is owned by a regular user
    /// (e.g. Homebrew), so that a user-writable binary can never be used to gain root.
    run_as: Option<(u32, u32)>,
}

fn dir_has_files(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .is_ok_and(|mut rd| rd.any(|e| e.is_ok_and(|e| e.file_type().is_ok_and(|t| t.is_file()))))
}

impl ClamAv {
    /// Finds clamscan and the DB directories (`official_db` = freshclam-managed dir, `extra_db` =
    /// bundle `clamav/`, each used only when non-empty). `None` when clamscan is not installed.
    pub fn locate(official_db: &Path, extra_db: Option<&Path>) -> Option<Self> {
        Self::locate_in(CANDIDATES.iter().map(PathBuf::from), official_db, extra_db)
    }

    pub(crate) fn locate_in(
        candidates: impl Iterator<Item = PathBuf>,
        official_db: &Path,
        extra_db: Option<&Path>,
    ) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        for binary in candidates {
            let Ok(meta) = std::fs::metadata(&binary) else {
                continue;
            };
            if !meta.is_file() || meta.mode() & 0o111 == 0 {
                continue;
            }
            // SAFETY: geteuid has no preconditions.
            let euid = unsafe { libc::geteuid() };
            let run_as = if euid == 0 && (meta.uid() != 0 || meta.mode() & 0o022 != 0) {
                if meta.uid() == 0 {
                    tracing::warn!(path = %binary.display(), "clamscan is group/world-writable, refusing to run it");
                    continue;
                }
                tracing::info!(path = %binary.display(), uid = meta.uid(), "clamscan not owned by root: it will run as its owner");
                Some((meta.uid(), meta.gid()))
            } else {
                None
            };
            let mut db_dirs = Vec::new();
            if dir_has_files(official_db) {
                db_dirs.push(official_db.to_path_buf());
            }
            if let Some(extra) = extra_db.filter(|d| dir_has_files(d)) {
                db_dirs.push(extra.to_path_buf());
            }
            let mut c = Self {
                binary,
                version: None,
                db_dirs,
                run_as,
            };
            c.version = c.query_version();
            return Some(c);
        }
        None
    }

    fn command(&self, background: bool) -> std::process::Command {
        let mut cmd = proc::background_command(&self.binary, background);
        if let Some((uid, gid)) = self.run_as {
            use std::os::unix::process::CommandExt;
            cmd.uid(uid).gid(gid);
        }
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C");
        cmd
    }

    fn query_version(&self) -> Option<String> {
        let mut cmd = self.command(false);
        cmd.arg("--version");
        let out = proc::run(cmd, None, VERSION_TIMEOUT, None, 4096).ok()?;
        let line = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()?
            .trim()
            .to_owned();
        (!line.is_empty()).then_some(line)
    }

    /// Scans `files` (regular files, absolute paths) in one clamscan run. Returns
    /// `path -> signature names`. `Err` when clamscan could not run or failed without output.
    pub fn scan_batch(
        &self,
        files: &[PathBuf],
        limits: &ClamLimits,
        cancel: &AtomicBool,
    ) -> Result<HashMap<PathBuf, Vec<String>>, String> {
        if files.is_empty() {
            return Ok(HashMap::new());
        }
        let mut cmd = self.command(true);
        cmd.args(build_args(&self.db_dirs, limits));
        cmd.arg("--");
        cmd.args(files);
        let out = proc::run(cmd, None, BATCH_TIMEOUT, Some(cancel), MAX_OUTPUT)
            .map_err(|e| format!("cannot run clamscan: {e}"))?;
        if out.cancelled {
            return Err("cancelled".into());
        }
        let hits = parse_output(&out.stdout);
        if out.timed_out {
            return Err(format!(
                "clamscan timed out ({} hits before timeout)",
                hits.len()
            ));
        }
        match out.code() {
            Some(0) | Some(1) => {}
            Some(2) if !hits.is_empty() => {}
            other => {
                let err = String::from_utf8_lossy(&out.stderr);
                let first = err
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                if hits.is_empty() {
                    return Err(format!("clamscan exited with {other:?}: {first}"));
                }
            }
        }
        let mut map: HashMap<PathBuf, Vec<String>> = HashMap::new();
        for (path, sig) in hits {
            map.entry(path).or_default().push(sig);
        }
        Ok(map)
    }
}

/// clamscan options (everything except the files).
pub(crate) fn build_args(db_dirs: &[PathBuf], limits: &ClamLimits) -> Vec<OsString> {
    let mb = |b: u64| (b.div_ceil(1024 * 1024)).clamp(1, MAX_SIZE_MB);
    let mut args: Vec<OsString> = vec![
        "--no-summary".into(),
        "--infected".into(),
        "--stdout".into(),
    ];
    for d in db_dirs {
        let mut a = OsString::from("--database=");
        a.push(d.as_os_str());
        args.push(a);
    }
    args.push(format!("--max-filesize={}M", mb(limits.max_file_size)).into());
    args.push(format!("--max-scansize={}M", mb(limits.max_scan_size)).into());
    args.push(
        format!(
            "--max-recursion={}",
            limits.max_recursion.clamp(1, MAX_RECURSION)
        )
        .into(),
    );
    args.push(format!("--max-files={}", limits.max_files.max(1)).into());
    args
}

/// Parses `<path>: <signature> FOUND` lines (other lines are ignored).
pub fn parse_output(stdout: &[u8]) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    for line in stdout.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(rest) = line.strip_suffix(b" FOUND") else {
            continue;
        };
        let Some(sep) = rest.windows(2).rposition(|w| w == b": ") else {
            continue;
        };
        let path = &rest[..sep];
        let sig = String::from_utf8_lossy(&rest[sep + 2..]).trim().to_owned();
        if path.is_empty() || sig.is_empty() || sig.contains(' ') {
            continue;
        }
        out.push((PathBuf::from(OsString::from_vec(path.to_vec())), sig));
    }
    out
}

/// Can this path be passed to clamscan and matched back from its output?
pub(crate) fn path_is_batchable(p: &Path) -> bool {
    let b = p.as_os_str().as_bytes();
    p.is_absolute() && !b.contains(&b'\n') && !b.contains(&b'\r') && !b.ends_with(b" FOUND")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_found_lines() {
        let out = b"/Users/q/Downloads/eicar.com: Win.Test.EICAR_HDB-1 FOUND\n\
/Users/q/weird: name/x.zip: Heuristics.Encrypted.Zip FOUND\n\
/Users/q/a.dmg: Osx.Trojan.Amos-1234 FOUND\r\n\
LibClamAV Warning: something\n\
/Users/q/err.bin: Can't open file or directory ERROR\n\
/Users/q/ok.txt: OK\n";
        let p = parse_output(out);
        assert_eq!(p.len(), 3);
        assert_eq!(
            p[0],
            (
                PathBuf::from("/Users/q/Downloads/eicar.com"),
                "Win.Test.EICAR_HDB-1".to_string()
            )
        );
        assert_eq!(
            p[1],
            (
                PathBuf::from("/Users/q/weird: name/x.zip"),
                "Heuristics.Encrypted.Zip".to_string()
            )
        );
        assert_eq!(p[2].1, "Osx.Trojan.Amos-1234");
    }

    #[test]
    fn args_and_batchable_paths() {
        let a = build_args(
            &[PathBuf::from("/db/a"), PathBuf::from("/db/b")],
            &ClamLimits {
                max_file_size: 200 << 20,
                max_scan_size: 10 << 40,
                max_recursion: 3,
                max_files: 20_000,
            },
        );
        let a: Vec<String> = a.into_iter().map(|s| s.into_string().unwrap()).collect();
        assert!(
            a.contains(&"--database=/db/a".to_string())
                && a.contains(&"--database=/db/b".to_string())
        );
        assert!(a.contains(&"--max-filesize=200M".to_string()));
        assert!(a.contains(&"--max-scansize=4000M".to_string()));
        assert!(a.contains(&"--max-recursion=3".to_string()));
        assert!(path_is_batchable(Path::new("/a/b c")));
        assert!(!path_is_batchable(Path::new("/a/b\nc")));
        assert!(!path_is_batchable(Path::new("rel")));
    }

    #[test]
    fn fake_clamscan_end_to_end() {
        // A stand-in clamscan script exercising argument passing and output parsing.
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("clamscan");
        std::fs::write(
            &bin,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ClamAV 1.4.1/27000/Sat Oct 25 2026'; exit 0; fi\n\
             seen=0\nfor a in \"$@\"; do if [ $seen = 1 ]; then case \"$a\" in *bad*) echo \"$a: Osx.Test.Bad FOUND\";; esac; fi; [ \"$a\" = \"--\" ] && seen=1; done\nexit 1\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let db = d.path().join("db");
        std::fs::create_dir_all(&db).unwrap();
        let c = ClamAv::locate_in(std::iter::once(bin), &db, None).unwrap();
        assert_eq!(
            c.version.as_deref(),
            Some("ClamAV 1.4.1/27000/Sat Oct 25 2026")
        );
        assert!(c.db_dirs.is_empty());
        let files = vec![PathBuf::from("/x/good: one"), PathBuf::from("/x/bad: two")];
        let limits = ClamLimits {
            max_file_size: 1 << 20,
            max_scan_size: 1 << 20,
            max_recursion: 3,
            max_files: 10,
        };
        let r = c
            .scan_batch(&files, &limits, &AtomicBool::new(false))
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(
            r[&PathBuf::from("/x/bad: two")],
            vec!["Osx.Test.Bad".to_string()]
        );
    }
}
