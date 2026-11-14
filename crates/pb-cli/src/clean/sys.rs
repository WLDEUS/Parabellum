//! macOS tools used by the cleaner (absolute paths, cleared environment with `LC_ALL=C`, bounded time)
//! and the parsers of their output.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MAX_OUTPUT: u64 = 64 * 1024 * 1024;

/// Run `program args…` as the current user; stdout when it exits 0 before `timeout`.
pub fn run(program: &str, args: &[&str], home: &Path, timeout: Duration) -> Option<String> {
    if !Path::new(program).is_file() {
        return None;
    }
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("HOME", home)
        .env(
            "PATH",
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .env("HOMEBREW_NO_ANALYTICS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut out = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut out).take(MAX_OUTPUT).read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let buf = reader.join().ok()?;
    status
        .filter(|s| s.success())
        .map(|_| String::from_utf8_lossy(&buf).into_owned())
}

/// Files open by the user's processes (`lsof -F n` output): sorted absolute paths.
#[derive(Debug, Clone, Default)]
pub struct OpenFiles(BTreeSet<String>);

impl OpenFiles {
    pub fn from_paths<I: IntoIterator<Item = String>>(paths: I) -> Self {
        Self(paths.into_iter().filter(|p| p.starts_with('/')).collect())
    }

    /// Parse `lsof -F n`: `p<pid>`, `f<fd>`, `n<name>` lines; only absolute names are kept.
    pub fn parse_lsof(text: &str) -> Self {
        Self::from_paths(
            text.lines()
                .filter_map(|l| l.strip_prefix('n'))
                .filter(|n| n.starts_with('/'))
                .map(|n| n.trim_end_matches(" (deleted)").to_string()),
        )
    }

    /// Some open file is `p` or inside it.
    pub fn touches(&self, p: &Path) -> bool {
        let Some(s) = p.to_str() else {
            return false;
        };
        let prefix = format!("{}/", s.trim_end_matches('/'));
        if self.0.contains(s) {
            return true;
        }
        self.0
            .range(prefix.clone()..)
            .next()
            .is_some_and(|o| o.starts_with(&prefix))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `lsof` of the user's processes (best effort: empty when unavailable or too slow).
pub fn open_files(uid: u32, home: &Path) -> Option<OpenFiles> {
    let uid = uid.to_string();
    run(
        "/usr/sbin/lsof",
        &["-n", "-P", "-w", "-b", "-F", "n", "-u", &uid],
        home,
        Duration::from_secs(20),
    )
    .map(|t| OpenFiles::parse_lsof(&t))
}

/// Every application bundle Spotlight knows (LaunchServices view of installed apps).
pub fn spotlight_apps(home: &Path) -> Option<Vec<PathBuf>> {
    let out = run(
        "/usr/bin/mdfind",
        &["kMDItemContentType == 'com.apple.application-bundle'"],
        home,
        Duration::from_secs(30),
    )?;
    Some(parse_path_lines(&out))
}

/// One absolute path per line.
pub fn parse_path_lines(text: &str) -> Vec<PathBuf> {
    text.lines()
        .map(str::trim_end)
        .filter(|l| l.starts_with('/'))
        .map(PathBuf::from)
        .collect()
}

/// `mdls -raw -name kMDItemLastUsedDate`: `2026-03-01 10:22:11 +0000` or `(null)`.
pub fn parse_mdls_date(text: &str) -> Option<i64> {
    let t = text.trim();
    if t.is_empty() || t == "(null)" {
        return None;
    }
    chrono::DateTime::parse_from_str(t, "%Y-%m-%d %H:%M:%S %z")
        .ok()
        .map(|d| d.timestamp())
}

/// Last time the file was opened according to Spotlight.
pub fn last_used(path: &Path, home: &Path) -> Option<i64> {
    let p = path.to_str()?;
    let out = run(
        "/usr/bin/mdls",
        &["-raw", "-name", "kMDItemLastUsedDate", p],
        home,
        Duration::from_secs(5),
    )?;
    parse_mdls_date(&out)
}

/// `brew --cache`, when Homebrew is installed.
pub fn brew_cache(home: &Path) -> Option<PathBuf> {
    for brew in ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"] {
        if let Some(out) = run(brew, &["--cache"], home, Duration::from_secs(15)) {
            let p = PathBuf::from(out.trim());
            if p.is_absolute() {
                return Some(p);
            }
        }
    }
    None
}

/// Home folder of the effective user (password database, not `$HOME`).
pub fn user_home() -> Option<(u32, PathBuf)> {
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: valid buffers, `result` is set to `&pwd` or null.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir points into `buf`, NUL-terminated.
    let dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) };
    let dir = PathBuf::from(dir.to_str().ok()?);
    Some((uid, dir))
}

/// File flags that mean "protected": SIP-restricted or locked (macOS `st_flags`).
#[cfg(target_os = "macos")]
pub fn protected_flags(meta: &std::fs::Metadata) -> bool {
    use std::os::macos::fs::MetadataExt;
    const UF_IMMUTABLE: u32 = 0x0000_0002;
    const SF_IMMUTABLE: u32 = 0x0002_0000;
    const SF_RESTRICTED: u32 = 0x0008_0000;
    meta.st_flags() & (UF_IMMUTABLE | SF_IMMUTABLE | SF_RESTRICTED) != 0
}

#[cfg(not(target_os = "macos"))]
pub fn protected_flags(_meta: &std::fs::Metadata) -> bool {
    false
}
