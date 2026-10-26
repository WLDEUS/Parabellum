//! Console user and Full Disk Access detection.

use std::ffi::CStr;
use std::path::PathBuf;

/// The user logged in at the GUI console (the daemon runs as root; `~` means this user's home).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleUser {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
}

/// Account entry resolved with `getpwuid_r`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Passwd {
    pub name: String,
    pub gid: u32,
    pub home: PathBuf,
}

/// Thread-safe `getpwuid_r` lookup.
pub(crate) fn passwd_for_uid(uid: u32) -> Option<Passwd> {
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    loop {
        // SAFETY: `passwd` is a plain C struct of integers and pointers; all-zero is a valid value.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the duration of the call and `buf.len()` is its size.
        let rc = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE && buf.len() < (1 << 20) {
            let n = buf.len() * 2;
            buf.resize(n, 0);
            continue;
        }
        if rc != 0 || result.is_null() || pwd.pw_name.is_null() || pwd.pw_dir.is_null() {
            return None;
        }
        // SAFETY: on success getpwuid_r points pw_name / pw_dir at NUL-terminated strings inside `buf`.
        let name = unsafe { CStr::from_ptr(pwd.pw_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: see above.
        let home = unsafe { CStr::from_ptr(pwd.pw_dir) }
            .to_string_lossy()
            .into_owned();
        return Some(Passwd {
            name,
            gid: pwd.pw_gid as u32,
            home: PathBuf::from(home),
        });
    }
}

/// User name for a uid, if it exists.
pub(crate) fn user_name(uid: u32) -> Option<String> {
    passwd_for_uid(uid).map(|p| p.name)
}

/// Names that own `/dev/console` while nobody is really logged in.
const NOT_A_USER: &[&str] = &["root", "_mbsetupuser", "loginwindow"];

/// macOS: owner of `/dev/console` (skipping root / `_mbsetupuser` / `loginwindow`), resolved with
/// `getpwuid_r`. Linux (development): the current user.
pub fn console_user() -> Option<ConsoleUser> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::fs::MetadataExt;
        let uid = std::fs::metadata("/dev/console").ok()?.uid();
        if uid == 0 {
            return None;
        }
        let pw = passwd_for_uid(uid)?;
        if NOT_A_USER.contains(&pw.name.as_str()) {
            return None;
        }
        Some(ConsoleUser {
            uid,
            gid: pw.gid,
            name: pw.name,
            home: pw.home,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        // SAFETY: getuid never fails and has no preconditions.
        let uid = unsafe { libc::getuid() } as u32;
        let pw = passwd_for_uid(uid);
        let home = pw
            .as_ref()
            .map(|p| p.home.clone())
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))?;
        let name = pw
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| uid.to_string());
        let _ = NOT_A_USER;
        Some(ConsoleUser {
            uid,
            gid: pw.map(|p| p.gid).unwrap_or(uid),
            name,
            home,
        })
    }
}

/// System TCC database: only readable by a process that has Full Disk Access.
#[cfg(target_os = "macos")]
const TCC_DB: &str = "/Library/Application Support/com.apple.TCC/TCC.db";

/// macOS: whether this process has Full Disk Access (it can open the system TCC database
/// read-only). Linux: always `true`.
pub fn has_full_disk_access() -> bool {
    #[cfg(target_os = "macos")]
    {
        match std::fs::File::open(TCC_DB) {
            Ok(_) => true,
            Err(e) => {
                tracing::debug!(error = %e, "TCC.db not readable: no Full Disk Access");
                false
            }
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_current_user() {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() } as u32;
        let pw = passwd_for_uid(uid).expect("current uid resolves");
        assert!(!pw.name.is_empty());
        assert_eq!(user_name(uid), Some(pw.name));
        assert!(passwd_for_uid(4_000_000_000).is_none());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn linux_console_user_and_fda() {
        let u = console_user().expect("current user");
        assert!(u.home.is_absolute());
        assert!(has_full_disk_access());
    }
}
