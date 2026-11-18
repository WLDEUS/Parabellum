//! Read a file inside a user-controlled tree as root without following links: every directory component is
//! opened from `/` with `openat(O_DIRECTORY | O_NOFOLLOW)`, the file with `O_NOFOLLOW | O_NONBLOCK`, then
//! `fstat` checks it is a regular file owned by the expected user (or root) and not too large. The bytes
//! come from that descriptor, never from a second path lookup.

use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path};

fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by a successful open call and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn cname(s: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
}

/// Read `path` (absolute, no `..`) if it is a regular file owned by `owner` or root, at most `max` bytes.
/// `Ok(None)` when it does not exist. A symbolic link anywhere in the path is an error.
pub fn read_no_follow(path: &Path, owner: u32, max: u64) -> io::Result<Option<Vec<u8>>> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "absolute path required",
        ));
    }
    let names: Vec<&std::ffi::OsStr> = path
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(Ok(n)),
            Component::RootDir | Component::CurDir => None,
            _ => Some(Err(())),
        })
        .collect::<Result<_, ()>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "`..` refused"))?;
    let Some((file, dirs)) = names.split_last() else {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no file name"));
    };
    // SAFETY: valid NUL-terminated path; plain syscall.
    let mut dir = owned(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })?;
    for d in dirs {
        let c = cname(d)?;
        // SAFETY: `c` is NUL-terminated and `dir` a live descriptor.
        let next = unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        match owned(next) {
            Ok(fd) => dir = fd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    let c = cname(file)?;
    // SAFETY: as above.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    let fd = match owned(fd) {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut f = std::fs::File::from(fd);
    let md = f.metadata()?;
    use std::os::unix::fs::MetadataExt;
    if !md.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a regular file",
        ));
    }
    if md.uid() != owner && md.uid() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unexpected owner",
        ));
    }
    if md.len() > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "file too large"));
    }
    let mut buf = Vec::with_capacity(md.len() as usize);
    f.by_ref().take(max).read_to_end(&mut buf)?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_plain_files_and_refuses_links() {
        let t = tempfile::tempdir().unwrap();
        // macOS: /var -> /private/var is itself a link.
        let d = t.path().canonicalize().unwrap();
        let me = crate::system::euid();
        let f = d.join("a.db");
        std::fs::write(&f, b"hello").unwrap();
        assert_eq!(read_no_follow(&f, me, 100).unwrap().unwrap(), b"hello");
        assert!(read_no_follow(&f, me, 3).is_err(), "too large");
        assert!(read_no_follow(&d.join("none"), me, 100).unwrap().is_none());
        assert!(read_no_follow(&d.join("x/none"), me, 100)
            .unwrap()
            .is_none());
        std::os::unix::fs::symlink(&f, d.join("link")).unwrap();
        assert!(read_no_follow(&d.join("link"), me, 100).is_err());
        std::os::unix::fs::symlink(&d, d.join("dirlink")).unwrap();
        assert!(read_no_follow(&d.join("dirlink/a.db"), me, 100).is_err());
        assert!(read_no_follow(Path::new("relative"), me, 100).is_err());
        assert!(read_no_follow(&d.join("../x"), me, 100).is_err());
        if me != 0 {
            assert!(read_no_follow(&f, me + 1, 100).is_err(), "owner check");
        }
    }
}
