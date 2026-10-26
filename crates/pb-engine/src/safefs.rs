//! Symlink-safe filesystem primitives on directory file descriptors (`openat` family).
//!
//! The daemon runs as root and acts on paths inside user-writable trees, so path strings are never
//! trusted twice: a directory is opened component by component from `/` with
//! `O_DIRECTORY | O_NOFOLLOW` (any symlink component is refused), and every later operation
//! (`openat`, `mkdirat`, `unlinkat`, `symlinkat`, `fstatat`) is relative to such a descriptor.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

/// Max directory depth handled by the recursive helpers.
pub(crate) const MAX_TREE_DEPTH: usize = 256;

/// Error of a descriptor-chain walk.
#[derive(Debug)]
pub(crate) enum WalkError {
    /// The component ending at this path is a symbolic link.
    Symlink(PathBuf),
    /// Other I/O error.
    Io(io::Error),
}

impl From<io::Error> for WalkError {
    fn from(e: io::Error) -> Self {
        WalkError::Io(e)
    }
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

/// NUL-free C string of a path component.
pub(crate) fn cname(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL byte in file name"))
}

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(last_err())
    } else {
        Ok(ret)
    }
}

fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
    let fd = check(fd)?;
    // SAFETY: `fd` was just returned by a successful open call and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `open("/")`.
pub(crate) fn open_root() -> io::Result<OwnedFd> {
    // SAFETY: valid NUL-terminated path; plain syscall.
    owned(unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    })
}

/// `openat(dir, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)`.
pub(crate) fn openat_dir(dir: RawFd, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: `name` is NUL-terminated; plain syscall.
    owned(unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

/// `openat(dir, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)` (never blocks on a FIFO).
pub(crate) fn openat_read(dir: RawFd, name: &CStr) -> io::Result<File> {
    // SAFETY: `name` is NUL-terminated; plain syscall.
    let fd = owned(unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    })?;
    Ok(File::from(fd))
}

/// `openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)`.
pub(crate) fn openat_create_excl(dir: RawFd, name: &CStr, mode: u32) -> io::Result<File> {
    // SAFETY: `name` is NUL-terminated; the variadic mode is passed as an unsigned int.
    let fd = owned(unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    })?;
    Ok(File::from(fd))
}

/// `mkdirat(dir, name, mode)`.
pub(crate) fn mkdirat(dir: RawFd, name: &CStr, mode: u32) -> io::Result<()> {
    // SAFETY: `name` is NUL-terminated; plain syscall.
    check(unsafe { libc::mkdirat(dir, name.as_ptr(), mode as libc::mode_t) }).map(|_| ())
}

/// `unlinkat(dir, name, 0 | AT_REMOVEDIR)`.
pub(crate) fn unlinkat(dir: RawFd, name: &CStr, is_dir: bool) -> io::Result<()> {
    let flags = if is_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: `name` is NUL-terminated; plain syscall.
    check(unsafe { libc::unlinkat(dir, name.as_ptr(), flags) }).map(|_| ())
}

/// `symlinkat(target, dir, name)`.
pub(crate) fn symlinkat(target: &CStr, dir: RawFd, name: &CStr) -> io::Result<()> {
    // SAFETY: both strings are NUL-terminated; plain syscall.
    check(unsafe { libc::symlinkat(target.as_ptr(), dir, name.as_ptr()) }).map(|_| ())
}

/// `fchownat(dir, name, uid, gid, AT_SYMLINK_NOFOLLOW)` (owner of a symlink itself).
pub(crate) fn lchownat(dir: RawFd, name: &CStr, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: `name` is NUL-terminated; plain syscall.
    check(unsafe {
        libc::fchownat(
            dir,
            name.as_ptr(),
            uid as libc::uid_t,
            gid as libc::gid_t,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })
    .map(|_| ())
}

/// Kind and identity of a directory entry, without following symlinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntryStat {
    pub kind: EntryKind,
    pub dev: u64,
    pub ino: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[allow(clippy::unnecessary_cast, clippy::useless_conversion)]
fn entry_stat(st: &libc::stat) -> EntryStat {
    let fmt = st.st_mode & libc::S_IFMT;
    let kind = if fmt == libc::S_IFREG {
        EntryKind::File
    } else if fmt == libc::S_IFDIR {
        EntryKind::Dir
    } else if fmt == libc::S_IFLNK {
        EntryKind::Symlink
    } else {
        EntryKind::Other
    };
    EntryStat {
        kind,
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
    }
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`.
pub(crate) fn stat_at(dir: RawFd, name: &CStr) -> io::Result<EntryStat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is a valid out-pointer; `name` NUL-terminated.
    check(unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    // SAFETY: fstatat succeeded, so `st` is initialised.
    Ok(entry_stat(unsafe { &st.assume_init() }))
}

/// `fstat(fd)`.
pub(crate) fn stat_fd(fd: RawFd) -> io::Result<EntryStat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `st` is a valid out-pointer.
    check(unsafe { libc::fstat(fd, st.as_mut_ptr()) })?;
    // SAFETY: fstat succeeded.
    Ok(entry_stat(unsafe { &st.assume_init() }))
}

/// Normal components of an absolute, `..`-free path.
pub(crate) fn normal_components(path: &Path) -> io::Result<Vec<&OsStr>> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not absolute",
        ));
    }
    let mut out = Vec::new();
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path contains '..'",
                ));
            }
        }
    }
    Ok(out)
}

/// Opens the directory `path` from `/`, one component at a time with `O_NOFOLLOW`.
/// With `create = Some(mode, owner)`, missing components are created (`mkdirat`) and chowned.
pub(crate) fn open_dir_chain(
    path: &Path,
    create: Option<(u32, Option<(u32, u32)>)>,
) -> Result<OwnedFd, WalkError> {
    let mut cur = open_root()?;
    let mut walked = PathBuf::from("/");
    for comp in normal_components(path)? {
        walked.push(comp);
        let c = cname(comp)?;
        let next = match openat_dir(cur.as_raw_fd(), &c) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) && create.is_some() => {
                let (mode, owner) = create.unwrap_or((0o755, None));
                // EEXIST (lost race) is fine: the O_NOFOLLOW open below decides.
                let _ = mkdirat(cur.as_raw_fd(), &c, mode);
                let fd = openat_dir(cur.as_raw_fd(), &c)
                    .map_err(|e| classify(cur.as_raw_fd(), &c, &walked, e))?;
                if let Some((uid, gid)) = owner {
                    // SAFETY: valid fd; plain syscall. Best effort.
                    let _ = unsafe {
                        libc::fchown(fd.as_raw_fd(), uid as libc::uid_t, gid as libc::gid_t)
                    };
                }
                fd
            }
            Err(e) => return Err(classify(cur.as_raw_fd(), &c, &walked, e)),
        };
        cur = next;
    }
    Ok(cur)
}

/// Turns an `openat` failure into `Symlink` when the component is a symbolic link.
fn classify(dir: RawFd, name: &CStr, walked: &Path, e: io::Error) -> WalkError {
    match stat_at(dir, name) {
        Ok(s) if s.kind == EntryKind::Symlink => WalkError::Symlink(walked.to_path_buf()),
        _ => WalkError::Io(e),
    }
}

/// Removes the entry `name` of `dir` (recursively for directories), never following symlinks.
pub(crate) fn remove_tree_at(dir: RawFd, name: &CStr) -> io::Result<()> {
    remove_tree_inner(dir, name, 0)
}

fn remove_tree_inner(dir: RawFd, name: &CStr, depth: usize) -> io::Result<()> {
    let st = stat_at(dir, name)?;
    if st.kind != EntryKind::Dir {
        return unlinkat(dir, name, false);
    }
    if depth >= MAX_TREE_DEPTH {
        return Err(io::Error::other("directory tree too deep"));
    }
    let child = openat_dir(dir, name)?;
    for entry in list_dir(child.as_raw_fd())? {
        remove_tree_inner(child.as_raw_fd(), &entry, depth + 1)?;
    }
    drop(child);
    unlinkat(dir, name, true)
}

/// Names in a directory (without `.` and `..`).
pub(crate) fn list_dir(dir: RawFd) -> io::Result<Vec<CString>> {
    // fdopendir takes ownership of the descriptor: give it a duplicate.
    // SAFETY: plain syscall on a valid fd.
    let dup = check(unsafe { libc::fcntl(dir, libc::F_DUPFD_CLOEXEC, 0) })?;
    // SAFETY: `dup` is a valid directory descriptor we own; on success DIR* owns it.
    let d = unsafe { libc::fdopendir(dup) };
    if d.is_null() {
        let e = last_err();
        // SAFETY: fdopendir failed, so we still own `dup`.
        unsafe { libc::close(dup) };
        return Err(e);
    }
    let mut out = Vec::new();
    loop {
        // SAFETY: `d` is a valid DIR*; readdir returns NULL at the end (or on error).
        let ent = unsafe { libc::readdir(d) };
        if ent.is_null() {
            break;
        }
        // SAFETY: `ent` points to a valid dirent whose d_name is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let b = name.to_bytes();
        if b != b"." && b != b".." {
            out.push(name.to_owned());
        }
    }
    // SAFETY: `d` is valid and closed exactly once (closes `dup`).
    unsafe { libc::closedir(d) };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_rejects_symlinks_and_creates() {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir_all(base.join("a/b")).unwrap();
        std::os::unix::fs::symlink(base.join("a"), base.join("link")).unwrap();
        assert!(open_dir_chain(&base.join("a/b"), None).is_ok());
        match open_dir_chain(&base.join("link/b"), None) {
            Err(WalkError::Symlink(p)) => assert_eq!(p, base.join("link")),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            open_dir_chain(&base.join("a/../a"), None),
            Err(WalkError::Io(_))
        ));
        let fd = open_dir_chain(&base.join("a/new/deeper"), Some((0o750, None))).unwrap();
        assert_eq!(stat_fd(fd.as_raw_fd()).unwrap().kind, EntryKind::Dir);
        // remove_tree_at never follows the symlink.
        std::fs::write(base.join("a/b/f"), b"x").unwrap();
        std::os::unix::fs::symlink(base.join("a/b"), base.join("a/new/l")).unwrap();
        let a = open_dir_chain(&base.join("a"), None).unwrap();
        remove_tree_at(a.as_raw_fd(), c"new").unwrap();
        assert!(base.join("a/b/f").exists());
        assert!(!base.join("a/new").exists());
    }
}
