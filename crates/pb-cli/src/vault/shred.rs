//! Effacement sûr: overwrite a file's contents once with random data, truncate it, rename it to a
//! random name, then unlink it. Never follows symlinks; refuses anything outside the user's home and
//! external volumes, the home's standard folders themselves, and the vault bundle.
//!
//! Honest limits (also shown in the app): on an SSD with APFS and TRIM, overwriting in place does not
//! guarantee the old blocks are gone: the drive's flash translation layer writes the new data
//! elsewhere (wear levelling), APFS clones and local Time Machine snapshots keep the old blocks, and
//! files compressed by APFS or not downloaded from iCloud cannot be overwritten in place. The real
//! guarantee is cryptographic: FileVault (the old blocks are ciphertext under a key that never leaves
//! the Secure Enclave) or keeping secrets in the vault and destroying it (its key disappears). Inside
//! the open vault, files are simply deleted.
//!
//! All operations are relative to directory descriptors opened with `O_NOFOLLOW` (`openat`,
//! `unlinkat`, `renameat`), so a path swapped for a symlink mid-way is never followed.

// `libc::stat` field types differ between macOS (dev_t = i32, mode_t = u16) and Linux (u64, u32):
// the casts are needed on one of the two.
#![allow(clippy::unnecessary_cast)]

use super::normalize;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// Overwrite buffer.
const CHUNK: usize = 1 << 20;
/// Maximum directory depth.
const MAX_DEPTH: usize = 256;
/// Per-item error messages kept in a report.
const MAX_ERRORS: usize = 20;
/// macOS `SF_DATALESS`: iCloud placeholder whose contents are not on the Mac (opening it would
/// download it).
const SF_DATALESS: u32 = 0x4000_0000;
/// macOS `UF_COMPRESSED` (transparent APFS/HFS+ compression: data lives in a resource fork).
const UF_COMPRESSED: u32 = 0x0000_0020;

/// Folders of the home that are never deleted themselves (their contents can be).
const PROTECTED_HOME_DIRS: &[&str] = &[
    ".Trash",
    "Applications",
    "Desktop",
    "Documents",
    "Downloads",
    "Library",
    "Library/Application Support",
    "Library/CloudStorage",
    "Library/Containers",
    "Library/Group Containers",
    "Library/Mobile Documents",
    "Library/Preferences",
    "Movies",
    "Music",
    "Pictures",
    "Public",
];
/// Home subtrees never touched at all.
const PROTECTED_HOME_TREES: &[&str] = &["Library/Keychains"];

/// Where a target is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Zone {
    /// Inside the open vault: plain deletion (the data is encrypted at rest).
    Vault,
    /// In the user's home: overwrite then delete.
    Home,
    /// On an external volume (/Volumes/…): overwrite then delete.
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Gone.
    Deleted,
    /// `--dry-run`: would be deleted.
    Planned,
    /// Refused by the safety rules (nothing touched).
    Refused,
    /// Not (entirely) deleted.
    Failed,
}

/// Result for one requested path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShredReport {
    pub path: String,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<Zone>,
    /// Files (and links / special files) deleted.
    pub files: u64,
    /// Folders deleted.
    pub dirs: u64,
    /// Total size of the regular files.
    pub bytes: u64,
    /// Bytes overwritten with random data.
    pub overwritten_bytes: u64,
    /// Files deleted without being overwritten (vault, hard links, compressed, iCloud, links).
    pub not_overwritten: u64,
    /// French notes (limits that applied).
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ShredReport {
    fn new(path: &Path) -> Self {
        ShredReport {
            path: path.to_string_lossy().into_owned(),
            outcome: Outcome::Failed,
            zone: None,
            files: 0,
            dirs: 0,
            bytes: 0,
            overwritten_bytes: 0,
            not_overwritten: 0,
            warnings: Vec::new(),
            error: None,
        }
    }

    fn refused(mut self, why: impl Into<String>) -> Self {
        self.outcome = Outcome::Refused;
        self.error = Some(why.into());
        self
    }
}

/// What the safety rules need to know.
#[derive(Debug, Clone)]
pub struct ShredContext {
    /// Canonical home folder.
    pub home: PathBuf,
    /// Canonical mount point of the open vault.
    pub vault_mount: Option<PathBuf>,
    /// Canonical vault bundle (never deleted here: « Détruire le coffre »).
    pub vault_bundle: Option<PathBuf>,
    /// `st_dev` of `/`.
    pub root_dev: u64,
}

impl ShredContext {
    pub fn new(home: &Path, vault_mount: Option<&Path>, vault_bundle: Option<&Path>) -> Self {
        let canon = |p: &Path| super::canonical_lenient(p);
        ShredContext {
            home: canon(home),
            vault_mount: vault_mount.map(canon),
            vault_bundle: vault_bundle.map(canon),
            root_dev: lstat_path(Path::new("/"))
                .map(|s| s.st_dev as u64)
                .unwrap_or(0),
        }
    }
}

/// Safety rules on a canonical path. `is_external(volume_root)` tells whether `/Volumes/<name>` is
/// a mounted volume other than the startup disk.
pub fn check_target(
    full: &Path,
    ctx: &ShredContext,
    is_external: &dyn Fn(&Path) -> bool,
) -> Result<Zone, String> {
    if full.parent().is_none() || full.file_name().is_none() {
        return Err("chemin refusé".into());
    }
    if let Some(b) = &ctx.vault_bundle {
        if full.starts_with(b) {
            return Err("c'est le coffre lui-même : utilisez « Détruire le coffre »".into());
        }
        if b.starts_with(full) {
            return Err("ce dossier contient le coffre : utilisez « Détruire le coffre »".into());
        }
    }
    if let Some(m) = &ctx.vault_mount {
        if full.starts_with(m) && full != m {
            return Ok(Zone::Vault);
        }
        if m.starts_with(full) {
            return Err("ce dossier contient le coffre ouvert".into());
        }
    }
    if let Ok(rel) = full.strip_prefix(&ctx.home) {
        if rel.as_os_str().is_empty() {
            return Err("impossible de supprimer votre dossier personnel".into());
        }
        if PROTECTED_HOME_DIRS.iter().any(|d| rel == Path::new(d)) {
            return Err(format!(
                "dossier système de votre compte ({}) : supprimez son contenu plutôt que le dossier",
                rel.display()
            ));
        }
        if PROTECTED_HOME_TREES.iter().any(|d| rel.starts_with(d)) {
            return Err("trousseaux de clés : jamais supprimés ici".into());
        }
        return Ok(Zone::Home);
    }
    if let Ok(rel) = full.strip_prefix("/Volumes") {
        let mut comps = rel.components();
        if let (Some(vol), Some(_)) = (comps.next(), comps.next()) {
            let root = Path::new("/Volumes").join(vol);
            if is_external(&root) {
                return Ok(Zone::External);
            }
            return Err("ce volume n'est pas un disque externe".into());
        }
        return Err("impossible de supprimer un volume entier".into());
    }
    Err("hors de votre dossier personnel et des volumes externes : refusé".into())
}

/// `/Volumes/<name>` is a real directory on another device than `/`.
pub fn volume_is_external(root: &Path, root_dev: u64) -> bool {
    lstat_path(root).is_ok_and(|s| is_dir(&s) && s.st_dev as u64 != root_dev)
}

/// Shred each path (or only check and measure with `dry_run`).
pub fn shred_paths(paths: &[PathBuf], ctx: &ShredContext, dry_run: bool) -> Vec<ShredReport> {
    let mut rng = Rng::from_os();
    paths
        .iter()
        .map(|p| shred_one(p, ctx, dry_run, &mut rng))
        .collect()
}

/// Items of the user's Trash (~/.Trash) and of external volumes' `.Trashes/<uid>`.
pub fn trash_items(home: &Path) -> io::Result<Vec<PathBuf>> {
    let mut v = Vec::new();
    let trash = home.join(".Trash");
    match std::fs::read_dir(&trash) {
        Ok(rd) => v.extend(rd.flatten().map(|e| e.path())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "accès à la Corbeille refusé par macOS : autorisez Parabellum dans Réglages Système > \
                 Confidentialité et sécurité > Accès complet au disque",
        )),
        Err(e) => return Err(e),
    }
    // SAFETY: no preconditions.
    let uid = unsafe { libc::getuid() };
    if let Ok(vols) = std::fs::read_dir("/Volumes") {
        for vol in vols.flatten() {
            let dir = vol.path().join(".Trashes").join(uid.to_string());
            if let Ok(rd) = std::fs::read_dir(&dir) {
                v.extend(rd.flatten().map(|e| e.path()));
            }
        }
    }
    v.sort();
    Ok(v)
}

// ---------------------------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct Counters {
    hard_links: u64,
    compressed: u64,
    dataless: u64,
    symlinks: u64,
    special: u64,
    mounts_skipped: u64,
    errors: Vec<String>,
}

struct Job<'a> {
    rep: &'a mut ShredReport,
    zone: Zone,
    dry_run: bool,
    rng: &'a mut Rng,
    c: Counters,
    uid: u32,
}

fn shred_one(path: &Path, ctx: &ShredContext, dry_run: bool, rng: &mut Rng) -> ShredReport {
    let rep = ShredReport::new(path);
    let Some(norm) = normalize(path) else {
        return rep.refused("chemin absolu sans « .. » attendu");
    };
    let (Some(parent), Some(name)) = (norm.parent(), norm.file_name()) else {
        return rep.refused("chemin refusé");
    };
    let parent_c = match std::fs::canonicalize(parent) {
        Ok(p) => p,
        Err(e) => return failed(rep, &e),
    };
    let full = parent_c.join(name);
    let zone = match check_target(&full, ctx, &|r| volume_is_external(r, ctx.root_dev)) {
        Ok(z) => z,
        Err(why) => return rep.refused(why),
    };
    let mut rep = rep;
    rep.zone = Some(zone);
    let dirfd = match open_dir_nofollow(&parent_c) {
        Ok(fd) => fd,
        Err(e) => return failed(rep, &e),
    };
    let parent_dev = match fstat(dirfd.as_raw_fd()) {
        Ok(s) => s.st_dev as u64,
        Err(e) => return failed(rep, &e),
    };
    // SAFETY: no preconditions.
    let uid = unsafe { libc::geteuid() };
    let mut job = Job {
        rep: &mut rep,
        zone,
        dry_run,
        rng,
        c: Counters::default(),
        uid,
    };
    let res = job.entry(dirfd.as_raw_fd(), name, &full, parent_dev, 0);
    let c = std::mem::take(&mut job.c);
    drop(job);
    finish(&mut rep, c, res, dry_run);
    rep
}

fn failed(mut rep: ShredReport, e: &io::Error) -> ShredReport {
    rep.outcome = Outcome::Failed;
    rep.error = Some(french_io(e));
    rep
}

fn finish(rep: &mut ShredReport, c: Counters, res: io::Result<()>, dry_run: bool) {
    let mut w = Vec::new();
    if c.hard_links > 0 {
        w.push(format!(
            "{} fichier(s) avec plusieurs liens physiques : supprimé(s) sans réécriture (le contenu reste accessible par les autres liens)",
            c.hard_links
        ));
    }
    if c.compressed > 0 {
        w.push(format!(
            "{} fichier(s) compressé(s) par macOS : supprimé(s) sans réécriture",
            c.compressed
        ));
    }
    if c.dataless > 0 {
        w.push(format!(
            "{} fichier(s) iCloud non téléchargé(s) : supprimé(s) sans réécriture (et d'iCloud Drive)",
            c.dataless
        ));
    }
    if c.symlinks > 0 {
        w.push(format!(
            "{} lien(s) symbolique(s) supprimé(s) ; leur cible n'est pas touchée",
            c.symlinks
        ));
    }
    if c.special > 0 {
        w.push(format!(
            "{} fichier(s) spéciaux (sockets, tubes) supprimé(s)",
            c.special
        ));
    }
    if c.mounts_skipped > 0 {
        w.push(format!(
            "{} point(s) de montage ignoré(s) (autre volume)",
            c.mounts_skipped
        ));
    }
    w.extend(c.errors.iter().cloned());
    rep.warnings = w;
    match res {
        Ok(()) if c.errors.is_empty() => {
            rep.outcome = if dry_run {
                Outcome::Planned
            } else {
                Outcome::Deleted
            };
        }
        Ok(()) => {
            rep.outcome = Outcome::Failed;
            rep.error = Some(format!(
                "{} élément(s) n'ont pas pu être supprimés",
                c.errors.len()
            ));
        }
        Err(e) => {
            rep.outcome = Outcome::Failed;
            rep.error = Some(french_io(&e));
        }
    }
}

impl Job<'_> {
    /// One directory entry: dispatch on its type (never following links).
    fn entry(
        &mut self,
        dirfd: RawFd,
        name: &OsStr,
        display: &Path,
        parent_dev: u64,
        depth: usize,
    ) -> io::Result<()> {
        let st = lstat_at(dirfd, name)?;
        match st.st_mode & libc::S_IFMT {
            libc::S_IFLNK => {
                self.c.symlinks += 1;
                self.rep.files += 1;
                self.rep.not_overwritten += 1;
                self.remove(dirfd, name, false)
            }
            libc::S_IFREG => self.file(dirfd, name, &st),
            libc::S_IFDIR => {
                if st.st_dev as u64 != parent_dev {
                    if depth == 0 {
                        return Err(io::Error::other("c'est un point de montage : refusé"));
                    }
                    self.c.mounts_skipped += 1;
                    return Err(io::Error::other(format!(
                        "{} : point de montage ignoré",
                        display.display()
                    )));
                }
                self.dir(dirfd, name, display, &st, depth)
            }
            _ => {
                self.c.special += 1;
                self.rep.files += 1;
                self.rep.not_overwritten += 1;
                self.remove(dirfd, name, false)
            }
        }
    }

    fn file(&mut self, dirfd: RawFd, name: &OsStr, st: &libc::stat) -> io::Result<()> {
        let size = st.st_size.max(0) as u64;
        self.rep.files += 1;
        self.rep.bytes += size;
        let flags = st_flags(st);
        let skip_reason = if self.zone == Zone::Vault {
            Some(None)
        } else if st.st_nlink > 1 {
            Some(Some(&mut self.c.hard_links))
        } else if flags & SF_DATALESS != 0 {
            Some(Some(&mut self.c.dataless))
        } else if flags & UF_COMPRESSED != 0 {
            Some(Some(&mut self.c.compressed))
        } else {
            None
        };
        if let Some(counter) = skip_reason {
            if let Some(c) = counter {
                *c += 1;
            }
            self.rep.not_overwritten += 1;
            return self.remove(dirfd, name, false);
        }
        if self.dry_run {
            self.rep.overwritten_bytes += size;
            return Ok(());
        }
        let fd = self.open_for_write(dirfd, name, st)?;
        let written = overwrite(fd.as_raw_fd(), size, self.rng)?;
        full_sync(fd.as_raw_fd());
        // SAFETY: valid owned descriptor.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        full_sync(fd.as_raw_fd());
        drop(fd);
        self.rep.overwritten_bytes += written;
        self.remove(dirfd, name, false)
    }

    /// `O_WRONLY|O_NOFOLLOW`, checking it is still the file we looked at; a read-only file of ours
    /// gets `u+w` first.
    fn open_for_write(&self, dirfd: RawFd, name: &OsStr, st: &libc::stat) -> io::Result<OwnedFd> {
        let flags = libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
        let fd = match open_at(dirfd, name, flags) {
            Ok(fd) => fd,
            Err(e) if e.raw_os_error() == Some(libc::EACCES) && st.st_uid == self.uid => {
                let ro = open_at(
                    dirfd,
                    name,
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )?;
                same_file(&fstat(ro.as_raw_fd())?, st)?;
                // SAFETY: valid owned descriptor.
                if unsafe {
                    libc::fchmod(
                        ro.as_raw_fd(),
                        (st.st_mode & 0o7777) as libc::mode_t | 0o200,
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                drop(ro);
                open_at(dirfd, name, flags)?
            }
            Err(e) => return Err(e),
        };
        same_file(&fstat(fd.as_raw_fd())?, st)?;
        Ok(fd)
    }

    fn dir(
        &mut self,
        dirfd: RawFd,
        name: &OsStr,
        display: &Path,
        st: &libc::stat,
        depth: usize,
    ) -> io::Result<()> {
        if depth > MAX_DEPTH {
            return Err(io::Error::other("arborescence trop profonde"));
        }
        let dfd = open_at(
            dirfd,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        same_file(&fstat(dfd.as_raw_fd())?, st)?;
        if !self.dry_run && st.st_mode & 0o200 == 0 && st.st_uid == self.uid {
            // SAFETY: valid owned descriptor.
            unsafe {
                libc::fchmod(
                    dfd.as_raw_fd(),
                    (st.st_mode & 0o7777) as libc::mode_t | 0o700,
                )
            };
        }
        let dev = st.st_dev as u64;
        for child in list_dir(dfd.as_raw_fd())? {
            let child_display = display.join(&child);
            if let Err(e) = self.entry(dfd.as_raw_fd(), &child, &child_display, dev, depth + 1) {
                if self.c.errors.len() < MAX_ERRORS {
                    let msg = french_io(&e);
                    self.c
                        .errors
                        .push(if msg.starts_with(&*child_display.to_string_lossy()) {
                            msg
                        } else {
                            format!("{} : {msg}", child_display.display())
                        });
                } else if self.c.errors.len() == MAX_ERRORS {
                    self.c
                        .errors
                        .push("… (autres erreurs non affichées)".into());
                }
            }
        }
        drop(dfd);
        self.rep.dirs += 1;
        self.remove(dirfd, name, true)
    }

    /// Rename to a random name (the old name leaves the directory), then unlink.
    fn remove(&mut self, dirfd: RawFd, name: &OsStr, is_dir: bool) -> io::Result<()> {
        if self.dry_run {
            return Ok(());
        }
        let flag = if is_dir { libc::AT_REMOVEDIR } else { 0 };
        if self.zone == Zone::Vault {
            return unlink_at(dirfd, name, flag);
        }
        let tmp = OsString::from(self.rng.name(16));
        let renamed = matches!(
            lstat_at(dirfd, &tmp),
            Err(ref e) if e.kind() == io::ErrorKind::NotFound
        ) && rename_at(dirfd, name, &tmp).is_ok();
        if renamed {
            unlink_at(dirfd, &tmp, flag)
        } else {
            unlink_at(dirfd, name, flag)
        }
    }
}

fn same_file(a: &libc::stat, b: &libc::stat) -> io::Result<()> {
    if a.st_dev != b.st_dev || a.st_ino != b.st_ino {
        return Err(io::Error::other(
            "le fichier a été remplacé pendant l'opération : arrêt",
        ));
    }
    Ok(())
}

/// Overwrite the allocated ranges of the file (holes of sparse files are left alone).
fn overwrite(fd: RawFd, size: u64, rng: &mut Rng) -> io::Result<u64> {
    let mut buf = vec![0u8; CHUNK];
    let mut written = 0u64;
    for (start, end) in data_extents(fd, size) {
        let mut off = start;
        while off < end {
            let n = ((end - off) as usize).min(CHUNK);
            rng.fill(&mut buf[..n]);
            let mut done = 0;
            while done < n {
                // SAFETY: buf[done..n] is valid for reads; fd is open for writing.
                let r = unsafe {
                    libc::pwrite(
                        fd,
                        buf[done..n].as_ptr().cast(),
                        n - done,
                        (off + done as u64) as libc::off_t,
                    )
                };
                if r < 0 {
                    let e = io::Error::last_os_error();
                    if e.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(e);
                }
                if r == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "écriture impossible",
                    ));
                }
                done += r as usize;
            }
            off += n as u64;
            written += n as u64;
        }
    }
    Ok(written)
}

/// Data ranges `[start, end)` within `size` (SEEK_DATA / SEEK_HOLE); the whole file when the file
/// system cannot tell.
fn data_extents(fd: RawFd, size: u64) -> Vec<(u64, u64)> {
    if size == 0 {
        return Vec::new();
    }
    let whole = vec![(0, size)];
    let mut v = Vec::new();
    let mut pos: u64 = 0;
    while pos < size {
        // SAFETY: lseek on a valid descriptor.
        let data = unsafe { libc::lseek(fd, pos as libc::off_t, libc::SEEK_DATA) };
        if data < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENXIO) {
                break; // no data after pos
            }
            return whole;
        }
        // SAFETY: as above.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 || hole < data {
            return whole;
        }
        let (start, end) = (data as u64, (hole as u64).min(size));
        if end > start {
            v.push((start, end));
        }
        if hole as u64 <= pos {
            return whole; // no progress: do not trust these answers
        }
        pos = hole as u64;
    }
    v
}

/// Flush to the storage device (F_FULLFSYNC on macOS: past the drive's cache).
fn full_sync(fd: RawFd) {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: fcntl on a valid descriptor.
        if unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) } == 0 {
            return;
        }
    }
    // SAFETY: fsync on a valid descriptor.
    unsafe { libc::fsync(fd) };
}

#[cfg(target_os = "macos")]
fn st_flags(st: &libc::stat) -> u32 {
    st.st_flags
}

#[cfg(not(target_os = "macos"))]
fn st_flags(_st: &libc::stat) -> u32 {
    0
}

fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

fn cstr(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "nom invalide"))
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn lstat_path(p: &Path) -> io::Result<libc::stat> {
    let c = cstr(p.as_os_str())?;
    // SAFETY: zeroed stat filled by lstat; c is a valid C string.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        check(libc::lstat(c.as_ptr(), &mut st))?;
        Ok(st)
    }
}

fn lstat_at(dirfd: RawFd, name: &OsStr) -> io::Result<libc::stat> {
    let c = cstr(name)?;
    // SAFETY: as above, relative to a valid directory descriptor.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        check(libc::fstatat(
            dirfd,
            c.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        ))?;
        Ok(st)
    }
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    // SAFETY: zeroed stat filled by fstat.
    unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        check(libc::fstat(fd, &mut st))?;
        Ok(st)
    }
}

fn open_at(dirfd: RawFd, name: &OsStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    let c = cstr(name)?;
    // SAFETY: openat returns a new descriptor we own, or -1.
    let fd = unsafe { libc::openat(dirfd, c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is a fresh, valid descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open a canonical directory path; on macOS no component may be a symlink (O_NOFOLLOW_ANY).
fn open_dir_nofollow(p: &Path) -> io::Result<OwnedFd> {
    #[cfg(target_os = "macos")]
    let extra = libc::O_NOFOLLOW_ANY;
    #[cfg(not(target_os = "macos"))]
    let extra = libc::O_NOFOLLOW;
    let c = cstr(p.as_os_str())?;
    // SAFETY: as open_at.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | extra,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn unlink_at(dirfd: RawFd, name: &OsStr, flags: libc::c_int) -> io::Result<()> {
    let c = cstr(name)?;
    // SAFETY: valid directory descriptor and C string.
    check(unsafe { libc::unlinkat(dirfd, c.as_ptr(), flags) })
}

fn rename_at(dirfd: RawFd, from: &OsStr, to: &OsStr) -> io::Result<()> {
    let (a, b) = (cstr(from)?, cstr(to)?);
    // SAFETY: valid directory descriptor and C strings.
    check(unsafe { libc::renameat(dirfd, a.as_ptr(), dirfd, b.as_ptr()) })
}

/// Names in a directory (without `.` and `..`).
fn list_dir(fd: RawFd) -> io::Result<Vec<OsString>> {
    // fdopendir takes ownership of the descriptor: give it a duplicate.
    // SAFETY: dup of a valid descriptor.
    let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: dup is ours; on failure we close it.
    let dir = unsafe { libc::fdopendir(dup) };
    if dir.is_null() {
        let e = io::Error::last_os_error();
        // SAFETY: dup is still ours.
        unsafe { libc::close(dup) };
        return Err(e);
    }
    // SAFETY: rewind so a reused descriptor lists from the start.
    unsafe { libc::rewinddir(dir) };
    let mut v = Vec::new();
    loop {
        // SAFETY: dir is a valid DIR*; the entry is copied before the next call.
        let ent = unsafe { libc::readdir(dir) };
        if ent.is_null() {
            break;
        }
        // SAFETY: d_name is NUL-terminated.
        let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let b = name.to_bytes();
        if b != b"." && b != b".." {
            v.push(OsString::from_vec(b.to_vec()));
        }
    }
    // SAFETY: closes dir and dup.
    unsafe { libc::closedir(dir) };
    Ok(v)
}

/// French message for an I/O error.
pub fn french_io(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ENOENT) => "introuvable".into(),
        Some(libc::EACCES) => "accès refusé".into(),
        Some(libc::EPERM) => {
            "opération non autorisée (fichier verrouillé, protégé par macOS, ou accès complet au disque requis)"
                .into()
        }
        Some(libc::ENOTEMPTY) => "dossier non vide".into(),
        Some(libc::EBUSY) => "en cours d'utilisation".into(),
        Some(libc::EROFS) => "volume en lecture seule".into(),
        Some(libc::ELOOP) => "lien symbolique dans le chemin : refusé".into(),
        _ => e.to_string(),
    }
}

/// xoshiro256** seeded from the OS: fast random filler (not a key; it only has to look random).
pub struct Rng([u64; 4]);

impl Rng {
    pub fn from_os() -> Self {
        let mut seed = [0u8; 32];
        let ok = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut seed))
            .is_ok();
        if !ok {
            let t = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            seed[..16].copy_from_slice(&t.to_le_bytes());
            seed[16..20].copy_from_slice(&std::process::id().to_le_bytes());
        }
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut s = [0u64; 4];
        for (i, w) in s.iter_mut().enumerate() {
            *w = u64::from_le_bytes(seed[i * 8..i * 8 + 8].try_into().unwrap_or([0; 8]));
        }
        if s.iter().all(|w| *w == 0) {
            s[0] = 0x9E37_79B9_7F4A_7C15;
        }
        Rng(s)
    }

    pub fn next_u64(&mut self) -> u64 {
        let s = &mut self.0;
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    pub fn fill(&mut self, buf: &mut [u8]) {
        let mut chunks = buf.chunks_exact_mut(8);
        for c in &mut chunks {
            c.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        let rest = chunks.into_remainder();
        if !rest.is_empty() {
            let b = self.next_u64().to_le_bytes();
            let n = rest.len();
            rest.copy_from_slice(&b[..n]);
        }
    }

    /// Random `[a-z0-9]` name.
    pub fn name(&mut self, len: usize) -> String {
        const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|_| A[(self.next_u64() % A.len() as u64) as usize] as char)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn ctx(home: &Path) -> ShredContext {
        ShredContext::new(home, None, None)
    }

    fn no_ext(_: &Path) -> bool {
        false
    }

    #[test]
    fn rules_home() {
        let c = ShredContext {
            home: "/Users/camille".into(),
            vault_mount: None,
            vault_bundle: Some(
                "/Users/camille/Library/Application Support/Parabellum/Vault/Coffre.sparsebundle"
                    .into(),
            ),
            root_dev: 1,
        };
        let ck = |p: &str| check_target(Path::new(p), &c, &no_ext);
        assert_eq!(ck("/Users/camille/Documents/relevé.pdf"), Ok(Zone::Home));
        assert_eq!(ck("/Users/camille/.Trash/x"), Ok(Zone::Home));
        assert_eq!(ck("/Users/camille/Library/Caches/x"), Ok(Zone::Home));
        for refused in [
            "/Users/camille",
            "/Users/camille/Documents",
            "/Users/camille/Library",
            "/Users/camille/.Trash",
            "/Users/camille/Library/Keychains/login.keychain-db",
            "/Users/camille/Library/Application Support/Parabellum/Vault/Coffre.sparsebundle",
            "/Users/camille/Library/Application Support/Parabellum/Vault/Coffre.sparsebundle/bands/0",
            "/Users/camille/Library/Application Support/Parabellum",
            "/Users/camille2/x",
            "/Users/someone/x",
            "/System/Library/x",
            "/Library/Preferences/x",
            "/Applications/Safari.app",
            "/private/etc/hosts",
            "/usr/bin/true",
            "/Volumes",
            "/Volumes/USB",
            "/",
        ] {
            assert!(ck(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn rules_vault_and_volumes() {
        let c = ShredContext {
            home: "/Users/camille".into(),
            vault_mount: Some("/Volumes/Coffre".into()),
            vault_bundle: None,
            root_dev: 1,
        };
        let ext = |p: &Path| p == Path::new("/Volumes/USB") || p == Path::new("/Volumes/Coffre");
        let ck = |p: &str| check_target(Path::new(p), &c, &ext);
        assert_eq!(ck("/Volumes/Coffre/secret.txt"), Ok(Zone::Vault));
        assert_eq!(ck("/Volumes/Coffre/a/b"), Ok(Zone::Vault));
        assert!(ck("/Volumes/Coffre").is_err());
        assert_eq!(ck("/Volumes/USB/photo.jpg"), Ok(Zone::External));
        assert_eq!(ck("/Volumes/USB/.Trashes/501/x"), Ok(Zone::External));
        assert!(ck("/Volumes/Macintosh HD/Users/camille/x").is_err());
        assert!(ck("/Volumes/USB").is_err());
        // A vault mounted inside the home.
        let c = ShredContext {
            home: "/Users/camille".into(),
            vault_mount: Some("/Users/camille/Coffre".into()),
            vault_bundle: None,
            root_dev: 1,
        };
        let ck = |p: &str| check_target(Path::new(p), &c, &no_ext);
        assert_eq!(ck("/Users/camille/Coffre/x"), Ok(Zone::Vault));
        assert!(ck("/Users/camille/Coffre").is_err());
        assert_eq!(ck("/Users/camille/Coffre2/x"), Ok(Zone::Home));
    }

    #[test]
    fn overwrites_then_deletes_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("relevé bancaire.txt");
        std::fs::write(&f, vec![b'A'; 3 * CHUNK + 17]).unwrap();
        let reps = shred_paths(std::slice::from_ref(&f), &ctx(d.path()), false);
        let r = &reps[0];
        assert_eq!(r.outcome, Outcome::Deleted, "{r:?}");
        assert_eq!(r.zone, Some(Zone::Home));
        assert_eq!(r.files, 1);
        assert_eq!(r.bytes, (3 * CHUNK + 17) as u64);
        assert_eq!(r.overwritten_bytes, (3 * CHUNK + 17) as u64);
        assert!(!f.exists());
        // Nothing left behind (no renamed leftovers).
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn overwrite_replaces_every_byte() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("x");
        let size = CHUNK + 4096 + 3;
        std::fs::write(&f, vec![0u8; size]).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&f).unwrap();
        let mut rng = Rng::from_seed([7; 32]);
        let n = overwrite(file.as_raw_fd(), size as u64, &mut rng).unwrap();
        assert_eq!(n, size as u64);
        drop(file);
        let data = std::fs::read(&f).unwrap();
        assert_eq!(data.len(), size);
        // Random data: no long run of the original zeros survives.
        let zeros = data.iter().filter(|b| **b == 0).count();
        assert!(zeros < size / 100, "{zeros} zero bytes left");
        let mut longest = 0;
        let mut run = 0;
        for b in &data {
            run = if *b == 0 { run + 1 } else { 0 };
            longest = longest.max(run);
        }
        assert!(longest < 8);
    }

    #[test]
    fn sparse_files_keep_holes() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("sparse.img");
        let file = std::fs::File::create(&f).unwrap();
        file.set_len(64 << 20).unwrap();
        use std::os::unix::fs::FileExt;
        file.write_all_at(&[1u8; 4096], 8 << 20).unwrap();
        file.sync_all().unwrap();
        let ext = data_extents(file.as_raw_fd(), 64 << 20);
        let total: u64 = ext.iter().map(|(a, b)| b - a).sum();
        // tmpfs/ext4 report the single data block; other file systems may report everything.
        assert!((4096..=64 << 20).contains(&total), "{ext:?}");
        assert!(ext
            .iter()
            .any(|(a, b)| *a <= 8 << 20 && *b >= (8 << 20) + 4096));
        drop(file);
        let r = &shred_paths(std::slice::from_ref(&f), &ctx(d.path()), false)[0];
        assert_eq!(r.outcome, Outcome::Deleted);
        assert_eq!(r.overwritten_bytes, total);
        assert!(!f.exists());
    }

    #[test]
    fn directories_links_and_hard_links() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path();
        let outside = home.join("outside.txt");
        std::fs::write(&outside, "do not touch").unwrap();
        let dir = home.join("Dossier secret");
        std::fs::create_dir_all(dir.join("sous/dossier")).unwrap();
        std::fs::write(dir.join("a.txt"), "aaaa").unwrap();
        std::fs::write(dir.join("sous/dossier/b.bin"), vec![9u8; 10_000]).unwrap();
        std::fs::write(dir.join("vide"), "").unwrap();
        symlink(&outside, dir.join("lien")).unwrap();
        symlink(home, dir.join("lien-dossier")).unwrap();
        std::fs::hard_link(&outside, dir.join("lien-physique")).unwrap();
        // Read-only file and folder of ours.
        std::fs::write(dir.join("sous/lecture-seule"), "ro").unwrap();
        std::fs::set_permissions(
            dir.join("sous/lecture-seule"),
            std::fs::Permissions::from_mode(0o444),
        )
        .unwrap();
        std::fs::set_permissions(
            dir.join("sous/dossier"),
            std::fs::Permissions::from_mode(0o555),
        )
        .unwrap();

        let planned = &shred_paths(std::slice::from_ref(&dir), &ctx(home), true)[0];
        assert_eq!(planned.outcome, Outcome::Planned, "{planned:?}");
        assert!(dir.join("a.txt").exists());

        let r = &shred_paths(std::slice::from_ref(&dir), &ctx(home), false)[0];
        assert_eq!(r.outcome, Outcome::Deleted, "{r:?}");
        assert_eq!(r.files, 7);
        assert_eq!(r.dirs, 3);
        assert_eq!(r.not_overwritten, 3); // 2 symlinks + 1 hard link
        assert_eq!(r.overwritten_bytes, 4 + 10_000 + 2);
        assert_eq!(planned.files, r.files);
        assert_eq!(planned.overwritten_bytes, r.overwritten_bytes);
        assert!(r.warnings.iter().any(|w| w.contains("liens physiques")));
        assert!(r.warnings.iter().any(|w| w.contains("symbolique")));
        assert!(!dir.exists());
        // Link targets untouched.
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "do not touch");
        assert!(home.is_dir());
    }

    #[test]
    fn top_level_symlink_removes_only_the_link() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("cible.txt");
        std::fs::write(&target, "keep").unwrap();
        let link = d.path().join("raccourci");
        symlink(&target, &link).unwrap();
        let r = &shred_paths(std::slice::from_ref(&link), &ctx(d.path()), false)[0];
        assert_eq!(r.outcome, Outcome::Deleted);
        assert_eq!(r.overwritten_bytes, 0);
        assert!(link.symlink_metadata().is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }

    #[test]
    fn symlinked_parent_is_resolved_then_checked() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::fs::write(elsewhere.path().join("f"), "x").unwrap();
        // ~/raccourci -> a folder outside the home: the real location is outside, refused.
        symlink(elsewhere.path(), home.path().join("raccourci")).unwrap();
        let r = &shred_paths(&[home.path().join("raccourci/f")], &ctx(home.path()), false)[0];
        assert_eq!(r.outcome, Outcome::Refused, "{r:?}");
        assert!(elsewhere.path().join("f").exists());
    }

    #[test]
    fn refusals_touch_nothing() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        std::fs::create_dir_all(home.join("Documents")).unwrap();
        std::fs::write(home.join("Documents/x"), "x").unwrap();
        let c = ctx(&home);
        let paths = [
            PathBuf::from("relative/path"),
            home.join("Documents/../Documents/x"),
            home.join("Documents"),
            home.clone(),
            d.path().join("outside"),
            PathBuf::from("/etc/hosts"),
        ];
        for r in shred_paths(&paths, &c, false) {
            assert_eq!(r.outcome, Outcome::Refused, "{r:?}");
            assert!(r.error.is_some());
        }
        assert!(home.join("Documents/x").exists());
        let missing = &shred_paths(&[home.join("absent")], &c, false)[0];
        assert_eq!(missing.outcome, Outcome::Failed);
        assert_eq!(missing.error.as_deref(), Some("introuvable"));
    }

    #[test]
    fn vault_zone_deletes_without_overwrite() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        let mount = d.path().join("Coffre");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(mount.join("dossier")).unwrap();
        std::fs::write(mount.join("dossier/note.txt"), "secret").unwrap();
        let c = ShredContext::new(&home, Some(&mount), None);
        let r = &shred_paths(&[mount.join("dossier")], &c, false)[0];
        assert_eq!(r.outcome, Outcome::Deleted, "{r:?}");
        assert_eq!(r.zone, Some(Zone::Vault));
        assert_eq!(r.overwritten_bytes, 0);
        assert_eq!(r.not_overwritten, 1);
        assert!(!mount.join("dossier").exists());
        assert!(mount.is_dir());
        let root = &shred_paths(std::slice::from_ref(&mount), &c, false)[0];
        assert_eq!(root.outcome, Outcome::Refused);
    }

    #[test]
    fn trash_listing() {
        let d = tempfile::tempdir().unwrap();
        assert!(trash_items(d.path())
            .unwrap()
            .iter()
            .all(|p| !p.starts_with(d.path())));
        std::fs::create_dir_all(d.path().join(".Trash/dossier")).unwrap();
        std::fs::write(d.path().join(".Trash/a.pdf"), "x").unwrap();
        let items = trash_items(d.path()).unwrap();
        let mine: Vec<_> = items.iter().filter(|p| p.starts_with(d.path())).collect();
        assert_eq!(mine.len(), 2);
        let r = shred_paths(
            &items
                .into_iter()
                .filter(|p| p.starts_with(d.path()))
                .collect::<Vec<_>>(),
            &ctx(d.path()),
            false,
        );
        assert!(r.iter().all(|r| r.outcome == Outcome::Deleted), "{r:?}");
        assert!(d.path().join(".Trash").is_dir());
        assert_eq!(
            std::fs::read_dir(d.path().join(".Trash")).unwrap().count(),
            0
        );
    }

    #[test]
    fn rng_is_deterministic_per_seed_and_fills_tails() {
        let mut a = Rng::from_seed([1; 32]);
        let mut b = Rng::from_seed([1; 32]);
        assert_eq!(a.next_u64(), b.next_u64());
        let mut buf = [0u8; 13];
        a.fill(&mut buf);
        assert!(buf[8..].iter().any(|x| *x != 0));
        let n = a.name(16);
        assert_eq!(n.len(), 16);
        assert!(n
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        let mut z = Rng::from_seed([0; 32]);
        assert!((0..4).map(|_| z.next_u64()).any(|x| x != 0));
    }
}
