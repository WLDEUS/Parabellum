//! Reversible quarantine, hardened for a root daemon acting inside user-writable trees.
//!
//! Layout of the quarantine directory (root-only, `0700`, created by the daemon):
//! ```text
//! <id>.bin    content XOR-ed with a fixed 32-byte key (inert: no Mach-O/script magic, not indexed
//!             as the original type); directories (e.g. `.app` bundles) are packed as a tar first
//! <id>.json   QuarantineEntry + {"is_dir", "parent", "parent_dev", "parent_ino"}
//! ```
//!
//! Safety model (see [`QuarantinePolicy`]):
//! * The target path is normalised lexically (absolute, no `..`; on macOS `/tmp`, `/var`, `/etc` are
//!   mapped to their `/private` form) and checked against the policy: a *denied* prefix (or a
//!   directory containing one) always wins, otherwise the path must be strictly below an *allowed*
//!   root.
//! * Its parent directory is opened from `/` one component at a time with
//!   `O_DIRECTORY | O_NOFOLLOW`: any symlink component is refused ([`QuarantineError::SymlinkInPath`]),
//!   which also proves the normalised path is the canonical one.
//! * Files are opened with `openat(O_NOFOLLOW)` in that parent, copied and hashed **from the
//!   descriptor**; with `expected_sha256` a mismatch aborts before anything is removed.
//! * `<id>.bin` and `<id>.json` are written and fsync-ed, then the parent path is re-opened and its
//!   `(dev, ino)` compared with the descriptor's; only then is the entry removed with `unlinkat`
//!   relative to the parent descriptor (directories: recursive `unlinkat`, never following links).
//! * Directories are packed by path below the verified parent (the directory itself must not be a
//!   symlink; links inside are archived as links); there is no content-hash check for directories
//!   (`expected_sha256` is ignored and the stored `sha256` is the digest of the packed tar).
//! * Restore re-validates the policy, re-opens the parent with the `O_NOFOLLOW` chain, refuses if
//!   its `(dev, ino)` differs from the recorded one ([`QuarantineError::ParentChanged`]), creates
//!   missing parents with `mkdirat` only, and creates the file with
//!   `openat(O_CREAT | O_EXCL | O_NOFOLLOW)` in the parent descriptor (directories are rebuilt entry by
//!   entry the same way) before `fchown`/`fchmod`. Nothing is ever renamed or hard-linked by path.
//!   If the original name exists, `<name>.restored-N` is used and returned.
//! * Ids must be canonical UUIDs (no path traversal into the quarantine directory).

use crate::safefs::{self, EntryKind, WalkError};
use pb_core::model::{Detection, QuarantineEntry};
use pb_core::paths::Paths;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

/// Neutralisation key (fixed; obfuscation against accidental execution/indexing, not encryption).
const XOR_KEY: [u8; 32] = [
    0x9d, 0x3b, 0xe4, 0x51, 0xa7, 0x0c, 0x6f, 0xd2, 0x38, 0xc9, 0x15, 0x7e, 0xb3, 0x64, 0xfa, 0x2d,
    0x81, 0x5c, 0xe9, 0x46, 0x1b, 0xaf, 0x72, 0xd8, 0x0e, 0x95, 0x63, 0xcb, 0x27, 0xbe, 0x4a, 0xf0,
];
const COPY_BUF: usize = 1024 * 1024;
const MAX_RESTORE_SUFFIX: u32 = 1000;

/// Errors of the quarantine store.
#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    /// Filesystem error.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// The id is not a canonical UUID.
    #[error("invalid quarantine id: {0}")]
    InvalidId(String),
    /// No entry with this id.
    #[error("no quarantine entry {0}")]
    NotFound(String),
    /// The path cannot be quarantined (symlink, special file, inside the quarantine…).
    #[error("cannot quarantine: {0}")]
    Unsupported(String),
    /// Metadata unreadable.
    #[error("corrupt quarantine entry {0}: {1}")]
    Corrupt(String, String),
    /// The path is not strictly below an allowed root of the policy.
    #[error("{0} is outside the locations Parabellum may quarantine or restore to")]
    OutsideAllowedRoots(PathBuf),
    /// The path is (or contains) a protected location.
    #[error("{0} is a protected location")]
    Denied(PathBuf),
    /// The file content is not the content that was scanned.
    #[error("file changed since it was scanned (expected sha256 {expected}, found {actual})")]
    HashMismatch {
        /// Expected digest (lowercase hex).
        expected: String,
        /// Digest of the content read.
        actual: String,
    },
    /// The parent directory is not the one recorded / opened earlier.
    #[error("parent directory {0} changed: refusing")]
    ParentChanged(PathBuf),
    /// A component of the path is a symbolic link.
    #[error("{0} is a symbolic link: refusing")]
    SymlinkInPath(PathBuf),
}

impl From<WalkError> for QuarantineError {
    fn from(e: WalkError) -> Self {
        match e {
            WalkError::Symlink(p) => QuarantineError::SymlinkInPath(p),
            WalkError::Io(e) => QuarantineError::Io(e),
        }
    }
}

/// Where the root daemon may remove files from (quarantine) and recreate them (restore).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuarantinePolicy {
    /// Targets must be strictly below one of these.
    pub allowed_roots: Vec<PathBuf>,
    /// Never touched; wins over `allowed_roots`, and a directory containing one is refused too.
    pub denied_prefixes: Vec<PathBuf>,
}

/// macOS firmlinked aliases mapped to their canonical `/private` form.
fn aliases() -> &'static [(&'static str, &'static str)] {
    if cfg!(target_os = "macos") {
        &[
            ("/tmp", "/private/tmp"),
            ("/var", "/private/var"),
            ("/etc", "/private/etc"),
        ]
    } else {
        &[]
    }
}

/// Lexical normalisation: absolute, no `.`/`..`, macOS aliases resolved. No filesystem access.
pub fn normalize_path(path: &Path) -> Result<PathBuf, QuarantineError> {
    let abs = std::path::absolute(path)?;
    let mut out = PathBuf::from("/");
    for c in abs.components() {
        match c {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(n) => out.push(n),
            Component::ParentDir | Component::Prefix(_) => {
                return Err(QuarantineError::Unsupported(format!(
                    "{} contains '..'",
                    path.display()
                )));
            }
        }
    }
    for (alias, real) in aliases() {
        if let Ok(rest) = out.strip_prefix(alias) {
            out = Path::new(real).join(rest);
            break;
        }
    }
    Ok(out)
}

/// Canonical form of a policy entry (resolved when it exists, else normalised).
fn canon(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| normalize_path(p).unwrap_or_else(|_| p.to_path_buf()))
}

impl QuarantinePolicy {
    /// Default policy of the macOS daemon. Allowed: the given user homes, `/Applications`,
    /// `/Users/Shared`, `/private/tmp`, `/private/var/folders`, `/Volumes`, `/opt/homebrew`,
    /// `/usr/local`, `/Library/{LaunchAgents, LaunchDaemons, Application Support,
    /// PrivilegedHelperTools, StartupItems, Internet Plug-Ins}`. Denied: Parabellum's own files
    /// (root dir, app, launchd plists, CLI link) and system locations (`/System`, `/bin`, `/sbin`,
    /// `/private/etc`, `/private/var/db`, `/Library/Apple`).
    pub fn macos_default(user_homes: &[PathBuf], paths: &Paths) -> Self {
        let mut allowed_roots: Vec<PathBuf> = user_homes.to_vec();
        allowed_roots.extend(
            [
                "/Applications",
                "/Users/Shared",
                "/private/tmp",
                "/private/var/folders",
                "/Volumes",
                "/opt/homebrew",
                "/usr/local",
                "/Library/LaunchAgents",
                "/Library/LaunchDaemons",
                "/Library/Application Support",
                "/Library/PrivilegedHelperTools",
                "/Library/StartupItems",
                "/Library/Internet Plug-Ins",
            ]
            .iter()
            .map(PathBuf::from),
        );
        let mut denied_prefixes = vec![paths.root.clone(), paths.log_dir.clone()];
        denied_prefixes.extend(
            [
                pb_core::paths::APP_PATH,
                pb_core::paths::LAUNCH_DAEMON_PLIST,
                pb_core::paths::LAUNCH_AGENT_PLIST,
                pb_core::paths::CLI_LINK,
                "/System",
                "/bin",
                "/sbin",
                "/private/etc",
                "/private/var/db",
                "/Library/Apple",
            ]
            .iter()
            .map(PathBuf::from),
        );
        Self {
            allowed_roots,
            denied_prefixes,
        }
    }

    /// Checks a target; returns its normalised path. Denied wins over allowed.
    pub fn check(&self, path: &Path) -> Result<PathBuf, QuarantineError> {
        let p = normalize_path(path)?;
        for d in &self.denied_prefixes {
            if d.as_os_str().is_empty() {
                continue;
            }
            let d = canon(d);
            if p.starts_with(&d) || d.starts_with(&p) {
                return Err(QuarantineError::Denied(p));
            }
        }
        let allowed = self
            .allowed_roots
            .iter()
            .filter(|r| !r.as_os_str().is_empty())
            .map(|r| canon(r))
            .any(|r| p.starts_with(&r) && p != r);
        if allowed {
            Ok(p)
        } else {
            Err(QuarantineError::OutsideAllowedRoots(p))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredEntry {
    #[serde(flatten)]
    entry: QuarantineEntry,
    #[serde(default)]
    is_dir: bool,
    /// Canonical parent directory at quarantine time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_dev: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_ino: Option<u64>,
}

/// Handle on the quarantine directory.
#[derive(Debug, Clone)]
pub struct Quarantine {
    dir: PathBuf,
    policy: QuarantinePolicy,
}

/// Writer that XORs (by absolute stream offset) and hashes the plaintext.
struct XorWriter<W: Write> {
    inner: W,
    offset: u64,
    hasher: Sha256,
    scratch: Vec<u8>,
}

impl<W: Write> XorWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            offset: 0,
            hasher: Sha256::new(),
            scratch: Vec::new(),
        }
    }
    fn finish(self) -> (W, String, u64) {
        (self.inner, hex::encode(self.hasher.finalize()), self.offset)
    }
}

impl<W: Write> Write for XorWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.scratch.clear();
        self.scratch.extend(
            buf.iter()
                .enumerate()
                .map(|(i, b)| b ^ XOR_KEY[((self.offset + i as u64) % 32) as usize]),
        );
        self.inner.write_all(&self.scratch)?;
        self.hasher.update(buf);
        self.offset += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Reader that undoes the XOR.
struct XorReader<R: Read> {
    inner: R,
    offset: u64,
}

impl<R: Read> Read for XorReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        for (i, b) in buf[..n].iter_mut().enumerate() {
            *b ^= XOR_KEY[((self.offset + i as u64) % 32) as usize];
        }
        self.offset += n as u64;
        Ok(n)
    }
}

fn validate_id(id: &str) -> Result<(), QuarantineError> {
    match uuid::Uuid::parse_str(id) {
        Ok(u) if u.hyphenated().to_string() == id => Ok(()),
        _ => Err(QuarantineError::InvalidId(id.chars().take(64).collect())),
    }
}

fn fsync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

fn split_target(target: &Path) -> Result<(&Path, &OsStr), QuarantineError> {
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
    match (parent, target.file_name()) {
        (Some(p), Some(n)) => Ok((p, n)),
        _ => Err(QuarantineError::Unsupported(format!(
            "{} has no parent directory",
            target.display()
        ))),
    }
}

impl Quarantine {
    /// Opens (creating it `0700` if needed) the quarantine directory, with the policy applied to
    /// every quarantine and restore.
    pub fn open(dir: &Path, policy: QuarantinePolicy) -> Result<Self, QuarantineError> {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        let m = fs::symlink_metadata(dir)?;
        if !m.is_dir() {
            return Err(QuarantineError::Unsupported(format!(
                "{} is not a directory",
                dir.display()
            )));
        }
        if m.mode() & 0o077 != 0 && m.uid() == euid() {
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
        }
        Ok(Self {
            dir: fs::canonicalize(dir)?,
            policy,
        })
    }

    /// Directory backing this store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Policy in force.
    pub fn policy(&self) -> &QuarantinePolicy {
        &self.policy
    }

    fn bin_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.bin"))
    }
    fn json_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    /// Moves `path` (regular file or directory, never a symlink) into the quarantine.
    ///
    /// `expected_sha256` (hex, files only) is the digest of the content that was scanned: if the
    /// file now has another content, nothing is removed ([`QuarantineError::HashMismatch`]).
    pub fn quarantine(
        &self,
        path: &Path,
        detections: &[Detection],
        reason: &str,
        expected_sha256: Option<&str>,
    ) -> Result<QuarantineEntry, QuarantineError> {
        let target = normalize_path(path)?;
        if target.starts_with(&self.dir) || self.dir.starts_with(&target) {
            return Err(QuarantineError::Denied(target));
        }
        let target = self.policy.check(&target)?;
        let (parent, name) = split_target(&target)?;
        let cname = safefs::cname(name)?;
        let pfd = safefs::open_dir_chain(parent, None)?;
        let pstat = safefs::stat_fd(pfd.as_raw_fd())?;
        let est = safefs::stat_at(pfd.as_raw_fd(), &cname)?;
        let is_dir = match est.kind {
            EntryKind::File => false,
            EntryKind::Dir => true,
            EntryKind::Symlink => {
                return Err(QuarantineError::SymlinkInPath(target));
            }
            EntryKind::Other => {
                return Err(QuarantineError::Unsupported(
                    "not a regular file or directory".into(),
                ))
            }
        };

        let id = uuid::Uuid::new_v4().hyphenated().to_string();
        let bin = self.bin_path(&id);
        let json = self.json_path(&id);
        let tmp_bin = self.dir.join(format!(".{id}.bin.tmp"));
        let tmp_json = self.dir.join(format!(".{id}.json.tmp"));
        let cleanup = || {
            for p in [&tmp_bin, &tmp_json, &bin, &json] {
                let _ = fs::remove_file(p);
            }
        };

        let staged = (|| -> Result<QuarantineEntry, QuarantineError> {
            let out = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_bin)?;
            let (out, sha256, written, meta) = if is_dir {
                let dfd = safefs::openat_dir(pfd.as_raw_fd(), &cname)?;
                let meta = File::from(dfd).metadata()?;
                if (meta.dev(), meta.ino()) != (est.dev, est.ino) {
                    return Err(QuarantineError::Unsupported(
                        "directory replaced while opening it".into(),
                    ));
                }
                let (out, sha, n) = pack_dir(&target, name, out)?;
                (out, sha, n, meta)
            } else {
                let src = safefs::openat_read(pfd.as_raw_fd(), &cname)?;
                let meta = src.metadata()?;
                if !meta.is_file() || (meta.dev(), meta.ino()) != (est.dev, est.ino) {
                    return Err(QuarantineError::Unsupported(
                        "file replaced while opening it".into(),
                    ));
                }
                let (out, sha, n) = copy_from(src, out)?;
                if let Some(expected) = expected_sha256 {
                    let expected = expected.trim().to_ascii_lowercase();
                    if expected != sha {
                        return Err(QuarantineError::HashMismatch {
                            expected,
                            actual: sha,
                        });
                    }
                }
                (out, sha, n, meta)
            };
            out.sync_all()?;
            drop(out);
            fs::rename(&tmp_bin, &bin)?;
            let entry = QuarantineEntry {
                id: id.clone(),
                original_path: target.to_string_lossy().into_owned(),
                sha256,
                size: if is_dir { written } else { meta.len() },
                detections: detections.to_vec(),
                quarantined_at: pb_core::now_ts(),
                owner_uid: meta.uid(),
                owner_gid: meta.gid(),
                mode: meta.mode() & 0o7777,
                reason: reason.to_owned(),
            };
            let stored = StoredEntry {
                entry: entry.clone(),
                is_dir,
                parent: Some(parent.to_string_lossy().into_owned()),
                parent_dev: Some(pstat.dev),
                parent_ino: Some(pstat.ino),
            };
            let bytes = serde_json::to_vec_pretty(&stored)
                .map_err(|e| QuarantineError::Corrupt(id.clone(), e.to_string()))?;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_json)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp_json, &json)?;
            fsync_dir(&self.dir);

            // Re-check that the path still leads to the descriptor we used, and that the entry
            // is still the one we copied, before removing anything.
            let again = safefs::open_dir_chain(parent, None)?;
            let s = safefs::stat_fd(again.as_raw_fd())?;
            if (s.dev, s.ino) != (pstat.dev, pstat.ino) {
                return Err(QuarantineError::ParentChanged(parent.to_path_buf()));
            }
            let now = safefs::stat_at(pfd.as_raw_fd(), &cname)?;
            if (now.dev, now.ino, now.kind) != (est.dev, est.ino, est.kind) {
                return Err(QuarantineError::Unsupported(
                    "entry replaced during quarantine".into(),
                ));
            }
            Ok(entry)
        })();
        let entry = match staged {
            Ok(e) => e,
            Err(e) => {
                cleanup();
                return Err(e);
            }
        };

        // Remove the original through the verified parent descriptor.
        let removed = if is_dir {
            safefs::remove_tree_at(pfd.as_raw_fd(), &cname)
        } else {
            safefs::unlinkat(pfd.as_raw_fd(), &cname, false)
        };
        if let Err(e) = removed {
            if is_dir {
                // Part of the tree may already be gone: keep the (complete) quarantine copy.
                tracing::error!(id = %entry.id, error = %e, "directory partially removed; quarantine copy kept");
            } else {
                cleanup();
            }
            return Err(e.into());
        }
        let _ = File::from(pfd).sync_all();
        Ok(entry)
    }

    /// Restores an entry and removes it from the quarantine. Returns the **actual** destination:
    /// the original path, or `<name>.restored-N` when that name is taken.
    pub fn restore(&self, id: &str) -> Result<PathBuf, QuarantineError> {
        let stored = self.load(id)?;
        let original = self.policy.check(Path::new(&stored.entry.original_path))?;
        let (parent, name) = split_target(&original)?;
        let e = &stored.entry;
        let owner = (euid() == 0).then_some((e.owner_uid, e.owner_gid));
        let pfd = match safefs::open_dir_chain(parent, None) {
            Ok(fd) => {
                if let (Some(dev), Some(ino)) = (stored.parent_dev, stored.parent_ino) {
                    let s = safefs::stat_fd(fd.as_raw_fd())?;
                    if (s.dev, s.ino) != (dev, ino) {
                        return Err(QuarantineError::ParentChanged(parent.to_path_buf()));
                    }
                }
                fd
            }
            // Parent (or an ancestor) was deleted: recreate the missing directories only.
            Err(WalkError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {
                safefs::open_dir_chain(parent, Some((0o755, owner)))?
            }
            Err(err) => return Err(err.into()),
        };
        let src = File::open(self.bin_path(id))?;
        let mut reader = XorReader {
            inner: io::BufReader::with_capacity(COPY_BUF, src),
            offset: 0,
        };

        let dest_name = if stored.is_dir {
            let (dname, dfd) = create_unique(name, |c| {
                safefs::mkdirat(pfd.as_raw_fd(), c, 0o700)
                    .and_then(|_| safefs::openat_dir(pfd.as_raw_fd(), c))
            })?;
            let cn = safefs::cname(&dname)?;
            let res = extract_tar(&mut reader, &dfd, name).and_then(|_| {
                let top = File::from(dfd);
                if let Some((uid, gid)) = owner {
                    let _ = std::os::unix::fs::fchown(&top, Some(uid), Some(gid));
                }
                top.set_permissions(fs::Permissions::from_mode(e.mode))?;
                Ok(())
            });
            if let Err(err) = res {
                let _ = safefs::remove_tree_at(pfd.as_raw_fd(), &cn);
                return Err(err);
            }
            dname
        } else {
            let (dname, mut out) = create_unique(name, |c| {
                safefs::openat_create_excl(pfd.as_raw_fd(), c, 0o600)
            })?;
            let cn = safefs::cname(&dname)?;
            let res = (|| -> Result<(), QuarantineError> {
                io::copy(&mut reader, &mut out)?;
                out.sync_all()?;
                // Owner first (chown clears set-id bits), then the original mode.
                if let Some((uid, gid)) = owner {
                    let _ = std::os::unix::fs::fchown(&out, Some(uid), Some(gid));
                }
                out.set_permissions(fs::Permissions::from_mode(e.mode))?;
                Ok(())
            })();
            if let Err(err) = res {
                let _ = safefs::unlinkat(pfd.as_raw_fd(), &cn, false);
                return Err(err);
            }
            dname
        };
        let _ = File::from(pfd).sync_all();
        let _ = fs::remove_file(self.bin_path(id));
        let _ = fs::remove_file(self.json_path(id));
        fsync_dir(&self.dir);
        Ok(parent.join(dest_name))
    }

    /// Permanently deletes an entry (explicit user action only).
    pub fn delete(&self, id: &str) -> Result<(), QuarantineError> {
        validate_id(id)?;
        let a = fs::remove_file(self.bin_path(id));
        let b = fs::remove_file(self.json_path(id));
        if a.is_err() && b.is_err() {
            return Err(QuarantineError::NotFound(id.into()));
        }
        fsync_dir(&self.dir);
        Ok(())
    }

    /// All entries, newest first. Unreadable entries are skipped with a warning.
    pub fn list(&self) -> Result<Vec<QuarantineEntry>, QuarantineError> {
        let mut out = Vec::new();
        for e in fs::read_dir(&self.dir)?.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if validate_id(id).is_err() {
                continue;
            }
            match self.load(id) {
                Ok(s) => out.push(s.entry),
                Err(err) => {
                    tracing::warn!(id, error = %err, "skipping unreadable quarantine entry")
                }
            }
        }
        out.sort_by(|a, b| {
            b.quarantined_at
                .cmp(&a.quarantined_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    /// One entry.
    pub fn get(&self, id: &str) -> Result<QuarantineEntry, QuarantineError> {
        self.load(id).map(|s| s.entry)
    }

    fn load(&self, id: &str) -> Result<StoredEntry, QuarantineError> {
        validate_id(id)?;
        let bytes = match fs::read(self.json_path(id)) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(QuarantineError::NotFound(id.into()))
            }
            Err(e) => return Err(e.into()),
        };
        let s: StoredEntry = serde_json::from_slice(&bytes)
            .map_err(|e| QuarantineError::Corrupt(id.into(), e.to_string()))?;
        if s.entry.id != id {
            return Err(QuarantineError::Corrupt(id.into(), "id mismatch".into()));
        }
        Ok(s)
    }
}

/// Tries `name`, then `name.restored-1`, `-2`… with an exclusive create; returns the name used.
fn create_unique<T>(
    name: &OsStr,
    mut create: impl FnMut(&std::ffi::CStr) -> io::Result<T>,
) -> Result<(OsString, T), QuarantineError> {
    for n in 0..=MAX_RESTORE_SUFFIX {
        let mut candidate = name.to_owned();
        if n > 0 {
            candidate.push(format!(".restored-{n}"));
        }
        let c = safefs::cname(&candidate)?;
        match create(&c) {
            Ok(t) => return Ok((candidate, t)),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(QuarantineError::Unsupported(
        "no free destination name".into(),
    ))
}

/// Rebuilds a packed directory below `root` (the new top directory) with descriptor-relative,
/// non-following operations only. Entries are `<top>/<rel path>`; links stay links; special files,
/// hard links and anything escaping the tree are skipped.
fn extract_tar<R: Read>(reader: R, root: &OwnedFd, top: &OsStr) -> Result<(), QuarantineError> {
    let as_root = euid() == 0;
    let mut ar = tar::Archive::new(reader);
    let mut dirs: Vec<(Vec<CString>, u32, u32, u32)> = Vec::new();
    for entry in ar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mut comps: Vec<CString> = Vec::new();
        let mut ok = true;
        for c in path.components() {
            match c {
                Component::Normal(n) => comps.push(safefs::cname(n)?),
                Component::CurDir => {}
                _ => ok = false,
            }
        }
        if !ok || comps.is_empty() || comps[0].as_bytes() != top.as_bytes() {
            continue;
        }
        comps.remove(0);
        let Some(last) = comps.pop() else { continue }; // the top directory itself
        if comps.len() >= safefs::MAX_TREE_DEPTH {
            continue;
        }
        // Walk / create the intermediate directories.
        let mut cur = safefs::openat_dir(root.as_raw_fd(), c".")?;
        for d in &comps {
            cur = match safefs::openat_dir(cur.as_raw_fd(), d) {
                Ok(fd) => fd,
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    safefs::mkdirat(cur.as_raw_fd(), d, 0o700)?;
                    safefs::openat_dir(cur.as_raw_fd(), d)?
                }
                Err(e) => return Err(e.into()),
            };
        }
        let header = entry.header();
        let kind = header.entry_type();
        let mode = header.mode()? & 0o7777;
        let uid = header.uid()? as u32;
        let gid = header.gid()? as u32;
        if kind.is_dir() {
            match safefs::mkdirat(cur.as_raw_fd(), &last, 0o700) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
                Err(e) => return Err(e.into()),
            }
            let mut full = comps.clone();
            full.push(last);
            dirs.push((full, mode, uid, gid));
        } else if kind.is_file() {
            let mut f = safefs::openat_create_excl(cur.as_raw_fd(), &last, 0o600)?;
            io::copy(&mut entry, &mut f)?;
            if as_root {
                let _ = std::os::unix::fs::fchown(&f, Some(uid), Some(gid));
            }
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        } else if kind.is_symlink() {
            if let Some(target) = entry.link_name()? {
                let t = safefs::cname(target.as_os_str())?;
                safefs::symlinkat(&t, cur.as_raw_fd(), &last)?;
                if as_root {
                    let _ = safefs::lchownat(cur.as_raw_fd(), &last, uid, gid);
                }
            }
        }
    }
    // Directory owners and modes last, deepest first (a read-only directory must not block its
    // children while extracting).
    dirs.sort_by_key(|d| std::cmp::Reverse(d.0.len()));
    for (comps, mode, uid, gid) in dirs {
        let mut cur = safefs::openat_dir(root.as_raw_fd(), c".")?;
        for c in &comps {
            cur = safefs::openat_dir(cur.as_raw_fd(), c)?;
        }
        let f = File::from(cur);
        if as_root {
            let _ = std::os::unix::fs::fchown(&f, Some(uid), Some(gid));
        }
        f.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Copies an open file through the XOR writer. Returns (file, sha256 of the plaintext, bytes).
fn copy_from(mut src: File, out: File) -> Result<(File, String, u64), QuarantineError> {
    let mut w = XorWriter::new(io::BufWriter::with_capacity(COPY_BUF, out));
    io::copy(&mut src, &mut w)?;
    w.flush()?;
    let (buf, sha, n) = w.finish();
    let file = buf.into_inner().map_err(|e| e.into_error())?;
    Ok((file, sha, n))
}

/// Packs a directory as tar (symlinks kept as links) through the XOR writer.
fn pack_dir(path: &Path, name: &OsStr, out: File) -> Result<(File, String, u64), QuarantineError> {
    let w = XorWriter::new(io::BufWriter::with_capacity(COPY_BUF, out));
    let mut builder = tar::Builder::new(w);
    builder.follow_symlinks(false);
    builder.mode(tar::HeaderMode::Complete);
    builder.append_dir_all(name, path)?;
    let mut w = builder.into_inner()?;
    w.flush()?;
    let (buf, sha, n) = w.finish();
    let file = buf.into_inner().map_err(|e| e.into_error())?;
    Ok((file, sha, n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pb_core::model::{DetectionEngine, Severity};

    fn det() -> Vec<Detection> {
        vec![Detection {
            engine: DetectionEngine::Yara,
            name: "EICAR-Test-File".into(),
            severity: Severity::High,
            confidence: 0.9,
            details: None,
        }]
    }

    struct Fx {
        _d: tempfile::TempDir,
        base: PathBuf,
        allowed: PathBuf,
        q: Quarantine,
    }

    fn fx() -> Fx {
        let d = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(d.path()).unwrap();
        let allowed = base.join("home");
        fs::create_dir_all(allowed.join("protected")).unwrap();
        fs::create_dir_all(base.join("outside")).unwrap();
        let policy = QuarantinePolicy {
            allowed_roots: vec![allowed.clone()],
            denied_prefixes: vec![allowed.join("protected")],
        };
        let q = Quarantine::open(&base.join("q"), policy).unwrap();
        Fx {
            _d: d,
            base,
            allowed,
            q,
        }
    }

    fn sha_hex(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    #[test]
    fn file_round_trip_with_expected_hash() {
        let f = fx();
        assert_eq!(fs::metadata(f.q.dir()).unwrap().mode() & 0o777, 0o700);
        let victim = f.allowed.join("data").join("evil.sh");
        fs::create_dir_all(victim.parent().unwrap()).unwrap();
        let content = b"#!/bin/sh\necho pwned\n".repeat(1000);
        fs::write(&victim, &content).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o751)).unwrap();

        let e =
            f.q.quarantine(
                &victim,
                &det(),
                "user",
                Some(&sha_hex(&content).to_uppercase()),
            )
            .unwrap();
        assert!(!victim.exists());
        assert_eq!(e.sha256, sha_hex(&content));
        assert_eq!(e.size, content.len() as u64);
        assert_eq!(e.mode, 0o751);
        let stored = fs::read(f.q.dir().join(format!("{}.bin", e.id))).unwrap();
        assert_eq!(stored.len(), content.len());
        assert!(!stored.starts_with(b"#!"));
        let json: serde_json::Value =
            serde_json::from_slice(&fs::read(f.q.dir().join(format!("{}.json", e.id))).unwrap())
                .unwrap();
        assert_eq!(
            json["parent"],
            victim.parent().unwrap().to_string_lossy().as_ref()
        );
        assert!(json["parent_ino"].as_u64().is_some());
        assert_eq!(f.q.list().unwrap().len(), 1);

        let restored = f.q.restore(&e.id).unwrap();
        assert_eq!(restored, victim);
        assert_eq!(fs::read(&victim).unwrap(), content);
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o7777, 0o751);
        assert!(f.q.list().unwrap().is_empty());
        assert!(matches!(f.q.get(&e.id), Err(QuarantineError::NotFound(_))));
    }

    #[test]
    fn hash_mismatch_aborts_and_keeps_original() {
        let f = fx();
        let victim = f.allowed.join("x.bin");
        fs::write(&victim, b"new content").unwrap();
        let err =
            f.q.quarantine(&victim, &det(), "auto", Some(&sha_hex(b"scanned content")))
                .unwrap_err();
        assert!(matches!(err, QuarantineError::HashMismatch { .. }), "{err}");
        assert_eq!(fs::read(&victim).unwrap(), b"new content");
        assert_eq!(fs::read_dir(f.q.dir()).unwrap().count(), 0, "no leftovers");
    }

    #[test]
    fn policy_outside_and_denied() {
        let f = fx();
        let out = f.base.join("outside/x");
        fs::write(&out, b"x").unwrap();
        assert!(matches!(
            f.q.quarantine(&out, &det(), "user", None),
            Err(QuarantineError::OutsideAllowedRoots(_))
        ));
        let prot = f.allowed.join("protected/x");
        fs::write(&prot, b"x").unwrap();
        assert!(matches!(
            f.q.quarantine(&prot, &det(), "user", None),
            Err(QuarantineError::Denied(_))
        ));
        // A root itself, a directory containing a denied prefix, and `..` tricks are refused.
        assert!(matches!(
            f.q.quarantine(&f.allowed, &det(), "user", None),
            Err(QuarantineError::OutsideAllowedRoots(_))
        ));
        let sneaky = f.allowed.join("..").join("outside/x");
        assert!(f.q.quarantine(&sneaky, &det(), "user", None).is_err());
        assert!(out.exists() && prot.exists());
        let mut policy = f.q.policy().clone();
        policy
            .denied_prefixes
            .push(f.allowed.join("apps/Keep.app/Contents"));
        assert!(matches!(
            policy.check(&f.allowed.join("apps/Keep.app")),
            Err(QuarantineError::Denied(_))
        ));
        // The quarantine directory itself is never a target.
        let mut policy = f.q.policy().clone();
        policy.allowed_roots.push(f.base.clone());
        let q2 = Quarantine::open(f.q.dir(), policy).unwrap();
        assert!(matches!(
            q2.quarantine(f.q.dir(), &det(), "user", None),
            Err(QuarantineError::Denied(_))
        ));
    }

    #[test]
    fn symlinks_in_path_are_refused() {
        let f = fx();
        fs::create_dir_all(f.allowed.join("real/b")).unwrap();
        fs::write(f.allowed.join("real/f"), b"f").unwrap();
        fs::write(f.allowed.join("real/b/f"), b"f").unwrap();
        std::os::unix::fs::symlink(f.allowed.join("real"), f.allowed.join("link")).unwrap();
        // Symlinked parent.
        let e =
            f.q.quarantine(&f.allowed.join("link/f"), &det(), "user", None)
                .unwrap_err();
        assert!(
            matches!(&e, QuarantineError::SymlinkInPath(p) if *p == f.allowed.join("link")),
            "{e}"
        );
        // Symlinked intermediate component.
        let e =
            f.q.quarantine(&f.allowed.join("link/b/f"), &det(), "user", None)
                .unwrap_err();
        assert!(matches!(e, QuarantineError::SymlinkInPath(_)), "{e}");
        // The target itself is a symlink.
        let e =
            f.q.quarantine(&f.allowed.join("link"), &det(), "user", None)
                .unwrap_err();
        assert!(matches!(e, QuarantineError::SymlinkInPath(_)), "{e}");
        assert!(f.allowed.join("real/f").exists() && f.allowed.join("real/b/f").exists());
    }

    #[test]
    fn restore_refuses_swapped_parent() {
        let f = fx();
        let dir = f.allowed.join("p");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("f"), b"payload").unwrap();
        let e =
            f.q.quarantine(&dir.join("f"), &det(), "user", None)
                .unwrap();
        // Parent replaced by a symlink to another directory.
        fs::rename(&dir, f.allowed.join("p.old")).unwrap();
        fs::create_dir_all(f.base.join("outside/target")).unwrap();
        std::os::unix::fs::symlink(f.base.join("outside/target"), &dir).unwrap();
        assert!(matches!(
            f.q.restore(&e.id),
            Err(QuarantineError::SymlinkInPath(_))
        ));
        assert!(!f.base.join("outside/target/f").exists());
        // Parent replaced by another real directory.
        fs::remove_file(&dir).unwrap();
        fs::create_dir(&dir).unwrap();
        assert!(matches!(
            f.q.restore(&e.id),
            Err(QuarantineError::ParentChanged(_))
        ));
        // Original parent back: restore works.
        fs::remove_dir(&dir).unwrap();
        fs::rename(f.allowed.join("p.old"), &dir).unwrap();
        assert_eq!(f.q.restore(&e.id).unwrap(), dir.join("f"));
    }

    #[test]
    fn restore_recreates_missing_parent_and_uses_suffix() {
        let f = fx();
        let victim = f.allowed.join("a/b/x.bin");
        fs::create_dir_all(victim.parent().unwrap()).unwrap();
        fs::write(&victim, b"one").unwrap();
        let e1 = f.q.quarantine(&victim, &det(), "auto", None).unwrap();
        fs::write(&victim, b"two").unwrap();
        let e2 = f.q.quarantine(&victim, &det(), "auto", None).unwrap();
        fs::write(&victim, b"new file at the same path").unwrap();
        let r1 = f.q.restore(&e1.id).unwrap();
        assert_eq!(r1, f.allowed.join("a/b/x.bin.restored-1"));
        assert_eq!(fs::read(&r1).unwrap(), b"one");
        assert_eq!(fs::read(&victim).unwrap(), b"new file at the same path");
        let r2 = f.q.restore(&e2.id).unwrap();
        assert_eq!(r2, f.allowed.join("a/b/x.bin.restored-2"));
        // Missing parents are recreated (only missing ones).
        let v = f.allowed.join("gone/deep/y");
        fs::create_dir_all(v.parent().unwrap()).unwrap();
        fs::write(&v, b"y").unwrap();
        let e3 = f.q.quarantine(&v, &det(), "auto", None).unwrap();
        fs::remove_dir_all(f.allowed.join("gone")).unwrap();
        assert_eq!(f.q.restore(&e3.id).unwrap(), v);
        assert_eq!(fs::read(&v).unwrap(), b"y");
    }

    #[test]
    fn directory_round_trip() {
        let f = fx();
        let app = f.allowed.join("Evil.app");
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        fs::write(app.join("Contents/MacOS/Evil"), b"\xcf\xfa\xed\xfe payload").unwrap();
        fs::set_permissions(
            app.join("Contents/MacOS/Evil"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(app.join("Contents/Info.plist"), b"<plist/>").unwrap();
        fs::set_permissions(app.join("Contents"), fs::Permissions::from_mode(0o555)).unwrap();
        std::os::unix::fs::symlink("MacOS/Evil", app.join("Contents/link")).unwrap();
        fs::set_permissions(&app, fs::Permissions::from_mode(0o750)).unwrap();

        let e =
            f.q.quarantine(&app, &det(), "user", Some("ignored-for-directories"))
                .unwrap();
        assert!(!app.exists());
        assert_eq!(f.q.list().unwrap()[0].id, e.id);
        let restored = f.q.restore(&e.id).unwrap();
        assert_eq!(restored, app);
        assert_eq!(
            fs::read(app.join("Contents/MacOS/Evil")).unwrap(),
            b"\xcf\xfa\xed\xfe payload"
        );
        assert_eq!(
            fs::metadata(app.join("Contents/MacOS/Evil"))
                .unwrap()
                .mode()
                & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(app.join("Contents")).unwrap().mode() & 0o777,
            0o555
        );
        assert_eq!(fs::metadata(&app).unwrap().mode() & 0o777, 0o750);
        assert_eq!(
            fs::read_link(app.join("Contents/link")).unwrap(),
            Path::new("MacOS/Evil")
        );
        fs::set_permissions(app.join("Contents"), fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn rejects_bad_ids_and_deletes() {
        let f = fx();
        for bad in [
            "../etc/passwd",
            "",
            "x",
            "00000000-0000-0000-0000-00000000000G",
            "9E3B1C2A-1111-4222-8333-444455556666",
        ] {
            assert!(
                matches!(f.q.restore(bad), Err(QuarantineError::InvalidId(_))),
                "{bad}"
            );
            assert!(matches!(
                f.q.delete(bad),
                Err(QuarantineError::InvalidId(_))
            ));
        }
        let target = f.allowed.join("t");
        fs::write(&target, b"t").unwrap();
        let e = f.q.quarantine(&target, &det(), "user", None).unwrap();
        f.q.delete(&e.id).unwrap();
        assert!(f.q.list().unwrap().is_empty());
        assert!(matches!(
            f.q.delete(&e.id),
            Err(QuarantineError::NotFound(_))
        ));
        assert!(!target.exists());
    }

    #[test]
    fn default_policy_shape() {
        let paths = Paths::with_root("/Library/Application Support/Parabellum");
        let p = QuarantinePolicy::macos_default(&[PathBuf::from("/Users/q")], &paths);
        assert!(p.check(Path::new("/Users/q/Downloads/x.dmg")).is_ok());
        assert!(matches!(
            p.check(Path::new("/Users/q")),
            Err(QuarantineError::OutsideAllowedRoots(_))
        ));
        assert!(matches!(
            p.check(Path::new(
                "/Library/Application Support/Parabellum/bin/parabellumd"
            )),
            Err(QuarantineError::Denied(_))
        ));
        assert!(matches!(
            p.check(Path::new("/Library/Application Support")),
            Err(QuarantineError::OutsideAllowedRoots(_))
        ));
        assert!(p
            .check(Path::new("/Library/Application Support/Evil/agent"))
            .is_ok());
        assert!(matches!(
            p.check(Path::new("/Applications/Parabellum.app/Contents/MacOS/x")),
            Err(QuarantineError::Denied(_))
        ));
        assert!(matches!(
            p.check(Path::new(
                "/Library/LaunchDaemons/com.wldeus.parabellum.daemon.plist"
            )),
            Err(QuarantineError::Denied(_))
        ));
        assert!(p
            .check(Path::new("/Library/LaunchDaemons/com.evil.plist"))
            .is_ok());
        assert!(matches!(
            p.check(Path::new("/System/Library/x")),
            Err(QuarantineError::OutsideAllowedRoots(_)) | Err(QuarantineError::Denied(_))
        ));
        assert!(p.check(Path::new("/etc/sudoers")).is_err());
        assert!(p.check(Path::new("/Users/q/../../etc/sudoers")).is_err());
    }
}
