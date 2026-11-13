//! Coffre (encrypted vault) & effacement sûr (secure delete). Runs as the user, never in the daemon.
//!
//! The vault is an AES-256 encrypted APFS sparse bundle managed with `hdiutil`. The passphrase is
//! kept by the app (login keychain, unlocked with Touch ID / the session password) and handed to
//! these commands on stdin only; it never appears in argv or the environment. This module holds the
//! state logic (is it attached, where, how big) and builds every hdiutil invocation, so it can be
//! tested with a fake [`tools::Runner`].
//!
//! - [`tools`]: runner + parsers of hdiutil / lsof / fdesetup output,
//! - [`shred`]: path safety checks and best-effort overwrite-then-delete,
//! - [`command`]: `parabellum vault …` subcommands (JSON for the app, French text for humans).

pub mod command;
pub mod shred;
pub mod tools;

use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tools::{Attached, FileVaultState, Holder, Runner, FDESETUP, HDIUTIL, LSOF};

/// Default volume name (also the Finder name: /Volumes/Coffre).
pub const DEFAULT_VOLUME_NAME: &str = "Coffre";
/// Default maximum size (sparse: only what is stored takes disk space).
pub const DEFAULT_SIZE: &str = "20g";
/// Bundle location relative to the home folder.
pub const DEFAULT_BUNDLE: &str = "Library/Application Support/Parabellum/Vault/Coffre.sparsebundle";
pub const BUNDLE_EXTENSION: &str = "sparsebundle";
pub const MIN_SIZE: u64 = 100 << 20;
pub const MAX_SIZE: u64 = 16 << 40;
/// Minimum length (characters) of a new passphrase. Generated keys are much longer.
pub const MIN_PASSWORD_CHARS: usize = 12;
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Recent files listed by `status --recent`: bounds of the walk.
const RECENT_MAX_ENTRIES: usize = 20_000;
const RECENT_MAX_DEPTH: usize = 8;

const T_INFO: Duration = Duration::from_secs(20);
const T_CREATE: Duration = Duration::from_secs(300);
const T_ATTACH: Duration = Duration::from_secs(120);
const T_DETACH: Duration = Duration::from_secs(60);
const T_RESIZE: Duration = Duration::from_secs(900);
const T_COMPACT: Duration = Duration::from_secs(1800);
const T_CHPASS: Duration = Duration::from_secs(120);
const T_LSOF: Duration = Duration::from_secs(15);
const T_FDESETUP: Duration = Duration::from_secs(10);

/// Errors, with a stable `code` for the app.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("aucun coffre à cet emplacement : {0}")]
    NotFound(String),
    #[error("un coffre existe déjà à cet emplacement : {0}")]
    AlreadyExists(String),
    #[error("mot de passe incorrect")]
    BadPassword,
    #[error("{0}")]
    WeakPassword(String),
    #[error("le coffre est ouvert : verrouillez-le d'abord")]
    Mounted,
    #[error("{}", busy_message(.0))]
    Busy(Vec<Holder>),
    #[error("{0}")]
    Unsafe(String),
    #[error("{0}")]
    Tool(String),
    #[error("{0}")]
    Io(#[from] io::Error),
}

fn busy_message(h: &[Holder]) -> String {
    if h.is_empty() {
        return "des fichiers du coffre sont encore ouverts : fermez-les puis réessayez".into();
    }
    let mut names: Vec<&str> = h.iter().map(|h| h.command.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    format!(
        "des fichiers du coffre sont encore ouverts par : {} — fermez-les puis réessayez",
        names.join(", ")
    )
}

impl VaultError {
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::NotFound(_) => "not_found",
            VaultError::AlreadyExists(_) => "already_exists",
            VaultError::BadPassword => "bad_password",
            VaultError::WeakPassword(_) => "weak_password",
            VaultError::Mounted => "mounted",
            VaultError::Busy(_) => "busy",
            VaultError::Unsafe(_) => "unsafe",
            VaultError::Tool(_) => "tool",
            VaultError::Io(_) => "io",
        }
    }
}

/// Where the vault lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPaths {
    /// `….sparsebundle` directory.
    pub bundle: PathBuf,
    /// Custom mount point; `None` lets macOS mount it in /Volumes (visible in the Finder sidebar).
    pub mountpoint: Option<PathBuf>,
}

impl VaultPaths {
    pub fn default_bundle(home: &Path) -> PathBuf {
        home.join(DEFAULT_BUNDLE)
    }
}

/// A recently modified file of the open vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    pub name: String,
    pub path: String,
    pub size: u64,
    /// Unix seconds.
    pub modified: i64,
}

/// `parabellum vault status --json` (also returned by every action).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct VaultStatus {
    pub bundle_path: String,
    /// The sparse bundle exists.
    pub exists: bool,
    /// It has an encryption header (`token`).
    pub encrypted: bool,
    pub mounted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    /// Maximum size of the image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_bytes: Option<u64>,
    /// Space the encrypted bands take on the Mac's disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocated_bytes: Option<u64>,
    /// Open vault: size and free space of the volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume_free_bytes: Option<u64>,
    pub filevault: FileVaultState,
    /// The bundle sits in a folder that a cloud service may sync (French message).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_warning: Option<String>,
    #[serde(default)]
    pub recent: Vec<VaultItem>,
}

/// A passphrase read from stdin; wiped from memory when dropped.
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// NUL-terminated, as `hdiutil -stdinpass` expects.
    fn stdin_payload(&self) -> Secret {
        let mut v = Vec::with_capacity(self.0.len() + 1);
        v.extend_from_slice(&self.0);
        v.push(0);
        Secret(v)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            // SAFETY: plain byte write through a valid &mut; volatile so it is not optimized away.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(…)")
    }
}

/// Read the passphrase(s) piped by the app: `pass` or `old\0new`, one trailing `\n` / `\0` ignored.
pub fn read_secrets(input: &mut dyn Read, count: usize) -> Result<Vec<Secret>, VaultError> {
    let mut raw = Secret(Vec::new());
    input
        .take((MAX_PASSWORD_BYTES * count + 8) as u64)
        .read_to_end(&mut raw.0)?;
    let mut data: &[u8] = &raw.0;
    if let Some(d) = data.strip_suffix(b"\n") {
        data = d.strip_suffix(b"\r").unwrap_or(d);
    } else if let Some(d) = data.strip_suffix(b"\0") {
        data = d;
    }
    let parts: Vec<Secret> = if count == 1 {
        vec![Secret(data.to_vec())]
    } else {
        data.splitn(count, |b| *b == 0)
            .map(|p| Secret(p.to_vec()))
            .collect()
    };
    if parts.len() != count || parts.iter().any(|p| p.0.is_empty()) {
        return Err(VaultError::WeakPassword(if count == 1 {
            "mot de passe attendu sur l'entrée standard".into()
        } else {
            "ancien et nouveau mots de passe attendus sur l'entrée standard (séparés par un octet nul)"
                .into()
        }));
    }
    for p in &parts {
        if p.0.len() > MAX_PASSWORD_BYTES || p.0.contains(&0) {
            return Err(VaultError::WeakPassword("mot de passe invalide".into()));
        }
    }
    Ok(parts)
}

/// A new passphrase: UTF-8, at least [`MIN_PASSWORD_CHARS`] characters, no control characters.
pub fn validate_new_password(p: &Secret) -> Result<(), VaultError> {
    let s = std::str::from_utf8(p.as_bytes())
        .map_err(|_| VaultError::WeakPassword("mot de passe : UTF-8 attendu".into()))?;
    if s.chars().any(char::is_control) {
        return Err(VaultError::WeakPassword(
            "mot de passe : caractères de contrôle interdits".into(),
        ));
    }
    if s.chars().count() < MIN_PASSWORD_CHARS {
        return Err(VaultError::WeakPassword(format!(
            "mot de passe trop court : {MIN_PASSWORD_CHARS} caractères au minimum"
        )));
    }
    Ok(())
}

/// Volume name: 1–27 characters, no `/`, `:` or control characters.
pub fn validate_volume_name(n: &str) -> Result<(), VaultError> {
    let count = n.chars().count();
    if count == 0
        || count > 27
        || n.starts_with('.')
        || n.chars().any(|c| c == '/' || c == ':' || c.is_control())
    {
        return Err(VaultError::Unsafe(format!("nom de volume invalide : {n}")));
    }
    Ok(())
}

/// Home folder of the current user (password database first, `$HOME` as a fallback).
pub fn home_dir() -> Option<PathBuf> {
    // SAFETY: getpwuid_r with a properly sized buffer; the result is only read on success.
    unsafe {
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut buf = vec![0 as libc::c_char; 4096];
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(
            libc::geteuid(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        );
        if rc == 0 && !result.is_null() && !pwd.pw_dir.is_null() {
            let dir = std::ffi::CStr::from_ptr(pwd.pw_dir);
            let p = PathBuf::from(std::ffi::OsStr::from_bytes(dir.to_bytes()));
            if p.is_absolute() {
                return Some(p);
            }
        }
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Lexical normalization (`.` removed); `None` when the path is relative or contains `..`.
pub fn normalize(p: &Path) -> Option<PathBuf> {
    if !p.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::RootDir => out.push("/"),
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(out)
}

/// Canonical form of a path whose last component may not exist (parent resolved, name kept).
pub fn canonical_lenient(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) => std::fs::canonicalize(parent)
            .map(|c| c.join(name))
            .unwrap_or_else(|_| p.to_path_buf()),
        _ => p.to_path_buf(),
    }
}

fn same_path(a: &str, b: &Path) -> bool {
    let a = a.trim_end_matches('/');
    if a.is_empty() {
        return false;
    }
    canonical_lenient(Path::new(a)) == canonical_lenient(b)
}

fn path_str(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

fn args(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn tool_error(what: &str, out: &tools::ToolOutput) -> VaultError {
    let detail = out.stderr_text();
    if out.timed_out {
        return VaultError::Tool(format!("{what} : délai dépassé"));
    }
    VaultError::Tool(if detail.is_empty() {
        format!("{what} : échec (code {})", out.status)
    } else {
        format!("{what} : {detail}")
    })
}

/// Warning when the bundle is in a folder that iCloud Drive or another cloud client may sync.
pub fn sync_warning(home: &Path, bundle: &Path) -> Option<String> {
    let b = canonical_lenient(bundle);
    let home = canonical_lenient(home);
    let synced = [
        "Library/Mobile Documents",
        "Library/CloudStorage",
        "Desktop",
        "Documents",
    ];
    synced
        .iter()
        .find(|s| b.starts_with(home.join(s)))
        .map(|_| {
            "Le coffre est dans un dossier qui peut être synchronisé (iCloud Drive, Dropbox…) : \
         seules des données chiffrées partent, mais la synchronisation d'un coffre ouvert peut \
         l'abîmer. Préférez un dossier local."
                .to_string()
        })
}

/// The bundle exists, is a real directory (not a symlink) and looks like a sparse bundle.
fn check_bundle(bundle: &Path) -> Result<(), VaultError> {
    let md = match std::fs::symlink_metadata(bundle) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(VaultError::NotFound(path_str(bundle)))
        }
        Err(e) => return Err(e.into()),
    };
    if !md.is_dir() || bundle.extension().and_then(|e| e.to_str()) != Some(BUNDLE_EXTENSION) {
        return Err(VaultError::Unsafe(format!(
            "{} n'est pas une image .sparsebundle",
            bundle.display()
        )));
    }
    let info = read_capped(&bundle.join("Info.plist"), 64 * 1024)
        .ok()
        .and_then(|x| tools::parse_bundle_info(&x).ok());
    match info {
        Some(i) if i.bundle_type == "com.apple.diskimage.sparsebundle" => Ok(()),
        _ => Err(VaultError::Unsafe(format!(
            "{} n'est pas une image .sparsebundle valide",
            bundle.display()
        ))),
    }
}

fn read_capped(p: &Path, max: u64) -> io::Result<Vec<u8>> {
    let mut v = Vec::new();
    std::fs::File::open(p)?.take(max).read_to_end(&mut v)?;
    Ok(v)
}

/// Bytes allocated on disk by the files of a directory tree (no symlinks followed).
fn allocated(dir: &Path, depth: usize) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0;
    for e in rd.flatten() {
        let Ok(md) = e.path().symlink_metadata() else {
            continue;
        };
        if md.is_dir() && depth > 0 {
            total += allocated(&e.path(), depth - 1);
        } else if md.is_file() {
            total += md.blocks() * 512;
        }
    }
    total
}

/// (total, available) bytes of the file system holding `p`.
#[allow(clippy::unnecessary_cast)]
fn fs_space(p: &Path) -> Option<(u64, u64)> {
    let c = CString::new(p.as_os_str().as_bytes()).ok()?;
    // SAFETY: statfs fills the zeroed struct; we read it only on success.
    unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        if libc::statfs(c.as_ptr(), &mut s) != 0 {
            return None;
        }
        let bsize = s.f_bsize as u64;
        Some((s.f_blocks as u64 * bsize, s.f_bavail as u64 * bsize))
    }
}

/// Most recently modified files of the open vault (hidden entries skipped, no symlinks followed).
pub fn recent_items(mount: &Path, limit: usize) -> Vec<VaultItem> {
    if limit == 0 {
        return Vec::new();
    }
    let mut found = Vec::new();
    let mut seen = 0usize;
    let mut stack = vec![(mount.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            seen += 1;
            if seen > RECENT_MAX_ENTRIES {
                break;
            }
            let name = e.file_name();
            if name.as_bytes().first() == Some(&b'.') {
                continue;
            }
            let path = e.path();
            let Ok(md) = path.symlink_metadata() else {
                continue;
            };
            if md.is_dir() {
                if depth < RECENT_MAX_DEPTH {
                    stack.push((path, depth + 1));
                }
            } else if md.is_file() {
                found.push(VaultItem {
                    name: name.to_string_lossy().into_owned(),
                    path: path_str(&path),
                    size: md.len(),
                    modified: md.mtime(),
                });
            }
        }
    }
    found.sort_by(|a, b| b.modified.cmp(&a.modified).then(a.name.cmp(&b.name)));
    found.truncate(limit);
    found
}

/// The vault image if it is attached (`hdiutil info`).
pub fn find_attached(r: &dyn Runner, bundle: &Path) -> Result<Option<Attached>, VaultError> {
    let out = r.run(HDIUTIL, &args(&["info", "-plist"]), None, T_INFO)?;
    if !out.ok() {
        return Err(tool_error("hdiutil info", &out));
    }
    Ok(tools::parse_info(&out.stdout)?
        .into_iter()
        .find(|a| same_path(&a.image_path, bundle)))
}

/// FileVault state (`fdesetup status`, no root needed); unknown on any failure.
pub fn filevault(r: &dyn Runner) -> FileVaultState {
    match r.run(FDESETUP, &args(&["status"]), None, T_FDESETUP) {
        Ok(o) if o.ok() => tools::parse_fdesetup(&String::from_utf8_lossy(&o.stdout)),
        _ => FileVaultState::Unknown,
    }
}

/// Processes holding files open on the mounted volume (only the user's own are visible).
pub fn holders(r: &dyn Runner, mount: &Path) -> Vec<Holder> {
    let a = vec![
        "-n".to_string(),
        "-P".into(),
        "-w".into(),
        "-F".into(),
        "pcn".into(),
        "+f".into(),
        "--".into(),
        path_str(mount),
    ];
    // Exit code 1 just means "nothing found".
    match r.run(LSOF, &a, None, T_LSOF) {
        Ok(o) if !o.timed_out => {
            let me = std::process::id() as i32;
            tools::parse_lsof(&String::from_utf8_lossy(&o.stdout))
                .into_iter()
                .filter(|h| h.pid != me)
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Full state. `recent` = number of recent files to list when the vault is open.
pub fn status(
    r: &dyn Runner,
    p: &VaultPaths,
    home: &Path,
    recent: usize,
) -> Result<VaultStatus, VaultError> {
    let mut s = VaultStatus {
        bundle_path: path_str(&p.bundle),
        filevault: filevault(r),
        sync_warning: sync_warning(home, &p.bundle),
        ..Default::default()
    };
    let is_dir = std::fs::symlink_metadata(&p.bundle).is_ok_and(|m| m.is_dir());
    if !is_dir {
        return Ok(s);
    }
    s.exists = true;
    s.encrypted = p.bundle.join("token").is_file();
    s.capacity_bytes = read_capped(&p.bundle.join("Info.plist"), 64 * 1024)
        .ok()
        .and_then(|x| tools::parse_bundle_info(&x).ok())
        .map(|i| i.size)
        .filter(|s| *s > 0);
    s.allocated_bytes = Some(allocated(&p.bundle, 2));
    if let Some(a) = find_attached(r, &p.bundle)? {
        s.mounted = true;
        s.device = Some(a.device);
        if let Some(m) = a.mount_point {
            let mp = PathBuf::from(&m);
            if let Some((total, free)) = fs_space(&mp) {
                s.volume_total_bytes = Some(total);
                s.volume_free_bytes = Some(free);
            }
            s.recent = recent_items(&mp, recent);
            s.mount_point = Some(m);
        }
    }
    Ok(s)
}

/// Create the encrypted sparse bundle (not attached afterwards).
pub fn create(
    r: &dyn Runner,
    p: &VaultPaths,
    home: &Path,
    size: u64,
    volume_name: &str,
    password: &Secret,
) -> Result<VaultStatus, VaultError> {
    validate_new_password(password)?;
    validate_volume_name(volume_name)?;
    if !(MIN_SIZE..=MAX_SIZE).contains(&size) {
        return Err(VaultError::Unsafe(
            "taille du coffre : entre 100 Mo et 16 To".into(),
        ));
    }
    if p.bundle.extension().and_then(|e| e.to_str()) != Some(BUNDLE_EXTENSION) {
        return Err(VaultError::Unsafe(
            "l'emplacement du coffre doit se terminer par .sparsebundle".into(),
        ));
    }
    if std::fs::symlink_metadata(&p.bundle).is_ok() {
        return Err(VaultError::AlreadyExists(path_str(&p.bundle)));
    }
    if let Some(parent) = p.bundle.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    // SAFETY: no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let a = vec![
        "create".to_string(),
        "-size".into(),
        tools::hdiutil_size_arg(size),
        "-type".into(),
        "SPARSEBUNDLE".into(),
        "-fs".into(),
        "APFS".into(),
        "-volname".into(),
        volume_name.into(),
        "-encryption".into(),
        "AES-256".into(),
        "-stdinpass".into(),
        "-uid".into(),
        uid.to_string(),
        "-gid".into(),
        gid.to_string(),
        "-mode".into(),
        "0700".into(),
        "-plist".into(),
        path_str(&p.bundle),
    ];
    let payload = password.stdin_payload();
    let out = r.run(HDIUTIL, &a, Some(payload.as_bytes()), T_CREATE)?;
    if !out.ok() {
        return Err(tool_error("hdiutil create", &out));
    }
    if !std::fs::symlink_metadata(&p.bundle).is_ok_and(|m| m.is_dir()) {
        let created = tools::parse_create(&out.stdout).unwrap_or_default();
        return Err(VaultError::Tool(format!(
            "hdiutil create : image introuvable après création ({})",
            created.join(", ")
        )));
    }
    status(r, p, home, 0)
}

/// Check (and create when missing) a custom mount point: a real, empty directory. A non-empty
/// folder would hide plain files under the vault: refused.
fn prepare_mountpoint(mp: &Path) -> Result<(), VaultError> {
    let Some(mp) = normalize(mp) else {
        return Err(VaultError::Unsafe(
            "point de montage : chemin absolu attendu".into(),
        ));
    };
    match std::fs::symlink_metadata(&mp) {
        Ok(md) => {
            if !md.is_dir() {
                return Err(VaultError::Unsafe(format!(
                    "{} n'est pas un dossier",
                    mp.display()
                )));
            }
            let busy = std::fs::read_dir(&mp)?
                .flatten()
                .any(|e| e.file_name() != ".DS_Store");
            if busy {
                return Err(VaultError::Unsafe(format!(
                    "le dossier {} contient des fichiers non chiffrés : déplacez-les avant d'ouvrir le coffre",
                    mp.display()
                )));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new().mode(0o700).create(&mp)?;
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// Remove a custom mount point left empty after detaching (so nothing is saved there unencrypted).
fn cleanup_mountpoint(p: &VaultPaths) {
    if let Some(mp) = &p.mountpoint {
        if std::fs::symlink_metadata(mp).is_ok_and(|m| m.is_dir()) {
            let ds = mp.join(".DS_Store");
            if std::fs::read_dir(mp).is_ok_and(|rd| rd.flatten().all(|e| e.path() == ds)) {
                let _ = std::fs::remove_file(&ds);
                let _ = std::fs::remove_dir(mp);
            }
        }
    }
}

/// Attach (unlock) the vault. Already attached: no-op.
pub fn attach(
    r: &dyn Runner,
    p: &VaultPaths,
    home: &Path,
    password: &Secret,
) -> Result<VaultStatus, VaultError> {
    check_bundle(&p.bundle)?;
    if find_attached(r, &p.bundle)?.is_some() {
        return status(r, p, home, 0);
    }
    if let Some(mp) = &p.mountpoint {
        prepare_mountpoint(mp)?;
    }
    let mut a = args(&["attach", "-stdinpass", "-plist", "-owners", "on"]);
    if let Some(mp) = &p.mountpoint {
        a.push("-mountpoint".into());
        a.push(path_str(mp));
    }
    a.push(path_str(&p.bundle));
    let payload = password.stdin_payload();
    let out = r.run(HDIUTIL, &a, Some(payload.as_bytes()), T_ATTACH)?;
    if !out.ok() {
        cleanup_mountpoint(p);
        if tools::is_auth_error(&out.stderr_text()) {
            return Err(VaultError::BadPassword);
        }
        return Err(tool_error("hdiutil attach", &out));
    }
    tools::parse_attach(&out.stdout)?;
    status(r, p, home, 0)
}

/// Detach (lock). Open files: `Busy` with the processes holding them, unless `force`.
pub fn detach(
    r: &dyn Runner,
    p: &VaultPaths,
    home: &Path,
    force: bool,
) -> Result<VaultStatus, VaultError> {
    let Some(att) = find_attached(r, &p.bundle)? else {
        cleanup_mountpoint(p);
        return status(r, p, home, 0);
    };
    let mut a = vec!["detach".to_string(), att.device.clone()];
    if force {
        a.push("-force".into());
    }
    let out = r.run(HDIUTIL, &a, None, T_DETACH)?;
    if !out.ok() {
        if tools::is_busy(&out) && !force {
            let h = att
                .mount_point
                .as_deref()
                .map(|m| holders(r, Path::new(m)))
                .unwrap_or_default();
            return Err(VaultError::Busy(h));
        }
        return Err(tool_error("hdiutil detach", &out));
    }
    cleanup_mountpoint(p);
    status(r, p, home, 0)
}

fn require_detached(r: &dyn Runner, p: &VaultPaths) -> Result<(), VaultError> {
    check_bundle(&p.bundle)?;
    if find_attached(r, &p.bundle)?.is_some() {
        return Err(VaultError::Mounted);
    }
    Ok(())
}

fn run_with_password(
    r: &dyn Runner,
    what: &str,
    a: &[String],
    stdin: &Secret,
    timeout: Duration,
) -> Result<(), VaultError> {
    let out = r.run(HDIUTIL, a, Some(stdin.as_bytes()), timeout)?;
    if !out.ok() {
        if tools::is_auth_error(&out.stderr_text()) {
            return Err(VaultError::BadPassword);
        }
        return Err(tool_error(what, &out));
    }
    Ok(())
}

/// Change the maximum size (vault locked).
pub fn resize(
    r: &dyn Runner,
    p: &VaultPaths,
    home: &Path,
    size: u64,
    password: &Secret,
) -> Result<VaultStatus, VaultError> {
    if !(MIN_SIZE..=MAX_SIZE).contains(&size) {
        return Err(VaultError::Unsafe(
            "taille du coffre : entre 100 Mo et 16 To".into(),
        ));
    }
    require_detached(r, p)?;
    let a = vec![
        "resize".to_string(),
        "-size".into(),
        tools::hdiutil_size_arg(size),
        "-stdinpass".into(),
        path_str(&p.bundle),
    ];
    run_with_password(r, "hdiutil resize", &a, &password.stdin_payload(), T_RESIZE)?;
    status(r, p, home, 0)
}

/// Give the space of deleted files back to the Mac (vault locked).
pub fn compact(
    r: &dyn Runner,
    p: &VaultPaths,
    home: &Path,
    password: &Secret,
) -> Result<VaultStatus, VaultError> {
    require_detached(r, p)?;
    let a = vec![
        "compact".to_string(),
        "-stdinpass".into(),
        path_str(&p.bundle),
    ];
    run_with_password(
        r,
        "hdiutil compact",
        &a,
        &password.stdin_payload(),
        T_COMPACT,
    )?;
    status(r, p, home, 0)
}

/// Change the passphrase (`hdiutil chpass`, old then new on stdin, NUL-separated).
pub fn change_password(
    r: &dyn Runner,
    p: &VaultPaths,
    home: &Path,
    old: &Secret,
    new: &Secret,
) -> Result<VaultStatus, VaultError> {
    validate_new_password(new)?;
    check_bundle(&p.bundle)?;
    let mut payload = Vec::with_capacity(old.as_bytes().len() + new.as_bytes().len() + 2);
    payload.extend_from_slice(old.as_bytes());
    payload.push(0);
    payload.extend_from_slice(new.as_bytes());
    payload.push(0);
    let payload = Secret(payload);
    let a = vec![
        "chpass".to_string(),
        "-oldstdinpass".into(),
        "-newstdinpass".into(),
        path_str(&p.bundle),
    ];
    run_with_password(r, "hdiutil chpass", &a, &payload, T_CHPASS)?;
    status(r, p, home, 0)
}

/// Crypto-shred: lock (forcing if asked) and delete the bundle. The app deletes the keychain item.
pub fn destroy(
    r: &dyn Runner,
    p: &VaultPaths,
    home: &Path,
    force: bool,
) -> Result<VaultStatus, VaultError> {
    check_bundle(&p.bundle)?;
    if find_attached(r, &p.bundle)?.is_some() {
        detach(r, p, home, force)?;
    }
    // remove_dir_all never follows symlinks; the bands are ciphertext.
    std::fs::remove_dir_all(&p.bundle)?;
    cleanup_mountpoint(p);
    status(r, p, home, 0)
}

#[cfg(test)]
mod tests;
