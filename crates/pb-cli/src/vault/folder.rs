//! « Chiffrer » un dossier ou un fichier (clic droit dans le Finder) : son contenu est copié dans une image
//! disque APFS chiffrée (AES-256, `hdiutil`) rangée dans un paquet `<nom>.coffre` à côté de lui, puis
//! vérifié fichier par fichier (SHA-256) avant que l'app ne supprime l'original. Un fichier seul est copié
//! à la racine du volume chiffré (`rapport.pdf` → `rapport.pdf.coffre`, qui s'ouvre sur `rapport.pdf`). Le paquet contient aussi `keys.json`, que
//! l'app écrit : les accès sans mot de passe (Touch ID via la Secure Enclave, fichier clé), qui ne font
//! que protéger une copie du mot de passe. Le mot de passe reste l'accès de secours : sans Parabellum,
//! « Afficher le contenu du paquet » puis double-clic sur l'image suffit à l'ouvrir.
//!
//! Ouvrir / verrouiller : `parabellum vault --bundle <x.coffre> attach | detach` (le paquet est résolu vers
//! son image).

use super::shred::{self, ShredContext};
use super::tools::Runner;
use super::{
    attach, create, detach, normalize, validate_volume_name, Secret, VaultError, VaultPaths,
    MAX_SIZE, MIN_SIZE,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{self, Read};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Extension of the package (a folder that the Finder shows as one item, opened by Parabellum).
pub const PACKAGE_EXTENSION: &str = "coffre";
/// The encrypted image inside the package.
pub const IMAGE_NAME: &str = "Contenu.sparsebundle";
/// Volume name when the folder's name is not usable as one.
pub const FALLBACK_VOLUME_NAME: &str = "Dossier chiffré";
const DITTO: &str = "/usr/bin/ditto";
const T_COPY: Duration = Duration::from_secs(6 * 3600);
/// Room for the folder to grow: the image is sparse, only what is stored takes disk space.
const MIN_CAPACITY: u64 = 1 << 30;

/// Result of `encrypt-folder`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderEncryption {
    pub source: String,
    pub package: String,
    pub bundle: String,
    pub volume_name: String,
    /// Maximum size of the image (bytes).
    pub capacity: u64,
    pub files: u64,
    pub bytes: u64,
    /// Every file compared (path, type, size, SHA-256) between the folder and the image.
    pub verified: bool,
}

/// The image of a `.coffre` package (or `path` itself when it is not one).
pub fn resolve_bundle(path: &Path) -> PathBuf {
    if is_package(path) {
        path.join(IMAGE_NAME)
    } else {
        path.to_path_buf()
    }
}

pub fn is_package(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case(PACKAGE_EXTENSION))
}

/// What the folder holds: relative path → entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Dir,
    File { size: u64 },
    Link(PathBuf),
}

/// Directories macOS creates at the root of a mounted volume, some owned by root and unreadable by the
/// user (`.fseventsd`): never part of the copy, never walked.
fn is_volume_internal(name: &str) -> bool {
    matches!(
        name,
        ".fseventsd" | ".Trashes" | ".TemporaryItems" | ".DocumentRevisions-V100" | ".apdisk"
    ) || name.starts_with(".Spotlight-V100")
}

/// `volume_root`: `root` is the mounted image, its macOS internals are skipped without being entered
/// (walking into `.fseventsd` failed with « Permission denied »). The source is inventoried in full.
fn inventory(root: &Path, volume_root: bool) -> Result<BTreeMap<PathBuf, Entry>, VaultError> {
    let mut out = BTreeMap::new();
    let walk = walkdir::WalkDir::new(root)
        .follow_links(false)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| {
            !(volume_root && e.depth() == 1 && is_volume_internal(&e.file_name().to_string_lossy()))
        });
    for e in walk {
        let e = e.map_err(|e| VaultError::Io(io::Error::other(e.to_string())))?;
        let rel = e
            .path()
            .strip_prefix(root)
            .map_err(|_| VaultError::Unsafe("chemin inattendu".into()))?
            .to_path_buf();
        let ft = e.file_type();
        let entry = if ft.is_dir() {
            Entry::Dir
        } else if ft.is_file() {
            Entry::File {
                size: e
                    .metadata()
                    .map_err(|e| VaultError::Io(io::Error::other(e.to_string())))?
                    .len(),
            }
        } else if ft.is_symlink() {
            Entry::Link(std::fs::read_link(e.path())?)
        } else {
            // Sockets, FIFOs, devices: nothing to keep.
            continue;
        };
        out.insert(rel, entry);
    }
    Ok(out)
}

fn sha256(p: &Path) -> io::Result<[u8; 32]> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// What is being encrypted, relative to `base`: a folder's whole tree (base = the folder), or one file
/// (base = its parent, a single entry named like it).
fn source_inventory(source: &Path) -> Result<(PathBuf, BTreeMap<PathBuf, Entry>), VaultError> {
    let md = std::fs::symlink_metadata(source)?;
    if md.is_dir() {
        return Ok((source.to_path_buf(), inventory(source, false)?));
    }
    let (Some(parent), Some(name)) = (source.parent(), source.file_name()) else {
        return Err(VaultError::Unsafe("nom de fichier invalide".into()));
    };
    let mut one = BTreeMap::new();
    one.insert(PathBuf::from(name), Entry::File { size: md.len() });
    Ok((parent.to_path_buf(), one))
}

/// Same tree, same file contents. Returns (files, bytes).
fn verify(source: &Path, copy: &Path) -> Result<(u64, u64), VaultError> {
    let (base, a) = source_inventory(source)?;
    let b = inventory(copy, true)?;
    let mismatch =
        |what: String| VaultError::Tool(format!("vérification de la copie chiffrée : {what}"));
    for (rel, e) in &a {
        match b.get(rel) {
            Some(x) if x == e => {}
            Some(_) => return Err(mismatch(format!("{} diffère", rel.display()))),
            None => return Err(mismatch(format!("{} manquant", rel.display()))),
        }
    }
    if let Some(extra) = b.keys().find(|k| !a.contains_key(*k)) {
        return Err(mismatch(format!("{} en trop", extra.display())));
    }
    let (mut files, mut bytes) = (0u64, 0u64);
    for (rel, e) in &a {
        if let Entry::File { size } = e {
            if sha256(&base.join(rel))? != sha256(&copy.join(rel))? {
                return Err(mismatch(format!("contenu de {} différent", rel.display())));
            }
            files += 1;
            bytes += size;
        }
    }
    Ok((files, bytes))
}

/// Image size for `bytes` of content: twice as much, at least 1 GB (sparse: costs nothing until used).
pub fn capacity_for(bytes: u64) -> u64 {
    bytes
        .saturating_mul(2)
        .max(MIN_CAPACITY)
        .clamp(MIN_SIZE, MAX_SIZE)
}

/// Package path next to the folder or file: `Projets` → `Projets.coffre`, `a.pdf` → `a.pdf.coffre`.
pub fn default_package(source: &Path) -> Option<PathBuf> {
    let name = source.file_name()?.to_string_lossy();
    Some(source.with_file_name(format!("{name}.{PACKAGE_EXTENSION}")))
}

/// Private, empty mount point for the copy (never in /Volumes: nothing shows up in the Finder).
fn temp_mountpoint() -> io::Result<PathBuf> {
    let base = std::env::temp_dir();
    for i in 0..16u32 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let p = base.join(format!(
            "parabellum-coffre-{}-{nanos:x}-{i}",
            std::process::id()
        ));
        match std::fs::DirBuilder::new().mode(0o700).create(&p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("point de montage temporaire impossible"))
}

/// Encrypts `source` (a folder or a regular file) into a new `.coffre` package; the original is left untouched (the app deletes it
/// afterwards, with « Supprimer définitivement », once the user has confirmed).
pub fn encrypt_folder(
    r: &dyn Runner,
    home: &Path,
    source: &Path,
    output: Option<&Path>,
    password: &Secret,
) -> Result<FolderEncryption, VaultError> {
    let Some(source) = normalize(source) else {
        return Err(VaultError::Unsafe("chemin absolu attendu".into()));
    };
    let md = std::fs::symlink_metadata(&source).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound => VaultError::NotFound(source.display().to_string()),
        _ => e.into(),
    })?;
    // Symlinks, sockets, devices: refused (the link's target would be encrypted, not the link).
    let is_file = md.is_file();
    if !md.is_dir() && !is_file {
        return Err(VaultError::Unsafe(format!(
            "{} n'est ni un dossier ni un fichier",
            source.display()
        )));
    }
    if is_package(&source) || source.extension().is_some_and(|e| e == "sparsebundle") {
        return Err(VaultError::Unsafe("c'est déjà un dossier chiffré".into()));
    }
    // Same rules as « Supprimer définitivement »: the original is deleted afterwards.
    let ctx = ShredContext::new(home, None, None);
    let canon = super::canonical_lenient(&source);
    shred::check_target(&canon, &ctx, &|root| {
        shred::volume_is_external(root, ctx.root_dev)
    })
    .map_err(VaultError::Unsafe)?;

    let package = match output {
        Some(o) => normalize(o)
            .ok_or_else(|| VaultError::Unsafe("destination : chemin absolu attendu".into()))?,
        None => default_package(&source)
            .ok_or_else(|| VaultError::Unsafe("nom de dossier invalide".into()))?,
    };
    if !is_package(&package) {
        return Err(VaultError::Unsafe(format!(
            "la destination doit se terminer par .{PACKAGE_EXTENSION}"
        )));
    }
    if package.starts_with(&source) {
        return Err(VaultError::Unsafe(
            "la destination ne peut pas être dans le dossier chiffré".into(),
        ));
    }
    if std::fs::symlink_metadata(&package).is_ok() {
        return Err(VaultError::AlreadyExists(package.display().to_string()));
    }
    let content_bytes: u64 = source_inventory(&source)?
        .1
        .values()
        .map(|e| match e {
            Entry::File { size } => *size,
            _ => 0,
        })
        .sum();
    let capacity = capacity_for(content_bytes);
    // A file's volume is named without its extension (`rapport.pdf` → « rapport »).
    let name_part = if is_file {
        source.file_stem()
    } else {
        source.file_name()
    };
    let name = name_part
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let volume_name = if validate_volume_name(&name).is_ok() {
        name
    } else {
        FALLBACK_VOLUME_NAME.to_string()
    };

    std::fs::DirBuilder::new().mode(0o700).create(&package)?;
    let mountpoint = match temp_mountpoint() {
        Ok(m) => m,
        Err(e) => {
            let _ = std::fs::remove_dir(&package);
            return Err(e.into());
        }
    };
    let paths = VaultPaths {
        bundle: package.join(IMAGE_NAME),
        mountpoint: Some(mountpoint.clone()),
    };
    let result = fill(
        r,
        home,
        &source,
        &paths,
        &mountpoint,
        capacity,
        &volume_name,
        password,
    );
    // Locked again whatever happened.
    let locked = detach(r, &paths, home, false)
        .or_else(|_| detach(r, &paths, home, true))
        .is_ok();
    let _ = std::fs::remove_dir(&mountpoint);
    match result {
        Ok((files, bytes)) if locked => Ok(FolderEncryption {
            source: source.display().to_string(),
            package: package.display().to_string(),
            bundle: paths.bundle.display().to_string(),
            volume_name,
            capacity,
            files,
            bytes,
            verified: true,
        }),
        Ok(_) => {
            remove_package(&package);
            Err(VaultError::Tool(
                "impossible de reverrouiller la copie chiffrée : annulé".into(),
            ))
        }
        Err(e) => {
            if locked {
                remove_package(&package);
            }
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn fill(
    r: &dyn Runner,
    home: &Path,
    source: &Path,
    paths: &VaultPaths,
    mountpoint: &Path,
    capacity: u64,
    volume_name: &str,
    password: &Secret,
) -> Result<(u64, u64), VaultError> {
    create(r, paths, home, capacity, volume_name, password)?;
    attach(r, paths, home, password)?;
    // `ditto src dst` copies the contents of src into dst (a file: to dst/<name>), with extended
    // attributes, ACLs and resource forks (quarantine flags kept: a downloaded file stays flagged).
    let dest = if source.is_dir() {
        mountpoint.to_path_buf()
    } else {
        let name = source
            .file_name()
            .ok_or_else(|| VaultError::Unsafe("nom de fichier invalide".into()))?;
        mountpoint.join(name)
    };
    let a = vec![source.display().to_string(), dest.display().to_string()];
    let out = r.run(DITTO, &a, None, T_COPY)?;
    if !out.ok() {
        return Err(VaultError::Tool(format!(
            "copie (ditto) : {}",
            out.stderr_text()
        )));
    }
    verify(source, mountpoint)
}

/// Removes a package this command created (never anything else: checked by name).
fn remove_package(package: &Path) {
    if is_package(package) && std::fs::symlink_metadata(package).is_ok_and(|m| m.is_dir()) {
        let _ = std::fs::remove_dir_all(package);
    }
}
