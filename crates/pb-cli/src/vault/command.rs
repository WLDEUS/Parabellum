//! `parabellum vault …`: encrypted vault and secure delete, run as the user (never via the daemon).
//!
//! Passphrases come on stdin (`pass`, or `old\0new` for `chpass`); on a terminal they are prompted
//! without echo. With `--json`, success prints the payload and failure prints
//! `{"error": {"code", "message", "holders"?}}` on stdout with exit code 2.

use super::shred::{self, Outcome, ShredContext, ShredReport, Zone};
use super::tools::{FileVaultState, Holder, Runner, SystemRunner};
use super::{home_dir, read_secrets, Secret, VaultError, VaultPaths, VaultStatus};
use crate::commands::{CliError, Output, EXIT_ERROR, EXIT_OK};
use crate::format::bytes;
use clap::{Args, Subcommand};
use serde::Serialize;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct VaultArgs {
    /// Image du coffre (.sparsebundle). Défaut : ~/Library/Application Support/Parabellum/Vault/Coffre.sparsebundle
    #[arg(long, global = true, value_name = "CHEMIN")]
    pub bundle: Option<PathBuf>,
    /// Dossier où ouvrir le coffre (défaut : /Volumes/Coffre, visible dans le Finder).
    #[arg(long, global = true, value_name = "DOSSIER")]
    pub mountpoint: Option<PathBuf>,
    #[command(subcommand)]
    pub action: VaultCmd,
}

#[derive(Debug, Subcommand)]
pub enum VaultCmd {
    /// État du coffre (ouvert, taille, FileVault).
    Status {
        /// Lister les N fichiers modifiés récemment (coffre ouvert).
        #[arg(long, default_value_t = 0)]
        recent: usize,
    },
    /// Créer le coffre chiffré (AES-256, APFS) ; mot de passe sur l'entrée standard.
    Create {
        /// Taille maximale (ex. 20g, 500m) ; l'image ne prend que la place utilisée.
        #[arg(long, default_value = super::DEFAULT_SIZE)]
        size: String,
        /// Nom du volume.
        #[arg(long, default_value = super::DEFAULT_VOLUME_NAME)]
        name: String,
    },
    /// Ouvrir (déverrouiller) le coffre ; mot de passe sur l'entrée standard.
    Attach,
    /// Verrouiller le coffre.
    Detach {
        /// Même si des fichiers sont ouverts (risque de perte des modifications non enregistrées).
        #[arg(long)]
        force: bool,
    },
    /// Applications qui gardent des fichiers du coffre ouverts.
    Holders,
    /// Changer la taille maximale (coffre verrouillé) ; mot de passe sur l'entrée standard.
    Resize {
        #[arg(long)]
        size: String,
    },
    /// Rendre au Mac la place des fichiers supprimés (coffre verrouillé).
    Compact,
    /// Changer le mot de passe : ancien et nouveau sur l'entrée standard, séparés par un octet nul.
    Chpass,
    /// Détruire le coffre (suppression de l'image chiffrée : irréversible).
    Destroy {
        /// Confirmer la destruction.
        #[arg(long)]
        yes: bool,
        /// Verrouiller de force si des fichiers sont ouverts.
        #[arg(long)]
        force: bool,
    },
    /// Supprimer définitivement des fichiers ou dossiers (réécriture puis suppression ; simple
    /// suppression dans le coffre).
    Shred {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Vérifier et mesurer sans rien supprimer.
        #[arg(long)]
        dry_run: bool,
    },
    /// Vider la Corbeille de façon sûre.
    EmptyTrash {
        #[arg(long)]
        dry_run: bool,
    },
    /// État de FileVault.
    Filevault,
}

/// Plain-language reminder printed after secure deletions.
pub const SSD_CAVEAT: &str = "Sur un SSD, réécrire un fichier ne garantit pas que les anciens blocs \
disparaissent (copie à l'écriture d'APFS, répartition de l'usure, instantanés Time Machine). La vraie \
protection est le chiffrement : FileVault pour tout le disque, et le coffre pour les fichiers sensibles.";

pub fn run(cli: &crate::Cli, io: &mut Output<'_>, a: &VaultArgs) -> Result<i32, CliError> {
    if io.is_root {
        return Err(CliError::Usage(
            "le coffre et l'effacement sûr s'utilisent sans sudo, avec votre compte".into(),
        ));
    }
    let home = home_dir().ok_or_else(|| CliError::Usage("dossier personnel introuvable".into()))?;
    let stdin = std::io::stdin();
    let tty = stdin.is_terminal();
    let mut lock = stdin.lock();
    let mut src = if tty {
        Passwords::Tty
    } else {
        Passwords::Pipe(&mut lock)
    };
    run_with(cli.json, io, a, &SystemRunner, &mut src, &home)
}

/// Where passphrases come from.
pub enum Passwords<'a> {
    Pipe(&'a mut dyn Read),
    Tty,
}

impl Passwords<'_> {
    /// `prompts.len()` secrets (on a pipe: `count` NUL-separated values).
    fn read(&mut self, prompts: &[&str], count: usize) -> Result<Vec<Secret>, VaultError> {
        match self {
            Passwords::Pipe(r) => read_secrets(*r, count),
            Passwords::Tty => prompts
                .iter()
                .map(|p| {
                    crate::protect::read_password(p)
                        .map(|s| Secret::new(s.into_bytes()))
                        .map_err(|e| VaultError::Io(std::io::Error::other(e.to_string())))
                })
                .collect(),
        }
    }
}

fn absolute(p: &Path) -> Result<PathBuf, CliError> {
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()?.join(p)
    };
    super::normalize(&abs)
        .ok_or_else(|| CliError::Usage(format!("chemin refusé : {}", p.display())))
}

/// Testable entry point (runner, password source and home injected).
pub fn run_with(
    json: bool,
    io: &mut Output<'_>,
    a: &VaultArgs,
    r: &dyn Runner,
    pw: &mut Passwords<'_>,
    home: &Path,
) -> Result<i32, CliError> {
    let paths = VaultPaths {
        bundle: match &a.bundle {
            Some(b) => absolute(b)?,
            None => VaultPaths::default_bundle(home),
        },
        mountpoint: a.mountpoint.as_deref().map(absolute).transpose()?,
    };
    match execute(json, io, a, r, pw, home, &paths) {
        Ok(code) => Ok(code),
        Err(Failure::Vault(e)) => {
            emit_error(json, io, &e)?;
            Ok(EXIT_ERROR)
        }
        Err(Failure::Cli(e)) => Err(e),
    }
}

enum Failure {
    Vault(VaultError),
    Cli(CliError),
}

impl From<VaultError> for Failure {
    fn from(e: VaultError) -> Self {
        Failure::Vault(e)
    }
}

impl From<CliError> for Failure {
    fn from(e: CliError) -> Self {
        Failure::Cli(e)
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Self {
        Failure::Cli(CliError::Io(e))
    }
}

fn size_arg(s: &str) -> Result<u64, VaultError> {
    super::tools::parse_size(s)
        .ok_or_else(|| VaultError::Unsafe(format!("taille invalide : {s} (exemples : 20g, 500m)")))
}

fn execute(
    json: bool,
    io: &mut Output<'_>,
    a: &VaultArgs,
    r: &dyn Runner,
    pw: &mut Passwords<'_>,
    home: &Path,
    p: &VaultPaths,
) -> Result<i32, Failure> {
    match &a.action {
        VaultCmd::Status { recent } => {
            let s = super::status(r, p, home, *recent)?;
            emit(json, io, &s, human_status)?;
        }
        VaultCmd::Create { size, name } => {
            let size = size_arg(size)?;
            let mut secrets = pw.read(&["Mot de passe du coffre : ", "Confirmez : "], 1)?;
            if secrets.len() == 2 {
                if secrets[0].as_bytes() != secrets[1].as_bytes() {
                    return Err(VaultError::WeakPassword(
                        "les deux mots de passe diffèrent".into(),
                    )
                    .into());
                }
                secrets.truncate(1);
            }
            let s = super::create(r, p, home, size, name, &secrets[0])?;
            emit(json, io, &s, |s| {
                format!(
                    "Coffre créé : {}\nNotez le mot de passe en lieu sûr : sans lui, le contenu est irrécupérable.\n",
                    s.bundle_path
                )
            })?;
        }
        VaultCmd::Attach => {
            let secrets = pw.read(&["Mot de passe du coffre : "], 1)?;
            let s = super::attach(r, p, home, &secrets[0])?;
            emit(json, io, &s, human_status)?;
        }
        VaultCmd::Detach { force } => {
            let s = super::detach(r, p, home, *force)?;
            emit(json, io, &s, |_| "Coffre verrouillé.\n".to_string())?;
        }
        VaultCmd::Holders => {
            let h = match super::find_attached(r, &p.bundle)?.and_then(|a| a.mount_point) {
                Some(m) => super::holders(r, Path::new(&m)),
                None => Vec::new(),
            };
            emit(json, io, &h, |h| human_holders(h))?;
        }
        VaultCmd::Resize { size } => {
            let size = size_arg(size)?;
            let secrets = pw.read(&["Mot de passe du coffre : "], 1)?;
            let s = super::resize(r, p, home, size, &secrets[0])?;
            emit(json, io, &s, human_status)?;
        }
        VaultCmd::Compact => {
            let secrets = pw.read(&["Mot de passe du coffre : "], 1)?;
            let s = super::compact(r, p, home, &secrets[0])?;
            emit(json, io, &s, human_status)?;
        }
        VaultCmd::Chpass => {
            let mut secrets = pw.read(
                &[
                    "Mot de passe actuel : ",
                    "Nouveau mot de passe : ",
                    "Confirmez : ",
                ],
                2,
            )?;
            if secrets.len() == 3 {
                if secrets[1].as_bytes() != secrets[2].as_bytes() {
                    return Err(VaultError::WeakPassword(
                        "les deux nouveaux mots de passe diffèrent".into(),
                    )
                    .into());
                }
                secrets.truncate(2);
            }
            let s = super::change_password(r, p, home, &secrets[0], &secrets[1])?;
            emit(json, io, &s, |_| {
                "Mot de passe du coffre changé.\n".to_string()
            })?;
        }
        VaultCmd::Destroy { yes, force } => {
            if !yes {
                return Err(CliError::Usage(
                    "destruction irréversible : ajoutez --yes pour confirmer".into(),
                )
                .into());
            }
            let s = super::destroy(r, p, home, *force)?;
            emit(json, io, &s, |_| {
                "Coffre détruit. Supprimez aussi sa clé de récupération si vous l'aviez notée.\n"
                    .to_string()
            })?;
        }
        VaultCmd::Shred { paths, dry_run } => {
            let targets = paths
                .iter()
                .map(|p| absolute(p))
                .collect::<Result<Vec<_>, _>>()?;
            return shred_and_report(json, io, r, home, p, &targets, *dry_run);
        }
        VaultCmd::EmptyTrash { dry_run } => {
            let targets = shred::trash_items(home)?;
            return shred_and_report(json, io, r, home, p, &targets, *dry_run);
        }
        VaultCmd::Filevault => {
            let f = super::filevault(r);
            emit(json, io, &serde_json::json!({ "filevault": f }), |_| {
                format!("FileVault : {}\n", filevault_label(f))
            })?;
        }
    }
    Ok(EXIT_OK)
}

fn shred_and_report(
    json: bool,
    io: &mut Output<'_>,
    r: &dyn Runner,
    home: &Path,
    p: &VaultPaths,
    targets: &[PathBuf],
    dry_run: bool,
) -> Result<i32, Failure> {
    // The open vault (if any) is where plain deletion is enough; a failing hdiutil just means "no
    // vault known" (stricter: everything is overwritten).
    let mount = super::find_attached(r, &p.bundle)
        .ok()
        .flatten()
        .and_then(|a| a.mount_point)
        .map(PathBuf::from);
    let ctx = ShredContext::new(home, mount.as_deref(), Some(&p.bundle));
    let reports = shred::shred_paths(targets, &ctx, dry_run);
    let ok = reports
        .iter()
        .all(|r| matches!(r.outcome, Outcome::Deleted | Outcome::Planned));
    emit(json, io, &reports, |reps| human_shred(reps, dry_run))?;
    Ok(if ok { EXIT_OK } else { EXIT_ERROR })
}

fn emit<T: Serialize>(
    json: bool,
    io: &mut Output<'_>,
    v: &T,
    human: impl FnOnce(&T) -> String,
) -> Result<(), CliError> {
    if json {
        let s = serde_json::to_string_pretty(v).map_err(|e| CliError::Usage(e.to_string()))?;
        writeln!(io.out, "{s}")?;
    } else {
        write!(io.out, "{}", human(v))?;
    }
    Ok(())
}

/// Error payload of `--json`.
#[derive(Debug, Serialize)]
pub struct ErrorBody<'a> {
    pub code: &'a str,
    pub message: String,
    #[serde(skip_serializing_if = "<[Holder]>::is_empty")]
    pub holders: &'a [Holder],
}

fn emit_error(json: bool, io: &mut Output<'_>, e: &VaultError) -> Result<(), CliError> {
    let holders: &[Holder] = match e {
        VaultError::Busy(h) => h,
        _ => &[],
    };
    if json {
        let body = serde_json::json!({
            "error": ErrorBody { code: e.code(), message: e.to_string(), holders }
        });
        writeln!(io.out, "{body}")?;
    } else {
        writeln!(io.err, "parabellum : {e}")?;
        if !holders.is_empty() {
            write!(io.err, "{}", human_holders(holders))?;
            writeln!(
                io.err,
                "Forcer (modifications non enregistrées perdues) : parabellum vault detach --force"
            )?;
        }
    }
    Ok(())
}

pub fn filevault_label(f: FileVaultState) -> &'static str {
    match f {
        FileVaultState::On => "activé",
        FileVaultState::Off => {
            "désactivé — activez-le (Réglages Système > Confidentialité et sécurité > FileVault)"
        }
        FileVaultState::Encrypting => "chiffrement en cours",
        FileVaultState::Decrypting => "déchiffrement en cours — le disque ne sera plus protégé",
        FileVaultState::Unknown => "inconnu",
    }
}

fn human_status(s: &VaultStatus) -> String {
    let mut o = String::new();
    if !s.exists {
        o.push_str(&format!(
            "Aucun coffre ({}).\nCréer : parabellum vault create\n",
            s.bundle_path
        ));
    } else if s.mounted {
        o.push_str(&format!(
            "Coffre : ouvert ({})\n",
            s.mount_point.as_deref().unwrap_or("?")
        ));
    } else {
        o.push_str("Coffre : verrouillé\n");
    }
    if s.exists {
        o.push_str(&format!(
            "Image : {}{}\n",
            s.bundle_path,
            if s.encrypted {
                " (chiffrée)"
            } else {
                " (NON chiffrée)"
            }
        ));
        if let Some(c) = s.capacity_bytes {
            o.push_str(&format!("Taille maximale : {}\n", bytes(c)));
        }
        if let Some(a) = s.allocated_bytes {
            o.push_str(&format!("Place sur le disque : {}\n", bytes(a)));
        }
        if let (Some(t), Some(f)) = (s.volume_total_bytes, s.volume_free_bytes) {
            o.push_str(&format!(
                "Contenu : {} utilisés, {} libres\n",
                bytes(t.saturating_sub(f)),
                bytes(f)
            ));
        }
        for item in &s.recent {
            o.push_str(&format!(
                "  {}  {}  {}\n",
                crate::format::ts(item.modified),
                bytes(item.size),
                item.path
            ));
        }
    }
    if let Some(w) = &s.sync_warning {
        o.push_str(&format!("Attention : {w}\n"));
    }
    o.push_str(&format!("FileVault : {}\n", filevault_label(s.filevault)));
    o
}

fn human_holders(h: &[Holder]) -> String {
    if h.is_empty() {
        return "Aucun fichier du coffre n'est ouvert.\n".into();
    }
    let mut o = String::new();
    for holder in h {
        o.push_str(&format!(
            "  {} (pid {}) : {}\n",
            holder.command,
            holder.pid,
            holder.paths.join(", ")
        ));
    }
    o
}

fn human_shred(reps: &[ShredReport], dry_run: bool) -> String {
    let mut o = String::new();
    if reps.is_empty() {
        return "Rien à supprimer.\n".into();
    }
    for r in reps {
        let what = match r.outcome {
            Outcome::Deleted => "supprimé",
            Outcome::Planned => "à supprimer",
            Outcome::Refused => "refusé",
            Outcome::Failed => "échec",
        };
        let how = match r.zone {
            Some(Zone::Vault) => " (dans le coffre : suppression simple)".to_string(),
            Some(_) if matches!(r.outcome, Outcome::Deleted | Outcome::Planned) => format!(
                " ({} fichier(s), {} réécrits)",
                r.files,
                bytes(r.overwritten_bytes)
            ),
            _ => String::new(),
        };
        o.push_str(&format!("{} : {what}{how}\n", r.path));
        if let Some(e) = &r.error {
            o.push_str(&format!("  {e}\n"));
        }
        for w in &r.warnings {
            o.push_str(&format!("  - {w}\n"));
        }
    }
    if !dry_run {
        o.push_str(&format!("\n{SSD_CAVEAT}\n"));
    }
    o
}
