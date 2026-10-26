//! Parabellum updater.
//!
//! - [`DbUpdater`]: signed threat-DB bundle (minisign, verified *before* unpacking), strict unpacking,
//!   per-file SHA-256 checks, atomic `db/current` symlink swap, rollback to `db/previous`.
//! - [`run_freshclam`]: official ClamAV signatures into `clamav/db/` with a generated `freshclam.conf`.
//! - [`ComponentManager`]: third-party tools (ClamAV, osquery, dnscrypt-proxy, LuLu, BlockBlock, OverSight)
//!   installed from their official GitHub releases after signature verification (Apple Team ID or
//!   minisign), plus Parabellum self-update and uBlock Origin Lite status ([`adblock_extension_states`]).
//!
//! Every HTTP request goes through [`http::Http`]: HTTPS only, `User-Agent: Parabellum/<version>`,
//! optional GitHub token (sent to `github.com` / `api.github.com` only), timeouts, size caps, streaming
//! to disk. Every subprocess is spawned by absolute path with an argument vector and a timeout.

mod adblock;
mod components;
mod db;
mod freshclam;
mod fsutil;
mod github;
pub mod http;
mod process;
mod selfupdate;
mod signing;
pub mod trust;
mod unpack;
pub mod version;

#[cfg(test)]
mod testutil;

pub use adblock::{
    adblock_extension_states, adblock_extension_states_for, CHROME_UBOL_EXTENSION_ID,
    CHROME_UBOL_STORE_URL, SAFARI_UBOL_STORE_URL,
};
pub use components::{
    dnscrypt_proxy_binary, ComponentManager, BLOCKBLOCK_DAEMON_APP, CLAMAV_PKG_CLAMSCAN,
    CLAMAV_TEAM_ID, COMPONENT_NAMES, DNSCRYPT_MINISIGN_KEY, LULU_APP, OBJECTIVE_SEE_TEAM_ID,
    OSQUERYI, OSQUERY_TEAM_ID, OVERSIGHT_APP,
};
pub use selfupdate::{
    finish_self_update, self_update_log, self_update_marker, self_update_plist, self_update_staging_dir,
    SELFUPDATE_LABEL,
};
pub use db::{DbUpdateOutcome, DbUpdater, MAX_BUNDLE_BYTES, MAX_MANIFEST_BYTES};
pub use freshclam::{find_freshclam, find_trusted_freshclam, run_freshclam, FRESHCLAM_CANDIDATES};

include!(concat!(env!("OUT_DIR"), "/pubkey.rs"));

/// The minisign public key (bare base64) compiled into the binary, used to verify the threat-DB
/// bundle and Parabellum `.pkg` releases. `None` when the build had no key (`make keys` not run).
pub fn embedded_public_key() -> Option<&'static str> {
    EMBEDDED_PUBKEY
}

/// Message shown when no signing key was compiled in.
pub const MISSING_KEY_MESSAGE: &str = "clé publique de signature absente — lancer `make keys`";

/// Errors of every updater operation. Messages are user-facing (shown in the app), mostly in French.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("{MISSING_KEY_MESSAGE}")]
    MissingPublicKey,
    #[error("URL refusée (HTTPS obligatoire) : {0}")]
    InsecureUrl(String),
    #[error("erreur réseau : {0}")]
    Http(String),
    #[error("{url} a répondu HTTP {status}")]
    HttpStatus { url: String, status: u16 },
    #[error("limite de requêtes GitHub atteinte, nouvel essai plus tard")]
    RateLimited,
    #[error("{what} dépasse la taille maximale ({limit} octets)")]
    TooLarge { what: String, limit: u64 },
    #[error("signature invalide : {0}")]
    Signature(String),
    #[error("manifeste invalide : {0}")]
    Manifest(String),
    #[error("archive refusée : {0}")]
    Archive(String),
    #[error("empreinte incorrecte : {0}")]
    Digest(String),
    #[error("cette base exige Parabellum >= {required} (version actuelle {current})")]
    ClientTooOld { required: String, current: String },
    #[error("aucune version précédente pour revenir en arrière")]
    NoPrevious,
    #[error("une mise à jour est déjà en cours")]
    Busy,
    #[error("vérification refusée : {0}")]
    Verification(String),
    #[error("commande échouée : {0}")]
    Command(String),
    #[error("délai dépassé : {0}")]
    Timeout(String),
    #[error("introuvable : {0}")]
    NotFound(String),
    #[error("serveur ClamAV en période de refroidissement (rate limit) : {0}")]
    CoolDown(String),
    #[error("binaire non fiable pour root (modifiable par un utilisateur) : {0}")]
    Untrusted(String),
    #[error("non pris en charge sur cette plateforme : {0}")]
    Unsupported(String),
    #[error("E/S : {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON : {0}")]
    Json(#[from] serde_json::Error),
}
