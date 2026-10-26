//! Parabellum shared contract.
//!
//! Everything that crosses a crate boundary or the daemon <-> UI socket lives here:
//! - [`paths`]: on-disk layout (overridable with `PARABELLUM_ROOT` for tests),
//! - [`config`]: the user-editable configuration (`config.toml`),
//! - [`model`]: verdicts, scan reports, alerts, devices, persistence items, components…
//! - [`events`]: internal monitor -> daemon events,
//! - [`ipc`]: the JSON-lines protocol spoken over the Unix socket (Rust daemon <-> SwiftUI app / CLI),
//! - [`db`]: the signed threat-database bundle manifest (pipeline <-> client).
//!
//! Conventions (the Swift side relies on them):
//! - JSON field names are `snake_case`, enum values are `snake_case` strings.
//! - Timestamps are `i64` Unix epoch **seconds** (UTC).
//! - Optional fields are omitted when `None`.

pub mod config;
pub mod db;
pub mod events;
pub mod ipc;
pub mod model;
pub mod paths;

/// Version of the Parabellum client (daemon, CLI, app share the same version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reverse-DNS prefix used for launchd labels, bundle ids, etc.
pub const BUNDLE_ID: &str = "com.wldeus.parabellum";
/// launchd label of the root daemon.
pub const DAEMON_LABEL: &str = "com.wldeus.parabellum.daemon";
/// launchd label of the per-user agent that starts the menu bar app at login.
pub const UI_AGENT_LABEL: &str = "com.wldeus.parabellum.ui";
/// GitHub repository hosting releases (app `.pkg`) and the nightly threat DB.
pub const GITHUB_REPO: &str = "WLDEUS/Parabellum";

/// Current Unix time in seconds.
pub fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Expand a leading `~` or `~/` with the given home directory.
/// The daemon runs as root, so `~` always means the *console user's* home, which the caller passes in.
pub fn expand_user_path(path: &str, home: &std::path::Path) -> std::path::PathBuf {
    if path == "~" {
        home.to_path_buf()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else {
        std::path::PathBuf::from(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn expands_tilde() {
        let h = Path::new("/Users/q");
        assert_eq!(
            expand_user_path("~/Downloads", h),
            Path::new("/Users/q/Downloads")
        );
        assert_eq!(expand_user_path("~", h), Path::new("/Users/q"));
        assert_eq!(expand_user_path("/tmp/x", h), Path::new("/tmp/x"));
    }
}
