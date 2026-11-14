//! `parabellum` command-line client (library part, reused by the daemon's end-to-end tests).
//!
//! - [`cli`]: clap definition (French help),
//! - [`client`]: synchronous JSON-lines client over the Unix socket,
//! - [`commands`]: execution + exit codes,
//! - [`format`]: human-readable tables,
//! - [`protect`]: `vpn`, `guard` and `privacy` commands,
//! - [`vault`]: encrypted vault and secure delete (local, as the user).

pub mod cli;
pub mod client;
pub mod commands;
pub mod format;
pub mod protect;
pub mod vault;
// Intelligence (domain model + behaviour baseline)
pub mod intel;
// ----- Local network & permissions audit -----
pub mod audit;
// ----- Travel mode -----
pub mod travel;

pub use cli::Cli;
pub use commands::{run, Output};
