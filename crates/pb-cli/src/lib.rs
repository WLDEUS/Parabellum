//! `parabellum` command-line client (library part, reused by the daemon's end-to-end tests).
//!
//! - [`cli`]: clap definition (French help),
//! - [`client`]: synchronous JSON-lines client over the Unix socket,
//! - [`commands`]: execution + exit codes,
//! - [`format`]: human-readable tables.

pub mod cli;
pub mod client;
pub mod commands;
pub mod format;

pub use cli::Cli;
pub use commands::{run, Output};
