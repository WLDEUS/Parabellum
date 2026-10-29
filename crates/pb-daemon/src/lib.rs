//! `parabellumd` internals (library so integration tests can run a daemon in-process).
//!
//! Layout:
//! - [`daemon`]: startup / shutdown of every task,
//! - [`ipc`] + [`router`] + [`auth`]: Unix-socket server, per-request peer checks, administrator
//!   approval (Authorization Services), one handler per command,
//! - [`store`]: SQLite (alerts, jobs, findings, history, devices, persistence, lists, stats, update log),
//! - [`jobs`]: scan job manager; [`realtime`]: monitor events → scans; [`actions`]: verdict policy & alerts,
//! - [`persistence`], [`devices`], [`baseline`]: monitor-specific handling,
//! - [`scheduler`]: updates, retro-hunts, osquery, battery; [`status`], [`report`],
//! - [`backends`]: traits the other crates are plugged into ([`adapters`] = production wiring),
//! - [`guard`]: behaviour detection (info-stealers, ransomware decoys / mass encryption) and APFS snapshots,
//! - [`vpn`] / [`privacy`]: glue to pb-vpn (VPN, kill switch, network guard) and pb-privacy (GDPR requests,
//!   breaches, aliases),
//! - [`system`], [`setup`]: platform helpers, directories, logging, config file.

pub mod actions;
pub mod adapters;
pub mod auth;
pub mod backends;
pub mod baseline;
pub mod bus;
pub mod ctx;
pub mod daemon;
pub mod devices;
pub mod guard;
pub mod ipc;
pub mod jobs;
pub mod persistence;
pub mod posture;
pub mod privacy;
pub mod realtime;
pub mod report;
pub mod router;
pub mod scheduler;
pub mod setup;
pub mod spyware;
pub mod status;
pub mod store;
pub mod system;
pub mod virustotal;
pub mod vpn;
