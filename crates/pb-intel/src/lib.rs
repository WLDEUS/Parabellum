//! Parabellum predictive intelligence.
//!
//! * [`domain`]: lexical features of DNS names (typosquatting, homoglyphs, brand-in-subdomain, DGA-like
//!   randomness, abused TLDs…) and the LightGBM phishing-domain model shipped in the threat-DB bundle
//!   ([`domain::model::DomainScorer`]); `pb-domain-features` prints the same vectors for the trainer.
//! * [`behavior`]: the on-device behavioural baseline (per-executable profiles, count-min sketch,
//!   Bayesian novelty scoring), persisted compactly in the daemon's state directory and never sent
//!   anywhere.

pub mod behavior;
pub mod domain;

pub use behavior::{AnomalyRecord, Baseline, BehaviorEvent, ObsKind};
pub use domain::model::{DomainScorer, DomainVerdict, Scored, VerdictSource};
