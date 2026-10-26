//! Static Mach-O features and gradient-boosted tree inference for Parabellum.
//!
//! * [`extract_features`] turns a (thin or universal) Mach-O into a fixed-length `f32` vector whose
//!   layout is described by [`feature_names`] / [`feature_descriptions`] and versioned by
//!   [`FEATURES_VERSION`]. The vector order is the contract with the Python trainer (`ml/train.py`),
//!   which consumes the JSON lines printed by the `pb-features` binary.
//! * [`GbdtModel`] evaluates a LightGBM model exported with `Booster.dump_model()` (pure Rust, no
//!   runtime, iterative traversal, LightGBM's exact missing-value semantics).
//! * [`MlModel`] bundles the model with its calibrated threshold, as shipped in the threat-DB bundle
//!   (`ml/macho_model.json` + `ml/model_meta.json`).
//!
//! Policy reminder (enforced by `pb-engine`): an ML score alone can only make a file *suspicious*,
//! never *malicious*, and never triggers an automatic quarantine.
//!
//! Everything here parses untrusted bytes: all reads are bounds-checked, every loop driven by a
//! count read from the file is capped, nothing recurses on attacker-controlled depth, and
//! [`extract_features`] wraps the parser in `catch_unwind` as a last line of defence.

mod codesig;
mod features;
mod gbdt;
mod macho;
mod model;

pub use codesig::{code_signature_summary, CodeSignatureSummary};
pub use features::{extract_features, feature_descriptions, feature_names, FEATURES_VERSION};
pub use gbdt::GbdtModel;
pub use macho::plausible_fat_header;
pub use model::{MlModel, ModelMeta, MODEL_FILE, MODEL_META_FILE};

#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub use model::test_model_json;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error)]
pub enum MlError {
    /// The input does not start with a Mach-O or universal (fat) magic.
    #[error("not a Mach-O file")]
    NotMachO,
    /// The input looks like a Mach-O but could not be parsed.
    #[error("malformed Mach-O: {0}")]
    Malformed(String),
    /// I/O error while reading a model or a file.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// Invalid JSON.
    #[error("invalid json: {0}")]
    Json(#[from] serde_json::Error),
    /// The model is structurally invalid or uses an unsupported LightGBM feature.
    #[error("invalid model: {0}")]
    Model(String),
    /// The model was trained on a different feature layout than the one compiled in.
    #[error("feature layout mismatch: {0}")]
    FeatureMismatch(String),
}

/// Returns true when `bytes` starts with a thin Mach-O magic (32/64-bit, either endianness) or a
/// universal-binary magic (`FAT_MAGIC` / `FAT_MAGIC_64`). Cheap pre-filter; a positive answer does
/// not guarantee [`extract_features`] will succeed (Java class files share `0xCAFEBABE`).
pub fn looks_like_macho(bytes: &[u8]) -> bool {
    match bytes.get(0..4) {
        Some(m) => matches!(
            [m[0], m[1], m[2], m[3]],
            [0xfe, 0xed, 0xfa, 0xce]
                | [0xce, 0xfa, 0xed, 0xfe]
                | [0xfe, 0xed, 0xfa, 0xcf]
                | [0xcf, 0xfa, 0xed, 0xfe]
                | [0xca, 0xfe, 0xba, 0xbe]
                | [0xca, 0xfe, 0xba, 0xbf]
        ),
        None => false,
    }
}

#[cfg(any(test, feature = "test-util"))]
#[doc(hidden)]
pub mod testutil;
