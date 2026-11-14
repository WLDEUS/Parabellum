//! `pb-features`: dump Mach-O or script static features as JSON lines for the trainer (`ml/train.py`).
//!
//! ```text
//! pb-features [--kind macho|script] [--label <0|1>] [--max-size-mb 100] <paths…>
//! pb-features [--kind macho|script] --names | --describe | --features-version
//! ```
//! For every Mach-O (`--kind macho`, default) or script (`--kind script`: magic, shebang, script
//! extension or script-like text, see `pb_ml::detect_script_kind`) found under `paths` (files or
//! directories, walked recursively without following symlinks) one line is printed on stdout:
//! `{"sha256":"…","path":"…","label":1,"features_version":1,"features":[…]}`.
//! Feature values are printed as the exact `f64` widening of the `f32` the engine computes, so a
//! trainer reading them as float64 or float32 sees exactly what the Rust inference sees.
//! Non-Mach-O files are skipped silently; errors go to stderr. Nothing is ever executed.

use clap::Parser;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "pb-features",
    version,
    about = "Extract Parabellum Mach-O features as JSON lines"
)]
struct Args {
    /// Feature family: `macho` (default) or `script`.
    #[arg(long, default_value = "macho", value_parser = ["macho", "script"])]
    kind: String,
    /// Label attached to every record (0 = clean, 1 = malicious).
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=1))]
    label: Option<u8>,
    /// Skip files larger than this many MiB.
    #[arg(long, default_value_t = 100)]
    max_size_mb: u64,
    /// Print the feature names (JSON array, vector order) and exit.
    #[arg(long)]
    names: bool,
    /// Print `{"name","description"}` objects for every feature (JSON array) and exit.
    #[arg(long)]
    describe: bool,
    /// Print the feature layout version of `--kind` and exit.
    #[arg(long)]
    features_version: bool,
    /// Files or directories to scan.
    paths: Vec<PathBuf>,
}

#[derive(Serialize)]
struct Record {
    sha256: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<u8>,
    features_version: u32,
    features: Vec<f64>,
}

#[derive(Serialize)]
struct Description<'a> {
    name: &'a str,
    description: &'a str,
}

fn main() {
    let args = Args::parse();
    let script = args.kind == "script";
    let (names, docs): (&[&str], &[&str]) = if script {
        (
            pb_ml::script_feature_names(),
            pb_ml::script_feature_descriptions(),
        )
    } else {
        (pb_ml::feature_names(), pb_ml::feature_descriptions())
    };
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    if args.features_version {
        let v = if script {
            pb_ml::SCRIPT_FEATURES_VERSION
        } else {
            pb_ml::FEATURES_VERSION
        };
        let _ = writeln!(out, "{v}");
        return;
    }
    if args.names || args.describe {
        let json = if args.names {
            serde_json::to_string(names)
        } else {
            let d: Vec<Description<'_>> = names
                .iter()
                .zip(docs)
                .map(|(n, d)| Description {
                    name: n,
                    description: d,
                })
                .collect();
            serde_json::to_string(&d)
        };
        match json {
            Ok(s) => {
                let _ = writeln!(out, "{s}");
            }
            Err(e) => {
                eprintln!("pb-features: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if args.paths.is_empty() {
        eprintln!("pb-features: no input paths (see --help)");
        std::process::exit(2);
    }
    let max_bytes = args.max_size_mb.saturating_mul(1024 * 1024);
    let mut errors = 0u64;
    for root in &args.paths {
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("pb-features: {e}");
                    errors += 1;
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let result = if script {
                process_script(entry.path(), max_bytes, args.label)
            } else {
                process(entry.path(), max_bytes, args.label)
            };
            match result {
                Ok(Some(line)) => {
                    if writeln!(out, "{line}").is_err() {
                        return; // broken pipe: consumer went away
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("pb-features: {}: {e}", entry.path().display());
                    errors += 1;
                }
            }
        }
    }
    let _ = out.flush();
    if errors > 0 {
        eprintln!("pb-features: {errors} error(s)");
    }
}

/// Returns the JSON line for a Mach-O, `None` for non-Mach-O / oversized files.
fn process(path: &Path, max_bytes: u64, label: Option<u8>) -> Result<Option<String>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    if len > max_bytes || len < 4 {
        return Ok(None);
    }
    let mut head = [0u8; 4];
    let mut reader = file;
    reader.read_exact(&mut head).map_err(|e| e.to_string())?;
    if !pb_ml::looks_like_macho(&head) {
        return Ok(None);
    }
    let mut bytes = head.to_vec();
    reader
        .take(max_bytes.saturating_sub(4))
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let features = match pb_ml::extract_features(&bytes) {
        Ok(f) => f,
        Err(pb_ml::MlError::NotMachO) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let record = Record {
        sha256: hex::encode(Sha256::digest(&bytes)),
        path: path.to_string_lossy().into_owned(),
        label,
        features_version: pb_ml::FEATURES_VERSION,
        features: features.into_iter().map(f64::from).collect(),
    };
    serde_json::to_string(&record)
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Returns the JSON line for a script, `None` for non-scripts / oversized files.
fn process_script(
    path: &Path,
    max_bytes: u64,
    label: Option<u8>,
) -> Result<Option<String>, String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    if len > max_bytes || len < 2 {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    file.take(max_bytes)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    // Mach-O files are never scripts, whatever their extension.
    if pb_ml::looks_like_macho(&bytes) {
        return Ok(None);
    }
    let features = match pb_ml::extract_script_features(&bytes, Some(path)) {
        Ok(f) => f,
        Err(pb_ml::MlError::NotScript) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    let record = Record {
        sha256: hex::encode(Sha256::digest(&bytes)),
        path: path.to_string_lossy().into_owned(),
        label,
        features_version: pb_ml::SCRIPT_FEATURES_VERSION,
        features: features.into_iter().map(f64::from).collect(),
    };
    serde_json::to_string(&record)
        .map(Some)
        .map_err(|e| e.to_string())
}
