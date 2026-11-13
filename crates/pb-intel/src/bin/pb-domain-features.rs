//! `pb-domain-features`: lexical domain features as JSON lines for the trainer (`ml/domains/`).
//!
//! ```text
//! pb-domain-features [--brands pipeline/data/brands.txt] [--label 0|1] < domains.txt
//! pb-domain-features --names | --describe | --version-info
//! ```
//! One input name per line (blank lines and `#` comments skipped); one output line per valid name:
//! `{"domain":"…","registrable":"…","label":1,"features_version":1,"features":[…]}`.
//! Values are the exact `f64` widening of the `f32` the daemon computes.

use clap::Parser;
use pb_intel::domain::{self, Brands, DomainFeatures, FEATURES_VERSION};
use serde::Serialize;
use std::io::{BufRead, Write};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "pb-domain-features",
    version,
    about = "Extract Parabellum domain features"
)]
struct Args {
    /// Brand list (default: the compiled-in pipeline/data/brands.txt).
    #[arg(long)]
    brands: Option<PathBuf>,
    /// Label attached to every record (0 = benign, 1 = malicious).
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=1))]
    label: Option<u8>,
    /// Print the feature names (JSON array) and exit.
    #[arg(long)]
    names: bool,
    /// Print `{"name","description"}` objects and exit.
    #[arg(long)]
    describe: bool,
    /// Print `{"features_version":N}` and exit.
    #[arg(long)]
    version_info: bool,
}

#[derive(Serialize)]
struct Record<'a> {
    domain: &'a str,
    registrable: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<u8>,
    features_version: u32,
    features: Vec<f64>,
}

fn main() {
    let args = Args::parse();
    let out = std::io::stdout();
    let mut out = std::io::BufWriter::new(out.lock());
    if args.names {
        let _ = writeln!(
            out,
            "{}",
            serde_json::to_string(domain::feature_names()).unwrap_or_default()
        );
        return;
    }
    if args.describe {
        let v: Vec<_> = domain::feature_names()
            .iter()
            .zip(domain::feature_descriptions())
            .map(|(n, d)| serde_json::json!({"name": n, "description": d}))
            .collect();
        let _ = writeln!(out, "{}", serde_json::Value::Array(v));
        return;
    }
    if args.version_info {
        let _ = writeln!(
            out,
            "{}",
            serde_json::json!({"features_version": FEATURES_VERSION})
        );
        return;
    }
    let brands = match &args.brands {
        Some(p) => match std::fs::read_to_string(p) {
            Ok(t) => Brands::parse(&t),
            Err(e) => {
                eprintln!("pb-domain-features: {}: {e}", p.display());
                std::process::exit(2);
            }
        },
        None => Brands::builtin(),
    };
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some(host) = domain::normalize(t) else {
            eprintln!("pb-domain-features: skipped invalid name {t:?}");
            continue;
        };
        let f = DomainFeatures::extract(&host, &brands);
        let rec = Record {
            domain: &host,
            registrable: &f.registrable,
            label: args.label,
            features_version: FEATURES_VERSION,
            features: f.values.iter().map(|v| f64::from(*v)).collect(),
        };
        if let Ok(s) = serde_json::to_string(&rec) {
            if writeln!(out, "{s}").is_err() {
                break;
            }
        }
    }
}
