//! `pb-features` output contract (consumed by `ml/train.py`).

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_pb-features");

fn fixtures() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

#[test]
fn names_match_library() {
    let out = Command::new(BIN).arg("--names").output().unwrap();
    assert!(out.status.success());
    let names: Vec<String> = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(names, pb_ml::feature_names());
}

#[test]
fn emits_one_json_line_per_macho_and_skips_others() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy(fixtures().join("min_arm64.macho"), dir.path().join("a.bin")).unwrap();
    std::fs::write(dir.path().join("b.txt"), b"#!/bin/sh\necho hi\n").unwrap();
    let out = Command::new(BIN)
        .args(["--label", "1"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "{text}");
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    // Field order on the wire: sha256, path, label, features_version, features.
    let pos: Vec<usize> = [
        "\"sha256\":",
        "\"path\":",
        "\"label\":",
        "\"features_version\":",
        "\"features\":",
    ]
    .iter()
    .map(|k| lines[0].find(k).unwrap())
    .collect();
    assert!(pos.windows(2).all(|w| w[0] < w[1]), "{}", lines[0]);
    assert_eq!(v["label"], 1);
    assert_eq!(v["features_version"], pb_ml::FEATURES_VERSION);
    let bytes = std::fs::read(dir.path().join("a.bin")).unwrap();
    let expected = pb_ml::extract_features(&bytes).unwrap();
    let got: Vec<f64> = serde_json::from_value(v["features"].clone()).unwrap();
    assert_eq!(got.len(), expected.len());
    // Round trip: the printed f64 (exact widening of the f32, shortest repr) parses back to the
    // same f32. (serde_json's default float parser is not correctly rounded in the last f64 ulp;
    // Python's float() is, so the trainer sees exactly f64::from(f32).)
    for (g, e) in got.iter().zip(&expected) {
        assert_eq!(*g as f32, *e);
    }
    assert_eq!(v["sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn rejects_bad_label() {
    let out = Command::new(BIN)
        .args(["--label", "2", "/nonexistent"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
