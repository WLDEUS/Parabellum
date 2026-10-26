//! End-to-end engine tests (run on Linux): fake bundle, hash DB, built-in and bundle rules,
//! containers, zip-bomb guard, cache, ClamAV merge (fake clamscan), ML, performance.

use super::*;
use std::collections::BTreeMap;
use std::io::Write;

pub(crate) const EICAR: &[u8] =
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
const MALWARE_SAMPLE: &[u8] = b"\x7fnot-really-malware: sample listed in the hash DB\n";
const VERSION: &str = "2026.10.25.1";

struct Fixture {
    _dir: tempfile::TempDir,
    paths: Paths,
    data: PathBuf,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(dir.path().join("root"));
    for d in paths.all_dirs() {
        std::fs::create_dir_all(d).unwrap();
    }
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    Fixture {
        _dir: dir,
        paths,
        data,
    }
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn write_digests(path: &Path, items: &[&[u8]]) {
    let mut d: Vec<[u8; 32]> = items.iter().map(|b| sha(b)).collect();
    // A few unrelated digests so the binary search has something to do.
    for i in 0..50u8 {
        d.push(sha(&[i; 7]));
    }
    d.sort();
    d.dedup();
    std::fs::write(path, d.concat()).unwrap();
}

/// Installs a bundle under `paths.db_versions_dir()/VERSION` and points `db/current` at it.
fn install_bundle(
    paths: &Paths,
    malware: &[&[u8]],
    allow: &[&[u8]],
    extra: impl FnOnce(&Path),
) -> PathBuf {
    let b = paths.db_versions_dir().join(VERSION);
    for sub in ["hashes", "yara", "allow", "clamav"] {
        std::fs::create_dir_all(b.join(sub)).unwrap();
    }
    write_digests(&b.join("hashes/malware.sha256"), malware);
    write_digests(&b.join("hashes/allow.sha256"), allow);
    let mut names: Vec<String> = malware
        .iter()
        .map(|m| format!("{}\tMacOS.Test.Sample", hex::encode(sha(m))))
        .collect();
    names.sort();
    std::fs::write(b.join("hashes/malware_names.tsv"), names.join("\n")).unwrap();
    std::fs::write(
        b.join("yara/test.yar"),
        "rule Test_Marker { meta: family = \"MacOS.Test.Marker\" severity = \"high\" description = \"test rule\" \
         strings: $m = \"PARABELLUM-TEST-MARKER\" condition: $m }",
    )
    .unwrap();
    std::fs::write(
        b.join("yara/broken.yar"),
        "rule Broken { strings: $a = \"x\" condition: $b }",
    )
    .unwrap();
    std::fs::write(
        b.join("allow/team_ids.txt"),
        "# trusted\nABCDE12345\nnot-a-team-id\n",
    )
    .unwrap();
    let manifest = pb_core::db::DbManifest {
        format: pb_core::db::DB_FORMAT,
        version: VERSION.into(),
        built_at: 0,
        min_client_version: "0.1.0".into(),
        sources: vec![],
        files: BTreeMap::new(),
        stats: Default::default(),
    };
    std::fs::write(
        b.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    extra(&b);
    let current = paths.db_current();
    let _ = std::fs::remove_file(&current);
    std::os::unix::fs::symlink(&b, &current).unwrap();
    b
}

fn opts() -> ScanOptions {
    ScanOptions::default()
}

fn zip_bytes(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    for (name, data, stored) in entries {
        let o = zip::write::SimpleFileOptions::default().compression_method(if *stored {
            zip::CompressionMethod::Stored
        } else {
            zip::CompressionMethod::Deflated
        });
        w.start_file(*name, o).unwrap();
        w.write_all(data).unwrap();
    }
    w.finish().unwrap().into_inner()
}

fn collect(engine: &Engine, paths: &[PathBuf], o: &ScanOptions) -> (Vec<ScanReport>, ScanTotals) {
    let mut reports = Vec::new();
    let totals = engine.scan_paths(paths, o, &AtomicBool::new(false), &mut |r| {
        reports.push(r.clone())
    });
    (reports, totals)
}

#[test]
fn engine_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Engine>();
}

#[test]
fn loads_without_bundle_and_detects_eicar() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let s = e.stats();
    assert_eq!(s.db_version, None);
    assert_eq!(s.malware_hashes, 0);
    assert_eq!(s.yara_rules, 4);
    assert!(s.warnings.iter().any(|w| w.contains("no threat database")));

    let p = f.data.join("eicar.com");
    std::fs::write(&p, EICAR).unwrap();
    let r = e.scan_file(&p, &opts());
    assert_eq!(r.verdict, Verdict::Malicious, "{r:?}");
    assert_eq!(r.detections[0].name, "EICAR-Test-File");
    assert_eq!(r.sha256.as_deref(), Some(hex::encode(sha(EICAR)).as_str()));
    assert!(!r.cached);
    assert!(r.error.is_none());

    let clean = f.data.join("notes.txt");
    std::fs::write(&clean, b"just some notes").unwrap();
    let r = e.scan_file(&clean, &opts());
    assert_eq!(r.verdict, Verdict::Clean);
    assert!(r.detections.is_empty());
}

#[test]
fn hash_db_allowlists_and_bundle_rules() {
    let f = fixture();
    let allowed_but_eicar: &[u8] =
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\r\n";
    install_bundle(&f.paths, &[MALWARE_SAMPLE], &[allowed_but_eicar], |_| {});
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let s = e.stats();
    assert_eq!(s.db_version.as_deref(), Some(VERSION));
    assert_eq!(s.malware_hashes, 51);
    assert_eq!(s.allow_hashes, 51);
    assert_eq!(
        s.yara_rules, 5,
        "built-in 4 + test.yar (broken.yar skipped)"
    );
    assert!(
        s.warnings.iter().any(|w| w.contains("broken.yar")),
        "{:?}",
        s.warnings
    );
    assert!(e.team_ids.contains("ABCDE12345") && e.team_ids.len() == 1);

    // Hash DB hit.
    let m = f.data.join("sample.bin");
    std::fs::write(&m, MALWARE_SAMPLE).unwrap();
    let r = e.scan_file(&m, &opts());
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!(r.detections[0].engine, DetectionEngine::HashDb);
    assert_eq!(r.detections[0].name, "MacOS.Test.Sample");
    assert!((r.score - 0.99).abs() < 1e-6);

    // Bundle allowlist wins over the built-in EICAR rule.
    let a = f.data.join("allowed.com");
    std::fs::write(&a, allowed_but_eicar).unwrap();
    let r = e.scan_file(&a, &opts());
    assert_eq!(r.verdict, Verdict::Clean, "{r:?}");
    assert!(r.detections.is_empty());

    // Local allowlist wins over the hash DB, and clears the cache.
    assert_eq!(e.scan_file(&m, &opts()).verdict, Verdict::Malicious);
    assert!(e.scan_file(&m, &opts()).cached);
    e.set_local_allowlist(&[
        hex::encode(sha(MALWARE_SAMPLE)).to_uppercase(),
        "garbage".into(),
    ]);
    let r = e.scan_file(&m, &opts());
    assert_eq!(r.verdict, Verdict::Clean);
    assert!(!r.cached);

    // Bundle YARA rule (high severity, unsigned) => malicious.
    let y = f.data.join("marker.txt");
    std::fs::write(&y, b"hello PARABELLUM-TEST-MARKER world").unwrap();
    let r = e.scan_file(&y, &opts());
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!(r.detections[0].name, "MacOS.Test.Marker");
}

#[test]
fn hash_db_file_with_bad_length_degrades() {
    let f = fixture();
    let b = install_bundle(&f.paths, &[MALWARE_SAMPLE], &[], |_| {});
    std::fs::write(b.join("hashes/malware.sha256"), [0u8; 33]).unwrap();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    assert_eq!(e.stats().malware_hashes, 0);
    assert!(e
        .stats()
        .warnings
        .iter()
        .any(|w| w.contains("multiple of 32")));
}

#[test]
fn zip_members_nested_and_rollup() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let inner = zip_bytes(&[("eicar.com", EICAR, true)]);
    let x = f.data.join("x.zip");
    std::fs::write(
        &x,
        zip_bytes(&[
            ("eicar.com", EICAR, false),
            ("readme.txt", b"hello", false),
            ("dir/inner.zip", &inner, true),
        ]),
    )
    .unwrap();

    let (reports, totals) = collect(&e, std::slice::from_ref(&x), &opts());
    let by_path: BTreeMap<&str, &ScanReport> =
        reports.iter().map(|r| (r.path.as_str(), r)).collect();
    let xs = x.to_string_lossy();
    let member = by_path[format!("{xs}!/eicar.com").as_str()];
    assert_eq!(member.verdict, Verdict::Malicious);
    assert_eq!(member.size, EICAR.len() as u64);
    assert_eq!(
        member.sha256.as_deref(),
        Some(hex::encode(sha(EICAR)).as_str())
    );
    assert_eq!(
        by_path[format!("{xs}!/readme.txt").as_str()].verdict,
        Verdict::Clean
    );
    let nested = by_path[format!("{xs}!/dir/inner.zip!/eicar.com").as_str()];
    assert_eq!(nested.verdict, Verdict::Malicious);
    assert_eq!(
        by_path[format!("{xs}!/dir/inner.zip").as_str()].verdict,
        Verdict::Malicious
    );
    let container = by_path[xs.as_ref()];
    assert_eq!(container.verdict, Verdict::Malicious);
    assert_eq!(container.kind, FileKind::Zip);
    assert!(container.detections.iter().any(|d| d
        .details
        .as_deref()
        .is_some_and(|x| x.starts_with("in eicar.com"))));
    // Container is delivered after its members.
    assert_eq!(reports.last().unwrap().path, xs);
    assert_eq!(
        totals.threats, 1,
        "members roll up into the on-disk container"
    );
    assert_eq!(totals.files, 5); // container + 3 members + nested member

    // scan_file: single rolled-up report.
    let r = e.scan_file(&x, &opts());
    assert_eq!(r.verdict, Verdict::Malicious);
    assert_eq!(r.path, xs);

    // Depth limit: with depth 1 the nested zip is not expanded.
    let mut o = opts();
    o.archive_max_depth = 1;
    let (reports, _) = collect(&e, &[x], &o);
    assert!(!reports
        .iter()
        .any(|r| r.path.ends_with("inner.zip!/eicar.com")));
}

#[test]
fn zip_bomb_guard() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let zeros = vec![0u8; 20 * 1024 * 1024];
    let bomb = f.data.join("bomb.zip");
    std::fs::write(&bomb, zip_bytes(&[("zeros.bin", &zeros, false)])).unwrap();
    assert!(std::fs::metadata(&bomb).unwrap().len() < 200_000);
    let r = e.scan_file(&bomb, &opts());
    assert_eq!(r.verdict, Verdict::Clean);
    assert!(
        r.error.as_deref().is_some_and(|x| x.contains("zip bomb")),
        "{r:?}"
    );

    // Entry-count limit, checked from the central directory before parsing it.
    let many: Vec<(String, Vec<u8>)> = (0..50)
        .map(|i| (format!("f{i}.txt"), vec![b'a'; 10]))
        .collect();
    let refs: Vec<(&str, &[u8], bool)> = many
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice(), false))
        .collect();
    let z = f.data.join("many.zip");
    std::fs::write(&z, zip_bytes(&refs)).unwrap();
    let mut o = opts();
    o.archive_max_entries = 10;
    let (reports, _) = collect(&e, &[z], &o);
    assert_eq!(reports.len(), 1);
    assert!(
        reports[0]
            .error
            .as_deref()
            .is_some_and(|x| x.contains("declares 50 entries")),
        "{:?}",
        reports[0]
    );
}

#[test]
fn tar_gz_members() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    {
        let mut t = tar::Builder::new(&mut gz);
        let mut h = tar::Header::new_gnu();
        h.set_size(EICAR.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        t.append_data(&mut h, "pkg/eicar.com", EICAR).unwrap();
        t.finish().unwrap();
    }
    let p = f.data.join("x.tar.gz");
    std::fs::write(&p, gz.finish().unwrap()).unwrap();
    let (reports, totals) = collect(&e, std::slice::from_ref(&p), &opts());
    let ps = p.to_string_lossy();
    assert!(
        reports
            .iter()
            .any(|r| r.path == format!("{ps}!/pkg/eicar.com") && r.verdict == Verdict::Malicious),
        "{reports:?}"
    );
    assert_eq!(totals.threats, 1);

    // Plain .gz of a single file.
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(EICAR).unwrap();
    let p = f.data.join("eicar.com.gz");
    std::fs::write(&p, gz.finish().unwrap()).unwrap();
    let (reports, _) = collect(&e, std::slice::from_ref(&p), &opts());
    assert!(reports.iter().any(|r| r.path.ends_with("eicar.com.gz!/eicar.com") && r.verdict == Verdict::Malicious), "{reports:?}");
}

#[test]
fn dmg_and_pkg_are_raw_scanned_off_macos() {
    if cfg!(target_os = "macos") {
        return;
    }
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let mut dmg = vec![0u8; 4096];
    let n = dmg.len();
    dmg[n - 512..n - 508].copy_from_slice(b"koly");
    let p = f.data.join("x.dmg");
    std::fs::write(&p, &dmg).unwrap();
    let r = e.scan_file(&p, &opts());
    assert_eq!(r.kind, FileKind::Dmg);
    assert!(r.error.as_deref().is_some_and(|x| x.contains("macOS-only")));
    let p = f.data.join("x.pkg");
    std::fs::write(&p, b"xar!\x00\x1c\x00\x01").unwrap();
    let r = e.scan_file(&p, &opts());
    assert_eq!(r.kind, FileKind::Pkg);
    let mut o = opts();
    o.expand_pkg = false;
    assert!(e.scan_file(&p, &o).error.is_none());
}

#[test]
fn walk_excludes_cache_risky_types_and_cancel() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let d = f.data.join("tree");
    std::fs::create_dir_all(d.join("sub")).unwrap();
    std::fs::create_dir_all(d.join("skip")).unwrap();
    std::fs::write(d.join("cat.jpg"), [0xff, 0xd8, 0xff, 0xe0, 1, 2, 3]).unwrap();
    std::fs::write(d.join("sub/run.sh"), b"#!/bin/sh\necho hi\n").unwrap();
    std::fs::write(d.join("sub/eicar.com"), EICAR).unwrap();
    std::fs::write(d.join("skip/eicar.com"), EICAR).unwrap();
    std::os::unix::fs::symlink(d.join("sub/eicar.com"), d.join("link.com")).unwrap();

    let mut o = opts();
    o.exclude_prefixes = vec![d.join("skip")];
    let (reports, totals) = collect(&e, std::slice::from_ref(&d), &o);
    assert_eq!(totals.files, 3, "{reports:?}"); // cat.jpg, run.sh, sub/eicar.com (symlink and excluded dir skipped)
    assert_eq!(totals.threats, 1);
    assert!(!totals.cancelled);

    // Second pass comes from the cache.
    let (reports, _) = collect(&e, std::slice::from_ref(&d), &o);
    assert!(reports.iter().all(|r| r.cached), "{reports:?}");
    // Modified file is rescanned.
    std::fs::write(d.join("sub/run.sh"), b"#!/bin/sh\necho changed\n").unwrap();
    let (reports, _) = collect(&e, std::slice::from_ref(&d), &o);
    assert!(reports
        .iter()
        .any(|r| r.path.ends_with("run.sh") && !r.cached));

    // Only risky types: the JPEG is neither hashed nor counted.
    o.only_risky_types = true;
    let (reports, totals) = collect(&e, std::slice::from_ref(&d), &o);
    assert_eq!(totals.files, 2, "{reports:?}");
    assert!(!reports.iter().any(|r| r.path.ends_with("cat.jpg")));

    // Non-recursive.
    o.only_risky_types = false;
    o.recursive = false;
    let (_, totals) = collect(&e, std::slice::from_ref(&d), &o);
    assert_eq!(totals.files, 1);

    // Directory summary through scan_file.
    let mut o2 = opts();
    o2.exclude_prefixes = vec![d.join("skip")];
    let r = e.scan_file(&d, &o2);
    assert_eq!(r.verdict, Verdict::Malicious);
    assert!(
        r.detections[0]
            .details
            .as_deref()
            .unwrap()
            .starts_with("in sub/eicar.com"),
        "{r:?}"
    );

    // Cancelled before start.
    let cancel = AtomicBool::new(true);
    let mut n = 0;
    let t = e.scan_paths(std::slice::from_ref(&d), &opts(), &cancel, &mut |_| n += 1);
    assert!(t.cancelled);
    assert_eq!(n, 0);

    // The Parabellum root itself is never scanned.
    std::fs::write(f.paths.cache_dir().join("eicar.com"), EICAR).unwrap();
    let (_, totals) = collect(&e, std::slice::from_ref(&f.paths.root), &opts());
    assert_eq!(totals.files, 0);

    // Missing path => error report.
    let (reports, totals) = collect(&e, &[f.data.join("missing")], &opts());
    assert_eq!(totals.errors, 1);
    assert!(reports[0].error.is_some());
}

#[test]
fn big_files_are_hash_only() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let p = f.data.join("big.bin");
    let mut content = EICAR.to_vec();
    content.resize(3 * 1024 * 1024, b' ');
    std::fs::write(&p, &content).unwrap();
    let mut o = opts();
    o.max_file_size = 1024 * 1024;
    let r = e.scan_file(&p, &o);
    assert_eq!(r.verdict, Verdict::Clean);
    assert_eq!(
        r.sha256.as_deref(),
        Some(hex::encode(sha(&content)).as_str())
    );
    assert!(r
        .error
        .as_deref()
        .is_some_and(|x| x.contains("hash check only")));
    assert_eq!(sha256_file(&p).unwrap(), hex::encode(sha(&content)));
}

#[test]
fn clamav_results_are_merged_before_delivery() {
    let f = fixture();
    let mut e = Engine::load(&f.paths, &Config::default()).unwrap();
    let bin = f.data.join("fake-clamscan");
    std::fs::write(
        &bin,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ClamAV 1.4.1/1/test'; exit 0; fi\n\
         seen=0\nfor a in \"$@\"; do if [ $seen = 1 ]; then case \"$a\" in *clam-bad*) echo \"$a: Osx.Trojan.Test-1 FOUND\";; *pua*) echo \"$a: PUA.Osx.Adware.Test FOUND\";; esac; fi; [ \"$a\" = \"--\" ] && seen=1; done\nexit 1\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    e.clamav = clamav::ClamAv::locate_in(std::iter::once(bin), &f.paths.clamav_db_dir(), None);
    assert!(e.stats().clamav_available);
    let d = f.data.join("c");
    std::fs::create_dir_all(&d).unwrap();
    for i in 0..300 {
        std::fs::write(d.join(format!("ok-{i}.txt")), format!("file {i}")).unwrap();
    }
    std::fs::write(d.join("clam-bad.bin"), b"payload").unwrap();
    std::fs::write(d.join("pua.bin"), b"adware").unwrap();
    std::fs::write(
        d.join("z.zip"),
        zip_bytes(&[("clam-bad-member.txt", b"x", false)]),
    )
    .unwrap();
    let mut o = opts();
    o.use_clamav = true;
    let (reports, totals) = collect(&e, std::slice::from_ref(&d), &o);
    assert_eq!(totals.files, 304);
    let bad = reports
        .iter()
        .find(|r| r.path.ends_with("clam-bad.bin"))
        .unwrap();
    assert_eq!(bad.verdict, Verdict::Malicious);
    assert_eq!(bad.detections[0].engine, DetectionEngine::ClamAv);
    assert_eq!(bad.detections[0].name, "Osx.Trojan.Test-1");
    let pua = reports
        .iter()
        .find(|r| r.path.ends_with("pua.bin"))
        .unwrap();
    assert_eq!(pua.verdict, Verdict::Suspicious);
    // Members are never passed to clamscan (it scans the container itself).
    let member = reports
        .iter()
        .find(|r| r.path.ends_with("z.zip!/clam-bad-member.txt"))
        .unwrap();
    assert_eq!(member.verdict, Verdict::Clean);
    assert_eq!(totals.threats, 2);
    // Single file API.
    assert_eq!(
        e.scan_file(&d.join("clam-bad.bin"), &o).verdict,
        Verdict::Malicious
    );
    assert_eq!(
        e.scan_file(&d.join("clam-bad.bin"), &opts()).verdict,
        Verdict::Clean
    );
}

#[test]
fn ml_flags_suspicious_only() {
    let f = fixture();
    install_bundle(&f.paths, &[], &[], |b| {
        std::fs::create_dir_all(b.join("ml")).unwrap();
        std::fs::write(
            b.join(pb_ml::MODEL_FILE),
            pb_ml::test_model_json("str_osascript", 0.5, -3.0, 3.0),
        )
        .unwrap();
        std::fs::write(
            b.join(pb_ml::MODEL_META_FILE),
            format!(
                r#"{{"features_version":{},"threshold":0.9,"version":"ml-test-1"}}"#,
                pb_ml::FEATURES_VERSION
            ),
        )
        .unwrap();
    });
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    assert_eq!(e.stats().ml_model_version.as_deref(), Some("ml-test-1"));
    let bad = pb_ml::testutil::MachOBuilder::new_arm64_execute()
        .cstrings(&["osascript -e 'do shell script'"])
        .build();
    let good = pb_ml::testutil::MachOBuilder::new_arm64_execute()
        .cstrings(&["hello"])
        .build();
    std::fs::write(f.data.join("bad"), &bad).unwrap();
    std::fs::write(f.data.join("good"), &good).unwrap();
    let r = e.scan_file(&f.data.join("bad"), &opts());
    assert_eq!(r.kind, FileKind::MachO);
    assert_eq!(r.verdict, Verdict::Suspicious, "{r:?}");
    assert_eq!(r.detections[0].engine, DetectionEngine::Ml);
    assert!(r.score > 0.9);
    assert_eq!(
        e.scan_file(&f.data.join("good"), &opts()).verdict,
        Verdict::Clean
    );
    let mut o = opts();
    o.use_ml = false;
    assert_eq!(e.scan_file(&f.data.join("bad"), &o).verdict, Verdict::Clean);
}

#[test]
fn realtime_latency_10mb() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let content: Vec<u8> = (0..10 * 1024 * 1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect();
    let p = f.data.join("random.bin");
    std::fs::write(&p, &content).unwrap();
    let o = ScanOptions {
        use_clamav: false,
        ..opts()
    };
    let _ = e.scan_file(
        &f.data.join("random.bin"),
        &ScanOptions {
            max_file_size: 1,
            ..o.clone()
        },
    ); // warm-up
    let t = Instant::now();
    let r = e.scan_file(&p, &o);
    let ms = t.elapsed().as_millis();
    println!(
        "scan of a 10 MB random file: {ms} ms (engine-reported {} ms, debug build: {})",
        r.duration_ms,
        cfg!(debug_assertions)
    );
    assert_eq!(r.verdict, Verdict::Clean);
    assert!(!r.cached);
    if cfg!(debug_assertions) {
        assert!(ms < 10_000);
    } else {
        assert!(ms < 200, "{ms} ms");
    }
}
