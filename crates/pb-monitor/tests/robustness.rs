//! Robustness of the parsers that read attacker-influenced input (eslogger lines carry file and process
//! names an attacker chooses; plists, manifests and tool outputs describe items an attacker can drop).
//!
//! A small deterministic mutational fuzzer, no extra dependency: each parser gets the seed fixtures, then
//! `PB_FUZZ_ITERS` (default 3 000) mutated inputs (bit flips, byte insertions / deletions, splices,
//! truncations, boundary bytes, random blobs). A parser may return an error but must never panic or hang:
//! a panic in the daemon's monitor stops that watcher (now: restarts the daemon), which is a way for a
//! malicious file to switch protection off.
//!
//! Longer local run: `PB_FUZZ_ITERS=200000 cargo test -p pb-monitor --release --test robustness`.

use pb_monitor::eslogger;
use pb_monitor::persistence::parsers;
use std::path::Path;
use std::time::{Duration, Instant};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const INTERESTING: &[u8] = &[
    0x00, 0xff, 0x7f, 0x80, b'"', b'\\', b'<', b'>', b'{', b'}', b'[', b']', b'\n', b'%', b'&',
    b';',
];

fn mutate(rng: &mut Rng, seeds: &[Vec<u8>], out: &mut Vec<u8>) {
    out.clear();
    out.extend_from_slice(&seeds[rng.below(seeds.len())]);
    for _ in 0..=rng.below(8) {
        let len = out.len();
        match rng.below(8) {
            0 if len > 0 => {
                let i = rng.below(len);
                out[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(len + 1);
                out.insert(i, INTERESTING[rng.below(INTERESTING.len())]);
            }
            2 if len > 0 => {
                let i = rng.below(len);
                let n = rng.below(len - i).min(64) + 1;
                out.drain(i..(i + n).min(len));
            }
            3 if len > 0 => out.truncate(rng.below(len)),
            4 => {
                // Splice a slice of another seed.
                let other = &seeds[rng.below(seeds.len())];
                if !other.is_empty() {
                    let a = rng.below(other.len());
                    let b = a + rng.below(other.len() - a);
                    let at = rng.below(len + 1);
                    out.splice(at..at, other[a..b].iter().copied());
                }
            }
            5 if len > 0 => {
                // Repeat a chunk (deep nesting, long fields).
                let a = rng.below(len);
                let b = (a + rng.below(32) + 1).min(len);
                let chunk = out[a..b].to_vec();
                for _ in 0..rng.below(64) {
                    out.extend_from_slice(&chunk);
                }
            }
            6 => {
                let n = rng.below(256);
                out.extend((0..n).map(|_| rng.next() as u8));
            }
            _ => {
                // Overwrite with a random byte.
                if len > 0 {
                    let i = rng.below(len);
                    out[i] = rng.next() as u8;
                }
            }
        }
        if out.len() > 1 << 20 {
            out.truncate(1 << 20);
        }
    }
}

fn iterations() -> usize {
    std::env::var("PB_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000)
}

fn fixture(name: &str) -> Vec<u8> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// Runs `f` on the seeds then on mutated inputs; fails on a panic or on one input taking over 2 s.
fn fuzz(name: &str, seed: u64, seeds: Vec<Vec<u8>>, f: impl Fn(&[u8])) {
    let mut rng = Rng(seed ^ 0x9E37_79B9_7F4A_7C15);
    let mut buf = Vec::new();
    for i in 0..seeds.len() + iterations() {
        if i < seeds.len() {
            buf.clone_from(&seeds[i]);
        } else {
            mutate(&mut rng, &seeds, &mut buf);
        }
        let start = Instant::now();
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&buf)));
        let took = start.elapsed();
        if r.is_err() {
            let dump = std::env::temp_dir().join(format!("pb-fuzz-{name}-{i}.bin"));
            let _ = std::fs::write(&dump, &buf);
            panic!("{name}: panic on input #{i} (saved to {})", dump.display());
        }
        assert!(
            took < Duration::from_secs(2),
            "{name}: input #{i} took {took:?}"
        );
    }
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn eslogger_lines() {
    let seeds: Vec<Vec<u8>> = fixture("eslogger.jsonl")
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    fuzz("eslogger", 1, seeds, |b| {
        let _ = eslogger::parse_line(b);
    });
}

#[test]
fn launchd_and_generic_plists() {
    let seeds = vec![
        fixture("launchd_agent.plist"),
        fixture("launchd_daemon.plist"),
        fixture("known_networks.plist"),
    ];
    fuzz("launchd_plist", 2, seeds, |b| {
        let _ = parsers::parse_launchd_plist(b);
        let _ = parsers::parse_plist(b);
        let _ = parsers::parse_bundle_info(b);
        let _ = parsers::parse_login_hooks(b);
    });
}

#[test]
fn configuration_profiles() {
    fuzz("profiles", 3, vec![fixture("profiles_show.xml")], |b| {
        let _ = parsers::parse_profiles_xml(b);
    });
}

#[test]
fn tool_outputs() {
    let seeds = vec![
        fixture("sfltool_dumpbtm.txt"),
        fixture("systemextensionsctl_list.txt"),
        fixture("pluginkit_safari.txt"),
    ];
    fuzz("tool_outputs", 4, seeds, |b| {
        let t = text(b);
        let _ = parsers::parse_sfltool_dumpbtm(&t);
        let _ = parsers::parse_systemextensionsctl(&t);
        let _ = parsers::parse_pluginkit(&t);
    });
}

#[test]
fn chrome_extension_manifests() {
    let seeds = vec![
        br#"{"manifest_version":3,"name":"X","version":"1.0","permissions":["tabs","<all_urls>"],"host_permissions":["*://*/*"],"background":{"service_worker":"bg.js"}}"#.to_vec(),
        br#"{"name":"__MSG_appName__","version":"2","content_scripts":[{"matches":["<all_urls>"],"js":["a.js"]}]}"#.to_vec(),
    ];
    fuzz("chrome_manifest", 5, seeds, |b| {
        let _ = parsers::parse_chrome_manifest(b);
    });
}
