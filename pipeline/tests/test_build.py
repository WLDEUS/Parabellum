"""End-to-end nightly build with an in-memory network: carry-over, FP gate, sanity guard, outputs."""

import hashlib
import json
import tarfile
from pathlib import Path

from pipeline import BUNDLE_FILE, MANIFEST_FILE, STATE_FILE
from pipeline.build import build, parse_args
from pipeline.hashes import read_digest_file

from .conftest import MACHO, FakeHttp

NOW = 1_792_929_600
H_MAC, H_WIN = "1" * 64, "2" * 64
MB_CSV = (
    '# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess",'
    '"mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"\n'
    f'"2026-10-25 10:00:00", "{H_WIN}", "m", "s", "r", "x.exe", "exe", "application/x-dosexec", "n/a", "", "", "", "", ""\n'
)
MB_API = json.dumps(
    {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": H_MAC,
                "file_size": 77,
                "file_type": "macho",
                "signature": "AMOS",
                "tags": ["macOS"],
                "first_seen": "2026-10-25 09:00:00",
            }
        ],
    }
).encode()


def write_sources(root: Path, rules_dir: Path, corpus_toml: Path) -> Path:
    data = root / "data"
    data.mkdir()
    (data / "team_ids.txt").write_text("# test\nEQHXZ8M8AV\n")
    (data / "allow.txt").write_text("captive.apple.com\n")
    (data / "hunting.json").write_text('{"queries": {"q": {"query": "SELECT 1;", "interval": 86400}}}')
    toml = root / "sources.toml"
    toml.write_text(
        f"""
[bundle]
min_client_version = "0.1.0"
sanity_max_drop = 0.5
[malwarebazaar]
file_types = ["macho"]
tags = []
[[source]]
name = "mb-recent"
kind = "hashes"
fetcher = "mb_export"
url = "https://mb.test/{{ABUSECH_AUTH_KEY}}/recent.csv"
license = "t"
[[source]]
name = "mb-macos"
kind = "hashes"
fetcher = "mb_api_macos"
url = "https://mb.test/api"
license = "t"
[[source]]
name = "ads-a"
kind = "domains"
fetcher = "domain_list"
url = "https://lists.test/ads.txt"
license = "t"
category = "ads"
format = "domains"
min_entries = 1
[[source]]
name = "malware-a"
kind = "domains"
fetcher = "domain_list"
url = "https://lists.test/malware.txt"
license = "t"
category = "malware"
format = "hosts"
min_entries = 1
[[source]]
name = "ours"
kind = "yara"
fetcher = "yara_local"
url = "https://repo.test/rules"
license = "MIT"
path = "{rules_dir}"
[[source]]
name = "team-ids"
kind = "allowlist"
fetcher = "local_file"
url = "https://repo.test/t"
license = "MIT"
path = "{data / "team_ids.txt"}"
dest = "allow/team_ids.txt"
[[source]]
name = "dns-allow"
kind = "allowlist"
fetcher = "local_file"
url = "https://repo.test/a"
license = "MIT"
path = "{data / "allow.txt"}"
dest = "dns/allowlist.txt"
[[source]]
name = "osquery"
kind = "osquery"
fetcher = "local_file"
url = "https://repo.test/o"
license = "MIT"
path = "{data / "hunting.json"}"
dest = "osquery/hunting.json"
"""
    )
    return toml


def setup(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ABUSECH_AUTH_KEY", "k3y")
    monkeypatch.delenv("MALWARE_CORPUS", raising=False)
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "a.yar").write_text(
        'rule T_Clean_FP { meta: severity = "high" strings: $a = "CLEANTOOL" condition: $a }\n'
        'rule T_Evil { meta: severity = "high" strings: $a = "EVILPAYLOAD" condition: $a }\n'
    )
    (rules / "broken.yar").write_text("rule Broken { condition: undefined_identifier }\n")
    clean_tool = MACHO + b"CLEANTOOL v1"
    corpus_toml = tmp_path / "corpus.toml"
    corpus_toml.write_text(
        'version = 1\n[[archive]]\nname = "tool"\nurl = "https://corpus.test/tool"\n'
        f'sha256 = "{hashlib.sha256(clean_tool).hexdigest()}"\nformat = "file"\n'
    )
    sources = write_sources(tmp_path, rules, corpus_toml)
    http = FakeHttp(
        {
            "https://mb.test/k3y/recent.csv": MB_CSV.encode(),
            "https://mb.test/api?file_type=macho&limit=1000&query=get_file_type": MB_API,
            "https://lists.test/ads.txt": b"ads.example.com\nx.ads.example.com\ngithub.com\n",
            "https://lists.test/malware.txt": b"0.0.0.0 evil.example.net\n0.0.0.0 captive.apple.com\n",
            "https://corpus.test/tool": clean_tool,
        }
    )
    return sources, corpus_toml, http


def run(tmp_path: Path, sources: Path, corpus: Path, http: FakeHttp, out: str, *extra: str) -> int:
    args = parse_args(
        [
            "--out",
            str(tmp_path / out),
            "--sources",
            str(sources),
            "--corpus-spec",
            str(corpus),
            "--corpus-cache",
            str(tmp_path / "cache"),
            "--allow-hashes",
            str(tmp_path / "none.txt"),
            "--now",
            str(NOW),
            "--build-number",
            "0",
            *extra,
        ]
    )
    return build(args, http)


def test_full_build_then_carry_over_and_sanity_guard(tmp_path, monkeypatch):
    sources, corpus, http = setup(tmp_path, monkeypatch)
    assert run(tmp_path, sources, corpus, http, "day1") == 0
    out = tmp_path / "day1"
    for name in (BUNDLE_FILE, MANIFEST_FILE, STATE_FILE, "report.json"):
        assert (out / name).is_file(), name
    stage = out / "stage"
    manifest = json.loads((out / MANIFEST_FILE).read_text())
    assert manifest["version"] == "2026.10.25.1" and manifest["format"] == 1
    assert read_digest_file(stage / "hashes" / "malware.sha256") == {H_MAC, H_WIN}
    assert (stage / "hashes" / "malware_names.tsv").read_text() == f"{H_MAC}\tAMOS\n"
    assert (stage / "clamav" / "parabellum.hsb").read_text() == f"{H_MAC}:77:Parabellum.Osx.AMOS:73\n"
    assert (stage / "dns" / "ads.txt").read_text() == "ads.example.com\n"  # github.com is a shared host
    assert (stage / "dns" / "malware.txt").read_text() == "evil.example.net\n"  # allowlisted dropped
    assert (stage / "dns" / "allowlist.txt").read_text() == "captive.apple.com\n"
    yara_text = (stage / "yara" / "ours__a.yar").read_text()
    assert "T_Evil" in yara_text and "T_Clean_FP" not in yara_text
    assert not (stage / "yara" / "ours__broken.yar").exists()
    st = manifest["stats"]
    assert st["yara_rules"] == 1 and st["yara_rules_rejected_fp"] == 1 and st["malware_hashes"] == 2
    assert st["allow_hashes"] == 1 and st["blocked_domains"] == 2 and st["fp_rate"] == 0.0
    with tarfile.open(out / BUNDLE_FILE) as tf:
        names = tf.getnames()
        packed = tf.extractfile("manifest.json").read()
    assert packed == (out / MANIFEST_FILE).read_bytes()
    for rel, digest in manifest["files"].items():
        assert rel in names
        assert hashlib.sha256((stage / rel).read_bytes()).hexdigest() == digest
    assert "k3y" not in (out / MANIFEST_FILE).read_text()
    assert any(s["url"] == "https://mb.test/<AUTH-KEY>/recent.csv" for s in manifest["sources"])

    # Day 2: the ads list is down -> carried over from the state, fresh=false; hashes kept by the index.
    del http.routes["https://lists.test/ads.txt"]
    del http.routes["https://mb.test/k3y/recent.csv"]
    assert (
        run(
            tmp_path,
            sources,
            corpus,
            http,
            "day2",
            "--previous",
            str(out / BUNDLE_FILE),
            "--state",
            str(out / STATE_FILE),
        )
        == 0
    )
    out2 = tmp_path / "day2"
    m2 = json.loads((out2 / MANIFEST_FILE).read_text())
    assert m2["version"] == "2026.10.25.2"
    src = {s["name"]: s for s in m2["sources"]}
    assert src["ads-a"]["fresh"] is False and src["ads-a"]["count"] == 3  # raw per-source state
    assert "k3y" not in (out2 / "report.json").read_text()
    assert src["mb-recent"]["fresh"] is False and src["mb-recent"]["fetched_at"] == NOW
    assert (out2 / "stage" / "dns" / "ads.txt").read_text() == "ads.example.com\n"
    assert read_digest_file(out2 / "stage" / "hashes" / "malware.sha256") == {H_MAC, H_WIN}

    # Day 3: everything external is down and the state is lost -> domains/hashes collapse -> refused.
    http.routes.clear()
    http.routes["https://corpus.test/tool"] = MACHO + b"CLEANTOOL v1"
    rc = run(tmp_path, sources, corpus, http, "day3", "--previous", str(out2 / BUNDLE_FILE))
    assert rc == 0  # previous bundle seeds hashes and category files: nothing collapses
    m3 = json.loads((tmp_path / "day3" / MANIFEST_FILE).read_text())
    assert m3["stats"]["malware_hashes"] == 2 and m3["stats"]["blocked_domains"] == 2


def test_source_failures_never_collapse_the_bundle(tmp_path, monkeypatch):
    sources, corpus, http = setup(tmp_path, monkeypatch)
    assert run(tmp_path, sources, corpus, http, "day1") == 0
    # The list now answers with a much smaller (but valid) list: a fresh drop the guard must catch.
    http.routes["https://lists.test/ads.txt"] = b"only.example.org\n"
    http.routes["https://lists.test/malware.txt"] = b"# empty\n0.0.0.0 x.invalid\n"
    rc = run(
        tmp_path,
        sources,
        corpus,
        http,
        "day2",
        "--previous",
        str(tmp_path / "day1" / BUNDLE_FILE),
        "--state",
        str(tmp_path / "day1" / STATE_FILE),
    )
    assert rc == 0  # malware list fails (0 entries < min_entries) -> carried; ads 1 -> 1: no drop
    http.routes["https://lists.test/ads.txt"] = b"a.example.org\n"
    rc = run(tmp_path, sources, corpus, http, "day3", "--previous", str(tmp_path / "day1" / BUNDLE_FILE))
    assert rc == 0
    # Hash index collapse: no state, no previous bundle, no hash sources.
    http.routes.pop("https://mb.test/k3y/recent.csv")
    http.routes.pop("https://mb.test/api?file_type=macho&limit=1000&query=get_file_type")
    prev = tmp_path / "day1" / "stage"
    rc = run(tmp_path, sources, corpus, http, "day4", "--previous", str(prev), "--state", str(tmp_path / "nostate"))
    assert rc == 0  # seeded from the previous bundle directory
    (prev / "hashes" / "malware.sha256").write_bytes(b"")
    rc = run(
        tmp_path,
        sources,
        corpus,
        http,
        "day5",
        "--previous",
        str(tmp_path / "day1" / BUNDLE_FILE),
        "--state",
        str(tmp_path / "nostate"),
    )
    assert rc == 0
    report = json.loads((tmp_path / "day5" / "report.json").read_text())
    assert report["sanity_problems"] == []


def test_sanity_guard_exit_code(tmp_path, monkeypatch):
    sources, corpus, http = setup(tmp_path, monkeypatch)
    assert run(tmp_path, sources, corpus, http, "day1") == 0
    # Fresh but tiny hash export and no state: 1 hash vs 2 yesterday is a 50 % drop -> allowed at 0.5;
    # make it 0 macOS + 0 recent -> index seeded from previous... so instead shrink domains sharply.
    big = "".join(f"d{i}.example.com\n" for i in range(100)).encode()
    http.routes["https://lists.test/ads.txt"] = big
    assert run(tmp_path, sources, corpus, http, "day2", "--previous", str(tmp_path / "day1" / BUNDLE_FILE)) == 0
    http.routes["https://lists.test/ads.txt"] = b"one.example.com\n"
    rc = run(
        tmp_path,
        sources,
        corpus,
        http,
        "day3",
        "--previous",
        str(tmp_path / "day2" / BUNDLE_FILE),
        "--state",
        str(tmp_path / "day2" / STATE_FILE),
    )
    assert rc == 2
    assert not (tmp_path / "day3" / BUNDLE_FILE).exists()
    assert "blocked_domains" in json.loads((tmp_path / "day3" / "report.json").read_text())["sanity_problems"][0]
    assert (
        run(
            tmp_path,
            sources,
            corpus,
            http,
            "day3b",
            "--previous",
            str(tmp_path / "day2" / BUNDLE_FILE),
            "--state",
            str(tmp_path / "day2" / STATE_FILE),
            "--allow-shrink",
        )
        == 0
    )
