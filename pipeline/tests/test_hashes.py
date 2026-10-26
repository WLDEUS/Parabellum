import json
from datetime import UTC, datetime

from pipeline.hashes import (
    HashIndex,
    MalwareEntry,
    hsb_line,
    parse_mb_api,
    parse_mb_csv,
    read_digest_file,
    read_hsb,
    write_digest_file,
    write_hsb,
)

H1, H2, H3 = "a" * 64, "b" * 64, "c" * 64

MB_CSV = f'''################################################################
# MalwareBazaar recent malware samples (last 48 hours)         #
################################################################
# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"
"2026-10-25 10:00:00", "{H1}", "m", "s", "r", "x.exe", "exe", "application/x-dosexec", "AgentTesla", "n/a", "50", "i", "s", "t"
"2026-10-25 11:00:00", "{H2}", "m", "s", "r", "Installer", "macho", "application/x-mach-binary", "AMOS", "n/a", "n/a", "n/a", "s", "t"
"2026-10-25 12:00:00", "NOTAHASH", "m", "s", "r", "x", "exe", "x", "n/a", "n/a", "n/a", "n/a", "s", "t"
'''


def test_parse_mb_csv():
    rows = parse_mb_csv(MB_CSV)
    assert [r.sha256 for r in rows] == [H1, H2]
    assert rows[0].macos is False and rows[0].name is None
    assert rows[1].macos is True and rows[1].name == "AMOS"
    assert rows[1].first_seen == int(datetime(2026, 10, 25, 11, tzinfo=UTC).timestamp())


def test_parse_mb_api():
    doc = {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": H3,
                "file_size": 1234,
                "file_type": "macho",
                "signature": None,
                "tags": ["AtomicStealer", "macOS"],
                "first_seen": "2026-10-24 09:00:00",
            },
            {"sha256_hash": "bad"},
        ],
    }
    rows = parse_mb_api(json.dumps(doc).encode(), {"atomicstealer": "AMOS"})
    assert rows == [MalwareEntry(H3, int(datetime(2026, 10, 24, 9, tzinfo=UTC).timestamp()), 1234, "AMOS", True)]
    assert parse_mb_api(b'{"query_status": "no_results"}') == []


def test_index_window_cap_and_persistence(tmp_path):
    now = 1_800_000_000
    idx = HashIndex()
    idx.add(
        [MalwareEntry(H1, now - 400 * 86400), MalwareEntry(H2, now - 10), MalwareEntry(H3, now - 5, 99, "AMOS", True)]
    )
    idx.prune(now, window_days=365, max_hashes=10, max_macos=10)
    assert set(idx.index) == {H2, H3}
    idx.add([MalwareEntry("d" * 64, now)])
    idx.prune(now, window_days=365, max_hashes=2, max_macos=10)
    assert set(idx.index) == {H3, "d" * 64}  # newest kept
    assert idx.malware_set() == {H3, "d" * 64}
    idx.save(tmp_path)
    again = HashIndex.load(tmp_path)
    assert again.index == idx.index and again.macos == idx.macos


def test_digest_file_sorted_raw(tmp_path):
    p = tmp_path / "m.sha256"
    assert write_digest_file(p, [H3, H1, H1, "zz"]) == 2
    data = p.read_bytes()
    assert data == bytes.fromhex(H1) + bytes.fromhex(H3)
    assert read_digest_file(p) == {H1, H3}


def test_hsb(tmp_path):
    assert hsb_line(H1, None, "Atomic:Stealer") == f"{H1}:*:Parabellum.Osx.Atomic_Stealer:73"
    assert hsb_line(H1, 42, None) == f"{H1}:42:Parabellum.Osx.Malware:73"
    p = tmp_path / "x.hsb"
    write_hsb(p, {H2: (10, "AMOS"), H1: (None, None)})
    assert p.read_text().splitlines()[0].startswith(H1)
    assert read_hsb(p) == {H1: (None, None), H2: (10, "AMOS")}
