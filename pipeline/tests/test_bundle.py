import json
import tarfile

from pipeline.bundle import (
    Manifest,
    SourceInfo,
    Stats,
    deterministic_tar_gz,
    make_version,
    safe_extract,
    sanity_problems,
    sha256_hex,
    write_manifest,
)

NOW = 1_792_929_600  # 2026-10-25 12:00 UTC


def _stage(tmp_path):
    stage = tmp_path / "stage"
    (stage / "hashes").mkdir(parents=True)
    (stage / "dns").mkdir()
    (stage / "hashes" / "malware.sha256").write_bytes(bytes(32))
    (stage / "dns" / "ads.txt").write_text("ads.example.com\n")
    return stage


def test_version():
    assert make_version(NOW, None, None) == "2026.10.25.1"
    assert make_version(NOW, "2026.10.25.3", None) == "2026.10.25.4"
    assert make_version(NOW, "2026.10.24.9", 42) == "2026.10.25.42"
    assert make_version(NOW, "2026.10.25.50", 42) == "2026.10.25.51"  # never go backwards
    assert make_version(NOW, "2026.10.26.1", None) == "2026.10.26.2"  # clock skew


def test_manifest_digests_and_deterministic_tar(tmp_path):
    stage = _stage(tmp_path)
    m = Manifest(
        "2026.10.25.1",
        NOW,
        "0.1.0",
        [SourceInfo("s", "domains", "https://x", "MIT", 1, NOW)],
        stats=Stats(blocked_domains=1),
    )
    data = write_manifest(stage, m)
    doc = json.loads(data)
    assert doc["format"] == 1 and doc["version"] == "2026.10.25.1"
    assert doc["files"] == {
        "dns/ads.txt": sha256_hex(b"ads.example.com\n"),
        "hashes/malware.sha256": sha256_hex(bytes(32)),
    }
    assert "detection_rate" not in doc["stats"] and doc["sources"][0]["fresh"] is True
    a = deterministic_tar_gz(stage, tmp_path / "a.tar.gz")
    (stage / "dns" / "ads.txt").touch()  # mtime change must not matter
    b = deterministic_tar_gz(stage, tmp_path / "b.tar.gz")
    assert a == b
    with tarfile.open(tmp_path / "a.tar.gz") as tf:
        members = tf.getmembers()
        assert [x.name for x in members] == sorted(x.name for x in members)
        assert all(x.mtime == 0 and x.uid == 0 and x.gid == 0 for x in members)
        assert all(x.isfile() or x.isdir() for x in members)
    out = tmp_path / "x"
    safe_extract(tmp_path / "a.tar.gz", out)
    assert (out / "manifest.json").read_bytes() == data


def test_safe_extract_rejects_traversal(tmp_path):
    import io

    evil = tmp_path / "evil.tar.gz"
    with tarfile.open(evil, "w:gz") as tf:
        ti = tarfile.TarInfo("../escape")
        ti.size = 1
        tf.addfile(ti, io.BytesIO(b"x"))
    try:
        safe_extract(evil, tmp_path / "o")
        raise AssertionError("expected ValueError")
    except ValueError:
        pass
    assert not (tmp_path / "escape").exists()


def test_sanity_guard():
    prev = {"malware_hashes": 1000, "blocked_domains": 1000}
    assert sanity_problems(Stats(malware_hashes=900, blocked_domains=600, yara_rules=5), prev, 0.5) == []
    probs = sanity_problems(Stats(malware_hashes=400, blocked_domains=1000, yara_rules=5), prev, 0.5)
    assert len(probs) == 1 and "malware_hashes" in probs[0]
    assert sanity_problems(Stats(), None, 0.5) == ["bundle is empty (no hashes, no domains, no YARA rules)"]
