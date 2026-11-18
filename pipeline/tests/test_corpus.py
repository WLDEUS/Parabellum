"""Clean corpus availability (review finding M2): rate-limited bottle resolution must not shrink it."""

import hashlib
import io
import json
import tarfile

from pipeline.corpus import BOTTLE_INDEX, CorpusSpec, ensure_corpus, expected_entries, spec_fingerprint
from pipeline.fpgate import corpus_problems

from .conftest import MACHO, FakeHttp

API = "https://formulae.brew.sh/api/formula/{}.json"


def _tar(name: str, data: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _routes(formula: str, data: bytes) -> dict[str, bytes]:
    blob = _tar(f"{formula}/bin/{formula}", data)
    sha = hashlib.sha256(blob).hexdigest()
    url = f"https://ghcr.io/v2/homebrew/core/{formula}/blobs/sha256:{sha}"
    doc = {"versions": {"stable": "1.0"}, "bottle": {"stable": {"files": {"all": {"url": url, "sha256": sha}}}}}
    return {API.format(formula): json.dumps(doc).encode(), url: blob}


def test_unresolvable_bottle_reuses_the_cached_one(tmp_path):
    spec = CorpusSpec(version=1, homebrew_formulae=["jq", "wget"], bottle_tags=["all"])
    cache = tmp_path / "cache"
    http = FakeHttp({**_routes("jq", MACHO + b"jq"), **_routes("wget", MACHO + b"wget")})
    assert len(ensure_corpus(spec, cache, http)) == 2
    assert set(json.loads((cache / BOTTLE_INDEX).read_text())) == {"jq", "wget"}

    # formulae.brew.sh rate-limits us: both entries still come from the cache, nothing is pruned.
    http.routes = {}
    items = ensure_corpus(spec, cache, http)
    assert sorted(i.name for i in items) == ["brew:jq-1.0-all", "brew:wget-1.0-all"]
    assert len(list((cache / "dl").iterdir())) == 2


def test_unresolvable_bottle_without_index_prunes_nothing(tmp_path):
    spec = CorpusSpec(version=1, homebrew_formulae=["jq"], bottle_tags=["all"])
    cache = tmp_path / "cache"
    ensure_corpus(spec, cache, FakeHttp(_routes("jq", MACHO + b"jq")))
    (cache / BOTTLE_INDEX).unlink()  # caches written before the index existed
    assert ensure_corpus(spec, cache, FakeHttp()) == []
    assert len(list((cache / "dl").iterdir())) == 1  # kept for the next run


def test_corpus_problems():
    spec = CorpusSpec(version=1, homebrew_formulae=[f"f{i}" for i in range(10)])
    fp = spec_fingerprint(spec)
    assert expected_entries(spec) == 10
    cur = {"spec": fp, "corpus_entries": 9, "files_scanned": 1000}
    assert corpus_problems(10, cur, [], {"spec": fp, "files_scanned": 1050}, 0.9) == []
    low = corpus_problems(10, {**cur, "corpus_entries": 8}, [], None, 0.9)
    assert len(low) == 1 and "8/10" in low[0]
    drop = corpus_problems(10, {**cur, "files_scanned": 500}, [], {"spec": fp, "files_scanned": 1000}, 0.9)
    assert len(drop) == 1 and "500" in drop[0]
    # Another corpus spec: scanned-file counts are not comparable.
    assert corpus_problems(10, {**cur, "files_scanned": 500}, [], {"spec": "x", "files_scanned": 1000}, 0.9) == []
    assert "could not scan" in corpus_problems(10, cur, ["tool:bin/x"], None, 0.9)[0]
