from __future__ import annotations

import gzip
import io
import json
import random
import sys
import zipfile
from pathlib import Path

from ml.domains import data
from ml.domains.train import main

FAKE = r"""#!PYTHON
import json, sys
NAMES = ["len", "digits", "kw", "hyphens"]
args = sys.argv[1:]
if "--names" in args:
    print(json.dumps(NAMES)); sys.exit(0)
if "--version-info" in args:
    print(json.dumps({"features_version": 1})); sys.exit(0)
for line in sys.stdin:
    d = line.strip()
    if not d or " " in d:
        continue
    f = [len(d), sum(c.isdigit() for c in d), float("login" in d or "verify" in d), d.count("-")]
    print(json.dumps({"domain": d, "registrable": d, "features_version": 1, "features": f}))
"""

DAY = 86_400
T0 = 1_762_000_000


def fake_binary(tmp: Path) -> Path:
    p = tmp / "pb-domain-features"
    p.write_text(FAKE.replace("#!PYTHON", f"#!{sys.executable}"))
    p.chmod(0o755)
    return p


def tranco_zip(path: Path, domains: list[str]) -> Path:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("top-1m.csv", "\n".join(f"{i + 1},{d}" for i, d in enumerate(domains)))
    path.write_bytes(buf.getvalue())
    return path


def setup(tmp: Path, n_pos: int, seed: int) -> tuple[Path, Path, Path]:
    rng = random.Random(seed)  # noqa: S311 (deterministic sampling, not security)
    state = tmp / f"state{seed}"
    (state / "domains").mkdir(parents=True)
    pos = [f"secure-login-{rng.randrange(10**6)}-verify.xyz" for _ in range(n_pos)]
    (state / "domains" / "phishing-filter.txt").write_text("\n".join(pos) + "\nNot A Domain\n")
    words = ["news", "shop", "maps", "mail", "cloud", "video", "games", "music", "photo", "bank"]
    neg = [f"{rng.choice(words)}{rng.choice(words)}{i}.com" for i in range(4000)]
    t = tranco_zip(tmp / f"t{seed}.zip", neg)
    s = tranco_zip(tmp / f"s{seed}.zip", [f"www.{d}" for d in neg[:1000]])
    return state, t, s


def args(binary: Path, state: Path, t: Path, s: Path, out: Path, now: int, *extra: str) -> list[str]:
    return [
        "--pb-domain-features",
        str(binary),
        "--state-dir",
        str(state),
        "--out",
        str(out),
        "--tranco-zip",
        str(t),
        "--tranco-sub-zip",
        str(s),
        "--neg-top",
        "1500",
        "--neg-tail",
        "1500",
        "--neg-sub",
        "500",
        "--popular",
        "50",
        "--min-pos",
        "200",
        "--min-neg",
        "1000",
        "--now",
        str(now),
        *extra,
    ]


def test_helpers():
    assert data.valid_domain("a.example.com") and not data.valid_domain("Example.com")
    assert not data.valid_domain("nodot") and not data.valid_domain("a..b")
    rows, added = data.merge_positives([data.Row("old.xyz", 1, 0)], {"old.xyz", "new.xyz"}, 5 * DAY + 10)
    assert added == 1 and {r.domain: r.first_seen for r in rows} == {"old.xyz": 0, "new.xyz": 5 * DAY}
    neg = data.negatives(
        ["evil.com", "good.com", "github.io"], ["www.evil.com", "a.good.com"], {"evil.com", "x.github.io"}, 3, 0, 2, 1
    )
    assert neg == ["a.good.com", "github.io", "good.com"]
    assert data.popular_list(["evil.com", "good.com"], {"evil.com"}, 5) == ["good.com"]


def test_min_data_guard(tmp_path):
    binary = fake_binary(tmp_path)
    state, t, s = setup(tmp_path, 50, 1)
    out = tmp_path / "out"
    assert main(args(binary, state, t, s, out, T0)) == 0
    d = json.loads((out / "decision.json").read_text())
    assert not d["trained"] and "not enough data" in d["reason"]
    assert d["n_pos"] == 50
    with gzip.open(out / "domains.csv.gz", "rt") as f:
        assert f.readline().strip() == "domain,label,first_seen"


def test_trains_exports_then_time_split(tmp_path):
    binary = fake_binary(tmp_path)
    state, t, s = setup(tmp_path, 600, 2)
    out1 = tmp_path / "day1"
    assert main(args(binary, state, t, s, out1, T0)) == 0
    d1 = json.loads((out1 / "decision.json").read_text())
    assert d1["trained"] and d1["promoted"], d1
    assert d1["time_split"] is False
    model = out1 / "model"
    for name in ("domain_model.json", "domain_model_meta.json", "domain_brands.txt", "domain_top.txt"):
        assert (model / name).is_file(), name
    meta = json.loads((model / "domain_model_meta.json").read_text())
    assert 0 < meta["threshold"] <= meta["block_threshold"] <= 1
    assert meta["features_version"] == 1 and len(meta["brands_sha256"]) == 64
    assert meta["metrics"]["fpr_at_threshold"] <= 0.0005
    assert len((model / "domain_top.txt").read_text().split()) == 50

    # Three weeks later, new campaigns: holdout = recent positives, compared with the current model.
    state2, _, _ = setup(tmp_path, 400, 3)
    out2 = tmp_path / "day2"
    rc = main(
        args(
            binary,
            state2,
            t,
            s,
            out2,
            T0 + 21 * DAY,
            "--dataset-in",
            str(out1 / "domains.csv.gz"),
            "--metrics-in",
            str(out1 / "metrics.jsonl"),
            "--current-model",
            str(model),
        )
    )
    assert rc == 0
    d2 = json.loads((out2 / "decision.json").read_text())
    assert d2["time_split"] is True and d2["n_pos"] == 1000
    assert d2["current_note"] == "ok" and d2["current"] is not None
    assert len((out2 / "metrics.jsonl").read_text().splitlines()) == 2
