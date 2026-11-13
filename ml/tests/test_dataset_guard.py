"""A failed ml-dataset download must never wipe the accumulated features (review finding H1)."""

import gzip
import json
import sys
import textwrap

import pytest

from ml import dataset, train

from .conftest import NAMES, synth_rows


def _fake_pb_features(tmp_path):
    fake = tmp_path / "pb-features"
    fake.write_text(
        textwrap.dedent(f"""\
        #!{sys.executable}
        import json, sys
        if sys.argv[1:] == ["--names"]:
            print(json.dumps({NAMES!r}))
        """)
    )
    fake.chmod(0o755)
    return fake


def _jsonl(path, rows):
    path.write_text(
        "".join(
            json.dumps({"sha256": r.sha256, "label": 0, "features_version": 1, "features": r.features}) + "\n"
            for r in rows
        )
    )
    return path


def _run(tmp_path, out, *extra):
    args = ["--pb-features", str(_fake_pb_features(tmp_path)), "--out", str(tmp_path / out), "--no-malware"]
    return train.run(train.parse_args([*args, *extra]))


@pytest.fixture
def week1(tmp_path):
    """A published week: 50 clean rows, decision.json with n_rows, metrics.jsonl."""
    extra = _jsonl(tmp_path / "extra.jsonl", synth_rows(0, 50, seed=3))
    assert _run(tmp_path, "w1", "--extra-clean", str(extra), "--now", "1") == 0
    d = json.loads((tmp_path / "w1" / "decision.json").read_text())
    assert d["n_rows"] == 50 and d["prev_rows"] is None
    return tmp_path / "w1"


def _week2(tmp_path, w1, dataset_in, *extra):
    # Five new clean rows this week, so the old code would have trained and published.
    new = _jsonl(tmp_path / "new.jsonl", synth_rows(0, 5, seed=9))
    return _run(
        tmp_path,
        "w2",
        "--dataset-in",
        str(dataset_in),
        "--metrics-in",
        str(w1 / "metrics.jsonl"),
        "--decision-in",
        str(w1 / "decision.json"),
        "--extra-clean",
        str(new),
        *extra,
    )


def test_normal_week_records_previous_rows(tmp_path, week1):
    assert _week2(tmp_path, week1, week1 / "dataset.csv.gz") == 0
    d = json.loads((tmp_path / "w2" / "decision.json").read_text())
    assert d["n_rows"] == 55 and d["prev_rows"] == 50


def test_missing_dataset_refuses(tmp_path, week1):
    # The download failed (or was skipped): training on nothing would publish an empty dataset.
    assert _week2(tmp_path, week1, tmp_path / "missing.csv.gz") == 1
    assert not (tmp_path / "w2" / "dataset.csv.gz").exists()
    assert not (tmp_path / "w2" / "decision.json").exists()


def test_damaged_dataset_refuses(tmp_path, week1):
    bad = tmp_path / "bad.csv.gz"
    with gzip.open(bad, "wt") as f:
        f.write("not,the,header\n")
    assert _week2(tmp_path, week1, bad) == 1
    # Half the rows unreadable (cut lines) is caught too.
    with gzip.open(week1 / "dataset.csv.gz", "rt") as f:
        lines = f.read().splitlines()
    half = tmp_path / "half.csv.gz"
    with gzip.open(half, "wt") as f:
        f.write("\n".join(lines[:20]) + "\n")
    assert _week2(tmp_path, week1, half) == 1


def test_missing_metrics_refuses(tmp_path, week1):
    (week1 / "metrics.jsonl").unlink()
    assert _week2(tmp_path, week1, week1 / "dataset.csv.gz") == 1


def test_explicit_override_publishes_the_smaller_dataset(tmp_path, week1):
    extra = _jsonl(tmp_path / "extra2.jsonl", synth_rows(0, 10, seed=4))
    rc = _run(
        tmp_path,
        "w2",
        "--decision-in",
        str(week1 / "decision.json"),
        "--extra-clean",
        str(extra),
        "--allow-dataset-shrink",
    )
    assert rc == 0
    d = json.loads((tmp_path / "w2" / "decision.json").read_text())
    assert d["n_rows"] == 10 and d["prev_rows"] == 50


def test_shrink_problem_and_previous_rows(tmp_path):
    assert dataset.shrink_problem(None, 0, 0) is None
    assert dataset.shrink_problem(100, 100, 100) is None
    assert "readable rows" in dataset.shrink_problem(100, 0, 0)
    assert "shrink" in dataset.shrink_problem(100, 100, 0)  # features_version change dropped everything
    assert dataset.shrink_problem(100, 100, 98, conflicts=2) is None  # label conflicts are expected
    p = tmp_path / "d.json"
    assert dataset.previous_rows(p) is None
    p.write_text('{"n_pos": 3, "n_neg": 4}')
    assert dataset.previous_rows(p) == 7
    p.write_text('{"trained": false}')
    assert dataset.previous_rows(p) is None
    p.write_text('{"n_rows": 9, "n_pos": 3, "n_neg": 4}')
    assert dataset.previous_rows(p) == 9
    p.write_text('{"n_rows": ')
    with pytest.raises(ValueError):
        dataset.previous_rows(p)
