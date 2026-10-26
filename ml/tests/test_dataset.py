import math

from ml import dataset
from ml.features import FeatureRow, parse_rows

from .conftest import NAMES, synth_rows


def test_roundtrip_exact(tmp_path):
    rows = synth_rows(5, 5)
    p = tmp_path / "d.csv.gz"
    assert dataset.save(p, rows, NAMES) == 10
    back = {r.sha256: r for r in dataset.load(p)}
    for r in rows:
        b = back[r.sha256]
        assert b.label == r.label and b.features_version == 1
        assert all((math.isnan(x) and math.isnan(y)) or x == y for x, y in zip(r.features, b.features, strict=True))


def test_merge_dedupe_version_conflicts():
    a = FeatureRow("a" * 64, 0, 1, [0.0] * len(NAMES))
    a_new = FeatureRow("a" * 64, 0, 1, [1.0] * len(NAMES))
    old_version = FeatureRow("b" * 64, 1, 0, [0.0] * len(NAMES))
    short = FeatureRow("c" * 64, 1, 1, [0.0])
    conflict_0 = FeatureRow("d" * 64, 0, 1, [0.0] * len(NAMES))
    conflict_1 = FeatureRow("d" * 64, 1, 1, [0.0] * len(NAMES))
    rows, stats = dataset.merge([a, old_version, conflict_0], [a_new, short, conflict_1], 1, len(NAMES))
    assert [r.sha256 for r in rows] == ["a" * 64]
    assert rows[0].features[0] == 1.0  # new rows win
    assert stats == {"dropped_version": 1, "dropped_length": 1, "conflicts": 1}


def test_parse_pb_features_lines():
    text = (
        "warning: not a Mach-O\n"
        '{"sha256":"' + "e" * 64 + '","path":"/x","label":0,"features_version":1,"features":[1.5,null,0]}\n'
        "{broken json\n"
    )
    rows = parse_rows(text)
    assert len(rows) == 1 and rows[0].label == 0 and math.isnan(rows[0].features[1]) and rows[0].path == "/x"
