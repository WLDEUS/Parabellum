import itertools
import math

import numpy as np

from ml import dataset, model
from ml.features import FeatureRow

from .conftest import NAMES, synth_rows


def test_dataset_metadata_roundtrip_and_old_header(tmp_path):
    rows = synth_rows(5, 5, dated=True)
    p = tmp_path / "d.csv.gz"
    dataset.save(p, rows, NAMES)
    back = {r.sha256: r for r in dataset.load(p)}
    for r in rows:
        assert back[r.sha256].first_seen == r.first_seen and back[r.sha256].family == r.family
    # File written before the first_seen / family columns existed.
    import gzip

    old = tmp_path / "old.csv.gz"
    with gzip.open(old, "wt") as f:
        f.write("sha256,label,features_version," + ",".join(NAMES) + "\n")
        f.write("a" * 64 + ",1,1," + ",".join(["0.5"] * len(NAMES)) + "\n")
    (r,) = dataset.load(old)
    assert r.label == 1 and r.first_seen == 0 and r.family == "" and len(r.features) == len(NAMES)


def test_merge_keeps_earliest_first_seen_and_stale_positives():
    a_old = FeatureRow("a" * 64, 1, 1, [0.0] * len(NAMES), first_seen=100, family="AMOS")
    a_new = FeatureRow("a" * 64, 1, 2, [1.0] * len(NAMES), first_seen=0)
    rows, _ = dataset.merge([a_old], [a_new], 2, len(NAMES))
    assert rows[0].first_seen == 100 and rows[0].family == "AMOS" and rows[0].features_version == 2
    stale = dataset.stale_positives([a_old, FeatureRow("b" * 64, 0, 1, [0.0])], 2)
    assert [r.sha256 for r in stale] == ["a" * 64]


def test_dedupe_collapses_identical_vectors():
    v = [0.25] * len(NAMES)
    rows = [
        FeatureRow("b" * 64, 1, 1, v, first_seen=200),
        FeatureRow("c" * 64, 1, 1, v, first_seen=100),
        FeatureRow("d" * 64, 0, 1, [0.5] * len(NAMES)),
        FeatureRow("e" * 64, 1, 1, [0.5] * len(NAMES)),  # same vector, other label: ambiguous
        FeatureRow("f" * 64, 0, 1, [0.75] * len(NAMES)),
    ]
    out, stats = model.dedupe(rows)
    assert [r.sha256 for r in out] == ["c" * 64, "f" * 64]  # earliest kept
    assert stats == {"duplicates": 1, "ambiguous": 2}


def test_time_split_and_group_buckets():
    rows = synth_rows(400, 2500, dated=True)
    tr, va, ho, info = model.split_with_info(rows)
    newest = max(r.first_seen for r in tr + va if r.label == 1)
    assert all(r.first_seen > newest for r in ho if r.label == 1)  # holdout strictly newer
    assert info.holdout_since == min(r.first_seen for r in ho if r.label == 1)
    assert sum(r.label for r in ho) == 80 and sum(r.label for r in va) == 60
    # A clean package never straddles two splits.
    where = {}
    for name, part in (("tr", tr), ("va", va), ("ho", ho)):
        for r in part:
            if r.label == 0:
                assert where.setdefault(r.family, name) == name
    # Stable whatever the input order.
    again = model.split_with_info(list(reversed(rows)))
    assert {r.sha256 for r in again[2]} == {r.sha256 for r in ho}


def test_sample_weights_balance_classes_and_families():
    rows = synth_rows(100, 300, dated=True)
    rows += [FeatureRow(f"{i:064x}", 1, 1, [0.0] * len(NAMES), family="BIG") for i in range(400)]
    w = model.sample_weights(rows)
    y = np.array([r.label for r in rows])
    assert math.isclose(w[y == 1].sum(), w[y == 0].sum())
    big = np.array([r.family == "BIG" for r in rows])
    # 400 rows of one family weigh less than the 100 rows spread over 12 families.
    assert w[big].sum() < w[(y == 1) & ~big].sum()


def test_average_precision_and_tpr_at_fpr():
    y = np.array([1, 0, 1, 0])
    s = np.array([0.9, 0.8, 0.7, 0.1], dtype=np.float32)
    assert math.isclose(model.average_precision(y, s), (1.0 + 2 / 3) / 2)
    assert math.isclose(model.average_precision(np.array([1, 1, 0]), np.array([0.5, 0.5, 0.1])), 1.0)
    assert model.tpr_at_fpr(y, s, 0.001) == 0.5


def test_platt_and_isotonic_calibration():
    rng = np.random.default_rng(1)
    m = rng.normal(0, 2, 5000)
    y = (rng.random(5000) < 1 / (1 + np.exp(-(0.5 * m - 1.0)))).astype(int)
    a, b = model.fit_platt(m, y)
    assert abs(a - 0.5) < 0.1 and abs(b + 1.0) < 0.15
    p = (1 / (1 + np.exp(-m))).astype(np.float32)
    x, v = model.fit_isotonic(p, y)
    assert all(x1 <= x2 for x1, x2 in itertools.pairwise(x))
    assert all(v1 <= v2 for v1, v2 in itertools.pairwise(v))
    assert v[0] >= 0.0 and v[-1] <= 1.0
    cal = model.fit_calibration(m, p, y)
    assert cal["method"] == "isotonic"
    small = model.fit_calibration(m[:300], p[:300], y[:300])
    assert small["method"] == "platt"
    # Mirror of pb_ml::Calibration::apply: Platt on the margin, isotonic interpolation clamped.
    out = model.apply_calibration({"method": "platt", "a": 1.0, "b": -2.0}, np.array([3.0]), np.array([0.9]))
    assert math.isclose(float(out[0]), 1 / (1 + math.exp(-1.0)), rel_tol=1e-6)
    iso = {"method": "isotonic", "x": [0.1, 0.5, 0.9], "y": [0.0, 0.2, 0.8]}
    got = model.apply_calibration(iso, np.zeros(3), np.array([0.05, 0.7, 0.99], dtype=np.float32))
    assert np.allclose(got, [0.0, 0.5, 0.8])
    assert model.apply_calibration({"method": "unknown"}, np.zeros(1), np.array([0.3]))[0] == np.float32(0.3)
