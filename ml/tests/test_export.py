import json

import numpy as np
import pytest

from ml import model
from ml.dump_eval import DumpModel

from .conftest import NAMES

EXPECTED_TREE_KEYS = {
    "split_feature",
    "threshold",
    "decision_type",
    "default_left",
    "missing_type",
    "left_child",
    "right_child",
}


def _walk(node, seen):
    if "leaf_value" in node:
        seen.add("leaf_value")
        return
    seen.update(k for k in EXPECTED_TREE_KEYS if k in node)
    _walk(node["left_child"], seen)
    _walk(node["right_child"], seen)


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    from .conftest import synth_rows

    rows = synth_rows(400, 2500)
    tr, va, ho = model.split(rows)
    x, y = model.matrix(tr)
    xv, yv = model.matrix(va)
    booster = model.train(x, y, xv, yv, NAMES)
    out = tmp_path_factory.mktemp("m")
    thr = model.pick_threshold(model.predict(booster, xv)[yv == 0])
    dump = model.export(booster, NAMES, out, 1, thr, "2026.10.25", {"auc": 0.99, "trained_at": 1})
    return booster, dump, out, model.matrix(ho)


def test_export_format_matches_pb_ml_contract(trained):
    _booster, dump, out, _ = trained
    doc = json.loads((out / "macho_model.json").read_text())
    assert doc == json.loads(json.dumps(dump))
    assert doc["feature_names"] == NAMES and doc["objective"].startswith("binary sigmoid:")
    assert doc["num_class"] == 1 and doc["max_feature_idx"] == len(NAMES) - 1
    assert 0 < len(doc["tree_info"]) <= 300
    seen: set[str] = set()
    for t in doc["tree_info"]:
        assert "tree_structure" in t
        _walk(t["tree_structure"], seen)
    assert seen == EXPECTED_TREE_KEYS | {"leaf_value"}
    meta = json.loads((out / "model_meta.json").read_text())
    assert set(meta) == {"features_version", "threshold", "version", "metrics"}
    assert meta["features_version"] == 1 and meta["version"] == "2026.10.25" and 0 < meta["threshold"] <= 1.0
    assert (out / "macho_model.txt").read_text().startswith("tree")


def test_dump_evaluator_matches_lightgbm(trained):
    booster, dump, _, (xh, _yh) = trained
    xh = xh.copy()
    xh[::7, 2] = np.nan  # missing values
    xh[::5, 3] = 0.0
    ours = model.predict_dump(DumpModel(dump), xh)
    ref = model.predict(booster, xh)
    assert np.max(np.abs(ours - ref)) < 1e-6


def test_check_dump_rejects_mismatches(trained):
    _, dump, _, _ = trained
    with pytest.raises(ValueError):
        model.check_dump(dump, [*NAMES[:-1], "other"])
    bad = json.loads(json.dumps(dump))
    bad["tree_info"][0]["tree_structure"]["decision_type"] = "=="
    with pytest.raises(ValueError):
        model.check_dump(bad, NAMES)
