import json
from types import SimpleNamespace

import pytest

from pipeline.http import FetchError
from pipeline.sources import SourceSpec, carry_over, f_ml_local

SPEC = SourceSpec(name="ml-macho", kind="ml", fetcher="ml_local", url="", license="", options={})


def _pair(d, model, meta, trees=2):
    (d / model).write_text(json.dumps({"tree_info": [{}] * trees}))
    (d / meta).write_text(json.dumps({"threshold": 0.9, "features_version": 2}))


def test_ml_local_ships_each_complete_pair(tmp_path):
    with pytest.raises(FetchError):
        f_ml_local(SPEC, SimpleNamespace(ml_dir=tmp_path))
    _pair(tmp_path, "script_model.json", "script_model_meta.json", 3)
    got = f_ml_local(SPEC, SimpleNamespace(ml_dir=tmp_path))
    assert set(got.files) == {"ml/script_model.json", "ml/script_model_meta.json"} and got.count == 3
    _pair(tmp_path, "macho_model.json", "model_meta.json", 2)
    (tmp_path / "script_model_meta.json").unlink()  # incomplete pair: skipped
    got = f_ml_local(SPEC, SimpleNamespace(ml_dir=tmp_path))
    assert set(got.files) == {"ml/macho_model.json", "ml/model_meta.json"} and got.count == 2
    (tmp_path / "macho_model.json").write_text("{}")
    with pytest.raises(FetchError):
        f_ml_local(SPEC, SimpleNamespace(ml_dir=tmp_path))


def test_ml_carry_over_keeps_both_models(tmp_path):
    ml = tmp_path / "ml"
    ml.mkdir()
    _pair(ml, "macho_model.json", "model_meta.json")
    _pair(ml, "script_model.json", "script_model_meta.json")
    out = carry_over(SPEC, None, tmp_path)
    assert out.count == 2 and len(out.files) == 4
    (ml / "model_meta.json").unlink()
    out = carry_over(SPEC, None, tmp_path)
    assert set(out.files) == {"ml/script_model.json", "ml/script_model_meta.json"} and out.count == 1
