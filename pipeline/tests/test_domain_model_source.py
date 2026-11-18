"""`ml_domain_local` fetcher: the domain model files from --ml-dir into ml/ of the bundle."""

import hashlib
import json
from pathlib import Path

import pytest

from pipeline.http import FetchError
from pipeline.sources import DOMAIN_MODEL_FILES, Context, SourceSpec, carry_over, f_ml_domain_local, load_settings

REPO = Path(__file__).resolve().parents[2]


def ctx(ml_dir: Path | None) -> Context:
    return Context(
        http=None,  # type: ignore[arg-type]
        repo_root=REPO,
        settings=load_settings(REPO / "pipeline" / "sources.toml"),
        now=0,
        ml_dir=ml_dir,
    )


SPEC = SourceSpec("ml-domain", "ml", "ml_domain_local", "", "MIT")


def write_model(d: Path, brands: bytes = b"paypal paypal.com\n", sha: str | None = None) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / "domain_model.json").write_text(json.dumps({"tree_info": [{}, {}]}))
    meta = {"features_version": 1, "threshold": 0.9, "brands_sha256": sha or hashlib.sha256(brands).hexdigest()}
    (d / "domain_model_meta.json").write_text(json.dumps(meta))
    (d / "domain_brands.txt").write_bytes(brands)
    (d / "domain_top.txt").write_text("example.com\n")


def test_fetches_all_files(tmp_path):
    write_model(tmp_path / "ml")
    got = f_ml_domain_local(SPEC, ctx(tmp_path / "ml"))
    assert sorted(got.files) == sorted(f"ml/{n}" for n in DOMAIN_MODEL_FILES)
    assert got.count == 2


def test_rejects_missing_or_mismatched(tmp_path):
    with pytest.raises(FetchError):
        f_ml_domain_local(SPEC, ctx(None))
    with pytest.raises(FetchError):
        f_ml_domain_local(SPEC, ctx(tmp_path))
    write_model(tmp_path / "bad", sha="00")
    with pytest.raises(FetchError):
        f_ml_domain_local(SPEC, ctx(tmp_path / "bad"))


def test_carry_over_needs_every_file(tmp_path):
    prev = tmp_path / "prev"
    write_model(prev / "ml")
    out = carry_over(SPEC, None, prev)
    assert out.count == 1 and len(out.files) == len(DOMAIN_MODEL_FILES)
    (prev / "ml" / "domain_top.txt").unlink()
    out = carry_over(SPEC, None, prev)
    assert out.count == 0 and out.files == {}
