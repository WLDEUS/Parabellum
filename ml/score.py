"""Score Mach-O files with a published model (``macho_model.json`` + ``model_meta.json``)."""

from __future__ import annotations

import json
from pathlib import Path

from .dump_eval import DumpModel, ModelError
from .features import extract, feature_names


class MlScorer:
    """Callable ``paths -> {path: probability}`` used by the pipeline (FP rate, detection rate)."""

    def __init__(self, pb_features: Path, model_dir: Path) -> None:
        self.pb_features = pb_features
        self.model = DumpModel.load(model_dir / "macho_model.json")
        meta = json.loads((model_dir / "model_meta.json").read_text(encoding="utf-8"))
        self.threshold = float(meta["threshold"])
        self.features_version = int(meta["features_version"])
        names = feature_names(pb_features)
        if names != self.model.feature_names:
            raise ModelError("model feature_names differ from pb-features --names")

    def __call__(self, paths: list[Path]) -> dict[Path, float]:
        out: dict[Path, float] = {}
        for row in extract(self.pb_features, paths, None):
            if row.features_version != self.features_version:
                continue
            out[Path(row.path)] = self.model.predict_proba(row.features)
        return out
