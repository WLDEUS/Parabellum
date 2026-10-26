from __future__ import annotations

import hashlib

import numpy as np
import pytest

from ml.features import FeatureRow

NAMES = [f"feat_{i}" for i in range(8)]


def synth_rows(n_pos: int, n_neg: int, seed: int = 0, version: int = 1) -> list[FeatureRow]:
    """Separable-ish synthetic data; NaN sprinkled in to exercise missing-value handling."""
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n_pos + n_neg):
        label = 1 if i < n_pos else 0
        f = rng.normal(0.0, 1.0, len(NAMES)).astype(np.float32)
        f[0] += 2.5 * label
        f[1] += 1.5 * label
        if i % 17 == 0:
            f[2] = np.nan
        if i % 11 == 0:
            f[3] = 0.0
        sha = hashlib.sha256(f"{seed}-{i}".encode()).hexdigest()
        rows.append(FeatureRow(sha, label, version, [float(v) for v in f]))
    return rows


@pytest.fixture
def rows() -> list[FeatureRow]:
    return synth_rows(400, 2500)
