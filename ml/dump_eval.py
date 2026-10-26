"""Pure-Python evaluator for LightGBM ``Booster.dump_model()`` JSON — mirrors ``pb_ml::GbdtModel``.

Used to (a) evaluate the *currently published* model in the promotion gate exactly as clients do,
(b) cross-check the export against ``booster.predict`` in tests, and (c) score the clean corpus in
the nightly pipeline. Semantics (LightGBM ``Tree::NumericalDecision``)::

    if isnan(x) and missing_type != NaN: x = 0
    if (missing_type == Zero and |x| <= 1e-35) or (missing_type == NaN and isnan(x)): go default
    else: go left if x <= threshold
"""

from __future__ import annotations

import json
import math
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ZERO_THRESHOLD = struct.unpack("f", struct.pack("f", 1e-35))[0]
MAX_TREES = 20_000
MAX_DEPTH = 100


class ModelError(ValueError):
    pass


def f32(x: float) -> float:
    """Round to float32 (pb-features emits f32; Rust widens f32 -> f64 exactly)."""
    if math.isnan(x):
        return x
    return struct.unpack("f", struct.pack("f", x))[0]


@dataclass
class _Node:
    feature: int = -1
    threshold: float = 0.0
    default_left: bool = False
    missing: str = "None"
    left: _Node | None = None
    right: _Node | None = None
    value: float = 0.0


def _parse(node: dict, depth: int) -> _Node:
    if depth > MAX_DEPTH:
        raise ModelError("tree too deep")
    if "leaf_value" in node:
        return _Node(value=float(node["leaf_value"]))
    if node.get("decision_type", "<=") != "<=":
        raise ModelError(f"unsupported decision_type {node.get('decision_type')!r}")
    return _Node(
        feature=int(node["split_feature"]),
        threshold=float(node["threshold"]),
        default_left=bool(node.get("default_left", False)),
        missing=str(node.get("missing_type", "None")),
        left=_parse(node["left_child"], depth + 1),
        right=_parse(node["right_child"], depth + 1),
    )


def _eval(node: _Node, x: Sequence[float]) -> float:
    while node.left is not None and node.right is not None:
        v = x[node.feature] if node.feature < len(x) else math.nan
        if math.isnan(v) and node.missing != "NaN":
            v = 0.0
        if (node.missing == "Zero" and -ZERO_THRESHOLD <= v <= ZERO_THRESHOLD) or (
            node.missing == "NaN" and math.isnan(v)
        ):
            node = node.left if node.default_left else node.right
        else:
            node = node.left if v <= node.threshold else node.right
    return node.value


class DumpModel:
    """A binary LightGBM model loaded from its JSON dump."""

    def __init__(self, doc: dict) -> None:
        if int(doc.get("num_class", 1)) != 1 or int(doc.get("num_tree_per_iteration", 1)) != 1:
            raise ModelError("only binary models are supported")
        objective = str(doc.get("objective", ""))
        self.sigmoid = 1.0
        if objective.startswith("binary"):
            for part in objective.split():
                if part.startswith("sigmoid:"):
                    self.sigmoid = float(part.split(":", 1)[1])
        elif objective.split()[0:1] != ["cross_entropy"]:
            raise ModelError(f"unsupported objective {objective!r}")
        self.average_output = bool(doc.get("average_output", False))
        self.feature_names: list[str] = [str(n) for n in doc.get("feature_names", [])]
        trees = doc.get("tree_info", [])
        if len(trees) > MAX_TREES:
            raise ModelError("too many trees")
        self.trees = [_parse(t["tree_structure"], 0) for t in trees]

    @classmethod
    def load(cls, path: Path) -> DumpModel:
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def predict_raw(self, x: Sequence[float]) -> float:
        xs = [f32(float(v)) for v in x]
        total = sum(_eval(t, xs) for t in self.trees)
        if self.average_output and self.trees:
            total /= len(self.trees)
        return total

    def predict_proba(self, x: Sequence[float]) -> float:
        """Probability of the malicious class, rounded to f32 like ``GbdtModel::predict_proba``."""
        return f32(1.0 / (1.0 + math.exp(-self.sigmoid * self.predict_raw(x))))
