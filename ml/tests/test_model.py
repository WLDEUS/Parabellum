import math

import numpy as np

from ml import model


def test_pick_threshold_respects_fpr():
    neg = np.linspace(0.0, 1.0, 2000, dtype=np.float32)
    t = model.pick_threshold(neg, 0.001)
    assert (neg >= t).sum() <= 2 and (neg > t).sum() <= 2
    assert (neg >= np.nextafter(np.float32(neg[-3]), np.float32(0))).sum() > 2  # it is the smallest such threshold
    # Fewer than 1000 negatives: no false positive allowed at all.
    small = np.array([0.1, 0.9, 0.5], dtype=np.float32)
    t2 = model.pick_threshold(small, 0.001)
    assert t2 > 0.9 and (small >= t2).sum() == 0
    # Ties at the pivot never let extra negatives through.
    ties = np.array([0.7] * 10 + [0.1] * 990, dtype=np.float32)
    assert (ties >= model.pick_threshold(ties, 0.001)).sum() == 0
    # pb-ml rejects thresholds > 1.
    assert model.pick_threshold(np.ones(10, dtype=np.float32), 0.001) == 1.0


def test_rates_and_auc():
    y = np.array([1, 1, 0, 0])
    s = np.array([0.9, 0.4, 0.5, 0.1], dtype=np.float32)
    assert model.rates(y, s, 0.45) == (0.5, 0.5)
    assert math.isclose(model.roc_auc(y, s), 0.75)
    assert math.isclose(model.roc_auc(np.array([1, 0]), np.array([0.5, 0.5])), 0.5)


def test_promotion_gate():
    def ev(tpr, fpr):
        return model.Evaluation(0.99, tpr, fpr, 0.5, 100, 1000)

    assert model.gate(ev(0.8, 0.0), None).promote
    assert not model.gate(ev(0.9, 0.002), None).promote  # FPR above 0.1 %
    assert model.gate(ev(0.8, 0.0), ev(0.8, 0.001)).promote  # equal TPR is enough
    d = model.gate(ev(0.7, 0.0), ev(0.8, 0.0))
    assert not d.promote and "keeping" in d.reason
    assert model.gate(ev(0.5, 0.0), ev(0.9, 0.01)).promote  # current model drifted


def test_split_is_stable_and_stratified(rows):
    a = model.split(rows)
    b = model.split(list(reversed(rows)))
    assert [{r.sha256 for r in part} for part in a] == [{r.sha256 for r in part} for part in b]
    _tr, _va, ho = a
    assert len(ho) / len(rows) == model.HOLDOUT_BUCKETS.stop / 100 or abs(len(ho) / len(rows) - 0.2) < 0.03
    for part in a:
        frac = sum(r.label for r in part) / len(part)
        assert abs(frac - 400 / 2900) < 0.05
