"""Parabellum weekly Mach-O classifier (LightGBM), exported for ``pb-ml`` (Rust).

Entry point: ``python -m ml.train ...``. Feature vectors come from the ``pb-features`` binary
(crate ``pb-ml``), so training and inference share the exact same extractor.
"""
