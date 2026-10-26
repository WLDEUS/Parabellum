"""Parabellum nightly threat-DB pipeline.

Entry point: ``python -m pipeline.build --out dist/db [--previous <bundle>] [--sources pipeline/sources.toml]``.
The bundle layout is the contract defined in ``crates/pb-core/src/db.rs``.
"""

__all__ = ["BUNDLE_FILE", "DB_FORMAT", "MANIFEST_FILE", "SIGNATURE_FILE", "STATE_FILE"]

#: Must match ``pb_core::db::DB_FORMAT``.
DB_FORMAT = 1
BUNDLE_FILE = "parabellum-db.tar.gz"
SIGNATURE_FILE = "parabellum-db.tar.gz.minisig"
MANIFEST_FILE = "manifest.json"
#: Per-source normalised data carried from one nightly run to the next (not part of the signed bundle).
STATE_FILE = "pipeline-state.tar.gz"
