import shutil
import subprocess

import pytest

from pipeline.sign import sign, verify

pytestmark = pytest.mark.skipif(shutil.which("minisign") is None, reason="minisign not installed")


def test_sign_with_key_text_and_verify(tmp_path):
    pub, sec = tmp_path / "k.pub", tmp_path / "k.key"
    subprocess.run(["minisign", "-G", "-W", "-p", str(pub), "-s", str(sec)], check=True, capture_output=True)
    bundle = tmp_path / "parabellum-db.tar.gz"
    bundle.write_bytes(b"bundle")
    sig = sign(bundle, secret_key=sec.read_text(), trusted_comment="parabellum-db 2026.10.25.1")
    assert sig.name == "parabellum-db.tar.gz.minisig"
    assert "trusted comment: parabellum-db 2026.10.25.1" in sig.read_text()
    assert verify(bundle, pub)
    bundle.write_bytes(b"tampered")
    assert not verify(bundle, pub)
