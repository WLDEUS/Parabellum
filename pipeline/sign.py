"""minisign signing (Ed25519). The CI secret key is unencrypted (generated with ``minisign -G -W``)."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


class SignError(Exception):
    pass


def minisign_path() -> str:
    exe = shutil.which("minisign")
    if not exe:
        raise SignError("minisign not found (apt-get install minisign / brew install minisign)")
    return exe


def sign(
    path: Path, secret_key: str | None = None, secret_key_file: Path | None = None, trusted_comment: str = ""
) -> Path:
    """Sign ``path`` -> ``path.minisig``. The key comes from a file or from its text (env secret).

    The key text is written to a 0600 temp file that is removed right after signing.
    """
    exe = minisign_path()
    sig = path.with_name(path.name + ".minisig")
    tmpdir: str | None = None
    try:
        if secret_key_file is None:
            if not secret_key:
                raise SignError("no minisign secret key (MINISIGN_SECRET_KEY or --secret-key-file)")
            tmpdir = tempfile.mkdtemp(prefix="pb-sign-")
            secret_key_file = Path(tmpdir, "key")
            fd = os.open(secret_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secret_key.strip() + "\n")
        cmd = [exe, "-S", "-s", str(secret_key_file), "-m", str(path), "-x", str(sig)]
        if trusted_comment:
            cmd += ["-t", trusted_comment]
        proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False)
        if proc.returncode != 0:
            raise SignError(f"minisign failed ({proc.returncode}): {proc.stderr.strip()[-300:]}")
        return sig
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def verify(path: Path, public_key_file: Path) -> bool:
    exe = minisign_path()
    proc = subprocess.run(
        [exe, "-V", "-p", str(public_key_file), "-m", str(path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
        check=False,
    )
    return proc.returncode == 0
