#!/usr/bin/env python3
"""Prove that two static self-host builds are byte-for-byte identical."""

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/release/selfhost.py"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def build(output: Path) -> bytes:
    subprocess.run(
        [sys.executable, str(SCRIPT), "--output", str(output)],
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=True,
        capture_output=True,
        text=True,
    )
    return output.read_bytes()


with tempfile.TemporaryDirectory() as temporary_directory:
    temporary = Path(temporary_directory)
    first_path = temporary / "first.zip"
    second_path = temporary / "second.zip"
    first = build(first_path)
    second = build(second_path)

    first_hash = sha256(first).hexdigest()
    second_hash = sha256(second).hexdigest()
    assert first == second
    assert first_hash == second_hash

    with zipfile.ZipFile(first_path) as archive:
        infos = archive.infolist()
        assert archive.testzip() is None
        assert [info.filename for info in infos] == sorted(info.filename for info in infos)
        assert all(info.date_time == FIXED_ZIP_TIME for info in infos)
        assert all(info.create_system == 3 for info in infos)
        assert all(((info.external_attr >> 16) & 0o777) == 0o644 for info in infos)

print(json.dumps({
    "status": "passed",
    "sha256": first_hash,
    "bytes": len(first),
    "files": len(infos),
}))
