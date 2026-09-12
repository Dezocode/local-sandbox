#!/usr/bin/env python3
"""Build a deterministic static self-host archive without user data."""

from __future__ import annotations

from argparse import ArgumentParser
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
import zipfile


SCRIPTS = Path(__file__).resolve().parent.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from release_common import SafeRoot, read_external_regular


ROOT = Path(__file__).resolve().parents[2]
STATIC_CAPABILITIES = {
    "schemaVersion": 1,
    "mode": "static-selfhost",
    "githubDirect": True,
    "cursorOrigin": False,
    "encryptedWorkspaceSync": False,
}


def archive_info(path: PurePosixPath) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path.as_posix())
    info.date_time = (1980, 1, 1, 0, 0, 0)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    info.create_system = 3
    return info


def build(root: Path, output: Path, source_archive: Path) -> tuple[int, int]:
    root = root.absolute()
    source_archive = source_archive.absolute()
    entries: dict[PurePosixPath, bytes] = {}

    with SafeRoot(root) as reader:
        for relative in [PurePosixPath("selfhost/Caddyfile"), PurePosixPath("selfhost/compose.yaml")]:
            data, _mode = reader.read_regular(relative)
            entries[PurePosixPath(relative.name)] = data

        for source_directory, archive_directory in [
            (PurePosixPath("public/local"), PurePosixPath("site/local")),
            (PurePosixPath("public/shortcuts"), PurePosixPath("site/shortcuts")),
        ]:
            for relative, data, _mode in reader.iter_regular_files(source_directory):
                entries[archive_directory / relative.relative_to(source_directory)] = data

        roadmap, _mode = reader.read_regular(PurePosixPath("docs/ROADMAP-AUTOMATION.md"))
        entries[PurePosixPath("site/downloads/ROADMAP-AUTOMATION.md")] = roadmap

        try:
            source_relative = PurePosixPath(source_archive.relative_to(root).as_posix())
        except ValueError:
            source_data, _mode = read_external_regular(source_archive)
        else:
            source_data, _mode = reader.read_regular(source_relative)
        entries[PurePosixPath("site/downloads/Local-Sandbox-Source.zip")] = source_data

    entries[PurePosixPath("site/local/capabilities.json")] = (
        json.dumps(STATIC_CAPABILITIES, indent=2) + "\n"
    ).encode("utf-8")
    entries[PurePosixPath("site/index.html")] = (
        '<!doctype html><meta http-equiv="refresh" content="0;url=/local/index.html">'
        '<a href="/local/index.html">Open Local Sandbox</a>'
    ).encode("utf-8")

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix="Local-Sandbox-Selfhost-", suffix=".zip", dir=output.parent, delete=False
    ) as handle:
        temporary_output = Path(handle.name)

    try:
        with zipfile.ZipFile(
            temporary_output,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=7,
        ) as archive:
            for relative in sorted(entries, key=lambda item: item.as_posix()):
                archive.writestr(archive_info(relative), entries[relative])
        with zipfile.ZipFile(temporary_output) as archive:
            if archive.testzip() is not None:
                raise ValueError("Static self-host archive failed its CRC check.")
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("Static self-host archive contains duplicate paths.")
        temporary_output.chmod(0o644)
        os.replace(temporary_output, output)
    finally:
        temporary_output.unlink(missing_ok=True)

    return len(entries), output.stat().st_size


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--source-archive", type=Path)
    options = parser.parse_args()
    root = options.root.absolute()
    output = options.output or root / "public/downloads/Local-Sandbox-Selfhost.zip"
    source_archive = options.source_archive or root / "public/downloads/Local-Sandbox-Source.zip"
    file_count, byte_count = build(root, output, source_archive)
    print(json.dumps({
        "archive": str(output),
        "files": file_count,
        "bytes": byte_count,
        "containsUserData": False,
        "appleWebAuthConfigured": False,
    }))


if __name__ == "__main__":
    main()
