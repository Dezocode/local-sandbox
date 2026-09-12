#!/usr/bin/env python3
"""Deliberately regenerate and then verify the three committed release artifacts."""

from __future__ import annotations

from argparse import ArgumentParser
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
DOWNLOADS = ROOT / "public/downloads"
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from release_common import read_external_regular  # noqa: E402


ARTIFACT_NAMES = (
    "Local-Sandbox-Setup-Guide.pdf",
    "Local-Sandbox-Source.zip",
    "Local-Sandbox-Selfhost.zip",
)


def run(arguments: list[str]) -> None:
    subprocess.run(
        [sys.executable, *arguments],
        cwd=ROOT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        check=True,
    )


def run_freshness(guide: Path, source: Path, selfhost: Path) -> None:
    run([
        "scripts/release/check_freshness.py",
        "--source-artifact",
        str(source),
        "--selfhost-artifact",
        str(selfhost),
        "--guide-artifact",
        str(guide),
    ])


def write_backup(path: Path, data: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, mode)
    finally:
        if descriptor != -1:
            os.close(descriptor)


def snapshot_outputs(
    output_directory: Path,
    temporary: Path,
) -> dict[str, tuple[Path, bytes, int] | None]:
    directory_status = os.lstat(output_directory)
    if stat.S_ISLNK(directory_status.st_mode) or not stat.S_ISDIR(directory_status.st_mode):
        raise ValueError(f"Release output must be a real directory: {output_directory}")
    previous: dict[str, tuple[Path, bytes, int] | None] = {}
    for name in ARTIFACT_NAMES:
        destination = output_directory / name
        try:
            data, mode = read_external_regular(destination)
        except FileNotFoundError:
            previous[name] = None
            continue
        backup = temporary / f"previous-{name}"
        write_backup(backup, data, mode)
        previous[name] = backup, data, mode
    return previous


def restore_outputs(
    output_directory: Path,
    previous: dict[str, tuple[Path, bytes, int] | None],
) -> None:
    errors: list[str] = []
    for name in ARTIFACT_NAMES:
        destination = output_directory / name
        saved = previous[name]
        try:
            if saved is None:
                try:
                    destination_status = os.lstat(destination)
                except FileNotFoundError:
                    continue
                if stat.S_ISLNK(destination_status.st_mode) or not stat.S_ISREG(
                    destination_status.st_mode
                ):
                    raise ValueError(f"Refusing to remove non-regular rollback target: {destination}")
                destination.unlink()
            else:
                backup, _data, _mode = saved
                os.replace(backup, destination)
        except (OSError, ValueError) as error:
            errors.append(f"{name}: {error}")

    for name in ARTIFACT_NAMES:
        destination = output_directory / name
        saved = previous[name]
        try:
            if saved is None:
                if destination.exists() or destination.is_symlink():
                    errors.append(f"{name}: newly-created output still exists")
            else:
                _backup, expected_data, expected_mode = saved
                actual_data, actual_mode = read_external_regular(destination)
                if actual_data != expected_data or actual_mode != expected_mode:
                    errors.append(f"{name}: restored bytes or mode differ")
        except (OSError, ValueError) as error:
            errors.append(f"{name}: rollback verification failed: {error}")
    if errors:
        raise RuntimeError("Could not restore the prior release artifact set: " + "; ".join(errors))


def publish_outputs(
    *,
    output_directory: Path,
    temporary: Path,
    staged: dict[str, Path],
) -> None:
    previous = snapshot_outputs(output_directory, temporary)
    try:
        for name in ARTIFACT_NAMES:
            os.replace(staged[name], output_directory / name)
        run_freshness(
            output_directory / "Local-Sandbox-Setup-Guide.pdf",
            output_directory / "Local-Sandbox-Source.zip",
            output_directory / "Local-Sandbox-Selfhost.zip",
        )
    except BaseException as error:
        try:
            restore_outputs(output_directory, previous)
        except Exception as rollback_error:
            raise RuntimeError(str(rollback_error)) from error
        raise


def regenerate(output_directory: Path) -> dict[str, str]:
    run(["scripts/release/check_python.py"])
    output_directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".regenerate-", dir=output_directory) as temporary_directory:
        temporary = Path(temporary_directory)
        guide = temporary / "Local-Sandbox-Setup-Guide.pdf"
        source = temporary / "Local-Sandbox-Source.zip"
        selfhost = temporary / "Local-Sandbox-Selfhost.zip"
        run(["scripts/generate-guide.py", "--output", str(guide)])
        run(["scripts/package-source.py", "--root", str(ROOT), "--output", str(source)])
        run([
            "scripts/release/selfhost.py",
            "--root",
            str(ROOT),
            "--source-archive",
            str(source),
            "--output",
            str(selfhost),
        ])
        run([
            "scripts/audit-release-artifacts.py",
            "--source-artifact",
            str(source),
            "--selfhost-artifact",
            str(selfhost),
        ])
        run_freshness(guide, source, selfhost)
        publish_outputs(
            output_directory=output_directory,
            temporary=temporary,
            staged={guide.name: guide, source.name: source, selfhost.name: selfhost},
        )
    return {"status": "regenerated-and-fresh", "directory": str(output_directory)}


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--output-directory", type=Path, default=DOWNLOADS)
    options = parser.parse_args()
    print(json.dumps(regenerate(options.output_directory.absolute())))


if __name__ == "__main__":
    main()
