#!/usr/bin/env python3
"""Compute the deterministic digest of the current release-candidate files."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
from typing import NoReturn, Sequence


EXCLUDED_PATHS = frozenset({
    b"docs/validation.json",
    b"qualification/Local-Sandbox-0.3-Progress.xlsx",
    b"qualification/Local-Sandbox-0.3-Progress.snapshot.json",
})
_DOMAIN = b"local-sandbox-release-candidate-v1\0"


class CandidateDigestError(RuntimeError):
    """Raised when the current repository candidate cannot be hashed safely."""


def fail(message: str) -> NoReturn:
    raise CandidateDigestError(message)


def _git(root: Path, arguments: Sequence[str]) -> bytes:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise CandidateDigestError(f"Could not run Git: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        fail(f"Git candidate enumeration failed: {detail or f'exit {result.returncode}'}")
    return result.stdout


def _candidate_paths(root: Path) -> tuple[bytes, ...]:
    top_level = _git(root, ["rev-parse", "--show-toplevel"])
    try:
        repository = Path(os.fsdecode(top_level.rstrip(b"\n"))).resolve(strict=True)
    except OSError as error:
        raise CandidateDigestError("Git returned an unreadable repository root") from error
    if repository != root:
        fail("Candidate digest root must be the Git repository top level")

    raw = _git(root, ["ls-files", "--cached", "--others", "--exclude-standard", "-z", "--"])
    entries = raw.split(b"\0")
    if entries[-1] != b"":
        fail("Git candidate enumeration was not NUL terminated")
    paths: set[bytes] = set()
    for relative in entries[:-1]:
        components = relative.split(b"/")
        if (
            not relative
            or relative.startswith(b"/")
            or any(component in {b"", b".", b".."} for component in components)
        ):
            fail("Git candidate enumeration returned an unsafe repository path")
        if relative not in EXCLUDED_PATHS:
            paths.add(relative)
    return tuple(sorted(paths))


def _open_parent(root_descriptor: int, components: list[bytes], relative: str) -> int:
    descriptor = os.dup(root_descriptor)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
    )
    try:
        for component in components[:-1]:
            next_descriptor = os.open(component, directory_flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        os.close(descriptor)
        raise CandidateDigestError(
            f"Could not open candidate parent for {relative!r}: {error}"
        ) from error


def _stat_from_root(root_descriptor: int, components: list[bytes], relative: str) -> os.stat_result:
    parent_descriptor = _open_parent(root_descriptor, components, relative)
    try:
        return os.stat(
            components[-1],
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
    except OSError as error:
        raise CandidateDigestError(
            f"Could not inspect candidate path {relative!r}: {error}"
        ) from error
    finally:
        os.close(parent_descriptor)


def candidate_digest(root: Path) -> str:
    """Hash all tracked and nonignored untracked regular files under ``root``."""

    try:
        repository = root.resolve(strict=True)
    except OSError as error:
        raise CandidateDigestError(f"Candidate digest root is unavailable: {error}") from error
    if not repository.is_dir():
        fail("Candidate digest root must be a directory")

    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    regular_files = 0
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        fail("Candidate digest requires O_DIRECTORY and O_NOFOLLOW support")
    open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | os.O_NOFOLLOW
    root_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
    )
    root_descriptor = os.open(repository, root_flags)
    try:
        for relative_bytes in _candidate_paths(repository):
            relative = os.fsdecode(relative_bytes)
            components = relative_bytes.split(b"/")
            listed = _stat_from_root(root_descriptor, components, relative)
            if not stat.S_ISREG(listed.st_mode):
                current = _stat_from_root(root_descriptor, components, relative)
                if (
                    current.st_dev != listed.st_dev
                    or current.st_ino != listed.st_ino
                    or stat.S_IFMT(current.st_mode) != stat.S_IFMT(listed.st_mode)
                ):
                    fail(f"Candidate path changed while it was inspected: {relative!r}")
                continue

            parent_descriptor = _open_parent(root_descriptor, components, relative)
            try:
                try:
                    descriptor = os.open(components[-1], open_flags, dir_fd=parent_descriptor)
                except OSError as error:
                    raise CandidateDigestError(
                        f"Could not open candidate file {relative!r}: {error}"
                    ) from error
                try:
                    before = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_dev != listed.st_dev
                        or before.st_ino != listed.st_ino
                    ):
                        fail(f"Candidate path changed before it was hashed: {relative!r}")
                    digest.update(b"file\0")
                    digest.update(struct.pack(">Q", len(relative_bytes)))
                    digest.update(relative_bytes)
                    digest.update(b"\1" if before.st_mode & 0o111 else b"\0")
                    digest.update(struct.pack(">Q", before.st_size))
                    while True:
                        chunk = os.read(descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                    after = os.fstat(descriptor)
                    if (
                        after.st_dev != before.st_dev
                        or after.st_ino != before.st_ino
                        or after.st_size != before.st_size
                        or after.st_mtime_ns != before.st_mtime_ns
                        or after.st_ctime_ns != before.st_ctime_ns
                        or stat.S_IFMT(after.st_mode) != stat.S_IFMT(before.st_mode)
                        or (after.st_mode & 0o111) != (before.st_mode & 0o111)
                    ):
                        fail(f"Candidate file changed while it was hashed: {relative!r}")
                finally:
                    os.close(descriptor)
            finally:
                os.close(parent_descriptor)

            current = _stat_from_root(root_descriptor, components, relative)
            if (
                current.st_dev != before.st_dev
                or current.st_ino != before.st_ino
                or current.st_size != before.st_size
                or current.st_mtime_ns != before.st_mtime_ns
                or current.st_ctime_ns != before.st_ctime_ns
                or stat.S_IFMT(current.st_mode) != stat.S_IFMT(before.st_mode)
                or (current.st_mode & 0o111) != (before.st_mode & 0o111)
            ):
                fail(f"Candidate path changed while it was hashed: {relative!r}")
            regular_files += 1
    finally:
        os.close(root_descriptor)
    digest.update(b"end\0")
    digest.update(struct.pack(">Q", regular_files))
    return digest.hexdigest()


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        print(candidate_digest(parse_arguments(arguments).root))
        return 0
    except CandidateDigestError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
