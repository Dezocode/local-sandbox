#!/usr/bin/env python3
"""No-follow filesystem reads for deterministic release packagers."""

from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
from typing import Callable, Iterator


DirectoryIdentity = tuple[int, int, int]
ReleaseEntry = tuple[PurePosixPath, bytes, int]

# Keep every release packager and artifact auditor on one fail-closed definition
# of signing and credential material. Public certificates are included because
# release archives must not carry any developer signing identity artifacts.
SENSITIVE_RELEASE_SUFFIXES = frozenset({
    ".cer",
    ".crt",
    ".csr",
    ".der",
    ".jks",
    ".key",
    ".keystore",
    ".mobileprovision",
    ".p12",
    ".p8",
    ".pem",
    ".pfx",
    ".pkcs12",
    ".provisionprofile",
})


class UnsafeReleasePath(ValueError):
    """Raised when release input is not a stable regular file below its root."""


def _relative_parts(relative: str | PurePosixPath, *, allow_empty: bool = False) -> tuple[str, ...]:
    path = PurePosixPath(relative)
    parts = path.parts
    if path.is_absolute() or any(part in {"", ".", ".."} or "\\" in part for part in parts):
        raise UnsafeReleasePath(f"Unsafe release path: {relative}")
    if not parts and not allow_empty:
        raise UnsafeReleasePath("Release path must not be empty.")
    return parts


def _identity(value: os.stat_result) -> tuple[int, int, int]:
    return value.st_dev, value.st_ino, value.st_mode


def _content_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory_flags() -> int:
    required = ["O_DIRECTORY", "O_NOFOLLOW"]
    missing = [name for name in required if not hasattr(os, name)]
    if missing:
        raise RuntimeError(f"Release packaging requires {', '.join(missing)} support.")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise RuntimeError("Release packaging requires O_NOFOLLOW support.")
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


class SafeRoot:
    """Read regular files through directory descriptors without following links."""

    def __init__(self, root: Path):
        self.root = Path(os.path.abspath(os.fspath(root)))
        try:
            before = os.lstat(self.root)
        except FileNotFoundError as error:
            raise FileNotFoundError(f"Release root does not exist: {self.root}") from error
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise UnsafeReleasePath(f"Release root must be a real directory: {self.root}")
        descriptor = os.open(self.root, _directory_flags())
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after):
            os.close(descriptor)
            raise UnsafeReleasePath(f"Release root changed while opening: {self.root}")
        self._root_identity = _identity(after)
        self._descriptor: int | None = descriptor

    def __enter__(self) -> SafeRoot:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None

    def _root_descriptor(self) -> int:
        if self._descriptor is None:
            raise RuntimeError("SafeRoot is closed.")
        return self._descriptor

    def _assert_root_unchanged(self) -> None:
        try:
            current = os.lstat(self.root)
        except OSError as error:
            raise UnsafeReleasePath(f"Release root changed during packaging: {self.root}") from error
        if _identity(current) != self._root_identity:
            raise UnsafeReleasePath(f"Release root changed during packaging: {self.root}")

    def _open_directory(
        self,
        parts: tuple[str, ...],
        expected_identities: tuple[DirectoryIdentity, ...] | None = None,
    ) -> tuple[int, tuple[DirectoryIdentity, ...]]:
        if expected_identities is not None and len(expected_identities) != len(parts):
            raise ValueError("Expected directory identities do not match the release path.")
        self._assert_root_unchanged()
        current = os.dup(self._root_descriptor())
        identities: list[DirectoryIdentity] = []
        try:
            traversed: list[str] = []
            for index, part in enumerate(parts):
                traversed.append(part)
                before = os.stat(part, dir_fd=current, follow_symlinks=False)
                if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                    raise UnsafeReleasePath(f"Release path ancestor is not a real directory: {part}")
                following = os.open(part, _directory_flags(), dir_fd=current)
                after = os.fstat(following)
                if _identity(before) != _identity(after):
                    os.close(following)
                    raise UnsafeReleasePath(f"Release path ancestor changed while opening: {part}")
                identity = _identity(after)
                if expected_identities is not None and identity != expected_identities[index]:
                    os.close(following)
                    relative = PurePosixPath(*traversed)
                    raise UnsafeReleasePath(
                        f"Release directory identity changed during traversal: {relative}"
                    )
                identities.append(identity)
                os.close(current)
                current = following
            self._assert_root_unchanged()
            return current, tuple(identities)
        except Exception:
            os.close(current)
            raise

    def _assert_directory_chain(
        self,
        parts: tuple[str, ...],
        expected_identities: tuple[DirectoryIdentity, ...],
    ) -> None:
        descriptor, _identities = self._open_directory(parts, expected_identities)
        os.close(descriptor)

    @staticmethod
    def _read_regular_at(directory: int, name: str, path: PurePosixPath) -> tuple[bytes, int]:
        descriptor: int | None = None
        try:
            before = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
                raise UnsafeReleasePath(f"Release input must be a real regular file: {path}")
            descriptor = os.open(name, _file_flags(), dir_fd=directory)
            opened = os.fstat(descriptor)
            if _content_identity(before) != _content_identity(opened):
                raise UnsafeReleasePath(f"Release input changed while opening: {path}")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(descriptor)
            if _content_identity(opened) != _content_identity(after):
                raise UnsafeReleasePath(f"Release input changed while reading: {path}")
            try:
                namespace_after = os.stat(name, dir_fd=directory, follow_symlinks=False)
            except OSError as error:
                raise UnsafeReleasePath(f"Release input changed while reading: {path}") from error
            if _content_identity(opened) != _content_identity(namespace_after):
                raise UnsafeReleasePath(f"Release input changed while reading: {path}")
            return b"".join(chunks), stat.S_IMODE(opened.st_mode)
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def iter_regular_files(
        self,
        directory: str | PurePosixPath,
        *,
        include_file: Callable[[PurePosixPath], bool] | None = None,
        descend_into: Callable[[PurePosixPath], bool] | None = None,
    ) -> Iterator[ReleaseEntry]:
        prefix = PurePosixPath(directory)
        parts = _relative_parts(prefix)
        descriptor, identities = self._open_directory(parts)

        def walk(
            current: int,
            current_prefix: PurePosixPath,
            current_identities: tuple[DirectoryIdentity, ...],
        ) -> Iterator[ReleaseEntry]:
            try:
                for name in sorted(os.listdir(current)):
                    _relative_parts(PurePosixPath(name))
                    before = os.stat(name, dir_fd=current, follow_symlinks=False)
                    relative = current_prefix / name
                    if stat.S_ISLNK(before.st_mode):
                        raise UnsafeReleasePath(f"Release input may not be a symbolic link: {relative}")
                    if stat.S_ISDIR(before.st_mode):
                        if descend_into is not None and not descend_into(relative):
                            continue
                        child = os.open(name, _directory_flags(), dir_fd=current)
                        after = os.fstat(child)
                        if _identity(before) != _identity(after):
                            os.close(child)
                            raise UnsafeReleasePath(f"Release directory changed while opening: {relative}")
                        child_identity = _identity(after)
                        yield from walk(child, relative, current_identities + (child_identity,))
                        try:
                            namespace_after = os.stat(name, dir_fd=current, follow_symlinks=False)
                        except OSError as error:
                            raise UnsafeReleasePath(
                                f"Release directory changed during traversal: {relative}"
                            ) from error
                        if _identity(namespace_after) != child_identity:
                            raise UnsafeReleasePath(
                                f"Release directory changed during traversal: {relative}"
                            )
                    elif stat.S_ISREG(before.st_mode):
                        if include_file is not None and not include_file(relative):
                            continue
                        data, mode = self._read_regular_at(current, name, relative)
                        yield relative, data, mode
                    else:
                        raise UnsafeReleasePath(f"Release input must be a regular file or directory: {relative}")
                self._assert_directory_chain(current_prefix.parts, current_identities)
            finally:
                os.close(current)

        yield from walk(descriptor, prefix, identities)

    def read_regular(self, relative: str | PurePosixPath) -> tuple[bytes, int]:
        path = PurePosixPath(relative)
        parts = _relative_parts(path)
        parent, identities = self._open_directory(parts[:-1])
        try:
            result = self._read_regular_at(parent, parts[-1], path)
            self._assert_directory_chain(parts[:-1], identities)
            return result
        finally:
            os.close(parent)


def read_external_regular(path: Path) -> tuple[bytes, int]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    with SafeRoot(absolute.parent) as reader:
        return reader.read_regular(PurePosixPath(absolute.name))
