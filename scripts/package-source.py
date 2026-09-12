#!/usr/bin/env python3
"""Build a deterministic, source-only release archive from an explicit allowlist."""

from __future__ import annotations

from argparse import ArgumentParser
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
import zipfile

from release_common import SENSITIVE_RELEASE_SUFFIXES, SafeRoot


ROOT = Path(__file__).resolve().parent.parent
ARCHIVE_ROOT = PurePosixPath("Local-Sandbox")

ROOT_FILES = {
    ".env.example", ".gitattributes", ".gitignore", ".npmrc", "README.md",
    "cloudflare-env.d.ts", "components.json", "drizzle.config.ts", "eslint.config.mjs",
    "next.config.ts", "package.json", "pnpm-lock.yaml",
    "pnpm-workspace.yaml", "postcss.config.mjs", "tsconfig.json", "vite.config.ts",
    "worker.ts",
}

# Next and Vinext generate this ignored file in a working checkout. Package the
# canonical generated form without making release bytes depend on local build
# state or an untracked file.
GENERATED_ROOT_FILES = {
    PurePosixPath("next-env.d.ts"): b"""/// <reference types=\"next\" />
/// <reference types=\"next/image-types/global\" />
import \"vinext/types/augmentations\";
import \"./.next/types/routes.d.ts\";

// NOTE: This file should not be edited
// see https://nextjs.org/docs/app/api-reference/config/typescript for more information.
""",
}

SOURCE_DIRECTORIES = {
    ".openai", "app", "build", "components", "db", "docs", "drizzle",
    "hooks", "ios", "lib", "public", "release", "scripts", "selfhost", "tests", "vendor",
}

# Qualification evidence is committed for release authorization but is never
# distributed inside either release ZIP. The self-host archive embeds this
# source ZIP, so this one exclusion covers both package formats.
EXCLUDED_SEGMENTS = {"__pycache__", "downloads", "qualification", "xcuserdata"}
EXCLUDED_SUFFIXES = SENSITIVE_RELEASE_SUFFIXES | {
    ".env", ".pyc", ".tsbuildinfo", ".xcuserstate", ".zip",
}
EXCLUDED_FILES = {PurePosixPath("docs/validation.json")}


def include_source_directory(relative: PurePosixPath) -> bool:
    return not any(part in EXCLUDED_SEGMENTS for part in relative.parts)


def include_source_file(relative: PurePosixPath) -> bool:
    if not include_source_directory(relative):
        return False
    if relative in EXCLUDED_FILES:
        return False
    if relative.name.startswith(".env") and relative.name != ".env.example":
        return False
    return relative.suffix.lower() not in EXCLUDED_SUFFIXES


def release_entries(
    root: Path,
    *,
    root_files: set[str] = ROOT_FILES,
    source_directories: set[str] = SOURCE_DIRECTORIES,
) -> list[tuple[PurePosixPath, bytes, int]]:
    entries: dict[PurePosixPath, tuple[bytes, int]] = {
        path: (data, 0o644) for path, data in GENERATED_ROOT_FILES.items()
    }
    with SafeRoot(root) as reader:
        for name in sorted(root_files):
            relative = PurePosixPath(name)
            try:
                data, mode = reader.read_regular(relative)
            except FileNotFoundError as error:
                raise FileNotFoundError(f"Required release source is missing: {name}") from error
            entries[relative] = (data, mode)

        for name in sorted(source_directories):
            directory = PurePosixPath(name)
            try:
                files = reader.iter_regular_files(
                    directory,
                    include_file=include_source_file,
                    descend_into=include_source_directory,
                )
            except FileNotFoundError as error:
                raise FileNotFoundError(f"Required release source directory is missing: {name}") from error
            try:
                for relative, data, mode in files:
                    entries[relative] = (data, mode)
            except FileNotFoundError as error:
                raise FileNotFoundError(
                    f"Required release source directory changed while reading: {name}"
                ) from error

    if not entries:
        raise ValueError("Release source allowlist produced no files.")
    return [(path, *entries[path]) for path in sorted(entries, key=lambda item: item.as_posix())]


def archive_info(path: PurePosixPath, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo((ARCHIVE_ROOT / path).as_posix())
    info.date_time = (1980, 1, 1, 0, 0, 0)
    info.compress_type = zipfile.ZIP_DEFLATED
    canonical_mode = 0o755 if mode & 0o111 else 0o644
    info.external_attr = canonical_mode << 16
    info.create_system = 3
    return info


def build(root: Path, output: Path) -> tuple[int, int]:
    entries = release_entries(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix="Local-Sandbox-Source-", suffix=".zip", dir=output.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)

    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=7) as archive:
            for relative, data, mode in entries:
                archive.writestr(archive_info(relative, mode), data)
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise ValueError("Release source archive failed its CRC check.")
            names = archive.namelist()
            required = "Local-Sandbox/ios/LocalSandbox.xcodeproj/project.pbxproj"
            if required not in names:
                raise ValueError(f"Release source archive is missing {required}.")
            if len(names) != len(set(names)):
                raise ValueError("Release source archive contains duplicate paths.")
        temporary.chmod(0o644)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)

    return len(entries), output.stat().st_size


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    root = options.root.absolute()
    output = options.output or root / "public/downloads/Local-Sandbox-Source.zip"
    file_count, byte_count = build(root, output)
    print(json.dumps({"archive": str(output), "files": file_count, "bytes": byte_count}))


if __name__ == "__main__":
    main()
