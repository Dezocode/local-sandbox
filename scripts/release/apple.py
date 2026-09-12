#!/usr/bin/env python3
"""Build or install locally, and gate archive/upload on canonical release evidence."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import Iterator, NamedTuple


ROOT = Path(__file__).resolve().parents[2]
RELEASE_VERSION = "0.3.0"
FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
INSTALL_BUILD_NUMBER = re.compile(r"[1-9][0-9]{0,17}")
RELEASE_BUILD_NUMBER = re.compile(r"[1-9][0-9]{0,3}\.[1-9][0-9]?\.0")
ACTION_READINESS_RECEIPT = "release-output/apple-action-readiness-receipt.json"
RELEASE_EVIDENCE = "release-output/apple-release-evidence.json"
REQUIRED_XCODE_VERSION = "27.0"
REQUIRED_XCODE_BUILD = "27A266a"
ACTION_READINESS_ENVIRONMENT = "LS_APPLE_ACTION_READINESS_JSON"
GIT_EXECUTABLE = Path("/usr/bin/git")
XCODE_SELECT_EXECUTABLE = Path("/usr/bin/xcode-select")
XCRUN_EXECUTABLE = Path("/usr/bin/xcrun")


class PinnedXcode(NamedTuple):
    executable: Path
    developer_directory: Path
    identity: tuple[int, int, int, int]
    version: str
    build: str


def run(arguments: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    subprocess.run(arguments, cwd=cwd, env=env, check=True)


def xcode_environment(base_environment: dict[str, str], toolchain: PinnedXcode) -> dict[str, str]:
    environment = dict(base_environment)
    environment["DEVELOPER_DIR"] = str(toolchain.developer_directory)
    return environment


def executable_identity(path: Path) -> tuple[int, int, int, int]:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
        raise RuntimeError(f"Pinned Xcode executable is not an executable regular file: {path}")
    return metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns


def parse_release_xcode_output(output: str) -> tuple[str, str]:
    match = re.fullmatch(r"Xcode ([^\r\n]+)\r?\nBuild version ([^\r\n]+)\r?\n?", output)
    if match is None:
        raise RuntimeError("xcodebuild -version returned an unexpected format.")
    version, build = match.groups()
    if version != REQUIRED_XCODE_VERSION or build != REQUIRED_XCODE_BUILD:
        raise RuntimeError(
            f"Archive and upload require Xcode {REQUIRED_XCODE_VERSION} build "
            f"{REQUIRED_XCODE_BUILD}; received Xcode {version} build {build}."
        )
    return version, build


def release_xcode_toolchain(environment: dict[str, str]) -> PinnedXcode:
    selected = subprocess.run(
        [str(XCODE_SELECT_EXECUTABLE), "-p"],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    developer_directory = Path(selected.stdout.strip()).resolve(strict=True)
    if not developer_directory.is_dir() or not developer_directory.is_absolute():
        raise RuntimeError("xcode-select did not resolve one absolute Developer directory.")
    selected_environment = dict(environment)
    selected_environment["DEVELOPER_DIR"] = str(developer_directory)
    located = subprocess.run(
        [str(XCRUN_EXECUTABLE), "--find", "xcodebuild"],
        cwd=ROOT,
        env=selected_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    executable = Path(located.stdout.strip()).resolve(strict=True)
    if not executable.is_relative_to(developer_directory):
        raise RuntimeError("xcrun resolved xcodebuild outside the selected Developer directory.")
    completed = subprocess.run(
        [str(executable), "-version"],
        cwd=ROOT,
        env=selected_environment,
        check=True,
        capture_output=True,
        text=True,
    )
    print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    version, build = parse_release_xcode_output(completed.stdout)
    return PinnedXcode(
        executable,
        developer_directory,
        executable_identity(executable),
        version,
        build,
    )


def recheck_release_xcode(toolchain: PinnedXcode, environment: dict[str, str]) -> None:
    if executable_identity(toolchain.executable) != toolchain.identity:
        raise RuntimeError("The pinned Xcode executable changed after release authorization.")
    completed = subprocess.run(
        [str(toolchain.executable), "-version"],
        cwd=ROOT,
        env=xcode_environment(environment, toolchain),
        check=True,
        capture_output=True,
        text=True,
    )
    if parse_release_xcode_output(completed.stdout) != (toolchain.version, toolchain.build):
        raise RuntimeError("The pinned Xcode toolchain changed after release authorization.")


@contextmanager
def immutable_source_snapshot(
    release_commit: str,
    environment: dict[str, str],
) -> Iterator[Path]:
    snapshot = Path(tempfile.mkdtemp(prefix="LocalSandbox-Apple-Source-"))
    try:
        archive = subprocess.run(
            [str(GIT_EXECUTABLE), "archive", "--format=tar", release_commit],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
            seen: set[Path] = set()
            for member in source.getmembers():
                relative = Path(member.name)
                if relative.is_absolute() or not relative.parts or ".." in relative.parts:
                    raise RuntimeError("The release commit contains an unsafe archive path.")
                destination = snapshot.joinpath(*relative.parts)
                if destination in seen:
                    raise RuntimeError("The release commit contains a duplicate archive path.")
                seen.add(destination)
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise RuntimeError("The release commit contains a non-regular archive member.")
                destination.parent.mkdir(parents=True, exist_ok=True)
                stream = source.extractfile(member)
                if stream is None:
                    raise RuntimeError("Could not read a release snapshot member.")
                with destination.open("xb") as handle:
                    shutil.copyfileobj(stream, handle)
                destination.chmod(0o555 if member.mode & 0o111 else 0o444)
        for directory, directories, _files in os.walk(snapshot, topdown=False):
            for name in directories:
                (Path(directory) / name).chmod(0o555)
        snapshot.chmod(0o555)
        yield snapshot
    finally:
        if snapshot.exists():
            for directory, directories, _files in os.walk(snapshot):
                Path(directory).chmod(0o700)
                for name in directories:
                    (Path(directory) / name).chmod(0o700)
            shutil.rmtree(snapshot)


def require_release_authorization(
    *,
    stage: str,
    release_commit: str,
    release_version: str,
    build_number: str,
    toolchain: PinnedXcode,
    readiness_json: str | None,
    environment: dict[str, str],
) -> None:
    authorization_environment = dict(environment)
    if readiness_json is not None:
        authorization_environment[ACTION_READINESS_ENVIRONMENT] = readiness_json
    try:
        run(
            [
                "node",
                "scripts/release/apple_ci.mjs",
                "authorize",
                "--release-commit",
                release_commit,
                "--release-version",
                release_version,
                "--build-number",
                build_number,
                "--stage",
                stage,
                "--validation",
                "docs/validation.json",
                "--evidence",
                RELEASE_EVIDENCE,
                "--receipt",
                ACTION_READINESS_RECEIPT,
                "--xcode-version",
                toolchain.version,
                "--xcode-build",
                toolchain.build,
            ],
            cwd=ROOT,
            env=authorization_environment,
        )
    finally:
        authorization_environment.pop(ACTION_READINESS_ENVIRONMENT, None)


def main(arguments: list[str] | None = None) -> None:
    readiness_json = os.environ.pop(ACTION_READINESS_ENVIRONMENT, None)
    child_environment = dict(os.environ)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=["check", "test", "install", "archive", "upload"])
    parser.add_argument("--team")
    parser.add_argument("--bundle-id", default="com.dezocode.LocalSandbox")
    parser.add_argument("--device")
    parser.add_argument("--simulator")
    parser.add_argument("--build-number", default="4")
    parser.add_argument("--release-commit")
    parser.add_argument("--release-version", default=RELEASE_VERSION)
    options = parser.parse_args(arguments)

    if platform.system() != "Darwin":
        raise RuntimeError("Run this on your Mac with Xcode. No Apple build was performed.")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", options.bundle_id):
        raise ValueError("Invalid bundle ID.")
    if options.stage in {"archive", "upload"}:
        if not options.release_commit or FULL_COMMIT.fullmatch(options.release_commit) is None:
            raise ValueError("Archive and upload require --release-commit with the selected full commit.")
        if options.release_version != RELEASE_VERSION:
            raise ValueError(f"Archive and upload require release version {RELEASE_VERSION}.")
        if RELEASE_BUILD_NUMBER.fullmatch(options.build_number) is None:
            raise ValueError("Archive and upload require the canonical run.attempt.0 build number.")
    elif INSTALL_BUILD_NUMBER.fullmatch(options.build_number) is None:
        raise ValueError("Install build number must be a canonical positive integer.")

    if options.stage not in {"check", "test"}:
        if not options.team or re.fullmatch(r"[A-Z0-9]{10}", options.team) is None:
            raise ValueError("Supply your 10-character Apple Developer team ID.")

    release_toolchain: PinnedXcode | None = None
    if options.stage in {"archive", "upload"}:
        release_toolchain = release_xcode_toolchain(child_environment)
        require_release_authorization(
            stage=options.stage,
            release_commit=options.release_commit,
            release_version=options.release_version,
            build_number=options.build_number,
            toolchain=release_toolchain,
            readiness_json=readiness_json,
            environment=child_environment,
        )
        readiness_json = None
        recheck_release_xcode(release_toolchain, child_environment)
        release_environment = xcode_environment(child_environment, release_toolchain)
        run(
            [str(release_toolchain.executable), "-showsdks"],
            cwd=ROOT,
            env=release_environment,
        )
    else:
        run(["xcodebuild", "-version"], cwd=ROOT, env=child_environment)
        run(["xcodebuild", "-showsdks"], cwd=ROOT, env=child_environment)
    if options.stage == "check":
        run(["/usr/bin/shortcuts", "--help"], cwd=ROOT, env=child_environment)
        return

    output_root = ROOT / "release-output"
    output_root.mkdir(exist_ok=True)
    base = ["xcodebuild", "-project", "ios/LocalSandbox.xcodeproj", "-scheme", "LocalSandbox"]
    if options.stage == "test":
        if not options.simulator:
            raise ValueError(
                "Supply --simulator with an available iPhone simulator UDID from xcrun simctl list devices available."
            )
        run(
            base
            + [
                "-destination",
                "platform=iOS Simulator,id=" + options.simulator,
                "CODE_SIGNING_ALLOWED=NO",
                "test",
            ],
            cwd=ROOT,
            env=child_environment,
        )
        return

    authentication = []
    key_names = ["LS_ASC_KEY_PATH", "LS_ASC_KEY_ID", "LS_ASC_ISSUER_ID"]
    if any(child_environment.get(name) for name in key_names):
        if not all(child_environment.get(name) for name in key_names):
            raise ValueError(
                "Set all three LS_ASC key environment values, or use your Xcode account."
            )
        authentication = [
            "-authenticationKeyPath",
            child_environment[key_names[0]],
            "-authenticationKeyID",
            child_environment[key_names[1]],
            "-authenticationKeyIssuerID",
            child_environment[key_names[2]],
        ]
    signing = [
        "DEVELOPMENT_TEAM=" + options.team,
        "PRODUCT_BUNDLE_IDENTIFIER=" + options.bundle_id,
        "CURRENT_PROJECT_VERSION=" + options.build_number,
        "-allowProvisioningUpdates",
        *authentication,
    ]
    if options.stage == "install":
        if not options.device:
            raise ValueError("Supply --device from xcrun devicectl list devices.")
        derived = output_root / "device-build"
        run(
            base
            + [
                "-configuration",
                "Debug",
                "-destination",
                "id=" + options.device,
                "-derivedDataPath",
                str(derived),
                *signing,
                "build",
            ],
            cwd=ROOT,
            env=child_environment,
        )
        run(
            [
                str(XCRUN_EXECUTABLE),
                "devicectl",
                "device",
                "install",
                "app",
                "--device",
                options.device,
                str(derived / "Build/Products/Debug-iphoneos/LocalSandbox.app"),
            ],
            cwd=ROOT,
            env=child_environment,
        )
        return

    archive = output_root / f"LocalSandbox-{options.build_number}.xcarchive"
    if archive.exists():
        raise FileExistsError("Archive already exists. Use a new build number; prior artifacts are preserved.")
    assert release_toolchain is not None
    release_environment = xcode_environment(child_environment, release_toolchain)
    derived = output_root / f"archive-derived-{options.build_number}"
    with immutable_source_snapshot(options.release_commit, child_environment) as source_root:
        recheck_release_xcode(release_toolchain, child_environment)
        release_base = [
            str(release_toolchain.executable),
            "-project",
            "ios/LocalSandbox.xcodeproj",
            "-scheme",
            "LocalSandbox",
        ]
        run(
            release_base
            + [
                "-configuration",
                "Release",
                "-destination",
                "generic/platform=iOS",
                "-derivedDataPath",
                str(derived),
                "-archivePath",
                str(archive),
                *signing,
                "archive",
            ],
            cwd=source_root,
            env=release_environment,
        )
        export_options = {
            "method": "app-store-connect",
            "teamID": options.team,
            "signingStyle": "automatic",
            "destination": "upload" if options.stage == "upload" else "export",
            "manageAppVersionAndBuildNumber": False,
            "uploadSymbols": True,
        }
        export = output_root / f"ExportOptions-{options.build_number}.plist"
        export.write_bytes(plistlib.dumps(export_options))
        recheck_release_xcode(release_toolchain, child_environment)
        run(
            [
                str(release_toolchain.executable),
                "-exportArchive",
                "-archivePath",
                str(archive),
                "-exportPath",
                str(output_root / f"export-{options.build_number}"),
                "-exportOptionsPlist",
                str(export),
                "-allowProvisioningUpdates",
                *authentication,
            ],
            cwd=source_root,
            env=release_environment,
        )
    print(
        json.dumps(
            {
                "stage": options.stage,
                "archive": str(archive),
                "appReviewApproved": False,
                "next": (
                    "Check App Store Connect processing, test on device, complete metadata, "
                    "then submit for review."
                ),
            }
        )
    )


if __name__ == "__main__":
    main()
