#!/usr/bin/env python3
"""Fail closed when release ZIPs contain unsafe paths, local state, or stale payloads."""

from __future__ import annotations

from argparse import ArgumentParser
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

from release_common import SENSITIVE_RELEASE_SUFFIXES, read_external_regular


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "public/downloads/Local-Sandbox-Source.zip"
SELFHOST = ROOT / "public/downloads/Local-Sandbox-Selfhost.zip"

FORBIDDEN_SEGMENTS = {
    ".agents", ".codex", ".git", ".next", ".sites-runtime", ".vinext", ".wrangler",
    "__pycache__", "node_modules", "private-exports", "release-output", "xcuserdata",
}
FORBIDDEN_SUFFIXES = SENSITIVE_RELEASE_SUFFIXES | {
    ".pyc", ".tsbuildinfo", ".xcuserstate",
}
HOME_ACCOUNT = rb"[A-Za-z0-9._-]+"
HOME_ACCOUNT_END = rb"(?=[/\\\x00\r\n\s]|$)"
LOCAL_PATH = re.compile(
    b"(?:"
    + b"/" + b"Users/" + HOME_ACCOUNT + HOME_ACCOUNT_END
    + b"|/" + b"home/" + HOME_ACCOUNT + HOME_ACCOUNT_END
    + b"|" + rb"[A-Za-z]:[\\/]" + b"Users" + rb"[\\/]"
    + HOME_ACCOUNT + HOME_ACCOUNT_END
    + b")"
)
TOKEN = re.compile(rb"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})")
SCAN_CHUNK_BYTES = 1024 * 1024
SCAN_OVERLAP_BYTES = 256
HOSTED_CAPABILITIES = {
    "schemaVersion": 1,
    "mode": "hosted",
    "githubDirect": True,
    "cursorOrigin": True,
    "encryptedWorkspaceSync": True,
}
STATIC_CAPABILITIES = {
    "schemaVersion": 1,
    "mode": "static-selfhost",
    "githubDirect": True,
    "cursorOrigin": False,
    "encryptedWorkspaceSync": False,
}


def safe_member(info: zipfile.ZipInfo, *, nested: bool = False) -> None:
    path = PurePosixPath(info.filename)
    if path.is_absolute() or ".." in path.parts or "" in path.parts:
        raise ValueError(f"Unsafe archive path: {info.filename}")
    if any(part in FORBIDDEN_SEGMENTS for part in path.parts):
        raise ValueError(f"Local-only state entered the archive: {info.filename}")
    if path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError(f"Credential-like file entered the archive: {info.filename}")
    if path.name.startswith(".env") and path.name != ".env.example":
        raise ValueError(f"Environment file entered the archive: {info.filename}")
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise ValueError(f"Symlink entered the archive: {info.filename}")
    if nested and path.suffix.lower() == ".zip":
        raise ValueError(f"Unexpected nested ZIP: {info.filename}")


def scan_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, label: str) -> None:
    """Stream every member so suffixes and file size cannot bypass secret checks."""
    if info.is_dir():
        return
    tail = b""
    with archive.open(info) as handle:
        while True:
            chunk = handle.read(SCAN_CHUNK_BYTES)
            if not chunk:
                break
            window = tail + chunk
            if LOCAL_PATH.search(window):
                raise ValueError(f"Machine-specific home path entered {label}: {info.filename}")
            if TOKEN.search(window):
                raise ValueError(f"Credential-shaped token entered {label}: {info.filename}")
            tail = window[-SCAN_OVERLAP_BYTES:]


def audit_zip(data: bytes, label: str, *, nested: bool = False) -> tuple[list[str], int]:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        bad_crc = archive.testzip()
        if bad_crc is not None:
            raise ValueError(f"{label} failed CRC at {bad_crc}")
        infos = archive.infolist()
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise ValueError(f"{label} contains duplicate paths")
        if len(infos) > 10_000:
            raise ValueError(f"{label} contains too many files")
        total = sum(item.file_size for item in infos)
        if total > 100 * 1024 * 1024:
            raise ValueError(f"{label} expands beyond 100 MiB")
        for info in infos:
            safe_member(info, nested=nested)
            scan_member(archive, info, label)
        return names, total


def require_json_member(data: bytes, member: str, expected: object, label: str) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        try:
            raw = archive.read(member)
        except KeyError as error:
            raise ValueError(f"{label} is missing {member}") from error
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} has a malformed capability manifest") from error
    if value != expected:
        raise ValueError(f"{label} capability manifest differs from the required deployment boundary")


def audit_artifacts(source: Path, selfhost: Path) -> dict[str, object]:
    if not source.is_file() or not selfhost.is_file():
        raise FileNotFoundError("Build both release ZIPs before auditing them.")

    source_data, _source_mode = read_external_regular(source)
    source_names, source_bytes = audit_zip(source_data, "source archive", nested=True)
    selfhost_data, _selfhost_mode = read_external_regular(selfhost)
    selfhost_names, selfhost_bytes = audit_zip(selfhost_data, "self-host archive")

    required_source = {
        "Local-Sandbox/package.json",
        "Local-Sandbox/ios/LocalSandbox.xcodeproj/project.pbxproj",
        "Local-Sandbox/public/local/capabilities.js",
        "Local-Sandbox/public/local/capabilities.json",
        "Local-Sandbox/public/local/workspace-sync.js",
    }
    missing_source = required_source.difference(source_names)
    if missing_source:
        raise ValueError(f"Source archive is missing: {sorted(missing_source)}")
    require_json_member(
        source_data,
        "Local-Sandbox/public/local/capabilities.json",
        HOSTED_CAPABILITIES,
        "source archive",
    )

    required_selfhost = {
        "site/local/capabilities.js",
        "site/local/capabilities.json",
    }
    missing_selfhost = required_selfhost.difference(selfhost_names)
    if missing_selfhost:
        raise ValueError(f"Self-host archive is missing: {sorted(missing_selfhost)}")
    if any(PurePosixPath(name).parts[:2] == ("site", "api") for name in selfhost_names):
        raise ValueError("Static self-host archive must not contain /api routes.")
    require_json_member(
        selfhost_data,
        "site/local/capabilities.json",
        STATIC_CAPABILITIES,
        "self-host archive",
    )

    nested_name = "site/downloads/Local-Sandbox-Source.zip"
    if nested_name not in selfhost_names:
        raise ValueError("Self-host archive is missing the source ZIP.")
    with zipfile.ZipFile(io.BytesIO(selfhost_data)) as archive:
        nested_data = archive.read(nested_name)
    if nested_data != source_data:
        raise ValueError("Self-host archive contains a stale source ZIP.")
    audit_zip(nested_data, "nested source archive", nested=True)
    require_json_member(
        nested_data,
        "Local-Sandbox/public/local/capabilities.json",
        HOSTED_CAPABILITIES,
        "nested source archive",
    )

    return {
        "status": "passed",
        "sourceFiles": len(source_names),
        "sourceBytes": source_bytes,
        "selfhostFiles": len(selfhost_names),
        "selfhostBytes": selfhost_bytes,
    }


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--source-artifact", type=Path, default=SOURCE)
    parser.add_argument("--selfhost-artifact", type=Path, default=SELFHOST)
    options = parser.parse_args()
    print(json.dumps(audit_artifacts(
        options.source_artifact.absolute(),
        options.selfhost_artifact.absolute(),
    )))


if __name__ == "__main__":
    main()
