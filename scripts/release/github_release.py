#!/usr/bin/env python3
"""Fail-closed GitHub publication preflight for Local Sandbox v0.3.0."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
from typing import Any, NoReturn, Sequence
from urllib.parse import urlsplit
import zipfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(ROOT / "scripts"))

from release_common import SafeRoot, read_external_regular  # noqa: E402
from release.candidate_digest import CandidateDigestError, candidate_digest  # noqa: E402
from release.shortcuts import parse_recipe  # noqa: E402
from release.tracker import (  # noqa: E402
    CANONICAL_SNAPSHOT_PATH,
    CANONICAL_TRACKER_PATH,
    TrackerBundle,
    TrackerError,
    assert_profile as assert_tracker_profile,
    verify_binding as verify_tracker_binding,
    verify_readiness_gates as verify_tracker_gates,
    verify_tracker_bundle,
)


VERSION = "0.3.0"
TAG = "v0.3.0"
EXPECTED_GATE_IDS = (
    "GOV-01", "SRC-01", "SRC-02", "SRC-03", "VER-01",
    "ENV-00", "ENV-01", "ENV-02", "ENV-03", "ENV-04",
    "BASE-01", "BASE-02", "BASE-03",
    "NAT-01", "NAT-02", "NAT-03", "NAT-04", "NAT-05", "NAT-06",
    "PROV-01", "PROV-02", "PROV-03", "PROV-04", "PROV-05", "PROV-06",
    "RUN-01", "RUN-02", "RUN-03", "RUN-04", "RUN-05", "RUN-06",
    "PKG-01", "PKG-02", "PKG-03",
    "PWA-01", "PWA-02", "PWA-03", "PWA-04",
    "AUTH-01", "SYNC-01", "KEY-01", "AUTOSAVE-01",
    "PWA-CONN-01", "PWA-CONN-02", "BG-01", "VERIFY-01",
    "GH-01", "GH-02", "ICLOUD-01", "PRIV-01",
    "REL-01", "REL-02", "REL-03", "REL-04", "REL-05", "REL-06", "REL-07",
)
EXPECTED_GATE_ID_SET = frozenset(EXPECTED_GATE_IDS)
GATE_COUNT = len(EXPECTED_GATE_IDS)
GITHUB_ACTION_GATE_ID = "REL-06"
GITHUB_READY_GATE_COUNT = GATE_COUNT - 1
GITHUB_READY_PERCENT = 98.24561403508771
RELEASE_TITLE = f"Local Sandbox {TAG}"
COMPLETION_RECEIPT_NAME = "REL-06-completion-receipt.json"
MAX_QUALIFICATION_AGE = timedelta(hours=24)
FUTURE_CLOCK_SKEW = timedelta(minutes=5)
ARTIFACT_PATHS = (
    PurePosixPath("public/downloads/Local-Sandbox-Source.zip"),
    PurePosixPath("public/downloads/Local-Sandbox-Selfhost.zip"),
    PurePosixPath("public/downloads/Local-Sandbox-Setup-Guide.pdf"),
)
VALIDATION_PATH = PurePosixPath("docs/validation.json")
SHORTCUT_CATALOG_PATH = PurePosixPath("public/shortcuts/catalog.json")
SHORTCUT_RECIPE_PATH = PurePosixPath("release/shortcuts/recipe.json")
SIGNED_SHORTCUT_STATUS = "signed-awaiting-device-acceptance"
OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\Z")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,100}\Z")
SHA_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
SHORTCUT_ID_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,40}\Z")
SHORTCUT_NAME_PATTERN = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]{0,78}[\x21-\x7e])?\Z")
DNS_LABEL_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
VERIFICATION_CHECKS_PATH = ROOT / "scripts/release/verification-checks.json"


def load_verification_checks() -> tuple[str, ...]:
    try:
        raw = json.loads(VERIFICATION_CHECKS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Could not load the release verification check contract") from error
    if (
        not isinstance(raw, list)
        or len(raw) != 41
        or any(not isinstance(label, str) or not label for label in raw)
        or len(raw) != len(set(raw))
    ):
        raise RuntimeError("Release verification check contract is malformed")
    return tuple(raw)


EXPECTED_AUTOMATED_CHECKS = load_verification_checks()
EXPECTED_AUTOMATED_CHECK_SET = frozenset(EXPECTED_AUTOMATED_CHECKS)
TRACKER_CHECK_LABEL = "Release qualification tracker"


class PreflightError(RuntimeError):
    """Raised when publication evidence or state is unsafe."""


@dataclass(frozen=True)
class Artifact:
    path: PurePosixPath
    data: bytes
    sha256: str
    size: int

    @property
    def name(self) -> str:
        return self.path.name


@dataclass(frozen=True)
class StagedFile:
    path: Path
    data: bytes


@dataclass(frozen=True)
class ActionReadiness:
    path: Path
    data: bytes
    sha256: str
    ready_at: datetime


@dataclass(frozen=True)
class ShortcutPackage:
    identifier: str
    name: str
    url: str
    sha256: str
    size: int
    requires: tuple[str, ...]


@dataclass(frozen=True)
class ShortcutCatalog:
    sha256: str
    origin: str
    packages: tuple[ShortcutPackage, ...]


@dataclass(frozen=True)
class Options:
    owner: str
    repository: str
    visibility: str
    expected_commit: str
    tag: str
    tracker: Path
    action_readiness: Path
    execute: bool

    @property
    def target(self) -> str:
        return f"{self.owner}/{self.repository}"


def fail(message: str) -> NoReturn:
    raise PreflightError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains a duplicate key: {key}")
        result[key] = value
    return result


def reject_json_constant(value: str) -> NoReturn:
    fail(f"JSON contains a non-finite number: {value}")


def parse_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PreflightError(f"{label} is not UTF-8 JSON") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_json_constant,
        )
    except (json.JSONDecodeError, PreflightError) as error:
        if isinstance(error, PreflightError):
            raise
        raise PreflightError(f"{label} is not valid JSON: {error.msg}") from error
    if not isinstance(value, dict):
        fail(f"{label} must contain one JSON object")
    return value


def require_object(container: dict[str, Any], key: str, label: str) -> dict[str, Any]:
    value = container.get(key)
    if not isinstance(value, dict):
        fail(f"{label}.{key} must be an object")
    return value


def require_list(container: dict[str, Any], key: str, label: str) -> list[Any]:
    value = container.get(key)
    if not isinstance(value, list):
        fail(f"{label}.{key} must be an array")
    return value


def require_string(container: dict[str, Any], key: str, label: str) -> str:
    value = container.get(key)
    if not isinstance(value, str) or not value.strip():
        fail(f"{label}.{key} must be a non-empty string")
    return value


def require_integer(container: dict[str, Any], key: str, label: str) -> int:
    value = container.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        fail(f"{label}.{key} must be an integer")
    return value


def require_boolean(container: dict[str, Any], key: str, label: str) -> bool:
    value = container.get(key)
    if not isinstance(value, bool):
        fail(f"{label}.{key} must be a boolean")
    return value


def parse_timestamp(value: str, label: str) -> datetime:
    candidate = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as error:
        raise PreflightError(f"{label} must be an ISO 8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        fail(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def run(
    command: Sequence[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            cwd=cwd,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as error:
        raise PreflightError(f"Could not run {command[0]}: {error}") from error


def checked(
    command: Sequence[str],
    *,
    cwd: Path = ROOT,
    env: dict[str, str] | None = None,
) -> str:
    result = run(command, cwd=cwd, env=env)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        fail(f"Command failed: {' '.join(command)}\n{detail}")
    return result.stdout.strip()


def checked_json(command: Sequence[str], label: str) -> dict[str, Any]:
    output = checked(command)
    return parse_json(output.encode("utf-8"), label)


def checked_bytes(command: Sequence[str]) -> bytes:
    try:
        result = subprocess.run(
            list(command),
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
    except OSError as error:
        raise PreflightError(f"Could not run {command[0]}: {error}") from error
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        detail = stderr or stdout or f"exit {result.returncode}"
        fail(f"Command failed: {' '.join(command)}\n{detail}")
    return result.stdout


def validate_options(options: Options) -> None:
    if OWNER_PATTERN.fullmatch(options.owner) is None or options.owner.endswith("-"):
        fail("--owner is not a valid GitHub owner")
    if (
        REPOSITORY_PATTERN.fullmatch(options.repository) is None
        or options.repository in {".", ".."}
    ):
        fail("--repo is not a valid GitHub repository name")
    if options.visibility not in {"private", "public"}:
        fail("--visibility must be private or public")
    if SHA_PATTERN.fullmatch(options.expected_commit) is None:
        fail("--expected-commit must be one full lowercase 40-character commit SHA")
    if options.tag != TAG:
        fail(f"Only --tag {TAG} can be published by this release script")


def verify_git_state(options: Options) -> None:
    top_level = checked(["git", "rev-parse", "--show-toplevel"])
    if Path(top_level).resolve() != ROOT:
        fail(f"The script must run against its own Git worktree: {ROOT}")

    head = checked(["git", "rev-parse", "--verify", "HEAD^{commit}"])
    if head != options.expected_commit:
        fail(
            "HEAD does not equal --expected-commit. Commit the complete 0.3 change set "
            "and pass that new commit SHA; the pre-0.3 base commit cannot be published."
        )

    status = checked(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        fail(
            "The Git worktree is not clean. Publication refuses tracked, staged, or "
            "untracked changes so it cannot publish an older base commit."
        )

    local_tag = run(["git", "show-ref", "--verify", "--quiet", f"refs/tags/{TAG}"])
    if local_tag.returncode == 0:
        fail(f"Local tag {TAG} already exists")
    if local_tag.returncode != 1:
        fail(f"Could not establish whether local tag {TAG} exists")


def read_release_inputs() -> tuple[dict[str, Any], bytes, tuple[Artifact, ...], bytes, bytes]:
    with SafeRoot(ROOT) as reader:
        package_data, _mode = reader.read_regular("package.json")
        validation_data, _mode = reader.read_regular(VALIDATION_PATH)
        shortcut_catalog_data, _mode = reader.read_regular(SHORTCUT_CATALOG_PATH)
        shortcut_recipe_data, _mode = reader.read_regular(SHORTCUT_RECIPE_PATH)
        artifacts = tuple(
            Artifact(path, data, sha256(data), len(data))
            for path in ARTIFACT_PATHS
            for data, _mode in [reader.read_regular(path)]
        )

    package = parse_json(package_data, "package.json")
    if package.get("version") != VERSION:
        fail(f"package.json must contain version {VERSION}")
    return (
        parse_json(validation_data, os.fspath(VALIDATION_PATH)),
        validation_data,
        artifacts,
        shortcut_catalog_data,
        shortcut_recipe_data,
    )


def git_blob(commit: str, relative: PurePosixPath) -> bytes:
    try:
        result = subprocess.run(
            ["git", "show", f"{commit}:{relative.as_posix()}"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise PreflightError(f"Could not read committed {relative}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        fail(f"Could not read committed {relative}: {detail or f'exit {result.returncode}'}")
    return result.stdout


def read_tracker(options: Options) -> TrackerBundle:
    expected = ROOT / CANONICAL_TRACKER_PATH
    supplied = options.tracker if options.tracker.is_absolute() else ROOT / options.tracker
    if Path(os.path.abspath(supplied)) != Path(os.path.abspath(expected)):
        fail(f"--tracker must be {CANONICAL_TRACKER_PATH}")
    tracker_data, _mode = read_external_regular(expected)
    snapshot_data, _mode = read_external_regular(ROOT / CANONICAL_SNAPSHOT_PATH)
    committed_tracker = git_blob(options.expected_commit, CANONICAL_TRACKER_PATH)
    committed_snapshot = git_blob(options.expected_commit, CANONICAL_SNAPSHOT_PATH)
    if tracker_data != committed_tracker:
        fail(f"{CANONICAL_TRACKER_PATH} differs from --expected-commit")
    if snapshot_data != committed_snapshot:
        fail(f"{CANONICAL_SNAPSHOT_PATH} differs from --expected-commit")
    try:
        committed_bundle = verify_tracker_bundle(committed_tracker, committed_snapshot)
        current_bundle = verify_tracker_bundle(tracker_data, snapshot_data)
    except TrackerError as error:
        raise PreflightError(f"Qualification tracker verification failed: {error}") from error
    if committed_bundle != current_bundle:
        fail("Current and committed tracker verification results differ")
    return committed_bundle


def verify_artifact_freshness() -> None:
    release_python = os.environ.get("LOCAL_SANDBOX_RELEASE_PYTHON") or sys.executable
    checked([release_python, "scripts/release/check_python.py"])
    checked([release_python, "scripts/release/check_freshness.py"])
    checked([release_python, "scripts/audit-release-artifacts.py"])


def validate_automated_verification(
    validation: dict[str, Any],
    tracker: TrackerBundle,
    *,
    now: datetime | None = None,
) -> tuple[datetime, str]:
    if validation.get("recordType") != "local-sandbox-release-validation":
        fail("docs/validation.json has the wrong recordType")
    if validation.get("schemaVersion") != 1:
        fail("docs/validation.json has an unsupported schemaVersion")
    if validation.get("version") != VERSION:
        fail(f"docs/validation.json must cover version {VERSION}")
    automated = require_object(validation, "automatedVerification", "validation")
    if automated.get("status") != "passed":
        fail("docs/validation.json automatedVerification.status must be passed")
    checks = require_list(automated, "checks", "validation.automatedVerification")
    if not checks:
        fail("docs/validation.json must contain the automated checks that passed")
    passed_labels: list[str] = []
    seen_labels: set[str] = set()
    for index, raw_check in enumerate(checks):
        if not isinstance(raw_check, dict) or raw_check.get("status") != "passed":
            fail(f"docs/validation.json automated check {index + 1} did not pass")
        label = require_string(
            raw_check,
            "label",
            f"validation.automatedVerification.checks[{index}]",
        )
        if label in seen_labels:
            fail(f"docs/validation.json contains duplicate automated check: {label}")
        seen_labels.add(label)
        passed_labels.append(label)
    missing_checks = EXPECTED_AUTOMATED_CHECK_SET - seen_labels
    if missing_checks:
        fail(
            "docs/validation.json is missing required passed checks: "
            + ", ".join(sorted(missing_checks))
        )
    unexpected_checks = seen_labels - EXPECTED_AUTOMATED_CHECK_SET
    if unexpected_checks:
        fail(
            "docs/validation.json contains unexpected automated checks: "
            + ", ".join(sorted(unexpected_checks))
        )
    if tuple(passed_labels) != EXPECTED_AUTOMATED_CHECKS:
        fail("docs/validation.json checks are not in canonical execution order")
    tracker_check = next((
        raw_check for raw_check in checks
        if isinstance(raw_check, dict) and raw_check.get("label") == TRACKER_CHECK_LABEL
    ), None)
    if tracker_check is None:
        fail("docs/validation.json has no qualification tracker check")
    try:
        verify_tracker_binding(
            tracker_check.get("tracker"),
            tracker,
            "docs/validation.json tracker check",
        )
    except TrackerError as error:
        raise PreflightError(str(error)) from error
    generated_at = parse_timestamp(
        require_string(validation, "generatedAt", "validation"),
        "validation.generatedAt",
    )
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("now must include a UTC offset")
    current = current.astimezone(timezone.utc)
    if generated_at > current + FUTURE_CLOCK_SKEW:
        fail("docs/validation.json generatedAt is too far in the future")
    if current - generated_at > MAX_QUALIFICATION_AGE:
        fail("docs/validation.json is older than 24 hours")
    claimed_candidate_digest = require_string(validation, "candidateDigest", "validation")
    if SHA256_PATTERN.fullmatch(claimed_candidate_digest) is None:
        fail("validation.candidateDigest must be one lowercase SHA-256 digest")
    try:
        current_candidate_digest = candidate_digest(ROOT)
    except CandidateDigestError as error:
        raise PreflightError(f"Could not recompute the release candidate digest: {error}") from error
    if claimed_candidate_digest != current_candidate_digest:
        fail("docs/validation.json candidateDigest does not match the current release candidate")
    return generated_at, current_candidate_digest


def validate_artifact_evidence(raw_artifacts: list[Any], artifacts: tuple[Artifact, ...]) -> None:
    evidence_by_path: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_artifacts):
        if not isinstance(raw, dict):
            fail(f"action readiness.artifacts[{index}] must be an object")
        path = require_string(raw, "path", f"action readiness.artifacts[{index}]")
        if path in evidence_by_path:
            fail(f"action readiness.artifacts contains a duplicate path: {path}")
        evidence_by_path[path] = raw

    expected_paths = {artifact.path.as_posix() for artifact in artifacts}
    if set(evidence_by_path) != expected_paths:
        fail("action readiness.artifacts must list exactly the three canonical release artifacts")

    for artifact in artifacts:
        label = f"action readiness.artifacts[{artifact.path.as_posix()}]"
        evidence = evidence_by_path[artifact.path.as_posix()]
        claimed_sha = require_string(evidence, "sha256", label)
        if SHA256_PATTERN.fullmatch(claimed_sha) is None:
            fail(f"{label}.sha256 must be one lowercase SHA-256 digest")
        if claimed_sha != artifact.sha256:
            fail(f"{artifact.path} does not match its qualified SHA-256 digest")
        if require_integer(evidence, "bytes", label) != artifact.size:
            fail(f"{artifact.path} does not match its qualified byte count")


def read_archive_member(archive: zipfile.ZipFile, member: str, label: str) -> bytes:
    try:
        return archive.read(member)
    except KeyError as error:
        raise PreflightError(f"{label} is missing {member}") from error


def canonical_shortcut_package_origin(url: str, identifier: str, label: str) -> str:
    if not url.isascii() or "%" in url or "\\" in url:
        fail(f"{label}.url must be unencoded canonical ASCII")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise PreflightError(f"{label}.url contains an invalid host or port") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or port == 443
    ):
        fail(f"{label}.url must use one canonical credential-free HTTPS origin")

    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if host.endswith(".") or len(host) > 253 or any(
            DNS_LABEL_PATTERN.fullmatch(part) is None for part in host.split(".")
        ):
            fail(f"{label}.url must contain a canonical DNS name or IP address")
        canonical_host = host
    else:
        canonical_host = f"[{address.compressed}]" if address.version == 6 else address.compressed

    authority = canonical_host if port is None else f"{canonical_host}:{port}"
    origin = f"https://{authority}"
    expected_url = f"{origin}/shortcuts/{VERSION}/{identifier}.shortcut"
    if url != expected_url:
        fail(f"{label}.url must be exactly {expected_url}")
    return origin


def validate_shortcut_catalog(
    catalog_data: bytes,
    recipe_data: bytes,
    artifacts: tuple[Artifact, ...],
) -> ShortcutCatalog:
    try:
        recipe_release, recipe_packages = parse_recipe(recipe_data)
    except ValueError as error:
        raise PreflightError(f"{SHORTCUT_RECIPE_PATH} is invalid: {error}") from error
    if recipe_release != VERSION:
        fail(f"{SHORTCUT_RECIPE_PATH} must cover release {VERSION}")
    document = parse_json(catalog_data, os.fspath(SHORTCUT_CATALOG_PATH))
    if set(document) != {"version", "release", "status", "packages"}:
        fail(f"{SHORTCUT_CATALOG_PATH} has missing or unexpected fields")
    if (
        require_integer(document, "version", os.fspath(SHORTCUT_CATALOG_PATH)) != 1
        or document.get("release") != VERSION
    ):
        fail(f"{SHORTCUT_CATALOG_PATH} must cover schema 1 and release {VERSION}")
    if document.get("status") != SIGNED_SHORTCUT_STATUS:
        fail(
            f"{SHORTCUT_CATALOG_PATH} must have status {SIGNED_SHORTCUT_STATUS}; "
            "unsigned or empty catalogs cannot be released"
        )
    raw_packages = require_list(document, "packages", os.fspath(SHORTCUT_CATALOG_PATH))
    if not 1 <= len(raw_packages) <= 30:
        fail(f"{SHORTCUT_CATALOG_PATH} must list between 1 and 30 signed packages")

    packages: list[ShortcutPackage] = []
    package_ids: set[str] = set()
    package_names: set[str] = set()
    publication_origin: str | None = None
    for index, raw_package in enumerate(raw_packages):
        label = f"{SHORTCUT_CATALOG_PATH}.packages[{index}]"
        if not isinstance(raw_package, dict) or set(raw_package) != {
            "bytes", "id", "name", "requires", "sha256", "url"
        }:
            fail(f"{label} has missing or unexpected fields")
        identifier = require_string(raw_package, "id", label)
        if SHORTCUT_ID_PATTERN.fullmatch(identifier) is None or identifier in package_ids:
            fail(f"{label}.id must be unique and use the canonical Shortcut package format")
        package_ids.add(identifier)
        name = require_string(raw_package, "name", label)
        if SHORTCUT_NAME_PATTERN.fullmatch(name) is None or name in package_names:
            fail(f"{label}.name must be unique canonical printable ASCII")
        package_names.add(name)
        url = require_string(raw_package, "url", label)
        package_origin = canonical_shortcut_package_origin(url, identifier, label)
        if publication_origin is None:
            publication_origin = package_origin
        elif package_origin != publication_origin:
            fail(f"{label}.url does not match the catalog publication origin {publication_origin}")
        package_sha = require_string(raw_package, "sha256", label)
        if SHA256_PATTERN.fullmatch(package_sha) is None:
            fail(f"{label}.sha256 must be one lowercase SHA-256 digest")
        package_size = require_integer(raw_package, "bytes", label)
        if not 1 <= package_size <= 5_000_000:
            fail(f"{label}.bytes must be between 1 and 5000000")
        raw_dependencies = require_list(raw_package, "requires", label)
        if any(
            not isinstance(value, str) or SHORTCUT_ID_PATTERN.fullmatch(value) is None
            for value in raw_dependencies
        ):
            fail(f"{label}.requires must contain only canonical package IDs")
        dependencies = tuple(raw_dependencies)
        if len(dependencies) != len(set(dependencies)) or identifier in dependencies:
            fail(f"{label}.requires must contain unique dependencies other than itself")
        packages.append(
            ShortcutPackage(
                identifier=identifier,
                name=name,
                url=url,
                sha256=package_sha,
                size=package_size,
                requires=dependencies,
            )
        )

    by_id = {package.identifier: package for package in packages}
    for package in packages:
        unknown = set(package.requires) - set(by_id)
        if unknown:
            fail(
                f"Shortcut package {package.identifier} has unknown dependencies: "
                + ", ".join(sorted(unknown))
            )
    visited: set[str] = set()
    active: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in active:
            fail(f"Shortcut catalog contains a dependency cycle at {identifier}")
        if identifier in visited:
            return
        active.add(identifier)
        for dependency in by_id[identifier].requires:
            visit(dependency)
        active.remove(identifier)
        visited.add(identifier)

    for package in packages:
        visit(package.identifier)

    expected_roster = [
        (
            row["id"],
            row["name"],
            tuple(row["requires"]),
            f'{row["id"]}.shortcut',
        )
        for row in recipe_packages
    ]
    actual_roster = [
        (
            package.identifier,
            package.name,
            package.requires,
            PurePosixPath(urlsplit(package.url).path).name,
        )
        for package in packages
    ]
    if actual_roster != expected_roster:
        fail(
            f"{SHORTCUT_CATALOG_PATH} package order, IDs, names, dependencies, and files "
            f"must exactly match {SHORTCUT_RECIPE_PATH}"
        )

    artifact_by_name = {artifact.name: artifact for artifact in artifacts}
    archive_layouts = (
        (
            artifact_by_name["Local-Sandbox-Source.zip"],
            "Local-Sandbox/public/shortcuts",
        ),
        (
            artifact_by_name["Local-Sandbox-Selfhost.zip"],
            "site/shortcuts",
        ),
    )
    for artifact, archive_root in archive_layouts:
        try:
            with zipfile.ZipFile(io.BytesIO(artifact.data)) as archive:
                names = archive.namelist()
                if len(names) != len(set(names)):
                    fail(f"{artifact.name} contains duplicate ZIP member names")
                archived_catalog = read_archive_member(
                    archive,
                    f"{archive_root}/catalog.json",
                    artifact.name,
                )
                if archived_catalog != catalog_data:
                    fail(f"{artifact.name} contains a different Shortcut catalog")
                package_root = f"{archive_root}/{VERSION}/"
                actual_package_files = {
                    name for name in names
                    if name.startswith(package_root) and not name.endswith("/")
                }
                expected_package_files = {
                    f"{package_root}{row['id']}.shortcut" for row in recipe_packages
                }
                if actual_package_files != expected_package_files:
                    fail(
                        f"{artifact.name} Shortcut package file set does not exactly match "
                        f"{SHORTCUT_RECIPE_PATH}"
                    )
                for package in packages:
                    member = f"{archive_root}/{VERSION}/{package.identifier}.shortcut"
                    package_data = read_archive_member(archive, member, artifact.name)
                    if len(package_data) != package.size or sha256(package_data) != package.sha256:
                        fail(f"{artifact.name} contains a changed signed Shortcut package: {member}")
        except zipfile.BadZipFile as error:
            raise PreflightError(f"{artifact.name} is not a valid ZIP archive") from error

    source_archive = artifact_by_name["Local-Sandbox-Source.zip"]
    try:
        with zipfile.ZipFile(io.BytesIO(source_archive.data)) as archive:
            archived_recipe = read_archive_member(
                archive,
                f"Local-Sandbox/{SHORTCUT_RECIPE_PATH}",
                source_archive.name,
            )
    except zipfile.BadZipFile as error:
        raise PreflightError(f"{source_archive.name} is not a valid ZIP archive") from error
    if archived_recipe != recipe_data:
        fail(f"{source_archive.name} contains a different Shortcut recipe")

    selfhost_archive = artifact_by_name["Local-Sandbox-Selfhost.zip"]
    try:
        with zipfile.ZipFile(io.BytesIO(selfhost_archive.data)) as archive:
            embedded_source = read_archive_member(
                archive,
                "site/downloads/Local-Sandbox-Source.zip",
                selfhost_archive.name,
            )
    except zipfile.BadZipFile as error:
        raise PreflightError(f"{selfhost_archive.name} is not a valid ZIP archive") from error
    if embedded_source != source_archive.data:
        fail(f"{selfhost_archive.name} does not contain the exact source archive")

    assert publication_origin is not None
    return ShortcutCatalog(
        sha256=sha256(catalog_data),
        origin=publication_origin,
        packages=tuple(packages),
    )


def validate_action_readiness(
    options: Options,
    validation: dict[str, Any],
    validation_data: bytes,
    artifacts: tuple[Artifact, ...],
    tracker: TrackerBundle,
    *,
    now: datetime,
) -> ActionReadiness:
    readiness_data, _mode = read_external_regular(options.action_readiness)
    document = parse_json(readiness_data, "action readiness")
    expected_keys = {
        "artifacts", "commit", "completionPercent", "gates", "passedGates", "readyAt",
        "recordType", "releaseState", "schemaVersion", "tag", "totalGates", "tracker",
        "verification", "version",
    }
    if set(document) != expected_keys:
        fail("action readiness has missing or unexpected fields")
    if document.get("recordType") != "local-sandbox-github-action-readiness":
        fail(
            "action readiness.recordType must be "
            "local-sandbox-github-action-readiness"
        )
    if document.get("schemaVersion") != 1:
        fail("action readiness.schemaVersion must be 1")
    if document.get("version") != VERSION or document.get("tag") != TAG:
        fail(f"action readiness must cover version {VERSION} and tag {TAG}")
    if document.get("releaseState") != "READY":
        fail("action readiness.releaseState must be READY")
    if document.get("commit") != options.expected_commit:
        fail("action readiness.commit does not equal --expected-commit")
    if require_integer(document, "totalGates", "action readiness") != GATE_COUNT:
        fail(f"action readiness.totalGates must be {GATE_COUNT}")
    if (
        require_integer(document, "passedGates", "action readiness")
        != GITHUB_READY_GATE_COUNT
    ):
        fail(f"action readiness.passedGates must be {GITHUB_READY_GATE_COUNT}")
    completion = document.get("completionPercent")
    if (
        isinstance(completion, bool)
        or not isinstance(completion, (int, float))
        or completion != GITHUB_READY_PERCENT
    ):
        fail(
            "action readiness.completionPercent must be the canonical 56/57 value "
            f"{GITHUB_READY_PERCENT}"
        )

    gates = require_list(document, "gates", "action readiness")
    if len(gates) != GATE_COUNT:
        fail(f"action readiness.gates must contain exactly {GATE_COUNT} gates")
    gate_ids: set[str] = set()
    passed_gates = 0
    for index, raw_gate in enumerate(gates):
        label = f"action readiness.gates[{index}]"
        if not isinstance(raw_gate, dict):
            fail(f"{label} must be an object")
        gate_id = require_string(raw_gate, "id", label)
        if gate_id in gate_ids:
            fail(f"action readiness.gates contains a duplicate id: {gate_id}")
        if gate_id not in EXPECTED_GATE_ID_SET:
            fail(
                "action readiness.gates do not match the 0.3 tracker: "
                f"unexpected {gate_id}"
            )
        if gate_id != EXPECTED_GATE_IDS[index]:
            fail(
                f"{label}.id must be {EXPECTED_GATE_IDS[index]} in canonical 0.3 gate order"
            )
        gate_ids.add(gate_id)
        expected_status = "IN PROGRESS" if gate_id == GITHUB_ACTION_GATE_ID else "PASS"
        if raw_gate.get("status") != expected_status:
            if gate_id == GITHUB_ACTION_GATE_ID and raw_gate.get("status") == "PASS":
                fail(
                    f"{GITHUB_ACTION_GATE_ID} cannot be pre-passed; GitHub remote "
                    "readback is the evidence that completes it"
                )
            fail(f"{label}.status must be {expected_status}")
        if expected_status == "PASS":
            passed_gates += 1
        if set(raw_gate) != {"evidenceSha256", "id", "status"}:
            fail(f"{label} has missing or unexpected fields")
        evidence_sha = require_string(raw_gate, "evidenceSha256", label)
        if SHA256_PATTERN.fullmatch(evidence_sha) is None:
            fail(f"{label}.evidenceSha256 must be one lowercase SHA-256 digest")
    if gate_ids != EXPECTED_GATE_ID_SET:
        missing = sorted(EXPECTED_GATE_ID_SET - gate_ids)
        unexpected = sorted(gate_ids - EXPECTED_GATE_ID_SET)
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        fail("action readiness.gates do not match the 0.3 tracker: " + "; ".join(details))
    if passed_gates != GITHUB_READY_GATE_COUNT:
        fail(
            "action readiness must contain exactly 56 PASS gates and REL-06 IN PROGRESS"
        )

    try:
        assert_tracker_profile(tracker, "github")
        verify_tracker_binding(document.get("tracker"), tracker, "action readiness.tracker")
        verify_tracker_gates(gates, tracker, "action readiness.gates")
    except TrackerError as error:
        raise PreflightError(str(error)) from error

    validation_generated_at, current_candidate_digest = validate_automated_verification(
        validation,
        tracker,
    )
    ready_at = parse_timestamp(
        require_string(document, "readyAt", "action readiness"),
        "action readiness.readyAt",
    )
    if ready_at < validation_generated_at:
        fail("action readiness.readyAt predates docs/validation.json")
    if ready_at > now + FUTURE_CLOCK_SKEW:
        fail("action readiness.readyAt is in the future")
    if now - ready_at > MAX_QUALIFICATION_AGE:
        fail("action readiness is older than 24 hours; rerun the 56 pre-publication gates")

    verification = require_object(document, "verification", "action readiness")
    if set(verification) != {
        "automatedStatus", "candidateDigest", "commit", "path", "sha256"
    }:
        fail("action readiness.verification has missing or unexpected fields")
    if verification.get("path") != VALIDATION_PATH.as_posix():
        fail(f"action readiness.verification.path must be {VALIDATION_PATH}")
    if verification.get("commit") != options.expected_commit:
        fail("action readiness.verification.commit does not equal --expected-commit")
    claimed_validation_sha = require_string(
        verification,
        "sha256",
        "action readiness.verification",
    )
    if SHA256_PATTERN.fullmatch(claimed_validation_sha) is None:
        fail("action readiness.verification.sha256 must be one lowercase SHA-256 digest")
    if claimed_validation_sha != sha256(validation_data):
        fail("docs/validation.json does not match its qualified SHA-256 digest")
    if verification.get("automatedStatus") != "passed":
        fail("action readiness.verification.automatedStatus must be passed")
    if verification.get("candidateDigest") != current_candidate_digest:
        fail("action readiness.verification.candidateDigest does not match the current release candidate")

    validate_artifact_evidence(
        require_list(document, "artifacts", "action readiness"),
        artifacts,
    )
    return ActionReadiness(
        path=options.action_readiness,
        data=readiness_data,
        sha256=sha256(readiness_data),
        ready_at=ready_at,
    )


def is_not_found(result: subprocess.CompletedProcess[str]) -> bool:
    response = f"{result.stdout}\n{result.stderr}"
    return re.search(r"\b(?:HTTP\s*)?404\b|\bnot found\b", response, re.IGNORECASE) is not None


def assert_absent(endpoint: str, label: str) -> None:
    result = run(["gh", "api", "--hostname", "github.com", endpoint, "--silent"])
    if result.returncode == 0:
        fail(f"{label} already exists")
    if not is_not_found(result):
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        fail(f"Could not prove that {label} is absent: {detail}")


def verify_existing_repository(options: Options) -> tuple[dict[str, Any], str]:
    base = f"repos/{options.target}"
    repository = checked_json(
        ["gh", "api", "--hostname", "github.com", base],
        "remote repository",
    )
    remote_name = require_string(repository, "full_name", "remote repository")
    if remote_name.casefold() != options.target.casefold():
        fail("Remote repository identity does not match the requested owner and name")
    remote_visibility = require_string(repository, "visibility", "remote repository")
    if remote_visibility != options.visibility:
        fail("Remote repository visibility does not match --visibility")
    if require_boolean(repository, "private", "remote repository") != (
        options.visibility == "private"
    ):
        fail("Remote repository private flag conflicts with its visibility")
    default_branch = require_string(repository, "default_branch", "remote repository")
    if default_branch != "main":
        fail("Remote repository default branch must be main")
    main_ref = checked_json(
        ["gh", "api", "--hostname", "github.com", f"{base}/git/ref/heads/main"],
        "remote main ref",
    )
    main_commit = verified_ref_commit(main_ref, "refs/heads/main", "main ref")
    if main_commit != options.expected_commit:
        fail("Remote main does not equal --expected-commit")
    return repository, main_commit


def verify_github_state(options: Options) -> None:
    checked(["gh", "auth", "status", "--hostname", "github.com"])
    verify_existing_repository(options)
    base = f"repos/{options.target}"
    assert_absent(f"{base}/git/ref/tags/{TAG}", f"GitHub tag {TAG}")
    assert_absent(f"{base}/releases/tags/{TAG}", f"GitHub release {TAG}")


def ensure_output_directory() -> Path:
    current = ROOT
    for part in ("release-output", f"github-{TAG}"):
        current = current / part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            current.mkdir(mode=0o755)
            metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            fail(f"Release output path must be a real directory: {current}")
    return current


def atomic_write(path: Path, data: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def release_notes(
    options: Options,
    action_readiness: ActionReadiness,
    artifacts: tuple[Artifact, ...],
    shortcut_catalog: ShortcutCatalog,
) -> bytes:
    lines = [
        f"# Local Sandbox {TAG}",
        "",
        f"Release commit: `{options.expected_commit}`",
        f"GitHub action readiness: {GITHUB_READY_GATE_COUNT} of {GATE_COUNT} gates PASS "
        f"({GITHUB_READY_PERCENT}%)",
        f"Pending publication gate: `{GITHUB_ACTION_GATE_ID}`",
        f"Ready at: `{action_readiness.ready_at.isoformat().replace('+00:00', 'Z')}`",
        f"Action-readiness SHA-256: `{action_readiness.sha256}`",
        "",
        "## Release artifacts",
        "",
    ]
    for artifact in sorted(artifacts, key=lambda item: item.name):
        lines.append(f"- `{artifact.name}`: `{artifact.sha256}` ({artifact.size} bytes)")
    lines.extend([
        "",
        "## Install",
        "",
        "1. Download the files you need and verify them against `SHA256SUMS`.",
        "2. For the native app, extract `Local-Sandbox-Source.zip`, then follow "
        "`docs/INSTALL-TODAY.md` with Xcode and your Apple Developer team.",
        "3. For the static web app, extract `Local-Sandbox-Selfhost.zip`, then follow "
        "the included `site/downloads/ROADMAP-AUTOMATION.md`.",
        "4. For the provider workflows, install only the catalog packages that match "
        "their recorded SHA-256 digests and review every permission in Apple Shortcuts.",
        "",
        "## Signed Shortcut catalog",
        "",
        f"Catalog SHA-256: `{shortcut_catalog.sha256}`",
        f"Publication origin: `{shortcut_catalog.origin}`",
        "",
        "The catalog and its package bytes are contained in both canonical ZIPs under "
        f"`Local-Sandbox/public/shortcuts/{VERSION}/` and `site/shortcuts/{VERSION}/`.",
        "",
    ])
    for package in sorted(shortcut_catalog.packages, key=lambda item: item.identifier):
        lines.append(
            f"- `{package.identifier}` ({package.name}): `{package.sha256}` "
            f"({package.size} bytes)"
        )
    lines.extend([
        "",
        "## Known limitations",
        "",
        "- Third-party provider workflows require compatible installed apps and signed-in "
        "accounts. Local Sandbox never substitutes a provider.",
        "- The static self-host package has no server-backed Apple authentication, Cursor "
        "Origin connection, or encrypted workspace-sync service.",
        "- iOS schedules background processing. Local Sandbox cannot operate as an always-on "
        "daemon or open provider apps while unattended.",
        "- This GitHub release does not publish an App Store or TestFlight build.",
    ])
    return ("\n".join(lines) + "\n").encode("utf-8")


def stage_release(
    options: Options,
    action_readiness: ActionReadiness,
    validation_data: bytes,
    artifacts: tuple[Artifact, ...],
    shortcut_catalog: ShortcutCatalog,
) -> tuple[StagedFile, tuple[StagedFile, ...]]:
    output = ensure_output_directory()
    staged_artifacts: list[StagedFile] = []
    for artifact in artifacts:
        destination = output / artifact.name
        atomic_write(destination, artifact.data)
        staged_artifacts.append(StagedFile(destination, artifact.data))

    checksum_lines = [
        f"{artifact.sha256}  {artifact.name}"
        for artifact in sorted(artifacts, key=lambda item: item.name)
    ]
    checksums_path = output / "SHA256SUMS"
    notes_path = output / "RELEASE_NOTES.md"
    plan_path = output / "github-release-plan.json"
    checksums_data = ("\n".join(checksum_lines) + "\n").encode("ascii")
    notes_data = release_notes(options, action_readiness, artifacts, shortcut_catalog)
    atomic_write(checksums_path, checksums_data)
    atomic_write(notes_path, notes_data)
    plan = {
        "artifacts": [
            {"bytes": artifact.size, "name": artifact.name, "sha256": artifact.sha256}
            for artifact in sorted(artifacts, key=lambda item: item.name)
        ],
        "commit": options.expected_commit,
        "actionReadiness": {
            "gates": {
                "passed": GITHUB_READY_GATE_COUNT,
                "pending": GITHUB_ACTION_GATE_ID,
                "total": GATE_COUNT,
            },
            "readyAt": action_readiness.ready_at.isoformat().replace("+00:00", "Z"),
            "sha256": action_readiness.sha256,
        },
        "shortcutCatalog": {
            "packages": [
                {
                    "bytes": package.size,
                    "id": package.identifier,
                    "sha256": package.sha256,
                }
                for package in sorted(
                    shortcut_catalog.packages,
                    key=lambda item: item.identifier,
                )
            ],
            "sha256": shortcut_catalog.sha256,
            "status": SIGNED_SHORTCUT_STATUS,
        },
        "tag": TAG,
        "target": options.target,
        "validationSha256": sha256(validation_data),
        "version": VERSION,
        "visibility": options.visibility,
    }
    atomic_write(
        plan_path,
        (json.dumps(plan, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return (
        StagedFile(notes_path, notes_data),
        tuple(staged_artifacts) + (StagedFile(checksums_path, checksums_data),),
    )


def verify_staged_release(notes: StagedFile, staged: tuple[StagedFile, ...]) -> None:
    for item in (notes, *staged):
        data, _mode = read_external_regular(item.path)
        if data != item.data:
            fail(f"Staged release file changed before publication: {item.path.name}")


def verified_ref_commit(document: dict[str, Any], ref: str, label: str) -> str:
    if document.get("ref") != ref:
        fail(f"Remote {label} returned the wrong ref")
    target = require_object(document, "object", f"remote {label}")
    if target.get("type") != "commit":
        fail(f"Remote {label} must point directly to a commit")
    commit = require_string(target, "sha", f"remote {label}.object")
    if SHA_PATTERN.fullmatch(commit) is None:
        fail(f"Remote {label} returned an invalid commit SHA")
    return commit


def validate_release_url(url: str, options: Options) -> None:
    parsed = urlsplit(url)
    expected_path = f"/{options.target}/releases/tag/{TAG}"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path.casefold() != expected_path.casefold()
    ):
        fail("Remote release returned an unexpected GitHub URL")


def verify_published_release(
    options: Options,
    notes: StagedFile,
    staged: tuple[StagedFile, ...],
) -> dict[str, Any]:
    base = f"repos/{options.target}"
    repository, main_commit = verify_existing_repository(options)
    remote_name = require_string(repository, "full_name", "remote repository")
    remote_visibility = require_string(repository, "visibility", "remote repository")
    default_branch = require_string(repository, "default_branch", "remote repository")

    tag_ref = checked_json(
        ["gh", "api", "--hostname", "github.com", f"{base}/git/ref/tags/{TAG}"],
        "remote release tag",
    )
    tag_commit = verified_ref_commit(tag_ref, f"refs/tags/{TAG}", f"tag {TAG}")
    if tag_commit != options.expected_commit:
        fail(f"Remote tag {TAG} does not equal --expected-commit")

    release = checked_json(
        ["gh", "api", "--hostname", "github.com", f"{base}/releases/tags/{TAG}"],
        "remote release",
    )
    if release.get("tag_name") != TAG:
        fail("Remote release tag name does not match the requested tag")
    if release.get("name") != RELEASE_TITLE:
        fail("Remote release title does not match the reviewed title")
    if require_boolean(release, "draft", "remote release"):
        fail("Remote release must not be a draft")
    if require_boolean(release, "prerelease", "remote release"):
        fail("Remote release must not be a prerelease")
    release_url = require_string(release, "html_url", "remote release")
    validate_release_url(release_url, options)
    try:
        expected_body = notes.data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PreflightError("Reviewed release notes are not UTF-8") from error
    if release.get("body") != expected_body:
        fail("Remote release body does not match the reviewed release notes")

    expected_assets: dict[str, bytes] = {}
    for item in staged:
        if item.path.name in expected_assets:
            fail(f"Staged release contains a duplicate asset name: {item.path.name}")
        expected_assets[item.path.name] = item.data

    raw_assets = require_list(release, "assets", "remote release")
    if len(raw_assets) != len(expected_assets):
        fail("Remote release does not contain exactly the reviewed asset set")
    assets_by_name: dict[str, dict[str, Any]] = {}
    for index, raw_asset in enumerate(raw_assets):
        label = f"remote release.assets[{index}]"
        if not isinstance(raw_asset, dict):
            fail(f"{label} must be an object")
        name = require_string(raw_asset, "name", label)
        if name in assets_by_name:
            fail(f"Remote release contains a duplicate asset name: {name}")
        assets_by_name[name] = raw_asset
    if set(assets_by_name) != set(expected_assets):
        fail("Remote release asset names do not match the reviewed asset set")

    verified_assets: list[dict[str, Any]] = []
    for name in sorted(expected_assets):
        label = f"remote release.assets[{name}]"
        metadata = assets_by_name[name]
        asset_id = require_integer(metadata, "id", label)
        if asset_id <= 0:
            fail(f"{label}.id must be positive")
        expected_data = expected_assets[name]
        if require_integer(metadata, "size", label) != len(expected_data):
            fail(f"Remote release asset {name} has the wrong byte count")
        if metadata.get("state") != "uploaded":
            fail(f"Remote release asset {name} is not uploaded")
        downloaded = checked_bytes([
            "gh",
            "api",
            "--hostname",
            "github.com",
            "-H",
            "Accept: application/octet-stream",
            f"{base}/releases/assets/{asset_id}",
        ])
        if downloaded != expected_data:
            fail(f"Remote release asset {name} does not match the reviewed bytes")
        digest = sha256(downloaded)
        remote_digest = metadata.get("digest")
        if remote_digest is not None and remote_digest != f"sha256:{digest}":
            fail(f"Remote release asset {name} reports a conflicting digest")
        verified_assets.append({"bytes": len(downloaded), "name": name, "sha256": digest})

    return {
        "assets": verified_assets,
        "refs": {"main": main_commit, "tag": tag_commit},
        "release": {
            "bodySha256": sha256(notes.data),
            "draft": False,
            "prerelease": False,
            "tag": TAG,
            "title": RELEASE_TITLE,
            "url": release_url,
        },
        "repository": {
            "defaultBranch": default_branch,
            "nameWithOwner": remote_name,
            "visibility": remote_visibility,
        },
    }


def write_completion_receipt(
    output: Path,
    action_readiness: ActionReadiness,
    remote: dict[str, Any],
) -> Path:
    receipt_path = output / COMPLETION_RECEIPT_NAME
    receipt = {
        "actionReadinessSha256": action_readiness.sha256,
        "finalQualificationClaimed": False,
        "gate": {"id": GITHUB_ACTION_GATE_ID, "status": "PASS"},
        "recordType": "local-sandbox-release-gate-completion",
        "remoteReadback": remote,
        "schemaVersion": 1,
        "verifiedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "version": VERSION,
    }
    atomic_write(
        receipt_path,
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return receipt_path


def checked_mutation(
    options: Options,
    phase: str,
    command: Sequence[str],
    *,
    env: dict[str, str] | None = None,
) -> None:
    try:
        checked(command, env=env)
    except PreflightError as error:
        fail(
            f"GitHub publication stopped during {phase}. GitHub state may be partial or "
            "uncertain. The publisher does not delete, overwrite, force-push, or retry an "
            "external mutation. Do not rerun --execute. Inspect "
            f"https://github.com/{options.target}, refs/heads/main at "
            f"{options.expected_commit}, refs/tags/{TAG}, and the {TAG} release before "
            f"choosing a manual recovery. Original error: {error}"
        )


def execute_release(
    options: Options,
    notes: StagedFile,
    staged: tuple[StagedFile, ...],
    action_readiness: ActionReadiness,
) -> Path:
    verify_git_state(options)
    verify_github_state(options)
    verify_staged_release(notes, staged)
    checked_mutation(options, "tag creation", [
        "gh",
        "api",
        "--hostname",
        "github.com",
        "--method",
        "POST",
        f"repos/{options.target}/git/refs",
        "-f",
        f"ref=refs/tags/{TAG}",
        "-f",
        f"sha={options.expected_commit}",
        "--silent",
    ])
    checked_mutation(options, "release creation", [
        "gh",
        "release",
        "create",
        TAG,
        "--repo",
        options.target,
        "--verify-tag",
        "--title",
        RELEASE_TITLE,
        "--notes-file",
        os.fspath(notes.path),
        *(os.fspath(item.path) for item in staged),
    ])
    try:
        remote = verify_published_release(options, notes, staged)
        return write_completion_receipt(notes.path.parent, action_readiness, remote)
    except (OSError, ValueError, RuntimeError) as error:
        fail(
            "GitHub publication completed its requested mutations, but exact remote "
            "readback or the local REL-06 completion receipt failed. Do not mark the "
            "final 57-gate release qualified and do not rerun --execute. Inspect the "
            f"repository, refs, release, and every asset manually. Original error: {error}"
        )


def parse_options(arguments: Sequence[str] | None = None) -> Options:
    parser = argparse.ArgumentParser(
        description=(
            f"Validate and stage GitHub publication for Local Sandbox {TAG}. "
            "The command is a dry run unless --execute is present."
        )
    )
    parser.add_argument("--owner", required=True, help="GitHub user or organization")
    parser.add_argument("--repo", required=True, help="existing GitHub repository name")
    parser.add_argument(
        "--visibility",
        required=True,
        choices=("private", "public"),
        help="expected visibility of the existing repository",
    )
    parser.add_argument(
        "--expected-commit",
        required=True,
        help="full clean commit SHA that contains the complete 0.3 release",
    )
    parser.add_argument("--tag", required=True, help=f"must be {TAG}")
    parser.add_argument(
        "--tracker",
        required=True,
        type=Path,
        help=f"must be the committed {CANONICAL_TRACKER_PATH}",
    )
    parser.add_argument(
        "--action-readiness",
        required=True,
        type=Path,
        help="machine-readable 56-of-57 GitHub action-readiness JSON",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="create the tag and release in an already-synchronized repository",
    )
    values = parser.parse_args(arguments)
    return Options(
        owner=values.owner,
        repository=values.repo,
        visibility=values.visibility,
        expected_commit=values.expected_commit,
        tag=values.tag,
        tracker=values.tracker,
        action_readiness=values.action_readiness,
        execute=values.execute,
    )


def main(arguments: Sequence[str] | None = None, *, now: datetime | None = None) -> int:
    try:
        options = parse_options(arguments)
        validate_options(options)
        verify_git_state(options)
        verify_artifact_freshness()
        tracker = read_tracker(options)
        (
            validation,
            validation_data,
            artifacts,
            shortcut_catalog_data,
            shortcut_recipe_data,
        ) = read_release_inputs()
        action_readiness = validate_action_readiness(
            options,
            validation,
            validation_data,
            artifacts,
            tracker,
            now=now or datetime.now(timezone.utc),
        )
        shortcut_catalog = validate_shortcut_catalog(
            shortcut_catalog_data,
            shortcut_recipe_data,
            artifacts,
        )
        verify_git_state(options)
        verify_github_state(options)
        notes, staged = stage_release(
            options,
            action_readiness,
            validation_data,
            artifacts,
            shortcut_catalog,
        )
        if options.execute:
            receipt_path = execute_release(
                options,
                notes,
                staged,
                action_readiness,
            )
            print(f"Published {options.target} {TAG} from {options.expected_commit}.")
            print(f"Verified REL-06 completion receipt: {receipt_path}")
            print("This receipt does not claim the final 57/57 release qualification.")
        else:
            print(
                f"DRY RUN PASSED: {options.target} {TAG}, {options.visibility}, "
                f"commit {options.expected_commit}, "
                f"{GITHUB_READY_GATE_COUNT}/{GATE_COUNT} gates PASS; "
                f"{GITHUB_ACTION_GATE_ID} IN PROGRESS."
            )
            print(f"Deterministic release files: {notes.path.parent}")
            print("No tag or release was created. Add --execute only after review.")
        return 0
    except (OSError, ValueError, RuntimeError) as error:
        print(f"GitHub release preflight failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
