#!/usr/bin/env python3
"""Verify the App Shortcuts availability emitted by Xcode."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from typing import Any


IOS_26_SHORTCUTS = frozenset(
    {
        "ApplyValidatedActionIntent",
        "BeginOracleTaskIntent",
        "BeginProviderQualificationIntent",
        "ConfigureOracleRoutingIntent",
        "OpenSandboxIntent",
        "PrepareWorkspaceIntent",
        "QualifyAppleProviderIntent",
        "RecordProviderQualificationIntent",
        "RunSandboxIntent",
    }
)
IOS_27_SHORTCUT = "RunLongAppleTaskIntent"
EXPECTED_SHORTCUTS = IOS_26_SHORTCUTS | {IOS_27_SHORTCUT}
WILDCARD_AVAILABILITY = {
    "LNPlatformNameWildcard": {"introducedVersion": "*"},
}
IOS_27_AVAILABILITY = {
    **WILDCARD_AVAILABILITY,
    "LNPlatformNameIOS": {"introducedVersion": "27.0"},
}


def require_dictionary(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object.")
    return value


def verify(metadata: dict[str, Any]) -> dict[str, Any]:
    shortcuts = metadata.get("autoShortcuts")
    if not isinstance(shortcuts, list):
        raise ValueError("autoShortcuts must be a JSON array.")
    if len(shortcuts) != 10:
        raise ValueError(f"Expected exactly 10 autoShortcuts; received {len(shortcuts)}.")

    by_identifier: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(shortcuts):
        shortcut = require_dictionary(value, f"autoShortcuts[{index}]")
        identifier = shortcut.get("actionIdentifier")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError(f"autoShortcuts[{index}].actionIdentifier must be a non-empty string.")
        if identifier in by_identifier:
            raise ValueError(f"Duplicate autoShortcut actionIdentifier: {identifier}.")
        by_identifier[identifier] = shortcut

    identifiers = set(by_identifier)
    if identifiers != EXPECTED_SHORTCUTS:
        missing = sorted(EXPECTED_SHORTCUTS - identifiers)
        unexpected = sorted(identifiers - EXPECTED_SHORTCUTS)
        raise ValueError(
            "App Shortcut identifiers do not match the release contract. "
            f"Missing: {missing or 'none'}; unexpected: {unexpected or 'none'}."
        )

    for identifier in sorted(IOS_26_SHORTCUTS):
        availability = by_identifier[identifier].get("availabilityAnnotations")
        if availability != WILDCARD_AVAILABILITY:
            raise ValueError(
                f"{identifier} must be wildcard-only so it remains available on iOS 26."
            )

    long_availability = by_identifier[IOS_27_SHORTCUT].get("availabilityAnnotations")
    if long_availability != IOS_27_AVAILABILITY:
        raise ValueError(
            f"{IOS_27_SHORTCUT} must be the only App Shortcut introduced on iOS 27.0."
        )

    wildcard_only = [
        identifier
        for identifier, shortcut in by_identifier.items()
        if shortcut.get("availabilityAnnotations") == WILDCARD_AVAILABILITY
    ]
    if len(wildcard_only) != 9:
        raise ValueError(f"Expected exactly nine wildcard-only App Shortcuts; received {len(wildcard_only)}.")

    ios_27 = [
        identifier
        for identifier, shortcut in by_identifier.items()
        if require_dictionary(
            shortcut.get("availabilityAnnotations"),
            f"{identifier}.availabilityAnnotations",
        ).get("LNPlatformNameIOS")
        == {"introducedVersion": "27.0"}
    ]
    if ios_27 != [IOS_27_SHORTCUT]:
        raise ValueError(
            f"Only {IOS_27_SHORTCUT} may carry the iOS 27.0 availability annotation; received {ios_27}."
        )

    return {
        "autoShortcuts": len(shortcuts),
        "ios26Compatible": sorted(wildcard_only),
        "ios27Only": ios_27,
        "openSandboxAvailability": "wildcard-only",
        "status": "passed",
    }


def verify_file(path: Path) -> dict[str, Any]:
    metadata_path = path.resolve(strict=True)
    if not metadata_path.is_file():
        raise ValueError(f"App Intents metadata is not a regular file: {metadata_path}")
    data = metadata_path.read_bytes()
    metadata = require_dictionary(json.loads(data), "App Intents metadata")
    result = verify(metadata)
    return {
        **result,
        "path": str(metadata_path),
        "sha256": sha256(data).hexdigest(),
    }


def main(arguments: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    options = parser.parse_args(arguments)
    try:
        result = verify_file(options.metadata)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"App Intents metadata verification failed: {error}") from error
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
