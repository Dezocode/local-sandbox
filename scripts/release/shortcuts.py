#!/usr/bin/env python3
"""Sign exported Shortcuts and publish one immutable 0.3.0 catalog."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import tempfile
from typing import Callable
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[2]
CATALOG_VERSION = 1
PACKAGE_RELEASE = "0.3.0"
SIGNED_STATUS = "signed-awaiting-device-acceptance"
UNAVAILABLE_STATUS = "awaiting-signed-device-exports"
MAXIMUM_PACKAGES = 30
MAXIMUM_PACKAGE_BYTES = 5_000_000
MAXIMUM_RECIPE_BYTES = 100_000
MAXIMUM_CATALOG_BYTES = 100_000
PACKAGE_ID = re.compile(r"[a-z][a-z0-9-]{0,40}")
SAFE_NAME = re.compile(r"[\x21-\x7e](?:[\x20-\x7e]{0,78}[\x21-\x7e])?")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


class PublicationConflict(RuntimeError):
    """The output contains state that cannot be adopted without replacement."""


def unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Shortcut recipe repeats the JSON member {key}.")
        result[key] = value
    return result


def reject_json_constant(value: str) -> None:
    raise ValueError(f"Shortcut recipe contains the invalid JSON number {value}.")


def canonical_shortcuts_base_url(value: str) -> str:
    """Require one canonical HTTPS origin followed by the exact /shortcuts path."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Use the canonical HTTPS package URL ending in /shortcuts.")
    if not value.isascii() or "%" in value or "\\" in value:
        raise ValueError("The package URL must be unencoded canonical ASCII.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("The package URL contains an invalid host or port.") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/shortcuts"
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "Use one HTTPS origin plus /shortcuts, without credentials, a trailing slash, query, or fragment."
        )
    if port == 443:
        raise ValueError("Omit the default HTTPS port from the package URL.")

    host = parsed.hostname
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if host.endswith(".") or len(host) > 253 or any(
            DNS_LABEL.fullmatch(label) is None for label in host.split(".")
        ):
            raise ValueError("The package URL must contain a canonical DNS name or IP address.")
        canonical_host = host
    else:
        canonical_host = f"[{address.compressed}]" if address.version == 6 else address.compressed

    authority = canonical_host if port is None else f"{canonical_host}:{port}"
    canonical = f"https://{authority}/shortcuts"
    if value != canonical:
        raise ValueError(f"Use the canonical package URL {canonical}.")
    return canonical


def read_regular_file(path: Path, maximum_bytes: int, label: str) -> bytes:
    """Read one bounded regular file without following a final-component symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"{label} must be a readable regular file.") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= maximum_bytes:
            raise ValueError(f"{label} must contain between 1 and {maximum_bytes} bytes.")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                raise ValueError(f"{label} changed while it was read.")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ValueError(f"{label} changed while it was read.")
        data = b"".join(chunks)
        if len(data) != metadata.st_size:
            raise ValueError(f"{label} changed while it was read.")
        return data
    finally:
        os.close(descriptor)


def parse_recipe(data: bytes) -> tuple[str, list[dict[str, object]]]:
    """Parse and validate one captured Shortcut recipe."""
    try:
        recipe = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_json_object,
            parse_constant=reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("Shortcut recipe must be valid UTF-8 JSON.") from error
    if not isinstance(recipe, dict) or set(recipe) != {"version", "release", "packages"}:
        raise ValueError("Shortcut recipe must contain only version, release, and packages.")
    if (
        isinstance(recipe["version"], bool)
        or not isinstance(recipe["version"], int)
        or recipe["version"] != CATALOG_VERSION
        or recipe["release"] != PACKAGE_RELEASE
    ):
        raise ValueError("Shortcut recipe must describe schema 1 release 0.3.0.")
    rows = recipe["packages"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAXIMUM_PACKAGES:
        raise ValueError(f"Shortcut recipe must contain between 1 and {MAXIMUM_PACKAGES} packages.")

    identifiers: set[str] = set()
    names: set[str] = set()
    files: set[str] = set()
    for index, row in enumerate(rows):
        label = f"Shortcut recipe package {index + 1}"
        if not isinstance(row, dict) or set(row) != {"id", "name", "file", "requires"}:
            raise ValueError(f"{label} must contain only id, name, file, and requires.")
        identifier = row["id"]
        name = row["name"]
        filename = row["file"]
        requirements = row["requires"]
        if not isinstance(identifier, str) or PACKAGE_ID.fullmatch(identifier) is None:
            raise ValueError(f"{label} has an invalid package ID.")
        if identifier in identifiers:
            raise ValueError("Shortcut package IDs must be unique.")
        if not isinstance(name, str) or len(name) > 80 or SAFE_NAME.fullmatch(name) is None:
            raise ValueError(f"{label} has an unsafe display name.")
        if name in names:
            raise ValueError("Shortcut package display names must be unique.")
        if (
            not isinstance(filename, str)
            or not filename.isascii()
            or Path(filename).name != filename
            or "\\" in filename
            or not filename.endswith(".shortcut")
            or len(filename) > 120
        ):
            raise ValueError(f"{label} has an invalid exported workflow filename.")
        if filename in files:
            raise ValueError("Shortcut exported workflow filenames must be unique.")
        if not isinstance(requirements, list) or any(
            not isinstance(dependency, str) or PACKAGE_ID.fullmatch(dependency) is None
            for dependency in requirements
        ):
            raise ValueError(f"{label} has an invalid dependency list.")
        if len(requirements) != len(set(requirements)):
            raise ValueError(f"{label} repeats a dependency.")
        if identifier in requirements:
            raise ValueError(f"{label} cannot depend on itself.")
        identifiers.add(identifier)
        names.add(name)
        files.add(filename)

    for row in rows:
        if not set(row["requires"]).issubset(identifiers):
            raise ValueError(f'Shortcut package {row["id"]} has an unknown dependency.')

    by_id = {row["id"]: row for row in rows}
    visited: set[str] = set()
    active: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in active:
            raise ValueError("Shortcut package dependencies contain a cycle.")
        if identifier in visited:
            return
        active.add(identifier)
        for dependency in by_id[identifier]["requires"]:
            visit(dependency)
        active.remove(identifier)
        visited.add(identifier)

    for identifier in identifiers:
        visit(identifier)
    return PACKAGE_RELEASE, rows


def load_recipe(path: Path) -> tuple[str, list[dict[str, object]]]:
    return parse_recipe(read_regular_file(path, MAXIMUM_RECIPE_BYTES, "Shortcut recipe"))


def validate_exports(exports: Path, rows: list[dict[str, object]]) -> None:
    try:
        metadata = exports.lstat()
    except FileNotFoundError as error:
        raise ValueError("Shortcut exports must be a real directory.") from error
    if not stat.S_ISDIR(metadata.st_mode) or exports.is_symlink():
        raise ValueError("Shortcut exports must be a real directory.")
    for row in rows:
        read_regular_file(
            exports / row["file"],
            MAXIMUM_PACKAGE_BYTES,
            f'Exported workflow {row["file"]}',
        )


def signed_catalog(
    destination: Path,
    rows: list[dict[str, object]],
    base_url: str,
) -> dict[str, object]:
    try:
        metadata = destination.lstat()
    except FileNotFoundError as error:
        raise PublicationConflict("The signed release directory is missing.") from error
    if not stat.S_ISDIR(metadata.st_mode) or destination.is_symlink():
        raise PublicationConflict("The signed release path must be a real directory.")
    expected_names = {f'{row["id"]}.shortcut' for row in rows}
    actual_names = {entry.name for entry in destination.iterdir()}
    if actual_names != expected_names:
        raise PublicationConflict("The signed release directory does not match the exact recipe file set.")

    packages = []
    for row in rows:
        filename = f'{row["id"]}.shortcut'
        data = read_regular_file(
            destination / filename,
            MAXIMUM_PACKAGE_BYTES,
            f"Signed Shortcut package {filename}",
        )
        packages.append(
            {
                "id": row["id"],
                "name": row["name"],
                "requires": row["requires"],
                "url": f"{base_url}/{PACKAGE_RELEASE}/{filename}",
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )
    return {
        "version": CATALOG_VERSION,
        "release": PACKAGE_RELEASE,
        "status": SIGNED_STATUS,
        "packages": packages,
    }


def read_existing_catalog(path: Path) -> dict[str, object] | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    data = read_regular_file(path, MAXIMUM_CATALOG_BYTES, "Existing Shortcut catalog")
    try:
        catalog = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationConflict("The existing Shortcut catalog is not valid UTF-8 JSON.") from error
    if not isinstance(catalog, dict):
        raise PublicationConflict("The existing Shortcut catalog must contain one JSON object.")
    return catalog


def publication_state(
    destination: Path,
    catalog_path: Path,
    rows: list[dict[str, object]],
    base_url: str,
) -> tuple[str, dict[str, object] | None]:
    existing_catalog = read_existing_catalog(catalog_path)
    try:
        destination.lstat()
    except FileNotFoundError:
        unavailable = {
            "version": CATALOG_VERSION,
            "release": PACKAGE_RELEASE,
            "packages": [],
            "status": UNAVAILABLE_STATUS,
        }
        if existing_catalog is None or existing_catalog == unavailable:
            return "new", None
        raise PublicationConflict(
            "The catalog claims published state but the immutable release directory is missing."
        )

    expected_catalog = signed_catalog(destination, rows, base_url)
    if existing_catalog == expected_catalog:
        return "complete", expected_catalog
    unavailable = {
        "version": CATALOG_VERSION,
        "release": PACKAGE_RELEASE,
        "packages": [],
        "status": UNAVAILABLE_STATUS,
    }
    if existing_catalog is None or existing_catalog == unavailable:
        return "recoverable", expected_catalog
    raise PublicationConflict(
        "The immutable signed files conflict with catalog.json; neither file set will be replaced."
    )


def write_catalog(path: Path, catalog: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix="catalog-", suffix=".tmp")
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(catalog, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def sign_with_apple(source: Path, output: Path) -> None:
    subprocess.run(
        [
            "/usr/bin/shortcuts",
            "sign",
            "--mode",
            "anyone",
            "--input",
            str(source.resolve()),
            "--output",
            str(output),
        ],
        check=True,
    )


def publish(
    *,
    exports: Path,
    base_url: str,
    recipe_path: Path,
    output: Path,
    check: bool,
    signer: Callable[[Path, Path], None] = sign_with_apple,
) -> dict[str, object]:
    canonical_base_url = canonical_shortcuts_base_url(base_url)
    release, rows = load_recipe(recipe_path)
    destination = output / release
    catalog_path = output / "catalog.json"
    state, recovered_catalog = publication_state(
        destination,
        catalog_path,
        rows,
        canonical_base_url,
    )
    if state == "new":
        validate_exports(exports, rows)
    if check:
        return {
            "checked": [row["id"] for row in rows],
            "packages": len(rows),
            "release": release,
            "state": state,
            "signed": state in {"recoverable", "complete"},
        }
    if state == "complete":
        raise FileExistsError(
            "Immutable release exists. Use a new package version instead of replacing it."
        )
    if state == "recoverable":
        write_catalog(catalog_path, recovered_catalog)
        return {
            "catalog": str(catalog_path),
            "deviceVerified": False,
            "packages": len(rows),
            "recovered": True,
        }

    if platform.system() != "Darwin":
        raise RuntimeError(
            "Apple Shortcuts signing requires macOS. No unsigned fallback will be published."
        )
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=output, prefix=f".{release}-staging-") as temporary:
        stage = Path(temporary)
        for row in rows:
            signed_path = stage / f'{row["id"]}.shortcut'
            signer(exports / row["file"], signed_path)
            read_regular_file(
                signed_path,
                MAXIMUM_PACKAGE_BYTES,
                f'Signed Shortcut package {signed_path.name}',
            )
        os.rename(stage, destination)
    catalog = signed_catalog(destination, rows, canonical_base_url)
    write_catalog(catalog_path, catalog)
    return {
        "catalog": str(catalog_path),
        "deviceVerified": False,
        "packages": len(rows),
        "recovered": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--recipe", type=Path, default=ROOT / "release/shortcuts/recipe.json")
    parser.add_argument("--output", type=Path, default=ROOT / "public/shortcuts")
    parser.add_argument("--check", action="store_true")
    options = parser.parse_args()
    try:
        result = publish(
            exports=options.exports,
            base_url=options.base_url,
            recipe_path=options.recipe,
            output=options.output,
            check=options.check,
        )
    except PublicationConflict as error:
        if options.check:
            print(json.dumps({"error": str(error), "state": "conflicting"}, sort_keys=True))
            raise SystemExit(1) from None
        raise
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
