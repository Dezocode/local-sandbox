#!/usr/bin/env python3
"""Exercise release packagers against symlink and path-swap fixtures."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
PACKAGE_SOURCE_SCRIPT = SCRIPTS / "package-source.py"
SELFHOST_SCRIPT = SCRIPTS / "release/selfhost.py"
SHORTCUTS_SCRIPT = SCRIPTS / "release/shortcuts.py"
APPLE_SCRIPT = SCRIPTS / "release/apple.py"
REGENERATE_SCRIPT = SCRIPTS / "release/regenerate.py"
AUDIT_SCRIPT = SCRIPTS / "audit-release-artifacts.py"
sys.path.insert(0, str(SCRIPTS))

from release_common import SENSITIVE_RELEASE_SUFFIXES, SafeRoot, UnsafeReleasePath


def load_package_source():
    spec = importlib.util.spec_from_file_location("local_sandbox_package_source", PACKAGE_SOURCE_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load package-source.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACKAGE_SOURCE = load_package_source()


def load_artifact_auditor():
    spec = importlib.util.spec_from_file_location("local_sandbox_artifact_auditor", AUDIT_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load audit-release-artifacts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ARTIFACT_AUDITOR = load_artifact_auditor()


def load_regenerator():
    spec = importlib.util.spec_from_file_location("local_sandbox_regenerator", REGENERATE_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load release/regenerate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


REGENERATOR = load_regenerator()


def load_shortcuts_release():
    spec = importlib.util.spec_from_file_location("local_sandbox_shortcuts_release", SHORTCUTS_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load release/shortcuts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SHORTCUTS = load_shortcuts_release()


def load_apple_release():
    spec = importlib.util.spec_from_file_location("local_sandbox_apple_release", APPLE_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load release/apple.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


APPLE = load_apple_release()


def run_rejected(arguments: list[str], output: Path) -> str:
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    result = subprocess.run(
        [sys.executable, *arguments],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        raise AssertionError(f"Unsafe package unexpectedly succeeded: {arguments}")
    if output.exists():
        raise AssertionError(f"Unsafe package wrote an output: {output}")
    message = f"{result.stdout}\n{result.stderr}"
    if not any(phrase in message for phrase in ["symbolic link", "real directory", "real regular file"]):
        raise AssertionError(f"Unsafe package failed for an unrelated reason: {message}")
    return message


def populate_source_root(root: Path, *, skipped_directory: str | None = None) -> None:
    root.mkdir()
    for name in PACKAGE_SOURCE.ROOT_FILES:
        (root / name).write_text(f"fixture for {name}\n", encoding="utf-8")
    for name in PACKAGE_SOURCE.SOURCE_DIRECTORIES:
        if name != skipped_directory:
            (root / name).mkdir(parents=True)


def populate_selfhost_root(root: Path) -> Path:
    for relative, contents in {
        "selfhost/Caddyfile": b"fixture\n",
        "selfhost/compose.yaml": b"services: {}\n",
        "public/local/app.js": b"console.log('fixture')\n",
        "public/local/capabilities.json": b"{}\n",
        "public/shortcuts/catalog.json": b"{}\n",
        "docs/ROADMAP-AUTOMATION.md": b"# Fixture\n",
        "public/downloads/Local-Sandbox-Source.zip": b"fixture source bytes",
    }.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    return root / "public/downloads/Local-Sandbox-Source.zip"


def shortcut_recipe() -> dict[str, object]:
    return {
        "version": 1,
        "release": "0.3.0",
        "packages": [
            {
                "id": "local",
                "name": "Agent Step - Local",
                "file": "Agent Step - Local.shortcut",
                "requires": [],
            },
            {
                "id": "runner",
                "name": "Local Sandbox",
                "file": "Local Sandbox.shortcut",
                "requires": ["local"],
            },
        ],
    }


def write_shortcut_fixture(root: Path, recipe: dict[str, object] | None = None) -> tuple[Path, Path]:
    exports = root / "exports"
    exports.mkdir(parents=True)
    recipe = recipe or shortcut_recipe()
    recipe_path = root / "recipe.json"
    recipe_path.write_text(json.dumps(recipe) + "\n", encoding="utf-8")
    for row in recipe.get("packages", []):
        filename = row.get("file") if isinstance(row, dict) else None
        if isinstance(filename, str) and Path(filename).name == filename:
            (exports / filename).write_bytes(f"unsigned {filename}".encode())
    return recipe_path, exports


class ReleasePackagerSafetyTests(unittest.TestCase):
    def test_source_packager_generates_next_environment_without_checkout_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            populate_source_root(root)
            project = root / "ios/LocalSandbox.xcodeproj/project.pbxproj"
            project.parent.mkdir(parents=True, exist_ok=True)
            project.write_text("// fixture\n", encoding="utf-8")
            first = temporary / "first.zip"
            second = temporary / "second.zip"

            PACKAGE_SOURCE.build(root, first)
            (root / "next-env.d.ts").write_text("checkout-local generated bytes\n", encoding="utf-8")
            PACKAGE_SOURCE.build(root, second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(
                    archive.read("Local-Sandbox/next-env.d.ts"),
                    PACKAGE_SOURCE.GENERATED_ROOT_FILES[PurePosixPath("next-env.d.ts")],
                )

    def test_reader_rejects_symlink_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            real_root = temporary / "real-repo"
            real_root.mkdir()
            symlink_root = temporary / "repo"
            symlink_root.symlink_to(real_root, target_is_directory=True)

            with self.assertRaises(UnsafeReleasePath):
                SafeRoot(symlink_root)

    def test_source_packager_rejects_root_file_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            root.mkdir()
            outside = temporary / "outside-secret"
            outside.write_text("must not be packaged", encoding="utf-8")
            (root / ".env.example").symlink_to(outside)
            output = temporary / "source.zip"
            run_rejected(
                [str(PACKAGE_SOURCE_SCRIPT), "--root", str(root), "--output", str(output)],
                output,
            )

    def test_source_packager_rejects_directory_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            populate_source_root(root, skipped_directory="app")
            outside = temporary / "outside-app"
            outside.mkdir()
            (outside / "secret.ts").write_text("must not be packaged", encoding="utf-8")
            (root / "app").symlink_to(outside, target_is_directory=True)
            output = temporary / "source.zip"
            run_rejected(
                [str(PACKAGE_SOURCE_SCRIPT), "--root", str(root), "--output", str(output)],
                output,
            )

    def test_source_packager_rejects_nested_file_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            populate_source_root(root)
            outside = temporary / "outside-secret"
            outside.write_text("must not be packaged", encoding="utf-8")
            (root / "app/escape.txt").symlink_to(outside)
            output = temporary / "source.zip"
            run_rejected(
                [str(PACKAGE_SOURCE_SCRIPT), "--root", str(root), "--output", str(output)],
                output,
            )

    def test_source_packager_does_not_read_excluded_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repo"
            fixtures = {
                "app/keep.txt": "allowed",
                "app/.env.production": "secret",
                "app/archive.zip": "secret",
                "app/downloads/private.txt": "secret",
                "app/__pycache__/cached.pyc": "secret",
            }
            fixtures.update({
                f"app/signing-material{suffix}": "secret"
                for suffix in SENSITIVE_RELEASE_SUFFIXES
            })
            for relative, contents in fixtures.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents, encoding="utf-8")

            original_read = SafeRoot._read_regular_at
            opened: list[PurePosixPath] = []

            def guarded_read(directory: int, name: str, path: PurePosixPath) -> tuple[bytes, int]:
                opened.append(path)
                if path != PurePosixPath("app/keep.txt"):
                    raise AssertionError(f"Excluded input was opened: {path}")
                return original_read(directory, name, path)

            with patch.object(SafeRoot, "_read_regular_at", new=staticmethod(guarded_read)):
                entries = PACKAGE_SOURCE.release_entries(
                    root,
                    root_files=set(),
                    source_directories={"app"},
                )

            self.assertEqual(opened, [PurePosixPath("app/keep.txt")])
            self.assertEqual(
                [
                    relative
                    for relative, _data, _mode in entries
                    if relative not in PACKAGE_SOURCE.GENERATED_ROOT_FILES
                ],
                opened,
            )

    def test_qualification_tracker_is_explicitly_excluded_from_release_zips(self) -> None:
        self.assertNotIn(".github", PACKAGE_SOURCE.SOURCE_DIRECTORIES)
        self.assertNotIn("qualification", PACKAGE_SOURCE.SOURCE_DIRECTORIES)
        self.assertIn("qualification", PACKAGE_SOURCE.EXCLUDED_SEGMENTS)
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            populate_source_root(root)
            qualification = root / "qualification"
            qualification.mkdir()
            (qualification / "Local-Sandbox-0.3-Progress.xlsx").write_bytes(b"private tracker")
            (qualification / "Local-Sandbox-0.3-Progress.snapshot.json").write_text(
                "{}\n", encoding="utf-8"
            )
            workflow = root / ".github/workflows/verify.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("canonical-only workflow\n", encoding="utf-8")
            project = root / "ios/LocalSandbox.xcodeproj/project.pbxproj"
            project.parent.mkdir(parents=True, exist_ok=True)
            project.write_text("// fixture\n", encoding="utf-8")
            output = temporary / "source.zip"
            PACKAGE_SOURCE.build(root, output)
            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
                self.assertFalse(any("/qualification/" in name for name in names))
                self.assertFalse(any(name.startswith("Local-Sandbox/.github/") for name in names))
                self.assertNotIn("Local-Sandbox/docs/validation.json", names)
                self.assertFalse(any(name.startswith("Local-Sandbox/public/downloads/") for name in names))

    def test_artifact_auditor_rejects_every_sensitive_file_suffix(self) -> None:
        for suffix in sorted(SENSITIVE_RELEASE_SUFFIXES):
            with self.subTest(suffix=suffix):
                archive_data = io.BytesIO()
                with zipfile.ZipFile(archive_data, "w") as archive:
                    archive.writestr(f"app/signing-material{suffix}", b"fixture")
                with self.assertRaisesRegex(ValueError, "Credential-like file"):
                    ARTIFACT_AUDITOR.audit_zip(archive_data.getvalue(), "synthetic archive")

    def test_artifact_auditor_streams_every_member_without_size_or_suffix_bypass(self) -> None:
        token = b"github_pat_" + (b"A" * 24)
        cases = {
            "app/.env.example": token,
            "app/opaque.bin": token,
            "app/large.txt": (b"x" * (2 * 1024 * 1024 + 17)) + token,
            "app/chunk-boundary.bin": (
                b"x" * (ARTIFACT_AUDITOR.SCAN_CHUNK_BYTES - 5)
            ) + token,
        }
        home_paths = {
            "mac-home": b"/" + b"Users/" + b"release-user/project",
            "linux-home": b"/" + b"home/" + b"release-user/project",
            "windows-forward-home": b"C:/" + b"Users/" + b"release-user/project",
            "windows-backslash-home": (
                b"C:" + b"\\" + b"Users" + b"\\" + b"release-user" + b"\\project"
            ),
        }
        for label, home_path in home_paths.items():
            split = max(1, len(home_path) // 2)
            cases[f"app/{label}.bin"] = home_path
            cases[f"app/{label}-chunk-boundary.bin"] = (
                b"x" * (ARTIFACT_AUDITOR.SCAN_CHUNK_BYTES - split)
            ) + home_path
        for filename, contents in cases.items():
            with self.subTest(filename=filename):
                archive_data = io.BytesIO()
                with zipfile.ZipFile(archive_data, "w") as archive:
                    archive.writestr(filename, contents)
                with self.assertRaisesRegex(ValueError, re.escape(filename)):
                    ARTIFACT_AUDITOR.audit_zip(archive_data.getvalue(), "synthetic archive")

    def test_source_archive_keeps_tests_and_scripts_without_machine_home_triggers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "source.zip"
            PACKAGE_SOURCE.build(ROOT, output)
            with zipfile.ZipFile(output) as archive:
                names = set(archive.namelist())
                self.assertIn("Local-Sandbox/scripts/release/tracker.py", names)
                self.assertIn("Local-Sandbox/tests/release-tracker.test.py", names)
                self.assertFalse(any(name.startswith("Local-Sandbox/.github/") for name in names))
            ARTIFACT_AUDITOR.audit_zip(output.read_bytes(), "source archive", nested=True)

    def test_artifact_auditor_accepts_explicit_artifact_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            source = temporary / "source.zip"
            selfhost = temporary / "selfhost.zip"
            source_buffer = io.BytesIO()
            with zipfile.ZipFile(source_buffer, "w") as archive:
                for name in (
                    "Local-Sandbox/package.json",
                    "Local-Sandbox/ios/LocalSandbox.xcodeproj/project.pbxproj",
                    "Local-Sandbox/public/local/capabilities.js",
                    "Local-Sandbox/public/local/workspace-sync.js",
                ):
                    archive.writestr(name, b"fixture\n")
                archive.writestr(
                    "Local-Sandbox/public/local/capabilities.json",
                    json.dumps(ARTIFACT_AUDITOR.HOSTED_CAPABILITIES).encode(),
                )
            source.write_bytes(source_buffer.getvalue())
            with zipfile.ZipFile(selfhost, "w") as archive:
                archive.writestr("site/local/capabilities.js", b"fixture\n")
                archive.writestr(
                    "site/local/capabilities.json",
                    json.dumps(ARTIFACT_AUDITOR.STATIC_CAPABILITIES).encode(),
                )
                archive.writestr(
                    "site/downloads/Local-Sandbox-Source.zip",
                    source.read_bytes(),
                )

            result = subprocess.run(
                [
                    sys.executable,
                    str(AUDIT_SCRIPT),
                    "--source-artifact",
                    str(source),
                    "--selfhost-artifact",
                    str(selfhost),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "passed")

    def test_regenerator_audits_temporary_zips_before_replacing_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "downloads"
            calls: list[list[str]] = []

            def fail_at_audit(arguments: list[str]) -> None:
                calls.append(arguments)
                if arguments[0] == "scripts/audit-release-artifacts.py":
                    raise subprocess.CalledProcessError(1, arguments)

            with (
                patch.object(REGENERATOR, "run", side_effect=fail_at_audit),
                patch.object(REGENERATOR.os, "replace") as replace,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                REGENERATOR.regenerate(output)

            self.assertEqual(calls[-1][0], "scripts/audit-release-artifacts.py")
            replace.assert_not_called()

    def test_regenerator_runs_full_temporary_freshness_before_replacing_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "downloads"
            calls: list[list[str]] = []

            def fail_at_freshness(arguments: list[str]) -> None:
                calls.append(arguments)
                if "--output" in arguments:
                    generated = Path(arguments[arguments.index("--output") + 1])
                    generated.write_bytes(f"new {generated.name}".encode())
                if arguments[0] == "scripts/release/check_freshness.py":
                    raise subprocess.CalledProcessError(1, arguments)

            with (
                patch.object(REGENERATOR, "run", side_effect=fail_at_freshness),
                patch.object(REGENERATOR.os, "replace") as replace,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                REGENERATOR.regenerate(output)

            freshness = calls[-1]
            self.assertEqual(freshness[0], "scripts/release/check_freshness.py")
            for flag in ("--source-artifact", "--selfhost-artifact", "--guide-artifact"):
                staged = Path(freshness[freshness.index(flag) + 1])
                self.assertTrue(staged.parent.name.startswith(".regenerate-"))
            replace.assert_not_called()

    def test_regenerator_rolls_back_the_whole_existing_set_on_replacement_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "downloads"
            output.mkdir()
            old = {
                name: f"old {name}".encode()
                for name in REGENERATOR.ARTIFACT_NAMES
            }
            for name, contents in old.items():
                (output / name).write_bytes(contents)

            def fake_run(arguments: list[str]) -> None:
                if "--output" in arguments:
                    generated = Path(arguments[arguments.index("--output") + 1])
                    generated.write_bytes(f"new {generated.name}".encode())

            real_replace = os.replace
            failed = False

            def fail_source_once(source: Path, destination: Path) -> None:
                nonlocal failed
                source = Path(source)
                if not failed and source.name == "Local-Sandbox-Source.zip":
                    failed = True
                    raise OSError("synthetic replacement failure")
                real_replace(source, destination)

            with (
                patch.object(REGENERATOR, "run", side_effect=fake_run),
                patch.object(REGENERATOR.os, "replace", side_effect=fail_source_once),
                self.assertRaisesRegex(OSError, "synthetic replacement failure"),
            ):
                REGENERATOR.regenerate(output)

            self.assertTrue(failed)
            self.assertEqual(
                {name: (output / name).read_bytes() for name in REGENERATOR.ARTIFACT_NAMES},
                old,
            )

    def test_regenerator_removes_new_outputs_on_replacement_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "downloads"

            def fake_run(arguments: list[str]) -> None:
                if "--output" in arguments:
                    generated = Path(arguments[arguments.index("--output") + 1])
                    generated.write_bytes(f"new {generated.name}".encode())

            real_replace = os.replace
            failed = False

            def fail_source_once(source: Path, destination: Path) -> None:
                nonlocal failed
                source = Path(source)
                if not failed and source.name == "Local-Sandbox-Source.zip":
                    failed = True
                    raise OSError("synthetic replacement failure")
                real_replace(source, destination)

            with (
                patch.object(REGENERATOR, "run", side_effect=fake_run),
                patch.object(REGENERATOR.os, "replace", side_effect=fail_source_once),
                self.assertRaisesRegex(OSError, "synthetic replacement failure"),
            ):
                REGENERATOR.regenerate(output)

            self.assertTrue(failed)
            self.assertFalse(any((output / name).exists() for name in REGENERATOR.ARTIFACT_NAMES))

    def test_regenerator_rolls_back_when_published_readback_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "downloads"
            output.mkdir()
            old = {
                name: f"old {name}".encode()
                for name in REGENERATOR.ARTIFACT_NAMES
            }
            for name, contents in old.items():
                (output / name).write_bytes(contents)
            freshness_calls = 0

            def fail_second_freshness(arguments: list[str]) -> None:
                nonlocal freshness_calls
                if "--output" in arguments:
                    generated = Path(arguments[arguments.index("--output") + 1])
                    generated.write_bytes(f"new {generated.name}".encode())
                if arguments[0] == "scripts/release/check_freshness.py":
                    freshness_calls += 1
                    if freshness_calls == 2:
                        raise subprocess.CalledProcessError(1, arguments)

            with (
                patch.object(REGENERATOR, "run", side_effect=fail_second_freshness),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                REGENERATOR.regenerate(output)

            self.assertEqual(freshness_calls, 2)
            self.assertEqual(
                {name: (output / name).read_bytes() for name in REGENERATOR.ARTIFACT_NAMES},
                old,
            )

    def test_regenerator_publishes_the_prevalidated_set_on_success(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            output = Path(temporary_directory) / "downloads"
            freshness_calls = 0

            def fake_run(arguments: list[str]) -> None:
                nonlocal freshness_calls
                if "--output" in arguments:
                    generated = Path(arguments[arguments.index("--output") + 1])
                    generated.write_bytes(f"new {generated.name}".encode())
                if arguments[0] == "scripts/release/check_freshness.py":
                    freshness_calls += 1

            with patch.object(REGENERATOR, "run", side_effect=fake_run):
                result = REGENERATOR.regenerate(output)

            self.assertEqual(result["status"], "regenerated-and-fresh")
            self.assertEqual(freshness_calls, 2)
            self.assertEqual(
                {
                    name: (output / name).read_bytes()
                    for name in REGENERATOR.ARTIFACT_NAMES
                },
                {
                    name: f"new {name}".encode()
                    for name in REGENERATOR.ARTIFACT_NAMES
                },
            )

    def test_source_packager_includes_default_shortcut_recipe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            populate_source_root(root)
            recipe = root / "release/shortcuts/recipe.json"
            recipe.parent.mkdir(parents=True, exist_ok=True)
            recipe.write_text('{"version":1,"release":"0.3.0","packages":[]}\n', encoding="utf-8")
            project = root / "ios/LocalSandbox.xcodeproj/project.pbxproj"
            project.parent.mkdir(parents=True, exist_ok=True)
            project.write_text("// fixture\n", encoding="utf-8")
            output = temporary / "source.zip"

            PACKAGE_SOURCE.build(root, output)

            with zipfile.ZipFile(output) as archive:
                self.assertEqual(
                    archive.read("Local-Sandbox/release/shortcuts/recipe.json"),
                    recipe.read_bytes(),
                )

    def test_source_packager_canonicalizes_noisy_permission_bits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            populate_source_root(root)
            project = root / "ios/LocalSandbox.xcodeproj/project.pbxproj"
            project.parent.mkdir(parents=True, exist_ok=True)
            project.write_text("// fixture\n", encoding="utf-8")
            executable = root / "scripts/run-release"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            first = temporary / "first.zip"
            second = temporary / "second.zip"

            for path in (candidate for candidate in root.rglob("*") if candidate.is_file()):
                path.chmod(0o700 if path == executable else 0o600)
            PACKAGE_SOURCE.build(root, first)
            for path in (candidate for candidate in root.rglob("*") if candidate.is_file()):
                path.chmod(0o777 if path == executable else 0o666)
            PACKAGE_SOURCE.build(root, second)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                modes = {
                    info.filename: (info.external_attr >> 16) & 0o777
                    for info in archive.infolist()
                }
            self.assertEqual(modes["Local-Sandbox/scripts/run-release"], 0o755)
            self.assertEqual(modes["Local-Sandbox/README.md"], 0o644)

    def test_shortcut_publisher_requires_canonical_https_shortcuts_base(self) -> None:
        self.assertEqual(
            SHORTCUTS.canonical_shortcuts_base_url("https://packages.example/shortcuts"),
            "https://packages.example/shortcuts",
        )
        self.assertEqual(
            SHORTCUTS.canonical_shortcuts_base_url("https://packages.example:8443/shortcuts"),
            "https://packages.example:8443/shortcuts",
        )
        for value in [
            "http://packages.example/shortcuts",
            "HTTPS://packages.example/shortcuts",
            "https://Packages.example/shortcuts",
            "https://packages.example:443/shortcuts",
            "https://packages.example/shortcuts/",
            "https://packages.example/shortcuts/../shortcuts",
            "https://packages.example/%73hortcuts",
            "https://user@packages.example/shortcuts",
            "https://packages.example/shortcuts?release=0.3.0",
            "https://packages.example/shortcuts#release",
            " https://packages.example/shortcuts",
        ]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                SHORTCUTS.canonical_shortcuts_base_url(value)

    def test_shortcut_recipe_enforces_the_shared_catalog_bounds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            invalid_recipes: dict[str, dict[str, object]] = {}

            empty = shortcut_recipe()
            empty["packages"] = []
            invalid_recipes["empty"] = empty

            boolean_version = shortcut_recipe()
            boolean_version["version"] = True
            invalid_recipes["boolean version"] = boolean_version

            too_many = shortcut_recipe()
            too_many["packages"] = [
                {
                    "id": f"p{index}",
                    "name": f"Package {index}",
                    "file": f"Package-{index}.shortcut",
                    "requires": [],
                }
                for index in range(31)
            ]
            invalid_recipes["too many"] = too_many

            unsafe_name = shortcut_recipe()
            unsafe_name["packages"][0]["name"] = "Agent\nStep"
            invalid_recipes["unsafe name"] = unsafe_name

            duplicate_id = shortcut_recipe()
            duplicate_id["packages"][1]["id"] = "local"
            invalid_recipes["duplicate ID"] = duplicate_id

            self_dependency = shortcut_recipe()
            self_dependency["packages"][0]["requires"] = ["local"]
            invalid_recipes["self dependency"] = self_dependency

            unknown_dependency = shortcut_recipe()
            unknown_dependency["packages"][1]["requires"] = ["missing"]
            invalid_recipes["unknown dependency"] = unknown_dependency

            repeated_dependency = shortcut_recipe()
            repeated_dependency["packages"][1]["requires"] = ["local", "local"]
            invalid_recipes["repeated dependency"] = repeated_dependency

            for label, recipe in invalid_recipes.items():
                path = temporary / f"{label.replace(' ', '-')}.json"
                path.write_text(json.dumps(recipe) + "\n", encoding="utf-8")
                with self.subTest(label=label), self.assertRaises(ValueError):
                    SHORTCUTS.load_recipe(path)

            recipe_path, exports = write_shortcut_fixture(temporary / "oversized")
            (exports / "Agent Step - Local.shortcut").write_bytes(
                b"x" * (SHORTCUTS.MAXIMUM_PACKAGE_BYTES + 1)
            )
            _release, rows = SHORTCUTS.load_recipe(recipe_path)
            with self.assertRaisesRegex(ValueError, "between 1 and 5000000 bytes"):
                SHORTCUTS.validate_exports(exports, rows)

    def test_shortcut_publish_recovers_after_destination_rename_without_resigning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            recipe_path, exports = write_shortcut_fixture(temporary / "input")
            output = temporary / "published"
            output.mkdir()
            (output / "catalog.json").write_text(
                json.dumps(
                    {
                        "version": 1,
                        "release": "0.3.0",
                        "packages": [],
                        "status": "awaiting-signed-device-exports",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            signer_calls: list[str] = []

            def fake_signer(source: Path, destination: Path) -> None:
                signer_calls.append(source.name)
                destination.write_bytes(b"signed:" + source.read_bytes())

            publish_arguments = {
                "exports": exports,
                "base_url": "https://packages.example/shortcuts",
                "recipe_path": recipe_path,
                "output": output,
                "check": False,
                "signer": fake_signer,
            }
            with (
                patch.object(SHORTCUTS.platform, "system", return_value="Darwin"),
                patch.object(SHORTCUTS, "write_catalog", side_effect=RuntimeError("injected crash")),
                self.assertRaisesRegex(RuntimeError, "injected crash"),
            ):
                SHORTCUTS.publish(**publish_arguments)

            self.assertEqual(signer_calls, ["Agent Step - Local.shortcut", "Local Sandbox.shortcut"])
            self.assertTrue((output / "0.3.0/local.shortcut").is_file())
            for exported in exports.iterdir():
                exported.unlink()
            exports.rmdir()

            check_result = SHORTCUTS.publish(**{**publish_arguments, "check": True})
            self.assertEqual(check_result["state"], "recoverable")
            recovery = SHORTCUTS.publish(**publish_arguments)
            self.assertTrue(recovery["recovered"])
            self.assertEqual(signer_calls, ["Agent Step - Local.shortcut", "Local Sandbox.shortcut"])

            catalog = json.loads((output / "catalog.json").read_text(encoding="utf-8"))
            self.assertEqual(
                [package["url"] for package in catalog["packages"]],
                [
                    "https://packages.example/shortcuts/0.3.0/local.shortcut",
                    "https://packages.example/shortcuts/0.3.0/runner.shortcut",
                ],
            )
            self.assertEqual(
                SHORTCUTS.publish(**{**publish_arguments, "check": True})["state"],
                "complete",
            )
            with self.assertRaises(FileExistsError):
                SHORTCUTS.publish(**publish_arguments)

            (output / "0.3.0/unexpected.shortcut").write_bytes(b"unexpected")
            with self.assertRaisesRegex(SHORTCUTS.PublicationConflict, "exact recipe file set"):
                SHORTCUTS.publish(**{**publish_arguments, "check": True})
            command = subprocess.run(
                [
                    sys.executable,
                    str(SHORTCUTS_SCRIPT),
                    "--exports",
                    str(exports),
                    "--base-url",
                    "https://packages.example/shortcuts",
                    "--recipe",
                    str(recipe_path),
                    "--output",
                    str(output),
                    "--check",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(command.returncode, 1)
            self.assertEqual(json.loads(command.stdout)["state"], "conflicting")

    def test_shortcut_publisher_rejects_oversized_signer_output_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            recipe = shortcut_recipe()
            recipe["packages"] = recipe["packages"][:1]
            recipe_path, exports = write_shortcut_fixture(temporary / "input", recipe)
            output = temporary / "published"

            def oversized_signer(_source: Path, destination: Path) -> None:
                destination.write_bytes(b"x" * (SHORTCUTS.MAXIMUM_PACKAGE_BYTES + 1))

            with (
                patch.object(SHORTCUTS.platform, "system", return_value="Darwin"),
                self.assertRaisesRegex(ValueError, "between 1 and 5000000 bytes"),
            ):
                SHORTCUTS.publish(
                    exports=exports,
                    base_url="https://packages.example/shortcuts",
                    recipe_path=recipe_path,
                    output=output,
                    check=False,
                    signer=oversized_signer,
                )
            self.assertFalse((output / "0.3.0").exists())
            self.assertFalse((output / "catalog.json").exists())

    def test_apple_archive_checks_exact_xcode_then_authorization_before_build_work(self) -> None:
        arguments = [
            "archive",
            "--team",
            "ABCDEFGHIJ",
            "--bundle-id",
            "com.example.LocalSandbox",
            "--build-number",
            "321.4.0",
            "--release-commit",
            "a" * 40,
            "--release-version",
            "0.3.0",
        ]
        toolchain = APPLE.PinnedXcode(
            Path("/fake/Xcode.app/Contents/Developer/usr/bin/xcodebuild"),
            Path("/fake/Xcode.app/Contents/Developer"),
            (1, 2, 3, 4),
            APPLE.REQUIRED_XCODE_VERSION,
            APPLE.REQUIRED_XCODE_BUILD,
        )
        for label in ["missing receipt", "stale receipt", "mismatched receipt"]:
            calls: list[list[str]] = []

            def fake_run(
                command: list[str],
                *,
                cwd: Path,
                env: dict[str, str],
            ) -> None:
                del cwd, env
                calls.append(command)
                if command[0] == "node":
                    raise subprocess.CalledProcessError(1, command, stderr=label)
                if command[0] == str(toolchain.executable):
                    raise AssertionError("xcodebuild ran before release authorization")

            with (
                self.subTest(label=label),
                patch.object(APPLE.platform, "system", return_value="Darwin"),
                patch.object(
                    APPLE,
                    "release_xcode_toolchain",
                    return_value=toolchain,
                ),
                patch.object(APPLE, "run", side_effect=fake_run),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                APPLE.main(arguments)
            self.assertTrue(calls)
            self.assertEqual(calls[0][0:3], ["node", "scripts/release/apple_ci.mjs", "authorize"])
            self.assertIn(APPLE.REQUIRED_XCODE_VERSION, calls[0])
            self.assertIn(APPLE.REQUIRED_XCODE_BUILD, calls[0])
            self.assertFalse(any(command[0] == str(toolchain.executable) for command in calls))

    def test_apple_archive_scrubs_readiness_and_builds_the_authorized_commit_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "repository"
            project = root / "ios/LocalSandbox.xcodeproj/project.pbxproj"
            project.parent.mkdir(parents=True)
            project.write_text("authorized source\n", encoding="utf-8")
            subprocess.run(["git", "init", "-b", "main"], cwd=root, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.name", "Release Test"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.email", "release@example.invalid"],
                cwd=root,
                check=True,
            )
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "authorized"], cwd=root, check=True, capture_output=True)
            release_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            toolchain = APPLE.PinnedXcode(
                Path("/fake/Xcode.app/Contents/Developer/usr/bin/xcodebuild"),
                Path("/fake/Xcode.app/Contents/Developer"),
                (1, 2, 3, 4),
                APPLE.REQUIRED_XCODE_VERSION,
                APPLE.REQUIRED_XCODE_BUILD,
            )
            child_calls: list[tuple[list[str], Path, dict[str, str]]] = []
            archive_source: bytes | None = None
            snapshot_root: Path | None = None

            def fake_run(
                command: list[str],
                *,
                cwd: Path,
                env: dict[str, str],
            ) -> None:
                nonlocal archive_source, snapshot_root
                child_calls.append((command, cwd, dict(env)))
                if command[0] == "node":
                    self.assertEqual(env.get(APPLE.ACTION_READINESS_ENVIRONMENT), "protected")
                    project.write_text("mutated after authorization\n", encoding="utf-8")
                else:
                    self.assertNotIn(APPLE.ACTION_READINESS_ENVIRONMENT, env)
                if command[-1:] == ["archive"]:
                    snapshot_root = cwd
                    archive_source = (cwd / "ios/LocalSandbox.xcodeproj/project.pbxproj").read_bytes()
                    self.assertFalse(os.access(cwd, os.W_OK))
                    for option in ("-archivePath", "-derivedDataPath"):
                        output = Path(command[command.index(option) + 1])
                        self.assertTrue(output.is_relative_to(root / "release-output"))
                        self.assertFalse(output.is_relative_to(cwd))

            arguments = [
                "archive",
                "--team",
                "ABCDEFGHIJ",
                "--build-number",
                "321.4.0",
                "--release-commit",
                release_commit,
            ]
            with (
                patch.object(APPLE, "ROOT", root),
                patch.object(APPLE.platform, "system", return_value="Darwin"),
                patch.object(APPLE, "release_xcode_toolchain", return_value=toolchain),
                patch.object(APPLE, "recheck_release_xcode"),
                patch.object(APPLE, "run", side_effect=fake_run),
                patch.dict(os.environ, {APPLE.ACTION_READINESS_ENVIRONMENT: "protected"}),
            ):
                APPLE.main(arguments)

            self.assertEqual(project.read_text(encoding="utf-8"), "mutated after authorization\n")
            self.assertEqual(archive_source, b"authorized source\n")
            self.assertIsNotNone(snapshot_root)
            self.assertFalse(snapshot_root.exists())
            self.assertEqual(
                sum(
                    APPLE.ACTION_READINESS_ENVIRONMENT in environment
                    for _command, _cwd, environment in child_calls
                ),
                1,
            )

    def test_apple_archive_rejects_non_rc_xcode_version_output(self) -> None:
        self.assertEqual(
            APPLE.parse_release_xcode_output("Xcode 27.0\nBuild version 27A266a\n"),
            ("27.0", "27A266a"),
        )
        for output in (
            "Xcode 27.0\nBuild version 27A5252f\n",
            "Xcode 27.1\nBuild version 27B123\n",
            "Xcode 27.0 beta 6\nBuild version 27A5252f\n",
            "27.0 27A266a\n",
        ):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                APPLE.parse_release_xcode_output(output)

    def test_apple_rechecks_the_pinned_xcode_executable_identity_and_build(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            executable = Path(temporary_directory) / "xcodebuild"
            executable.write_bytes(b"pinned toolchain")
            executable.chmod(0o755)
            toolchain = APPLE.PinnedXcode(
                executable,
                executable.parent,
                APPLE.executable_identity(executable),
                APPLE.REQUIRED_XCODE_VERSION,
                APPLE.REQUIRED_XCODE_BUILD,
            )
            completed = subprocess.CompletedProcess(
                [str(executable), "-version"],
                0,
                stdout="Xcode 27.0\nBuild version 27A266a\n",
            )
            with patch.object(APPLE.subprocess, "run", return_value=completed) as invoked:
                APPLE.recheck_release_xcode(toolchain, {})
            self.assertEqual(invoked.call_count, 1)
            executable.write_bytes(b"replaced toolchain binary")
            executable.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "changed after release authorization"):
                APPLE.recheck_release_xcode(toolchain, {})

    def test_selfhost_packager_rejects_fixed_file_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            source_archive = populate_selfhost_root(root)
            outside = temporary / "outside-secret"
            outside.write_text("must not be packaged", encoding="utf-8")
            (root / "selfhost/Caddyfile").unlink()
            (root / "selfhost/Caddyfile").symlink_to(outside)
            output = temporary / "selfhost.zip"
            run_rejected(
                [
                    str(SELFHOST_SCRIPT), "--root", str(root),
                    "--source-archive", str(source_archive), "--output", str(output),
                ],
                output,
            )

    def test_selfhost_packager_rejects_directory_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            source_archive = populate_selfhost_root(root)
            outside = temporary / "outside-local"
            outside.mkdir()
            (outside / "secret.js").write_text("must not be packaged", encoding="utf-8")
            for path in (root / "public/local").iterdir():
                path.unlink()
            (root / "public/local").rmdir()
            (root / "public/local").symlink_to(outside, target_is_directory=True)
            output = temporary / "selfhost.zip"
            run_rejected(
                [
                    str(SELFHOST_SCRIPT), "--root", str(root),
                    "--source-archive", str(source_archive), "--output", str(output),
                ],
                output,
            )

    def test_selfhost_packager_rejects_nested_and_override_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            source_archive = populate_selfhost_root(root)
            outside = temporary / "outside-secret"
            outside.write_text("must not be packaged", encoding="utf-8")
            (root / "public/local/escape.js").symlink_to(outside)
            output = temporary / "nested.zip"
            run_rejected(
                [
                    str(SELFHOST_SCRIPT), "--root", str(root),
                    "--source-archive", str(source_archive), "--output", str(output),
                ],
                output,
            )

            (root / "public/local/escape.js").unlink()
            source_archive.unlink()
            source_archive.symlink_to(outside)
            output = temporary / "override.zip"
            run_rejected(
                [
                    str(SELFHOST_SCRIPT), "--root", str(root),
                    "--source-archive", str(source_archive), "--output", str(output),
                ],
                output,
            )

    def test_reader_rejects_real_directory_swap_during_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            root = temporary / "repo"
            (root / "app").mkdir(parents=True)
            (root / "app/value.txt").write_text("inside", encoding="utf-8")
            replacement = temporary / "replacement-app"
            replacement.mkdir()
            (replacement / "value.txt").write_text("outside", encoding="utf-8")

            with SafeRoot(root) as reader:
                files = reader.iter_regular_files(PurePosixPath("app"))
                relative, data, _mode = next(files)
                self.assertEqual(relative, PurePosixPath("app/value.txt"))
                self.assertEqual(data, b"inside")
                (root / "app").rename(root / "original-app")
                replacement.rename(root / "app")
                with self.assertRaisesRegex(UnsafeReleasePath, "identity changed"):
                    list(files)


if __name__ == "__main__":
    unittest.main()
