#!/usr/bin/env python3
"""Fail-closed contracts for the canonical 57-gate XLSX qualification tracker."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

from release.tracker import (  # noqa: E402
    APPLE_PENDING,
    ARTIFACT_PATHS,
    CANONICAL_SNAPSHOT_PATH,
    CANONICAL_TRACKER_PATH,
    EXPECTED_IMMUTABLE_REQUIREMENTS_SHA256,
    EXPECTED_GATE_IDS,
    IMMUTABLE_REQUIREMENT_COLUMNS,
    TrackerError,
    assert_profile,
    build_snapshot,
    export_readiness,
    verify_tracker_bundle,
)
from release.candidate_digest import CandidateDigestError, candidate_digest  # noqa: E402
from release_tracker_fixture import (  # noqa: E402
    CANONICAL_REQUIREMENT_TEXT,
    build_workbook,
    replace_part,
)


class ReleaseTrackerTests(unittest.TestCase):
    def bundle(self, **options):
        workbook = build_workbook(**options)
        snapshot = build_snapshot(workbook)
        return workbook, snapshot, verify_tracker_bundle(workbook, snapshot)

    def test_exact_ordered_57_rows_and_evidence_are_bound_without_prose(self) -> None:
        workbook, snapshot, bundle = self.bundle()
        document = json.loads(snapshot)
        self.assertEqual([row["id"] for row in document["gates"]], list(EXPECTED_GATE_IDS))
        self.assertEqual(document["requirements"]["rows"], 57)
        self.assertEqual(document["evidence"]["rows"], 57)
        self.assertEqual(document["workbook"]["sha256"], bundle.workbook_sha256)
        self.assertNotIn("Exact fixture evidence", snapshot.decode())
        self.assertNotIn("tests/GOV-01.test.py", snapshot.decode())
        self.assertEqual(bundle.binding()["path"], CANONICAL_TRACKER_PATH.as_posix())
        self.assertEqual(
            bundle.binding()["snapshotPath"], CANONICAL_SNAPSHOT_PATH.as_posix()
        )
        self.assertEqual(build_snapshot(workbook), snapshot)

    def test_immutable_contract_rejects_nonempty_weakened_text_everywhere(self) -> None:
        self.assertEqual(tuple(CANONICAL_REQUIREMENT_TEXT), EXPECTED_GATE_IDS)
        self.assertEqual(
            IMMUTABLE_REQUIREMENT_COLUMNS,
            ("ID", "Phase", "Requirement", "Acceptance evidence", "Source", "Dependencies"),
        )
        self.assertEqual(
            EXPECTED_IMMUTABLE_REQUIREMENTS_SHA256,
            "8d0792903070b30159fa7d76805b8b1ec47691ced34e3a595b0caa3c3ec15462",
        )
        canonical_workbook = build_workbook()
        canonical_snapshot = build_snapshot(canonical_workbook)
        verify_tracker_bundle(canonical_workbook, canonical_snapshot)
        mutations = (
            ("Requirement", {"requirement_overrides": {"GOV-01": "Document a smaller release"}}),
            (
                "Acceptance evidence",
                {"acceptance_overrides": {"GOV-01": "Manual review is sufficient"}},
            ),
            ("Source", {"source_overrides": {"GOV-01": "README.md"}}),
        )
        for field, options in mutations:
            with self.subTest(field=field):
                weakened_workbook = build_workbook(**options)
                with self.assertRaisesRegex(TrackerError, "immutable 0.3 contract changed"):
                    build_snapshot(weakened_workbook)
                with self.assertRaisesRegex(TrackerError, "immutable 0.3 contract changed"):
                    verify_tracker_bundle(weakened_workbook, canonical_snapshot)
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    tracker = root / CANONICAL_TRACKER_PATH
                    snapshot = root / CANONICAL_SNAPSHOT_PATH
                    tracker.parent.mkdir(parents=True)
                    tracker.write_bytes(weakened_workbook)
                    snapshot.write_bytes(canonical_snapshot)
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(ROOT / "scripts/release/tracker.py"),
                            "export-readiness",
                            "--root",
                            str(root),
                            "--profile",
                            "apple",
                            "--tracker",
                            CANONICAL_TRACKER_PATH.as_posix(),
                            "--expected-commit",
                            "a" * 40,
                            "--ready-at",
                            "2026-09-11T16:01:00Z",
                        ],
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertIn("immutable 0.3 contract changed", result.stderr)

    def test_reordered_requirement_rows_fail(self) -> None:
        order = list(EXPECTED_GATE_IDS)
        order[0], order[1] = order[1], order[0]
        with self.assertRaisesRegex(TrackerError, "canonical order"):
            build_snapshot(build_workbook(order=order))

    def test_pass_with_open_dependency_fails(self) -> None:
        with self.assertRaisesRegex(TrackerError, "dependencies remain open"):
            build_snapshot(build_workbook(statuses={"RUN-02": "IN PROGRESS"}))

    def test_dependency_text_cannot_be_removed(self) -> None:
        workbook = build_workbook()
        changed = replace_part(
            workbook,
            "xl/worksheets/sheet2.xml",
            lambda data: data.replace(b"BASE-01; BASE-02", b"None", 1),
        )
        with self.assertRaisesRegex(TrackerError, "canonical 0.3 graph"):
            build_snapshot(changed)

    def test_generic_pass_proof_fails(self) -> None:
        with self.assertRaisesRegex(TrackerError, "generic"):
            build_snapshot(build_workbook(evidence_overrides={"GOV-01": "done"}))

    def test_machine_home_paths_and_tokens_fail(self) -> None:
        for note, pattern in (
            ("Captured at /" + "Users/release-user/project", "local-machine path"),
            (f"token ghp_{'A' * 30}", "token-shaped credential"),
        ):
            with self.subTest(note=note):
                with self.assertRaisesRegex(TrackerError, pattern):
                    build_snapshot(build_workbook(note_overrides={"GOV-01": note}))

    def test_unapproved_formula_fails(self) -> None:
        workbook = build_workbook()
        changed = replace_part(
            workbook,
            "xl/worksheets/sheet1.xml",
            lambda data: data.replace(
                b"IF($B$7&gt;=0.05,1,0)",
                b"WEBSERVICE(&quot;https://example.invalid&quot;)",
                1,
            ),
        )
        with self.assertRaisesRegex(TrackerError, "formula contract"):
            build_snapshot(changed)

    def test_external_ooxml_relationship_fails(self) -> None:
        workbook = build_workbook()
        changed = replace_part(
            workbook,
            "xl/_rels/workbook.xml.rels",
            lambda data: data.replace(
                b'Target="/xl/styles.xml"',
                b'Target="https://example.invalid/styles.xml" TargetMode="External"',
                1,
            ),
        )
        with self.assertRaisesRegex(TrackerError, "external relationship"):
            build_snapshot(changed)

    def test_stale_workbook_or_altered_snapshot_fails(self) -> None:
        original = build_workbook()
        snapshot = build_snapshot(original)
        changed = build_workbook(
            evidence_overrides={"GOV-01": "tests/GOV-01.test.py 2/2 PASS at build 27A266a"}
        )
        with self.assertRaisesRegex(TrackerError, "stale, altered"):
            verify_tracker_bundle(changed, snapshot)
        document = json.loads(snapshot)
        document["gates"][0]["evidenceSha256"] = "0" * 64
        altered = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
        with self.assertRaisesRegex(TrackerError, "stale, altered"):
            verify_tracker_bundle(original, altered)

    def test_action_profiles_are_exact_and_noncircular(self) -> None:
        apple_statuses = {
            identifier: "NOT STARTED" for identifier in APPLE_PENDING
        }
        apple_statuses["REL-03"] = "IN PROGRESS"
        _workbook, _snapshot, apple = self.bundle(statuses=apple_statuses)
        self.assertIsNone(assert_profile(apple, "apple"))

        github_statuses = {"REL-06": "IN PROGRESS"}
        _workbook, _snapshot, github = self.bundle(statuses=github_statuses)
        self.assertIsNone(assert_profile(github, "github"))

        _workbook, _snapshot, complete = self.bundle()
        with self.assertRaisesRegex(TrackerError, "cannot be pre-passed"):
            assert_profile(complete, "apple")
        with self.assertRaisesRegex(TrackerError, "cannot be pre-passed"):
            assert_profile(complete, "github")

    def test_readiness_export_is_deterministic_and_hash_only(self) -> None:
        statuses = {identifier: "NOT STARTED" for identifier in APPLE_PENDING}
        statuses["REL-03"] = "IN PROGRESS"
        _workbook, _snapshot, bundle = self.bundle(statuses=statuses)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checks = [f"check-{index}" for index in range(41)]
            checks[7] = "Release qualification tracker"
            contract = root / "scripts/release/verification-checks.json"
            contract.parent.mkdir(parents=True)
            contract.write_text(json.dumps(checks), encoding="utf-8")
            validation = {
                "automatedVerification": {
                    "checks": [
                        {
                            "label": label,
                            "status": "passed",
                            **(
                                {"tracker": bundle.binding()}
                                if label == "Release qualification tracker"
                                else {}
                            ),
                        }
                        for label in checks
                    ],
                    "status": "passed",
                },
                "generatedAt": "2026-09-11T16:00:00Z",
                "recordType": "local-sandbox-release-validation",
                "schemaVersion": 1,
                "version": "0.3.0",
            }
            validation_path = root / "docs/validation.json"
            validation_path.parent.mkdir(parents=True)
            validation_path.write_text(json.dumps(validation), encoding="utf-8")
            for relative in ARTIFACT_PATHS:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(f"artifact {relative}".encode())
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            validation["candidateDigest"] = candidate_digest(root)
            validation_path.write_text(json.dumps(validation), encoding="utf-8")
            arguments = {
                "profile": "apple",
                "bundle": bundle,
                "root": root,
                "commit": "a" * 40,
                "ready_at": "2026-09-11T16:01:00Z",
            }
            first = export_readiness(**arguments)
            second = export_readiness(**arguments)
            self.assertEqual(first, second)
            readiness = json.loads(first)
            self.assertEqual(readiness["tracker"], bundle.binding())
            self.assertEqual(readiness["gates"], bundle.gates())
            self.assertEqual(
                readiness["verification"]["candidateDigest"],
                validation["candidateDigest"],
            )
            self.assertNotIn("tests/GOV-01.test.py", first.decode())

            changed_source = root / "untracked-source.txt"
            changed_source.write_text("post-validation source\n", encoding="utf-8")
            with self.assertRaisesRegex(TrackerError, "candidateDigest does not match"):
                export_readiness(**arguments)
            changed_source.unlink()

            for mutation in ("missing", "mismatched"):
                invalid = json.loads(json.dumps(validation))
                tracker_check = next(
                    check
                    for check in invalid["automatedVerification"]["checks"]
                    if check["label"] == "Release qualification tracker"
                )
                if mutation == "missing":
                    del tracker_check["tracker"]
                else:
                    tracker_check["tracker"]["sha256"] = "0" * 64
                validation_path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    TrackerError,
                    "tracker check does not exactly match",
                ):
                    export_readiness(**arguments)

    def test_candidate_digest_covers_current_regular_source_and_only_cycle_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".gitignore").write_text("ignored.txt\n", encoding="utf-8")
            (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            (root / "untracked.txt").write_text("untracked\n", encoding="utf-8")
            (root / "ignored.txt").write_text("ignored\n", encoding="utf-8")
            for relative in (
                "docs/validation.json",
                "qualification/Local-Sandbox-0.3-Progress.xlsx",
                "qualification/Local-Sandbox-0.3-Progress.snapshot.json",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("excluded\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            subprocess.run(
                ["git", "add", ".gitignore", "tracked.txt", "docs/validation.json"],
                cwd=root,
                check=True,
            )

            original = candidate_digest(root)
            (root / "ignored.txt").write_text("changed ignored\n", encoding="utf-8")
            (root / "docs/validation.json").write_text("changed validation\n", encoding="utf-8")
            (root / "qualification/Local-Sandbox-0.3-Progress.xlsx").write_text(
                "changed tracker\n",
                encoding="utf-8",
            )
            (root / "qualification/Local-Sandbox-0.3-Progress.snapshot.json").write_text(
                "changed snapshot\n",
                encoding="utf-8",
            )
            self.assertEqual(candidate_digest(root), original)

            (root / "untracked.txt").write_text("changed untracked\n", encoding="utf-8")
            self.assertNotEqual(candidate_digest(root), original)
            (root / "untracked.txt").write_text("untracked\n", encoding="utf-8")
            self.assertEqual(candidate_digest(root), original)

            (root / "tracked.txt").write_text("changed tracked\n", encoding="utf-8")
            self.assertNotEqual(candidate_digest(root), original)
            (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            self.assertEqual(candidate_digest(root), original)

            tracked_mode = (root / "tracked.txt").stat().st_mode
            (root / "tracked.txt").chmod(tracked_mode | 0o111)
            self.assertNotEqual(candidate_digest(root), original)

    def test_candidate_digest_rejects_a_symlinked_parent_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            container = Path(temporary)
            root = container / "repository"
            external = container / "external"
            nested = root / "nested"
            nested.mkdir(parents=True)
            external.mkdir()
            (nested / "source.txt").write_text("trusted\n", encoding="utf-8")
            (external / "source.txt").write_text("external\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            subprocess.run(["git", "add", "nested/source.txt"], cwd=root, check=True)
            self.assertRegex(candidate_digest(root), r"^[0-9a-f]{64}$")

            (nested / "source.txt").unlink()
            nested.rmdir()
            nested.symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(CandidateDigestError, "candidate parent"):
                candidate_digest(root)


if __name__ == "__main__":
    unittest.main()
