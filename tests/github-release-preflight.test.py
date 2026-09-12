#!/usr/bin/env python3
"""Integration contracts for the dry-run GitHub release preflight."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from release.tracker import build_snapshot, verify_tracker_bundle  # noqa: E402
from release.candidate_digest import candidate_digest  # noqa: E402
from release_tracker_fixture import build_workbook  # noqa: E402


SOURCE_ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_PATHS = (
    "public/downloads/Local-Sandbox-Source.zip",
    "public/downloads/Local-Sandbox-Selfhost.zip",
    "public/downloads/Local-Sandbox-Setup-Guide.pdf",
)
GATE_IDS = (
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
GITHUB_ACTION_GATE_ID = "REL-06"
GITHUB_READY_PERCENT = 98.24561403508771
VERIFICATION_CHECKS = tuple(json.loads(
    (SOURCE_ROOT / "scripts/release/verification-checks.json").read_text(encoding="utf-8")
))
TRACKER_CHECK_LABEL = "Release qualification tracker"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def passed_validation_checks(
    labels: list[str] | tuple[str, ...],
    tracker_binding: dict[str, object],
) -> list[dict[str, object]]:
    return [
        {
            "label": label,
            "status": "passed",
            **({"tracker": tracker_binding} if label == TRACKER_CHECK_LABEL else {}),
        }
        for label in labels
    ]


class GitHubReleasePreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.repository = self.base / "repository"
        (self.repository / "scripts/release").mkdir(parents=True)
        for relative in (
            "scripts/publish-github.sh",
            "scripts/release/github_release.py",
            "scripts/release/candidate_digest.py",
            "scripts/release/shortcuts.py",
            "scripts/release/tracker.py",
            "scripts/release/verification-checks.json",
            "scripts/release_common.py",
        ):
            destination = self.repository / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SOURCE_ROOT / relative, destination)
        for relative in (
            "scripts/release/check_python.py",
            "scripts/release/check_freshness.py",
            "scripts/audit-release-artifacts.py",
        ):
            check = self.repository / relative
            check.parent.mkdir(parents=True, exist_ok=True)
            check.write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")

        (self.repository / "package.json").write_text(
            json.dumps({"name": "local-sandbox", "version": "0.3.0"}) + "\n",
            encoding="utf-8",
        )
        (self.repository / ".gitignore").write_text(
            "__pycache__/\nrelease-output/\n",
            encoding="utf-8",
        )
        generated_at = datetime.now(timezone.utc) - timedelta(minutes=2)
        validation = {
            "recordType": "local-sandbox-release-validation",
            "schemaVersion": 1,
            "version": "0.3.0",
            "generatedAt": generated_at.isoformat().replace("+00:00", "Z"),
            "automatedVerification": {
                "status": "passed",
                "checks": [
                    {"label": label, "status": "passed"}
                    for label in VERIFICATION_CHECKS
                ],
            },
            "qualifications": {"releaseState": "QUALIFYING"},
        }
        validation_path = self.repository / "docs/validation.json"
        validation_path.parent.mkdir()
        validation_path.write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")
        self.shortcut_data = b"signed Shortcut fixture\n"
        self.write_shortcut_release()
        qualification = self.repository / "qualification"
        qualification.mkdir()
        tracker_data = build_workbook(statuses={GITHUB_ACTION_GATE_ID: "IN PROGRESS"})
        (qualification / "Local-Sandbox-0.3-Progress.xlsx").write_bytes(tracker_data)
        (qualification / "Local-Sandbox-0.3-Progress.snapshot.json").write_bytes(
            build_snapshot(tracker_data)
        )
        tracker = verify_tracker_bundle(
            tracker_data,
            (qualification / "Local-Sandbox-0.3-Progress.snapshot.json").read_bytes(),
        )
        validation["automatedVerification"]["checks"] = passed_validation_checks(
            VERIFICATION_CHECKS,
            tracker.binding(),
        )
        validation_path.write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")

        self.git("init", "-b", "main")
        self.git("config", "user.name", "Release Test")
        self.git("config", "user.email", "release@example.invalid")
        self.git("add", ".")
        self.refresh_candidate_digest()
        self.git("add", "docs/validation.json")
        self.git("commit", "-m", "qualified release")
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()

        self.qualification_path = self.base / "github-action-readiness.json"
        self.write_qualification()
        self.fake_bin = self.base / "fake-bin"
        self.fake_bin.mkdir()
        self.gh_log = self.base / "gh.log"
        self.git_log = self.base / "git.log"
        self.gh_state = self.base / "gh-state"
        fake_gh = self.fake_bin / "gh"
        fake_gh.write_text(
            """#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import sys

arguments = sys.argv[1:]
joined = ' '.join(arguments)
with open(os.environ['FAKE_GH_LOG'], 'a', encoding='utf-8') as log:
    log.write(joined + '\\n')
state = Path(os.environ['FAKE_GH_STATE'])
state.mkdir(parents=True, exist_ok=True)
failure = os.environ.get('FAKE_GH_FAIL', 'none')

if arguments[:2] == ['auth', 'status']:
    raise SystemExit(0)
if arguments[:2] == ['repo', 'create']:
    if failure == 'repo':
        print('injected repository failure', file=sys.stderr)
        raise SystemExit(42)
    (state / 'repo').write_text('created')
    visibility = 'public' if '--public' in arguments else 'private'
    (state / 'visibility').write_text(visibility)
    raise SystemExit(0)
if arguments[:2] == ['release', 'create']:
    if failure == 'release':
        print('injected release failure', file=sys.stderr)
        raise SystemExit(42)
    (state / 'release').write_text('created')
    raise SystemExit(0)

endpoint = next((value for value in reversed(arguments) if value.startswith('repos/')), '')
if arguments and arguments[0] == 'api' and '--method' in arguments and 'POST' in arguments:
    if endpoint.endswith('/git/refs'):
        if failure == 'tag':
            print('injected tag failure', file=sys.stderr)
            raise SystemExit(42)
        (state / 'tag').write_text('created')
        raise SystemExit(0)

kind = 'unknown'
if endpoint.endswith('/git/ref/tags/v0.3.0'):
    kind = 'tag'
elif endpoint.endswith('/releases/tags/v0.3.0'):
    kind = 'release'
elif endpoint == 'repos/test-owner/local-sandbox':
    kind = 'repo'
if os.environ.get('FAKE_GH_EXISTS', 'none') == kind:
    print('{}')
    raise SystemExit(0)

exists = {
    'repo': (state / 'repo').exists(),
    'tag': (state / 'tag').exists(),
    'release': (state / 'release').exists(),
}
if kind in exists and not exists[kind]:
    print('gh: Not Found (HTTP 404)', file=sys.stderr)
    raise SystemExit(1)
if endpoint.endswith('/git/ref/heads/main') and not exists['repo']:
    print('gh: Not Found (HTTP 404)', file=sys.stderr)
    raise SystemExit(1)
if '/releases/assets/' in endpoint and not exists['release']:
    print('gh: Not Found (HTTP 404)', file=sys.stderr)
    raise SystemExit(1)
if failure == 'readback' and exists['release']:
    print('injected remote readback failure', file=sys.stderr)
    raise SystemExit(42)

commit = os.environ['FAKE_COMMIT']
if endpoint == 'repos/test-owner/local-sandbox':
    reads_path = state / 'repo-reads'
    reads = int(reads_path.read_text()) + 1 if reads_path.exists() else 1
    reads_path.write_text(str(reads))
    if reads == 2 and failure in {'tamper-checksums', 'tamper-notes'}:
        target = 'SHA256SUMS' if failure == 'tamper-checksums' else 'RELEASE_NOTES.md'
        release_root = Path(os.environ['FAKE_REPO_ROOT']) / 'release-output' / 'github-v0.3.0'
        with open(release_root / target, 'ab') as stream:
            stream.write(b'tampered')
    visibility = (state / 'visibility').read_text()
    print(json.dumps({
        'default_branch': 'main',
        'full_name': 'test-owner/local-sandbox',
        'private': visibility == 'private',
        'visibility': visibility,
    }))
    raise SystemExit(0)
if endpoint.endswith('/git/ref/heads/main'):
    print(json.dumps({'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': commit}}))
    raise SystemExit(0)
if endpoint.endswith('/git/ref/tags/v0.3.0'):
    print(json.dumps({'ref': 'refs/tags/v0.3.0', 'object': {'type': 'commit', 'sha': commit}}))
    raise SystemExit(0)

release_root = Path(os.environ['FAKE_REPO_ROOT']) / 'release-output' / 'github-v0.3.0'
asset_names = sorted([
    'Local-Sandbox-Selfhost.zip',
    'Local-Sandbox-Setup-Guide.pdf',
    'Local-Sandbox-Source.zip',
    'SHA256SUMS',
])
if endpoint.endswith('/releases/tags/v0.3.0'):
    assets = []
    for asset_id, name in enumerate(asset_names, 1):
        data = (release_root / name).read_bytes()
        assets.append({
            'digest': 'sha256:' + hashlib.sha256(data).hexdigest(),
            'id': asset_id,
            'name': name,
            'size': len(data),
            'state': 'uploaded',
        })
    print(json.dumps({
        'assets': assets,
        'body': (release_root / 'RELEASE_NOTES.md').read_text(encoding='utf-8')
            + ('tampered' if failure == 'body-readback' else ''),
        'draft': False,
        'html_url': 'https://github.com/test-owner/local-sandbox/releases/tag/v0.3.0',
        'name': 'Local Sandbox v0.3.0',
        'prerelease': False,
        'tag_name': 'v0.3.0',
    }))
    raise SystemExit(0)
if '/releases/assets/' in endpoint:
    asset_id = int(endpoint.rsplit('/', 1)[1])
    data = (release_root / asset_names[asset_id - 1]).read_bytes()
    if failure == 'asset-readback' and asset_id == 1:
        data += b'tampered'
    sys.stdout.buffer.write(data)
    raise SystemExit(0)

print('unexpected gh command', file=sys.stderr)
raise SystemExit(97)
""",
            encoding="utf-8",
        )
        fake_gh.chmod(0o755)
        fake_git = self.fake_bin / "git"
        fake_git.write_text(
            f"""#!/bin/sh
set -eu
case " $* " in
  *" push "*)
    printf '%s\\n' "$*" >> "$FAKE_GIT_LOG"
    [ "${{FAKE_GH_FAIL:-none}}" = push ] && echo 'injected push failure' >&2 && exit 42
    exit 0 ;;
esac
exec {shutil.which('git')} "$@"
""",
            encoding="utf-8",
        )
        fake_git.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            check=True,
            capture_output=True,
            text=True,
        )

    def write_shortcut_release(
        self,
        *,
        status: str = "signed-awaiting-device-acceptance",
        source_package: bytes | None = None,
        selfhost_package: bytes | None = None,
        include_package: bool = True,
        catalog_changes: dict[str, object] | None = None,
        package_changes: dict[str, object] | None = None,
        recipe_packages: list[dict[str, object]] | None = None,
    ) -> None:
        package = {
            "id": "local",
            "name": "Agent Step - Local",
            "requires": [],
            "url": "https://downloads.example.invalid/shortcuts/0.3.0/local.shortcut",
            "sha256": digest(self.shortcut_data),
            "bytes": len(self.shortcut_data),
        }
        package.update(package_changes or {})
        recipe = {
            "version": 1,
            "release": "0.3.0",
            "packages": recipe_packages or [
                {
                    "id": "local",
                    "name": "Agent Step - Local",
                    "file": "Agent Step - Local.shortcut",
                    "requires": [],
                }
            ],
        }
        recipe_data = (json.dumps(recipe, indent=2) + "\n").encode()
        recipe_path = self.repository / "release/shortcuts/recipe.json"
        recipe_path.parent.mkdir(parents=True, exist_ok=True)
        recipe_path.write_bytes(recipe_data)
        catalog = {
            "version": 1,
            "release": "0.3.0",
            "status": status,
            "packages": [
                package
            ] if include_package else [],
        }
        catalog.update(catalog_changes or {})
        catalog_data = (json.dumps(catalog, indent=2) + "\n").encode()
        catalog_path = self.repository / "public/shortcuts/catalog.json"
        catalog_path.parent.mkdir(parents=True, exist_ok=True)
        catalog_path.write_bytes(catalog_data)
        downloads = self.repository / "public/downloads"
        downloads.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(downloads / "Local-Sandbox-Source.zip", "w") as archive:
            archive.writestr("Local-Sandbox/public/shortcuts/catalog.json", catalog_data)
            archive.writestr("Local-Sandbox/release/shortcuts/recipe.json", recipe_data)
            if include_package:
                archive.writestr(
                    f"Local-Sandbox/public/shortcuts/0.3.0/{package['id']}.shortcut",
                    self.shortcut_data if source_package is None else source_package,
                )
        with zipfile.ZipFile(downloads / "Local-Sandbox-Selfhost.zip", "w") as archive:
            archive.writestr("site/shortcuts/catalog.json", catalog_data)
            archive.writestr(
                "site/downloads/Local-Sandbox-Source.zip",
                (downloads / "Local-Sandbox-Source.zip").read_bytes(),
            )
            if include_package:
                archive.writestr(
                    f"site/shortcuts/0.3.0/{package['id']}.shortcut",
                    self.shortcut_data if selfhost_package is None else selfhost_package,
                )
        (downloads / "Local-Sandbox-Setup-Guide.pdf").write_bytes(b"setup guide fixture\n")

    def commit_fixture_change(self, message: str) -> None:
        self.refresh_candidate_digest()
        self.git("add", ".")
        self.git("commit", "-m", message)
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.write_qualification()

    def refresh_candidate_digest(self) -> None:
        validation_path = self.repository / "docs/validation.json"
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        validation["candidateDigest"] = candidate_digest(self.repository)
        validation_path.write_text(
            json.dumps(validation, indent=2) + "\n",
            encoding="utf-8",
        )

    def write_qualification(self, **changes: object) -> None:
        validation_data = (self.repository / "docs/validation.json").read_bytes()
        tracker_data = (
            self.repository / "qualification/Local-Sandbox-0.3-Progress.xlsx"
        ).read_bytes()
        snapshot_data = (
            self.repository / "qualification/Local-Sandbox-0.3-Progress.snapshot.json"
        ).read_bytes()
        tracker = verify_tracker_bundle(tracker_data, snapshot_data)
        qualified_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        document: dict[str, object] = {
            "recordType": "local-sandbox-github-action-readiness",
            "schemaVersion": 1,
            "version": "0.3.0",
            "tag": "v0.3.0",
            "releaseState": "READY",
            "commit": getattr(self, "commit", "0" * 40),
            "readyAt": qualified_at.isoformat().replace("+00:00", "Z"),
            "totalGates": 57,
            "passedGates": 56,
            "completionPercent": GITHUB_READY_PERCENT,
            "gates": tracker.gates(),
            "tracker": tracker.binding(),
            "verification": {
                "path": "docs/validation.json",
                "sha256": digest(validation_data),
                "automatedStatus": "passed",
                "candidateDigest": json.loads(validation_data)["candidateDigest"],
                "commit": getattr(self, "commit", "0" * 40),
            },
            "artifacts": [
                {
                    "path": relative,
                    "sha256": digest((self.repository / relative).read_bytes()),
                    "bytes": (self.repository / relative).stat().st_size,
                }
                for relative in ARTIFACT_PATHS
            ],
        }
        document.update(changes)
        self.qualification_path.write_text(
            json.dumps(document, indent=2) + "\n",
            encoding="utf-8",
        )

    def command(self, *extra: str) -> list[str]:
        return [
            os.fspath(self.repository / "scripts/publish-github.sh"),
            "--owner",
            "test-owner",
            "--repo",
            "local-sandbox",
            "--visibility",
            "private",
            "--expected-commit",
            self.commit,
            "--tag",
            "v0.3.0",
            "--tracker",
            "qualification/Local-Sandbox-0.3-Progress.xlsx",
            "--action-readiness",
            os.fspath(self.qualification_path),
            *extra,
        ]

    def invoke(
        self,
        *extra: str,
        exists: str = "none",
        failure: str = "none",
        missing_repository: bool = False,
        remote_main: str | None = None,
        remote_visibility: str | None = None,
        command: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        selected_command = command or self.command(*extra)
        environment = dict(os.environ)
        environment["PATH"] = f"{self.fake_bin}{os.pathsep}{environment['PATH']}"
        environment["FAKE_GH_LOG"] = os.fspath(self.gh_log)
        environment["FAKE_GIT_LOG"] = os.fspath(self.git_log)
        shutil.rmtree(self.gh_state, ignore_errors=True)
        self.gh_state.mkdir()
        if not missing_repository:
            (self.gh_state / "repo").write_text("existing", encoding="utf-8")
            visibility = remote_visibility
            if visibility is None and "--visibility" in selected_command:
                visibility = selected_command[selected_command.index("--visibility") + 1]
            (self.gh_state / "visibility").write_text(
                visibility or "private",
                encoding="utf-8",
            )
        environment["FAKE_GH_STATE"] = os.fspath(self.gh_state)
        environment["FAKE_REPO_ROOT"] = os.fspath(self.repository)
        environment["FAKE_COMMIT"] = remote_main or self.commit
        environment["FAKE_GH_EXISTS"] = exists
        environment["FAKE_GH_FAIL"] = failure
        return subprocess.run(
            selected_command,
            cwd=self.repository,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_required_arguments_are_not_defaulted(self) -> None:
        result = self.invoke(command=[os.fspath(self.repository / "scripts/publish-github.sh")])
        self.assertEqual(result.returncode, 2)
        self.assertIn("--owner", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_tracker_argument_is_required_and_must_name_the_canonical_workbook(self) -> None:
        command = self.command()
        tracker_index = command.index("--tracker")
        without_tracker = command[:tracker_index] + command[tracker_index + 2 :]
        result = self.invoke(command=without_tracker)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--tracker", result.stderr)

        external = self.base / "copy.xlsx"
        external.write_bytes(
            (self.repository / "qualification/Local-Sandbox-0.3-Progress.xlsx").read_bytes()
        )
        command[tracker_index + 1] = os.fspath(external)
        result = self.invoke(command=command)
        self.assertEqual(result.returncode, 1)
        self.assertIn("must be qualification/Local-Sandbox-0.3-Progress.xlsx", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_full_verifier_runs_this_suite_as_a_named_stage(self) -> None:
        verifier = (SOURCE_ROOT / "scripts/verify-release.mjs").read_text(encoding="utf-8")
        self.assertIn(
            "await run('GitHub release preflight contracts', releasePython, "
            "['tests/github-release-preflight.test.py']);",
            verifier,
        )

    def test_dirty_worktree_refuses_the_base_commit(self) -> None:
        (self.repository / "uncommitted-0.3-change.txt").write_text("not in HEAD\n", encoding="utf-8")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("worktree is not clean", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_committed_post_validation_source_change_rejects_stale_candidate_digest(self) -> None:
        (self.repository / "post-validation-source.txt").write_text(
            "changed after validation\n",
            encoding="utf-8",
        )
        self.git("add", "post-validation-source.txt")
        self.git("commit", "-m", "post-validation source change")
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.write_qualification()

        result = self.invoke()

        self.assertEqual(result.returncode, 1)
        self.assertIn("candidateDigest does not match", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_wrong_expected_commit_is_rejected(self) -> None:
        command = self.command()
        commit_index = command.index("--expected-commit") + 1
        command[commit_index] = "0" * 40
        result = self.invoke(command=command)
        self.assertEqual(result.returncode, 1)
        self.assertIn("HEAD does not equal --expected-commit", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_only_ready_record_can_authorize_the_github_action(self) -> None:
        self.write_qualification(releaseState="QUALIFYING")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("releaseState must be READY", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_action_readiness_requires_56_pass_and_rel_06_in_progress(self) -> None:
        gates = [
            {
                "id": gate_id,
                "status": "IN PROGRESS" if gate_id == GITHUB_ACTION_GATE_ID else "PASS",
                "evidenceSha256": digest(f"proof {gate_id}".encode()),
            }
            for gate_id in GATE_IDS
        ]
        gates[0]["status"] = "IN PROGRESS"
        self.write_qualification(gates=gates)
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("status must be PASS", result.stderr)

        gates[0] = {
            "id": "NOT-A-GATE",
            "status": "PASS",
            "evidenceSha256": digest(b"wrong gate"),
        }
        self.write_qualification(gates=gates)
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("do not match the 0.3 tracker", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_action_readiness_rejects_reordered_canonical_gates(self) -> None:
        document = json.loads(self.qualification_path.read_text(encoding="utf-8"))
        document["gates"][0], document["gates"][1] = (
            document["gates"][1],
            document["gates"][0],
        )
        self.qualification_path.write_text(
            json.dumps(document, indent=2) + "\n",
            encoding="utf-8",
        )

        result = self.invoke()

        self.assertEqual(result.returncode, 1)
        self.assertIn("canonical 0.3 gate order", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_action_readiness_must_match_tracker_evidence_and_binding_exactly(self) -> None:
        for mutate, expected in (
            (
                lambda document: document["gates"][0].update({"evidenceSha256": "0" * 64}),
                "gate status or evidence does not exactly match",
            ),
            (
                lambda document: document["tracker"].update({"requirementsSha256": "0" * 64}),
                "does not exactly match the recomputed tracker",
            ),
            (
                lambda document: document["verification"].update(
                    {"candidateDigest": "0" * 64}
                ),
                "verification.candidateDigest does not match",
            ),
        ):
            with self.subTest(expected=expected):
                self.write_qualification()
                document = json.loads(self.qualification_path.read_text(encoding="utf-8"))
                mutate(document)
                self.qualification_path.write_text(
                    json.dumps(document, indent=2) + "\n", encoding="utf-8"
                )
                result = self.invoke()
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
                self.assertFalse(self.gh_log.exists())

    def test_committed_stale_snapshot_and_open_dependencies_fail_before_github(self) -> None:
        cases = (
            build_workbook(
                statuses={GITHUB_ACTION_GATE_ID: "IN PROGRESS"},
                evidence_overrides={
                    "GOV-01": "tests/GOV-01.test.py 2/2 PASS at build 27A266a"
                },
            ),
            build_workbook(statuses={
                GITHUB_ACTION_GATE_ID: "IN PROGRESS",
                "RUN-02": "IN PROGRESS",
            }),
        )
        for index, workbook in enumerate(cases):
            with self.subTest(index=index):
                qualification = self.repository / "qualification"
                (qualification / "Local-Sandbox-0.3-Progress.xlsx").write_bytes(workbook)
                self.git("add", ".")
                self.git("commit", "-m", f"invalid tracker {index}")
                self.commit = self.git("rev-parse", "HEAD").stdout.strip()
                document = json.loads(self.qualification_path.read_text(encoding="utf-8"))
                document["commit"] = self.commit
                document["verification"]["commit"] = self.commit
                self.qualification_path.write_text(
                    json.dumps(document, indent=2) + "\n", encoding="utf-8"
                )
                result = self.invoke()
                self.assertEqual(result.returncode, 1)
                self.assertRegex(result.stderr, "stale, altered|dependencies remain open")
                self.assertFalse(self.gh_log.exists())

    def test_rel_06_cannot_be_prepassed(self) -> None:
        gates = [
            {
                "id": gate_id,
                "status": "PASS",
                "evidenceSha256": digest(f"proof {gate_id}".encode()),
            }
            for gate_id in GATE_IDS
        ]
        self.write_qualification(gates=gates)
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("REL-06 cannot be pre-passed", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_action_readiness_requires_canonical_counts_and_percentage(self) -> None:
        for change, expected in (
            ({"passedGates": 57}, "passedGates must be 56"),
            ({"completionPercent": 98.25}, "canonical 56/57 value"),
        ):
            with self.subTest(change=change):
                self.write_qualification(**change)
                result = self.invoke()
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
                self.assertFalse(self.gh_log.exists())

    def test_qualification_must_bind_the_exact_artifact_digests(self) -> None:
        self.write_qualification()
        document = json.loads(self.qualification_path.read_text(encoding="utf-8"))
        document["artifacts"][0]["sha256"] = "0" * 64
        self.qualification_path.write_text(
            json.dumps(document, indent=2) + "\n",
            encoding="utf-8",
        )
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not match its qualified SHA-256 digest", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_validation_must_include_the_named_github_preflight_stage(self) -> None:
        validation_path = self.repository / "docs/validation.json"
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        validation["automatedVerification"]["checks"] = [
            check
            for check in validation["automatedVerification"]["checks"]
            if check["label"] != "GitHub release preflight contracts"
        ]
        validation_path.write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")
        self.commit_fixture_change("remove GitHub preflight evidence")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("GitHub release preflight contracts", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_validation_must_contain_the_exact_canonical_check_roster(self) -> None:
        cases = {}

        duplicate = list(VERIFICATION_CHECKS)
        duplicate.append(VERIFICATION_CHECKS[-1])
        cases["duplicate"] = (duplicate, "duplicate automated check")

        unexpected = list(VERIFICATION_CHECKS)
        unexpected.append("Unreviewed release stage")
        cases["unexpected"] = (unexpected, "unexpected automated checks")

        reordered = list(VERIFICATION_CHECKS)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        cases["reordered"] = (reordered, "canonical execution order")

        for index, (label, (check_labels, expected)) in enumerate(cases.items()):
            with self.subTest(label=label):
                validation_path = self.repository / "docs/validation.json"
                validation = json.loads(validation_path.read_text(encoding="utf-8"))
                tracker_data = (
                    self.repository / "qualification/Local-Sandbox-0.3-Progress.xlsx"
                ).read_bytes()
                snapshot_data = (
                    self.repository
                    / "qualification/Local-Sandbox-0.3-Progress.snapshot.json"
                ).read_bytes()
                tracker = verify_tracker_bundle(tracker_data, snapshot_data)
                validation["automatedVerification"]["checks"] = passed_validation_checks(
                    check_labels,
                    tracker.binding(),
                )
                validation_path.write_text(
                    json.dumps(validation, indent=2) + "\n",
                    encoding="utf-8",
                )
                self.commit_fixture_change(f"invalid verification roster {index}")
                result = self.invoke()
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
                self.assertFalse(self.gh_log.exists())

    def test_validation_tracker_binding_must_be_present_and_exact(self) -> None:
        cases = (
            ("missing", None),
            ("mismatched", "0" * 64),
        )
        for index, (label, changed_snapshot_sha) in enumerate(cases):
            with self.subTest(label=label):
                validation_path = self.repository / "docs/validation.json"
                validation = json.loads(validation_path.read_text(encoding="utf-8"))
                tracker_data = (
                    self.repository / "qualification/Local-Sandbox-0.3-Progress.xlsx"
                ).read_bytes()
                snapshot_data = (
                    self.repository
                    / "qualification/Local-Sandbox-0.3-Progress.snapshot.json"
                ).read_bytes()
                tracker = verify_tracker_bundle(tracker_data, snapshot_data)
                validation["automatedVerification"]["checks"] = passed_validation_checks(
                    VERIFICATION_CHECKS,
                    tracker.binding(),
                )
                tracker_check = next(
                    check
                    for check in validation["automatedVerification"]["checks"]
                    if check["label"] == TRACKER_CHECK_LABEL
                )
                if changed_snapshot_sha is None:
                    del tracker_check["tracker"]
                else:
                    tracker_check["tracker"]["snapshotSha256"] = changed_snapshot_sha
                validation_path.write_text(
                    json.dumps(validation, indent=2) + "\n",
                    encoding="utf-8",
                )
                self.commit_fixture_change(f"invalid validation tracker binding {index}")
                result = self.invoke()
                self.assertEqual(result.returncode, 1)
                self.assertIn(
                    "docs/validation.json tracker check does not exactly match",
                    result.stderr,
                )
                self.assertFalse(self.gh_log.exists())

    def test_validation_timestamp_must_be_fresh_and_not_future_dated(self) -> None:
        timestamps = (
            (
                datetime.now(timezone.utc) - timedelta(hours=25),
                "older than 24 hours",
            ),
            (
                datetime.now(timezone.utc) + timedelta(minutes=6),
                "too far in the future",
            ),
        )
        for index, (generated_at, expected) in enumerate(timestamps):
            with self.subTest(expected=expected):
                validation_path = self.repository / "docs/validation.json"
                validation = json.loads(validation_path.read_text(encoding="utf-8"))
                validation["generatedAt"] = generated_at.isoformat().replace("+00:00", "Z")
                validation_path.write_text(
                    json.dumps(validation, indent=2) + "\n",
                    encoding="utf-8",
                )
                self.commit_fixture_change(f"invalid validation timestamp {index}")
                result = self.invoke()
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
                self.assertFalse(self.gh_log.exists())

    def test_catalog_must_have_the_signer_published_status(self) -> None:
        self.write_shortcut_release(status="awaiting-signed-device-exports")
        self.commit_fixture_change("replace signed catalog with empty-state metadata")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("signed-awaiting-device-acceptance", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_signed_catalog_must_not_be_empty(self) -> None:
        self.write_shortcut_release(include_package=False)
        self.commit_fixture_change("remove every signed Shortcut package")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("between 1 and 30 signed packages", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_catalog_rejects_noncanonical_prefix_and_schema_drift(self) -> None:
        cases = (
            (
                {"package_changes": {"url": "https://downloads.example.invalid/unexpected/prefix/0.3.0/local.shortcut"}},
                "must be exactly https://downloads.example.invalid/shortcuts/0.3.0/local.shortcut",
            ),
            (
                {"package_changes": {"name": "Agént Step"}},
                "canonical printable ASCII",
            ),
            (
                {"package_changes": {"unexpected": True}},
                "missing or unexpected fields",
            ),
            (
                {"catalog_changes": {"unexpected": True}},
                "missing or unexpected fields",
            ),
            (
                {"catalog_changes": {"version": True}},
                "version must be an integer",
            ),
        )
        for index, (arguments, expected) in enumerate(cases):
            with self.subTest(arguments=arguments):
                self.write_shortcut_release(**arguments)
                self.commit_fixture_change(f"invalid catalog fixture {index}")
                result = self.invoke()
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
                self.assertFalse(self.gh_log.exists())

    def test_catalog_roster_and_metadata_must_exactly_match_the_recipe(self) -> None:
        cases = (
            {
                "id": "bogus",
                "url": "https://downloads.example.invalid/shortcuts/0.3.0/bogus.shortcut",
            },
            {"name": "Metadata drift"},
        )
        for index, package_changes in enumerate(cases):
            with self.subTest(package_changes=package_changes):
                self.write_shortcut_release(package_changes=package_changes)
                self.commit_fixture_change(f"recipe mismatch fixture {index}")
                result = self.invoke()
                self.assertEqual(result.returncode, 1)
                self.assertIn("must exactly match release/shortcuts/recipe.json", result.stderr)
                self.assertFalse(self.gh_log.exists())

    def test_archived_shortcut_file_set_and_recipe_are_exact(self) -> None:
        self.write_shortcut_release()
        source = self.repository / "public/downloads/Local-Sandbox-Source.zip"
        with zipfile.ZipFile(source, "a") as archive:
            archive.writestr(
                "Local-Sandbox/public/shortcuts/0.3.0/unexpected.shortcut",
                self.shortcut_data,
            )
        self.commit_fixture_change("add unlisted Shortcut package")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("file set does not exactly match", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_catalog_package_digest_must_match_each_archive(self) -> None:
        self.write_shortcut_release(source_package=b"changed package\n")
        self.commit_fixture_change("tamper with archived Shortcut package")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("changed signed Shortcut package", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_catalog_package_digest_must_match_the_selfhost_archive(self) -> None:
        self.write_shortcut_release(selfhost_package=b"changed package\n")
        self.commit_fixture_change("tamper with self-hosted Shortcut package")
        result = self.invoke()
        self.assertEqual(result.returncode, 1)
        self.assertIn("changed signed Shortcut package", result.stderr)
        self.assertFalse(self.gh_log.exists())

    def test_existing_tag_or_release_is_rejected(self) -> None:
        for existing, expected in (
            ("tag", "tag v0.3.0 already exists"),
            ("release", "release v0.3.0 already exists"),
        ):
            with self.subTest(existing=existing):
                self.gh_log.unlink(missing_ok=True)
                result = self.invoke(exists=existing)
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)

    def test_repository_must_exist_with_exact_visibility_and_main_commit(self) -> None:
        for invocation, expected in (
            ({"missing_repository": True}, "Command failed"),
            ({"remote_visibility": "public"}, "visibility does not match"),
            ({"remote_main": "b" * 40}, "Remote main does not equal"),
        ):
            with self.subTest(invocation=invocation):
                self.gh_log.unlink(missing_ok=True)
                result = self.invoke(**invocation)
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
                self.assertNotIn("release create", self.gh_log.read_text(encoding="utf-8"))

    def test_happy_path_is_dry_and_deterministic(self) -> None:
        first = self.invoke()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertIn("DRY RUN PASSED", first.stdout)
        self.assertIn("56/57 gates PASS; REL-06 IN PROGRESS", first.stdout)
        self.assertIn("No tag or release was created", first.stdout)
        output = self.repository / "release-output/github-v0.3.0"
        files = sorted(path for path in output.iterdir() if path.is_file())
        first_contents = {path.name: path.read_bytes() for path in files}

        second = self.invoke()
        self.assertEqual(second.returncode, 0, second.stderr)
        second_contents = {path.name: path.read_bytes() for path in files}
        self.assertEqual(first_contents, second_contents)
        self.assertEqual(
            set(first_contents),
            {
                "Local-Sandbox-Selfhost.zip",
                "Local-Sandbox-Setup-Guide.pdf",
                "Local-Sandbox-Source.zip",
                "RELEASE_NOTES.md",
                "SHA256SUMS",
                "github-release-plan.json",
            },
        )
        checksum_names = [
            line.split("  ", 1)[1]
            for line in first_contents["SHA256SUMS"].decode("ascii").splitlines()
        ]
        self.assertEqual(checksum_names, sorted(checksum_names))
        notes = first_contents["RELEASE_NOTES.md"].decode("utf-8")
        self.assertIn("## Install", notes)
        self.assertIn("## Signed Shortcut catalog", notes)
        self.assertIn("## Known limitations", notes)
        self.assertIn("`local` (Agent Step - Local)", notes)
        plan = json.loads(first_contents["github-release-plan.json"])
        self.assertEqual(plan["actionReadiness"]["gates"], {
            "passed": 56,
            "pending": "REL-06",
            "total": 57,
        })
        self.assertEqual(plan["shortcutCatalog"]["status"], "signed-awaiting-device-acceptance")
        self.assertEqual(plan["shortcutCatalog"]["packages"][0]["id"], "local")
        gh_calls = self.gh_log.read_text(encoding="utf-8")
        self.assertNotIn("repo create", gh_calls)
        self.assertNotIn("release create", gh_calls)

    def test_execute_verifies_existing_public_repository_and_mutates_only_release_state(self) -> None:
        command = self.command("--execute")
        visibility_index = command.index("--visibility") + 1
        command[visibility_index] = "public"
        result = self.invoke(command=command)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Published test-owner/local-sandbox v0.3.0", result.stdout)
        self.assertIn("does not claim the final 57/57", result.stdout)
        receipt = json.loads(
            (
                self.repository
                / "release-output/github-v0.3.0/REL-06-completion-receipt.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["gate"], {"id": "REL-06", "status": "PASS"})
        self.assertFalse(receipt["finalQualificationClaimed"])
        self.assertEqual(receipt["remoteReadback"]["refs"], {
            "main": self.commit,
            "tag": self.commit,
        })
        self.assertEqual(
            receipt["remoteReadback"]["release"]["bodySha256"],
            digest(
                (
                    self.repository / "release-output/github-v0.3.0/RELEASE_NOTES.md"
                ).read_bytes()
            ),
        )
        self.assertEqual(len(receipt["remoteReadback"]["assets"]), 4)
        for asset in receipt["remoteReadback"]["assets"]:
            self.assertRegex(asset["sha256"], r"^[0-9a-f]{64}$")
        gh_calls = self.gh_log.read_text(encoding="utf-8")
        self.assertNotIn("repo create", gh_calls)
        self.assertIn("release create v0.3.0", gh_calls)
        git_calls = self.git_log.read_text(encoding="utf-8") if self.git_log.exists() else ""
        self.assertNotIn(" push ", git_calls)
        self.assertNotIn("--force", f"{gh_calls}\n{git_calls}")
        self.assertNotIn("repo delete", gh_calls)

    def test_execute_rejects_incomplete_remote_readback_without_a_receipt(self) -> None:
        for failure, expected in (
            ("readback", "exact remote readback"),
            ("asset-readback", "does not match the reviewed bytes"),
            ("body-readback", "does not match the reviewed release notes"),
        ):
            with self.subTest(failure=failure):
                result = self.invoke("--execute", failure=failure)
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
                self.assertIn("do not rerun --execute", result.stderr)
                receipt = (
                    self.repository
                    / "release-output/github-v0.3.0/REL-06-completion-receipt.json"
                )
                self.assertFalse(receipt.exists())

    def test_staged_checksums_and_notes_are_reverified_before_mutation(self) -> None:
        for failure, filename in (
            ("tamper-checksums", "SHA256SUMS"),
            ("tamper-notes", "RELEASE_NOTES.md"),
        ):
            with self.subTest(failure=failure):
                self.gh_log.unlink(missing_ok=True)
                result = self.invoke("--execute", failure=failure)
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"Staged release file changed before publication: {filename}", result.stderr)
                gh_calls = self.gh_log.read_text(encoding="utf-8")
                self.assertNotIn("--method POST", gh_calls)
                self.assertNotIn("release create", gh_calls)
                self.assertFalse(
                    (
                        self.repository
                        / "release-output/github-v0.3.0/REL-06-completion-receipt.json"
                    ).exists()
                )

    def test_external_failure_stops_without_rollback_force_or_automatic_retry(self) -> None:
        for failure, phase in (
            ("tag", "tag creation"),
            ("release", "release creation"),
        ):
            with self.subTest(failure=failure):
                self.gh_log.unlink(missing_ok=True)
                self.git_log.unlink(missing_ok=True)
                result = self.invoke("--execute", failure=failure)
                self.assertEqual(result.returncode, 1)
                self.assertIn(f"stopped during {phase}", result.stderr)
                self.assertIn("state may be partial or uncertain", result.stderr)
                self.assertIn("Do not rerun --execute", result.stderr)
                gh_calls = self.gh_log.read_text(encoding="utf-8")
                git_calls = self.git_log.read_text(encoding="utf-8") if self.git_log.exists() else ""
                self.assertNotIn("repo create ", gh_calls)
                self.assertNotIn(" push ", git_calls)
                self.assertNotIn("--force", f"{gh_calls}\n{git_calls}")
                self.assertNotIn("repo delete", gh_calls)
                if failure == "tag":
                    self.assertNotIn("release create ", gh_calls)


if __name__ == "__main__":
    unittest.main()
