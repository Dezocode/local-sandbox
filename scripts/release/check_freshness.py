#!/usr/bin/env python3
"""Compare committed release artifacts with independent temporary builds."""

from __future__ import annotations

from argparse import ArgumentParser
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from pypdf import PdfReader


SCRIPTS = Path(__file__).resolve().parent.parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from release_common import read_external_regular


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_GUIDE_PAGES = 27
REQUIRED_GUIDE_TEXT = [
    "authenticate with ChatGPT or configured app-level Apple sign-in",
    "portable native crypto, account and sync, autosave, and recursive-filesystem contracts",
    "Those checks do not build the full Xcode app, run a simulator, sign the app, or install it on an iPhone",
    "15-minute, device-only bearer",
    "standalone Apple sign-in and deliberate linking to a ChatGPT-owned workspace",
    "It never merges accounts by email",
    "Production Apple identifiers, keys, domain, and accounts still require live qualification",
    "strict-json, read-tool, list-tool, patch-tool, and bounded-context",
    "at least four schema-valid responses, at least four passing assertions, and zero integrity faults",
    "The protected ledger stores at most 240 attempts",
    "Scores use only the 20 freshest attempts",
    "One provider-probe pair can record once per UTC day",
    "Saved and explicit choices never substitute",
    "Best local considers only Apple and Locally",
    "Cold start applies only while neither has comparable evidence",
    "The selected route cannot switch mid-run",
    "Begin Provider Check",
    "Record Provider Check",
    "Apply Oracle Recommendation",
    "registers nine iOS 26 App Shortcuts",
    "Qualify Apple Intelligence",
    "Local Sandbox validates only the returned challenge response",
    "This records only that returned text reached Record Provider Check",
    "It does not prove unattended execution or provider, account, or model provenance",
    "Live physical-device evidence qualifies unattended operation",
    "it does not attest the response source, Shortcut contents, or login state",
    "Record live visual device evidence",
    "Every route requires five probe types, at least 80 percent schema and assertion pass rates",
    "Manual return is never eligible for unattended Siri",
    "Select Local Sandbox -> Plan One Step",
    "Read -> patch -> reread -> verified receipt",
    "full OS version and build",
    "https://developer.apple.com/xcode/system-requirements/",
    "the dashboard shows the validated committed route and ordered handoff hashes",
    "it receives no live native or provider activity",
    "The user must review and confirm the workflow and permissions",
    "No real iOS 27 execution or App Store approval is claimed",
]
STALE_GUIDE_TEXT = [
    "This is a local identity feature",
    "It does not authenticate the separate Sites dashboard",
    "The native app has not been compiled",
    "in this Linux environment",
    "private Sites version uses platform authentication instead",
    "one-tap installer",
    "detects provider sign-in",
    "installs third-party provider adapters automatically",
    "A recent valid response proves a round trip",
    "proves a valid challenge response from the configured action",
]


class StaleReleaseArtifact(AssertionError):
    """Raised when a committed artifact differs from its independent build."""


def run(command: list[str], root: Path) -> None:
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    subprocess.run(command, cwd=root, env=environment, check=True)


def read_artifact(path: Path) -> bytes:
    data, _mode = read_external_regular(path)
    return data


def require_identical(expected: Path, committed: Path, label: str) -> dict[str, object]:
    expected_data = read_artifact(expected)
    try:
        committed_data = read_artifact(committed)
    except FileNotFoundError as error:
        raise StaleReleaseArtifact(f"{label} is missing: {committed}") from error
    expected_hash = sha256(expected_data).hexdigest()
    committed_hash = sha256(committed_data).hexdigest()
    if expected_data != committed_data:
        raise StaleReleaseArtifact(
            f"{label} is stale: expected sha256 {expected_hash}, committed sha256 {committed_hash}. "
            "Run scripts/release/regenerate.py with the selected release Python before verification."
        )
    return {"sha256": expected_hash, "bytes": len(expected_data)}


def normalized_pdf_text(reader: PdfReader) -> str:
    extracted = "\n".join(page.extract_text() or "" for page in reader.pages)
    return re.sub(r"\s+", " ", extracted).strip()


def validate_guide(path: Path) -> dict[str, object]:
    data = read_artifact(path)
    try:
        reader = PdfReader(io.BytesIO(data), strict=True)
    except Exception as error:
        raise AssertionError("Setup guide is not a valid strict PDF.") from error
    if reader.is_encrypted:
        raise AssertionError("Setup guide must not be encrypted.")
    if len(reader.pages) != EXPECTED_GUIDE_PAGES:
        raise AssertionError(
            f"Setup guide has {len(reader.pages)} pages; expected {EXPECTED_GUIDE_PAGES}."
        )
    metadata = reader.metadata
    if metadata is None or metadata.title != "Local Sandbox - iOS setup and release guide":
        raise AssertionError("Setup guide title metadata is missing or stale.")
    if metadata.author != "Local Sandbox" or metadata.creator != "Local Sandbox guide generator":
        raise AssertionError("Setup guide author or creator metadata is missing or stale.")
    text = normalized_pdf_text(reader)
    for required in REQUIRED_GUIDE_TEXT:
        if required not in text:
            raise AssertionError(f"Setup guide is missing required current text: {required}")
    for stale in STALE_GUIDE_TEXT:
        if stale in text:
            raise AssertionError(f"Setup guide still contains a stale claim: {stale}")
    return {"pages": len(reader.pages), "sha256": sha256(data).hexdigest(), "bytes": len(data)}


def check(
    root: Path,
    source_artifact: Path,
    selfhost_artifact: Path,
    guide_artifact: Path,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        expected_source = temporary / "Local-Sandbox-Source.zip"
        expected_selfhost = temporary / "Local-Sandbox-Selfhost.zip"
        expected_guide = temporary / "Local-Sandbox-Setup-Guide.pdf"
        repeated_guide = temporary / "Local-Sandbox-Setup-Guide-repeat.pdf"

        run(
            [sys.executable, "scripts/package-source.py", "--root", str(root), "--output", str(expected_source)],
            root,
        )
        run(
            [
                sys.executable,
                "scripts/release/selfhost.py",
                "--root",
                str(root),
                "--source-archive",
                str(expected_source),
                "--output",
                str(expected_selfhost),
            ],
            root,
        )
        run([sys.executable, "scripts/generate-guide.py", "--output", str(expected_guide)], root)
        run([sys.executable, "scripts/generate-guide.py", "--output", str(repeated_guide)], root)

        if read_artifact(expected_guide) != read_artifact(repeated_guide):
            raise AssertionError("Setup guide generation is not byte-for-byte deterministic.")
        guide_validation = validate_guide(expected_guide)
        result = {
            "source": require_identical(expected_source, source_artifact, "Source archive"),
            "selfhost": require_identical(expected_selfhost, selfhost_artifact, "Static self-host archive"),
            "guide": require_identical(expected_guide, guide_artifact, "Setup guide"),
            "guideValidation": guide_validation,
        }
    return result


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--source-artifact", type=Path)
    parser.add_argument("--selfhost-artifact", type=Path)
    parser.add_argument("--guide-artifact", type=Path)
    options = parser.parse_args()
    root = options.root.absolute()
    result = check(
        root,
        (options.source_artifact or root / "public/downloads/Local-Sandbox-Source.zip").absolute(),
        (options.selfhost_artifact or root / "public/downloads/Local-Sandbox-Selfhost.zip").absolute(),
        (options.guide_artifact or root / "public/downloads/Local-Sandbox-Setup-Guide.pdf").absolute(),
    )
    print(json.dumps({"status": "passed", **result}, sort_keys=True))


if __name__ == "__main__":
    main()
