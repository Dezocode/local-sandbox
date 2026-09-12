#!/usr/bin/env python3
"""Test deterministic guide output and fail-closed artifact comparison."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from pypdf import PdfReader
from reportlab.pdfgen import canvas


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from release.check_freshness import (
    EXPECTED_GUIDE_PAGES,
    REQUIRED_GUIDE_TEXT,
    STALE_GUIDE_TEXT,
    StaleReleaseArtifact,
    require_identical,
    normalized_pdf_text,
    validate_guide,
)


def generate(output: Path) -> None:
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    subprocess.run(
        [sys.executable, "scripts/generate-guide.py", "--output", str(output)],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )


class ReleaseFreshnessTests(unittest.TestCase):
    def test_guide_is_deterministic_and_structurally_current(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            first = temporary / "first.pdf"
            second = temporary / "second.pdf"
            generate(first)
            generate(second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            validation = validate_guide(first)
            self.assertEqual(validation["pages"], EXPECTED_GUIDE_PAGES)
            text = normalized_pdf_text(PdfReader(first))
            self.assertIn("Select Local Sandbox -> Plan One Step", text)
            self.assertIn("Read -> patch -> reread -> verified receipt", text)
            self.assertNotIn("\u2192", text)
            self.assertNotIn("Local Sandbox ■ Plan One Step", text)

    def test_guide_validation_rejects_corruption_and_stale_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            valid = temporary / "valid.pdf"
            generate(valid)
            corrupt = temporary / "corrupt.pdf"
            corrupt.write_bytes(valid.read_bytes()[:200])
            with self.assertRaisesRegex(AssertionError, "valid strict PDF"):
                validate_guide(corrupt)

            stale = temporary / "stale.pdf"
            document = canvas.Canvas(str(stale), invariant=1, pageCompression=1, pdfVersion=(1, 4))
            document.setTitle("Local Sandbox - iOS setup and release guide")
            document.setAuthor("Local Sandbox")
            document.setCreator("Local Sandbox guide generator")
            text = document.beginText(20, 760)
            for line in [*REQUIRED_GUIDE_TEXT, STALE_GUIDE_TEXT[0]]:
                text.textLine(line)
            document.drawText(text)
            document.drawString(20, 20, "1")
            for page_number in range(2, EXPECTED_GUIDE_PAGES + 1):
                document.showPage()
                document.drawString(20, 20, str(page_number))
            document.save()
            with self.assertRaisesRegex(AssertionError, "stale claim"):
                validate_guide(stale)

    def test_artifact_comparison_rejects_stale_or_missing_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            expected = temporary / "expected.bin"
            committed = temporary / "committed.bin"
            expected.write_bytes(b"expected")
            committed.write_bytes(b"expected")
            self.assertEqual(require_identical(expected, committed, "Fixture")["bytes"], 8)

            committed.write_bytes(b"stale")
            with self.assertRaisesRegex(StaleReleaseArtifact, "is stale"):
                require_identical(expected, committed, "Fixture")
            committed.unlink()
            with self.assertRaisesRegex(StaleReleaseArtifact, "is missing"):
                require_identical(expected, committed, "Fixture")


if __name__ == "__main__":
    unittest.main()
