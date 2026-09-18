#!/usr/bin/env python3
"""Test deterministic guide output and fail-closed artifact comparison."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from pypdf import PdfReader
from PIL import Image
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


def generate(output: Path, *, root: Path = ROOT) -> None:
    environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    subprocess.run(
        [sys.executable, "scripts/generate-guide.py", "--output", str(output)],
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )


class PdfReaderPage:
    def __init__(self, page):
        self.pages = [page]


class ReleaseFreshnessTests(unittest.TestCase):
    def test_guide_bytes_do_not_depend_on_checkout_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            outputs = []
            for checkout in [temporary / "authoring", temporary / "ci/runner/local-sandbox"]:
                for relative in ["scripts/generate-guide.py", "lib/catalog.ts", "public/app-icon.png"]:
                    destination = checkout / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(ROOT / relative, destination)
                output = checkout / "guide.pdf"
                generate(output, root=checkout)
                self.assertEqual(validate_guide(output)["pages"], EXPECTED_GUIDE_PAGES)
                reader = PdfReader(output, strict=True)
                self.assertEqual(len(reader.pages[0].images), 1)
                embedded_icon = reader.pages[0].images[0].image.convert("RGBA")
                with Image.open(ROOT / "public/app-icon.png") as source_icon:
                    self.assertEqual(embedded_icon.size, source_icon.size)
                    self.assertEqual(embedded_icon.tobytes(), source_icon.convert("RGBA").tobytes())
                outputs.append(output.read_bytes())
            self.assertEqual(outputs[0], outputs[1])

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
            pages = [normalized_pdf_text(PdfReaderPage(page)) for page in PdfReader(first).pages]
            sharing_index = next(i for i, value in enumerate(pages) if value.startswith("Native provider sharing"))
            self.assertTrue(pages[sharing_index - 1].startswith("Native setup / Xcode"))
            self.assertTrue(pages[sharing_index + 1].startswith("Resource policy / exact meaning"))
            for label in ["Save configuration", "What is sent", "Allow these handoffs on this iPhone", "Withdraw sharing permission", "Review and share current prompt", "Allow this export and choose recipient or Cancel"]:
                self.assertIn(label, pages[sharing_index])

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
