#!/usr/bin/env python3
"""Require the pinned Python libraries used for deterministic release artifacts."""

from __future__ import annotations

import sys


EXPECTED = {"pillow": "12.3.0", "reportlab": "4.4.9", "pypdf": "6.10.0"}

try:
    import PIL
    import pypdf
    import reportlab
except ModuleNotFoundError as error:
    raise SystemExit(
        "Release verification requires pillow 12.3.0, reportlab 4.4.9, and pypdf 6.10.0. "
        "Install those versions or set LOCAL_SANDBOX_RELEASE_PYTHON to a Python executable that has them."
    ) from error

installed = {"pillow": PIL.__version__, "reportlab": reportlab.Version, "pypdf": pypdf.__version__}
if installed != EXPECTED:
    raise SystemExit(
        f"Release verification requires {EXPECTED}, but the selected Python has {installed}. "
        "Set LOCAL_SANDBOX_RELEASE_PYTHON to a Python executable with the required versions."
    )

print(f"Release Python dependencies passed on {sys.executable}: {installed}")
