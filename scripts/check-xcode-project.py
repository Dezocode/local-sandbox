#!/usr/bin/env python3
"""Regenerate the Xcode metadata in isolation and compare it with the release source."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
GENERATED = (
    "ios/LocalSandbox.xcodeproj/project.pbxproj",
    "ios/LocalSandbox.xcodeproj/project.xcworkspace/contents.xcworkspacedata",
    "ios/LocalSandbox.xcodeproj/xcshareddata/xcschemes/LocalSandbox.xcscheme",
    "ios/LocalSandbox/Info.plist",
    "ios/LocalSandbox/LocalSandbox.entitlements",
    "ios/LocalSandbox/PrivacyInfo.xcprivacy",
    "ios/LocalSandbox/Assets.xcassets/Contents.json",
    "ios/LocalSandbox/Assets.xcassets/AppIcon.appiconset/Contents.json",
    "ios/LocalSandbox/Assets.xcassets/AppIcon.appiconset/AppIcon.png",
    "ios/LocalSandbox/Assets.xcassets/Brand.imageset/Contents.json",
    "ios/LocalSandbox/Assets.xcassets/Brand.imageset/Brand.png",
)


def copy_swift_files(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.glob("*.swift")):
        shutil.copy2(path, destination / path.name)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="local-sandbox-xcode-check-") as temporary:
        stage = Path(temporary)
        copy_swift_files(ROOT / "ios/LocalSandbox", stage / "ios/LocalSandbox")
        copy_swift_files(ROOT / "ios/LocalSandboxTests", stage / "ios/LocalSandboxTests")
        for relative in (
            "ios/LocalSandbox/Assets.xcassets/AppIcon.appiconset/AppIcon.png",
            "ios/LocalSandbox/Assets.xcassets/Brand.imageset/Brand.png",
        ):
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        (stage / "ios/LocalSandbox.xcodeproj/project.xcworkspace").mkdir(parents=True)
        (stage / "ios/LocalSandbox.xcodeproj/xcshareddata/xcschemes").mkdir(parents=True)
        (stage / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/generate-xcode-project.py", stage / "scripts/generate-xcode-project.py")
        subprocess.run([sys.executable, "scripts/generate-xcode-project.py"], cwd=stage, check=True)

        changed = []
        for relative in GENERATED:
            expected = stage / relative
            actual = ROOT / relative
            if not expected.is_file() or not actual.is_file() or expected.read_bytes() != actual.read_bytes():
                changed.append(relative)
        if changed:
            joined = "\n  ".join(changed)
            raise SystemExit(
                "Xcode generated files are stale. Run python3 scripts/generate-xcode-project.py.\n"
                f"  {joined}"
            )

    print(f"Xcode generated files match {len(GENERATED)} isolated outputs.")


if __name__ == "__main__":
    main()
