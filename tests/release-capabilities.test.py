#!/usr/bin/env python3
"""Exercise the hosted/static capability split and pinned self-host image."""

from argparse import ArgumentParser
from pathlib import Path
import json
import re
import zipfile


ROOT = Path(__file__).resolve().parent.parent
HOSTED = {
    "schemaVersion": 1,
    "mode": "hosted",
    "githubDirect": True,
    "cursorOrigin": True,
    "encryptedWorkspaceSync": True,
}
STATIC = {
    "schemaVersion": 1,
    "mode": "static-selfhost",
    "githubDirect": True,
    "cursorOrigin": False,
    "encryptedWorkspaceSync": False,
}
CADDY_IMAGE = (
    "caddy:2.11.4@sha256:"
    "13ba145cba2f3e28fa801994876e4c086d1b95d5aa2a520a734765ffb6b12017"
)
CADDY_IMAGE_PATTERN = re.compile(
    r"caddy:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}"
)


def json_member(archive: zipfile.ZipFile, name: str) -> object:
    return json.loads(archive.read(name))


def assert_caddy_pin(compose: str, source: str) -> None:
    images = re.findall(r"^\s*image:\s*(\S+)\s*$", compose, flags=re.MULTILINE)
    assert len(images) == 1, f"{source} must declare exactly one container image"
    image = images[0]
    assert CADDY_IMAGE_PATTERN.fullmatch(image), (
        f"{source} must use caddy:<patch-version>@sha256:<64-hex-digest>"
    )
    assert image == CADDY_IMAGE, f"{source} has an unreviewed Caddy image: {image}"


parser = ArgumentParser(description=__doc__)
parser.add_argument(
    "--source-only",
    action="store_true",
    help="check the source Compose pin without opening release archives",
)
parser.add_argument(
    "--source-archive",
    type=Path,
    default=ROOT / "public/downloads/Local-Sandbox-Source.zip",
)
parser.add_argument(
    "--selfhost-archive",
    type=Path,
    default=ROOT / "public/downloads/Local-Sandbox-Selfhost.zip",
)
options = parser.parse_args()

source_compose = (ROOT / "selfhost/compose.yaml").read_text()
assert_caddy_pin(source_compose, "selfhost/compose.yaml")

if options.source_only:
    print(json.dumps({"status": "passed", "caddyImage": CADDY_IMAGE, "scope": "source"}))
    raise SystemExit(0)


source_path = options.source_archive
selfhost_path = options.selfhost_archive
assert json.loads((ROOT / "public/local/capabilities.json").read_text()) == HOSTED

with zipfile.ZipFile(source_path) as source:
    assert json_member(source, "Local-Sandbox/public/local/capabilities.json") == HOSTED

with zipfile.ZipFile(selfhost_path) as selfhost:
    names = selfhost.namelist()
    assert_caddy_pin(selfhost.read("compose.yaml").decode(), "self-host archive compose.yaml")
    assert json_member(selfhost, "site/local/capabilities.json") == STATIC
    assert not any(Path(name).parts[:2] == ("site", "api") for name in names)
    nested_path = "site/downloads/Local-Sandbox-Source.zip"
    nested_bytes = selfhost.read(nested_path)

assert nested_bytes == source_path.read_bytes()
print(json.dumps({
    "status": "passed",
    "hosted": HOSTED,
    "selfhost": STATIC,
    "caddyImage": CADDY_IMAGE,
}))
