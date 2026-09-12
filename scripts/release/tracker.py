#!/usr/bin/env python3
"""Validate and bind the canonical Local Sandbox 0.3 qualification tracker."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import sys
import tempfile
import unicodedata
from typing import Any, NoReturn, Sequence
from xml.etree import ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, os.fspath(ROOT / "scripts"))

from release_common import read_external_regular  # noqa: E402
from release.candidate_digest import CandidateDigestError, candidate_digest  # noqa: E402


VERSION = "0.3.0"
TAG = "v0.3.0"
CANONICAL_TRACKER_PATH = PurePosixPath("qualification/Local-Sandbox-0.3-Progress.xlsx")
CANONICAL_SNAPSHOT_PATH = PurePosixPath(
    "qualification/Local-Sandbox-0.3-Progress.snapshot.json"
)
VALIDATION_PATH = PurePosixPath("docs/validation.json")
TRACKER_CHECK_LABEL = "Release qualification tracker"
ARTIFACT_PATHS = (
    PurePosixPath("public/downloads/Local-Sandbox-Source.zip"),
    PurePosixPath("public/downloads/Local-Sandbox-Selfhost.zip"),
    PurePosixPath("public/downloads/Local-Sandbox-Setup-Guide.pdf"),
)
EXPECTED_GATE_IDS = (
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
EXPECTED_GATE_ID_SET = frozenset(EXPECTED_GATE_IDS)
EXPECTED_PHASE_BY_GATE = {
    **{identifier: "Governance & source" for identifier in EXPECTED_GATE_IDS[:5]},
    **{identifier: "Apple environment" for identifier in EXPECTED_GATE_IDS[5:10]},
    **{identifier: "Baseline regression" for identifier in EXPECTED_GATE_IDS[10:13]},
    **{identifier: "Native identity & storage" for identifier in EXPECTED_GATE_IDS[13:19]},
    **{identifier: "Provider integrations" for identifier in EXPECTED_GATE_IDS[19:25]},
    **{identifier: "Runner & file operations" for identifier in EXPECTED_GATE_IDS[25:31]},
    **{identifier: "Shortcut packages" for identifier in EXPECTED_GATE_IDS[31:34]},
    **{identifier: "Local PWA & hosting" for identifier in EXPECTED_GATE_IDS[34:38]},
    **{identifier: "Full 0.3 engineering" for identifier in EXPECTED_GATE_IDS[38:46]},
    **{identifier: "GitHub & iCloud" for identifier in EXPECTED_GATE_IDS[46:50]},
    **{identifier: "Release" for identifier in EXPECTED_GATE_IDS[50:]},
}
EXPECTED_DEPENDENCY_TEXT = {
    "GOV-01": "None",
    "SRC-01": "GOV-01",
    "SRC-02": "SRC-01",
    "SRC-03": "SRC-01",
    "VER-01": "SRC-03",
    "ENV-00": "None",
    "ENV-01": "ENV-00",
    "ENV-02": "ENV-01; SRC-01",
    "ENV-03": "ENV-01",
    "ENV-04": "ENV-01; SRC-01",
    "BASE-01": "SRC-03",
    "BASE-02": "SRC-01",
    "BASE-03": "BASE-01; BASE-02",
    "NAT-01": "ENV-02; ENV-03; ENV-04; SRC-03",
    "NAT-02": "NAT-01; AUTH-01",
    "NAT-03": "NAT-02",
    "NAT-04": "NAT-02; NAT-03",
    "NAT-05": "NAT-04; ENV-03",
    "NAT-06": "NAT-03; NAT-05",
    "PROV-01": "NAT-01; ENV-03",
    "PROV-02": "NAT-01; ENV-03",
    "PROV-03": "NAT-01; ENV-03",
    "PROV-04": "NAT-01; ENV-03; PROV-01",
    "PROV-05": "NAT-03; ENV-03; PROV-01; PROV-02; PROV-03; PROV-04",
    "PROV-06": "NAT-01",
    "RUN-01": "PROV-01; PROV-02; PROV-03; PROV-04; PROV-05; NAT-01",
    "RUN-02": "RUN-01",
    "RUN-03": "RUN-02",
    "RUN-04": "RUN-02",
    "RUN-05": "RUN-01",
    "RUN-06": "RUN-01",
    "PKG-01": "PROV-01; PROV-02; PROV-03; RUN-01",
    "PKG-02": "PKG-01; VER-01",
    "PKG-03": "PKG-02; ENV-03",
    "PWA-01": "BASE-01",
    "PWA-02": "PWA-01",
    "PWA-03": "PWA-01; AUTOSAVE-01",
    "PWA-04": "BASE-01; PKG-02",
    "AUTH-01": "SRC-03",
    "SYNC-01": "AUTH-01; NAT-03; PWA-02",
    "KEY-01": "AUTH-01; SYNC-01",
    "AUTOSAVE-01": "SRC-03",
    "PWA-CONN-01": "SRC-02; AUTH-01",
    "PWA-CONN-02": "SRC-02; PWA-CONN-01",
    "BG-01": "RUN-05; ENV-03",
    "VERIFY-01": "RUN-02; BASE-03",
    "GH-01": "SRC-02; NAT-04",
    "GH-02": "GH-01; PWA-CONN-01",
    "ICLOUD-01": "NAT-03; ENV-03",
    "PRIV-01": "GH-02; SYNC-01",
    "REL-01": "All 50 prior rows",
    "REL-02": "ENV-04; VER-01; REL-01",
    "REL-03": "REL-01; REL-02; REL-05",
    "REL-04": "REL-03; ENV-03; PROV-01; PROV-02; PROV-03; PROV-04; PROV-05; RUN-01",
    "REL-05": "SRC-02; REL-01; REL-02",
    "REL-06": "REL-01; PKG-02",
    "REL-07": "REL-04; REL-02",
}
REQUIREMENT_COLUMNS = (
    "ID", "Phase", "Requirement", "Acceptance evidence", "Source", "Status",
    "Owner", "Dependencies", "Evidence/reference", "Blocker or next action",
    "Recorded/updated UTC",
)
IMMUTABLE_REQUIREMENT_COLUMN_INDICES = (0, 1, 2, 3, 4, 7)
IMMUTABLE_REQUIREMENT_COLUMNS = tuple(
    REQUIREMENT_COLUMNS[index] for index in IMMUTABLE_REQUIREMENT_COLUMN_INDICES
)
EXPECTED_IMMUTABLE_REQUIREMENTS_SHA256 = (
    "8d0792903070b30159fa7d76805b8b1ec47691ced34e3a595b0caa3c3ec15462"
)
EVIDENCE_COLUMNS = (
    "Recorded/updated UTC", "Gate/ID", "Environment", "Command or test", "Result",
    "Evidence or path", "Notes",
)
PHASES = (
    "Governance & source", "Apple environment", "Baseline regression",
    "Native identity & storage", "Provider integrations", "Runner & file operations",
    "Shortcut packages", "Local PWA & hosting", "Full 0.3 engineering",
    "GitHub & iCloud", "Release",
)
STATUSES = frozenset({"PASS", "IN PROGRESS", "BLOCKED", "FAIL", "NOT STARTED"})
APPLE_PENDING = frozenset({"REL-03", "REL-04", "REL-06", "REL-07"})
GITHUB_PENDING = frozenset({"REL-06"})
APPLE_PERCENT = 92.98245614035088
GITHUB_PERCENT = 98.24561403508771
MAX_WORKBOOK_BYTES = 8_000_000
MAX_MEMBER_BYTES = 8_000_000
MAX_EXPANDED_BYTES = 24_000_000
MAX_SHARED_STRINGS = 20_000
MAX_CELL_TEXT = 32_000
NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS_PACKAGE_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
NS = {"x": NS_MAIN, "r": NS_REL, "pr": NS_PACKAGE_REL}
CELL_REFERENCE = re.compile(r"([A-Z]{1,3})([1-9][0-9]{0,6})\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_PATTERN = re.compile(
    r"(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"sk-[A-Za-z0-9_-]{20,})"
)
MACHINE_PATH_PATTERN = re.compile(
    r"(?:/" + r"Users/[^/\s]+|/home/[^/\s]+|[A-Za-z]:\\" + r"Users\\[^\\\s]+)"
)
FORMULA_TEXT_PATTERN = re.compile(r"^(?:[=+@]|-[A-Za-z(])")
GENERIC_PROOF = frozenset({
    "done", "pass", "passed", "complete", "completed", "ok", "works", "working",
    "verified", "tested", "proof", "evidence", "see tracker", "tracker", "n/a", "na",
})
PROOF_ANCHOR = re.compile(
    r"(?:\d|/|https://|[A-Za-z0-9_-]+\.(?:json|mjs|js|ts|py|swift|zip|pdf|plist|xcprivacy)\b|"
    r"\b(?:xcodebuild|devicectl|simctl|swiftc|pnpm|sha-?256|commit|receipt|identity|device)\b)",
    re.IGNORECASE,
)
ALLOWED_PACKAGE_PART = re.compile(
    r"(?:"
    r"\[Content_Types\]\.xml|_rels/\.rels|"
    r"docProps/(?:app|core|custom)\.xml|"
    r"xl/workbook\.xml|xl/_rels/workbook\.xml\.rels|xl/styles\.xml|"
    r"xl/sharedStrings\.xml|xl/theme/theme[0-9]+\.xml|"
    r"xl/worksheets/sheet[1-3]\.xml|"
    r"xl/worksheets/_rels/sheet[23]\.xml\.rels|"
    r"xl/tables/table[12]\.xml"
    r")\Z"
)
ALLOWED_RELATIONSHIP_TYPES = frozenset({
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument",
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/custom-properties",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings",
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships/table",
})


class TrackerError(RuntimeError):
    """Raised when tracker evidence is malformed, unsafe, stale, or inconsistent."""


@dataclass(frozen=True)
class Cell:
    value: str
    formula: str | None
    kind: str


@dataclass(frozen=True)
class Requirement:
    values: tuple[str, ...]
    dependencies: tuple[str, ...]

    @property
    def identifier(self) -> str:
        return self.values[0]

    @property
    def status(self) -> str:
        return self.values[5]

    @property
    def evidence(self) -> str:
        return self.values[8]


@dataclass(frozen=True)
class TrackerBundle:
    workbook_sha256: str
    snapshot_sha256: str
    requirements_sha256: str
    evidence_sha256: str
    requirements: tuple[Requirement, ...]
    evidence_rows: tuple[tuple[str, ...], ...]

    def binding(self) -> dict[str, Any]:
        return {
            "evidenceSha256": self.evidence_sha256,
            "path": CANONICAL_TRACKER_PATH.as_posix(),
            "requirementsSha256": self.requirements_sha256,
            "sha256": self.workbook_sha256,
            "snapshotPath": CANONICAL_SNAPSHOT_PATH.as_posix(),
            "snapshotSha256": self.snapshot_sha256,
        }

    def gates(self) -> list[dict[str, str]]:
        return [
            {
                "evidenceSha256": digest(row.evidence.encode("utf-8")),
                "id": row.identifier,
                "status": row.status,
            }
            for row in self.requirements
        ]


def fail(message: str) -> NoReturn:
    raise TrackerError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: Any, *, pretty: bool = False) -> bytes:
    if pretty:
        text = json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True)
    else:
        text = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return f"{text}\n".encode("utf-8")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains a duplicate key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TrackerError(f"{label} is not UTF-8 JSON") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=lambda item: fail(f"{label} contains {item}"),
        )
    except (json.JSONDecodeError, TrackerError) as error:
        if isinstance(error, TrackerError):
            raise
        raise TrackerError(f"{label} is not valid JSON: {error.msg}") from error
    if not isinstance(value, dict):
        fail(f"{label} must contain one object")
    return value


def normalize_text(value: str, label: str) -> str:
    normalized = unicodedata.normalize("NFC", value.replace("\r\n", "\n").replace("\r", "\n"))
    if len(normalized) > MAX_CELL_TEXT:
        fail(f"{label} exceeds {MAX_CELL_TEXT} characters")
    if any(ord(character) < 32 and character not in "\n\t" for character in normalized):
        fail(f"{label} contains a control character")
    if MACHINE_PATH_PATTERN.search(normalized):
        fail(f"{label} contains a local-machine path")
    if TOKEN_PATTERN.search(normalized):
        fail(f"{label} contains token-shaped credential material")
    if FORMULA_TEXT_PATTERN.match(normalized.lstrip()):
        fail(f"{label} contains formula-like text")
    return normalized


def normalize_number(value: str, label: str) -> str:
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise TrackerError(f"{label} contains an invalid number") from error
    if not number.is_finite():
        fail(f"{label} contains a non-finite number")
    normalized = format(number, "f")
    if "." in normalized:
        normalized = normalized.rstrip("0").rstrip(".")
    if normalized == "-0":
        normalized = "0"
    return normalized


def safe_xml(data: bytes, label: str) -> ET.Element:
    upper = data.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        fail(f"{label} contains a forbidden XML declaration")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise TrackerError(f"{label} is malformed XML") from error
    for node in root.iter():
        for value in (node.text, node.tail, *node.attrib.values()):
            if value is None:
                continue
            if MACHINE_PATH_PATTERN.search(value):
                fail(f"{label} contains a local-machine path")
            if TOKEN_PATTERN.search(value):
                fail(f"{label} contains token-shaped credential material")
    return root


def relationship_source(part: str) -> str:
    if part == "_rels/.rels":
        return ""
    parent, name = posixpath.split(part)
    if not parent.endswith("/_rels") or not name.endswith(".rels"):
        fail(f"Unexpected relationship part: {part}")
    return posixpath.join(parent[:-6], name[:-5])


def resolve_relationship(source: str, target: str, label: str) -> str:
    if "\\" in target or not target:
        fail(f"{label} has an unsafe target")
    if target.startswith("/"):
        resolved = posixpath.normpath(target[1:])
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), target))
    if resolved.startswith("../") or resolved in {"", ".", ".."}:
        fail(f"{label} escapes the workbook package")
    return resolved


def read_package(workbook_data: bytes) -> dict[str, bytes]:
    if not workbook_data or len(workbook_data) > MAX_WORKBOOK_BYTES:
        fail(f"Tracker workbook must contain 1 to {MAX_WORKBOOK_BYTES} bytes")
    try:
        archive = zipfile.ZipFile(io.BytesIO(workbook_data))
    except zipfile.BadZipFile as error:
        raise TrackerError("Tracker workbook is not a valid OOXML ZIP") from error
    with archive:
        infos = archive.infolist()
        if not infos or len(infos) > 200:
            fail("Tracker workbook has an unsafe ZIP member count")
        names: set[str] = set()
        expanded = 0
        parts: dict[str, bytes] = {}
        for info in infos:
            name = info.filename
            path = PurePosixPath(name)
            if (
                name in names
                or path.is_absolute()
                or "\\" in name
                or any(part in {"", ".", ".."} for part in path.parts)
                or info.flag_bits & 0x1
                or info.is_dir()
                or (info.external_attr >> 16) & 0o170000 == 0o120000
            ):
                fail(f"Tracker workbook contains an unsafe ZIP member: {name}")
            if ALLOWED_PACKAGE_PART.fullmatch(name) is None:
                fail(f"Tracker workbook contains an unexpected OOXML part: {name}")
            if info.file_size > MAX_MEMBER_BYTES:
                fail(f"Tracker workbook member is too large: {name}")
            if info.file_size > 1_000_000 and info.compress_size * 200 < info.file_size:
                fail(f"Tracker workbook member has an unsafe compression ratio: {name}")
            expanded += info.file_size
            if expanded > MAX_EXPANDED_BYTES:
                fail("Tracker workbook expands beyond its safe size limit")
            names.add(name)
            try:
                parts[name] = archive.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                raise TrackerError(f"Could not read tracker workbook member: {name}") from error
        if archive.testzip() is not None:
            fail("Tracker workbook failed its CRC check")

    required = {
        "[Content_Types].xml", "_rels/.rels", "xl/workbook.xml",
        "xl/_rels/workbook.xml.rels", "xl/styles.xml", "xl/sharedStrings.xml",
        "xl/worksheets/sheet1.xml", "xl/worksheets/sheet2.xml",
        "xl/worksheets/sheet3.xml", "xl/worksheets/_rels/sheet2.xml.rels",
        "xl/worksheets/_rels/sheet3.xml.rels", "xl/tables/table1.xml", "xl/tables/table2.xml",
    }
    missing = required - set(parts)
    if missing:
        fail("Tracker workbook is missing required OOXML parts: " + ", ".join(sorted(missing)))

    forbidden_markers = (b"macroenabled", b"vbaproject", b"externallink", b"oleobject", b"activex")
    for name, data in parts.items():
        lowered = data.lower()
        if any(marker in lowered for marker in forbidden_markers):
            fail(f"Tracker workbook contains active or external content in {name}")
        if name.endswith(".xml") or name.endswith(".rels"):
            safe_xml(data, name)

    for name, data in parts.items():
        if not name.endswith(".rels"):
            continue
        source = relationship_source(name)
        root = safe_xml(data, name)
        relationship_ids: set[str] = set()
        for relationship in root.findall("pr:Relationship", NS):
            identifier = relationship.get("Id", "")
            relationship_type = relationship.get("Type", "")
            if not identifier or identifier in relationship_ids:
                fail(f"{name} contains a missing or duplicate relationship ID")
            relationship_ids.add(identifier)
            if relationship.get("TargetMode", "Internal") != "Internal":
                fail(f"{name} contains an external relationship")
            if relationship_type not in ALLOWED_RELATIONSHIP_TYPES:
                fail(f"{name} contains a forbidden relationship type")
            target = resolve_relationship(source, relationship.get("Target", ""), name)
            if target not in parts:
                fail(f"{name} references a missing OOXML part: {target}")
    return parts


def shared_strings(parts: dict[str, bytes]) -> tuple[str, ...]:
    root = safe_xml(parts["xl/sharedStrings.xml"], "xl/sharedStrings.xml")
    values: list[str] = []
    for index, item in enumerate(root.findall("x:si", NS)):
        value = "".join(text.text or "" for text in item.iter(f"{{{NS_MAIN}}}t"))
        values.append(normalize_text(value, f"shared string {index}"))
        if len(values) > MAX_SHARED_STRINGS:
            fail("Tracker workbook has too many shared strings")
    return tuple(values)


def column_number(letters: str) -> int:
    result = 0
    for character in letters:
        result = result * 26 + ord(character) - 64
    return result


def parse_sheet(data: bytes, strings: tuple[str, ...], label: str) -> dict[str, Cell]:
    root = safe_xml(data, label)
    cells: dict[str, Cell] = {}
    for cell in root.findall(".//x:sheetData/x:row/x:c", NS):
        reference = cell.get("r", "")
        match = CELL_REFERENCE.fullmatch(reference)
        if match is None or reference in cells:
            fail(f"{label} contains a missing, invalid, or duplicate cell reference")
        if column_number(match.group(1)) > 200 or int(match.group(2)) > 10_000:
            fail(f"{label} contains an out-of-bounds cell: {reference}")
        formula_node = cell.find("x:f", NS)
        formula = None if formula_node is None else (formula_node.text or "")
        if formula_node is not None and (formula_node.attrib or not formula):
            fail(f"{label}!{reference} uses an unsupported formula form")
        kind = cell.get("t", "n")
        value_node = cell.find("x:v", NS)
        inline = cell.find("x:is", NS)
        if kind == "s":
            if value_node is None or not (value_node.text or "").isdigit():
                fail(f"{label}!{reference} has an invalid shared-string index")
            index = int(value_node.text or "0")
            if index >= len(strings):
                fail(f"{label}!{reference} has an out-of-range shared-string index")
            value = strings[index]
        elif kind in {"str", "inlineStr"}:
            if kind == "inlineStr":
                if inline is None:
                    fail(f"{label}!{reference} is missing inline text")
                value = "".join(text.text or "" for text in inline.iter(f"{{{NS_MAIN}}}t"))
            else:
                value = "" if value_node is None else value_node.text or ""
            value = normalize_text(value, f"{label}!{reference}")
        elif kind == "n":
            value = "" if value_node is None else normalize_number(
                value_node.text or "", f"{label}!{reference}"
            )
        elif kind == "b":
            if value_node is None or value_node.text not in {"0", "1"}:
                fail(f"{label}!{reference} has an invalid Boolean")
            value = value_node.text
        else:
            fail(f"{label}!{reference} uses unsupported cell type {kind}")
        cells[reference] = Cell(value=value, formula=formula, kind=kind)
    return cells


def workbook_sheets(parts: dict[str, bytes]) -> tuple[tuple[str, str], ...]:
    relationships = safe_xml(
        parts["xl/_rels/workbook.xml.rels"], "xl/_rels/workbook.xml.rels"
    )
    by_id = {
        node.get("Id", ""): resolve_relationship(
            "xl/workbook.xml", node.get("Target", ""), "xl/_rels/workbook.xml.rels"
        )
        for node in relationships.findall("pr:Relationship", NS)
        if node.get("Type", "").endswith("/worksheet")
    }
    workbook = safe_xml(parts["xl/workbook.xml"], "xl/workbook.xml")
    if workbook.findall("x:definedNames/x:definedName", NS):
        fail("Tracker workbook must not contain defined names")
    sheets: list[tuple[str, str]] = []
    for node in workbook.findall("x:sheets/x:sheet", NS):
        name = node.get("name", "")
        relationship_id = node.get(f"{{{NS_REL}}}id", "")
        if relationship_id not in by_id:
            fail(f"Tracker sheet {name} has no internal worksheet relationship")
        sheets.append((name, by_id[relationship_id]))
    expected = (
        ("Release status", "xl/worksheets/sheet1.xml"),
        ("Requirements", "xl/worksheets/sheet2.xml"),
        ("Evidence", "xl/worksheets/sheet3.xml"),
    )
    if tuple(sheets) != expected:
        fail("Tracker workbook must contain Release status, Requirements, and Evidence in order")
    return tuple(sheets)


def table_contract(
    parts: dict[str, bytes],
    part: str,
    *,
    name: str,
    columns: tuple[str, ...],
    required_ref: str | None = None,
) -> tuple[int, int]:
    root = safe_xml(parts[part], part)
    if root.get("name") != name or root.get("displayName") != name:
        fail(f"{part} must define {name}")
    reference = root.get("ref", "")
    match = re.fullmatch(r"A5:([A-Z]+)([1-9][0-9]*)", reference)
    if match is None or match.group(1) != chr(64 + len(columns)):
        fail(f"{name} has an invalid table range")
    if required_ref is not None and reference != required_ref:
        fail(f"{name} range must be {required_ref}")
    table_columns = root.findall("x:tableColumns/x:tableColumn", NS)
    actual_columns = tuple(node.get("name", "") for node in table_columns)
    if root.find("x:tableColumns", NS) is None or actual_columns != columns:
        fail(f"{name} columns do not match the canonical contract")
    if root.find("x:tableColumns", NS).get("count") != str(len(columns)):
        fail(f"{name} has an inconsistent column count")
    return 5, int(match.group(2))


def table_rows(
    cells: dict[str, Cell],
    columns: tuple[str, ...],
    start: int,
    end: int,
    label: str,
) -> tuple[tuple[str, ...], ...]:
    header = tuple(cells.get(f"{chr(65 + index)}{start}", Cell("", None, "str")).value
                   for index in range(len(columns)))
    if header != columns:
        fail(f"{label} worksheet headers do not match its table definition")
    rows: list[tuple[str, ...]] = []
    for row_number in range(start + 1, end + 1):
        row: list[str] = []
        for index in range(len(columns)):
            reference = f"{chr(65 + index)}{row_number}"
            cell = cells.get(reference)
            if cell is not None and cell.formula is not None:
                fail(f"{label}!{reference} must not contain a formula")
            row.append("" if cell is None else cell.value)
        rows.append(tuple(row))
    return tuple(rows)


def parse_dependencies(identifier: str, value: str, index: int) -> tuple[str, ...]:
    if value == "None":
        return ()
    if value == "All 50 prior rows":
        if identifier != "REL-01" or index != 50:
            fail(f"{identifier} uses All 50 prior rows outside its canonical position")
        return EXPECTED_GATE_IDS[:50]
    dependencies = tuple(part.strip() for part in value.split(";"))
    if not dependencies or any(not item for item in dependencies):
        fail(f"{identifier} has malformed dependencies")
    if len(dependencies) != len(set(dependencies)) or identifier in dependencies:
        fail(f"{identifier} has duplicate or self-referential dependencies")
    unknown = set(dependencies) - EXPECTED_GATE_ID_SET
    if unknown:
        fail(f"{identifier} has unknown dependencies: {', '.join(sorted(unknown))}")
    return dependencies


def concrete_proof(value: str, identifier: str) -> None:
    stripped = value.strip()
    if (
        len(stripped) < 16
        or stripped.casefold() in GENERIC_PROOF
        or PROOF_ANCHOR.search(stripped) is None
    ):
        fail(f"{identifier} PASS evidence is generic; record a concrete result, path, count, or digest")


def immutable_requirements_sha256(rows: Sequence[Sequence[str]]) -> str:
    """Commit to the ordered 57-gate definition while excluding mutable progress."""
    immutable_rows = tuple(
        tuple(values[index] for index in IMMUTABLE_REQUIREMENT_COLUMN_INDICES)
        for values in rows
    )
    return digest(canonical_json({
        "columns": IMMUTABLE_REQUIREMENT_COLUMNS,
        "rows": immutable_rows,
    }))


def validate_requirements(rows: tuple[tuple[str, ...], ...]) -> tuple[Requirement, ...]:
    if len(rows) != len(EXPECTED_GATE_IDS):
        fail(f"RequirementsTable must contain exactly {len(EXPECTED_GATE_IDS)} data rows")
    requirements: list[Requirement] = []
    for index, values in enumerate(rows):
        identifier = values[0]
        if identifier != EXPECTED_GATE_IDS[index]:
            fail(
                f"Requirements row {index + 1} must be {EXPECTED_GATE_IDS[index]} in canonical order"
            )
        if any(not values[position].strip() for position in (1, 2, 3, 4, 5, 6, 7, 9, 10)):
            fail(f"{identifier} is missing required tracker fields")
        if values[1] != EXPECTED_PHASE_BY_GATE[identifier]:
            fail(f"{identifier} is not assigned to its canonical phase")
        if values[5] not in STATUSES:
            fail(f"{identifier} has an unknown status")
        if values[7] != EXPECTED_DEPENDENCY_TEXT[identifier]:
            fail(f"{identifier} dependencies do not match the canonical 0.3 graph")
        dependencies = parse_dependencies(identifier, values[7], index)
        if values[5] == "PASS":
            concrete_proof(values[8], identifier)
        requirements.append(Requirement(values=values, dependencies=dependencies))

    immutable_sha256 = immutable_requirements_sha256(rows)
    if immutable_sha256 != EXPECTED_IMMUTABLE_REQUIREMENTS_SHA256:
        fail(
            "RequirementsTable immutable 0.3 contract changed; ID, Phase, Requirement, "
            "Acceptance evidence, Source, and Dependencies must match the canonical "
            f"57-gate definition (expected {EXPECTED_IMMUTABLE_REQUIREMENTS_SHA256}, "
            f"got {immutable_sha256})"
        )

    by_id = {row.identifier: row for row in requirements}
    visited: set[str] = set()
    active: set[str] = set()

    def visit(identifier: str) -> None:
        if identifier in active:
            fail(f"Tracker dependency graph contains a cycle at {identifier}")
        if identifier in visited:
            return
        active.add(identifier)
        for dependency in by_id[identifier].dependencies:
            visit(dependency)
        active.remove(identifier)
        visited.add(identifier)

    for row in requirements:
        visit(row.identifier)
        if row.status == "PASS":
            open_dependencies = [
                dependency for dependency in row.dependencies
                if by_id[dependency].status != "PASS"
            ]
            if open_dependencies:
                fail(
                    f"{row.identifier} cannot be PASS while dependencies remain open: "
                    + ", ".join(open_dependencies)
                )
    return tuple(requirements)


def validate_evidence(
    rows: tuple[tuple[str, ...], ...], requirements: tuple[Requirement, ...]
) -> None:
    if not rows:
        fail("EvidenceTable must contain at least one evidence row")
    passed_evidence: set[str] = set()
    for index, values in enumerate(rows):
        label = f"Evidence row {index + 1}"
        if any(not value.strip() for value in values):
            fail(f"{label} has a blank field")
        if values[1] not in EXPECTED_GATE_ID_SET:
            fail(f"{label} references an unknown gate")
        if values[4] not in STATUSES:
            fail(f"{label} has an unknown result")
        timestamp = values[0]
        try:
            serial = Decimal(timestamp)
        except InvalidOperation:
            serial = Decimal(0)
        if serial <= 0 or serial >= 100_000:
            try:
                from datetime import datetime

                parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError as error:
                raise TrackerError(f"{label} has an invalid timestamp") from error
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                fail(f"{label} timestamp must include a UTC offset")
        if values[4] == "PASS":
            concrete_proof(values[5], values[1])
            passed_evidence.add(values[1])
    missing = [
        row.identifier for row in requirements
        if row.status == "PASS" and row.identifier not in passed_evidence
    ]
    if missing:
        fail("PASS requirements lack a PASS EvidenceTable row: " + ", ".join(missing))


def decimal_equal(actual: str, expected: Decimal, label: str) -> None:
    try:
        value = Decimal(actual)
    except InvalidOperation as error:
        raise TrackerError(f"{label} has no numeric cached result") from error
    if abs(value - expected) > Decimal("0.000000000001"):
        fail(f"{label} has a stale cached result")


def validate_dashboard(
    cells: dict[str, Cell], requirements: tuple[Requirement, ...]
) -> None:
    expected_formulas: dict[str, str] = {
        "B6": 'IF(AND(COUNTA(Requirements!$A$6:$A$62)=57,COUNTIFS(Requirements!$F$6:$F$62,"PASS")=57,COUNTIFS(Requirements!$F$6:$F$62,"PASS",Requirements!$I$6:$I$62,"<>")=57),"FULL 0.3 QUALIFIED","NOT QUALIFIED")',
        "B7": 'IF(COUNTA(Requirements!$A$6:$A$62)<>57,0,COUNTIFS(Requirements!$F$6:$F$62,"PASS",Requirements!$I$6:$I$62,"<>")/57)',
        "B13": "COUNTA(Requirements!$A$6:$A$62)",
        "B14": 'COUNTIFS(Requirements!$F$6:$F$62,"PASS",Requirements!$I$6:$I$62,"<>")',
        "B15": 'COUNTIFS(Requirements!$F$6:$F$62,"IN PROGRESS")',
        "B16": 'COUNTIFS(Requirements!$F$6:$F$62,"BLOCKED")+COUNTIFS(Requirements!$F$6:$F$62,"FAIL")',
        "B17": 'COUNTIFS(Requirements!$F$6:$F$62,"NOT STARTED")',
    }
    for index in range(20):
        column = chr(ord("B") + index)
        threshold = format(Decimal(index + 1) / Decimal(20), "f").rstrip("0").rstrip(".")
        expected_formulas[f"{column}9"] = f"IF($B$7>={threshold},1,0)"
    for row_number in range(13, 24):
        expected_formulas.update({
            f"E{row_number}": f"COUNTIFS(Requirements!$B$6:$B$62,$D{row_number})",
            f"F{row_number}": f'COUNTIFS(Requirements!$B$6:$B$62,$D{row_number},Requirements!$F$6:$F$62,"PASS",Requirements!$I$6:$I$62,"<>")',
            f"G{row_number}": f'COUNTIFS(Requirements!$B$6:$B$62,$D{row_number},Requirements!$F$6:$F$62,"IN PROGRESS")',
            f"H{row_number}": f'COUNTIFS(Requirements!$B$6:$B$62,$D{row_number},Requirements!$F$6:$F$62,"BLOCKED")+COUNTIFS(Requirements!$B$6:$B$62,$D{row_number},Requirements!$F$6:$F$62,"FAIL")',
            f"I{row_number}": f"IF(E{row_number}=0,0,F{row_number}/E{row_number})",
            f"J{row_number}": f'IF(E{row_number}=0,"OPEN",IF(F{row_number}=E{row_number},"PASS",IF(H{row_number}>0,"BLOCKED","OPEN")))',
        })
    actual_formulas = {reference: cell.formula for reference, cell in cells.items() if cell.formula}
    if actual_formulas != expected_formulas:
        missing = sorted(set(expected_formulas) - set(actual_formulas))
        unexpected = sorted(set(actual_formulas) - set(expected_formulas))
        changed = sorted(
            reference for reference in set(actual_formulas) & set(expected_formulas)
            if actual_formulas[reference] != expected_formulas[reference]
        )
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        if changed:
            details.append("changed " + ", ".join(changed))
        fail("Release status formula contract failed: " + "; ".join(details))
    if cells.get("B4", Cell("", None, "str")).value != "0.3":
        fail("Release status target version must be 0.3")
    phases = tuple(cells.get(f"D{row}", Cell("", None, "str")).value for row in range(13, 24))
    if phases != PHASES:
        fail("Release status phase roster is not canonical")

    pass_count = sum(row.status == "PASS" and bool(row.evidence.strip()) for row in requirements)
    completion = Decimal(pass_count) / Decimal(len(requirements))
    expected_text = "FULL 0.3 QUALIFIED" if pass_count == len(requirements) else "NOT QUALIFIED"
    if cells["B6"].value != expected_text:
        fail("Release status!B6 has a stale cached qualification result")
    decimal_equal(cells["B7"].value, completion, "Release status!B7")
    numeric_summary = {
        "B13": len(requirements),
        "B14": pass_count,
        "B15": sum(row.status == "IN PROGRESS" for row in requirements),
        "B16": sum(row.status in {"BLOCKED", "FAIL"} for row in requirements),
        "B17": sum(row.status == "NOT STARTED" for row in requirements),
    }
    for reference, expected in numeric_summary.items():
        decimal_equal(cells[reference].value, Decimal(expected), f"Release status!{reference}")
    for index in range(20):
        column = chr(ord("B") + index)
        threshold = Decimal(index + 1) / Decimal(20)
        expected = Decimal(1 if completion >= threshold else 0)
        decimal_equal(cells[f"{column}9"].value, expected, f"Release status!{column}9")
    for phase_index, phase in enumerate(PHASES, start=13):
        rows = [row for row in requirements if row.values[1] == phase]
        total = len(rows)
        passed = sum(row.status == "PASS" and bool(row.evidence.strip()) for row in rows)
        active = sum(row.status == "IN PROGRESS" for row in rows)
        blocked = sum(row.status in {"BLOCKED", "FAIL"} for row in rows)
        phase_completion = Decimal(passed) / Decimal(total) if total else Decimal(0)
        gate = "OPEN" if total == 0 else "PASS" if passed == total else "BLOCKED" if blocked else "OPEN"
        for column, expected in (("E", total), ("F", passed), ("G", active), ("H", blocked)):
            decimal_equal(cells[f"{column}{phase_index}"].value, Decimal(expected), f"Release status!{column}{phase_index}")
        decimal_equal(cells[f"I{phase_index}"].value, phase_completion, f"Release status!I{phase_index}")
        if cells[f"J{phase_index}"].value != gate:
            fail(f"Release status!J{phase_index} has a stale cached result")


def parse_workbook(workbook_data: bytes) -> tuple[
    tuple[Requirement, ...], tuple[tuple[str, ...], ...], str, str
]:
    parts = read_package(workbook_data)
    workbook_sheets(parts)
    strings = shared_strings(parts)
    dashboard = parse_sheet(parts["xl/worksheets/sheet1.xml"], strings, "Release status")
    requirement_cells = parse_sheet(parts["xl/worksheets/sheet2.xml"], strings, "Requirements")
    evidence_cells = parse_sheet(parts["xl/worksheets/sheet3.xml"], strings, "Evidence")
    for sheet_name, cells in (("Requirements", requirement_cells), ("Evidence", evidence_cells)):
        formulas = sorted(reference for reference, cell in cells.items() if cell.formula is not None)
        if formulas:
            fail(f"{sheet_name} must not contain formulas: {', '.join(formulas)}")
    requirement_range = table_contract(
        parts,
        "xl/tables/table1.xml",
        name="RequirementsTable",
        columns=REQUIREMENT_COLUMNS,
        required_ref="A5:K62",
    )
    evidence_range = table_contract(
        parts,
        "xl/tables/table2.xml",
        name="EvidenceTable",
        columns=EVIDENCE_COLUMNS,
    )
    requirement_rows = table_rows(
        requirement_cells, REQUIREMENT_COLUMNS, *requirement_range, "Requirements"
    )
    evidence_rows = table_rows(evidence_cells, EVIDENCE_COLUMNS, *evidence_range, "Evidence")
    requirements = validate_requirements(requirement_rows)
    validate_evidence(evidence_rows, requirements)
    validate_dashboard(dashboard, requirements)
    requirements_sha = digest(canonical_json({
        "columns": REQUIREMENT_COLUMNS,
        "rows": requirement_rows,
    }))
    evidence_sha = digest(canonical_json({
        "columns": EVIDENCE_COLUMNS,
        "rows": evidence_rows,
    }))
    return requirements, evidence_rows, requirements_sha, evidence_sha


def snapshot_document(workbook_data: bytes) -> dict[str, Any]:
    requirements, evidence_rows, requirements_sha, evidence_sha = parse_workbook(workbook_data)
    return {
        "evidence": {
            "rows": len(evidence_rows),
            "sha256": evidence_sha,
        },
        "gates": [
            {
                "dependencies": list(row.dependencies),
                "evidenceSha256": digest(row.evidence.encode("utf-8")),
                "id": row.identifier,
                "status": row.status,
            }
            for row in requirements
        ],
        "recordType": "local-sandbox-qualification-snapshot",
        "requirements": {
            "rows": len(requirements),
            "sha256": requirements_sha,
        },
        "schemaVersion": 1,
        "version": VERSION,
        "workbook": {
            "path": CANONICAL_TRACKER_PATH.as_posix(),
            "sha256": digest(workbook_data),
        },
    }


def build_snapshot(workbook_data: bytes) -> bytes:
    return canonical_json(snapshot_document(workbook_data), pretty=True)


def verify_tracker_bundle(workbook_data: bytes, snapshot_data: bytes) -> TrackerBundle:
    expected_snapshot = build_snapshot(workbook_data)
    parse_json(snapshot_data, CANONICAL_SNAPSHOT_PATH.as_posix())
    if snapshot_data != expected_snapshot:
        fail("Qualification snapshot is stale, altered, or not in deterministic canonical form")
    document = snapshot_document(workbook_data)
    requirements, evidence_rows, requirements_sha, evidence_sha = parse_workbook(workbook_data)
    return TrackerBundle(
        workbook_sha256=document["workbook"]["sha256"],
        snapshot_sha256=digest(snapshot_data),
        requirements_sha256=requirements_sha,
        evidence_sha256=evidence_sha,
        requirements=requirements,
        evidence_rows=evidence_rows,
    )


def verify_binding(value: Any, bundle: TrackerBundle, label: str) -> None:
    if not isinstance(value, dict) or value != bundle.binding():
        fail(f"{label} does not exactly match the recomputed tracker and snapshot binding")


def verify_readiness_gates(value: Any, bundle: TrackerBundle, label: str) -> None:
    if value != bundle.gates():
        fail(f"{label} gate status or evidence does not exactly match the tracker snapshot")


def assert_profile(bundle: TrackerBundle, profile: str) -> None:
    if profile == "apple":
        pending = APPLE_PENDING
        action = "REL-03"
    elif profile == "github":
        pending = GITHUB_PENDING
        action = "REL-06"
    else:
        raise ValueError(f"Unknown readiness profile: {profile}")
    for row in bundle.requirements:
        if not row.evidence.strip():
            fail(f"{profile} readiness requires exact nonempty tracker evidence for {row.identifier}")
        concrete_proof(row.evidence, row.identifier)
        if row.identifier not in pending:
            if row.status != "PASS":
                fail(f"{profile} readiness requires {row.identifier} to be PASS")
        elif row.identifier == action:
            if row.status == "PASS":
                fail(f"{action} cannot be pre-passed; its external action must complete it")
            if row.status != "IN PROGRESS":
                fail(f"{profile} readiness requires {action} to be IN PROGRESS")
        elif row.status not in {"IN PROGRESS", "NOT STARTED"}:
            fail(f"{profile} readiness requires {row.identifier} to remain open")


def read_exact_checks(root: Path) -> tuple[str, ...]:
    data, _mode = read_external_regular(root / "scripts/release/verification-checks.json")
    document = json.loads(data)
    if (
        not isinstance(document, list)
        or len(document) != 41
        or len(document) != len(set(document))
        or any(not isinstance(item, str) or not item for item in document)
    ):
        fail("Full verification check contract must contain exactly 41 unique labels")
    return tuple(document)


def export_readiness(
    *,
    profile: str,
    bundle: TrackerBundle,
    root: Path,
    commit: str,
    ready_at: str,
) -> bytes:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        fail("--expected-commit must be one full lowercase Git commit SHA")
    try:
        ready = datetime.fromisoformat(ready_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise TrackerError("--ready-at must be an ISO 8601 timestamp") from error
    if ready.tzinfo is None or ready.utcoffset() is None:
        fail("--ready-at must include a UTC offset")
    ready = ready.astimezone(timezone.utc)
    ready_at = ready.isoformat().replace("+00:00", "Z")
    assert_profile(bundle, profile)
    validation_data, _mode = read_external_regular(root / VALIDATION_PATH)
    validation = parse_json(validation_data, VALIDATION_PATH.as_posix())
    expected_checks = read_exact_checks(root)
    automated = validation.get("automatedVerification")
    if not isinstance(automated, dict):
        fail("docs/validation.json has no automatedVerification object")
    checks = automated.get("checks")
    if (
        validation.get("recordType") != "local-sandbox-release-validation"
        or validation.get("schemaVersion") != 1
        or validation.get("version") != VERSION
        or automated.get("status") != "passed"
        or not isinstance(checks, list)
        or tuple(
            item.get("label") for item in checks
            if isinstance(item, dict) and item.get("status") == "passed"
        ) != expected_checks
        or len(checks) != len(expected_checks)
    ):
        fail("docs/validation.json is not an exact passed 41-stage full verification record")
    if TRACKER_CHECK_LABEL not in expected_checks:
        fail("Full verification contract has no qualification tracker stage")
    tracker_check = checks[expected_checks.index(TRACKER_CHECK_LABEL)]
    verify_binding(
        tracker_check.get("tracker") if isinstance(tracker_check, dict) else None,
        bundle,
        "docs/validation.json tracker check",
    )
    generated_at = validation.get("generatedAt")
    if not isinstance(generated_at, str):
        fail("docs/validation.json has no generatedAt timestamp")
    try:
        generated = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise TrackerError("docs/validation.json generatedAt is not ISO 8601") from error
    if generated.tzinfo is None or generated.utcoffset() is None:
        fail("docs/validation.json generatedAt must include a UTC offset")
    if ready < generated.astimezone(timezone.utc):
        fail("--ready-at predates docs/validation.json")
    claimed_candidate_digest = validation.get("candidateDigest")
    if (
        not isinstance(claimed_candidate_digest, str)
        or SHA256_PATTERN.fullmatch(claimed_candidate_digest) is None
    ):
        fail("docs/validation.json has no valid candidateDigest")
    try:
        current_candidate_digest = candidate_digest(root)
    except CandidateDigestError as error:
        raise TrackerError(f"Could not recompute the release candidate digest: {error}") from error
    if claimed_candidate_digest != current_candidate_digest:
        fail("docs/validation.json candidateDigest does not match the current release candidate")
    artifacts = []
    for relative in ARTIFACT_PATHS:
        data, _mode = read_external_regular(root / relative)
        artifacts.append({"bytes": len(data), "path": relative.as_posix(), "sha256": digest(data)})
    common: dict[str, Any] = {
        "artifacts": artifacts,
        "commit": commit,
        "completionPercent": APPLE_PERCENT if profile == "apple" else GITHUB_PERCENT,
        "gates": bundle.gates(),
        "passedGates": 53 if profile == "apple" else 56,
        "readyAt": ready_at,
        "releaseState": "READY",
        "schemaVersion": 1,
        "totalGates": len(EXPECTED_GATE_IDS),
        "tracker": bundle.binding(),
        "verification": {
            "automatedStatus": "passed",
            "candidateDigest": current_candidate_digest,
            "commit": commit,
            "path": VALIDATION_PATH.as_posix(),
            "sha256": digest(validation_data),
        },
        "version": VERSION,
    }
    if profile == "apple":
        common["recordType"] = "local-sandbox-apple-action-readiness"
        common["xcode"] = {"build": "27A266a", "version": "27.0"}
    else:
        common["recordType"] = "local-sandbox-github-action-readiness"
        common["tag"] = TAG
    return canonical_json(common, pretty=True)


def git_bytes(root: Path, arguments: Sequence[str]) -> bytes:
    import subprocess

    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        raise TrackerError(f"Could not run Git: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        fail(f"Git command failed: {detail or f'exit {result.returncode}'}")
    return result.stdout


def verify_export_commit(root: Path, commit: str) -> None:
    head = git_bytes(root, ["rev-parse", "--verify", "HEAD^{commit}"]).decode().strip()
    if head != commit:
        fail("--expected-commit must equal the current Git HEAD")
    status = git_bytes(root, ["status", "--porcelain=v1", "--untracked-files=all"])
    if status:
        fail("Readiness export requires a clean committed worktree")
    for relative in (
        CANONICAL_TRACKER_PATH,
        CANONICAL_SNAPSHOT_PATH,
        VALIDATION_PATH,
        *ARTIFACT_PATHS,
    ):
        current, _mode = read_external_regular(root / relative)
        committed = git_bytes(root, ["show", f"{commit}:{relative.as_posix()}"])
        if current != committed:
            fail(f"{relative} differs from --expected-commit")


def verify_tracker_commit(root: Path) -> str:
    commit = git_bytes(root, ["rev-parse", "--verify", "HEAD^{commit}"]).decode().strip()
    for relative in (CANONICAL_TRACKER_PATH, CANONICAL_SNAPSHOT_PATH):
        current, _mode = read_external_regular(root / relative)
        committed = git_bytes(root, ["show", f"{commit}:{relative.as_posix()}"])
        if current != committed:
            fail(f"{relative} differs from committed HEAD")
    return commit


def read_bundle_paths(tracker: Path, snapshot: Path) -> TrackerBundle:
    workbook_data, _mode = read_external_regular(tracker)
    snapshot_data, _mode = read_external_regular(snapshot)
    return verify_tracker_bundle(workbook_data, snapshot_data)


def canonical_path(root: Path, supplied: Path, canonical: PurePosixPath, label: str) -> Path:
    expected = root / canonical
    actual = supplied if supplied.is_absolute() else root / supplied
    if Path(os.path.abspath(actual)) != Path(os.path.abspath(expected)):
        fail(f"{label} must be {canonical.as_posix()}")
    return expected


def atomic_write(destination: Path, data: bytes) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        fail(f"Refusing to replace symlink: {destination}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def summary(bundle: TrackerBundle) -> dict[str, Any]:
    return {
        "binding": bundle.binding(),
        "evidenceRows": len(bundle.evidence_rows),
        "finalQualificationClaimed": False,
        "gates": bundle.gates(),
        "requirementsRows": len(bundle.requirements),
        "status": "tracker-snapshot-verified",
    }


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="verify canonical workbook and snapshot")
    verify.add_argument("--root", type=Path, default=ROOT)
    verify.add_argument("--tracker", type=Path, default=Path(CANONICAL_TRACKER_PATH))
    verify.add_argument("--snapshot", type=Path, default=Path(CANONICAL_SNAPSHOT_PATH))
    subparsers.add_parser("verify-envelope", help="verify base64 workbook/snapshot JSON from stdin")
    snapshot = subparsers.add_parser("snapshot", help="write a deterministic sanitized snapshot")
    snapshot.add_argument("--root", type=Path, default=ROOT)
    snapshot.add_argument("--tracker", type=Path, required=True)
    snapshot.add_argument("--output", type=Path, default=Path(CANONICAL_SNAPSHOT_PATH))
    export = subparsers.add_parser("export-readiness", help="export exact Apple or GitHub readiness")
    export.add_argument("--root", type=Path, default=ROOT)
    export.add_argument("--profile", choices=("apple", "github"), required=True)
    export.add_argument("--tracker", type=Path, required=True)
    export.add_argument("--snapshot", type=Path, default=Path(CANONICAL_SNAPSHOT_PATH))
    export.add_argument("--expected-commit", required=True)
    export.add_argument("--ready-at", required=True)
    export.add_argument("--output", type=Path)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = parse_arguments(arguments)
        if options.command == "verify-envelope":
            envelope_data = sys.stdin.buffer.read(16_000_000)
            envelope = parse_json(envelope_data, "tracker verification envelope")
            if set(envelope) != {"snapshot", "workbook"}:
                fail("Tracker verification envelope has missing or unexpected fields")
            try:
                workbook_data = base64.b64decode(envelope["workbook"], validate=True)
                snapshot_data = base64.b64decode(envelope["snapshot"], validate=True)
            except (TypeError, ValueError) as error:
                raise TrackerError("Tracker verification envelope is not canonical base64") from error
            bundle = verify_tracker_bundle(workbook_data, snapshot_data)
            sys.stdout.buffer.write(canonical_json(summary(bundle)))
            return 0

        root = options.root.absolute()
        tracker = canonical_path(root, options.tracker, CANONICAL_TRACKER_PATH, "--tracker")
        if options.command == "snapshot":
            workbook_data, _mode = read_external_regular(tracker)
            output = canonical_path(root, options.output, CANONICAL_SNAPSHOT_PATH, "--output")
            atomic_write(output, build_snapshot(workbook_data))
            print(json.dumps({"snapshot": CANONICAL_SNAPSHOT_PATH.as_posix(), "status": "written"}))
            return 0

        snapshot_path = canonical_path(
            root, options.snapshot, CANONICAL_SNAPSHOT_PATH, "--snapshot"
        )
        bundle = read_bundle_paths(tracker, snapshot_path)
        if options.command == "verify":
            verified = summary(bundle)
            verified["commit"] = verify_tracker_commit(root)
            sys.stdout.buffer.write(canonical_json(verified))
            return 0
        verify_export_commit(root, options.expected_commit)
        readiness = export_readiness(
            profile=options.profile,
            bundle=bundle,
            root=root,
            commit=options.expected_commit,
            ready_at=options.ready_at,
        )
        if options.output is None:
            sys.stdout.buffer.write(readiness)
        else:
            atomic_write(options.output.absolute(), readiness)
            print(json.dumps({"output": os.fspath(options.output), "status": "written"}))
        return 0
    except (OSError, TrackerError, ValueError, zipfile.BadZipFile) as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
