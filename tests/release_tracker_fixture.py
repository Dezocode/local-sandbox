"""Deterministic OOXML fixtures for qualification tracker release tests."""

from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
from html import escape
from io import BytesIO
from pathlib import Path
import sys
from typing import Mapping, Sequence
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE_ROOT / "scripts"))

from release.tracker import (  # noqa: E402
    EVIDENCE_COLUMNS,
    EXPECTED_DEPENDENCY_TEXT,
    EXPECTED_GATE_IDS,
    EXPECTED_PHASE_BY_GATE,
    PHASES,
    REQUIREMENT_COLUMNS,
    build_snapshot,
)


def xml_text(value: str) -> str:
    return escape(value, quote=False)


def string_cell(reference: str, value: str) -> str:
    preserve = ' xml:space="preserve"' if value != value.strip() else ""
    return (
        f'<c r="{reference}" t="inlineStr"><is><t{preserve}>'
        f"{xml_text(value)}</t></is></c>"
    )


def number_cell(reference: str, value: int | Decimal | str) -> str:
    return f'<c r="{reference}" t="n"><v>{value}</v></c>'


def formula_cell(reference: str, formula: str, value: str, *, text: bool = False) -> str:
    kind = ' t="str"' if text else ' t="n"'
    return (
        f'<c r="{reference}"{kind}><f>{xml_text(formula)}</f>'
        f"<v>{xml_text(value)}</v></c>"
    )


def worksheet(rows: Sequence[tuple[int, Sequence[str]]]) -> bytes:
    body = "".join(
        f'<row r="{number}">{"".join(cells)}</row>' for number, cells in rows
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheetData>{body}</sheetData></worksheet>"
    ).encode()


def dashboard_rows(statuses: Mapping[str, str]) -> list[tuple[int, list[str]]]:
    evidence = {identifier: proof(identifier) for identifier in EXPECTED_GATE_IDS}
    passed = sum(
        statuses[identifier] == "PASS" and bool(evidence[identifier])
        for identifier in EXPECTED_GATE_IDS
    )
    completion = Decimal(passed) / Decimal(57)
    rows: dict[int, list[str]] = {
        2: [string_cell("A2", "Local Sandbox 0.3 release tracker")],
        4: [string_cell("A4", "Target version"), string_cell("B4", "0.3")],
        5: [string_cell("A5", "Source provenance"), string_cell("B5", "a" * 40)],
        6: [
            string_cell("A6", "Qualification"),
            formula_cell(
                "B6",
                'IF(AND(COUNTA(Requirements!$A$6:$A$62)=57,COUNTIFS(Requirements!$F$6:$F$62,"PASS")=57,COUNTIFS(Requirements!$F$6:$F$62,"PASS",Requirements!$I$6:$I$62,"<>")=57),"FULL 0.3 QUALIFIED","NOT QUALIFIED")',
                "FULL 0.3 QUALIFIED" if passed == 57 else "NOT QUALIFIED",
                text=True,
            ),
        ],
        7: [
            string_cell("A7", "Completion"),
            formula_cell(
                "B7",
                'IF(COUNTA(Requirements!$A$6:$A$62)<>57,0,COUNTIFS(Requirements!$F$6:$F$62,"PASS",Requirements!$I$6:$I$62,"<>")/57)',
                str(completion),
            ),
        ],
        9: [string_cell("A9", "Done bar")],
        12: [
            string_cell("A12", "Measure"), string_cell("B12", "Count"),
            string_cell("D12", "Phase"), string_cell("E12", "Total"),
            string_cell("F12", "PASS"), string_cell("G12", "Active"),
            string_cell("H12", "Blocked/Fail"), string_cell("I12", "Completion"),
            string_cell("J12", "Gate"),
        ],
    }
    for index in range(20):
        column = chr(ord("B") + index)
        threshold = Decimal(index + 1) / Decimal(20)
        formula_threshold = format(threshold, "f").rstrip("0").rstrip(".")
        rows[9].append(formula_cell(
            f"{column}9",
            f"IF($B$7>={formula_threshold},1,0)",
            "1" if completion >= threshold else "0",
        ))
    summary = {
        13: ("Total requirements", 57, None),
        14: ("PASS + evidence", passed, None),
        15: ("IN PROGRESS", sum(value == "IN PROGRESS" for value in statuses.values()), None),
        16: ("BLOCKED or FAIL", sum(value in {"BLOCKED", "FAIL"} for value in statuses.values()), None),
        17: ("NOT STARTED", sum(value == "NOT STARTED" for value in statuses.values()), None),
    }
    summary_formulas = {
        13: "COUNTA(Requirements!$A$6:$A$62)",
        14: 'COUNTIFS(Requirements!$F$6:$F$62,"PASS",Requirements!$I$6:$I$62,"<>")',
        15: 'COUNTIFS(Requirements!$F$6:$F$62,"IN PROGRESS")',
        16: 'COUNTIFS(Requirements!$F$6:$F$62,"BLOCKED")+COUNTIFS(Requirements!$F$6:$F$62,"FAIL")',
        17: 'COUNTIFS(Requirements!$F$6:$F$62,"NOT STARTED")',
    }
    for row_number, (label, value, _unused) in summary.items():
        rows.setdefault(row_number, []).extend([
            string_cell(f"A{row_number}", label),
            formula_cell(f"B{row_number}", summary_formulas[row_number], str(value)),
        ])
    for row_number, phase in enumerate(PHASES, start=13):
        phase_ids = [identifier for identifier in EXPECTED_GATE_IDS if EXPECTED_PHASE_BY_GATE[identifier] == phase]
        total = len(phase_ids)
        phase_passed = sum(statuses[identifier] == "PASS" for identifier in phase_ids)
        active = sum(statuses[identifier] == "IN PROGRESS" for identifier in phase_ids)
        blocked = sum(statuses[identifier] in {"BLOCKED", "FAIL"} for identifier in phase_ids)
        phase_completion = Decimal(phase_passed) / Decimal(total) if total else Decimal(0)
        gate = "OPEN" if total == 0 else "PASS" if phase_passed == total else "BLOCKED" if blocked else "OPEN"
        rows.setdefault(row_number, []).extend([
            string_cell(f"D{row_number}", phase),
            formula_cell(f"E{row_number}", f"COUNTIFS(Requirements!$B$6:$B$62,$D{row_number})", str(total)),
            formula_cell(f"F{row_number}", f'COUNTIFS(Requirements!$B$6:$B$62,$D{row_number},Requirements!$F$6:$F$62,"PASS",Requirements!$I$6:$I$62,"<>")', str(phase_passed)),
            formula_cell(f"G{row_number}", f'COUNTIFS(Requirements!$B$6:$B$62,$D{row_number},Requirements!$F$6:$F$62,"IN PROGRESS")', str(active)),
            formula_cell(f"H{row_number}", f'COUNTIFS(Requirements!$B$6:$B$62,$D{row_number},Requirements!$F$6:$F$62,"BLOCKED")+COUNTIFS(Requirements!$B$6:$B$62,$D{row_number},Requirements!$F$6:$F$62,"FAIL")', str(blocked)),
            formula_cell(f"I{row_number}", f"IF(E{row_number}=0,0,F{row_number}/E{row_number})", str(phase_completion)),
            formula_cell(f"J{row_number}", f'IF(E{row_number}=0,"OPEN",IF(F{row_number}=E{row_number},"PASS",IF(H{row_number}>0,"BLOCKED","OPEN")))', gate, text=True),
        ])
    return sorted(rows.items())


def proof(identifier: str) -> str:
    result = sha256(identifier.encode()).hexdigest()
    return f"tests/{identifier}.test.py 1/1 PASS; SHA-256 {result}"


# Exact test preimage for the hardcoded 0.3 immutable-contract digest. Never derive it
# from the workbook under test, or weakened release text could become a new fixture.
CANONICAL_REQUIREMENT_TEXT = {'GOV-01': ('Audit the complete 0.3 installation book',
            'All 22 pages inspected; every release gate and page 17 gap is represented in this '
            'tracker.',
            'PDF pp. 1-22'),
 'SRC-01': ('Retrieve the exact source archive',
            'Archive opens and contains ios, scripts, public, and docs; provenance matches '
            '14ca3564528816d591410b28a504b998994bea30.',
            'PDF pp. 3, 22'),
 'SRC-02': ('Identify the authoritative GitHub repository',
            'Remote owner/repo is recorded and its current remote head is inspected before edits.',
            'PDF p. 15'),
 'SRC-03': ('Create an isolated 0.3 working branch',
            'Branch starts from verified source provenance and preserves the source snapshot.',
            'PDF pp. 3, 15'),
 'VER-01': ('Set all marketing/package versions to 0.3',
            'Native marketing version, web metadata, package catalog, docs, and release notes '
            'agree on 0.3 or 0.3.0 as appropriate.',
            'PDF pp. 12, 18, 22'),
 'ENV-00': ('Verify host architecture and working capacity',
            'Apple-silicon Mac is available with enough disk for Xcode and an iOS runtime.',
            'PDF p. 4'),
 'ENV-01': ('Install full Xcode and required iOS platform',
            'xcodebuild works; Xcode SDK supports the actual target phone OS, including iOS 27 on '
            'iPhone 18 Pro Max; first-launch components are complete.',
            'PDF p. 4'),
 'ENV-02': ('Install and boot a compatible iPhone simulator',
            'simctl lists the runtime and the project test target passes on the selected '
            'simulator.',
            'PDF p. 5'),
 'ENV-03': ('Pair the physical iPhone',
            'Unlocked iPhone is trusted, Developer Mode is enabled, and devicectl lists it as '
            'available.',
            'PDF pp. 4-5'),
 'ENV-04': ('Configure Apple development signing',
            'A valid development identity, team, unique bundle ID, profile, and Sign in with '
            'Apple entitlement are active.',
            'PDF pp. 3-6'),
 'BASE-01': ('Reproduce and extend the automated test baseline',
             'The canonical verifier passes every retained baseline test plus the 0.3 security, '
             'auth, sync, autosave, native, packaging, and regression contracts.',
             'PDF p. 22'),
 'BASE-02': ('Inventory current features and supported workflows',
             'Feature map covers native, web, local vault, provider dispatch, sync, packages, '
             'hosting, and release scripts.',
             'PDF pp. 1-19'),
 'BASE-03': ('Add a repeatable release verification script',
             'One deterministic command exercises tests, builds, version checks, package checks, '
             'and required security invariants.',
             'Release proof requirement'),
 'NAT-01': ('Build and launch the native app',
            'Signed build opens without crashing on simulator and physical iPhone.',
            'PDF pp. 4-5'),
 'NAT-02': ('Complete real Sign in with Apple',
            'Real login succeeds; server/client token handling rejects invalid, expired, '
            'replayed, and revoked credentials.',
            'PDF pp. 6, 17'),
 'NAT-03': ('Prepare an isolated app-owned workspace',
            "config, workspace, state, logs, and output exist under the signed-in user's "
            'protected root without overwriting existing files.',
            'PDF p. 6'),
 'NAT-04': ('Protect files and credentials',
            'Native files use complete file protection; credentials use Keychain; another Apple '
            'user cannot inherit access.',
            'PDF p. 6'),
 'NAT-05': ('Require Face ID or passcode on re-entry',
            'Lock now, background/reopen, and relaunch hide protected UI until '
            'LocalAuthentication succeeds.',
            'PDF p. 6'),
 'NAT-06': ('Persist exact local file edits',
            'A harmless edit survives close/relaunch with identical bytes after unlock.',
            'PDF p. 6'),
 'PROV-01': ('Qualify the Locally provider adapter',
             'On the target phone, record the exact installed Locally app version and '
             "text-returning action. That exact configured action, using Locally's own session, "
             'must return each closed-v1 raw JSON challenge through Begin Provider Check and '
             "Record Provider Check. During live acceptance, visibly show the provider's "
             'signed-out state and verify that Shortcuts yields no valid closed response. '
             'Missing-action, unavailable, invalid-response, replay, provider-mismatch, and '
             'cloud-disabled cases must stop without fallback or file mutation. Local Sandbox '
             "validates returned challenge text; it does not introspect Locally's login, model, "
             'action inventory, or response provenance.',
             'PDF p. 7; user clarification'),
 'PROV-02': ('Qualify ChatGPT subscription handoff',
             'On the target phone, record the exact installed ChatGPT app version and '
             "text-returning action. That exact configured action, using ChatGPT's own signed-in "
             'session rather than an API key, must return each closed-v1 raw JSON challenge and '
             'record both handoff directions without credentials. During live acceptance, visibly '
             "show the provider's signed-out state and verify that Shortcuts yields no valid "
             'closed response. Missing-action, unavailable, invalid-response, replay, '
             'provider-mismatch, and cloud-disabled cases must stop without fallback or file '
             'mutation. Local Sandbox validates returned challenge text; it does not introspect '
             "ChatGPT's login, model, action inventory, or response provenance.",
             'PDF p. 8; user clarification'),
 'PROV-03': ('Qualify Grok, Grokbot, and Claude handoffs',
             'For Grok, Grokbot, and Claude separately, record the exact installed '
             "app/action/version and complete the closed-v1 raw JSON challenge through that app's "
             'own session. Each exact adapter must record outbound and return hashes. During live '
             "acceptance, visibly show each provider's signed-out state and verify that Shortcuts "
             'yields no valid closed response. Missing-action, unavailable, invalid-response, '
             'replay, provider-mismatch, and cloud-disabled cases must stop without fallback or '
             'file mutation. Local Sandbox validates returned challenge text; it does not '
             "introspect another app's login, model, action inventory, or response provenance.",
             'PDF p. 8; user clarification'),
 'PROV-04': ('Detect, qualify, and deterministically select local Apple/Locally capability',
             'devicectl identifies the exact iPhone 18 Pro Max and OS. Apple Foundation Models '
             'completes the same five fixed probes and one bounded task directly, online and in '
             'Airplane Mode, only while SystemLanguageModel reports available. A protected '
             'device-local HMAC ledger retains at most 240 total attempts, scores the freshest 20 '
             'completed attempts per provider and epoch within seven days, permits at most one '
             'attempt per provider/probe/UTC day, and invalidates on device, full OS '
             'major/minor/patch plus build descriptor, app version/build, suite, adapter '
             'fingerprint, or Apple-availability epoch change. Every runnable route, including '
             'direct Apple, requires all five probe types, at least five samples, at least 80% '
             'local schema-validation reliability, at least 80% exact-assertion quality, all '
             'three tool probes, sufficient tested context, zero integrity faults, and, for an '
             'external Siri route, an observed App Intent return for every probe plus live '
             'physical-device proof of unattended operation. As soon as either Apple or Locally '
             'has comparable evidence, Best local ranks only comparable task-qualified candidates '
             'by schema reliability and assertion quality. It compares 500 ms duration buckets '
             'only between candidates using the same transport class: external App Intent or '
             'Shortcut round trips compare only with external round trips. Apple in-process model '
             'time is recorded separately and is never compared with an external handoff. '
             'Incomparable timing uses the fixed Apple-first tie-break. If no comparable '
             'candidate qualifies, routing blocks. Best local never selects cloud. Saved and '
             'explicit selections never substitute. Current app-owned activity, authorization, '
             'device/configuration/qualification digests, and Oracle pin are revalidated at every '
             'continuation; any change stops for a new task rather than switching. A lower device '
             'that runs the iOS 26 app and Shortcuts retains all iOS 26 native actions and can '
             'use a qualified Locally or exact configured provider route.',
             'PDF pp. 8, 16; user clarification'),
 'PROV-05': ('Expose native Siri App Shortcuts and user-reviewed provider wrappers',
             "On a clean signed installation, Siri and Shortcuts discover Local Sandbox's nine "
             'iOS 26 native App Shortcuts, the tenth iOS 27 long-run action, and all eight '
             'provider values: Saved, Best local, Apple Intelligence, Locally, ChatGPT, Grok, '
             'Grokbot, and Claude. Installation registers the native actions. After explicit '
             'Apple sign-in, protected-folder selection, and successful Prepare Workspace, the '
             'app verifies or creates the HMAC ledger and refreshes App Shortcut parameters. '
             'Begin Provider Check, Record Provider Check, Qualify Apple Intelligence, and Apply '
             'Oracle Recommendation provide measured setup. A personal provider Shortcut, whether '
             'user-created or Apple-Intelligence-assisted, must still be visibly reviewed and '
             "saved in Apple's UI. Its exact flow is Run or Begin → Get Dictionary from Input → "
             'send only payload to the exact qualified provider action → pass its raw returned '
             'JSON text to Apply Validated Action → repeat only while phase is awaiting_response '
             '→ retain or deliberately import the terminal receipt. Provider authentication and '
             'permissions stay in the provider app. Local Sandbox stores bounded adapter metadata '
             'only; it never receives credentials, detects provider login/model activity, '
             'silently installs a personal workflow, or stores arbitrary executable Shortcut '
             'content.',
             'PDF p. 8; user clarification'),
 'PROV-06': ('Enforce explicit device-local resource authorization',
             'Defaults are 6 steps, 15% battery drop, 20% reserve, 35% app memory, and 6,000 '
             'prompt characters. Cloud handoff, clipboard read, and clipboard write each require '
             'device-local Save authorization; both clipboard permissions default false, '
             'workspace config cannot grant them, and every denial is visible.',
             'PDF pp. 8, 16'),
 'RUN-01': ('Run the deterministic native Siri/Shortcut loop',
            'On the target phone, complete one Siri-started exact-readback sandbox task through '
            'direct Apple and through every provider route qualified in PROV-01 through PROV-05. '
            'Before the first side effect and at every continuation, the app re-resolves the '
            'exact saved authorization, requested selection, resolved provider, strategy, '
            'app-owned activity gate, access evidence, device/configuration/qualification '
            'digests, sample and distinct-probe counts, schema reliability, assertion quality, '
            'observed App Intent handoff elapsed bucket, tested context, tool qualification, '
            'observed-App-Intent-return qualification, integrity faults, and current Oracle pin. '
            'A mismatch stops for a new task; no route substitutes or switches. For an external '
            'Siri route, live physical-device proof must separately establish unattended return '
            'and the intended provider/action/model path. The external flow is Run or Begin → Get '
            'Dictionary from Input → payload only to the exact provider action → raw returned '
            'JSON text to Apply Validated Action → repeat only while phase is awaiting_response → '
            'retain or deliberately import the terminal receipt. Mutations remain confined to the '
            'selected workspace. After deliberate terminal-receipt import, the dashboard '
            'validates the configured route and ordered outbound/inbound hashes; it does not '
            'claim live native/provider/model activity or response provenance and shows no '
            'credentials, raw adapter names, prompts, provider output, or copied file/clipboard '
            'contents.',
            'PDF p. 9; user clarification'),
 'RUN-02': ('Prove create, read, hash-guarded patch, and exact readback',
            'A disposable workspace file changes from Status: pending to Status: verified through '
            'create-only, complete read, SHA-256 base-guarded patch, and independent exact '
            'post-write readback.',
            'PDF p. 10'),
 'RUN-03': ('Reject path traversal and overwrite attempts',
            'Outside-workspace paths, symlink escapes, and duplicate creates are rejected without '
            'disclosing or replacing bytes.',
            'PDF p. 11'),
 'RUN-04': ('Reject stale and ambiguous patches',
            'A stale base hash or duplicated old text is rejected; no arbitrary write occurs and '
            'exact bytes remain unchanged.',
            'PDF p. 11'),
 'RUN-05': ('Recover checkpoints without blind replay',
            'Completed actions resume without replay; an uncertain write requires journal and '
            'fresh file inspection before any retry.',
            'PDF pp. 11, 16'),
 'RUN-06': ('Count distinct malformed responses correctly',
            'Receipt step and failure counts match distinct response hashes and never overcount a '
            'repeated cached response.',
            'PDF p. 11'),
 'PKG-01': ('Export real tested Shortcut packages',
            'Private exports match recipe names and include only qualified provider dependencies '
            'plus the runner.',
            'PDF p. 12'),
 'PKG-02': ('Sign and publish an immutable 0.3.0 catalog',
            'public/shortcuts/0.3.0 contains signed packages and catalog hashes/sizes; rerun '
            'refuses replacement.',
            'PDF p. 12'),
 'PKG-03': ('Install dependencies and runner on the phone',
            'The catalog rejects missing or cyclic dependencies and presents every dependency '
            "before its runner. The user completes Apple's Add Shortcut and permission prompts in "
            'that order. Starting a runner with an absent dependency stops visibly without '
            'mutation. The complete installed stack then passes a harmless run and exact '
            'readback.',
            'PDF p. 12; platform boundary'),
 'PWA-01': ('Install the local workspace as a Home Screen app',
            'Home Screen mode is detected on launch and browser mode remains distinct.',
            'PDF p. 13'),
 'PWA-02': ('Verify encrypted vault persistence and recovery',
            '12+ character vault, lock/reopen, wrong-password rejection, encrypted backup, and '
            'exact restore pass.',
            'PDF p. 13'),
 'PWA-03': ('Verify offline read and save',
            'After online installation, Airplane Mode relaunch reads an existing file and saves a '
            'second local file.',
            'PDF p. 13'),
 'PWA-04': ('Produce and test the self-host bundle',
            'Pinned Caddy image serves the app and packages over valid HTTPS without moving vault '
            'data to the server.',
            'PDF p. 14'),
 'AUTH-01': ('Implement the full Apple authentication lifecycle',
             'Web and native Sign in with Apple, deliberate account linking, secure session '
             'refresh, token revocation, official account-change notifications, and '
             'server-account deletion pass. Signature, issuer, audience, time, replay, and '
             'event-order checks fail closed. Deleting a standalone Apple account removes its '
             'owner data; deleting an Apple link from a ChatGPT-owned workspace retains the '
             'workspace and removes Apple access.',
             'PDF p. 17; user full-auth requirement'),
 'SYNC-01': ('Implement one encrypted native/web sync protocol',
             'Stable identity mapping, key management, conflicts, recovery-credential rotation, '
             'explicit unenrollment, hosted-ciphertext deletion, and round-trip edits across '
             'native and web clients pass without claiming full data-key/epoch rotation.',
             'PDF p. 17'),
 'KEY-01': ('Implement Apple-backed encryption recovery',
            'Random data keys, recovery credentials, explicit synchronizable iCloud Keychain '
            'enrollment/removal, crash-safe device re-enrollment, and lost-key behavior are '
            'specified and tested without using Apple IDs or tokens as keys.',
            'PDF p. 17'),
 'AUTOSAVE-01': ('Implement automatic progress saving',
                 'Serialized/debounced saves expose dirty/failure state and pass conflict, crash, '
                 'and reload tests.',
                 'PDF p. 17'),
 'PWA-CONN-01': ('Add GitHub access to the local PWA',
                 'Repository-scoped auth, branch/commit status, compare, publish, stale-head '
                 'rejection, and credential privacy pass in the local client.',
                 'PDF p. 17'),
 'PWA-CONN-02': ('Establish a supported Cursor Origin integration',
                 'The hosted local PWA can show and manually synchronize an approved Origin '
                 'repository mirror without exposing private profile/config files or broad '
                 'repository authority.',
                 'PDF p. 17'),
 'BG-01': ('Implement permitted background execution',
           'Scheduling, expiration, checkpoint/resume, locked-device behavior, and provider '
           'restrictions are explicit and device-qualified.',
           'PDF pp. 16-17'),
 'VERIFY-01': ('Bind completion to goal-specific expected state',
               'A goal cannot be marked verified until its declared changes are independently '
               'read back and compared.',
               'PDF pp. 11, 17'),
 'GH-01': ('Configure repository-scoped GitHub authentication',
           'Fine-grained access is limited to the chosen repo and stored only in Keychain or tab '
           'memory as documented.',
           'PDF p. 15'),
 'GH-02': ('Prove branch compare, publish, worktree pull, and conflict rejection',
           'Synthetic bytes match across app, GitHub, and worktree; stale publication is rejected '
           'without force push.',
           'PDF p. 15'),
 'ICLOUD-01': ('Qualify optional Files/iCloud storage',
               'Dedicated folder persists synthetic content; switching back preserves app-local '
               'files; protection limits are stated accurately.',
               'PDF p. 16'),
 'PRIV-01': ('Protect private config and profile data',
             'Default sync excludes config, profile, state, credentials, private exports, and '
             'signing material.',
             'PDF pp. 14-16'),
 'REL-01': ('Complete all automated and device regression gates',
            'All 50 preceding rows, GOV-01 through PRIV-01, are PASS with nonblank direct '
            'evidence. Any blank, FAIL, BLOCKED, IN PROGRESS, or NOT STARTED status blocks this '
            'pre-release gate.',
            'PDF pp. 1, 20'),
 'REL-02': ('Create App Store Connect metadata and compliance record',
            'Bundle ID, screenshots, URLs, privacy, age rating, export compliance, provider '
            'disclosures, and reviewer instructions are complete and accurate.',
            'PDF p. 18'),
 'REL-03': ('Archive and upload an unused build number',
            'Before archive or upload, the exact 53-row Apple readiness set is PASS: every '
            'requirement except REL-03, REL-04, REL-06, and REL-07. REL-03 then becomes IN '
            'PROGRESS with nonblank action evidence. PASS requires a successful signed archive '
            'and App Store Connect acceptance of that exact unused build number; no secret or .p8 '
            'file enters source or artifacts.',
            'PDF p. 18'),
 'REL-04': ('Qualify the processed TestFlight build',
            'PASS requires App Store Connect to process the exact REL-03 commit/build and the '
            'installed TestFlight binary to repeat the complete identity, protected local '
            'storage, five-probe qualification, deterministic Oracle ranking, direct Apple '
            'online/Airplane Mode, every qualified exact-provider and failure route, automatic '
            'native App Shortcut discovery, user-confirmed personal Shortcut composition, package '
            'dependencies, sandbox confinement, no-mid-run-switch, deliberate terminal-receipt '
            'import, dashboard rendering of the validated route and ordered handoff hashes, and '
            'the exact-readback matrix on the exact target iPhone. The dashboard-import proof is '
            'not live device activity, provider authentication, model-activity, '
            'response-provenance, or cross-app telemetry. No local development build can satisfy '
            'this row.',
            'PDF p. 18; user clarification'),
 'REL-05': ('Configure the GitHub apple-release environment',
            'Variables and secrets are scoped correctly. The workflow enforces the exact 53-row '
            'Apple readiness set before archive or upload, uses a non-colliding build number, '
            'records REL-03 as IN PROGRESS during the action, removes temporary key material, and '
            'never requires TestFlight, GitHub publication, or App Review outcomes before upload.',
            'PDF p. 19'),
 'REL-06': ('Publish the GitHub v0.3 release',
            'Before publication, all other 56 requirement IDs are PASS with nonblank evidence and '
            'REL-06 becomes IN PROGRESS with nonblank preflight evidence. PASS requires remote '
            'readback proving main, tag v0.3.0, the GitHub release, assets, checksums, signed '
            'catalog, install notes, known limitations, exact commit, and artifact hashes all '
            'agree. No local plan or attempted upload counts as publication.',
            'User request'),
 'REL-07': ("Submit for App Review and record Apple's outcome",
            'Submission or Apple processing is IN PROGRESS. PASS is allowed only after Apple '
            'approves the exact REL-04 TestFlight build for App Store release; rejection remains '
            "FAIL or open with Apple's reason recorded. TestFlight, submission, processing, and "
            'approval stay separate outcomes.',
            'PDF pp. 18, 20')}


def build_workbook(
    *,
    statuses: Mapping[str, str] | None = None,
    order: Sequence[str] = EXPECTED_GATE_IDS,
    evidence_overrides: Mapping[str, str] | None = None,
    note_overrides: Mapping[str, str] | None = None,
    requirement_overrides: Mapping[str, str] | None = None,
    acceptance_overrides: Mapping[str, str] | None = None,
    source_overrides: Mapping[str, str] | None = None,
) -> bytes:
    resolved_statuses = {identifier: "PASS" for identifier in EXPECTED_GATE_IDS}
    if statuses:
        resolved_statuses.update(statuses)
    evidence_overrides = evidence_overrides or {}
    note_overrides = note_overrides or {}
    requirement_overrides = requirement_overrides or {}
    acceptance_overrides = acceptance_overrides or {}
    source_overrides = source_overrides or {}

    requirement_rows: list[tuple[int, list[str]]] = [(5, [
        string_cell(f"{chr(65 + index)}5", value)
        for index, value in enumerate(REQUIREMENT_COLUMNS)
    ])]
    for row_number, identifier in enumerate(order, start=6):
        requirement, acceptance, source = CANONICAL_REQUIREMENT_TEXT[identifier]
        evidence = evidence_overrides.get(identifier, proof(identifier))
        values = (
            identifier,
            EXPECTED_PHASE_BY_GATE[identifier],
            requirement_overrides.get(identifier, requirement),
            acceptance_overrides.get(identifier, acceptance),
            source_overrides.get(identifier, source),
            resolved_statuses[identifier],
            "Release owner",
            EXPECTED_DEPENDENCY_TEXT[identifier],
            evidence,
            f"Preserve the exact {identifier} release boundary",
            "2026-09-11T16:00:00Z",
        )
        requirement_rows.append((row_number, [
            string_cell(f"{chr(65 + index)}{row_number}", value)
            for index, value in enumerate(values)
        ]))

    evidence_rows: list[tuple[int, list[str]]] = [(5, [
        string_cell(f"{chr(65 + index)}5", value)
        for index, value in enumerate(EVIDENCE_COLUMNS)
    ])]
    for row_number, identifier in enumerate(EXPECTED_GATE_IDS, start=6):
        result = resolved_statuses[identifier]
        evidence = evidence_overrides.get(identifier, proof(identifier))
        values = (
            "2026-09-11T16:00:00Z",
            identifier,
            "Deterministic test fixture",
            f"Run {identifier} contract",
            result,
            evidence,
            note_overrides.get(identifier, f"Exact fixture evidence for {identifier} at build 27A266a"),
        )
        evidence_rows.append((row_number, [
            string_cell(f"{chr(65 + index)}{row_number}", value)
            for index, value in enumerate(values)
        ]))

    relationship_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    parts = {
        "[Content_Types].xml": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
            '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
            '<Override PartName="/xl/tables/table1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml"/>'
            '<Override PartName="/xl/tables/table2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml"/>'
            '</Types>'
        ).encode(),
        "_rels/.rels": (
            f'<Relationships xmlns="{relationship_ns}">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="/xl/workbook.xml"/>'
            '</Relationships>'
        ).encode(),
        "xl/workbook.xml": (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Release status" sheetId="1" r:id="rId1"/>'
            '<sheet name="Requirements" sheetId="2" r:id="rId2"/>'
            '<sheet name="Evidence" sheetId="3" r:id="rId3"/></sheets></workbook>'
        ).encode(),
        "xl/_rels/workbook.xml.rels": (
            f'<Relationships xmlns="{relationship_ns}">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="/xl/worksheets/sheet1.xml"/>'
            '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="/xl/worksheets/sheet2.xml"/>'
            '<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="/xl/worksheets/sheet3.xml"/>'
            '<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="/xl/styles.xml"/>'
            '<Relationship Id="rId5" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="/xl/sharedStrings.xml"/>'
            '</Relationships>'
        ).encode(),
        "xl/styles.xml": b'<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="1"><font/></fonts><fills count="1"><fill/></fills><borders count="1"><border/></borders><cellXfs count="1"><xf/></cellXfs></styleSheet>',
        "xl/sharedStrings.xml": b'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="0" uniqueCount="0"/>',
        "xl/worksheets/sheet1.xml": worksheet(dashboard_rows(resolved_statuses)),
        "xl/worksheets/sheet2.xml": worksheet(requirement_rows),
        "xl/worksheets/sheet3.xml": worksheet(evidence_rows),
        "xl/worksheets/_rels/sheet2.xml.rels": (
            f'<Relationships xmlns="{relationship_ns}"><Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/table" '
            'Target="/xl/tables/table1.xml"/></Relationships>'
        ).encode(),
        "xl/worksheets/_rels/sheet3.xml.rels": (
            f'<Relationships xmlns="{relationship_ns}"><Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/table" '
            'Target="/xl/tables/table2.xml"/></Relationships>'
        ).encode(),
        "xl/tables/table1.xml": table_xml("RequirementsTable", "A5:K62", REQUIREMENT_COLUMNS, 1),
        "xl/tables/table2.xml": table_xml("EvidenceTable", "A5:G62", EVIDENCE_COLUMNS, 2),
    }
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=7) as archive:
        for name in sorted(parts):
            info = ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, parts[name])
    return output.getvalue()


def table_xml(name: str, reference: str, columns: Sequence[str], identifier: int) -> bytes:
    table_columns = "".join(
        f'<tableColumn id="{index}" name="{escape(value, quote=True)}"/>'
        for index, value in enumerate(columns, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<table xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" id="{identifier}" '
        f'name="{name}" displayName="{name}" ref="{reference}" headerRowCount="1" totalsRowCount="0" totalsRowShown="0">'
        f'<autoFilter ref="{reference}"/><tableColumns count="{len(columns)}">'
        f"{table_columns}</tableColumns></table>"
    ).encode()


def replace_part(workbook: bytes, name: str, transform) -> bytes:
    with ZipFile(BytesIO(workbook)) as source:
        parts = {info.filename: source.read(info) for info in source.infolist()}
    parts[name] = transform(parts[name])
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED, compresslevel=7) as archive:
        for part_name in sorted(parts):
            info = ZipInfo(part_name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 3
            archive.writestr(info, parts[part_name])
    return output.getvalue()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--profile", choices=("apple", "github", "complete"), required=True)
    options = parser.parse_args()
    statuses: dict[str, str] = {}
    if options.profile == "apple":
        statuses = {identifier: "NOT STARTED" for identifier in {"REL-03", "REL-04", "REL-06", "REL-07"}}
        statuses["REL-03"] = "IN PROGRESS"
    elif options.profile == "github":
        statuses = {"REL-06": "IN PROGRESS"}
    data = build_workbook(statuses=statuses)
    qualification = options.root / "qualification"
    qualification.mkdir(parents=True, exist_ok=True)
    (qualification / "Local-Sandbox-0.3-Progress.xlsx").write_bytes(data)
    (qualification / "Local-Sandbox-0.3-Progress.snapshot.json").write_bytes(
        build_snapshot(data)
    )
