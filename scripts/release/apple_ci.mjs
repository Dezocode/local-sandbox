import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { isDeepStrictEqual, TextDecoder } from 'node:util';

const projectRoot = fileURLToPath(new URL('../../', import.meta.url));
const fullCommit = /^[0-9a-f]{40}$/;
const releaseVersion = /^[0-9]+\.[0-9]+\.[0-9]+$/;
const requiredChecks = JSON.parse(await readFile(
  new URL('./verification-checks.json', import.meta.url),
  'utf8',
));
if (!Array.isArray(requiredChecks)
  || requiredChecks.length !== 41
  || new Set(requiredChecks).size !== requiredChecks.length
  || requiredChecks.some((label) => typeof label !== 'string' || label.length === 0)) {
  throw new Error('Release verification check contract is malformed.');
}
const expectedGateIds = [
  'GOV-01', 'SRC-01', 'SRC-02', 'SRC-03', 'VER-01',
  'ENV-00', 'ENV-01', 'ENV-02', 'ENV-03', 'ENV-04',
  'BASE-01', 'BASE-02', 'BASE-03',
  'NAT-01', 'NAT-02', 'NAT-03', 'NAT-04', 'NAT-05', 'NAT-06',
  'PROV-01', 'PROV-02', 'PROV-03', 'PROV-04', 'PROV-05', 'PROV-06',
  'RUN-01', 'RUN-02', 'RUN-03', 'RUN-04', 'RUN-05', 'RUN-06',
  'PKG-01', 'PKG-02', 'PKG-03',
  'PWA-01', 'PWA-02', 'PWA-03', 'PWA-04',
  'AUTH-01', 'SYNC-01', 'KEY-01', 'AUTOSAVE-01',
  'PWA-CONN-01', 'PWA-CONN-02', 'BG-01', 'VERIFY-01',
  'GH-01', 'GH-02', 'ICLOUD-01', 'PRIV-01',
  'REL-01', 'REL-02', 'REL-03', 'REL-04', 'REL-05', 'REL-06', 'REL-07',
];
const appleActionGateId = 'REL-03';
const pendingAppleGateIds = new Set(['REL-03', 'REL-04', 'REL-06', 'REL-07']);
const appleReadyGateCount = expectedGateIds.length - pendingAppleGateIds.size;
const appleReadyPercent = 92.98245614035088;
const maximumReadinessAgeMilliseconds = 24 * 60 * 60 * 1000;
const futureClockSkewMilliseconds = 5 * 60 * 1000;
const requiredXcode = Object.freeze({ build: '27A266a', version: '27.0' });
const canonicalArtifacts = [
  'public/downloads/Local-Sandbox-Source.zip',
  'public/downloads/Local-Sandbox-Selfhost.zip',
  'public/downloads/Local-Sandbox-Setup-Guide.pdf',
];
const canonicalTrackerPath = 'qualification/Local-Sandbox-0.3-Progress.xlsx';
const canonicalTrackerSnapshotPath = 'qualification/Local-Sandbox-0.3-Progress.snapshot.json';
const trackerCheckLabel = 'Release qualification tracker';
const trackerVerifierPath = path.join(projectRoot, 'scripts/release/tracker.py');
const releasePython = process.env.LOCAL_SANDBOX_RELEASE_PYTHON || 'python3';
const sha256Pattern = /^[0-9a-f]{64}$/;
const candidateDigestVerifierPath = path.join(
  projectRoot,
  'scripts/release/candidate_digest.py',
);
const actionReadinessReceiptPath = 'release-output/apple-action-readiness-receipt.json';
const releaseEvidencePath = 'release-output/apple-release-evidence.json';
const protectedAppleReadinessJson = process.env.LS_APPLE_ACTION_READINESS_JSON;
delete process.env.LS_APPLE_ACTION_READINESS_JSON;
const artifactEvidencePaths = {
  guide: 'public/downloads/Local-Sandbox-Setup-Guide.pdf',
  selfhost: 'public/downloads/Local-Sandbox-Selfhost.zip',
  source: 'public/downloads/Local-Sandbox-Source.zip',
};

function fail(message) {
  throw new Error(message);
}

export function parseUniqueJson(data, label = 'JSON document') {
  let text;
  try {
    const bytes = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8 JSON.`);
  }

  let index = 0;
  const invalid = () => fail(`${label} is not valid UTF-8 JSON.`);
  const whitespace = () => {
    while (index < text.length && /[\t\n\r ]/.test(text[index])) index += 1;
  };
  const string = () => {
    if (text[index] !== '"') invalid();
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === '"') {
        index += 1;
        try {
          return JSON.parse(text.slice(start, index));
        } catch {
          invalid();
        }
      }
      if (character.charCodeAt(0) < 0x20) invalid();
      if (character === '\\') {
        index += 1;
        if (index >= text.length || !/["\\/bfnrtu]/.test(text[index])) invalid();
        if (text[index] === 'u') {
          const escape = text.slice(index + 1, index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(escape)) invalid();
          index += 4;
        }
      }
      index += 1;
    }
    return invalid();
  };
  const value = () => {
    whitespace();
    const character = text[index];
    if (character === '{') {
      index += 1;
      whitespace();
      const members = new Set();
      if (text[index] === '}') {
        index += 1;
        return;
      }
      while (index < text.length) {
        const member = string();
        if (members.has(member)) {
          fail(`${label} contains a duplicate object member name: ${member}.`);
        }
        members.add(member);
        whitespace();
        if (text[index] !== ':') invalid();
        index += 1;
        value();
        whitespace();
        if (text[index] === '}') {
          index += 1;
          return;
        }
        if (text[index] !== ',') invalid();
        index += 1;
        whitespace();
      }
      invalid();
    }
    if (character === '[') {
      index += 1;
      whitespace();
      if (text[index] === ']') {
        index += 1;
        return;
      }
      while (index < text.length) {
        value();
        whitespace();
        if (text[index] === ']') {
          index += 1;
          return;
        }
        if (text[index] !== ',') invalid();
        index += 1;
      }
      invalid();
    }
    if (character === '"') {
      string();
      return;
    }
    for (const literal of ['true', 'false', 'null']) {
      if (text.startsWith(literal, index)) {
        index += literal.length;
        return;
      }
    }
    const number = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
    number.lastIndex = index;
    const match = number.exec(text);
    if (match === null) invalid();
    index = number.lastIndex;
  };

  whitespace();
  value();
  whitespace();
  if (index !== text.length) invalid();
  try {
    return JSON.parse(text);
  } catch {
    return invalid();
  }
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireExactKeys(record, keys, label) {
  if (!isObject(record) || !isDeepStrictEqual(Object.keys(record).sort(), [...keys].sort())) {
    fail(`${label} has missing or unexpected fields.`);
  }
}

export function verifyReleaseXcode(record, label = 'Xcode toolchain') {
  requireExactKeys(record, ['build', 'version'], label);
  if (record.version !== requiredXcode.version || record.build !== requiredXcode.build) {
    fail(
      `${label} must be Xcode ${requiredXcode.version} build ${requiredXcode.build}; `
      + `received ${record.version ?? 'missing'} build ${record.build ?? 'missing'}.`,
    );
  }
  return { ...requiredXcode };
}

function requiredString(record, key, label) {
  const value = record?.[key];
  if (typeof value !== 'string' || value.trim().length === 0) {
    fail(`${label}.${key} must be a non-empty string.`);
  }
  return value;
}

function requiredInteger(record, key, label) {
  const value = record?.[key];
  if (!Number.isSafeInteger(value)) fail(`${label}.${key} must be a safe integer.`);
  return value;
}

function canonicalPositiveInteger(value, label, maximum) {
  if (!/^[1-9][0-9]*$/.test(value)) {
    fail(`${label} must be a canonical positive integer.`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) {
    fail(`${label} must be between 1 and ${maximum}.`);
  }
  return parsed;
}

export function buildNumberFor(runNumberValue, runAttemptValue) {
  const runNumber = canonicalPositiveInteger(runNumberValue, 'GitHub run number', 9_999);
  const runAttempt = canonicalPositiveInteger(runAttemptValue, 'GitHub run attempt', 99);
  return `${runNumber}.${runAttempt}.0`;
}

export function verifyReleaseInputs({
  releaseCommit,
  triggerCommit,
  requestedVersion,
  packageVersion,
  headCommit,
}) {
  if (!fullCommit.test(releaseCommit)) {
    fail('release_commit must be a full lowercase 40-character Git commit SHA.');
  }
  if (!fullCommit.test(triggerCommit)) {
    fail('The workflow trigger did not supply a full lowercase Git commit SHA.');
  }
  if (releaseCommit !== triggerCommit || releaseCommit !== headCommit) {
    fail('release_commit must equal both the workflow-dispatch main commit and checked-out HEAD.');
  }
  if (!releaseVersion.test(requestedVersion)) {
    fail('release_version must contain three numeric components.');
  }
  if (requestedVersion !== packageVersion) {
    fail(`release_version ${requestedVersion} does not match package.json ${packageVersion}.`);
  }
}

export function verifyPassedValidation(
  record,
  requestedVersion,
  trackerSummary,
  expectedCandidateDigest,
  now = new Date(),
) {
  if (record?.recordType !== 'local-sandbox-release-validation' || record?.schemaVersion !== 1) {
    fail('docs/validation.json is not a Local Sandbox release validation record.');
  }
  if (record.version !== requestedVersion) {
    fail(`Validation version ${record.version ?? 'missing'} does not match ${requestedVersion}.`);
  }
  if (!sha256Pattern.test(expectedCandidateDigest)
    || !sha256Pattern.test(record.candidateDigest)
    || record.candidateDigest !== expectedCandidateDigest) {
    fail('docs/validation.json candidateDigest does not match the current release candidate.');
  }
  if (record.automatedVerification?.status !== 'passed') {
    fail('The canonical full verifier did not record a passed result.');
  }
  const checks = record.automatedVerification.checks;
  if (!Array.isArray(checks) || checks.length === 0) {
    fail('The passed validation record has no executed checks.');
  }
  const failed = checks.filter((check) => check?.status !== 'passed' || typeof check?.label !== 'string');
  if (failed.length > 0) {
    fail('The validation record contains a missing or non-passed check.');
  }
  const labels = checks.map((check) => check.label);
  const uniqueLabels = new Set(labels);
  if (uniqueLabels.size !== labels.length) {
    fail('The validation record contains a duplicate full-verifier check.');
  }
  const missing = requiredChecks.filter((label) => !uniqueLabels.has(label));
  if (missing.length > 0) {
    fail(`The validation record is missing required full-verifier checks: ${missing.join(', ')}.`);
  }
  const expectedLabels = new Set(requiredChecks);
  const unexpected = labels.filter((label) => !expectedLabels.has(label));
  if (unexpected.length > 0) {
    fail(`The validation record contains unexpected full-verifier checks: ${unexpected.join(', ')}.`);
  }
  if (!isDeepStrictEqual(labels, requiredChecks)) {
    fail('The validation record checks are not in canonical execution order.');
  }
  const tracker = verifyTrackerSummary(trackerSummary, 'Validation qualification tracker');
  const trackerCheck = checks.find((check) => check.label === trackerCheckLabel);
  if (!isObject(trackerCheck?.tracker)
    || !isDeepStrictEqual(trackerCheck.tracker, tracker.binding)) {
    fail('The validation tracker binding is missing or differs from the recomputed qualification tracker.');
  }
  const generatedAt = parseBoundedTimestamp(record.generatedAt, 'Validation generatedAt');
  const nowMilliseconds = now.getTime();
  if (!Number.isFinite(nowMilliseconds)) fail('The validation verification clock is invalid.');
  if (generatedAt > nowMilliseconds + futureClockSkewMilliseconds) {
    fail('The validation record generatedAt is in the future.');
  }
  if (nowMilliseconds - generatedAt > maximumReadinessAgeMilliseconds) {
    fail('The validation record is older than 24 hours.');
  }
  return checks;
}

function digest(data) {
  return createHash('sha256').update(data).digest('hex');
}

function candidateDigestForRoot(root) {
  let value;
  try {
    value = execFileSync(
      releasePython,
      [candidateDigestVerifierPath, '--root', root],
      { cwd: root, encoding: 'utf8', maxBuffer: 16_000 },
    ).trim();
  } catch (error) {
    const detail = error?.stderr?.toString('utf8').trim();
    fail(`Release candidate digest failed${detail ? `: ${detail}` : '.'}`);
  }
  if (!sha256Pattern.test(value)) fail('Release candidate digest output is invalid.');
  return value;
}

function recomputeTracker(workbookData, snapshotData) {
  if (!Buffer.isBuffer(workbookData) || !Buffer.isBuffer(snapshotData)) {
    fail('Tracker verification requires workbook and snapshot bytes.');
  }
  let output;
  try {
    output = execFileSync(releasePython, [trackerVerifierPath, 'verify-envelope'], {
      cwd: projectRoot,
      input: JSON.stringify({
        snapshot: snapshotData.toString('base64'),
        workbook: workbookData.toString('base64'),
      }),
      maxBuffer: 2_000_000,
    });
  } catch (error) {
    const detail = error?.stderr?.toString('utf8').trim();
    fail(`Qualification tracker verification failed${detail ? `: ${detail}` : '.'}`);
  }
  return parseUniqueJson(output, 'Qualification tracker verification result');
}

function verifyTrackerSummary(summary, label = 'Qualification tracker') {
  requireExactKeys(summary, [
    'binding', 'evidenceRows', 'finalQualificationClaimed', 'gates', 'requirementsRows',
    'status',
  ], label);
  if (summary.status !== 'tracker-snapshot-verified' || summary.finalQualificationClaimed !== false) {
    fail(`${label} is not a non-qualifying tracker-snapshot verification result.`);
  }
  if (requiredInteger(summary, 'requirementsRows', label) !== expectedGateIds.length) {
    fail(`${label} must contain exactly ${expectedGateIds.length} requirements rows.`);
  }
  if (requiredInteger(summary, 'evidenceRows', label) < 1) {
    fail(`${label} must contain Evidence rows.`);
  }
  requireExactKeys(summary.binding, [
    'evidenceSha256', 'path', 'requirementsSha256', 'sha256', 'snapshotPath',
    'snapshotSha256',
  ], `${label}.binding`);
  if (summary.binding.path !== canonicalTrackerPath
    || summary.binding.snapshotPath !== canonicalTrackerSnapshotPath) {
    fail(`${label} does not use the canonical workbook and snapshot paths.`);
  }
  for (const key of ['evidenceSha256', 'requirementsSha256', 'sha256', 'snapshotSha256']) {
    if (!sha256Pattern.test(summary.binding[key])) fail(`${label}.binding.${key} is invalid.`);
  }
  if (!Array.isArray(summary.gates) || summary.gates.length !== expectedGateIds.length) {
    fail(`${label}.gates must contain exactly ${expectedGateIds.length} rows.`);
  }
  for (const [index, gate] of summary.gates.entries()) {
    requireExactKeys(gate, ['evidenceSha256', 'id', 'status'], `${label}.gates[${index}]`);
    if (gate.id !== expectedGateIds[index]
      || !['PASS', 'IN PROGRESS', 'BLOCKED', 'FAIL', 'NOT STARTED'].includes(gate.status)
      || !sha256Pattern.test(gate.evidenceSha256)) {
      fail(`${label}.gates[${index}] is not a canonical gate digest.`);
    }
  }
  return summary;
}

function recomputeCommittedAndCurrentTracker({
  committedWorkbookData,
  committedSnapshotData,
  currentWorkbookData,
  currentSnapshotData,
}) {
  if (!currentWorkbookData.equals(committedWorkbookData)) {
    fail(`${canonicalTrackerPath} differs from the selected release commit.`);
  }
  if (!currentSnapshotData.equals(committedSnapshotData)) {
    fail(`${canonicalTrackerSnapshotPath} differs from the selected release commit.`);
  }
  const committed = verifyTrackerSummary(
    recomputeTracker(committedWorkbookData, committedSnapshotData),
    'Committed qualification tracker',
  );
  const current = verifyTrackerSummary(
    recomputeTracker(currentWorkbookData, currentSnapshotData),
    'Current qualification tracker',
  );
  if (!isDeepStrictEqual(current, committed)) {
    fail('Current and committed tracker verification results differ.');
  }
  return committed;
}

function parseBoundedTimestamp(value, label) {
  if (typeof value !== 'string' || !/(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(value)) {
    fail(`${label} must be an ISO 8601 timestamp with a UTC offset.`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) fail(`${label} is not a valid timestamp.`);
  return milliseconds;
}

export function verifyAppleActionReadiness({
  record,
  releaseCommit,
  releaseVersion,
  committedValidationData,
  committedArtifacts,
  trackerSummary,
  candidateDigest,
  now = new Date(),
}) {
  requireExactKeys(record, [
    'artifacts', 'commit', 'completionPercent', 'gates', 'passedGates', 'readyAt',
    'recordType', 'releaseState', 'schemaVersion', 'totalGates', 'tracker', 'verification', 'version',
    'xcode',
  ], 'Apple action readiness');
  if (record.recordType !== 'local-sandbox-apple-action-readiness' || record.schemaVersion !== 1) {
    fail('Apple action readiness has the wrong record type or schema version.');
  }
  if (record.releaseState !== 'READY') fail('Apple action readiness.releaseState must be READY.');
  if (record.commit !== releaseCommit) {
    fail('Apple action readiness.commit does not equal the selected release commit.');
  }
  if (record.version !== releaseVersion) {
    fail('Apple action readiness.version does not equal the selected release version.');
  }
  if (requiredInteger(record, 'totalGates', 'Apple action readiness') !== expectedGateIds.length) {
    fail(`Apple action readiness.totalGates must be ${expectedGateIds.length}.`);
  }
  if (requiredInteger(record, 'passedGates', 'Apple action readiness') !== appleReadyGateCount) {
    fail(`Apple action readiness.passedGates must be ${appleReadyGateCount}.`);
  }
  if (record.completionPercent !== appleReadyPercent) {
    fail(`Apple action readiness.completionPercent must be ${appleReadyPercent}.`);
  }
  const xcode = verifyReleaseXcode(record.xcode, 'Apple action readiness.xcode');
  const tracker = verifyTrackerSummary(trackerSummary);
  if (!isDeepStrictEqual(record.tracker, tracker.binding)) {
    fail('Apple action readiness.tracker does not exactly match the recomputed tracker binding.');
  }

  if (!Array.isArray(record.gates) || record.gates.length !== expectedGateIds.length) {
    fail(`Apple action readiness.gates must contain exactly ${expectedGateIds.length} gates.`);
  }
  const expectedIds = new Set(expectedGateIds);
  const seenIds = new Set();
  let passed = 0;
  for (const [index, gate] of record.gates.entries()) {
    const label = `Apple action readiness.gates[${index}]`;
    requireExactKeys(gate, ['evidenceSha256', 'id', 'status'], label);
    const id = requiredString(gate, 'id', label);
    if (!expectedIds.has(id) || seenIds.has(id)) {
      fail(`${label}.id must be one unique 0.3 gate ID.`);
    }
    if (id !== expectedGateIds[index]) {
      fail(`${label}.id must be ${expectedGateIds[index]} in canonical 0.3 gate order.`);
    }
    seenIds.add(id);
    const evidenceSha256 = requiredString(gate, 'evidenceSha256', label);
    if (!sha256Pattern.test(evidenceSha256)) {
      fail(`${label}.evidenceSha256 must be one lowercase SHA-256 digest.`);
    }
    if (!pendingAppleGateIds.has(id)) {
      if (gate.status !== 'PASS') fail(`${label}.status must be PASS.`);
      passed += 1;
      continue;
    }
    if (id === appleActionGateId) {
      if (gate.status === 'PASS') {
        fail('REL-03 cannot be pre-passed; the signed Apple action must complete it.');
      }
      if (gate.status !== 'IN PROGRESS') fail(`${label}.status must be IN PROGRESS.`);
      continue;
    }
    if (!['IN PROGRESS', 'NOT STARTED'].includes(gate.status)) {
      fail(`${label}.status must not be PASS before the Apple action.`);
    }
  }
  if (seenIds.size !== expectedIds.size || passed !== appleReadyGateCount) {
    fail('Apple action readiness must contain exactly 53 PASS gates.');
  }
  if (!isDeepStrictEqual(record.gates, tracker.gates)) {
    fail('Apple action readiness gate status or evidence differs from the tracker snapshot.');
  }

  const committedValidation = parseUniqueJson(
    committedValidationData,
    'The committed docs/validation.json',
  );
  verifyPassedValidation(
    committedValidation,
    releaseVersion,
    tracker,
    candidateDigest,
    now,
  );
  const generatedAt = parseBoundedTimestamp(
    committedValidation.generatedAt,
    'Committed validation.generatedAt',
  );
  const readyAt = parseBoundedTimestamp(record.readyAt, 'Apple action readiness.readyAt');
  const nowMilliseconds = now.getTime();
  if (!Number.isFinite(nowMilliseconds)) fail('The readiness verification clock is invalid.');
  if (readyAt < generatedAt) {
    fail('Apple action readiness.readyAt predates the committed validation record.');
  }
  if (readyAt > nowMilliseconds + futureClockSkewMilliseconds) {
    fail('Apple action readiness.readyAt is in the future.');
  }
  if (nowMilliseconds - readyAt > maximumReadinessAgeMilliseconds) {
    fail('Apple action readiness is older than 24 hours.');
  }

  const verification = record.verification;
  requireExactKeys(
    verification,
    ['automatedStatus', 'candidateDigest', 'commit', 'path', 'sha256'],
    'Apple action readiness.verification',
  );
  if (verification.path !== 'docs/validation.json') {
    fail('Apple action readiness.verification.path must be docs/validation.json.');
  }
  if (verification.commit !== releaseCommit) {
    fail('Apple action readiness.verification.commit does not equal the release commit.');
  }
  if (verification.automatedStatus !== 'passed') {
    fail('Apple action readiness.verification.automatedStatus must be passed.');
  }
  if (verification.candidateDigest !== candidateDigest) {
    fail('Apple action readiness.verification.candidateDigest does not match the current release candidate.');
  }
  const validationSha256 = requiredString(verification, 'sha256', 'Apple action readiness.verification');
  if (!sha256Pattern.test(validationSha256) || validationSha256 !== digest(committedValidationData)) {
    fail('Apple action readiness does not match the committed validation digest.');
  }

  if (!Array.isArray(record.artifacts) || record.artifacts.length !== canonicalArtifacts.length) {
    fail('Apple action readiness.artifacts must list exactly the three canonical artifacts.');
  }
  const evidenceByPath = new Map();
  for (const [index, artifact] of record.artifacts.entries()) {
    const label = `Apple action readiness.artifacts[${index}]`;
    requireExactKeys(artifact, ['bytes', 'path', 'sha256'], label);
    const artifactPath = requiredString(artifact, 'path', label);
    if (evidenceByPath.has(artifactPath)) fail(`${label}.path is duplicated.`);
    evidenceByPath.set(artifactPath, artifact);
  }
  if (
    evidenceByPath.size !== canonicalArtifacts.length
    || canonicalArtifacts.some((artifactPath) => !evidenceByPath.has(artifactPath))
  ) {
    fail('Apple action readiness.artifacts must list exactly the three canonical artifacts.');
  }
  const verifiedArtifacts = [];
  for (const artifactPath of canonicalArtifacts) {
    const data = committedArtifacts.get(artifactPath);
    if (!Buffer.isBuffer(data)) fail(`Missing committed artifact bytes for ${artifactPath}.`);
    const evidence = evidenceByPath.get(artifactPath);
    const label = `Apple action readiness.artifacts[${artifactPath}]`;
    const artifactSha256 = requiredString(evidence, 'sha256', label);
    if (!sha256Pattern.test(artifactSha256) || artifactSha256 !== digest(data)) {
      fail(`${artifactPath} does not match its committed SHA-256 digest.`);
    }
    if (requiredInteger(evidence, 'bytes', label) !== data.length) {
      fail(`${artifactPath} does not match its committed byte count.`);
    }
    verifiedArtifacts.push({ bytes: data.length, path: artifactPath, sha256: artifactSha256 });
  }
  return {
    artifacts: verifiedArtifacts,
    commit: releaseCommit,
    freshness: {
      maximumAgeSeconds: maximumReadinessAgeMilliseconds / 1000,
      readyAt: record.readyAt,
      validationGeneratedAt: committedValidation.generatedAt,
    },
    gateState: {
      inProgressGate: appleActionGateId,
      inProgressStatus: 'IN PROGRESS',
      passedGates: passed,
      totalGates: expectedGateIds.length,
    },
    validation: {
      candidateDigest,
      path: 'docs/validation.json',
      sha256: validationSha256,
    },
    tracker: tracker.binding,
    version: releaseVersion,
    xcode,
  };
}

export function verifyAppleReleaseEvidence({
  record,
  releaseCommit,
  releaseVersion: selectedVersion,
  buildNumber,
  stage,
  xcodeVersion,
  xcodeBuild,
  validationData,
  artifacts,
  trackerSummary,
  candidateDigest,
  now = new Date(),
}) {
  requireExactKeys(record, [
    'artifacts', 'buildNumber', 'checks', 'recordType', 'releaseCommit', 'releaseVersion',
    'schemaVersion', 'stage', 'tracker', 'validation', 'validationSha256', 'xcode',
  ], 'Apple release evidence');
  if (record.recordType !== 'local-sandbox-apple-release-evidence'
    || record.schemaVersion !== 1) {
    fail('Apple release evidence has the wrong record type or schema version.');
  }
  if (record.releaseCommit !== releaseCommit || record.releaseVersion !== selectedVersion) {
    fail('Apple release evidence does not match the selected commit and version.');
  }
  if (record.buildNumber !== buildNumber || record.stage !== stage) {
    fail('Apple release evidence does not match the selected build number and stage.');
  }
  const xcode = verifyReleaseXcode(record.xcode, 'Apple release evidence.xcode');
  if (!isDeepStrictEqual(xcode, verifyReleaseXcode(
    { build: xcodeBuild, version: xcodeVersion },
    'Selected Xcode toolchain',
  ))) {
    fail('Apple release evidence does not match the selected Xcode toolchain.');
  }

  const tracker = verifyTrackerSummary(trackerSummary);
  const validation = parseUniqueJson(validationData, 'Current docs/validation.json');
  const checks = verifyPassedValidation(
    validation,
    selectedVersion,
    tracker,
    candidateDigest,
    now,
  );
  if (record.validationSha256 !== digest(validationData)) {
    fail('Apple release evidence does not match current docs/validation.json.');
  }
  if (!isDeepStrictEqual(record.validation, validation)) {
    fail('Apple release evidence embeds a different validation record.');
  }
  if (!isDeepStrictEqual(record.checks, checks.map((check) => check.label))) {
    fail('Apple release evidence does not list the exact executed validation checks.');
  }

  if (!isObject(record.artifacts)
    || !isDeepStrictEqual(Object.keys(record.artifacts).sort(), Object.keys(artifactEvidencePaths).sort())) {
    fail('Apple release evidence must bind exactly the three canonical artifacts.');
  }
  for (const [name, artifactPath] of Object.entries(artifactEvidencePaths)) {
    const data = artifacts.get(artifactPath);
    const evidence = record.artifacts[name];
    requireExactKeys(evidence, ['path', 'sha256'], `Apple release evidence.artifacts.${name}`);
    if (!Buffer.isBuffer(data)
      || evidence.path !== artifactPath
      || evidence.sha256 !== digest(data)) {
      fail(`Apple release evidence does not match ${artifactPath}.`);
    }
  }
  if (!isDeepStrictEqual(record.tracker, tracker.binding)) {
    fail('Apple release evidence does not match the recomputed qualification tracker.');
  }
  return {
    checks: checks.length,
    tracker: tracker.binding,
    validationSha256: digest(validationData),
    xcode,
  };
}

export function verifyAppleArchiveAuthorization({
  receipt,
  actionReadinessRecord,
  actionReadinessData,
  evidence,
  evidenceData,
  releaseCommit,
  releaseVersion: selectedVersion,
  buildNumber,
  stage,
  xcodeVersion,
  xcodeBuild,
  committedValidationData,
  currentValidationData,
  committedArtifacts,
  currentArtifacts,
  trackerSummary,
  candidateDigest,
  now = new Date(),
}) {
  if (!isObject(receipt)
    || receipt.recordType !== 'local-sandbox-apple-action-readiness-receipt'
    || receipt.schemaVersion !== 1) {
    fail('Apple action-readiness receipt has the wrong record type or schema version.');
  }
  const receiptKeys = [
    'actionReadinessSha256', 'buildNumber', 'readiness', 'recordType',
    'releaseCommit', 'releaseEvidence', 'releaseVersion', 'schemaVersion', 'stage',
    'verifiedAt',
  ];
  if (!isDeepStrictEqual(Object.keys(receipt).sort(), receiptKeys.sort())) {
    fail('Apple action-readiness receipt has missing or unexpected fields.');
  }
  if (receipt.releaseCommit !== releaseCommit || receipt.releaseVersion !== selectedVersion) {
    fail('Apple action-readiness receipt does not match the selected commit and version.');
  }
  if (receipt.buildNumber !== buildNumber || receipt.stage !== stage) {
    fail('Apple action-readiness receipt does not match the selected build number and stage.');
  }
  if (!Buffer.isBuffer(actionReadinessData)
    || !sha256Pattern.test(receipt.actionReadinessSha256)
    || receipt.actionReadinessSha256 !== digest(actionReadinessData)) {
    fail('Apple action-readiness receipt does not match the protected record bytes.');
  }

  const readiness = verifyAppleActionReadiness({
    record: actionReadinessRecord,
    releaseCommit,
    releaseVersion: selectedVersion,
    committedValidationData,
    committedArtifacts,
    trackerSummary,
    candidateDigest,
    now,
  });
  const xcode = verifyReleaseXcode(
    { build: xcodeBuild, version: xcodeVersion },
    'Current Xcode toolchain',
  );
  if (!isDeepStrictEqual(readiness.xcode, xcode)) {
    fail('Protected Apple action readiness does not match the current Xcode toolchain.');
  }
  if (!isDeepStrictEqual(receipt.readiness, readiness)) {
    fail('Apple action-readiness receipt does not match the revalidated canonical readiness summary.');
  }

  const nowMilliseconds = now.getTime();
  const verifiedAt = parseBoundedTimestamp(
    receipt.verifiedAt,
    'Apple action-readiness receipt.verifiedAt',
  );
  if (!Number.isFinite(nowMilliseconds)) fail('The authorization verification clock is invalid.');
  if (verifiedAt > nowMilliseconds + futureClockSkewMilliseconds) {
    fail('Apple action-readiness receipt.verifiedAt is in the future.');
  }
  if (nowMilliseconds - verifiedAt > maximumReadinessAgeMilliseconds) {
    fail('Apple action-readiness receipt is older than 24 hours.');
  }
  if (verifiedAt < parseBoundedTimestamp(
    readiness.freshness.readyAt,
    'Canonical Apple action readiness.readyAt',
  )) {
    fail('Apple action-readiness receipt predates the protected readiness record.');
  }
  if (!isObject(receipt.releaseEvidence)
    || !isDeepStrictEqual(Object.keys(receipt.releaseEvidence).sort(), ['path', 'sha256'])
    || receipt.releaseEvidence.path !== releaseEvidencePath
    || receipt.releaseEvidence.sha256 !== digest(evidenceData)) {
    fail('Apple action-readiness receipt does not match the release evidence file.');
  }

  for (const artifactPath of canonicalArtifacts) {
    const committed = committedArtifacts.get(artifactPath);
    const current = currentArtifacts.get(artifactPath);
    if (!Buffer.isBuffer(committed) || !Buffer.isBuffer(current) || !current.equals(committed)) {
      fail(`${artifactPath} differs from the selected release commit.`);
    }
  }

  verifyAppleReleaseEvidence({
    record: evidence,
    releaseCommit,
    releaseVersion: selectedVersion,
    buildNumber,
    stage,
    xcodeVersion,
    xcodeBuild,
    validationData: currentValidationData,
    artifacts: currentArtifacts,
    trackerSummary,
    candidateDigest,
    now,
  });
  return {
    buildNumber,
    releaseCommit,
    releaseVersion: selectedVersion,
    stage,
    status: 'authorized',
    xcode,
  };
}

async function writeAtomicJson(destination, value) {
  const data = `${JSON.stringify(value, null, 2)}\n`;
  if (Buffer.byteLength(data, 'utf8') > 16_000) fail('The Apple readiness receipt is too large.');
  await mkdir(path.dirname(destination), { recursive: true });
  const temporary = `${destination}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, data, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    await rename(temporary, destination);
  } finally {
    await unlink(temporary).catch((error) => {
      if (error?.code !== 'ENOENT') throw error;
    });
  }
}

function git(root, arguments_) {
  return execFileSync('git', arguments_, { cwd: root, encoding: 'utf8' }).trim();
}

function gitBytes(root, arguments_) {
  return execFileSync('git', arguments_, { cwd: root });
}

function changedSourcePaths(root) {
  const paths = new Set();
  for (const arguments_ of [
    ['diff', '--name-only', '--no-ext-diff'],
    ['diff', '--cached', '--name-only', '--no-ext-diff'],
    ['ls-files', '--others', '--exclude-standard'],
  ]) {
    for (const entry of git(root, arguments_).split('\n')) {
      if (entry) paths.add(entry);
    }
  }
  return [...paths].sort();
}

async function trackerForCommit(root, commit) {
  const committedWorkbookData = gitBytes(root, ['show', `${commit}:${canonicalTrackerPath}`]);
  const committedSnapshotData = gitBytes(root, [
    'show', `${commit}:${canonicalTrackerSnapshotPath}`,
  ]);
  const currentWorkbookData = await readFile(path.join(root, canonicalTrackerPath));
  const currentSnapshotData = await readFile(path.join(root, canonicalTrackerSnapshotPath));
  return recomputeCommittedAndCurrentTracker({
    committedWorkbookData,
    committedSnapshotData,
    currentWorkbookData,
    currentSnapshotData,
  });
}

async function sha256(file) {
  return createHash('sha256').update(await readFile(file)).digest('hex');
}

function protectedAppleReadiness() {
  const readinessJson = protectedAppleReadinessJson;
  if (!readinessJson) {
    fail('The protected APPLE_ACTION_READINESS_JSON environment secret is missing.');
  }
  const data = Buffer.from(readinessJson, 'utf8');
  if (data.length > 48_000) {
    fail('The protected Apple action-readiness record exceeds 48,000 bytes.');
  }
  const record = parseUniqueJson(data, 'The protected Apple action-readiness record');
  return { data, record };
}

function parseArguments(values) {
  const options = {};
  for (let index = 0; index < values.length; index += 1) {
    const argument = values[index];
    if (!argument.startsWith('--') || !values[index + 1] || values[index + 1].startsWith('--')) {
      fail(`Expected --name value, received ${argument}.`);
    }
    const name = argument.slice(2);
    if (Object.hasOwn(options, name)) fail(`Duplicate option: --${name}.`);
    options[name] = values[index + 1];
    index += 1;
  }
  return options;
}

function requireOptions(options, names) {
  for (const name of names) {
    if (!options[name]) fail(`Missing required option: --${name}.`);
  }
}

async function prepare(options) {
  requireOptions(options, [
    'release-commit', 'trigger-commit', 'release-version', 'run-number', 'run-attempt', 'github-env',
    'github-output',
  ]);
  const root = path.resolve(options.root ?? projectRoot);
  const packageMetadata = parseUniqueJson(
    await readFile(path.join(root, 'package.json')),
    'package.json',
  );
  const headCommit = git(root, ['rev-parse', 'HEAD']);
  verifyReleaseInputs({
    releaseCommit: options['release-commit'],
    triggerCommit: options['trigger-commit'],
    requestedVersion: options['release-version'],
    packageVersion: packageMetadata.version,
    headCommit,
  });
  const changed = changedSourcePaths(root);
  if (changed.length > 0) {
    fail(`The release checkout is not clean: ${changed.join(', ')}.`);
  }
  const buildNumber = buildNumberFor(options['run-number'], options['run-attempt']);
  await appendFile(options['github-env'], `LS_BUILD_NUMBER=${buildNumber}\n`, { encoding: 'utf8' });
  await appendFile(options['github-output'], `build_number=${buildNumber}\n`, { encoding: 'utf8' });
  process.stdout.write(`${JSON.stringify({
    status: 'prepared',
    releaseCommit: headCommit,
    releaseVersion: packageMetadata.version,
    buildNumber,
  })}\n`);
}

async function readiness(options) {
  requireOptions(options, [
    'release-commit', 'release-version', 'build-number', 'stage', 'validation', 'evidence',
    'receipt', 'xcode-version', 'xcode-build',
  ]);
  if (options.validation !== 'docs/validation.json') {
    fail('--validation must be docs/validation.json.');
  }
  if (options.evidence !== releaseEvidencePath) {
    fail(`--evidence must be ${releaseEvidencePath}.`);
  }
  if (options.receipt !== actionReadinessReceiptPath) {
    fail(`--receipt must be ${actionReadinessReceiptPath}.`);
  }
  if (!['archive', 'upload'].includes(options.stage)) fail('stage must be archive or upload.');
  if (!/^([1-9][0-9]{0,3})\.([1-9][0-9]?)\.0$/.test(options['build-number'])) {
    fail('build-number does not match the bounded CI build-number format.');
  }
  const root = path.resolve(options.root ?? projectRoot);
  const packageMetadata = parseUniqueJson(
    await readFile(path.join(root, 'package.json')),
    'package.json',
  );
  const headCommit = git(root, ['rev-parse', 'HEAD']);
  verifyReleaseInputs({
    releaseCommit: options['release-commit'],
    triggerCommit: options['release-commit'],
    requestedVersion: options['release-version'],
    packageVersion: packageMetadata.version,
    headCommit,
  });
  const trackerSummary = await trackerForCommit(root, options['release-commit']);
  const changed = changedSourcePaths(root);
  const unexpected = changed.filter((entry) => entry !== 'docs/validation.json');
  if (unexpected.length > 0) {
    fail(`Source changed before Apple action readiness: ${unexpected.join(', ')}.`);
  }
  const candidateDigest = candidateDigestForRoot(root);

  const currentXcode = verifyReleaseXcode({
    build: options['xcode-build'],
    version: options['xcode-version'],
  }, 'Workflow Xcode toolchain');
  const { data: readinessData, record } = protectedAppleReadiness();

  const committedValidationData = gitBytes(root, [
    'show',
    `${options['release-commit']}:${options.validation}`,
  ]);
  const currentValidationData = await readFile(path.join(root, options.validation));
  const committedArtifacts = new Map();
  const currentArtifacts = new Map();
  for (const artifactPath of canonicalArtifacts) {
    const committed = gitBytes(root, ['show', `${options['release-commit']}:${artifactPath}`]);
    const working = await readFile(path.join(root, artifactPath));
    if (!working.equals(committed)) {
      fail(`${artifactPath} differs from the selected release commit.`);
    }
    committedArtifacts.set(artifactPath, committed);
    currentArtifacts.set(artifactPath, working);
  }
  const summary = verifyAppleActionReadiness({
    record,
    releaseCommit: options['release-commit'],
    releaseVersion: options['release-version'],
    committedValidationData,
    committedArtifacts,
    trackerSummary,
    candidateDigest,
  });
  if (!isDeepStrictEqual(summary.xcode, currentXcode)) {
    fail('Protected Apple action readiness does not match the workflow Xcode toolchain.');
  }
  const evidenceData = await readFile(path.join(root, options.evidence));
  if (evidenceData.length > 1_000_000) fail('Apple release evidence exceeds 1,000,000 bytes.');
  const evidence = parseUniqueJson(evidenceData, 'Apple release evidence');
  verifyAppleReleaseEvidence({
    record: evidence,
    releaseCommit: options['release-commit'],
    releaseVersion: options['release-version'],
    buildNumber: options['build-number'],
    stage: options.stage,
    xcodeVersion: currentXcode.version,
    xcodeBuild: currentXcode.build,
    validationData: currentValidationData,
    artifacts: currentArtifacts,
    trackerSummary,
    candidateDigest,
  });
  const actionReadinessSha256 = digest(readinessData);
  const receipt = {
    actionReadinessSha256,
    buildNumber: options['build-number'],
    readiness: summary,
    recordType: 'local-sandbox-apple-action-readiness-receipt',
    releaseCommit: options['release-commit'],
    releaseEvidence: {
      path: options.evidence,
      sha256: digest(evidenceData),
    },
    releaseVersion: options['release-version'],
    schemaVersion: 1,
    stage: options.stage,
    verifiedAt: new Date().toISOString(),
  };
  await writeAtomicJson(path.join(root, options.receipt), receipt);
  process.stdout.write(`${JSON.stringify({
    actionReadinessSha256,
    passedGates: summary.gateState.passedGates,
    pendingGate: summary.gateState.inProgressGate,
    receipt: options.receipt,
    releaseCommit: options['release-commit'],
    releaseVersion: options['release-version'],
    buildNumber: options['build-number'],
    stage: options.stage,
    status: 'action-ready',
  })}\n`);
}

async function authorize(options) {
  requireOptions(options, [
    'release-commit', 'release-version', 'build-number', 'stage', 'validation', 'evidence',
    'receipt', 'xcode-version', 'xcode-build',
  ]);
  if (options.validation !== 'docs/validation.json') {
    fail('--validation must be docs/validation.json.');
  }
  if (options.evidence !== releaseEvidencePath) {
    fail(`--evidence must be ${releaseEvidencePath}.`);
  }
  if (options.receipt !== actionReadinessReceiptPath) {
    fail(`--receipt must be ${actionReadinessReceiptPath}.`);
  }
  if (!['archive', 'upload'].includes(options.stage)) fail('stage must be archive or upload.');
  if (!/^([1-9][0-9]{0,3})\.([1-9][0-9]?)\.0$/.test(options['build-number'])) {
    fail('build-number does not match the bounded CI build-number format.');
  }

  const root = path.resolve(options.root ?? projectRoot);
  const currentXcode = verifyReleaseXcode({
    build: options['xcode-build'],
    version: options['xcode-version'],
  }, 'Current Xcode toolchain');
  const { data: actionReadinessData, record: actionReadinessRecord } = protectedAppleReadiness();
  const packageMetadata = parseUniqueJson(
    await readFile(path.join(root, 'package.json')),
    'package.json',
  );
  const headCommit = git(root, ['rev-parse', 'HEAD']);
  verifyReleaseInputs({
    releaseCommit: options['release-commit'],
    triggerCommit: options['release-commit'],
    requestedVersion: options['release-version'],
    packageVersion: packageMetadata.version,
    headCommit,
  });
  const trackerSummary = await trackerForCommit(root, options['release-commit']);
  const changed = changedSourcePaths(root);
  if (!changed.includes('docs/validation.json')) {
    fail('The canonical full verifier did not refresh docs/validation.json.');
  }
  const unexpected = changed.filter((entry) => entry !== 'docs/validation.json');
  if (unexpected.length > 0) {
    fail(`Source changed before Apple archive authorization: ${unexpected.join(', ')}.`);
  }
  const candidateDigest = candidateDigestForRoot(root);

  const receiptData = await readFile(path.join(root, options.receipt));
  if (receiptData.length > 16_000) fail('Apple action-readiness receipt exceeds 16,000 bytes.');
  const evidenceData = await readFile(path.join(root, options.evidence));
  if (evidenceData.length > 1_000_000) fail('Apple release evidence exceeds 1,000,000 bytes.');
  const receipt = parseUniqueJson(receiptData, 'Apple action-readiness receipt');
  const evidence = parseUniqueJson(evidenceData, 'Apple release evidence');

  const committedValidationData = gitBytes(root, [
    'show',
    `${options['release-commit']}:${options.validation}`,
  ]);
  const currentValidationData = await readFile(path.join(root, options.validation));
  const committedArtifacts = new Map();
  const currentArtifacts = new Map();
  for (const artifactPath of canonicalArtifacts) {
    committedArtifacts.set(
      artifactPath,
      gitBytes(root, ['show', `${options['release-commit']}:${artifactPath}`]),
    );
    currentArtifacts.set(artifactPath, await readFile(path.join(root, artifactPath)));
  }
  const result = verifyAppleArchiveAuthorization({
    receipt,
    actionReadinessRecord,
    actionReadinessData,
    evidence,
    evidenceData,
    releaseCommit: options['release-commit'],
    releaseVersion: options['release-version'],
    buildNumber: options['build-number'],
    stage: options.stage,
    xcodeVersion: currentXcode.version,
    xcodeBuild: currentXcode.build,
    committedValidationData,
    currentValidationData,
    committedArtifacts,
    currentArtifacts,
    trackerSummary,
    candidateDigest,
  });
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

async function validate(options) {
  requireOptions(options, [
    'release-commit', 'release-version', 'build-number', 'stage', 'validation', 'evidence',
    'xcode-version', 'xcode-build',
  ]);
  if (options.validation !== 'docs/validation.json') {
    fail('--validation must be docs/validation.json.');
  }
  if (options.evidence !== releaseEvidencePath) {
    fail(`--evidence must be ${releaseEvidencePath}.`);
  }
  if (!['archive', 'upload'].includes(options.stage)) fail('stage must be archive or upload.');
  if (!/^([1-9][0-9]{0,3})\.([1-9][0-9]?)\.0$/.test(options['build-number'])) {
    fail('build-number does not match the bounded CI build-number format.');
  }
  const xcode = verifyReleaseXcode({
    build: options['xcode-build'],
    version: options['xcode-version'],
  }, 'Workflow Xcode toolchain');
  const root = path.resolve(options.root ?? projectRoot);
  const headCommit = git(root, ['rev-parse', 'HEAD']);
  if (headCommit !== options['release-commit']) {
    fail('Checked-out HEAD changed after release preflight.');
  }
  const changed = changedSourcePaths(root);
  if (!changed.includes('docs/validation.json')) {
    fail('The canonical full verifier did not refresh docs/validation.json.');
  }
  const unexpected = changed.filter((entry) => entry !== 'docs/validation.json');
  if (unexpected.length > 0) {
    fail(`Verification changed release source: ${unexpected.join(', ')}.`);
  }
  const candidateDigest = candidateDigestForRoot(root);
  const validationPath = path.resolve(root, options.validation);
  const validation = parseUniqueJson(await readFile(validationPath), 'docs/validation.json');
  if (typeof validation.generatedAt !== 'string' || Number.isNaN(Date.parse(validation.generatedAt))) {
    fail('The validation record has no valid generation timestamp.');
  }
  const trackerSummary = await trackerForCommit(root, options['release-commit']);
  const checks = verifyPassedValidation(
    validation,
    options['release-version'],
    trackerSummary,
    candidateDigest,
  );
  const artifacts = {};
  for (const [name, relative] of Object.entries(artifactEvidencePaths)) {
    artifacts[name] = { path: relative, sha256: await sha256(path.join(root, relative)) };
  }
  const evidence = {
    recordType: 'local-sandbox-apple-release-evidence',
    schemaVersion: 1,
    releaseCommit: headCommit,
    releaseVersion: options['release-version'],
    buildNumber: options['build-number'],
    stage: options.stage,
    xcode,
    validationSha256: await sha256(validationPath),
    checks: checks.map((check) => check.label),
    artifacts,
    tracker: trackerSummary.binding,
    validation,
  };
  const evidencePath = path.resolve(root, options.evidence);
  await mkdir(path.dirname(evidencePath), { recursive: true });
  await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o644 });
  process.stdout.write(`${JSON.stringify({
    status: 'validated',
    releaseCommit: headCommit,
    releaseVersion: options['release-version'],
    buildNumber: options['build-number'],
    checks: checks.length,
    evidence: path.relative(root, evidencePath),
  })}\n`);
}

async function main() {
  const [command, ...arguments_] = process.argv.slice(2);
  const options = parseArguments(arguments_);
  if (command === 'prepare') return prepare(options);
  if (command === 'readiness') return readiness(options);
  if (command === 'authorize') return authorize(options);
  if (command === 'validate') return validate(options);
  fail('Usage: apple_ci.mjs prepare|readiness|authorize|validate --name value ...');
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
