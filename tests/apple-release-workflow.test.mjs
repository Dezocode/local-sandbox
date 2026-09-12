import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  buildNumberFor,
  parseUniqueJson,
  verifyAppleActionReadiness,
  verifyAppleArchiveAuthorization,
  verifyAppleReleaseEvidence,
  verifyPassedValidation,
  verifyReleaseInputs,
  verifyReleaseXcode,
} from '../scripts/release/apple_ci.mjs';

const workflow = await readFile(new URL('../.github/workflows/apple-release.yml', import.meta.url), 'utf8');
const verificationWorkflow = await readFile(new URL('../.github/workflows/verify.yml', import.meta.url), 'utf8');
const fullVerificationChecks = JSON.parse(await readFile(
  new URL('../scripts/release/verification-checks.json', import.meta.url),
  'utf8',
));
const portableVerificationChecks = JSON.parse(await readFile(
  new URL('../scripts/release/portable-verification-checks.json', import.meta.url),
  'utf8',
));
const appleCiSource = await readFile(new URL('../scripts/release/apple_ci.mjs', import.meta.url), 'utf8');
const appleLocalSource = await readFile(new URL('../scripts/release/apple.py', import.meta.url), 'utf8');
const releaseGuide = await readFile(new URL('../docs/ROADMAP-AUTOMATION.md', import.meta.url), 'utf8');
const releaseEvidenceGuide = await readFile(new URL('../docs/RELEASE.md', import.meta.url), 'utf8');
const verifyReleaseSource = await readFile(new URL('../scripts/verify-release.mjs', import.meta.url), 'utf8');
const appleCiPath = new URL('../scripts/release/apple_ci.mjs', import.meta.url);
const candidateDigestPath = fileURLToPath(
  new URL('../scripts/release/candidate_digest.py', import.meta.url),
);
const commit = 'a'.repeat(40);
const fixtureCandidateDigest = '5'.repeat(64);
const releaseXcode = Object.freeze({ build: '27A266a', version: '27.0' });
const requiredValidationChecks = fullVerificationChecks;
const gateIds = [
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
const pendingAppleGates = new Set(['REL-03', 'REL-04', 'REL-06', 'REL-07']);
const canonicalArtifactPaths = [
  'public/downloads/Local-Sandbox-Source.zip',
  'public/downloads/Local-Sandbox-Selfhost.zip',
  'public/downloads/Local-Sandbox-Setup-Guide.pdf',
];

function digest(data) {
  return createHash('sha256').update(data).digest('hex');
}

function candidateDigestForRoot(root) {
  return execFileSync(
    process.env.LOCAL_SANDBOX_RELEASE_PYTHON || 'python3',
    [candidateDigestPath, '--root', root],
    { cwd: root, encoding: 'utf8' },
  ).trim();
}

function appleTrackerSummary() {
  const gates = gateIds.map((id) => ({
    evidenceSha256: digest(Buffer.from(`exact tracker evidence ${id} build 27A266a`)),
    id,
    status: id === 'REL-03' ? 'IN PROGRESS' : pendingAppleGates.has(id) ? 'NOT STARTED' : 'PASS',
  }));
  return {
    binding: {
      evidenceSha256: '1'.repeat(64),
      path: 'qualification/Local-Sandbox-0.3-Progress.xlsx',
      requirementsSha256: '2'.repeat(64),
      sha256: '3'.repeat(64),
      snapshotPath: 'qualification/Local-Sandbox-0.3-Progress.snapshot.json',
      snapshotSha256: '4'.repeat(64),
    },
    evidenceRows: 57,
    finalQualificationClaimed: false,
    gates,
    requirementsRows: 57,
    status: 'tracker-snapshot-verified',
  };
}

function passedValidationChecks(trackerSummary = appleTrackerSummary()) {
  return requiredValidationChecks.map((label) => ({
    label,
    status: 'passed',
    ...(label === 'Release qualification tracker' ? { tracker: trackerSummary.binding } : {}),
  }));
}

test('Protected Apple authorization JSON rejects duplicate member names recursively', () => {
  for (const document of [
    '{"recordType":"contradictory","recordType":"valid"}',
    '{"xcode":{"version":"contradictory","version":"27.0"}}',
  ]) {
    assert.throws(
      () => parseUniqueJson(Buffer.from(document), 'Protected Apple authorization JSON'),
      /duplicate object member name/,
    );
  }
});

test('Apple CI removes protected readiness before helper processes can inherit it', () => {
  const program = `
    process.env.LS_APPLE_ACTION_READINESS_JSON = 'protected';
    await import(${JSON.stringify(appleCiPath.href)});
    if (Object.hasOwn(process.env, 'LS_APPLE_ACTION_READINESS_JSON')) process.exit(91);
  `;
  execFileSync(process.execPath, ['--input-type=module', '--eval', program]);
});

function appleReadiness({
  validationData,
  artifacts,
  readyAt,
  releaseCommit = commit,
  trackerSummary = appleTrackerSummary(),
  overrides = {},
}) {
  const validation = JSON.parse(validationData.toString('utf8'));
  return {
    recordType: 'local-sandbox-apple-action-readiness',
    schemaVersion: 1,
    releaseState: 'READY',
    commit: releaseCommit,
    version: '0.3.0',
    readyAt,
    totalGates: 57,
    passedGates: 53,
    completionPercent: 92.98245614035088,
    xcode: releaseXcode,
    gates: trackerSummary.gates,
    tracker: trackerSummary.binding,
    verification: {
      path: 'docs/validation.json',
      commit: releaseCommit,
      sha256: digest(validationData),
      automatedStatus: 'passed',
      candidateDigest: validation.candidateDigest,
    },
    artifacts: canonicalArtifactPaths.map((artifactPath) => ({
      path: artifactPath,
      sha256: digest(artifacts.get(artifactPath)),
      bytes: artifacts.get(artifactPath).length,
    })),
    ...overrides,
  };
}

function appleReleaseEvidence({
  validationData,
  artifacts,
  trackerSummary = appleTrackerSummary(),
  buildNumber = '321.4.0',
  stage = 'archive',
}) {
  const validation = JSON.parse(validationData.toString('utf8'));
  return {
    recordType: 'local-sandbox-apple-release-evidence',
    schemaVersion: 1,
    releaseCommit: commit,
    releaseVersion: '0.3.0',
    buildNumber,
    stage,
    xcode: releaseXcode,
    validationSha256: digest(validationData),
    checks: validation.automatedVerification.checks.map((check) => check.label),
    artifacts: {
      guide: {
        path: canonicalArtifactPaths[2],
        sha256: digest(artifacts.get(canonicalArtifactPaths[2])),
      },
      selfhost: {
        path: canonicalArtifactPaths[1],
        sha256: digest(artifacts.get(canonicalArtifactPaths[1])),
      },
      source: {
        path: canonicalArtifactPaths[0],
        sha256: digest(artifacts.get(canonicalArtifactPaths[0])),
      },
    },
    tracker: trackerSummary.binding,
    validation,
  };
}

function appleAuthorizationReceipt({
  actionReadinessData,
  readiness,
  evidenceData,
  buildNumber = '321.4.0',
  stage = 'archive',
  verifiedAt = new Date().toISOString(),
}) {
  return {
    actionReadinessSha256: digest(actionReadinessData),
    buildNumber,
    readiness,
    recordType: 'local-sandbox-apple-action-readiness-receipt',
    releaseCommit: commit,
    releaseEvidence: {
      path: 'release-output/apple-release-evidence.json',
      sha256: digest(evidenceData),
    },
    releaseVersion: '0.3.0',
    schemaVersion: 1,
    stage,
    verifiedAt,
  };
}

test('Apple CI build numbers are unique for a workflow run attempt and stay in conservative bundle bounds', () => {
  assert.equal(buildNumberFor('1', '1'), '1.1.0');
  assert.equal(buildNumberFor('9999', '99'), '9999.99.0');
  assert.notEqual(buildNumberFor('81', '1'), buildNumberFor('81', '2'));
  assert.notEqual(buildNumberFor('81', '1'), buildNumberFor('82', '1'));
  for (const [run, attempt] of [['0', '1'], ['01', '1'], ['10000', '1'], ['1', '0'], ['1', '100']]) {
    assert.throws(() => buildNumberFor(run, attempt));
  }
});

test('Apple release inputs bind the checked out commit and package version to the dispatch', () => {
  const valid = {
    releaseCommit: commit,
    triggerCommit: commit,
    requestedVersion: '0.3.0',
    packageVersion: '0.3.0',
    headCommit: commit,
  };
  assert.doesNotThrow(() => verifyReleaseInputs(valid));
  assert.throws(() => verifyReleaseInputs({ ...valid, triggerCommit: 'b'.repeat(40) }), /must equal/);
  assert.throws(() => verifyReleaseInputs({ ...valid, requestedVersion: '0.3.1' }), /does not match/);
  assert.throws(() => verifyReleaseInputs({ ...valid, releaseCommit: 'main' }), /full lowercase/);
});

test('Apple release actions require the exact Xcode 27 RC toolchain', () => {
  assert.deepEqual(verifyReleaseXcode(releaseXcode), releaseXcode);
  assert.throws(
    () => verifyReleaseXcode({ build: '27A5252f', version: '27.0' }),
    /27A266a.*27A5252f/,
  );
  assert.throws(
    () => verifyReleaseXcode({ build: '27A266a', version: '27.0', channel: 'RC' }),
    /missing or unexpected fields/,
  );
});

test('Apple release validation requires a passed full verifier with freshness and artifact audit', () => {
  const now = new Date();
  const trackerSummary = appleTrackerSummary();
  const record = {
    recordType: 'local-sandbox-release-validation',
    schemaVersion: 1,
    version: '0.3.0',
    generatedAt: new Date(now.getTime() - 60_000).toISOString(),
    candidateDigest: fixtureCandidateDigest,
    automatedVerification: {
      status: 'passed',
      checks: passedValidationChecks(trackerSummary),
    },
  };
  assert.equal(
    verifyPassedValidation(
      record,
      '0.3.0',
      trackerSummary,
      fixtureCandidateDigest,
      now,
    ).length,
    requiredValidationChecks.length,
  );
  assert.throws(
    () => verifyPassedValidation(
      { ...record, candidateDigest: '0'.repeat(64) },
      '0.3.0',
      trackerSummary,
      fixtureCandidateDigest,
      now,
    ),
    /candidateDigest does not match/,
  );
  assert.throws(
    () => verifyPassedValidation(
      { ...record, automatedVerification: { ...record.automatedVerification, status: 'failed' } },
      '0.3.0',
      trackerSummary,
      fixtureCandidateDigest,
      now,
    ),
    /did not record a passed result/,
  );
  assert.throws(
    () => verifyPassedValidation({
      ...record,
      automatedVerification: { status: 'passed', checks: record.automatedVerification.checks.slice(1) },
    }, '0.3.0', trackerSummary, fixtureCandidateDigest, now),
    /missing required full-verifier checks/,
  );

  const duplicate = structuredClone(record);
  duplicate.automatedVerification.checks.push({
    label: requiredValidationChecks.at(-1),
    status: 'passed',
  });
  assert.throws(
    () => verifyPassedValidation(duplicate, '0.3.0', trackerSummary, fixtureCandidateDigest, now),
    /duplicate full-verifier check/,
  );

  const unexpected = structuredClone(record);
  unexpected.automatedVerification.checks.push({ label: 'Unreviewed release stage', status: 'passed' });
  assert.throws(
    () => verifyPassedValidation(unexpected, '0.3.0', trackerSummary, fixtureCandidateDigest, now),
    /unexpected full-verifier checks/,
  );

  const reordered = structuredClone(record);
  [reordered.automatedVerification.checks[0], reordered.automatedVerification.checks[1]] = [
    reordered.automatedVerification.checks[1],
    reordered.automatedVerification.checks[0],
  ];
  assert.throws(
    () => verifyPassedValidation(reordered, '0.3.0', trackerSummary, fixtureCandidateDigest, now),
    /canonical execution order/,
  );

  assert.throws(
    () => verifyPassedValidation({
      ...record,
      generatedAt: new Date(now.getTime() - (25 * 60 * 60 * 1000)).toISOString(),
    }, '0.3.0', trackerSummary, fixtureCandidateDigest, now),
    /older than 24 hours/,
  );
  assert.throws(
    () => verifyPassedValidation({
      ...record,
      generatedAt: new Date(now.getTime() + (6 * 60 * 1000)).toISOString(),
    }, '0.3.0', trackerSummary, fixtureCandidateDigest, now),
    /generatedAt is in the future/,
  );

  const missingTrackerBinding = structuredClone(record);
  delete missingTrackerBinding.automatedVerification.checks.find(
    (check) => check.label === 'Release qualification tracker',
  ).tracker;
  assert.throws(
    () => verifyPassedValidation(
      missingTrackerBinding,
      '0.3.0',
      trackerSummary,
      fixtureCandidateDigest,
      now,
    ),
    /tracker binding is missing or differs/,
  );

  const changedTrackerBinding = structuredClone(record);
  changedTrackerBinding.automatedVerification.checks.find(
    (check) => check.label === 'Release qualification tracker',
  ).tracker.snapshotSha256 = '0'.repeat(64);
  assert.throws(
    () => verifyPassedValidation(
      changedTrackerBinding,
      '0.3.0',
      trackerSummary,
      fixtureCandidateDigest,
      now,
    ),
    /tracker binding is missing or differs/,
  );
});

test('Apple action readiness requires exactly 53 PASS gates and keeps REL-03 causal', () => {
  const generatedAt = new Date(Date.now() - 120_000).toISOString();
  const readyAt = new Date(Date.now() - 60_000).toISOString();
  const trackerSummary = appleTrackerSummary();
  const validationData = Buffer.from(JSON.stringify({
    recordType: 'local-sandbox-release-validation',
    schemaVersion: 1,
    version: '0.3.0',
    generatedAt,
    candidateDigest: fixtureCandidateDigest,
    automatedVerification: {
      status: 'passed',
      checks: passedValidationChecks(trackerSummary),
    },
  }));
  const artifacts = new Map(canonicalArtifactPaths.map((artifactPath) => [
    artifactPath,
    Buffer.from(`bytes for ${artifactPath}`),
  ]));
  const record = appleReadiness({ validationData, artifacts, readyAt, trackerSummary });
  const input = {
    record,
    releaseCommit: commit,
    releaseVersion: '0.3.0',
    committedValidationData: validationData,
    committedArtifacts: artifacts,
    trackerSummary,
    candidateDigest: fixtureCandidateDigest,
    now: new Date(),
  };
  const verified = verifyAppleActionReadiness(input);
  assert.deepEqual(verified.gateState, {
    inProgressGate: 'REL-03',
    inProgressStatus: 'IN PROGRESS',
    passedGates: 53,
    totalGates: 57,
  });
  assert.deepEqual(verified.validation, {
    candidateDigest: fixtureCandidateDigest,
    path: 'docs/validation.json',
    sha256: digest(validationData),
  });
  assert.equal(verified.commit, commit);
  assert.equal(verified.version, '0.3.0');
  assert.deepEqual(verified.xcode, releaseXcode);
  assert.equal(verified.freshness.readyAt, readyAt);
  assert.deepEqual(verified.artifacts, canonicalArtifactPaths.map((artifactPath) => ({
    bytes: artifacts.get(artifactPath).length,
    path: artifactPath,
    sha256: digest(artifacts.get(artifactPath)),
  })));

  const reordered = structuredClone(record);
  [reordered.gates[0], reordered.gates[1]] = [reordered.gates[1], reordered.gates[0]];
  assert.throws(
    () => verifyAppleActionReadiness({ ...input, record: reordered }),
    /canonical 0\.3 gate order/,
  );

  const prepassed = structuredClone(record);
  prepassed.gates.find((gate) => gate.id === 'REL-03').status = 'PASS';
  assert.throws(
    () => verifyAppleActionReadiness({ ...input, record: prepassed }),
    /REL-03 cannot be pre-passed/,
  );
  const futureOutcome = structuredClone(record);
  futureOutcome.gates.find((gate) => gate.id === 'REL-04').status = 'PASS';
  assert.throws(
    () => verifyAppleActionReadiness({ ...input, record: futureOutcome }),
    /must not be PASS/,
  );
  const changedValidation = structuredClone(record);
  changedValidation.verification.sha256 = '0'.repeat(64);
  assert.throws(
    () => verifyAppleActionReadiness({ ...input, record: changedValidation }),
    /committed validation digest/,
  );
  const changedCandidate = structuredClone(record);
  changedCandidate.verification.candidateDigest = '0'.repeat(64);
  assert.throws(
    () => verifyAppleActionReadiness({ ...input, record: changedCandidate }),
    /candidateDigest does not match/,
  );
  const changedArtifact = structuredClone(record);
  changedArtifact.artifacts[0].bytes += 1;
  assert.throws(
    () => verifyAppleActionReadiness({ ...input, record: changedArtifact }),
    /committed byte count/,
  );
  const betaToolchain = structuredClone(record);
  betaToolchain.xcode.build = '27A5252f';
  assert.throws(
    () => verifyAppleActionReadiness({ ...input, record: betaToolchain }),
    /27A266a.*27A5252f/,
  );
  const changedEvidence = structuredClone(record);
  changedEvidence.gates[0].evidenceSha256 = '0'.repeat(64);
  assert.throws(
    () => verifyAppleActionReadiness({ ...input, record: changedEvidence }),
    /status or evidence differs from the tracker snapshot/,
  );
  const changedTracker = structuredClone(record);
  changedTracker.tracker.requirementsSha256 = '0'.repeat(64);
  assert.throws(
    () => verifyAppleActionReadiness({ ...input, record: changedTracker }),
    /does not exactly match the recomputed tracker binding/,
  );
});

test('Apple archive authorization binds the current commit, build, stage, evidence, and artifacts', () => {
  const now = new Date('2026-09-11T12:00:00.000Z');
  const trackerSummary = appleTrackerSummary();
  const validationData = Buffer.from(JSON.stringify({
    recordType: 'local-sandbox-release-validation',
    schemaVersion: 1,
    version: '0.3.0',
    generatedAt: '2026-09-11T11:58:00.000Z',
    candidateDigest: fixtureCandidateDigest,
    automatedVerification: {
      status: 'passed',
      checks: passedValidationChecks(trackerSummary),
    },
  }));
  const artifacts = new Map(canonicalArtifactPaths.map((artifactPath) => [
    artifactPath,
    Buffer.from(`bytes for ${artifactPath}`),
  ]));
  const evidence = appleReleaseEvidence({ validationData, artifacts, trackerSummary });
  const evidenceData = Buffer.from(JSON.stringify(evidence));
  const actionReadinessRecord = appleReadiness({
    validationData,
    artifacts,
    trackerSummary,
    readyAt: '2026-09-11T11:58:30.000Z',
  });
  const actionReadinessData = Buffer.from(JSON.stringify(actionReadinessRecord));
  const readiness = verifyAppleActionReadiness({
    record: actionReadinessRecord,
    releaseCommit: commit,
    releaseVersion: '0.3.0',
    committedValidationData: validationData,
    committedArtifacts: artifacts,
    trackerSummary,
    candidateDigest: fixtureCandidateDigest,
    now,
  });
  const receipt = appleAuthorizationReceipt({
    actionReadinessData,
    readiness,
    evidenceData,
    verifiedAt: '2026-09-11T11:59:00.000Z',
  });
  const input = {
    receipt,
    actionReadinessRecord,
    actionReadinessData,
    evidence,
    evidenceData,
    releaseCommit: commit,
    releaseVersion: '0.3.0',
    buildNumber: '321.4.0',
    stage: 'archive',
    xcodeVersion: releaseXcode.version,
    xcodeBuild: releaseXcode.build,
    committedValidationData: validationData,
    currentValidationData: validationData,
    committedArtifacts: artifacts,
    currentArtifacts: artifacts,
    trackerSummary,
    candidateDigest: fixtureCandidateDigest,
    now,
  };

  assert.equal(verifyAppleReleaseEvidence({
    record: evidence,
    releaseCommit: commit,
    releaseVersion: '0.3.0',
    buildNumber: '321.4.0',
    stage: 'archive',
    xcodeVersion: releaseXcode.version,
    xcodeBuild: releaseXcode.build,
    validationData,
    artifacts,
    trackerSummary,
    candidateDigest: fixtureCandidateDigest,
    now,
  }).checks, requiredValidationChecks.length);
  assert.equal(verifyAppleArchiveAuthorization(input).status, 'authorized');
  assert.throws(
    () => verifyAppleArchiveAuthorization({
      ...input,
      receipt: { ...receipt, actionReadinessSha256: 'b'.repeat(64) },
    }),
    /does not match the protected record bytes/,
  );
  assert.throws(
    () => verifyAppleArchiveAuthorization({ ...input, actionReadinessData: undefined }),
    /does not match the protected record bytes/,
  );
  assert.throws(
    () => verifyAppleArchiveAuthorization({ ...input, receipt: undefined }),
    /wrong record type or schema version/,
  );
  assert.throws(
    () => verifyAppleArchiveAuthorization({ ...input, buildNumber: '321.5.0' }),
    /selected build number and stage/,
  );
  assert.throws(
    () => verifyAppleArchiveAuthorization({
      ...input,
      receipt: { ...receipt, verifiedAt: '2026-09-10T11:58:59.000Z' },
    }),
    /older than 24 hours/,
  );
  const changedArtifacts = new Map(artifacts);
  changedArtifacts.set(canonicalArtifactPaths[0], Buffer.from('changed source bytes'));
  assert.throws(
    () => verifyAppleArchiveAuthorization({ ...input, currentArtifacts: changedArtifacts }),
    /differs from the selected release commit/,
  );
  const changedEvidenceData = Buffer.from(`${evidenceData.toString('utf8')}\n`);
  assert.throws(
    () => verifyAppleArchiveAuthorization({ ...input, evidenceData: changedEvidenceData }),
    /does not match the release evidence file/,
  );
  const changedReadiness = structuredClone(actionReadinessRecord);
  changedReadiness.readyAt = '2026-09-11T11:58:45.000Z';
  const changedReadinessData = Buffer.from(JSON.stringify(changedReadiness));
  assert.throws(
    () => verifyAppleArchiveAuthorization({
      ...input,
      actionReadinessRecord: changedReadiness,
      actionReadinessData: changedReadinessData,
      receipt: { ...receipt, actionReadinessSha256: digest(changedReadinessData) },
    }),
    /canonical readiness summary/,
  );
});

test('Apple release preflight writes bounded run state and evidence from a clean immutable checkout', async (context) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'local-sandbox-apple-ci-'));
  context.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'docs'), { recursive: true });
  await mkdir(path.join(root, 'public', 'downloads'), { recursive: true });
  await writeFile(path.join(root, 'package.json'), '{"version":"0.3.0"}\n');
  execFileSync(process.env.LOCAL_SANDBOX_RELEASE_PYTHON || 'python3', [
    fileURLToPath(new URL('./release_tracker_fixture.py', import.meta.url)),
    '--root', root,
    '--profile', 'apple',
  ]);
  const initialTrackerSummary = JSON.parse(execFileSync(
    process.env.LOCAL_SANDBOX_RELEASE_PYTHON || 'python3',
    [fileURLToPath(new URL('../scripts/release/tracker.py', import.meta.url)), 'verify-envelope'],
    {
      encoding: 'utf8',
      input: JSON.stringify({
        workbook: (await readFile(path.join(
          root,
          'qualification/Local-Sandbox-0.3-Progress.xlsx',
        ))).toString('base64'),
        snapshot: (await readFile(path.join(
          root,
          'qualification/Local-Sandbox-0.3-Progress.snapshot.json',
        ))).toString('base64'),
      }),
    },
  ));
  const committedGeneratedAt = new Date(Date.now() - 120_000).toISOString();
  const committedValidation = {
    recordType: 'local-sandbox-release-validation',
    schemaVersion: 1,
    version: '0.3.0',
    generatedAt: committedGeneratedAt,
    candidateDigest: '0'.repeat(64),
    automatedVerification: {
      status: 'passed',
      checks: passedValidationChecks(initialTrackerSummary),
    },
  };
  let committedValidationData = Buffer.from(`${JSON.stringify(committedValidation)}\n`);
  await writeFile(path.join(root, 'docs', 'validation.json'), committedValidationData);
  await writeFile(path.join(root, '.gitignore'), 'release-output/\n');
  for (const [name, value] of [
    ['Local-Sandbox-Source.zip', 'source'],
    ['Local-Sandbox-Selfhost.zip', 'selfhost'],
    ['Local-Sandbox-Setup-Guide.pdf', 'guide'],
  ]) {
    await writeFile(path.join(root, 'public', 'downloads', name), value);
  }
  execFileSync('git', ['init', '--quiet'], { cwd: root });
  execFileSync('git', ['config', 'user.name', 'Local Sandbox Test'], { cwd: root });
  execFileSync('git', ['config', 'user.email', 'test@localhost'], { cwd: root });
  execFileSync('git', ['add', '.'], { cwd: root });
  committedValidation.candidateDigest = candidateDigestForRoot(root);
  committedValidationData = Buffer.from(`${JSON.stringify(committedValidation)}\n`);
  await writeFile(path.join(root, 'docs', 'validation.json'), committedValidationData);
  execFileSync('git', ['add', 'docs/validation.json'], { cwd: root });
  execFileSync('git', ['-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'fixture'], { cwd: root });
  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  const githubEnvironment = path.join(root, '.git', 'github-env');
  const githubOutput = path.join(root, '.git', 'github-output');
  const prepareOutput = execFileSync(process.execPath, [
    appleCiPath.pathname,
    'prepare',
    '--root', root,
    '--release-commit', head,
    '--trigger-commit', head,
    '--release-version', '0.3.0',
    '--run-number', '321',
    '--run-attempt', '4',
    '--github-env', githubEnvironment,
    '--github-output', githubOutput,
  ], { encoding: 'utf8' });
  assert.equal(JSON.parse(prepareOutput).buildNumber, '321.4.0');
  assert.equal(await readFile(githubEnvironment, 'utf8'), 'LS_BUILD_NUMBER=321.4.0\n');
  assert.equal(await readFile(githubOutput, 'utf8'), 'build_number=321.4.0\n');

  const passedValidation = {
    ...committedValidation,
    generatedAt: new Date(Date.now() - 30_000).toISOString(),
  };
  await writeFile(path.join(root, 'docs', 'validation.json'), `${JSON.stringify(passedValidation)}\n`);
  const validateOutput = execFileSync(process.execPath, [
    appleCiPath.pathname,
    'validate',
    '--root', root,
    '--release-commit', head,
    '--release-version', '0.3.0',
    '--build-number', '321.4.0',
    '--stage', 'archive',
    '--xcode-version', releaseXcode.version,
    '--xcode-build', releaseXcode.build,
    '--validation', 'docs/validation.json',
    '--evidence', 'release-output/apple-release-evidence.json',
  ], { encoding: 'utf8' });
  assert.equal(JSON.parse(validateOutput).status, 'validated');
  const evidenceData = await readFile(path.join(root, 'release-output', 'apple-release-evidence.json'));
  const evidence = JSON.parse(evidenceData.toString('utf8'));
  assert.equal(evidence.releaseCommit, head);
  assert.equal(evidence.releaseVersion, '0.3.0');
  assert.equal(evidence.buildNumber, '321.4.0');
  assert.deepEqual(evidence.xcode, releaseXcode);
  assert.equal(evidence.validation.automatedVerification.status, 'passed');
  assert.match(evidence.artifacts.source.sha256, /^[0-9a-f]{64}$/);

  const committedArtifacts = new Map();
  for (const artifactPath of canonicalArtifactPaths) {
    committedArtifacts.set(artifactPath, await readFile(path.join(root, artifactPath)));
  }
  const trackerVerification = JSON.parse(execFileSync(
    process.env.LOCAL_SANDBOX_RELEASE_PYTHON || 'python3',
    [fileURLToPath(new URL('../scripts/release/tracker.py', import.meta.url)), 'verify', '--root', root],
    { encoding: 'utf8' },
  ));
  const { commit: verifiedTrackerCommit, ...trackerSummary } = trackerVerification;
  assert.equal(verifiedTrackerCommit, head);
  assert.deepEqual(trackerSummary.binding, initialTrackerSummary.binding);
  const readinessRecord = appleReadiness({
    validationData: committedValidationData,
    artifacts: committedArtifacts,
    readyAt: new Date(Date.now() - 60_000).toISOString(),
    releaseCommit: head,
    trackerSummary,
  });
  const readinessArguments = [
    appleCiPath.pathname,
    'readiness',
    '--root', root,
    '--release-commit', head,
    '--release-version', '0.3.0',
    '--build-number', '321.4.0',
    '--stage', 'archive',
    '--xcode-version', releaseXcode.version,
    '--xcode-build', releaseXcode.build,
    '--validation', 'docs/validation.json',
    '--evidence', 'release-output/apple-release-evidence.json',
    '--receipt', 'release-output/apple-action-readiness-receipt.json',
  ];
  const readinessJson = JSON.stringify(readinessRecord);
  for (const duplicateJson of [
    readinessJson.replace('{', '{"recordType":"contradictory",'),
    readinessJson.replace('"xcode":{', '"xcode":{"version":"contradictory",'),
  ]) {
    assert.throws(
      () => execFileSync(process.execPath, readinessArguments, {
        encoding: 'utf8',
        env: { ...process.env, LS_APPLE_ACTION_READINESS_JSON: duplicateJson },
      }),
      /duplicate object member name/,
    );
  }
  const readinessOutput = execFileSync(process.execPath, readinessArguments, {
    encoding: 'utf8',
    env: { ...process.env, LS_APPLE_ACTION_READINESS_JSON: readinessJson },
  });
  assert.deepEqual(
    {
      passedGates: JSON.parse(readinessOutput).passedGates,
      pendingGate: JSON.parse(readinessOutput).pendingGate,
      status: JSON.parse(readinessOutput).status,
    },
    { passedGates: 53, pendingGate: 'REL-03', status: 'action-ready' },
  );
  const readinessReceiptPath = path.join(
    root,
    'release-output',
    'apple-action-readiness-receipt.json',
  );
  const readinessReceiptData = await readFile(readinessReceiptPath);
  const readinessReceipt = JSON.parse(readinessReceiptData.toString('utf8'));
  assert.equal(readinessReceipt.recordType, 'local-sandbox-apple-action-readiness-receipt');
  assert.equal(readinessReceipt.releaseCommit, head);
  assert.equal(readinessReceipt.buildNumber, '321.4.0');
  assert.equal(readinessReceipt.stage, 'archive');
  assert.equal(readinessReceipt.releaseEvidence.path, 'release-output/apple-release-evidence.json');
  assert.equal(readinessReceipt.actionReadinessSha256, digest(Buffer.from(JSON.stringify(readinessRecord))));
  assert.equal(readinessReceipt.readiness.commit, head);
  assert.equal(readinessReceipt.readiness.version, '0.3.0');
  assert.equal(readinessReceipt.readiness.validation.sha256, digest(committedValidationData));
  assert.deepEqual(readinessReceipt.readiness.xcode, releaseXcode);
  assert.deepEqual(readinessReceipt.readiness.gateState, {
    inProgressGate: 'REL-03',
    inProgressStatus: 'IN PROGRESS',
    passedGates: 53,
    totalGates: 57,
  });
  assert.deepEqual(readinessReceipt.readiness.artifacts, canonicalArtifactPaths.map((artifactPath) => ({
    bytes: committedArtifacts.get(artifactPath).length,
    path: artifactPath,
    sha256: digest(committedArtifacts.get(artifactPath)),
  })));
  const receiptText = JSON.stringify(readinessReceipt);
  assert.doesNotMatch(receiptText, /proof REL-/);
  assert.doesNotMatch(receiptText, /"gates"/);

  const authorizationArguments = [
    appleCiPath.pathname,
    'authorize',
    '--root', root,
    '--release-commit', head,
    '--release-version', '0.3.0',
    '--build-number', '321.4.0',
    '--stage', 'archive',
    '--xcode-version', releaseXcode.version,
    '--xcode-build', releaseXcode.build,
    '--validation', 'docs/validation.json',
    '--evidence', 'release-output/apple-release-evidence.json',
    '--receipt', 'release-output/apple-action-readiness-receipt.json',
  ];
  const authorizationEnvironment = {
    ...process.env,
    LS_APPLE_ACTION_READINESS_JSON: JSON.stringify(readinessRecord),
  };
  const authorizationOutput = execFileSync(process.execPath, authorizationArguments, {
    encoding: 'utf8',
    env: authorizationEnvironment,
  });
  assert.equal(JSON.parse(authorizationOutput).status, 'authorized');
  assert.deepEqual(JSON.parse(authorizationOutput).xcode, releaseXcode);

  const trackerPath = path.join(root, 'qualification', 'Local-Sandbox-0.3-Progress.xlsx');
  const trackerSnapshotPath = path.join(
    root,
    'qualification',
    'Local-Sandbox-0.3-Progress.snapshot.json',
  );
  const trackerData = await readFile(trackerPath);
  const trackerSnapshotData = await readFile(trackerSnapshotPath);
  await writeFile(trackerPath, Buffer.concat([trackerData, Buffer.from('\n')]));
  assert.throws(
    () => execFileSync(process.execPath, readinessArguments, {
      env: authorizationEnvironment,
    }),
    /Local-Sandbox-0\.3-Progress\.xlsx differs from the selected release commit/,
  );
  await writeFile(trackerPath, trackerData);
  await writeFile(trackerSnapshotPath, Buffer.concat([trackerSnapshotData, Buffer.from('\n')]));
  assert.throws(
    () => execFileSync(process.execPath, authorizationArguments, {
      env: authorizationEnvironment,
    }),
    /Local-Sandbox-0\.3-Progress\.snapshot\.json differs from the selected release commit/,
  );
  await writeFile(trackerSnapshotPath, trackerSnapshotData);

  await writeFile(
    readinessReceiptPath,
    readinessReceiptData.toString('utf8').replace('{', '{"recordType":"contradictory",'),
  );
  assert.throws(
    () => execFileSync(process.execPath, authorizationArguments, { env: authorizationEnvironment }),
    /duplicate object member name/,
  );
  await writeFile(readinessReceiptPath, readinessReceiptData);
  const evidencePath = path.join(root, 'release-output', 'apple-release-evidence.json');
  await writeFile(
    evidencePath,
    evidenceData.toString('utf8').replace('"xcode": {', '"xcode": {"version":"contradictory",'),
  );
  assert.throws(
    () => execFileSync(process.execPath, authorizationArguments, { env: authorizationEnvironment }),
    /duplicate object member name/,
  );
  await writeFile(evidencePath, evidenceData);
  assert.throws(
    () => execFileSync(process.execPath, [
      ...authorizationArguments.slice(0, authorizationArguments.indexOf('--build-number') + 1),
      '321.5.0',
      ...authorizationArguments.slice(authorizationArguments.indexOf('--build-number') + 2),
    ], { env: authorizationEnvironment }),
    /selected build number and stage/,
  );

  const fabricatedReceipt = {
    ...readinessReceipt,
    actionReadinessSha256: 'b'.repeat(64),
  };
  await writeFile(
    path.join(root, 'release-output', 'apple-action-readiness-receipt.json'),
    `${JSON.stringify(fabricatedReceipt, null, 2)}\n`,
  );
  assert.throws(
    () => execFileSync(process.execPath, authorizationArguments, { env: authorizationEnvironment }),
    /does not match the protected record bytes/,
  );
  await writeFile(
    path.join(root, 'release-output', 'apple-action-readiness-receipt.json'),
    `${JSON.stringify(readinessReceipt, null, 2)}\n`,
  );
  assert.throws(
    () => execFileSync(process.execPath, authorizationArguments, {
      env: { ...process.env, LS_APPLE_ACTION_READINESS_JSON: '' },
    }),
    /environment secret is missing/,
  );

  await writeFile(
    path.join(root, 'release-output', 'apple-action-readiness-receipt.json'),
    `${JSON.stringify({ ...readinessReceipt, verifiedAt: '2000-01-01T00:00:00.000Z' }, null, 2)}\n`,
  );
  assert.throws(
    () => execFileSync(process.execPath, authorizationArguments, { env: authorizationEnvironment }),
    /older than 24 hours/,
  );
  await writeFile(
    path.join(root, 'release-output', 'apple-action-readiness-receipt.json'),
    `${JSON.stringify(readinessReceipt, null, 2)}\n`,
  );

  await rm(path.join(root, 'release-output', 'apple-action-readiness-receipt.json'));
  const prepassedReadiness = structuredClone(readinessRecord);
  prepassedReadiness.gates.find((gate) => gate.id === 'REL-03').status = 'PASS';
  assert.throws(() => execFileSync(process.execPath, [
    appleCiPath.pathname,
    'readiness',
    '--root', root,
    '--release-commit', head,
    '--release-version', '0.3.0',
    '--build-number', '321.4.0',
    '--stage', 'archive',
    '--xcode-version', releaseXcode.version,
    '--xcode-build', releaseXcode.build,
    '--validation', 'docs/validation.json',
    '--evidence', 'release-output/apple-release-evidence.json',
    '--receipt', 'release-output/apple-action-readiness-receipt.json',
  ], {
    encoding: 'utf8',
    env: { ...process.env, LS_APPLE_ACTION_READINESS_JSON: JSON.stringify(prepassedReadiness) },
  }), /REL-03 cannot be pre-passed/);
  await assert.rejects(
    readFile(path.join(root, 'release-output', 'apple-action-readiness-receipt.json')),
    { code: 'ENOENT' },
  );
});

test('Apple release workflow fixes the release identity, runner, actions, and credential scope', () => {
  assert.match(workflow, /release_commit:\n[\s\S]*release_version:/);
  assert.match(workflow, /if: github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /runs-on: xcode-27/);
  assert.doesNotMatch(workflow, /runs-on: macos-latest/);
  assert.match(workflow, /environment: apple-release/);
  assert.match(workflow, /permissions:\n  contents: read/);
  assert.match(workflow, /ref: \$\{\{ inputs\.release_commit \}\}/);
  assert.match(workflow, /persist-credentials: false/);

  const actionPins = [...workflow.matchAll(/uses: (actions\/[a-z-]+)@([0-9a-f]{40})/g)]
    .map((match) => `${match[1]}@${match[2]}`);
  assert.deepEqual(actionPins, [
    'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
    'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
    'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065',
    'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
  ]);
  assert.doesNotMatch(workflow, /uses: actions\/[a-z-]+@v[0-9]/);

  const jobEnvironment = workflow.slice(workflow.indexOf('    env:'), workflow.indexOf('    steps:'));
  assert.doesNotMatch(jobEnvironment, /ASC_KEY|APPLE_TEAM|APPLE_BUNDLE/);
  assert.equal(workflow.match(/secrets\.ASC_KEY_P8/g)?.length, 1);
  assert.equal(workflow.match(/secrets\.APPLE_ACTION_READINESS_JSON/g)?.length, 2);
  const readinessStep = workflow.slice(
    workflow.indexOf('- name: Validate protected Apple action readiness'),
    workflow.indexOf('- name: Materialize the temporary Apple API key'),
  );
  const finalActionStep = workflow.slice(
    workflow.indexOf('- name: Archive or upload'),
    workflow.indexOf('- name: Remove signing key'),
  );
  assert.equal(readinessStep.match(/secrets\.APPLE_ACTION_READINESS_JSON/g)?.length, 1);
  assert.equal(finalActionStep.match(/secrets\.APPLE_ACTION_READINESS_JSON/g)?.length, 1);
  assert.match(workflow, /Xcode 27\.0\\nBuild version 27A266a/);
  assert.match(workflow, /LS_XCODE_VERSION=27\.0\\nLS_XCODE_BUILD=27A266a/);
  assert.doesNotMatch(workflow, /case "\$LOCAL_SANDBOX_XCODE_VERSION"|27\.\*\)/);
});

test('Apple release workflow verifies everything before exposing the private key or archiving', () => {
  const orderedSteps = [
    'Run canonical full verification',
    'Run native simulator regression tests',
    'Validate release evidence',
    'Validate protected Apple action readiness',
    'Materialize the temporary Apple API key',
    'Archive or upload',
    'Remove signing key',
    'Retain the signed release evidence',
  ];
  let previous = -1;
  for (const step of orderedSteps) {
    const current = workflow.indexOf(step);
    assert.ok(current > previous, `${step} is out of order or missing`);
    previous = current;
  }
  assert.match(workflow, /LOCAL_SANDBOX_RELEASE_PYTHON: python3\n        run: pnpm run verify/);
  assert.match(workflow, /Remove signing key\n        if: always\(\)/);
  assert.match(appleCiSource, /LS_BUILD_NUMBER=\$\{buildNumber\}/);
  assert.match(appleCiSource, /did not refresh docs\/validation\.json/);
  assert.match(appleCiSource, /candidateDigestForRoot\(root\)/);
  assert.match(verifyReleaseSource, /\n    candidateDigest,\n/);
  assert.match(verifyReleaseSource, /currentCandidateDigest\(\) !== candidateDigest/);
  assert.match(workflow, /--github-output "\$GITHUB_OUTPUT"/);
  assert.match(workflow, /steps\.release\.outputs\.build_number/);
  assert.match(workflow, /--build-number "\$LS_BUILD_NUMBER"/);
  assert.match(workflow, /--receipt release-output\/apple-action-readiness-receipt\.json/);
  assert.match(workflow, /apple_ci\.mjs readiness[\s\S]*--build-number "\$LS_BUILD_NUMBER"[\s\S]*--stage "\$LS_STAGE"[\s\S]*--xcode-version "\$LS_XCODE_VERSION"[\s\S]*--xcode-build "\$LS_XCODE_BUILD"[\s\S]*--evidence release-output\/apple-release-evidence\.json/);
  assert.match(workflow, /apple\.py "\$LS_STAGE"[\s\S]*--release-commit "\$LS_RELEASE_COMMIT"[\s\S]*--release-version "\$LS_RELEASE_VERSION"/);
  assert.match(workflow, /LS_APPLE_ACTION_READINESS_JSON: \$\{\{ secrets\.APPLE_ACTION_READINESS_JSON \}\}/);
  assert.match(appleCiSource, /REL-03 cannot be pre-passed/);
  const appleMain = appleLocalSource.slice(appleLocalSource.indexOf('def main('));
  const releaseToolchainCall = appleMain.indexOf(
    'release_toolchain = release_xcode_toolchain(child_environment)',
  );
  const authorizationCall = appleMain.indexOf('require_release_authorization(', releaseToolchainCall);
  const sdkInspectionCall = appleMain.indexOf('"-showsdks"', authorizationCall);
  assert.ok(
    releaseToolchainCall >= 0 && releaseToolchainCall < authorizationCall,
    'apple.py must identify the actual Xcode release toolchain before authorization',
  );
  assert.ok(
    authorizationCall >= 0 && authorizationCall < sdkInspectionCall,
    'apple.py must authorize archive/upload before SDK inspection or build work',
  );
  assert.match(appleLocalSource, /REQUIRED_XCODE_VERSION = "27\.0"/);
  assert.match(appleLocalSource, /REQUIRED_XCODE_BUILD = "27A266a"/);
  assert.match(appleLocalSource, /readiness_json = os\.environ\.pop\(ACTION_READINESS_ENVIRONMENT, None\)/);
  assert.match(appleLocalSource, /with immutable_source_snapshot\(options\.release_commit/);
  assert.match(appleLocalSource, /recheck_release_xcode\(release_toolchain, child_environment\)/);
  assert.match(appleCiSource, /delete process\.env\.LS_APPLE_ACTION_READINESS_JSON/);
  assert.match(appleCiSource, /protectedAppleReadiness\(\)[\s\S]*verifyAppleArchiveAuthorization/);
  assert.match(appleCiSource, /gitBytes\(root, \['show'/);
});

test('Continuous verification separates portable Ubuntu evidence from canonical macOS release evidence', () => {
  assert.equal(fullVerificationChecks.length, 41);
  assert.equal(portableVerificationChecks.length, 18);
  const pinnedVerificationActions = [
    'actions/checkout@11d5960a326750d5838078e36cf38b85af677262',
    'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
    'actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065',
  ];
  for (const action of pinnedVerificationActions) {
    assert.equal(
      verificationWorkflow.split(action).length - 1,
      2,
      `${action} must be pinned once in each verification job`,
    );
  }
  assert.doesNotMatch(
    verificationWorkflow,
    /uses:\s+actions\/(?:checkout|setup-node|setup-python)@v\d+/,
  );
  assert.ok(fullVerificationChecks.includes('Release qualification tracker'));
  assert.ok(portableVerificationChecks.includes('Release qualification tracker'));
  assert.deepEqual(
    portableVerificationChecks,
    fullVerificationChecks.filter((label) => ![
      'Swift parser',
      'Native core compile',
      'Native core contracts',
      'Native execution core compile',
      'Native execution core contracts',
      'Provider qualification strict typecheck',
      'Provider qualification contracts compile',
      'Provider qualification contracts',
      'Shortcut package core compile',
      'Shortcut package core contracts',
      'Workspace crypto compile',
      'Workspace crypto interoperability',
      'Native account and sync compile',
      'Native account and sync contracts',
      'Native autosave compile',
      'Native autosave contracts',
      'Recursive sandbox compile',
      'Recursive sandbox contracts',
      'Workspace preparation compile',
      'Workspace preparation contracts',
      'GitHub transport compile',
      'GitHub transport contracts',
      'Apple metadata',
    ].includes(label)),
  );
  const compileSources = (compileLabel, followingLabel) => {
    const start = verifyReleaseSource.indexOf(`await run('${compileLabel}'`);
    const end = verifyReleaseSource.indexOf(`await run('${followingLabel}'`, start);
    assert.ok(start >= 0 && end > start, `${compileLabel} source block is missing`);
    return [...verifyReleaseSource.slice(start, end).matchAll(/'([^']+\.swift)'/g)]
      .map((match) => match[1]);
  };
  assert.deepEqual(
    compileSources('Workspace preparation compile', 'Workspace preparation contracts'),
    [
      'ios/LocalSandbox/Models.swift',
      'ios/LocalSandbox/ProviderRoutingCore.swift',
      'ios/LocalSandbox/WorkspacePreparation.swift',
      'tests/workspace-preparation-stubs.swift',
      'tests/workspace-preparation-contracts.test.swift',
    ],
  );
  assert.deepEqual(
    compileSources('GitHub transport compile', 'GitHub transport contracts'),
    [
      'ios/LocalSandbox/Models.swift',
      'ios/LocalSandbox/ProviderRoutingCore.swift',
      'ios/LocalSandbox/GitHubTransport.swift',
      'tests/github-transport.test.swift',
    ],
  );
  const webJob = verificationWorkflow.slice(
    verificationWorkflow.indexOf('  web-contracts:'),
    verificationWorkflow.indexOf('  native:'),
  );
  const nativeJob = verificationWorkflow.slice(verificationWorkflow.indexOf('  native:'));
  assert.match(webJob, /runs-on: ubuntu-latest/);
  assert.match(webJob, /verify-release\.mjs --portable-web-only/);
  assert.doesNotMatch(webJob, /pnpm run verify/);
  assert.match(nativeJob, /runs-on: macos-latest/);
  assert.match(nativeJob, /Run canonical full verification[\s\S]*run: pnpm run verify/);
  assert.match(nativeJob, /LOCAL_SANDBOX_RELEASE_PYTHON: python3/);
});

test('Release documentation states the build-number limits and hosted-runner limit', () => {
  assert.match(releaseGuide, /`run_number\.run_attempt\.0`/);
  assert.match(releaseGuide, /1 through 9,999/);
  assert.match(releaseGuide, /1 through 99/);
  assert.match(releaseGuide, /underlying hosted image revision can change/);
  assert.match(releaseGuide, /Xcode 27\.0 build `27A266a`/);
});

test('Release documentation separates repository bootstrap and protected causal readiness', () => {
  assert.match(releaseEvidenceGuide, /APPLE_ACTION_READINESS_JSON/);
  assert.match(releaseEvidenceGuide, /53 of 57/);
  assert.match(releaseEvidenceGuide, /REL-03.*IN PROGRESS/);
  assert.match(releaseEvidenceGuide, /56 of 57/);
  assert.match(releaseEvidenceGuide, /REL-06.*IN PROGRESS/);
  assert.match(releaseEvidenceGuide, /bootstrap.*does not create a tag or release/is);
  assert.match(releaseEvidenceGuide, /does not claim.*57 of 57/is);
  assert.match(releaseEvidenceGuide, /Nine iOS 26 App Shortcuts[\s\S]*Qualify Apple Intelligence/);
});
