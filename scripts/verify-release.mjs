import { spawn } from 'node:child_process';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const projectRoot = fileURLToPath(new URL('../', import.meta.url));
const validationPath = new URL('../docs/validation.json', import.meta.url);
const verificationContractPath = new URL('./release/verification-checks.json', import.meta.url);
const portableVerificationContractPath = new URL('./release/portable-verification-checks.json', import.meta.url);
const expectedFullCheckLabels = JSON.parse(await readFile(verificationContractPath, 'utf8'));
const expectedPortableCheckLabels = JSON.parse(await readFile(portableVerificationContractPath, 'utf8'));
const checks = [];
const verifierArguments = process.argv.slice(2);
const fullVerification = verifierArguments.length === 0;
const portableNativeOnly = verifierArguments.length === 1 && verifierArguments[0] === '--portable-native-only';
const portableWebOnly = verifierArguments.length === 1 && verifierArguments[0] === '--portable-web-only';
const releasePython = process.env.LOCAL_SANDBOX_RELEASE_PYTHON || 'python3';
const trackerCheckLabel = 'Release qualification tracker';
const trackerBindingKeys = [
  'evidenceSha256',
  'path',
  'requirementsSha256',
  'sha256',
  'snapshotPath',
  'snapshotSha256',
];
const canonicalTrackerPath = 'qualification/Local-Sandbox-0.3-Progress.xlsx';
const canonicalTrackerSnapshotPath = 'qualification/Local-Sandbox-0.3-Progress.snapshot.json';
const sha256Pattern = /^[0-9a-f]{64}$/;

async function currentCandidateDigest() {
  const child = spawn(releasePython, ['scripts/release/candidate_digest.py', '--root', projectRoot], {
    cwd: projectRoot,
    env: process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  let outputBytes = 0;
  let outputTooLarge = false;
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', (chunk) => {
      if (outputTooLarge) return;
      outputBytes += chunk.length;
      if (outputBytes > 16_000) {
        outputTooLarge = true;
        child.kill('SIGTERM');
        return;
      }
      (stream === child.stdout ? stdout : stderr).push(chunk);
    });
  }
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), 5_000).unref();
  }, 30_000);
  let result;
  try {
    result = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
  } finally {
    clearTimeout(timer);
  }
  if (outputTooLarge) throw new Error('Candidate digest output exceeded 16,000 bytes');
  if (timedOut) throw new Error('Candidate digest timed out');
  const candidateDigest = Buffer.concat(stdout).toString('utf8').trim();
  if (result.code !== 0 || !sha256Pattern.test(candidateDigest)) {
    const detail = Buffer.concat(stderr).toString('utf8').trim();
    throw new Error(`Candidate digest failed${detail ? `: ${detail}` : ` with exit ${result.code ?? result.signal}`}`);
  }
  return candidateDigest;
}

function assertVerificationContract(expectedLabels, description, expectedCount) {
  if (!Array.isArray(expectedLabels)
      || expectedLabels.length !== expectedCount
      || new Set(expectedLabels).size !== expectedLabels.length
      || expectedLabels.some((label) => typeof label !== 'string' || label.length === 0)) {
    throw new Error(`${description} verification check contract is malformed`);
  }
  const actual = checks.map(({ label }) => label);
  if (JSON.stringify(actual) !== JSON.stringify(expectedLabels)) {
    throw new Error(`${description} verification did not execute its exact canonical check roster`);
  }
}

async function writeValidation(status, error = null) {
  const candidateDigest = await currentCandidateDigest();
  const result = {
    recordType: 'local-sandbox-release-validation',
    schemaVersion: 1,
    version: '0.3.0',
    generatedAt: new Date().toISOString(),
    candidateDigest,
    automatedVerification: {status, checks},
    qualifications: {
      releaseState: 'QUALIFYING. Automated checks do not qualify external services or release channels.',
      xcodeIOSBuild: 'Full Xcode app and simulator builds are not run by the portable verifier. Run native CI and verify again on the release Mac.',
      physicalIPhone: 'signing, installation, iOS 26 and iOS 27 behavior, iPhone 18 Pro Max on-device Foundation Models, lower-device Shortcut fallback, device lifecycle, and hardware acceptance are not run by the portable verifier',
      liveAppleSignIn: 'web standalone, link, refresh, conflict, and revocation flows are not run without production Apple identifiers, secrets, domain, and accounts',
      liveAppleNativeExchange: 'native nonce exchange, bearer expiry, revocation, and device lifecycle are not run against the production Apple and hosted services',
      nativeDeviceProtection: 'Face ID, passcode, locked-device files, Files-provider protection, and iCloud Keychain recovery require physical-device qualification',
      liveEncryptedSync: 'cross-device recovery, pagination under live mutation, conflict review, key loss, and service transport are not run against production accounts',
      nativeBackgroundProcessing: 'BGProcessingTask scheduling, expiration, lock deferral, resubmission, and exactly-once completion require physical-device qualification',
      providerShortcuts: 'portable checks cover the five-probe verifier, device-local signed-ledger types, deterministic ranking, strict routing receipts, and eight provider selections; iPhone 18 Pro Max offline Foundation Models, lower-device Siri/App Shortcut discovery, provider-owned app sessions/actions, daily probe timing, signed Shortcut packages, text return, and foreground handoff still require installed signed device builds',
      liveGitHubSync: 'dashboard proxy, direct browser access, native access, and non-force writes are not run with a live repository token',
      liveCursorOrigin: 'installation, repository discovery, mirror refresh, and disconnect are not run without production Cursor application credentials and a permitted repository',
      browserLifecycle: 'Safari Home Screen installation, persistence, suspend and resume, offline behavior, quota failure, and multi-tab recovery require target-device testing',
      staticSelfHostDeployment: 'archive contracts do not replace an HTTPS deployment smoke test of the generated static self-host package',
      accessibilityAndDeviceMatrix: 'VoiceOver, Dynamic Type, landscape, iPad, touch targets, and the requested device matrix require real UI testing',
      githubRelease: 'source publication and release workflow configuration are not performed by verification',
      appStoreAndTestFlight: 'archive upload, TestFlight acceptance, metadata, submission, and App Review are not performed by verification',
    },
    ...(error === null ? {} : {error}),
  };
  await writeFile(validationPath, `${JSON.stringify(result, null, 2)}\n`);
  if (await currentCandidateDigest() !== candidateDigest) {
    throw new Error('Release candidate changed while the validation record was written');
  }
}

async function run(label, command, args, timeoutMs = 180_000, recordCheck = true) {
  const startedAt = Date.now();
  const child = spawn(command, args, {
    cwd: projectRoot,
    env: process.env,
    stdio: 'inherit',
  });

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), 5_000).unref();
  }, timeoutMs);

  const result = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer);

  const durationMs = Date.now() - startedAt;
  if (timedOut || result.code !== 0) {
    throw new Error(`${label} ${timedOut ? 'timed out' : `failed with exit code ${result.code ?? `signal ${result.signal}`}`}`);
  }
  if (recordCheck) checks.push({ label, durationMs, status: 'passed' });
}

function verifiedTrackerBinding(result) {
  if (result === null || typeof result !== 'object' || Array.isArray(result)
      || result.status !== 'tracker-snapshot-verified'
      || result.finalQualificationClaimed !== false) {
    throw new Error(`${trackerCheckLabel} returned an invalid non-qualifying verification result`);
  }
  const binding = result.binding;
  if (binding === null || typeof binding !== 'object' || Array.isArray(binding)
      || JSON.stringify(Object.keys(binding).sort()) !== JSON.stringify([...trackerBindingKeys].sort())
      || binding.path !== canonicalTrackerPath
      || binding.snapshotPath !== canonicalTrackerSnapshotPath
      || ['evidenceSha256', 'requirementsSha256', 'sha256', 'snapshotSha256']
        .some((key) => typeof binding[key] !== 'string' || !sha256Pattern.test(binding[key]))) {
    throw new Error(`${trackerCheckLabel} returned an invalid canonical workbook/snapshot binding`);
  }
  return binding;
}

async function runQualificationTracker(timeoutMs = 180_000) {
  const startedAt = Date.now();
  await run(
    'Release qualification tracker contracts',
    releasePython,
    ['tests/release-tracker.test.py'],
    timeoutMs,
    false,
  );
  const child = spawn(releasePython, ['scripts/release/tracker.py', 'verify'], {
    cwd: projectRoot,
    env: process.env,
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  const chunks = [];
  const maximumOutputBytes = 1_000_000;
  let outputBytes = 0;
  let outputTooLarge = false;
  child.stdout.on('data', (chunk) => {
    outputBytes += chunk.length;
    if (outputBytes > maximumOutputBytes) {
      outputTooLarge = true;
      child.kill('SIGTERM');
      return;
    }
    chunks.push(chunk);
  });

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), 5_000).unref();
  }, timeoutMs);
  let result;
  try {
    result = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
  } finally {
    clearTimeout(timer);
  }

  if (outputTooLarge) throw new Error(`${trackerCheckLabel} output exceeded 1,000,000 bytes`);
  if (timedOut || result.code !== 0) {
    throw new Error(`${trackerCheckLabel} ${timedOut ? 'timed out' : `failed with exit code ${result.code ?? `signal ${result.signal}`}`}`);
  }
  let parsed;
  const output = Buffer.concat(chunks).toString('utf8').trim();
  try {
    parsed = JSON.parse(output);
  } catch {
    throw new Error(`${trackerCheckLabel} did not return one JSON verification result`);
  }
  const tracker = verifiedTrackerBinding(parsed);
  checks.push({
    label: trackerCheckLabel,
    durationMs: Date.now() - startedAt,
    status: 'passed',
    tracker,
  });
  console.log(output);
}

function filesIn(directory, extension) {
  return readdir(new URL(directory, import.meta.url)).then((entries) =>
    entries.filter((entry) => entry.endsWith(extension)).map((entry) => `${directory.replace('../', '')}${entry}`),
  );
}

async function runPortableNativeChecks() {
  if (process.platform !== 'darwin') {
    throw new Error('Portable native checks require macOS and the Apple command-line tools');
  }
  const swiftFiles = [
    ...(await filesIn('../ios/LocalSandbox/', '.swift')),
    ...(await filesIn('../ios/LocalSandboxTests/', '.swift')),
  ];
  const swift6StrictFlags = ['-swift-version', '6', '-warnings-as-errors', '-strict-concurrency=complete'];
  await run('Swift parser', 'swiftc', ['-frontend', '-parse', ...swiftFiles]);
  await run('Native core compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/BackgroundExecution.swift',
    'ios/LocalSandbox/Keychain.swift',
    'tests/native-core.test.swift',
    '-o', '.sites-runtime/native-core-tests',
  ]);
  await run('Native core contracts', '.sites-runtime/native-core-tests', []);
  await run('Native execution core compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/NativeExecutionCore.swift',
    'tests/native-execution-core.test.swift',
    '-o', '.sites-runtime/native-execution-core-tests',
  ]);
  await run('Native execution core contracts', '.sites-runtime/native-execution-core-tests', []);
  await run('Provider qualification strict typecheck', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    '-typecheck',
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/NativeExecutionCore.swift',
    'ios/LocalSandbox/ProviderQualification.swift',
    'tests/provider-qualification-stubs.swift',
  ]);
  await run('Provider qualification contracts compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/NativeExecutionCore.swift',
    'ios/LocalSandbox/ProviderQualification.swift',
    'tests/provider-qualification-stubs.swift',
    'tests/provider-qualification-contracts.test.swift',
    '-o', '.sites-runtime/provider-qualification-contract-tests',
  ]);
  await run('Provider qualification contracts', '.sites-runtime/provider-qualification-contract-tests', []);
  await run('Shortcut package core compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/ShortcutPackageCore.swift',
    'tests/shortcut-package-core.test.swift',
    '-o', '.sites-runtime/shortcut-package-core-tests',
  ]);
  await run('Shortcut package core contracts', '.sites-runtime/shortcut-package-core-tests', []);
  await run('Workspace crypto compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/WorkspaceCrypto.swift',
    'tests/workspace-crypto.test.swift',
    '-o', '.sites-runtime/workspace-crypto-tests',
  ]);
  await run('Workspace crypto interoperability', '.sites-runtime/workspace-crypto-tests', []);
  await run('Native account and sync compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/WorkspaceCrypto.swift',
    'ios/LocalSandbox/Keychain.swift',
    'ios/LocalSandbox/LocalAccess.swift',
    'ios/LocalSandbox/NativeAccountSync.swift',
    'tests/native-account-sync.test.swift',
    '-o', '.sites-runtime/native-account-sync-tests',
  ]);
  await run('Native account and sync contracts', '.sites-runtime/native-account-sync-tests', []);
  await run('Native autosave compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/NativeAutosaveCore.swift',
    'tests/native-autosave.test.swift',
    '-o', '.sites-runtime/native-autosave-tests',
  ]);
  await run('Native autosave contracts', '.sites-runtime/native-autosave-tests', []);
  await run('Recursive sandbox compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/SandboxRecursiveIndex.swift',
    'tests/sandbox-recursive.test.swift',
    '-o', '.sites-runtime/sandbox-recursive-tests',
  ]);
  await run('Recursive sandbox contracts', '.sites-runtime/sandbox-recursive-tests', []);
  await run('Workspace preparation compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/WorkspacePreparation.swift',
    'tests/workspace-preparation-stubs.swift',
    'tests/workspace-preparation-contracts.test.swift',
    '-o', '.sites-runtime/workspace-preparation-contract-tests',
  ]);
  await run('Workspace preparation contracts', '.sites-runtime/workspace-preparation-contract-tests', []);
  await run('GitHub transport compile', 'xcrun', ['swiftc',
    ...swift6StrictFlags,
    'ios/LocalSandbox/Models.swift',
    'ios/LocalSandbox/ProviderRoutingCore.swift',
    'ios/LocalSandbox/GitHubTransport.swift',
    'tests/github-transport.test.swift',
    '-o', '.sites-runtime/github-transport-tests',
  ]);
  await run('GitHub transport contracts', '.sites-runtime/github-transport-tests', []);
  await run('Apple metadata', 'plutil', [
    '-lint',
    'ios/LocalSandbox/Info.plist',
    'ios/LocalSandbox/LocalSandbox.entitlements',
    'ios/LocalSandbox/PrivacyInfo.xcprivacy',
    'ios/LocalSandbox.xcodeproj/project.pbxproj',
  ]);
}

async function runPreNativeChecks() {
  await run('Release version ownership', process.execPath, ['scripts/check-release-version.mjs']);
  await run('Release Python dependencies', releasePython, ['scripts/release/check_python.py']);
  await run('Generated Xcode metadata', releasePython, ['scripts/check-xcode-project.py']);
  await run('Release packager safety', releasePython, ['tests/release-packager-safety.test.py']);
  await run('GitHub release preflight contracts', releasePython, ['tests/github-release-preflight.test.py']);
  await run('Deterministic setup guide contracts', releasePython, ['tests/release-freshness.test.py']);
  await run('Committed release artifact freshness', releasePython, ['scripts/release/check_freshness.py']);
  await runQualificationTracker();
  await run('Lint', 'pnpm', ['run', 'lint']);
  await run('TypeScript', 'pnpm', ['exec', 'tsc', '--noEmit']);
  await run('Node contracts', process.execPath, [
    '--experimental-strip-types',
    '--test',
    'tests/apple-release-workflow.test.mjs',
    'tests/apple-auth.test.ts',
    'tests/apple-auth-retention.test.ts',
    'tests/apple-native-auth.test.ts',
    'tests/autosave.test.ts',
    'tests/background-metadata.test.mjs',
    'tests/bounded-response.test.ts',
    'tests/contracts.test.ts',
    'tests/drizzle-schema.test.mjs',
    'tests/file-version-d1.test.ts',
    'tests/image-size-backport.test.mjs',
    'tests/install.test.mjs',
    'tests/integrations.test.ts',
    'tests/local-capabilities.test.mjs',
    'tests/local-github.test.mjs',
    'tests/local-origin.test.mjs',
    'tests/local-workspace-sync.test.mjs',
    'tests/native-account-ui.test.mjs',
    'tests/origin-auth.test.ts',
    'tests/origin-persistence.test.ts',
    'tests/unexpected-error-logging.test.mjs',
    'tests/vault.test.mjs',
    'tests/packages.test.mjs',
    'tests/workspace-crypto.test.ts',
    'tests/workspace-sync-client.test.ts',
    'tests/xcode-swift-modernization.test.mjs',
  ]);
  await run('D1 storage contracts', releasePython, ['tests/storage.test.py']);
  await run('Git worktree contracts', releasePython, ['tests/worktree.test.py']);
}

async function runPostNativeChecks() {
  await run('Production web build', 'pnpm', ['run', 'build']);
  await run('Built worker integration', process.execPath, ['tests/worker-integration.mjs']);
  await run('Static self-host reproducibility', releasePython, ['tests/selfhost-reproducibility.test.py']);
  await run('Release capability contracts', releasePython, ['tests/release-capabilities.test.py']);
  await run('Release artifact audit', releasePython, ['scripts/audit-release-artifacts.py']);
}

try {
  if (!fullVerification && !portableNativeOnly && !portableWebOnly) {
    throw new Error(`Unknown verifier argument: ${verifierArguments.join(' ')}`);
  }
  await mkdir(new URL('../.sites-runtime/', import.meta.url), { recursive: true });
  if (portableNativeOnly) {
    await runPortableNativeChecks();
  } else if (portableWebOnly) {
    await runPreNativeChecks();
    await runPostNativeChecks();
    assertVerificationContract(expectedPortableCheckLabels, 'Portable web', 18);
  } else {
    if (process.platform !== 'darwin') {
      throw new Error('Canonical full verification requires macOS; use --portable-web-only elsewhere');
    }
    await runPreNativeChecks();
    await runPortableNativeChecks();
    await runPostNativeChecks();
    assertVerificationContract(expectedFullCheckLabels, 'Full', 41);
    await writeValidation('passed');
  }
  const mode = portableNativeOnly ? 'portable-native-only' : portableWebOnly ? 'portable-web-only' : 'full';
  console.log(JSON.stringify({ status: 'passed', mode, checks }, null, 2));
} catch (error) {
  const message = error instanceof Error ? error.message : 'Unknown verification failure';
  if (fullVerification) {
    try {
      await writeValidation('failed', message);
    } catch (validationError) {
      console.error(`Could not write validation record: ${validationError instanceof Error ? validationError.message : 'unknown failure'}`);
    }
  }
  console.error(JSON.stringify({
    status: 'failed',
    checks,
    error: message,
  }, null, 2));
  process.exitCode = 1;
}
