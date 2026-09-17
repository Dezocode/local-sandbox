import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';

const app = await readFile(new URL('../ios/LocalSandbox/LocalSandboxApp.swift', import.meta.url), 'utf8');
const localAccess = await readFile(new URL('../ios/LocalSandbox/LocalAccess.swift', import.meta.url), 'utf8');
const sync = await readFile(new URL('../ios/LocalSandbox/NativeWorkspaceSyncView.swift', import.meta.url), 'utf8');
const account = await readFile(new URL('../ios/LocalSandbox/NativeAccountSync.swift', import.meta.url), 'utf8');
const crypto = await readFile(new URL('../ios/LocalSandbox/WorkspaceCrypto.swift', import.meta.url), 'utf8');
const autosave = await readFile(new URL('../ios/LocalSandbox/NativeAutosaveCore.swift', import.meta.url), 'utf8');
const editor = await readFile(new URL('../ios/LocalSandbox/NativeFileEditorView.swift', import.meta.url), 'utf8');
const store = await readFile(new URL('../ios/LocalSandbox/SandboxStore.swift', import.meta.url), 'utf8');
const intents = await readFile(new URL('../ios/LocalSandbox/AppIntents.swift', import.meta.url), 'utf8');
const routing = await readFile(new URL('../ios/LocalSandbox/ProviderRoutingCore.swift', import.meta.url), 'utf8');
const qualification = await readFile(new URL('../ios/LocalSandbox/ProviderQualification.swift', import.meta.url), 'utf8');
const workspacePreparation = await readFile(new URL('../ios/LocalSandbox/WorkspacePreparation.swift', import.meta.url), 'utf8');
const bridge = await readFile(new URL('../ios/LocalSandbox/ShortcutBridge.swift', import.meta.url), 'utf8');
const models = await readFile(new URL('../ios/LocalSandbox/Models.swift', import.meta.url), 'utf8');
const runtime = await readFile(new URL('../ios/LocalSandbox/Runtime.swift', import.meta.url), 'utf8');
const background = await readFile(new URL('../ios/LocalSandbox/BackgroundExecution.swift', import.meta.url), 'utf8');
const shortcutPackages = await readFile(new URL('../ios/LocalSandbox/ShortcutPackagesView.swift', import.meta.url), 'utf8');
const shortcutPackageCore = await readFile(new URL('../ios/LocalSandbox/ShortcutPackageCore.swift', import.meta.url), 'utf8');
const dashboard = await readFile(new URL('../app/dashboard.tsx', import.meta.url), 'utf8');
const connections = await readFile(new URL('../app/connections.tsx', import.meta.url), 'utf8');
const handoffParser = await readFile(new URL('../lib/provider-handoff.ts', import.meta.url), 'utf8');
const contracts = await readFile(new URL('../lib/contracts.ts', import.meta.url), 'utf8');
const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
const installGuide = await readFile(new URL('../docs/INSTALL-TODAY.md', import.meta.url), 'utf8');
const releaseGuide = await readFile(new URL('../docs/RELEASE.md', import.meta.url), 'utf8');
const architecture = await readFile(new URL('../docs/ARCHITECTURE.md', import.meta.url), 'utf8');
const roadmap = await readFile(new URL('../docs/ROADMAP-AUTOMATION.md', import.meta.url), 'utf8');
const guideGenerator = await readFile(new URL('../scripts/generate-guide.py', import.meta.url), 'utf8');

function sourceSlice(source, startMarker, endMarker, label) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0, `${label} start marker is missing`);
  assert.ok(end > start, `${label} end marker is missing or out of order`);
  return source.slice(start, end);
}

function assertInOrder(source, markers, message) {
  let previous = -1;
  for (const marker of markers) {
    const current = source.indexOf(marker, previous + 1);
    assert.ok(current >= 0, `${message}: missing ${marker}`);
    assert.ok(current > previous, `${message}: ${marker} is out of order`);
    previous = current;
  }
}

function assertAuthenticatedEntry(source, startMarker, endMarker, actionMarker, label) {
  const entry = sourceSlice(source, startMarker, endMarker, label);
  assert.equal((entry.match(/ExecutionContinuationGate\.shared\.capture\(\)/g) ?? []).length, 1,
    `${label} must capture exactly one lock generation`);
  assert.equal((entry.match(/sync\.captureOperationGeneration\(\)/g) ?? []).length, 1,
    `${label} must capture exactly one native-sync operation generation`);
  assert.equal((entry.match(/LocalAccess\.authenticate\(executionGeneration: executionGeneration\)/g) ?? []).length, 1,
    `${label} must authenticate against its captured generation`);
  assert.equal((entry.match(/try localAccessLease\.requireCurrent\(\)/g) ?? []).length, 1,
    `${label} must validate its authentication lease exactly once before the action`);
  assert.equal((entry.match(/operationGeneration: operationGeneration/g) ?? []).length, 1,
    `${label} must forward exactly its captured native-sync operation generation`);
  assertInOrder(entry, [
    'let executionGeneration = ExecutionContinuationGate.shared.capture()',
    'let operationGeneration = sync.captureOperationGeneration()',
    'Task {',
    'LocalAccess.authenticate(executionGeneration: executionGeneration)',
    'try localAccessLease.requireCurrent()',
    actionMarker,
    'operationGeneration: operationGeneration',
  ], `${label} must retain its tap-time generation through local authentication`);
}

test('provider qualification UI and App Intent share saved authorization before prompt output', () => {
  const ui = sourceSlice(app, 'private func startQualification()', 'private func completeQualification()', 'provider qualification handoff');
  assertInOrder(ui, [
    'ProviderQualificationStore.requireSavedAuthorization(for:provider)',
    'AdapterSettings.save(adapter,for:provider)',
    'ProviderQualificationStore.externalChallenge(provider:provider,pendingAttemptID:pending?.attemptID)',
    'AdapterSettings.runURL(name:name,input:challenge.prompt)',
    'openURL(url)',
  ], 'UI qualification must check saved consent and reread the pending challenge before handoff');
  assert.doesNotMatch(ui, /pending\s*\?\?|model\.policy\.contextChars/);
  const intent = sourceSlice(intents, 'struct BeginProviderQualificationIntent:', 'struct RecordProviderQualificationIntent:', 'provider qualification App Intent');
  assertInOrder(intent, [
    'continuationValidator.beforePersistence()',
    'ProviderQualificationStore.externalChallenge(provider: exact, appIntentTransportObserved: true)',
    'payload: challenge.prompt',
    'continuationValidator.requireCurrent()',
    'return .result',
  ], 'App Intent qualification must authorize before creating its output');
  const entry = sourceSlice(qualification, 'static func externalChallenge(', 'static func begin(', 'shared external qualification admission');
  assert.match(entry, /try ProviderQualificationStore\.pending\(provider: \$0\)/);
  assertInOrder(entry, [
    'let policy = try requireSavedAuthorization(for: provider)',
    'try loadPending(provider)',
    'challenge.attemptID == pendingAttemptID',
    'challenge.prompt.count <= contextCharacters',
    'return challenge',
  ], 'pending output must use current protected ledger and saved cap');
  const begin = sourceSlice(qualification, 'static func begin(', '@discardableResult\n    static func complete(', 'provider qualification begin');
  assertInOrder(begin, [
    'try requireSavedAuthorization(for: provider)',
    'min(contextCharacters, policy.contextChars)',
    'qualificationActive',
    'var ledger = try load(now: now)',
    'try save(ledger)',
  ], 'direct external qualification cannot persist before saved authorization');
});

test('native Sign in with Apple binds a random raw nonce and keeps local access local-first', () => {
  assert.match(app, /rawNonce\s*=\s*try NativeAppleNonce\.make\(\)/);
  assert.match(app, /request\.nonce\s*=\s*try NativeAppleNonce\.requestHash\(rawNonce\)/);
  assert.match(app, /credential\.identityToken/);
  const localIdentity = app.indexOf('try Keychain.set(user,for:"appleUser")');
  const hostedExchange = app.indexOf('nativeAuth.connect(', localIdentity);
  assert.ok(localIdentity >= 0 && hostedExchange > localIdentity, 'hosted reachability became a prerequisite for local identity');
  const signIn = sourceSlice(app, 'func completeAppleSignIn(', 'func disconnectNativeSync', 'native Apple sign-in');
  assertInOrder(signIn, [
    'NativeHostedAccessAdmission.block()',
    'invalidateAuthLifecycle()',
    'let pendingGeneration=authLifecycleGeneration.capture()',
    'NativeAppleAuthorizationCode.validated(authorizationCode)',
  ], 'Apple sign-in must block hosted admission before validation, await, exchange, or local mutation');
  const checkedPriorIdentity = signIn.indexOf('previous=try Keychain.getChecked("appleUser")');
  assert.match(signIn, /let previous:String\?\s*do \{previous=try Keychain\.getChecked\("appleUser"\)\}\s*catch \{self\.error=error\.localizedDescription;return\}/);
  assert.doesNotMatch(signIn, /Keychain\.get\("appleUser"\)/);
  assert.equal((signIn.match(/Keychain\.getChecked\("appleUser"\)/g) ?? []).length, 1);
  for (const protectedAction of ['try Keychain.set(user,for:"appleUser")', 'unlocked=true', 'nativeAuth.connect(']) {
    assert.ok(signIn.indexOf(protectedAction) > checkedPriorIdentity,
      `Apple sign-in reached ${protectedAction} before the checked prior-profile read`);
  }
  assertInOrder(signIn, [
    'previous=try Keychain.getChecked("appleUser")',
    'if let transferRecoveryUser',
    'previous == transferRecoveryUser',
    'let switchingProfile=',
    'try Keychain.set(user,for:"appleUser")',
    'unlocked=true',
    'nativeAuth.connect(',
  ], 'Apple sign-in must fail before transfer classification, local identity mutation, unlock, or hosted connect when the prior profile is unreadable');
  assert.match(app, /Your local workspace is ready\. Encrypted hosted sync is unavailable/);
  const lease = sourceSlice(localAccess, '@MainActor\nstruct LocalAccessLease', '@MainActor enum LocalAccess', 'LocalAccess lease');
  assert.match(lease, /let executionGeneration: ExecutionContinuationGate\.Generation[\s\S]*continuationValidator = gate\.validator\(for: executionGeneration\)[\s\S]*func requireCurrent\(\) throws \{[\s\S]*continuationValidator\.requireCurrent\(\)/);
  const publicAuthenticationStart = localAccess.indexOf('static func authenticate(');
  const injectedAuthenticationStart = localAccess.indexOf('static func authenticate(', publicAuthenticationStart + 1);
  assert.ok(publicAuthenticationStart >= 0 && injectedAuthenticationStart > publicAuthenticationStart, 'LocalAccess authentication overloads are missing');
  const publicAuthentication = localAccess.slice(publicAuthenticationStart, injectedAuthenticationStart);
  assert.match(publicAuthentication, /executionGeneration providedExecutionGeneration: ExecutionContinuationGate\.Generation\? = nil[\s\S]*async throws -> LocalAccessLease[\s\S]*return try await authenticate\([\s\S]*executionGeneration: providedExecutionGeneration/);
  const injectedAuthentication = localAccess.slice(injectedAuthenticationStart);
  assertInOrder(injectedAuthentication, [
    'let executionGeneration = providedExecutionGeneration ?? gate.capture()',
    'let lease = LocalAccessLease(executionGeneration: executionGeneration, gate: gate)',
    'try lease.requireCurrent()',
    'guard hasLocalAccount()',
    'gate.validator(for: executionGeneration).validatedAwait',
    'try await evaluatePolicy()',
    'guard accepted else',
    'try lease.requireCurrent()',
    'return lease',
  ], 'LocalAccess authentication must retain and revalidate one generation across device authentication');
  const unlock = sourceSlice(app, 'func unlock(', 'func connect(_ url:URL)', 'AppModel unlock');
  assert.match(unlock, /func unlock\(executionGeneration:ExecutionContinuationGate\.Generation\) async/);
  assertInOrder(unlock, [
    'LocalAccess.authenticate(executionGeneration:executionGeneration)',
    'try localAccessLease.requireCurrent()',
    'try SandboxStore.shared.restore()',
    'try localAccessLease.requireCurrent()',
    'try prepare()',
    'try localAccessLease.requireCurrent()',
    'unlocked=true',
  ], 'AppModel unlock must fence every protected mutation with the authenticated lease');
  const prepare = app.slice(app.indexOf('func prepare()'), app.indexOf('func refresh()'));
  assert.match(prepare, /WorkspacePreparationService\.live\.prepare\(defaultPolicy:policy\)/);
  assert.match(workspacePreparation, /prepareProviderQualification: \{ try ProviderQualificationStore\.prepare\(\) \}/);
  assert.doesNotMatch(workspacePreparation, /do\s*\{\s*try operations\.prepareProviderQualification\(\)[\s\S]*catch/);
  const prepareIntent = intents.slice(intents.indexOf('struct PrepareWorkspaceIntent'), intents.indexOf('\n}', intents.indexOf('struct PrepareWorkspaceIntent')) + 2);
  assert.match(prepareIntent, /WorkspacePreparationService\.live\.prepare\(defaultPolicy:ResourcePolicy\(\)\)/);
  assert.doesNotMatch(prepareIntent, /AppModel\(\)/);
  assert.match(workspacePreparation, /try operations\.writeText\(policyPath, encodedPolicy, true\)/);
  assert.doesNotMatch(workspacePreparation, /saveWorkspacePolicy/);
});

test('native lock and explicit disconnect durably retire bearer and scrub in-memory workspace keys', () => {
  assert.doesNotMatch(app, /NativeBearerVault\.live\.(?:loadForRetirement|clearChecked)\(\)/,
    'AppModel bypasses its injected auth controller for bearer retirement');
  assert.match(app, /private func clearNativeSessionAuthority\(\)[\s\S]*nativeSessionExpiry=nil/);
  assert.match(app, /nativeAuth\.disconnect\(\)/);
  assert.match(sync, /cryptoSession = nil/);
  assert.match(sync, /displayedRecoverySecret = nil/);
  assert.match(sync,/addObserver\(forName: \.localSandboxDidLock, object: nil, queue: \.main\)[\s\S]*MainActor\.assumeIsolated \{ self\?\.lock\(\) \}/);
  assert.match(sync, /\.onReceive\(NotificationCenter\.default\.publisher\(for: \.localSandboxDidLock\)\)[\s\S]*currentRecoveryPassphrase = ""[\s\S]*replacementRecoveryPassphrase = ""/);
  const nativeLock=sync.slice(sync.indexOf('func lock()'),sync.indexOf('func refreshWorkspaces(operationGeneration: UInt64)'));
  const retireGeneration=nativeLock.indexOf('lifecycleGeneration.invalidate()');
  const cancelOperation=nativeLock.indexOf('activeOperation?.task.cancel()');
  assert.ok(retireGeneration>=0&&cancelOperation>retireGeneration&&cancelOperation<nativeLock.indexOf('cryptoSession = nil'),'native sync operation must retire and cancel before key scrub');
  assert.match(nativeLock,/activeOperation = nil[\s\S]*busy = false/);
  assert.match(nativeLock,/hosted mutation may already have committed[\s\S]*idempotent readback/);
  const unlock=sync.slice(sync.indexOf('func unlock('),sync.indexOf('func revealICloudRecoverySecret'));
  assert.ok(unlock.indexOf('try await self.api.readWorkspace')<unlock.indexOf('try self.requireCurrent(generation)')&&unlock.indexOf('try self.requireCurrent(generation)')<unlock.indexOf('self.cryptoSession = session'),'delayed unlock can restore a key after lock');
  const pull=sync.slice(sync.indexOf('func stagePull(operationGeneration: UInt64)'),sync.indexOf('func applyStagedPull(operationGeneration: UInt64)'));
  assert.ok(pull.indexOf('try await self.api.readWorkspace')<pull.indexOf('try self.requireCurrent(generation)')&&pull.indexOf('try self.requireCurrent(generation)')<pull.indexOf('self.stagedDifferences = staged'),'delayed pull can restore plaintext after lock');
  const deleteWorkspace=sync.slice(sync.indexOf('func deleteUnlockedWorkspace(operationGeneration: UInt64)'),sync.indexOf('func revealICloudRecoverySecret(operationGeneration: UInt64)'));
  const deleteRequest=deleteWorkspace.indexOf('try await self.api.deleteWorkspace');
  const deleteFence=deleteWorkspace.indexOf('try self.requireCurrent(generation)',deleteRequest);
  assert.ok(deleteRequest>=0&&deleteFence>deleteRequest&&deleteFence<deleteWorkspace.indexOf('self.workspaces.removeAll'),'delayed delete response can mutate local state after lock');
  assert.match(sync,/private func run\([\s\S]*impact: OperationImpact = \.readOnly,[\s\S]*_ operation: @escaping @MainActor \(UInt64\) async throws -> Void/);
  assert.match(sync,/let task = Task \{ @MainActor in[\s\S]*try requireCurrent\(capturedGeneration\)[\s\S]*try await operation\(capturedGeneration\)[\s\S]*try requireCurrent\(capturedGeneration\)/);
  assert.match(sync,/activeOperation = ActiveOperation\(id: operationID, impact: impact, task: task\)[\s\S]*let result = await task\.result[\s\S]*guard activeOperation\?\.id == operationID else \{ return \}/);
  assert.match(sync,/private func requireCurrent\([\s\S]*try Task\.checkCancellation\(\)[\s\S]*lifecycleGeneration\.isCurrent/);
  assert.match(account,/private func get<T: Decodable>[\s\S]*try Task\.checkCancellation\(\)[\s\S]*transport\.perform/);
  for (const mutation of ['create','rotateRecovery','deleteUnlockedWorkspace','push','keepNativeAfterConflict']) {
    const start=sync.indexOf(`func ${mutation}`);
    assert.ok(start>=0&&sync.slice(start,start+500).includes('run(operationGeneration: operationGeneration, impact: .hostedMutation)'),`${mutation} does not forward its captured generation as a hosted mutation`);
  }
  assert.match(account, /\/api\/auth\/apple\/native\/revoke/);
  assert.match(account, /pendingRevocationRecords = 4/);
  assert.match(account, /appleNativeRevocationFollowUp\.v1/);
  assert.match(account, /func upgradedForGrantRevocation\(now: Int\) throws -> Self/);
  assert.match(account, /let valid = try entries\.map \{ try \$0\.upgradedForGrantRevocation\(now: now\) \}/);
  assert.match(account, /write: \{ try Keychain\.set\(\$0, for: storageKey\) \}/);
  assert.match(account, /func retryPendingRevocations\(/);
  const retirement = account.slice(account.indexOf('private func retireServerSession'), account.indexOf('\n    }', account.indexOf('private func retireServerSession')) + 6);
  assert.ok(retirement.indexOf('pendingRevocationVault.stage') < retirement.indexOf('api.revoke'), 'server revocation was attempted before its crash-safe follow-up was staged');
  const activeRetirement = sourceSlice(account, 'private func retireActiveSession(', 'func hasPendingAccountDeletion()', 'active bearer retirement');
  assertInOrder(activeRetirement, [
    'retireServerSession(session, now: now)',
    'vault.clearIfMatchingChecked(token: session.token)',
    'pendingRevocationVault.remove(bearerToken: session.token, now: now)',
  ], 'active bearer retirement must establish server-or-queue safety before exact local deletion');
  const retirementFailure = activeRetirement.slice(activeRetirement.indexOf('catch'));
  assert.doesNotMatch(retirementFailure.slice(0, retirementFailure.indexOf('try vault.clearIfMatchingChecked')), /clearChecked|clearIfMatchingChecked/,
    'combined follow-up persistence and network failure can clear the only exact bearer');
  const availabilityLoad = sourceSlice(account, 'private func loadLocked(now: Int) -> NativeBearerSession?', 'private func clearCheckedLocked()', 'bearer availability load');
  assert.doesNotMatch(availabilityLoad, /storage\.delete|clearChecked/,
    'ordinary bearer availability checks must be pure');
  assert.match(availabilityLoad, /try\? session\.validated\(now: now\)/);
  assert.match(availabilityLoad, /!storage\.retirementBlocked\(admitted\.token, now\)/);
  const pendingLoad = sourceSlice(account, 'private func loadLocked(now: Int) throws -> [NativePendingRevocation]', 'private func persistLocked(', 'pending revocation checked load');
  assert.match(pendingLoad, /else \{\s*throw SandboxError\.blocked\("APPLE_NATIVE_REVOCATION_FOLLOW_UP_INVALID"\)\s*\}/);
  assert.doesNotMatch(pendingLoad, /else \{[\s\S]*clearLocked\(\)[\s\S]*return \[\]/,
    'malformed pending-revocation evidence is auto-deleted as if no retirement were pending');
  assert.doesNotMatch(pendingLoad, /filter[\s\S]*expiresAt|expiresAt\s*>\s*now/,
    'local wall clock must not erase or unblock unconfirmed exact-token debt');
  const sync401 = sourceSlice(
    sync,
    '        catch let error as NativeServiceError {\n            guard lifecycleGeneration',
    '        } catch {\n            guard lifecycleGeneration',
    'workspace sync service failure',
  );
  assertInOrder(sync401, [
    'if error.status == 401',
    'NativeHostedAccessAdmission.block()',
    'lock()',
    'let retirementGeneration = lifecycleGeneration.capture()',
    'try await nativeAuth.disconnect()',
    'guard lifecycleGeneration.isCurrent(retirementGeneration) else { return }',
  ], 'workspace 401 must lock immediately and use a separate checked retirement request');
  assert.equal((sync401.match(/guard lifecycleGeneration\.isCurrent\(retirementGeneration\) else \{ return \}/g) ?? []).length, 3,
    'every post-retirement workspace-401 status path must reject a later lock generation');
  assert.doesNotMatch(sync401, /bearerVault\.clearChecked\(\)/,
    'an arbitrary sync 401 is not authoritative proof of bearer revocation');
  assert.match(app, /Revocation follow-up/);
  assert.match(app, /only confirmed revoke success or the revoke endpoint's authoritative absence response removes the debt/);
});

test('queued UI actions capture one lock generation before spawning work and forward it unchanged', () => {
  const unlockEntry = sourceSlice(
    app,
    'Button("Unlock with Face ID or passcode")',
    '.buttonStyle(.borderedProminent)',
    'unlock UI entry',
  );
  assert.equal((unlockEntry.match(/ExecutionContinuationGate\.shared\.capture\(\)/g) ?? []).length, 1);
  assertInOrder(unlockEntry, [
    'let executionGeneration=ExecutionContinuationGate.shared.capture()',
    'Task{@MainActor in',
    'model.unlock(executionGeneration:executionGeneration)',
  ], 'unlock UI entry must capture its generation before queueing authentication');

  const resumeEntry = sourceSlice(
    app,
    'Button(model.running ? "Resuming…":"Resume from safe checkpoint")',
    '.disabled(model.running)',
    'checkpoint resume UI entry',
  );
  assert.equal((resumeEntry.match(/ExecutionContinuationGate\.shared\.capture\(\)/g) ?? []).length, 1);
  assertInOrder(resumeEntry, [
    'let executionGeneration=ExecutionContinuationGate.shared.capture()',
    'Task{@MainActor in',
    'model.resumeCheckpoint(executionGeneration:executionGeneration)',
  ], 'checkpoint resume UI entry must capture its generation before queueing AgentRunner');

  const modelRun = sourceSlice(app, 'func run(_ goal:String', 'func applyOracleRecommendation()', 'AppModel run');
  assert.match(modelRun, /func run\(_ goal:String,contract:GoalContract,selection:ProviderSelection = \.saved,executionGeneration:ExecutionContinuationGate\.Generation\) async/);
  assertInOrder(modelRun, [
    'AgentRunner.shared.run(',
    'executionGeneration:executionGeneration',
  ], 'AppModel run must forward the tap-time generation to AgentRunner');
  const modelResume = sourceSlice(app, 'func resumeCheckpoint(', 'func acknowledgeCheckpoint()', 'AppModel resume');
  assert.match(modelResume, /func resumeCheckpoint\(executionGeneration:ExecutionContinuationGate\.Generation\) async/);
  assertInOrder(modelResume, [
    'AgentRunner.shared.resume(',
    'executionGeneration:executionGeneration',
  ], 'AppModel resume must forward the tap-time generation to AgentRunner');

  const oracleView = sourceSlice(app, 'struct OracleView:View {', 'struct FilesView:View {', 'Oracle view');
  assert.match(oracleView, /Button\(model\.running \? "Running…":"Resolve and begin task"\)\{beginTask\(\)\}/);
  const beginEntry = sourceSlice(oracleView, 'private func beginTask()', 'private func launch()', 'Oracle begin entry');
  assert.equal((beginEntry.match(/ExecutionContinuationGate\.shared\.capture\(\)/g) ?? []).length, 1);
  assertInOrder(beginEntry, [
    'let executionGeneration=ExecutionContinuationGate.shared.capture()',
    'Task{@MainActor in',
    'model.run(',
    'executionGeneration:executionGeneration',
  ], 'Oracle native run must use the generation captured before its queued task');
  assertInOrder(beginEntry, [
    'let executionGeneration=ExecutionContinuationGate.shared.capture()',
    'ShortcutCoordinator.shared.begin(',
    'executionGeneration:executionGeneration',
  ], 'Oracle Shortcut begin must use the generation captured at entry');

  const acceptEntry = sourceSlice(
    oracleView,
    'Button("Validate and apply response")',
    'Button("Stop handoff"',
    'Shortcut accept UI entry',
  );
  assert.equal((acceptEntry.match(/ExecutionContinuationGate\.shared\.capture\(\)/g) ?? []).length, 1);
  assertInOrder(acceptEntry, [
    'let executionGeneration=ExecutionContinuationGate.shared.capture()',
    'Task{@MainActor in',
    'ShortcutCoordinator.shared.accept(response,executionGeneration:executionGeneration)',
  ], 'Shortcut accept UI entry must capture its generation before queueing validation');

  const stopEntry = sourceSlice(
    oracleView,
    'Button("Stop handoff"',
    'if !prompt.isEmpty',
    'Shortcut stop UI entry',
  );
  assert.equal((stopEntry.match(/ExecutionContinuationGate\.shared\.capture\(\)/g) ?? []).length, 1);
  assertInOrder(stopEntry, [
    'let executionGeneration=ExecutionContinuationGate.shared.capture()',
    'Task{@MainActor in',
    'ShortcutCoordinator.shared.stop(executionGeneration:executionGeneration)',
  ], 'Shortcut stop UI entry must capture its generation before queueing cleanup');
});

test('transferred Apple credentials durably block hosted admission and preserve verified local continuity', () => {
  assert.match(app, /case \.transferred:\s*await self\.blockHostedAccessForTransferredCredential\(checkedUserID\)/);
  const transferred = app.slice(
    app.indexOf('private func blockHostedAccessForTransferredCredential'),
    app.indexOf('func unlock(', app.indexOf('private func blockHostedAccessForTransferredCredential')),
  );
  const block = transferred.indexOf('NativeHostedAccessAdmission.block()');
  const invalidate = transferred.indexOf('invalidateAuthLifecycle()');
  const lockSync = transferred.indexOf('NotificationCenter.default.post(name:.localSandboxDidLock');
  const persistBlock = transferred.indexOf('transferBlockVault.block(oldUser:oldUser)');
  const prepareSessions = transferred.indexOf('nativeAuth.prepareSessionsForRetirement()');
  const retire = transferred.indexOf('finishPreparedSessionRetirement(');
  assert.ok(block >= 0 && invalidate > block && lockSync > invalidate && persistBlock > lockSync && prepareSessions > persistBlock && retire > prepareSessions,
    'transferred state did not block admission, cancel sync, persist its transfer block, atomically prepare exact active and pending tokens, then retire them');
  assert.doesNotMatch(transferred, /NativeBearerVault\.live|retireClearedSession|clearChecked\(\)/,
    'transferred state bypasses injected checked retirement or clears before durable staging');
  const preparationFailure = transferred.slice(prepareSessions, retire);
  assert.match(preparationFailure, /catch \{[\s\S]*could not be atomically handed to revocation follow-up[\s\S]*Keychain evidence and the stored profile were kept[\s\S]*return/,
    'transferred state continues after atomic capture, batch-stage, or checked handoff failure');
  const atomicPreparation = sourceSlice(account, 'func prepareSessionsForRetirement(', 'func retirePreparedSessions(', 'atomic session-retirement preparation');
  assertInOrder(atomicPreparation, [
    'persistenceGate.serialized',
    'captureSessionsForRetirement()',
    'stageSessionsForRetirement(captured, now: now)',
    'handoffPreparedSessionsForRetirement(prepared, now: now)',
  ], 'session retirement must serialize checked capture, one batch stage, and exact local handoff');
  assert.match(account, /admissionBlocked:[\s\S]*NativeHostedAccessAdmission\.isBlocked\(\)[\s\S]*appleNativeTransferBlock\.v1/);
  assert.match(account, /private func loadLocked\(now: Int\)[\s\S]*guard !storage\.admissionBlocked\(\) else \{ return nil \}/);
  assert.match(account, /func loadForRetirement\(\) throws -> NativeBearerSession\?/);
  assert.match(account, /appleLocalWorkspaceBinding\.v1/);
  assert.match(account, /workspaceBindingVault\.migrateAccountBinding\([\s\S]*expectedDirectoryName: record\.workspaceDirectoryName/);
  assert.match(account, /let recoveryBindingState = try recoveryVault\.validateAccountBindingMigration/);
  assert.match(account, /if record\.recoveryBindingState == \.requiresMigration \{[\s\S]*from: record\.newUser,[\s\S]*to: record\.oldUser/);
  assert.match(sync, /private func activeBearer\(\) throws -> NativeBearerSession \{[\s\S]*bearerVault\.load\(\)/);
  assert.match(store, /func useLocal\(\) throws \{[\s\S]*NativeLocalWorkspaceBindingVault\.live\.directoryName\(accountBinding: user\)[\s\S]*appendingPathComponent\(directoryName\)/);
  assert.match(store, /var workspaceID: String\? \{[\s\S]*directoryName\.prefix\(24\)/);

  const signIn = app.slice(app.indexOf('func completeAppleSignIn'), app.indexOf('func disconnectNativeSync'));
  assert.match(signIn, /let verifiedTransfer=transferRecoveryUser != nil/);
  assert.match(signIn, /transferMigration\.migrateVerifiedTransfer\([\s\S]*from:transferRecoveryUser,[\s\S]*to:user,[\s\S]*verifiedAccountMode:session\.accountMode/);
  assert.match(signIn, /if !switchingProfile && !verifiedTransfer \{[\s\S]*Keychain\.set\(user,for:"appleUser"\)/);
  assert.match(signIn, /This Apple credential is a different account, not a server-verified transfer/);
  const transferBranch = signIn.slice(signIn.indexOf('if verifiedTransfer,let transferRecoveryUser'), signIn.indexOf('if !verifiedTransfer'));
  assert.doesNotMatch(transferBranch, /clearLocalProfile|SandboxStore\.shared\.disconnect|ProviderQualificationStore\.reset/);
  assert.match(app, /if !transferRecoveryUser\.isEmpty \{ request\.user = transferRecoveryUser \}/);
  assert.match(account, /try workspaceBindingVault\.clearChecked\(\)/);
});

test('native hosted account deletion is explicit, retry-safe, bearer-only, and scrubs only after confirmation', () => {
  assert.match(app, /Section\("Hosted Apple access and account"\)/);
  assert.match(app, /Button\("Retry native-session revocation"\)\{Task\{await model\.retryNativeRevocationFollowUp\(\)\}\}/);
  const retryRevocations = sourceSlice(app, 'func retryNativeRevocationFollowUp() async', 'func refreshAppleCredentialReview()', 'native revocation retry action');
  assertInOrder(retryRevocations, [
    'nativeAuth.retryPendingRevocations()',
    'refresh()',
  ], 'the visible revocation retry action must run the checked native queue retry before refreshing dashboard state');
  assert.match(app, /model\.appleAccountDeletionPending \? "Retry hosted account deletion"/);
  assert.match(app, /model\.appleAccountMode == \.linked \? "Remove this Apple identity's access\?":model\.appleAccountMode == \.standalone \? "Permanently delete account and server data\?":"Account mode unavailable"/);
  assert.match(app, /Button\("Keep account",role:\.cancel\)/);
  assert.match(app, /The ChatGPT-owned workspace, its Local Sandbox data, and other linked Apple identities are retained/);
  assert.match(app, /Selected Files and iCloud documents stay on your devices/);
  const request = app.indexOf('nativeAuth.deleteAccount(accountBinding:accountBinding)');
  const immediateLock = app.indexOf('lockAndDisconnectLocalProfile(preserveDeletionRecovery:true)', request);
  const persistOutcome = app.indexOf('try deletionCompletionRecovery.record(outcome)', request);
  const scrub = app.indexOf('hostedDeletionAccountBindingHash:record.accountBindingHash', request);
  const finalize = app.indexOf('try nativeAuth.finalizeConfirmedAccountDeletion(', scrub);
  const notice = app.indexOf('accountDeletionNotice=deletionNotice(completedOutcome)', finalize);
  assert.ok(request >= 0 && immediateLock > request && persistOutcome > immediateLock && scrub > persistOutcome && finalize > scrub && notice > finalize, 'native deletion outcome/lock/scrub/finalization order is unsafe');
  assert.match(app, /manualRevocationRequired:result\.providerCredentials\.manualRevocationRequired/);
  assert.match(app, /if let notice=model\.accountDeletionNotice/);
  assert.match(app, /model\.dismissAccountDeletionNotice\(\)/);
  assert.match(app, /Apple may still require manual authorization removal in Apple Account settings/);
  assert.match(app, /retains the uncertain hosted-deletion transaction and its retry key for safe recovery/);
  assert.match(app, /try credentialScrubber\.scrubNonIdentity\(/);
  assert.match(app, /includeRecoverySecrets:hostedDeletionAccountBindingHash != nil/);
  assert.match(app, /deletionCompletionRecovery\.resume\(/);
  assert.match(app, /clearLocalProfile\([\s\S]*discardPendingAccountDeletion:false,[\s\S]*hostedDeletionAccountBindingHash:record\.accountBindingHash/);
  assert.match(app, /finalizeConfirmedAccountDeletion\([\s\S]*accountBindingHash:outcome\.accountBindingHash/);
  assert.match(app, /NotificationCenter\.default\.post\(name:\.localSandboxDidLock/);
  const localScrub=app.slice(app.indexOf('private func clearLocalProfile('),app.indexOf('private func lockAndDisconnectLocalProfile'));
  const scrubEphemeral=localScrub.indexOf('lockAndDisconnectLocalProfile(preserveDeletionRecovery:!discardPendingAccountDeletion)');
  const durableScrub=localScrub.indexOf('try credentialScrubber.scrubNonIdentity(');
  assert.ok(scrubEphemeral>=0&&durableScrub>scrubEphemeral,'confirmed deletion must lock UI and in-memory keys before fallible durable credential cleanup');
  const ephemeralLock=app.slice(app.indexOf('private func lockAndDisconnectLocalProfile'),app.indexOf('private func invalidateAuthLifecycle'));
  const scrubGeneration=ephemeralLock.indexOf('invalidateAuthLifecycle()');
  const scrubUI=ephemeralLock.indexOf('userID=""');
  const scrubLock=ephemeralLock.indexOf('NotificationCenter.default.post(name:.localSandboxDidLock');
  const scrubDisconnect=ephemeralLock.indexOf('SandboxStore.shared.disconnect()');
  assert.ok(scrubGeneration>=0&&scrubUI>scrubGeneration&&scrubLock>scrubUI&&scrubDisconnect>scrubLock,'ephemeral deletion cleanup must retire auth, clear UI, lock sync state, and disconnect selected-folder access in order');
  const lifecycleInvalidation=app.slice(app.indexOf('private func invalidateAuthLifecycle'),app.indexOf('\n}',app.indexOf('private func invalidateAuthLifecycle')));
  assert.ok(lifecycleInvalidation.indexOf('authLifecycleGeneration.invalidate()')<lifecycleInvalidation.indexOf('nativeAuth.invalidatePersistence(generation:authLifecycleGeneration.capture())'),'AppModel invalidation did not synchronously advance the bearer persistence gate');
  assert.match(app, /Button\("Delete local profile",role:\.destructive\)\{delete=true\}/);
  assert.match(account, /\/api\/auth\/apple\/delete/);
  assert.match(account, /Idempotency-Key/);
  assert.match(account, /request\.setValue\(nil, forHTTPHeaderField: "Cookie"\)/);
  assert.match(account, /accountDeletionResponseBytes = 8_192/);
  assert.match(account, /bearerToken: bearer\.token/);
  assert.match(account, /private static let storageKey = "appleAccountDeletionAttempt\.v2"/);
  assert.match(account, /accountBindingHash/);
  assert.match(account, /requiresReauthentication/);
  assert.match(account, /reauthorizePendingAccountDeletion/);
  assert.match(account, /try deletionVault\.replaceBearer/);
  assert.match(account, /enum NativeAccountDeletionRecoveryState: Equatable/);
  assert.match(account, /case requiresExplicitDiscard/);
  assert.match(account, /func accountDeletionRecoveryState\(/);
  assert.match(account, /catch \{\s*return \.requiresExplicitDiscard\s*\}/);
  assert.match(app, /Button\("Finish hosted account deletion"\)/);
  assert.match(app, /Sign in with the same Apple identity below to refresh authorization and retry with that same key/);
  assert.match(app, /@Published var appleAccountDeletionNeedsDiscard = false/);
  assert.match(app, /case \.requiresExplicitDiscard:/);
  assert.match(app, /Button\("Discard recovery and restart sign-in",role:\.destructive\)/);
  assert.match(app, /\.alert\("Discard hosted deletion recovery\?"/);
  assert.match(app, /It does not undo or confirm any server-side account deletion/);
  assert.match(app, /try nativeAuth\.discardPendingAccountDeletion\(\)[\s\S]*refresh\(\)[\s\S]*You can start a fresh Apple sign-in/);
  assert.match(app, /\.disabled\(model\.appleAuthorizationInFlight \|\| exchanging \|\| \(model\.appleAccountDeletionPending && !model\.appleAccountDeletionNeedsReauthentication\)\)/);
  const refresh = app.slice(app.indexOf('func refresh()'), app.indexOf('func savePolicy()'));
  assert.ok(refresh.indexOf('accountDeletionRecoveryState()') < refresh.indexOf('NativeBearerVault.live.load()'),
    'refresh destroyed an expired bearer before classifying its pending deletion transaction');
  assert.match(refresh, /accountModeVault\.load\(accountBinding:userID\)/);
  assert.match(app, /if self\.nativeAuth\.hasPendingAccountDeletion\(\)\s*\{\s*self\.refresh\(\)\s*\}[\s\S]*else\s*\{\s*await self\.deleteProfile\(\)\s*\}/);
  assert.match(app, /ASAuthorizationAppleIDProvider\.credentialRevokedNotification/);
  assert.match(app, /NotificationCenter\.default\.removeObserver\(appleCredentialRevocationObserver\)/);
  const credentialRecheck = app.slice(app.indexOf('private func recheckAppleCredentialState()'), app.indexOf('func unlock('));
  assert.match(credentialRecheck, /guard self\.appleCredentialStateGeneration\.isCurrent\(credentialStateGeneration\),[\s\S]*self\.userID == checkedUserID else\{return\}[\s\S]*guard error == nil else/);
  assert.ok(
    credentialRecheck.indexOf('nativeAuth.hasPendingAccountDeletion()') < credentialRecheck.indexOf('await self.deleteProfile()'),
    'credential revocation discarded a pending hosted-deletion transaction',
  );
  const authorizedRecheck = credentialRecheck.slice(credentialRecheck.indexOf('case .authorized:'));
  assertInOrder(authorizedRecheck, [
    'transferBlockVault.load()',
    'guard self.unlocked else',
    'storedUser=try Keychain.getChecked("appleUser")',
    'nativeAuth.resumeOrdinaryPendingActivation(',
    'guard await self.refreshNativeSessionIfNeeded(',
    'whileHostedAdmissionBlocked:true',
    'NativeHostedAccessAdmission.allowAfterCredentialVerification()',
  ], 'Apple authorized status must replay activation and finish a checked server refresh while admission stays blocked');
  const localUnlock = sourceSlice(app, 'func unlock(executionGeneration:', 'func connect(_ url:URL)', 'local unlock');
  assertInOrder(localUnlock, ['unlocked=true', 'refresh()', 'recheckAppleCredentialState()'],
    'local unlock must request fresh Apple credential-state verification before restoring hosted admission');
  assert.match(app, /value == \.active\{model\.applicationDidBecomeActive\(\)\}/);
  assert.match(app, /Account ownership mode is unavailable\. Sign in with Apple again before using hosted deletion/);
  assert.match(app, /\.disabled\(model\.deletingAppleAccount \|\| model\.appleAccountMode == nil \|\| model\.appleAuthorizationInFlight\)/);
  const lockTransition = sourceSlice(app, 'private func transitionToLocked(notifyNativeSync:Bool=true)', 'func lock()', 'central lock transition');
  assert.doesNotMatch(lockTransition, /discardPendingAccountDeletion/);
  assertInOrder(lockTransition, [
    'NativeHostedAccessAdmission.block()',
    'retireActiveAgentRunForLock()',
    'invalidateAuthLifecycle()',
    'unlocked=false',
    'NotificationCenter.default.post(name:.localSandboxDidLock',
  ], 'central lock transition must retire execution and auth before UI cleanup');
  assert.doesNotMatch(lockTransition, /bearer|clearChecked/,
    'the shared background/system lock transition destroys a revocable bearer');
  const explicitLock = sourceSlice(app, 'func lock()', 'func deleteProfile()', 'explicit lock');
  assertInOrder(explicitLock, [
    'transitionToLocked()',
    'nativeAuth.prepareSessionsForRetirement()',
    'Task{@MainActor [weak self]',
    'finishPreparedSessionRetirement(',
  ], 'explicit lock must synchronously serialize capture, batch-stage, and detach every exact active or pending token before asynchronous retirement');
  assert.match(app, /value == \.background \{model\.suspendForSystemTransition\(\)\}/);
  assert.doesNotMatch(explicitLock, /clearChecked|clearIfMatchingChecked/,
    'explicit lock clears the bearer before server-or-queue retirement safety');
  assert.doesNotMatch(explicitLock, /discardPendingAccountDeletion/);
  const deleteProfile = sourceSlice(app, 'func deleteProfile() async', 'func deleteHostedAppleAccount()', 'local profile deletion');
  assertInOrder(deleteProfile, [
    'NativeHostedAccessAdmission.block()',
    'invalidateAuthLifecycle()',
    'nativeAuth.prepareSessionsForRetirement()',
    'clearLocalProfile(',
    'preserveNativeBearer:false',
    'finishPreparedSessionRetirement(',
  ], 'profile deletion must serialize checked capture, batch-stage, and exact detachment before any local scrub');
  assert.doesNotMatch(deleteProfile, /NativeBearerVault\.live|\.load\(\)/,
    'profile deletion uses a fail-open or non-injected bearer read');
  const nonIdentityScrub = sourceSlice(account, '    func scrubNonIdentity(', '    func clearIdentity()', 'non-identity credential scrubber');
  assertInOrder(nonIdentityScrub, [
    'try workspaceBindingVault.clearChecked()',
    'for key in ["openaiKey", "openaiModel", "githubToken"]',
    'try accountModeVault.clearChecked()',
    'if !preserveBearer { try bearerVault.clearChecked() }',
  ], 'profile scrub must verify every non-identity credential before its identity commit');
  const identityCommit = sourceSlice(account, '    func clearIdentity()', '    func scrub(', 'identity-last credential commit');
  assertInOrder(identityCommit, [
    'let retainedIdentity = try read("appleUser")',
    'try delete("appleUser")',
    'guard try read("appleUser") == nil',
    'try write("appleUser", retainedIdentity)',
  ], 'identity commit must capture and restore the exact profile identity when checked deletion cannot be proven');
  assertInOrder(localScrub, [
    'try clearShortcutDistributionApproval()',
    'guard try readShortcutDistributionApproval() == nil',
    'try credentialScrubber.scrubNonIdentity(',
    'guard localProfileStateIsCleared()',
    'try transferBlockVault.clearChecked(oldUser:transferBlockedUser)',
    'if discardPendingAccountDeletion {try nativeAuth.discardPendingAccountDeletion()}',
    'try credentialScrubber.clearIdentity()',
  ], 'all fallible profile cleanup and state proof must precede the final identity commit');
  const stateProof = sourceSlice(app, 'localProfileStateIsCleared:@escaping', 'nativeSessionNow:@escaping', 'local profile state-proof dependency');
  assertInOrder(stateProof, [
    'BackgroundExecutionCoordinator.latestStatus() == nil',
    '!SandboxStore.shared.connected',
    'UserDefaults.standard.object(forKey:"sandboxBookmark") == nil',
    'UserDefaults.standard.object(forKey:"githubTarget") == nil',
    'UserDefaults.standard.object(forKey:"policy") == nil',
    'AppProvider.allCases.allSatisfy',
  ], 'the production profile state proof omitted durable or in-memory cleanup state');
  assert.equal(localScrub.slice(localScrub.indexOf('try credentialScrubber.clearIdentity()')).match(/\btry\b/g)?.length ?? 0, 1,
    'a fallible profile mutation follows the final identity commit');
  const signIn=app.slice(app.indexOf('func completeAppleSignIn'),app.indexOf('func disconnectNativeSync'));
  assertInOrder(signIn, [
    'NativeHostedAccessAdmission.block()',
    'invalidateAuthLifecycle()',
    'nativeAuth.reauthorizePendingAccountDeletion(',
    'persistenceGeneration:capturedGeneration',
    'guard authLifecycleGeneration.isCurrent(capturedGeneration)',
    'await deleteHostedAppleAccount()',
  ], 'deletion reauthorization must stay blocked and generation-fenced through its destructive postcondition');
  const ordinaryConnect = signIn.slice(signIn.lastIndexOf('let capturedGeneration=authLifecycleGeneration.capture()'));
  assertInOrder(ordinaryConnect, [
    'nativeAuth.connect(',
    'persistenceGeneration:capturedGeneration',
    'guard authLifecycleGeneration.isCurrent(capturedGeneration)',
    'accountModeVault.save(',
    'NativeHostedAccessAdmission.allowAfterCredentialVerification()',
  ], 'ordinary sign-in must remain generation-fenced and blocked until local account-mode persistence succeeds');
  assert.doesNotMatch(signIn, /guard authLifecycleGeneration\.isCurrent\(capturedGeneration\) else \{[\s\S]{0,180}retireIssuedSession/,
    'a stale coalesced caller may revoke a token owned by the newer generation');
  assert.match(signIn,/NativeAppleAuthorizationCode\.validated\(authorizationCode\)/);
  assert.match(app, /@Published var appleAuthorizationInFlight = false/);
  const appleLogin = sourceSlice(app, 'struct AppleLoginButton:View', 'struct WelcomeView:View', 'Apple authorization UI');
  assertInOrder(appleLogin, [
    'model.appleAuthorizationInFlight = true',
    'await model.completeAppleSignIn(',
    'model.appleAuthorizationInFlight = false',
  ], 'the full Apple authorization flight must be globally visible to lifecycle controls');
  assert.match(appleLogin, /\.disabled\(model\.appleAuthorizationInFlight \|\| exchanging/,
    'another Apple authorization ceremony can start while the global flight is active');
  assert.match(app, /Button\("Discard recovery and restart sign-in",role:\.destructive\)[\s\S]{0,100}\.disabled\(model\.appleAuthorizationInFlight\)/);
  assert.match(app, /Button\("Lock now"\)\{model\.lock\(\)\}\.disabled\(model\.appleAuthorizationInFlight\)/);
  assert.match(app, /Button\("Delete local profile",role:\.destructive\)\{delete=true\}\.disabled\(model\.appleAuthorizationInFlight\)/);
  assert.ok(signIn.indexOf('if switchingProfile') < signIn.indexOf('nativeAuth.connect('), 'arbitrary account switching reached the hosted exchange');
  assert.match(account,/func retireIssuedSession\([\s\S]*retireActiveSession\(issued[\s\S]*deletionVault\.requireReauthentication/);
  assert.match(account,/private func retireActiveSession\([\s\S]*clearIfMatchingChecked\(token: session\.token\)/);
  const persistenceCommit=account.slice(account.indexOf('func persistIfCurrent('),account.indexOf('\n    }',account.indexOf('func persistIfCurrent('))+6);
  assertInOrder(persistenceCommit, [
    'lock.lock()',
    'guard generation == newestGeneration',
    'let previous = try vault.loadChecked(now: now)',
    'previous.mayHaveRevocableGrant(at: now)',
    'try stagePrevious(previous)',
    'try vault.save(issued, now: now)',
  ], 'native bearer replacement must durably stage a still-revocable prior token in the serialized critical section');
});

test('native Apple possible-credential review is visible, strict, and receipt-bound', () => {
  assert.match(account, /credentialReviewRequestBytes = 2_000/);
  assert.match(account, /credentialReviewResponseBytes = 2_000/);
  assert.match(account, /\/api\/auth\/apple\/possible-credential/);
  assert.match(account, /struct NativeAppleCredentialReviewAcknowledgementID: Equatable, Sendable/);
  assert.match(account, /\^\[A-Za-z0-9_-\]\{43\}\$/);
  assert.match(account, /enum NativeAppleCredentialReview: Equatable, Sendable, Decodable[\s\S]*case clear[\s\S]*case required/);
  assert.match(account, /requireExactKeys\(decoder, expected: Set\(CodingKeys\.allCases\.map\(\\\.rawValue\)\)\)/);
  assert.match(account, /guard try container\.decodeNil\(forKey: \.acknowledgementId\),[\s\S]*try container\.decodeNil\(forKey: \.markedAt\)/);
  const nativeAPI = account.slice(account.indexOf('struct NativeAppleAuthAPI'), account.indexOf('private struct NativeRevokeResponse'));
  assert.match(nativeAPI, /func possibleCredentialReview\(bearer: String\)/);
  assert.match(nativeAPI, /NativeJSON\.requireJSONSuccessContentType\(result\)[\s\S]*NativeJSON\.decode\([\s\S]*NativeAppleCredentialReview\.self/);
  assert.match(nativeAPI, /func acknowledgePossibleCredentialReview\([\s\S]*NativeAppleCredentialReviewAcknowledgement\.self/);
  const controller = account.slice(account.indexOf('struct NativeAppleAuthController'), account.indexOf('private struct NativeRecoverySecretRegistration'));
  const acknowledge = controller.slice(controller.indexOf('func acknowledgePossibleCredentialReview'), controller.indexOf('func invalidatePersistence'));
  const post = acknowledge.indexOf('api.acknowledgePossibleCredentialReview');
  const finalRead = acknowledge.indexOf('api.possibleCredentialReview', post);
  const finalFence = acknowledge.indexOf('vault.load(now: now)?.token == session.token', finalRead);
  const returned = acknowledge.indexOf('return current', finalFence);
  assert.ok(post >= 0 && finalRead > post && finalFence > finalRead && returned > finalFence,
    'native review state can clear without POST confirmation, final GET, and current-session fence');

  assert.match(app, /enum AppleCredentialReviewDisplayState: Equatable[\s\S]*case notChecked[\s\S]*case clear[\s\S]*case required\(markedAt: Date\)/);
  assert.match(app, /@Published private\(set\) var appleCredentialReviewDisplayState/);
  assert.match(app, /private var appleCredentialReview:NativeAppleCredentialReview\?/);
  const refresh = app.slice(app.indexOf('func refreshAppleCredentialReview()'), app.indexOf('func acknowledgeAppleCredentialReview()'));
  assert.match(refresh, /guard let review=try await nativeAuth\.possibleCredentialReview\(\)/);
  assert.match(refresh, /guard requireNativeSessionAuthority\(\) else\{return\}/);
  assert.match(refresh, /The last visible warning, if any, was kept/);
  const modelAcknowledge = app.slice(app.indexOf('func acknowledgeAppleCredentialReview()'), app.indexOf('func lock()'));
  const exactReceipt = modelAcknowledge.indexOf('nativeAuth.acknowledgePossibleCredentialReview(receipt.acknowledgementID)');
  const applyConfirmed = modelAcknowledge.indexOf('applyAppleCredentialReview(current)', exactReceipt);
  assert.ok(exactReceipt >= 0 && applyConfirmed > exactReceipt,
    'native UI changed review state before exact server confirmation');
  assert.match(modelAcknowledge, /APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED/);
  assert.match(modelAcknowledge, /APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS/);
  assert.match(modelAcknowledge, /APPLE_ACCOUNT_DELETION_IN_PROGRESS/);
  assert.match(modelAcknowledge, /try await nativeAuth\.possibleCredentialReview\(\)/);
  assert.match(modelAcknowledge, /The existing cleanup warning was kept/);
  assert.equal((app.match(/appleCredentialReviewDisplayState = \.clear/g) ?? []).length, 1,
    'native UI has a second unconfirmed path that clears credential review state');

  const section = app.slice(app.indexOf('private struct AppleCredentialReviewSection'), app.indexOf('struct SettingsView'));
  assert.match(section, /Section\("Apple authorization review"\)/);
  assert.match(section, /Apple credential cleanup needs review/);
  assert.match(section, /LabeledContent\("Detected",value:markedAt\.formatted/);
  assert.match(section, /https:\/\/account\.apple\.com\/account\/manage/);
  assert.match(section, /Open Apple Account settings/);
  assert.match(section, /Button\("I reviewed Apple Account"\)\{confirmingReview=true\}/);
  assert.match(section, /\.alert\("Confirm Apple Account review\?"/);
  assert.match(section, /Confirm only after you reviewed Sign in with Apple in Apple Account settings/);
  assert.match(section, /a changed receipt will be rejected/);
  assert.match(section, /Sign in with Apple again above after your review, then confirm this receipt/);
  assert.doesNotMatch(section, /acknowledgementID|acknowledgementId|rawValue/);
  assert.match(section, /\.task\{await model\.refreshAppleCredentialReview\(\)\}/);
  assert.match(app, /await refreshAppleCredentialReview\(\)/);
  const appleLogin = app.slice(app.indexOf('struct AppleLoginButton'), app.indexOf('struct WelcomeView'));
  assert.doesNotMatch(appleLogin, /appleCredentialReview/, 'credential cleanup warning blocked Sign in with Apple recovery');
});

test('native Apple clear status expires with bearer authority while required warnings survive', () => {
  assert.match(account, /struct NativeBearerAuthorityWindow: Equatable, Sendable/);
  assert.match(account, /let remaining = expiresAt\.timeIntervalSince\(now\)[\s\S]*remaining > 0/);
  const downgrade = app.slice(
    app.indexOf('private func downgradeAppleCredentialReviewClear()'),
    app.indexOf('private func applyAppleCredentialReview'),
  );
  assert.match(downgrade, /guard case \.clear=appleCredentialReviewDisplayState else\{return\}/);
  assert.match(downgrade, /appleCredentialReview=nil[\s\S]*appleCredentialReviewDisplayState = \.notChecked/);
  assert.doesNotMatch(downgrade, /\.required/, 'bearer retirement can hide an unresolved credential warning');
  assert.equal((app.match(/appleCredentialReviewDisplayState = \.notChecked/g) ?? []).length, 1,
    'credential review status bypasses the clear-only downgrade transition');

  const invalidation = app.slice(
    app.indexOf('private func invalidateAuthLifecycle()'),
    app.indexOf('private func downgradeAppleCredentialReviewClear()'),
  );
  assert.match(invalidation, /clearNativeSessionAuthority\(\)/);
  const clearAuthority = app.slice(
    app.indexOf('private func clearNativeSessionAuthority()'),
    app.indexOf('private func refreshNativeSessionIfNeeded('),
  );
  assert.match(clearAuthority, /cancelNativeSessionExpiryTask\(\)[\s\S]*nativeSessionExpiry=nil[\s\S]*downgradeAppleCredentialReviewClear\(\)/);
  const credentialCheckSuspension = app.slice(
    app.indexOf('private func suspendNativeSessionAuthorityForCredentialCheck()'),
    app.indexOf('private func refreshNativeSessionIfNeeded('),
  );
  assert.match(credentialCheckSuspension, /appleCredentialReviewLifecycleGeneration\.invalidate\(\)[\s\S]*clearNativeSessionAuthority\(\)/);
  assert.doesNotMatch(credentialCheckSuspension, /authLifecycleGeneration\.invalidate|nativeAuth\.invalidatePersistence/,
    'credential-state suspension can cancel a valid in-flight Apple exchange');

  const lockTransition = sourceSlice(app, 'private func transitionToLocked(notifyNativeSync:Bool=true)', 'func lock()', 'credential-preserving lock transition');
  assertInOrder(lockTransition, ['NativeHostedAccessAdmission.block()', 'invalidateAuthLifecycle()', 'unlocked=false'],
    'shared lock transition must block hosted admission and retire in-memory authority');
  assert.doesNotMatch(lockTransition, /clearChecked|clearIfMatchingChecked/,
    'shared background lock transition destroys durable bearer retirement evidence');
  assert.doesNotMatch(lockTransition, /appleCredentialReview=nil|appleCredentialReviewDisplayState = \.notChecked/,
    'locking can expire an affirmative credential-review status');
  const disconnect = sourceSlice(app, 'func disconnectNativeSync(executionGeneration:ExecutionContinuationGate.Generation)', 'func refreshAppleCredentialReview()', 'native disconnect');
  assertInOrder(disconnect, [
    'try ExecutionContinuationGate.shared.requireCurrent(executionGeneration)',
    'NativeHostedAccessAdmission.block()',
    'invalidateAuthLifecycle()',
    'NotificationCenter.default.post(name:.localSandboxDidLock',
    'try await nativeAuth.disconnect()',
  ], 'disconnecting must reject stale work, block admission, retire auth, and lock local state before awaiting bearer retirement');
  assert.equal((disconnect.match(/NotificationCenter\.default\.post\(name:\.localSandboxDidLock/g) ?? []).length, 1,
    'disconnect must publish exactly one immediate lock notification');
  const readbackStart = disconnect.indexOf('let retainedBearer:Bool');
  const clearedBearerStart = disconnect.indexOf('if !retainedBearer', readbackStart);
  const retainedBearerStart = disconnect.indexOf('} else {', clearedBearerStart);
  assert.ok(readbackStart >= 0 && clearedBearerStart > readbackStart && retainedBearerStart > clearedBearerStart,
    'disconnect bearer-failure branches are missing or out of order');
  const unreadableBearerBranch = disconnect.slice(readbackStart, clearedBearerStart);
  assertInOrder(unreadableBearerBranch, [
    'nativeAuth.vault.loadForRetirement()',
    'transitionToLocked(notifyNativeSync:false)',
    'The hosted bearer could not be verified or removed from Keychain',
    'return',
  ], 'an unreadable bearer must retain the immediate admission block and lock state without a duplicate notification');
  const clearedBearerBranch = disconnect.slice(clearedBearerStart, retainedBearerStart);
  const retainedBearerBranch = disconnect.slice(retainedBearerStart);
  assert.match(clearedBearerBranch, /reportNativeRevocationFollowUp\(error,context:"The native bearer was cleared locally\."\)/);
  assert.doesNotMatch(clearedBearerBranch, /transitionToLocked/,
    'a deferred revocation with a cleared bearer must not adopt the retained-bearer lock transition');
  assertInOrder(retainedBearerBranch, [
    'transitionToLocked(notifyNativeSync:false)',
    'self.error="The hosted bearer could not be removed from Keychain, so Local Sandbox was locked.',
    'return',
  ], 'a disconnect failure that retains the bearer must lock and retire the execution generation');
  assert.equal((disconnect.match(/transitionToLocked\(notifyNativeSync:false\)/g) ?? []).length, 2,
    'unreadable and retained bearer failures must both reuse the non-notifying lock transition');
  const profileLock = app.slice(
    app.indexOf('private func lockAndDisconnectLocalProfile'),
    app.indexOf('private func invalidateAuthLifecycle'),
  );
  assert.match(profileLock, /invalidateAuthLifecycle\(\)/);
  assert.doesNotMatch(profileLock, /appleCredentialReview=nil|appleCredentialReviewDisplayState = \.notChecked/,
    'profile cleanup bypasses the clear-only transition and could hide a required warning');

  const sessionRefresh = app.slice(
    app.indexOf('private func refreshNativeSessionIfNeeded('),
    app.indexOf('private func recheckAppleCredentialState()'),
  );
  assert.match(sessionRefresh, /guard let session = try await nativeAuth\.refreshIfNeeded\([\s\S]*persistenceGeneration:refreshGeneration,[\s\S]*allowWhileHostedAdmissionBlocked:whileHostedAdmissionBlocked[\s\S]*\) else \{[\s\S]*clearNativeSessionAuthority\(\)/);
  assert.doesNotMatch(sessionRefresh, /guard let session = try await nativeAuth\.refreshIfNeeded\([\s\S]*\) else \{[\s\S]*invalidateAuthLifecycle\(\)/,
    'an empty session refresh can supersede a concurrent Apple exchange');
  const credentialRecheck = app.slice(
    app.indexOf('private func recheckAppleCredentialState()'),
    app.indexOf('private func blockHostedAccessForTransferredCredential'),
  );
  assert.ok(credentialRecheck.indexOf('suspendNativeSessionAuthorityForCredentialCheck()') < credentialRecheck.indexOf('NotificationCenter.default.post(name:.localSandboxDidLock'),
    'Apple credential revalidation can suspend the bearer while leaving a stale clear status');
  assert.doesNotMatch(credentialRecheck, /invalidateAuthLifecycle\(\)/,
    'foreground Apple credential recheck can supersede a concurrent Apple exchange');
  const modelRefresh = app.slice(app.indexOf('func refresh()'), app.indexOf('func savePolicy()'));
  assert.match(modelRefresh, /if nativeSessionExpiry == nil \{downgradeAppleCredentialReviewClear\(\)\}/);
  assert.doesNotMatch(modelRefresh, /if nativeSessionExpiry == nil \{invalidateAuthLifecycle\(\)\}/,
    'ordinary local refresh can supersede an in-flight Apple exchange before it installs a bearer');

  const reviewRefresh = app.slice(
    app.indexOf('func refreshAppleCredentialReview()'),
    app.indexOf('func acknowledgeAppleCredentialReview()'),
  );
  assert.match(reviewRefresh, /guard requireNativeSessionAuthority\(\) else\{return\}/);
  assert.match(reviewRefresh, /serviceError\.status == 401 \{ invalidateAuthLifecycle\(\) \}/);
  assert.match(reviewRefresh, /APPLE_NATIVE_AUTH_SUPERSEDED[\s\S]*invalidateAuthLifecycle\(\)/);
  const acknowledgement = app.slice(app.indexOf('func acknowledgeAppleCredentialReview()'), app.indexOf('func lock()'));
  assert.match(acknowledgement, /guard requireNativeSessionAuthority\(\) else\{return\}/);
  assert.match(acknowledgement, /serviceError\.status == 401 \{ invalidateAuthLifecycle\(\) \}/);

  assert.match(app, /@Published private\(set\) var nativeSessionExpiry: Date\?/);
  assert.match(app, /private let nativeSessionNow:@MainActor \(\)->Date/);
  assert.match(app, /private var nativeSessionExpiryGeneration=NativeLifecycleGeneration\(\)/);
  assert.match(app, /private var nativeSessionExpiryTask:Task<Void,Never>\?/);
  const schedule = app.slice(
    app.indexOf('private func scheduleNativeSessionExpiryTask'),
    app.indexOf('private func nativeSessionExpiryTaskFired'),
  );
  const cancel = schedule.indexOf('cancelNativeSessionExpiryTask()');
  const generation = schedule.indexOf('nativeSessionExpiryGeneration.capture()');
  const task = schedule.indexOf('Task{@MainActor [weak self]');
  assert.ok(cancel >= 0 && generation > cancel && task > generation,
    'native expiry task is not cancelled and generation-bound before launch');
  assert.match(schedule, /Task<Never,Never>\.sleep\(for:\.seconds\(remaining\)\)/);
  const expiryFire = app.slice(
    app.indexOf('private func nativeSessionExpiryTaskFired'),
    app.indexOf('private func reconcileNativeSessionAuthorityAfterTimeChange'),
  );
  assert.match(expiryFire, /nativeSessionExpiryGeneration\.isCurrent\(generation\)[\s\S]*nativeSessionExpiry == expectedExpiry/);
  assert.match(expiryFire, /if window\.isAvailable[\s\S]*scheduleNativeSessionExpiryTask[\s\S]*else \{[\s\S]*invalidateAuthLifecycle\(\)/);
  assert.match(app, /UIApplication\.significantTimeChangeNotification/);
  const becameActive = app.slice(app.indexOf('func applicationDidBecomeActive()'), app.indexOf('var nativeSessionAuthorityAvailable'));
  assert.ok(becameActive.indexOf('reconcileNativeSessionAuthorityAfterTimeChange()') < becameActive.indexOf('refresh()'),
    'foreground resume does not reconcile wall-clock expiry before reading session state');

  const section = app.slice(app.indexOf('private struct AppleCredentialReviewSection'), app.indexOf('struct SettingsView'));
  assert.match(section, /nativeSessionAuthorityAvailable/);
  assert.doesNotMatch(section, /nativeSessionExpiry == nil/,
    'Apple review controls trust a non-nil but expired bearer date');
  assert.match(app, /else if model\.nativeSessionAuthorityAvailable,let expiry=model\.nativeSessionExpiry/);
});

test('encrypted native sync is UI-wired, manual, conflict-aware, and cross-surface recoverable', () => {
  assert.match(app, /NavigationLink\{EncryptedWorkspaceSyncView\(\)\}/);
  assert.match(sync, /Review remote changes/);
  assert.match(sync, /Import reviewed remote changes/);
  assert.match(sync, /Push this native path/);
  assert.match(sync, /Keep reviewed native copy/);
  assert.match(sync, /ShareLink\("Export recovery secret"/);
  assert.match(sync, /hosted or local PWA/);
  assert.match(sync, /create or reopen your Apple-owned workspace/);
  assert.match(sync, /link Apple from that signed-in account before this device's first native sign-in/);
  assert.match(sync, /never merges accounts by email/);
  assert.match(sync, /if current == item\.remoteContent/);
  assert.match(sync, /SYNC_PULL_PARTIAL_/);
  assert.match(sync, /NATIVE_FILE_CHANGED_BEFORE_PUSH_REVIEW_AGAIN/);
  assert.match(sync, /reviewIndex\.decision\(path: path\.value, current: currentBase\)/);
  assert.match(sync, /reviewIndex\.remember\(path:/);
  assert.match(sync, /Later native edits, if any, remain unsynced/);
  assert.match(sync, /Rotate recovery key/);
  assert.match(sync, /Save current recovery key to iCloud Keychain/);
  assert.match(sync, /Remove recovery key from iCloud Keychain/);
  assert.match(sync, /Delete hosted encrypted workspace/);
  assert.match(sync, /Obsolete iCloud recovery credentials/);
  assert.match(sync, /recoveryVault\.registeredWorkspaceIds\(\)/);
  assert.equal((sync.match(/LocalAccess\.authenticate\(executionGeneration: executionGeneration\)/g) ?? []).length, 6,
    'every raw workspace authentication caller must inject its tap-time generation');
  assertAuthenticatedEntry(
    sync,
    'Button("Reveal iCloud recovery secret")',
    'Text("Only non-private workspace/',
    'sync.revealICloudRecoverySecret(',
    'recovery-secret reveal entry',
  );
  assertAuthenticatedEntry(
    sync,
    '.alert("Rotate recovery key?"',
    '.alert("Save recovery key to iCloud Keychain?"',
    'await sync.rotateRecovery(',
    'recovery rotation entry',
  );
  assertAuthenticatedEntry(
    sync,
    '.alert("Save recovery key to iCloud Keychain?"',
    '.alert("Remove iCloud recovery key?"',
    'await sync.enrollRecoveryInICloud(',
    'iCloud recovery enrollment entry',
  );
  assertAuthenticatedEntry(
    sync,
    '.alert("Remove iCloud recovery key?"',
    '.alert("Delete hosted encrypted workspace?"',
    'sync.removeRecoveryFromICloud(',
    'iCloud recovery removal entry',
  );
  assertAuthenticatedEntry(
    sync,
    '.alert("Delete hosted encrypted workspace?"',
    '.alert("Remove obsolete iCloud recovery credential?"',
    'await sync.deleteUnlockedWorkspace(',
    'hosted workspace deletion entry',
  );
  assertAuthenticatedEntry(
    sync,
    '.alert("Remove obsolete iCloud recovery credential?"',
    'private func preview(',
    'sync.removeOrphanedRecoveryFromICloud(workspaceId: workspaceId,',
    'orphaned recovery removal entry',
  );
  assert.match(sync, /expectedRevision: snapshot\.snapshotRevision/);
  assert.match(sync, /verified\.recovery == rotated\.1/);
  assert.match(account, /kind = "replaceRecovery"/);
  assert.match(account, /kind = "deleteWorkspace"/);
  assert.match(account, /pendingPrefix = "pending\."/);
  assert.match(sync, /SandboxStore\.shared\.delete\(path, expectedSHA256: item\.nativeSHA256\)/);
  assert.match(sync, /content: nativeContent/);
  assert.match(account, /snapshotRevision/);
  assert.match(account, /syncResponseBytes = 512 \* 1_024/);
  assert.match(crypto, /legacyMaximumCiphertextCharacters = 100_000/);
  assert.match(crypto, /maximumCiphertextCharacters = 120_000/);
  assert.doesNotMatch(sync, /Timer\.|scheduledTimer|repeatForever/);
});

test('unlock cannot approve unseen remote values as a push base', () => {
  const unlock = sync.slice(sync.indexOf('func unlock('), sync.indexOf('func revealICloudRecoverySecret'));
  assert.match(unlock, /_ = try self\.open\(snapshot: snapshot, session: session\)/);
  assert.match(unlock, /self\.reviewIndex\.clear\(\)/);
  assert.match(unlock, /self\.stagedDifferences = \[\]/);
  assert.doesNotMatch(unlock, /reviewIndex\.remember|rememberReviewed/);

  const stagePull = sync.slice(sync.indexOf('func stagePull('), sync.indexOf('func applyStagedPull'));
  const published = stagePull.indexOf('self.differences = staged');
  const reset = stagePull.indexOf('self.reviewIndex.clear()');
  const displayedOnly = stagePull.indexOf('for item in staged');
  const remembered = stagePull.indexOf('self.reviewIndex.remember(path: item.path, revision: item.remoteRevision, content: item.remoteContent)');
  assert.ok(published >= 0 && reset > published && displayedOnly > reset && remembered > displayedOnly,
    'stagePull must establish bases only from differences published to the comparison UI');

  const push = sync.slice(sync.indexOf('func push('), sync.indexOf('func keepNativeAfterConflict'));
  assert.match(push, /reviewIndex\.decision\(path: path\.value, current: currentBase\)/);
  assert.match(push, /case \.conflict:[\s\S]*self\.conflict = NativePushConflict/);
  assert.match(push, /Compare both versions before keeping the native copy/);
});

test('native editor journals every edit and exposes autosave, recovery, failure, and conflict controls', () => {
  assert.match(app, /NativeFileEditorView\(path:selected\)/);
  assert.match(app, /listWorkspaceFilesRecursively\(\)/);
  assert.match(store, /case \.folderContains[\s\S]*containsRecursively\(SandboxPath\(rawPath\), in: folder\)/);
  assert.match(editor, /extension NativeAutosaveJournal/);
  assert.match(editor, /Button\("Save now"/);
  assert.match(editor, /Button\("Retry journal and save"/);
  assert.match(editor, /Button\("Discard unreadable recovery journal"/);
  assert.match(editor, /Button\("Keep draft"/);
  assert.match(editor, /Button\("Discard draft"/);
  assert.match(editor, /interactiveDismissDisabled\(editor\.hasPendingChanges\)/);
  assert.match(autosave, /try journal\.save\(draft\)/);
  assert.match(autosave, /case saving/);
  assert.match(autosave, /case saved/);
  assert.match(autosave, /case offlineOrFailed/);
  assert.match(autosave, /case conflict/);
  assert.match(store, /writeAutosaveJournal/);
  assert.match(store, /AUTOSAVE_JOURNAL_READBACK_FAILED/);
});

test('Siri exposes every provider route and refreshes App Shortcut parameters', () => {
  for (const choice of ['saved','bestLocal','apple','local','chatgpt','grok','grokbot','claude']) {
    assert.match(routing, new RegExp(`case ${choice === 'bestLocal' ? 'bestLocal = "best-local"' : choice}`));
  }
  const shortcutProvider = intents.slice(intents.indexOf('struct LocalSandboxShortcuts'), intents.indexOf('struct BeginOracleTaskIntent'));
  const shortcutDeclarations = [...shortcutProvider.matchAll(/\bAppShortcut\s*\(/g)];
  const declaredIntentTypes = [...shortcutProvider.matchAll(/\bAppShortcut\s*\(intent:([A-Za-z0-9_]+)\(\)/g)].map((match) => match[1]);
  const phraseLists = [...shortcutProvider.matchAll(/phrases\s*:\s*\[([^\]]*)\]/g)].map((match) => match[1]);
  const providerSelectionDeclaration = routing.slice(routing.indexOf('enum ProviderSelection'), routing.indexOf('var id:', routing.indexOf('enum ProviderSelection')));
  const providerSelectionCount = providerSelectionDeclaration.match(/^\s*case\s+/gm)?.length ?? 0;
  const providerParameterizedPhraseCount = phraseLists.filter((phrase) => phrase.includes('\\(\\.$provider)')).length;
  assert.equal(shortcutDeclarations.length, 10, 'iOS 27 App Shortcut declaration count drifted');
  assert.equal(shortcutDeclarations.length - 1, 9, 'iOS 26 App Shortcut declaration count drifted');
  assert.ok(shortcutDeclarations.length <= 10, 'Apple permits at most ten App Shortcuts');
  assert.ok(phraseLists.every((phrase) => (phrase.match(/\\\(\\\.\$/g)?.length ?? 0) <= 1), 'an App Shortcut phrase contains more than one intent parameter');
  assert.equal(providerParameterizedPhraseCount * providerSelectionCount, 16, 'provider phrase expansion drifted');
  assert.ok(providerParameterizedPhraseCount * providerSelectionCount <= 1000, 'expanded App Shortcut phrases exceed Apple’s limit');
  const ios26IntentTypes = declaredIntentTypes.filter((name) => name !== 'RunLongAppleTaskIntent');
  const declaredTitles = ios26IntentTypes.map((name) => {
    const start = intents.indexOf(`struct ${name}:`);
    const end = intents.indexOf('\nstruct ', start + 1);
    const block = intents.slice(start, end < 0 ? undefined : end);
    const title = block.match(/static let title\s*:\s*LocalizedStringResource\s*=\s*"([^"]+)"/)?.[1];
    assert.ok(title, `Could not read the title for ${name}`);
    return title;
  });
  assert.equal(new Set(declaredTitles).size, 9, 'iOS 26 App Shortcut titles must be unique');
  assert.match(installGuide, /registers nine actions on iOS 26 and later:/);
  for (const title of declaredTitles) assert.match(installGuide, new RegExp(title));
  assert.match(installGuide, /iOS 27 also exposes Run Long Apple Task/);
  assert.equal(intents.match(/@Parameter\(title:\s*"Provider",\s*default:\s*\.saved\)/g)?.length, 2);
  assert.match(intents, /Run a task with \\\(\\\.\$provider\) in \\\(\.applicationName\)/);
  assert.match(intents, /Begin an Oracle task with \\\(\\\.\$provider\) in \\\(\.applicationName\)/);
  assert.match(intents, /Summary\("Run \\\(\\\.\$goal\) with \\\(\\\.\$provider\)"\)/);
  assert.match(intents, /Summary\("Begin \\\(\\\.\$goal\) with \\\(\\\.\$provider\)"\)/);
  assert.match(intents, /case \.onDeviceApple:[\s\S]*AgentRunner\.shared\.run/);
  assert.match(intents, /case \.shortcut:[\s\S]*ShortcutCoordinator\.shared\.begin/);
  assert.match(intents, /AppIntentTaskOutput\.terminalAppleReceipt/);
  assert.match(intents, /ShortcutCoordinator\.shared\.appIntentOutput\(payload:prompt,executionGeneration:executionGeneration\)/);
  assert.match(intents, /ShortcutCoordinator\.shared\.appIntentOutput\(payload:output,executionGeneration:executionGeneration\)/);
  assert.match(routing, /enum AppIntentTaskOutput: Codable, Equatable/);
  assert.match(routing, /case terminalAppleReceipt = "terminal-apple-receipt"/);
  assert.match(routing, /case providerHandoffPrompt = "provider-handoff-prompt"/);
  assert.match(routing, /case terminalProviderReceipt = "terminal-provider-receipt"/);
  assert.match(routing, /case onDeviceApple = "on-device-apple"/);
  assert.match(routing, /case appShortcut = "app-shortcut"/);
  assert.match(routing, /decision == \.onDeviceApple/);
  assert.match(routing, /decision == \.appShortcut/);
  assert.match(routing, /fields == baseFields\.union\(\["adapterName"\]\)/);
  assert.match(routing, /recordType\\\":\\\"provider-handoff-prompt/);
  assert.match(bridge, /ProviderHandoffPromptHeader\(provider:provider,selection:session\.providerSelection,origin:session\.taskOrigin\)\.jsonLine/);
  assert.match(bridge, /shortcutAdapterName:adapterName/);
  assert.ok((app.match(/LocalSandboxShortcuts\.updateAppShortcutParameters\(\)/g)?.length??0)>=2);
  assert.match(bridge, /LocalSandboxShortcuts\.updateAppShortcutParameters\(\)/);
});

test('provider qualification is measured, device-local, tamper-evident, and deterministic', () => {
  for (const probe of ['strictJSON','readTool','listTool','patchTool','boundedContext']) assert.match(routing,new RegExp(`case ${probe}`));
  assert.match(qualification, /freshnessSeconds:\s*TimeInterval\s*=\s*7 \* 24 \* 60 \* 60/);
  assert.match(qualification, /pendingTimeoutSeconds:\s*TimeInterval\s*=\s*10 \* 60/);
  assert.match(qualification, /clockRollbackToleranceSeconds:\s*TimeInterval\s*=\s*5 \* 60/);
  assert.match(qualification, /maximumStoredAttempts = 240/);
  assert.match(qualification, /Set\(dailyKeys\)\.count == attempts\.count/);
  assert.match(qualification, /availableProbes = ProviderQualificationProbe\.allCases\.filter \{ !recordedToday\.contains\(\$0\) \}/);
  assert.match(qualification, /PROVIDER_QUALIFICATION_DAILY_SUITE_ALREADY_RECORDED/);
  assert.match(qualification, /PROVIDER_QUALIFICATION_CLOCK_ROLLBACK_DETECTED/);
  assert.match(qualification, /completedToday\.count == ProviderQualificationSnapshot\.requiredSamples/);
  assert.match(qualification, /Apple checks already recorded today\./);
  assert.match(qualification, /HMAC<SHA256>\.authenticationCode/);
  assert.match(qualification, /kSecRandomDefault/);
  const signingKey = sourceSlice(qualification, 'private static func signingKey()', 'private static func hmac', 'provider qualification signing key');
  assert.match(signingKey, /Keychain\.getChecked\(ledgerKeyName\)/);
  assert.doesNotMatch(signingKey, /Keychain\.get\(ledgerKeyName\)/);
  assertInOrder(signingKey, [
    'Keychain.getChecked(ledgerKeyName)',
    'SecRandomCopyBytes',
    'Keychain.set($0, for: ledgerKeyName)',
  ], 'qualification signing-key creation must begin with a checked read and use a checked write');
  const signingKeyResolver = sourceSlice(qualification, 'static func resolveSigningKey(using operations:', 'private static func signingKey()', 'provider qualification signing-key transaction');
  assertInOrder(signingKeyResolver, [
    'try operations.readChecked()',
    'let generated = try operations.generateRandomBytes()',
    'try operations.writeChecked(generated.base64EncodedString())',
    'let encoded = try operations.readChecked()',
    'stored == generated',
    'return SymmetricKey(data: stored)',
  ], 'qualification signing-key transaction must distinguish retained state and verify exact readback before use');
  assert.match(qualification, /FileProtectionType\.complete/);
  assert.match(qualification, /LocalSandboxPrivateRouting/);
  assert.match(qualification, /guard constantTimeEqual\(expected, signed\.hmacSHA256\)/);
  assert.match(bridge, /PROVIDER_QUALIFICATION_LEDGER_UNREADABLE/);
  assert.match(routing, /provider != \.apple[\s\S]*qualifications\[provider\]\?\.qualifies\(for: requirements\) != true/);
  assert.match(routing, /PROVIDER_QUALIFICATION_REQUIRED/);
  assert.doesNotMatch(qualification, /struct ProviderQualificationAttempt[\s\S]{0,1200}(?:response|prompt|credential|token): String/);
  assert.match(qualification, /schemaPassCount = schemaPassed \? 1 : 0/);
  assert.match(qualification, /upgradedToCurrentSchema/);
  assert.match(qualification, /schemaVersion: Self\.currentSchemaVersion/);
  assert.match(qualification, /\$0\.outcome != \.started/);
  assert.match(routing, /schemaPassCount \* 5 >= sampleCount \* 4/);
  assert.match(routing, /assertionPassCount \* 5 >= assertionCount \* 4/);
  assert.match(routing, /toolProbePassCount >= Self\.requiredToolProbes/);
  assert.match(routing, /maximumContextCharacters >= requirements\.minimumContextCharacters/);
  assert.match(routing, /medianDurationBucketMilliseconds < right\.medianDurationBucketMilliseconds/);
  assert.match(routing, /let fixedOrder: \[AppProvider\] = \[\.apple, \.local, \.chatgpt, \.claude, \.grok, \.grokbot\]/);
  assert.match(routing, /if !comparable\.isEmpty/);
  assert.match(routing, /left\.schemaPassCount \* max\(1, right\.sampleCount\)/);
  assert.match(routing, /MANUAL_PROVIDER_RETURN_REQUIRES_USER/);
  assert.match(routing, /case recentLocallyValidatedResponse = "recent-locally-validated-response"/);
  assert.match(intents, /struct BeginProviderQualificationIntent: AppIntent/);
  assert.match(intents, /struct RecordProviderQualificationIntent: AppIntent/);
  assert.match(intents, /struct ConfigureOracleRoutingIntent: AppIntent/);
  assert.match(intents, /ProviderQualificationStore\.complete\(attemptID: attemptID, provider: exact, response: response, appIntentTransportObserved: true\)/);
  assert.match(intents, /ProviderQualificationStore\.externalChallenge\(provider: exact, appIntentTransportObserved: true\)/);
  assert.match(qualification, /return try createChallenge\(provider, contextCharacters, appIntentTransportObserved\)/);
  assert.match(intents, /record that it reached this App Intent/);
  assert.match(intents, /This does not prove unattended execution, provider identity, account state, or model provenance/);
  assert.match(qualification, /attempt\.appIntentReturnObserved = attempt\.appIntentReturnObserved && appIntentTransportObserved/);
  assert.match(qualification, /filter \{ \$0\.outcome != \.started && \$0\.appIntentReturnObserved \}/);
  assert.match(qualification, /appIntentReturnProbes\.count >= ProviderQualificationSnapshot\.requiredDistinctProbes/);
  assert.match(qualification, /ProviderRuntimeIdentity\.operatingSystemDescriptor/);
  assert.match(qualification, /ProcessInfo\.processInfo\.operatingSystemVersionString/);
  assert.match(routing, /version\.patchVersion/);
  assert.match(routing, /\|build=\\\(buildDescription\)/);
  for (const source of [readme, architecture, installGuide, roadmap, releaseGuide, guideGenerator]) {
    assert.match(source, /240 attempts/);
    assert.match(source, /20 freshest attempts/);
  }
  for (const source of [readme, architecture, installGuide, roadmap, releaseGuide]) {
    assert.match(source, /full OS major, minor, and patch version/);
    assert.match(source, /OS build descriptor/);
    assert.match(source, /observed App Intent return/);
    assert.match(source, /physical-device evidence|physical device/);
  }
  assert.match(bridge, /ProviderQualificationStore\.qualificationActive \{ return \.providerQualificationActive \}/);
  assert.match(routing, /let evidence: ProviderRoutingEvidence\?/);
  assert.match(routing, /decision\.isRunnable[\s\S]*try candidate\.validate\(\)[\s\S]*evidence = nil/);
  assert.match(app, /Run five Apple checks/);
  assert.match(app, /Apply Oracle recommendation/);
  assert.doesNotMatch(app, /I received the test response/);
  assert.match(app, /response is validated in memory and is not saved/);
  assert.match(app, /resolvedRoute:route/);
  assert.match(app, /session\.shortcutAdapterName/);
  assert.match(app, /inboxCard\("Working",count:workingCount/);
  assert.match(app, /\["awaiting_response","applying"\]\.contains\(session\.phase\)/);
  assert.match(bridge, /return \.providerResponsePending/);
  assert.match(bridge, /return \.applyingProviderResponse/);
  assert.match(bridge, /validateActiveExternalRoute\(_ session: ShortcutSession\)/);
  assert.match(bridge, /let resolved = ProviderRoutingPolicy\.resolve\(/);
  assert.match(bridge, /resolved\.provider == provider,[\s\S]*resolved\.evidence == session\.routingEvidence/);
  assert.match(bridge, /Provider qualification or route evidence changed\. Review the device checks and begin a new task\./);
  assert.match(models, /enum SavedExecutionAuthorization[\s\S]*SAVE_AUTHORIZATION_BEFORE_RUNNING/);
  assert.doesNotMatch(app, /restored\.validated\(\);UserDefaults\.standard\.set\(try JSONEncoder\(\)\.encode\(policy\),forKey:"policy"\)/);
  assert.match(workspacePreparation, /Workspace policy is configuration only\./);
  assert.match(app, /Resource, clipboard, and cloud-consent changes take effect only after Save authorization on this iPhone\./);
  assert.match(bridge, /let providerSafeCode=ReceiptPrivacy\.errorCode\(privateMessage\)[\s\S]*session\.recordFailedResponse\(providerSafeCode\)/);
  assert.match(bridge, /LEGACY_SHORTCUT_SESSION_RESTART_REQUIRED[\s\S]*legacyTraceOnly:true[\s\S]*state\/shortcut-session\.json/);
  assert.match(app, /Provider selection and Apply Oracle recommendation change only the saved provider/);
  assert.match(runtime, /SavedExecutionAuthorization\.requireExact\(authorizationPolicy\)/);
  assert.match(runtime, /RESOLVED_POLICY_EXCEEDS_SAVED_AUTHORIZATION/);
  assert.match(runtime, /PROVIDER_ROUTE_EVIDENCE_CHANGED_RESTART_TASK/);
  assert.match(runtime, /ProviderRuntimeCapabilities\.activity == expectedActivity/);
  assert.match(runtime, /\["awaiting_response", "applying"\]\.contains\(session\.phase\)/);
  assert.match(routing, /@MainActor\s*final class ExecutionContinuationGate[\s\S]*func invalidate\(\)[\s\S]*generation &\+= 1[\s\S]*func requireCurrent/);
  assert.match(routing, /struct ExecutionContinuationValidator[\s\S]*func validatedAwait<Response>\([\s\S]*try requireCurrent\(\)[\s\S]*value = try await response\(\)[\s\S]*catch \{[\s\S]*try afterAwait\(\)[\s\S]*throw error[\s\S]*try afterAwait\(\)[\s\S]*return value/);
  assert.match(routing, /func validator\(for captured: Generation\)[\s\S]*try self\.requireCurrent\(captured\)/);
  const runnerPause=runtime.slice(runtime.indexOf('func pauseForSystemInterruption'),runtime.indexOf('func run(',runtime.indexOf('func pauseForSystemInterruption')));
  assert.ok(runnerPause.indexOf('ExecutionContinuationGate.shared.invalidate()')<runnerPause.indexOf('generation?.cancel()'),'system interruption must retire the continuation before cancelling the provider task');
  const runnerRun=runtime.slice(runtime.indexOf('func run('),runtime.indexOf('func resume(',runtime.indexOf('func run(')));
  assert.match(runnerRun,/executionGeneration providedExecutionGeneration: ExecutionContinuationGate\.Generation\? = nil/);
  assert.equal((runnerRun.match(/ExecutionContinuationGate\.shared\.capture\(\)/g)??[]).length,1,'new runs must resolve exactly one supplied-or-current continuation generation');
  assertInOrder(runnerRun, [
    'let executionGeneration = providedExecutionGeneration ?? ExecutionContinuationGate.shared.capture()',
    'try ExecutionContinuationGate.shared.requireCurrent(executionGeneration)',
    'guard !running else',
  ], 'AgentRunner run must reject a queued stale generation before reading runner state');
  const runnerResume=runtime.slice(runtime.indexOf('func resume('),runtime.indexOf('private func validateCurrentAppleRoute'));
  assert.match(runnerResume,/executionGeneration providedExecutionGeneration: ExecutionContinuationGate\.Generation\? = nil/);
  assert.equal((runnerResume.match(/ExecutionContinuationGate\.shared\.capture\(\)/g)??[]).length,1,'resumed runs must resolve exactly one supplied-or-current continuation generation');
  assertInOrder(runnerResume, [
    'let executionGeneration = providedExecutionGeneration ?? ExecutionContinuationGate.shared.capture()',
    'try ExecutionContinuationGate.shared.requireCurrent(executionGeneration)',
    'guard !running else',
  ], 'AgentRunner resume must reject a queued stale generation before reading runner state');
  const continuationFactory=runtime.slice(runtime.indexOf('private func makeContinuationValidator'),runtime.indexOf('private func execute'));
  assert.ok(continuationFactory.indexOf('ExecutionContinuationGate.shared.requireCurrent(executionGeneration)')<continuationFactory.indexOf('SavedExecutionAuthorization.requireExact'),'lock generation must fail before auth and routing continuation checks');
  const providerAwait=runtime.slice(runtime.indexOf('let text: String'),runtime.indexOf('try throwIfSystemDeferred',runtime.indexOf('let text: String')));
  assert.match(providerAwait,/validatedAwait[\s\S]*pending\.value/);
  const scheduledProvider=runtime.slice(runtime.indexOf('let pending = Task { @MainActor'),runtime.indexOf('generation = pending'));
  assertInOrder(scheduledProvider, [
    'continuationValidator.requireCurrent()',
    'Task.checkCancellation()',
    'provider.step(',
  ], 'scheduled provider work must revalidate its generation and cancellation before entering the model');
  const heartbeatMonitor=runtime.slice(runtime.indexOf('let monitor = Task'),runtime.indexOf('let text: String'));
  assert.ok(heartbeatMonitor.indexOf('Task.sleep')<heartbeatMonitor.indexOf('continuationValidator.afterAwait()')&&heartbeatMonitor.indexOf('continuationValidator.afterAwait()')<heartbeatMonitor.indexOf('onHeartbeat('),'runner heartbeat callbacks must revalidate after their timer suspension');
  const runnerFailureStart=runtime.indexOf('            } catch {',runtime.indexOf('for step in'));
  const runnerFailure=runtime.slice(runnerFailureStart,runtime.indexOf('        let environment',runnerFailureStart));
  assert.ok(runnerFailure.indexOf('continuationValidator.requireCurrent()')<runnerFailure.indexOf('failures += 1'),'retired runner generations must escape before provider-failure accounting');
  const runnerFinalization=runtime.slice(runtime.indexOf('        let environment',runnerFailureStart),runtime.indexOf('\n    }',runtime.indexOf('        let environment',runnerFailureStart)));
  assert.ok((runnerFinalization.match(/continuationValidator\.beforePersistence\(\)/g)??[]).length>=2,'runner receipt and terminal checkpoint writes must both be fenced');
  assert.match(runnerFinalization,/validatedAwait[\s\S]*UNUserNotificationCenter\.current\(\)\.add[\s\S]*catch \{[\s\S]*continuationValidator\.requireCurrent\(\)[\s\S]*continuationValidator\.requireCurrent\(\)[\s\S]*return receipt/);
  const appleProbe=qualification.slice(qualification.indexOf('static func performAppleQualificationProbe'),qualification.indexOf('private static func runAppleSuite'));
  assert.doesNotMatch(appleProbe,/try\?\s+persistCompletion/,'required Apple qualification completion cannot be best-effort');
  assertInOrder(appleProbe, [
    'response = try await continuationValidator.validatedAwait',
    'try persistCompletion("{}", !cancelled)',
    'try persistCompletion(response, true)',
  ], 'Apple qualification must separate provider-response handling from durable completion');
  const appleSuite=qualification.slice(qualification.indexOf('private static func runAppleSuite'),qualification.indexOf('private static func challengeToken'));
  assert.match(appleSuite,/performAppleQualificationProbe\([\s\S]*persistCompletion:[\s\S]*_ = try complete\(/);
  assert.doesNotMatch(appleSuite,/try\?\s*complete\(/,'Apple qualification swallowed a required ledger write');
  assert.match(app,/private func retireActiveAgentRunForLock\(\)[\s\S]*AgentRunner\.shared\.pauseForSystemInterruption\(reason:"LOCAL_SANDBOX_LOCKED"\)/);
  const profileLock=app.slice(app.indexOf('private func lockAndDisconnectLocalProfile'),app.indexOf('private func invalidateAuthLifecycle'));
  assert.ok(profileLock.indexOf('retireActiveAgentRunForLock()')<profileLock.indexOf('invalidateAuthLifecycle()'),'profile removal must retire active model execution before disconnect cleanup');
  assert.match(runtime, /beforeSideEffect: continuationValidator\.beforeDispatcherSideEffect/);
  assert.match(runtime, /try beforeSideEffect\(\)[\s\S]*switch try executor\.prepare/);
  assert.match(runtime, /try beforeSideEffect\(\)[\s\S]*try executor\.complete\(prepared, result: result\)/);
  assert.match(bridge, /SavedExecutionAuthorization\.requireExact\(savedPolicy\)/);
  assert.match(bridge, /beforeSideEffect:\{[\s\S]*continuationValidator\.beforeDispatcherSideEffect\(\)[\s\S]*SavedExecutionAuthorization\.requireExact\(session\.authorizationPolicy\)[\s\S]*validateActiveExternalRoute\(session\)/);
  const shortcutBegin=bridge.slice(bridge.indexOf('func begin('),bridge.indexOf('func appIntentOutput'));
  assert.match(shortcutBegin,/executionGeneration providedExecutionGeneration:ExecutionContinuationGate\.Generation\? = nil/);
  assert.match(shortcutBegin,/providedExecutionGeneration \?\? ExecutionContinuationGate\.shared\.capture\(\)/);
  assert.match(shortcutBegin,/continuationValidator\.beforePersistence\(\)[\s\S]*store\.save\(session/);
  const shortcutOutput=bridge.slice(bridge.indexOf('func appIntentOutput'),bridge.indexOf('func prompt',bridge.indexOf('func appIntentOutput')));
  assert.match(shortcutOutput,/executionGeneration:ExecutionContinuationGate\.Generation/);
  assert.ok((shortcutOutput.match(/continuationValidator\.requireCurrent\(\)/g)??[]).length>=2,'App Intent handoff output must validate before protected reads and final return');
  const shortcutAccept=bridge.slice(bridge.indexOf('func accept(_ response:String,'),bridge.indexOf('func stop(',bridge.indexOf('func accept(_ response:String,')));
  assert.match(shortcutAccept,/executionGeneration providedExecutionGeneration:ExecutionContinuationGate\.Generation\? = nil/);
  assert.equal((shortcutAccept.match(/ExecutionContinuationGate\.shared\.capture\(\)/g)??[]).length,1,'Shortcut accept must capture exactly one lock generation');
  assert.ok(shortcutAccept.indexOf('continuationValidator.requireCurrent()')<shortcutAccept.indexOf('AgentAction.requireBoundedResponse'),'Shortcut accept must validate its lock generation before processing a response');
  assert.match(shortcutAccept,/validatedAwait \{[\s\S]*Dispatcher\.shared\.execute/);
  const shortcutCatch=shortcutAccept.slice(shortcutAccept.lastIndexOf('} catch {'));
  assert.ok(shortcutCatch.indexOf('continuationValidator.requireCurrent()')<shortcutCatch.indexOf('ReceiptPrivacy.errorCode'),'lock retirement must escape before provider-failure accounting');
  const shortcutStop=bridge.slice(bridge.indexOf('func stop('),bridge.indexOf('private func finish',bridge.indexOf('func stop(')));
  assert.match(shortcutStop,/executionGeneration providedExecutionGeneration:ExecutionContinuationGate\.Generation\? = nil/);
  assert.equal((shortcutStop.match(/ExecutionContinuationGate\.shared\.capture\(\)/g)??[]).length,1,'Shortcut stop must resolve exactly one supplied-or-current lock generation');
  assertInOrder(shortcutStop, [
    'let executionGeneration = providedExecutionGeneration ?? ExecutionContinuationGate.shared.capture()',
    'let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)',
    'try continuationValidator.requireCurrent()',
    'guard !applying else',
  ], 'Shortcut stop must reject a queued stale generation before reading or mutating handoff state');
  assert.match(shortcutStop,/continuationValidator\.beforePersistence\(\)[\s\S]*store\.saveReceipt[\s\S]*continuationValidator\.beforePersistence\(\)[\s\S]*store\.delete/);
  const shortcutFinish=bridge.slice(bridge.indexOf('private func finish'),bridge.indexOf('\n}',bridge.indexOf('private func finish')));
  assert.match(shortcutFinish,/continuationValidator:ExecutionContinuationValidator/);
  assert.match(shortcutFinish,/continuationValidator\.beforePersistence\(\)[\s\S]*store\.save\(session[\s\S]*continuationValidator\.beforePersistence\(\)[\s\S]*store\.saveReceipt/);
  assert.match(shortcutFinish,/validatedAwait \{[\s\S]*UNUserNotificationCenter\.current\(\)\.add[\s\S]*continuationValidator\.requireCurrent\(\)/);
  assert.match(bridge, /activity == expectedActivity/);
  assert.match(store, /RunCheckpointIdentity\.requireUnchanged\(expected: expected, current: current\)/);
  assert.match(models, /enum RunCheckpointIdentity[\s\S]*encoder\.outputFormatting = \[\.sortedKeys\][\s\S]*BACKGROUND_CHECKPOINT_CHANGED/);
  assert.match(intents, /struct ApplyValidatedActionIntent: AppIntent/);
  assert.doesNotMatch(intents, /ApplyReviewedActionIntent/);
  assert.match(models, /let routingEvidence: ProviderRoutingEvidence\?/);
  assert.match(contracts, /providerRoutingEvidenceSchema=z\.object/);
  assert.match(dashboard, /Deterministic route/);
  assert.match(dashboard, /deviceProfileSHA256\.slice\(0,12\)/);
});

test('Apple qualification records App Intent transport only from an App Intent execution', () => {
  const suiteStart=qualification.indexOf('private static func runAppleSuite');
  const suiteEnd=qualification.indexOf('private static func challengeToken',suiteStart);
  assert.ok(suiteStart>=0 && suiteEnd>suiteStart,'Apple qualification suite source is missing');
  const appleSuite=qualification.slice(suiteStart,suiteEnd);
  assert.equal((appleSuite.match(/appIntentTransportObserved:\s*true/g)??[]).length,1);
  assert.match(qualification,/static func runAppleSuiteFromAppIntent[\s\S]*executionGeneration: ExecutionContinuationGate\.Generation[\s\S]*validator\(for: executionGeneration\)[\s\S]*validatedAwait[\s\S]*runAppleSuite\([\s\S]*continuationValidator: continuationValidator/);
  assert.match(qualification,/appleTransportEpoch = "app-intent-suite-v1"/);
  assert.match(qualification,/retainingCurrentAppleTransportEvidence/);
  assert.match(qualification,/static func reset\(\) throws[\s\S]*reset\(using: ProviderQualificationResetOperations/);
  assert.match(qualification,/static func reset\(using operations: ProviderQualificationResetOperations\) throws[\s\S]*guard !operations\.qualificationIsActive\(\)[\s\S]*PROVIDER_QUALIFICATION_RESET_REQUIRES_IDLE_STATE/);
  assert.match(app,/FINISH_PROVIDER_QUALIFICATION_BEFORE_DELETING_PROFILE/);
  assert.match(app,/try ProviderQualificationStore\.reset\(\)/);
  assert.match(intents,/struct QualifyAppleProviderIntent: AppIntent/);
  assert.match(intents,/runAppleSuiteFromAppIntent\([\s\S]*policy:\s*policy,[\s\S]*executionGeneration:\s*executionGeneration/);
  assert.match(intents,/AppShortcut\(intent:QualifyAppleProviderIntent\(\)/);
  assert.match(app,/Button\("Run five Apple checks through App Intent",intent:QualifyAppleProviderIntent\(\)\)/);
  assert.doesNotMatch(app,/model\.qualifyApple\(\)/);
  const qualificationProbeStart=qualification.indexOf('static func performAppleQualificationProbe');
  const qualificationProbe=qualification.slice(qualificationProbeStart,suiteStart);
  assert.match(qualificationProbe,/try Task\.checkCancellation\(\)/);
  assert.match(qualificationProbe,/error is CancellationError \|\| Task\.isCancelled[\s\S]*persistCompletion\("\{\}", !cancelled\)[\s\S]*persistCompletion\("\{\}", false\)[\s\S]*throw CancellationError\(\)/);
  const qualificationCatch=qualificationProbe.slice(qualificationProbe.indexOf('} catch {'));
  assert.ok(qualificationCatch.indexOf('continuationValidator.requireCurrent()')<qualificationCatch.indexOf('error is CancellationError'),'retired qualification generations must escape before cancellation or failure completion');
  assert.match(qualificationProbe,/continuationValidator\.validatedAwait[\s\S]*providerResponse\(\)/);
  assert.match(appleSuite,/providerResponse:[\s\S]*AppleProvider\(\)\.qualificationResponse/);
  assert.match(appleSuite,/persistCompletion:[\s\S]*appIntentTransportObserved: appIntentTransportObserved/);
  assert.match(qualificationProbe,/continuationValidator\.beforePersistence\(\)[\s\S]*persistCompletion\("\{\}", false\)[\s\S]*continuationValidator\.beforePersistence\(\)[\s\S]*persistCompletion\(response, true\)/);
  assert.match(routing,/timingIsComparable = \(lhs == \.apple\) == \(rhs == \.apple\)/);
});

test('App Intents keep iOS 26 foreground auth and isolate iOS 27 extended execution', () => {
  assert.doesNotMatch(intents, /openAppWhenRun/);
  const authenticationHelper = intents.slice(intents.indexOf('private func authenticateSensitiveIntent'), intents.indexOf('private func executeProviderTask'));
  assertInOrder(authenticationHelper, [
    'let executionGeneration=ExecutionContinuationGate.shared.capture()',
    'let continuationValidator=ExecutionContinuationGate.shared.validator(for:executionGeneration)',
    'continuationValidator.validatedAwait',
    'LocalAccess.authenticate(executionGeneration:executionGeneration)',
    'try localAccessLease.requireCurrent()',
    'return executionGeneration',
  ], 'sensitive App Intents must retain one generation through local authentication and lease validation');
  assert.equal((intents.match(/LocalAccess\.authenticate\(executionGeneration:executionGeneration\)/g)??[]).length,1,'only the pre-auth generation helper may invoke LocalAccess authentication with its captured generation');
  assert.equal((intents.match(/try await authenticateSensitiveIntent\(\)/g)??[]).length,10,'every sensitive App Intent must use the pre-auth generation helper');
  const locallyAuthenticatedIntents = [
    'RunSandboxIntent',
    'RunLongAppleTaskIntent',
    'PlanOneStepIntent',
    'BeginProviderQualificationIntent',
    'RecordProviderQualificationIntent',
    'QualifyAppleProviderIntent',
    'ConfigureOracleRoutingIntent',
    'BeginOracleTaskIntent',
    'ApplyValidatedActionIntent',
    'PrepareWorkspaceIntent',
  ];
  for (const name of locallyAuthenticatedIntents) {
    const start = intents.indexOf(`struct ${name}:`);
    const end = intents.indexOf('\nstruct ', start + 1);
    const block = intents.slice(start, end < 0 ? undefined : end);
    assert.ok(start >= 0, `${name} is missing`);
    assert.match(block, /static let authenticationPolicy\s*:\s*IntentAuthenticationPolicy\s*=\s*\.requiresLocalDeviceAuthentication/);
  }
  assert.equal(intents.match(/=\s*\.requiresLocalDeviceAuthentication/g)?.length, 10);
  assert.equal(intents.match(/=\s*\.alwaysAllowed/g)?.length, 1);
  assert.match(intents, /struct OpenSandboxIntent:[\s\S]*?authenticationPolicy\s*:\s*IntentAuthenticationPolicy\s*=\s*\.alwaysAllowed[\s\S]*?func perform\(\) async throws -> some IntentResult \{ \.result\(\) \}/);
  const providerTask=intents.slice(intents.indexOf('private func executeProviderTask'),intents.indexOf('struct RunSandboxIntent'));
  assert.match(providerTask,/executionGeneration: ExecutionContinuationGate\.Generation/);
  assert.match(providerTask,/AgentRunner\.shared\.run\([\s\S]*executionGeneration:executionGeneration/);
  assert.match(providerTask,/ShortcutCoordinator\.shared\.begin\([\s\S]*executionGeneration:executionGeneration/);
  assert.match(providerTask,/appIntentOutput\(payload:prompt,executionGeneration:executionGeneration\)/);
  const planIntent=intents.slice(intents.indexOf('struct PlanOneStepIntent'),intents.indexOf('struct OpenSandboxIntent'));
  assert.match(planIntent,/continuationValidator\.validatedAwait[\s\S]*AppleProvider\(\)\.step/);
  assert.ok(planIntent.indexOf('continuationValidator.requireCurrent()')<planIntent.indexOf('return .result(value:text)'),'Plan One Step must revalidate before returning model output');
  const qualifyIntent=intents.slice(intents.indexOf('struct QualifyAppleProviderIntent'),intents.indexOf('struct ConfigureOracleRoutingIntent'));
  assert.match(qualifyIntent,/runAppleSuiteFromAppIntent\([\s\S]*executionGeneration: executionGeneration/);
  const applyIntent=intents.slice(intents.indexOf('struct ApplyValidatedActionIntent'),intents.indexOf('struct PrepareWorkspaceIntent'));
  assert.match(applyIntent,/accept\(response,executionGeneration:executionGeneration\)/);
  assert.match(applyIntent,/appIntentOutput\(payload:output,executionGeneration:executionGeneration\)/);
  assert.ok((intents.match(/supportedModes\s*:\s*IntentModes\s*=\s*\[\.foreground\(\.immediate\)\]/g)?.length??0)>=7);
  assert.match(intents, /@available\(iOS 27\.0, \*\)\s*struct RunLongAppleTaskIntent: LongRunningIntent, CancellableIntent/);
  assert.match(intents, /performBackgroundTask\s*\{\s*@Sendable in/);
  assert.match(intents, /RunLongAppleTaskIntent[\s\S]*performBackgroundTask\s*\{[\s\S]*progress\.completedUnitCount[\s\S]*onCancel:/);
  assert.match(intents, /onCancel:\s*\{ reason in\s*cancellationState\.record\(reason\)/);
  assert.match(intents, /reason == \.userCancelled[\s\S]*\.userCancelled[\s\S]*reason == \.timeout[\s\S]*APP_INTENT_LONG_RUN_TIMEOUT/);
  assert.match(intents, /RunLongAppleTaskIntent[\s\S]*providerSelection:\.apple/);
  assert.match(intents, /RunLongAppleTaskIntent[\s\S]*systemManaged:true[\s\S]*cancellationDisposition:\{cancellationState\.current\(\)\}/);
  assert.match(intents, /onHeartbeat:[\s\S]*progress\.localizedAdditionalDescription=message/);
  assert.match(intents, /if #available\(iOS 27\.0, \*\)\s*\{\s*AppShortcut\(intent:RunLongAppleTaskIntent\(\)/);
  assert.match(intents, /AgentRunner\.shared\.run\([\s\S]*systemManaged:systemManaged[\s\S]*onProgress:onProgress[\s\S]*onHeartbeat:onHeartbeat/);
  assert.match(runtime, /systemManaged: Bool = false/);
  assert.match(runtime, /case \.systemDeferred\(let reason\) = disposition/);
  assert.match(runtime, /if disposition == \.userCancelled \{ return \}/);
  assert.match(runtime, /cancellationDisposition\(\) == \.userCancelled/);
  assert.match(runtime, /if systemManaged && Task\.isCancelled \{ throw AgentRunInterruption\.systemDeferred/);
  assert.match(runtime, /elapsedSeconds\.isMultiple\(of: 5\)[\s\S]*onHeartbeat\("Apple Intelligence is still working/);
  assert.match(releaseGuide, /Xcode 27 and a signed iOS 27 device/);
  assert.match(releaseGuide, /LongRunningIntent\.performBackgroundTask/);
  assert.match(releaseGuide, /iOS 26[\s\S]*Begin Oracle Task[\s\S]*Run Bounded Task[\s\S]*Apply Validated Action/);
  assert.match(releaseGuide, /remains `QUALIFYING`/);
});

test('personal Shortcut instructions consume only schema v1 payload and retain terminal receipts', () => {
  assert.match(intents, /ShortcutCoordinator\.shared\.accept\(response,executionGeneration:executionGeneration\)/);
  assert.match(intents, /Returns a JSON envelope with phase and payload\./);
  for (const source of [readme, installGuide, architecture, guideGenerator]) {
    assert.match(source, /Get Dictionary from Input/);
    assert.match(source, /payload/);
    assert.match(source, /awaiting_response/);
  }
  assert.match(readme, /provider action's raw JSON text to Apply/);
  assert.match(readme, /`phase`, output `kind`, `payload`/);
  assert.match(installGuide, /terminal receipt from `payload`/);
  assert.match(architecture, /returned raw JSON proposal to Apply Validated Action/);
  assert.match(app, /import AppIntents/);
  assert.match(app, /ShortcutsLink\(\)/);
  assert.match(app, /Get Dictionary from Input/);
  assert.match(app, /raw JSON output to Apply Validated Action/);
  assert.match(app, /Repeat with payload only while phase equals awaiting_response/);
  assert.match(app, /terminal receipt from payload/);
  assert.doesNotMatch(guideGenerator, /read prompt/);
  assert.doesNotMatch(guideGenerator, /read receipt/);
});

test('provider handoffs are typed, hash-only, and visible as a dashboard round trip', () => {
  assert.match(routing, /private struct ProviderOutboundHandoff: Encodable, Equatable/);
  assert.match(routing, /private struct ProviderInboundReturn: Encodable, Equatable/);
  assert.match(routing, /let promptSHA256: String/);
  assert.match(routing, /let responseSHA256: String/);
  assert.ok((routing.match(/let schemaVersion = 2/g)?.length??0)>=2);
  assert.ok((routing.match(/let adapterSHA256: String/g)?.length??0)>=2);
  assert.match(routing, /adapterSHA256: NativeDigest\.sha256\(adapterName\)/);
  assert.doesNotMatch(routing, /Provider(?:OutboundHandoff|InboundReturn)[\s\S]{0,500}let (?:prompt|response|content|credential|token): String/);
  const boundedResponse = bridge.indexOf('try AgentAction.requireBoundedResponse(response)');
  const distinct = bridge.indexOf('guard let actionIndex=try session.beginDistinctResponse(response)');
  const inbound = bridge.indexOf('ProviderHandoffTrace.inbound', distinct);
  const nextPrompt = bridge.indexOf('let nextPrompt=prompt(session)', inbound);
  const outbound = bridge.indexOf('ProviderHandoffTrace.outbound', nextPrompt);
  assert.ok(boundedResponse>=0&&distinct>boundedResponse&&inbound>distinct&&nextPrompt>inbound&&outbound>nextPrompt, 'handoff timeline does not bound input before distinct response accounting');
  assert.match(models,/static let maximumResponseBytes = 16_000/);
  assert.match(models,/PROVIDER_RESPONSE_TOO_LARGE/);
  assert.match(bridge, /authorizationPolicy:savedPolicy/);
  assert.match(bridge, /!session\.authorizationMatches\(current\)/);
  assert.match(bridge, /Authorization is missing\. Save it again before starting a new task\./);
  assert.doesNotMatch(bridge, /current\s*!=\s*session\.policy/);
  assert.match(contracts, /providerHandoffEventSchema=z\.discriminatedUnion\('direction'/);
  assert.match(handoffParser, /event\.provider!==identity\.provider\|\|event\.selection!==identity\.selection\|\|event\.origin!==identity\.origin/);
  assert.match(handoffParser, /event\.adapterSHA256!==identity\.adapterSHA256/);
  assert.match(handoffParser, /event\.direction!==['"]outbound['"]\|\|event\.actionIndex!==nextActionIndex/);
  assert.match(handoffParser, /event\.direction!==['"]inbound['"]\|\|event\.actionIndex!==pendingOutbound\.actionIndex/);
  assert.match(handoffParser, /entry\.status!==['"]ok['"]/);
  assert.match(handoffParser, /completeRoundTrips!==receipt\.steps/);
  assert.match(handoffParser, /receipt\.status===['"]completed['"]\|\|receipt\.status===['"]verified['"]/);
  assert.match(models, /static func receiptSuccess\(_ result: ToolResult\)/);
  assert.match(models, /func receiptSafe\(\) -> Self/);
  assert.doesNotMatch(runtime, /TraceEntry\(tool: call\.tool\.rawValue, status: "ok", detail: String\(value\.result/);
  assert.doesNotMatch(bridge, /TraceEntry\(tool:call\.tool\.rawValue,status:"ok",detail:String\(result\.result/);
  assert.match(dashboard, /Provider handoff telemetry rejected/);
  assert.match(dashboard, /Provider handoff timeline/);
  assert.match(dashboard, /Cancelled before the provider returned this action/);
  assert.match(dashboard, /Workspace → \$\{providerLabel\(event\.provider\)\}/);
  assert.match(dashboard, /\$\{providerLabel\(event\.provider\)\} → workspace/);
  assert.match(dashboard, /providerSelectionLabel\(event\.selection\)/);
  assert.match(dashboard, /prompt, response, and adapter fingerprints—not provider output, custom adapter names, credentials, or app tokens/);
  assert.match(dashboard, /adapterSHA256\.slice\(0,12\)/);
  assert.match(dashboard, /providerLabel\(r\.provider\).*receiptOriginLabel\(r\)/);
});

test('explicit Apple App Intent preserves saved authorization and invocation origin across resume', () => {
  assert.match(intents, /authorizationPolicy:policy,[\s\S]*taskOrigin:\.appIntent/);
  assert.match(models, /let authorizationPolicy: ResourcePolicy\?/);
  assert.match(models, /let taskOrigin: ProviderTaskOrigin\?/);
  assert.match(models, /authorizationPolicy = version >= 3/);
  assert.match(runtime, /policy: policy, authorizationPolicy: authorizationPolicy,[\s\S]*taskOrigin: taskOrigin/);
  assert.match(runtime, /SavedExecutionAuthorization\.requireExact\(authorizationPolicy\)/);
  assert.match(models, /enum SavedExecutionAuthorization[\s\S]*JSONDecoder\(\)\.decode\(ResourcePolicy\.self, from: data\)\.validated\(\)[\s\S]*guard try load\(\) == expected/);
  assert.match(background, /context\.currentPolicy == approvedAuthorization/);
  assert.match(runtime, /environment: environment, taskOrigin: taskOrigin/);
  assert.match(bridge, /environment:environment,taskOrigin:session\.taskOrigin/);
  assert.match(dashboard, /if\(receipt\.taskOrigin\)return handoffOriginLabel\(receipt\.taskOrigin\)/);
});

test('provider and device UI remains evidence-bound instead of inferring phone or app state', () => {
  assert.match(connections, /Availability unknown · no device report/);
  assert.match(connections, /cannot inspect those apps’ account state/);
  assert.match(connections, /Shortcut test recorded/);
  assert.match(connections, /Shortcut test not recorded/);
  assert.match(app, /inboxCard\("Provider routes",count:AppProvider\.allCases\.count/);
  assert.match(app, /records only that a returned response passed local validation/);
  assert.doesNotMatch(app, /records only a locally validated returned response/);
  assert.match(dashboard, /<span>Provider routes <b>\{providers\.length\}<\/b><\/span>/);
  assert.doesNotMatch(app, /All Agents/);
  assert.doesNotMatch(dashboard, /All Agents/);
  assert.match(routing, /Choose another provider only after Local Sandbox shows its Shortcut route is configured and currently qualified/);
  assert.match(bridge, /Choose another provider only after Local Sandbox shows its Shortcut route is configured and currently qualified/);
  assert.doesNotMatch(routing, /Locally and app Shortcuts remain available/);
  assert.doesNotMatch(bridge, /Locally and app Shortcuts remain available/);
  assert.match(dashboard, /Record App Intent return \{receipt\.routingEvidence\.automatedReturnQualified\?'observed':'not observed'\}/);
  assert.match(dashboard, /They do not verify a provider login, active model, Shortcut contents, unattended return, or which provider produced a response/);
  assert.doesNotMatch(dashboard, /automated return \{receipt\.routingEvidence/);
  assert.match(contracts, /observed Record App Intent return coverage for every qualifying probe/);
  assert.doesNotMatch(connections, /iPhone 14|iOS 27|Not available on this iPhone/);
  assert.doesNotMatch(dashboard, /iPhone 14 Pro · iOS 27\.0|Apple Intelligence is unavailable on your iPhone 14 Pro/);
});

test('corrupt execution state stays visible and blocked until an exact raw-byte review transaction completes', () => {
  assert.match(models, /struct CorruptExecutionState: Identifiable, Equatable, Sendable/);
  assert.match(models, /enum CheckpointReviewDisposition[\s\S]*case acknowledge[\s\S]*case alreadyAcknowledged/);
  assert.match(models, /RunCheckpointIdentity\.requireUnchanged\(expected: expected, current: current\)/);
  assert.match(models, /state\/active\.json/);
  assert.match(models, /state\/shortcut-session\.json/);
  assert.match(store, /enum ExecutionStateInspector[\s\S]*kind: \.nativeCheckpoint[\s\S]*kind: \.shortcutSession/);
  assert.match(store, /func readData\(_ path: SandboxPath, maximumBytes:/);
  assert.match(store, /func preserveAndDiscardCorruptExecutionState/);
  const quarantine = store.slice(store.indexOf('func preserveAndDiscardCorruptExecutionState'), store.indexOf('func acknowledgeCheckpoint'));
  assert.ok(quarantine.indexOf('writeData') < quarantine.indexOf('delete('), 'corrupt state was deleted before its raw bytes were preserved');
  assert.match(quarantine, /expectedSHA256: record\.sha256/);
  assert.match(app, /@Published var corruptExecutionStates: \[CorruptExecutionState\]/);
  assert.match(app, /ExecutionStateInspector\.inspect/);
  assert.match(app, /Export original bytes/);
  assert.match(app, /Preserve and discard corrupt state/);
  assert.match(app, /fileExporter\(/);
  assert.match(app, /\.alert\("Preserve corrupt state before discarding\?"/);
  assert.doesNotMatch(app, /try\? SandboxStore\.shared\.load\(RunCheckpoint\.self,path:"state\/active\.json"\)/);
});

test('checkpoint acknowledgement reloads, compares, archives exact bytes, and writes with a current-byte guard', () => {
  const acknowledge = store.slice(store.indexOf('func acknowledgeCheckpoint'), store.indexOf('private func preserveExactData'));
  assert.match(acknowledge, /readData\(source/);
  assert.match(acknowledge, /CheckpointReviewCore\.disposition\(expected: expected, current: current\)/);
  assert.match(acknowledge, /preserveExactData\(currentData, at: reviewPath/);
  assert.match(store, /private func preserveExactData[\s\S]*writeData\(path, data: data/);
  assert.match(acknowledge, /expectedSHA256: NativeDigest\.sha256\(currentData\)/);
  assert.match(app, /guard !running,!AgentRunner\.shared\.running/);
  assert.match(app, /SandboxStore\.shared\.acknowledgeCheckpoint\(expected:checkpoint\)/);
  assert.doesNotMatch(app, /try SandboxStore\.shared\.save\(checkpoint,path:"output\/reviewed-/);
});

test('Shortcut package UI separates verified bytes, OS open acceptance, and installation', () => {
  assert.match(shortcutPackageCore, /enum ShortcutPackageOpenOutcome/);
  assert.match(shortcutPackageCore, /case verified[\s\S]*case accepted[\s\S]*case rejected/);
  assert.match(shortcutPackages, /openURL\(verified\.fileURL\) \{ accepted in/);
  assert.match(shortcutPackages, /accepted \? \.accepted[\s\S]*: \.rejected/);
  assert.match(shortcutPackages, /iOS accepted the request/);
  assert.match(shortcutPackages, /Installation remains unconfirmed/);
  assert.doesNotMatch(shortcutPackages, /last package opened from a locally verified/);
  assert.doesNotMatch(shortcutPackages, /installed successfully|Shortcut was installed/i);
});

test('native self-host Shortcut catalogs require exact-origin Keychain consent', () => {
  assert.match(shortcutPackageCore, /candidateDistributionOrigin/);
  assert.match(shortcutPackageCore, /validated\(distributionOrigin:/);
  assert.match(shortcutPackageCore, /url\.user == nil[\s\S]*url\.password == nil[\s\S]*url\.query == nil[\s\S]*url\.fragment == nil/);
  assert.match(shortcutPackages, /shortcutDistributionOrigin\.v1/);
  assert.match(shortcutPackages, /Keychain\.set\(origin, for: storageKey\)/);
  assert.match(shortcutPackages, /Keychain\.deleteChecked\(storageKey\)/);
  assert.match(shortcutPackages, /Trust exact self-host origin/);
  assert.match(shortcutPackages, /Catalog SHA-256/);
  assert.match(app, /try ShortcutDistributionApprovalStore\.clear\(\)/);
});
