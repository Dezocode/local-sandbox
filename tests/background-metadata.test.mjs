import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const taskIdentifier = 'com.dezocode.LocalSandbox.processing';
test('iOS background processing metadata matches the registered task', async () => {
  const [info, entitlements, source, appIntents, providers, project, generator] = await Promise.all([
    readFile('ios/LocalSandbox/Info.plist', 'utf8'),
    readFile('ios/LocalSandbox/LocalSandbox.entitlements', 'utf8'),
    readFile('ios/LocalSandbox/BackgroundExecution.swift', 'utf8'),
    readFile('ios/LocalSandbox/AppIntents.swift', 'utf8'),
    readFile('ios/LocalSandbox/Providers.swift', 'utf8'),
    readFile('ios/LocalSandbox.xcodeproj/project.pbxproj', 'utf8'),
    readFile('scripts/generate-xcode-project.py', 'utf8'),
  ]);

  assert.match(info, /<key>BGTaskSchedulerPermittedIdentifiers<\/key>[\s\S]*?<string>com\.dezocode\.LocalSandbox\.processing<\/string>/);
  assert.match(info, /<key>UIBackgroundModes<\/key>[\s\S]*?<string>processing<\/string>/);
  assert.doesNotMatch(info, /<string>(audio|location|voip)<\/string>/);
  assert.match(source, new RegExp(`taskIdentifier = "${taskIdentifier.replaceAll('.', '\\.')}"`));
  assert.match(source, /expirationHandler\s*=/);
  assert.match(source, /setTaskCompleted\(success:/);
  const expirationBody = source.slice(
    source.indexOf('task.expirationHandler = {'),
    source.indexOf('activeWork = Task { @MainActor in'),
  );
  const expirationOrder = [
    'expiringWork?.cancel()',
    'pauseForSystemInterruption',
    'state: .expired',
    'scheduleSafeRetry',
    'await expiringWork?.value',
    'task.setTaskCompleted(success: false)',
  ].map((token) => expirationBody.indexOf(token));
  assert.ok(expirationOrder.every((offset) => offset >= 0), 'expiration cleanup is missing a required operation or runner join');
  assert.deepEqual(expirationOrder, [...expirationOrder].sort((left, right) => left - right), 'iOS task completion must follow cancellation, checkpoint/status recording, retry scheduling, and runner termination');
  assert.match(expirationBody, /guard completion\.claim\(\) else \{ return \}/);
  assert.equal((expirationBody.match(/task\.setTaskCompleted\(success: false\)/g)??[]).length, 1, 'expiration must report completion exactly once');
  assert.match(source, /private nonisolated static func submitTaskRequestOffMain\(/);
  assert.match(source, /DispatchQueue\.global\(qos: \.utility\)\.async/);
  assert.match(source, /submitTaskRequest\(request\)/);
  assert.doesNotMatch(source, /@MainActor[\s\S]{0,600}submitTaskRequest\(/);
  assert.match(source, /#available\(iOS 27\.0, \*\)/);
  assert.match(source, /queuedSubmission = PendingSubmission\(/);
  assert.match(source, /cancel\(taskRequestWithIdentifier: Self\.taskIdentifier\)/);
  assert.match(source, /submission\.generation != lifecycleGeneration/);
  assert.match(source, /if #available\(iOS 27\.0, \*\)[\s\S]*?submitTaskRequestOffMain[\s\S]*?else \{[\s\S]*?BGTaskScheduler\.shared\.submit\(submission\.request\)/);
  assert.doesNotMatch(entitlements, /com\.apple\.developer\.background-tasks\.continued-processing/);
  assert.match(appIntents, /@available\(iOS 27\.0, \*\)[\s\S]*?performBackgroundTask/);
  assert.match(providers, /LanguageModelSession\(/);
  assert.match(project, /LocalSandbox\/BackgroundExecution\.swift/);
  assert.match(project, /com\.apple\.BackgroundModes = \{enabled = 1;\}/);
  assert.match(project, /CODE_SIGN_ENTITLEMENTS = "LocalSandbox\/LocalSandbox\.entitlements"/);
  assert.match(generator, new RegExp(taskIdentifier.replaceAll('.', '\\.')));
  assert.doesNotMatch(generator, /com\.apple\.developer\.background-tasks\.continued-processing/);
});
