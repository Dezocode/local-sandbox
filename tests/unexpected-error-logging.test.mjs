import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { runnerImport } from 'vite';

const projectRoot = fileURLToPath(new URL('..', import.meta.url)).replace(/\/$/, '');
const entryID = `${projectRoot}/tests/.logging-regression-entry.ts`;
const hostID = `${projectRoot}/tests/.logging-host.ts`;
const envID = `${projectRoot}/tests/.logging-env.ts`;
const fetchID = `${projectRoot}/tests/.logging-fetch.ts`;
const runtime = (await runnerImport(entryID, {
  root: projectRoot,
  configFile: false,
  cacheDir: fileURLToPath(new URL('../.logging-test-cache', import.meta.url)),
  plugins: [{
    name: 'isolated-logging-test-bindings',
    enforce: 'pre',
    resolveId(id) {
      if ([entryID, hostID, envID, fetchID].includes(id)) return id;
    },
    transform(code, id) {
      if (![`${projectRoot}/lib/server.ts`, `${projectRoot}/lib/apple-auth-http.ts`, `${projectRoot}/worker.ts`].includes(id)) return;
      for (const [specifier, target] of [['@/app/chatgpt-auth', hostID], ['cloudflare:workers', envID], ['vinext/server/fetch-handler', fetchID]]) {
        code = code.replaceAll(`from '${specifier}'`, `from ${JSON.stringify(target)}`);
      }
      return {code, map: null};
    },
    load(id) {
      if (id === entryID) return [
        `export {boundary, HttpError} from ${JSON.stringify(`${projectRoot}/lib/server.ts`)};`,
        `export {appleAuthErrorResponse} from ${JSON.stringify(`${projectRoot}/lib/apple-auth-http.ts`)};`,
        `export {AppleAuthError} from ${JSON.stringify(`${projectRoot}/lib/apple-auth.ts`)};`,
        `export {default as worker} from ${JSON.stringify(`${projectRoot}/worker.ts`)};`,
        'export {z} from "zod";',
      ].join('\n');
      if (id === hostID) return 'export async function getChatGPTUser() { throw new Error("Host identity must not be requested by logging tests"); }';
      if (id === envID) return 'export const env = {};';
      if (id === fetchID) return 'export default {fetch() { throw new Error("Network handler must not be requested by logging tests"); }};';
    },
  }],
})).module;

const mockToken = 'mock-token-DO-NOT-LOG-7bb964';
const mockContent = 'mock-private-file-content-DO-NOT-LOG-abc123';
const syntheticText = `${mockToken} ${mockContent}`;
const scheduledTime = 1_800_000_000_000;

function unexpectedFailures() {
  const error = new Error(syntheticText, {cause: new Error(syntheticText)});
  error.name = syntheticText;
  error.stack = syntheticText;
  return [error, syntheticText, {message: syntheticText, stack: syntheticText}, null];
}

function captureLogs(t) {
  const error = [];
  const info = [];
  t.mock.method(console, 'error', (...args) => error.push(args));
  t.mock.method(console, 'info', (...args) => info.push(args));
  return {error, info};
}

function assertNoSyntheticText(logs) {
  const serialized = JSON.stringify(logs);
  assert.ok(!serialized.includes(mockToken), 'a synthetic token reached application logs');
  assert.ok(!serialized.includes(mockContent), 'synthetic file content reached application logs');
}

function assertFailureLog(logs, event, code) {
  assertNoSyntheticText(logs);
  assert.deepEqual(logs.error, [[JSON.stringify({event, code})]]);
}

function assertSafeScheduledRejection(error) {
  assert.ok(error instanceof Error);
  assert.equal(error.message, 'APPLE_AUTH_RETENTION_FAILED');
  assert.equal(error.cause, undefined);
  assert.equal(Object.hasOwn(error, 'cause'), false);
  assert.ok(!String(error.stack).includes(mockToken));
  assert.ok(!String(error.stack).includes(mockContent));
  return true;
}

function database({grantFailure, lifecycleFailure} = {}) {
  const calls = {grantReads: 0, lifecycleBatches: 0};
  return {
    calls,
    prepare() {
      return {
        bind() { return this; },
        async first() {
          calls.grantReads += 1;
          if (grantFailure !== undefined) throw grantFailure;
          return null;
        },
      };
    },
    async batch(statements) {
      calls.lifecycleBatches += 1;
      if (lifecycleFailure !== undefined) throw lifecycleFailure;
      return statements.map(() => ({meta: {changes: 0}}));
    },
  };
}

test('request boundary excludes arbitrary exceptions and preserves its 503 response', async t => {
  const logs = captureLogs(t);
  for (const failure of unexpectedFailures()) {
    logs.error.length = 0;
    const response = await runtime.boundary(async () => { throw failure; });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), {
      error: 'The operation could not be completed. Your changes have not been discarded; retry after refreshing.',
      code: 'SERVICE_UNAVAILABLE',
    });
    assertFailureLog(logs, 'request_failed', 'SERVICE_UNAVAILABLE');
  }
});

test('request success, typed HTTP errors and validation errors keep their existing behavior', async t => {
  const logs = captureLogs(t);
  const success = await runtime.boundary(async () => ({saved: true}));
  assert.equal(success.status, 200);
  assert.equal(success.headers.get('cache-control'), 'no-store');
  assert.equal(success.headers.get('x-content-type-options'), 'nosniff');
  assert.deepEqual(await success.json(), {saved: true});
  const conflict = await runtime.boundary(async () => {
    throw new runtime.HttpError(409, 'The file changed.', 'FILE_CHANGED', {retry: false});
  });
  assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), {retry: false, error: 'The file changed.', code: 'FILE_CHANGED'});
  const validation = await runtime.boundary(async () => runtime.z.object({name: runtime.z.string()}).parse({name: 1}));
  assert.equal(validation.status, 400);
  assert.deepEqual(await validation.json(), {error: 'name: Expected string, received number', code: 'INVALID_REQUEST'});
  assert.deepEqual(logs.error, []);
});

test('Apple auth boundary excludes arbitrary exceptions and preserves 503/security headers', async t => {
  const logs = captureLogs(t);
  for (const failure of unexpectedFailures()) {
    logs.error.length = 0;
    const response = runtime.appleAuthErrorResponse(failure, {'Set-Cookie': 'review=; Max-Age=0'});
    assert.equal(response.status, 503);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(response.headers.get('set-cookie'), 'review=; Max-Age=0');
    assert.deepEqual(await response.json(), {error: 'Apple authentication could not complete.', code: 'APPLE_AUTH_UNAVAILABLE'});
    assertFailureLog(logs, 'apple_auth_failed', 'APPLE_AUTH_UNAVAILABLE');
  }
});

test('known Apple auth errors retain status/code/message and do not become unexpected failures', async t => {
  const logs = captureLogs(t);
  const response = runtime.appleAuthErrorResponse(new runtime.AppleAuthError(401, 'APPLE_SESSION_INVALID', 'Sign in again.'));
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), {error: 'Sign in again.', code: 'APPLE_SESSION_INVALID'});
  assert.deepEqual(logs.error, []);
});

test('scheduled storage failures exclude arbitrary text from logs and runtime rejection', async t => {
  const logs = captureLogs(t);
  for (const failure of unexpectedFailures()) {
    logs.error.length = 0;
    const db = database({lifecycleFailure: failure});
    await assert.rejects(runtime.worker.scheduled({scheduledTime}, {DB: db}), assertSafeScheduledRejection);
    assert.deepEqual(db.calls, {grantReads: 1, lifecycleBatches: 1});
    assertFailureLog(logs, 'apple-auth-retention-failed', 'APPLE_AUTH_RETENTION_FAILED');
    assert.deepEqual(logs.info, []);
  }
});

test('native grant failure still permits lifecycle cleanup, records counts and fails the task', async t => {
  const logs = captureLogs(t);
  const db = database({grantFailure: new Error(syntheticText)});
  await assert.rejects(runtime.worker.scheduled({scheduledTime}, {DB: db}), assertSafeScheduledRejection);
  assert.deepEqual(db.calls, {grantReads: 1, lifecycleBatches: 1});
  assert.equal(logs.info.length, 1);
  assert.deepEqual(JSON.parse(logs.info[0][0]), {
    event: 'apple-auth-retention-complete', scheduledTime, nativeGrants: null,
    batches: 1, flows: 0, sessions: 0, nativeSessions: 0, authorizationCodeClaims: 0,
    deletions: 0, notifications: 0, externalOperationLeases: 0,
  });
  assertFailureLog(logs, 'apple-auth-retention-failed', 'APPLE_AUTH_RETENTION_FAILED');
});

test('successful scheduled retention retains aggregate telemetry and resolves', async t => {
  const logs = captureLogs(t);
  const db = database();
  assert.equal(await runtime.worker.scheduled({scheduledTime}, {DB: db}), undefined);
  assert.deepEqual(db.calls, {grantReads: 1, lifecycleBatches: 1});
  assert.deepEqual(logs.error, []);
  assert.deepEqual(JSON.parse(logs.info[0][0]), {
    event: 'apple-auth-retention-complete', scheduledTime,
    nativeGrants: {batches: 0, found: 0, revoked: 0, failed: 0, backlog: false},
    batches: 1, flows: 0, sessions: 0, nativeSessions: 0, authorizationCodeClaims: 0,
    deletions: 0, notifications: 0, externalOperationLeases: 0,
  });
});

test('missing DB and invalid scheduled time remain rejected before retention work', async t => {
  const logs = captureLogs(t);
  await assert.rejects(runtime.worker.scheduled({scheduledTime}, {}), assertSafeScheduledRejection);
  assertFailureLog(logs, 'apple-auth-retention-failed', 'APPLE_AUTH_RETENTION_FAILED');
  logs.error.length = 0;
  const db = database();
  await assert.rejects(runtime.worker.scheduled({scheduledTime: Number.NaN}, {DB: db}), assertSafeScheduledRejection);
  assert.deepEqual(db.calls, {grantReads: 0, lifecycleBatches: 0});
  assertFailureLog(logs, 'apple-auth-retention-failed', 'APPLE_AUTH_RETENTION_FAILED');
});

test('failure logging does not inspect attacker-controlled Error properties', async t => {
  const logs = captureLogs(t);
  const failure = new Error();
  let reads = 0;
  for (const name of ['message', 'name', 'stack', 'cause']) {
    Object.defineProperty(failure, name, {get() { reads += 1; return syntheticText; }});
  }
  assert.equal((await runtime.boundary(async () => {throw failure;})).status, 503);
  assert.equal(runtime.appleAuthErrorResponse(failure).status, 503);
  await assert.rejects(runtime.worker.scheduled({scheduledTime}, {DB: database({lifecycleFailure: failure})}), assertSafeScheduledRejection);
  assert.equal(reads, 0);
  assertNoSyntheticText(logs);
});
