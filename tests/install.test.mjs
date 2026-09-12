import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { PortableInstallLease, parseDuration, parsePackageManager, runBounded } from '../scripts/install-ci.mjs';

test('installer derives and validates the exact pnpm pin', () => {
  assert.equal(parsePackageManager('pnpm@11.19.0'), '11.19.0');
  for (const value of ['pnpm@11', 'npm@11.19.0', '^11.19.0', '']) assert.throws(() => parsePackageManager(value));
});

test('installer durations are bounded and explicit', () => {
  assert.equal(parseDuration('8m', 1), 480_000);
  assert.equal(parseDuration('15s', 1), 15_000);
  assert.equal(parseDuration(undefined, 42_000), 42_000);
  for (const value of ['0s', '999ms', '61m', 'soon']) assert.throws(() => parseDuration(value, 1));
});

test('portable install lease rejects overlap and removes only its own owner', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'local-sandbox-install-'));
  const lock = path.join(root, 'install.lock');
  try {
    const first = new PortableInstallLease(lock);
    first.acquire();
    const second = new PortableInstallLease(lock);
    assert.throws(() => second.acquire(), (error) => error.exitCode === 75);
    first.release();
    second.acquire();
    second.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('portable install lease reconciles a dead owner but refuses unknown contents', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'local-sandbox-install-'));
  const lock = path.join(root, 'install.lock');
  try {
    await mkdir(lock);
    await writeFile(path.join(lock, 'owner.json'), JSON.stringify({
      version: 1,
      pid: 2_147_483_647,
      nonce: '00000000-0000-4000-8000-000000000000',
      startedAt: new Date(0).toISOString(),
    }));
    const recovered = new PortableInstallLease(lock);
    recovered.acquire();
    recovered.release();

    await mkdir(lock);
    await writeFile(path.join(lock, 'do-not-delete'), 'unexpected');
    const guarded = new PortableInstallLease(lock);
    assert.throws(() => guarded.acquire(), (error) => error.exitCode === 78);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('portable install lease waits before reconciling an empty owner gap', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'local-sandbox-install-'));
  const lock = path.join(root, 'install.lock');
  try {
    await mkdir(lock);
    assert.throws(() => new PortableInstallLease(lock).acquire(), (error) => error.exitCode === 75);
    const old = new Date(Date.now() - 31_000);
    await utimes(lock, old, old);
    const recovered = new PortableInstallLease(lock);
    recovered.acquire();
    recovered.release();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('bounded child returns timeout evidence', async () => {
  const result = await runBounded(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
    cwd: process.cwd(),
    env: process.env,
    stdio: 'ignore',
    timeoutMs: 1_000,
    killAfterMs: 1_000,
  });
  assert.equal(result.timedOut, true);
});
