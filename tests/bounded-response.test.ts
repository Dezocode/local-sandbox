import assert from 'node:assert/strict';
import test from 'node:test';
import { BoundedResponseError, readBoundedResponseText } from '../lib/bounded-response.ts';

test('bounded response text cancels a chunked body as soon as its byte limit is exceeded', async () => {
  let cancelled = false;
  let pulls = 0;
  const response = new Response(new ReadableStream<Uint8Array>({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new Uint8Array(40));
      if (pulls >= 10) controller.close();
    },
    cancel() { cancelled = true; },
  }));
  await assert.rejects(
    () => readBoundedResponseText(response, 64),
    error => error instanceof BoundedResponseError && error.kind === 'too-large',
  );
  assert.equal(cancelled, true);
  assert.ok(pulls < 10);
});

test('bounded response text rejects oversized declarations and malformed UTF-8', async () => {
  await assert.rejects(
    () => readBoundedResponseText(new Response('small', {headers: {'Content-Length': '1000'}}), 100),
    error => error instanceof BoundedResponseError && error.kind === 'too-large',
  );
  await assert.rejects(
    () => readBoundedResponseText(new Response(Uint8Array.of(0xc3, 0x28)), 100),
    error => error instanceof BoundedResponseError && error.kind === 'invalid-utf8',
  );
});

test('bounded response text returns exact multibyte UTF-8 within the byte limit', async () => {
  const value = 'safe αβ';
  assert.equal(await readBoundedResponseText(new Response(value), new TextEncoder().encode(value).byteLength), value);
});
