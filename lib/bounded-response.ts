export type BoundedResponseFailure = 'invalid-length' | 'too-large' | 'invalid-utf8';

export class BoundedResponseError extends Error {
  readonly kind: BoundedResponseFailure;

  constructor(kind: BoundedResponseFailure) {
    super(kind);
    this.name = 'BoundedResponseError';
    this.kind = kind;
  }
}

export async function readBoundedResponseText(response: Response, maximumBytes: number): Promise<string> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) throw new TypeError('maximumBytes must be a nonnegative safe integer.');
  const declared = response.headers.get('content-length');
  if (declared !== null) {
    if (!/^\d+$/.test(declared)) throw new BoundedResponseError('invalid-length');
    const value = Number(declared);
    if (!Number.isSafeInteger(value)) throw new BoundedResponseError('invalid-length');
    if (value > maximumBytes) {
      await response.body?.cancel().catch(() => undefined);
      throw new BoundedResponseError('too-large');
    }
  }

  if (response.body === null) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    total += chunk.value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel().catch(() => undefined);
      throw new BoundedResponseError('too-large');
    }
    chunks.push(chunk.value);
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder('utf-8', {fatal: true}).decode(bytes);
  } catch {
    throw new BoundedResponseError('invalid-utf8');
  }
}
