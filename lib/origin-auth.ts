import { z } from 'zod';
import { BoundedResponseError, readBoundedResponseText } from './bounded-response.ts';

export const ORIGIN_API_BASE_URL = 'https://api.cursor.com/v1/origin';
export const ORIGIN_ISSUER = ORIGIN_API_BASE_URL;
export const ORIGIN_DISCOVERY_URL = `${ORIGIN_API_BASE_URL}/.well-known/openid-configuration`;
export const ORIGIN_KEYS_URL = `${ORIGIN_API_BASE_URL}/keys`;
export const ORIGIN_INSTALL_URL = 'https://cursor.com/codebase/apps/install';

const APP_JWT_LIFETIME_SECONDS = 5 * 60;
const INSTALLATION_RECEIPT_LIFETIME_SECONDS = 5 * 60;
const INSTALLATION_TOKEN_MAX_LIFETIME_SECONDS = 15 * 60;
export const ORIGIN_RECEIPT_CLOCK_SKEW_SECONDS = 60;
const JWKS_FRESH_SECONDS = 10 * 60;
const JWKS_STALE_SECONDS = 20 * 60;
const MAX_JSON_BYTES = 128 * 1024;

export const ORIGIN_CONTENTS_READ_SCOPE = 'repository:contents:read' as const;

const originScopeSchema = z.literal(ORIGIN_CONTENTS_READ_SCOPE);
const appIDSchema = z.string().regex(/^app_[a-z0-9]{8,100}$/).brand<'OriginAppID'>();
const installationIDSchema = z.string().regex(/^(?:i|inst)_[a-z0-9]{8,100}$/).brand<'OriginInstallationID'>();
const namespaceIDSchema = z.string().regex(/^ns_[a-z0-9]{8,100}$/).brand<'OriginNamespaceID'>();
const repositoryIDSchema = z.string().regex(/^repo_[a-z0-9]{8,100}$/).brand<'OriginRepositoryID'>();
const receiptIDSchema = z.string().uuid().brand<'OriginReceiptID'>();
const stateSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/).brand<'OriginInstallState'>();

const environmentSchema = z.object({
  ORIGIN_APP_ID: appIDSchema,
  ORIGIN_APP_PRIVATE_KEY_PKCS8: z.string().min(100).max(10_000),
  ORIGIN_INSTALL_REDIRECT_URI: z.string().url().max(500),
  ORIGIN_INSTALL_SCOPES: z.string().min(1).max(1_000),
  ORIGIN_INSTALL_SUMMARY: z.string().min(1).max(200).optional(),
}).passthrough();

export type OriginScope = z.infer<typeof originScopeSchema>;
export type OriginAppID = z.infer<typeof appIDSchema>;
export type OriginInstallationID = z.infer<typeof installationIDSchema>;
export type OriginRepositoryID = z.infer<typeof repositoryIDSchema>;

export type OriginConfiguration = {
  schemaVersion: 1;
  appId: OriginAppID;
  privateKeyPem: string;
  redirectUri: string;
  requestedScopes: readonly [OriginScope];
  installSummary: string;
};

export class OriginAuthError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'OriginAuthError';
    this.status = status;
    this.code = code;
  }
}

function notConfigured(): OriginAuthError {
  return new OriginAuthError(
    503,
    'ORIGIN_NOT_CONFIGURED',
    'Cursor Origin is not configured on this server.',
  );
}

export function parseOriginConfiguration(environment: unknown): OriginConfiguration {
  const parsed = environmentSchema.safeParse(environment);
  if (!parsed.success) throw notConfigured();

  let redirect: URL;
  try {
    redirect = new URL(parsed.data.ORIGIN_INSTALL_REDIRECT_URI);
  } catch {
    throw notConfigured();
  }
  const loopback = redirect.hostname === 'localhost' ||
    redirect.hostname === '127.0.0.1' ||
    redirect.hostname === '[::1]';
  if (
    (redirect.protocol !== 'https:' && !(loopback && redirect.protocol === 'http:')) ||
    redirect.username !== '' ||
    redirect.password !== '' ||
    redirect.search !== '' ||
    redirect.hash !== ''
  ) {
    throw notConfigured();
  }

  const privateKeyPem = parsed.data.ORIGIN_APP_PRIVATE_KEY_PKCS8.includes('\n')
    ? parsed.data.ORIGIN_APP_PRIVATE_KEY_PKCS8
    : parsed.data.ORIGIN_APP_PRIVATE_KEY_PKCS8.replaceAll('\\n', '\n');
  if (!/^-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n\r]+\n-----END PRIVATE KEY-----\n?$/.test(privateKeyPem)) {
    throw notConfigured();
  }

  const rawScopes = parsed.data.ORIGIN_INSTALL_SCOPES.trim().split(/\s+/);
  const scopes = z.tuple([originScopeSchema]).safeParse(rawScopes);
  if (!scopes.success) {
    throw notConfigured();
  }

  return {
    schemaVersion: 1,
    appId: parsed.data.ORIGIN_APP_ID,
    privateKeyPem,
    redirectUri: redirect.toString(),
    requestedScopes: Object.freeze([ORIGIN_CONTENTS_READ_SCOPE]),
    installSummary: parsed.data.ORIGIN_INSTALL_SUMMARY ?? 'Connect Local Sandbox to selected Origin repositories.',
  };
}

export type OriginInstallationStart = {
  schemaVersion: 1;
  authorizationUrl: string;
  state: string;
};

export function createOriginInstallationStart(
  configuration: OriginConfiguration,
  cryptoProvider: Crypto,
): OriginInstallationStart {
  const state = randomState(cryptoProvider);
  const url = new URL(ORIGIN_INSTALL_URL);
  url.searchParams.set('client_id', configuration.appId);
  url.searchParams.set('scope', ORIGIN_CONTENTS_READ_SCOPE);
  url.searchParams.set('redirect_uri', configuration.redirectUri);
  url.searchParams.set('state', state);
  url.searchParams.set('summary', configuration.installSummary);
  return {schemaVersion: 1, authorizationUrl: url.toString(), state};
}

export type OriginReceiptReplayStore = {
  /** Atomically returns true only for the first claim of this receipt ID. */
  claim(receipt: {id: string; expiresAt: number}, now: number): Promise<boolean>;
};

const installedBySchema = z.object({
  id: z.string().regex(/^user_[a-z0-9]{8,100}$/),
  email: z.string().email().max(320),
  displayName: z.string().min(1).max(200).optional(),
}).strict();

const receiptHeaderSchema = z.object({
  alg: z.literal('EdDSA'),
  kid: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/),
  typ: z.literal('origin-installation-receipt+jwt'),
}).strict();

const receiptClaimsSchema = z.object({
  iss: z.literal(ORIGIN_ISSUER),
  aud: appIDSchema,
  sub: installationIDSchema,
  namespace_id: namespaceIDSchema,
  iat: z.number().int().nonnegative(),
  exp: z.number().int().positive(),
  jti: receiptIDSchema,
  installedBy: installedBySchema,
  state: stateSchema,
}).strict();

export type OriginInstallationReceipt = {
  schemaVersion: 1;
  appId: OriginAppID;
  installationId: OriginInstallationID;
  namespaceId: z.infer<typeof namespaceIDSchema>;
  receiptId: z.infer<typeof receiptIDSchema>;
  installedBy: z.infer<typeof installedBySchema>;
  issuedAt: number;
  expiresAt: number;
};

const discoverySchema = z.object({
  issuer: z.literal(ORIGIN_ISSUER),
  jwks_uri: z.literal(ORIGIN_KEYS_URL),
  response_types_supported: z.array(z.string()).refine(values => values.includes('id_token')),
  subject_types_supported: z.array(z.string()).refine(values => values.includes('public')),
  id_token_signing_alg_values_supported: z.array(z.string()).refine(values => values.includes('EdDSA')),
}).passthrough();

const signingKeySchema = z.object({
  kty: z.literal('OKP'),
  crv: z.literal('Ed25519'),
  use: z.literal('sig'),
  alg: z.literal('EdDSA'),
  kid: z.string().regex(/^[A-Za-z0-9_-]{8,128}$/),
  x: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
}).strict();

const keySetSchema = z.object({
  keys: z.array(signingKeySchema).min(1).max(20),
}).strict().superRefine((value, context) => {
  if (new Set(value.keys.map(key => key.kid)).size !== value.keys.length) {
    context.addIssue({code: z.ZodIssueCode.custom, message: 'Signing key IDs must be unique.'});
  }
});

type OriginSigningKey = z.infer<typeof signingKeySchema>;
export type OriginFetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export class OriginSigningKeyCache {
  private cached: {keys: readonly OriginSigningKey[]; freshUntil: number; staleUntil: number} | null = null;

  async read(input: {
    fetcher: OriginFetch;
    now: number;
    forceRefresh?: boolean;
  }): Promise<readonly OriginSigningKey[]> {
    if (!input.forceRefresh && this.cached && input.now < this.cached.freshUntil) {
      return this.cached.keys;
    }

    try {
      const discovery = discoverySchema.parse(await fetchJSON(
        input.fetcher,
        ORIGIN_DISCOVERY_URL,
        'ORIGIN_DISCOVERY_UNAVAILABLE',
      ));
      const keySet = keySetSchema.parse(await fetchJSON(
        input.fetcher,
        discovery.jwks_uri,
        'ORIGIN_KEYS_UNAVAILABLE',
      ));
      this.cached = {
        keys: keySet.keys,
        freshUntil: input.now + JWKS_FRESH_SECONDS,
        staleUntil: input.now + JWKS_STALE_SECONDS,
      };
      return keySet.keys;
    } catch (error) {
      if (!input.forceRefresh && this.cached && input.now < this.cached.staleUntil) {
        return this.cached.keys;
      }
      if (error instanceof OriginAuthError) throw error;
      throw new OriginAuthError(
        502,
        'ORIGIN_KEYS_UNAVAILABLE',
        'Cursor Origin signing keys could not be validated.',
      );
    }
  }
}

export type OriginReceiptVerificationDependencies = {
  configuration: OriginConfiguration;
  replayStore: OriginReceiptReplayStore;
  fetcher: OriginFetch;
  crypto: Crypto;
  now: () => number;
  signingKeys?: OriginSigningKeyCache;
};

export async function verifyOriginInstallationReceipt(
  dependencies: OriginReceiptVerificationDependencies,
  serializedReceipt: string,
  expectedState: string,
): Promise<OriginInstallationReceipt> {
  const now = dependencies.now();
  const state = parseOrThrow(
    stateSchema,
    expectedState,
    'ORIGIN_INSTALL_STATE_INVALID',
    'The Cursor Origin install state is missing or invalid.',
  );
  const compact = parseCompactJWT(serializedReceipt);
  const header: z.output<typeof receiptHeaderSchema> = parseJSONSegment(
    receiptHeaderSchema,
    compact.header,
    'ORIGIN_RECEIPT_INVALID',
    'The Cursor Origin installation receipt header is invalid.',
  );
  const claims: z.output<typeof receiptClaimsSchema> = parseJSONSegment(
    receiptClaimsSchema,
    compact.payload,
    'ORIGIN_RECEIPT_INVALID',
    'The Cursor Origin installation receipt claims are invalid.',
  );

  if (claims.aud !== dependencies.configuration.appId) {
    throw invalidReceipt('The Cursor Origin installation receipt targets another app.');
  }
  if (!constantTimeEqual(claims.state, state)) {
    throw new OriginAuthError(400, 'ORIGIN_INSTALL_STATE_MISMATCH', 'The Cursor Origin install state did not match.');
  }
  if (
    claims.exp <= now ||
    claims.iat > now + ORIGIN_RECEIPT_CLOCK_SKEW_SECONDS ||
    claims.exp <= claims.iat ||
    claims.exp - claims.iat > INSTALLATION_RECEIPT_LIFETIME_SECONDS
  ) {
    throw invalidReceipt('The Cursor Origin installation receipt is expired or has an invalid lifetime.');
  }

  const keyCache = dependencies.signingKeys ?? new OriginSigningKeyCache();
  let keys = await keyCache.read({fetcher: dependencies.fetcher, now});
  let verified = await verifyReceiptSignature(
    dependencies.crypto,
    keys.find(key => key.kid === header.kid),
    compact,
  );
  if (!verified) {
    keys = await keyCache.read({fetcher: dependencies.fetcher, now, forceRefresh: true});
    verified = await verifyReceiptSignature(
      dependencies.crypto,
      keys.find(key => key.kid === header.kid),
      compact,
    );
  }
  if (!verified) throw invalidReceipt('The Cursor Origin installation receipt signature is invalid.');

  let claimed: boolean;
  try {
    claimed = await dependencies.replayStore.claim({id: claims.jti, expiresAt: claims.exp}, now);
  } catch {
    throw new OriginAuthError(
      503,
      'ORIGIN_REPLAY_STORE_UNAVAILABLE',
      'Cursor Origin receipt replay protection is unavailable.',
    );
  }
  if (!claimed) {
    throw new OriginAuthError(409, 'ORIGIN_RECEIPT_REPLAYED', 'This Cursor Origin installation receipt was already used.');
  }

  return {
    schemaVersion: 1,
    appId: claims.aud,
    installationId: claims.sub,
    namespaceId: claims.namespace_id,
    receiptId: claims.jti,
    installedBy: claims.installedBy,
    issuedAt: claims.iat,
    expiresAt: claims.exp,
  };
}

export type OriginAppJWT = {
  token: string;
  issuedAt: number;
  expiresAt: number;
};

export async function createOriginAppJWT(input: {
  configuration: OriginConfiguration;
  crypto: Crypto;
  now: number;
}): Promise<OriginAppJWT> {
  const issuedAt = input.now;
  const expiresAt = issuedAt + APP_JWT_LIFETIME_SECONDS;
  const header = base64URLEncode(new TextEncoder().encode(JSON.stringify({
    alg: 'EdDSA',
    kid: input.configuration.appId,
    typ: 'JWT',
  })));
  const payload = base64URLEncode(new TextEncoder().encode(JSON.stringify({
    iss: input.configuration.appId,
    aud: 'origin-apps',
    iat: issuedAt,
    exp: expiresAt,
  })));
  const signingInput = new TextEncoder().encode(`${header}.${payload}`);

  let privateKey: CryptoKey;
  try {
    privateKey = await input.crypto.subtle.importKey(
      'pkcs8',
      pemPrivateKey(input.configuration.privateKeyPem),
      {name: 'Ed25519'},
      false,
      ['sign'],
    );
  } catch {
    throw notConfigured();
  }
  const signature = new Uint8Array(await input.crypto.subtle.sign(
    {name: 'Ed25519'},
    privateKey,
    signingInput,
  ));
  if (signature.byteLength !== 64) throw notConfigured();
  return {
    token: `${header}.${payload}.${base64URLEncode(signature)}`,
    issuedAt,
    expiresAt,
  };
}

export const originInstallationTokenRequestSchema = z.object({
  installationId: installationIDSchema,
  repositoryIds: z.array(repositoryIDSchema).max(50)
    .refine(values => new Set(values).size === values.length, 'Repository IDs must be unique.'),
}).strict();

export type OriginInstallationTokenRequest = z.infer<typeof originInstallationTokenRequestSchema>;
export type OriginInstallationToken = {
  token: string;
  expiresAt: string;
};

export function parseOriginInstallationTokenRequest(value: unknown): OriginInstallationTokenRequest {
  return parseOrThrow(
    originInstallationTokenRequestSchema,
    value,
    'ORIGIN_TOKEN_REQUEST_INVALID',
    'Cursor Origin installation or repository IDs are invalid.',
  );
}

const installationTokenResponseSchema = z.object({
  token: z.string().regex(/^oit_[A-Za-z0-9_-]{8,2000}$/),
  expiresAt: z.string().datetime({offset: true}),
}).strict();

export async function mintOriginInstallationToken(input: {
  configuration: OriginConfiguration;
  request: OriginInstallationTokenRequest;
  fetcher: OriginFetch;
  crypto: Crypto;
  now: () => number;
}): Promise<OriginInstallationToken> {
  const now = input.now();
  const appJWT = await createOriginAppJWT({
    configuration: input.configuration,
    crypto: input.crypto,
    now,
  });
  const url = `${ORIGIN_API_BASE_URL}/app/installations/${encodeURIComponent(input.request.installationId)}/access_tokens`;
  let response: Response;
  try {
    response = await input.fetcher(url, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${appJWT.token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({scopes: [ORIGIN_CONTENTS_READ_SCOPE], repositoryIds: input.request.repositoryIds}),
      redirect: 'error',
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw new OriginAuthError(502, 'ORIGIN_TOKEN_UNAVAILABLE', 'Cursor Origin could not mint an installation token.');
  }
  if (!response.ok) {
    const status = response.status === 401 || response.status === 403 || response.status === 404
      ? response.status
      : 502;
    throw new OriginAuthError(
      status,
      'ORIGIN_TOKEN_REJECTED',
      `Cursor Origin rejected the installation token request (${response.status}).`,
    );
  }
  const serialized = await boundedJSON(response, 'ORIGIN_TOKEN_INVALID');
  const token = parseOrThrow(
    installationTokenResponseSchema,
    serialized,
    'ORIGIN_TOKEN_INVALID',
    'Cursor Origin returned an invalid installation token.',
  );
  const expiresAt = Math.floor(Date.parse(token.expiresAt) / 1_000);
  if (
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    expiresAt > now + INSTALLATION_TOKEN_MAX_LIFETIME_SECONDS ||
    expiresAt > appJWT.expiresAt
  ) {
    throw new OriginAuthError(502, 'ORIGIN_TOKEN_INVALID', 'Cursor Origin returned an invalid token lifetime.');
  }
  return token;
}

type CompactJWT = {
  header: string;
  payload: string;
  signature: string;
  signed: Uint8Array;
};

function parseCompactJWT(value: string): CompactJWT {
  if (value.length < 40 || value.length > 20_000) throw invalidReceipt('The Cursor Origin installation receipt is invalid.');
  const segments = value.split('.');
  if (segments.length !== 3 || segments.some(segment => segment === '')) {
    throw invalidReceipt('The Cursor Origin installation receipt is invalid.');
  }
  const [header, payload, signature] = segments;
  base64URLDecode(header, 2_048);
  base64URLDecode(payload, 16_384);
  const signatureBytes = base64URLDecode(signature, 128);
  if (signatureBytes.byteLength !== 64) throw invalidReceipt('The Cursor Origin installation receipt signature is invalid.');
  return {
    header,
    payload,
    signature,
    signed: new TextEncoder().encode(`${header}.${payload}`),
  };
}

async function verifyReceiptSignature(
  cryptoProvider: Crypto,
  signingKey: OriginSigningKey | undefined,
  compact: CompactJWT,
): Promise<boolean> {
  if (!signingKey) return false;
  const jwk: JsonWebKey = {
    kty: signingKey.kty,
    crv: signingKey.crv,
    x: signingKey.x,
  };
  try {
    const key = await cryptoProvider.subtle.importKey(
      'jwk',
      jwk,
      {name: 'Ed25519'},
      false,
      ['verify'],
    );
    return await cryptoProvider.subtle.verify(
      {name: 'Ed25519'},
      key,
      base64URLDecode(compact.signature, 128),
      toArrayBuffer(compact.signed),
    );
  } catch {
    return false;
  }
}

function parseJSONSegment<Output, Input>(
  schema: z.ZodType<Output, z.ZodTypeDef, Input>,
  segment: string,
  code: string,
  message: string,
): Output {
  try {
    const decoded = new TextDecoder('utf-8', {fatal: true}).decode(base64URLDecode(segment, 16_384));
    return schema.parse(JSON.parse(decoded));
  } catch {
    throw new OriginAuthError(400, code, message);
  }
}

function parseOrThrow<Output, Input>(
  schema: z.ZodType<Output, z.ZodTypeDef, Input>,
  value: unknown,
  code: string,
  message: string,
): Output {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new OriginAuthError(400, code, message);
  return parsed.data;
}

async function fetchJSON(fetcher: OriginFetch, url: string, code: string): Promise<unknown> {
  let response: Response;
  try {
    response = await fetcher(url, {
      method: 'GET',
      headers: {Accept: 'application/json'},
      redirect: 'error',
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    throw new OriginAuthError(502, code, 'Cursor Origin authentication metadata is unavailable.');
  }
  if (!response.ok) {
    throw new OriginAuthError(502, code, 'Cursor Origin authentication metadata is unavailable.');
  }
  return boundedJSON(response, code);
}

async function boundedJSON(response: Response, code: string): Promise<unknown> {
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new OriginAuthError(502, code, 'Cursor Origin returned an invalid response.');
  }
  let text: string;
  try {
    text = await readBoundedResponseText(response, MAX_JSON_BYTES);
  } catch (error) {
    const message = error instanceof BoundedResponseError && error.kind === 'too-large'
      ? 'Cursor Origin returned an oversized response.'
      : 'Cursor Origin returned an invalid response.';
    throw new OriginAuthError(502, code, message);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new OriginAuthError(502, code, 'Cursor Origin returned invalid JSON.');
  }
}

function pemPrivateKey(pem: string): ArrayBuffer {
  const encoded = pem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(encoded)) throw notConfigured();
  let binary: string;
  try {
    binary = atob(encoded);
  } catch {
    throw notConfigured();
  }
  return toArrayBuffer(Uint8Array.from(binary, character => character.charCodeAt(0)));
}

function randomState(cryptoProvider: Crypto): z.infer<typeof stateSchema> {
  const bytes = new Uint8Array(32);
  cryptoProvider.getRandomValues(bytes);
  return stateSchema.parse(base64URLEncode(bytes));
}

function base64URLEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function base64URLDecode(value: string, maxBytes: number): ArrayBuffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(maxBytes * 4 / 3) + 4) {
    throw new Error('Invalid base64url value.');
  }
  const padded = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new Error('Invalid base64url value.');
  }
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (bytes.byteLength > maxBytes || base64URLEncode(bytes) !== value) {
    throw new Error('Invalid base64url value.');
  }
  return toArrayBuffer(bytes);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  if (leftBytes.byteLength !== rightBytes.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < leftBytes.byteLength; index += 1) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  return difference === 0;
}

function invalidReceipt(message: string): OriginAuthError {
  return new OriginAuthError(400, 'ORIGIN_RECEIPT_INVALID', message);
}
