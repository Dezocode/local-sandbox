import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ORIGIN_DISCOVERY_URL,
  ORIGIN_INSTALL_URL,
  ORIGIN_ISSUER,
  ORIGIN_KEYS_URL,
  OriginAuthError,
  OriginSigningKeyCache,
  type OriginConfiguration,
  type OriginFetch,
  type OriginInstallationID,
  type OriginReceiptReplayStore,
  createOriginAppJWT,
  createOriginInstallationStart,
  mintOriginInstallationToken,
  parseOriginConfiguration,
  parseOriginInstallationTokenRequest,
  verifyOriginInstallationReceipt,
} from '../lib/origin-auth.ts';
import {
  ORIGIN_COMMAND_MAXIMUM_BYTES,
  ORIGIN_FLOW_COOKIE,
  originAuthErrorResponse,
  originInstallationStartResponse,
  persistOriginInstallationOrRequireManualCleanup,
  readOriginCommandRequest,
  verifyOriginInstallationCallback,
} from '../lib/origin-auth-http.ts';

const NOW = 1_800_000_000;
const APP_ID = 'app_01k2ja2000e0080000000000a1';
const INSTALLATION_ID = 'i_01k2ja2000e0080000000000b2' as OriginInstallationID;
const NAMESPACE_ID = 'ns_01k2ja2000e0080000000000p3';
const REPOSITORY_ID = 'repo_01k2ja2000e0080000000000q4';
const ORIGIN_KEY_ID = 'origin_key_fixture_01';
const STATE = 'S'.repeat(43);

class MemoryReplayStore implements OriginReceiptReplayStore {
  readonly receipts = new Set<string>();
  fail = false;

  async claim(receipt: {id: string; expiresAt: number}, now: number): Promise<boolean> {
    if (this.fail) throw new Error('storage down');
    if (receipt.expiresAt <= now || this.receipts.has(receipt.id)) return false;
    this.receipts.add(receipt.id);
    return true;
  }
}

type Fixture = {
  configuration: OriginConfiguration;
  appPublicKey: CryptoKey;
  originPrivateKey: CryptoKey;
  originPublicJWK: {kty: 'OKP'; crv: 'Ed25519'; use: 'sig'; alg: 'EdDSA'; kid: string; x: string};
  replayStore: MemoryReplayStore;
  requests: {url: string; authorization: string | null; body: string | null}[];
  fetcher: OriginFetch;
};

async function createFixture(): Promise<Fixture> {
  const appKeys = await crypto.subtle.generateKey({name: 'Ed25519'}, true, ['sign', 'verify']);
  const originKeys = await crypto.subtle.generateKey({name: 'Ed25519'}, true, ['sign', 'verify']);
  const privateKeyPem = pemFromPKCS8(await crypto.subtle.exportKey('pkcs8', appKeys.privateKey));
  const exportedOriginJWK = await crypto.subtle.exportKey('jwk', originKeys.publicKey);
  if (!exportedOriginJWK.x) throw new Error('The generated Origin fixture key has no public coordinate.');
  const originPublicJWK = {
    kty: 'OKP' as const,
    crv: 'Ed25519' as const,
    use: 'sig' as const,
    alg: 'EdDSA' as const,
    kid: ORIGIN_KEY_ID,
    x: exportedOriginJWK.x,
  };
  const configuration = parseOriginConfiguration({
    ORIGIN_APP_ID: APP_ID,
    ORIGIN_APP_PRIVATE_KEY_PKCS8: privateKeyPem,
    ORIGIN_INSTALL_REDIRECT_URI: 'https://sandbox.example.com/api/origin/callback',
    ORIGIN_INSTALL_SCOPES: 'repository:contents:read',
    ORIGIN_INSTALL_SUMMARY: 'Sync selected Local Sandbox files.',
    UNRELATED_BINDING: 'allowed',
  });
  const requests: {url: string; authorization: string | null; body: string | null}[] = [];
  const fetcher: OriginFetch = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    const headers = new Headers(init?.headers);
    requests.push({
      url,
      authorization: headers.get('authorization'),
      body: typeof init?.body === 'string' ? init.body : null,
    });
    if (url === ORIGIN_DISCOVERY_URL) {
      return jsonResponse({
        issuer: ORIGIN_ISSUER,
        jwks_uri: ORIGIN_KEYS_URL,
        response_types_supported: ['id_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['EdDSA'],
      });
    }
    if (url === ORIGIN_KEYS_URL) return jsonResponse({keys: [originPublicJWK]});
    if (url.endsWith(`/app/installations/${INSTALLATION_ID}/access_tokens`)) {
      return jsonResponse({
        token: 'oit_generated_fixture_token',
        expiresAt: new Date((NOW + 240) * 1_000).toISOString(),
      });
    }
    return new Response(null, {status: 404});
  };
  return {
    configuration,
    appPublicKey: appKeys.publicKey,
    originPrivateKey: originKeys.privateKey,
    originPublicJWK,
    replayStore: new MemoryReplayStore(),
    requests,
    fetcher,
  };
}

test('configuration fails closed unless the Origin grant is exactly contents read-only', async () => {
  assert.throws(() => parseOriginConfiguration({}), matchesCode('ORIGIN_NOT_CONFIGURED'));
  const fixture = await createFixture();
  const base = {
    ORIGIN_APP_ID: fixture.configuration.appId,
    ORIGIN_APP_PRIVATE_KEY_PKCS8: fixture.configuration.privateKeyPem,
    ORIGIN_INSTALL_REDIRECT_URI: fixture.configuration.redirectUri,
  };
  assert.throws(
    () => parseOriginConfiguration({...base, ORIGIN_INSTALL_SCOPES: 'repository:metadata:read'}),
    matchesCode('ORIGIN_NOT_CONFIGURED'),
  );
  assert.throws(
    () => parseOriginConfiguration({...base, ORIGIN_INSTALL_SCOPES: 'repository:contents:read repository:contents:read'}),
    matchesCode('ORIGIN_NOT_CONFIGURED'),
  );
  for (const scopes of [
    'repository:contents:write',
    'repository:pull_requests:read',
    'repository:contents:read repository:contents:write',
  ]) {
    assert.throws(
      () => parseOriginConfiguration({...base, ORIGIN_INSTALL_SCOPES: scopes}),
      matchesCode('ORIGIN_NOT_CONFIGURED'),
    );
  }
  assert.throws(
    () => parseOriginConfiguration({...base, ORIGIN_INSTALL_SCOPES: 'repository:contents:read', ORIGIN_INSTALL_REDIRECT_URI: 'http://remote.example.com/callback'}),
    matchesCode('ORIGIN_NOT_CONFIGURED'),
  );
  const local = parseOriginConfiguration({
    ...base,
    ORIGIN_INSTALL_SCOPES: 'repository:contents:read',
    ORIGIN_INSTALL_REDIRECT_URI: 'http://localhost:3000/api/origin/callback',
  });
  assert.equal(local.redirectUri, 'http://localhost:3000/api/origin/callback');
});

test('install start uses a fresh 256-bit state and fixed configured grants', async () => {
  const fixture = await createFixture();
  const first = createOriginInstallationStart(fixture.configuration, crypto);
  const second = createOriginInstallationStart(fixture.configuration, crypto);
  assert.notEqual(first.state, second.state);
  assert.match(first.state, /^[A-Za-z0-9_-]{43}$/);
  const url = new URL(first.authorizationUrl);
  assert.equal(`${url.origin}${url.pathname}`, ORIGIN_INSTALL_URL);
  assert.equal(url.searchParams.get('client_id'), APP_ID);
  assert.equal(url.searchParams.get('scope'), 'repository:contents:read');
  assert.equal(url.searchParams.get('redirect_uri'), fixture.configuration.redirectUri);
  assert.equal(url.searchParams.get('state'), first.state);
  assert.equal(url.searchParams.get('summary'), fixture.configuration.installSummary);
  assert.equal(url.searchParams.has('include_granted_scopes'), false);

  const response = originInstallationStartResponse(
    new Request('https://sandbox.example.com/api/origin/start'),
    fixture.configuration,
    crypto,
  );
  assert.equal(response.status, 303);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(response.headers.get('set-cookie') ?? '', new RegExp(`^${ORIGIN_FLOW_COOKIE}=[A-Za-z0-9_-]{43};`));
  assert.match(response.headers.get('set-cookie') ?? '', /HttpOnly; Secure; SameSite=Lax/);
  assert.throws(
    () => originInstallationStartResponse(
      new Request('https://sandbox.example.com/api/origin/start?scope=repository:contents:write'),
      fixture.configuration,
      crypto,
    ),
    matchesCode('ORIGIN_START_INVALID'),
  );
});

test('app JWT has the exact Origin header, claims, lifetime, and Ed25519 signature', async () => {
  const fixture = await createFixture();
  const jwt = await createOriginAppJWT({configuration: fixture.configuration, crypto, now: NOW});
  const [header, payload, signature] = jwt.token.split('.');
  assert.deepEqual(decodeJSON(header), {alg: 'EdDSA', kid: APP_ID, typ: 'JWT'});
  assert.deepEqual(decodeJSON(payload), {
    iss: APP_ID,
    aud: 'origin-apps',
    iat: NOW,
    exp: NOW + 300,
  });
  assert.equal(jwt.expiresAt - jwt.issuedAt, 300);
  assert.equal(await crypto.subtle.verify(
    {name: 'Ed25519'},
    fixture.appPublicKey,
    base64URLDecode(signature),
    new TextEncoder().encode(`${header}.${payload}`),
  ), true);
});

test('receipt verification checks discovery, JWKS, claims, state, signature, and atomic replay', async () => {
  const fixture = await createFixture();
  const cache = new OriginSigningKeyCache();
  const receipt = await signedReceipt(fixture.originPrivateKey);
  const dependencies = {
    configuration: fixture.configuration,
    replayStore: fixture.replayStore,
    fetcher: fixture.fetcher,
    crypto,
    now: () => NOW,
    signingKeys: cache,
  };
  const verified = await verifyOriginInstallationReceipt(dependencies, receipt, STATE);
  assert.equal(verified.appId, APP_ID);
  assert.equal(verified.installationId, INSTALLATION_ID);
  assert.equal(verified.namespaceId, NAMESPACE_ID);
  assert.equal(fixture.requests.filter(request => request.url === ORIGIN_DISCOVERY_URL).length, 1);
  assert.equal(fixture.requests.filter(request => request.url === ORIGIN_KEYS_URL).length, 1);
  await assert.rejects(
    () => verifyOriginInstallationReceipt(dependencies, receipt, STATE),
    matchesCode('ORIGIN_RECEIPT_REPLAYED'),
  );
  assert.equal(fixture.requests.filter(request => request.url === ORIGIN_KEYS_URL).length, 1);
});

test('receipt verification rejects altered JOSE metadata, claims, state, expiry, and storage failure', async () => {
  const cases: {header?: Record<string, unknown>; claims?: Record<string, unknown>; state?: string; code: string}[] = [
    {header: {alg: 'EdDSA', kid: ORIGIN_KEY_ID, typ: 'JWT'}, code: 'ORIGIN_RECEIPT_INVALID'},
    {header: {alg: 'RS256', kid: ORIGIN_KEY_ID, typ: 'origin-installation-receipt+jwt'}, code: 'ORIGIN_RECEIPT_INVALID'},
    {claims: {iss: 'https://attacker.example.com'}, code: 'ORIGIN_RECEIPT_INVALID'},
    {claims: {aud: 'app_01attacker0000000000000000'}, code: 'ORIGIN_RECEIPT_INVALID'},
    {claims: {exp: NOW}, code: 'ORIGIN_RECEIPT_INVALID'},
    {claims: {iat: NOW, exp: NOW + 301}, code: 'ORIGIN_RECEIPT_INVALID'},
    {state: 'T'.repeat(43), code: 'ORIGIN_INSTALL_STATE_MISMATCH'},
  ];
  for (const item of cases) {
    const fixture = await createFixture();
    const receipt = await signedReceipt(fixture.originPrivateKey, item.header, item.claims);
    await assert.rejects(
      () => verifyOriginInstallationReceipt({
        configuration: fixture.configuration,
        replayStore: fixture.replayStore,
        fetcher: fixture.fetcher,
        crypto,
        now: () => NOW,
      }, receipt, item.state ?? STATE),
      matchesCode(item.code),
    );
    assert.equal(fixture.replayStore.receipts.size, 0);
  }

  const fixture = await createFixture();
  fixture.replayStore.fail = true;
  const storageFailureReceipt = await signedReceipt(fixture.originPrivateKey);
  await assert.rejects(
    () => verifyOriginInstallationReceipt({
      configuration: fixture.configuration,
      replayStore: fixture.replayStore,
      fetcher: fixture.fetcher,
      crypto,
      now: () => NOW,
    }, storageFailureReceipt, STATE),
    matchesCode('ORIGIN_REPLAY_STORE_UNAVAILABLE'),
  );
});

test('unknown receipt keys force one JWKS refresh before failing closed', async () => {
  const fixture = await createFixture();
  let keyReads = 0;
  const fetcher: OriginFetch = async input => {
    const url = input.toString();
    if (url === ORIGIN_DISCOVERY_URL) return jsonResponse(validDiscovery());
    if (url === ORIGIN_KEYS_URL) {
      keyReads += 1;
      return jsonResponse({keys: [{...fixture.originPublicJWK, kid: `different_key_${keyReads}`} ]});
    }
    return new Response(null, {status: 404});
  };
  const unknownKeyReceipt = await signedReceipt(fixture.originPrivateKey);
  await assert.rejects(
    () => verifyOriginInstallationReceipt({
      configuration: fixture.configuration,
      replayStore: fixture.replayStore,
      fetcher,
      crypto,
      now: () => NOW,
      signingKeys: new OriginSigningKeyCache(),
    }, unknownKeyReceipt, STATE),
    matchesCode('ORIGIN_RECEIPT_INVALID'),
  );
  assert.equal(keyReads, 2);
});

test('token minting accepts repository attenuation but no caller-selected scope', async () => {
  assert.deepEqual(
    parseOriginInstallationTokenRequest({installationId: INSTALLATION_ID, repositoryIds: []}).repositoryIds,
    [],
  );
  assert.throws(
    () => parseOriginInstallationTokenRequest({installationId: INSTALLATION_ID, scopes: [], repositoryIds: [REPOSITORY_ID]}),
    matchesCode('ORIGIN_TOKEN_REQUEST_INVALID'),
  );
  assert.throws(
    () => parseOriginInstallationTokenRequest({installationId: INSTALLATION_ID, scopes: ['repository:contents:read'], repositoryIds: [REPOSITORY_ID]}),
    matchesCode('ORIGIN_TOKEN_REQUEST_INVALID'),
  );
  assert.throws(
    () => parseOriginInstallationTokenRequest({installationId: INSTALLATION_ID, scopes: ['repository:contents:write'], repositoryIds: [REPOSITORY_ID]}),
    matchesCode('ORIGIN_TOKEN_REQUEST_INVALID'),
  );
  assert.throws(
    () => parseOriginInstallationTokenRequest({installationId: INSTALLATION_ID, repositoryIds: [REPOSITORY_ID, REPOSITORY_ID]}),
    matchesCode('ORIGIN_TOKEN_REQUEST_INVALID'),
  );
  assert.throws(
    () => parseOriginInstallationTokenRequest({installationId: INSTALLATION_ID, repositoryIds: [REPOSITORY_ID], extra: true}),
    matchesCode('ORIGIN_TOKEN_REQUEST_INVALID'),
  );
});

test('token minting sends an app JWT and exact attenuation, then enforces server expiry', async () => {
  const fixture = await createFixture();
  const request = parseOriginInstallationTokenRequest({
    installationId: INSTALLATION_ID,
    repositoryIds: [REPOSITORY_ID],
  });
  const minted = await mintOriginInstallationToken({
    configuration: fixture.configuration,
    request,
    fetcher: fixture.fetcher,
    crypto,
    now: () => NOW,
  });
  assert.equal(minted.token, 'oit_generated_fixture_token');
  const call = fixture.requests.find(item => item.url.endsWith('/access_tokens'));
  assert.ok(call);
  assert.match(call.authorization ?? '', /^Bearer [^.]+\.[^.]+\.[^.]+$/);
  const bearer = (call.authorization ?? '').slice('Bearer '.length);
  const [, payload] = bearer.split('.');
  assert.deepEqual(decodeJSON(payload), {iss: APP_ID, aud: 'origin-apps', iat: NOW, exp: NOW + 300});
  assert.deepEqual(JSON.parse(call.body ?? ''), {
    scopes: ['repository:contents:read'],
    repositoryIds: [REPOSITORY_ID],
  });

  await assert.rejects(
    () => mintOriginInstallationToken({
      configuration: fixture.configuration,
      request,
      fetcher: async () => jsonResponse({
        token: 'oit_secret_must_not_escape',
        expiresAt: new Date((NOW + 301) * 1_000).toISOString(),
      }),
      crypto,
      now: () => NOW,
    }),
    error => error instanceof OriginAuthError &&
      error.code === 'ORIGIN_TOKEN_INVALID' &&
      !error.message.includes('oit_secret_must_not_escape'),
  );
});

test('callback HTTP parsing rejects extra fields and verifies the cookie-bound receipt', async () => {
  const fixture = await createFixture();
  const receipt = await signedReceipt(fixture.originPrivateKey);
  const request = new Request(
    `https://sandbox.example.com/api/origin/callback?installation_receipt=${encodeURIComponent(receipt)}`,
    {headers: {Cookie: `${ORIGIN_FLOW_COOKIE}=${STATE}`}},
  );
  const verified = await verifyOriginInstallationCallback({
    request,
    dependencies: {
      configuration: fixture.configuration,
      replayStore: fixture.replayStore,
      fetcher: fixture.fetcher,
      crypto,
      now: () => NOW,
    },
  });
  assert.equal(verified.installationId, INSTALLATION_ID);

  await assert.rejects(
    () => verifyOriginInstallationCallback({
      request: new Request(`${request.url}&next=https://attacker.example.com`, {headers: request.headers}),
      dependencies: {
        configuration: fixture.configuration,
        replayStore: new MemoryReplayStore(),
        fetcher: fixture.fetcher,
        crypto,
        now: () => NOW,
      },
    }),
    matchesCode('ORIGIN_CALLBACK_INVALID'),
  );
  const response = originAuthErrorResponse(new Error('oit_secret_value'));
  assert.equal(response.status, 503);
  assert.equal((await response.text()).includes('oit_secret_value'), false);
});

test('Origin command JSON is content-typed, streaming-bounded, and valid UTF-8', async () => {
  const request = (body: BodyInit, headers: HeadersInit = {'Content-Type': 'application/json'}) =>
    new Request('https://sandbox.example.com/api/origin', {method: 'POST', headers, body});
  assert.deepEqual(
    await readOriginCommandRequest(request(JSON.stringify({kind: 'repositories'}))),
    {kind: 'repositories'},
  );
  await assert.rejects(
    () => readOriginCommandRequest(request('{}', {'Content-Type': 'text/plain'})),
    matchesCode('ORIGIN_REQUEST_CONTENT_TYPE'),
  );
  await assert.rejects(
    () => readOriginCommandRequest(request('{}', {
      'Content-Type': 'application/json',
      'Content-Length': '2e3',
    })),
    matchesCode('ORIGIN_REQUEST_CONTENT_LENGTH'),
  );
  await assert.rejects(
    () => readOriginCommandRequest(request(new Uint8Array(ORIGIN_COMMAND_MAXIMUM_BYTES + 1))),
    matchesCode('ORIGIN_REQUEST_TOO_LARGE'),
  );
  await assert.rejects(
    () => readOriginCommandRequest(request(new Uint8Array([0xc3, 0x28]))),
    matchesCode('ORIGIN_REQUEST_ENCODING'),
  );
  await assert.rejects(
    () => readOriginCommandRequest(request('{')),
    matchesCode('ORIGIN_REQUEST_INVALID'),
  );
});

test('callback persistence requires manual cleanup without deleting a possibly shared installation', async () => {
  let persistenceAttempts = 0;
  let authorityReleases = 0;
  const gated = new OriginAuthError(
    409,
    'APPLE_ACCOUNT_DELETION_IN_PROGRESS',
    'This Apple access is being deleted.',
  );
  await assert.rejects(
    persistOriginInstallationOrRequireManualCleanup({
      async persist() {
        persistenceAttempts += 1;
        throw gated;
      },
      async releaseAuthority() { authorityReleases += 1; },
    }),
    matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'),
  );
  assert.equal(persistenceAttempts, 1);
  assert.equal(authorityReleases, 1);

  await assert.rejects(
    persistOriginInstallationOrRequireManualCleanup({
      async persist() { throw gated; },
      async releaseAuthority() { throw new Error('storage unavailable'); },
    }),
    matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'),
  );

  let successReleaseCalls = 0;
  assert.equal(await persistOriginInstallationOrRequireManualCleanup({
    async persist() { return 'connected' as const; },
    async releaseAuthority() { successReleaseCalls += 1; },
  }), 'connected');
  assert.equal(successReleaseCalls, 0);
});

async function signedReceipt(
  privateKey: CryptoKey,
  headerOverride: Record<string, unknown> = {},
  claimsOverride: Record<string, unknown> = {},
): Promise<string> {
  const header = {
    alg: 'EdDSA',
    kid: ORIGIN_KEY_ID,
    typ: 'origin-installation-receipt+jwt',
    ...headerOverride,
  };
  const claims = {
    iss: ORIGIN_ISSUER,
    aud: APP_ID,
    sub: INSTALLATION_ID,
    namespace_id: NAMESPACE_ID,
    iat: NOW,
    exp: NOW + 300,
    jti: crypto.randomUUID(),
    installedBy: {id: 'user_01k2ja2000e0080000000000c3', email: 'installer@example.com', displayName: 'Ada Lovelace'},
    state: STATE,
    ...claimsOverride,
  };
  const headerSegment = base64URL(new TextEncoder().encode(JSON.stringify(header)));
  const payloadSegment = base64URL(new TextEncoder().encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign(
    {name: 'Ed25519'},
    privateKey,
    new TextEncoder().encode(`${headerSegment}.${payloadSegment}`),
  );
  return `${headerSegment}.${payloadSegment}.${base64URL(new Uint8Array(signature))}`;
}

function validDiscovery(): Record<string, unknown> {
  return {
    issuer: ORIGIN_ISSUER,
    jwks_uri: ORIGIN_KEYS_URL,
    response_types_supported: ['id_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['EdDSA'],
  };
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {headers: {'Content-Type': 'application/json'}});
}

function pemFromPKCS8(key: ArrayBuffer): string {
  const encoded = Buffer.from(key).toString('base64').match(/.{1,64}/g)?.join('\n');
  if (!encoded) throw new Error('Could not encode fixture private key.');
  return `-----BEGIN PRIVATE KEY-----\n${encoded}\n-----END PRIVATE KEY-----\n`;
}

function base64URL(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function base64URLDecode(value: string): ArrayBuffer {
  const bytes = new Uint8Array(Buffer.from(value, 'base64url'));
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

function decodeJSON(segment: string): unknown {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

function matchesCode(code: string): (error: unknown) => boolean {
  return error => error instanceof OriginAuthError && error.code === code;
}
