import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import {
  APPLE_CLIENT_SECRET_LIFETIME_SECONDS,
  APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
  AppleAuthError,
  type AppleAuthSessionRecord,
  encryptAppleStorageRecord,
  hashAppleSubject,
  parseAppleAuthConfiguration,
} from '../lib/apple-auth.ts';
import {
  type AppleNativeAuthDependencies,
  type AppleNativeAuthRepository,
  type AppleNativeGrantRecord,
  type AppleNativeSession,
  type AppleNativeSessionRecord,
  APPLE_NATIVE_GRANT_RETENTION_BATCH_LIMIT,
  APPLE_NATIVE_GRANT_RETENTION_MAX_BATCHES,
  APPLE_NATIVE_GRANT_RETENTION_OVERHEAD_SECONDS,
  APPLE_NATIVE_GRANT_RETENTION_WORST_CASE_SECONDS,
  APPLE_NATIVE_GRANT_RETENTION_WORKER_LIMIT_SECONDS,
  APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS,
  activateAppleNativeSession,
  exchangeAppleNativeIdentityToken,
  parseAppleNativeBearer,
  parseAppleNativeExchangeRequest,
  readAppleNativeSession,
  refreshAppleNativeSession,
  requireEmptyAppleNativeBody,
  revokeAppleNativeSession,
  drainExpiredAppleNativeGrants,
  decryptAppleNativeGrant,
} from '../lib/apple-native-auth.ts';
import { createD1AppleAuthRepository } from '../lib/apple-auth-d1.ts';
import { createD1AppleNativeAuthRepository } from '../lib/apple-native-auth-d1.ts';

const NOW = 1_800_000_000;
const WEB_CLIENT_ID = 'com.dezocode.local-sandbox.web';
const NATIVE_CLIENT_ID = 'com.dezocode.LocalSandbox';
const APPLE_KEY_ID = 'APPLEKEY01';
const RAW_NONCE = 'native_nonce_0123456789_ABCDEFGHIJK';
const APPLE_SUBJECT = '001234.native-fixture-user';
const AUTHORIZATION_CODE = 'native-authorization-code';

class MemoryNativeRepository implements AppleNativeAuthRepository {
  readonly links = new Map<string, string>();
  readonly principals = new Map<string, string>();
  readonly identitySessions = new Map<string, AppleNativeSessionRecord>();
  readonly sessionIndex = new Map<string, AppleNativeSessionRecord>();
  readonly grants = new Map<string, AppleNativeGrantRecord>();
  readonly revoked = new Set<string>();
  readonly authorizationCodeClaims = new Set<string>();
  readonly authorizationLeases = new Set<string>();
  readonly possibleAuthorizationLeases = new Set<string>();

  async resolveAppleOwner(input: {
    appleSubjectHash: string;
    transferSubjectHash?: string | null;
    proposedOwnerId: string;
    requiredOwnerId?: string | null;
    requiredPrincipalId?: string | null;
    now: number;
  }): Promise<{ownerId: string; principalId: string; created: boolean}> {
    const hashes = input.transferSubjectHash === undefined || input.transferSubjectHash === null ||
      input.transferSubjectHash === input.appleSubjectHash
      ? [input.appleSubjectHash]
      : [input.appleSubjectHash, input.transferSubjectHash];
    const owners = new Set(hashes.map(hash => this.links.get(hash)).filter(owner => owner !== undefined));
    if (owners.size > 1) {
      throw new AppleAuthError(
        409,
        'APPLE_IDENTITY_LINK_CONFLICT',
        'The Apple transfer identifiers resolve to different Local Sandbox accounts.',
      );
    }
    const existingOwnerId = owners.values().next().value ?? null;
    if (input.requiredOwnerId && existingOwnerId && input.requiredOwnerId !== existingOwnerId) {
      throw new AppleAuthError(
        409,
        'APPLE_IDENTITY_LINK_CONFLICT',
        'The Apple transfer identifiers resolve to different Local Sandbox accounts.',
      );
    }
    const existingPrincipalIds = [...new Set(
      hashes.map(hash => this.principals.get(hash)).filter(value => value !== undefined),
    )];
    if (
      input.requiredPrincipalId
      && !existingPrincipalIds.includes(input.requiredPrincipalId)
    ) {
      throw new AppleAuthError(
        409,
        'APPLE_IDENTITY_LINK_CONFLICT',
        'The Apple transfer principal changed during reauthorization.',
      );
    }
    const ownerId = input.requiredOwnerId ?? existingOwnerId ?? input.proposedOwnerId;
    const principalId = input.requiredPrincipalId
      ?? existingPrincipalIds[0]
      ?? input.transferSubjectHash
      ?? input.appleSubjectHash;
    for (const grant of this.grants.values()) {
      if (grant.ownerId === ownerId && existingPrincipalIds.includes(grant.principalId)) {
        grant.principalId = principalId;
      }
    }
    for (const hash of hashes) {
      this.links.set(hash, ownerId);
      this.principals.set(hash, principalId);
    }
    return {ownerId, principalId, created: owners.size === 0};
  }

  async readLinkedIdentity(appleSubjectHash: string) {
    const ownerId = this.links.get(appleSubjectHash);
    if (ownerId === undefined) return null;
    return {
      ownerId,
      principalId: this.principals.get(appleSubjectHash) ?? appleSubjectHash,
      principalCreatedAt: NOW,
    };
  }

  async claimAuthorizationCode(authorizationCodeHash: string): Promise<boolean> {
    if (this.authorizationCodeClaims.has(authorizationCodeHash)) return false;
    this.authorizationCodeClaims.add(authorizationCodeHash);
    return true;
  }

  async createSessionWithGrant(
    record: AppleNativeSessionRecord,
    grant: AppleNativeGrantRecord,
  ): Promise<boolean> {
    if (
      this.identitySessions.has(record.identityTokenHash)
      || [...this.grants.values()].some(value => value.authorizationCodeHash === grant.authorizationCodeHash)
    ) return false;
    if (this.sessionIndex.has(record.sessionHash) || this.grants.has(grant.grantHash)) {
      throw new Error('opaque hash collision');
    }
    this.identitySessions.set(record.identityTokenHash, structuredClone(record));
    this.sessionIndex.set(record.sessionHash, structuredClone(record));
    this.grants.set(grant.grantHash, structuredClone(grant));
    return true;
  }

  async createSession(record: AppleNativeSessionRecord): Promise<boolean> {
    if (this.identitySessions.has(record.identityTokenHash)) return false;
    if (this.sessionIndex.has(record.sessionHash)) throw new Error('session hash collision');
    this.identitySessions.set(record.identityTokenHash, structuredClone(record));
    this.sessionIndex.set(record.sessionHash, structuredClone(record));
    return true;
  }

  async activateSession(sessionHash: string, now: number): Promise<AppleNativeSession | null> {
    const record = this.sessionIndex.get(sessionHash);
    const grant = [...this.grants.values()].find(value => value.sessionHash === sessionHash);
    if (
      !record
      || !grant
      || record.expiresAt <= now
      || grant.expiresAt <= now
      || grant.revocationPendingAt !== null
      || this.revoked.has(sessionHash)
      || this.links.get(record.appleSubjectHash) !== record.ownerId
      || this.principals.get(record.appleSubjectHash) !== grant.principalId
    ) return null;
    record.activationState = 'active';
    this.identitySessions.set(record.identityTokenHash, structuredClone(record));
    return {
      schemaVersion: record.schemaVersion,
      ownerId: record.ownerId,
      appleSubjectHash: record.appleSubjectHash,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
    };
  }

  async readSession(sessionHash: string, now: number): Promise<AppleNativeSession | null> {
    const record = this.sessionIndex.get(sessionHash);
    if (
      !record
      || record.activationState !== 'active'
      || record.expiresAt <= now
      || this.revoked.has(sessionHash)
    ) return null;
    return {
      schemaVersion: record.schemaVersion,
      ownerId: record.ownerId,
      appleSubjectHash: record.appleSubjectHash,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
    };
  }

  async readSessionWithGrant(sessionHash: string, now: number) {
    const session = this.sessionIndex.get(sessionHash);
    const grant = [...this.grants.values()].find(value => value.sessionHash === sessionHash);
    if (
      !session
      || session.activationState !== 'active'
      || !grant
      || session.expiresAt <= now
      || grant.expiresAt <= now
      || this.revoked.has(sessionHash)
    ) return null;
    return {session: structuredClone(session), grant: structuredClone(grant)};
  }

  async updateSessionAndGrant(input: {
    sessionHash: string;
    ownerId: string;
    principalId: string;
    appleSubjectHash: string;
    expectedEncryptedCredentials: string;
    expectedLastValidatedAt: number;
    encryptedCredentials: string;
    lastValidatedAt: number;
    sessionExpiresAt: number;
    identityTokenExpiresAt: number;
    grantExpiresAt: number;
  }): Promise<boolean> {
    const session = this.sessionIndex.get(input.sessionHash);
    const grant = [...this.grants.values()].find(value => value.sessionHash === input.sessionHash);
    if (!session || session.activationState !== 'active' || !grant || this.revoked.has(input.sessionHash)
      || grant.revocationPendingAt !== null
      || grant.ownerId !== input.ownerId || grant.principalId !== input.principalId
      || grant.appleSubjectHash !== input.appleSubjectHash
      || grant.encryptedCredentials !== input.expectedEncryptedCredentials
      || grant.lastValidatedAt !== input.expectedLastValidatedAt) return false;
    session.expiresAt = input.sessionExpiresAt;
    session.identityTokenExpiresAt = input.identityTokenExpiresAt;
    grant.encryptedCredentials = input.encryptedCredentials;
    grant.lastValidatedAt = input.lastValidatedAt;
    grant.expiresAt = input.grantExpiresAt;
    grant.revocationPendingAt = null;
    return true;
  }

  async beginSessionRevocation(sessionHash: string) {
    const session = this.sessionIndex.get(sessionHash);
    if (!session) return {found: false, grant: null};
    this.revoked.add(sessionHash);
    const grant = [...this.grants.values()].find(value => value.sessionHash === sessionHash) ?? null;
    return {found: true, grant: grant === null ? null : structuredClone(grant)};
  }

  async revokeSession(sessionHash: string): Promise<boolean> {
    const record = this.sessionIndex.get(sessionHash);
    if (!record) return false;
    this.revoked.add(sessionHash);
    return true;
  }

  async markGrantRevocationPending(grantHash: string, now: number): Promise<void> {
    const grant = this.grants.get(grantHash);
    if (grant) grant.revocationPendingAt = now;
  }

  async deleteGrant(grantHash: string): Promise<boolean> {
    return this.grants.delete(grantHash);
  }

  async hasExpiredSessionGrant(eligibilityCutoff: number, claimTime: number): Promise<boolean> {
    return this.expiredSessionGrants(eligibilityCutoff, claimTime).length > 0;
  }

  async claimExpiredSessionGrants(
    eligibilityCutoff: number,
    claimedAt: number,
    limit: number,
  ): Promise<AppleNativeGrantRecord[]> {
    const selected = this.expiredSessionGrants(eligibilityCutoff, claimedAt).slice(0, limit);
    for (const grant of selected) {
      this.revoked.add(grant.sessionHash);
      grant.revocationPendingAt = claimedAt;
    }
    return selected.map(value => structuredClone(value));
  }

  async deleteClaimedExpiredGrant(grantHash: string, claimedAt: number): Promise<boolean> {
    const grant = this.grants.get(grantHash);
    if (
      grant === undefined
      || grant.revocationPendingAt !== claimedAt
      || !this.revoked.has(grant.sessionHash)
    ) return false;
    return this.grants.delete(grantHash);
  }

  private expiredSessionGrants(
    eligibilityCutoff: number,
    claimTime: number,
  ): AppleNativeGrantRecord[] {
    return [...this.grants.values()]
      .filter(grant => {
        const session = this.sessionIndex.get(grant.sessionHash);
        const retryable = grant.revocationPendingAt !== null
          && grant.revocationPendingAt + APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS <= claimTime;
        return (
          grant.expiresAt <= eligibilityCutoff
          || (session?.expiresAt ?? 0) <= eligibilityCutoff
          || this.revoked.has(grant.sessionHash)
        ) && (grant.revocationPendingAt === null || retryable);
      })
      .sort((left, right) => left.expiresAt - right.expiresAt
        || left.grantHash.localeCompare(right.grantHash));
  }

  async cleanupSessions(now: number, limit: number): Promise<number> {
    const expired = [...this.identitySessions.values()]
      .filter(record => record.expiresAt <= now && record.identityTokenExpiresAt <= now - 60
        && ![...this.grants.values()].some(grant => grant.sessionHash === record.sessionHash))
      .sort((left, right) => left.expiresAt - right.expiresAt)
      .slice(0, limit);
    for (const record of expired) {
      this.identitySessions.delete(record.identityTokenHash);
      this.sessionIndex.delete(record.sessionHash);
      this.revoked.delete(record.sessionHash);
    }
    return expired.length;
  }

  async claimAuthorizationExchangeLease(input: {
    leaseToken: string;
    ownerId: string;
  }): Promise<void> {
    this.authorizationLeases.add(`${input.ownerId}\0${input.leaseToken}`);
  }

  async completeAuthorizationExchangeLease(input: {
    leaseToken: string;
    ownerId: string;
  }): Promise<void> {
    this.authorizationLeases.delete(`${input.ownerId}\0${input.leaseToken}`);
    this.possibleAuthorizationLeases.delete(input.leaseToken);
  }

  async markAuthorizationExchangePossible(leaseToken: string): Promise<void> {
    if (![...this.authorizationLeases].some(value => value.endsWith(`\0${leaseToken}`))) {
      throw new Error('authorization lease missing');
    }
    this.possibleAuthorizationLeases.add(leaseToken);
  }

  async releaseAuthorizationExchangeLease(leaseToken: string): Promise<void> {
    for (const value of this.authorizationLeases) {
      if (value.endsWith(`\0${leaseToken}`)) this.authorizationLeases.delete(value);
    }
    this.possibleAuthorizationLeases.delete(leaseToken);
  }
}

type Fixture = {
  dependencies: AppleNativeAuthDependencies;
  repository: MemoryNativeRepository;
  setNow(value: number): void;
  setProviderClaims(overrides: Record<string, unknown> | null): void;
  signToken(overrides?: Record<string, unknown>): Promise<string>;
  linkSubject(ownerId: string): Promise<string>;
  providerRequests: Array<{url: string; values: URLSearchParams}>;
};

async function createFixture(): Promise<Fixture> {
  const clientKeys = await crypto.subtle.generateKey(
    {name: 'ECDSA', namedCurve: 'P-256'},
    true,
    ['sign', 'verify'],
  );
  const appleKeys = await crypto.subtle.generateKey(
    {name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'},
    true,
    ['sign', 'verify'],
  );
  const configuration = parseAppleAuthConfiguration({
    APPLE_AUTH_TEAM_ID: 'TEAMID0001',
    APPLE_AUTH_KEY_ID: APPLE_KEY_ID,
    APPLE_AUTH_CLIENT_ID: WEB_CLIENT_ID,
    APPLE_AUTH_NATIVE_CLIENT_ID: NATIVE_CLIENT_ID,
    APPLE_AUTH_REDIRECT_URI: 'https://sandbox.example.test/api/auth/apple/callback',
    APPLE_AUTH_PRIVATE_KEY_P8: pemFromPKCS8(await crypto.subtle.exportKey('pkcs8', clientKeys.privateKey)),
    APPLE_AUTH_STORAGE_KEY: base64URL(Uint8Array.from({length: 32}, (_, index) => index + 1)),
  });
  const applePublicKey = await crypto.subtle.exportKey('jwk', appleKeys.publicKey);
  const repository = new MemoryNativeRepository();
  let now = NOW;
  let lastClaims: Record<string, unknown> = {};
  let providerClaimsOverride: Record<string, unknown> | null = null;
  const providerRequests: Array<{url: string; values: URLSearchParams}> = [];
  const signClaims = async (claims: Record<string, unknown>): Promise<string> => {
    const header = base64URL(new TextEncoder().encode(JSON.stringify({alg: 'RS256', kid: APPLE_KEY_ID})));
    const payload = base64URL(new TextEncoder().encode(JSON.stringify(claims)));
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      appleKeys.privateKey,
      new TextEncoder().encode(`${header}.${payload}`),
    );
    return `${header}.${payload}.${base64URL(new Uint8Array(signature))}`;
  };
  const signToken = async (overrides: Record<string, unknown> = {}): Promise<string> => {
    lastClaims = {
      iss: 'https://appleid.apple.com',
      aud: NATIVE_CLIENT_ID,
      exp: now + 600,
      iat: now,
      sub: APPLE_SUBJECT,
      nonce: await sha256Base64URL(RAW_NONCE),
      email: 'native-relay@example.test',
      email_verified: true,
      ...overrides,
    };
    return signClaims(lastClaims);
  };
  const dependencies: AppleNativeAuthDependencies = {
    configuration,
    repository,
    fetcher: async (input, init) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (url.endsWith('/auth/keys')) {
        return Response.json({keys: [{...applePublicKey, alg: 'RS256', use: 'sig', kid: APPLE_KEY_ID}]});
      }
      const values = new URLSearchParams(String(init?.body ?? ''));
      providerRequests.push({url, values});
      if (url.endsWith('/auth/revoke')) return new Response(null, {status: 200});
      if (!url.endsWith('/auth/token')) return new Response(null, {status: 404});
      const exchangedClaims = {
        ...lastClaims,
        ...(providerClaimsOverride ?? {}),
      };
      if (values.get('grant_type') === 'refresh_token') {
        exchangedClaims.iat = now;
        exchangedClaims.exp = now + 600;
      }
      const exchangedIdentityToken = await signClaims(exchangedClaims);
      const response: Record<string, unknown> = {
        access_token: 'native-access-token',
        expires_in: 3_600,
        id_token: exchangedIdentityToken,
        token_type: 'Bearer',
      };
      if (values.get('grant_type') === 'authorization_code') {
        response.refresh_token = `native-refresh-${values.get('code') ?? 'missing'}`;
      }
      return Response.json(response);
    },
    crypto,
    now: () => now,
    revocationTimeoutMilliseconds: 50,
  };

  return {
    dependencies,
    repository,
    providerRequests,
    setNow(value) { now = value; },
    setProviderClaims(overrides) { providerClaimsOverride = overrides; },
    signToken,
    async linkSubject(ownerId) {
      const subjectHash = await hashAppleSubject(APPLE_SUBJECT, dependencies);
      repository.links.set(subjectHash, ownerId);
      repository.principals.set(subjectHash, subjectHash);
      return subjectHash;
    },
  };
}

async function activateIssued(
  dependencies: AppleNativeAuthDependencies,
  token: string,
) {
  const activated = await activateAppleNativeSession(dependencies, token);
  assert.ok(activated);
  return activated;
}

test('native exchange issues one bounded pending session without storing Apple or bearer secrets', async () => {
  const fixture = await createFixture();
  const subjectHash = await fixture.linkSubject('host-owner-a');
  const identityToken = await fixture.signToken();
  const result = await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken,
    authorizationCode: AUTHORIZATION_CODE,
    rawNonce: RAW_NONCE,
  });
  assert.deepEqual(result, {
    schemaVersion: 2,
    activationState: 'pending',
    tokenType: 'Bearer',
    token: result.token,
    expiresAt: NOW + 900,
    accountMode: 'linked',
  });
  assert.match(result.token, /^v1\.[A-Za-z0-9_-]{43}$/);
  assert.equal(fixture.repository.identitySessions.size, 1);
  assert.equal(
    fixture.providerRequests.filter(request => request.url.endsWith('/auth/token')).length,
    1,
  );
  const tokenRequest = fixture.providerRequests.find(request => request.url.endsWith('/auth/token'));
  assert.equal(tokenRequest?.values.get('client_id'), NATIVE_CLIENT_ID);
  assert.equal(tokenRequest?.values.get('grant_type'), 'authorization_code');
  assert.equal(tokenRequest?.values.get('code'), AUTHORIZATION_CODE);
  assert.equal(tokenRequest?.values.has('redirect_uri'), false);
  assert.equal(decodeJWTPayload(tokenRequest?.values.get('client_secret') ?? '').sub, NATIVE_CLIENT_ID);
  const stored = JSON.stringify([...fixture.repository.identitySessions.values()]);
  for (const secret of [identityToken, result.token, APPLE_SUBJECT, 'native-relay@example.test']) {
    assert.equal(stored.includes(secret), false, secret);
  }
  assert.equal(fixture.repository.identitySessions.values().next().value?.activationState, 'pending');
  assert.equal(await readAppleNativeSession(
    fixture.repository,
    result.token,
    NOW + 1,
    crypto,
  ), null);
  assert.equal(await refreshAppleNativeSession(fixture.dependencies, result.token), null);
  const activated = await activateIssued(fixture.dependencies, result.token);
  assert.deepEqual(activated, {
    schemaVersion: 2,
    activationState: 'active',
    tokenType: 'Bearer',
    token: result.token,
    expiresAt: NOW + 900,
    accountMode: 'linked',
  });
  assert.deepEqual(await activateAppleNativeSession(fixture.dependencies, result.token), activated);
  const session = await readAppleNativeSession(fixture.repository, result.token, NOW + 1, crypto);
  assert.equal(session?.ownerId, 'host-owner-a');
  assert.equal(session?.appleSubjectHash, subjectHash);
  const grants = [...fixture.repository.grants.values()];
  assert.equal(grants.length, 1);
  const persistedGrant = JSON.stringify(grants);
  for (const secret of [
    AUTHORIZATION_CODE,
    `native-refresh-${AUTHORIZATION_CODE}`,
    APPLE_SUBJECT,
    result.token,
  ]) assert.equal(persistedGrant.includes(secret), false, secret);
  const decrypted = await decryptAppleNativeGrant(grants[0], fixture.dependencies);
  assert.equal(decrypted.refreshToken, `native-refresh-${AUTHORIZATION_CODE}`);
  assert.equal(decrypted.subject, APPLE_SUBJECT);
  const regrouped = await decryptAppleNativeGrant(
    {...grants[0], principalId: 'p'.repeat(43)},
    fixture.dependencies,
  );
  assert.equal(regrouped.refreshToken, decrypted.refreshToken);
});

test('native identity-token replay has exactly one winner under concurrency', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  const identityToken = await fixture.signToken();
  const results = await Promise.allSettled([
    exchangeAppleNativeIdentityToken(fixture.dependencies, {identityToken, authorizationCode: AUTHORIZATION_CODE, rawNonce: RAW_NONCE}),
    exchangeAppleNativeIdentityToken(fixture.dependencies, {identityToken, authorizationCode: AUTHORIZATION_CODE, rawNonce: RAW_NONCE}),
  ]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const rejected = results.find(result => result.status === 'rejected');
  assert.ok(rejected && rejected.status === 'rejected');
  assert.equal(matchesCode('APPLE_NATIVE_CREDENTIAL_REPLAY')(rejected.reason), true);
  assert.equal(fixture.repository.identitySessions.size, 1);
  assert.equal(
    fixture.providerRequests.filter(request => request.url.endsWith('/auth/token')).length,
    1,
  );
});

test('native replay rejects a distinct non-canonical token spelling with the same signature bytes', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  const identityToken = await fixture.signToken();
  const segments = identityToken.split('.');
  const signatureAlias = nonCanonicalBase64URLAlias(segments[2]);
  const textualAlias = `${segments[0]}.${segments[1]}.${signatureAlias}`;
  assert.notEqual(textualAlias, identityToken);
  assert.deepEqual(base64URLBytes(signatureAlias), base64URLBytes(segments[2]));

  await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken,
    authorizationCode: AUTHORIZATION_CODE,
    rawNonce: RAW_NONCE,
  });
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {
      identityToken: textualAlias,
      authorizationCode: `${AUTHORIZATION_CODE}-alias`,
      rawNonce: RAW_NONCE,
    }),
    matchesCode('APPLE_ID_TOKEN_INVALID'),
  );
  assert.equal(fixture.repository.identitySessions.size, 1);
});

test('first native exchange creates and reuses a random Apple-owned workspace', async () => {
  const fixture = await createFixture();
  const first = await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken({jti: 'first-native-owner-token'}),
    authorizationCode: `${AUTHORIZATION_CODE}-first`,
    rawNonce: RAW_NONCE,
  });
  await activateIssued(fixture.dependencies, first.token);
  const firstSession = await readAppleNativeSession(fixture.repository, first.token, NOW, crypto);
  assert.match(firstSession?.ownerId ?? '', /^apple-owner:v1\.[A-Za-z0-9_-]{43}$/);
  const second = await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken({jti: 'second-native-owner-token'}),
    authorizationCode: `${AUTHORIZATION_CODE}-second`,
    rawNonce: RAW_NONCE,
  });
  await activateIssued(fixture.dependencies, second.token);
  const secondSession = await readAppleNativeSession(fixture.repository, second.token, NOW, crypto);
  assert.equal(secondSession?.ownerId, firstSession?.ownerId);
  assert.equal(fixture.repository.links.size, 1);
});

test('native exchange uses a verified transfer_sub mapping for owner continuity', async () => {
  const fixture = await createFixture();
  const transferSubject = 'native-transfer-subject';
  const transferSubjectHash = await hashAppleSubject(transferSubject, fixture.dependencies);
  fixture.repository.links.set(transferSubjectHash, 'imported-native-owner');
  const result = await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken({
      sub: 'recipient-native-subject',
      transfer_sub: transferSubject,
    }),
    authorizationCode: `${AUTHORIZATION_CODE}-transfer`,
    rawNonce: RAW_NONCE,
  });
  await activateIssued(fixture.dependencies, result.token);
  const session = await readAppleNativeSession(fixture.repository, result.token, NOW, crypto);
  assert.equal(session?.ownerId, 'imported-native-owner');
  assert.equal(
    fixture.repository.links.get(
      await hashAppleSubject('recipient-native-subject', fixture.dependencies),
    ),
    'imported-native-owner',
  );
});

test('transferred recovery requires the exact old linked user and preserves one principal', async () => {
  const fixture = await createFixture();
  const oldUser = 'old-native-transfer-user';
  const oldHash = await hashAppleSubject(oldUser, fixture.dependencies);
  fixture.repository.links.set(oldHash, 'transfer-owner');
  fixture.repository.principals.set(oldHash, oldHash);
  const identityToken = await fixture.signToken({
    sub: 'new-native-transfer-user',
    transfer_sub: oldUser,
  });
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {
      identityToken,
      authorizationCode: `${AUTHORIZATION_CODE}-wrong-old`,
      rawNonce: RAW_NONCE,
      transferRecoveryUser: 'different-old-user',
    }),
    matchesCode('APPLE_NATIVE_TRANSFER_RECOVERY_INVALID'),
  );
  assert.equal(fixture.providerRequests.length, 0);

  const result = await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken,
    authorizationCode: `${AUTHORIZATION_CODE}-exact-old`,
    rawNonce: RAW_NONCE,
    transferRecoveryUser: oldUser,
  });
  await activateIssued(fixture.dependencies, result.token);
  const session = await readAppleNativeSession(fixture.repository, result.token, NOW, crypto);
  assert.equal(session?.ownerId, 'transfer-owner');
  const newHash = await hashAppleSubject('new-native-transfer-user', fixture.dependencies);
  assert.equal(fixture.repository.links.get(newHash), 'transfer-owner');
  assert.equal(fixture.repository.principals.get(newHash), oldHash);
});

test('native code exchange rejects exchanged audience, subject, and transfer mismatches and revokes the fresh grant', async () => {
  for (const [suffix, override, code] of [
    ['audience', {aud: WEB_CLIENT_ID}, 'APPLE_ID_TOKEN_CLAIMS'],
    ['subject', {sub: 'different-native-user'}, 'APPLE_TOKEN_SUBJECT_MISMATCH'],
    ['transfer', {transfer_sub: 'different-transfer-user'}, 'APPLE_TOKEN_TRANSFER_MISMATCH'],
  ] as const) {
    const fixture = await createFixture();
    await fixture.linkSubject('host-owner-a');
    const identityToken = await fixture.signToken({transfer_sub: suffix === 'transfer' ? 'expected-transfer-user' : undefined});
    fixture.setProviderClaims(override);
    await assert.rejects(
      () => exchangeAppleNativeIdentityToken(fixture.dependencies, {
        identityToken,
        authorizationCode: `${AUTHORIZATION_CODE}-${suffix}`,
        rawNonce: RAW_NONCE,
      }),
      matchesCode(code),
    );
    assert.equal(fixture.repository.grants.size, 0);
    const revocation = fixture.providerRequests.find(request => request.url.endsWith('/auth/revoke'));
    assert.equal(revocation?.values.get('token'), `native-refresh-${AUTHORIZATION_CODE}-${suffix}`);
    assert.equal(revocation?.values.get('client_id'), NATIVE_CLIENT_ID);
  }
});

test('post-exchange persistence failure revokes the fresh Apple grant without exposing it', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  fixture.repository.createSessionWithGrant = async () => false;
  const identityToken = await fixture.signToken();
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {
      identityToken,
      authorizationCode: `${AUTHORIZATION_CODE}-persistence-failure`,
      rawNonce: RAW_NONCE,
    }),
    matchesCode('APPLE_NATIVE_CREDENTIAL_REPLAY'),
  );
  assert.equal(fixture.repository.grants.size, 0);
  const revocation = fixture.providerRequests.find(request => request.url.endsWith('/auth/revoke'));
  assert.equal(
    revocation?.values.get('token'),
    `native-refresh-${AUTHORIZATION_CODE}-persistence-failure`,
  );
  assert.equal(fixture.repository.possibleAuthorizationLeases.size, 0);
});

test('native provider exchange requires durable possible-credential state first', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  fixture.repository.markAuthorizationExchangePossible = async () => {
    throw new AppleAuthError(503, 'APPLE_AUTH_CREDENTIAL_MARKER_UNAVAILABLE', 'marker unavailable');
  };
  await assert.rejects(exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken({jti: 'native-marker-readback'}),
    authorizationCode: `${AUTHORIZATION_CODE}-marker-readback`,
    rawNonce: RAW_NONCE,
  }), matchesCode('APPLE_AUTH_CREDENTIAL_MARKER_UNAVAILABLE'));
  assert.equal(
    fixture.providerRequests.filter(request => request.url.endsWith('/auth/token')).length,
    0,
  );
});

test('ambiguous native exchange and failed compensation retain possible-credential state', async () => {
  const exchangeFixture = await createFixture();
  await exchangeFixture.linkSubject('host-owner-a');
  const healthyExchangeFetcher = exchangeFixture.dependencies.fetcher;
  exchangeFixture.dependencies.fetcher = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.endsWith('/auth/token')) return new Response(null, {status: 503});
    return healthyExchangeFetcher(input, init);
  };
  await assert.rejects(exchangeAppleNativeIdentityToken(exchangeFixture.dependencies, {
    identityToken: await exchangeFixture.signToken({jti: 'native-token-503'}),
    authorizationCode: `${AUTHORIZATION_CODE}-token-503`,
    rawNonce: RAW_NONCE,
  }), matchesCode('APPLE_CODE_REJECTED'));
  assert.equal(exchangeFixture.repository.possibleAuthorizationLeases.size, 1);

  const persistenceFixture = await createFixture();
  await persistenceFixture.linkSubject('host-owner-a');
  persistenceFixture.repository.createSessionWithGrant = async () => false;
  const healthyPersistenceFetcher = persistenceFixture.dependencies.fetcher;
  let failedRevocationAttempts = 0;
  persistenceFixture.dependencies.fetcher = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.endsWith('/auth/revoke')) {
      failedRevocationAttempts += 1;
      return new Response(null, {status: 503});
    }
    return healthyPersistenceFetcher(input, init);
  };
  await assert.rejects(exchangeAppleNativeIdentityToken(persistenceFixture.dependencies, {
    identityToken: await persistenceFixture.signToken({jti: 'native-storage-and-revoke-failure'}),
    authorizationCode: `${AUTHORIZATION_CODE}-storage-and-revoke-failure`,
    rawNonce: RAW_NONCE,
  }), matchesCode('APPLE_NATIVE_CREDENTIAL_REPLAY'));
  assert.equal(failedRevocationAttempts, 1);
  assert.equal(persistenceFixture.repository.possibleAuthorizationLeases.size, 1);
});

test('a known Apple 400 clears only the current native exchange marker', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  const healthyFetcher = fixture.dependencies.fetcher;
  fixture.dependencies.fetcher = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.endsWith('/auth/token')) {
      return Response.json({error: 'invalid_grant'}, {status: 400});
    }
    return healthyFetcher(input, init);
  };
  await assert.rejects(exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken({jti: 'native-definitive-no-token'}),
    authorizationCode: `${AUTHORIZATION_CODE}-definitive-no-token`,
    rawNonce: RAW_NONCE,
  }), matchesCode('APPLE_CODE_REJECTED'));
  assert.equal(fixture.repository.possibleAuthorizationLeases.size, 0);
  assert.equal(fixture.repository.authorizationLeases.size, 0);
});

test('native refresh revalidates server-held grant and extends only the same opaque bearer', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  const issued = await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken(),
    authorizationCode: `${AUTHORIZATION_CODE}-refresh`,
    rawNonce: RAW_NONCE,
  });
  await activateIssued(fixture.dependencies, issued.token);
  const before = structuredClone([...fixture.repository.grants.values()][0]);
  fixture.setNow(NOW + 700);
  const refreshed = await refreshAppleNativeSession(fixture.dependencies, issued.token);
  assert.equal(refreshed?.token, issued.token);
  assert.equal(refreshed?.expiresAt, NOW + 1_600);
  assert.equal('refreshToken' in (refreshed ?? {}), false);
  const refreshRequest = fixture.providerRequests.find(
    request => request.values.get('grant_type') === 'refresh_token',
  );
  assert.equal(refreshRequest?.values.get('refresh_token'), `native-refresh-${AUTHORIZATION_CODE}-refresh`);
  assert.equal(refreshRequest?.values.get('client_id'), NATIVE_CLIENT_ID);
  assert.equal(refreshRequest?.values.has('redirect_uri'), false);
  const after = [...fixture.repository.grants.values()][0];
  assert.notEqual(after.encryptedCredentials, before.encryptedCredentials);
  assert.equal(after.lastValidatedAt, NOW + 700);
});

test('native refresh final joined read suppresses success after post-CAS revocation', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  const issued = await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken({jti: 'native-post-cas-fence'}),
    authorizationCode: `${AUTHORIZATION_CODE}-post-cas-fence`,
    rawNonce: RAW_NONCE,
  });
  await activateIssued(fixture.dependencies, issued.token);
  fixture.setNow(NOW + 700);
  const sessionHash = [...fixture.repository.sessionIndex.keys()][0]!;
  const update = fixture.repository.updateSessionAndGrant.bind(fixture.repository);
  let signalUpdated!: () => void;
  let releaseUpdated!: () => void;
  const updated = new Promise<void>(resolve => {signalUpdated = resolve;});
  const released = new Promise<void>(resolve => {releaseUpdated = resolve;});
  fixture.repository.updateSessionAndGrant = async input => {
    const result = await update(input);
    signalUpdated();
    await released;
    return result;
  };
  const refresh = refreshAppleNativeSession(fixture.dependencies, issued.token);
  await updated;
  assert.equal(await fixture.repository.revokeSession(sessionHash), true);
  releaseUpdated();
  await assert.rejects(refresh, matchesCode('APPLE_NATIVE_SESSION_CHANGED'));
});

test('native Apple verification rejects nonce, issuer, audience, signature, expiry, and invalid issue time', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  const wrongNonce = await fixture.signToken({nonce: await sha256Base64URL('other_nonce_0123456789_ABCDEFGHIJK')});
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {identityToken: wrongNonce, authorizationCode: `${AUTHORIZATION_CODE}-nonce`, rawNonce: RAW_NONCE}),
    matchesCode('APPLE_ID_TOKEN_NONCE'),
  );
  const wrongAudience = await fixture.signToken({aud: 'com.attacker.App'});
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {identityToken: wrongAudience, authorizationCode: `${AUTHORIZATION_CODE}-audience`, rawNonce: RAW_NONCE}),
    matchesCode('APPLE_ID_TOKEN_CLAIMS'),
  );
  const wrongIssuer = await fixture.signToken({iss: 'https://attacker.example'});
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {identityToken: wrongIssuer, authorizationCode: `${AUTHORIZATION_CODE}-issuer`, rawNonce: RAW_NONCE}),
    matchesCode('APPLE_ID_TOKEN_INVALID'),
  );
  const expired = await fixture.signToken({exp: NOW});
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {identityToken: expired, authorizationCode: `${AUTHORIZATION_CODE}-expired`, rawNonce: RAW_NONCE}),
    matchesCode('APPLE_ID_TOKEN_CLAIMS'),
  );
  const stale = await fixture.signToken({iat: NOW - 601});
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {identityToken: stale, authorizationCode: `${AUTHORIZATION_CODE}-stale`, rawNonce: RAW_NONCE}),
    matchesCode('APPLE_ID_TOKEN_CLAIMS'),
  );
  const future = await fixture.signToken({iat: NOW + 61});
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {identityToken: future, authorizationCode: `${AUTHORIZATION_CODE}-future`, rawNonce: RAW_NONCE}),
    matchesCode('APPLE_ID_TOKEN_CLAIMS'),
  );
  const signed = await fixture.signToken();
  const segments = signed.split('.');
  const first = segments[2][0] === 'A' ? 'B' : 'A';
  const tampered = `${segments[0]}.${segments[1]}.${first}${segments[2].slice(1)}`;
  await assert.rejects(
    () => exchangeAppleNativeIdentityToken(fixture.dependencies, {identityToken: tampered, authorizationCode: `${AUTHORIZATION_CODE}-tampered`, rawNonce: RAW_NONCE}),
    matchesCode('APPLE_ID_TOKEN_SIGNATURE'),
  );
  assert.equal(fixture.repository.identitySessions.size, 0);
});

test('native exchange parser is strict, bounded, and independent of ambient browser auth', async () => {
  const validBody = JSON.stringify({identityToken: 'x'.repeat(20), authorizationCode: AUTHORIZATION_CODE, rawNonce: RAW_NONCE});
  const parsed = await parseAppleNativeExchangeRequest(new Request(
    'https://sandbox.example.test/api/auth/apple/native/exchange',
    {method: 'POST', headers: {'Content-Type': 'application/json'}, body: validBody},
  ));
  assert.equal(parsed.rawNonce, RAW_NONCE);
  await assert.rejects(
    () => parseAppleNativeExchangeRequest(new Request(
      'https://sandbox.example.test/api/auth/apple/native/exchange',
      {method: 'POST', headers: {'Content-Type': 'application/json', Cookie: 'host=session'}, body: validBody},
    )),
    matchesCode('APPLE_NATIVE_AMBIENT_AUTH'),
  );
  await assert.rejects(
    () => parseAppleNativeExchangeRequest(new Request(
      'https://sandbox.example.test/api/auth/apple/native/exchange',
      {method: 'POST', headers: {'Content-Type': 'application/json', 'Content-Length': '20001'}, body: validBody},
    )),
    matchesCode('APPLE_NATIVE_REQUEST_TOO_LARGE'),
  );
  await assert.rejects(
    () => parseAppleNativeExchangeRequest(new Request(
      'https://sandbox.example.test/api/auth/apple/native/exchange',
      {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({identityToken: 'x'.repeat(20), authorizationCode: AUTHORIZATION_CODE, rawNonce: RAW_NONCE, ownerId: 'forged'})},
    )),
    matchesCode('APPLE_NATIVE_REQUEST_INVALID'),
  );
  for (const authorizationCode of [undefined, '', 'x'.repeat(8_001)]) {
    await assert.rejects(
      () => parseAppleNativeExchangeRequest(new Request(
        'https://sandbox.example.test/api/auth/apple/native/exchange',
        {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({identityToken: 'x'.repeat(20), authorizationCode, rawNonce: RAW_NONCE}),
        },
      )),
      matchesCode('APPLE_NATIVE_REQUEST_INVALID'),
    );
  }
});

test('native grant retention fits the provider-secret, claim-lease, and Worker budgets', () => {
  assert.equal(
    APPLE_NATIVE_GRANT_RETENTION_BATCH_LIMIT * APPLE_NATIVE_GRANT_RETENTION_MAX_BATCHES,
    20,
  );
  assert.equal(
    APPLE_NATIVE_GRANT_RETENTION_WORST_CASE_SECONDS,
    Math.ceil(
      APPLE_NATIVE_GRANT_RETENTION_BATCH_LIMIT
        * APPLE_NATIVE_GRANT_RETENTION_MAX_BATCHES
        * APPLE_REVOCATION_TIMEOUT_MILLISECONDS / 1_000,
    ) + APPLE_NATIVE_GRANT_RETENTION_OVERHEAD_SECONDS,
  );
  assert.ok(
    APPLE_NATIVE_GRANT_RETENTION_WORST_CASE_SECONDS
      < APPLE_CLIENT_SECRET_LIFETIME_SECONDS,
  );
  assert.ok(
    APPLE_NATIVE_GRANT_RETENTION_WORST_CASE_SECONDS
      < APPLE_NATIVE_GRANT_RETENTION_WORKER_LIMIT_SECONDS,
  );
  assert.ok(
    APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS
      > APPLE_NATIVE_GRANT_RETENTION_WORST_CASE_SECONDS,
  );
});

test('scheduled native retention uses its cutoff only for selection and a fresh signing clock', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken({jti: 'delayed-scheduled-retention'}),
    authorizationCode: `${AUTHORIZATION_CODE}-delayed-scheduled-retention`,
    rawNonce: RAW_NONCE,
  });
  const scheduledCutoff = NOW + 901;
  const currentWallTime = NOW + 1_801;
  fixture.setNow(currentWallTime);
  const providerFetcher = fixture.dependencies.fetcher;
  let clientSecretIssuedAt: number | null = null;
  fixture.dependencies.fetcher = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.endsWith('/auth/revoke')) {
      const values = new URLSearchParams(String(init?.body ?? ''));
      clientSecretIssuedAt = z.number().int().parse(
        decodeJWTPayload(values.get('client_secret') ?? '').iat,
      );
    }
    return providerFetcher(input, init);
  };
  assert.deepEqual(await drainExpiredAppleNativeGrants(fixture.dependencies, {
    batchLimit: 1,
    maximumBatches: 1,
    cutoff: scheduledCutoff,
  }), {batches: 1, found: 1, revoked: 1, failed: 0, backlog: false});
  assert.equal(clientSecretIssuedAt, currentWallTime);
});

test('native grant retention drains bounded batches and reports a post-limit backlog', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  for (let index = 0; index < 5; index += 1) {
    await exchangeAppleNativeIdentityToken(fixture.dependencies, {
      identityToken: await fixture.signToken({jti: `retention-${index}`}),
      authorizationCode: `${AUTHORIZATION_CODE}-retention-${index}`,
      rawNonce: RAW_NONCE,
    });
  }
  fixture.setNow(NOW + 901);
  assert.deepEqual(
    await drainExpiredAppleNativeGrants(fixture.dependencies, {batchLimit: 2, maximumBatches: 2}),
    {batches: 2, found: 4, revoked: 4, failed: 0, backlog: true},
  );
  assert.equal(fixture.repository.grants.size, 1);
  assert.deepEqual(
    await drainExpiredAppleNativeGrants(fixture.dependencies, {batchLimit: 2, maximumBatches: 2}),
    {batches: 1, found: 1, revoked: 1, failed: 0, backlog: false},
  );
  assert.equal(fixture.repository.grants.size, 0);

  for (let index = 0; index < 5; index += 1) {
    await exchangeAppleNativeIdentityToken(fixture.dependencies, {
      identityToken: await fixture.signToken({jti: `poison-retention-${index}`}),
      authorizationCode: `${AUTHORIZATION_CODE}-poison-${index}`,
      rawNonce: RAW_NONCE,
    });
  }
  fixture.setNow(NOW + 1_802);
  let movingProviderClock = NOW + 1_802;
  fixture.dependencies.now = () => movingProviderClock++;
  const healthyFetcher = fixture.dependencies.fetcher;
  fixture.dependencies.fetcher = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    const values = new URLSearchParams(String(init?.body ?? ''));
    if (
      url.endsWith('/auth/revoke')
      && values.get('token') === `native-refresh-${AUTHORIZATION_CODE}-poison-0`
    ) return new Response(null, {status: 503});
    return healthyFetcher(input, init);
  };
  assert.deepEqual(
    await drainExpiredAppleNativeGrants(fixture.dependencies, {batchLimit: 2, maximumBatches: 3}),
    {batches: 3, found: 5, revoked: 4, failed: 1, backlog: false},
  );
  assert.equal(fixture.repository.grants.size, 1);
  fixture.dependencies.now = () => NOW + 1_802;
  assert.deepEqual(
    await drainExpiredAppleNativeGrants(fixture.dependencies, {batchLimit: 2, maximumBatches: 3}),
    {batches: 1, found: 0, revoked: 0, failed: 0, backlog: false},
  );
  fixture.dependencies.fetcher = healthyFetcher;
  const pendingClaimedAt = [...fixture.repository.grants.values()][0]?.revocationPendingAt;
  assert.equal(typeof pendingClaimedAt, 'number');
  fixture.dependencies.now = () => (pendingClaimedAt as number)
    + APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS;
  assert.deepEqual(
    await drainExpiredAppleNativeGrants(fixture.dependencies, {batchLimit: 2, maximumBatches: 3}),
    {batches: 1, found: 1, revoked: 1, failed: 0, backlog: false},
  );
  assert.equal(fixture.repository.grants.size, 0);
  await assert.rejects(
    drainExpiredAppleNativeGrants(fixture.dependencies, {maximumBatches: 0}),
    /positive maximum batch count/,
  );
  await assert.rejects(
    drainExpiredAppleNativeGrants(fixture.dependencies, {
      batchLimit: 10_000,
      maximumBatches: 10_000,
    }),
    /exceeds its provider or lease budget/,
  );
});

test('native bearer operations require an exact bearer and empty body', async () => {
  const token = `v1.${'A'.repeat(43)}`;
  assert.equal(parseAppleNativeBearer(new Request(
    'https://sandbox.example.test/api/auth/apple/native/activate',
    {headers: {Authorization: `Bearer ${token}`}},
  )), token);
  for (const authorization of [
    `Basic ${token}`,
    `Bearer ${token}.extra`,
    `Bearer v2.${'A'.repeat(43)}`,
  ]) {
    assert.throws(() => parseAppleNativeBearer(new Request(
      'https://sandbox.example.test/api/auth/apple/native/activate',
      {headers: {Authorization: authorization}},
    )), matchesCode('APPLE_NATIVE_SESSION_INVALID'));
  }
  await requireEmptyAppleNativeBody(new Request('https://sandbox.example.test/revoke', {method: 'POST'}));
  await requireEmptyAppleNativeBody(new Request('https://sandbox.example.test/revoke', {method: 'POST', headers: {'Content-Length': '0'}}));
  for (const value of ['-1', 'nope', '00', '1']) {
    await assert.rejects(
      () => requireEmptyAppleNativeBody(new Request('https://sandbox.example.test/revoke', {method: 'POST', headers: {'Content-Length': value}})),
      matchesCode('APPLE_NATIVE_REQUEST_INVALID'),
    );
  }
  const route = await readFile(
    new URL('../app/api/auth/apple/native/activate/route.ts', import.meta.url),
    'utf8',
  );
  const cookieCheck = route.indexOf("request.headers.has('cookie')");
  const emptyBodyCheck = route.indexOf('requireEmptyAppleNativeBody(request)');
  const bearerCheck = route.indexOf('parseAppleNativeBearer(request)');
  const activation = route.indexOf('activateAppleNativeSession(');
  assert.ok(
    cookieCheck >= 0
      && emptyBodyCheck > cookieCheck
      && bearerCheck > emptyBodyCheck
      && activation > bearerCheck,
  );
  assert.doesNotMatch(route, /request\.(?:json|text)\(/);
});

test('native session revocation is idempotent until expiry and cleanup is bounded', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  const result = await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken(),
    authorizationCode: `${AUTHORIZATION_CODE}-revoke`,
    rawNonce: RAW_NONCE,
  });
  fixture.setNow(NOW + 1);
  assert.equal(await revokeAppleNativeSession(fixture.dependencies, result.token), true);
  fixture.setNow(NOW + 2);
  assert.equal(await revokeAppleNativeSession(fixture.dependencies, result.token), true);
  assert.equal(await readAppleNativeSession(fixture.repository, result.token, NOW + 2, crypto), null);
  fixture.setNow(NOW + 1_000);
  assert.equal(await revokeAppleNativeSession(fixture.dependencies, result.token), true);
  assert.equal(fixture.repository.identitySessions.size, 0);
  assert.equal(await revokeAppleNativeSession(fixture.dependencies, result.token), false);
});

test('an exact expired bearer disables its durable grant and preserves explicit outage follow-up', async () => {
  const fixture = await createFixture();
  await fixture.linkSubject('host-owner-a');
  const issued = await exchangeAppleNativeIdentityToken(fixture.dependencies, {
    identityToken: await fixture.signToken(),
    authorizationCode: `${AUTHORIZATION_CODE}-expired-revoke`,
    rawNonce: RAW_NONCE,
  });
  fixture.setNow(NOW + 901);
  const originalFetcher = fixture.dependencies.fetcher;
  fixture.dependencies.fetcher = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.endsWith('/auth/revoke')) throw new TypeError('Apple offline');
    return originalFetcher(input, init);
  };
  await assert.rejects(
    () => revokeAppleNativeSession(fixture.dependencies, issued.token),
    matchesCode('APPLE_REVOCATION_UNAVAILABLE'),
  );
  assert.equal(fixture.repository.grants.size, 1);
  assert.equal([...fixture.repository.grants.values()][0].revocationPendingAt, NOW + 901);
  assert.equal(await readAppleNativeSession(fixture.repository, issued.token, NOW + 901, crypto), null);

  fixture.dependencies.fetcher = originalFetcher;
  assert.equal(await revokeAppleNativeSession(fixture.dependencies, issued.token), true);
  assert.equal(fixture.repository.grants.size, 0);
  assert.equal(await revokeAppleNativeSession(fixture.dependencies, issued.token), false);
});

test('D1 enforces activation, replay, identity, deletion, expiry, revocation, and cleanup', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    for (const name of [
      '0000_dashing_epoch.sql',
      '0001_eager_sheva_callister.sql',
      '0002_shallow_sabra.sql',
      '0003_wet_edwin_jarvis.sql',
    ]) {
      const baseMigration = await readFile(`drizzle/${name}`, 'utf8');
      for (const statement of baseMigration
        .split('--> statement-breakpoint')
        .map(value => value.trim())
        .filter(Boolean)) await database.prepare(statement).run();
    }
    const migration = await readFile('drizzle/0004_native_apple_bridge.sql', 'utf8');
    const statements = migration.split('--> statement-breakpoint').map(value => value.trim()).filter(Boolean);
    for (const statement of statements) await database.prepare(statement).run();
    for (const statement of statements) await database.prepare(statement).run();
    for (const name of [
      '0005_sync_snapshot_revision.sql',
      '0006_dear_luckman.sql',
      '0007_puzzling_tempest.sql',
      '0008_long_fat_cobra.sql',
      '0009_apple_identity_principals.sql',
      '0010_native_apple_grants.sql',
      '0011_durable_deletion_subjects.sql',
      '0012_owner_external_operation_leases.sql',
      '0013_general_external_operation_leases.sql',
    ]) {
      const lifecycleMigration = await readFile(`drizzle/${name}`, 'utf8');
      for (const statement of lifecycleMigration
        .split('--> statement-breakpoint')
        .map(value => value.trim())
        .filter(Boolean)) await database.prepare(statement).run();
    }
    const legacyIdentityTokenHash = 'L'.repeat(43);
    const legacySessionHash = 'l'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_native_sessions(
        schema_version,identity_token_hash,session_hash,owner_id,apple_subject_hash,
        created_at,expires_at,identity_token_expires_at,revoked_at
      ) VALUES(1,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      legacyIdentityTokenHash,
      legacySessionHash,
      'legacy-owner',
      'l'.repeat(43),
      NOW,
      NOW + 900,
      NOW + 600,
    ).run();
    const activationMigration = await readFile(
      'drizzle/0014_native_apple_session_activation.sql',
      'utf8',
    );
    for (const statement of activationMigration
      .split('--> statement-breakpoint')
      .map(value => value.trim())
      .filter(Boolean)) await database.prepare(statement).run();
    assert.equal(await database.prepare(
      'SELECT activation_state FROM apple_native_sessions WHERE session_hash=?',
    ).bind(legacySessionHash).first('activation_state'), 'active');
    const defaultPendingIdentityTokenHash = 'P'.repeat(43);
    const defaultPendingSessionHash = 'p'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_native_sessions(
        schema_version,identity_token_hash,session_hash,owner_id,apple_subject_hash,
        created_at,expires_at,identity_token_expires_at,revoked_at
      ) VALUES(1,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      defaultPendingIdentityTokenHash,
      defaultPendingSessionHash,
      'default-pending-owner',
      'p'.repeat(43),
      NOW,
      NOW + 900,
      NOW + 600,
    ).run();
    assert.equal(await database.prepare(
      'SELECT activation_state FROM apple_native_sessions WHERE session_hash=?',
    ).bind(defaultPendingSessionHash).first('activation_state'), 'pending');
    await assert.rejects(
      database.prepare(
        'UPDATE apple_native_sessions SET activation_state=? WHERE session_hash=?',
      ).bind('unknown', legacySessionHash).run(),
      /CHECK constraint failed/,
    );
    await database.prepare(
      'DELETE FROM apple_native_sessions WHERE session_hash=?',
    ).bind(legacySessionHash).run();
    await database.prepare(
      'DELETE FROM apple_native_sessions WHERE session_hash=?',
    ).bind(defaultPendingSessionHash).run();

    const webRepository = createD1AppleAuthRepository(database);
    const subjectHash = 's'.repeat(43);
    assert.equal(await webRepository.linkAppleIdentity({appleSubjectHash: subjectHash, ownerId: 'owner-a', createdAt: NOW, updatedAt: NOW}), 'linked');
    assert.equal(await webRepository.linkAppleIdentity({appleSubjectHash: subjectHash, ownerId: 'owner-a', createdAt: NOW, updatedAt: NOW + 1}), 'linked');
    assert.equal(await webRepository.linkAppleIdentity({appleSubjectHash: subjectHash, ownerId: 'owner-b', createdAt: NOW, updatedAt: NOW + 2}), 'owner-conflict');

    const repository = createD1AppleNativeAuthRepository(database);
    assert.deepEqual(
      await repository.resolveAppleOwner({appleSubjectHash: subjectHash, proposedOwnerId: 'owner-b', now: NOW + 3}),
      {ownerId: 'owner-a', principalId: subjectHash, created: false},
    );
    const gatedSubject = 'g'.repeat(43);
    await webRepository.linkAppleIdentity({
      appleSubjectHash: gatedSubject,
      ownerId: 'owner-a',
      createdAt: NOW + 3,
      updatedAt: NOW + 3,
    });
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        provider_credentials,started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,0,NULL,?,NULL,?)`,
    ).bind(
      'G'.repeat(43), 'H'.repeat(43), 'owner-a', gatedSubject,
      NOW + 4, NOW + 604,
    ).run();
    await assert.rejects(
      repository.resolveAppleOwner({
        appleSubjectHash: gatedSubject,
        proposedOwnerId: 'owner-a',
        now: NOW + 5,
        authorizationStartedAt: NOW + 5,
      }),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    const gatedSession: AppleNativeSessionRecord = {
      schemaVersion: 1,
      identityTokenHash: 'G'.repeat(43),
      sessionHash: 'H'.repeat(43),
      ownerId: 'owner-a',
      principalId: gatedSubject,
      appleSubjectHash: gatedSubject,
      activationState: 'active',
      createdAt: NOW + 5,
      expiresAt: NOW + 905,
      identityTokenExpiresAt: NOW + 605,
    };
    await assert.rejects(
      repository.createSession(gatedSession, NOW + 5),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    await database.prepare(
      `UPDATE apple_account_deletions
       SET provider_credentials=?,origin_connections=?,completion_fence_token=?,completed_at=?
       WHERE deletion_key_hash=?`,
    ).bind(JSON.stringify({
      credentialsFound: 0,
      credentialsRevoked: 0,
      unreadableSessions: 1,
      failedRevocations: 0,
      manualRevocationRequired: true,
    }), JSON.stringify({
      installationsFound: 0,
      installationsRevoked: 0,
      unreadableInstallations: 0,
      failedRevocations: 0,
      manualRevocationRequired: false,
    }), 'F'.repeat(43), NOW + 6, 'G'.repeat(43)).run();
    await assert.rejects(
      repository.resolveAppleOwner({
        appleSubjectHash: gatedSubject,
        proposedOwnerId: 'owner-a',
        now: NOW + 7,
        authorizationStartedAt: NOW + 5,
      }),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    assert.deepEqual(await repository.resolveAppleOwner({
      appleSubjectHash: gatedSubject,
      proposedOwnerId: 'owner-a',
      now: NOW + 8,
      authorizationStartedAt: NOW + 7,
    }), {ownerId: 'owner-a', principalId: gatedSubject, created: false});
    const newSubjectHash = 'u'.repeat(43);
    const ownerRace = await Promise.all([
      repository.resolveAppleOwner({appleSubjectHash: newSubjectHash, proposedOwnerId: 'random-owner-a', now: NOW + 4}),
      repository.resolveAppleOwner({appleSubjectHash: newSubjectHash, proposedOwnerId: 'random-owner-b', now: NOW + 4}),
    ]);
    assert.equal(new Set(ownerRace.map(result => result.ownerId)).size, 1);
    assert.equal(ownerRace.filter(result => result.created).length, 1);

    const transferredSubject = 'z'.repeat(43);
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: transferredSubject,
      ownerId: 'owner-a',
      createdAt: NOW + 4,
      updatedAt: NOW + 4,
    }), 'linked');
    let signalNativeBatch!: () => void;
    let releaseNativeBatch!: () => void;
    const nativeBatchStarted = new Promise<void>(resolve => { signalNativeBatch = resolve; });
    const nativeBatchReleased = new Promise<void>(resolve => { releaseNativeBatch = resolve; });
    let nativeSessionInsertPrepared = false;
    let pauseNativeBatch = true;
    const pausedDatabase = {
      prepare(query: string) {
        if (query.includes('INSERT INTO apple_native_sessions')) {
          nativeSessionInsertPrepared = true;
        }
        return database.prepare(query);
      },
      async batch(statements: D1PreparedStatement[]) {
        if (pauseNativeBatch && nativeSessionInsertPrepared) {
          pauseNativeBatch = false;
          signalNativeBatch();
          await nativeBatchReleased;
        }
        return database.batch(statements);
      },
    } as D1Database;
    const pausedRepository = createD1AppleNativeAuthRepository(pausedDatabase);
    const transferRaceSession: AppleNativeSessionRecord = {
      schemaVersion: 1,
      identityTokenHash: 'V'.repeat(43),
      sessionHash: 'v'.repeat(43),
      ownerId: 'owner-a',
      principalId: transferredSubject,
      appleSubjectHash: transferredSubject,
      activationState: 'active',
      createdAt: NOW + 5,
      expiresAt: NOW + 905,
      identityTokenExpiresAt: NOW + 605,
    };
    const transferRaceGrant: AppleNativeGrantRecord = {
      schemaVersion: 1,
      grantHash: 'Y'.repeat(43),
      authorizationCodeHash: 'W'.repeat(43),
      sessionHash: transferRaceSession.sessionHash,
      ownerId: transferRaceSession.ownerId,
      principalId: transferRaceSession.principalId,
      appleSubjectHash: transferRaceSession.appleSubjectHash,
      ownerBinding: 'y'.repeat(43),
      encryptedCredentials: `v1.${'y'.repeat(16)}.${'y'.repeat(32)}`,
      createdAt: NOW + 5,
      lastValidatedAt: NOW + 5,
      expiresAt: NOW + 905,
      revocationPendingAt: null,
    };
    const staleNativeCreation = pausedRepository.createSessionWithGrant(
      transferRaceSession,
      transferRaceGrant,
    );
    await nativeBatchStarted;
    assert.deepEqual(await repository.resolveAppleOwner({
      appleSubjectHash: transferredSubject,
      transferSubjectHash: subjectHash,
      proposedOwnerId: 'ignored-owner',
      now: NOW + 6,
      authorizationStartedAt: NOW + 6,
    }), {ownerId: 'owner-a', principalId: subjectHash, created: false});
    releaseNativeBatch();
    await assert.rejects(
      staleNativeCreation,
      matchesCode('APPLE_IDENTITY_LINK_CONFLICT'),
    );
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_native_sessions WHERE session_hash=?',
    ).bind(transferRaceSession.sessionHash).first(), null);
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_native_grants WHERE grant_hash=?',
    ).bind(transferRaceGrant.grantHash).first(), null);

    const directNativeSubject = 'x'.repeat(43);
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: directNativeSubject,
      ownerId: 'owner-a',
      createdAt: NOW + 7,
      updatedAt: NOW + 7,
    }), 'linked');
    const directNativePause = pauseD1Statement(
      database,
      'INSERT INTO apple_native_sessions',
    );
    const directNativeRepository = createD1AppleNativeAuthRepository(directNativePause.database);
    const directNativeSession: AppleNativeSessionRecord = {
      ...transferRaceSession,
      identityTokenHash: 'Q'.repeat(43),
      sessionHash: 'q'.repeat(43),
      principalId: directNativeSubject,
      appleSubjectHash: directNativeSubject,
      createdAt: NOW + 7,
    };
    const staleDirectNativeCreation = directNativeRepository.createSession(directNativeSession);
    await directNativePause.started;
    assert.deepEqual(await repository.resolveAppleOwner({
      appleSubjectHash: directNativeSubject,
      transferSubjectHash: subjectHash,
      proposedOwnerId: 'ignored-owner',
      now: NOW + 8,
      authorizationStartedAt: NOW + 8,
    }), {ownerId: 'owner-a', principalId: subjectHash, created: false});
    directNativePause.release();
    await assert.rejects(
      staleDirectNativeCreation,
      matchesCode('APPLE_IDENTITY_LINK_CONFLICT'),
    );
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_native_sessions WHERE session_hash=?',
    ).bind(directNativeSession.sessionHash).first(), null);

    const webSubject = 'y'.repeat(43);
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: webSubject,
      ownerId: 'owner-a',
      createdAt: NOW + 9,
      updatedAt: NOW + 9,
    }), 'linked');
    const webPause = pauseD1Statement(database, 'INSERT INTO apple_auth_sessions');
    const pausedWebRepository = createD1AppleAuthRepository(webPause.database);
    const webSession: AppleAuthSessionRecord = {
      schemaVersion: 2,
      sessionHash: 'K'.repeat(43),
      ownerId: 'owner-a',
      ownerBinding: 'k'.repeat(43),
      appleSubjectHash: webSubject,
      encryptedCredentials: `v2.${'k'.repeat(16)}.${'k'.repeat(32)}`,
      createdAt: NOW + 9,
      expiresAt: NOW + 909,
      lastValidatedAt: NOW + 9,
    };
    const staleWebCreation = pausedWebRepository.createSession(webSession);
    await webPause.started;
    assert.deepEqual(await repository.resolveAppleOwner({
      appleSubjectHash: webSubject,
      transferSubjectHash: subjectHash,
      proposedOwnerId: 'ignored-owner',
      now: NOW + 10,
      authorizationStartedAt: NOW + 10,
    }), {ownerId: 'owner-a', principalId: subjectHash, created: false});
    webPause.release();
    await assert.rejects(
      staleWebCreation,
      matchesCode('APPLE_IDENTITY_LINK_CONFLICT'),
    );
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_auth_sessions WHERE session_hash=?',
    ).bind(webSession.sessionHash).first(), null);

    const session: AppleNativeSessionRecord = {
      schemaVersion: 1,
      identityTokenHash: 'i'.repeat(43),
      sessionHash: 'b'.repeat(43),
      ownerId: 'owner-a',
      principalId: subjectHash,
      appleSubjectHash: subjectHash,
      activationState: 'active',
      createdAt: NOW,
      expiresAt: NOW + 900,
      identityTokenExpiresAt: NOW + 600,
    };
    const concurrent = await Promise.all([
      repository.createSession(session),
      repository.createSession({...session, sessionHash: 'c'.repeat(43)}),
    ]);
    assert.deepEqual(concurrent.sort(), [false, true]);
    assert.equal((await repository.readSession(session.sessionHash, NOW + 1))?.ownerId, 'owner-a');
    assert.equal(await repository.readSession(session.sessionHash, session.expiresAt), null);
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        provider_credentials,started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,0,NULL,?,NULL,?)`,
    ).bind(
      'N'.repeat(43), 'O'.repeat(43), session.ownerId, session.appleSubjectHash,
      NOW + 1, NOW + 601,
    ).run();
    assert.equal(await repository.readSession(session.sessionHash, NOW + 2), null);
    await database.prepare('DELETE FROM apple_account_deletions WHERE deletion_key_hash=?').bind('N'.repeat(43)).run();
    assert.equal(await repository.revokeSession(session.sessionHash, NOW + 2), true);
    assert.equal(await repository.revokeSession(session.sessionHash, NOW + 3), true);
    assert.equal(await repository.readSession(session.sessionHash, NOW + 3), null);

    const expired = {
      ...session,
      identityTokenHash: 'j'.repeat(43),
      sessionHash: 'd'.repeat(43),
      expiresAt: NOW - 1,
      identityTokenExpiresAt: NOW - 61,
    };
    assert.equal(await repository.createSession(expired), true);
    assert.equal(await repository.createSession({
      ...expired,
      identityTokenHash: 'k'.repeat(43),
      sessionHash: 'e'.repeat(43),
      expiresAt: NOW - 2,
    }), true);
    assert.equal(await repository.cleanupSessions(NOW, 1), 1);
    const expiredCount = await database.prepare(
      'SELECT count(*) AS total FROM apple_native_sessions WHERE expires_at<=?',
    ).bind(NOW).first('total');
    assert.equal(expiredCount, 1);
    assert.equal(await repository.cleanupSessions(NOW, 1), 1);
    assert.equal(await repository.cleanupSessions(NOW, 1), 0);

    const raceSession: AppleNativeSessionRecord = {
      schemaVersion: 1,
      identityTokenHash: '1'.repeat(43),
      sessionHash: '2'.repeat(43),
      ownerId: 'owner-a',
      principalId: subjectHash,
      appleSubjectHash: subjectHash,
      activationState: 'pending',
      createdAt: NOW + 10,
      expiresAt: NOW + 910,
      identityTokenExpiresAt: NOW + 610,
    };
    const raceGrant: AppleNativeGrantRecord = {
      schemaVersion: 1,
      grantHash: '3'.repeat(43),
      authorizationCodeHash: '4'.repeat(43),
      sessionHash: raceSession.sessionHash,
      ownerId: raceSession.ownerId,
      principalId: raceSession.principalId,
      appleSubjectHash: raceSession.appleSubjectHash,
      ownerBinding: '5'.repeat(43),
      encryptedCredentials: 'old-encrypted-native-grant',
      createdAt: NOW + 10,
      lastValidatedAt: NOW + 10,
      expiresAt: NOW + 2_000,
      revocationPendingAt: null,
    };
    assert.equal(await repository.createSessionWithGrant(raceSession, raceGrant), true);
    assert.equal(await repository.readSession(raceSession.sessionHash, NOW + 11), null);
    assert.equal(await repository.readSessionWithGrant(raceSession.sessionHash, NOW + 11), null);
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,apple_principal_id,
        delete_owner_data,started_at,expires_at
      ) VALUES(?,?,?,?,?,0,?,?)`,
    ).bind(
      '6'.repeat(43), '7'.repeat(43), raceSession.ownerId, raceSession.appleSubjectHash,
      raceSession.principalId, NOW + 11, NOW + 611,
    ).run();
    assert.equal(await repository.activateSession(raceSession.sessionHash, NOW + 12), null);
    assert.equal(await database.prepare(
      'SELECT activation_state FROM apple_native_sessions WHERE session_hash=?',
    ).bind(raceSession.sessionHash).first('activation_state'), 'pending');
    await database.prepare('DELETE FROM apple_account_deletions WHERE deletion_key_hash=?')
      .bind('6'.repeat(43)).run();
    const activations = await Promise.all([
      repository.activateSession(raceSession.sessionHash, NOW + 12),
      repository.activateSession(raceSession.sessionHash, NOW + 12),
    ]);
    assert.deepEqual(activations.map(value => value?.ownerId), ['owner-a', 'owner-a']);
    assert.equal(await database.prepare(
      'SELECT activation_state FROM apple_native_sessions WHERE session_hash=?',
    ).bind(raceSession.sessionHash).first('activation_state'), 'active');

    const expiredPendingSession: AppleNativeSessionRecord = {
      ...raceSession,
      identityTokenHash: 'U'.repeat(43),
      sessionHash: 'u'.repeat(43),
      activationState: 'pending',
      expiresAt: NOW + 12,
    };
    const expiredPendingGrant: AppleNativeGrantRecord = {
      ...raceGrant,
      grantHash: 'V'.repeat(43),
      authorizationCodeHash: 'w'.repeat(43),
      sessionHash: expiredPendingSession.sessionHash,
    };
    assert.equal(await repository.createSessionWithGrant(
      expiredPendingSession,
      expiredPendingGrant,
    ), true);
    assert.equal(await repository.activateSession(expiredPendingSession.sessionHash, NOW + 12), null);

    const revokedPendingSession: AppleNativeSessionRecord = {
      ...raceSession,
      identityTokenHash: 'W'.repeat(43),
      sessionHash: 'x'.repeat(43),
      activationState: 'pending',
    };
    const revokedPendingGrant: AppleNativeGrantRecord = {
      ...raceGrant,
      grantHash: 'X'.repeat(43),
      authorizationCodeHash: 'y'.repeat(43),
      sessionHash: revokedPendingSession.sessionHash,
    };
    assert.equal(await repository.createSessionWithGrant(
      revokedPendingSession,
      revokedPendingGrant,
    ), true);
    assert.equal(await repository.revokeSession(revokedPendingSession.sessionHash, NOW + 12), true);
    assert.equal(await repository.activateSession(revokedPendingSession.sessionHash, NOW + 12), null);

    const invalidIdentitySubject = 't'.repeat(43);
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: invalidIdentitySubject,
      ownerId: 'owner-a',
      createdAt: NOW + 10,
      updatedAt: NOW + 10,
    }), 'linked');
    const invalidIdentityPendingSession: AppleNativeSessionRecord = {
      ...raceSession,
      identityTokenHash: 'Z'.repeat(43),
      sessionHash: 'z'.repeat(43),
      principalId: invalidIdentitySubject,
      appleSubjectHash: invalidIdentitySubject,
      activationState: 'pending',
    };
    const invalidIdentityPendingGrant: AppleNativeGrantRecord = {
      ...raceGrant,
      grantHash: 'M'.repeat(43),
      authorizationCodeHash: 'm'.repeat(43),
      sessionHash: invalidIdentityPendingSession.sessionHash,
      principalId: invalidIdentitySubject,
      appleSubjectHash: invalidIdentitySubject,
    };
    assert.equal(await repository.createSessionWithGrant(
      invalidIdentityPendingSession,
      invalidIdentityPendingGrant,
    ), true);
    await database.prepare('DELETE FROM apple_identity_links WHERE apple_subject_hash=?')
      .bind(invalidIdentitySubject).run();
    assert.equal(
      await repository.activateSession(invalidIdentityPendingSession.sessionHash, NOW + 12),
      null,
    );
    for (const pendingSessionHash of [
      expiredPendingSession.sessionHash,
      revokedPendingSession.sessionHash,
      invalidIdentityPendingSession.sessionHash,
    ]) {
      await database.prepare('DELETE FROM apple_native_grants WHERE session_hash=?')
        .bind(pendingSessionHash).run();
      await database.prepare('DELETE FROM apple_native_sessions WHERE session_hash=?')
        .bind(pendingSessionHash).run();
    }

    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,apple_principal_id,
        delete_owner_data,started_at,expires_at
      ) VALUES(?,?,?,?,?,0,?,?)`,
    ).bind(
      '6'.repeat(43), '7'.repeat(43), raceSession.ownerId, raceSession.appleSubjectHash,
      raceSession.principalId, NOW + 11, NOW + 611,
    ).run();
    assert.equal(await repository.readSessionWithGrant(raceSession.sessionHash, NOW + 12), null);
    const deletionFirstUpdate = await repository.updateSessionAndGrant({
      sessionHash: raceSession.sessionHash,
      ownerId: raceSession.ownerId,
      principalId: raceSession.principalId,
      appleSubjectHash: raceSession.appleSubjectHash,
      expectedEncryptedCredentials: raceGrant.encryptedCredentials,
      expectedLastValidatedAt: raceGrant.lastValidatedAt,
      encryptedCredentials: 'new-encrypted-native-grant',
      lastValidatedAt: NOW + 12,
      sessionExpiresAt: NOW + 912,
      identityTokenExpiresAt: NOW + 612,
      grantExpiresAt: NOW + 2_012,
    });
    assert.equal(deletionFirstUpdate, false);
    assert.deepEqual(await database.prepare(
      `SELECT encrypted_credentials,last_validated_at,revocation_pending_at
       FROM apple_native_grants WHERE grant_hash=?`,
    ).bind(raceGrant.grantHash).first(), {
      encrypted_credentials: raceGrant.encryptedCredentials,
      last_validated_at: raceGrant.lastValidatedAt,
      revocation_pending_at: NOW + 12,
    });
    await database.prepare('DELETE FROM apple_account_deletions WHERE deletion_key_hash=?')
      .bind('6'.repeat(43)).run();
    await database.prepare(
      'UPDATE apple_native_grants SET revocation_pending_at=NULL WHERE grant_hash=?',
    ).bind(raceGrant.grantHash).run();
    assert.equal(await repository.updateSessionAndGrant({
      sessionHash: raceSession.sessionHash,
      ownerId: raceSession.ownerId,
      principalId: raceSession.principalId,
      appleSubjectHash: raceSession.appleSubjectHash,
      expectedEncryptedCredentials: raceGrant.encryptedCredentials,
      expectedLastValidatedAt: raceGrant.lastValidatedAt,
      encryptedCredentials: 'new-encrypted-native-grant',
      lastValidatedAt: NOW + 13,
      sessionExpiresAt: NOW + 10_013,
      identityTokenExpiresAt: NOW + 10_013,
      grantExpiresAt: NOW + 20_013,
    }), true);
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,apple_principal_id,
        delete_owner_data,started_at,expires_at
      ) VALUES(?,?,?,?,?,0,?,?)`,
    ).bind(
      '8'.repeat(43), '9'.repeat(43), raceSession.ownerId, raceSession.appleSubjectHash,
      raceSession.principalId, NOW + 14, NOW + 614,
    ).run();
    assert.equal(await repository.readSessionWithGrant(raceSession.sessionHash, NOW + 15), null);

    const partialSession: AppleNativeSessionRecord = {
      ...raceSession,
      activationState: 'active',
      identityTokenHash: 'A'.repeat(43),
      sessionHash: 'B'.repeat(43),
      createdAt: NOW + 20,
    };
    const partialFixture = await createFixture();
    const partialRefreshToken = 'tracked-partial-refresh-token';
    const partialOwnerBinding = await sha256Base64URL(
      `native-grant-owner\0${partialSession.ownerId}\0${partialSession.appleSubjectHash}`,
    );
    const partialGrantHash = 'C'.repeat(43);
    const partialAdditionalData = [
      'apple-native-grant-v1',
      partialGrantHash,
      partialSession.sessionHash,
      partialSession.ownerId,
      partialSession.appleSubjectHash,
    ].join('\0');
    const partialCredentials = JSON.stringify({
      recordType: 'apple-native-refresh-grant',
      schemaVersion: 1,
      refreshToken: partialRefreshToken,
      subject: 'tracked-partial-subject',
      transferSubject: null,
    });
    const initialPartialCiphertext = await encryptAppleStorageRecord(
      partialCredentials,
      partialAdditionalData,
      partialFixture.dependencies,
    );
    const updatedPartialCiphertext = await encryptAppleStorageRecord(
      partialCredentials,
      partialAdditionalData,
      partialFixture.dependencies,
    );
    const partialGrant: AppleNativeGrantRecord = {
      ...raceGrant,
      grantHash: partialGrantHash,
      authorizationCodeHash: 'D'.repeat(43),
      sessionHash: partialSession.sessionHash,
      ownerBinding: partialOwnerBinding,
      encryptedCredentials: initialPartialCiphertext,
      createdAt: NOW + 20,
      lastValidatedAt: NOW + 20,
    };
    await database.prepare('DELETE FROM apple_account_deletions WHERE deletion_key_hash=?')
      .bind('8'.repeat(43)).run();
    assert.equal(await repository.createSessionWithGrant(partialSession, partialGrant), true);
    await database.prepare('DELETE FROM apple_native_sessions WHERE session_hash=?')
      .bind(partialSession.sessionHash).run();
    assert.equal(await repository.updateSessionAndGrant({
      sessionHash: partialSession.sessionHash,
      ownerId: partialSession.ownerId,
      principalId: partialSession.principalId,
      appleSubjectHash: partialSession.appleSubjectHash,
      expectedEncryptedCredentials: partialGrant.encryptedCredentials,
      expectedLastValidatedAt: partialGrant.lastValidatedAt,
      encryptedCredentials: updatedPartialCiphertext,
      lastValidatedAt: NOW + 21,
      sessionExpiresAt: NOW + 921,
      identityTokenExpiresAt: NOW + 621,
      grantExpiresAt: NOW + 2_021,
    }), false);
    assert.deepEqual(
      await database.prepare(
        `SELECT encrypted_credentials,revocation_pending_at
         FROM apple_native_grants WHERE grant_hash=?`,
      ).bind(partialGrant.grantHash).first(),
      {
        encrypted_credentials: initialPartialCiphertext,
        revocation_pending_at: NOW + 21,
      },
    );

    let partialNow = NOW + 22;
    let providerAvailable = false;
    const partialDependencies: AppleNativeAuthDependencies = {
      ...partialFixture.dependencies,
      repository,
      now: () => partialNow,
      fetcher: async (input, init) => {
        const url = input instanceof Request ? input.url : input.toString();
        if (!url.endsWith('/auth/revoke')) {
          return partialFixture.dependencies.fetcher(input, init);
        }
        return providerAvailable
          ? new Response(null, {status: 200})
          : new Response('unavailable', {status: 503});
      },
    };
    assert.deepEqual(
      await drainExpiredAppleNativeGrants(partialDependencies, {
        batchLimit: 1,
        maximumBatches: 2,
      }),
      {batches: 1, found: 0, revoked: 0, failed: 0, backlog: false},
    );
    assert.equal(
      await database.prepare('SELECT COUNT(*) AS total FROM apple_native_grants WHERE grant_hash=?')
        .bind(partialGrant.grantHash).first('total'),
      1,
    );
    assert.equal(JSON.stringify(
      await database.prepare('SELECT * FROM apple_native_grants WHERE grant_hash=?')
        .bind(partialGrant.grantHash).first(),
    ).includes(partialRefreshToken), false);
    assert.deepEqual(
      await drainExpiredAppleNativeGrants(partialDependencies, {
        batchLimit: 1,
        maximumBatches: 1,
      }),
      {batches: 1, found: 0, revoked: 0, failed: 0, backlog: false},
    );
    partialNow = NOW + 21 + APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS;
    assert.deepEqual(
      await drainExpiredAppleNativeGrants(partialDependencies, {
        batchLimit: 1,
        maximumBatches: 2,
      }),
      {batches: 2, found: 1, revoked: 0, failed: 1, backlog: false},
    );
    assert.deepEqual(
      await drainExpiredAppleNativeGrants(partialDependencies, {
        batchLimit: 1,
        maximumBatches: 1,
      }),
      {batches: 1, found: 0, revoked: 0, failed: 0, backlog: false},
    );
    providerAvailable = true;
    partialNow += APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS;
    assert.deepEqual(
      await drainExpiredAppleNativeGrants(partialDependencies, {
        batchLimit: 1,
        maximumBatches: 2,
      }),
      {batches: 2, found: 1, revoked: 1, failed: 0, backlog: false},
    );
    assert.equal(
      await database.prepare('SELECT COUNT(*) AS total FROM apple_native_grants WHERE grant_hash=?')
        .bind(partialGrant.grantHash).first('total'),
      0,
    );

    const changedSession: AppleNativeSessionRecord = {
      ...raceSession,
      activationState: 'active',
      identityTokenHash: 'E'.repeat(43),
      sessionHash: 'F'.repeat(43),
      createdAt: NOW + 30,
      expiresAt: NOW + 930,
      identityTokenExpiresAt: NOW + 630,
    };
    const changedGrantHash = 'I'.repeat(43);
    const changedAdditionalData = [
      'apple-native-grant-v1',
      changedGrantHash,
      changedSession.sessionHash,
      changedSession.ownerId,
      changedSession.appleSubjectHash,
    ].join('\0');
    const changedCredentials = JSON.stringify({
      recordType: 'apple-native-refresh-grant',
      schemaVersion: 1,
      refreshToken: 'tracked-changed-refresh-token',
      subject: 'tracked-changed-subject',
      transferSubject: null,
    });
    const initialChangedCiphertext = await encryptAppleStorageRecord(
      changedCredentials,
      changedAdditionalData,
      partialFixture.dependencies,
    );
    const updatedChangedCiphertext = await encryptAppleStorageRecord(
      changedCredentials,
      changedAdditionalData,
      partialFixture.dependencies,
    );
    const changedGrant: AppleNativeGrantRecord = {
      ...raceGrant,
      grantHash: changedGrantHash,
      authorizationCodeHash: 'J'.repeat(43),
      sessionHash: changedSession.sessionHash,
      ownerBinding: partialOwnerBinding,
      encryptedCredentials: initialChangedCiphertext,
      createdAt: NOW + 30,
      lastValidatedAt: NOW + 30,
      expiresAt: NOW + 2_030,
      revocationPendingAt: null,
    };
    assert.equal(await repository.createSessionWithGrant(changedSession, changedGrant), true);
    assert.equal(await repository.revokeSession(changedSession.sessionHash, NOW + 31), true);
    assert.equal(await repository.updateSessionAndGrant({
      sessionHash: changedSession.sessionHash,
      ownerId: changedSession.ownerId,
      principalId: changedSession.principalId,
      appleSubjectHash: changedSession.appleSubjectHash,
      expectedEncryptedCredentials: changedGrant.encryptedCredentials,
      expectedLastValidatedAt: changedGrant.lastValidatedAt,
      encryptedCredentials: updatedChangedCiphertext,
      lastValidatedAt: NOW + 32,
      sessionExpiresAt: NOW + 932,
      identityTokenExpiresAt: NOW + 632,
      grantExpiresAt: NOW + 2_032,
    }), false);
    assert.deepEqual(
      await database.prepare(
        `SELECT session.expires_at,session.revoked_at,grant.revocation_pending_at
         FROM apple_native_sessions AS session
         JOIN apple_native_grants AS grant ON grant.session_hash=session.session_hash
         WHERE session.session_hash=?`,
      ).bind(changedSession.sessionHash).first(),
      {
        expires_at: changedSession.expiresAt,
        revoked_at: NOW + 31,
        revocation_pending_at: NOW + 32,
      },
    );
    partialNow = NOW + 32 + APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS;
    assert.deepEqual(
      await drainExpiredAppleNativeGrants(partialDependencies, {
        batchLimit: 1,
        maximumBatches: 2,
      }),
      {batches: 2, found: 1, revoked: 1, failed: 0, backlog: false},
    );
    assert.equal(
      await database.prepare('SELECT COUNT(*) AS total FROM apple_native_grants WHERE grant_hash=?')
        .bind(changedGrant.grantHash).first('total'),
      0,
    );

    const retentionCutoff = NOW + 100;
    const refreshWinsSession: AppleNativeSessionRecord = {
      ...raceSession,
      activationState: 'active',
      identityTokenHash: 'retention-refresh-token'.padEnd(43, 'a'),
      sessionHash: 'retention-refresh-session'.padEnd(43, 'b'),
      createdAt: NOW + 40,
      expiresAt: retentionCutoff,
      identityTokenExpiresAt: retentionCutoff + 600,
    };
    const refreshWinsGrant: AppleNativeGrantRecord = {
      ...raceGrant,
      grantHash: 'retention-refresh-grant'.padEnd(43, 'c'),
      authorizationCodeHash: 'retention-refresh-code'.padEnd(43, 'd'),
      sessionHash: refreshWinsSession.sessionHash,
      encryptedCredentials: 'retention-refresh-old-credentials',
      createdAt: NOW + 40,
      lastValidatedAt: NOW + 40,
      expiresAt: retentionCutoff + 2_000,
      revocationPendingAt: null,
    };
    assert.equal(await repository.createSessionWithGrant(
      refreshWinsSession,
      refreshWinsGrant,
    ), true);
    const claimPause = pauseNextD1Batch(database);
    const pausedClaimRepository = createD1AppleNativeAuthRepository(claimPause.database);
    const staleClaim = pausedClaimRepository.claimExpiredSessionGrants(
      retentionCutoff,
      retentionCutoff + 10,
      1,
    );
    await claimPause.started;
    const refreshedCredentials = 'retention-refresh-new-credentials';
    assert.equal(await repository.updateSessionAndGrant({
      sessionHash: refreshWinsSession.sessionHash,
      ownerId: refreshWinsSession.ownerId,
      principalId: refreshWinsSession.principalId,
      appleSubjectHash: refreshWinsSession.appleSubjectHash,
      expectedEncryptedCredentials: refreshWinsGrant.encryptedCredentials,
      expectedLastValidatedAt: refreshWinsGrant.lastValidatedAt,
      encryptedCredentials: refreshedCredentials,
      lastValidatedAt: retentionCutoff - 1,
      sessionExpiresAt: retentionCutoff + 900,
      identityTokenExpiresAt: retentionCutoff + 600,
      grantExpiresAt: retentionCutoff + 2_000,
    }), true);
    claimPause.release();
    assert.deepEqual(await staleClaim, []);
    assert.notEqual(
      await repository.readSession(refreshWinsSession.sessionHash, retentionCutoff + 1),
      null,
    );

    const claimWinsSession: AppleNativeSessionRecord = {
      ...raceSession,
      activationState: 'active',
      identityTokenHash: 'retention-claim-token'.padEnd(43, 'e'),
      sessionHash: 'retention-claim-session'.padEnd(43, 'f'),
      createdAt: NOW + 41,
      expiresAt: retentionCutoff,
      identityTokenExpiresAt: retentionCutoff + 600,
    };
    const claimWinsGrant: AppleNativeGrantRecord = {
      ...raceGrant,
      grantHash: 'retention-claim-grant'.padEnd(43, 'g'),
      authorizationCodeHash: 'retention-claim-code'.padEnd(43, 'h'),
      sessionHash: claimWinsSession.sessionHash,
      encryptedCredentials: 'retention-claim-old-credentials',
      createdAt: NOW + 41,
      lastValidatedAt: NOW + 41,
      expiresAt: retentionCutoff + 2_000,
      revocationPendingAt: null,
    };
    assert.equal(await repository.createSessionWithGrant(claimWinsSession, claimWinsGrant), true);
    const refreshPause = pauseNextD1Batch(database);
    const pausedRefreshRepository = createD1AppleNativeAuthRepository(refreshPause.database);
    const staleRefresh = pausedRefreshRepository.updateSessionAndGrant({
      sessionHash: claimWinsSession.sessionHash,
      ownerId: claimWinsSession.ownerId,
      principalId: claimWinsSession.principalId,
      appleSubjectHash: claimWinsSession.appleSubjectHash,
      expectedEncryptedCredentials: claimWinsGrant.encryptedCredentials,
      expectedLastValidatedAt: claimWinsGrant.lastValidatedAt,
      encryptedCredentials: 'retention-claim-new-credentials',
      lastValidatedAt: retentionCutoff - 1,
      sessionExpiresAt: retentionCutoff + 900,
      identityTokenExpiresAt: retentionCutoff + 600,
      grantExpiresAt: retentionCutoff + 2_000,
    });
    await refreshPause.started;
    const firstClaimedAt = retentionCutoff + 20;
    assert.deepEqual(
      (await repository.claimExpiredSessionGrants(
        retentionCutoff,
        firstClaimedAt,
        1,
      )).map(record => record.grantHash),
      [claimWinsGrant.grantHash],
    );
    assert.equal(await repository.readSession(claimWinsSession.sessionHash, retentionCutoff - 1), null);
    assert.equal(await repository.hasExpiredSessionGrant(
      retentionCutoff,
      firstClaimedAt + APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS - 1,
    ), false);
    assert.deepEqual(await repository.claimExpiredSessionGrants(
      retentionCutoff,
      firstClaimedAt + APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS - 1,
      1,
    ), []);
    const secondClaimedAt = firstClaimedAt + APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS;
    assert.deepEqual(
      (await repository.claimExpiredSessionGrants(
        retentionCutoff,
        secondClaimedAt,
        1,
      )).map(record => record.grantHash),
      [claimWinsGrant.grantHash],
    );
    assert.equal(await repository.deleteClaimedExpiredGrant(
      claimWinsGrant.grantHash,
      firstClaimedAt,
    ), false);
    refreshPause.release();
    assert.equal(await staleRefresh, false);
    assert.equal(await repository.readSession(claimWinsSession.sessionHash, retentionCutoff - 1), null);
    assert.deepEqual(await database.prepare(
      `SELECT encrypted_credentials,revocation_pending_at FROM apple_native_grants
       WHERE grant_hash=?`,
    ).bind(claimWinsGrant.grantHash).first(), {
      encrypted_credentials: claimWinsGrant.encryptedCredentials,
      revocation_pending_at: secondClaimedAt,
    });
    assert.equal(await repository.deleteClaimedExpiredGrant(
      claimWinsGrant.grantHash,
      secondClaimedAt,
    ), true);

    const rows = await database.prepare('SELECT * FROM apple_native_sessions').all();
    const serialized = JSON.stringify(rows.results);
    for (const secret of [APPLE_SUBJECT, RAW_NONCE, 'v1.' + 'x'.repeat(43)]) {
      assert.equal(serialized.includes(secret), false, secret);
    }
    const link = await database.prepare('SELECT * FROM apple_identity_links').first();
    assert.equal(JSON.stringify(link).includes(APPLE_SUBJECT), false);
  } finally {
    await miniflare.dispose();
  }
});

function pauseD1Statement(database: D1Database, queryNeedle: string): {
  database: D1Database;
  started: Promise<void>;
  release: () => void;
} {
  let signalStarted!: () => void;
  let signalReleased!: () => void;
  const started = new Promise<void>(resolve => { signalStarted = resolve; });
  const released = new Promise<void>(resolve => { signalReleased = resolve; });
  let paused = false;
  return {
    database: {
      prepare(query: string) {
        const statement = database.prepare(query);
        if (!query.includes(queryNeedle)) return statement;
        return {
          bind(...values: unknown[]) {
            const bound = statement.bind(...values);
            return {
              async first<T = Record<string, unknown>>(column?: string) {
                if (!paused) {
                  paused = true;
                  signalStarted();
                  await released;
                }
                return column === undefined
                  ? bound.first<T>()
                  : bound.first<T>(column);
              },
            } as D1PreparedStatement;
          },
        } as D1PreparedStatement;
      },
      batch(statements: D1PreparedStatement[]) {
        return database.batch(statements);
      },
    } as D1Database,
    started,
    release: signalReleased,
  };
}

function pauseNextD1Batch(database: D1Database): {
  database: D1Database;
  started: Promise<void>;
  release: () => void;
} {
  let signalStarted!: () => void;
  let signalReleased!: () => void;
  const started = new Promise<void>(resolve => { signalStarted = resolve; });
  const released = new Promise<void>(resolve => { signalReleased = resolve; });
  let paused = false;
  return {
    database: {
      prepare(query: string) {
        return database.prepare(query);
      },
      async batch(statements: D1PreparedStatement[]) {
        if (!paused) {
          paused = true;
          signalStarted();
          await released;
        }
        return database.batch(statements);
      },
    } as D1Database,
    started,
    release: signalReleased,
  };
}

function matchesCode(code: string): (error: unknown) => boolean {
  return error => error instanceof AppleAuthError && error.code === code;
}

async function sha256Base64URL(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return base64URL(new Uint8Array(digest));
}

function pemFromPKCS8(value: ArrayBuffer): string {
  const encoded = base64(new Uint8Array(value));
  const lines = encoded.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;
}

function base64URL(value: Uint8Array): string {
  return base64(value).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function nonCanonicalBase64URLAlias(value: string): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const unusedBits = value.length % 4 === 2 ? 4 : value.length % 4 === 3 ? 2 : 0;
  assert.notEqual(unusedBits, 0, 'test value needs unused base64url padding bits');
  const index = alphabet.indexOf(value.at(-1) ?? '');
  assert.ok(index >= 0);
  const unusedMask = (1 << unusedBits) - 1;
  assert.equal(index & unusedMask, 0, 'input must use the canonical zero padding bits');
  return `${value.slice(0, -1)}${alphabet[index | 1]}`;
}

function base64URLBytes(value: string): Uint8Array {
  const padding = '='.repeat((4 - value.length % 4) % 4);
  const decoded = atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
  return Uint8Array.from(decoded, character => character.charCodeAt(0));
}

function base64(value: Uint8Array): string {
  let result = '';
  for (const byte of value) result += String.fromCharCode(byte);
  return btoa(result);
}

function decodeJWTPayload(token: string): Record<string, unknown> {
  const segment = token.split('.')[1] ?? '';
  return JSON.parse(new TextDecoder().decode(base64URLBytes(segment))) as Record<string, unknown>;
}
