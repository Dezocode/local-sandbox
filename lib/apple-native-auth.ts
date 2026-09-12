import { z } from 'zod';
import {
  APPLE_CLIENT_SECRET_LIFETIME_SECONDS,
  APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
  AppleAuthError,
  appleAccountModeForOwner,
  createAppleOpaqueOwnerId,
  createAppleOpaqueToken,
  decryptAppleStorageRecord,
  encryptAppleStorageRecord,
  exchangeAppleNativeAuthorizationCode,
  hashAppleOpaqueToken,
  hashAppleSubject,
  isDefinitiveAppleNoCredentialError,
  refreshAppleNativeAuthorization,
  revokeAppleNativeRefreshToken,
  type AppleAccountMode,
  type AppleAuthConfiguration,
  type AppleAuthFetch,
  type AppleNativeExchangedTokens,
  type AppleAuthorizationExchangeLease,
  type AppleCredentialRevocationSummary,
  verifyExchangedNativeAppleIdentityToken,
  verifyNativeAppleIdentityToken,
} from './apple-auth.ts';

const NATIVE_SESSION_LIFETIME_SECONDS = 15 * 60;
export const NATIVE_GRANT_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
const MAX_NATIVE_REQUEST_BYTES = 20_000;
export const APPLE_NATIVE_GRANT_RETENTION_BATCH_LIMIT = 20;
export const APPLE_NATIVE_GRANT_RETENTION_MAX_BATCHES = 1;
export const APPLE_NATIVE_GRANT_RETENTION_OVERHEAD_SECONDS = 60;
export const APPLE_NATIVE_GRANT_RETENTION_WORKER_LIMIT_SECONDS = 15 * 60;
export const APPLE_NATIVE_GRANT_RETENTION_WORST_CASE_SECONDS = Math.ceil(
  APPLE_NATIVE_GRANT_RETENTION_BATCH_LIMIT
    * APPLE_NATIVE_GRANT_RETENTION_MAX_BATCHES
    * APPLE_REVOCATION_TIMEOUT_MILLISECONDS / 1_000,
) + APPLE_NATIVE_GRANT_RETENTION_OVERHEAD_SECONDS;
export const APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS = 4 * 60;
assertAppleNativeGrantRetentionBounds(
  APPLE_NATIVE_GRANT_RETENTION_BATCH_LIMIT,
  APPLE_NATIVE_GRANT_RETENTION_MAX_BATCHES,
  APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
);
const CLEANUP_BATCH_SIZE = APPLE_NATIVE_GRANT_RETENTION_BATCH_LIMIT;

function assertAppleNativeGrantRetentionBounds(
  batchLimit: number,
  maximumBatches: number,
  revocationTimeoutMilliseconds: number,
): void {
  const requestCount = batchLimit * maximumBatches;
  const requestBudgetMilliseconds = requestCount * revocationTimeoutMilliseconds;
  if (
    !Number.isSafeInteger(requestCount) || requestCount <= 0
    || !Number.isSafeInteger(revocationTimeoutMilliseconds)
    || revocationTimeoutMilliseconds <= 0
    || !Number.isSafeInteger(requestBudgetMilliseconds)
  ) throw new TypeError('Native Apple grant retention requires bounded provider work.');
  const worstCaseSeconds = Math.ceil(requestBudgetMilliseconds / 1_000)
    + APPLE_NATIVE_GRANT_RETENTION_OVERHEAD_SECONDS;
  if (
    worstCaseSeconds >= APPLE_CLIENT_SECRET_LIFETIME_SECONDS
    || worstCaseSeconds >= APPLE_NATIVE_GRANT_RETENTION_WORKER_LIMIT_SECONDS
    || worstCaseSeconds >= APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS
  ) throw new TypeError('Native Apple grant retention exceeds its provider or lease budget.');
}

export type AppleNativeSessionRecord = {
  schemaVersion: 1;
  identityTokenHash: string;
  sessionHash: string;
  ownerId: string;
  principalId: string;
  appleSubjectHash: string;
  activationState: 'pending' | 'active';
  createdAt: number;
  expiresAt: number;
  identityTokenExpiresAt: number;
};

export type AppleNativeSession = {
  schemaVersion: 1;
  ownerId: string;
  appleSubjectHash: string;
  createdAt: number;
  expiresAt: number;
};

export type AppleNativeGrantRecord = {
  schemaVersion: 1;
  grantHash: string;
  authorizationCodeHash: string;
  sessionHash: string;
  ownerId: string;
  principalId: string;
  appleSubjectHash: string;
  ownerBinding: string;
  encryptedCredentials: string;
  createdAt: number;
  lastValidatedAt: number;
  expiresAt: number;
  revocationPendingAt: number | null;
};

export type AppleNativeSessionGrant = {
  session: AppleNativeSessionRecord;
  grant: AppleNativeGrantRecord;
};

export type AppleNativeAuthRepository = {
  resolveAppleOwner(link: {
    appleSubjectHash: string;
    transferSubjectHash?: string | null;
    proposedOwnerId: string;
    requiredOwnerId?: string | null;
    requiredPrincipalId?: string | null;
    now: number;
    authorizationStartedAt?: number;
  }): Promise<{ownerId: string; principalId: string; created: boolean}>;
  readLinkedIdentity(appleSubjectHash: string): Promise<{
    ownerId: string;
    principalId: string;
    principalCreatedAt: number;
  } | null>;
  claimAuthorizationCode(
    authorizationCodeHash: string,
    claimedAt: number,
    expiresAt: number,
  ): Promise<boolean>;
  createSessionWithGrant(
    session: AppleNativeSessionRecord,
    grant: AppleNativeGrantRecord,
    authorizationStartedAt?: number,
  ): Promise<boolean>;
  createSession(record: AppleNativeSessionRecord, authorizationStartedAt?: number): Promise<boolean>;
  activateSession(sessionHash: string, now: number): Promise<AppleNativeSession | null>;
  readSession(sessionHash: string, now: number): Promise<AppleNativeSession | null>;
  readSessionWithGrant(sessionHash: string, now: number): Promise<AppleNativeSessionGrant | null>;
  updateSessionAndGrant(input: {
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
  }): Promise<boolean>;
  beginSessionRevocation(sessionHash: string, now: number): Promise<{
    found: boolean;
    grant: AppleNativeGrantRecord | null;
  }>;
  revokeSession(sessionHash: string, now: number): Promise<boolean>;
  markGrantRevocationPending(grantHash: string, now: number): Promise<void>;
  deleteGrant(grantHash: string): Promise<boolean>;
  hasExpiredSessionGrant(eligibilityCutoff: number, claimTime: number): Promise<boolean>;
  claimExpiredSessionGrants(
    eligibilityCutoff: number,
    claimedAt: number,
    limit: number,
  ): Promise<AppleNativeGrantRecord[]>;
  deleteClaimedExpiredGrant(grantHash: string, claimedAt: number): Promise<boolean>;
  cleanupSessions(now: number, limit: number): Promise<number>;
  claimAuthorizationExchangeLease(input: AppleAuthorizationExchangeLease): Promise<void>;
  markAuthorizationExchangePossible(leaseToken: string, now: number): Promise<void>;
  completeAuthorizationExchangeLease(input: AppleAuthorizationExchangeLease): Promise<void>;
  releaseAuthorizationExchangeLease(leaseToken: string, now: number): Promise<void>;
};

export type AppleNativeAuthDependencies = {
  configuration: AppleAuthConfiguration;
  repository: AppleNativeAuthRepository;
  fetcher: AppleAuthFetch;
  crypto: Crypto;
  now: () => number;
  revocationTimeoutMilliseconds: number;
};

export type AppleNativeProviderDependencies = Pick<
  AppleNativeAuthDependencies,
  'configuration' | 'fetcher' | 'crypto' | 'now' | 'revocationTimeoutMilliseconds'
>;

const exchangeRequestBaseSchema = z.object({
  identityToken: z.string().min(20).max(16_000),
  authorizationCode: z.string().min(1).max(8_000),
  rawNonce: z.string().min(32).max(128),
});
const exchangeRequestSchema = z.union([
  exchangeRequestBaseSchema.extend({transferRecoveryUser: z.undefined().optional()}).strict(),
  exchangeRequestBaseSchema.extend({transferRecoveryUser: z.string().min(1).max(255)}).strict(),
]);

export type AppleNativeExchangeRequest = z.infer<typeof exchangeRequestSchema>;

export type AppleNativeExchangeResult = {
  schemaVersion: 2;
  activationState: 'pending';
  tokenType: 'Bearer';
  token: string;
  expiresAt: number;
  accountMode: AppleAccountMode;
};

export type AppleNativeActiveSessionResult = {
  schemaVersion: 2;
  activationState: 'active';
  tokenType: 'Bearer';
  token: string;
  expiresAt: number;
  accountMode: AppleAccountMode;
};

const storedGrantCredentialsSchema = z.object({
  recordType: z.literal('apple-native-refresh-grant'),
  schemaVersion: z.literal(1),
  refreshToken: z.string().min(1).max(8_000),
  subject: z.string().min(1).max(255),
  transferSubject: z.string().min(1).max(255).nullable(),
}).strict();
type StoredGrantCredentials = z.infer<typeof storedGrantCredentialsSchema>;

export async function parseAppleNativeExchangeRequest(
  request: Request,
): Promise<AppleNativeExchangeRequest> {
  if (request.headers.has('cookie') || request.headers.has('authorization')) {
    throw new AppleAuthError(
      400,
      'APPLE_NATIVE_AMBIENT_AUTH',
      'Native Apple exchange does not accept browser cookies or bearer credentials.',
    );
  }
  const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new AppleAuthError(415, 'APPLE_NATIVE_CONTENT_TYPE', 'Native Apple exchange requires JSON.');
  }
  const contentLength = request.headers.get('content-length');
  if (
    contentLength !== null
    && (!/^\d+$/.test(contentLength) || Number(contentLength) > MAX_NATIVE_REQUEST_BYTES)
  ) {
    throw new AppleAuthError(413, 'APPLE_NATIVE_REQUEST_TOO_LARGE', 'Native Apple exchange request is too large.');
  }
  const text = await readBoundedText(request, MAX_NATIVE_REQUEST_BYTES);
  try {
    return exchangeRequestSchema.parse(JSON.parse(text));
  } catch {
    throw new AppleAuthError(400, 'APPLE_NATIVE_REQUEST_INVALID', 'Native Apple exchange request is invalid.');
  }
}

export async function requireEmptyAppleNativeBody(request: Request): Promise<void> {
  const declaredLength = request.headers.get('content-length');
  if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || declaredLength !== '0')) {
    throw invalidEmptyBody();
  }
  if (request.body === null) return;
  const reader = request.body.getReader();
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) return;
    if (chunk.value.byteLength > 0) {
      await reader.cancel();
      throw invalidEmptyBody();
    }
  }
}

function invalidEmptyBody(): AppleAuthError {
  return new AppleAuthError(
    400,
    'APPLE_NATIVE_REQUEST_INVALID',
    'Native session operation does not accept a request body.',
  );
}

async function readBoundedText(request: Request, maximumBytes: number): Promise<string> {
  if (request.body === null) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    total += chunk.value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel();
      throw new AppleAuthError(413, 'APPLE_NATIVE_REQUEST_TOO_LARGE', 'Native Apple exchange request is too large.');
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
    throw new AppleAuthError(400, 'APPLE_NATIVE_REQUEST_INVALID', 'Native Apple exchange request is invalid.');
  }
}

export async function exchangeAppleNativeIdentityToken(
  dependencies: AppleNativeAuthDependencies,
  request: AppleNativeExchangeRequest,
): Promise<AppleNativeExchangeResult> {
  const callbackClaims = await verifyNativeAppleIdentityToken(
    request.identityToken,
    request.rawNonce,
    dependencies,
  );
  const transferRecoveryUser = request.transferRecoveryUser ?? null;
  let requiredTransferIdentity: {
    ownerId: string;
    principalId: string;
    principalCreatedAt: number;
  } | null = null;
  if (transferRecoveryUser !== null) {
    if (
      callbackClaims.transferSubject === null
      || !constantTimeEqual(callbackClaims.transferSubject, transferRecoveryUser)
      || constantTimeEqual(callbackClaims.subject, transferRecoveryUser)
    ) {
      throw new AppleAuthError(
        409,
        'APPLE_NATIVE_TRANSFER_RECOVERY_INVALID',
        'Apple did not verify continuity with the transferred account.',
      );
    }
    requiredTransferIdentity = await dependencies.repository.readLinkedIdentity(
      await hashAppleSubject(transferRecoveryUser, dependencies),
    );
    if (requiredTransferIdentity === null) {
      throw new AppleAuthError(
        409,
        'APPLE_NATIVE_TRANSFER_RECOVERY_INVALID',
        'The transferred Apple account is not linked to this Local Sandbox service.',
      );
    }
  }

  const now = dependencies.now();
  const authorizationCodeHash = await hashAppleOpaqueToken(
    request.authorizationCode,
    dependencies.crypto,
  );
  if (!await dependencies.repository.claimAuthorizationCode(
    authorizationCodeHash,
    now,
    now + NATIVE_GRANT_LIFETIME_SECONDS,
  )) {
    throw new AppleAuthError(
      409,
      'APPLE_NATIVE_CREDENTIAL_REPLAY',
      'This Apple authorization credential was already exchanged.',
    );
  }
  const appleSubjectHash = await hashAppleSubject(callbackClaims.subject, dependencies);
  const transferSubjectHash = callbackClaims.transferSubject === null
    ? null
    : await hashAppleSubject(callbackClaims.transferSubject, dependencies);
  const identity = await dependencies.repository.resolveAppleOwner({
    appleSubjectHash,
    transferSubjectHash,
    proposedOwnerId: createAppleOpaqueOwnerId(dependencies.crypto),
    requiredOwnerId: requiredTransferIdentity?.ownerId ?? null,
    requiredPrincipalId: requiredTransferIdentity?.principalId ?? null,
    now,
    authorizationStartedAt: callbackClaims.issuedAt,
  });
  if (
    requiredTransferIdentity !== null
    && (
      identity.ownerId !== requiredTransferIdentity.ownerId
      || identity.principalId !== requiredTransferIdentity.principalId
    )
  ) {
    throw new AppleAuthError(
      409,
      'APPLE_NATIVE_TRANSFER_RECOVERY_INVALID',
      'The transferred Apple identity resolved to a different Local Sandbox account.',
    );
  }
  const authorizationLease: AppleAuthorizationExchangeLease = {
    leaseToken: createAppleOpaqueToken(dependencies.crypto).slice(3),
    ownerId: identity.ownerId,
    appleSubjectHash,
    authorizationStartedAt: callbackClaims.issuedAt,
    now,
  };
  await dependencies.repository.claimAuthorizationExchangeLease(authorizationLease);
  await dependencies.repository.markAuthorizationExchangePossible(
    authorizationLease.leaseToken,
    dependencies.now(),
  );
  let tokenResponse: AppleNativeExchangedTokens;
  try {
    tokenResponse = await exchangeAppleNativeAuthorizationCode(
      request.authorizationCode,
      dependencies,
    );
  } catch (error) {
    if (isDefinitiveAppleNoCredentialError(error)) {
      await releaseNativeAuthorizationLeaseAfterConfirmedCompensation(
        dependencies.repository,
        authorizationLease.leaseToken,
        dependencies.now(),
      );
    }
    throw error;
  }
  try {
    const exchangedClaims = await verifyExchangedNativeAppleIdentityToken(
      tokenResponse.idToken,
      dependencies,
    );
    requireClaimContinuity(callbackClaims, exchangedClaims);

    await dependencies.repository.cleanupSessions(now, CLEANUP_BATCH_SIZE);
    const token = createAppleOpaqueToken(dependencies.crypto);
    const sessionHash = await hashAppleOpaqueToken(token, dependencies.crypto);
    const grantHash = await hashAppleOpaqueToken(
      createAppleOpaqueToken(dependencies.crypto),
      dependencies.crypto,
    );
    const ownerBinding = await nativeGrantOwnerBinding(
      identity.ownerId,
      appleSubjectHash,
      dependencies.crypto,
    );
    const credentials: StoredGrantCredentials = {
      recordType: 'apple-native-refresh-grant',
      schemaVersion: 1,
      refreshToken: tokenResponse.refreshToken,
      subject: exchangedClaims.subject,
      transferSubject: exchangedClaims.transferSubject,
    };
    const sessionExpiresAt = now + NATIVE_SESSION_LIFETIME_SECONDS;
    const grantExpiresAt = now + NATIVE_GRANT_LIFETIME_SECONDS;
    const grantBase = {
      schemaVersion: 1 as const,
      grantHash,
      authorizationCodeHash,
      sessionHash,
      ownerId: identity.ownerId,
      principalId: identity.principalId,
      appleSubjectHash,
      ownerBinding,
      createdAt: now,
      lastValidatedAt: now,
      expiresAt: grantExpiresAt,
      revocationPendingAt: null,
    };
    const created = await dependencies.repository.createSessionWithGrant({
      schemaVersion: 1,
      identityTokenHash: await hashAppleOpaqueToken(request.identityToken, dependencies.crypto),
      sessionHash,
      ownerId: identity.ownerId,
      principalId: identity.principalId,
      appleSubjectHash,
      activationState: 'pending',
      createdAt: now,
      expiresAt: sessionExpiresAt,
      identityTokenExpiresAt: exchangedClaims.expiresAt,
    }, {
      ...grantBase,
      encryptedCredentials: await encryptNativeGrant(credentials, grantBase, dependencies),
    }, callbackClaims.issuedAt);
    if (!created) {
      throw new AppleAuthError(
        409,
        'APPLE_NATIVE_CREDENTIAL_REPLAY',
        'This Apple authorization credential was already exchanged.',
      );
    }
    await dependencies.repository.completeAuthorizationExchangeLease({
      ...authorizationLease,
      now: dependencies.now(),
    });
    return {
      schemaVersion: 2,
      activationState: 'pending',
      tokenType: 'Bearer',
      token,
      expiresAt: sessionExpiresAt,
      accountMode: appleAccountModeForOwner(identity.ownerId),
    };
  } catch (error) {
    let revoked = false;
    try {
      await revokeAppleNativeRefreshToken(tokenResponse.refreshToken, dependencies);
      revoked = true;
    } catch {
      // The pre-exchange durable marker remains for account-deletion manual follow-up.
    }
    if (revoked) await releaseNativeAuthorizationLeaseAfterConfirmedCompensation(
      dependencies.repository,
      authorizationLease.leaseToken,
      dependencies.now(),
    );
    throw error;
  }
}

async function releaseNativeAuthorizationLeaseAfterConfirmedCompensation(
  repository: AppleNativeAuthRepository,
  leaseToken: string,
  now: number,
): Promise<void> {
  try {
    await repository.releaseAuthorizationExchangeLease(leaseToken, now);
  } catch {
    // Keeping the durable possible-credential marker is the fail-closed outcome.
  }
}

export async function refreshAppleNativeSession(
  dependencies: AppleNativeAuthDependencies,
  token: string,
): Promise<AppleNativeActiveSessionResult | null> {
  const now = dependencies.now();
  const sessionHash = await hashAppleOpaqueToken(token, dependencies.crypto);
  const stored = await dependencies.repository.readSessionWithGrant(sessionHash, now);
  if (stored === null) return null;
  const credentials = await decryptAppleNativeGrant(stored.grant, dependencies);
  const refreshed = await refreshAppleNativeAuthorization(credentials.refreshToken, dependencies);
  const claims = await verifyExchangedNativeAppleIdentityToken(refreshed.idToken, dependencies);
  try {
    await requireStoredGrantContinuity(stored.grant, credentials, claims, dependencies);
  } catch (error) {
    await dependencies.repository.beginSessionRevocation(sessionHash, now);
    try {
      await revokeAppleNativeRefreshToken(credentials.refreshToken, dependencies);
      await dependencies.repository.deleteGrant(stored.grant.grantHash);
    } catch {
      await dependencies.repository.markGrantRevocationPending(stored.grant.grantHash, now);
    }
    throw error;
  }
  const sessionExpiresAt = now + NATIVE_SESSION_LIFETIME_SECONDS;
  const updatedGrant = {
    ...stored.grant,
    lastValidatedAt: now,
    expiresAt: now + NATIVE_GRANT_LIFETIME_SECONDS,
  };
  const encryptedCredentials = await encryptNativeGrant(credentials, updatedGrant, dependencies);
  const updated = await dependencies.repository.updateSessionAndGrant({
    sessionHash,
    ownerId: stored.grant.ownerId,
    principalId: stored.grant.principalId,
    appleSubjectHash: stored.grant.appleSubjectHash,
    expectedEncryptedCredentials: stored.grant.encryptedCredentials,
    expectedLastValidatedAt: stored.grant.lastValidatedAt,
    encryptedCredentials,
    lastValidatedAt: now,
    sessionExpiresAt,
    identityTokenExpiresAt: claims.expiresAt,
    grantExpiresAt: updatedGrant.expiresAt,
  });
  if (!updated) {
    throw new AppleAuthError(
      409,
      'APPLE_NATIVE_SESSION_CHANGED',
      'The native session changed while Apple revalidated it.',
    );
  }
  const finalState = await dependencies.repository.readSessionWithGrant(
    sessionHash,
    dependencies.now(),
  );
  if (
    finalState === null
    || finalState.session.ownerId !== stored.session.ownerId
    || finalState.session.appleSubjectHash !== stored.session.appleSubjectHash
    || finalState.session.expiresAt !== sessionExpiresAt
    || finalState.session.identityTokenExpiresAt !== claims.expiresAt
    || finalState.grant.grantHash !== stored.grant.grantHash
    || finalState.grant.principalId !== stored.grant.principalId
    || finalState.grant.encryptedCredentials !== encryptedCredentials
    || finalState.grant.lastValidatedAt !== now
    || finalState.grant.expiresAt !== updatedGrant.expiresAt
    || finalState.grant.revocationPendingAt !== null
  ) {
    throw new AppleAuthError(
      409,
      'APPLE_NATIVE_SESSION_CHANGED',
      'The native session changed before the refreshed bearer could return.',
    );
  }
  return {
    schemaVersion: 2,
    activationState: 'active',
    tokenType: 'Bearer',
    token,
    expiresAt: sessionExpiresAt,
    accountMode: appleAccountModeForOwner(stored.session.ownerId),
  };
}

export async function activateAppleNativeSession(
  dependencies: AppleNativeAuthDependencies,
  token: string,
): Promise<AppleNativeActiveSessionResult | null> {
  const now = dependencies.now();
  const session = await dependencies.repository.activateSession(
    await hashAppleOpaqueToken(token, dependencies.crypto),
    now,
  );
  if (session === null) return null;
  return {
    schemaVersion: 2,
    activationState: 'active',
    tokenType: 'Bearer',
    token,
    expiresAt: session.expiresAt,
    accountMode: appleAccountModeForOwner(session.ownerId),
  };
}

function requireClaimContinuity(
  callback: {subject: string; transferSubject: string | null},
  exchanged: {subject: string; transferSubject: string | null},
): void {
  if (!constantTimeEqual(callback.subject, exchanged.subject)) {
    throw new AppleAuthError(400, 'APPLE_TOKEN_SUBJECT_MISMATCH', 'Apple returned different users for the callback and code exchange.');
  }
  if (!optionalConstantTimeEqual(callback.transferSubject, exchanged.transferSubject)) {
    throw new AppleAuthError(400, 'APPLE_TOKEN_TRANSFER_MISMATCH', 'Apple returned different transfer identifiers for the callback and code exchange.');
  }
}

async function requireStoredGrantContinuity(
  record: AppleNativeGrantRecord,
  credentials: StoredGrantCredentials,
  claims: {subject: string; transferSubject: string | null},
  dependencies: AppleNativeAuthDependencies,
): Promise<void> {
  if (
    !constantTimeEqual(credentials.subject, claims.subject)
    || !optionalConstantTimeEqual(credentials.transferSubject, claims.transferSubject)
    || !constantTimeEqual(record.appleSubjectHash, await hashAppleSubject(claims.subject, dependencies))
  ) {
    throw new AppleAuthError(
      401,
      'APPLE_NATIVE_GRANT_SUBJECT_CHANGED',
      'Apple returned a different user while revalidating the native grant.',
    );
  }
}

export function parseAppleNativeBearer(request: Request): string | null {
  const authorization = request.headers.get('authorization');
  if (authorization === null) return null;
  const match = /^Bearer (v1\.[A-Za-z0-9_-]{43})$/i.exec(authorization);
  if (!match) {
    throw new AppleAuthError(401, 'APPLE_NATIVE_SESSION_INVALID', 'The native bearer session is invalid.');
  }
  return match[1];
}

export async function readAppleNativeSession(
  repository: AppleNativeAuthRepository,
  token: string,
  now: number,
  webCrypto: Crypto,
): Promise<AppleNativeSession | null> {
  return repository.readSession(await hashAppleOpaqueToken(token, webCrypto), now);
}

export async function revokeAppleNativeSession(
  dependencies: AppleNativeAuthDependencies,
  token: string,
): Promise<boolean> {
  const now = dependencies.now();
  const sessionHash = await hashAppleOpaqueToken(token, dependencies.crypto);
  const pending = await dependencies.repository.beginSessionRevocation(sessionHash, now);
  if (!pending.found) {
    await dependencies.repository.cleanupSessions(now, CLEANUP_BATCH_SIZE);
    return false;
  }
  if (pending.grant !== null) {
    try {
      const credentials = await decryptAppleNativeGrant(pending.grant, dependencies);
      await revokeAppleNativeRefreshToken(credentials.refreshToken, dependencies);
      if (!await dependencies.repository.deleteGrant(pending.grant.grantHash)) {
        throw new AppleAuthError(
          503,
          'APPLE_NATIVE_GRANT_DELETE_FAILED',
          'Apple revoked the native grant, but local grant cleanup needs another retry.',
        );
      }
    } catch (error) {
      await dependencies.repository.markGrantRevocationPending(pending.grant.grantHash, now);
      if (error instanceof AppleAuthError) throw error;
      throw new AppleAuthError(
        503,
        'APPLE_NATIVE_REVOCATION_UNAVAILABLE',
        'The native session was disabled locally, but Apple grant revocation needs another retry.',
      );
    }
  }
  await dependencies.repository.cleanupSessions(now, CLEANUP_BATCH_SIZE);
  return true;
}

export async function decryptAppleNativeGrant(
  record: AppleNativeGrantRecord,
  dependencies: Pick<AppleNativeProviderDependencies, 'configuration' | 'crypto'>,
): Promise<StoredGrantCredentials> {
  const expectedOwnerBinding = await nativeGrantOwnerBinding(
    record.ownerId,
    record.appleSubjectHash,
    dependencies.crypto,
  );
  if (!constantTimeEqual(record.ownerBinding, expectedOwnerBinding)) {
    throw new AppleAuthError(401, 'APPLE_NATIVE_GRANT_INVALID', 'The native Apple grant owner binding is invalid.');
  }
  try {
    return storedGrantCredentialsSchema.parse(JSON.parse(await decryptAppleStorageRecord(
      record.encryptedCredentials,
      nativeGrantAdditionalData(record),
      dependencies,
    )));
  } catch {
    throw new AppleAuthError(401, 'APPLE_NATIVE_GRANT_INVALID', 'The native Apple grant could not be authenticated.');
  }
}

export async function revokeAppleNativeGrantsForAccountDeletion(
  dependencies: AppleNativeProviderDependencies,
  records: AppleNativeGrantRecord[],
): Promise<AppleCredentialRevocationSummary> {
  const refreshTokens = new Set<string>();
  let unreadableSessions = 0;
  for (const record of records) {
    try {
      refreshTokens.add((await decryptAppleNativeGrant(record, dependencies)).refreshToken);
    } catch {
      unreadableSessions += 1;
    }
  }
  const outcomes = await Promise.all([...refreshTokens].map(async refreshToken => {
    try {
      await revokeAppleNativeRefreshToken(refreshToken, dependencies);
      return true;
    } catch {
      return false;
    }
  }));
  const credentialsRevoked = outcomes.filter(Boolean).length;
  const failedRevocations = outcomes.length - credentialsRevoked;
  return {
    credentialsFound: refreshTokens.size,
    credentialsRevoked,
    unreadableSessions,
    failedRevocations,
    manualRevocationRequired:
      refreshTokens.size === 0 || unreadableSessions > 0 || failedRevocations > 0,
  };
}

export async function revokeExpiredAppleNativeGrants(
  dependencies: AppleNativeAuthDependencies,
  limit = CLEANUP_BATCH_SIZE,
): Promise<{found: number; revoked: number; failed: number}> {
  assertAppleNativeGrantRetentionBounds(limit, 1, dependencies.revocationTimeoutMilliseconds);
  const now = dependencies.now();
  return revokeExpiredAppleNativeGrantsAt(dependencies, now, now, limit);
}

async function revokeExpiredAppleNativeGrantsAt(
  dependencies: AppleNativeAuthDependencies,
  eligibilityCutoff: number,
  claimedAt: number,
  limit: number,
): Promise<{found: number; revoked: number; failed: number}> {
  const records = await dependencies.repository.claimExpiredSessionGrants(
    eligibilityCutoff,
    claimedAt,
    limit,
  );
  let revoked = 0;
  let failed = 0;
  for (const record of records) {
    try {
      const credentials = await decryptAppleNativeGrant(record, dependencies);
      await revokeAppleNativeRefreshToken(credentials.refreshToken, dependencies);
      if (!await dependencies.repository.deleteClaimedExpiredGrant(
        record.grantHash,
        claimedAt,
      )) throw new Error('claimed grant delete failed');
      revoked += 1;
    } catch {
      failed += 1;
    }
  }
  await dependencies.repository.cleanupSessions(eligibilityCutoff, limit);
  return {found: records.length, revoked, failed};
}

export async function drainExpiredAppleNativeGrants(
  dependencies: AppleNativeAuthDependencies,
  options: {batchLimit?: number; maximumBatches?: number; cutoff?: number} = {},
): Promise<{
  batches: number;
  found: number;
  revoked: number;
  failed: number;
  backlog: boolean;
}> {
  const batchLimit = options.batchLimit ?? APPLE_NATIVE_GRANT_RETENTION_BATCH_LIMIT;
  const maximumBatches = options.maximumBatches ?? APPLE_NATIVE_GRANT_RETENTION_MAX_BATCHES;
  if (!Number.isSafeInteger(batchLimit) || batchLimit <= 0) {
    throw new TypeError('Native Apple grant retention requires a positive batch limit.');
  }
  if (!Number.isSafeInteger(maximumBatches) || maximumBatches <= 0) {
    throw new TypeError('Native Apple grant retention requires a positive maximum batch count.');
  }
  assertAppleNativeGrantRetentionBounds(
    batchLimit,
    maximumBatches,
    dependencies.revocationTimeoutMilliseconds,
  );

  let batches = 0;
  let found = 0;
  let revoked = 0;
  let failed = 0;
  const cutoff = options.cutoff ?? dependencies.now();
  if (!Number.isSafeInteger(cutoff) || cutoff < 0) {
    throw new TypeError('Native Apple grant retention requires a valid cutoff.');
  }
  while (batches < maximumBatches) {
    const claimedAt = dependencies.now();
    if (!Number.isSafeInteger(claimedAt) || claimedAt < 0) {
      throw new TypeError('Native Apple grant retention requires a valid claim time.');
    }
    const result = await revokeExpiredAppleNativeGrantsAt(
      dependencies,
      cutoff,
      claimedAt,
      batchLimit,
    );
    batches += 1;
    found += result.found;
    revoked += result.revoked;
    failed += result.failed;
    if (result.found < batchLimit) {
      return {batches, found, revoked, failed, backlog: false};
    }
  }
  const backlog = await dependencies.repository.hasExpiredSessionGrant(cutoff, dependencies.now());
  return {batches, found, revoked, failed, backlog};
}

async function encryptNativeGrant(
  credentials: StoredGrantCredentials,
  record: Pick<
    AppleNativeGrantRecord,
    'grantHash' | 'sessionHash' | 'ownerId' | 'appleSubjectHash'
  >,
  dependencies: Pick<AppleNativeProviderDependencies, 'configuration' | 'crypto'>,
): Promise<string> {
  return encryptAppleStorageRecord(
    JSON.stringify(credentials),
    nativeGrantAdditionalData(record),
    dependencies,
  );
}

function nativeGrantAdditionalData(record: Pick<
  AppleNativeGrantRecord,
  'grantHash' | 'sessionHash' | 'ownerId' | 'appleSubjectHash'
>): string {
  return [
    'apple-native-grant-v1',
    record.grantHash,
    record.sessionHash,
    record.ownerId,
    record.appleSubjectHash,
  ].join('\0');
}

async function nativeGrantOwnerBinding(
  ownerId: string,
  appleSubjectHash: string,
  cryptoProvider: Crypto,
): Promise<string> {
  return hashAppleOpaqueToken(`native-grant-owner\0${ownerId}\0${appleSubjectHash}`, cryptoProvider);
}

function constantTimeEqual(left: string, right: string): boolean {
  const maximum = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < maximum; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function optionalConstantTimeEqual(left: string | null, right: string | null): boolean {
  if (left === null || right === null) return left === right;
  return constantTimeEqual(left, right);
}

export function appleNativeDependenciesWithDefaults(
  dependencies: Omit<AppleNativeAuthDependencies, 'revocationTimeoutMilliseconds'>
    & {revocationTimeoutMilliseconds?: number},
): AppleNativeAuthDependencies {
  return {
    ...dependencies,
    revocationTimeoutMilliseconds:
      dependencies.revocationTimeoutMilliseconds ?? APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
  };
}
