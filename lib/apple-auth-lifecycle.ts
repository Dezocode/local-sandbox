import {
  type AppleAuthDependencies,
  AppleAuthError,
  type AppleAuthSessionRecord,
  type AppleCredentialRevocationSummary,
  type VerifiedAppleServerNotification,
  appleAccountModeForOwner,
  hashAppleOpaqueToken,
  revokeAppleCredentialsForAccountDeletion,
  verifyAppleServerNotification,
} from './apple-auth.ts';
import {
  type AppleNativeGrantRecord,
  revokeAppleNativeGrantsForAccountDeletion,
} from './apple-native-auth.ts';

export const APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
export const APPLE_ACCOUNT_DELETION_REVOCATION_LEASE_SECONDS = 60;
export const APPLE_ACCOUNT_DELETION_REVOCATION_SESSION_LIMIT = 8;
export const APPLE_ACCOUNT_DELETION_ORIGIN_INSTALLATION_LIMIT = 8;
export const APPLE_ACCOUNT_DELETION_ORIGIN_TIMEOUT_MILLISECONDS = 5_000;

export type OriginConnectionRevocationSummary = {
  installationsFound: number;
  installationsRevoked: number;
  unreadableInstallations: number;
  failedRevocations: number;
  manualRevocationRequired: boolean;
};

export type OriginConnectionRevocationDependencies = {
  revokeInstallation(installationId: string, signal: AbortSignal): Promise<void>;
};

export type AppleAccountDeletionReceipt = {
  ownerBinding: string;
  providerCredentials: AppleCredentialRevocationSummary;
  originConnections: OriginConnectionRevocationSummary;
};

export type AppleAccountDeletionAttempt = {
  ownerId: string;
  appleSubjectHash: string;
  deleteOwnerData: boolean;
  providerCredentials: AppleCredentialRevocationSummary | null;
  originConnections: OriginConnectionRevocationSummary | null;
};

export type AppleAccountDeletionSessionRead = {
  sessions: AppleAuthSessionRecord[];
  nativeGrants?: AppleNativeGrantRecord[];
  unreadableSessions: number;
};

export type AppleAccountDeletionOriginInstallationRead = {
  installationIds: string[];
  unreadableInstallations: number;
};

export type AppleAccountDeletionRepository = {
  readDeletionReceipt(
    deletionKeyHash: string,
    now: number,
  ): Promise<AppleAccountDeletionReceipt | null>;
  readDeletionAttempt(
    deletionKeyHash: string,
    now: number,
  ): Promise<AppleAccountDeletionAttempt | null>;
  beginAppleAccountDeletion(input: {
    ownerId: string;
    appleSubjectHash: string;
    deleteOwnerData: boolean;
    ownerBinding: string;
    deletionKeyHash: string;
    revocationLeaseToken: string;
    startedAt: number;
    leaseClaimedAt: number;
    expiresAt: number;
  }): Promise<AppleAccountDeletionReceipt | null>;
  readWebSessionsForDeletion(input: {
    ownerId: string;
    appleSubjectHash: string;
    deleteOwnerData: boolean;
  }): Promise<AppleAccountDeletionSessionRead>;
  readOriginInstallationsForDeletion(input: {
    ownerId: string;
    appleSubjectHash: string;
    deleteOwnerData: boolean;
  }): Promise<AppleAccountDeletionOriginInstallationRead>;
  deleteAppleAccessAndCompleteReceipt(input: {
    ownerId: string;
    appleSubjectHash: string;
    deleteOwnerData: boolean;
    ownerBinding: string;
    deletionKeyHash: string;
    revocationLeaseToken: string;
    providerCredentials: AppleCredentialRevocationSummary;
    originConnections: OriginConnectionRevocationSummary;
    originUnresolvedInstallationIds?: string[];
    completedAt: number;
    expiresAt: number;
  }): Promise<{
    created: boolean;
    providerCredentials: AppleCredentialRevocationSummary;
    originConnections: OriginConnectionRevocationSummary;
  }>;
  beginServerNotification(
    notification: VerifiedAppleServerNotification,
    now: number,
  ): Promise<{idempotent: boolean; ownerId: string | null}>;
};

export type AppleAccountDeletionResult = {
  deleted: true;
  idempotent: boolean;
  providerCredentials: AppleCredentialRevocationSummary;
  originConnections: OriginConnectionRevocationSummary;
};

export function parseAppleAccountDeletionKey(request: Request): string {
  const value = request.headers.get('idempotency-key');
  if (value === null || !isCanonicalAppleAccountDeletionKey(value)) {
    throw new AppleAuthError(
      400,
      'APPLE_ACCOUNT_DELETION_KEY_INVALID',
      'Account deletion requires a random versioned Idempotency-Key.',
    );
  }
  return value;
}

export function isCanonicalAppleAccountDeletionKey(value: string): boolean {
  const match = /^v1\.([A-Za-z0-9_-]{43})$/.exec(value);
  if (match === null) return false;
  try {
    const bytes = atob(`${match[1].replaceAll('-', '+').replaceAll('_', '/')}=`);
    const canonical = btoa(bytes)
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '');
    return bytes.length === 32 && canonical === match[1];
  } catch {
    return false;
  }
}

export async function requireEmptyAppleAccountDeletionBody(request: Request): Promise<void> {
  const declaredLength = request.headers.get('content-length');
  if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || declaredLength !== '0')) {
    throw invalidAccountDeletionBody();
  }
  if (request.body === null) return;
  const reader = request.body.getReader();
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) return;
    if (chunk.value.byteLength > 0) {
      await reader.cancel();
      throw invalidAccountDeletionBody();
    }
  }
}

function invalidAccountDeletionBody(): AppleAuthError {
  return new AppleAuthError(
    400,
    'APPLE_ACCOUNT_DELETION_BODY_INVALID',
    'Account deletion does not accept a request body.',
  );
}

export async function readCompletedAppleAccountDeletion(input: {
  repository: AppleAccountDeletionRepository;
  deletionKey: string;
  crypto: Crypto;
  now: number;
}): Promise<AppleAccountDeletionResult | null> {
  const providerCredentials = await input.repository.readDeletionReceipt(
    await hashAppleOpaqueToken(input.deletionKey, input.crypto),
    input.now,
  );
  return providerCredentials === null ? null : {
    deleted: true,
    idempotent: true,
    providerCredentials: providerCredentials.providerCredentials,
    originConnections: providerCredentials.originConnections,
  };
}

export async function recoverAppleAccountDeletion(input: {
  repository: AppleAccountDeletionRepository;
  authDependencies: AppleAuthDependencies | null;
  deletionKey: string;
  crypto: Crypto;
  now: number;
  completionNow?: () => number;
  originDependencies?: OriginConnectionRevocationDependencies | null;
  revocationLeaseToken?: () => string;
}): Promise<AppleAccountDeletionResult | null> {
  const attempt = await input.repository.readDeletionAttempt(
    await hashAppleOpaqueToken(input.deletionKey, input.crypto),
    input.now,
  );
  if (attempt === null) return null;
  if (attempt.providerCredentials !== null && attempt.originConnections !== null) {
    return {
      deleted: true,
      idempotent: true,
      providerCredentials: attempt.providerCredentials,
      originConnections: attempt.originConnections,
    };
  }
  return deleteAppleAccount({
    repository: input.repository,
    authDependencies: input.authDependencies,
    ownerId: attempt.ownerId,
    appleSubjectHash: attempt.appleSubjectHash,
    deletionKey: input.deletionKey,
    crypto: input.crypto,
    now: input.now,
    completionNow: input.completionNow,
    originDependencies: input.originDependencies,
    revocationLeaseToken: input.revocationLeaseToken,
  });
}

export async function deleteAppleAccount(input: {
  repository: AppleAccountDeletionRepository;
  authDependencies: AppleAuthDependencies | null;
  ownerId: string;
  appleSubjectHash: string;
  deletionKey: string;
  crypto: Crypto;
  now: number;
  completionNow?: () => number;
  originDependencies?: OriginConnectionRevocationDependencies | null;
  revocationLeaseToken?: () => string;
}): Promise<AppleAccountDeletionResult> {
  const deletionKeyHash = await hashAppleOpaqueToken(input.deletionKey, input.crypto);
  const ownerBinding = await hashAppleOpaqueToken(
    `owner\0${input.ownerId}\0apple-subject\0${input.appleSubjectHash}`,
    input.crypto,
  );
  const deleteOwnerData = appleAccountModeForOwner(input.ownerId) === 'standalone';
  const revocationLeaseToken = input.revocationLeaseToken?.()
    ?? createAppleAccountDeletionLeaseToken(input.crypto);
  if (!isCanonicalAppleAccountDeletionKey(`v1.${revocationLeaseToken}`)) {
    throw new AppleAuthError(
      503,
      'APPLE_ACCOUNT_DELETION_LEASE_INVALID',
      'Account deletion could not create a secure provider-cleanup lease.',
    );
  }
  const completed = await input.repository.readDeletionReceipt(deletionKeyHash, input.now);
  if (completed !== null) {
    if (completed.ownerBinding !== ownerBinding) {
      throw new AppleAuthError(
        409,
        'APPLE_ACCOUNT_DELETION_KEY_CONFLICT',
        'This account deletion key belongs to a different account.',
      );
    }
    return {
      deleted: true,
      idempotent: true,
      providerCredentials: completed.providerCredentials,
      originConnections: completed.originConnections,
    };
  }

  const leaseClaimedAt = freshCompletionTime(input);
  const racedCompletion = await input.repository.beginAppleAccountDeletion({
    ownerId: input.ownerId,
    appleSubjectHash: input.appleSubjectHash,
    deleteOwnerData,
    ownerBinding,
    deletionKeyHash,
    revocationLeaseToken,
    startedAt: input.now,
    leaseClaimedAt,
    expiresAt: input.now + APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_SECONDS,
  });
  if (racedCompletion !== null) {
    return {
      deleted: true,
      idempotent: true,
      providerCredentials: racedCompletion.providerCredentials,
      originConnections: racedCompletion.originConnections,
    };
  }

  const sessionRead = await input.repository.readWebSessionsForDeletion({
    ownerId: input.ownerId,
    appleSubjectHash: input.appleSubjectHash,
    deleteOwnerData,
  });
  const sessions = sessionRead.sessions.slice(
    0,
    APPLE_ACCOUNT_DELETION_REVOCATION_SESSION_LIMIT,
  );
  const allNativeGrants = sessionRead.nativeGrants ?? [];
  const nativeGrants = allNativeGrants.slice(
    0,
    APPLE_ACCOUNT_DELETION_REVOCATION_SESSION_LIMIT,
  );
  const omittedSessions = sessionRead.sessions.length - sessions.length
    + allNativeGrants.length - nativeGrants.length;
  const unreadableSessions = sessionRead.unreadableSessions + omittedSessions;
  const [providerCredentials, originCleanup] = await Promise.all([
    revokeDeletionProviderCredentials(
      input.authDependencies,
      sessions,
      nativeGrants,
      unreadableSessions,
    ),
    revokeOriginConnectionsForAccountDeletion({
      repository: input.repository,
      ownerId: input.ownerId,
      appleSubjectHash: input.appleSubjectHash,
      deleteOwnerData,
      originDependencies: input.originDependencies,
    }),
  ]);
  const completionAt = freshCompletionTime(input);
  const deletion = await input.repository.deleteAppleAccessAndCompleteReceipt({
    ownerId: input.ownerId,
    appleSubjectHash: input.appleSubjectHash,
    deleteOwnerData,
    ownerBinding,
    deletionKeyHash,
    revocationLeaseToken,
    providerCredentials,
    originConnections: originCleanup.summary,
    completedAt: completionAt,
    expiresAt: completionAt + APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_SECONDS,
  });
  return {
    deleted: true,
    idempotent: !deletion.created,
    providerCredentials: deletion.providerCredentials,
    originConnections: deletion.originConnections,
  };
}

function createAppleAccountDeletionLeaseToken(cryptoProvider: Crypto): string {
  const bytes = cryptoProvider.getRandomValues(new Uint8Array(32));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

async function revokeOriginConnectionsForAccountDeletion(input: {
  repository: AppleAccountDeletionRepository;
  ownerId: string;
  appleSubjectHash: string;
  deleteOwnerData?: boolean;
  originDependencies?: OriginConnectionRevocationDependencies | null;
}): Promise<{
  summary: OriginConnectionRevocationSummary;
  unresolvedInstallationIds: string[];
}> {
  const stored = await input.repository.readOriginInstallationsForDeletion({
    ownerId: input.ownerId,
    appleSubjectHash: input.appleSubjectHash,
    deleteOwnerData: input.deleteOwnerData ?? false,
  });
  const installationIds = stored.installationIds.slice(
    0,
    APPLE_ACCOUNT_DELETION_ORIGIN_INSTALLATION_LIMIT,
  );
  const omitted = stored.installationIds.length - installationIds.length;
  const unreadableInstallations = stored.unreadableInstallations + omitted;
  const dependencies = input.originDependencies ?? null;
  const revoked = dependencies === null
    ? installationIds.map(() => false)
    : await Promise.all(installationIds.map(
        installationId => revokeOriginInstallationWithinBound(
          dependencies,
          installationId,
        ),
      ));
  const installationsRevoked = revoked.filter(Boolean).length;
  const failedRevocations = installationIds.length - installationsRevoked;
  return {
    summary: {
      installationsFound: installationIds.length + unreadableInstallations,
      installationsRevoked,
      unreadableInstallations,
      failedRevocations,
      manualRevocationRequired: unreadableInstallations > 0 || failedRevocations > 0,
    },
    unresolvedInstallationIds: installationIds.filter((_, index) => !revoked[index]),
  };
}

async function revokeOriginInstallationWithinBound(
  dependencies: OriginConnectionRevocationDependencies,
  installationId: string,
): Promise<boolean> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<false>(resolve => {
    timeout = setTimeout(() => {
      controller.abort();
      resolve(false);
    }, APPLE_ACCOUNT_DELETION_ORIGIN_TIMEOUT_MILLISECONDS);
  });
  const request = dependencies.revokeInstallation(installationId, controller.signal)
    .then(() => true as const, () => false as const);
  try {
    return await Promise.race([request, deadline]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

function freshCompletionTime(input: {
  now: number;
  completionNow?: () => number;
  authDependencies: AppleAuthDependencies | null;
}): number {
  const value = input.completionNow?.() ?? input.authDependencies?.now() ?? input.now;
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new AppleAuthError(
      503,
      'APPLE_ACCOUNT_DELETION_CLOCK_INVALID',
      'Account deletion could not record a valid completion time.',
    );
  }
  return Math.max(input.now, value);
}

function verifiedCompletionTime(now: number, clock?: () => number): number {
  const value = clock?.() ?? now;
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new AppleAuthError(
      503,
      'APPLE_ACCOUNT_DELETION_CLOCK_INVALID',
      'Account deletion could not record a valid completion time.',
    );
  }
  return Math.max(now, value);
}

function emptyRevocationSummary(unreadableSessions: number): AppleCredentialRevocationSummary {
  return {
    credentialsFound: 0,
    credentialsRevoked: 0,
    unreadableSessions,
    failedRevocations: 0,
    manualRevocationRequired: true,
  };
}

function addUnreadableSessions(
  summary: AppleCredentialRevocationSummary,
  unreadableSessions: number,
): AppleCredentialRevocationSummary {
  if (unreadableSessions === 0) return summary;
  const total = summary.unreadableSessions + unreadableSessions;
  if (!Number.isSafeInteger(total) || total < 0) {
    throw new AppleAuthError(
      503,
      'APPLE_ACCOUNT_SESSION_READ_INVALID',
      'Stored Apple account sessions could not be counted safely.',
    );
  }
  return {
    ...summary,
    unreadableSessions: total,
    manualRevocationRequired: true,
  };
}

async function revokeDeletionProviderCredentials(
  dependencies: AppleAuthDependencies | null,
  webSessions: AppleAuthSessionRecord[],
  nativeGrants: AppleNativeGrantRecord[],
  unreadableSessions: number,
): Promise<AppleCredentialRevocationSummary> {
  if (dependencies === null) {
    return emptyRevocationSummary(webSessions.length + nativeGrants.length + unreadableSessions);
  }
  const [web, native] = await Promise.all([
    revokeAppleCredentialsForAccountDeletion(dependencies, webSessions),
    revokeAppleNativeGrantsForAccountDeletion(dependencies, nativeGrants),
  ]);
  const combined = {
    credentialsFound: web.credentialsFound + native.credentialsFound,
    credentialsRevoked: web.credentialsRevoked + native.credentialsRevoked,
    unreadableSessions: web.unreadableSessions + native.unreadableSessions,
    failedRevocations: web.failedRevocations + native.failedRevocations,
    manualRevocationRequired: false,
  };
  combined.manualRevocationRequired = combined.credentialsFound === 0
    || combined.unreadableSessions > 0
    || combined.failedRevocations > 0;
  return addUnreadableSessions(combined, unreadableSessions);
}

export async function processAppleServerNotification(input: {
  repository: AppleAccountDeletionRepository;
  authDependencies: AppleAuthDependencies;
  token: string;
  originDependencies?: OriginConnectionRevocationDependencies | null;
}): Promise<{
  received: true;
  idempotent: boolean;
  eventType: string;
}> {
  const notification = await verifyAppleServerNotification(input.token, input.authDependencies);
  const result = await applyVerifiedAppleServerNotification({
    repository: input.repository,
    notification,
    now: input.authDependencies.now(),
    completionNow: input.authDependencies.now,
    crypto: input.authDependencies.crypto,
    authDependencies: input.authDependencies,
    originDependencies: input.originDependencies,
  });
  return {
    received: true,
    idempotent: result.idempotent,
    eventType: notification.kind === 'unknown' ? notification.eventType : notification.kind,
  };
}

export async function applyVerifiedAppleServerNotification(input: {
  repository: AppleAccountDeletionRepository;
  notification: VerifiedAppleServerNotification;
  crypto: Crypto;
  now: number;
  completionNow?: () => number;
  authDependencies?: AppleAuthDependencies | null;
  originDependencies?: OriginConnectionRevocationDependencies | null;
}): Promise<{idempotent: boolean}> {
  const registration = await input.repository.beginServerNotification(
    input.notification,
    input.now,
  );
  if (
    input.notification.kind !== 'consent-revoked'
    && input.notification.kind !== 'account-deleted'
  ) return {idempotent: registration.idempotent};
  if (registration.ownerId === null) return {idempotent: true};

  const deletionKeyHash = input.notification.notificationIdHash;
  const ownerBinding = input.notification.notificationIdHash;
  const deleteOwnerData = appleAccountModeForOwner(registration.ownerId) === 'standalone';
  const leaseClaimedAt = verifiedCompletionTime(input.now, input.completionNow);
  const revocationLeaseToken = createAppleAccountDeletionLeaseToken(input.crypto);
  const deletionReceiptExpiresAt = Math.min(
    input.notification.receiptExpiresAt,
    input.now + APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_SECONDS,
  );
  const completed = await input.repository.beginAppleAccountDeletion({
    ownerId: registration.ownerId,
    appleSubjectHash: input.notification.appleSubjectHash,
    deleteOwnerData,
    ownerBinding,
    deletionKeyHash,
    revocationLeaseToken,
    startedAt: input.notification.eventTime,
    leaseClaimedAt,
    expiresAt: deletionReceiptExpiresAt,
  });
  if (completed !== null) return {idempotent: true};

  const sessionRead = await input.repository.readWebSessionsForDeletion({
    ownerId: registration.ownerId,
    appleSubjectHash: input.notification.appleSubjectHash,
    deleteOwnerData,
  });
  const sessions = sessionRead.sessions.slice(0, APPLE_ACCOUNT_DELETION_REVOCATION_SESSION_LIMIT);
  const allNativeGrants = sessionRead.nativeGrants ?? [];
  const nativeGrants = allNativeGrants.slice(
    0,
    APPLE_ACCOUNT_DELETION_REVOCATION_SESSION_LIMIT,
  );
  const unreadableSessions = sessionRead.unreadableSessions
    + sessionRead.sessions.length - sessions.length
    + allNativeGrants.length - nativeGrants.length;
  const [providerCredentials, originCleanup] = await Promise.all([
    revokeDeletionProviderCredentials(
      input.authDependencies ?? null,
      sessions,
      nativeGrants,
      unreadableSessions,
    ),
    revokeOriginConnectionsForAccountDeletion({
      repository: input.repository,
      ownerId: registration.ownerId,
      appleSubjectHash: input.notification.appleSubjectHash,
      deleteOwnerData,
      originDependencies: input.originDependencies,
    }),
  ]);
  await input.repository.deleteAppleAccessAndCompleteReceipt({
    ownerId: registration.ownerId,
    appleSubjectHash: input.notification.appleSubjectHash,
    deleteOwnerData,
    ownerBinding,
    deletionKeyHash,
    revocationLeaseToken,
    providerCredentials,
    originConnections: originCleanup.summary,
    originUnresolvedInstallationIds: originCleanup.unresolvedInstallationIds,
    completedAt: verifiedCompletionTime(input.now, input.completionNow),
    expiresAt: deletionReceiptExpiresAt,
  });
  return {idempotent: registration.idempotent};
}
