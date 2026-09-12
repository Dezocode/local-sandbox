import { z } from 'zod';
import { BoundedResponseError, readBoundedResponseText } from './bounded-response.ts';

const APPLE_ISSUER = 'https://appleid.apple.com';
const APPLE_AUTHORIZE_URL = `${APPLE_ISSUER}/auth/authorize`;
const APPLE_TOKEN_URL = `${APPLE_ISSUER}/auth/token`;
export const APPLE_TOKEN_EXCHANGE_TIMEOUT_MILLISECONDS = 20_000;
const APPLE_KEYS_URL = `${APPLE_ISSUER}/auth/keys`;
const APPLE_REVOKE_URL = `${APPLE_ISSUER}/auth/revoke`;
const FLOW_LIFETIME_SECONDS = 10 * 60;
const SESSION_LIFETIME_SECONDS = 30 * 24 * 60 * 60;
const APPLE_REVALIDATION_SECONDS = 24 * 60 * 60;
const CLOCK_SKEW_SECONDS = 60;
const NATIVE_ID_TOKEN_MAX_AGE_SECONDS = 10 * 60;
const APPLE_NOTIFICATION_MAX_AGE_SECONDS = 24 * 60 * 60;
export const APPLE_NOTIFICATION_RECEIPT_LIFETIME_SECONDS = 90 * 24 * 60 * 60;
export const APPLE_REVOCATION_TIMEOUT_MILLISECONDS = 5_000;
export const APPLE_CLIENT_SECRET_LIFETIME_SECONDS = 5 * 60;

const configurationInputSchema = z.object({
  APPLE_AUTH_TEAM_ID: z.string().regex(/^[A-Z0-9]{10}$/),
  APPLE_AUTH_KEY_ID: z.string().regex(/^[A-Z0-9]{10}$/),
  APPLE_AUTH_CLIENT_ID: z.string().min(3).max(255).regex(/^[A-Za-z0-9.-]+$/),
  APPLE_AUTH_NATIVE_CLIENT_ID: z.string().min(3).max(255).regex(/^[A-Za-z0-9.-]+$/).optional(),
  APPLE_AUTH_REDIRECT_URI: z.string().url().max(500),
  APPLE_AUTH_PRIVATE_KEY_P8: z.string().min(100).max(10_000),
  APPLE_AUTH_STORAGE_KEY: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
}).strict();

export type AppleAuthConfiguration = {
  schemaVersion: 1;
  teamId: string;
  keyId: string;
  clientId: string;
  nativeClientId: string | null;
  redirectUri: string;
  privateKeyPem: string;
  storageKey: string;
};

export type AppleAuthEnvironment = {
  APPLE_AUTH_TEAM_ID?: string;
  APPLE_AUTH_KEY_ID?: string;
  APPLE_AUTH_CLIENT_ID?: string;
  APPLE_AUTH_NATIVE_CLIENT_ID?: string;
  APPLE_AUTH_REDIRECT_URI?: string;
  APPLE_AUTH_PRIVATE_KEY_P8?: string;
  APPLE_AUTH_STORAGE_KEY?: string;
};

export class AppleAuthError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'AppleAuthError';
    this.status = status;
    this.code = code;
  }
}

function invalidConfiguration(): AppleAuthError {
  return new AppleAuthError(
    503,
    'APPLE_AUTH_NOT_CONFIGURED',
    'Sign in with Apple is not configured on this server.',
  );
}

export function parseAppleAuthConfiguration(environment: AppleAuthEnvironment): AppleAuthConfiguration {
  const parsed = configurationInputSchema.safeParse(environment);
  if (!parsed.success) throw invalidConfiguration();

  const redirect = new URL(parsed.data.APPLE_AUTH_REDIRECT_URI);
  if (
    redirect.protocol !== 'https:' ||
    redirect.hash !== '' ||
    redirect.username !== '' ||
    redirect.password !== '' ||
    redirect.hostname === 'localhost' ||
    isIPAddress(redirect.hostname) ||
    base64URLDecode(parsed.data.APPLE_AUTH_STORAGE_KEY).byteLength !== 32
  ) {
    throw invalidConfiguration();
  }

  const privateKeyPem = parsed.data.APPLE_AUTH_PRIVATE_KEY_P8.includes('\n')
    ? parsed.data.APPLE_AUTH_PRIVATE_KEY_P8
    : parsed.data.APPLE_AUTH_PRIVATE_KEY_P8.replaceAll('\\n', '\n');
  if (!/^-----BEGIN PRIVATE KEY-----\n[\s\S]+\n-----END PRIVATE KEY-----\n?$/.test(privateKeyPem)) {
    throw invalidConfiguration();
  }

  return {
    schemaVersion: 1,
    teamId: parsed.data.APPLE_AUTH_TEAM_ID,
    keyId: parsed.data.APPLE_AUTH_KEY_ID,
    clientId: parsed.data.APPLE_AUTH_CLIENT_ID,
    nativeClientId: parsed.data.APPLE_AUTH_NATIVE_CLIENT_ID ?? null,
    redirectUri: redirect.toString(),
    privateKeyPem,
    storageKey: parsed.data.APPLE_AUTH_STORAGE_KEY,
  };
}

function isIPAddress(hostname: string): boolean {
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) return true;
  return hostname.includes(':');
}

type AppleAuthFlowBase = {
  schemaVersion: 2;
  stateHash: string;
  nonceHash: string;
  browserBindingHash: string;
  ownerBinding: string;
  returnTo: string;
  createdAt: number;
  expiresAt: number;
};

export type AppleAuthPurpose = 'authenticate' | 'link';

export type AppleAuthFlow = AppleAuthFlowBase & (
  | {purpose: 'authenticate'; ownerId: null}
  | {purpose: 'link'; ownerId: string}
);

export type AppleAuthorizationIntent =
  | {purpose: 'authenticate'}
  | {purpose: 'link'; ownerId: string};

export type AppleAuthSessionRecord = {
  schemaVersion: 1 | 2;
  sessionHash: string;
  ownerId: string;
  ownerBinding: string;
  appleSubjectHash: string;
  encryptedCredentials: string;
  createdAt: number;
  expiresAt: number;
  lastValidatedAt: number;
};

export type AppleAuthSessionUpdate = {
  expected: AppleAuthSessionRecord;
  next: AppleAuthSessionRecord;
  now: number;
};

export type AppleAuthorizationExchangeLease = {
  leaseToken: string;
  ownerId: string;
  appleSubjectHash: string;
  authorizationStartedAt: number;
  now: number;
};

export type AppleAuthRepository = {
  createFlow(flow: AppleAuthFlow): Promise<void>;
  consumeFlow(stateHash: string, now: number): Promise<AppleAuthFlow | null>;
  createSession(session: AppleAuthSessionRecord, authorizationStartedAt?: number): Promise<void>;
  readSession(sessionHash: string, now: number): Promise<AppleAuthSessionRecord | null>;
  readLatestSessionForSubject(
    appleSubjectHash: string,
    now: number,
  ): Promise<AppleAuthSessionRecord | null>;
  updateSession(update: AppleAuthSessionUpdate): Promise<void>;
  revokeSession(sessionHash: string, revokedAt: number): Promise<boolean>;
  linkAppleIdentity(link: AppleIdentityLink, authorizationStartedAt?: number): Promise<'linked' | 'owner-conflict'>;
  resolveAppleOwner(link: AppleIdentityLink, authorizationStartedAt?: number): Promise<{ownerId: string; created: boolean}>;
  resolveAppleIdentityGroup(input: {
    appleSubjectHashes: readonly string[];
    proposedOwnerId: string;
    requiredOwnerId: string | null;
    createdAt: number;
    updatedAt: number;
  }, authorizationStartedAt?: number): Promise<
    | {kind: 'linked'; ownerId: string; principalId: string; created: boolean}
    | {kind: 'owner-conflict'}
  >;
  readLinkedIdentity(appleSubjectHash: string): Promise<{
    ownerId: string;
    principalId: string;
    principalCreatedAt: number;
  } | null>;
  readLinkedOwner(appleSubjectHash: string): Promise<string | null>;
  claimAuthorizationExchangeLease(input: AppleAuthorizationExchangeLease): Promise<void>;
  markAuthorizationExchangePossible(leaseToken: string, now: number): Promise<void>;
  completeAuthorizationExchangeLease(input: AppleAuthorizationExchangeLease): Promise<void>;
  releaseAuthorizationExchangeLease(leaseToken: string, now: number): Promise<void>;
};

export type AppleIdentityLink = {
  appleSubjectHash: string;
  ownerId: string;
  createdAt: number;
  updatedAt: number;
};

export type AppleAuthFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export type AppleAuthDependencies = {
  configuration: AppleAuthConfiguration;
  repository: AppleAuthRepository;
  fetcher: AppleAuthFetch;
  crypto: Crypto;
  now: () => number;
  revocationTimeoutMilliseconds: number;
};

type AppleProviderTokenDependencies = Pick<
  AppleAuthDependencies,
  'configuration' | 'fetcher' | 'crypto' | 'now' | 'revocationTimeoutMilliseconds'
>;

export type AuthorizationStart = {
  schemaVersion: 1;
  authorizationUrl: string;
  browserBinding: string;
  expiresAt: number;
};

export async function startAppleAuthorization(
  dependencies: AppleAuthDependencies,
  intent: AppleAuthorizationIntent,
  requestedReturnTo: string | null,
): Promise<AuthorizationStart> {
  const now = dependencies.now();
  const state = randomVersionedToken(dependencies.crypto);
  const nonce = randomVersionedToken(dependencies.crypto);
  const browserBinding = randomVersionedToken(dependencies.crypto);
  const stateHash = await sha256(state, dependencies.crypto);
  const base: AppleAuthFlowBase = {
    schemaVersion: 2,
    stateHash,
    nonceHash: await sha256(nonce, dependencies.crypto),
    browserBindingHash: await sha256(browserBinding, dependencies.crypto),
    ownerBinding: intent.purpose === 'link'
      ? await keyedDigest('owner', intent.ownerId, dependencies)
      : await keyedDigest('authenticate-flow', stateHash, dependencies),
    returnTo: safeReturnTo(requestedReturnTo),
    createdAt: now,
    expiresAt: now + FLOW_LIFETIME_SECONDS,
  };
  const flow: AppleAuthFlow = intent.purpose === 'link'
    ? {...base, purpose: 'link', ownerId: intent.ownerId}
    : {...base, purpose: 'authenticate', ownerId: null};
  await dependencies.repository.createFlow(flow);

  const authorizationUrl = new URL(APPLE_AUTHORIZE_URL);
  authorizationUrl.searchParams.set('client_id', dependencies.configuration.clientId);
  authorizationUrl.searchParams.set('redirect_uri', dependencies.configuration.redirectUri);
  authorizationUrl.searchParams.set('response_type', 'code id_token');
  authorizationUrl.searchParams.set('scope', 'name email');
  authorizationUrl.searchParams.set('response_mode', 'form_post');
  authorizationUrl.searchParams.set('state', state);
  authorizationUrl.searchParams.set('nonce', nonce);

  return {
    schemaVersion: 1,
    authorizationUrl: authorizationUrl.toString(),
    browserBinding,
    expiresAt: flow.expiresAt,
  };
}

const appleUserSchema = z.object({
  name: z.object({
    firstName: z.string().max(100).regex(/^[^\u0000-\u001f\u007f]*$/),
    lastName: z.string().max(100).regex(/^[^\u0000-\u001f\u007f]*$/),
  }).strict(),
  email: z.string().email().max(320),
}).strict();

export const appleAuthorizationCallbackSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('success'),
    state: z.string().min(20).max(200),
    code: z.string().min(1).max(2_000),
    idToken: z.string().min(20).max(16_000),
    user: appleUserSchema.nullable(),
  }).strict(),
  z.object({
    kind: z.literal('cancelled'),
    state: z.string().min(20).max(200),
  }).strict(),
]);

export type AppleAuthorizationCallback = z.infer<typeof appleAuthorizationCallbackSchema>;

export async function parseAppleAuthorizationCallback(request: Request): Promise<AppleAuthorizationCallback> {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/x-www-form-urlencoded') {
    throw new AppleAuthError(415, 'APPLE_CALLBACK_CONTENT_TYPE', 'Apple callback must use form encoding.');
  }
  const body = await readAppleRequestBody(request, 20_000, 'callback');
  const parameters = new URLSearchParams(body);
  const allowed = new Set(['state', 'code', 'id_token', 'user', 'error']);
  for (const key of parameters.keys()) {
    if (!allowed.has(key) || parameters.getAll(key).length !== 1) {
      throw new AppleAuthError(400, 'APPLE_CALLBACK_INVALID', 'Apple callback contains invalid fields.');
    }
  }
  const state = parameters.get('state');
  if (!state) throw new AppleAuthError(400, 'APPLE_CALLBACK_INVALID', 'Apple callback is missing state.');

  const error = parameters.get('error');
  if (error !== null) {
    if (error !== 'user_cancelled_authorize') {
      throw new AppleAuthError(400, 'APPLE_CALLBACK_INVALID', 'Apple returned an unsupported authorization error.');
    }
    if (parameters.has('code') || parameters.has('id_token') || parameters.has('user')) {
      throw new AppleAuthError(400, 'APPLE_CALLBACK_INVALID', 'Apple callback mixes cancellation and authorization fields.');
    }
    return appleAuthorizationCallbackSchema.parse({kind: 'cancelled', state});
  }

  const serializedUser = parameters.get('user');
  let user: z.infer<typeof appleUserSchema> | null = null;
  if (serializedUser !== null) {
    try {
      user = appleUserSchema.parse(JSON.parse(serializedUser));
    } catch {
      throw new AppleAuthError(400, 'APPLE_CALLBACK_INVALID_USER', 'Apple user data is invalid.');
    }
  }
  return appleAuthorizationCallbackSchema.parse({
    kind: 'success',
    state,
    code: parameters.get('code'),
    idToken: parameters.get('id_token'),
    user,
  });
}

export type AppleSessionIdentity = {
  recordType: 'apple-auth-session';
  schemaVersion: 2;
  userId: string;
  email: string | null;
  emailVerified: boolean;
  displayName: string | null;
  expiresAt: number;
};

type StoredAppleCredentials = {
  recordType: 'apple-auth-credentials';
  schemaVersion: 2;
  subject: string;
  email: string | null;
  emailVerified: boolean;
  displayName: string | null;
  refreshToken: string;
  accessToken: string;
  accessTokenExpiresAt: number;
};

const storedCredentialsFields = {
  recordType: z.literal('apple-auth-credentials'),
  subject: z.string().min(1).max(255),
  email: z.string().email().max(320).nullable(),
  emailVerified: z.boolean(),
  displayName: z.string().min(1).max(201).nullable(),
  refreshToken: z.string().min(1).max(8_000),
  accessToken: z.string().min(1).max(8_000),
  accessTokenExpiresAt: z.number().int().positive(),
};
const storedCredentialsV1Schema = z.object({...storedCredentialsFields, schemaVersion: z.literal(1)}).strict();
const storedCredentialsV2Schema = z.object({...storedCredentialsFields, schemaVersion: z.literal(2)}).strict();

export type AuthorizationCompletion = {
  kind: 'authenticated';
  sessionToken: string;
  returnTo: string;
  identity: AppleSessionIdentity;
} | {
  kind: 'cancelled';
  returnTo: string;
};

export type AppleSessionPrincipal = {
  ownerId: string;
  appleSubjectHash: string;
  identity: AppleSessionIdentity;
};

export type AppleAccountMode = 'standalone' | 'linked';

export function appleAccountModeForOwner(ownerId: string): AppleAccountMode {
  return /^apple-owner:v1\.[A-Za-z0-9_-]{43}$/.test(ownerId) ? 'standalone' : 'linked';
}

export async function completeAppleAuthorization(
  dependencies: AppleAuthDependencies,
  callback: AppleAuthorizationCallback,
  browserBinding: string | null,
  ambientHostOwnerId: string | null,
): Promise<AuthorizationCompletion> {
  const now = dependencies.now();
  const flow = await dependencies.repository.consumeFlow(
    await sha256(callback.state, dependencies.crypto),
    now,
  );
  if (!flow) {
    throw new AppleAuthError(400, 'APPLE_FLOW_INVALID', 'The Apple authorization request is expired or was already used.');
  }
  const expectedOwner = flow.purpose === 'link'
    ? await keyedDigest('owner', flow.ownerId, dependencies)
    : await keyedDigest('authenticate-flow', flow.stateHash, dependencies);
  const bindingHash = browserBinding === null ? '' : await sha256(browserBinding, dependencies.crypto);
  if (
    !constantTimeEqual(flow.ownerBinding, expectedOwner) ||
    !constantTimeEqual(flow.browserBindingHash, bindingHash)
  ) {
    throw new AppleAuthError(403, 'APPLE_FLOW_BINDING_MISMATCH', 'The Apple authorization request does not belong to this browser session.');
  }
  if (callback.kind === 'cancelled') return {kind: 'cancelled', returnTo: flow.returnTo};
  if (flow.purpose === 'link' && ambientHostOwnerId !== flow.ownerId) {
    throw new AppleAuthError(403, 'APPLE_LINK_HOST_MISMATCH', 'The ChatGPT account that started this Apple link is no longer active.');
  }
  if (flow.purpose === 'authenticate' && ambientHostOwnerId !== null) {
    throw new AppleAuthError(409, 'AUTH_SESSION_AMBIGUOUS', 'Sign out of ChatGPT before creating a standalone Apple session.');
  }

  const expectedNonceHash = flow.nonceHash;
  const callbackClaims = await verifyAppleIdentityToken(
    callback.idToken,
    {kind: 'claim-hash', value: expectedNonceHash},
    dependencies,
  );
  const appleSubjectHash = await keyedDigest(
    'apple-subject',
    callbackClaims.subject,
    dependencies,
  );
  const transferSubjectHash = callbackClaims.transferSubject === null
    ? null
    : await keyedDigest('apple-subject', callbackClaims.transferSubject, dependencies);
  const ownerId = await resolveAuthorizationOwner({
    dependencies,
    flow,
    appleSubjectHash,
    transferSubjectHash,
    now,
  });
  const authorizationLease: AppleAuthorizationExchangeLease = {
    leaseToken: randomVersionedToken(dependencies.crypto).slice(3),
    ownerId,
    appleSubjectHash,
    authorizationStartedAt: flow.createdAt,
    now,
  };
  await dependencies.repository.claimAuthorizationExchangeLease(authorizationLease);
  await dependencies.repository.markAuthorizationExchangePossible(
    authorizationLease.leaseToken,
    dependencies.now(),
  );
  let tokenResponse: ExchangedTokens;
  try {
    tokenResponse = await exchangeAuthorizationCode(callback.code, dependencies);
  } catch (error) {
    if (isDefinitiveAppleNoCredentialError(error)) {
      await releaseAuthorizationLeaseAfterConfirmedCompensation(
        dependencies.repository,
        authorizationLease.leaseToken,
        dependencies.now(),
      );
    }
    throw error;
  }
  try {
    const exchangedClaims = await verifyAppleIdentityToken(
      tokenResponse.idToken,
      {kind: 'claim-hash', value: expectedNonceHash},
      dependencies,
    );
    if (!constantTimeEqual(callbackClaims.subject, exchangedClaims.subject)) {
      throw new AppleAuthError(400, 'APPLE_TOKEN_SUBJECT_MISMATCH', 'Apple returned different users for the callback and code exchange.');
    }
    if (!optionalConstantTimeEqual(callbackClaims.transferSubject, exchangedClaims.transferSubject)) {
      throw new AppleAuthError(400, 'APPLE_TOKEN_TRANSFER_MISMATCH', 'Apple returned different transfer identifiers for the callback and code exchange.');
    }
    if (
      callback.user !== null &&
      exchangedClaims.email !== null &&
      callback.user.email.toLowerCase() !== exchangedClaims.email.toLowerCase()
    ) {
      throw new AppleAuthError(400, 'APPLE_USER_EMAIL_MISMATCH', 'Apple user data does not match the verified identity token.');
    }

    const displayName = callback.user === null
      ? null
      : [callback.user.name.firstName.trim(), callback.user.name.lastName.trim()].filter(Boolean).join(' ').slice(0, 201) || null;
    const initialCredentials: StoredAppleCredentials = {
      recordType: 'apple-auth-credentials',
      schemaVersion: 2,
      subject: exchangedClaims.subject,
      email: exchangedClaims.email,
      emailVerified: exchangedClaims.emailVerified,
      displayName,
      refreshToken: tokenResponse.refreshToken,
      accessToken: tokenResponse.accessToken,
      accessTokenExpiresAt: now + tokenResponse.expiresIn,
    };
    const sessionToken = randomVersionedToken(dependencies.crypto);
    const sessionHash = await sha256(sessionToken, dependencies.crypto);
    const previousDisplayName = initialCredentials.displayName === null
      ? await recoverPreviousDisplayName(appleSubjectHash, now, dependencies)
      : null;
    const credentials: StoredAppleCredentials = {
      ...initialCredentials,
      displayName: initialCredentials.displayName ?? previousDisplayName,
    };
    const ownerBinding = await keyedDigest('owner', ownerId, dependencies);
    const expiresAt = now + SESSION_LIFETIME_SECONDS;
    await dependencies.repository.createSession({
      schemaVersion: 2,
      sessionHash,
      ownerId,
      ownerBinding,
      appleSubjectHash,
      encryptedCredentials: await encryptCredentials(credentials, sessionHash, dependencies),
      createdAt: now,
      expiresAt,
      lastValidatedAt: now,
    }, flow.createdAt);
    await dependencies.repository.completeAuthorizationExchangeLease({
      ...authorizationLease,
      now: dependencies.now(),
    });

    return {
      kind: 'authenticated',
      sessionToken,
      returnTo: flow.returnTo,
      identity: publicIdentity(ownerId, credentials, expiresAt),
    };
  } catch (error) {
    let revoked = false;
    try {
      await revokeAppleToken(tokenResponse.refreshToken, dependencies);
      revoked = true;
    } catch {
      // The pre-exchange durable marker remains for account-deletion manual follow-up.
    }
    if (revoked) await releaseAuthorizationLeaseAfterConfirmedCompensation(
      dependencies.repository,
      authorizationLease.leaseToken,
      dependencies.now(),
    );
    throw error;
  }
}

async function releaseAuthorizationLeaseAfterConfirmedCompensation(
  repository: AppleAuthRepository,
  leaseToken: string,
  now: number,
): Promise<void> {
  try {
    await repository.releaseAuthorizationExchangeLease(leaseToken, now);
  } catch {
    // Keeping the durable possible-credential marker is the fail-closed outcome.
  }
}

export async function readAppleSessionLocalPrincipal(
  dependencies: AppleAuthDependencies,
  sessionToken: string | null,
): Promise<AppleSessionPrincipal | null> {
  if (!isVersionedToken(sessionToken)) return null;
  const now = dependencies.now();
  const sessionHash = await sha256(sessionToken, dependencies.crypto);
  let record = await dependencies.repository.readSession(sessionHash, now);
  if (!record) return null;
  const credentials = await readAuthenticatedCredentials(record, dependencies);
  record = await upgradeSessionRecord(record, credentials, dependencies);
  if (!await sessionRecordRemainsAllowed(record, dependencies)) return null;
  return {
    ownerId: record.ownerId,
    appleSubjectHash: record.appleSubjectHash,
    identity: publicIdentity(record.ownerId, credentials, record.expiresAt),
  };
}

export async function readAppleSession(
  dependencies: AppleAuthDependencies,
  sessionToken: string | null,
): Promise<AppleSessionPrincipal | null> {
  if (!isVersionedToken(sessionToken)) return null;
  const now = dependencies.now();
  const sessionHash = await sha256(sessionToken, dependencies.crypto);
  let record = await dependencies.repository.readSession(sessionHash, now);
  if (!record) return null;
  let credentials = await readAuthenticatedCredentials(record, dependencies);
  record = await upgradeSessionRecord(record, credentials, dependencies);

  if (now - record.lastValidatedAt >= APPLE_REVALIDATION_SECONDS) {
    const refreshed = await exchangeRefreshToken(credentials.refreshToken, dependencies);
    const claims = await verifyAppleIdentityToken(refreshed.idToken, {kind: 'none'}, dependencies);
    const refreshedSubjectHash = await keyedDigest('apple-subject', claims.subject, dependencies);
    if (!constantTimeEqual(record.appleSubjectHash, refreshedSubjectHash)) {
      throw new AppleAuthError(401, 'APPLE_SESSION_SUBJECT_CHANGED', 'Apple returned a different user while validating this session.');
    }
    const validatedAt = dependencies.now();
    credentials = {
      ...credentials,
      email: claims.email,
      emailVerified: claims.emailVerified,
      accessToken: refreshed.accessToken,
      accessTokenExpiresAt: validatedAt + refreshed.expiresIn,
    };
    const expected = record;
    record = {
      ...record,
      encryptedCredentials: await encryptCredentials(credentials, sessionHash, dependencies),
      lastValidatedAt: validatedAt,
    };
    await dependencies.repository.updateSession({expected, next: record, now: validatedAt});
  }
  if (!await sessionRecordRemainsAllowed(record, dependencies)) return null;
  return {
    ownerId: record.ownerId,
    appleSubjectHash: record.appleSubjectHash,
    identity: publicIdentity(record.ownerId, credentials, record.expiresAt),
  };
}

export async function revokeAppleSession(
  dependencies: AppleAuthDependencies,
  sessionToken: string | null,
): Promise<boolean> {
  if (!isVersionedToken(sessionToken)) return false;
  const now = dependencies.now();
  const sessionHash = await sha256(sessionToken, dependencies.crypto);
  const record = await dependencies.repository.readSession(sessionHash, now);
  if (!record) return false;
  const credentials = await readAuthenticatedCredentials(record, dependencies);
  await dependencies.repository.revokeSession(sessionHash, now);
  await revokeAppleToken(credentials.refreshToken, dependencies);
  return true;
}

export type AppleCredentialRevocationSummary = {
  credentialsFound: number;
  credentialsRevoked: number;
  unreadableSessions: number;
  failedRevocations: number;
  manualRevocationRequired: boolean;
};

export async function revokeAppleCredentialsForAccountDeletion(
  dependencies: AppleAuthDependencies,
  records: AppleAuthSessionRecord[],
): Promise<AppleCredentialRevocationSummary> {
  const refreshTokens = new Set<string>();
  let unreadableSessions = 0;
  for (const record of records) {
    try {
      refreshTokens.add((await readAuthenticatedCredentials(record, dependencies)).refreshToken);
    } catch {
      unreadableSessions += 1;
    }
  }

  const outcomes = await Promise.all([...refreshTokens].map(async token => {
    try {
      await revokeAppleToken(token, dependencies);
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

async function resolveAuthorizationOwner(input: {
  dependencies: AppleAuthDependencies;
  flow: AppleAuthFlow;
  appleSubjectHash: string;
  transferSubjectHash: string | null;
  now: number;
}): Promise<string> {
  const {dependencies, flow, appleSubjectHash, transferSubjectHash, now} = input;
  const hashes = transferSubjectHash === null || transferSubjectHash === appleSubjectHash
    ? [appleSubjectHash]
    : [appleSubjectHash, transferSubjectHash];
  const result = await dependencies.repository.resolveAppleIdentityGroup({
    appleSubjectHashes: hashes,
    proposedOwnerId: createAppleOpaqueOwnerId(dependencies.crypto),
    requiredOwnerId: flow.purpose === 'link' ? flow.ownerId : null,
    createdAt: now,
    updatedAt: now,
  }, flow.createdAt);
  if (result.kind === 'owner-conflict') {
    throw new AppleAuthError(
      409,
      flow.purpose === 'link' ? 'APPLE_IDENTITY_ALREADY_LINKED' : 'APPLE_IDENTITY_LINK_CONFLICT',
      flow.purpose === 'link'
        ? 'This Apple identity is already linked to another Local Sandbox account.'
        : 'The Apple transfer identifiers resolve to different Local Sandbox accounts.',
    );
  }
  const ownerId = result.ownerId;
  for (const hash of hashes) {
    const linked = await dependencies.repository.readLinkedIdentity(hash);
    if (linked?.ownerId !== ownerId || linked.principalId !== result.principalId) {
      throw new AppleAuthError(
        409,
        'APPLE_IDENTITY_LINK_CONFLICT',
        'The Apple account mapping changed during sign-in.',
      );
    }
  }
  return ownerId;
}

function publicIdentity(
  ownerId: string,
  credentials: StoredAppleCredentials,
  expiresAt: number,
): AppleSessionIdentity {
  return {
    recordType: 'apple-auth-session',
    schemaVersion: 2,
    userId: ownerId,
    email: credentials.email,
    emailVerified: credentials.emailVerified,
    displayName: credentials.displayName,
    expiresAt,
  };
}

async function readAuthenticatedCredentials(
  record: AppleAuthSessionRecord,
  dependencies: AppleAuthDependencies,
): Promise<StoredAppleCredentials> {
  const ownerBinding = await keyedDigest('owner', record.ownerId, dependencies);
  if (!constantTimeEqual(record.ownerBinding, ownerBinding)) {
    throw new AppleAuthError(401, 'APPLE_SESSION_INVALID', 'The Apple session owner binding is invalid.');
  }
  const credentials = await decryptCredentials(record, dependencies);
  await verifySubjectBinding(record, credentials, dependencies);
  if ((await dependencies.repository.readLinkedIdentity(record.appleSubjectHash))?.ownerId !== record.ownerId) {
    throw new AppleAuthError(401, 'APPLE_SESSION_INVALID', 'The Apple account mapping no longer matches this session.');
  }
  return credentials;
}

async function recoverPreviousDisplayName(
  appleSubjectHash: string,
  now: number,
  dependencies: AppleAuthDependencies,
): Promise<string | null> {
  try {
    const record = await dependencies.repository.readLatestSessionForSubject(appleSubjectHash, now);
    if (record === null) return null;
    return (await readAuthenticatedCredentials(record, dependencies)).displayName;
  } catch {
    return null;
  }
}

async function upgradeSessionRecord(
  record: AppleAuthSessionRecord,
  credentials: StoredAppleCredentials,
  dependencies: AppleAuthDependencies,
): Promise<AppleAuthSessionRecord> {
  if (record.schemaVersion === 2) return record;
  const upgraded: AppleAuthSessionRecord = {
    ...record,
    schemaVersion: 2,
    encryptedCredentials: await encryptCredentials(credentials, record.sessionHash, dependencies),
  };
  await dependencies.repository.updateSession({
    expected: record,
    next: upgraded,
    now: dependencies.now(),
  });
  return upgraded;
}

async function sessionRecordRemainsAllowed(
  expected: AppleAuthSessionRecord,
  dependencies: AppleAuthDependencies,
): Promise<boolean> {
  const current = await dependencies.repository.readSession(
    expected.sessionHash,
    dependencies.now(),
  );
  return current !== null
    && current.schemaVersion === expected.schemaVersion
    && current.sessionHash === expected.sessionHash
    && current.ownerId === expected.ownerId
    && current.ownerBinding === expected.ownerBinding
    && current.appleSubjectHash === expected.appleSubjectHash
    && current.encryptedCredentials === expected.encryptedCredentials
    && current.createdAt === expected.createdAt
    && current.expiresAt === expected.expiresAt
    && current.lastValidatedAt === expected.lastValidatedAt;
}

async function verifySubjectBinding(
  record: AppleAuthSessionRecord,
  credentials: StoredAppleCredentials,
  dependencies: AppleAuthDependencies,
): Promise<void> {
  const expected = await keyedDigest('apple-subject', credentials.subject, dependencies);
  if (!constantTimeEqual(record.appleSubjectHash, expected)) {
    throw new AppleAuthError(401, 'APPLE_SESSION_INVALID', 'The Apple session binding is invalid.');
  }
}

export type AppleIdentityClaims = {
  subject: string;
  transferSubject: string | null;
  email: string | null;
  emailVerified: boolean;
  issuedAt: number;
  expiresAt: number;
};

type AppleNonceExpectation =
  | {kind: 'none'}
  | {kind: 'claim-hash'; value: string}
  | {kind: 'exact-claim'; value: string};

const jwtHeaderSchema = z.object({
  alg: z.literal('RS256'),
  kid: z.string().min(1).max(100),
  typ: z.string().max(20).optional(),
}).passthrough();

const identityClaimsSchema = z.object({
  iss: z.literal(APPLE_ISSUER),
  aud: z.string().min(1).max(255),
  exp: z.number().int(),
  iat: z.number().int(),
  sub: z.string().min(1).max(255),
  transfer_sub: z.string().min(1).max(255).optional(),
  nonce: z.string().min(1).max(500).optional(),
  email: z.string().email().max(320).optional(),
  email_verified: z.union([z.boolean(), z.enum(['true', 'false'])]).optional(),
}).passthrough();

const appleKeySchema = z.object({
  kty: z.literal('RSA'),
  kid: z.string().min(1).max(100),
  alg: z.literal('RS256').optional(),
  use: z.literal('sig').optional(),
  n: z.string().min(20).max(2_000),
  e: z.string().min(1).max(20),
}).passthrough();
const appleKeySetSchema = z.object({keys: z.array(appleKeySchema).min(1).max(20)}).strict();

async function verifyAppleIdentityToken(
  token: string,
  nonceExpectation: AppleNonceExpectation,
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'fetcher' | 'crypto' | 'now'>,
  expectedAudience = dependencies.configuration.clientId,
): Promise<AppleIdentityClaims> {
  const segments = token.split('.');
  if (segments.length !== 3 || segments.some(segment => segment === '')) {
    throw new AppleAuthError(400, 'APPLE_ID_TOKEN_INVALID', 'Apple identity token is malformed.');
  }
  const signature = decodeCanonicalIdentityTokenSegment(segments[2]);
  const header = parseBase64URLJSON(segments[0], jwtHeaderSchema);
  const claims = parseBase64URLJSON(segments[1], identityClaimsSchema);
  const now = dependencies.now();
  if (
    claims.aud !== expectedAudience ||
    claims.exp <= now - CLOCK_SKEW_SECONDS ||
    claims.iat > now + CLOCK_SKEW_SECONDS
  ) {
    throw new AppleAuthError(401, 'APPLE_ID_TOKEN_CLAIMS', 'Apple identity token claims are invalid.');
  }
  if (nonceExpectation.kind !== 'none') {
    if (!claims.nonce) {
      throw new AppleAuthError(401, 'APPLE_ID_TOKEN_NONCE', 'Apple identity token is missing its nonce.');
    }
    const actualNonce = nonceExpectation.kind === 'claim-hash'
      ? await sha256(claims.nonce, dependencies.crypto)
      : claims.nonce;
    if (!constantTimeEqual(actualNonce, nonceExpectation.value)) {
      throw new AppleAuthError(401, 'APPLE_ID_TOKEN_NONCE', 'Apple identity token nonce does not match the authorization request.');
    }
  }

  const keySet = await fetchAppleKeySet(dependencies);
  const key = keySet.keys.find(candidate => candidate.kid === header.kid);
  if (!key) {
    throw new AppleAuthError(401, 'APPLE_ID_TOKEN_KEY', 'Apple identity token references an unknown signing key.');
  }
  const jsonWebKey: JsonWebKey = {
    kty: key.kty,
    alg: key.alg,
    use: key.use,
    n: key.n,
    e: key.e,
  };
  const publicKey = await dependencies.crypto.subtle.importKey(
    'jwk',
    jsonWebKey,
    {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'},
    false,
    ['verify'],
  );
  const valid = await dependencies.crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    toArrayBuffer(signature),
    new TextEncoder().encode(`${segments[0]}.${segments[1]}`),
  );
  if (!valid) {
    throw new AppleAuthError(401, 'APPLE_ID_TOKEN_SIGNATURE', 'Apple identity token signature is invalid.');
  }

  const emailVerified = claims.email === undefined
    ? false
    : claims.email_verified === true || claims.email_verified === 'true';
  if (claims.email !== undefined && !emailVerified) {
    throw new AppleAuthError(401, 'APPLE_EMAIL_UNVERIFIED', 'Apple did not verify the email in the identity token.');
  }
  return {
    subject: claims.sub,
    transferSubject: claims.transfer_sub ?? null,
    email: claims.email ?? null,
    emailVerified,
    issuedAt: claims.iat,
    expiresAt: claims.exp,
  };
}

export async function verifyNativeAppleIdentityToken(
  token: string,
  rawNonce: string,
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'fetcher' | 'crypto' | 'now'>,
): Promise<AppleIdentityClaims> {
  const nativeClientId = dependencies.configuration.nativeClientId;
  if (!nativeClientId) {
    throw new AppleAuthError(
      503,
      'APPLE_NATIVE_AUTH_NOT_CONFIGURED',
      'Native Sign in with Apple is not configured on this server.',
    );
  }
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(rawNonce)) {
    throw new AppleAuthError(400, 'APPLE_NATIVE_NONCE_INVALID', 'The native Apple nonce is invalid.');
  }
  const claims = await verifyAppleIdentityToken(
    token,
    {kind: 'exact-claim', value: await sha256(rawNonce, dependencies.crypto)},
    dependencies,
    nativeClientId,
  );
  const now = dependencies.now();
  if (
    claims.expiresAt <= now ||
    claims.issuedAt < now - NATIVE_ID_TOKEN_MAX_AGE_SECONDS ||
    claims.issuedAt > now + CLOCK_SKEW_SECONDS
  ) {
    throw new AppleAuthError(401, 'APPLE_ID_TOKEN_CLAIMS', 'Apple identity token claims are invalid.');
  }
  return claims;
}

export async function verifyExchangedNativeAppleIdentityToken(
  token: string,
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'fetcher' | 'crypto' | 'now'>,
): Promise<AppleIdentityClaims> {
  const nativeClientId = dependencies.configuration.nativeClientId;
  if (!nativeClientId) {
    throw new AppleAuthError(
      503,
      'APPLE_NATIVE_AUTH_NOT_CONFIGURED',
      'Native Sign in with Apple is not configured on this server.',
    );
  }
  const claims = await verifyAppleIdentityToken(
    token,
    {kind: 'none'},
    dependencies,
    nativeClientId,
  );
  const now = dependencies.now();
  if (
    claims.expiresAt <= now
    || claims.issuedAt < now - NATIVE_ID_TOKEN_MAX_AGE_SECONDS
    || claims.issuedAt > now + CLOCK_SKEW_SECONDS
  ) {
    throw new AppleAuthError(401, 'APPLE_ID_TOKEN_CLAIMS', 'Apple identity token claims are invalid.');
  }
  return claims;
}

type VerifiedKnownAppleServerNotification = {
  notificationIdHash: string;
  appleSubjectHash: string;
  issuedAt: number;
  eventTime: number;
  receiptExpiresAt: number;
};

export type VerifiedAppleServerNotification =
  | (VerifiedKnownAppleServerNotification & {kind: 'email-enabled'})
  | (VerifiedKnownAppleServerNotification & {kind: 'email-disabled'})
  | (VerifiedKnownAppleServerNotification & {kind: 'consent-revoked'})
  | (VerifiedKnownAppleServerNotification & {kind: 'account-deleted'})
  | {
    kind: 'unknown';
    eventType: string;
    notificationIdHash: string;
    appleSubjectHash: string | null;
    issuedAt: number;
    eventTime: number | null;
    receiptExpiresAt: number;
  };

const notificationClaimsSchema = z.object({
  iss: z.string().min(1).max(255),
  aud: z.string().min(1).max(255),
  iat: z.number().int().positive(),
  exp: z.number().int().positive().optional(),
  jti: z.string().min(1).max(500),
  events: z.object({
    type: z.string().min(1).max(100).regex(/^[A-Za-z0-9_-]+$/),
    sub: z.string().min(1).max(255).optional(),
    event_time: z.number().int().positive().optional(),
  }).passthrough(),
}).passthrough();

const notificationKnownEventSchema = z.object({
  type: z.enum(['email-enabled', 'email-disabled', 'consent-revoked', 'account-deleted']),
  sub: z.string().min(1).max(255),
  event_time: z.number().int().positive(),
}).passthrough();

const notificationEmailEventSchema = notificationKnownEventSchema.extend({
  type: z.enum(['email-enabled', 'email-disabled']),
  email: z.string().email().max(320),
  is_private_email: z.union([z.boolean(), z.enum(['true', 'false'])]),
}).passthrough();
const appleKnownNotificationTypes = new Set<string>([
  'email-enabled',
  'email-disabled',
  'consent-revoked',
  'account-deleted',
]);

export async function parseAppleServerNotificationRequest(request: Request): Promise<string> {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new AppleAuthError(
      415,
      'APPLE_NOTIFICATION_CONTENT_TYPE',
      'Apple server notifications require JSON.',
    );
  }
  const text = await readAppleRequestBody(request, 32_000, 'notification');
  try {
    return z.object({payload: z.string().min(20).max(24_000)}).strict().parse(JSON.parse(text)).payload;
  } catch {
    throw new AppleAuthError(
      400,
      'APPLE_NOTIFICATION_INVALID',
      'The Apple server notification request is invalid.',
    );
  }
}

export async function verifyAppleServerNotification(
  token: string,
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'fetcher' | 'crypto' | 'now'>,
): Promise<VerifiedAppleServerNotification> {
  const segments = token.split('.');
  if (segments.length !== 3 || segments.some(segment => segment === '')) {
    throw invalidAppleNotification();
  }
  let signature: Uint8Array;
  let header: z.infer<typeof jwtHeaderSchema>;
  let claims: z.infer<typeof notificationClaimsSchema>;
  try {
    signature = decodeCanonicalBase64URLSegment(segments[2]);
    header = parseNotificationJSONSegment(segments[0], jwtHeaderSchema);
    claims = parseNotificationJSONSegment(segments[1], notificationClaimsSchema);
  } catch (error) {
    if (error instanceof AppleAuthError) throw error;
    throw invalidAppleNotification();
  }

  const keySet = await fetchAppleKeySet(dependencies);
  const key = keySet.keys.find(candidate => candidate.kid === header.kid);
  if (!key) {
    throw new AppleAuthError(
      401,
      'APPLE_NOTIFICATION_KEY',
      'The Apple server notification references an unknown signing key.',
    );
  }
  const publicKey = await dependencies.crypto.subtle.importKey(
    'jwk',
    {kty: key.kty, alg: key.alg, use: key.use, n: key.n, e: key.e},
    {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256'},
    false,
    ['verify'],
  );
  const signatureValid = await dependencies.crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    publicKey,
    toArrayBuffer(signature),
    new TextEncoder().encode(`${segments[0]}.${segments[1]}`),
  );
  if (!signatureValid) {
    throw new AppleAuthError(
      401,
      'APPLE_NOTIFICATION_SIGNATURE',
      'The Apple server notification signature is invalid.',
    );
  }

  const now = dependencies.now();
  const allowedAudiences = new Set([
    dependencies.configuration.clientId,
    ...(dependencies.configuration.nativeClientId === null
      ? []
      : [dependencies.configuration.nativeClientId]),
  ]);
  if (
    claims.iss !== APPLE_ISSUER ||
    !allowedAudiences.has(claims.aud) ||
    claims.iat < now - APPLE_NOTIFICATION_MAX_AGE_SECONDS ||
    claims.iat > now + CLOCK_SKEW_SECONDS ||
    (claims.exp !== undefined && claims.exp <= now - CLOCK_SKEW_SECONDS)
  ) {
    throw invalidAppleNotificationClaims();
  }

  const notificationIdHash = await keyedDigest(
    'apple-notification-jti',
    claims.jti,
    dependencies,
  );
  const receiptExpiresAt = now + APPLE_NOTIFICATION_RECEIPT_LIFETIME_SECONDS;
  if (
    claims.events.event_time !== undefined &&
    (
      claims.events.event_time < now - APPLE_NOTIFICATION_MAX_AGE_SECONDS ||
      claims.events.event_time > now + CLOCK_SKEW_SECONDS
    )
  ) {
    throw invalidAppleNotificationClaims();
  }
  const known = notificationKnownEventSchema.safeParse(claims.events);
  if (!known.success) {
    if (appleKnownNotificationTypes.has(claims.events.type)) throw invalidAppleNotification();
    const appleSubjectHash = claims.events.sub === undefined
      ? null
      : await keyedDigest('apple-subject', claims.events.sub, dependencies);
    return {
      kind: 'unknown',
      eventType: claims.events.type,
      notificationIdHash,
      appleSubjectHash,
      issuedAt: claims.iat,
      eventTime: claims.events.event_time ?? null,
      receiptExpiresAt,
    };
  }
  if (
    (known.data.type === 'email-enabled' || known.data.type === 'email-disabled') &&
    !notificationEmailEventSchema.safeParse(claims.events).success
  ) {
    throw invalidAppleNotification();
  }
  return {
    kind: known.data.type,
    notificationIdHash,
    appleSubjectHash: await keyedDigest('apple-subject', known.data.sub, dependencies),
    issuedAt: claims.iat,
    eventTime: known.data.event_time,
    receiptExpiresAt,
  };
}

function parseNotificationJSONSegment<T>(segment: string, schema: z.ZodType<T>): T {
  try {
    return schema.parse(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(
      decodeCanonicalBase64URLSegment(segment),
    )));
  } catch {
    throw invalidAppleNotification();
  }
}

function decodeCanonicalBase64URLSegment(segment: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = base64URLDecode(segment);
  } catch {
    throw invalidAppleNotification();
  }
  if (base64URLEncode(decoded) !== segment) throw invalidAppleNotification();
  return decoded;
}

function invalidAppleNotification(): AppleAuthError {
  return new AppleAuthError(
    400,
    'APPLE_NOTIFICATION_INVALID',
    'The Apple server notification is invalid.',
  );
}

function invalidAppleNotificationClaims(): AppleAuthError {
  return new AppleAuthError(
    401,
    'APPLE_NOTIFICATION_CLAIMS',
    'The Apple server notification claims are invalid.',
  );
}

export function createAppleOpaqueToken(webCrypto: Crypto): string {
  return randomVersionedToken(webCrypto);
}

export async function hashAppleOpaqueToken(value: string, webCrypto: Crypto): Promise<string> {
  return sha256(value, webCrypto);
}

export async function hashAppleSubject(
  subject: string,
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'crypto'>,
): Promise<string> {
  return keyedDigest('apple-subject', subject, dependencies);
}

async function fetchAppleKeySet(
  dependencies: Pick<AppleAuthDependencies, 'fetcher'>,
): Promise<z.infer<typeof appleKeySetSchema>> {
  let response: Response;
  try {
    response = await dependencies.fetcher(APPLE_KEYS_URL, {
      method: 'GET',
      headers: {'Accept': 'application/json'},
      redirect: 'error',
    });
  } catch {
    throw new AppleAuthError(503, 'APPLE_KEYS_UNAVAILABLE', 'Apple signing keys are unavailable.');
  }
  if (!response.ok) {
    throw new AppleAuthError(503, 'APPLE_KEYS_UNAVAILABLE', 'Apple signing keys are unavailable.');
  }
  let responseText: string;
  try {
    responseText = await readBoundedResponseText(response, 64_000);
  } catch (error) {
    if (error instanceof BoundedResponseError) {
      throw new AppleAuthError(503, 'APPLE_KEYS_INVALID', 'Apple returned invalid signing keys.');
    }
    throw error;
  }
  return parseBoundedJSON(responseText, appleKeySetSchema, 'APPLE_KEYS_INVALID');
}

const tokenResponseSchema = z.object({
  access_token: z.string().min(1).max(8_000),
  expires_in: z.number().int().positive().max(86_400),
  id_token: z.string().min(20).max(16_000),
  refresh_token: z.string().min(1).max(8_000).optional(),
  token_type: z.string().regex(/^bearer$/i),
}).passthrough();
const tokenErrorResponseSchema = z.object({
  error: z.enum([
    'invalid_request',
    'invalid_client',
    'invalid_grant',
    'unauthorized_client',
    'unsupported_grant_type',
    'invalid_scope',
  ]),
}).passthrough();

class AppleDefinitiveNoCredentialError extends AppleAuthError {}

export function isDefinitiveAppleNoCredentialError(
  error: unknown,
): error is AppleDefinitiveNoCredentialError {
  return error instanceof AppleDefinitiveNoCredentialError;
}

type ExchangedTokens = {
  accessToken: string;
  expiresIn: number;
  idToken: string;
  refreshToken: string;
};

export type AppleNativeExchangedTokens = ExchangedTokens;

async function exchangeAuthorizationCode(
  code: string,
  dependencies: AppleAuthDependencies,
): Promise<ExchangedTokens> {
  const values = new URLSearchParams({
    client_id: dependencies.configuration.clientId,
    client_secret: await createAppleClientSecret(dependencies),
    code,
    grant_type: 'authorization_code',
    redirect_uri: dependencies.configuration.redirectUri,
  });
  const parsed = await postAppleToken(values, dependencies);
  if (!parsed.refresh_token) {
    throw new AppleAuthError(503, 'APPLE_REFRESH_TOKEN_MISSING', 'Apple did not return a refresh token for this authorization.');
  }
  return {
    accessToken: parsed.access_token,
    expiresIn: parsed.expires_in,
    idToken: parsed.id_token,
    refreshToken: parsed.refresh_token,
  };
}

async function exchangeRefreshToken(
  refreshToken: string,
  dependencies: AppleAuthDependencies,
): Promise<Omit<ExchangedTokens, 'refreshToken'>> {
  const values = new URLSearchParams({
    client_id: dependencies.configuration.clientId,
    client_secret: await createAppleClientSecret(dependencies),
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });
  const parsed = await postAppleToken(values, dependencies);
  return {
    accessToken: parsed.access_token,
    expiresIn: parsed.expires_in,
    idToken: parsed.id_token,
  };
}

export async function exchangeAppleNativeAuthorizationCode(
  code: string,
  dependencies: AppleProviderTokenDependencies,
): Promise<AppleNativeExchangedTokens> {
  const nativeClientId = requireNativeClientId(dependencies.configuration);
  const values = new URLSearchParams({
    client_id: nativeClientId,
    client_secret: await createAppleClientSecret(dependencies, nativeClientId),
    code,
    grant_type: 'authorization_code',
  });
  const parsed = await postAppleToken(values, dependencies);
  if (!parsed.refresh_token) {
    throw new AppleAuthError(503, 'APPLE_REFRESH_TOKEN_MISSING', 'Apple did not return a refresh token for this authorization.');
  }
  return {
    accessToken: parsed.access_token,
    expiresIn: parsed.expires_in,
    idToken: parsed.id_token,
    refreshToken: parsed.refresh_token,
  };
}

export async function refreshAppleNativeAuthorization(
  refreshToken: string,
  dependencies: AppleProviderTokenDependencies,
): Promise<Omit<AppleNativeExchangedTokens, 'refreshToken'>> {
  const nativeClientId = requireNativeClientId(dependencies.configuration);
  const values = new URLSearchParams({
    client_id: nativeClientId,
    client_secret: await createAppleClientSecret(dependencies, nativeClientId),
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });
  const parsed = await postAppleToken(values, dependencies);
  return {
    accessToken: parsed.access_token,
    expiresIn: parsed.expires_in,
    idToken: parsed.id_token,
  };
}

async function postAppleToken(
  values: URLSearchParams,
  dependencies: Pick<AppleAuthDependencies, 'fetcher'>,
): Promise<z.infer<typeof tokenResponseSchema>> {
  let response: Response;
  const abortController = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    response = await Promise.race([
      dependencies.fetcher(APPLE_TOKEN_URL, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: values,
        redirect: 'error',
        signal: abortController.signal,
      }),
      new Promise<Response>((_resolve, reject) => {
        timeout = setTimeout(() => {
          abortController.abort();
          reject(new AppleAuthError(
            503,
            'APPLE_TOKEN_UNAVAILABLE',
            'Apple token validation is unavailable.',
          ));
        }, APPLE_TOKEN_EXCHANGE_TIMEOUT_MILLISECONDS);
      }),
    ]);
  } catch (error) {
    if (error instanceof AppleAuthError) throw error;
    throw new AppleAuthError(503, 'APPLE_TOKEN_UNAVAILABLE', 'Apple token validation is unavailable.');
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
  let responseText: string;
  try {
    responseText = await readBoundedResponseText(response, 64_000);
  } catch (error) {
    if (error instanceof BoundedResponseError) {
      throw new AppleAuthError(503, 'APPLE_TOKEN_INVALID', 'Apple returned an invalid token response.');
    }
    throw error;
  }
  if (response.status === 400) {
    try {
      parseBoundedJSON(responseText, tokenErrorResponseSchema, 'APPLE_TOKEN_INVALID');
    } catch (error) {
      if (error instanceof AppleAuthError) throw error;
      throw new AppleAuthError(503, 'APPLE_TOKEN_INVALID', 'Apple returned an invalid token response.');
    }
    throw new AppleDefinitiveNoCredentialError(
      401,
      'APPLE_CODE_REJECTED',
      'Apple rejected the authorization credential.',
    );
  }
  if (!response.ok) {
    throw new AppleAuthError(401, 'APPLE_CODE_REJECTED', 'Apple rejected the authorization credential.');
  }
  return parseBoundedJSON(responseText, tokenResponseSchema, 'APPLE_TOKEN_INVALID');
}

async function revokeAppleToken(token: string, dependencies: AppleAuthDependencies): Promise<void> {
  return revokeAppleTokenForClient(token, dependencies.configuration.clientId, dependencies);
}

export async function revokeAppleNativeRefreshToken(
  token: string,
  dependencies: AppleProviderTokenDependencies,
): Promise<void> {
  return revokeAppleTokenForClient(
    token,
    requireNativeClientId(dependencies.configuration),
    dependencies,
  );
}

async function revokeAppleTokenForClient(
  token: string,
  clientId: string,
  dependencies: AppleProviderTokenDependencies,
): Promise<void> {
  const values = new URLSearchParams({
    client_id: clientId,
    client_secret: await createAppleClientSecret(dependencies, clientId),
    token,
    token_type_hint: 'refresh_token',
  });
  const controller = new AbortController();
  let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
  const timeout = new Promise<never>((_resolve, reject) => {
    timeoutHandle = setTimeout(() => {
      reject(new AppleAuthError(
        503,
        'APPLE_REVOCATION_TIMEOUT',
        'Apple token revocation timed out after the local session was cleared.',
      ));
      controller.abort();
    }, dependencies.revocationTimeoutMilliseconds);
  });
  let response: Response;
  try {
    response = await Promise.race([
      dependencies.fetcher(APPLE_REVOKE_URL, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: values,
        redirect: 'error',
        signal: controller.signal,
      }),
      timeout,
    ]);
  } catch (error) {
    if (error instanceof AppleAuthError) throw error;
    throw new AppleAuthError(503, 'APPLE_REVOCATION_UNAVAILABLE', 'Apple token revocation is unavailable.');
  } finally {
    if (timeoutHandle !== null) clearTimeout(timeoutHandle);
  }
  if (!response.ok) {
    throw new AppleAuthError(503, 'APPLE_REVOCATION_FAILED', 'Apple did not confirm token revocation.');
  }
}

export async function createAppleClientSecret(
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'crypto' | 'now'>,
  clientId = dependencies.configuration.clientId,
): Promise<string> {
  const now = dependencies.now();
  const header = base64URLEncode(new TextEncoder().encode(JSON.stringify({
    alg: 'ES256',
    kid: dependencies.configuration.keyId,
  })));
  const payload = base64URLEncode(new TextEncoder().encode(JSON.stringify({
    iss: dependencies.configuration.teamId,
    iat: now,
    exp: now + APPLE_CLIENT_SECRET_LIFETIME_SECONDS,
    aud: APPLE_ISSUER,
    sub: clientId,
  })));
  const privateKey = await dependencies.crypto.subtle.importKey(
    'pkcs8',
    toArrayBuffer(pemBody(dependencies.configuration.privateKeyPem)),
    {name: 'ECDSA', namedCurve: 'P-256'},
    false,
    ['sign'],
  );
  const signature = new Uint8Array(await dependencies.crypto.subtle.sign(
    {name: 'ECDSA', hash: 'SHA-256'},
    privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  ));
  if (signature.byteLength !== 64) {
    throw new AppleAuthError(503, 'APPLE_CLIENT_SECRET_SIGNING', 'This runtime returned an unsupported ES256 signature format.');
  }
  return `${header}.${payload}.${base64URLEncode(signature)}`;
}

function requireNativeClientId(configuration: AppleAuthConfiguration): string {
  if (!configuration.nativeClientId) {
    throw new AppleAuthError(
      503,
      'APPLE_NATIVE_AUTH_NOT_CONFIGURED',
      'Native Sign in with Apple is not configured on this server.',
    );
  }
  return configuration.nativeClientId;
}

export async function encryptAppleStorageRecord(
  plaintext: string,
  additionalData: string,
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'crypto'>,
): Promise<string> {
  const key = await storageEncryptionKey(dependencies);
  const iv = new Uint8Array(12);
  dependencies.crypto.getRandomValues(iv);
  const ciphertext = await dependencies.crypto.subtle.encrypt(
    {name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(additionalData)},
    key,
    new TextEncoder().encode(plaintext),
  );
  return `v1.${base64URLEncode(iv)}.${base64URLEncode(new Uint8Array(ciphertext))}`;
}

export async function decryptAppleStorageRecord(
  value: string,
  additionalData: string,
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'crypto'>,
): Promise<string> {
  const segments = value.split('.');
  if (segments.length !== 3 || segments[0] !== 'v1') {
    throw new AppleAuthError(401, 'APPLE_SESSION_INVALID', 'The Apple storage record has an unsupported version.');
  }
  try {
    const plaintext = await dependencies.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(base64URLDecode(segments[1])),
        additionalData: new TextEncoder().encode(additionalData),
      },
      await storageEncryptionKey(dependencies),
      toArrayBuffer(base64URLDecode(segments[2])),
    );
    return new TextDecoder('utf-8', {fatal: true}).decode(plaintext);
  } catch {
    throw new AppleAuthError(401, 'APPLE_SESSION_INVALID', 'The Apple storage record could not be authenticated.');
  }
}

async function encryptCredentials(
  credentials: StoredAppleCredentials,
  sessionHash: string,
  dependencies: AppleAuthDependencies,
): Promise<string> {
  const key = await storageEncryptionKey(dependencies);
  const iv = new Uint8Array(12);
  dependencies.crypto.getRandomValues(iv);
  const ciphertext = await dependencies.crypto.subtle.encrypt(
    {name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`apple-session-v2\0${sessionHash}`)},
    key,
    new TextEncoder().encode(JSON.stringify(credentials)),
  );
  return `v2.${base64URLEncode(iv)}.${base64URLEncode(new Uint8Array(ciphertext))}`;
}

async function decryptCredentials(
  record: AppleAuthSessionRecord,
  dependencies: AppleAuthDependencies,
): Promise<StoredAppleCredentials> {
  const segments = record.encryptedCredentials.split('.');
  const expectedVersion = record.schemaVersion === 1 ? 'v1' : 'v2';
  if (segments.length !== 3 || segments[0] !== expectedVersion) {
    throw new AppleAuthError(401, 'APPLE_SESSION_INVALID', 'The Apple session record has an unsupported version.');
  }
  try {
    const plaintext = await dependencies.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: toArrayBuffer(base64URLDecode(segments[1])),
        additionalData: new TextEncoder().encode(`apple-session-v${record.schemaVersion}\0${record.sessionHash}`),
      },
      await storageEncryptionKey(dependencies),
      toArrayBuffer(base64URLDecode(segments[2])),
    );
    const decoded: unknown = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(plaintext));
    const parsed = record.schemaVersion === 1
      ? storedCredentialsV1Schema.parse(decoded)
      : storedCredentialsV2Schema.parse(decoded);
    return {...parsed, schemaVersion: 2};
  } catch {
    throw new AppleAuthError(401, 'APPLE_SESSION_INVALID', 'The Apple session record could not be authenticated.');
  }
}

async function storageEncryptionKey(
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'crypto'>,
): Promise<CryptoKey> {
  return dependencies.crypto.subtle.importKey(
    'raw',
    toArrayBuffer(base64URLDecode(dependencies.configuration.storageKey)),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  );
}

async function keyedDigest(
  purpose: string,
  value: string,
  dependencies: Pick<AppleAuthDependencies, 'configuration' | 'crypto'>,
): Promise<string> {
  const key = await dependencies.crypto.subtle.importKey(
    'raw',
    toArrayBuffer(base64URLDecode(dependencies.configuration.storageKey)),
    {name: 'HMAC', hash: 'SHA-256'},
    false,
    ['sign'],
  );
  const digest = await dependencies.crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${purpose}\0${value}`),
  );
  return base64URLEncode(new Uint8Array(digest));
}

async function sha256(value: string, webCrypto: Crypto): Promise<string> {
  const digest = await webCrypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return base64URLEncode(new Uint8Array(digest));
}

function randomVersionedToken(webCrypto: Crypto): string {
  const bytes = new Uint8Array(32);
  webCrypto.getRandomValues(bytes);
  return `v1.${base64URLEncode(bytes)}`;
}

export function createAppleOpaqueOwnerId(webCrypto: Crypto): string {
  return `apple-owner:${randomVersionedToken(webCrypto)}`;
}

function isVersionedToken(value: string | null): value is string {
  return value !== null && /^v1\.[A-Za-z0-9_-]{43}$/.test(value);
}

function safeReturnTo(value: string | null): string {
  if (!value || !value.startsWith('/') || value.startsWith('//')) return '/';
  try {
    const url = new URL(value, 'https://app.local');
    if (url.origin !== 'https://app.local' || url.pathname.startsWith('/api/auth/apple/')) return '/';
    return `${url.pathname}${url.search}${url.hash}`;
  } catch {
    return '/';
  }
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

function parseBase64URLJSON<T>(segment: string, schema: z.ZodType<T>): T {
  try {
    return schema.parse(JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(
      decodeCanonicalIdentityTokenSegment(segment),
    )));
  } catch {
    throw new AppleAuthError(400, 'APPLE_ID_TOKEN_INVALID', 'Apple identity token contains invalid JSON.');
  }
}

function decodeCanonicalIdentityTokenSegment(segment: string): Uint8Array {
  let decoded: Uint8Array;
  try {
    decoded = base64URLDecode(segment);
  } catch {
    throw new AppleAuthError(400, 'APPLE_ID_TOKEN_INVALID', 'Apple identity token is malformed.');
  }
  if (base64URLEncode(decoded) !== segment) {
    throw new AppleAuthError(400, 'APPLE_ID_TOKEN_INVALID', 'Apple identity token is malformed.');
  }
  return decoded;
}

function parseBoundedJSON<T>(text: string, schema: z.ZodType<T>, code: string): T {
  if (new TextEncoder().encode(text).byteLength > 64_000) {
    throw new AppleAuthError(503, code, 'Apple returned an invalid response.');
  }
  try {
    return schema.parse(JSON.parse(text));
  } catch {
    throw new AppleAuthError(503, code, 'Apple returned an invalid response.');
  }
}

async function readAppleRequestBody(
  request: Request,
  maximumBytes: number,
  purpose: 'callback' | 'start' | 'notification',
): Promise<string> {
  const headers = new Headers();
  const declared = request.headers.get('content-length');
  if (declared !== null) headers.set('Content-Length', declared);
  try {
    return await readBoundedResponseText(new Response(request.body, {headers}), maximumBytes);
  } catch (error) {
    if (!(error instanceof BoundedResponseError)) throw error;
    const prefix = purpose === 'callback'
      ? 'APPLE_CALLBACK'
      : purpose === 'start'
        ? 'APPLE_AUTH_START'
        : 'APPLE_NOTIFICATION';
    if (error.kind === 'too-large') {
      throw new AppleAuthError(413, `${prefix}_TOO_LARGE`, `Apple ${purpose} request is too large.`);
    }
    if (error.kind === 'invalid-length') {
      throw new AppleAuthError(400, `${prefix}_CONTENT_LENGTH`, `Apple ${purpose} request has an invalid Content-Length.`);
    }
    throw new AppleAuthError(400, `${prefix}_ENCODING`, `Apple ${purpose} request must use valid UTF-8.`);
  }
}

export async function parseAppleAuthorizationStartRequest(request: Request): Promise<{
  intent: {purpose: 'authenticate'} | {purpose: 'link'};
  returnTo: string | null;
}> {
  const contentType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    throw new AppleAuthError(415, 'APPLE_AUTH_START_CONTENT_TYPE', 'Apple sign-in start requires JSON.');
  }
  const text = await readAppleRequestBody(request, 4_000, 'start');
  const schema = z.object({
    purpose: z.enum(['authenticate', 'link']),
    returnTo: z.string().max(2_000).nullable().optional(),
  }).strict();
  try {
    const parsed = schema.parse(JSON.parse(text));
    return {intent: {purpose: parsed.purpose}, returnTo: safeReturnTo(parsed.returnTo ?? null)};
  } catch {
    throw new AppleAuthError(400, 'APPLE_AUTH_START_INVALID', 'Apple sign-in start request is invalid.');
  }
}

function pemBody(pem: string): Uint8Array {
  const body = pem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  return base64Decode(body);
}

function base64URLDecode(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(value)) throw invalidConfiguration();
  const padding = '='.repeat((4 - value.length % 4) % 4);
  return base64Decode(value.replaceAll('-', '+').replaceAll('_', '/') + padding);
}

function base64Decode(value: string): Uint8Array {
  try {
    return Uint8Array.from(atob(value), character => character.charCodeAt(0));
  } catch {
    throw invalidConfiguration();
  }
}

function base64URLEncode(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new ArrayBuffer(value.byteLength);
  new Uint8Array(copy).set(value);
  return copy;
}
