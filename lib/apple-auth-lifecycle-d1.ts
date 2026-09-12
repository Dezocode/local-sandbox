import { z } from 'zod';
import {
  AppleAuthError,
  type AppleAuthSessionRecord,
  type AppleCredentialRevocationSummary,
  type VerifiedAppleServerNotification,
} from './apple-auth.ts';
import {
  APPLE_ACCOUNT_DELETION_ORIGIN_INSTALLATION_LIMIT,
  APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_SECONDS,
  APPLE_ACCOUNT_DELETION_REVOCATION_LEASE_SECONDS,
  APPLE_ACCOUNT_DELETION_REVOCATION_SESSION_LIMIT,
  type AppleAccountDeletionRepository,
  type OriginConnectionRevocationSummary,
} from './apple-auth-lifecycle.ts';
import { readD1AppleLinkedIdentity } from './apple-identity-d1.ts';
import {
  APPLE_OWNER_EXTERNAL_OPERATION_ABSENT_SQL,
  appleOwnerExternalOperationAbsentBindings,
} from './apple-auth-owner-d1.ts';
import type { AppleNativeGrantRecord } from './apple-native-auth.ts';

const sessionRowSchema = z.object({
  schema_version: z.union([z.literal(1), z.literal(2)]),
  session_hash: z.string().length(43),
  owner_id: z.string().min(1).max(1_000),
  owner_binding: z.string().length(43),
  apple_subject_hash: z.string().length(43),
  encrypted_credentials: z.string().min(20).max(32_000),
  created_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  last_validated_at: z.number().int().positive(),
}).strict();
const nativeGrantRowSchema = z.object({
  schema_version: z.literal(1),
  grant_hash: z.string().length(43),
  authorization_code_hash: z.string().length(43),
  session_hash: z.string().length(43),
  owner_id: z.string().min(1).max(1_000),
  principal_id: z.string().length(43),
  apple_subject_hash: z.string().length(43),
  owner_binding: z.string().length(43),
  encrypted_credentials: z.string().min(20).max(24_000),
  created_at: z.number().int().positive(),
  last_validated_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  revocation_pending_at: z.number().int().positive().nullable(),
}).strict();

const notificationRowSchema = z.object({
  event_type: z.string(),
  apple_subject_hash: z.string().nullable(),
  owner_id: z.string().min(1).max(1_000).nullable(),
  issued_at: z.number().int(),
  event_time: z.number().int().nullable(),
}).strict();

const nonnegativeSafeIntegerSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const deletionProviderCredentialsSchema = z.object({
  credentialsFound: nonnegativeSafeIntegerSchema,
  credentialsRevoked: nonnegativeSafeIntegerSchema,
  unreadableSessions: nonnegativeSafeIntegerSchema,
  failedRevocations: nonnegativeSafeIntegerSchema,
  manualRevocationRequired: z.boolean(),
}).strict().refine(
  value => value.credentialsRevoked <= value.credentialsFound
    && value.failedRevocations === value.credentialsFound - value.credentialsRevoked
    && value.manualRevocationRequired === (
      value.credentialsFound === 0
      || value.unreadableSessions > 0
      || value.failedRevocations > 0
    ),
  {message: 'Provider credential counts are inconsistent.'},
);
const deletionOriginConnectionsSchema = z.object({
  installationsFound: nonnegativeSafeIntegerSchema,
  installationsRevoked: nonnegativeSafeIntegerSchema,
  unreadableInstallations: nonnegativeSafeIntegerSchema,
  failedRevocations: nonnegativeSafeIntegerSchema,
  manualRevocationRequired: z.boolean(),
}).strict().refine(
  value => value.installationsFound === (
    value.installationsRevoked + value.unreadableInstallations + value.failedRevocations
  ) && value.manualRevocationRequired === (
    value.unreadableInstallations > 0 || value.failedRevocations > 0
  ),
  {message: 'Origin connection revocation counts are inconsistent.'},
);
const originInstallationIdSchema = z.string().regex(/^(?:i|inst)_[a-z0-9]{8,100}$/);
const originUnresolvedInstallationIdsSchema = z.array(originInstallationIdSchema)
  .max(APPLE_ACCOUNT_DELETION_ORIGIN_INSTALLATION_LIMIT)
  .refine(value => new Set(value).size === value.length, {
    message: 'Origin installation cleanup identifiers must be unique.',
  })
  .refine(value => value.every((item, index) => index === 0 || value[index - 1]! < item), {
    message: 'Origin installation cleanup identifiers must be canonical.',
  });
const deletionReceiptRowSchema = z.object({
  owner_binding: z.string().length(43),
  provider_credentials: z.string().min(2).max(512),
  origin_connections: z.string().min(2).max(512),
  completion_fence_token: z.string().length(43),
}).strict();
const deletionAttemptRowSchema = z.object({
  owner_binding: z.string().length(43),
  owner_id: z.string().min(1).max(1_000),
  apple_subject_hash: z.string().length(43),
  apple_principal_id: z.string().length(43),
  delete_owner_data: z.union([z.literal(0), z.literal(1)]),
  provider_credentials: z.string().min(2).max(512).nullable(),
  origin_connections: z.string().min(2).max(512).nullable(),
  revocation_lease_token: z.string().length(43).nullable(),
  revocation_lease_until: nonnegativeSafeIntegerSchema.nullable(),
  completion_fence_token: z.string().length(43).nullable(),
}).strict().refine(
  value => (value.provider_credentials === null) === (value.origin_connections === null),
  {message: 'Account deletion completion fields are inconsistent.'},
).refine(
  value => (value.revocation_lease_token === null) === (value.revocation_lease_until === null),
  {message: 'Account deletion lease fields are inconsistent.'},
).refine(
  value => (value.provider_credentials === null) === (value.completion_fence_token === null),
  {message: 'Account deletion completion fence is inconsistent.'},
);

function parseSession(row: unknown): AppleAuthSessionRecord {
  const value = sessionRowSchema.parse(row);
  return {
    schemaVersion: value.schema_version,
    sessionHash: value.session_hash,
    ownerId: value.owner_id,
    ownerBinding: value.owner_binding,
    appleSubjectHash: value.apple_subject_hash,
    encryptedCredentials: value.encrypted_credentials,
    createdAt: value.created_at,
    expiresAt: value.expires_at,
    lastValidatedAt: value.last_validated_at,
  };
}

function parseNativeGrant(row: unknown): AppleNativeGrantRecord {
  const value = nativeGrantRowSchema.parse(row);
  return {
    schemaVersion: value.schema_version,
    grantHash: value.grant_hash,
    authorizationCodeHash: value.authorization_code_hash,
    sessionHash: value.session_hash,
    ownerId: value.owner_id,
    principalId: value.principal_id,
    appleSubjectHash: value.apple_subject_hash,
    ownerBinding: value.owner_binding,
    encryptedCredentials: value.encrypted_credentials,
    createdAt: value.created_at,
    lastValidatedAt: value.last_validated_at,
    expiresAt: value.expires_at,
    revocationPendingAt: value.revocation_pending_at,
  };
}

function canonicalProviderCredentials(
  input: AppleCredentialRevocationSummary,
): string {
  const value = deletionProviderCredentialsSchema.parse(input);
  return JSON.stringify({
    credentialsFound: value.credentialsFound,
    credentialsRevoked: value.credentialsRevoked,
    unreadableSessions: value.unreadableSessions,
    failedRevocations: value.failedRevocations,
    manualRevocationRequired: value.manualRevocationRequired,
  });
}

function canonicalOriginConnections(
  input: OriginConnectionRevocationSummary,
): string {
  const value = deletionOriginConnectionsSchema.parse(input);
  return JSON.stringify({
    installationsFound: value.installationsFound,
    installationsRevoked: value.installationsRevoked,
    unreadableInstallations: value.unreadableInstallations,
    failedRevocations: value.failedRevocations,
    manualRevocationRequired: value.manualRevocationRequired,
  });
}

function canonicalOriginUnresolvedInstallationIds(input: string[]): string {
  return JSON.stringify(originUnresolvedInstallationIdsSchema.parse([...input].sort()));
}

function parseDeletionReceipt(row: unknown): {
  ownerBinding: string;
  providerCredentials: AppleCredentialRevocationSummary;
  originConnections: OriginConnectionRevocationSummary;
} {
  try {
    const receipt = deletionReceiptRowSchema.parse(row);
    const encoded = receipt.provider_credentials;
    const parsed: unknown = JSON.parse(encoded);
    const value = deletionProviderCredentialsSchema.parse(parsed);
    if (encoded !== canonicalProviderCredentials(value)) throw new Error('Non-canonical receipt.');
    const encodedOrigin = receipt.origin_connections;
    const parsedOrigin: unknown = JSON.parse(encodedOrigin);
    const originConnections = deletionOriginConnectionsSchema.parse(parsedOrigin);
    if (encodedOrigin !== canonicalOriginConnections(originConnections)) throw new Error('Non-canonical receipt.');
    return {ownerBinding: receipt.owner_binding, providerCredentials: value, originConnections};
  } catch {
    throw invalidDeletionReceipt();
  }
}

async function readDeletionReceiptFromD1(
  database: D1Database,
  deletionKeyHash: string,
  now: number,
): Promise<{
  ownerBinding: string;
  providerCredentials: AppleCredentialRevocationSummary;
  originConnections: OriginConnectionRevocationSummary;
} | null> {
  const row = await database.prepare(
    `SELECT owner_binding,provider_credentials,origin_connections,completion_fence_token
     FROM apple_account_deletions
     WHERE deletion_key_hash=? AND expires_at>?
       AND provider_credentials IS NOT NULL AND origin_connections IS NOT NULL
       AND completed_at IS NOT NULL`,
  ).bind(deletionKeyHash, now).first();
  return row === null ? null : parseDeletionReceipt(row);
}

function assertDeletionAttemptMatches(
  stored: z.infer<typeof deletionAttemptRowSchema>,
  input: {
    ownerBinding: string;
    ownerId: string;
    appleSubjectHash: string;
    applePrincipalId?: string;
    deleteOwnerData: boolean;
  },
): void {
  if (
    stored.owner_binding !== input.ownerBinding ||
    stored.owner_id !== input.ownerId ||
    stored.apple_subject_hash !== input.appleSubjectHash ||
    (input.applePrincipalId !== undefined && stored.apple_principal_id !== input.applePrincipalId) ||
    stored.delete_owner_data !== (input.deleteOwnerData ? 1 : 0)
  ) {
    throw new AppleAuthError(
      409,
      'APPLE_ACCOUNT_DELETION_KEY_CONFLICT',
      'This account deletion key belongs to a different Apple identity.',
    );
  }
}

function invalidDeletionReceipt(): AppleAuthError {
  return new AppleAuthError(
    503,
    'APPLE_ACCOUNT_DELETION_RECEIPT_INVALID',
    'The stored account deletion receipt is invalid.',
  );
}

async function readDeletionAttemptFromD1(
  database: D1Database,
  deletionKeyHash: string,
  now: number,
): Promise<z.infer<typeof deletionAttemptRowSchema> | null> {
  const row = await database.prepare(
    `SELECT owner_binding,owner_id,apple_subject_hash,
            COALESCE(apple_principal_id,apple_subject_hash) AS apple_principal_id,delete_owner_data,
            provider_credentials,origin_connections,
            revocation_lease_token,revocation_lease_until,completion_fence_token
     FROM apple_account_deletions
     WHERE deletion_key_hash=? AND expires_at>?`,
  ).bind(deletionKeyHash, now).first();
  if (row === null) return null;
  try {
    return deletionAttemptRowSchema.parse(row);
  } catch {
    throw invalidDeletionReceipt();
  }
}

export function createD1AppleAccountDeletionRepository(
  database: D1Database,
): AppleAccountDeletionRepository {
  return {
    async readDeletionReceipt(deletionKeyHash, now) {
      return readDeletionReceiptFromD1(database, deletionKeyHash, now);
    },

    async readDeletionAttempt(deletionKeyHash, now) {
      const stored = await readDeletionAttemptFromD1(database, deletionKeyHash, now);
      if (stored === null) return null;
      return {
        ownerId: stored.owner_id,
        appleSubjectHash: stored.apple_subject_hash,
        deleteOwnerData: stored.delete_owner_data === 1,
        providerCredentials: stored.provider_credentials === null
          ? null
          : parseDeletionReceipt({
              owner_binding: stored.owner_binding,
              provider_credentials: stored.provider_credentials,
              origin_connections: stored.origin_connections,
              completion_fence_token: stored.completion_fence_token,
            }).providerCredentials,
        originConnections: stored.origin_connections === null
          ? null
          : parseDeletionReceipt({
              owner_binding: stored.owner_binding,
              provider_credentials: stored.provider_credentials,
              origin_connections: stored.origin_connections,
              completion_fence_token: stored.completion_fence_token,
            }).originConnections,
      };
    },

    async beginAppleAccountDeletion(input) {
      const keyedAttempt = await readDeletionAttemptFromD1(
        database,
        input.deletionKeyHash,
        input.leaseClaimedAt,
      );
      if (keyedAttempt !== null && keyedAttempt.provider_credentials !== null) {
        assertDeletionAttemptMatches(keyedAttempt, input);
        return parseDeletionReceipt({
          owner_binding: keyedAttempt.owner_binding,
          provider_credentials: keyedAttempt.provider_credentials,
          origin_connections: keyedAttempt.origin_connections,
          completion_fence_token: keyedAttempt.completion_fence_token,
        });
      }
      const identity = await readD1AppleLinkedIdentity(database, input.appleSubjectHash);
      if (identity === null || identity.ownerId !== input.ownerId) {
        throw new AppleAuthError(
          409,
          'APPLE_IDENTITY_LINK_MISSING',
          'Account deletion requires a current Apple identity group.',
        );
      }
      const principalId = identity.principalId;
      const currentIdentityGate = `EXISTS(
        SELECT 1 FROM apple_identity_links AS current_identity
        WHERE current_identity.apple_subject_hash=?
          AND current_identity.owner_id=?
          AND current_identity.principal_id=?
      )`;
      const currentIdentityBindings = [
        input.appleSubjectHash,
        input.ownerId,
        principalId,
      ];
      const scope = input.deleteOwnerData
        ? 'owner_id=? AND delete_owner_data=1'
        : 'owner_id=? AND COALESCE(apple_principal_id,apple_subject_hash)=? AND delete_owner_data=0';
      const scopeBindings = input.deleteOwnerData
        ? [input.ownerId]
        : [input.ownerId, principalId];
      const activeScope = input.deleteOwnerData
        ? 'active.owner_id=? AND active.delete_owner_data=1'
        : `active.owner_id=?
           AND COALESCE(active.apple_principal_id,active.apple_subject_hash)=?
           AND active.delete_owner_data=0`;
      const leaseUntil = input.leaseClaimedAt
        + APPLE_ACCOUNT_DELETION_REVOCATION_LEASE_SECONDS;
      const externalOperationGateBindings = appleOwnerExternalOperationAbsentBindings({
        ownerId: input.ownerId,
        applePrincipalId: principalId,
        deleteOwnerData: input.deleteOwnerData,
      }, input.leaseClaimedAt);
      const results = await database.batch([
        database.prepare(
          'DELETE FROM apple_account_deletions WHERE expires_at<=?',
        ).bind(input.startedAt),
        database.prepare(
          `UPDATE apple_account_deletions
           SET revocation_lease_token=NULL,revocation_lease_until=NULL
           WHERE provider_credentials IS NULL AND origin_connections IS NULL
             AND revocation_lease_until<=?`,
        ).bind(input.leaseClaimedAt),
        database.prepare(
          `INSERT INTO apple_account_deletions(
            deletion_key_hash,owner_binding,owner_id,apple_subject_hash,apple_principal_id,delete_owner_data,
            provider_credentials,origin_connections,
            revocation_lease_token,revocation_lease_until,
            completion_fence_token,started_at,completed_at,expires_at
          )
          SELECT ?,?,?,?,?,?,provider_credentials,origin_connections,NULL,NULL,
                 completion_fence_token,?,completed_at,expires_at
          FROM apple_account_deletions
          WHERE ${scope} AND completed_at>=? AND expires_at>?
            AND provider_credentials IS NOT NULL AND origin_connections IS NOT NULL
            AND ${currentIdentityGate}
          ORDER BY completed_at DESC LIMIT 1
          ON CONFLICT(deletion_key_hash) DO NOTHING`,
        ).bind(
          input.deletionKeyHash,
          input.ownerBinding,
          input.ownerId,
          input.appleSubjectHash,
          principalId,
          input.deleteOwnerData ? 1 : 0,
          input.startedAt,
          ...scopeBindings,
          input.startedAt,
          input.startedAt,
          ...currentIdentityBindings,
        ),
        database.prepare(
          `INSERT INTO apple_account_deletions(
            deletion_key_hash,owner_binding,owner_id,apple_subject_hash,apple_principal_id,delete_owner_data,
            provider_credentials,origin_connections,
            revocation_lease_token,revocation_lease_until,
            completion_fence_token,started_at,completed_at,expires_at
          ) SELECT ?,?,?,?,?,?,NULL,NULL,NULL,NULL,NULL,?,NULL,?
          WHERE ${currentIdentityGate}
          ON CONFLICT(deletion_key_hash) DO NOTHING`,
        ).bind(
          input.deletionKeyHash,
          input.ownerBinding,
          input.ownerId,
          input.appleSubjectHash,
          principalId,
          input.deleteOwnerData ? 1 : 0,
          input.startedAt,
          input.expiresAt,
          ...currentIdentityBindings,
        ),
        database.prepare(
          `UPDATE apple_account_deletions
           SET revocation_lease_token=?,revocation_lease_until=?
           WHERE deletion_key_hash=?
             AND provider_credentials IS NULL AND origin_connections IS NULL
             AND revocation_lease_token IS NULL AND revocation_lease_until IS NULL
             AND ${currentIdentityGate} AND ${APPLE_OWNER_EXTERNAL_OPERATION_ABSENT_SQL}
             AND NOT EXISTS(
               SELECT 1 FROM apple_account_deletions AS active
               WHERE active.deletion_key_hash<>?
                 AND active.provider_credentials IS NULL
                 AND active.origin_connections IS NULL
                 AND active.revocation_lease_token IS NOT NULL
                 AND active.revocation_lease_until>?
                 AND ${activeScope}
             )`,
        ).bind(
          input.revocationLeaseToken,
          leaseUntil,
          input.deletionKeyHash,
          ...currentIdentityBindings,
          ...externalOperationGateBindings,
          input.deletionKeyHash,
          input.leaseClaimedAt,
          ...scopeBindings,
        ),
      ]);
      const stored = await readDeletionAttemptFromD1(
        database,
        input.deletionKeyHash,
        input.leaseClaimedAt,
      );
      if (stored === null) {
        const currentIdentity = await readD1AppleLinkedIdentity(
          database,
          input.appleSubjectHash,
        );
        if (
          currentIdentity === null
          || currentIdentity.ownerId !== input.ownerId
          || currentIdentity.principalId !== principalId
        ) {
          throw new AppleAuthError(
            409,
            'APPLE_IDENTITY_LINK_CHANGED',
            'The Apple identity group changed while account deletion was starting. Retry deletion.',
          );
        }
        throw new AppleAuthError(
          409,
          'APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS',
          'An external repository operation is still using this Apple access. Retry account deletion after it finishes.',
        );
      }
      assertDeletionAttemptMatches(stored, {...input, applePrincipalId: principalId});
      if (stored.provider_credentials !== null) {
        return parseDeletionReceipt({
            owner_binding: stored.owner_binding,
            provider_credentials: stored.provider_credentials,
            origin_connections: stored.origin_connections,
            completion_fence_token: stored.completion_fence_token,
          });
      }
      const acquiredLease = (results[4].meta.changes ?? 0) === 1
        && stored.revocation_lease_token === input.revocationLeaseToken
        && stored.revocation_lease_until === leaseUntil;
      if (acquiredLease) {
        return null;
      }
      if (await database.prepare(
        `SELECT 1 AS active WHERE NOT (${APPLE_OWNER_EXTERNAL_OPERATION_ABSENT_SQL})`,
      ).bind(...externalOperationGateBindings).first() !== null) {
        throw new AppleAuthError(
          409,
          'APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS',
          'An external repository operation is still using this Apple access. Retry account deletion after it finishes.',
        );
      }
      throw new AppleAuthError(
        409,
        'APPLE_ACCOUNT_DELETION_IN_PROGRESS',
        'Another request is already completing this account deletion. Retry with the same key.',
      );
    },

    async readWebSessionsForDeletion(input) {
      const identity = await readD1AppleLinkedIdentity(database, input.appleSubjectHash);
      if (identity === null || identity.ownerId !== input.ownerId) {
        throw new AppleAuthError(
          409,
          'APPLE_IDENTITY_LINK_MISSING',
          'Account deletion requires a current Apple identity group.',
        );
      }
      const where = input.deleteOwnerData
        ? 'owner_id=?'
        : `owner_id=? AND apple_subject_hash IN (
            SELECT apple_subject_hash FROM apple_identity_links
            WHERE owner_id=? AND principal_id=?
          )`;
      const bindings = input.deleteOwnerData
        ? [input.ownerId]
        : [input.ownerId, input.ownerId, identity.principalId];
      const nativeWhere = input.deleteOwnerData
        ? 'owner_id=?'
        : 'owner_id=? AND principal_id=?';
      const nativeBindings = input.deleteOwnerData
        ? [input.ownerId]
        : [input.ownerId, identity.principalId];
      const possibleCredentialWhere = input.deleteOwnerData
        ? 'owner_id=?'
        : `owner_id=? AND COALESCE(
            (SELECT current_identity.principal_id
             FROM apple_identity_links AS current_identity
             WHERE current_identity.apple_subject_hash=apple_auth_possible_credentials.apple_subject_hash
               AND current_identity.owner_id=apple_auth_possible_credentials.owner_id),
            apple_principal_id
          )=?`;
      const possibleCredentialBindings = input.deleteOwnerData
        ? [input.ownerId]
        : [input.ownerId, identity.principalId];
      const countRow = z.object({count: nonnegativeSafeIntegerSchema}).strict().parse(
        await database.prepare(
          `SELECT COUNT(*) AS count FROM apple_auth_sessions WHERE ${where}`,
        ).bind(...bindings).first(),
      );
      const nativeCountRow = z.object({count: nonnegativeSafeIntegerSchema}).strict().parse(
        await database.prepare(
          `SELECT COUNT(*) AS count FROM apple_native_grants WHERE ${nativeWhere}`,
        ).bind(...nativeBindings).first(),
      );
      const possibleCredentialCountRow = z.object({count: nonnegativeSafeIntegerSchema})
        .strict().parse(await database.prepare(
          `SELECT COUNT(*) AS count FROM apple_auth_possible_credentials
           WHERE credential_state='possible' AND ${possibleCredentialWhere}`,
        ).bind(...possibleCredentialBindings).first());
      const statement = database.prepare(
        `SELECT schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
                encrypted_credentials,created_at,expires_at,last_validated_at
         FROM apple_auth_sessions
         WHERE ${where}
         ORDER BY created_at,session_hash
         LIMIT ?`,
      );
      const result = await statement.bind(
        ...bindings,
        APPLE_ACCOUNT_DELETION_REVOCATION_SESSION_LIMIT,
      ).all();
      const nativeResult = await database.prepare(
        `SELECT schema_version,grant_hash,authorization_code_hash,session_hash,owner_id,
                principal_id,apple_subject_hash,owner_binding,encrypted_credentials,
                created_at,last_validated_at,expires_at,revocation_pending_at
         FROM apple_native_grants WHERE ${nativeWhere}
         ORDER BY created_at,grant_hash LIMIT ?`,
      ).bind(...nativeBindings, APPLE_ACCOUNT_DELETION_REVOCATION_SESSION_LIMIT).all();
      const sessions: AppleAuthSessionRecord[] = [];
      const nativeGrants: AppleNativeGrantRecord[] = [];
      let unreadableSessions = Math.max(0, countRow.count - result.results.length)
        + Math.max(0, nativeCountRow.count - nativeResult.results.length)
        + possibleCredentialCountRow.count;
      for (const row of result.results) {
        try {
          sessions.push(parseSession(row));
        } catch {
          unreadableSessions += 1;
        }
      }
      for (const row of nativeResult.results) {
        try {
          nativeGrants.push(parseNativeGrant(row));
        } catch {
          unreadableSessions += 1;
        }
      }
      return {sessions, nativeGrants, unreadableSessions};
    },

    async readOriginInstallationsForDeletion(input) {
      const identity = await readD1AppleLinkedIdentity(database, input.appleSubjectHash);
      if (identity === null || identity.ownerId !== input.ownerId) {
        throw new AppleAuthError(
          409,
          'APPLE_IDENTITY_LINK_MISSING',
          'Account deletion requires a current Apple identity group.',
        );
      }
      const countRow = z.object({count: nonnegativeSafeIntegerSchema}).strict().parse(
        input.deleteOwnerData
          ? await database.prepare(
            'SELECT COUNT(*) AS count FROM origin_installations WHERE owner_id=?',
          ).bind(input.ownerId).first()
          : {count: 0},
      );
      const result = input.deleteOwnerData
        ? await database.prepare(
          `SELECT installation_id FROM origin_installations
           WHERE owner_id=? ORDER BY installation_id LIMIT ?`,
        ).bind(input.ownerId, APPLE_ACCOUNT_DELETION_ORIGIN_INSTALLATION_LIMIT).all()
        : {results: []};
      const markerWhere = input.deleteOwnerData
        ? 'owner_id=?'
        : `owner_id=? AND COALESCE(
            (SELECT current_identity.principal_id
             FROM apple_identity_links AS current_identity
             WHERE current_identity.apple_subject_hash=origin_possible_installations.apple_subject_hash
               AND current_identity.owner_id=origin_possible_installations.owner_id),
            apple_principal_id
          )=?`;
      const markerBindings = input.deleteOwnerData
        ? [input.ownerId]
        : [input.ownerId, identity.principalId];
      const markerCount = z.object({count: nonnegativeSafeIntegerSchema}).strict().parse(
        await database.prepare(
          `SELECT COUNT(*) AS count FROM origin_possible_installations
           WHERE ${markerWhere}`,
        ).bind(...markerBindings).first(),
      ).count;
      const installationSchema = z.object({installation_id: originInstallationIdSchema}).strict();
      const installationIds: string[] = [];
      let unreadableInstallations = Math.max(0, countRow.count - result.results.length)
        + markerCount;
      for (const row of result.results) {
        const parsed = installationSchema.safeParse(row);
        if (parsed.success) installationIds.push(parsed.data.installation_id);
        else unreadableInstallations += 1;
      }
      return {installationIds, unreadableInstallations};
    },

    async deleteAppleAccessAndCompleteReceipt(input) {
      const existing = await readDeletionAttemptFromD1(
        database,
        input.deletionKeyHash,
        input.completedAt,
      );
      if (existing === null) {
        throw new AppleAuthError(
          503,
          'APPLE_ACCOUNT_DELETION_ATTEMPT_MISSING',
          'Account deletion is missing its durable attempt gate.',
        );
      }
      assertDeletionAttemptMatches(existing, input);
      if (existing.provider_credentials !== null && existing.origin_connections !== null) {
        if (existing.completion_fence_token !== input.revocationLeaseToken) {
          throw new AppleAuthError(
            409,
            'APPLE_ACCOUNT_DELETION_LEASE_LOST',
            'This account deletion request no longer owns the completed provider-cleanup lease.',
          );
        }
        const receipt = parseDeletionReceipt({
          owner_binding: existing.owner_binding,
          provider_credentials: existing.provider_credentials,
          origin_connections: existing.origin_connections,
          completion_fence_token: existing.completion_fence_token,
        });
        return {
          created: false,
          providerCredentials: receipt.providerCredentials,
          originConnections: receipt.originConnections,
        };
      }
      if (
        existing.revocation_lease_token !== input.revocationLeaseToken
        || existing.revocation_lease_until === null
        || existing.revocation_lease_until < input.completedAt
      ) {
        throw new AppleAuthError(
          409,
          'APPLE_ACCOUNT_DELETION_LEASE_LOST',
          'This account deletion request no longer owns the provider-cleanup lease. Retry with the same key.',
        );
      }
      const providerCredentials = canonicalProviderCredentials(input.providerCredentials);
      const originConnections = canonicalOriginConnections(input.originConnections);
      const unresolvedOriginInstallations = input.originUnresolvedInstallationIds === undefined
        ? null
        : canonicalOriginUnresolvedInstallationIds(input.originUnresolvedInstallationIds);
      const completionScope = input.deleteOwnerData
        ? 'owner_id=? AND delete_owner_data=1'
        : `owner_id=? AND COALESCE(apple_principal_id,apple_subject_hash)=?
           AND delete_owner_data=0`;
      const completionBindings = input.deleteOwnerData
        ? [input.ownerId]
        : [input.ownerId, existing.apple_principal_id];
      const gate = `EXISTS(
        SELECT 1 FROM apple_account_deletions
        WHERE deletion_key_hash=? AND owner_binding=?
          AND revocation_lease_token=? AND revocation_lease_until>=?
      )`;
      const gatedOwnerDelete = (table: string, ownerColumn: 'user_id' | 'owner_id') => database.prepare(
        `DELETE FROM ${table} WHERE ${ownerColumn}=? AND ${gate}`,
      ).bind(
        input.ownerId,
        input.deletionKeyHash,
        input.ownerBinding,
        input.revocationLeaseToken,
        input.completedAt,
      );
      const gatedAppleSessionDelete = (table: 'apple_native_sessions' | 'apple_auth_sessions') => {
        const subjectFilter = input.deleteOwnerData ? '' : ` AND apple_subject_hash IN (
          SELECT apple_subject_hash FROM apple_identity_links
          WHERE owner_id=? AND principal_id=?
        )`;
        return database.prepare(
          `DELETE FROM ${table} WHERE owner_id=?${subjectFilter} AND ${gate}`,
        ).bind(
          input.ownerId,
          ...(input.deleteOwnerData ? [] : [input.ownerId, existing.apple_principal_id]),
          input.deletionKeyHash,
          input.ownerBinding,
          input.revocationLeaseToken,
          input.completedAt,
        );
      };
      const gatedNativeGrantDelete = database.prepare(
        `DELETE FROM apple_native_grants
         WHERE owner_id=?${input.deleteOwnerData ? '' : ' AND principal_id=?'} AND ${gate}`,
      ).bind(
        input.ownerId,
        ...(input.deleteOwnerData ? [] : [existing.apple_principal_id]),
        input.deletionKeyHash,
        input.ownerBinding,
        input.revocationLeaseToken,
        input.completedAt,
      );
      const gatedPossibleCredentialDelete = database.prepare(
        `DELETE FROM apple_auth_possible_credentials
         WHERE owner_id=?
           ${input.deleteOwnerData ? '' : `AND COALESCE(
             (SELECT current_identity.principal_id
              FROM apple_identity_links AS current_identity
              WHERE current_identity.apple_subject_hash=apple_auth_possible_credentials.apple_subject_hash
                AND current_identity.owner_id=apple_auth_possible_credentials.owner_id),
             apple_principal_id
           )=?`}
           AND ${gate}`,
      ).bind(
        input.ownerId,
        ...(input.deleteOwnerData ? [] : [existing.apple_principal_id]),
        input.deletionKeyHash,
        input.ownerBinding,
        input.revocationLeaseToken,
        input.completedAt,
      );
      const gatedPossibleInstallationDelete = database.prepare(
        `DELETE FROM origin_possible_installations
         WHERE owner_id=?
           ${input.deleteOwnerData ? '' : `AND COALESCE(
             (SELECT current_identity.principal_id
              FROM apple_identity_links AS current_identity
              WHERE current_identity.apple_subject_hash=origin_possible_installations.apple_subject_hash
                AND current_identity.owner_id=origin_possible_installations.owner_id),
             apple_principal_id
           )=?`}
           AND ${gate}`,
      ).bind(
        input.ownerId,
        ...(input.deleteOwnerData ? [] : [existing.apple_principal_id]),
        input.deletionKeyHash,
        input.ownerBinding,
        input.revocationLeaseToken,
        input.completedAt,
      );
      const statements: D1PreparedStatement[] = [
        database.prepare(
          'DELETE FROM apple_account_deletions WHERE expires_at<=? AND deletion_key_hash<>?',
        ).bind(input.completedAt, input.deletionKeyHash),
        database.prepare(
          `UPDATE apple_account_deletions
           SET provider_credentials=?,origin_connections=?,completion_fence_token=?,
               completed_at=?,expires_at=?
           WHERE ${completionScope} AND expires_at>?
             AND provider_credentials IS NULL AND origin_connections IS NULL
             AND ${gate}`,
        ).bind(
          providerCredentials,
          originConnections,
          input.revocationLeaseToken,
          input.completedAt,
          input.expiresAt,
          ...completionBindings,
          input.completedAt,
          input.deletionKeyHash,
          input.ownerBinding,
          input.revocationLeaseToken,
          input.completedAt,
        ),
      ];
      statements.push(database.prepare(
        `UPDATE apple_auth_notifications
         SET owner_id=NULL,origin_connections=?,origin_unresolved_installation_ids=?
         WHERE notification_id_hash IN (
           SELECT scoped_deletion.deletion_key_hash
           FROM apple_account_deletions AS scoped_deletion
           WHERE ${completionScope} AND scoped_deletion.completed_at=?
             AND scoped_deletion.provider_credentials=?
             AND scoped_deletion.origin_connections=?
         ) AND ${gate}`,
      ).bind(
        originConnections,
        unresolvedOriginInstallations,
        ...completionBindings,
        input.completedAt,
        providerCredentials,
        originConnections,
        input.deletionKeyHash,
        input.ownerBinding,
        input.revocationLeaseToken,
        input.completedAt,
      ));
      if (input.deleteOwnerData) {
        statements.push(
          gatedOwnerDelete('sync_records', 'user_id'),
          gatedOwnerDelete('sync_workspace_epochs', 'user_id'),
          gatedOwnerDelete('sync_workspaces', 'user_id'),
          gatedOwnerDelete('files', 'user_id'),
          gatedOwnerDelete('receipts', 'user_id'),
          gatedOwnerDelete('usage', 'user_id'),
          gatedOwnerDelete('workspaces', 'user_id'),
          gatedOwnerDelete('origin_auth_flows', 'owner_id'),
          gatedOwnerDelete('origin_installations', 'owner_id'),
          database.prepare(
            `DELETE FROM apple_auth_flows
             WHERE owner_id=? AND ${gate}`,
          ).bind(
            input.ownerId,
            input.deletionKeyHash,
            input.ownerBinding,
            input.revocationLeaseToken,
            input.completedAt,
          ),
        );
      }
      statements.push(database.prepare(
        `INSERT INTO apple_account_deletion_subjects(deletion_key_hash,apple_subject_hash)
         SELECT ?,identity.apple_subject_hash
         FROM apple_identity_links AS identity
         WHERE identity.owner_id=?${input.deleteOwnerData ? '' : ' AND identity.principal_id=?'}
           AND ${gate}
         ON CONFLICT(deletion_key_hash,apple_subject_hash) DO NOTHING`,
      ).bind(
        input.deletionKeyHash,
        input.ownerId,
        ...(input.deleteOwnerData ? [] : [existing.apple_principal_id]),
        input.deletionKeyHash,
        input.ownerBinding,
        input.revocationLeaseToken,
        input.completedAt,
      ));
      statements.push(
        gatedNativeGrantDelete,
        gatedAppleSessionDelete('apple_native_sessions'),
        gatedAppleSessionDelete('apple_auth_sessions'),
        gatedPossibleCredentialDelete,
        gatedPossibleInstallationDelete,
        database.prepare(
          `DELETE FROM apple_identity_links
           WHERE owner_id=?${input.deleteOwnerData ? '' : ' AND principal_id=?'} AND ${gate}`,
        ).bind(
          input.ownerId,
          ...(input.deleteOwnerData ? [] : [existing.apple_principal_id]),
          input.deletionKeyHash,
          input.ownerBinding,
          input.revocationLeaseToken,
          input.completedAt,
        ),
        database.prepare(
          `UPDATE apple_account_deletions
           SET revocation_lease_token=NULL,revocation_lease_until=NULL
           WHERE ${completionScope} AND completed_at=?
             AND provider_credentials=? AND origin_connections=?`,
        ).bind(
          ...completionBindings,
          input.completedAt,
          providerCredentials,
          originConnections,
        ),
      );
      const results = await database.batch(statements);
      const stored = await readDeletionReceiptFromD1(
        database,
        input.deletionKeyHash,
        input.completedAt,
      );
      if (stored === null) {
        throw new AppleAuthError(
          503,
          'APPLE_ACCOUNT_DELETION_RECEIPT_MISSING',
          'Account deletion did not produce a durable receipt.',
        );
      }
      if (stored.ownerBinding !== input.ownerBinding) {
        throw new AppleAuthError(
          409,
          'APPLE_ACCOUNT_DELETION_KEY_CONFLICT',
          'This account deletion key belongs to a different account.',
        );
      }
      return {
        created: (results[1].meta.changes ?? 0) > 0,
        providerCredentials: stored.providerCredentials,
        originConnections: stored.originConnections,
      };
    },

    async beginServerNotification(notification, now) {
      const eventType = notification.kind === 'unknown'
        ? notification.eventType
        : notification.kind;
      const insert = database.prepare(
        `INSERT INTO apple_auth_notifications(
          notification_id_hash,event_type,apple_subject_hash,owner_id,issued_at,
          event_time,processed_at,expires_at
        ) VALUES(?,?,?,(
          SELECT link.owner_id FROM apple_identity_links AS link
          WHERE link.apple_subject_hash=?
            AND (? IS NULL OR link.principal_created_at<=?)
        ),?,?,?,?)
        ON CONFLICT(notification_id_hash) DO NOTHING`,
      ).bind(
        notification.notificationIdHash,
        eventType,
        notification.appleSubjectHash,
        notification.appleSubjectHash,
        notification.eventTime,
        notification.eventTime,
        notification.issuedAt,
        notification.eventTime,
        now,
        notification.receiptExpiresAt,
      );
      const statements: D1PreparedStatement[] = [insert];
      if (notification.kind === 'email-enabled' || notification.kind === 'email-disabled') {
        statements.push(emailStateStatement(database, notification));
      } else if (
        notification.kind === 'consent-revoked' ||
        notification.kind === 'account-deleted'
      ) {
        statements.push(database.prepare(
          `INSERT INTO apple_account_deletions(
            deletion_key_hash,owner_binding,owner_id,apple_subject_hash,apple_principal_id,delete_owner_data,
            provider_credentials,origin_connections,
            revocation_lease_token,revocation_lease_until,
            completion_fence_token,started_at,completed_at,expires_at
          )
          SELECT ?,?,notification.owner_id,?,identity.principal_id,
                 CASE WHEN length(notification.owner_id)=58
                   AND substr(notification.owner_id,1,15)='apple-owner:v1.'
                   AND substr(notification.owner_id,16) NOT GLOB '*[^A-Za-z0-9_-]*'
                 THEN 1 ELSE 0 END,
                 NULL,NULL,NULL,NULL,NULL,?,NULL,?
          FROM apple_auth_notifications AS notification
          JOIN apple_identity_links AS identity
            ON identity.apple_subject_hash=notification.apple_subject_hash
           AND identity.owner_id=notification.owner_id
          WHERE notification.notification_id_hash=?
            AND notification.owner_id IS NOT NULL
            AND ${notificationGate()}
          ON CONFLICT(deletion_key_hash) DO NOTHING`,
        ).bind(
          notification.notificationIdHash,
          notification.notificationIdHash,
          notification.appleSubjectHash,
          notification.eventTime,
          Math.min(
            notification.receiptExpiresAt,
            now + APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_SECONDS,
          ),
          notification.notificationIdHash,
          ...notificationGateValues(notification),
        ));
      }
      statements.push(
        database.prepare(
          'DELETE FROM apple_auth_notifications WHERE expires_at<=? AND notification_id_hash<>?',
        ).bind(now, notification.notificationIdHash),
      );
      const results = await database.batch(statements);
      const stored = notificationRowSchema.parse(await database.prepare(
        `SELECT event_type,apple_subject_hash,owner_id,issued_at,event_time
         FROM apple_auth_notifications WHERE notification_id_hash=?`,
      ).bind(notification.notificationIdHash).first());
      if (
        stored.event_type !== eventType ||
        stored.apple_subject_hash !== notification.appleSubjectHash ||
        stored.issued_at !== notification.issuedAt ||
        stored.event_time !== notification.eventTime
      ) {
        throw new AppleAuthError(
          409,
          'APPLE_NOTIFICATION_REPLAY_CONFLICT',
          'The Apple notification identifier was reused with different event data.',
        );
      }
      return {
        idempotent: (results[0].meta.changes ?? 0) === 0,
        ownerId: stored.owner_id,
      };
    },
  };
}

function notificationGate(): string {
  return `EXISTS(
    SELECT 1 FROM apple_auth_notifications
    WHERE notification_id_hash=? AND event_type=? AND apple_subject_hash IS ?
      AND issued_at=? AND event_time IS ?
  )`;
}

function notificationGateValues(notification: VerifiedAppleServerNotification): unknown[] {
  return [
    notification.notificationIdHash,
    notification.kind === 'unknown' ? notification.eventType : notification.kind,
    notification.appleSubjectHash,
    notification.issuedAt,
    notification.eventTime,
  ];
}

function emailStateStatement(
  database: D1Database,
  notification: Extract<VerifiedAppleServerNotification, {kind: 'email-enabled' | 'email-disabled'}>,
): D1PreparedStatement {
  return database.prepare(
    `UPDATE apple_identity_links
     SET email_forwarding_enabled=?,email_state_updated_at=?
     WHERE apple_subject_hash=?
       AND principal_created_at<=?
       AND (email_state_updated_at IS NULL OR email_state_updated_at<=?)
       AND ${notificationGate()}`,
  ).bind(
    notification.kind === 'email-enabled' ? 1 : 0,
    notification.eventTime,
    notification.appleSubjectHash,
    notification.eventTime,
    notification.eventTime,
    ...notificationGateValues(notification),
  );
}
