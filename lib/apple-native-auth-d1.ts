import { z } from 'zod';
import { AppleAuthError } from './apple-auth.ts';
import { purgeExpiredAppleAuthLifecycleRecords } from './apple-auth-retention-d1.ts';
import {
  AppleOwnerExternalOperationError,
  createD1AppleOwnerExternalOperationLeaseRepository,
} from './apple-auth-external-operation-d1.ts';
import {
  appleIdentityDeletionAdmissionGate,
  bindD1AppleIdentityGroup,
  hasD1AppleIdentityDeletion,
  readD1AppleLinkedIdentity,
} from './apple-identity-d1.ts';
import {
  APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS,
  type AppleNativeAuthRepository,
  type AppleNativeGrantRecord,
  type AppleNativeSession,
  type AppleNativeSessionRecord,
} from './apple-native-auth.ts';

const digestSchema = z.string().length(43);
const activationStateSchema = z.enum(['pending', 'active']);
const nativeSessionRowSchema = z.object({
  schema_version: z.literal(1),
  identity_token_hash: digestSchema,
  session_hash: digestSchema,
  owner_id: z.string().min(1).max(1_000),
  apple_subject_hash: digestSchema,
  activation_state: activationStateSchema,
  created_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  identity_token_expires_at: z.number().int().positive(),
}).strict();
const nativeGrantRowSchema = z.object({
  schema_version: z.literal(1),
  grant_hash: digestSchema,
  authorization_code_hash: digestSchema,
  session_hash: digestSchema,
  owner_id: z.string().min(1).max(1_000),
  principal_id: digestSchema,
  apple_subject_hash: digestSchema,
  owner_binding: digestSchema,
  encrypted_credentials: z.string().min(20).max(24_000),
  created_at: z.number().int().positive(),
  last_validated_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
  revocation_pending_at: z.number().int().positive().nullable(),
}).strict();
const nativeSessionGrantRowSchema = z.object({
  session_schema_version: z.literal(1),
  session_identity_token_hash: digestSchema,
  session_hash: digestSchema,
  session_owner_id: z.string().min(1).max(1_000),
  session_apple_subject_hash: digestSchema,
  session_activation_state: activationStateSchema,
  session_created_at: z.number().int().positive(),
  session_expires_at: z.number().int().positive(),
  session_identity_token_expires_at: z.number().int().positive(),
  grant_schema_version: z.literal(1),
  grant_hash: digestSchema,
  grant_authorization_code_hash: digestSchema,
  grant_owner_id: z.string().min(1).max(1_000),
  grant_principal_id: digestSchema,
  grant_apple_subject_hash: digestSchema,
  grant_owner_binding: digestSchema,
  grant_encrypted_credentials: z.string().min(20).max(24_000),
  grant_created_at: z.number().int().positive(),
  grant_last_validated_at: z.number().int().positive(),
  grant_expires_at: z.number().int().positive(),
  grant_revocation_pending_at: z.number().int().positive().nullable(),
}).strict();

function parseSessionRecord(row: unknown): AppleNativeSessionRecord {
  const parsed = nativeSessionRowSchema.parse(row);
  return {
    schemaVersion: parsed.schema_version,
    identityTokenHash: parsed.identity_token_hash,
    sessionHash: parsed.session_hash,
    ownerId: parsed.owner_id,
    principalId: '',
    appleSubjectHash: parsed.apple_subject_hash,
    activationState: parsed.activation_state,
    createdAt: parsed.created_at,
    expiresAt: parsed.expires_at,
    identityTokenExpiresAt: parsed.identity_token_expires_at,
  };
}

function parseSession(row: unknown): AppleNativeSession {
  const parsed = parseSessionRecord(row);
  return {
    schemaVersion: parsed.schemaVersion,
    ownerId: parsed.ownerId,
    appleSubjectHash: parsed.appleSubjectHash,
    createdAt: parsed.createdAt,
    expiresAt: parsed.expiresAt,
  };
}

function parseGrant(row: unknown): AppleNativeGrantRecord {
  const parsed = nativeGrantRowSchema.parse(row);
  return {
    schemaVersion: parsed.schema_version,
    grantHash: parsed.grant_hash,
    authorizationCodeHash: parsed.authorization_code_hash,
    sessionHash: parsed.session_hash,
    ownerId: parsed.owner_id,
    principalId: parsed.principal_id,
    appleSubjectHash: parsed.apple_subject_hash,
    ownerBinding: parsed.owner_binding,
    encryptedCredentials: parsed.encrypted_credentials,
    createdAt: parsed.created_at,
    lastValidatedAt: parsed.last_validated_at,
    expiresAt: parsed.expires_at,
    revocationPendingAt: parsed.revocation_pending_at,
  };
}

const sessionColumns = `schema_version,identity_token_hash,session_hash,owner_id,
  apple_subject_hash,activation_state,created_at,expires_at,identity_token_expires_at`;
const grantColumns = `schema_version,grant_hash,authorization_code_hash,session_hash,
  owner_id,principal_id,apple_subject_hash,owner_binding,encrypted_credentials,
  created_at,last_validated_at,expires_at,revocation_pending_at`;

export function createD1AppleNativeAuthRepository(
  database: D1Database,
): AppleNativeAuthRepository {
  const authorizationLeases = createD1AppleOwnerExternalOperationLeaseRepository(database);
  return {
    async resolveAppleOwner({
      appleSubjectHash,
      transferSubjectHash = null,
      proposedOwnerId,
      requiredOwnerId = null,
      requiredPrincipalId = null,
      now,
      authorizationStartedAt = now,
    }) {
      const hashes = transferSubjectHash === null || transferSubjectHash === appleSubjectHash
        ? [appleSubjectHash]
        : [appleSubjectHash, transferSubjectHash];
      const result = await bindD1AppleIdentityGroup({
        database,
        appleSubjectHashes: hashes,
        proposedOwnerId,
        requiredOwnerId,
        requiredPrincipalId,
        now,
        authorizationStartedAt,
      });
      if (result.kind === 'owner-conflict') throw transferConflict();
      return {
        ownerId: result.ownerId,
        principalId: result.principalId,
        created: result.created,
      };
    },

    readLinkedIdentity(appleSubjectHash) {
      return readD1AppleLinkedIdentity(database, appleSubjectHash);
    },

    async claimAuthorizationCode(authorizationCodeHash, claimedAt, expiresAt) {
      const claimed = await database.prepare(
        `INSERT INTO apple_native_authorization_code_claims(
          authorization_code_hash,claimed_at,expires_at
        ) VALUES(?,?,?) ON CONFLICT(authorization_code_hash) DO NOTHING
        RETURNING authorization_code_hash`,
      ).bind(authorizationCodeHash, claimedAt, expiresAt).first();
      return claimed !== null;
    },

    async createSessionWithGrant(
      session: AppleNativeSessionRecord,
      grant: AppleNativeGrantRecord,
      authorizationStartedAt = session.createdAt,
    ) {
      await purgeExpiredAppleAuthLifecycleRecords(database, session.createdAt);
      const identity = await readD1AppleLinkedIdentity(database, session.appleSubjectHash);
      if (
        identity === null
        || identity.ownerId !== session.ownerId
        || identity.principalId !== session.principalId
        || grant.ownerId !== session.ownerId
        || grant.principalId !== session.principalId
        || grant.appleSubjectHash !== session.appleSubjectHash
        || grant.sessionHash !== session.sessionHash
      ) throw transferConflict();
      if (await hasD1AppleIdentityDeletion(database, {
        ownerId: session.ownerId,
        principalIds: [identity.principalId],
        appleSubjectHashes: [session.appleSubjectHash],
        now: session.createdAt,
        authorizationStartedAt,
      })) throw deletionInProgress();
      const deletionAdmission = appleIdentityDeletionAdmissionGate({
        ownerId: session.ownerId,
        principalIds: [identity.principalId],
        appleSubjectHashes: [session.appleSubjectHash],
        now: session.createdAt,
        authorizationStartedAt,
      });
      const currentIdentityGate = `EXISTS(
        SELECT 1 FROM apple_identity_links AS current_identity
        WHERE current_identity.apple_subject_hash=?
          AND current_identity.owner_id=?
          AND current_identity.principal_id=?
      )`;
      const currentIdentityBindings = [
        session.appleSubjectHash,
        session.ownerId,
        session.principalId,
      ];
      const results = await database.batch([
        database.prepare(
          `INSERT INTO apple_native_sessions(
            schema_version,identity_token_hash,session_hash,owner_id,apple_subject_hash,
            activation_state,created_at,expires_at,identity_token_expires_at,revoked_at
          ) SELECT ?,?,?,?,?,?,?,?,?,NULL
          WHERE ${deletionAdmission.sql} AND ${currentIdentityGate}
          ON CONFLICT(identity_token_hash) DO NOTHING`,
        ).bind(
          session.schemaVersion,
          session.identityTokenHash,
          session.sessionHash,
          session.ownerId,
          session.appleSubjectHash,
          session.activationState,
          session.createdAt,
          session.expiresAt,
          session.identityTokenExpiresAt,
          ...deletionAdmission.bindings,
          ...currentIdentityBindings,
        ),
        database.prepare(
          `INSERT INTO apple_native_grants(
            schema_version,grant_hash,authorization_code_hash,session_hash,owner_id,
            principal_id,apple_subject_hash,owner_binding,encrypted_credentials,
            created_at,last_validated_at,expires_at,revocation_pending_at
          ) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?
          WHERE EXISTS(
            SELECT 1 FROM apple_native_sessions
            WHERE identity_token_hash=? AND session_hash=? AND owner_id=?
          ) AND ${deletionAdmission.sql} AND ${currentIdentityGate}
          ON CONFLICT(authorization_code_hash) DO NOTHING`,
        ).bind(
          grant.schemaVersion,
          grant.grantHash,
          grant.authorizationCodeHash,
          grant.sessionHash,
          grant.ownerId,
          grant.principalId,
          grant.appleSubjectHash,
          grant.ownerBinding,
          grant.encryptedCredentials,
          grant.createdAt,
          grant.lastValidatedAt,
          grant.expiresAt,
          grant.revocationPendingAt,
          session.identityTokenHash,
          session.sessionHash,
          session.ownerId,
          ...deletionAdmission.bindings,
          ...currentIdentityBindings,
        ),
        database.prepare(
          `DELETE FROM apple_native_sessions
           WHERE identity_token_hash=? AND session_hash=?
             AND NOT EXISTS(
               SELECT 1 FROM apple_native_grants
               WHERE session_hash=? AND authorization_code_hash=?
             )`,
        ).bind(
          session.identityTokenHash,
          session.sessionHash,
          session.sessionHash,
          grant.authorizationCodeHash,
        ),
      ]);
      if (
        (results[0].meta.changes ?? 0) !== 1
        || (results[1].meta.changes ?? 0) !== 1
      ) {
        const currentIdentity = await readD1AppleLinkedIdentity(
          database,
          session.appleSubjectHash,
        );
        if (
          currentIdentity === null
          || currentIdentity.ownerId !== session.ownerId
          || currentIdentity.principalId !== session.principalId
        ) throw transferConflict();
        if (await hasD1AppleIdentityDeletion(database, {
          ownerId: session.ownerId,
          principalIds: [identity.principalId],
          appleSubjectHashes: [session.appleSubjectHash],
          now: session.createdAt,
          authorizationStartedAt,
        })) throw deletionInProgress();
        return false;
      }
      const stored = await database.prepare(
        `SELECT grant_hash FROM apple_native_grants
         WHERE grant_hash=? AND session_hash=? AND authorization_code_hash=?`,
      ).bind(grant.grantHash, session.sessionHash, grant.authorizationCodeHash).first();
      return stored !== null;
    },

    async createSession(record, authorizationStartedAt = record.createdAt) {
      await purgeExpiredAppleAuthLifecycleRecords(database, record.createdAt);
      const identity = await readD1AppleLinkedIdentity(database, record.appleSubjectHash);
      if (identity === null || identity.ownerId !== record.ownerId) throw transferConflict();
      if (await hasD1AppleIdentityDeletion(database, {
        ownerId: record.ownerId,
        principalIds: [identity.principalId],
        appleSubjectHashes: [record.appleSubjectHash],
        now: record.createdAt,
        authorizationStartedAt,
      })) throw deletionInProgress();
      const deletionAdmission = appleIdentityDeletionAdmissionGate({
        ownerId: record.ownerId,
        principalIds: [identity.principalId],
        appleSubjectHashes: [record.appleSubjectHash],
        now: record.createdAt,
        authorizationStartedAt,
      });
      const currentIdentityGate = `EXISTS(
        SELECT 1 FROM apple_identity_links AS current_identity
        WHERE current_identity.apple_subject_hash=?
          AND current_identity.owner_id=?
          AND current_identity.principal_id=?
      )`;
      const inserted = await database.prepare(
        `INSERT INTO apple_native_sessions(
          schema_version,identity_token_hash,session_hash,owner_id,apple_subject_hash,
          activation_state,created_at,expires_at,identity_token_expires_at,revoked_at
        ) SELECT ?,?,?,?,?,?,?,?,?,NULL
        WHERE ${deletionAdmission.sql} AND ${currentIdentityGate}
        ON CONFLICT(identity_token_hash) DO NOTHING RETURNING session_hash`,
      ).bind(
        record.schemaVersion,
        record.identityTokenHash,
        record.sessionHash,
        record.ownerId,
        record.appleSubjectHash,
        record.activationState,
        record.createdAt,
        record.expiresAt,
        record.identityTokenExpiresAt,
        ...deletionAdmission.bindings,
        record.appleSubjectHash,
        record.ownerId,
        record.principalId,
      ).first();
      if (inserted === null) {
        const currentIdentity = await readD1AppleLinkedIdentity(
          database,
          record.appleSubjectHash,
        );
        if (
          currentIdentity === null
          || currentIdentity.ownerId !== record.ownerId
          || currentIdentity.principalId !== record.principalId
        ) throw transferConflict();
        if (await hasD1AppleIdentityDeletion(database, {
          ownerId: record.ownerId,
          principalIds: [identity.principalId],
          appleSubjectHashes: [record.appleSubjectHash],
          now: record.createdAt,
          authorizationStartedAt,
        })) throw deletionInProgress();
      }
      return inserted !== null;
    },

    async activateSession(sessionHash, now) {
      await purgeExpiredAppleAuthLifecycleRecords(database, now);
      const row = await database.prepare(
        `UPDATE apple_native_sessions
         SET activation_state='active'
         WHERE session_hash=? AND activation_state IN ('pending','active')
           AND revoked_at IS NULL AND expires_at>?
           AND EXISTS(
             SELECT 1 FROM apple_auth_admission_cutover AS admission_cutover
             WHERE admission_cutover.singleton=1
               AND apple_native_sessions.created_at>admission_cutover.cutover_at
           )
           AND EXISTS(
             SELECT 1 FROM apple_native_grants AS grant
             JOIN apple_identity_links AS identity
               ON identity.apple_subject_hash=grant.apple_subject_hash
              AND identity.owner_id=grant.owner_id
              AND identity.principal_id=grant.principal_id
             WHERE grant.session_hash=apple_native_sessions.session_hash
               AND grant.owner_id=apple_native_sessions.owner_id
               AND grant.apple_subject_hash=apple_native_sessions.apple_subject_hash
               AND grant.expires_at>? AND grant.revocation_pending_at IS NULL
           )
           AND NOT EXISTS(
             SELECT 1 FROM apple_account_deletions AS deletion
             JOIN apple_native_grants AS grant
               ON grant.session_hash=apple_native_sessions.session_hash
              AND grant.owner_id=apple_native_sessions.owner_id
              AND grant.apple_subject_hash=apple_native_sessions.apple_subject_hash
             WHERE deletion.expires_at>?
               AND deletion.owner_id=apple_native_sessions.owner_id
               AND (deletion.delete_owner_data=1 OR COALESCE(
                 deletion.apple_principal_id,deletion.apple_subject_hash
               )=grant.principal_id)
               AND (deletion.provider_credentials IS NULL OR deletion.origin_connections IS NULL
                 OR deletion.completion_fence_token IS NULL OR deletion.completed_at IS NULL
                 OR deletion.completed_at>=apple_native_sessions.created_at)
           )
         RETURNING ${sessionColumns}`,
      ).bind(sessionHash, now, now, now).first();
      return row ? parseSession(row) : null;
    },

    async readSession(sessionHash, now) {
      await purgeExpiredAppleAuthLifecycleRecords(database, now);
      const row = await database.prepare(
        `SELECT ${sessionColumns}
         FROM apple_native_sessions
         WHERE session_hash=? AND activation_state='active'
           AND revoked_at IS NULL AND expires_at>?
           AND EXISTS(
             SELECT 1 FROM apple_auth_admission_cutover AS admission_cutover
             WHERE admission_cutover.singleton=1
               AND apple_native_sessions.created_at>admission_cutover.cutover_at
           )
           AND EXISTS(
             SELECT 1 FROM apple_identity_links AS identity
             WHERE identity.apple_subject_hash=apple_native_sessions.apple_subject_hash
               AND identity.owner_id=apple_native_sessions.owner_id
           )
           AND NOT EXISTS(
             SELECT 1 FROM apple_account_deletions AS deletion
             WHERE deletion.expires_at>?
               AND deletion.owner_id=apple_native_sessions.owner_id
               AND (deletion.delete_owner_data=1 OR COALESCE(
                 deletion.apple_principal_id,deletion.apple_subject_hash
               )=(
                 SELECT identity.principal_id FROM apple_identity_links AS identity
                 WHERE identity.apple_subject_hash=apple_native_sessions.apple_subject_hash
                   AND identity.owner_id=apple_native_sessions.owner_id
               ))
               AND (deletion.provider_credentials IS NULL OR deletion.origin_connections IS NULL
                 OR deletion.completion_fence_token IS NULL OR deletion.completed_at IS NULL
                 OR deletion.completed_at>=apple_native_sessions.created_at)
           )`,
      ).bind(sessionHash, now, now).first();
      return row ? parseSession(row) : null;
    },

    async readSessionWithGrant(sessionHash, now) {
      const row = await database.prepare(
        `SELECT session.schema_version AS session_schema_version,
                session.identity_token_hash AS session_identity_token_hash,
                session.session_hash AS session_hash,
                session.owner_id AS session_owner_id,
                session.apple_subject_hash AS session_apple_subject_hash,
                session.activation_state AS session_activation_state,
                session.created_at AS session_created_at,
                session.expires_at AS session_expires_at,
                session.identity_token_expires_at AS session_identity_token_expires_at,
                grant.schema_version AS grant_schema_version,
                grant.grant_hash AS grant_hash,
                grant.authorization_code_hash AS grant_authorization_code_hash,
                grant.owner_id AS grant_owner_id,
                grant.principal_id AS grant_principal_id,
                grant.apple_subject_hash AS grant_apple_subject_hash,
                grant.owner_binding AS grant_owner_binding,
                grant.encrypted_credentials AS grant_encrypted_credentials,
                grant.created_at AS grant_created_at,
                grant.last_validated_at AS grant_last_validated_at,
                grant.expires_at AS grant_expires_at,
                grant.revocation_pending_at AS grant_revocation_pending_at
         FROM apple_native_sessions AS session
         JOIN apple_native_grants AS grant
           ON grant.session_hash=session.session_hash
          AND grant.owner_id=session.owner_id
          AND grant.apple_subject_hash=session.apple_subject_hash
         JOIN apple_identity_links AS identity
           ON identity.apple_subject_hash=grant.apple_subject_hash
          AND identity.owner_id=grant.owner_id
          AND identity.principal_id=grant.principal_id
         JOIN apple_auth_admission_cutover AS admission_cutover
           ON admission_cutover.singleton=1
          AND session.created_at>admission_cutover.cutover_at
         WHERE session.session_hash=? AND session.activation_state='active'
           AND session.revoked_at IS NULL
           AND session.expires_at>? AND grant.expires_at>?
           AND grant.revocation_pending_at IS NULL
           AND NOT EXISTS(
             SELECT 1 FROM apple_account_deletions AS deletion
             WHERE deletion.expires_at>?
               AND deletion.owner_id=session.owner_id
               AND (deletion.delete_owner_data=1
                 OR COALESCE(deletion.apple_principal_id,deletion.apple_subject_hash)=grant.principal_id)
               AND (deletion.provider_credentials IS NULL OR deletion.origin_connections IS NULL
                 OR deletion.completion_fence_token IS NULL OR deletion.completed_at IS NULL
                 OR deletion.completed_at>=session.created_at)
           )`,
      ).bind(sessionHash, now, now, now).first();
      if (row === null) return null;
      const parsed = nativeSessionGrantRowSchema.parse(row);
      const session = parseSessionRecord({
        schema_version:parsed.session_schema_version,
        identity_token_hash:parsed.session_identity_token_hash,
        session_hash:parsed.session_hash,
        owner_id:parsed.session_owner_id,
        apple_subject_hash:parsed.session_apple_subject_hash,
        activation_state:parsed.session_activation_state,
        created_at:parsed.session_created_at,
        expires_at:parsed.session_expires_at,
        identity_token_expires_at:parsed.session_identity_token_expires_at,
      });
      const grant = parseGrant({
        schema_version:parsed.grant_schema_version,
        grant_hash:parsed.grant_hash,
        authorization_code_hash:parsed.grant_authorization_code_hash,
        session_hash:parsed.session_hash,
        owner_id:parsed.grant_owner_id,
        principal_id:parsed.grant_principal_id,
        apple_subject_hash:parsed.grant_apple_subject_hash,
        owner_binding:parsed.grant_owner_binding,
        encrypted_credentials:parsed.grant_encrypted_credentials,
        created_at:parsed.grant_created_at,
        last_validated_at:parsed.grant_last_validated_at,
        expires_at:parsed.grant_expires_at,
        revocation_pending_at:parsed.grant_revocation_pending_at,
      });
      session.principalId = grant.principalId;
      if (
        session.ownerId !== grant.ownerId
        || session.appleSubjectHash !== grant.appleSubjectHash
      ) throw transferConflict();
      return {session, grant};
    },

    async updateSessionAndGrant(input) {
      const identityGate = `EXISTS(
        SELECT 1 FROM apple_identity_links
        WHERE apple_subject_hash=? AND owner_id=? AND principal_id=?
      )`;
      const deletionGate = `NOT EXISTS(
        SELECT 1 FROM apple_account_deletions
        WHERE expires_at>? AND owner_id=?
          AND (delete_owner_data=1 OR COALESCE(apple_principal_id,apple_subject_hash)=?)
          AND (provider_credentials IS NULL OR origin_connections IS NULL
            OR completion_fence_token IS NULL OR completed_at IS NULL OR completed_at>=?)
      )`;
      const sessionAdmissionGate = `EXISTS(
        SELECT 1 FROM apple_native_sessions AS admission_session
        JOIN apple_auth_admission_cutover AS admission_cutover
          ON admission_cutover.singleton=1
         AND admission_session.created_at>admission_cutover.cutover_at
        WHERE admission_session.session_hash=? AND admission_session.owner_id=?
          AND admission_session.apple_subject_hash=?
          AND admission_session.activation_state='active'
          AND admission_session.revoked_at IS NULL
      )`;
      const sessionAdmissionBindings = [
        input.sessionHash,
        input.ownerId,
        input.appleSubjectHash,
      ];
      const completedSessionGate = `EXISTS(
        SELECT 1 FROM apple_native_sessions AS completed_session
        JOIN apple_auth_admission_cutover AS admission_cutover
          ON admission_cutover.singleton=1
         AND completed_session.created_at>admission_cutover.cutover_at
        JOIN apple_identity_links AS completed_identity
          ON completed_identity.apple_subject_hash=completed_session.apple_subject_hash
         AND completed_identity.owner_id=completed_session.owner_id
         AND completed_identity.principal_id=?
        WHERE completed_session.session_hash=? AND completed_session.owner_id=?
          AND completed_session.apple_subject_hash=?
          AND completed_session.activation_state='active'
          AND completed_session.revoked_at IS NULL
          AND completed_session.expires_at=? AND completed_session.identity_token_expires_at=?
          AND NOT EXISTS(
            SELECT 1 FROM apple_account_deletions AS completed_deletion
            WHERE completed_deletion.expires_at>? AND completed_deletion.owner_id=?
              AND (completed_deletion.delete_owner_data=1 OR COALESCE(
                completed_deletion.apple_principal_id,completed_deletion.apple_subject_hash
              )=?)
              AND (completed_deletion.provider_credentials IS NULL
                OR completed_deletion.origin_connections IS NULL
                OR completed_deletion.completion_fence_token IS NULL
                OR completed_deletion.completed_at IS NULL
                OR completed_deletion.completed_at>=?)
          )
      )`;
      const completedSessionBindings = [
        input.principalId,
        input.sessionHash,
        input.ownerId,
        input.appleSubjectHash,
        input.sessionExpiresAt,
        input.identityTokenExpiresAt,
        input.lastValidatedAt,
        input.ownerId,
        input.principalId,
        input.lastValidatedAt,
      ];
      const gateBindings = [
        input.appleSubjectHash,
        input.ownerId,
        input.principalId,
        input.lastValidatedAt,
        input.ownerId,
        input.principalId,
        input.lastValidatedAt,
      ];
      const results = await database.batch([
        database.prepare(
          `UPDATE apple_native_grants
           SET encrypted_credentials=?,last_validated_at=?,expires_at=?,revocation_pending_at=NULL
           WHERE session_hash=? AND owner_id=? AND principal_id=? AND apple_subject_hash=?
             AND encrypted_credentials=? AND last_validated_at=?
             AND expires_at>? AND revocation_pending_at IS NULL
             AND ${identityGate} AND ${deletionGate} AND ${sessionAdmissionGate}`,
        ).bind(
          input.encryptedCredentials,
          input.lastValidatedAt,
          input.grantExpiresAt,
          input.sessionHash,
          input.ownerId,
          input.principalId,
          input.appleSubjectHash,
          input.expectedEncryptedCredentials,
          input.expectedLastValidatedAt,
          input.lastValidatedAt,
          ...gateBindings,
          ...sessionAdmissionBindings,
        ),
        database.prepare(
          `UPDATE apple_native_sessions
           SET expires_at=?,identity_token_expires_at=?
           WHERE session_hash=? AND owner_id=? AND apple_subject_hash=?
             AND activation_state='active' AND revoked_at IS NULL AND expires_at>?
             AND EXISTS(
               SELECT 1 FROM apple_auth_admission_cutover AS admission_cutover
               WHERE admission_cutover.singleton=1
                 AND apple_native_sessions.created_at>admission_cutover.cutover_at
             )
             AND EXISTS(
               SELECT 1 FROM apple_native_grants
               WHERE session_hash=? AND owner_id=? AND principal_id=?
                 AND apple_subject_hash=? AND encrypted_credentials=?
                 AND revocation_pending_at IS NULL
             )
             AND ${identityGate} AND ${deletionGate}`,
        ).bind(
          input.sessionExpiresAt,
          input.identityTokenExpiresAt,
          input.sessionHash,
          input.ownerId,
          input.appleSubjectHash,
          input.lastValidatedAt,
          input.sessionHash,
          input.ownerId,
          input.principalId,
          input.appleSubjectHash,
          input.encryptedCredentials,
          ...gateBindings,
        ),
        database.prepare(
          `UPDATE apple_native_grants
           SET revocation_pending_at=?
           WHERE session_hash=? AND owner_id=? AND principal_id=? AND apple_subject_hash=?
             AND encrypted_credentials=? AND last_validated_at=?
             AND revocation_pending_at IS NULL AND NOT (${completedSessionGate})`,
        ).bind(
          input.lastValidatedAt,
          input.sessionHash,
          input.ownerId,
          input.principalId,
          input.appleSubjectHash,
          input.expectedEncryptedCredentials,
          input.expectedLastValidatedAt,
          ...completedSessionBindings,
        ),
        database.prepare(
          `UPDATE apple_native_grants
           SET revocation_pending_at=?
           WHERE session_hash=? AND owner_id=? AND principal_id=? AND apple_subject_hash=?
             AND encrypted_credentials=? AND last_validated_at=? AND expires_at=?
             AND revocation_pending_at IS NULL AND NOT (${completedSessionGate})`,
        ).bind(
          input.lastValidatedAt,
          input.sessionHash,
          input.ownerId,
          input.principalId,
          input.appleSubjectHash,
          input.encryptedCredentials,
          input.lastValidatedAt,
          input.grantExpiresAt,
          ...completedSessionBindings,
        ),
      ]);
      return (results[0].meta.changes ?? 0) === 1 && (results[1].meta.changes ?? 0) === 1;
    },

    async beginSessionRevocation(sessionHash, now) {
      const session = await database.prepare(
        `UPDATE apple_native_sessions SET revoked_at=COALESCE(revoked_at,?)
         WHERE session_hash=? RETURNING session_hash`,
      ).bind(now, sessionHash).first();
      if (session === null) return {found: false, grant: null};
      const grant = await database.prepare(
        `SELECT ${grantColumns} FROM apple_native_grants WHERE session_hash=?`,
      ).bind(sessionHash).first();
      return {found: true, grant: grant === null ? null : parseGrant(grant)};
    },

    async revokeSession(sessionHash, now) {
      const result = await database.prepare(
        `UPDATE apple_native_sessions SET revoked_at=COALESCE(revoked_at,?)
         WHERE session_hash=? RETURNING session_hash`,
      ).bind(now, sessionHash).first();
      return result !== null;
    },

    async markGrantRevocationPending(grantHash, now) {
      await database.prepare(
        `UPDATE apple_native_grants
         SET revocation_pending_at=? WHERE grant_hash=?`,
      ).bind(now, grantHash).run();
    },

    async deleteGrant(grantHash) {
      const result = await database.prepare(
        'DELETE FROM apple_native_grants WHERE grant_hash=?',
      ).bind(grantHash).run();
      return (result.meta.changes ?? 0) === 1;
    },

    async hasExpiredSessionGrant(eligibilityCutoff, claimTime) {
      const retryBefore = claimTime - APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS;
      const row = await database.prepare(
        `SELECT 1 AS present
         FROM apple_native_grants AS grant
         LEFT JOIN apple_native_sessions AS session ON session.session_hash=grant.session_hash
         WHERE (grant.expires_at<=? OR session.session_hash IS NULL OR session.expires_at<=?
             OR session.revoked_at IS NOT NULL)
           AND (grant.revocation_pending_at IS NULL OR grant.revocation_pending_at<=?)
         LIMIT 1`,
      ).bind(eligibilityCutoff, eligibilityCutoff, retryBefore).first();
      return row !== null;
    },

    async claimExpiredSessionGrants(eligibilityCutoff, claimedAt, limit) {
      const retryBefore = claimedAt - APPLE_NATIVE_GRANT_REVOCATION_CLAIM_SECONDS;
      const eligibleGrantSelection = `
        SELECT grant.grant_hash
        FROM apple_native_grants AS grant
        LEFT JOIN apple_native_sessions AS session ON session.session_hash=grant.session_hash
        WHERE (grant.expires_at<=? OR session.session_hash IS NULL OR session.expires_at<=?
            OR session.revoked_at IS NOT NULL)
          AND (grant.revocation_pending_at IS NULL OR grant.revocation_pending_at<=?)
        ORDER BY COALESCE(session.expires_at,grant.expires_at),grant.grant_hash LIMIT ?`;
      const eligibilityBindings = [eligibilityCutoff, eligibilityCutoff, retryBefore, limit];
      const results = await database.batch([
        database.prepare(
          `UPDATE apple_native_sessions SET revoked_at=COALESCE(revoked_at,?)
           WHERE session_hash IN (
             SELECT selected_grant.session_hash FROM apple_native_grants AS selected_grant
             WHERE selected_grant.grant_hash IN (${eligibleGrantSelection})
           )`,
        ).bind(claimedAt, ...eligibilityBindings),
        database.prepare(
          `UPDATE apple_native_grants SET revocation_pending_at=?
           WHERE grant_hash IN (${eligibleGrantSelection})
           RETURNING ${grantColumns}`,
        ).bind(claimedAt, ...eligibilityBindings),
      ]);
      return results[1].results.map(parseGrant);
    },

    async deleteClaimedExpiredGrant(grantHash, claimedAt) {
      const deleted = await database.prepare(
        `DELETE FROM apple_native_grants
         WHERE grant_hash=? AND revocation_pending_at=?
           AND NOT EXISTS(
             SELECT 1 FROM apple_native_sessions AS session
             WHERE session.session_hash=apple_native_grants.session_hash
               AND session.revoked_at IS NULL
           )
         RETURNING grant_hash`,
      ).bind(grantHash, claimedAt).first();
      return deleted !== null;
    },

    async cleanupSessions(now, limit) {
      const results = await database.batch([
        database.prepare(
          `DELETE FROM apple_native_sessions
           WHERE identity_token_hash IN (
             SELECT identity_token_hash
             FROM apple_native_sessions
             WHERE expires_at<=? AND identity_token_expires_at<=?
               AND NOT EXISTS(
                 SELECT 1 FROM apple_native_grants
                 WHERE apple_native_grants.session_hash=apple_native_sessions.session_hash
               )
             ORDER BY expires_at,identity_token_hash
             LIMIT ?
           )`,
        ).bind(now, now - 60, limit),
        database.prepare(
          `DELETE FROM apple_native_authorization_code_claims
           WHERE authorization_code_hash IN (
             SELECT authorization_code_hash
             FROM apple_native_authorization_code_claims
             WHERE expires_at<=?
             ORDER BY expires_at,authorization_code_hash
             LIMIT ?
           )`,
        ).bind(now, limit),
      ]);
      return results[0].meta.changes ?? 0;
    },

    async claimAuthorizationExchangeLease(input) {
      try {
        await authorizationLeases.claim({
          authorization: {
            userId: input.ownerId,
            appleSubjectHash: input.appleSubjectHash,
            authorizationStartedAt: input.authorizationStartedAt,
          },
          operationKind: 'apple-auth',
          resourceId: input.appleSubjectHash,
          leaseToken: input.leaseToken,
          now: input.now,
        });
      } catch (error) {
        throw asAppleAuthError(error);
      }
    },

    async markAuthorizationExchangePossible(leaseToken, now) {
      try {
        await authorizationLeases.markPossibleCredential(leaseToken, now);
      } catch (error) {
        throw asAppleAuthError(error);
      }
    },

    async completeAuthorizationExchangeLease(input) {
      try {
        await authorizationLeases.complete(input.leaseToken, input.now);
        await authorizationLeases.assertOwnerOperationAllowed({
          userId: input.ownerId,
          appleSubjectHash: input.appleSubjectHash,
          authorizationStartedAt: input.authorizationStartedAt,
        }, input.now);
      } catch (error) {
        throw asAppleAuthError(error);
      }
    },

    async releaseAuthorizationExchangeLease(leaseToken, now) {
      try {
        await authorizationLeases.release(leaseToken, true, now);
      } catch (error) {
        throw asAppleAuthError(error);
      }
    },
  };
}

function asAppleAuthError(error: unknown): unknown {
  return error instanceof AppleOwnerExternalOperationError
    ? new AppleAuthError(error.status, error.code, error.message)
    : error;
}

function deletionInProgress(): AppleAuthError {
  return new AppleAuthError(
    409,
    'APPLE_ACCOUNT_DELETION_IN_PROGRESS',
    'This Apple identity is being removed and cannot create another session.',
  );
}

function transferConflict(): AppleAuthError {
  return new AppleAuthError(
    409,
    'APPLE_IDENTITY_LINK_CONFLICT',
    'The Apple transfer identifiers resolve to different Local Sandbox accounts.',
  );
}
