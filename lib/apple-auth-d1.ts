import { z } from 'zod';
import {
  AppleAuthError,
  type AppleAuthFlow,
  type AppleAuthRepository,
  type AppleAuthSessionRecord,
} from './apple-auth.ts';
import { purgeExpiredAppleAuthRecords } from './apple-auth-retention-d1.ts';
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

const flowRowBase = {
  schema_version: z.literal(2),
  state_hash: z.string().length(43),
  purpose: z.enum(['authenticate', 'link']),
  nonce_hash: z.string().length(43),
  browser_binding_hash: z.string().length(43),
  owner_binding: z.string().length(43),
  return_to: z.string().min(1).max(2_000),
  created_at: z.number().int().positive(),
  expires_at: z.number().int().positive(),
};

const flowRowSchema = z.discriminatedUnion('purpose', [
  z.object({...flowRowBase, purpose: z.literal('authenticate'), owner_id: z.null()}).strict(),
  z.object({...flowRowBase, purpose: z.literal('link'), owner_id: z.string().min(1).max(1_000)}).strict(),
]);

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

function parseFlow(row: unknown): AppleAuthFlow {
  const value = flowRowSchema.parse(row);
  const base = {
    schemaVersion: value.schema_version,
    stateHash: value.state_hash,
    nonceHash: value.nonce_hash,
    browserBindingHash: value.browser_binding_hash,
    ownerBinding: value.owner_binding,
    returnTo: value.return_to,
    createdAt: value.created_at,
    expiresAt: value.expires_at,
  };
  return value.purpose === 'link'
    ? {...base, purpose: 'link', ownerId: value.owner_id}
    : {...base, purpose: 'authenticate', ownerId: null};
}

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

export function createD1AppleAuthRepository(database: D1Database): AppleAuthRepository {
  const authorizationLeases = createD1AppleOwnerExternalOperationLeaseRepository(database);
  return {
    async createFlow(flow) {
      await purgeExpiredAppleAuthRecords(database, flow.createdAt);
      const created = await database.prepare(
        `INSERT INTO apple_auth_flows(
          schema_version,state_hash,purpose,owner_id,nonce_hash,browser_binding_hash,
          owner_binding,return_to,created_at,expires_at,consumed_at
        ) SELECT ?,?,?,?,?,?,?,?,?,?,NULL
          WHERE EXISTS(
            SELECT 1 FROM apple_auth_admission_cutover AS admission_cutover
            WHERE admission_cutover.singleton=1 AND ?>admission_cutover.cutover_at
          )`,
      ).bind(
        flow.schemaVersion,
        flow.stateHash,
        flow.purpose,
        flow.ownerId,
        flow.nonceHash,
        flow.browserBindingHash,
        flow.ownerBinding,
        flow.returnTo,
        flow.createdAt,
        flow.expiresAt,
        flow.createdAt,
      ).run();
      if ((created.meta.changes ?? 0) !== 1) {
        throw new AppleAuthError(
          503,
          'APPLE_AUTH_ROLLOUT_PENDING',
          'Sign in with Apple is temporarily unavailable while the authorization upgrade completes.',
        );
      }
    },

    async consumeFlow(stateHash, now) {
      const row = await database.prepare(
        `DELETE FROM apple_auth_flows
         WHERE state_hash=? AND consumed_at IS NULL AND expires_at>?
           AND EXISTS(
             SELECT 1 FROM apple_auth_admission_cutover AS admission_cutover
             WHERE admission_cutover.singleton=1
               AND apple_auth_flows.created_at>admission_cutover.cutover_at
           )
         RETURNING schema_version,state_hash,purpose,owner_id,nonce_hash,browser_binding_hash,
                   owner_binding,return_to,created_at,expires_at`,
      ).bind(stateHash, now).first();
      return row ? parseFlow(row) : null;
    },

    async createSession(session, authorizationStartedAt = session.createdAt) {
      await purgeExpiredAppleAuthRecords(database, session.createdAt);
      const identity = await readD1AppleLinkedIdentity(database, session.appleSubjectHash);
      if (identity === null || identity.ownerId !== session.ownerId) {
        throw new AppleAuthError(
          409,
          'APPLE_IDENTITY_LINK_CONFLICT',
          'The Apple account mapping changed during sign-in.',
        );
      }
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
      const inserted = await database.prepare(
        `INSERT INTO apple_auth_sessions(
          schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
          encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
        ) SELECT ?,?,?,?,?,?,?,?,?,NULL
        WHERE ${deletionAdmission.sql} AND ${currentIdentityGate}
        RETURNING session_hash`,
      ).bind(
        session.schemaVersion,
        session.sessionHash,
        session.ownerId,
        session.ownerBinding,
        session.appleSubjectHash,
        session.encryptedCredentials,
        session.createdAt,
        session.expiresAt,
        session.lastValidatedAt,
        ...deletionAdmission.bindings,
        session.appleSubjectHash,
        session.ownerId,
        identity.principalId,
      ).first();
      if (inserted === null) {
        const currentIdentity = await readD1AppleLinkedIdentity(
          database,
          session.appleSubjectHash,
        );
        if (
          currentIdentity === null
          || currentIdentity.ownerId !== session.ownerId
          || currentIdentity.principalId !== identity.principalId
        ) throw new AppleAuthError(
          409,
          'APPLE_IDENTITY_LINK_CONFLICT',
          'The Apple account mapping changed during sign-in.',
        );
        if (await hasD1AppleIdentityDeletion(database, {
          ownerId: session.ownerId,
          principalIds: [identity.principalId],
          appleSubjectHashes: [session.appleSubjectHash],
          now: session.createdAt,
          authorizationStartedAt,
        })) throw deletionInProgress();
      }
    },

    async readSession(sessionHash, now) {
      await purgeExpiredAppleAuthRecords(database, now);
      const row = await database.prepare(
        `SELECT schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
                encrypted_credentials,created_at,expires_at,last_validated_at
         FROM apple_auth_sessions
         WHERE session_hash=? AND owner_id IS NOT NULL AND revoked_at IS NULL AND expires_at>?
           AND EXISTS(
             SELECT 1 FROM apple_auth_admission_cutover AS admission_cutover
             WHERE admission_cutover.singleton=1
               AND apple_auth_sessions.created_at>admission_cutover.cutover_at
           )
           AND EXISTS(
             SELECT 1 FROM apple_identity_links AS identity
             WHERE identity.apple_subject_hash=apple_auth_sessions.apple_subject_hash
               AND identity.owner_id=apple_auth_sessions.owner_id
           )
           AND NOT EXISTS(
             SELECT 1 FROM apple_account_deletions AS deletion
             WHERE deletion.expires_at>?
               AND deletion.owner_id=apple_auth_sessions.owner_id
               AND (deletion.delete_owner_data=1 OR COALESCE(
                 deletion.apple_principal_id,deletion.apple_subject_hash
               )=(
                 SELECT identity.principal_id FROM apple_identity_links AS identity
                 WHERE identity.apple_subject_hash=apple_auth_sessions.apple_subject_hash
                   AND identity.owner_id=apple_auth_sessions.owner_id
               ))
               AND (deletion.provider_credentials IS NULL OR deletion.origin_connections IS NULL
                 OR deletion.completion_fence_token IS NULL OR deletion.completed_at IS NULL
                 OR deletion.completed_at>=apple_auth_sessions.created_at)
           )`,
      ).bind(sessionHash, now, now).first();
      return row ? parseSession(row) : null;
    },

    async readLatestSessionForSubject(appleSubjectHash, now) {
      await purgeExpiredAppleAuthRecords(database, now);
      const row = await database.prepare(
        `SELECT schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
                encrypted_credentials,created_at,expires_at,last_validated_at
         FROM apple_auth_sessions
         WHERE apple_subject_hash=? AND owner_id IS NOT NULL AND revoked_at IS NULL
           AND expires_at>?
           AND EXISTS(
             SELECT 1 FROM apple_auth_admission_cutover AS admission_cutover
             WHERE admission_cutover.singleton=1
               AND apple_auth_sessions.created_at>admission_cutover.cutover_at
           )
           AND EXISTS(
             SELECT 1 FROM apple_identity_links AS identity
             WHERE identity.apple_subject_hash=apple_auth_sessions.apple_subject_hash
               AND identity.owner_id=apple_auth_sessions.owner_id
           )
         ORDER BY created_at DESC LIMIT 1`,
      ).bind(appleSubjectHash, now).first();
      return row ? parseSession(row) : null;
    },

    async updateSession(update) {
      const {expected, next, now} = update;
      if (
        next.sessionHash !== expected.sessionHash
        || next.ownerId !== expected.ownerId
        || next.ownerBinding !== expected.ownerBinding
        || next.appleSubjectHash !== expected.appleSubjectHash
        || next.createdAt !== expected.createdAt
        || next.expiresAt !== expected.expiresAt
      ) throw new TypeError('Apple session updates cannot change immutable bindings.');
      const result = await database.prepare(
       `UPDATE apple_auth_sessions
         SET schema_version=?,encrypted_credentials=?,last_validated_at=?
         WHERE session_hash=? AND schema_version=? AND owner_id=? AND owner_binding=?
           AND apple_subject_hash=? AND encrypted_credentials=?
           AND created_at=? AND expires_at=? AND last_validated_at=?
           AND revoked_at IS NULL AND expires_at>?
           AND EXISTS(
             SELECT 1 FROM apple_auth_admission_cutover AS admission_cutover
             WHERE admission_cutover.singleton=1
               AND apple_auth_sessions.created_at>admission_cutover.cutover_at
           )
           AND EXISTS(
             SELECT 1 FROM apple_identity_links AS identity
             WHERE identity.apple_subject_hash=apple_auth_sessions.apple_subject_hash
               AND identity.owner_id=apple_auth_sessions.owner_id
           )
           AND NOT EXISTS(
             SELECT 1 FROM apple_account_deletions AS deletion
             WHERE deletion.expires_at>?
               AND deletion.owner_id=apple_auth_sessions.owner_id
               AND (deletion.delete_owner_data=1 OR COALESCE(
                 deletion.apple_principal_id,deletion.apple_subject_hash
               )=(
                 SELECT identity.principal_id FROM apple_identity_links AS identity
                 WHERE identity.apple_subject_hash=apple_auth_sessions.apple_subject_hash
                   AND identity.owner_id=apple_auth_sessions.owner_id
               ))
               AND (deletion.provider_credentials IS NULL OR deletion.origin_connections IS NULL
                 OR deletion.completion_fence_token IS NULL OR deletion.completed_at IS NULL
                 OR deletion.completed_at>=apple_auth_sessions.created_at)
           )`,
      ).bind(
        next.schemaVersion,
        next.encryptedCredentials,
        next.lastValidatedAt,
        expected.sessionHash,
        expected.schemaVersion,
        expected.ownerId,
        expected.ownerBinding,
        expected.appleSubjectHash,
        expected.encryptedCredentials,
        expected.createdAt,
        expected.expiresAt,
        expected.lastValidatedAt,
        now,
        now,
      ).run();
      if ((result.meta.changes ?? 0) !== 1) throw new Error('APPLE_SESSION_UPDATE_CONFLICT');
    },

    async revokeSession(sessionHash) {
      const result = await database.prepare(
        `DELETE FROM apple_auth_sessions
         WHERE session_hash=? AND revoked_at IS NULL`,
      ).bind(sessionHash).run();
      return (result.meta.changes ?? 0) === 1;
    },

    async linkAppleIdentity(link, authorizationStartedAt = link.createdAt) {
      const result = await bindD1AppleIdentityGroup({
        database,
        appleSubjectHashes: [link.appleSubjectHash],
        proposedOwnerId: link.ownerId,
        requiredOwnerId: link.ownerId,
        now: link.updatedAt,
        authorizationStartedAt,
      });
      return result.kind === 'owner-conflict' ? 'owner-conflict' : 'linked';
    },

    async resolveAppleOwner(link, authorizationStartedAt = link.createdAt) {
      const result = await bindD1AppleIdentityGroup({
        database,
        appleSubjectHashes: [link.appleSubjectHash],
        proposedOwnerId: link.ownerId,
        now: link.updatedAt,
        authorizationStartedAt,
      });
      if (result.kind === 'owner-conflict') throw identityConflict();
      return {ownerId: result.ownerId, created: result.created};
    },

    async resolveAppleIdentityGroup(input, authorizationStartedAt = input.createdAt) {
      return bindD1AppleIdentityGroup({
        database,
        appleSubjectHashes: input.appleSubjectHashes,
        proposedOwnerId: input.proposedOwnerId,
        requiredOwnerId: input.requiredOwnerId,
        now: input.updatedAt,
        authorizationStartedAt,
      });
    },

    async readLinkedIdentity(appleSubjectHash) {
      const identity = await readD1AppleLinkedIdentity(database, appleSubjectHash);
      return identity === null ? null : {
        ownerId: identity.ownerId,
        principalId: identity.principalId,
        principalCreatedAt: identity.principalCreatedAt,
      };
    },

    async readLinkedOwner(appleSubjectHash) {
      return (await readD1AppleLinkedIdentity(database, appleSubjectHash))?.ownerId ?? null;
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

function identityConflict(): AppleAuthError {
  return new AppleAuthError(
    409,
    'APPLE_IDENTITY_LINK_CONFLICT',
    'The Apple identity group could not be resolved safely.',
  );
}
