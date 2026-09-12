import { z } from 'zod';
import {
  APPLE_OWNER_OPERATION_ALLOWED_SQL,
  appleOwnerOperationGateBindings,
  isAppleOwnerOperationAllowed,
  type AppleOwnerOperationAuthorization,
} from './apple-auth-owner-d1.ts';

export const APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS = 5 * 60;

const opaqueHashSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const operationKindSchema = z.enum(['origin', 'github', 'apple-auth', 'origin-install']);
const resourceIdSchema = z.string().min(1).max(200);
const leaseRowSchema = z.object({
  lease_token: opaqueHashSchema,
  owner_id: z.string().min(1).max(1_000),
  operation_kind: operationKindSchema,
  resource_id: resourceIdSchema,
  apple_subject_hash: opaqueHashSchema.nullable(),
  apple_principal_id: opaqueHashSchema.nullable(),
  claimed_at: z.number().int().nonnegative(),
  expires_at: z.number().int().positive(),
}).strict().refine(
  value => (value.apple_subject_hash === null) === (value.apple_principal_id === null),
  {message: 'External operation lease identity is inconsistent.'},
);

export type AppleOwnerExternalOperationKind = z.infer<typeof operationKindSchema>;

export type AppleOwnerExternalOperationLeaseRepository = {
  claim(input: {
    authorization: AppleOwnerOperationAuthorization;
    operationKind: AppleOwnerExternalOperationKind;
    resourceId: string;
    leaseToken: string;
    now: number;
  }): Promise<{expiresAt: number}>;
  complete(leaseToken: string, now: number): Promise<void>;
  markPossibleCredential(leaseToken: string, now: number): Promise<void>;
  release(
    leaseToken: string,
    possibleCredentialResolved?: boolean,
    now?: number,
  ): Promise<void>;
  assertOwnerOperationAllowed(
    authorization: AppleOwnerOperationAuthorization,
    now: number,
  ): Promise<void>;
};

export class AppleOwnerExternalOperationError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(
    status: number,
    code: string,
    message: string,
  ) {
    super(message);
    this.name = 'AppleOwnerExternalOperationError';
    this.status = status;
    this.code = code;
  }
}

export type ApplePossibleCredentialReview = {
  acknowledgementId: string;
  markedAt: number;
};

export async function readD1ApplePossibleCredentialReview(
  database: D1Database,
  authorization: AppleOwnerOperationAuthorization,
  now: number,
): Promise<ApplePossibleCredentialReview | null> {
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new TypeError('Possible Apple credential review time is invalid.');
  }
  if (authorization.appleSubjectHash === null) {
    if (!await isAppleOwnerOperationAllowed(database, authorization, now)) {
      throw externalOperationError(409, 'APPLE_ACCOUNT_DELETION_IN_PROGRESS', 'This Apple access is being deleted.');
    }
    return null;
  }
  const stored = await database.prepare(
    `SELECT review_token,marked_at FROM apple_auth_possible_credentials
     WHERE owner_id=? AND credential_state='possible'
       AND apple_principal_id=(
         SELECT identity.principal_id FROM apple_identity_links AS identity
         WHERE identity.apple_subject_hash=? AND identity.owner_id=?
       )
       AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`,
  ).bind(
    authorization.userId,
    authorization.appleSubjectHash,
    authorization.userId,
    ...appleOwnerOperationGateBindings(authorization, now),
  ).first();
  if (stored === null) {
    if (!await isAppleOwnerOperationAllowed(database, authorization, now)) {
      throw externalOperationError(409, 'APPLE_ACCOUNT_DELETION_IN_PROGRESS', 'This Apple access is being deleted.');
    }
    return null;
  }
  const row = z.object({
    review_token: opaqueHashSchema,
    marked_at: z.number().int().nonnegative(),
  }).strict().safeParse(stored);
  if (row.success) {
    return {acknowledgementId: row.data.review_token, markedAt: row.data.marked_at};
  }
  throw externalOperationError(
    503,
    'APPLE_AUTH_CREDENTIAL_REVIEW_STATE_INVALID',
    'Stored Apple credential review state is invalid and requires operator review.',
  );
}

export async function acknowledgeD1ApplePossibleCredentialReview(
  database: D1Database,
  authorization: AppleOwnerOperationAuthorization,
  acknowledgementId: string,
  now: number,
): Promise<void> {
  const expectedReviewToken = opaqueHashSchema.parse(acknowledgementId);
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new TypeError('Possible Apple credential acknowledgement time is invalid.');
  }
  if (authorization.appleSubjectHash === null) {
    throw externalOperationError(401, 'APPLE_SESSION_REQUIRED', 'An Apple session is required to review possible credential cleanup.');
  }
  const deleted = await database.prepare(
    `DELETE FROM apple_auth_possible_credentials
     WHERE owner_id=? AND credential_state='possible' AND review_token=?
       AND apple_principal_id=(
         SELECT identity.principal_id FROM apple_identity_links AS identity
         WHERE identity.apple_subject_hash=? AND identity.owner_id=?
       )
       AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
       AND NOT EXISTS(
         SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
         WHERE active_lease.owner_id=apple_auth_possible_credentials.owner_id
           AND active_lease.apple_principal_id=apple_auth_possible_credentials.apple_principal_id
           AND active_lease.operation_kind='apple-auth' AND active_lease.expires_at>?
       )
     RETURNING review_token`,
  ).bind(
    authorization.userId,
    expectedReviewToken,
    authorization.appleSubjectHash,
    authorization.userId,
    ...appleOwnerOperationGateBindings(authorization, now),
    now,
  ).first();
  if (deleted !== null) return;
  if (!await isAppleOwnerOperationAllowed(database, authorization, now)) {
    throw externalOperationError(409, 'APPLE_ACCOUNT_DELETION_IN_PROGRESS', 'This Apple access is being deleted.');
  }
  const principalId = await database.prepare(
    `SELECT principal_id FROM apple_identity_links
     WHERE apple_subject_hash=? AND owner_id=?`,
  ).bind(authorization.appleSubjectHash, authorization.userId).first<string>('principal_id');
  if (principalId === null) {
    throw externalOperationError(409, 'APPLE_IDENTITY_LINK_MISSING', 'This Apple identity is no longer linked to the signed-in account.');
  }
  const storedCurrent = await database.prepare(
    `SELECT review_token,marked_at FROM apple_auth_possible_credentials
     WHERE owner_id=? AND apple_principal_id=? AND credential_state='possible'`,
  ).bind(authorization.userId, principalId).first();
  if (storedCurrent === null) return;
  const current = z.object({
    review_token: opaqueHashSchema,
    marked_at: z.number().int().nonnegative(),
  }).strict().safeParse(storedCurrent);
  if (!current.success) {
    throw externalOperationError(
      503,
      'APPLE_AUTH_CREDENTIAL_REVIEW_STATE_INVALID',
      'Stored Apple credential review state is invalid and requires operator review.',
    );
  }
  if (current.data.review_token !== expectedReviewToken) {
    throw externalOperationError(
      409,
      'APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED',
      'Apple credential cleanup state changed. Review the current warning before acknowledging it.',
    );
  }
  if (await database.prepare(
    `SELECT 1 FROM apple_owner_external_operation_leases
     WHERE owner_id=? AND apple_principal_id=? AND operation_kind='apple-auth' AND expires_at>?`,
  ).bind(authorization.userId, principalId, now).first() !== null) {
    throw externalOperationError(
      409,
      'APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS',
      'Finish the active Apple sign-in before acknowledging manual credential review.',
    );
  }
  throw externalOperationError(
    503,
    'APPLE_AUTH_CREDENTIAL_REVIEW_UNAVAILABLE',
    'Apple credential cleanup state could not be acknowledged safely.',
  );
}

export function createD1AppleOwnerExternalOperationLeaseRepository(
  database: D1Database,
): AppleOwnerExternalOperationLeaseRepository {
  const assertOwnerAllowed = async (
    authorization: AppleOwnerOperationAuthorization,
    now: number,
  ) => {
    if (!await isAppleOwnerOperationAllowed(database, authorization, now)) {
      throw externalOperationError(
        409,
        'APPLE_ACCOUNT_DELETION_IN_PROGRESS',
        'This Apple access is being deleted.',
      );
    }
  };

  return {
    async claim(input) {
      const leaseToken = opaqueHashSchema.parse(input.leaseToken);
      const operationKind = operationKindSchema.parse(input.operationKind);
      const resourceId = resourceIdSchema.parse(input.resourceId);
      const expiresAt = input.now + APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS;
      if (
        !Number.isSafeInteger(input.now) || input.now < 0
        || !Number.isSafeInteger(expiresAt)
      ) {
        throw new TypeError('External operation lease time is invalid.');
      }
      const authorizationGate = appleOwnerOperationGateBindings(
        input.authorization,
        input.now,
      );
      const resourceGate = operationKind === 'origin'
        ? `EXISTS(
            SELECT 1 FROM origin_installations
            WHERE owner_id=? AND installation_id=?
          )`
        : operationKind === 'origin-install'
          ? `EXISTS(
              SELECT 1 FROM origin_auth_flows
              WHERE owner_id=? AND state_hash=?
                AND consumed_at IS NULL AND expires_at>?
            )`
          : '1=1';
      const resourceGateBindings = operationKind === 'origin'
        ? [input.authorization.userId, resourceId]
        : operationKind === 'origin-install'
          ? [input.authorization.userId, resourceId, input.now]
          : [];
      const results = await database.batch([
        database.prepare(
          `DELETE FROM apple_owner_external_operation_leases
           WHERE lease_token IN (
             SELECT lease_token FROM apple_owner_external_operation_leases
             WHERE expires_at<=?
             ORDER BY expires_at,lease_token LIMIT 100
           )`,
        ).bind(input.now),
        database.prepare(
          `INSERT INTO apple_auth_possible_credentials(
             owner_id,apple_principal_id,apple_subject_hash,attempt_token,
             review_token,credential_state,marked_at
           )
           SELECT ?,identity.principal_id,?,?,?,'prepared',?
           FROM apple_identity_links AS identity
           WHERE ?='apple-auth' AND ? IS NOT NULL
             AND identity.apple_subject_hash=? AND identity.owner_id=?
             AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
           ON CONFLICT(owner_id,apple_principal_id) DO UPDATE SET
             apple_subject_hash=CASE
               WHEN apple_auth_possible_credentials.credential_state='prepared'
               THEN excluded.apple_subject_hash
               ELSE apple_auth_possible_credentials.apple_subject_hash
             END,
             attempt_token=CASE
               WHEN apple_auth_possible_credentials.credential_state='prepared'
               THEN excluded.attempt_token
               ELSE apple_auth_possible_credentials.attempt_token
             END,
             review_token=excluded.review_token,
             credential_state=apple_auth_possible_credentials.credential_state,
             marked_at=CASE
               WHEN apple_auth_possible_credentials.credential_state='prepared'
               THEN excluded.marked_at
               ELSE apple_auth_possible_credentials.marked_at
             END
           WHERE NOT EXISTS(
               SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
               WHERE active_lease.operation_kind='apple-auth'
                 AND active_lease.owner_id=excluded.owner_id
                 AND active_lease.apple_principal_id=excluded.apple_principal_id
                 AND active_lease.expires_at>?
             )`,
        ).bind(
          input.authorization.userId,
          input.authorization.appleSubjectHash,
          leaseToken,
          leaseToken,
          input.now,
          operationKind,
          input.authorization.appleSubjectHash,
          input.authorization.appleSubjectHash,
          input.authorization.userId,
          ...authorizationGate,
          input.now,
        ),
        database.prepare(
          `INSERT INTO apple_owner_external_operation_leases(
             lease_token,owner_id,operation_kind,resource_id,
             apple_subject_hash,apple_principal_id,claimed_at,expires_at
           )
           SELECT ?,?,?,?,?,CASE WHEN ? IS NULL THEN NULL ELSE (
             SELECT identity.principal_id FROM apple_identity_links AS identity
             WHERE identity.apple_subject_hash=? AND identity.owner_id=?
           ) END,?,?
           WHERE ${resourceGate}
             AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
             AND (? IS NULL OR EXISTS(
               SELECT 1 FROM apple_identity_links AS identity
               WHERE identity.apple_subject_hash=? AND identity.owner_id=?
             ))
             AND (?<>'origin' OR NOT EXISTS(
               SELECT 1 FROM apple_owner_external_operation_leases AS active_install_flow
               WHERE active_install_flow.owner_id=?
                 AND active_install_flow.operation_kind='origin-install'
                 AND active_install_flow.expires_at>?
             ))
             AND (?<>'origin-install' OR NOT EXISTS(
               SELECT 1 FROM apple_owner_external_operation_leases AS active_origin_operation
               WHERE active_origin_operation.owner_id=?
                 AND active_origin_operation.operation_kind='origin'
                 AND active_origin_operation.expires_at>?
             ))
             AND (?<>'apple-auth' OR EXISTS(
               SELECT 1 FROM apple_auth_possible_credentials AS possible_credential
               WHERE possible_credential.owner_id=?
                 AND possible_credential.apple_principal_id=(
                   SELECT identity.principal_id FROM apple_identity_links AS identity
                   WHERE identity.apple_subject_hash=? AND identity.owner_id=?
                 )
                 AND (
                   (possible_credential.credential_state='possible'
                     AND possible_credential.review_token=?)
                   OR (possible_credential.credential_state='prepared'
                     AND possible_credential.attempt_token=?
                     AND possible_credential.review_token=?)
                 )
             ))
             AND (?<>'origin-install' OR EXISTS(
               SELECT 1 FROM origin_possible_installations AS possible_installation
                 WHERE possible_installation.owner_id=?
                   AND possible_installation.scope_id=CASE WHEN ? IS NULL THEN 'host' ELSE (
                     SELECT identity.principal_id FROM apple_identity_links AS identity
                     WHERE identity.apple_subject_hash=? AND identity.owner_id=?
                   ) END
                   AND possible_installation.flow_token=?
             ))
           ON CONFLICT DO NOTHING
           RETURNING lease_token,owner_id,operation_kind,resource_id,
                     apple_subject_hash,apple_principal_id,claimed_at,expires_at`,
        ).bind(
          leaseToken,
          input.authorization.userId,
          operationKind,
          resourceId,
          input.authorization.appleSubjectHash,
          input.authorization.appleSubjectHash,
          input.authorization.appleSubjectHash,
          input.authorization.userId,
          input.now,
          expiresAt,
          ...resourceGateBindings,
          ...authorizationGate,
          input.authorization.appleSubjectHash,
          input.authorization.appleSubjectHash,
          input.authorization.userId,
          operationKind,
          input.authorization.userId,
          input.now,
          operationKind,
          input.authorization.userId,
          input.now,
          operationKind,
          input.authorization.userId,
          input.authorization.appleSubjectHash,
          input.authorization.userId,
          leaseToken,
          leaseToken,
          leaseToken,
          operationKind,
          input.authorization.userId,
          input.authorization.appleSubjectHash,
          input.authorization.appleSubjectHash,
          input.authorization.userId,
          leaseToken,
        ),
      ]);
      let currentPrincipalId: string | null = null;
      if (input.authorization.appleSubjectHash !== null) {
        currentPrincipalId = await database.prepare(
          `SELECT principal_id FROM apple_identity_links
           WHERE apple_subject_hash=? AND owner_id=?`,
        ).bind(
          input.authorization.appleSubjectHash,
          input.authorization.userId,
        ).first<string>('principal_id');
      }
      const credentialCoverageRecorded = operationKind !== 'apple-auth' || (
        currentPrincipalId !== null
        && await database.prepare(
          `SELECT 1 FROM apple_auth_possible_credentials
           WHERE owner_id=? AND apple_principal_id=?
             AND (credential_state='possible'
               OR credential_state='prepared')
             AND review_token=?
             AND (credential_state='possible' OR attempt_token=?)`,
        ).bind(
          input.authorization.userId,
          currentPrincipalId,
          leaseToken,
          leaseToken,
        ).first() !== null
      );
      const installationCoverageRecorded = operationKind !== 'origin-install'
        || await database.prepare(
          `SELECT 1 FROM origin_possible_installations
           WHERE owner_id=?
             AND scope_id=CASE WHEN ? IS NULL THEN 'host' ELSE ? END
             AND flow_token=?`,
        ).bind(
          input.authorization.userId,
          input.authorization.appleSubjectHash,
          currentPrincipalId,
          leaseToken,
        ).first() !== null;
      const inserted = leaseRowSchema.safeParse(results[2]?.results[0]);
      if (inserted.success) {
        if (
          inserted.data.owner_id !== input.authorization.userId
          || inserted.data.operation_kind !== operationKind
          || inserted.data.resource_id !== resourceId
          || inserted.data.apple_subject_hash !== input.authorization.appleSubjectHash
          || inserted.data.apple_principal_id !== currentPrincipalId
          || inserted.data.claimed_at !== input.now
          || inserted.data.expires_at !== expiresAt
          || !credentialCoverageRecorded
          || !installationCoverageRecorded
        ) {
          throw externalOperationError(
            503,
            'APPLE_OWNER_EXTERNAL_OPERATION_LEASE_INVALID',
            'The server stored invalid external-operation authority.',
          );
        }
        return {expiresAt: inserted.data.expires_at};
      }

      await assertOwnerAllowed(input.authorization, input.now);
      if (input.authorization.appleSubjectHash !== null) {
        if (currentPrincipalId === null) {
          throw externalOperationError(
            409,
            'APPLE_IDENTITY_LINK_MISSING',
            'This Apple identity is no longer linked to the signed-in account.',
          );
        }
      }
      if (operationKind === 'origin') {
        const resource = await database.prepare(
          `SELECT 1 AS present FROM origin_installations
           WHERE owner_id=? AND installation_id=?`,
        ).bind(input.authorization.userId, resourceId).first();
        if (resource === null) {
          throw externalOperationError(
            404,
            'APPLE_OWNER_EXTERNAL_OPERATION_RESOURCE_NOT_FOUND',
            'The external-operation resource is not connected to this account.',
          );
        }
      }
      const stored = leaseRowSchema.safeParse(await database.prepare(
        `SELECT lease_token,owner_id,operation_kind,resource_id,
                apple_subject_hash,apple_principal_id,claimed_at,expires_at
         FROM apple_owner_external_operation_leases WHERE lease_token=?`,
      ).bind(leaseToken).first());
      if (
        stored.success
        && stored.data.owner_id === input.authorization.userId
        && stored.data.operation_kind === operationKind
        && stored.data.resource_id === resourceId
        && stored.data.apple_subject_hash === input.authorization.appleSubjectHash
        && stored.data.apple_principal_id === currentPrincipalId
        && stored.data.claimed_at <= input.now
        && stored.data.expires_at > input.now
        && credentialCoverageRecorded
        && installationCoverageRecorded
      ) {
        return {expiresAt: stored.data.expires_at};
      }
      throw externalOperationError(
        503,
        'APPLE_OWNER_EXTERNAL_OPERATION_LEASE_UNAVAILABLE',
        'The server could not establish durable external-operation authority. Retry the action.',
      );
    },

    async complete(leaseToken, now) {
      const token = opaqueHashSchema.parse(leaseToken);
      if (!Number.isSafeInteger(now) || now < 0) {
        throw new TypeError('External operation completion time is invalid.');
      }
      const results = await database.batch([
        database.prepare(
          `DELETE FROM apple_auth_possible_credentials
           WHERE attempt_token=? AND EXISTS(
             SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
             WHERE active_lease.lease_token=? AND active_lease.operation_kind='apple-auth'
               AND active_lease.expires_at>?
           )`,
        ).bind(token, token, now),
        database.prepare(
          `DELETE FROM apple_owner_external_operation_leases
           WHERE lease_token=? AND expires_at>?
           RETURNING lease_token`,
        ).bind(token, now),
      ]);
      const released = results[1]?.results[0] ?? null;
      if (released === null) {
        throw externalOperationError(
          503,
          'APPLE_OWNER_EXTERNAL_OPERATION_LEASE_EXPIRED',
          'External-operation authority expired before completion. Verify provider state before retrying.',
        );
      }
      if (await database.prepare(
        'SELECT 1 FROM apple_owner_external_operation_leases WHERE lease_token=?',
      ).bind(token).first() !== null || await database.prepare(
        'SELECT 1 FROM apple_auth_possible_credentials WHERE attempt_token=?',
      ).bind(token).first() !== null) {
        throw externalOperationError(
          503,
          'APPLE_OWNER_EXTERNAL_OPERATION_LEASE_RELEASE_FAILED',
          'External-operation authority could not be released safely.',
        );
      }
    },

    async markPossibleCredential(leaseToken, now) {
      const token = opaqueHashSchema.parse(leaseToken);
      if (!Number.isSafeInteger(now) || now < 0) {
        throw new TypeError('Possible Apple credential time is invalid.');
      }
      await database.prepare(
        `UPDATE apple_auth_possible_credentials
         SET credential_state='possible'
         WHERE attempt_token=? AND credential_state IN ('prepared','possible')
           AND EXISTS(
             SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
             WHERE active_lease.lease_token=? AND active_lease.operation_kind='apple-auth'
               AND active_lease.expires_at>?
           )
         RETURNING attempt_token`,
      ).bind(token, token, now).first();
      const stored = await database.prepare(
        `SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
         JOIN apple_auth_possible_credentials AS possible_credential
           ON possible_credential.owner_id=active_lease.owner_id
          AND possible_credential.apple_principal_id=active_lease.apple_principal_id
         WHERE active_lease.lease_token=? AND active_lease.operation_kind='apple-auth'
           AND active_lease.expires_at>?
           AND possible_credential.credential_state='possible'
           AND possible_credential.review_token=?`,
      ).bind(token, now, token).first();
      if (stored === null) {
        throw externalOperationError(
          503,
          'APPLE_AUTH_CREDENTIAL_MARKER_UNAVAILABLE',
          'The server could not record possible Apple credential issuance before provider exchange.',
        );
      }
    },

    async release(leaseToken, possibleCredentialResolved = false, now) {
      const token = opaqueHashSchema.parse(leaseToken);
      if (possibleCredentialResolved) {
        if (!Number.isSafeInteger(now) || (now ?? -1) < 0) {
          throw new TypeError('Resolved external operation release requires a valid timestamp.');
        }
        const results = await database.batch([
          database.prepare(
            `DELETE FROM apple_auth_possible_credentials
             WHERE attempt_token=? AND EXISTS(
               SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
               WHERE active_lease.lease_token=? AND active_lease.operation_kind='apple-auth'
                 AND active_lease.expires_at>?
             )`,
          ).bind(token, token, now),
          database.prepare(
            `DELETE FROM apple_owner_external_operation_leases
             WHERE lease_token=? AND expires_at>?
             RETURNING lease_token`,
          ).bind(token, now),
        ]);
        if ((results[1]?.results[0] ?? null) === null) {
          throw externalOperationError(
            503,
            'APPLE_OWNER_EXTERNAL_OPERATION_LEASE_EXPIRED',
            'External-operation authority expired before confirmed compensation. Manual provider review remains required.',
          );
        }
      } else {
        await database.prepare(
          'DELETE FROM apple_owner_external_operation_leases WHERE lease_token=?',
        ).bind(token).run();
      }
      if (await database.prepare(
        'SELECT 1 FROM apple_owner_external_operation_leases WHERE lease_token=?',
      ).bind(token).first() !== null || (possibleCredentialResolved && await database.prepare(
        'SELECT 1 FROM apple_auth_possible_credentials WHERE attempt_token=?',
      ).bind(token).first() !== null)) {
        throw externalOperationError(
          503,
          'APPLE_OWNER_EXTERNAL_OPERATION_LEASE_RELEASE_FAILED',
          'External-operation authority could not be released safely.',
        );
      }
    },

    assertOwnerOperationAllowed: assertOwnerAllowed,
  };
}

export async function withD1AppleOwnerExternalOperationLease<T>(input: {
  repository: AppleOwnerExternalOperationLeaseRepository;
  authorization: AppleOwnerOperationAuthorization;
  operationKind: AppleOwnerExternalOperationKind;
  resourceId: string;
  crypto: Crypto;
  now: () => number;
  operation: () => Promise<T>;
}): Promise<T> {
  const leaseToken = createExternalOperationLeaseToken(input.crypto);
  await input.repository.claim({
    authorization: input.authorization,
    operationKind: input.operationKind,
    resourceId: input.resourceId,
    leaseToken,
    now: input.now(),
  });
  let completed = false;
  try {
    const result = await input.operation();
    await input.repository.complete(leaseToken, input.now());
    await input.repository.assertOwnerOperationAllowed(input.authorization, input.now());
    completed = true;
    return result;
  } finally {
    if (!completed) await input.repository.release(leaseToken);
  }
}

function createExternalOperationLeaseToken(cryptoProvider: Crypto): string {
  const bytes = new Uint8Array(32);
  cryptoProvider.getRandomValues(bytes);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function externalOperationError(
  status: number,
  code: string,
  message: string,
): AppleOwnerExternalOperationError {
  return new AppleOwnerExternalOperationError(status, code, message);
}
