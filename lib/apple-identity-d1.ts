import { z } from 'zod';
import { AppleAuthError } from './apple-auth.ts';

const opaqueHashSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
const identityRowSchema = z.object({
  apple_subject_hash: opaqueHashSchema,
  principal_id: opaqueHashSchema,
  principal_created_at: z.number().int().positive(),
  owner_id: z.string().min(1).max(1_000),
}).strict();

export type AppleLinkedIdentity = {
  appleSubjectHash: string;
  principalId: string;
  principalCreatedAt: number;
  ownerId: string;
};

export type AppleIdentityGroupResolution =
  | {kind: 'linked'; ownerId: string; principalId: string; created: boolean}
  | {kind: 'owner-conflict'};

export type AppleIdentityDeletionAdmission = {
  ownerId: string;
  principalIds: readonly string[];
  appleSubjectHashes: readonly string[];
  now: number;
  authorizationStartedAt: number;
};

export function appleIdentityDeletionAdmissionGate(
  input: AppleIdentityDeletionAdmission,
): {sql: string; bindings: unknown[]} {
  const principalIds = [...new Set(input.principalIds.map(value => opaqueHashSchema.parse(value)))];
  const appleSubjectHashes = [
    ...new Set(input.appleSubjectHashes.map(value => opaqueHashSchema.parse(value))),
  ];
  if (
    principalIds.length < 1
    || appleSubjectHashes.length < 1
    || input.ownerId.length < 1
    || input.ownerId.length > 1_000
    || !Number.isSafeInteger(input.now)
    || input.now < 0
    || !Number.isSafeInteger(input.authorizationStartedAt)
    || input.authorizationStartedAt < 0
  ) {
    throw new TypeError('Apple deletion admission requires a valid identity and time.');
  }
  const principalPlaceholders = principalIds.map(() => '?').join(',');
  const subjectPlaceholders = appleSubjectHashes.map(() => '?').join(',');
  return {
    sql: `EXISTS(
      SELECT 1 FROM apple_auth_admission_cutover AS admission_cutover
      WHERE admission_cutover.singleton=1
        AND ?>admission_cutover.cutover_at
    ) AND NOT EXISTS(
      SELECT 1 FROM apple_account_deletions AS deletion
      WHERE deletion.expires_at>?
        AND (
          EXISTS(
            SELECT 1 FROM apple_account_deletion_subjects AS deleted_identity
            WHERE deleted_identity.deletion_key_hash=deletion.deletion_key_hash
              AND deleted_identity.apple_subject_hash IN (${subjectPlaceholders})
          )
          OR (deletion.owner_id=? AND (
            deletion.delete_owner_data=1
            OR COALESCE(deletion.apple_principal_id,deletion.apple_subject_hash)
              IN (${principalPlaceholders})
          ))
        )
        AND (deletion.provider_credentials IS NULL OR deletion.origin_connections IS NULL
          OR deletion.completion_fence_token IS NULL OR deletion.completed_at IS NULL
          OR deletion.completed_at>=?)
    )`,
    bindings: [
      input.authorizationStartedAt,
      input.now,
      ...appleSubjectHashes,
      input.ownerId,
      ...principalIds,
      input.authorizationStartedAt,
    ],
  };
}

export async function readD1AppleLinkedIdentity(
  database: D1Database,
  appleSubjectHash: string,
): Promise<AppleLinkedIdentity | null> {
  opaqueHashSchema.parse(appleSubjectHash);
  const row = await database.prepare(
    `SELECT apple_subject_hash,principal_id,principal_created_at,owner_id
     FROM apple_identity_links WHERE apple_subject_hash=?`,
  ).bind(appleSubjectHash).first();
  if (row === null) return null;
  try {
    const value = identityRowSchema.parse(row);
    return {
      appleSubjectHash: value.apple_subject_hash,
      principalId: value.principal_id,
      principalCreatedAt: value.principal_created_at,
      ownerId: value.owner_id,
    };
  } catch {
    throw invalidIdentityGroup();
  }
}

export async function bindD1AppleIdentityGroup(input: {
  database: D1Database;
  appleSubjectHashes: readonly string[];
  proposedOwnerId: string;
  requiredOwnerId?: string | null;
  requiredPrincipalId?: string | null;
  now: number;
  authorizationStartedAt: number;
}): Promise<AppleIdentityGroupResolution> {
  const hashes = [...new Set(input.appleSubjectHashes.map(hash => opaqueHashSchema.parse(hash)))]
    .sort();
  if (
    hashes.length < 1 || hashes.length > 2
    || input.proposedOwnerId.length < 1 || input.proposedOwnerId.length > 1_000
    || !Number.isSafeInteger(input.now) || input.now <= 0
    || !Number.isSafeInteger(input.authorizationStartedAt)
    || input.authorizationStartedAt <= 0
  ) {
    throw new TypeError('Apple identity group binding is invalid.');
  }

  const identities = (await Promise.all(
    hashes.map(hash => readD1AppleLinkedIdentity(input.database, hash)),
  )).filter((identity): identity is AppleLinkedIdentity => identity !== null);
  const owners = new Set(identities.map(identity => identity.ownerId));
  if (owners.size > 1) return {kind: 'owner-conflict'};
  const existingOwnerId = owners.values().next().value ?? null;
  const requiredOwnerId = input.requiredOwnerId ?? null;
  const requiredPrincipalId = input.requiredPrincipalId === undefined
    || input.requiredPrincipalId === null
    ? null
    : opaqueHashSchema.parse(input.requiredPrincipalId);
  if (requiredPrincipalId !== null && requiredOwnerId === null) {
    throw new TypeError('Apple identity principal binding requires an owner binding.');
  }
  if (requiredOwnerId !== null && existingOwnerId !== null && existingOwnerId !== requiredOwnerId) {
    return {kind: 'owner-conflict'};
  }
  const ownerId = requiredOwnerId ?? existingOwnerId ?? input.proposedOwnerId;
  const existingPrincipalIds = [...new Set(
    identities.map(identity => identity.principalId),
  )].sort();
  if (requiredPrincipalId !== null && !existingPrincipalIds.includes(requiredPrincipalId)) {
    return {kind: 'owner-conflict'};
  }
  const principalId = requiredPrincipalId ?? existingPrincipalIds[0] ?? hashes[0]!;
  const principalIds = [...new Set([...existingPrincipalIds, principalId])];
  const principalCreatedAt = Math.min(
    input.now,
    input.authorizationStartedAt,
    ...identities.map(identity => identity.principalCreatedAt),
  );

  const principalPlaceholders = principalIds.map(() => '?').join(',');
  const collision = await input.database.prepare(
    `SELECT 1 FROM apple_identity_links
     WHERE principal_id IN (${principalPlaceholders}) AND owner_id<>? LIMIT 1`,
  ).bind(...principalIds, ownerId).first();
  if (collision !== null) return {kind: 'owner-conflict'};
  const mergingPrincipals = principalIds.length > 1;
  const mergedAppleReviewToken = mergingPrincipals ? createAcknowledgementToken() : null;
  const mergedOriginReviewToken = mergingPrincipals ? createAcknowledgementToken() : null;
  const activeMergeLeaseSQL = `EXISTS(
    SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
    WHERE active_lease.owner_id=?
      AND active_lease.apple_principal_id IN (${principalPlaceholders})
      AND active_lease.expires_at>?
  )`;
  const activeMergeLeaseBindings = [ownerId, ...principalIds, input.now];
  if (mergingPrincipals && await input.database.prepare(
    `SELECT 1 AS active WHERE ${activeMergeLeaseSQL}`,
  ).bind(...activeMergeLeaseBindings).first() !== null) {
    throw identityExternalOperationInProgress();
  }
  if (await hasD1AppleIdentityDeletion(input.database, {
    ownerId,
    principalIds,
    appleSubjectHashes: hashes,
    now: input.now,
    authorizationStartedAt: input.authorizationStartedAt,
  })) throw deletionInProgress();

  const hashPlaceholders = hashes.map(() => '?').join(',');
  const identityGroupGate = `NOT EXISTS(
    SELECT 1 FROM apple_identity_links
    WHERE apple_subject_hash IN (${hashPlaceholders})
      AND (owner_id<>? OR principal_id NOT IN (${principalPlaceholders}))
  ) AND NOT EXISTS(
    SELECT 1 FROM apple_identity_links
    WHERE principal_id IN (${principalPlaceholders}) AND owner_id<>?
  )${requiredPrincipalId === null ? '' : ` AND EXISTS(
    SELECT 1 FROM apple_identity_links
    WHERE apple_subject_hash IN (${hashPlaceholders}) AND owner_id=? AND principal_id=?
  )`}${mergingPrincipals ? ` AND NOT (${activeMergeLeaseSQL})` : ''}`;
  const identityGroupGateBindings = [
    ...hashes,
    ownerId,
    ...principalIds,
    ...principalIds,
    ownerId,
    ...(requiredPrincipalId === null ? [] : [...hashes, ownerId, requiredPrincipalId]),
    ...(mergingPrincipals ? activeMergeLeaseBindings : []),
  ];
  const deletionAdmission = appleIdentityDeletionAdmissionGate({
    ownerId,
    principalIds,
    appleSubjectHashes: hashes,
    now: input.now,
    authorizationStartedAt: input.authorizationStartedAt,
  });
  const statements: D1PreparedStatement[] = [input.database.prepare(
    `UPDATE apple_identity_links
     SET principal_id=?,
         principal_created_at=MIN(COALESCE(principal_created_at,?),?),
         updated_at=MAX(updated_at,?)
     WHERE owner_id=? AND principal_id IN (${principalPlaceholders})
       AND ${identityGroupGate} AND ${deletionAdmission.sql}`,
  ).bind(
    principalId,
    principalCreatedAt,
    principalCreatedAt,
    input.now,
    ownerId,
    ...principalIds,
    ...identityGroupGateBindings,
    ...deletionAdmission.bindings,
  ), input.database.prepare(
    `UPDATE apple_native_grants
     SET principal_id=?
     WHERE owner_id=? AND principal_id IN (${principalPlaceholders})
       AND ${identityGroupGate} AND ${deletionAdmission.sql}`,
  ).bind(
    principalId,
    ownerId,
    ...principalIds,
    ...identityGroupGateBindings,
    ...deletionAdmission.bindings,
  )];
  for (const hash of hashes) {
    statements.push(input.database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) SELECT ?,?,?,?,?,? WHERE ${identityGroupGate} AND ${deletionAdmission.sql}
        ON CONFLICT(apple_subject_hash) DO NOTHING`,
    ).bind(
      hash,
      principalId,
      principalCreatedAt,
      ownerId,
      input.now,
      input.now,
      ...identityGroupGateBindings,
      ...deletionAdmission.bindings,
    ));
  }
  statements.push(input.database.prepare(
    `UPDATE apple_identity_links
     SET principal_created_at=MIN(COALESCE(principal_created_at,?),?),
         updated_at=MAX(updated_at,?)
     WHERE owner_id=? AND principal_id=?
       AND ${identityGroupGate} AND ${deletionAdmission.sql}`,
  ).bind(
    principalCreatedAt,
    principalCreatedAt,
    input.now,
    ownerId,
    principalId,
    ...identityGroupGateBindings,
    ...deletionAdmission.bindings,
  ));
  if (mergingPrincipals) {
    statements.push(
      input.database.prepare(
        `INSERT INTO apple_auth_possible_credentials(
           owner_id,apple_principal_id,apple_subject_hash,attempt_token,
           review_token,credential_state,marked_at
         )
         SELECT owner_id,?,apple_subject_hash,attempt_token,?,'possible',marked_at
         FROM apple_auth_possible_credentials
         WHERE owner_id=? AND apple_principal_id IN (${principalPlaceholders})
           AND credential_state='possible'
           AND NOT (${activeMergeLeaseSQL})
           AND ${deletionAdmission.sql}
         ORDER BY marked_at,attempt_token LIMIT 1
         ON CONFLICT(owner_id,apple_principal_id) DO UPDATE SET
           apple_subject_hash=excluded.apple_subject_hash,
           attempt_token=excluded.attempt_token,
           review_token=excluded.review_token,
           credential_state='possible',
           marked_at=MIN(apple_auth_possible_credentials.marked_at,excluded.marked_at)`,
      ).bind(
        principalId,
        mergedAppleReviewToken,
        ownerId,
        ...principalIds,
        ...activeMergeLeaseBindings,
        ...deletionAdmission.bindings,
      ),
      input.database.prepare(
        `DELETE FROM apple_auth_possible_credentials
         WHERE owner_id=? AND apple_principal_id IN (${principalPlaceholders})
           AND apple_principal_id<>?
           AND NOT (${activeMergeLeaseSQL})
           AND ${deletionAdmission.sql}`,
      ).bind(
        ownerId,
        ...principalIds,
        principalId,
        ...activeMergeLeaseBindings,
        ...deletionAdmission.bindings,
      ),
      input.database.prepare(
        `DELETE FROM apple_auth_possible_credentials
         WHERE owner_id=? AND apple_principal_id=? AND credential_state='prepared'
           AND NOT (${activeMergeLeaseSQL})
           AND ${deletionAdmission.sql}`,
      ).bind(
        ownerId,
        principalId,
        ...activeMergeLeaseBindings,
        ...deletionAdmission.bindings,
      ),
      input.database.prepare(
        `INSERT INTO origin_possible_installations(
           owner_id,scope_id,apple_principal_id,apple_subject_hash,flow_token,marked_at
         )
         SELECT owner_id,?,?,apple_subject_hash,?,marked_at
         FROM origin_possible_installations
         WHERE owner_id=? AND scope_id IN (${principalPlaceholders})
           AND NOT (${activeMergeLeaseSQL})
           AND ${deletionAdmission.sql}
         ORDER BY marked_at,flow_token LIMIT 1
         ON CONFLICT(owner_id,scope_id) DO UPDATE SET
           apple_principal_id=excluded.apple_principal_id,
           apple_subject_hash=excluded.apple_subject_hash,
           flow_token=excluded.flow_token,
           marked_at=excluded.marked_at`,
      ).bind(
        principalId,
        principalId,
        mergedOriginReviewToken,
        ownerId,
        ...principalIds,
        ...activeMergeLeaseBindings,
        ...deletionAdmission.bindings,
      ),
      input.database.prepare(
        `DELETE FROM origin_possible_installations
         WHERE owner_id=? AND scope_id IN (${principalPlaceholders})
           AND scope_id<>?
           AND NOT (${activeMergeLeaseSQL})
           AND ${deletionAdmission.sql}`,
      ).bind(
        ownerId,
        ...principalIds,
        principalId,
        ...activeMergeLeaseBindings,
        ...deletionAdmission.bindings,
      ),
    );
  }
  const results = await input.database.batch(statements);

  const resolved = await Promise.all(
    hashes.map(hash => readD1AppleLinkedIdentity(input.database, hash)),
  );
  if (resolved.some(identity => identity === null)) {
    if (mergingPrincipals && await input.database.prepare(
      `SELECT 1 AS active WHERE ${activeMergeLeaseSQL}`,
    ).bind(...activeMergeLeaseBindings).first() !== null) {
      throw identityExternalOperationInProgress();
    }
    if (await hasD1AppleIdentityDeletion(input.database, {
      ownerId,
      principalIds,
      appleSubjectHashes: hashes,
      now: input.now,
      authorizationStartedAt: input.authorizationStartedAt,
    })) throw deletionInProgress();
    return {kind: 'owner-conflict'};
  }
  const finalIdentities = resolved.filter(
    (identity): identity is AppleLinkedIdentity => identity !== null,
  );
  const finalOwnerIds = new Set(finalIdentities.map(identity => identity.ownerId));
  const finalPrincipalIds = new Set(finalIdentities.map(identity => identity.principalId));
  const finalPrincipalCreatedAt = new Set(
    finalIdentities.map(identity => identity.principalCreatedAt),
  );
  if (
    finalOwnerIds.size !== 1
    || finalPrincipalIds.size !== 1
    || finalPrincipalCreatedAt.size !== 1
  ) return {kind: 'owner-conflict'};
  const finalOwnerId = finalOwnerIds.values().next().value;
  const finalPrincipalId = finalPrincipalIds.values().next().value;
  if (
    finalOwnerId === undefined || finalPrincipalId === undefined
    || (requiredOwnerId !== null && finalOwnerId !== requiredOwnerId)
    || (requiredPrincipalId !== null && finalPrincipalId !== requiredPrincipalId)
  ) return {kind: 'owner-conflict'};
  if (await hasD1AppleIdentityDeletion(input.database, {
    ownerId: finalOwnerId,
    principalIds: [finalPrincipalId],
    appleSubjectHashes: hashes,
    now: input.now,
    authorizationStartedAt: input.authorizationStartedAt,
  })) throw deletionInProgress();
  return {
    kind: 'linked',
    ownerId: finalOwnerId,
    principalId: finalPrincipalId,
    created: identities.length === 0
      && results.slice(2, hashes.length + 2).some(result => (result.meta.changes ?? 0) > 0),
  };
}

function createAcknowledgementToken(): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return opaqueHashSchema.parse(
    btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''),
  );
}

function identityExternalOperationInProgress(): AppleAuthError {
  return new AppleAuthError(
    409,
    'APPLE_IDENTITY_EXTERNAL_OPERATION_IN_PROGRESS',
    'An external provider operation is still using this Apple identity group. Retry linking after it finishes.',
  );
}

export async function hasD1AppleIdentityDeletion(
  database: D1Database,
  input: {
    ownerId: string;
    principalIds: readonly string[];
    appleSubjectHashes: readonly string[];
    now: number;
    authorizationStartedAt: number;
  },
): Promise<boolean> {
  const gate = appleIdentityDeletionAdmissionGate(input);
  return await database.prepare(
    `SELECT 1 AS blocked WHERE NOT (${gate.sql})`,
  ).bind(...gate.bindings).first() !== null;
}

function invalidIdentityGroup(): AppleAuthError {
  return new AppleAuthError(
    503,
    'APPLE_IDENTITY_GROUP_INVALID',
    'The stored Apple identity group is invalid.',
  );
}

function deletionInProgress(): AppleAuthError {
  return new AppleAuthError(
    409,
    'APPLE_ACCOUNT_DELETION_IN_PROGRESS',
    'This Apple identity is being removed and cannot create another session.',
  );
}
