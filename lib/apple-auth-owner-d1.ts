import { purgeExpiredAppleAuthLifecycleRecords } from './apple-auth-retention-d1.ts';

export type AppleOwnerOperationAuthorization = {
  userId: string;
  authorizationStartedAt: number;
  appleSubjectHash: string | null;
};

export type AppleOwnerDeletionScope = {
  ownerId: string;
  applePrincipalId: string;
  deleteOwnerData: boolean;
};

export const APPLE_OWNER_OPERATION_ALLOWED_SQL = `NOT EXISTS(
  SELECT 1 FROM apple_account_deletions AS deletion
  WHERE deletion.expires_at>?
    AND deletion.owner_id=?
    AND (
      deletion.delete_owner_data=1
      OR (? IS NOT NULL AND deletion.delete_owner_data=0
        AND (
          EXISTS(
            SELECT 1 FROM apple_account_deletion_subjects AS deleted_identity
            WHERE deleted_identity.deletion_key_hash=deletion.deletion_key_hash
              AND deleted_identity.apple_subject_hash=?
          )
          OR COALESCE(deletion.apple_principal_id,deletion.apple_subject_hash)=COALESCE(
            (SELECT identity.principal_id FROM apple_identity_links AS identity
             WHERE identity.apple_subject_hash=? AND identity.owner_id=?),
            ?
          )
        ))
    )
    AND (deletion.provider_credentials IS NULL OR deletion.origin_connections IS NULL
      OR deletion.completion_fence_token IS NULL OR deletion.completed_at IS NULL
      OR deletion.completed_at>=?)
)`;

export const APPLE_OWNER_EXTERNAL_OPERATION_ABSENT_SQL = `NOT EXISTS(
  SELECT 1 FROM apple_owner_external_operation_leases AS external_operation
  WHERE external_operation.expires_at>?
    AND external_operation.owner_id=?
    AND (
      ?=1
      OR (
        ?=0
        AND external_operation.apple_subject_hash IS NOT NULL
        AND COALESCE(
          (SELECT current_identity.principal_id
           FROM apple_identity_links AS current_identity
           WHERE current_identity.apple_subject_hash=external_operation.apple_subject_hash
             AND current_identity.owner_id=external_operation.owner_id),
          external_operation.apple_principal_id
        )=?
      )
    )
)`;

export function appleOwnerExternalOperationAbsentBindings(
  scope: AppleOwnerDeletionScope,
  now: number,
): [number, string, 0 | 1, 0 | 1, string] {
  if (
    !Number.isSafeInteger(now) || now < 0 ||
    scope.ownerId.length < 1 || scope.ownerId.length > 1_000 ||
    !/^[A-Za-z0-9_-]{43}$/.test(scope.applePrincipalId)
  ) {
    throw new TypeError('Apple owner deletion scope is invalid.');
  }
  const deleteOwnerData = scope.deleteOwnerData ? 1 : 0;
  return [now, scope.ownerId, deleteOwnerData, deleteOwnerData, scope.applePrincipalId];
}

export function appleOwnerOperationGateBindings(
  authorization: AppleOwnerOperationAuthorization,
  now: number,
): [number, string, string | null, string | null, string | null, string, string | null, number] {
  if (
    !Number.isSafeInteger(now) || now < 0 ||
    !Number.isSafeInteger(authorization.authorizationStartedAt) ||
    authorization.authorizationStartedAt < 0 ||
    authorization.userId.length < 1 || authorization.userId.length > 1_000 ||
    (authorization.appleSubjectHash !== null && !/^[A-Za-z0-9_-]{43}$/.test(authorization.appleSubjectHash))
  ) {
    throw new TypeError('Apple owner operation authorization is invalid.');
  }
  return [
    now,
    authorization.userId,
    authorization.appleSubjectHash,
    authorization.appleSubjectHash,
    authorization.appleSubjectHash,
    authorization.userId,
    authorization.appleSubjectHash,
    authorization.authorizationStartedAt,
  ];
}

export async function isAppleOwnerOperationAllowed(
  database: D1Database,
  authorization: AppleOwnerOperationAuthorization,
  now: number,
): Promise<boolean> {
  await purgeExpiredAppleAuthLifecycleRecords(database, now);
  const row = await database.prepare(
    `SELECT 1 AS allowed WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`,
  ).bind(...appleOwnerOperationGateBindings(authorization, now)).first();
  return row !== null;
}
