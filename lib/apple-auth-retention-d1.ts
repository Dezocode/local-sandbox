export const APPLE_AUTH_RETENTION_PURGE_LIMIT = 100;
export const APPLE_AUTH_RETENTION_SCHEDULE_MAX_BATCHES = 20;

type AppleAuthRetentionPurgeResult = {
  flows: number;
  sessions: number;
  nativeSessions: number;
  authorizationCodeClaims: number;
  deletions: number;
  notifications: number;
  externalOperationLeases: number;
};

type AppleAuthRetentionDrainResult = AppleAuthRetentionPurgeResult & {
  batches: number;
};

export async function purgeExpiredAppleAuthRecords(
  database: D1Database,
  now: number,
): Promise<AppleAuthRetentionPurgeResult> {
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new TypeError('Apple auth retention cleanup requires a valid timestamp.');
  }
  const results = await database.batch([
    database.prepare(
      `DELETE FROM apple_auth_flows
       WHERE state_hash IN (
         SELECT state_hash FROM apple_auth_flows
         WHERE expires_at<=? ORDER BY expires_at,state_hash LIMIT ?
       )`,
    ).bind(now, APPLE_AUTH_RETENTION_PURGE_LIMIT),
    database.prepare(
      `DELETE FROM apple_auth_sessions
       WHERE session_hash IN (
         SELECT session_hash FROM apple_auth_sessions
         WHERE expires_at<=? ORDER BY expires_at,session_hash LIMIT ?
       )`,
    ).bind(now, APPLE_AUTH_RETENTION_PURGE_LIMIT),
    database.prepare(
      `DELETE FROM apple_account_deletions
       WHERE deletion_key_hash IN (
         SELECT deletion_key_hash FROM apple_account_deletions
         WHERE expires_at<=? ORDER BY expires_at,deletion_key_hash LIMIT ?
       )`,
    ).bind(now, APPLE_AUTH_RETENTION_PURGE_LIMIT),
    database.prepare(
      `DELETE FROM apple_native_sessions
       WHERE identity_token_hash IN (
         SELECT identity_token_hash FROM apple_native_sessions
         WHERE expires_at<=? AND identity_token_expires_at<=?
           AND NOT EXISTS(
             SELECT 1 FROM apple_native_grants
             WHERE apple_native_grants.session_hash=apple_native_sessions.session_hash
           )
         ORDER BY expires_at,identity_token_hash LIMIT ?
       )`,
    ).bind(now, now - 60, APPLE_AUTH_RETENTION_PURGE_LIMIT),
    database.prepare(
      `DELETE FROM apple_native_authorization_code_claims
       WHERE authorization_code_hash IN (
         SELECT authorization_code_hash FROM apple_native_authorization_code_claims
         WHERE expires_at<=? ORDER BY expires_at,authorization_code_hash LIMIT ?
       )`,
    ).bind(now, APPLE_AUTH_RETENTION_PURGE_LIMIT),
    database.prepare(
      `DELETE FROM apple_auth_notifications
       WHERE notification_id_hash IN (
         SELECT notification_id_hash FROM apple_auth_notifications
         WHERE expires_at<=? ORDER BY expires_at,notification_id_hash LIMIT ?
       )`,
    ).bind(now, APPLE_AUTH_RETENTION_PURGE_LIMIT),
    database.prepare(
      `DELETE FROM apple_owner_external_operation_leases
       WHERE lease_token IN (
             SELECT lease_token FROM apple_owner_external_operation_leases
             WHERE expires_at<=?
             ORDER BY expires_at,lease_token LIMIT ?
           )`,
    ).bind(now, APPLE_AUTH_RETENTION_PURGE_LIMIT),
  ]);
  return {
    flows: results[0].meta.changes ?? 0,
    sessions: results[1].meta.changes ?? 0,
    deletions: results[2].meta.changes ?? 0,
    nativeSessions: results[3].meta.changes ?? 0,
    authorizationCodeClaims: results[4].meta.changes ?? 0,
    notifications: results[5].meta.changes ?? 0,
    externalOperationLeases: results[6].meta.changes ?? 0,
  };
}

export async function purgeExpiredAppleAuthLifecycleRecords(
  database: D1Database,
  now: number,
): Promise<{deletions: number; notifications: number; externalOperationLeases: number}> {
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new TypeError('Apple auth retention cleanup requires a valid timestamp.');
  }
  const results = await database.batch([
    database.prepare(
      `DELETE FROM apple_account_deletions
       WHERE deletion_key_hash IN (
         SELECT deletion_key_hash FROM apple_account_deletions
         WHERE expires_at<=? ORDER BY expires_at,deletion_key_hash LIMIT ?
       )`,
    ).bind(now, APPLE_AUTH_RETENTION_PURGE_LIMIT),
    database.prepare(
      `DELETE FROM apple_auth_notifications
       WHERE notification_id_hash IN (
         SELECT notification_id_hash FROM apple_auth_notifications
         WHERE expires_at<=? ORDER BY expires_at,notification_id_hash LIMIT ?
       )`,
    ).bind(now, APPLE_AUTH_RETENTION_PURGE_LIMIT),
    database.prepare(
      `DELETE FROM apple_owner_external_operation_leases
       WHERE lease_token IN (
             SELECT lease_token FROM apple_owner_external_operation_leases
             WHERE expires_at<=?
             ORDER BY expires_at,lease_token LIMIT ?
           )`,
    ).bind(now, APPLE_AUTH_RETENTION_PURGE_LIMIT),
  ]);
  return {
    deletions: results[0].meta.changes ?? 0,
    notifications: results[1].meta.changes ?? 0,
    externalOperationLeases: results[2].meta.changes ?? 0,
  };
}

export async function drainExpiredAppleAuthLifecycleRecords(
  database: D1Database,
  now: number,
  maxBatches = APPLE_AUTH_RETENTION_SCHEDULE_MAX_BATCHES,
): Promise<AppleAuthRetentionDrainResult> {
  if (!Number.isSafeInteger(maxBatches) || maxBatches < 1) {
    throw new TypeError('Apple auth retention drain requires a positive batch limit.');
  }
  let flows = 0;
  let sessions = 0;
  let nativeSessions = 0;
  let authorizationCodeClaims = 0;
  let deletions = 0;
  let notifications = 0;
  let externalOperationLeases = 0;
  for (let batch = 1; batch <= maxBatches; batch += 1) {
    const result = await purgeExpiredAppleAuthRecords(database, now);
    flows += result.flows;
    sessions += result.sessions;
    nativeSessions += result.nativeSessions;
    authorizationCodeClaims += result.authorizationCodeClaims;
    deletions += result.deletions;
    notifications += result.notifications;
    externalOperationLeases += result.externalOperationLeases;
    if (
      result.flows < APPLE_AUTH_RETENTION_PURGE_LIMIT
      && result.sessions < APPLE_AUTH_RETENTION_PURGE_LIMIT
      && result.nativeSessions < APPLE_AUTH_RETENTION_PURGE_LIMIT
      && result.authorizationCodeClaims < APPLE_AUTH_RETENTION_PURGE_LIMIT
      && result.deletions < APPLE_AUTH_RETENTION_PURGE_LIMIT
      && result.notifications < APPLE_AUTH_RETENTION_PURGE_LIMIT
      && result.externalOperationLeases < APPLE_AUTH_RETENTION_PURGE_LIMIT
    ) {
      return {
        batches: batch,
        flows,
        sessions,
        nativeSessions,
        authorizationCodeClaims,
        deletions,
        notifications,
        externalOperationLeases,
      };
    }
  }
  const [
    flow,
    session,
    nativeSession,
    authorizationCodeClaim,
    deletion,
    notification,
    externalOperationLease,
  ] = await Promise.all([
    database.prepare(
      'SELECT 1 AS present FROM apple_auth_flows WHERE expires_at<=? LIMIT 1',
    ).bind(now).first<{present: number}>(),
    database.prepare(
      'SELECT 1 AS present FROM apple_auth_sessions WHERE expires_at<=? LIMIT 1',
    ).bind(now).first<{present: number}>(),
    database.prepare(
      `SELECT 1 AS present FROM apple_native_sessions
       WHERE expires_at<=? AND identity_token_expires_at<=?
         AND NOT EXISTS(
           SELECT 1 FROM apple_native_grants
           WHERE apple_native_grants.session_hash=apple_native_sessions.session_hash
         ) LIMIT 1`,
    ).bind(now, now - 60).first<{present: number}>(),
    database.prepare(
      `SELECT 1 AS present FROM apple_native_authorization_code_claims
       WHERE expires_at<=? LIMIT 1`,
    ).bind(now).first<{present: number}>(),
    database.prepare(
      'SELECT 1 AS present FROM apple_account_deletions WHERE expires_at<=? LIMIT 1',
    ).bind(now).first<{present: number}>(),
    database.prepare(
      'SELECT 1 AS present FROM apple_auth_notifications WHERE expires_at<=? LIMIT 1',
    ).bind(now).first<{present: number}>(),
    database.prepare(
      `SELECT 1 AS present FROM apple_owner_external_operation_leases
       WHERE expires_at<=? LIMIT 1`,
    ).bind(now).first<{present: number}>(),
  ]);
  if (
    flow === null && session === null && nativeSession === null
    && authorizationCodeClaim === null && deletion === null && notification === null
    && externalOperationLease === null
  ) {
    return {
      batches: maxBatches,
      flows,
      sessions,
      nativeSessions,
      authorizationCodeClaims,
      deletions,
      notifications,
      externalOperationLeases,
    };
  }
  throw new Error(
    `APPLE_AUTH_RETENTION_BACKLOG_REMAINS: scheduled cleanup reached ${maxBatches} batches`,
  );
}
