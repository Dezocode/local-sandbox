import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile, readdir } from 'node:fs/promises';
import {
  APPLE_AUTH_RETENTION_PURGE_LIMIT,
  drainExpiredAppleAuthLifecycleRecords,
  purgeExpiredAppleAuthRecords,
} from '../lib/apple-auth-retention-d1.ts';

const NOW = 1_800_000_000;

async function applyAllMigrations(database: D1Database): Promise<void> {
  const migrations = (await readdir('drizzle')).filter(name => name.endsWith('.sql')).sort();
  for (const name of migrations) {
    const migration = await readFile(`drizzle/${name}`, 'utf8');
    for (const statement of migration
      .split('--> statement-breakpoint')
      .map(value => value.trim())
      .filter(Boolean)) {
      await database.prepare(statement).run();
    }
  }
}

async function seedExpired(
  database: D1Database,
  count: number,
  prefix: string,
): Promise<void> {
  await database.prepare(
    `WITH RECURSIVE ids(value) AS (
       VALUES(1) UNION ALL SELECT value+1 FROM ids WHERE value<?
     )
     INSERT INTO apple_auth_flows(
       schema_version,state_hash,purpose,owner_id,nonce_hash,browser_binding_hash,
       owner_binding,return_to,created_at,expires_at,consumed_at
     )
     SELECT 2,? || printf('%042d',value),'authenticate',NULL,
            ? || printf('%042d',value),? || printf('%042d',value),
            ? || printf('%042d',value),'/',?,?,NULL
     FROM ids`,
  ).bind(
    count,
    prefix,
    prefix.toUpperCase(),
    prefix === prefix.toUpperCase() ? 'n' : 'N',
    prefix === prefix.toUpperCase() ? 'b' : 'B',
    NOW - 2,
    NOW - 1,
  ).run();
  await database.prepare(
    `WITH RECURSIVE ids(value) AS (
       VALUES(1) UNION ALL SELECT value+1 FROM ids WHERE value<?
     )
     INSERT INTO apple_auth_sessions(
       schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
       encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
     )
     SELECT 2,? || printf('%042d',value),'owner-' || ? || value,
            ? || printf('%042d',value),? || printf('%042d',value),
            'malformed-expired-ciphertext-' || value,?,?,?,NULL
     FROM ids`,
  ).bind(
    count,
    prefix.toUpperCase(),
    prefix,
    prefix === prefix.toUpperCase() ? 's' : 'S',
    prefix === prefix.toUpperCase() ? 'a' : 'A',
    NOW - 2,
    NOW - 1,
    NOW - 2,
  ).run();
  await database.prepare(
    `WITH RECURSIVE ids(value) AS (
       VALUES(1) UNION ALL SELECT value+1 FROM ids WHERE value<?
     )
     INSERT INTO apple_native_sessions(
       schema_version,identity_token_hash,session_hash,owner_id,apple_subject_hash,
       created_at,expires_at,identity_token_expires_at,revoked_at
     )
     SELECT 1,? || printf('%042d',value),? || printf('%042d',value),
            'native-owner-' || ? || value,? || printf('%042d',value),
            ?,?,?,NULL
     FROM ids`,
  ).bind(
    count,
    prefix === prefix.toUpperCase() ? 'i' : 'I',
    prefix === prefix.toUpperCase() ? 'j' : 'J',
    prefix,
    prefix === prefix.toUpperCase() ? 'k' : 'K',
    NOW - 2,
    NOW - 1,
    NOW - 61,
  ).run();
  await database.prepare(
    `WITH RECURSIVE ids(value) AS (
       VALUES(1) UNION ALL SELECT value+1 FROM ids WHERE value<?
     )
     INSERT INTO apple_native_authorization_code_claims(
       authorization_code_hash,claimed_at,expires_at
     )
     SELECT ? || printf('%042d',value),?,? FROM ids`,
  ).bind(
    count,
    prefix === prefix.toUpperCase() ? 'c' : 'C',
    NOW - 2,
    NOW - 1,
  ).run();
  await database.prepare(
    `WITH RECURSIVE ids(value) AS (
       VALUES(1) UNION ALL SELECT value+1 FROM ids WHERE value<?
     )
     INSERT INTO apple_account_deletions(
       deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
       started_at,expires_at
     )
     SELECT ? || printf('%042d',value),
            ? || printf('%042d',value),
            'owner-' || ? || value,
            'subject-' || ? || value,
            1,?,?
     FROM ids`,
  ).bind(count, prefix, prefix.toUpperCase(), prefix, prefix, NOW - 2, NOW - 1).run();
  await database.prepare(
    `WITH RECURSIVE ids(value) AS (
       VALUES(1) UNION ALL SELECT value+1 FROM ids WHERE value<?
     )
     INSERT INTO apple_auth_notifications(
       notification_id_hash,event_type,issued_at,processed_at,expires_at
     )
     SELECT ? || printf('%042d',value),'email-enabled',?,?,?
     FROM ids`,
  ).bind(count, prefix.toUpperCase(), NOW - 3, NOW - 2, NOW - 1).run();
  await database.prepare(
    `WITH RECURSIVE ids(value) AS (
       VALUES(1) UNION ALL SELECT value+1 FROM ids WHERE value<?
     )
     INSERT INTO apple_owner_external_operation_leases(
       lease_token,owner_id,operation_kind,resource_id,apple_subject_hash,apple_principal_id,
       claimed_at,expires_at
     )
     SELECT ? || printf('%042d',value),'lease-owner-' || ? || value,
            'origin','inst_' || printf('%020d',value),NULL,NULL,?,?
     FROM ids`,
  ).bind(
    count,
    prefix === prefix.toUpperCase() ? 'l' : 'L',
    prefix,
    NOW - 2,
    NOW - 1,
  ).run();
}

test('scheduled Apple lifecycle retention drains bounded batches and signals backlog', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const flowPlan = await database.prepare(
      `EXPLAIN QUERY PLAN SELECT state_hash FROM apple_auth_flows
       WHERE expires_at<=? ORDER BY expires_at,state_hash LIMIT ?`,
    ).bind(NOW, APPLE_AUTH_RETENTION_PURGE_LIMIT).all();
    const sessionPlan = await database.prepare(
      `EXPLAIN QUERY PLAN SELECT session_hash FROM apple_auth_sessions
       WHERE expires_at<=? ORDER BY expires_at,session_hash LIMIT ?`,
    ).bind(NOW, APPLE_AUTH_RETENTION_PURGE_LIMIT).all();
    const nativeSessionPlan = await database.prepare(
      `EXPLAIN QUERY PLAN SELECT identity_token_hash FROM apple_native_sessions
       WHERE expires_at<=? AND identity_token_expires_at<=?
       ORDER BY expires_at,identity_token_hash LIMIT ?`,
    ).bind(NOW, NOW - 60, APPLE_AUTH_RETENTION_PURGE_LIMIT).all();
    const nativeGrantPlan = await database.prepare(
      `EXPLAIN QUERY PLAN SELECT grant_hash FROM apple_native_grants
       WHERE expires_at<=? ORDER BY expires_at,grant_hash LIMIT ?`,
    ).bind(NOW, APPLE_AUTH_RETENTION_PURGE_LIMIT).all();
    const nativeCodeClaimPlan = await database.prepare(
      `EXPLAIN QUERY PLAN SELECT authorization_code_hash
       FROM apple_native_authorization_code_claims
       WHERE expires_at<=? ORDER BY expires_at,authorization_code_hash LIMIT ?`,
    ).bind(NOW, APPLE_AUTH_RETENTION_PURGE_LIMIT).all();
    const deletionPlan = await database.prepare(
      `EXPLAIN QUERY PLAN SELECT deletion_key_hash FROM apple_account_deletions
       WHERE expires_at<=? ORDER BY expires_at,deletion_key_hash LIMIT ?`,
    ).bind(NOW, APPLE_AUTH_RETENTION_PURGE_LIMIT).all();
    const notificationPlan = await database.prepare(
      `EXPLAIN QUERY PLAN SELECT notification_id_hash FROM apple_auth_notifications
       WHERE expires_at<=? ORDER BY expires_at,notification_id_hash LIMIT ?`,
    ).bind(NOW, APPLE_AUTH_RETENTION_PURGE_LIMIT).all();
    const externalOperationLeasePlan = await database.prepare(
      `EXPLAIN QUERY PLAN SELECT lease_token FROM apple_owner_external_operation_leases
       WHERE expires_at<=? ORDER BY expires_at,lease_token LIMIT ?`,
    ).bind(NOW, APPLE_AUTH_RETENTION_PURGE_LIMIT).all();
    assert.match(JSON.stringify(deletionPlan.results), /apple_account_deletions_expiry_idx/);
    assert.match(JSON.stringify(notificationPlan.results), /apple_auth_notifications_expiry_idx/);
    assert.match(JSON.stringify(flowPlan.results), /apple_auth_flows_expiry_idx/);
    assert.match(JSON.stringify(sessionPlan.results), /apple_auth_sessions_expiry_idx/);
    assert.match(JSON.stringify(nativeSessionPlan.results), /apple_native_sessions_expiry_idx/);
    assert.match(JSON.stringify(nativeGrantPlan.results), /apple_native_grants_expiry_idx/);
    assert.match(
      JSON.stringify(externalOperationLeasePlan.results),
      /apple_owner_external_operation_leases_expiry_idx/,
    );
    assert.match(
      JSON.stringify(nativeCodeClaimPlan.results),
      /apple_native_authorization_code_claims_expiry_idx/,
    );

    await seedExpired(database, 205, 'd');
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        started_at,expires_at
      ) VALUES('future-deletion','future-binding','future-owner','future-subject',1,?,?)`,
    ).bind(NOW, NOW + 1).run();
    await database.prepare(
      `INSERT INTO apple_auth_notifications(
        notification_id_hash,event_type,issued_at,processed_at,expires_at
      ) VALUES('future-notification','email-enabled',?,?,?)`,
    ).bind(NOW, NOW, NOW + 1).run();
    await database.prepare(
      `INSERT INTO apple_owner_external_operation_leases(
        lease_token,owner_id,operation_kind,resource_id,apple_subject_hash,apple_principal_id,
        claimed_at,expires_at
      ) VALUES(?,'future-owner','origin','inst_00000000future',NULL,NULL,?,?)`,
    ).bind('e'.repeat(43), NOW, NOW + 1).run();
    await database.prepare(
      `INSERT INTO apple_auth_flows(
        schema_version,state_hash,purpose,owner_id,nonce_hash,browser_binding_hash,
        owner_binding,return_to,created_at,expires_at,consumed_at
      ) VALUES(2,?,'authenticate',NULL,?,?,?,'/',?,?,NULL)`,
    ).bind(
      'f'.repeat(43),
      'n'.repeat(43),
      'b'.repeat(43),
      'o'.repeat(43),
      NOW,
      NOW + 1,
    ).run();
    await database.prepare(
      `INSERT INTO apple_auth_sessions(
        schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
        encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
      ) VALUES(2,?,'future-owner',?,?,?, ?,?,?,NULL)`,
    ).bind(
      'q'.repeat(43),
      'r'.repeat(43),
      't'.repeat(43),
      'future-malformed-ciphertext',
      NOW,
      NOW + 1,
      NOW,
    ).run();
    await database.prepare(
      `INSERT INTO apple_native_sessions(
        schema_version,identity_token_hash,session_hash,owner_id,apple_subject_hash,
        created_at,expires_at,identity_token_expires_at,revoked_at
      ) VALUES(1,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      'u'.repeat(43),
      'v'.repeat(43),
      'future-owner',
      'w'.repeat(43),
      NOW,
      NOW + 1,
      NOW + 1,
    ).run();
    await database.prepare(
      `INSERT INTO apple_native_authorization_code_claims(
        authorization_code_hash,claimed_at,expires_at
      ) VALUES(?,?,?)`,
    ).bind('y'.repeat(43), NOW, NOW + 1).run();
    assert.deepEqual(
      await purgeExpiredAppleAuthRecords(database, NOW),
      {
        flows: 100,
        sessions: 100,
        nativeSessions: 100,
        authorizationCodeClaims: 100,
        deletions: 100,
        notifications: 100,
        externalOperationLeases: 100,
      },
    );
    assert.deepEqual(
      await drainExpiredAppleAuthLifecycleRecords(database, NOW, 2),
      {
        batches: 2,
        flows: 105,
        sessions: 105,
        nativeSessions: 105,
        authorizationCodeClaims: 105,
        deletions: 105,
        notifications: 105,
        externalOperationLeases: 105,
      },
    );
    const flowCount = await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_auth_flows',
    ).first() as {count:number} | null;
    const sessionCount = await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_auth_sessions',
    ).first() as {count:number} | null;
    const deletionCount = await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_account_deletions',
    ).first() as {count:number} | null;
    const notificationCount = await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_auth_notifications',
    ).first() as {count:number} | null;
    assert.equal(flowCount?.count, 1);
    assert.equal(sessionCount?.count, 1);
    const nativeSessionCount = await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_native_sessions',
    ).first() as {count:number} | null;
    assert.equal(nativeSessionCount?.count, 1);
    assert.equal(
      await database.prepare(
        'SELECT COUNT(*) AS count FROM apple_native_authorization_code_claims',
      ).first('count'),
      1,
    );
    assert.equal(deletionCount?.count, 1);
    assert.equal(notificationCount?.count, 1);
    assert.equal(
      await database.prepare(
        'SELECT COUNT(*) AS count FROM apple_owner_external_operation_leases',
      ).first('count'),
      1,
    );
    assert.deepEqual(
      await purgeExpiredAppleAuthRecords(database, NOW),
      {
        flows: 0,
        sessions: 0,
        nativeSessions: 0,
        authorizationCodeClaims: 0,
        deletions: 0,
        notifications: 0,
        externalOperationLeases: 0,
      },
    );

    await seedExpired(database, 201, 'x');
    await assert.rejects(
      drainExpiredAppleAuthLifecycleRecords(database, NOW, 2),
      /APPLE_AUTH_RETENTION_BACKLOG_REMAINS/,
    );
    assert.deepEqual(
      await drainExpiredAppleAuthLifecycleRecords(database, NOW),
      {
        batches: 1,
        flows: 1,
        sessions: 1,
        nativeSessions: 1,
        authorizationCodeClaims: 1,
        deletions: 1,
        notifications: 1,
        externalOperationLeases: 1,
      },
    );
    assert.deepEqual(
      await drainExpiredAppleAuthLifecycleRecords(database, NOW),
      {
        batches: 1,
        flows: 0,
        sessions: 0,
        nativeSessions: 0,
        authorizationCodeClaims: 0,
        deletions: 0,
        notifications: 0,
        externalOperationLeases: 0,
      },
    );
    await assert.rejects(
      drainExpiredAppleAuthLifecycleRecords(database, NOW, 0),
      /positive batch limit/,
    );
  } finally {
    await miniflare.dispose();
  }
});

test('Sites worker preserves Vinext fetch and declares the hourly retention trigger', async () => {
  const [worker, vite] = await Promise.all([
    readFile('worker.ts', 'utf8'),
    readFile('vite.config.ts', 'utf8'),
  ]);
  assert.match(worker, /vinextHandler\.fetch\(request, env, context\)/);
  assert.match(worker, /async scheduled\(controller: ScheduledController, env: Cloudflare\.Env\)/);
  assert.match(worker, /drainExpiredAppleAuthLifecycleRecords/);
  assert.match(worker, /drainExpiredAppleNativeGrants/);
  assert.match(worker, /DB binding is required for scheduled retention cleanup/);
  assert.match(worker, /apple-auth-retention-complete/);
  assert.match(worker, /apple-auth-retention-failed/);
  assert.match(worker, /retention scheduler received an invalid scheduled time/);
  assert.match(vite, /main: "\.\/worker\.ts"/);
  assert.match(vite, /triggers: \{ crons: \["17 \* \* \* \*"\] \}/);
});
