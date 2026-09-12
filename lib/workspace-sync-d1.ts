import { z } from 'zod';
import {
  APPLE_OWNER_OPERATION_ALLOWED_SQL,
  appleOwnerOperationGateBindings,
  type AppleOwnerOperationAuthorization,
} from './apple-auth-owner-d1.ts';

const workspaceAuthorityRowSchema = z.object({
  epoch: z.string(),
  incarnation: z.string().length(64).regex(/^[0-9a-f]+$/),
  revision: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
}).strict();

const recordFenceSchema = z.object({
  recordId: z.string(),
  revision: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  mutationId: z.string(),
  encodedEnvelope: z.string(),
}).strict();

const enrollmentWorkspaceRowSchema = z.object({
  epoch: z.string(),
  incarnation: z.string().length(64).regex(/^[0-9a-f]+$/),
  recovery: z.string(),
  revision: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
}).strict();

export const maximumSyncEpochsPerWorkspace = 256;
export const maximumSyncEpochsPerOwner = 4_096;

export class SyncD1IntegrityError extends Error {
  constructor(){super('Encrypted sync storage returned an invalid state.');this.name='SyncD1IntegrityError';}
}

export type SyncWorkspaceAuthority = z.infer<typeof workspaceAuthorityRowSchema>;
export type SyncWorkspaceAuthorityRead =
  | {kind:'missing'}
  | {kind:'invalid'}
  | ({kind:'present'} & SyncWorkspaceAuthority);

export async function readSyncWorkspaceAuthority(input: {
  database: D1Database;
  userId: string;
  workspaceId: string;
}): Promise<SyncWorkspaceAuthorityRead> {
  const raw = await input.database.prepare(
    `SELECT workspace.epoch,workspace.incarnation,workspace.revision,
       EXISTS(
         SELECT 1 FROM sync_workspace_epochs AS history
         WHERE history.user_id=workspace.user_id
           AND history.workspace_id=workspace.workspace_id
           AND history.epoch=workspace.epoch
           AND history.incarnation=workspace.incarnation
       ) AS history_current,
       (SELECT count(*) FROM sync_records WHERE user_id=? AND workspace_id=?) AS record_count
     FROM (SELECT 1) AS marker
     LEFT JOIN sync_workspaces AS workspace ON workspace.user_id=? AND workspace.workspace_id=?`,
  ).bind(input.userId, input.workspaceId, input.userId, input.workspaceId).first();
  if (raw === null) return {kind:'invalid'};
  const row = z.object({
    epoch:z.string().nullable(),
    incarnation:z.string().nullable(),
    revision:z.number().nullable(),
    history_current:z.union([z.literal(0),z.literal(1)]),
    record_count:z.number().int().nonnegative().max(1_000),
  }).strict().safeParse(raw);
  if (!row.success) return {kind:'invalid'};
  const {epoch,incarnation,revision,history_current:historyCurrent,record_count:recordCount}=row.data;
  if (epoch===null&&incarnation===null&&revision===null) {
    return historyCurrent===0&&recordCount===0 ? {kind:'missing'} : {kind:'invalid'};
  }
  const authority=workspaceAuthorityRowSchema.safeParse({epoch,incarnation,revision});
  return authority.success&&historyCurrent===1 ? {kind:'present',...authority.data} : {kind:'invalid'};
}

export function syncWorkspaceAuthorityMatches(
  current: SyncWorkspaceAuthorityRead,
  expected: SyncWorkspaceAuthority,
): boolean {
  return current.kind === 'present'
    && current.epoch === expected.epoch
    && current.incarnation === expected.incarnation
    && current.revision === expected.revision;
}

export type AuthorizedSyncFenceResult = 'current' | 'changed' | 'unauthorized';

export type SyncRecordFence =
  | {kind:'missing';recordId:string}
  | ({kind:'present'} & z.infer<typeof recordFenceSchema>);

export async function readAuthorizedSyncFence(input: {
  database: D1Database;
  authorization: AppleOwnerOperationAuthorization;
  operationTime: number;
  workspaceId: string;
  workspace:
    | {kind:'missing';requireRecordsAbsent?:boolean}
    | ({kind:'present';recovery?:string} & SyncWorkspaceAuthority);
  record?: SyncRecordFence;
}): Promise<AuthorizedSyncFenceResult> {
  const bindings: unknown[] = [];
  let workspaceClause: string;
  if (input.workspace.kind === 'missing') {
    workspaceClause = 'NOT EXISTS(SELECT 1 FROM sync_workspaces WHERE user_id=? AND workspace_id=?)';
    bindings.push(input.authorization.userId, input.workspaceId);
    if (input.workspace.requireRecordsAbsent) {
      workspaceClause += ' AND NOT EXISTS(SELECT 1 FROM sync_records WHERE user_id=? AND workspace_id=?)';
      bindings.push(input.authorization.userId, input.workspaceId);
    }
  } else {
    workspaceClause = `EXISTS(
      SELECT 1 FROM sync_workspaces
      WHERE user_id=? AND workspace_id=? AND epoch=? AND incarnation=? AND revision=?`;
    bindings.push(
      input.authorization.userId,
      input.workspaceId,
      input.workspace.epoch,
      input.workspace.incarnation,
      input.workspace.revision,
    );
    if (input.workspace.recovery !== undefined) {
      workspaceClause += ' AND recovery=?';
      bindings.push(input.workspace.recovery);
    }
    workspaceClause += ')';
  }
  if (input.record?.kind === 'missing') {
    workspaceClause += ' AND NOT EXISTS(SELECT 1 FROM sync_records WHERE user_id=? AND workspace_id=? AND record_id=?)';
    bindings.push(input.authorization.userId, input.workspaceId, input.record.recordId);
  } else if (input.record?.kind === 'present') {
    const record = recordFenceSchema.parse({
      recordId:input.record.recordId,
      revision:input.record.revision,
      mutationId:input.record.mutationId,
      encodedEnvelope:input.record.encodedEnvelope,
    });
    workspaceClause += ` AND EXISTS(
      SELECT 1 FROM sync_records
      WHERE user_id=? AND workspace_id=? AND record_id=? AND revision=?
        AND mutation_id=? AND envelope=?
    )`;
    bindings.push(
      input.authorization.userId,
      input.workspaceId,
      record.recordId,
      record.revision,
      record.mutationId,
      record.encodedEnvelope,
    );
  }
  const raw = await input.database.prepare(
    `WITH authorized AS (SELECT 1 AS allowed WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL})
     SELECT CASE WHEN ${workspaceClause} THEN 1 ELSE 0 END AS state_current,
       CASE WHEN
         (
           NOT EXISTS(SELECT 1 FROM sync_workspaces WHERE user_id=? AND workspace_id=?)
           AND NOT EXISTS(SELECT 1 FROM sync_records WHERE user_id=? AND workspace_id=?)
         ) OR EXISTS(
           SELECT 1 FROM sync_workspaces AS workspace
           WHERE workspace.user_id=? AND workspace.workspace_id=?
             AND EXISTS(
               SELECT 1 FROM sync_workspace_epochs AS history
               WHERE history.user_id=workspace.user_id
                 AND history.workspace_id=workspace.workspace_id
                 AND history.epoch=workspace.epoch
                 AND history.incarnation=workspace.incarnation
             )
             AND (SELECT count(*) FROM sync_records WHERE user_id=? AND workspace_id=?)<=1000
         ) THEN 1 ELSE 0 END AS storage_valid
     FROM authorized`,
  ).bind(
    ...appleOwnerOperationGateBindings(input.authorization, input.operationTime),
    ...bindings,
    input.authorization.userId,input.workspaceId,
    input.authorization.userId,input.workspaceId,
    input.authorization.userId,input.workspaceId,
    input.authorization.userId,input.workspaceId,
  ).first();
  if (raw === null) return 'unauthorized';
  const row = z.object({
    state_current:z.union([z.literal(0),z.literal(1)]),
    storage_valid:z.union([z.literal(0),z.literal(1)]),
  }).strict().safeParse(raw);
  if(!row.success)throw new SyncD1IntegrityError();
  if(row.data.storage_valid!==1)throw new SyncD1IntegrityError();
  return row.data.state_current === 1 ? 'current' : 'changed';
}

export type AuthorizedSyncWorkspaceList =
  | {kind:'unauthorized'}
  | {kind:'authorized';rows:{workspace_id:string;epoch:string;updated_at:string}[]};

export async function readAuthorizedSyncWorkspaceList(input: {
  database:D1Database;
  authorization:AppleOwnerOperationAuthorization;
  operationTime:number;
}):Promise<AuthorizedSyncWorkspaceList> {
  const result = await input.database.prepare(
    `WITH authorized AS (SELECT 1 AS allowed WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}),
     listed AS (
       SELECT workspace.workspace_id,workspace.epoch,workspace.updated_at,
         EXISTS(
           SELECT 1 FROM sync_workspace_epochs AS history
           WHERE history.user_id=workspace.user_id
             AND history.workspace_id=workspace.workspace_id
             AND history.epoch=workspace.epoch
             AND history.incarnation=workspace.incarnation
         ) AS history_current,
         (SELECT count(*) FROM sync_records AS records
          WHERE records.user_id=workspace.user_id AND records.workspace_id=workspace.workspace_id) AS record_count
       FROM sync_workspaces AS workspace
       WHERE user_id=? ORDER BY updated_at DESC LIMIT 21
     )
     SELECT authorized.allowed,listed.workspace_id,listed.epoch,listed.updated_at,
       listed.history_current,listed.record_count,
       (SELECT count(*) FROM sync_records AS records
        WHERE records.user_id=?
          AND NOT EXISTS(
            SELECT 1 FROM sync_workspaces AS workspace
            WHERE workspace.user_id=records.user_id AND workspace.workspace_id=records.workspace_id
          )) AS owner_orphan_count
     FROM authorized LEFT JOIN listed ON 1=1
     ORDER BY listed.updated_at DESC`,
  ).bind(
    ...appleOwnerOperationGateBindings(input.authorization,input.operationTime),
    input.authorization.userId,
    input.authorization.userId,
  ).all();
  if (result.results.length === 0) return {kind:'unauthorized'};
  const markerSchema = z.object({
    allowed:z.literal(1),
    workspace_id:z.string().nullable(),
    epoch:z.string().nullable(),
    updated_at:z.string().nullable(),
    history_current:z.union([z.literal(0),z.literal(1)]).nullable(),
    record_count:z.number().int().nonnegative().max(1_000).nullable(),
    owner_orphan_count:z.literal(0),
  }).strict();
  const rows = result.results.map(row => {const parsed=markerSchema.safeParse(row);if(!parsed.success)throw new SyncD1IntegrityError();return parsed.data;});
  if (rows.length === 1 && rows[0]?.workspace_id === null) {
    if(rows[0]?.history_current!==null||rows[0]?.record_count!==null)throw new SyncD1IntegrityError();
    return {kind:'authorized',rows:[]};
  }
  return {kind:'authorized',rows:rows.map(row => {
    if (row.workspace_id === null || row.epoch === null || row.updated_at === null || row.history_current!==1 || row.record_count===null) {
      throw new SyncD1IntegrityError();
    }
    return {workspace_id:row.workspace_id,epoch:row.epoch,updated_at:row.updated_at};
  })};
}

export type AuthorizedSyncWorkspaceSnapshot =
  | {kind:'unauthorized'}
  | {kind:'authorized';workspace:z.infer<typeof enrollmentWorkspaceRowSchema>|null};

export async function readAuthorizedSyncWorkspaceSnapshot(input: {
  database:D1Database;
  authorization:AppleOwnerOperationAuthorization;
  operationTime:number;
  workspaceId:string;
}):Promise<AuthorizedSyncWorkspaceSnapshot> {
  const raw = await input.database.prepare(
    `WITH authorized AS (SELECT 1 AS allowed WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL})
     SELECT workspace.epoch,workspace.incarnation,workspace.recovery,workspace.revision
       ,EXISTS(
         SELECT 1 FROM sync_workspace_epochs AS history
         WHERE history.user_id=workspace.user_id
           AND history.workspace_id=workspace.workspace_id
           AND history.epoch=workspace.epoch
           AND history.incarnation=workspace.incarnation
       ) AS history_current
       ,(SELECT count(*) FROM sync_records WHERE user_id=? AND workspace_id=?) AS record_count
     FROM authorized
     LEFT JOIN sync_workspaces AS workspace ON workspace.user_id=? AND workspace.workspace_id=?`,
  ).bind(
    ...appleOwnerOperationGateBindings(input.authorization,input.operationTime),
    input.authorization.userId,input.workspaceId,
    input.authorization.userId,input.workspaceId,
  ).first();
  if (raw === null) return {kind:'unauthorized'};
  const parsed = z.object({
    epoch:z.string().nullable(),
    incarnation:z.string().nullable(),
    recovery:z.string().nullable(),
    revision:z.number().nullable(),
    history_current:z.union([z.literal(0),z.literal(1)]),
    record_count:z.number().int().nonnegative().max(1_000),
  }).strict().safeParse(raw);
  if(!parsed.success)throw new SyncD1IntegrityError();
  const nullableRow=parsed.data;
  const values = [nullableRow.epoch,nullableRow.incarnation,nullableRow.recovery,nullableRow.revision];
  if (values.every(value => value === null)) {
    if(nullableRow.history_current!==0||nullableRow.record_count!==0)throw new SyncD1IntegrityError();
    return {kind:'authorized',workspace:null};
  }
  const workspace=enrollmentWorkspaceRowSchema.safeParse({
    epoch:nullableRow.epoch,
    incarnation:nullableRow.incarnation,
    recovery:nullableRow.recovery,
    revision:nullableRow.revision,
  });
  if(!workspace.success||nullableRow.history_current!==1)throw new SyncD1IntegrityError();
  return {kind:'authorized',workspace:workspace.data};
}

export type AuthorizedSyncEnrollmentSnapshot =
  | {kind:'unauthorized'}
  | {
      kind:'authorized';
      ownerEpochCount:number;
      workspaceEpochCount:number;
      activeWorkspaceCount:number;
      epochSeen:boolean;
      workspace:z.infer<typeof enrollmentWorkspaceRowSchema>|null;
    };

export async function readAuthorizedSyncEnrollmentSnapshot(input: {
  database:D1Database;
  authorization:AppleOwnerOperationAuthorization;
  operationTime:number;
  workspaceId:string;
  epoch:string;
}):Promise<AuthorizedSyncEnrollmentSnapshot> {
  const raw = await input.database.prepare(
    `WITH authorized AS (SELECT 1 AS allowed WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL})
     SELECT
       (SELECT count(*) FROM sync_workspace_epochs WHERE user_id=?) AS owner_epoch_count,
       (SELECT count(*) FROM sync_workspace_epochs WHERE user_id=? AND workspace_id=?) AS workspace_epoch_count,
       (SELECT count(*) FROM sync_workspaces WHERE user_id=?) AS active_workspace_count,
       EXISTS(SELECT 1 FROM sync_workspace_epochs WHERE user_id=? AND workspace_id=? AND epoch=?) AS epoch_seen,
       workspace.epoch,workspace.incarnation,workspace.recovery,workspace.revision,
       EXISTS(
         SELECT 1 FROM sync_workspace_epochs AS history
         WHERE history.user_id=workspace.user_id
           AND history.workspace_id=workspace.workspace_id
           AND history.epoch=workspace.epoch
           AND history.incarnation=workspace.incarnation
       ) AS history_current,
       (SELECT count(*) FROM sync_records WHERE user_id=? AND workspace_id=?) AS record_count
     FROM authorized
     LEFT JOIN sync_workspaces AS workspace ON workspace.user_id=? AND workspace.workspace_id=?`,
  ).bind(
    ...appleOwnerOperationGateBindings(input.authorization,input.operationTime),
    input.authorization.userId,
    input.authorization.userId,input.workspaceId,
    input.authorization.userId,
    input.authorization.userId,input.workspaceId,input.epoch,
    input.authorization.userId,input.workspaceId,
    input.authorization.userId,input.workspaceId,
  ).first();
  if (raw === null) return {kind:'unauthorized'};
  const parsed = z.object({
    owner_epoch_count:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    workspace_epoch_count:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    active_workspace_count:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    epoch_seen:z.union([z.literal(0),z.literal(1)]),
    epoch:z.string().nullable(),
    incarnation:z.string().nullable(),
    recovery:z.string().nullable(),
    revision:z.number().nullable(),
    history_current:z.union([z.literal(0),z.literal(1)]),
    record_count:z.number().int().nonnegative().max(1_000),
  }).strict().safeParse(raw);
  if(!parsed.success)throw new SyncD1IntegrityError();
  const row=parsed.data;
  const nullableWorkspace = [row.epoch,row.incarnation,row.recovery,row.revision];
  const workspace = nullableWorkspace.every(value => value === null)
    ? null
    : enrollmentWorkspaceRowSchema.safeParse({
        epoch:row.epoch,
        incarnation:row.incarnation,
        recovery:row.recovery,
        revision:row.revision,
      });
  if(workspace===null){if(row.history_current!==0||row.record_count!==0)throw new SyncD1IntegrityError();}
  else if(!workspace.success||row.history_current!==1)throw new SyncD1IntegrityError();
  return {
    kind:'authorized',
    ownerEpochCount:row.owner_epoch_count,
    workspaceEpochCount:row.workspace_epoch_count,
    activeWorkspaceCount:row.active_workspace_count,
    epochSeen:row.epoch_seen === 1,
    workspace:workspace?.data??null,
  };
}

function freshSyncIncarnation():string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map(byte => byte.toString(16).padStart(2,'0')).join('');
}

export type SyncWorkspaceEnrollmentResult =
  | {kind:'applied';workspace:z.infer<typeof enrollmentWorkspaceRowSchema>}
  | {kind:'not-applied'};

export async function enrollSyncWorkspaceWithFreshIncarnation(input: {
  database:D1Database;
  authorization:AppleOwnerOperationAuthorization;
  operationTime:number;
  workspaceId:string;
  epoch:string;
  encodedRecovery:string;
  timestamp:string;
}):Promise<SyncWorkspaceEnrollmentResult> {
  const incarnation = freshSyncIncarnation();
  const gate = appleOwnerOperationGateBindings(input.authorization,input.operationTime);
  const results = await input.database.batch([
    input.database.prepare(
      `INSERT OR IGNORE INTO sync_workspace_epochs(user_id,workspace_id,epoch,incarnation,enrolled_at)
       SELECT ?,?,?,?,?
       WHERE EXISTS(SELECT 1 FROM workspaces WHERE user_id=?)
         AND NOT EXISTS(SELECT 1 FROM sync_workspaces WHERE user_id=? AND workspace_id=?)
         AND NOT EXISTS(SELECT 1 FROM sync_records WHERE user_id=? AND workspace_id=?)
         AND (SELECT count(*) FROM sync_workspaces WHERE user_id=?)<20
         AND (SELECT count(*) FROM sync_workspace_epochs WHERE user_id=?)<?
         AND (SELECT count(*) FROM sync_workspace_epochs WHERE user_id=? AND workspace_id=?)<?
         AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
       RETURNING incarnation`,
    ).bind(
      input.authorization.userId,input.workspaceId,input.epoch,incarnation,input.timestamp,
      input.authorization.userId,
      input.authorization.userId,input.workspaceId,
      input.authorization.userId,input.workspaceId,
      input.authorization.userId,
      input.authorization.userId,maximumSyncEpochsPerOwner,
      input.authorization.userId,input.workspaceId,maximumSyncEpochsPerWorkspace,
      ...gate,
    ),
    input.database.prepare(
      `INSERT OR IGNORE INTO sync_workspaces(
         user_id,workspace_id,epoch,incarnation,recovery,revision,created_at,updated_at
       )
       SELECT ?,?,?,?,?,0,?,?
       WHERE EXISTS(
         SELECT 1 FROM sync_workspace_epochs
         WHERE user_id=? AND workspace_id=? AND epoch=? AND incarnation=?
       )
         AND NOT EXISTS(SELECT 1 FROM sync_workspaces WHERE user_id=? AND workspace_id=?)
         AND (SELECT count(*) FROM sync_workspaces WHERE user_id=?)<20
         AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
       RETURNING epoch,incarnation,recovery,revision`,
    ).bind(
      input.authorization.userId,input.workspaceId,input.epoch,incarnation,input.encodedRecovery,
      input.timestamp,input.timestamp,
      input.authorization.userId,input.workspaceId,input.epoch,incarnation,
      input.authorization.userId,input.workspaceId,
      input.authorization.userId,
      ...gate,
    ),
    input.database.prepare(
      `DELETE FROM sync_workspace_epochs
       WHERE user_id=? AND workspace_id=? AND epoch=? AND incarnation=?
         AND NOT EXISTS(
           SELECT 1 FROM sync_workspaces
           WHERE user_id=? AND workspace_id=? AND epoch=? AND incarnation=?
         )
       RETURNING incarnation`,
    ).bind(
      input.authorization.userId,input.workspaceId,input.epoch,incarnation,
      input.authorization.userId,input.workspaceId,input.epoch,incarnation,
    ),
  ]);
  const claimed = z.object({incarnation:z.string()}).strict().safeParse(results[0]?.results[0]);
  const workspace = enrollmentWorkspaceRowSchema.safeParse(results[1]?.results[0]);
  const rolledBack = z.object({incarnation:z.string()}).strict().safeParse(results[2]?.results[0]);
  if (!claimed.success) {
    if (workspace.success || rolledBack.success || (results[1]?.meta.changes ?? 0) !== 0 || (results[2]?.meta.changes ?? 0) !== 0) {
      throw new SyncD1IntegrityError();
    }
    return {kind:'not-applied'};
  }
  if (
    claimed.data.incarnation !== incarnation
    || !workspace.success
    || workspace.data.incarnation !== incarnation
    || rolledBack.success
    || (results[0]?.meta.changes ?? 0) !== 1
    || (results[1]?.meta.changes ?? 0) !== 1
    || (results[2]?.meta.changes ?? 0) !== 0
  ) throw new SyncD1IntegrityError();
  return {kind:'applied',workspace:workspace.data};
}

export async function insertEncryptedSyncRecordIfWorkspaceCurrent(input: {
  database: D1Database;
  authorization: AppleOwnerOperationAuthorization;
  operationTime: number;
  workspaceId: string;
  expectedEpoch: string;
  expectedIncarnation: string;
  recordId: string;
  mutationId: string;
  encodedEnvelope: string;
  updatedAt: string;
}): Promise<unknown | null> {
  return input.database.prepare(
    `INSERT OR IGNORE INTO sync_records(
       user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at
     )
     SELECT ?,?,?,0,?,?,?
     WHERE (SELECT count(*) FROM sync_records WHERE user_id=? AND workspace_id=?)<1000
       AND EXISTS(
         SELECT 1 FROM sync_workspaces AS workspace
         WHERE workspace.user_id=? AND workspace.workspace_id=? AND workspace.epoch=? AND workspace.incarnation=? AND workspace.revision<?
           AND EXISTS(
             SELECT 1 FROM sync_workspace_epochs AS history
             WHERE history.user_id=workspace.user_id
               AND history.workspace_id=workspace.workspace_id
               AND history.epoch=workspace.epoch
               AND history.incarnation=workspace.incarnation
           )
       )
       AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
     RETURNING record_id,revision,mutation_id,envelope`,
  ).bind(
    input.authorization.userId,
    input.workspaceId,
    input.recordId,
    input.mutationId,
    input.encodedEnvelope,
    input.updatedAt,
    input.authorization.userId,
    input.workspaceId,
    input.authorization.userId,
    input.workspaceId,
    input.expectedEpoch,
    input.expectedIncarnation,
    Number.MAX_SAFE_INTEGER,
    ...appleOwnerOperationGateBindings(input.authorization, input.operationTime),
  ).first();
}

export async function updateEncryptedSyncRecordIfWorkspaceCurrent(input: {
  database: D1Database;
  authorization: AppleOwnerOperationAuthorization;
  operationTime: number;
  workspaceId: string;
  expectedEpoch: string;
  expectedIncarnation: string;
  recordId: string;
  expectedRevision: number;
  mutationId: string;
  encodedEnvelope: string;
  updatedAt: string;
}): Promise<unknown | null> {
  return input.database.prepare(
    `UPDATE sync_records
     SET revision=revision+1,mutation_id=?,envelope=?,updated_at=?
     WHERE user_id=? AND workspace_id=? AND record_id=? AND revision=? AND revision<? AND mutation_id<>?
       AND EXISTS(
         SELECT 1 FROM sync_workspaces AS workspace
         WHERE workspace.user_id=? AND workspace.workspace_id=? AND workspace.epoch=? AND workspace.incarnation=? AND workspace.revision<?
           AND EXISTS(
             SELECT 1 FROM sync_workspace_epochs AS history
             WHERE history.user_id=workspace.user_id
               AND history.workspace_id=workspace.workspace_id
               AND history.epoch=workspace.epoch
               AND history.incarnation=workspace.incarnation
           )
           AND (SELECT count(*) FROM sync_records WHERE user_id=? AND workspace_id=?)<=1000
       )
       AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
     RETURNING record_id,revision,mutation_id,envelope`,
  ).bind(
    input.mutationId,
    input.encodedEnvelope,
    input.updatedAt,
    input.authorization.userId,
    input.workspaceId,
    input.recordId,
    input.expectedRevision,
    Number.MAX_SAFE_INTEGER,
    input.mutationId,
    input.authorization.userId,
    input.workspaceId,
    input.expectedEpoch,
    input.expectedIncarnation,
    Number.MAX_SAFE_INTEGER,
    input.authorization.userId,
    input.workspaceId,
    ...appleOwnerOperationGateBindings(input.authorization, input.operationTime),
  ).first();
}
