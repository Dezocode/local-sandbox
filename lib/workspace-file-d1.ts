import { z } from 'zod';
import {
  APPLE_OWNER_OPERATION_ALLOWED_SQL,
  appleOwnerOperationGateBindings,
  type AppleOwnerOperationAuthorization,
} from './apple-auth-owner-d1.ts';
import { fileContentSchema, fileSchema, pathSchema, type SandboxFile } from './contracts.ts';

export const maximumFileVersion = Number.MAX_SAFE_INTEGER;

const allocationRowSchema = z.object({
  file_clock: z.number().int().nonnegative().max(maximumFileVersion),
  file_clock_claim: z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
});

export class FileVersionD1IntegrityError extends Error {
  constructor() {
    super('The file version allocation transaction returned an invalid result.');
    this.name = 'FileVersionD1IntegrityError';
  }
}

type SharedMutationInput = {
  database: D1Database;
  authorization: AppleOwnerOperationAuthorization;
  operationTime: number;
  path: z.infer<typeof pathSchema>;
  content: z.infer<typeof fileContentSchema>;
};

export type FileMutationInput = SharedMutationInput & (
  | { kind: 'create' }
  | { kind: 'save'; expectedVersion: number }
);

export type FileMutationResult =
  | { kind: 'applied'; file: SandboxFile }
  | { kind: 'not-applied' };

export type AuthorizedFileWorkspaceSnapshot =
  | {kind:'unauthorized'}
  | {
      kind:'authorized';
      workspacePresent:boolean;
      fileClock:number|null;
      fileCount:number;
      file:SandboxFile|null;
    };

function freshClaim(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export async function readAuthorizedFileWorkspaceSnapshot(input: {
  database:D1Database;
  authorization:AppleOwnerOperationAuthorization;
  operationTime:number;
  path:z.infer<typeof pathSchema>;
}):Promise<AuthorizedFileWorkspaceSnapshot> {
  const raw = await input.database.prepare(
    `WITH authorized AS (SELECT 1 AS allowed WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL})
     SELECT
       CASE WHEN workspace.user_id IS NULL THEN 0 ELSE 1 END AS workspace_present,
       workspace.file_clock,
       (SELECT count(*) FROM files WHERE user_id=?) AS file_count,
       (SELECT MAX(version) FROM files WHERE user_id=?) AS maximum_file_version,
       file.path AS file_path,file.content AS file_content,file.version AS file_version
     FROM authorized
     LEFT JOIN workspaces AS workspace ON workspace.user_id=?
     LEFT JOIN files AS file ON file.user_id=? AND file.path=?`,
  ).bind(
    ...appleOwnerOperationGateBindings(input.authorization,input.operationTime),
    input.authorization.userId,
    input.authorization.userId,
    input.authorization.userId,
    input.authorization.userId,input.path,
  ).first();
  if (raw === null) return {kind:'unauthorized'};
  const parsed = z.object({
    workspace_present:z.union([z.literal(0),z.literal(1)]),
    file_clock:z.number().int().min(-1).max(maximumFileVersion).nullable(),
    file_count:z.number().int().nonnegative().max(100),
    maximum_file_version:z.number().int().nonnegative().max(maximumFileVersion).nullable(),
    file_path:z.string().nullable(),
    file_content:z.string().nullable(),
    file_version:z.number().nullable(),
  }).strict().safeParse(raw);
  if (!parsed.success) throw new FileVersionD1IntegrityError();
  const row = parsed.data;
  const workspacePresent = row.workspace_present === 1;
  if (workspacePresent !== (row.file_clock !== null)) throw new FileVersionD1IntegrityError();
  const nullableFile = [row.file_path,row.file_content,row.file_version];
  const file = nullableFile.every(value => value === null)
    ? null
    : fileSchema.safeParse({path:row.file_path,content:row.file_content,version:row.file_version});
  if (file !== null && !file.success) throw new FileVersionD1IntegrityError();
  if (!workspacePresent && (row.file_count !== 0 || file !== null)) throw new FileVersionD1IntegrityError();
  if (workspacePresent && row.file_count > 0 && row.file_clock === -1) throw new FileVersionD1IntegrityError();
  if ((row.file_count===0)!==(row.maximum_file_version===null))throw new FileVersionD1IntegrityError();
  if(row.maximum_file_version!==null&&(row.file_clock===null||row.file_clock<row.maximum_file_version))throw new FileVersionD1IntegrityError();
  return {
    kind:'authorized',
    workspacePresent,
    fileClock:row.file_clock,
    fileCount:row.file_count,
    file:file?.data??null,
  };
}

export async function applyFileMutationWithFreshVersion(input: FileMutationInput): Promise<FileMutationResult> {
  const claim = freshClaim();
  const gate = appleOwnerOperationGateBindings(input.authorization, input.operationTime);
  const allocation = input.kind === 'create'
    ? input.database.prepare(
      `UPDATE workspaces
       SET file_clock=file_clock+1,file_clock_claim=?
       WHERE user_id=? AND file_clock>=-1 AND file_clock<?
         AND NOT EXISTS(SELECT 1 FROM files WHERE user_id=? AND path=?)
         AND (SELECT count(*) FROM files WHERE user_id=?)<100
         AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
       RETURNING file_clock,file_clock_claim`,
    ).bind(
      claim,
      input.authorization.userId,
      maximumFileVersion,
      input.authorization.userId,
      input.path,
      input.authorization.userId,
      ...gate,
    )
    : input.database.prepare(
      `UPDATE workspaces
       SET file_clock=file_clock+1,file_clock_claim=?
       WHERE user_id=? AND file_clock>=-1 AND file_clock<?
         AND EXISTS(
           SELECT 1 FROM files
           WHERE user_id=? AND path=? AND version=?
         )
         AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
       RETURNING file_clock,file_clock_claim`,
    ).bind(
      claim,
      input.authorization.userId,
      maximumFileVersion,
      input.authorization.userId,
      input.path,
      input.expectedVersion,
      ...gate,
    );
  const mutation = input.kind === 'create'
    ? input.database.prepare(
      `INSERT OR IGNORE INTO files(user_id,path,content,version)
       SELECT ?,?,?,workspace.file_clock
       FROM workspaces AS workspace
       WHERE workspace.user_id=? AND workspace.file_clock_claim=?
         AND NOT EXISTS(SELECT 1 FROM files WHERE user_id=? AND path=?)
         AND (SELECT count(*) FROM files WHERE user_id=?)<100
         AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
       RETURNING path,content,version`,
    ).bind(
      input.authorization.userId,
      input.path,
      input.content,
      input.authorization.userId,
      claim,
      input.authorization.userId,
      input.path,
      input.authorization.userId,
      ...gate,
    )
    : input.database.prepare(
      `UPDATE files
       SET content=?,version=(
         SELECT file_clock FROM workspaces
         WHERE user_id=? AND file_clock_claim=?
       )
       WHERE user_id=? AND path=? AND version=?
         AND EXISTS(
           SELECT 1 FROM workspaces
           WHERE user_id=? AND file_clock_claim=?
         )
         AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
       RETURNING path,content,version`,
    ).bind(
      input.content,
      input.authorization.userId,
      claim,
      input.authorization.userId,
      input.path,
      input.expectedVersion,
      input.authorization.userId,
      claim,
      ...gate,
    );
  const clear = input.database.prepare(
    `UPDATE workspaces SET file_clock_claim=NULL
     WHERE user_id=? AND file_clock_claim=?
     RETURNING file_clock`,
  ).bind(input.authorization.userId, claim);
  const results = await input.database.batch([allocation, mutation, clear]);
  const allocated = allocationRowSchema.safeParse(results[0]?.results[0]);
  const stored = fileSchema.safeParse(results[1]?.results[0]);
  const cleared = z.object({file_clock:z.number().int().nonnegative().max(maximumFileVersion)}).safeParse(results[2]?.results[0]);
  if (!allocated.success) {
    if (stored.success || cleared.success || (results[1]?.meta.changes ?? 0) !== 0 || (results[2]?.meta.changes ?? 0) !== 0) {
      throw new FileVersionD1IntegrityError();
    }
    return {kind:'not-applied'};
  }
  if (
    allocated.data.file_clock_claim !== claim
    || !stored.success
    || stored.data.version !== allocated.data.file_clock
    || !cleared.success
    || cleared.data.file_clock !== allocated.data.file_clock
    || (results[0]?.meta.changes ?? 0) !== 1
    || (results[1]?.meta.changes ?? 0) !== 1
    || (results[2]?.meta.changes ?? 0) !== 1
  ) {
    throw new FileVersionD1IntegrityError();
  }
  return {kind:'applied',file:stored.data};
}
