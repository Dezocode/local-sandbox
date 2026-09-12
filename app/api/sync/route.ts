import { z } from 'zod';
import { boundary,database,HttpError,initialize,syncIdentity,syncInput } from '@/lib/server';
import { APPLE_OWNER_OPERATION_ALLOWED_SQL,appleOwnerOperationGateBindings } from '@/lib/apple-auth-owner-d1';
import { encryptedWorkspaceRecordSchema,workspaceRecoverySchema } from '@/lib/workspace-crypto';
import {
  enrollSyncWorkspaceWithFreshIncarnation,
  insertEncryptedSyncRecordIfWorkspaceCurrent,
  maximumSyncEpochsPerOwner,
  maximumSyncEpochsPerWorkspace,
  readAuthorizedSyncEnrollmentSnapshot,
  readAuthorizedSyncFence,
  readAuthorizedSyncWorkspaceList,
  readAuthorizedSyncWorkspaceSnapshot,
  SyncD1IntegrityError,
  updateEncryptedSyncRecordIfWorkspaceCurrent,
  type AuthorizedSyncFenceResult,
  type AuthorizedSyncWorkspaceSnapshot,
  type SyncWorkspaceAuthority,
} from '@/lib/workspace-sync-d1';

const workspaceID=z.string().length(32).regex(/^[A-Za-z0-9_-]+$/);
const epoch=z.string().min(16).max(64).regex(/^[A-Za-z0-9_-]+$/);
const recordID=z.string().length(43).regex(/^[A-Za-z0-9_-]+$/);
const snapshotRevision=z.string().regex(/^(0|[1-9]\d*)$/).transform(Number).pipe(z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER));
const pageSize=4;
const command=z.discriminatedUnion('kind',[
  z.object({kind:z.literal('enroll'),workspaceId:workspaceID,epoch,recovery:workspaceRecoverySchema}).strict(),
  z.object({kind:z.literal('replaceRecovery'),workspaceId:workspaceID,expectedEpoch:epoch,expectedRevision:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),recovery:workspaceRecoverySchema}).strict(),
  z.object({kind:z.literal('deleteWorkspace'),workspaceId:workspaceID,expectedEpoch:epoch,expectedRevision:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)}).strict(),
  z.object({kind:z.literal('write'),workspaceId:workspaceID,expectedRevision:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).nullable(),envelope:encryptedWorkspaceRecordSchema}).strict(),
]);
const workspaceSummaryRow=z.object({workspace_id:z.string(),epoch:z.string(),updated_at:z.string()}).strict();
const workspaceReplacementRow=z.object({epoch:z.string(),incarnation:z.string().length(64).regex(/^[0-9a-f]+$/),recovery:z.string(),revision:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)}).strict();
const recordRow=z.object({record_id:z.string(),revision:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),mutation_id:z.string(),envelope:z.string()}).strict();

type StoredWorkspace={
  epoch:string;
  incarnation:string;
  recovery:z.infer<typeof workspaceRecoverySchema>;
  encodedRecovery:string;
  revision:number;
};

function storageIntegrity():never{
  throw new HttpError(503,'Encrypted sync storage failed an integrity check.','SYNC_STORAGE_INTEGRITY');
}

function deletionInProgress():never{
  throw new HttpError(409,'This standalone Apple account is being deleted. Sign in again after deletion finishes to create a new workspace.','APPLE_ACCOUNT_DELETION_IN_PROGRESS');
}

function revisionExhausted():never{
  throw new HttpError(409,'This encrypted workspace exhausted its safe revision range. Export and re-enroll it with a fresh epoch before writing again.','SYNC_REVISION_EXHAUSTED');
}

function requireCurrentFence(result:AuthorizedSyncFenceResult):void{
  if(result==='unauthorized')deletionInProgress();
  if(result==='changed')throw new HttpError(409,'The encrypted workspace changed while the response was being prepared. Refresh and retry.','SYNC_SNAPSHOT_CHANGED');
}

async function syncStorageCall<T>(operation:()=>Promise<T>):Promise<T>{
  try{return await operation();}
  catch(error){if(error instanceof SyncD1IntegrityError)storageIntegrity();throw error;}
}

async function finalFence(input:Parameters<typeof readAuthorizedSyncFence>[0]){
  return syncStorageCall(()=>readAuthorizedSyncFence(input));
}

function parseStoredRecord(row:unknown,expected:{workspaceId:string;epoch:string}){
  const parsed=recordRow.safeParse(row);
  if(!parsed.success)storageIntegrity();
  let rawEnvelope:unknown;
  try{rawEnvelope=JSON.parse(parsed.data.envelope);}catch{storageIntegrity();}
  const envelope=encryptedWorkspaceRecordSchema.safeParse(rawEnvelope);
  const revisionMatches=envelope.success&&(parsed.data.revision===0?envelope.data.baseRevision===null:envelope.data.baseRevision===parsed.data.revision-1);
  if(!envelope.success||parsed.data.record_id!==envelope.data.recordId||parsed.data.mutation_id!==envelope.data.mutationId||envelope.data.workspaceId!==expected.workspaceId||envelope.data.epoch!==expected.epoch||!revisionMatches)storageIntegrity();
  return {stored:parsed.data,response:{revision:parsed.data.revision,envelope:envelope.data}};
}

function parseWorkspace(value:NonNullable<Extract<AuthorizedSyncWorkspaceSnapshot,{kind:'authorized'}>['workspace']>,id:string):StoredWorkspace{
  let rawRecovery:unknown;
  try{rawRecovery=JSON.parse(value.recovery);}catch{storageIntegrity();}
  const recovery=workspaceRecoverySchema.safeParse(rawRecovery);
  if(!recovery.success||recovery.data.workspaceId!==id||recovery.data.epoch!==value.epoch)storageIntegrity();
  return {epoch:value.epoch,incarnation:value.incarnation,recovery:recovery.data,encodedRecovery:value.recovery,revision:value.revision};
}

async function readWorkspace(db:D1Database,user:Parameters<typeof readAuthorizedSyncWorkspaceSnapshot>[0]['authorization'],operationTime:number,id:string):Promise<StoredWorkspace|null>{
  const snapshot=await syncStorageCall(()=>readAuthorizedSyncWorkspaceSnapshot({database:db,authorization:user,operationTime,workspaceId:id}));
  if(snapshot.kind==='unauthorized')deletionInProgress();
  return snapshot.workspace===null?null:parseWorkspace(snapshot.workspace,id);
}

async function requireWorkspace(db:D1Database,user:Parameters<typeof readAuthorizedSyncWorkspaceSnapshot>[0]['authorization'],operationTime:number,id:string):Promise<StoredWorkspace>{
  const workspace=await readWorkspace(db,user,operationTime,id);
  if(workspace===null)throw new HttpError(404,'This encrypted workspace is not enrolled for the signed-in account.','SYNC_WORKSPACE_NOT_FOUND');
  return workspace;
}

function authority(workspace:StoredWorkspace):SyncWorkspaceAuthority{
  return {epoch:workspace.epoch,incarnation:workspace.incarnation,revision:workspace.revision};
}

export async function GET(request:Request){return boundary(async()=>{
  const user=await syncIdentity(request);const url=new URL(request.url),db=database(),operationTime=Math.floor(Date.now()/1_000);
  const allowed=['workspaceId','recordId','cursor','snapshotRevision'];
  if([...url.searchParams.keys()].some(key=>!allowed.includes(key))||allowed.some(key=>url.searchParams.getAll(key).length>1))throw new HttpError(400,'Encrypted sync query parameters are invalid.','INVALID_QUERY');
  const rawWorkspace=url.searchParams.get('workspaceId');const requestedRecord=url.searchParams.get('recordId');const rawCursor=url.searchParams.get('cursor');const rawSnapshotRevision=url.searchParams.get('snapshotRevision');
  if(rawWorkspace===null){
    if(requestedRecord!==null||rawCursor!==null||rawSnapshotRevision!==null)throw new HttpError(400,'Workspace reads require a workspaceId.','INVALID_QUERY');
    const listed=await syncStorageCall(()=>readAuthorizedSyncWorkspaceList({database:db,authorization:user,operationTime}));
    if(listed.kind==='unauthorized')deletionInProgress();
    if(listed.rows.length>20)throw new HttpError(409,'This account exceeds the bounded 20-workspace sync limit.','SYNC_WORKSPACE_LIMIT');
    const workspaces=listed.rows.map(value=>{const parsed=workspaceSummaryRow.safeParse(value);if(!parsed.success)storageIntegrity();return{workspaceId:parsed.data.workspace_id,epoch:parsed.data.epoch,updatedAt:parsed.data.updated_at};});
    return {workspaces};
  }
  const id=workspaceID.parse(rawWorkspace);
  const hasCursor=rawCursor!==null,hasSnapshotRevision=rawSnapshotRevision!==null;
  if(hasCursor!==hasSnapshotRevision||requestedRecord!==null&&(hasCursor||hasSnapshotRevision))throw new HttpError(400,'cursor and snapshotRevision must appear together and cannot be combined with recordId.','INVALID_QUERY');
  const workspace=await requireWorkspace(db,user,operationTime,id);
  if(requestedRecord!==null){
    const selected=recordID.parse(requestedRecord);
    const raw=await db.prepare('SELECT record_id,revision,mutation_id,envelope FROM sync_records WHERE user_id=? AND workspace_id=? AND record_id=?').bind(user.userId,id,selected).first();
    const parsed=raw===null?null:parseStoredRecord(raw,{workspaceId:id,epoch:workspace.epoch});
    const result=parsed===null?null:{workspaceId:id,epoch:workspace.epoch,record:parsed.response};
    const fence=await finalFence({
      database:db,authorization:user,operationTime,workspaceId:id,
      workspace:{kind:'present',...authority(workspace),recovery:workspace.encodedRecovery},
      record:parsed===null?{kind:'missing',recordId:selected}:{kind:'present',recordId:parsed.stored.record_id,revision:parsed.stored.revision,mutationId:parsed.stored.mutation_id,encodedEnvelope:parsed.stored.envelope},
    });
    requireCurrentFence(fence);
    if(result===null)throw new HttpError(404,'The encrypted record does not exist.','SYNC_RECORD_NOT_FOUND');
    return result;
  }
  const parsedCursor=rawCursor===null?null:recordID.safeParse(rawCursor);
  const parsedSnapshotRevision=rawSnapshotRevision===null?null:snapshotRevision.safeParse(rawSnapshotRevision);
  if(parsedCursor!==null&&!parsedCursor.success||parsedSnapshotRevision!==null&&!parsedSnapshotRevision.success)throw new HttpError(400,'Encrypted sync query parameters are invalid.','INVALID_QUERY');
  const cursor=parsedCursor?.data??null;
  const requestedSnapshotRevision=parsedSnapshotRevision?.data??null;
  if(requestedSnapshotRevision!==null&&requestedSnapshotRevision!==workspace.revision)throw new HttpError(409,'The encrypted workspace changed while it was being read. Restart from the first page.','SYNC_SNAPSHOT_CHANGED');
  const result=cursor===null
    ?await db.prepare('SELECT record_id,revision,mutation_id,envelope FROM sync_records WHERE user_id=? AND workspace_id=? ORDER BY record_id LIMIT 5').bind(user.userId,id).all()
    :await db.prepare('SELECT record_id,revision,mutation_id,envelope FROM sync_records WHERE user_id=? AND workspace_id=? AND record_id>? ORDER BY record_id LIMIT 5').bind(user.userId,id,cursor).all();
  const parsedRecords=result.results.map(row=>parseStoredRecord(row,{workspaceId:id,epoch:workspace.epoch}).response);
  const records=parsedRecords.slice(0,pageSize);
  const nextCursor=parsedRecords.length>pageSize?records.at(-1)?.envelope.recordId??null:null;
  const response={workspaceId:id,epoch:workspace.epoch,recovery:workspace.recovery,snapshotRevision:workspace.revision,records,nextCursor};
  const fence=await finalFence({database:db,authorization:user,operationTime,workspaceId:id,workspace:{kind:'present',...authority(workspace),recovery:workspace.encodedRecovery}});
  requireCurrentFence(fence);
  return response;
});}

export async function POST(request:Request){return boundary(async()=>{
  const user=await syncIdentity(request);const value=await syncInput(request,command,user);const db=database(),operationTime=Math.floor(Date.now()/1_000),gate=appleOwnerOperationGateBindings(user,operationTime);
  if(value.kind==='enroll'){
    if(value.recovery.workspaceId!==value.workspaceId||value.recovery.epoch!==value.epoch)throw new HttpError(400,'Recovery identity does not match the workspace enrollment.','SYNC_RECOVERY_IDENTITY_MISMATCH');
    await initialize(user);
    const encoded=JSON.stringify(value.recovery),now=new Date().toISOString();
    const enrolled=await syncStorageCall(()=>enrollSyncWorkspaceWithFreshIncarnation({database:db,authorization:user,operationTime,workspaceId:value.workspaceId,epoch:value.epoch,encodedRecovery:encoded,timestamp:now}));
    if(enrolled.kind==='applied'){
      if(enrolled.workspace.epoch!==value.epoch||enrolled.workspace.recovery!==encoded||enrolled.workspace.revision!==0)storageIntegrity();
      const fence=await finalFence({database:db,authorization:user,operationTime,workspaceId:value.workspaceId,workspace:{kind:'present',epoch:value.epoch,incarnation:enrolled.workspace.incarnation,revision:0,recovery:encoded}});
      requireCurrentFence(fence);
      return {workspaceId:value.workspaceId,epoch:value.epoch,recovery:value.recovery,created:true};
    }
    const snapshot=await syncStorageCall(()=>readAuthorizedSyncEnrollmentSnapshot({database:db,authorization:user,operationTime,workspaceId:value.workspaceId,epoch:value.epoch}));
    if(snapshot.kind==='unauthorized')deletionInProgress();
    if(snapshot.workspace!==null){
      const current=parseWorkspace(snapshot.workspace,value.workspaceId);
      if(current.epoch===value.epoch&&current.encodedRecovery===encoded)return {workspaceId:value.workspaceId,epoch:value.epoch,recovery:value.recovery,created:false};
      throw new HttpError(409,'This workspace already has a different key epoch or recovery envelope. Recover it before attempting rotation.','SYNC_ENROLLMENT_CONFLICT',{workspaceId:value.workspaceId,epoch:current.epoch});
    }
    if(snapshot.epochSeen)throw new HttpError(409,'This workspace key epoch was already used by an earlier enrollment. Generate a fresh encrypted workspace epoch.','SYNC_EPOCH_REUSED');
    if(snapshot.workspaceEpochCount>=maximumSyncEpochsPerWorkspace||snapshot.ownerEpochCount>=maximumSyncEpochsPerOwner)throw new HttpError(409,'This account exhausted its bounded encrypted-workspace enrollment history. Export the workspace and contact support before enrolling again.','SYNC_ENROLLMENT_HISTORY_EXHAUSTED');
    if(snapshot.activeWorkspaceCount>=20)throw new HttpError(409,'This account has reached the bounded 20-workspace sync limit.','SYNC_WORKSPACE_LIMIT');
    throw new HttpError(409,'The encrypted workspace enrollment changed before it completed. Refresh before retrying.','SYNC_ENROLLMENT_CONFLICT');
  }
  if(value.kind==='replaceRecovery'){
    if(value.recovery.workspaceId!==value.workspaceId||value.recovery.epoch!==value.expectedEpoch)throw new HttpError(400,'Recovery identity does not match the workspace rotation.','SYNC_RECOVERY_IDENTITY_MISMATCH');
    const workspace=await requireWorkspace(db,user,operationTime,value.workspaceId);
    const encoded=JSON.stringify(value.recovery),now=new Date().toISOString();
    const rawReplaced=await db.prepare(`UPDATE sync_workspaces SET recovery=?,revision=revision+1,updated_at=?
      WHERE user_id=? AND workspace_id=? AND epoch=? AND incarnation=? AND revision=? AND revision<? AND recovery<>?
        AND EXISTS(
          SELECT 1 FROM sync_workspace_epochs AS history
          WHERE history.user_id=sync_workspaces.user_id
            AND history.workspace_id=sync_workspaces.workspace_id
            AND history.epoch=sync_workspaces.epoch
            AND history.incarnation=sync_workspaces.incarnation
        )
        AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
      RETURNING epoch,incarnation,recovery,revision`).bind(encoded,now,user.userId,value.workspaceId,value.expectedEpoch,workspace.incarnation,value.expectedRevision,Number.MAX_SAFE_INTEGER,encoded,...gate).first();
    const replaced=rawReplaced===null?null:workspaceReplacementRow.safeParse(rawReplaced);
    if(replaced!==null&&!replaced.success)storageIntegrity();
    if(replaced!==null){
      let rawRecovery:unknown;try{rawRecovery=JSON.parse(replaced.data.recovery);}catch{storageIntegrity();}const recovery=workspaceRecoverySchema.safeParse(rawRecovery);
      if(!recovery.success||replaced.data.epoch!==value.expectedEpoch||replaced.data.incarnation!==workspace.incarnation||JSON.stringify(recovery.data)!==encoded)storageIntegrity();
      const response={workspaceId:value.workspaceId,epoch:replaced.data.epoch,recovery:recovery.data,snapshotRevision:replaced.data.revision,idempotent:false};
      const fence=await finalFence({database:db,authorization:user,operationTime,workspaceId:value.workspaceId,workspace:{kind:'present',epoch:replaced.data.epoch,incarnation:replaced.data.incarnation,revision:replaced.data.revision,recovery:replaced.data.recovery}});
      requireCurrentFence(fence);
      return response;
    }
    const current=await requireWorkspace(db,user,operationTime,value.workspaceId);
    if(current.epoch===value.expectedEpoch&&current.encodedRecovery===encoded)return {workspaceId:value.workspaceId,epoch:current.epoch,recovery:current.recovery,snapshotRevision:current.revision,idempotent:true};
    if(current.epoch!==value.expectedEpoch||current.incarnation!==workspace.incarnation)throw new HttpError(409,'This device uses a different workspace key epoch. Re-enroll before rotating recovery.','SYNC_KEY_EPOCH_CONFLICT',{epoch:current.epoch});
    if(current.revision===Number.MAX_SAFE_INTEGER&&value.expectedRevision===Number.MAX_SAFE_INTEGER)revisionExhausted();
    throw new HttpError(409,'The encrypted workspace changed before recovery rotation. Pull and authenticate it again.','SYNC_RECOVERY_ROTATION_CONFLICT',{snapshotRevision:current.revision});
  }
  if(value.kind==='deleteWorkspace'){
    const staged=await readWorkspace(db,user,operationTime,value.workspaceId);
    if(staged===null)return {workspaceId:value.workspaceId,deleted:true,idempotent:true};
    if(staged.epoch!==value.expectedEpoch)throw new HttpError(409,'This device uses a different workspace key epoch. Re-enroll before deletion.','SYNC_KEY_EPOCH_CONFLICT',{epoch:staged.epoch});
    if(staged.revision!==value.expectedRevision)throw new HttpError(409,'The encrypted workspace changed before deletion. Pull and authenticate it again.','SYNC_WORKSPACE_DELETE_CONFLICT',{snapshotRevision:staged.revision});
    const workspaceGate=`EXISTS(
      SELECT 1 FROM sync_workspaces AS workspace
      WHERE workspace.user_id=? AND workspace.workspace_id=? AND workspace.epoch=? AND workspace.incarnation=? AND workspace.revision=?
        AND EXISTS(
          SELECT 1 FROM sync_workspace_epochs AS history
          WHERE history.user_id=workspace.user_id
            AND history.workspace_id=workspace.workspace_id
            AND history.epoch=workspace.epoch
            AND history.incarnation=workspace.incarnation
        )
        AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
    )`;
    const results=await db.batch([
      db.prepare(`DELETE FROM sync_records WHERE user_id=? AND workspace_id=? AND ${workspaceGate}`).bind(user.userId,value.workspaceId,user.userId,value.workspaceId,staged.epoch,staged.incarnation,staged.revision,...gate),
      db.prepare(`DELETE FROM sync_workspaces
        WHERE user_id=? AND workspace_id=? AND epoch=? AND incarnation=? AND revision=?
          AND EXISTS(
            SELECT 1 FROM sync_workspace_epochs AS history
            WHERE history.user_id=sync_workspaces.user_id
              AND history.workspace_id=sync_workspaces.workspace_id
              AND history.epoch=sync_workspaces.epoch
              AND history.incarnation=sync_workspaces.incarnation
          )
          AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(user.userId,value.workspaceId,staged.epoch,staged.incarnation,staged.revision,...gate),
    ]);
    const deleted=(results[1]?.meta.changes??0)===1;
    const fence=await finalFence({database:db,authorization:user,operationTime,workspaceId:value.workspaceId,workspace:{kind:'missing',requireRecordsAbsent:true}});
    if(fence==='current')return {workspaceId:value.workspaceId,deleted:true,idempotent:!deleted};
    if(fence==='unauthorized')deletionInProgress();
    const current=await readWorkspace(db,user,operationTime,value.workspaceId);
    if(current===null)storageIntegrity();
    if(current.epoch!==value.expectedEpoch||current.incarnation!==staged.incarnation)throw new HttpError(409,'This device uses a different workspace key epoch. Re-enroll before deletion.','SYNC_KEY_EPOCH_CONFLICT',{epoch:current.epoch});
    throw new HttpError(409,'The encrypted workspace changed before deletion. Pull and authenticate it again.','SYNC_WORKSPACE_DELETE_CONFLICT',{snapshotRevision:current.revision});
  }
  const envelope=value.envelope;
  if(envelope.workspaceId!==value.workspaceId||envelope.baseRevision!==value.expectedRevision)throw new HttpError(400,'Encrypted write metadata does not match its compare-and-swap request.','SYNC_WRITE_METADATA_MISMATCH');
  const workspace=await requireWorkspace(db,user,operationTime,value.workspaceId);
  if(envelope.epoch!==workspace.epoch)throw new HttpError(409,'This device uses a different workspace key epoch. Re-enroll before syncing.','SYNC_KEY_EPOCH_CONFLICT',{epoch:workspace.epoch});
  const encoded=JSON.stringify(envelope),now=new Date().toISOString();let raw:unknown;
  if(value.expectedRevision===null){
    raw=await insertEncryptedSyncRecordIfWorkspaceCurrent({database:db,authorization:user,operationTime,workspaceId:value.workspaceId,expectedEpoch:workspace.epoch,expectedIncarnation:workspace.incarnation,recordId:envelope.recordId,mutationId:envelope.mutationId,encodedEnvelope:encoded,updatedAt:now});
  }else{
    raw=await updateEncryptedSyncRecordIfWorkspaceCurrent({database:db,authorization:user,operationTime,workspaceId:value.workspaceId,expectedEpoch:workspace.epoch,expectedIncarnation:workspace.incarnation,recordId:envelope.recordId,expectedRevision:value.expectedRevision,mutationId:envelope.mutationId,encodedEnvelope:encoded,updatedAt:now});
  }
  if(raw!==null){
    const parsed=parseStoredRecord(raw,{workspaceId:value.workspaceId,epoch:workspace.epoch});
    const latest=await requireWorkspace(db,user,operationTime,value.workspaceId);
    if(latest.epoch!==workspace.epoch||latest.incarnation!==workspace.incarnation)throw new HttpError(409,'This device uses a different workspace key epoch. Re-enroll before syncing.','SYNC_KEY_EPOCH_CONFLICT',{epoch:latest.epoch});
    const fence=await finalFence({database:db,authorization:user,operationTime,workspaceId:value.workspaceId,workspace:{kind:'present',...authority(latest),recovery:latest.encodedRecovery},record:{kind:'present',recordId:parsed.stored.record_id,revision:parsed.stored.revision,mutationId:parsed.stored.mutation_id,encodedEnvelope:parsed.stored.envelope}});
    requireCurrentFence(fence);
    return {record:parsed.response,idempotent:false};
  }
  const currentWorkspace=await readWorkspace(db,user,operationTime,value.workspaceId);
  if(currentWorkspace===null||currentWorkspace.epoch!==workspace.epoch||currentWorkspace.incarnation!==workspace.incarnation)throw new HttpError(409,'This device uses a different workspace key epoch. Re-enroll before syncing.','SYNC_KEY_EPOCH_CONFLICT',currentWorkspace===null?undefined:{epoch:currentWorkspace.epoch});
  const currentRaw=await db.prepare('SELECT record_id,revision,mutation_id,envelope FROM sync_records WHERE user_id=? AND workspace_id=? AND record_id=?').bind(user.userId,value.workspaceId,envelope.recordId).first();
  const current=currentRaw===null?null:parseStoredRecord(currentRaw,{workspaceId:value.workspaceId,epoch:currentWorkspace.epoch});
  const fence=await finalFence({database:db,authorization:user,operationTime,workspaceId:value.workspaceId,workspace:{kind:'present',...authority(currentWorkspace),recovery:currentWorkspace.encodedRecovery},record:current===null?{kind:'missing',recordId:envelope.recordId}:{kind:'present',recordId:current.stored.record_id,revision:current.stored.revision,mutationId:current.stored.mutation_id,encodedEnvelope:current.stored.envelope}});
  requireCurrentFence(fence);
  if(current===null){if(currentWorkspace.revision===Number.MAX_SAFE_INTEGER)revisionExhausted();throw new HttpError(409,'The encrypted record was not created. The workspace may have reached its record limit.','SYNC_CREATE_CONFLICT');}
  if(current.stored.mutation_id===envelope.mutationId){
    if(current.stored.envelope!==encoded)throw new HttpError(409,'A mutation identifier was reused with different ciphertext. Generate a new mutation.','SYNC_MUTATION_ID_REUSED');
    return {record:current.response,idempotent:true};
  }
  if(currentWorkspace.revision===Number.MAX_SAFE_INTEGER||(current.stored.revision===Number.MAX_SAFE_INTEGER&&value.expectedRevision===Number.MAX_SAFE_INTEGER))revisionExhausted();
  throw new HttpError(409,'The encrypted record changed on another device. Decrypt and compare both versions before retrying.','SYNC_VERSION_CONFLICT',{record:current.response});
});}
