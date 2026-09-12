import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile,readdir } from 'node:fs/promises';
import test from 'node:test';
import {
  EncryptedSyncConflict,
  EncryptedWorkspaceSyncClient,
  assembleSyncWorkspaceSnapshot,
  type EncryptedSyncRepository,
  type StoredEncryptedRecord,
  type SyncWorkspacePage,
  type SyncWorkspacePageRequest,
  type SyncWorkspaceSnapshot,
  isDefaultSyncPath,
} from '../lib/workspace-sync-client.ts';
import { encryptedWorkspaceRecordSchema, workspaceRecoverySchema, type EncryptedWorkspaceRecord, type WorkspaceRecovery } from '../lib/workspace-crypto.ts';
import { isAppleOwnerOperationAllowed } from '../lib/apple-auth-owner-d1.ts';
import {
  enrollSyncWorkspaceWithFreshIncarnation,
  insertEncryptedSyncRecordIfWorkspaceCurrent,
  maximumSyncEpochsPerOwner,
  maximumSyncEpochsPerWorkspace,
  readAuthorizedSyncEnrollmentSnapshot,
  readAuthorizedSyncFence,
  readAuthorizedSyncWorkspaceList,
  readAuthorizedSyncWorkspaceSnapshot,
  readSyncWorkspaceAuthority,
  SyncD1IntegrityError,
  syncWorkspaceAuthorityMatches,
  updateEncryptedSyncRecordIfWorkspaceCurrent,
} from '../lib/workspace-sync-d1.ts';

const passphrase='correct horse battery staple';
const firstDevice='device_0123456789abcdef';
const secondDevice='device_fedcba9876543210';

function noncanonicalFinalSextet(value:string):string{
  const replacement=new Map([['A','B'],['Q','R'],['g','h'],['w','x']]).get(value.at(-1)??'');
  assert.ok(replacement,'fixture does not end in a two-byte base64url canonical sextet');
  return value.slice(0,-1)+replacement;
}

class MemoryRepository implements EncryptedSyncRepository {
  workspace:SyncWorkspaceSnapshot|null=null;
  records=new Map<string,StoredEncryptedRecord>();
  writeCalls=0;
  replacementCalls=0;

  async enroll(input:{workspaceId:string;epoch:string;recovery:WorkspaceRecovery}){
    if(this.workspace)throw Error('already enrolled');
    this.workspace={...input,snapshotRevision:0,records:[]};
  }
  async replaceRecovery(input:{workspaceId:string;expectedEpoch:string;expectedRevision:number;recovery:WorkspaceRecovery}){
    this.replacementCalls+=1;
    if(!this.workspace||input.workspaceId!==this.workspace.workspaceId)throw Error('missing workspace');
    if(input.expectedEpoch!==this.workspace.epoch||input.expectedRevision!==this.workspace.snapshotRevision)throw Error('recovery rotation conflict');
    this.workspace={...this.workspace,recovery:input.recovery,snapshotRevision:this.workspace.snapshotRevision+1};
    return {workspaceId:this.workspace.workspaceId,epoch:this.workspace.epoch,recovery:this.workspace.recovery,snapshotRevision:this.workspace.snapshotRevision,idempotent:false};
  }
  async deleteWorkspace(input:{workspaceId:string;expectedEpoch:string;expectedRevision:number}){
    if(!this.workspace||input.workspaceId!==this.workspace.workspaceId)throw Error('missing workspace');
    if(input.expectedEpoch!==this.workspace.epoch||input.expectedRevision!==this.workspace.snapshotRevision)throw Error('workspace deletion conflict');
    this.workspace=null;this.records.clear();
  }
  async readWorkspace(workspaceId:string){
    if(!this.workspace||workspaceId!==this.workspace.workspaceId)throw Error('missing workspace');
    return {...this.workspace,records:[...this.records.values()]};
  }
  async readRecord(workspaceId:string,recordId:string){
    if(!this.workspace||workspaceId!==this.workspace.workspaceId)throw Error('missing workspace');
    return this.records.get(recordId)??null;
  }
  async write(input:{workspaceId:string;expectedRevision:number|null;envelope:EncryptedWorkspaceRecord}){
    this.writeCalls+=1;
    if(!this.workspace||input.workspaceId!==this.workspace.workspaceId)throw Error('missing workspace');
    const current=this.records.get(input.envelope.recordId)??null;
    if((current?.revision??null)!==input.expectedRevision){if(!current)throw Error('create conflict');throw new EncryptedSyncConflict(current);}
    const record={revision:input.expectedRevision===null?0:input.expectedRevision+1,envelope:input.envelope};
    this.records.set(input.envelope.recordId,record);
    this.workspace={...this.workspace,snapshotRevision:this.workspace.snapshotRevision+1};
    return record;
  }
}

test('encrypted sync creates, restores, pushes, and independently pulls only authenticated plaintext',async()=>{
  const repository=new MemoryRepository();
  const created=await EncryptedWorkspaceSyncClient.create(passphrase,repository,firstDevice);
  const saved=await created.client.push({path:'workspace/notes.md',content:'private αβ',generation:1});
  assert.equal(saved.kind,'saved');
  const serialized=JSON.stringify([...repository.records.values()]);
  assert.equal(serialized.includes('workspace/notes.md'),false);
  assert.equal(serialized.includes('private αβ'),false);

  const restored=await EncryptedWorkspaceSyncClient.restore(created.recovery,passphrase,repository,secondDevice);
  assert.deepEqual((await restored.pull()).map(item=>item.value.content),['private αβ']);
  await assert.rejects(()=>EncryptedWorkspaceSyncClient.restore(created.recovery,'this is the wrong password',repository,secondDevice),/wrong or the recovery envelope is damaged/);
});

test('device B cannot silently overwrite device A after both reviewed the same base',async()=>{
  const repository=new MemoryRepository();
  const deviceA=await EncryptedWorkspaceSyncClient.create(passphrase,repository,firstDevice);
  const deviceB=await EncryptedWorkspaceSyncClient.restore(deviceA.recovery,passphrase,repository,secondDevice);
  await deviceA.client.push({path:'workspace/shared.txt',content:'base',generation:0});
  assert.equal((await deviceB.pull())[0]?.value.content,'base');
  const recordId=[...repository.records.keys()][0];
  assert.ok(recordId);
  await deviceA.client.push({path:'workspace/shared.txt',content:'device A change',generation:1});
  const remoteWinner=structuredClone(repository.records.get(recordId));
  const writesBeforeStalePush=repository.writeCalls;
  const conflict=await deviceB.push({path:'workspace/shared.txt',content:'device B change',generation:2});
  assert.equal(conflict.kind,'conflict');
  if(conflict.kind!=='conflict')throw Error('expected conflict');
  assert.equal(conflict.remote.content,'device A change');
  assert.equal(repository.writeCalls,writesBeforeStalePush);
  assert.deepEqual(repository.records.get(recordId),remoteWinner);
  const kept=await deviceB.keepMine(conflict);
  assert.equal(kept.record.revision,2);
  assert.equal((await deviceA.client.pull())[0]?.value.content,'device B change');
});

test('recovery rotation preserves encrypted records and workspace deletion is snapshot-bound',async()=>{
  const repository=new MemoryRepository();
  const created=await EncryptedWorkspaceSyncClient.create(passphrase,repository,firstDevice);
  await created.client.push({path:'workspace/lifecycle.txt',content:'keep local; rotate remote recovery',generation:4});
  const originalRecord=structuredClone([...repository.records.values()][0]);
  const rotated=await created.client.rotateRecovery(passphrase,'replacement recovery passphrase');
  assert.equal(rotated.client.workspaceId,created.client.workspaceId);
  assert.equal(rotated.client.epoch,created.client.epoch);
  assert.deepEqual([...repository.records.values()][0],originalRecord);
  await assert.rejects(()=>EncryptedWorkspaceSyncClient.restore(rotated.recovery,passphrase,repository,secondDevice),/wrong or the recovery envelope is damaged/);
  const restored=await EncryptedWorkspaceSyncClient.restore(rotated.recovery,'replacement recovery passphrase',repository,secondDevice);
  assert.equal((await restored.pull())[0]?.value.content,'keep local; rotate remote recovery');
  await restored.deleteWorkspace();
  assert.equal(repository.workspace,null);
  assert.equal(repository.records.size,0);
});

test('D1 first-record creation survives distinct writers but never outlives workspace deletion',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    const migrationNames=(await readdir(new URL('../drizzle/',import.meta.url))).filter(name=>name.endsWith('.sql')).sort();
    for(const name of migrationNames){
      const migration=await readFile(new URL(`../drizzle/${name}`,import.meta.url),'utf8');
      for(const statement of migration.split('--> statement-breakpoint').map(value=>value.trim()).filter(Boolean))await database.prepare(statement).run();
    }
    const userId='sync-race-owner',workspaceId='D'.repeat(32),epoch='E'.repeat(24),incarnation='1'.repeat(64),now=1_800_000_000,updatedAt='2027-01-15T08:00:00.000Z';
    await database.prepare("INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,'{}','[]',0)").bind(userId).run();
    const seedWorkspace=async(input:{workspaceId:string;epoch:string;incarnation:string;revision?:number})=>{
      const revision=input.revision??0;
      await database.batch([
        database.prepare('INSERT INTO sync_workspace_epochs(user_id,workspace_id,epoch,incarnation,enrolled_at) VALUES(?,?,?,?,?)').bind(userId,input.workspaceId,input.epoch,input.incarnation,updatedAt),
        database.prepare('INSERT INTO sync_workspaces(user_id,workspace_id,epoch,incarnation,recovery,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)').bind(userId,input.workspaceId,input.epoch,input.incarnation,'{}',revision,updatedAt,updatedAt),
      ]);
    };
    await seedWorkspace({workspaceId,epoch,incarnation});
    const activeSnapshot=await readAuthorizedSyncWorkspaceSnapshot({
      database,
      authorization:{userId,authorizationStartedAt:now,appleSubjectHash:null},
      operationTime:now,
      workspaceId,
    });
    assert.deepEqual(activeSnapshot,{
      kind:'authorized',
      workspace:{epoch,incarnation,recovery:'{}',revision:0},
    },'a valid active workspace excludes integrity-only columns from its strict stored shape');
    const captured=await database.prepare('SELECT epoch,incarnation,revision FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(userId,workspaceId).first() as {epoch:string;incarnation:string;revision:number}|null;
    assert.deepEqual(captured,{epoch,incarnation,revision:0});assert.ok(captured);
    await database.batch([
      database.prepare('DELETE FROM sync_records WHERE user_id=? AND workspace_id=?').bind(userId,workspaceId),
      database.prepare('DELETE FROM sync_workspaces WHERE user_id=? AND workspace_id=? AND epoch=? AND revision=?').bind(userId,workspaceId,captured.epoch,captured.revision),
    ]);
    const delayed=await insertEncryptedSyncRecordIfWorkspaceCurrent({
      database,
      authorization:{userId,authorizationStartedAt:now,appleSubjectHash:null},
      operationTime:now,
      workspaceId,
      expectedEpoch:captured.epoch,
      expectedIncarnation:captured.incarnation,
      recordId:'R'.repeat(43),
      mutationId:'delayed-first-record',
      encodedEnvelope:'{}',
      updatedAt,
    });
    assert.equal(delayed,null);
    assert.deepEqual(await database.prepare('SELECT COUNT(*) AS count FROM sync_records WHERE user_id=? AND workspace_id=?').bind(userId,workspaceId).first(),{count:0});

    const concurrentWorkspaceId='C'.repeat(32);
    await seedWorkspace({workspaceId:concurrentWorkspaceId,epoch,incarnation});
    const sharedCreate={database,authorization:{userId,authorizationStartedAt:now,appleSubjectHash:null},operationTime:now,workspaceId:concurrentWorkspaceId,expectedEpoch:epoch,expectedIncarnation:incarnation,encodedEnvelope:'{}',updatedAt};
    const [firstCreate,secondCreate]=await Promise.all([
      insertEncryptedSyncRecordIfWorkspaceCurrent({...sharedCreate,recordId:'A'.repeat(43),mutationId:'first-concurrent-record'}),
      insertEncryptedSyncRecordIfWorkspaceCurrent({...sharedCreate,recordId:'B'.repeat(43),mutationId:'second-concurrent-record'}),
    ]);
    assert.notEqual(firstCreate,null);assert.notEqual(secondCreate,null);
    assert.deepEqual(await database.prepare('SELECT COUNT(*) AS count FROM sync_records WHERE user_id=? AND workspace_id=?').bind(userId,concurrentWorkspaceId).first(),{count:2});
    assert.deepEqual(await database.prepare('SELECT revision FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(userId,concurrentWorkspaceId).first(),{revision:2});

    const insertWinsWorkspaceId='I'.repeat(32);
    await seedWorkspace({workspaceId:insertWinsWorkspaceId,epoch,incarnation});
    const inserted=await insertEncryptedSyncRecordIfWorkspaceCurrent({...sharedCreate,workspaceId:insertWinsWorkspaceId,recordId:'W'.repeat(43),mutationId:'insert-wins-record'});
    assert.notEqual(inserted,null);
    const staleDeletion=await database.batch([
      database.prepare('DELETE FROM sync_records WHERE user_id=? AND workspace_id=? AND EXISTS(SELECT 1 FROM sync_workspaces WHERE user_id=? AND workspace_id=? AND epoch=? AND revision=?)').bind(userId,insertWinsWorkspaceId,userId,insertWinsWorkspaceId,epoch,0),
      database.prepare('DELETE FROM sync_workspaces WHERE user_id=? AND workspace_id=? AND epoch=? AND revision=?').bind(userId,insertWinsWorkspaceId,epoch,0),
    ]);
    assert.deepEqual([staleDeletion[0]?.meta.changes??0,staleDeletion[1]?.meta.changes??0],[0,0]);
    assert.deepEqual(await database.prepare('SELECT COUNT(*) AS count FROM sync_records WHERE user_id=? AND workspace_id=?').bind(userId,insertWinsWorkspaceId).first(),{count:1});
    assert.deepEqual(await database.prepare('SELECT revision FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(userId,insertWinsWorkspaceId).first(),{revision:1});

    const abaWorkspaceId='A'.repeat(32),firstEpoch='F'.repeat(24),firstIncarnation='2'.repeat(64),replacementEpoch='G'.repeat(24),replacementIncarnation='3'.repeat(64),abaRecordId='Z'.repeat(43);
    const firstEnvelope=JSON.stringify({workspaceId:abaWorkspaceId,epoch:firstEpoch,recordId:abaRecordId,mutationId:'first-epoch-mutation'});
    await seedWorkspace({workspaceId:abaWorkspaceId,epoch:firstEpoch,incarnation:firstIncarnation});
    await database.prepare('INSERT INTO sync_records(user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at) VALUES(?,?,?,?,?,?,?)').bind(userId,abaWorkspaceId,abaRecordId,0,'first-epoch-mutation',firstEnvelope,updatedAt).run();
    const stagedAuthority=await readSyncWorkspaceAuthority({database,userId,workspaceId:abaWorkspaceId});
    assert.deepEqual(stagedAuthority,{kind:'present',epoch:firstEpoch,incarnation:firstIncarnation,revision:1});
    if(stagedAuthority.kind!=='present')throw Error('expected first workspace authority');
    const stagedSingle=await database.prepare('SELECT record_id,revision,mutation_id,envelope FROM sync_records WHERE user_id=? AND workspace_id=? AND record_id=?').bind(userId,abaWorkspaceId,abaRecordId).first();
    const stagedPage=(await database.prepare('SELECT record_id,revision,mutation_id,envelope FROM sync_records WHERE user_id=? AND workspace_id=? ORDER BY record_id').bind(userId,abaWorkspaceId).all()).results;
    assert.equal(stagedPage.length,1);assert.notEqual(stagedSingle,null);
    const authorization={userId,authorizationStartedAt:now,appleSubjectHash:null};
    assert.equal(await isAppleOwnerOperationAllowed(database,authorization,now),true,'the former owner-only final gate resolves before the deterministic ABA pause');
    await database.batch([
      database.prepare('DELETE FROM sync_records WHERE user_id=? AND workspace_id=?').bind(userId,abaWorkspaceId),
      database.prepare('DELETE FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(userId,abaWorkspaceId),
    ]);
    await seedWorkspace({workspaceId:abaWorkspaceId,epoch:replacementEpoch,incarnation:replacementIncarnation});
    await database.prepare('INSERT INTO sync_records(user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at) VALUES(?,?,?,?,?,?,?)').bind(userId,abaWorkspaceId,abaRecordId,0,'replacement-epoch-mutation',JSON.stringify({workspaceId:abaWorkspaceId,epoch:replacementEpoch,recordId:abaRecordId,mutationId:'replacement-epoch-mutation'}),updatedAt).run();
    const replacementAuthority=await readSyncWorkspaceAuthority({database,userId,workspaceId:abaWorkspaceId});
    assert.deepEqual(replacementAuthority,{kind:'present',epoch:replacementEpoch,incarnation:replacementIncarnation,revision:1});
    assert.equal(syncWorkspaceAuthorityMatches(replacementAuthority,stagedAuthority),false,'a same-ID replacement at the same numeric revision must invalidate staged page and single-record reads');
    const stagedRecord=stagedSingle as {record_id:string;revision:number;mutation_id:string;envelope:string};
    const stagedRecordFence={kind:'present' as const,recordId:stagedRecord.record_id,revision:stagedRecord.revision,mutationId:stagedRecord.mutation_id,encodedEnvelope:stagedRecord.envelope};
    assert.equal(await readAuthorizedSyncFence({database,authorization,operationTime:now,workspaceId:abaWorkspaceId,workspace:stagedAuthority,record:stagedRecordFence}),'changed','single-record response cannot escape after E1 is replaced during the old final owner gate');
    assert.equal(await readAuthorizedSyncFence({database,authorization,operationTime:now,workspaceId:abaWorkspaceId,workspace:stagedAuthority}),'changed','page response cannot escape after E1 is replaced during the old final owner gate');
    assert.equal(await readAuthorizedSyncFence({database,authorization,operationTime:now,workspaceId:abaWorkspaceId,workspace:stagedAuthority,record:stagedRecordFence}),'changed','write and idempotency readback cannot escape after E1 is replaced during the old final owner gate');
    assert.equal(await readAuthorizedSyncFence({database,authorization,operationTime:now,workspaceId:abaWorkspaceId,workspace:{kind:'missing',requireRecordsAbsent:true}}),'changed','delete success cannot escape after E2 is enrolled during the old final owner gate');
    const delayedUpdate=await updateEncryptedSyncRecordIfWorkspaceCurrent({
      database,
      authorization:{userId,authorizationStartedAt:now,appleSubjectHash:null},
      operationTime:now,
      workspaceId:abaWorkspaceId,
      expectedEpoch:firstEpoch,
      expectedIncarnation:firstIncarnation,
      recordId:abaRecordId,
      expectedRevision:0,
      mutationId:'delayed-first-epoch-update',
      encodedEnvelope:JSON.stringify({workspaceId:abaWorkspaceId,epoch:firstEpoch,recordId:abaRecordId,mutationId:'delayed-first-epoch-update'}),
      updatedAt,
    });
    assert.equal(delayedUpdate,null);
    assert.deepEqual(await database.prepare('SELECT revision,mutation_id,envelope FROM sync_records WHERE user_id=? AND workspace_id=? AND record_id=?').bind(userId,abaWorkspaceId,abaRecordId).first(),{revision:0,mutation_id:'replacement-epoch-mutation',envelope:JSON.stringify({workspaceId:abaWorkspaceId,epoch:replacementEpoch,recordId:abaRecordId,mutationId:'replacement-epoch-mutation'})});

    const emptyWorkspaceId='B'.repeat(32),emptyEpoch='H'.repeat(24),emptyIncarnation='4'.repeat(64),emptyReplacementEpoch=emptyEpoch,emptyReplacementIncarnation='5'.repeat(64);
    await seedWorkspace({workspaceId:emptyWorkspaceId,epoch:emptyEpoch,incarnation:emptyIncarnation});
    const stagedEmptyAuthority=await readSyncWorkspaceAuthority({database,userId,workspaceId:emptyWorkspaceId});
    assert.deepEqual(stagedEmptyAuthority,{kind:'present',epoch:emptyEpoch,incarnation:emptyIncarnation,revision:0});
    if(stagedEmptyAuthority.kind!=='present')throw Error('expected empty workspace authority');
    assert.deepEqual((await database.prepare('SELECT record_id FROM sync_records WHERE user_id=? AND workspace_id=?').bind(userId,emptyWorkspaceId).all()).results,[]);
    assert.equal(await isAppleOwnerOperationAllowed(database,authorization,now),true,'empty-page response pauses after the former owner-only final gate');
    await database.batch([
      database.prepare('DELETE FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(userId,emptyWorkspaceId),
      database.prepare('INSERT INTO sync_workspaces(user_id,workspace_id,epoch,incarnation,recovery,revision,created_at,updated_at) VALUES(?,?,?,?,?,0,?,?)').bind(userId,emptyWorkspaceId,emptyReplacementEpoch,emptyReplacementIncarnation,'{}',updatedAt,updatedAt),
    ]);
    const emptyReplacementAuthority=await readSyncWorkspaceAuthority({database,userId,workspaceId:emptyWorkspaceId});
    assert.deepEqual(emptyReplacementAuthority,{kind:'invalid'},'an active workspace whose same epoch points at a different incarnation is corrupt');
    assert.equal(syncWorkspaceAuthorityMatches(emptyReplacementAuthority,stagedEmptyAuthority),false,'a malicious same-epoch replacement cannot match staged authority');
    await assert.rejects(
      ()=>readAuthorizedSyncFence({database,authorization,operationTime:now,workspaceId:emptyWorkspaceId,workspace:stagedEmptyAuthority}),
      SyncD1IntegrityError,
      'the final fence fails closed when an active workspace does not own its exact history tuple',
    );
    await assert.rejects(
      ()=>readAuthorizedSyncWorkspaceSnapshot({database,authorization,operationTime:now,workspaceId:emptyWorkspaceId}),
      SyncD1IntegrityError,
      'a mismatched active history tuple cannot reach idempotent enrollment or reads',
    );
    await assert.rejects(
      ()=>readAuthorizedSyncEnrollmentSnapshot({database,authorization,operationTime:now,workspaceId:emptyWorkspaceId,epoch:emptyEpoch}),
      SyncD1IntegrityError,
      'idempotent enrollment fails closed when active authority does not match durable history',
    );
    await assert.rejects(
      ()=>readAuthorizedSyncWorkspaceList({database,authorization,operationTime:now}),
      SyncD1IntegrityError,
      'workspace lists reject a mismatched active history tuple',
    );
    await database.prepare('DELETE FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(userId,emptyWorkspaceId).run();

    const missingHistoryWorkspaceId='N'.repeat(32),missingHistoryIncarnation='7'.repeat(64);
    await database.prepare('INSERT INTO sync_workspaces(user_id,workspace_id,epoch,incarnation,recovery,revision,created_at,updated_at) VALUES(?,?,?,?,?,0,?,?)').bind(userId,missingHistoryWorkspaceId,epoch,missingHistoryIncarnation,'{}',updatedAt,updatedAt).run();
    assert.deepEqual(await readSyncWorkspaceAuthority({database,userId,workspaceId:missingHistoryWorkspaceId}),{kind:'invalid'});
    await assert.rejects(
      ()=>readAuthorizedSyncWorkspaceSnapshot({database,authorization,operationTime:now,workspaceId:missingHistoryWorkspaceId}),
      SyncD1IntegrityError,
      'an active workspace with no history tuple fails closed',
    );
    await database.prepare('DELETE FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(userId,missingHistoryWorkspaceId).run();

    const orphanRecordWorkspaceId='J'.repeat(32);
    await database.prepare('INSERT INTO sync_records(user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at) VALUES(?,?,?,0,?,?,?)').bind(userId,orphanRecordWorkspaceId,'J'.repeat(43),'orphan-record','{}',updatedAt).run();
    await assert.rejects(
      ()=>readAuthorizedSyncWorkspaceSnapshot({database,authorization,operationTime:now,workspaceId:orphanRecordWorkspaceId}),
      SyncD1IntegrityError,
      'records cannot exist without an active workspace',
    );
    await assert.rejects(
      ()=>readAuthorizedSyncWorkspaceList({database,authorization,operationTime:now}),
      SyncD1IntegrityError,
      'workspace lists reject owner-wide records whose workspace is absent',
    );
    const orphanEnrollment=await enrollSyncWorkspaceWithFreshIncarnation({database,authorization,operationTime:now,workspaceId:orphanRecordWorkspaceId,epoch:'J'.repeat(24),encodedRecovery:'{}',timestamp:updatedAt});
    assert.deepEqual(orphanEnrollment,{kind:'not-applied'},'orphan records cannot be reattached to a new workspace incarnation');
    await database.prepare('DELETE FROM sync_records WHERE user_id=? AND workspace_id=?').bind(userId,orphanRecordWorkspaceId).run();

    const overLimitWorkspaceId='T'.repeat(32),overLimitIncarnation='8'.repeat(64);
    await seedWorkspace({workspaceId:overLimitWorkspaceId,epoch,incarnation:overLimitIncarnation});
    await database.prepare(`WITH RECURSIVE sequence(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM sequence WHERE value<1000)
      INSERT INTO sync_records(user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at)
      SELECT ?,?,printf('%043d',value),0,printf('over-limit-%d',value),'{}',? FROM sequence`).bind(userId,overLimitWorkspaceId,updatedAt).run();
    await assert.rejects(
      ()=>readAuthorizedSyncWorkspaceSnapshot({database,authorization,operationTime:now,workspaceId:overLimitWorkspaceId}),
      SyncD1IntegrityError,
      'active workspaces cannot exceed the 1000-record storage bound',
    );
    await database.prepare('DELETE FROM sync_records WHERE user_id=? AND workspace_id=?').bind(userId,overLimitWorkspaceId).run();
    await database.prepare('DELETE FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(userId,overLimitWorkspaceId).run();

    const historyOwner='sync-history-owner',historyAuthorization={userId:historyOwner,authorizationStartedAt:now,appleSubjectHash:null},historyWorkspaceId='K'.repeat(32),historyEpochA='L'.repeat(24),historyEpochB='M'.repeat(24);
    await database.prepare("INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,'{}','[]',0)").bind(historyOwner).run();
    const enrollmentA=await enrollSyncWorkspaceWithFreshIncarnation({database,authorization:historyAuthorization,operationTime:now,workspaceId:historyWorkspaceId,epoch:historyEpochA,encodedRecovery:'{}',timestamp:updatedAt});
    assert.equal(enrollmentA.kind,'applied');if(enrollmentA.kind!=='applied')throw Error('expected first history enrollment');assert.match(enrollmentA.workspace.incarnation,/^[0-9a-f]{64}$/);
    await database.prepare('DELETE FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(historyOwner,historyWorkspaceId).run();
    const immediateReuse=await enrollSyncWorkspaceWithFreshIncarnation({database,authorization:historyAuthorization,operationTime:now,workspaceId:historyWorkspaceId,epoch:historyEpochA,encodedRecovery:'{}',timestamp:updatedAt});
    assert.deepEqual(immediateReuse,{kind:'not-applied'});
    const enrollmentB=await enrollSyncWorkspaceWithFreshIncarnation({database,authorization:historyAuthorization,operationTime:now,workspaceId:historyWorkspaceId,epoch:historyEpochB,encodedRecovery:'{}',timestamp:updatedAt});
    assert.equal(enrollmentB.kind,'applied');if(enrollmentB.kind!=='applied')throw Error('expected second history enrollment');assert.notEqual(enrollmentB.workspace.incarnation,enrollmentA.workspace.incarnation);
    await database.prepare('DELETE FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(historyOwner,historyWorkspaceId).run();
    const cycledReuse=await enrollSyncWorkspaceWithFreshIncarnation({database,authorization:historyAuthorization,operationTime:now,workspaceId:historyWorkspaceId,epoch:historyEpochA,encodedRecovery:'{}',timestamp:updatedAt});
    assert.deepEqual(cycledReuse,{kind:'not-applied'},'durable history rejects A to B to A epoch reuse');
    const reusedSnapshot=await readAuthorizedSyncEnrollmentSnapshot({database,authorization:historyAuthorization,operationTime:now,workspaceId:historyWorkspaceId,epoch:historyEpochA});
    assert.equal(reusedSnapshot.kind,'authorized');if(reusedSnapshot.kind!=='authorized')throw Error('expected history snapshot');assert.equal(reusedSnapshot.epochSeen,true);assert.equal(reusedSnapshot.workspaceEpochCount,2);assert.equal(reusedSnapshot.workspace,null);

    const cappedWorkspaceOwner='sync-workspace-cap-owner',cappedWorkspaceAuthorization={userId:cappedWorkspaceOwner,authorizationStartedAt:now,appleSubjectHash:null},cappedWorkspaceId='P'.repeat(32);
    await database.prepare("INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,'{}','[]',0)").bind(cappedWorkspaceOwner).run();
    await database.prepare(`WITH RECURSIVE sequence(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM sequence WHERE value+1<?)
      INSERT INTO sync_workspace_epochs(user_id,workspace_id,epoch,incarnation,enrolled_at)
      SELECT ?,?,printf('%016x',value),printf('%064x',value+1),? FROM sequence`).bind(maximumSyncEpochsPerWorkspace,cappedWorkspaceOwner,cappedWorkspaceId,updatedAt).run();
    const cappedWorkspaceEnrollment=await enrollSyncWorkspaceWithFreshIncarnation({database,authorization:cappedWorkspaceAuthorization,operationTime:now,workspaceId:cappedWorkspaceId,epoch:'Q'.repeat(24),encodedRecovery:'{}',timestamp:updatedAt});
    assert.deepEqual(cappedWorkspaceEnrollment,{kind:'not-applied'});
    assert.deepEqual(await database.prepare('SELECT count(*) AS count FROM sync_workspace_epochs WHERE user_id=?').bind(cappedWorkspaceOwner).first(),{count:maximumSyncEpochsPerWorkspace});
    assert.equal(await database.prepare('SELECT 1 FROM sync_workspaces WHERE user_id=?').bind(cappedWorkspaceOwner).first(),null,'history exhaustion leaves no partial active workspace');

    const cappedOwner='sync-owner-cap-owner',cappedOwnerAuthorization={userId:cappedOwner,authorizationStartedAt:now,appleSubjectHash:null};
    await database.prepare("INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,'{}','[]',0)").bind(cappedOwner).run();
    await database.prepare(`WITH RECURSIVE sequence(value) AS (VALUES(0) UNION ALL SELECT value+1 FROM sequence WHERE value<63)
      INSERT INTO sync_workspace_epochs(user_id,workspace_id,epoch,incarnation,enrolled_at)
      SELECT ?,printf('%032x',left_side.value*64+right_side.value),printf('%016x',left_side.value*64+right_side.value),printf('%064x',left_side.value*64+right_side.value+1),?
      FROM sequence AS left_side CROSS JOIN sequence AS right_side`).bind(cappedOwner,updatedAt).run();
    assert.deepEqual(await database.prepare('SELECT count(*) AS count FROM sync_workspace_epochs WHERE user_id=?').bind(cappedOwner).first(),{count:maximumSyncEpochsPerOwner});
    const cappedOwnerEnrollment=await enrollSyncWorkspaceWithFreshIncarnation({database,authorization:cappedOwnerAuthorization,operationTime:now,workspaceId:'Y'.repeat(32),epoch:'Z'.repeat(24),encodedRecovery:'{}',timestamp:updatedAt});
    assert.deepEqual(cappedOwnerEnrollment,{kind:'not-applied'});
    assert.deepEqual(await database.prepare('SELECT count(*) AS count FROM sync_workspace_epochs WHERE user_id=?').bind(cappedOwner).first(),{count:maximumSyncEpochsPerOwner});
    assert.equal(await database.prepare('SELECT 1 FROM sync_workspaces WHERE user_id=?').bind(cappedOwner).first(),null,'owner history exhaustion leaves no partial active workspace');
    await database.prepare('DELETE FROM workspaces WHERE user_id=?').bind(cappedOwner).run();
    assert.deepEqual(await database.prepare('SELECT count(*) AS count FROM sync_workspace_epochs WHERE user_id=?').bind(cappedOwner).first(),{count:0},'owner workspace deletion cascades durable epoch history');

    const exhaustedWorkspaceId='X'.repeat(32),exhaustedIncarnation='6'.repeat(64);
    await seedWorkspace({workspaceId:exhaustedWorkspaceId,epoch,incarnation:exhaustedIncarnation,revision:Number.MAX_SAFE_INTEGER});
    const exhaustedWrite=await insertEncryptedSyncRecordIfWorkspaceCurrent({database,authorization,operationTime:now,workspaceId:exhaustedWorkspaceId,expectedEpoch:epoch,expectedIncarnation:exhaustedIncarnation,recordId:'X'.repeat(43),mutationId:'exhausted-write',encodedEnvelope:'{}',updatedAt});
    assert.equal(exhaustedWrite,null);assert.equal(await database.prepare('SELECT 1 FROM sync_records WHERE user_id=? AND workspace_id=?').bind(userId,exhaustedWorkspaceId).first(),null);
    await assert.rejects(()=>database.prepare('INSERT INTO sync_records(user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at) VALUES(?,?,?,0,?,?,?)').bind(userId,exhaustedWorkspaceId,'Y'.repeat(43),'unsafe-trigger','{}',updatedAt).run(),'database trigger and workspace check reject an unsafe revision increment atomically');
    assert.deepEqual(await database.prepare('SELECT revision FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(userId,exhaustedWorkspaceId).first(),{revision:Number.MAX_SAFE_INTEGER});
    await assert.rejects(()=>database.prepare('INSERT INTO sync_workspaces(user_id,workspace_id,epoch,recovery,revision,created_at,updated_at) VALUES(?,?,?,?,0,?,?)').bind(userId,'O'.repeat(32),epoch,'{}',updatedAt,updatedAt).run(),'canonical sync workspace schema has no default incarnation');
  }finally{await miniflare.dispose();}
});

test('D1 0013 backfills bounded sync incarnations and rejects unsafe legacy revisions',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const migrations=(await readdir(new URL('../drizzle/',import.meta.url))).filter(name=>name.endsWith('.sql')).sort();
  const apply=async(database:D1Database,names:string[])=>{for(const name of names){const source=await readFile(new URL(`../drizzle/${name}`,import.meta.url),'utf8');for(const statement of source.split('--> statement-breakpoint').map(value=>value.trim()).filter(Boolean))await database.prepare(statement).run();}};
  const legacy=migrations.filter(name=>name<'0013_');
  const upgrade=migrations.filter(name=>name.startsWith('0013_'));
  const migrated=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await migrated.getD1Database('DB');await apply(database,legacy);
    const owner='migration-sync-owner',workspaceId='U'.repeat(32),epoch='V'.repeat(24),createdAt='2027-01-15T08:00:00.000Z',recordId='W'.repeat(43);
    await database.prepare("INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,'{}','[]',0)").bind(owner).run();
    await database.prepare('INSERT INTO sync_workspaces(user_id,workspace_id,epoch,recovery,revision,created_at,updated_at) VALUES(?,?,?,?,0,?,?)').bind(owner,workspaceId,epoch,'{}',createdAt,createdAt).run();
    await database.prepare('INSERT INTO sync_records(user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at) VALUES(?,?,?,0,?,?,?)').bind(owner,workspaceId,recordId,'legacy-mutation','{}',createdAt).run();
    await apply(database,upgrade);
    assert.deepEqual(await database.prepare('SELECT epoch,incarnation,revision FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(owner,workspaceId).first(),{epoch,incarnation:'0'.repeat(64),revision:1});
    assert.deepEqual(await database.prepare('SELECT epoch,incarnation FROM sync_workspace_epochs WHERE user_id=? AND workspace_id=?').bind(owner,workspaceId).first(),{epoch,incarnation:'0'.repeat(64)});
    assert.deepEqual(await database.prepare('SELECT record_id,revision,mutation_id FROM sync_records WHERE user_id=? AND workspace_id=?').bind(owner,workspaceId).first(),{record_id:recordId,revision:0,mutation_id:'legacy-mutation'});
    const columns=(await database.prepare("PRAGMA table_info('sync_workspaces')").all()).results as {name:string;notnull:number;dflt_value:unknown}[];
    const incarnationColumn=columns.find(column=>column.name==='incarnation');assert.ok(incarnationColumn);assert.equal(incarnationColumn.notnull,1);assert.equal(incarnationColumn.dflt_value,null);
    const indexes=(await database.prepare("PRAGMA index_list('sync_workspace_epochs')").all()).results as {name:string}[];
    assert.ok(indexes.some(index=>index.name==='sync_workspace_epochs_incarnation_unique'));assert.ok(indexes.some(index=>index.name==='sync_workspace_epochs_owner_idx'));
    const foreignKeys=(await database.prepare("PRAGMA foreign_key_list('sync_workspace_epochs')").all()).results as {table:string;from:string;to:string;on_delete:string}[];
    assert.ok(foreignKeys.some(key=>key.table==='workspaces'&&key.from==='user_id'&&key.to==='user_id'&&key.on_delete.toLowerCase()==='cascade'));
    const triggerRows=(await database.prepare("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'sync_records_workspace_revision_after_%' ORDER BY name").all()).results as {name:string}[];const triggers=triggerRows.map(row=>row.name);
    assert.deepEqual(triggers,['sync_records_workspace_revision_after_insert','sync_records_workspace_revision_after_update']);
    await database.prepare('INSERT INTO sync_records(user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at) VALUES(?,?,?,0,?,?,?)').bind(owner,workspaceId,'X'.repeat(43),'post-migration-trigger','{}',createdAt).run();
    assert.deepEqual(await database.prepare('SELECT revision FROM sync_workspaces WHERE user_id=? AND workspace_id=?').bind(owner,workspaceId).first(),{revision:2});
    await assert.rejects(()=>database.prepare('INSERT INTO sync_workspaces(user_id,workspace_id,epoch,recovery,revision,created_at,updated_at) VALUES(?,?,?,?,0,?,?)').bind(owner,'Y'.repeat(32),epoch,'{}',createdAt,createdAt).run());
  }finally{await migrated.dispose();}

  const unsafe=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await unsafe.getD1Database('DB');await apply(database,legacy);
    const createdAt='2027-01-15T08:00:00.000Z';
    await database.prepare('INSERT INTO sync_workspaces(user_id,workspace_id,epoch,recovery,revision,created_at,updated_at) VALUES(?,?,?,?,?,?,?)').bind('unsafe-migration-owner','Z'.repeat(32),'Q'.repeat(24),'{}',Number.MAX_SAFE_INTEGER+1,createdAt,createdAt).run();
    await assert.rejects(()=>apply(database,upgrade),'0013 must fail rather than silently filter an unsafe legacy revision');
  }finally{await unsafe.dispose();}
});

test('recovery rotation authenticates every current record before replacing the recovery envelope',async()=>{
  const repository=new MemoryRepository();
  const created=await EncryptedWorkspaceSyncClient.create(passphrase,repository,firstDevice);
  const saved=await created.client.push({path:'workspace/tampered-before-rotation.txt',content:'must authenticate',generation:0});
  assert.equal(saved.kind,'saved');
  if(saved.kind!=='saved')throw Error('expected a saved record');
  const first=saved.record.envelope.data.at(0)??'A';
  repository.records.set(saved.record.envelope.recordId,{...saved.record,envelope:{...saved.record.envelope,data:(first==='A'?'B':'A')+saved.record.envelope.data.slice(1)}});
  const callsBefore=repository.replacementCalls;
  await assert.rejects(()=>created.client.rotateRecovery(passphrase,'replacement recovery passphrase'),/failed authentication/);
  assert.equal(repository.replacementCalls,callsBefore);
});

test('encrypted sync rejects excluded paths, epoch drift, noncanonical encoding, and tampered remote ciphertext',async()=>{
  const repository=new MemoryRepository();
  const created=await EncryptedWorkspaceSyncClient.create(passphrase,repository,firstDevice);
  await assert.rejects(()=>created.client.push({path:'config/private.json',content:'secret',generation:0}),/Only non-private workspace and output files/);
  for(const path of ['workspace/signing-key.p8','workspace/private-exports/token.txt','output/profile.json','workspace/credentials/account.txt','output/.env.production']){
    assert.equal(isDefaultSyncPath(path),false,path);
    await assert.rejects(()=>created.client.push({path,content:'must remain local',generation:0}),/Only non-private workspace and output files/);
  }
  assert.equal(isDefaultSyncPath('workspace/reports/profile-notes.md'),true);
  await created.client.push({path:'output/result.txt',content:'complete',generation:0});
  if(!repository.workspace)throw Error('missing fixture workspace');
  repository.workspace={...repository.workspace,epoch:'F'.repeat(24)};
  await assert.rejects(()=>created.client.pull(),/different encrypted workspace key epoch/);
  repository.workspace={...repository.workspace,epoch:created.client.epoch};
  const [recordId,record]=[...repository.records.entries()][0]??[];
  if(!recordId||!record)throw Error('missing fixture record');
  repository.records.set(recordId,{...record,envelope:{...record.envelope,data:noncanonicalFinalSextet(record.envelope.data)}});
  await assert.rejects(()=>created.client.pull(),/failed authentication/);
  const first=record.envelope.data[0]??'A';
  repository.records.set(recordId,{...record,envelope:{...record.envelope,data:(first==='A'?'B':'A')+record.envelope.data.slice(1)}});
  await assert.rejects(()=>created.client.pull(),/failed authentication/);
});

test('TypeScript snapshot assembly paginates five records and restarts once from page one',async()=>{
  const repository=new MemoryRepository();
  const created=await EncryptedWorkspaceSyncClient.create(passphrase,repository,firstDevice);
  for(let index=0;index<5;index+=1)await created.client.push({path:`workspace/page-${index}.txt`,content:`page ${index}`,generation:index});
  const records=[...repository.records.values()].sort((left,right)=>left.envelope.recordId<right.envelope.recordId?-1:left.envelope.recordId>right.envelope.recordId?1:0);
  const requests:SyncWorkspacePageRequest[]=[];
  const stablePage=(request:SyncWorkspacePageRequest,revision:number):SyncWorkspacePage=>{
    const pageRecords=request.kind==='initial'?records.slice(0,4):records.slice(4);
    return {workspaceId:created.client.workspaceId,epoch:created.client.epoch,recovery:created.recovery,snapshotRevision:revision,records:pageRecords,nextCursor:request.kind==='initial'?records[3]?.envelope.recordId??null:null};
  };
  const snapshot=await assembleSyncWorkspaceSnapshot({
    workspaceId:created.client.workspaceId,
    readPage:async request=>{requests.push(request);return stablePage(request,5);},
    isSnapshotChanged:()=>false,
  });
  assert.deepEqual(snapshot.records,records);
  assert.equal(snapshot.snapshotRevision,5);
  assert.deepEqual(requests,[{kind:'initial'},{kind:'continuation',cursor:records[3]?.envelope.recordId,snapshotRevision:5}]);

  class SnapshotChanged extends Error {}
  let call=0;
  const restarted=await assembleSyncWorkspaceSnapshot({
    workspaceId:created.client.workspaceId,
    readPage:async request=>{
      call+=1;requests.push(request);
      if(call===2)throw new SnapshotChanged();
      return stablePage(request,call<3?5:6);
    },
    isSnapshotChanged:error=>error instanceof SnapshotChanged,
  });
  assert.equal(restarted.snapshotRevision,6);
  assert.deepEqual(restarted.records,records);
  assert.deepEqual(requests.slice(-4).map(request=>request.kind),['initial','continuation','initial','continuation']);
});

test('TypeScript snapshot assembly surfaces a second mutation and rejects duplicate cursor state',async()=>{
  const repository=new MemoryRepository();
  const created=await EncryptedWorkspaceSyncClient.create(passphrase,repository,firstDevice);
  for(let index=0;index<4;index+=1)await created.client.push({path:`workspace/retry-${index}.txt`,content:`page ${index}`,generation:index});
  const records=[...repository.records.values()].sort((left,right)=>left.envelope.recordId<right.envelope.recordId?-1:left.envelope.recordId>right.envelope.recordId?1:0);
  class SnapshotChanged extends Error {}
  let calls=0;
  await assert.rejects(()=>assembleSyncWorkspaceSnapshot({
    workspaceId:created.client.workspaceId,
    readPage:async()=>{
      calls+=1;
      if(calls%2===0)throw new SnapshotChanged();
      return {workspaceId:created.client.workspaceId,epoch:created.client.epoch,recovery:created.recovery,snapshotRevision:calls,records,nextCursor:records.at(-1)?.envelope.recordId??null};
    },
    isSnapshotChanged:error=>error instanceof SnapshotChanged,
  }),SnapshotChanged);
  assert.equal(calls,4);
  const duplicate=records[0];
  if(!duplicate)throw Error('missing encrypted record fixture');
  await assert.rejects(()=>assembleSyncWorkspaceSnapshot({
    workspaceId:created.client.workspaceId,
    readPage:async()=>({workspaceId:created.client.workspaceId,epoch:created.client.epoch,recovery:created.recovery,snapshotRevision:4,records:[duplicate,duplicate],nextCursor:null}),
    isSnapshotChanged:()=>false,
  }),/out-of-order/);
});

test('encrypted workspace wire schemas enforce bounded ciphertext without reducing the 64 KB cleartext limit',async()=>{
  const repository=new MemoryRepository();
  const created=await EncryptedWorkspaceSyncClient.create(passphrase,repository,firstDevice);
  const maximum=await created.client.push({path:'workspace/maximum.txt',content:'\0'.repeat(64_000),generation:0});
  assert.equal(maximum.kind,'saved');
  if(maximum.kind!=='saved')throw Error('expected a saved record');
  assert.equal(maximum.record.envelope.version,2);
  assert.ok(maximum.record.envelope.data.length<=120_000);
  assert.equal(maximum.value.content,'\0'.repeat(64_000));
  for(let index=1;index<4;index+=1){
    const content=index%2===0?'\0'.repeat(64_000):'\\'.repeat(64_000);
    const saved=await created.client.push({path:`workspace/maximum-${index}-${'x'.repeat(140)}.txt`,content,generation:Number.MAX_SAFE_INTEGER});
    assert.equal(saved.kind,'saved');
  }
  if(!repository.workspace)throw Error('missing bounded workspace fixture');
  const actualMaximumPage={...repository.workspace,records:[...repository.records.values()],nextCursor:null};
  const actualMaximumPageBytes=new TextEncoder().encode(JSON.stringify(actualMaximumPage)).byteLength;
  assert.ok(actualMaximumPageBytes<512*1_024,`four real maximum records used ${actualMaximumPageBytes} bytes`);
  assert.ok(actualMaximumPageBytes>450_000,`maximum-record proof unexpectedly used only ${actualMaximumPageBytes} bytes`);
  assert.equal(encryptedWorkspaceRecordSchema.safeParse({...maximum.record.envelope,data:'A'.repeat(120_000)}).success,true);
  assert.equal(encryptedWorkspaceRecordSchema.safeParse({...maximum.record.envelope,data:'A'.repeat(120_001)}).success,false);
  assert.equal(encryptedWorkspaceRecordSchema.safeParse({...maximum.record.envelope,version:1,data:'A'.repeat(100_000)}).success,true);
  assert.equal(encryptedWorkspaceRecordSchema.safeParse({...maximum.record.envelope,version:1,data:'A'.repeat(100_001)}).success,false);
  assert.equal(encryptedWorkspaceRecordSchema.safeParse({...maximum.record.envelope,iv:'A'.repeat(17)}).success,false);
  assert.equal(workspaceRecoverySchema.safeParse({...created.recovery,cipher:{...created.recovery.cipher,data:'A'.repeat(4_096)}}).success,true);
  assert.equal(workspaceRecoverySchema.safeParse({...created.recovery,cipher:{...created.recovery.cipher,data:'A'.repeat(4_097)}}).success,false);
  assert.equal(workspaceRecoverySchema.safeParse({...created.recovery,kdf:{...created.recovery.kdf,salt:'A'.repeat(23)}}).success,false);
  await assert.rejects(()=>created.client.push({path:'workspace/too-large.txt',content:'x'.repeat(64_001),generation:0}),/64 KB/);
});
