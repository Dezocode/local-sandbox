import assert from'node:assert/strict';
import test from'node:test';
import{readFile}from'node:fs/promises';
import{createWorkspaceWithRecovery,openWorkspaceRecord,restoreWorkspaceRecovery,sealWorkspaceRecord,workspaceRecordID}from'../lib/workspace-crypto.ts';
import{EncryptedWorkspaceClient,WorkspaceSyncConflict,WorkspaceSyncError,createHostedSyncRepository}from'../public/local/workspace-sync.js';

const passphrase='correct horse battery staple';
const firstDevice='device_0123456789abcdef';
const secondDevice='device_fedcba9876543210';

class MemoryRepository{
  workspace=null;records=new Map();writeCalls=0;replacementCalls=0;
  async list(){return this.workspace?[{workspaceId:this.workspace.workspaceId,epoch:this.workspace.epoch,updatedAt:new Date().toISOString()}]:[];}
  async enroll(input){if(this.workspace)throw Error('already enrolled');this.workspace={...input,snapshotRevision:0};}
  async replaceRecovery(input){this.replacementCalls+=1;if(!this.workspace||input.workspaceId!==this.workspace.workspaceId)throw Error('missing');if(input.expectedEpoch!==this.workspace.epoch||input.expectedRevision!==this.workspace.snapshotRevision)throw Error('recovery rotation conflict');this.workspace={...this.workspace,recovery:input.recovery,snapshotRevision:this.workspace.snapshotRevision+1};return{workspaceId:this.workspace.workspaceId,epoch:this.workspace.epoch,recovery:this.workspace.recovery,snapshotRevision:this.workspace.snapshotRevision,idempotent:false};}
  async deleteWorkspace(input){if(!this.workspace||input.workspaceId!==this.workspace.workspaceId)throw Error('missing');if(input.expectedEpoch!==this.workspace.epoch||input.expectedRevision!==this.workspace.snapshotRevision)throw Error('workspace deletion conflict');this.workspace=null;this.records.clear();}
  async readWorkspace(workspaceId){if(!this.workspace||workspaceId!==this.workspace.workspaceId)throw Error('missing');return{...this.workspace,records:[...this.records.values()]};}
  async readRecord(workspaceId,recordId){if(!this.workspace||workspaceId!==this.workspace.workspaceId)throw Error('missing');return this.records.get(recordId)??null;}
  async write(input){this.writeCalls+=1;const current=this.records.get(input.envelope.recordId)??null;if((current?.revision??null)!==input.expectedRevision){if(!current)throw Error('create conflict');throw new WorkspaceSyncConflict(current);}const record={revision:input.expectedRevision===null?0:input.expectedRevision+1,envelope:input.envelope};this.records.set(input.envelope.recordId,record);this.workspace.snapshotRevision+=1;return record;}
}

function binaryRecords(records){return[...records].sort((left,right)=>left.envelope.recordId<right.envelope.recordId?-1:left.envelope.recordId>right.envelope.recordId?1:0);}
function base64URL(value){return Buffer.from(value instanceof ArrayBuffer?new Uint8Array(value):value).toString('base64url');}
function noncanonicalFinalSextet(value){const replacement=new Map([['A','B'],['Q','R'],['g','h'],['w','x']]).get(value.at(-1)??'');assert.ok(replacement,'fixture does not end in a two-byte base64url canonical sextet');return value.slice(0,-1)+replacement;}
async function legacyV1Envelope(session,path,content){
  const text=new TextEncoder(),recordId=await workspaceRecordID(session,path),baseRevision=null,mutationId='legacy_pwa_0123456789abcdef',iv=new Uint8Array(12).fill(6),writtenAt='2026-09-10T00:00:00.000Z';
  const contentSHA256=await crypto.subtle.digest('SHA-256',text.encode(content)).then(value=>Buffer.from(value).toString('hex'));
  const payload={version:1,path,content,contentSHA256,generation:0,writerDevice:firstDevice,writtenAt};
  const additionalData=text.encode(['local-sandbox.workspace-record',1,session.workspaceId,session.epoch,recordId,'-',mutationId].join('\0'));
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData},session.encryptionKey,text.encode(JSON.stringify(payload)));
  return{format:'local-sandbox.workspace-record',version:1,workspaceId:session.workspaceId,epoch:session.epoch,recordId,baseRevision,mutationId,iv:base64URL(iv),data:base64URL(data)};
}

test('local PWA and hosted TypeScript restore the same recovery envelopes and derive the same record IDs',async()=>{
  const repository=new MemoryRepository(),pwa=await EncryptedWorkspaceClient.create(passphrase,repository,firstDevice);
  const hostedSession=await restoreWorkspaceRecovery(pwa.recovery,passphrase);
  const noncanonicalRecovery={...pwa.recovery,kdf:{...pwa.recovery.kdf,salt:noncanonicalFinalSextet(pwa.recovery.kdf.salt)}};
  await assert.rejects(()=>EncryptedWorkspaceClient.restore(noncanonicalRecovery,passphrase,repository,secondDevice),error=>error instanceof WorkspaceSyncError&&error.code==='invalid-envelope');
  assert.equal(await pwa.client.recordID('workspace/interop.txt'),await workspaceRecordID(hostedSession,'workspace/interop.txt'));
  const pwaRecord=await pwa.client.push({path:'workspace/pwa-v2.txt',content:'PWA v2 → TypeScript',generation:0});
  assert.equal(pwaRecord.kind,'saved');assert.equal(pwaRecord.record.envelope.version,2);
  assert.equal((await openWorkspaceRecord(hostedSession,pwaRecord.record.envelope)).content,'PWA v2 → TypeScript');
  const legacy=await legacyV1Envelope(hostedSession,'workspace/legacy-v1.txt','PWA opens authenticated v1');
  await repository.write({workspaceId:hostedSession.workspaceId,expectedRevision:null,envelope:legacy});
  assert.equal((await pwa.client.pull()).find(item=>item.value.path==='workspace/legacy-v1.txt')?.value.content,'PWA opens authenticated v1');

  const hosted=await createWorkspaceWithRecovery(passphrase),hostedRepository=new MemoryRepository();
  await hostedRepository.enroll({workspaceId:hosted.session.workspaceId,epoch:hosted.session.epoch,recovery:hosted.recovery});
  const hostedEnvelope=await sealWorkspaceRecord(hosted.session,{path:'workspace/ts-v2.txt',content:'TypeScript v2 → PWA',baseRevision:null,generation:0,writerDevice:firstDevice});
  await hostedRepository.write({workspaceId:hosted.session.workspaceId,expectedRevision:null,envelope:hostedEnvelope});
  const pwaRestored=await EncryptedWorkspaceClient.restore(hosted.recovery,passphrase,hostedRepository,secondDevice);
  assert.equal(await pwaRestored.recordID('output/result.txt'),await workspaceRecordID(hosted.session,'output/result.txt'));
  assert.equal((await pwaRestored.pull())[0].value.content,'TypeScript v2 → PWA');
});

test('local PWA v2 round-trips worst-case JSON escaping at the exact 64,000-byte boundary',async()=>{
  const repository=new MemoryRepository(),created=await EncryptedWorkspaceClient.create(passphrase,repository,firstDevice);
  for(const [name,content] of [['nul','\0'.repeat(64000)],['backslash','\\'.repeat(64000)]]){
    const saved=await created.client.push({path:`workspace/${name}.txt`,content,generation:0});
    assert.equal(saved.kind,'saved');assert.equal(saved.record.envelope.version,2);assert.ok(saved.record.envelope.data.length<=120000);assert.equal(saved.value.content,content);
  }
  const tombstone=await created.client.push({path:'workspace/nul.txt',content:null,generation:1});
  assert.equal(tombstone.kind,'saved');assert.equal(tombstone.value.content,null);assert.equal((await created.client.pull()).find(item=>item.value.path==='workspace/nul.txt')?.value.content,null);
  await assert.rejects(()=>created.client.push({path:'workspace/too-large.txt',content:'\0'.repeat(64001),generation:0}),/64 KB/);
});

test('local PWA device B cannot silently overwrite device A after both reviewed the same base',async()=>{
  const repository=new MemoryRepository(),deviceA=await EncryptedWorkspaceClient.create(passphrase,repository,firstDevice),deviceB=await EncryptedWorkspaceClient.restore(deviceA.recovery,passphrase,repository,secondDevice);
  await deviceA.client.push({path:'workspace/shared.txt',content:'private base',generation:0});
  assert.doesNotMatch(JSON.stringify([...repository.records.values()]),/shared\.txt|private base/);
  await deviceB.pull();
  const recordId=[...repository.records.keys()][0];
  await deviceA.client.push({path:'workspace/shared.txt',content:'device A change',generation:1});
  const winner=structuredClone(repository.records.get(recordId)),writesBeforeStalePush=repository.writeCalls;
  const conflict=await deviceB.push({path:'workspace/shared.txt',content:'device B change',generation:2});assert.equal(conflict.kind,'conflict');assert.equal(conflict.remote.content,'device A change');
  assert.equal(repository.writeCalls,writesBeforeStalePush);assert.deepEqual(repository.records.get(recordId),winner);
  await deviceB.keepMine(conflict);assert.equal((await deviceA.client.pull())[0].value.content,'device B change');
  const record=repository.records.get(recordId),first=record.envelope.data[0];repository.records.set(recordId,{...record,envelope:{...record.envelope,data:(first==='A'?'B':'A')+record.envelope.data.slice(1)}});
  await assert.rejects(()=>deviceA.client.pull(),/failed authentication/);
});

test('local PWA rotates the recovery credential with record readback and deletes one snapshot-bound workspace',async()=>{
  const repository=new MemoryRepository(),created=await EncryptedWorkspaceClient.create(passphrase,repository,firstDevice);
  await created.client.push({path:'workspace/lifecycle.txt',content:'encrypted record stays byte-for-byte',generation:3});
  await assert.rejects(()=>created.client.rotateRecovery(passphrase,passphrase),/differs from the current one/);
  const stored=structuredClone([...repository.records.values()][0]);
  const rotated=await created.client.rotateRecovery(passphrase,'replacement recovery passphrase');
  assert.equal(rotated.client.workspaceId,created.client.workspaceId);assert.equal(rotated.client.epoch,created.client.epoch);
  assert.deepEqual([...repository.records.values()][0],stored);
  await assert.rejects(()=>EncryptedWorkspaceClient.restore(rotated.recovery,passphrase,repository,secondDevice),/wrong or the recovery envelope is damaged/);
  const restored=await EncryptedWorkspaceClient.restore(rotated.recovery,'replacement recovery passphrase',repository,secondDevice);
  assert.equal((await restored.pull())[0].value.content,'encrypted record stays byte-for-byte');
  await restored.deleteWorkspace();assert.equal(repository.workspace,null);assert.equal(repository.records.size,0);
});

test('local PWA authenticates every current record before replacing the recovery envelope',async()=>{
  const repository=new MemoryRepository(),created=await EncryptedWorkspaceClient.create(passphrase,repository,firstDevice);
  const saved=await created.client.push({path:'workspace/tampered-before-rotation.txt',content:'must authenticate',generation:0});
  assert.equal(saved.kind,'saved');
  const first=saved.record.envelope.data[0];
  repository.records.set(saved.record.envelope.recordId,{...saved.record,envelope:{...saved.record.envelope,data:(first==='A'?'B':'A')+saved.record.envelope.data.slice(1)}});
  const callsBefore=repository.replacementCalls;
  await assert.rejects(()=>created.client.rotateRecovery(passphrase,'replacement recovery passphrase'),/failed authentication/);
  assert.equal(repository.replacementCalls,callsBefore);
});

test('local PWA sync enforces path, passphrase, and same-origin HTTP boundaries',async()=>{
  const repository=new MemoryRepository(),created=await EncryptedWorkspaceClient.create(passphrase,repository,firstDevice);
  await assert.rejects(()=>created.client.push({path:'config/private.json',content:'secret',generation:0}),/Only non-private workspace and output/);
  for(const path of ['workspace/signing-key.p8','workspace/private-exports/token.txt','output/profile.json','workspace/credentials/account.txt']){
    await assert.rejects(()=>created.client.push({path,content:'must remain local',generation:0}),/Only non-private workspace and output/);
  }
  await created.client.push({path:'workspace/reports/profile-notes.md',content:'ordinary workspace document',generation:0});
  await assert.rejects(()=>EncryptedWorkspaceClient.restore(created.recovery,'short',repository,secondDevice),/12 to 1,024 UTF-8 bytes/);

  const calls=[];const hosted=createHostedSyncRepository({fetchImpl:async(path,options)=>{calls.push({path,options});return Response.json({workspaces:[{workspaceId:'W'.repeat(32),epoch:'E'.repeat(24),updatedAt:'2026-09-10T00:00:00.000Z'}]});}});
  assert.equal((await hosted.list())[0].workspaceId,'W'.repeat(32));
  assert.deepEqual(calls.map(call=>call.path),['/api/sync']);assert.equal(calls[0].options.credentials,'same-origin');assert.equal(calls[0].options.cache,'no-store');assert.equal(calls[0].options.redirect,'error');
});

test('hosted PWA repository sends bounded recovery-rotation and deletion CAS commands',async()=>{
  const memory=new MemoryRepository(),created=await EncryptedWorkspaceClient.create(passphrase,memory,firstDevice),calls=[];
  const hosted=createHostedSyncRepository({fetchImpl:async(path,options)=>{
    const body=JSON.parse(options.body);calls.push({path,body});
    if(body.kind==='replaceRecovery')return Response.json({workspaceId:body.workspaceId,epoch:body.expectedEpoch,recovery:body.recovery,snapshotRevision:body.expectedRevision+1,idempotent:false});
    if(body.kind==='deleteWorkspace')return Response.json({workspaceId:body.workspaceId,deleted:true,idempotent:false});
    throw Error('unexpected command');
  }});
  const replaced=await hosted.replaceRecovery({workspaceId:created.client.workspaceId,expectedEpoch:created.client.epoch,expectedRevision:0,recovery:created.recovery});
  assert.equal(replaced.snapshotRevision,1);
  await hosted.deleteWorkspace({workspaceId:created.client.workspaceId,expectedEpoch:created.client.epoch,expectedRevision:1});
  assert.deepEqual(calls.map(call=>call.body.kind),['replaceRecovery','deleteWorkspace']);
  assert.ok(calls.every(call=>call.path==='/api/sync'));
});

test('hosted transport preserves the authenticated server record on an HTTP conflict',async()=>{
  const memory=new MemoryRepository(),created=await EncryptedWorkspaceClient.create(passphrase,memory,firstDevice);
  await created.client.push({path:'workspace/conflict.txt',content:'server winner',generation:1});
  const current=[...memory.records.values()][0];
  const hosted=createHostedSyncRepository({fetchImpl:async()=>Response.json({
    code:'SYNC_VERSION_CONFLICT',
    error:'The encrypted record changed on another device.',
    record:current,
  },{status:409})});
  await assert.rejects(
    ()=>hosted.write({workspaceId:created.client.workspaceId,expectedRevision:0,envelope:current.envelope}),
    error=>error instanceof WorkspaceSyncConflict&&JSON.stringify(error.current)===JSON.stringify(current),
  );
});

test('hosted PWA repository assembles pages and restarts once on a changed snapshot',async()=>{
  const memory=new MemoryRepository(),created=await EncryptedWorkspaceClient.create(passphrase,memory,firstDevice);
  for(let index=0;index<5;index+=1)await created.client.push({path:`workspace/page-${index}.txt`,content:`page ${index}`,generation:index});
  const records=binaryRecords(memory.records.values()),cursor=records[3].envelope.recordId;
  const page=(revision,pageRecords,nextCursor)=>({workspaceId:created.client.workspaceId,epoch:created.client.epoch,recovery:created.recovery,snapshotRevision:revision,records:pageRecords,nextCursor});
  const paths=[];
  const hosted=createHostedSyncRepository({fetchImpl:async path=>{paths.push(path);return paths.length===1?Response.json(page(5,records.slice(0,4),cursor)):Response.json(page(5,records.slice(4),null));}});
  const snapshot=await hosted.readWorkspace(created.client.workspaceId);
  assert.equal(snapshot.snapshotRevision,5);assert.deepEqual(snapshot.records,records);
  assert.deepEqual(paths,[`/api/sync?workspaceId=${encodeURIComponent(created.client.workspaceId)}`,`/api/sync?workspaceId=${encodeURIComponent(created.client.workspaceId)}&cursor=${encodeURIComponent(cursor)}&snapshotRevision=5`]);

  let restartCalls=0;
  const restarting=createHostedSyncRepository({fetchImpl:async()=>{restartCalls+=1;if(restartCalls===2)return Response.json({code:'SYNC_SNAPSHOT_CHANGED',error:'changed'},{status:409});return restartCalls<3?Response.json(page(5,records.slice(0,4),cursor)):restartCalls===3?Response.json(page(6,records.slice(0,4),cursor)):Response.json(page(6,records.slice(4),null));}});
  const restarted=await restarting.readWorkspace(created.client.workspaceId);
  assert.equal(restarted.snapshotRevision,6);assert.deepEqual(restarted.records,records);assert.equal(restartCalls,4);

  let repeatedCalls=0;
  const repeatedlyChanging=createHostedSyncRepository({fetchImpl:async()=>{repeatedCalls+=1;return repeatedCalls%2===0?Response.json({code:'SYNC_SNAPSHOT_CHANGED',error:'changed again'},{status:409}):Response.json(page(repeatedCalls,records.slice(0,4),cursor));}});
  await assert.rejects(()=>repeatedlyChanging.readWorkspace(created.client.workspaceId),error=>error instanceof WorkspaceSyncError&&error.status===409&&error.code==='SYNC_SNAPSHOT_CHANGED');
  assert.equal(repeatedCalls,4);
});

test('hosted PWA repository rejects invalid cursor pages and enforces response and wire bounds',async()=>{
  const memory=new MemoryRepository(),created=await EncryptedWorkspaceClient.create(passphrase,memory,firstDevice);
  for(let index=0;index<4;index+=1)await created.client.push({path:`workspace/bound-${index}.txt`,content:`bound ${index}`,generation:index});
  const records=binaryRecords(memory.records.values());
  const boundedRecords=records.map(record=>({...record,envelope:{...record.envelope,version:2,data:'A'.repeat(120000)}}));
  const boundedRecovery={...created.recovery,cipher:{...created.recovery.cipher,data:'A'.repeat(4096)}};
  const boundedBody={workspaceId:created.client.workspaceId,epoch:created.client.epoch,recovery:boundedRecovery,snapshotRevision:4,records:boundedRecords,nextCursor:null};
  assert.ok(new TextEncoder().encode(JSON.stringify(boundedBody)).length<512*1024);
  assert.ok(new TextEncoder().encode(JSON.stringify(boundedBody)).length>480000);
  const bounded=createHostedSyncRepository({fetchImpl:async()=>Response.json(boundedBody)});
  assert.equal((await bounded.readWorkspace(created.client.workspaceId)).records.length,4);

  const badCursor=createHostedSyncRepository({fetchImpl:async()=>Response.json({...boundedBody,records,nextCursor:records[2].envelope.recordId})});
  await assert.rejects(()=>badCursor.readWorkspace(created.client.workspaceId),/invalid pagination cursor/);
  const oversizedCipher=createHostedSyncRepository({fetchImpl:async()=>Response.json({...boundedBody,records:[{...records[0],envelope:{...records[0].envelope,version:2,data:'A'.repeat(120001)}}]})});
  await assert.rejects(()=>oversizedCipher.readWorkspace(created.client.workspaceId),/invalid base64url data/);
  const legacyBounded={...records[0],envelope:{...records[0].envelope,version:1,data:'A'.repeat(100000)}};
  assert.equal((await createHostedSyncRepository({fetchImpl:async()=>Response.json({...boundedBody,records:[legacyBounded]})}).readWorkspace(created.client.workspaceId)).records.length,1);
  const oversizedLegacy=createHostedSyncRepository({fetchImpl:async()=>Response.json({...boundedBody,records:[{...legacyBounded,envelope:{...legacyBounded.envelope,data:'A'.repeat(100001)}}]})});
  await assert.rejects(()=>oversizedLegacy.readWorkspace(created.client.workspaceId),/invalid base64url data/);
  const oversizedResponse=createHostedSyncRepository({fetchImpl:async()=>Response.json({padding:'x'.repeat(512*1024)})});
  await assert.rejects(()=>oversizedResponse.readWorkspace(created.client.workspaceId),error=>error instanceof WorkspaceSyncError&&error.code==='response-too-large');
  let canceled=false;
  const streaming=createHostedSyncRepository({fetchImpl:async()=>new Response(new ReadableStream({start(controller){controller.enqueue(new Uint8Array(300000));controller.enqueue(new Uint8Array(300000));},cancel(){canceled=true;}}),{headers:{'Content-Type':'application/json'}})});
  await assert.rejects(()=>streaming.readWorkspace(created.client.workspaceId),error=>error instanceof WorkspaceSyncError&&error.code==='response-too-large');
  assert.equal(canceled,true);
});

test('local and dashboard UIs expose confirmed tombstone creation/application with readback',async()=>{
  const root=new URL('../public/local/',import.meta.url),[client,app,html,worker,dashboard]=await Promise.all([
    ...['workspace-sync.js','app.js','index.html','sw.js'].map(file=>readFile(new URL(file,root),'utf8')),
    readFile(new URL('../app/dashboard.tsx',import.meta.url),'utf8'),
  ]);
  assert.doesNotMatch(client,/localStorage|sessionStorage|indexedDB|setInterval/);assert.match(client,/local-sandbox\.workspace-recovery/);assert.match(client,/local-sandbox\.workspace-record/);
  assert.doesNotMatch(client,/\.arrayBuffer\(/);assert.match(client,/\.body\.getReader\(\)/);assert.match(client,/reader\.cancel\(\)/);
  assert.match(app,/EncryptedWorkspaceClient/);assert.match(html,/id="device-sync-create"/);assert.match(html,/id="device-sync-tombstone"/);assert.match(html,/manual encrypted sync/i);assert.match(worker,/['"]\.\/workspace-sync\.js['"]/);
  assert.match(app,/rotateRecovery\(current,replacement\)/);assert.match(app,/deleteWorkspace\(\)/);assert.match(html,/id="device-sync-rotate"/);assert.match(html,/id="device-sync-delete"/);
  assert.match(app,/Delete the local \$\{path\} using the reviewed encrypted tombstone/);assert.match(app,/engine\.deleteFile\(path\)/);assert.match(app,/reviewed deletion did not read back/);
  assert.match(app,/Replace encrypted \$\{remote\.value\.path\} with a deletion tombstone/);assert.match(app,/item\.value\.content===null/);
  assert.match(dashboard,/Delete hosted \$\{value\.path\} using the reviewed encrypted tombstone/);assert.match(dashboard,/kind:'delete',path:value\.path,version:local\.version/);assert.match(dashboard,/reviewed deletion did not read back from the hosted workspace/);
  assert.match(dashboard,/Replace encrypted \$\{value\.path\} with a deletion tombstone/);assert.match(dashboard,/deletion tombstone did not authenticate on readback/i);
  assert.match(dashboard,/kind:'replaceRecovery'/);assert.match(dashboard,/kind:'deleteWorkspace'/);
  assert.match(dashboard,/rotateEncryptedSyncRecovery\(\)[\s\S]*client\.rotateRecovery\(current,replacement\)[\s\S]*setSyncClient\(rotated\.client\)/);
  assert.match(dashboard,/deleteEncryptedSyncWorkspace\(\)[\s\S]*client\.deleteWorkspace\(\)[\s\S]*lockEncryptedSync\(\)/);
  assert.match(dashboard,/Rotate this recovery credential\?/);assert.match(dashboard,/Delete this hosted encrypted workspace\?/);
  assert.match(dashboard,/does not rotate the data key or epoch/);assert.match(dashboard,/does not delete local Files or iCloud documents/);
  assert.match(dashboard,/function lockEncryptedSync\(\)[\s\S]*clearSyncCredentialFields\(\)/);
  assert.doesNotMatch(dashboard,/disabled=\{syncConflict\.remote\.content===null\|\|!!busy\}/);assert.doesNotMatch(dashboard,/disabled=\{item\.value\.content===null\|\|!!busy\}/);
});
