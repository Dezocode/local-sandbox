import assert from 'node:assert/strict';
import test from 'node:test';
import { createWorkspaceWithRecovery,maximumRecordCiphertextCharacters,openWorkspaceRecord,restoreWorkspaceRecovery,rewrapWorkspaceRecovery,sealWorkspaceRecord,workspaceRecordID,type EncryptedWorkspaceRecord,type WorkspaceSession } from '../lib/workspace-crypto.ts';

const password='correct horse battery staple';
const device='device_0123456789abcdef';
const textEncoder=new TextEncoder();

function base64URL(value:ArrayBuffer|Uint8Array):string{
  return Buffer.from(value instanceof ArrayBuffer?new Uint8Array(value):value).toString('base64url');
}

function noncanonicalFinalSextet(value:string):string{
  const replacement=new Map([['A','B'],['Q','R'],['g','h'],['w','x']]).get(value.at(-1)??'');
  assert.ok(replacement,'fixture does not end in a two-byte base64url canonical sextet');
  return value.slice(0,-1)+replacement;
}

function recordAAD(...parts:(string|number|null)[]):Uint8Array<ArrayBuffer>{
  return textEncoder.encode(parts.map(part=>part===null?'-':String(part)).join('\0'));
}

async function legacyV1Record(session:WorkspaceSession,path:string,content:string):Promise<EncryptedWorkspaceRecord>{
  const recordId=await workspaceRecordID(session,path),baseRevision=7,mutationId='legacy_mutation_0123456789',iv=new Uint8Array(12).fill(7),writtenAt='2026-09-10T00:00:00.000Z';
  const digest=await crypto.subtle.digest('SHA-256',textEncoder.encode(content)).then(value=>Buffer.from(value).toString('hex'));
  const payload={version:1,path,content,contentSHA256:digest,generation:4,writerDevice:device,writtenAt};
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:recordAAD('local-sandbox.workspace-record',1,session.workspaceId,session.epoch,recordId,baseRevision,mutationId)},session.encryptionKey,textEncoder.encode(JSON.stringify(payload)));
  return {format:'local-sandbox.workspace-record',version:1,workspaceId:session.workspaceId,epoch:session.epoch,recordId,baseRevision,mutationId,iv:base64URL(iv),data:base64URL(data)};
}

test('encrypted workspace record hides path and content and round-trips Unicode',async()=>{
  const {session}=await createWorkspaceWithRecovery(password);
  const record=await sealWorkspaceRecord(session,{path:'workspace/private.txt',content:'private αβ',baseRevision:null,generation:1,writerDevice:device});
  const serialized=JSON.stringify(record);
  assert.equal(serialized.includes('workspace/private.txt'),false);
  assert.equal(serialized.includes('private αβ'),false);
  assert.deepEqual(await openWorkspaceRecord(session,record),{
    version:2,path:'workspace/private.txt',content:'private αβ',contentSHA256:await crypto.subtle.digest('SHA-256',new TextEncoder().encode('private αβ')).then(value=>[...new Uint8Array(value)].map(byte=>byte.toString(16).padStart(2,'0')).join('')),generation:1,writerDevice:device,writtenAt:(await openWorkspaceRecord(session,record)).writtenAt,
  });
  assert.equal(record.version,2);
});

test('v2 accepts every 64,000-byte UTF-8 file independent of JSON escaping and still reads v1',async()=>{
  const {session}=await createWorkspaceWithRecovery(password);
  for(const [name,content] of [['nul','\0'.repeat(64_000)],['backslash','\\'.repeat(64_000)]] as const){
    const record=await sealWorkspaceRecord(session,{path:`workspace/${name}.txt`,content,baseRevision:null,generation:0,writerDevice:device});
    assert.equal(record.version,2);
    assert.ok(record.data.length<=maximumRecordCiphertextCharacters);
    assert.equal((await openWorkspaceRecord(session,record)).content,content);
  }
  const legacy=await legacyV1Record(session,'workspace/legacy.txt','legacy direct JSON content');
  assert.equal((await openWorkspaceRecord(session,legacy)).version,1);
  assert.equal((await openWorkspaceRecord(session,legacy)).content,'legacy direct JSON content');
});

test('record IDs are deterministic inside one epoch and distinct across paths',async()=>{
  const {session}=await createWorkspaceWithRecovery(password);
  assert.equal(await workspaceRecordID(session,'workspace/a.txt'),await workspaceRecordID(session,'workspace/a.txt'));
  assert.notEqual(await workspaceRecordID(session,'workspace/a.txt'),await workspaceRecordID(session,'workspace/b.txt'));
});

test('authenticated metadata rejects record swapping and stale-base tampering',async()=>{
  const {session}=await createWorkspaceWithRecovery(password);
  const record=await sealWorkspaceRecord(session,{path:'workspace/a.txt',content:'value',baseRevision:4,generation:2,writerDevice:device});
  await assert.rejects(()=>openWorkspaceRecord(session,{...record,recordId:'A'.repeat(43)}),/failed authentication/);
  await assert.rejects(()=>openWorkspaceRecord(session,{...record,baseRevision:5}),/failed authentication/);
  await assert.rejects(()=>openWorkspaceRecord(session,{...record,mutationId:'B'.repeat(24)}),/failed authentication/);
});

test('recovery restores the same identity and key while rejecting wrong credentials or tampering',async()=>{
  const {session,recovery}=await createWorkspaceWithRecovery(password,'2026-09-10T00:00:00.000Z');
  const restored=await restoreWorkspaceRecovery(recovery,password);
  assert.equal(restored.workspaceId,session.workspaceId);assert.equal(restored.epoch,session.epoch);
  assert.equal(await workspaceRecordID(restored,'workspace/a.txt'),await workspaceRecordID(session,'workspace/a.txt'));
  await assert.rejects(()=>restoreWorkspaceRecovery(recovery,'this is the wrong password'),/wrong or the recovery envelope is damaged/);
  await assert.rejects(()=>restoreWorkspaceRecovery({...recovery,kdf:{...recovery.kdf,salt:noncanonicalFinalSextet(recovery.kdf.salt)}},password),/wrong or the recovery envelope is damaged/);
  const last=recovery.cipher.data.at(-1)??'A';
  await assert.rejects(()=>restoreWorkspaceRecovery({...recovery,cipher:{...recovery.cipher,data:recovery.cipher.data.slice(0,-1)+(last==='A'?'B':'A')}},password),/wrong or the recovery envelope is damaged/);
});

test('recovery rotation rewraps the same nonextractable workspace key under a replacement credential',async()=>{
  const original='original recovery passphrase';
  const replacement='replacement recovery passphrase';
  const created=await createWorkspaceWithRecovery(original,'2026-09-10T00:00:00.000Z');
  await assert.rejects(()=>rewrapWorkspaceRecovery(created.recovery,original,original),/differs from the current one/);
  const before=await sealWorkspaceRecord(created.session,{path:'workspace/rotated.txt',content:'survives recovery rotation',baseRevision:null,generation:0,writerDevice:'device_0123456789abcdef'});
  const rotated=await rewrapWorkspaceRecovery(created.recovery,original,replacement,'2026-09-11T00:00:00.000Z');
  assert.equal(rotated.session.workspaceId,created.session.workspaceId);
  assert.equal(rotated.session.epoch,created.session.epoch);
  assert.notDeepEqual(rotated.recovery,created.recovery);
  assert.equal((await openWorkspaceRecord(rotated.session,before)).content,'survives recovery rotation');
  await assert.rejects(()=>restoreWorkspaceRecovery(rotated.recovery,original),/wrong or the recovery envelope is damaged/);
  const restored=await restoreWorkspaceRecovery(rotated.recovery,replacement);
  assert.equal(await workspaceRecordID(restored,'workspace/rotated.txt'),before.recordId);
});

test('workspace and epoch mismatch fail closed before decrypting',async()=>{
  const first=await createWorkspaceWithRecovery(password),second=await createWorkspaceWithRecovery(password);
  const record=await sealWorkspaceRecord(first.session,{path:'workspace/a.txt',content:'value',baseRevision:null,generation:0,writerDevice:device});
  await assert.rejects(()=>openWorkspaceRecord(second.session,record),/different workspace or key epoch/);
});

test('deletions are authenticated tombstones rather than absent writes',async()=>{
  const {session}=await createWorkspaceWithRecovery(password);
  const record=await sealWorkspaceRecord(session,{path:'workspace/a.txt',content:null,baseRevision:9,generation:4,writerDevice:device});
  const opened=await openWorkspaceRecord(session,record);
  assert.equal(opened.content,null);assert.equal(opened.contentSHA256,null);assert.equal(record.baseRevision,9);
});

test('path, size, nonce, and recovery-password boundaries reject invalid input',async()=>{
  const {session}=await createWorkspaceWithRecovery(password);
  await assert.rejects(()=>sealWorkspaceRecord(session,{path:'../escape',content:'x',baseRevision:null,generation:0,writerDevice:device}));
  await assert.rejects(()=>sealWorkspaceRecord(session,{path:'workspace/a',content:'x'.repeat(64_001),baseRevision:null,generation:0,writerDevice:device}));
  await assert.rejects(()=>sealWorkspaceRecord(session,{path:'workspace/a',content:'x',baseRevision:null,generation:0,writerDevice:device},{iv:new Uint8Array(11)}));
  await assert.rejects(()=>createWorkspaceWithRecovery('short'));
  await assert.rejects(()=>createWorkspaceWithRecovery('x'.repeat(1_025)));
});

test('recovery passphrases use an explicit UTF-8 byte boundary and preserve embedded NUL bytes',async()=>{
  const unicode='🔐🔑🧩';
  const {session,recovery}=await createWorkspaceWithRecovery(unicode);
  const restored=await restoreWorkspaceRecovery(recovery,unicode);
  assert.equal(restored.workspaceId,session.workspaceId);

  const embedded='123456789012\0alpha';
  const created=await createWorkspaceWithRecovery(embedded);
  await assert.rejects(()=>restoreWorkspaceRecovery(created.recovery,'123456789012\0bravo'),/wrong or the recovery envelope is damaged/);
});
