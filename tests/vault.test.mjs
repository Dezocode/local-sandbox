import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {EncryptedDraftJournal} from '../public/local/draft-journal.js';
import {LocalAutosaveEngine} from '../public/local/local-autosave.js';
import {storagePersistenceReport} from '../public/local/storage.js';
import {createVaultSession,normalizeVault,openVault,seal,sealWithSession,unseal,validVault} from '../public/local/vault.js';
const sample={version:1,files:{'workspace/notes.md':'private αβ'},messages:[{role:'Oracle',text:'Read the file',at:'2026-09-10T00:00:00Z'}]};
async function legacySeal(vault,password){
  const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
  const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(JSON.stringify(vault)));
  return{format:'local-sandbox.vault',version:1,salt:Buffer.from(salt).toString('base64'),iv:Buffer.from(iv).toString('base64'),data:Buffer.from(data).toString('base64')};
}
test('encrypted vault round-trips unicode content and contains no plaintext',async()=>{const a=await seal(sample,'a long local password');assert.deepEqual(await unseal(a,'a long local password'),sample);assert.equal(JSON.stringify(a).includes('private'),false)});
test('wrong password and modified ciphertext cannot unlock vault',async()=>{const a=await seal(sample,'a long local password');await assert.rejects(()=>unseal(a,'wrong password'));const bytes=Buffer.from(a.data,'base64');bytes[0]^=1;await assert.rejects(()=>unseal({...a,data:bytes.toString('base64')},'a long local password'))});
test('every encryption has fresh salt and IV',async()=>{const a=await seal(sample,'a long local password'),b=await seal(sample,'a long local password');assert.notEqual(a.salt,b.salt);assert.notEqual(a.iv,b.iv);assert.notEqual(a.data,b.data)});
test('backup validation excludes path escapes and oversized files',()=>{for(const path of ['../secret','workspace/../secret','config/.hidden','workspace//x'])assert.throws(()=>validVault({...sample,files:{[path]:'x'}}));assert.throws(()=>validVault({...sample,files:{'workspace/a':'a'.repeat(64001)}}))});

class MemoryDraftStore{
  constructor(timeline=[]){this.records=new Map();this.events=[];this.timeline=timeline;this.failInsert=false;this.failDelete=false;}
  async insertIfAbsent(record){if(this.failInsert)throw Error('journal unavailable');if(this.records.has(record.id))return false;this.records.set(record.id,structuredClone(record));this.events.push('journal:insert');this.timeline.push('journal:insert');return true;}
  async replaceIf(record,etag){if(this.records.get(record.id)?.etag!==etag)return false;this.records.set(record.id,structuredClone(record));this.events.push('journal:replace');this.timeline.push('journal:replace');return true;}
  async deleteIf(id,etag){if(this.failDelete){this.failDelete=false;throw Error('cleanup unavailable');}if(this.records.get(id)?.etag!==etag)return false;this.records.delete(id);this.events.push('journal:delete');this.timeline.push('journal:delete');return true;}
  async list(){return[...this.records.values()].map(record=>structuredClone(record));}
  clear(){this.records.clear();this.events.push('journal:clear');this.timeline.push('journal:clear');}
}

class MemoryVaultStore{
  constructor(envelope,drafts,timeline=[]){this.envelope=structuredClone(envelope);this.drafts=drafts;this.events=[];this.timeline=timeline;this.active=0;this.maxActive=0;this.gate=null;}
  async read(){return structuredClone(this.envelope);}
  async compareAndSwap(expected,next){
    this.active+=1;this.maxActive=Math.max(this.maxActive,this.active);this.events.push('vault:cas');this.timeline.push('vault:cas');if(this.gate)await this.gate;
    const matches=JSON.stringify(this.envelope)===JSON.stringify(expected);if(matches)this.envelope=structuredClone(next);this.active-=1;return matches;
  }
  async compareAndSwapAndClearDrafts(expected,next){
    this.active+=1;this.maxActive=Math.max(this.maxActive,this.active);this.events.push('vault:restore');this.timeline.push('vault:restore');
    const matches=JSON.stringify(this.envelope)===JSON.stringify(expected);if(matches){this.envelope=structuredClone(next);this.drafts.clear();}this.active-=1;return matches;
  }
}

async function memoryEngine(vault=sample,debounceMs=1000){
  const session=await createVaultSession('a long local password');
  const normalized=normalizeVault(vault),envelope=await sealWithSession(normalized,session),timeline=[],drafts=new MemoryDraftStore(timeline),store=new MemoryVaultStore(envelope,drafts,timeline);
  const engine=await LocalAutosaveEngine.open({vault:normalized,envelope,session,vaultStore:store,draftStore:drafts,debounceMs});
  return{engine,session,store,drafts,timeline};
}

test('an unlocked v1 backup reuses one non-extractable key with fresh nonces',async()=>{
  const original=await legacySeal(sample,'a long local password');const opened=await openVault(original,'a long local password');const normalized=normalizeVault(opened.vault);
  const first=await sealWithSession(normalized,opened.session),second=await sealWithSession(normalized,opened.session);
  assert.equal(first.salt,original.salt);assert.equal(second.salt,original.salt);assert.notEqual(first.iv,second.iv);assert.notEqual(first.data,second.data);assert.equal(opened.session.vaultKey.extractable,false);assert.deepEqual(await unseal(first,'a long local password'),normalized);
});

test('recovery journal encrypts paths and content and rejects altered ciphertext',async()=>{
  const session=await createVaultSession('a long local password'),store=new MemoryDraftStore(),journal=new EncryptedDraftJournal(store,session);
  const payload={version:1,kind:'file',target:'file:workspace/private.md',path:'workspace/private.md',baseGeneration:0,baseContent:'old secret',content:'new secret',generation:1,updatedAt:'2026-09-10T00:00:00Z'};
  const token=await journal.put(payload),serialized=JSON.stringify([...store.records.values()]);
  assert.equal(serialized.includes('workspace/private.md'),false);assert.equal(serialized.includes('new secret'),false);assert.deepEqual((await journal.list())[0].payload,payload);
  const row=store.records.get(token.id);row.data=(row.data[0]==='A'?'B':'A')+row.data.slice(1);await assert.rejects(()=>journal.list(),/damaged|another vault/);
});

test('file and session mutations journal before one-at-a-time vault CAS writes',async()=>{
  const {engine,store,drafts,timeline}=await memoryEngine();
  await engine.editFile('workspace/notes.md','updated');await engine.flushFile('workspace/notes.md');
  await engine.addMessage('Locally response','done');await engine.flushMessages();
  assert.equal(store.maxActive,1);assert.equal(engine.fileContent('workspace/notes.md'),'updated');assert.equal(engine.messages().at(-1).text,'done');assert.equal(engine.getState('workspace/notes.md').kind,'clean');assert.equal(engine.getMessageState().kind,'clean');assert.deepEqual([...drafts.records],[]);
  assert.deepEqual(timeline,['journal:insert','vault:cas','journal:delete','journal:insert','vault:cas','journal:delete']);engine.dispose();
});

test('reviewed deletion is journaled, committed, and absent after an independent vault reopen',async()=>{
  const {engine,store,drafts,timeline}=await memoryEngine();
  await engine.deleteFile('workspace/notes.md');
  assert.equal(engine.fileContent('workspace/notes.md'),undefined);assert.equal(engine.getState('workspace/notes.md').kind,'dirtyJournaled');
  await engine.flushFile('workspace/notes.md');
  assert.equal(engine.getState('workspace/notes.md').kind,'clean');assert.equal(drafts.records.size,0);
  assert.deepEqual(timeline,['journal:insert','vault:cas','journal:delete']);
  const readback=await openVault(store.envelope,'a long local password');
  assert.equal(readback.vault.files['workspace/notes.md'],undefined);assert.equal(readback.vault.autosave.fileGenerations['workspace/notes.md'],undefined);
  const reopened=await LocalAutosaveEngine.open({vault:readback.vault,envelope:store.envelope,session:readback.session,vaultStore:store,draftStore:drafts,debounceMs:1000});
  assert.equal(reopened.fileContent('workspace/notes.md'),undefined);assert.deepEqual(reopened.listFiles(),[]);reopened.dispose();engine.dispose();
});

test('debounce saves a journaled file without a manual save action',async()=>{
  const {engine}=await memoryEngine(sample,5);await engine.editFile('workspace/notes.md','automatic');await new Promise(resolve=>setTimeout(resolve,25));
  assert.equal(engine.getState('workspace/notes.md').kind,'clean');assert.equal(engine.fileContent('workspace/notes.md'),'automatic');engine.dispose();
});

test('rapid edits replace one journal record instead of resurrecting a stale draft',async()=>{
  const {engine,drafts}=await memoryEngine();const first=engine.editFile('workspace/notes.md','one'),second=engine.editFile('workspace/notes.md','two');await Promise.all([first,second]);
  assert.equal(drafts.records.size,1);await engine.flushFile('workspace/notes.md');assert.equal(drafts.records.size,0);assert.equal(engine.fileContent('workspace/notes.md'),'two');engine.dispose();
});

test('journal failure blocks the vault write, and a cleanup failure can retry safely',async()=>{
  const first=await memoryEngine();first.drafts.failInsert=true;await first.engine.editFile('workspace/notes.md','not yet safe');await first.engine.flushFile('workspace/notes.md');
  assert.equal(first.engine.getState('workspace/notes.md').kind,'failed');assert.equal(first.store.events.filter(event=>event==='vault:cas').length,0);first.engine.dispose();
  const second=await memoryEngine();await second.engine.editFile('workspace/notes.md','saved once');second.drafts.failDelete=true;await second.engine.flushFile('workspace/notes.md');assert.equal(second.engine.getState('workspace/notes.md').kind,'failed');assert.equal(second.engine.fileContent('workspace/notes.md'),'saved once');
  await second.engine.retryFile('workspace/notes.md');assert.equal(second.engine.getState('workspace/notes.md').kind,'clean');assert.equal(second.store.events.filter(event=>event==='vault:cas').length,1);second.engine.dispose();
});

test('reload recovers a journaled draft and resumes its guarded save',async()=>{
  const {engine,session,store,drafts}=await memoryEngine();await engine.editFile('workspace/notes.md','recovered');engine.dispose();
  const vault=await openVault(store.envelope,'a long local password');const recovered=await LocalAutosaveEngine.open({vault:vault.vault,envelope:store.envelope,session,draftStore:drafts,vaultStore:store,debounceMs:1000});
  assert.equal(recovered.getState('workspace/notes.md').kind,'dirtyJournaled');assert.equal(recovered.fileContent('workspace/notes.md'),'recovered');await recovered.flushFile('workspace/notes.md');assert.equal(recovered.getState('workspace/notes.md').kind,'clean');assert.equal(recovered.fileContent('workspace/notes.md'),'recovered');recovered.dispose();
});

test('a same-file generation change becomes an explicit conflict without losing the draft',async()=>{
  const {engine,session,store,drafts}=await memoryEngine();await engine.editFile('workspace/notes.md','local draft');
  const remote=normalizeVault(sample);remote.files['workspace/notes.md']='other tab';remote.autosave.fileGenerations['workspace/notes.md']=1;remote.autosave.revision=1;store.envelope=await sealWithSession(remote,session);
  await engine.flushFile('workspace/notes.md');assert.equal(engine.getState('workspace/notes.md').kind,'conflict');assert.equal(engine.fileContent('workspace/notes.md'),'local draft');assert.equal(drafts.records.size,1);
  await engine.useSavedFile('workspace/notes.md');assert.equal(engine.fileContent('workspace/notes.md'),'other tab');assert.equal(drafts.records.size,0);engine.dispose();
});

test('an edit during a save rebases into a second file generation',async()=>{
  const {engine,store}=await memoryEngine();let release=()=>{};store.gate=new Promise(resolve=>{release=resolve;});
  await engine.editFile('workspace/notes.md','first');const first=engine.flushFile('workspace/notes.md');await new Promise(resolve=>setTimeout(resolve,0));const secondJournal=engine.editFile('workspace/notes.md','second');release();store.gate=null;await first;await secondJournal;await engine.flushFile('workspace/notes.md');
  assert.equal(engine.fileContent('workspace/notes.md'),'second');assert.equal(engine.getVaultRevision(),2);assert.equal(store.events.filter(event=>event==='vault:cas').length,2);engine.dispose();
});

test('restore replaces the vault and clears recovery journals in one storage operation',async()=>{
  const {engine,store,drafts}=await memoryEngine();await engine.editFile('workspace/notes.md','discarded draft');assert.equal(drafts.records.size,1);
  const restored={version:1,files:{'workspace/restored.md':'restored'},messages:[]},session=await createVaultSession('another long password');await engine.replaceVault(restored,session);
  assert.deepEqual(engine.listFiles(),[{path:'workspace/restored.md',content:'restored'}]);assert.equal(drafts.records.size,0);assert.equal(store.events.at(-1),'vault:restore');engine.dispose();
});

test('storage persistence reports granted and evictable browser states',async()=>{
  let check=0;const granted=await storagePersistenceReport({persisted:async()=>check++>0,persist:async()=>true,estimate:async()=>({usage:1048576,quota:10485760})});
  const denied=await storagePersistenceReport({persisted:async()=>false,persist:async()=>false});
  assert.equal(granted.kind,'persisted');assert.match(granted.message,/1\.0 MB of 10\.0 MB/);assert.equal(denied.kind,'evictable');assert.match(denied.message,/encrypted backup/);
});

test('the offline shell caches every autosave module and app DOM references exist',async()=>{
  const root=new URL('../public/local/',import.meta.url);
  const [app,html,worker]=await Promise.all([readFile(new URL('app.js',root),'utf8'),readFile(new URL('index.html',root),'utf8'),readFile(new URL('sw.js',root),'utf8')]);
  const referenced=[...app.matchAll(/el\('([^']+)'\)/g)].map(match=>match[1]);
  assert.deepEqual([...new Set(referenced)].filter(id=>!html.includes(`id="${id}"`)),[]);
  for(const id of ['editor','prompt'])assert.match(html,new RegExp(`<textarea(?=[^>]*\\bid="${id}")(?=[^>]*\\bautocomplete="off")[^>]*>`));
  for(const file of ['index.html','style.css','app.js','local-autosave.js','draft-journal.js','storage.js','vault.js','github.js'])assert.match(worker,new RegExp(`['"]\\./${file.replace('.','\\.')}['"]`));
});
