import assert from 'node:assert/strict';
import test from 'node:test';
import { IndexedDBDraftJournal } from '../app/draft-journal.ts';
import { AutosaveCoordinator,AutosaveFailure,purgeDraftScope,type DraftJournal,type DraftPurgeEntry,type DraftRecord,type FileRepository,type JournaledDraft,type RemoteFile } from '../lib/autosave.ts';

class MemoryJournal implements DraftJournal{
  readonly records=new Map<string,JournaledDraft>();
  readonly events:string[]=[];
  failPut=false;
  async put(record:DraftRecord){this.events.push(`journal:${record.path}:${record.generation}`);if(this.failPut)throw Error('journal unavailable');const token=`${record.path}:${record.generation}:${record.content}`;this.records.set(record.path,{record,token});return token;}
  async removeIf(_scope:string,path:string,generation:number,token:string){const current=this.records.get(path);if(current?.record.generation!==generation||current.token!==token)return false;this.records.delete(path);this.events.push(`clean:${path}:${generation}`);return true;}
  async list(scope:string){return [...this.records.values()].filter(value=>value.record.scope===scope);}
}
class MemoryRepository implements FileRepository{
  readonly files=new Map<string,RemoteFile>();
  readonly events:string[]=[];
  failure:AutosaveFailure|null=null;
  readFailure:AutosaveFailure|null=null;
  gate:Promise<void>|null=null;
  constructor(files:RemoteFile[]){for(const file of files)this.files.set(file.path,file);}
  async save(record:Pick<DraftRecord,'path'|'baseVersion'|'content'>){this.events.push(`save:${record.path}:${record.baseVersion}:${record.content}`);if(this.gate)await this.gate;if(this.failure){const error=this.failure;this.failure=null;throw error;}const current=this.files.get(record.path);if(!current||current.version!==record.baseVersion)throw new AutosaveFailure('conflict','stale',current??null);const next={path:record.path,content:record.content,version:current.version+1};this.files.set(record.path,next);return next;}
  async read(path:string){if(this.readFailure){const error=this.readFailure;this.readFailure=null;throw error;}return this.files.get(path)??null;}
}
const file=(path='workspace/a.txt',content='base',version=0):RemoteFile=>({path,content,version});
const tick=()=>new Promise(resolve=>setTimeout(resolve,0));

type FakeRequest<T>={result:T;error:DOMException|null;onsuccess:(()=>void)|null;onerror:(()=>void)|null};

class FakeTransaction {
  oncomplete:(()=>void)|null=null;
  onabort:(()=>void)|null=null;
  onerror:(()=>void)|null=null;
  error:DOMException|null=null;
  private pending=0;
  private settled=false;
  private readonly records:Map<IDBValidKey,unknown>;
  constructor(records:Map<IDBValidKey,unknown>){this.records=records;}
  objectStore():IDBObjectStore{
    const request=<T>(operation:()=>T):IDBRequest<T>=>{
      this.pending+=1;
      const output:FakeRequest<T>={result:undefined as T,error:null,onsuccess:null,onerror:null};
      queueMicrotask(()=>{
        if(this.settled)return;
        try{output.result=operation();output.onsuccess?.();}
        catch(error){const failure=error instanceof DOMException?error:new DOMException(error instanceof Error?error.message:'IndexedDB request failed.','UnknownError');output.error=failure;this.error=failure;output.onerror?.();this.abort();}
        finally{this.pending-=1;this.queueCompletion();}
      });
      return output as unknown as IDBRequest<T>;
    };
    return {
      get:(key:IDBValidKey)=>request(()=>this.records.get(key)),
      add:(value:unknown,key?:IDBValidKey)=>request(()=>{if(key===undefined)throw new DOMException('A key is required.','DataError');if(this.records.has(key))throw new DOMException('The key already exists.','ConstraintError');this.records.set(key,value);return key;}),
      put:(value:unknown,key?:IDBValidKey)=>request(()=>{if(key===undefined)throw new DOMException('A key is required.','DataError');this.records.set(key,value);return key;}),
      delete:(key:IDBValidKey)=>request(()=>{this.records.delete(key);return undefined;}),
      getAllKeys:(_query?:IDBValidKey|IDBKeyRange|null,count?:number)=>request(()=>[...this.records.keys()].slice(0,count)),
      getAll:(_query?:IDBValidKey|IDBKeyRange|null,count?:number)=>request(()=>[...this.records.values()].slice(0,count)),
    } as unknown as IDBObjectStore;
  }
  abort():void{
    if(this.settled)return;
    this.settled=true;
    this.error??=new DOMException('The transaction was aborted.','AbortError');
    queueMicrotask(()=>this.onabort?.());
  }
  private queueCompletion():void{
    queueMicrotask(()=>{
      if(this.settled||this.pending!==0)return;
      this.settled=true;this.oncomplete?.();
    });
  }
}

class FakeIndexedDB {
  private readonly stores=new Map<string,Map<IDBValidKey,unknown>>();
  get records():Map<IDBValidKey,unknown>{const records=this.stores.get('drafts');if(!records)throw Error('The draft store has not been created.');return records;}
  readonly database={
    objectStoreNames:{contains:(name:string)=>this.stores.has(name)},
    createObjectStore:(name:string)=>{this.stores.set(name,new Map());return{} as IDBObjectStore;},
    transaction:(name:string)=>{const store=this.stores.get(name);if(!store)throw Error(`Missing object store: ${name}`);return new FakeTransaction(store) as unknown as IDBTransaction;},
  } as IDBDatabase;
  open():IDBOpenDBRequest{
    const request={result:this.database,error:null,onupgradeneeded:null,onsuccess:null,onerror:null,onblocked:null} as unknown as IDBOpenDBRequest;
    queueMicrotask(()=>{if(this.stores.size===0)request.onupgradeneeded?.(new Event('upgradeneeded') as IDBVersionChangeEvent);request.onsuccess?.(new Event('success'));});
    return request;
  }
}

async function withFakeIndexedDB(action:(database:FakeIndexedDB)=>Promise<void>):Promise<void>{
  const original=globalThis.indexedDB,originalRandom=globalThis.crypto.getRandomValues;const database=new FakeIndexedDB();let nonce=0;
  Object.defineProperty(globalThis,'indexedDB',{configurable:true,writable:true,value:database as unknown as IDBFactory});
  Object.defineProperty(globalThis.crypto,'getRandomValues',{configurable:true,value:<T extends ArrayBufferView|null>(array:T):T=>{if(array instanceof Uint8Array){nonce+=1;array.fill(nonce);}return array;}});
  try{await action(database);}
  finally{Object.defineProperty(globalThis.crypto,'getRandomValues',{configurable:true,value:originalRandom});if(original)Object.defineProperty(globalThis,'indexedDB',{configurable:true,writable:true,value:original});else Reflect.deleteProperty(globalThis,'indexedDB');}
}

test('hosted journal preserves two same-path writers and confines legacy tokens to the legacy record',async()=>{
  await withFakeIndexedDB(async database=>{
      const scope='scope-123',base=file();
      const first:DraftRecord={scope,path:base.path,baseVersion:base.version,baseContent:base.content,content:'writer one',generation:1,updatedAt:'2026-09-11T12:00:00.000Z'};
      const second:DraftRecord={...first,content:'writer two',updatedAt:'2026-09-11T12:00:01.000Z'};
      const writerOne=new IndexedDBDraftJournal(),writerTwo=new IndexedDBDraftJournal();
      const firstToken=await writerOne.put(first),secondToken=await writerTwo.put(second);
      assert.notEqual(firstToken,secondToken);
      assert.deepEqual((await writerOne.list(scope)).map(value=>value.record.content).sort(),['writer one','writer two']);

      const recovery=new AutosaveCoordinator(scope,writerOne,new MemoryRepository([base]),60_000);
      await recovery.hydrate([base]);
      const recovered=recovery.getState(base.path);assert.equal(recovered?.kind,'conflict');
      if(recovered?.kind!=='conflict')throw Error('Expected both durable drafts to require recovery review.');
      assert.match(recovered.message,/Multiple recovered drafts/);
      recovery.dispose();

      const parsed=/^v2:([a-f0-9]{64}\.[a-f0-9]{32}):([a-f0-9]{64})$/.exec(firstToken);assert.ok(parsed);
      const [,firstRecordID,firstETag]=parsed;const targetID=firstRecordID.slice(0,64);const stored=database.records.get(firstRecordID);assert.ok(stored);
      database.records.set(targetID,stored);database.records.delete(firstRecordID);
      const replacement:DraftRecord={...first,content:'legacy writer update',generation:2,updatedAt:'2026-09-11T12:00:02.000Z'};
      const replacementToken=await writerOne.put(replacement,firstETag);
      assert.equal(await writerOne.removeIf(scope,base.path,1,firstETag),false,'a stale legacy token cannot remove either current writer');
      assert.deepEqual((await writerOne.list(scope)).map(value=>value.record.content).sort(),['legacy writer update','writer two']);
      const updatedETag=replacementToken.split(':').at(-1);assert.ok(updatedETag);
      assert.equal(await writerOne.removeIf(scope,base.path,2,updatedETag),true,'a current legacy token removes only the deterministic legacy record');
      assert.deepEqual((await writerTwo.list(scope)).map(value=>value.record.content),['writer two']);
      assert.equal(await writerOne.removeIf(scope,base.path,1,secondToken),true);
      assert.equal((await writerOne.list(scope)).length,0);
  });
});

test('a stale recovered token forks the second writer instead of overwriting either draft',async()=>{
  await withFakeIndexedDB(async()=>{
    const scope='scope-123',base=file();
    const initial:DraftRecord={scope,path:base.path,baseVersion:base.version,baseContent:base.content,content:'shared recovered draft',generation:1,updatedAt:'2026-09-11T12:00:00.000Z'};
    const writerOne=new IndexedDBDraftJournal(),writerTwo=new IndexedDBDraftJournal();
    await writerOne.put(initial);
    const recoveredToken=(await writerOne.list(scope))[0]?.token;assert.ok(recoveredToken);
    const first:DraftRecord={...initial,content:'writer one after recovery',generation:2,updatedAt:'2026-09-11T12:00:01.000Z'};
    const second:DraftRecord={...initial,content:'writer two after recovery',generation:2,updatedAt:'2026-09-11T12:00:02.000Z'};
    const firstToken=await writerOne.put(first,recoveredToken),secondToken=await writerTwo.put(second,recoveredToken);
    assert.notEqual(firstToken,secondToken);
    assert.equal(await writerOne.removeIf(scope,base.path,1,recoveredToken),false);
    assert.deepEqual((await writerOne.list(scope)).map(value=>value.record.content).sort(),['writer one after recovery','writer two after recovery']);
  });
});

test('hydration treats a conditional cleanup miss as a replacement conflict',async()=>{
  const journal=new MemoryJournal(),base=file();
  const initial:DraftRecord={scope:'scope-123',path:base.path,baseVersion:base.version,baseContent:base.content,content:base.content,generation:1,updatedAt:'2026-09-11T12:00:00.000Z'};
  await journal.put(initial);
  const replacement:DraftRecord={...initial,content:'replacement writer',generation:2,updatedAt:'2026-09-11T12:00:01.000Z'};
  journal.removeIf=async()=>{journal.records.set(base.path,{record:replacement,token:'replacement-token'});return false;};
  const coordinator=new AutosaveCoordinator('scope-123',journal,new MemoryRepository([base]),60_000);
  await coordinator.hydrate([base]);
  const state=coordinator.getState(base.path);
  assert.equal(state?.kind,'conflict');
  assert.equal(state?.kind==='conflict'?state.local.content:null,'replacement writer');
  assert.equal(journal.records.get(base.path)?.record.content,'replacement writer');
  coordinator.dispose();
});

test('save completion treats a conditional cleanup miss as an in-flight replacement conflict',async()=>{
  const journal=new MemoryJournal(),base=file(),repository=new MemoryRepository([base]);
  const entered=Promise.withResolvers<void>(),release=Promise.withResolvers<void>();const save=repository.save.bind(repository);
  repository.save=async record=>{entered.resolve();await release.promise;return save(record);};
  const coordinator=new AutosaveCoordinator('scope-123',journal,repository,60_000);coordinator.seed(base);coordinator.edit(base,'saving writer');
  const saving=coordinator.flush(base.path);await entered.promise;
  const replacement:DraftRecord={scope:'scope-123',path:base.path,baseVersion:0,baseContent:'base',content:'replacement writer',generation:1,updatedAt:'2026-09-11T12:00:01.000Z'};
  journal.records.set(base.path,{record:replacement,token:'replacement-token'});release.resolve();await saving;
  const state=coordinator.getState(base.path);
  assert.equal(repository.files.get(base.path)?.content,'saving writer');
  assert.equal(state?.kind,'conflict');
  assert.equal(state?.kind==='conflict'?state.local.content:null,'replacement writer');
  assert.equal(journal.records.get(base.path)?.record.content,'replacement writer');
  coordinator.dispose();
});

test('journal commits before serialized save and debounce coalesces edits',async()=>{
  const journal=new MemoryJournal(),repository=new MemoryRepository([file()]);
  const coordinator=new AutosaveCoordinator('scope-123',journal,repository,5);
  coordinator.seed(file());coordinator.edit(file(),'one');coordinator.edit(file(),'two');await new Promise(resolve=>setTimeout(resolve,20));
  assert.equal(repository.files.get('workspace/a.txt')?.content,'two');
  assert.equal(repository.events.length,1);assert.equal(journal.events[0],'journal:workspace/a.txt:1');assert.equal(journal.events[1],'journal:workspace/a.txt:2');
  assert.equal(coordinator.getState('workspace/a.txt')?.kind,'clean');coordinator.dispose();
});

test('edit during an in-flight save rebases and writes a second CAS generation',async()=>{
  const journal=new MemoryJournal(),repository=new MemoryRepository([file()]);
  let release:()=>void=()=>{};repository.gate=new Promise<void>(resolve=>{release=resolve;});
  const coordinator=new AutosaveCoordinator('scope-123',journal,repository,1000);coordinator.seed(file());coordinator.edit(file(),'one');const first=coordinator.flush('workspace/a.txt');await tick();coordinator.edit(file(),'two');release();repository.gate=null;await first;await coordinator.flush('workspace/a.txt');
  assert.deepEqual(repository.events,['save:workspace/a.txt:0:one','save:workspace/a.txt:1:two']);assert.equal(repository.files.get('workspace/a.txt')?.content,'two');coordinator.dispose();
});

test('remote writes for multiple files never overlap',async()=>{
  const journal=new MemoryJournal(),repository=new MemoryRepository([file('workspace/a','a'),file('workspace/b','b')]);
  let active=0,maxActive=0;const original=repository.save.bind(repository);repository.save=async record=>{active+=1;maxActive=Math.max(maxActive,active);await tick();const result=await original(record);active-=1;return result;};
  const coordinator=new AutosaveCoordinator('scope-123',journal,repository,1000);for(const current of repository.files.values())coordinator.seed(current);coordinator.edit(file('workspace/a','a'),'A');coordinator.edit(file('workspace/b','b'),'B');await Promise.all([coordinator.flush('workspace/a'),coordinator.flush('workspace/b')]);assert.equal(maxActive,1);coordinator.dispose();
});

test('conflict retains local draft and keep mine performs a new guarded CAS',async()=>{
  const journal=new MemoryJournal(),repository=new MemoryRepository([file()]);const coordinator=new AutosaveCoordinator('scope-123',journal,repository,1000);coordinator.seed(file());coordinator.edit(file(),'local');repository.files.set('workspace/a.txt',file('workspace/a.txt','remote',1));await coordinator.flush('workspace/a.txt');assert.equal(coordinator.getState('workspace/a.txt')?.kind,'conflict');assert.equal(journal.records.get('workspace/a.txt')?.record.content,'local');await coordinator.keepMine('workspace/a.txt');assert.deepEqual(repository.files.get('workspace/a.txt'),file('workspace/a.txt','local',2));coordinator.dispose();
});

test('use remote cannot hide a newer edit made while journal cleanup is pending',async()=>{
  const journal=new MemoryJournal(),repository=new MemoryRepository([file()]);
  const coordinator=new AutosaveCoordinator('scope-123',journal,repository,1000);
  coordinator.seed(file());coordinator.edit(file(),'reviewed local');
  repository.files.set('workspace/a.txt',file('workspace/a.txt','reviewed remote',1));
  await coordinator.flush('workspace/a.txt');
  assert.equal(coordinator.getState('workspace/a.txt')?.kind,'conflict');
  const entered=Promise.withResolvers<void>(),release=Promise.withResolvers<void>();
  const removeIf=journal.removeIf.bind(journal);
  journal.removeIf=async(...input)=>{entered.resolve();await release.promise;return removeIf(...input);};
  const selection=coordinator.useRemote('workspace/a.txt');
  await entered.promise;
  coordinator.edit(file(),'newer local edit');
  await tick();release.resolve();await selection;
  const state=coordinator.getState('workspace/a.txt');
  assert.equal(state?.kind,'conflict');
  assert.equal(state?.kind==='conflict'?state.local.content:null,'newer local edit');
  assert.equal(journal.records.get('workspace/a.txt')?.record.content,'newer local edit');
  coordinator.dispose();
});

test('offline and invalid failures remain distinguishable and keep the journal',async()=>{
  for(const [failure,kind] of [[new AutosaveFailure('offline','offline'),'offlinePending'],[new AutosaveFailure('invalid','invalid'),'failed']] as const){const journal=new MemoryJournal(),repository=new MemoryRepository([file()]);repository.failure=failure;const coordinator=new AutosaveCoordinator('scope-123',journal,repository,1000);coordinator.seed(file());coordinator.edit(file(),'draft');await coordinator.flush('workspace/a.txt');assert.equal(coordinator.getState('workspace/a.txt')?.kind,kind);assert.equal(journal.records.has('workspace/a.txt'),true);coordinator.dispose();}
});

test('uncertain success is accepted only after matching independent readback',async()=>{
  const journal=new MemoryJournal(),repository=new MemoryRepository([file()]);repository.save=async record=>{repository.files.set(record.path,{path:record.path,content:record.content,version:record.baseVersion+1});throw new AutosaveFailure('uncertain','response lost');};const coordinator=new AutosaveCoordinator('scope-123',journal,repository,1000);coordinator.seed(file());coordinator.edit(file(),'saved');await coordinator.flush('workspace/a.txt');assert.equal(coordinator.getState('workspace/a.txt')?.kind,'clean');assert.equal(journal.records.size,0);coordinator.dispose();
});

test('hydration resumes a journaled draft and detects divergent recovery',async()=>{
  const journal=new MemoryJournal(),base=file();await journal.put({scope:'scope-123',path:base.path,baseVersion:0,baseContent:'base',content:'draft',generation:1,updatedAt:new Date().toISOString()});const repository=new MemoryRepository([base]);const coordinator=new AutosaveCoordinator('scope-123',journal,repository,1000);await coordinator.hydrate([base]);assert.equal(coordinator.getState(base.path)?.kind,'dirtyJournaled');await coordinator.flush(base.path);assert.equal(repository.files.get(base.path)?.content,'draft');
  await journal.put({scope:'scope-123',path:base.path,baseVersion:1,baseContent:'draft',content:'local-again',generation:2,updatedAt:new Date().toISOString()});repository.files.set(base.path,file(base.path,'remote-again',2));const recovered=new AutosaveCoordinator('scope-123',journal,repository,1000);await recovered.hydrate([...repository.files.values()]);assert.equal(recovered.getState(base.path)?.kind,'conflict');coordinator.dispose();recovered.dispose();
});

test('journal failure blocks remote save instead of pretending crash recovery',async()=>{
  const journal=new MemoryJournal();journal.failPut=true;const repository=new MemoryRepository([file()]);const coordinator=new AutosaveCoordinator('scope-123',journal,repository,0);coordinator.seed(file());coordinator.edit(file(),'draft');await tick();await coordinator.flush('workspace/a.txt');assert.equal(coordinator.getState('workspace/a.txt')?.kind,'failed');assert.equal(repository.events.length,0);coordinator.dispose();
});

test('retry re-journals a draft after local journal storage recovers',async()=>{
  const journal=new MemoryJournal();journal.failPut=true;const repository=new MemoryRepository([file()]);const coordinator=new AutosaveCoordinator('scope-123',journal,repository,1000);coordinator.seed(file());coordinator.edit(file(),'draft');await tick();assert.equal(coordinator.getState('workspace/a.txt')?.kind,'failed');journal.failPut=false;await coordinator.retry('workspace/a.txt');assert.equal(coordinator.getState('workspace/a.txt')?.kind,'clean');assert.equal(repository.files.get('workspace/a.txt')?.content,'draft');coordinator.dispose();
});

test('failed uncertainty readback remains retryable and keeps encrypted journal evidence',async()=>{
  const journal=new MemoryJournal(),repository=new MemoryRepository([file()]);repository.failure=new AutosaveFailure('uncertain','response lost');repository.readFailure=new AutosaveFailure('offline','readback offline');const coordinator=new AutosaveCoordinator('scope-123',journal,repository,1000);coordinator.seed(file());coordinator.edit(file(),'draft');await coordinator.flush('workspace/a.txt');const state=coordinator.getState('workspace/a.txt');assert.equal(state?.kind,'offlinePending');assert.equal(journal.records.has('workspace/a.txt'),true);coordinator.dispose();
});

test('workspace draft purge is bounded and preserves every other workspace',async()=>{
  const deletedScope='deleted-scope';const retainedScope='retained-scope';
  const records=new Map<string,DraftPurgeEntry>([
    [`${'a'.repeat(64)}.${'1'.repeat(32)}`,{id:`${'a'.repeat(64)}.${'1'.repeat(32)}`,scope:deletedScope}],
    ['b'.repeat(64),{id:'b'.repeat(64),scope:retainedScope}],
    ['c'.repeat(64),{id:'c'.repeat(64),scope:deletedScope}],
  ]);
  let keyReferenceCleared=false;
  const removed=await purgeDraftScope({scope:deletedScope,maximumRecords:8,read:async limit=>[...records.values()].slice(0,limit),remove:async ids=>{for(const id of ids)records.delete(id);},clearKeyReference:()=>{keyReferenceCleared=true;}});
  assert.equal(removed,2);assert.deepEqual([...records.values()],[{id:'b'.repeat(64),scope:retainedScope}]);assert.equal(keyReferenceCleared,true);
});

test('workspace draft purge fails closed without clearing the key reference',async()=>{
  const scope='deleted-scope';const record={id:'a'.repeat(64),scope} as const;let keyReferenceCleared=false;
  await assert.rejects(purgeDraftScope({scope,maximumRecords:8,read:async()=>[record],remove:async()=>{throw Error('injected IndexedDB delete failure');},clearKeyReference:()=>{keyReferenceCleared=true;}}),/injected IndexedDB delete failure/);
  assert.equal(keyReferenceCleared,false);
  let removeCalled=false;
  await assert.rejects(purgeDraftScope({scope,maximumRecords:1,read:async()=>[record,{id:'b'.repeat(64),scope:'other-scope'}],remove:async()=>{removeCalled=true;},clearKeyReference:()=>{keyReferenceCleared=true;}}),/bounded journal limit/);
  assert.equal(removeCalled,false);assert.equal(keyReferenceCleared,false);
});

test('account-deletion drain waits for a queued draft write before purging',async()=>{
  const started=Promise.withResolvers<void>(),release=Promise.withResolvers<void>();const entries=new Map<string,DraftPurgeEntry>();const id='d'.repeat(64);
  const journal:DraftJournal={
    put:async record=>{started.resolve();await release.promise;entries.set(id,{id,scope:record.scope});return 'token';},
    removeIf:async()=>false,
    list:async()=>[],
  };
  const coordinator=new AutosaveCoordinator('deleted-scope',journal,new MemoryRepository([file()]),10_000);coordinator.seed(file());coordinator.edit(file(),'queued draft');await started.promise;
  let cleanupFinished=false;
  const cleanup=(async()=>{await coordinator.disposeAndDrain();await purgeDraftScope({scope:'deleted-scope',maximumRecords:8,read:async limit=>[...entries.values()].slice(0,limit),remove:async ids=>{for(const target of ids)entries.delete(target);},clearKeyReference:()=>undefined});cleanupFinished=true;})();
  await tick();assert.equal(cleanupFinished,false);release.resolve();await cleanup;assert.equal(entries.size,0);await tick();assert.equal(entries.size,0);
});
