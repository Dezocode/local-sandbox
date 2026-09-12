import{EncryptedDraftJournal,JournalWriteConflict}from'./draft-journal.js';
import{normalizeVault,openVaultWithSession,sealWithSession,validPath,validVault}from'./vault.js';

const encoder=new TextEncoder();
const MESSAGE_TARGET='messages';
const clone=value=>JSON.parse(JSON.stringify(value));
const same=(left,right)=>JSON.stringify(left)===JSON.stringify(right);
const fileTarget=path=>`file:${path}`;

export class LocalAutosaveError extends Error{
  constructor(code,message){super(message);this.name='LocalAutosaveError';this.code=code;}
}

function stateMutation(state){return state&&state.kind!=='clean'?state.mutation:null;}

function validMessages(messages){
  validVault({version:1,files:{},messages});
  return messages;
}

function validMutation(mutation){
  if(!mutation||mutation.version!==1||!Number.isSafeInteger(mutation.generation)||mutation.generation<1||typeof mutation.updatedAt!=='string'||Number.isNaN(Date.parse(mutation.updatedAt)))throw Error('Invalid encrypted recovery draft.');
  if(mutation.kind==='file'){
    if(!validPath(mutation.path)||mutation.target!==fileTarget(mutation.path)||!Number.isSafeInteger(mutation.baseGeneration)||mutation.baseGeneration< -1||mutation.content!==null&&(typeof mutation.content!=='string'||encoder.encode(mutation.content).length>64000))throw Error('Invalid encrypted file recovery draft.');
    if(mutation.baseGeneration===-1?mutation.baseContent!==null:typeof mutation.baseContent!=='string'||encoder.encode(mutation.baseContent).length>64000)throw Error('Invalid encrypted file recovery base.');
    return mutation;
  }
  if(mutation.kind==='messages'){
    if(mutation.target!==MESSAGE_TARGET||!Number.isSafeInteger(mutation.baseGeneration)||mutation.baseGeneration<0||!Array.isArray(mutation.messages))throw Error('Invalid encrypted session recovery draft.');
    validMessages(mutation.messages);return mutation;
  }
  throw Error('Invalid encrypted recovery draft kind.');
}

function desiredSignature(mutation){return mutation.kind==='file'?JSON.stringify([mutation.path,mutation.content]):JSON.stringify(mutation.messages);}

function storageFailure(error){
  if(error instanceof LocalAutosaveError)return error;
  if(error instanceof JournalWriteConflict)return new LocalAutosaveError('conflict',error.message);
  if(globalThis.navigator?.onLine===false&&error instanceof DOMException&&['AbortError','UnknownError'].includes(error.name))return new LocalAutosaveError('offline','The encrypted draft is safe, but browser storage is temporarily unavailable. Retry when the device is ready.');
  if(error instanceof DOMException&&error.name==='QuotaExceededError')return new LocalAutosaveError('invalid','The browser storage quota is full. Export a backup, then remove unneeded content.');
  return new LocalAutosaveError('storage',error instanceof Error?error.message:'Encrypted local storage failed.');
}

export class LocalAutosaveEngine{
  static async open({vault,envelope,session,vaultStore,draftStore,debounceMs=650}){
    const normalized=normalizeVault(vault);
    let committedEnvelope=envelope??null;
    if(!envelope||!same(vault,normalized)){
      const migrated=await sealWithSession(normalized,session);
      if(!await vaultStore.compareAndSwap(envelope??null,migrated))throw new LocalAutosaveError('conflict','The vault changed in another tab while it was opening. Lock and unlock again.');
      committedEnvelope=migrated;
    }
    const engine=new LocalAutosaveEngine({vault:normalized,envelope:committedEnvelope,session,vaultStore,draftStore,debounceMs});
    await engine.recover();
    return engine;
  }

  constructor({vault,envelope,session,vaultStore,draftStore,debounceMs}){
    if(!Number.isFinite(debounceMs)||debounceMs<0)throw Error('Autosave debounce cannot be negative.');
    this.committed=normalizeVault(vault);
    this.envelope=envelope;
    this.session=session;
    this.vaultStore=vaultStore;
    this.journal=new EncryptedDraftJournal(draftStore,session);
    this.debounceMs=debounceMs;
    this.states=new Map();
    this.timers=new Map();
    this.listeners=new Set();
    this.tail=Promise.resolve();
    this.revision=0;
    this.disposed=false;
    this.replacing=false;
  }

  subscribe(listener){this.listeners.add(listener);return()=>this.listeners.delete(listener);}
  getRevision(){return this.revision;}
  getState(path){return this.states.get(fileTarget(path))??{kind:'clean'};}
  getMessageState(){return this.states.get(MESSAGE_TARGET)??{kind:'clean'};}
  getVaultRevision(){return this.committed.autosave.revision;}
  getFileGeneration(path){const pending=stateMutation(this.states.get(fileTarget(path)));return pending?.kind==='file'?pending.generation:this.committed.autosave.fileGenerations[path]??0;}

  listFiles(){
    const files={...this.committed.files};
    for(const state of this.states.values())if(state.mutation?.kind==='file'){if(state.mutation.content===null)delete files[state.mutation.path];else files[state.mutation.path]=state.mutation.content;}
    return Object.keys(files).sort().map(path=>({path,content:files[path]}));
  }

  fileContent(path){
    const pending=stateMutation(this.states.get(fileTarget(path)));
    return pending?.kind==='file'?(pending.content??undefined):this.committed.files[path];
  }

  messages(){
    const pending=stateMutation(this.states.get(MESSAGE_TARGET));
    return clone(pending?.kind==='messages'?pending.messages:this.committed.messages);
  }

  createFile(path){
    this.assertActive();
    if(!validPath(path))return Promise.reject(Error('Use a regular relative file path inside the workspace.'));
    if(this.fileContent(path)!==undefined)return Promise.reject(Error('That file already exists.'));
    if(this.listFiles().length>=1000)return Promise.reject(Error('The vault is limited to 1,000 files.'));
    return this.editFile(path,'',true);
  }

  editFile(path,content,allowCreate=false){
    this.assertActive();
    if(!validPath(path))return Promise.reject(Error('Invalid workspace path.'));
    if(typeof content!=='string'||encoder.encode(content).length>64000)return Promise.reject(Error('Files are limited to 64 KB.'));
    const target=fileTarget(path),state=this.states.get(target),previous=stateMutation(state);
    const committedContent=this.committed.files[path];
    if(!previous&&committedContent===undefined&&!allowCreate)return Promise.reject(Error('Create the file before editing it.'));
    if(!previous&&committedContent===content)return Promise.resolve();
    const mutation={
      version:1,kind:'file',target,path,content,
      baseGeneration:previous?.kind==='file'?previous.baseGeneration:(committedContent===undefined?-1:this.committed.autosave.fileGenerations[path]),
      baseContent:previous?.kind==='file'?previous.baseContent:(committedContent??null),
      generation:(previous?.generation??0)+1,
      updatedAt:new Date().toISOString(),
    };
    const conflict=state?.kind==='conflict';
    this.setState(target,conflict?{...state,mutation,pendingJournal:true}:{kind:'dirty',mutation,token:state?.token});
    return this.enqueue(()=>this.writeLatestJournal(target));
  }

  deleteFile(path){
    this.assertActive();
    if(!validPath(path))return Promise.reject(Error('Invalid workspace path.'));
    const target=fileTarget(path),state=this.states.get(target),previous=stateMutation(state),committedContent=this.committed.files[path];
    if(!previous&&committedContent===undefined)return Promise.resolve();
    if(previous?.kind==='file'&&previous.content===null)return Promise.resolve();
    const mutation={
      version:1,kind:'file',target,path,content:null,
      baseGeneration:previous?.kind==='file'?previous.baseGeneration:(committedContent===undefined?-1:this.committed.autosave.fileGenerations[path]),
      baseContent:previous?.kind==='file'?previous.baseContent:(committedContent??null),
      generation:(previous?.generation??0)+1,
      updatedAt:new Date().toISOString(),
    };
    const conflict=state?.kind==='conflict';
    this.setState(target,conflict?{...state,mutation,pendingJournal:true}:{kind:'dirty',mutation,token:state?.token});
    return this.enqueue(()=>this.writeLatestJournal(target));
  }

  addMessage(role,text){
    this.assertActive();
    if(!['Oracle','Locally response'].includes(role)||typeof text!=='string'||!text||text.length>12000)return Promise.reject(Error('Keep messages between 1 and 12,000 characters.'));
    const state=this.states.get(MESSAGE_TARGET),previous=stateMutation(state);
    const messages=previous?.kind==='messages'?clone(previous.messages):clone(this.committed.messages);
    if(messages.length>=1000)return Promise.reject(Error('The vault is limited to 1,000 session messages.'));
    messages.push({role,text,at:new Date().toISOString()});
    const mutation={version:1,kind:'messages',target:MESSAGE_TARGET,baseGeneration:previous?.kind==='messages'?previous.baseGeneration:this.committed.autosave.messagesGeneration,messages,generation:(previous?.generation??0)+1,updatedAt:new Date().toISOString()};
    const conflict=state?.kind==='conflict';
    this.setState(MESSAGE_TARGET,conflict?{...state,mutation,pendingJournal:true}:{kind:'dirty',mutation,token:state?.token});
    return this.enqueue(()=>this.writeLatestJournal(MESSAGE_TARGET));
  }

  flushFile(path){return this.flushTarget(fileTarget(path));}
  flushMessages(){return this.flushTarget(MESSAGE_TARGET);}

  flushAll(){
    for(const target of this.timers.keys())this.clearTimer(target);
    return this.enqueue(async()=>{
      for(const target of [...this.states.keys()])await this.persistTarget(target);
      const blocker=[...this.states.values()].find(state=>state.kind!=='clean');
      if(blocker)throw new LocalAutosaveError(blocker.kind,blocker.message??'Resolve pending local changes before exporting a backup.');
    });
  }

  retryFile(path){return this.retryTarget(fileTarget(path));}
  retryMessages(){return this.retryTarget(MESSAGE_TARGET);}
  useSavedFile(path){return this.useSavedTarget(fileTarget(path));}
  keepDraftFile(path){return this.keepDraftTarget(fileTarget(path));}
  useSavedMessages(){return this.useSavedTarget(MESSAGE_TARGET);}
  keepDraftMessages(){return this.keepDraftTarget(MESSAGE_TARGET);}

  async exportEnvelope(){
    this.assertActive();this.replacing=true;
    try{await this.flushAll();return clone(this.envelope);}
    finally{this.replacing=false;}
  }

  replaceVault(vault,session){
    this.assertActive();this.replacing=true;
    for(const target of this.timers.keys())this.clearTimer(target);
    return this.enqueue(async()=>{
      try{
        const normalized=normalizeVault(vault);
        const nextEnvelope=await sealWithSession(normalized,session);
        if(!await this.vaultStore.compareAndSwapAndClearDrafts(this.envelope,nextEnvelope))throw new LocalAutosaveError('conflict','The vault changed in another tab before restore. Lock and unlock again.');
        this.committed=normalized;this.envelope=nextEnvelope;this.session=session;this.journal.rekey(session);this.states.clear();this.changed();
      }finally{this.replacing=false;}
    });
  }

  dispose(){
    this.disposed=true;
    for(const target of this.timers.keys())this.clearTimer(target);
    this.listeners.clear();
  }

  async recover(){
    const grouped=new Map();
    for(const entry of await this.journal.list()){
      const mutation=validMutation(entry.payload);
      const entries=grouped.get(mutation.target)??[];entries.push({mutation,token:entry.token});grouped.set(mutation.target,entries);
    }
    for(const [target,entries]of grouped){
      entries.sort((left,right)=>right.mutation.updatedAt.localeCompare(left.mutation.updatedAt)||right.mutation.generation-left.mutation.generation);
      const latest=entries[0];
      if(entries.some(entry=>desiredSignature(entry.mutation)!==desiredSignature(latest.mutation))){
        this.setState(target,{kind:'conflict',mutation:latest.mutation,token:latest.token,message:`${entries.length} recovered drafts differ. The newest is loaded; keep it or use the saved vault.`,alternatives:entries.length});
      }else if(this.wasApplied(latest.mutation)){
        await this.journal.removeAll(target);
      }else if(this.baseMatches(latest.mutation)){
        this.setState(target,{kind:'dirtyJournaled',mutation:latest.mutation,token:latest.token,recovered:true});this.schedule(target);
      }else{
        this.setState(target,{kind:'conflict',mutation:latest.mutation,token:latest.token,message:'The recovered draft and saved vault both changed.',alternatives:entries.length});
      }
    }
  }

  assertActive(){
    if(this.disposed)throw Error('The vault is locked.');
    if(this.replacing)throw Error('Wait for the vault restore to finish.');
  }

  enqueue(operation){
    const result=this.tail.then(operation);
    this.tail=result.catch(()=>undefined);
    return result;
  }

  async writeLatestJournal(target){
    const state=this.states.get(target);
    if(!state||(!['dirty','conflict'].includes(state.kind))||(state.kind==='conflict'&&!state.pendingJournal))return;
    const captured=state.mutation;
    try{
      const token=await this.journal.put(captured,state.token);
      const current=this.states.get(target);
      if(!current)return;
      if(current.mutation.generation!==captured.generation){
        if(!current.token||current.token.id===token.id)this.setState(target,{...current,token});
        return;
      }
      if(current.kind==='conflict')this.setState(target,{...current,token,pendingJournal:false});
      else{this.setState(target,{kind:'dirtyJournaled',mutation:captured,token});if(!this.disposed)this.schedule(target);}
    }catch(error){
      const failure=storageFailure(error),current=this.states.get(target);
      if(!current||current.mutation.generation!==captured.generation)return;
      this.setState(target,failure.code==='conflict'
        ?{kind:'conflict',mutation:captured,token:current.token,message:failure.message,alternatives:1}
        :{kind:failure.code==='offline'?'offline':'failed',mutation:captured,token:current.token,journalPending:true,retryable:failure.code!=='invalid',code:failure.code,message:failure.message});
    }
  }

  flushTarget(target){
    this.clearTimer(target);
    return this.enqueue(()=>this.persistTarget(target));
  }

  async persistTarget(target){
    const state=this.states.get(target);
    if(!state||['conflict','dirty','failed'].includes(state.kind))return;
    if(!state.token)return;
    const captured={mutation:state.mutation,token:state.token};
    if(this.wasApplied(captured.mutation)){await this.finishSaved(target,captured);return;}
    if(!this.baseMatches(captured.mutation)){
      this.setState(target,{kind:'conflict',...captured,message:'The saved vault changed after this draft began.',alternatives:1});return;
    }
    this.setState(target,{kind:'saving',...captured});
    let nextVault,nextEnvelope;
    try{
      nextVault=this.apply(captured.mutation);
      nextEnvelope=await sealWithSession(nextVault,this.session);
      if(!await this.vaultStore.compareAndSwap(this.envelope,nextEnvelope)){await this.reconcileExternal(target,captured);return;}
    }catch(error){
      const failure=storageFailure(error);
      this.setState(target,{kind:failure.code==='offline'?'offline':'failed',...captured,retryable:failure.code!=='invalid',code:failure.code,message:failure.message});return;
    }
    this.committed=nextVault;this.envelope=nextEnvelope;
    await this.finishSaved(target,captured);
  }

  async reconcileExternal(target,captured){
    let observedEnvelope;
    try{observedEnvelope=await this.vaultStore.read();}
    catch(error){
      const failure=storageFailure(error);this.setState(target,{kind:failure.code==='offline'?'offline':'failed',...captured,retryable:true,code:failure.code,message:failure.message});return;
    }
    if(!observedEnvelope){this.setState(target,{kind:'conflict',...captured,message:'The saved vault was removed in another tab.',alternatives:1});return;}
    let observed;
    try{observed=normalizeVault(await openVaultWithSession(observedEnvelope,this.session));}
    catch(error){this.setState(target,{kind:'conflict',...captured,message:error.message,alternatives:1});return;}
    this.committed=observed;this.envelope=observedEnvelope;
    if(this.wasApplied(captured.mutation)){await this.finishSaved(target,captured);return;}
    if(this.baseMatches(captured.mutation)){
      this.setState(target,{kind:'dirtyJournaled',...captured,message:'Another file changed in a different tab. Autosave will retry.'});this.schedule(target);return;
    }
    this.setState(target,{kind:'conflict',...captured,message:'This item changed in another tab. Review both versions.',alternatives:1});
  }

  async finishSaved(target,captured){
    let removed=false;
    try{removed=await this.journal.removeIf(captured.token);}
    catch(error){
      const failure=storageFailure(error),current=this.states.get(target),newer=current&&current.mutation.generation!==captured.mutation.generation;
      this.setState(target,newer
        ?{kind:'failed',mutation:this.rebase(current.mutation),token:captured.token,journalPending:true,retryable:true,code:failure.code,message:`The earlier edit saved, but the newer draft needs recovery cleanup. ${failure.message}`}
        :{kind:'failed',...captured,retryable:true,code:failure.code,message:`The vault saved, but recovery cleanup failed. ${failure.message}`});return;
    }
    if(!removed){
      const current=this.states.get(target),newer=current&&current.mutation.generation!==captured.mutation.generation;
      this.setState(target,{kind:'conflict',mutation:newer?this.rebase(current.mutation):captured.mutation,token:captured.token,message:'The recovery draft changed in another tab after the vault saved.',alternatives:1});return;
    }
    const current=this.states.get(target);
    if(!current||current.mutation.generation===captured.mutation.generation){this.states.delete(target);this.changed();return;}
    const rebased=this.rebase(current.mutation);
    this.setState(target,{kind:'dirty',mutation:rebased});
  }

  retryTarget(target){
    const state=this.states.get(target);
    if(!state||state.kind==='conflict')return Promise.resolve();
    if(['failed','offline'].includes(state.kind)&&(!state.token||state.journalPending)){this.setState(target,{kind:'dirty',mutation:state.mutation,token:state.token});return this.enqueue(async()=>{await this.writeLatestJournal(target);await this.persistTarget(target);});}
    if(['failed','offline'].includes(state.kind)){this.setState(target,{kind:'dirtyJournaled',mutation:state.mutation,token:state.token});return this.flushTarget(target);}
    return this.flushTarget(target);
  }

  useSavedTarget(target){
    this.clearTimer(target);
    return this.enqueue(async()=>{await this.journal.removeAll(target);this.states.delete(target);this.changed();});
  }

  keepDraftTarget(target){
    this.clearTimer(target);
    return this.enqueue(async()=>{
      const state=this.states.get(target);if(state?.kind!=='conflict')return;
      await this.journal.removeAll(target);
      const mutation=this.rebase({...state.mutation,generation:state.mutation.generation+1,updatedAt:new Date().toISOString()});
      this.setState(target,{kind:'dirty',mutation});
      await this.writeLatestJournal(target);
      await this.persistTarget(target);
    });
  }

  baseMatches(mutation){
    if(mutation.kind==='file'){
      const content=this.committed.files[mutation.path],generation=this.committed.autosave.fileGenerations[mutation.path];
      return mutation.baseGeneration===-1?content===undefined:generation===mutation.baseGeneration&&content===mutation.baseContent;
    }
    return this.committed.autosave.messagesGeneration===mutation.baseGeneration;
  }

  wasApplied(mutation){
    if(mutation.kind==='file')return mutation.content===null?this.committed.files[mutation.path]===undefined:this.committed.files[mutation.path]===mutation.content&&(this.committed.autosave.fileGenerations[mutation.path]??-1)>mutation.baseGeneration;
    return same(this.committed.messages,mutation.messages)&&this.committed.autosave.messagesGeneration>mutation.baseGeneration;
  }

  apply(mutation){
    const next=clone(this.committed);next.autosave.revision+=1;
    if(mutation.kind==='file'){
      if(mutation.content===null){delete next.files[mutation.path];delete next.autosave.fileGenerations[mutation.path];}
      else{next.files[mutation.path]=mutation.content;next.autosave.fileGenerations[mutation.path]=mutation.baseGeneration+1;}
    }else{
      next.messages=clone(mutation.messages);next.autosave.messagesGeneration=mutation.baseGeneration+1;
    }
    return normalizeVault(next);
  }

  rebase(mutation){
    if(mutation.kind==='file'){
      const content=this.committed.files[mutation.path];
      return{...mutation,baseGeneration:content===undefined?-1:this.committed.autosave.fileGenerations[mutation.path],baseContent:content??null,updatedAt:new Date().toISOString()};
    }
    return{...mutation,baseGeneration:this.committed.autosave.messagesGeneration,updatedAt:new Date().toISOString()};
  }

  schedule(target){
    this.clearTimer(target);
    this.timers.set(target,setTimeout(()=>{this.timers.delete(target);void this.flushTarget(target);},this.debounceMs));
  }

  clearTimer(target){const timer=this.timers.get(target);if(timer!==undefined){clearTimeout(timer);this.timers.delete(target);}}
  setState(target,state){this.states.set(target,state);this.changed();}
  changed(){this.revision+=1;for(const listener of this.listeners)listener();}
}
