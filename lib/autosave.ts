export type RemoteFile = Readonly<{path:string;content:string;version:number}>;

export type DraftRecord = Readonly<{
  scope:string;
  path:string;
  baseVersion:number;
  baseContent:string;
  content:string;
  generation:number;
  updatedAt:string;
}>;

export type JournaledDraft = Readonly<{record:DraftRecord;token:string}>;

export interface DraftJournal {
  put(record:DraftRecord,currentToken?:string):Promise<string>;
  removeIf(scope:string,path:string,generation:number,token:string):Promise<boolean>;
  list(scope:string):Promise<readonly JournaledDraft[]>;
}

export type DraftPurgeEntry = Readonly<{id:string;scope:string}>;

export async function purgeDraftScope(input: {
  scope:string;
  maximumRecords:number;
  read:(limit:number)=>Promise<readonly DraftPurgeEntry[]>;
  remove:(ids:readonly string[])=>Promise<void>;
  clearKeyReference:()=>void;
}):Promise<number> {
  if(input.scope.length<8||input.scope.length>80)throw new TypeError('Draft purge requires a valid workspace scope.');
  if(!Number.isSafeInteger(input.maximumRecords)||input.maximumRecords<1||input.maximumRecords>4_096)throw new TypeError('Draft purge record limit is invalid.');
  const readLimit=input.maximumRecords+1;
  const before=await input.read(readLimit);
  if(before.length>input.maximumRecords)throw new Error('Draft purge stopped because the bounded journal limit was exceeded.');
  const ids=new Set<string>();
  for(const entry of before){
    if(!/^[a-f0-9]{64}(?:\.[a-f0-9]{32})?$/.test(entry.id)||entry.scope.length<8||entry.scope.length>80||ids.has(entry.id))throw new Error('Draft purge found an invalid journal record.');
    ids.add(entry.id);
  }
  const targets=before.filter(entry=>entry.scope===input.scope).map(entry=>entry.id);
  await input.remove(targets);
  const after=await input.read(readLimit);
  if(after.length>input.maximumRecords||after.some(entry=>entry.scope===input.scope))throw new Error('Draft purge could not verify workspace removal.');
  input.clearKeyReference();
  return targets.length;
}

export interface FileRepository {
  save(record:Pick<DraftRecord,'path'|'baseVersion'|'content'>):Promise<RemoteFile>;
  read(path:string):Promise<RemoteFile|null>;
}

export type AutosaveFailureCode='offline'|'conflict'|'invalid'|'transient'|'uncertain'|'journal'|'unknown';

export class AutosaveFailure extends Error {
  readonly code:AutosaveFailureCode;
  readonly remote:RemoteFile|null;
  constructor(code:AutosaveFailureCode,message:string,remote:RemoteFile|null=null){super(message);this.name='AutosaveFailure';this.code=code;this.remote=remote;}
}

type LocalState=Readonly<{local:DraftRecord;token?:string}>;
export type AutosaveState=
  | Readonly<{kind:'clean';remote:RemoteFile}>
  | (Readonly<{kind:'dirtyMemory'}>&LocalState)
  | (Readonly<{kind:'dirtyJournaled';token:string}>&LocalState)
  | (Readonly<{kind:'saving';token:string}>&LocalState)
  | (Readonly<{kind:'offlinePending';token:string;message:string}>&LocalState)
  | (Readonly<{kind:'conflict';token:string;remote:RemoteFile|null;message:string}>&LocalState)
  | (Readonly<{kind:'failed';retryable:boolean;errorCode:AutosaveFailureCode;message:string}>&LocalState);

type TimerHandle=ReturnType<typeof setTimeout>;
type Listener=()=>void;

function localState(state:AutosaveState|undefined):LocalState|null {
  if(!state||state.kind==='clean')return null;
  return {local:state.local,...('token' in state&&state.token?{token:state.token}:{})};
}

function asFailure(error:unknown):AutosaveFailure {
  if(error instanceof AutosaveFailure)return error;
  return new AutosaveFailure('unknown',error instanceof Error?error.message:'Autosave failed.');
}

export class AutosaveCoordinator {
  private readonly scope:string;
  private readonly journal:DraftJournal;
  private readonly repository:FileRepository;
  private readonly debounceMs:number;
  private readonly states=new Map<string,AutosaveState>();
  private readonly journalTokens=new Map<string,string>();
  private readonly timers=new Map<string,TimerHandle>();
  private readonly listeners=new Set<Listener>();
  private journalTail:Promise<void>=Promise.resolve();
  private saveTail:Promise<void>=Promise.resolve();
  private revision=0;
  private disposed=false;

  constructor(
    scope:string,
    journal:DraftJournal,
    repository:FileRepository,
    debounceMs=650,
  ){
    this.scope=scope;this.journal=journal;this.repository=repository;this.debounceMs=debounceMs;
    if(!scope)throw new Error('Autosave requires an opaque workspace scope.');
    if(debounceMs<0)throw new Error('Autosave debounce cannot be negative.');
  }

  subscribe(listener:Listener):()=>void {this.listeners.add(listener);return()=>this.listeners.delete(listener);}
  getRevision():number{return this.revision;}
  getState(path:string):AutosaveState|undefined{return this.states.get(path);}
  allStates():ReadonlyMap<string,AutosaveState>{return new Map(this.states);}

  seed(file:RemoteFile):void {
    const current=this.states.get(file.path);
    if(!current||current.kind==='clean'){
      if(current?.kind==='clean'&&current.remote.version===file.version&&current.remote.content===file.content)return;
      this.setState(file.path,{kind:'clean',remote:file});
    }
  }

  edit(file:RemoteFile,content:string):void {
    if(this.disposed)throw new AutosaveFailure('journal','This autosave session is closed.');
    const existing=this.states.get(file.path);
    if(existing&&existing.kind!=='clean'&&existing.token)this.journalTokens.set(file.path,existing.token);
    const pending=localState(existing);
    const base=pending?.local??{scope:this.scope,path:file.path,baseVersion:file.version,baseContent:file.content,content:file.content,generation:0,updatedAt:new Date(0).toISOString()};
    const draft:DraftRecord={...base,scope:this.scope,path:file.path,content,generation:base.generation+1,updatedAt:new Date().toISOString()};
    this.clearTimer(file.path);
    if(existing?.kind==='conflict'){
      this.setState(file.path,{...existing,local:draft});
      this.enqueueJournal(draft,{remote:existing.remote,message:existing.message});
      return;
    }
    this.setState(file.path,{kind:'dirtyMemory',local:draft});
    this.enqueueJournal(draft);
  }

  async flush(path:string):Promise<void> {
    this.clearTimer(path);
    await this.journalTail;
    const operation=this.saveTail.then(()=>this.saveOne(path));
    this.saveTail=operation.catch(()=>undefined);
    await operation;
  }

  async retry(path:string):Promise<void>{
    const state=this.states.get(path);
    if(!state||state.kind==='clean'||state.kind==='conflict'||state.kind==='dirtyMemory')return;
    if(state.kind==='failed'&&!state.token){
      this.setState(path,{kind:'dirtyMemory',local:state.local});
      this.enqueueJournal(state.local);
      await this.journalTail;
    }
    await this.flush(path);
  }

  async useRemote(path:string):Promise<void>{
    const state=this.states.get(path);
    if(state?.kind!=='conflict')return;
    if(!state.remote)throw new AutosaveFailure('conflict','The remote file no longer exists.',null);
    const removed=await this.journal.removeIf(this.scope,path,state.local.generation,state.token);
    const current=this.states.get(path);
    if(current?.kind!=='conflict'||current.local.generation!==state.local.generation||current.token!==state.token)return;
    if(!removed){await this.recoverStaleCleanup(path,state.local,state.remote,'The local draft changed while the remote version was being selected.');throw new AutosaveFailure('journal','The local draft changed while the remote version was being selected.');}
    this.journalTokens.delete(path);
    const alternate=await this.latestJournal(path);
    if(alternate){this.adoptConflict(path,alternate,state.remote,'Another recovered draft still needs review.');return;}
    this.setState(path,{kind:'clean',remote:state.remote});
  }

  async keepMine(path:string):Promise<void>{
    const state=this.states.get(path);
    if(state?.kind!=='conflict')return;
    if(!state.remote)throw new AutosaveFailure('conflict','The remote file no longer exists.',null);
    const rebased:DraftRecord={...state.local,baseVersion:state.remote.version,baseContent:state.remote.content,generation:state.local.generation+1,updatedAt:new Date().toISOString()};
    this.setState(path,{kind:'dirtyMemory',local:rebased});
    this.enqueueJournal(rebased);
    await this.flush(path);
  }

  async hydrate(remoteFiles:readonly RemoteFile[]):Promise<void>{
    const remoteByPath=new Map(remoteFiles.map(file=>[file.path,file]));
    const grouped=new Map<string,JournaledDraft[]>();
    for(const draft of await this.journal.list(this.scope)){
      const current=grouped.get(draft.record.path)??[];
      current.push(draft);grouped.set(draft.record.path,current);
    }
    for(const file of remoteFiles)this.seed(file);
    for(const [path,drafts] of grouped){
      drafts.sort((left,right)=>right.record.generation-left.record.generation||right.record.updatedAt.localeCompare(left.record.updatedAt));
      const latest=drafts[0];
      if(!latest)continue;
      const remote=remoteByPath.get(path)??null;
      this.journalTokens.set(path,latest.token);
      if(drafts.length>1||!remote){
        this.setState(path,{kind:'conflict',local:latest.record,token:latest.token,remote,message:drafts.length>1?'Multiple recovered drafts need review.':'The remote file is missing.'});
      }else if(remote.content===latest.record.content){
        const removed=await this.journal.removeIf(this.scope,path,latest.record.generation,latest.token);
        if(!removed){await this.recoverStaleCleanup(path,latest.record,remote,'The recovered draft changed while saved content was being confirmed.');continue;}
        this.journalTokens.delete(path);
        const alternate=await this.latestJournal(path);
        if(alternate){this.adoptConflict(path,alternate,remote,'Another recovered draft appeared while saved content was being confirmed.');continue;}
        this.setState(path,{kind:'clean',remote});
      }else if(remote.version===latest.record.baseVersion&&remote.content===latest.record.baseContent){
        this.setState(path,{kind:'dirtyJournaled',local:latest.record,token:latest.token});
        this.schedule(path);
      }else{
        this.setState(path,{kind:'conflict',local:latest.record,token:latest.token,remote,message:'Recovered draft and remote file both changed.'});
      }
    }
  }

  dispose():void {this.disposed=true;for(const timer of this.timers.values())clearTimeout(timer);this.timers.clear();this.listeners.clear();}

  async disposeAndDrain():Promise<void>{this.dispose();await Promise.all([this.journalTail,this.saveTail]);}

  private enqueueJournal(draft:DraftRecord,conflict?:{remote:RemoteFile|null;message:string}):void {
    const operation=this.journalTail.then(async()=>{
      if(this.disposed)return;
      try{
        const currentToken=this.journalTokens.get(draft.path);
        const token=await this.journal.put(draft,currentToken);
        this.journalTokens.set(draft.path,token);
        if(this.disposed)return;
        const current=this.states.get(draft.path);
        if(!current||current.kind==='clean'||current.local.generation!==draft.generation)return;
        if(conflict){this.setState(draft.path,{kind:'conflict',local:draft,token,remote:conflict.remote,message:conflict.message});return;}
        this.setState(draft.path,{kind:'dirtyJournaled',local:draft,token});
        this.schedule(draft.path);
      }catch(error){
        this.journalTokens.delete(draft.path);
        const current=this.states.get(draft.path);
        if(current&&current.kind!=='clean'&&current.local.generation===draft.generation){
          this.setState(draft.path,{kind:'failed',local:draft,retryable:false,errorCode:'journal',message:error instanceof Error?error.message:'Draft journal failed.'});
        }
      }
    });
    this.journalTail=operation.catch(()=>undefined);
  }

  private schedule(path:string):void {
    if(this.disposed)return;
    this.clearTimer(path);
    this.timers.set(path,setTimeout(()=>{this.timers.delete(path);void this.flush(path);},this.debounceMs));
  }

  private clearTimer(path:string):void {const timer=this.timers.get(path);if(timer!==undefined){clearTimeout(timer);this.timers.delete(path);}}

  private async saveOne(path:string):Promise<void>{
    const state=this.states.get(path);
    if(!state||state.kind==='clean'||state.kind==='dirtyMemory'||state.kind==='conflict')return;
    if(!state.token)return;
    const captured={local:state.local,token:state.token};
    this.setState(path,{kind:'saving',...captured});
    let saved:RemoteFile;
    try{
      saved=await this.repository.save({path,baseVersion:captured.local.baseVersion,content:captured.local.content});
    }catch(error){
      const failure=asFailure(error);
      if(failure.code==='uncertain'){
        let observed:RemoteFile|null;
        try{observed=await this.repository.read(path);}
        catch(readError){
          const readFailure=asFailure(readError);
          if(readFailure.code==='offline')this.setState(path,{kind:'offlinePending',...captured,message:readFailure.message});
          else this.setState(path,{kind:'failed',...captured,retryable:true,errorCode:readFailure.code,message:`The save result is still unknown: ${readFailure.message}`});
          return;
        }
        if(observed?.content===captured.local.content)saved=observed;
        else if(observed?.version===captured.local.baseVersion&&observed.content===captured.local.baseContent){
          this.setState(path,{kind:'dirtyJournaled',...captured});this.schedule(path);return;
        }else{
          this.setState(path,{kind:'conflict',...captured,remote:observed,message:'The write result was uncertain and readback diverged.'});return;
        }
      }else if(failure.code==='conflict'){
        let remote=failure.remote;
        if(!remote){
          try{remote=await this.repository.read(path);}
          catch(readError){
            const readFailure=asFailure(readError);
            this.setState(path,{kind:'failed',...captured,retryable:true,errorCode:readFailure.code,message:`The conflict could not be read back: ${readFailure.message}`});
            return;
          }
        }
        this.setState(path,{kind:'conflict',...captured,remote,message:failure.message});return;
      }else if(failure.code==='offline'){
        this.setState(path,{kind:'offlinePending',...captured,message:failure.message});return;
      }else{
        this.setState(path,{kind:'failed',...captured,retryable:failure.code==='transient'||failure.code==='unknown',errorCode:failure.code,message:failure.message});return;
      }
    }
    if(saved.path!==path||saved.content!==captured.local.content||saved.version<=captured.local.baseVersion){
      this.setState(path,{kind:'conflict',...captured,remote:saved,message:'Save response did not match the attempted content.'});return;
    }
    let removed:boolean;
    try{removed=await this.journal.removeIf(this.scope,path,captured.local.generation,captured.token);}
    catch(error){this.setState(path,{kind:'failed',...captured,retryable:true,errorCode:'journal',message:error instanceof Error?error.message:'Saved, but draft cleanup failed.'});return;}
    const current=this.states.get(path);
    if(!current||current.kind==='clean')return;
    if(current.local.generation===captured.local.generation){
      if(!removed){await this.recoverStaleCleanup(path,captured.local,saved,'The recovery draft changed while the completed save was being confirmed.');return;}
      this.journalTokens.delete(path);
      try{
        const alternate=await this.latestJournal(path);
        if(alternate){this.adoptConflict(path,alternate,saved,'Another recovered draft still needs review after this save.');return;}
      }catch(error){
        this.setState(path,{kind:'failed',local:{...captured.local,baseVersion:saved.version,baseContent:saved.content},retryable:true,errorCode:'journal',message:error instanceof Error?error.message:'Saved, but remaining recovery drafts could not be checked.'});return;
      }
      this.setState(path,{kind:'clean',remote:saved});return;
    }
    const rebased:DraftRecord={...current.local,baseVersion:saved.version,baseContent:saved.content,updatedAt:new Date().toISOString()};
    this.setState(path,{kind:'dirtyMemory',local:rebased});
    this.enqueueJournal(rebased);
  }

  private async latestJournal(path:string):Promise<JournaledDraft|null>{
    const drafts=(await this.journal.list(this.scope)).filter(candidate=>candidate.record.path===path);
    drafts.sort((left,right)=>right.record.generation-left.record.generation||right.record.updatedAt.localeCompare(left.record.updatedAt)||right.token.localeCompare(left.token));
    return drafts[0]??null;
  }

  private adoptConflict(path:string,draft:JournaledDraft,remote:RemoteFile|null,message:string):void{
    this.journalTokens.set(path,draft.token);
    this.setState(path,{kind:'conflict',local:draft.record,token:draft.token,remote,message});
  }

  private async recoverStaleCleanup(path:string,fallback:DraftRecord,remote:RemoteFile|null,message:string):Promise<void>{
    try{
      const current=await this.latestJournal(path);
      if(current){this.adoptConflict(path,current,remote,message);return;}
    }catch(error){
      this.setState(path,{kind:'failed',local:fallback,retryable:true,errorCode:'journal',message:error instanceof Error?error.message:'Recovery draft inspection failed.'});return;
    }
    this.journalTokens.delete(path);
    this.setState(path,{kind:'failed',local:fallback,retryable:true,errorCode:'journal',message});
  }

  private setState(path:string,state:AutosaveState):void {this.states.set(path,state);this.revision+=1;for(const listener of this.listeners)listener();}
}
