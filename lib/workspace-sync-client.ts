import {
  type EncryptedWorkspaceRecord,
  type WorkspaceRecovery,
  type WorkspaceRecord,
  type WorkspaceSession,
  createWorkspaceWithRecovery,
  openWorkspaceRecord,
  rewrapWorkspaceRecovery,
  restoreWorkspaceRecovery,
  sealWorkspaceRecord,
  workspaceRecordID,
} from './workspace-crypto.ts';

export type StoredEncryptedRecord={revision:number;envelope:EncryptedWorkspaceRecord};
export type SyncWorkspacePage={workspaceId:string;epoch:string;recovery:WorkspaceRecovery;snapshotRevision:number;records:StoredEncryptedRecord[];nextCursor:string|null};
export type SyncWorkspacePageRequest={kind:'initial'}|{kind:'continuation';cursor:string;snapshotRevision:number};
export type SyncWorkspaceSnapshot={workspaceId:string;epoch:string;recovery:WorkspaceRecovery;snapshotRevision:number;records:StoredEncryptedRecord[]};
export type SyncRecoveryReplacement={workspaceId:string;epoch:string;recovery:WorkspaceRecovery;snapshotRevision:number;idempotent:boolean};

const workspaceIDPattern=/^[A-Za-z0-9_-]{32}$/;
const recordIDPattern=/^[A-Za-z0-9_-]{43}$/;
const maximumPages=250;
const maximumRecords=1_000;
const pageSize=4;

async function readStableWorkspaceSnapshot(input:{workspaceId:string;readPage:(request:SyncWorkspacePageRequest)=>Promise<SyncWorkspacePage>}):Promise<SyncWorkspaceSnapshot>{
  let pageRequest:SyncWorkspacePageRequest={kind:'initial'};
  let expected:{epoch:string;recovery:WorkspaceRecovery;snapshotRevision:number}|null=null;
  const records:StoredEncryptedRecord[]=[];
  const recordIDs=new Set<string>();
  let previousRecordID:string|null=null;
  for(let pageNumber=0;pageNumber<maximumPages;pageNumber+=1){
    const page=await input.readPage(pageRequest);
    if(page.workspaceId!==input.workspaceId||!workspaceIDPattern.test(page.workspaceId)||!Number.isSafeInteger(page.snapshotRevision)||page.snapshotRevision<0||page.records.length>pageSize||page.recovery.workspaceId!==page.workspaceId||page.recovery.epoch!==page.epoch)throw Error('Encrypted sync returned an invalid workspace page.');
    if(expected===null)expected={epoch:page.epoch,recovery:page.recovery,snapshotRevision:page.snapshotRevision};
    else if(page.epoch!==expected.epoch||page.snapshotRevision!==expected.snapshotRevision||JSON.stringify(page.recovery)!==JSON.stringify(expected.recovery))throw Error('Encrypted sync returned pages from different workspace snapshots.');
    for(const record of page.records){
      const recordID=record.envelope.recordId;
      if(!Number.isSafeInteger(record.revision)||record.revision<0||!recordIDPattern.test(recordID)||record.envelope.workspaceId!==page.workspaceId||record.envelope.epoch!==page.epoch||previousRecordID!==null&&recordID<=previousRecordID||recordIDs.has(recordID))throw Error('Encrypted sync returned invalid or out-of-order records.');
      recordIDs.add(recordID);records.push(record);previousRecordID=recordID;
      if(records.length>maximumRecords)throw Error('Encrypted sync exceeded the 1,000-record limit.');
    }
    if(page.nextCursor===null)return {workspaceId:input.workspaceId,epoch:expected.epoch,recovery:expected.recovery,snapshotRevision:expected.snapshotRevision,records};
    const lastRecordID=page.records.at(-1)?.envelope.recordId;
    if(page.records.length!==pageSize||page.nextCursor!==lastRecordID||!recordIDPattern.test(page.nextCursor)||pageNumber===maximumPages-1)throw Error('Encrypted sync returned an invalid pagination cursor.');
    pageRequest={kind:'continuation',cursor:page.nextCursor,snapshotRevision:expected.snapshotRevision};
  }
  throw Error('Encrypted sync exceeded the 250-page limit.');
}

export async function assembleSyncWorkspaceSnapshot(input:{workspaceId:string;readPage:(request:SyncWorkspacePageRequest)=>Promise<SyncWorkspacePage>;isSnapshotChanged:(error:unknown)=>boolean}):Promise<SyncWorkspaceSnapshot>{
  if(!workspaceIDPattern.test(input.workspaceId))throw Error('Encrypted sync has an invalid workspace identifier.');
  for(let attempt=0;attempt<2;attempt+=1){
    try{return await readStableWorkspaceSnapshot(input);}
    catch(error){if(attempt===0&&input.isSnapshotChanged(error))continue;throw error;}
  }
  throw Error('Encrypted sync snapshot assembly failed.');
}

export interface EncryptedSyncRepository{
  enroll(input:{workspaceId:string;epoch:string;recovery:WorkspaceRecovery}):Promise<void>;
  replaceRecovery?(input:{workspaceId:string;expectedEpoch:string;expectedRevision:number;recovery:WorkspaceRecovery}):Promise<SyncRecoveryReplacement>;
  deleteWorkspace?(input:{workspaceId:string;expectedEpoch:string;expectedRevision:number}):Promise<void>;
  readWorkspace(workspaceId:string):Promise<SyncWorkspaceSnapshot>;
  readRecord(workspaceId:string,recordId:string):Promise<StoredEncryptedRecord|null>;
  write(input:{workspaceId:string;expectedRevision:number|null;envelope:EncryptedWorkspaceRecord}):Promise<StoredEncryptedRecord>;
}

export class EncryptedSyncConflict extends Error{
  readonly current:StoredEncryptedRecord;
  constructor(current:StoredEncryptedRecord){super('The encrypted file changed on another device. Review both versions before choosing one.');this.name='EncryptedSyncConflict';this.current=current;}
}

export type DecryptedSyncConflict={kind:'conflict';path:string;localContent:string|null;localGeneration:number;remote:WorkspaceRecord;remoteRevision:number};
export type EncryptedSyncSave={kind:'saved';record:StoredEncryptedRecord;value:WorkspaceRecord};
type ReviewedSyncBase=Readonly<{revision:number;content:string|null}>;
const privateSyncSegments=new Set([
  'credential',
  'credentials',
  'private-export',
  'private-exports',
  'private_exports',
  'profile',
  'profiles',
  'signing',
  'signing-material',
]);
const privateSyncFileNames=new Set(['auth.json','credential.json','credentials.json','profile.json']);
const privateSyncSuffixes=['.cer','.key','.mobileprovision','.p12','.p8','.pem'];

export function isDefaultSyncPath(path:string):boolean{
  const segments=path.split('/');
  if(segments.length<2||!['workspace','output'].includes(segments[0]??'')||segments.some(segment=>!segment||segment==='.'||segment==='..'))return false;
  const relativeSegments=segments.slice(1).map(segment=>segment.toLowerCase());
  const fileName=relativeSegments.at(-1)??'';
  return !relativeSegments.some(segment=>privateSyncSegments.has(segment)||segment==='.env'||segment.startsWith('.env.'))
    && !privateSyncFileNames.has(fileName)
    && !privateSyncSuffixes.some(suffix=>fileName.endsWith(suffix));
}

export class EncryptedWorkspaceSyncClient{
  private readonly session:WorkspaceSession;
  private readonly repository:EncryptedSyncRepository;
  private readonly writerDevice:string;
  private readonly reviewedByPath=new Map<string,ReviewedSyncBase>();
  private constructor(session:WorkspaceSession,repository:EncryptedSyncRepository,writerDevice:string){this.session=session;this.repository=repository;this.writerDevice=writerDevice;}

  static async create(passphrase:string,repository:EncryptedSyncRepository,writerDevice:string):Promise<{client:EncryptedWorkspaceSyncClient;recovery:WorkspaceRecovery}>{
    const {session,recovery}=await createWorkspaceWithRecovery(passphrase);
    await repository.enroll({workspaceId:session.workspaceId,epoch:session.epoch,recovery});
    return {client:new EncryptedWorkspaceSyncClient(session,repository,writerDevice),recovery};
  }

  static async restore(recovery:WorkspaceRecovery,passphrase:string,repository:EncryptedSyncRepository,writerDevice:string):Promise<EncryptedWorkspaceSyncClient>{
    const session=await restoreWorkspaceRecovery(recovery,passphrase);
    return new EncryptedWorkspaceSyncClient(session,repository,writerDevice);
  }

  get workspaceId(){return this.session.workspaceId;}
  get epoch(){return this.session.epoch;}

  async rotateRecovery(currentPassphrase:string,replacementPassphrase:string):Promise<{client:EncryptedWorkspaceSyncClient;recovery:WorkspaceRecovery}>{
    const repository=this.repository;
    if(!repository.replaceRecovery)throw Error('This encrypted sync repository does not support recovery rotation.');
    const snapshot=await this.repository.readWorkspace(this.workspaceId);
    if(snapshot.epoch!==this.epoch)throw Error('This device uses a different encrypted workspace key epoch. Re-enroll it before rotating recovery.');
    const rotated=await rewrapWorkspaceRecovery(snapshot.recovery,currentPassphrase,replacementPassphrase);
    await this.openSnapshot(snapshot,rotated.session);
    const replacement=await repository.replaceRecovery({
      workspaceId:this.workspaceId,
      expectedEpoch:this.epoch,
      expectedRevision:snapshot.snapshotRevision,
      recovery:rotated.recovery,
    });
    if(replacement.workspaceId!==this.workspaceId||replacement.epoch!==this.epoch||JSON.stringify(replacement.recovery)!==JSON.stringify(rotated.recovery)||replacement.snapshotRevision<=snapshot.snapshotRevision)throw Error('Encrypted sync returned an invalid recovery-rotation result.');
    const verified=await this.repository.readWorkspace(this.workspaceId);
    if(verified.epoch!==this.epoch||JSON.stringify(verified.recovery)!==JSON.stringify(rotated.recovery)||verified.snapshotRevision<replacement.snapshotRevision)throw Error('The rotated recovery envelope did not read back from encrypted sync.');
    const verifiedSession=await restoreWorkspaceRecovery(verified.recovery,replacementPassphrase);
    await this.openSnapshot(verified,verifiedSession);
    return {client:new EncryptedWorkspaceSyncClient(verifiedSession,this.repository,this.writerDevice),recovery:rotated.recovery};
  }

  async deleteWorkspace():Promise<void>{
    const repository=this.repository;
    if(!repository.deleteWorkspace)throw Error('This encrypted sync repository does not support workspace deletion.');
    const snapshot=await this.repository.readWorkspace(this.workspaceId);
    if(snapshot.epoch!==this.epoch)throw Error('This device uses a different encrypted workspace key epoch. Re-enroll it before deletion.');
    await repository.deleteWorkspace({workspaceId:this.workspaceId,expectedEpoch:this.epoch,expectedRevision:snapshot.snapshotRevision});
    this.reviewedByPath.clear();
  }

  async pull():Promise<{record:StoredEncryptedRecord;value:WorkspaceRecord}[]>{
    const snapshot=await this.repository.readWorkspace(this.workspaceId);
    if(snapshot.epoch!==this.epoch)throw Error('This device uses a different encrypted workspace key epoch. Re-enroll it before syncing.');
    const sorted=await this.openSnapshot(snapshot,this.session);
    this.reviewedByPath.clear();
    for(const item of sorted)this.remember(item.value.path,item.record,item.value);
    return sorted;
  }

  private async openSnapshot(snapshot:SyncWorkspaceSnapshot,session:WorkspaceSession):Promise<{record:StoredEncryptedRecord;value:WorkspaceRecord}[]>{
    if(snapshot.workspaceId!==session.workspaceId||snapshot.epoch!==session.epoch)throw Error('This encrypted snapshot belongs to a different workspace or key epoch.');
    const opened=await Promise.all(snapshot.records.map(async record=>({record,value:await openWorkspaceRecord(session,record.envelope)})));
    const paths=new Set<string>();
    for(const item of opened){if(!isDefaultSyncPath(item.value.path))throw Error('The encrypted workspace contains a private or unsupported path. Stop and inspect its records.');if(paths.has(item.value.path))throw Error('The encrypted workspace contains duplicate paths. Stop and inspect its records.');paths.add(item.value.path);}
    return opened.sort((left,right)=>left.value.path.localeCompare(right.value.path));
  }

  async push(input:{path:string;content:string|null;generation:number}):Promise<EncryptedSyncSave|DecryptedSyncConflict>{
    if(!isDefaultSyncPath(input.path))throw Error('Only non-private workspace and output files are eligible for encrypted device sync.');
    const recordId=await workspaceRecordID(this.session,input.path);
    const current=await this.repository.readRecord(this.workspaceId,recordId);
    const reviewed=this.reviewedByPath.get(input.path);
    if(current){
      const remote=await openWorkspaceRecord(this.session,current.envelope);
      if(remote.path!==input.path)throw Error('The encrypted sync record resolved to a different path.');
      if(!reviewed||reviewed.revision!==current.revision||reviewed.content!==remote.content)return this.conflict(input,current,remote);
    }else if(reviewed){
      throw Error('The reviewed encrypted record disappeared outside the tombstone protocol. Pull and inspect the workspace before retrying.');
    }
    const baseRevision=reviewed?.revision??null;
    const envelope=await sealWorkspaceRecord(this.session,{...input,baseRevision,writerDevice:this.writerDevice});
    try{
      const record=await this.repository.write({workspaceId:this.workspaceId,expectedRevision:baseRevision,envelope});
      const value=await openWorkspaceRecord(this.session,record.envelope);
      this.remember(input.path,record,value);
      return {kind:'saved',record,value};
    }catch(error){
      if(!(error instanceof EncryptedSyncConflict))throw error;
      const remote=await openWorkspaceRecord(this.session,error.current.envelope);
      return this.conflict(input,error.current,remote);
    }
  }

  async keepMine(conflict:DecryptedSyncConflict):Promise<EncryptedSyncSave>{
    const envelope=await sealWorkspaceRecord(this.session,{path:conflict.path,content:conflict.localContent,baseRevision:conflict.remoteRevision,generation:conflict.localGeneration,writerDevice:this.writerDevice});
    try{
      const record=await this.repository.write({workspaceId:this.workspaceId,expectedRevision:conflict.remoteRevision,envelope});
      const value=await openWorkspaceRecord(this.session,record.envelope);
      this.remember(conflict.path,record,value);
      return {kind:'saved',record,value};
    }catch(error){
      if(error instanceof EncryptedSyncConflict)throw Error('The encrypted file changed again. Pull the latest version before retrying.');
      throw error;
    }
  }

  private conflict(input:{path:string;content:string|null;generation:number},current:StoredEncryptedRecord,remote:WorkspaceRecord):DecryptedSyncConflict{
    return {kind:'conflict',path:input.path,localContent:input.content,localGeneration:input.generation,remote,remoteRevision:current.revision};
  }

  private remember(path:string,record:StoredEncryptedRecord,value:WorkspaceRecord):void{
    this.reviewedByPath.set(path,{revision:record.revision,content:value.content});
  }
}
