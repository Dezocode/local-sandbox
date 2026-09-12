import { z } from 'zod';
import { boundary,database,identity,initialize,input,HttpError } from '@/lib/server';
import { APPLE_OWNER_OPERATION_ALLOWED_SQL,appleOwnerOperationGateBindings } from '@/lib/apple-auth-owner-d1';
import { fileContentSchema,fileSchema,pathSchema } from '@/lib/contracts';
import { applyFileMutationWithFreshVersion,FileVersionD1IntegrityError,maximumFileVersion,readAuthorizedFileWorkspaceSnapshot,type AuthorizedFileWorkspaceSnapshot,type FileMutationInput } from '@/lib/workspace-file-d1';

const command=z.discriminatedUnion('kind',[
  z.object({kind:z.literal('create'),path:pathSchema,content:fileContentSchema}).strict(),
  z.object({kind:z.literal('save'),path:pathSchema,content:fileContentSchema,version:z.number().int().nonnegative().max(maximumFileVersion)}).strict(),
  z.object({kind:z.literal('delete'),path:pathSchema,version:z.number().int().nonnegative().max(maximumFileVersion)}).strict(),
]);
const deletedFileSchema=z.object({path:pathSchema,version:z.number().int().nonnegative().max(maximumFileVersion)});

async function mutateFile(value:FileMutationInput){
  try{return await applyFileMutationWithFreshVersion(value);}
  catch(error){if(error instanceof FileVersionD1IntegrityError)throw new HttpError(503,'Hosted file storage failed a version integrity check.','FILE_STORAGE_INTEGRITY');throw error;}
}

async function finalFileSnapshot(value:Parameters<typeof readAuthorizedFileWorkspaceSnapshot>[0]){
  try{return await readAuthorizedFileWorkspaceSnapshot(value);}
  catch(error){if(error instanceof FileVersionD1IntegrityError)throw new HttpError(503,'Hosted file storage failed a version integrity check.','FILE_STORAGE_INTEGRITY');throw error;}
}

function authorizedSnapshot(value:AuthorizedFileWorkspaceSnapshot){
  if(value.kind==='unauthorized')throw new HttpError(409,'This standalone Apple account is being deleted. Sign in again after deletion finishes to create a new workspace.','APPLE_ACCOUNT_DELETION_IN_PROGRESS');
  if(!value.workspacePresent||value.fileClock===null)throw new HttpError(503,'Hosted file storage failed an integrity check.','FILE_STORAGE_INTEGRITY');
  return value;
}

function sameFile(left:z.infer<typeof fileSchema>|null,right:z.infer<typeof fileSchema>){
  return left!==null&&left.path===right.path&&left.content===right.content&&left.version===right.version;
}

export async function GET(request:Request){return boundary(async()=>{
  const user=await identity(request);
  const url=new URL(request.url);
  if([...url.searchParams.keys()].some(key=>key!=='path'))throw new HttpError(400,'Only a sandbox path can be queried.','INVALID_QUERY');
  const path=pathSchema.parse(url.searchParams.get('path'));
  await initialize(user);
  const snapshot=authorizedSnapshot(await finalFileSnapshot({database:database(),authorization:user,operationTime:Math.floor(Date.now()/1_000),path}));
  if(snapshot.file===null)throw new HttpError(404,'The file no longer exists.','FILE_NOT_FOUND');
  return {file:snapshot.file};
});}

export async function POST(request:Request){return boundary(async()=>{
  const user=await identity(request);
  const value=await input(request,command);
  await initialize(user);
  const db=database(),now=Math.floor(Date.now()/1_000),gate=appleOwnerOperationGateBindings(user,now);
  const mutationPath=pathSchema.parse(value.path);
  if(value.kind==='create'){
    const result=await mutateFile({kind:'create',database:db,authorization:user,operationTime:now,path:mutationPath,content:value.content});
    const snapshot=authorizedSnapshot(await finalFileSnapshot({database:db,authorization:user,operationTime:now,path:mutationPath}));
    if(result.kind==='applied'){
      if(sameFile(snapshot.file,result.file))return {file:result.file};
      throw new HttpError(409,'The file changed again before the create response completed. Refresh before retrying.','FILE_SNAPSHOT_CHANGED',snapshot.file===null?undefined:{file:snapshot.file});
    }
    if(snapshot.file!==null)throw new HttpError(409,'A file already exists at that path.','FILE_EXISTS_OR_LIMIT',{file:snapshot.file});
    if(snapshot.fileClock===maximumFileVersion)throw new HttpError(409,'This workspace exhausted its safe file-version range. Export the workspace before creating another version.','FILE_VERSION_EXHAUSTED');
    if(snapshot.fileCount>=100)throw new HttpError(409,'This text workspace supports 100 files. Export your archive before adding more.','FILE_LIMIT');
    throw new HttpError(409,'The file changed while it was being created. Refresh before retrying.','FILE_CREATE_CONFLICT');
  }
  if(value.kind==='delete'){
    const rawDeleted=await db.prepare(`DELETE FROM files WHERE user_id=? AND path=? AND version=? AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL} RETURNING path,version`).bind(user.userId,value.path,value.version,...gate).first();
    const deleted=rawDeleted===null?null:deletedFileSchema.safeParse(rawDeleted);
    if(deleted!==null&&!deleted.success)throw new HttpError(503,'Hosted file storage failed a version integrity check.','FILE_STORAGE_INTEGRITY');
    const snapshot=authorizedSnapshot(await finalFileSnapshot({database:db,authorization:user,operationTime:now,path:mutationPath}));
    if(deleted?.success&&snapshot.file===null)return {deleted:deleted.data};
    if(snapshot.file===null)throw new HttpError(404,'The file no longer exists.','FILE_NOT_FOUND');
    throw new HttpError(409,'This file changed elsewhere. Compare both versions before deleting it.','VERSION_CONFLICT',{file:snapshot.file});
  }
  const result=await mutateFile({kind:'save',database:db,authorization:user,operationTime:now,path:mutationPath,content:value.content,expectedVersion:value.version});
  const snapshot=authorizedSnapshot(await finalFileSnapshot({database:db,authorization:user,operationTime:now,path:mutationPath}));
  if(result.kind==='applied'){
    if(sameFile(snapshot.file,result.file))return {file:result.file};
    throw new HttpError(409,'The file changed again before the save response completed. Refresh before retrying.','FILE_SNAPSHOT_CHANGED',snapshot.file===null?undefined:{file:snapshot.file});
  }
  if(snapshot.file===null)throw new HttpError(404,'The file no longer exists.','FILE_NOT_FOUND');
  if(snapshot.file.version===value.version&&snapshot.fileClock===maximumFileVersion)throw new HttpError(409,'This workspace exhausted its safe file-version range. Export the workspace before saving another version.','FILE_VERSION_EXHAUSTED');
  throw new HttpError(409,'This file changed elsewhere. Compare both versions before choosing which one to keep.','VERSION_CONFLICT',{file:snapshot.file});
});}
