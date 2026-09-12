import { z } from 'zod';
import {
  ORIGIN_API_BASE_URL,
  ORIGIN_CONTENTS_READ_SCOPE,
  OriginAuthError,
  type OriginConfiguration,
  type OriginFetch,
  createOriginAppJWT,
  mintOriginInstallationToken,
  parseOriginInstallationTokenRequest,
} from './origin-auth.ts';
import { readBoundedResponseText } from './bounded-response.ts';

const MAX_RESPONSE_BYTES=256*1024;
const encoder=new TextEncoder();
export const originRepositorySchema=z.object({
  id:z.string().regex(/^repo_[a-z0-9]{8,100}$/),
  name:z.string().min(1).max(100).regex(/^[A-Za-z0-9._-]+$/),
  fullName:z.string().min(3).max(220),
  owner:z.object({slug:z.string().min(1).max(100).regex(/^[A-Za-z0-9._-]+$/),id:z.string().regex(/^ns_[a-z0-9]{8,100}$/),type:z.enum(['team','user']).optional()}).passthrough(),
  defaultBranch:z.string().min(1).max(255),
  cloneUrl:z.string().url(),
}).passthrough();
const repositoryListSchema=z.object({repositories:z.array(originRepositorySchema).max(100),repoSelectionMode:z.enum(['all','selected']),nextPageToken:z.string().max(2_000).optional()}).passthrough();
const syncMirrorResponseSchema=z.object({synced:z.boolean()}).passthrough();
const installationAccessSchema=z.object({
  id:z.string().regex(/^(?:i|inst)_[a-z0-9]{8,100}$/),
  appId:z.string().regex(/^app_[a-z0-9]{8,100}$/),
  scopes:z.array(z.string().min(1).max(100)).max(20)
    .refine(values=>new Set(values).size===values.length,'Scopes must be unique.'),
}).passthrough();

export type OriginRepository={id:string;name:string;fullName:string;owner:{slug:string;id:string;type?:'team'|'user'};defaultBranch:string;cloneUrl:string};

function publicRepository(value:z.infer<typeof originRepositorySchema>):OriginRepository{
  let clone:URL;
  try{clone=new URL(value.cloneUrl);}catch{throw invalidRepositories();}
  if(
    clone.protocol!=='https:'||clone.hostname!=='origin.cursor.com'||clone.port
    || clone.username||clone.password||clone.search||clone.hash
    || encoder.encode(value.cloneUrl).byteLength>4_096
    || value.cloneUrl.includes('\\')||/[\u0000-\u001f\u007f]/.test(value.cloneUrl)
  )throw invalidRepositories();
  if(value.fullName!==`${value.owner.slug}/${value.name}`)throw invalidRepositories();
  if(encoder.encode(value.defaultBranch).byteLength>1_024||value.defaultBranch==='@'||value.defaultBranch==='HEAD'||value.defaultBranch.startsWith('-')||value.defaultBranch.startsWith('.')||value.defaultBranch.startsWith('/')||value.defaultBranch.endsWith('/')||value.defaultBranch.endsWith('.')||value.defaultBranch.includes('//')||value.defaultBranch.includes('..')||value.defaultBranch.includes('@{')||/[\u0000-\u0020\u007f~^:?*[\\]/.test(value.defaultBranch)||value.defaultBranch.split('/').some(part=>!part||part.startsWith('.')||part.endsWith('.lock')))throw invalidRepositories();
  return {id:value.id,name:value.name,fullName:value.fullName,owner:{slug:value.owner.slug,id:value.owner.id,type:value.owner.type},defaultBranch:value.defaultBranch,cloneUrl:clone.toString()};
}

function invalidRepositories(){return new OriginAuthError(502,'ORIGIN_REPOSITORIES_INVALID','Cursor Origin returned an invalid repository list.');}

async function responseJSON(response:Response,invalid:()=>OriginAuthError):Promise<unknown>{
  const type=response.headers.get('content-type')?.split(';',1)[0]?.trim().toLowerCase();
  if(type!=='application/json')throw invalid();
  try{return JSON.parse(await readBoundedResponseText(response,MAX_RESPONSE_BYTES));}catch{throw invalid();}
}

async function requestOrigin(url:string,token:string,init:RequestInit,fetcher:OriginFetch):Promise<Response>{
  try{return await fetcher(url,{...init,headers:{Accept:'application/json',Authorization:`Bearer ${token}`,...init.headers},redirect:'error',signal:init.signal??AbortSignal.timeout(20_000)});}
  catch{throw new OriginAuthError(502,'ORIGIN_API_UNAVAILABLE','Cursor Origin could not complete the repository request.');}
}

async function installationToken(input:{configuration:OriginConfiguration;installationId:string;repositoryIds:string[];fetcher:OriginFetch;crypto:Crypto;now:()=>number}){
  await requireOriginReadOnlyInstallation(input);
  return mintOriginInstallationToken({
    configuration:input.configuration,
    request:parseOriginInstallationTokenRequest({installationId:input.installationId,repositoryIds:input.repositoryIds}),
    fetcher:input.fetcher,
    crypto:input.crypto,
    now:input.now,
  });
}

export async function requireOriginReadOnlyInstallation(input:{configuration:OriginConfiguration;installationId:string;fetcher:OriginFetch;crypto:Crypto;now:()=>number}):Promise<void>{
  const app=await createOriginAppJWT({configuration:input.configuration,crypto:input.crypto,now:input.now()});
  const response=await requestOrigin(`${ORIGIN_API_BASE_URL}/app/installations/${encodeURIComponent(input.installationId)}`,app.token,{method:'GET'},input.fetcher);
  if(!response.ok)throw new OriginAuthError(response.status===401||response.status===403||response.status===404?response.status:502,'ORIGIN_INSTALLATION_INSPECTION_REJECTED',`Cursor Origin rejected installation scope inspection (${response.status}).`);
  const invalid=()=>new OriginAuthError(502,'ORIGIN_INSTALLATION_INVALID','Cursor Origin returned invalid installation metadata.');
  const parsed=installationAccessSchema.safeParse(await responseJSON(response,invalid));
  if(!parsed.success||parsed.data.id!==input.installationId||parsed.data.appId!==input.configuration.appId)throw invalid();
  if(parsed.data.scopes.length!==1||parsed.data.scopes[0]!==ORIGIN_CONTENTS_READ_SCOPE){
    throw new OriginAuthError(403,'ORIGIN_INSTALLATION_SCOPE_REJECTED',`Remove and reconnect this Cursor Origin installation with only ${ORIGIN_CONTENTS_READ_SCOPE}.`);
  }
}

export async function listOriginRepositories(input:{configuration:OriginConfiguration;installationId:string;fetcher:OriginFetch;crypto:Crypto;now:()=>number}):Promise<{repositories:OriginRepository[];selectionMode:'all'|'selected';truncated:boolean}>{
  const credential=await installationToken({...input,repositoryIds:[]});
  const response=await requestOrigin(`${ORIGIN_API_BASE_URL}/installation/repos?pageSize=100`,credential.token,{method:'GET'},input.fetcher);
  if(!response.ok)throw new OriginAuthError(response.status===401||response.status===403?response.status:502,'ORIGIN_REPOSITORIES_REJECTED',`Cursor Origin rejected repository discovery (${response.status}).`);
  const parsed=repositoryListSchema.safeParse(await responseJSON(response,invalidRepositories));
  if(!parsed.success)throw invalidRepositories();
  return {repositories:parsed.data.repositories.map(publicRepository),selectionMode:parsed.data.repoSelectionMode,truncated:Boolean(parsed.data.nextPageToken)};
}

export async function syncOriginMirror(input:{configuration:OriginConfiguration;installationId:string;repository:OriginRepository;fetcher:OriginFetch;crypto:Crypto;now:()=>number}):Promise<'synchronized'|'pending'>{
  const repository=publicRepository(originRepositorySchema.parse(input.repository));
  const credential=await installationToken({...input,repositoryIds:[repository.id]});
  const path=`${ORIGIN_API_BASE_URL}/repos/${encodeURIComponent(repository.owner.slug)}/${encodeURIComponent(repository.name)}:syncMirror`;
  const response=await requestOrigin(path,credential.token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ref:`refs/heads/${repository.defaultBranch}`,wait:false})},input.fetcher);
  if(response.status===200||response.status===202){
    const parsed=syncMirrorResponseSchema.safeParse(await responseJSON(response,()=>new OriginAuthError(502,'ORIGIN_MIRROR_INVALID','Cursor Origin returned an invalid mirror synchronization result.')));
    const synchronized=response.status===200;
    if(!parsed.success||parsed.data.synced!==synchronized)throw new OriginAuthError(502,'ORIGIN_MIRROR_INVALID','Cursor Origin returned an invalid mirror synchronization result.');
    return synchronized?'synchronized':'pending';
  }
  throw new OriginAuthError(response.status===401||response.status===403||response.status===404?response.status:502,'ORIGIN_MIRROR_REJECTED',`Cursor Origin rejected mirror synchronization (${response.status}).`);
}

export async function deleteOriginInstallation(input:{configuration:OriginConfiguration;installationId:string;fetcher:OriginFetch;crypto:Crypto;now:()=>number;signal?:AbortSignal}):Promise<void>{
  const app=await createOriginAppJWT({configuration:input.configuration,crypto:input.crypto,now:input.now()});
  const response=await requestOrigin(`${ORIGIN_API_BASE_URL}/app/installations/${encodeURIComponent(input.installationId)}`,app.token,{method:'DELETE',signal:input.signal},input.fetcher);
  if(response.status===204||response.status===404)return;
  throw new OriginAuthError(response.status===401||response.status===403?response.status:502,'ORIGIN_DELETE_REJECTED',`Cursor Origin rejected installation removal (${response.status}).`);
}
