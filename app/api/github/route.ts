import { z } from 'zod';
import {
 AppleOwnerExternalOperationError,
 createD1AppleOwnerExternalOperationLeaseRepository,
 withD1AppleOwnerExternalOperationLease,
} from '@/lib/apple-auth-external-operation-d1';
import { boundary,database,identity,input,HttpError } from '@/lib/server';
import { fineGrainedGitHubTokenSchema,githubClient,gitTarget,inspectGitFile,pushGitFile,createGitBranch } from '@/lib/github';
const command=z.discriminatedUnion('kind',[
 z.object({kind:z.literal('connect'),token:fineGrainedGitHubTokenSchema}).strict(),
 z.object({kind:z.literal('inspect'),token:fineGrainedGitHubTokenSchema,target:gitTarget}).strict(),
 z.object({kind:z.literal('createBranch'),token:fineGrainedGitHubTokenSchema,target:gitTarget}).strict(),
 z.object({kind:z.literal('push'),token:fineGrainedGitHubTokenSchema,target:gitTarget,expectedCommit:z.string().regex(/^[a-f0-9]{40}$/),content:z.string().max(64000)}).strict(),
]);
async function operationResource(value:z.infer<typeof command>):Promise<string>{
 const scope=value.kind==='connect'
  ?{kind:value.kind}
  :{kind:value.kind,repository:value.target.repository,branch:value.target.branch,path:value.target.path};
 const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(JSON.stringify(scope)));
 let binary='';for(const byte of new Uint8Array(digest))binary+=String.fromCharCode(byte);
 return btoa(binary).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}
export async function POST(request:Request){return boundary(async()=>{
 const user=await identity(request);const value=await input(request,command);const api=githubClient(value.token);
 try {
  return await withD1AppleOwnerExternalOperationLease({
   repository:createD1AppleOwnerExternalOperationLeaseRepository(database()),
   authorization:user,
   operationKind:'github',
   resourceId:await operationResource(value),
   crypto:globalThis.crypto,
   now:()=>Math.floor(Date.now()/1_000),
   operation:async()=>{
    if(value.kind==='connect'){const account=z.object({login:z.string()}).parse(await api('/user'));return {login:account.login};}
    if(value.kind==='inspect')return inspectGitFile(api,value.target);
    if(value.kind==='createBranch')return createGitBranch(api,value.target.repository,value.target.branch);
    if(new TextEncoder().encode(value.content).length>64000)throw new HttpError(413,'Text must be under 64 KB.');
    return pushGitFile(api,value.target,value.expectedCommit,value.content);
   },
  });
 }catch(e){
  if(e instanceof HttpError)throw e;
  if(e instanceof AppleOwnerExternalOperationError)throw new HttpError(e.status,e.message,e.code);
  throw new HttpError(409,e instanceof Error?e.message:'GitHub could not complete this operation.');
 }
});}
