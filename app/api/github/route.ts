import { z } from 'zod';
import { boundary,identity,input,HttpError } from '@/lib/server';
import { githubClient,gitTarget,inspectGitFile,pushGitFile,createGitBranch } from '@/lib/github';
const token=z.string().min(10).max(500).regex(/^[A-Za-z0-9_]+$/);
const command=z.discriminatedUnion('kind',[
 z.object({kind:z.literal('connect'),token}).strict(),
 z.object({kind:z.literal('inspect'),token,target:gitTarget}).strict(),
 z.object({kind:z.literal('createBranch'),token,target:gitTarget}).strict(),
 z.object({kind:z.literal('push'),token,target:gitTarget,expectedCommit:z.string().regex(/^[a-f0-9]{40}$/),content:z.string().max(64000)}).strict(),
]);
export async function POST(request:Request){return boundary(async()=>{
 await identity();const value=await input(request,command);const api=githubClient(value.token);
 try {
  if(value.kind==='connect'){const user=z.object({login:z.string()}).parse(await api('/user'));return {login:user.login};}
  if(value.kind==='inspect')return await inspectGitFile(api,value.target);
  if(value.kind==='createBranch')return await createGitBranch(api,value.target.repository,value.target.branch);
  if(new TextEncoder().encode(value.content).length>64000)throw new HttpError(413,'Text must be under 64 KB.');
  return await pushGitFile(api,value.target,value.expectedCommit,value.content);
 }catch(e){throw new HttpError(409,e instanceof Error?e.message:'GitHub could not complete this operation.');}
});}
