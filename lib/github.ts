import { z } from 'zod';
import { branchSchema,repoPathSchema,repositorySchema } from './integrations.ts';
export const gitTarget=z.object({repository:repositorySchema,branch:branchSchema,path:repoPathSchema}).strict();
export const snapshotSchema=z.object({commit:z.string().regex(/^[a-f0-9]{40}$/),content:z.string().nullable(),sha:z.string().nullable()});
export type Snapshot=z.infer<typeof snapshotSchema>;
const refSchema=z.object({object:z.object({sha:z.string().regex(/^[a-f0-9]{40}$/)})});
const shaSchema=z.object({sha:z.string().regex(/^[a-f0-9]{40}$/)});
type Transport=(path:string,method?:string,body?:unknown)=>Promise<unknown>;
export function githubClient(token:string):Transport {return async(path,method='GET',body)=>{
 const response=await fetch('https://api.github.com'+path,{method,headers:{Authorization:`Bearer ${token}`,Accept:'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'Local-Sandbox','Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(20000)});
 if(!response.ok)throw new Error(response.status===401?'GitHub authentication expired. Reconnect in Settings.':response.status===404?'Repository, branch, or permission not found. Check the saved target.':response.status===409||response.status===422?'GitHub changed while syncing. Compare again; nothing was force-pushed.':`GitHub request failed (${response.status}).`);
 return response.json();
};}
const base=(repository:string)=>'/repos/'+repository.split('/').map(encodeURIComponent).join('/');
export async function createGitBranch(api:Transport,repository:string,branch:string){
 const root=base(repositorySchema.parse(repository));branchSchema.parse(branch);
 const repo=z.object({default_branch:z.string()}).parse(await api(root));
 const head=refSchema.parse(await api(root+'/git/ref/heads/'+repo.default_branch.split('/').map(encodeURIComponent).join('/')));
 const created=refSchema.parse(await api(root+'/git/refs','POST',{ref:'refs/heads/'+branch,sha:head.object.sha}));
 return {commit:created.object.sha};
}
export async function inspectGitFile(api:Transport,target:z.infer<typeof gitTarget>):Promise<Snapshot>{
 const root=base(target.repository);const ref=refSchema.parse(await api(root+'/git/ref/heads/'+target.branch.split('/').map(encodeURIComponent).join('/')));const commit=ref.object.sha;
 // A recursive tree lets a missing file be distinguished from inaccessible authentication.
 const tree=z.object({tree:z.array(z.object({path:z.string(),type:z.string(),mode:z.string(),sha:z.string(),size:z.number().optional()})),truncated:z.boolean()}).parse(await api(root+'/git/trees/'+commit+'?recursive=1'));
 if(tree.truncated)throw new Error('Repository tree is too large for this bounded sync. Use a smaller repository or the worktree patch bridge.');
 const entry=tree.tree.find(f=>f.path===target.path);
 if(!entry)return {commit,content:null,sha:null};
 if(entry.type!=='blob'||entry.mode==='120000'||(entry.size??0)>64000)throw new Error('Only regular text files under 64 KB can be synced.');
 const blob=z.object({content:z.string(),encoding:z.literal('base64'),size:z.number().max(64000)}).parse(await api(root+'/git/blobs/'+entry.sha));
 const bytes=Uint8Array.from(atob(blob.content.replace(/\s/g,'')),c=>c.charCodeAt(0));
 const content=new TextDecoder('utf-8',{fatal:true}).decode(bytes);if(content.includes('\0'))throw new Error('Binary files are not supported.');
 return {commit,content,sha:entry.sha};
}
export async function pushGitFile(api:Transport,target:z.infer<typeof gitTarget>,expectedCommit:string,content:string){
 const root=base(target.repository);const ref=refSchema.parse(await api(root+'/git/ref/heads/'+target.branch.split('/').map(encodeURIComponent).join('/')));
 if(ref.object.sha!==expectedCommit)throw new Error('Branch advanced since comparison. Compare again before syncing.');
 const commit=z.object({tree:shaSchema}).parse(await api(root+'/git/commits/'+expectedCommit));
 const blob=shaSchema.parse(await api(root+'/git/blobs','POST',{content,encoding:'utf-8'}));
 const tree=shaSchema.parse(await api(root+'/git/trees','POST',{base_tree:commit.tree.sha,tree:[{path:target.path,mode:'100644',type:'blob',sha:blob.sha}]}));
 const next=shaSchema.parse(await api(root+'/git/commits','POST',{message:`Local Sandbox: update ${target.path}`,tree:tree.sha,parents:[expectedCommit]}));
 const updated=refSchema.parse(await api(root+'/git/refs/heads/'+target.branch.split('/').map(encodeURIComponent).join('/'),'PATCH',{sha:next.sha,force:false}));
 if(updated.object.sha!==next.sha)throw new Error('GitHub did not confirm the expected commit. Compare before retrying.');
 return {commit:next.sha,sha:blob.sha};
}
