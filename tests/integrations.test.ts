import test from 'node:test';
import assert from 'node:assert/strict';
import { defaultIntegrations,adapterFor,integrationSchema,repoPathSchema,branchSchema,worktreePatch } from '../lib/integrations.ts';
import { pushGitFile,inspectGitFile,createGitBranch } from '../lib/github.ts';
import { policySchema,defaultPolicy,normalizeSavedPolicy } from '../lib/contracts.ts';

test('saved API policy migrates to ChatGPT without increasing authorization or losing limits',()=>{
 const saved={...defaultPolicy,provider:'openai',maxSteps:3,cloudAllowed:false,batteryBudget:7};
 assert.deepEqual(normalizeSavedPolicy(saved),{...saved,provider:'chatgpt'});
 assert.throws(()=>normalizeSavedPolicy({...saved,maxSteps:99}));
});

test('all subscription apps and local providers use Shortcuts, legacy API provider rejected',()=>{
 for(const id of ['local','chatgpt','grok','grokbot','claude','apple'] as const){assert.ok(adapterFor(defaultIntegrations,id).name);assert.equal(policySchema.safeParse({...defaultPolicy,provider:id}).success,true);}
 assert.equal(policySchema.safeParse({...defaultPolicy,provider:'openai'}).success,false);
 assert.equal(integrationSchema.safeParse({...defaultIntegrations,adapters:{chatgpt:{name:'x',mode:'action',tested:false,installURL:'https://evil.test/shortcut'}}}).success,false);
});
test('Git paths and branch names reject boundary escapes',()=>{
 for(const p of ['../x','.git/config','a/../b','a//b','a/.git/config','https://evil.test','.github/workflows/x.yml'])assert.equal(repoPathSchema.safeParse(p).success,false,p);
 for(const p of ['x..y','refs//x','x.lock','x/','-unsafe'])assert.equal(branchSchema.safeParse(p).success,false,p);
});
test('worktree patch binds text to a base commit and both content hashes',async()=>{
 const p=await worktreePatch({repository:'Dezocode/example',branch:'phone',baseCommit:'a'.repeat(40),path:'notes.md',before:'before',after:'after'});
 assert.equal(p.version,1);assert.equal(p.changes[0].beforeSHA256?.length,64);assert.notEqual(p.changes[0].beforeSHA256,p.changes[0].afterSHA256);
});
test('remote branch conflicts stop before creating any Git objects',async()=>{
 let requests=0;await assert.rejects(()=>pushGitFile(async()=>{requests++;return {object:{sha:'b'.repeat(40)}}},{repository:'Dezocode/example',branch:'phone',path:'x.txt'},'a'.repeat(40),'text'),/Branch advanced/);assert.equal(requests,1);
});
test('Git push preserves base tree and uses a non-force ref update',async()=>{
 const calls:{path:string;method?:string;body?:unknown}[]=[];
 const api=async(path:string,method?:string,body?:unknown)=>{calls.push({path,method,body});if(path.includes('/git/ref/'))return {object:{sha:'a'.repeat(40)}};if(path.endsWith('/git/commits/'+ 'a'.repeat(40)))return {tree:{sha:'b'.repeat(40)}};if(path.endsWith('/git/blobs'))return {sha:'c'.repeat(40)};if(path.endsWith('/git/trees'))return {sha:'d'.repeat(40)};if(path.endsWith('/git/commits'))return {sha:'e'.repeat(40)};return {object:{sha:'e'.repeat(40)}};};
 const result=await pushGitFile(api,{repository:'Dezocode/example',branch:'phone/test',path:'x.txt'},'a'.repeat(40),'text');
 assert.equal(result.commit,'e'.repeat(40));assert.deepEqual(calls.at(-1)?.body,{sha:'e'.repeat(40),force:false});assert.equal(calls.at(-1)?.method,'PATCH');
 assert.deepEqual(calls.find(c=>c.path.endsWith('/git/trees'))?.body,{base_tree:'b'.repeat(40),tree:[{path:'x.txt',mode:'100644',type:'blob',sha:'c'.repeat(40)}]});
});
test('remote inspection refuses truncated trees and symlink blobs',async()=>{
 const target={repository:'Dezocode/example',branch:'phone',path:'x.txt'};
 await assert.rejects(()=>inspectGitFile(async(path)=>path.includes('/git/ref/')?{object:{sha:'a'.repeat(40)}}:{tree:[],truncated:true},target),/too large/);
 await assert.rejects(()=>inspectGitFile(async(path)=>path.includes('/git/ref/')?{object:{sha:'a'.repeat(40)}}:{tree:[{path:'x.txt',type:'blob',mode:'120000',sha:'b'.repeat(40),size:5}],truncated:false},target),/regular text/);
});

test('branch creation uses the default head without updating an existing reference',async()=>{
 const calls:{path:string;method?:string;body?:unknown}[]=[];
 const result=await createGitBranch(async(path,method,body)=>{calls.push({path,method,body});if(calls.length===1)return {default_branch:'main'};return {object:{sha:'a'.repeat(40)}};},'Dezocode/example','phone');
 assert.equal(result.commit,'a'.repeat(40));assert.equal(calls.at(-1)?.method,'POST');assert.deepEqual(calls.at(-1)?.body,{ref:'refs/heads/phone',sha:'a'.repeat(40)});assert.ok(!calls.some(c=>c.method==='PATCH'));
});
