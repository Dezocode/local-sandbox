import test from'node:test';
import assert from'node:assert/strict';
import{readFile}from'node:fs/promises';
import{fineGrainedGitHubTokenSchema,githubClient}from'../lib/github.ts';
import{GitHubConflict,GitHubConnection,resetGitHubComparisonView,validateFineGrainedGitHubToken,validateGitHubBranch,validateGitHubContent,validateGitHubPath,validateGitHubRepository,validateGitHubTarget}from'../public/local/github.js';

const token='github_pat_'+ 'A'.repeat(40);
const sha=character=>character.repeat(40);
const bytes=value=>new TextEncoder().encode(value);
const base64=value=>Buffer.from(typeof value==='string'?bytes(value):value).toString('base64');
const json=(value,status=200,headers={})=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json',...headers}});
const ref=value=>json({object:{sha:value}});
const created=value=>json({sha:value});

function routeFetch(route){
  const calls=[];
  const fetchImpl=async(url,options={})=>{const call={url:new URL(url),options,body:options.body===undefined?undefined:JSON.parse(options.body)};calls.push(call);return route(call,calls);};
  return{calls,fetchImpl};
}

async function connect(client){assert.deepEqual(await client.connect(token),{login:'Dezocode'});}

test('hosted, local-web, and native manual-token paths share the fine-grained PAT contract',async()=>{
  const validTokens=[
    'github_pat_'+'A'.repeat(20),
    'github_pat_'+'a0_'.repeat(160),
  ];
  const rejectedTokens=[
    'ghp_'+'A'.repeat(40),
    'gho_'+'A'.repeat(40),
    'ghu_'+'A'.repeat(40),
    'ghs_'+'A'.repeat(40),
    'github_pat_'+'A'.repeat(19),
    'github_pat_'+'A'.repeat(481),
    'github_pat_'+'A'.repeat(20)+'-',
    ' github_pat_'+'A'.repeat(20),
  ];
  for(const value of validTokens){
    assert.equal(fineGrainedGitHubTokenSchema.parse(value),value);
    assert.equal(validateFineGrainedGitHubToken(value),value);
  }
  for(const value of rejectedTokens){
    assert.throws(()=>fineGrainedGitHubTokenSchema.parse(value),/fine-grained personal access token/);
    assert.throws(()=>validateFineGrainedGitHubToken(value),/fine-grained personal access token/);
  }

  let requests=0,authorization='';
  const originalFetch=globalThis.fetch;
  globalThis.fetch=async(_url,options)=>{requests+=1;authorization=options.headers.Authorization;return json({login:'Dezocode'});};
  try{
    assert.throws(()=>githubClient(rejectedTokens[0]),/fine-grained personal access token/);
    assert.deepEqual(await githubClient(validTokens[0])('/user'),{login:'Dezocode'});
  }
  finally{globalThis.fetch=originalFetch;}
  assert.equal(requests,1,'the rejected credential reached transport or the accepted credential did not');
  assert.equal(authorization,`Bearer ${validTokens[0]}`);

  const [route,connections,native,nativeTransport]=await Promise.all([
    readFile(new URL('../app/api/github/route.ts',import.meta.url),'utf8'),
    readFile(new URL('../app/connections.tsx',import.meta.url),'utf8'),
    readFile(new URL('../ios/LocalSandbox/GitHubSync.swift',import.meta.url),'utf8'),
    readFile(new URL('../ios/LocalSandbox/GitHubTransport.swift',import.meta.url),'utf8'),
  ]);
  assert.equal((route.match(/token:fineGrainedGitHubTokenSchema/g)??[]).length,4);
  assert.doesNotMatch(route,/const token=z\.string/);
  assert.match(connections,/submittedToken=fineGrainedGitHubToken\(token\)/);
  assert.match(native,/\^github_pat_\[A-Za-z0-9_\]\{20,480\}\$/);
  assert.match(native,/private let credential:GitHubFineGrainedCredential/);
  assert.match(native,/let credential=try GitHubFineGrainedCredential\(token\);let name=try await GitHubClient\(credential:credential\)\.login\(\);try Keychain\.set\(credential\.rawValue/);
  assert.doesNotMatch(native+nativeTransport,/\.data\(for:/);
  assert.match(native,/transport\.perform\(request,maximumResponseBytes:GitHubTransportLimits\.responseBytes\)/);
  assert.match(nativeTransport,/session\.bytes\(for: request\)/);
  assert.match(nativeTransport,/GITHUB_RESPONSE_TOO_LARGE/);
  assert.match(nativeTransport,/GITHUB_RESPONSE_CONTENT_TYPE_INVALID/);
  assert.match(native,/GitHubCredentialDisconnect\(deleteChecked:\{try Keychain\.deleteChecked\("githubToken"\)\},readChecked:\{try Keychain\.getChecked\("githubToken"\)\}\)\.perform\(\)/);
  assert.doesNotMatch(native,/Keychain\.delete\("githubToken"\)/);
  assert.match(nativeTransport,/guard try readChecked\(\) == nil/);
});

test('repository, branch, path, token, and content boundaries reject unsafe values',async()=>{
  assert.equal(validateGitHubRepository('Dezocode/Local-Sandbox'),'Dezocode/Local-Sandbox');
  for(const value of ['https://github.com/a/b','a/b/c','-owner/repo','owner/..','owner/repo?token=x'])assert.throws(()=>validateGitHubRepository(value));
  assert.equal(validateGitHubBranch('feature/phone-0.3'),'feature/phone-0.3');
  for(const value of ['-unsafe','refs//x','x..y','x.lock','x/','x @{ y','x:y','x\\y','HEAD','@','feature/.hidden'])assert.throws(()=>validateGitHubBranch(value));
  assert.equal(validateGitHubPath('workspace/notes.md'),'workspace/notes.md');
  for(const value of ['../secret','workspace/../secret','.github/workflows/release.yml','workspace//x','workspace/'+Array(32).fill('x').join('/')])assert.throws(()=>validateGitHubPath(value));
  assert.equal(validateGitHubContent('private αβ').bytes.length,12);
  for(const value of ['a'.repeat(64001),'nul\0byte','\ud800'])assert.throws(()=>validateGitHubContent(value));
  const client=new GitHubConnection({fetchImpl:async()=>json({login:'Dezocode'})});
  await assert.rejects(()=>client.connect('ghp_'+'classicTokenIsRejected1234567890'),/fine-grained/);
});

test('connection uses only api.github.com, rejects redirects, and disconnect aborts an active request',async()=>{
  const first=routeFetch(call=>{assert.equal(call.url.origin,'https://api.github.com');assert.equal(call.url.pathname,'/user');assert.equal(call.options.redirect,'manual');assert.equal(call.options.credentials,'omit');assert.equal(call.options.cache,'no-store');assert.equal(call.options.referrerPolicy,'no-referrer');assert.equal(call.options.headers.Authorization,`Bearer ${token}`);return json({login:'Dezocode'});});
  const client=new GitHubConnection({fetchImpl:first.fetchImpl});await connect(client);assert.equal(client.connected,true);client.disconnect();assert.equal(client.connected,false);assert.equal(client.identity,null);

  const redirected=new GitHubConnection({fetchImpl:async()=>new Response('',{status:302,headers:{location:'https://evil.test/'}})});
  await assert.rejects(()=>redirected.connect(token),error=>error.code==='redirect');assert.equal(redirected.connected,false);

  let started=()=>{};const active=new Promise(resolve=>{started=resolve;});
  const hanging=new GitHubConnection({fetchImpl:(_url,{signal})=>{started();return new Promise((_resolve,reject)=>signal.addEventListener('abort',()=>reject(new DOMException('aborted','AbortError')),{once:true}));}});
  const pending=hanging.connect(token);await active;hanging.disconnect();await assert.rejects(()=>pending,error=>error.code==='disconnected');assert.equal(hanging.connected,false);
});

test('timeout and disconnect remain active while a response body is stalled',async t=>{
  const stalled=()=>new Response(new ReadableStream({pull(){return new Promise(()=>{});}}),{status:200,headers:{'content-type':'application/json'}});
  await t.test('timeout',async()=>{
    const client=new GitHubConnection({fetchImpl:async()=>stalled(),timeoutMs:20});
    await assert.rejects(()=>client.connect(token),error=>error.code==='timeout');assert.equal(client.connected,false);
  });
  await t.test('disconnect',async()=>{
    let delivered=()=>{};const headersDelivered=new Promise(resolve=>{delivered=resolve;});
    const client=new GitHubConnection({fetchImpl:async()=>{delivered();return stalled();},timeoutMs:1000});
    const pending=client.connect(token);await headersDelivered;await new Promise(resolve=>setTimeout(resolve,0));client.disconnect();
    await assert.rejects(()=>pending,error=>error.code==='disconnected');assert.equal(client.connected,false);
  });
});

test('inspection walks bounded trees and decodes one regular UTF-8 file',async()=>{
  const content='remote αβ',size=bytes(content).length;
  const transport=routeFetch(call=>{
    const {pathname}=call.url;
    if(pathname==='/user')return json({login:'Dezocode'});
    if(pathname==='/repos/Dezocode/example')return json({default_branch:'main',archived:false,disabled:false});
    if(pathname.endsWith('/git/ref/heads/feature/phone'))return ref(sha('a'));
    if(pathname.endsWith(`/git/commits/${sha('a')}`))return json({tree:{sha:sha('b')}});
    if(pathname.endsWith(`/git/trees/${sha('b')}`))return json({truncated:false,tree:[{path:'workspace',type:'tree',mode:'040000',sha:sha('c')}]});
    if(pathname.endsWith(`/git/trees/${sha('c')}`))return json({truncated:false,tree:[{path:'notes.md',type:'blob',mode:'100644',sha:sha('d'),size}]});
    if(pathname.endsWith(`/git/blobs/${sha('d')}`))return json({sha:sha('d'),encoding:'base64',size,content:base64(content)});
    assert.fail(`Unexpected ${call.options.method} ${pathname}`);
  });
  const client=new GitHubConnection({fetchImpl:transport.fetchImpl});await connect(client);
  const target={repository:'Dezocode/example',branch:'feature/phone',path:'workspace/notes.md'};
  assert.deepEqual(await client.inspectFile(target),{target,head:sha('a'),defaultBranch:'main',branchExists:true,content,blobSHA:sha('d'),mode:'100644'});
  assert.ok(transport.calls.every(call=>call.url.origin==='https://api.github.com'&&call.options.redirect==='manual'));
});

test('inspection rejects oversized responses, symlinks, oversized blobs, and malformed UTF-8',async t=>{
  async function inspectWith(finalEntry,blobResponse){
    const transport=routeFetch(call=>{
      const {pathname}=call.url;
      if(pathname==='/user')return json({login:'Dezocode'});
      if(pathname==='/repos/Dezocode/example')return json({default_branch:'main'});
      if(pathname.includes('/git/ref/heads/'))return ref(sha('a'));
      if(pathname.includes('/git/commits/'))return json({tree:{sha:sha('b')}});
      if(pathname.endsWith(`/git/trees/${sha('b')}`))return json({truncated:false,tree:[{path:'workspace',type:'tree',mode:'040000',sha:sha('c')}]});
      if(pathname.endsWith(`/git/trees/${sha('c')}`))return json({truncated:false,tree:[finalEntry]});
      if(pathname.includes('/git/blobs/'))return blobResponse;
      assert.fail(`Unexpected ${pathname}`);
    });
    const client=new GitHubConnection({fetchImpl:transport.fetchImpl});await connect(client);
    return client.inspectFile({repository:'Dezocode/example',branch:'main',path:'workspace/file.txt'});
  }
  await t.test('symlink',async()=>assert.rejects(()=>inspectWith({path:'file.txt',type:'blob',mode:'120000',sha:sha('d'),size:4},json({})),/regular UTF-8/));
  await t.test('oversized blob',async()=>assert.rejects(()=>inspectWith({path:'file.txt',type:'blob',mode:'100644',sha:sha('d'),size:64001},json({})),/up to 64 KB/));
  await t.test('malformed UTF-8',async()=>assert.rejects(()=>inspectWith({path:'file.txt',type:'blob',mode:'100644',sha:sha('d'),size:2},json({sha:sha('d'),encoding:'base64',size:2,content:base64(Uint8Array.of(0xc3,0x28))})),/valid UTF-8/));
  const oversized=new GitHubConnection({fetchImpl:async()=>json({login:'Dezocode'},200,{'content-length':'64001'})});
  await assert.rejects(()=>oversized.connect(token),error=>error.code==='response-too-large');
});

test('an existing branch push checks the head twice, updates without force, and reads the file back',async()=>{
  const local='reviewed local text',size=bytes(local).length;let refReads=0;
  const transport=routeFetch(call=>{
    const {pathname}=call.url,method=call.options.method;
    if(pathname==='/user')return json({login:'Dezocode'});
    if(pathname==='/repos/Dezocode/example')return json({default_branch:'main'});
    if(pathname.endsWith('/git/ref/heads/phone')&&method==='GET'){refReads+=1;return ref(refReads<3?sha('a'):sha('e'));}
    if(pathname.endsWith('/git/refs/heads/phone')&&method==='PATCH'){assert.deepEqual(call.body,{sha:sha('e'),force:false});return ref(sha('e'));}
    if(pathname.endsWith(`/git/commits/${sha('a')}`))return json({tree:{sha:sha('b')}});
    if(pathname.endsWith('/git/blobs')&&method==='POST'){assert.deepEqual(call.body,{content:base64(local),encoding:'base64'});return created(sha('c'));}
    if(pathname.endsWith('/git/trees')&&method==='POST'){assert.deepEqual(call.body,{base_tree:sha('b'),tree:[{path:'workspace/notes.md',mode:'100644',type:'blob',sha:sha('c')}]});return created(sha('d'));}
    if(pathname.endsWith('/git/commits')&&method==='POST'){assert.deepEqual(call.body.parents,[sha('a')]);return created(sha('e'));}
    if(pathname.endsWith(`/git/commits/${sha('e')}`))return json({tree:{sha:sha('d')}});
    if(pathname.endsWith(`/git/trees/${sha('d')}`))return json({truncated:false,tree:[{path:'workspace',type:'tree',mode:'040000',sha:sha('f')}]});
    if(pathname.endsWith(`/git/trees/${sha('f')}`))return json({truncated:false,tree:[{path:'notes.md',type:'blob',mode:'100644',sha:sha('c'),size}]});
    if(pathname.endsWith(`/git/blobs/${sha('c')}`))return json({sha:sha('c'),encoding:'base64',size,content:base64(local)});
    assert.fail(`Unexpected ${method} ${pathname}`);
  });
  const client=new GitHubConnection({fetchImpl:transport.fetchImpl});await connect(client);
  const target=validateGitHubTarget({repository:'Dezocode/example',branch:'phone',path:'workspace/notes.md'});
  const snapshot={target,head:sha('a'),defaultBranch:'main',branchExists:true,content:'old',blobSHA:sha('9'),mode:'100644'};
  assert.deepEqual(await client.pushFile(snapshot,local,'Update reviewed note'),{target,head:sha('e'),defaultBranch:'main',branchExists:true,content:local,blobSHA:sha('c'),mode:'100644'});
  assert.equal(refReads,3);assert.equal(transport.calls.filter(call=>call.options.method==='PATCH').length,1);
});

test('a second head change blocks the non-force update after object preparation',async()=>{
  let refReads=0;
  const transport=routeFetch(call=>{
    const {pathname}=call.url,method=call.options.method;
    if(pathname==='/user')return json({login:'Dezocode'});
    if(pathname==='/repos/Dezocode/example')return json({default_branch:'main'});
    if(pathname.endsWith('/git/ref/heads/phone')&&method==='GET'){refReads+=1;return ref(refReads===1?sha('a'):sha('9'));}
    if(pathname.endsWith(`/git/commits/${sha('a')}`))return json({tree:{sha:sha('b')}});
    if(pathname.endsWith('/git/blobs')&&method==='POST')return created(sha('c'));
    if(pathname.endsWith('/git/trees')&&method==='POST')return created(sha('d'));
    if(pathname.endsWith('/git/commits')&&method==='POST')return created(sha('e'));
    assert.fail(`Unexpected ${method} ${pathname}`);
  });
  const client=new GitHubConnection({fetchImpl:transport.fetchImpl});await connect(client);
  const snapshot={target:{repository:'Dezocode/example',branch:'phone',path:'workspace/notes.md'},head:sha('a'),defaultBranch:'main',branchExists:true,content:'old',blobSHA:sha('8'),mode:'100644'};
  await assert.rejects(()=>client.pushFile(snapshot,'new'),GitHubConflict);assert.equal(transport.calls.some(call=>call.options.method==='PATCH'),false);
});

test('a missing branch is created from the unchanged default head before its non-force commit',async()=>{
  const local='new branch text',size=bytes(local).length;let targetReads=0,branchCreated=false,updated=false;
  const transport=routeFetch(call=>{
    const {pathname}=call.url,method=call.options.method;
    if(pathname==='/user')return json({login:'Dezocode'});
    if(pathname==='/repos/Dezocode/example')return json({default_branch:'main'});
    if(pathname.endsWith('/git/ref/heads/main'))return ref(sha('a'));
    if(pathname.endsWith('/git/ref/heads/new/phone')&&method==='GET'){
      targetReads+=1;if(!branchCreated)return json({message:'Not Found'},404);return ref(updated?sha('e'):sha('a'));
    }
    if(pathname.endsWith('/git/refs')&&method==='POST'){assert.deepEqual(call.body,{ref:'refs/heads/new/phone',sha:sha('a')});branchCreated=true;return ref(sha('a'));}
    if(pathname.endsWith(`/git/commits/${sha('a')}`))return json({tree:{sha:sha('b')}});
    if(pathname.endsWith('/git/blobs')&&method==='POST')return created(sha('c'));
    if(pathname.endsWith('/git/trees')&&method==='POST')return created(sha('d'));
    if(pathname.endsWith('/git/commits')&&method==='POST')return created(sha('e'));
    if(pathname.endsWith('/git/refs/heads/new/phone')&&method==='PATCH'){assert.deepEqual(call.body,{sha:sha('e'),force:false});updated=true;return ref(sha('e'));}
    if(pathname.endsWith(`/git/commits/${sha('e')}`))return json({tree:{sha:sha('d')}});
    if(pathname.endsWith(`/git/trees/${sha('d')}`))return json({truncated:false,tree:[{path:'workspace',type:'tree',mode:'040000',sha:sha('f')}]});
    if(pathname.endsWith(`/git/trees/${sha('f')}`))return json({truncated:false,tree:[{path:'notes.md',type:'blob',mode:'100644',sha:sha('c'),size}]});
    if(pathname.endsWith(`/git/blobs/${sha('c')}`))return json({sha:sha('c'),encoding:'base64',size,content:base64(local)});
    assert.fail(`Unexpected ${method} ${pathname}`);
  });
  const client=new GitHubConnection({fetchImpl:transport.fetchImpl});await connect(client);
  const target={repository:'Dezocode/example',branch:'new/phone',path:'workspace/notes.md'};
  const snapshot={target,head:sha('a'),defaultBranch:'main',branchExists:false,content:null,blobSHA:null,mode:'100644'};
  const result=await client.pushFile(snapshot,local);
  assert.equal(result.head,sha('e'));assert.equal(branchCreated,true);assert.equal(updated,true);assert.equal(targetReads,3);
  const createIndex=transport.calls.findIndex(call=>call.options.method==='POST'&&call.url.pathname.endsWith('/git/refs'));
  const missingIndex=transport.calls.findIndex(call=>call.url.pathname.endsWith('/git/ref/heads/new/phone'));
  assert.ok(createIndex>missingIndex);
});

test('PWA GitHub source has no credential persistence, logging, polling, or hidden request trigger',async()=>{
  const root=new URL('../public/local/',import.meta.url);
  const [client,app,html,worker]=await Promise.all(['github.js','app.js','index.html','sw.js'].map(file=>readFile(new URL(file,root),'utf8')));
  assert.doesNotMatch(client,/localStorage|sessionStorage|indexedDB|openLocalDatabase|console\.|setInterval|BroadcastChannel/);
  assert.match(client,/cache:'no-store'/);assert.match(client,/redirect:'manual'/);assert.match(client,/credentials:'omit'/);
  assert.doesNotMatch(app,/setInterval/);assert.match(app,/github\.connect\(token\)/);assert.match(app,/github\.disconnect\(\)/);
  assert.match(app,/finally\{token='';el\('github-token'\)\.value='';\}/);
  assert.match(html,/id="github-token" type="password" autocomplete="off"/);assert.match(html,/Nothing syncs in the background/);
  assert.match(worker,/['"]\.\/github\.js['"]/);
});

test('locking uses the comparison scrubber, which removes reviewed plaintext from the DOM view',async()=>{
  const view={remote:{textContent:'remote secret'},local:{textContent:'local secret'},meta:{textContent:'commit aaaaaaaa'}};
  resetGitHubComparisonView(view,'Disconnected and cleared.');
  assert.deepEqual(view,{remote:{textContent:'No GitHub version loaded.'},local:{textContent:'No local version selected for comparison.'},meta:{textContent:'Disconnected and cleared.'}});
  const app=await readFile(new URL('../public/local/app.js',import.meta.url),'utf8'),start=app.indexOf("el('lock').onclick"),end=app.indexOf("el('editor').oninput",start),lockHandler=app.slice(start,end);
  assert.match(lockHandler,/clearGitComparison\('Disconnected\. The reviewed GitHub and local text was cleared\.'\)/);
});
