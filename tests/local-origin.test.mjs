import assert from'node:assert/strict';
import test from'node:test';
import{readFile}from'node:fs/promises';
import{OriginConnection}from'../public/local/origin.js';

const installationId='inst_01k2ja2000e0080000000000b2';
const repositoryId='repo_01k2ja2000e0080000000000q4';
const installed={installationId,namespaceId:'ns_01k2ja2000e0080000000000p3',createdAt:1800000000,updatedAt:1800000001};
const repository={id:repositoryId,name:'rocket',fullName:'acme/rocket',owner:{slug:'acme',id:'ns_01k2ja2000e0080000000000p3',type:'team'},defaultBranch:'main',cloneUrl:'https://origin.cursor.com/acme/rocket.git'};
const json=(value,status=200)=>Response.json(value,{status});
const installationState=installations=>({installations,manualCleanupRequired:false,manualCleanupAcknowledgementId:null});

function transport(handler){const calls=[];return{calls,fetchImpl:async(path,options)=>{calls.push({path,options,body:options.body?JSON.parse(options.body):undefined});return handler(calls.at(-1));}};}

test('Origin client keeps installation start on-site and uses only bounded same-origin API requests',async()=>{
  const mock=transport(call=>{if(call.options.method==='GET')return json(installationState([installed]));if(call.body.kind==='repositories')return json({repositories:[repository],selectionMode:'selected',truncated:false});if(call.body.kind==='syncMirror')return json({status:'pending',repository});if(call.body.kind==='disconnect')return json({disconnected:true});return json({error:'unexpected'},500);});
  const connection=new OriginConnection({fetchImpl:mock.fetchImpl});
  assert.equal(connection.startURL(),'/api/origin/start?return_to=%2Flocal%2Findex.html');
  assert.deepEqual(await connection.refresh(),[installed]);
  assert.deepEqual(await connection.listRepositories(installationId),{repositories:[repository],selectionMode:'selected',truncated:false});
  assert.equal((await connection.syncMirror(installationId,repositoryId)).status,'pending');
  await connection.disconnect(installationId);
  assert.ok(mock.calls.every(call=>call.path==='/api/origin'&&call.options.credentials==='same-origin'&&call.options.cache==='no-store'&&call.options.redirect==='error'));
  assert.deepEqual(mock.calls.filter(call=>call.options.method==='POST').map(call=>call.body),[
    {kind:'repositories',installationId},
    {kind:'syncMirror',installationId,repositoryId},
    {kind:'disconnect',installationId},
  ]);
  assert.doesNotMatch(JSON.stringify(mock.calls),/oit_|Bearer|private.key/i);
});

test('Origin client rejects forged repository metadata and oversized installation lists',async()=>{
  for(const cloneUrl of [
    'https://origin.cursor.com/git/acme/rocket.git',
    'https://origin.cursor.com/v2/repositories/opaque_clone_token.git',
    'https://origin.cursor.com/%E7%A0%82%E7%AE%B1/%2Fopaque',
    'https://origin.cursor.com/砂箱/存储库',
    'https://origin.cursor.com/',
  ]){
    const compatible=new OriginConnection({fetchImpl:async(_path,options)=>options.method==='GET'?json(installationState([installed])):json({repositories:[{...repository,cloneUrl}],selectionMode:'selected',truncated:false})});
    await compatible.refresh();
    assert.equal((await compatible.listRepositories(installationId)).repositories[0].cloneUrl,new URL(cloneUrl).toString());
  }
  const badClone=new OriginConnection({fetchImpl:async(_path,options)=>options.method==='GET'?json(installationState([installed])):json({repositories:[{...repository,cloneUrl:'https://attacker.example/acme/rocket.git'}],selectionMode:'selected',truncated:false})});
  await badClone.refresh();await assert.rejects(()=>badClone.listRepositories(installationId),/unexpected clone URL/);
  const tooMany=new OriginConnection({fetchImpl:async()=>json(installationState(Array(21).fill(installed)))});
  await assert.rejects(()=>tooMany.refresh(),/too many installations/);
});

test('manual cleanup acknowledgement applies only after a final current-state read',async()=>{
  const oldAcknowledgement='A'.repeat(43),currentAcknowledgement='B'.repeat(43);
  let reads=0;
  const mock=transport(call=>{
    if(call.options.method==='GET'){
      reads+=1;
      const acknowledgementId=reads===1?oldAcknowledgement:currentAcknowledgement;
      return json({installations:[],manualCleanupRequired:true,manualCleanupAcknowledgementId:acknowledgementId});
    }
    assert.deepEqual(call.body,{kind:'acknowledgeManualCleanup',acknowledgementId:oldAcknowledgement});
    return json({acknowledged:true});
  });
  const connection=new OriginConnection({fetchImpl:mock.fetchImpl});
  await connection.refresh();
  await assert.rejects(
    ()=>connection.acknowledgeManualCleanup(),
    error=>error instanceof Error&&error.code==='cleanup-state-changed',
  );
  assert.equal(reads,2);
  assert.equal(connection.manualCleanupRequired,true);
});

test('timeout and clear stay active while an Origin response body is stalled',async t=>{
  const stalled=()=>new Response(new ReadableStream({pull(){return new Promise(()=>{});}}),{status:200,headers:{'content-type':'application/json'}});
  await t.test('timeout',async()=>{const connection=new OriginConnection({fetchImpl:async()=>stalled(),timeoutMs:20});await assert.rejects(()=>connection.refresh(),error=>error.code==='timeout');});
  await t.test('clear',async()=>{let delivered=()=>{};const ready=new Promise(resolve=>{delivered=resolve;});const connection=new OriginConnection({fetchImpl:async()=>{delivered();return stalled();},timeoutMs:1000});const pending=connection.refresh();await ready;await new Promise(resolve=>setTimeout(resolve,0));connection.clear();await assert.rejects(()=>pending,error=>error.code==='cleared');assert.deepEqual(connection.installations,[]);});
});

test('local PWA source exposes manual Origin controls without tokens, polling, or metadata persistence',async()=>{
  const root=new URL('../public/local/',import.meta.url);const [client,app,html,worker]=await Promise.all(['origin.js','app.js','index.html','sw.js'].map(file=>readFile(new URL(file,root),'utf8')));
  assert.doesNotMatch(client,/localStorage|sessionStorage|indexedDB|setInterval|Authorization|access_tokens/);
  assert.match(client,/credentials:'same-origin'/);assert.match(client,/cache:'no-store'/);assert.match(client,/redirect:'error'/);
  assert.match(app,/origin\.startURL/);assert.match(app,/origin\.syncMirror/);assert.match(app,/origin\.clear\(\)/);
  assert.match(html,/id="origin-connect"/);assert.match(html,/nothing runs in the background/i);
  assert.match(worker,/['"]\.\/origin\.js['"]/);
});
