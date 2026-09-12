import assert from'node:assert/strict';
import test from'node:test';
import{readFile}from'node:fs/promises';
import{DIRECT_ONLY_CAPABILITIES,capabilityEnabled,loadDeploymentCapabilities,parseDeploymentCapabilities}from'../public/local/capabilities.js';

const hosted={schemaVersion:1,mode:'hosted',githubDirect:true,cursorOrigin:true,encryptedWorkspaceSync:true};
const selfhost={schemaVersion:1,mode:'static-selfhost',githubDirect:true,cursorOrigin:false,encryptedWorkspaceSync:false};
const response=value=>new Response(typeof value==='string'?value:JSON.stringify(value),{headers:{'content-type':'application/json'}});

test('schema version 1 parses hosted and static self-host capability manifests',async()=>{
  assert.deepEqual(parseDeploymentCapabilities(hosted),hosted);
  assert.deepEqual(parseDeploymentCapabilities(selfhost),selfhost);
  assert.equal(capabilityEnabled(hosted,'cursorOrigin'),true);
  assert.equal(capabilityEnabled(selfhost,'cursorOrigin'),false);
  assert.deepEqual(JSON.parse(await readFile(new URL('../public/local/capabilities.json',import.meta.url),'utf8')),hosted);
});

test('missing, malformed, oversized, and unknown manifests fail closed for server-backed features',async()=>{
  const cases=[
    async()=>{throw Error('missing');},
    async()=>new Response('missing',{status:404}),
    async()=>response('{bad json'),
    async()=>response({...hosted,schemaVersion:2}),
    async()=>response({...hosted,mode:'future-host'}),
    async()=>response({...selfhost,cursorOrigin:true}),
    async()=>response({...hosted,extra:true}),
    async()=>response(' '.repeat(4097)),
    async()=>new Promise(()=>{}),
  ];
  for(const fetchImpl of cases){
    const value=await loadDeploymentCapabilities({fetchImpl,timeoutMs:5});
    assert.deepEqual(value,DIRECT_ONLY_CAPABILITIES);
    assert.equal(value.githubDirect,true);
    assert.equal(value.cursorOrigin,false);
    assert.equal(value.encryptedWorkspaceSync,false);
  }
});

test('the loader requests same-origin uncached metadata and accepts an explicit static package',async()=>{
  const calls=[];
  const value=await loadDeploymentCapabilities({fetchImpl:async(url,options)=>{calls.push({url,options});return response(selfhost);}});
  assert.deepEqual(value,selfhost);
  assert.equal(calls.length,1);assert.equal(calls[0].url,'./capabilities.json');
  const{signal,...options}=calls[0].options;assert.ok(signal instanceof AbortSignal);assert.deepEqual(options,{method:'GET',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{Accept:'application/json'}});
});

test('the app guards callbacks, handlers, tab entry, and automatic refresh before server-backed actions',async()=>{
  const root=new URL('../public/local/',import.meta.url);
  const [app,html,worker]=await Promise.all(['app.js','index.html','sw.js'].map(file=>readFile(new URL(file,root),'utf8')));
  assert.match(app,/originCallback=hasCapability\('cursorOrigin'\)\?receivedOriginCallback:null/);
  assert.match(app,/if\(receivedOriginCallback!==null\).*searchParams\.delete\('cursor_origin'\)/);
  for(const id of ['origin-connect','origin-refresh','origin-load','origin-sync','origin-disconnect'])assert.match(app,new RegExp(`el\\('${id}'\\)\\.onclick=capabilityAction\\('cursorOrigin'`));
  for(const id of ['device-sync-refresh','device-sync-create','device-sync-unlock','device-sync-lock','device-sync-pull','device-sync-push','device-sync-import','device-sync-keep'])assert.match(app,new RegExp(`el\\('${id}'\\)\\.onclick=capabilityAction\\('encryptedWorkspaceSync'`));
  assert.match(app,/button\.dataset\.page==='origin'&&hasCapability\('cursorOrigin'\)/);
  assert.match(app,/button\.dataset\.page==='sync'&&hasCapability\('encryptedWorkspaceSync'\)/);
  assert.match(app,/function showPage\(id\)\{const required=capabilityForPage\(id\);if\(required&&!hasCapability\(required\)\)/);
  assert.match(html,/<button data-page="sync" hidden>/);
  assert.match(html,/<button data-page="origin" hidden>/);
  assert.match(html,/id="deployment-capability-notice"/);
  assert.match(app,/static package has no hosted identity or API service/i);
  assert.match(html,/Capability metadata/);
  assert.match(worker,/local-sandbox-shell-0\.3\.0-build10/);
  for(const file of ['capabilities.js','capabilities.json'])assert.match(worker,new RegExp(`['"]\\./${file.replace('.','\\.')}['"]`));
});
