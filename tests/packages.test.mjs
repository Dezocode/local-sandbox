import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {parseCatalog,installOrder} from '../public/local/packages.js';

const origin='https://local-sandbox.ctyy4wd4c2.chatgpt.site';
const signedStatus='signed-awaiting-device-acceptance';
const unavailableStatus='awaiting-signed-device-exports';
const p=(id,requires=[])=>({id,name:id,url:`${origin}/shortcuts/0.3.0/${id}.shortcut`,sha256:'a'.repeat(64),bytes:20,requires});
const catalog=(packages,status=packages.length?signedStatus:unavailableStatus)=>({version:1,release:'0.3.0',status,packages});

test('installer pins signed 0.3.0 packages to its current HTTPS origin and sorts dependencies',()=>{
  assert.deepEqual(installOrder(parseCatalog(catalog([p('runner',['local']),p('local')]),origin)).map(p=>p.id),['local','runner']);
  assert.deepEqual(parseCatalog(catalog([]),origin).packages,[]);
  const selfHostedOrigin='https://sandbox.example';
  const selfHostedPackage={...p('local'),url:`${selfHostedOrigin}/shortcuts/0.3.0/local.shortcut`};
  assert.deepEqual(parseCatalog(catalog([selfHostedPackage]),selfHostedOrigin).packages,[selfHostedPackage]);
});

test('installer rejects wrong host, release, status, path, duplicates and dependency faults',()=>{
  const invalidCatalogs=[
    {...catalog([p('local')]),unexpected:true},
    {...catalog([p('local')]),release:'0.3.1'},
    catalog([p('local')],unavailableStatus),
    catalog([],signedStatus),
    catalog([{...p('local'),url:'https://example.test/shortcuts/0.3.0/local.shortcut'}]),
    catalog([{...p('local'),url:`https://user:secret@local-sandbox.ctyy4wd4c2.chatgpt.site/shortcuts/0.3.0/local.shortcut`}]),
    catalog([{...p('local'),url:`${origin}/shortcuts/0.3.0/other.shortcut`}]),
    catalog([{...p('local'),url:`${origin}/unexpected/prefix/0.3.0/local.shortcut`}]),
    catalog([{...p('local'),url:'shortcuts://create-shortcut'}]),
    catalog([{...p('local'),unexpected:true}]),
    catalog([{...p('local'),sha256:'A'.repeat(64)}]),
    catalog([{...p('local'),name:' Agent Step'}]),
    catalog([{...p('local'),name:'Agent\nStep'}]),
    catalog([{...p('local'),name:'Agént Step'}]),
    catalog([{...p('local'),bytes:5000001}]),
    catalog([p('local'),p('local')]),
    catalog([p('local'),{...p('runner'),name:'local'}]),
    catalog([p('local',['local'])]),
    catalog([p('local',['runner','runner']),p('runner')]),
    catalog([p('local',['missing'])]),
    catalog([p('local',['runner']),p('runner',['local'])]),
  ];
  for(const value of invalidCatalogs)assert.throws(()=>parseCatalog(value,origin));
  assert.throws(()=>parseCatalog(catalog([p('local')]),'http://local-sandbox.example'));
  assert.throws(()=>parseCatalog(catalog([p('local')]),`${origin}/local/`));
  assert.throws(()=>parseCatalog(catalog([p('local')]),'https://LOCAL-SANDBOX.ctyy4wd4c2.chatgpt.site'));
  assert.throws(()=>parseCatalog(catalog([p('local')]),`${origin}:443`));
});

test('native Add Shortcut path opens only the locally verified file and gates duplicate verification',async()=>{
  const source=await readFile(new URL('../ios/LocalSandbox/ShortcutPackagesView.swift',import.meta.url),'utf8');
  assert.doesNotMatch(source,/openURL\(package\.url\)|openURL\(p\.url\)/);
  assert.match(source,/let verified = try await ShortcutPackageInstaller\.downloadVerifiedPackage\(package\)[\s\S]*openURL\(verified\.fileURL\)/);
  assert.match(source,/guard installGate\.begin\(package\.id\) else \{ return \}/);
  assert.match(source,/\.disabled\(installsDisabled\)/);
});

test('browser installer validates imported and fetched catalogs against its current origin',async()=>{
  const source=await readFile(new URL('../public/local/install.html',import.meta.url),'utf8');
  assert.match(source,/parseCatalog\(value,location\.origin\)/);
  assert.doesNotMatch(source,/parseCatalog\(value\)(?!,)/);
});
