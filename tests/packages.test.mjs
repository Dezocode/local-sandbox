import test from 'node:test';import assert from 'node:assert/strict';
import{parseCatalog,installOrder}from'../public/local/packages.js';
const p=(id,requires=[])=>({id,name:id,url:'https://example.test/'+id+'.shortcut',sha256:'a'.repeat(64),bytes:20,requires});
test('installer sorts dependencies before runner and preserves empty unavailable catalog',()=>{assert.deepEqual(installOrder(parseCatalog({version:1,release:'0.3.0',packages:[p('runner',['local']),p('local')]})).map(p=>p.id),['local','runner']);assert.deepEqual(parseCatalog({version:1,release:'0.3.0',packages:[]}).packages,[])});
test('installer rejects blank editors, unsafe URLs, duplicate IDs and dependency cycles',()=>{for(const packages of [[{...p('a'),url:'shortcuts://create-shortcut'}],[{...p('a'),url:'https://user:secret@example.test/a.shortcut'}],[p('a'),p('a')],[p('a',['b'])],[p('a',['b']),p('b',['a'])]])assert.throws(()=>parseCatalog({version:1,release:'0.3.0',packages}))});
