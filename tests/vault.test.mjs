import test from 'node:test';
import assert from 'node:assert/strict';
import {seal,unseal,validVault} from '../public/local/vault.js';
const sample={version:1,files:{'workspace/notes.md':'private αβ'},messages:[{role:'Oracle',text:'Read the file',at:'2026-09-10T00:00:00Z'}]};
test('encrypted vault round-trips unicode content and contains no plaintext',async()=>{const a=await seal(sample,'a long local password');assert.deepEqual(await unseal(a,'a long local password'),sample);assert.equal(JSON.stringify(a).includes('private'),false)});
test('wrong password and modified ciphertext cannot unlock vault',async()=>{const a=await seal(sample,'a long local password');await assert.rejects(()=>unseal(a,'wrong password'));const bytes=Buffer.from(a.data,'base64');bytes[0]^=1;await assert.rejects(()=>unseal({...a,data:bytes.toString('base64')},'a long local password'))});
test('every encryption has fresh salt and IV',async()=>{const a=await seal(sample,'a long local password'),b=await seal(sample,'a long local password');assert.notEqual(a.salt,b.salt);assert.notEqual(a.iv,b.iv);assert.notEqual(a.data,b.data)});
test('backup validation excludes path escapes and oversized files',()=>{for(const path of ['../secret','workspace/../secret','config/.hidden','workspace//x'])assert.throws(()=>validVault({...sample,files:{[path]:'x'}}));assert.throws(()=>validVault({...sample,files:{'workspace/a':'a'.repeat(64001)}}))});
