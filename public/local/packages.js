const PACKAGE_RELEASE='0.3.0';
const SIGNED_STATUS='signed-awaiting-device-acceptance';
const UNAVAILABLE_STATUS='awaiting-signed-device-exports';
const CATALOG_KEYS=['packages','release','status','version'];
const PACKAGE_KEYS=['bytes','id','name','requires','sha256','url'];
const ID=/^[a-z][a-z0-9-]{0,40}$/;
const NAME=/^[\x21-\x7e](?:[\x20-\x7e]{0,78}[\x21-\x7e])?$/;
function exactObject(value,keys){return !!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join('\0')===keys.join('\0')}
function packageOrigin(value){if(typeof value!=='string'||!value||!/^[\x00-\x7f]+$/.test(value)||value.includes('%')||value.includes('\\'))throw Error('Expected the current canonical HTTPS installer origin.');const origin=new URL(value);if(origin.protocol!=='https:'||origin.username||origin.password||origin.search||origin.hash||origin.pathname!=='/'||origin.origin!==value)throw Error('Expected the current canonical HTTPS installer origin.');return origin.origin}
export function parseCatalog(v,expectedOrigin){
 const origin=packageOrigin(expectedOrigin);
 if(!exactObject(v,CATALOG_KEYS)||v.version!==1||v.release!==PACKAGE_RELEASE||!Array.isArray(v.packages)||v.packages.length>30)throw Error('Invalid Shortcut catalog.');
 if(v.packages.length===0){if(v.status!==UNAVAILABLE_STATUS)throw Error('Unavailable Shortcut catalog status required.');return v}
 if(v.status!==SIGNED_STATUS)throw Error('Signed Shortcut catalog required.');
 const ids=new Set(),names=new Set();for(const p of v.packages){if(!exactObject(p,PACKAGE_KEYS)||typeof p.id!=='string'||!ID.test(p.id)||ids.has(p.id)||typeof p.name!=='string'||!NAME.test(p.name)||names.has(p.name)||typeof p.url!=='string'||p.url!==`${origin}/shortcuts/${PACKAGE_RELEASE}/${p.id}.shortcut`||typeof p.sha256!=='string'||!/^[a-f0-9]{64}$/.test(p.sha256)||!Number.isInteger(p.bytes)||p.bytes<1||p.bytes>5000000||!Array.isArray(p.requires)||new Set(p.requires).size!==p.requires.length||p.requires.includes(p.id)||!p.requires.every(id=>typeof id==='string'&&ID.test(id)))throw Error('Invalid Shortcut package.');const url=new URL(p.url);if(url.protocol!=='https:'||url.origin!==origin||url.username||url.password||url.search||url.hash)throw Error('Expected an installer-origin HTTPS signed Shortcut file.');ids.add(p.id);names.add(p.name)}
 const visited=new Set(),active=new Set();function visit(id){if(active.has(id))throw Error('Shortcut dependency cycle.');if(visited.has(id))return;const p=v.packages.find(p=>p.id===id);if(!p)throw Error('Missing Shortcut dependency.');active.add(id);p.requires.forEach(visit);active.delete(id);visited.add(id)}v.packages.forEach(p=>visit(p.id));return v;
}
export function installOrder(catalog){const result=[],visited=new Set();function add(p){if(visited.has(p.id))return;p.requires.forEach(id=>add(catalog.packages.find(p=>p.id===id)));visited.add(p.id);result.push(p)}catalog.packages.forEach(add);return result}
