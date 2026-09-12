const MAX_MANIFEST_BYTES=4096;
const MODES=new Set(['hosted','static-selfhost']);
const KEYS=['schemaVersion','mode','githubDirect','cursorOrigin','encryptedWorkspaceSync'];

export const DIRECT_ONLY_CAPABILITIES=Object.freeze({
  schemaVersion:1,
  mode:'direct-only',
  githubDirect:true,
  cursorOrigin:false,
  encryptedWorkspaceSync:false,
});

function isRecord(value){return Boolean(value)&&typeof value==='object'&&!Array.isArray(value);}

export function parseDeploymentCapabilities(value){
  if(!isRecord(value)||Object.keys(value).sort().join(',')!==[...KEYS].sort().join(','))throw new Error('The deployment capability manifest has an unexpected shape.');
  if(value.schemaVersion!==1||!MODES.has(value.mode))throw new Error('The deployment capability manifest version or mode is unsupported.');
  for(const key of KEYS.slice(2))if(typeof value[key]!=='boolean')throw new Error(`The deployment capability flag ${key} must be a boolean.`);
  if(value.mode==='static-selfhost'&&(value.cursorOrigin||value.encryptedWorkspaceSync))throw new Error('A static self-host package cannot advertise hosted server capabilities.');
  return Object.freeze(Object.fromEntries(KEYS.map(key=>[key,value[key]])));
}

async function boundedJSON(response){
  const declared=Number(response.headers?.get?.('content-length'));
  if(Number.isFinite(declared)&&declared>MAX_MANIFEST_BYTES)throw new Error('The deployment capability manifest is too large.');
  const text=await response.text();
  if(new TextEncoder().encode(text).byteLength>MAX_MANIFEST_BYTES)throw new Error('The deployment capability manifest is too large.');
  return JSON.parse(text);
}

export async function loadDeploymentCapabilities({fetchImpl=globalThis.fetch,manifestURL='./capabilities.json',timeoutMs=3000}={}){
  if(typeof fetchImpl!=='function')return DIRECT_ONLY_CAPABILITIES;
  const controller=new AbortController();
  let timer;
  try{
    const load=(async()=>{
      const response=await fetchImpl(manifestURL,{method:'GET',credentials:'same-origin',cache:'no-store',redirect:'error',headers:{Accept:'application/json'},signal:controller.signal});
      if(!response?.ok||response.redirected||response.type==='opaqueredirect')throw new Error('The deployment capability manifest is unavailable.');
      return parseDeploymentCapabilities(await boundedJSON(response));
    })();
    const timeout=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error('The deployment capability manifest timed out.'));},timeoutMs);});
    return await Promise.race([load,timeout]);
  }catch{
    return DIRECT_ONLY_CAPABILITIES;
  }finally{
    clearTimeout(timer);
  }
}

export function capabilityEnabled(capabilities,name){return KEYS.slice(2).includes(name)&&capabilities?.[name]===true;}
