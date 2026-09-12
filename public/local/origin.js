const INSTALLATION=/^(?:i|inst)_[a-z0-9]{8,100}$/;
const NAMESPACE=/^ns_[a-z0-9]{8,100}$/;
const REPOSITORY=/^repo_[a-z0-9]{8,100}$/;
const SLUG=/^[A-Za-z0-9._-]{1,100}$/;
const MAX_RESPONSE_BYTES=256*1024;
const decoder=new TextDecoder('utf-8',{fatal:true});

export class OriginClientError extends Error{
  constructor(code,message,status=0){super(message);this.name='OriginClientError';this.code=code;this.status=status;}
}

function object(value){if(!value||typeof value!=='object'||Array.isArray(value))throw new OriginClientError('invalid-response','Cursor Origin returned an invalid response.');return value;}
function clone(value){return JSON.parse(JSON.stringify(value));}
function id(value,pattern,message){if(typeof value!=='string'||!pattern.test(value))throw new OriginClientError('invalid-response',message);return value;}

function installation(value){
  const item=object(value);
  if(!Number.isSafeInteger(item.createdAt)||!Number.isSafeInteger(item.updatedAt)||item.createdAt<0||item.updatedAt<item.createdAt)throw new OriginClientError('invalid-response','Cursor Origin returned invalid installation metadata.');
  return Object.freeze({installationId:id(item.installationId,INSTALLATION,'Cursor Origin returned an invalid installation identifier.'),namespaceId:id(item.namespaceId,NAMESPACE,'Cursor Origin returned an invalid namespace identifier.'),createdAt:item.createdAt,updatedAt:item.updatedAt});
}

function repository(value){
  const item=object(value),owner=object(item.owner);
  const repositoryId=id(item.id,REPOSITORY,'Cursor Origin returned an invalid repository identifier.');
  if(typeof item.name!=='string'||!SLUG.test(item.name)||typeof owner.slug!=='string'||!SLUG.test(owner.slug)||typeof item.defaultBranch!=='string'||item.defaultBranch.length<1||item.defaultBranch.length>255)throw new OriginClientError('invalid-response','Cursor Origin returned invalid repository metadata.');
  id(owner.id,NAMESPACE,'Cursor Origin returned an invalid repository owner.');
  if(item.fullName!==`${owner.slug}/${item.name}`)throw new OriginClientError('invalid-response','Cursor Origin returned a mismatched repository name.');
  let cloneURL;try{cloneURL=new URL(item.cloneUrl);}catch{throw new OriginClientError('invalid-response','Cursor Origin returned an invalid clone URL.');}
  if(cloneURL.protocol!=='https:'||cloneURL.hostname!=='origin.cursor.com'||cloneURL.port||cloneURL.username||cloneURL.password||cloneURL.search||cloneURL.hash||new TextEncoder().encode(item.cloneUrl).byteLength>4096||item.cloneUrl.includes('\\')||/[\u0000-\u001f\u007f]/.test(item.cloneUrl))throw new OriginClientError('invalid-response','Cursor Origin returned an unexpected clone URL.');
  return Object.freeze({id:repositoryId,name:item.name,fullName:item.fullName,owner:{slug:owner.slug,id:owner.id,type:owner.type},defaultBranch:item.defaultBranch,cloneUrl:cloneURL.toString()});
}

function abortError(){const error=new Error('The request was aborted.');error.name='AbortError';return error;}
function withAbort(promise,signal,onAbort){
  if(signal.aborted){onAbort?.();return Promise.reject(abortError());}
  return new Promise((resolve,reject)=>{const aborted=()=>{signal.removeEventListener('abort',aborted);onAbort?.();reject(abortError());};signal.addEventListener('abort',aborted,{once:true});Promise.resolve(promise).then(value=>{signal.removeEventListener('abort',aborted);resolve(value);},error=>{signal.removeEventListener('abort',aborted);reject(error);});});
}

async function boundedJSON(response,signal){
  const declared=Number(response.headers?.get?.('content-length'));
  if(Number.isFinite(declared)&&declared>MAX_RESPONSE_BYTES){void response.body?.cancel?.().catch(()=>undefined);throw new OriginClientError('response-too-large','Cursor Origin returned too much data.');}
  if(response.headers?.get?.('content-type')?.split(';',1)[0]?.trim().toLowerCase()!=='application/json')throw new OriginClientError('invalid-response','Cursor Origin returned an invalid response type.');
  let bytes;
  if(response.body?.getReader){
    const reader=response.body.getReader(),chunks=[];let length=0;
    try{for(;;){const {done,value}=await withAbort(reader.read(),signal,()=>{void reader.cancel().catch(()=>undefined);});if(done)break;length+=value.byteLength;if(length>MAX_RESPONSE_BYTES){void reader.cancel().catch(()=>undefined);throw new OriginClientError('response-too-large','Cursor Origin returned too much data.');}chunks.push(value);}}
    finally{try{reader.releaseLock();}catch{}}
    bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
  }else{bytes=new Uint8Array(await withAbort(response.arrayBuffer(),signal,()=>{void response.body?.cancel?.().catch(()=>undefined);}));if(bytes.length>MAX_RESPONSE_BYTES)throw new OriginClientError('response-too-large','Cursor Origin returned too much data.');}
  try{return JSON.parse(decoder.decode(bytes));}catch(error){if(error instanceof OriginClientError)throw error;throw new OriginClientError('invalid-response','Cursor Origin returned invalid JSON.');}
}

function responseError(value,status){const item=value&&typeof value==='object'&&!Array.isArray(value)?value:{};const code=typeof item.code==='string'?item.code:`HTTP_${status}`;const message=typeof item.error==='string'?item.error:`Cursor Origin request failed with status ${status}.`;return new OriginClientError(code,message,status);}

export class OriginConnection{
  #fetch;
  #timeoutMs;
  #controllers=new Set();
  #generation=0;
  #installations=[];
  #repositories=[];
  #manualCleanupRequired=false;
  #manualCleanupAcknowledgementId=null;

  constructor({fetchImpl=globalThis.fetch,timeoutMs=20000}={}){if(typeof fetchImpl!=='function')throw new TypeError('A fetch implementation is required.');this.#fetch=fetchImpl;this.#timeoutMs=timeoutMs;}
  get installations(){return clone(this.#installations);}
  get repositories(){return clone(this.#repositories);}
  get manualCleanupRequired(){return this.#manualCleanupRequired;}
  startURL(returnTo='/local/index.html'){if(typeof returnTo!=='string'||!returnTo.startsWith('/')||returnTo.startsWith('//'))throw new TypeError('Cursor Origin return path must stay on this site.');return`/api/origin/start?${new URLSearchParams({return_to:returnTo})}`;}
  clear(){this.#generation+=1;for(const controller of this.#controllers)controller.abort();this.#controllers.clear();this.#installations=[];this.#repositories=[];this.#manualCleanupRequired=false;this.#manualCleanupAcknowledgementId=null;}

  async refresh(){const result=object(await this.#request('/api/origin'));if(!Array.isArray(result.installations))throw new OriginClientError('invalid-response','Cursor Origin returned invalid installation state.');if(result.installations.length>20)throw new OriginClientError('invalid-response','Cursor Origin returned too many installations.');if(typeof result.manualCleanupRequired!=='boolean'||(result.manualCleanupAcknowledgementId!==null&&(typeof result.manualCleanupAcknowledgementId!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(result.manualCleanupAcknowledgementId)))||(result.manualCleanupRequired!==(result.manualCleanupAcknowledgementId!==null)))throw new OriginClientError('invalid-response','Cursor Origin returned invalid installation state.');this.#installations=result.installations.map(installation);this.#repositories=[];this.#manualCleanupRequired=result.manualCleanupRequired;this.#manualCleanupAcknowledgementId=result.manualCleanupAcknowledgementId;return this.installations;}
  async listRepositories(installationId){id(installationId,INSTALLATION,'Choose a valid Cursor Origin installation.');const result=object(await this.#request('/api/origin',{kind:'repositories',installationId}));if(!Array.isArray(result.repositories)||result.repositories.length>100||!['all','selected'].includes(result.selectionMode)||typeof result.truncated!=='boolean')throw new OriginClientError('invalid-response','Cursor Origin returned an invalid repository list.');this.#repositories=result.repositories.map(repository);return{repositories:this.repositories,selectionMode:result.selectionMode,truncated:result.truncated};}
  async syncMirror(installationId,repositoryId){id(installationId,INSTALLATION,'Choose a valid Cursor Origin installation.');id(repositoryId,REPOSITORY,'Choose a valid Cursor Origin repository.');const result=object(await this.#request('/api/origin',{kind:'syncMirror',installationId,repositoryId}));if(!['synchronized','pending'].includes(result.status)||repository(result.repository).id!==repositoryId)throw new OriginClientError('invalid-response','Cursor Origin returned an invalid mirror result.');return{status:result.status,repository:repository(result.repository)};}
  async disconnect(installationId){id(installationId,INSTALLATION,'Choose a valid Cursor Origin installation.');const result=object(await this.#request('/api/origin',{kind:'disconnect',installationId}));if(result.disconnected!==true)throw new OriginClientError('invalid-response','Cursor Origin did not confirm disconnection.');await this.refresh();return true;}
  async acknowledgeManualCleanup(){if(this.#manualCleanupAcknowledgementId===null)throw new OriginClientError('cleanup-state-missing','Refresh Cursor Origin cleanup state before acknowledging it.');const acknowledgementId=this.#manualCleanupAcknowledgementId;const result=object(await this.#request('/api/origin',{kind:'acknowledgeManualCleanup',acknowledgementId}));if(result.acknowledged!==true)throw new OriginClientError('invalid-response','Cursor Origin did not confirm manual cleanup review.');await this.refresh();if(this.#manualCleanupRequired)throw new OriginClientError('cleanup-state-changed','Cursor Origin cleanup state changed. Review the current unresolved installation before acknowledging it.');return true;}

  async #request(path,body){
    const generation=this.#generation,controller=new AbortController();this.#controllers.add(controller);const timer=setTimeout(()=>controller.abort('timeout'),this.#timeoutMs);
    try{
      const response=await this.#fetch(path,{method:body===undefined?'GET':'POST',headers:{Accept:'application/json',...(body===undefined?{}:{'Content-Type':'application/json'})},body:body===undefined?undefined:JSON.stringify(body),credentials:'same-origin',cache:'no-store',redirect:'error',signal:controller.signal});
      if(generation!==this.#generation)throw new OriginClientError('cleared','Cursor Origin state was cleared.');
      if(response.status>=300&&response.status<400)throw new OriginClientError('redirect','Cursor Origin returned an unexpected redirect.');
      const value=await boundedJSON(response,controller.signal);
      if(!response.ok)throw responseError(value,response.status);
      return value;
    }catch(error){if(error instanceof OriginClientError)throw error;if(controller.signal.aborted)throw new OriginClientError(controller.signal.reason==='timeout'?'timeout':'cleared',controller.signal.reason==='timeout'?'Cursor Origin timed out.':'Cursor Origin state was cleared.');throw new OriginClientError('network','Cursor Origin could not complete the request.');}
    finally{clearTimeout(timer);this.#controllers.delete(controller);}
  }
}
