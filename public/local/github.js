import{validPath}from'./vault.js';

const API_ORIGIN='https://api.github.com';
const API_VERSION='2026-03-10';
const MAX_FILE_BYTES=64000;
const MAX_JSON_BYTES=1000000;
const MAX_TREE_ENTRIES=4096;
const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
const SHA=/^[a-f0-9]{40}$/;
const OWNER=/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPOSITORY=/^[A-Za-z0-9_.-]{1,100}$/;
const TOKEN=/^github_pat_[A-Za-z0-9_]{20,480}$/;

export class GitHubError extends Error{
  constructor(code,message,status=0){super(message);this.name='GitHubError';this.code=code;this.status=status;}
}

export class GitHubConflict extends GitHubError{
  constructor(message='The GitHub branch changed. Compare again before committing.'){super('conflict',message,409);this.name='GitHubConflict';}
}

function clone(value){return JSON.parse(JSON.stringify(value));}

function assertObject(value,message='GitHub returned an invalid response.'){
  if(!value||typeof value!=='object'||Array.isArray(value))throw new GitHubError('invalid-response',message);
  return value;
}

function validSHA(value){
  if(typeof value!=='string'||!SHA.test(value))throw new GitHubError('invalid-response','GitHub returned an invalid commit identifier.');
  return value;
}

function encodeSegments(value){return value.split('/').map(encodeURIComponent).join('/');}

function repositoryRoot(repository){return`/repos/${repository.split('/').map(encodeURIComponent).join('/')}`;}

function branchRef(root,branch){return`${root}/git/ref/heads/${encodeSegments(branch)}`;}

export function validateFineGrainedGitHubToken(token){
  if(typeof token!=='string'||!TOKEN.test(token))throw new GitHubError('invalid-token','Enter a fine-grained personal access token beginning with github_pat_.');
  return token;
}

export function validateGitHubRepository(value){
  if(typeof value!=='string'||value.length>141)throw new GitHubError('invalid-target','Repository must use owner/name.');
  const parts=value.split('/');
  if(parts.length!==2||!OWNER.test(parts[0])||!REPOSITORY.test(parts[1])||parts[1]==='.'||parts[1]==='..')throw new GitHubError('invalid-target','Repository must use a valid owner/name with no URL or credentials.');
  return`${parts[0]}/${parts[1]}`;
}

export function validateGitHubBranch(value){
  if(typeof value!=='string'||value.length>255||encoder.encode(value).length>1024||value==='@'||value==='HEAD'||value.startsWith('-')||value.startsWith('.')||value.startsWith('/')||value.endsWith('/')||value.endsWith('.')||value.includes('//')||value.includes('..')||value.includes('@{')||/[\u0000-\u0020\u007f~^:?*[\\]/.test(value)||value.split('/').some(part=>!part||part.startsWith('.')||part.endsWith('.lock')))throw new GitHubError('invalid-target','Branch name contains characters GitHub cannot use safely.');
  return value;
}

export function validateGitHubPath(value){
  const parts=typeof value==='string'?value.split('/'):[];
  if(!validPath(value)||encoder.encode(value).length>512||parts.length>32||parts.some(part=>encoder.encode(part).length>255))throw new GitHubError('invalid-target','Use a bounded sandbox-relative path such as workspace/notes.md.');
  return value;
}

export function validateGitHubTarget(value){
  const target=assertObject(value,'Choose a GitHub repository, branch, and file path.');
  return Object.freeze({repository:validateGitHubRepository(target.repository),branch:validateGitHubBranch(target.branch),path:validateGitHubPath(target.path)});
}

export function validateGitHubContent(value){
  if(typeof value!=='string')throw new GitHubError('invalid-content','Only text files can be committed.');
  const bytes=encoder.encode(value);
  if(bytes.length>MAX_FILE_BYTES||value.includes('\0')||decoder.decode(bytes)!==value)throw new GitHubError('invalid-content','Only valid UTF-8 text files up to 64 KB can be committed.');
  return{content:value,bytes};
}

export function resetGitHubComparisonView(view,message='Compare manually before importing or committing.'){
  if(!view?.remote||!view?.local||!view?.meta)throw new TypeError('GitHub comparison view is unavailable.');
  view.remote.textContent='No GitHub version loaded.';view.local.textContent='No local version selected for comparison.';view.meta.textContent=message;
}

function decodeBase64(value){
  if(typeof value!=='string')throw new GitHubError('invalid-response','GitHub returned an invalid text blob.');
  const compact=value.replace(/[\r\n]/g,'');
  if(compact.length>Math.ceil(MAX_FILE_BYTES/3)*4+4||compact.length%4!==0||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact))throw new GitHubError('invalid-response','GitHub returned an invalid text blob.');
  try{return Uint8Array.from(atob(compact),character=>character.charCodeAt(0));}
  catch{throw new GitHubError('invalid-response','GitHub returned an invalid text blob.');}
}

function encodeBase64(bytes){
  let binary='';
  for(let offset=0;offset<bytes.length;offset+=32768)binary+=String.fromCharCode(...bytes.subarray(offset,offset+32768));
  return btoa(binary);
}

function abortError(){const error=new Error('The request was aborted.');error.name='AbortError';return error;}

function withAbort(promise,signal,onAbort){
  if(signal.aborted){onAbort?.();return Promise.reject(abortError());}
  return new Promise((resolve,reject)=>{
    const aborted=()=>{signal.removeEventListener('abort',aborted);onAbort?.();reject(abortError());};
    signal.addEventListener('abort',aborted,{once:true});
    Promise.resolve(promise).then(value=>{signal.removeEventListener('abort',aborted);resolve(value);},error=>{signal.removeEventListener('abort',aborted);reject(error);});
  });
}

async function boundedJSON(response,maxBytes,signal){
  const declared=Number(response.headers?.get?.('content-length'));
  if(Number.isFinite(declared)&&declared>maxBytes){void response.body?.cancel?.().catch(()=>undefined);throw new GitHubError('response-too-large','GitHub returned more data than this bounded connection accepts.');}
  let bytes;
  if(response.body?.getReader){
    const reader=response.body.getReader(),chunks=[];let length=0;
    try{
      for(;;){const {done,value}=await withAbort(reader.read(),signal,()=>{void reader.cancel().catch(()=>undefined);});if(done)break;length+=value.byteLength;if(length>maxBytes){void reader.cancel().catch(()=>undefined);throw new GitHubError('response-too-large','GitHub returned more data than this bounded connection accepts.');}chunks.push(value);}
    }finally{try{reader.releaseLock();}catch{}}
    bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
  }else{
    bytes=new Uint8Array(await withAbort(response.arrayBuffer(),signal,()=>{void response.body?.cancel?.().catch(()=>undefined);}));
    if(bytes.length>maxBytes)throw new GitHubError('response-too-large','GitHub returned more data than this bounded connection accepts.');
  }
  try{return JSON.parse(decoder.decode(bytes));}
  catch(error){if(error instanceof GitHubError)throw error;throw new GitHubError('invalid-response','GitHub returned invalid JSON.');}
}

function statusError(status){
  if(status===401)return new GitHubError('authentication','GitHub rejected this token. Reconnect with a fine-grained token.',status);
  if(status===403)return new GitHubError('permission','GitHub denied this request. Grant Contents access to the selected repository.',status);
  if(status===404)return new GitHubError('not-found','The repository, branch, file, or token permission was not found.',status);
  if(status===409||status===422)return new GitHubConflict();
  if(status===410)return new GitHubError('api-version','This GitHub API version is no longer available. Update Local Sandbox.',status);
  return new GitHubError('request',`GitHub request failed with status ${status}.`,status);
}

function parseRef(value){
  const object=assertObject(assertObject(value).object);
  return validSHA(object.sha);
}

function parseRepository(value){
  const repository=assertObject(value);
  return{defaultBranch:validateGitHubBranch(repository.default_branch),archived:repository.archived===true,disabled:repository.disabled===true};
}

function parseCommitTree(value){return validSHA(assertObject(assertObject(value).tree).sha);}

function parseCreatedSHA(value){return validSHA(assertObject(value).sha);}

function parseTree(value){
  const tree=assertObject(value);
  if(tree.truncated===true)throw new GitHubError('tree-too-large','A GitHub directory listing was truncated. Use a smaller directory.');
  if(!Array.isArray(tree.tree)||tree.tree.length>MAX_TREE_ENTRIES)throw new GitHubError('tree-too-large','A GitHub directory has too many entries for bounded inspection.');
  return tree.tree.map(entry=>{
    const item=assertObject(entry);
    if(typeof item.path!=='string'||item.path.includes('/')||typeof item.type!=='string'||typeof item.mode!=='string')throw new GitHubError('invalid-response','GitHub returned an invalid tree entry.');
    return{path:item.path,type:item.type,mode:item.mode,sha:validSHA(item.sha),size:item.size};
  });
}

function validateSnapshot(value){
  const snapshot=assertObject(value,'Compare with GitHub before committing.');
  const target=validateGitHubTarget(snapshot.target);
  const head=validSHA(snapshot.head);
  const defaultBranch=validateGitHubBranch(snapshot.defaultBranch);
  if(typeof snapshot.branchExists!=='boolean'||(snapshot.content!==null&&typeof snapshot.content!=='string')||(snapshot.blobSHA!==null&&typeof snapshot.blobSHA!=='string')||!['100644','100755'].includes(snapshot.mode??'100644'))throw new GitHubError('invalid-snapshot','Compare with GitHub again before committing.');
  if(snapshot.blobSHA!==null)validSHA(snapshot.blobSHA);
  if(snapshot.content!==null)validateGitHubContent(snapshot.content);
  return{target,head,defaultBranch,branchExists:snapshot.branchExists,content:snapshot.content,blobSHA:snapshot.blobSHA,mode:snapshot.mode??'100644'};
}

export class GitHubConnection{
  #fetch;
  #timeoutMs;
  #token='';
  #identity=null;
  #generation=0;
  #controllers=new Set();

  constructor({fetchImpl=globalThis.fetch,timeoutMs=20000}={}){
    if(typeof fetchImpl!=='function')throw new TypeError('A fetch implementation is required.');
    this.#fetch=fetchImpl;this.#timeoutMs=timeoutMs;
  }

  get identity(){return this.#identity?clone(this.#identity):null;}
  get connected(){return this.#token!==''&&this.#identity!==null;}

  async connect(token){
    this.disconnect();
    this.#token=validateFineGrainedGitHubToken(token);
    const generation=this.#generation;
    try{
      const value=assertObject(await this.#request('/user',{maxBytes:64000,generation}));
      if(typeof value.login!=='string'||!OWNER.test(value.login))throw new GitHubError('invalid-response','GitHub returned an invalid account identity.');
      this.#identity=Object.freeze({login:value.login});
      return this.identity;
    }catch(error){this.disconnect();throw error;}
  }

  disconnect(){
    this.#generation+=1;this.#token='';this.#identity=null;
    for(const controller of this.#controllers)controller.abort();
    this.#controllers.clear();
  }

  async inspectFile(rawTarget){
    this.#requireConnected();
    const target=validateGitHubTarget(rawTarget),root=repositoryRoot(target.repository);
    const repository=parseRepository(await this.#request(root,{maxBytes:128000}));
    if(repository.archived||repository.disabled)throw new GitHubError('read-only','This repository is archived or disabled.');
    let head=await this.#readRef(root,target.branch,true),branchExists=head!==null;
    if(head===null){head=await this.#readRef(root,repository.defaultBranch,false);}
    const file=await this.#readFile(root,head,target.path);
    return Object.freeze({target,head,defaultBranch:repository.defaultBranch,branchExists,content:file.content,blobSHA:file.blobSHA,mode:file.mode});
  }

  async pushFile(rawSnapshot,rawContent,rawMessage){
    this.#requireConnected();
    const snapshot=validateSnapshot(rawSnapshot),{content,bytes}=validateGitHubContent(rawContent);
    const target=snapshot.target,root=repositoryRoot(target.repository);
    const message=rawMessage===undefined||rawMessage===''?`Local Sandbox: update ${target.path}`:rawMessage;
    if(typeof message!=='string'||message.trim()!==message||message.length<1||message.length>120||/[\u0000-\u001f\u007f]/.test(message))throw new GitHubError('invalid-message','Commit message must be 1 to 120 characters on one line.');
    const repository=parseRepository(await this.#request(root,{maxBytes:128000}));
    if(repository.archived||repository.disabled)throw new GitHubError('read-only','This repository is archived or disabled.');

    if(snapshot.branchExists){
      const current=await this.#readRef(root,target.branch,false);
      if(current!==snapshot.head)throw new GitHubConflict('The branch advanced after your comparison. Compare again; no commit was published.');
    }else{
      if(repository.defaultBranch!==snapshot.defaultBranch)throw new GitHubConflict('The default branch changed after your comparison. Compare again; no branch was created.');
      const defaultHead=await this.#readRef(root,repository.defaultBranch,false);
      if(defaultHead!==snapshot.head)throw new GitHubConflict('The default branch advanced after your comparison. Compare again; no branch was created.');
      if(await this.#readRef(root,target.branch,true)!==null)throw new GitHubConflict('The target branch was created after your comparison. Compare it before committing.');
      const created=parseRef(await this.#request(`${root}/git/refs`,{method:'POST',body:{ref:`refs/heads/${target.branch}`,sha:snapshot.head},maxBytes:128000}));
      if(created!==snapshot.head)throw new GitHubConflict('GitHub created the branch at an unexpected commit. Compare it before committing.');
    }

    const baseTree=parseCommitTree(await this.#request(`${root}/git/commits/${snapshot.head}`,{maxBytes:256000}));
    const blobSHA=parseCreatedSHA(await this.#request(`${root}/git/blobs`,{method:'POST',body:{content:encodeBase64(bytes),encoding:'base64'},maxBytes:128000}));
    const treeSHA=parseCreatedSHA(await this.#request(`${root}/git/trees`,{method:'POST',body:{base_tree:baseTree,tree:[{path:target.path,mode:snapshot.mode,type:'blob',sha:blobSHA}]},maxBytes:128000}));
    const commitSHA=parseCreatedSHA(await this.#request(`${root}/git/commits`,{method:'POST',body:{message,tree:treeSHA,parents:[snapshot.head]},maxBytes:256000}));
    const beforeUpdate=await this.#readRef(root,target.branch,false);
    if(beforeUpdate!==snapshot.head)throw new GitHubConflict('The branch advanced while the commit was prepared. The branch was not updated. Compare again.');

    try{
      const updated=parseRef(await this.#request(`${root}/git/refs/heads/${encodeSegments(target.branch)}`,{method:'PATCH',body:{sha:commitSHA,force:false},maxBytes:128000}));
      if(updated!==commitSHA)throw new GitHubConflict('GitHub did not confirm the new branch head. Compare again.');
    }catch(error){
      if(error instanceof GitHubConflict)throw error;
      try{if(await this.#readRef(root,target.branch,false)===commitSHA)return this.#verifiedSnapshot(target,repository.defaultBranch,commitSHA,content,blobSHA,snapshot.mode);}
      catch{throw new GitHubError('uncertain','The GitHub update result is uncertain. Compare again before retrying.');}
      throw new GitHubError('uncertain','The GitHub update result is uncertain. Compare again before retrying.');
    }
    return this.#verifiedSnapshot(target,repository.defaultBranch,commitSHA,content,blobSHA,snapshot.mode);
  }

  async #verifiedSnapshot(target,defaultBranch,commitSHA,content,blobSHA,mode){
    const root=repositoryRoot(target.repository),confirmed=await this.#readRef(root,target.branch,false);
    if(confirmed!==commitSHA)throw new GitHubConflict('The branch moved immediately after the commit. Compare again before another change.');
    const file=await this.#readFile(root,commitSHA,target.path);
    if(file.blobSHA!==blobSHA||file.content!==content)throw new GitHubError('readback','GitHub did not return the committed file exactly. Compare again before retrying.');
    return Object.freeze({target,head:commitSHA,defaultBranch,branchExists:true,content,blobSHA,mode});
  }

  async #readFile(root,commit,path){
    let treeSHA=parseCommitTree(await this.#request(`${root}/git/commits/${commit}`,{maxBytes:256000}));
    const segments=path.split('/');
    for(let index=0;index<segments.length;index+=1){
      const entries=parseTree(await this.#request(`${root}/git/trees/${treeSHA}`,{maxBytes:MAX_JSON_BYTES}));
      const matches=entries.filter(entry=>entry.path===segments[index]);
      if(matches.length===0)return{content:null,blobSHA:null,mode:'100644'};
      if(matches.length!==1)throw new GitHubError('invalid-response','GitHub returned duplicate tree entries.');
      const entry=matches[0],last=index===segments.length-1;
      if(!last){if(entry.type!=='tree'||entry.mode!=='040000')throw new GitHubError('not-regular','The selected GitHub path crosses a non-directory entry.');treeSHA=entry.sha;continue;}
      if(entry.type!=='blob'||!['100644','100755'].includes(entry.mode)||!Number.isSafeInteger(entry.size)||entry.size<0||entry.size>MAX_FILE_BYTES)throw new GitHubError('not-regular','Only regular UTF-8 GitHub files up to 64 KB can be compared.');
      const blob=assertObject(await this.#request(`${root}/git/blobs/${entry.sha}`,{maxBytes:128000}));
      if(blob.encoding!=='base64'||blob.sha!==entry.sha||blob.size!==entry.size)throw new GitHubError('invalid-response','GitHub returned inconsistent file metadata.');
      const bytes=decodeBase64(blob.content);
      if(bytes.length!==entry.size||bytes.length>MAX_FILE_BYTES)throw new GitHubError('invalid-response','GitHub returned inconsistent file data.');
      let content;try{content=decoder.decode(bytes);}catch{throw new GitHubError('not-text','Only valid UTF-8 GitHub files can be compared.');}
      if(content.includes('\0'))throw new GitHubError('not-text','Binary GitHub files cannot be compared.');
      return{content,blobSHA:entry.sha,mode:entry.mode};
    }
    throw new GitHubError('invalid-target','Choose a file path.');
  }

  async #readRef(root,branch,allowMissing){
    const value=await this.#request(branchRef(root,branch),{allow404:allowMissing,maxBytes:128000});
    return value===null?null:parseRef(value);
  }

  #requireConnected(){if(!this.connected)throw new GitHubError('disconnected','Connect GitHub for this app session first.');}

  async #request(path,{method='GET',body,allow404=false,maxBytes=MAX_JSON_BYTES,generation=this.#generation}={}){
    this.#requireToken();
    if(typeof path!=='string'||!path.startsWith('/')||path.startsWith('//'))throw new GitHubError('origin','GitHub API path is invalid.');
    const url=new URL(path,API_ORIGIN);
    if(url.origin!==API_ORIGIN||url.username||url.password)throw new GitHubError('origin','GitHub requests are restricted to api.github.com.');
    const controller=new AbortController();this.#controllers.add(controller);
    const headers={Accept:'application/vnd.github+json',Authorization:`Bearer ${this.#token}`,'X-GitHub-Api-Version':API_VERSION};
    if(body!==undefined)headers['Content-Type']='application/json';
    let response,timedOut=false;
    const timeout=setTimeout(()=>{timedOut=true;controller.abort();},this.#timeoutMs);
    try{
      response=await this.#fetch(url.href,{method,headers,body:body===undefined?undefined:JSON.stringify(body),redirect:'manual',credentials:'omit',cache:'no-store',referrerPolicy:'no-referrer',mode:'cors',signal:controller.signal});
      if(generation!==this.#generation)throw new GitHubError('disconnected','GitHub disconnected.');
      if(!response||typeof response.status!=='number')throw new GitHubError('invalid-response','GitHub returned an invalid response.');
      if(response.redirected||response.type==='opaqueredirect'||(response.url&&new URL(response.url).origin!==API_ORIGIN)||response.status>=300&&response.status<400)throw new GitHubError('redirect','GitHub redirected a request, so Local Sandbox stopped it.');
      if(response.status===404&&allow404)return null;
      if(!response.ok)throw statusError(response.status);
      const value=await boundedJSON(response,maxBytes,controller.signal);
      if(generation!==this.#generation)throw new GitHubError('disconnected','GitHub disconnected.');
      return value;
    }catch(error){
      if(error instanceof GitHubError)throw error;
      if(generation!==this.#generation)throw new GitHubError('disconnected','GitHub disconnected.');
      if(timedOut||error?.name==='AbortError')throw new GitHubError('timeout','GitHub did not finish before the request timed out.');
      throw new GitHubError('network','GitHub is unavailable. Check the connection and try again.');
    }finally{clearTimeout(timeout);this.#controllers.delete(controller);}
  }

  #requireToken(){if(this.#token==='')throw new GitHubError('disconnected','Connect GitHub for this app session first.');}
}
