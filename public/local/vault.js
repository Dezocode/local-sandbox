const encoder=new TextEncoder();
const decoder=new TextDecoder();
const PATH=/^(workspace|config|state|logs|output)\/[A-Za-z0-9_-][A-Za-z0-9_./-]*$/;
const MAX_FILE_BYTES=64000;
const MAX_VAULT_BYTES=10000000;
const FORMAT='local-sandbox.vault';

function encode(value){
  const bytes=new Uint8Array(value);let binary='';
  for(let offset=0;offset<bytes.length;offset+=32768)binary+=String.fromCharCode(...bytes.subarray(offset,offset+32768));
  return btoa(binary);
}
const decode=value=>Uint8Array.from(atob(value),character=>character.charCodeAt(0));

function joined(left,right){const value=new Uint8Array(left.length+right.length);value.set(left);value.set(right,left.length);return value;}

function randomToken(bytes=18){
  return encode(crypto.getRandomValues(new Uint8Array(bytes))).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}

function validMessage(message){
  return Boolean(message&&['Oracle','Locally response'].includes(message.role)&&typeof message.text==='string'&&message.text.length<=12000&&typeof message.at==='string');
}

export function validPath(path){
  return typeof path==='string'&&PATH.test(path)&&!path.split('/').some(segment=>!segment||segment==='.'||segment==='..'||segment.startsWith('.'));
}

function validAutosaveMetadata(metadata,files){
  if(metadata===undefined)return;
  if(!metadata||metadata.version!==1||!Number.isSafeInteger(metadata.revision)||metadata.revision<0||!Number.isSafeInteger(metadata.messagesGeneration)||metadata.messagesGeneration<0||!metadata.fileGenerations||typeof metadata.fileGenerations!=='object'||Array.isArray(metadata.fileGenerations))throw Error('Invalid vault autosave metadata.');
  for(const [path,generation]of Object.entries(metadata.fileGenerations))if(!(path in files)||!Number.isSafeInteger(generation)||generation<0)throw Error('Invalid vault autosave generation.');
  for(const path of Object.keys(files))if(!Number.isSafeInteger(metadata.fileGenerations[path])||metadata.fileGenerations[path]<0)throw Error('Missing vault autosave generation.');
}

export function validVault(vault){
  if(!vault||vault.version!==1||typeof vault.files!=='object'||!vault.files||Array.isArray(vault.files)||!Array.isArray(vault.messages)||Object.keys(vault.files).length>1000||vault.messages.length>1000)throw Error('Invalid vault.');
  for(const [path,content]of Object.entries(vault.files))if(!validPath(path)||typeof content!=='string'||encoder.encode(content).length>MAX_FILE_BYTES)throw Error('Invalid file in backup.');
  for(const message of vault.messages)if(!validMessage(message))throw Error('Invalid session in backup.');
  validAutosaveMetadata(vault.autosave,vault.files);
  return vault;
}

export function normalizeVault(vault){
  validVault(vault);
  const existing=vault.autosave;
  const fileGenerations={};
  for(const path of Object.keys(vault.files))fileGenerations[path]=existing?.fileGenerations[path]??0;
  return {
    ...vault,
    files:{...vault.files},
    messages:vault.messages.map(message=>({...message})),
    autosave:{
      version:1,
      revision:existing?.revision??0,
      fileGenerations,
      messagesGeneration:existing?.messagesGeneration??0,
    },
  };
}

function validEnvelope(envelope){
  if(!envelope||envelope.format!==FORMAT||envelope.version!==1||typeof envelope.salt!=='string'||typeof envelope.iv!=='string'||typeof envelope.data!=='string'||envelope.data.length>15000000)throw Error('Invalid encrypted backup.');
  const salt=decode(envelope.salt),iv=decode(envelope.iv);
  if(salt.length!==16||iv.length!==12)throw Error('Invalid encrypted backup.');
  return{salt,iv};
}

async function deriveSession(password,salt){
  if(typeof password!=='string')throw Error('A vault password is required.');
  const material=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);
  const bits=new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',salt,iterations:600000,hash:'SHA-256'},material,256));
  try{
    const vaultKey=await crypto.subtle.importKey('raw',bits,{name:'AES-GCM'},false,['encrypt','decrypt']);
    return Object.freeze({format:'local-sandbox.session',version:1,salt:encode(salt),vaultKey});
  }finally{
    bits.fill(0);
  }
}

function validSession(session){
  if(!session||session.format!=='local-sandbox.session'||session.version!==1||typeof session.salt!=='string'||!session.vaultKey)throw Error('The vault session is invalid. Lock and unlock again.');
  return session;
}

export async function createVaultSession(password){
  return deriveSession(password,crypto.getRandomValues(new Uint8Array(16)));
}

export async function openVault(envelope,password){
  const {salt,iv}=validEnvelope(envelope);
  try{
    const session=await deriveSession(password,salt);
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv},session.vaultKey,decode(envelope.data));
    return{vault:validVault(JSON.parse(decoder.decode(plain))),session};
  }catch(error){
    if(error instanceof Error&&error.message.startsWith('Invalid encrypted backup'))throw error;
    throw Error('Wrong password, damaged backup, or invalid vault.');
  }
}

export async function openVaultWithSession(envelope,session){
  validSession(session);
  const {iv}=validEnvelope(envelope);
  if(envelope.salt!==session.salt)throw Error('The vault key changed in another tab. Lock and unlock again.');
  try{
    const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv},session.vaultKey,decode(envelope.data));
    return validVault(JSON.parse(decoder.decode(plain)));
  }catch{
    throw Error('The encrypted vault changed or is damaged. Lock and unlock again.');
  }
}

export async function sealWithSession(vault,session){
  validSession(session);validVault(vault);
  const plain=encoder.encode(JSON.stringify(vault));
  if(plain.length>MAX_VAULT_BYTES)throw Error('Vault limit reached. Export a backup and reduce stored content.');
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const body=await crypto.subtle.encrypt({name:'AES-GCM',iv},session.vaultKey,plain);
  return{format:FORMAT,version:1,salt:session.salt,iv:encode(iv),data:encode(body)};
}

export async function seal(vault,password){
  return sealWithSession(vault,await createVaultSession(password));
}

export async function unseal(envelope,password){
  return(await openVault(envelope,password)).vault;
}

export async function sealJournalPayload(payload,session,recordID){
  validSession(session);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const additionalData=encoder.encode(`local-sandbox.draft.v1\0${recordID}`);
  const plain=encoder.encode(JSON.stringify(payload));if(plain.length>MAX_VAULT_BYTES)throw Error('Recovery draft limit reached. Export a backup and reduce stored content.');
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData},session.vaultKey,plain);
  const digest=await crypto.subtle.digest('SHA-256',joined(iv,new Uint8Array(data)));
  return{version:1,id:recordID,iv:encode(iv),data:encode(data),etag:encode(digest)};
}

export async function openJournalPayload(record,session){
  validSession(session);
  if(!record||record.version!==1||typeof record.id!=='string'||!/^[A-Za-z0-9_-]{32}$/.test(record.id)||typeof record.iv!=='string'||record.iv.length>24||typeof record.data!=='string'||record.data.length>15000000||typeof record.etag!=='string'||record.etag.length>64)throw Error('Invalid encrypted draft journal.');
  try{
    const iv=decode(record.iv),data=decode(record.data);
    if(iv.length!==12)throw Error();
    const digest=encode(await crypto.subtle.digest('SHA-256',joined(iv,data)));
    if(digest!==record.etag)throw Error();
    const additionalData=encoder.encode(`local-sandbox.draft.v1\0${record.id}`);
    return JSON.parse(decoder.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData},session.vaultKey,data)));
  }catch{
    throw Error('An encrypted recovery draft is damaged or belongs to another vault.');
  }
}

export function newJournalRecordID(){return randomToken(24);}
