import { z } from 'zod';
import { pathSchema } from './contracts.ts';

const encoder=new TextEncoder();
const decoder=new TextDecoder('utf-8',{fatal:true});
const recordFormat='local-sandbox.workspace-record';
const recoveryFormat='local-sandbox.workspace-recovery';
const keyBytes=32;
const recoveryIterations=600_000;
export const maximumWorkspaceContentBytes=64_000;
export const maximumEncodedContentCharacters=85_334;
export const maximumRecordCiphertextCharacters=120_000;
const legacyMaximumRecordCiphertextCharacters=100_000;
const nonceSchema=z.string().length(16).regex(/^[A-Za-z0-9_-]+$/);
const saltSchema=z.string().length(22).regex(/^[A-Za-z0-9_-]+$/);
const legacyRecordCiphertextSchema=z.string().min(22).max(legacyMaximumRecordCiphertextCharacters).regex(/^[A-Za-z0-9_-]+$/);
const recordCiphertextSchema=z.string().min(22).max(maximumRecordCiphertextCharacters).regex(/^[A-Za-z0-9_-]+$/);
const encodedContentSchema=z.string().max(maximumEncodedContentCharacters).regex(/^[A-Za-z0-9_-]*$/);
const recoveryCiphertextSchema=z.string().min(22).max(4_096).regex(/^[A-Za-z0-9_-]+$/);
const workspaceIDSchema=z.string().length(32).regex(/^[A-Za-z0-9_-]+$/);
const epochSchema=z.string().min(16).max(64).regex(/^[A-Za-z0-9_-]+$/);
const identifierSchema=z.string().min(16).max(64).regex(/^[A-Za-z0-9_-]+$/);

const encryptedWorkspaceRecordBase={
  format:z.literal(recordFormat),
  workspaceId:workspaceIDSchema,
  epoch:epochSchema,
  recordId:z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
  baseRevision:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).nullable(),
  mutationId:identifierSchema,
  iv:nonceSchema,
};
export const encryptedWorkspaceRecordSchema=z.discriminatedUnion('version',[
  z.object({...encryptedWorkspaceRecordBase,version:z.literal(1),data:legacyRecordCiphertextSchema}).strict(),
  z.object({...encryptedWorkspaceRecordBase,version:z.literal(2),data:recordCiphertextSchema}).strict(),
]);

export const workspaceRecoverySchema=z.object({
  format:z.literal(recoveryFormat),
  version:z.literal(1),
  workspaceId:workspaceIDSchema,
  epoch:epochSchema,
  kdf:z.object({name:z.literal('PBKDF2'),hash:z.literal('SHA-256'),iterations:z.literal(recoveryIterations),salt:saltSchema}).strict(),
  cipher:z.object({name:z.literal('AES-GCM'),iv:nonceSchema,data:recoveryCiphertextSchema}).strict(),
}).strict();

const recordPayloadV1Schema=z.object({
  version:z.literal(1),
  path:pathSchema,
  content:z.string().max(maximumWorkspaceContentBytes).nullable(),
  contentSHA256:z.string().length(64).regex(/^[a-f0-9]+$/).nullable(),
  generation:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  writerDevice:identifierSchema,
  writtenAt:z.string().datetime(),
}).strict().superRefine((value,context)=>{
  if((value.content===null)!==(value.contentSHA256===null))context.addIssue({code:z.ZodIssueCode.custom,path:['contentSHA256'],message:'A tombstone must not carry a content digest.'});
  if(value.content!==null&&encoder.encode(value.content).byteLength>maximumWorkspaceContentBytes)context.addIssue({code:z.ZodIssueCode.custom,path:['content'],message:'Workspace files are limited to 64 KB of UTF-8.'});
});

const recordPayloadV2Schema=z.object({
  version:z.literal(2),
  path:pathSchema,
  contentUTF8:encodedContentSchema.nullable(),
  contentSHA256:z.string().length(64).regex(/^[a-f0-9]+$/).nullable(),
  generation:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  writerDevice:identifierSchema,
  writtenAt:z.string().datetime(),
}).strict().superRefine((value,context)=>{
  if((value.contentUTF8===null)!==(value.contentSHA256===null))context.addIssue({code:z.ZodIssueCode.custom,path:['contentSHA256'],message:'A tombstone must not carry a content digest.'});
});

const workspaceRecordSchema=z.object({
  version:z.union([z.literal(1),z.literal(2)]),path:pathSchema,content:z.string().max(maximumWorkspaceContentBytes).nullable(),
  contentSHA256:z.string().length(64).regex(/^[a-f0-9]+$/).nullable(),generation:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),writerDevice:identifierSchema,writtenAt:z.string().datetime(),
}).strict().superRefine((value,context)=>{
  if((value.content===null)!==(value.contentSHA256===null))context.addIssue({code:z.ZodIssueCode.custom,path:['contentSHA256'],message:'A tombstone must not carry a content digest.'});
  if(value.content!==null&&encoder.encode(value.content).byteLength>maximumWorkspaceContentBytes)context.addIssue({code:z.ZodIssueCode.custom,path:['content'],message:'Workspace files are limited to 64 KB of UTF-8.'});
});

const recoveryPayloadSchema=z.object({
  version:z.literal(1),
  workspaceId:workspaceIDSchema,
  epoch:epochSchema,
  workspaceKey:z.string().length(43).regex(/^[A-Za-z0-9_-]+$/),
  createdAt:z.string().datetime(),
}).strict();

export type EncryptedWorkspaceRecord=z.infer<typeof encryptedWorkspaceRecordSchema>;
export type WorkspaceRecovery=z.infer<typeof workspaceRecoverySchema>;
export type WorkspaceRecord=z.infer<typeof workspaceRecordSchema>;
export type WorkspaceSession=Readonly<{format:'local-sandbox.workspace-session';version:1;workspaceId:string;epoch:string;encryptionKey:CryptoKey;pathKey:CryptoKey}>;

function owned(bytes:Uint8Array<ArrayBufferLike>):Uint8Array<ArrayBuffer>{const copy=new Uint8Array(bytes.byteLength);copy.set(bytes);return copy;}
function encode(bytes:ArrayBuffer|Uint8Array<ArrayBufferLike>):string{
  const view=bytes instanceof ArrayBuffer?new Uint8Array(bytes):bytes;
  let value='';
  for(let offset=0;offset<view.byteLength;offset+=0x8000)value+=String.fromCharCode(...view.subarray(offset,offset+0x8000));
  return btoa(value).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}

function decode(value:string,minimum=16,maximum=maximumRecordCiphertextCharacters):Uint8Array<ArrayBuffer>{
  if(value.length<minimum||value.length>maximum||!/^[A-Za-z0-9_-]*$/.test(value))throw Error('Invalid base64url value.');
  const padded=value.replaceAll('-','+').replaceAll('_','/')+'='.repeat((4-value.length%4)%4);
  const decoded=owned(Uint8Array.from(atob(padded),character=>character.charCodeAt(0)));
  if(encode(decoded)!==value)throw Error('Invalid base64url value.');
  return decoded;
}

function randomID(bytes:number):string{return encode(crypto.getRandomValues(new Uint8Array(bytes)));}
function aad(...parts:(string|number|null)[]):Uint8Array<ArrayBuffer>{return encoder.encode(parts.map(part=>part===null?'-':String(part)).join('\0'));}
async function sha256(value:string):Promise<string>{return [...new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value)))].map(byte=>byte.toString(16).padStart(2,'0')).join('');}

function validateSession(session:WorkspaceSession):WorkspaceSession{
  if(session?.format!=='local-sandbox.workspace-session'||session.version!==1||!session.encryptionKey||!session.pathKey)throw Error('The encrypted workspace session is invalid. Re-enroll this device.');
  workspaceIDSchema.parse(session.workspaceId);epochSchema.parse(session.epoch);return session;
}

async function sessionFromRaw(workspaceId:string,epoch:string,source:Uint8Array<ArrayBufferLike>):Promise<WorkspaceSession>{
  workspaceIDSchema.parse(workspaceId);epochSchema.parse(epoch);
  if(source.byteLength!==keyBytes)throw Error('The workspace key must contain 32 bytes.');
  const raw=owned(source);
  try{
    const [encryptionKey,pathKey]=await Promise.all([
      crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']),
      crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign']),
    ]);
    return Object.freeze({format:'local-sandbox.workspace-session' as const,version:1 as const,workspaceId,epoch,encryptionKey,pathKey});
  }finally{raw.fill(0);}
}

async function recoveryKey(passphrase:string,salt:Uint8Array<ArrayBufferLike>):Promise<CryptoKey>{
  if(typeof passphrase!=='string')throw Error('Use a recovery passphrase containing 12 to 1,024 UTF-8 bytes.');
  const password=encoder.encode(passphrase);
  if(password.byteLength<12||password.byteLength>1_024){password.fill(0);throw Error('Use a recovery passphrase containing 12 to 1,024 UTF-8 bytes.');}
  try{
    const material=await crypto.subtle.importKey('raw',password,'PBKDF2',false,['deriveKey']);
    return await crypto.subtle.deriveKey({name:'PBKDF2',hash:'SHA-256',salt:owned(salt),iterations:recoveryIterations},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
  }finally{password.fill(0);}
}

async function sealRecovery(workspaceId:string,epoch:string,raw:Uint8Array<ArrayBufferLike>,passphrase:string,createdAt:string):Promise<WorkspaceRecovery>{
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const key=await recoveryKey(passphrase,salt);
  const payload=recoveryPayloadSchema.parse({version:1,workspaceId,epoch,workspaceKey:encode(raw),createdAt});
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(recoveryFormat,1,workspaceId,epoch)},key,encoder.encode(JSON.stringify(payload)));
  return workspaceRecoverySchema.parse({format:recoveryFormat,version:1,workspaceId,epoch,kdf:{name:'PBKDF2',hash:'SHA-256',iterations:recoveryIterations,salt:encode(salt)},cipher:{name:'AES-GCM',iv:encode(iv),data:encode(data)}});
}

export async function createWorkspaceWithRecovery(passphrase:string,createdAt=new Date().toISOString()):Promise<{session:WorkspaceSession;recovery:WorkspaceRecovery}>{
  const raw=crypto.getRandomValues(new Uint8Array(keyBytes));
  const workspaceId=randomID(24);
  const epoch=randomID(18);
  try{return {session:await sessionFromRaw(workspaceId,epoch,raw),recovery:await sealRecovery(workspaceId,epoch,raw,passphrase,createdAt)};}
  finally{raw.fill(0);}
}

async function openWorkspaceRecoveryKey(value:unknown,passphrase:string):Promise<{recovery:WorkspaceRecovery;raw:Uint8Array<ArrayBuffer>}>{
  const recovery=workspaceRecoverySchema.parse(value);
  try{
    const salt=decode(recovery.kdf.salt),iv=decode(recovery.cipher.iv),data=decode(recovery.cipher.data);
    if(salt.byteLength!==16||iv.byteLength!==12)throw Error('The recovery envelope parameters are invalid.');
    const key=await recoveryKey(passphrase,salt);
    const clear=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:aad(recoveryFormat,1,recovery.workspaceId,recovery.epoch)},key,data);
    const clearBytes=new Uint8Array(clear);
    try{
      const payload=recoveryPayloadSchema.parse(JSON.parse(decoder.decode(clearBytes)));
      if(payload.workspaceId!==recovery.workspaceId||payload.epoch!==recovery.epoch)throw Error('Recovery identity mismatch.');
      const raw=decode(payload.workspaceKey);
      if(raw.byteLength!==keyBytes){raw.fill(0);throw Error();}
      return {recovery,raw};
    }finally{clearBytes.fill(0);}
  }catch(error){
    if(error instanceof Error&&(error.message.startsWith('Use a recovery')||error.message==='Recovery identity mismatch.'))throw error;
    throw Error('The recovery passphrase is wrong or the recovery envelope is damaged.');
  }
}

export async function restoreWorkspaceRecovery(value:unknown,passphrase:string):Promise<WorkspaceSession>{
  const opened=await openWorkspaceRecoveryKey(value,passphrase);
  try{return await sessionFromRaw(opened.recovery.workspaceId,opened.recovery.epoch,opened.raw);}
  finally{opened.raw.fill(0);}
}

export async function rewrapWorkspaceRecovery(
  value:unknown,
  currentPassphrase:string,
  replacementPassphrase:string,
  createdAt=new Date().toISOString(),
):Promise<{session:WorkspaceSession;recovery:WorkspaceRecovery}>{
  if(currentPassphrase===replacementPassphrase)throw Error('Choose a replacement recovery passphrase that differs from the current one.');
  const opened=await openWorkspaceRecoveryKey(value,currentPassphrase);
  try{
    const [session,recovery]=await Promise.all([
      sessionFromRaw(opened.recovery.workspaceId,opened.recovery.epoch,opened.raw),
      sealRecovery(opened.recovery.workspaceId,opened.recovery.epoch,opened.raw,replacementPassphrase,createdAt),
    ]);
    return {session,recovery};
  }finally{opened.raw.fill(0);}
}

export async function workspaceRecordID(session:WorkspaceSession,path:string):Promise<string>{
  validateSession(session);const validPath=pathSchema.parse(path);
  return encode(await crypto.subtle.sign('HMAC',session.pathKey,aad(recordFormat,1,session.workspaceId,session.epoch,validPath)));
}

export async function sealWorkspaceRecord(session:WorkspaceSession,input:{path:string;content:string|null;baseRevision:number|null;generation:number;writerDevice:string},options:{mutationId?:string;iv?:Uint8Array<ArrayBufferLike>;writtenAt?:string}={}):Promise<EncryptedWorkspaceRecord>{
  validateSession(session);
  const path=pathSchema.parse(input.path),baseRevision=z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).nullable().parse(input.baseRevision),generation=z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER).parse(input.generation),writerDevice=identifierSchema.parse(input.writerDevice);
  const contentBytes=input.content===null?null:encoder.encode(input.content);
  if(contentBytes!==null&&contentBytes.byteLength>maximumWorkspaceContentBytes)throw Error('Workspace files are limited to 64 KB of UTF-8.');
  const mutationId=identifierSchema.parse(options.mutationId??randomID(18));
  const iv=options.iv?owned(options.iv):crypto.getRandomValues(new Uint8Array(12));
  if(iv.byteLength!==12)throw Error('Workspace record nonces must contain 12 bytes.');
  const recordId=await workspaceRecordID(session,path);
  const payload=recordPayloadV2Schema.parse({version:2,path,contentUTF8:contentBytes===null?null:encode(contentBytes),contentSHA256:input.content===null?null:await sha256(input.content),generation,writerDevice,writtenAt:options.writtenAt??new Date().toISOString()});
  const additionalData=aad(recordFormat,2,session.workspaceId,session.epoch,recordId,baseRevision,mutationId);
  const data=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData},session.encryptionKey,encoder.encode(JSON.stringify(payload)));
  return encryptedWorkspaceRecordSchema.parse({format:recordFormat,version:2,workspaceId:session.workspaceId,epoch:session.epoch,recordId,baseRevision,mutationId,iv:encode(iv),data:encode(data)});
}

export async function openWorkspaceRecord(session:WorkspaceSession,value:unknown):Promise<WorkspaceRecord>{
  validateSession(session);const record=encryptedWorkspaceRecordSchema.parse(value);
  if(record.workspaceId!==session.workspaceId||record.epoch!==session.epoch)throw Error('This record belongs to a different workspace or key epoch.');
  try{
    const iv=decode(record.iv);if(iv.byteLength!==12)throw Error();
    const additionalData=aad(recordFormat,record.version,record.workspaceId,record.epoch,record.recordId,record.baseRevision,record.mutationId);
    const clear=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData},session.encryptionKey,decode(record.data));
    const raw:unknown=JSON.parse(decoder.decode(clear));
    const payload=record.version===1
      ?workspaceRecordSchema.parse(recordPayloadV1Schema.parse(raw))
      :await (async()=>{
        const encoded=recordPayloadV2Schema.parse(raw);
        let content:string|null=null;
        if(encoded.contentUTF8!==null){
          const bytes=decode(encoded.contentUTF8,0,maximumEncodedContentCharacters);
          if(bytes.byteLength>maximumWorkspaceContentBytes||encode(bytes)!==encoded.contentUTF8)throw Error();
          content=decoder.decode(bytes);
        }
        return workspaceRecordSchema.parse({
          version:encoded.version,
          path:encoded.path,
          content,
          contentSHA256:encoded.contentSHA256,
          generation:encoded.generation,
          writerDevice:encoded.writerDevice,
          writtenAt:encoded.writtenAt,
        });
      })();
    if(await workspaceRecordID(session,payload.path)!==record.recordId)throw Error();
    if(payload.content!==null&&await sha256(payload.content)!==payload.contentSHA256)throw Error();
    return payload;
  }catch{throw Error('The encrypted workspace record failed authentication.');}
}
