'use client';

import { z } from 'zod';
import { fileContentSchema,pathSchema } from '../lib/contracts.ts';
import { purgeDraftScope,type DraftJournal,type DraftPurgeEntry,type DraftRecord,type JournaledDraft } from '../lib/autosave.ts';

const databaseName='local-sandbox-draft-journal';
const keyStore='keys';
const draftStore='drafts';
const maximumPurgeRecords=512;
const maximumStoredCiphertextBytes=140_000;
const additionalData=new TextEncoder().encode('local-sandbox.hosted-draft.v1');
const draftSchema=z.object({scope:z.string().min(8).max(80),path:pathSchema,baseVersion:z.number().int().nonnegative(),baseContent:fileContentSchema,content:fileContentSchema,generation:z.number().int().positive(),updatedAt:z.string().datetime()}).strict();
type StoredDraft={version:1;iv:ArrayBuffer;data:ArrayBuffer;token:string;generation:number};
type StoredDraftToken=Readonly<{recordID:string;etag:string}>;
const legacyRecordIDPattern=/^[a-f0-9]{64}$/;
const writerRecordIDPattern=/^[a-f0-9]{64}\.[a-f0-9]{32}$/;
const storedETagPattern=/^[a-f0-9]{64}$/;

function requestValue<T>(request:IDBRequest<T>):Promise<T>{return new Promise((resolve,reject)=>{request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error??Error('IndexedDB request failed.'));});}
function transactionDone(transaction:IDBTransaction):Promise<void>{return new Promise((resolve,reject)=>{transaction.oncomplete=()=>resolve();transaction.onabort=()=>reject(transaction.error??Error('IndexedDB transaction was aborted.'));transaction.onerror=()=>reject(transaction.error??Error('IndexedDB transaction failed.'));});}
function bytesToHex(bytes:Uint8Array):string{return [...bytes].map(value=>value.toString(16).padStart(2,'0')).join('');}
function copyBuffer(bytes:Uint8Array):ArrayBuffer{return bytes.buffer.slice(bytes.byteOffset,bytes.byteOffset+bytes.byteLength) as ArrayBuffer;}
async function digest(...values:Uint8Array[]):Promise<string>{const size=values.reduce((total,value)=>total+value.byteLength,0);const joined=new Uint8Array(size);let offset=0;for(const value of values){joined.set(value,offset);offset+=value.byteLength;}return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-256',joined)));}
function validRecordID(value:unknown):value is string{return typeof value==='string'&&(legacyRecordIDPattern.test(value)||writerRecordIDPattern.test(value));}
function encodeStoredDraftToken(value:StoredDraftToken):string{return `v2:${value.recordID}:${value.etag}`;}
function parseStoredDraftToken(value:string,legacyRecordID:string):StoredDraftToken|null{
  if(storedETagPattern.test(value))return{recordID:legacyRecordID,etag:value};
  const match=/^v2:([a-f0-9]{64}(?:\.[a-f0-9]{32})?):([a-f0-9]{64})$/.exec(value);
  if(!match)return null;
  return{recordID:match[1],etag:match[2]};
}
function recordBelongsToTarget(recordID:string,targetID:string):boolean{return recordID===targetID||recordID.startsWith(`${targetID}.`);}
function parseStoredDraft(value:unknown):StoredDraft{
  if(typeof value!=='object'||value===null)throw Error('A draft journal record is invalid.');
  const ownKeys=Reflect.ownKeys(value);if(ownKeys.some(key=>typeof key!=='string'))throw Error('A draft journal record is invalid.');
  const keys=(ownKeys as string[]).sort();
  if(JSON.stringify(keys)!==JSON.stringify(['data','generation','iv','token','version']))throw Error('A draft journal record is invalid.');
  const candidate=value as Partial<StoredDraft>;
  if(candidate.version!==1||!(candidate.iv instanceof ArrayBuffer)||candidate.iv.byteLength!==12||!(candidate.data instanceof ArrayBuffer)||candidate.data.byteLength<16||candidate.data.byteLength>maximumStoredCiphertextBytes||typeof candidate.token!=='string'||!/^[a-f0-9]{64}$/.test(candidate.token)||typeof candidate.generation!=='number'||!Number.isSafeInteger(candidate.generation)||candidate.generation<1)throw Error('A draft journal record is invalid.');
  return candidate as StoredDraft;
}

export class IndexedDBDraftJournal implements DraftJournal{
  private readonly database:Promise<IDBDatabase>;
  private deviceKey:Promise<CryptoKey>|null=null;
  constructor(){this.database=new Promise((resolve,reject)=>{const request=indexedDB.open(databaseName,1);request.onupgradeneeded=()=>{const db=request.result;if(!db.objectStoreNames.contains(keyStore))db.createObjectStore(keyStore);if(!db.objectStoreNames.contains(draftStore))db.createObjectStore(draftStore);};request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error??Error('Draft journal could not open.'));request.onblocked=()=>reject(Error('Close other Local Sandbox tabs so the draft journal can upgrade.'));});}

  async put(record:DraftRecord,currentToken?:string):Promise<string>{
    const validated=draftSchema.parse(record);
    const plaintext=new TextEncoder().encode(JSON.stringify(validated));
    const key=await this.key();
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const encrypted=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData},key,plaintext));
    const etag=await digest(iv,encrypted);
    const stored:StoredDraft={version:1,iv:copyBuffer(iv),data:copyBuffer(encrypted),token:etag,generation:validated.generation};
    const targetID=await this.targetID(validated.scope,validated.path);
    if(currentToken){
      const expected=parseStoredDraftToken(currentToken,targetID);
      if(!expected||!recordBelongsToTarget(expected.recordID,targetID))throw Error('A recovery draft changed before it could be journaled.');
      const db=await this.database;const transaction=db.transaction(draftStore,'readwrite');const done=transactionDone(transaction);const store=transaction.objectStore(draftStore);
      let shouldFork=false,validationError:unknown;
      const get=store.get(expected.recordID);get.onsuccess=()=>{try{const current=get.result;if(current===undefined||parseStoredDraft(current).token!==expected.etag){shouldFork=true;transaction.abort();return;}store.put(stored,expected.recordID);}catch(error){validationError=error;transaction.abort();}};
      try{await done;}catch(error){if(validationError)throw validationError;if(shouldFork)return this.addRecord(stored,targetID,etag);throw error;}
      return encodeStoredDraftToken({recordID:expected.recordID,etag});
    }
    return this.addRecord(stored,targetID,etag);
  }

  private async addRecord(stored:StoredDraft,targetID:string,etag:string):Promise<string>{
    for(let attempt=0;attempt<3;attempt+=1){
      const recordID=`${targetID}.${bytesToHex(crypto.getRandomValues(new Uint8Array(16)))}`;
      const db=await this.database;const transaction=db.transaction(draftStore,'readwrite');const done=transactionDone(transaction);transaction.objectStore(draftStore).add(stored,recordID);
      try{await done;return encodeStoredDraftToken({recordID,etag});}
      catch(error){if(!(error instanceof DOMException)||error.name!=='ConstraintError')throw error;}
    }
    throw Error('Could not allocate an encrypted recovery draft.');
  }

  async removeIf(scope:string,path:string,generation:number,token:string):Promise<boolean>{
    const targetID=await this.targetID(scope,path);const expected=parseStoredDraftToken(token,targetID);
    if(!expected||!recordBelongsToTarget(expected.recordID,targetID))return false;
    const db=await this.database;const transaction=db.transaction(draftStore,'readwrite');const done=transactionDone(transaction);const store=transaction.objectStore(draftStore);let removed=false;
    const get=store.get(expected.recordID);get.onsuccess=()=>{const value=get.result;if(value===undefined)return;const current=parseStoredDraft(value);if(current.generation===generation&&current.token===expected.etag){store.delete(expected.recordID);removed=true;}};
    await done;return removed;
  }

  async list(scope:string):Promise<readonly JournaledDraft[]>{
    const db=await this.database;const transaction=db.transaction(draftStore,'readonly');const done=transactionDone(transaction);const store=transaction.objectStore(draftStore);
    const [recordIDs,values]=await Promise.all([requestValue(store.getAllKeys()),requestValue<unknown[]>(store.getAll())]);await done;
    if(recordIDs.length!==values.length)throw Error('Draft journal records could not be aligned.');
    const key=await this.key();const output:JournaledDraft[]=[];
    for(let index=0;index<values.length;index+=1){
      const recordID=recordIDs[index];if(!validRecordID(recordID))throw Error('A draft journal record identifier is invalid.');
      const stored=parseStoredDraft(values[index]);const iv=new Uint8Array(stored.iv);const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData},key,stored.data);const record=draftSchema.parse(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plaintext)));const targetID=await this.targetID(record.scope,record.path);
      if(!recordBelongsToTarget(recordID,targetID))throw Error('A draft journal record failed identity verification.');
      if(record.scope===scope)output.push({record,token:encodeStoredDraftToken({recordID,etag:stored.token})});
    }
    return output;
  }

  async purge(scope:string):Promise<number>{
    return purgeDraftScope({
      scope,
      maximumRecords:maximumPurgeRecords,
      read:limit=>this.readPurgeEntries(limit),
      remove:ids=>this.deletePurgeEntries(ids),
      clearKeyReference:()=>{this.deviceKey=null;},
    });
  }

  private async targetID(scope:string,path:string):Promise<string>{return digest(new TextEncoder().encode(`${scope}\0${path}`));}

  private async readPurgeEntries(limit:number):Promise<readonly DraftPurgeEntry[]>{
    const db=await this.database;const transaction=db.transaction(draftStore,'readonly');const done=transactionDone(transaction);const store=transaction.objectStore(draftStore);
    const [rawIds,rawValues]=await Promise.all([
      requestValue(store.getAllKeys(undefined,limit)),
      requestValue(store.getAll(undefined,limit) as IDBRequest<unknown[]>),
    ]);await done;
    if(rawIds.length!==rawValues.length)throw Error('Draft purge could not align journal records.');
    const key=await this.key();
    return Promise.all(rawValues.map(async(value,index)=>{
      const id=rawIds[index];if(!validRecordID(id))throw Error('A draft journal record identifier is invalid.');
      const stored=parseStoredDraft(value);const iv=new Uint8Array(stored.iv);
      const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData},key,stored.data);
      const decoded=new TextDecoder('utf-8',{fatal:true}).decode(plaintext);
      const record=draftSchema.parse(JSON.parse(decoded));
      const targetID=await this.targetID(record.scope,record.path);
      if(JSON.stringify(record)!==decoded||stored.generation!==record.generation||stored.token!==await digest(iv,new Uint8Array(stored.data))||!recordBelongsToTarget(id,targetID))throw Error('A draft journal record failed canonical verification.');
      return {id,scope:record.scope};
    }));
  }

  private async deletePurgeEntries(ids:readonly string[]):Promise<void>{
    const db=await this.database;const transaction=db.transaction(draftStore,'readwrite');const done=transactionDone(transaction);const store=transaction.objectStore(draftStore);for(const id of ids)store.delete(id);await done;
  }

  private key():Promise<CryptoKey>{
    this.deviceKey??=(async()=>{
      const db=await this.database;let transaction=db.transaction(keyStore,'readonly');let done=transactionDone(transaction);const existing=await requestValue(transaction.objectStore(keyStore).get('device-key') as IDBRequest<CryptoKey|undefined>);await done;if(existing)return existing;
      const generated=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
      try{transaction=db.transaction(keyStore,'readwrite');done=transactionDone(transaction);transaction.objectStore(keyStore).add(generated,'device-key');await done;return generated;}
      catch{transaction=db.transaction(keyStore,'readonly');done=transactionDone(transaction);const winner=await requestValue(transaction.objectStore(keyStore).get('device-key') as IDBRequest<CryptoKey|undefined>);await done;if(!winner)throw Error('Draft encryption key could not be stored.');return winner;}
    })();
    return this.deviceKey;
  }
}

let sharedJournal:IndexedDBDraftJournal|undefined;
export function hostedDraftJournal():IndexedDBDraftJournal{
  sharedJournal??=new IndexedDBDraftJournal();
  return sharedJournal;
}
