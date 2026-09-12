import { env } from 'cloudflare:workers';
import { getChatGPTUser, type ChatGPTUser } from '@/app/chatgpt-auth';
import { z } from 'zod';
import { defaultPolicy, normalizeSavedPolicy, parseReceiptWire, receiptPageCursorSchema, receiptSchema, receiptWireContract } from './contracts';
import { oraclePolicy, shortcuts } from './catalog';
import {
  AppleAuthError,
  type AppleSessionPrincipal,
  readAppleSession,
  readAppleSessionLocalPrincipal,
} from './apple-auth.ts';
import {
  APPLE_SESSION_COOKIE,
  appleAuthContext,
  readCookie,
} from './apple-auth-http.ts';
import {
  parseAppleNativeBearer,
  readAppleNativeSession,
} from './apple-native-auth.ts';
import { createD1AppleNativeAuthRepository } from './apple-native-auth-d1.ts';
import {
  APPLE_OWNER_OPERATION_ALLOWED_SQL,
  appleOwnerOperationGateBindings,
  isAppleOwnerOperationAllowed,
  type AppleOwnerOperationAuthorization,
} from './apple-auth-owner-d1.ts';

export class HttpError extends Error {constructor(public status:number,message:string,public code=`HTTP_${status}`,public details:Record<string,unknown>={}){super(message);}}
export function database(){if(!env.DB)throw new HttpError(503,'Workspace storage is unavailable. Please retry.');return env.DB;}
export type AppIdentity={
  kind:'host'|'apple'|'host+apple';
  userId:string;
  displayName:string;
  email:string|null;
  authorizationStartedAt:number;
  appleSubjectHash:string|null;
};

function hostIdentity(user:ChatGPTUser,authorizationStartedAt:number):AppIdentity{
  return {kind:'host',userId:user.userId,displayName:user.displayName,email:user.email,authorizationStartedAt,appleSubjectHash:null};
}

export function resolveAppIdentity(
  hostUser:ChatGPTUser|null,
  applePrincipal:AppleSessionPrincipal|null,
  authorizationStartedAt=Math.floor(Date.now()/1_000),
):AppIdentity|null{
  if(hostUser&&applePrincipal&&hostUser.userId!==applePrincipal.ownerId){
    throw new HttpError(409,'The Apple and ChatGPT sessions belong to different Local Sandbox accounts.','AUTH_SESSION_AMBIGUOUS');
  }
  if(hostUser&&applePrincipal)return{...hostIdentity(hostUser,authorizationStartedAt),kind:'host+apple'};
  if(hostUser)return hostIdentity(hostUser,authorizationStartedAt);
  if(!applePrincipal)return null;
  return{
    kind:'apple',
    userId:applePrincipal.ownerId,
    displayName:applePrincipal.identity.displayName??applePrincipal.identity.email??'Apple account',
    email:applePrincipal.identity.email,
    authorizationStartedAt,
    appleSubjectHash:applePrincipal.appleSubjectHash,
  };
}

function appleHttpError(error:AppleAuthError):HttpError{
  return new HttpError(error.status,error.message,error.code);
}

async function requestIdentity(
  request:Request,
  appleValidation:'remote'|'local',
  ignoreUnavailableApple=false,
  authorizationStartedAt=Math.floor(Date.now()/1_000),
):Promise<AppIdentity|null>{
  const hostUser=await getChatGPTUser();
  const token=readCookie(request,APPLE_SESSION_COOKIE);
  if(token===null||!/^v1\.[A-Za-z0-9_-]{43}$/.test(token))return resolveAppIdentity(hostUser,null,authorizationStartedAt);
  try{
    const {dependencies}=await appleAuthContext(request);
    const localPrincipal=await readAppleSessionLocalPrincipal(dependencies,token);
    const locallyResolved=resolveAppIdentity(hostUser,localPrincipal,authorizationStartedAt);
    if(localPrincipal===null||hostUser!==null||appleValidation==='local')return locallyResolved;
    return resolveAppIdentity(null,await readAppleSession(dependencies,token),authorizationStartedAt);
  }catch(error){
    if(error instanceof HttpError&&error.code==='AUTH_SESSION_AMBIGUOUS')throw error;
    if(hostUser)return hostIdentity(hostUser,authorizationStartedAt);
    if(ignoreUnavailableApple)return null;
    if(error instanceof AppleAuthError)throw appleHttpError(error);
    throw error;
  }
}

export async function identity(request:Request):Promise<AppIdentity>{
  const authorizationStartedAt=Math.floor(Date.now()/1_000);
  const user=await requestIdentity(request,'remote',false,authorizationStartedAt);
  if(!user)throw new HttpError(401,'Sign in with Apple or ChatGPT to open your workspace.','AUTH_REQUIRED');
  return user;
}
export type SyncIdentity=({kind:'web'}|{kind:'apple-native'})&AppleOwnerOperationAuthorization;
export async function syncIdentity(request:Request):Promise<SyncIdentity>{
  const authorizationStartedAt=Math.floor(Date.now()/1_000);
  const authorization=request.headers.get('authorization');
  const ambient=await requestIdentity(request,authorization===null?'remote':'local',authorization!==null,authorizationStartedAt);
  if(ambient&&authorization!==null)throw new HttpError(400,'Choose either a web account session or a native bearer session, not both.','SYNC_AUTH_AMBIGUOUS');
  if(ambient)return {kind:'web',userId:ambient.userId,authorizationStartedAt,appleSubjectHash:ambient.kind==='apple'?ambient.appleSubjectHash:null};
  let token:string|null;
  try{token=parseAppleNativeBearer(request);}catch(error){
    if(error instanceof AppleAuthError)throw new HttpError(error.status,error.message,error.code);
    throw error;
  }
  if(!token)throw new HttpError(401,'Sign in to the hosted app or supply a native bearer session.','SYNC_AUTH_REQUIRED');
  const now=Math.floor(Date.now()/1_000);
  const session=await readAppleNativeSession(createD1AppleNativeAuthRepository(database()),token,now,globalThis.crypto);
  if(!session)throw new HttpError(401,'The native bearer session is invalid, expired, or revoked.','APPLE_NATIVE_SESSION_INVALID');
  return {kind:'apple-native',userId:session.ownerId,authorizationStartedAt,appleSubjectHash:session.appleSubjectHash};
}
const applicationRequestMaximumBytes=400_000;
export const syncRequestMaximumBytes=200_000;
// Exact compact overhead for the closed {"receipt":<value>} request envelope.
export const receiptRequestMaximumBytes=receiptWireContract.maximumSerializedUTF8Bytes+12;
export const hostedReceiptPageMaximumRows=100;
export const hostedReceiptPageMaximumUTF8Bytes=6_400_000;
async function parseInputBody<T>(request:Request,schema:z.ZodType<T>,maximumBytes:number,parseJSON:(text:string)=>unknown=JSON.parse):Promise<T>{
  const text=await readBoundedText(request,maximumBytes);
  let value:unknown;try{value=parseJSON(text);}catch{throw new HttpError(400,'Expected valid JSON.');}
  return schema.parse(value);
}
async function readBoundedText(request:Request,maximumBytes:number):Promise<string>{
  const declared=request.headers.get('content-length');
  if(declared!==null){
    if(!/^\d+$/.test(declared))throw new HttpError(400,'Content-Length is invalid.','INVALID_CONTENT_LENGTH');
    if(Number(declared)>maximumBytes)throw new HttpError(413,'Request is too large.','REQUEST_TOO_LARGE');
  }
  if(request.body===null)return'';
  const reader=request.body.getReader(),chunks:Uint8Array[]=[];let total=0;
  for(;;){
    const chunk=await reader.read();if(chunk.done)break;
    total+=chunk.value.byteLength;
    if(total>maximumBytes){await reader.cancel();throw new HttpError(413,'Request is too large.','REQUEST_TOO_LARGE');}
    chunks.push(chunk.value);
  }
  const bytes=new Uint8Array(total);let offset=0;
  for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
  try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}
  catch{throw new HttpError(400,'Expected valid UTF-8 JSON.','INVALID_JSON_ENCODING');}
}
export async function input<T>(request:Request,schema:z.ZodType<T>,maximumBytes=applicationRequestMaximumBytes,parseJSON?:(text:string)=>unknown):Promise<T>{
  const origin=request.headers.get('origin');
  if(origin!==new URL(request.url).origin)throw new HttpError(403,'Open the dashboard and submit this action there.');
  return parseInputBody(request,schema,maximumBytes,parseJSON);
}
export async function syncInput<T>(request:Request,schema:z.ZodType<T>,authentication:SyncIdentity):Promise<T>{
  if(authentication.kind==='web'){
    const origin=request.headers.get('origin');
    if(origin!==new URL(request.url).origin)throw new HttpError(403,'Open the dashboard and submit this action there.');
    return parseInputBody(request,schema,syncRequestMaximumBytes);
  }
  const origin=request.headers.get('origin');
  if(origin!==null&&origin!==new URL(request.url).origin)throw new HttpError(403,'Native sync rejected a foreign web origin.','SYNC_ORIGIN_REJECTED');
  const contentType=request.headers.get('content-type')?.split(';',1)[0]?.trim().toLowerCase();
  if(contentType!=='application/json')throw new HttpError(415,'Native sync requires JSON.','SYNC_CONTENT_TYPE');
  return parseInputBody(request,schema,syncRequestMaximumBytes);
}
export async function boundary(fn:()=>Promise<unknown>):Promise<Response>{try{return Response.json(await fn(),{headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});}catch(e){if(e instanceof HttpError)return Response.json({...e.details,error:e.message,code:e.code},{status:e.status});if(e instanceof z.ZodError)return Response.json({error:e.issues.map(i=>`${i.path.join('.')}: ${i.message}`).join('; '),code:'INVALID_REQUEST'},{status:400});console.error(JSON.stringify({event:'request_failed',error:e instanceof Error?e.message:'Unknown failure'}));return Response.json({error:'The operation could not be completed. Your changes have not been discarded; retry after refreshing.',code:'SERVICE_UNAVAILABLE'},{status:503});}}
export async function opaqueWorkspaceID(userId:string):Promise<string>{const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(`local-sandbox-workspace\0${userId}`));return [...new Uint8Array(bytes)].map(byte=>byte.toString(16).padStart(2,'0')).join('').slice(0,32);}
type ReceiptPageCursor=z.infer<typeof receiptPageCursorSchema>;
const storedReceiptMetadataSchema=z.object({id:z.string(),created_at:z.string(),payload_bytes:z.number().int().nonnegative()}).strict();
const storedReceiptRowSchema=z.object({id:z.string(),created_at:z.string(),payload:z.string()}).strict();
function receiptStorageIntegrity():never{throw new HttpError(503,'Stored receipt data failed an integrity check.','RECEIPT_STORAGE_INTEGRITY');}
export function receiptPageCursor(request:Request):ReceiptPageCursor|null{
  const parameters=new URL(request.url).searchParams,allowed=new Set(['receiptCursorCreatedAt','receiptCursorID']);
  if([...parameters.keys()].some(key=>!allowed.has(key)))throw new HttpError(400,'Workspace receipt cursor parameters are invalid.','INVALID_RECEIPT_CURSOR');
  const createdAt=parameters.getAll('receiptCursorCreatedAt'),id=parameters.getAll('receiptCursorID');
  if(createdAt.length===0&&id.length===0)return null;
  if(createdAt.length!==1||id.length!==1)throw new HttpError(400,'Supply one complete workspace receipt cursor.','INVALID_RECEIPT_CURSOR');
  const parsed=receiptPageCursorSchema.safeParse({createdAt:createdAt[0],id:id[0]});
  if(!parsed.success)throw new HttpError(400,'Workspace receipt cursor is invalid.','INVALID_RECEIPT_CURSOR');
  return parsed.data;
}
export async function receiptPage(userId:string,cursor:ReceiptPageCursor|null):Promise<{receipts:z.infer<typeof receiptSchema>[];receiptNextCursor:ReceiptPageCursor|null}>{
  const db=database(),query=cursor
    ?db.prepare('SELECT id,created_at,length(CAST(payload AS BLOB)) AS payload_bytes FROM receipts WHERE user_id=? AND (created_at<? OR (created_at=? AND id<?)) ORDER BY created_at DESC,id DESC LIMIT ?').bind(userId,cursor.createdAt,cursor.createdAt,cursor.id,hostedReceiptPageMaximumRows+1)
    :db.prepare('SELECT id,created_at,length(CAST(payload AS BLOB)) AS payload_bytes FROM receipts WHERE user_id=? ORDER BY created_at DESC,id DESC LIMIT ?').bind(userId,hostedReceiptPageMaximumRows+1);
  const metadataResult=await query.all();
  let metadata:({cursor:ReceiptPageCursor;payloadBytes:number})[];
  try{metadata=metadataResult.results.map(value=>{const row=storedReceiptMetadataSchema.parse(value);return{cursor:receiptPageCursorSchema.parse({createdAt:row.created_at,id:row.id}),payloadBytes:row.payload_bytes};});}
  catch{return receiptStorageIntegrity();}
  const selected:typeof metadata=[];let storedBytes=0;
  for(const candidate of metadata.slice(0,hostedReceiptPageMaximumRows)){
    if(candidate.payloadBytes>receiptWireContract.maximumSerializedUTF8Bytes)return receiptStorageIntegrity();
    if(storedBytes+candidate.payloadBytes>hostedReceiptPageMaximumUTF8Bytes)break;
    storedBytes+=candidate.payloadBytes;selected.push(candidate);
  }
  if(selected.length===0)return{receipts:[],receiptNextCursor:null};
  const results=await db.batch(selected.map(candidate=>db.prepare('SELECT id,created_at,payload FROM receipts WHERE user_id=? AND id=? AND created_at=?').bind(userId,candidate.cursor.id,candidate.cursor.createdAt)));
  const receipts:z.infer<typeof receiptSchema>[]=[];let responseBytes=0;
  for(const [index,result] of results.entries()){
    const expected=selected[index];if(!expected)return receiptStorageIntegrity();
    let row:z.infer<typeof storedReceiptRowSchema>,receipt:z.infer<typeof receiptSchema>;
    try{row=storedReceiptRowSchema.parse(result.results[0]);if(row.id!==expected.cursor.id||row.created_at!==expected.cursor.createdAt||new TextEncoder().encode(row.payload).byteLength!==expected.payloadBytes)return receiptStorageIntegrity();receipt=parseReceiptWire(row.payload);}
    catch(error){if(error instanceof HttpError)throw error;return receiptStorageIntegrity();}
    if(receipt.id!==row.id||receipt.createdAt!==row.created_at)return receiptStorageIntegrity();
    const bytes=new TextEncoder().encode(JSON.stringify(receipt)).byteLength;
    if(responseBytes+bytes>hostedReceiptPageMaximumUTF8Bytes)break;
    responseBytes+=bytes;receipts.push(receipt);
  }
  if(receipts.length===0)return receiptStorageIntegrity();
  const hasMore=receipts.length<metadata.length;
  return{receipts,receiptNextCursor:hasMore?selected[receipts.length-1]?.cursor??receiptStorageIntegrity():null};
}
function operationNow():number{return Math.floor(Date.now()/1_000);}
export async function assertAppleOwnerOperationAllowed(authorization:AppleOwnerOperationAuthorization,db=database(),now=operationNow()):Promise<void>{
  if(!await isAppleOwnerOperationAllowed(db,authorization,now))throw new HttpError(409,'This standalone Apple account is being deleted. Sign in again after deletion finishes to create a new workspace.','APPLE_ACCOUNT_DELETION_IN_PROGRESS');
}
export async function initialize(authorization:AppleOwnerOperationAuthorization){
  const db=database(),now=operationNow(),gate=appleOwnerOperationGateBindings(authorization,now);
  await db.batch([
    db.prepare(`INSERT OR IGNORE INTO workspaces(user_id,policy,completed,revision) SELECT ?,?,?,0 WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(authorization.userId,JSON.stringify(defaultPolicy),'[]',...gate),
    db.prepare(`INSERT OR IGNORE INTO files(user_id,path,content,version)
      SELECT workspace.user_id,?,?,0 FROM workspaces AS workspace
      WHERE workspace.user_id=? AND workspace.file_clock=-1 AND workspace.file_clock_claim IS NULL
        AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind('config/oracle.md',oraclePolicy,authorization.userId,...gate),
    db.prepare(`INSERT OR IGNORE INTO files(user_id,path,content,version)
      SELECT workspace.user_id,?,?,0 FROM workspaces AS workspace
      WHERE workspace.user_id=? AND workspace.file_clock=-1 AND workspace.file_clock_claim IS NULL
        AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind('workspace/welcome.md','# Local Sandbox\n\nThis is your online source workspace. It is separate from iCloud Drive.\n\nExport files to your approved LocalSandbox folder on iPhone.\n\nStart with one task, one tool action, and a receipt.\n',authorization.userId,...gate),
    db.prepare(`UPDATE workspaces SET file_clock=0
      WHERE user_id=? AND file_clock=-1 AND file_clock_claim IS NULL
        AND EXISTS(SELECT 1 FROM files WHERE user_id=? AND path='config/oracle.md' AND version=0)
        AND EXISTS(SELECT 1 FROM files WHERE user_id=? AND path='workspace/welcome.md' AND version=0)
        AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(authorization.userId,authorization.userId,authorization.userId,...gate),
  ]);
  await assertAppleOwnerOperationAllowed(authorization,db,now);
}
const settingsSchema=z.object({policy:z.string(),completed:z.string(),revision:z.number()});
export async function settings(userId:string){const result=settingsSchema.parse(await database().prepare('SELECT policy,completed,revision FROM workspaces WHERE user_id=?').bind(userId).first());return {policy:normalizeSavedPolicy(JSON.parse(result.policy)),completed:z.array(z.string()).parse(JSON.parse(result.completed)).filter(id=>shortcuts.some(s=>s.id===id)),revision:result.revision};}
export async function putReceipt(authorization:AppleOwnerOperationAuthorization,value:unknown){const receipt=receiptSchema.parse(value),payload=JSON.stringify(receipt);if(new TextEncoder().encode(payload).byteLength>receiptWireContract.maximumSerializedUTF8Bytes)throw new HttpError(413,'Receipt is too large to store.','RECEIPT_TOO_LARGE');const db=database(),now=operationNow();await db.prepare(`INSERT OR IGNORE INTO receipts(user_id,id,payload,created_at) SELECT ?,?,?,? WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(authorization.userId,receipt.id,payload,receipt.createdAt,...appleOwnerOperationGateBindings(authorization,now)).run();await assertAppleOwnerOperationAllowed(authorization,db,now);}
