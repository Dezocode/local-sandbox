import { z } from 'zod';
import { exactPatch,pathSchema,receiptSchema } from '@/lib/contracts';
import { assertAppleOwnerOperationAllowed,boundary,database,identity,initialize,input,putReceipt,HttpError,opaqueWorkspaceID } from '@/lib/server';
import { APPLE_OWNER_OPERATION_ALLOWED_SQL,appleOwnerOperationGateBindings } from '@/lib/apple-auth-owner-d1';
import { applyFileMutationWithFreshVersion,FileVersionD1IntegrityError,maximumFileVersion,type FileMutationInput } from '@/lib/workspace-file-d1';

async function sha256(value:string):Promise<string>{
  const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(byte=>byte.toString(16).padStart(2,'0')).join('');
}

async function mutateCheckFile(value:FileMutationInput){
  try{return await applyFileMutationWithFreshVersion(value);}
  catch(error){if(error instanceof FileVersionD1IntegrityError)throw new HttpError(503,'Hosted file storage failed a version integrity check.','FILE_STORAGE_INTEGRITY');throw error;}
}

export async function POST(request:Request){return boundary(async()=>{
  const user=await identity(request);
  const {id}=await input(request,z.object({id:z.string().uuid()}).strict());
  await initialize(user);
  const db=database(),operationTime=Math.floor(Date.now()/1_000),gate=appleOwnerOperationGateBindings(user,operationTime);
  const cached=await db.prepare(`SELECT payload FROM receipts WHERE user_id=? AND id=? AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(user.userId,id,...gate).first();
  if(cached){const receipt=receiptSchema.parse(JSON.parse(z.object({payload:z.string()}).parse(cached).payload));await assertAppleOwnerOperationAllowed(user,db);return receipt;}

  const start=Date.now();
  const path=pathSchema.parse(`workspace/check-${id}.txt`);
  const before='Status: pending';
  const expected='Status: complete';
  const created=await mutateCheckFile({kind:'create',database:db,authorization:user,operationTime,path,content:before});
  if(created.kind==='not-applied')await assertAppleOwnerOperationAllowed(user,db,operationTime);
  const rawRow=await db.prepare(`SELECT content,version FROM files WHERE user_id=? AND path=? AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(user.userId,path,...gate).first();
  if(!rawRow){
    await assertAppleOwnerOperationAllowed(user,db,operationTime);
    const clock=z.object({file_clock:z.number().int().min(-1).max(maximumFileVersion)}).safeParse(await db.prepare('SELECT file_clock FROM workspaces WHERE user_id=?').bind(user.userId).first());
    if(!clock.success)throw new HttpError(503,'Hosted file storage failed a version integrity check.','FILE_STORAGE_INTEGRITY');
    if(clock.data.file_clock===maximumFileVersion)throw new HttpError(409,'This workspace exhausted its safe file-version range. Export the workspace before running another check.','FILE_VERSION_EXHAUSTED');
    throw new HttpError(409,'The check file could not be created. Run a new check.');
  }
  const row=z.object({content:z.string(),version:z.number().int().nonnegative().max(maximumFileVersion)}).parse(rawRow);
  const beforeSHA=await sha256(row.content);
  if(row.content===before){
    const next=exactPatch(row.content,'Status: pending','Status: complete');
    const changed=await mutateCheckFile({kind:'save',database:db,authorization:user,operationTime,path,content:next,expectedVersion:row.version});
    if(changed.kind==='not-applied'){await assertAppleOwnerOperationAllowed(user,db,operationTime);throw new HttpError(409,'The check file changed during verification. Run a new check.');}
  }
  const rawAfter=await db.prepare(`SELECT content,version FROM files WHERE user_id=? AND path=? AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(user.userId,path,...gate).first();
  if(!rawAfter){await assertAppleOwnerOperationAllowed(user,db,operationTime);throw new HttpError(409,'The check file was removed during verification. Run a new check.');}
  const after=z.object({content:z.string(),version:z.number().int().nonnegative().max(maximumFileVersion)}).parse(rawAfter);
  if(after.content!==expected)throw new HttpError(409,'Readback did not match the expected content.');
  const afterSHA=await sha256(after.content);
  const checkedAt=new Date().toISOString();
  const receipt=receiptSchema.parse({
    recordType:'run-receipt',schemaVersion:2,id,goal:'Verify the online sandbox file tools',status:'verified',origin:'cloud-sandbox',
    summary:'Created, read, patched, and independently reread one sandbox file.',steps:4,failures:0,durationMs:Date.now()-start,createdAt:checkedAt,
    trace:[
      {tool:'file.create',status:'ok',detail:`Created ${path}`,evidence:{path,sha256:beforeSHA,byteCount:new TextEncoder().encode(before).length,readbackKind:'write-readback',contentComplete:true}},
      {tool:'file.read',status:'ok',detail:'Read the complete file before applying the exact-text patch.',evidence:{path,sha256:beforeSHA,byteCount:new TextEncoder().encode(row.content).length,readbackKind:'source-read',contentComplete:true}},
      {tool:'file.patch',status:'ok',detail:'Changed Status: pending to Status: complete with a version guard.',evidence:{path,sha256:afterSHA,byteCount:new TextEncoder().encode(after.content).length,readbackKind:'write-readback',contentComplete:true}},
      {tool:'file.read',status:'ok',detail:'Independent database read matched Status: complete.',evidence:{path,sha256:afterSHA,byteCount:new TextEncoder().encode(after.content).length,readbackKind:'independent-readback',contentComplete:true}},
    ],
    contract:{recordType:'goal-contract',schemaVersion:1,assertions:[{kind:'exactText',path,expected}]},
    assertions:[{kind:'exactText',path,folder:null,passed:true,expected,observed:'exact match',observedSHA256:afterSHA,byteCount:new TextEncoder().encode(after.content).length,checkedAt,errorCode:null}],
    provider:'system',policyDigest:null,workspaceID:await opaqueWorkspaceID(user.userId),
    environment:{appVersion:'0.3.0',build:'web',os:'Cloudflare Workers',device:'server'},legacyTraceOnly:false,
  });
  await putReceipt(user,receipt);
  await db.prepare(`DELETE FROM files WHERE user_id=? AND path=? AND version=? AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(user.userId,path,after.version,...gate).run();
  await assertAppleOwnerOperationAllowed(user,db);
  return receipt;
});}
