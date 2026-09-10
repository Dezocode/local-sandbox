import { env } from 'cloudflare:workers';
import { getChatGPTUser } from '@/app/chatgpt-auth';
import { z } from 'zod';
import { defaultPolicy, normalizeSavedPolicy, policySchema, receiptSchema } from './contracts';
import { oraclePolicy, shortcuts } from './catalog';

export class HttpError extends Error {constructor(public status:number,message:string){super(message);}}
export function database(){if(!env.DB)throw new HttpError(503,'Workspace storage is unavailable. Please retry.');return env.DB;}
export async function identity(){const user=await getChatGPTUser();if(!user)throw new HttpError(401,'Sign in to this private site to open your workspace.');return user;}
export async function input<T>(request:Request,schema:z.ZodType<T>):Promise<T>{
  const origin=request.headers.get('origin');
  if(origin!==new URL(request.url).origin)throw new HttpError(403,'Open the dashboard and submit this action there.');
  if(Number(request.headers.get('content-length')??0)>200000)throw new HttpError(413,'Request is too large.');
  const text=await request.text();if(new TextEncoder().encode(text).length>200000)throw new HttpError(413,'Request is too large.');
  let value:unknown;try{value=JSON.parse(text);}catch{throw new HttpError(400,'Expected valid JSON.');}
  return schema.parse(value);
}
export async function boundary(fn:()=>Promise<unknown>):Promise<Response>{try{return Response.json(await fn(),{headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});}catch(e){if(e instanceof HttpError)return Response.json({error:e.message},{status:e.status});if(e instanceof z.ZodError)return Response.json({error:e.issues.map(i=>`${i.path.join('.')}: ${i.message}`).join('; ')},{status:400});console.error(JSON.stringify({event:'request_failed',error:e instanceof Error?e.message:'Unknown failure'}));return Response.json({error:'The operation could not be completed. Your changes have not been discarded; retry after refreshing.'},{status:503});}}
export async function initialize(userId:string){const db=database();await db.batch([
  db.prepare('INSERT OR IGNORE INTO workspaces(user_id,policy,completed,revision) VALUES (?,?,?,0)').bind(userId,JSON.stringify(defaultPolicy),'[]'),
  db.prepare('INSERT OR IGNORE INTO files(user_id,path,content,version) VALUES (?,?,?,0)').bind(userId,'config/oracle.md',oraclePolicy),
  db.prepare('INSERT OR IGNORE INTO files(user_id,path,content,version) VALUES (?,?,?,0)').bind(userId,'workspace/welcome.md','# Local Sandbox\n\nThis is your online source workspace. It is separate from iCloud Drive.\n\nExport files to your approved LocalSandbox folder on iPhone.\n\nStart with one task, one tool action, and a receipt.\n'),
]);}
const settingsSchema=z.object({policy:z.string(),completed:z.string(),revision:z.number()});
export async function settings(userId:string){const result=settingsSchema.parse(await database().prepare('SELECT policy,completed,revision FROM workspaces WHERE user_id=?').bind(userId).first());return {policy:normalizeSavedPolicy(JSON.parse(result.policy)),completed:z.array(z.string()).parse(JSON.parse(result.completed)).filter(id=>shortcuts.some(s=>s.id===id)),revision:result.revision};}
export async function putReceipt(userId:string,receipt:z.infer<typeof receiptSchema>){await database().prepare('INSERT OR IGNORE INTO receipts(user_id,id,payload,created_at) VALUES(?,?,?,?)').bind(userId,receipt.id,JSON.stringify(receipt),receipt.createdAt).run();}
