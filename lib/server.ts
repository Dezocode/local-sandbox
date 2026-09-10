import { env } from 'cloudflare:workers';
import { getChatGPTUser } from '@/app/chatgpt-auth';
import { z } from 'zod';
import { defaultPolicy, policySchema, receiptSchema } from './contracts';
import { oraclePolicy } from './catalog';

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
export async function settings(userId:string){const result=settingsSchema.parse(await database().prepare('SELECT policy,completed,revision FROM workspaces WHERE user_id=?').bind(userId).first());return {policy:policySchema.parse(JSON.parse(result.policy)),completed:z.array(z.string()).parse(JSON.parse(result.completed)),revision:result.revision};}
export async function putReceipt(userId:string,receipt:z.infer<typeof receiptSchema>){await database().prepare('INSERT OR IGNORE INTO receipts(user_id,id,payload,created_at) VALUES(?,?,?,?)').bind(userId,receipt.id,JSON.stringify(receipt),receipt.createdAt).run();}
export function providerConfig(){const key=process.env.OPENAI_API_KEY;const model=process.env.OPENAI_MODEL;return key&&model?{key,model}:null;}
export async function frontierAllowance(userId:string){const current=await settings(userId);if(!current.policy.cloudAllowed)throw new HttpError(403,'Cloud reasoning is off. Save cloud authorization in Resource controls first.');const config=providerConfig();if(!config)throw new HttpError(503,'OpenAI is not configured. Set server runtime OPENAI_API_KEY and OPENAI_MODEL.');const window=new Date().toISOString().slice(0,13);const updated=await database().prepare('INSERT INTO usage(user_id,window,calls) VALUES(?,?,1) ON CONFLICT(user_id,window) DO UPDATE SET calls=calls+1 WHERE calls<30 RETURNING calls').bind(userId,window).first();if(!updated)throw new HttpError(429,'The 30-call hourly cloud limit has been reached.');return {config,policy:current.policy};}
