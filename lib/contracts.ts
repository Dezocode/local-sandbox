import { z } from 'zod';
export const pathSchema = z.string().min(1).max(180).regex(/^(workspace|config|state|logs|output)\/[A-Za-z0-9][A-Za-z0-9._/-]*$/).refine(p => p.split('/').every(s => s !== '..' && s !== '.' && s !== ''), 'Use a relative path inside the sandbox.').brand<'SandboxPath'>();
export const policySchema = z.object({
  batteryBudget: z.number().int().min(1).max(80), batteryReserve: z.number().int().min(5).max(80),
  memoryTarget: z.number().int().min(10).max(80), maxSteps: z.number().int().min(1).max(24),
  maxFailures: z.number().int().min(1).max(3), contextChars: z.number().int().min(2000).max(12000),
  cloudAllowed: z.boolean(), notifications: z.boolean(), provider: z.enum(['local','apple','openai']),
  localShortcut: z.string().min(1).max(80),
}).strict();
export type Policy = z.infer<typeof policySchema>;
export const defaultPolicy: Policy = { batteryBudget:15, batteryReserve:20, memoryTarget:35, maxSteps:6, maxFailures:3, contextChars:6000, cloudAllowed:false, notifications:true, provider:'local', localShortcut:'Agent Step - Local' };
export const fileSchema = z.object({path:pathSchema, content:z.string().max(64000), version:z.number().int().nonnegative()});
export type SandboxFile = z.infer<typeof fileSchema>;
export const toolCallSchema = z.discriminatedUnion('tool', [
  z.object({tool:z.literal('file.read'),path:pathSchema}).strict(),
  z.object({tool:z.literal('file.list'),path:z.enum(['workspace','config','state','logs','output'])}).strict(),
  z.object({tool:z.literal('file.create'),path:pathSchema,content:z.string().max(64000)}).strict(),
  z.object({tool:z.literal('file.append'),path:pathSchema,content:z.string().max(8000),version:z.number().int().nonnegative()}).strict(),
  z.object({tool:z.literal('file.patch'),path:pathSchema,old:z.string().min(1).max(8000),replacement:z.string().max(8000),version:z.number().int().nonnegative()}).strict(),
]);
export type ToolCall = z.infer<typeof toolCallSchema>;
export const receiptSchema = z.object({id:z.string().min(1).max(80),goal:z.string().max(2000),status:z.enum(['verified','blocked','cancelled']),origin:z.enum(['cloud-sandbox','shortcut','native']),summary:z.string().max(3000),steps:z.number().int().min(0).max(100),failures:z.number().int().min(0).max(100),durationMs:z.number().min(0).max(86400000),createdAt:z.string().datetime(),trace:z.array(z.object({tool:z.string().max(100),status:z.enum(['ok','error','skipped']),detail:z.string().max(1000)})).max(100)}).strict();
export type Receipt = z.infer<typeof receiptSchema>;
export const workspaceSchema = z.object({policy:policySchema,files:z.array(fileSchema),receipts:z.array(receiptSchema),completed:z.array(z.string()),user:z.string(),revision:z.number().int().nonnegative(),cloudReady:z.boolean()});
export type Workspace = z.infer<typeof workspaceSchema>;
export function exactPatch(content:string, old:string, replacement:string):string {
  const first=content.indexOf(old);
  if(first<0) throw new Error('PATCH_CONTEXT_NOT_FOUND');
  if(content.indexOf(old,first+1)>=0) throw new Error('PATCH_CONTEXT_AMBIGUOUS');
  return content.slice(0,first)+replacement+content.slice(first+old.length);
}
export function compactContext(goal:string,capsule:string,latest:string,budget:number):string {
  const header=`Goal: ${goal.slice(0,2000)}\nState: ${capsule.slice(0,1800)}\nLatest result:\n`;
  return (header+latest.slice(0,Math.max(0,budget-header.length))).slice(0,budget);
}
export function shortcutURL(name:string,input:string):string {
  return `shortcuts://run-shortcut?name=${encodeURIComponent(name)}&input=text&text=${encodeURIComponent(input)}`;
}
