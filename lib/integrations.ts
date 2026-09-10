import { z } from 'zod';
export const providerID = z.enum(['local','chatgpt','grok','grokbot','claude','apple']);
export type ProviderID = z.infer<typeof providerID>;
export const deviceReportSchema=z.object({version:z.literal(1),name:z.string().max(100),os:z.string().max(50),appleAvailable:z.boolean(),appleReason:z.string().max(500),reportedAt:z.string().datetime()}).strict();
export function deviceReport(files:{path:string;content:string}[]){const file=files.find(f=>f.path==='config/device.json');if(file){try{return deviceReportSchema.parse(JSON.parse(file.content));}catch{return null;}}return null;}
export const providers = [
 {id:'local',name:'Locally',symbol:'◈',detail:'Your installed local model · LM Link',shortcut:'Agent Step - Local',local:true},
 {id:'chatgpt',name:'ChatGPT',symbol:'✳',detail:'Your ChatGPT app account',shortcut:'Agent Step - ChatGPT',local:false},
 {id:'grok',name:'Grok',symbol:'↗',detail:'Your Grok app account',shortcut:'Agent Step - Grok',local:false},
 {id:'grokbot',name:'Grokbot',symbol:'⌘',detail:'Your named app or Shortcut adapter',shortcut:'Agent Step - Grokbot',local:false},
 {id:'claude',name:'Claude',symbol:'✺',detail:'Your Claude app account',shortcut:'Agent Step - Claude',local:false},
 {id:'apple',name:'Apple Intelligence',symbol:'✧',detail:'Detected by the native companion',shortcut:'Agent Step - Apple',local:true},
] satisfies {id:ProviderID,name:string,symbol:string,detail:string,shortcut:string,local:boolean}[];
const installURL=z.string().max(300).refine(v=>!v||/^https:\/\/www\.icloud\.com\/shortcuts\/[a-fA-F0-9]{32}$/.test(v),'Use a shared iCloud Shortcut link.');
export const adapterSchema=z.object({name:z.string().min(1).max(80),mode:z.enum(['action','manual']),installURL,tested:z.boolean()}).strict();
export const repositorySchema=z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/).max(160);
export const branchSchema=z.string().min(1).max(160).regex(/^[A-Za-z0-9][A-Za-z0-9._/-]*$/).refine(s=>!s.includes('..')&&!s.includes('//')&&!s.endsWith('/')&&!s.endsWith('.')&&!s.endsWith('.lock'));
export const repoPathSchema=z.string().min(1).max(180).regex(/^[A-Za-z0-9][A-Za-z0-9._/-]*$/).refine(s=>s.split('/').every(p=>p&&p!=='.'&&p!=='..'&&p!=='.git')&&!s.startsWith('.github/'),'Use a regular repository file path.');
export const integrationSchema=z.object({version:z.literal(2),adapters:z.record(providerID,adapterSchema),repository:z.string().max(160),branch:z.string().max(160),remotePath:z.string().max(180)}).strict();
export type Integrations=z.infer<typeof integrationSchema>;
export const defaultIntegrations:Integrations={version:2,adapters:Object.fromEntries(providers.map(p=>[p.id,{name:p.shortcut,mode:'action',installURL:'',tested:false}])),repository:'',branch:'local-sandbox/phone',remotePath:'notes.md'};
export function parseIntegrations(content?:string):Integrations {if(!content)return structuredClone(defaultIntegrations);return integrationSchema.parse(JSON.parse(content));}
export function adapterFor(config:Integrations,id:ProviderID){return config.adapters[id]??{name:providers.find(p=>p.id===id)!.shortcut,mode:'action' as const,installURL:'',tested:false};}
export async function sha256(text:string){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text)))).map(n=>n.toString(16).padStart(2,'0')).join('');}
export async function worktreePatch(input:{repository:string;branch:string;baseCommit:string;path:string;before:string|null;after:string}){
 return {format:'local-sandbox.patch',version:1,id:crypto.randomUUID(),repository:repositorySchema.parse(input.repository),branch:branchSchema.parse(input.branch),baseCommit:z.string().regex(/^[a-f0-9]{40}$/).parse(input.baseCommit),createdAt:new Date().toISOString(),changes:[{path:repoPathSchema.parse(input.path),beforeSHA256:input.before===null?null:await sha256(input.before),afterSHA256:await sha256(input.after),content:input.after}]};
}
