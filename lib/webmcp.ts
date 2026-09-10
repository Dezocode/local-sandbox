import { z } from 'zod';
import { policySchema, type Policy, type Workspace } from './contracts';
interface PageTool {name:string;description:string;inputSchema:object;annotations:{readOnlyHint:boolean;untrustedContentHint:boolean};execute:(input:unknown)=>unknown|Promise<unknown>}
declare global { interface Document { modelContext?: {registerTool:(tool:PageTool,options?:{signal?:AbortSignal})=>void|Promise<void>} } }
export function registerWorkspaceTools(actions:{read:()=>Workspace,stage:(policy:Policy)=>void,prepare:(goal:string)=>Promise<unknown>}) {
  const context=document.modelContext;if(!context?.registerTool)return()=>{};
  const lifecycle=new AbortController();
  const tools:PageTool[]=[
    {name:'read_local_sandbox',description:'Read saved policy, file paths, and recent receipts from the current workspace. File content is excluded.',inputSchema:{type:'object',properties:{},additionalProperties:false},annotations:{readOnlyHint:true,untrustedContentHint:true},execute(input){z.object({}).strict().parse(input);const w=actions.read();return {policy:w.policy,files:w.files.map(f=>({path:f.path,version:f.version})),receipts:w.receipts.slice(0,10),completed:w.completed};}},
    {name:'stage_resource_policy',description:'Stage resource settings in the visible controls for review. Does not save or authorize them.',inputSchema:{type:'object',properties:{batteryBudget:{type:'integer',minimum:1,maximum:80},batteryReserve:{type:'integer',minimum:5,maximum:80},memoryTarget:{type:'integer',minimum:10,maximum:80},maxSteps:{type:'integer',minimum:1,maximum:24},maxFailures:{type:'integer',minimum:1,maximum:3},contextChars:{type:'integer',minimum:2000,maximum:12000},cloudAllowed:{type:'boolean'},notifications:{type:'boolean'},provider:{type:'string',enum:['local','apple','openai']},localShortcut:{type:'string'}},required:['batteryBudget','batteryReserve','memoryTarget','maxSteps','maxFailures','contextChars','cloudAllowed','notifications','provider','localShortcut'],additionalProperties:false},annotations:{readOnlyHint:false,untrustedContentHint:false},execute(input){actions.stage(policySchema.parse(input));return {staged:true,authorized:false};}},
    {name:'prepare_oracle_task',description:'Prepare and display an Oracle task packet. Does not run device tools or submit a cloud model request.',inputSchema:{type:'object',properties:{goal:{type:'string',minLength:1,maxLength:2000}},required:['goal'],additionalProperties:false},annotations:{readOnlyHint:false,untrustedContentHint:true},async execute(input){const {goal}=z.object({goal:z.string().trim().min(1).max(2000)}).strict().parse(input);return actions.prepare(goal);}},
  ];
  for(const tool of tools){try{void Promise.resolve(context.registerTool(tool,{signal:lifecycle.signal})).catch(()=>{});}catch{/* Unsupported WebMCP must not interrupt the user interface. */}}
  return()=>lifecycle.abort();
}
