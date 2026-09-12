import { env } from 'cloudflare:workers';
import { z } from 'zod';
import { OriginAuthError, parseOriginConfiguration } from '@/lib/origin-auth';
import { createD1OriginRepository, withD1OriginExternalOperationLease } from '@/lib/origin-auth-d1';
import { originAuthErrorResponse, readOriginCommandRequest, requireOriginSameOrigin } from '@/lib/origin-auth-http';
import { deleteOriginInstallation, listOriginRepositories, syncOriginMirror } from '@/lib/origin-service';
import { HttpError, identity } from '@/lib/server';

const installationId=z.string().regex(/^(?:i|inst)_[a-z0-9]{8,100}$/);
const repositoryId=z.string().regex(/^repo_[a-z0-9]{8,100}$/);
const command=z.discriminatedUnion('kind',[
  z.object({kind:z.literal('repositories'),installationId}).strict(),
  z.object({kind:z.literal('syncMirror'),installationId,repositoryId}).strict(),
  z.object({kind:z.literal('disconnect'),installationId}).strict(),
  z.object({kind:z.literal('acknowledgeManualCleanup'),acknowledgementId:z.string().regex(/^[A-Za-z0-9_-]{43}$/)}).strict(),
]);

async function requestIdentity(request:Request){
  try{return await identity(request);}
  catch(error){if(error instanceof HttpError)throw new OriginAuthError(error.status,error.code,error.message);throw error;}
}

async function parseInput(request:Request):Promise<z.infer<typeof command>>{
  requireOriginSameOrigin(request);
  const decoded=await readOriginCommandRequest(request);
  try{return command.parse(decoded);}
  catch{throw new OriginAuthError(400,'ORIGIN_REQUEST_INVALID','Cursor Origin request is invalid.');}
}

async function context(request:Request){
  const user=await requestIdentity(request);
  if(!env.DB)throw new OriginAuthError(503,'ORIGIN_STORAGE_UNAVAILABLE','Cursor Origin connection storage is unavailable.');
  return {user,configuration:parseOriginConfiguration(env),repository:createD1OriginRepository(env.DB),now:()=>Math.floor(Date.now()/1_000)};
}

export async function GET(request:Request):Promise<Response>{
  try{
    const {user,repository,now}=await context(request);
    const {installations,possibleInstallation}=await repository.readDashboardState(user,now);
    return Response.json({
      installations,
      manualCleanupRequired:possibleInstallation!==null,
      manualCleanupAcknowledgementId:possibleInstallation?.acknowledgementId??null,
    },{headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
  }catch(error){return originAuthErrorResponse(error);}
}

export async function POST(request:Request):Promise<Response>{
  try{
    const value=await parseInput(request);
    const {user,configuration,repository,now}=await context(request);
    if(value.kind==='acknowledgeManualCleanup'){
      await repository.acknowledgePossibleInstallation(user,value.acknowledgementId,now());
      return Response.json({acknowledged:true},{headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
    }
    if(value.kind==='disconnect'){
      const completed=await withD1OriginExternalOperationLease({
        repository,
        authorization:user,
        installationId:value.installationId,
        crypto:globalThis.crypto,
        now,
        operation:async incarnation=>{
          await deleteOriginInstallation({configuration,installationId:value.installationId,fetcher:fetch,crypto:globalThis.crypto,now});
          const absence=await repository.deleteInstallationForIncarnation(user,incarnation,now());
          return {
            response:Response.json({disconnected:true},{headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}}),
            absence,
          };
        },
        completionState:result=>({kind:'absent',absence:result.absence}),
      });
      return completed.response;
    }
    return await withD1OriginExternalOperationLease({
      repository,
      authorization:user,
      installationId:value.installationId,
      crypto:globalThis.crypto,
      now,
      operation:async()=>{
        const available=await listOriginRepositories({configuration,installationId:value.installationId,fetcher:fetch,crypto:globalThis.crypto,now});
        if(value.kind==='repositories')return Response.json(available,{headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
        const selected=available.repositories.find(candidate=>candidate.id===value.repositoryId);
        if(!selected)throw new OriginAuthError(404,'ORIGIN_REPOSITORY_NOT_FOUND','The selected repository is not available to this installation.');
        const status=await syncOriginMirror({configuration,installationId:value.installationId,repository:selected,fetcher:fetch,crypto:globalThis.crypto,now});
        return Response.json({status,repository:selected},{headers:{'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}});
      },
    });
  }catch(error){return originAuthErrorResponse(error);}
}
