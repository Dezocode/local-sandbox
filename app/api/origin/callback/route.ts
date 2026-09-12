import { env } from 'cloudflare:workers';
import { OriginAuthError, parseOriginConfiguration } from '@/lib/origin-auth';
import { createD1OriginRepository, hashOriginState } from '@/lib/origin-auth-d1';
import {
  ORIGIN_FLOW_COOKIE,
  clearOriginFlowCookie,
  originAuthErrorResponse,
  originConfigurationForRequest,
  originResultRedirect,
  persistOriginInstallationOrRequireManualCleanup,
  readCookie,
  verifyOriginInstallationCallback,
} from '@/lib/origin-auth-http';
import { requireOriginReadOnlyInstallation } from '@/lib/origin-service';
import { HttpError, identity } from '@/lib/server';

async function requestIdentity(request:Request){
  try{return await identity(request);}
  catch(error){if(error instanceof HttpError)throw new OriginAuthError(error.status,error.code,error.message);throw error;}
}

export async function GET(request:Request):Promise<Response>{
  try{
    if(!env.DB)throw new OriginAuthError(503,'ORIGIN_STORAGE_UNAVAILABLE','Cursor Origin connection storage is unavailable.');
    const configuration=originConfigurationForRequest(request,parseOriginConfiguration(env));
    const repository=createD1OriginRepository(env.DB);
    const receipt=await verifyOriginInstallationCallback({request,dependencies:{configuration,replayStore:repository.replayStore,fetcher:fetch,crypto:globalThis.crypto,now:()=>Math.floor(Date.now()/1_000)}});
    const state=readCookie(request,ORIGIN_FLOW_COOKIE);
    if(!state)throw new OriginAuthError(400,'ORIGIN_INSTALL_STATE_INVALID','The Cursor Origin install state is missing or invalid.');
    const stateHash=await hashOriginState(state);
    const flow=await persistOriginInstallationOrRequireManualCleanup({
      persist:async()=>{
        const user=await requestIdentity(request);
        const appleSubjectHash=user.kind==='apple'?user.appleSubjectHash:null;
        const authorization={
          userId:user.userId,
          authorizationStartedAt:user.authorizationStartedAt,
          appleSubjectHash,
        };
        await repository.claimInstallationFlowLease({
          authorization,
          stateHash,
          installationId:receipt.installationId,
          receiptIssuedAt:receipt.issuedAt,
          now:Math.floor(Date.now()/1_000),
        });
        const storedFlow=await repository.consumeFlow(
          stateHash,
          user.userId,
          Math.floor(Date.now()/1_000),
          user.authorizationStartedAt,
          appleSubjectHash,
        );
        if(!storedFlow)throw new OriginAuthError(409,'ORIGIN_FLOW_INVALID','This Cursor Origin installation request expired, was already used, or belongs to another account.');
        await requireOriginReadOnlyInstallation({configuration,installationId:receipt.installationId,fetcher:fetch,crypto:globalThis.crypto,now:()=>Math.floor(Date.now()/1_000)});
        await repository.saveInstallationAndCompleteFlow({
          ownerId:user.userId,
          stateHash,
          receipt,
          now:Math.floor(Date.now()/1_000),
          authorizationStartedAt:user.authorizationStartedAt,
          appleSubjectHash,
        });
        return storedFlow;
      },
      releaseAuthority:()=>repository.releaseInstallationFlowLease(stateHash),
    });
    const target=originResultRedirect(flow.returnTo,'connected');
    const current=new URL(request.url);target.protocol=current.protocol;target.host=current.host;
    return new Response(null,{status:303,headers:{'Cache-Control':'no-store','Location':target.toString(),'Set-Cookie':clearOriginFlowCookie(),'X-Content-Type-Options':'nosniff'}});
  }catch(error){return originAuthErrorResponse(error,{'Set-Cookie':clearOriginFlowCookie()});}
}
