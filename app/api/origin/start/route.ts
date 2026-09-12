import { env } from 'cloudflare:workers';
import { OriginAuthError, createOriginInstallationStart, parseOriginConfiguration } from '@/lib/origin-auth';
import { createD1OriginRepository, hashOriginState } from '@/lib/origin-auth-d1';
import {
  originAuthErrorResponse,
  originConfigurationForRequest,
  originFlowCookie,
  safeOriginReturnTo,
} from '@/lib/origin-auth-http';
import { HttpError, identity } from '@/lib/server';

async function requestIdentity(request:Request){
  try{return await identity(request);}
  catch(error){if(error instanceof HttpError)throw new OriginAuthError(error.status,error.code,error.message);throw error;}
}

export async function GET(request: Request): Promise<Response> {
  try {
    const user=await requestIdentity(request);
    if(!env.DB)throw new OriginAuthError(503,'ORIGIN_STORAGE_UNAVAILABLE','Cursor Origin connection storage is unavailable.');
    const url=new URL(request.url);
    if([...url.searchParams.keys()].some(key=>key!=='return_to'))throw new OriginAuthError(400,'ORIGIN_START_INVALID','Only a return path can be supplied.');
    const configuration=originConfigurationForRequest(request,parseOriginConfiguration(env));
    const start=createOriginInstallationStart(configuration,globalThis.crypto);
    const now=Math.floor(Date.now()/1_000);
    await createD1OriginRepository(env.DB).createFlow({stateHash:await hashOriginState(start.state),ownerId:user.userId,returnTo:safeOriginReturnTo(url.searchParams.get('return_to')),createdAt:now,expiresAt:now+10*60,authorizationStartedAt:user.authorizationStartedAt,appleSubjectHash:user.kind==='apple'?user.appleSubjectHash:null});
    return new Response(null,{status:303,headers:{'Cache-Control':'no-store','Location':start.authorizationUrl,'Set-Cookie':originFlowCookie(start.state),'X-Content-Type-Options':'nosniff'}});
  } catch (error) {
    return originAuthErrorResponse(error);
  }
}
