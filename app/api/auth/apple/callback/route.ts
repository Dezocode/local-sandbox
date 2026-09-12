import {
  completeAppleAuthorization,
  parseAppleAuthorizationCallback,
} from '@/lib/apple-auth';
import {
  APPLE_FLOW_COOKIE,
  appleAuthContext,
  appleAuthErrorResponse,
  clearFlowCookie,
  flowCookie,
  readCookie,
  resultRedirect,
  sessionCookie,
} from '@/lib/apple-auth-http';

export async function POST(request: Request): Promise<Response> {
  try {
    const {dependencies, hostUser} = await appleAuthContext(request);
    const callback = await parseAppleAuthorizationCallback(request);
    const completion = await completeAppleAuthorization(
      dependencies,
      callback,
      readCookie(request, APPLE_FLOW_COOKIE),
      hostUser?.userId ?? null,
    );
    const target = resultRedirect(
      completion.returnTo,
      completion.kind === 'authenticated' ? 'connected' : 'cancelled',
    );
    target.host = new URL(request.url).host;
    target.protocol = new URL(request.url).protocol;
    const headers = new Headers({
      'Cache-Control': 'no-store',
      'Location': target.toString(),
      'X-Content-Type-Options': 'nosniff',
    });
    headers.append('Set-Cookie', clearFlowCookie());
    if (completion.kind === 'authenticated') {
      headers.append('Set-Cookie', sessionCookie(completion.sessionToken));
    }
    return new Response(null, {status: 303, headers});
  } catch (error) {
    return appleAuthErrorResponse(error, {'Set-Cookie': flowCookie('', 0)});
  }
}
