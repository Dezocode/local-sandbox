import { getChatGPTUser } from '@/app/chatgpt-auth';
import { AppleAuthError, appleAccountModeForOwner, hashAppleOpaqueToken, readAppleSession, readAppleSessionLocalPrincipal } from '@/lib/apple-auth';
import {
  APPLE_SESSION_COOKIE,
  appleAuthContext,
  appleAuthErrorResponse,
  clearSessionCookie,
  readCookie,
} from '@/lib/apple-auth-http';

function unauthenticatedResponse(hostAuthenticated: boolean, clearCookie: boolean): Response {
  return Response.json(
    {authenticated: false, hostAuthenticated},
    {headers: {
      'Cache-Control': 'no-store',
      ...(clearCookie ? {'Set-Cookie': clearSessionCookie()} : {}),
      'X-Content-Type-Options': 'nosniff',
    }},
  );
}

export async function GET(request: Request): Promise<Response> {
  const hostUser = await getChatGPTUser();
  const token = readCookie(request, APPLE_SESSION_COOKIE);
  if (token === null) return unauthenticatedResponse(hostUser !== null, false);
  if (!/^v1\.[A-Za-z0-9_-]{43}$/.test(token)) {
    return unauthenticatedResponse(hostUser !== null, true);
  }
  try {
    const {dependencies} = await appleAuthContext(request);
    const local = await readAppleSessionLocalPrincipal(dependencies, token);
    if (local !== null && hostUser !== null && local.ownerId !== hostUser.userId) {
      throw new AppleAuthError(409, 'AUTH_SESSION_AMBIGUOUS', 'The Apple and ChatGPT sessions belong to different Local Sandbox accounts.');
    }
    if (local === null) return unauthenticatedResponse(hostUser !== null, true);
    const principal = hostUser === null ? await readAppleSession(dependencies, token) : local;
    if (principal === null) return unauthenticatedResponse(hostUser !== null, true);
    const deletionScope = await hashAppleOpaqueToken(
      `deletion-scope\0${principal.ownerId}\0${principal.appleSubjectHash}`,
      dependencies.crypto,
    );
    return Response.json(
      {
        authenticated: true,
        hostAuthenticated: hostUser !== null,
        mode: appleAccountModeForOwner(principal.ownerId),
        session: {...principal.identity, deletionScope},
      },
      {headers: {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}},
    );
  } catch (error) {
    if (
      hostUser !== null &&
      error instanceof AppleAuthError &&
      error.code !== 'AUTH_SESSION_AMBIGUOUS'
    ) {
      return unauthenticatedResponse(true, error.status === 401);
    }
    return appleAuthErrorResponse(error);
  }
}
