import {
  AppleAuthError,
  type AppleAuthorizationIntent,
  parseAppleAuthorizationStartRequest,
  startAppleAuthorization,
} from '@/lib/apple-auth';
import {
  appleAuthContext,
  appleAuthErrorResponse,
  flowCookie,
  requireSameOrigin,
} from '@/lib/apple-auth-http';

export async function POST(request: Request): Promise<Response> {
  try {
    requireSameOrigin(request);
    const parsed = await parseAppleAuthorizationStartRequest(request);
    const {dependencies, hostUser} = await appleAuthContext(request);
    let intent: AppleAuthorizationIntent;
    if (parsed.intent.purpose === 'link') {
      if (hostUser === null) {
        throw new AppleAuthError(401, 'HOST_SESSION_REQUIRED', 'Sign in with ChatGPT before linking an Apple account.');
      }
      intent = {purpose: 'link' as const, ownerId: hostUser.userId};
    } else {
      if (hostUser !== null) {
        throw new AppleAuthError(409, 'AUTH_SESSION_AMBIGUOUS', 'Sign out of ChatGPT before starting a standalone Apple account.');
      }
      intent = parsed.intent;
    }
    const start = await startAppleAuthorization(dependencies, intent, parsed.returnTo);
    return Response.json({
      authorizationUrl: start.authorizationUrl,
      expiresAt: start.expiresAt,
    }, {
      headers: {
        'Cache-Control': 'no-store',
        'Set-Cookie': flowCookie(start.browserBinding),
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (error) {
    return appleAuthErrorResponse(error);
  }
}
