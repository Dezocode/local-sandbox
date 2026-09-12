import { revokeAppleSession } from '@/lib/apple-auth';
import {
  APPLE_SESSION_COOKIE,
  appleAuthContext,
  appleAuthErrorResponse,
  clearSessionCookie,
  readCookie,
  requireSameOrigin,
} from '@/lib/apple-auth-http';

export async function POST(request: Request): Promise<Response> {
  try {
    requireSameOrigin(request);
    const {dependencies} = await appleAuthContext(request);
    const revoked = await revokeAppleSession(
      dependencies,
      readCookie(request, APPLE_SESSION_COOKIE),
    );
    return Response.json(
      {revoked},
      {
        headers: {
          'Cache-Control': 'no-store',
          'Set-Cookie': clearSessionCookie(),
          'X-Content-Type-Options': 'nosniff',
        },
      },
    );
  } catch (error) {
    return appleAuthErrorResponse(error, {'Set-Cookie': clearSessionCookie()});
  }
}
