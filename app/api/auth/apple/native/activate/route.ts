import {
  activateAppleNativeSession,
  parseAppleNativeBearer,
  requireEmptyAppleNativeBody,
} from '@/lib/apple-native-auth';
import { appleNativeAuthContext } from '@/lib/apple-native-auth-http';
import { AppleAuthError } from '@/lib/apple-auth';
import { appleAuthErrorResponse } from '@/lib/apple-auth-http';

export async function POST(request: Request): Promise<Response> {
  try {
    if (request.headers.has('cookie')) {
      throw new AppleAuthError(
        400,
        'APPLE_NATIVE_AMBIENT_AUTH',
        'Native session activation does not accept browser cookies.',
      );
    }
    await requireEmptyAppleNativeBody(request);
    const token = parseAppleNativeBearer(request);
    if (!token) {
      throw new AppleAuthError(
        401,
        'APPLE_NATIVE_SESSION_REQUIRED',
        'A pending native bearer session is required.',
      );
    }
    const activated = await activateAppleNativeSession(appleNativeAuthContext(request), token);
    if (activated === null) {
      throw new AppleAuthError(
        401,
        'APPLE_NATIVE_SESSION_INVALID',
        'The pending native bearer session is invalid, expired, revoked, or blocked.',
      );
    }
    return Response.json(activated, {
      headers: {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'},
    });
  } catch (error) {
    return appleAuthErrorResponse(error);
  }
}
