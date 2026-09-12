import {
  parseAppleNativeBearer,
  requireEmptyAppleNativeBody,
  revokeAppleNativeSession,
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
        'Native session revocation does not accept browser cookies.',
      );
    }
    await requireEmptyAppleNativeBody(request);
    const token = parseAppleNativeBearer(request);
    if (!token) {
      throw new AppleAuthError(
        401,
        'APPLE_NATIVE_SESSION_REQUIRED',
        'A native bearer session is required.',
      );
    }
    const revoked = await revokeAppleNativeSession(appleNativeAuthContext(request), token);
    if (!revoked) {
      throw new AppleAuthError(
        401,
        'APPLE_NATIVE_SESSION_INVALID',
        'The native bearer session is invalid or expired.',
      );
    }
    return Response.json(
      {revoked: true},
      {headers: {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}},
    );
  } catch (error) {
    return appleAuthErrorResponse(error);
  }
}
