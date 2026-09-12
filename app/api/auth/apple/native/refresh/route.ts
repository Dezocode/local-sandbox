import {
  parseAppleNativeBearer,
  refreshAppleNativeSession,
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
        'Native session refresh does not accept browser cookies.',
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
    const refreshed = await refreshAppleNativeSession(appleNativeAuthContext(request), token);
    if (refreshed === null) {
      throw new AppleAuthError(
        401,
        'APPLE_NATIVE_SESSION_INVALID',
        'The native bearer session is invalid, expired, or cannot be revalidated.',
      );
    }
    return Response.json(refreshed, {
      headers: {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'},
    });
  } catch (error) {
    return appleAuthErrorResponse(error);
  }
}
