import {
  exchangeAppleNativeIdentityToken,
  parseAppleNativeExchangeRequest,
} from '@/lib/apple-native-auth';
import { appleNativeAuthContext } from '@/lib/apple-native-auth-http';
import { appleAuthErrorResponse } from '@/lib/apple-auth-http';

export async function POST(request: Request): Promise<Response> {
  try {
    const body = await parseAppleNativeExchangeRequest(request);
    const session = await exchangeAppleNativeIdentityToken(
      appleNativeAuthContext(request),
      body,
    );
    return Response.json(session, {
      headers: {
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (error) {
    return appleAuthErrorResponse(error);
  }
}
