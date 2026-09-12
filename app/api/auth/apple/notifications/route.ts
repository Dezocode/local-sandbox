import { env } from 'cloudflare:workers';
import {
  parseAppleServerNotificationRequest,
} from '@/lib/apple-auth';
import {
  processAppleServerNotification,
  type OriginConnectionRevocationDependencies,
} from '@/lib/apple-auth-lifecycle';
import { createD1AppleAccountDeletionRepository } from '@/lib/apple-auth-lifecycle-d1';
import { appleAuthErrorResponse, appleAuthRuntime } from '@/lib/apple-auth-http';
import { OriginAuthError, parseOriginConfiguration } from '@/lib/origin-auth';
import { deleteOriginInstallation } from '@/lib/origin-service';

export async function POST(request: Request): Promise<Response> {
  try {
    const runtime = appleAuthRuntime(request);
    const result = await processAppleServerNotification({
      repository: createD1AppleAccountDeletionRepository(runtime.database),
      authDependencies: runtime.dependencies,
      token: await parseAppleServerNotificationRequest(request),
      originDependencies: optionalOriginDependencies(
        runtime.dependencies.crypto,
        runtime.dependencies.now,
      ),
    });
    return Response.json(result, {
      headers: {
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (error) {
    return appleAuthErrorResponse(error);
  }
}

function optionalOriginDependencies(
  cryptoProvider: Crypto,
  now: () => number,
): OriginConnectionRevocationDependencies | null {
  try {
    const configuration = parseOriginConfiguration(env);
    return {
      revokeInstallation: (installationId, signal) => deleteOriginInstallation({
        configuration,
        installationId,
        fetcher: fetch,
        crypto: cryptoProvider,
        now,
        signal,
      }),
    };
  } catch (error) {
    if (error instanceof OriginAuthError && error.code === 'ORIGIN_NOT_CONFIGURED') return null;
    throw error;
  }
}
