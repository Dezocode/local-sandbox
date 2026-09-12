import { env } from 'cloudflare:workers';
import {
  deleteAppleAccount,
  parseAppleAccountDeletionKey,
  recoverAppleAccountDeletion,
  requireEmptyAppleAccountDeletionBody,
  type OriginConnectionRevocationDependencies,
} from '@/lib/apple-auth-lifecycle';
import { createD1AppleAccountDeletionRepository } from '@/lib/apple-auth-lifecycle-d1';
import {
  AppleAuthError,
  readAppleSessionLocalPrincipal,
  type AppleAuthDependencies,
} from '@/lib/apple-auth';
import {
  APPLE_SESSION_COOKIE,
  appleAuthErrorResponse,
  appleAuthRuntime,
  clearSessionCookie,
  readCookie,
  requireSameOrigin,
} from '@/lib/apple-auth-http';
import { parseAppleNativeBearer, readAppleNativeSession } from '@/lib/apple-native-auth';
import { appleNativeSessionContext } from '@/lib/apple-native-auth-http';
import { OriginAuthError, parseOriginConfiguration } from '@/lib/origin-auth';
import { deleteOriginInstallation } from '@/lib/origin-service';

export async function POST(request: Request): Promise<Response> {
  try {
    await requireEmptyAppleAccountDeletionBody(request);
    const deletionKey = parseAppleAccountDeletionKey(request);
    const nativeContext = appleNativeSessionContext();
    const repository = createD1AppleAccountDeletionRepository(nativeContext.database);
    const originDependencies = optionalOriginDependencies(
      nativeContext.crypto,
      nativeContext.clock,
    );
    const bearer = request.headers.get('authorization');
    if (bearer === null) requireSameOrigin(request);

    if (bearer !== null) {
      if (request.headers.has('cookie')) {
        throw new AppleAuthError(
          400,
          'APPLE_ACCOUNT_DELETION_AMBIENT_AUTH',
          'Native account deletion does not accept browser cookies.',
        );
      }
      const token = parseAppleNativeBearer(request);
      if (token === null) throw nativeSessionRequired();
      const principal = await readAppleNativeSession(
        nativeContext.repository,
        token,
        nativeContext.now,
        nativeContext.crypto,
      );
      if (principal === null) {
        const replay = await recoverAppleAccountDeletion({
          repository,
          authDependencies: optionalAppleAuthDependencies(request),
          deletionKey,
          crypto: nativeContext.crypto,
          now: nativeContext.now,
          completionNow: nativeContext.clock,
          originDependencies,
        });
        if (replay !== null) return deletionResponse(replay, false);
        throw nativeSessionRequired();
      }
      const ownerId = principal.ownerId;
      const appleSubjectHash = principal.appleSubjectHash;
      const authDependencies = optionalAppleAuthDependencies(request);
      return deletionResponse(await deleteAppleAccount({
        repository,
        authDependencies,
        ownerId,
        appleSubjectHash,
        deletionKey,
        crypto: nativeContext.crypto,
        now: nativeContext.now,
        completionNow: nativeContext.clock,
        originDependencies,
      }), false);
    } else {
      const token = readCookie(request, APPLE_SESSION_COOKIE);
      if (token === null) {
        const replay = await recoverAppleAccountDeletion({
          repository,
          authDependencies: optionalAppleAuthDependencies(request),
          deletionKey,
          crypto: nativeContext.crypto,
          now: nativeContext.now,
          completionNow: nativeContext.clock,
          originDependencies,
        });
        if (replay !== null) return deletionResponse(replay);
        throw new AppleAuthError(
          401,
          'APPLE_ACCOUNT_SESSION_REQUIRED',
          'An authenticated Apple session is required to delete this account.',
        );
      }
      const runtime = appleAuthRuntime(request);
      const principal = await readAppleSessionLocalPrincipal(runtime.dependencies, token);
      if (principal === null) {
        const replay = await recoverAppleAccountDeletion({
          repository,
          authDependencies: runtime.dependencies,
          deletionKey,
          crypto: nativeContext.crypto,
          now: nativeContext.now,
          completionNow: nativeContext.clock,
          originDependencies,
        });
        if (replay !== null) return deletionResponse(replay);
        throw new AppleAuthError(
          401,
          'APPLE_ACCOUNT_SESSION_REQUIRED',
          'An authenticated Apple session is required to delete this account.',
        );
      }
      const ownerId = principal.ownerId;
      const appleSubjectHash = principal.appleSubjectHash;
      const authDependencies = runtime.dependencies;
      return deletionResponse(await deleteAppleAccount({
        repository,
        authDependencies,
        ownerId,
        appleSubjectHash,
        deletionKey,
        crypto: nativeContext.crypto,
        now: nativeContext.now,
        completionNow: nativeContext.clock,
        originDependencies,
      }));
    }
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

function optionalAppleAuthDependencies(request: Request): AppleAuthDependencies | null {
  try {
    return appleAuthRuntime(request).dependencies;
  } catch (error) {
    if (error instanceof AppleAuthError && error.code === 'APPLE_AUTH_NOT_CONFIGURED') return null;
    throw error;
  }
}

function nativeSessionRequired(): AppleAuthError {
  return new AppleAuthError(
    401,
    'APPLE_NATIVE_SESSION_REQUIRED',
    'A valid native bearer session is required to delete this account.',
  );
}

function deletionResponse(
  result: Awaited<ReturnType<typeof deleteAppleAccount>>,
  clearWebCookie = true,
): Response {
  return Response.json(result, {
    headers: {
      'Cache-Control': 'no-store',
      ...(clearWebCookie ? {'Set-Cookie': clearSessionCookie()} : {}),
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
