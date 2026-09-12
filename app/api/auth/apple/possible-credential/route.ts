import { getChatGPTUser } from '@/app/chatgpt-auth';
import {
  AppleAuthError,
  hashAppleOpaqueToken,
  readAppleSessionLocalPrincipal,
} from '@/lib/apple-auth';
import {
  acknowledgeD1ApplePossibleCredentialReview,
  AppleOwnerExternalOperationError,
  readD1ApplePossibleCredentialReview,
  type ApplePossibleCredentialReview,
} from '@/lib/apple-auth-external-operation-d1';
import {
  APPLE_SESSION_COOKIE,
  appleAuthErrorResponse,
  appleAuthRuntime,
  readCookie,
  requireSameOrigin,
} from '@/lib/apple-auth-http';
import { parseAppleNativeBearer, readAppleNativeSession } from '@/lib/apple-native-auth';
import { appleNativeSessionContext } from '@/lib/apple-native-auth-http';
import {
  AppleCredentialReviewRequestError,
  readAppleCredentialReviewAcknowledgementRequest,
} from '@/lib/apple-credential-review';

type ReviewAuthorization = {
  database: D1Database;
  authorization: {
    userId: string;
    appleSubjectHash: string;
    authorizationStartedAt: number;
  };
  now: number;
};

async function requireReviewAuthorization(
  request: Request,
  bearer = parseAppleNativeBearer(request),
): Promise<ReviewAuthorization> {
  if (bearer !== null) {
    if (request.headers.has('cookie')) {
      throw new AppleAuthError(400, 'APPLE_NATIVE_AMBIENT_AUTH', 'Native credential review does not accept browser cookies.');
    }
    const context = appleNativeSessionContext();
    const session = await readAppleNativeSession(context.repository, bearer, context.now, context.crypto);
    if (session === null) {
      throw new AppleAuthError(401, 'APPLE_NATIVE_SESSION_INVALID', 'The native bearer session is invalid or expired.');
    }
    return {
      database: context.database,
      authorization: {
        userId: session.ownerId,
        appleSubjectHash: session.appleSubjectHash,
        authorizationStartedAt: session.createdAt,
      },
      now: context.now,
    };
  }

  const runtime = appleAuthRuntime(request);
  const token = readCookie(request, APPLE_SESSION_COOKIE);
  const principal = await readAppleSessionLocalPrincipal(runtime.dependencies, token);
  if (principal === null || token === null) {
    throw new AppleAuthError(401, 'APPLE_SESSION_REQUIRED', 'An Apple session is required to review possible credential cleanup.');
  }
  const hostUser = await getChatGPTUser();
  if (hostUser !== null && hostUser.userId !== principal.ownerId) {
    throw new AppleAuthError(409, 'AUTH_SESSION_AMBIGUOUS', 'The Apple and ChatGPT sessions belong to different Local Sandbox accounts.');
  }
  const record = await runtime.dependencies.repository.readSession(
    await hashAppleOpaqueToken(token, runtime.dependencies.crypto),
    runtime.dependencies.now(),
  );
  if (record === null || record.ownerId !== principal.ownerId || record.appleSubjectHash !== principal.appleSubjectHash) {
    throw new AppleAuthError(401, 'APPLE_SESSION_REQUIRED', 'The Apple session changed before credential cleanup could be reviewed.');
  }
  return {
    database: runtime.database,
    authorization: {
      userId: principal.ownerId,
      appleSubjectHash: principal.appleSubjectHash,
      authorizationStartedAt: record.createdAt,
    },
    now: runtime.dependencies.now(),
  };
}

function response(review: ApplePossibleCredentialReview | null): Response {
  return Response.json({
    manualReviewRequired: review !== null,
    acknowledgementId: review?.acknowledgementId ?? null,
    markedAt: review?.markedAt ?? null,
  }, {headers: {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}});
}

function asAppleAuthError(error: unknown): unknown {
  return error instanceof AppleCredentialReviewRequestError
    ? new AppleAuthError(error.status, error.code, error.message)
    : error instanceof AppleOwnerExternalOperationError
    ? new AppleAuthError(error.status, error.code, error.message)
    : error;
}

export async function GET(request: Request): Promise<Response> {
  try {
    const context = await requireReviewAuthorization(request);
    return response(await readD1ApplePossibleCredentialReview(
      context.database,
      context.authorization,
      context.now,
    ));
  } catch (error) {
    return appleAuthErrorResponse(asAppleAuthError(error));
  }
}

export async function POST(request: Request): Promise<Response> {
  try {
    const bearer = parseAppleNativeBearer(request);
    if (bearer === null) requireSameOrigin(request);
    const context = await requireReviewAuthorization(request, bearer);
    const input = await readAppleCredentialReviewAcknowledgementRequest(request);
    await acknowledgeD1ApplePossibleCredentialReview(
      context.database,
      context.authorization,
      input.acknowledgementId,
      context.now,
    );
    return Response.json({acknowledged: true}, {
      headers: {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'},
    });
  } catch (error) {
    return appleAuthErrorResponse(asAppleAuthError(error));
  }
}
