import { env } from 'cloudflare:workers';
import { getChatGPTUser, type ChatGPTUser } from '@/app/chatgpt-auth';
import {
  APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
  AppleAuthError,
  type AppleAuthDependencies,
  parseAppleAuthConfiguration,
} from './apple-auth';
import { createD1AppleAuthRepository } from './apple-auth-d1';

export const APPLE_FLOW_COOKIE = '__Host-local_sandbox_apple_flow';
export const APPLE_SESSION_COOKIE = '__Host-local_sandbox_apple_session';

export function appleAuthRuntime(request: Request): {
  dependencies: AppleAuthDependencies;
  database: D1Database;
} {
  if (!env.DB) {
    throw new AppleAuthError(503, 'APPLE_AUTH_STORAGE_UNAVAILABLE', 'Apple authentication storage is unavailable.');
  }
  const configuration = parseAppleAuthConfiguration({
    APPLE_AUTH_TEAM_ID: env.APPLE_AUTH_TEAM_ID,
    APPLE_AUTH_KEY_ID: env.APPLE_AUTH_KEY_ID,
    APPLE_AUTH_CLIENT_ID: env.APPLE_AUTH_CLIENT_ID,
    APPLE_AUTH_NATIVE_CLIENT_ID: env.APPLE_AUTH_NATIVE_CLIENT_ID,
    APPLE_AUTH_REDIRECT_URI: env.APPLE_AUTH_REDIRECT_URI,
    APPLE_AUTH_PRIVATE_KEY_P8: env.APPLE_AUTH_PRIVATE_KEY_P8,
    APPLE_AUTH_STORAGE_KEY: env.APPLE_AUTH_STORAGE_KEY,
  });
  if (new URL(request.url).origin !== new URL(configuration.redirectUri).origin) {
    throw new AppleAuthError(503, 'APPLE_AUTH_ORIGIN_MISMATCH', 'This site origin does not match the registered Apple return URL.');
  }
  return {
    dependencies: {
      configuration,
      repository: createD1AppleAuthRepository(env.DB),
      fetcher: fetch,
      crypto: globalThis.crypto,
      now: () => Math.floor(Date.now() / 1_000),
      revocationTimeoutMilliseconds: APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
    },
    database: env.DB,
  };
}

export async function appleAuthContext(request: Request): Promise<{
  dependencies: AppleAuthDependencies;
  hostUser: ChatGPTUser | null;
}> {
  const runtime = appleAuthRuntime(request);
  return {
    dependencies: runtime.dependencies,
    hostUser: await getChatGPTUser(),
  };
}

export function appleAuthErrorResponse(error: unknown, additionalHeaders?: HeadersInit): Response {
  const known = error instanceof AppleAuthError
    ? error
    : new AppleAuthError(503, 'APPLE_AUTH_UNAVAILABLE', 'Apple authentication could not complete.');
  if (!(error instanceof AppleAuthError)) {
    console.error(JSON.stringify({
      event: 'apple_auth_failed',
      error: error instanceof Error ? error.message : 'Unknown failure',
    }));
  }
  const headers = new Headers(additionalHeaders);
  headers.set('Cache-Control', 'no-store');
  headers.set('Content-Type', 'application/json');
  headers.set('X-Content-Type-Options', 'nosniff');
  return Response.json({error: known.message, code: known.code}, {status: known.status, headers});
}

export function readCookie(request: Request, name: string): string | null {
  const matches = (request.headers.get('cookie') ?? '')
    .split(';')
    .map(part => part.trim())
    .filter(part => part.startsWith(`${name}=`));
  if (matches.length !== 1) return null;
  return matches[0].slice(name.length + 1) || null;
}

export function flowCookie(value: string, maxAge = 600): string {
  return `${APPLE_FLOW_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=None`;
}

export function sessionCookie(value: string, maxAge = 30 * 24 * 60 * 60): string {
  return `${APPLE_SESSION_COOKIE}=${value}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`;
}

export function clearFlowCookie(): string {
  return flowCookie('', 0);
}

export function clearSessionCookie(): string {
  return sessionCookie('', 0);
}

export function requireSameOrigin(request: Request): void {
  if (request.headers.get('origin') !== new URL(request.url).origin) {
    throw new AppleAuthError(403, 'APPLE_AUTH_CSRF', 'Submit this action from the Local Sandbox site.');
  }
}

export function resultRedirect(returnTo: string, result: 'connected' | 'cancelled'): URL {
  const redirect = new URL(returnTo, 'https://app.local');
  redirect.searchParams.set('apple_auth', result);
  return new URL(`${redirect.pathname}${redirect.search}${redirect.hash}`, 'https://app.local');
}
