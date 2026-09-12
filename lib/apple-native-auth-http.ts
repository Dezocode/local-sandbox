import { env } from 'cloudflare:workers';
import {
  APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
  AppleAuthError,
  parseAppleAuthConfiguration,
} from './apple-auth.ts';
import type { AppleNativeAuthDependencies } from './apple-native-auth.ts';
import { createD1AppleNativeAuthRepository } from './apple-native-auth-d1.ts';

export function appleNativeAuthContext(request: Request): AppleNativeAuthDependencies {
  if (!env.DB) {
    throw new AppleAuthError(
      503,
      'APPLE_AUTH_STORAGE_UNAVAILABLE',
      'Apple authentication storage is unavailable.',
    );
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
  if (!configuration.nativeClientId) {
    throw new AppleAuthError(
      503,
      'APPLE_NATIVE_AUTH_NOT_CONFIGURED',
      'Native Sign in with Apple is not configured on this server.',
    );
  }
  if (new URL(request.url).origin !== new URL(configuration.redirectUri).origin) {
    throw new AppleAuthError(
      503,
      'APPLE_AUTH_ORIGIN_MISMATCH',
      'This site origin does not match the registered Apple return URL.',
    );
  }
  return {
    configuration,
    repository: createD1AppleNativeAuthRepository(env.DB),
    fetcher: fetch,
    crypto: globalThis.crypto,
    now: () => Math.floor(Date.now() / 1_000),
    revocationTimeoutMilliseconds: APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
  };
}

export function appleNativeSessionContext(): {
  repository: ReturnType<typeof createD1AppleNativeAuthRepository>;
  database: D1Database;
  crypto: Crypto;
  now: number;
  clock: () => number;
} {
  if (!env.DB) {
    throw new AppleAuthError(
      503,
      'APPLE_AUTH_STORAGE_UNAVAILABLE',
      'Apple authentication storage is unavailable.',
    );
  }
  const clock = () => Math.floor(Date.now() / 1_000);
  return {
    repository: createD1AppleNativeAuthRepository(env.DB),
    database: env.DB,
    crypto: globalThis.crypto,
    now: clock(),
    clock,
  };
}
