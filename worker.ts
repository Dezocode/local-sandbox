import vinextHandler from 'vinext/server/fetch-handler';
import {
  APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
  parseAppleAuthConfiguration,
} from './lib/apple-auth.ts';
import { createD1AppleNativeAuthRepository } from './lib/apple-native-auth-d1.ts';
import { drainExpiredAppleNativeGrants } from './lib/apple-native-auth.ts';
import { drainExpiredAppleAuthLifecycleRecords } from './lib/apple-auth-retention-d1.ts';

const worker = {
  fetch(request: Request, env: Cloudflare.Env, context: ExecutionContext) {
    return vinextHandler.fetch(request, env, context);
  },
  async scheduled(controller: ScheduledController, env: Cloudflare.Env): Promise<void> {
    try {
      if (env.DB === undefined) {
        throw new Error('The DB binding is required for scheduled retention cleanup.');
      }
      const scheduledTime = controller.scheduledTime;
      if (!Number.isSafeInteger(scheduledTime) || scheduledTime < 0) {
        throw new Error('The retention scheduler received an invalid scheduled time.');
      }
      const retentionCutoff = Math.floor(scheduledTime / 1_000);
      let nativeGrantResult: Awaited<ReturnType<typeof drainExpiredAppleNativeGrants>> | null = null;
      let nativeGrantFailure: unknown = null;
      try {
        const repository = createD1AppleNativeAuthRepository(env.DB);
        const grantRequiresProvider = await repository.hasExpiredSessionGrant(
          retentionCutoff,
          Math.floor(Date.now() / 1_000),
        );
        if (!grantRequiresProvider) {
          nativeGrantResult = {
            batches: 0,
            found: 0,
            revoked: 0,
            failed: 0,
            backlog: false,
          };
        } else {
          const configuration = parseAppleAuthConfiguration({
            APPLE_AUTH_TEAM_ID: env.APPLE_AUTH_TEAM_ID,
            APPLE_AUTH_KEY_ID: env.APPLE_AUTH_KEY_ID,
            APPLE_AUTH_CLIENT_ID: env.APPLE_AUTH_CLIENT_ID,
            APPLE_AUTH_NATIVE_CLIENT_ID: env.APPLE_AUTH_NATIVE_CLIENT_ID,
            APPLE_AUTH_REDIRECT_URI: env.APPLE_AUTH_REDIRECT_URI,
            APPLE_AUTH_PRIVATE_KEY_P8: env.APPLE_AUTH_PRIVATE_KEY_P8,
            APPLE_AUTH_STORAGE_KEY: env.APPLE_AUTH_STORAGE_KEY,
          });
          nativeGrantResult = await drainExpiredAppleNativeGrants({
            configuration,
            repository,
            fetcher: fetch,
            crypto: globalThis.crypto,
            now: () => Math.floor(Date.now() / 1_000),
            revocationTimeoutMilliseconds: APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
          }, {cutoff: retentionCutoff});
        }
        if (nativeGrantResult.failed > 0 || nativeGrantResult.backlog) {
          nativeGrantFailure = new Error(
            `${nativeGrantResult.failed} native Apple grant revocation(s) failed; backlog=${nativeGrantResult.backlog}.`,
          );
        }
      } catch (error) {
        nativeGrantFailure = error;
      }
      const result = await drainExpiredAppleAuthLifecycleRecords(
        env.DB,
        retentionCutoff,
      );
      console.info(JSON.stringify({
        event: 'apple-auth-retention-complete',
        scheduledTime,
        nativeGrants: nativeGrantResult,
        ...result,
      }));
      if (nativeGrantFailure !== null) throw nativeGrantFailure;
    } catch (error) {
      console.error(JSON.stringify({
        event: 'apple-auth-retention-failed',
        message: error instanceof Error ? error.message : 'Unknown retention failure',
      }));
      throw error;
    }
  },
} satisfies ExportedHandler<Cloudflare.Env>;

export default worker;
