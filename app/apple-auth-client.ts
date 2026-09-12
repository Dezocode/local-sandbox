import { z } from 'zod';
import { readBoundedResponseText } from '../lib/bounded-response.ts';

type WorkspaceRequestOutcome<T> =
  | {kind: 'success'; value: T}
  | {kind: 'failure'; reason: unknown};

export type WorkspaceSessionCommit<T> =
  | {kind: 'applied'; value: T}
  | {kind: 'stale'};

export type WorkspaceSessionRequest<T, R> = {
  request: () => Promise<T>;
  onSuccess: (value: T) => R;
  onFailure: (reason: unknown) => R;
};

export type WorkspaceSessionScope = {
  run<T, R>(input: WorkspaceSessionRequest<T, R>): Promise<WorkspaceSessionCommit<R>>;
  commit<R>(onCurrent: () => R): WorkspaceSessionCommit<R>;
};

export class WorkspaceSessionGeneration {
  private generation: object = {};

  invalidate(): void {
    this.generation = {};
  }

  bind(): WorkspaceSessionScope {
    const capturedGeneration = this.generation;
    return {
      run: <T, R>(input: WorkspaceSessionRequest<T, R>) => (
        this.runForGeneration(capturedGeneration, input)
      ),
      commit: <R>(onCurrent: () => R) => (
        capturedGeneration === this.generation
          ? {kind: 'applied', value: onCurrent()}
          : {kind: 'stale'}
      ),
    };
  }

  run<T, R>(input: WorkspaceSessionRequest<T, R>): Promise<WorkspaceSessionCommit<R>> {
    return this.bind().run(input);
  }

  private async runForGeneration<T, R>(
    capturedGeneration: object,
    input: WorkspaceSessionRequest<T, R>,
  ): Promise<WorkspaceSessionCommit<R>> {
    if (capturedGeneration !== this.generation) return {kind: 'stale'};
    let outcome: WorkspaceRequestOutcome<T>;
    try {
      outcome = {kind: 'success', value: await input.request()};
    } catch (reason) {
      outcome = {kind: 'failure', reason};
    }
    if (capturedGeneration !== this.generation) return {kind: 'stale'};
    return outcome.kind === 'success'
      ? {kind: 'applied', value: input.onSuccess(outcome.value)}
      : {kind: 'applied', value: input.onFailure(outcome.reason)};
  }
}

export class StaleWorkspaceSessionError extends Error {
  constructor() {
    super('The workspace account changed before the request completed.');
    this.name = 'StaleWorkspaceSessionError';
  }
}

export function requireCurrentWorkspaceResult<T>(result: WorkspaceSessionCommit<T>): T {
  if (result.kind === 'stale') throw new StaleWorkspaceSessionError();
  return result.value;
}

export async function revokeAppleSessionAndScrub(input: {
  revoke: () => Promise<void>;
  scrub: () => void;
}): Promise<void> {
  const revocation = (() => {
    try {
      return input.revoke();
    } finally {
      input.scrub();
    }
  })();
  await revocation;
}

const nonnegativeSafeIntegerSchema = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const appleAccountDeletionProviderCredentialsSchema = z.object({
  credentialsFound: nonnegativeSafeIntegerSchema,
  credentialsRevoked: nonnegativeSafeIntegerSchema,
  unreadableSessions: nonnegativeSafeIntegerSchema,
  failedRevocations: nonnegativeSafeIntegerSchema,
  manualRevocationRequired: z.boolean(),
}).strict().refine(
  value => value.credentialsRevoked <= value.credentialsFound
    && value.failedRevocations === value.credentialsFound - value.credentialsRevoked
    && value.manualRevocationRequired === (
      value.credentialsFound === 0
      || value.unreadableSessions > 0
      || value.failedRevocations > 0
    ),
  {message: 'Provider credential deletion summary is inconsistent.'},
);
const appleAccountDeletionResponseSchema = z.object({
  deleted: z.literal(true),
  idempotent: z.boolean(),
  providerCredentials: appleAccountDeletionProviderCredentialsSchema,
  originConnections: z.object({
    installationsFound: nonnegativeSafeIntegerSchema,
    installationsRevoked: nonnegativeSafeIntegerSchema,
    unreadableInstallations: nonnegativeSafeIntegerSchema,
    failedRevocations: nonnegativeSafeIntegerSchema,
    manualRevocationRequired: z.boolean(),
  }).strict().refine(
    value => value.installationsFound === (
      value.installationsRevoked + value.unreadableInstallations + value.failedRevocations
    ) && value.manualRevocationRequired === (
      value.unreadableInstallations > 0 || value.failedRevocations > 0
    ),
    {message: 'Origin connection revocation summary is inconsistent.'},
  ),
}).strict();
const appleAccountDeletionErrorSchema = z.object({
  error: z.string().min(1).max(1_000),
  code: z.string().min(1).max(100),
}).strict();
const APPLE_ACCOUNT_DELETION_RESPONSE_BYTES = 8_192;
const APPLE_ACCOUNT_DELETION_ATTEMPT_STORAGE_KEY = 'localSandbox.appleAccountDeletionAttempt.v1';
const APPLE_ACCOUNT_DELETION_FOLLOW_UP_STORAGE_KEY = 'localSandbox.appleAccountDeletionFollowUp.v1';
const APPLE_ACCOUNT_LIFECYCLE_CHANNEL = 'localSandbox.appleAccountLifecycle.v1';
const APPLE_ACCOUNT_LIFECYCLE_STORAGE_KEY = 'localSandbox.appleAccountLifecycleEvent.v1';
const APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_MILLISECONDS = 30 * 24 * 60 * 60 * 1_000;
const APPLE_ACCOUNT_DELETION_ATTEMPT_BYTES = 4_096;
const APPLE_ACCOUNT_LIFECYCLE_EVENT_BYTES = 1_024;
const APPLE_ACCOUNT_LIFECYCLE_EVENT_MAX_AGE_MILLISECONDS = 5 * 60 * 1_000;
const canonicalAppleAccountDeletionKeySchema = z.string().refine(
  isCanonicalAppleAccountDeletionKey,
  {message: 'Account deletion key is not canonical.'},
);
const appleAccountDeletionAttemptSchema = z.object({
  schemaVersion: z.literal(1),
  accountScope: z.string().length(43).regex(/^[A-Za-z0-9_-]{43}$/),
  workspaceScope: z.string().length(32).regex(/^[A-Za-z0-9_-]{32}$/),
  accountMode: z.enum(['standalone', 'linked']),
  deletionKey: canonicalAppleAccountDeletionKeySchema,
  createdAt: z.number().int().nonnegative()
    .max(Number.MAX_SAFE_INTEGER - APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_MILLISECONDS),
  expiresAt: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
}).strict().refine(
  value => value.expiresAt
    === value.createdAt + APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_MILLISECONDS,
  {message: 'Account deletion attempt lifetime is invalid.'},
);
const appleAccountDeletionFollowUpSchema = z.object({
  schemaVersion: z.literal(1),
  accountScope: z.string().length(43).regex(/^[A-Za-z0-9_-]{43}$/),
  workspaceScope: z.string().length(32).regex(/^[A-Za-z0-9_-]{32}$/),
  accountMode: z.enum(['standalone', 'linked']),
  providerManualRevocationRequired: z.boolean(),
  originManualRevocationRequired: z.boolean(),
  createdAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
}).strict().refine(
  value => value.providerManualRevocationRequired || value.originManualRevocationRequired,
  {message: 'Account deletion follow-up is unnecessary.'},
);
const appleAccountLifecycleEventSchema = z.discriminatedUnion('kind', [
  z.object({
    schemaVersion: z.literal(1),
    kind: z.literal('apple-account-deletion-lock'),
    eventId: z.string().regex(/^v1\.[A-Za-z0-9_-]{43}$/),
    occurredAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    workspaceScope: z.string().length(32).regex(/^[A-Za-z0-9_-]{32}$/),
  }).strict(),
  z.object({
    schemaVersion: z.literal(1),
    kind: z.literal('apple-account-deleted'),
    eventId: z.string().regex(/^v1\.[A-Za-z0-9_-]{43}$/),
    occurredAt: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    workspaceScope: z.string().length(32).regex(/^[A-Za-z0-9_-]{32}$/),
    accountMode: z.enum(['standalone', 'linked']),
    manualRevocationRequired: z.boolean(),
    originManualRevocationRequired: z.boolean(),
  }).strict(),
]);

export type AppleAccountDeletionResponse = z.infer<typeof appleAccountDeletionResponseSchema>;
export type AppleAccountDeletionOutcome =
  | {kind: 'cancelled'}
  | {kind: 'deleted'; response: AppleAccountDeletionResponse};
type AppleAccountDeletionAttempt = z.infer<typeof appleAccountDeletionAttemptSchema>;
export type AppleAccountDeletionFollowUp = z.infer<typeof appleAccountDeletionFollowUpSchema>;

export type AppleAccountDeletionAttemptStore = {
  read(): string | null;
  write(value: string): void;
  clear(): void;
};

export type AppleAccountLifecycleInvalidation =
  | {kind:'lock';workspaceScope:string}
  | {kind:'deleted';workspaceScope:string;accountMode:'standalone'|'linked';manualRevocationRequired:boolean;originManualRevocationRequired:boolean};

export type AppleAccountLifecycleInvalidationTransport = {
  publish(value: string): void;
  subscribe(listener: (value: unknown) => void): () => void;
};

export class AppleAccountDeletionHTTPError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'AppleAccountDeletionHTTPError';
    this.status = status;
    this.code = code;
  }
}

export class AppleAccountDeletionIdentityMismatchError extends Error {
  constructor() {
    super('The pending account deletion belongs to a different Apple identity.');
    this.name = 'AppleAccountDeletionIdentityMismatchError';
  }
}

export class AppleAccountDeletionAttemptInvalidError extends Error {
  constructor() {
    super('The saved account deletion retry record is invalid and was retained. Do not start a different account deletion until this browser storage is reviewed.');
    this.name = 'AppleAccountDeletionAttemptInvalidError';
  }
}

export class AppleAccountDeletionClient {
  private readonly attemptStore: AppleAccountDeletionAttemptStore;
  private readonly followUpStore: AppleAccountDeletionAttemptStore;
  private readonly randomBytes: (count: number) => Uint8Array;
  private readonly now: () => number;

  constructor(input: {
    randomBytes?: (count: number) => Uint8Array;
    attemptStore?: AppleAccountDeletionAttemptStore;
    followUpStore?: AppleAccountDeletionAttemptStore;
    now?: () => number;
  } = {}) {
    this.randomBytes = input.randomBytes ?? secureRandomBytes;
    this.attemptStore = input.attemptStore ?? browserAppleAccountDeletionAttemptStore();
    this.followUpStore = input.followUpStore ?? browserAppleAccountDeletionFollowUpStore();
    this.now = input.now ?? Date.now;
  }

  hasPendingAttempt(accountScope: string): boolean {
    return this.readPendingAttempt()?.accountScope === accountScope;
  }

  pendingAccountScope(): string | null {
    return this.readPendingAttempt()?.accountScope ?? null;
  }

  pendingAccountMode(): 'standalone' | 'linked' | null {
    return this.readPendingAttempt()?.accountMode ?? null;
  }

  pendingWorkspaceScope(): string | null {
    return this.readPendingAttempt()?.workspaceScope ?? null;
  }

  pendingManualFollowUp(): AppleAccountDeletionFollowUp | null {
    const encoded=this.followUpStore.read();
    if(encoded===null)return null;
    try{
      if(new TextEncoder().encode(encoded).byteLength>APPLE_ACCOUNT_DELETION_ATTEMPT_BYTES)throw new Error('Oversized follow-up.');
      const value=appleAccountDeletionFollowUpSchema.parse(JSON.parse(encoded));
      if(encoded!==JSON.stringify(value))throw new Error('Non-canonical follow-up.');
      return value;
    }catch{throw new AppleAccountDeletionAttemptInvalidError();}
  }

  dismissManualFollowUp(): void {
    if(this.pendingManualFollowUp()!==null)this.followUpStore.clear();
  }

  async deleteIfConfirmed(input: {
    confirmed: boolean;
    accountScope: string;
    workspaceScope: string;
    accountMode: 'standalone' | 'linked';
    fetcher?: typeof fetch;
    scrub: (response: AppleAccountDeletionResponse) => void | Promise<void>;
  }): Promise<AppleAccountDeletionOutcome> {
    if (!input.confirmed) return {kind: 'cancelled'};
    if (!/^[A-Za-z0-9_-]{43}$/.test(input.accountScope)) {
      throw new TypeError('Apple account deletion requires a valid account scope.');
    }
    if (!/^[A-Za-z0-9_-]{32}$/.test(input.workspaceScope)) {
      throw new TypeError('Apple account deletion requires a valid workspace scope.');
    }
    const existingFollowUp = this.pendingManualFollowUp();
    if (existingFollowUp !== null && existingFollowUp.accountScope !== input.accountScope) {
      throw new AppleAccountDeletionIdentityMismatchError();
    }
    const existing = this.readPendingAttempt();
    if (
      existing !== null &&
      (existing.accountScope !== input.accountScope
        || existing.workspaceScope !== input.workspaceScope
        || existing.accountMode !== input.accountMode)
    ) {
      throw new AppleAccountDeletionIdentityMismatchError();
    }
    const attempt = existing ?? this.createPendingAttempt(
      input.accountScope,
      input.workspaceScope,
      input.accountMode,
    );
    const response = await (input.fetcher ?? fetch)('/api/auth/apple/delete', {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Idempotency-Key': attempt.deletionKey,
      },
      body: undefined,
      cache: 'no-store',
      credentials: 'same-origin',
      mode: 'same-origin',
      redirect: 'error',
      referrerPolicy: 'same-origin',
    });
    const parsed = await parseAppleAccountDeletionResponse(response);
    const providerManualRevocationRequired=parsed.providerCredentials.manualRevocationRequired;
    const originManualRevocationRequired=parsed.originConnections.manualRevocationRequired;
    await input.scrub(parsed);
    if(providerManualRevocationRequired||originManualRevocationRequired){
      const followUp=appleAccountDeletionFollowUpSchema.parse({
        schemaVersion:1,
        accountScope:attempt.accountScope,
        workspaceScope:attempt.workspaceScope,
        accountMode:attempt.accountMode,
        providerManualRevocationRequired,
        originManualRevocationRequired,
        createdAt:this.now(),
      });
      const encoded=JSON.stringify(followUp);
      this.followUpStore.write(encoded);
      if(this.followUpStore.read()!==encoded)throw new Error('The account deletion follow-up could not be stored safely.');
    }
    this.attemptStore.clear();
    return {kind: 'deleted', response: parsed};
  }

  private createPendingAttempt(
    accountScope: string,
    workspaceScope: string,
    accountMode: 'standalone' | 'linked',
  ): AppleAccountDeletionAttempt {
    const createdAt = this.now();
    const attempt = appleAccountDeletionAttemptSchema.parse({
      schemaVersion: 1,
      accountScope,
      workspaceScope,
      accountMode,
      deletionKey: createAppleAccountDeletionKey(this.randomBytes),
      createdAt,
      expiresAt: createdAt + APPLE_ACCOUNT_DELETION_RECEIPT_LIFETIME_MILLISECONDS,
    });
    this.attemptStore.write(JSON.stringify(attempt));
    const persisted = this.readPendingAttempt();
    if (persisted === null || persisted.deletionKey !== attempt.deletionKey) {
      throw new Error('The account deletion retry key could not be stored safely.');
    }
    return persisted;
  }

  private readPendingAttempt(): AppleAccountDeletionAttempt | null {
    const encoded = this.attemptStore.read();
    if (encoded === null) return null;
    let value: AppleAccountDeletionAttempt;
    try {
      if (new TextEncoder().encode(encoded).byteLength > APPLE_ACCOUNT_DELETION_ATTEMPT_BYTES) {
        throw new Error('Oversized attempt.');
      }
      const parsed: unknown = JSON.parse(encoded);
      value = appleAccountDeletionAttemptSchema.parse(parsed);
      if (encoded !== JSON.stringify(value)) throw new Error('Non-canonical attempt.');
    } catch {
      throw new AppleAccountDeletionAttemptInvalidError();
    }
    return value;
  }
}

export class AppleAccountLifecycleInvalidationBus {
  private readonly now: () => number;
  private readonly randomBytes: (count: number) => Uint8Array;
  private readonly transport: AppleAccountLifecycleInvalidationTransport;
  private readonly seenEventIds: string[] = [];

  constructor(input: {
    now?: () => number;
    randomBytes?: (count: number) => Uint8Array;
    transport?: AppleAccountLifecycleInvalidationTransport;
  } = {}) {
    this.now = input.now ?? Date.now;
    this.randomBytes = input.randomBytes ?? secureRandomBytes;
    this.transport = input.transport ?? browserAppleAccountLifecycleInvalidationTransport();
  }

  publishLock(workspaceScope: string): void {
    this.publishEvent({
      schemaVersion: 1,
      kind: 'apple-account-deletion-lock',
      eventId: createAppleAccountDeletionKey(this.randomBytes),
      occurredAt: this.now(),
      workspaceScope,
    });
  }

  publish(
    manualRevocationRequired: boolean,
    originManualRevocationRequired: boolean,
    accountMode: 'standalone' | 'linked',
    workspaceScope: string,
  ): void {
    this.publishEvent({
      schemaVersion: 1,
      kind: 'apple-account-deleted',
      eventId: createAppleAccountDeletionKey(this.randomBytes),
      occurredAt: this.now(),
      workspaceScope,
      accountMode,
      manualRevocationRequired,
      originManualRevocationRequired,
    });
  }

  subscribe(listener: (event: AppleAccountLifecycleInvalidation) => void): () => void {
    return this.transport.subscribe(value => {
      const event = this.parseEvent(value);
      if (event === null || this.seenEventIds.includes(event.eventId)) return;
      this.remember(event.eventId);
      listener(event.kind==='apple-account-deletion-lock'
        ? {kind:'lock',workspaceScope:event.workspaceScope}
        : {kind:'deleted',workspaceScope:event.workspaceScope,accountMode:event.accountMode,manualRevocationRequired:event.manualRevocationRequired,originManualRevocationRequired:event.originManualRevocationRequired});
    });
  }

  private publishEvent(value: z.input<typeof appleAccountLifecycleEventSchema>): void {
    const event=appleAccountLifecycleEventSchema.parse(value);
    this.remember(event.eventId);
    this.transport.publish(JSON.stringify(event));
  }

  private parseEvent(value: unknown): z.infer<typeof appleAccountLifecycleEventSchema> | null {
    if (typeof value !== 'string') return null;
    if (new TextEncoder().encode(value).byteLength > APPLE_ACCOUNT_LIFECYCLE_EVENT_BYTES) {
      return null;
    }
    try {
      const parsed = appleAccountLifecycleEventSchema.parse(JSON.parse(value));
      if (value !== JSON.stringify(parsed)) return null;
      const age = this.now() - parsed.occurredAt;
      return age >= 0 && age <= APPLE_ACCOUNT_LIFECYCLE_EVENT_MAX_AGE_MILLISECONDS
        ? parsed
        : null;
    } catch {
      return null;
    }
  }

  private remember(eventId: string): void {
    this.seenEventIds.push(eventId);
    if (this.seenEventIds.length > 32) this.seenEventIds.shift();
  }
}

function browserAppleAccountDeletionAttemptStore(): AppleAccountDeletionAttemptStore {
  return {
    read: () => {
      if (typeof window === 'undefined') return null;
      return window.localStorage.getItem(APPLE_ACCOUNT_DELETION_ATTEMPT_STORAGE_KEY);
    },
    write: value => {
      if (typeof window === 'undefined') {
        throw new Error('Durable browser storage is unavailable.');
      }
      window.localStorage.setItem(APPLE_ACCOUNT_DELETION_ATTEMPT_STORAGE_KEY, value);
    },
    clear: () => {
      if (typeof window !== 'undefined') {
        window.localStorage.removeItem(APPLE_ACCOUNT_DELETION_ATTEMPT_STORAGE_KEY);
      }
    },
  };
}

function browserAppleAccountDeletionFollowUpStore(): AppleAccountDeletionAttemptStore {
  return {
    read: () => {
      if (typeof window === 'undefined') return null;
      return window.localStorage.getItem(APPLE_ACCOUNT_DELETION_FOLLOW_UP_STORAGE_KEY);
    },
    write: value => {
      if (typeof window === 'undefined') {
        throw new Error('Durable browser storage is unavailable.');
      }
      window.localStorage.setItem(APPLE_ACCOUNT_DELETION_FOLLOW_UP_STORAGE_KEY, value);
    },
    clear: () => {
      if (typeof window !== 'undefined') {
        window.localStorage.removeItem(APPLE_ACCOUNT_DELETION_FOLLOW_UP_STORAGE_KEY);
      }
    },
  };
}

function browserAppleAccountLifecycleInvalidationTransport(): AppleAccountLifecycleInvalidationTransport {
  if (typeof window === 'undefined') {
    return {
      publish: () => { throw new Error('Cross-tab account invalidation is unavailable.'); },
      subscribe: () => () => undefined,
    };
  }
  const channel = typeof BroadcastChannel === 'undefined'
    ? null
    : new BroadcastChannel(APPLE_ACCOUNT_LIFECYCLE_CHANNEL);
  return {
    publish: value => {
      let delivered = false;
      try {
        channel?.postMessage(value);
        delivered ||= channel !== null;
      } catch { /* Try the storage-event fallback. */ }
      try {
        window.localStorage.setItem(APPLE_ACCOUNT_LIFECYCLE_STORAGE_KEY, value);
        delivered = true;
      } catch { /* The broadcast channel may still have succeeded. */ }
      if (!delivered) throw new Error('Other open tabs could not be invalidated safely.');
    },
    subscribe: listener => {
      const onMessage = (event: MessageEvent<unknown>) => { listener(event.data); };
      const onStorage = (event: StorageEvent) => {
        if (event.key === APPLE_ACCOUNT_LIFECYCLE_STORAGE_KEY && event.newValue !== null) {
          listener(event.newValue);
        }
      };
      channel?.addEventListener('message', onMessage);
      window.addEventListener('storage', onStorage);
      return () => {
        channel?.removeEventListener('message', onMessage);
        window.removeEventListener('storage', onStorage);
      };
    },
  };
}

function secureRandomBytes(count: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(count));
}

function createAppleAccountDeletionKey(randomBytes: (count: number) => Uint8Array): string {
  const bytes = randomBytes(32);
  if (bytes.byteLength !== 32) throw new Error('Secure random deletion key generation failed.');
  const encoded = btoa(String.fromCharCode(...bytes))
    .replaceAll('+', '-')
    .replaceAll('/', '_')
    .replaceAll('=', '');
  const key = `v1.${encoded}`;
  if (!isCanonicalAppleAccountDeletionKey(key)) {
    throw new Error('Secure random deletion key encoding failed.');
  }
  return key;
}

function isCanonicalAppleAccountDeletionKey(value: string): boolean {
  const match = /^v1\.([A-Za-z0-9_-]{43})$/.exec(value);
  if (match === null) return false;
  try {
    const bytes = atob(`${match[1].replaceAll('-', '+').replaceAll('_', '/')}=`);
    const canonical = btoa(bytes)
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '');
    return bytes.length === 32 && canonical === match[1];
  } catch {
    return false;
  }
}

async function parseAppleAccountDeletionResponse(
  response: Response,
): Promise<AppleAccountDeletionResponse> {
  const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
  if (contentType !== 'application/json') {
    await response.body?.cancel().catch(() => undefined);
    throw new Error('The account deletion response was not valid JSON.');
  }
  let raw: unknown;
  try {
    raw = JSON.parse(await readBoundedResponseText(response, APPLE_ACCOUNT_DELETION_RESPONSE_BYTES));
  } catch {
    throw new Error('The account deletion response was invalid or too large.');
  }
  if (!response.ok) {
    const error = appleAccountDeletionErrorSchema.safeParse(raw);
    throw new AppleAccountDeletionHTTPError(
      response.status,
      error.success ? error.data.code : `HTTP_${response.status}`,
      error.success ? error.data.error : 'The account deletion request was rejected.',
    );
  }
  const result = appleAccountDeletionResponseSchema.safeParse(raw);
  if (!result.success) throw new Error('The account deletion response was invalid.');
  return result.data;
}
