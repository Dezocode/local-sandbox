import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { runnerImport } from 'vite';
import { z } from 'zod';
import {
  APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
  AppleAuthError,
  type AppleAuthDependencies,
  type AppleAuthFlow,
  type AppleAuthRepository,
  type AppleAuthSessionRecord,
  type AppleCredentialRevocationSummary,
  type VerifiedAppleServerNotification,
  completeAppleAuthorization,
  createAppleClientSecret,
  hashAppleOpaqueToken,
  hashAppleSubject,
  parseAppleAuthConfiguration,
  parseAppleAuthorizationCallback,
  parseAppleAuthorizationStartRequest,
  parseAppleServerNotificationRequest,
  readAppleSession,
  readAppleSessionLocalPrincipal,
  revokeAppleSession,
  startAppleAuthorization,
  verifyAppleServerNotification,
} from '../lib/apple-auth.ts';
import { createD1AppleAuthRepository } from '../lib/apple-auth-d1.ts';
import {
  APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS,
  AppleOwnerExternalOperationError,
  createD1AppleOwnerExternalOperationLeaseRepository,
} from '../lib/apple-auth-external-operation-d1.ts';
import { createD1AppleNativeAuthRepository } from '../lib/apple-native-auth-d1.ts';
import type { AppleNativeGrantRecord, AppleNativeSessionRecord } from '../lib/apple-native-auth.ts';
import { readD1AppleLinkedIdentity } from '../lib/apple-identity-d1.ts';
import { drainExpiredAppleAuthLifecycleRecords } from '../lib/apple-auth-retention-d1.ts';
import {
  APPLE_OWNER_OPERATION_ALLOWED_SQL,
  appleOwnerOperationGateBindings,
  isAppleOwnerOperationAllowed,
} from '../lib/apple-auth-owner-d1.ts';
import {
  APPLE_ACCOUNT_DELETION_REVOCATION_LEASE_SECONDS,
  type OriginConnectionRevocationSummary,
  type AppleAccountDeletionRepository,
  applyVerifiedAppleServerNotification,
  deleteAppleAccount,
  parseAppleAccountDeletionKey,
  processAppleServerNotification,
  recoverAppleAccountDeletion,
  requireEmptyAppleAccountDeletionBody,
} from '../lib/apple-auth-lifecycle.ts';
import { createD1AppleAccountDeletionRepository } from '../lib/apple-auth-lifecycle-d1.ts';
import {
  APPLE_CREDENTIAL_REVIEW_REQUEST_MAXIMUM_BYTES,
  AppleCredentialReviewRequestError,
  appleCredentialReviewAcknowledgementResponseSchema,
  appleCredentialReviewResponseSchema,
  readAppleCredentialReviewAcknowledgementRequest,
} from '../lib/apple-credential-review.ts';
import {
  AppleAccountDeletionClient,
  AppleAccountDeletionAttemptInvalidError,
  AppleAccountDeletionHTTPError,
  AppleAccountDeletionIdentityMismatchError,
  AppleAccountLifecycleInvalidationBus,
  type AppleAccountDeletionAttemptStore,
  type AppleAccountLifecycleInvalidation,
  type AppleAccountLifecycleInvalidationTransport,
  revokeAppleSessionAndScrub,
  WorkspaceSessionGeneration,
} from '../app/apple-auth-client.ts';

const INITIAL_TIME = 1_800_000_000;
const APPLE_KEY_ID = 'APPLEKEY01';
const TEAM_ID = 'TEAMID0001';
const CLIENT_ID = 'com.dezocode.local-sandbox.web';
const WEB_WORKSPACE_SCOPE = 'W'.repeat(32);
const NO_ORIGIN_CONNECTIONS: OriginConnectionRevocationSummary = {
  installationsFound: 0,
  installationsRevoked: 0,
  unreadableInstallations: 0,
  failedRevocations: 0,
  manualRevocationRequired: false,
};

class MemoryAppleAccountDeletionAttemptStore implements AppleAccountDeletionAttemptStore {
  value: string | null;
  failWrites = false;

  constructor(value: string | null = null) {
    this.value = value;
  }

  read(): string | null { return this.value; }

  write(value: string): void {
    if (this.failWrites) throw new Error('durable storage unavailable');
    this.value = value;
  }

  clear(): void { this.value = null; }
}

class MemoryAppleAuthRepository implements AppleAuthRepository {
  readonly flows = new Map<string, AppleAuthFlow>();
  readonly sessions = new Map<string, AppleAuthSessionRecord>();
  readonly revoked = new Set<string>();
  readonly links = new Map<string, string>();
  readonly principalIds = new Map<string, string>();
  readonly principalCreatedAt = new Map<string, number>();
  readonly deletionSubjects = new Set<string>();
  readonly deletionOwners = new Set<string>();
  readonly authorizationLeases = new Set<string>();
  readonly possibleAuthorizationLeases = new Set<string>();

  async createFlow(flow: AppleAuthFlow): Promise<void> {
    if (this.flows.has(flow.stateHash)) throw new Error('duplicate flow');
    this.flows.set(flow.stateHash, structuredClone(flow));
  }

  async consumeFlow(stateHash: string, now: number): Promise<AppleAuthFlow | null> {
    const flow = this.flows.get(stateHash);
    if (!flow || flow.expiresAt <= now) return null;
    this.flows.delete(stateHash);
    return structuredClone(flow);
  }

  async createSession(session: AppleAuthSessionRecord): Promise<void> {
    if (this.deletionBlocked(session.ownerId, session.appleSubjectHash)) {
      throw new AppleAuthError(409, 'APPLE_ACCOUNT_DELETION_IN_PROGRESS', 'deletion in progress');
    }
    if (this.sessions.has(session.sessionHash)) throw new Error('duplicate session');
    this.sessions.set(session.sessionHash, structuredClone(session));
  }

  async readSession(sessionHash: string, now: number): Promise<AppleAuthSessionRecord | null> {
    const session = this.sessions.get(sessionHash);
    if (
      !session ||
      session.expiresAt <= now ||
      this.revoked.has(sessionHash) ||
      this.deletionBlocked(session.ownerId, session.appleSubjectHash)
    ) return null;
    return structuredClone(session);
  }

  async readLatestSessionForSubject(
    appleSubjectHash: string,
    now: number,
  ): Promise<AppleAuthSessionRecord | null> {
    const session = [...this.sessions.values()]
      .filter(candidate => (
        candidate.appleSubjectHash === appleSubjectHash
        && candidate.expiresAt > now
        && !this.revoked.has(candidate.sessionHash)
      ))
      .sort((left, right) => right.createdAt - left.createdAt)[0];
    return session ? structuredClone(session) : null;
  }

  async updateSession(update: {
    expected: AppleAuthSessionRecord;
    next: AppleAuthSessionRecord;
    now: number;
  }): Promise<void> {
    const current = this.sessions.get(update.expected.sessionHash);
    if (
      current === undefined
      || JSON.stringify(current) !== JSON.stringify(update.expected)
      || this.deletionBlocked(update.next.ownerId, update.next.appleSubjectHash)
      || update.next.expiresAt <= update.now
    ) throw new Error('APPLE_SESSION_UPDATE_CONFLICT');
    this.sessions.set(update.next.sessionHash, structuredClone(update.next));
  }

  async revokeSession(sessionHash: string): Promise<boolean> {
    const session = this.sessions.get(sessionHash);
    if (!session || this.revoked.has(sessionHash)) return false;
    this.revoked.add(sessionHash);
    this.sessions.delete(sessionHash);
    return true;
  }

  async linkAppleIdentity(link: {
    appleSubjectHash: string;
    ownerId: string;
    createdAt: number;
    updatedAt: number;
  }): Promise<'linked' | 'owner-conflict'> {
    const result = await this.resolveAppleIdentityGroup({
      appleSubjectHashes: [link.appleSubjectHash],
      proposedOwnerId: link.ownerId,
      requiredOwnerId: link.ownerId,
      createdAt: link.createdAt,
      updatedAt: link.updatedAt,
    });
    return result.kind === 'linked' ? 'linked' : 'owner-conflict';
  }

  async resolveAppleOwner(link: {
    appleSubjectHash: string;
    ownerId: string;
    createdAt: number;
    updatedAt: number;
  }): Promise<{ownerId: string; created: boolean}> {
    const result = await this.resolveAppleIdentityGroup({
      appleSubjectHashes: [link.appleSubjectHash],
      proposedOwnerId: link.ownerId,
      requiredOwnerId: null,
      createdAt: link.createdAt,
      updatedAt: link.updatedAt,
    });
    if (result.kind === 'owner-conflict') throw new Error('identity conflict');
    return {ownerId: result.ownerId, created: result.created};
  }

  async resolveAppleIdentityGroup(input: {
    appleSubjectHashes: readonly string[];
    proposedOwnerId: string;
    requiredOwnerId: string | null;
    createdAt: number;
    updatedAt: number;
  }): Promise<
    | {kind: 'linked'; ownerId: string; principalId: string; created: boolean}
    | {kind: 'owner-conflict'}
  > {
    const hashes = [...new Set(input.appleSubjectHashes)].sort();
    const owners = new Set(hashes.map(hash => this.links.get(hash)).filter(owner => owner !== undefined));
    if (owners.size > 1) return {kind: 'owner-conflict'};
    const existingOwnerId = owners.values().next().value ?? null;
    if (
      input.requiredOwnerId !== null
      && existingOwnerId !== null
      && existingOwnerId !== input.requiredOwnerId
    ) return {kind: 'owner-conflict'};
    const ownerId = input.requiredOwnerId ?? existingOwnerId ?? input.proposedOwnerId;
    const existingPrincipalIds = [...new Set(
      hashes.flatMap(hash => {
        if (!this.links.has(hash)) return [];
        return [this.principalIds.get(hash) ?? hash];
      }),
    )].sort();
    const principalId = existingPrincipalIds[0] ?? hashes[0]!;
    if (hashes.some(hash => this.deletionBlocked(ownerId, hash))) {
      throw new AppleAuthError(409, 'APPLE_ACCOUNT_DELETION_IN_PROGRESS', 'deletion in progress');
    }
    const groupCreatedAt = Math.min(
      input.createdAt,
      ...hashes.flatMap(hash => {
        const value = this.principalCreatedAt.get(hash);
        return value === undefined ? [] : [value];
      }),
    );
    for (const [hash, linkedOwner] of this.links) {
      if (
        linkedOwner === ownerId
        && existingPrincipalIds.includes(this.principalIds.get(hash) ?? hash)
      ) {
        this.principalIds.set(hash, principalId);
        this.principalCreatedAt.set(hash, groupCreatedAt);
      }
    }
    const created = hashes.every(hash => !this.links.has(hash));
    for (const hash of hashes) {
      this.links.set(hash, ownerId);
      this.principalIds.set(hash, principalId);
      this.principalCreatedAt.set(hash, groupCreatedAt);
    }
    return {kind: 'linked', ownerId, principalId, created};
  }

  async readLinkedIdentity(appleSubjectHash: string): Promise<{
    ownerId: string;
    principalId: string;
    principalCreatedAt: number;
  } | null> {
    const ownerId = this.links.get(appleSubjectHash);
    if (ownerId === undefined) return null;
    return {
      ownerId,
      principalId: this.principalIds.get(appleSubjectHash) ?? appleSubjectHash,
      principalCreatedAt: this.principalCreatedAt.get(appleSubjectHash) ?? 1,
    };
  }

  async readLinkedOwner(appleSubjectHash: string): Promise<string | null> {
    return this.links.get(appleSubjectHash) ?? null;
  }

  async claimAuthorizationExchangeLease(input: {
    leaseToken: string;
    ownerId: string;
    appleSubjectHash: string;
  }): Promise<void> {
    if (this.deletionBlocked(input.ownerId, input.appleSubjectHash)) {
      throw new AppleAuthError(409, 'APPLE_ACCOUNT_DELETION_IN_PROGRESS', 'deletion in progress');
    }
    this.authorizationLeases.add(input.leaseToken);
  }

  async completeAuthorizationExchangeLease(input: {
    leaseToken: string;
    ownerId: string;
    appleSubjectHash: string;
  }): Promise<void> {
    this.authorizationLeases.delete(input.leaseToken);
    this.possibleAuthorizationLeases.delete(input.leaseToken);
    if (this.deletionBlocked(input.ownerId, input.appleSubjectHash)) {
      throw new AppleAuthError(409, 'APPLE_ACCOUNT_DELETION_IN_PROGRESS', 'deletion in progress');
    }
  }

  async markAuthorizationExchangePossible(leaseToken: string): Promise<void> {
    if (!this.authorizationLeases.has(leaseToken)) throw new Error('authorization lease missing');
    this.possibleAuthorizationLeases.add(leaseToken);
  }

  async releaseAuthorizationExchangeLease(leaseToken: string): Promise<void> {
    this.authorizationLeases.delete(leaseToken);
    this.possibleAuthorizationLeases.delete(leaseToken);
  }

  deletionBlocked(ownerId: string, appleSubjectHash: string): boolean {
    return this.deletionOwners.has(ownerId) || this.deletionSubjects.has(appleSubjectHash);
  }
}

class MemoryAppleAccountDeletionRepository implements AppleAccountDeletionRepository {
  readonly authRepository: MemoryAppleAuthRepository;
  readonly deletionReceipts = new Map<string, {
    ownerBinding: string;
    ownerId: string;
    appleSubjectHash: string;
    applePrincipalId: string;
    deleteOwnerData: boolean;
    providerCredentials: AppleCredentialRevocationSummary | null;
    originConnections: OriginConnectionRevocationSummary | null;
    completedAt: number | null;
    completionFenceToken: string | null;
    revocationLeaseToken: string | null;
    revocationLeaseUntil: number | null;
    expiresAt: number;
  }>();
  readonly notifications = new Map<string, VerifiedAppleServerNotification>();
  readonly notificationOwners = new Map<string, string | null>();
  readonly notificationOriginCleanup = new Map<string, string[]>();
  readonly emailForwarding = new Map<string, {enabled: boolean; eventTime: number}>();
  readonly ownerData = new Set<string>();
  readonly originInstallations = new Map<string, string[]>();

  constructor(authRepository: MemoryAppleAuthRepository) {
    this.authRepository = authRepository;
  }

  async readDeletionReceipt(
    deletionKeyHash: string,
    now: number,
  ): Promise<{
    ownerBinding: string;
    providerCredentials: AppleCredentialRevocationSummary;
    originConnections: OriginConnectionRevocationSummary;
  } | null> {
    const receipt = this.deletionReceipts.get(deletionKeyHash);
    return receipt !== undefined && receipt.expiresAt > now &&
      receipt.providerCredentials !== null && receipt.originConnections !== null
      ? {
          ownerBinding: receipt.ownerBinding,
          providerCredentials: structuredClone(receipt.providerCredentials),
          originConnections: structuredClone(receipt.originConnections),
        }
      : null;
  }

  async readDeletionAttempt(deletionKeyHash: string, now: number): Promise<{
    ownerId: string;
    appleSubjectHash: string;
    deleteOwnerData: boolean;
    providerCredentials: AppleCredentialRevocationSummary | null;
    originConnections: OriginConnectionRevocationSummary | null;
  } | null> {
    const attempt = this.deletionReceipts.get(deletionKeyHash);
    return attempt === undefined || attempt.expiresAt <= now ? null : {
      ownerId: attempt.ownerId,
      appleSubjectHash: attempt.appleSubjectHash,
      deleteOwnerData: attempt.deleteOwnerData,
      providerCredentials: attempt.providerCredentials === null
        ? null
        : structuredClone(attempt.providerCredentials),
      originConnections: attempt.originConnections === null
        ? null
        : structuredClone(attempt.originConnections),
    };
  }

  async beginAppleAccountDeletion(input: {
    ownerId: string;
    appleSubjectHash: string;
    deleteOwnerData: boolean;
    ownerBinding: string;
    deletionKeyHash: string;
    revocationLeaseToken: string;
    startedAt: number;
    leaseClaimedAt: number;
    expiresAt: number;
  }): Promise<{
    ownerBinding: string;
    providerCredentials: AppleCredentialRevocationSummary;
    originConnections: OriginConnectionRevocationSummary;
  } | null> {
    const principalId = this.authRepository.principalIds.get(input.appleSubjectHash)
      ?? input.appleSubjectHash;
    const existing = this.deletionReceipts.get(input.deletionKeyHash);
    if (existing !== undefined) {
      this.assertAttemptMatches(existing, input);
      if (existing.providerCredentials !== null && existing.originConnections !== null) return {
        ownerBinding: existing.ownerBinding,
        providerCredentials: structuredClone(existing.providerCredentials),
        originConnections: structuredClone(existing.originConnections),
      };
    } else {
      const completed = [...this.deletionReceipts.values()]
        .filter(receipt => this.sameDeletionScope(receipt, input)
          && receipt.completedAt !== null
          && receipt.completedAt >= input.startedAt
          && receipt.expiresAt > input.startedAt
          && receipt.providerCredentials !== null
          && receipt.originConnections !== null)
        .sort((left, right) => (right.completedAt ?? 0) - (left.completedAt ?? 0))[0];
      if (
        completed !== undefined
        && completed.providerCredentials !== null
        && completed.originConnections !== null
      ) {
        const alias = {
          ownerBinding: input.ownerBinding,
          ownerId: input.ownerId,
          appleSubjectHash: input.appleSubjectHash,
          applePrincipalId: principalId,
          deleteOwnerData: input.deleteOwnerData,
          providerCredentials: structuredClone(completed.providerCredentials),
          originConnections: structuredClone(completed.originConnections),
          completedAt: completed.completedAt,
          completionFenceToken: completed.completionFenceToken,
          revocationLeaseToken: null,
          revocationLeaseUntil: null,
          expiresAt: completed.expiresAt,
        };
        this.deletionReceipts.set(input.deletionKeyHash, alias);
        return {
          ownerBinding: alias.ownerBinding,
          providerCredentials: structuredClone(alias.providerCredentials),
          originConnections: structuredClone(alias.originConnections),
        };
      }
      this.deletionReceipts.set(input.deletionKeyHash, {
        ownerBinding: input.ownerBinding,
        ownerId: input.ownerId,
        appleSubjectHash: input.appleSubjectHash,
        applePrincipalId: principalId,
        deleteOwnerData: input.deleteOwnerData,
        providerCredentials: null,
        originConnections: null,
        completedAt: null,
        completionFenceToken: null,
        revocationLeaseToken: null,
        revocationLeaseUntil: null,
        expiresAt: input.expiresAt,
      });
    }
    const current = this.deletionReceipts.get(input.deletionKeyHash);
    if (current === undefined) throw new Error('missing in-memory deletion attempt');
    for (const receipt of this.deletionReceipts.values()) {
      if (
        receipt.providerCredentials === null
        && receipt.originConnections === null
        && receipt.revocationLeaseUntil !== null
        && receipt.revocationLeaseUntil <= input.leaseClaimedAt
      ) {
        receipt.revocationLeaseToken = null;
        receipt.revocationLeaseUntil = null;
      }
    }
    const activeLeader = [...this.deletionReceipts.entries()].some(([key, receipt]) =>
      key !== input.deletionKeyHash
        && this.sameDeletionScope(receipt, input)
        && receipt.providerCredentials === null
        && receipt.originConnections === null
        && receipt.revocationLeaseUntil !== null
        && receipt.revocationLeaseUntil > input.leaseClaimedAt);
    let acquiredLease = false;
    if (
      !activeLeader
      && current.revocationLeaseToken === null
      && current.revocationLeaseUntil === null
    ) {
      current.revocationLeaseToken = input.revocationLeaseToken;
      current.revocationLeaseUntil = input.leaseClaimedAt
        + APPLE_ACCOUNT_DELETION_REVOCATION_LEASE_SECONDS;
      acquiredLease = true;
    }
    if (input.deleteOwnerData) this.authRepository.deletionOwners.add(input.ownerId);
    else {
      for (const [subjectHash, ownerId] of this.authRepository.links) {
        if (
          ownerId === input.ownerId
          && (this.authRepository.principalIds.get(subjectHash) ?? subjectHash) === principalId
        ) this.authRepository.deletionSubjects.add(subjectHash);
      }
    }
    if (acquiredLease) {
      return null;
    }
    throw new AppleAuthError(
      409,
      'APPLE_ACCOUNT_DELETION_IN_PROGRESS',
      'Another request is already completing this account deletion. Retry with the same key.',
    );
  }

  async readWebSessionsForDeletion(input: {
    ownerId: string;
    appleSubjectHash: string;
    deleteOwnerData: boolean;
  }): Promise<{
    sessions: AppleAuthSessionRecord[];
    unreadableSessions: number;
  }> {
    const principalId = this.authRepository.principalIds.get(input.appleSubjectHash)
      ?? input.appleSubjectHash;
    return {
      sessions: [...this.authRepository.sessions.values()]
        .filter(session => session.ownerId === input.ownerId && (
          input.deleteOwnerData
          || (this.authRepository.principalIds.get(session.appleSubjectHash)
            ?? session.appleSubjectHash) === principalId
        ))
        .map(session => structuredClone(session)),
      unreadableSessions: 0,
    };
  }

  async readOriginInstallationsForDeletion(input: {
    ownerId: string;
    appleSubjectHash: string;
    deleteOwnerData: boolean;
  }): Promise<{
    installationIds: string[];
    unreadableInstallations: number;
  }> {
    return {
      installationIds: input.deleteOwnerData
        ? structuredClone(this.originInstallations.get(input.ownerId) ?? [])
        : [],
      unreadableInstallations: 0,
    };
  }

  async deleteAppleAccessAndCompleteReceipt(input: {
    ownerId: string;
    appleSubjectHash: string;
    deleteOwnerData: boolean;
    ownerBinding: string;
    deletionKeyHash: string;
    revocationLeaseToken: string;
    providerCredentials: AppleCredentialRevocationSummary;
    originConnections: OriginConnectionRevocationSummary;
    originUnresolvedInstallationIds?: string[];
    completedAt: number;
    expiresAt: number;
  }): Promise<{created: boolean; providerCredentials: AppleCredentialRevocationSummary;originConnections:OriginConnectionRevocationSummary}> {
    const existing = this.deletionReceipts.get(input.deletionKeyHash);
    if (existing === undefined) throw new Error('missing deletion gate');
    this.assertAttemptMatches(existing, input);
    if (existing.providerCredentials !== null && existing.originConnections !== null) {
      if (existing.completionFenceToken !== input.revocationLeaseToken) {
        throw new AppleAuthError(
          409,
          'APPLE_ACCOUNT_DELETION_LEASE_LOST',
          'This account deletion request no longer owns the completed provider-cleanup lease.',
        );
      }
      return {created: false, providerCredentials: structuredClone(existing.providerCredentials),originConnections:structuredClone(existing.originConnections)};
    }
    if (
      existing.revocationLeaseToken !== input.revocationLeaseToken
      || existing.revocationLeaseUntil === null
      || existing.revocationLeaseUntil < input.completedAt
    ) {
      throw new AppleAuthError(
        409,
        'APPLE_ACCOUNT_DELETION_LEASE_LOST',
        'This account deletion request no longer owns the provider-cleanup lease.',
      );
    }
    let created = false;
    for (const receipt of this.deletionReceipts.values()) {
      const sameScope = receipt.ownerId === input.ownerId && (
        input.deleteOwnerData
          ? receipt.deleteOwnerData
          : !receipt.deleteOwnerData && receipt.applePrincipalId === existing.applePrincipalId
      );
      if (sameScope && receipt.expiresAt > input.completedAt && receipt.providerCredentials === null) {
        receipt.providerCredentials = structuredClone(input.providerCredentials);
        receipt.originConnections = structuredClone(input.originConnections);
        receipt.completedAt = input.completedAt;
        receipt.completionFenceToken = input.revocationLeaseToken;
        receipt.revocationLeaseToken = null;
        receipt.revocationLeaseUntil = null;
        receipt.expiresAt = input.expiresAt;
        created = true;
      }
    }
    for (const [hash, session] of this.authRepository.sessions) {
      const sessionPrincipalId = this.authRepository.principalIds.get(session.appleSubjectHash)
        ?? session.appleSubjectHash;
      if (
        session.ownerId === input.ownerId &&
        (input.deleteOwnerData || sessionPrincipalId === existing.applePrincipalId)
      ) this.authRepository.sessions.delete(hash);
    }
    for (const [subjectHash, ownerId] of this.authRepository.links) {
      if (
        ownerId === input.ownerId &&
        (input.deleteOwnerData || (
          this.authRepository.principalIds.get(subjectHash) ?? subjectHash
        ) === existing.applePrincipalId)
      ) {
        this.authRepository.links.delete(subjectHash);
        this.authRepository.principalIds.delete(subjectHash);
        this.authRepository.principalCreatedAt.delete(subjectHash);
      }
    }
    if (input.deleteOwnerData) {
      this.ownerData.delete(input.ownerId);
      this.originInstallations.delete(input.ownerId);
    }
    if (input.originUnresolvedInstallationIds !== undefined) {
      this.notificationOriginCleanup.set(
        input.deletionKeyHash,
        structuredClone(input.originUnresolvedInstallationIds),
      );
      this.notificationOwners.set(input.deletionKeyHash, null);
    }
    this.authRepository.deletionOwners.delete(input.ownerId);
    for (const subjectHash of this.authRepository.deletionSubjects) {
      if (input.deleteOwnerData || !this.authRepository.links.has(subjectHash)) {
        this.authRepository.deletionSubjects.delete(subjectHash);
      }
    }
    const winningSummary = existing.providerCredentials;
    const winningOriginSummary = existing.originConnections;
    if (winningSummary === null || winningOriginSummary === null) throw new Error('deletion receipt completion failed');
    return {created, providerCredentials: structuredClone(winningSummary),originConnections:structuredClone(winningOriginSummary)};
  }

  private assertAttemptMatches(
    stored: {
      ownerBinding: string;
      ownerId: string;
      appleSubjectHash: string;
      deleteOwnerData: boolean;
    },
    input: {
      ownerBinding: string;
      ownerId: string;
      appleSubjectHash: string;
      deleteOwnerData: boolean;
    },
  ): void {
    if (
      stored.ownerBinding !== input.ownerBinding ||
      stored.ownerId !== input.ownerId ||
      stored.appleSubjectHash !== input.appleSubjectHash ||
      stored.deleteOwnerData !== input.deleteOwnerData
    ) {
      throw new AppleAuthError(
        409,
        'APPLE_ACCOUNT_DELETION_KEY_CONFLICT',
        'This account deletion key belongs to a different Apple identity.',
      );
    }
  }

  async beginServerNotification(
    notification: VerifiedAppleServerNotification,
  ): Promise<{idempotent: boolean; ownerId: string | null}> {
    const existing = this.notifications.get(notification.notificationIdHash);
    if (existing !== undefined) {
      if (JSON.stringify(existing) !== JSON.stringify(notification)) {
        throw new AppleAuthError(
          409,
          'APPLE_NOTIFICATION_REPLAY_CONFLICT',
          'The Apple notification identifier was reused with different event data.',
        );
      }
      return {
        idempotent: true,
        ownerId: this.notificationOwners.get(notification.notificationIdHash) ?? null,
      };
    }
    const ownerId = notification.appleSubjectHash === null
      ? null
      : notification.eventTime !== null
        && (this.authRepository.principalCreatedAt.get(notification.appleSubjectHash) ?? 1)
          > notification.eventTime
        ? null
        : this.authRepository.links.get(notification.appleSubjectHash) ?? null;
    this.notifications.set(notification.notificationIdHash, structuredClone(notification));
    this.notificationOwners.set(notification.notificationIdHash, ownerId);
    if (notification.kind === 'email-enabled' || notification.kind === 'email-disabled') {
      const current = this.emailForwarding.get(notification.appleSubjectHash);
      if (current === undefined || current.eventTime <= notification.eventTime) {
        this.emailForwarding.set(notification.appleSubjectHash, {
          enabled: notification.kind === 'email-enabled',
          eventTime: notification.eventTime,
        });
      }
    }
    if (
      ownerId !== null
      && (notification.kind === 'consent-revoked' || notification.kind === 'account-deleted')
    ) {
      const deleteOwnerData = ownerId.startsWith('apple-owner:v1.');
      if (!this.deletionReceipts.has(notification.notificationIdHash)) {
        this.deletionReceipts.set(notification.notificationIdHash, {
          ownerBinding: notification.notificationIdHash,
          ownerId,
          appleSubjectHash: notification.appleSubjectHash,
          applePrincipalId: this.authRepository.principalIds.get(notification.appleSubjectHash)
            ?? notification.appleSubjectHash,
          deleteOwnerData,
          providerCredentials: null,
          originConnections: null,
          completedAt: null,
          completionFenceToken: null,
          revocationLeaseToken: null,
          revocationLeaseUntil: null,
          expiresAt: notification.receiptExpiresAt,
        });
      }
      if (deleteOwnerData) this.authRepository.deletionOwners.add(ownerId);
      else this.authRepository.deletionSubjects.add(notification.appleSubjectHash);
    }
    return {idempotent: false, ownerId};
  }

  private sameDeletionScope(
    stored: {
      ownerId: string;
      appleSubjectHash: string;
      applePrincipalId: string;
      deleteOwnerData: boolean;
    },
    input: {ownerId: string; appleSubjectHash: string; deleteOwnerData: boolean},
  ): boolean {
    const principalId = this.authRepository.principalIds.get(input.appleSubjectHash)
      ?? input.appleSubjectHash;
    return stored.ownerId === input.ownerId
      && stored.deleteOwnerData === input.deleteOwnerData
      && (input.deleteOwnerData || stored.applePrincipalId === principalId);
  }
}

type Fixture = {
  dependencies: AppleAuthDependencies;
  repository: MemoryAppleAuthRepository;
  setNow(value: number): void;
  setActiveNonce(value: string): void;
  setActiveSubject(value: string): void;
  setActiveTransferSubject(value: string | null): void;
  setActiveRefreshToken(value: string): void;
  setRevokeFailure(value: boolean): void;
  requests: {url: string; form: URLSearchParams | null}[];
  seedLegacySession(input: {
    sessionToken: string;
    ownerId: string;
    subject: string;
    displayName: string | null;
  }): Promise<AppleAuthSessionRecord>;
  signIdentityToken(claims: Record<string, unknown>): Promise<string>;
  clientSecretPublicKey: CryptoKey;
};

async function createFixture(): Promise<Fixture> {
  const clientKeys = await crypto.subtle.generateKey(
    {name: 'ECDSA', namedCurve: 'P-256'},
    true,
    ['sign', 'verify'],
  );
  const appleKeys = await crypto.subtle.generateKey(
    {name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256'},
    true,
    ['sign', 'verify'],
  );
  const privateKeyPem = pemFromPKCS8(await crypto.subtle.exportKey('pkcs8', clientKeys.privateKey));
  const storageBytes = Uint8Array.from({length: 32}, (_, index) => index + 1);
  const configuration = parseAppleAuthConfiguration({
    APPLE_AUTH_TEAM_ID: TEAM_ID,
    APPLE_AUTH_KEY_ID: APPLE_KEY_ID,
    APPLE_AUTH_CLIENT_ID: CLIENT_ID,
    APPLE_AUTH_REDIRECT_URI: 'https://sandbox.example.test/api/auth/apple/callback',
    APPLE_AUTH_PRIVATE_KEY_P8: privateKeyPem,
    APPLE_AUTH_STORAGE_KEY: base64URL(storageBytes),
  });
  const repository = new MemoryAppleAuthRepository();
  const requests: {url: string; form: URLSearchParams | null}[] = [];
  let now = INITIAL_TIME;
  let activeNonce = '';
  let activeSubject = '001234.fixture-user';
  let activeTransferSubject: string | null = null;
  let activeRefreshToken = 'stored-refresh-token';
  let revokeFailure = false;

  const signIdentityToken = async (claims: Record<string, unknown>): Promise<string> => {
    const header = base64URL(new TextEncoder().encode(JSON.stringify({alg: 'RS256', kid: APPLE_KEY_ID})));
    const payload = base64URL(new TextEncoder().encode(JSON.stringify(claims)));
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      appleKeys.privateKey,
      new TextEncoder().encode(`${header}.${payload}`),
    );
    return `${header}.${payload}.${base64URL(new Uint8Array(signature))}`;
  };

  const validClaims = (): Record<string, unknown> => ({
    iss: 'https://appleid.apple.com',
    aud: CLIENT_ID,
    exp: now + 3_600,
    iat: now,
    sub: activeSubject,
    nonce: activeNonce,
    email: 'relay@example.test',
    email_verified: 'true',
    ...(activeTransferSubject === null ? {} : {transfer_sub: activeTransferSubject}),
  });
  const applePublicKey = await crypto.subtle.exportKey('jwk', appleKeys.publicKey);
  const fetcher = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = input instanceof Request ? input.url : input.toString();
    const form = init?.body instanceof URLSearchParams ? new URLSearchParams(init.body) : null;
    requests.push({url, form});
    if (url.endsWith('/auth/keys')) {
      return Response.json({keys: [{...applePublicKey, alg: 'RS256', use: 'sig', kid: APPLE_KEY_ID}]});
    }
    if (url.endsWith('/auth/token')) {
      const grantType = form?.get('grant_type');
      const claims = validClaims();
      if (grantType === 'refresh_token') delete claims.nonce;
      const response: Record<string, unknown> = {
        access_token: grantType === 'refresh_token' ? 'refreshed-access-token' : 'initial-access-token',
        expires_in: 3_600,
        id_token: await signIdentityToken(claims),
        token_type: 'Bearer',
      };
      if (grantType === 'authorization_code') response.refresh_token = activeRefreshToken;
      return Response.json(response);
    }
    if (url.endsWith('/auth/revoke')) return new Response(null, {status: revokeFailure ? 503 : 200});
    return new Response(null, {status: 404});
  };
  const dependencies: AppleAuthDependencies = {
    configuration,
    repository,
    fetcher,
    crypto,
    now: () => now,
    revocationTimeoutMilliseconds: APPLE_REVOCATION_TIMEOUT_MILLISECONDS,
  };
  const seedLegacySession = async (input: {
    sessionToken: string;
    ownerId: string;
    subject: string;
    displayName: string | null;
  }): Promise<AppleAuthSessionRecord> => {
    const sessionHash = await hashAppleOpaqueToken(input.sessionToken, crypto);
    const appleSubjectHash = await hashAppleSubject(input.subject, dependencies);
    const ownerKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(storageBytes),
      {name: 'HMAC', hash: 'SHA-256'},
      false,
      ['sign'],
    );
    const ownerBinding = base64URL(new Uint8Array(await crypto.subtle.sign(
      'HMAC',
      ownerKey,
      new TextEncoder().encode(`owner\0${input.ownerId}`),
    )));
    const encryptionKey = await crypto.subtle.importKey(
      'raw',
      toArrayBuffer(storageBytes),
      'AES-GCM',
      false,
      ['encrypt'],
    );
    const iv = Uint8Array.from({length: 12}, (_, index) => index + 11);
    const plaintext = new TextEncoder().encode(JSON.stringify({
      recordType: 'apple-auth-credentials',
      schemaVersion: 1,
      subject: input.subject,
      email: 'legacy-relay@example.test',
      emailVerified: true,
      displayName: input.displayName,
      refreshToken: 'legacy-refresh-token',
      accessToken: 'legacy-access-token',
      accessTokenExpiresAt: INITIAL_TIME + 3_600,
    }));
    const encrypted = await crypto.subtle.encrypt(
      {name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(`apple-session-v1\0${sessionHash}`)},
      encryptionKey,
      plaintext,
    );
    const record: AppleAuthSessionRecord = {
      schemaVersion: 1,
      sessionHash,
      ownerId: input.ownerId,
      ownerBinding,
      appleSubjectHash,
      encryptedCredentials: `v1.${base64URL(iv)}.${base64URL(new Uint8Array(encrypted))}`,
      createdAt: INITIAL_TIME,
      expiresAt: INITIAL_TIME + 3_600,
      lastValidatedAt: INITIAL_TIME,
    };
    repository.links.set(appleSubjectHash, input.ownerId);
    repository.sessions.set(sessionHash, structuredClone(record));
    return record;
  };

  return {
    dependencies,
    repository,
    setNow(value) { now = value; },
    setActiveNonce(value) { activeNonce = value; },
    setActiveSubject(value) { activeSubject = value; },
    setActiveTransferSubject(value) { activeTransferSubject = value; },
    setActiveRefreshToken(value) { activeRefreshToken = value; },
    setRevokeFailure(value) { revokeFailure = value; },
    requests,
    seedLegacySession,
    signIdentityToken,
    clientSecretPublicKey: clientKeys.publicKey,
  };
}

async function authorizeFixture(input: {
  fixture: Fixture;
  subject: string;
  intent: {purpose: 'authenticate'} | {purpose: 'link'; ownerId: string};
  ambientHostOwnerId: string | null;
  user?: {name: {firstName: string; lastName: string}; email: string} | null;
  transferSubject?: string | null;
}) {
  const {fixture, subject, intent, ambientHostOwnerId} = input;
  const start = await startAppleAuthorization(fixture.dependencies, intent, '/');
  const authorizationUrl = new URL(start.authorizationUrl);
  const nonce = authorizationUrl.searchParams.get('nonce');
  const state = authorizationUrl.searchParams.get('state');
  assert.ok(nonce);
  assert.ok(state);
  fixture.setActiveNonce(nonce);
  fixture.setActiveSubject(subject);
  fixture.setActiveTransferSubject(input.transferSubject ?? null);
  const idToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: subject, nonce,
    email: 'relay@example.test', email_verified: true,
    ...(input.transferSubject === undefined || input.transferSubject === null
      ? {}
      : {transfer_sub: input.transferSubject}),
  });
  const completion = await completeAppleAuthorization(
    fixture.dependencies,
    {kind: 'success', state, code: `code-${subject}`, idToken, user: input.user ?? null},
    start.browserBinding,
    ambientHostOwnerId,
  );
  assert.equal(completion.kind, 'authenticated');
  if (completion.kind !== 'authenticated') throw new Error('Expected an authenticated completion.');
  return completion;
}

test('configuration fails closed for missing secrets, localhost, IP redirects, and weak storage keys', async () => {
  assert.throws(() => parseAppleAuthConfiguration({}), matchesCode('APPLE_AUTH_NOT_CONFIGURED'));
  const fixture = await createFixture();
  const valid = fixture.dependencies.configuration;
  const environment = {
    APPLE_AUTH_TEAM_ID: valid.teamId,
    APPLE_AUTH_KEY_ID: valid.keyId,
    APPLE_AUTH_CLIENT_ID: valid.clientId,
    APPLE_AUTH_PRIVATE_KEY_P8: valid.privateKeyPem,
    APPLE_AUTH_STORAGE_KEY: valid.storageKey,
  };
  assert.throws(
    () => parseAppleAuthConfiguration({...environment, APPLE_AUTH_REDIRECT_URI: 'http://localhost/callback'}),
    matchesCode('APPLE_AUTH_NOT_CONFIGURED'),
  );
  assert.throws(
    () => parseAppleAuthConfiguration({...environment, APPLE_AUTH_REDIRECT_URI: 'https://127.0.0.1/callback'}),
    matchesCode('APPLE_AUTH_NOT_CONFIGURED'),
  );
  assert.throws(
    () => parseAppleAuthConfiguration({...environment, APPLE_AUTH_REDIRECT_URI: 'https://valid.test/callback', APPLE_AUTH_STORAGE_KEY: 'short'}),
    matchesCode('APPLE_AUTH_NOT_CONFIGURED'),
  );
});

test('authorization start stores only hashes and produces a scoped form_post request', async () => {
  const fixture = await createFixture();
  const start = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-a'}, '//evil.test/steal');
  const url = new URL(start.authorizationUrl);
  assert.equal(url.origin, 'https://appleid.apple.com');
  assert.equal(url.pathname, '/auth/authorize');
  assert.equal(url.searchParams.get('client_id'), CLIENT_ID);
  assert.equal(url.searchParams.get('redirect_uri'), fixture.dependencies.configuration.redirectUri);
  assert.equal(url.searchParams.get('response_type'), 'code id_token');
  assert.equal(url.searchParams.get('response_mode'), 'form_post');
  assert.equal(url.searchParams.get('scope'), 'name email');
  assert.match(url.searchParams.get('state') ?? '', /^v1\.[A-Za-z0-9_-]{43}$/);
  assert.match(url.searchParams.get('nonce') ?? '', /^v1\.[A-Za-z0-9_-]{43}$/);
  const stored = JSON.stringify([...fixture.repository.flows.values()]);
  assert.equal(stored.includes(url.searchParams.get('state') ?? 'missing'), false);
  assert.equal(stored.includes(url.searchParams.get('nonce') ?? 'missing'), false);
  assert.equal(stored.includes(start.browserBinding), false);
  assert.equal([...fixture.repository.flows.values()][0].returnTo, '/');
});

test('standalone Apple authentication creates one random stable owner without email matching', async () => {
  const fixture = await createFixture();
  const first = await authorizeFixture({
    fixture,
    subject: 'apple-subject-a',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
    user: {name: {firstName: 'Ada', lastName: 'Lovelace'}, email: 'relay@example.test'},
  });
  assert.match(first.identity.userId, /^apple-owner:v1\.[A-Za-z0-9_-]{43}$/);
  const second = await authorizeFixture({
    fixture,
    subject: 'apple-subject-a',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  });
  assert.equal(second.identity.userId, first.identity.userId);
  assert.equal(second.identity.displayName, 'Ada Lovelace');

  const differentSubject = await authorizeFixture({
    fixture,
    subject: 'apple-subject-b',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
    user: {name: {firstName: 'Ada', lastName: 'Lovelace'}, email: 'relay@example.test'},
  });
  assert.notEqual(differentSubject.identity.userId, first.identity.userId);
  assert.equal(fixture.repository.links.size, 2);
  const serialized = JSON.stringify({flows: [...fixture.repository.flows.values()], sessions: [...fixture.repository.sessions.values()], links: [...fixture.repository.links.entries()]});
  for (const secret of ['apple-subject-a', 'apple-subject-b', 'stored-refresh-token', 'initial-access-token']) {
    assert.equal(serialized.includes(secret), false, secret);
  }
});

test('unreadable prior credentials cannot block a fresh sign-in used only to recover a display name', async () => {
  const fixture = await createFixture();
  const ownerId = `apple-owner:v1.${'C'.repeat(43)}`;
  const prior = await fixture.seedLegacySession({
    sessionToken: `v1.${'P'.repeat(43)}`,
    ownerId,
    subject: 'corrupt-prior-session-subject',
    displayName: 'Previous Name',
  });
  fixture.repository.sessions.set(prior.sessionHash, {
    ...prior,
    schemaVersion: 2,
    encryptedCredentials: 'malformed-current-ciphertext',
  });

  const completion = await authorizeFixture({
    fixture,
    subject: 'corrupt-prior-session-subject',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  });

  assert.equal(completion.identity.userId, ownerId);
  assert.equal(completion.identity.displayName, null);
});

test('retention removes an expired malformed session and abandoned flow before fresh sign-in', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const fixture = await createFixture();
    fixture.dependencies.repository = createD1AppleAuthRepository(database);
    const subject = 'expired-malformed-session-subject';
    const appleSubjectHash = await hashAppleSubject(subject, fixture.dependencies);
    const ownerId = `apple-owner:v1.${'E'.repeat(43)}`;
    await database.batch([
      database.prepare(
        `INSERT INTO apple_identity_links(
          apple_subject_hash,owner_id,created_at,updated_at
        ) VALUES(?,?,?,?)`,
      ).bind(appleSubjectHash, ownerId, INITIAL_TIME - 10, INITIAL_TIME - 10),
      database.prepare(
        `INSERT INTO apple_auth_flows(
          schema_version,state_hash,purpose,owner_id,nonce_hash,browser_binding_hash,
          owner_binding,return_to,created_at,expires_at,consumed_at
        ) VALUES(2,?,'authenticate',NULL,?,?,?,'/',?,?,NULL)`,
      ).bind(
        'F'.repeat(43),
        'N'.repeat(43),
        'B'.repeat(43),
        'O'.repeat(43),
        INITIAL_TIME - 10,
        INITIAL_TIME - 1,
      ),
      database.prepare(
        `INSERT INTO apple_auth_sessions(
          schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
          encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
        ) VALUES(2,?,?,?,?,?,?,?,?,NULL)`,
      ).bind(
        'S'.repeat(43),
        ownerId,
        'V'.repeat(43),
        appleSubjectHash,
        'malformed-expired-ciphertext',
        INITIAL_TIME - 10,
        INITIAL_TIME - 1,
        INITIAL_TIME - 10,
      ),
    ]);

    assert.deepEqual(
      await drainExpiredAppleAuthLifecycleRecords(database, INITIAL_TIME),
      {
        batches: 1,
        flows: 1,
        sessions: 1,
        nativeSessions: 0,
        authorizationCodeClaims: 0,
        deletions: 0,
        notifications: 0,
        externalOperationLeases: 0,
      },
    );
    assert.deepEqual(
      await database.prepare(
        `SELECT
          (SELECT COUNT(*) FROM apple_auth_flows) AS flows,
          (SELECT COUNT(*) FROM apple_auth_sessions) AS sessions`,
      ).first(),
      {flows: 0, sessions: 0},
    );

    const completion = await authorizeFixture({
      fixture,
      subject,
      intent: {purpose: 'authenticate'},
      ambientHostOwnerId: null,
    });
    assert.equal(completion.identity.userId, ownerId);
    assert.equal(completion.identity.displayName, null);
    const freshSessionCount = await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_auth_sessions WHERE owner_id=? AND expires_at>?',
    ).bind(ownerId, INITIAL_TIME).first() as {count: number} | null;
    assert.equal(
      freshSessionCount?.count,
      1,
    );
  } finally {
    await miniflare.dispose();
  }
});

test('verified transfer_sub preserves an imported owner and mismatches fail closed', async () => {
  const fixture = await createFixture();
  const transferSubject = 'transfer-subject-from-sending-team';
  const transferHash = await hashAppleSubject(transferSubject, fixture.dependencies);
  fixture.repository.links.set(transferHash, 'imported-owner');
  const completion = await authorizeFixture({
    fixture,
    subject: 'recipient-team-subject',
    transferSubject,
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  });
  assert.equal(completion.identity.userId, 'imported-owner');
  assert.equal(
    fixture.repository.links.get(await hashAppleSubject('recipient-team-subject', fixture.dependencies)),
    'imported-owner',
  );
  assert.equal(fixture.repository.links.get(transferHash), 'imported-owner');

  const start = await startAppleAuthorization(fixture.dependencies, {purpose: 'authenticate'}, '/');
  const url = new URL(start.authorizationUrl);
  const nonce = url.searchParams.get('nonce');
  const state = url.searchParams.get('state');
  assert.ok(nonce);
  assert.ok(state);
  fixture.setActiveNonce(nonce);
  fixture.setActiveSubject('mismatched-transfer-subject');
  fixture.setActiveTransferSubject('exchange-transfer-subject');
  const callbackToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: 'mismatched-transfer-subject', nonce,
    transfer_sub: 'callback-transfer-subject',
  });
  await assert.rejects(
    () => completeAppleAuthorization(
      fixture.dependencies,
      {kind: 'success', state, code: 'transfer-code', idToken: callbackToken, user: null},
      start.browserBinding,
      null,
    ),
    matchesCode('APPLE_TOKEN_TRANSFER_MISMATCH'),
  );
});

test('authorization start JSON is strict, bounded, and sanitizes return paths', async () => {
  const parsed = await parseAppleAuthorizationStartRequest(jsonRequest({purpose: 'authenticate', returnTo: '/settings?tab=account'}));
  assert.deepEqual(parsed, {intent: {purpose: 'authenticate'}, returnTo: '/settings?tab=account'});
  assert.deepEqual(
    await parseAppleAuthorizationStartRequest(jsonRequest({purpose: 'link', returnTo: '//evil.test/steal'})),
    {intent: {purpose: 'link'}, returnTo: '/'},
  );
  await assert.rejects(
    () => parseAppleAuthorizationStartRequest(jsonRequest({purpose: 'authenticate', ownerId: 'forged'})),
    matchesCode('APPLE_AUTH_START_INVALID'),
  );
  await assert.rejects(
    () => parseAppleAuthorizationStartRequest(new Request('https://sandbox.example.test/api/auth/apple/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'Content-Length': 'nope'},
      body: '{}',
    })),
    matchesCode('APPLE_AUTH_START_CONTENT_LENGTH'),
  );
});

test('client secret has Apple claims and a valid ES256 signature', async () => {
  const fixture = await createFixture();
  const token = await createAppleClientSecret(fixture.dependencies);
  const [headerSegment, payloadSegment, signatureSegment] = token.split('.');
  assert.deepEqual(JSON.parse(decodeText(headerSegment)), {alg: 'ES256', kid: APPLE_KEY_ID});
  assert.deepEqual(JSON.parse(decodeText(payloadSegment)), {
    iss: TEAM_ID,
    iat: INITIAL_TIME,
    exp: INITIAL_TIME + 300,
    aud: 'https://appleid.apple.com',
    sub: CLIENT_ID,
  });
  assert.equal(await crypto.subtle.verify(
    {name: 'ECDSA', hash: 'SHA-256'},
    fixture.clientSecretPublicKey,
    toArrayBuffer(base64URLDecode(signatureSegment)),
    new TextEncoder().encode(`${headerSegment}.${payloadSegment}`),
  ), true);
});

test('callback parser accepts Apple form_post and rejects duplicate or non-form fields', async () => {
  const user = JSON.stringify({name: {firstName: 'Ada', lastName: 'Lovelace'}, email: 'relay@example.test'});
  const request = formRequest(new URLSearchParams({state: 'v1.' + 's'.repeat(43), code: 'code', id_token: 'x'.repeat(20), user}));
  const parsed = await parseAppleAuthorizationCallback(request);
  assert.equal(parsed.kind, 'success');
  if (parsed.kind === 'success') assert.equal(parsed.user?.name.firstName, 'Ada');
  await assert.rejects(
    () => parseAppleAuthorizationCallback(formRequest('state=a&state=b&error=user_cancelled_authorize')),
    matchesCode('APPLE_CALLBACK_INVALID'),
  );
  await assert.rejects(
    () => parseAppleAuthorizationCallback(formRequest(`state=${'s'.repeat(43)}&error=user_cancelled_authorize&code=mixed`)),
    matchesCode('APPLE_CALLBACK_INVALID'),
  );
  await assert.rejects(
    () => parseAppleAuthorizationCallback(new Request('https://sandbox.example.test/callback', {method: 'POST', body: '{}', headers: {'Content-Type': 'application/json'}})),
    matchesCode('APPLE_CALLBACK_CONTENT_TYPE'),
  );
  await assert.rejects(
    () => parseAppleAuthorizationCallback(new Request('https://sandbox.example.test/callback', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': 'invalid'},
      body: 'state=value',
    })),
    matchesCode('APPLE_CALLBACK_CONTENT_LENGTH'),
  );
  const stream = new ReadableStream<Uint8Array>({
    pull(controller) { controller.enqueue(new Uint8Array(8_000)); },
  });
  const streamInit: RequestInit & {duplex: 'half'} = {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body: stream,
    duplex: 'half',
  };
  await assert.rejects(
    () => parseAppleAuthorizationCallback(new Request('https://sandbox.example.test/callback', streamInit)),
    matchesCode('APPLE_CALLBACK_TOO_LARGE'),
  );
});

test('server notification parser is strict, bounded, and requires Apple JSON envelope', async () => {
  const payload = 'x'.repeat(20);
  assert.equal(
    await parseAppleServerNotificationRequest(notificationRequest({payload})),
    payload,
  );
  await assert.rejects(
    () => parseAppleServerNotificationRequest(notificationRequest({payload, extra: true})),
    matchesCode('APPLE_NOTIFICATION_INVALID'),
  );
  await assert.rejects(
    () => parseAppleServerNotificationRequest(new Request(
      'https://sandbox.example.test/api/auth/apple/notifications',
      {method: 'POST', headers: {'Content-Type': 'text/plain'}, body: payload},
    )),
    matchesCode('APPLE_NOTIFICATION_CONTENT_TYPE'),
  );
  await assert.rejects(
    () => parseAppleServerNotificationRequest(new Request(
      'https://sandbox.example.test/api/auth/apple/notifications',
      {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'Content-Length': '32001'},
        body: '{}',
      },
    )),
    matchesCode('APPLE_NOTIFICATION_TOO_LARGE'),
  );
});

test('signed Apple notifications enforce claims and apply four official events idempotently', async () => {
  const fixture = await createFixture();
  const lifecycle = new MemoryAppleAccountDeletionRepository(fixture.repository);
  const subject = 'notification-subject';
  const subjectHash = await hashAppleSubject(subject, fixture.dependencies);
  fixture.repository.links.set(subjectHash, 'host-owner');
  lifecycle.ownerData.add('host-owner');

  const emailDisabledToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, iat: INITIAL_TIME,
    jti: 'notification-email-disabled',
    events: {
      type: 'email-disabled', sub: subject, email: 'relay@example.test',
      is_private_email: 'true', event_time: INITIAL_TIME,
    },
  });
  const verified = await verifyAppleServerNotification(emailDisabledToken, fixture.dependencies);
  assert.equal(verified.kind, 'email-disabled');
  assert.equal(verified.appleSubjectHash, subjectHash);
  assert.equal(JSON.stringify(verified).includes(subject), false);
  assert.equal(JSON.stringify(verified).includes('notification-email-disabled'), false);
  assert.deepEqual(
    await processAppleServerNotification({
      repository: lifecycle,
      authDependencies: fixture.dependencies,
      token: emailDisabledToken,
    }),
    {received: true, idempotent: false, eventType: 'email-disabled'},
  );
  assert.deepEqual(lifecycle.emailForwarding.get(subjectHash), {
    enabled: false,
    eventTime: INITIAL_TIME,
  });
  assert.equal((await processAppleServerNotification({
    repository: lifecycle,
    authDependencies: fixture.dependencies,
    token: emailDisabledToken,
  })).idempotent, true);

  const emailEnabledToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, iat: INITIAL_TIME + 1,
    jti: 'notification-email-enabled',
    events: {
      type: 'email-enabled', sub: subject, email: 'relay@example.test',
      is_private_email: true, event_time: INITIAL_TIME + 1,
    },
  });
  fixture.setNow(INITIAL_TIME + 1);
  await processAppleServerNotification({
    repository: lifecycle,
    authDependencies: fixture.dependencies,
    token: emailEnabledToken,
  });
  assert.deepEqual(lifecycle.emailForwarding.get(subjectHash), {
    enabled: true,
    eventTime: INITIAL_TIME + 1,
  });

  const consentToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, iat: INITIAL_TIME + 1,
    jti: 'notification-consent-revoked',
    events: {type: 'consent-revoked', sub: subject, event_time: INITIAL_TIME + 1},
  });
  await processAppleServerNotification({
    repository: lifecycle,
    authDependencies: fixture.dependencies,
    token: consentToken,
  });
  assert.equal(fixture.repository.links.has(subjectHash), false);
  assert.equal(lifecycle.ownerData.has('host-owner'), true);

  const appleOwner = `apple-owner:v1.${'O'.repeat(43)}`;
  const deletedSubject = 'deleted-apple-owner-subject';
  const deletedSubjectHash = await hashAppleSubject(deletedSubject, fixture.dependencies);
  fixture.repository.links.set(deletedSubjectHash, appleOwner);
  lifecycle.ownerData.add(appleOwner);
  const accountDeletedToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, iat: INITIAL_TIME + 1,
    jti: 'notification-account-deleted',
    events: {type: 'account-deleted', sub: deletedSubject, event_time: INITIAL_TIME + 1},
  });
  await processAppleServerNotification({
    repository: lifecycle,
    authDependencies: fixture.dependencies,
    token: accountDeletedToken,
  });
  assert.equal(lifecycle.ownerData.has(appleOwner), false);
  assert.equal(fixture.repository.links.has(deletedSubjectHash), false);
});

test('destructive Apple notifications bound Origin cleanup and replay exact outcomes', async () => {
  const fixture = await createFixture();
  const lifecycle = new MemoryAppleAccountDeletionRepository(fixture.repository);
  const successOwner = `apple-owner:v1.${'S'.repeat(43)}`;
  const successSubject = 's'.repeat(43);
  const successInstallations = ['inst_notificationsuccess01', 'inst_notificationsuccess02'];
  fixture.repository.links.set(successSubject, successOwner);
  lifecycle.ownerData.add(successOwner);
  lifecycle.originInstallations.set(successOwner, successInstallations);
  const successNotification: VerifiedAppleServerNotification = {
    kind: 'account-deleted',
    notificationIdHash: 'N'.repeat(43),
    appleSubjectHash: successSubject,
    issuedAt: INITIAL_TIME,
    eventTime: INITIAL_TIME,
    receiptExpiresAt: INITIAL_TIME + 600,
  };
  const revoked: string[] = [];
  const originDependencies = {
    async revokeInstallation(installationId: string): Promise<void> {
      revoked.push(installationId);
    },
  };
  assert.deepEqual(await applyVerifiedAppleServerNotification({
    repository: lifecycle,
    notification: successNotification,
    crypto: globalThis.crypto,
    now: INITIAL_TIME,
    originDependencies,
  }), {idempotent: false});
  assert.deepEqual(revoked.sort(), successInstallations);
  assert.deepEqual(
    (await lifecycle.readDeletionReceipt(successNotification.notificationIdHash, INITIAL_TIME + 1))
      ?.originConnections,
    {
      installationsFound: 2,
      installationsRevoked: 2,
      unreadableInstallations: 0,
      failedRevocations: 0,
      manualRevocationRequired: false,
    },
  );
  assert.deepEqual(await applyVerifiedAppleServerNotification({
    repository: lifecycle,
    notification: successNotification,
    crypto: globalThis.crypto,
    now: INITIAL_TIME + 1,
    originDependencies,
  }), {idempotent: true});
  assert.equal(revoked.length, 2);

  const unconfiguredOwner = `apple-owner:v1.${'U'.repeat(43)}`;
  const unconfiguredSubject = 'u'.repeat(43);
  const unconfiguredInstallation = 'inst_notificationmanual01';
  fixture.repository.links.set(unconfiguredSubject, unconfiguredOwner);
  lifecycle.ownerData.add(unconfiguredOwner);
  lifecycle.originInstallations.set(unconfiguredOwner, [unconfiguredInstallation]);
  const unconfiguredNotification: VerifiedAppleServerNotification = {
    kind: 'consent-revoked',
    notificationIdHash: 'M'.repeat(43),
    appleSubjectHash: unconfiguredSubject,
    issuedAt: INITIAL_TIME + 2,
    eventTime: INITIAL_TIME + 2,
    receiptExpiresAt: INITIAL_TIME + 602,
  };
  await applyVerifiedAppleServerNotification({
    repository: lifecycle,
    notification: unconfiguredNotification,
    crypto: globalThis.crypto,
    now: INITIAL_TIME + 2,
    originDependencies: null,
  });
  assert.deepEqual(
    (await lifecycle.readDeletionReceipt(
      unconfiguredNotification.notificationIdHash,
      INITIAL_TIME + 3,
    ))?.originConnections,
    {
      installationsFound: 1,
      installationsRevoked: 0,
      unreadableInstallations: 0,
      failedRevocations: 1,
      manualRevocationRequired: true,
    },
  );
  assert.deepEqual(
    lifecycle.notificationOriginCleanup.get(unconfiguredNotification.notificationIdHash),
    [unconfiguredInstallation],
  );
});

test('a destructive Apple notification gates access before external Origin cleanup settles', async () => {
  const fixture = await createFixture();
  const lifecycle = new MemoryAppleAccountDeletionRepository(fixture.repository);
  const ownerId = `apple-owner:v1.${'G'.repeat(43)}`;
  const subjectHash = 'g'.repeat(43);
  fixture.repository.links.set(subjectHash, ownerId);
  lifecycle.ownerData.add(ownerId);
  lifecycle.originInstallations.set(ownerId, ['inst_notificationpending01']);
  let releaseCleanup: () => void = () => {};
  let markCleanupStarted: () => void = () => {};
  const cleanupStarted = new Promise<void>(resolve => { markCleanupStarted = resolve; });
  const cleanupReleased = new Promise<void>(resolve => { releaseCleanup = resolve; });
  const notification: VerifiedAppleServerNotification = {
    kind: 'account-deleted',
    notificationIdHash: 'G'.repeat(43),
    appleSubjectHash: subjectHash,
    issuedAt: INITIAL_TIME,
    eventTime: INITIAL_TIME,
    receiptExpiresAt: INITIAL_TIME + 600,
  };
  const processing = applyVerifiedAppleServerNotification({
    repository: lifecycle,
    notification,
    crypto: globalThis.crypto,
    now: INITIAL_TIME,
    originDependencies: {
      async revokeInstallation() {
        markCleanupStarted();
        await cleanupReleased;
      },
    },
  });
  await cleanupStarted;
  assert.equal(fixture.repository.deletionBlocked(ownerId, subjectHash), true);
  assert.equal(lifecycle.ownerData.has(ownerId), true);
  await assert.rejects(
    fixture.repository.linkAppleIdentity({
      appleSubjectHash: subjectHash,
      ownerId,
      createdAt: INITIAL_TIME + 1,
      updatedAt: INITIAL_TIME + 1,
    }),
    matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
  );
  releaseCleanup();
  await processing;
  assert.equal(lifecycle.ownerData.has(ownerId), false);
});

test('notification verification rejects bad signature, issuer, audience, expiry, and event time', async () => {
  const fixture = await createFixture();
  const validClaims = {
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, iat: INITIAL_TIME,
    jti: 'notification-claims',
    events: {type: 'consent-revoked', sub: 'claims-subject', event_time: INITIAL_TIME},
  };
  const valid = await fixture.signIdentityToken(validClaims);
  const segments = valid.split('.');
  const tamperedSignature = `${segments[0]}.${segments[1]}.${segments[2][0] === 'A' ? 'B' : 'A'}${segments[2].slice(1)}`;
  await assert.rejects(
    () => verifyAppleServerNotification(tamperedSignature, fixture.dependencies),
    matchesCode('APPLE_NOTIFICATION_SIGNATURE'),
  );
  for (const claims of [
    {...validClaims, iss: 'https://attacker.example'},
    {...validClaims, aud: 'attacker-client'},
    {...validClaims, iat: INITIAL_TIME - 24 * 60 * 60 - 1},
    {...validClaims, iat: INITIAL_TIME + 61},
    {...validClaims, exp: INITIAL_TIME - 61},
    {...validClaims, events: {...validClaims.events, event_time: INITIAL_TIME - 24 * 60 * 60 - 1}},
  ]) {
    await assert.rejects(
      () => fixture.signIdentityToken(claims).then(token =>
        verifyAppleServerNotification(token, fixture.dependencies)),
      matchesCode('APPLE_NOTIFICATION_CLAIMS'),
    );
  }
  const malformedKnown = await fixture.signIdentityToken({
    ...validClaims,
    events: {type: 'email-enabled', sub: 'claims-subject', event_time: INITIAL_TIME},
  });
  await assert.rejects(
    () => verifyAppleServerNotification(malformedKnown, fixture.dependencies),
    matchesCode('APPLE_NOTIFICATION_INVALID'),
  );
});

test('unknown signed notification events are recorded without destructive state changes', async () => {
  const fixture = await createFixture();
  const lifecycle = new MemoryAppleAccountDeletionRepository(fixture.repository);
  lifecycle.ownerData.add('owner-safe');
  const token = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, iat: INITIAL_TIME,
    jti: 'future-notification-event',
    events: {type: 'future-event', sub: 'future-subject', event_time: INITIAL_TIME},
  });
  assert.deepEqual(await processAppleServerNotification({
    repository: lifecycle,
    authDependencies: fixture.dependencies,
    token,
  }), {received: true, idempotent: false, eventType: 'future-event'});
  assert.deepEqual([...lifecycle.ownerData], ['owner-safe']);
  assert.equal(lifecycle.notifications.size, 1);
});

test('code exchange verifies both Apple tokens and creates an encrypted, owner-bound session', async () => {
  const fixture = await createFixture();
  const start = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-a'}, '/settings?tab=account');
  const authorizationUrl = new URL(start.authorizationUrl);
  const nonce = authorizationUrl.searchParams.get('nonce');
  const state = authorizationUrl.searchParams.get('state');
  assert.ok(nonce);
  assert.ok(state);
  fixture.setActiveNonce(nonce);
  const idToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: '001234.fixture-user', nonce,
    email: 'relay@example.test', email_verified: true,
  });
  const completion = await completeAppleAuthorization(
    fixture.dependencies,
    {kind: 'success', state, code: 'one-time-code', idToken, user: {name: {firstName: 'Ada', lastName: 'Lovelace'}, email: 'relay@example.test'}},
    start.browserBinding,
    'host-user-a',
  );
  assert.equal(completion.kind, 'authenticated');
  if (completion.kind !== 'authenticated') return;
  assert.equal(completion.returnTo, '/settings?tab=account');
  assert.equal(completion.identity.displayName, 'Ada Lovelace');
  assert.equal(completion.identity.userId, 'host-user-a');
  const session = [...fixture.repository.sessions.values()][0];
  const serialized = JSON.stringify(session);
  assert.equal(session.ownerId, 'host-user-a');
  for (const secret of [completion.sessionToken, '001234.fixture-user', 'relay@example.test', 'stored-refresh-token', 'initial-access-token']) {
    assert.equal(serialized.includes(secret), false, secret);
  }
  assert.deepEqual(await readAppleSession(fixture.dependencies, completion.sessionToken), {
    ownerId: 'host-user-a',
    appleSubjectHash: session.appleSubjectHash,
    identity: completion.identity,
  });
  await assert.rejects(
    () => completeAppleAuthorization(fixture.dependencies, {kind: 'success', state, code: 'replay', idToken, user: null}, start.browserBinding, 'host-user-a'),
    matchesCode('APPLE_FLOW_INVALID'),
  );
  const codeRequest = fixture.requests.find(candidate => candidate.url.endsWith('/auth/token'));
  assert.equal(codeRequest?.form?.get('grant_type'), 'authorization_code');
  assert.equal(codeRequest?.form?.get('code'), 'one-time-code');
  assert.equal(codeRequest?.form?.get('redirect_uri'), fixture.dependencies.configuration.redirectUri);
});

test('web callback links a hashed Apple subject once and fails closed across host owners', async () => {
  const fixture = await createFixture();
  const first = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-a'}, '/');
  const firstURL = new URL(first.authorizationUrl);
  const firstNonce = firstURL.searchParams.get('nonce');
  const firstState = firstURL.searchParams.get('state');
  assert.ok(firstNonce);
  assert.ok(firstState);
  fixture.setActiveNonce(firstNonce);
  const firstToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: '001234.fixture-user', nonce: firstNonce,
  });
  const firstCompletion = await completeAppleAuthorization(
    fixture.dependencies,
    {kind: 'success', state: firstState, code: 'first-code', idToken: firstToken, user: null},
    first.browserBinding,
    'host-user-a',
  );
  assert.equal(firstCompletion.kind, 'authenticated');
  assert.deepEqual([...fixture.repository.links.values()], ['host-user-a']);
  assert.equal(JSON.stringify([...fixture.repository.links.keys()]).includes('001234.fixture-user'), false);

  const second = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-b'}, '/');
  const secondURL = new URL(second.authorizationUrl);
  const secondNonce = secondURL.searchParams.get('nonce');
  const secondState = secondURL.searchParams.get('state');
  assert.ok(secondNonce);
  assert.ok(secondState);
  fixture.setActiveNonce(secondNonce);
  const secondToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: '001234.fixture-user', nonce: secondNonce,
  });
  await assert.rejects(
    () => completeAppleAuthorization(
      fixture.dependencies,
      {kind: 'success', state: secondState, code: 'second-code', idToken: secondToken, user: null},
      second.browserBinding,
      'host-user-b',
    ),
    matchesCode('APPLE_IDENTITY_ALREADY_LINKED'),
  );
  assert.equal(fixture.repository.sessions.size, 1);
  assert.deepEqual([...fixture.repository.links.values()], ['host-user-a']);
});

test('callback rechecks the current host for link and rejects ambient host during standalone authentication', async () => {
  const fixture = await createFixture();
  const linkStart = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-a'}, '/');
  const linkUrl = new URL(linkStart.authorizationUrl);
  const linkNonce = linkUrl.searchParams.get('nonce');
  const linkState = linkUrl.searchParams.get('state');
  assert.ok(linkNonce);
  assert.ok(linkState);
  fixture.setActiveNonce(linkNonce);
  const linkToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: 'link-host-check', nonce: linkNonce,
  });
  await assert.rejects(
    () => completeAppleAuthorization(
      fixture.dependencies,
      {kind: 'success', state: linkState, code: 'code', idToken: linkToken, user: null},
      linkStart.browserBinding,
      'host-user-b',
    ),
    matchesCode('APPLE_LINK_HOST_MISMATCH'),
  );

  const authenticateStart = await startAppleAuthorization(fixture.dependencies, {purpose: 'authenticate'}, '/');
  const authenticateUrl = new URL(authenticateStart.authorizationUrl);
  const authenticateNonce = authenticateUrl.searchParams.get('nonce');
  const authenticateState = authenticateUrl.searchParams.get('state');
  assert.ok(authenticateNonce);
  assert.ok(authenticateState);
  fixture.setActiveNonce(authenticateNonce);
  const authenticateToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: 'standalone-host-check', nonce: authenticateNonce,
  });
  await assert.rejects(
    () => completeAppleAuthorization(
      fixture.dependencies,
      {kind: 'success', state: authenticateState, code: 'code', idToken: authenticateToken, user: null},
      authenticateStart.browserBinding,
      'host-user-a',
    ),
    matchesCode('AUTH_SESSION_AMBIGUOUS'),
  );
  assert.equal(fixture.repository.sessions.size, 0);
});

test('wrong browser binding and nonce fail before a session can be created', async () => {
  const fixture = await createFixture();
  const bindingStart = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-a'}, '/');
  const bindingURL = new URL(bindingStart.authorizationUrl);
  const bindingNonce = bindingURL.searchParams.get('nonce');
  const bindingState = bindingURL.searchParams.get('state');
  assert.ok(bindingNonce);
  assert.ok(bindingState);
  const bindingToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: '001234.fixture-user', nonce: bindingNonce,
  });
  await assert.rejects(
    () => completeAppleAuthorization(fixture.dependencies, {kind: 'success', state: bindingState, code: 'code', idToken: bindingToken, user: null}, 'v1.' + 'x'.repeat(43), 'host-user-a'),
    matchesCode('APPLE_FLOW_BINDING_MISMATCH'),
  );

  const nonceStart = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-a'}, '/');
  const nonceURL = new URL(nonceStart.authorizationUrl);
  const nonceState = nonceURL.searchParams.get('state');
  assert.ok(nonceState);
  const wrongNonceToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: '001234.fixture-user', nonce: 'wrong-nonce',
  });
  await assert.rejects(
    () => completeAppleAuthorization(fixture.dependencies, {kind: 'success', state: nonceState, code: 'code', idToken: wrongNonceToken, user: null}, nonceStart.browserBinding, 'host-user-a'),
    matchesCode('APPLE_ID_TOKEN_NONCE'),
  );
  assert.equal(fixture.repository.sessions.size, 0);
});

test('a deletion gate rejects a callback before Apple can mint a credential', async () => {
  const fixture = await createFixture();
  const subject = 'deletion-race-subject';
  fixture.repository.deletionSubjects.add(await hashAppleSubject(subject, fixture.dependencies));
  await assert.rejects(
    authorizeFixture({
      fixture,
      subject,
      intent: {purpose: 'authenticate'},
      ambientHostOwnerId: null,
    }),
    matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
  );
  assert.equal(fixture.repository.sessions.size, 0);
  assert.equal(
    fixture.requests.filter(request => request.url.endsWith('/auth/token')).length,
    0,
  );
  assert.equal(fixture.repository.possibleAuthorizationLeases.size, 0);
});

test('web Apple exchange starts only after durable possible-credential readback', async () => {
  const fixture = await createFixture();
  fixture.repository.markAuthorizationExchangePossible = async () => {
    throw new AppleAuthError(503, 'APPLE_AUTH_CREDENTIAL_MARKER_UNAVAILABLE', 'marker unavailable');
  };
  await assert.rejects(authorizeFixture({
    fixture,
    subject: 'web-marker-readback-subject',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  }), matchesCode('APPLE_AUTH_CREDENTIAL_MARKER_UNAVAILABLE'));
  assert.equal(fixture.requests.filter(request => request.url.endsWith('/auth/token')).length, 0);
});

test('ambiguous web token exchange and failed compensation retain possible-credential state', async () => {
  const unavailableFixture = await createFixture();
  const healthyFetcher = unavailableFixture.dependencies.fetcher;
  unavailableFixture.dependencies.fetcher = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.endsWith('/auth/token')) return new Response(null, {status: 503});
    return healthyFetcher(input, init);
  };
  await assert.rejects(authorizeFixture({
    fixture: unavailableFixture,
    subject: 'web-token-503-after-acceptance',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  }), matchesCode('APPLE_CODE_REJECTED'));
  assert.equal(unavailableFixture.repository.possibleAuthorizationLeases.size, 1);

  const persistenceFixture = await createFixture();
  persistenceFixture.setRevokeFailure(true);
  persistenceFixture.repository.createSession = async () => {
    throw new Error('durable session unavailable');
  };
  await assert.rejects(authorizeFixture({
    fixture: persistenceFixture,
    subject: 'web-post-provider-storage-failure',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  }), /durable session unavailable/);
  assert.equal(
    persistenceFixture.requests.filter(request => request.url.endsWith('/auth/revoke')).length,
    1,
  );
  assert.equal(persistenceFixture.repository.possibleAuthorizationLeases.size, 1);
});

test('only a bounded known Apple 400 response clears the current web exchange marker', async () => {
  const definitiveFixture = await createFixture();
  const definitiveHealthyFetcher = definitiveFixture.dependencies.fetcher;
  definitiveFixture.dependencies.fetcher = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.endsWith('/auth/token')) {
      return Response.json({error: 'invalid_grant'}, {status: 400});
    }
    return definitiveHealthyFetcher(input, init);
  };
  await assert.rejects(authorizeFixture({
    fixture: definitiveFixture,
    subject: 'web-definitive-no-token',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  }), matchesCode('APPLE_CODE_REJECTED'));
  assert.equal(definitiveFixture.repository.possibleAuthorizationLeases.size, 0);
  assert.equal(definitiveFixture.repository.authorizationLeases.size, 0);

  const malformedFixture = await createFixture();
  const malformedHealthyFetcher = malformedFixture.dependencies.fetcher;
  malformedFixture.dependencies.fetcher = async (input, init) => {
    const url = input instanceof Request ? input.url : input.toString();
    if (url.endsWith('/auth/token')) return Response.json({error: 'unknown_error'}, {status: 400});
    return malformedHealthyFetcher(input, init);
  };
  await assert.rejects(authorizeFixture({
    fixture: malformedFixture,
    subject: 'web-ambiguous-malformed-error',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  }), matchesCode('APPLE_TOKEN_INVALID'));
  assert.equal(malformedFixture.repository.possibleAuthorizationLeases.size, 1);
});

test('code-exchange identity validation failure revokes the newly issued refresh token', async () => {
  const fixture = await createFixture();
  const start = await startAppleAuthorization(
    fixture.dependencies,
    {purpose: 'authenticate'},
    '/',
  );
  const authorizationURL = new URL(start.authorizationUrl);
  const nonce = authorizationURL.searchParams.get('nonce');
  const state = authorizationURL.searchParams.get('state');
  assert.ok(nonce);
  assert.ok(state);
  fixture.setActiveNonce(nonce);
  fixture.setActiveSubject('exchange-subject-mismatch');
  fixture.setActiveRefreshToken('refresh-token-requires-compensation');
  const callbackToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com',
    aud: CLIENT_ID,
    exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME,
    sub: 'callback-subject',
    nonce,
  });
  await assert.rejects(
    completeAppleAuthorization(
      fixture.dependencies,
      {kind: 'success', state, code: 'subject-mismatch-code', idToken: callbackToken, user: null},
      start.browserBinding,
      null,
    ),
    matchesCode('APPLE_TOKEN_SUBJECT_MISMATCH'),
  );
  const revokeRequest = fixture.requests.find(request => request.url.endsWith('/auth/revoke'));
  assert.equal(revokeRequest?.form?.get('token'), 'refresh-token-requires-compensation');
  assert.equal(revokeRequest?.form?.get('token_type_hint'), 'refresh_token');
  assert.equal(fixture.repository.sessions.size, 0);
});

test('expired and tampered Apple identity tokens fail before code exchange', async () => {
  const fixture = await createFixture();
  const expiredStart = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-a'}, '/');
  const expiredURL = new URL(expiredStart.authorizationUrl);
  const expiredNonce = expiredURL.searchParams.get('nonce');
  const expiredState = expiredURL.searchParams.get('state');
  assert.ok(expiredNonce);
  assert.ok(expiredState);
  const expiredToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME - 61,
    iat: INITIAL_TIME - 3_600, sub: '001234.fixture-user', nonce: expiredNonce,
  });
  await assert.rejects(
    () => completeAppleAuthorization(fixture.dependencies, {kind: 'success', state: expiredState, code: 'code', idToken: expiredToken, user: null}, expiredStart.browserBinding, 'host-user-a'),
    matchesCode('APPLE_ID_TOKEN_CLAIMS'),
  );

  const tamperedStart = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-a'}, '/');
  const tamperedURL = new URL(tamperedStart.authorizationUrl);
  const tamperedNonce = tamperedURL.searchParams.get('nonce');
  const tamperedState = tamperedURL.searchParams.get('state');
  assert.ok(tamperedNonce);
  assert.ok(tamperedState);
  const validToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: '001234.fixture-user', nonce: tamperedNonce,
  });
  const segments = validToken.split('.');
  const firstSignatureCharacter = segments[2][0] === 'A' ? 'B' : 'A';
  const tamperedToken = `${segments[0]}.${segments[1]}.${firstSignatureCharacter}${segments[2].slice(1)}`;
  await assert.rejects(
    () => completeAppleAuthorization(fixture.dependencies, {kind: 'success', state: tamperedState, code: 'code', idToken: tamperedToken, user: null}, tamperedStart.browserBinding, 'host-user-a'),
    matchesCode('APPLE_ID_TOKEN_SIGNATURE'),
  );
  assert.equal(fixture.requests.some(candidate => candidate.form?.get('grant_type') === 'authorization_code'), false);
  assert.equal(fixture.repository.sessions.size, 0);
});

test('Apple signing-key and token responses enforce streaming byte bounds', async () => {
  const fixture = await createFixture();
  const oversizedKeysStart = await startAppleAuthorization(fixture.dependencies, {purpose: 'authenticate'}, '/');
  const oversizedKeysUrl = new URL(oversizedKeysStart.authorizationUrl);
  const oversizedKeysNonce = oversizedKeysUrl.searchParams.get('nonce');
  const oversizedKeysState = oversizedKeysUrl.searchParams.get('state');
  assert.ok(oversizedKeysNonce);
  assert.ok(oversizedKeysState);
  const oversizedKeysToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: 'bounded-keys-subject', nonce: oversizedKeysNonce,
  });
  const oversizedKeysDependencies: AppleAuthDependencies = {
    ...fixture.dependencies,
    fetcher: async () => new Response('small', {headers: {'Content-Length': '64001'}}),
  };
  await assert.rejects(
    () => completeAppleAuthorization(
      oversizedKeysDependencies,
      {kind: 'success', state: oversizedKeysState, code: 'code', idToken: oversizedKeysToken, user: null},
      oversizedKeysStart.browserBinding,
      null,
    ),
    matchesCode('APPLE_KEYS_INVALID'),
  );

  const oversizedTokenStart = await startAppleAuthorization(fixture.dependencies, {purpose: 'authenticate'}, '/');
  const oversizedTokenUrl = new URL(oversizedTokenStart.authorizationUrl);
  const oversizedTokenNonce = oversizedTokenUrl.searchParams.get('nonce');
  const oversizedTokenState = oversizedTokenUrl.searchParams.get('state');
  assert.ok(oversizedTokenNonce);
  assert.ok(oversizedTokenState);
  fixture.setActiveNonce(oversizedTokenNonce);
  fixture.setActiveSubject('bounded-token-subject');
  const oversizedTokenIdentity = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: 'bounded-token-subject', nonce: oversizedTokenNonce,
  });
  const regularFetcher = fixture.dependencies.fetcher;
  const oversizedTokenDependencies: AppleAuthDependencies = {
    ...fixture.dependencies,
    fetcher: async (request, init) => {
      const url = request instanceof Request ? request.url : request.toString();
      if (url.endsWith('/auth/token')) return new Response('small', {headers: {'Content-Length': '64001'}});
      return regularFetcher(request, init);
    },
  };
  await assert.rejects(
    () => completeAppleAuthorization(
      oversizedTokenDependencies,
      {kind: 'success', state: oversizedTokenState, code: 'code', idToken: oversizedTokenIdentity, user: null},
      oversizedTokenStart.browserBinding,
      null,
    ),
    matchesCode('APPLE_TOKEN_INVALID'),
  );
});

test('daily refresh preserves subject binding and revocation clears the local session before Apple', async () => {
  const fixture = await createFixture();
  const start = await startAppleAuthorization(fixture.dependencies, {purpose: 'link', ownerId: 'host-user-a'}, '/');
  const url = new URL(start.authorizationUrl);
  const nonce = url.searchParams.get('nonce');
  const state = url.searchParams.get('state');
  assert.ok(nonce);
  assert.ok(state);
  fixture.setActiveNonce(nonce);
  const idToken = await fixture.signIdentityToken({
    iss: 'https://appleid.apple.com', aud: CLIENT_ID, exp: INITIAL_TIME + 3_600,
    iat: INITIAL_TIME, sub: '001234.fixture-user', nonce,
  });
  const completion = await completeAppleAuthorization(
    fixture.dependencies,
    {kind: 'success', state, code: 'code', idToken, user: null},
    start.browserBinding,
    'host-user-a',
  );
  assert.equal(completion.kind, 'authenticated');
  if (completion.kind !== 'authenticated') return;

  fixture.setNow(INITIAL_TIME + 24 * 60 * 60 + 1);
  const refreshed = await readAppleSession(fixture.dependencies, completion.sessionToken);
  assert.equal(refreshed?.identity.userId, completion.identity.userId);
  const refreshRequest = fixture.requests.find(candidate => candidate.form?.get('grant_type') === 'refresh_token');
  assert.equal(refreshRequest?.form?.get('refresh_token'), 'stored-refresh-token');

  assert.equal(await revokeAppleSession(fixture.dependencies, completion.sessionToken), true);
  const revokeRequest = fixture.requests.find(candidate => candidate.url.endsWith('/auth/revoke'));
  assert.equal(revokeRequest?.form?.get('token'), 'stored-refresh-token');
  assert.equal(revokeRequest?.form?.get('token_type_hint'), 'refresh_token');
  assert.equal(await readAppleSession(fixture.dependencies, completion.sessionToken), null);
  assert.equal(await revokeAppleSession(fixture.dependencies, completion.sessionToken), false);
});

test('D1 web revalidation CAS is fenced against deletion before and after commit', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository = createD1AppleAuthRepository(database);
    const deletionRepository = createD1AppleAccountDeletionRepository(database);
    const refreshAt = INITIAL_TIME + 24 * 60 * 60 + 1;
    const authorize = async (subject: string) => {
      const fixture = await createFixture();
      fixture.dependencies.repository = repository;
      const completion = await authorizeFixture({
        fixture,
        subject,
        intent: {purpose: 'authenticate'},
        ambientHostOwnerId: null,
      });
      fixture.setNow(refreshAt);
      const sessionHash = await hashAppleOpaqueToken(completion.sessionToken, crypto);
      const session = await repository.readSession(sessionHash, refreshAt);
      assert.ok(session);
      return {fixture, completion, sessionHash, session};
    };
    const beginDeletion = async (
      session: AppleAuthSessionRecord,
      marker: string,
      startedAt: number,
    ) => {
      assert.equal(await deletionRepository.beginAppleAccountDeletion({
        ownerId: session.ownerId,
        appleSubjectHash: session.appleSubjectHash,
        deleteOwnerData: true,
        ownerBinding: session.ownerBinding,
        deletionKeyHash: marker.repeat(43),
        revocationLeaseToken: marker.toLowerCase().repeat(43),
        startedAt,
        leaseClaimedAt: startedAt,
        expiresAt: startedAt + 600,
      }), null);
    };

    const beforeCommit = await authorize('web-refresh-delete-before-cas');
    const providerStarted = Promise.withResolvers<void>();
    const releaseProvider = Promise.withResolvers<void>();
    const normalFetcher = beforeCommit.fixture.dependencies.fetcher;
    beforeCommit.fixture.dependencies.fetcher = async (request, init) => {
      const form = init?.body instanceof URLSearchParams ? init.body : null;
      if (form?.get('grant_type') === 'refresh_token') {
        providerStarted.resolve();
        await releaseProvider.promise;
      }
      return normalFetcher(request, init);
    };
    const refreshBeforeCommit = readAppleSession(
      beforeCommit.fixture.dependencies,
      beforeCommit.completion.sessionToken,
    );
    await providerStarted.promise;
    beforeCommit.fixture.setNow(refreshAt + 1);
    await beginDeletion(beforeCommit.session, 'R', refreshAt + 1);
    releaseProvider.resolve();
    await assert.rejects(refreshBeforeCommit, /APPLE_SESSION_UPDATE_CONFLICT/);
    assert.equal(await database.prepare(
      'SELECT last_validated_at FROM apple_auth_sessions WHERE session_hash=?',
    ).bind(beforeCommit.sessionHash).first('last_validated_at'), beforeCommit.session.lastValidatedAt);
    assert.equal(await repository.readSession(beforeCommit.sessionHash, refreshAt + 1), null);

    const afterCommit = await authorize('web-refresh-delete-after-cas');
    const updateCommitted = Promise.withResolvers<void>();
    const releaseUpdate = Promise.withResolvers<void>();
    const pausedRepository: AppleAuthRepository = {
      ...repository,
      async updateSession(update) {
        await repository.updateSession(update);
        updateCommitted.resolve();
        await releaseUpdate.promise;
      },
    };
    afterCommit.fixture.dependencies.repository = pausedRepository;
    const refreshAfterCommit = readAppleSession(
      afterCommit.fixture.dependencies,
      afterCommit.completion.sessionToken,
    );
    await updateCommitted.promise;
    afterCommit.fixture.setNow(refreshAt + 1);
    await beginDeletion(afterCommit.session, 'S', refreshAt + 1);
    releaseUpdate.resolve();
    assert.equal(await refreshAfterCommit, null);
    assert.equal(await database.prepare(
      'SELECT last_validated_at FROM apple_auth_sessions WHERE session_hash=?',
    ).bind(afterCommit.sessionHash).first('last_validated_at'), refreshAt);

    const concurrent = await authorize('web-refresh-concurrent-cas');
    const nextA = {
      ...concurrent.session,
      encryptedCredentials: `${concurrent.session.encryptedCredentials}A`,
      lastValidatedAt: refreshAt,
    };
    const nextB = {
      ...concurrent.session,
      encryptedCredentials: `${concurrent.session.encryptedCredentials}B`,
      lastValidatedAt: refreshAt,
    };
    const outcomes = await Promise.allSettled([
      repository.updateSession({expected: concurrent.session, next: nextA, now: refreshAt}),
      repository.updateSession({expected: concurrent.session, next: nextB, now: refreshAt}),
    ]);
    assert.equal(outcomes.filter(outcome => outcome.status === 'fulfilled').length, 1);
    assert.equal(outcomes.filter(outcome => outcome.status === 'rejected').length, 1);
    const persistedCiphertext = await database.prepare(
      'SELECT encrypted_credentials FROM apple_auth_sessions WHERE session_hash=?',
    ).bind(concurrent.sessionHash).first('encrypted_credentials');
    assert.ok(
      persistedCiphertext === nextA.encryptedCredentials
      || persistedCiphertext === nextB.encryptedCredentials,
    );
  } finally {
    await miniflare.dispose();
  }
});

test('local revocation survives an Apple revocation outage', async () => {
  const fixture = await createFixture();
  const completion = await authorizeFixture({
    fixture,
    subject: 'revoke-outage-subject',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  });
  assert.ok(await readAppleSessionLocalPrincipal(fixture.dependencies, completion.sessionToken));
  fixture.setRevokeFailure(true);
  await assert.rejects(
    () => revokeAppleSession(fixture.dependencies, completion.sessionToken),
    matchesCode('APPLE_REVOCATION_FAILED'),
  );
  assert.equal(await readAppleSessionLocalPrincipal(fixture.dependencies, completion.sessionToken), null);
});

test('local revocation precedes a bounded and cancelled hanging Apple request', async () => {
  const fixture = await createFixture();
  const completion = await authorizeFixture({
    fixture,
    subject: 'revoke-timeout-subject',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  });
  const revokeStarted = Promise.withResolvers<void>();
  const regularFetcher = fixture.dependencies.fetcher;
  let abortObserved = false;
  const dependencies: AppleAuthDependencies = {
    ...fixture.dependencies,
    revocationTimeoutMilliseconds: 25,
    fetcher: (input, init) => {
      const url = input instanceof Request ? input.url : input.toString();
      if (!url.endsWith('/auth/revoke')) return regularFetcher(input, init);
      revokeStarted.resolve();
      return new Promise<Response>((_resolve, reject) => {
        const signal = init?.signal;
        const abort = () => {
          abortObserved = true;
          reject(new Error('fixture observed cancellation'));
        };
        if (!signal) {
          reject(new Error('revocation request did not receive an abort signal'));
        } else if (signal.aborted) {
          abort();
        } else {
          signal.addEventListener('abort', abort, {once: true});
        }
      });
    },
  };
  let settled = false;
  const revocation = revokeAppleSession(dependencies, completion.sessionToken);
  void revocation.then(() => { settled = true; }, () => { settled = true; });
  await revokeStarted.promise;
  assert.equal(settled, false);
  assert.equal(await readAppleSessionLocalPrincipal(dependencies, completion.sessionToken), null);
  await assert.rejects(revocation, matchesCode('APPLE_REVOCATION_TIMEOUT'));
  assert.equal(abortObserved, true);
});

test('account deletion requires a random idempotency key and an empty body', async () => {
  const canonicalKey = `v1.${'I'.repeat(42)}Q`;
  const valid = new Request('https://sandbox.example.test/api/auth/apple/delete', {
    method: 'POST',
    headers: {'Idempotency-Key': canonicalKey},
  });
  assert.equal(parseAppleAccountDeletionKey(valid), canonicalKey);
  await requireEmptyAppleAccountDeletionBody(valid);
  assert.throws(
    () => parseAppleAccountDeletionKey(new Request(
      'https://sandbox.example.test/api/auth/apple/delete',
      {method: 'POST', headers: {'Idempotency-Key': 'predictable'}},
    )),
    matchesCode('APPLE_ACCOUNT_DELETION_KEY_INVALID'),
  );
  assert.throws(
    () => parseAppleAccountDeletionKey(new Request(
      'https://sandbox.example.test/api/auth/apple/delete',
      {method: 'POST', headers: {'Idempotency-Key': `v1.${'I'.repeat(42)}B`}},
    )),
    matchesCode('APPLE_ACCOUNT_DELETION_KEY_INVALID'),
  );
  await assert.rejects(
    () => requireEmptyAppleAccountDeletionBody(new Request(
      'https://sandbox.example.test/api/auth/apple/delete',
      {
        method: 'POST',
        headers: {'Content-Length': '1'},
        body: 'x',
      },
    )),
    matchesCode('APPLE_ACCOUNT_DELETION_BODY_INVALID'),
  );
});

test('account deletion attempts provider revocation, deletes local data, and replays idempotently', async () => {
  const fixture = await createFixture();
  const first = await authorizeFixture({
    fixture,
    subject: 'delete-account-subject',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  });
  await authorizeFixture({
    fixture,
    subject: 'delete-account-subject',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  });
  const repository = new MemoryAppleAccountDeletionRepository(fixture.repository);
  repository.ownerData.add(first.identity.userId);
  const appleSubjectHash = [...fixture.repository.sessions.values()]
    .find(session => session.ownerId === first.identity.userId)?.appleSubjectHash;
  assert.ok(appleSubjectHash);
  const deletionKey = `v1.${'D'.repeat(43)}`;
  fixture.setRevokeFailure(true);
  const result = await deleteAppleAccount({
    repository,
    authDependencies: fixture.dependencies,
    ownerId: first.identity.userId,
    appleSubjectHash,
    deletionKey,
    crypto,
    now: INITIAL_TIME,
    completionNow: () => INITIAL_TIME + 5,
  });
  assert.deepEqual(result, {
    deleted: true,
    idempotent: false,
    providerCredentials: {
      credentialsFound: 1,
      credentialsRevoked: 0,
      unreadableSessions: 0,
      failedRevocations: 1,
      manualRevocationRequired: true,
    },
    originConnections: NO_ORIGIN_CONNECTIONS,
  });
  assert.equal(repository.ownerData.has(first.identity.userId), false);
  const storedDeletion = repository.deletionReceipts.get(
    await hashAppleOpaqueToken(deletionKey, crypto),
  );
  assert.equal(storedDeletion?.completedAt, INITIAL_TIME + 5);
  assert.equal(storedDeletion?.expiresAt, INITIAL_TIME + 5 + (30 * 24 * 60 * 60));
  assert.equal(
    [...fixture.repository.sessions.values()].some(session => session.ownerId === first.identity.userId),
    false,
  );
  assert.equal(
    [...fixture.repository.links.values()].some(ownerId => ownerId === first.identity.userId),
    false,
  );
  const revocationCount = fixture.requests.filter(request => request.url.endsWith('/auth/revoke')).length;
  assert.equal(revocationCount, 1);
  assert.deepEqual(await deleteAppleAccount({
    repository,
    authDependencies: fixture.dependencies,
    ownerId: first.identity.userId,
    appleSubjectHash,
    deletionKey,
    crypto,
    now: INITIAL_TIME + 1,
  }), {
    deleted: true,
    idempotent: true,
    providerCredentials: {
      credentialsFound: 1,
      credentialsRevoked: 0,
      unreadableSessions: 0,
      failedRevocations: 1,
      manualRevocationRequired: true,
    },
    originConnections: NO_ORIGIN_CONNECTIONS,
  });
  assert.equal(
    fixture.requests.filter(request => request.url.endsWith('/auth/revoke')).length,
    revocationCount,
  );
});

test('native-only account deletion reports manual Apple revocation without retaining local data', async () => {
  const fixture = await createFixture();
  const repository = new MemoryAppleAccountDeletionRepository(fixture.repository);
  const ownerId = `apple-owner:v1.${'N'.repeat(43)}`;
  repository.ownerData.add(ownerId);
  const result = await deleteAppleAccount({
    repository,
    authDependencies: null,
    ownerId,
    appleSubjectHash: 'N'.repeat(43),
    deletionKey: `v1.${'K'.repeat(43)}`,
    crypto,
    now: INITIAL_TIME,
  });
  assert.equal(result.deleted, true);
  assert.equal(result.providerCredentials.manualRevocationRequired, true);
  assert.equal(repository.ownerData.has(ownerId), false);
  assert.deepEqual(await deleteAppleAccount({
    repository,
    authDependencies: null,
    ownerId,
    appleSubjectHash: 'N'.repeat(43),
    deletionKey: `v1.${'K'.repeat(43)}`,
    crypto,
    now: INITIAL_TIME + 1,
  }), {
    ...result,
    idempotent: true,
  });
});

test('standalone deletion bounds Origin uninstall, preserves partial manual follow-up, and replays exactly', async () => {
  const allRevokedFixture=await createFixture();
  const allRevokedRepository=new MemoryAppleAccountDeletionRepository(allRevokedFixture.repository);
  const allRevokedOwner=`apple-owner:v1.${'O'.repeat(43)}`;
  const installationIds=['inst_01k2ja20','inst_01k2ja21'];
  allRevokedRepository.originInstallations.set(allRevokedOwner,installationIds);
  const revoked:string[]=[];
  const deletionKey=`v1.${'O'.repeat(42)}Q`;
  const allRevoked=await deleteAppleAccount({
    repository:allRevokedRepository,
    authDependencies:null,
    originDependencies:{revokeInstallation:async(installationId,signal)=>{
      assert.equal(signal.aborted,false);
      revoked.push(installationId);
    }},
    ownerId:allRevokedOwner,
    appleSubjectHash:'O'.repeat(43),
    deletionKey,
    crypto,
    now:INITIAL_TIME,
  });
  assert.deepEqual(allRevoked.originConnections,{
    installationsFound:2,
    installationsRevoked:2,
    unreadableInstallations:0,
    failedRevocations:0,
    manualRevocationRequired:false,
  });
  assert.deepEqual(revoked.sort(),installationIds);
  const replay=await deleteAppleAccount({
    repository:allRevokedRepository,
    authDependencies:null,
    originDependencies:{revokeInstallation:async()=>{throw new Error('replay retried Origin');}},
    ownerId:allRevokedOwner,
    appleSubjectHash:'O'.repeat(43),
    deletionKey,
    crypto,
    now:INITIAL_TIME+1,
  });
  assert.equal(replay.idempotent,true);
  assert.deepEqual(replay.originConnections,allRevoked.originConnections);
  assert.equal(revoked.length,2);

  const partialFixture=await createFixture();
  const partialRepository=new MemoryAppleAccountDeletionRepository(partialFixture.repository);
  const partialOwner=`apple-owner:v1.${'P'.repeat(43)}`;
  partialRepository.originInstallations.set(partialOwner,[
    'inst_01k2ja30','inst_01k2ja31','inst_01k2ja32',
  ]);
  const partial=await deleteAppleAccount({
    repository:partialRepository,
    authDependencies:null,
    originDependencies:{revokeInstallation:async installationId=>{
      if(installationId.endsWith('31'))throw new Error('provider unavailable');
    }},
    ownerId:partialOwner,
    appleSubjectHash:'P'.repeat(43),
    deletionKey:`v1.${'P'.repeat(42)}Q`,
    crypto,
    now:INITIAL_TIME,
  });
  assert.deepEqual(partial.originConnections,{
    installationsFound:3,
    installationsRevoked:2,
    unreadableInstallations:0,
    failedRevocations:1,
    manualRevocationRequired:true,
  });

  const unconfiguredFixture=await createFixture();
  const unconfiguredRepository=new MemoryAppleAccountDeletionRepository(unconfiguredFixture.repository);
  const unconfiguredOwner=`apple-owner:v1.${'U'.repeat(43)}`;
  unconfiguredRepository.originInstallations.set(unconfiguredOwner,['inst_01k2ja40']);
  const unconfigured=await deleteAppleAccount({
    repository:unconfiguredRepository,
    authDependencies:null,
    originDependencies:null,
    ownerId:unconfiguredOwner,
    appleSubjectHash:'U'.repeat(43),
    deletionKey:`v1.${'U'.repeat(42)}Q`,
    crypto,
    now:INITIAL_TIME,
  });
  assert.deepEqual(unconfigured.originConnections,{
    installationsFound:1,
    installationsRevoked:0,
    unreadableInstallations:0,
    failedRevocations:1,
    manualRevocationRequired:true,
  });
});

test('one scope leader performs provider cleanup across concurrent same-key and distinct-key deletes', async () => {
  const fixture = await createFixture();
  const authorization = await authorizeFixture({
    fixture,
    subject: 'concurrent-deletion-subject',
    intent: {purpose: 'authenticate'},
    ambientHostOwnerId: null,
  });
  const ownerId = authorization.identity.userId;
  const appleSubjectHash = await hashAppleSubject(
    'concurrent-deletion-subject',
    fixture.dependencies,
  );
  const repository = new MemoryAppleAccountDeletionRepository(fixture.repository);
  repository.originInstallations.set(ownerId, ['inst_01k2leader']);
  const originStarted = Promise.withResolvers<void>();
  const originRelease = Promise.withResolvers<void>();
  let originRevocations = 0;
  const originDependencies = {
    revokeInstallation: async () => {
      originRevocations += 1;
      originStarted.resolve();
      await originRelease.promise;
    },
  };
  const keyA = `v1.${'a'.repeat(42)}A`;
  const keyB = `v1.${'b'.repeat(42)}A`;
  const leader = deleteAppleAccount({
    repository,
    authDependencies: fixture.dependencies,
    originDependencies,
    ownerId,
    appleSubjectHash,
    deletionKey: keyA,
    crypto,
    now: INITIAL_TIME,
  });
  await originStarted.promise;
  for (const deletionKey of [keyA, keyB]) {
    await assert.rejects(deleteAppleAccount({
      repository,
      authDependencies: fixture.dependencies,
      originDependencies,
      ownerId,
      appleSubjectHash,
      deletionKey,
      crypto,
      now: INITIAL_TIME,
    }), matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
  }
  originRelease.resolve();
  const completed = await leader;
  const appleRevocations = fixture.requests.filter(
    request => request.url === 'https://appleid.apple.com/auth/revoke',
  );
  assert.equal(appleRevocations.length, 1);
  assert.equal(originRevocations, 1);
  const staleRequestReplay = await deleteAppleAccount({
    repository,
    authDependencies: fixture.dependencies,
    originDependencies,
    ownerId,
    appleSubjectHash,
    deletionKey: keyB,
    crypto,
    now: INITIAL_TIME,
  });
  assert.deepEqual(staleRequestReplay, {...completed, idempotent: true});
  assert.equal(originRevocations, 1);
  assert.equal(fixture.requests.filter(
    request => request.url === 'https://appleid.apple.com/auth/revoke',
  ).length, 1);
});

test('a fresh same-key lease takeover fences the expired provider-cleanup leader', async () => {
  const fixture = await createFixture();
  const repository = new MemoryAppleAccountDeletionRepository(fixture.repository);
  const ownerId = `apple-owner:v1.${'c'.repeat(42)}A`;
  const appleSubjectHash = 'd'.repeat(43);
  const deletionKey = `v1.${'e'.repeat(42)}A`;
  repository.originInstallations.set(ownerId, ['inst_01k2fence']);
  const completionEntered = Promise.withResolvers<void>();
  const completionRelease = Promise.withResolvers<void>();
  const complete = repository.deleteAppleAccessAndCompleteReceipt.bind(repository);
  let completionCalls = 0;
  repository.deleteAppleAccessAndCompleteReceipt = async input => {
    completionCalls += 1;
    if (completionCalls === 1) {
      completionEntered.resolve();
      await completionRelease.promise;
    }
    return complete(input);
  };
  let clock = INITIAL_TIME;
  const staleLeader = deleteAppleAccount({
    repository,
    authDependencies: null,
    originDependencies: {revokeInstallation: async () => {
      throw new Error('first provider cleanup failed');
    }},
    ownerId,
    appleSubjectHash,
    deletionKey,
    crypto,
    now: INITIAL_TIME,
    completionNow: () => clock,
    revocationLeaseToken: () => `${'f'.repeat(42)}A`,
  });
  await completionEntered.promise;
  clock = INITIAL_TIME + APPLE_ACCOUNT_DELETION_REVOCATION_LEASE_SECONDS + 1;
  const winner = await deleteAppleAccount({
    repository,
    authDependencies: null,
    originDependencies: {revokeInstallation: async () => undefined},
    ownerId,
    appleSubjectHash,
    deletionKey,
    crypto,
    now: INITIAL_TIME,
    completionNow: () => clock,
    revocationLeaseToken: () => `${'g'.repeat(42)}A`,
  });
  assert.equal(winner.originConnections.manualRevocationRequired, false);
  completionRelease.resolve();
  await assert.rejects(staleLeader, matchesCode('APPLE_ACCOUNT_DELETION_LEASE_LOST'));
  assert.deepEqual(await repository.readDeletionReceipt(
    await hashAppleOpaqueToken(deletionKey, crypto),
    clock + 1,
  ), {
    ownerBinding: await hashAppleOpaqueToken(
      `owner\0${ownerId}\0apple-subject\0${appleSubjectHash}`,
      crypto,
    ),
    providerCredentials: winner.providerCredentials,
    originConnections: winner.originConnections,
  });
});

test('linked Apple deletion removes only that subject and binds keys within one ChatGPT owner', async () => {
  const fixture = await createFixture();
  const ownerId = 'chatgpt-owner-with-two-apple-identities';
  await authorizeFixture({
    fixture,
    subject: 'linked-subject-a',
    intent: {purpose: 'link', ownerId},
    ambientHostOwnerId: ownerId,
  });
  await authorizeFixture({
    fixture,
    subject: 'linked-subject-b',
    intent: {purpose: 'link', ownerId},
    ambientHostOwnerId: ownerId,
  });
  const subjectA = await hashAppleSubject('linked-subject-a', fixture.dependencies);
  const subjectB = await hashAppleSubject('linked-subject-b', fixture.dependencies);
  const repository = new MemoryAppleAccountDeletionRepository(fixture.repository);
  repository.ownerData.add(ownerId);
  const deletionKey = `v1.${'L'.repeat(43)}`;
  await repository.beginAppleAccountDeletion({
    ownerId,
    appleSubjectHash: subjectA,
    deleteOwnerData: false,
    ownerBinding: await hashAppleOpaqueToken(
      `owner\0${ownerId}\0apple-subject\0${subjectA}`,
      crypto,
    ),
    deletionKeyHash: await hashAppleOpaqueToken(deletionKey, crypto),
    revocationLeaseToken: 'T'.repeat(43),
    startedAt: INITIAL_TIME,
    leaseClaimedAt: INITIAL_TIME,
    expiresAt: INITIAL_TIME + 600,
  });
  await assert.rejects(
    deleteAppleAccount({
      repository,
      authDependencies: fixture.dependencies,
      ownerId,
      appleSubjectHash: subjectB,
      deletionKey,
      crypto,
      now: INITIAL_TIME,
    }),
    matchesCode('APPLE_ACCOUNT_DELETION_KEY_CONFLICT'),
  );
  const result = await deleteAppleAccount({
    repository,
    authDependencies: fixture.dependencies,
    ownerId,
    appleSubjectHash: subjectA,
    deletionKey,
    crypto,
    now: INITIAL_TIME + APPLE_ACCOUNT_DELETION_REVOCATION_LEASE_SECONDS,
  });
  assert.equal(result.deleted, true);
  assert.equal(repository.ownerData.has(ownerId), true);
  assert.equal(fixture.repository.links.has(subjectA), false);
  assert.equal(fixture.repository.links.get(subjectB), ownerId);
  assert.equal(
    [...fixture.repository.sessions.values()].some(session => session.appleSubjectHash === subjectA),
    false,
  );
  assert.equal(
    [...fixture.repository.sessions.values()].some(session => session.appleSubjectHash === subjectB),
    true,
  );
  await assert.rejects(
    deleteAppleAccount({
      repository,
      authDependencies: fixture.dependencies,
      ownerId,
      appleSubjectHash: subjectB,
      deletionKey,
      crypto,
      now: INITIAL_TIME + 1,
    }),
    matchesCode('APPLE_ACCOUNT_DELETION_KEY_CONFLICT'),
  );
});

test('one deletion attempt bounds provider revocation work and still removes all local sessions', async () => {
  const fixture = await createFixture();
  let ownerId = '';
  for (let index = 0; index < 10; index += 1) {
    fixture.setActiveRefreshToken(`refresh-token-${index}`);
    const completion = await authorizeFixture({
      fixture,
      subject: 'many-session-subject',
      intent: {purpose: 'authenticate'},
      ambientHostOwnerId: null,
    });
    ownerId = completion.identity.userId;
  }
  const appleSubjectHash = await hashAppleSubject('many-session-subject', fixture.dependencies);
  const repository = new MemoryAppleAccountDeletionRepository(fixture.repository);
  const result = await deleteAppleAccount({
    repository,
    authDependencies: fixture.dependencies,
    ownerId,
    appleSubjectHash,
    deletionKey: `v1.${'B'.repeat(43)}`,
    crypto,
    now: INITIAL_TIME,
  });
  assert.deepEqual(result.providerCredentials, {
    credentialsFound: 8,
    credentialsRevoked: 8,
    unreadableSessions: 2,
    failedRevocations: 0,
    manualRevocationRequired: true,
  });
  assert.equal(
    fixture.requests.filter(request => request.url.endsWith('/auth/revoke')).length,
    8,
  );
  assert.equal(
    [...fixture.repository.sessions.values()].some(session => session.ownerId === ownerId),
    false,
  );
});

test('web account deletion cancellation sends no request and creates no retry attempt', async () => {
  const accountScope = 'A'.repeat(43);
  const client = new AppleAccountDeletionClient({
    randomBytes: count => new Uint8Array(count),
    attemptStore: new MemoryAppleAccountDeletionAttemptStore(),
    now: () => INITIAL_TIME * 1_000,
  });
  let requests = 0;
  let scrubbed = false;
  const outcome = await client.deleteIfConfirmed({
    confirmed: false,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone',
    fetcher: async () => { requests += 1; return Response.json({}); },
    scrub: () => { scrubbed = true; },
  });
  assert.deepEqual(outcome, {kind: 'cancelled'});
  assert.equal(requests, 0);
  assert.equal(scrubbed, false);
  assert.equal(client.hasPendingAttempt(accountScope), false);
});

test('web account deletion sends an empty same-origin request and scrubs only after strict success', async () => {
  const accountScope = 'A'.repeat(43);
  const random = Uint8Array.from({length: 32}, (_, index) => index);
  const client = new AppleAccountDeletionClient({
    randomBytes: count => {
      assert.equal(count, 32);
      return random;
    },
    attemptStore: new MemoryAppleAccountDeletionAttemptStore(),
    followUpStore: new MemoryAppleAccountDeletionAttemptStore(),
    now: () => INITIAL_TIME * 1_000,
  });
  const requests: {path: string | URL | Request; init?: RequestInit}[] = [];
  let scrubbed = false;
  const response = {
    deleted: true,
    idempotent: false,
    providerCredentials: {
      credentialsFound: 1,
      credentialsRevoked: 1,
      unreadableSessions: 0,
      failedRevocations: 0,
      manualRevocationRequired: false,
    },
    originConnections: NO_ORIGIN_CONNECTIONS,
  } as const;
  const outcome = await client.deleteIfConfirmed({
    confirmed: true,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone',
    fetcher: async (path, init) => {
      requests.push({path, init});
      assert.equal(scrubbed, false);
      return Response.json(response);
    },
    scrub: parsed => {
      assert.deepEqual(parsed, response);
      scrubbed = true;
    },
  });
  assert.deepEqual(outcome, {kind: 'deleted', response});
  assert.equal(scrubbed, true);
  assert.equal(requests.length, 1);
  assert.equal(requests[0]?.path, '/api/auth/apple/delete');
  const init = requests[0]?.init;
  assert.equal(init?.method, 'POST');
  assert.equal(init?.body, undefined);
  assert.equal(init?.credentials, 'same-origin');
  assert.equal(init?.mode, 'same-origin');
  assert.equal(init?.redirect, 'error');
  const headers = new Headers(init?.headers);
  assert.equal(headers.get('content-type'), null);
  assert.equal(headers.get('accept'), 'application/json');
  assert.equal(headers.get('idempotency-key'), 'v1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
  assert.equal(client.hasPendingAttempt(accountScope), false);
});

test('web account deletion keeps one idempotency key across HTTP and uncertain retries', async () => {
  const accountScope = 'A'.repeat(43);
  let randomCalls = 0;
  const client = new AppleAccountDeletionClient({
    randomBytes: count => {
      randomCalls += 1;
      return new Uint8Array(count).fill(7);
    },
    attemptStore: new MemoryAppleAccountDeletionAttemptStore(),
    followUpStore: new MemoryAppleAccountDeletionAttemptStore(),
    now: () => INITIAL_TIME * 1_000,
  });
  const keys: string[] = [];
  let scrubbed = false;
  await assert.rejects(
    client.deleteIfConfirmed({
      confirmed: true,
      accountScope,
      workspaceScope: WEB_WORKSPACE_SCOPE,
      accountMode: 'standalone',
      fetcher: async (_path, init) => {
        keys.push(new Headers(init?.headers).get('idempotency-key') ?? '');
        return Response.json({error: 'Temporarily unavailable.', code: 'APPLE_AUTH_UNAVAILABLE'}, {status: 503});
      },
      scrub: () => { scrubbed = true; },
    }),
    error => error instanceof AppleAccountDeletionHTTPError && error.status === 503,
  );
  await assert.rejects(
    client.deleteIfConfirmed({
      confirmed: true,
      accountScope,
      workspaceScope: WEB_WORKSPACE_SCOPE,
      accountMode: 'standalone',
      fetcher: async (_path, init) => {
        keys.push(new Headers(init?.headers).get('idempotency-key') ?? '');
        throw new TypeError('connection lost');
      },
      scrub: () => { scrubbed = true; },
    }),
    /connection lost/,
  );
  const result = await client.deleteIfConfirmed({
    confirmed: true,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone',
    fetcher: async (_path, init) => {
      keys.push(new Headers(init?.headers).get('idempotency-key') ?? '');
      return Response.json({
        deleted: true,
        idempotent: true,
        providerCredentials: {
          credentialsFound: 0,
          credentialsRevoked: 0,
          unreadableSessions: 0,
          failedRevocations: 0,
          manualRevocationRequired: true,
        },
        originConnections: NO_ORIGIN_CONNECTIONS,
      });
    },
    scrub: () => { scrubbed = true; },
  });
  assert.equal(result.kind, 'deleted');
  assert.equal(randomCalls, 1);
  assert.equal(new Set(keys).size, 1);
  assert.match(keys[0] ?? '', /^v1\.[A-Za-z0-9_-]{43}$/);
  assert.equal(scrubbed, true);
  assert.equal(client.hasPendingAttempt(accountScope), false);
});

test('web account deletion retains the same durable attempt when local draft scrubbing fails', async () => {
  const accountScope = 'P'.repeat(43);
  const store = new MemoryAppleAccountDeletionAttemptStore();
  let randomCalls = 0;
  const client = new AppleAccountDeletionClient({
    randomBytes: count => { randomCalls += 1; return new Uint8Array(count).fill(13); },
    attemptStore: store,
    followUpStore: new MemoryAppleAccountDeletionAttemptStore(),
    now: () => INITIAL_TIME * 1_000,
  });
  const keys: string[] = [];
  const response = {
    deleted: true,
    idempotent: true,
    providerCredentials: {
      credentialsFound: 0,
      credentialsRevoked: 0,
      unreadableSessions: 0,
      failedRevocations: 0,
      manualRevocationRequired: true,
    },
    originConnections: NO_ORIGIN_CONNECTIONS,
  } as const;
  const fetcher: typeof fetch = async (_path, init) => {
    keys.push(new Headers(init?.headers).get('idempotency-key') ?? '');
    return Response.json(response);
  };
  await assert.rejects(client.deleteIfConfirmed({
    confirmed: true,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone',
    fetcher,
    scrub: () => { throw Error('injected IndexedDB purge failure'); },
  }), /injected IndexedDB purge failure/);
  assert.notEqual(store.value, null);
  const result = await client.deleteIfConfirmed({
    confirmed: true,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone',
    fetcher,
    scrub: () => undefined,
  });
  assert.equal(result.kind, 'deleted');
  assert.equal(randomCalls, 1);
  assert.equal(keys.length, 2);
  assert.equal(keys[0], keys[1]);
  assert.equal(store.value, null);
});

test('web account deletion recovers after reload with the same durable subject-scoped key', async () => {
  const accountScope = 'R'.repeat(43);
  const store = new MemoryAppleAccountDeletionAttemptStore();
  const keys: string[] = [];
  const first = new AppleAccountDeletionClient({
    randomBytes: count => new Uint8Array(count).fill(11),
    attemptStore: store,
    followUpStore: new MemoryAppleAccountDeletionAttemptStore(),
    now: () => INITIAL_TIME * 1_000,
  });
  await assert.rejects(first.deleteIfConfirmed({
    confirmed: true,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'linked',
    fetcher: async (_path, init) => {
      keys.push(new Headers(init?.headers).get('idempotency-key') ?? '');
      throw new TypeError('response lost after commit');
    },
    scrub: () => { throw new Error('unconfirmed response scrubbed state'); },
  }), /response lost after commit/);
  assert.notEqual(store.value, null);

  let randomCalls = 0;
  let scrubbed = false;
  const reloaded = new AppleAccountDeletionClient({
    randomBytes: count => { randomCalls += 1; return new Uint8Array(count).fill(12); },
    attemptStore: store,
    followUpStore: new MemoryAppleAccountDeletionAttemptStore(),
    now: () => INITIAL_TIME * 1_000 + 1,
  });
  assert.equal(reloaded.pendingAccountScope(), accountScope);
  assert.equal(reloaded.pendingWorkspaceScope(), WEB_WORKSPACE_SCOPE);
  assert.equal(reloaded.pendingAccountMode(), 'linked');
  const recovered = await reloaded.deleteIfConfirmed({
    confirmed: true,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'linked',
    fetcher: async (_path, init) => {
      keys.push(new Headers(init?.headers).get('idempotency-key') ?? '');
      return Response.json({
        deleted: true,
        idempotent: true,
        providerCredentials: {
          credentialsFound: 1,
          credentialsRevoked: 0,
          unreadableSessions: 0,
          failedRevocations: 1,
          manualRevocationRequired: true,
        },
        originConnections: NO_ORIGIN_CONNECTIONS,
      });
    },
    scrub: () => { scrubbed = true; },
  });
  assert.equal(recovered.kind, 'deleted');
  assert.equal(randomCalls, 0);
  assert.equal(keys.length, 2);
  assert.equal(keys[0], keys[1]);
  assert.equal(scrubbed, true);
  assert.equal(store.value, null);
});

test('web deletion retains and replays a valid uncertain key after a client clock jump', async () => {
  const accountScope='T'.repeat(43);
  const store=new MemoryAppleAccountDeletionAttemptStore();
  const keys:string[]=[];
  const first=new AppleAccountDeletionClient({
    attemptStore:store,
    followUpStore:new MemoryAppleAccountDeletionAttemptStore(),
    randomBytes:count=>new Uint8Array(count).fill(21),
    now:()=>INITIAL_TIME*1_000,
  });
  await assert.rejects(first.deleteIfConfirmed({
    confirmed:true,
    accountScope,
    workspaceScope:WEB_WORKSPACE_SCOPE,
    accountMode:'standalone',
    fetcher:async(_path,init)=>{
      keys.push(new Headers(init?.headers).get('idempotency-key')??'');
      throw new TypeError('offline before a response');
    },
    scrub:()=>undefined,
  }),/offline before a response/);
  const encodedAttempt=store.value;
  assert.notEqual(encodedAttempt,null);

  let randomCalls=0;
  const afterClockJump=new AppleAccountDeletionClient({
    attemptStore:store,
    followUpStore:new MemoryAppleAccountDeletionAttemptStore(),
    randomBytes:count=>{randomCalls+=1;return new Uint8Array(count).fill(22);},
    now:()=>INITIAL_TIME*1_000+31*24*60*60*1_000,
  });
  assert.equal(afterClockJump.pendingAccountScope(),accountScope);
  await afterClockJump.deleteIfConfirmed({
    confirmed:true,
    accountScope,
    workspaceScope:WEB_WORKSPACE_SCOPE,
    accountMode:'standalone',
    fetcher:async(_path,init)=>{
      keys.push(new Headers(init?.headers).get('idempotency-key')??'');
      return Response.json({
        deleted:true,
        idempotent:true,
        providerCredentials:{
          credentialsFound:0,
          credentialsRevoked:0,
          unreadableSessions:0,
          failedRevocations:0,
          manualRevocationRequired:true,
        },
        originConnections:NO_ORIGIN_CONNECTIONS,
      });
    },
    scrub:()=>undefined,
  });
  assert.equal(randomCalls,0);
  assert.equal(keys[0],keys[1]);
  assert.equal(store.value,null);
});

test('web deletion durably preserves Origin follow-up before clearing its receipt capability', async () => {
  const accountScope = 'F'.repeat(43);
  const attemptStore = new MemoryAppleAccountDeletionAttemptStore();
  const followUpStore = new MemoryAppleAccountDeletionAttemptStore();
  const client = new AppleAccountDeletionClient({
    attemptStore,
    followUpStore,
    randomBytes: count => new Uint8Array(count).fill(24),
    now: () => INITIAL_TIME * 1_000,
  });
  let scrubbed = false;
  await client.deleteIfConfirmed({
    confirmed: true,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone',
    fetcher: async () => Response.json({
      deleted: true,
      idempotent: false,
      providerCredentials: {
        credentialsFound: 1,
        credentialsRevoked: 1,
        unreadableSessions: 0,
        failedRevocations: 0,
        manualRevocationRequired: false,
      },
      originConnections: {
        installationsFound: 1,
        installationsRevoked: 0,
        unreadableInstallations: 0,
        failedRevocations: 1,
        manualRevocationRequired: true,
      },
    }),
    scrub: () => { scrubbed = true; },
  });
  assert.equal(scrubbed, true);
  assert.equal(attemptStore.value, null);
  const reloaded = new AppleAccountDeletionClient({attemptStore, followUpStore});
  assert.deepEqual(reloaded.pendingManualFollowUp(), {
    schemaVersion: 1,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone',
    providerManualRevocationRequired: false,
    originManualRevocationRequired: true,
    createdAt: INITIAL_TIME * 1_000,
  });
  let replacementRequests = 0;
  await assert.rejects(reloaded.deleteIfConfirmed({
    confirmed: true,
    accountScope: 'G'.repeat(43),
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone',
    fetcher: async () => {
      replacementRequests += 1;
      return Response.json({});
    },
    scrub: () => undefined,
  }), AppleAccountDeletionIdentityMismatchError);
  assert.equal(replacementRequests, 0);
  reloaded.dismissManualFollowUp();
  assert.equal(followUpStore.value, null);

  const failedAttemptStore = new MemoryAppleAccountDeletionAttemptStore();
  const failedFollowUpStore = new MemoryAppleAccountDeletionAttemptStore();
  failedFollowUpStore.failWrites = true;
  let failedScrub = false;
  const failed = new AppleAccountDeletionClient({
    attemptStore: failedAttemptStore,
    followUpStore: failedFollowUpStore,
    randomBytes: count => new Uint8Array(count).fill(25),
    now: () => INITIAL_TIME * 1_000,
  });
  await assert.rejects(failed.deleteIfConfirmed({
    confirmed: true,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone',
    fetcher: async () => Response.json({
      deleted: true,
      idempotent: true,
      providerCredentials: {
        credentialsFound: 0,
        credentialsRevoked: 0,
        unreadableSessions: 0,
        failedRevocations: 0,
        manualRevocationRequired: true,
      },
      originConnections: NO_ORIGIN_CONNECTIONS,
    }),
    scrub: () => { failedScrub = true; },
  }), /durable storage unavailable/);
  assert.notEqual(failedAttemptStore.value, null);
  assert.equal(failedScrub, true);
});

test('web deletion storage fails closed and never reuses a pending key across Apple identities', async () => {
  const scopeA = 'A'.repeat(43);
  const scopeB = 'B'.repeat(43);
  const unwritable = new MemoryAppleAccountDeletionAttemptStore();
  unwritable.failWrites = true;
  const blocked = new AppleAccountDeletionClient({
    randomBytes: count => new Uint8Array(count).fill(3),
    attemptStore: unwritable,
    now: () => INITIAL_TIME * 1_000,
  });
  let requests = 0;
  await assert.rejects(blocked.deleteIfConfirmed({
    confirmed: true,
    accountScope: scopeA,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'linked',
    fetcher: async () => { requests += 1; return Response.json({}); },
    scrub: () => undefined,
  }), /durable storage unavailable/);
  assert.equal(requests, 0);

  const shared = new MemoryAppleAccountDeletionAttemptStore();
  const client = new AppleAccountDeletionClient({
    randomBytes: count => new Uint8Array(count).fill(4),
    attemptStore: shared,
    now: () => INITIAL_TIME * 1_000,
  });
  await assert.rejects(client.deleteIfConfirmed({
    confirmed: true,
    accountScope: scopeA,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'linked',
    fetcher: async () => { throw new TypeError('uncertain'); },
    scrub: () => undefined,
  }), /uncertain/);
  await assert.rejects(client.deleteIfConfirmed({
    confirmed: true,
    accountScope: scopeA,
    workspaceScope: 'X'.repeat(32),
    accountMode: 'linked',
    fetcher: async () => { requests += 1; return Response.json({}); },
    scrub: () => undefined,
  }), error => error instanceof AppleAccountDeletionIdentityMismatchError);
  await assert.rejects(client.deleteIfConfirmed({
    confirmed: true,
    accountScope: scopeB,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'linked',
    fetcher: async () => { requests += 1; return Response.json({}); },
    scrub: () => undefined,
  }), error => error instanceof AppleAccountDeletionIdentityMismatchError);
  assert.equal(requests, 0);

  shared.value = '{}';
  assert.throws(
    () => client.pendingAccountScope(),
    error => error instanceof AppleAccountDeletionAttemptInvalidError,
  );
  assert.equal(shared.value, '{}');
});

test('account deletion success invalidates other open dashboard tabs', () => {
  const listeners = new Set<(value: unknown) => void>();
  const transport: AppleAccountLifecycleInvalidationTransport = {
    publish(value) { for (const listener of listeners) listener(value); },
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
  };
  let publishedEvents=0;
  const first = new AppleAccountLifecycleInvalidationBus({
    transport,
    randomBytes: count => new Uint8Array(count).fill(5+(publishedEvents+=1)),
    now: () => INITIAL_TIME * 1_000,
  });
  const second = new AppleAccountLifecycleInvalidationBus({
    transport,
    randomBytes: count => new Uint8Array(count).fill(6),
    now: () => INITIAL_TIME * 1_000,
  });
  const received: AppleAccountLifecycleInvalidation[] = [];
  const unsubscribe = second.subscribe(event => received.push(event));
  first.publishLock(WEB_WORKSPACE_SCOPE);
  first.publish(true, false, 'linked', WEB_WORKSPACE_SCOPE);
  unsubscribe();
  assert.deepEqual(received, [
    {kind: 'lock', workspaceScope: WEB_WORKSPACE_SCOPE},
    {kind: 'deleted', workspaceScope: WEB_WORKSPACE_SCOPE, accountMode: 'linked', manualRevocationRequired: true, originManualRevocationRequired: false},
  ]);
});

test('web account deletion invalidates other tabs before an autosave cleanup barrier settles', async () => {
  const listeners = new Set<(value: unknown) => void>();
  const transport: AppleAccountLifecycleInvalidationTransport = {
    publish(value) { for (const listener of listeners) listener(value); },
    subscribe(listener) { listeners.add(listener); return () => listeners.delete(listener); },
  };
  let publishedEvents=0;
  const publishingBus = new AppleAccountLifecycleInvalidationBus({transport,randomBytes:count=>new Uint8Array(count).fill(14+(publishedEvents+=1)),now:()=>INITIAL_TIME*1_000});
  const receivingBus = new AppleAccountLifecycleInvalidationBus({transport,randomBytes:count=>new Uint8Array(count).fill(15),now:()=>INITIAL_TIME*1_000});
  const received: AppleAccountLifecycleInvalidation[]=[];receivingBus.subscribe(event=>received.push(event));
  const cleanup=Promise.withResolvers<void>();const attemptStore=new MemoryAppleAccountDeletionAttemptStore();
  const client=new AppleAccountDeletionClient({attemptStore,followUpStore:new MemoryAppleAccountDeletionAttemptStore(),randomBytes:count=>new Uint8Array(count).fill(16),now:()=>INITIAL_TIME*1_000});
  const deletion=client.deleteIfConfirmed({
    confirmed:true,accountScope:'L'.repeat(43),workspaceScope:WEB_WORKSPACE_SCOPE,accountMode:'standalone',
    fetcher:async()=>Response.json({deleted:true,idempotent:false,providerCredentials:{credentialsFound:0,credentialsRevoked:0,unreadableSessions:0,failedRevocations:0,manualRevocationRequired:true},originConnections:NO_ORIGIN_CONNECTIONS}),
    scrub:async response=>{publishingBus.publishLock(WEB_WORKSPACE_SCOPE);await cleanup.promise;publishingBus.publish(response.providerCredentials.manualRevocationRequired,response.originConnections.manualRevocationRequired,'standalone',WEB_WORKSPACE_SCOPE);},
  });
  await new Promise(resolve=>setImmediate(resolve));
  assert.deepEqual(received,[{kind:'lock',workspaceScope:WEB_WORKSPACE_SCOPE}]);
  assert.notEqual(attemptStore.value,null);
  cleanup.resolve();await deletion;
  assert.deepEqual(received.at(-1),{kind:'deleted',workspaceScope:WEB_WORKSPACE_SCOPE,accountMode:'standalone',manualRevocationRequired:true,originManualRevocationRequired:false});
  assert.equal(attemptStore.value,null);
});

test('web account deletion rejects unbounded or non-strict success responses without scrubbing', async () => {
  const accountScope = 'A'.repeat(43);
  const client = new AppleAccountDeletionClient({
    randomBytes: count => new Uint8Array(count).fill(9),
    attemptStore: new MemoryAppleAccountDeletionAttemptStore(),
    now: () => INITIAL_TIME * 1_000,
  });
  let scrubbed = false;
  const input = {
    confirmed: true,
    accountScope,
    workspaceScope: WEB_WORKSPACE_SCOPE,
    accountMode: 'standalone' as const,
    scrub: () => { scrubbed = true; },
  };
  await assert.rejects(
    client.deleteIfConfirmed({
      ...input,
      fetcher: async () => Response.json({
        deleted: true,
        idempotent: false,
        providerCredentials: {
          credentialsFound: 0,
          credentialsRevoked: 0,
          unreadableSessions: 0,
          failedRevocations: 0,
          manualRevocationRequired: true,
        },
        unexpected: true,
      }),
    }),
    /response was invalid/,
  );
  await assert.rejects(
    client.deleteIfConfirmed({
      ...input,
      fetcher: async () => new Response('{}', {
        headers: {'Content-Type': 'application/json', 'Content-Length': '9000'},
      }),
    }),
    /invalid or too large/,
  );
  await assert.rejects(
    client.deleteIfConfirmed({
      ...input,
      fetcher: async () => Response.json({
        deleted: true,
        idempotent: true,
        providerCredentials: {
          credentialsFound: 0,
          credentialsRevoked: 0,
          unreadableSessions: 0,
          failedRevocations: 0,
          manualRevocationRequired: false,
        },
      }),
    }),
    /response was invalid/,
  );
  assert.equal(scrubbed, false);
  assert.equal(client.hasPendingAttempt(accountScope), true);
});

test('client revocation scrubs before a pending request settles and preserves its error', async () => {
  const failure = new Error('Apple did not confirm token revocation.');
  const pending = Promise.withResolvers<void>();
  let scrubbed = false;
  const revocation = revokeAppleSessionAndScrub({
    revoke: () => pending.promise,
    scrub: () => { scrubbed = true; },
  });
  assert.equal(scrubbed, true);
  pending.reject(failure);
  await assert.rejects(revocation, error => error === failure);
});

test('workspace generation blocks delayed load, read, and save commits after invalidation', async () => {
  const generation = new WorkspaceSessionGeneration();
  const load = Promise.withResolvers<string>();
  const read = Promise.withResolvers<string>();
  const save = Promise.withResolvers<string>();
  const failedRead = Promise.withResolvers<string>();
  const committed: string[] = [];
  const operations = [
    generation.run({request: () => load.promise, onSuccess: value => committed.push(`load:${value}`), onFailure: () => committed.push('load:error')}),
    generation.run({request: () => read.promise, onSuccess: value => committed.push(`read:${value}`), onFailure: () => committed.push('read:error')}),
    generation.run({request: () => save.promise, onSuccess: value => committed.push(`save:${value}`), onFailure: () => committed.push('save:error')}),
    generation.run({request: () => failedRead.promise, onSuccess: value => committed.push(`failed-read:${value}`), onFailure: () => committed.push('failed-read:error')}),
  ];
  generation.invalidate();
  load.resolve('old workspace');
  read.resolve('old file read');
  save.resolve('old file save');
  failedRead.reject(new Error('old read failed'));
  assert.deepEqual(await Promise.all(operations), [
    {kind: 'stale'},
    {kind: 'stale'},
    {kind: 'stale'},
    {kind: 'stale'},
  ]);
  assert.equal(committed.length, 0);

  const delayedSyncScope = generation.bind();
  generation.invalidate();
  let restoredSyncState = false;
  assert.deepEqual(delayedSyncScope.commit(() => { restoredSyncState = true; }), {kind: 'stale'});
  assert.equal(restoredSyncState, false);

  const delayedDashboardScope = generation.bind();
  generation.invalidate();
  let restoredPlan = false;
  let restoredGitHubToken = false;
  assert.deepEqual(delayedDashboardScope.commit(() => { restoredPlan = true; }), {kind: 'stale'});
  assert.deepEqual(delayedDashboardScope.commit(() => { restoredGitHubToken = true; }), {kind: 'stale'});
  assert.equal(restoredPlan, false);
  assert.equal(restoredGitHubToken, false);

  const retiredAutosaveSession = generation.bind();
  generation.invalidate();
  let lateRequestCount = 0;
  const lateResult = await retiredAutosaveSession.run<string, number>({
    request: async () => { lateRequestCount += 1; return 'late save'; },
    onSuccess: value => committed.push(value),
    onFailure: () => committed.push('late:error'),
  });
  assert.deepEqual(lateResult, {kind: 'stale'});
  assert.equal(lateRequestCount, 0);
  assert.equal(committed.length, 0);
});

test('dashboard 401 scrubs loaded, unlocked, and connected state before a stale response settles', async () => {
  const projectRoot = fileURLToPath(new URL('..', import.meta.url));
  const dashboardPath = fileURLToPath(new URL('../app/dashboard.tsx', import.meta.url));
  const dashboard = (await runnerImport<typeof import('../app/dashboard.tsx')>(dashboardPath, {
    root: projectRoot,
    resolve: {alias: {'@': projectRoot}},
  })).module;
  const generation = new WorkspaceSessionGeneration();
  const sensitive = {
    workspacePlaintext: 'private workspace content',
    autosavePlaintext: 'unsaved private draft',
    githubToken: 'github_pat_private',
    syncKey: 'unlocked content-encryption key',
    recoveryMaterial: 'private recovery passphrase',
    authenticated: true,
    editorVisible: true,
  };
  const scrubOrder: string[] = [];
  const scrub = () => dashboard.scrubDashboardSensitiveState({
    invalidateGeneration: () => { scrubOrder.push('generation'); generation.invalidate(); },
    retireAutosave: () => { scrubOrder.push('autosave'); sensitive.autosavePlaintext = ''; },
    clearWorkspacePlaintext: () => { scrubOrder.push('workspace'); sensitive.workspacePlaintext = ''; },
    clearGitHubToken: () => { scrubOrder.push('github'); sensitive.githubToken = ''; },
    clearSyncSecrets: () => { scrubOrder.push('sync'); sensitive.syncKey = ''; sensitive.recoveryMaterial = ''; },
    clearAuthenticationState: () => { scrubOrder.push('authentication'); sensitive.authenticated = false; },
    hideWorkspace: () => { scrubOrder.push('editor'); sensitive.editorVisible = false; },
  });
  const delayedLoad = Promise.withResolvers<typeof sensitive>();
  const staleLoad = generation.run({
    request: () => delayedLoad.promise,
    onSuccess: value => { Object.assign(sensitive, value); },
    onFailure: () => { throw new Error('a stale load failure must not commit'); },
  });
  const sessionLoss = new dashboard.RequestError(401, {error: 'Session expired.'});

  await assert.rejects(
    dashboard.runAuthenticatedDashboardRequest(async () => { throw sessionLoss; }, reason => {
      scrub();
      assert.equal(reason, sessionLoss);
      assert.deepEqual(sensitive, {
        workspacePlaintext: '',
        autosavePlaintext: '',
        githubToken: '',
        syncKey: '',
        recoveryMaterial: '',
        authenticated: false,
        editorVisible: false,
      });
    }),
    reason => reason === sessionLoss,
  );
  assert.deepEqual(scrubOrder, ['generation', 'autosave', 'workspace', 'github', 'sync', 'authentication', 'editor']);

  delayedLoad.resolve({
    workspacePlaintext: 'late private workspace content',
    autosavePlaintext: 'late private draft',
    githubToken: 'late_github_pat',
    syncKey: 'late content-encryption key',
    recoveryMaterial: 'late recovery passphrase',
    authenticated: true,
    editorVisible: true,
  });
  assert.deepEqual(await staleLoad, {kind: 'stale'});
  assert.deepEqual(sensitive, {
    workspacePlaintext: '',
    autosavePlaintext: '',
    githubToken: '',
    syncKey: '',
    recoveryMaterial: '',
    authenticated: false,
    editorVisible: false,
  });
});

test('dashboard routes every authenticated request through its 401 scrub boundary', async () => {
  const dashboard = await readFile(new URL('../app/dashboard.tsx', import.meta.url), 'utf8');
  assert.equal((dashboard.match(/fetch\(/g)??[]).length, 1, 'dashboard requests must share one raw fetch boundary');
  assert.match(dashboard, /runAuthenticatedDashboardRequest\(\(\)=>requestJSON\(path,body\),handleAuthenticationLoss\)/);
  assert.match(dashboard, /handleAuthenticationLoss=useCallback\(\(reason:RequestError\)=>\{scrubLoadedWorkspace\(\);setAuthRequired\(true\)/);
  assert.match(dashboard, /clearWorkspacePlaintext:\(\)=>\{[\s\S]*setData\(emptyWorkspace\)/);
  assert.match(dashboard, /clearGitHubToken:\(\)=>setGitSession\(null\)/);
  assert.match(dashboard, /clearSyncSecrets:\(\)=>\{setSyncClient\(null\);[\s\S]*setSyncPassphrase\(''\)/);
  assert.match(dashboard, /retireAutosave:\(\)=>autosaveSlot\.replace\(null\)/);
  assert.match(dashboard, /hideWorkspace:\(\)=>\{setLoaded\(false\);setWorkspaceMounted\(false\)/);
  assert.match(dashboard, /\{workspaceMounted\?<><Sidebar/);
});

test('ambiguous web authentication exposes an Apple-session recovery action', async () => {
  const dashboard = await readFile(new URL('../app/dashboard.tsx', import.meta.url), 'utf8');
  assert.match(dashboard, /AUTH_SESSION_AMBIGUOUS/);
  assert.match(dashboard, /authSessionAmbiguous\?<div className="splash-actions">/);
  assert.match(dashboard, /Clear Apple session/);
  assert.match(dashboard, /revokeAppleSessionAndScrub/);
  for (const guardedRequest of [
    "request:async()=>workspaceSchema.parse(await request('/api/workspace'))",
    "request:async()=>fileResponseSchema.parse(await request('/api/files',{kind:'save'",
    'request:async()=>fileResponseSchema.parse(await request(`/api/files?path=',
  ]) {
    assert.ok(dashboard.includes(guardedRequest), `missing guarded dashboard request: ${guardedRequest}`);
  }
  assert.ok(dashboard.includes('const autosaveSession=bindWorkspaceSession();'));
  assert.equal(dashboard.match(/await autosaveSession\.run\(/g)?.length, 2);
  assert.equal(dashboard.match(/setData\(current=>current\.workspaceId===workspaceId\?/g)?.length, 2);
  const scrub = dashboard.indexOf('const scrubLoadedWorkspace=useCallback(()=>{');
  const invalidate = dashboard.indexOf('workspaceSessionGeneration.invalidate();', scrub);
  const clear = dashboard.indexOf('setData(emptyWorkspace)', scrub);
  assert.ok(scrub >= 0 && invalidate > scrub && clear > invalidate, 'scrub must invalidate before clearing workspace data');
});

test('dashboard keeps disconnect separate from explicitly confirmed account deletion', async () => {
  const dashboard = await readFile(new URL('../app/dashboard.tsx', import.meta.url), 'utf8');
  assert.match(dashboard, /Disconnect & revoke Apple token/);
  assert.match(dashboard, /Delete account and server data/);
  assert.match(dashboard, /Permanently delete account/);
  assert.match(dashboard, /Removing this Apple link preserves the ChatGPT-owned workspace and other linked Apple identities/);
  assert.match(dashboard, /retaining the ChatGPT-owned workspace, its Local Sandbox server data, your ChatGPT account, and other linked Apple identities/);
  assert.match(dashboard, /Selected Files and iCloud documents stay on your devices/);
  assert.match(dashboard, /pendingWorkspaceScope=appleAccountDeletion\.pendingWorkspaceScope\(\)/);
  const deletionScrub=dashboard.indexOf('scrub:async response=>{const cleanup=scrubDeletedWorkspace(workspaceScope);');
  const lockPublish=dashboard.indexOf('appleAccountLifecycle.publishLock(workspaceScope)',deletionScrub);
  const cleanupAwait=dashboard.indexOf('await cleanup',deletionScrub);
  const lifecyclePublish=dashboard.indexOf('appleAccountLifecycle.publish(',deletionScrub);
  assert.ok(deletionScrub>=0&&lockPublish>deletionScrub&&cleanupAwait>lockPublish&&lifecyclePublish>cleanupAwait,'account deletion must publish an immediate lock, then publish completion only after local draft cleanup');
  const scrubHelper=dashboard.slice(dashboard.indexOf('const scrubDeletedWorkspace=useCallback'),dashboard.indexOf('useEffect(()=>appleAccountLifecycle.subscribe'));
  assert.ok(scrubHelper.indexOf('autosave?.disposeAndDrain()')<scrubHelper.indexOf('scrubLoadedWorkspace()')&&scrubHelper.indexOf('scrubLoadedWorkspace()')<scrubHelper.indexOf('await autosaveBarrier')&&scrubHelper.indexOf('await autosaveBarrier')<scrubHelper.indexOf('await hostedDraftJournal().purge(workspaceScope)'),'account deletion must retire and drain autosave before purging IndexedDB drafts');
  assert.match(dashboard,/requireWorkspaceCommit\(scope,\(\)=>\{setSyncClient\(client\)/);
  assert.match(dashboard,/prepare:async\(goal\)=>\{const scope=bindWorkspaceSession\(\);[\s\S]*return requireWorkspaceCommit\(scope,\(\)=>\{setTask\(goal\);setPlan\(result\);setPage\('oracle'\)/);
  assert.match(dashboard,/async function buildPlan\(\)[\s\S]*const scope=bindWorkspaceSession\(\);[\s\S]*requireWorkspaceCommit\(scope,\(\)=>\{setPlan\(result\);setPage\('oracle'\)/);
  assert.match(dashboard,/async function runCheck\(\)[\s\S]*await load\(\);requireWorkspaceCommit\(scope,\(\)=>\{setReceipt\(result\)/);
  const connections = await readFile(new URL('../app/connections.tsx', import.meta.url), 'utf8');
  assert.match(connections,/const scope=bindWorkspaceSession\(\);const submittedToken=fineGrainedGitHubToken\(token\);[\s\S]*commitWorkspace\(scope,\(\)=>\{onSession\(\{login:user\.login,token:submittedToken\}\)/);
  assert.equal((dashboard.match(/bindWorkspaceSession=\{bindWorkspaceSession\}/g)??[]).length,2);
  assert.match(dashboard, /<AlertDialogCancel disabled=\{!!busy\}>Keep account<\/AlertDialogCancel>/);
});

test('possible Apple credential review uses a bounded exact contract and visible reviewed resolution', async () => {
  const acknowledgementId='A'.repeat(43);
  assert.deepEqual(await readAppleCredentialReviewAcknowledgementRequest(new Request(
    'https://local.example/api/auth/apple/possible-credential',
    {
      method:'POST',
      headers:{'Content-Type':'application/json; charset=utf-8'},
      body:JSON.stringify({acknowledgementId}),
    },
  )),{acknowledgementId});
  const requestFailure=(code:string)=>(reason:unknown)=>reason instanceof AppleCredentialReviewRequestError
    && reason.code===code;
  await assert.rejects(
    readAppleCredentialReviewAcknowledgementRequest(new Request(
      'https://local.example/api/auth/apple/possible-credential',
      {method:'POST',body:JSON.stringify({acknowledgementId})},
    )),
    requestFailure('APPLE_AUTH_REQUEST_CONTENT_TYPE'),
  );
  await assert.rejects(
    readAppleCredentialReviewAcknowledgementRequest(new Request(
      'https://local.example/api/auth/apple/possible-credential',
      {method:'POST',headers:{'Content-Type':'application/json','Content-Length':'invalid'},body:'{}'},
    )),
    requestFailure('APPLE_AUTH_REQUEST_CONTENT_LENGTH'),
  );
  await assert.rejects(
    readAppleCredentialReviewAcknowledgementRequest(new Request(
      'https://local.example/api/auth/apple/possible-credential',
      {method:'POST',headers:{'Content-Type':'application/json'},body:'x'.repeat(APPLE_CREDENTIAL_REVIEW_REQUEST_MAXIMUM_BYTES+1)},
    )),
    requestFailure('APPLE_AUTH_REQUEST_TOO_LARGE'),
  );
  await assert.rejects(
    readAppleCredentialReviewAcknowledgementRequest(new Request(
      'https://local.example/api/auth/apple/possible-credential',
      {method:'POST',headers:{'Content-Type':'application/json'},body:Uint8Array.of(0xc3,0x28)},
    )),
    requestFailure('APPLE_AUTH_REQUEST_ENCODING'),
  );
  await assert.rejects(
    readAppleCredentialReviewAcknowledgementRequest(new Request(
      'https://local.example/api/auth/apple/possible-credential',
      {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({acknowledgementId,extra:true})},
    )),
    requestFailure('APPLE_AUTH_REQUEST_INVALID'),
  );
  assert.deepEqual(appleCredentialReviewResponseSchema.parse({
    manualReviewRequired:true,
    acknowledgementId,
    markedAt:INITIAL_TIME,
  }),{manualReviewRequired:true,acknowledgementId,markedAt:INITIAL_TIME});
  assert.throws(()=>appleCredentialReviewResponseSchema.parse({
    manualReviewRequired:false,
    acknowledgementId,
    markedAt:null,
  }));
  assert.deepEqual(
    appleCredentialReviewAcknowledgementResponseSchema.parse({acknowledged:true}),
    {acknowledged:true},
  );
  assert.throws(()=>appleCredentialReviewAcknowledgementResponseSchema.parse({acknowledged:true,extra:true}));

  const route=await readFile(new URL('../app/api/auth/apple/possible-credential/route.ts',import.meta.url),'utf8');
  assert.match(route,/parseAppleNativeBearer/);
  assert.match(route,/requireSameOrigin\(request\)/);
  assert.match(route,/readAppleCredentialReviewAcknowledgementRequest\(request\)/);
  assert.doesNotMatch(route,/request\.text\(\)/);
  const reviewPost=route.slice(route.indexOf('export async function POST'));
  assert.ok(
    reviewPost.indexOf('requireSameOrigin(request)')<reviewPost.indexOf('requireReviewAuthorization(request, bearer)'),
    'web credential-review CSRF validation must precede session/provider work',
  );
  const dashboard=await readFile(new URL('../app/dashboard.tsx',import.meta.url),'utf8');
  assert.match(dashboard,/https:\/\/account\.apple\.com\//);
  assert.match(dashboard,/target="_blank" rel="noreferrer"/);
  assert.match(dashboard,/Detected \{new Date\(\(appleCredentialReview\.markedAt\?\?0\)\*1000\)\.toLocaleString\(\)\}/);
  const acknowledgementFunction=dashboard.slice(
    dashboard.indexOf('async function acknowledgeAppleCredentialReview'),
    dashboard.indexOf('async function deleteAppleAccountFromDashboard'),
  );
  const confirmation=acknowledgementFunction.indexOf('appleCredentialReviewAcknowledgementResponseSchema.parse(await request');
  const finalRead=acknowledgementFunction.indexOf("appleCredentialReviewResponseSchema.parse(await request('/api/auth/apple/possible-credential'))",confirmation);
  const applyCurrent=acknowledgementFunction.indexOf('setAppleCredentialReview(current)',finalRead);
  assert.ok(
    confirmation>=0&&finalRead>confirmation&&applyCurrent>finalRead,
    'the warning may change only after exact acknowledgement and a final current-state read',
  );
  assert.doesNotMatch(acknowledgementFunction,/setAppleCredentialReview\(null\)/);
  assert.match(dashboard,/APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED/,'changed review state must refresh before retry');
  assert.match(dashboard,/APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS/,'an active sign-in must refresh review state');
});

test('account deletion route validates transport and principals before capability replay', async () => {
  const route = await readFile(new URL('../app/api/auth/apple/delete/route.ts', import.meta.url), 'utf8');
  const ambientCookieRejection = route.indexOf("if (request.headers.has('cookie'))");
  const nativePrincipalRead = route.indexOf('const principal = await readAppleNativeSession');
  const nativeReplay = route.indexOf('const replay = await recoverAppleAccountDeletion');
  assert.ok(
    ambientCookieRejection >= 0 && nativePrincipalRead > ambientCookieRejection && nativeReplay > nativePrincipalRead,
    'native transport or principal validation moved after receipt replay',
  );
  assert.match(route, /if \(principal === null\) \{[\s\S]*recoverAppleAccountDeletion/);
  assert.match(route, /const ownerId = principal\.ownerId;[\s\S]*deleteAppleAccount\(\{/);
  assert.match(route, /deletionResponse\(replay, false\)/);
  assert.match(route, /clearWebCookie \? \{'Set-Cookie': clearSessionCookie\(\)\} : \{\}/);

  const sessionRoute = await readFile(new URL('../app/api/auth/apple/session/route.ts', import.meta.url), 'utf8');
  assert.match(sessionRoute, /mode: appleAccountModeForOwner\(principal\.ownerId\)/);
  assert.match(sessionRoute, /deletion-scope\\0\$\{principal\.ownerId\}\\0\$\{principal\.appleSubjectHash\}/);
  assert.doesNotMatch(sessionRoute, /hostUser===null\s*\?\s*['"]standalone/);
});

test('a mapped v1 session is authenticated before lazy v2 re-encryption', async () => {
  const fixture = await createFixture();
  const sessionToken = `v1.${'L'.repeat(43)}`;
  const legacy = await fixture.seedLegacySession({
    sessionToken,
    ownerId: 'legacy-owner',
    subject: 'legacy-apple-subject',
    displayName: 'Legacy Apple User',
  });
  assert.equal(legacy.schemaVersion, 1);
  assert.match(legacy.encryptedCredentials, /^v1\./);
  for (const plaintext of ['legacy-apple-subject', 'legacy-refresh-token', 'legacy-access-token']) {
    assert.equal(JSON.stringify(legacy).includes(plaintext), false);
  }

  const principal = await readAppleSessionLocalPrincipal(fixture.dependencies, sessionToken);
  assert.equal(principal?.ownerId, 'legacy-owner');
  assert.equal(principal?.identity.displayName, 'Legacy Apple User');
  const upgraded = fixture.repository.sessions.get(legacy.sessionHash);
  assert.equal(upgraded?.schemaVersion, 2);
  assert.match(upgraded?.encryptedCredentials ?? '', /^v2\./);
  assert.notEqual(upgraded?.encryptedCredentials, legacy.encryptedCredentials);
  assert.equal((await readAppleSessionLocalPrincipal(fixture.dependencies, sessionToken))?.ownerId, 'legacy-owner');
});

test('D1 consumes a flow once and enforces session owner, expiry, update, and revocation', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    const baseMigration = await readFile('drizzle/0000_dashing_epoch.sql', 'utf8');
    for (const statement of baseMigration.split('--> statement-breakpoint').map(value => value.trim()).filter(Boolean)) {
      await database.prepare(statement).run();
    }
    const migration = await readFile('drizzle/0001_eager_sheva_callister.sql', 'utf8');
    for (const statement of migration.split('--> statement-breakpoint').map(value => value.trim()).filter(Boolean)) {
      await database.prepare(statement).run();
    }
    for (const name of [
      '0002_shallow_sabra.sql',
      '0003_wet_edwin_jarvis.sql',
      '0004_native_apple_bridge.sql',
      '0005_sync_snapshot_revision.sql',
    ]) {
      const migrationStep = await readFile(`drizzle/${name}`, 'utf8');
      for (const statement of migrationStep.split('--> statement-breakpoint').map(value => value.trim()).filter(Boolean)) {
        await database.prepare(statement).run();
      }
    }
    await database.prepare(
      'INSERT INTO apple_identity_links(apple_subject_hash,owner_id,created_at,updated_at) VALUES(?,?,?,?)',
    ).bind('f'.repeat(43), 'owner-a', INITIAL_TIME, INITIAL_TIME).run();
    await database.prepare(
      'INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,?,?,?)',
    ).bind('owner-a', '{"cloudAllowed":false}', '["existing"]', 7).run();
    await database.prepare(
      `INSERT INTO apple_auth_flows(
        schema_version,state_hash,nonce_hash,browser_binding_hash,owner_binding,
        return_to,created_at,expires_at,consumed_at
      ) VALUES(?,?,?,?,?,?,?,?,NULL)`,
    ).bind(1, 'a'.repeat(43), 'b'.repeat(43), 'c'.repeat(43), 'd'.repeat(43), '/', INITIAL_TIME, INITIAL_TIME + 600).run();
    await database.prepare(
      `INSERT INTO apple_auth_sessions(
        schema_version,session_hash,owner_binding,apple_subject_hash,encrypted_credentials,
        created_at,expires_at,last_validated_at,revoked_at
      ) VALUES(?,?,?,?,?,?,?,?,NULL)`,
    ).bind(1, 'e'.repeat(43), 'd'.repeat(43), 'f'.repeat(43), `v1.${'g'.repeat(16)}.${'h'.repeat(32)}`, INITIAL_TIME, INITIAL_TIME + 600, INITIAL_TIME).run();
    await database.prepare(
      `INSERT INTO apple_auth_sessions(
        schema_version,session_hash,owner_binding,apple_subject_hash,encrypted_credentials,
        created_at,expires_at,last_validated_at,revoked_at
      ) VALUES(?,?,?,?,?,?,?,?,NULL)`,
    ).bind(1, 'u'.repeat(43), 'v'.repeat(43), 'w'.repeat(43), `v1.${'x'.repeat(16)}.${'y'.repeat(32)}`, INITIAL_TIME, INITIAL_TIME + 600, INITIAL_TIME).run();
    const authUpgrade = await readFile('drizzle/0006_dear_luckman.sql', 'utf8');
    for (const statement of authUpgrade.split('--> statement-breakpoint').map(value => value.trim()).filter(Boolean)) {
      await database.prepare(statement).run();
    }
    const lifecycleMigration = await readFile('drizzle/0007_puzzling_tempest.sql', 'utf8');
    for (const statement of lifecycleMigration.split('--> statement-breakpoint').map(value => value.trim()).filter(Boolean)) {
      await database.prepare(statement).run();
    }
    const flowCount = await database.prepare('SELECT COUNT(*) AS count FROM apple_auth_flows').first() as {count: number} | null;
    assert.equal(flowCount?.count, 0);
    assert.deepEqual(
      (await database.prepare('SELECT session_hash,owner_id,schema_version FROM apple_auth_sessions').all()).results,
      [{session_hash: 'e'.repeat(43), owner_id: 'owner-a', schema_version: 1}],
    );
    assert.deepEqual(
      await database.prepare('SELECT owner_id FROM apple_identity_links WHERE apple_subject_hash=?').bind('f'.repeat(43)).first(),
      {owner_id: 'owner-a'},
    );
    assert.deepEqual(
      await database.prepare('SELECT policy,completed,revision FROM workspaces WHERE user_id=?').bind('owner-a').first(),
      {policy: '{"cloudAllowed":false}', completed: '["existing"]', revision: 7},
    );
    const sessionColumns = await database.prepare('PRAGMA table_info(apple_auth_sessions)').all() as {results: {name: string; notnull: number}[]};
    assert.equal(sessionColumns.results.find(column => column.name === 'owner_id')?.notnull, 1);
    const deletionIndexes = await database.prepare("PRAGMA index_list('apple_account_deletions')").all() as {results: {name: string}[]};
    assert.deepEqual(
      deletionIndexes.results.map(index => index.name).filter(name => name.startsWith('apple_account_deletions_')).sort(),
      [
        'apple_account_deletions_linked_lease_idx',
        'apple_account_deletions_owner_subject_expiry_idx',
        'apple_account_deletions_standalone_lease_idx',
        'apple_account_deletions_subject_expiry_idx',
      ],
    );
    for (const name of [
      '0008_long_fat_cobra.sql',
      '0009_apple_identity_principals.sql',
      '0010_native_apple_grants.sql',
      '0011_durable_deletion_subjects.sql',
      '0012_owner_external_operation_leases.sql',
      '0013_general_external_operation_leases.sql',
      '0014_native_apple_session_activation.sql',
    ]) {
      const hardeningMigration = await readFile(`drizzle/${name}`, 'utf8');
      for (const statement of hardeningMigration
        .split('--> statement-breakpoint')
        .map(value => value.trim())
        .filter(Boolean)) {
        await database.prepare(statement).run();
      }
    }
    assert.deepEqual(
      await database.prepare(
        `SELECT owner_id,principal_id,principal_created_at
         FROM apple_identity_links WHERE apple_subject_hash=?`,
      ).bind('f'.repeat(43)).first(),
      {
        owner_id: 'owner-a',
        principal_id: 'f'.repeat(43),
        principal_created_at: INITIAL_TIME,
      },
    );
    const repository = createD1AppleAuthRepository(database);
    const flow: AppleAuthFlow = {
      schemaVersion: 2,
      stateHash: 'a'.repeat(43),
      purpose: 'link',
      ownerId: 'owner-a',
      nonceHash: 'b'.repeat(43),
      browserBindingHash: 'c'.repeat(43),
      ownerBinding: 'd'.repeat(43),
      returnTo: '/',
      createdAt: INITIAL_TIME,
      expiresAt: INITIAL_TIME + 600,
    };
    await repository.createFlow(flow);
    const consumed = await Promise.all([
      repository.consumeFlow(flow.stateHash, INITIAL_TIME + 1),
      repository.consumeFlow(flow.stateHash, INITIAL_TIME + 1),
    ]);
    assert.equal(consumed.filter(Boolean).length, 1);
    assert.deepEqual(consumed.find(Boolean), flow);

    const session: AppleAuthSessionRecord = {
      schemaVersion: 2,
      sessionHash: 'n'.repeat(43),
      ownerId: 'owner-a',
      ownerBinding: flow.ownerBinding,
      appleSubjectHash: 'f'.repeat(43),
      encryptedCredentials: `v2.${'g'.repeat(16)}.${'h'.repeat(32)}`,
      createdAt: INITIAL_TIME,
      expiresAt: INITIAL_TIME + 600,
      lastValidatedAt: INITIAL_TIME,
    };
    await repository.createSession(session);
    assert.deepEqual(await repository.readSession(session.sessionHash, INITIAL_TIME + 1), session);
    const updated = {...session, encryptedCredentials: `v2.${'i'.repeat(16)}.${'j'.repeat(32)}`, lastValidatedAt: INITIAL_TIME + 2};
    await repository.updateSession({expected: session, next: updated, now: INITIAL_TIME + 2});
    assert.deepEqual(await repository.readSession(session.sessionHash, INITIAL_TIME + 3), updated);
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        provider_credentials,started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,0,NULL,?,NULL,?)`,
    ).bind(
      'Q'.repeat(43), session.ownerBinding, session.ownerId, session.appleSubjectHash,
      INITIAL_TIME + 3, INITIAL_TIME + 603,
    ).run();
    assert.equal(await repository.readSession(session.sessionHash, INITIAL_TIME + 4), null);
    await database.prepare('DELETE FROM apple_account_deletions WHERE deletion_key_hash=?').bind('Q'.repeat(43)).run();
    assert.equal(await repository.revokeSession(session.sessionHash, INITIAL_TIME + 4), true);
    assert.equal(await repository.revokeSession(session.sessionHash, INITIAL_TIME + 5), false);
    assert.equal(await repository.readSession(session.sessionHash, INITIAL_TIME + 6), null);
    const expiringSession = {
      ...session,
      sessionHash: 'p'.repeat(43),
      expiresAt: INITIAL_TIME + 10,
    };
    await repository.createSession(expiringSession);
    assert.deepEqual(
      await repository.readSession(expiringSession.sessionHash, INITIAL_TIME + 9),
      expiringSession,
    );
    assert.equal(
      await repository.readSession(expiringSession.sessionHash, expiringSession.expiresAt),
      null,
    );
  } finally {
    await miniflare.dispose();
  }
});

test('D1 owner mutation gate blocks stale Apple authority without blocking the host or another linked subject', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const ownerId = 'linked-owner-operation-race';
    const subjectA = 'A'.repeat(43);
    const subjectB = 'B'.repeat(43);
    const staleSubjectA = {userId: ownerId, authorizationStartedAt: INITIAL_TIME, appleSubjectHash: subjectA};
    const host = {userId: ownerId, authorizationStartedAt: INITIAL_TIME, appleSubjectHash: null};
    const otherSubject = {userId: ownerId, authorizationStartedAt: INITIAL_TIME, appleSubjectHash: subjectB};
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        provider_credentials,started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,0,NULL,?,NULL,?)`,
    ).bind(
      'K'.repeat(43), 'L'.repeat(43), ownerId, subjectA,
      INITIAL_TIME + 1, INITIAL_TIME + 601,
    ).run();

    const insertFile = async (
      authorization: {userId:string;authorizationStartedAt:number;appleSubjectHash:string|null},
      path: string,
    ) => database.prepare(
      `INSERT INTO files(user_id,path,content,version)
       SELECT ?,?,'content',0 WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
       RETURNING path`,
    ).bind(
      ownerId,
      path,
      ...appleOwnerOperationGateBindings(authorization, INITIAL_TIME + 2),
    ).first();
    assert.equal(await insertFile(staleSubjectA, 'blocked-a.txt'), null);
    assert.notEqual(await insertFile(host, 'allowed-host.txt'), null);
    assert.notEqual(await insertFile(otherSubject, 'allowed-b.txt'), null);
    assert.equal(await isAppleOwnerOperationAllowed(database, staleSubjectA, INITIAL_TIME + 2), false);
    assert.equal(await isAppleOwnerOperationAllowed(database, host, INITIAL_TIME + 2), true);
    assert.equal(await isAppleOwnerOperationAllowed(database, otherSubject, INITIAL_TIME + 2), true);

    const summary: AppleCredentialRevocationSummary = {
      credentialsFound: 1,
      credentialsRevoked: 1,
      unreadableSessions: 0,
      failedRevocations: 0,
      manualRevocationRequired: false,
    };
    await database.prepare(
      `UPDATE apple_account_deletions
       SET provider_credentials=?,completed_at=? WHERE deletion_key_hash=?`,
    ).bind(JSON.stringify(summary), INITIAL_TIME + 3, 'K'.repeat(43)).run();
    assert.equal(await insertFile(staleSubjectA, 'still-blocked-a.txt'), null);
    const reauthorizedA = {...staleSubjectA, authorizationStartedAt: INITIAL_TIME + 4};
    assert.equal(await insertFile(reauthorizedA, 'torn-receipt-blocked-a.txt'), null);
    await database.prepare(
      `UPDATE apple_account_deletions
       SET origin_connections=?,completion_fence_token=? WHERE deletion_key_hash=?`,
    ).bind(
      JSON.stringify(NO_ORIGIN_CONNECTIONS),
      'C'.repeat(43),
      'K'.repeat(43),
    ).run();
    assert.notEqual(await insertFile(reauthorizedA, 'reauthorized-a.txt'), null);

    const standaloneOwner = `apple-owner:v1.${'S'.repeat(43)}`;
    const staleStandalone = {userId: standaloneOwner, authorizationStartedAt: INITIAL_TIME, appleSubjectHash: subjectA};
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        provider_credentials,started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,1,NULL,?,NULL,?)`,
    ).bind(
      'M'.repeat(43), 'N'.repeat(43), standaloneOwner, subjectA,
      INITIAL_TIME + 1, INITIAL_TIME + 601,
    ).run();
    const gate = appleOwnerOperationGateBindings(staleStandalone, INITIAL_TIME + 2);
    const guardedStatements = [
      database.prepare(`INSERT INTO workspaces(user_id,policy,completed,revision) SELECT ?,'{}','[]',0 WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(standaloneOwner, ...gate),
      database.prepare(`INSERT INTO files(user_id,path,content,version) SELECT ?,'race.txt','content',0 WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(standaloneOwner, ...gate),
      database.prepare(`INSERT INTO receipts(user_id,id,payload,created_at) SELECT ?,'race-receipt','{}','2030-01-01T00:00:00.000Z' WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(standaloneOwner, ...gate),
      database.prepare(`INSERT INTO sync_workspaces(user_id,workspace_id,epoch,incarnation,recovery,revision,created_at,updated_at) SELECT ?,'race-workspace','race-epoch',?,'{}',0,'2030-01-01T00:00:00.000Z','2030-01-01T00:00:00.000Z' WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind(standaloneOwner, '0'.repeat(64), ...gate),
      database.prepare(`INSERT INTO origin_auth_flows(state_hash,owner_id,return_to,created_at,expires_at,consumed_at) SELECT ? ,?,'/',?,?,NULL WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`).bind('O'.repeat(43), standaloneOwner, INITIAL_TIME + 2, INITIAL_TIME + 602, ...gate),
    ];
    const results = await database.batch(guardedStatements);
    assert.deepEqual(results.map((result:{meta:{changes?:number}}) => result.meta.changes ?? 0), [0, 0, 0, 0, 0]);
    for (const [table, column] of [
      ['workspaces', 'user_id'],
      ['files', 'user_id'],
      ['receipts', 'user_id'],
      ['sync_workspaces', 'user_id'],
      ['origin_auth_flows', 'owner_id'],
    ] as const) assert.equal(await countRows(database, table, column, standaloneOwner), 0, table);

    await database.prepare(
      `INSERT INTO apple_auth_notifications(
        notification_id_hash,event_type,apple_subject_hash,owner_id,issued_at,event_time,
        processed_at,expires_at
      ) VALUES(?,?,?,?,?,?,?,?)`,
    ).bind(
      'P'.repeat(43),
      'future-event',
      subjectA,
      null,
      INITIAL_TIME,
      INITIAL_TIME,
      INITIAL_TIME,
      INITIAL_TIME + 601,
    ).run();
    assert.equal(
      await isAppleOwnerOperationAllowed(database, staleStandalone, INITIAL_TIME + 602),
      true,
    );
    assert.equal(
      (await database.prepare('SELECT COUNT(*) AS count FROM apple_account_deletions').first() as {count:number}).count,
      0,
    );
    assert.equal(
      (await database.prepare('SELECT COUNT(*) AS count FROM apple_auth_notifications').first() as {count:number}).count,
      0,
    );

    for (const relativePath of [
      '../lib/server.ts',
      '../app/api/workspace/route.ts',
      '../app/api/files/route.ts',
      '../app/api/check/route.ts',
      '../app/api/sync/route.ts',
      '../lib/origin-auth-d1.ts',
    ]) {
      const source = await readFile(new URL(relativePath, import.meta.url), 'utf8');
      assert.match(source, /APPLE_OWNER_OPERATION_ALLOWED_SQL/, relativePath);
    }
    const [workspaceRoute,filesRoute,fileRepository,syncRoute,oracleRoute,checkRoute,githubRoute,originRoute,originRepository] = await Promise.all([
      readFile(new URL('../app/api/workspace/route.ts', import.meta.url), 'utf8'),
      readFile(new URL('../app/api/files/route.ts', import.meta.url), 'utf8'),
      readFile(new URL('../lib/workspace-file-d1.ts', import.meta.url), 'utf8'),
      readFile(new URL('../app/api/sync/route.ts', import.meta.url), 'utf8'),
      readFile(new URL('../app/api/oracle/route.ts', import.meta.url), 'utf8'),
      readFile(new URL('../app/api/check/route.ts', import.meta.url), 'utf8'),
      readFile(new URL('../app/api/github/route.ts', import.meta.url), 'utf8'),
      readFile(new URL('../app/api/origin/route.ts', import.meta.url), 'utf8'),
      readFile(new URL('../lib/origin-auth-d1.ts', import.meta.url), 'utf8'),
    ]);
    assert.match(
      workspaceRoute,
      /await assertAppleOwnerOperationAllowed\(user,db\);return response;/,
      'workspace GET must fence its staged response immediately before return',
    );
    assert.match(
      syncRoute,
      /readAuthorizedSyncWorkspaceSnapshot\(\{database:db,authorization:user,operationTime,workspaceId:id\}\)[\s\S]*if\(snapshot\.kind==='unauthorized'\)deletionInProgress\(\)/,
      'every initial workspace read must include the owner/deletion admission gate',
    );
    assert.ok(
      (syncRoute.match(/const fence=await finalFence\(/g)?.length ?? 0) >= 7
        && (syncRoute.match(/requireCurrentFence\(fence\)/g)?.length ?? 0) >= 6
        && /if\(fence==='current'\)return[\s\S]*if\(fence==='unauthorized'\)deletionInProgress\(\)/.test(syncRoute),
      'every staged sync payload or mutation result must pass an exact incarnation/state final fence',
    );
    assert.match(
      syncRoute,
      /const workspace=await requireWorkspace[\s\S]*if\(envelope\.epoch!==workspace\.epoch\)throw/,
      'the early sync key-epoch conflict must use the admission-aware workspace snapshot',
    );
    assert.match(
      filesRoute,
      /const snapshot=authorizedSnapshot\(await finalFileSnapshot\(\{database:database\(\),authorization:user,operationTime:[^,]+,path\}\)\)/,
      'file GET must use the atomic owner-gated workspace and plaintext snapshot',
    );
    assert.equal(
      filesRoute.match(/authorizedSnapshot\(await finalFileSnapshot\(/g)?.length,
      4,
      'file GET and every mutation response branch must use a fresh atomic owner-gated snapshot',
    );
    assert.match(
      fileRepository,
      /WITH authorized AS \(SELECT 1 AS allowed WHERE \$\{APPLE_OWNER_OPERATION_ALLOWED_SQL\}\)[\s\S]*if \(raw === null\) return \{kind:'unauthorized'\};/,
      'the final file snapshot must read workspace state, counts, and plaintext through the same owner/deletion gate',
    );
    assert.match(
      filesRoute,
      /if\(snapshot\.fileCount>=100\)throw[^;]+FILE_LIMIT/,
      'the file-limit result must use the final owner-gated file count',
    );
    assert.match(
      oracleRoute,
      /const response=\{[^;]+\};await assertAppleOwnerOperationAllowed\(user,database\(\)\);return response;/,
      'Oracle must fence the staged policy-derived response',
    );
    assert.match(
      checkRoute,
      /if\(cached\)\{const receipt=[^;]+;await assertAppleOwnerOperationAllowed\(user,db\);return receipt;/,
      'cached receipts must be fenced after parsing and immediately before return',
    );
    assert.match(
      githubRoute,
      /withD1AppleOwnerExternalOperationLease[\s\S]*operationKind:'github'/,
      'every GitHub provider operation must run inside the durable owner lease',
    );
    assert.match(
      originRoute,
      /withD1OriginExternalOperationLease/,
      'Origin provider operations must run inside the durable lease',
    );
    assert.match(
      originRepository,
      /readInstallationIncarnations[\s\S]*receipt_fence\.issued_at_fence[\s\S]*sameInstallationIncarnations[\s\S]*ORIGIN_DASHBOARD_STATE_CHANGED/,
      'Origin installation reads must fence the exact installation and receipt-fence generation before return',
    );
  } finally {
    await miniflare.dispose();
  }
});

test('D1 final fences suppress staged file and sync data after linked Apple deletion', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const ownerId = 'host-owner-with-preserved-linked-data';
    const appleSubjectHash = 'v'.repeat(43);
    const principalId = 'j'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(
      appleSubjectHash,
      principalId,
      INITIAL_TIME,
      ownerId,
      INITIAL_TIME,
      INITIAL_TIME,
    ).run();
    await database.prepare(
      'INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,?,?,0)',
    ).bind(ownerId, '{}', '[]').run();
    await database.prepare(
      'INSERT INTO files(user_id,path,content,version) VALUES(?,?,?,?)',
    ).bind(ownerId, 'workspace/private.txt', 'private staged plaintext', 7).run();
    const workspaceId = 'W'.repeat(32);
    const epoch = 'epoch_staged_0123456789';
    const incarnation = '1'.repeat(64);
    const recovery = JSON.stringify({secret: 'staged recovery envelope'});
    const updatedAt = '2030-01-01T00:00:00.000Z';
    await database.prepare(
      `INSERT INTO sync_workspaces(
        user_id,workspace_id,epoch,incarnation,recovery,revision,created_at,updated_at
      ) VALUES(?,?,?,?,?,0,?,?)`,
    ).bind(ownerId, workspaceId, epoch, incarnation, recovery, updatedAt, updatedAt).run();
    await database.prepare(
      `INSERT INTO sync_workspace_epochs(
        user_id,workspace_id,epoch,incarnation,enrolled_at
      ) VALUES(?,?,?,?,?)`,
    ).bind(ownerId, workspaceId, epoch, incarnation, updatedAt).run();
    await database.prepare(
      `INSERT INTO sync_records(
        user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at
      ) VALUES(?,?,?,?,?,?,?)`,
    ).bind(
      ownerId,
      workspaceId,
      'R'.repeat(43),
      0,
      'M'.repeat(43),
      JSON.stringify({ciphertext: 'staged encrypted record'}),
      updatedAt,
    ).run();

    const authorization = {
      userId: ownerId,
      authorizationStartedAt: INITIAL_TIME,
      appleSubjectHash,
    };
    const reads = [
      () => database.prepare(
        'SELECT path,content,version FROM files WHERE user_id=? AND path=?',
      ).bind(ownerId, 'workspace/private.txt').first(),
      () => database.prepare(
        'SELECT count(*) AS n FROM files WHERE user_id=?',
      ).bind(ownerId).first(),
      () => database.prepare(
        'SELECT epoch,recovery,revision FROM sync_workspaces WHERE user_id=? AND workspace_id=?',
      ).bind(ownerId, workspaceId).first(),
      () => database.prepare(
        `SELECT record_id,revision,mutation_id,envelope FROM sync_records
         WHERE user_id=? AND workspace_id=? AND record_id=?`,
      ).bind(ownerId, workspaceId, 'R'.repeat(43)).first(),
    ];
    let stagedCount = 0;
    let signalAllStaged!: () => void;
    let releaseResponses!: () => void;
    const allStaged = new Promise<void>(resolve => { signalAllStaged = resolve; });
    const responsesReleased = new Promise<void>(resolve => { releaseResponses = resolve; });
    let responseNow = INITIAL_TIME;
    const stagedResponses = reads.map(async read => {
      const value = await read();
      assert.notEqual(value, null);
      stagedCount += 1;
      if (stagedCount === reads.length) signalAllStaged();
      await responsesReleased;
      if (!await isAppleOwnerOperationAllowed(database, authorization, responseNow)) {
        throw new AppleAuthError(
          409,
          'APPLE_ACCOUNT_DELETION_IN_PROGRESS',
          'This Apple access is being deleted.',
        );
      }
      return value;
    });
    await allStaged;

    const deletion = await deleteAppleAccount({
      repository: createD1AppleAccountDeletionRepository(database),
      authDependencies: null,
      ownerId,
      appleSubjectHash,
      deletionKey: `v1.${'Q'.repeat(42)}A`,
      crypto,
      now: INITIAL_TIME + 1,
      completionNow: () => INITIAL_TIME + 2,
      revocationLeaseToken: () => `${'U'.repeat(42)}A`,
    });
    assert.equal(deletion.deleted, true);
    responseNow = INITIAL_TIME + 2;
    releaseResponses();
    for (const response of stagedResponses) {
      await assert.rejects(
        response,
        matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
      );
    }
    assert.deepEqual(await database.prepare(
      'SELECT content,version FROM files WHERE user_id=? AND path=?',
    ).bind(ownerId, 'workspace/private.txt').first(), {
      content: 'private staged plaintext',
      version: 7,
    });
    assert.notEqual(await database.prepare(
      'SELECT recovery FROM sync_workspaces WHERE user_id=? AND workspace_id=?',
    ).bind(ownerId, workspaceId).first(), null);
    assert.notEqual(await database.prepare(
      'SELECT envelope FROM sync_records WHERE user_id=? AND workspace_id=?',
    ).bind(ownerId, workspaceId).first(), null);
    assert.notEqual(await database.prepare(
      'SELECT incarnation FROM sync_workspace_epochs WHERE user_id=? AND workspace_id=?',
    ).bind(ownerId, workspaceId).first(), null);
  } finally {
    await miniflare.dispose();
  }
});

test('D1 account deletion removes every owner-scoped record atomically and binds its receipt', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const ownerId = `apple-owner:v1.${'A'.repeat(43)}`;
    const subjectHash = 's'.repeat(43);
    await seedOwnerRecords(database, ownerId, subjectHash, 'a');
    const repository = createD1AppleAccountDeletionRepository(database);
    await database.prepare(
      'UPDATE apple_auth_sessions SET revoked_at=? WHERE owner_id=?',
    ).bind(INITIAL_TIME - 1, ownerId).run();
    const ownerSessionRead = await repository.readWebSessionsForDeletion({
      ownerId,
      appleSubjectHash: subjectHash,
      deleteOwnerData: true,
    });
    assert.equal(ownerSessionRead.sessions.length, 1);
    assert.equal(ownerSessionRead.sessions[0]?.sessionHash, 'a'.repeat(43));
    assert.equal(ownerSessionRead.unreadableSessions, 0);
    for (let index=0;index<9;index+=1) {
      await database.prepare(
        'INSERT INTO origin_installations(installation_id,owner_id,namespace_id,created_at,updated_at) VALUES(?,?,?,?,?)',
      ).bind(`inst_0000000${index}`,ownerId,`namespace-${index}`,INITIAL_TIME,INITIAL_TIME).run();
    }
    const originRead=await repository.readOriginInstallationsForDeletion({
      ownerId,
      appleSubjectHash: subjectHash,
      deleteOwnerData: true,
    });
    assert.equal(originRead.installationIds.length,7);
    assert.equal(originRead.unreadableInstallations,3);
    const request = {
      ownerId,
      appleSubjectHash: subjectHash,
      deleteOwnerData: true,
      ownerBinding: 'b'.repeat(43),
      deletionKeyHash: 'd'.repeat(43),
      revocationLeaseToken: 'l'.repeat(43),
      providerCredentials: {
        credentialsFound: 2,
        credentialsRevoked: 1,
        unreadableSessions: 1,
        failedRevocations: 1,
        manualRevocationRequired: true,
      },
      originConnections: {
        installationsFound: 2,
        installationsRevoked: 1,
        unreadableInstallations: 0,
        failedRevocations: 1,
        manualRevocationRequired: true,
      },
      completedAt: INITIAL_TIME,
      expiresAt: INITIAL_TIME + 600,
    };
    assert.equal(await repository.beginAppleAccountDeletion({
      ownerId: request.ownerId,
      appleSubjectHash: request.appleSubjectHash,
      deleteOwnerData: request.deleteOwnerData,
      ownerBinding: request.ownerBinding,
      deletionKeyHash: request.deletionKeyHash,
      revocationLeaseToken: request.revocationLeaseToken,
      startedAt: request.completedAt,
      leaseClaimedAt: request.completedAt,
      expiresAt: request.expiresAt,
    }), null);
    assert.deepEqual(await repository.deleteAppleAccessAndCompleteReceipt(request), {
      created: true,
      providerCredentials: request.providerCredentials,
      originConnections: request.originConnections,
    });
    const ownerTables: ReadonlyArray<readonly [string, 'user_id' | 'owner_id']> = [
      ['workspaces', 'user_id'],
      ['files', 'user_id'],
      ['receipts', 'user_id'],
      ['usage', 'user_id'],
      ['sync_workspaces', 'user_id'],
      ['sync_workspace_epochs', 'user_id'],
      ['sync_records', 'user_id'],
      ['origin_auth_flows', 'owner_id'],
      ['origin_installations', 'owner_id'],
      ['apple_auth_sessions', 'owner_id'],
      ['apple_native_sessions', 'owner_id'],
      ['apple_identity_links', 'owner_id'],
    ];
    for (const [table, column] of ownerTables) {
      assert.equal(
        await countRows(database, table, column, ownerId),
        0,
        table,
      );
    }
    assert.deepEqual(
      await repository.readDeletionReceipt(request.deletionKeyHash, INITIAL_TIME + 1),
      {
        ownerBinding: request.ownerBinding,
        providerCredentials: request.providerCredentials,
        originConnections: request.originConnections,
      },
    );
    assert.deepEqual(await repository.deleteAppleAccessAndCompleteReceipt(request), {
      created: false,
      providerCredentials: request.providerCredentials,
      originConnections: request.originConnections,
    });

    const otherOwner = 'host-owner-not-deleted';
    await database.prepare(
      'INSERT INTO files(user_id,path,content,version) VALUES(?,?,?,0)',
    ).bind(otherOwner, 'safe.txt', 'safe').run();
    await assert.rejects(
      repository.deleteAppleAccessAndCompleteReceipt({
        ...request,
        ownerId: otherOwner,
        appleSubjectHash: 'x'.repeat(43),
        deleteOwnerData: false,
        ownerBinding: 'x'.repeat(43),
      }),
      matchesCode('APPLE_ACCOUNT_DELETION_KEY_CONFLICT'),
    );
    assert.equal(
      await countRows(database, 'files', 'user_id', otherOwner),
      1,
    );

    const linkedOwner = 'chatgpt-owner-retained-after-apple-removal';
    const linkedSubjectA = 'h'.repeat(43);
    const linkedSubjectB = 'i'.repeat(43);
    await seedOwnerRecords(database, linkedOwner, linkedSubjectA, 'l');
    await database.prepare(
      'INSERT INTO apple_identity_links(apple_subject_hash,owner_id,created_at,updated_at) VALUES(?,?,?,?)',
    ).bind(linkedSubjectB, linkedOwner, INITIAL_TIME, INITIAL_TIME).run();
    await database.prepare(
      `INSERT INTO apple_auth_sessions(
        schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
        encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
      ) VALUES(2,?,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      'k'.repeat(43), linkedOwner, 'K'.repeat(43), linkedSubjectB,
      `v2.${'k'.repeat(16)}.${'k'.repeat(32)}`,
      INITIAL_TIME, INITIAL_TIME + 600, INITIAL_TIME,
    ).run();
    await database.prepare(
      `INSERT INTO apple_native_sessions(
        schema_version,identity_token_hash,session_hash,owner_id,apple_subject_hash,
        created_at,expires_at,identity_token_expires_at,revoked_at
      ) VALUES(1,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      'I'.repeat(43), 'J'.repeat(43), linkedOwner, linkedSubjectB,
      INITIAL_TIME, INITIAL_TIME + 600, INITIAL_TIME + 600,
    ).run();
    await database.prepare(
      `INSERT INTO apple_auth_flows(
        schema_version,state_hash,purpose,owner_id,nonce_hash,browser_binding_hash,
        owner_binding,return_to,created_at,expires_at,consumed_at
      ) VALUES(2,?,'link',?,?,?,?,?,?,?,NULL)`,
    ).bind(
      'F'.repeat(43), linkedOwner, 'N'.repeat(43), 'G'.repeat(43),
      'O'.repeat(43), '/', INITIAL_TIME, INITIAL_TIME + 600,
    ).run();
    const linkedDeletion = {
      ownerId: linkedOwner,
      appleSubjectHash: linkedSubjectA,
      deleteOwnerData: false,
      ownerBinding: 'H'.repeat(43),
      deletionKeyHash: 'D'.repeat(43),
      revocationLeaseToken: 'E'.repeat(43),
      providerCredentials: {
        credentialsFound: 0,
        credentialsRevoked: 0,
        unreadableSessions: 1,
        failedRevocations: 0,
        manualRevocationRequired: true,
      },
      originConnections: NO_ORIGIN_CONNECTIONS,
      completedAt: INITIAL_TIME + 20,
      expiresAt: INITIAL_TIME + 620,
    };
    assert.equal(await repository.beginAppleAccountDeletion({
      ownerId: linkedDeletion.ownerId,
      appleSubjectHash: linkedDeletion.appleSubjectHash,
      deleteOwnerData: linkedDeletion.deleteOwnerData,
      ownerBinding: linkedDeletion.ownerBinding,
      deletionKeyHash: linkedDeletion.deletionKeyHash,
      revocationLeaseToken: linkedDeletion.revocationLeaseToken,
      startedAt: INITIAL_TIME + 10,
      leaseClaimedAt: INITIAL_TIME + 10,
      expiresAt: linkedDeletion.expiresAt,
    }), null);
    const webRepository = createD1AppleAuthRepository(database);
    await assert.rejects(
      webRepository.linkAppleIdentity({
        appleSubjectHash: linkedSubjectA,
        ownerId: linkedOwner,
        createdAt: INITIAL_TIME + 11,
        updatedAt: INITIAL_TIME + 11,
      }, INITIAL_TIME + 9),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    assert.deepEqual(await repository.deleteAppleAccessAndCompleteReceipt(linkedDeletion), {
      created: true,
      providerCredentials: linkedDeletion.providerCredentials,
      originConnections: linkedDeletion.originConnections,
    });
    assert.equal(await countRows(database, 'files', 'user_id', linkedOwner), 1);
    assert.equal(await countRows(database, 'workspaces', 'user_id', linkedOwner), 1);
    assert.equal(await countRows(database, 'apple_auth_flows', 'owner_id', linkedOwner), 1);
    assert.equal(
      await database.prepare('SELECT 1 FROM apple_identity_links WHERE apple_subject_hash=?')
        .bind(linkedSubjectA).first(),
      null,
    );
    assert.notEqual(
      await database.prepare('SELECT 1 FROM apple_identity_links WHERE apple_subject_hash=?')
        .bind(linkedSubjectB).first(),
      null,
    );
    assert.equal(
      await database.prepare('SELECT 1 FROM apple_auth_sessions WHERE apple_subject_hash=?')
        .bind(linkedSubjectA).first(),
      null,
    );
    assert.notEqual(
      await database.prepare('SELECT 1 FROM apple_auth_sessions WHERE apple_subject_hash=?')
        .bind(linkedSubjectB).first(),
      null,
    );
    await assert.rejects(
      webRepository.linkAppleIdentity({
        appleSubjectHash: linkedSubjectA,
        ownerId: linkedOwner,
        createdAt: INITIAL_TIME + 21,
        updatedAt: INITIAL_TIME + 21,
      }, INITIAL_TIME + 9),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: linkedSubjectA,
      ownerId: linkedOwner,
      createdAt: INITIAL_TIME + 22,
      updatedAt: INITIAL_TIME + 22,
    }, INITIAL_TIME + 21), 'linked');

    const boundedOwner = `apple-owner:v1.${'Q'.repeat(43)}`;
    const boundedSubject = 'q'.repeat(43);
    await seedOwnerRecords(database, boundedOwner, boundedSubject, 'q');
    for (let index = 1; index <= 9; index += 1) {
      const value = String(index);
      await database.prepare(
        `INSERT INTO apple_auth_sessions(
          schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
          encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
        ) VALUES(2,?,?,?,?,?,?,?,?,NULL)`,
      ).bind(
        value.repeat(43), boundedOwner, 'V'.repeat(43), boundedSubject,
        `v2.${value.repeat(16)}.${value.repeat(32)}`,
        INITIAL_TIME, INITIAL_TIME + 600, INITIAL_TIME,
      ).run();
    }
    await database.prepare(
      'UPDATE apple_auth_sessions SET schema_version=99 WHERE session_hash=?',
    ).bind('1'.repeat(43)).run();
    const boundedRead = await repository.readWebSessionsForDeletion({
      ownerId: boundedOwner,
      appleSubjectHash: boundedSubject,
      deleteOwnerData: true,
    });
    assert.equal(boundedRead.sessions.length, 7);
    assert.equal(boundedRead.unreadableSessions, 3);
    const boundedDeletion = await deleteAppleAccount({
      repository,
      authDependencies: null,
      ownerId: boundedOwner,
      appleSubjectHash: boundedSubject,
      deletionKey: `v1.${'Q'.repeat(43)}`,
      crypto,
      now: INITIAL_TIME + 30,
    });
    assert.deepEqual(boundedDeletion.providerCredentials, {
      credentialsFound: 0,
      credentialsRevoked: 0,
      unreadableSessions: 10,
      failedRevocations: 0,
      manualRevocationRequired: true,
    });
    assert.equal(await countRows(database, 'files', 'user_id', boundedOwner), 0);

    const concurrentOwner = `apple-owner:v1.${'C'.repeat(43)}`;
    await seedOwnerRecords(database, concurrentOwner, 't'.repeat(43), 'c');
    const concurrentKeyHash = 'q'.repeat(43);
    const concurrentSummaries: AppleCredentialRevocationSummary[] = [
      {
        credentialsFound: 1,
        credentialsRevoked: 1,
        unreadableSessions: 0,
        failedRevocations: 0,
        manualRevocationRequired: false,
      },
      {
        credentialsFound: 1,
        credentialsRevoked: 0,
        unreadableSessions: 0,
        failedRevocations: 1,
        manualRevocationRequired: true,
      },
    ];
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        provider_credentials,origin_connections,started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?)`,
    ).bind(
      'e'.repeat(43),
      'e'.repeat(43),
      ownerId,
      subjectHash,
      1,
      JSON.stringify(request.providerCredentials),
      JSON.stringify(NO_ORIGIN_CONNECTIONS),
      INITIAL_TIME - 600,
      INITIAL_TIME - 600,
      INITIAL_TIME,
    ).run();
    assert.equal(await repository.beginAppleAccountDeletion({
      ownerId: concurrentOwner,
      appleSubjectHash: 't'.repeat(43),
      deleteOwnerData: true,
      ownerBinding: 'r'.repeat(43),
      deletionKeyHash: concurrentKeyHash,
      revocationLeaseToken: 's'.repeat(43),
      startedAt: INITIAL_TIME + 1,
      leaseClaimedAt: INITIAL_TIME + 1,
      expiresAt: INITIAL_TIME + 602,
    }), null);
    const concurrentResults = await Promise.all(concurrentSummaries.map(providerCredentials => (
      repository.deleteAppleAccessAndCompleteReceipt({
        ownerId: concurrentOwner,
        appleSubjectHash: 't'.repeat(43),
        deleteOwnerData: true,
        ownerBinding: 'r'.repeat(43),
        deletionKeyHash: concurrentKeyHash,
        revocationLeaseToken: 's'.repeat(43),
        providerCredentials,
        originConnections: NO_ORIGIN_CONNECTIONS,
        completedAt: INITIAL_TIME + 2,
        expiresAt: INITIAL_TIME + 602,
      })
    )));
    assert.equal(concurrentResults.filter(result => result.created).length, 1);
    assert.deepEqual(concurrentResults[0]?.providerCredentials, concurrentResults[1]?.providerCredentials);
    assert.deepEqual(
      await repository.readDeletionReceipt(concurrentKeyHash, INITIAL_TIME + 3),
      {
        ownerBinding: 'r'.repeat(43),
        providerCredentials: concurrentResults[0]?.providerCredentials,
        originConnections: concurrentResults[0]?.originConnections,
      },
    );
    assert.equal(await countRows(database, 'files', 'user_id', concurrentOwner), 0);
    assert.equal(
      z.object({count: z.number().int()}).parse(await database.prepare(
        'SELECT COUNT(*) AS count FROM apple_account_deletions WHERE deletion_key_hash=?',
      ).bind('e'.repeat(43)).first()).count,
      0,
    );

    const multiKeyOwner = 'chatgpt-owner-with-two-deletion-keys';
    const multiKeySubject = 'U'.repeat(43);
    const multiKeyBinding = 'W'.repeat(43);
    const multiKeyRawA = `v1.${'X'.repeat(42)}A`;
    const multiKeyRawB = `v1.${'Y'.repeat(42)}A`;
    const multiKeyA = await hashAppleOpaqueToken(multiKeyRawA, crypto);
    const multiKeyB = await hashAppleOpaqueToken(multiKeyRawB, crypto);
    await seedOwnerRecords(database, multiKeyOwner, multiKeySubject, 'z');
    assert.equal(await repository.beginAppleAccountDeletion({
        ownerId: multiKeyOwner,
        appleSubjectHash: multiKeySubject,
        deleteOwnerData: false,
        ownerBinding: multiKeyBinding,
        deletionKeyHash: multiKeyA,
        revocationLeaseToken: 'a'.repeat(43),
        startedAt: INITIAL_TIME + 40,
        leaseClaimedAt: INITIAL_TIME + 40,
        expiresAt: INITIAL_TIME + 640,
    }), null);
    await assert.rejects(repository.beginAppleAccountDeletion({
      ownerId: multiKeyOwner,
      appleSubjectHash: multiKeySubject,
      deleteOwnerData: false,
      ownerBinding: multiKeyBinding,
      deletionKeyHash: multiKeyB,
      revocationLeaseToken: 'b'.repeat(43),
      startedAt: INITIAL_TIME + 40,
      leaseClaimedAt: INITIAL_TIME + 40,
      expiresAt: INITIAL_TIME + 640,
    }), matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
    const multiKeySummary: AppleCredentialRevocationSummary = {
      credentialsFound: 1,
      credentialsRevoked: 0,
      unreadableSessions: 0,
      failedRevocations: 1,
      manualRevocationRequired: true,
    };
    assert.deepEqual(await repository.deleteAppleAccessAndCompleteReceipt({
      ownerId: multiKeyOwner,
      appleSubjectHash: multiKeySubject,
      deleteOwnerData: false,
      ownerBinding: multiKeyBinding,
      deletionKeyHash: multiKeyA,
      revocationLeaseToken: 'a'.repeat(43),
      providerCredentials: multiKeySummary,
      originConnections: NO_ORIGIN_CONNECTIONS,
      completedAt: INITIAL_TIME + 45,
      expiresAt: INITIAL_TIME + 645,
    }), {created: true, providerCredentials: multiKeySummary,originConnections:NO_ORIGIN_CONNECTIONS});
    assert.deepEqual(await repository.readDeletionReceipt(multiKeyB, INITIAL_TIME + 46), {
      ownerBinding: multiKeyBinding,
      providerCredentials: multiKeySummary,
      originConnections: NO_ORIGIN_CONNECTIONS,
    });
    assert.deepEqual(await recoverAppleAccountDeletion({
      repository,
      authDependencies: null,
      deletionKey: multiKeyRawB,
      crypto,
      now: INITIAL_TIME + 46,
    }), {
      deleted: true,
      idempotent: true,
      providerCredentials: multiKeySummary,
      originConnections: NO_ORIGIN_CONNECTIONS,
    });
    await assert.rejects(webRepository.linkAppleIdentity({
      appleSubjectHash: multiKeySubject,
      ownerId: multiKeyOwner,
      createdAt: INITIAL_TIME + 46,
      updatedAt: INITIAL_TIME + 46,
    }, INITIAL_TIME + 42), matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: multiKeySubject,
      ownerId: multiKeyOwner,
      createdAt: INITIAL_TIME + 46,
      updatedAt: INITIAL_TIME + 46,
    }, INITIAL_TIME + 46), 'linked');

    const leaseOwner = 'linked-owner-with-expired-deletion-leader';
    const leaseSubject = 'j'.repeat(43);
    const leaseBinding = 'k'.repeat(43);
    const leaseKeyA = 'l'.repeat(43);
    const leaseKeyB = 'm'.repeat(43);
    const leaseTokenA = 'n'.repeat(43);
    const leaseTokenB = 'o'.repeat(43);
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: leaseSubject,
      ownerId: leaseOwner,
      createdAt: INITIAL_TIME + 79,
      updatedAt: INITIAL_TIME + 79,
    }), 'linked');
    assert.equal(await repository.beginAppleAccountDeletion({
      ownerId: leaseOwner,
      appleSubjectHash: leaseSubject,
      deleteOwnerData: false,
      ownerBinding: leaseBinding,
      deletionKeyHash: leaseKeyA,
      revocationLeaseToken: leaseTokenA,
      startedAt: INITIAL_TIME + 80,
      leaseClaimedAt: INITIAL_TIME + 80,
      expiresAt: INITIAL_TIME + 680,
    }), null);
    assert.equal(await repository.beginAppleAccountDeletion({
      ownerId: leaseOwner,
      appleSubjectHash: leaseSubject,
      deleteOwnerData: false,
      ownerBinding: leaseBinding,
      deletionKeyHash: leaseKeyB,
      revocationLeaseToken: leaseTokenB,
      startedAt: INITIAL_TIME + 80,
      leaseClaimedAt: INITIAL_TIME + 141,
      expiresAt: INITIAL_TIME + 680,
    }), null);
    await assert.rejects(repository.deleteAppleAccessAndCompleteReceipt({
      ownerId: leaseOwner,
      appleSubjectHash: leaseSubject,
      deleteOwnerData: false,
      ownerBinding: leaseBinding,
      deletionKeyHash: leaseKeyA,
      revocationLeaseToken: leaseTokenA,
      providerCredentials: multiKeySummary,
      originConnections: NO_ORIGIN_CONNECTIONS,
      completedAt: INITIAL_TIME + 142,
      expiresAt: INITIAL_TIME + 742,
    }), matchesCode('APPLE_ACCOUNT_DELETION_LEASE_LOST'));
    assert.deepEqual(await repository.deleteAppleAccessAndCompleteReceipt({
      ownerId: leaseOwner,
      appleSubjectHash: leaseSubject,
      deleteOwnerData: false,
      ownerBinding: leaseBinding,
      deletionKeyHash: leaseKeyB,
      revocationLeaseToken: leaseTokenB,
      providerCredentials: multiKeySummary,
      originConnections: NO_ORIGIN_CONNECTIONS,
      completedAt: INITIAL_TIME + 142,
      expiresAt: INITIAL_TIME + 742,
    }), {created: true, providerCredentials: multiKeySummary, originConnections: NO_ORIGIN_CONNECTIONS});
    assert.deepEqual(await repository.readDeletionReceipt(leaseKeyA, INITIAL_TIME + 143), {
      ownerBinding: leaseBinding,
      providerCredentials: multiKeySummary,
      originConnections: NO_ORIGIN_CONNECTIONS,
    });

    const malformedOwner = 'owner-protected-from-malformed-receipt';
    await database.prepare(
      'INSERT INTO files(user_id,path,content,version) VALUES(?,?,?,0)',
    ).bind(malformedOwner, 'protected.txt', 'safe').run();
    const malformedKeyHash = 'p'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        provider_credentials,origin_connections,started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?)`,
    ).bind(
      malformedKeyHash,
      'z'.repeat(43),
      malformedOwner,
      'z'.repeat(43),
      0,
      JSON.stringify({
        credentialsFound: 0,
        credentialsRevoked: 0,
        unreadableSessions: 0,
        failedRevocations: 0,
        manualRevocationRequired: false,
      }),
      JSON.stringify(NO_ORIGIN_CONNECTIONS),
      INITIAL_TIME,
      INITIAL_TIME,
      INITIAL_TIME + 600,
    ).run();
    await assert.rejects(
      repository.deleteAppleAccessAndCompleteReceipt({
        ownerId: malformedOwner,
        appleSubjectHash: 'z'.repeat(43),
        deleteOwnerData: false,
        ownerBinding: 'z'.repeat(43),
        deletionKeyHash: malformedKeyHash,
        revocationLeaseToken: 'z'.repeat(43),
        providerCredentials: request.providerCredentials,
        originConnections: NO_ORIGIN_CONNECTIONS,
        completedAt: INITIAL_TIME + 1,
        expiresAt: INITIAL_TIME + 601,
      }),
      matchesCode('APPLE_ACCOUNT_DELETION_RECEIPT_INVALID'),
    );
    assert.equal(await countRows(database, 'files', 'user_id', malformedOwner), 1);

    const oversizedKeyHash = 'o'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        provider_credentials,origin_connections,started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?)`,
    ).bind(
      oversizedKeyHash,
      'o'.repeat(43),
      'oversized-owner',
      'o'.repeat(43),
      0,
      'x'.repeat(513),
      JSON.stringify(NO_ORIGIN_CONNECTIONS),
      INITIAL_TIME,
      INITIAL_TIME,
      INITIAL_TIME + 600,
    ).run();
    await assert.rejects(
      repository.readDeletionReceipt(oversizedKeyHash, INITIAL_TIME + 1),
      matchesCode('APPLE_ACCOUNT_DELETION_RECEIPT_INVALID'),
    );
  } finally {
    await miniflare.dispose();
  }
});

test('D1 notification handling is replay-safe, monotonic, and preserves linked host data', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository = createD1AppleAccountDeletionRepository(database);
    const applyNotification = (
      notification: VerifiedAppleServerNotification,
      now: number,
      originDependencies?: {revokeInstallation(id: string, signal: AbortSignal): Promise<void>},
    ) => applyVerifiedAppleServerNotification({
      repository,
      notification,
      crypto: globalThis.crypto,
      now,
      completionNow: () => now,
      originDependencies,
    });
    const hostOwner = 'chatgpt-owner';
    const hostSubject = 'h'.repeat(43);
    await seedOwnerRecords(database, hostOwner, hostSubject, 'h');
    const disabled: VerifiedAppleServerNotification = {
      kind: 'email-disabled',
      notificationIdHash: '1'.repeat(43),
      appleSubjectHash: hostSubject,
      issuedAt: INITIAL_TIME,
      eventTime: INITIAL_TIME,
      receiptExpiresAt: INITIAL_TIME + 600,
    };
    assert.deepEqual(await applyNotification(disabled, INITIAL_TIME), {idempotent: false});
    assert.deepEqual(
      await database.prepare(
        'SELECT email_forwarding_enabled,email_state_updated_at FROM apple_identity_links WHERE apple_subject_hash=?',
      ).bind(hostSubject).first(),
      {email_forwarding_enabled: 0, email_state_updated_at: INITIAL_TIME},
    );
    assert.deepEqual(await applyNotification(disabled, INITIAL_TIME + 1), {idempotent: true});
    await applyNotification({
      ...disabled,
      kind: 'email-enabled',
      notificationIdHash: '2'.repeat(43),
      issuedAt: INITIAL_TIME - 1,
      eventTime: INITIAL_TIME - 1,
    }, INITIAL_TIME + 1);
    assert.deepEqual(
      await database.prepare(
        'SELECT email_forwarding_enabled,email_state_updated_at FROM apple_identity_links WHERE apple_subject_hash=?',
      ).bind(hostSubject).first(),
      {email_forwarding_enabled: 0, email_state_updated_at: INITIAL_TIME},
    );
    await assert.rejects(
      () => applyNotification({...disabled, kind: 'account-deleted'}, INITIAL_TIME + 2),
      matchesCode('APPLE_NOTIFICATION_REPLAY_CONFLICT'),
    );

    await applyNotification({
      kind: 'consent-revoked',
      notificationIdHash: '3'.repeat(43),
      appleSubjectHash: hostSubject,
      issuedAt: INITIAL_TIME + 2,
      eventTime: INITIAL_TIME + 2,
      receiptExpiresAt: INITIAL_TIME + 602,
    }, INITIAL_TIME + 2);
    assert.equal(
      await database.prepare('SELECT 1 FROM apple_identity_links WHERE apple_subject_hash=?')
        .bind(hostSubject).first(),
      null,
    );
    assert.equal(
      await database.prepare('SELECT 1 FROM apple_auth_sessions WHERE owner_id=?')
        .bind(hostOwner).first(),
      null,
    );
    assert.notEqual(
      await database.prepare('SELECT 1 FROM files WHERE user_id=?').bind(hostOwner).first(),
      null,
    );
    assert.notEqual(
      await database.prepare('SELECT 1 FROM workspaces WHERE user_id=?').bind(hostOwner).first(),
      null,
    );
    const hostReauthorizedAt = INITIAL_TIME + 10;
    await database.prepare(
      'INSERT INTO apple_identity_links(apple_subject_hash,owner_id,created_at,updated_at) VALUES(?,?,?,?)',
    ).bind(hostSubject, hostOwner, hostReauthorizedAt, hostReauthorizedAt).run();
    await database.prepare(
      `INSERT INTO apple_auth_sessions(
        schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
        encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
      ) VALUES(2,?,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      'R'.repeat(43), hostOwner, 'S'.repeat(43), hostSubject,
      `v2.${'r'.repeat(16)}.${'r'.repeat(32)}`,
      hostReauthorizedAt, hostReauthorizedAt + 600, hostReauthorizedAt,
    ).run();
    assert.deepEqual(await applyNotification({
      kind: 'consent-revoked',
      notificationIdHash: '3'.repeat(43),
      appleSubjectHash: hostSubject,
      issuedAt: INITIAL_TIME + 2,
      eventTime: INITIAL_TIME + 2,
      receiptExpiresAt: INITIAL_TIME + 602,
    }, hostReauthorizedAt + 1), {idempotent: true});
    await applyNotification({
      kind: 'account-deleted',
      notificationIdHash: '5'.repeat(43),
      appleSubjectHash: hostSubject,
      issuedAt: INITIAL_TIME + 1,
      eventTime: INITIAL_TIME + 1,
      receiptExpiresAt: INITIAL_TIME + 601,
    }, hostReauthorizedAt + 1);
    await applyNotification({
      kind: 'email-disabled',
      notificationIdHash: '6'.repeat(43),
      appleSubjectHash: hostSubject,
      issuedAt: INITIAL_TIME + 1,
      eventTime: INITIAL_TIME + 1,
      receiptExpiresAt: INITIAL_TIME + 601,
    }, hostReauthorizedAt + 1);
    assert.deepEqual(
      await database.prepare(
        'SELECT owner_id,email_forwarding_enabled,email_state_updated_at FROM apple_identity_links WHERE apple_subject_hash=?',
      ).bind(hostSubject).first(),
      {owner_id: hostOwner, email_forwarding_enabled: null, email_state_updated_at: null},
    );
    assert.notEqual(
      await database.prepare('SELECT 1 FROM apple_auth_sessions WHERE session_hash=?')
        .bind('R'.repeat(43)).first(),
      null,
    );

    const appleOwner = `apple-owner:v1.${'Z'.repeat(43)}`;
    const appleSubject = 'z'.repeat(43);
    await seedOwnerRecords(database, appleOwner, appleSubject, 'z');
    await database.prepare('DELETE FROM origin_installations WHERE owner_id=?')
      .bind(appleOwner).run();
    const revokedOriginInstallation = 'inst_01notificationcleanupok';
    const unresolvedOriginInstallation = 'inst_02notificationcleanupfail';
    for (const installationId of [revokedOriginInstallation, unresolvedOriginInstallation]) {
      await database.prepare(
        `INSERT INTO origin_installations(
          installation_id,owner_id,namespace_id,created_at,updated_at
        ) VALUES(?,?,?,?,?)`,
      ).bind(
        installationId,
        appleOwner,
        `ns_${installationId.slice(5)}`,
        INITIAL_TIME,
        INITIAL_TIME,
      ).run();
    }
    const originRevocations: string[] = [];
    await applyNotification({
      kind: 'account-deleted',
      notificationIdHash: '4'.repeat(43),
      appleSubjectHash: appleSubject,
      issuedAt: INITIAL_TIME + 3,
      eventTime: INITIAL_TIME + 3,
      receiptExpiresAt: INITIAL_TIME + 603,
    }, INITIAL_TIME + 3, {
      async revokeInstallation(installationId) {
        originRevocations.push(installationId);
        if (installationId === unresolvedOriginInstallation) throw new Error('unavailable');
      },
    });
    assert.deepEqual(originRevocations.sort(), [
      revokedOriginInstallation,
      unresolvedOriginInstallation,
    ]);
    for (const table of ['workspaces', 'files', 'receipts', 'usage', 'sync_workspaces', 'sync_workspace_epochs', 'sync_records']) {
      assert.equal(
        await countRows(database, table, 'user_id', appleOwner),
        0,
        table,
      );
    }
    assert.deepEqual(
      z.object({
        owner_id: z.string().nullable(),
        origin_connections: z.string(),
        origin_unresolved_installation_ids: z.string(),
      }).parse(
        await database.prepare(
          `SELECT owner_id,origin_connections,origin_unresolved_installation_ids
           FROM apple_auth_notifications WHERE notification_id_hash=?`,
        ).bind('4'.repeat(43)).first(),
      ),
      {
        owner_id: null,
        origin_connections: JSON.stringify({
          installationsFound: 2,
          installationsRevoked: 1,
          unreadableInstallations: 0,
          failedRevocations: 1,
          manualRevocationRequired: true,
        }),
        origin_unresolved_installation_ids: JSON.stringify([unresolvedOriginInstallation]),
      },
    );
    const reauthorizedAppleOwner = `apple-owner:v1.${'Y'.repeat(43)}`;
    const reauthorizedAppleAt = INITIAL_TIME + 20;
    await seedOwnerRecords(
      database,
      reauthorizedAppleOwner,
      appleSubject,
      'y',
      reauthorizedAppleAt,
    );
    assert.deepEqual(await applyNotification({
      kind: 'account-deleted',
      notificationIdHash: '4'.repeat(43),
      appleSubjectHash: appleSubject,
      issuedAt: INITIAL_TIME + 3,
      eventTime: INITIAL_TIME + 3,
      receiptExpiresAt: INITIAL_TIME + 603,
    }, reauthorizedAppleAt + 1), {idempotent: true});
    assert.equal(originRevocations.length, 2);
    await applyNotification({
      kind: 'consent-revoked',
      notificationIdHash: '7'.repeat(43),
      appleSubjectHash: appleSubject,
      issuedAt: INITIAL_TIME + 2,
      eventTime: INITIAL_TIME + 2,
      receiptExpiresAt: INITIAL_TIME + 602,
    }, reauthorizedAppleAt + 1);
    assert.notEqual(
      await database.prepare('SELECT 1 FROM apple_identity_links WHERE apple_subject_hash=?')
        .bind(appleSubject).first(),
      null,
    );
    assert.notEqual(
      await database.prepare('SELECT 1 FROM workspaces WHERE user_id=?')
        .bind(reauthorizedAppleOwner).first(),
      null,
    );
  } finally {
    await miniflare.dispose();
  }
});

test('D1 deletion start cannot commit a stale principal after a verified alias merge', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const webRepository = createD1AppleAuthRepository(database);
    const nativeRepository = createD1AppleNativeAuthRepository(database);
    const ownerId = 'linked-owner-deletion-transfer-race';
    const sendingAlias = 'A'.repeat(43);
    const recipientAlias = 'B'.repeat(43);
    const recipientSession: AppleAuthSessionRecord = {
      schemaVersion: 2,
      sessionHash: 'v'.repeat(43),
      ownerId,
      ownerBinding: 'V'.repeat(43),
      appleSubjectHash: recipientAlias,
      encryptedCredentials: `v2.${'v'.repeat(16)}.${'v'.repeat(32)}`,
      createdAt: INITIAL_TIME + 1,
      expiresAt: INITIAL_TIME + 601,
      lastValidatedAt: INITIAL_TIME + 1,
    };
    await seedOwnerRecords(database, ownerId, sendingAlias, 'u');
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: recipientAlias,
      ownerId,
      createdAt: INITIAL_TIME + 1,
      updatedAt: INITIAL_TIME + 1,
    }), 'linked');
    await webRepository.createSession(recipientSession);
    assert.equal(
      (await readD1AppleLinkedIdentity(database, recipientAlias))?.principalId,
      recipientAlias,
    );

    let signalDeletionBatch!: () => void;
    let releaseDeletionBatch!: () => void;
    const deletionBatchStarted = new Promise<void>(resolve => {
      signalDeletionBatch = resolve;
    });
    const deletionBatchReleased = new Promise<void>(resolve => {
      releaseDeletionBatch = resolve;
    });
    let pauseNextBatch = true;
    const pausedDatabase = {
      prepare: (query: string) => database.prepare(query),
      batch: async (statements: D1PreparedStatement[]) => {
        if (pauseNextBatch) {
          pauseNextBatch = false;
          signalDeletionBatch();
          await deletionBatchReleased;
        }
        return database.batch(statements);
      },
    } as D1Database;
    const pausedDeletionRepository = createD1AppleAccountDeletionRepository(pausedDatabase);
    const deletionKey = `v1.${'R'.repeat(42)}A`;
    const deletionKeyHash = await hashAppleOpaqueToken(deletionKey, globalThis.crypto);
    const ownerBinding = await hashAppleOpaqueToken(
      `owner\0${ownerId}\0apple-subject\0${recipientAlias}`,
      globalThis.crypto,
    );
    const staleStart = pausedDeletionRepository.beginAppleAccountDeletion({
      ownerId,
      appleSubjectHash: recipientAlias,
      deleteOwnerData: false,
      ownerBinding,
      deletionKeyHash,
      revocationLeaseToken: `${'L'.repeat(42)}A`,
      startedAt: INITIAL_TIME + 2,
      leaseClaimedAt: INITIAL_TIME + 2,
      expiresAt: INITIAL_TIME + 602,
    });
    await deletionBatchStarted;

    assert.deepEqual(await nativeRepository.resolveAppleOwner({
      appleSubjectHash: recipientAlias,
      transferSubjectHash: sendingAlias,
      proposedOwnerId: ownerId,
      requiredOwnerId: ownerId,
      requiredPrincipalId: sendingAlias,
      now: INITIAL_TIME + 3,
      authorizationStartedAt: INITIAL_TIME + 1,
    }), {ownerId, principalId: sendingAlias, created: false});
    const staleStartRejected = assert.rejects(
      staleStart,
      matchesCode('APPLE_IDENTITY_LINK_CHANGED'),
    );
    releaseDeletionBatch();
    await staleStartRejected;

    assert.equal(
      await database.prepare(
        'SELECT COUNT(*) AS count FROM apple_account_deletions WHERE deletion_key_hash=?',
      ).bind(deletionKeyHash).first('count'),
      0,
    );
    assert.equal(
      (await readD1AppleLinkedIdentity(database, recipientAlias))?.principalId,
      sendingAlias,
    );
    assert.deepEqual(
      await webRepository.readSession(recipientSession.sessionHash, INITIAL_TIME + 3),
      recipientSession,
    );

    const deletionRepository = createD1AppleAccountDeletionRepository(database);
    const completed = await deleteAppleAccount({
      repository: deletionRepository,
      authDependencies: null,
      ownerId,
      appleSubjectHash: recipientAlias,
      deletionKey,
      crypto: globalThis.crypto,
      now: INITIAL_TIME + 4,
      completionNow: () => INITIAL_TIME + 5,
      revocationLeaseToken: () => `${'M'.repeat(42)}A`,
    });
    assert.equal(completed.deleted, true);
    assert.equal(completed.idempotent, false);
    assert.deepEqual(
      await database.prepare(
        `SELECT apple_principal_id,completed_at
         FROM apple_account_deletions WHERE deletion_key_hash=?`,
      ).bind(deletionKeyHash).first(),
      {apple_principal_id: sendingAlias, completed_at: INITIAL_TIME + 5},
    );
    assert.equal(await webRepository.readLinkedIdentity(sendingAlias), null);
    assert.equal(await webRepository.readLinkedIdentity(recipientAlias), null);
    assert.equal(
      await webRepository.readSession(recipientSession.sessionHash, INITIAL_TIME + 5),
      null,
    );
    assert.equal((await deleteAppleAccount({
      repository: deletionRepository,
      authDependencies: null,
      ownerId,
      appleSubjectHash: recipientAlias,
      deletionKey,
      crypto: globalThis.crypto,
      now: INITIAL_TIME + 6,
      revocationLeaseToken: () => `${'N'.repeat(42)}A`,
    })).idempotent, true);
  } finally {
    await miniflare.dispose();
  }
});

test('D1 transfer principals delete every alias while preserving unrelated identities and new generations', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const webRepository = createD1AppleAuthRepository(database);
    const nativeRepository = createD1AppleNativeAuthRepository(database);
    const deletionRepository = createD1AppleAccountDeletionRepository(database);
    const ownerId = 'host-owner-with-transfer-principal';
    const sendingAlias = 'a'.repeat(43);
    const recipientAlias = 'b'.repeat(43);
    const unrelatedSubject = 'c'.repeat(43);
    await seedOwnerRecords(database, ownerId, sendingAlias, 'a');
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: recipientAlias,
      ownerId,
      createdAt: INITIAL_TIME,
      updatedAt: INITIAL_TIME,
    }), 'linked');
    const sendingNativeSessionHash = `${'a'}n`.repeat(22).slice(0, 43);
    const recipientNativeSessionHash = 'r'.repeat(43);
    assert.equal(await nativeRepository.createSession({
      schemaVersion: 1,
      identityTokenHash: 'R'.repeat(43),
      sessionHash: recipientNativeSessionHash,
      ownerId,
      principalId: recipientAlias,
      appleSubjectHash: recipientAlias,
      activationState: 'active',
      createdAt: INITIAL_TIME,
      expiresAt: INITIAL_TIME + 600,
      identityTokenExpiresAt: INITIAL_TIME + 600,
    }), true);
    for (const [marker, sessionHash, subject, principal] of [
      ['S', sendingNativeSessionHash, sendingAlias, sendingAlias],
      ['T', recipientNativeSessionHash, recipientAlias, recipientAlias],
    ] as const) {
      await database.prepare(
        `INSERT INTO apple_native_grants(
          schema_version,grant_hash,authorization_code_hash,session_hash,owner_id,
          principal_id,apple_subject_hash,owner_binding,encrypted_credentials,
          created_at,last_validated_at,expires_at,revocation_pending_at
        ) VALUES(1,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
      ).bind(
        marker.repeat(43), marker.toLowerCase().repeat(43), sessionHash, ownerId,
        principal, subject, marker.toLowerCase().repeat(43),
        `v1.${marker.toLowerCase().repeat(16)}.${marker.toLowerCase().repeat(32)}`,
        INITIAL_TIME, INITIAL_TIME, INITIAL_TIME + 600,
      ).run();
    }
    const rejectedPrincipal = 'z'.repeat(43);
    await assert.rejects(
      nativeRepository.resolveAppleOwner({
        appleSubjectHash: recipientAlias,
        transferSubjectHash: sendingAlias,
        proposedOwnerId: 'ignored-new-owner',
        requiredOwnerId: ownerId,
        requiredPrincipalId: rejectedPrincipal,
        now: INITIAL_TIME + 1,
      }),
      (error: unknown) => error instanceof AppleAuthError
        && error.code === 'APPLE_IDENTITY_LINK_CONFLICT',
    );
    assert.equal(
      (await webRepository.readLinkedIdentity(recipientAlias))?.principalId,
      recipientAlias,
    );
    assert.equal(
      await database.prepare(
        'SELECT principal_id FROM apple_native_grants WHERE grant_hash=?',
      ).bind('T'.repeat(43)).first('principal_id'),
      recipientAlias,
    );
    assert.deepEqual(await nativeRepository.resolveAppleOwner({
      appleSubjectHash: recipientAlias,
      transferSubjectHash: sendingAlias,
      proposedOwnerId: 'ignored-new-owner',
      requiredOwnerId: ownerId,
      requiredPrincipalId: sendingAlias,
      now: INITIAL_TIME + 1,
    }), {ownerId, principalId: sendingAlias, created: false});
    assert.equal(await webRepository.linkAppleIdentity({
      appleSubjectHash: unrelatedSubject,
      ownerId,
      createdAt: INITIAL_TIME + 2,
      updatedAt: INITIAL_TIME + 2,
    }), 'linked');

    const groupRows = await database.prepare(
      `SELECT apple_subject_hash,principal_id,principal_created_at
       FROM apple_identity_links WHERE owner_id=? ORDER BY apple_subject_hash`,
    ).bind(ownerId).all();
    assert.deepEqual(groupRows.results, [
      {apple_subject_hash: sendingAlias, principal_id: sendingAlias, principal_created_at: INITIAL_TIME},
      {apple_subject_hash: recipientAlias, principal_id: sendingAlias, principal_created_at: INITIAL_TIME},
      {apple_subject_hash: unrelatedSubject, principal_id: unrelatedSubject, principal_created_at: INITIAL_TIME + 2},
    ]);
    const regroupedGrants = await database.prepare(
      'SELECT principal_id FROM apple_native_grants WHERE owner_id=? ORDER BY grant_hash',
    ).bind(ownerId).all();
    assert.deepEqual(regroupedGrants.results, [
      {principal_id: sendingAlias},
      {principal_id: sendingAlias},
    ]);

    const addSessions = async (subject: string, prefix: string, createdAt: number) => {
      await webRepository.createSession({
        schemaVersion: 2,
        sessionHash: prefix.repeat(43),
        ownerId,
        ownerBinding: prefix.toUpperCase().repeat(43),
        appleSubjectHash: subject,
        encryptedCredentials: `v2.${prefix.repeat(16)}.${prefix.repeat(32)}`,
        createdAt,
        expiresAt: createdAt + 600,
        lastValidatedAt: createdAt,
      });
      assert.equal(await nativeRepository.createSession({
        schemaVersion: 1,
        identityTokenHash: prefix.toUpperCase().repeat(43),
        sessionHash: `${prefix}n`.repeat(22).slice(0, 43),
        ownerId,
        principalId: (await readD1AppleLinkedIdentity(database, subject))?.principalId ?? subject,
        appleSubjectHash: subject,
        activationState: 'active',
        createdAt,
        expiresAt: createdAt + 600,
        identityTokenExpiresAt: createdAt + 300,
      }), true);
    };
    await addSessions(recipientAlias, 'd', INITIAL_TIME + 3);
    await addSessions(unrelatedSubject, 'e', INITIAL_TIME + 3);

    const explicitDeletion = await deleteAppleAccount({
      repository: deletionRepository,
      authDependencies: null,
      ownerId,
      appleSubjectHash: recipientAlias,
      deletionKey: `v1.${'D'.repeat(43)}`,
      crypto,
      now: INITIAL_TIME + 10,
      completionNow: () => INITIAL_TIME + 10,
    });
    assert.equal(explicitDeletion.deleted, true);
    assert.equal(explicitDeletion.providerCredentials.unreadableSessions, 4);
    const deletionKeyHash = await hashAppleOpaqueToken(
      `v1.${'D'.repeat(43)}`,
      globalThis.crypto,
    );
    assert.deepEqual(
      (await database.prepare(
        `SELECT apple_subject_hash FROM apple_account_deletion_subjects
         WHERE deletion_key_hash=? ORDER BY apple_subject_hash`,
      ).bind(deletionKeyHash).all()).results,
      [
        {apple_subject_hash: sendingAlias},
        {apple_subject_hash: recipientAlias},
      ],
    );
    for (const subject of [sendingAlias, recipientAlias]) {
      assert.equal(await webRepository.readLinkedIdentity(subject), null);
      assert.equal(await database.prepare(
        'SELECT 1 FROM apple_auth_sessions WHERE owner_id=? AND apple_subject_hash=?',
      ).bind(ownerId, subject).first(), null);
      assert.equal(await database.prepare(
        'SELECT 1 FROM apple_native_sessions WHERE owner_id=? AND apple_subject_hash=?',
      ).bind(ownerId, subject).first(), null);
    }
    assert.equal((await webRepository.readLinkedIdentity(unrelatedSubject))?.ownerId, ownerId);
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM workspaces WHERE user_id=?',
    ).bind(ownerId).first(), null);

    const guardedFileInsert = async (
      appleSubjectHash: string | null,
      authorizationStartedAt: number,
      path: string,
      now: number,
    ) => database.prepare(
      `INSERT INTO files(user_id,path,content,version)
       SELECT ?,?,'content',0 WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
       RETURNING path`,
    ).bind(
      ownerId,
      path,
      ...appleOwnerOperationGateBindings({
        userId: ownerId,
        authorizationStartedAt,
        appleSubjectHash,
      }, now),
    ).first();
    assert.equal(
      await guardedFileInsert(
        sendingAlias,
        INITIAL_TIME + 3,
        'stale-sending-alias.txt',
        INITIAL_TIME + 11,
      ),
      null,
    );
    assert.equal(
      await guardedFileInsert(
        recipientAlias,
        INITIAL_TIME + 3,
        'stale-recipient-alias.txt',
        INITIAL_TIME + 11,
      ),
      null,
    );
    assert.notEqual(
      await guardedFileInsert(
        null,
        INITIAL_TIME + 3,
        'host-after-linked-deletion.txt',
        INITIAL_TIME + 11,
      ),
      null,
    );
    assert.notEqual(
      await guardedFileInsert(
        unrelatedSubject,
        INITIAL_TIME + 3,
        'unrelated-after-linked-deletion.txt',
        INITIAL_TIME + 11,
      ),
      null,
    );

    assert.deepEqual(await nativeRepository.resolveAppleOwner({
      appleSubjectHash: recipientAlias,
      transferSubjectHash: sendingAlias,
      proposedOwnerId: ownerId,
      now: INITIAL_TIME + 25,
      authorizationStartedAt: INITIAL_TIME + 20,
    }), {ownerId, principalId: sendingAlias, created: true});
    const renewed = await webRepository.readLinkedIdentity(recipientAlias);
    assert.equal(renewed?.principalCreatedAt, INITIAL_TIME + 20);
    assert.notEqual(
      await guardedFileInsert(
        recipientAlias,
        INITIAL_TIME + 20,
        'new-generation-recipient-alias.txt',
        INITIAL_TIME + 25,
      ),
      null,
    );
    await addSessions(recipientAlias, 'i', INITIAL_TIME + 26);

    const applyNotification = (notification: VerifiedAppleServerNotification, now: number) => (
      applyVerifiedAppleServerNotification({
        repository: deletionRepository,
        notification,
        crypto,
        now,
        completionNow: () => now,
      })
    );
    await applyNotification({
      kind: 'consent-revoked',
      notificationIdHash: 'f'.repeat(43),
      appleSubjectHash: sendingAlias,
      issuedAt: INITIAL_TIME + 15,
      eventTime: INITIAL_TIME + 15,
      receiptExpiresAt: INITIAL_TIME + 615,
    }, INITIAL_TIME + 27);
    assert.equal((await webRepository.readLinkedIdentity(sendingAlias))?.ownerId, ownerId);
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM apple_auth_sessions WHERE owner_id=? AND apple_subject_hash=?',
    ).bind(ownerId, recipientAlias).first(), null);
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM apple_native_sessions WHERE owner_id=? AND apple_subject_hash=?',
    ).bind(ownerId, recipientAlias).first(), null);

    await applyNotification({
      kind: 'email-disabled',
      notificationIdHash: 'g'.repeat(43),
      appleSubjectHash: recipientAlias,
      issuedAt: INITIAL_TIME + 23,
      eventTime: INITIAL_TIME + 23,
      receiptExpiresAt: INITIAL_TIME + 623,
    }, INITIAL_TIME + 30);
    const routine = await webRepository.resolveAppleIdentityGroup({
      appleSubjectHashes: [recipientAlias],
      proposedOwnerId: ownerId,
      requiredOwnerId: ownerId,
      createdAt: INITIAL_TIME + 40,
      updatedAt: INITIAL_TIME + 40,
    }, INITIAL_TIME + 40);
    assert.equal(routine.kind, 'linked');
    assert.equal((await webRepository.readLinkedIdentity(recipientAlias))?.principalCreatedAt, INITIAL_TIME + 20);

    await applyNotification({
      kind: 'account-deleted',
      notificationIdHash: 'h'.repeat(43),
      appleSubjectHash: recipientAlias,
      issuedAt: INITIAL_TIME + 22,
      eventTime: INITIAL_TIME + 22,
      receiptExpiresAt: INITIAL_TIME + 622,
    }, INITIAL_TIME + 50);
    assert.equal(await webRepository.readLinkedIdentity(sendingAlias), null);
    assert.equal(await webRepository.readLinkedIdentity(recipientAlias), null);
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_auth_sessions WHERE owner_id=? AND apple_subject_hash=?',
    ).bind(ownerId, recipientAlias).first(), null);
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_native_sessions WHERE owner_id=? AND apple_subject_hash=?',
    ).bind(ownerId, recipientAlias).first(), null);
    assert.equal((await webRepository.readLinkedIdentity(unrelatedSubject))?.ownerId, ownerId);
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM workspaces WHERE user_id=?',
    ).bind(ownerId).first(), null);
  } finally {
    await miniflare.dispose();
  }
});

test('D1 0013 cutover invalidates unreconstructable stale alias ceremonies and sessions', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    for (const name of [
      '0000_dashing_epoch.sql',
      '0001_eager_sheva_callister.sql',
      '0002_shallow_sabra.sql',
      '0003_wet_edwin_jarvis.sql',
      '0004_native_apple_bridge.sql',
      '0005_sync_snapshot_revision.sql',
      '0006_dear_luckman.sql',
      '0007_puzzling_tempest.sql',
      '0008_long_fat_cobra.sql',
      '0009_apple_identity_principals.sql',
      '0010_native_apple_grants.sql',
      '0011_durable_deletion_subjects.sql',
      '0012_owner_external_operation_leases.sql',
    ]) {
      const migration = await readFile(`drizzle/${name}`, 'utf8');
      for (const statement of migration
        .split('--> statement-breakpoint')
        .map(value => value.trim())
        .filter(Boolean)) await database.prepare(statement).run();
    }
    const deletedOwner = `apple-owner:v1.${'a'.repeat(43)}`;
    const reboundOwner = `apple-owner:v1.${'b'.repeat(43)}`;
    const retainedSubject = 'c'.repeat(43);
    const erasedAlias = 'd'.repeat(43);
    const providerCredentials = JSON.stringify({
      credentialsFound: 0,
      credentialsRevoked: 0,
      unreadableSessions: 0,
      failedRevocations: 0,
      manualRevocationRequired: true,
    });
    const originConnections = JSON.stringify(NO_ORIGIN_CONNECTIONS);
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,apple_principal_id,
        delete_owner_data,provider_credentials,origin_connections,completion_fence_token,
        started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,?,1,?,?,?,?,?,?)`,
    ).bind(
      'A'.repeat(43),
      'B'.repeat(43),
      deletedOwner,
      retainedSubject,
      retainedSubject,
      providerCredentials,
      originConnections,
      'C'.repeat(43),
      1,
      2,
      4_000_000_000,
    ).run();
    await database.prepare(
      `INSERT INTO apple_account_deletion_subjects(deletion_key_hash,apple_subject_hash)
       VALUES(?,?)`,
    ).bind('A'.repeat(43), retainedSubject).run();

    // Source-base 0.2 could no longer prove that this rebound subject was the erased
    // second alias of the completed owner-wide deletion above.
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(erasedAlias, erasedAlias, 3, reboundOwner, 3, 3).run();
    const oldWebSession: AppleAuthSessionRecord = {
      schemaVersion: 2,
      sessionHash: 'E'.repeat(43),
      ownerId: reboundOwner,
      ownerBinding: 'e'.repeat(43),
      appleSubjectHash: erasedAlias,
      encryptedCredentials: `v2.${'e'.repeat(16)}.${'e'.repeat(32)}`,
      createdAt: 3,
      expiresAt: 4_000_000_000,
      lastValidatedAt: 3,
    };
    await database.prepare(
      `INSERT INTO apple_auth_sessions(
        schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
        encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
      ) VALUES(?,?,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      oldWebSession.schemaVersion,
      oldWebSession.sessionHash,
      oldWebSession.ownerId,
      oldWebSession.ownerBinding,
      oldWebSession.appleSubjectHash,
      oldWebSession.encryptedCredentials,
      oldWebSession.createdAt,
      oldWebSession.expiresAt,
      oldWebSession.lastValidatedAt,
    ).run();
    const oldNativeSession: AppleNativeSessionRecord = {
      schemaVersion: 1,
      identityTokenHash: 'F'.repeat(43),
      sessionHash: 'f'.repeat(43),
      ownerId: reboundOwner,
      principalId: erasedAlias,
      appleSubjectHash: erasedAlias,
      activationState: 'active',
      createdAt: 3,
      expiresAt: 4_000_000_000,
      identityTokenExpiresAt: 4_000_000_000,
    };
    const oldNativeGrant: AppleNativeGrantRecord = {
      schemaVersion: 1,
      grantHash: 'G'.repeat(43),
      authorizationCodeHash: 'H'.repeat(43),
      sessionHash: oldNativeSession.sessionHash,
      ownerId: reboundOwner,
      principalId: erasedAlias,
      appleSubjectHash: erasedAlias,
      ownerBinding: 'g'.repeat(43),
      encryptedCredentials: `v1.${'g'.repeat(16)}.${'g'.repeat(32)}`,
      createdAt: 3,
      lastValidatedAt: 3,
      expiresAt: 4_000_000_000,
      revocationPendingAt: null,
    };
    await database.prepare(
      `INSERT INTO apple_native_sessions(
        schema_version,identity_token_hash,session_hash,owner_id,apple_subject_hash,
        created_at,expires_at,identity_token_expires_at,revoked_at
      ) VALUES(?,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      oldNativeSession.schemaVersion,
      oldNativeSession.identityTokenHash,
      oldNativeSession.sessionHash,
      oldNativeSession.ownerId,
      oldNativeSession.appleSubjectHash,
      oldNativeSession.createdAt,
      oldNativeSession.expiresAt,
      oldNativeSession.identityTokenExpiresAt,
    ).run();
    await database.prepare(
      `INSERT INTO apple_native_grants(
        schema_version,grant_hash,authorization_code_hash,session_hash,owner_id,
        principal_id,apple_subject_hash,owner_binding,encrypted_credentials,
        created_at,last_validated_at,expires_at,revocation_pending_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      oldNativeGrant.schemaVersion,
      oldNativeGrant.grantHash,
      oldNativeGrant.authorizationCodeHash,
      oldNativeGrant.sessionHash,
      oldNativeGrant.ownerId,
      oldNativeGrant.principalId,
      oldNativeGrant.appleSubjectHash,
      oldNativeGrant.ownerBinding,
      oldNativeGrant.encryptedCredentials,
      oldNativeGrant.createdAt,
      oldNativeGrant.lastValidatedAt,
      oldNativeGrant.expiresAt,
    ).run();

    for (const name of [
      '0013_general_external_operation_leases.sql',
      '0014_native_apple_session_activation.sql',
    ]) {
      const migration = await readFile(`drizzle/${name}`, 'utf8');
      for (const statement of migration
        .split('--> statement-breakpoint')
        .map(value => value.trim())
        .filter(Boolean)) await database.prepare(statement).run();
    }
    const cutoverAtValue: unknown = await database.prepare(
      'SELECT cutover_at FROM apple_auth_admission_cutover WHERE singleton=1',
    ).first('cutover_at');
    assert.equal(typeof cutoverAtValue, 'number');
    const cutoverAt = cutoverAtValue as number;
    assert.deepEqual((await database.prepare(
      `SELECT apple_subject_hash FROM apple_account_deletion_subjects
       WHERE deletion_key_hash=? ORDER BY apple_subject_hash`,
    ).bind('A'.repeat(43)).all()).results, [{apple_subject_hash: retainedSubject}]);

    const webRepository = createD1AppleAuthRepository(database);
    const nativeRepository = createD1AppleNativeAuthRepository(database);
    const rolloutFlow: AppleAuthFlow = {
      schemaVersion: 2,
      stateHash: 'Q'.repeat(43),
      purpose: 'authenticate',
      ownerId: null,
      nonceHash: 'R'.repeat(43),
      browserBindingHash: 'S'.repeat(43),
      ownerBinding: 'T'.repeat(43),
      returnTo: '/',
      createdAt: cutoverAt,
      expiresAt: cutoverAt + 600,
    };
    await assert.rejects(
      webRepository.createFlow(rolloutFlow),
      matchesCode('APPLE_AUTH_ROLLOUT_PENDING'),
    );
    await webRepository.createFlow({
      ...rolloutFlow,
      stateHash: 'U'.repeat(43),
      createdAt: cutoverAt + 1,
    });
    assert.notEqual(await webRepository.consumeFlow('U'.repeat(43), cutoverAt + 2), null);
    await database.prepare(
      `INSERT INTO apple_auth_flows(
        schema_version,state_hash,purpose,owner_id,nonce_hash,browser_binding_hash,
        owner_binding,return_to,created_at,expires_at,consumed_at
      ) VALUES(2,?,'authenticate',NULL,?,?,?,'/',?,?,NULL)`,
    ).bind(
      'V'.repeat(43),
      'W'.repeat(43),
      'X'.repeat(43),
      'Y'.repeat(43),
      cutoverAt,
      cutoverAt + 600,
    ).run();
    assert.equal(await webRepository.consumeFlow('V'.repeat(43), cutoverAt + 2), null);
    const oldWorkerSession = {
      ...oldWebSession,
      sessionHash: 'Z'.repeat(43),
      createdAt: cutoverAt,
      lastValidatedAt: cutoverAt,
    };
    await database.prepare(
      `INSERT INTO apple_auth_sessions(
        schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
        encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
      ) VALUES(?,?,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      oldWorkerSession.schemaVersion,
      oldWorkerSession.sessionHash,
      oldWorkerSession.ownerId,
      oldWorkerSession.ownerBinding,
      oldWorkerSession.appleSubjectHash,
      oldWorkerSession.encryptedCredentials,
      oldWorkerSession.createdAt,
      cutoverAt + 600,
      oldWorkerSession.lastValidatedAt,
    ).run();
    assert.equal(await webRepository.readSession(oldWorkerSession.sessionHash, cutoverAt + 1), null);
    assert.equal(await webRepository.readSession(oldWebSession.sessionHash, cutoverAt + 1), null);
    assert.equal(await nativeRepository.readSession(oldNativeSession.sessionHash, cutoverAt + 1), null);
    assert.equal(
      await nativeRepository.readSessionWithGrant(oldNativeSession.sessionHash, cutoverAt + 1),
      null,
    );
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM apple_auth_sessions WHERE session_hash=?',
    ).bind(oldWebSession.sessionHash).first(), null);
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM apple_native_grants WHERE grant_hash=?',
    ).bind(oldNativeGrant.grantHash).first(), null);
    await assert.rejects(
      webRepository.updateSession({
        expected: oldWebSession,
        next: {...oldWebSession, lastValidatedAt: cutoverAt + 1},
        now: cutoverAt + 1,
      }),
      /APPLE_SESSION_UPDATE_CONFLICT/,
    );
    assert.equal(await nativeRepository.updateSessionAndGrant({
      sessionHash: oldNativeSession.sessionHash,
      ownerId: reboundOwner,
      principalId: erasedAlias,
      appleSubjectHash: erasedAlias,
      expectedEncryptedCredentials: oldNativeGrant.encryptedCredentials,
      expectedLastValidatedAt: oldNativeGrant.lastValidatedAt,
      encryptedCredentials: `v1.${'i'.repeat(16)}.${'i'.repeat(32)}`,
      lastValidatedAt: cutoverAt + 1,
      sessionExpiresAt: cutoverAt + 901,
      identityTokenExpiresAt: cutoverAt + 601,
      grantExpiresAt: cutoverAt + 2_001,
    }), false);

    const staleWebBinding = webRepository.resolveAppleIdentityGroup({
      appleSubjectHashes: [erasedAlias],
      proposedOwnerId: reboundOwner,
      requiredOwnerId: null,
      createdAt: cutoverAt + 1,
      updatedAt: cutoverAt + 1,
    }, cutoverAt);
    await assert.rejects(staleWebBinding, matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
    await assert.rejects(nativeRepository.resolveAppleOwner({
      appleSubjectHash: erasedAlias,
      proposedOwnerId: reboundOwner,
      now: cutoverAt + 1,
      authorizationStartedAt: cutoverAt,
    }), matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));

    const staleWebSession = {...oldWebSession, sessionHash: 'I'.repeat(43), createdAt: cutoverAt + 1};
    await assert.rejects(
      webRepository.createSession(staleWebSession, cutoverAt),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    const staleNativeSession = {
      ...oldNativeSession,
      identityTokenHash: 'J'.repeat(43),
      sessionHash: 'j'.repeat(43),
      createdAt: cutoverAt + 1,
    };
    await assert.rejects(
      nativeRepository.createSession(staleNativeSession, cutoverAt),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    const staleNativeGrant = {
      ...oldNativeGrant,
      grantHash: 'K'.repeat(43),
      authorizationCodeHash: 'L'.repeat(43),
      sessionHash: staleNativeSession.sessionHash,
      createdAt: cutoverAt + 1,
      lastValidatedAt: cutoverAt + 1,
    };
    await assert.rejects(
      nativeRepository.createSessionWithGrant(staleNativeSession, staleNativeGrant, cutoverAt),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );

    const freshAuthorizationStartedAt = cutoverAt + 1;
    assert.deepEqual(await webRepository.resolveAppleIdentityGroup({
      appleSubjectHashes: [erasedAlias],
      proposedOwnerId: reboundOwner,
      requiredOwnerId: null,
      createdAt: cutoverAt + 2,
      updatedAt: cutoverAt + 2,
    }, freshAuthorizationStartedAt), {
      kind: 'linked',
      ownerId: reboundOwner,
      principalId: erasedAlias,
      created: false,
    });
    const freshWebSession = {
      ...oldWebSession,
      sessionHash: 'M'.repeat(43),
      createdAt: cutoverAt + 2,
      lastValidatedAt: cutoverAt + 2,
    };
    await webRepository.createSession(freshWebSession, freshAuthorizationStartedAt);
    assert.notEqual(
      await webRepository.readSession(freshWebSession.sessionHash, cutoverAt + 2),
      null,
    );
    const freshNativeSession = {
      ...oldNativeSession,
      identityTokenHash: 'N'.repeat(43),
      sessionHash: 'n'.repeat(43),
      createdAt: cutoverAt + 2,
    };
    const freshNativeGrant = {
      ...oldNativeGrant,
      grantHash: 'O'.repeat(43),
      authorizationCodeHash: 'P'.repeat(43),
      sessionHash: freshNativeSession.sessionHash,
      createdAt: cutoverAt + 2,
      lastValidatedAt: cutoverAt + 2,
    };
    assert.equal(await nativeRepository.createSessionWithGrant(
      freshNativeSession,
      freshNativeGrant,
      freshAuthorizationStartedAt,
    ), true);
    assert.notEqual(
      await nativeRepository.readSessionWithGrant(freshNativeSession.sessionHash, cutoverAt + 2),
      null,
    );
  } finally {
    await miniflare.dispose();
  }
});

test('D1 Apple exchange markers serialize provider work and survive unresolved credentials until deletion', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const cutoverValue: unknown = await database.prepare(
      'SELECT cutover_at FROM apple_auth_admission_cutover WHERE singleton=1',
    ).first('cutover_at');
    assert.equal(typeof cutoverValue, 'number');
    const cutoverAt = cutoverValue as number;
    const exchangeRepository = createD1AppleOwnerExternalOperationLeaseRepository(database);
    const deletionRepository = createD1AppleAccountDeletionRepository(database);
    const webRepository = createD1AppleAuthRepository(database);
    const ownerId = 'linked-owner-possible-credential';
    const subjectHash = 'q'.repeat(43);
    const principalId = 'r'.repeat(43);
    const startedAt = cutoverAt + 1;
    const claimedAt = cutoverAt + 2;
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subjectHash, principalId, startedAt, ownerId, startedAt, startedAt).run();
    const authorization = {userId: ownerId, appleSubjectHash: subjectHash, authorizationStartedAt: startedAt};
    const attemptA = 'a'.repeat(43);
    const attemptB = 'b'.repeat(43);
    await exchangeRepository.claim({
      authorization,
      operationKind: 'apple-auth',
      resourceId: subjectHash,
      leaseToken: attemptA,
      now: claimedAt,
    });
    assert.deepEqual(await database.prepare(
      `SELECT attempt_token,credential_state FROM apple_auth_possible_credentials
       WHERE owner_id=? AND apple_principal_id=?`,
    ).bind(ownerId, principalId).first(), {
      attempt_token: attemptA,
      credential_state: 'prepared',
    });
    await assert.rejects(deletionRepository.beginAppleAccountDeletion({
      ownerId,
      appleSubjectHash: subjectHash,
      deleteOwnerData: false,
      ownerBinding: 'o'.repeat(43),
      deletionKeyHash: 'd'.repeat(43),
      revocationLeaseToken: 'l'.repeat(43),
      startedAt: claimedAt + 1,
      leaseClaimedAt: claimedAt + 1,
      expiresAt: claimedAt + 601,
    }), matchesCode('APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS'));
    await assert.rejects(exchangeRepository.claim({
      authorization,
      operationKind: 'apple-auth',
      resourceId: subjectHash,
      leaseToken: attemptB,
      now: claimedAt + 1,
    }), matchesExternalCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));

    await exchangeRepository.markPossibleCredential(attemptA, claimedAt + 1);
    await exchangeRepository.release(attemptA);
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_owner_external_operation_leases WHERE lease_token=?',
    ).bind(attemptA).first(), null);
    const afterThirtyDays = claimedAt + 31 * 24 * 60 * 60;
    await drainExpiredAppleAuthLifecycleRecords(database, afterThirtyDays);
    assert.deepEqual(await database.prepare(
      `SELECT attempt_token,credential_state FROM apple_auth_possible_credentials
       WHERE owner_id=? AND apple_principal_id=?`,
    ).bind(ownerId, principalId).first(), {
      attempt_token: attemptA,
      credential_state: 'possible',
    });

    await exchangeRepository.claim({
      authorization,
      operationKind: 'apple-auth',
      resourceId: subjectHash,
      leaseToken: attemptB,
      now: afterThirtyDays,
    });
    await exchangeRepository.markPossibleCredential(attemptB, afterThirtyDays + 1);
    await assert.rejects(
      exchangeRepository.release(attemptA, true, afterThirtyDays + 1),
      matchesExternalCode('APPLE_OWNER_EXTERNAL_OPERATION_LEASE_EXPIRED'),
    );
    const session: AppleAuthSessionRecord = {
      schemaVersion: 2,
      sessionHash: 's'.repeat(43),
      ownerId,
      ownerBinding: 't'.repeat(43),
      appleSubjectHash: subjectHash,
      encryptedCredentials: `v2.${'u'.repeat(16)}.${'v'.repeat(32)}`,
      createdAt: afterThirtyDays + 1,
      expiresAt: afterThirtyDays + 601,
      lastValidatedAt: afterThirtyDays + 1,
    };
    await webRepository.createSession(session, startedAt);
    await exchangeRepository.complete(attemptB, afterThirtyDays + 2);
    assert.notEqual(await webRepository.readSession(session.sessionHash, afterThirtyDays + 2), null);
    assert.deepEqual(await database.prepare(
      `SELECT attempt_token,credential_state FROM apple_auth_possible_credentials
       WHERE owner_id=? AND apple_principal_id=?`,
    ).bind(ownerId, principalId).first(), {
      attempt_token: attemptA,
      credential_state: 'possible',
    });

    const deletionKey = `v1.${'D'.repeat(43)}`;
    const deletion = await deleteAppleAccount({
      repository: deletionRepository,
      authDependencies: null,
      ownerId,
      appleSubjectHash: subjectHash,
      deletionKey,
      crypto,
      now: afterThirtyDays + 3,
      completionNow: () => afterThirtyDays + 4,
      revocationLeaseToken: () => `${'M'.repeat(42)}A`,
    });
    assert.equal(deletion.providerCredentials.manualRevocationRequired, true);
    assert.equal(deletion.providerCredentials.unreadableSessions, 2);
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_auth_possible_credentials WHERE owner_id=?',
    ).bind(ownerId).first(), null);
    assert.equal((await deleteAppleAccount({
      repository: deletionRepository,
      authDependencies: null,
      ownerId,
      appleSubjectHash: subjectHash,
      deletionKey,
      crypto,
      now: afterThirtyDays + 5,
      revocationLeaseToken: () => `${'N'.repeat(42)}A`,
    })).providerCredentials.manualRevocationRequired, true);

    const retryOwner = 'linked-owner-prepared-retry';
    const retrySubject = 'x'.repeat(43);
    const retryPrincipal = 'y'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(retrySubject, retryPrincipal, startedAt, retryOwner, startedAt, startedAt).run();
    const retryAuthorization = {
      userId: retryOwner,
      appleSubjectHash: retrySubject,
      authorizationStartedAt: startedAt,
    };
    const preparedA = 'c'.repeat(43);
    const preparedB = 'e'.repeat(43);
    await exchangeRepository.claim({
      authorization: retryAuthorization,
      operationKind: 'apple-auth',
      resourceId: retrySubject,
      leaseToken: preparedA,
      now: claimedAt,
    });
    await exchangeRepository.claim({
      authorization: retryAuthorization,
      operationKind: 'apple-auth',
      resourceId: retrySubject,
      leaseToken: preparedB,
      now: claimedAt + APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS,
    });
    assert.deepEqual(await database.prepare(
      `SELECT attempt_token,credential_state FROM apple_auth_possible_credentials
       WHERE owner_id=? AND apple_principal_id=?`,
    ).bind(retryOwner, retryPrincipal).first(), {
      attempt_token: preparedB,
      credential_state: 'prepared',
    });
    await assert.rejects(
      exchangeRepository.release(preparedA, true, claimedAt + APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS),
      matchesExternalCode('APPLE_OWNER_EXTERNAL_OPERATION_LEASE_EXPIRED'),
    );
    await exchangeRepository.markPossibleCredential(
      preparedB,
      claimedAt + APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS + 1,
    );
    await exchangeRepository.complete(
      preparedB,
      claimedAt + APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS + 2,
    );
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_auth_possible_credentials WHERE owner_id=?',
    ).bind(retryOwner).first(), null);

    const deletionFirstOwner = 'linked-owner-deletion-first';
    const deletionFirstSubject = 'z'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(
      deletionFirstSubject,
      deletionFirstSubject,
      startedAt,
      deletionFirstOwner,
      startedAt,
      startedAt,
    ).run();
    await deletionRepository.beginAppleAccountDeletion({
      ownerId: deletionFirstOwner,
      appleSubjectHash: deletionFirstSubject,
      deleteOwnerData: false,
      ownerBinding: 'w'.repeat(43),
      deletionKeyHash: 'k'.repeat(43),
      revocationLeaseToken: 'j'.repeat(43),
      startedAt: claimedAt,
      leaseClaimedAt: claimedAt,
      expiresAt: claimedAt + 600,
    });
    await assert.rejects(exchangeRepository.claim({
      authorization: {
        userId: deletionFirstOwner,
        appleSubjectHash: deletionFirstSubject,
        authorizationStartedAt: startedAt,
      },
      operationKind: 'apple-auth',
      resourceId: deletionFirstSubject,
      leaseToken: 'i'.repeat(43),
      now: claimedAt + 1,
    }), matchesExternalCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
  } finally {
    await miniflare.dispose();
  }
});

test('D1 owner-wide alias tombstones block stale web and native Apple authorization resurrection', async () => {
  const require = createRequire(import.meta.url);
  const wranglerRequire = createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare} = wranglerRequire('miniflare');
  const miniflare = new Miniflare({
    modules: true,
    script: 'export default {fetch(){return new Response("ok")}}',
    compatibilityDate: '2026-05-15',
    compatibilityFlags: ['nodejs_compat'],
    d1Databases: ['DB'],
    log: undefined,
  });
  try {
    const database = await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const webRepository = createD1AppleAuthRepository(database);
    const nativeRepository = createD1AppleNativeAuthRepository(database);
    const deletionRepository = createD1AppleAccountDeletionRepository(database);
    const ownerId = `apple-owner:v1.${'o'.repeat(43)}`;
    const subject = 's'.repeat(43);
    const transferAlias = 't'.repeat(43);
    const principal = 'p'.repeat(43);
    for (const appleSubjectHash of [subject, transferAlias]) {
      await database.prepare(
        `INSERT INTO apple_identity_links(
          apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
        ) VALUES(?,?,?,?,?,?)`,
      ).bind(
        appleSubjectHash,
        principal,
        INITIAL_TIME,
        ownerId,
        INITIAL_TIME,
        INITIAL_TIME,
      ).run();
    }
    await database.prepare(
      'INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,?,?,0)',
    ).bind(ownerId, '{}', '[]').run();

    const deletionKey = `v1.${'D'.repeat(43)}`;
    const deletion = await deleteAppleAccount({
      repository: deletionRepository,
      authDependencies: null,
      ownerId,
      appleSubjectHash: transferAlias,
      deletionKey,
      crypto,
      now: INITIAL_TIME + 10,
      completionNow: () => INITIAL_TIME + 11,
      revocationLeaseToken: () => `${'L'.repeat(42)}A`,
    });
    assert.equal(deletion.deleted, true);
    const deletionKeyHash = await hashAppleOpaqueToken(deletionKey, crypto);
    assert.deepEqual(
      (await database.prepare(
        `SELECT apple_subject_hash FROM apple_account_deletion_subjects
         WHERE deletion_key_hash=? ORDER BY apple_subject_hash`,
      ).bind(deletionKeyHash).all()).results,
      [
        {apple_subject_hash: subject},
        {apple_subject_hash: transferAlias},
      ],
    );
    assert.equal(await webRepository.readLinkedIdentity(subject), null);
    assert.equal(await webRepository.readLinkedIdentity(transferAlias), null);

    const staleAuthorizationStartedAt = INITIAL_TIME + 9;
    await assert.rejects(
      webRepository.resolveAppleIdentityGroup({
        appleSubjectHashes: [subject],
        proposedOwnerId: `apple-owner:v1.${'x'.repeat(43)}`,
        requiredOwnerId: null,
        createdAt: INITIAL_TIME + 12,
        updatedAt: INITIAL_TIME + 12,
      }, staleAuthorizationStartedAt),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    await assert.rejects(
      nativeRepository.resolveAppleOwner({
        appleSubjectHash: 'u'.repeat(43),
        transferSubjectHash: transferAlias,
        proposedOwnerId: `apple-owner:v1.${'y'.repeat(43)}`,
        now: INITIAL_TIME + 12,
        authorizationStartedAt: staleAuthorizationStartedAt,
      }),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );

    const resurrectedOwner = `apple-owner:v1.${'r'.repeat(43)}`;
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(
      transferAlias,
      transferAlias,
      INITIAL_TIME + 12,
      resurrectedOwner,
      INITIAL_TIME + 12,
      INITIAL_TIME + 12,
    ).run();
    const webSession: AppleAuthSessionRecord = {
      schemaVersion: 2,
      sessionHash: 'w'.repeat(43),
      ownerId: resurrectedOwner,
      ownerBinding: 'b'.repeat(43),
      appleSubjectHash: transferAlias,
      encryptedCredentials: `v2.${'w'.repeat(16)}.${'w'.repeat(32)}`,
      createdAt: INITIAL_TIME + 12,
      expiresAt: INITIAL_TIME + 612,
      lastValidatedAt: INITIAL_TIME + 12,
    };
    await assert.rejects(
      webRepository.createSession(webSession, staleAuthorizationStartedAt),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    assert.equal(await webRepository.readSession(webSession.sessionHash, INITIAL_TIME + 12), null);

    const nativeSession: AppleNativeSessionRecord = {
      schemaVersion: 1,
      identityTokenHash: 'I'.repeat(43),
      sessionHash: 'n'.repeat(43),
      ownerId: resurrectedOwner,
      principalId: transferAlias,
      appleSubjectHash: transferAlias,
      activationState: 'active',
      createdAt: INITIAL_TIME + 12,
      expiresAt: INITIAL_TIME + 612,
      identityTokenExpiresAt: INITIAL_TIME + 312,
    };
    await assert.rejects(
      nativeRepository.createSession(nativeSession, staleAuthorizationStartedAt),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    const grant: AppleNativeGrantRecord = {
      schemaVersion: 1,
      grantHash: 'G'.repeat(43),
      authorizationCodeHash: 'C'.repeat(43),
      sessionHash: nativeSession.sessionHash,
      ownerId: resurrectedOwner,
      principalId: transferAlias,
      appleSubjectHash: transferAlias,
      ownerBinding: 'g'.repeat(43),
      encryptedCredentials: `v1.${'g'.repeat(16)}.${'g'.repeat(32)}`,
      createdAt: INITIAL_TIME + 12,
      lastValidatedAt: INITIAL_TIME + 12,
      expiresAt: INITIAL_TIME + 612,
      revocationPendingAt: null,
    };
    await assert.rejects(
      nativeRepository.createSessionWithGrant(
        nativeSession,
        grant,
        staleAuthorizationStartedAt,
      ),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    assert.equal(await nativeRepository.readSession(nativeSession.sessionHash, INITIAL_TIME + 12), null);
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_native_grants WHERE grant_hash=?',
    ).bind(grant.grantHash).first(), null);

    await database.prepare(
      'DELETE FROM apple_identity_links WHERE apple_subject_hash=?',
    ).bind(transferAlias).run();
    assert.deepEqual(await nativeRepository.resolveAppleOwner({
      appleSubjectHash: transferAlias,
      proposedOwnerId: resurrectedOwner,
      now: INITIAL_TIME + 13,
      authorizationStartedAt: INITIAL_TIME + 12,
    }), {
      ownerId: resurrectedOwner,
      principalId: transferAlias,
      created: true,
    });
    assert.equal(
      (await nativeRepository.readLinkedIdentity(transferAlias))?.principalCreatedAt,
      INITIAL_TIME + 12,
    );
  } finally {
    await miniflare.dispose();
  }
});

function matchesCode(code: string): (error: unknown) => boolean {
  return error => error instanceof AppleAuthError && error.code === code;
}

function matchesExternalCode(code: string): (error: unknown) => boolean {
  return error => error instanceof AppleOwnerExternalOperationError && error.code === code;
}

function formRequest(body: URLSearchParams | string): Request {
  return new Request('https://sandbox.example.test/api/auth/apple/callback', {
    method: 'POST',
    headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    body,
  });
}

function jsonRequest(body: unknown): Request {
  return new Request('https://sandbox.example.test/api/auth/apple/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
}

function notificationRequest(body: unknown): Request {
  return new Request('https://sandbox.example.test/api/auth/apple/notifications', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
}

async function applyAllMigrations(database: D1Database): Promise<void> {
  for (const name of [
    '0000_dashing_epoch.sql',
    '0001_eager_sheva_callister.sql',
    '0002_shallow_sabra.sql',
    '0003_wet_edwin_jarvis.sql',
    '0004_native_apple_bridge.sql',
    '0005_sync_snapshot_revision.sql',
    '0006_dear_luckman.sql',
    '0007_puzzling_tempest.sql',
    '0008_long_fat_cobra.sql',
    '0009_apple_identity_principals.sql',
    '0010_native_apple_grants.sql',
    '0011_durable_deletion_subjects.sql',
    '0012_owner_external_operation_leases.sql',
    '0013_general_external_operation_leases.sql',
    '0014_native_apple_session_activation.sql',
  ]) {
    const migration = await readFile(`drizzle/${name}`, 'utf8');
    for (const statement of migration
      .split('--> statement-breakpoint')
      .map(value => value.trim())
      .filter(Boolean)) {
      await database.prepare(statement).run();
    }
  }
}

async function countRows(
  database: D1Database,
  table: string,
  column: 'user_id' | 'owner_id',
  ownerId: string,
): Promise<number> {
  return z.object({count: z.number().int().nonnegative()}).parse(
    await database.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE ${column}=?`)
      .bind(ownerId).first(),
  ).count;
}

async function seedOwnerRecords(
  database: D1Database,
  ownerId: string,
  appleSubjectHash: string,
  prefix: string,
  createdAt = INITIAL_TIME,
): Promise<void> {
  const syncIncarnation = [...new TextEncoder().encode(prefix)]
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('').padEnd(64, '0').slice(0, 64);
  const syncWorkspaceId = `${prefix}_workspace`.padEnd(32, prefix).slice(0, 32);
  const syncEpoch = `${prefix}_epoch`.padEnd(16, '0');
  await database.prepare(
    'INSERT INTO apple_identity_links(apple_subject_hash,owner_id,created_at,updated_at) VALUES(?,?,?,?)',
  ).bind(appleSubjectHash, ownerId, createdAt, createdAt).run();
  await database.prepare(
    `INSERT INTO apple_auth_sessions(
      schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
      encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
    ) VALUES(2,?,?,?,?,?,?,?,?,NULL)`,
  ).bind(
    prefix.repeat(43),
    ownerId,
    prefix.toUpperCase().repeat(43),
    appleSubjectHash,
    `v2.${prefix.repeat(16)}.${prefix.repeat(32)}`,
    createdAt,
    createdAt + 600,
    createdAt,
  ).run();
  await database.prepare(
    `INSERT INTO apple_native_sessions(
      schema_version,identity_token_hash,session_hash,owner_id,apple_subject_hash,
      created_at,expires_at,identity_token_expires_at,revoked_at
    ) VALUES(1,?,?,?,?,?,?,?,NULL)`,
  ).bind(
    prefix.toUpperCase().repeat(43),
    `${prefix}n`.repeat(22).slice(0, 43),
    ownerId,
    appleSubjectHash,
    createdAt,
    createdAt + 600,
    createdAt + 600,
  ).run();
  await database.prepare(
    'INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,?,?,0)',
  ).bind(ownerId, '{}', '[]').run();
  await database.prepare(
    'INSERT INTO files(user_id,path,content,version) VALUES(?,?,?,0)',
  ).bind(ownerId, `${prefix}.txt`, 'content').run();
  await database.prepare(
    'INSERT INTO receipts(user_id,id,payload,created_at) VALUES(?,?,?,?)',
  ).bind(ownerId, `${prefix}-receipt`, '{}', new Date(createdAt * 1_000).toISOString()).run();
  await database.prepare(
    'INSERT INTO usage(user_id,window,calls) VALUES(?,?,1)',
  ).bind(ownerId, `${prefix}-window`).run();
  await database.prepare(
    `INSERT INTO sync_workspaces(
      user_id,workspace_id,epoch,incarnation,recovery,revision,created_at,updated_at
    ) VALUES(?,?,?,?,?,0,?,?)`,
  ).bind(
    ownerId,
    syncWorkspaceId,
    syncEpoch,
    syncIncarnation,
    '{}',
    new Date(createdAt * 1_000).toISOString(),
    new Date(createdAt * 1_000).toISOString(),
  ).run();
  await database.prepare(
    `INSERT INTO sync_workspace_epochs(
      user_id,workspace_id,epoch,incarnation,enrolled_at
    ) VALUES(?,?,?,?,?)`,
  ).bind(
    ownerId,
    syncWorkspaceId,
    syncEpoch,
    syncIncarnation,
    new Date(createdAt * 1_000).toISOString(),
  ).run();
  await database.prepare(
    `INSERT INTO sync_records(
      user_id,workspace_id,record_id,revision,mutation_id,envelope,updated_at
    ) VALUES(?,?,?,0,?,?,?)`,
  ).bind(
    ownerId,
    syncWorkspaceId,
    `${prefix}-record`,
    `${prefix}-mutation`,
    '{}',
    new Date(createdAt * 1_000).toISOString(),
  ).run();
  await database.prepare(
    `INSERT INTO origin_auth_flows(
      state_hash,owner_id,return_to,created_at,expires_at,consumed_at
    ) VALUES(?,?,?,?,?,NULL)`,
  ).bind(prefix.repeat(43), ownerId, '/', createdAt, createdAt + 600).run();
  await database.prepare(
    `INSERT INTO origin_installations(
      installation_id,owner_id,namespace_id,created_at,updated_at
    ) VALUES(?,?,?,?,?)`,
  ).bind(`${prefix}-installation`, ownerId, `${prefix}-namespace`, createdAt, createdAt).run();
}

function pemFromPKCS8(value: ArrayBuffer): string {
  const encoded = base64(new Uint8Array(value));
  const lines = encoded.match(/.{1,64}/g) ?? [];
  return `-----BEGIN PRIVATE KEY-----\n${lines.join('\n')}\n-----END PRIVATE KEY-----\n`;
}

function decodeText(value: string): string {
  return new TextDecoder().decode(base64URLDecode(value));
}

function base64URL(value: Uint8Array): string {
  return base64(value).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

function base64(value: Uint8Array): string {
  let result = '';
  for (const byte of value) result += String.fromCharCode(byte);
  return btoa(result);
}

function base64URLDecode(value: string): Uint8Array {
  const padding = '='.repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(
    atob(value.replaceAll('-', '+').replaceAll('_', '/') + padding),
    character => character.charCodeAt(0),
  );
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  const result = new ArrayBuffer(value.byteLength);
  new Uint8Array(result).set(value);
  return result;
}
