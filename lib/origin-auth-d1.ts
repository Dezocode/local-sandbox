import { z } from 'zod';
import {
  OriginAuthError,
  ORIGIN_RECEIPT_CLOCK_SKEW_SECONDS,
  type OriginInstallationReceipt,
  type OriginReceiptReplayStore,
} from './origin-auth.ts';
import {
  APPLE_OWNER_OPERATION_ALLOWED_SQL,
  appleOwnerOperationGateBindings,
  isAppleOwnerOperationAllowed,
  type AppleOwnerOperationAuthorization,
} from './apple-auth-owner-d1.ts';
import {
  APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS,
  AppleOwnerExternalOperationError,
  createD1AppleOwnerExternalOperationLeaseRepository,
} from './apple-auth-external-operation-d1.ts';

export const ORIGIN_EXTERNAL_OPERATION_LEASE_SECONDS=APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS;
const flowRowSchema=z.object({return_to:z.string()});
const installationRowSchema=z.object({installation_id:z.string(),namespace_id:z.string(),created_at:z.number().int(),updated_at:z.number().int()});
const installationIncarnationRowSchema=installationRowSchema.extend({
  owner_id:z.string().min(1).max(1_000),
  issued_at_fence:z.number().int().nonnegative(),
}).strict();
const possibleInstallationRowSchema=z.object({flow_token:z.string().regex(/^[A-Za-z0-9_-]{43}$/)}).strict();
const possibleInstallationSnapshotRowSchema=possibleInstallationRowSchema.extend({
  marked_at:z.number().int().nonnegative(),
}).strict();
const installationIdSchema=z.string().regex(/^(?:i|inst)_[a-z0-9]{8,100}$/);
const opaqueHashSchema=z.string().regex(/^[A-Za-z0-9_-]{43}$/);

export type OriginInstallation={
  installationId:string;
  namespaceId:string;
  createdAt:number;
  updatedAt:number;
};
export type OriginInstallationIncarnation=OriginInstallation&{
  ownerId:string;
  receiptIssuedAtFence:number;
};
export type OriginInstallationAbsenceIncarnation={
  installationId:string;
  ownerId:string;
  receiptIssuedAtFence:number;
};
export type OriginDashboardState={
  installations:OriginInstallation[];
  possibleInstallation:{acknowledgementId:string}|null;
};
export type OriginInstallationState='present'|'absent';
export type OriginInstallationCompletionState=
  |{kind:'present'}
  |{kind:'absent';absence:OriginInstallationAbsenceIncarnation};

export type OriginD1Repository={
  replayStore:OriginReceiptReplayStore;
  createFlow(input:{stateHash:string;ownerId:string;returnTo:string;createdAt:number;expiresAt:number;authorizationStartedAt:number;appleSubjectHash:string|null}):Promise<void>;
  claimInstallationFlowLease(input:{authorization:AppleOwnerOperationAuthorization;stateHash:string;installationId:string;receiptIssuedAt:number;now:number}):Promise<{expiresAt:number}>;
  consumeFlow(stateHash:string,ownerId:string,now:number,authorizationStartedAt:number,appleSubjectHash:string|null):Promise<{returnTo:string}|null>;
  saveInstallation(ownerId:string,receipt:OriginInstallationReceipt,now:number,authorizationStartedAt:number,appleSubjectHash:string|null):Promise<OriginInstallation>;
  saveInstallationAndCompleteFlow(input:{ownerId:string;stateHash:string;receipt:OriginInstallationReceipt;now:number;authorizationStartedAt:number;appleSubjectHash:string|null}):Promise<OriginInstallation>;
  releaseInstallationFlowLease(stateHash:string):Promise<void>;
  readDashboardState(authorization:AppleOwnerOperationAuthorization,now:()=>number):Promise<OriginDashboardState>;
  listInstallations(authorization:AppleOwnerOperationAuthorization,now:()=>number):Promise<OriginInstallation[]>;
  readPossibleInstallation(authorization:AppleOwnerOperationAuthorization,now:()=>number):Promise<{acknowledgementId:string}|null>;
  acknowledgePossibleInstallation(authorization:AppleOwnerOperationAuthorization,acknowledgementId:string,now:number):Promise<void>;
  ownsInstallation(ownerId:string,installationId:string):Promise<boolean>;
  deleteInstallation(ownerId:string,installationId:string,now:number,authorizationStartedAt:number,appleSubjectHash:string|null):Promise<boolean>;
  deleteInstallationForIncarnation(authorization:AppleOwnerOperationAuthorization,incarnation:OriginInstallationIncarnation,now:number):Promise<OriginInstallationAbsenceIncarnation>;
  claimExternalOperationLease(input:{authorization:AppleOwnerOperationAuthorization;installationId:string;leaseToken:string;now:number}):Promise<{expiresAt:number;incarnation:OriginInstallationIncarnation}>;
  completeExternalOperationLease(leaseToken:string,now:number):Promise<void>;
  completeExternalOperationLeaseForIncarnation(input:{authorization:AppleOwnerOperationAuthorization;leaseToken:string;incarnation:OriginInstallationIncarnation;completionState:OriginInstallationCompletionState;now:number}):Promise<void>;
  releaseExternalOperationLease(leaseToken:string):Promise<void>;
  assertOwnerOperationAllowed(authorization:AppleOwnerOperationAuthorization,now:number):Promise<void>;
  assertInstallationOperationAllowed(authorization:AppleOwnerOperationAuthorization,installationId:string,expectedState:OriginInstallationState,now:number):Promise<void>;
  assertInstallationIncarnationOperationAllowed(authorization:AppleOwnerOperationAuthorization,incarnation:OriginInstallationIncarnation,completionState:OriginInstallationCompletionState,now:number):Promise<void>;
};

type OriginPossibleInstallationSnapshot={acknowledgementId:string;markedAt:number};

function parseInstallation(value:unknown):OriginInstallation{
  const row=installationRowSchema.parse(value);
  return {installationId:row.installation_id,namespaceId:row.namespace_id,createdAt:row.created_at,updatedAt:row.updated_at};
}

function parseInstallationIncarnation(value:unknown):OriginInstallationIncarnation{
  const row=installationIncarnationRowSchema.parse(value);
  return {
    ...parseInstallation(row),
    ownerId:row.owner_id,
    receiptIssuedAtFence:row.issued_at_fence,
  };
}

function normalizeInstallationIncarnation(value:OriginInstallationIncarnation):OriginInstallationIncarnation{
  return parseInstallationIncarnation({
    installation_id:installationIdSchema.parse(value.installationId),
    owner_id:value.ownerId,
    namespace_id:value.namespaceId,
    created_at:value.createdAt,
    updated_at:value.updatedAt,
    issued_at_fence:value.receiptIssuedAtFence,
  });
}

function installationIncarnationState(
  incarnation:OriginInstallationIncarnation,
  completionState:OriginInstallationCompletionState,
):{sql:string;bindings:(string|number)[]}{
  if(completionState.kind==='present')return{
    sql:`EXISTS(
      SELECT 1 FROM origin_installations AS current_installation
      JOIN origin_installation_receipt_fences AS current_fence
        ON current_fence.installation_id=current_installation.installation_id
      WHERE current_installation.installation_id=?
        AND current_installation.owner_id=?
        AND current_installation.namespace_id=?
        AND current_installation.created_at=?
        AND current_installation.updated_at=?
        AND current_fence.issued_at_fence=?
    )`,
    bindings:[
      incarnation.installationId,
      incarnation.ownerId,
      incarnation.namespaceId,
      incarnation.createdAt,
      incarnation.updatedAt,
      incarnation.receiptIssuedAtFence,
    ],
  };
  const absence={
    installationId:installationIdSchema.parse(completionState.absence.installationId),
    ownerId:z.string().min(1).max(1_000).parse(completionState.absence.ownerId),
    receiptIssuedAtFence:z.number().int().nonnegative().parse(completionState.absence.receiptIssuedAtFence),
  };
  if(absence.installationId!==incarnation.installationId||absence.ownerId!==incarnation.ownerId){
    throw new TypeError('Origin installation absence does not match the admitted incarnation.');
  }
  return{
    sql:`NOT EXISTS(
      SELECT 1 FROM origin_installations AS current_installation
      WHERE current_installation.installation_id=?
    ) AND EXISTS(
      SELECT 1 FROM origin_installation_receipt_fences AS current_fence
      WHERE current_fence.installation_id=?
        AND current_fence.issued_at_fence=?
    )`,
    bindings:[
      incarnation.installationId,
      absence.installationId,
      absence.receiptIssuedAtFence,
    ],
  };
}

function parsePossibleInstallation(value:unknown):{acknowledgementId:string}|null{
  if(value===null)return null;
  const row=possibleInstallationRowSchema.safeParse(value);
  if(!row.success)throw new OriginAuthError(503,'ORIGIN_CLEANUP_STATE_INVALID','Stored Cursor Origin cleanup state is invalid and requires operator review.');
  return {acknowledgementId:row.data.flow_token};
}

function parsePossibleInstallationSnapshot(value:unknown):OriginPossibleInstallationSnapshot|null{
  if(value===null)return null;
  const row=possibleInstallationSnapshotRowSchema.safeParse(value);
  if(!row.success)throw new OriginAuthError(503,'ORIGIN_CLEANUP_STATE_INVALID','Stored Cursor Origin cleanup state is invalid and requires operator review.');
  return {acknowledgementId:row.data.flow_token,markedAt:row.data.marked_at};
}

function sameInstallationIncarnations(
  first:readonly OriginInstallationIncarnation[],
  second:readonly OriginInstallationIncarnation[],
):boolean{
  return first.length===second.length&&first.every((installation,index)=>{
    const candidate=second[index];
    return candidate!==undefined
      && installation.installationId===candidate.installationId
      && installation.ownerId===candidate.ownerId
      && installation.namespaceId===candidate.namespaceId
      && installation.createdAt===candidate.createdAt
      && installation.updatedAt===candidate.updatedAt
      && installation.receiptIssuedAtFence===candidate.receiptIssuedAtFence;
  });
}

function samePossibleInstallationSnapshot(
  first:OriginPossibleInstallationSnapshot|null,
  second:OriginPossibleInstallationSnapshot|null,
):boolean{
  return first===null
    ?second===null
    :second!==null
      && first.acknowledgementId===second.acknowledgementId
      && first.markedAt===second.markedAt;
}

export function createD1OriginRepository(database:D1Database):OriginD1Repository{
  const externalOperations=createD1AppleOwnerExternalOperationLeaseRepository(database);
  const authorization=(ownerId:string,authorizationStartedAt:number,appleSubjectHash:string|null)=>({userId:ownerId,authorizationStartedAt,appleSubjectHash});
  const assertOwnerAllowed=async(ownerId:string,now:number,authorizationStartedAt:number,appleSubjectHash:string|null)=>{
    if(!await isAppleOwnerOperationAllowed(database,authorization(ownerId,authorizationStartedAt,appleSubjectHash),now))throw new OriginAuthError(409,'APPLE_ACCOUNT_DELETION_IN_PROGRESS','This Apple access is being deleted.');
  };
  const readInstallationIncarnations=async(ownerId:string):Promise<OriginInstallationIncarnation[]>=>{
    const rows=await database.prepare(
      `SELECT installation.installation_id,installation.owner_id,
              installation.namespace_id,installation.created_at,installation.updated_at,
              receipt_fence.issued_at_fence
       FROM origin_installations AS installation
       LEFT JOIN origin_installation_receipt_fences AS receipt_fence
         ON receipt_fence.installation_id=installation.installation_id
       WHERE installation.owner_id=?
       ORDER BY installation.updated_at DESC,installation.installation_id LIMIT 20`,
    ).bind(ownerId).all();
    try{return rows.results.map(parseInstallationIncarnation);}
    catch{throw new OriginAuthError(503,'ORIGIN_INSTALLATION_STATE_INVALID','Stored Cursor Origin installation state is invalid.');}
  };
  const readPossibleInstallationSnapshot=async(
    operationAuthorization:AppleOwnerOperationAuthorization,
  ):Promise<OriginPossibleInstallationSnapshot|null>=>parsePossibleInstallationSnapshot(await database.prepare(
    `SELECT flow_token,marked_at FROM origin_possible_installations
     WHERE owner_id=? AND scope_id=CASE WHEN ? IS NULL THEN 'host' ELSE (
       SELECT identity.principal_id FROM apple_identity_links AS identity
       WHERE identity.apple_subject_hash=? AND identity.owner_id=?
     ) END`,
  ).bind(
    operationAuthorization.userId,
    operationAuthorization.appleSubjectHash,
    operationAuthorization.appleSubjectHash,
    operationAuthorization.userId,
  ).first());
  const assertDashboardSnapshotAllowed=async(
    operationAuthorization:AppleOwnerOperationAuthorization,
    installations:readonly OriginInstallationIncarnation[],
    possibleInstallation:OriginPossibleInstallationSnapshot|null,
    at:number,
  )=>{
    const currentInstallations=await readInstallationIncarnations(operationAuthorization.userId);
    const currentPossibleInstallation=await readPossibleInstallationSnapshot(operationAuthorization);
    await assertOwnerAllowed(
      operationAuthorization.userId,
      at,
      operationAuthorization.authorizationStartedAt,
      operationAuthorization.appleSubjectHash,
    );
    if(
      !sameInstallationIncarnations(installations,currentInstallations)
      ||!samePossibleInstallationSnapshot(possibleInstallation,currentPossibleInstallation)
    )throw new OriginAuthError(409,'ORIGIN_DASHBOARD_STATE_CHANGED','Cursor Origin connection state changed while the dashboard was loading. Refresh it again.');
  };
  const assertInstallationOperationAllowed=async(
    operationAuthorization:AppleOwnerOperationAuthorization,
    installationId:string,
    expectedState:OriginInstallationState,
    now:number,
  )=>{
    const resource=installationIdSchema.parse(installationId);
    const expectedStateSQL=expectedState==='present'
      ? 'EXISTS(SELECT 1 FROM origin_installations WHERE owner_id=? AND installation_id=?)'
      : 'NOT EXISTS(SELECT 1 FROM origin_installations WHERE owner_id=? AND installation_id=?)';
    const row=await database.prepare(
      `SELECT 1 AS allowed WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
         AND ${expectedStateSQL}
         AND NOT EXISTS(
           SELECT 1 FROM apple_owner_external_operation_leases AS resource_operation
           WHERE resource_operation.resource_id=?
             AND resource_operation.operation_kind IN ('origin','origin-install')
             AND resource_operation.expires_at>?
         )`,
    ).bind(
      ...appleOwnerOperationGateBindings(operationAuthorization,now),
      operationAuthorization.userId,
      resource,
      resource,
      now,
    ).first();
    if(row!==null)return;
    await assertOwnerAllowed(
      operationAuthorization.userId,
      now,
      operationAuthorization.authorizationStartedAt,
      operationAuthorization.appleSubjectHash,
    );
    throw new OriginAuthError(
      409,
      expectedState==='present'?'ORIGIN_INSTALLATION_STATE_CHANGED':'ORIGIN_INSTALLATION_DISCONNECT_UNCERTAIN',
      expectedState==='present'
        ?'The Cursor Origin installation changed before the operation could return.'
        :'The Cursor Origin installation may have been reconnected before disconnection completed.',
    );
  };
  const assertInstallationIncarnationOperationAllowed=async(
    operationAuthorization:AppleOwnerOperationAuthorization,
    expectedIncarnation:OriginInstallationIncarnation,
    completionState:OriginInstallationCompletionState,
    now:number,
  )=>{
    const incarnation=normalizeInstallationIncarnation(expectedIncarnation);
    if(incarnation.ownerId!==operationAuthorization.userId){
      throw new TypeError('Origin installation incarnation owner is invalid.');
    }
    const state=installationIncarnationState(incarnation,completionState);
    const allowed=await database.prepare(
      `SELECT 1 AS allowed WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
         AND ${state.sql}
         AND NOT EXISTS(
           SELECT 1 FROM apple_owner_external_operation_leases AS resource_operation
           WHERE resource_operation.resource_id=?
             AND resource_operation.operation_kind IN ('origin','origin-install')
             AND resource_operation.expires_at>?
         )`,
    ).bind(
      ...appleOwnerOperationGateBindings(operationAuthorization,now),
      ...state.bindings,
      incarnation.installationId,
      now,
    ).first();
    if(allowed!==null)return;
    await assertOwnerAllowed(
      operationAuthorization.userId,
      now,
      operationAuthorization.authorizationStartedAt,
      operationAuthorization.appleSubjectHash,
    );
    throw new OriginAuthError(
      409,
      completionState.kind==='present'?'ORIGIN_INSTALLATION_STATE_CHANGED':'ORIGIN_INSTALLATION_DISCONNECT_UNCERTAIN',
      completionState.kind==='present'
        ?'The Cursor Origin installation changed before the operation could return.'
        :'The Cursor Origin installation may have been reconnected before disconnection completed.',
    );
  };
  return {
    replayStore:{
      async claim(receipt,now){
        const row=await database.prepare(
          'INSERT OR IGNORE INTO origin_auth_receipts(receipt_id,expires_at,claimed_at) SELECT ?,?,? WHERE ?>? RETURNING receipt_id',
        ).bind(receipt.id,receipt.expiresAt,now,receipt.expiresAt,now).first();
        return row!==null;
      },
    },
    async createFlow(flow){
      const stateHash=opaqueHashSchema.parse(flow.stateHash);
      const gate=appleOwnerOperationGateBindings(authorization(flow.ownerId,flow.authorizationStartedAt,flow.appleSubjectHash),flow.createdAt);
      const leaseExpiresAt=flow.createdAt+ORIGIN_EXTERNAL_OPERATION_LEASE_SECONDS;
      if(!Number.isSafeInteger(leaseExpiresAt))throw new TypeError('Origin flow lease time is invalid.');
      try{
        await database.batch([
          database.prepare(
            `DELETE FROM apple_owner_external_operation_leases
             WHERE lease_token IN (
               SELECT lease_token FROM apple_owner_external_operation_leases
               WHERE expires_at<=? ORDER BY expires_at,lease_token LIMIT 100
             )`,
          ).bind(flow.createdAt),
          database.prepare('DELETE FROM origin_auth_flows WHERE expires_at<=?').bind(flow.createdAt),
          database.prepare('DELETE FROM origin_auth_receipts WHERE expires_at<=?').bind(flow.createdAt),
          database.prepare(
            `INSERT INTO origin_possible_installations(
               owner_id,scope_id,apple_principal_id,apple_subject_hash,flow_token,marked_at
             )
             SELECT ?,CASE WHEN ? IS NULL THEN 'host' ELSE (
               SELECT identity.principal_id FROM apple_identity_links AS identity
               WHERE identity.apple_subject_hash=? AND identity.owner_id=?
             ) END,CASE WHEN ? IS NULL THEN NULL ELSE (
               SELECT identity.principal_id FROM apple_identity_links AS identity
               WHERE identity.apple_subject_hash=? AND identity.owner_id=?
             ) END,?,?,?
             WHERE (? IS NULL OR EXISTS(
               SELECT 1 FROM apple_identity_links AS identity
               WHERE identity.apple_subject_hash=? AND identity.owner_id=?
             ))
               AND NOT EXISTS(
                 SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
                 WHERE active_lease.operation_kind='origin-install'
                   AND active_lease.owner_id=?
                   AND active_lease.expires_at>?
               )
               AND NOT EXISTS(
                 SELECT 1 FROM apple_owner_external_operation_leases AS active_operation
                 WHERE active_operation.operation_kind='origin'
                   AND active_operation.owner_id=?
                   AND active_operation.expires_at>?
               )
               AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
             ON CONFLICT(owner_id,scope_id) DO NOTHING`,
          ).bind(
            flow.ownerId,
            flow.appleSubjectHash,
            flow.appleSubjectHash,
            flow.ownerId,
            flow.appleSubjectHash,
            flow.appleSubjectHash,
            flow.ownerId,
            flow.appleSubjectHash,
            stateHash,
            flow.createdAt,
            flow.appleSubjectHash,
            flow.appleSubjectHash,
            flow.ownerId,
            flow.ownerId,
            flow.createdAt,
            flow.ownerId,
            flow.createdAt,
            ...gate,
          ),
          database.prepare(
            `INSERT INTO apple_owner_external_operation_leases(
               lease_token,owner_id,operation_kind,resource_id,
               apple_subject_hash,apple_principal_id,claimed_at,expires_at
             )
             SELECT ?,?,'origin-install',?,?,CASE WHEN ? IS NULL THEN NULL ELSE (
               SELECT identity.principal_id FROM apple_identity_links AS identity
               WHERE identity.apple_subject_hash=? AND identity.owner_id=?
             ) END,?,?
             WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
               AND (? IS NULL OR EXISTS(
                 SELECT 1 FROM apple_identity_links AS identity
                 WHERE identity.apple_subject_hash=? AND identity.owner_id=?
               ))
               AND NOT EXISTS(
                 SELECT 1 FROM apple_owner_external_operation_leases AS active_operation
                 WHERE active_operation.operation_kind='origin'
                   AND active_operation.owner_id=?
                   AND active_operation.expires_at>?
               )
               AND EXISTS(
                 SELECT 1 FROM origin_possible_installations AS possible_installation
                 WHERE possible_installation.owner_id=?
                   AND possible_installation.scope_id=CASE WHEN ? IS NULL THEN 'host' ELSE (
                     SELECT identity.principal_id FROM apple_identity_links AS identity
                     WHERE identity.apple_subject_hash=? AND identity.owner_id=?
                   ) END
                   AND possible_installation.flow_token=?
               )
             ON CONFLICT DO NOTHING`,
          ).bind(
            stateHash,
            flow.ownerId,
            stateHash,
            flow.appleSubjectHash,
            flow.appleSubjectHash,
            flow.appleSubjectHash,
            flow.ownerId,
            flow.createdAt,
            leaseExpiresAt,
            ...gate,
            flow.appleSubjectHash,
            flow.appleSubjectHash,
            flow.ownerId,
            flow.ownerId,
            flow.createdAt,
            flow.ownerId,
            flow.appleSubjectHash,
            flow.appleSubjectHash,
            flow.ownerId,
            stateHash,
          ),
          database.prepare(
            `INSERT INTO origin_auth_flows(
               state_hash,owner_id,return_to,created_at,expires_at,consumed_at
             )
             SELECT ?,?,?,?,?,NULL
             WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
               AND EXISTS(
                 SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
                 WHERE active_lease.lease_token=?
                   AND active_lease.owner_id=?
                   AND active_lease.operation_kind='origin-install'
                   AND active_lease.resource_id=?
                   AND active_lease.apple_subject_hash IS ?
                   AND active_lease.expires_at>?
               )`,
          ).bind(
            stateHash,
            flow.ownerId,
            flow.returnTo,
            flow.createdAt,
            flow.expiresAt,
            ...gate,
            stateHash,
            flow.ownerId,
            stateHash,
            flow.appleSubjectHash,
            flow.createdAt,
          ),
        ]);
        const storedFlow=await database.prepare(
          `SELECT 1 FROM origin_auth_flows
           WHERE state_hash=? AND owner_id=? AND return_to=?
             AND created_at=? AND expires_at=? AND consumed_at IS NULL`,
        ).bind(
          stateHash,
          flow.ownerId,
          flow.returnTo,
          flow.createdAt,
          flow.expiresAt,
        ).first();
        const storedCoverage=await database.prepare(
          `SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
           WHERE active_lease.lease_token=?
             AND active_lease.operation_kind='origin-install'
             AND active_lease.owner_id=?
             AND active_lease.resource_id=?
             AND active_lease.apple_subject_hash IS ?
             AND active_lease.expires_at>?
             AND EXISTS(
               SELECT 1 FROM origin_possible_installations AS possible_installation
               WHERE possible_installation.owner_id=active_lease.owner_id
                 AND possible_installation.scope_id=CASE
                   WHEN active_lease.apple_subject_hash IS NULL THEN 'host'
                   ELSE active_lease.apple_principal_id
                 END
                 AND possible_installation.flow_token=active_lease.lease_token
             )`,
        ).bind(
          stateHash,
          flow.ownerId,
          stateHash,
          flow.appleSubjectHash,
          flow.createdAt,
        ).first();
        if(storedFlow!==null&&storedCoverage!==null)return;
        await assertOwnerAllowed(flow.ownerId,flow.createdAt,flow.authorizationStartedAt,flow.appleSubjectHash);
        if(await database.prepare(
          `SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
           WHERE active_lease.owner_id=? AND active_lease.expires_at>?
             AND active_lease.operation_kind IN ('origin','origin-install')`,
        ).bind(flow.ownerId,flow.createdAt).first()!==null){
          throw new OriginAuthError(409,'ORIGIN_INSTALLATION_FLOW_IN_PROGRESS','Another Cursor Origin operation is already active for this dashboard account.');
        }
        if(await database.prepare(
          `SELECT 1 FROM origin_possible_installations
           WHERE owner_id=? AND scope_id=CASE WHEN ? IS NULL THEN 'host' ELSE (
             SELECT identity.principal_id FROM apple_identity_links AS identity
             WHERE identity.apple_subject_hash=? AND identity.owner_id=?
           ) END`,
        ).bind(
          flow.ownerId,
          flow.appleSubjectHash,
          flow.appleSubjectHash,
          flow.ownerId,
        ).first()!==null){
          throw new OriginAuthError(409,'ORIGIN_MANUAL_CLEANUP_REQUIRED','Review or remove the unresolved Local Sandbox installation in Cursor Origin settings before reconnecting.');
        }
        throw new OriginAuthError(503,'ORIGIN_FLOW_STORE_UNAVAILABLE','Cursor Origin installation state could not be stored.');
      }catch(error){
        try{await database.batch([
          database.prepare('DELETE FROM origin_auth_flows WHERE state_hash=?').bind(stateHash),
          database.prepare(
            `DELETE FROM origin_possible_installations WHERE flow_token=?`,
          ).bind(stateHash),
          database.prepare(
            `DELETE FROM apple_owner_external_operation_leases
             WHERE lease_token=? AND operation_kind='origin-install'`,
          ).bind(stateHash),
        ]);}catch{}
        if(error instanceof OriginAuthError)throw error;
        throw new OriginAuthError(503,'ORIGIN_FLOW_STORE_UNAVAILABLE','Cursor Origin installation state could not be stored.');
      }
    },
    async claimInstallationFlowLease(input){
      const stateHash=opaqueHashSchema.parse(input.stateHash);
      const installationId=installationIdSchema.parse(input.installationId);
      if(!Number.isSafeInteger(input.receiptIssuedAt)||input.receiptIssuedAt<0||input.receiptIssuedAt>input.now+ORIGIN_RECEIPT_CLOCK_SKEW_SECONDS){
        throw new TypeError('Origin receipt issue time is invalid.');
      }
      const gate=appleOwnerOperationGateBindings(input.authorization,input.now);
      const results=await database.batch([
        database.prepare(
          `DELETE FROM apple_owner_external_operation_leases
           WHERE expires_at<=?`,
        ).bind(input.now),
        database.prepare(
          `UPDATE apple_owner_external_operation_leases
           SET resource_id=?
           WHERE lease_token=? AND owner_id=? AND operation_kind='origin-install'
             AND resource_id IN (?,?) AND apple_subject_hash IS ? AND expires_at>?
             AND EXISTS(
               SELECT 1 FROM origin_auth_flows AS flow
               WHERE flow.state_hash=? AND flow.owner_id=?
                 AND flow.consumed_at IS NULL AND flow.expires_at>?
             )
             AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
             AND NOT EXISTS(
               SELECT 1 FROM origin_installation_receipt_fences AS receipt_fence
               WHERE receipt_fence.installation_id=?
                 AND receipt_fence.issued_at_fence>=?
             )
             AND NOT EXISTS(
               SELECT 1 FROM apple_owner_external_operation_leases AS competing
               WHERE competing.lease_token<>? AND competing.resource_id=?
                 AND competing.operation_kind IN ('origin','origin-install')
                 AND competing.expires_at>?
             )
           RETURNING expires_at`,
        ).bind(
          installationId,
          stateHash,
          input.authorization.userId,
          stateHash,
          installationId,
          input.authorization.appleSubjectHash,
          input.now,
          stateHash,
          input.authorization.userId,
          input.now,
          ...gate,
          installationId,
          input.receiptIssuedAt,
          stateHash,
          installationId,
          input.now,
        ),
      ]);
      const expiresAt=z.object({expires_at:z.number().int().positive()}).safeParse(results[1]?.results[0]);
      if(expiresAt.success)return {expiresAt:expiresAt.data.expires_at};
      await assertOwnerAllowed(
        input.authorization.userId,
        input.now,
        input.authorization.authorizationStartedAt,
        input.authorization.appleSubjectHash,
      );
      if(await database.prepare(
        `SELECT 1 FROM origin_installation_receipt_fences
         WHERE installation_id=? AND issued_at_fence>=?`,
      ).bind(installationId,input.receiptIssuedAt).first()!==null){
        throw new OriginAuthError(409,'ORIGIN_INSTALLATION_RECEIPT_STALE','This Cursor Origin callback predates a completed disconnect or newer consent. Start a new connection after the disconnect safety window.');
      }
      if(await database.prepare(
        `SELECT 1 FROM apple_owner_external_operation_leases
         WHERE resource_id=? AND operation_kind IN ('origin','origin-install')
           AND expires_at>?`,
      ).bind(installationId,input.now).first()!==null){
        throw new OriginAuthError(409,'ORIGIN_EXTERNAL_OPERATION_IN_PROGRESS','This Cursor Origin installation is already being changed. Retry after the active operation finishes.');
      }
      throw new OriginAuthError(409,'ORIGIN_FLOW_INVALID','This Cursor Origin installation request expired, was already used, or belongs to another account.');
    },
    async consumeFlow(stateHash,ownerId,now,authorizationStartedAt,appleSubjectHash){
      const row=flowRowSchema.safeParse(await database.prepare(
        `UPDATE origin_auth_flows SET consumed_at=? WHERE state_hash=? AND owner_id=? AND consumed_at IS NULL AND expires_at>? AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL} RETURNING return_to`,
      ).bind(now,stateHash,ownerId,now,...appleOwnerOperationGateBindings(authorization(ownerId,authorizationStartedAt,appleSubjectHash),now)).first());
      if(!row.success)await assertOwnerAllowed(ownerId,now,authorizationStartedAt,appleSubjectHash);
      return row.success?{returnTo:row.data.return_to}:null;
    },
    async saveInstallation(ownerId,receipt,now,authorizationStartedAt,appleSubjectHash){
      if(!Number.isSafeInteger(receipt.issuedAt)||receipt.issuedAt<0||receipt.issuedAt>now+ORIGIN_RECEIPT_CLOCK_SKEW_SECONDS){
        throw new TypeError('Origin receipt issue time is invalid.');
      }
      const gate=appleOwnerOperationGateBindings(authorization(ownerId,authorizationStartedAt,appleSubjectHash),now);
      const results=await database.batch([
        database.prepare(
          `INSERT INTO origin_installations(installation_id,owner_id,namespace_id,created_at,updated_at)
           SELECT ?,?,?,?,? WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
             AND NOT EXISTS(
               SELECT 1 FROM origin_installation_receipt_fences AS receipt_fence
               WHERE receipt_fence.installation_id=? AND receipt_fence.issued_at_fence>=?
             )
           ON CONFLICT(installation_id) DO UPDATE SET namespace_id=excluded.namespace_id,updated_at=excluded.updated_at
           WHERE origin_installations.owner_id=excluded.owner_id
           RETURNING installation_id,namespace_id,created_at,updated_at`,
        ).bind(
          receipt.installationId,ownerId,receipt.namespaceId,now,now,
          ...gate,
          receipt.installationId,receipt.issuedAt,
        ),
        database.prepare(
          `INSERT INTO origin_installation_receipt_fences(installation_id,issued_at_fence)
           SELECT ?,? WHERE EXISTS(
             SELECT 1 FROM origin_installations
             WHERE installation_id=? AND owner_id=? AND namespace_id=? AND updated_at=?
           ) AND NOT EXISTS(
             SELECT 1 FROM origin_installation_receipt_fences
             WHERE installation_id=? AND issued_at_fence>=?
           )
           ON CONFLICT(installation_id) DO UPDATE SET issued_at_fence=excluded.issued_at_fence
           WHERE origin_installation_receipt_fences.issued_at_fence<excluded.issued_at_fence
           RETURNING issued_at_fence`,
        ).bind(
          receipt.installationId,receipt.issuedAt,
          receipt.installationId,ownerId,receipt.namespaceId,now,
          receipt.installationId,receipt.issuedAt,
        ),
      ]);
      const row=installationRowSchema.safeParse(results[0]?.results[0]);
      const receiptFence=z.object({issued_at_fence:z.number().int().nonnegative()}).strict().safeParse(results[1]?.results[0]);
      if(row.success&&receiptFence.success&&receiptFence.data.issued_at_fence===receipt.issuedAt)return parseInstallation(row.data);
      await assertOwnerAllowed(ownerId,now,authorizationStartedAt,appleSubjectHash);
      const existingOwner=await database.prepare(
        'SELECT owner_id FROM origin_installations WHERE installation_id=?',
      ).bind(receipt.installationId).first<string>('owner_id');
      if(existingOwner!==null&&existingOwner!==ownerId){
        throw new OriginAuthError(409,'ORIGIN_INSTALLATION_OWNER_CONFLICT','This Cursor Origin installation is already connected to another dashboard account.');
      }
      if(await database.prepare(
        `SELECT 1 FROM origin_installation_receipt_fences
         WHERE installation_id=? AND issued_at_fence>=?`,
      ).bind(receipt.installationId,receipt.issuedAt).first()!==null){
        throw new OriginAuthError(409,'ORIGIN_INSTALLATION_RECEIPT_STALE','This Cursor Origin receipt was already accepted or predates a completed disconnect or newer consent.');
      }
      throw new OriginAuthError(409,'ORIGIN_INSTALLATION_OWNER_CONFLICT','This Cursor Origin installation is already connected to another dashboard account.');
    },
    async saveInstallationAndCompleteFlow(input){
      const stateHash=opaqueHashSchema.parse(input.stateHash);
      if(!Number.isSafeInteger(input.receipt.issuedAt)||input.receipt.issuedAt<0||input.receipt.issuedAt>input.now+ORIGIN_RECEIPT_CLOCK_SKEW_SECONDS){
        throw new TypeError('Origin receipt issue time is invalid.');
      }
      const gate=appleOwnerOperationGateBindings(
        authorization(input.ownerId,input.authorizationStartedAt,input.appleSubjectHash),
        input.now,
      );
      const installationMatches=`EXISTS(
        SELECT 1 FROM origin_installations AS stored_installation
        WHERE stored_installation.installation_id=?
          AND stored_installation.owner_id=?
          AND stored_installation.namespace_id=?
          AND stored_installation.updated_at=?
      )`;
      const receiptFenceMatches=`EXISTS(
        SELECT 1 FROM origin_installation_receipt_fences AS receipt_fence
        WHERE receipt_fence.installation_id=? AND receipt_fence.issued_at_fence=?
      )`;
      let results:D1Result<unknown>[];
      try{
        results=await database.batch([
          database.prepare(
            `INSERT INTO origin_installations(
               installation_id,owner_id,namespace_id,created_at,updated_at
             )
             SELECT ?,?,?,?,?
             WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
               AND NOT EXISTS(
                 SELECT 1 FROM origin_installation_receipt_fences AS receipt_fence
                 WHERE receipt_fence.installation_id=?
                   AND receipt_fence.issued_at_fence>=?
               )
               AND EXISTS(
                 SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
                 WHERE active_lease.lease_token=?
                   AND active_lease.owner_id=?
                   AND active_lease.operation_kind='origin-install'
                   AND active_lease.resource_id=?
                   AND active_lease.apple_subject_hash IS ?
                   AND active_lease.expires_at>?
               )
             ON CONFLICT(installation_id) DO UPDATE SET
               namespace_id=excluded.namespace_id,updated_at=excluded.updated_at
             WHERE origin_installations.owner_id=excluded.owner_id
             RETURNING installation_id,namespace_id,created_at,updated_at`,
          ).bind(
            input.receipt.installationId,
            input.ownerId,
            input.receipt.namespaceId,
            input.now,
            input.now,
            ...gate,
            input.receipt.installationId,
            input.receipt.issuedAt,
            stateHash,
            input.ownerId,
            input.receipt.installationId,
            input.appleSubjectHash,
            input.now,
          ),
          database.prepare(
            `INSERT INTO origin_installation_receipt_fences(installation_id,issued_at_fence)
             SELECT ?,? WHERE ${installationMatches}
               AND NOT EXISTS(
                 SELECT 1 FROM origin_installation_receipt_fences
                 WHERE installation_id=? AND issued_at_fence>=?
               )
             ON CONFLICT(installation_id) DO UPDATE SET issued_at_fence=excluded.issued_at_fence
             WHERE origin_installation_receipt_fences.issued_at_fence<excluded.issued_at_fence
             RETURNING issued_at_fence`,
          ).bind(
            input.receipt.installationId,
            input.receipt.issuedAt,
            input.receipt.installationId,
            input.ownerId,
            input.receipt.namespaceId,
            input.now,
            input.receipt.installationId,
            input.receipt.issuedAt,
          ),
          database.prepare(
            `DELETE FROM origin_possible_installations
             WHERE flow_token=? AND ${installationMatches} AND ${receiptFenceMatches}
               AND EXISTS(
                 SELECT 1 FROM apple_owner_external_operation_leases AS active_lease
                 WHERE active_lease.lease_token=?
                   AND active_lease.operation_kind='origin-install'
                   AND active_lease.expires_at>?
               )`,
          ).bind(
            stateHash,
            input.receipt.installationId,
            input.ownerId,
            input.receipt.namespaceId,
            input.now,
            input.receipt.installationId,
            input.receipt.issuedAt,
            stateHash,
            input.now,
          ),
          database.prepare(
            `DELETE FROM apple_owner_external_operation_leases
             WHERE lease_token=? AND operation_kind='origin-install'
               AND expires_at>? AND ${installationMatches} AND ${receiptFenceMatches}
             RETURNING lease_token`,
          ).bind(
            stateHash,
            input.now,
            input.receipt.installationId,
            input.ownerId,
            input.receipt.namespaceId,
            input.now,
            input.receipt.installationId,
            input.receipt.issuedAt,
          ),
        ]);
      }catch{
        throw new OriginAuthError(503,'ORIGIN_INSTALLATION_STORE_UNAVAILABLE','Cursor Origin installation storage is unavailable.');
      }
      const installation=installationRowSchema.safeParse(results[0]?.results[0]);
      const receiptFence=z.object({issued_at_fence:z.number().int().nonnegative()}).strict().safeParse(results[1]?.results[0]);
      if(!installation.success){
        await assertOwnerAllowed(
          input.ownerId,
          input.now,
          input.authorizationStartedAt,
          input.appleSubjectHash,
        );
        const existingOwner=await database.prepare(
          'SELECT owner_id FROM origin_installations WHERE installation_id=?',
        ).bind(input.receipt.installationId).first<string>('owner_id');
        if(existingOwner!==null&&existingOwner!==input.ownerId){
          throw new OriginAuthError(409,'ORIGIN_INSTALLATION_OWNER_CONFLICT','This Cursor Origin installation is already connected to another dashboard account.');
        }
        if(await database.prepare(
          `SELECT 1 FROM origin_installation_receipt_fences
           WHERE installation_id=? AND issued_at_fence>=?`,
        ).bind(input.receipt.installationId,input.receipt.issuedAt).first()!==null){
          throw new OriginAuthError(409,'ORIGIN_INSTALLATION_RECEIPT_STALE','This Cursor Origin receipt was already accepted or predates a completed disconnect or newer consent.');
        }
        throw new OriginAuthError(409,'ORIGIN_INSTALLATION_OWNER_CONFLICT','This Cursor Origin installation is already connected to another dashboard account.');
      }
      if(!receiptFence.success||receiptFence.data.issued_at_fence!==input.receipt.issuedAt){
        throw new OriginAuthError(503,'ORIGIN_INSTALLATION_RECEIPT_FENCE_FAILED','Cursor Origin receipt order could not be recorded safely.');
      }
      if((results[3]?.results[0]??null)===null){
        throw new OriginAuthError(503,'ORIGIN_INSTALLATION_FLOW_LEASE_EXPIRED','Cursor Origin installation authority expired before the connection was saved.');
      }
      if(await database.prepare(
        `SELECT 1 FROM apple_owner_external_operation_leases
         WHERE lease_token=? AND operation_kind='origin-install'`,
      ).bind(stateHash).first()!==null){
        throw new OriginAuthError(503,'ORIGIN_INSTALLATION_FLOW_RELEASE_FAILED','Cursor Origin installation authority could not be released safely.');
      }
      await assertOwnerAllowed(
        input.ownerId,
        input.now,
        input.authorizationStartedAt,
        input.appleSubjectHash,
      );
      await assertInstallationOperationAllowed(
        authorization(input.ownerId,input.authorizationStartedAt,input.appleSubjectHash),
        input.receipt.installationId,
        'present',
        input.now,
      );
      return parseInstallation(installation.data);
    },
    async releaseInstallationFlowLease(stateHash){
      try{await externalOperations.release(opaqueHashSchema.parse(stateHash));}
      catch(error){throw originExternalOperationError(error,true);}
    },
    async readDashboardState(operationAuthorization,now){
      const installations=await readInstallationIncarnations(operationAuthorization.userId);
      const possibleInstallation=await readPossibleInstallationSnapshot(operationAuthorization);
      await assertDashboardSnapshotAllowed(operationAuthorization,installations,possibleInstallation,now());
      return {
        installations:installations.map(installation=>({
          installationId:installation.installationId,
          namespaceId:installation.namespaceId,
          createdAt:installation.createdAt,
          updatedAt:installation.updatedAt,
        })),
        possibleInstallation:possibleInstallation===null
          ?null
          :{acknowledgementId:possibleInstallation.acknowledgementId},
      };
    },
    async listInstallations(operationAuthorization,now){
      const installations=await readInstallationIncarnations(operationAuthorization.userId);
      const current=await readInstallationIncarnations(operationAuthorization.userId);
      await assertOwnerAllowed(
        operationAuthorization.userId,
        now(),
        operationAuthorization.authorizationStartedAt,
        operationAuthorization.appleSubjectHash,
      );
      if(!sameInstallationIncarnations(installations,current)){
        throw new OriginAuthError(409,'ORIGIN_DASHBOARD_STATE_CHANGED','Cursor Origin connection state changed while the dashboard was loading. Refresh it again.');
      }
      return installations.map(installation=>({
        installationId:installation.installationId,
        namespaceId:installation.namespaceId,
        createdAt:installation.createdAt,
        updatedAt:installation.updatedAt,
      }));
    },
    async readPossibleInstallation(operationAuthorization,now){
      const stored=await database.prepare(
        `SELECT flow_token FROM origin_possible_installations
         WHERE owner_id=? AND scope_id=CASE WHEN ? IS NULL THEN 'host' ELSE (
           SELECT identity.principal_id FROM apple_identity_links AS identity
           WHERE identity.apple_subject_hash=? AND identity.owner_id=?
         ) END`,
      ).bind(
        operationAuthorization.userId,
        operationAuthorization.appleSubjectHash,
        operationAuthorization.appleSubjectHash,
        operationAuthorization.userId,
      ).first();
      await assertOwnerAllowed(
        operationAuthorization.userId,
        now(),
        operationAuthorization.authorizationStartedAt,
        operationAuthorization.appleSubjectHash,
      );
      return parsePossibleInstallation(stored);
    },
    async acknowledgePossibleInstallation(operationAuthorization,acknowledgementId,now){
      const expectedToken=opaqueHashSchema.parse(acknowledgementId);
      await database.prepare(
        `DELETE FROM origin_possible_installations
         WHERE owner_id=? AND flow_token=?
           AND scope_id=CASE WHEN ? IS NULL THEN 'host' ELSE (
             SELECT identity.principal_id FROM apple_identity_links AS identity
             WHERE identity.apple_subject_hash=? AND identity.owner_id=?
           ) END
           AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
           AND NOT EXISTS(
             SELECT 1 FROM apple_owner_external_operation_leases AS active_operation
             WHERE active_operation.owner_id=?
               AND active_operation.operation_kind IN ('origin','origin-install')
               AND active_operation.expires_at>?
           )`,
      ).bind(
        operationAuthorization.userId,
        expectedToken,
        operationAuthorization.appleSubjectHash,
        operationAuthorization.appleSubjectHash,
        operationAuthorization.userId,
        ...appleOwnerOperationGateBindings(operationAuthorization,now),
        operationAuthorization.userId,
        now,
      ).run();
      const currentMarker=await database.prepare(
        `SELECT flow_token,marked_at FROM origin_possible_installations
         WHERE owner_id=? AND scope_id=CASE WHEN ? IS NULL THEN 'host' ELSE (
           SELECT identity.principal_id FROM apple_identity_links AS identity
           WHERE identity.apple_subject_hash=? AND identity.owner_id=?
         ) END`,
      ).bind(
        operationAuthorization.userId,
        operationAuthorization.appleSubjectHash,
        operationAuthorization.appleSubjectHash,
        operationAuthorization.userId,
      ).first();
      if(currentMarker===null)return;
      const parsedMarker=z.object({flow_token:opaqueHashSchema,marked_at:z.number().int().nonnegative()}).strict().safeParse(currentMarker);
      if(!parsedMarker.success)throw new OriginAuthError(503,'ORIGIN_CLEANUP_STATE_INVALID','Stored Cursor Origin cleanup state is invalid and requires operator review.');
      if(parsedMarker.data.flow_token!==expectedToken){
        await assertOwnerAllowed(
          operationAuthorization.userId,
          now,
          operationAuthorization.authorizationStartedAt,
          operationAuthorization.appleSubjectHash,
        );
        throw new OriginAuthError(409,'ORIGIN_MANUAL_CLEANUP_CHANGED','Cursor Origin cleanup state changed. Review the current unresolved installation before acknowledging it.');
      }
      await assertOwnerAllowed(
        operationAuthorization.userId,
        now,
        operationAuthorization.authorizationStartedAt,
        operationAuthorization.appleSubjectHash,
      );
      throw new OriginAuthError(409,'ORIGIN_EXTERNAL_OPERATION_IN_PROGRESS','Finish the active Cursor Origin operation before acknowledging manual cleanup.');
    },
    async ownsInstallation(ownerId,installationId){
      const row=await database.prepare('SELECT 1 AS owned FROM origin_installations WHERE owner_id=? AND installation_id=?').bind(ownerId,installationId).first();
      return row!==null;
    },
    async deleteInstallation(ownerId,installationId,now,authorizationStartedAt,appleSubjectHash){
      const disconnectedThrough=now+ORIGIN_RECEIPT_CLOCK_SKEW_SECONDS;
      if(!Number.isSafeInteger(disconnectedThrough))throw new TypeError('Origin disconnect receipt fence time is invalid.');
      const operationAuthorization=authorization(ownerId,authorizationStartedAt,appleSubjectHash);
      const results=await database.batch([
        database.prepare(
          `DELETE FROM origin_auth_flows WHERE owner_id=? AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}`,
        ).bind(ownerId,...appleOwnerOperationGateBindings(operationAuthorization,now)),
        database.prepare(
          `INSERT INTO origin_installation_receipt_fences(installation_id,issued_at_fence)
           SELECT ?,? WHERE EXISTS(
             SELECT 1 FROM origin_installations
             WHERE owner_id=? AND installation_id=?
           ) AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
           ON CONFLICT(installation_id) DO UPDATE SET
             issued_at_fence=MAX(origin_installation_receipt_fences.issued_at_fence,excluded.issued_at_fence)
           RETURNING issued_at_fence`,
        ).bind(
          installationId,
          disconnectedThrough,
          ownerId,
          installationId,
          ...appleOwnerOperationGateBindings(operationAuthorization,now),
        ),
        database.prepare(
          `DELETE FROM origin_installations WHERE owner_id=? AND installation_id=?
             AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
             AND EXISTS(
               SELECT 1 FROM origin_installation_receipt_fences
               WHERE installation_id=? AND issued_at_fence>=?
             ) RETURNING installation_id`,
        ).bind(
          ownerId,
          installationId,
          ...appleOwnerOperationGateBindings(operationAuthorization,now),
          installationId,
          disconnectedThrough,
        ),
      ]);
      const fence=z.object({issued_at_fence:z.number().int().nonnegative()}).strict().safeParse(results[1]?.results[0]);
      const deleted=(results[2]?.results[0]??null)!==null;
      if(deleted&&(!fence.success||fence.data.issued_at_fence<disconnectedThrough)){
        throw new OriginAuthError(503,'ORIGIN_DISCONNECT_FENCE_FAILED','Cursor Origin disconnect order could not be recorded safely.');
      }
      if(!deleted)await assertOwnerAllowed(ownerId,now,authorizationStartedAt,appleSubjectHash);
      return deleted;
    },
    async deleteInstallationForIncarnation(operationAuthorization,expectedIncarnation,now){
      const incarnation=normalizeInstallationIncarnation(expectedIncarnation);
      if(incarnation.ownerId!==operationAuthorization.userId){
        throw new TypeError('Origin installation incarnation owner is invalid.');
      }
      const disconnectedThrough=now+ORIGIN_RECEIPT_CLOCK_SKEW_SECONDS;
      if(!Number.isSafeInteger(now)||now<0||!Number.isSafeInteger(disconnectedThrough)){
        throw new TypeError('Origin disconnect receipt fence time is invalid.');
      }
      const present=installationIncarnationState(incarnation,{kind:'present'});
      let results:D1Result<unknown>[];
      try{
        results=await database.batch([
          database.prepare(
            `DELETE FROM origin_auth_flows
             WHERE owner_id=? AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL} AND ${present.sql}`,
          ).bind(
            operationAuthorization.userId,
            ...appleOwnerOperationGateBindings(operationAuthorization,now),
            ...present.bindings,
          ),
          database.prepare(
            `INSERT INTO origin_installation_receipt_fences(installation_id,issued_at_fence)
             SELECT ?,? WHERE ${APPLE_OWNER_OPERATION_ALLOWED_SQL} AND ${present.sql}
             ON CONFLICT(installation_id) DO UPDATE SET issued_at_fence=excluded.issued_at_fence
             WHERE origin_installation_receipt_fences.issued_at_fence=?
               AND origin_installation_receipt_fences.issued_at_fence<excluded.issued_at_fence
             RETURNING issued_at_fence`,
          ).bind(
            incarnation.installationId,
            disconnectedThrough,
            ...appleOwnerOperationGateBindings(operationAuthorization,now),
            ...present.bindings,
            incarnation.receiptIssuedAtFence,
          ),
          database.prepare(
            `DELETE FROM origin_installations
             WHERE installation_id=? AND owner_id=? AND namespace_id=?
               AND created_at=? AND updated_at=? AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
               AND EXISTS(
                 SELECT 1 FROM origin_installation_receipt_fences AS receipt_fence
                 WHERE receipt_fence.installation_id=? AND receipt_fence.issued_at_fence=?
               )
             RETURNING installation_id`,
          ).bind(
            incarnation.installationId,
            incarnation.ownerId,
            incarnation.namespaceId,
            incarnation.createdAt,
            incarnation.updatedAt,
            ...appleOwnerOperationGateBindings(operationAuthorization,now),
            incarnation.installationId,
            disconnectedThrough,
          ),
        ]);
      }catch{
        throw new OriginAuthError(503,'ORIGIN_DISCONNECT_STORE_UNAVAILABLE','Cursor Origin disconnect state could not be stored safely.');
      }
      const fence=z.object({issued_at_fence:z.number().int().nonnegative()}).strict().safeParse(results[1]?.results[0]);
      const deleted=(results[2]?.results[0]??null)!==null;
      if(fence.success&&fence.data.issued_at_fence===disconnectedThrough&&deleted){
        return {
          installationId:incarnation.installationId,
          ownerId:incarnation.ownerId,
          receiptIssuedAtFence:disconnectedThrough,
        };
      }
      await assertOwnerAllowed(
        operationAuthorization.userId,
        now,
        operationAuthorization.authorizationStartedAt,
        operationAuthorization.appleSubjectHash,
      );
      throw new OriginAuthError(409,'ORIGIN_INSTALLATION_STATE_CHANGED','The Cursor Origin installation changed before local disconnection completed.');
    },
    async claimExternalOperationLease(input){
      const resource=installationIdSchema.parse(input.installationId);
      let lease:{expiresAt:number};
      try{
        lease=await externalOperations.claim({
          authorization:input.authorization,
          operationKind:'origin',
          resourceId:resource,
          leaseToken:input.leaseToken,
          now:input.now,
        });
      }catch(error){throw originExternalOperationError(error);}
      const stored=installationIncarnationRowSchema.safeParse(await database.prepare(
        `SELECT installation.installation_id,installation.owner_id,
                installation.namespace_id,installation.created_at,installation.updated_at,
                receipt_fence.issued_at_fence
         FROM apple_owner_external_operation_leases AS active_lease
         JOIN origin_installations AS installation
           ON installation.owner_id=active_lease.owner_id
          AND installation.installation_id=active_lease.resource_id
         JOIN origin_installation_receipt_fences AS receipt_fence
           ON receipt_fence.installation_id=installation.installation_id
         WHERE active_lease.lease_token=? AND active_lease.owner_id=?
           AND active_lease.operation_kind='origin' AND active_lease.resource_id=?
           AND active_lease.apple_subject_hash IS ? AND active_lease.expires_at>?`,
      ).bind(
        input.leaseToken,
        input.authorization.userId,
        resource,
        input.authorization.appleSubjectHash,
        input.now,
      ).first());
      if(stored.success){
        return {expiresAt:lease.expiresAt,incarnation:parseInstallationIncarnation(stored.data)};
      }
      try{await externalOperations.release(input.leaseToken);}catch{}
      await assertOwnerAllowed(
        input.authorization.userId,
        input.now,
        input.authorization.authorizationStartedAt,
        input.authorization.appleSubjectHash,
      );
      throw new OriginAuthError(503,'ORIGIN_INSTALLATION_INCARNATION_UNAVAILABLE','Cursor Origin installation generation could not be fenced safely.');
    },
    async completeExternalOperationLease(leaseToken,now){
      try{await externalOperations.complete(leaseToken,now);}catch(error){throw originExternalOperationError(error);}
    },
    async completeExternalOperationLeaseForIncarnation(input){
      const token=opaqueHashSchema.parse(input.leaseToken);
      const incarnation=normalizeInstallationIncarnation(input.incarnation);
      if(incarnation.ownerId!==input.authorization.userId){
        throw new TypeError('Origin installation incarnation owner is invalid.');
      }
      if(!Number.isSafeInteger(input.now)||input.now<0){
        throw new TypeError('Origin installation completion time is invalid.');
      }
      const expectedState=installationIncarnationState(incarnation,input.completionState);
      const released=await database.prepare(
        `DELETE FROM apple_owner_external_operation_leases
         WHERE lease_token=? AND owner_id=? AND operation_kind='origin'
           AND resource_id=? AND apple_subject_hash IS ? AND expires_at>?
           AND ${APPLE_OWNER_OPERATION_ALLOWED_SQL}
           AND ${expectedState.sql}
         RETURNING lease_token`,
      ).bind(
        token,
        input.authorization.userId,
        incarnation.installationId,
        input.authorization.appleSubjectHash,
        input.now,
        ...appleOwnerOperationGateBindings(input.authorization,input.now),
        ...expectedState.bindings,
      ).first();
      if(released!==null){
        if(await database.prepare(
          'SELECT 1 FROM apple_owner_external_operation_leases WHERE lease_token=?',
        ).bind(token).first()!==null){
          throw new OriginAuthError(503,'ORIGIN_EXTERNAL_OPERATION_LEASE_RELEASE_FAILED','Cursor Origin operation authority could not be released safely.');
        }
        return;
      }
      await assertOwnerAllowed(
        input.authorization.userId,
        input.now,
        input.authorization.authorizationStartedAt,
        input.authorization.appleSubjectHash,
      );
      const activeLease=await database.prepare(
        `SELECT 1 FROM apple_owner_external_operation_leases
         WHERE lease_token=? AND owner_id=? AND operation_kind='origin'
           AND resource_id=? AND apple_subject_hash IS ? AND expires_at>?`,
      ).bind(
        token,
        input.authorization.userId,
        incarnation.installationId,
        input.authorization.appleSubjectHash,
        input.now,
      ).first();
      if(activeLease===null){
        throw new OriginAuthError(503,'ORIGIN_EXTERNAL_OPERATION_LEASE_EXPIRED','Cursor Origin operation authority expired before completion. Verify provider state before retrying.');
      }
      throw new OriginAuthError(
        409,
        input.completionState.kind==='present'?'ORIGIN_INSTALLATION_STATE_CHANGED':'ORIGIN_INSTALLATION_DISCONNECT_UNCERTAIN',
        input.completionState.kind==='present'
          ?'The Cursor Origin installation changed before the operation could return.'
          :'The Cursor Origin installation was reconnected before disconnection completed.',
      );
    },
    async releaseExternalOperationLease(leaseToken){
      try{await externalOperations.release(leaseToken);}catch(error){throw originExternalOperationError(error);}
    },
    async assertOwnerOperationAllowed(operationAuthorization,now){
      await assertOwnerAllowed(
        operationAuthorization.userId,
        now,
        operationAuthorization.authorizationStartedAt,
        operationAuthorization.appleSubjectHash,
      );
    },
    assertInstallationOperationAllowed,
    assertInstallationIncarnationOperationAllowed,
  };
}

export async function withD1OriginExternalOperationLease<T>(input:{
  repository:OriginD1Repository;
  authorization:AppleOwnerOperationAuthorization;
  installationId:string;
  crypto:Crypto;
  now:()=>number;
  completionState?:(result:T)=>OriginInstallationCompletionState;
  operation:(incarnation:OriginInstallationIncarnation)=>Promise<T>;
}):Promise<T>{
  const leaseToken=createOriginExternalOperationLeaseToken(input.crypto);
  const lease=await input.repository.claimExternalOperationLease({
    authorization:input.authorization,
    installationId:input.installationId,
    leaseToken,
    now:input.now(),
  });
  let completed=false;
  try{
    const result=await input.operation(lease.incarnation);
    const completionState=input.completionState?.(result)??{kind:'present'};
    await input.repository.completeExternalOperationLeaseForIncarnation({
      authorization:input.authorization,
      leaseToken,
      incarnation:lease.incarnation,
      completionState,
      now:input.now(),
    });
    await input.repository.assertInstallationIncarnationOperationAllowed(
      input.authorization,
      lease.incarnation,
      completionState,
      input.now(),
    );
    completed=true;
    return result;
  }finally{
    if(!completed)await input.repository.releaseExternalOperationLease(leaseToken);
  }
}

function createOriginExternalOperationLeaseToken(cryptoProvider:Crypto):string{
  const bytes=new Uint8Array(32);
  cryptoProvider.getRandomValues(bytes);
  let binary='';
  for(const byte of bytes)binary+=String.fromCharCode(byte);
  return btoa(binary).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}

function originExternalOperationError(error:unknown,installationFlow=false):unknown{
  if(!(error instanceof AppleOwnerExternalOperationError))return error;
  if(error.code==='APPLE_OWNER_EXTERNAL_OPERATION_RESOURCE_NOT_FOUND'){
    if(installationFlow){
      return new OriginAuthError(409,'ORIGIN_FLOW_INVALID','This Cursor Origin installation request expired, was already used, or belongs to another account.');
    }
    return new OriginAuthError(404,'ORIGIN_INSTALLATION_NOT_FOUND','This Cursor Origin installation is not connected to the signed-in account.');
  }
  const code=error.code.startsWith('APPLE_OWNER_EXTERNAL_OPERATION_')
    ?error.code.replace('APPLE_OWNER_','ORIGIN_')
    :error.code;
  return new OriginAuthError(error.status,code,error.message.replace('External-operation','Cursor Origin operation'));
}

export async function hashOriginState(state:string,cryptoProvider:Crypto=globalThis.crypto):Promise<string>{
  const digest=await cryptoProvider.subtle.digest('SHA-256',new TextEncoder().encode(state));
  let binary='';for(const byte of new Uint8Array(digest))binary+=String.fromCharCode(byte);
  return btoa(binary).replaceAll('+','-').replaceAll('/','_').replaceAll('=','');
}
