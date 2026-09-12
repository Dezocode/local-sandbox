import { sql } from 'drizzle-orm';
import { check, index, integer, primaryKey, sqliteTable, text, uniqueIndex } from 'drizzle-orm/sqlite-core';
export const workspaces=sqliteTable('workspaces',{userId:text('user_id').primaryKey(),policy:text('policy').notNull(),completed:text('completed').notNull(),revision:integer('revision').notNull().default(0),fileClock:integer('file_clock').notNull().default(-1),fileClockClaim:text('file_clock_claim')},t=>[
 check('workspaces_file_clock_safe_check',sql`${t.fileClock} between -1 and 9007199254740991`),
 check('workspaces_file_clock_claim_check',sql`${t.fileClockClaim} is null or (length(${t.fileClockClaim})=43 and ${t.fileClockClaim} not glob '*[^A-Za-z0-9_-]*')`),
]);
export const files=sqliteTable('files',{userId:text('user_id').notNull(),path:text('path').notNull(),content:text('content').notNull(),version:integer('version').notNull().default(0)},t=>[primaryKey({columns:[t.userId,t.path]}),check('files_version_safe_check',sql`${t.version} between 0 and 9007199254740991`)]);
export const receipts=sqliteTable('receipts',{userId:text('user_id').notNull(),id:text('id').notNull(),payload:text('payload').notNull(),createdAt:text('created_at').notNull()},t=>[primaryKey({columns:[t.userId,t.id]})]);
export const usage=sqliteTable('usage',{userId:text('user_id').notNull(),window:text('window').notNull(),calls:integer('calls').notNull().default(0)},t=>[primaryKey({columns:[t.userId,t.window]})]);
export const appleAuthFlows=sqliteTable('apple_auth_flows',{
 schemaVersion:integer('schema_version').notNull(),stateHash:text('state_hash').primaryKey(),purpose:text('purpose').notNull(),ownerId:text('owner_id'),nonceHash:text('nonce_hash').notNull(),browserBindingHash:text('browser_binding_hash').notNull(),ownerBinding:text('owner_binding').notNull(),returnTo:text('return_to').notNull(),createdAt:integer('created_at').notNull(),expiresAt:integer('expires_at').notNull(),consumedAt:integer('consumed_at'),
},t=>[index('apple_auth_flows_expiry_idx').on(t.expiresAt,t.stateHash)]);
export const appleAuthSessions=sqliteTable('apple_auth_sessions',{
 schemaVersion:integer('schema_version').notNull(),sessionHash:text('session_hash').primaryKey(),ownerId:text('owner_id').notNull(),ownerBinding:text('owner_binding').notNull(),appleSubjectHash:text('apple_subject_hash').notNull(),encryptedCredentials:text('encrypted_credentials').notNull(),createdAt:integer('created_at').notNull(),expiresAt:integer('expires_at').notNull(),lastValidatedAt:integer('last_validated_at').notNull(),revokedAt:integer('revoked_at'),
},t=>[index('apple_auth_sessions_expiry_idx').on(t.expiresAt,t.sessionHash)]);
export const appleIdentityLinks=sqliteTable('apple_identity_links',{
 appleSubjectHash:text('apple_subject_hash').primaryKey(),principalId:text('principal_id'),principalCreatedAt:integer('principal_created_at'),ownerId:text('owner_id').notNull(),emailForwardingEnabled:integer('email_forwarding_enabled',{mode:'boolean'}),emailStateUpdatedAt:integer('email_state_updated_at'),createdAt:integer('created_at').notNull(),updatedAt:integer('updated_at').notNull(),
},t=>[index('apple_identity_links_principal_idx').on(t.ownerId,t.principalId,t.appleSubjectHash)]);
export const appleAuthNotifications=sqliteTable('apple_auth_notifications',{
 notificationIdHash:text('notification_id_hash').primaryKey(),eventType:text('event_type').notNull(),appleSubjectHash:text('apple_subject_hash'),ownerId:text('owner_id'),issuedAt:integer('issued_at').notNull(),eventTime:integer('event_time'),originConnections:text('origin_connections'),originUnresolvedInstallationIds:text('origin_unresolved_installation_ids'),processedAt:integer('processed_at').notNull(),expiresAt:integer('expires_at').notNull(),
},t=>[index('apple_auth_notifications_expiry_idx').on(t.expiresAt,t.notificationIdHash)]);
export const appleAccountDeletions=sqliteTable('apple_account_deletions',{
 deletionKeyHash:text('deletion_key_hash').primaryKey(),ownerBinding:text('owner_binding').notNull(),ownerId:text('owner_id').notNull(),appleSubjectHash:text('apple_subject_hash').notNull(),applePrincipalId:text('apple_principal_id'),deleteOwnerData:integer('delete_owner_data',{mode:'boolean'}).notNull(),providerCredentials:text('provider_credentials'),originConnections:text('origin_connections'),revocationLeaseToken:text('revocation_lease_token'),revocationLeaseUntil:integer('revocation_lease_until'),completionFenceToken:text('completion_fence_token'),startedAt:integer('started_at').notNull(),completedAt:integer('completed_at'),expiresAt:integer('expires_at').notNull(),
},t=>[
 index('apple_account_deletions_expiry_idx').on(t.expiresAt,t.deletionKeyHash),
 index('apple_account_deletions_subject_expiry_idx').on(t.appleSubjectHash,t.expiresAt),
 index('apple_account_deletions_owner_subject_expiry_idx').on(t.ownerId,t.appleSubjectHash,t.expiresAt),
 uniqueIndex('apple_account_deletions_standalone_lease_idx').on(t.ownerId).where(sql`${t.revocationLeaseToken} is not null and ${t.deleteOwnerData}=1`),
 uniqueIndex('apple_account_deletions_linked_lease_idx').on(t.ownerId,t.applePrincipalId).where(sql`${t.revocationLeaseToken} is not null and ${t.deleteOwnerData}=0`),
]);
export const appleAccountDeletionSubjects=sqliteTable('apple_account_deletion_subjects',{
 deletionKeyHash:text('deletion_key_hash').notNull().references(()=>appleAccountDeletions.deletionKeyHash,{onDelete:'cascade'}),appleSubjectHash:text('apple_subject_hash').notNull(),
},t=>[primaryKey({columns:[t.deletionKeyHash,t.appleSubjectHash]})]);
export const appleAuthAdmissionCutover=sqliteTable('apple_auth_admission_cutover',{
 singleton:integer('singleton').primaryKey(),cutoverAt:integer('cutover_at').notNull(),
},t=>[
 check('apple_auth_admission_cutover_singleton_check',sql`${t.singleton}=1`),
 check('apple_auth_admission_cutover_time_check',sql`${t.cutoverAt}>=0`),
]);
export const appleOwnerExternalOperationLeases=sqliteTable('apple_owner_external_operation_leases',{
 leaseToken:text('lease_token').primaryKey(),ownerId:text('owner_id').notNull(),operationKind:text('operation_kind',{enum:['origin','github','apple-auth','origin-install']}).notNull(),resourceId:text('resource_id').notNull(),appleSubjectHash:text('apple_subject_hash'),applePrincipalId:text('apple_principal_id'),claimedAt:integer('claimed_at').notNull(),expiresAt:integer('expires_at').notNull(),
},t=>[
 index('apple_owner_external_operation_leases_expiry_idx').on(t.expiresAt,t.leaseToken),
 index('apple_owner_external_operation_leases_owner_principal_expiry_idx').on(t.ownerId,t.applePrincipalId,t.expiresAt),
 uniqueIndex('apple_owner_external_operation_leases_apple_auth_principal_idx').on(t.ownerId,t.applePrincipalId).where(sql`${t.operationKind}='apple-auth'`),
 uniqueIndex('apple_owner_external_operation_leases_origin_install_principal_idx').on(t.ownerId,t.applePrincipalId).where(sql`${t.operationKind}='origin-install'`),
 uniqueIndex('apple_owner_external_operation_leases_origin_resource_idx').on(t.resourceId).where(sql`${t.operationKind} in ('origin','origin-install')`),
 uniqueIndex('apple_owner_external_operation_leases_origin_install_owner_idx').on(t.ownerId).where(sql`${t.operationKind}='origin-install'`),
 check('apple_owner_external_operation_leases_operation_check',sql`${t.operationKind} in ('origin','github','apple-auth','origin-install') and length(${t.resourceId}) between 1 and 200`),
 check('apple_owner_external_operation_leases_identity_check',sql`(${t.appleSubjectHash} is null and ${t.applePrincipalId} is null) or (${t.appleSubjectHash} is not null and ${t.applePrincipalId} is not null)`),
]);
export const appleAuthPossibleCredentials=sqliteTable('apple_auth_possible_credentials',{
 ownerId:text('owner_id').notNull(),applePrincipalId:text('apple_principal_id').notNull(),appleSubjectHash:text('apple_subject_hash').notNull(),attemptToken:text('attempt_token').notNull(),reviewToken:text('review_token').notNull(),credentialState:text('credential_state',{enum:['prepared','possible']}).notNull().default('prepared'),markedAt:integer('marked_at').notNull(),
},t=>[
 primaryKey({columns:[t.ownerId,t.applePrincipalId]}),
 index('apple_auth_possible_credentials_subject_idx').on(t.ownerId,t.appleSubjectHash),
 check('apple_auth_possible_credentials_hash_check',sql`length(${t.applePrincipalId})=43 and length(${t.appleSubjectHash})=43 and length(${t.attemptToken})=43 and length(${t.reviewToken})=43`),
 check('apple_auth_possible_credentials_state_check',sql`${t.credentialState} in ('prepared','possible')`),
]);
export const originPossibleInstallations=sqliteTable('origin_possible_installations',{
 ownerId:text('owner_id').notNull(),scopeId:text('scope_id').notNull(),applePrincipalId:text('apple_principal_id'),appleSubjectHash:text('apple_subject_hash'),flowToken:text('flow_token').notNull(),markedAt:integer('marked_at').notNull(),
},t=>[
 primaryKey({columns:[t.ownerId,t.scopeId]}),
 index('origin_possible_installations_subject_idx').on(t.ownerId,t.appleSubjectHash),
 check('origin_possible_installations_hash_check',sql`((${t.scopeId}='host' and ${t.applePrincipalId} is null and ${t.appleSubjectHash} is null) or (${t.scopeId}=${t.applePrincipalId} and length(${t.applePrincipalId})=43 and length(${t.appleSubjectHash})=43)) and length(${t.flowToken})=43`),
]);
export const appleNativeSessions=sqliteTable('apple_native_sessions',{
 schemaVersion:integer('schema_version').notNull(),identityTokenHash:text('identity_token_hash').primaryKey(),sessionHash:text('session_hash').notNull(),ownerId:text('owner_id').notNull(),appleSubjectHash:text('apple_subject_hash').notNull(),activationState:text('activation_state',{enum:['pending','active']}).notNull().default('pending'),createdAt:integer('created_at').notNull(),expiresAt:integer('expires_at').notNull(),identityTokenExpiresAt:integer('identity_token_expires_at').notNull(),revokedAt:integer('revoked_at'),
},t=>[
 uniqueIndex('apple_native_sessions_session_hash_unique').on(t.sessionHash),
 index('apple_native_sessions_expiry_idx').on(t.expiresAt,t.identityTokenHash),
 check('apple_native_sessions_activation_state_check',sql`${t.activationState} in ('pending','active')`),
]);
export const appleNativeGrants=sqliteTable('apple_native_grants',{
 schemaVersion:integer('schema_version').notNull(),grantHash:text('grant_hash').primaryKey(),authorizationCodeHash:text('authorization_code_hash').notNull(),sessionHash:text('session_hash').notNull(),ownerId:text('owner_id').notNull(),principalId:text('principal_id').notNull(),appleSubjectHash:text('apple_subject_hash').notNull(),ownerBinding:text('owner_binding').notNull(),encryptedCredentials:text('encrypted_credentials').notNull(),createdAt:integer('created_at').notNull(),lastValidatedAt:integer('last_validated_at').notNull(),expiresAt:integer('expires_at').notNull(),revocationPendingAt:integer('revocation_pending_at'),
},t=>[
 uniqueIndex('apple_native_grants_authorization_code_unique').on(t.authorizationCodeHash),
 uniqueIndex('apple_native_grants_session_unique').on(t.sessionHash),
 index('apple_native_grants_principal_idx').on(t.ownerId,t.principalId,t.grantHash),
 index('apple_native_grants_expiry_idx').on(t.expiresAt,t.grantHash),
]);
export const appleNativeAuthorizationCodeClaims=sqliteTable('apple_native_authorization_code_claims',{
 authorizationCodeHash:text('authorization_code_hash').primaryKey(),claimedAt:integer('claimed_at').notNull(),expiresAt:integer('expires_at').notNull(),
},t=>[index('apple_native_authorization_code_claims_expiry_idx').on(t.expiresAt,t.authorizationCodeHash)]);
export const syncWorkspaces=sqliteTable('sync_workspaces',{
 userId:text('user_id').notNull(),workspaceId:text('workspace_id').notNull(),epoch:text('epoch').notNull(),incarnation:text('incarnation').notNull(),recovery:text('recovery').notNull(),revision:integer('revision').notNull().default(0),createdAt:text('created_at').notNull(),updatedAt:text('updated_at').notNull(),
},t=>[
 primaryKey({columns:[t.userId,t.workspaceId]}),
 check('sync_workspaces_incarnation_check',sql`length(${t.incarnation})=64 and ${t.incarnation} not glob '*[^0-9a-f]*'`),
 check('sync_workspaces_revision_safe_check',sql`${t.revision} between 0 and 9007199254740991`),
]);
export const syncWorkspaceEpochs=sqliteTable('sync_workspace_epochs',{
 userId:text('user_id').notNull().references(()=>workspaces.userId,{onDelete:'cascade'}),workspaceId:text('workspace_id').notNull(),epoch:text('epoch').notNull(),incarnation:text('incarnation').notNull(),enrolledAt:text('enrolled_at').notNull(),
},t=>[
 primaryKey({columns:[t.userId,t.workspaceId,t.epoch]}),
 uniqueIndex('sync_workspace_epochs_incarnation_unique').on(t.userId,t.workspaceId,t.incarnation),
 index('sync_workspace_epochs_owner_idx').on(t.userId,t.workspaceId),
 check('sync_workspace_epochs_workspace_check',sql`length(${t.workspaceId})=32 and ${t.workspaceId} not glob '*[^A-Za-z0-9_-]*'`),
 check('sync_workspace_epochs_epoch_check',sql`length(${t.epoch}) between 16 and 64 and ${t.epoch} not glob '*[^A-Za-z0-9_-]*'`),
 check('sync_workspace_epochs_incarnation_check',sql`length(${t.incarnation})=64 and ${t.incarnation} not glob '*[^0-9a-f]*'`),
]);
export const syncRecords=sqliteTable('sync_records',{
 userId:text('user_id').notNull(),workspaceId:text('workspace_id').notNull(),recordId:text('record_id').notNull(),revision:integer('revision').notNull().default(0),mutationId:text('mutation_id').notNull(),envelope:text('envelope').notNull(),updatedAt:text('updated_at').notNull(),
},t=>[primaryKey({columns:[t.userId,t.workspaceId,t.recordId]}),check('sync_records_revision_safe_check',sql`${t.revision} between 0 and 9007199254740991`)]);
export const originAuthFlows=sqliteTable('origin_auth_flows',{
 stateHash:text('state_hash').primaryKey(),ownerId:text('owner_id').notNull(),returnTo:text('return_to').notNull(),createdAt:integer('created_at').notNull(),expiresAt:integer('expires_at').notNull(),consumedAt:integer('consumed_at'),
});
export const originAuthReceipts=sqliteTable('origin_auth_receipts',{
 receiptId:text('receipt_id').primaryKey(),expiresAt:integer('expires_at').notNull(),claimedAt:integer('claimed_at').notNull(),
});
export const originInstallations=sqliteTable('origin_installations',{
 installationId:text('installation_id').primaryKey(),ownerId:text('owner_id').notNull(),namespaceId:text('namespace_id').notNull(),createdAt:integer('created_at').notNull(),updatedAt:integer('updated_at').notNull(),
});
export const originInstallationReceiptFences=sqliteTable('origin_installation_receipt_fences',{
 installationId:text('installation_id').primaryKey(),issuedAtFence:integer('issued_at_fence').notNull(),
},t=>[
 check('origin_installation_receipt_fences_installation_check',sql`(substr(${t.installationId},1,2)='i_' and length(${t.installationId}) between 10 and 102 and substr(${t.installationId},3) not glob '*[^a-z0-9]*') or (substr(${t.installationId},1,5)='inst_' and length(${t.installationId}) between 13 and 105 and substr(${t.installationId},6) not glob '*[^a-z0-9]*')`),
 check('origin_installation_receipt_fences_time_check',sql`${t.issuedAtFence} between 0 and 9007199254740991`),
]);
