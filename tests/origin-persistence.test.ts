import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import { AppleAuthError } from '../lib/apple-auth.ts';
import { createD1AppleAuthRepository } from '../lib/apple-auth-d1.ts';
import { createD1AppleAccountDeletionRepository } from '../lib/apple-auth-lifecycle-d1.ts';
import { applyVerifiedAppleServerNotification } from '../lib/apple-auth-lifecycle.ts';
import {
  APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS,
  AppleOwnerExternalOperationError,
  acknowledgeD1ApplePossibleCredentialReview,
  createD1AppleOwnerExternalOperationLeaseRepository,
  readD1ApplePossibleCredentialReview,
  withD1AppleOwnerExternalOperationLease,
} from '../lib/apple-auth-external-operation-d1.ts';
import { OriginAuthError, type OriginConfiguration, type OriginInstallationReceipt, parseOriginConfiguration } from '../lib/origin-auth.ts';
import { ORIGIN_EXTERNAL_OPERATION_LEASE_SECONDS, createD1OriginRepository, hashOriginState, withD1OriginExternalOperationLease } from '../lib/origin-auth-d1.ts';
import { persistOriginInstallationOrRequireManualCleanup } from '../lib/origin-auth-http.ts';
import { deleteOriginInstallation, listOriginRepositories, syncOriginMirror, type OriginRepository } from '../lib/origin-service.ts';

const NOW=1_800_000_000;
const INSTALLATION_ID='inst_01k2ja2000e0080000000000b2';
const REPOSITORY_ID='repo_01k2ja2000e0080000000000q4';

test('D1 binds one-use Origin flows, receipts, and installations to one dashboard owner',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1OriginRepository(database);
    const stateHash=await hashOriginState('S'.repeat(43));
    assert.equal(stateHash.includes('S'.repeat(20)),false);
    await repository.createFlow({stateHash,ownerId:'host-a',returnTo:'/local/index.html',createdAt:NOW,expiresAt:NOW+600,authorizationStartedAt:NOW,appleSubjectHash:null});
    assert.equal(await repository.consumeFlow(stateHash,'host-b',NOW+1,NOW,null),null);
    const consumed=await Promise.all([repository.consumeFlow(stateHash,'host-a',NOW+1,NOW,null),repository.consumeFlow(stateHash,'host-a',NOW+1,NOW,null)]);
    assert.equal(consumed.filter(Boolean).length,1);
    assert.deepEqual(consumed.find(Boolean),{returnTo:'/local/index.html'});

    const receiptId=crypto.randomUUID();
    const claims=await Promise.all([repository.replayStore.claim({id:receiptId,expiresAt:NOW+300},NOW),repository.replayStore.claim({id:receiptId,expiresAt:NOW+300},NOW)]);
    assert.deepEqual(claims.sort(),[false,true]);
    assert.equal(await repository.replayStore.claim({id:crypto.randomUUID(),expiresAt:NOW},NOW),false);

    const receipt={schemaVersion:1,appId:'app_01k2ja2000e0080000000000a1',installationId:INSTALLATION_ID,namespaceId:'ns_01k2ja2000e0080000000000p3',receiptId,installedBy:{id:'user_01k2ja2000e0080000000000c3',email:'private@example.test'},issuedAt:NOW,expiresAt:NOW+300} as OriginInstallationReceipt;
    const installed=await repository.saveInstallation('host-a',receipt,NOW,NOW,null);
    assert.equal(installed.installationId,INSTALLATION_ID);
    assert.equal(await repository.ownsInstallation('host-a',INSTALLATION_ID),true);
    assert.equal(await repository.ownsInstallation('host-b',INSTALLATION_ID),false);
    await assert.rejects(()=>repository.saveInstallation('host-b',receipt,NOW+1,NOW,null),matchesCode('ORIGIN_INSTALLATION_OWNER_CONFLICT'));
    assert.deepEqual((await repository.listInstallations({userId:'host-a',authorizationStartedAt:NOW,appleSubjectHash:null},()=>NOW)).map(value=>value.installationId),[INSTALLATION_ID]);
    assert.deepEqual(await repository.listInstallations({userId:'host-b',authorizationStartedAt:NOW,appleSubjectHash:null},()=>NOW),[]);
    assert.equal(await repository.deleteInstallation('host-b',INSTALLATION_ID,NOW+2,NOW,null),false);
    assert.equal(await repository.deleteInstallation('host-a',INSTALLATION_ID,NOW+2,NOW,null),true);
    assert.equal(await repository.deleteInstallation('host-a',INSTALLATION_ID,NOW+2,NOW,null),false);

    const linkedOwner='linked-chatgpt-owner';
    const subjectA='A'.repeat(43);
    const subjectB='B'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subjectB,'P'.repeat(43),NOW,linkedOwner,NOW,NOW).run();
    await database.prepare(
      `INSERT INTO apple_account_deletions(
        deletion_key_hash,owner_binding,owner_id,apple_subject_hash,delete_owner_data,
        provider_credentials,started_at,completed_at,expires_at
      ) VALUES(?,?,?,?,0,NULL,?,NULL,?)`,
    ).bind('D'.repeat(43),'E'.repeat(43),linkedOwner,subjectA,NOW+10,NOW+600).run();
    await assert.rejects(()=>repository.createFlow({
      stateHash:'A'.repeat(43),ownerId:linkedOwner,returnTo:'/',createdAt:NOW+11,
      expiresAt:NOW+611,authorizationStartedAt:NOW+9,appleSubjectHash:subjectA,
    }),matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
    const callbackRaceReceipt={
      ...receipt,
      installationId:'inst_01k2ja2000e0080000000000r9',
      receiptId:crypto.randomUUID(),
    } as OriginInstallationReceipt;
    const compensatedInstallations:string[]=[];
    await assert.rejects(()=>persistOriginInstallationOrRequireManualCleanup({
      persist:()=>repository.saveInstallation(
        linkedOwner,
        callbackRaceReceipt,
        NOW+11,
        NOW+9,
        subjectA,
      ),
      async releaseAuthority(){compensatedInstallations.push(callbackRaceReceipt.installationId);},
    }),matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'));
    assert.deepEqual(compensatedInstallations,[callbackRaceReceipt.installationId]);
    assert.equal(
      await repository.ownsInstallation(linkedOwner,callbackRaceReceipt.installationId),
      false,
    );
    await repository.createFlow({
      stateHash:'B'.repeat(43),ownerId:linkedOwner,returnTo:'/',createdAt:NOW+11,
      expiresAt:NOW+611,authorizationStartedAt:NOW+9,appleSubjectHash:subjectB,
    });
    await assert.rejects(()=>repository.createFlow({
      stateHash:'H'.repeat(43),ownerId:linkedOwner,returnTo:'/',createdAt:NOW+11,
      expiresAt:NOW+611,authorizationStartedAt:NOW+9,appleSubjectHash:null,
    }),matchesCode('ORIGIN_INSTALLATION_FLOW_IN_PROGRESS'));
    assert.equal((await repository.consumeFlow('B'.repeat(43),linkedOwner,NOW+12,NOW+9,subjectB))?.returnTo,'/');
    await repository.releaseInstallationFlowLease('B'.repeat(43));
    await repository.createFlow({
      stateHash:'H'.repeat(43),ownerId:linkedOwner,returnTo:'/',createdAt:NOW+13,
      expiresAt:NOW+613,authorizationStartedAt:NOW+9,appleSubjectHash:null,
    });
    assert.equal((await repository.consumeFlow('H'.repeat(43),linkedOwner,NOW+14,NOW+9,null))?.returnTo,'/');
  }finally{await miniflare.dispose();}
});

test('D1 Origin install markers serialize callbacks and preserve manual cleanup debt across expiry',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1OriginRepository(database);
    const deletionRepository=createD1AppleAccountDeletionRepository(database);
    const ownerId='linked-origin-install-owner';
    const subject='o'.repeat(43),principal='r'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subject,principal,NOW,ownerId,NOW,NOW).run();
    const authorization={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subject};
    const receipt=(installationId:string)=>({
      schemaVersion:1,
      appId:'app_01k2ja2000e0080000000000a1',
      installationId,
      namespaceId:'ns_01k2ja2000e0080000000000p3',
      receiptId:crypto.randomUUID(),
      installedBy:{id:'user_01k2ja2000e0080000000000c3',email:'private@example.test'},
      issuedAt:NOW,
      expiresAt:NOW+1_800,
    } as OriginInstallationReceipt);
    const flow=(stateHash:string,createdAt:number)=>({
      stateHash,
      ownerId,
      returnTo:'/',
      createdAt,
      expiresAt:createdAt+600,
      authorizationStartedAt:NOW,
      appleSubjectHash:subject,
    });
    const deletionInput=(at:number)=>({
      ownerId,
      appleSubjectHash:subject,
      deleteOwnerData:false,
      ownerBinding:'w'.repeat(43),
      deletionKeyHash:'y'.repeat(43),
      revocationLeaseToken:'z'.repeat(43),
      startedAt:at,
      leaseClaimedAt:at,
      expiresAt:at+600,
    });

    const successfulState='s'.repeat(43);
    await repository.createFlow(flow(successfulState,NOW+1));
    assert.deepEqual(await database.prepare(
      `SELECT flow_token FROM origin_possible_installations
       WHERE owner_id=? AND apple_principal_id=?`,
    ).bind(ownerId,principal).first(),{flow_token:successfulState});
    await assert.rejects(
      deletionRepository.beginAppleAccountDeletion(deletionInput(NOW+2)),
      matchesAppleCode('APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS'),
    );
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM apple_account_deletions WHERE deletion_key_hash=?',
    ).bind(deletionInput(NOW+2).deletionKeyHash).first(),null);
    await database.prepare(
      'DELETE FROM apple_account_deletions WHERE deletion_key_hash=?',
    ).bind(deletionInput(NOW+2).deletionKeyHash).run();
    await repository.claimInstallationFlowLease({authorization,stateHash:successfulState,installationId:'inst_01k2ja2000e0080000000000s1',receiptIssuedAt:NOW,now:NOW+2});
    assert.notEqual(await repository.consumeFlow(successfulState,ownerId,NOW+2,NOW,subject),null);
    const successfulReceipt=receipt('inst_01k2ja2000e0080000000000s1');
    assert.equal(await repository.replayStore.claim({id:successfulReceipt.receiptId,expiresAt:successfulReceipt.expiresAt},NOW+2),true);
    assert.equal((await repository.saveInstallationAndCompleteFlow({
      ownerId,
      stateHash:successfulState,
      receipt:successfulReceipt,
      now:NOW+3,
      authorizationStartedAt:NOW,
      appleSubjectHash:subject,
    })).installationId,successfulReceipt.installationId);
    assert.equal(await repository.replayStore.claim({id:successfulReceipt.receiptId,expiresAt:successfulReceipt.expiresAt},NOW+4),false);
    assert.deepEqual(await repository.listInstallations(authorization,()=>NOW+4),[{
      installationId:successfulReceipt.installationId,
      namespaceId:successfulReceipt.namespaceId,
      createdAt:NOW+3,
      updatedAt:NOW+3,
    }]);
    await assert.rejects(repository.saveInstallationAndCompleteFlow({
      ownerId,
      stateHash:successfulState,
      receipt:successfulReceipt,
      now:NOW+4,
      authorizationStartedAt:NOW,
      appleSubjectHash:subject,
    }),matchesCode('ORIGIN_INSTALLATION_RECEIPT_STALE'));
    assert.equal(await repository.ownsInstallation(ownerId,successfulReceipt.installationId),true);
    assert.equal(await database.prepare(
      `SELECT 1 FROM origin_possible_installations WHERE owner_id=?`,
    ).bind(ownerId).first(),null);

    const abandonedState='a'.repeat(43);
    const abandonedAt=NOW+10;
    await repository.createFlow(flow(abandonedState,abandonedAt));
    await repository.claimInstallationFlowLease({authorization,stateHash:abandonedState,installationId:'inst_01k2ja2000e0080000000000b1',receiptIssuedAt:NOW,now:abandonedAt+1});
    assert.notEqual(
      await repository.consumeFlow(abandonedState,ownerId,abandonedAt+1,NOW,subject),
      null,
    );
    const retryState='b'.repeat(43);
    const retryAt=abandonedAt+ORIGIN_EXTERNAL_OPERATION_LEASE_SECONDS;
    await assert.rejects(
      repository.createFlow(flow(retryState,retryAt)),
      matchesCode('ORIGIN_MANUAL_CLEANUP_REQUIRED'),
    );
    assert.deepEqual(await database.prepare(
      `SELECT flow_token FROM origin_possible_installations
       WHERE owner_id=? AND apple_principal_id=?`,
    ).bind(ownerId,principal).first(),{flow_token:abandonedState});
    await assert.rejects(persistOriginInstallationOrRequireManualCleanup({
      persist:()=>repository.saveInstallationAndCompleteFlow({
        ownerId,
        stateHash:abandonedState,
        receipt:receipt('inst_01k2ja2000e0080000000000b1'),
        now:retryAt+1,
        authorizationStartedAt:NOW,
        appleSubjectHash:subject,
      }),
      releaseAuthority:()=>repository.releaseInstallationFlowLease(abandonedState),
    }),matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'));
    assert.deepEqual(await database.prepare(
      `SELECT flow_token FROM origin_possible_installations
       WHERE owner_id=? AND apple_principal_id=?`,
    ).bind(ownerId,principal).first(),{flow_token:abandonedState});
    await repository.acknowledgePossibleInstallation(authorization,abandonedState,retryAt+1);
    const failedState='c'.repeat(43);
    const failedAt=retryAt+2;
    await repository.createFlow(flow(failedState,failedAt));
    await assert.rejects(persistOriginInstallationOrRequireManualCleanup({
      persist:async()=>{
        await repository.claimInstallationFlowLease({authorization,stateHash:failedState,installationId:'inst_01k2ja2000e0080000000000f1',receiptIssuedAt:NOW,now:failedAt+1});
        assert.notEqual(await repository.consumeFlow(failedState,ownerId,failedAt+1,NOW,subject),null);
        throw new OriginAuthError(503,'ORIGIN_INSTALLATION_STORE_UNAVAILABLE','simulated post-provider failure');
      },
      releaseAuthority:()=>repository.releaseInstallationFlowLease(failedState),
    }),matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'));
    assert.equal(await database.prepare(
      `SELECT COUNT(*) AS count FROM origin_possible_installations WHERE owner_id=?`,
    ).bind(ownerId).first('count'),1);
    assert.equal(await database.prepare(
      `SELECT 1 FROM apple_owner_external_operation_leases
       WHERE lease_token=? AND operation_kind='origin-install'`,
    ).bind(failedState).first(),null);
    assert.doesNotMatch(
      await readFile('app/api/origin/callback/route.ts','utf8'),
      /deleteOriginInstallation/,
    );

    const deleteAt=failedAt+601;
    assert.equal(await database.prepare(
      'SELECT expires_at<=? AS expired FROM origin_auth_flows WHERE state_hash=?',
    ).bind(deleteAt,failedState).first('expired'),1);
    const deletion=deletionInput(deleteAt);
    assert.equal(await deletionRepository.beginAppleAccountDeletion(deletion),null);
    assert.deepEqual(await deletionRepository.readOriginInstallationsForDeletion({
      ownerId,
      appleSubjectHash:subject,
      deleteOwnerData:false,
    }),{installationIds:[],unreadableInstallations:1});
    const providerCredentials={
      credentialsFound:0,
      credentialsRevoked:0,
      unreadableSessions:0,
      failedRevocations:0,
      manualRevocationRequired:true,
    };
    const originConnections={
      installationsFound:1,
      installationsRevoked:0,
      unreadableInstallations:1,
      failedRevocations:0,
      manualRevocationRequired:true,
    };
    assert.deepEqual(await deletionRepository.deleteAppleAccessAndCompleteReceipt({
      ...deletion,
      providerCredentials,
      originConnections,
      completedAt:deleteAt+1,
      expiresAt:deleteAt+601,
    }),{created:true,providerCredentials,originConnections});
    assert.equal(await database.prepare(
      'SELECT 1 FROM origin_possible_installations WHERE owner_id=?',
    ).bind(ownerId).first(),null);
    assert.equal(await repository.ownsInstallation(ownerId,successfulReceipt.installationId),true);
    await assert.rejects(
      repository.claimInstallationFlowLease({authorization,stateHash:failedState,installationId:'inst_01k2ja2000e0080000000000f1',receiptIssuedAt:NOW,now:deleteAt+2}),
      error=>matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS')(error)
        || matchesCode('ORIGIN_FLOW_INVALID')(error),
    );
  }finally{await miniflare.dispose();}
});

test('host Origin callback failure leaves bounded durable cleanup state visible after reload',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1OriginRepository(database);
    const ownerId='host-origin-cleanup-owner',stateHash='s'.repeat(43);
    const authorization={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:null};
    await repository.createFlow({stateHash,ownerId,returnTo:'/',createdAt:NOW,expiresAt:NOW+600,authorizationStartedAt:NOW,appleSubjectHash:null});
    assert.deepEqual(await database.prepare(
      `SELECT apple_principal_id,apple_subject_hash,flow_token
       FROM origin_possible_installations WHERE owner_id=?`,
    ).bind(ownerId).first(),{apple_principal_id:null,apple_subject_hash:null,flow_token:stateHash});
    await repository.claimInstallationFlowLease({authorization,stateHash,installationId:'inst_01k2ja2000e0080000000000h1',receiptIssuedAt:NOW,now:NOW+1});
    assert.notEqual(await repository.consumeFlow(stateHash,ownerId,NOW+1,NOW,null),null);
    await assert.rejects(persistOriginInstallationOrRequireManualCleanup({
      persist:async()=>{throw new OriginAuthError(503,'ORIGIN_INSTALLATION_STORE_UNAVAILABLE','simulated host persistence failure');},
      releaseAuthority:()=>repository.releaseInstallationFlowLease(stateHash),
    }),matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'));
    assert.deepEqual(await createD1OriginRepository(database).readPossibleInstallation(authorization,()=>NOW+2),{acknowledgementId:stateHash});
    assert.equal(await database.prepare(
      'SELECT COUNT(*) AS count FROM origin_possible_installations WHERE owner_id=?',
    ).bind(ownerId).first('count'),1);
    const recoveryState='t'.repeat(43);
    const recoveryReceipt={
      schemaVersion:1,
      appId:'app_01k2ja2000e0080000000000a1',
      installationId:'inst_01k2ja2000e0080000000000h2',
      namespaceId:'ns_01k2ja2000e0080000000000h3',
      receiptId:crypto.randomUUID(),
      installedBy:{id:'user_01k2ja2000e0080000000000h4',email:'private@example.test'},
      issuedAt:NOW+2,
      expiresAt:NOW+302,
    } as OriginInstallationReceipt;
    await assert.rejects(
      repository.createFlow({stateHash:recoveryState,ownerId,returnTo:'/',createdAt:NOW+2,expiresAt:NOW+602,authorizationStartedAt:NOW,appleSubjectHash:null}),
      matchesCode('ORIGIN_MANUAL_CLEANUP_REQUIRED'),
    );
    await repository.acknowledgePossibleInstallation(authorization,stateHash,NOW+2);
    await repository.createFlow({stateHash:recoveryState,ownerId,returnTo:'/',createdAt:NOW+3,expiresAt:NOW+603,authorizationStartedAt:NOW,appleSubjectHash:null});
    await repository.claimInstallationFlowLease({authorization,stateHash:recoveryState,installationId:recoveryReceipt.installationId,receiptIssuedAt:recoveryReceipt.issuedAt,now:NOW+3});
    assert.notEqual(await repository.consumeFlow(recoveryState,ownerId,NOW+3,NOW,null),null);
    await assert.rejects(persistOriginInstallationOrRequireManualCleanup({
      persist:async()=>{throw new OriginAuthError(503,'ORIGIN_INSTALLATION_STORE_UNAVAILABLE','simulated second host persistence failure');},
      releaseAuthority:()=>repository.releaseInstallationFlowLease(recoveryState),
    }),matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'));
    assert.deepEqual(await database.prepare(
      'SELECT flow_token FROM origin_possible_installations WHERE owner_id=?',
    ).bind(ownerId).first(),{flow_token:recoveryState});
    await assert.rejects(
      repository.acknowledgePossibleInstallation(authorization,stateHash,NOW+5),
      matchesCode('ORIGIN_MANUAL_CLEANUP_CHANGED'),
    );
    await repository.acknowledgePossibleInstallation(authorization,recoveryState,NOW+5);
    assert.equal(await createD1OriginRepository(database).readPossibleInstallation(authorization,()=>NOW+5),null);
    await database.prepare('PRAGMA ignore_check_constraints=ON').run();
    await database.prepare(
      `INSERT INTO origin_possible_installations(
        owner_id,scope_id,apple_principal_id,apple_subject_hash,flow_token,marked_at
      ) VALUES(?,'host',NULL,NULL,'invalid',-1)`,
    ).bind(ownerId).run();
    await database.prepare('PRAGMA ignore_check_constraints=OFF').run();
    await assert.rejects(
      createD1OriginRepository(database).readPossibleInstallation(authorization,()=>NOW+6),
      matchesCode('ORIGIN_CLEANUP_STATE_INVALID'),
    );
    await assert.rejects(
      repository.acknowledgePossibleInstallation(authorization,recoveryState,NOW+6),
      matchesCode('ORIGIN_CLEANUP_STATE_INVALID'),
    );
  }finally{await miniflare.dispose();}
});

test('linked Origin cleanup debt remains isolated when another principal is deleted',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1OriginRepository(database);
    const deletionRepository=createD1AppleAccountDeletionRepository(database);
    const ownerId='origin-principal-scoped-debt-owner';
    const subjectA='u'.repeat(43),subjectB='v'.repeat(43);
    const principalA='w'.repeat(43),principalB='x'.repeat(43);
    for(const [subject,principal] of [[subjectA,principalA],[subjectB,principalB]])await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subject,principal,NOW,ownerId,NOW,NOW).run();
    const failFlow=async(subject:string,stateHash:string,installationId:string,at:number)=>{
      const authorization={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subject};
      await repository.createFlow({stateHash,ownerId,returnTo:'/',createdAt:at,expiresAt:at+600,authorizationStartedAt:NOW,appleSubjectHash:subject});
      await repository.claimInstallationFlowLease({authorization,stateHash,installationId,receiptIssuedAt:NOW,now:at+1});
      assert.notEqual(await repository.consumeFlow(stateHash,ownerId,at+1,NOW,subject),null);
      await assert.rejects(persistOriginInstallationOrRequireManualCleanup({
        persist:async()=>{throw new OriginAuthError(503,'ORIGIN_INSTALLATION_STORE_UNAVAILABLE','simulated principal-scoped failure');},
        releaseAuthority:()=>repository.releaseInstallationFlowLease(stateHash),
      }),matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'));
    };
    const stateA='y'.repeat(43),stateB='z'.repeat(43);
    await failFlow(subjectA,stateA,'inst_01k2ja2000e0080000000000p1',NOW+1);
    await failFlow(subjectB,stateB,'inst_01k2ja2000e0080000000000p2',NOW+2);
    assert.deepEqual((await database.prepare(
      `SELECT scope_id,flow_token FROM origin_possible_installations
       WHERE owner_id=? ORDER BY scope_id`,
    ).bind(ownerId).all()).results,[
      {scope_id:principalA,flow_token:stateA},
      {scope_id:principalB,flow_token:stateB},
    ]);

    const deletion={
      ownerId,
      appleSubjectHash:subjectA,
      deleteOwnerData:false,
      ownerBinding:'A'.repeat(43),
      deletionKeyHash:'B'.repeat(43),
      revocationLeaseToken:'C'.repeat(43),
      startedAt:NOW+10,
      leaseClaimedAt:NOW+10,
      expiresAt:NOW+610,
    };
    assert.equal(await deletionRepository.beginAppleAccountDeletion(deletion),null);
    const providerCredentials={credentialsFound:0,credentialsRevoked:0,unreadableSessions:0,failedRevocations:0,manualRevocationRequired:true};
    const originConnections={installationsFound:1,installationsRevoked:0,unreadableInstallations:1,failedRevocations:0,manualRevocationRequired:true};
    assert.deepEqual(await deletionRepository.deleteAppleAccessAndCompleteReceipt({
      ...deletion,
      providerCredentials,
      originConnections,
      completedAt:NOW+11,
      expiresAt:NOW+611,
    }),{created:true,providerCredentials,originConnections});
    assert.deepEqual(await database.prepare(
      `SELECT scope_id,flow_token FROM origin_possible_installations WHERE owner_id=?`,
    ).bind(ownerId).first(),{scope_id:principalB,flow_token:stateB});
    assert.deepEqual(await repository.readPossibleInstallation({
      userId:ownerId,
      authorizationStartedAt:NOW,
      appleSubjectHash:subjectB,
    },()=>NOW+12),{acknowledgementId:stateB});
  }finally{await miniflare.dispose();}
});

test('Apple credential review token advances across recovery auth and rejects stale acknowledgement',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1AppleOwnerExternalOperationLeaseRepository(database);
    const ownerId='apple-credential-review-owner';
    const subject='D'.repeat(43),principal='E'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subject,principal,NOW,ownerId,NOW,NOW).run();
    const authorization={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subject};
    const attemptA='F'.repeat(43),attemptB='G'.repeat(43);
    await repository.claim({authorization,operationKind:'apple-auth',resourceId:subject,leaseToken:attemptA,now:NOW+1});
    await repository.markPossibleCredential(attemptA,NOW+1);
    await repository.release(attemptA);
    assert.deepEqual(await readD1ApplePossibleCredentialReview(database,authorization,NOW+2),{
      acknowledgementId:attemptA,
      markedAt:NOW+1,
    });

    await database.prepare(
      `CREATE TRIGGER reject_apple_review_rotation
       BEFORE UPDATE OF review_token ON apple_auth_possible_credentials
       BEGIN SELECT RAISE(IGNORE); END`,
    ).run();
    await assert.rejects(
      repository.claim({authorization,operationKind:'apple-auth',resourceId:subject,leaseToken:attemptB,now:NOW+3}),
      matchesExternalCode('APPLE_OWNER_EXTERNAL_OPERATION_LEASE_UNAVAILABLE'),
    );
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_owner_external_operation_leases WHERE lease_token=?',
    ).bind(attemptB).first(),null);
    assert.deepEqual(await readD1ApplePossibleCredentialReview(database,authorization,NOW+3),{
      acknowledgementId:attemptA,
      markedAt:NOW+1,
    });
    await database.prepare('DROP TRIGGER reject_apple_review_rotation').run();

    await repository.claim({authorization,operationKind:'apple-auth',resourceId:subject,leaseToken:attemptB,now:NOW+3});
    await repository.markPossibleCredential(attemptB,NOW+3);
    assert.deepEqual(await database.prepare(
      `SELECT attempt_token,review_token,credential_state,marked_at
       FROM apple_auth_possible_credentials WHERE owner_id=? AND apple_principal_id=?`,
    ).bind(ownerId,principal).first(),{
      attempt_token:attemptA,
      review_token:attemptB,
      credential_state:'possible',
      marked_at:NOW+1,
    });
    await assert.rejects(
      acknowledgeD1ApplePossibleCredentialReview(database,authorization,attemptA,NOW+3),
      matchesExternalCode('APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED'),
    );
    await repository.complete(attemptB,NOW+4);
    assert.deepEqual(await readD1ApplePossibleCredentialReview(database,authorization,NOW+4),{
      acknowledgementId:attemptB,
      markedAt:NOW+1,
    });
    await assert.rejects(
      acknowledgeD1ApplePossibleCredentialReview(database,authorization,attemptA,NOW+4),
      matchesExternalCode('APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED'),
    );
    await acknowledgeD1ApplePossibleCredentialReview(database,authorization,attemptB,NOW+4);
    assert.equal(await readD1ApplePossibleCredentialReview(database,authorization,NOW+4),null);
    await database.prepare('PRAGMA ignore_check_constraints=ON').run();
    await database.prepare(
      `INSERT INTO apple_auth_possible_credentials(
        owner_id,apple_principal_id,apple_subject_hash,attempt_token,review_token,credential_state,marked_at
      ) VALUES(?,?,?,?,?,'possible',-1)`,
    ).bind(ownerId,principal,subject,'H'.repeat(43),'invalid').run();
    await database.prepare('PRAGMA ignore_check_constraints=OFF').run();
    await assert.rejects(
      readD1ApplePossibleCredentialReview(database,authorization,NOW+5),
      matchesExternalCode('APPLE_AUTH_CREDENTIAL_REVIEW_STATE_INVALID'),
    );
    await assert.rejects(
      acknowledgeD1ApplePossibleCredentialReview(database,authorization,'H'.repeat(43),NOW+5),
      matchesExternalCode('APPLE_AUTH_CREDENTIAL_REVIEW_STATE_INVALID'),
    );
  }finally{await miniflare.dispose();}
});

test('verified principal merge waits for active authority and rotates every cleanup acknowledgement',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const authRepository=createD1AppleAuthRepository(database);
    const leaseRepository=createD1AppleOwnerExternalOperationLeaseRepository(database);
    const originRepository=createD1OriginRepository(database);
    const ownerId='principal-merge-lease-owner';
    const subjectA='1'.repeat(43),subjectB='2'.repeat(43);
    const principalA='3'.repeat(43),principalB='4'.repeat(43);
    for(const [subject,principal] of [[subjectA,principalA],[subjectB,principalB]])await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subject,principal,NOW,ownerId,NOW,NOW).run();
    await database.prepare(
      `INSERT INTO apple_auth_possible_credentials(
        owner_id,apple_principal_id,apple_subject_hash,attempt_token,review_token,credential_state,marked_at
      ) VALUES(?,?,?,?,?,?,?),(?,?,?,?,?,?,?)`,
    ).bind(
      ownerId,principalA,subjectA,'5'.repeat(43),'5'.repeat(43),'possible',NOW,
      ownerId,principalB,subjectB,'6'.repeat(43),'6'.repeat(43),'possible',NOW+1,
    ).run();
    await database.prepare(
      `INSERT INTO origin_possible_installations(
        owner_id,scope_id,apple_principal_id,apple_subject_hash,flow_token,marked_at
      ) VALUES(?,?,?,?,?,?),(?,?,?,?,?,?)`,
    ).bind(
      ownerId,principalA,principalA,subjectA,'O'.repeat(43),NOW,
      ownerId,principalB,principalB,subjectB,'Q'.repeat(43),NOW+1,
    ).run();
    await database.prepare(
      `INSERT INTO apple_owner_external_operation_leases(
        lease_token,owner_id,operation_kind,resource_id,apple_subject_hash,
        apple_principal_id,claimed_at,expires_at
      ) VALUES(?,?,?,?,?,?,?,?)`,
    ).bind('7'.repeat(43),ownerId,'github','owner/repository',subjectB,principalB,NOW,NOW+300).run();
    const merge=()=>authRepository.resolveAppleIdentityGroup({
      appleSubjectHashes:[subjectA,subjectB],
      proposedOwnerId:ownerId,
      requiredOwnerId:ownerId,
      createdAt:NOW,
      updatedAt:NOW+2,
    },NOW);
    await assert.rejects(merge(),matchesAppleCode('APPLE_IDENTITY_EXTERNAL_OPERATION_IN_PROGRESS'));
    assert.deepEqual(await database.prepare(
      'SELECT principal_id FROM apple_identity_links WHERE apple_subject_hash=?',
    ).bind(subjectB).first(),{principal_id:principalB});
    await database.prepare(
      'DELETE FROM apple_owner_external_operation_leases WHERE lease_token=?',
    ).bind('7'.repeat(43)).run();
    assert.deepEqual(await merge(),{kind:'linked',ownerId,principalId:principalA,created:false});
    const mergedAppleDebt=await database.prepare(
      `SELECT apple_principal_id,apple_subject_hash,attempt_token,review_token,credential_state
       FROM apple_auth_possible_credentials WHERE owner_id=?`,
    ).bind(ownerId).first() as {
      apple_principal_id:string;
      apple_subject_hash:string;
      attempt_token:string;
      review_token:string;
      credential_state:string;
    }|null;
    assert.ok(mergedAppleDebt);
    const {review_token:mergedAppleReviewToken,...mergedAppleFields}=mergedAppleDebt;
    assert.deepEqual(mergedAppleFields,{
      apple_principal_id:principalA,
      apple_subject_hash:subjectA,
      attempt_token:'5'.repeat(43),
      credential_state:'possible',
    });
    assert.equal(mergedAppleReviewToken.length,43);
    assert.equal(['5'.repeat(43),'6'.repeat(43)].includes(mergedAppleReviewToken),false);
    assert.equal(await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_auth_possible_credentials WHERE owner_id=?',
    ).bind(ownerId).first('count'),1);
    const mergedOriginDebt=await database.prepare(
      `SELECT scope_id,apple_principal_id,apple_subject_hash,flow_token
       FROM origin_possible_installations WHERE owner_id=?`,
    ).bind(ownerId).first() as {
      scope_id:string;
      apple_principal_id:string;
      apple_subject_hash:string;
      flow_token:string;
    }|null;
    assert.ok(mergedOriginDebt);
    const {flow_token:mergedOriginReviewToken,...mergedOriginFields}=mergedOriginDebt;
    assert.deepEqual(mergedOriginFields,{
      scope_id:principalA,
      apple_principal_id:principalA,
      apple_subject_hash:subjectA,
    });
    assert.equal(mergedOriginReviewToken.length,43);
    assert.equal(['O'.repeat(43),'Q'.repeat(43)].includes(mergedOriginReviewToken),false);
    for(const staleToken of ['5'.repeat(43),'6'.repeat(43)])await assert.rejects(
      acknowledgeD1ApplePossibleCredentialReview(
        database,
        {userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subjectA},
        staleToken,
        NOW+3,
      ),
      matchesExternalCode('APPLE_AUTH_CREDENTIAL_REVIEW_CHANGED'),
    );
    for(const staleToken of ['O'.repeat(43),'Q'.repeat(43)])await assert.rejects(
      originRepository.acknowledgePossibleInstallation(
        {userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subjectA},
        staleToken,
        NOW+3,
      ),
      matchesCode('ORIGIN_MANUAL_CLEANUP_CHANGED'),
    );
    await leaseRepository.claim({
      authorization:{userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subjectA},
      operationKind:'apple-auth',
      resourceId:'apple-authentication',
      leaseToken:'8'.repeat(43),
      now:NOW+3,
    });
    await assert.rejects(leaseRepository.claim({
      authorization:{userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subjectB},
      operationKind:'apple-auth',
      resourceId:'apple-authentication',
      leaseToken:'9'.repeat(43),
      now:NOW+3,
    }),error=>error instanceof AppleOwnerExternalOperationError
      && error.code==='APPLE_OWNER_EXTERNAL_OPERATION_LEASE_UNAVAILABLE');
  }finally{await miniflare.dispose();}
});

test('uncertain Origin callback completion never removes a locally saved installation',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1OriginRepository(database);
    const deletionRepository=createD1AppleAccountDeletionRepository(database);
    const ownerId='origin-post-write-fence-owner';
    const subject='u'.repeat(43),principal='v'.repeat(43),stateHash='t'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subject,principal,NOW,ownerId,NOW,NOW).run();
    const authorization={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subject};
    await repository.createFlow({
      stateHash,
      ownerId,
      returnTo:'/',
      createdAt:NOW+1,
      expiresAt:NOW+601,
      authorizationStartedAt:NOW,
      appleSubjectHash:subject,
    });
    await repository.claimInstallationFlowLease({authorization,stateHash,installationId:'inst_01k2ja2000e0080000000000f1',receiptIssuedAt:NOW,now:NOW+2});
    assert.notEqual(await repository.consumeFlow(stateHash,ownerId,NOW+2,NOW,subject),null);
    let signalWriteCommitted!:()=>void,releaseWrite!:()=>void;
    const writeCommitted=new Promise<void>(resolve=>{signalWriteCommitted=resolve;});
    const writeReleased=new Promise<void>(resolve=>{releaseWrite=resolve;});
    const pausedDatabase={
      prepare(query:string){return database.prepare(query);},
      async batch(statements:D1PreparedStatement[]){
        const result=await database.batch(statements);
        signalWriteCommitted();
        await writeReleased;
        return result;
      },
    } as D1Database;
    const pausedRepository=createD1OriginRepository(pausedDatabase);
    const callbackReceipt={
      schemaVersion:1,
      appId:'app_01k2ja2000e0080000000000a1',
      installationId:'inst_01k2ja2000e0080000000000f1',
      namespaceId:'ns_01k2ja2000e0080000000000p3',
      receiptId:crypto.randomUUID(),
      installedBy:{id:'user_01k2ja2000e0080000000000c3',email:'private@example.test'},
      issuedAt:NOW,
      expiresAt:NOW+300,
    } as OriginInstallationReceipt;
    const providerRemovals=0;
    const callback=persistOriginInstallationOrRequireManualCleanup({
      persist:()=>pausedRepository.saveInstallationAndCompleteFlow({
        ownerId,
        stateHash,
        receipt:callbackReceipt,
        now:NOW+3,
        authorizationStartedAt:NOW,
        appleSubjectHash:subject,
      }),
      releaseAuthority:()=>repository.releaseInstallationFlowLease(stateHash),
    });
    await writeCommitted;
    assert.equal(await repository.ownsInstallation(ownerId,callbackReceipt.installationId),true);
    assert.equal(await deletionRepository.beginAppleAccountDeletion({
      ownerId,
      appleSubjectHash:subject,
      deleteOwnerData:false,
      ownerBinding:'c'.repeat(43),
      deletionKeyHash:'d'.repeat(43),
      revocationLeaseToken:'e'.repeat(43),
      startedAt:NOW+4,
      leaseClaimedAt:NOW+4,
      expiresAt:NOW+604,
    }),null);
    releaseWrite();
    await assert.rejects(callback,matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'));
    assert.equal(providerRemovals,0);
    assert.equal(await repository.ownsInstallation(ownerId,callbackReceipt.installationId),true);
  }finally{await miniflare.dispose();}
});

test('cross-owner Origin re-consent conflict preserves the previously connected installation',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1OriginRepository(database);
    const ownerA='origin-existing-owner',ownerB='origin-reconsent-owner';
    const subjectA='1'.repeat(43),subjectB='2'.repeat(43);
    for(const [owner,subject,principal] of [
      [ownerA,subjectA,'3'.repeat(43)],
      [ownerB,subjectB,'4'.repeat(43)],
    ])await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subject,principal,NOW,owner,NOW,NOW).run();
    const sharedReceipt={
      schemaVersion:1,
      appId:'app_01k2ja2000e0080000000000a1',
      installationId:'inst_01k2ja2000e0080000000000x1',
      namespaceId:'ns_01k2ja2000e0080000000000p3',
      receiptId:crypto.randomUUID(),
      installedBy:{id:'user_01k2ja2000e0080000000000c3',email:'private@example.test'},
      issuedAt:NOW+1,
      expiresAt:NOW+300,
    } as OriginInstallationReceipt;
    await repository.saveInstallation(ownerA,{
      ...sharedReceipt,
      receiptId:crypto.randomUUID(),
      issuedAt:NOW,
    } as OriginInstallationReceipt,NOW,NOW,subjectA);
    const stateHash='5'.repeat(43);
    await repository.createFlow({
      stateHash,
      ownerId:ownerB,
      returnTo:'/',
      createdAt:NOW+1,
      expiresAt:NOW+601,
      authorizationStartedAt:NOW,
      appleSubjectHash:subjectB,
    });
    const authorization={userId:ownerB,authorizationStartedAt:NOW,appleSubjectHash:subjectB};
    await repository.claimInstallationFlowLease({authorization,stateHash,installationId:sharedReceipt.installationId,receiptIssuedAt:sharedReceipt.issuedAt,now:NOW+2});
    assert.notEqual(await repository.consumeFlow(stateHash,ownerB,NOW+2,NOW,subjectB),null);
    await assert.rejects(persistOriginInstallationOrRequireManualCleanup({
      persist:()=>repository.saveInstallationAndCompleteFlow({
        ownerId:ownerB,
        stateHash,
        receipt:sharedReceipt,
        now:NOW+3,
        authorizationStartedAt:NOW,
        appleSubjectHash:subjectB,
      }),
      releaseAuthority:()=>repository.releaseInstallationFlowLease(stateHash),
    }),matchesCode('ORIGIN_INSTALLATION_COMPENSATION_REQUIRED'));
    assert.deepEqual(await database.prepare(
      'SELECT owner_id FROM origin_installations WHERE installation_id=?',
    ).bind(sharedReceipt.installationId).first(),{owner_id:ownerA});
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM origin_possible_installations WHERE owner_id=?',
    ).bind(ownerB).first(),null);
    assert.equal(await database.prepare(
      `SELECT 1 FROM apple_owner_external_operation_leases
       WHERE lease_token=? AND operation_kind='origin-install'`,
    ).bind(stateHash).first(),null);
  }finally{await miniflare.dispose();}
});

test('Origin callback and disconnect share global installation authority and a final state fence',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1OriginRepository(database);
    const ownerA='origin-global-owner-a',ownerB='origin-global-owner-b';
    const subjectA='a'.repeat(43),subjectB='b'.repeat(43);
    for(const [owner,subject,principal] of [
      [ownerA,subjectA,'c'.repeat(43)],
      [ownerB,subjectB,'d'.repeat(43)],
    ])await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subject,principal,NOW,owner,NOW,NOW).run();
    const receipt={
      schemaVersion:1,
      appId:'app_01k2ja2000e0080000000000a1',
      installationId:'inst_01k2ja2000e0080000000000g1',
      namespaceId:'ns_01k2ja2000e0080000000000g2',
      receiptId:crypto.randomUUID(),
      installedBy:{id:'user_01k2ja2000e0080000000000g3',email:'private@example.test'},
      issuedAt:NOW,
      expiresAt:NOW+600,
    } as OriginInstallationReceipt;
    await repository.saveInstallation(ownerA,receipt,NOW,NOW,subjectA);
    const authorizationA={userId:ownerA,authorizationStartedAt:NOW,appleSubjectHash:subjectA};
    const authorizationB={userId:ownerB,authorizationStartedAt:NOW,appleSubjectHash:subjectB};

    const callbackFirstState='e'.repeat(43);
    const callbackFirstReceipt={...receipt,receiptId:crypto.randomUUID(),issuedAt:NOW+1} as OriginInstallationReceipt;
    await repository.createFlow({stateHash:callbackFirstState,ownerId:ownerB,returnTo:'/',createdAt:NOW+1,expiresAt:NOW+601,authorizationStartedAt:NOW,appleSubjectHash:subjectB});
    await repository.claimInstallationFlowLease({authorization:authorizationB,stateHash:callbackFirstState,installationId:receipt.installationId,receiptIssuedAt:callbackFirstReceipt.issuedAt,now:NOW+2});
    await assert.rejects(repository.claimExternalOperationLease({
      authorization:authorizationA,
      installationId:receipt.installationId,
      leaseToken:'f'.repeat(43),
      now:NOW+2,
    }),matchesCode('ORIGIN_EXTERNAL_OPERATION_LEASE_UNAVAILABLE'));
    assert.equal(await repository.ownsInstallation(ownerA,receipt.installationId),true);
    await repository.releaseInstallationFlowLease(callbackFirstState);
    await repository.acknowledgePossibleInstallation(authorizationB,callbackFirstState,NOW+3);

    const disconnectToken='g'.repeat(43);
    await repository.claimExternalOperationLease({authorization:authorizationA,installationId:receipt.installationId,leaseToken:disconnectToken,now:NOW+3});
    const disconnectFirstState='h'.repeat(43);
    const disconnectCallbackIssuedAt=NOW+2;
    await repository.createFlow({stateHash:disconnectFirstState,ownerId:ownerB,returnTo:'/',createdAt:NOW+3,expiresAt:NOW+603,authorizationStartedAt:NOW,appleSubjectHash:subjectB});
    await assert.rejects(repository.claimInstallationFlowLease({
      authorization:authorizationB,
      stateHash:disconnectFirstState,
      installationId:receipt.installationId,
      receiptIssuedAt:disconnectCallbackIssuedAt,
      now:NOW+4,
    }),matchesCode('ORIGIN_EXTERNAL_OPERATION_IN_PROGRESS'));
    assert.equal(await repository.deleteInstallation(ownerA,receipt.installationId,NOW+4,NOW,subjectA),true);
    await repository.completeExternalOperationLease(disconnectToken,NOW+4);
    assert.equal(await repository.ownsInstallation(ownerA,receipt.installationId),false);
    await assert.rejects(repository.claimInstallationFlowLease({
      authorization:authorizationB,
      stateHash:disconnectFirstState,
      installationId:receipt.installationId,
      receiptIssuedAt:disconnectCallbackIssuedAt,
      now:NOW+5,
    }),matchesCode('ORIGIN_INSTALLATION_RECEIPT_STALE'));
    await repository.releaseInstallationFlowLease(disconnectFirstState);
    await repository.acknowledgePossibleInstallation(authorizationB,disconnectFirstState,NOW+5);
    const reconnectState='l'.repeat(43);
    const reconnectReceipt={
      ...receipt,
      receiptId:crypto.randomUUID(),
      issuedAt:NOW+65,
      expiresAt:NOW+365,
    } as OriginInstallationReceipt;
    await repository.createFlow({stateHash:reconnectState,ownerId:ownerB,returnTo:'/',createdAt:NOW+65,expiresAt:NOW+665,authorizationStartedAt:NOW,appleSubjectHash:subjectB});
    await repository.claimInstallationFlowLease({authorization:authorizationB,stateHash:reconnectState,installationId:receipt.installationId,receiptIssuedAt:reconnectReceipt.issuedAt,now:NOW+65});
    assert.notEqual(await repository.consumeFlow(reconnectState,ownerB,NOW+65,NOW,subjectB),null);
    assert.equal((await repository.saveInstallationAndCompleteFlow({
      ownerId:ownerB,
      stateHash:reconnectState,
      receipt:reconnectReceipt,
      now:NOW+65,
      authorizationStartedAt:NOW,
      appleSubjectHash:subjectB,
    })).installationId,receipt.installationId);
    const exactRetryState='m'.repeat(43);
    await repository.createFlow({stateHash:exactRetryState,ownerId:ownerB,returnTo:'/',createdAt:NOW+66,expiresAt:NOW+666,authorizationStartedAt:NOW,appleSubjectHash:subjectB});
    await assert.rejects(repository.claimInstallationFlowLease({
      authorization:authorizationB,
      stateHash:exactRetryState,
      installationId:receipt.installationId,
      receiptIssuedAt:reconnectReceipt.issuedAt,
      now:NOW+66,
    }),matchesCode('ORIGIN_INSTALLATION_RECEIPT_STALE'));
    await repository.releaseInstallationFlowLease(exactRetryState);
    await repository.acknowledgePossibleInstallation(authorizationB,exactRetryState,NOW+66);
    const crossOwnerStaleState='n'.repeat(43);
    await repository.createFlow({stateHash:crossOwnerStaleState,ownerId:ownerA,returnTo:'/',createdAt:NOW+67,expiresAt:NOW+667,authorizationStartedAt:NOW,appleSubjectHash:subjectA});
    await assert.rejects(repository.claimInstallationFlowLease({
      authorization:authorizationA,
      stateHash:crossOwnerStaleState,
      installationId:receipt.installationId,
      receiptIssuedAt:NOW+64,
      now:NOW+67,
    }),matchesCode('ORIGIN_INSTALLATION_RECEIPT_STALE'));
    await repository.releaseInstallationFlowLease(crossOwnerStaleState);
    await repository.acknowledgePossibleInstallation(authorizationA,crossOwnerStaleState,NOW+67);
    await assert.rejects(
      repository.deleteInstallation(ownerB,receipt.installationId,Number.MAX_SAFE_INTEGER-30,NOW,subjectB),
      /Origin disconnect receipt fence time is invalid/,
    );
    assert.equal(await repository.ownsInstallation(ownerB,receipt.installationId),true);
    assert.match(
      await readFile('app/api/origin/callback/route.ts','utf8'),
      /claimInstallationFlowLease[\s\S]*requireOriginReadOnlyInstallation[\s\S]*saveInstallationAndCompleteFlow/,
    );

    const readReceipt={...receipt,installationId:'inst_01k2ja2000e0080000000000g5',receiptId:crypto.randomUUID(),issuedAt:NOW+5} as OriginInstallationReceipt;
    await repository.saveInstallation(ownerA,readReceipt,NOW+5,NOW,subjectA);
    let signalReadStarted!:()=>void,releaseRead!:()=>void;
    const readStarted=new Promise<void>(resolve=>{signalReadStarted=resolve;});
    const readReleased=new Promise<void>(resolve=>{releaseRead=resolve;});
    const stagedRead=withD1OriginExternalOperationLease({
      repository,
      authorization:authorizationA,
      installationId:readReceipt.installationId,
      crypto,
      now:()=>NOW+6,
      operation:async()=>{signalReadStarted();await readReleased;return 'repositories';},
    });
    await readStarted;
    let competingDisconnectEffects=0;
    await assert.rejects(withD1OriginExternalOperationLease({
      repository,
      authorization:authorizationA,
      installationId:readReceipt.installationId,
      crypto,
      now:()=>NOW+7,
      operation:async()=>{competingDisconnectEffects+=1;},
    }),matchesCode('ORIGIN_EXTERNAL_OPERATION_LEASE_UNAVAILABLE'));
    assert.equal(competingDisconnectEffects,0);
    releaseRead();
    assert.equal(await stagedRead,'repositories');
    await withD1OriginExternalOperationLease({
      repository,
      authorization:authorizationA,
      installationId:readReceipt.installationId,
      crypto,
      now:()=>NOW+8,
      operation:async incarnation=>{
        const absence=await repository.deleteInstallationForIncarnation(authorizationA,incarnation,NOW+8);
        return {absence};
      },
      completionState:result=>({kind:'absent',absence:result.absence}),
    });
    assert.equal(await repository.ownsInstallation(ownerA,readReceipt.installationId),false);

    const fenceOwner='origin-callback-fence-owner',fenceSubject='i'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(fenceSubject,'j'.repeat(43),NOW,fenceOwner,NOW,NOW).run();
    const fenceAuthorization={userId:fenceOwner,authorizationStartedAt:NOW,appleSubjectHash:fenceSubject};
    const fenceState='k'.repeat(43);
    const fenceReceipt={...receipt,installationId:'inst_01k2ja2000e0080000000000g4',receiptId:crypto.randomUUID()} as OriginInstallationReceipt;
    await repository.createFlow({stateHash:fenceState,ownerId:fenceOwner,returnTo:'/',createdAt:NOW+10,expiresAt:NOW+610,authorizationStartedAt:NOW,appleSubjectHash:fenceSubject});
    await repository.claimInstallationFlowLease({authorization:fenceAuthorization,stateHash:fenceState,installationId:fenceReceipt.installationId,receiptIssuedAt:fenceReceipt.issuedAt,now:NOW+11});
    assert.notEqual(await repository.consumeFlow(fenceState,fenceOwner,NOW+11,NOW,fenceSubject),null);
    let signalFinalFence!:()=>void,releaseFinalFence!:()=>void;
    const finalFenceStarted=new Promise<void>(resolve=>{signalFinalFence=resolve;});
    const finalFenceReleased=new Promise<void>(resolve=>{releaseFinalFence=resolve;});
    const pausedDatabase={
      prepare(query:string){
        const statement=database.prepare(query);
        if(!query.includes('resource_operation.resource_id=?'))return statement;
        return{
          bind(...values:unknown[]){
            const bound=statement.bind(...values);
            return{
              async first(column?:string){
                signalFinalFence();
                await finalFenceReleased;
                return column===undefined?bound.first():bound.first(column);
              },
            } as D1PreparedStatement;
          },
        } as D1PreparedStatement;
      },
      batch(statements:D1PreparedStatement[]){return database.batch(statements);},
    } as D1Database;
    const callbackSave=createD1OriginRepository(pausedDatabase).saveInstallationAndCompleteFlow({
      ownerId:fenceOwner,
      stateHash:fenceState,
      receipt:fenceReceipt,
      now:NOW+12,
      authorizationStartedAt:NOW,
      appleSubjectHash:fenceSubject,
    });
    await finalFenceStarted;
    await withD1OriginExternalOperationLease({
      repository,
      authorization:fenceAuthorization,
      installationId:fenceReceipt.installationId,
      crypto,
      now:()=>NOW+13,
      operation:async incarnation=>{
        const absence=await repository.deleteInstallationForIncarnation(fenceAuthorization,incarnation,NOW+13);
        return {absence};
      },
      completionState:result=>({kind:'absent',absence:result.absence}),
    });
    releaseFinalFence();
    await assert.rejects(callbackSave,matchesCode('ORIGIN_INSTALLATION_STATE_CHANGED'));
    assert.equal(await repository.ownsInstallation(fenceOwner,fenceReceipt.installationId),false);
  }finally{await miniflare.dispose();}
});

test('Origin completion and dashboard reads reject delete-reconnect ABA for one installation ID',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1OriginRepository(database);
    const ownerId='origin-installation-aba-owner';
    const authorization={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:null};
    const receipt=(installationId:string,namespaceId:string,issuedAt:number)=>({
      schemaVersion:1,
      appId:'app_01k2ja2000e0080000000000a1',
      installationId,
      namespaceId,
      receiptId:crypto.randomUUID(),
      installedBy:{id:'user_01k2ja2000e0080000000000c3',email:'private@example.test'},
      issuedAt,
      expiresAt:issuedAt+300,
    }) as OriginInstallationReceipt;

    const readInstallationId='inst_01k2ja2000e0080000000000u1';
    const readA=receipt(readInstallationId,'ns_01k2ja2000e0080000000000u2',NOW);
    await repository.saveInstallation(ownerId,readA,NOW,NOW,null);
    let signalProviderRead!:()=>void,releaseProviderRead!:()=>void;
    const providerReadStarted=new Promise<void>(resolve=>{signalProviderRead=resolve;});
    const providerReadReleased=new Promise<void>(resolve=>{releaseProviderRead=resolve;});
    let providerReadClock=NOW+1;
    let admittedReadIncarnation!:Parameters<typeof repository.deleteInstallationForIncarnation>[1];
    const stagedProviderRead=withD1OriginExternalOperationLease({
      repository,
      authorization,
      installationId:readInstallationId,
      crypto,
      now:()=>providerReadClock,
      operation:async incarnation=>{
        admittedReadIncarnation=incarnation;
        signalProviderRead();
        await providerReadReleased;
        return 'stale repositories';
      },
    });
    await providerReadStarted;
    assert.equal(await repository.deleteInstallation(ownerId,readInstallationId,NOW+2,NOW,null),true);
    const readB=receipt(readInstallationId,'ns_01k2ja2000e0080000000000u3',NOW+63);
    await repository.saveInstallation(ownerId,readB,NOW+63,NOW,null);
    await assert.rejects(
      repository.deleteInstallationForIncarnation(authorization,admittedReadIncarnation,NOW+64),
      matchesCode('ORIGIN_INSTALLATION_STATE_CHANGED'),
    );
    assert.equal(await repository.ownsInstallation(ownerId,readInstallationId),true);
    providerReadClock=NOW+64;
    releaseProviderRead();
    await assert.rejects(stagedProviderRead,matchesCode('ORIGIN_INSTALLATION_STATE_CHANGED'));

    const disconnectInstallationId='inst_01k2ja2000e0080000000000v1';
    const disconnectA=receipt(disconnectInstallationId,'ns_01k2ja2000e0080000000000v2',NOW+100);
    await repository.saveInstallation(ownerId,disconnectA,NOW+100,NOW,null);
    let disconnectClock=NOW+101;
    const stagedDisconnect=withD1OriginExternalOperationLease({
      repository,
      authorization,
      installationId:disconnectInstallationId,
      crypto,
      now:()=>disconnectClock,
      operation:async incarnation=>{
        const absence=await repository.deleteInstallationForIncarnation(authorization,incarnation,NOW+102);
        const disconnectB=receipt(disconnectInstallationId,'ns_01k2ja2000e0080000000000v3',NOW+163);
        await repository.saveInstallation(ownerId,disconnectB,NOW+163,NOW,null);
        assert.equal(await repository.deleteInstallation(ownerId,disconnectInstallationId,NOW+164,NOW,null),true);
        disconnectClock=NOW+165;
        return {absence};
      },
      completionState:result=>({kind:'absent',absence:result.absence}),
    });
    await assert.rejects(stagedDisconnect,matchesCode('ORIGIN_INSTALLATION_DISCONNECT_UNCERTAIN'));

    const dashboardInstallationId='inst_01k2ja2000e0080000000000w1';
    const dashboardA=receipt(dashboardInstallationId,'ns_01k2ja2000e0080000000000w2',NOW+200);
    await repository.saveInstallation(ownerId,dashboardA,NOW+200,NOW,null);
    let signalDashboardRead!:()=>void,releaseDashboardRead!:()=>void;
    const dashboardReadStarted=new Promise<void>(resolve=>{signalDashboardRead=resolve;});
    const dashboardReadReleased=new Promise<void>(resolve=>{releaseDashboardRead=resolve;});
    let pauseFirstDashboardRead=true;
    const pausedDatabase={
      prepare(query:string){
        const statement=database.prepare(query);
        if(!query.includes('FROM origin_installations AS installation'))return statement;
        return{
          bind(...values:unknown[]){
            const bound=statement.bind(...values);
            return{
              async all(){
                const result=await bound.all();
                if(pauseFirstDashboardRead){
                  pauseFirstDashboardRead=false;
                  signalDashboardRead();
                  await dashboardReadReleased;
                }
                return result;
              },
            } as D1PreparedStatement;
          },
        } as D1PreparedStatement;
      },
      batch(statements:D1PreparedStatement[]){return database.batch(statements);},
    } as D1Database;
    const pausedRepository=createD1OriginRepository(pausedDatabase);
    let dashboardClock=NOW+201;
    const stagedDashboard=pausedRepository.readDashboardState(authorization,()=>dashboardClock);
    await dashboardReadStarted;
    assert.equal(await repository.deleteInstallation(ownerId,dashboardInstallationId,NOW+202,NOW,null),true);
    const dashboardB=receipt(dashboardInstallationId,'ns_01k2ja2000e0080000000000w3',NOW+263);
    await repository.saveInstallation(ownerId,dashboardB,NOW+263,NOW,null);
    dashboardClock=NOW+264;
    releaseDashboardRead();
    await assert.rejects(stagedDashboard,matchesCode('ORIGIN_DASHBOARD_STATE_CHANGED'));
  }finally{await miniflare.dispose();}
});

test('verified destructive notification fences access while an admitted Origin lease drains',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const originRepository=createD1OriginRepository(database);
    const authRepository=createD1AppleAuthRepository(database);
    const deletionRepository=createD1AppleAccountDeletionRepository(database);
    const ownerId='notification-lease-drain-owner';
    const subject='6'.repeat(43),principal='7'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subject,principal,NOW,ownerId,NOW,NOW).run();
    const receipt={
      schemaVersion:1,
      appId:'app_01k2ja2000e0080000000000a1',
      installationId:'inst_01k2ja2000e0080000000000n1',
      namespaceId:'ns_01k2ja2000e0080000000000n2',
      receiptId:crypto.randomUUID(),
      installedBy:{id:'user_01k2ja2000e0080000000000n3',email:'private@example.test'},
      issuedAt:NOW,
      expiresAt:NOW+300,
    } as OriginInstallationReceipt;
    await originRepository.saveInstallation(ownerId,receipt,NOW,NOW,subject);
    const sessionHash='8'.repeat(43),ownerBinding='9'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_auth_sessions(
        schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
        encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
      ) VALUES(2,?,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      sessionHash,
      ownerId,
      ownerBinding,
      subject,
      `v2.${'a'.repeat(16)}.${'b'.repeat(32)}`,
      NOW,
      NOW+600,
      NOW,
    ).run();
    const authorization={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subject};
    const admittedLease='A'.repeat(43);
    await originRepository.claimExternalOperationLease({
      authorization,
      installationId:receipt.installationId,
      leaseToken:admittedLease,
      now:NOW+1,
    });
    const notification={
      kind:'consent-revoked' as const,
      notificationIdHash:'B'.repeat(43),
      appleSubjectHash:subject,
      issuedAt:NOW+2,
      eventTime:NOW+2,
      receiptExpiresAt:NOW+602,
    };
    await assert.rejects(applyVerifiedAppleServerNotification({
      repository:deletionRepository,
      notification,
      crypto,
      now:NOW+2,
      completionNow:()=>NOW+2,
      authDependencies:null,
      originDependencies:null,
    }),matchesAppleCode('APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS'));
    assert.notEqual(await database.prepare(
      `SELECT 1 FROM apple_account_deletions
       WHERE deletion_key_hash=? AND revocation_lease_token IS NULL`,
    ).bind(notification.notificationIdHash).first(),null);
    assert.equal(await authRepository.readSession(sessionHash,NOW+2),null);
    await assert.rejects(originRepository.claimExternalOperationLease({
      authorization,
      installationId:receipt.installationId,
      leaseToken:'C'.repeat(43),
      now:NOW+2,
    }),matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));

    await originRepository.releaseExternalOperationLease(admittedLease);
    assert.deepEqual(await applyVerifiedAppleServerNotification({
      repository:deletionRepository,
      notification,
      crypto,
      now:NOW+3,
      completionNow:()=>NOW+3,
      authDependencies:null,
      originDependencies:null,
    }),{idempotent:true});
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_identity_links WHERE apple_subject_hash=?',
    ).bind(subject).first(),null);
    assert.equal(await authRepository.readSession(sessionHash,NOW+3),null);
    assert.equal(await originRepository.ownsInstallation(ownerId,receipt.installationId),true);
    assert.notEqual(await deletionRepository.readDeletionReceipt(
      notification.notificationIdHash,
      NOW+3,
    ),null);
  }finally{await miniflare.dispose();}
});

test('completed explicit deletion makes an earlier pending notification retry idempotent',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1AppleAccountDeletionRepository(database);
    const ownerId='notification-explicit-race-owner';
    const subject='l'.repeat(43),principal='m'.repeat(43);
    await database.prepare(
      `INSERT INTO apple_identity_links(
        apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
      ) VALUES(?,?,?,?,?,?)`,
    ).bind(subject,principal,NOW,ownerId,NOW,NOW).run();
    const notificationKey='n'.repeat(43);
    assert.deepEqual(await repository.beginServerNotification({
      kind:'account-deleted',
      notificationIdHash:notificationKey,
      appleSubjectHash:subject,
      issuedAt:NOW+1,
      eventTime:NOW+1,
      receiptExpiresAt:NOW+601,
    },NOW+1),{idempotent:false,ownerId});
    const explicit={
      ownerId,
      appleSubjectHash:subject,
      deleteOwnerData:false,
      ownerBinding:'o'.repeat(43),
      deletionKeyHash:'p'.repeat(43),
      revocationLeaseToken:'q'.repeat(43),
      startedAt:NOW+2,
      leaseClaimedAt:NOW+2,
      expiresAt:NOW+602,
    };
    assert.equal(await repository.beginAppleAccountDeletion(explicit),null);
    const providerCredentials={credentialsFound:0,credentialsRevoked:0,unreadableSessions:0,failedRevocations:0,manualRevocationRequired:true};
    const originConnections={installationsFound:0,installationsRevoked:0,unreadableInstallations:0,failedRevocations:0,manualRevocationRequired:false};
    assert.deepEqual(await repository.deleteAppleAccessAndCompleteReceipt({
      ...explicit,
      providerCredentials,
      originConnections,
      completedAt:NOW+3,
      expiresAt:NOW+603,
    }),{created:true,providerCredentials,originConnections});
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_identity_links WHERE apple_subject_hash=?',
    ).bind(subject).first(),null);
    assert.deepEqual(await database.prepare(
      `SELECT owner_id,origin_connections,origin_unresolved_installation_ids
       FROM apple_auth_notifications WHERE notification_id_hash=?`,
    ).bind(notificationKey).first(),{
      owner_id:null,
      origin_connections:JSON.stringify(originConnections),
      origin_unresolved_installation_ids:null,
    });
    assert.deepEqual(await repository.beginAppleAccountDeletion({
      ownerId,
      appleSubjectHash:subject,
      deleteOwnerData:false,
      ownerBinding:notificationKey,
      deletionKeyHash:notificationKey,
      revocationLeaseToken:'r'.repeat(43),
      startedAt:NOW+1,
      leaseClaimedAt:NOW+4,
      expiresAt:NOW+604,
    }),{ownerBinding:notificationKey,providerCredentials,originConnections});
  }finally{await miniflare.dispose();}
});

test('D1 Origin leases serialize provider side effects with principal deletion and fence staged reads',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1OriginRepository(database);
    const authRepository=createD1AppleAuthRepository(database);
    const deletionRepository=createD1AppleAccountDeletionRepository(database);
    const ownerId='linked-owner-origin-deletion-race';
    const subjectA='a'.repeat(43),subjectAlias='c'.repeat(43),principalA='p'.repeat(43);
    const subjectB='b'.repeat(43),principalB='q'.repeat(43);
    for(const [subject,principal] of [
      [subjectA,principalA],
      [subjectAlias,principalA],
      [subjectB,principalB],
    ]){
      await database.prepare(
        `INSERT INTO apple_identity_links(
          apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
        ) VALUES(?,?,?,?,?,?)`,
      ).bind(subject,principal,NOW,ownerId,NOW,NOW).run();
    }
    await database.prepare(
      `INSERT INTO apple_auth_sessions(
        schema_version,session_hash,owner_id,owner_binding,apple_subject_hash,
        encrypted_credentials,created_at,expires_at,last_validated_at,revoked_at
      ) VALUES(2,?,?,?,?,?,?,?,?,NULL)`,
    ).bind(
      'R'.repeat(43),
      ownerId,
      'T'.repeat(43),
      subjectA,
      `v2.${'a'.repeat(16)}.${'b'.repeat(32)}`,
      NOW,
      NOW+600,
      NOW,
    ).run();
    const receipt={
      schemaVersion:1,
      appId:'app_01k2ja2000e0080000000000a1',
      installationId:INSTALLATION_ID,
      namespaceId:'ns_01k2ja2000e0080000000000p3',
      receiptId:crypto.randomUUID(),
      installedBy:{id:'user_01k2ja2000e0080000000000c3',email:'private@example.test'},
      issuedAt:NOW,
      expiresAt:NOW+300,
    } as OriginInstallationReceipt;
    await repository.saveInstallation(ownerId,receipt,NOW,NOW,subjectA);
    const authorizationA={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subjectA};
    const authorizationB={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subjectB};
    const hostAuthorization={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:null};
    const deletionInput=(subject:string,key:string,lease:string,at:number)=>({
      ownerId,
      appleSubjectHash:subject,
      deleteOwnerData:false,
      ownerBinding:key.toLowerCase().repeat(43),
      deletionKeyHash:key.repeat(43),
      revocationLeaseToken:lease.repeat(43),
      startedAt:at,
      leaseClaimedAt:at,
      expiresAt:at+600,
    });

    let signalProviderStarted!:()=>void,releaseProvider!:()=>void;
    const providerStarted=new Promise<void>(resolve=>{signalProviderStarted=resolve;});
    const providerReleased=new Promise<void>(resolve=>{releaseProvider=resolve;});
    let clock=NOW+1,providerSideEffects=0;
    const providerOperation=withD1OriginExternalOperationLease({
      repository,
      authorization:authorizationA,
      installationId:INSTALLATION_ID,
      crypto,
      now:()=>clock,
      operation:async()=>{
        providerSideEffects+=1;
        signalProviderStarted();
        await providerReleased;
        return 'provider-finished';
      },
    });
    await providerStarted;
    await assert.rejects(
      deletionRepository.beginAppleAccountDeletion(deletionInput(subjectA,'D','L',NOW+2)),
      matchesAppleCode('APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS'),
    );
    await assert.rejects(
      deletionRepository.beginAppleAccountDeletion(deletionInput(subjectAlias,'G','K',NOW+2)),
      matchesAppleCode('APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS'),
    );
    for(const deletionKeyHash of ['D'.repeat(43),'G'.repeat(43)])assert.notEqual(
      await database.prepare(
        'SELECT 1 FROM apple_account_deletions WHERE deletion_key_hash=? AND revocation_lease_token IS NULL',
      ).bind(deletionKeyHash).first(),
      null,
    );
    assert.equal(await authRepository.readSession('R'.repeat(43),NOW+2),null);
    await assert.rejects(
      repository.claimExternalOperationLease({
        authorization:authorizationA,
        installationId:INSTALLATION_ID,
        leaseToken:'S'.repeat(43),
        now:NOW+2,
      }),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    await database.prepare(
      `DELETE FROM apple_account_deletions WHERE deletion_key_hash IN (?,?)`,
    ).bind('D'.repeat(43),'G'.repeat(43)).run();
    const notificationIdHash='J'.repeat(43);
    assert.deepEqual(await deletionRepository.beginServerNotification({
      kind:'account-deleted',
      notificationIdHash,
      appleSubjectHash:subjectAlias,
      issuedAt:NOW+2,
      eventTime:NOW+2,
      receiptExpiresAt:NOW+602,
    },NOW+2),{idempotent:false,ownerId});
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM apple_account_deletions WHERE deletion_key_hash=?',
    ).bind(notificationIdHash).first(),null);
    assert.equal(await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_account_deletions WHERE owner_id=?',
    ).bind(ownerId).first('count'),1);
    await assert.rejects(
      repository.claimExternalOperationLease({
        authorization:authorizationA,
        installationId:INSTALLATION_ID,
        leaseToken:'O'.repeat(43),
        now:NOW+2,
      }),
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    clock=NOW+3;
    releaseProvider();
    await assert.rejects(providerOperation,matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
    assert.equal(providerSideEffects,1);
    assert.equal(await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_owner_external_operation_leases WHERE owner_id=?',
    ).bind(ownerId).first('count'),0);
    await database.prepare(
      'DELETE FROM apple_account_deletions WHERE deletion_key_hash=?',
    ).bind(notificationIdHash).run();
    await database.prepare(
      'DELETE FROM apple_auth_notifications WHERE notification_id_hash=?',
    ).bind(notificationIdHash).run();

    const idempotentLeaseToken='H'.repeat(43);
    const initialLease=await repository.claimExternalOperationLease({
      authorization:hostAuthorization,
      installationId:INSTALLATION_ID,
      leaseToken:idempotentLeaseToken,
      now:NOW+4,
    });
    assert.deepEqual(await repository.claimExternalOperationLease({
      authorization:hostAuthorization,
      installationId:INSTALLATION_ID,
      leaseToken:idempotentLeaseToken,
      now:NOW+5,
    }),initialLease);
    await repository.releaseExternalOperationLease(idempotentLeaseToken);
    await repository.releaseExternalOperationLease(idempotentLeaseToken);

    const expiringLeaseToken='X'.repeat(43);
    const expiringLease=await repository.claimExternalOperationLease({
      authorization:authorizationA,
      installationId:INSTALLATION_ID,
      leaseToken:expiringLeaseToken,
      now:NOW+10,
    });
    assert.equal(expiringLease.expiresAt,NOW+10+ORIGIN_EXTERNAL_OPERATION_LEASE_SECONDS);
    await assert.rejects(
      deletionRepository.beginAppleAccountDeletion(
        deletionInput(subjectA,'E','M',expiringLease.expiresAt-1),
      ),
      matchesAppleCode('APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS'),
    );
    const deletionA=deletionInput(subjectA,'E','M',expiringLease.expiresAt);
    assert.equal(await deletionRepository.beginAppleAccountDeletion(deletionA),null);
    await assert.rejects(
      repository.completeExternalOperationLease(expiringLeaseToken,expiringLease.expiresAt),
      matchesCode('ORIGIN_EXTERNAL_OPERATION_LEASE_EXPIRED'),
    );
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM apple_account_deletions WHERE deletion_key_hash=?',
    ).bind(deletionA.deletionKeyHash).first(),null);
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM apple_owner_external_operation_leases WHERE lease_token=?',
    ).bind(expiringLeaseToken).first(),null);

    let deletionFirstSideEffects=0;
    await assert.rejects(withD1OriginExternalOperationLease({
      repository,
      authorization:authorizationA,
      installationId:INSTALLATION_ID,
      crypto,
      now:()=>expiringLease.expiresAt+1,
      operation:async()=>{deletionFirstSideEffects+=1;},
    }),matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
    assert.equal(deletionFirstSideEffects,0);

    for(const authorization of [hostAuthorization,authorizationB]){
      assert.equal(await withD1OriginExternalOperationLease({
        repository,
        authorization,
        installationId:INSTALLATION_ID,
        crypto,
        now:()=>expiringLease.expiresAt+2,
        operation:async()=>authorization.appleSubjectHash??'host',
      }),authorization.appleSubjectHash??'host');
    }
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_owner_external_operation_leases WHERE lease_token=?',
    ).bind(expiringLeaseToken).first(),null);
    const providerCredentials={
      credentialsFound:0,
      credentialsRevoked:0,
      unreadableSessions:0,
      failedRevocations:0,
      manualRevocationRequired:true,
    };
    const originConnections={
      installationsFound:0,
      installationsRevoked:0,
      unreadableInstallations:0,
      failedRevocations:0,
      manualRevocationRequired:false,
    };
    assert.deepEqual(await deletionRepository.deleteAppleAccessAndCompleteReceipt({
      ...deletionA,
      providerCredentials,
      originConnections,
      completedAt:expiringLease.expiresAt+3,
      expiresAt:expiringLease.expiresAt+603,
    }),{created:true,providerCredentials,originConnections});
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_identity_links WHERE apple_subject_hash=?',
    ).bind(subjectAlias).first(),null);
    assert.equal(await repository.ownsInstallation(ownerId,INSTALLATION_ID),true);

    let signalResponseLeaseReleased!:()=>void,releaseResponseCompletion!:()=>void;
    const responseLeaseReleased=new Promise<void>(resolve=>{signalResponseLeaseReleased=resolve;});
    const responseCompletionReleased=new Promise<void>(resolve=>{releaseResponseCompletion=resolve;});
    const completionFencedRepository={
      ...repository,
      async completeExternalOperationLeaseForIncarnation(
        input:Parameters<typeof repository.completeExternalOperationLeaseForIncarnation>[0],
      ){
        await repository.completeExternalOperationLeaseForIncarnation(input);
        signalResponseLeaseReleased();
        await responseCompletionReleased;
      },
    } satisfies typeof repository;
    let responseClock=expiringLease.expiresAt+4;
    const stagedProviderResponse=withD1OriginExternalOperationLease({
      repository:completionFencedRepository,
      authorization:authorizationB,
      installationId:INSTALLATION_ID,
      crypto,
      now:()=>responseClock,
      operation:async()=>'staged-provider-response',
    });
    await responseLeaseReleased;

    let signalReadStaged!:()=>void,releaseRead!:()=>void;
    const readStaged=new Promise<void>(resolve=>{signalReadStaged=resolve;});
    const readReleased=new Promise<void>(resolve=>{releaseRead=resolve;});
    let pauseInstallationRead=true;
    const pausedDatabase={
      prepare(query:string){
        const statement=database.prepare(query);
        if(!query.includes('FROM origin_installations AS installation'))return statement;
        return{
          bind(...values:unknown[]){
            const bound=statement.bind(...values);
            return{
              async all(){
                const result=await bound.all();
                if(pauseInstallationRead){
                  pauseInstallationRead=false;
                  signalReadStaged();
                  await readReleased;
                }
                return result;
              },
            } as D1PreparedStatement;
          },
        } as D1PreparedStatement;
      },
      batch(statements:D1PreparedStatement[]){return database.batch(statements);},
    } as D1Database;
    const pausedRepository=createD1OriginRepository(pausedDatabase);
    let readClock=responseClock;
    const stagedList=pausedRepository.listInstallations(authorizationB,()=>readClock);
    await readStaged;
    const deletionB=deletionInput(subjectB,'F','N',readClock+1);
    assert.equal(await deletionRepository.beginAppleAccountDeletion(deletionB),null);
    assert.deepEqual(await deletionRepository.deleteAppleAccessAndCompleteReceipt({
      ...deletionB,
      providerCredentials,
      originConnections,
      completedAt:readClock+2,
      expiresAt:readClock+602,
    }),{created:true,providerCredentials,originConnections});
    readClock+=2;
    responseClock=readClock;
    const fencedProviderResponse=assert.rejects(
      stagedProviderResponse,
      matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    const fencedRead=assert.rejects(stagedList,matchesCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
    releaseResponseCompletion();
    releaseRead();
    await fencedProviderResponse;
    await fencedRead;
    assert.equal(await repository.ownsInstallation(ownerId,INSTALLATION_ID),true);
    assert.equal((await repository.listInstallations(hostAuthorization,()=>readClock+1)).length,1);
  }finally{await miniflare.dispose();}
});

test('D1 GitHub leases exclude deletion, expire safely, and fence successful remote effects',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const repository=createD1AppleOwnerExternalOperationLeaseRepository(database);
    const deletionRepository=createD1AppleAccountDeletionRepository(database);
    const ownerId='linked-owner-github-deletion-race';
    const subjectA='d'.repeat(43),subjectAlias='e'.repeat(43),principalA='f'.repeat(43);
    const subjectB='g'.repeat(43),principalB='h'.repeat(43);
    for(const [subject,principal] of [
      [subjectA,principalA],
      [subjectAlias,principalA],
      [subjectB,principalB],
    ]){
      await database.prepare(
        `INSERT INTO apple_identity_links(
          apple_subject_hash,principal_id,principal_created_at,owner_id,created_at,updated_at
        ) VALUES(?,?,?,?,?,?)`,
      ).bind(subject,principal,NOW,ownerId,NOW,NOW).run();
    }
    const authorizationA={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subjectA};
    const authorizationB={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:subjectB};
    const hostAuthorization={userId:ownerId,authorizationStartedAt:NOW,appleSubjectHash:null};
    const resourceId='R'.repeat(43);
    const deletionInput=(subject:string,key:string,lease:string,at:number)=>({
      ownerId,
      appleSubjectHash:subject,
      deleteOwnerData:false,
      ownerBinding:key.toLowerCase().repeat(43),
      deletionKeyHash:key.repeat(43),
      revocationLeaseToken:lease.repeat(43),
      startedAt:at,
      leaseClaimedAt:at,
      expiresAt:at+600,
    });
    const providerCredentials={
      credentialsFound:0,
      credentialsRevoked:0,
      unreadableSessions:0,
      failedRevocations:0,
      manualRevocationRequired:true,
    };
    const originConnections={
      installationsFound:0,
      installationsRevoked:0,
      unreadableInstallations:0,
      failedRevocations:0,
      manualRevocationRequired:false,
    };

    let signalRemoteStarted!:()=>void,releaseRemote!:()=>void;
    const remoteStarted=new Promise<void>(resolve=>{signalRemoteStarted=resolve;});
    const remoteReleased=new Promise<void>(resolve=>{releaseRemote=resolve;});
    let clock=NOW+1,remoteSideEffects=0;
    const remoteOperation=withD1AppleOwnerExternalOperationLease({
      repository,
      authorization:authorizationA,
      operationKind:'github',
      resourceId,
      crypto,
      now:()=>clock,
      operation:async()=>{
        remoteSideEffects+=1;
        signalRemoteStarted();
        await remoteReleased;
        return 'github-finished';
      },
    });
    await remoteStarted;
    assert.deepEqual(await database.prepare(
      `SELECT operation_kind,resource_id,apple_subject_hash,apple_principal_id
       FROM apple_owner_external_operation_leases WHERE owner_id=?`,
    ).bind(ownerId).first(),{
      operation_kind:'github',
      resource_id:resourceId,
      apple_subject_hash:subjectA,
      apple_principal_id:principalA,
    });
    await assert.rejects(
      deletionRepository.beginAppleAccountDeletion(deletionInput(subjectA,'A','I',NOW+2)),
      matchesAppleCode('APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS'),
    );
    await assert.rejects(
      deletionRepository.beginAppleAccountDeletion(deletionInput(subjectAlias,'B','J',NOW+2)),
      matchesAppleCode('APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS'),
    );
    clock=NOW+3;
    releaseRemote();
    await assert.rejects(remoteOperation,matchesExternalCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
    assert.equal(remoteSideEffects,1);
    await database.prepare(
      `DELETE FROM apple_account_deletions WHERE deletion_key_hash IN (?,?)`,
    ).bind('A'.repeat(43),'B'.repeat(43)).run();

    const idempotentLeaseToken='C'.repeat(43);
    const initialLease=await repository.claim({
      authorization:hostAuthorization,
      operationKind:'github',
      resourceId,
      leaseToken:idempotentLeaseToken,
      now:NOW+4,
    });
    assert.deepEqual(await repository.claim({
      authorization:hostAuthorization,
      operationKind:'github',
      resourceId,
      leaseToken:idempotentLeaseToken,
      now:NOW+5,
    }),initialLease);
    await repository.release(idempotentLeaseToken);
    await repository.release(idempotentLeaseToken);

    const expiringLeaseToken='X'.repeat(43);
    const expiringLease=await repository.claim({
      authorization:authorizationA,
      operationKind:'github',
      resourceId,
      leaseToken:expiringLeaseToken,
      now:NOW+10,
    });
    assert.equal(
      expiringLease.expiresAt,
      NOW+10+APPLE_OWNER_EXTERNAL_OPERATION_LEASE_SECONDS,
    );
    await assert.rejects(
      deletionRepository.beginAppleAccountDeletion(
        deletionInput(subjectA,'D','K',expiringLease.expiresAt-1),
      ),
      matchesAppleCode('APPLE_OWNER_EXTERNAL_OPERATION_IN_PROGRESS'),
    );
    const deletionA=deletionInput(subjectA,'D','K',expiringLease.expiresAt);
    assert.equal(await deletionRepository.beginAppleAccountDeletion(deletionA),null);
    await assert.rejects(
      repository.complete(expiringLeaseToken,expiringLease.expiresAt),
      matchesExternalCode('APPLE_OWNER_EXTERNAL_OPERATION_LEASE_EXPIRED'),
    );
    assert.notEqual(await database.prepare(
      'SELECT 1 FROM apple_owner_external_operation_leases WHERE lease_token=?',
    ).bind(expiringLeaseToken).first(),null);

    let deletionFirstSideEffects=0;
    await assert.rejects(withD1AppleOwnerExternalOperationLease({
      repository,
      authorization:authorizationA,
      operationKind:'github',
      resourceId,
      crypto,
      now:()=>expiringLease.expiresAt+1,
      operation:async()=>{deletionFirstSideEffects+=1;},
    }),matchesExternalCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'));
    assert.equal(deletionFirstSideEffects,0);
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_owner_external_operation_leases WHERE lease_token=?',
    ).bind(expiringLeaseToken).first(),null);
    for(const authorization of [hostAuthorization,authorizationB]){
      assert.equal(await withD1AppleOwnerExternalOperationLease({
        repository,
        authorization,
        operationKind:'github',
        resourceId,
        crypto,
        now:()=>expiringLease.expiresAt+1,
        operation:async()=>authorization.appleSubjectHash??'host',
      }),authorization.appleSubjectHash??'host');
    }
    assert.deepEqual(await deletionRepository.deleteAppleAccessAndCompleteReceipt({
      ...deletionA,
      providerCredentials,
      originConnections,
      completedAt:expiringLease.expiresAt+2,
      expiresAt:expiringLease.expiresAt+602,
    }),{created:true,providerCredentials,originConnections});
    assert.equal(await database.prepare(
      'SELECT 1 FROM apple_identity_links WHERE apple_subject_hash=?',
    ).bind(subjectAlias).first(),null);
    for(const authorization of [hostAuthorization,authorizationB]){
      assert.equal(await withD1AppleOwnerExternalOperationLease({
        repository,
        authorization,
        operationKind:'github',
        resourceId,
        crypto,
        now:()=>expiringLease.expiresAt+3,
        operation:async()=>authorization.appleSubjectHash??'host',
      }),authorization.appleSubjectHash??'host');
    }

    let signalLeaseReleased!:()=>void,releaseCompletion!:()=>void;
    const leaseReleased=new Promise<void>(resolve=>{signalLeaseReleased=resolve;});
    const completionReleased=new Promise<void>(resolve=>{releaseCompletion=resolve;});
    const completionFencedRepository={
      ...repository,
      async complete(leaseToken:string,now:number){
        await repository.complete(leaseToken,now);
        signalLeaseReleased();
        await completionReleased;
      },
    } satisfies typeof repository;
    let responseClock=expiringLease.expiresAt+4;
    let successfulRemoteSideEffects=0;
    const stagedRemoteResponse=withD1AppleOwnerExternalOperationLease({
      repository:completionFencedRepository,
      authorization:authorizationB,
      operationKind:'github',
      resourceId:'S'.repeat(43),
      crypto,
      now:()=>responseClock,
      operation:async()=>{
        successfulRemoteSideEffects+=1;
        return 'staged-github-success';
      },
    });
    await leaseReleased;
    assert.equal(successfulRemoteSideEffects,1);
    const deletionB=deletionInput(subjectB,'E','L',responseClock+1);
    assert.equal(await deletionRepository.beginAppleAccountDeletion(deletionB),null);
    assert.deepEqual(await deletionRepository.deleteAppleAccessAndCompleteReceipt({
      ...deletionB,
      providerCredentials,
      originConnections,
      completedAt:responseClock+2,
      expiresAt:responseClock+602,
    }),{created:true,providerCredentials,originConnections});
    responseClock+=2;
    releaseCompletion();
    await assert.rejects(
      stagedRemoteResponse,
      matchesExternalCode('APPLE_ACCOUNT_DELETION_IN_PROGRESS'),
    );
    assert.equal(await database.prepare(
      'SELECT COUNT(*) AS count FROM apple_owner_external_operation_leases WHERE owner_id=?',
    ).bind(ownerId).first('count'),0);
  }finally{await miniflare.dispose();}
});

test('Origin repository proxy mints credentials just in time and returns only sanitized repository metadata',async()=>{
  const configuration=await configurationFixture();
  const requests:{url:string;method:string;authorization:string|null;contentType:string|null;body:string|null}[]=[];
  const fetcher=async(input:string|URL|Request,init?:RequestInit)=>{
    const url=input instanceof Request?input.url:input.toString();
    const headers=new Headers(init?.headers);requests.push({url,method:init?.method??'GET',authorization:headers.get('authorization'),contentType:headers.get('content-type'),body:typeof init?.body==='string'?init.body:null});
    if(url.endsWith(`/app/installations/${INSTALLATION_ID}`)&&(init?.method??'GET')==='GET')return json(installationFixture());
    if(url.endsWith('/access_tokens'))return json({token:'oit_ephemeral_secret_value',expiresAt:new Date((NOW+240)*1000).toISOString()});
    if(url.includes('/installation/repos?'))return json({repositories:[repositoryFixture()],repoSelectionMode:'selected',nextPageToken:''});
    if(url.endsWith(':syncMirror'))return json({synced:false},202);
    if(url.includes('/app/installations/'))return new Response(null,{status:204});
    return new Response(null,{status:404});
  };
  const listed=await listOriginRepositories({configuration,installationId:INSTALLATION_ID,fetcher,crypto,now:()=>NOW});
  assert.equal(listed.repositories.length,1);assert.equal(listed.repositories[0].cloneUrl,'https://origin.cursor.com/acme/rocket.git');assert.equal(JSON.stringify(listed).includes('oit_ephemeral'),false);
  const listMint=requests.find(item=>item.url.endsWith('/access_tokens'));
  assert.deepEqual(JSON.parse(listMint?.body??'null'),{scopes:['repository:contents:read'],repositoryIds:[]});
  assert.match(listMint?.authorization??'',/^Bearer [^.]+\.[^.]+\.[^.]+$/);

  assert.equal(await syncOriginMirror({configuration,installationId:INSTALLATION_ID,repository:listed.repositories[0],fetcher,crypto,now:()=>NOW}),'pending');
  const syncMint=requests.filter(item=>item.url.endsWith('/access_tokens')).at(-1);
  assert.deepEqual(JSON.parse(syncMint?.body??'null'),{scopes:['repository:contents:read'],repositoryIds:[REPOSITORY_ID]});
  const sync=requests.find(item=>item.url.endsWith('/repos/acme/rocket:syncMirror'));assert.equal(sync?.method,'POST');assert.match(sync?.authorization??'',/^Bearer oit_/);assert.equal(sync?.contentType,'application/json');assert.deepEqual(JSON.parse(sync?.body??'null'),{ref:'refs/heads/main',wait:false});

  await deleteOriginInstallation({configuration,installationId:INSTALLATION_ID,fetcher,crypto,now:()=>NOW});
  const deletion=requests.find(item=>item.method==='DELETE');assert.ok(deletion);assert.match(deletion.authorization??'',/^Bearer [^.]+\.[^.]+\.[^.]+$/);
});

test('Origin repository credentials fail closed before minting unless the live grant is exactly contents read-only',async()=>{
  const configuration=await configurationFixture();
  for(const scopes of [[],['repository:contents:write'],['repository:contents:read','repository:contents:write']]){
    let tokenMinted=false;
    const fetcher=async(input:string|URL|Request)=>{
      const url=input instanceof Request?input.url:input.toString();
      if(url.endsWith(`/app/installations/${INSTALLATION_ID}`))return json({...installationFixture(),scopes});
      if(url.endsWith('/access_tokens')){tokenMinted=true;return json({token:'oit_ephemeral_secret_value',expiresAt:new Date((NOW+240)*1000).toISOString()});}
      return new Response(null,{status:404});
    };
    await assert.rejects(()=>listOriginRepositories({configuration,installationId:INSTALLATION_ID,fetcher,crypto,now:()=>NOW}),matchesCode('ORIGIN_INSTALLATION_SCOPE_REJECTED'));
    assert.equal(tokenMinted,false);
  }
});

test('Origin repository validation accepts current and legacy provider clone paths',async()=>{
  const configuration=await configurationFixture();
  for(const cloneUrl of [
    'https://origin.cursor.com/acme/rocket.git',
    'https://origin.cursor.com/git/acme/rocket.git',
    'https://origin.cursor.com/v2/repositories/opaque_clone_token.git',
    'https://origin.cursor.com/%E7%A0%82%E7%AE%B1/%2Fopaque',
    'https://origin.cursor.com/砂箱/存储库',
    'https://origin.cursor.com/',
  ]){
    const fetcher=async(input:string|URL|Request)=>{
      const url=input instanceof Request?input.url:input.toString();
      if(url.endsWith(`/app/installations/${INSTALLATION_ID}`))return json(installationFixture());
      if(url.endsWith('/access_tokens'))return json({token:'oit_ephemeral_secret_value',expiresAt:new Date((NOW+240)*1000).toISOString()});
      return json({repositories:[{...repositoryFixture(),cloneUrl}],repoSelectionMode:'selected'});
    };
    assert.equal(
      (await listOriginRepositories({configuration,installationId:INSTALLATION_ID,fetcher,crypto,now:()=>NOW})).repositories[0]?.cloneUrl,
      new URL(cloneUrl).toString(),
    );
  }
});

test('Origin repository proxy rejects a clone URL outside the selected Origin repository',async()=>{
  const configuration=await configurationFixture();
  for(const repository of [
    {...repositoryFixture(),cloneUrl:'https://attacker.example/acme/rocket.git'},
    {...repositoryFixture(),cloneUrl:'https://origin.cursor.com:444/acme/rocket.git'},
    {...repositoryFixture(),cloneUrl:'https://origin.cursor.com/acme/rocket.git?token=secret'},
    {...repositoryFixture(),cloneUrl:'https://user@origin.cursor.com/acme/rocket.git'},
    {...repositoryFixture(),defaultBranch:'main\nrefs/heads/injected'},
  ]){
    const fetcher=async(input:string|URL|Request)=>{
      const url=input instanceof Request?input.url:input.toString();
      if(url.endsWith(`/app/installations/${INSTALLATION_ID}`))return json(installationFixture());
      if(url.endsWith('/access_tokens'))return json({token:'oit_ephemeral_secret_value',expiresAt:new Date((NOW+240)*1000).toISOString()});
      return json({repositories:[repository],repoSelectionMode:'selected',nextPageToken:''});
    };
    await assert.rejects(()=>listOriginRepositories({configuration,installationId:INSTALLATION_ID,fetcher,crypto,now:()=>NOW}),matchesCode('ORIGIN_REPOSITORIES_INVALID'));
  }
});

test('Origin mirror proxy rejects a status and response body mismatch',async()=>{
  const configuration=await configurationFixture();
  const fetcher=async(input:string|URL|Request)=>{
    const url=input instanceof Request?input.url:input.toString();
    if(url.endsWith(`/app/installations/${INSTALLATION_ID}`))return json(installationFixture());
    if(url.endsWith('/access_tokens'))return json({token:'oit_ephemeral_secret_value',expiresAt:new Date((NOW+240)*1000).toISOString()});
    if(url.endsWith(':syncMirror'))return json({synced:true},202);
    return new Response(null,{status:404});
  };
  await assert.rejects(()=>syncOriginMirror({configuration,installationId:INSTALLATION_ID,repository:repositoryFixture(),fetcher,crypto,now:()=>NOW}),matchesCode('ORIGIN_MIRROR_INVALID'));
});

async function configurationFixture():Promise<OriginConfiguration>{
  const keys=await crypto.subtle.generateKey({name:'Ed25519'},true,['sign','verify']);
  const raw=new Uint8Array(await crypto.subtle.exportKey('pkcs8',keys.privateKey));
  let base64='';for(const byte of raw)base64+=String.fromCharCode(byte);
  const encoded=btoa(base64).match(/.{1,64}/g)?.join('\n')??'';
  return parseOriginConfiguration({ORIGIN_APP_ID:'app_01k2ja2000e0080000000000a1',ORIGIN_APP_PRIVATE_KEY_PKCS8:`-----BEGIN PRIVATE KEY-----\n${encoded}\n-----END PRIVATE KEY-----\n`,ORIGIN_INSTALL_REDIRECT_URI:'https://sandbox.example.test/api/origin/callback',ORIGIN_INSTALL_SCOPES:'repository:contents:read'});
}

function repositoryFixture():OriginRepository{return {id:REPOSITORY_ID,name:'rocket',fullName:'acme/rocket',owner:{slug:'acme',id:'ns_01k2ja2000e0080000000000p3',type:'team'},defaultBranch:'main',cloneUrl:'https://origin.cursor.com/acme/rocket.git'};}
function installationFixture(){return{id:INSTALLATION_ID,appId:'app_01k2ja2000e0080000000000a1',scopes:['repository:contents:read']};}
function json(value:unknown,status=200){return Response.json(value,{status,headers:{'Content-Type':'application/json'}});}
function matchesCode(code:string){return (error:unknown)=>error instanceof OriginAuthError&&error.code===code;}
function matchesAppleCode(code:string){return (error:unknown)=>error instanceof AppleAuthError&&error.code===code;}
function matchesExternalCode(code:string){return (error:unknown)=>error instanceof AppleOwnerExternalOperationError&&error.code===code;}

async function applyAllMigrations(database:D1Database):Promise<void>{
  for(const name of [
    '0000_dashing_epoch.sql','0001_eager_sheva_callister.sql','0002_shallow_sabra.sql',
    '0003_wet_edwin_jarvis.sql','0004_native_apple_bridge.sql','0005_sync_snapshot_revision.sql',
    '0006_dear_luckman.sql','0007_puzzling_tempest.sql','0008_long_fat_cobra.sql',
    '0009_apple_identity_principals.sql',
    '0010_native_apple_grants.sql',
    '0011_durable_deletion_subjects.sql',
    '0012_owner_external_operation_leases.sql',
    '0013_general_external_operation_leases.sql',
  ]){
    const migration=await readFile(`drizzle/${name}`,'utf8');
    for(const statement of migration.split('--> statement-breakpoint').map(value=>value.trim()).filter(Boolean))await database.prepare(statement).run();
  }
}
