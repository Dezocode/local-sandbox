import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';
import { fileContentSchema, pathSchema } from '../lib/contracts.ts';
import { isAppleOwnerOperationAllowed } from '../lib/apple-auth-owner-d1.ts';
import { applyFileMutationWithFreshVersion, FileVersionD1IntegrityError, maximumFileVersion, readAuthorizedFileWorkspaceSnapshot } from '../lib/workspace-file-d1.ts';

async function applyAllMigrations(database:D1Database):Promise<void>{
  const names=(await readdir(new URL('../drizzle/',import.meta.url))).filter(name=>name.endsWith('.sql')).sort();
  for(const name of names){
    const source=await readFile(new URL(`../drizzle/${name}`,import.meta.url),'utf8');
    for(const statement of source.split('--> statement-breakpoint').map(value=>value.trim()).filter(Boolean))await database.prepare(statement).run();
  }
}

test('D1 file versions never repeat after same-path recreation and stop at the safe integer bound',async()=>{
  const require=createRequire(import.meta.url);
  const wranglerRequire=createRequire(require.resolve('wrangler/package.json'));
  const {Miniflare}=wranglerRequire('miniflare');
  const miniflare=new Miniflare({modules:true,script:'export default {fetch(){return new Response("ok")}}',compatibilityDate:'2026-05-15',compatibilityFlags:['nodejs_compat'],d1Databases:['DB'],log:undefined});
  try{
    const database=await miniflare.getD1Database('DB');
    await applyAllMigrations(database);
    const operationTime=1_800_000_000,userId='file-version-owner';
    const authorization={userId,authorizationStartedAt:operationTime,appleSubjectHash:null};
    const path=pathSchema.parse('workspace/incarnation.txt');
    await database.prepare("INSERT INTO workspaces(user_id,policy,completed,revision) VALUES(?,'{}','[]',0)").bind(userId).run();
    const first=await applyFileMutationWithFreshVersion({kind:'create',database,authorization,operationTime,path,content:fileContentSchema.parse('first')});
    assert.equal(first.kind,'applied');if(first.kind!=='applied')throw Error('expected first file creation');assert.equal(first.file.version,0);
    const saved=await applyFileMutationWithFreshVersion({kind:'save',database,authorization,operationTime,path,content:fileContentSchema.parse('saved'),expectedVersion:first.file.version});
    assert.equal(saved.kind,'applied');if(saved.kind!=='applied')throw Error('expected file save');assert.equal(saved.file.version,1);
    await database.prepare('DELETE FROM files WHERE user_id=? AND path=? AND version=?').bind(userId,path,saved.file.version).run();
    const replacement=await applyFileMutationWithFreshVersion({kind:'create',database,authorization,operationTime,path,content:fileContentSchema.parse('replacement')});
    assert.equal(replacement.kind,'applied');if(replacement.kind!=='applied')throw Error('expected replacement file creation');assert.equal(replacement.file.version,2);
    const delayedSave=await applyFileMutationWithFreshVersion({kind:'save',database,authorization,operationTime,path,content:fileContentSchema.parse('stale'),expectedVersion:saved.file.version});
    assert.deepEqual(delayedSave,{kind:'not-applied'});
    assert.deepEqual(await database.prepare('SELECT content,version FROM files WHERE user_id=? AND path=?').bind(userId,path).first(),{content:'replacement',version:2});
    assert.deepEqual(await database.prepare('SELECT file_clock,file_clock_claim FROM workspaces WHERE user_id=?').bind(userId).first(),{file_clock:2,file_clock_claim:null});

    const racePath=pathSchema.parse('workspace/final-fence.txt');
    const stagedCreate=await applyFileMutationWithFreshVersion({kind:'create',database,authorization,operationTime,path:racePath,content:fileContentSchema.parse('staged create')});
    assert.equal(stagedCreate.kind,'applied');if(stagedCreate.kind!=='applied')throw Error('expected staged create');
    assert.equal(await isAppleOwnerOperationAllowed(database,authorization,operationTime),true,'old owner-only final gate resolves before the pause');
    const changedDuringGate=await applyFileMutationWithFreshVersion({kind:'save',database,authorization,operationTime,path:racePath,content:fileContentSchema.parse('changed during owner gate'),expectedVersion:stagedCreate.file.version});
    assert.equal(changedDuringGate.kind,'applied');if(changedDuringGate.kind!=='applied')throw Error('expected paused save');
    const createFence=await readAuthorizedFileWorkspaceSnapshot({database,authorization,operationTime,path:racePath});
    assert.equal(createFence.kind,'authorized');if(createFence.kind!=='authorized')throw Error('expected authorized file fence');
    assert.deepEqual(createFence.file,changedDuringGate.file);
    assert.notDeepEqual(createFence.file,stagedCreate.file,'a stale applied create cannot pass the joint final file fence');

    const stagedConflict=createFence.file;if(stagedConflict===null)throw Error('expected staged conflict row');
    assert.equal(await isAppleOwnerOperationAllowed(database,authorization,operationTime),true,'conflict readback pauses after the old owner-only gate');
    const changedConflict=await applyFileMutationWithFreshVersion({kind:'save',database,authorization,operationTime,path:racePath,content:fileContentSchema.parse('new conflict winner'),expectedVersion:stagedConflict.version});
    assert.equal(changedConflict.kind,'applied');if(changedConflict.kind!=='applied')throw Error('expected conflict replacement');
    const conflictFence=await readAuthorizedFileWorkspaceSnapshot({database,authorization,operationTime,path:racePath});
    assert.equal(conflictFence.kind,'authorized');if(conflictFence.kind!=='authorized')throw Error('expected authorized conflict fence');
    assert.deepEqual(conflictFence.file,changedConflict.file);
    assert.notDeepEqual(conflictFence.file,stagedConflict,'stale conflict data cannot escape after the pause');

    await database.prepare('DELETE FROM files WHERE user_id=? AND path=? AND version=?').bind(userId,racePath,changedConflict.file.version).run();
    assert.equal(await isAppleOwnerOperationAllowed(database,authorization,operationTime),true,'delete response pauses after the old owner-only gate');
    const recreatedDuringGate=await applyFileMutationWithFreshVersion({kind:'create',database,authorization,operationTime,path:racePath,content:fileContentSchema.parse('recreated during gate')});
    assert.equal(recreatedDuringGate.kind,'applied');if(recreatedDuringGate.kind!=='applied')throw Error('expected paused recreation');
    const deleteFence=await readAuthorizedFileWorkspaceSnapshot({database,authorization,operationTime,path:racePath});
    assert.equal(deleteFence.kind,'authorized');if(deleteFence.kind!=='authorized')throw Error('expected authorized delete fence');
    assert.deepEqual(deleteFence.file,recreatedDuringGate.file,'delete success cannot finalize after same-path recreation');

    const corruptOwner='file-version-corrupt-owner',corruptPath=pathSchema.parse('workspace/corrupt.txt'),corruptAuthorization={userId:corruptOwner,authorizationStartedAt:operationTime,appleSubjectHash:null};
    await database.prepare("INSERT INTO workspaces(user_id,policy,completed,revision,file_clock) VALUES(?,'{}','[]',0,0)").bind(corruptOwner).run();
    await database.prepare('INSERT INTO files(user_id,path,content,version) VALUES(?,?,?,1)').bind(corruptOwner,corruptPath,'clock is behind').run();
    await assert.rejects(()=>readAuthorizedFileWorkspaceSnapshot({database,authorization:corruptAuthorization,operationTime,path:corruptPath}),FileVersionD1IntegrityError);
    await database.prepare('DELETE FROM workspaces WHERE user_id=?').bind(corruptOwner).run();
    await assert.rejects(()=>readAuthorizedFileWorkspaceSnapshot({database,authorization:corruptAuthorization,operationTime,path:corruptPath}),FileVersionD1IntegrityError,'an orphan file cannot become an authorized absence');

    const boundedOwner='file-version-bounded-owner',boundedPath=pathSchema.parse('workspace/bounded.txt');
    const boundedAuthorization={userId:boundedOwner,authorizationStartedAt:operationTime,appleSubjectHash:null};
    await database.prepare("INSERT INTO workspaces(user_id,policy,completed,revision,file_clock) VALUES(?,'{}','[]',0,?)").bind(boundedOwner,maximumFileVersion-1).run();
    await database.prepare('INSERT INTO files(user_id,path,content,version) VALUES(?,?,?,?)').bind(boundedOwner,boundedPath,'before maximum',maximumFileVersion-1).run();
    const maximum=await applyFileMutationWithFreshVersion({kind:'save',database,authorization:boundedAuthorization,operationTime,path:boundedPath,content:fileContentSchema.parse('at maximum'),expectedVersion:maximumFileVersion-1});
    assert.equal(maximum.kind,'applied');if(maximum.kind!=='applied')throw Error('expected maximum safe version');assert.equal(maximum.file.version,maximumFileVersion);
    const exhausted=await applyFileMutationWithFreshVersion({kind:'save',database,authorization:boundedAuthorization,operationTime,path:boundedPath,content:fileContentSchema.parse('must not write'),expectedVersion:maximumFileVersion});
    assert.deepEqual(exhausted,{kind:'not-applied'});
    assert.deepEqual(await database.prepare('SELECT content,version FROM files WHERE user_id=? AND path=?').bind(boundedOwner,boundedPath).first(),{content:'at maximum',version:maximumFileVersion});
    assert.deepEqual(await database.prepare('SELECT file_clock,file_clock_claim FROM workspaces WHERE user_id=?').bind(boundedOwner).first(),{file_clock:maximumFileVersion,file_clock_claim:null});
    await assert.rejects(()=>database.prepare('INSERT INTO files(user_id,path,content,version) VALUES(?,?,?,?)').bind(boundedOwner,'workspace/unsafe.txt','unsafe',maximumFileVersion+1).run());
  }finally{await miniflare.dispose();}
});
