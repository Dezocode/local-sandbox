import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {cp, mkdtemp, readdir, rm} from 'node:fs/promises';
import {join, relative} from 'node:path';
import test from 'node:test';

test('Drizzle 0014 snapshot is schema-complete and future generation is a no-op',async()=>{
  const project=process.cwd();
  const temporary=await mkdtemp(join(project,'.drizzle-noop-'));
  const out=join(temporary,'drizzle');
  try{
    await cp(join(project,'drizzle'),out,{recursive:true});
    const output=execFileSync('pnpm',[
      'exec','drizzle-kit','generate',
      '--dialect=sqlite',
      '--schema=db/schema.ts',
      `--out=${relative(project,out)}`,
      '--name=noop_guard',
    ],{cwd:project,encoding:'utf8'});
    assert.match(output,/No schema changes, nothing to migrate/);
    assert.equal((await readdir(out)).some(name=>name.startsWith('0015_')),false);
  }finally{
    await rm(temporary,{recursive:true,force:true});
  }
});
