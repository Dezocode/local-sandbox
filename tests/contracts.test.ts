import test from 'node:test';
import assert from 'node:assert/strict';
import { pathSchema, exactPatch, policySchema, defaultPolicy, compactContext, shortcutURL, receiptSchema } from '../lib/contracts.ts';

test('sandbox paths reject traversal, encoded paths, empty segments, and absolute roots',()=>{
  for(const path of ['../a','workspace/../config/a','/workspace/a','workspace//a','workspace/%2e%2e/a','workspace/a\\b','state/./a','workspace/a/'])assert.equal(pathSchema.safeParse(path).success,false,path);
  assert.equal(pathSchema.parse('workspace/project/notes.md'),'workspace/project/notes.md');
});
test('exact patches reject absent, duplicate, and overlapping matches',()=>{
  assert.equal(exactPatch('Status: pending','pending','complete'),'Status: complete');
  assert.throws(()=>exactPatch('a a','a','b'),/AMBIGUOUS/);
  assert.throws(()=>exactPatch('aaa','aa','b'),/AMBIGUOUS/);
  assert.throws(()=>exactPatch('a','z','b'),/NOT_FOUND/);
});
test('policy cannot exceed bounded ranges or include hidden authorization keys',()=>{
  assert.equal(policySchema.safeParse({...defaultPolicy,memoryTarget:100}).success,false);
  assert.equal(policySchema.safeParse({...defaultPolicy,maxFailures:99}).success,false);
  assert.equal(policySchema.safeParse({...defaultPolicy,unrestricted:true}).success,false);
  assert.equal(policySchema.parse(defaultPolicy).cloudAllowed,false);
});
test('context compaction cannot grow beyond the configured budget',()=>{
  for(const budget of [2000,6000,12000])assert.ok(compactContext('g'.repeat(3000),'s'.repeat(4000),'x'.repeat(20000),budget).length<=budget);
});
test('shortcut input is encoded as data, not interpreted as extra URL parameters',()=>{
  const input='Edit a&name=Malicious #?\nfile';const url=new URL(shortcutURL('Local Sandbox',input));
  assert.equal(url.protocol,'shortcuts:');assert.equal(url.searchParams.get('name'),'Local Sandbox');assert.equal(url.searchParams.get('text'),input);assert.equal(url.searchParams.getAll('name').length,1);
});
test('receipts require an explicit origin and reject unsupported success states',()=>{
  const base={id:'test',goal:'test',status:'verified',origin:'shortcut',summary:'readback',steps:3,failures:0,durationMs:50,createdAt:new Date().toISOString(),trace:[]};
  assert.equal(receiptSchema.safeParse(base).success,true);
  assert.equal(receiptSchema.safeParse({...base,origin:'iphone-live-unverified'}).success,false);
  assert.equal(receiptSchema.safeParse({...base,status:'probably-done'}).success,false);
});
