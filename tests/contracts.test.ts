import test from 'node:test';
import assert from 'node:assert/strict';
import { assertionEvidenceSchema, pathSchema, exactPatch, policySchema, defaultPolicy, compactContext, shortcutURL, parseReceiptWire, parseReceiptWireBytes, receiptCodePointLength, receiptSchema, receiptSerializedByteCountIsValid, receiptWireContract, fileContentSchema, providerRoutingEvidenceSchema } from '../lib/contracts.ts';
import { shortcuts } from '../lib/catalog.ts';
import { providerHandoffTimeline } from '../lib/provider-handoff.ts';

test('sandbox paths reject traversal, encoded paths, empty segments, and absolute roots',()=>{
  for(const path of ['../a','workspace/../config/a','/workspace/a','workspace//a','workspace/%2e%2e/a','workspace/a\\b','state/./a','workspace/a/'])assert.equal(pathSchema.safeParse(path).success,false,path);
  assert.equal(pathSchema.parse('workspace/project/notes.md'),'workspace/project/notes.md');
});
test('file content uses an exact 64,000-byte UTF-8 contract independent of JSON escaping',()=>{
  assert.equal(fileContentSchema.safeParse('\0'.repeat(64_000)).success,true);
  assert.equal(fileContentSchema.safeParse('\\'.repeat(64_000)).success,true);
  assert.equal(fileContentSchema.safeParse('🔐'.repeat(16_000)).success,true);
  assert.equal(fileContentSchema.safeParse('🔐'.repeat(16_001)).success,false);
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
test('Apple shortcut guidance stops an unavailable run instead of switching providers',()=>{
  const appleShortcut=shortcuts.find(({id})=>id==='apple');
  assert.ok(appleShortcut);
  const guidance=appleShortcut.steps.map(([,detail])=>detail).join(' ');
  assert.match(guidance,/Plan One Step/);
  assert.match(guidance,/stop this run/);
  assert.match(guidance,/Start a new task with an explicitly selected provider/);
  assert.match(guidance,/never switch the active route/);
  assert.doesNotMatch(guidance,/select an approved fallback/);
});
test('receipt verification requires an approved contract and independent passing evidence',()=>{
  const base={id:'test',goal:'test',status:'verified',origin:'shortcut',summary:'readback',steps:3,failures:0,durationMs:50,createdAt:new Date().toISOString(),trace:[]};
  const legacy=receiptSchema.parse(base);
  assert.equal(legacy.status,'completed');
  assert.equal(legacy.legacyTraceOnly,true);
  assert.equal(legacy.goal,'[redacted]');
  assert.equal(receiptSchema.parse(legacy).legacyTraceOnly,true);
  const path='workspace/result.txt';
  const routingEvidence={recordType:'provider-routing-decision',schemaVersion:2,selection:'best-local',provider:'apple',authorizedProvider:'local',strategy:'best-local-measured',activity:'workspace-idle',accessEvidence:'on-device-runtime',deviceProfileSHA256:'c'.repeat(64),configurationSHA256:'d'.repeat(64),qualificationEpochSHA256:'e'.repeat(64),sampleCount:5,distinctProbeCount:5,verifiedCount:5,reliabilityBasisPoints:10000,qualityBasisPoints:10000,medianDurationBucketMilliseconds:500,testedContextCharacters:6000,toolCallingQualified:true,integrityFaultCount:0,automatedReturnQualified:true};
  const current={...base,origin:'native',recordType:'run-receipt',schemaVersion:2,contract:{recordType:'goal-contract',schemaVersion:1,assertions:[{kind:'exactText',path,expected:'done'}]},assertions:[{kind:'exactText',path,folder:null,passed:true,expected:'done',observed:'exact match',observedSHA256:'a'.repeat(64),byteCount:4,checkedAt:new Date().toISOString(),errorCode:null}],provider:'apple',policyDigest:'b'.repeat(64),workspaceID:'workspace-123',environment:{appVersion:'0.3.0',build:'4',os:'iOS',device:'iPhone'},taskOrigin:'app-intent',routingEvidence,legacyTraceOnly:false};
  assert.equal(receiptSchema.safeParse(current).success,true);
  const routed=receiptSchema.parse(current);
  assert.deepEqual(routed.routingEvidence,routingEvidence);
  const recommended={...routingEvidence,selection:'saved',authorizedProvider:'apple',strategy:'oracle-recommendation'};
  assert.deepEqual(receiptSchema.parse({...current,routingEvidence:recommended}).routingEvidence,recommended);
  assert.equal(receiptSchema.safeParse({...current,routingEvidence:{...routingEvidence,provider:'chatgpt'}}).success,false);
  assert.equal(receiptSchema.safeParse({...current,routingEvidence:{...routingEvidence,verifiedCount:6}}).success,false);
  assert.equal(receiptSchema.safeParse({...current,routingEvidence:{...routingEvidence,providerOutput:'private'}}).success,false);
  assert.equal(receiptSchema.safeParse({...current,routingEvidence:{...routingEvidence,strategy:'oracle-recommendation'}}).success,false);
  assert.equal(receiptSchema.safeParse({...current,contract:null}).success,false);
  assert.equal(receiptSchema.safeParse({...current,assertions:[{...current.assertions[0],passed:false}]}).success,false);
  assert.equal(receiptSchema.safeParse({...current,assertions:[{...current.assertions[0],kind:'pathExists'}]}).success,false);
  assert.equal(receiptSchema.safeParse({...current,assertions:[{...current.assertions[0],path:'workspace/other.txt'}]}).success,false);
  assert.equal(receiptSchema.safeParse({...current,assertions:[{...current.assertions[0],expected:'wrong'}]}).success,false);
  assert.equal(receiptSchema.safeParse({...current,assertions:[{...current.assertions[0],errorCode:'UNVERIFIED'}]}).success,false);
  assert.equal(receiptSchema.safeParse({...current,routingEvidence:{...routingEvidence,automatedReturnQualified:false}}).success,false);
  assert.equal(receiptSchema.safeParse({...current,taskOrigin:'app-handoff',routingEvidence:{...routingEvidence,automatedReturnQualified:false}}).success,true);
  assert.equal(receiptSchema.safeParse({...current,status:'completed',legacyTraceOnly:true}).success,false);
  const folder={...current,contract:{recordType:'goal-contract',schemaVersion:1,assertions:[{kind:'folderContains',folder:'workspace',path}]},assertions:[{...current.assertions[0],kind:'folderContains',folder:'workspace',expected:null,observedSHA256:null,byteCount:null}]};
  assert.equal(receiptSchema.safeParse(folder).success,true);
  assert.equal(receiptSchema.safeParse({...folder,assertions:[{...folder.assertions[0],folder:'output'}]}).success,false);
  assert.equal(receiptSchema.safeParse({...base,origin:'iphone-live-unverified'}).success,false);
  assert.equal(receiptSchema.safeParse({...base,status:'probably-done'}).success,false);
});

test('receipt wire contract shares scalar, datetime, and raw/canonical byte boundaries',()=>{
  const current=(createdAt='2026-09-11T12:34:56Z')=>({
    recordType:'run-receipt',schemaVersion:2,id:'wire',goal:'goal',status:'completed',origin:'cloud-sandbox',summary:'done',steps:0,failures:0,durationMs:1,createdAt,trace:[],
    contract:null,assertions:[],provider:null,policyDigest:null,workspaceID:null,environment:null,taskOrigin:null,routingEvidence:null,legacyTraceOnly:false,
  });
  assert.equal(receiptCodePointLength('🙂'),1);
  assert.equal(receiptCodePointLength('e\u0301'),2);
  assert.equal(receiptCodePointLength('👨‍👩‍👧‍👦'),7);
  assert.equal(receiptSchema.safeParse({...current(),summary:'🙂'.repeat(3_000)}).success,true);
  assert.equal(receiptSchema.safeParse({...current(),summary:'🙂'.repeat(3_001)}).success,false);
  assert.equal(receiptSchema.safeParse({...current(),summary:'e\u0301'.repeat(1_500)}).success,true);
  assert.equal(receiptSchema.safeParse({...current(),summary:'e\u0301'.repeat(1_501)}).success,false);

  const validDates=['0000-02-29T00:00:00Z','2000-02-29T23:59:59Z','2024-02-29T23:59:59Z','2026-09-11T12:34:56.123456789Z','2026-09-11T12:34:56+00:00','2026-09-11T12:34:56-23:59','2026-09-11T12:34:56z'];
  const invalidDates=['1900-02-29T12:34:56Z','2023-02-29T12:34:56Z','2026-00-11T12:34:56Z','2026-13-11T12:34:56Z','2026-04-31T12:34:56Z','2026-09-00T12:34:56Z','2026-09-11T24:34:56Z','2026-09-11T12:60:56Z','2026-09-11T12:34:60Z','2026-09-11T12:34Z','2026-09-11T12:34:56.1234567890Z','2026-09-11T12:34:56+24:00','2026-09-11T12:34:56+00:60','2026-09-11t12:34:56Z'];
  for(const date of validDates){
    assert.equal(receiptSchema.safeParse(current(date)).success,true,date);
    assert.equal(assertionEvidenceSchema.safeParse({kind:'pathExists',path:'workspace/a',folder:null,passed:true,expected:null,observed:null,observedSHA256:null,byteCount:null,checkedAt:date,errorCode:null}).success,true,date);
  }
  for(const date of invalidDates){
    assert.equal(receiptSchema.safeParse(current(date)).success,false,date);
    assert.equal(assertionEvidenceSchema.safeParse({kind:'pathExists',path:'workspace/a',folder:null,passed:true,expected:null,observed:null,observedSHA256:null,byteCount:null,checkedAt:date,errorCode:null}).success,false,date);
  }

  const safeDetail=JSON.stringify({recordType:'trace-metadata',schemaVersion:1,resultKind:'legacy-redacted',sha256:null,byteCount:0,readbackKind:null,errorCode:null});
  const maximumShape=receiptSchema.parse({
    ...current('2026-09-11T12:34:56.123456789+00:00'),id:'i'.repeat(80),goal:'🙂'.repeat(2_000),summary:'🙂'.repeat(3_000),steps:100,failures:100,durationMs:86_400_000,
    trace:Array.from({length:100},()=>({tool:'🛠'.repeat(100),status:'ok',detail:safeDetail})),
    workspaceID:'w'.repeat(80),environment:{appVersion:'📱'.repeat(40),build:'📱'.repeat(40),os:'📱'.repeat(100),device:'📱'.repeat(100)},
  });
  const maximumShapeBytes=new TextEncoder().encode(JSON.stringify(maximumShape)).byteLength;
  assert.ok(maximumShapeBytes>64_000);
  assert.ok(maximumShapeBytes<=128_000);

  const control='\0',maximumPath=`workspace/${'a'.repeat(170)}`,maximumHash='a'.repeat(64);
  const maximumAssertions=Array.from({length:20},()=>({kind:'sha256' as const,path:maximumPath,expected:maximumHash}));
  const maximumPersistedShortcut=receiptSchema.parse({
    ...current('2026-09-11T12:34:56.123456789+23:59'),id:control.repeat(80),goal:control.repeat(2_000),origin:'shortcut',summary:control.repeat(3_000),steps:100,failures:100,durationMs:86_400_000,
    trace:Array.from({length:100},()=>({tool:control.repeat(100),status:'skipped',detail:control.repeat(1_000),evidence:{path:maximumPath,sha256:maximumHash,byteCount:64_000,readbackKind:control.repeat(40),contentComplete:true}})),
    contract:{recordType:'goal-contract',schemaVersion:1,assertions:maximumAssertions},
    assertions:maximumAssertions.map(assertion=>({kind:assertion.kind,path:assertion.path,folder:null,passed:false,expected:assertion.expected,observed:null,observedSHA256:maximumHash,byteCount:64_000,checkedAt:'2026-09-11T12:34:56.123456789+23:59',errorCode:'A'.repeat(80)})),
    provider:'chatgpt',policyDigest:maximumHash,workspaceID:control.repeat(80),environment:{appVersion:control.repeat(40),build:control.repeat(40),os:control.repeat(100),device:control.repeat(100)},taskOrigin:'app-handoff',
    routingEvidence:{recordType:'provider-routing-decision',schemaVersion:2,selection:'chatgpt',provider:'chatgpt',authorizedProvider:'local',strategy:'explicit-pinned',activity:'workspace-idle',accessEvidence:'recent-locally-validated-response',deviceProfileSHA256:maximumHash,configurationSHA256:maximumHash,qualificationEpochSHA256:maximumHash,sampleCount:5,distinctProbeCount:5,verifiedCount:5,reliabilityBasisPoints:10_000,qualityBasisPoints:10_000,medianDurationBucketMilliseconds:300_000,testedContextCharacters:12_000,toolCallingQualified:true,integrityFaultCount:0,automatedReturnQualified:true},legacyTraceOnly:false,
  });
  const maximumPersistedShortcutBytes=new TextEncoder().encode(JSON.stringify(maximumPersistedShortcut)).byteLength;
  assert.ok(maximumPersistedShortcutBytes>128_000);
  assert.ok(maximumPersistedShortcutBytes<=receiptWireContract.maximumSerializedUTF8Bytes);

  const fullExpected='x'.repeat(64_000);
  const fixedAssertions=Array.from({length:14},(_,index)=>({kind:'exactText' as const,path:`workspace/full-${index}.txt`,expected:fullExpected}));
  const exactCapCandidate=(tailLength:number,summary:string)=>{
    const assertions=[...fixedAssertions,{kind:'exactText' as const,path:'workspace/tail.txt',expected:'x'.repeat(tailLength)}];
    return {...current(),summary,contract:{recordType:'goal-contract' as const,schemaVersion:1 as const,assertions},assertions:assertions.map(assertion=>({kind:assertion.kind,path:assertion.path,folder:null,passed:true,expected:assertion.expected,observed:null,observedSHA256:null,byteCount:new TextEncoder().encode(assertion.expected).byteLength,checkedAt:'2026-09-11T12:34:56Z',errorCode:null}))};
  };
  let minimumTail=0,maximumTail=64_000;
  while(minimumTail<maximumTail){
    const candidate=Math.ceil((minimumTail+maximumTail)/2);
    if(new TextEncoder().encode(JSON.stringify(exactCapCandidate(candidate,''))).byteLength<=receiptWireContract.maximumSerializedUTF8Bytes)minimumTail=candidate;
    else maximumTail=candidate-1;
  }
  const tailLength=minimumTail;
  const almostExact=exactCapCandidate(tailLength,'');
  const almostExactBytes=new TextEncoder().encode(JSON.stringify(almostExact)).byteLength;
  const exactCanonical=exactCapCandidate(tailLength,'s'.repeat(receiptWireContract.maximumSerializedUTF8Bytes-almostExactBytes));
  assert.equal(new TextEncoder().encode(JSON.stringify(exactCanonical)).byteLength,receiptWireContract.maximumSerializedUTF8Bytes);
  const parsedExactCanonical=receiptSchema.parse(exactCanonical);
  assert.equal(receiptSerializedByteCountIsValid(new TextEncoder().encode(JSON.stringify(parsedExactCanonical)).byteLength),true);
  assert.equal(receiptSchema.safeParse({...exactCanonical,summary:exactCanonical.summary+'s'}).success,false);

  assert.equal(receiptSerializedByteCountIsValid(receiptWireContract.maximumSerializedUTF8Bytes),true);
  assert.equal(receiptSerializedByteCountIsValid(receiptWireContract.maximumSerializedUTF8Bytes+1),false);
  const compact=JSON.stringify(current());
  const compactBytes=new TextEncoder().encode(compact).byteLength;
  const exactRaw=compact+' '.repeat(receiptWireContract.maximumSerializedUTF8Bytes-compactBytes);
  assert.equal(new TextEncoder().encode(exactRaw).byteLength,receiptWireContract.maximumSerializedUTF8Bytes);
  assert.equal(parseReceiptWire(exactRaw).id,'wire');
  assert.throws(()=>parseReceiptWire(exactRaw+' '),/exceeds/);
  assert.throws(()=>parseReceiptWireBytes(Uint8Array.of(0xc3,0x28)),/UTF-8/);
  assert.throws(()=>parseReceiptWire(compact.replace('"status":"completed"','"status":"completed","status":"blocked"')),/duplicate/);
  assert.throws(()=>parseReceiptWire(compact.replace('"provider":null','"provider":null,"\\u0070rovider":"chatgpt"')),/duplicate/);
  const environmentJSON=JSON.stringify({...current(),environment:{appVersion:'0.3.0',build:'1',os:'iOS',device:'iPhone'}});
  assert.throws(()=>parseReceiptWire(environmentJSON.replace('"device":"iPhone"','"device":"iPhone","\\u0064evice":"iPad"')),/duplicate/);
  assert.throws(()=>parseReceiptWire('{"recordType":'),/valid unambiguous JSON/);
  assert.throws(()=>parseReceiptWire(`${'['.repeat(receiptWireContract.maximumJSONDepth+1)}0${']'.repeat(receiptWireContract.maximumJSONDepth+1)}`),/depth/);
  assert.throws(()=>parseReceiptWire(`[${Array.from({length:receiptWireContract.maximumJSONMembers+1},()=>0).join(',')}]`),/member limit/);
});

test('provider routing evidence normalizes legacy access wording and rejects impossible states',()=>{
  const hash='a'.repeat(64);
  const measured={
    recordType:'provider-routing-decision',schemaVersion:2,selection:'chatgpt',provider:'chatgpt',authorizedProvider:'apple',strategy:'explicit-pinned',activity:'workspace-idle',accessEvidence:'recent-locally-validated-response',
    deviceProfileSHA256:hash,configurationSHA256:'b'.repeat(64),qualificationEpochSHA256:'c'.repeat(64),sampleCount:5,distinctProbeCount:5,verifiedCount:4,reliabilityBasisPoints:10000,qualityBasisPoints:8000,
    medianDurationBucketMilliseconds:500,testedContextCharacters:6000,toolCallingQualified:true,integrityFaultCount:0,automatedReturnQualified:true,
  };
  assert.deepEqual(providerRoutingEvidenceSchema.parse(measured),measured);
  const saved={...measured,selection:'saved',authorizedProvider:'chatgpt',strategy:'saved-pinned'};
  assert.deepEqual(providerRoutingEvidenceSchema.parse(saved),saved);
  const normalized=providerRoutingEvidenceSchema.parse({...measured,accessEvidence:'recent-successful-round-trip'});
  assert.equal(normalized.accessEvidence,'recent-locally-validated-response');
  assert.doesNotMatch(JSON.stringify(normalized),/recent-successful-round-trip/);

  const zeroSample={
    recordType:'provider-routing-decision',schemaVersion:2,selection:'apple',provider:'apple',authorizedProvider:'local',strategy:'explicit-pinned',activity:'workspace-idle',accessEvidence:'on-device-runtime',
    deviceProfileSHA256:hash,configurationSHA256:'b'.repeat(64),sampleCount:0,distinctProbeCount:0,verifiedCount:0,toolCallingQualified:false,integrityFaultCount:0,automatedReturnQualified:false,
  };
  assert.equal(providerRoutingEvidenceSchema.safeParse(zeroSample).success,false);
  const invalidCases:[string,unknown][]=[
    ['non-idle native activity',{...measured,activity:'native-run-active'}],
    ['non-idle pending response',{...measured,activity:'provider-response-pending'}],
    ['external zero-sample explicit route',{...zeroSample,selection:'local',provider:'local',accessEvidence:'configured-unmeasured'}],
    ['external zero-sample Saved route',{...zeroSample,selection:'saved',provider:'claude',strategy:'saved-pinned',accessEvidence:'unavailable'}],
    ['explicit provider mismatch',{...measured,provider:'claude'}],
    ['Best Local cloud provider',{...measured,selection:'best-local',strategy:'best-local-measured'}],
    ['Saved selection with explicit strategy',{...measured,selection:'saved'}],
    ['Apple claiming external response evidence',{...measured,selection:'apple',provider:'apple'}],
    ['external provider claiming Apple runtime',{...measured,accessEvidence:'on-device-runtime'}],
    ['response evidence without a passing assertion',{...measured,accessEvidence:'recent-locally-validated-response',verifiedCount:0,qualityBasisPoints:0,testedContextCharacters:0,toolCallingQualified:false}],
    ['zero samples with qualification metrics',{...zeroSample,qualificationEpochSHA256:'c'.repeat(64),reliabilityBasisPoints:0,qualityBasisPoints:0,medianDurationBucketMilliseconds:500,testedContextCharacters:0}],
    ['zero samples with qualified tools',{...zeroSample,toolCallingQualified:true}],
    ['measured samples without an epoch',{...measured,qualificationEpochSHA256:undefined}],
    ['quality inconsistent with exact assertion passes',{...measured,qualityBasisPoints:10000}],
    ['reliability not representable by whole samples',{...measured,reliabilityBasisPoints:9000}],
    ['schema passes fewer than assertion passes',{...measured,reliabilityBasisPoints:6000}],
    ['validated response without tested context',{...measured,testedContextCharacters:0}],
    ['qualified tools without three passing probes',{...measured,verifiedCount:2,qualityBasisPoints:4000,toolCallingQualified:true}],
    ['external route below 80 percent assertions',{...measured,verifiedCount:3,qualityBasisPoints:6000,toolCallingQualified:true}],
    ['external route below 80 percent schema reliability',{...measured,reliabilityBasisPoints:6000}],
    ['external route below 2,000 tested context characters',{...measured,testedContextCharacters:1999}],
    ['external route without qualified tools',{...measured,toolCallingQualified:false}],
    ['route without all five probe types',{...measured,distinctProbeCount:4}],
    ['route with an integrity fault',{...measured,integrityFaultCount:1}],
    ['fully measured external route marked configured but unmeasured',{...measured,accessEvidence:'configured-unmeasured'}],
    ['underqualified external Saved route',{...measured,selection:'saved',strategy:'saved-pinned',verifiedCount:3,qualityBasisPoints:6000,toolCallingQualified:true}],
    ['measured Best Local route below five samples',{...measured,selection:'best-local',provider:'local',strategy:'best-local-measured',sampleCount:4,verifiedCount:4,qualityBasisPoints:10000}],
    ['underqualified Oracle recommendation',{...measured,selection:'saved',strategy:'oracle-recommendation',verifiedCount:3,qualityBasisPoints:6000,toolCallingQualified:true}],
    ['external Oracle recommendation without local response evidence',{...measured,selection:'saved',strategy:'oracle-recommendation',accessEvidence:'configured-unmeasured'}],
    ['unknown evidence field',{...measured,providerLoginVerified:true}],
  ];
  for(const [name,value] of invalidCases)assert.equal(providerRoutingEvidenceSchema.safeParse(value).success,false,name);
});

test('provider handoff timeline accepts only ordered, stable, hash-only round trips that match receipt state',()=>{
  const hash='a'.repeat(64);
  const adapterHash='b'.repeat(64);
  const event=(direction:'outbound'|'inbound',actionIndex:number,provider:'local'|'chatgpt'='local',adapterSHA256=adapterHash)=>JSON.stringify(direction==='outbound'
    ?{recordType:'provider-handoff',schemaVersion:2,direction,transport:'app-shortcut',provider,selection:'best-local',origin:'app-intent',adapterSHA256,actionIndex,promptSHA256:hash}
    :{recordType:'provider-handoff',schemaVersion:2,direction,transport:'app-shortcut',provider,selection:'best-local',origin:'app-intent',adapterSHA256,actionIndex,responseSHA256:hash});
  const receipt=(trace:{tool:string;status:'ok'|'error';detail:string;evidence?:unknown}[],status:'verified'|'completed'|'blocked'|'cancelled'='completed',steps=2,provider:'local'|'chatgpt'='local',taskOrigin:'app-intent'|'app-handoff'='app-intent')=>receiptSchema.parse({
    recordType:'run-receipt',schemaVersion:2,id:`timeline-${status}-${steps}`,goal:'route',status,origin:'shortcut',summary:'done',steps,failures:0,durationMs:5,createdAt:new Date().toISOString(),trace,
    contract:null,assertions:[],provider,policyDigest:hash,workspaceID:'workspace-123',environment:{appVersion:'0.3.0',build:'1',os:'iOS',device:'iPhone'},taskOrigin,
    routingEvidence:{recordType:'provider-routing-decision',schemaVersion:2,selection:provider==='local'?'best-local':'chatgpt',provider,authorizedProvider:'apple',strategy:provider==='local'?'best-local-measured':'explicit-pinned',activity:'workspace-idle',accessEvidence:'recent-locally-validated-response',deviceProfileSHA256:hash,configurationSHA256:'c'.repeat(64),qualificationEpochSHA256:'d'.repeat(64),sampleCount:5,distinctProbeCount:5,verifiedCount:5,reliabilityBasisPoints:10000,qualityBasisPoints:10000,medianDurationBucketMilliseconds:500,testedContextCharacters:6000,toolCallingQualified:true,integrityFaultCount:0,automatedReturnQualified:true},legacyTraceOnly:false,
  });
  const entry=(direction:'outbound'|'inbound',actionIndex:number,provider:'local'|'chatgpt'='local')=>({tool:`provider.handoff.${direction}`,status:'ok' as const,detail:event(direction,actionIndex,provider)});

  const complete=providerHandoffTimeline(receipt([entry('outbound',0),entry('inbound',0),entry('outbound',1),entry('inbound',1)]));
  assert.equal(complete.kind,'valid');
  if(complete.kind==='valid'){
    assert.equal(complete.completeRoundTrips,2);
    assert.equal(complete.pendingOutbound,null);
    assert.deepEqual(complete.events.map(value=>`${value.direction}-${value.actionIndex}`),['outbound-0','inbound-0','outbound-1','inbound-1']);
  }

  const outboundOnly=providerHandoffTimeline(receipt([entry('outbound',0)],'cancelled',0));
  assert.equal(outboundOnly.kind,'valid');
  if(outboundOnly.kind==='valid'){
    assert.equal(outboundOnly.completeRoundTrips,0);
    assert.equal(outboundOnly.pendingOutbound?.actionIndex,0);
  }

  assert.equal(providerHandoffTimeline(receipt([entry('inbound',0),entry('outbound',0)])).kind,'invalid');
  assert.equal(providerHandoffTimeline(receipt([entry('outbound',0),entry('inbound',0,'chatgpt')])).kind,'invalid');
  assert.equal(providerHandoffTimeline(receipt([entry('outbound',0),{tool:'provider.handoff.inbound',status:'ok',detail:event('inbound',0,'local','c'.repeat(64))}])).kind,'invalid');
  assert.equal(providerHandoffTimeline(receipt([entry('outbound',0,'chatgpt')])).kind,'invalid');
  const changedOrigin=JSON.parse(event('outbound',0));
  changedOrigin.origin='app-handoff';
  assert.equal(providerHandoffTimeline(receipt([{tool:'provider.handoff.outbound',status:'ok',detail:JSON.stringify(changedOrigin)}])).kind,'invalid');
  assert.equal(providerHandoffTimeline(receipt([entry('outbound',0),entry('inbound',0),entry('outbound',2)])).kind,'invalid');
  const leaked=JSON.parse(event('outbound',0));
  leaked.content='provider output';
  assert.equal(providerHandoffTimeline(receipt([{tool:'provider.handoff.outbound',status:'ok',detail:JSON.stringify(leaked)}])).kind,'invalid');
  const missingAdapter=JSON.parse(event('outbound',0));
  delete missingAdapter.adapterSHA256;
  assert.equal(providerHandoffTimeline(receipt([{tool:'provider.handoff.outbound',status:'ok',detail:JSON.stringify(missingAdapter)}],'cancelled',0)).kind,'invalid');
  const oldSchema=JSON.parse(event('outbound',0));
  oldSchema.schemaVersion=1;
  assert.equal(providerHandoffTimeline(receipt([{tool:'provider.handoff.outbound',status:'ok',detail:JSON.stringify(oldSchema)}],'cancelled',0)).kind,'invalid');
  const rawAdapter=JSON.parse(event('outbound',0));
  rawAdapter.adapterName='PRIVATE CUSTOM SHORTCUT';
  const rawAdapterReceipt=receipt([{tool:'provider.handoff.outbound',status:'ok',detail:JSON.stringify(rawAdapter)}],'cancelled',0);
  assert.doesNotMatch(JSON.stringify(rawAdapterReceipt),/PRIVATE CUSTOM SHORTCUT/);
  assert.equal(providerHandoffTimeline(rawAdapterReceipt).kind,'invalid');
  assert.equal(providerHandoffTimeline(receipt([{...entry('outbound',0),status:'error'}],'cancelled',0)).kind,'invalid');
  assert.equal(providerHandoffTimeline(receipt([{...entry('outbound',0),evidence:{path:null,sha256:null,byteCount:null,readbackKind:'source-read',contentComplete:true}}],'cancelled',0)).kind,'invalid');
  assert.equal(providerHandoffTimeline(receipt([entry('outbound',0)],'completed',0)).kind,'invalid');
  assert.equal(providerHandoffTimeline(receipt([entry('outbound',0),entry('inbound',0)],'completed',2)).kind,'invalid');
  const validReceipt=receipt([entry('outbound',0),entry('inbound',0)],'completed',1);
  assert.equal(receiptSchema.safeParse({...validReceipt,provider:null}).success,false);
  assert.equal(receiptSchema.safeParse({...validReceipt,taskOrigin:null}).success,false);
  const wrongSelection=JSON.parse(event('outbound',0));
  wrongSelection.selection='chatgpt';
  assert.equal(providerHandoffTimeline(receipt([{tool:'provider.handoff.outbound',status:'ok',detail:JSON.stringify(wrongSelection)}],'cancelled',0)).kind,'invalid');
});

test('receipt parsing removes ordinary sensitive trace, verification, summary, and malformed handoff data',()=>{
  const marker='PRIVATE-FILE-CLIPBOARD-PROVIDER-OUTPUT';
  const hash='a'.repeat(64);
  const parsed=receiptSchema.parse({
    recordType:'run-receipt',schemaVersion:2,id:'private-import',goal:'Approved private task',status:'verified',origin:'shortcut',summary:marker,steps:1,failures:0,durationMs:5,createdAt:new Date().toISOString(),
    trace:[{tool:'file.read',status:'ok',detail:marker,evidence:{path:'workspace/private.txt',sha256:hash,byteCount:marker.length,readbackKind:'source-read',contentComplete:true}}],
    contract:{recordType:'goal-contract',schemaVersion:1,assertions:[{kind:'exactText',path:'workspace/private.txt',expected:marker}]},
    assertions:[{kind:'exactText',path:'workspace/private.txt',folder:null,passed:true,expected:marker,observed:marker,observedSHA256:hash,byteCount:marker.length,checkedAt:new Date().toISOString(),errorCode:null}],
    provider:'local',policyDigest:hash,workspaceID:'workspace-123',environment:{appVersion:'0.3.0',build:'1',os:'iOS',device:'iPhone'},taskOrigin:'app-intent',
    routingEvidence:{recordType:'provider-routing-decision',schemaVersion:2,selection:'local',provider:'local',authorizedProvider:'apple',strategy:'explicit-pinned',activity:'workspace-idle',accessEvidence:'recent-locally-validated-response',deviceProfileSHA256:hash,configurationSHA256:'b'.repeat(64),qualificationEpochSHA256:'c'.repeat(64),sampleCount:5,distinctProbeCount:5,verifiedCount:5,reliabilityBasisPoints:10000,qualityBasisPoints:10000,medianDurationBucketMilliseconds:500,testedContextCharacters:6000,toolCallingQualified:true,integrityFaultCount:0,automatedReturnQualified:true},legacyTraceOnly:false,
  });
  const stored=JSON.stringify(parsed);
  assert.doesNotMatch(stored,new RegExp(marker));
  assert.match(stored,/legacy-redacted/);
  assert.equal(parsed.assertions[0]?.observed,null);
  assert.equal(parsed.assertions[0]?.expected,'[redacted]');

  const malformedHandoff=receiptSchema.parse({
    ...parsed,id:'malformed-handoff',status:'cancelled',steps:0,summary:'cancelled',contract:null,assertions:[],
    trace:[{tool:'provider.handoff.outbound',status:'ok',detail:JSON.stringify({content:marker})}],
  });
  assert.doesNotMatch(JSON.stringify(malformedHandoff),new RegExp(marker));
  assert.equal(providerHandoffTimeline(malformedHandoff).kind,'invalid');
});
