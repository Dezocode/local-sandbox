import { z } from 'zod';
const utf8Encoder=new TextEncoder();
const utf8Decoder=new TextDecoder('utf-8',{fatal:true});
export const receiptWireContract=Object.freeze({
  maximumSerializedUTF8Bytes:1_900_000,
  stringLengthMetric:'unicode-code-points' as const,
  maximumFractionalSecondDigits:9,
  maximumJSONDepth:32,
  maximumJSONMembers:4_096,
});
export type StrictJSONLimits={maximumDepth:number;maximumMembers:number};
function parseStrictJSONText(text:string,limits:StrictJSONLimits):unknown{
  if(!Number.isSafeInteger(limits.maximumDepth)||limits.maximumDepth<1||limits.maximumDepth>64||!Number.isSafeInteger(limits.maximumMembers)||limits.maximumMembers<1||limits.maximumMembers>16_384)throw new Error('Invalid strict JSON limits.');
  let index=0,memberCount=0;
  const invalid=()=>new Error('Receipt must contain valid unambiguous JSON.');
  const code=()=>text.charCodeAt(index);
  const consume=(expected:number)=>{if(index<text.length&&code()===expected){index+=1;return true;}return false;};
  const expect=(expected:number)=>{if(!consume(expected))throw invalid();};
  const whitespace=()=>{while(index<text.length){const value=code();if(value!==0x20&&value!==0x09&&value!==0x0a&&value!==0x0d)break;index+=1;}};
  const countMember=()=>{memberCount+=1;if(memberCount>limits.maximumMembers)throw new Error('Receipt JSON member limit exceeded.');};
  const hexCodeUnit=()=>{
    if(index+4>text.length)throw invalid();
    let value=0;
    for(let offset=0;offset<4;offset+=1){
      const digit=code();let decoded:number;
      if(digit>=0x30&&digit<=0x39)decoded=digit-0x30;
      else if(digit>=0x41&&digit<=0x46)decoded=digit-0x41+10;
      else if(digit>=0x61&&digit<=0x66)decoded=digit-0x61+10;
      else throw invalid();
      value=value*16+decoded;index+=1;
    }
    return value;
  };
  const stringValue=(capture:boolean):string=>{
    expect(0x22);let decoded='';
    while(index<text.length){
      const value=code();index+=1;
      if(value===0x22)return decoded;
      if(value===0x5c){
        if(index>=text.length)throw invalid();
        const escaped=code();index+=1;
        if(escaped===0x22||escaped===0x5c||escaped===0x2f){if(capture)decoded+=String.fromCharCode(escaped);continue;}
        if(escaped===0x62||escaped===0x66||escaped===0x6e||escaped===0x72||escaped===0x74){
          if(capture)decoded+=String.fromCharCode(escaped===0x62?0x08:escaped===0x66?0x0c:escaped===0x6e?0x0a:escaped===0x72?0x0d:0x09);
          continue;
        }
        if(escaped!==0x75)throw invalid();
        const first=hexCodeUnit();let scalar=first;
        if(first>=0xd800&&first<=0xdbff){
          if(index+6>text.length||text.charCodeAt(index)!==0x5c||text.charCodeAt(index+1)!==0x75)throw invalid();
          index+=2;const second=hexCodeUnit();if(second<0xdc00||second>0xdfff)throw invalid();
          scalar=0x10000+((first-0xd800)<<10)+(second-0xdc00);
        }else if(first>=0xdc00&&first<=0xdfff)throw invalid();
        if(capture)decoded+=String.fromCodePoint(scalar);
        continue;
      }
      if(value<=0x1f)throw invalid();
      if(value>=0xd800&&value<=0xdbff){
        if(index>=text.length)throw invalid();
        const second=code();if(second<0xdc00||second>0xdfff)throw invalid();
        if(capture)decoded+=String.fromCharCode(value,second);index+=1;continue;
      }
      if(value>=0xdc00&&value<=0xdfff)throw invalid();
      if(capture)decoded+=String.fromCharCode(value);
    }
    throw invalid();
  };
  const literal=(expected:string)=>{if(text.slice(index,index+expected.length)!==expected)throw invalid();index+=expected.length;};
  const number=()=>{
    consume(0x2d);
    if(index>=text.length)throw invalid();
    if(consume(0x30)){if(index<text.length&&code()>=0x30&&code()<=0x39)throw invalid();}
    else{if(code()<0x31||code()>0x39)throw invalid();index+=1;while(index<text.length&&code()>=0x30&&code()<=0x39)index+=1;}
    if(consume(0x2e)){if(index>=text.length||code()<0x30||code()>0x39)throw invalid();while(index<text.length&&code()>=0x30&&code()<=0x39)index+=1;}
    if(index<text.length&&(code()===0x65||code()===0x45)){
      index+=1;if(index<text.length&&(code()===0x2b||code()===0x2d))index+=1;
      if(index>=text.length||code()<0x30||code()>0x39)throw invalid();while(index<text.length&&code()>=0x30&&code()<=0x39)index+=1;
    }
  };
  const value=(containerDepth:number):void=>{
    if(index>=text.length)throw invalid();
    const token=code();
    if(token===0x7b){if(containerDepth>=limits.maximumDepth)throw new Error('Receipt JSON depth limit exceeded.');object(containerDepth+1);}
    else if(token===0x5b){if(containerDepth>=limits.maximumDepth)throw new Error('Receipt JSON depth limit exceeded.');array(containerDepth+1);}
    else if(token===0x22){stringValue(false);}
    else if(token===0x74)literal('true');
    else if(token===0x66)literal('false');
    else if(token===0x6e)literal('null');
    else if(token===0x2d||(token>=0x30&&token<=0x39))number();
    else throw invalid();
  };
  const object=(containerDepth:number):void=>{
    expect(0x7b);whitespace();if(consume(0x7d))return;
    const keys=new Set<string>();
    for(;;){
      if(index>=text.length||code()!==0x22)throw invalid();
      const key=stringValue(true);if(keys.has(key))throw new Error('Receipt JSON contains a duplicate object member.');keys.add(key);countMember();
      whitespace();expect(0x3a);whitespace();value(containerDepth);whitespace();if(consume(0x7d))return;expect(0x2c);whitespace();
    }
  };
  const array=(containerDepth:number):void=>{
    expect(0x5b);whitespace();if(consume(0x5d))return;
    for(;;){countMember();value(containerDepth);whitespace();if(consume(0x5d))return;expect(0x2c);whitespace();}
  };
  whitespace();if(index>=text.length)throw invalid();value(0);whitespace();if(index!==text.length)throw invalid();
  return JSON.parse(text) as unknown;
}
export function parseStrictJSON(text:string,limits:StrictJSONLimits):unknown{return parseStrictJSONText(text,limits);}
export function receiptCodePointLength(value:string):number{return Array.from(value).length;}
function receiptString(maximum:number,minimum=0){return z.string().refine(value=>{const count=receiptCodePointLength(value);return count>=minimum&&count<=maximum;},`Use ${minimum} to ${maximum} Unicode code points.`);}
export function isReceiptDateTime(value:string):boolean{
  const match=/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$/.exec(value);
  if(!match)return false;
  const [,yearText,monthText,dayText,hourText,minuteText,secondText,,,offsetSign,offsetHourText,offsetMinuteText]=match;
  const year=Number(yearText),month=Number(monthText),day=Number(dayText),hour=Number(hourText),minute=Number(minuteText),second=Number(secondText);
  if(month<1||month>12||hour>23||minute>59||second>59)return false;
  const leap=year%4===0&&(year%100!==0||year%400===0);
  const maximumDay=month===2?(leap?29:28):[4,6,9,11].includes(month)?30:31;
  if(day<1||day>maximumDay)return false;
  if(offsetSign!==undefined){const offsetHour=Number(offsetHourText),offsetMinute=Number(offsetMinuteText);if(offsetHour>23||offsetMinute>59)return false;}
  return true;
}
const receiptDateTimeSchema=receiptString(35,20).refine(isReceiptDateTime,'Use a valid RFC 3339 timestamp with seconds and at most nine fractional digits.');
export const receiptPageCursorSchema=z.object({createdAt:receiptDateTimeSchema,id:receiptString(80,1)}).strict();
export function receiptSerializedUTF8ByteCount(value:unknown):number{
  const serialized=JSON.stringify(value);
  return serialized===undefined?Number.POSITIVE_INFINITY:utf8Encoder.encode(serialized).byteLength;
}
export function receiptSerializedByteCountIsValid(byteCount:number):boolean{return Number.isSafeInteger(byteCount)&&byteCount>=0&&byteCount<=receiptWireContract.maximumSerializedUTF8Bytes;}
function addReceiptByteLimitIssue(value:unknown,context:z.RefinementCtx):void{
  if(!receiptSerializedByteCountIsValid(receiptSerializedUTF8ByteCount(value)))context.addIssue({code:z.ZodIssueCode.custom,message:`Receipt JSON exceeds ${receiptWireContract.maximumSerializedUTF8Bytes} UTF-8 bytes.`});
}
export const fileContentSchema=z.string().refine(value=>utf8Encoder.encode(value).byteLength<=64_000,'Files are limited to 64 KB of UTF-8.');
export const pathSchema = z.string().min(1).max(180).regex(/^(workspace|config|state|logs|output)\/[A-Za-z0-9][A-Za-z0-9._/-]*$/).refine(p => p.split('/').every(s => s !== '..' && s !== '.' && s !== ''), 'Use a relative path inside the sandbox.').brand<'SandboxPath'>();
export const providerSchema=z.enum(['local','apple','chatgpt','grok','grokbot','claude']);
export const providerSelectionSchema=z.enum(['saved','best-local','apple','local','chatgpt','grok','grokbot','claude']);
export const providerTaskOriginSchema=z.enum(['app-handoff','app-intent']);
const sha256Schema=z.string().regex(/^[a-f0-9]{64}$/);
const providerAccessEvidenceSchema=z.preprocess(
  value=>value==='recent-successful-round-trip'?'recent-locally-validated-response':value,
  z.enum(['on-device-runtime','recent-locally-validated-response','configured-unmeasured','unavailable']),
);
export const providerHandoffEventSchema=z.discriminatedUnion('direction',[
  z.object({recordType:z.literal('provider-handoff'),schemaVersion:z.literal(2),direction:z.literal('outbound'),transport:z.literal('app-shortcut'),provider:providerSchema,selection:providerSelectionSchema,origin:providerTaskOriginSchema,adapterSHA256:sha256Schema,actionIndex:z.number().int().nonnegative().max(100),promptSHA256:sha256Schema}).strict(),
  z.object({recordType:z.literal('provider-handoff'),schemaVersion:z.literal(2),direction:z.literal('inbound'),transport:z.literal('app-shortcut'),provider:providerSchema,selection:providerSelectionSchema,origin:providerTaskOriginSchema,adapterSHA256:sha256Schema,actionIndex:z.number().int().nonnegative().max(100),responseSHA256:sha256Schema}).strict(),
]);
export type ProviderHandoffEvent=z.infer<typeof providerHandoffEventSchema>;
export const providerRoutingEvidenceSchema=z.object({
  recordType:z.literal('provider-routing-decision'),schemaVersion:z.literal(2),
  selection:providerSelectionSchema,provider:providerSchema,authorizedProvider:providerSchema,
  strategy:z.enum(['saved-pinned','explicit-pinned','best-local-cold-start','best-local-measured','oracle-recommendation']),
  activity:z.literal('workspace-idle'),
  accessEvidence:providerAccessEvidenceSchema,
  deviceProfileSHA256:sha256Schema,configurationSHA256:sha256Schema,qualificationEpochSHA256:sha256Schema.optional(),
  sampleCount:z.number().int().min(0).max(20),distinctProbeCount:z.number().int().min(0).max(5),verifiedCount:z.number().int().min(0).max(20),
  reliabilityBasisPoints:z.number().int().min(0).max(10000).optional(),qualityBasisPoints:z.number().int().min(0).max(10000).optional(),
  medianDurationBucketMilliseconds:z.number().int().min(0).max(300000).optional(),testedContextCharacters:z.number().int().min(0).max(12000).optional(),
  toolCallingQualified:z.boolean(),integrityFaultCount:z.number().int().min(0).max(20),automatedReturnQualified:z.boolean(),
}).strict().superRefine((evidence,context)=>{
  if(evidence.verifiedCount>evidence.sampleCount)context.addIssue({code:z.ZodIssueCode.custom,path:['verifiedCount'],message:'Verified routing samples cannot exceed total samples.'});
  if(evidence.distinctProbeCount>Math.min(evidence.sampleCount,5))context.addIssue({code:z.ZodIssueCode.custom,path:['distinctProbeCount'],message:'Distinct probe coverage cannot exceed measured samples or the five-probe suite.'});
  if(evidence.integrityFaultCount>evidence.sampleCount)context.addIssue({code:z.ZodIssueCode.custom,path:['integrityFaultCount'],message:'Integrity faults cannot exceed measured samples.'});
  if(evidence.selection==='best-local'&&evidence.provider!=='apple'&&evidence.provider!=='local')context.addIssue({code:z.ZodIssueCode.custom,path:['provider'],message:'Best Local routing evidence must name Apple or Locally.'});
  if(!['saved','best-local'].includes(evidence.selection)&&evidence.selection!==evidence.provider)context.addIssue({code:z.ZodIssueCode.custom,path:['provider'],message:'Explicit routing evidence must retain the requested provider.'});
  if((evidence.strategy==='saved-pinned'||evidence.strategy==='oracle-recommendation')&&(evidence.selection!=='saved'||evidence.provider!==evidence.authorizedProvider))context.addIssue({code:z.ZodIssueCode.custom,path:['strategy'],message:'Saved routing strategies require the Saved selection and its authorized provider.'});
  if((evidence.strategy==='best-local-cold-start'||evidence.strategy==='best-local-measured')&&evidence.selection!=='best-local')context.addIssue({code:z.ZodIssueCode.custom,path:['strategy'],message:'Best Local strategies require the Best Local selection.'});
  if(evidence.strategy==='best-local-cold-start')context.addIssue({code:z.ZodIssueCode.custom,path:['strategy'],message:'A Best Local cold-start target is blocked and cannot be committed as route evidence.'});
  if(evidence.strategy==='explicit-pinned'&&(evidence.selection==='saved'||evidence.selection==='best-local'))context.addIssue({code:z.ZodIssueCode.custom,path:['strategy'],message:'Explicit routing requires an explicit provider selection.'});
  if(evidence.provider==='apple'&&evidence.accessEvidence!=='on-device-runtime'&&evidence.accessEvidence!=='unavailable')context.addIssue({code:z.ZodIssueCode.custom,path:['accessEvidence'],message:'Apple routing can claim only the on-device runtime or an unavailable runtime.'});
  if(evidence.provider!=='apple'&&evidence.accessEvidence==='on-device-runtime')context.addIssue({code:z.ZodIssueCode.custom,path:['accessEvidence'],message:'External Shortcut providers cannot claim the Apple on-device runtime.'});
  if(evidence.accessEvidence==='recent-locally-validated-response'&&(evidence.provider==='apple'||evidence.verifiedCount===0))context.addIssue({code:z.ZodIssueCode.custom,path:['accessEvidence'],message:'Locally validated response evidence requires a non-Apple provider and at least one exact local assertion.'});

  const qualificationFields=['qualificationEpochSHA256','reliabilityBasisPoints','qualityBasisPoints','medianDurationBucketMilliseconds','testedContextCharacters'] as const;
  if(evidence.sampleCount===0){
    for(const field of qualificationFields)if(evidence[field]!==undefined)context.addIssue({code:z.ZodIssueCode.custom,path:[field],message:'Qualification metrics require at least one measured sample.'});
    if(evidence.toolCallingQualified)context.addIssue({code:z.ZodIssueCode.custom,path:['toolCallingQualified'],message:'Tool calling cannot be qualified without measured samples.'});
    if(evidence.distinctProbeCount!==0||evidence.integrityFaultCount!==0||evidence.automatedReturnQualified)context.addIssue({code:z.ZodIssueCode.custom,path:['sampleCount'],message:'An unmeasured route cannot claim probe coverage, integrity faults, or observed Record App Intent return coverage.'});
  }else{
    for(const field of qualificationFields)if(evidence[field]===undefined)context.addIssue({code:z.ZodIssueCode.custom,path:[field],message:'Measured routing evidence must include its complete qualification metric set.'});
    const expectedQuality=Math.floor(evidence.verifiedCount*10_000/evidence.sampleCount);
    if(evidence.qualityBasisPoints!==undefined&&evidence.qualityBasisPoints!==expectedQuality)context.addIssue({code:z.ZodIssueCode.custom,path:['qualityBasisPoints'],message:'Assertion quality must match exact local assertion passes over measured samples.'});
    if(evidence.reliabilityBasisPoints!==undefined){
      const possibleSchemaPasses=Array.from({length:evidence.sampleCount+1},(_,passes)=>passes).find(passes=>Math.floor(passes*10_000/evidence.sampleCount)===evidence.reliabilityBasisPoints);
      if(possibleSchemaPasses===undefined||possibleSchemaPasses<evidence.verifiedCount)context.addIssue({code:z.ZodIssueCode.custom,path:['reliabilityBasisPoints'],message:'Schema reliability must represent a whole-sample pass count that covers every exact local assertion pass.'});
    }
    if(evidence.verifiedCount===0&&evidence.testedContextCharacters!==0)context.addIssue({code:z.ZodIssueCode.custom,path:['testedContextCharacters'],message:'Tested context must be zero when no exact local assertion passed.'});
    if(evidence.verifiedCount>0&&evidence.testedContextCharacters===0)context.addIssue({code:z.ZodIssueCode.custom,path:['testedContextCharacters'],message:'A validated response must record a nonzero tested context size.'});
    if(evidence.toolCallingQualified&&evidence.verifiedCount<3)context.addIssue({code:z.ZodIssueCode.custom,path:['toolCallingQualified'],message:'Tool calling requires three distinct passing tool probes.'});
  }
  if(
    evidence.sampleCount<5||
    evidence.distinctProbeCount<5||
    evidence.verifiedCount*5<evidence.sampleCount*4||
    (evidence.reliabilityBasisPoints??-1)<8_000||
    (evidence.qualityBasisPoints??-1)<8_000||
    (evidence.testedContextCharacters??0)<2_000||
    evidence.integrityFaultCount!==0||
    !evidence.toolCallingQualified||
    (evidence.provider!=='apple'&&evidence.accessEvidence!=='recent-locally-validated-response')
  ){
    context.addIssue({code:z.ZodIssueCode.custom,path:['sampleCount'],message:'Every committed route requires five measured samples, 80 percent local assertion and schema reliability, 2,000 tested context characters, qualified tools, and locally validated external responses.'});
  }
});
export type ProviderRoutingEvidence=z.infer<typeof providerRoutingEvidenceSchema>;
export const policySchema = z.object({
  batteryBudget: z.number().int().min(1).max(80), batteryReserve: z.number().int().min(5).max(80),
  memoryTarget: z.number().int().min(10).max(80), maxSteps: z.number().int().min(1).max(24),
  maxFailures: z.number().int().min(1).max(3), contextChars: z.number().int().min(2000).max(12000),
  cloudAllowed: z.boolean(), notifications: z.boolean(), clipboardReadAllowed:z.boolean().default(false), clipboardWriteAllowed:z.boolean().default(false), provider: providerSchema,
  localShortcut: z.string().min(1).max(80),
}).strict();
export type Policy = z.infer<typeof policySchema>;
export function normalizeSavedPolicy(value:unknown):Policy {
  const legacy=z.object({provider:z.literal('openai')}).passthrough().safeParse(value);
  return policySchema.parse(legacy.success?{...legacy.data,provider:'chatgpt'}:value);
}
export const defaultPolicy: Policy = { batteryBudget:15, batteryReserve:20, memoryTarget:35, maxSteps:6, maxFailures:3, contextChars:6000, cloudAllowed:false, notifications:true, clipboardReadAllowed:false, clipboardWriteAllowed:false, provider:'local', localShortcut:'Agent Step - Local' };
export const fileSchema = z.object({path:pathSchema, content:fileContentSchema, version:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)});
export type SandboxFile = z.infer<typeof fileSchema>;
export const toolCallSchema = z.discriminatedUnion('tool', [
  z.object({tool:z.literal('file.read'),path:pathSchema}).strict(),
  z.object({tool:z.literal('file.list'),path:z.enum(['workspace','config','state','logs','output'])}).strict(),
  z.object({tool:z.literal('file.create'),path:pathSchema,content:fileContentSchema}).strict(),
  z.object({tool:z.literal('file.append'),path:pathSchema,content:z.string().max(8000),version:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)}).strict(),
  z.object({tool:z.literal('file.patch'),path:pathSchema,old:z.string().min(1).max(8000),replacement:z.string().max(8000),version:z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)}).strict(),
]);
export type ToolCall = z.infer<typeof toolCallSchema>;
const evidencePathSchema=pathSchema.or(z.enum(['workspace','config','state','logs','output']));
export const toolEvidenceSchema=z.object({path:evidencePathSchema.nullable(),sha256:z.string().regex(/^[a-f0-9]{64}$/).nullable(),byteCount:z.number().int().min(0).max(64000).nullable(),readbackKind:receiptString(40,1),contentComplete:z.boolean()}).strict();
export const goalAssertionSchema=z.discriminatedUnion('kind',[
  z.object({kind:z.literal('exactText'),path:pathSchema,expected:fileContentSchema}).strict(),
  z.object({kind:z.literal('sha256'),path:pathSchema,expected:z.string().regex(/^[a-f0-9]{64}$/)}).strict(),
  z.object({kind:z.literal('containsText'),path:pathSchema,expected:receiptString(8000,1)}).strict(),
  z.object({kind:z.literal('pathExists'),path:pathSchema}).strict(),
  z.object({kind:z.literal('pathAbsent'),path:pathSchema}).strict(),
  z.object({kind:z.literal('folderContains'),folder:z.enum(['workspace','config','state','logs','output']),path:pathSchema}).strict(),
]);
export const goalContractSchema=z.object({recordType:z.literal('goal-contract'),schemaVersion:z.literal(1),assertions:z.array(goalAssertionSchema).min(1).max(20)}).strict();
export const assertionEvidenceSchema=z.object({kind:z.enum(['exactText','sha256','containsText','pathExists','pathAbsent','folderContains']),path:pathSchema,folder:z.enum(['workspace','config','state','logs','output']).nullable().optional(),passed:z.boolean(),expected:fileContentSchema.nullable(),observed:receiptString(1000).nullable(),observedSHA256:z.string().regex(/^[a-f0-9]{64}$/).nullable(),byteCount:z.number().int().min(0).max(64000).nullable(),checkedAt:receiptDateTimeSchema,errorCode:receiptString(500).nullable()}).strict();
export const traceMetadataSchema=z.discriminatedUnion('resultKind',[
  z.object({recordType:z.literal('trace-metadata'),schemaVersion:z.literal(1),resultKind:z.enum(['file-read','directory-list','file-mutation','clipboard-read','clipboard-write','notification','legacy-redacted']),sha256:z.string().regex(/^[a-f0-9]{64}$/).nullable().optional(),byteCount:z.number().int().min(0).max(64000).nullable().optional(),readbackKind:z.enum(['source-read','directory-list','write-readback','independent-readback']).nullable().optional(),errorCode:z.null().optional()}).strict(),
  z.object({recordType:z.literal('trace-metadata'),schemaVersion:z.literal(1),resultKind:z.literal('error'),sha256:z.string().regex(/^[a-f0-9]{64}$/).nullable().optional(),byteCount:z.number().int().min(0).max(64000).nullable().optional(),readbackKind:z.null().optional(),errorCode:z.string().regex(/^[A-Z][A-Z0-9_]{1,79}$/)}).strict(),
]);
const traceEntrySchema=z.object({tool:receiptString(100),status:z.enum(['ok','error','skipped']),detail:receiptString(1000),evidence:toolEvidenceSchema.nullable().optional()}).strict();
const receiptBase={id:receiptString(80,1),goal:receiptString(2000),status:z.enum(['verified','completed','blocked','cancelled']),origin:z.enum(['cloud-sandbox','shortcut','native']),summary:receiptString(3000),steps:z.number().int().min(0).max(100),failures:z.number().int().min(0).max(100),durationMs:z.number().min(0).max(86400000),createdAt:receiptDateTimeSchema,trace:z.array(traceEntrySchema).max(100)};
const currentReceiptSchema=z.object({...receiptBase,recordType:z.literal('run-receipt'),schemaVersion:z.literal(2),contract:goalContractSchema.nullable(),assertions:z.array(assertionEvidenceSchema).max(20),provider:providerSchema.or(z.literal('system')).nullable(),policyDigest:z.string().regex(/^[a-f0-9]{64}$/).nullable(),workspaceID:receiptString(80,8).nullable(),environment:z.object({appVersion:receiptString(40),build:receiptString(40),os:receiptString(100),device:receiptString(100)}).strict().nullable(),taskOrigin:z.enum(['app-handoff','app-intent']).nullable().optional(),routingEvidence:providerRoutingEvidenceSchema.nullable().optional(),legacyTraceOnly:z.boolean()}).strict().superRefine((receipt,context)=>{
  const assertions=receipt.contract?.assertions;
  const mappingValid=!!assertions&&receipt.assertions.length===assertions.length&&receipt.assertions.every((evidence,index)=>{
    const assertion=assertions[index];
    const expected='expected' in assertion?assertion.expected:null;
    const folder='folder' in assertion?assertion.folder:null;
    return evidence.kind===assertion.kind&&evidence.path===assertion.path&&evidence.expected===expected&&(evidence.folder??null)===folder;
  });
  if(receipt.assertions.length>0&&!mappingValid)context.addIssue({code:z.ZodIssueCode.custom,path:['assertions'],message:'Assertion evidence must exactly match the approved contract in order, kind, path, expected value, and folder.'});
  if(receipt.status==='verified'&&(!receipt.contract||receipt.assertions.length===0||!mappingValid||receipt.assertions.some(assertion=>!assertion.passed||assertion.errorCode!==null)||receipt.legacyTraceOnly)){context.addIssue({code:z.ZodIssueCode.custom,path:['status'],message:'Verified receipts require a nonempty approved contract and exactly matching, passing independent assertions.'});}
  if(receipt.routingEvidence&&receipt.provider!==receipt.routingEvidence.provider)context.addIssue({code:z.ZodIssueCode.custom,path:['routingEvidence','provider'],message:'Routing evidence must match the receipt provider.'});
  if(receipt.taskOrigin==='app-intent'&&receipt.routingEvidence&&!receipt.routingEvidence.automatedReturnQualified)context.addIssue({code:z.ZodIssueCode.custom,path:['routingEvidence','automatedReturnQualified'],message:'App Intent receipts require observed Record App Intent return coverage for every qualifying probe.'});
  if(receipt.legacyTraceOnly){
    if(receipt.status==='verified'||receipt.contract!==null||receipt.assertions.length!==0||receipt.provider!==null||receipt.policyDigest!==null||receipt.workspaceID!==null||receipt.environment!==null||(receipt.taskOrigin??null)!==null||(receipt.routingEvidence??null)!==null)context.addIssue({code:z.ZodIssueCode.custom,path:['legacyTraceOnly'],message:'Legacy receipts must remain unqualified, evidence-free compatibility records.'});
  }else if(receipt.origin==='native'||receipt.origin==='shortcut'){
    if(!receipt.provider||receipt.provider==='system'||!receipt.policyDigest||!receipt.workspaceID||!receipt.environment||!receipt.taskOrigin||!receipt.routingEvidence)context.addIssue({code:z.ZodIssueCode.custom,path:['routingEvidence'],message:'Native and Shortcut receipts require complete local route, authorization, workspace, environment, and invocation evidence.'});
    if(receipt.origin==='native'&&(receipt.provider!=='apple'||receipt.routingEvidence?.provider!=='apple'))context.addIssue({code:z.ZodIssueCode.custom,path:['provider'],message:'Native receipts require the Apple on-device route.'});
    if(receipt.origin==='shortcut'&&(receipt.provider==='apple'||receipt.routingEvidence?.provider==='apple'))context.addIssue({code:z.ZodIssueCode.custom,path:['provider'],message:'Shortcut receipts require a non-Apple provider.'});
  }
});
const legacyReceiptSchema=z.object({...receiptBase,status:z.enum(['verified','blocked','cancelled'])}).strict();
type GoalAssertion=z.infer<typeof goalAssertionSchema>;
type AssertionEvidence=z.infer<typeof assertionEvidenceSchema>;
type TraceEntry=z.infer<typeof traceEntrySchema>;
type CurrentReceipt=z.infer<typeof currentReceiptSchema>;

function safeExpected(kind:GoalAssertion['kind']|AssertionEvidence['kind'],value:string|null|undefined):string|null{
  if(value===undefined||value===null)return null;
  if(kind!=='exactText'&&kind!=='containsText')return value;
  return /^sha256:[a-f0-9]{64}$/.test(value)?value:'[redacted]';
}
function safeErrorCode(value:string|null):string|null{
  if(value===null)return null;
  const candidate=value.split(':',1)[0]??'';
  return /^[A-Z][A-Z0-9_]{1,79}$/.test(candidate)?candidate:'TASK_STEP_FAILED';
}
function safeGoalAssertion(assertion:GoalAssertion):GoalAssertion{
  switch(assertion.kind){
    case'exactText':return{...assertion,expected:safeExpected(assertion.kind,assertion.expected)??'[redacted]'};
    case'containsText':return{...assertion,expected:safeExpected(assertion.kind,assertion.expected)??'[redacted]'};
    case'sha256':case'pathExists':case'pathAbsent':case'folderContains':return assertion;
  }
}
function safeAssertionEvidence(evidence:AssertionEvidence):AssertionEvidence{
  return{...evidence,expected:safeExpected(evidence.kind,evidence.expected),observed:null,errorCode:safeErrorCode(evidence.errorCode)};
}
function safeTraceDetail(entry:TraceEntry):string{
  let value:unknown;
  try{value=JSON.parse(entry.detail);}catch{value=null;}
  if(entry.tool==='provider.handoff.outbound'||entry.tool==='provider.handoff.inbound'){
    const event=providerHandoffEventSchema.safeParse(value);
    if(event.success&&entry.tool===`provider.handoff.${event.data.direction}`)return JSON.stringify(event.data);
  }else{
    const metadata=traceMetadataSchema.safeParse(value);
    if(metadata.success)return JSON.stringify(metadata.data);
  }
  return JSON.stringify({recordType:'trace-metadata',schemaVersion:1,resultKind:'legacy-redacted',sha256:null,byteCount:utf8Encoder.encode(entry.detail).byteLength,readbackKind:null,errorCode:null});
}
function safeTraceEntry(entry:TraceEntry):TraceEntry{
  const evidence=entry.evidence?{...entry.evidence,readbackKind:(['source-read','directory-list','write-readback','independent-readback'] as const).find(kind=>kind===entry.evidence?.readbackKind)??'source-read'}:entry.evidence;
  return{...entry,detail:safeTraceDetail(entry),evidence};
}
function safeReceiptSummary(receipt:Pick<CurrentReceipt,'origin'|'status'|'summary'>):string{
  if(receipt.origin!=='native'&&receipt.origin!=='shortcut')return receipt.summary;
  switch(receipt.status){
    case'verified':return'Task completed and independent verification passed.';
    case'completed':return'Task completed without a passing independent verification result.';
    case'blocked':return'Task stopped at a policy or execution boundary.';
    case'cancelled':return'Task was cancelled.';
  }
}
function safeReceiptGoal(receipt:Pick<CurrentReceipt,'origin'|'goal'>):string{
  if(receipt.origin!=='native'&&receipt.origin!=='shortcut')return receipt.goal;
  if(/^sha256:[a-f0-9]{64}$/.test(receipt.goal))return receipt.goal;
  return '[redacted]';
}
function safeCurrentReceipt(receipt:CurrentReceipt):CurrentReceipt{
  const contract=receipt.contract?{...receipt.contract,assertions:receipt.contract.assertions.map(safeGoalAssertion)}:null;
  return{...receipt,goal:safeReceiptGoal(receipt),summary:safeReceiptSummary(receipt),trace:receipt.trace.map(safeTraceEntry),contract,assertions:receipt.assertions.map(safeAssertionEvidence)};
}

const receiptInputSchema=z.union([currentReceiptSchema,legacyReceiptSchema]).superRefine(addReceiptByteLimitIssue);
export const receiptSchema=receiptInputSchema.transform(receipt=>{
  if('schemaVersion' in receipt)return safeCurrentReceipt(receipt);
  return safeCurrentReceipt({...receipt,recordType:'run-receipt' as const,schemaVersion:2 as const,status:receipt.status==='verified'?'completed' as const:receipt.status,contract:null,assertions:[],provider:null,policyDigest:null,workspaceID:null,environment:null,taskOrigin:null,routingEvidence:null,legacyTraceOnly:true});
}).superRefine(addReceiptByteLimitIssue);
export type Receipt = z.infer<typeof receiptSchema>;
export function parseReceiptWireBytes(bytes:Uint8Array):Receipt{
  if(!receiptSerializedByteCountIsValid(bytes.byteLength))throw new Error(`Receipt JSON exceeds ${receiptWireContract.maximumSerializedUTF8Bytes} UTF-8 bytes.`);
  let text:string;
  try{text=utf8Decoder.decode(bytes);}catch{throw new Error('Receipt JSON must be valid UTF-8.');}
  const value=parseStrictJSONText(text,{maximumDepth:receiptWireContract.maximumJSONDepth,maximumMembers:receiptWireContract.maximumJSONMembers});
  return receiptSchema.parse(value);
}
export function parseReceiptWire(text:string):Receipt{return parseReceiptWireBytes(utf8Encoder.encode(text));}
export const workspaceSchema = z.object({policy:policySchema,files:z.array(fileSchema),receipts:z.array(receiptSchema).max(100),receiptNextCursor:receiptPageCursorSchema.nullable(),completed:z.array(z.string()),workspaceId:z.string().length(32),user:z.string(),revision:z.number().int().nonnegative(),cloudReady:z.boolean()});
export type Workspace = z.infer<typeof workspaceSchema>;
export function exactPatch(content:string, old:string, replacement:string):string {
  const first=content.indexOf(old);
  if(first<0) throw new Error('PATCH_CONTEXT_NOT_FOUND');
  if(content.indexOf(old,first+1)>=0) throw new Error('PATCH_CONTEXT_AMBIGUOUS');
  return content.slice(0,first)+replacement+content.slice(first+old.length);
}
export function compactContext(goal:string,capsule:string,latest:string,budget:number):string {
  const header=`Goal: ${goal.slice(0,2000)}\nState: ${capsule.slice(0,1800)}\nLatest result:\n`;
  return (header+latest.slice(0,Math.max(0,budget-header.length))).slice(0,budget);
}
export function shortcutURL(name:string,input:string):string {
  return `shortcuts://run-shortcut?name=${encodeURIComponent(name)}&input=text&text=${encodeURIComponent(input)}`;
}
