import { providerHandoffEventSchema, type ProviderHandoffEvent } from './contracts.ts';

export { providerHandoffEventSchema, type ProviderHandoffEvent } from './contracts.ts';
type ProviderOutboundEvent=Extract<ProviderHandoffEvent,{direction:'outbound'}>;
type ProviderHandoffIdentity=Pick<ProviderHandoffEvent,'provider'|'selection'|'origin'|'adapterSHA256'>;
type ProviderHandoffReceipt={
  origin:'cloud-sandbox'|'shortcut'|'native';
  status:'verified'|'completed'|'blocked'|'cancelled';
  steps:number;
  provider:string|null;
  taskOrigin?:string|null;
  legacyTraceOnly:boolean;
  trace:{tool:string;status:'ok'|'error'|'skipped';detail:string;evidence?:unknown}[];
};

export type ProviderHandoffTimeline=
  | {kind:'none';events:[];completeRoundTrips:0;pendingOutbound:null}
  | {kind:'valid';events:ProviderHandoffEvent[];completeRoundTrips:number;pendingOutbound:ProviderOutboundEvent|null}
  | {kind:'invalid';events:[];completeRoundTrips:0;pendingOutbound:null;reason:string};

function invalid(reason:string):ProviderHandoffTimeline{
  return {kind:'invalid',events:[],completeRoundTrips:0,pendingOutbound:null,reason};
}

function selectionMatchesProvider(event:ProviderHandoffEvent):boolean{
  switch(event.selection){
    case'saved':return true;
    case'best-local':return event.provider==='local';
    case'apple':case'local':case'chatgpt':case'grok':case'grokbot':case'claude':return event.selection===event.provider;
  }
}

export function providerHandoffTimeline(receipt:ProviderHandoffReceipt):ProviderHandoffTimeline{
  const events:ProviderHandoffEvent[]=[];
  let identity:ProviderHandoffIdentity|null=null;
  let pendingOutbound:ProviderOutboundEvent|null=null;
  let nextActionIndex=0;
  let completeRoundTrips=0;

  for(const entry of receipt.trace){
    if(entry.tool!=='provider.handoff.outbound'&&entry.tool!=='provider.handoff.inbound')continue;
    if(entry.status!=='ok'||(entry.evidence!==undefined&&entry.evidence!==null)){
      return invalid('Provider handoff telemetry must be successful and cannot carry ordinary tool evidence.');
    }
    let raw:unknown;
    try{raw=JSON.parse(entry.detail);}
    catch{return invalid('Provider handoff telemetry contains invalid JSON.');}
    const parsed=providerHandoffEventSchema.safeParse(raw);
    if(!parsed.success||entry.tool!==`provider.handoff.${parsed.data.direction}`){
      return invalid('Provider handoff telemetry failed its strict schema.');
    }
    const event=parsed.data;
    if(event.provider==='apple'||!selectionMatchesProvider(event)){
      return invalid('Provider handoff telemetry does not match the selected Shortcut route.');
    }
    if(identity===null){
      identity={provider:event.provider,selection:event.selection,origin:event.origin,adapterSHA256:event.adapterSHA256};
    }else if(event.provider!==identity.provider||event.selection!==identity.selection||event.origin!==identity.origin||event.adapterSHA256!==identity.adapterSHA256){
      return invalid('Provider handoff telemetry changed route, adapter, or origin during one run.');
    }

    if(pendingOutbound===null){
      if(event.direction!=='outbound'||event.actionIndex!==nextActionIndex){
        return invalid('Provider handoff telemetry is out of order.');
      }
      pendingOutbound=event;
    }else{
      if(event.direction!=='inbound'||event.actionIndex!==pendingOutbound.actionIndex){
        return invalid('Provider handoff telemetry has no matching return.');
      }
      pendingOutbound=null;
      completeRoundTrips+=1;
      nextActionIndex+=1;
    }
    events.push(event);
  }

  if(events.length===0){
    if(receipt.origin==='shortcut'&&!receipt.legacyTraceOnly)return invalid('Shortcut receipt is missing provider handoff telemetry.');
    return {kind:'none',events:[],completeRoundTrips:0,pendingOutbound:null};
  }
  if(receipt.origin!=='shortcut'||!receipt.provider||!receipt.taskOrigin){
    return invalid('Provider handoff telemetry requires a shortcut receipt with provider and task origin.');
  }
  if(receipt.provider!==identity?.provider){
    return invalid('Provider handoff telemetry does not match the receipt provider.');
  }
  if(receipt.taskOrigin!==identity?.origin){
    return invalid('Provider handoff telemetry does not match the receipt origin.');
  }
  if(completeRoundTrips!==receipt.steps||(pendingOutbound!==null&&pendingOutbound.actionIndex!==receipt.steps)){
    return invalid('Provider handoff telemetry does not match the receipt step count.');
  }
  if((receipt.status==='completed'||receipt.status==='verified')&&pendingOutbound!==null){
    return invalid('A terminal receipt cannot retain a pending provider handoff.');
  }
  return {kind:'valid',events,completeRoundTrips,pendingOutbound};
}
