import { z } from 'zod';
import { parseStrictJSON, receiptSchema, receiptWireContract } from '@/lib/contracts';
import { providerHandoffTimeline } from '@/lib/provider-handoff';
import { boundary,identity,input,putReceipt,HttpError,receiptRequestMaximumBytes } from '@/lib/server';
export async function POST(request:Request){return boundary(async()=>{const user=await identity(request);const body=await input(request,z.object({receipt:z.unknown()}).strict(),receiptRequestMaximumBytes,text=>parseStrictJSON(text,{maximumDepth:receiptWireContract.maximumJSONDepth+1,maximumMembers:receiptWireContract.maximumJSONMembers+1}));const receipt=receiptSchema.parse(body.receipt);if(receipt.origin==='cloud-sandbox')throw new HttpError(400,'Imported receipts must identify a native or shortcut origin.');const handoff=providerHandoffTimeline(receipt);if(handoff.kind==='invalid')throw new HttpError(400,handoff.reason,'INVALID_PROVIDER_HANDOFF_RECEIPT');await putReceipt(user,receipt);return {ok:true};});}
